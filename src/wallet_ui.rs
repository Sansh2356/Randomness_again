// SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: MIT

// MuSig wallet screens. The signer lives here while the app is open and is never written to storage;
// everything that leaves the Passport is a public key, an address, a PSBT or a transaction.

use std::cell::{Cell, RefCell};
use std::rc::Rc;

use bitcoin::psbt::Psbt;
use bitcoin::Network;
use penlock::Share;
use slint_keyos_platform::slint::{self, Color, ComponentHandle, Model, ModelRc, VecModel};

use crate::musig::{self, Review, Signer, Step};
use crate::single::SeedSigner;
use crate::{
    AddressChunk, AddressRow, AppState, AppWindow, Callbacks, PenlockScreen, PenlockState, QrKind, SendRow,
    ToastVariant, WalletState,
};

// The runtime's QR renderer panics past QR capacity (~2.3 kB at its error-correction level).
// ponytail: single static QR, so a PSBT past a few inputs can't be shown; animated UR if that bites.
const MAX_QR_BYTES: usize = 2000;
// An address's groups of four, and how many fit a line of the well.
const CHUNK: usize = 4;
const CHUNKS_PER_ROW: usize = 7;
// The review's headline amount drops a size past this many characters.
const LONG_TOTAL: usize = 10;

#[derive(Clone, Copy)]
enum Wanted {
    Cosigner,
    Psbt,
    Share,
    SeedPsbt,
}

struct Wallet {
    ui: slint::Weak<AppWindow>,
    signer: RefCell<Option<Signer>>,
    // A seed rebuilt from two shares, spending its own coins. Dropped on leaving those screens.
    seed: RefCell<Option<SeedSigner>>,
    wanted: Cell<Wanted>,
    // The transaction on the review screen, until it's approved or cancelled.
    reviewing: RefCell<Option<Psbt>>,
    address: Cell<u32>,
}

/// 30000000 as 30,000,000.
fn grouped(amount: u64) -> String {
    let digits = amount.to_string();
    let lead = digits.len() % 3;
    let mut groups: Vec<&str> = if lead > 0 { vec![&digits[..lead]] } else { Vec::new() };
    groups.extend(digits.as_bytes()[lead..].chunks(3).map(|c| std::str::from_utf8(c).expect("ascii digits")));
    groups.join(",")
}

/// 4f789518 as 4f78 9518.
fn fingerprint_groups(fingerprint: &str) -> String {
    let groups: Vec<&str> =
        fingerprint.as_bytes().chunks(CHUNK).map(|c| std::str::from_utf8(c).expect("ascii hex")).collect();
    groups.join(" ")
}

/// An address in groups of four, with the first two groups and the last two picked out.
fn address_rows(address: &str) -> ModelRc<AddressRow> {
    let chunks: Vec<&str> =
        address.as_bytes().chunks(CHUNK).map(|c| std::str::from_utf8(c).expect("bech32 is ascii")).collect();
    let last = chunks.len().saturating_sub(2);
    let cells: Vec<AddressChunk> = chunks
        .iter()
        .enumerate()
        .map(|(i, text)| AddressChunk { text: (*text).into(), hot: i < 2 || i >= last })
        .collect();
    let rows: Vec<AddressRow> = cells
        .chunks(CHUNKS_PER_ROW)
        .map(|row| AddressRow { chunks: ModelRc::new(VecModel::from(row.to_vec())) })
        .collect();
    ModelRc::new(VecModel::from(rows))
}

impl Wallet {
    fn ui(&self) -> AppWindow { self.ui.upgrade().expect("window outlives callbacks") }

    fn with_state(&self, f: impl FnOnce(WalletState)) { f(self.ui().global::<WalletState>()) }

    fn screen(&self, screen: PenlockScreen) { self.ui().global::<PenlockState>().set_screen(screen); }

    fn toast(&self, msg: impl Into<slint::SharedString>, variant: ToastVariant) { self.toast_detail(msg, "", variant) }

    fn toast_detail(&self, msg: impl Into<slint::SharedString>, detail: &str, variant: ToastVariant) {
        let ui = self.ui();
        let state = ui.global::<AppState>();
        state.set_toast(msg.into());
        state.set_toast_detail(detail.into());
        state.set_toast_variant(variant);
    }

    fn refresh(&self) {
        let signer = self.signer.borrow();
        self.with_state(|s| {
            s.set_loaded(signer.is_some());
            let fingerprint = signer.as_ref().map(|k| k.fingerprint().to_string()).unwrap_or_default();
            s.set_fingerprint(fingerprint_groups(&fingerprint).into());
            s.set_cosigners(signer.as_ref().map_or(0, |k| k.cosigners()) as i32);
        });
    }

    fn network(&self) -> Network {
        if self.ui().global::<WalletState>().get_mainnet() {
            Network::Bitcoin
        } else {
            Network::Signet
        }
    }

    fn open(&self, phrase: &str) {
        match Signer::from_phrase(phrase, self.network()) {
            Ok(signer) => {
                *self.signer.borrow_mut() = Some(signer);
                self.address.set(0);
                self.with_state(|s| s.set_source("SEED PHRASE".into()));
                self.refresh();
                let ui = self.ui();
                let penlock = ui.global::<PenlockState>();
                penlock.set_phrase("".into());
                penlock.set_words(ModelRc::default());
                self.screen(PenlockScreen::Wallet);
            }
            Err(e) => self.toast(e, ToastVariant::Error),
        }
    }

    /// A signer of one share's own key. It signs with a cosigner holding another share of the backup.
    fn open_share(&self, text: &str) {
        // Line breaks may not survive being pasted: the header is four tokens, the rest are rows.
        let tokens: Vec<&str> = text.split_whitespace().collect();
        let (header, rows) = tokens.split_at(tokens.len().min(4));
        let lines = format!("{}\n{}", header.join(" "), rows.join("\n"));
        let signer = Share::parse(&lines, None).map_err(|e| format!("That isn't a share: {e}")).and_then(|share| {
            Signer::from_share(share.index().number(), &rows.concat(), self.network()).map(|signer| (share, signer))
        });
        match signer {
            Ok((share, signer)) => {
                *self.signer.borrow_mut() = Some(signer);
                self.address.set(0);
                self.with_state(|s| s.set_source(format!("SHARE {}", share.index().number()).into()));
                self.refresh();
                self.screen(PenlockScreen::Wallet);
            }
            Err(e) => self.toast(e, ToastVariant::Error),
        }
    }

    fn lock(&self) {
        *self.signer.borrow_mut() = None;
        *self.reviewing.borrow_mut() = None;
        self.refresh();
        self.screen(PenlockScreen::Home);
    }

    fn show_qr(&self, kind: QrKind, title: &str, caption: &str, payload: &str) {
        if payload.len() > MAX_QR_BYTES {
            self.toast("This is too large for one QR code", ToastVariant::Error);
            self.screen(PenlockScreen::Wallet);
            return;
        }
        // Only public data reaches this function, and the simulator can't hold a QR up to a camera.
        #[cfg(not(keyos))]
        log::info!("wallet-qr {title}: {payload}");
        let black = Color::from_rgb_u8(0, 0, 0);
        let white = Color::from_rgb_u8(255, 255, 255);
        let qr = slint_keyos_platform::qrcode::render(payload.as_bytes(), black, white);
        self.with_state(|s| {
            s.set_qr_title(title.into());
            s.set_qr_caption(caption.into());
            s.set_qr_kind(kind);
            s.set_qr(qr);
        });
        self.screen(PenlockScreen::WalletQr);
    }

    fn show_address(&self) {
        let index = self.address.get();
        let address = self.signer.borrow().as_ref().map(|k| k.address(musig::RECEIVE, index));
        match address {
            Some(Ok(address)) => {
                self.with_state(|s| s.set_address_rows(address_rows(&address)));
                self.show_qr(QrKind::Address, &format!("Address {}", index + 1), "", &address);
            }
            Some(Err(e)) => self.toast(e, ToastVariant::Error),
            None => {}
        }
    }

    fn ask(&self, wanted: Wanted) {
        self.wanted.set(wanted);
        if cfg!(keyos) {
            self.scan();
        } else {
            self.with_state(|s| {
                s.set_input("".into());
                s.set_input_title(
                    match wanted {
                        Wanted::Cosigner => "Add a cosigner",
                        Wanted::Psbt | Wanted::SeedPsbt => "Sign a transaction",
                        Wanted::Share => "Paste a share",
                    }
                    .into(),
                );
            });
            self.screen(PenlockScreen::WalletInput);
        }
    }

    fn scan(&self) {
        let title = match self.wanted.get() {
            Wanted::Cosigner => "Add a cosigner",
            Wanted::Psbt | Wanted::Share | Wanted::SeedPsbt => "Sign a transaction",
        };
        self.ui().global::<Callbacks>().invoke_scan_qr(title.into());
    }

    fn received(&self, data: &[u8]) {
        match self.wanted.get() {
            Wanted::Cosigner => self.add_cosigner(data),
            Wanted::Psbt => self.psbt(data),
            Wanted::SeedPsbt => self.seed_psbt(data),
            Wanted::Share => self.open_share(&String::from_utf8_lossy(data)),
        }
    }

    fn add_cosigner(&self, data: &[u8]) {
        let added = self
            .signer
            .borrow_mut()
            .as_mut()
            .ok_or_else(|| "The signer is locked".to_string())
            .and_then(|k| k.add_cosigner(&String::from_utf8_lossy(data)));
        self.screen(PenlockScreen::Wallet);
        self.refresh();
        match added {
            Ok(()) => {
                let size = self.signer.borrow().as_ref().map_or(0, |k| k.cosigners()) + 1;
                let detail = format!("This signer is now {size}-of-{size}.");
                self.toast_detail("Cosigner added", &detail, ToastVariant::Success);
            }
            Err(e) => self.toast(e, ToastVariant::Error),
        }
    }

    fn psbt(&self, data: &[u8]) {
        if let Err(e) = self.step(data) {
            self.screen(PenlockScreen::Wallet);
            let detail = if e == musig::NOT_A_PSBT {
                "Export the transaction from your wallet as a PSBT QR, then scan again."
            } else {
                ""
            };
            self.toast_detail(e, detail, ToastVariant::Error);
        }
    }

    fn step(&self, data: &[u8]) -> Result<(), String> {
        let mut psbt = musig::parse_psbt(data)?;
        let mut guard = self.signer.borrow_mut();
        let signer = guard.as_mut().ok_or("The signer is locked")?;
        match signer.inspect(&psbt)? {
            Step::Nonce(review) => {
                drop(guard);
                self.show_review(review);
                *self.reviewing.borrow_mut() = Some(psbt);
            }
            Step::Sign => {
                signer.add_signatures(&mut psbt)?;
                drop(guard);
                let caption = "Signed. Pass this to your cosigners, or scan the PSBT holding every signature here to finish.";
                self.show_qr(QrKind::Partial, "Partial signature", caption, &psbt.to_string());
            }
            Step::Finalize => {
                let tx = signer.finalize(&mut psbt)?;
                drop(guard);
                let caption = "Scan this with a device that's online to broadcast the transaction.";
                self.show_qr(QrKind::FinalTx, "Final transaction", caption, &tx);
            }
        }
        Ok(())
    }

    fn seed_psbt(&self, data: &[u8]) {
        let reviewed = musig::parse_psbt(data).and_then(|psbt| {
            let guard = self.seed.borrow();
            let seed = guard.as_ref().ok_or("The seed is gone. Restore it again.")?;
            seed.review(&psbt).map(|review| (psbt, review))
        });
        match reviewed {
            Ok((psbt, review)) => {
                self.show_review(review);
                *self.reviewing.borrow_mut() = Some(psbt);
            }
            // A refused PSBT drops the seed too, so it's never left loaded behind a screen that can't clear it.
            Err(e) => {
                self.leave();
                self.toast(e, ToastVariant::Error);
            }
        }
    }

    /// Sign with a phrase directly, for a PSBT from any wallet that holds the same seed.
    fn open_seed(&self, phrase: &str) {
        match SeedSigner::from_phrase(phrase, self.network()) {
            Ok(seed) => {
                *self.seed.borrow_mut() = Some(seed);
                let ui = self.ui();
                let penlock = ui.global::<PenlockState>();
                penlock.set_phrase("".into());
                penlock.set_words(ModelRc::default());
                self.ask(Wanted::SeedPsbt);
            }
            Err(e) => self.toast(e, ToastVariant::Error),
        }
    }

    /// Back from a signing screen, to the signer or, for a seed, out of it altogether.
    fn leave(&self) {
        *self.reviewing.borrow_mut() = None;
        if self.seed.borrow_mut().take().is_some() {
            self.screen(PenlockScreen::Home);
        } else {
            self.screen(PenlockScreen::Wallet);
        }
    }

    fn show_review(&self, review: Review) {
        let total = grouped(review.sends.iter().map(|(_, amount)| amount).sum());
        let rows: Vec<SendRow> = review
            .sends
            .iter()
            .map(|(address, amount)| SendRow { rows: address_rows(address), amount: grouped(*amount).into() })
            .collect();
        self.with_state(|s| {
            s.set_send_total_long(total.len() > LONG_TOTAL);
            s.set_send_total(total.into());
            s.set_sends(ModelRc::new(VecModel::from(rows)));
            s.set_change(grouped(review.change).into());
            s.set_fee(grouped(review.fee).into());
        });
        self.screen(PenlockScreen::WalletReview);
    }

    fn approve(&self) {
        let Some(mut psbt) = self.reviewing.borrow_mut().take() else { return };
        let signed = self.seed.borrow().as_ref().map(|seed| seed.sign(&mut psbt));
        match signed {
            Some(Ok(tx)) => {
                let caption = "Scan this with a device that's online to broadcast the transaction.";
                self.show_qr(QrKind::SingleTx, "Final transaction", caption, &tx);
                return;
            }
            Some(Err(e)) => {
                self.toast(e, ToastVariant::Error);
                self.leave();
                return;
            }
            None => {}
        }
        let added = self
            .signer
            .borrow_mut()
            .as_mut()
            .ok_or_else(|| "The signer is locked".to_string())
            .and_then(|k| k.add_nonces(&mut psbt));
        match added {
            Ok(()) => {
                let caption = "Pass this to your cosigners, then scan the PSBT that comes back with their nonces.";
                self.show_qr(QrKind::Nonces, "Round 1 of 2", caption, &psbt.to_string());
            }
            Err(e) => {
                self.screen(PenlockScreen::Wallet);
                self.toast(e, ToastVariant::Error);
            }
        }
    }
}

pub fn init(ui: &AppWindow) {
    let wallet = Rc::new(Wallet {
        ui: ui.as_weak(),
        signer: RefCell::default(),
        seed: RefCell::default(),
        wanted: Cell::new(Wanted::Psbt),
        reviewing: RefCell::default(),
        address: Cell::new(0),
    });
    ui.global::<WalletState>().set_simulator(cfg!(not(keyos)));

    let cb = ui.global::<Callbacks>();
    cb.on_open_wallet({
        let w = wallet.clone();
        move |phrase| w.open(&phrase)
    });
    cb.on_open_share({
        let w = wallet.clone();
        move |text| w.open_share(&text)
    });
    cb.on_wallet_paste_share({
        let w = wallet.clone();
        move || w.ask(Wanted::Share)
    });
    cb.on_wallet_from_recovered({
        let w = wallet.clone();
        move || {
            let ui = w.ui();
            let words: Vec<String> = ui.global::<PenlockState>().get_words().iter().map(|w| w.to_string()).collect();
            w.open(&words.join(" "));
        }
    });
    cb.on_seed_sign({
        let w = wallet.clone();
        move |phrase| {
            if !phrase.is_empty() {
                return w.open_seed(&phrase);
            }
            let ui = w.ui();
            let words: Vec<String> = ui.global::<PenlockState>().get_words().iter().map(|w| w.to_string()).collect();
            w.open_seed(&words.join(" "));
        }
    });
    cb.on_wallet_home({
        let w = wallet.clone();
        move || w.screen(PenlockScreen::Wallet)
    });
    cb.on_wallet_lock({
        let w = wallet.clone();
        move || w.lock()
    });
    cb.on_wallet_show_key({
        let w = wallet.clone();
        move || {
            let key = w.signer.borrow().as_ref().map(|k| k.xpub());
            if let Some(key) = key {
                w.show_qr(QrKind::Key, "My key", "Your cosigners add this. It's public, and it can't spend.", &key);
            }
        }
    });
    cb.on_wallet_add_cosigner({
        let w = wallet.clone();
        move || w.ask(Wanted::Cosigner)
    });
    cb.on_wallet_sign({
        let w = wallet.clone();
        move || w.ask(Wanted::Psbt)
    });
    cb.on_wallet_scan({
        let w = wallet.clone();
        move || w.scan()
    });
    cb.on_qr_scanned({
        let w = wallet.clone();
        move |text| w.received(text.as_bytes())
    });
    cb.on_wallet_submit({
        let w = wallet.clone();
        move |text| {
            // Long PSBTs stall the simulator's injected keystrokes, so "@path" reads one from a file.
            #[cfg(not(keyos))]
            if let Some(Ok(file)) = text.strip_prefix('@').map(|path| std::fs::read(path.trim())) {
                return w.received(&file);
            }
            w.received(text.as_bytes())
        }
    });
    cb.on_wallet_receive({
        let w = wallet.clone();
        move || w.show_address()
    });
    cb.on_wallet_next_address({
        let w = wallet.clone();
        move || {
            w.address.set(w.address.get() + 1);
            w.show_address();
        }
    });
    cb.on_wallet_approve({
        let w = wallet.clone();
        move || w.approve()
    });
    cb.on_wallet_cancel({
        let w = wallet.clone();
        move || w.leave()
    });
    cb.on_wallet_back({
        let w = wallet.clone();
        move || w.leave()
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn amounts_group_in_thousands() {
        assert_eq!(grouped(0), "0");
        assert_eq!(grouped(999), "999");
        assert_eq!(grouped(1_000), "1,000");
        assert_eq!(grouped(30_000_000), "30,000,000");
        assert_eq!(grouped(100_000_000), "100,000,000");
    }

    #[test]
    fn fingerprints_group_in_fours() {
        assert_eq!(fingerprint_groups("4f789518"), "4f78 9518");
        assert_eq!(fingerprint_groups(""), "");
    }
}
