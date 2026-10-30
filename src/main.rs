// SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: MIT

mod backup;
mod penlock_ui;
mod scan;
mod theme;
mod wallet;

use std::cell::RefCell;
use std::rc::Rc;

use slint_keyos_platform::app_ui2;
use slint_keyos_platform::fs::Location;
use slint_keyos_platform::gui_server_api::navigation::qrscanner::{MatchedQrResult, ScanQrOptions, ScanQrResult};
use slint_keyos_platform::navigation::async_open_qr_scanner;
use slint_keyos_platform::slint::{Color, ModelRc, VecModel};

use wallet::Wallet;

app_ui2!("my-app");

const WALLET_FILE: &str = "wallet.json";
// The runtime's QR renderer panics past QR capacity (~2.3 kB at its error-correction level).
// ponytail: single static QR, so big multi-proof tokens can't be shown; NUT-16 animated UR if that bites.
const MAX_QR_BYTES: usize = 2000;

struct App {
    ui: slint::Weak<AppWindow>,
    cx: AppContext,
    wallet: RefCell<Wallet>,
}

impl App {
    fn ui(&self) -> AppWindow { self.ui.upgrade().expect("window outlives callbacks") }

    fn refresh(&self) {
        let wallet = self.wallet.borrow();
        let notes: Vec<NoteItem> = wallet
            .notes
            .iter()
            .map(|n| NoteItem { amount: format!("{} {}", n.amount, n.unit).into(), mint: n.mint.clone().into() })
            .collect();
        let ui = self.ui();
        let state = ui.global::<AppState>();
        state.set_balance(wallet.balance().into());
        state.set_notes(ModelRc::new(VecModel::from(notes)));
    }

    fn toast(&self, msg: impl Into<slint::SharedString>, variant: ToastVariant) {
        let ui = self.ui();
        let state = ui.global::<AppState>();
        state.set_toast(msg.into());
        state.set_toast_variant(variant);
    }

    fn save(&self) -> bool {
        let json = self.wallet.borrow().to_json();
        match self.cx.fs.durable_file_write(WALLET_FILE, Location::AppData, &json) {
            Ok(()) => true,
            Err(e) => {
                log::error!("saving wallet: {e:?}");
                false
            }
        }
    }

    fn receive(&self, raw: &str) {
        let added = self.wallet.borrow_mut().add(raw).map(|n| format!("Received {} {}", n.amount, n.unit));
        match added {
            Ok(msg) if self.save() => self.toast(msg, ToastVariant::Success),
            Ok(_) => {
                // Not on disk, so it would vanish on restart: don't pretend it was kept.
                self.wallet.borrow_mut().notes.pop();
                self.toast("Couldn't save the token. It was not received.", ToastVariant::Error);
            }
            Err(e) => self.toast(e, ToastVariant::Error),
        }
        self.refresh();
    }

    fn remove_selected(&self, msg: &str) {
        let ui = self.ui();
        let state = ui.global::<AppState>();
        let i = state.get_selected();
        if i < 0 {
            return;
        }
        self.wallet.borrow_mut().notes.remove(i as usize);
        state.set_selected(-1);
        if self.save() {
            self.toast(msg, ToastVariant::Success);
        } else {
            self.toast("Sent, but the wallet couldn't be saved. The note may reappear.", ToastVariant::Warning);
        }
        self.refresh();
    }
}

fn app_main(cx: AppContext, ui: AppWindow) {
    log_server::init_wait(env!("CARGO_CRATE_NAME")).unwrap();
    log::set_max_level(log::LevelFilter::Info);

    theme::init(&ui);

    let wallet = match cx.fs.durable_file_read(WALLET_FILE, Location::AppData) {
        Ok(bytes) => Wallet::from_json(&bytes),
        Err(slint_keyos_platform::fs::Error::FileNotFound) => Wallet::default(),
        Err(e) => {
            log::error!("reading wallet: {e:?}");
            Wallet::default()
        }
    };
    let app = Rc::new(App { ui: ui.as_weak(), cx: cx.clone(), wallet: RefCell::new(wallet) });
    app.refresh();
    penlock_ui::init(&cx, &ui);

    // Launched from the Launcher QR tile with a cashu token (see qr-match-rules in app-config.toml).
    if let Ok(Some(req)) = cx.gui.navigate_pending() {
        let scan = MatchedQrResult::from_slice(&req).map(|m| m.scan_result).or_else(|| ScanQrResult::from_slice(&req));
        if let Some(ScanQrResult::Qr { data, .. }) = scan {
            app.receive(&String::from_utf8_lossy(&data));
        }
    }

    let cb = ui.global::<Callbacks>();

    cb.on_scan_receive({
        let app = app.clone();
        move || {
            let app = app.clone();
            slint_keyos_platform::spawn_local(async move {
                let options = ScanQrOptions {
                    header_title: "Receive ecash".into(),
                    message: "Scan a Cashu token".into(),
                    ..Default::default()
                };
                match async_open_qr_scanner::<gui_permissions::GuiPermissions>(options).await {
                    Ok(Some(ScanQrResult::Qr { data, .. })) => app.receive(&String::from_utf8_lossy(&data)),
                    Ok(Some(ScanQrResult::Ur2 { .. })) => {
                        app.toast("Animated (UR) tokens aren't supported yet", ToastVariant::Error)
                    }
                    Ok(_) => {} // cancelled
                    Err(e) => app.toast(format!("Scanner unavailable: {e:?}"), ToastVariant::Error),
                }
            })
            .detach();
        }
    });

    cb.on_select_note({
        let app = app.clone();
        move |i| {
            let Some(token) = app.wallet.borrow().notes.get(i as usize).map(|n| n.token.clone()) else { return };
            let ui = app.ui();
            let state = ui.global::<AppState>();
            if token.len() > MAX_QR_BYTES {
                app.toast("This token is too large for a QR code", ToastVariant::Error);
                return;
            }
            let black = Color::from_rgb_u8(0, 0, 0);
            let white = Color::from_rgb_u8(255, 255, 255);
            state.set_qr(slint_keyos_platform::qrcode::render(token.as_bytes(), black, white));
            state.set_selected(i);
        }
    });

    cb.on_close_note({
        let app = app.clone();
        move || app.ui().global::<AppState>().set_selected(-1)
    });

    cb.on_mark_sent({
        let app = app.clone();
        move || app.remove_selected("Note marked as sent")
    });

    cb.on_dismiss_toast({
        let app = app.clone();
        move || app.ui().global::<AppState>().set_toast("".into())
    });

    ui.run().expect("UI running");
}
