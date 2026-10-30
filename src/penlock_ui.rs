// SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: MIT

// Penlock screens: creating shares from a phrase, restoring a phrase by scanning two strips, and reading
// a handwritten phrase.
// Phrases, shares and readings only live in this struct and the UI while their screen is open, and are
// dropped when it closes. Nothing is logged or saved.

use std::cell::{Cell, OnceCell, RefCell};
use std::collections::BTreeMap;
use std::rc::Rc;
use std::time::{Duration, Instant};

use penlock::word::WORD_LEN;
use penlock::{Distribution, ShareIndex};
use slint_keyos_platform::slint::{self, ComponentHandle, Image, Model, ModelRc, SharedString, VecModel};

use crate::backup::{self, PhraseCheck};
use crate::scan::{self, Event, Reader, Source};
use crate::{
    AppContext, AppWindow, Callbacks, ChipRow, PenlockScreen, PenlockState, PhraseStatus, PhraseWord, ShareRow, ShareSheet,
};

camera::use_api!();

// Preview refresh cap; the software renderer can't keep up with every camera frame.
const PREVIEW_INTERVAL: Duration = Duration::from_millis(66);
// How long without a frame before telling the person the camera isn't working.
const CAMERA_WATCHDOG: Duration = Duration::from_secs(5);
// How long "Read share N" stays up before the status goes back to searching.
const HIT_HOLD: Duration = Duration::from_millis(1500);
const CHIPS_PER_ROW: usize = 3;

type Cells = Vec<[Distribution; WORD_LEN]>;

struct Penlock {
    ui: slint::Weak<AppWindow>,
    cx: AppContext,
    share_reader: OnceCell<Reader>,
    phrase_reader: OnceCell<Reader>,
    qr_reader: OnceCell<Reader>,
    share_ready: Cell<bool>,
    phrase_ready: Cell<bool>,
    qr_ready: Cell<bool>,
    source: Cell<Source>,
    // The latest handwritten reading, until it's reviewed.
    draft: RefCell<Vec<String>>,
    // Best reading per share number: (index, cells, unread boxes).
    scanned: RefCell<BTreeMap<u8, (ShareIndex, Cells, usize)>>,
    // Bumped whenever a scan screen opens or closes, so a stale frame loop knows to stop.
    session: Cell<u32>,
    last_hit: Cell<Option<Instant>>,
}

fn strings(items: impl IntoIterator<Item = String>) -> ModelRc<SharedString> {
    ModelRc::new(VecModel::from(items.into_iter().map(SharedString::from).collect::<Vec<_>>()))
}

impl Penlock {
    fn ui(&self) -> AppWindow { self.ui.upgrade().expect("window outlives callbacks") }

    fn with_state(&self, f: impl FnOnce(PenlockState)) { f(self.ui().global::<PenlockState>()) }

    fn reader_ready(&self, source: Source) -> &Cell<bool> {
        match source {
            Source::Shares => &self.share_ready,
            Source::Phrase => &self.phrase_ready,
            Source::Qr => &self.qr_ready,
        }
    }

    fn reader(&self, source: Source) -> &Reader {
        let cell = match source {
            Source::Shares => &self.share_reader,
            Source::Phrase => &self.phrase_reader,
            Source::Qr => &self.qr_reader,
        };
        cell.get_or_init(|| Reader::start(source))
    }

    fn searching(&self) -> &'static str {
        match self.source.get() {
            Source::Shares => "Looking for a share strip",
            Source::Phrase => "Looking for written words",
            Source::Qr => "Looking for a QR code",
        }
    }

    fn open(&self, screen: PenlockScreen) {
        self.wipe();
        self.with_state(|s| s.set_screen(screen));
    }

    /// Drop everything sensitive the screens held, and stop the camera.
    fn wipe(&self) {
        self.session.set(self.session.get() + 1);
        let _ = self.cx.gui.hide_camera();
        self.scanned.borrow_mut().clear();
        self.draft.borrow_mut().clear();
        self.last_hit.set(None);
        self.with_state(|s| {
            s.set_phrase("".into());
            s.set_phrase_note("".into());
            s.set_draft_ready(false);
            s.set_can_sign_share(false);
            s.set_scan_hit(false);
            s.set_scan_failed(false);
            s.set_words_read(0);
            s.set_draft_complete(false);
            s.set_phrase_count(0);
            s.set_chip_rows(ModelRc::default());
            s.set_phrase_status(PhraseStatus::Neutral);
            s.set_phrase_message(PhraseCheck::Empty.message().into());
            s.set_shares(ModelRc::default());
            s.set_words(ModelRc::default());
            s.set_corrections(ModelRc::default());
            s.set_result_subtitle("".into());
            s.set_preview(Image::default());
            s.set_camera_live(false);
            s.set_scan_error("".into());
            s.set_have(ModelRc::new(VecModel::from(vec![false; 3])));
        });
    }

    fn phrase_edited(&self, text: &str) {
        let check = backup::check_phrase(text);
        let status = match check {
            PhraseCheck::Valid(_) => PhraseStatus::Valid,
            PhraseCheck::UnknownWord(..) | PhraseCheck::TooLong(_) | PhraseCheck::BadChecksum(_) => PhraseStatus::Error,
            PhraseCheck::Empty | PhraseCheck::Incomplete(_) => PhraseStatus::Neutral,
        };
        let typed = backup::typed_words(text);
        let slots = if typed.len() <= backup::LENGTHS[0] { backup::LENGTHS[0] } else { backup::LENGTHS[1].max(typed.len()) };
        let chips: Vec<PhraseWord> = (0..slots)
            .map(|i| {
                let (word, bad) = typed.get(i).cloned().unwrap_or_default();
                PhraseWord { number: i as i32 + 1, word: word.into(), bad }
            })
            .collect();
        let rows: Vec<ChipRow> = chips
            .chunks(CHIPS_PER_ROW)
            .map(|row| ChipRow { chips: ModelRc::new(VecModel::from(row.to_vec())) })
            .collect();
        self.with_state(|s| {
            s.set_phrase_message(check.message().into());
            s.set_phrase_status(status);
            s.set_phrase_count(typed.len() as i32);
            s.set_chip_rows(ModelRc::new(VecModel::from(rows)));
        });
    }

    fn split(&self, text: &str) {
        let PhraseCheck::Valid(words) = backup::check_phrase(text) else { return };
        match backup::split(&words) {
            Ok(shares) => {
                let sheets: Vec<ShareSheet> = shares
                    .iter()
                    .map(|share| ShareSheet {
                        rows: ModelRc::new(VecModel::from(
                            backup::rows(share)
                                .into_iter()
                                .map(|row| ShareRow { symbols: strings(row.iter().map(|c| c.to_string())) })
                                .collect::<Vec<_>>(),
                        )),
                    })
                    .collect();
                self.with_state(|s| {
                    s.set_shares(ModelRc::new(VecModel::from(sheets)));
                    s.set_screen(PenlockScreen::Shares);
                });
            }
            Err(e) => {
                let ui = self.ui();
                let app = ui.global::<crate::AppState>();
                app.set_toast(e.into());
                app.set_toast_variant(crate::ToastVariant::Error);
            }
        }
    }

    fn start_scan(self: &Rc<Self>, source: Source) {
        self.open(PenlockScreen::Scan);
        self.source.set(source);
        let session = self.session.get();
        let ready = self.reader_ready(source).get();
        let status = if ready { self.searching() } else { "Preparing the reader…" };
        self.with_state(|s| {
            s.set_scan_phrase(source == Source::Phrase);
            s.set_scan_qr(source == Source::Qr);
            s.set_reader_ready(ready);
            s.set_scan_status(status.into());
        });
        self.reader(source);

        let y = self.ui().global::<PenlockState>().get_viewfinder_y();
        if let Err(e) = self.cx.gui.show_camera(y as u16) {
            log::warn!("show_camera: {e:?}");
        }

        let this = self.clone();
        slint_keyos_platform::spawn_local(async move {
            slint_keyos_platform::sleep(CAMERA_WATCHDOG).await;
            if this.session.get() == session && !this.ui().global::<PenlockState>().get_camera_live() {
                this.with_state(|s| {
                    s.set_scan_status("No picture from the camera".into());
                    s.set_scan_error("The camera isn't sending pictures. Go back and try again.".into());
                    s.set_scan_failed(true);
                });
            }
        })
        .detach();

        let this = self.clone();
        slint_keyos_platform::spawn_local(async move {
            let subscribed =
                slint_keyos_platform::try_subscribe_scalar::<camera_permissions::CameraPermissions, _>(
                    camera::messages::Subscribe,
                )
                .await;
            let mut frames = match subscribed {
                Ok(frames) => frames,
                Err(e) => {
                    log::error!("camera subscribe: {e:?}");
                    this.with_state(|s| {
                        s.set_scan_error("The camera is unavailable.".into());
                        s.set_scan_failed(true);
                    });
                    return;
                }
            };
            let mut last_preview: Option<Instant> = None;
            while let Some(frame) = frames.next().await {
                if this.session.get() != session {
                    break;
                }
                let (rgb, preview) = scan::convert(frame.content().as_slice::<u8>());
                if last_preview.is_none_or(|t| t.elapsed() >= PREVIEW_INTERVAL) {
                    last_preview = Some(Instant::now());
                    this.with_state(|s| {
                        s.set_camera_live(true);
                        s.set_preview(Image::from_rgb8(preview));
                    });
                }
                let reader = this.reader(source);
                if this.reader_ready(source).get() {
                    reader.offer(rgb);
                }
                while let Ok(event) = reader.events.try_recv() {
                    this.handle(event);
                    if this.session.get() != session {
                        return;
                    }
                }
            }
        })
        .detach();
    }

    fn handle(&self, event: Event) {
        match event {
            Event::Ready => {
                self.reader_ready(self.source.get()).set(true);
                self.with_state(|s| {
                    s.set_reader_ready(true);
                    s.set_scan_status(self.searching().into());
                });
            }
            Event::Failed(e) => {
                log::error!("reader: {e}");
                self.with_state(|s| {
                    s.set_scan_status("Reader unavailable".into());
                    s.set_scan_error("The reader couldn't start on this device.".into());
                    s.set_scan_failed(true);
                });
            }
            Event::Nothing => {
                if self.last_hit.get().is_none_or(|t| t.elapsed() >= HIT_HOLD) {
                    self.with_state(|s| {
                        s.set_scan_hit(false);
                        s.set_scan_status(self.searching().into());
                    });
                }
            }
            Event::Read { index, cells, unread } => self.read(index, cells, unread),
            Event::Qr(text) => {
                self.open(PenlockScreen::Wallet);
                self.ui().global::<Callbacks>().invoke_qr_scanned(text.into());
            }
            Event::Words { words, checksum } => {
                let count = words.len();
                *self.draft.borrow_mut() = words;
                self.last_hit.set(Some(Instant::now()));
                self.with_state(|s| {
                    s.set_draft_ready(true);
                    s.set_draft_complete(checksum && backup::LENGTHS.contains(&count));
                    s.set_words_read(count as i32);
                    s.set_scan_hit(true);
                    s.set_scan_status(format!("Read {count} words").into());
                });
            }
        }
    }

    /// Hand what was read to the phrase screen. It's only ever a draft: one wrong word can still pass the
    /// checksum, so nothing is done with it until the person has checked it against the paper.
    fn review_draft(&self) {
        let phrase = self.draft.borrow().join(" ");
        self.open(PenlockScreen::Enter);
        self.with_state(|s| {
            s.set_phrase(phrase.as_str().into());
            s.set_phrase_note("Check every word against it, even if the checksum passes.".into());
        });
        self.phrase_edited(&phrase);
    }

    /// Take the clearest strip read so far to the wallet, on its own.
    fn sign_with_scanned(&self) {
        let text = {
            let scanned = self.scanned.borrow();
            let best = scanned.values().min_by_key(|(_, _, unread)| *unread);
            best.map(|(index, cells, _)| backup::share_text(&backup::share_from_cells(*index, cells)))
        };
        let Some(text) = text else { return };
        self.open(PenlockScreen::Home);
        self.ui().global::<Callbacks>().invoke_open_share(text.into());
    }

    /// Take one of the shares on screen to the wallet. The others leave this Passport with the screen.
    fn sign_with_sheet(&self, sheet: usize) {
        let ui = self.ui();
        let Some(rows) = ui.global::<PenlockState>().get_shares().row_data(sheet) else { return };
        let rows: Vec<String> =
            rows.rows.iter().map(|row| row.symbols.iter().map(|c| c.to_string()).collect()).collect();
        let text = format!("penlock v1 share {}\n{}", sheet + 1, rows.join("\n"));
        self.open(PenlockScreen::Home);
        ui.global::<Callbacks>().invoke_open_share(text.into());
    }

    fn read(&self, index: ShareIndex, cells: Cells, unread: usize) {
        let n = index.number();
        let better = self.scanned.borrow().get(&n).is_none_or(|(_, _, u)| unread < *u);
        if better {
            self.scanned.borrow_mut().insert(n, (index, cells, unread));
        }
        self.last_hit.set(Some(Instant::now()));
        let have: Vec<bool> = (1..=3).map(|i| self.scanned.borrow().contains_key(&i)).collect();
        self.with_state(|s| {
            s.set_have(ModelRc::new(VecModel::from(have)));
            s.set_scan_error("".into());
            s.set_scan_failed(false);
            s.set_can_sign_share(true);
            s.set_read_share(n as i32);
            s.set_scan_hit(true);
            s.set_scan_status(match unread {
                0 => format!("Read share {n} · scan the next strip"),
                1 => format!("Read share {n} · 1 faint box"),
                u => format!("Read share {n} · {u} faint boxes"),
            }
            .into());
        });

        // Two different shares: try to restore, preferring the cleanest readings.
        let pair = {
            let scanned = self.scanned.borrow();
            let mut best: Vec<_> = scanned.values().collect();
            best.sort_by_key(|(_, _, unread)| *unread);
            match best.as_slice() {
                [a, b, ..] => Some((a.0, a.1.clone(), b.0, b.1.clone())),
                _ => None,
            }
        };
        let Some((ia, a, ib, b)) = pair else { return };
        match backup::recover(&a, ia, &b, ib) {
            Ok(got) => {
                self.session.set(self.session.get() + 1);
                let _ = self.cx.gui.hide_camera();
                self.scanned.borrow_mut().clear();
                let (lo, hi) = (ia.number().min(ib.number()), ia.number().max(ib.number()));
                self.with_state(|s| {
                    s.set_preview(Image::default());
                    s.set_words(strings(got.words.iter().map(|w| w.as_str().to_string())));
                    s.set_corrections(strings(got.corrections));
                    s.set_result_subtitle(format!("From shares {lo} and {hi} · BIP39 checksum valid").into());
                    s.set_screen(PenlockScreen::Result);
                });
            }
            Err(e) => {
                // Forget the share just read so the person can rescan it.
                self.scanned.borrow_mut().remove(&n);
                let have: Vec<bool> = (1..=3).map(|i| self.scanned.borrow().contains_key(&i)).collect();
                self.with_state(|s| {
                    s.set_have(ModelRc::new(VecModel::from(have)));
                    s.set_scan_error(e.into());
                    s.set_scan_failed(true);
                });
            }
        }
    }
}

pub fn init(cx: &AppContext, ui: &AppWindow) {
    let penlock = Rc::new(Penlock {
        ui: ui.as_weak(),
        cx: cx.clone(),
        share_reader: OnceCell::new(),
        phrase_reader: OnceCell::new(),
        qr_reader: OnceCell::new(),
        share_ready: Cell::new(false),
        phrase_ready: Cell::new(false),
        qr_ready: Cell::new(false),
        source: Cell::new(Source::Shares),
        draft: RefCell::default(),
        scanned: RefCell::default(),
        session: Cell::new(0),
        last_hit: Cell::new(None),
    });
    penlock.wipe();

    let cb = ui.global::<Callbacks>();
    cb.on_penlock_create({
        let p = penlock.clone();
        move || p.open(PenlockScreen::Enter)
    });
    cb.on_penlock_scan({
        let p = penlock.clone();
        move || p.start_scan(Source::Shares)
    });
    cb.on_penlock_read_phrase({
        let p = penlock.clone();
        move || p.start_scan(Source::Phrase)
    });
    cb.on_scan_qr({
        let p = penlock.clone();
        move |title| {
            p.with_state(|s| s.set_scan_title(title));
            p.start_scan(Source::Qr);
        }
    });
    cb.on_scan_qr_cancel({
        let p = penlock.clone();
        move || p.open(PenlockScreen::Wallet)
    });
    cb.on_review_draft({
        let p = penlock.clone();
        move || p.review_draft()
    });
    cb.on_sign_with_scanned({
        let p = penlock.clone();
        move || p.sign_with_scanned()
    });
    cb.on_sign_with_sheet({
        let p = penlock.clone();
        move |sheet| p.sign_with_sheet(sheet as usize)
    });
    cb.on_penlock_close({
        let p = penlock.clone();
        move || p.open(PenlockScreen::Home)
    });
    cb.on_phrase_edited({
        let p = penlock.clone();
        move |text| {
            p.phrase_edited(&text);
            text.ends_with('\n')
        }
    });
    cb.on_split_phrase({
        let p = penlock.clone();
        move |text| p.split(&text)
    });
}
