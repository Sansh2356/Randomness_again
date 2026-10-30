// SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: MIT

// Penlock screens: creating shares from a phrase, restoring a phrase by scanning two strips, and reading
// a handwritten phrase.
// Phrases, shares and readings only live in this struct and the UI while their screen is open, and are
// dropped when it closes. Nothing is logged, and only a share the person chooses to export is saved.

use std::cell::{Cell, OnceCell, RefCell};
use std::collections::BTreeMap;
use std::io::Read;
use std::rc::Rc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use penlock::word::WORD_LEN;
use penlock::{Distribution, Share, ShareIndex};
use slint_keyos_platform::fs::{Location, OpenFlags};
use slint_keyos_platform::gui_server_api::navigation::filepicker::{
    AllowedExtensions, Location as PickerLocation, SelectFileOptions,
};
use slint_keyos_platform::navigation::select_file;
use slint_keyos_platform::slint::{self, ComponentHandle, Image, Model, ModelRc, SharedString, VecModel};

use crate::backup::{self, PhraseCheck};
use crate::scan::{self, Event, Reader, Source};
use crate::{
    gui_permissions, AppContext, AppState, AppWindow, Callbacks, ChipRow, PenlockScreen, PenlockState, PhraseStatus,
    PhraseWord, ShareRow, ShareSheet, ToastVariant,
};

camera::use_api!();

// Preview refresh cap; the software renderer can't keep up with every camera frame.
const PREVIEW_INTERVAL: Duration = Duration::from_millis(66);
// How long without a frame before telling the person the camera isn't working.
const CAMERA_WATCHDOG: Duration = Duration::from_secs(5);
// How long "Read share N" stays up before the status goes back to searching.
const HIT_HOLD: Duration = Duration::from_millis(1500);
const CHIPS_PER_ROW: usize = 3;
// Far past any phone photo: the image reader's own limit is 64 MiB, and a Passport has less room.
const MAX_UPLOAD_BYTES: u64 = 32 * 1024 * 1024;
// Drawing a strip recurses deeply, and the app's own stack is small on a device.
const RENDER_STACK: usize = 8 << 20;

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
    // A photo was asked for: the next camera frame goes to the phrase reader.
    photo_wanted: Cell<bool>,
    // The picture stays on the photo being read, or read, until a retake.
    frozen: Cell<bool>,
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
            Source::Shares => "Frame a strip, then take a photo",
            Source::Phrase => "Frame your words, then take a photo",
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
        self.photo_wanted.set(false);
        self.frozen.set(false);
        self.with_state(|s| {
            s.set_photo_reading(false);
            s.set_full_share(-1);
            s.set_confirm_save(-1);
            s.set_saved_shares(0);
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
                self.toast(&e, "", ToastVariant::Error);
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
            s.set_scan_for_wallet(false);
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
                if !this.frozen.get() && last_preview.is_none_or(|t| t.elapsed() >= PREVIEW_INTERVAL) {
                    last_preview = Some(Instant::now());
                    this.with_state(|s| {
                        s.set_camera_live(true);
                        s.set_preview(Image::from_rgb8(preview));
                    });
                }
                let reader = this.reader(source);
                if this.reader_ready(source).get() {
                    // Paper is read from one steady photo, QR codes frame by frame.
                    if source == Source::Qr {
                        reader.offer(rgb);
                    } else if this.photo_wanted.get() && reader.offer(rgb) {
                        this.photo_wanted.set(false);
                    }
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
            Event::Nothing if self.source.get() != Source::Qr => {
                self.frozen.set(false);
                let missing = if self.source.get() == Source::Phrase { "words" } else { "strip" };
                self.with_state(|s| {
                    s.set_photo_reading(false);
                    s.set_scan_hit(false);
                    s.set_scan_status(self.searching().into());
                    s.set_scan_error(format!("No {missing} found in that photo. Try again with more light, and fill the frame.").into());
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
                    s.set_photo_reading(false);
                    s.set_draft_ready(true);
                    s.set_draft_complete(checksum && backup::LENGTHS.contains(&count));
                    s.set_words_read(count as i32);
                    s.set_scan_hit(true);
                    s.set_scan_status(format!("Read {count} words").into());
                });
            }
        }
    }

    fn take_photo(&self) {
        self.photo_wanted.set(true);
        self.frozen.set(true);
        self.with_state(|s| {
            s.set_photo_reading(true);
            s.set_scan_hit(false);
            s.set_scan_error("".into());
            s.set_scan_failed(false);
            s.set_scan_status("Reading your photo…".into());
        });
    }

    /// Read a photo already on the device: sharper than the camera, so better for handwriting.
    fn upload_photo(&self, share: Option<ShareIndex>) {
        let options = SelectFileOptions::default()
            .with_allowed_extensions(AllowedExtensions::specific(["jpg", "jpeg", "png", "webp"]));
        let picked = select_file::<gui_permissions::GuiPermissions>(options);
        let file = match picked {
            Ok(Some(result)) => result.files.into_iter().next(),
            Ok(None) => None,
            Err(e) => {
                log::warn!("file picker: {e:?}");
                self.upload_failed("The file picker couldn't open.");
                return;
            }
        };
        let Some((path, location)) = file else { return };
        let location = match location {
            PickerLocation::Internal => Location::User,
            PickerLocation::Airlock => Location::Airlock,
            PickerLocation::External => Location::Usb,
        };
        let photo = match self.read_photo(&path, location) {
            Ok(photo) => photo,
            Err(e) => {
                self.upload_failed(e);
                return;
            }
        };
        self.frozen.set(true);
        self.with_state(|s| {
            s.set_preview(Image::default());
            s.set_photo_reading(true);
            s.set_scan_hit(false);
            s.set_scan_error("".into());
            s.set_scan_failed(false);
            s.set_scan_status("Reading your photo…".into());
        });
        if !self.reader(self.source.get()).offer_upload(photo, share) {
            self.frozen.set(false);
            self.with_state(|s| s.set_photo_reading(false));
            self.upload_failed("Still reading the last photo. Try again in a moment.");
        }
    }

    fn read_photo(&self, path: &str, location: Location) -> Result<Vec<u8>, &'static str> {
        let unreadable = "That photo couldn't be opened.";
        let size = self.cx.fs.metadata(path, location).map_err(|_| unreadable)?.size;
        if size > MAX_UPLOAD_BYTES {
            return Err("That photo is too large. Use one under 32 MB.");
        }
        let mut file = self.cx.fs.open_file(path, location, OpenFlags::READ_ONLY).map_err(|_| unreadable)?;
        let mut photo = Vec::with_capacity(size as usize);
        file.read_to_end(&mut photo).map_err(|_| unreadable)?;
        Ok(photo)
    }

    fn upload_failed(&self, message: &str) {
        self.with_state(|s| {
            s.set_scan_error(message.into());
            s.set_scan_failed(true);
        });
    }

    fn retake_photo(&self) {
        self.draft.borrow_mut().clear();
        self.frozen.set(false);
        self.with_state(|s| {
            s.set_draft_ready(false);
            s.set_draft_complete(false);
            s.set_words_read(0);
            s.set_scan_hit(false);
            s.set_scan_status(self.searching().into());
        });
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

    fn sheet_text(&self, sheet: usize) -> Option<String> {
        let rows = self.ui().global::<PenlockState>().get_shares().row_data(sheet)?;
        let rows: Vec<String> =
            rows.rows.iter().map(|row| row.symbols.iter().map(|c| c.to_string()).collect()).collect();
        Some(format!("penlock v1 share {}\n{}", sheet + 1, rows.join("\n")))
    }

    /// Save one share on the screen as a strip image, under a name that can't replace an earlier one.
    fn save_share(&self, sheet: usize) {
        match self.write_share(sheet) {
            Ok(path) => {
                self.with_state(|s| s.set_saved_shares(s.get_saved_shares() + 1));
                self.toast(&format!("Share {} saved", sheet + 1), &format!("{path}, in your files."), ToastVariant::Success);
            }
            Err(e) => self.toast(&e, "", ToastVariant::Error),
        }
    }

    fn write_share(&self, sheet: usize) -> Result<String, String> {
        let text = self.sheet_text(sheet).ok_or("That share is gone.")?;
        let share = Share::parse(&text, None).map_err(|e| e.to_string())?;
        let png = std::thread::Builder::new()
            .name("share-image".into())
            .stack_size(RENDER_STACK)
            .spawn(move || backup::share_png(&share))
            .map_err(|e| e.to_string())?
            .join()
            .map_err(|_| "The image couldn't be drawn.".to_string())??;
        let now = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |since| since.as_secs());
        let path = backup::export_path(sheet as u8 + 1, now);
        // A share is the one file here that can't be remade, so nothing ever replaces one.
        if self.cx.fs.metadata(path.as_str(), Location::User).is_ok() {
            return Err("A file with that name exists. Try again in a moment.".to_string());
        }
        let failed = |e| {
            log::warn!("saving a share: {e:?}");
            "The image couldn't be saved.".to_string()
        };
        self.cx.fs.ensure_parent_dir_exists(&path, Location::User).map_err(failed)?;
        self.cx.fs.durable_file_write(&path, Location::User, &png).map_err(failed)?;
        Ok(path)
    }

    fn toast(&self, message: &str, detail: &str, variant: ToastVariant) {
        let ui = self.ui();
        let app = ui.global::<AppState>();
        app.set_toast(message.into());
        app.set_toast_detail(detail.into());
        app.set_toast_variant(variant);
    }

    fn read(&self, index: ShareIndex, cells: Cells, unread: usize) {
        let n = index.number();
        let better = self.scanned.borrow().get(&n).is_none_or(|(_, _, u)| unread < *u);
        if better {
            self.scanned.borrow_mut().insert(n, (index, cells, unread));
        }
        self.last_hit.set(Some(Instant::now()));
        let have: Vec<bool> = (1..=3).map(|i| self.scanned.borrow().contains_key(&i)).collect();
        self.frozen.set(false);
        self.with_state(|s| {
            s.set_photo_reading(false);
            s.set_have(ModelRc::new(VecModel::from(have)));
            s.set_scan_error("".into());
            s.set_scan_failed(false);
            s.set_can_sign_share(true);
            s.set_read_share(n as i32);
            s.set_scan_hit(true);
            s.set_scan_status(match unread {
                0 => format!("Read share {n} · now the next strip"),
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
                let kept = self.scanned.borrow().keys().next().copied();
                self.with_state(|s| {
                    s.set_have(ModelRc::new(VecModel::from(have)));
                    s.set_can_sign_share(kept.is_some());
                    s.set_read_share(kept.map_or(0, i32::from));
                    s.set_scan_hit(false);
                    s.set_scan_status(self.searching().into());
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
        photo_wanted: Cell::new(false),
        frozen: Cell::new(false),
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
        move || {
            p.open(PenlockScreen::Wallet);
            p.ui().global::<Callbacks>().invoke_wallet_back();
        }
    });
    cb.on_wallet_scan_share({
        let p = penlock.clone();
        move || {
            p.start_scan(Source::Shares);
            p.with_state(|s| s.set_scan_for_wallet(true));
        }
    });
    cb.on_save_share({
        let p = penlock.clone();
        move |sheet| p.save_share(sheet as usize)
    });
    cb.on_take_photo({
        let p = penlock.clone();
        move || p.take_photo()
    });
    cb.on_upload_photo({
        let p = penlock.clone();
        move || p.upload_photo(None)
    });
    cb.on_upload_share({
        let p = penlock.clone();
        move |sheet| p.upload_photo(ShareIndex::new(sheet as u8 + 1))
    });
    cb.on_retake_photo({
        let p = penlock.clone();
        move || p.retake_photo()
    });
    cb.on_review_draft({
        let p = penlock.clone();
        move || p.review_draft()
    });
    cb.on_sign_with_scanned({
        let p = penlock.clone();
        move || p.sign_with_scanned()
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
