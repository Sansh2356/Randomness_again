// SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: MIT

// Reading Penlock share strips from camera frames with Bitcoin Vision's on-device model.
//
// Inference takes far longer than a frame, so it runs on its own thread. Frames are only handed over
// while that thread is idle, so the preview never waits on the model and no backlog builds up.

use std::sync::mpsc;

use image::RgbImage;
use penlock::word::WORD_LEN;
use penlock::{Distribution, ShareIndex};
use penlock_scan::{ScanOptions, Scanner};
use slint_keyos_platform::slint::{Rgb8Pixel, SharedPixelBuffer};

pub const SIZE: u32 = camera::CAMERA_WIDTH as u32;
// tract's graph optimisation recurses deeply; the KeyOS default thread stack is too small for it.
// ponytail: fixed guess, raise it if the reader thread faults while loading the model.
const READER_STACK: usize = 4 << 20;

pub enum Event {
    /// The model is loaded and reading.
    Ready,
    Failed(String),
    Read { index: ShareIndex, cells: Vec<[Distribution; WORD_LEN]>, unread: usize },
    /// The frame had no readable share strip.
    Nothing,
}

pub struct Reader {
    frames: mpsc::SyncSender<RgbImage>,
    pub events: mpsc::Receiver<Event>,
}

impl Reader {
    pub fn start() -> Self {
        // Zero capacity: a send only succeeds while the thread is blocked waiting for a frame.
        let (frames, frame_rx) = mpsc::sync_channel::<RgbImage>(0);
        let (event_tx, events) = mpsc::channel();
        std::thread::Builder::new()
            .name("penlock-reader".into())
            .stack_size(READER_STACK)
            .spawn(move || {
                let scanner = match Scanner::bundled() {
                    Ok(s) => s,
                    Err(e) => {
                        let _ = event_tx.send(Event::Failed(e.to_string()));
                        return;
                    }
                };
                let _ = event_tx.send(Event::Ready);
                for frame in frame_rx {
                    let event = match scanner.scan_rgb(&frame, ScanOptions::default()) {
                        Ok(result) => result
                            .shares
                            .into_iter()
                            .find_map(|s| {
                                Some(Event::Read { index: s.identity.share()?, unread: s.unread.len(), cells: s.cells })
                            })
                            .unwrap_or(Event::Nothing),
                        Err(_) => Event::Nothing,
                    };
                    if event_tx.send(event).is_err() {
                        break;
                    }
                }
            })
            .expect("spawn reader thread");
        Self { frames, events }
    }

    /// Hand a frame to the reader if it is idle. Returns false (and drops the frame) if it is busy.
    pub fn offer(&self, frame: RgbImage) -> bool { self.frames.try_send(frame).is_ok() }
}

/// Convert the visible part of a camera frame into the model's input and a preview buffer.
pub fn convert(content: &[u8]) -> (RgbImage, SharedPixelBuffer<Rgb8Pixel>) {
    let mut rgb = Vec::with_capacity((SIZE * SIZE * 3) as usize);
    #[cfg(keyos)]
    for px in content.chunks_exact(2) {
        // RGB565, little-endian.
        let v = u16::from_le_bytes([px[0], px[1]]);
        let (r, g, b) = ((v >> 11) & 0x1F, (v >> 5) & 0x3F, v & 0x1F);
        rgb.extend_from_slice(&[(r << 3 | r >> 2) as u8, (g << 2 | g >> 4) as u8, (b << 3 | b >> 2) as u8]);
    }
    #[cfg(not(keyos))]
    for px in content.chunks_exact(4) {
        // The simulator's frames are RGBA.
        rgb.extend_from_slice(&px[..3]);
    }
    let preview = SharedPixelBuffer::clone_from_slice(&rgb, SIZE, SIZE);
    (RgbImage::from_raw(SIZE, SIZE, rgb).expect("frame is SIZE x SIZE"), preview)
}
