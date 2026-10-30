// SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: MIT

// Reading Penlock share strips and handwritten phrases from camera frames with Bitcoin Vision's
// on-device models.
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
const READER_STACK: usize = 8 << 20;

#[derive(Clone, Copy, PartialEq)]
pub enum Source {
    Shares,
    Phrase,
    Qr,
}

pub enum Event {
    /// The model is loaded and reading.
    Ready,
    Failed(String),
    Read { index: ShareIndex, cells: Vec<[Distribution; WORD_LEN]>, unread: usize },
    /// A written phrase, in reading order. A passing checksum doesn't prove it was read correctly.
    Words { words: Vec<String>, checksum: bool },
    /// A QR code's text.
    Qr(String),
    /// The frame had nothing readable.
    Nothing,
}

pub struct Reader {
    frames: mpsc::SyncSender<RgbImage>,
    pub events: mpsc::Receiver<Event>,
}

impl Reader {
    pub fn start(source: Source) -> Self {
        // Zero capacity: a send only succeeds while the thread is blocked waiting for a frame.
        let (frames, frame_rx) = mpsc::sync_channel::<RgbImage>(0);
        let (event_tx, events) = mpsc::channel();
        std::thread::Builder::new()
            .name("penlock-reader".into())
            .stack_size(READER_STACK)
            .spawn(move || match source {
                Source::Shares => read_shares(frame_rx, event_tx),
                Source::Phrase => read_phrases(frame_rx, event_tx),
                Source::Qr => read_qr_codes(frame_rx, event_tx),
            })
            .expect("spawn reader thread");
        Self { frames, events }
    }

    /// Hand a frame to the reader if it is idle. Returns false (and drops the frame) if it is busy.
    pub fn offer(&self, frame: RgbImage) -> bool { self.frames.try_send(frame).is_ok() }
}

fn read_shares(frames: mpsc::Receiver<RgbImage>, events: mpsc::Sender<Event>) {
    let scanner = match Scanner::bundled() {
        Ok(s) => s,
        Err(e) => {
            let _ = events.send(Event::Failed(e.to_string()));
            return;
        }
    };
    let _ = events.send(Event::Ready);
    for frame in frames {
        let event = match scanner.scan_rgb(&frame, ScanOptions::default()) {
            Ok(result) => result
                .shares
                .into_iter()
                .find_map(|s| Some(Event::Read { index: s.identity.share()?, unread: s.unread.len(), cells: s.cells }))
                .unwrap_or(Event::Nothing),
            Err(_) => Event::Nothing,
        };
        if events.send(event).is_err() {
            break;
        }
    }
}

fn read_phrases(frames: mpsc::Receiver<RgbImage>, events: mpsc::Sender<Event>) {
    let scanner = match bitcoin_vision_words::Scanner::bundled() {
        Ok(s) => s,
        Err(e) => {
            let _ = events.send(Event::Failed(e.to_string()));
            return;
        }
    };
    let _ = events.send(Event::Ready);
    for frame in frames {
        let event = match scanner.scan_rgb(&frame, bitcoin_vision_words::ScanOptions::default()) {
            Ok(result) => {
                let document = result.document();
                let words: Vec<String> = document
                    .ordered_observations
                    .iter()
                    .filter_map(|&i| document.observations[i].selected.map(str::to_string))
                    .collect();
                if words.is_empty() {
                    Event::Nothing
                } else {
                    Event::Words { words, checksum: document.checksum_valid }
                }
            }
            Err(_) => Event::Nothing,
        };
        if events.send(event).is_err() {
            break;
        }
    }
}

fn read_qr_codes(frames: mpsc::Receiver<RgbImage>, events: mpsc::Sender<Event>) {
    let _ = events.send(Event::Ready);
    for frame in frames {
        let event = decode_qr(&frame).map_or(Event::Nothing, Event::Qr);
        if events.send(event).is_err() {
            break;
        }
    }
}

fn decode_qr(frame: &RgbImage) -> Option<String> {
    let mut image = rqrr::PreparedImage::prepare_from_greyscale(frame.width() as usize, frame.height() as usize, |x, y| {
        let [r, g, b] = frame.get_pixel(x as u32, y as u32).0;
        ((r as u16 + g as u16 + b as u16) / 3) as u8
    });
    image.detect_grids().iter().find_map(|grid| grid.decode().ok().map(|(_, text)| text))
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

#[cfg(test)]
mod tests {
    use image::Rgb;

    use super::*;

    fn frame_of(text: &str) -> RgbImage {
        let code = qrcode::QrCode::new(text.as_bytes()).unwrap();
        let modules = code.width() as u32;
        let colors = code.to_colors();
        let scale = SIZE / (modules + 8);
        let margin = (SIZE - modules * scale) / 2;
        RgbImage::from_fn(SIZE, SIZE, |x, y| {
            let inside = |v: u32| v >= margin && v < margin + modules * scale;
            let dark = inside(x) && inside(y) && {
                let (column, row) = ((x - margin) / scale, (y - margin) / scale);
                colors[(row * modules + column) as usize] == qrcode::Color::Dark
            };
            if dark { Rgb([0, 0, 0]) } else { Rgb([255, 255, 255]) }
        })
    }

    #[test]
    fn reads_qr_codes_at_camera_size() {
        // A short key, and a PSBT as long as the signing rounds produce.
        for length in [120, 900] {
            let text = "cHNidP8B".repeat(length / 8);
            assert_eq!(decode_qr(&frame_of(&text)).as_deref(), Some(text.as_str()));
        }
        assert_eq!(decode_qr(&RgbImage::new(SIZE, SIZE)), None);
    }
}
