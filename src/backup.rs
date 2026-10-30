// SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: MIT

// Penlock 2-of-3 backups, entirely on the device.
//
// A phrase is split into three paper shares; any two give it back and one alone says nothing. The
// phrase and shares only ever live in memory while their screen is open, and nothing here is logged.
// The one thing that reaches storage is a share the person chose to export as an image.

use std::io::Cursor;

use bitcoin_vision_forms::render::Font;
use image::ImageFormat;
use penlock::word::WORD_LEN;
use penlock::{Distribution, Evidence, Share, ShareCount, ShareIndex, Word};
use penlock_scan::sheet::{cut_strip, front_png, Fill};

/// Hardware randomness for the split, through the SDK's getrandom 0.2 (the TRNG on device).
pub struct Trng;

impl rand_core::RngCore for Trng {
    fn next_u32(&mut self) -> u32 { rand_core::impls::next_u32_via_fill(self) }
    fn next_u64(&mut self) -> u64 { rand_core::impls::next_u64_via_fill(self) }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        // A share is only secret if its randomness is; never fall back to anything weaker.
        getrandom::getrandom(dest).expect("hardware RNG unavailable");
    }
}

impl rand_core::CryptoRng for Trng {}

/// Phrase lengths a Penlock worksheet holds.
pub const LENGTHS: [usize; 2] = [12, 24];

#[derive(Debug, PartialEq)]
pub enum PhraseCheck {
    Empty,
    /// Words typed so far, all recognised.
    Incomplete(usize),
    /// 1-based position and the word as typed.
    UnknownWord(usize, String),
    TooLong(usize),
    BadChecksum(usize),
    Valid(Vec<Word>),
}

impl PhraseCheck {
    /// One line for under the input. Errors are worded as what to do next.
    pub fn message(&self) -> String {
        match self {
            Self::Empty => "Enter 12 or 24 words, separated by spaces.".into(),
            Self::Incomplete(n) => {
                let target = if *n <= 12 { 12 } else { 24 };
                format!("{n} of {target} words")
            }
            Self::UnknownWord(i, w) => format!("Word {i}, \u{201c}{w}\u{201d}, isn't a BIP39 word. Check it for a typo."),
            Self::TooLong(n) => format!("{n} words is too many: Penlock takes 12 or 24"),
            Self::BadChecksum(n) => format!("These {n} words fail the BIP39 checksum. Check each one for a typo"),
            Self::Valid(w) => format!("Valid {}-word phrase · checksum OK", w.len()),
        }
    }
}

/// Validate a phrase as it is typed. The word still being typed is only flagged once no BIP39 word
/// starts with it, so the field doesn't go red mid-word.
pub fn check_phrase(text: &str) -> PhraseCheck {
    let lower = text.to_lowercase();
    let tokens: Vec<&str> = lower.split_whitespace().collect();
    if tokens.is_empty() {
        return PhraseCheck::Empty;
    }
    let still_typing = !text.ends_with(char::is_whitespace);
    let mut words = Vec::with_capacity(tokens.len());
    for (i, token) in tokens.iter().enumerate() {
        match Word::from_bip39(token) {
            Some(w) => words.push(w),
            None if still_typing && i + 1 == tokens.len() && Word::all().any(|w| w.as_str().starts_with(token)) => {
                return PhraseCheck::Incomplete(words.len());
            }
            None => return PhraseCheck::UnknownWord(i + 1, token.to_string()),
        }
    }
    match words.len() {
        n if n > 24 => PhraseCheck::TooLong(n),
        n if !LENGTHS.contains(&n) => PhraseCheck::Incomplete(n),
        n if !penlock::backup::bip39_checksum_ok(&words) => PhraseCheck::BadChecksum(n),
        _ => PhraseCheck::Valid(words),
    }
}

/// The phrase as typed so far, word by word, each marked if it can't be a BIP39 word. The word still
/// being typed isn't marked while one could start with it, the same as `check_phrase`.
pub fn typed_words(text: &str) -> Vec<(String, bool)> {
    let lower = text.to_lowercase();
    let tokens: Vec<&str> = lower.split_whitespace().collect();
    let still_typing = !text.ends_with(char::is_whitespace);
    tokens
        .iter()
        .enumerate()
        .map(|(i, token)| {
            let typing = still_typing && i + 1 == tokens.len() && Word::all().any(|w| w.as_str().starts_with(token));
            (token.to_string(), Word::from_bip39(token).is_none() && !typing)
        })
        .collect()
}

/// Split into three shares, then check the split recovers the phrase from every pair before anyone
/// copies it onto paper.
pub fn split(words: &[Word]) -> Result<Vec<Share>, String> {
    let shares = penlock::split(words, ShareCount::THREE, &mut Trng);
    penlock::verify(words, &shares).map_err(|e| format!("Self-check failed: {e}"))?;
    Ok(shares)
}

/// A share as worksheet rows of six symbols, the two checksum symbols first.
pub fn rows(share: &Share) -> Vec<[char; WORD_LEN]> {
    share.words().iter().map(|w| w.map(|sym| sym.to_char())).collect()
}

// Sharp enough to read back: a worksheet box is about 8 mm, so about 90 pixels across.
const EXPORT_DPI: f64 = 220.0;

/// A share drawn on its worksheet strip, as a PNG the strip reader can read back. A worksheet holds 12
/// words, so a 24-word share can't be exported. PNG rather than JPEG: blur could cost a symbol.
pub fn share_png(share: &Share) -> Result<Vec<u8>, String> {
    // The cell reader was trained on handwriting, and reads this font exactly where it misreads print.
    let fill = Fill::new(None, &[share], Font::PatrickHand).map_err(|_| "Only 12-word shares fit on a strip image.".to_string())?;
    let page = front_png(Some(&fill), EXPORT_DPI).map_err(|e| e.to_string())?;
    let strip = cut_strip(&page, EXPORT_DPI, usize::from(share.index().number()));
    let mut png = Cursor::new(Vec::new());
    strip.write_to(&mut png, ImageFormat::Png).map_err(|e| e.to_string())?;
    Ok(png.into_inner())
}

/// Where a share saved at `unix_seconds` goes, in UTC: penlock/penlock-share-1_2026-10-30_15-49-12.png.
pub fn export_path(number: u8, unix_seconds: u64) -> String {
    let (days, seconds) = (unix_seconds / 86_400, unix_seconds % 86_400);
    // Days to a calendar date, counted from 1 March 0000 so that leap days fall last in a year.
    let z = days + 719_468;
    let era = z / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + u64::from(month <= 2);
    let (hour, minute, second) = (seconds / 3_600, seconds / 60 % 60, seconds % 60);
    format!("penlock/penlock-share-{number}_{year:04}-{month:02}-{day:02}_{hour:02}-{minute:02}-{second:02}.png")
}

/// A share as `Share::parse` reads it, for handing between screens.
pub fn share_text(share: &Share) -> String {
    let rows: Vec<String> = rows(share).iter().map(|row| row.iter().collect()).collect();
    format!("penlock v1 share {}\n{}", share.index().number(), rows.join("\n"))
}

/// The most likely reading of one strip. With no second share there's nothing to check it against.
pub fn share_from_cells(index: ShareIndex, cells: &[[Distribution; WORD_LEN]]) -> Share {
    Share::new(index, cells.iter().map(|row| row.map(|cell| cell.argmax())).collect())
}

pub struct Recovered {
    pub words: Vec<Word>,
    /// Rows worth rechecking on paper, one line each (1-based).
    pub corrections: Vec<String>,
}

/// Recover the phrase from two scanned shares, letting the per-word checksums fix misread cells.
pub fn recover(
    a: &[[Distribution; WORD_LEN]],
    index_a: ShareIndex,
    b: &[[Distribution; WORD_LEN]],
    index_b: ShareIndex,
) -> Result<Recovered, String> {
    let soft = match penlock::recover_soft(a, index_a, b, index_b) {
        Ok(soft) => soft,
        Err(penlock::SoftRecoverError::Shares(e)) => return Err(format!("These strips don't belong together: {e}")),
        Err(penlock::SoftRecoverError::Undecodable(words)) => {
            // The model can be unsure of cells it read correctly. Every word's own checksum, and the
            // phrase's, still have to pass on its plain readings, with nothing corrected.
            let plain = penlock::recover(&share_from_cells(index_a, a), &share_from_cells(index_b, b));
            if let Ok(exact) = plain.as_ref().map_err(|_| ()).and_then(|r| {
                if r.corrections.is_empty() && r.bip39_checksum_ok { Ok(r) } else { Err(()) }
            }) {
                return Ok(Recovered { words: exact.words.clone(), corrections: Vec::new() });
            }
            let list: Vec<String> = words.iter().map(|(i, _)| (i + 1).to_string()).collect();
            return Err(format!("Couldn't read word {} clearly. Rescan with more light.", list.join(", ")));
        }
    };
    if !penlock::backup::bip39_checksum_ok(&soft.words) {
        return Err("The words read don't pass the BIP39 checksum. Rescan both strips.".into());
    }
    // Evidence is about the combined (secret) symbols, which appear on neither strip, so point the
    // person at the row to recheck rather than at a letter.
    let mut corrections: Vec<String> = Vec::new();
    for (word, ev) in &soft.evidence {
        let line = match ev {
            Evidence::Substituted { .. } => format!("Row {}: misread, fixed by its checksum", word + 1),
            Evidence::LowConfidence { .. } => format!("Row {}: faint, read with low confidence", word + 1),
        };
        if !corrections.contains(&line) {
            corrections.push(line);
        }
    }
    Ok(Recovered { words: soft.words, corrections })
}

#[cfg(test)]
mod tests {
    use super::*;

    const PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    #[test]
    fn phrase_checks() {
        assert_eq!(check_phrase(""), PhraseCheck::Empty);
        assert_eq!(check_phrase("abandon aban"), PhraseCheck::Incomplete(1), "mid-word is not an error");
        assert_eq!(check_phrase("abandon abanx"), PhraseCheck::UnknownWord(2, "abanx".into()));
        assert_eq!(check_phrase("abandon zzz abandon"), PhraseCheck::UnknownWord(2, "zzz".into()));
        let bad = PHRASE.replace("about", "abandon");
        assert_eq!(check_phrase(&bad), PhraseCheck::BadChecksum(12));
        assert!(matches!(check_phrase(&PHRASE.to_uppercase()), PhraseCheck::Valid(w) if w.len() == 12));
    }

    #[test]
    fn exported_shares_read_back_and_recover_the_phrase() {
        let PhraseCheck::Valid(words) = check_phrase(PHRASE) else { panic!() };
        let shares = split(&words).unwrap();
        let scanner = penlock_scan::Scanner::bundled().unwrap();
        let read = |share: &Share| {
            let png = share_png(share).unwrap();
            let result = scanner.scan(&png, penlock_scan::ScanOptions::default()).unwrap();
            let strip = result.shares.into_iter().next().expect("the strip is found");
            assert_eq!(strip.identity.share(), Some(share.index()));
            strip.cells
        };
        let (a, b) = (read(&shares[0]), read(&shares[2]));
        let got = recover(&a, shares[0].index(), &b, shares[2].index()).unwrap();
        assert_eq!(got.words, words);
        assert!(got.corrections.is_empty(), "{:?}", got.corrections);
    }

    #[test]
    fn exports_are_named_by_share_date_and_time() {
        assert_eq!(export_path(1, 0), "penlock/penlock-share-1_1970-01-01_00-00-00.png");
        assert_eq!(export_path(2, 951_868_800), "penlock/penlock-share-2_2000-03-01_00-00-00.png");
        assert_eq!(export_path(3, 1_709_164_800 + 3_661), "penlock/penlock-share-3_2024-02-29_01-01-01.png");
    }

    #[test]
    fn long_shares_are_refused_as_images() {
        let words: Vec<Word> = (0..24).map(|_| Word::from_bip39("abandon").unwrap()).collect();
        let shares = penlock::split(&words, ShareCount::THREE, &mut Trng);
        assert!(share_png(&shares[0]).is_err());
    }

    #[test]
    fn typed_words_mark_only_what_cannot_be_a_word() {
        let flags = |text| typed_words(text).into_iter().map(|(_, bad)| bad).collect::<Vec<_>>();
        assert_eq!(flags("abandon aban"), [false, false], "mid-word is not an error");
        assert_eq!(flags("abandon aban "), [false, true], "a finished word has to be whole");
        assert_eq!(flags("zzz abandon"), [true, false]);
        assert!(typed_words("").is_empty());
    }

    #[test]
    fn split_then_recover_any_pair() {
        let PhraseCheck::Valid(words) = check_phrase(PHRASE) else { panic!() };
        let shares = split(&words).unwrap();
        assert_eq!(shares.len(), 3);
        assert_eq!(rows(&shares[0]).len(), 12);

        let (a, b) = (&shares[0], &shares[2]);
        let got = recover(
            &penlock::soft::one_hot_share(a),
            a.index(),
            &penlock::soft::one_hot_share(b),
            b.index(),
        )
        .unwrap();
        assert_eq!(got.words, words);
        assert!(got.corrections.is_empty());

        // Two strips of the same share can't be combined.
        let same = penlock::soft::one_hot_share(a);
        assert!(recover(&same, a.index(), &same, a.index()).is_err());
    }
}
