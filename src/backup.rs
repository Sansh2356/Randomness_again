// SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: MIT

// Penlock 2-of-3 backups, entirely on the device.
//
// A phrase is split into three paper shares; any two give it back and one alone says nothing. The
// phrase and shares only ever live in memory while their screen is open: nothing here is logged or
// written to storage.

use penlock::word::WORD_LEN;
use penlock::{Distribution, Evidence, Share, ShareCount, ShareIndex, Word};

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
    let soft = penlock::recover_soft(a, index_a, b, index_b).map_err(|e| match e {
        penlock::SoftRecoverError::Shares(e) => format!("These strips don't belong together: {e}"),
        penlock::SoftRecoverError::Undecodable(words) => {
            let list: Vec<String> = words.iter().map(|(i, _)| (i + 1).to_string()).collect();
            format!("Couldn't read word {} clearly. Rescan with more light.", list.join(", "))
        }
    })?;
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
