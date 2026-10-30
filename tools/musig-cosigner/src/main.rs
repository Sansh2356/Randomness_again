// SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: MIT

// A laptop cosigner for the MuSig wallet, built on the same signer as the app. It keeps its nonces in
// memory, so it runs as one long session reading commands from stdin:
//
//   COSIGNER_NETWORK=mainnet ...                         sign on mainnet rather than signet
//   COSIGNER_PHRASE="twelve test words" cargo run       one participant from a phrase
//   COSIGNER_SHARE="$(cat share-2.txt)" cargo run        one participant from a Penlock share
//   cargo run -- split "twelve test words" DIRECTORY     write share-1.txt to share-3.txt
//   cargo run -- rebuild 3 share-1.txt share-2.txt       print a lost share from two others
//
// In a session:
//
//   add <passport tpub>
//   address <index>                 the shared signet address, as the Passport shows it
//   <any PSBT>                      take the next step, approving automatically
//
// It only signs. A PSBT comes from whatever wallet or coordinator built it. To read a transaction:
//
//   cargo run -- decode <transaction hex>
//
// Use throwaway phrases and shares. This is for testing and hasn't been audited.

#[path = "../../../src/musig.rs"]
mod musig;

use std::io::BufRead;
use std::path::Path;

use bitcoin::{Network, Transaction};
use musig::{Signer, Step};
use penlock::word::{Word, WORD_LEN};
use penlock::{Share, ShareCount, ShareIndex, Symbol};
use rand_core::{CryptoRng, RngCore};

struct OsRng;

impl RngCore for OsRng {
    fn next_u32(&mut self) -> u32 { rand_core::impls::next_u32_via_fill(self) }
    fn next_u64(&mut self) -> u64 { rand_core::impls::next_u64_via_fill(self) }
    fn fill_bytes(&mut self, dest: &mut [u8]) { getrandom::getrandom(dest).expect("system RNG") }
}

impl CryptoRng for OsRng {}

fn network() -> Network {
    match std::env::var("COSIGNER_NETWORK").as_deref() {
        Ok("mainnet") => Network::Bitcoin,
        _ => Network::Signet,
    }
}

fn decode(hex: &str) -> Result<(), String> {
    let tx: Transaction = bitcoin::consensus::encode::deserialize_hex(hex).map_err(|e| e.to_string())?;
    println!("txid {}", tx.compute_txid());
    println!("size {} bytes, {} vbytes", tx.total_size(), tx.vsize());
    for input in &tx.input {
        println!("in  {} witness items {}", input.previous_output, input.witness.len());
    }
    for out in &tx.output {
        let to = bitcoin::Address::from_script(&out.script_pubkey, network()).map_err(|e| e.to_string())?;
        println!("out {} sats to {to}", out.value.to_sat());
    }
    Ok(())
}

fn share_text(share: &Share) -> String {
    let rows: Vec<String> =
        share.words().iter().map(|row| row.iter().map(|sym| sym.to_char()).collect()).collect();
    format!("penlock v1 share {}\n{}", share.index().number(), rows.join("\n"))
}

fn split(phrase: &str, directory: &str) {
    let words: Vec<Word> =
        phrase.split_whitespace().map(|w| Word::from_bip39(w).expect("a BIP39 word")).collect();
    for share in penlock::split(&words, ShareCount::THREE, &mut OsRng) {
        let path = Path::new(directory).join(format!("share-{}.txt", share.index().number()));
        std::fs::write(path, share_text(&share)).expect("writing a share");
    }
}

/// Every symbol of every share lies on one line, so two shares give the third.
fn rebuild(a: &Share, b: &Share, target: ShareIndex) -> Option<Share> {
    let (xa, xb, x) = (a.index().symbol(), b.index().symbol(), target.symbol());
    let scale = (xb - xa).inv()?;
    let words = a.words().iter().zip(b.words()).map(|(ya, yb)| {
        let mut row = [Symbol::ZERO; WORD_LEN];
        for (position, cell) in row.iter_mut().enumerate() {
            let slope = (yb[position] - ya[position]) * scale;
            *cell = ya[position] + slope * (x - xa);
        }
        row
    });
    Some(Share::new(target, words.collect()))
}

fn share_from_file(path: &str) -> Share {
    Share::parse(&std::fs::read_to_string(path).expect("reading a share"), None).expect("a share")
}

fn signer_from_env() -> Signer {
    let network = network();
    if let Ok(text) = std::env::var("COSIGNER_SHARE") {
        let share = Share::parse(&text, None).expect("a share");
        let symbols: String = text.lines().skip(1).map(str::trim).collect();
        return Signer::from_share(share.index().number(), &symbols, network).expect("a signer");
    }
    let phrase = std::env::var("COSIGNER_PHRASE").expect("set COSIGNER_SHARE or COSIGNER_PHRASE");
    Signer::from_phrase(&phrase, network).expect("a valid phrase")
}

fn step(signer: &mut Signer, text: &str) -> Result<String, String> {
    let mut psbt = musig::parse_psbt(text.as_bytes())?;
    match signer.inspect(&psbt)? {
        Step::Nonce(review) => {
            eprintln!("approving {review:?}");
            signer.add_nonces(&mut psbt)?;
        }
        Step::Sign => signer.add_signatures(&mut psbt)?,
        Step::Finalize => return signer.finalize(&mut psbt),
    }
    Ok(psbt.to_string())
}

fn run(signer: &mut Signer, line: &str) -> Result<String, String> {
    let words: Vec<&str> = line.split_whitespace().collect();
    match words.as_slice() {
        ["add", key] => signer.add_cosigner(key).map(|()| "ok".into()),
        ["address", index] => signer.address(musig::RECEIVE, index.parse().map_err(|_| "bad index")?),
        [psbt] => step(signer, psbt),
        _ => Err("unknown command".into()),
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.iter().map(String::as_str).collect::<Vec<_>>().as_slice() {
        ["split", phrase, directory] => return split(phrase, directory),
        ["rebuild", number, a, b] => {
            let target = number.parse().ok().and_then(ShareIndex::new).expect("a share number");
            let rebuilt = rebuild(&share_from_file(a), &share_from_file(b), target).expect("two different shares");
            return println!("{}", share_text(&rebuilt));
        }
        ["decode", hex] => {
            if let Err(e) = decode(hex) {
                println!("error: {e}");
            }
            return;
        }
        _ => {}
    }
    let mut signer = signer_from_env();
    println!("{}", signer.xpub());
    for line in std::io::stdin().lock().lines() {
        match run(&mut signer, &line.expect("reading stdin")) {
            Ok(out) => println!("{out}"),
            Err(e) => println!("error: {e}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn any_two_shares_rebuild_the_third() {
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let words: Vec<Word> = phrase.split_whitespace().map(|w| Word::from_bip39(w).unwrap()).collect();
        let shares = penlock::split(&words, ShareCount::THREE, &mut OsRng);
        for (a, b, c) in [(0, 1, 2), (0, 2, 1), (1, 2, 0)] {
            assert_eq!(rebuild(&shares[a], &shares[b], shares[c].index()).unwrap(), shares[c]);
        }
    }
}
