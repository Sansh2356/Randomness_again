// SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: MIT

// A laptop cosigner for the MuSig wallet, built on the same signer as the app. It keeps its nonces in
// memory, so it runs as one long session reading commands from stdin:
//
//   COSIGNER_PHRASE="twelve test words" cargo run       one participant from a phrase
//   COSIGNER_SHARE="$(cat share-2.txt)" cargo run        one participant from a Penlock share
//   cargo run -- split "twelve test words" DIRECTORY     write share-1.txt to share-3.txt
//   cargo run -- rebuild 3 share-1.txt share-2.txt       print a lost share from two others
//
// In a session:
//
//   add <passport tpub>
//   address <index>                 the shared signet address, as the Passport shows it
//   script <chain> <index>          its output script, hex
//   new <txid> <vout> <sats> <index> <to script hex> <send sats> <fee sats>
//   <any PSBT>                      take the next step, approving automatically
//
// Use throwaway phrases and shares. This is for testing, on signet.

#[path = "../../../src/musig.rs"]
mod musig;

use std::io::BufRead;
use std::path::Path;
use std::str::FromStr;

use bitcoin::absolute::LockTime;
use bitcoin::psbt::Psbt;
use bitcoin::transaction::Version;
use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid};
use musig::{Signer, Step, CHANGE};
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
    if let Ok(text) = std::env::var("COSIGNER_SHARE") {
        let share = Share::parse(&text, None).expect("a share");
        let symbols: String = text.lines().skip(1).map(str::trim).collect();
        return Signer::from_share(share.index().number(), &symbols).expect("a signer");
    }
    let phrase = std::env::var("COSIGNER_PHRASE").expect("set COSIGNER_SHARE or COSIGNER_PHRASE");
    Signer::from_phrase(&phrase).expect("a valid phrase")
}

fn new_psbt(signer: &Signer, args: &[&str]) -> Result<Psbt, String> {
    let [txid, vout, sats, index, to, send, fee] = args else {
        return Err("new <txid> <vout> <sats> <index> <to script hex> <send sats> <fee sats>".into());
    };
    let number = |s: &str| s.parse::<u64>().map_err(|e| e.to_string());
    let (spent, send, fee) = (number(sats)?, number(send)?, number(fee)?);
    let change = spent.checked_sub(send + fee).ok_or("not enough to spend")?;
    let input = TxIn {
        previous_output: OutPoint { txid: Txid::from_str(txid).map_err(|e| e.to_string())?, vout: number(vout)? as u32 },
        sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
        ..Default::default()
    };
    let to = ScriptBuf::from_hex(to).map_err(|e| e.to_string())?;
    let output = vec![
        TxOut { value: Amount::from_sat(send), script_pubkey: to },
        TxOut { value: Amount::from_sat(change), script_pubkey: signer.script(CHANGE, 0)? },
    ];
    let tx = Transaction { version: Version::TWO, lock_time: LockTime::ZERO, input: vec![input], output };
    let mut psbt = Psbt::from_unsigned_tx(tx).map_err(|e| e.to_string())?;
    let script_pubkey = signer.script(musig::RECEIVE, number(index)? as u32)?;
    psbt.inputs[0].witness_utxo = Some(TxOut { value: Amount::from_sat(spent), script_pubkey });
    Ok(psbt)
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
        ["script", chain, index] => {
            let (chain, index) = (chain.parse().map_err(|_| "bad chain")?, index.parse().map_err(|_| "bad index")?);
            Ok(signer.script(chain, index)?.to_hex_string())
        }
        ["new", args @ ..] => Ok(new_psbt(signer, args)?.to_string()),
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
