// SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: MIT

// MuSig2 (BIP327) taproot key-spend wallet, signing PSBTs that carry BIP373 fields.
//
// Every participant holds an account xpub. An address is the MuSig2 aggregate of each participant's
// key at <chain>/<index>, with the BIP341 no-script tweak. The Passport has no network, so PSBTs travel
// by QR through three steps: add our nonce, add our partial signature, and join the signatures.
//
// A signer's key comes from a seed phrase, or from one Penlock share. Two shares of one backup can sign
// together this way without either device seeing the other's share or the phrase: each share is its own
// MuSig2 participant. A single strip has no checksum, so a misread one gives a different key, and the
// fingerprint is how a person notices.
//
// Only the account key and the public keys of the cosigners are held, and only in memory.
// Signet is the default. Mainnet is the person's explicit choice: this code hasn't been audited.

use std::collections::BTreeMap;
use std::str::FromStr;

use bip39::{Language, Mnemonic};
use bitcoin::bip32::{ChildNumber, DerivationPath, Fingerprint, Xpriv, Xpub};
use bitcoin::hashes::{hmac, sha512, Hash, HashEngine};
use bitcoin::psbt::{raw, Psbt};
use bitcoin::secp256k1::{All, PublicKey, Secp256k1, SecretKey, XOnlyPublicKey};
use bitcoin::sighash::{Prevouts, SighashCache};
use bitcoin::{Address, Network, NetworkKind, ScriptBuf, TapSighashType, TxOut, Txid, Witness};
use musig2::secp::{MaybeScalar, Point, Scalar};
use musig2::{AggNonce, KeyAggContext, LiftedSignature, PartialSignature, PubNonce, SecNonce};

pub const NOT_A_PSBT: &str = "That isn't a PSBT";
// A fee above this is refused outright, whatever the rate: it's a mistake or an attack.
pub const FEE_CEILING: u64 = 1_000_000;
pub const RECEIVE: u32 = 0;
pub const CHANGE: u32 = 1;
// How many addresses per chain are matched against a PSBT.
const GAP: u32 = 50;

// BIP373 PSBT input fields.
const IN_PARTICIPANTS: u8 = 0x1a;
const IN_PUB_NONCE: u8 = 0x1b;
const IN_PARTIAL_SIG: u8 = 0x1c;

// Domain separation for share keys. Changing it changes every share wallet's addresses.
const SHARE_KEY_TAG: &[u8] = b"penlock-share-musig2-key/v1";

const COMPRESSED: usize = 33;
const PUB_NONCE: usize = 66;
const PARTIAL_SIG: usize = 32;

/// What a scanned PSBT needs from this signer next.
pub enum Step {
    /// First sight of this transaction: review it, then add our nonce.
    Nonce(Review),
    /// Everyone's nonces are in, and we hold ours: add our partial signature.
    Sign,
    /// Everyone has signed: join the signatures into a transaction.
    Finalize,
}

/// What the person approves. Only outputs we can't prove are ours count as sends.
#[derive(Debug, PartialEq)]
pub struct Review {
    pub sends: Vec<(String, u64)>,
    pub change: u64,
    pub fee: u64,
}

/// Secret nonces waiting for the second round. They are single use: signing takes them out of the
/// signer before anything else happens, so no failure can leave them around to be used again.
struct Pending {
    txid: Txid,
    sighashes: Vec<[u8; 32]>,
    nonces: Vec<SecNonce>,
}

/// One address's keys.
struct Slot {
    seckey: SecretKey,
    pubkey: [u8; COMPRESSED],
    participants: Vec<[u8; COMPRESSED]>,
    plain: [u8; COMPRESSED],
    tweaked: KeyAggContext,
}

pub struct Signer {
    secp: Secp256k1<All>,
    network: Network,
    account: Xpriv,
    xpub: Xpub,
    cosigners: Vec<Xpub>,
    // Output script to (chain, index), rebuilt when the cosigners change.
    scripts: BTreeMap<ScriptBuf, (u32, u32)>,
    pending: Option<Pending>,
}

fn err(e: impl std::fmt::Display) -> String { e.to_string() }

fn parse_keys(value: &[u8]) -> Result<Vec<[u8; COMPRESSED]>, String> {
    if value.is_empty() || value.len() % COMPRESSED != 0 {
        return Err("This PSBT has a malformed participant list".into());
    }
    Ok(value.chunks_exact(COMPRESSED).map(|c| c.try_into().expect("chunk is 33 bytes")).collect())
}

fn field_key(kind: u8, key: Vec<u8>) -> raw::Key { raw::Key { type_value: kind, key } }

/// The BIP373 key of a nonce or partial signature: the participant, then the aggregate it's for.
fn participant_key(kind: u8, participant: &[u8; COMPRESSED], plain: &[u8; COMPRESSED]) -> raw::Key {
    field_key(kind, [participant.as_slice(), plain.as_slice()].concat())
}

impl Signer {
    pub fn from_phrase(phrase: &str, network: Network) -> Result<Self, String> {
        let words = phrase.split_whitespace().collect::<Vec<_>>().join(" ").to_lowercase();
        let mnemonic = Mnemonic::parse_in_normalized(Language::English, &words).map_err(err)?;
        Self::from_seed(&mnemonic.to_seed(""), network)
    }

    /// A signer of its own for one Penlock share: its number and its symbols, row after row.
    pub fn from_share(number: u8, symbols: &str, network: Network) -> Result<Self, String> {
        let mut engine = hmac::HmacEngine::<sha512::Hash>::new(SHARE_KEY_TAG);
        engine.input(&[number]);
        engine.input(symbols.as_bytes());
        Self::from_seed(hmac::Hmac::<sha512::Hash>::from_engine(engine).as_byte_array(), network)
    }

    fn from_seed(seed: &[u8], network: Network) -> Result<Self, String> {
        let secp = Secp256k1::new();
        let master = Xpriv::new_master(network, seed).map_err(err)?;
        // BIP86: mainnet's coin type is 0, and every test network's is 1.
        let coin = if network == Network::Bitcoin { 0 } else { 1 };
        let path = DerivationPath::from_str(&format!("m/86'/{coin}'/0'")).map_err(err)?;
        let account = master.derive_priv(&secp, &path).map_err(err)?;
        let xpub = Xpub::from_priv(&secp, &account);
        Ok(Self { secp, network, account, xpub, cosigners: Vec::new(), scripts: BTreeMap::new(), pending: None })
    }

    pub fn xpub(&self) -> String { self.xpub.to_string() }

    pub fn fingerprint(&self) -> Fingerprint { self.xpub.fingerprint() }

    pub fn cosigners(&self) -> usize { self.cosigners.len() }

    pub fn add_cosigner(&mut self, text: &str) -> Result<(), String> {
        let xpub = Xpub::from_str(text.trim()).map_err(|_| "That isn't an extended public key".to_string())?;
        if xpub.network != NetworkKind::from(self.network) {
            return Err("That key is for a different network".into());
        }
        if xpub == self.xpub {
            return Err("That's this wallet's own key".into());
        }
        if self.cosigners.contains(&xpub) {
            return Err("That cosigner is already added".into());
        }
        self.cosigners.push(xpub);
        self.pending = None;
        self.index_scripts()
    }

    fn index_scripts(&mut self) -> Result<(), String> {
        let mut scripts = BTreeMap::new();
        for chain in [RECEIVE, CHANGE] {
            for index in 0..GAP {
                scripts.insert(self.script(chain, index)?, (chain, index));
            }
        }
        self.scripts = scripts;
        Ok(())
    }

    fn slot(&self, chain: u32, index: u32) -> Result<Slot, String> {
        let path = [
            ChildNumber::from_normal_idx(chain).map_err(err)?,
            ChildNumber::from_normal_idx(index).map_err(err)?,
        ];
        let seckey = self.account.derive_priv(&self.secp, &path).map_err(err)?.private_key;
        let pubkey = PublicKey::from_secret_key(&self.secp, &seckey).serialize();
        let mut participants = vec![pubkey];
        for cosigner in &self.cosigners {
            participants.push(cosigner.derive_pub(&self.secp, &path).map_err(err)?.public_key.serialize());
        }
        // BIP327 KeySort, so every participant aggregates the same list.
        participants.sort();
        let points: Vec<Point> =
            participants.iter().map(|k| Point::from_slice(k).map_err(err)).collect::<Result<_, _>>()?;
        let context = KeyAggContext::new(points).map_err(err)?;
        let plain: Point = context.aggregated_pubkey();
        let tweaked = context.with_unspendable_taproot_tweak().map_err(err)?;
        Ok(Slot { seckey, pubkey, participants, plain: plain.serialize(), tweaked })
    }

    pub fn script(&self, chain: u32, index: u32) -> Result<ScriptBuf, String> {
        let slot = self.slot(chain, index)?;
        let internal = XOnlyPublicKey::from_slice(&slot.plain[1..]).map_err(err)?;
        Ok(ScriptBuf::new_p2tr(&self.secp, internal, None))
    }

    pub fn address(&self, chain: u32, index: u32) -> Result<String, String> {
        if self.cosigners.is_empty() {
            return Err("Add a cosigner first".into());
        }
        let script = self.script(chain, index)?;
        Ok(Address::from_script(&script, self.network).map_err(err)?.to_string())
    }

    fn slot_of(&self, script: &ScriptBuf) -> Result<Slot, String> {
        let (chain, index) = self.scripts.get(script).ok_or("An input isn't from this wallet")?;
        self.slot(*chain, *index)
    }

    /// Every input's amount and script, which the signature commits to.
    fn prevouts(psbt: &Psbt) -> Result<Vec<TxOut>, String> {
        psbt.inputs
            .iter()
            .map(|input| input.witness_utxo.clone().ok_or_else(|| "An input is missing its amount".to_string()))
            .collect()
    }

    fn sighashes(psbt: &Psbt, prevouts: &[TxOut]) -> Result<Vec<[u8; 32]>, String> {
        let mut cache = SighashCache::new(&psbt.unsigned_tx);
        let mut hashes = Vec::with_capacity(prevouts.len());
        for (i, input) in psbt.inputs.iter().enumerate() {
            if input.sighash_type.is_some_and(|t| t.taproot_hash_ty() != Ok(TapSighashType::Default)) {
                return Err("This PSBT asks for an unusual signature type".into());
            }
            let hash = cache
                .taproot_key_spend_signature_hash(i, &Prevouts::All(prevouts), TapSighashType::Default)
                .map_err(err)?;
            hashes.push(hash.to_byte_array());
        }
        Ok(hashes)
    }

    fn slots(&self, psbt: &Psbt, prevouts: &[TxOut]) -> Result<Vec<Slot>, String> {
        let slots: Vec<Slot> = prevouts.iter().map(|p| self.slot_of(&p.script_pubkey)).collect::<Result<_, _>>()?;
        // A coordinator can't quietly swap in a different cosigner.
        for (input, slot) in psbt.inputs.iter().zip(&slots) {
            if let Some(listed) = input.unknown.get(&field_key(IN_PARTICIPANTS, slot.plain.to_vec())) {
                if parse_keys(listed)? != slot.participants {
                    return Err("This PSBT lists different cosigners".into());
                }
            }
        }
        Ok(slots)
    }

    fn all_present(psbt: &Psbt, slots: &[Slot], kind: u8) -> bool {
        psbt.inputs.iter().zip(slots).all(|(input, slot)| {
            slot.participants.iter().all(|p| input.unknown.contains_key(&participant_key(kind, p, &slot.plain)))
        })
    }

    pub fn inspect(&self, psbt: &Psbt) -> Result<Step, String> {
        if self.cosigners.is_empty() {
            return Err("Add a cosigner first".into());
        }
        let prevouts = Self::prevouts(psbt)?;
        let slots = self.slots(psbt, &prevouts)?;
        if Self::all_present(psbt, &slots, IN_PARTIAL_SIG) {
            return Ok(Step::Finalize);
        }
        let waiting = self.pending.as_ref().is_some_and(|p| p.txid == psbt.unsigned_tx.compute_txid());
        if waiting && Self::all_present(psbt, &slots, IN_PUB_NONCE) {
            return Ok(Step::Sign);
        }
        if waiting {
            return Err("Still waiting for the cosigners' nonces".into());
        }
        if psbt.inputs.iter().zip(&slots).any(|(input, slot)| {
            input.unknown.contains_key(&participant_key(IN_PARTIAL_SIG, &slot.pubkey, &slot.plain))
        }) {
            return Err("This Passport has already signed that transaction".into());
        }
        self.review(psbt, &prevouts).map(Step::Nonce)
    }

    fn review(&self, psbt: &Psbt, prevouts: &[TxOut]) -> Result<Review, String> {
        let spent = prevouts.iter().try_fold(0u64, |sum, p| sum.checked_add(p.value.to_sat()));
        let spent = spent.ok_or("Input amounts overflow")?;
        let mut sent = 0u64;
        let mut change = 0u64;
        let mut sends = Vec::new();
        for out in &psbt.unsigned_tx.output {
            let sats = out.value.to_sat();
            sent = sent.checked_add(sats).ok_or("Output amounts overflow")?;
            // Our receive addresses are a send too: only the change chain is change.
            if self.scripts.get(&out.script_pubkey).is_some_and(|(chain, _)| *chain == CHANGE) {
                change += sats;
                continue;
            }
            let to = match Address::from_script(&out.script_pubkey, self.network) {
                Ok(address) => address.to_string(),
                Err(_) => "Unknown script".to_string(),
            };
            sends.push((to, sats));
        }
        let fee = spent.checked_sub(sent).ok_or("This transaction spends more than its inputs")?;
        if fee > FEE_CEILING {
            return Err(format!("A fee of {fee} sats is too high. Check the transaction."));
        }
        Ok(Review { sends, change, fee })
    }

    /// Round one, after the person approved the review: add our nonces, keep their secrets.
    pub fn add_nonces(&mut self, psbt: &mut Psbt) -> Result<(), String> {
        let prevouts = Self::prevouts(psbt)?;
        let slots = self.slots(psbt, &prevouts)?;
        let sighashes = Self::sighashes(psbt, &prevouts)?;
        let mut nonces = Vec::with_capacity(slots.len());
        for (i, slot) in slots.iter().enumerate() {
            let mut seed = [0u8; 32];
            getrandom::getrandom(&mut seed).map_err(err)?;
            let aggregate: Point = slot.tweaked.aggregated_pubkey();
            let seckey = Scalar::from_slice(&slot.seckey.secret_bytes()).map_err(err)?;
            let nonce = SecNonce::generate(seed, seckey, aggregate, sighashes[i], b"");
            let input = &mut psbt.inputs[i];
            input.unknown.insert(field_key(IN_PARTICIPANTS, slot.plain.to_vec()), slot.participants.concat());
            input.unknown.insert(
                participant_key(IN_PUB_NONCE, &slot.pubkey, &slot.plain),
                nonce.public_nonce().serialize().to_vec(),
            );
            nonces.push(nonce);
        }
        self.pending = Some(Pending { txid: psbt.unsigned_tx.compute_txid(), sighashes, nonces });
        Ok(())
    }

    fn pub_nonces(input: &bitcoin::psbt::Input, slot: &Slot) -> Result<Vec<PubNonce>, String> {
        slot.participants
            .iter()
            .map(|p| {
                let bytes = input
                    .unknown
                    .get(&participant_key(IN_PUB_NONCE, p, &slot.plain))
                    .ok_or("A cosigner's nonce is missing")?;
                if bytes.len() != PUB_NONCE {
                    return Err("A cosigner's nonce is malformed".to_string());
                }
                PubNonce::from_bytes(bytes).map_err(err)
            })
            .collect()
    }

    /// Round two: use up our nonces on this exact transaction.
    pub fn add_signatures(&mut self, psbt: &mut Psbt) -> Result<(), String> {
        // Out first: from here on these nonces are gone, whatever happens.
        let pending = self.pending.take().ok_or("Nothing is waiting to be signed")?;
        let prevouts = Self::prevouts(psbt)?;
        let sighashes = Self::sighashes(psbt, &prevouts)?;
        if pending.txid != psbt.unsigned_tx.compute_txid() || pending.sighashes != sighashes {
            return Err("This isn't the transaction you approved. Start again.".into());
        }
        let slots = self.slots(psbt, &prevouts)?;
        for (i, (nonce, slot)) in pending.nonces.into_iter().zip(&slots).enumerate() {
            let ours = psbt.inputs[i]
                .unknown
                .get(&participant_key(IN_PUB_NONCE, &slot.pubkey, &slot.plain))
                .ok_or("This Passport's nonce is missing")?;
            if *ours != nonce.public_nonce().serialize() {
                return Err("This PSBT changed this Passport's nonce. Start again.".into());
            }
            let aggregate = AggNonce::sum(Self::pub_nonces(&psbt.inputs[i], slot)?);
            let seckey = Scalar::from_slice(&slot.seckey.secret_bytes()).map_err(err)?;
            let signature: PartialSignature =
                musig2::sign_partial(&slot.tweaked, seckey, nonce, &aggregate, sighashes[i]).map_err(err)?;
            psbt.inputs[i]
                .unknown
                .insert(participant_key(IN_PARTIAL_SIG, &slot.pubkey, &slot.plain), signature.serialize().to_vec());
        }
        Ok(())
    }

    /// Check every partial signature, join them, and return the transaction, hex-encoded.
    pub fn finalize(&self, psbt: &mut Psbt) -> Result<String, String> {
        let prevouts = Self::prevouts(psbt)?;
        let sighashes = Self::sighashes(psbt, &prevouts)?;
        let slots = self.slots(psbt, &prevouts)?;
        for (i, slot) in slots.iter().enumerate() {
            let nonces = Self::pub_nonces(&psbt.inputs[i], slot)?;
            let aggregate = AggNonce::sum(&nonces);
            let mut partials: Vec<PartialSignature> = Vec::with_capacity(slot.participants.len());
            for (participant, nonce) in slot.participants.iter().zip(&nonces) {
                let bytes = psbt.inputs[i]
                    .unknown
                    .get(&participant_key(IN_PARTIAL_SIG, participant, &slot.plain))
                    .ok_or("A cosigner's signature is missing")?;
                if bytes.len() != PARTIAL_SIG {
                    return Err("A cosigner's signature is malformed".into());
                }
                let partial = MaybeScalar::from_slice(bytes).map_err(err)?;
                let key = Point::from_slice(participant).map_err(err)?;
                musig2::verify_partial(&slot.tweaked, partial, &aggregate, key, nonce, sighashes[i])
                    .map_err(|_| "A cosigner's signature is invalid".to_string())?;
                partials.push(partial);
            }
            let signature: LiftedSignature =
                musig2::aggregate_partial_signatures(&slot.tweaked, &aggregate, partials, sighashes[i]).map_err(err)?;
            psbt.inputs[i].final_script_witness = Some(Witness::from_slice(&[signature.serialize()]));
        }
        let tx = psbt.clone().extract_tx_unchecked_fee_rate();
        Ok(bitcoin::consensus::encode::serialize_hex(&tx))
    }
}

/// A PSBT from a QR code or typed text: base64, or raw bytes as in a UR crypto-psbt.
pub fn parse_psbt(data: &[u8]) -> Result<Psbt, String> {
    if let Ok(psbt) = Psbt::deserialize(data) {
        return Ok(psbt);
    }
    let text = std::str::from_utf8(data).map_err(|_| NOT_A_PSBT.to_string())?;
    Psbt::from_str(text.trim()).map_err(|_| NOT_A_PSBT.to_string())
}

#[cfg(test)]
mod tests {
    use bitcoin::absolute::LockTime;
    use bitcoin::key::Keypair;
    use bitcoin::secp256k1::{schnorr, Message};
    use bitcoin::transaction::Version;
    use bitcoin::{Amount, OutPoint, Sequence, Transaction, TxIn};

    use super::*;

    const ALICE: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    const BOB: &str = "legal winner thank year wave sausage worth useful legal winner thank yellow";
    const OTHER: &str = "letter advice cage absurd amount doctor acoustic avoid letter advice cage above";
    const NET: Network = Network::Signet;

    fn pair() -> (Signer, Signer) {
        let mut alice = Signer::from_phrase(ALICE, NET).unwrap();
        let mut bob = Signer::from_phrase(BOB, NET).unwrap();
        let (a, b) = (alice.xpub(), bob.xpub());
        alice.add_cosigner(&b).unwrap();
        bob.add_cosigner(&a).unwrap();
        (alice, bob)
    }

    fn unsigned(spent: &[(ScriptBuf, u64)], outputs: Vec<TxOut>) -> Psbt {
        let input = spent
            .iter()
            .enumerate()
            .map(|(i, _)| TxIn {
                previous_output: OutPoint { txid: Txid::all_zeros(), vout: i as u32 },
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                ..Default::default()
            })
            .collect();
        let tx = Transaction { version: Version::TWO, lock_time: LockTime::ZERO, input, output: outputs };
        let mut psbt = Psbt::from_unsigned_tx(tx).unwrap();
        for (input, (script, sats)) in psbt.inputs.iter_mut().zip(spent) {
            input.witness_utxo = Some(TxOut { value: Amount::from_sat(*sats), script_pubkey: script.clone() });
        }
        psbt
    }

    fn spend(alice: &Signer) -> Psbt {
        let change = alice.script(CHANGE, 0).unwrap();
        let elsewhere = alice.script(RECEIVE, 7).unwrap();
        unsigned(
            &[(alice.script(RECEIVE, 0).unwrap(), 60_000), (alice.script(RECEIVE, 3).unwrap(), 40_000)],
            vec![
                TxOut { value: Amount::from_sat(30_000), script_pubkey: elsewhere },
                TxOut { value: Amount::from_sat(69_000), script_pubkey: change },
            ],
        )
    }

    fn sign_round(alice: &mut Signer, bob: &mut Signer, psbt: &mut Psbt) {
        assert!(matches!(alice.inspect(psbt), Ok(Step::Nonce(_))));
        alice.add_nonces(psbt).unwrap();
        // Over a QR code and back, as it travels for real.
        *psbt = parse_psbt(psbt.to_string().as_bytes()).unwrap();
        assert!(matches!(bob.inspect(psbt), Ok(Step::Nonce(_))));
        bob.add_nonces(psbt).unwrap();
        assert!(matches!(alice.inspect(psbt), Ok(Step::Sign)));
        alice.add_signatures(psbt).unwrap();
        assert!(matches!(bob.inspect(psbt), Ok(Step::Sign)));
        bob.add_signatures(psbt).unwrap();
    }

    #[test]
    fn both_sides_agree_on_addresses() {
        let (alice, bob) = pair();
        let address = alice.address(RECEIVE, 0).unwrap();
        assert_eq!(address, bob.address(RECEIVE, 0).unwrap());
        assert!(address.starts_with("tb1p"));
        assert_ne!(address, alice.address(RECEIVE, 1).unwrap());
        assert_ne!(address, alice.address(CHANGE, 0).unwrap());
    }

    #[test]
    fn review_separates_sends_change_and_fee() {
        let (alice, _) = pair();
        let psbt = spend(&alice);
        let Ok(Step::Nonce(review)) = alice.inspect(&psbt) else { panic!() };
        assert_eq!(review, Review { sends: vec![(alice.address(RECEIVE, 7).unwrap(), 30_000)], change: 69_000, fee: 1_000 });
    }

    #[test]
    fn two_signers_produce_a_valid_key_spend() {
        let (mut alice, mut bob) = pair();
        let mut psbt = spend(&alice);
        sign_round(&mut alice, &mut bob, &mut psbt);
        assert!(matches!(alice.inspect(&psbt), Ok(Step::Finalize)));
        let hex = alice.finalize(&mut psbt).unwrap();
        assert_eq!(hex, bob.finalize(&mut psbt).unwrap());

        // Each witness must verify as plain BIP340 against the output key on chain, with no MuSig involved.
        let prevouts = Signer::prevouts(&psbt).unwrap();
        let sighashes = Signer::sighashes(&psbt, &prevouts).unwrap();
        let secp = Secp256k1::verification_only();
        for ((input, prevout), sighash) in psbt.inputs.iter().zip(&prevouts).zip(&sighashes) {
            let witness = input.final_script_witness.as_ref().unwrap();
            let signature = schnorr::Signature::from_slice(&witness[0]).unwrap();
            let key = XOnlyPublicKey::from_slice(&prevout.script_pubkey.as_bytes()[2..]).unwrap();
            secp.verify_schnorr(&signature, &Message::from_digest(*sighash), &key).unwrap();
        }
    }

    #[test]
    fn nonces_cannot_sign_twice() {
        let (mut alice, mut bob) = pair();
        let mut psbt = spend(&alice);
        sign_round(&mut alice, &mut bob, &mut psbt);
        assert!(alice.add_signatures(&mut psbt).is_err());
    }

    #[test]
    fn a_failed_round_burns_the_nonces() {
        let (mut alice, mut bob) = pair();
        let mut psbt = spend(&alice);
        alice.add_nonces(&mut psbt).unwrap();
        bob.add_nonces(&mut psbt).unwrap();

        // The coordinator swaps the destination between rounds.
        let mut swapped = psbt.clone();
        swapped.unsigned_tx.output[0].value = Amount::from_sat(29_000);
        assert!(alice.add_signatures(&mut swapped).is_err());

        // Even the honest PSBT can no longer be signed with those nonces.
        assert!(alice.add_signatures(&mut psbt).is_err());
    }

    #[test]
    fn replaced_nonce_is_refused() {
        let (mut alice, mut bob) = pair();
        let mut psbt = spend(&alice);
        alice.add_nonces(&mut psbt).unwrap();
        let mut replaced = spend(&alice);
        bob.add_nonces(&mut replaced).unwrap();
        let mut other = Signer::from_phrase(ALICE, NET).unwrap();
        other.add_cosigner(&bob.xpub()).unwrap();
        other.add_nonces(&mut replaced).unwrap();
        assert!(alice.add_signatures(&mut replaced).is_err());
    }

    #[test]
    fn foreign_inputs_and_cosigners_are_refused() {
        let (alice, _) = pair();
        let stranger = Keypair::from_seckey_slice(&alice.secp, &[7u8; 32]).unwrap();
        let foreign = ScriptBuf::new_p2tr(&alice.secp, stranger.x_only_public_key().0, None);
        let psbt = unsigned(&[(foreign.clone(), 1_000)], vec![TxOut { value: Amount::from_sat(500), script_pubkey: foreign }]);
        assert!(alice.inspect(&psbt).is_err());

        let mut swapped = spend(&alice);
        let slot = alice.slot(RECEIVE, 0).unwrap();
        let carol = Signer::from_phrase(OTHER, NET).unwrap().slot_key();
        let list = [slot.pubkey, carol].concat();
        swapped.inputs[0].unknown.insert(field_key(IN_PARTICIPANTS, slot.plain.to_vec()), list);
        assert!(alice.inspect(&swapped).is_err());
    }

    #[test]
    fn shares_sign_as_separate_participants() {
        let mut one = Signer::from_share(1, "ABCDEF", NET).unwrap();
        let mut two = Signer::from_share(2, "GHIJKL", NET).unwrap();
        let (a, b) = (one.xpub(), two.xpub());
        assert_ne!(a, b);
        assert_eq!(a, Signer::from_share(1, "ABCDEF", NET).unwrap().xpub(), "a share always gives its key");
        assert_ne!(a, Signer::from_share(1, "ABCDEG", NET).unwrap().xpub(), "one misread symbol is another key");
        one.add_cosigner(&b).unwrap();
        two.add_cosigner(&a).unwrap();
        let mut psbt = spend(&one);
        sign_round(&mut one, &mut two, &mut psbt);
        one.finalize(&mut psbt).unwrap();
    }

    #[test]
    fn mainnet_follows_bip86() {
        // The account key from BIP86's own test vectors.
        let main = Signer::from_phrase(ALICE, Network::Bitcoin).unwrap();
        assert_eq!(
            main.xpub(),
            "xpub6BgBgsespWvERF3LHQu6CnqdvfEvtMcQjYrcRzx53QJjSxarj2afYWcLteoGVky7D3UKDP9QyrLprQ3VCECoY49yfdDEHGCtMMj92pReUsQ"
        );
        assert_ne!(main.fingerprint(), Signer::from_phrase(ALICE, NET).unwrap().fingerprint());
    }

    #[test]
    fn mainnet_signers_spend_to_mainnet_addresses() {
        let mut alice = Signer::from_phrase(ALICE, Network::Bitcoin).unwrap();
        let mut bob = Signer::from_phrase(BOB, Network::Bitcoin).unwrap();
        let (a, b) = (alice.xpub(), bob.xpub());
        alice.add_cosigner(&b).unwrap();
        bob.add_cosigner(&a).unwrap();
        assert!(alice.address(RECEIVE, 0).unwrap().starts_with("bc1p"));
        assert_eq!(alice.address(RECEIVE, 0).unwrap(), bob.address(RECEIVE, 0).unwrap());
        let mut psbt = spend(&alice);
        let Ok(Step::Nonce(review)) = alice.inspect(&psbt) else { panic!() };
        assert!(review.sends[0].0.starts_with("bc1p"));
        sign_round(&mut alice, &mut bob, &mut psbt);
        alice.finalize(&mut psbt).unwrap();
    }

    #[test]
    fn networks_cannot_mix() {
        let mut main = Signer::from_phrase(ALICE, Network::Bitcoin).unwrap();
        let test_key = Signer::from_phrase(BOB, NET).unwrap().xpub();
        assert!(main.add_cosigner(&test_key).is_err());
        let mut signet = Signer::from_phrase(ALICE, NET).unwrap();
        let main_key = Signer::from_phrase(BOB, Network::Bitcoin).unwrap().xpub();
        assert!(signet.add_cosigner(&main_key).is_err());
    }

    #[test]
    fn absurd_fees_are_refused() {
        let (alice, _) = pair();
        let change = alice.script(CHANGE, 0).unwrap();
        let ceiling = unsigned(
            &[(alice.script(RECEIVE, 0).unwrap(), FEE_CEILING + 1_000)],
            vec![TxOut { value: Amount::from_sat(1_000), script_pubkey: change.clone() }],
        );
        assert!(alice.inspect(&ceiling).is_ok(), "exactly the ceiling is allowed");
        let over = unsigned(
            &[(alice.script(RECEIVE, 0).unwrap(), FEE_CEILING + 1_001)],
            vec![TxOut { value: Amount::from_sat(1_000), script_pubkey: change }],
        );
        assert!(alice.inspect(&over).is_err());
    }

    #[test]
    fn cosigner_list_is_checked() {
        let mut alice = Signer::from_phrase(ALICE, NET).unwrap();
        assert!(alice.address(RECEIVE, 0).is_err());
        assert!(alice.add_cosigner("not a key").is_err());
        assert!(alice.add_cosigner(&alice.xpub()).is_err());
        let bob = Signer::from_phrase(BOB, NET).unwrap().xpub();
        alice.add_cosigner(&bob).unwrap();
        assert!(alice.add_cosigner(&bob).is_err());
    }

    impl Signer {
        fn slot_key(&self) -> [u8; COMPRESSED] { self.xpub.public_key.serialize() }
    }
}
