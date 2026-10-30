// SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: MIT

// Spending a seed's own BIP84 addresses, once two shares have rebuilt it. This is one key signing, not
// multisig: the shares protect the seed on paper, and the whole seed is in memory while it signs.

use std::collections::BTreeMap;
use std::str::FromStr;

use bip39::{Language, Mnemonic};
use bitcoin::bip32::{ChildNumber, DerivationPath, Xpriv};
use bitcoin::ecdsa;
use bitcoin::hashes::Hash;
use bitcoin::key::CompressedPublicKey;
use bitcoin::psbt::Psbt;
use bitcoin::secp256k1::{All, Message, PublicKey, Secp256k1, SecretKey};
use bitcoin::sighash::SighashCache;
use bitcoin::{Address, EcdsaSighashType, Network, ScriptBuf, Witness};

use crate::musig::{Review, CHANGE, FEE_CEILING, RECEIVE};

// How many addresses per chain are matched against a PSBT.
const GAP: u32 = 50;

fn err(e: impl std::fmt::Display) -> String { e.to_string() }

pub struct SeedSigner {
    secp: Secp256k1<All>,
    network: Network,
    account: Xpriv,
    // Output script to (chain, index).
    scripts: BTreeMap<ScriptBuf, (u32, u32)>,
}

impl SeedSigner {
    pub fn from_phrase(phrase: &str, network: Network) -> Result<Self, String> {
        let words = phrase.split_whitespace().collect::<Vec<_>>().join(" ").to_lowercase();
        let mnemonic = Mnemonic::parse_in_normalized(Language::English, &words).map_err(err)?;
        let secp = Secp256k1::new();
        let master = Xpriv::new_master(network, &mnemonic.to_seed("")).map_err(err)?;
        // BIP84: mainnet's coin type is 0, and every test network's is 1.
        let coin = if network == Network::Bitcoin { 0 } else { 1 };
        let path = DerivationPath::from_str(&format!("m/84'/{coin}'/0'")).map_err(err)?;
        let account = master.derive_priv(&secp, &path).map_err(err)?;
        let mut signer = Self { secp, network, account, scripts: BTreeMap::new() };
        for chain in [RECEIVE, CHANGE] {
            for index in 0..GAP {
                let script = signer.script(chain, index)?;
                signer.scripts.insert(script, (chain, index));
            }
        }
        Ok(signer)
    }

    fn keys(&self, chain: u32, index: u32) -> Result<(SecretKey, PublicKey), String> {
        let path =
            [ChildNumber::from_normal_idx(chain).map_err(err)?, ChildNumber::from_normal_idx(index).map_err(err)?];
        let secret = self.account.derive_priv(&self.secp, &path).map_err(err)?.private_key;
        Ok((secret, PublicKey::from_secret_key(&self.secp, &secret)))
    }

    fn script(&self, chain: u32, index: u32) -> Result<ScriptBuf, String> {
        Ok(ScriptBuf::new_p2wpkh(&CompressedPublicKey(self.keys(chain, index)?.1).wpubkey_hash()))
    }

    /// Whether a script is one of this seed's addresses, and which.
    fn find(&self, script: &ScriptBuf) -> Option<(u32, u32)> { self.scripts.get(script).copied() }

    /// What's being approved. Every input must be this seed's own, with its amount.
    pub fn review(&self, psbt: &Psbt) -> Result<Review, String> {
        let mut spent = 0u64;
        for input in &psbt.inputs {
            let utxo = input.witness_utxo.as_ref().ok_or("An input is missing its amount")?;
            self.find(&utxo.script_pubkey).ok_or("An input isn't from this seed")?;
            spent = spent.checked_add(utxo.value.to_sat()).ok_or("Input amounts overflow")?;
        }
        let (mut sent, mut change, mut sends) = (0u64, 0u64, Vec::new());
        for out in &psbt.unsigned_tx.output {
            let sats = out.value.to_sat();
            sent = sent.checked_add(sats).ok_or("Output amounts overflow")?;
            if self.find(&out.script_pubkey).is_some_and(|(chain, _)| chain == CHANGE) {
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

    /// Sign every input, check each signature, and return the transaction, hex-encoded.
    pub fn sign(&self, psbt: &mut Psbt) -> Result<String, String> {
        self.review(psbt)?;
        let tx = psbt.unsigned_tx.clone();
        let mut cache = SighashCache::new(&tx);
        for (i, input) in psbt.inputs.iter_mut().enumerate() {
            let utxo = input.witness_utxo.as_ref().ok_or("An input is missing its amount")?;
            if input.sighash_type.is_some_and(|t| t.ecdsa_hash_ty() != Ok(EcdsaSighashType::All)) {
                return Err("This PSBT asks for an unusual signature type".into());
            }
            let (chain, index) = self.find(&utxo.script_pubkey).ok_or("An input isn't from this seed")?;
            let (secret, public) = self.keys(chain, index)?;
            let hash = cache
                .p2wpkh_signature_hash(i, &utxo.script_pubkey, utxo.value, EcdsaSighashType::All)
                .map_err(err)?;
            let message = Message::from_digest(hash.to_byte_array());
            let signature = self.secp.sign_ecdsa(&message, &secret);
            self.secp.verify_ecdsa(&message, &signature, &public).map_err(err)?;
            let signature = ecdsa::Signature { signature, sighash_type: EcdsaSighashType::All };
            input.final_script_witness = Some(Witness::p2wpkh(&signature, &public));
        }
        let signed = psbt.clone().extract_tx_unchecked_fee_rate();
        Ok(bitcoin::consensus::encode::serialize_hex(&signed))
    }
}

#[cfg(test)]
mod tests {
    use bitcoin::absolute::LockTime;
    use bitcoin::transaction::Version;
    use bitcoin::{Amount, OutPoint, Sequence, Transaction, TxIn, TxOut, Txid};

    use super::*;

    const PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    fn signer() -> SeedSigner { SeedSigner::from_phrase(PHRASE, Network::Bitcoin).unwrap() }

    fn spend(from: ScriptBuf, sats: u64, outputs: Vec<TxOut>) -> Psbt {
        let input = TxIn {
            previous_output: OutPoint { txid: Txid::all_zeros(), vout: 0 },
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            ..Default::default()
        };
        let tx = Transaction { version: Version::TWO, lock_time: LockTime::ZERO, input: vec![input], output: outputs };
        let mut psbt = Psbt::from_unsigned_tx(tx).unwrap();
        psbt.inputs[0].witness_utxo = Some(TxOut { value: Amount::from_sat(sats), script_pubkey: from });
        psbt
    }

    #[test]
    fn addresses_match_bip84_vectors() {
        let s = signer();
        let address = |chain, index| Address::from_script(&s.script(chain, index).unwrap(), Network::Bitcoin).unwrap();
        assert_eq!(address(RECEIVE, 0).to_string(), "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu");
        assert_eq!(address(RECEIVE, 1).to_string(), "bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g");
        assert_eq!(address(CHANGE, 0).to_string(), "bc1q8c6fshw2dlwun7ekn9qwf37cu2rn755upcp6el");
    }

    #[test]
    fn signs_a_spend_and_reports_it() {
        let s = signer();
        let (from, to, change) =
            (s.script(RECEIVE, 0).unwrap(), s.script(RECEIVE, 3).unwrap(), s.script(CHANGE, 0).unwrap());
        let mut psbt = spend(
            from,
            13_000,
            vec![
                TxOut { value: Amount::from_sat(999), script_pubkey: to },
                TxOut { value: Amount::from_sat(11_401), script_pubkey: change },
            ],
        );
        let review = s.review(&psbt).unwrap();
        assert_eq!((review.sends.len(), review.sends[0].1, review.change, review.fee), (1, 999, 11_401, 600));
        let hex = s.sign(&mut psbt).unwrap();
        assert!(hex.len() > 300);
        assert_eq!(psbt.inputs[0].final_script_witness.as_ref().unwrap().len(), 2);
    }

    #[test]
    fn refuses_other_coins_and_absurd_fees() {
        let s = signer();
        let other = SeedSigner::from_phrase(
            "legal winner thank year wave sausage worth useful legal winner thank yellow",
            Network::Bitcoin,
        )
        .unwrap();
        let to = TxOut { value: Amount::from_sat(1_000), script_pubkey: s.script(CHANGE, 0).unwrap() };
        assert!(s.sign(&mut spend(other.script(RECEIVE, 0).unwrap(), 2_000, vec![to.clone()])).is_err());
        let huge = FEE_CEILING + 1_001;
        assert!(s.sign(&mut spend(s.script(RECEIVE, 0).unwrap(), huge, vec![to])).is_err());
    }
}
