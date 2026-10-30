// SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: MIT

// Offline Cashu wallet.
//
// Passport has no network, so it can never swap, mint or melt at a mint. Notes are therefore kept as
// the exact token strings they arrived as and passed on whole: nothing is split, and keyset ids never
// need resolving against the mint. A received token is not checked against the mint either, so it is
// only as good as the sender's word until someone online redeems it.

use std::collections::{BTreeMap, HashSet};
use std::str::FromStr;

use cashu::Token;

pub struct Note {
    pub token: String,
    pub amount: u64,
    pub unit: String,
    pub mint: String,
    secrets: HashSet<String>,
}

impl Note {
    /// Parse a token as scanned or read from a tag. Accepts a `cashu:` URI prefix and surrounding
    /// whitespace.
    pub fn parse(raw: &str) -> Result<Self, String> {
        let raw = raw.trim();
        let raw = raw.strip_prefix("cashu:").unwrap_or(raw);
        let token = Token::from_str(raw).map_err(|e| format!("Not a Cashu token: {e}"))?;
        let amount = token.value().map_err(|e| format!("Bad token amount: {e}"))?.to_u64();
        let mint = token.mint_url().map_err(|_| "Multi-mint tokens aren't supported".to_string())?;
        let unit = token.unit().map(|u| u.to_string()).unwrap_or_else(|| "sat".into());
        let secrets = token.token_secrets().iter().map(|s| s.to_string()).collect();
        Ok(Self { token: raw.to_string(), amount, unit, mint: mint.to_string(), secrets })
    }
}

#[derive(Default)]
pub struct Wallet {
    pub notes: Vec<Note>,
}

impl Wallet {
    /// Load from the JSON array of token strings written by [`Wallet::to_json`]. Entries that no
    /// longer parse are dropped with a log line rather than failing the whole wallet.
    pub fn from_json(bytes: &[u8]) -> Self {
        let tokens: Vec<String> = serde_json::from_slice(bytes).unwrap_or_else(|e| {
            log::error!("wallet file unreadable: {e}");
            Vec::new()
        });
        let notes = tokens
            .iter()
            .filter_map(|t| Note::parse(t).map_err(|e| log::error!("dropping stored token: {e}")).ok())
            .collect();
        Self { notes }
    }

    pub fn to_json(&self) -> Vec<u8> {
        let tokens: Vec<&str> = self.notes.iter().map(|n| n.token.as_str()).collect();
        serde_json::to_vec(&tokens).expect("string list serializes")
    }

    /// Add a token, refusing one whose proofs are already held (the same token scanned twice).
    pub fn add(&mut self, raw: &str) -> Result<&Note, String> {
        let note = Note::parse(raw)?;
        if self.notes.iter().any(|n| !n.secrets.is_disjoint(&note.secrets)) {
            return Err("This token is already in the wallet".into());
        }
        self.notes.push(note);
        Ok(self.notes.last().unwrap())
    }

    /// Balance per unit, e.g. "21 sat" or "21 sat · 5 usd".
    pub fn balance(&self) -> String {
        let mut totals = BTreeMap::<&str, u64>::new();
        for n in &self.notes {
            *totals.entry(&n.unit).or_default() += n.amount;
        }
        if totals.is_empty() {
            return "0 sat".into();
        }
        totals.iter().map(|(unit, amount)| format!("{amount} {unit}")).collect::<Vec<_>>().join(" · ")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // NUT-00 vector from the cashu crate's own tests: 1 sat from http://localhost:3338.
    const TOKEN: &str = "cashuBpGF0gaJhaUgArSaMTR9YJmFwgaNhYQFhc3hAOWE2ZGJiODQ3YmQyMzJiYTc2ZGIwZGYxOTcyMTZiMjlkM2I4Y2MxNDU1M2NkMjc4MjdmYzFjYzk0MmZlZGI0ZWFjWCEDhhhUP_trhpXfStS6vN6So0qWvc2X3O4NfM-Y1HISZ5JhZGlUaGFuayB5b3VhbXVodHRwOi8vbG9jYWxob3N0OjMzMzhhdWNzYXQ=";

    #[test]
    fn add_dedupe_roundtrip() {
        let mut w = Wallet::default();
        let n = w.add(&format!(" cashu:{TOKEN}\n")).unwrap();
        assert_eq!((n.amount, n.unit.as_str(), n.mint.as_str()), (1, "sat", "http://localhost:3338"));
        assert!(w.add(TOKEN).is_err(), "same proofs twice");
        assert!(w.add("cashuBnope").is_err());
        assert_eq!(w.balance(), "1 sat");

        let back = Wallet::from_json(&w.to_json());
        assert_eq!(back.notes.len(), 1);
        assert_eq!(back.notes[0].token, TOKEN);
    }
}
