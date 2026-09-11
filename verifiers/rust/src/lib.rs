//! CryptoValid hash-chain verifier — independent, zero-dependency Rust implementation.
//! Verdict/fields identical to the Python reference and the JS/Swift verifiers on the
//! shared normative vectors. Air-gapped: SHA-256 and SHA3-256 are pure Rust in-crate.
//!
//! Honest scope: proves integrity, prev_hash linkage and sequential idx. Ed25519
//! signature verification is intentionally OUT of this zero-dependency core (as in the
//! reference's stdlib verifier); verify signatures with the signer tool / a vetted
//! Ed25519 crate. This crate never proves the truth of the recorded facts.
pub mod json;
pub mod keccak;
pub mod sha256;

use json::{canonical, Json, Parser};
use std::collections::BTreeMap;

pub const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";
const ATTEST: [&str; 3] = ["self_hash", "signature", "signer"];

#[derive(Debug, PartialEq)]
pub struct VerifyResult {
    pub verdict: String,
    pub chain_integrity: bool,
    pub algorithm: String,
    pub entries: usize,
    pub hash_failures_idx: Vec<i64>,
    pub link_failures_idx: Vec<i64>,
    pub parse_errors: usize,
}

fn canonical_payload(entry: &BTreeMap<String, Json>) -> Vec<u8> {
    let mut d = entry.clone();
    for k in ATTEST.iter() {
        d.remove(*k);
    }
    canonical(&Json::Object(d)).into_bytes()
}

fn hash_with(algo: &str, bytes: &[u8]) -> String {
    if algo == "sha3_256" {
        keccak::hex(bytes)
    } else {
        sha256::hex(bytes)
    }
}

fn get_str<'a>(e: &'a BTreeMap<String, Json>, k: &str) -> Option<&'a str> {
    match e.get(k) {
        Some(Json::Str(s)) => Some(s.as_str()),
        _ => None,
    }
}
fn get_int(e: &BTreeMap<String, Json>, k: &str) -> Option<i64> {
    match e.get(k) {
        Some(Json::Int(n)) => Some(*n),
        _ => None,
    }
}

fn detect_algo(entries: &[BTreeMap<String, Json>]) -> Option<&'static str> {
    let e0 = entries.first()?;
    let sh = get_str(e0, "self_hash")?;
    let p = canonical_payload(e0);
    for a in ["sha256", "sha3_256"] {
        if hash_with(a, &p) == sh {
            return Some(if a == "sha256" { "sha256" } else { "sha3_256" });
        }
    }
    None
}

pub fn verify_ledger(text: &str, algo: Option<&str>) -> VerifyResult {
    let mut entries: Vec<BTreeMap<String, Json>> = Vec::new();
    let mut parse_errors = 0usize;
    for line in text.split('\n') {
        let t = line.trim();
        if t.is_empty() {
            continue;
        }
        match Parser::parse(t) {
            Ok(Json::Object(o)) => entries.push(o),
            _ => parse_errors += 1,
        }
    }
    let use_algo = algo
        .map(|a| a.to_string())
        .unwrap_or_else(|| detect_algo(&entries).unwrap_or("sha256").to_string());

    let mut hash_failures = Vec::new();
    let mut link_failures = Vec::new();
    for (i, e) in entries.iter().enumerate() {
        let idx = get_int(e, "idx").unwrap_or(i as i64);
        match get_str(e, "self_hash") {
            None => hash_failures.push(idx),
            Some(sh) => {
                if hash_with(&use_algo, &canonical_payload(e)) != sh {
                    hash_failures.push(idx);
                }
            }
        }
    }
    for (i, e) in entries.iter().enumerate() {
        let idx = get_int(e, "idx").unwrap_or(i as i64);
        let expected = if i > 0 {
            get_str(&entries[i - 1], "self_hash").unwrap_or("")
        } else {
            GENESIS
        };
        if get_str(e, "prev_hash") != Some(expected) {
            link_failures.push(idx);
        }
    }
    let mut idx_ok = true;
    for (i, e) in entries.iter().enumerate() {
        if get_int(e, "idx") != Some(i as i64) {
            idx_ok = false;
        }
    }
    // zero entries = nothing verified = FAIL (2026-09-11: all four verifiers said PASS on an empty file)
    let chain = hash_failures.is_empty() && link_failures.is_empty() && idx_ok && parse_errors == 0
        && !entries.is_empty();

    VerifyResult {
        verdict: if chain { "PASS" } else { "FAIL" }.into(),
        chain_integrity: chain,
        algorithm: use_algo,
        entries: entries.len(),
        hash_failures_idx: hash_failures,
        link_failures_idx: link_failures,
        parse_errors,
    }
}

impl VerifyResult {
    /// Minimal JSON receipt (stable field order) for the CLI.
    pub fn to_json(&self) -> String {
        let idxs = |v: &Vec<i64>| {
            v.iter()
                .map(|x| x.to_string())
                .collect::<Vec<_>>()
                .join(",")
        };
        format!(
            "{{\"algorithm\":\"{}\",\"chain_integrity\":{},\"entries\":{},\"hash_failures_idx\":[{}],\"link_failures_idx\":[{}],\"verdict\":\"{}\"}}",
            self.algorithm, self.chain_integrity, self.entries, idxs(&self.hash_failures_idx), idxs(&self.link_failures_idx), self.verdict
        )
    }
}
