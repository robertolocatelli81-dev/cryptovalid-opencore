//! Conformance + controls for the Rust verifier, against the SAME normative vectors
//! used by the Python reference and the JS/Swift verifiers (bundled under tests/vectors).
use cvverify::{keccak, sha256, verify_ledger};
use std::fs;
use std::path::Path;

fn vdir() -> &'static Path {
    Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/vectors"))
}

// tiny field readers for the expected.json normative block (no serde dependency)
fn field<'a>(s: &'a str, key: &str) -> &'a str {
    let k = format!("\"{}\"", key);
    let start = s.find(&k).map(|p| p + k.len()).unwrap_or(0);
    let rest = &s[start..];
    let colon = rest.find(':').unwrap() + 1;
    rest[colon..]
        .trim_start()
        .split([',', '\n', '}'])
        .next()
        .unwrap()
        .trim()
        .trim_matches('"')
}

#[test]
fn normative_vectors() {
    let mut count = 0;
    for entry in fs::read_dir(vdir()).unwrap() {
        let p = entry.unwrap().path();
        if !p.to_string_lossy().ends_with(".expected.json") {
            continue;
        }
        count += 1;
        let exp = fs::read_to_string(&p).unwrap();
        let input = field(&exp, "input").to_string();
        let ledger = fs::read_to_string(vdir().join(&input)).unwrap();
        let r = verify_ledger(&ledger, None);
        assert_eq!(r.verdict, field(&exp, "verdict"), "{}", input);
        assert_eq!(
            r.chain_integrity.to_string(),
            field(&exp, "chain_integrity"),
            "{}",
            input
        );
        assert_eq!(r.algorithm, field(&exp, "algorithm"), "{}", input);
        assert_eq!(r.entries.to_string(), field(&exp, "entries"), "{}", input);
    }
    assert!(count >= 6, "expected at least 6 vectors, found {}", count);
}

#[test]
fn controls_can_fail() {
    let good = fs::read_to_string(vdir().join("valid_sha256.jsonl")).unwrap();
    assert_eq!(verify_ledger(&good, None).verdict, "PASS");
    // tamper: flip one hex char of the first self_hash -> hash recompute must FAIL
    let sh = good
        .find("\"self_hash\": \"")
        .map(|p| p + "\"self_hash\": \"".len())
        .unwrap();
    let mut t: Vec<char> = good.chars().collect();
    t[sh] = if t[sh] == 'a' { 'b' } else { 'a' };
    let tampered: String = t.into_iter().collect();
    assert_eq!(verify_ledger(&tampered, None).verdict, "FAIL");
    // tamper a content byte inside the first entry's data -> also FAIL
    let brk = good.replacen("prev_hash", "prev_hAsh", 1);
    assert_eq!(verify_ledger(&brk, None).verdict, "FAIL");
    // wrong algorithm -> must FAIL
    assert_eq!(verify_ledger(&good, Some("sha3_256")).verdict, "FAIL");
    // garbage never panics
    assert_eq!(verify_ledger("null\n[1,2]\nnot json", None).verdict, "FAIL");
}

#[test]
fn hash_known_answers() {
    assert_eq!(
        sha256::hex(b"abc"),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    assert_eq!(
        sha256::hex(b""),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
    assert_eq!(
        keccak::hex(b"abc"),
        "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"
    );
    assert_eq!(
        keccak::hex(b""),
        "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
    );
}

#[test]
fn canonical_matches_python() {
    use cvverify::json::{canonical, Parser};
    let v = Parser::parse("{\"key\":\"caf\\u00e9\"}").unwrap();
    assert_eq!(canonical(&v), "{\"key\":\"caf\\u00e9\"}");
}

#[test]
fn duplicate_keys_rejected() {
    // hash malleability: a line whose visible payload differs from the hashed one
    let dup = format!("{{\"idx\":0,\"ts\":\"t\",\"data\":{{\"evil\":1}},\"data\":{{\"real\":1}},\"prev_hash\":\"{}\",\"self_hash\":\"x\"}}", "0".repeat(64));
    assert_eq!(verify_ledger(&dup, None).verdict, "FAIL");
}

fn entry_with(data_json: &str) -> String {
    // a chained one-entry ledger whose self_hash is computed the reference way (sha256 over the canonical payload)
    use cvverify::json::{canonical, Parser};
    let body = format!("{{\"data\":{},\"idx\":0,\"prev_hash\":\"{}\",\"ts\":\"t\"}}", data_json, "0".repeat(64));
    let v = Parser::parse(&body).unwrap();
    let h = cvverify::sha256::hex(canonical(&v).as_bytes());
    format!("{{\"data\":{},\"idx\":0,\"prev_hash\":\"{}\",\"self_hash\":\"{}\",\"ts\":\"t\"}}\n", data_json, "0".repeat(64), h)
}

#[test]
fn surrogate_pairs_accepted_lone_surrogates_refused() {
    // 15/09/2026: a VALID pair (U+1F600) was refused as "bad scalar" — an undeclared divergence from Python/JS/Go
    let pair = entry_with("{\"k\":\"\\ud83d\\ude00\"}");
    let r = verify_ledger(&pair, None);
    assert_eq!(r.verdict, "PASS", "valid surrogate pair must PASS: {:?}", r.to_json());
    for bad in ["{\"k\":\"\\ud800\"}", "{\"k\":\"\\udc00\"}", "{\"k\":\"\\ud800\\u0041\"}", "{\"k\":\"\\ud800\\uzzzz\"}"] {
        let line = format!("{{\"idx\":0,\"ts\":\"t\",\"data\":{},\"prev_hash\":\"{}\",\"self_hash\":\"z\"}}\n", bad, "0".repeat(64));
        let r = verify_ledger(&line, None);
        assert_eq!(r.verdict, "FAIL");
        assert_eq!(r.parse_errors, 1, "lone surrogate must be a PARSE refusal, not a hash mismatch: {}", bad);
    }
    // a short `\u` tail must not parse "12" as U+0012
    assert!(cvverify::json::Parser::parse("{\"k\":\"\\u12\"}").is_err());
}

fn entry_with_top_level(extra_key: &str, extra_json: &str) -> String {
    // a chained one-entry ledger carrying one extra TOP-LEVEL key, self_hash recomputed OVER it (only the schema rule can see it)
    use cvverify::json::{canonical, Parser};
    let body = format!("{{\"data\":{{\"i\":0}},\"idx\":0,\"prev_hash\":\"{}\",\"ts\":\"t\",{}:{}}}", "0".repeat(64), extra_key, extra_json);
    let v = Parser::parse(&body).unwrap();
    let h = cvverify::sha256::hex(canonical(&v).as_bytes());
    format!("{{\"data\":{{\"i\":0}},\"idx\":0,\"prev_hash\":\"{}\",\"self_hash\":\"{}\",\"ts\":\"t\",{}:{}}}\n", "0".repeat(64), h, extra_key, extra_json)
}

#[test]
fn closed_entry_schema_spec_2_1() {
    // SPEC §2.1 (2026-10-10): a top-level key nobody defined is a schema failure (idx named), never a silent PASS.
    // Measured on this verifier before 2026-10-11: PASS with no trace.
    for key in ["\"x_unknown_2026\"", "\"__proto__\"", "\"Idx\"", "\"\""] {
        let r = verify_ledger(&entry_with_top_level(key, "\"x\""), None);
        assert_eq!(r.verdict, "FAIL", "unknown top-level key {} must FAIL", key);
        assert_eq!(r.schema_failures_idx, vec![0], "the failure names the entry: {}", key);
        assert!(r.hash_failures_idx.is_empty(), "hash recomputed over the key: only the schema rule sees it");
        assert!(r.to_json().contains("\"schema_failures_idx\":[0]"));
    }
    // an OPTIONAL key of §2 with a value is in the schema: PASS (the rule must not reject too much)
    let r = verify_ledger(&entry_with_top_level("\"tsa_token\"", "\"AAAA\""), None);
    assert_eq!(r.verdict, "PASS", "{:?}", r);
    assert!(r.schema_failures_idx.is_empty());
    // the same unknown key INSIDE data is free (SPEC §4): PASS
    let r = verify_ledger(&entry_with("{\"x_unknown_2026\":\"payload\"}"), None);
    assert_eq!(r.verdict, "PASS");
    assert!(r.schema_failures_idx.is_empty());
    // positive control of the bench: the intact entry PASSES
    assert_eq!(verify_ledger(&entry_with("{\"i\":0}"), None).verdict, "PASS");
}

#[test]
fn nesting_bound_512() {
    let nest = |n: usize| format!("{}{}", "[".repeat(n), "]".repeat(n));
    assert_eq!(verify_ledger(&entry_with(&nest(510)), None).verdict, "PASS", "510 levels inside data (512 total) is AT the bound");
    // beyond the bound the line cannot even be hashed the reference way (the reference refuses it too):
    // build it raw and expect a PARSE refusal, not a hash mismatch
    for n in [598usize, 2000] {
        let line = format!("{{\"idx\":0,\"ts\":\"t\",\"data\":{},\"prev_hash\":\"{}\",\"self_hash\":\"z\"}}\n", nest(n), "0".repeat(64));
        let r = verify_ledger(&line, None);
        assert_eq!(r.verdict, "FAIL");
        assert_eq!(r.parse_errors, 1, "json_too_deep must be a parse refusal ({} levels)", n);
    }
}

// NEMESIS 12/10/2026: --algo takes only the two profiles; anything else is a usage error (exit 2), never a verdict
#[test]
fn cli_algo_closed() {
    let bin = env!("CARGO_BIN_EXE_cvverify");
    let v = vdir().join("valid_sha256.jsonl");
    let run = |args: &[&str]| std::process::Command::new(bin).arg(&v).args(args).output().unwrap();
    assert_eq!(run(&[]).status.code(), Some(0), "control");
    assert_eq!(run(&["--algo", "sha256"]).status.code(), Some(0));
    assert_eq!(run(&["--algo", "sha3_256"]).status.code(), Some(1), "applied: FAIL on a SHA-256 ledger");
    for a in ["foo", "SHA256", "sha3-256", "sha256\",\"verdict\":\"PASS"] {
        let o = run(&["--algo", a]);
        assert_eq!(o.status.code(), Some(2), "usage for --algo {}", a);
        assert!(o.stdout.is_empty(), "no receipt for --algo {}", a);
    }
}
