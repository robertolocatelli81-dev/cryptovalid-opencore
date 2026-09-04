//! cvverify — CLI. Usage: cvverify <ledger.jsonl> [--algo sha256|sha3_256]
use std::process::exit;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let path = match args.first() {
        Some(p) if !p.starts_with("--") => p,
        _ => {
            eprintln!("usage: cvverify <ledger.jsonl> [--algo sha256|sha3_256]");
            exit(2);
        }
    };
    let algo = args
        .iter()
        .position(|a| a == "--algo")
        .and_then(|i| args.get(i + 1))
        .map(|s| s.as_str());
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) => {
            println!("{{\"verdict\":\"FILE_ERROR\",\"error\":\"{}\"}}", e);
            exit(2);
        }
    };
    let r = cvverify::verify_ledger(&text, algo);
    println!("{}", r.to_json());
    exit(if r.verdict == "PASS" { 0 } else { 1 });
}
