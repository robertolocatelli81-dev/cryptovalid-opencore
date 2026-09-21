//! cvverify — CLI. Usage: cvverify <ledger.jsonl> [--algo sha256|sha3_256]
use std::process::exit;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let path = match args.first() {
        Some(p) if !p.starts_with('-') => p,
        _ => {
            eprintln!("usage: cvverify <ledger.jsonl> [--algo sha256|sha3_256]");
            exit(2);
        }
    };
    // one grammar (21/09/2026): an unknown flag, "--algo" without a value or with "", a second positional = usage error, exit 2
    let mut algo: Option<&str> = None;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--algo" => {
                match args.get(i + 1) {
                    Some(v) if !v.is_empty() && !v.starts_with('-') => { algo = Some(v.as_str()); i += 2; }
                    _ => { eprintln!("usage: cvverify <ledger.jsonl> [--algo sha256|sha3_256]"); exit(2); }
                }
            }
            _ => { eprintln!("usage: cvverify <ledger.jsonl> [--algo sha256|sha3_256]"); exit(2); }
        }
    }
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) => {
            println!("{{\"verdict\":\"FILE_ERROR\",\"error\":\"{}\"}}", e);
            exit(2);
        }
    };
    let text = match String::from_utf8(bytes) {   // the file exists but is not UTF-8: a FAIL verdict like the other verifiers, not "file error"
        Ok(t) => t,
        Err(_) => {
            println!("{{\"verdict\":\"FAIL\",\"error\":\"ledger is not valid UTF-8\"}}");
            exit(1);
        }
    };
    let r = cvverify::verify_ledger(&text, algo);
    println!("{}", r.to_json());
    exit(if r.verdict == "PASS" { 0 } else { 1 });
}
