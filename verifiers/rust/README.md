# cvverify (Rust) — independent, air-gapped CryptoValid verifier

Zero-dependency Rust re-implementation of the CryptoValid evidence verifier: SHA-256
and SHA3-256 are pure-Rust in this crate, so it builds and runs fully offline with no
external crates. It agrees with the Python reference and the JS/Swift verifiers on the normative vectors (same verdicts
and same canonical digests, i.e. byte-identical canonical JSON on those vectors) and on every verdict of the
adversarial corpus (cross-oracle in CI).

```bash
cargo build --release
./target/release/cvverify ledger.jsonl [--algo sha256|sha3_256]
cargo test            # normative vectors + controls + SHA/Keccak known-answers
cargo clippy -- -D warnings && cargo fmt --check
```

- Exit 0 PASS, 1 FAIL (also a file that is not UTF-8), 2 usage or an unreadable file (`FILE_ERROR`), 74 the receipt
  could not be written whole (stdout full, read-only, under a file size limit or a reader gone; since 0.20.3: it was a
  panic, exit 101, the kernel's SIGXFSZ under `ulimit -f`, and exit 0/1 with stdout opened read-only), whatever the
  verdict. A full non-blocking stdout (a reader that reads late) is waited for, and the receipt arrives whole. A usage
  error stays exit 2 when stderr is full (`eprintln!` panicked: 101). With stdout closed (`>&-`) the Rust runtime reopens it on `/dev/null`: the write succeeds there and the
  program cannot tell.
- Library: `cvverify::verify_ledger(text, algo) -> VerifyResult`.
- Verifies canonical hash-chain: self_hash recompute, prev_hash linkage, sequential idx.
- Ed25519 signature verification is intentionally OUT of this zero-dependency core (as
  in the reference's stdlib verifier); add a vetted Ed25519 crate to check signatures.

Honest scope: proves integrity and linkage, not the truth of the recorded facts;
Ed25519 (in the signer) is not post-quantum.
