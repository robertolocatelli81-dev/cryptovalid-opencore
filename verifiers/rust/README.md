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

- Library: `cvverify::verify_ledger(text, algo) -> VerifyResult`.
- Verifies canonical hash-chain: self_hash recompute, prev_hash linkage, sequential idx.
- Ed25519 signature verification is intentionally OUT of this zero-dependency core (as
  in the reference's stdlib verifier); add a vetted Ed25519 crate to check signatures.

Honest scope: proves integrity and linkage, not the truth of the recorded facts;
Ed25519 (in the signer) is not post-quantum.
