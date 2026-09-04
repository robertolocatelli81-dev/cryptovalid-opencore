# CryptoValidVerify — independent verifier for Apple platforms (Swift)

A clean-room CryptoValid verifier for iOS / iPadOS / macOS (and Linux with
swift-crypto), built the way Apple builds for its own systems: **no third-party
dependencies** — SHA-256 and Ed25519 come from the system **CryptoKit**; SHA3-256
(absent from CryptoKit) is a small pure-Swift Keccak in this package. Canonical JSON
is a byte-for-byte twin of the Python reference and the JS verifier.

```bash
swift build
swift run cvverify ledger.jsonl [--algo sha256|sha3_256] [--pubkey <hex>]
swift test        # runs the SAME normative vectors bundled as test resources
```

- `CryptoValidVerifier.verify(ledgerText:algo:expectedPubkeyHex:)` → `VerifyResult`
- Verdict/fields identical to the reference and the JS/Java verifiers (shared vectors).

Status: written against the documented CryptoKit API and validated by construction
against the shared conformance vectors. It is **not compiled in this Linux dev
environment** (no `swiftc`); build & test it on macOS, or on Linux by adding
`swift-crypto` as the CryptoKit shim. Honest scope as the JS verifier.
