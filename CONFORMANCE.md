# Cross-implementation conformance

The CryptoValid evidence format has one normative contract: `spec/vectors/*`.

## ap2-evidence-pack vectors (spec/vectors/ap2/)

The AP2 dispute-evidence pack has its own normative text (`SPEC_AP2_EVIDENCE.md`) and vector set:
one ACCEPT (`valid_signed`, the positive control) and five REJECTs (stripped-signature downgrade,
valid-but-unpinned producer key, digest mismatch, time anchor required-but-missing, time anchor
claimed-but-invalid). A verifier conforms iff it reproduces each vector's `normative` block under
the declared policy — `python3 spec/vectors/ap2/run_ap2_conformance.py` (exit 0 = conformant).
The ML-DSA-65 producer-signature primitive is additionally checked against the NIST ACVP sigVer
subset in `pqcrypto/vectors/acvp_mldsa65_sigver.txt` (the same 9 cases elara-mesh runs — one NIST
oracle for both stacks): `python3 test_ap2_conformance.py`.

| Implementation | Runtime / deps | Status |
|---|---|---|
| `ap2_evidence.py` | Python 3 + `cryptography` | reference — conformant 6/6; ACVP ML-DSA-65 sigVer 9/9 |

## Ledger vectors (spec/vectors/)
Every independent verifier MUST reproduce the normative block (verdict, chain_integrity,
algorithm, entries, hash/link failure indices) on each vector — including the vectors
that MUST fail (bad_idx, broken_link, tampered_content).

| Implementation | Runtime / deps | Status |
|---|---|---|
| `verifier.py` | Python 3, stdlib | reference — conformant |
| `verifiers/js/cvverify.mjs` | Node ≥18, stdlib only | **conformant 6/6**; 38-check suite incl. cross-oracle vs the Python reference |
| `verifiers/rust/` | Rust, **std only** (SHA-256+Keccak in-crate) | **conformant 6/6**; `cargo test` + `clippy -D warnings`; cross-oracle Python↔JS↔Rust = 0 mismatch |
| `verifiers/swift/` | Swift + CryptoKit (Apple) / swift-crypto (Linux) | **compiled & tested (Swift 6.3.3): swift test 4/4**; in the 4-language cross-oracle (Python/JS/Rust/Swift) = 0 mismatch |

The JS verifier is cross-checked at test time by running the actual Python reference
as an independent oracle: it must produce the same verdict/chain_integrity/algorithm
on every vector, so a self-serving bug (agreeing only with itself) is caught.

Honest scope: these verifiers prove integrity, linkage and signatures — not the truth
of the recorded facts; Ed25519 is not post-quantum.

## Canonical acceptance profile (enforced identically by all four + reference)

Verified by `verifiers/differential_oracle.py` (feeds an adversarial corpus to Python|JS|Rust|Swift and
FAILS on any verdict disagreement — 0 disagreements). The profile a valid ledger MUST satisfy; anything
outside it is REJECTED uniformly (not silently transformed):

- Numbers: integers only, in the portable range +/-(2^53-1). **No floats** (decimals travel as strings),
  **no NaN / Infinity**, no integer beyond the range.
- Objects: **no duplicate keys** (top-level or nested; escaped duplicates like `"a"` vs `"\u0061"` too).
- Strings: valid UTF-8. (Residual: lone UTF-16 surrogates are rejected by Rust/Swift; Python/JS acceptance
  of them is a documented residual to close — tracked.)

The four verifiers agreeing on the 6 normative vectors is necessary but NOT sufficient; the differential
oracle over the adversarial corpus is the real invariant. "Agree byte-for-byte" means *on this profile*.
