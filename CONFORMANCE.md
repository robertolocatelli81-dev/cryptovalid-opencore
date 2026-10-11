# Cross-implementation conformance

The CryptoValid evidence format has one normative contract: `spec/vectors/*`.

## ap2-evidence-pack (dependency since 0.18.0)

The AP2 dispute-evidence format, its normative text (`SPEC_AP2_EVIDENCE.md`), its vector set (`spec/vectors/ap2/`, 8
vectors), the conformance runner and the differential oracle live in the ap2-evidence-pack repository
(https://github.com/robertolocatelli81-dev/ap2-evidence-pack). This repository's `cryptovalid-verify ap2` calls that
package's `verify_evidence` and adds nothing to the verdict; the vectors it used to carry (6, built by an older copy
of the builder) were refused by the reference since its 1.1.0 (measured: 1.0.2 accepts them) and were removed in 0.18.0.

## Closed entry and manifest schemas (SPEC §2.1, 2026-10-10; every verifier aligned 2026-10-11)

The entry's top level is exactly the core + optional fields of SPEC §2; a MANIFEST, each `ledgers[i]` and the
`rfc3161_timestamp` block are closed objects (`evidence_pack.MANIFEST_KEYS`, `LEDGER_ENTRY_KEYS`, `RFC3161_KEYS`). The
reference reports `unknown_field:<key>` in `schema_failures` (ledger) and `manifest_unknown_field: …` (pack) and FAILS.
Measured on 0.18.1 on 2026-10-10: the same inputs verified PASS / valid with no trace in the receipt. Tests:
`test_closed_schema_20261010.py`.

**The five other verifiers apply the ledger rule since 2026-10-11** — the same closed list, the same failure name
`unknown_field:<keys>` (keys in code-point order, cut to 120 code points as the reference does) in the Go and Java
`failures[]` strings and in the JS `schema_failures[].reason`; Rust and Swift receipts carry no reason text and name the
entry in a new `schema_failures_idx` list. Measured before the alignment (an intermediate state, not published, where only the reference had the rule): JS, Go, Java, Rust and Swift all
answered PASS on an entry written with a key nobody defined, self_hash recomputed over it. Two normative vectors fix the
rule for every runner, `unknown_top_level_key` (FAIL) and `unknown_key_in_data` (PASS; `data` is free, SPEC §4): before
the alignment JS conformance was 8/9 and the Rust and Swift normative tests failed on the first. The differential oracle
carries nine new cases — seven negative (a plain key, a case variant `Idx`, the empty name `""`, a non-ASCII name, two keys,
a key on entry 1 of 3, the SHA3 profile) and the controls `unknown-key-in-data` / `optional-tsa-token-rehashed` that must
stay PASS — and the existing `proto-key-rehashed` (`__proto__`) now expects FAIL; on the negative ones it checks that every
receipt NAMES the key. Two more cases (`unknown-keys-long-cut`: keys past the 120-code-point cut, one outside the BMP;
`unknown-key-wrong-idx`) require the reason TEXT and the idx list to equal the reference's, not only to contain the key:
0/89 disagreements over Python, JS, Go, Java and Rust (28 declared). `verifiers/closed_schema_mutants.py` is a generative, differential bench over the
same rule (random keys at every level, case variants, JS-special names, escaped keys, wrong types, missing core keys,
duplicates, floats, reordering; the expected class comes from the SPEC tables, never from a verifier; the key must be
named): 1 500 mutations from 4 sources GREEN over the six verifiers, Swift included (seed 20261011); on that intermediate
state the quick run (150) counted 32 silent passes in each of JS, Go, Java and Rust, and on 0.18.1 32 in each of the five
including Python. `test_closed_schema_mutants.py` runs the
quick bench in CI and proves it can go red (a JS copy without the rule). The empty-name key `""` is the case the first
JS and Java ports got wrong (a joined string tested for truth): the oracle caught it before the commit.

Two things the bench measured and this change does NOT decide: (a) a chain whose first three entries lack `idx` is PASS in
the reference when no `--algo` is given (verifier.py takes its native-schema fallback for ledgers of other OMEGA modules,
receipt `mode: full_recompute_generic`; `evidence_pack.py verify` counts it as `hash_pass: true`), which applies neither SPEC
§5 step 4 nor §2.1 — an unknown top-level key passes there, not named —
and FAIL in the five others; the oracle declares both (`missing-idx-every-entry`, `missing-idx-first-three-unknown-key`),
the decision on the fallback is open; (b) a
missing or non-string `ts` / `data` is PASS in all six (SPEC §2 gives the types, §5 never checks them) — reported, not
changed.

## Ledger vectors (spec/vectors/)
Every independent verifier MUST reproduce the normative block (verdict, chain_integrity,
algorithm, entries, hash/link failure indices) on each vector — including the vectors
that MUST fail (bad_idx, broken_link, tampered_content).

| Implementation | Runtime / deps | Status |
|---|---|---|
| `verifier.py` | Python 3, stdlib | reference — conformant |
| `verifiers/js/cvverify.mjs` | Node ≥18, stdlib only | **conformant 9/9** (2026-10-11); 92–93-check suite incl. cross-oracle vs the Python reference (the count moves by one or two with the random signature's characters) |
| `verifiers/rust/` | Rust, **std only** (SHA-256+Keccak in-crate) | **conformant 9/9**; `cargo test` 8 tests + `clippy -D warnings` (Rust 1.98.1, 2026-10-11); in the differential oracle = 0 mismatch |
| `verifiers/swift/` | Swift + CryptoKit (Apple) / swift-crypto (Linux) | **compiled & tested on Linux (Swift 6.2, 2026-10-11): swift test 6/6, conformant 9/9**; the closed-schema cases agree with the five others; 12 OLDER divergences measured for the first time (surrogate pair refused, `+10` / `010` / a raw tab accepted, CRLF refused, `FILE_ERROR` on non-UTF-8, no usage errors in the CLI) — Swift was not updated for the 15/09–21/09 profile rules; in CI it has its own macOS job (`swift test` and the intact /
tampered gate) and is not part of the differential oracle |

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
