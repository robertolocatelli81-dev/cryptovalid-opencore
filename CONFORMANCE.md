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
stay PASS (since 0.20.2 `tsa_token` is outside the canonical form, SPEC §3: the second control is
`optional-tsa-token-attached`, and the rehashed form is the case `tsa-token-inside-hash`, FAIL in all six) — and the existing `proto-key-rehashed` (`__proto__`) now expects FAIL; on the negative ones it checks that every
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

Two things the bench measured in 0.19.0: (a) a chain whose first three entries lack `idx` was PASS in the reference when
no `--algo` was given (a native-schema fallback that applied neither SPEC §5 step 4 nor §2.1) and FAIL in the five others —
**closed in 0.20.0**: the fallback is removed, the two oracle cases (`missing-idx-every-entry`,
`missing-idx-first-three-unknown-key`) are FAIL in all of them and no longer declared; (b) a
missing or non-string `ts` / `data` is PASS in all six (SPEC §2 gives the types, §5 never checks them) — reported, not
changed.

## Ledger vectors (spec/vectors/)
Every independent verifier MUST reproduce the normative block (verdict, chain_integrity,
algorithm, entries, hash/link failure indices) on each vector — including the vectors
that MUST fail (bad_idx, broken_link, tampered_content).

| Implementation | Runtime / deps | Status |
|---|---|---|
| `verifier.py` | Python 3, stdlib | reference — conformant |
| `verifiers/js/cvverify.mjs` | Node ≥18, stdlib only | **conformant 11/11** (0.20.2, 2026-10-12: the two `tsa_token` vectors; 9/9 on 2026-10-11; 117–118 checks in the suite on 2026-10-12); 92–93-check suite (112 in 4 runs on 2026-10-12, after the checks for a BOM, `--algo`, float lexemes, `idx` past 2^53-1, a receipt over 64 KiB on a pipe; 115–116 in 9 runs after the review's checks: the receipt read through `| cat`, a signed tip with a BOM, `1.0` after an escaped quote, the float scan linear on 100 000 escaped quotes) incl. cross-oracle vs the Python reference (the count moves by one or two with the random signature's characters) |
| `verifiers/rust/` | Rust, **std only** (SHA-256+Keccak in-crate) | **conformant 11/11** (0.20.2; 9/9 before the two `tsa_token` vectors); `cargo test` 8 tests + `clippy -D warnings` (Rust 1.98.1, 2026-10-11; 9 tests since 2026-10-12, `--algo` closed); in the differential oracle = 0 mismatch |
| `verifiers/swift/` | Swift + CryptoKit (Apple) / swift-crypto (Linux) | **compiled & tested on Linux (Swift 6.3.3, 2026-10-12): swift test 18/18, conformant 11/11** (the binary on `spec/vectors/`; 0.20.2: reads a FIFO, `tsa_token` outside the hash; 17/17 and 9/9 in 0.20.1); aligned with the acceptance profile on 2026-10-12 — the 12 divergences measured on 2026-10-11 (surrogate pair refused, `+10` / `010` / a raw tab accepted, CRLF refused, `FILE_ERROR` on non-UTF-8, no usage errors in the CLI) are closed: the differential oracle with Swift is 0/106 (it was 12/89 on 2026-10-11; on the corpus of 2026-10-12 the code before the change counts 23/106); the parser now reads Unicode scalars, not grapheme clusters, compares keys scalar by scalar, and applies MAX_JSON_DEPTH = 512 (`deep-valid-600` is FAIL in all six, no longer declared). Tests by family (numbers, raw controls, `\u` escapes, surrogates, line endings, key equality, nesting, signature fields, non-UTF-8 bytes, CLI grammar) fail on the code before the change (10 of the 11 new tests; the whitespace one already passed there). In CI it has its own macOS job (`swift test` and the intact / tampered gate) and is not part of the differential oracle |

The JS verifier is cross-checked at test time by running the actual Python reference
as an independent oracle: it must produce the same verdict/chain_integrity/algorithm
on every vector, so a self-serving bug (agreeing only with itself) is caught.

Honest scope: these verifiers prove integrity and linkage — and signatures in the JS, Go, Java and Swift verifiers
and in `signer.py verify`, not in `verifier.py` or the Rust verifier (who checks what, and when a signature enters the
verdict: SPEC §5) — not the truth of the recorded facts; Ed25519 is not post-quantum.

## Canonical acceptance profile (enforced identically by all four + reference)

Verified by `verifiers/differential_oracle.py` (feeds an adversarial corpus to Python|JS|Rust|Swift and
FAILS on any verdict disagreement — 0 disagreements). The profile a valid ledger MUST satisfy; anything
outside it is REJECTED uniformly (not silently transformed):

- Numbers: integers only, in the portable range +/-(2^53-1). **No floats** (decimals travel as strings),
  **no NaN / Infinity**, no integer beyond the range.
- Objects: **no duplicate keys** (top-level or nested; escaped duplicates like `"a"` vs `"\u0061"` too).
- Strings: valid UTF-8; an unpaired UTF-16 surrogate escape is refused by all six (named `lone_surrogate` by the four whose receipts carry reasons; oracle
  cases `lone-surrogate-hashed-dropped` / `-fffd` / `-kept`, `low-surrogate-hashed-dropped` and `surrogate-split-by-escape`,
  whose self_hash is computed over what a lax decoder reads, 2026-10-12). Closed on 2026-10-12 (each with an oracle case, FAIL in all six; on the code before, the case disagrees): a raw byte
  that is not UTF-8, its self_hash computed over the code point Python's `surrogateescape` decoder gives it (`\udcff` for
  `0xFF`), was PASS in the reference alone — `verifier.py` now refuses a line holding such a code point (`not_utf8`,
  SPEC §3) (`non-utf8-byte-hashed-as-surrogateescape`, `…-in-key-…`); a UTF-8 BOM at the start of the file was PASS in JS
  (and in the Swift code of 0.20.0) (`bom-start`, `bom-then-blank-line`); a whole-number float lexeme (`1.0`, `0e0`), hashed as the integer it reads
  as, was PASS in JS alone (`float-whole-hashed-as-int`, `float-exp-idx-hashed-as-int`); an `idx` past 2^53-1 made JS
  throw without a receipt (`idx-past-2^53`). Closed the same day without an oracle case (tests in `verifiers/js/test.mjs`): a JS
  receipt larger than 64 KiB was cut when read through a pipe; a signed tip with a leading UTF-8 BOM was accepted by JS alone of the four verifiers that check tips (Python, Go and Java: unreadable).
- CLI: `--algo` takes only `sha256` and `sha3_256` in the four CLIs that have it (Python, JS, Rust, Swift); anything else
  is a usage error (`cli-algo-unknown`, `cli-algo-uppercase`; JS and Rust hashed SHA-256 and reported `"algorithm": "foo"`
  until 2026-10-12, Rust printing the value unescaped in its receipt). Not a divergence of outcome: `--algo=sha256`, the flag before the path and a `--` right before or right after the
  path are accepted by Python (argparse), which applies `--algo` (a `--` after a flag's value is a usage error there
  too), and are usage errors in JS, Rust and Swift; each verifier either applies the constraint or refuses the command
  (measured 2026-10-12, Python 3.9 / 3.11 / 3.13).

The four verifiers agreeing on the 6 normative vectors is necessary but NOT sufficient; the differential
oracle over the adversarial corpus is the real invariant. "Agree byte-for-byte" means *on this profile*.
