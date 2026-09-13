<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- Copyright (C) 2026 Roberto Locatelli -->

# CryptoValid Evidence Format — Conformance

A standard is defined by **interoperability**, not by one implementation. This file is how any verifier
— in any language — proves it conforms.

## The conformance test vectors

`spec/vectors/` contains input ledgers and, for each, a `*.expected.json` with a **normative** block:

```json
{
  "input": "tampered_content.jsonl",
  "normative": {
    "verdict": "FAIL",
    "chain_integrity": false,
    "algorithm": "sha256",
    "entries": 3,
    "hash_failures_idx": [1],
    "link_failures_idx": []
  }
}
```

A **conformant verifier** MUST, for every vector, reproduce the `normative` fields:
- the same `verdict` (PASS / FAIL),
- the same `chain_integrity`,
- the same auto-detected `algorithm`,
- the same `entries` count,
- the same **set of failing entry indices** for hash recompute and for chain linkage.

Nothing else is required. Your receipt may look however you like; only these facts are normative.
The current vectors cover: valid SHA-256, valid SHA3-256, tampered content, broken linkage, non-monotonic
`idx`. Contributions of new vectors (edge cases) are welcome.

## Claim conformance

1. Run each `spec/vectors/*.jsonl` through your verifier.
2. Compare your result to that vector's `normative` block.
3. If all match, you conform. Open a pull request adding your implementation to the list below.

The reference runner checks the reference verifier:

```bash
python3 conformance.py     # exit 0 = conformant
```

## Known implementations

| Implementation | Language | Author | Conformance |
|---|---|---|---|
| `verifier.py` (reference) | Python (stdlib) | Roberto Locatelli | ✅ 7/7 vectors |
| `verifiers/js/cvverify.mjs` | Node (stdlib) | Roberto Locatelli | ✅ 7/7 vectors, cross-oracle vs reference in CI |
| `verifiers/rust/` | Rust (std) | Roberto Locatelli | ✅ cargo test + tampered-ledger rejection in CI |
| `verifiers/swift/` | Swift (swift-crypto) | Roberto Locatelli | ✅ swift test + tampered-ledger rejection in CI (macOS job) |
| _your implementation here_ | | | |

## Optional profiles

- **Signatures** (`signer.py`): Ed25519 over `self_hash`. A signing-conformant tool re-derives
  `self_hash` from content and verifies the signature (content → self_hash → signature).
- **RFC 3161** timestamping: the token's message imprint MUST equal the stamped digest.
- **Regulatory profiles** (`spec/regulatory_profiles.json`, self-updated by `refresh_regulatory.py`):
  a ledger entry MAY set `data.regulatory_ref = "<id>"` to declare which EU requirement it supports.
  The profile carries provenance and an `as_of` date; stale entries are flagged, never silently trusted.

## Declared profile limit — nesting depth (normative, 2026-09-13)

**`MAX_JSON_DEPTH = 512`.** A line whose JSON nesting exceeds 512 levels is outside the acceptance profile. The
reference verifier measures nesting with a **linear pre-scan** (`verifier.json_nesting_depth`: no recursion, no
parsing, brackets inside strings ignored) and refuses deeper lines **fail-closed** with `json_too_deep` — a FAIL
receipt, exit 1. Before v0.9.4 a ~5000-level line crashed the Python reference with a traceback (no receipt), which
is not a verdict. The same pre-scan guards `ap2_evidence.verify_evidence` and `evidence_pack.verify_pack`.

Measured on 2026-09-13 (`test_verifier_depth.py`, 9 tests; 8 of them RED when run against the v0.9.3 `verifier.py` = positive control, measured, not assumed):
- a valid chained entry nested exactly 512 levels → **PASS** on Python and on JS (identical digests);
- 513 levels → Python **FAIL** `json_too_deep`; a valid 600-level entry → Python FAIL, **JS PASS**. This is the
  declared divergence *outside* the profile: the other verifiers do not enforce the 512 bound.
- What bounds the other verifiers is their own stack, not a rule: **JS** uses V8 `JSON.parse`; **Rust** has zero
  dependencies and a hand-written recursive-descent parser (`verifiers/rust/src/json.rs`) with no explicit depth
  guard — beyond the thread stack it aborts, and the differential oracle counts a crash as a disagreement
  (`NONJSON/CRASH`), never as agreement; **Swift** likewise (`JSONValue.swift`), and the Linux CI job does not build
  the Swift binary, so Swift is not exercised by the oracle in CI (its macOS job runs the Swift suite and the
  tampered-ledger gate). Oracle corpus: `deep-nesting-2000` (malformed, 2000 levels) = FAIL on Python and JS;
  `deep-valid-512` (valid, at the bound) = PASS on both; `deep-valid-600` (valid, beyond the bound) = the one
  **declared divergence** — Python FAIL / JS PASS — kept in the corpus and reported as `[DECL]`, never counted
  as agreement (local run: 0/14 undeclared disagreements, 1 declared; Rust is checked by the CI oracle).
- The PASS side is guarded too: the reference raises its own recursion headroom before decoding, so an
  in-profile line is accepted even when `verify_ledger` is called from a deep caller stack (test with a
  700-frame caller; RED without the headroom). Inputs larger than **`MAX_INPUT_BYTES` = 256 MiB** are refused
  fail-closed (`input_too_large`) before being read.
- Declared platform limits (council review, not measured here): the recursion headroom raises the interpreter
  limit, it cannot enlarge the thread's C stack — on a thread with a very small stack the C decoder could still
  die without a receipt; on CPython ≥ 3.12 the C decoder keeps its own counter, so the "RED without headroom"
  control was reproduced on 3.11 only; the linear pre-scan is pure Python (~seconds per 100 MB), a cost, not a
  crash. Rust and Swift were **not** executed on the three depth cases locally (no toolchain in the sandbox):
  the first measurement is the CI oracle run of this release.
