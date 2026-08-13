<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- Copyright (C) 2026 Roberto Locatelli -->

# Worked example — verify it yourself in 10 seconds

Two small ledgers demonstrate the whole point: **trust replaced by verification**.
The verifier is ~300 lines of Python standard library — no server, no account, no vendor.

## 1. An intact ledger → PASS

```
$ python3 ../verifier.py sample_ledger.jsonl
```
```json
{
  "algorithm_used": "sha256",
  "entries_count": 3,
  "hash_recompute_passed": true,
  "link_passed": true,
  "chain_integrity": true,
  "verdict": "PASS",
  "receipt_sha256": "a1784f04ff0072cdfbec70e7466981ba6ecfff732ce17b152363c12779ca1264"
}
```
Exit code `0`. A third party recomputed every SHA-256 hash from the file alone and
reached the same values, and every `prev_hash` links to the previous `self_hash`.

## 2. A tampered ledger → FAIL, and it says WHERE

`sample_ledger_tampered.jsonl` is a copy of the intact ledger with **one field changed**
in entry 1 (`decision`: `onboard` → `reject`) *without* recomputing its hash.

```
$ python3 ../verifier.py sample_ledger_tampered.jsonl
```
```json
{
  "hash_recompute_passed": false,
  "hash_failures": [
    { "idx": 1, "reason": "hash_mismatch",
      "expected": "f52c1655…", "computed": "46c74bd6…" }
  ],
  "chain_integrity": false,
  "verdict": "FAIL"
}
```
Exit code `1`. The file itself tells you the break is at **entry 1** — no vendor, no
dashboard, no trust required. That is the difference between "we promise it wasn't
altered" and "here is a file anyone can re-execute to prove it wasn't."

## Format

Each line is a JSON object `{idx, ts, data, prev_hash, self_hash}` where
`self_hash = SHA-256( canonical-JSON(entry without self_hash) )` and
`prev_hash` of entry *i* equals `self_hash` of entry *i-1* (entry 0 uses 64 zeros).
Full specification: [`../SPEC_EVIDENCE_FORMAT.md`](../SPEC_EVIDENCE_FORMAT.md).

**Honest scope:** the chain proves *what was recorded, when, in which order, and that
it was not altered afterwards* — not the truth of the recorded facts (provenance
fields say who/what asserted them).
