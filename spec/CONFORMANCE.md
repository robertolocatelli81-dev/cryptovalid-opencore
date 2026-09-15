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
| `verifiers/go/` | Go (stdlib) — verifier **and writer** (`Append`) | Roberto Locatelli | ✅ go test -race (shared `vectors.json`, refusals, concurrent appends), 6003-tamper bench identical to Python/JS (14/09/2026) |
| _your implementation here_ | | | |

## Optional profiles

- **Signatures** (`signer.py`): Ed25519 over `self_hash`. A signing-conformant tool re-derives
  `self_hash` from content and verifies the signature (content → self_hash → signature).
- **Signed chain tip** (`cryptovalid_tip.py`, 15/09/2026): the writer MAY publish `<ledger>.tip.json` =
  `{kind:"cryptovalid_tip/1", entries, ledger_id, tip_sha256, ts, log_pubkey_hex, signature_hex}`, Ed25519 over the
  canonical bytes `{"entries":N,"kind":"cryptovalid_tip/1","ledger_id":"…","tip_sha256":"…","ts":"…"}` (key order
  fixed, no spaces; `ledger_id` = `self_hash` of entry 0, the chain's identity). A tip-conformant verifier, given
  the tip and the TRUSTED log key: (1) verifies the signature against the trusted key (the key inside the tip is
  informative only); (2) FAILs `tip_of_another_ledger` when `ledger_id` is not the file's first `self_hash`,
  `ledger_id_mismatch` when it is not the identity the relying party expects (`--expect-ledger-id`, out of band:
  the only defence when a log key signs several ledgers and a whole pair file+tip is substituted),
  `tail_truncated` when the file has fewer entries than the tip, `unsealed_tail` when it has more,
  `tail_rewritten` when the count matches but the last `self_hash` differs; (3) when the tip is REQUIRED, a
  missing tip is `tip_missing`; a malformed tip is never silence (`tip_invalid` / `tip_unreadable`); (4) **without
  the trusted log key the tip is NOT checked** (`tip_untrusted`, `checked:false`; the key inside the tip proves
  nothing): the verdict is the bare chain's, and a required tip is a FAIL — never a "PASS but untrusted" an
  automation would read as exit 0; (5) `--tip-not-before` compares INSTANTS (ISO-8601 with `Z`, an offset, or
  naive = UTC), never strings; (6) formats are strict and identical in the three checkers — `ledger_id` and
  `tip_sha256` 64 lowercase hex, `ts` **RFC 3339 with seconds and a zone** (`Z` or `±hh:mm`; optional fraction of 1-9 digits) — validated by
  a HAND-WRITTEN range check identical in the three checkers (year 0001-9999, real calendar day with leap years,
  hour 0-23, minute/second 0-59, offset 00:00-23:59), never by a library date parser: until 0.11.2 the format rule
  was shared but `fromisoformat` / `Date.parse` / `time.Parse` disagreed on `2026-02-30`, hour `24`, year `0000`,
  a comma fraction, a 10-digit fraction and offset `+24:00` (measured, oracle cases `tip-feb30` … `tip-leap60`);
  `--tip-not-before` follows the same profile in the three checkers,
  `entries` a non-negative integer, an empty `log_pubkey_hex` = absent — a SIGNED tip outside the profile is
  `tip_invalid` (oracle cases `tip-garbage-ts`, `tip-upper-hex`, `tip-date-only-ts`, `tip-no-seconds-ts`: FAIL on
  Python/JS/Go, unchecked by Rust/Swift, declared; `tip-empty-pubkey`: PASS everywhere). A malformed
  `--tip-not-before` is the verifier's error (`bad_not_before`), never blamed on the tip; the instant resolution
  is one second (two tips signed in the same second are indistinguishable to `--tip-not-before`). These were
  measured divergences until 0.11.1 (review with Fable 5.1, 15/09/2026).
  Writers: `cryptovalid_ingest.Ingestor(tip_keyfile=…)` (every flush, O(1), same lock), Go `AppendSigned` /
  `cvappend -tipkey`, `cryptovalid_tip.py sign` (any file, O(n)). Verifiers: Python (reference), JS, Go;
  **declared divergence**: Rust and Swift ignore the tip (measured by the oracle case `tip-truncated`).
  What the tip does not prove: the holder of the log key can truncate and re-sign (key custody is the limit);
  and a **rollback** — truncation plus an OLDER genuine tip restored — passes, because the tip proves "a state
  the key signed", not "the latest": a verifier MAY refuse tips dated before a known instant
  (`--tip-not-before`, string comparison on the tip's ISO-8601 `ts`); the monitor state, receipts or an external
  anchor are the systematic answer. Types are strict: `entries` is a non-negative JSON integer (a `"10"` or
  `10.0` would sign the same bytes but is refused by all three checkers).
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
- 513 levels → Python **FAIL** `json_too_deep`; a valid 600-level entry → Python FAIL, **JS PASS** (measured 13/09).
  **Closed on 14/09/2026:** the JS verifier and the Go reference (`verifiers/go`) now apply the same linear
  pre-scan and the same bound; a 600-level line is FAIL `json_too_deep` in all three.

## Declared profile limit — unpaired UTF-16 surrogates (normative, 2026-09-14)

A `\uD800`–`\uDFFF` escape that is not part of a high+low pair is **outside the acceptance profile** and refused
fail-closed (`lone_surrogate`) by the three references (Python `verifier.has_lone_surrogate`, JS
`hasLoneSurrogate`, Go `cryptovalid.Parse`). Reason, measured on 14/09 (council round 1 on the Go reference):
Python and JS decoders keep a lone surrogate and re-emit `\ud800`, Go's stdlib decoder silently replaces it with
U+FFFD — same file, different `self_hash`. A lone surrogate is not a Unicode scalar value and cannot be UTF-8
encoded, so §3's "non-UTF-8 bytes forbidden" already excluded it; this makes the exclusion explicit and testable.
Valid pairs (`\ud83d\ude00` = U+1F600) are unaffected; a malformed escape (`\uzzzz`) is NOT this rule's
business — the decoder refuses it as a decode error (council round 2). **Writer note (Go `Append`, declared):** a
crash between write and fsync can leave a torn last line without newline; the next append refuses to continue
from it ("torn last line") — recovery is a human decision (verify, truncate the torn bytes, record the incident).
The check is on the last byte ON DISK, always (council round 3): a *complete* last entry that lost only its `\n` is
refused too (recovery = verify, append the missing newline), because continuing would write the next entry on the
same line and the writer itself would corrupt the chain. **Three writer policies, declared (council round 4, 15/09/2026):** (1) Go `Append` REFUSES — it reads only the
last line, never re-verifies the chain, so it has no right to repair; (2) the Python ingest writer
(`cryptovalid_ingest._resume`) TRUNCATES an unterminated tail (an un-acknowledged write: `flush()` had not
returned); (3) OMEGA's operational `PersistentLedger` (private repo) REPAIRS — it re-verifies every hash and link
of the whole file on open, so a complete, verified last entry that only lost its `\n` is closed with the missing
newline at once, with a logged warning. Same invariant everywhere: two records are never fused on one line, and a
tail that does not parse is never continued from. **Rust updated 15/09/2026** (toolchain installed in the sandbox):
`verifiers/rust/src/json.rs` now enforces the same rule — `MAX_JSON_DEPTH` = 512 (`json_too_deep`), surrogate
pairs combined into one scalar, unpaired surrogates refused (`lone_surrogate`), exactly four hex digits per
`\u` escape. Until then the Rust parser refused even a **valid** pair (`\ud83d\ude00` → "bad scalar"): an
undeclared divergence from Python/JS/Go that nobody had measured because Rust was not in the local oracle run.
**Declared divergence (remaining): Swift** was not updated (no toolchain): a lone-surrogate line or a line
deeper than 512 is FAIL on Python/JS/Go/Rust and still parsed by Swift; the oracle accepts only that pattern as
declared, never as agreement.
- What bounds the verifiers is now a RULE in four of five: **JS** (V8 `JSON.parse` + linear pre-scan), **Rust**
  (depth counter in the recursive-descent parser: 2000 levels = one parse refusal, no stack abort), **Go** (linear
  pre-scan). **Swift** (`JSONValue.swift`) has no guard beyond its stack, and the Linux CI job does not build the
  Swift binary, so Swift is not exercised by the oracle in CI (its macOS job runs the Swift suite and the
  tampered-ledger gate). Oracle corpus (16 cases, 15/09/2026): `deep-nesting-2000` = FAIL everywhere;
  `deep-valid-512` (at the bound) = PASS everywhere; `deep-valid-600`, `lone-surrogate` = FAIL on the four
  references (Swift declared); `valid-surrogate-pair` = PASS everywhere; `empty` = FAIL everywhere (the Go
  reference answered a third verdict "EMPTY" until 15/09 — found the day Go joined the oracle). Local run with
  Python+JS+Go+Rust: 0/16 disagreements.
- The PASS side is guarded too: the reference raises its own recursion headroom before decoding, so an
  in-profile line is accepted even when `verify_ledger` is called from a deep caller stack (test with a
  700-frame caller; RED without the headroom). Inputs larger than **`MAX_INPUT_BYTES` = 256 MiB** are refused
  fail-closed (`input_too_large`) before being read.
- Declared platform limits (council review, not measured here): the recursion headroom raises the interpreter
  limit, it cannot enlarge the thread's C stack — on a thread with a very small stack the C decoder could still
  die without a receipt; on CPython ≥ 3.12 the C decoder keeps its own counter, so the "RED without headroom"
  control was reproduced on 3.11 only; the linear pre-scan is pure Python (~seconds per 100 MB), a cost, not a
  crash. Rust was executed locally on 15/09/2026 (7 cargo tests + the oracle); Swift was **not** (no toolchain):
  its first measurement is the macOS CI job.
