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
| `verifiers/go/` | Go (stdlib) — verifier **and writer** (`Append`) | Roberto Locatelli | ✅ go test -race (shared `vectors.json`, refusals, concurrent appends), 6003-tamper bench identical to Python/JS (14/09/2026); hybrid ML-DSA-65 tip check with `crypto/mldsa` (Go ≥ 1.27, 15/09/2026) |
| `verifiers/java/CvVerify.java` | Java (JDK stdlib, single file, JDK 24+ for ML-DSA) | Roberto Locatelli | ✅ intact/tampered gate in CI (JDK 27) + in the differential oracle: verdicts, tip tri-state and per-entry Ed25519 + ML-DSA-65 signatures identical to Python/Go (16/09/2026) |
| _your implementation here_ | | | |

## Line rules and bounds (one rule in the five verifiers, 16/09/2026)

- **Line separator**: LF only. A lone CR is data inside the line (it makes the line undecodable: two entries
  separated by CR are one line with trailing data). No universal-newline translation.
- **Blank line**: a line holding nothing but ASCII space (0x20), tab (0x09) and CR (0x0D) is skipped; any other
  character (U+00A0, U+0085, U+000C…) makes it a line that must decode as an entry, or fails.
- **`\uXXXX` escapes**: exactly four ASCII hex digits (`0-9a-fA-F`); a sign or a non-ASCII digit is a decode error
  (Java's `Integer.parseInt` would have taken `\u+041`).
- **`idx`**: a JSON integer; a boolean is not an index (Python's `True == 1` was measured and refused).
- **Size**: the Python reference and the Java verifier refuse a file over 256 MiB (`input_too_large`) before
  reading it; the Go, JS and Rust verifiers bound a single line (Go: 64 MiB) but not the file — a 300 MiB valid
  ledger is FAIL in Python/Java and PASS elsewhere (declared divergence, outside the acceptance profile).

## Optional profiles

- **Signatures** (`signer.py`): Ed25519 over `self_hash`. A signing-conformant tool re-derives
  `self_hash` from content and verifies the signature (content → self_hash → signature). The attestation fields
  excluded from the content hash are exactly `self_hash`, `signature`, `signer`, `signature_pq`, `signer_pq`
  (the last two since 0.12.0; a verifier of an earlier version treats them as content and FAILs a hybrid ledger —
  declared, not interop).
- **Hybrid post-quantum signatures** (0.12.0, optional; context changed in 0.13.0). Algorithm: **pure ML-DSA-65**
  (FIPS 204 pure ML-DSA, NOT HashML-DSA) with the **EMPTY context string**. 0.12.0 used the contexts
  `cryptovalid/entry/1` / `cryptovalid/tip/1`; 0.13.0 dropped them after checking the ecosystem (16/09/2026): the
  JDK's built-in ML-DSA provider (JDK 24 → 27, JEP 497) has no API to set a context ("not a goal"), so a plain JDK
  `verify(pk, msg, sig)` cannot check a context-signed signature (AWS KMS could have produced one through
  `EXTERNAL_MU`; the constraint was the JDK verifier, not the HSM). Entries and tips are separated by message FORMAT
  instead: an entry message is 64 lowercase hex characters, a tip message is a JSON object (first byte `{`), so the
  two byte sets are disjoint and, since every verifier re-derives the message itself, no signature of one can be
  replayed as the other (declared). That separation covers entry↔tip only: **the ML-DSA key MUST be dedicated to
  this profile** (with no context, any other application signing a 64-hex string with the same key would produce a
  valid entry signature — the Ed25519 layer has the same property) and a KMS key policy SHOULD restrict it to the
  signing principal. 0.12.0 signatures (with a context) do NOT verify under 0.13.0 and vice versa: a 0.12.0 hybrid
  ledger reads as `invalid` under 0.13.0 (declared; re-sign it). Entry message = the **UTF-8 bytes of the 64-character lowercase-hex
  `self_hash` string** (the identical bytes Ed25519 signs; not the 32 decoded bytes). `signature_pq` = the 3309-byte
  signature (FIPS 204 allows hedged and deterministic signing: two signatures of one message MAY differ, so nothing
  may compare signature bytes), `signer_pq`
  = the 1952-byte public key (FIPS 204 pkEncode); both standard base64 with padding, decoded STRICTLY (no
  whitespace or foreign characters, canonical length; keys are compared as base64 strings, so a non-canonical
  re-encoding of the right key is a mismatch). Tip: `signature_pq_hex` = 6618 lowercase hex over the same
  canonical tip payload, `log_pq_pubkey_b64` = the key; when either optional field is PRESENT (even as `null` or
  `""`) both must be present AND well-formed or the tip is `tip_invalid` in Python, JS, Go and Java; the tip document
  itself is parsed with the SAME strict acceptance profile as the entries (no duplicate keys, no floats, bounded
  integers, depth/surrogate pre-scan, every field a string except `entries`) — it is a signed document, an ambiguous
  encoding is refused, not guessed (16/09/2026; Rust and Swift do not read
  tips: declared); `signature_hex` too: 128 lowercase hex, and the entries' `signature`/`signer` are decoded
  strictly as well. Semantics of
  `pq_protected`: **true** only when EVERY entry (or the tip) carries a valid ML-DSA-65 signature by the PINNED key
  (the expected / trusted key given by the relying party) AND the Ed25519 layer holds (hybrid = both);
  **null** when a layer is present but not pinned (verified against the key inside the file only, which anyone
  can put there) or not verifiable on the host; **false** when absent, invalid, foreign, malformed or partial.
  Giving the pinned key REQUIRES the layer: a stripped or partial ledger is `pq_missing`, a layer that cannot be
  verified on the host is `pq_unverifiable`, and in both cases `ok` is false at library level (not only exit 1 in
  the CLI); when the layer is NOT required and the host cannot verify ML-DSA, `ok` reflects the classical layer
  only (`pq_status: unverifiable`, `pq_protected: null`) — a present-but-unpinned layer grants nothing either way;
  `require_pq` without a key, and a PQ key without the Ed25519 key, are refused by the library and the
  CLI alike; a trusted PQ key on the tip implies a required tip and needs the trusted Ed25519 log key
  (`pq_key_without_log_key`). Both keys must be pinned for the AND guarantee (with only the PQ key, a re-signed
  Ed25519 layer by a foreign key would still verify).
  Who checks what (0.13.0): per-entry Ed25519 + ML-DSA-65 — Python (`signer.py`, `cryptography` ≥ 50), Go
  (`cvverify -pubkey -pq-pubkey [-require-pq]`, `crypto/mldsa`, Go ≥ 1.27) and Java (`CvVerify.java`, JDK 24+,
  `Signature.getInstance("ML-DSA-65")`), all with the same tri-state and the same rules (a PQ key needs the Ed25519
  key and requires the layer; with a caller-given key a failing layer is a FAIL); the tip's ML-DSA-65 — Python, Go
  and Java; an older Go toolchain or a JDK < 24 answers `pq_unverifiable` (a FAIL when the key is
  required; the compat path is not exercised by CI, declared); JS verifies per-entry Ed25519 only, Rust and Swift
  none of the signatures (the JS tip checker reports null/false, never true; declared in the differential oracle,
  which also compares the tri-state between Python and Go). Any FIPS 204 implementation with a plain
  `verify(pk, msg, sig)` (JDK 24+, OpenSSL 3.5, .NET 10, Go 1.27) can verify the layer: the message is the bytes
  above and the context is empty (measured with `cryptography`, Go `crypto/mldsa` and the JDK 27 verifier; OpenSSL
  3.5 and .NET 10 are expected from their documented APIs, not measured). **The evidence pack is not quantum-resistant on its own**: its manifest records
  `pq_protected`, `pq_status`, `signers` and `pq_signers` per ledger but is signed with Ed25519 only, so
  `verify_pack` confirms a ledger's layer ONLY against keys the caller pins (`pq_pubkey_b64` + `signer_pubkey_hex`,
  or the manifest's recorded keys when the caller pins `manifest_signer_hex` and BOTH the manifest digest and its
  signature verify — a malformed recorded key means "not pinned", never an exception);
  with nothing pinned the manifest's claim is reported `null` with `pq_reason: manifest_unpinned`, never `true`
  (a forged, unsigned manifest cannot promote itself). A pinned build (`build_pack(..., pq_pubkey_b64,
  signer_pubkey_hex)`) refuses to write a pack whose layer does not verify. The PQ private key is a file (PKCS#8,
  0600) or, since 0.13.0, an **AWS KMS key** (`KeySpec ML_DSA_65`, `ML_DSA_SHAKE_256`, `MessageType RAW` —
  `signer.py sign --pq-kms <key>`, `cryptovalid_tip.py sign --pq-kms <key>`; real round-trip 16/09/2026, verified
  by `cryptography`, Go and the JDK 27 verifier): the same custody model as the Ed25519 `awskms` backend, the
  private key never in process memory; KMS keys live in FIPS 140-3 validated HSMs (whether ML-DSA is inside the
  validated boundary is AWS's statement, not measured here); FIPS 204 allows hedged or deterministic signing and
  the tools never compare signature bytes; every signature is self-verified against the declared key right after
  signing, and the Sign response's KeyId must match the key whose public key was read. Cost: about 4.4 KB of base64 signature and 2.6 KB of base64 key per entry (the key is repeated
  on every entry so each line verifies on its own).
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
  digits are ASCII `0-9` only (Python's `\d` would take Unicode digits — measured, refused since 0.11.3), and the
  instant is compared as the INTEGER PAIR (epoch seconds, nanoseconds) in the three checkers — never through a
  library date type, whose fraction precision (µs / ms / ns) ordered two instants differently at a sub-millisecond
  `--tip-not-before` boundary, and whose `Date.UTC` mapped years 1-99 to 1900+ in JS (both measured, oracle
  `ordering-*` vectors); `--tip-not-before` follows the same profile in the three checkers,
  `entries` a non-negative integer, an empty `log_pubkey_hex` = absent — a SIGNED tip outside the profile is
  `tip_invalid` (oracle cases `tip-garbage-ts`, `tip-upper-hex`, `tip-date-only-ts`, `tip-no-seconds-ts`: FAIL on
  Python/JS/Go, unchecked by Rust/Swift, declared; `tip-empty-pubkey`: PASS everywhere). A malformed
  `--tip-not-before` is the verifier's error (`bad_not_before`), never blamed on the tip; the instant is compared
  as the integer pair (seconds, nanoseconds), so two tips signed in the same second are told apart by their
  fraction (measured by the `ordering-*` oracle vectors). These were
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
