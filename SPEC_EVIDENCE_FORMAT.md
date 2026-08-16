<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- Copyright (C) 2026 Roberto Locatelli -->

# CryptoValid Evidence Format — candidate standard v0.2 (2026-08-13)

License: AGPL-3.0-or-later (see LICENSE). Status: **candidate standard** — defined by CONFORMANCE
TEST VECTORS (see `CONFORMANCE.md` + `spec/vectors/`), so any implementation in any language can prove
interoperability. This is the moat that a copyable feature is not: a shared, adopted format. Comments and
independent implementations welcome (open a PR to the conformance table).

## Design goals

1. **Re-executable**: any third party recomputes every hash from the file alone.
2. **Vendor-free**: verification needs only this spec + a ~300-line stdlib
   verifier. No server, no account, no token.
3. **Append-only**: any reordering, deletion or insertion breaks the chain.
4. **Honest scope**: the format proves *what was recorded, when, in which order,
   and that it was not altered afterwards*. It does NOT prove the recorded facts
   themselves — provenance fields say who/what asserted them.

## 1. Ledger container

A ledger is a UTF-8 **JSONL** file: one JSON object per line, no blank lines
required, order = chain order.

## 2. Entry schema (core fields)

| Field | Type | Meaning |
|---|---|---|
| `idx` | int | 0-based position; MUST equal the line's position |
| `ts` | string | ISO-8601 UTC timestamp of the recording |
| `data` | object | The evidence payload (free-form, see §4) |
| `prev_hash` | hex string | `self_hash` of entry `idx-1`; entry 0 uses 64 zeros |
| `self_hash` | hex string | hash of the entry's canonical form (§3) |

Optional fields (verified when present):
| Field | Type | Meaning |
|---|---|---|
| `signature` | hex | Ed25519 signature over the canonical form (§3), by `signer` |
| `signer` | hex | Ed25519 public key (32 bytes hex) of the recording party |
| `tsa_token` | base64 | RFC 3161 timestamp token over `self_hash` |

## 3. Canonicalisation and hashing (NORMATIVE — interoperability depends on it)

Canonical form of an entry = JSON serialisation of the object **without**
`self_hash`, `signature`, `signer`, with **exactly** these rules (so any language
produces identical bytes — a single differing byte breaks the hash):

- keys sorted lexicographically (`sort_keys`), applied **recursively**;
- separators `(",", ":")` — no insignificant whitespace;
- **ASCII-escaped output** (`ensure_ascii=true`): every non-ASCII character is a
  `\uXXXX` escape. This removes the `é` vs `é` ambiguity across languages.

To keep the bytes deterministic, a conforming ledger **MUST NOT** contain, anywhere
in an entry:
- **floating-point numbers** — represent decimals as strings (e.g. `"400000.00"`)
  or integers. (`1.0` vs `1` vs `1e0` are not interoperable.)
- **duplicate object keys** — a strict parser MUST reject them.
- non-UTF-8 bytes.

`self_hash = HEX( H(canonical_bytes) )` where `H` is **SHA-256** (profile
`sha256`, default) or **SHA3-256** (profile `sha3_256`). A ledger uses ONE
profile throughout; verifiers MUST auto-detect by recomputing entry 0.
(A future minor version may adopt RFC 8785 JCS; the constrained profile above is a
strict subset that stdlib `json` already produces, chosen to stay vendor-free.)

Chain rule: `entry[i].prev_hash == entry[i-1].self_hash`; `entry[0].prev_hash`
is `"0" * 64`. Genesis is not special-cased beyond that.

**Replay binding (recommended).** The signature covers `self_hash`, which covers
`{idx, ts, data, prev_hash}` — this binds an entry to its POSITION within a chain but
not to a chain IDENTITY. To prevent a signed entry being replayed into a different
ledger, entries SHOULD carry a `ledger_id` (a random 128-bit hex) inside `data` of
entry 0 (and it is thus covered by every entry's `prev_hash` transitively). Verifiers
MAY require a single consistent `ledger_id` per file.

## 4. Evidence payload (`data`) conventions

The payload is domain-specific but SHOULD carry provenance:

```json
{
  "kind": "registry_check",
  "subject": "<who/what was verified>",
  "source": {"name": "ESMA CASP register", "url": "...", "fetched_utc": "..."},
  "source_snapshot_sha256": "<hash of the raw source document>",
  "outcome": "FOUND | NOT_FOUND | INCONCLUSIVE",
  "detail": {}
}
```

`INCONCLUSIVE` (source unreachable) is a first-class outcome: the format never
forces a boolean where reality had none.

## 5. Verification algorithm (normative)

1. Parse every line as JSON; any parse error → FAIL.
2. Detect profile on entry 0; recompute `self_hash` for EVERY entry → any
   mismatch → FAIL.
3. Check the chain rule for every entry → any mismatch → FAIL.
4. Check `idx == position` for every entry → any mismatch → FAIL.
5. If `signature`/`signer` present: verify Ed25519 over the canonical form.
6. If `tsa_token` present: verify the RFC 3161 token binds `self_hash` and a
   TSA time consistent with `ts`.
7. Emit a JSON receipt including counts, failures (capped), verdict PASS/FAIL,
   and the receipt's own SHA-256 (receipt-of-receipt, deterministic: timestamp
   excluded).

Reference implementation: `verifier.py` (steps 1–4 + receipt, stdlib-only); `signer.py` (step 5,
Ed25519); `evidence_pack.py` (step 6, RFC 3161 — verified today against a real DigiCert TSA). Steps 5–6
are OPTIONAL profiles; their absence never weakens steps 1–4.

## 6. Versioning

The spec is versioned semver-style. Ledgers MAY carry
`{"spec": "cryptovalid-evidence/0.2"}` inside `data` of entry 0. Breaking
changes bump major; verifiers state the versions they support.

## 7. Conformance (normative)

The standard is defined by the conformance test vectors in `spec/vectors/`. A verifier conforms iff,
for every vector, it reproduces the vector's `normative` block (verdict, chain integrity, detected
algorithm, entry count, and the sets of failing indices for hash and linkage). See `CONFORMANCE.md`.
Run `python3 conformance.py` (exit 0 = conformant). Independent implementations (Go, Rust, JS, …) claim
conformance the same way and are listed in the conformance table.

## 8. Regulatory profiles (self-updating, provenance-carrying)

A ledger entry MAY declare which EU requirement it supports:
`data.regulatory_ref = "<id>"` where `<id>` is an entry in `spec/regulatory_profiles.json`
(e.g. `MiCA`, `AI-Act-AnnexIII`, `DORA`, `GDPR`). Each profile carries `status`, `effective_utc`,
`source_url` and an `as_of` date.

`refresh_regulatory.py` keeps the profiles HONEST: it re-checks source reachability, stamps
`last_checked_utc`, and FLAGS any entry older than the staleness window for human re-verification
against its PRIMARY source (exit 1 if anything needs review). **Honest scope:** the mapping is
provenance-carrying and self-monitoring, NOT legal advice and NOT a compliance claim; a stale entry is
flagged, never silently trusted — the format never lets outdated regulatory status pass unnoticed.

## 6. Optional Merkle extension (RFC 6962) — efficient inclusion & consistency

For large ledgers, `cryptovalid_merkle.py` builds an **RFC 6962** Merkle tree over the
canonical form of each entry (§3), giving:

- **inclusion proofs** — verify one entry in `O(log n)` (audit path), no full-chain recompute;
- **consistency proofs** — cryptographic proof that a newer ledger *append-only extends* an older one;
- a **Signed Tree Head** (`{tree_size, root_sha256}`) — the `root_sha256` is the value to submit
  to a **qualified TSP** (eIDAS EU Trusted List) for a *qualified* RFC 3161 timestamp.

This is an **optional, additive** layer: the linear hash-chain (§2, §3) remains the interoperable
core; Merkle proofs are computed on demand and verified by any third party with
`(entry, index, tree_size, audit_path, root)`. Domain separation: `0x00` leaves, `0x01` nodes.
