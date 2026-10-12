<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- Copyright (C) 2026 Roberto Locatelli -->

# CryptoValid Evidence Format — candidate standard v0.3 (2026-10-12)

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

Optional fields — attestations over `self_hash`, added after it is computed and outside the canonical form (§3). A
present field is not verified by being present: which verifier checks which field is in §5 (steps 5–6; until 0.20.1 this
line read "verified when present", which `verifier.py` and the Rust verifier do not do for any of them):
| Field | Type | Meaning |
|---|---|---|
| `signature` | base64 | Ed25519 signature over the `self_hash` string (its UTF-8 bytes), by `signer` |
| `signer` | hex | Ed25519 public key (32 bytes hex) of the recording party |
| `tsa_token` | base64 | RFC 3161 timestamp token over `self_hash` (message imprint = its 32 bytes); outside the canonical form since 0.20.2 (§3) |
| `signature_pq` | base64 | ML-DSA-65 signature over the `self_hash` string (its UTF-8 bytes), by `signer_pq` (hybrid ledgers, `signer.py`) |
| `signer_pq` | base64 | ML-DSA-65 public key of the recording party |

### 2.1 Closed entry schema (NORMATIVE, v0.2.1 — 2026-10-10)

The entry is a CLOSED object: its top-level keys are exactly the core fields plus the optional fields of the two
tables above. A top-level key outside that list is a verification FAIL with the named error `unknown_field:<key>`,
never a silent pass — measured on 2026-10-10: a ledger whose entries were written with an extra top-level key (hash
recomputed over it) verified PASS in the reference with no trace in the receipt. The `data` payload stays
domain-specific (§4): keys inside `data` are not constrained by this section. The same rule applies to the evidence
pack manifest (`evidence_pack.py`): `MANIFEST.json`, each `ledgers[i]` entry and the `rfc3161_timestamp` block are
closed objects (keys listed in `evidence_pack.MANIFEST_KEYS`, `LEDGER_ENTRY_KEYS`, `RFC3161_KEYS`); an unknown key
is `manifest_unknown_field` and the pack is not valid. The ledger rule is applied by every verifier of `verifiers/`
(JS, Go, Java, Rust, Swift — aligned 2026-10-11, see CONFORMANCE.md): the same closed list, the failure named
`unknown_field:<keys>` (keys in code-point order; Rust and Swift, whose receipts carry no reason text, name the entry in
`schema_failures_idx`). The pack manifest is verified by the reference only (`evidence_pack.py`): the other verifiers do
not read packs. Two conformance vectors fix the rule: `unknown_top_level_key` (FAIL) and `unknown_key_in_data` (PASS). Since 0.20.0 the reference applies this
section and §5 step 4 on every path: the fallback 0.19.0 declared (a ledger whose first three entries carried no `idx`, no
algorithm forced, read by a generic path that applied neither) is removed; such a ledger is FAIL with `idx_mismatch` named.

## 3. Canonicalisation and hashing (NORMATIVE — interoperability depends on it)

Canonical form of an entry = JSON serialisation of the object **without** the attestation fields
`self_hash`, `signature`, `signer`, `signature_pq`, `signer_pq`, `tsa_token` (§2; corrected 2026-10-12, the list named only
the first three; `tsa_token` is in the list since 0.20.2 — a token over `self_hash` cannot be inside the bytes `self_hash` is
computed from: until 0.20.1 the six verifiers hashed it as content, so a token that binds its own `self_hash` failed step 2
and only a value that binds something else could pass. A ledger written with `tsa_token` hashed as content fails step 2
from 0.20.2 on; on 2026-10-12 none was found — 2 880 `.jsonl` files in four directory trees of the author's machine, 315 057 JSON objects, no
top-level `tsa_token` — and no writer in this repository produces the field), with **exactly** these rules (so any language
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
5. If `signature`/`signer` present: verify Ed25519 over the `self_hash` string (its UTF-8 bytes).
6. If `tsa_token` present: verify the RFC 3161 token binds `self_hash` and a
   TSA time consistent with `ts`. (No verifier in this repository performs this step: see below.)
7. A ledger with zero entries is FAIL (nothing was verified; `empty_ledger` error). Emit a JSON receipt including counts, failures (capped), verdict PASS/FAIL,
   and the receipt's own SHA-256 (receipt-of-receipt, deterministic: timestamp
   excluded).

Reference implementation: `verifier.py` (steps 1–4 + receipt, stdlib-only); `signer.py verify` (step 5, Ed25519 and,
when present, ML-DSA-65). Steps 5–6 are OPTIONAL profiles; their absence never weakens steps 1–4. Who performs them,
measured on 2026-10-12 (0.20.2) on a three-entry ledger with one signature changed, missing, malformed or by another key:

- `verifier.py` and the Rust verifier do not verify signatures and have no key option: a broken signature is PASS.
- `signer.py verify` verifies every entry: an unsigned, broken, malformed or partial layer is `ok: false`, exit 1, with or
  without `--pubkey`; with `--pubkey` a foreign signer is too.
- The JS, Go, Java and Swift verifiers verify Ed25519 when an entry carries `signature` or a key is given (`--pubkey`,
  Go/Java `-pubkey`). Without a key the result is reported (`signatures.all_verified` in JS, `signatures.ok` in Go and
  Java, `signatures_all_verified` in Swift) and the verdict is the chain's: PASS on a broken, missing or malformed
  signature and on a foreign signer. With a key, a layer that does not verify — an entry unsigned, a signature broken or
  malformed, another signer — makes the verdict FAIL.
- ML-DSA-65 (`signature_pq`): `signer.py`, Go and Java verify it (with a key, a broken one is FAIL); JS and Swift do not
  (with `--pubkey`, a ledger whose `signature_pq` is broken is PASS there).
- Step 6: no verifier in this repository performs it. `tsa_token` is accepted (§2.1) and excluded from the hash (§3), and
  not checked. `evidence_pack.py` timestamps the pack's manifest digest with RFC 3161 (verified against a real DigiCert
  TSA), not entries; `cryptovalid_tsa.py` requests and checks a token over any digest (e.g. a Merkle root).

Until 0.20.1 this paragraph named `evidence_pack.py` as the implementation of step 6 and §2 said the optional fields
were "verified when present".

## 6. Versioning

The spec is versioned semver-style. Ledgers MAY carry
`{"spec": "cryptovalid-evidence/0.3"}` inside `data` of entry 0. Breaking
changes bump major (before 1.0, minor); verifiers state the versions they support.
v0.3 (2026-10-12, cryptovalid-opencore 0.20.2) collects the changes since v0.2 (2026-08-13) that turn a PASS into a FAIL: the
closed entry schema of §2.1 (cryptovalid-opencore 0.19.0: an undefined top-level key fails); `idx` required on every
path (0.20.0); `tsa_token` outside the canonical form of §3 (0.20.2: a token hashed as content fails step 2). The first two
were made in 0.19.0 and 0.20.0 without a version bump. No verifier
in this repository reads the `spec` value yet.

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

For large ledgers, `cryptovalid_merkle.py` builds an **RFC 6962** Merkle tree whose leaves are each entry
serialised by the rules of §3 without `self_hash`, `signature` and `signer` only — so a leaf keeps `signature_pq`,
`signer_pq` and `tsa_token`, which the canonical form of §3 leaves out (corrected 2026-10-12: this line said "the
canonical form of each entry (§3)"; whether the leaves follow §3 is open, since it changes the root of any ledger that
carries those fields), giving:

- **inclusion proofs** — verify one entry in `O(log n)` (audit path), no full-chain recompute;
- **consistency proofs** — cryptographic proof that a newer ledger *append-only extends* an older one;
- a **Signed Tree Head** (`{tree_size, root_sha256}`) — the `root_sha256` is the value to submit
  to a **qualified TSP** (eIDAS EU Trusted List) for a *qualified* RFC 3161 timestamp.

This is an **optional, additive** layer: the linear hash-chain (§2, §3) remains the interoperable
core; Merkle proofs are computed on demand and verified by any third party with
`(entry, index, tree_size, audit_path, root)`. Domain separation: `0x00` leaves, `0x01` nodes.
