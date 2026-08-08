# CryptoValid Evidence Format — specification draft v0.1 (2026-08-08)

License: AGPL-3.0-or-later (see LICENSE). Status: **draft** — v1.0 freeze is a
deliverable of the pending grant work. Comments welcome.

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

## 3. Canonicalisation and hashing

Canonical form of an entry = JSON serialisation of the object **without**
`self_hash` (and without `signature` where the profile says so), with
`sort_keys=true` and separators `(",", ":")` — no whitespace, keys sorted.

`self_hash = HEX( H(canonical_bytes) )` where `H` is **SHA-256** (profile
`sha256`, default) or **SHA3-256** (profile `sha3_256`). A ledger uses ONE
profile throughout; verifiers MUST auto-detect by recomputing entry 0.

Chain rule: `entry[i].prev_hash == entry[i-1].self_hash`; `entry[0].prev_hash`
is `"0" * 64`. Genesis is not special-cased beyond that.

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

Reference implementation: `verifier.py` (steps 1–4 + receipt; 5–6 are grant
deliverables for the standalone tool — they exist today in the parent project).

## 6. Versioning

The spec is versioned semver-style. Ledgers MAY carry
`{"spec": "cryptovalid-evidence/0.1"}` inside `data` of entry 0. Breaking
changes bump major; verifiers state the versions they support.
