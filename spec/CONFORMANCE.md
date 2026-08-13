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
| `verifier.py` (reference) | Python (stdlib) | Roberto Locatelli | ✅ 5/5 vectors |
| _your implementation here_ | | | |

## Optional profiles

- **Signatures** (`signer.py`): Ed25519 over `self_hash`. A signing-conformant tool re-derives
  `self_hash` from content and verifies the signature (content → self_hash → signature).
- **RFC 3161** timestamping: the token's message imprint MUST equal the stamped digest.
- **Regulatory profiles** (`spec/regulatory_profiles.json`, self-updated by `refresh_regulatory.py`):
  a ledger entry MAY set `data.regulatory_ref = "<id>"` to declare which EU requirement it supports.
  The profile carries provenance and an `as_of` date; stale entries are flagged, never silently trusted.
