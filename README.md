<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- Copyright (C) 2026 Roberto Locatelli -->

# CryptoValid Open Core

**Verifiable compliance evidence for internet services — free software.**

This directory is the **AGPL-3.0 carve-out** of the OMEGA Ecosystem, decided by
the author (Roberto Locatelli) on 2026-08-08.

## Licensing architecture (dual license, honest and explicit)

| Component | License |
|---|---|
| `opencore/` — evidence format spec, standalone verifier, and every deliverable funded by open-source grants | **AGPL-3.0-or-later** (see `LICENSE` in this directory) |
| Everything else in the OMEGA Ecosystem repository | **BSL 1.1** (source-available; see repository root) |

Copyright for both sides: Roberto Locatelli, 2026. The author licenses the
contents of this directory under the GNU Affero General Public License v3.0 or
later. Contributions to `opencore/` are accepted under the same license.

## What this is

A self-hosted toolkit that turns compliance activities into **evidence anyone can
re-execute**:

- append-only **hash-chained ledgers** (canonical JSON, SHA-256);
- **Ed25519**-signed records;
- **RFC 3161** independent timestamps;
- a **standalone verifier** (`verifier.py`, in this directory): one command, no
  server, no vendor — a third party replays the chain and reaches the same
  hashes, or the verification fails. Trust is replaced by verification.

## Status (honest)

This is the **seed** of the open core: the frozen evidence-format specification
draft (`SPEC_EVIDENCE_FORMAT.md`) and the working standalone verifier. The full
extraction (registry verifiers, RFC 3161 anchoring tools, packaging, security
review) is the object of pending grant applications (NLnet, Ethereum Foundation
ESP — see the parent project). No users yet; no claims beyond what the test
suite proves.

## Quick start

```bash
python3 opencore/verifier.py <ledger.jsonl>     # verifies a hash-chained ledger
```

Exit code 0 = chain intact; non-zero = the file tells you where it broke.

## Signed evidence (the enterprise edge)

Hash-chaining proves a ledger was not altered. **Signing** proves *who sealed it* — and lets a
third party verify authorship with nothing but a public key. This is what closed, cloud GRC
evidence tools do **not** give you: their evidence lives in a vendor database ("trust us");
CryptoValid evidence is signed, self-hosted, and verifiable offline by anyone, forever.

```bash
python3 opencore/signer.py keygen  signer.key                          # Ed25519 keypair (seed, chmod 600)
python3 opencore/signer.py sign    ledger.jsonl  ledger.signed.jsonl  signer.key
python3 opencore/verifier.py       ledger.signed.jsonl                 # hash chain still PASS (stdlib-only)
python3 opencore/signer.py verify  ledger.signed.jsonl                 # signatures PASS (content->self_hash->signature)
```

- The signature commits to each entry's `self_hash`; `signature`/`signer` are attestation fields
  excluded from the content hash, so a signed ledger **still passes the stdlib hash verifier unchanged**.
- `signer verify` re-derives `self_hash` from the content too, so it catches content tampering on its
  own: the full chain is *content → self_hash → signature*.
- **Optional layer, honest scope:** the core hash verifier stays **stdlib-only**; signatures need the
  `cryptography` package. Absence of signatures never weakens the hash chain. Keys are software keys on
  a file (not an HSM). Tests: `python3 opencore/test_signer.py`.
