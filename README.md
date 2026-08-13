<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- Copyright (C) 2026 Roberto Locatelli -->

# CryptoValid Open Core

[![verify-evidence](https://github.com/robertolocatelli81-dev/cryptovalid-opencore/actions/workflows/verify.yml/badge.svg)](https://github.com/robertolocatelli81-dev/cryptovalid-opencore/actions/workflows/verify.yml)

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

## Auditor-ready evidence pack

Assembling evidence for an auditor is the regtech time-sink. `evidence_pack.py` turns one or more
ledgers into a **self-verifying bundle** (MANIFEST with per-file SHA-256 + per-ledger hash/signature
verdicts + signer keys + an optional RFC 3161 timestamp, a human `SUMMARY.md`, and the ledgers).
A third party re-checks **everything** with nothing but this repository:

```bash
python3 opencore/evidence_pack.py build  pack_dir/  ledger.signed.jsonl  --subject "audit CUST-001"
python3 opencore/evidence_pack.py verify pack_dir/
```

`verify` returns `valid: true` only if every file digest matches the manifest, the manifest is
self-consistent, and every ledger passes its hash chain **and** (if signed) its signatures — no server,
no account, no vendor. Tamper any file and it drops to `valid: false`. RFC 3161 anchoring is optional
(needs `openssl` + a TSA); its absence never invalidates the pack. Tests: `python3 opencore/test_evidence_pack.py`.

This is the difference from closed GRC evidence tools: **your evidence is a bundle anyone can re-execute
to verify — forever, offline, without trusting us.**

Build a pack with `--sign-key <keyfile>` to **authenticate the manifest** (recommended): it binds the
subject, the file digests, and each ledger's entry count + head hash. `verify_pack` reports
`manifest_authenticated`.

## Threat model (honest — hardened after adversarial review)

Adversarial testing (NEMESIS + an independent LLM red-team) found and CLOSED real gaps:

- **Truncation / branching:** a bare hash chain does not prevent dropping trailing entries or forking a
  new history after any point. A **signed manifest** commits each ledger's entry count and head hash, so
  `verify_pack` detects truncation. *Bare ledgers still need a signed manifest (or an external anchor) for
  this — documented, not hidden.*
- **Manifest re-forge:** an unsigned manifest is integrity-checked, **not authenticated** — its metadata is
  trustworthy only if `manifest_authenticated` is true. A tampered signed manifest → `valid: false`.
- **RFC 3161:** the timestamp token is now **cryptographically verified** (status Granted + message imprint
  == manifest digest), proved against a real DigiCert TSA. A forged token → `rfc3161.verified: false`.
- **Cross-language integrity:** canonicalisation is pinned (ASCII-escaped, no floats, unique keys — see
  §3 of the spec) with a dedicated conformance vector, so a Go/Rust/JS verifier computes the same hashes.
- **Replay across ledgers:** carry a `ledger_id` in `data` (see spec §3) to bind entries to one chain.

Honest scope unchanged: the format proves *what/when/order/who-signed + non-alteration*, **not the truth
of the recorded facts**, and is **not** an HSM or a legal-compliance certification.

## An open standard (not just a tool)

A verifiable-evidence *feature* is copyable; an *adopted format* is not. CryptoValid is defined by
**conformance test vectors** (`spec/vectors/` + `spec/CONFORMANCE.md`), so a verifier in **any language**
proves interoperability by reproducing the same verdicts:

```bash
python3 conformance.py            # exit 0 = the reference verifier conforms (5/5 vectors)
```

Implement it in Go/Rust/JS, match the vectors, and open a PR to the conformance table — the format becomes
a shared standard, not one vendor's tool. Full spec: [`SPEC_EVIDENCE_FORMAT.md`](SPEC_EVIDENCE_FORMAT.md).

## Self-updating regulatory profiles

`spec/regulatory_profiles.json` maps evidence to EU requirements (MiCA, EU AI Act, DORA, GDPR) with
`status`, `effective_utc`, `source_url` and an `as_of` date. A ledger entry may set
`data.regulatory_ref = "<id>"` to declare what it supports.

```bash
python3 refresh_regulatory.py --check-urls   # re-checks sources, flags stale entries; exit 1 = needs review
```

**Honest scope:** it keeps the mapping fresh and provenance-honest and **flags** stale entries for a human
to re-verify against the primary source — it does not auto-interpret law. Outdated regulatory status is
never allowed to pass silently.
