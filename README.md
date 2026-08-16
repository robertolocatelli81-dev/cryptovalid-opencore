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

## Where this fits (honest scope of the demand)

The broad *compliance-automation* market (evidence-collection dashboards) is owned by SaaS
incumbents and is **not** the target — their model is *trust the vendor's database*. CryptoValid
targets the narrower, regulation-driven case where evidence must survive **without** trusting any
vendor:

- **EU AI Act** high-risk systems must keep automatic logs (Art. 12) for **≥ 6 months** (Art. 19);
  the high-risk obligations become enforceable on **2 August 2026**.
- For records to be **admissible** in judicial or regulatory proceedings, each event should be
  timestamped with an **eIDAS *qualified* timestamp** and made immutable by a **third party
  independent of both provider and deployer** — cryptographic measures, not access controls.

That is exactly this format's shape: offline third-party verification (`verifier.py`), a
qualified-TSP-ready **Signed Tree Head** (see *Merkle proofs* below), and tamper-evidence that
fails loudly. **Honest limits:** this is an *emerging* segment (not proven revenue); the *qualified*
timestamp needs a real QTSP integration; and general-purpose "crypto-ledger" demand is genuinely
weak (cf. AWS retiring QLDB). The wedge is **court-admissible AI/records evidence, not a database**.

## Status (honest)

Delivered and tested — the CI badge above is green on every push:

- append-only **hash-chained ledgers** + a **standalone stdlib verifier**, defined by
  **conformance test vectors** (`spec/vectors/`) so any language can prove interoperability;
- **Ed25519-signed** records (`signer.py`) and a signed, **auditor-ready evidence pack**
  (`evidence_pack.py`) that a third party verifies offline, vendor-free;
- **RFC 3161** timestamping — cryptographically verified against a real public TSA;
- a **self-updating regulatory profile** (MiCA / EU AI Act / DORA / GDPR) that carries provenance
  and flags stale mappings for human review;
- **adversarially hardened**: an independent red-team pass found and closed real gaps (truncation,
  manifest re-forge, timestamp forgery, cross-language JSON canonicalisation) — each with a regression test;
- **KMS/HSM signing backends** (`cryptovalid_kms.py`): the Ed25519 private key can live in a
  **PKCS#11 HSM** (tested end-to-end against SoftHSM2; YubiHSM 2 exposes the same mechanism),
  **AWS KMS** (`ECC_NIST_EDWARDS25519`, exercised against the API contract — a live signature
  needs a real AWS account), or **HashiCorp Vault Transit** (protocol-tested against a stub) —
  instead of a local key file. Signatures stay standard Ed25519, so the stdlib verifier is unchanged.

Honest caveats, unchanged: **no users yet**; this is **not** an HSM itself (it *talks to* one —
key custody is only as strong as the token/KMS policy behind it), **not** an accredited certification,
and **not** legal advice — it proves *what / when / order / who-signed + non-alteration*, not the truth of
the recorded facts. Broader packaging and an independent security audit are the object of a pending NLnet
application.

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
  `cryptography` package. Absence of signatures never weakens the hash chain. By default keys are
  software keys on a file — production should use a KMS/HSM backend (below). Tests:
  `python3 opencore/test_signer.py`.

### KMS/HSM key custody (no private key in process memory)

`cryptovalid_kms.py` delegates the signature to a backend where the key is **non-exportable**;
the evidence format and the verifier do not change. URI-style selection:

```bash
# PKCS#11 HSM (YubiHSM 2, SoftHSM2, smartcard) — PIN via env, never on argv
export CRYPTOVALID_PIN=****
python3 opencore/cryptovalid_kms.py keygen-hsm --backend \
  "pkcs11:module=/usr/lib/softhsm/libsofthsm2.so;token=cryptovalid;key=evidence;pin=env:CRYPTOVALID_PIN"
python3 opencore/signer.py sign ledger.jsonl ledger.signed.jsonl --backend "pkcs11:module=...;token=...;key=evidence"

# AWS KMS (KeySpec ECC_NIST_EDWARDS25519, EdDSA supported since 2025-11; needs boto3+credentials)
python3 opencore/signer.py sign ledger.jsonl out.jsonl --backend "awskms:key_id=alias/cryptovalid;region=eu-south-1"

# HashiCorp Vault Transit (key type ed25519; token from $VAULT_TOKEN; stdlib-only client)
python3 opencore/signer.py sign ledger.jsonl out.jsonl --backend "vault:url=https://vault:8200;key=cryptovalid"
```

**Honest bench per backend** (`opencore/test_kms.py`): PKCS#11 is tested **end-to-end against a
real SoftHSM2 token** (non-exportable key, tamper ⇒ FAIL); AWS KMS is exercised against the exact
API contract (`MessageType RAW` + `ED25519_SHA_512`) with an injected client — a live signature
requires a real account; Vault Transit is protocol-tested against a local stub. Removing the key
from process memory does **not** protect against a compromised host asking the HSM to sign
attacker-chosen data — pair it with KMS policies/audit and HSM touch-policies.

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

## Merkle proofs (optional extension, RFC 6962)

`cryptovalid_merkle.py` builds an **RFC 6962** Merkle tree over the same canonical entries,
adding what a linear chain cannot do efficiently:

- **inclusion proofs** — verify one entry in `O(log n)` without recomputing the whole chain;
- **consistency proofs** — cryptographic proof that a newer ledger *append-only extends* an older one;
- a **Signed Tree Head** (`{tree_size, root_sha256}`) — submit `root_sha256` to a **qualified TSP**
  (eIDAS EU Trusted List) for a *qualified* RFC 3161 timestamp (the admissibility requirement above).

```bash
python3 cryptovalid_merkle.py sth    examples/sample_ledger.jsonl   # {tree_size, root_sha256}
python3 cryptovalid_merkle.py prove  examples/sample_ledger.jsonl 1 # audit path for entry 1
python3 cryptovalid_merkle.py verify examples/sample_ledger.jsonl 1 # INCLUSION VALID
```

A working **RFC 3161 client** (`cryptovalid_tsa.py`) requests a timestamp over the STH root from any
TSA — point `--tsa` at an eIDAS **qualified** TSP for a *qualified* token, then **`cryptovalid_lotl.py`** certifies it is *qualified* by matching its TSA
certificate against the **EU List of Trusted Lists** (ETSI TS 119 612, service type `TSA/QTST`) — verified end-to-end against real Trusted Lists (a non-qualified TSA is correctly rejected). The linear hash-chain stays the interoperable core; Merkle is **additive**. Domain separation:
`0x00` leaves, `0x01` nodes. Third-party verification needs only
`(entry, index, tree_size, audit_path, root)`. Tests: `python3 test_merkle.py`.

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

## Standards & freedom-to-operate (factual, not legal advice)

CryptoValid is built **only** on open standards and public-domain techniques: **RFC 3161**
timestamping and **RFC 6962** Merkle proofs (open IETF standards), SHA-256 / Ed25519, and Merkle
trees. The foundational timestamping patents are long expired (Merkle US4309569, 1979; Haber–Stornetta US5136647/US5373561, filed 1991–92, **expired 2004**), and the same design is
practised openly by Certificate Transparency, Sigstore/Rekor, OpenTimestamps and immudb — broad
prior art. No third-party patent is knowingly practised. *This is a technical freedom-to-operate
note, not a legal opinion; a definitive FTO requires professional counsel.*
