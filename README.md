<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- Copyright (C) 2026 Roberto Locatelli -->

# CryptoValid Open Core

[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.22539578.svg)](https://doi.org/10.5281/zenodo.22539578)
[![verify-evidence](https://github.com/robertolocatelli81-dev/cryptovalid-opencore/actions/workflows/verify.yml/badge.svg)](https://github.com/robertolocatelli81-dev/cryptovalid-opencore/actions/workflows/verify.yml)

**Evidence files that a third party verifies offline, years later, without trusting whoever wrote them:**
hash-chained JSONL ledgers, Ed25519 (optionally + ML-DSA-65) signatures, a signed chain tip, RFC 3161 timestamps,
and verifiers in six languages that agree on the same conformance vectors.

## The problem

Regulated records have to outlive the system that wrote them, and the reader is often someone who has no reason to
trust that system:

- **Manufacturers under the EU Cyber Resilience Act** (Regulation (EU) 2024/2847) must keep the technical
  documentation at the disposal of market surveillance authorities for at least 10 years after the product is placed
  on the market, or for the support period if longer (Art. 13(13)); the Regulation applies from 11 December 2027, its
  reporting obligations (Art. 14) already from 11 September 2026 (Art. 71(2)).
  [cra-evidence](https://github.com/robertolocatelli81-dev/cra-evidence) writes that evidence in this repository's
  ledger profile (see *What cra-evidence relies on*).
- **Providers of high-risk AI systems** must keep automatically generated logs (EU AI Act, Regulation (EU) 2024/1689,
  Art. 12) for at least six months (Art. 19); for Annex III systems those obligations apply from 2 December 2027
  (amended by Regulation (EU) 2026/1744).
- **Auditors and supervisors** receive a log, a database export or a vendor dashboard and have to decide whether it
  was altered, truncated or re-written. A hash chain alone cannot tell a shorter prefix from the whole file; a
  vendor's database asks to be trusted.

This repository is the format and the tools to check it: one stdlib-only command replays a ledger and either reaches
the same hashes or names the entry where it breaks; a signed chain tip makes truncation and a re-written tail
visible; an evidence pack bundles ledgers, digests, signatures and an optional RFC 3161 token for an auditor.

## Demo (one minute, from a clone)

```bash
git clone https://github.com/robertolocatelli81-dev/cryptovalid-opencore && cd cryptovalid-opencore
python3 verifier.py --quiet examples/sample_ledger.jsonl            # PASS, exit 0
python3 verifier.py --quiet examples/sample_ledger_tampered.jsonl   # FAIL, exit 1: entry 1 was edited

pip install 'cryptography>=48'                                      # only signatures need it
python3 signer.py keygen log.key                                    # prints public_key_hex
cp examples/sample_ledger.jsonl ledger.jsonl
python3 cryptovalid_tip.py sign ledger.jsonl log.key                # writes ledger.jsonl.tip.json
python3 verifier.py --quiet --trusted-pubkey <public_key_hex> --require-tip ledger.jsonl   # PASS
head -n 2 ledger.jsonl > cut && mv cut ledger.jsonl                 # drop the last entry
python3 verifier.py --quiet --trusted-pubkey <public_key_hex> --require-tip ledger.jsonl   # FAIL, exit 1
```

Without `--quiet` the verifier prints a JSON receipt: the last run names `tail_truncated: file has 2 entries, the
signed tip commits to 3`, and every receipt carries a `scope` field that says what a bare chain cannot see.
Exit codes: 0 PASS, 1 FAIL, 2 usage, 74 the receipt could not be written whole (stdout or `--out` full, closed, or a
reader gone), whatever the verdict.

## Proofs

- **CI on every push and weekly** ([verify.yml](.github/workflows/verify.yml)): every `test_*.py` suite on Python 3.9
  and 3.11, the conformance vectors, a real PKCS#11 token (SoftHSM2) signing a ledger end to end, a tampered ledger
  that must be refused, the declared dependency floors, and the verifiers in the other languages.
- **Verifiers in six languages, by the same author:** Python (`verifier.py`, the reference), JavaScript
  (`verifiers/js`), Go (`verifiers/go`, which also writes ledgers), Java (`verifiers/java/CvVerify.java`, JDK
  standard library only), Rust (`verifiers/rust`, no external crates for the hash chain) and Swift (`verifiers/swift`,
  reduced scope: no chain tip, no ML-DSA). The differential oracle (`verifiers/differential_oracle.py`) runs Python,
  JS, Go, Rust and Java on the same hostile inputs in CI and fails on any disagreement.
- **Conformance vectors:** `spec/vectors/` holds 11 normative ledger vectors with their expected receipts;
  `python3 conformance.py` exits 0 only if the reference reproduces all 11 (`"conformant": true, "vectors": 11`).
  Signature vectors are in `spec/vectors/signatures/`. Implementing the format elsewhere means matching these.
- **Used downstream, measured in their CI:** cra-evidence runs a job (`interop-newest-cryptovalid`) that writes a
  ledger with a signed tip and requires the newest release of this package to verify it, and to fail it once
  truncated; ap2-evidence-pack runs a job (`downstream-cryptovalid`) that clones this repository and runs its AP2
  front-end suites against each new build. Both were green on their last runs (2026-11-04 and 2026-11-05).
- **Archived** on Zenodo, concept DOI [10.5281/zenodo.22539578](https://doi.org/10.5281/zenodo.22539578).

## Core and experimental modules

The maintained core is the evidence format and what cra-evidence relies on. Everything else stays in the repository
and in the wheel, keeps its tests and its CI step, and is marked **experimental** in its module docstring: no new
scope is added to it.

| Core | What it is |
|---|---|
| `SPEC_EVIDENCE_FORMAT.md` §1-7, §10 | ledger container, closed entry schema, canonical JSON and hashing, verification algorithm, versioning, conformance, evidence-pack receipt |
| `verifier.py` | stdlib-only reference verifier (SHA-256 / SHA3-256 chains, strict JSON profile, signed tip check) |
| `cryptovalid_tip.py`, `ed25519_order.py` | signed chain tip (`cryptovalid_tip/1`); refusal of small- and mixed-order Ed25519 keys and R |
| `signer.py`, `cryptovalid_kms.py` | per-entry Ed25519 (+ optional ML-DSA-65) signatures; keys in a PKCS#11 HSM, AWS KMS or Vault Transit |
| `cryptovalid_tsa.py` | RFC 3161 timestamp client and token check |
| `evidence_pack.py`, `verify_evidence.py` (`auto`, `pack`, `ledger`) | auditor bundle and the `cryptovalid-verify` front-end |
| `conformance.py`, `spec/vectors/`, `verifiers/` | conformance vectors and the JS, Go, Java, Rust and Swift verifiers |

| Experimental | Modules |
|---|---|
| AP2 / SD-JWT dispute evidence (front-end to ap2-evidence-pack) | `verify_evidence.py ap2`, MCP tool `verify_ap2_evidence` |
| MCP server | `cryptovalid_mcp.py` |
| Receipts, monitor, checkpoints, witnesses, SCITT, COSE receipts, JWS | `cryptovalid_receipt.py`, `cryptovalid_monitor.py`, `cryptovalid_checkpoint.py`, `cryptovalid_witness.py`, `cryptovalid_scitt.py`, `cryptovalid_cose_receipts.py`, `cryptovalid_jws.py` |
| Merkle proofs (RFC 6962, SPEC §9) and high-frequency ingestion | `cryptovalid_merkle.py`, `cryptovalid_ingest.py`, `verify_evidence.py archive` |
| eIDAS: EU trusted list (LOTL), qualified-ledger self-assessment, QEAA | `cryptovalid_lotl.py`, `eidas_ledger_check.py`, `cryptovalid_qeas.py` |
| Anchoring and retention: Solana, OpenTimestamps, heterogeneous anchors, re-anchor, WORM, pruning probe | `cryptovalid_solana.py`, `committed_attestation.py`, `cryptovalid_heterogeneous.py`, `cryptovalid_reanchor.py`, `cryptovalid_worm.py`, `cryptovalid_pruning_probe.py` |
| Confidential attestations (CLDMA, Pedersen commitments) | `cldma_confidential.py`, `pedersen_commit.py`, `verify_evidence.py cldma` |
| Agent decision receipts of other formats (ACTA, APS, Cedulon, Vaara) | `cryptovalid_acta.py`, `cryptovalid_aps.py`, `cryptovalid_cedulon.py`, `cryptovalid_vaara_receipt.py` |
| Domain records: DORA incidents, IRS 1099-DA transactions, fund metrics, microfinance | `dora_incident.py`, `tx_evidence.py`, `fundcert_canonical.py`, `fundcert_crosssource.py`, `microfinance.py` |
| Auditor report (HTML/PDF) | `cryptovalid_report.py` |
| Regulatory profiles (SPEC §8) | `refresh_regulatory.py`, `spec/regulatory_profiles.json` |
| Development tooling | `mutation_runner.py` |

Each experimental module documents its use in its docstring and `--help`; the history of each is in
[CHANGELOG.md](CHANGELOG.md).

### What cra-evidence relies on

Measured on cra-evidence `f18097e` (master, 2026-11-12): it declares no runtime dependency on this package
(`dependencies = []`) and writes the ledger and the tip itself. What it relies on is the profile:

- the ledger profile of SPEC §1-3 and §5 (canonical JSON, `prev_hash` / `self_hash`, strict JSON acceptance, the
  64 MiB line bound of the Go verifier);
- the signed chain tip `cryptovalid_tip/1`, byte-identical payload;
- `verifier.verify_ledger(path)` and `verifier.verify_ledger(path, trusted_pubkey_hex=…, require_tip=True)`, which
  its interop test calls (PASS on a ledger it wrote, FAIL once truncated);
- the parser and canonical encoder of `verifiers/go`, `verifiers/rust` and `verifiers/js`, which its own verifiers
  reuse (its THIRD_PARTY_NOTICES.md names them).

It does not use `regulatory_ref`, the regulatory profiles, Merkle proofs, ingestion or any experimental module.

## Signed evidence

```bash
python3 signer.py keygen  signer.key                          # Ed25519 seed, mode 0600
python3 signer.py sign    ledger.jsonl  ledger.signed.jsonl  signer.key
python3 verifier.py       ledger.signed.jsonl                 # hash chain still PASS (stdlib only)
python3 signer.py verify  ledger.signed.jsonl --pubkey <hex>  # signatures PASS against the pinned key
```

The signature covers each entry's `self_hash`; `signature` / `signer` (and `signature_pq` / `signer_pq`) are excluded
from the content hash, so a signed ledger still passes the hash verifier unchanged. `signer verify` re-derives
`self_hash` from the content, so the chain checked is content → `self_hash` → signature. Without `--pubkey` the
receipt says `classical_status: unpinned`: the signatures were checked against the key the ledger carries.

**Hybrid post-quantum (opt-in):** `keygen --pq` also writes an ML-DSA-65 key (FIPS 204, PKCS#8); `sign --pq-key`
(or `--pq-kms <AWS KMS key>`) signs every `self_hash` with both keys; `verify --pubkey <hex> --pq-pubkey <b64>`
requires both layers. The FIPS 204 context is empty, so the JDK, OpenSSL 3.5 and Go verify the same bytes. The
ML-DSA-65 layer of entries and tip is checked by Python, Go (≥ 1.27) and Java (JDK 24+); JS, Rust and Swift report it
as unchecked.

**Keys in an HSM or KMS** (`cryptovalid_kms.py`): the signature is delegated to a backend where the key is not
exportable; the format and the verifier do not change.

```bash
export CRYPTOVALID_PIN=****    # PKCS#11 (SoftHSM2, YubiHSM 2, smartcard): PIN from the environment, never on argv
python3 cryptovalid_kms.py keygen-hsm --backend \
  "pkcs11:module=/usr/lib/softhsm/libsofthsm2.so;token=cryptovalid;key=evidence;pin=env:CRYPTOVALID_PIN"
python3 signer.py sign ledger.jsonl ledger.signed.jsonl --backend "pkcs11:module=...;token=...;key=evidence"
python3 signer.py sign ledger.jsonl out.jsonl --backend "awskms:key_id=alias/cryptovalid;region=eu-south-1"
python3 signer.py sign ledger.jsonl out.jsonl --backend "vault:url=https://vault:8200;key=cryptovalid"
```

PKCS#11 is tested end to end against a real SoftHSM2 token in CI; AWS KMS is tested against its API contract
(`MessageType RAW`, `ED25519_SHA_512`) with an injected client, and an ML-DSA-65 key in AWS KMS was verified live (0.13.0);
Vault Transit is tested against a local stub.

## Evidence pack

```bash
python3 evidence_pack.py build  pack_dir/  ledger.signed.jsonl  --subject "audit CUST-001" --sign-key signer.key
python3 evidence_pack.py verify pack_dir/          # or: cryptovalid-verify pack pack_dir/
```

The pack holds the ledgers, a MANIFEST with per-file SHA-256, per-ledger hash and signature verdicts, signer keys,
entry count and head hash, an optional RFC 3161 token, and a human `SUMMARY.md`. `verify` returns `valid: true` only
if every digest matches, the manifest is self-consistent, every ledger passes its chain and its signatures, and a
claimed RFC 3161 token is not refuted; with `--sign-key` the manifest is authenticated (`manifest_authenticated`) and
a truncated ledger fails. The receipt states per subject what was checked and how it came out (`admission`,
`states`: SPEC §10), so a refused manifest is told apart from tampering.

## Guarantees and assumptions

What a PASS means, and what it does not:

- **Bare chain:** internally consistent, unmodified entries in order. It cannot see truncation or a suffix
  re-chained by someone with write access; the receipt's `scope` field says so.
- **Signed tip, with the trusted log key:** truncation, a rewritten tail and unsealed appends become named FAILs
  (`tail_truncated`, `tail_rewritten`, `unsealed_tail`). A holder of the log key can still truncate and re-sign
  (key custody belongs in an HSM/KMS); a rollback to an older genuine tip passes unless `--tip-not-before` is given or
  the tip is compared with a copy kept elsewhere; when one key signs several ledgers, `--expect-ledger-id` binds the
  tip to its chain. Without a trusted key the tip is not checked (`tip_untrusted`), never a PASS.
- **Signatures:** prove which key sealed each entry; they count only against a key the relying party pins. A
  non-exportable key does not stop a compromised host from asking the HSM to sign; KMS policy, rotation and
  revocation are part of the perimeter.
- **Time:** entry timestamps come from the writer's clock. An RFC 3161 token proves the data existed at the TSA's
  time; the evidence pack checks the token's status and its binding to the manifest, not the TSA's signature
  (`time_anchor: tsa_not_checked`). Between an event and its anchor, a root-level attacker on the writer can re-write
  and re-seal.
- **Completeness:** an append-only log proves what it contains, never that everything that should have been recorded
  was.
- **Post-quantum:** Ed25519 and the RSA/ECDSA signatures of TSA tokens do not survive a quantum adversary; the
  ML-DSA-65 layer is opt-in and counts only when its key is pinned; the evidence-pack manifest signature is Ed25519.
- **What it is not:** not proof that the recorded facts are true, not an HSM, not a qualified trust service, not a
  conformity assessment or certification under any of the Regulations named above, and not legal advice.

The detailed threat analysis of each release is in [CHANGELOG.md](CHANGELOG.md); key handling is in
[docs/KEY_LIFECYCLE.md](docs/KEY_LIFECYCLE.md).

## Install (pip)

```bash
pip install --extra-index-url https://robertolocatelli81-dev.github.io/pypi/ cryptovalid-opencore
```

The hash-chain verifier needs only the standard library. Signing and signature verification (Ed25519, ECDSA,
ML-DSA-65, COSE, JWS, AP2) need `cryptography` (≥ 48: the floor where ML-DSA-65 works; measured with 48.0.0 and
50.0.x), installed with the `sign` extra:

```bash
pip install --extra-index-url https://robertolocatelli81-dev.github.io/pypi/ 'cryptovalid-opencore[sign]'
```

AP2 dispute evidence (experimental) needs the `ap2` extra (`'cryptovalid-opencore[ap2]'`), which installs
ap2-evidence-pack >= 1.6.0, < 2 from the same index; without it `cryptovalid-verify ap2` is a refusal that names the
extra (exit 1). Release artifacts are attached to GitHub Releases; the index links carry `#sha256=` fragments that
pip verifies. All documented `python3 <file>.py` commands also work from a clone.

## Licence, contact, citation

- **Licence:** AGPL-3.0-or-later, see [LICENSE](LICENSE). A commercial licence of the same code is available from the
  author.
- **Contact:** issues and [Discussions](https://github.com/robertolocatelli81-dev/cryptovalid-opencore/discussions)
  of this repository (interoperability reports and divergences found by your own verifier are welcome);
  roberto.locatelli.81@gmail.com. Security reports: [SECURITY.md](SECURITY.md).
- **Citation:** DOI [10.5281/zenodo.22539578](https://doi.org/10.5281/zenodo.22539578) (concept DOI: always the
  latest version).
- **Digital Public Good candidate** for SDG 16 (accountable institutions) and SDG 9 (open infrastructure): see
  [DPG_NOMINATION.md](DPG_NOMINATION.md).
- Author: Roberto Locatelli, 2026. Public interventions by his AI agent (Noûs) are signed as such.
- Changes: [CHANGELOG.md](CHANGELOG.md).
