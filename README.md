<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- Copyright (C) 2026 Roberto Locatelli -->

# CryptoValid Open Core

[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.22539578.svg)](https://doi.org/10.5281/zenodo.22539578)

[![verify-evidence](https://github.com/robertolocatelli81-dev/cryptovalid-opencore/actions/workflows/verify.yml/badge.svg)](https://github.com/robertolocatelli81-dev/cryptovalid-opencore/actions/workflows/verify.yml)

**Verifiable compliance evidence for internet services — free software.**

This directory is the **AGPL-3.0 carve-out** of the OMEGA Ecosystem, decided by
the author (Roberto Locatelli) on 2026-08-08.

## Licensing architecture (dual license, honest and explicit)

| Component | License |
|---|---|
| **this repository (`cryptovalid-opencore`)** — evidence format spec, standalone verifier, and every deliverable funded by open-source grants | **AGPL-3.0-or-later** (see `LICENSE` in this directory) |
| Everything else in the OMEGA Ecosystem repository | **BSL 1.1** (source-available; see repository root) |

Copyright for both sides: Roberto Locatelli, 2026. The author licenses the
contents of this directory under the GNU Affero General Public License v3.0 or
later. Contributions to this repository are accepted under the same license.

**Commercial license — for AGPL-averse enterprises.** The AGPL-3.0 (esp. the §13 network clause)
deliberately prevents cloud-stripping, but many corporate legal policies forbid AGPL to avoid copyleft
contagion. If that is your case, a **commercial license of this code** is available from the author
(roberto.locatelli.81@gmail.com): the same code, without the AGPL network/copyleft obligations. This is
the standard open-core arrangement — AGPL for the community, a commercial license for enterprises that
need it — so the copyleft protection is a positioning choice, not an adoption dead-end.

## Patents / freedom-to-operate (honest — no professional FTO was done)

Stated plainly so no one relies on a guarantee that does not exist:

- **Measured (low patent exposure):** the primitives here are open standards or public prior art —
  SHA-256/SHA3 (FIPS 180-4/202, royalty-free), Ed25519 (published patent-free by its authors),
  RFC 3161 timestamping and RFC 6962 Merkle trees (open IETF standards), and hash-of-document
  timestamping + hash-chaining, whose foundational patents (Haber–Stornetta, US 5,136,646/647)
  expired over a decade ago. There are **no third-party dependencies**, so no patent or licence
  travels in from an external library.
- **Not established (residual risk — needs a lawyer, not this file):** a professional
  freedom-to-operate search has **not** been performed. Patent risk in software is rarely in the
  algorithms; it is in *combinations* and *business methods* (e.g. "verifying regulatory compliance
  using a blockchain anchor"), and it varies by jurisdiction — US software/business-method patents
  are broader than the EU (Art. 52 EPC). **AGPL-3.0 §11 grants a patent licence only from this
  project's contributors; it does NOT shield you from a third party's patent.**
- **Post-quantum layer (0.12.0 → 0.13.0), checked on 16/09/2026 on primary sources:** ML-DSA is FIPS 204, a
  public NIST standard; NIST's submission rules required signed IP statements from every submitter, and NIST's two
  royalty-free patent licence agreements (a US portfolio and the CNRS / Université de Limoges portfolio) concern
  CRYSTALS-Kyber / ML-KEM, which this project does not use; no patent licence was needed for CRYSTALS-Dilithium /
  ML-DSA, whose submitters declared none. The hybrid here is **two independent signatures** (Ed25519 and ML-DSA-65
  over the same bytes, separate keys, no combined key or OID): it does NOT implement the IETF LAMPS "composite
  signatures" draft (draft-ietf-lamps-pq-composite-sigs, RFC Editor queue, one IPR disclosure listed on the
  datatracker). AWS KMS is used through its public API under AWS's terms. The Java verifier uses only JDK APIs
  (GPLv2 + Classpath Exception runtime; this file is AGPL-3.0). None of this is an FTO opinion.
- **Your responsibility:** this project is provided as-is, with no warranty of non-infringement.
  Anyone deploying it — especially commercially or in the United States — should conduct their own
  patent due diligence / FTO. The author has not, and this document is not legal advice.

## What this is

A self-hosted toolkit that turns compliance activities into **evidence anyone can
re-execute**:

- append-only **hash-chained ledgers** (canonical JSON, SHA-256);
- **Ed25519**-signed records (optionally **hybrid Ed25519 + ML-DSA-65**, FIPS 204, since 0.12.0);
- **RFC 3161** independent timestamps;
- a **standalone verifier** (`verifier.py`, in this directory): one command, no
  server, no vendor — a third party replays the chain and reaches the same
  hashes, or the verification fails. Trust is replaced by verification.

## Relevance to the Sustainable Development Goals

CryptoValid is submitted as a candidate **Digital Public Good**. Its relevance to the SDGs is **institutional
transparency and accountability**, not (yet) financial inclusion:

- **SDG 16 — Peace, Justice and Strong Institutions.** Verifiable, tamper-evident compliance evidence directly
  supports **target 16.6** (*effective, accountable and transparent institutions*) and **target 16.5** (*reduce
  corruption*): any third party can re-execute `verifier.py` and reach the same hashes, so an institution's
  records can be checked **without trusting the institution** — accountability by verification, not by assertion.
- **SDG 9 — Industry, Innovation and Infrastructure.** It is open, dependency-free (`dependencies = []`) digital
  infrastructure for trustworthy record-keeping, usable by any organisation at no licence cost.

- **SDG 1 / 8 / 10 — NOT claimed.** They were withdrawn from the DPG nomination on 2026-08-22 after the 4-mind
  review (see `DPG_NOMINATION.md`, «SOLO 16 + 9»): the `microfinance` module is a real capability, but a
  proof-of-integrity tool does not by itself advance poverty or inequality targets. What it does:
  `microfinance.py` applies the same primitives to **microcredit transparency**: a microfinance institution's
  **loan portfolio** is canonicalized (same portfolio → same digest, re-derivable by a **donor or regulator**),
  its internal consistency is attested (disbursed = outstanding + repaid + written-off), and standard
  **Portfolio-at-Risk (PAR30/PAR90)** is computed. On the **borrower-protection** side, `over_indebtedness()`
  detects **over-indebtedness** — a borrower carrying loans across **multiple institutions** (a debt-trap
  signal) — using a **hashed borrower reference** so exposure is aggregated **without any PII**.

**Honest scope (no overclaim):** the microfinance module is a **real capability** but is currently validated on
**synthetic loan data** (unlike the fund side, which is validated on real SEC filings) — MFIs do not publish
portfolios the way funds do, so real-data validation awaits an operator's data. The confine is unchanged:
**proof-of-integrity, not proof-of-veracity** (it attests that records are internally consistent and
tamper-evident, not that the loans are real or well-underwritten). No PII by design (see PRIVACY.md).

## Where this fits (honest scope of the demand)

The broad *compliance-automation* market (evidence-collection dashboards) is owned by SaaS
incumbents and is **not** the target — their model is *trust the vendor's database*. CryptoValid
targets the narrower, regulation-driven case where evidence must survive **without** trusting any
vendor:

- **EU AI Act** high-risk systems must keep automatic logs (Art. 12) for **≥ 6 months** (Art. 19);
  the high-risk obligations for Annex III systems apply from **2 December 2027** (deferred by the
  Digital Omnibus, Reg. (EU) 2026/1744 — the original 2 August 2026 date no longer holds; see
  `spec/regulatory_profiles.json`, which carries the dated source).
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
- **adversarially hardened**: red-team passes found and closed real gaps (truncation and manifest
  re-forge at the *signed pack* layer, timestamp forgery, cross-language JSON canonicalisation; and on
  2026-09-11, a bare-ledger verifier that answered `PASS` on an **empty** file) — each with a regression test.
  **Know what `verifier.py` proves**: a bare hash chain is internally consistent evidence — it cannot see
  truncation or a re-chained suffix written by someone with write access to the file. The receipt
  says so in a `scope` field. Since 0.11.0 the **signed chain tip** (`cryptovalid_tip.py`, sidecar
  `<ledger>.tip.json`, written after every append — O(1) for the writers that already know their tail,
  `Ingestor` and Go `AppendSigned`; `cryptovalid_tip.py sign` reads the file, O(n)) moves that limit: with the tip and the
  trusted log key, `verifier.py --trusted-pubkey <hex> [--require-tip]` names `tail_truncated`,
  `tail_rewritten` and `unsealed_tail`; the JS and Go verifiers check it too (Rust/Swift: declared no).
  Without the trusted log key the tip is not checked at all (`tip_untrusted`): the key inside a tip proves
  nothing, so there is no "PASS but untrusted" for an automation to misread.
  What remains, stated in the receipt: a holder of the log key can truncate and re-sign (key custody:
  HSM/KMS); a rollback to an older genuine tip passes unless you pass `--tip-not-before` or compare
  with the monitor state / receipts / an anchor; and when one log key signs several ledgers, a whole
  pair file+tip of another ledger is caught only with `--expect-ledger-id` (the tip carries the chain's
  identity, `ledger_id` = self_hash of entry 0). The production writer keeps the tip itself:
  `Ingestor(tip_keyfile=…)` signs it at every flush under its lock. Measured on the arc (#703)
  bench: 6002/6003 tamperings without the tip, 6003/6003 with it, and an attacker re-signing the tip
  with a key of their own is refused;
- **high-frequency ingestion** (`cryptovalid_ingest.py`): segmented hash-chained ledgers with
  Merkle-STH sealing (chained across segments, KMS/HSM-signable), batched fsync, fail-closed
  crash recovery — throughput measured by the bench, never quoted as a fixed claim;
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
python3 verifier.py <ledger.jsonl>     # verifies a hash-chained ledger
```

Exit code 0 = chain intact; non-zero = the file tells you where it broke.

## Signed evidence (the enterprise edge)

Hash-chaining proves a ledger was not altered. **Signing** proves *who sealed it* — and lets a
third party verify authorship with nothing but a public key. This is what closed, cloud GRC
evidence tools do **not** give you: their evidence lives in a vendor database ("trust us");
CryptoValid evidence is signed, self-hosted, and verifiable offline by anyone, forever.

```bash
python3 signer.py keygen  signer.key                          # Ed25519 keypair (seed, chmod 600)
python3 signer.py sign    ledger.jsonl  ledger.signed.jsonl  signer.key
python3 verifier.py       ledger.signed.jsonl                 # hash chain still PASS (stdlib-only)
python3 signer.py verify  ledger.signed.jsonl                 # signatures PASS (content->self_hash->signature)
```

- The signature commits to each entry's `self_hash`; `signature`/`signer` (and the hybrid `signature_pq`/
  `signer_pq`) are attestation fields excluded from the content hash, so a signed ledger **still passes the stdlib
  hash verifier unchanged** — in all five verifiers.
- **Hybrid post-quantum (0.12.0, 0.13.0):** `keygen signer.key --pq` also writes `signer.key.pq` (ML-DSA-65, FIPS 204,
  PKCS#8, 0600); `sign … --pq-key signer.key.pq` — or `--pq-kms <AWS KMS key, KeySpec ML_DSA_65>` to sign inside
  KMS — signs every `self_hash` with BOTH keys (re-signing without a PQ key strips stale PQ fields); `verify …
  --pq-pubkey <b64>` requires the layer and exits 1 unless every entry
  carries a valid ML-DSA-65 signature by THAT key (`--pq-pubkey` needs `--pubkey`, and `--require-pq` alone is
  refused: a layer checked against the key inside the file is self-declared). The tip: `--trusted-pq-pubkey` on
  `verifier.py` and on the Go `cvverify` (implies a required tip and needs `--trusted-pubkey`). Per-entry Ed25519 +
  ML-DSA-65 are verified by Python (`signer.py verify`) and Go (`cvverify -pubkey <hex> -pq-pubkey <b64>`); the tip's
  by both. The context string is EMPTY (FIPS 204 default) so the JDK, OpenSSL 3.5, .NET and Go verify the same
  bytes. Needs `cryptography` ≥ 50 (Python) or Go ≥ 1.27; where a REQUIRED layer cannot be verified the result is
  `pq_unverifiable` with `ok: false` / exit 1, never a green.
- `signer verify` re-derives `self_hash` from the content too, so it catches content tampering on its
  own: the full chain is *content → self_hash → signature*.
- **Optional layer, honest scope:** the core hash verifier stays **stdlib-only**; signatures need the
  `cryptography` package. Absence of signatures never weakens the hash chain. By default keys are
  software keys on a file — production should use a KMS/HSM backend (below). Tests:
  `python3 test_signer.py`.

### KMS/HSM key custody (no private key in process memory)

`cryptovalid_kms.py` delegates the signature to a backend where the key is **non-exportable**;
the evidence format and the verifier do not change. URI-style selection:

```bash
# PKCS#11 HSM (YubiHSM 2, SoftHSM2, smartcard) — PIN via env, never on argv
export CRYPTOVALID_PIN=****
python3 cryptovalid_kms.py keygen-hsm --backend \
  "pkcs11:module=/usr/lib/softhsm/libsofthsm2.so;token=cryptovalid;key=evidence;pin=env:CRYPTOVALID_PIN"
python3 signer.py sign ledger.jsonl ledger.signed.jsonl --backend "pkcs11:module=...;token=...;key=evidence"

# AWS KMS (KeySpec ECC_NIST_EDWARDS25519, EdDSA supported since 2025-11; needs boto3+credentials)
python3 signer.py sign ledger.jsonl out.jsonl --backend "awskms:key_id=alias/cryptovalid;region=eu-south-1"

# HashiCorp Vault Transit (key type ed25519; token from $VAULT_TOKEN; stdlib-only client)
python3 signer.py sign ledger.jsonl out.jsonl --backend "vault:url=https://vault:8200;key=cryptovalid"
```

**Honest bench per backend** (`test_kms.py`): PKCS#11 is tested **end-to-end against a
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
python3 evidence_pack.py build  pack_dir/  ledger.signed.jsonl  --subject "audit CUST-001"
python3 evidence_pack.py verify pack_dir/
```

`verify` returns `valid: true` only if every file digest matches the manifest, the manifest is
self-consistent, and every ledger passes its hash chain **and** (if signed) its signatures — no server,
no account, no vendor. Tamper any file and it drops to `valid: false`. RFC 3161 anchoring is optional
(needs `openssl` + a TSA); its absence never invalidates the pack. Tests: `python3 test_evidence_pack.py`.

This is the difference from closed GRC evidence tools: **your evidence is a bundle anyone can re-execute
to verify — forever, offline, without trusting us.**

Build a pack with `--sign-key <keyfile>` to **authenticate the manifest** (recommended): it binds the
subject, the file digests, and each ledger's entry count + head hash. `verify_pack` reports
`manifest_authenticated`.

### Dispute evidence for agentic-payment mandates (AP2 / SD-JWT)

The AP2 spec tells implementers *what* to keep for dispute resolution (the SD-JWTs with their
disclosures) but not *how* — no key snapshotting, no tamper-evidence, no long-term validation.
`ap2_evidence.py` turns a set of SD-JWT mandates into **one self-contained evidence file** that
verifies **offline years later**: it validates each ES256 signature at build time, snapshots the
key material with an explicit **provenance class** (`x5c_header` / `jwk_header` / `supplied` /
`jwks_fetched` — declared, never dressed up), recomputes cross-mandate hash **bindings** from the
exact compact serializations, and seals everything under a SHA-256 digest with an optional
RFC 3161 timestamp:

```bash
python3 ap2_evidence.py build ev.json intent=intent.sdjwt cart=cart.sdjwt --tsa http://tsa.izenpe.com
python3 ap2_evidence.py verify ev.json     # offline, fail-closed
```

Honest scope: proves these exact artifacts verified with this key material at build time (and
existed at the TSA's time, if stamped). It does **not** confer eIDAS art. 45j qualified-archive
legal presumption and does not validate x5c chains to a trust anchor. ES256 only, loudly.
Tests: `python3 test_ap2_evidence.py`. Also exposed read-only as the MCP tool
`verify_ap2_evidence`.

### Auditor-facing report (PDF/HTML)

An ISO inspector or an EU regulator expects a formal document, not JSON on a terminal.
`cryptovalid_report.py` renders an evidence pack into a typographic audit report — front page,
global status, per-ledger detail, signer keys, RFC 3161 / eIDAS anchoring, honest scope, and the
exact vendor-free re-verify command:

```bash
python3 cryptovalid_report.py pack_dir/                      # -> report.html + report.pdf
python3 cryptovalid_report.py pack_dir/ --lotl --lotl-ms ES  # opt-in eIDAS check (network)
```

Design rules (they ARE the security model of this layer): the report **never recomputes a
verdict** — every light comes verbatim from the same fail-closed `verify_pack()` an auditor runs by
hand, so a tampered pack renders RED, always. The report is a **rendering, not evidence**: the
authoritative artifacts remain `MANIFEST.json` + the ledgers, and the document says so on its face.
HTML needs nothing but the Python stdlib; PDF uses [WeasyPrint](https://weasyprint.org/) only if it
is already installed (honest degrade to HTML otherwise). The eIDAS light has three honest states —
not checked (default) / qualified / not qualified — never a fabricated green.
Tests: `python3 test_report.py` (tamper→RED proven before the positive path).

## MCP server — agents that can prove what they did

`cryptovalid_mcp.py` exposes CryptoValid to any MCP client (Claude Code, Claude Desktop, other
agents) over stdio — **zero dependencies**: the MCP JSON-RPC transport is implemented with the
Python stdlib, same ethos as the rest of this repo.

```jsonc
// client config
{"command": "python3", "args": ["/path/to/cryptovalid_mcp.py"]}
```

Read-only tools, always available, every answer carries **provenance** (source, SHA-256, UTC):
`verify_ledger`, `verify_pack`, `verify_archive` (with optional trusted-signer set and opt-in
eIDAS/LOTL check). Write tools — `append_event`, `seal_segment` — let an agent **seal its own
actions** into a tamper-evident, signed, RFC 3161-anchorable archive that anyone re-verifies
offline; they are **human-gated twice** (env `CRYPTOVALID_MCP_ALLOW_WRITE=1` *and* a per-call
`confirm_token` matching `CRYPTOVALID_MCP_CONFIRM`) and disabled by default. Signing uses the
same backend URIs as everywhere else (`file:` / `pkcs11:` / `awskms:` / `vault:` / `nethsm:`) —
with the HSM/KMS backends the private key never enters the server process.

Tests: `python3 test_mcp.py` — over the real stdio transport, gate refusals and
tampered-ledger failure proven before the positive path.
Honest scope: sealing proves what/when/order/who-signed — never the truth of the recorded facts.

## DORA ICT-incident evidence (EU, evidence-driven enforcement)

Under EU DORA, supervisors moved to *evidence-driven* enforcement in 2026: they want
**timestamps, classification rationales and log trails — not policy PDFs**. Major ICT incidents
follow a hard reporting lifecycle: initial notification within **4h** of major classification
(24h backstop), intermediate within **72h**, final within **1 month**.

`dora_incident.py` makes that lifecycle **tamper-evident and reproducible**: each phase
(detected → classified → initial/intermediate/final) is a canonical, hash-chained record, and
the DORA deadlines are checked against the *recorded* timestamps — a regulator recomputes the
same verdicts from the records alone, then re-verifies with the unified verifier. Seal the chain
head with a qualified eIDAS timestamp (`cryptovalid_tsa`) for legal-grade time.
`python3 dora_incident.py attest phases.json --incident-id INC-1` / `verify att.json phases.json`.

Honest scope (the boundary never moves): **proof-of-integrity + timeline + deadline-check, NOT a
DORA compliance certificate** and NOT proof that the major/significant classification is correct
(the entity's judgement, reviewed by its auditor). Complements web-evidence anchoring tools by
covering the part they leave open: the incident lifecycle and its deadlines.

## Transaction evidence for tax/audit (IRS Form 1099-DA era)

From 2026 US brokers must report crypto cost basis (Form 1099-DA) — but NOT for assets acquired
before 2026, nor for non-custodial/DeFi activity: the taxpayer must track and, on audit, *prove*
their own transactions. Tax software computes the numbers; it does not give evidence that survives
an audit without trusting the software.

`tx_evidence.py` fills exactly that gap: it canonicalizes each transaction deterministically,
hash-chains the set (tamper-evident), and re-derives the cost basis with a **declared, deterministic
FIFO** method — so a third party (an auditor, the IRS) recomputes the **same numbers** from the same
records. `python3 tx_evidence.py attest transactions.json` / `verify attestation.json transactions.json`.

Honest scope (the boundary never moves): **proof-of-integrity + proof-of-reproducibility, NOT tax
advice and NOT proof of tax-correctness** — it does not pick your accounting method, apply
wash-sale/jurisdiction rules, or certify compliance. Those remain the taxpayer's and their advisor's.

## Long-term evidence defenders (WORM · re-anchor · heterogeneous anchors)

Three capabilities that keep evidence sound *over years*, each a runnable tool now:

- **`cryptovalid_worm.py`** — WORM escrow of the *record* (not just its hash): append-only,
  overwrite refused, GDPR crypto-shredding of the key. Meets immutable-retention rules
  (SEC Rule 17a-4, MiCA 5–7 years). `python3 cryptovalid_worm.py put <store> <key> <file>`.
- **`cryptovalid_reanchor.py`** — public-RPC anchors lose witnesses as nodes prune history
  (an "auto-DoS" of the evidence, measured). This assesses decay and flags when to re-anchor
  *before* the evidence becomes unreachable. `python3 cryptovalid_reanchor.py <retention.json> --age-days N`.
  Run it on a timer; re-anchoring itself is an on-chain tx and stays human-gated.
- **`cryptovalid_heterogeneous.py`** — real fault-independence: N *distinct* trust domains
  (Solana + Bitcoin/OTS + eIDAS QTSP), not replicas of one chain. Same-domain replicas count
  once. `python3 cryptovalid_heterogeneous.py <sha3_hex> <attestations.json> --min-domains 2`.

Honest scope: these harden *availability, retention and robustness* of the evidence — not the
truth of its content (that boundary never moves).

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

**Declared limits** (from a further independent adversarial review, 2026-08-17 — stated, not hidden):

- **Split-view / equivocation** — declared "future work" here from 2026-08-17 to 2026-09-19; since **0.14.0**
  it is a measured feature, see *Checkpoints, witnesses, split-view* below: a signer-key holder can still write two
  internally valid chains, but a checkpoint of either is cosigned by a witness only if it extends what that witness
  already cosigned, so a witness that has cosigned one view refuses the other — and, when the two views have the
  same size, returns a pair of log-signed checkpoints that is proof by itself. What remains: a log that feeds
  DISJOINT subsets of the trusted witnesses different views gets both cosigned without any refusal whenever a
  relying party's quorum N fits inside one subset (M trusted witnesses, M ≥ 2N) — which is why witness policies fix
  the set and demand N > M/2, and why the monitoring side of the protocol (not implemented here) exists; a log
  colluding with enough witnesses to reach the quorum; a relying party that trusts no witness is where it was.
- **Rollback / freshness** — the same section: the witness cosignature carries a timestamp inside the signed
  bytes, and `verify_witnessed(min_witnesses=N, max_age_s=T)` requires N trusted witnesses each with a cosignature
  younger than T on this exact checkpoint. A witness that has cosigned a newer tree never cosigns the older one
  again, so a stale view stays acceptable only for as long as the log can keep N witnesses from seeing the newer
  tree. What remains: the witnesses' clocks are the reference (not the log's), a stale view younger than T passes,
  and a log that starves N witnesses of its newer checkpoints keeps them re-cosigning the old one (the spec allows
  re-cosigning the same checkpoint). Without a witness, the anti-truncation HEAD still protects only relative to a
  known HEAD and TSA anchors give no freshness.
- **Pre-anchor window:** between an event and its sealed anchor, a root-level attacker can rewrite and
  re-seal silently. The anchor proves "existed by T"; the per-entry timestamp comes from the local
  clock and is not independently attested.
- **Selective omission:** an append-only log proves what it contains, never the completeness of what
  should have been recorded.
- **Signing-channel governance:** "non-exportable key" ≠ "custody service incompressible": whoever
  controls the KMS/HSM policy or unseal material can authorize signatures. Policy governance,
  rotation and revocation are part of the security perimeter.
- **Post-quantum: hybrid, opt-in, pinned.** Since 0.12.0 ledger entries and the signed chain tip MAY carry an
  **ML-DSA-65** (FIPS 204, pure mode, empty context since 0.13.0 so that the JDK 24+ and AWS KMS can produce and
  verify it) signature next to Ed25519 over the same bytes
  (`signer.py keygen --pq`, `sign --pq-key`, `cryptovalid_tip.py sign --pq-key`). The layer counts only when the
  relying party PINS the ML-DSA-65 key (`--pq-pubkey`, `--trusted-pq-pubkey`, both of which REQUIRE the layer): then a
  missing, foreign, malformed or invalid PQ signature is a FAIL, and `pq_protected: true` also needs every Ed25519
  signature to hold. Without the pinned key a present layer is reported as `null` (verified against the key inside
  the file, which anyone can put there), never `true`; an Ed25519-only ledger is still accepted, so stripping the
  PQ fields is a downgrade the relying party's requirement refuses, not the file. Both keys must be pinned (the
  library and the CLI refuse a PQ key without the Ed25519 key): with only the PQ key required, a re-signed Ed25519
  layer by a foreign key would still verify. Who checks what: per-entry
  Ed25519 + ML-DSA-65 — **Python and Go** (`cvverify -pubkey … -pq-pubkey …`, `crypto/mldsa`, Go ≥ 1.27); the tip's
  ML-DSA-65 — Python and Go; JS verifies the hash chain and per-entry Ed25519, Rust and Swift the hash chain only,
  and all three say the PQ layer is unchecked. The evidence
  pack is not quantum-resistant on its own: its manifest records `pq_protected` per ledger with the keys it was
  built against, but the manifest signature is Ed25519 only, so `verify_pack` confirms the layer only against keys
  the verifier pins (the ledger keys, or the manifest signer); with nothing pinned it reports `null`, never `true`.
  The PQ private key is a file (PKCS#8, 0600) or, since 0.13.0, an **AWS KMS ML-DSA-65 key** (`--pq-kms`: signed in
  a FIPS 140-3 Level 3 HSM, the key never in process memory — verified live). Cost: about 4.4 KB of base64
  signature and 2.6 KB of base64 public key per entry. Already-published TSA anchors (RSA/ECDSA) do not survive a quantum adversary either, which keeps hash-only
  anchor coverage part of the security perimeter.

Honest scope unchanged: the format proves *what/when/order/who-signed + non-alteration*, **not the truth
of the recorded facts**, and is **not** an HSM or a legal-compliance certification.

## An open standard (not just a tool)

A verifiable-evidence *feature* is copyable; an *adopted format* is not. CryptoValid is defined by
**conformance test vectors** (`spec/vectors/` + `spec/CONFORMANCE.md`), so a verifier in **any language**
proves interoperability by reproducing the same verdicts:

```bash
python3 conformance.py            # exit 0 = the reference verifier conforms (7/7 vectors)
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
certificate against the **EU List of Trusted Lists** (ETSI TS 119 612, service type `TSA/QTST`) —
**validated end-to-end LIVE (2026-08-16)**: a real timestamp from a real *qualified* TSP
(**Izenpe**, Spanish Trusted List) over an ingestion HEAD hash returned `qualified: true`, while
two non-qualified TSAs (freetsa, and **Certum's public TSA** — correctly distinguished from the
*qualified* services of the same company listed in the Polish TL) were rejected. Honest scope:
`qualified: true` means the TSA certificate is a QTST-`granted` service in the EU Trusted Lists
at verification time; full ETSI TS 119 615 legal validation (chains, revocation, time constraints)
is beyond exact-fingerprint matching, and production use still wants a contracted QTSP with an SLA. The linear hash-chain stays the interoperable core; Merkle is **additive**. Domain separation:
`0x00` leaves, `0x01` nodes. Third-party verification needs only
`(entry, index, tree_size, audit_path, root)`. Tests: `python3 test_merkle.py`.

## Java verifier (JDK standard library, 2026-09-16)

`verifiers/java/CvVerify.java` is a single-file, dependency-free Java implementation of the verifier: the strict
JSON acceptance profile, the canonical hash chain (SHA-256 / SHA3-256), per-entry **Ed25519** (JDK 15+) and
**ML-DSA-65** (JDK 24+, `Signature.getInstance("ML-DSA-65")`) signatures with the same tri-state as `signer.py`, and
the signed chain tip including its post-quantum layer. It is possible only because the profile signs with the EMPTY
FIPS 204 context: the JDK (24 → 27) exposes ML-DSA with no context API. It sits in the differential oracle next to
Python, JS, Go and Rust (verdicts, tip tri-state and entry signatures compared on every hostile input) and in CI on
JDK 27. Run: `java verifiers/java/CvVerify.java ledger.jsonl [-pubkey HEX -pq-pubkey B64] [-tip F -trusted-pubkey HEX
-trusted-pq-pubkey B64]`. Measured on a ledger and tip whose ML-DSA-65 signatures were made inside AWS KMS: PASS,
entries and tip `pq_protected: true`.

## Go reference: writer + verifier (2026-09-14)

`verifiers/go/` is a stdlib-only Go implementation of the profile — the first one that also **writes**
(`cryptovalid.Append`: canonical JSON, `prev_hash`, SHA-256, O(1) per append, `flock` from tail-read to
fsync) so a Go service can produce a cryptovalid ledger at insert time and anyone can verify it with the
Python, JS or Go verifier. `vectors.json` (generated by Python) is the single byte-level oracle for the three
languages; on a 200-row audit-log ledger and 6003 enumerated tampers the three verifiers give identical
verdicts. Two profile rules made explicit the same day in all three: nesting > 512 and unpaired UTF-16
surrogates are refused fail-closed (`spec/CONFORMANCE.md`).
Since 0.12.0 `cvverify -trusted-pq-pubkey <b64>` also checks the **ML-DSA-65** signature of a hybrid tip, and since
0.13.0 `-pubkey <hex> -pq-pubkey <b64>` verify every entry's Ed25519 + ML-DSA-65 signatures with the standard library
(`crypto/mldsa`, **Go ≥ 1.27**, the same tri-state as `signer.py`); a binary built with an older toolchain answers
`pq_unverifiable` (a FAIL when the key is required), never a silent pass.

## Receipts, monitor, eIDAS 2.0 self-assessment, JWS (2026-09-13)

Compared online with the field (Sigstore Rekor v2, immudb, Azure Confidential Ledger, Google Trillian/Tessera,
the IETF SCITT architecture) and with the new EU rules for **qualified electronic ledgers** (eIDAS 2.0,
Regulation (EU) 2024/1183 Art. 45l; Commission Implementing Regulation (EU) 2025/2531 of 16 December 2025),
four pieces were missing and are now here, stdlib-only:

| Module | What it adds | Standard |
|---|---|---|
| `cryptovalid_receipt.py` | **Portable receipts**: inclusion and consistency proofs for one entry / two tree heads, with a tree head **really signed** by the log key (the old `signed_tree_head` in `cryptovalid_merkle` carried no signature — renamed `tree_head`, alias kept). JSON profile and **COSE_Sign1** encoding per RFC 9942 (`vds`=1 RFC9162_SHA256, `vdp` with inclusion −1 / consistency −2 as arrays of bstr, alg EdDSA; consistency receipts carry a **detached** payload and the verifier recomputes root_2); minimal CBOR codec (duplicate keys and deep nesting refused). Verification is fail-closed: it needs **your** entry (inclusion) or **your** previous root (consistency) and a **trusted** log key — nothing named inside the receipt is trusted, and the proof's tree size must equal the signed head's. | RFC 9942, RFC 9162, RFC 9052, RFC 8949 |
| `cryptovalid_tip.py` | **Signed chain tip** (0.11.0): `{entries, tip_sha256, ts}` signed with the log key after every append (O(1), atomic sidecar `<ledger>.tip.json`; Go `AppendSigned` / `cvappend -tipkey` writes it under the same lock). Any snapshot verifier holding the tip and the trusted key sees tail truncation, suffix rewrite and unsealed appends — the three attacks a bare chain cannot see. Same signed bytes in Python, JS and Go (cross-signed in the tests). Limit: the holder of the log key; deleting the tip is visible only with `--require-tip` or a copy kept elsewhere (monitor state, receipts, anchor). | signed tree-head idea of RFC 6962, reduced to the chain tip |
| `cryptovalid_monitor.py` | **Append-only / non-equivocation monitor** (what rekor-monitor and immudb's auditor do): keeps the last green tree head and proves at every run that the ledger only grew; catches truncation, rewrite of old entries, forks and log-key changes; a red run never advances the baseline; the saved state is itself verified on load (signed head). Three modes, stated: **writer** (`--keyfile`, signs the head), **auditor** (`--trusted-pubkey`, never writes an unsigned state, advances only with a signed head published by the writer via `--sth-file`), none (blind trust, declared). Declared limits: the blind window between two runs, and deletion/replay of the state file (keep it where the ledger writer cannot write, or anchor each signed head externally). | RFC 6962 consistency proofs |
| `eidas_ledger_check.py` | **Self-assessment** of a ledger against IR 2025/2531 (REQ-7.5-03/04/05/06, Art. 45l): what is met by construction (hash list + Merkle, SHA-256/SHA3-256, immediate detectability), what needs the deployment's qualified pieces (qualified certificates, QTSP timestamps, certified signing device), what no code can give (being a QTSP). Produces the automated **ledger report** (Annex §2) and an **Electronic Ledger Practice Statement** skeleton (REQ-6.1-12) filled from what was measured. Never a claim of qualification. | eIDAS 2.0, IR 2025/2531, ETSI EN 319 401 |
| `cryptovalid_jws.py` | **JWS container** (RFC 7515, EdDSA per RFC 8037) of a record's canonical form with `kid` and optional **`x5c`** — the header the regulation requires for JAdES; the qualified certificate is the user's, the toolkit puts it in the right place. Not a full JAdES profile (stated). | RFC 7515, RFC 8037, ETSI TS 119 182-1 (target) |

```bash
python3 signer.py keygen log.key
python3 cryptovalid_receipt.py inclusion examples/sample_ledger.jsonl 2 log.key --cose r.cose > r.json
python3 cryptovalid_receipt.py verify r.json <log_pubkey_hex> --entry-json my_entry.json   # offline: YOUR entry + trusted key
python3 cryptovalid_monitor.py examples/sample_ledger.jsonl state.json --keyfile log.key   # run it on a schedule
python3 eidas_ledger_check.py examples/sample_ledger.jsonl --practice-statement --provider "ACME"
python3 cryptovalid_jws.py sign examples/sample_ledger.jsonl 0 log.key --x5c <base64 DER cert>
python3 test_ledger_evidence.py                                         # 18 tests, negatives first
```

Honest scope, once more: a receipt signed by the log key proves what the log key holder published; a
qualified electronic ledger needs a qualified trust service provider, qualified certificates/timestamps and
certified devices — `eidas_ledger_check.py` tells you exactly which of those you still owe.

## Checkpoints, witnesses, split-view (2026-09-19, 0.14.0)

The two limits above were the honest gap between this archive and a transparency log. They are closed the way the
field closes them — with the world's formats, so that the field's own software verifies the result — and the
closure is measured, not asserted (`test_cryptovalid_witness.py`, 27 tests — 26 without a Go toolchain, 5 without `cryptography`; the bench against
the reference witness is in the release dossier):

| Module | What it does | Standard (editor's copies downloaded 2026-09-19) |
|---|---|---|
| `cryptovalid_checkpoint.py` | A **checkpoint** of a ledger: origin, tree size, RFC 6962 root of the canonical entries (the same leaves the receipts prove against), signed as a **note** by the log key (Ed25519, key id = SHA-256(name ‖ 0x0A ‖ type ‖ pubkey)[:4]); `vkey` strings; strict parsing where the spec is strict (tree size without leading zeroes, canonical base64 root, control characters refused, at most 100 signature lines — the ceiling of the Go implementation, the spec floor being 16) and permissive where the spec says so (any non-empty origin line: "go.sum database tree" parses); every line of a known key is verified (the spec's MUST — the Go library verifies the first line per key and drops repeats, so a note with a bogus repeat opens there and is refused here: declared, fail-closed), byte-identical repeats count once, keys of types nobody verifies here (RFC 6962 THS 0x05, unassigned) are ignored, never accepted — ECDSA (0x02) and ML-DSA-44 (0x06) ARE verified, see below — two different trusted keys colliding on one 4-byte id are refused as ambiguous (measured with a real collision); consistency proofs as base64 lists. | c2sp.org/tlog-checkpoint, c2sp.org/signed-note |
| `cryptovalid_witness.py` | A **witness**: keeps the last checkpoint it cosigned per origin (trust on first use, stated; several trusted keys per origin for rotation; an origin that differs from the key name is configured explicitly, as for `sum.golang.org`), cosigns a new one only when the log signature verifies **and** the new tree extends the stored one (same size → same root; larger → a consistency proof that verifies; smaller → rollback). Every refusal that involves two log-signed checkpoints returns both (`evidenza`); the pairs that are **proof** — `split-view`, two log-signed roots at one size, anyone can check both signatures — are appended once each to `<state>.evidence.jsonl` (also when the refusal reaches an HTTP client as a bare status), whether the witness meets them at the size it holds, at a size it cosigned earlier (`<state>.cosigned.jsonl`, one line per cosigned checkpoint; the last 4 MiB are searched) or at a size it refused earlier without proof and is now passing; `rollback` and `unproven-extension` are **not** proof (a log genuinely signed the older checkpoint, a missing proof may be a client error): they are returned and counted (distinct ones), and remembered as size/root/time (last 100 per origin); the log-signed notes refused without proof beyond the stored size — whatever old size the request stated — are kept in a `pending` ring (at most 100 per origin and 256 KiB, notes above 16 KiB kept as root only, smallest sizes dropped first) so that a later cosign, a second root at that size or a later rollback to it can turn them into proof (a cosign consumes the pending roots at its own size and leaves the others in the ring). A second root at a size the witness never cosigned pairs with a root it still remembers (pending ring, or the refusals ring as root only → `split-view-unkept`); one it no longer remembers (never seen, or dropped from the rings) is a `rollback`/`unproven-extension` it cannot turn into proof — stated. The cosignature is **cosignature/v1** (timestamp inside the signed bytes). `serve` exposes the `add-checkpoint` endpoint of the **tlog-witness HTTP interface** (`POST <prefix>/add-checkpoint`; 200 with the signature lines, 400, 403, 404, 409 with the size as `text/x.tlog.size`, 422, in the spec's order; 500 when the witness cannot decide — no Ed25519 implementation (the reason in the body), state file unreadable or unwritable or invalid configuration (the reason on stderr); check-and-persist under a process lock and a file lock, state and evidence fsync'ed before the response); `submit` is the log side (old size 0, then 409 → the witness's size and our proof; from the answer it keeps only the lines of the witness keys it trusts, each replacing that key's older line). `verify_witnessed` is the relying party: log signature (one key or a rotation set), the expected origin, ≥ N distinct trusted witnesses on *this* text — every line of a trusted witness key is verified and its newest counts — and, with `max_age_s`, ≥ N of them younger than it (a witness whose newest cosignature is in the future beyond `clock_skew_s` does not count; without `max_age_s` no clock is consulted). | c2sp.org/tlog-cosignature (Ed25519 v1), c2sp.org/tlog-witness |
| `cryptovalid_scitt.py` | **SCITT** (RFC 9943, Proposed Standard, June 2026): a **Signed Statement** (COSE_Sign1 with the CWT Claims header — iss, sub — content type and kid, payload attached or detached), its **registration** on a cryptovalid ledger (the entry binds the statement's SHA-256), a **Receipt** with the CWT Claims RFC 9943 requires and the RFC 9942 inclusion proof (vds 1, vdp −1; the canonical leaf travels unsigned beside it), and the **Transparent Statement** (receipts under label 394). The relying party verifies offline, fail-closed: Issuer signature, TS signature with ITS trusted key, that the leaf binds THIS statement, and the RFC 6962 path up to the signed root. Measured with **pycose**, an independent COSE implementation: it decodes both messages, verifies both signatures, reads labels 15/394/395, refuses a wrong key or a tampered payload (`test_cryptovalid_scitt.py`, 5 tests, pycose required in CI). Stated: EdDSA only; the `RFC9162_SHA256` profile, not CCF's; no public Transparency Service here. | RFC 9943, RFC 9942, RFC 9052 |
| `cryptovalid_monitor.py --match REGEX` | **Identity / subject search** while monitoring, the way rekor-monitor searches a log for identities (its README, 2026-09-19): each pattern is matched against the canonical bytes of every entry — the bytes the Merkle leaf commits to — and the run reports the matching leaves (index, self_hash, snippet) and the NEW ones since the last green state, so an inclusion receipt can prove any of them. | rekor-monitor (Sigstore) |
| `verifiers/note_oracle/` | **Independent verifier** with no cryptovalid code: `golang.org/x/mod/sumdb/note` (the Go checksum database's implementation of signed notes) and `github.com/transparency-dev/formats/note` (cosignature/v1; pinned to the commit the reference witness of 2026-09-18 uses, which also caps cosigner names at 255 bytes — so do we). Built and run in CI; every listed key must have signed, a tampered byte or a missing cosigner is exit 1. | the ecosystem's own libraries |

Measured on 2026-09-19 against the **reference witness** (`github.com/transparency-dev/witness`, commit 55a5a0bf332a of
2026-09-18, the code the Armored Witness hardware runs), three ways: its in-process `witness.Update` cosigned our
checkpoint of a 5-entry ledger, refused the 8-entry one without a proof, cosigned it with our RFC 6962 consistency
proof, refused a fork at size 8 ("roots do not match", logging both checkpoints as inconsistent) and refused rollbacks;
its HTTP **client** drove our `serve` with the same outcome at every step; our `submit` **client** drove its HTTP
server (200, 409 then proof, 422 on the fork, 409 on rollbacks) and the cosignature it returned verified in
`verify_witnessed` and in the Go oracle (`VERIFIED sigs=3 unverified=0` on a note cosigned by both witnesses).

```bash
python3 signer.py keygen log.key && python3 signer.py keygen witness.key
python3 cryptovalid_checkpoint.py sign ledger.jsonl --origin example.org/ledger --key log.key --out cp.note
LOG=$(python3 cryptovalid_checkpoint.py vkey --key log.key --name example.org/ledger)
WIT=$(python3 cryptovalid_checkpoint.py vkey --key witness.key --name witness.example/w1 --cosigner)
python3 cryptovalid_witness.py serve --state witness.json --name witness.example/w1 --key witness.key --log-vkey "$LOG" --port 8477 &
python3 cryptovalid_witness.py submit ledger.jsonl --origin example.org/ledger --key log.key --url http://127.0.0.1:8477 --witness-vkey "$WIT" --out cp.cosigned.note
python3 cryptovalid_witness.py verify cp.cosigned.note --log-vkey "$LOG" --witness-vkey "$WIT" --min-witnesses 1 --max-age 3600
```

Log keys: Ed25519 (0x01) and **ECDSA** (0x02, P-256/384/521, the type Rekor v1 uses — key id SHA-256(DER SPKI)[:4], as
transparency-dev/formats computes it) — measured on the three real `rekor.sigstore.dev` checkpoints of 2026-09-19 in
`examples/checkpoints/` (2.77 billion entries on the active shard: verified by us and by the Go oracle's
`NewECDSAVerifier`, refused when tampered, cosigned by our witness). Cosignatures: Ed25519 cosignature/v1 (0x04) and
**ML-DSA-44** cosignature/v1 (0x06, the type the witness spec now says witnesses SHOULD use; FIPS 204 pure mode, the
spec's `cosigned_message` over origin/size/root — extension lines are outside it, as the spec states): `serve --pq-key`
adds the ML-DSA-44 line beside the Ed25519 one, and the Go oracle (filippo.io/mldsa through transparency-dev/formats)
verifies it. Stated limits of this layer: RFC 6962 THS keys (0x05) are ignored; our own logs sign Ed25519 (ECDSA is
verified, not emitted); the monitoring (GET) side of tlog-witness is
not implemented, only `add-checkpoint`; no public witness has cosigned an OMEGA ledger (there is no public OMEGA log — the
interop above is local, with the reference implementation); the witness state file's integrity is the operator's; the
per-entry timestamps remain local-clock claims (pre-anchor window) and an append-only log never proves completeness
(selective omission). Declared divergences from the Go libraries, in the refusing direction: a cosignature
timestamp above 2^63−1 is refused here because the cosignature spec says it MUST NOT exceed that value, a zero timestamp is
refused because the witness spec says a witness MUST NOT emit one (Go's Ed25519 cosignature verifier checks neither; its ML-DSA-44 one refuses above 2^63−1 and accepts zero), a second, invalid line
from a key that already signed validly makes the note invalid here (Go drops repeats), a signature line above 8 KiB of
decoded material makes the note invalid here even from an unknown key (Go has only the 100-line cap and ignores the
line); the checkpoint parser demands canonical base64 for the root (the `formats/log` reader does not); and one in the
accepting direction: the same vkey listed twice is one key here, `ambiguous key` in Go's `VerifierList` (the same key,
no effect on what verifies). The
evidence file holds proofs only (one record per distinct pair of log-signed roots at one size), so an unauthenticated
client replaying the log's public history cannot grow it (measured: 5 replays of one rollback → no record; 291 future
checkpoints without proof → no record at the 289 fresh sizes, and one record at each of the two sizes that already held
refused roots, where the third log-signed root is one more genuine proof — one pair per request, so a log signing many
roots at one size buys one record and one fsync per request, not one per pair). The state it can grow only up to two
bounded rings per origin — the last 100 refusals as size/root/time and at most 100 pending log-signed notes, 256 KiB
(UTF-8 bytes) in all, notes above 16 KiB remembered by their root only — a later conflicting root then yields a
`split-view-unkept` record with the earlier root, not a full pair (measured: 291 replays → 100 pending, file size flat;
20 notes with 115 extension lines of 8 000 bytes and 60 with 20 KB of four-byte characters → state under 200 KB) — plus
one index of the last 10 000 recorded proof pairs (≈ 0.75 MB at most; beyond it a very old pair replayed is recorded
again), which grows only with the log's misbehaviour. A request that adds something to the rings or to the proofs
(a rollback, an unproven extension, a log-signed root beyond the stored size, a new pair — whatever status it then gets)
rewrites and fsyncs the state file once; a request that adds nothing (a replay of a refusal already in the ring, a
replay of a recorded pair, a bad signature, an unknown origin, a malformed body) writes nothing — measured on every
path with a spy on the writer. The refusals ring counts distinct refusals, not attempts. A rollback is compared with the roots the witness still
holds at that size and with the last 4 MiB of the cosigned history — one file shared by all the origins a witness
serves, so a busy origin can push a quiet one's older cosigned checkpoints out of that window (a bounded read: stated). What grows without a bound: the cosigned
history, one line per checkpoint this witness cosigns (each needed a valid consistency proof), and the proofs, at most one
per request — a log that signs many roots for one size fills the file with proofs of its own misbehaviour at the rate of
its requests, each request costing the witness a bounded number of writes. Lines from keys the witness does not know are stripped from
everything it stores.

## High-frequency ingestion (Art. 12 logs at scale)

`cryptovalid_ingest.py` turns a high-rate event stream into this same evidence format —
nothing new to verify, just more of it, faster:

- **segments** (`ledger-000000.jsonl`, …): each one an ordinary hash-chained ledger the
  stdlib verifier accepts unchanged — an auditor needs one file, not the archive;
- **sealing**: each segment gets an RFC 6962 **STH sidecar**, hash-chained to the previous
  STH (removing or reordering *interior* segments is detectable), optionally **Ed25519-signed
  via any KMS/HSM backend** above, and ready for a single RFC 3161 timestamp per batch;
- **HEAD manifest** (`<prefix>.head.json`, rewritten at every seal): commits to the segment
  *count* and the last STH — a bare STH chain, like any bare hash chain, cannot see its own
  **tail** being truncated or extended (same limit the threat model states for entries).
  Honest scope: the HEAD closes the tail gap only when **signed** and verified against a
  **pinned public key**; an unsigned HEAD can be rewritten by whoever rewrites the archive.
  Anchor the HEAD hash via RFC 3161 for third-party time;
- **batched fsync** (the durability unit is the flush; `batch_size=1` for per-event
  durability) and **fail-closed crash recovery**: a torn trailing line is truncated and
  reported; a *tampered* history refuses to resume;
- **automatic RFC 3161 anchoring** (`tsa_url=`): every seal live-timestamps the STH canonical
  hash (token in `<segment>.sth.tsr` + honest metadata receipt), optionally LOTL-certified as
  eIDAS-qualified (`lotl_check=True`, cached) — validated live against a real QTSP (Izenpe).
  Best-effort by design: a TSA/network failure never blocks ingestion (it lands in the receipt
  and in a verify warning) and runs outside the writer lock (a slow TSA never stalls appends).
  Verification of tokens is two-layer and fail-closed: **CMS signature** (openssl, `-noverify`:
  the chain-to-QTST question belongs to the LOTL match) + **digest binding** to the STH — a
  forged blob or an unbound token fails; without openssl, acceptance degrades to binding-only
  with an explicit warning. The LOTL cache lives in `~/.cache/cryptovalid/`, never inside the
  archive (a co-located cache could be poisoned to fake the qualified verdict);
- `verify_archive()` / `python3 cryptovalid_ingest.py verify <dir> [--lotl --lotl-ms ES]`
  re-checks every sealed segment: hash chain, Merkle root vs sidecar, STH chain, signatures,
  HEAD manifest, and RFC 3161 token binding (LOTL qualification opt-in, needs network).

```bash
python3 cryptovalid_ingest.py bench  /tmp/cv-bench --n 50000   # throughput MEASURED on your machine
python3 cryptovalid_ingest.py verify /tmp/cv-bench --prefix bench
```

**Honest numbers:** throughput depends on machine/filesystem/batch — the bench measures it
where you run it (reference dev box: ~25k events/s at batch 256 with per-batch fsync; your
number is the one that counts). Timestamps come from the **host clock**: pair sealed STHs
with RFC 3161 tokens for independent time. Tests: `python3 test_ingest.py` (tamper, torn-tail
recovery, concurrency, signed-STH negative controls).

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

CryptoValid is built on open standards and techniques whose inventors we **name and credit**:
Merkle trees (**Ralph Merkle**, US4309569, 1979 — expired), hash-chain timestamping (**Stuart
Haber & W. Scott Stornetta**, US5136647/US5373561, filed 1991–92 — **expired 2004**), **RFC 3161**
timestamping and **RFC 6962** Merkle proofs (open IETF standards; CT by **Laurie, Langley &
Kasper**), SHA-256 (NIST) and Ed25519 (**D. J. Bernstein et al.**, public domain). The same design
has been practised openly since 2013 by Certificate Transparency, Sigstore/Rekor, OpenTimestamps
and immudb — broad, load-bearing prior art.

**Closest patented art, considered and distinguished** (screening 2026-08-17): the **Guardtime /
KSI** family (Buldas et al.) — its foundational US8719576B2 ("distributed calendar infrastructure",
priority 2003) **expired December 2024**, and the living members (e.g. US9614682, US11057187) claim
the calendar-aggregation KSI architecture, which this design does not practise (we use per-archive
Merkle STHs + independent RFC 3161 TSAs, not a distributed calendar). The IETF datatracker records
**zero IPR disclosures** against RFC 6962 — noting honestly that IETF disclosure duties bind
*participants* only, so this is corroboration, not proof.

**No *known* third-party patent is practised, after the documented screening above.** A freedom-to-
operate claim is a universal negative and cannot be proven — pending applications and non-US filings
remain invisible by construction. *Technical FTO note, not a legal opinion; a definitive FTO
requires professional counsel.*

## The next decade (read on 15/09/2026)

What will change under an evidence ledger written today, and what this repository already does about it:

- **Signatures.** NIST IR 8547 (an initial public draft, not a final standard) proposes deprecating the
  112-bit-strength quantum-vulnerable schemes after 2030 and disallowing all of them — Ed25519 and ECDSA included —
  after 2035. A ledger kept for the multi-year retention windows of DORA, the CRA (technical documentation for at
  least 10 years, Art. 13(13)) or eIDAS crosses that line. The `pqcrypto/` suite lets the **AP2 evidence format**
  carry a hybrid classical + **ML-DSA-65** (FIPS 204) signature through the `cryptography` library, checked against
  the NIST ACVP ML-DSA-65 signature-verification vectors; since **0.12.0** the core ledger entries, the signed chain
  tip carry the same hybrid Ed25519 + ML-DSA-65 layer and the evidence-pack manifest records it per ledger (threat
  model above: opt-in, pinned by the relying party's PQ key; entries checked by Python, the tip by Python and Go).
  After 2035 an RFC 3161 token (itself RSA/ECDSA-signed) proves nothing on its own: hash-only anchors
  (OpenTimestamps) and periodic re-timestamping are what keep an Ed25519-only ledger load-bearing, which is why
  anchor coverage is part of the threat model.
- **Transparency and receipts.** The IETF SCITT architecture is now **RFC 9943** (Proposed Standard, June 2026) and
  COSE receipts are **RFC 9942**; this repository's receipts follow RFC 9942 (`vds`=1 RFC9162_SHA256, inclusion −1 /
  consistency −2, alg EdDSA) and its monitor plays the role rekor-monitor and immudb's auditor play (append-only,
  consistency over time; the blind window between two runs is declared), and since 0.14.0 its checkpoints and
  witness speak the C2SP formats and protocol the transparency ecosystem (Sigstore, Tessera, the Go checksum
  database, the witness network) uses — measured against the reference witness, see above. Registering signed statements with a SCITT
  transparency service and obtaining its receipts is the natural next step and is not implemented yet.
- **Qualified ledgers in the EU.** Commission Implementing Regulation (EU) 2025/2531 gives the requirements for
  *qualified* electronic ledgers under eIDAS 2.0 (Art. 45l); `eidas_ledger_check.py` self-assesses a ledger against
  them and says what only a QTSP can add. Being qualified is a status a QTSP holds, never something this code confers.
- **Supply-chain formats.** CycloneDX 1.7 (ECMA-424, October 2025) is the current specification; the CRA evidence
  packs attached to this project's releases are produced with the public **cra-evidence** tool (CycloneDX 1.6 by
  choice — the stable schema with mature validators — Art. 14 clock, ENISA SRP fields) and signed with an AWS
  KMS-held (HSM-backed) key whose public part ships with the release; the Transparency Exchange API (ECMA TC54) is the
  distribution channel to watch.
- **Verification without the producer.** The five verifiers in the differential oracle (Python, JavaScript, Go, Java,
  Rust) plus a reduced-scope Swift one exist so that the evidence outlives this codebase: an auditor in 2035 needs the
  profile and one independent implementation, not this repository.


## Contact, pilots, citation

- **Questions, interoperability reports, divergences found by your own verifier**: open a thread in this repository's
  [Discussions](https://github.com/robertolocatelli81-dev/cryptovalid-opencore/discussions) or an issue; e-mail:
  roberto.locatelli.81@gmail.com.
- **Pilots**: the author runs short evaluation pilots (four to six weeks, scoped and priced up front) with banks, QTSPs,
  GRC vendors and Java shops that need evidence verifiable offline for years, including through the post-quantum
  transition. Write with the use case; the answer says what is measured and what is not.
- **Licence**: AGPL-3.0-or-later for this repository (see the licensing table above); a **commercial licence of the same
  code** is available from the author for organisations that cannot adopt AGPL.
- **Citation**: DOI [10.5281/zenodo.22539578](https://doi.org/10.5281/zenodo.22539578) (Zenodo concept DOI: always the latest version).
- Author: Roberto Locatelli, 2026. Public interventions by his AI agent (Noûs) are signed as such.

## Install (pip)

```bash
pip install --extra-index-url https://robertolocatelli81-dev.github.io/pypi/ cryptovalid-opencore
```

Release artifacts are attached to GitHub Releases; the index links carry `#sha256=` fragments verified by pip. All documented `python3 <file>.py` commands keep working unchanged from a clone.
