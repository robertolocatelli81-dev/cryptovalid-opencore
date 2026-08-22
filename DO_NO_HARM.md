<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- Copyright (C) 2026 Roberto Locatelli -->

# Do No Harm By Design — CryptoValid Open Core (DPG Standard, indicator 9)

CryptoValid is **non-user-facing infrastructure**: a self-hosted toolkit that produces and verifies
cryptographic compliance evidence. It has **no end users, no user-generated content, no accounts, no social
features**. The three sub-indicators of the DPG Standard's "Do No Harm" are addressed as follows.

## 9a) Data privacy & security — ADDRESSED

- **No PII by design** (see [PRIVACY.md](PRIVACY.md)): the system handles operational/financial artifacts, not
  personal data.
- **Security model is the product.** Records are append-only and hash-chained (SHA-256/SHA3-256); tampering
  fails verification loudly (`verifier.py`). Signing uses **Ed25519 (RFC 8032)**; keys can be kept in an
  **HSM/KMS** and never in process memory (PKCS#11, AWS KMS, Vault Transit). Independent timestamps via
  **RFC 3161**. The honest threat model — what it protects and what it does **not** — is documented in the
  README ("Threat model") and in `SPEC_EVIDENCE_FORMAT.md`.
- Hardened after adversarial review (mutation testing, NEMESIS adversarial engine); see `spec/` and the test
  suite (`test_*.py`).

## 9b) Inappropriate & illegal content — NOT APPLICABLE

The tool **does not host, display, transmit, moderate, or store user-generated content**. There is no channel
through which a user could publish content to others. It seals and verifies an operator's own records on the
operator's own infrastructure. Content-moderation and takedown mechanisms are therefore **not applicable** to
this class of software (non-user-facing infrastructure).

## 9c) Protection from harassment — NOT APPLICABLE

The tool has **no users, accounts, messaging, or interaction between people**. There is no surface for
harassment, and no minors interact with it. User-safety and anti-harassment systems are therefore **not
applicable** to this class of software.

## Dual-use / misuse note (honest)

CryptoValid makes records **tamper-evident**; it cannot make a *false* record *true* — it is
**proof-of-integrity, not proof-of-veracity** (an operator that seals wrong data seals it faithfully; the digest
proves only that it was not altered afterwards). It is a **defensive** transparency tool: it strengthens
accountability, and provides no offensive capability. The confine is explicit throughout the docs and specs.

## Optional microfinance module — pseudonymisation & exclusion risk (honest disclosure)

The optional `microfinance.py` module is **outside the scope of this DPG nomination** (which claims only SDG 16
and 9), but it ships in the repository, so its risks are disclosed here — not hidden.

- **Pseudonymised data IS personal data in the cross-institution case.** A single MFI portfolio uses a
  **per-institution salt** for `hash_borrower()`, so the borrower reference is not linkable across institutions.
  The **cross-MFI over-indebtedness** feature, however, only works when institutions **share the hashing scheme**
  (a shared salt): the borrower reference then becomes a **stable, linkable pseudonym**, which **is personal data**
  under GDPR Recital 26 (pseudonymisation is not anonymisation). This is a genuine limitation, not a claim of
  anonymity.
- **Exclusion / blacklisting risk.** An over-indebtedness flag is dual-use: it can *protect* a borrower from a
  debt trap, or be misused as a **credit-exclusion blacklist** against poor borrowers. The tool computes and
  attests numbers; it makes **no automated decision** about any person and must not be used as the sole basis to
  deny credit.
- **Controller responsibility.** In any deployment touching a subject, the **hosting operator is the data
  controller**, responsible for the lawful basis, consent, and data-subject requests. The software provides
  local isolation and pseudonymisation, not a lawful basis.
- A privacy-preserving cross-MFI design (PSI / blinded pseudonyms / ZK) is **future work**, required **before**
  claiming any financial-inclusion (SDG 1/8/10) impact. See `spec/SPEC_MICROFINANCE.md`.
