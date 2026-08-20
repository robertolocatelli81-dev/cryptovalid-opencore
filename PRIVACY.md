<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- Copyright (C) 2026 Roberto Locatelli -->

# Privacy — CryptoValid Open Core (DPG Standard, indicator 7)

## No PII by design

CryptoValid is infrastructure for **verifiable compliance evidence**. It processes **operational and financial
artifacts** — event logs, fund holdings (securities, quantities, identifiers such as CUSIP/ISIN), digests, and
cryptographic signatures. **It does not collect, require, or process personally identifiable information (PII)**
about natural persons:

- No user accounts, no authentication of end users, no profiles.
- No names, contact details, biometric, location, financial-account, or health data of individuals.
- The identifiers it handles (ISIN/CUSIP/LEI, fund tickers) identify **securities and legal entities**, not
  natural persons.

The tool is **self-hosted**: the operator runs it on their own infrastructure. CryptoValid neither transmits
data to the author nor to any third-party service by default (the only optional outbound calls are to a
timestamp authority (RFC 3161) or a KMS/HSM the operator explicitly configures).

## Operator responsibility

If an operator chooses to place PII inside the records it seals (which the design neither needs nor encourages),
that is the operator's decision and responsibility under the **applicable law of their jurisdiction** (e.g. GDPR
in the EU). Recommendation: keep PII **out** of the sealed content; seal a reference/hash instead, so the
append-only, immutable nature of the ledger does not conflict with data-subject erasure rights.

## Data extraction (DPG indicator 6)

All stored data is in **open, non-proprietary formats** (JSONL ledgers, JSON digests/vectors). An operator can
export or import the full non-PII content at any time with standard tools; nothing is locked into a proprietary
container.
