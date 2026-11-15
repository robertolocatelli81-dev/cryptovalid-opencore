<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# Governance

## Who decides

cryptovalid-opencore has **one maintainer**, Roberto Locatelli, who holds the copyright, decides what is merged and
released, and answers for it. Changes written with the help of his AI agent (Noûs) are reviewed by him and signed as
such.

| Access | Who |
|---|---|
| Merge to `master`, tags, releases, repository settings | the maintainer |
| Publishing to PyPI (environment `pypi`, approved by a person for each release) | the maintainer |
| Signing keys of releases and evidence packs | the maintainer |

## How decisions are made

- The evidence format is specified in `SPEC_EVIDENCE_FORMAT.md` before it is coded; a rule that changes takes a new
  version of the specification, and a ledger valid under a published version stays verifiable (§6).
- A change of behaviour of a verifier is made in every verifier, and the differential oracle in CI fails on any
  disagreement it does not declare by name.
- Defects reported publicly are answered in the issue; vulnerabilities as [SECURITY.md](SECURITY.md) says.
- What other code may rely on is declared in [API.md](API.md); what is supported, in [SUPPORT.md](SUPPORT.md).

## What is not met today

- **No second reviewer.** Every change is reviewed by its author only; reviews named in the CHANGELOG are run by the
  same author, not by a third party.
- **No external code contributions** ([CONTRIBUTING.md](CONTRIBUTING.md)).

## Continuity

The code, the specification, the vectors and the release history are public under AGPL-3.0-or-later: anyone may keep
using, studying, changing and redistributing them under that licence, also if the maintainer stops. Releases stay on
GitHub, PyPI and Zenodo (concept DOI in `CITATION.cff`).
