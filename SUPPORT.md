<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# Support

## Where to ask

| You have | Go to |
|---|---|
| A question on how to use the tools or the format | [Discussions](https://github.com/robertolocatelli81-dev/cryptovalid-opencore/discussions) |
| A bug, or a file that two verifiers judge differently | [Issues](https://github.com/robertolocatelli81-dev/cryptovalid-opencore/issues), with the smallest input that shows it |
| A suspected vulnerability | **not** an issue: [SECURITY.md](SECURITY.md) |
| A change you want to propose | [CONTRIBUTING.md](CONTRIBUTING.md) |

Community support is given by one maintainer, in public, on a best-effort basis: there is no guaranteed response
time for questions. Security reports have the times stated in SECURITY.md.

## What is supported

- **Releases:** only the **latest release** receives fixes, security fixes included. A release stops being
  supported on the day the next one is published. There are no maintenance branches. Before 1.0 a minor release
  (0.y) may contain a breaking change of the declared API, announced as [API.md](API.md) says; pin with
  `cryptovalid-opencore~=0.Y.0` to stay on one minor.
- **Python:** the versions run by CI on every push, 3.9 and 3.11; the package declares `>=3.9`. A Python version is
  dropped only in a minor release, with a line in `CHANGELOG.md`, and not before its upstream end of life.
- **The evidence format:** a ledger that is valid under a published version of `SPEC_EVIDENCE_FORMAT.md` stays
  verifiable by later releases (the versioning rules are in §6 of the specification). This outlives the support of
  any single release, because the records are meant to.
- **Core and experimental modules:** the support above is for the core listed in the README. Experimental modules
  are run by the same CI and receive fixes, without a promise of stability.

## End of support

If the project stops providing security fixes, that will be announced at the top of `README.md` and in
`SECURITY.md` before the last fix, together with what remains usable without maintenance (the
specification, the vectors, the verifiers). [GOVERNANCE.md](GOVERNANCE.md) says what to assume if the maintainer
stops answering without such an announcement.

No paid support, commercial licence or pilot is offered at present.
