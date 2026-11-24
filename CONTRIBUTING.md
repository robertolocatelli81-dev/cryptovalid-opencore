<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# Contributing

Thank you for looking at cryptovalid-opencore. This page says what is welcome today and how changes are made.

## Welcome

- **Reports of defects** you can reproduce, and files that two verifiers judge differently: open an
  [issue](https://github.com/robertolocatelli81-dev/cryptovalid-opencore/issues) with the version
  (`cryptovalid-verify --version`), the exact command, the smallest input that shows the result, what you expected and
  what you got.
- **Interoperability reports** from your own verifier or writer, and questions: open a thread in
  [Discussions](https://github.com/robertolocatelli81-dev/cryptovalid-opencore/discussions).
- **Vulnerabilities**: privately, as [SECURITY.md](SECURITY.md) says — never in an issue or a discussion.

## Code contributions

Pull requests with code are **not accepted at present**. The project has one maintainer, who answers for every line
it publishes; until there is a reviewer other than the author and a written rule for the rights in contributed code,
a report with a reproducer is the way to get a change made. A pull request is closed with a pointer to this section;
its idea is welcome as an issue.

## How the maintainer's own changes are made

- Since 15/11/2026 every commit carries a `Signed-off-by:` line (earlier commits do not): the author certifies the
  [Developer Certificate of Origin 1.1](DCO) (the text in this repository is the one published at
  https://developercertificate.org/).
- Changes written with the help of an AI agent say so in the commit message (`Assisted-by:` line); the maintainer
  reviews them and is accountable for them.
- A rule of the format changes first in `SPEC_EVIDENCE_FORMAT.md`, with a version, then in the code.

## What a change must satisfy

1. **A fix comes with a test that fails without it.** The change says how it was seen to fail.
2. **The suites stay green.** From the root of a clone, with `cryptography` installed
   (`pip install 'cryptography>=48'`):

   ```bash
   for t in test_*.py; do echo "== $t"; python3 "$t" || break; done
   python3 conformance.py
   python3 verifiers/differential_oracle.py     # needs node, go, cargo and a JDK; CI runs it if you cannot
   ```

   These are the commands of `.github/workflows/verify.yml`, which runs them on Python 3.9 to 3.14 on Linux, and 3.13
   on macOS and Windows.
3. **The core hash verifier stays standard-library only.** `verifier.py` must import and run on a Python with no
   third-party package installed.
4. **A change of behaviour of a verifier is made in every verifier** (`verifier.py` and `verifiers/`), or the change
   says which ones are missing and why. The differential oracle fails on any disagreement.
5. **Every Python file starts with its licence line** (`# SPDX-License-Identifier: AGPL-3.0-or-later`); a module
   added at the root is listed in `py-modules` of `pyproject.toml` (`test_spdx_headers.py` and `test_packaging.py`
   check both).
6. **A name of the declared API is not removed or changed without the deprecation period** of [API.md](API.md).
7. **User-visible changes have a line in `CHANGELOG.md`.**
8. **Files of other projects** (test vectors, fixtures) keep their own licence: put them under `testdata/`, add the
   licence text and list each file with its source and commit, as `testdata/interop/README.md` does. Do not mix them
   into a commit with your own work.
