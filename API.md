<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# The declared API and how it changes

This file declares what cryptovalid-opencore promises to keep stable, from release 0.25.0. Anything not listed here
may change in any release. [Semantic Versioning 2.0.0](https://semver.org/) §1 asks a project to declare its public
API; this is the declaration.

There are four surfaces. A user of a verifier mostly depends on the last three.

## 1. Python: the package `cryptovalid`

`import cryptovalid` is the one import name that is declared. It is a typed package (it carries `py.typed`, PEP 561)
and exports exactly the names of its `__all__`:

| Name | What it is |
|---|---|
| `verify_ledger(path, algo=None, tip=None, trusted_pubkey_hex=None, require_tip=False, tip_not_before=None, expect_ledger_id=None, trusted_pq_pubkey_b64=None) -> LedgerReceipt` | the reference check of a hash-chained ledger (SPEC §5) |
| `LedgerReceipt` | `TypedDict` of the receipt of `verify_ledger` (`cryptovalid.receipts`) |
| `canonical_payload(entry) -> bytes`, `hash_with(algo, payload) -> str` | canonical JSON of an entry and its hash (SPEC §3) |
| `verify_pack(pack_dir, pq_pubkey_b64=None, signer_pubkey_hex=None, manifest_signer_hex=None, tsa_certs=None, tsa_crls=None) -> dict` | check of an evidence pack (SPEC §10; `tsa_certs`, the pinned TSA certificates, since SPEC v0.8; `tsa_crls`, the pinned CRLs of the TSA, since SPEC v0.10) |
| `verify_ledger_signatures(entries, expected_pubkey_hex=None, expected_pq_pubkey_b64=None, require_pq=False) -> dict` | per-entry signatures (needs the `sign` extra) |
| `verify_note(note, vkeys) -> dict`, `parse_checkpoint(text) -> dict`, `NoteError` | C2SP signed notes and checkpoints (SPEC §13) |
| `verify_inclusion(m, n, leaf_data, proof, root) -> bool`, `verify_consistency(m, n, proof, old_root, new_root) -> bool` | RFC 6962 proofs (SPEC §9) |
| `verify_tiles(directory, size, root=None, profile="tlog-tiles", entries=True, encoding="auto", max_size=...) -> dict`, `TileError` | tiles of C2SP tiled logs (SPEC §14) |
| `verify_token(token_der, digest, hash_alg=None, tsa_certs=None, crls=None) -> dict`, `TokenError` | RFC 3161 token check (SPEC §11; `crls`, the revocation step 8, since SPEC v0.10) |
| `CheckNotRun` | raised when a check the input asks for cannot be run here (SPEC §10) |
| `CryptovalidDeprecationWarning` | the warning class of a deprecated name (below) |
| `__version__` | the installed version of the distribution |

Each function is the same object as in the flat module it comes from (`cryptovalid.verify_ledger is
verifier.verify_ledger`); the package adds the declaration and the types, not a second implementation.

**Not declared:** the flat top-level modules themselves (`import verifier`, `import signer`, `import
cryptovalid_merkle`, ...). They are how the code is laid out today, they stay importable and their documented
commands keep working, but their names, their other functions and anything starting with an underscore may change.
Before 1.0 the code of the core moves into the package and the flat core modules become thin, deprecated aliases
(see "The road to 1.0"). Experimental modules (README) are not declared at all.

## 2. Command line

- The command `cryptovalid-verify` and its sub-commands `auto`, `pack`, `ledger`, `checkpoint`, `tiles`,
  `vkey-rfc6962`. (`archive`, `ap2`, `cldma` are experimental.)
- The documented commands of the core files run from a clone: `python3 verifier.py`, `python3 signer.py`,
  `python3 evidence_pack.py`, `python3 cryptovalid_tip.py`, `python3 conformance.py`.
- **Exit status: `0` the evidence is valid for what could be checked here, `1` it is not, `2` usage error, `74` the
  receipt was not written whole or a required check could not be run.** These meanings do not change.
- An option is not removed or given another meaning without the deprecation period. New options and new
  sub-commands may be added in a minor release.
- The wording of messages for people (stderr, help text) is not part of the API. What is written to stdout as JSON
  is surface 3.

## 3. Receipts (the JSON a verifier returns and prints)

- A key that exists keeps its name, type and meaning.
- A key **may be added** in a minor release: a program that reads receipts must ignore keys it does not know.
- A closed vocabulary (a verdict, a `reason`) may gain a value in a minor release, announced in `CHANGELOG.md`; a
  value is not removed or redefined without the deprecation period.
- The receipt of `verify_ledger` is declared key by key in `cryptovalid/receipts.py` and a test compares it with the
  code that builds it. 0.27.0 adds `failure_classes` (present only on a FAIL with entries read; its members are a
  closed vocabulary, SPEC §5 "Failure classes"). The other receipts are described in the specification (§10, §11, §13, §14) and typed as
  plain dictionaries until they are declared in the same way.

## 4. The evidence format

`SPEC_EVIDENCE_FORMAT.md` has its own version and its own rules (§6 Versioning, §7 Conformance). The promise that
matters most is there: a ledger valid under a published version of the format stays verifiable. The conformance
vectors in `spec/vectors/` are part of that promise.

## Versioning

The project follows Semantic Versioning 2.0.0.

- **Before 1.0 (now):** SemVer §4 allows anything to change in 0.y.z. This project binds itself to more: a breaking
  change of a declared surface happens **only in a minor release (0.y)**, after the deprecation period below, and is
  the first entry of that release in `CHANGELOG.md` under the heading "Breaking". A patch release (0.y.z) never
  breaks a declared surface. To stay on one minor: `cryptovalid-opencore~=0.25.0`.
- **From 1.0:** breaking changes only in a major release.
- A change that makes a verifier **refuse an input it used to accept wrongly** (or the reverse) is a fix, not a
  breaking change, whatever it does to callers who relied on the wrong answer. It is named in `CHANGELOG.md`.

## Deprecation

- A declared name, option or receipt key that is going to be removed or changed keeps working and **warns for at
  least two minor releases and at least 90 days** before the release that removes it.
- The warning is a `cryptovalid.CryptovalidDeprecationWarning`, a subclass of `UserWarning`, so it is shown by default;
  on the command line it is one line on stderr. It names the replacement and the first release without the old name.
- Each deprecation has an entry in `CHANGELOG.md` when it starts and when it ends.
- **Exception:** a fix for a vulnerability may break a declared surface without the period. The release notes say so.

## Type checking

- The package is checked in CI (`.github/workflows/governance.yml`, job `api`): `mypy --strict` (mypy 2.4.1, pinned by
  hash in `tools/requirements-types.txt`; target Python 3.10, the oldest that mypy 2.4 accepts — on 3.9 the suites
  import and run the package), `python -m mypy.stubtest` (the stub against the runtime) and `tools/check_stub.py`; the
  receipt types against the code (`test_declared_api.py`).
- Type annotations may become more precise in a minor release (for example a `dict` return declared as a
  `TypedDict`). That can make a type checker report something new in your code; it does not change behaviour and is
  not treated as a breaking change before 1.0.

## The road to 1.0

1.0.0 is released when all of these are true:

1. the code of the core lives inside the package `cryptovalid`, and the flat core modules are deprecated aliases;
2. the package passes `mypy --strict` in CI;
3. two consecutive minor releases have shipped without a breaking change of a declared surface;
4. at least one user other than the author imports the package or runs the command in their own CI.

Until then the version stays 0.y, on purpose: a 1.0 would freeze `import verifier` and its 31 public names as the
public API, which is not the API the project wants to keep.
