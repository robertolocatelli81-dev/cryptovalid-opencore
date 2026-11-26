<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- Copyright (C) 2026 Roberto Locatelli -->

# CryptoValid Evidence Format — candidate standard v0.16 (2026-11-26; v0.15 2026-11-23, v0.14 2026-11-22, v0.13 2026-11-20, v0.12 2026-11-18, v0.11 2026-11-18, v0.10 2026-11-16, v0.9 2026-11-16, v0.8 2026-11-15, v0.7 2026-11-15, v0.6 2026-11-13, v0.5 2026-10-19)

License: AGPL-3.0-or-later (see LICENSE). Status: **candidate standard** — defined by CONFORMANCE
TEST VECTORS (see `CONFORMANCE.md` + `spec/vectors/`), so any implementation in any language can prove
interoperability. This is the moat that a copyable feature is not: a shared, adopted format. Comments and
independent implementations welcome (open a PR to the conformance table).

## Design goals

1. **Re-executable**: any third party recomputes every hash from the file alone.
2. **Vendor-free**: verification needs only this spec + a ~300-line stdlib
   verifier. No server, no account, no token.
3. **Append-only**: any reordering, deletion or insertion breaks the chain.
4. **Honest scope**: the format proves *what was recorded, when, in which order,
   and that it was not altered afterwards*. It does NOT prove the recorded facts
   themselves — provenance fields say who/what asserted them.

## 1. Ledger container

A ledger is a UTF-8 **JSONL** file: one JSON object per line, no blank lines
required, order = chain order.

## 2. Entry schema (core fields)

| Field | Type | Meaning |
|---|---|---|
| `idx` | int | 0-based position; MUST equal the line's position |
| `ts` | string | ISO-8601 UTC timestamp of the recording |
| `data` | object | The evidence payload (free-form, see §4) |
| `prev_hash` | hex string | `self_hash` of entry `idx-1`; entry 0 uses 64 zeros |
| `self_hash` | hex string | hash of the entry's canonical form (§3) |

Optional fields — attestations over `self_hash`, added after it is computed and outside the canonical form (§3). A
present field is not verified by being present: which verifier checks which field is in §5 (steps 5–6; until 0.20.1 this
line read "verified when present", which `verifier.py` and the Rust verifier do not do for any of them):
| Field | Type | Meaning |
|---|---|---|
| `signature` | base64 | Ed25519 signature over the `self_hash` string (its UTF-8 bytes), by `signer` |
| `signer` | hex | Ed25519 public key (32 bytes hex) of the recording party |
| `tsa_token` | base64 | RFC 3161 timestamp token over `self_hash` (message imprint = its 32 bytes); outside the canonical form since 0.20.2 (§3) |
| `signature_pq` | base64 | ML-DSA-65 signature over the `self_hash` string (its UTF-8 bytes), by `signer_pq` (hybrid ledgers, `signer.py`) |
| `signer_pq` | base64 | ML-DSA-65 public key of the recording party |

### 2.1 Closed entry schema (NORMATIVE since v0.3; written 2026-10-10 as v0.2.1)

The entry is a CLOSED object: its top-level keys are exactly the core fields plus the optional fields of the two
tables above. A top-level key outside that list is a verification FAIL with the named error `unknown_field:<key>`,
never a silent pass — measured on 2026-10-10: a ledger whose entries were written with an extra top-level key (hash
recomputed over it) verified PASS in the reference with no trace in the receipt. The `data` payload stays
domain-specific (§4): keys inside `data` are not constrained by this section. The same rule applies to the evidence
pack manifest (`evidence_pack.py`): `MANIFEST.json`, each `ledgers[i]` entry and the `rfc3161_timestamp` block are
closed objects (keys listed in `evidence_pack.MANIFEST_KEYS`, `LEDGER_ENTRY_KEYS`, `RFC3161_KEYS`); an unknown key
is `manifest_unknown_field` and the pack is not valid (since v0.5 a refusal of class `unknown_member`, §10). The ledger rule is applied by every verifier of `verifiers/`
(JS, Go, Java, Rust, Swift — aligned 2026-10-11, see CONFORMANCE.md): the same closed list, the failure named
`unknown_field:<keys>` (keys in code-point order; Rust and Swift, whose receipts carry no reason text, name the entry in
`schema_failures_idx`). The pack manifest is verified by the reference only (`evidence_pack.py`): the other verifiers do
not read packs. Two conformance vectors fix the rule: `unknown_top_level_key` (FAIL) and `unknown_key_in_data` (PASS). Since 0.20.0 the reference applies this
section and §5 step 4 on every path: the fallback 0.19.0 declared (a ledger whose first three entries carried no `idx`, no
algorithm forced, read by a generic path that applied neither) is removed; such a ledger is FAIL with `idx_mismatch` named.

## 3. Canonicalisation and hashing (NORMATIVE — interoperability depends on it)

Canonical form of an entry = JSON serialisation of the object **without** the attestation fields
`self_hash`, `signature`, `signer`, `signature_pq`, `signer_pq`, `tsa_token` (§2; corrected 2026-10-12, the list named only
the first three; `tsa_token` is in the list since 0.20.2 — a token over `self_hash` cannot be inside the bytes `self_hash` is
computed from: until 0.20.1 the six verifiers hashed it as content, so a token that binds its own `self_hash` failed step 2
and only a value that binds something else could pass. A ledger written with `tsa_token` hashed as content fails step 2
from 0.20.2 on; on 2026-10-12 none was found — 2 880 `.jsonl` files in four directory trees of the author's machine, 315 057 JSON objects, no
top-level `tsa_token` — and no writer in this repository produces the field), with **exactly** these rules (so any language
produces identical bytes — a single differing byte breaks the hash):

- keys sorted lexicographically (`sort_keys`), applied **recursively**;
- separators `(",", ":")` — no insignificant whitespace;
- **ASCII-escaped output** (`ensure_ascii=true`): every non-ASCII character is a
  `\uXXXX` escape. This removes the `é` vs `é` ambiguity across languages.

To keep the bytes deterministic, a conforming ledger **MUST NOT** contain, anywhere
in an entry:
- **floating-point numbers** — represent decimals as strings (e.g. `"400000.00"`)
  or integers. (`1.0` vs `1` vs `1e0` are not interoperable.)
- **duplicate object keys** — a strict parser MUST reject them.
- non-UTF-8 bytes.

`self_hash = HEX( H(canonical_bytes) )` where `H` is **SHA-256** (profile
`sha256`, default) or **SHA3-256** (profile `sha3_256`). A ledger uses ONE
profile throughout; verifiers MUST auto-detect by recomputing entry 0.
The constrained profile above gives the same bytes as RFC 8785 JCS only when every character of every key and string is
in U+0000..U+007E; it differs for U+007F and for any non-ASCII character (escaped here, raw UTF-8 in JCS), beyond the
BMP the member order can differ too (code points here, UTF-16 code units in JCS), and so does an integer that JCS writes
as an IEEE 754 double (10^21 is `1e+21` there, 2^53+1 becomes 9007199254740992). It is not a subset of JCS. Vector:
`spec/vectors/canonical_vs_jcs.json` (corrected 2026-11-13: until v0.5 this paragraph called the profile "a strict
subset" of JCS; the profile and every hash are unchanged).

Chain rule: `entry[i].prev_hash == entry[i-1].self_hash`; `entry[0].prev_hash`
is `"0" * 64`. Genesis is not special-cased beyond that.

**Replay binding (recommended).** The signature covers `self_hash`, which covers
`{idx, ts, data, prev_hash}` — this binds an entry to its POSITION within a chain but
not to a chain IDENTITY. To prevent a signed entry being replayed into a different
ledger, entries SHOULD carry a `ledger_id` (a random 128-bit hex) inside `data` of
entry 0 (and it is thus covered by every entry's `prev_hash` transitively). Verifiers
MAY require a single consistent `ledger_id` per file.

## 4. Evidence payload (`data`) conventions

The payload is domain-specific but SHOULD carry provenance:

```json
{
  "kind": "registry_check",
  "subject": "<who/what was verified>",
  "source": {"name": "ESMA CASP register", "url": "...", "fetched_utc": "..."},
  "source_snapshot_sha256": "<hash of the raw source document>",
  "outcome": "FOUND | NOT_FOUND | INCONCLUSIVE",
  "detail": {}
}
```

`INCONCLUSIVE` (source unreachable) is a first-class outcome: the format never
forces a boolean where reality had none.

## 5. Verification algorithm (normative)

0. **Input (v0.11, 2026-11-18).** A verifier that reads the ledger from a path opens it once, without blocking, and
   judges the OPEN descriptor: a path that is not a regular file (a FIFO, a device, a directory) is FAIL
   (`unreadable: not a regular file`) without reading a byte, and a file larger than the bound (`verifier.py`:
   `MAX_INPUT_BYTES`, 256 MiB) is FAIL (`input_too_large`). Checking the path first and opening it after leaves a window
   where the path is replaced by a FIFO, and opening a FIFO for reading blocks until a writer comes: measured on
   2026-11-18 with 0.26.0, `verifier.py <a FIFO>` did not return (killed after 5 s, exit 124). The same rule holds for
   every file §10 and §11 read from a path (below). The JS, Go and Java verifiers in `verifiers/` read the ledger by
   the same rule since 2026-11-22 (§22 rule 8); the Rust and Swift verifiers are not measured here.
   **v0.12:** for the ledger itself a FIFO is read, not refused: `verifier.py <(cat ledger.jsonl)` gives the verdict of
   the same bytes in a file, as the five other verifiers do since 0.20.2 (the oracle case `input-fifo`; v0.11 had made
   it FAIL in `verifier.py` only, a disagreement with the other five that the differential oracle reported on
   2026-11-18). It is read without ever blocking: at most the size bound (`input_too_large`), and a pipe that gives no
   byte and no end of file for 10 s (`FIFO_IDLE_SECONDS`; a FIFO with no writer) is FAIL (`unreadable: FIFO idle for
   10 s`). A device or a directory stays `unreadable: not a regular file`; the files of §10 and §11 and `auto` (§12)
   still refuse a FIFO. Only the wait for a byte is bounded, not the whole read: a writer that keeps giving bytes is
   read up to the size bound, however slowly.
   **v0.12, every path read:** the rule holds for every path a module of this package reads, through three readers and
   a closed list of exceptions that a test keeps (`test_every_open_is_bounded_20261118.py`: an `open()` of a path
   outside the list fails it, and so does a call of the loaders it names (`ctypes`, `zipfile`, `pathlib`
   `read_text`/`read_bytes`, `shutil` copies, `importlib`, `runpy`, `numpy`; `tarfile`/`gzip`/`bz2`/`lzma`/`shelve`/`dbm`
   `open`) outside a second list; no other loader of a path is used by the package (searched by hand on 2026-11-19)).
   (a) What a verifier, a checker or a report reads is a regular file, as in the first paragraph: the manifest when
   the front-end reads it again, the ledgers of a pack when their signatures and their count are read, the
   `*.sth.json`, `*.head.json` and `*.sth.tsr` of an ingest archive, the signed tip (`--tip`) and the ledger of
   `cryptovalid_tip check`, the ledger given to `signer.py verify`, the note of §13, the tiles of §14 and the files of
   §18-§19; the inputs of `cryptovalid_jws verify`, `cryptovalid_scitt verify`, `cryptovalid_witness verify`,
   `cryptovalid_receipt verify`, `cryptovalid_monitor` (ledger, state, `--sth-file`), `eidas_ledger_check`,
   `cryptovalid_heterogeneous`, `cryptovalid_reanchor`, `tx_evidence`, `dora_incident`, `fundcert_crosssource`,
   `cryptovalid_qeas`, `cryptovalid_merkle` and `cryptovalid_acta` (its key file too), the object `cryptovalid_worm
   get` reads back, the LOTL cache, the profiles of `refresh_regulatory`, the MANIFEST.json and SOLANA_ANCHOR.json that
   `cryptovalid_report` reads again and the file the MCP server hashes for its provenance. So is a writer's input that
   is read more than once or appended to: the ledger of `cryptovalid_tip sign`, of `cryptovalid_receipt` and of
   `cryptovalid_checkpoint sign`, the ledgers `evidence_pack.py build` copies, the ledger `cryptovalid_scitt register`
   appends to, the witness's state and the ingest writer's own segments. An ingest archive's segment without STH,
   which is not read, is a regular file or the failure `unsealed_segment_not_regular`, judged on a descriptor opened
   without blocking (until 0.26.0 a directory, a device or a FIFO in its place left the archive `ok`).
   (b) The ledger given to `verifier.py` is a regular file or a FIFO read within the two bounds above.
   (c) What a writer reads once, a key file or the data it signs or stores, is read as (b) (`verifier.read_input`): a
   regular file, or a FIFO read to its end within the size bound (1 MiB for a key file) and FAIL after 10 s without a
   byte, so `signer.py sign ledger out <(a command that prints the key)` works as before; a device or a directory is
   refused. These are the key files of `signer.py`, `cryptovalid_tip`, `cryptovalid_jws`, `cryptovalid_receipt`,
   `cryptovalid_scitt`, `cryptovalid_checkpoint`, `cryptovalid_witness`, `cryptovalid_kms` (the file backend) and
   `evidence_pack.py build --sign-key`, the ledger of `signer.py sign` and of `cryptovalid_jws sign`, the statement
   and the signed statement of `cryptovalid_scitt`, the previous tree head of `cryptovalid_receipt consistency`, the
   note of `cryptovalid_witness cosign` and the file of `cryptovalid_worm put`. As for the ledger, only the wait for a
   byte is bounded, not the whole read (measured on 2026-11-18: a pipe giving one byte every 3 s kept `read_input`
   reading past 30 s; a pipe of zeros stopped at the bound, `input_too_large`, peak memory 271 MiB for 256 MiB).
   The PKCS#11 module that the token backend of `cryptovalid_kms` loads (`module=` of the backend URI) is judged on a
   descriptor opened without blocking before `dlopen`: a FIFO there blocked `dlopen` with the interpreter lock held,
   past the backend's own timeout (measured on 2026-11-18: `timeout=3`, still waiting after 20 s).
   The exceptions: a temporary file the module has just written itself (three), a directory opened to fsync it (two),
   this distribution's own `pyproject.toml`, the expected verdicts `conformance.py` reads beside the vectors, and the
   development tools (`mutation_runner.py`, `tools/`).
   Measured on 2026-11-18. First by replacing each file of a pack and of an archive, one at a time, with a FIFO, a link
   to `/dev/zero` and a directory: `cryptovalid-verify pack` and `auto` with a FIFO as MANIFEST.json,
   `cryptovalid-verify archive` and `auto` with a FIFO as `*.sth.json` or `*.head.json`, `signer.py verify <a FIFO>`
   and `verifier.py --tip <a FIFO> --trusted-pubkey ...` did not return; the readers of §13, §14, §18-§19 and `auto`
   checked the path with `stat` and opened it after (the window above). Each is now a named failure of its own receipt
   (`manifest_unreadable`, `sth_unreadable`, `head_unreadable`, `tsa_token_invalid` with `unreadable`,
   `tip_unreadable`, `unreadable`, `not a regular file`, `input_unreadable`). Then a review found ten more commands,
   the report and the MCP server's pack check waiting, and a bench gave every string argument of every command, one at
   a time, a FIFO with no writer and a link to `/dev/zero` (716 cases: 179 arguments of 44 commands in 22 modules; not
   run: the commands that go to the network or serve, `cryptovalid_solana`, `cryptovalid_lotl`, `cryptovalid_tsa`,
   `cryptovalid_kms`, `cryptovalid_witness serve` and `submit`, `cryptovalid_acta run-vectors`, `cryptovalid_ingest
   bench`; `cryptovalid-verify` was measured apart, 210 cases): on 54fc7eb the command waited, or read the device
   without bound, for 41 arguments that it reads; now for none.
   Not covered: a path a command WRITES. Six output arguments still wait when the path is a FIFO with no reader
   (`--out` of `verifier.py`, `cryptovalid_tip sign`, `cryptovalid_checkpoint sign`, `cryptovalid_scitt sign` and
   `cryptovalid_acta sign`; `--cose` of `cryptovalid_receipt inclusion`). And the FORM of the error is each command's:
   for 48 of the 179 arguments the command given a FIFO or `/dev/zero` ends in a traceback and exit 1, not in a named
   failure (25 on 54fc7eb, where others waited).
1. Parse every line as JSON; any parse error → FAIL.
2. Detect profile on entry 0; recompute `self_hash` for EVERY entry → any
   mismatch → FAIL.
3. Check the chain rule for every entry → any mismatch → FAIL.
4. Check `idx == position` for every entry → any mismatch → FAIL.
5. If any entry carries a signature field (`signature`, `signer`, `signature_pq`, `signer_pq`): verify Ed25519 over the
   `self_hash` string (its UTF-8 bytes) for every entry — the **signature profile**, NORMATIVE for a verifier that performs
   this step since v0.4: a layer that does not verify (an entry unsigned or partly signed, a signature broken or malformed,
   a key or an R refused below) is a FAIL, with or without a pinned key, and the failing entries are named. The public key
   MUST decode as RFC 8032 5.1.3 says (`y < p`; `x = 0` with the sign bit set refused), MUST NOT be of small order (`[8]A`
   neutral) and MUST lie in the subgroup of order L (`[L]A` neutral); R MUST decode and MUST NOT be of small order; the
   equation is RFC 8032 5.1.7's (an R of mixed order with such a key cannot satisfy the cofactorless equation). Without a
   pinned key a valid signature by any key is a PASS: the key is the caller's to pin. Vectors: `spec/vectors/signatures/`
   (21: their `normative` block is steps 1-4, their `signature_profile` block step 5).
6. If `tsa_token` present: verify the RFC 3161 token binds `self_hash` and a
   TSA time consistent with `ts`. A verifier that performs it follows the token profile of §11. (No ledger verifier in
   this repository performs this step: see below.)
7. A ledger with zero entries is FAIL (nothing was verified; `empty_ledger` error). Emit a JSON receipt including counts, failures (capped), verdict PASS/FAIL,
   and the receipt's own SHA-256 (receipt-of-receipt, deterministic: timestamp
   excluded).

**Failure classes (v0.12, 2026-11-18; a presentation of the receipt, the verdict does not change).** A FAIL can mean two
different things: the chain is broken, or the entries are not written in this format. On a ledger of another schema the
two came out mixed: measured on 2026-11-18 on a third-party ledger of 179 entries that hashes as §3 does
(`self_hash`/`prev_hash` the same rule) but carries its own fields and no `idx`, `verifier.py` 0.26.0 named its 4 true
link breaks among one `unknown_field` and one `idx_mismatch` per entry, and `cryptovalid-verify ledger` listed 4 + 10 +
10 reasons. The receipt of `verifier.py` for a FAIL of a file it read (zero entries included; not the FAILs of step 0) therefore
carries `failure_classes`, counts over
every entry (not capped like the lists), with a closed set of members:
`{"chain": {"link_mismatch", "hash_mismatch"}, "format": {"unknown_field", "idx_mismatch", "missing_self_hash",
"missing_prev_hash"}, "other"}`. `chain.link_mismatch` counts the entries that carry `prev_hash` and whose `prev_hash` is
not the previous entry's `self_hash` (genesis: 64 zeros): it needs only those two fields, so it holds on any schema that
names them so. `chain.hash_mismatch` counts the entries whose `self_hash` does not recompute under §3: on a ledger of
another schema it may come from another canonical form, not from a change. `format` counts the entries outside §2
(top-level keys outside §2.1, `idx` not equal to the position, `self_hash` or `prev_hash` absent); they say nothing on the
links. `other` counts the remaining errors (lines that are not JSON objects, nesting, zero entries, the caller's
expectations of §17, the tip). The receipt of a PASS is unchanged. `cryptovalid-verify ledger` (and `auto` when it
reads a ledger) writes the classes first in the layer's `detail`, copies them as `failure_classes`, and lists the chain's
reasons (links, then hashes) before the schema's. The other five verifiers do not emit the member.

Reference implementation: `verifier.py` (steps 1–4 + receipt, stdlib-only); `signer.py verify` (step 5, Ed25519 and,
when present, ML-DSA-65). Steps 5–6 are OPTIONAL profiles: a verifier may leave them out (and says so: see below), their
absence never weakens steps 1–4; a verifier that performs step 5 follows its profile. Who performs them, measured on
2026-10-12 (0.20.2) on a three-entry ledger with one signature changed, missing, malformed or by another key, and on
2026-10-14 (0.21.0) on the 21 vectors of `spec/vectors/signatures/` in the six verifiers and `signer.py`:

- `verifier.py` and the Rust verifier do not perform step 5 and have no key option: a broken signature is PASS. Since 0.21.0
  their receipt says so when it matters: `signatures_not_checked` = the number of entries carrying a signature field, present
  only when it is not zero (the receipt of a ledger without signature fields is unchanged).
- `signer.py verify` verifies every entry: an unsigned, broken, malformed or partial layer is `ok: false`, exit 1, with or
  without `--pubkey`; with `--pubkey` a foreign signer is too. Its receipt names whether the signer was pinned:
  `classical_status` is `pinned` with `--pubkey` and `unpinned` without (a valid signature by any key; added 2026-11-04,
  the verdict and the exit code are unchanged). An empty `--pubkey ""` is a usage refusal, exit 2, as in JS and Java, and so is
  an empty `--pq-pubkey ""` (2026-11-04: an unset variable dropped the pin it was given for, with exit 0).
- The JS, Go, Java and Swift verifiers perform step 5 (the signature profile above) when an entry carries any signature
  field or a key is given (`--pubkey`, Go/Java `-pubkey`); the result is in `signatures.all_verified` (JS),
  `signatures.ok` (Go, Java), `signatures_all_verified` (Swift). Since 0.21.0 a layer that does not verify is a FAIL
  without a key too (until 0.20.3 the verdict was the chain's: PASS on a broken, missing or malformed signature; and only
  `signature` opened the layer). A foreign signer is a PASS without a key and a FAIL with one. The small/mixed-order rule
  applies to the entry signatures and to the signed chain tip (measured 14/10/2026: until 0.20.3 OpenSSL through
  `cryptography`, Node, Go and swift-crypto verified 6 of the 12 classes of novifinancial/ed25519-speccheck rebuilt on
  ledger entries, the JDK 4; now none in the five).
- ML-DSA-65 (`signature_pq`): `signer.py`, Go and Java verify it (a broken one is FAIL, with or without a key since 0.21.0);
  JS and Swift do not: they count the entries that carry it (`pq_not_checked`), and a ledger whose `signature_pq` is broken
  is PASS there.
- Step 6: no ledger verifier in this repository performs it. `tsa_token` is accepted (§2.1) and excluded from the hash
  (§3), and not checked by them; `eidas_ledger_check.py` counts the entries whose token passes §11 (since v0.6). `evidence_pack.py` timestamps the pack's manifest digest with RFC 3161 (verified against a real DigiCert
  TSA), not entries; `cryptovalid_tsa.py` requests and checks a token over any digest (e.g. a Merkle root).

Until 0.20.1 this paragraph named `evidence_pack.py` as the implementation of step 6 and §2 said the optional fields
were "verified when present".

## 6. Versioning

The spec is versioned semver-style. Ledgers MAY carry
`{"spec": "cryptovalid-evidence/0.4"}` inside `data` of entry 0. Breaking
changes bump major (before 1.0, minor). Verifiers should state the versions they support; the six verifiers of this
repository implement v0.4, do not state it in their receipts and do not read the `spec` value yet.
v0.3 (2026-10-12, cryptovalid-opencore 0.20.2) collects the changes since v0.2 (2026-08-13) that turn a PASS into a FAIL:
a ledger with zero entries is FAIL (§5 step 7, cryptovalid-opencore 0.9.3, 2026-09-11: until then the JS verifier said
PASS on it, exit 0, and the reference EMPTY, exit 1); the closed entry schema of §2.1 (0.19.0: an undefined top-level key fails); `idx` required on every
path (0.20.0); `tsa_token` outside the canonical form of §3 (0.20.2: a token hashed as content fails step 2). The first
three were made without a version bump (§2.1 carried its own label, v0.2.1, while the header stayed v0.2); this list
was corrected after the release of 0.20.2, which named three changes, without the empty ledger.
v0.4 (2026-10-14, cryptovalid-opencore 0.21.0) changes the Merkle leaves (§9: the canonical form of §3; a different root
for a ledger carrying `signature_pq`, `signer_pq` or `tsa_token`) and makes step 5 a normative profile (§5): for the
verifiers that perform it, a signature layer that does not verify, a key or an R of small order, a key of mixed order
turn a PASS into a FAIL without a key.
v0.5 (2026-10-19, cryptovalid-opencore 0.22.0) adds §10, the evidence pack's receipt (`admission`, `states`), and changes
the pack's verdict — not additive: a claimed RFC 3161 token that does not verify, or a claim without a token, makes the pack
not valid; an unknown `pack_format`, a key written twice in one object, a manifest field of the wrong type, an
`rfc3161_timestamp` without `anchored` and a `tsr_b64` without `anchored: true` are refusals; `manifest_signer` is read as
64 lowercase hex and `manifest_signature` as strict base64 of 64 bytes (a signer in capitals, a signature with a space or a
newline verified until 0.21.0); a ledger's signature layer is
opened by a signature field on any entry (§5 step 5), not only on the first; a manifest that claims a post-quantum layer the
file does not carry makes the pack not valid; the manifest signature and the ingest's tree-head signatures refuse keys and
R of small or mixed order (§5 step 5's rule); a check that cannot run while verifying a pack (openssl that cannot start,
does not answer, is ended by a signal — the last was "not verified" until 0.21.0) writes the complete receipt and exits
74 (stdout was empty); `evidence_pack.py build --tsa`, when openssl is ended by a signal while it reads the TSA's reply,
exits 74 and writes no pack (until 0.21.0 it wrote the pack unanchored). The ledger format (§2–§5) and its vectors do not
change. The JSON tree head (`cryptovalid_sth/1`) and the COSE receipts of `cryptovalid_receipt.py` refuse keys of small or
mixed order and R of small order by the same rule (until 0.21.0 the neutral point with R neutral and S = 0 was
`signature_valid: true` for any tree head).
v0.6 (2026-11-13, cryptovalid-opencore 0.23.0) adds §11, the profile for checking an RFC 3161 token, used by the ingest's verify, the
ingest's seal, `eidas_ledger_check.py`, the inclusion receipt of `cryptovalid_receipt.py`, the rfc3161 domain of
`cryptovalid_heterogeneous.py` and the LOTL qualification. Not additive: until v0.5 a token "bound" a digest when the
bytes `04 20 <digest>` appeared anywhere in it and a CMS signature verified with any certificate the blob carried, so a
CMS blob signed with a key made on the spot, whose content is only that OCTET STRING, counted as a timestamp
(`timestamped_segments`, `record_con_token_rfc3161`); and the LOTL called a token qualified when any certificate it
carried was a QTST certificate, signer or not. From v0.6 such tokens are refused or not counted (§11). §3 corrects the
sentence on RFC 8785. The ledger format (§2–§5), its hashes and its vectors do not change.
v0.7 (2026-11-15, cryptovalid-opencore 0.24.0) adds §12, the closed list of what `cryptovalid-verify auto` recognises. Not additive for that command: until
v0.6 every file that was not an AP2 pack or a CLDMA attestation was verified as a ledger, so a JSON document of another
kind (measured on 2026-11-14 with the `cra_pack.json` of omega-cra-evol 0.10.0) was answered with the ledger's line-by-line
`json_decode` errors instead of "not recognised". The ledger format (§2–§5), its hashes and its vectors do not change.
v0.7 also adds §13 (2026-11-15), the checkpoint signatures of static CT logs (signature type 0x05), when
`cryptovalid_checkpoint.py` moved to the core. Not additive for `verify_note`: until then a 0x05 vkey was ignored as an
unknown key, so the checkpoint of a static CT log signed only by its log key was NON_VALIDA ("no signature from a known
key"); it is OK when the signature verifies, NON_VALIDA with the reason when it does not, and a 0x05 vkey whose key is not a
canonical ECDSA P-256 key is refused as the caller's error.
v0.7 also adds §14 (2026-11-15), reading the tiles of C2SP tiled logs, when `cryptovalid_merkle.py` moved to the core.
Additive: nothing read tiles before.
v0.7 also adds to §12 (2026-11-15) the two C2SP rows, a checkpoint file and a directory of tiles: `auto` answered "format
not recognised" for both; it now names the command that verifies them (`cryptovalid-verify checkpoint`, `tiles`), which
it cannot run itself without a trusted key. `cryptovalid-verify` gains the commands `checkpoint`, `tiles` and
`vkey-rfc6962` of §13 and §14 (until then only in `cryptovalid_checkpoint.py`, which has no installed command).
v0.8 (2026-11-15) lets the caller of the evidence pack's verify pin TSA certificates (§10, `tsa_certs`, `--tsa-cert`), and
writes in §11 which refusals of the token check show the token false and which only leave it unestablished. Additive
for a pack verified without a pin: the receipt is the receipt of v0.7, `states_vocabulary` included. With a pin the
receipt names `cryptovalid-evidence-pack/states-2`, and `time_anchor` can be `verified` (it was never), `not_evaluated /
tsa_unresolved` (a token valid but not established under the pinned certificates, or, since v0.11, whose signer
certificate is neither in the token nor pinned, §11 step 6), or `contradicted` for a token whose
signature does not verify or that §11 refuses at steps 1–6 (without a pin such a token is `tsa_not_checked` and the pack
valid, as before). §11's function and the other callers of it do not change.
v0.8 also adds §15 (2026-11-15), the difference between the hybrid signature of this format and the composite ML-DSA of
RFC 10073, with the rule that the keys of one are not used for the other. Additive: no verifier changes.
v0.8 also adds §16 (2026-11-15), the roles of the keys of a witnessed checkpoint (`cryptovalid_witness.py`). Not
additive for that module: a log key of type 0x06 (ML-DSA-44), refused until then before any signature was read, is a log
key, and a log signature counts only for the log and a witness cosignature only for the witness, by the list the key
is in (until then by the type of the key); a key given in both lists stays refused, now by rule 4 of §16; a checkpoint
with extension lines whose only trusted log signature is ML-DSA-44 is refused, by the witness and by the relying party
(no such checkpoint was accepted before: a 0x06 log key was refused).
v0.9 (2026-11-16, cryptovalid-opencore 0.25.1) adds §17, what a ledger verifier does with the expectations its caller
gives. Not additive: until v0.8 the expected ledger identity (`--expect-ledger-id`) and the oldest acceptable tip
(`--tip-not-before`) were applied only inside the check of a signed tip, so without a tip file, or with a tip and no
trusted log key, a ledger other than the one expected, or a ledger whose tip could not be dated, was PASS, exit 0, and
the receipt did not name the option (measured on 2026-11-16 with `verifier.py` 0.25.0 and the JS, Go and Java
verifiers). From v0.9 such a ledger is FAIL. The ledger format (§2–§5), its hashes and its vectors do not change.
v0.10 (2026-11-16) adds §18, a closed payment entry profile (`cryptovalid-payment/1`: a random payment identifier, amount,
ISO 4217 currency, a list of beacon values, a record salt, and the parties' IBANs, names and EndToEndId only as salted
commitments, opened by disclosures), and §19, a "not before" bound from the NIST Randomness Beacon 2.0 (chain 2)
carried inside that entry, with the window it gives together with the RFC 3161 token of an evidence pack and the
witnessed checkpoint inside that pack that fixes the entry in one history. Additive:
a new command (`cryptovalid-verify beacon`) and a new module; the ledger verifiers, `auto`, the pack and their receipts do
not change. The ledger format (§2–§5), its hashes and its vectors do not change.
v0.10 also adds to §11 step 8, the TSA certificate's revocation checked against CRLs the caller pins (`crls`, new reasons
`tsa_certificate_revoked`, `tsa_revocation_unknown`), and to §10 the library parameter `tsa_crls`. Additive: without
CRLs the outcome is the outcome of v0.9.
v0.11 (2026-11-18) adds §5 step 0 (a path is opened once without blocking and must be a regular file within the size
bound; §10's listed files and §11's pinned files follow it, and §10 refuses a listed file over the bound before reading
it) and to §11 step 6 the reason `signer_certificate_absent`: a token whose signer certificate is neither
in the token nor pinned was `signature_invalid`, a signature reported as failed that was never evaluated. The status
stays `invalid` (it does not count as a timestamp); the evidence pack with a pin reports it `not_evaluated /
tsa_unresolved` where v0.10 said `contradicted / token_invalid`. v0.11 also writes in §11 step 7 the rule of RFC 2634
§5.4 and RFC 5035 §3 for a signing-certificate attribute that lists more than one ESSCertID (the first identifies the
signer certificate, the ones after it limit the certificates of the path), checked by this format instead of by openssl
`ts -verify`, which asked every ESSCertID to be in the chain it built: a token under a pinned CA that is listed below
the last certificate of the list (sectigo.tsr of spec/vectors/rfc3161 with its CA R41 pinned) was
`not_issued_by_pinned_tsa` and is `verified`; a path through a certificate the list leaves out is refused (OpenSSL
accepted it). Every other token has the outcome of v0.10.
v0.12 (2026-11-18) reads the TSTInfo's `nonce` and `serialNumber` as INTEGERs of either sign (§11 step 3): RFC 3161
§2.4.2 sets no sign on either. Until v0.11 the code refused a negative nonce as `malformed`, stricter than §11 itself,
and §11 asked "not negative" of `serialNumber`, stricter than RFC 3161 (measured on 2026-11-18 with OpenSSL 3.0.22: a
token re-signed here with serialNumber -5 or -2^63, `ts -verify` OK, 0.26.0 `malformed`). Measured on
2026-11-18 on a real DigiCert token (nonce -0x5BDDFD8205AA38EC, `spec/vectors/rfc3161/third_party/`): 0.26.0 said
`invalid / malformed`, OpenSSL `ts -verify` OK; now `verified` under the DigiCert root pinned. A token with a nonce in
non-minimal form is still `malformed`. v0.12 also reads a FIFO given as the ledger (§5 step 0) instead of refusing it,
bounded in size and in idle time: the verdict of v0.10 for `<(cat ledger.jsonl)`, never the hang of v0.10 for a pipe
with no writer. v0.12 also adds to §5 the failure classes of a FAIL receipt (`failure_classes`),
an added member: the verdict, the receipt of a PASS and the other verifiers do not change.
v0.12 also adds §20 (2026-11-19), rules written after a security review of 0.26.0. Not additive where they turn an
accepted input into a refused one; each rule says what changed. Rules 1 and 2 are about outbound URLs (a redirect
judged on the address it reaches; a credential not sent to another origin). Rule 3: the RFC 8785 serializer used for
the formats of others refuses an integer that is not exactly a double (until 0.26.0 rounded: two integers, the same
signed bytes). Rules 4 to 6: the experimental Cedulon reader takes the context of `control` and of an approval only
from inputs a signature binds, reports a repeated ref as `duplicate-ref`, and checks an approval's WebAuthn RP ID and
origin against the caller's or says it did not. Rule 7: the digest-field check answers `grammar`, never an
exception, for a field of nested "@". Rules 8 to 11, the ingest archive: with a pinned key a missing HEAD is a
failure; the writer cuts only a last line without its line feed when it reopens a segment; a segment without a tree
head is read, and failed or named in a warning; member-state codes are two ASCII letters. Rule 12: the MCP server
answers a malformed message with a JSON-RPC error and goes on. The ledger format (§2–§5), its hashes and its vectors do
not change.
v0.13 (2026-11-20) adds §21, eight rules written after the findings of the same review were re-run on the released
0.27.0. Not additive where they turn an accepted input into a refused one. Rule 1: an RFC 9162 inclusion proof longer
than the path of its (index, size) fails. Rule 2: a key written twice in one object of a ledger line read by the
signature verifier, of a JWS header or payload, of a tree head, a HEAD or a receipt file, is refused. Rule 3: an XML document read without `defusedxml` is
refused when it carries a document type declaration anywhere, in any encoding. Rule 4: the experimental Vaara reader
verifies ES256 with a P-256 key only, and an evidence record given for a receipt that binds none is not bound. Rule 5:
an argument of an MCP tool is of the JSON type its input schema declares. Rule 6: a body read from the network is
bounded. Rule 7: the evidence pack checks the digest, the chain, the signatures, the count and the head of a ledger on
the same bytes. Rule 8: `signer.py sign` signs only lines within the entry schema whose `self_hash` it recomputes, and
`signer.py verify` fails a line outside that schema. The ledger format (§2–§5),
its hashes and its vectors do not change.
v0.14 (2026-11-22, cryptovalid-opencore 0.28.0) adds §22, nine rules: six written for the decisions of 2026-11-20, rule 7
on 2026-11-21, rules 8 and 9 on 2026-11-22. Not additive where a rule turns an accepted input into a refused one or
changes a verdict; rule 3 changes what a tree head, a HEAD and a pack manifest are signed over.
v0.15 (2026-11-23, cryptovalid-opencore 0.29.0) adds §23: the list of the checks of `cryptovalid-verify`, printed from the tables the code that runs
them reads (`--list-checks`), and the verification profile (`--profile`), a closed JSON document by which the relying
party adds requirements and cannot remove a check. Additive: without `--profile` the verdict and the exit status are
those of v0.14; the receipt gains the member `profile` (`"default"`) and each layer the member `id`.
v0.15 also adds §24, the SLH-DSA archival anchor `omega-slhdsa-anchor-v2` (FIPS 205), verified by
`cryptovalid_slhdsa.py`, §25, DSSE envelopes carrying in-toto Statements, verified by `cryptovalid_dsse.py`, §26,
the properties a weekly fuzz run holds three readers to, and §27, the GitHub Action. Additive: no existing input
changes verdict.
v0.15 also adds §28, the COSE Receipts of an MMR (vds 3, draft-ietf-scitt-receipts-mmr-profile-00) in the experimental
`cryptovalid_cose_receipts.py`: additive, a receipt with vds 3 was `UNSUPPORTED_VDS` before. And §29, the verification of a
composite ML-DSA signature of RFC 10073 (three ML-DSA-65 algorithms) in the new experimental `cryptovalid_composite.py`:
additive.
v0.16 (2026-11-26, cryptovalid-opencore 0.29.1) adds §32, nine rules: a secret given to a command or to the library does
not appear in what it writes. No verdict on a ledger, a pack, an archive or a receipt changes; what changes is what the
writers accept (a file given as a ledger to `evidence_pack.py build`, an output over a key file, a URL with credentials, a
witness that cosigns with a log's own key) and what their errors repeat.

## 7. Conformance (normative)

The standard is defined by the conformance test vectors in `spec/vectors/`. A verifier conforms iff,
for every vector, it reproduces the vector's `normative` block (verdict, chain integrity, detected
algorithm, entry count, and the sets of failing indices for hash and linkage). See `CONFORMANCE.md`.
Run `python3 conformance.py` (exit 0 = conformant). Independent implementations (Go, Rust, JS, …) claim
conformance the same way and are listed in the conformance table.

## 8. Regulatory profiles (self-updating, provenance-carrying)

A ledger entry MAY declare which EU requirement it supports:
`data.regulatory_ref = "<id>"` where `<id>` is an entry in `spec/regulatory_profiles.json`
(e.g. `MiCA`, `AI-Act-AnnexIII`, `DORA`, `GDPR`). Each profile carries `status`, `effective_utc`,
`source_url` and an `as_of` date.

`refresh_regulatory.py` keeps the profiles HONEST: it re-checks source reachability, stamps
`last_checked_utc`, and FLAGS any entry older than the staleness window for human re-verification
against its PRIMARY source (exit 1 if anything needs review). **Honest scope:** the mapping is
provenance-carrying and self-monitoring, NOT legal advice and NOT a compliance claim; a stale entry is
flagged, never silently trusted — the format never lets outdated regulatory status pass unnoticed.

## 9. Optional Merkle extension (RFC 6962) — efficient inclusion & consistency

For large ledgers, `cryptovalid_merkle.py` builds an **RFC 6962** Merkle tree whose leaf data is the **canonical form of
§3** of each entry — the bytes its `self_hash` is computed over, without `self_hash` and the five attestation fields
(NORMATIVE since v0.4, cryptovalid-opencore 0.21.0; vector `spec/vectors/merkle_leaves.json`). An attestation added after a
tree head (a `tsa_token`, an ML-DSA layer) does not change the root. **Compatibility:** until 0.20.3 a leaf kept
`signature_pq`, `signer_pq` and `tsa_token`; the root of a ledger that carries any of them differs from 0.21.0 on, and a
tree head, checkpoint or receipt computed for such a ledger before 0.21.0 is reproduced by cryptovalid-opencore 0.20.3,
not by later versions (the vector records both roots). The root of a ledger without those fields is unchanged. Giving:

- **inclusion proofs** — verify one entry in `O(log n)` (audit path), no full-chain recompute;
- **consistency proofs** — cryptographic proof that a newer ledger *append-only extends* an older one;
- a **Signed Tree Head** (`{tree_size, root_sha256}`) — the `root_sha256` is the value to submit
  to a **qualified TSP** (eIDAS EU Trusted List) for a *qualified* RFC 3161 timestamp.

This is an **optional, additive** layer: the linear hash-chain (§2, §3) remains the interoperable
core; Merkle proofs are computed on demand and verified by any third party with
`(entry, index, tree_size, audit_path, root)`. Domain separation: `0x00` leaves, `0x01` nodes.

## 10. Evidence pack receipt: admission and states (NORMATIVE since v0.5, cryptovalid-opencore 0.22.0)

`evidence_pack.py verify` (library `evidence_pack.verify_pack`, and `cryptovalid-verify pack`, which copies these fields)
answers on two axes, so that a reader takes one closed field per subject instead of combining booleans. The design is the
one ap2-evidence-pack 1.6.0 uses (its SPEC §6.9, vocabulary `ap2-evidence-pack/states-1`): the same states, the same reason
tokens with the same meaning, the same precedence. It is aligned with draft-krausz-verification-state-03 §3.1, §3.3, §5.4.2
(work in progress); the identifier is ours: `states_vocabulary: "cryptovalid-evidence-pack/states-1"` (immutable: a change
of meaning is a new identifier).

**Admission.** `admission` is `"admitted"` or `"refused"`. A refused pack has `refusal_class` — `format_unsupported`
(`pack_format` absent, not a string, or neither `cryptovalid-evidence-pack/1.1` nor, since §22 rule 3,
`cryptovalid-evidence-pack/1.2`; packs of format 1.0 included), `unknown_member`
(a key outside §2.1's lists: `manifest_unknown_field`), `malformed` (anything else that makes the manifest unreadable as this
format: not readable (not a regular file, §5 step 0, since v0.11), not UTF-8 JSON, a key twice in one object, nested deeper than the bound, larger than the bound, not an
object, `file_digests_sha256` not an object of names inside the pack to strings, `ledgers` not a list of objects naming a file inside the pack, `rfc3161_timestamp` not an object,
`anchored` not a boolean, `tsa` / `tsr_b64` / `note` not strings, `tsr_b64` without `anchored: true`,
`manifest_digest_sha256` / `manifest_signer` / `manifest_signature` not strings, `ledgers[i].entries` not an integer
(a boolean is not one), `ledgers[i].head_self_hash` not a string or null, `ledgers[i].pq_protected` not a boolean or null; since v0.11, a file named in `file_digests_sha256` that is larger
than the bound of §5 step 0 (`input_too_large: file <name> ...`, judged on the open descriptor before any byte is read,
then hashed in blocks: measured on 2026-11-18 with 0.26.0, which read each listed file whole into memory first, a peak
of 17 MB for a 1 MiB file and 515 MB for a 500 MiB one, `resource.getrusage`) or that exists and cannot be opened
(`input_unreadable: file <name> ...`, a permission error: until v0.11 an exception)) — `states: null`, `valid: false`, exit 1, and the reason text in `error` (the field this receipt has carried since
0.9). The order of the checks is the order of this list's classes as the code meets them: size, read, depth, JSON, object,
format, unknown keys, shapes and types (the format first, as in ap2-evidence-pack 1.6.0: a later revision that adds a
member is `format_unsupported`, not `unknown_member`). The other fields of a refused receipt keep their fail values (`files_ok`,
`manifest_ok`, `ledgers_ok` false): a reader of those fields alone sees a failure, and must read `admission` to tell a
refusal from tampering.

**States** (admitted only). `states` is a closed object with exactly three subjects — the pack has no holder binding and no
issuer chain, so ap2's `holder_binding` and `issuer_identity` are absent, not `not_present`. Each subject is
`{"state": S, "reasons": [R, ...], "detail"?: str}` with S ∈ `verified` | `contradicted` | `indeterminate` |
`not_evaluated`; `indeterminate` is reserved and no pack produces it. A subject is computed from its elements in order;
its state is the state of the element of highest rank: `contradicted` > `not_evaluated` with `instrument_failure` > other
`not_evaluated` > `verified` (`verified` only when every element is); `reasons` lists one reason per element that is not
`verified`, in element order.

| subject | elements, in order | verified | contradicted | not_evaluated |
|---|---|---|---|---|
| `sealed_content` | each name of `file_digests_sha256`; the manifest's own digest; for each `ledgers[i]`: the file inside the pack, its hash chain (§5 steps 1–4), its entry count and head equal to the manifest's | every element holds | `digest_mismatch` (a file absent, outside the pack, not a regular file (§5 step 0: opened once without blocking, so a FIFO never blocks) or of another digest; the manifest digest; no file listed at all), `artifact_invalid` (a ledger that is not a file inside the pack, or whose chain fails), `binding_mismatch` (entry count or head differ from the manifest: truncation or extension) | — |
| `producer_signature` | the manifest signature; then, for each ledger whose entries carry a signature field (any entry, §5 step 5), its signature layer, then its post-quantum layer when the manifest claims one (`pq_protected: true`) | every element verifies under a key the CALLER pinned (`manifest_signer_hex`; `signer_pubkey_hex` and, for the post-quantum layer, `pq_pubkey_b64`) | `signature_invalid` (a signature that was checked and fails: broken, malformed, a key or R of small or mixed order, an entry of a signed ledger unsigned; a post-quantum layer the manifest claims and the file does not carry, carries partly, or carries broken) | `not_present` (no manifest signature, no signed ledger), `self_asserted` (it verifies under the key it carries; nobody pinned one: draft-krausz §5.4.2(a)), `key_unresolved` (a pin was given and the signer is another key), `backend_missing` (`cryptography`, or ML-DSA-65 in it, is not available here) |
| `time_anchor` | the `rfc3161_timestamp` block | only when the caller pins TSA certificates (v0.8, below): §11 gives `verified` for the token, the manifest digest and the pinned certificates. Without a pin never: this verifier does not check the TSA's signature (a self-issued token binds as well as a real one) | `token_missing` (`anchored: true` and no `tsr_b64`), `binding_mismatch` (an imprint was read and is another digest; with a pin also §11's `imprint_mismatch`), `token_invalid` (otherwise: not a TimeStampResp, status not granted, no imprint read; with a pin, any other refusal of §11 steps 1–6, its reason in `detail`: a signature that does not verify, a token that is not DER as §11 reads it, a hash algorithm outside §11's list) | `not_present` (no block, or `anchored: false`), `tsa_not_checked` (no pin; status granted, imprint = the manifest digest), `tsa_unresolved` (a pin was given; §11 steps 1–6 pass and step 7 refuses: the token is not established under the pinned certificates; since v0.11 also §11's `signer_certificate_absent`), `instrument_failure` (openssl absent, with or without a pin; openssl that cannot be started, gives no answer in time, is ended by a signal, or no temporary file: exit 74, below) |

**A pinned TSA (v0.8).** `verify_pack(..., tsa_certs=[...])` and `evidence_pack.py verify DIR --tsa-cert PEM` (repeatable:
the TSA certificate or a CA above it, as in §11) check the token with §11, `verify_token(token, manifest digest, "sha256",
tsa_certs)`, after the checks of the row above and only when they leave `tsa_not_checked`; every other outcome of the
row stays as it is. Each pinned item, a PEM block or DER bytes, MUST have the shape of an X.509 certificate (RFC 5280
§4.1: a SEQUENCE of two SEQUENCEs and a BIT STRING, filling the item); a path that is not a readable regular file, or an
item of another shape, is refused before the pack is read (`ValueError`; exit 2 for `--tsa-cert`): a pin the
verifier cannot load would otherwise make every token look broken. The outcome of §11 maps to the state as ETSI EN 319 102-1 V1.4.1 (2024-06) §5.1.3, Table 6, maps a
signature validation: a token whose cryptographic checks fail or that cannot be processed (TOTAL-FAILED: SIG_CRYPTO_FAILURE,
HASH_FAILURE, FORMAT_FAILURE) is `contradicted`, as a token over another digest already is (§11, "What a refusal shows");
a token for which no chain to the pinned certificates is found
(INDETERMINATE: NO_CERTIFICATE_CHAIN_FOUND, "no certificate chain has been found for the identified signing
certificate") is `not_evaluated / tsa_unresolved`, as `key_unresolved` for the producer: a pin for another TSA does not
make the pack false (until 0.27.0; replaced by §22 rule 7, v0.14: the state stays `tsa_unresolved`, the pack is not
valid). The receipt's `rfc3161` object gains `tsa_check` = `{status, reason, detail, gen_time,
signer_sha256, sha1_signature_legacy}` of §11 whenever §11 ran (`sha1_signature_legacy` since v0.10, §11 step 7); a receipt computed with a pin names `states_vocabulary:
"cryptovalid-evidence-pack/states-2"` (states-1 with `verified` and `tsa_unresolved` reachable on `time_anchor` and the
wider `token_invalid` above); a receipt without a pin keeps `states-1` and does not change. ap2-evidence-pack 1.7.x
(`states-1` of its §6.9) answers `not_evaluated / tsa_invalid` for "the TSA signature does not verify under the
certificate given", one token for the two cases that ETSI separates and this format separates: a deliberate divergence.

**Disposition.** `valid` is computed as before v0.5 plus the changes listed in §6 (v0.5); it is not derived from
`states`. Two rules hold between them (proved on the generative bench of 0.22.0, receipt fields only): a `valid` pack is
admitted and has no `contradicted` subject; an admitted pack that is not valid and has no `contradicted` subject has a
`producer_signature` reason `key_unresolved` (a ledger signed by a key other than the one pinned) or `backend_missing` (a
manifest signature, an Ed25519 layer, or a pinned post-quantum layer that cannot be checked here). The converse does not
hold, by design: a manifest signed by a key other than `manifest_signer_hex` (library only; it pins the post-quantum keys the
manifest records, as since 0.12.0) is `key_unresolved` and leaves `valid` as it was (until 0.27.0: since §22 rule 4,
v0.14, a pinned element that is not `verified` makes the pack not valid), and a post-quantum layer that nobody
pinned and that cannot be checked here is `backend_missing` with the pack valid. The post-quantum layer of a ledger is an
element only when the manifest claims it (`pq_protected: true`), a key pins it, or the file carries it broken; otherwise
it is reported in `ledgers[i].pq_protected` as before and is not part of what the pack asserts.

**A check that cannot run here.** openssl present but not startable (fork refused, no descriptor), not answering within
the timeout, ended by a signal (draft-krausz-verification-state-03 §3.1, "a crashed dependency"; as ap2-evidence-pack 1.6.0
§6.10), or no temporary file for the token: the receipt is written WHOLE with `time_anchor: not_evaluated / instrument_failure` (its `detail` names the
cause) and every other subject evaluated, `check not run here: <reason>` on stderr, exit 74; the library raises
`verifier.CheckNotRun` carrying that receipt in `receipt`. A run that cannot write its receipt exits 74 with
`receipt not written: <reason>` and no complete JSON on stdout: on 74, a complete JSON receipt means a check did not run,
none (or a cut one) means the write failed. openssl absent is `instrument_failure` too, with the exit `valid` gives (as
before v0.5: an absent tool is not a failed run). An openssl that exits with a code and no signal has answered: a token
it does not accept is `token_invalid`. The token check of §11 (v0.6) follows the same rule: a tool ended by a signal is a
check not run. The older functions `cryptovalid_tsa.verify_cms_signature` and `verify_with_openssl`, kept for callers
outside this repository, keep their rule of 0.21.0: a tool ended by a signal there is a token not verified. `verify_with_openssl` reads a TimeStampResp, not a
token, and validates the chain against the system CA store at the time of the call, not at genTime (its docstring
states the rule since v0.7): its answer for the same reply changes when a certificate expires or the store changes.

**What no state can say.** The RFC 3161 block and the manifest signature lie outside the manifest digest: a copy with the
block removed has the states of a pack that never had one (`time_anchor: not_present`), and a copy with the manifest
signature removed those of an unsigned pack. Only a pinned manifest signer or a hash of the whole folder tells them apart;
since §22 rule 7 (v0.14) pinned TSA certificates also make the copy without the block not valid (the states are the same).

## 11. RFC 3161 token check (NORMATIVE since v0.6, 2026-11-13)

One function checks a token's structure, imprint, signature and anchor in this repository:
`cryptovalid_tsa.verify_token(token_der, digest, hash_alg=None, tsa_certs=None, crls=None)`. `evidence_pack.py verify` reads a
pack's token for its status and imprint only (§10, `tsa_not_checked`), and with this function when its caller pins TSA
certificates (§10, v0.8); the pack's report (`cryptovalid_report.py`) shows
the outcome of this function for that token, with no TSA pinned. Its input is a TimeStampToken (a CMS ContentInfo, RFC 3161 §2.4.2) or a whole TimeStampResp, whose
status MUST then be granted (0) or grantedWithMods (1) and whose token is the one checked. The steps, in order; the
first that fails gives the outcome:

1. **Structure, closed.** DER (RFC 5652 §1 asks DER for the signed attributes) at every level this function reads —
   ContentInfo, SignedData, encapContentInfo, the TSTInfo and its messageImprint, the SignerInfo's elements: definite
   lengths in the shortest form, no high tag numbers, no byte after the outer element, INTEGER and OBJECT IDENTIFIER in
   minimal form. The certificates, the crls and the inside of the SignerInfo's elements are read by openssl, which
   accepts BER there. ContentInfo = `{contentType id-signedData (1.2.840.113549.1.7.2), [0] SignedData}`.
   SignedData = `{version 3, digestAlgorithms SET, encapContentInfo, [0] certificates OPTIONAL, [1] crls OPTIONAL,
   signerInfos SET}` in this order, nothing else; exactly one SignerInfo (RFC 3161 §2.4.2: no signature other than the
   TSA's) = `{version, sid, digestAlgorithm, signedAttrs, signatureAlgorithm, signature[, unsignedAttrs]}` (RFC 5652
   §5.3: signedAttrs present, the content is not id-data). encapContentInfo = `{eContentType, [0] eContent}`, the eContent present as one primitive OCTET STRING.
2. **Content type.** eContentType MUST be id-ct-TSTInfo (1.2.840.113549.1.9.16.1.4); anything else is
   `econtent_type_not_tstinfo`.
3. **TSTInfo, closed.** `{version 1, policy OID, messageImprint {hashAlgorithm {OID, NULL or absent}, hashedMessage
   OCTET STRING}, serialNumber INTEGER (of either sign since v0.12: RFC 3161 §2.4.2 writes `serialNumber INTEGER` and
   sets no sign; until v0.11 "not negative"), genTime GeneralizedTime}` then, each at most once and in this
   order, `accuracy` (SEQUENCE), `ordering` (BOOLEAN, DER: 00 or FF), `nonce` (INTEGER of either sign, v0.12: RFC 3161
   §2.4.2 writes `nonce INTEGER OPTIONAL` and sets no sign), `tsa` ([0]), `extensions`
   ([1], Extensions of RFC 5280 §4.1); any other element, a repeated one or one out of order, and any extension marked
   critical (none is understood here), is `tstinfo_unknown_element`. genTime is
   `YYYYMMDDhhmmss[.f+]Z` (RFC 3161 §2.4.2: UTC, no trailing zero in the fraction) and a real calendar time.
4. **Hash algorithm, closed list.** sha256, sha384, sha512, sha3-256, sha3-384, sha3-512 (NIST OIDs
   2.16.840.1.101.3.4.2.{1,2,3,8,9,10}); any other (SHA-1 included) is `hash_algorithm_not_allowed`. hashedMessage MUST
   have the algorithm's length. The SignerInfo's digestAlgorithm (the hash under the signed attributes and the
   signature) is held to the same list (`hash_algorithm_not_allowed`). When the caller names the algorithm it stamped
   with (`hash_alg`), another one is `hash_algorithm_mismatch`.
5. **Imprint.** `messageImprint.hashedMessage` MUST equal the expected digest byte for byte (`imprint_mismatch`). It is
   read from the parsed TSTInfo, never searched for in the bytes.
6. **Signature.** openssl `cms -verify -noverify` over the token: the CMS signature and the messageDigest signed attribute
   against the eContent, with the certificate the SignerInfo names, looked up in the token and among the pinned
   certificates (a token requested with certReq FALSE carries none, RFC 3161 §2.4.1) (`signature_invalid` if not). The signer
   certificate's SHA-256 is returned (`signer_sha256`).
   **Signer certificate absent (v0.11, 2026-11-18).** When openssl refuses and the certificate the SignerInfo's `sid`
   names (RFC 5652 §5.3: issuerAndSerialNumber, the issuer compared as in step 7 and the serial as an integer; or
   subjectKeyIdentifier, against the certificate's subjectKeyIdentifier extension, as OpenSSL looks it up: measured on
   2026-11-18 with OpenSSL 3.0.22, a certificate without the extension cannot sign with `cms -sign -keyid`, "certificate
   has no keyid") is neither among the token's certificates
   nor among the pinned ones, and openssl stopped at the lookup of the signer certificate ("signer certificate not
   found"), the signature was not evaluated, and the reason is `signer_certificate_absent`, not `signature_invalid`.
   The absence is never presumed: a certificate, a pin, the `sid`, a Name or a certificates field that is not read here
   (BER, another CertificateChoices, a string that does not decode) keeps `signature_invalid`, and so does a token that
   openssl cannot parse (ETSI EN 319 102-1 V1.4.1 §5.3.4: the format check, step 1, FORMAT_FAILURE, comes before the
   identification of the signing certificate, step 2). Until v0.11 such a token was
   `signature_invalid`: measured on 2026-11-18 with the published wheel 0.26.0 on the RFC 3161 token of a sigstore bundle
   (stacklok/toolhive 0.66.0, its `[0] certificates` present and empty), `verified` with the sigstore TSA chain pinned and
   `invalid / signature_invalid` (openssl: "signer certificate not found") without it; and on freetsa.tsr of
   spec/vectors/rfc3161 with its certificates removed (as certReq FALSE), `invalid / signature_invalid` unpinned and with
   digicert's certificate pinned, `verified` with freetsa's. A signature never evaluated was reported as one that does
   not verify. ETSI EN 319 102-1 V1.4.1 (2024-06) §5.2.3.3: when the signing certificate cannot be identified the output
   is INDETERMINATE / NO_SIGNING_CERTIFICATE_FOUND.
7. **Anchor.** With `tsa_certs` (certificates the verifier pins: the TSA certificate or a CA above it), the token is
   checked against them. How depends on how the SignerInfo names its signer (`sid`, RFC 5652 §5.3: both forms are
   allowed, the SignedData version is 3 in both):
   - **issuerAndSerialNumber**, each signing-certificate attribute listing one ESSCertID: openssl `ts -verify` checks
     the token against them: signer certificate, ESS signing-certificate attribute, extended key usage timeStamping, the
     `tsa` field against the signer's name, chain to a pinned certificate (`-partial_chain`; the pinned certificates are
     also given as `-untrusted`), validity at genTime (`-attime`); it passes on exit 0 with `Verification: OK` on stdout.
   - **issuerAndSerialNumber, a signing-certificate attribute listing more than one ESSCertID** (v0.11, 2026-11-18): the
     checks of the next form, (a) to (c), on the signer certificate of step 6. OpenSSL's `ts -verify` asks every
     ESSCertID of the list to identify a certificate of the chain it built, the first at the signer's place and the others
     elsewhere in it (`OSSL_ESS_check_signing_certs` and its `find`, the same in the OpenSSL 3.0 branch and in master,
     read on 2026-11-18); RFC 2634 §5.4 and RFC 5035 §3 do not ask that (below). With a pinned CA below the last
     certificate listed, `-partial_chain` ends the chain at the pin and the token was refused ("ess cert id not found").
     Measured on 2026-11-18 with OpenSSL 3.0.22 and cryptovalid 0.26.0: sectigo.tsr of spec/vectors/rfc3161, whose
     signingCertificate lists its signer (Sectigo Public Time Stamping Signer R37), the CA R41 and the Root R46, was
     `verified` with the signer or R46 pinned and `not_issued_by_pinned_tsa` with R41 pinned (alone or with others),
     although `openssl verify -partial_chain` establishes the signer under R41; never `contradicted` (in a pack,
     `tsa_unresolved`), but the reason was false. Which route a token takes is read from its signed attributes; one that
     cannot be read there takes `ts -verify`, as until v0.11.
   - **subjectKeyIdentifier** (since v0.10): openssl's TS code reads the token as PKCS #7, whose SignerInfo has only
     issuerAndSerialNumber, and refuses such a token with an ASN.1 error. Measured on 2026-11-16 with OpenSSL 3.0.22:
     the TSTInfo of a valid token re-signed by `openssl cms -sign -keyid -cades` with the same TSA key and certificate
     verifies at step 6 and was `not_issued_by_pinned_tsa` here until v0.10 (in a pack, `tsa_unresolved`): a valid token
     reported as not established. The same checks are made one by one on the signer certificate of step 6, and two
     names are compared as OpenSSL compares them (`X509_NAME_cmp`, its reading of RFC 5280 §7.1 name matching): each
     attribute value of a string type (UTF8String, PrintableString, IA5String, VisibleString, T61String, BMPString,
     UniversalString) is turned into UTF-8, its leading and trailing white space removed, each run of white space made
     one space and its ASCII letters lowercased; values of other types are compared as encoded; the names are equal when
     they have the same RDNs in the same order, each RDN the same attributes in any order. Until this correction (first
     wording of v0.10) the names were compared byte for byte: measured on 2026-11-17, a `tsa` field that differs from
     the signer's subject only in letter case was `verified` in the issuerAndSerialNumber form and
     `not_issued_by_pinned_tsa` in this one. (a) a signed
     attribute signingCertificate (RFC 2634 §5.4, SHA-1) or signingCertificateV2 (RFC 5035 §3, its `hashAlgorithm`,
     SHA-256 when absent; RFC 3161 §2.4.2 as updated by RFC 5816 §2.2.1 asks the TSA for the identifier of its
     certificate in one of them, and allows both), each one present checked and at least one present. The rule (RFC
     2634 §5.4, rewritten by RFC 5035 as §5.4.1 for ESSCertIDv2 and §5.4.2 for ESSCertID with the same words; texts read
     on rfc-editor.org on 2026-11-18, neither obsoleted): "The first certificate identified in the sequence of
     certificate identifiers MUST be the certificate used to verify the signature. [...] If the hash of the certificate
     does not match the certificate used to verify the signature, the signature MUST be considered invalid"; "If more
     than one certificate is present in the sequence of ESSCertIDs, the certificates after the first one limit the set
     of certificates that are used during validation. Certificates can be either attribute certificates (limiting
     authorizations) or public key certificates (limiting path validation)"; "If only the signing certificate is present
     in the sequence, there are no restrictions on the set of certificates used in validating the signature". For a
     public key certificate the issuerSerial's issuer "MUST contain only the issuer name from the certificate encoded in
     the directoryName choice of GeneralNames" (RFC 5035 §4). Applied here: the first
     ESSCertID's `certHash` is the hash of the signer certificate, and its `issuerSerial` (SHOULD in the RFCs, not
     required here), when present, is exactly one directoryName equal (as above) to the certificate's issuer and a
     serial number equal to the certificate's (compared as integers); otherwise the token is refused (so is an empty
     list). The RFCs do not
     say how the later ESSCertIDs limit the path; this format's reading (v0.11): every ESSCertID, the later ones too, is
     `{certHash, issuerSerial OPTIONAL}` (ESSCertIDv2 `{hashAlgorithm OPTIONAL, certHash, issuerSerial OPTIONAL}`, the
     algorithm one of SHA-1, SHA-224, SHA-256, SHA-384, SHA-512, SHA3-256, SHA3-384, SHA3-512 with absent or NULL
     parameters), `certHash` of that algorithm's length, `issuerSerial` of that same shape, and no two with the same
     algorithm and `certHash` (the signer listed again, or any certificate listed twice: OpenSSL refuses the first case
     too, "ess cert id wrong order"), else refused; a later
     ESSCertID whose hash is the hash of a certificate of the token or a pinned one and whose `issuerSerial` does not
     name that certificate is refused; with more than one ESSCertID, the certificates of the token that (c) may use to
     build the path are the ones some later ESSCertID identifies by its hash (with both attributes listing more than one,
     the ones both identify); the pinned certificates are the trust anchors the verifier chose and stay usable; a later
     ESSCertID that identifies no certificate here (an attribute certificate, a certificate the token does not carry)
     adds no certificate to the path and is not an error. With one ESSCertID the path is not limited. Until v0.11 this form
     refused more than one ESSCertID ("not evaluated here"); OpenSSL also accepts a path through a certificate the list
     leaves out (it asks the opposite inclusion), which this format refuses. (b) the TSTInfo `tsa` field, when present:
     a directoryName equal (as above) to the signer's subject, or one of the names of its subjectAltName (a
     directoryName compared as above, another name of the same type with the same bytes, as `GENERAL_NAME_cmp`); (c)
     openssl `verify -purpose timestampsign -partial_chain -attime <genTime> -CAfile <pinned> -no-CApath -no-CAstore
     -untrusted <pinned and the token's certificates (a) allows>` over the signer certificate, exit 0: the extended key
     usage timeStamping (OpenSSL's purpose: present, critical, the only one), the chain to a pinned certificate and the
     validity at genTime, with the same OpenSSL chain building as `ts -verify`.
     Closed shapes (v0.10, measured on 2026-11-17 against the generative bench of omega-cra-evol's port of this step,
     which found them): exactly one SignerInfo (step 1 asks it of the token; this step asks it again of what it reads);
     every signed attribute is `Attribute ::= SEQUENCE { attrType OID, attrValues SET }` and nothing else; a
     SigningCertificate or SigningCertificateV2 is `{certs SEQUENCE OF ESSCertID(v2), policies OPTIONAL}`, `policies` a
     SEQUENCE OF PolicyInformation, each a SEQUENCE that starts with an OID (RFC 2634 §5.4.1, RFC 5035 §3); anything else
     is `not_issued_by_pinned_tsa`. Until this correction the attribute's tag, elements after attrValues, the tag of
     attrValues and the elements after `certs` were not read: 9 changes inside the ESS attribute and 8 attributes
     retagged or extended were accepted by this step alone (the CMS signature of step 6 covers the signed attributes, so
     no token was accepted by §11 for it). An openssl whose `verify` does not know an option this step gives (before
     OpenSSL 3.0, `-no-CAstore`: it answers "Unknown option") is a check not run here (`CheckNotRun`, exit 74), not a
     refusal: until this correction it was `not_issued_by_pinned_tsa`.
   Failure is `not_issued_by_pinned_tsa`. Without `tsa_certs` there is no anchor (step 8). In both forms, a pinned leaf
   (the TSA certificate itself) does not end the chain: OpenSSL continues it with the certificates the token carries and
   checks the CA above the leaf too (a CA expired at genTime, not a CA, or without keyCertSign makes the token refused),
   measured on 2026-11-16 on generated tokens by the extraction of this profile into a separate repository; a verifier
   that stops at the pinned leaf accepts tokens this one refuses.
   **SHA-1, legacy verification (v0.10).** A certificate of the chain signed with SHA-1 does not change the outcome
   (OpenSSL 3.0.22 accepts it at its default security level, in both forms; measured on 2026-11-17). NIST SP 800-131A
   Rev. 2 (March 2019, §9 Table 8; still in force on 2026-11-17: Rev. 3 is an initial public draft of October 2024)
   disallows SHA-1 for generating digital signatures and allows it for verifying them as legacy use. The outcome
   reports it: `sha1_signature_legacy`, a closed member, `null` unless step 7 passed, then `true` or `false`. It is
   `true` when one of these certificates is signed with SHA-1 (sha1WithRSAEncryption 1.2.840.113549.1.1.5, its OIW form
   1.3.14.3.2.29, ecdsa-with-SHA1 1.2.840.10045.4.1, dsa-with-sha1 1.2.840.10040.4.3 and its OIW form 1.3.14.3.2.27,
   RSASSA-PSS 1.2.840.113549.1.1.10 whose hashAlgorithm is SHA-1 or absent, RFC 4055 §3.1): the signer certificate,
   then, again and again, every pinned certificate or certificate of the token whose subject equals (as above) the
   issuer of a certificate already reached, a self-issued certificate (subject equal to issuer) excepted and not
   followed further, since OpenSSL does not check the signature of a trust anchor on itself. This path is read by names
   and not by the chain OpenSSL builds: when two certificates have the name of the issuer, both are read, and the
   flag can say `true` for a chain that OpenSSL built through the other one (it reports more, never less). A pinned
   certificate or a certificate of the token that this reader cannot read (signatureAlgorithm, issuer, subject) makes
   the member `null` even after step 7 passed: the path is then not known, and nothing is read as absent. The
   token's own signature cannot use SHA-1 here: step 4 refuses it.

Outcome `status`, a closed set:

| status | when | counts as a timestamp |
|---|---|---|
| `verified` | steps 1–7 pass with pinned certificates | yes |
| `signature_only` | steps 1–6 pass, nothing pinned: "signature valid with the certificate contained in the token, chain not established" | no |
| `invalid` | a step fails; `reason` names it (`malformed`, `not_signed_data`, `response_not_granted`, `econtent_type_not_tstinfo`, `tstinfo_unknown_element`, `hash_algorithm_not_allowed`, `hash_algorithm_mismatch`, `imprint_mismatch`, `signature_invalid`, `signer_certificate_absent` (v0.11), `not_issued_by_pinned_tsa`; with `crls`, v0.10: `tsa_certificate_revoked`, `tsa_revocation_unknown`), `detail` says where | no |
| `not_evaluated` | steps 1–5 pass and openssl is absent; or, with `crls` (v0.10), `cryptography` is absent (`crl_backend_missing`) | no |

openssl present that cannot start, does not answer in time or is ended by a signal is a check not run here
(`CheckNotRun`, exit 74 in a command), as in §10. The outcome carries the parsed `tst_info` (policy, hash algorithm,
hashed message, serial number, `gen_time` as ISO 8601 UTC, nonce) whenever steps 1–4 pass.

**What a refusal shows (v0.8).** ETSI EN 319 102-1 V1.4.1 (2024-06) validates a time-stamp token as a signature (§5.4)
and names the outcomes in §5.1.3, Table 6. A refusal at steps 1–4 or 6 shows that the token is not a valid signed
timestamp: TOTAL-FAILED (FORMAT_FAILURE for a token that cannot be processed; SIG_CRYPTO_FAILURE for the signature;
HASH_FAILURE for the messageDigest attribute), except `signer_certificate_absent` (v0.11): the signature was not
evaluated, INDETERMINATE / NO_SIGNING_CERTIFICATE_FOUND (§5.2.3.3), read as step 7's refusal is (the evidence pack
reports it `not_evaluated / tsa_unresolved`, §10; the ingest's verify `tsa_token_signer_certificate_absent`; the report
shows the signature as not checked; `eidas_ledger_check.py` counts it among the invalid tokens, as it counts step 7).
The status stays `invalid`: such a token does not count as a timestamp. A refusal at step 5 shows that the token is not a timestamp of the digest
the caller expects; ETSI answers a content time-stamp over other data INDETERMINATE / SIG_CONSTRAINTS_FAILURE
(§5.2.8.4.2.5), and the callers of this repository that hold a claim of that digest (the pack's `binding_mismatch`, §10,
since v0.5) treat it as a contradiction of the claim: a deliberate difference. A refusal at step 7,
`not_issued_by_pinned_tsa`, shows neither: the token was not established under the certificates pinned. The case step 7
exists for, a token of another TSA, is INDETERMINATE / NO_CERTIFICATE_CHAIN_FOUND ("no certificate chain has been found
for the identified signing certificate"). Step 7 gives one refusal for all its checks and does not tell that case from
the others (a certificate without the timeStamping usage, outside its validity at genTime, a signing-certificate
attribute that does not match); this format reads them all as not established, none as false. The status stays `invalid` for all of them, as since v0.6: it answers "does this
count as a timestamp here", and none counts. A caller that reports what the evidence shows
reads the reason: the evidence pack (§10) reports step 7 as `not_evaluated / tsa_unresolved`. Not aligned in v0.8, and
named here: the ingest's verify still reports step 7 as a failure (`tsa_token_not_issued_by_pinned_tsa`) and
`eidas_ledger_check.py` counts it among the invalid tokens.

**LOTL.** A token is qualified only through its signer: `cryptovalid_lotl.qualification` takes the certificate that
verified the signature (step 6) and looks up that one certificate in the trusted lists; a certificate the token merely
carries does not count (until v0.5 any of them did). In `cryptovalid_ingest verify --lotl` a token whose signer is a
QTST certificate counts as a timestamp even without `--tsa-cert`: the trusted list is the anchor. The trusted-list status
is the status now, not at genTime (unchanged).

**The qualified statement (v0.10).** Commission Implementing Regulation (EU) 2025/1929 (OJ L, 30.9.2025; in force since
2025-10-20; read on CELLAR on 2026-11-17, which lists no act amending it) sets in its Annex the reference standards for
qualified electronic time stamps and adapts ETSI EN 319 422 V1.1.1 (2016-03) clause 9.1: "If a time-stamp token is
declared by the TSA to be a qualified electronic time stamp in accordance with Regulation (EU) No 910/2014, it shall
contain one instance of the qcStatements extension in the time stamp token extension field with the syntax as defined
in IETF RFC 3739, clause 3.2.6. The qcStatements extension shall contain one instance of the statement
'esi4-qtstStatement-1' as defined in Annex B. The extension qcStatements shall not be marked as critical." (EN 319 422
itself said "should"; its Annex B: `id-etsi-tsts-EuQCompliance` = 0.4.0.19422.1.1.) Since v0.10
`cryptovalid_lotl.qualification` says `qualified` only when both hold: the signer is a granted QTST certificate (as
above), and the TSTInfo `extensions` (§11 step 3) carry exactly one extension `id-pe-qcStatements` (1.3.6.1.5.5.7.1.3,
RFC 3739 §3.2.6) whose value is DER `QCStatements` (SEQUENCE OF `QCStatement` {`statementId` OID, `statementInfo`
OPTIONAL}) holding exactly one statement 0.4.0.19422.1.1, without `statementInfo` (Annex B gives it none); other
statements beside it are allowed. A critical one never gets here: step 3 refuses a critical TSTInfo extension. For a
signer that is a granted QTST certificate, otherwise: `not_qualified` with a closed reason, `qualified_statement_missing`
(no qcStatements extension, or one without that statement) or `qualified_statement_malformed` (two qcStatements
extensions, a value that is not that DER, the statement twice or with `statementInfo`, a token whose TSTInfo this step
cannot read). A token that carries the statement while its signer is not in the lists stays `not_qualified` without a
reason: the statement is the TSA's claim, the list is the check. Until v0.10 the statement was not read, and a token of
a QTST service without it was `qualified`. Measured on 2026-11-17 on tokens requested that day
(`spec/vectors/rfc3161/`): those of `tsa.belgium.be/connect`, `tsa.izenpe.com` and `tss.accv.es:8318/tsa` carry the
statement as above; the one of `timestamp.sectigo.com/qualified` carries it in an Extension that writes `critical`
FALSE, a DEFAULT value DER leaves out, so step 1 refuses that token as `malformed` (RFC 3161 §2.4.2: "The eContent
SHALL be the DER-encoded value of TSTInfo"; a verdict this version does not change, and OpenSSL reads the token); the
tokens of 2026-11-13 (freetsa, DigiCert, Sectigo, GlobalSign) carry no statement. Whether those signers are granted QTST
services is read from a trusted list the caller gives, not assumed here.

**Files the caller pins (v0.11).** A path given in `tsa_certs` or `crls` is read as §5 step 0 says: opened once without
blocking and judged on the open descriptor, a regular file of at most 64 MiB, else a ValueError naming it (exit 2 in a
command). Until v0.11 the path was checked with `os.stat` and then opened: a FIFO put in its place between the two
blocked the program (measured on 2026-11-18 by replaying the window, `timeout 5`, exit 124; opening first and
checking after blocks too, since the open itself waits for a writer).

**Revocation, with CRLs the caller pins (v0.10).** `verify_token(..., crls=[...])` (paths or bytes, PEM or DER, each
one X.509 CRL) adds step 8 after step 7, and only when steps 1–7 gave `verified`. Measured on 2026-11-16 (Athena's
bench, re-measured in `test_tsa_revocation_20261116.py`): without it, a token issued by a TSA certificate after the
certificate was revoked for key compromise is `verified`; `openssl ts -verify -crl_check` with the CRL refuses it.

8. **Revocation.** The signer certificate (step 6) is taken from the token or the pinned certificates. A pinned CRL
   applies when its issuer is the signer certificate's issuer and its signature verifies under a pinned certificate of
   that name. No applicable CRL, or two that disagree, is `invalid` / `tsa_revocation_unknown` (the caller asked for a
   revocation check that cannot be made). Not listed: `verified`, with `revocation` = `{"status": "not_revoked",
   "crl_this_update"}`. Listed, after RFC 3161 §4 item 1: with the reason unspecified, affiliationChanged, superseded or
   cessationOfOperation (RFC 5280 §5.3.1), a token whose genTime is before the revocation date stays `verified`
   (`revocation.status` `revoked_after_gen_time`) and one at or after it is `tsa_certificate_revoked`; without a reason
   code ("all the tokens that have been signed with the corresponding key SHALL be considered as invalid"), with
   keyCompromise, cACompromise, aACompromise or any other reason, no token of that certificate is valid, whatever its
   genTime: `invalid` / `tsa_certificate_revoked`; certificateHold and removeFromCRL are `tsa_revocation_unknown`. A
   pinned CRL that carries an extension other than cRLNumber, authorityKeyIdentifier, authorityInfoAccess and
   freshestCRL (a delta CRL, an issuing distribution point), or an entry extension other than reasonCode and
   invalidityDate, is not processed here and gives `tsa_revocation_unknown` (RFC 5280 §5.2, §6.3.3: such a CRL may not
   cover every certificate and reason). When the latest applicable CRL was issued (thisUpdate) before the token's
   genTime, the CRLs cannot show that the certificate was not revoked at genTime: the outcome is
   `tsa_revocation_unknown` (whatever they list or omit).
   `cryptography` absent: `not_evaluated`, reason `crl_backend_missing`.

`crls` without `tsa_certs`, or a pinned item that is not one CRL, is a `ValueError` (exit 2 in a command). The CRL is
the caller's: this function does not fetch one and does not judge whether it is recent enough (its
`thisUpdate` is returned). Without `crls` nothing changes and the outcome has no `revocation` member: revocation is not
checked, and a caller that reports to a person says so (the beacon window of §19 writes `tsa_revocation:
"not_checked"`). `evidence_pack.verify_pack(..., tsa_crls=[...])` passes them to this function (library only; the
command line of the pack is unchanged); a `tsa_certificate_revoked` or `tsa_revocation_unknown` there is `contradicted /
token_invalid`, as the other refusals of §11 after step 5.

**Not checked here.** Revocation of the TSA certificate without `crls` (no CRL or OCSP is fetched); the TSA's `accuracy` against `ts`;
whether genTime is consistent with `ts` (§5 step 6: genTime is returned for the caller to compare); the content-type
signed attribute against eContentType (RFC 5652 §11.1; openssl does not compare them). Without `tsa_certs` the ESS
signing-certificate attribute, the extended key usage, the `tsa` field and the content of `accuracy` are not checked
(they are part of step 7).

Vectors: `spec/vectors/rfc3161/` — tokens of public TSAs requested on 2026-11-13 over one digest, with their source and
time, and negative tokens (a CMS blob whose content is the digest's OCTET STRING, a token for another digest, a token whose
content is not a TSTInfo, a token with its signature altered); `manifest.json` gives the expected outcome of each.

## 12. What `cryptovalid-verify auto` recognises (NORMATIVE since v0.7)

`auto` routes a path to one verifier of the list below, or refuses it with the reason; it never guesses. The list is
closed: anything else is "format not recognised" (`kind: "auto"`, one `auto-detect` layer with status FAIL whose detail
starts `format not recognised:` and names the reason; exit 1).

| Path | Recognised as | Verifier |
|---|---|---|
| directory holding `MANIFEST.json` | evidence pack | `pack` (§10) |
| directory holding an entry whose name matches `*.head.json` or `*-*.jsonl` (shell-style match: a name that starts with a dot does not count) | ingest archive | `archive` |
| regular file whose whole content is one JSON object with a string `evidence_format` that starts with `ap2-evidence` | AP2 evidence | `ap2` |
| regular file whose whole content is one JSON object holding the members `root_hash` and `metric_id` | CLDMA attestation | `cldma` |
| regular file whose first non-blank line is one JSON object holding the members `prev_hash` and `self_hash` (§2) | ledger | `ledger` (§5) |
| regular file of at most 1 MiB whose whole content is a signed note (c2sp.org/signed-note: text, a blank line, signature lines) whose text is a checkpoint (c2sp.org/tlog-checkpoint: an origin line, the size in ASCII decimal without leading zeroes, the root as the canonical base64 of 32 bytes, then any extension lines), read as `cryptovalid-verify checkpoint` reads it: UTF-8 without the ASCII control characters below U+0020 other than newline (c2sp.org/signed-note; DEL and the C1 controls are not refused there either), ending with a newline, text and signatures split at the last blank line, each signature line `— <name> <base64>` of 5 to 8192 bytes, at most 100 lines | C2SP checkpoint | none in `auto`: a checkpoint is verified against a trusted key, which `auto` has not got; the receipt names the command, `cryptovalid-verify checkpoint <path> --vkey <vkey>` (since v0.7, 2026-11-15) |
| directory holding a directory (not a link) named `tile`, when neither row of a directory above matches | C2SP tiled log | none in `auto` (a trusted key and the profile are needed); the receipt names the command, `cryptovalid-verify tiles <dir> --vkey <vkey> --profile <static-ct-api or tlog-tiles>`, with `--checkpoint <file>` when the directory holds no regular file `checkpoint` (since v0.7, 2026-11-15) |

Read as follows. A file is read whole, as UTF-8 without a byte order mark, up to 64 MiB for the two JSON documents; a larger
file can only be a ledger, and its first line is read up to 64 MiB. "Blank" is a line of spaces, tabs and a carriage
return only. A file that matches two rows (an object that is a one-line ledger and also an AP2 or CLDMA document) is
refused as ambiguous, with the rows named: the caller then names the verifier. Refused, each with its reason: a path that
does not exist or cannot be read; anything that is neither a directory nor a regular file (a pipe, a device: `ledger`
reads a pipe); an empty or blank file; bytes that are not UTF-8 in a line up to the first non-blank one (later lines of a
ledger are judged by `ledger`, which names them); a JSON value other than those of the table (an array, a
string, an object with other members); a first line that is not a JSON object (a document written over several lines,
binary data); JSON nested deeper than 512 levels (§30; until 0.29.0 the parser's limit, which moved with the
Python version).

The rows of a directory are tried in the order of the table (an evidence pack first). A file is read as a signed note
only when it was read whole and holds at most 1 MiB, the limit of a note file on the command line (§13).

Recognised is not valid: the row's verifier then gives the verdict, as when it is named directly. For the two C2SP rows
`auto` verifies nothing: the receipt has `kind` `checkpoint` or `tiles`, `valid` false and one layer with status SKIP
whose detail names the command to run (exit 1); the checkpoint's origin and size are named, read from untrusted text. A ledger whose first
line is damaged so that it no longer holds `prev_hash` and `self_hash` is not recognised; `cryptovalid-verify ledger`
names the failure of each line.

## 13. Checkpoint signatures of static CT logs, type 0x05 (NORMATIVE since v0.7, 2026-11-15)

`cryptovalid_checkpoint.verify_note` verifies the note signature of a static CT log. Sources, read on 2026-11-15:
c2sp.org/static-ct-api at commit 7e91dadf3c (2026-10-01), c2sp.org/signed-note and c2sp.org/tlog-checkpoint at commit
b2dd989233 (2026-10-07) of github.com/C2SP/C2SP, unchanged on `main` that day; RFC 6962. The rules they set:

- signed-note, signature types: "`0x05` — RFC 6962 `TreeHeadSignature`s, as specified by [c2sp.org/static-ct-api]".
- static-ct-api, Checkpoints: "The key name of the signature line MUST match the checkpoint origin line. The key ID MUST
  be the first four bytes (interpreted in big-endian order) of the SHA-256 hash of the following sequence: the key name, a
  newline character (`0x0A`), the signature type identifier byte `0x05`, and the 32-byte RFC 6962 `LogID`."
- static-ct-api: "The signature body MUST be an encoding of the following structure. `struct { uint64 timestamp;
  TreeHeadSignature signature; } RFC6962NoteSignature;`" — "“signature” is the `TreeHeadSignature` digitally-signed
  value", and "A checkpoint signed with this algorithm MUST NOT include any extension lines."
- RFC 6962 §3.5: `digitally-signed struct { Version version; SignatureType signature_type = tree_hash; uint64 timestamp;
  uint64 tree_size; opaque sha256_root_hash[32]; } TreeHeadSignature;` (version v1 = 0, tree_hash = 1); §2.1.4: "A log
  MUST use either elliptic curve signatures using the NIST P-256 curve [...] or RSA signatures".
- signed-note: "Verifiers MUST ignore signatures from unknown keys, even if they share a name or ID (but not both) with a
  known key. If the key name and ID match a known key, verifiers MUST verify the signature."

The rule of this implementation:

1. **vkey.** `<name>+<8 hex digits>+base64(0x05 || DER SubjectPublicKeyInfo)` — the form of
   github.com/transparency-dev/formats `RFC6962VerifierString` (signed-note gives no vkey form for 0x05). `LogID` =
   SHA-256 of the DER (RFC 6962 §3.2). Refused as the caller's error, with the reason: an ID that is not SHA-256(name ||
   0x0A || 0x05 || LogID)[:4]; material that is not a DER SubjectPublicKeyInfo; a key that is not ECDSA P-256 (RSA, which
   RFC 6962 allows, is not implemented; other curves are outside RFC 6962); a DER that is not the canonical encoding of the
   key (trailing bytes, another encoding). `cryptovalid-verify vkey-rfc6962 --name <origin> --key-b64 <DER>` (or `cryptovalid_checkpoint.py
   vkey-rfc6962`) prints the vkey from the `key` of a CT log list entry; `cryptovalid-verify checkpoint <note> --vkey
   <vkey>` (or `cryptovalid_checkpoint.py verify`) verifies a note.
2. **Signature body**, after the 4-byte key ID, read in this order, each length checked before the bytes it covers are
   read: 8 bytes `timestamp` (milliseconds, any uint64); 1 byte hash algorithm; 1 byte signature algorithm; 2 bytes length
   `L` (big-endian); exactly `L` bytes of signature and nothing after them. A body of fewer than 12 bytes, a length that
   differs from the bytes that follow, a hash algorithm other than 4 (SHA-256) or a signature algorithm other than 3
   (ECDSA) makes the line fail, with the reason.
3. **Text.** The note text must be a checkpoint as `parse_checkpoint` reads it (three lines; size in ASCII decimal without
   leading zeroes, at most 2^64-1; root as the canonical base64 of 32 bytes), with no extension line, and its origin line
   must equal the key name; otherwise the line fails, with the reason.
4. **Signature.** ECDSA P-256 with SHA-256 over `00 01 || timestamp || tree_size || root` (RFC 6962 §3.5), the signature
   ASN.1 DER: a BER encoding (a long-form length, an integer with a leading zero byte) does not verify; a high S verifies
   (RFC 6962 sets no low-S rule).
5. A line whose (name, key ID) matches a trusted 0x05 key and fails any of 2–4 makes the whole note NON_VALIDA; the
   `motivo` is `signature from known key <name> does not verify: <reason>`. A line that verifies is reported as
   `{"name", "type": 5, "timestamp_ms"}`. Lines of unknown keys are ignored and counted (`ignored`), as for every type.
   Without `cryptography` the note is NON_VERIFICATA, as for the other types.

Vectors: `testdata/interop/` — the checkpoint of the test log `rome2026h1.example.org` of FiloSottile/sunlight (size 300)
with its log list entry; `test_c2sp_static_ct_20261115.py` checks it, its altered forms, every body length from 0 to the
real one plus 64, and notes signed with keys made in the test, against the rule above and, where Go is installed, against
github.com/transparency-dev/formats (`verifiers/note_oracle`).

## 14. Tiles of C2SP tiled logs (NORMATIVE since v0.7, 2026-11-15)

`cryptovalid_merkle.verify_tiles` reads, from a directory laid out as the log serves it (`<dir>/tile/...`), the tiles of a
tree of a given size, and checks them against the root of a checkpoint; `cryptovalid-verify tiles <dir> --vkey ... --profile
static-ct-api|tlog-tiles` (or `cryptovalid_checkpoint.py tiles`) first verifies the checkpoint (`<dir>/checkpoint`, §13 for static CT logs) and
then its tiles. Sources, read on 2026-11-15: c2sp.org/tlog-tiles at commit b2dd989233 (2026-10-07) and
c2sp.org/static-ct-api at commit 7e91dadf3c (2026-10-01) of github.com/C2SP/C2SP, unchanged on `main` that day; RFC 6962
§2.1 and §3.4. The rules they set:

- tlog-tiles: "Tiles are served at `<prefix>/tile/<L>/<N>[.p/<W>]`"; "`<L>` is the “level” of the tile, and MUST be a
  decimal ASCII integer between 0 and 63" (static-ct-api: "between 0 and 5"); "`<N>` [...] MUST be a non-negative integer
  encoded into zero-padded 3-digit path elements. All but the last path element MUST begin with an `x`"; "`<W>` is the
  width of the tile, a decimal ASCII integer between 1 and 255".
- "Full tiles MUST be exactly 256 hashes wide, or 8,192 bytes. At “level 0” tiles contain leaf hashes. At “level 1” and
  above, each hash in a tile is the Merkle Tree Hash of a *full* tile at the level below."
- "The partial tile at level *l* for a tree of size *s* has `floor(s / 256**l) mod 256` entries"; logs "MAY delete any
  partial tile once the corresponding full tile is available" and clients "MAY fetch the full tile in parallel as a
  fallback".
- tlog-tiles: "Entry bundles are sequences of big-endian uint16 length-prefixed log entries. Each entry in a bundle hashes
  to the corresponding entry in the corresponding “level 0” Merkle Tree tile", at `<prefix>/tile/entries/<N>[.p/<W>]`.
- static-ct-api: data tiles at `<monitoring prefix>/tile/data/<N>[.p/<W>]` "are sequences of the following structure, one
  per entry": `TileLeaf { TimestampedEntry timestamped_entry; select (entry_type) { case x509_entry: Empty; case
  precert_entry: ASN.1Cert pre_certificate; }; Fingerprint certificate_chain<0..2^16-1>; }`, `opaque Fingerprint[32]`;
  "Static API logs MUST include a `leaf_index` extension" whose data "MUST be a `LeafIndex` value, which is a big-endian
  unsigned 40-bit integer specifying the 0-based index of the included entry in the log"; "Duplicate extensions with the
  same `CExtensionType` MUST NOT be included". RFC 6962 §3.4: the leaf is `MerkleTreeLeaf` = version v1 (0), leaf_type
  timestamped_entry (0), `TimestampedEntry { uint64 timestamp; LogEntryType entry_type; select(entry_type) { case
  x509_entry: ASN.1Cert; case precert_entry: PreCert; } signed_entry; CtExtensions extensions; }`.
- Both: "Clients MUST support `Content-Encoding: gzip`" (static-ct-api) for data tiles; entry bundles "SHOULD be
  compressed at the HTTP layer".

The rule of this implementation:

1. **Which tiles.** For a tree of `s` leaves, level `l` has `floor(s / 256^l)` hashes, in full tiles and one partial tile
   of `floor(s / 256^l) mod 256` hashes when that is not 0; the levels are those where `floor(s / 256^l) > 0`. A tree that
   needs a level above the profile's (5 for static-ct-api, 63 for tlog-tiles) is refused. Size 0 has no tiles and the
   root of the empty tree.
2. **Reading.** A path is a regular file of at most 64 MiB, reached through real directories under `<dir>`: a link,
   at the file or at any directory under `<dir>` (`tile/`, the level, `x###`, `.p`), or anything else is refused. A partial tile that is
   absent is read as the first `W` hashes (or entries) of the full tile, and counted (`partial_from_full`); when both
   files are present, the partial hash tile must equal the prefix of the full one.
3. **Hash tiles** are exactly 32 × width bytes. Every level-0 tile is required. The root is the RFC 6962 Merkle Tree Hash
   of the level-0 hashes and must equal the checkpoint's. Every upper-level tile that is present must hold, for each of
   its hashes, the root of the 256 hashes below it computed from level 0; an upper-level tile that is absent is counted
   (`upper_missing`), never silently passed over.
4. **Entries** (unless `--no-entries`): every data tile (static-ct-api) or entry bundle (tlog-tiles) is required and holds
   exactly its width of entries and nothing after them, each length read before the bytes it covers. Entry bundle: uint16
   length, entry; leaf hash SHA-256(0x00 || entry). Data tile: timestamp (8), entry_type (2: 0 x509_entry, 1
   precert_entry, anything else refused), the certificate (uint24 length, at least 1 byte) or issuer_key_hash (32) and
   TBSCertificate (uint24, at least 1), extensions (uint16), for a precertificate the pre_certificate (uint24, at least
   1), certificate_chain (uint16, a multiple of 32); leaf hash SHA-256(0x00 || 00 00 || TimestampedEntry). The extensions
   are a list of (uint8 type, uint16-length data); a type twice, a type other than leaf_index, a leaf_index that is not 5
   bytes, no leaf_index, or a leaf_index other than the entry's index is refused (static-ct-api says nothing of other
   types: this implementation knows only leaf_index and refuses the rest). Each leaf hash must equal its level-0 hash.
   The pre_certificate and certificate_chain of a data tile are read for their structure only: they are outside the
   TimestampedEntry, no leaf hash covers them, and a change of their content is not detected (measured on the real data
   tile); the issuers they name are not fetched.
5. **Encoding** of data tiles and entry bundles on disk: `gzip` (exactly one gzip member, nothing after it, at most 64 MiB
   once decompressed), `identity`, or `auto` (the default: gzip when the file starts with the bytes 1f 8b). A wrong guess
   cannot pass: the leaf hashes decide.
6. **Limits** of this implementation, stated: at most 2^24 leaves (every leaf hash is held in memory; measured on
   2026-11-15 with level-0 tiles only, Python 3.11: 0.4 GB resident at 2^22 leaves). The whole tree is read
   from leaf 0: a log pruned as tlog-tiles §Pruning allows (tiles and entry bundles below its minimum index no longer
   served) cannot be checked here, and the first missing level-0 tile or entry file is the reason given.
7. Result: `{"stato": "OK" | "NON_VALIDA", "motivo", "size", "root", "tiles_read", "partial_from_full", "upper_missing",
   "entries", "entries_checked"}`; the first rule that fails gives the reason. The command exits 0 when the checkpoint and
   the tiles are OK, 1 when either is not, 2 when a vkey or the checkpoint file cannot be used.

Vectors: `testdata/interop/sunlight_mirror/` — a checkpoint of size 300 cosigned by a mirror (Ed25519 cosignature/v1)
and its three hash tiles, whose root is the checkpoint's, with two placeholder entry bundles that do not hash to the
leaves (a negative); `testdata/interop/sunlight_navigli2025h2/` — four level-0 tiles and a partial one of a real static CT
log and the partial data tile of its 10 entries (precertificates). `test_c2sp_tiles_20261115.py` checks them and trees
generated in the test (both profiles, sizes around every tile and level boundary, partial tiles absent or present, gzip),
every truncation and altered byte of the entries, against the rule above and, where Go is installed, against
golang.org/x/mod/sumdb/tlog, filippo.io/sunlight and filippo.io/torchwood (`verifiers/tile_oracle`).


## 15. The hybrid signature of this format is not a composite signature (since v0.8, 2026-11-15)

A hybrid ledger entry (§2: `signature` with `signer`, `signature_pq` with `signer_pq`) and a hybrid log tip
(`cryptovalid_tip.py`) carry two independent signatures over the same bytes: Ed25519, and ML-DSA-65 (FIPS 204, pure, with
the empty context string), each over the UTF-8 bytes of the `self_hash` string (the tip: over its payload), each in its own
field and under its own key.

RFC 10073 (Composite ML-DSA for Use in X.509 Public Key Infrastructure, Standards Track, November 2026; §2.1, §2.2,
§3.1–§3.3, §4.1, §4.3, §5.3, §9.3 and its entry for `id-MLDSA65-Ed25519-SHA512` in §6 read in full on 2026-11-15 from
https://www.rfc-editor.org/rfc/rfc10073.txt) defines, for the same two algorithms, `id-MLDSA65-Ed25519-SHA512`
(OID 1.3.6.1.5.5.7.6.48). It is another construction, and the two are not interchangeable:

| | this format | RFC 10073 `id-MLDSA65-Ed25519-SHA512` |
|---|---|---|
| bytes both algorithms sign | the message itself | `M' := Prefix \|\| Label \|\| len(ctx) \|\| ctx \|\| PH( M )` (§2.1, §3.2): Prefix the ASCII string `CompositeAlgorithmSignatures2025`, Label `COMPSIG-MLDSA65-Ed25519-SHA512`, `len(ctx)` "a single unsigned byte", PH SHA512 |
| ML-DSA context string | empty | the Label: "the per-algorithm Label is used as the ctx for the underlying ML-DSA primitive" (§3.2) |
| signature | two fields | one value, `mldsaSig \|\| tradSig` (§4.3): 3309 + 64 bytes |
| public key | two fields | one value, `mldsaPK \|\| tradPK` (§4.1): 1952 + 32 bytes |
| valid when | per layer: the post-quantum layer may be absent, and is required only when the caller pins it or a pack's manifest claims it (§5, §10) | "if and only if all component signatures were successfully validated" (§3.3) |

Rules of this format (NORMATIVE since v0.8):

1. The two signatures of an entry, concatenated, are not a composite signature, and a composite signature value is not a
   `signature` or a `signature_pq`: a verifier of this format refuses it (its length alone is not 64 or 3309 bytes, and
   its halves sign `M'`, not the message). Measured on 2026-11-15 with the same two keys over the same message: neither
   crossing verifies, both direct checks do (`test_hybrid_is_not_composite_20261115.py`).
2. This format does not call its hybrid "composite", and an implementation MUST NOT label these fields with the OID of
   a composite algorithm.
3. Keys do not move between the two. RFC 10073 §5.3: "Component keys of a composite MUST NOT be used in any other type
   of key or as a standalone key"; §3.1: key generation "MUST NOT reuse existing key material"; §9.3: "key reuse MUST be
   avoided to prevent the introduction of EUF-CMA vulnerabilities". The keys of this format are standalone keys: a
   `signer` / `signer_pq` pair MUST NOT be published as a composite public key, and composite signatures need keys
   generated for them.
4. What the composite has and this format does not: the two signatures bound to each other. An entry whose
   `signature_pq` is removed still carries a valid Ed25519 signature; what refuses it is the verifier's pin
   (`expected_pq_pubkey_b64`, `require_pq`: the stripped layer is then `pq_missing`, §5), not the signature itself. A
   reader who needs "both or nothing" inside one signature value needs the composite, not this format.

Since v0.15 (§29) `cryptovalid_composite.py` verifies composite signatures of RFC 10073 for three ML-DSA-65
algorithms; it signs nothing, and the hybrid of this section stays what it is. Until v0.15: nothing in this repository
implemented RFC 10073. The test builds composite signatures with a helper
of its own and checks that helper against the two signatures of Appendix E for `id-MLDSA65-Ed25519-SHA512` (they
verified on 2026-11-15), read since v0.15 from the RFC's text in `spec/vectors/rfc10073/` (§29 rule 5).

**Quantum-vulnerable signatures, a limit stated (v0.10).** NIST IR 8547, *Transition to Post-Quantum Cryptography
Standards*, final, October 2026 (CSRC document history: draft 11/12/24, final 10/27/26; https://doi.org/10.6028/NIST.IR.8547;
read on 2026-11-17), §4.1.1, Table 2: ECDSA, EdDSA and RSA signatures are "Deprecated after 2030" and "Disallowed after
2035" under NIST standards and guidelines ("Organizations may continue using these algorithms and parameter sets as
they migrate to the post-quantum signatures identified in Table 3"). Ed25519 is EdDSA. This format signs with Ed25519:
ledger entries and tips (§2, this section), the evidence pack's manifest (§10), checkpoints and cosignatures (§13, §16),
and the maintainer signs each release's evidence pack with an Ed25519 key held in AWS KMS. The path this repository has
is the hybrid signature of this section: Ed25519 and ML-DSA-65 (FIPS 204) over the same bytes, the ML-DSA-65 key in a
file or in AWS KMS (`signer.py --pq-kms`, KeySpec ML_DSA_65), the post-quantum layer required when the caller pins it or
a pack's manifest claims it (§5, §10). A ledger, tip or pack with Ed25519 only verifies as before: no verdict here depends
on the date; for an Ed25519-only ledger, the report of `signer.py` and of the Go and Java verifiers says `pq_protected:
false` with a note that names IR 8547. A witnessed checkpoint (§16) can carry ML-DSA-44 (FIPS 204) cosignatures and
log signatures of tlog-checkpoint, which this verifier checks; a checkpoint signed with Ed25519 or ECDSA only has no
post-quantum layer. The RFC 3161 tokens of §11 are
signed by the TSA with its own algorithm; this verifier does not refuse a classical one. Until v0.10 this repository
cited IR 8547 as a draft (its initial public draft of 2024).

## 16. Roles of the keys of a witnessed checkpoint (NORMATIVE since v0.8, 2026-11-15)

`cryptovalid_witness.py` (experimental module) checks a checkpoint signed by a log and cosigned by witnesses: the witness
side (`witness_cosign`, `WitnessService`, `serve`), the log side (`submit_checkpoint`, `submit`) and the relying party
(`verify_witnessed`, `verify`). Sources, read on 2026-11-15 at C2SP/C2SP commit 09f3e519fe79 (main):

- tlog-checkpoint, "ML-DSA-44 Checkpoint Cosignatures": "This signature type can be used either by the log to
  authenticate itself, or by an arbitrary cosigner role. When the log is authenticating itself, the cosigner name
  SHOULD be the log origin." and "Extension lines are ignored and not covered by the signature."
- tlog-checkpoint, "Ed25519 Log Signatures": "This signature type only supports the log itself."
- tlog-checkpoint, "Signatures": "ML-DSA-44 checkpoint cosignatures don't sign the extension lines, which SHOULD be
  empty."
- tlog-cosignature: "Clients are configured with tuples of (cosigner name, cosigner algorithm, public key), specifying
  the particular key they accept for each supported cosigner."

One signature type, 0x06, can therefore stand for the log or for a witness; the type of a key does not say its role.

Rules (NORMATIVE since v0.8):

1. **The role of a key is the list the caller puts it in**: the log keys (`log_vkey`, `--log-vkey`, `--log-origin`) or
   the witness keys (`witness_vkeys`, `--witness-vkey`; for `witness_cosign` and `serve`, the witness's own keys). A
   signature line counts as the log's only when it verifies under a log key, and as a witness's only when it verifies
   under a witness key; the two are counted separately, so a log signature is never a witness cosignature and the
   reverse.
2. **Log keys**: type 0x01 (Ed25519 log signature), 0x02 (ECDSA, as Rekor v1 and transparency-dev/witness) or 0x06
   (ML-DSA-44 cosignature/v1, the log authenticating itself). Any other type in the log list is refused (`NoteError`)
   before any signature is read. Type 0x04 is not accepted as a log key (the "generalized" sentence of the Ed25519
   cosignature section is not read here as admitting it; open).
3. **Witness keys**: type 0x04 or 0x06. A 0x01 or 0x02 key in the witness list is refused (`NoteError`: it can only be
   a log key); a key of another type is ignored: an unassigned type, as `verify_note` ignores it, and a 0x05 (static CT)
   key, which `verify_note` would verify but which signs only as a log.
4. **One key, one role**: a key — a (name, key id) pair, which commits to the type byte and the public key — given in
   both lists is refused (`NoteError`) before any signature is read; for the witness side, a trusted log key equal to
   one of the witness's own keys is refused the same way (`WitnessService` at start-up, `witness_cosign` before it
   cosigns or writes its state). Only a 0x06 key can be in both lists. An Ed25519 key used under one name as a 0x01 log
   key and as a 0x04 witness key is two keys (two key ids, two signed messages): its 0x01 line counts only for the log
   and its 0x04 line only for the witness, as before v0.8. Since v0.16 a witness does not make such a line (§32 rule 7);
   the relying party still reads one as two keys.
5. **Extension lines must be signed by the log**: when every trusted log signature that verified is ML-DSA-44 (0x06),
   no log signature covers the extension lines; a checkpoint with extension lines is then refused — by the witness,
   which would otherwise sign them under its Ed25519 cosignature (HTTP 400), and by the relying party (`NON_VALIDA`).
   FiloSottile/torchwood @ 1c05157 goes further: it refuses every ML-DSA-44 cosignature, signed or verified, on a
   checkpoint with extension lines ("Unsigned extension lines are dangerous", `cosignature.go`); this rule refuses
   only a checkpoint whose extension lines no log signature covers.

Measured on 2026-11-15 (`test_witness_mldsa_log_20261115.py`): the litewitness vector of torchwood (an ML-DSA-44 log
key, `testdata/interop/torchwood_mldsa44_log.*`) is cosigned; checkpoints of an ML-DSA-44 log with self-generated keys
are accepted by `verify_witnessed`, the `verify` command, `witness_cosign` and `WitnessService.add_checkpoint`; a live checkpoint of the Sigstore staging log `pqc27-a1.us-east4.rekor.sigstage.dev` (ML-DSA-44 log key
from its TUF `trusted_root.json`, three ML-DSA-44 witnesses; read at 2026-11-15T22:24:41Z) verifies with `min_witnesses`
3 and not 4 when given (`CV_SIGSTAGE_DIR`; not shipped here).

## 17. What the caller of a ledger verifier asks for is applied or refused (NORMATIVE since v0.9, 2026-11-16)

A ledger verifier takes expectations from its caller besides the file: a trusted key, the identity of the ledger it
expects, the oldest tip it accepts. The expected identity and the oldest tip are applied in every branch of the
verification, or the verdict is FAIL with the reason named; they are never accepted and then left out because the branch
that applies them was not taken. On the command line a value option given twice is a usage error (exit 2), never a
second value that silently replaces the first. An expected identity that can match no ledger is the caller's error,
refused before the file is judged (rule 1). The trusted log key given without a tip is the exception written at the end
of this section.

1. **The ledger identity** is the `self_hash` of entry 0, as written in the file (the `ledger_id` of a signed tip is
   the same value, `spec/CONFORMANCE.md`). It is readable without a tip. The expected identity (`expect_ledger_id`,
   `--expect-ledger-id`, Go and Java `-expect-ledger-id`) is compared with it whether or not a tip is present, checked,
   or trusted: a different value, or a file with no entry, is FAIL with `ledger_id_mismatch`. With a checked tip the
   tip's own comparison (`ledger_id_mismatch`, `tip_of_another_ledger`) still applies. The expected identity is 64
   lowercase hexadecimal characters (the form of every `self_hash` of §3); any other value (empty, upper case,
   surrounded by spaces, other characters) is refused: a usage error, exit 2, in the command-line verifiers; a
   `ValueError` in `verifier.verify_ledger` and `cryptovalid_tip.check_tip`.
2. **The oldest acceptable tip** (`tip_not_before`, `--tip-not-before`) is a requirement on a signed tip: given, it
   makes the tip required (as the trusted post-quantum log key already does). Without a tip the verdict is FAIL with
   `tip_missing`; with a tip and no trusted log key, FAIL with `tip_untrusted`; with a checked tip, the comparison of
   instants of `spec/CONFORMANCE.md` (`tip_rolled_back`, `bad_not_before`). An empty value given to the Python API is a
   given value, never "not given": it makes the tip required, and a checked tip FAILs with `bad_not_before`.
3. **A PASS names what was compared.** When the expected identity is given and matches, the receipt's
   `scope.proves` names it; the receipt keeps its keys (`cryptovalid/receipts.py`).
4. **An empty pin is not "no pin" on the command line and in the archive verifier.** An empty value of a value
   option is refused: `--expect-ledger-id`, `--trusted-pubkey` and the other value options of the four command-line
   verifiers (exit 2, as since 2026-09-21); `--tip` and `--trusted-pq-pubkey` of `cryptovalid_tip.py check` (exit 2;
   until 0.25.0 an empty `--trusted-pq-pubkey` there dropped the post-quantum check: ok, exit 0); in the archive
   verifier (`cryptovalid_ingest.verify_archive`, `cryptovalid-ingest verify --pubkey`, the MCP tool `verify_archive`)
   an empty `expected_pubkey_hex` — `""`, an empty list, or a list holding an empty or non-string key — is a
   `ValueError` (exit 2 for `--pubkey ""`). Until 0.25.0 `""` and an empty list meant "not pinned", ok with the warning
   `no_pinned_pubkey`; a list holding an empty key was already not ok (`sth_signer_mismatch`). In the libraries an
   empty trusted log key is still "not given", unchanged by this section: `trusted_pubkey_hex` and
   `trusted_pq_pubkey_b64` of `verifier.verify_ledger`, `trustedPubkey` of the JS `verifyLedger`, and the string
   parameters of the Go and Java libraries (the zero string).
5. **A tool argument is one the tool takes.** The MCP server (`cryptovalid_mcp.py`) refuses an argument outside a
   tool's input schema (JSON-RPC `-32602`; the schemas say `additionalProperties: false`): until 0.25.0 it was dropped.

Not changed by this section: a trusted log key (`--trusted-pubkey`) given without a tip file. It is the key a tip is
checked with when there is one; the tip is required only with `--require-tip` (or rule 2, or a trusted post-quantum
key), and without it the receipt's `tip` is `null` and its `scope` says the tail is not covered. Changed by §22 rule 1
(v0.14): the trusted log key makes the tip required too. The Rust and Swift
verifiers have none of these options and refuse them as unknown flags, exit 2 (Rust measured on 2026-11-16; Swift by
its code, `main.swift` takes only `--algo` and `--pubkey`).

Measured on 2026-11-16 (`test_expect_applied_20261116.py`): on 0.25.0 `verifier.py examples/sample_ledger.jsonl
--expect-ledger-id <another ledger's id>` is PASS, exit 0, and so is `--tip-not-before 2099-01-01T00:00:00Z`; the JS, Go
and Java verifiers answer the same; from 0.25.1 the four answer FAIL, exit 1, and refuse a malformed identity with exit 2.

## 18. Payment entry profile `cryptovalid-payment/1` (NORMATIVE since v0.10, 2026-11-16)

The `data` of an entry is free-form (§4) and the ledger verifiers do not read it (§2.1). This section defines one closed
payload for a classic payment, so that the bound of §19 covers the payment's value and its parties inside one entry
and does not sit next to them. It is a recording format, not an assessment of compliance with any regulation.
"Character" in this section and in §19 means a Unicode code point.

*Texts the content was chosen after* (informative; the version in force and where each was read are listed in §19
rule 13; none of this is a legal opinion): Regulation (EU) 2023/1113, Art. 5(1) (within the Union a transfer carries at
least the payment account numbers of payer and payee), Art. 5(2) (further information made available within three
working days on request) and Art. 26 (records of the information of Art. 4-7 kept for five years, then the personal data
deleted unless national law provides otherwise; a further retention a Member State allows or requires "shall not exceed
five years"); Regulation (EU) 2024/1624, Art. 77 (record retention; the Regulation applies from 2027-07-10);
Regulation (EU) No 260/2012, Art. 5c, inserted by Regulation (EU) 2024/886 (verification of the payee; payment service
providers in a Member State whose currency is the euro comply by 2025-10-09, the others by 2027-07-09); Regulation (EU)
2016/679, Art. 5(1)(c) and Art. 17; EDPB Guidelines 02/2025 on processing of personal data through blockchain
technologies, version 2.0 adopted on 2026-07-07, §52-53.

**Personal data.** An entry under a hash chain cannot be removed without breaking the chain. So the IBANs, the names, the
payer's further data and the EndToEndId are recorded only as salted commitments, and their values and salts are kept by
the payment service provider outside the ledger. Such a commitment is a salted hash in the terms of EDPB Guidelines
02/2025 v2.0 §52, which says that "the hash will also be considered personal data, as will any other identifiers that
might exist", and that after deletion of the salt "the hash should not be linkable to the original data, provided that
the algorithm has not been broken, the keys have not been compromised or leaked, and the salt was not leaked or poorly
chosen"; whether it then stops being personal data that paragraph does not say, and this format does not decide it. It is computationally hiding, not the perfectly hiding commitment of §53. The
destruction is a statement of the provider, which this format cannot prove; it covers the provider's backups and logs
only if the provider says so, and never a copy of a disclosure held by someone else. The members in clear (amount,
currency, the random `payment_id`, the beacon values, the record salt) may also be personal data, depending on what else
the holder keeps; this format does not decide it.

A `data` object whose member `profile` is the string `cryptovalid-payment/1` is a payment entry and has exactly these
members (plain names: the ISO 20022 message definitions could not be read on 2026-11-16, the site answered 403, so no
alignment with their element names is claimed):

| member | required | value |
|---|---|---|
| `profile` | yes | `"cryptovalid-payment/1"` |
| `payment_id` | yes | a random identifier the provider draws for the payment, never a reference of the payer: a version 4 UUID (RFC 9562) in its lowercase canonical form, 36 characters `xxxxxxxx-xxxx-4xxx-Yxxx-xxxxxxxxxxxx` with `x` in `0-9a-f` and `Y` in `8 9 a b` (the form of an ISO 20022 UETR); no two payment entries of the prefix of the ledger the verifier receives carry the same value (`payment_id_not_unique`) |
| `amount` | yes | a string (never a JSON number, §3): the integer part `0` or 1 to 18 digits not starting with 0, then optionally `.` and 1 to 4 digits; greater than zero. With a pinned currency table (rule below, "Currencies") one canonical form: when the currency has N > 0 minor units, `.` and exactly N digits (`1.50`, never `1.5`), and when N = 0 nothing |
| `currency` | yes | three capital letters `A`-`Z`; with a pinned currency table, one of its codes (rule below, "Currencies") |
| `beacons` | yes | a list of 1 to 8 beacon values of §19 rule 1, each an object of exactly `source`, `chain_index`, `pulse_index`, `output_value` |
| `record_salt` | yes | 32 to 128 lowercase hexadecimal characters, an even number (16 to 64 bytes: at least 128 bits) the provider draws at random for this entry |
| `execution_date` | no | the date the payment service provider executed the payment, `YYYY-MM-DD` and a real calendar date, as the provider records it (a claim of the provider: the window dates the entry, not the execution) |
| `payee_entity_id` | no | in clear, only for a payee that is not a natural person (a public body, a company): its identifier as the provider records it (for example a tax code), 1 to 35 characters `A-Z a-z 0-9`; for a natural person use `payee_name_commitment` |
| `psp_id` | no | in clear: an identifier of the payment service provider that executed the payment (for example a BIC or a registry code), 1 to 35 characters `A-Z a-z 0-9` |
| `payer_iban_commitment` | no | commitment to the payer's IBAN, rule below |
| `payee_iban_commitment` | no | commitment to the payee's IBAN |
| `payer_name_commitment` | no | commitment to the payer's name |
| `payer_tax_id_commitment` | no | commitment to the payer's tax identifier (for example an Italian codice fiscale) |
| `payer_details_commitment` | no | commitment to the payer's address, document or birth data, as the provider records them |
| `debtor_name_commitment` | no | commitment to the name of the debtor, when another person than the payer |
| `debtor_tax_id_commitment` | no | commitment to the debtor's tax identifier |
| `payee_name_commitment` | no | commitment to the payee's name |
| `end_to_end_id_commitment` | no | commitment to the EndToEndId the payer gave |
| `notice_code_commitment` | no | commitment to the creditor's payment reference (for example a pagoPA notice code or IUV) |
| `purpose_commitment` | no | commitment to the purpose text (causale) |
| `receipt_id_commitment` | no | commitment to the provider's receipt identifier |
| `rrn_commitment` | no | commitment to a card payment's retrieval reference number |

At least one **party identifier** is present: `payer_iban_commitment`, `payee_iban_commitment`, `payer_tax_id_commitment`,
`debtor_tax_id_commitment` or `payee_entity_id` (`payment_malformed`, `party_identifier_missing`). Which identifiers a
payment needs depends on the instrument and the law: Regulation (EU) 2023/1113 Art. 5(1) asks, for a transfer of funds
whose providers are all in the Union, at least the payment account numbers of payer and payee (or the unique transaction
identifier where Art. 4(3) applies); a card payment has no payer IBAN, and a creditor that issues a receipt may not know
it; this profile records what the provider has and does not judge which law applies. **In clear or committed** (after
EDPB Guidelines 02/2025 v2.0 §52, rule 13 of §19): what identifies or can single out a natural person, or a payment of
one (names, tax identifiers, IBANs, the payer's details, the creditor's reference, the purpose text, the receipt
identifier, the RRN), is a commitment; in clear only what identifies a payment service provider or a payee that is not a
natural person, the amount, the currency, the execution date and the random identifier, which may still be personal data
in the hands of whoever can link them (§18 "Personal data").

**Order of the profile's checks** (closed: the first that fails gives the outcome, and its detail names the member):
(1) `profile` is this profile's, else `entry_not_a_payment`; (2) no member outside the table (all unknown members named,
in code-point order); (3) no required member missing (named in the order of the table); (4) `payment_id`; (5)
`currency`; (6) `amount` (its decimals by the currency of step 5); (7) `record_salt`; (7a) `execution_date`,
`payee_entity_id`, `psp_id` when present, in this order; (8) each commitment present, in the order of the table; (8a) at
least one party identifier; (9) `beacons`: a list of 1 to 8 elements, then each element in list order: its members, then
`source` (a string; a value outside the closed list of §19 is `source_not_supported`), `chain_index`, `pulse_index`,
`output_value`; then no two elements with the same `source` and `pulse_index`. Every failure of (2)-(9) other than
`source_not_supported` is `payment_malformed`.

**Commitment.** 64 lowercase hexadecimal characters:

    SHA-256( "cryptovalid-payment/1/" || member || 0x00 || salt || normalised value )

where `"cryptovalid-payment/1/"` and `member` (the member's name, e.g. `payer_iban_commitment`) are ASCII, 0x00 is one
zero byte, salt is exactly 16 bytes (128 bits) the provider draws at random for this member of this entry and keeps
outside the ledger, and the normalised value is: for the two IBAN members, the IBAN with every space (U+0020) removed and
the letters in upper case (a value with a character outside ASCII is refused first: "ß" in upper case is "SS"), which
MUST then pass the IBAN rule below before it is committed; for the other members, the string in Unicode NFC (a disclosed
name that normalises to the same NFC string opens the same commitment: the provider records the exact string it
discloses, and the verifier normalises it); then UTF-8. *Unicode version:* every code point of a value of these members
MUST be assigned in Unicode 13.0.0 (the database of CPython 3.9, the oldest runtime supported); a value with another code
point, or with a lone surrogate, is refused (`disclosure_malformed` for a disclosure, an error for the writer). NFC of a
string of such code points is the same in every later Unicode version (the normalization stability policy); for a code
point assigned later it is not: measured on 2026-11-16, "a" U+1E08F U+0316 is reordered by NFC in Unicode 15.1 (CPython
3.13) and not in 13.0 (CPython 3.9), and U+105D2 U+0307 is composed into U+105C9 by Node 22 (Unicode 17.0) and by no
CPython from 3.9 to 3.13, so one disclosure would open a commitment in one runtime and not in another. The member name in the hashed bytes keeps a commitment from being
moved to another member, the zero byte ends the name (no member name contains it), and the salt's fixed length leaves
one way to split what follows. A value is 1 to 1024 characters before normalisation. A disclosure is `{"member": <one of
the commitment members of the table>, "salt": <32 lowercase hex>, "value": <string>}`, exactly these members; the verifier
normalises the value as above (for an IBAN member, a value that fails the IBAN rule is `disclosure_iban_invalid`) and
the disclosure matches when the recomputed commitment equals the entry's member byte for byte (`disclosure_mismatch`
otherwise, and when the entry has no such member). 128 bits of salt make a search over a list of IBANs or names hopeless,
where Athena measured on 2026-11-16 the last five digits of an account recovered in 2.4 s from an unsalted hash and a
16-bit salt still searchable over a dictionary of names. A commitment that is not disclosed proves nothing about its
value: the receipt says so (§19 rule 7, `commitments_not_opened`); "a provider commits only to an IBAN that passes the
rule" is an obligation of the provider that no verifier can check before a disclosure.

**Why also a record salt.** What leaves the provider's hands are hashes: an entry's `self_hash`, a signed tip, a
checkpoint's root, a manifest digest. `record_salt` puts at least 128 bits under the same `self_hash`, so that the
members in clear cannot be searched behind it either. The entry is hashed as canonical JSON (§3), never as concatenated
fields: two free fields joined without lengths collide (`INV-1` + `0.50` and `INV-` + `10.50`, measured by Athena).

**IBAN** (ISO 13616-1, electronic format): two capital letters (the country code), two digits (the check digits), then 11
to 30 capital letters or digits; 15 to 34 characters in all, no space, no lower case. Its check is ISO 7064 MOD 97-10:
move the first four characters to the end, replace each letter by two digits (A = 10 … Z = 35), and the number read in
decimal MUST be 1 modulo 97. The check digits MUST be in 02–98, the only values the MOD 97-10 computation produces (00,
01 and 99 pass the modulo exactly when 97, 98 and 02 do). Not checked: that the country code is a country of the IBAN
registry, and the length and the BBAN structure the registry gives each country. The check catches every substitution
of one digit by another and of one letter by another, not every substitution of a digit by a letter: measured on
2026-11-16 on the two example IBANs below, 7 of their 1 540 single-character substitutions pass it, each a digit
replaced by a letter (e.g. DE89370400440532I13000), which the registry's BBAN structure would refuse and this profile
does not read. The IBAN rule applies to a disclosed value: the ledger holds only its commitment. Not carried: the
outcome of the verification of the payee of Art. 5c of Regulation (EU) No 260/2012 (inserted by Regulation (EU)
2024/886); a member for it is left to a later
version, after its outcome codes are read on the primary text.

**Currencies (v0.10).** This verifier ships no currency table. ISO 4217 is the standard payments and ISO 20022 use;
its maintenance agency publishes list one with terms of use (read on 2026-11-17) that provide the content "exclusively
for personal use as well as information purposes", so a copy of it is not distributed here. The two open sources
measured on 2026-11-17 are not ISO 4217: Unicode CLDR 49's `digits` are a display convention (HUF, IDR, COP and IQD 0
where ISO 4217 gives 2, 2, 2 and 3; 12 fund and other codes of list one absent) and the EU Publications Office's
authority table "currency" gives `decimalPlace` 0 to COP, HUF, IDR and LAK where ISO 4217 gives 2, and has no XAD.
The caller may pin a currency table (`currency_table`, `--currency-table <file>`), a JSON file of exactly
`{"format": "cryptovalid-iso4217-table/1", "source": <string, 1 to 200 characters>, "currencies": {<three capital
letters>: <integer 0 to 4>, ...}}` (at least one code; strict JSON, §3; at most 64 KiB); a file outside that form is
the caller's error (`ValueError`, exit 2). `tools/iso4217_table.py <list-one.xml>` writes it from the caller's own
download of list one (the codes whose `CcyMnrUnts` is a number; one code with two different minor units is an error):
the caller accepts that source's terms, this repository does not redistribute it. With a table, `currency` must be one
of its codes (`currency_unknown`) and `amount` has exactly its minor units (`not_canonical`); the receipt names the
table (`currency_table`: `{"source", "sha256"}` of the file). Without one, the check is of form only (three capital
letters; at most 4 decimals, else `not_canonical`), the receipt's `currency_table` is `null` and its scope does not
prove `currency_not_checked`. Until this correction the first draft of v0.10 carried a table copied from list one, then
one generated from CLDR 49; neither was published.

**Amount limits.** The 18 integer digits are this profile's bound; whether every such amount fits the ISO 20022 amount
types (read from memory as 18 digits in all, not re-read) was not checked.

The RFC 3161 token that gives the upper bound is not a member: it binds the ledger through an evidence pack (§19 rule 5).
Who applies the profile: `cryptovalid_beacon.check_payment(data)` and `cryptovalid-verify beacon` (§19), on the entry it
dates. `verifier.py` and the other ledger verifiers do not (unchanged).

Vectors: `spec/vectors/beacon/` uses only IBANs published as examples (GB82WEST12345698765432,
DE89370400440532013000), fictitious amounts and names, never a real account or person.

## 19. A "not before" bound from a public randomness beacon (NORMATIVE since v0.10, 2026-11-16)

Every time proof this format verified until v0.9 is an upper bound: an RFC 3161 token (§11), a signed tip or a
checkpoint says that something existed no later than an instant. None says "not earlier": a record can be prepared in
advance and stamped later. A value that a public randomness beacon published at an instant T, and that nobody outside
the beacon could know before T, gives the other bound: the bytes that carry it were put together after T. It is
additional technical evidence, not a timestamp with a legal category: the NIST service names itself "NIST Randomness
Beacon (Version 2.0 Beta)" and "a beta release" (beacon.nist.gov/home, read on 2026-11-16), and no regulation gives a
beacon value the presumption eIDAS Art. 41(2) gives a qualified electronic time stamp. This section defines where the
values are carried, how a verifier checks the beacon's pulses offline, the bounds it may then state, how the bound
combines with an RFC 3161 token into a window, and when an entry is fixed in one history. The module is
`cryptovalid_beacon.py`, the command `cryptovalid-verify beacon`.

**Sources, a closed list.**

| `source` | Beacon | Status |
|---|---|---|
| `nist-beacon-2.0` | NIST Randomness Beacon, pulses of format version `2.0` of chain 2 (https://beacon.nist.gov/beacon/2.0/chain/2/), the chain measured on 2026-11-16 | supported |
| `drand` | drand, a threshold beacon of several operators | planned as an independent second source; no grammar and no code in v0.10 (refused as any other value) |

Any other value is refused (`source_not_supported`). Chain 1 is not accepted: a real pulse of chain 1 carries the version
"Version 2.0" (measured by an independent review on 2026-11-16) and has not been measured here. CURBy (random.colorado.edu,
Twine protocol) is not supported: its data path was not measured end to end here, its RNG sub-specification is a 0.1
crate whose API is declared unstable, and its client libraries carry no licence; its quantum certification would stay out
of scope even when supported: a verifier of this format checks a chain, its signatures and its commitments, never
"quantum certified".

**1. Where the values are: inside the entry they date.** The values are the member `beacons` of a payment entry (§18): a
list of 1 to 8 objects `{"source", "chain_index" (for `nist-beacon-2.0`: the integer 2), "pulse_index" (integer ≥ 1),
"output_value" (128 upper-case hexadecimal characters, the pulse's `outputValue` as NIST serves it)}`, exactly these
members, no two with the same `source` and `pulse_index`. They are inside `data`, so the entry's `self_hash` (§3)
covers them together with every other member of the payment (§18): the bound is a bound on the bytes that put the
values and these members together, and the receipt names the members it covers. The caller names the entry (`--entry
<idx>`); the ledger (UTF-8, at most 64 MiB, else `input_too_large`) MUST pass steps 1–4 of §5 (`ledger_invalid`); no
entry of that `idx` is `entry_not_found`. Several values of independent beacons reduce the trust to "not all their
operators colluding" (rule 9); with one source supported in v0.10 they are values of one operator, and the lower bound
is the latest of their timestamps.

What the bound does not cover. An entry before the one that carries the values gets no bound from them. An entry after
it holds, through `prev_hash`, a hash that depends on them, so its bytes too were put together after T; this verifier
reports the window only for the entry whose own payload carries the values, and names only that entry's members. A "not
before" bound dates the binding of the members, never the decision behind them: the same amount and IBANs may have been
agreed earlier.

**2. A NIST pulse, closed.** For each element of `beacons`, in list order, the caller supplies the pulse of
`pulse_index` and the pulse before it, each as the beacon serves them (`/beacon/2.0/chain/2/pulse/<index>`): a UTF-8 JSON
document of at most 64 KiB, read as a ledger line is (§3: a key twice in one object, a number with a fraction or
exponent, an integer outside ±(2^53−1), NaN or Infinity, a lone surrogate, nesting deeper than the bound are refused),
whose value is `{"pulse": P}`. P has exactly the members `uri`, `version`, `cipherSuite`, `period`, `certificateId`,
`chainIndex`, `pulseIndex`, `timeStamp`, `localRandomValue`, `external`, `listValues`, `precommitmentValue`,
`statusCode`, `signatureValue`, `outputValue`; `external` exactly `sourceId`, `statusCode`, `value`; `listValues` is a
list of exactly five objects of exactly `uri`, `type`, `value`, whose `type` is `previous`, `hour`, `day`, `month`,
`year` in this order. `uri`, `version` and the `uri` of each list value are strings of 1 to 2048 characters without
control characters (Unicode category Cc); `cipherSuite`, `period`, `statusCode` and `external.statusCode` are integers
in [0, 2^32−1] (a boolean is not an integer); `chainIndex` and `pulseIndex` integers ≥ 0; `timeStamp` is
`YYYY-MM-DDThh:mm:ss.sssZ` and a real calendar time; `certificateId` and every other value are 128 hexadecimal
characters (64 bytes) in the case the beacon serves them (NIST serves `certificateId` in lower case and the other values
in upper case; this grammar accepts either case, and the bytes are compared); `signatureValue` is hexadecimal, 2 to
2048 characters, an even number. Anything else is refused with the member named (`pulse_malformed`); a path that is not
a readable regular file is `input_unreadable`, a larger file `input_too_large`. The `uri` of the list values is not
signed by the beacon and is not used. The number of pulse pairs MUST equal the number of `beacons` (a usage error
otherwise).

**3. The checks of each pulse pair,** in order; the first that fails gives the outcome:

1. `version` is exactly `2.0` and `cipherSuite` is 0 (RSA PKCS#1 v1.5 with SHA-512, hash SHA-512); cipher suite 1 (RSA-PSS
   with a delay function) is `cipher_suite_not_supported`, another version `version_not_supported`.
2. `statusCode` is 0 in both pulses (NIST IR 8213 draft, §4.3.4: a normal transition, no gap, no change of certificate,
   the local random value related to the previous commitment, not the end of the chain); any other value is
   `status_not_supported`.
3. The pulses are the one the entry names and its predecessor in chain 2: `chainIndex` equal to the element's
   `chain_index` in both, `pulseIndex` equal to `pulse_index` and to `pulse_index − 1`, and the `uri` of each exactly
   `https://beacon.nist.gov/beacon/2.0/chain/<chainIndex>/pulse/<pulseIndex>` (`pulse_mismatch`); equal `period` and
   `certificateId` in both (`chain_inconsistent`).
4. **Certificate.** The caller pins one or more beacon certificates (each a PEM file of at most 64 KiB holding exactly
   one PEM block, a certificate, or DER; anything else is refused, `certificate_malformed`). The one whose SHA-512 over
   the DER equals `certificateId` is used; none is `certificate_mismatch`; its key MUST be RSA of at least 2048 bits
   (`certificate_key_not_supported`); both `timeStamp`s MUST lie within its validity
   (`certificate_not_valid_at_pulse_time`). The certificate's chain to a CA and its revocation are not checked: the pin
   is the trust.
5. **Signature** of each pulse: RSA PKCS#1 v1.5 with SHA-512 over the signed message M below, with the pinned key
   (`signature_invalid`). M is the concatenation, in this order, of: `uri` and `version` (UTF-8, each after its length
   in 4 bytes big-endian); `cipherSuite` and `period` (4 bytes big-endian each); `certificateId` (the bytes, after their
   length in 4 bytes); `chainIndex` and `pulseIndex` (8 bytes big-endian each); `timeStamp` (UTF-8, after its length in
   4 bytes); `localRandomValue`, `external.sourceId` (bytes, each after its length in 4 bytes); `external.statusCode`
   (4 bytes big-endian); `external.value`, the five list values in the order of rule 2, `precommitmentValue` (bytes,
   each after its length in 4 bytes); `statusCode` (4 bytes big-endian).
6. **Output value** of each pulse: `outputValue` = SHA-512(M || the signature's bytes, without a length)
   (`output_value_mismatch`).
7. **Chain.** The `previous` list value of the named pulse equals the predecessor's `outputValue` (`previous_mismatch`);
   its `timeStamp` is the predecessor's plus `period` milliseconds, exactly (`period_mismatch`).
8. **Commitment.** SHA-512 of the named pulse's `localRandomValue` equals the predecessor's `precommitmentValue`
   (`commitment_mismatch`).
9. **The entry's value.** The element's `output_value` equals the named pulse's `outputValue` as bytes
   (`beacon_value_mismatch`).

The serialization of step 5 is the one the service deploys, not the one of the draft NIST IR 8213 (May 2019, Algorithms
1 to 3): the draft prefixes every length with 8 bytes (a uint64), gives `external.statusCode` 8 bytes, and hashes the
signature with its length prefix into `outputValue`. Measured on 2026-11-16 on six consecutive pulses of chain 2
(2030298–2030303, `spec/vectors/beacon/nist/`): with the draft's rules neither the signature nor `outputValue` verifies;
with the rules above all six verify (the format of clcert/beacon-verifier, MIT, `scripts/chain_consistency_version2.py`,
agrees).

*Beacon certificates seen* (for verification years later; the caller pins them, this list is informative):
`certificateId` 5b6386e6ac8a993b…c0f286fb73cc8fa79864ec0c18 (full value in `spec/vectors/beacon/README.md`), subject
CN=engine.beacon.nist.gov, issuer DigiCert Global G2 TLS RSA SHA256 2020 CA1, valid 2026-10-21 to 2027-03-20, seen on
pulses 2030298–2030303 of 2026-11-16, served by `/beacon/2.0/certificate/<certificateId>`. It is a TLS certificate of a
public CA, so certificate transparency logs may hold an independent copy (not checked here).

**4. The verdict and its two bounds.** Bounds are stated only when the entry and every pulse pass, with T the latest
`timeStamp` of the named pulses and π the `period` of that pulse:

- `not_before` = T, **against anyone but the beacons' operators.** The draft NIST IR 8213 (§3.3, promises 1 and 2)
  promises that `outputValue` stays unpredictable to outsiders until T. An entry that carries it was put together after
  T, unless the operator, or whoever controls its engine or key before T, disclosed the value early. A key compromised
  after T does not touch the bound: the value was public from T on.
- `not_before_operator_promise` = T − π, **against the operator, only if it kept its freshness promise** (§3.3,
  promise 3: `outputValue` depends on randomness sampled less than one period before T). This is a promise of the
  operator, not something a verifier checks.
- **Against an operator that breaks its promises there is no bound.** Every input of `outputValue` is in the operator's
  hands (its local random values, the timestamps, an external value that is all zeros on chain 2 on 2026-11-16) and the
  signature is deterministic, so it can compute the value of a future pulse long before T. The commitment of step 8
  proves that the local random value was fixed at the latest when the predecessor was published, at T − π, not that it
  was unknown earlier.

**5. The window.** A "not before" and a "not after" bound over the same bytes give the interval in which they were put
together. The upper bound is the RFC 3161 token of an evidence pack, checked by §11 with pinned TSA certificates as the
pack's verify does it (§10, v0.8): the pack is admitted, `sealed_content` is `verified` (else `pack_not_valid`),
`time_anchor` is `verified` (else `time_anchor_not_verified`), the pack is `valid` (else `pack_not_valid`), and the
ledger is one of the pack's files with the same bytes (its SHA-256 equal to the value `file_digests_sha256` gives it,
else `ledger_not_in_pack`). The token binds the manifest, the manifest binds the ledger's bytes and every entry: the
token's genTime (`rfc3161.tsa_check.gen_time`) is an upper bound for the entry. The window is [T, genTime] against anyone
but the operator, [T − π, genTime] under the operator's freshness promise. A window whose lower bound is after its upper
bound, genTime < T − τ, is refused as `window_inverted`, τ being a clock tolerance the caller gives (`clock_tolerance_s`,
`--clock-tolerance <seconds>`, an integer ≥ 0, default 0); with genTime in [T − τ, T] the window is reported as one
instant at T. The TSA's `accuracy` is not read (§11) and is not added: a caller that needs it gives it in τ. The
entry's own `ts` is a claim of its writer and is not used. The window is what shows a later change: an entry rewritten
after T and rehashed still carries the values, but its ledger is no longer the one the pack's token binds.

*Width.* The window is "fresh" when genTime − T is at most a maximum width the verifier's caller gives
(`max_window_s`, `--max-window <seconds>`, an integer ≥ 0, required with a pack): wider is `window_too_wide`. The caller
chooses it by its own policy; this format gives no default. Without a maximum, a pulse of last year and a token of today
would be a window of a year, true and useless.

*Operation over years.* The token binds the ledger as it was when the pack was made. A provider that wants a window of
minutes for every payment makes a pack (and gets a token) at least once per such period; the verifier receives, years
later, the prefix of the ledger as it was packed (the ledger truncated after the last entry of that pack), the pack, the
pulses and the pins. Renewing the token before its certificate or algorithms expire (RFC 4998, ETSI EN 319 102-1) is not
part of this version.

*Pins.* The beacon's certificates, the TSA's certificates and CRLs, the Trusted List snapshot, and the witness and log
keys of rule 6 are given by the verifier's caller, never read from the evidence: a beacon certificate carried with the
proof lets its author run a beacon of its own (with the certificate pinned, such a pulse is `certificate_mismatch` or
`signature_invalid`). The TSA's revocation is checked with the CRLs the caller pins (§11 step 8, `--tsa-crl`); without
them the receipt's window says `tsa_revocation: "not_checked"`. The window's `tsa_sha1_signature_legacy` is the token's
`sha1_signature_legacy` (§11 step 7): `true` when a certificate of the TSA chain is signed with SHA-1, accepted as
legacy verification (NIST SP 800-131A Rev. 2) and not hidden from the person who reads the receipt.

*Qualified or not.* Only a qualified electronic time stamp has the presumption of eIDAS Art. 41(2). The window says
`tsa_qualification: "qualified"` only when the caller pins a trusted list of ETSI TS 119 612 (`--tsa-trusted-list
<xml>`) and, at genTime, the SHA-256 of the certificate that signed the token (§11 step 6) equals the SHA-256 of an
`X509Certificate` in the `ServiceDigitalIdentity` of the `ServiceInformation` of a `TSPService` whose entry in force at
genTime (among `ServiceInformation` and its `ServiceHistoryInstance` entries, the one with the latest
`StatusStartingTime` not after genTime) has `ServiceTypeIdentifier` `http://uri.etsi.org/TrstSvc/Svctype/TSA/QTST` and
`ServiceStatus` `http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted`. A QTST service whose history instances have
two equal starting times or are not in descending order (ETSI TS 119 615 PRO-4.3.4-03A) is `indeterminate`; otherwise
`not_qualified`. Since v0.10 `qualified` also needs the token's qualified statement (§11, Regulation (EU) 2025/1929): a
signer granted in the list whose token lacks it is `not_qualified`, and the window's `tsa_qualification_reason` says
`qualified_statement_missing` or `qualified_statement_malformed` (`null` in every other case). Without a list, `not_checked`, and the window is an upper bound from "an RFC 3161 TSA", nothing more. A
list that cannot be read as XML of that form is `trusted_list_malformed`. The list's own XML signature is not checked:
the caller pins it as it pins a certificate.

**6. Fixed in one history.** A window proves when the entry was composed, not that it is the only entry composed. After
one pulse an author can compose N ledgers with N different amounts and cover them all with one token or N tokens: every
one gives a valid window (Athena measured 100 of 100 on 2026-11-16). A tip or checkpoint signed by the author does not
close this (the author signs one for each variant); a witness that cosigns one append-only history per log does, but only
if it cosigned before the question could be chosen: an independent review measured on 2026-11-16 20 variants, each with
its own pack, and a witness cosignature added 400 days later on the variant chosen, all 20 then reported as fixed by
v0.10 as it was. So the entry is fixed in one history only when the witnessed checkpoint is **inside the evidence pack**
and therefore under the token: `--checkpoint <file>`, `--log-vkey <vkey>`, `--witness-vkey <vkey> ...` (needs `--pack`).
Checks, in order: the checkpoint file is read (a regular file of at most 1 MiB, else `checkpoint_malformed`); its
SHA-256 is the value `file_digests_sha256` of the pack gives to one of its files (`checkpoint_not_in_pack`); the
pinned keys can be parsed and keep §16's rules on roles (`checkpoint_malformed`); the note is a signed note, signed by a
pinned log key, whose origin is the pinned log's (`checkpoint_log_not_trusted`: the checkpoint does not come from that
log); it carries at least `--min-witnesses` (default 1) cosignatures of pinned witnesses, by the rules of §16
(`checkpoint_not_witnessed`); no counted cosignature carries a timestamp after genTime
(`checkpoint_cosigned_after_gen_time`: the witness's clock and the TSA's contradict each other); its size N covers the
entry (N > idx, `checkpoint_not_covering_entry`); its root is the RFC 6962 root of the first N entries of this ledger
(`cryptovalid_merkle`, leaves = the canonical entries; a size larger than the ledger is `checkpoint_root_mismatch`).
Then `unique` = `{"status": "witnessed", "witnesses", "checkpoint_size", "origin"}`: as of genTime the entry was at its
position in the history the pinned witnesses cosigned. Other entries of that history may carry the same pulse, so the
scope keeps `not_unique` (rule 7). A witness that cosigns two histories (dishonest or compromised), a log with two keys
(two origins, two histories), and the revocation of a witness's or log's key are outside what this proves; several
pinned witnesses narrow the first. The third party can also be a qualified electronic ledger: Commission Implementing
Regulation (EU) 2025/2531 (Annex, REQ-7.5-03 and REQ-7.5-04) asks of its provider a unique sequential chronological
ordering of data records by cryptographic links "based in hash lists or hash trees" (SHA-256, SHA3-256 or higher), the
origin of data records established by advanced electronic signatures or seals based on qualified certificates (CAdES,
XAdES or JAdES), and, where digital signatures are used, the provider's signing keys in a certified secure cryptographic
device. This format's own ledgers are not qualified electronic ledgers (their tips
and checkpoints are not AdES under qualified certificates); this verifier checks only the witness.

**7. Scope, closed.** The receipt carries `scope` = `{"proves": [...], "does_not_prove": [...]}`, sentences taken from
this closed list, never composed:

- proves `composed_after_pulse`: "the entry's bytes, with every member of the payment, were put together after the
  pulse's timeStamp, for anyone but the beacon's operator";
- proves `stamped_before_gen_time` (with a window): "the same bytes existed at the TSA's genTime";
- proves `stamped_by_qualified_tsa` (with `tsa_qualification` `qualified`): "the TSA's certificate was a granted qualified
  timestamp service, at genTime, in the pinned EU Trusted List snapshot, and the token carries the qualified statement
  of Regulation (EU) 2025/1929";
- proves `unique_under_pinned_witness` (with `unique.status` `witnessed`): "the entry is the one at its position in the
  history the pinned witnesses cosigned before the TSA's genTime";
- does not prove `not_execution`: "that a payment service provider executed the payment";
- does not prove `not_unique` (always): "that this is the only entry composed after that pulse (a witness fixes the entry
  at its position, not the other entries that carry the same pulse)"; measured by NEMESIS on 2026-11-16: two payments
  of one witnessed history carrying the same pulse both verify with `unique.status` `witnessed`;
- does not prove `not_ownership`: "that the IBANs belong to the parties";
- does not prove `commitments_not_opened` (while a commitment of the entry is not in `disclosed`): "that a commitment not
  disclosed here opens to an IBAN, a name or an identifier";
- does not prove `payment_id_uniqueness` (one entry verified without its ledger, rule 14): "that no other entry of the
  ledger carries the same payment_id";
- does not prove `currency_not_checked` (no currency table pinned): "that the currency is an ISO 4217 code and the
  amount carries exactly its minor units";
- does not prove `not_operator`: "anything against the beacon's operator beyond its freshness promise";
- does not prove `not_qualified` (unless `stamped_by_qualified_tsa`): "that the upper bound is a qualified electronic
  time stamp";
- does not prove `not_legal_beacon`: "that the beacon value is a legal timestamp: it is technical evidence of not
  before".

`record_complete` is true only when a window is verified, the TSA's revocation was checked (`tsa_revocation` not
`not_checked`), and `unique.status` is `witnessed`; it does not require disclosures, a qualified TSA or several beacon
sources, and the scope says what remains.

**8. The algorithm, in one place, and its result codes.** For an implementer who does not read this repository's code.
Inputs: the ledger bytes, the entry's `idx`, one pulse pair per beacon value, the pinned beacon certificates; optionally
the evidence pack with its pinned TSA certificates, CRLs, Trusted List, maximum width and clock tolerance; the
checkpoint with its pinned log and witness keys; disclosures. Steps, in this order, the first failure ending the run
(every implementation gives the same code for every combination of faults):

1. Ledger bytes: unreadable `input_unreadable`, more than 64 MiB `input_too_large`; §5 steps 1–4 `ledger_invalid`; no
   entry of `idx` `entry_not_found`.
2. Payment profile, in the order of §18 "Order of the profile's checks" (`entry_not_a_payment`, `payment_malformed`,
   `source_not_supported`); then `payment_id` unique among the ledger's payment entries (`payment_id_not_unique`).
3. Disclosures: each read in the order given (`input_unreadable`, `input_too_large`, `disclosure_malformed`), two for one
   member `disclosure_malformed`; then each checked in the order given (`disclosure_iban_invalid`,
   `disclosure_mismatch`); then the required disclosures of rule 15 (`required_disclosure_missing`).
4. Pulses, pair by pair in the order of `beacons`: the named pulse then its predecessor read by rule 2
   (`input_unreadable`, `input_too_large`, `pulse_malformed`); then rule 3 steps 1–9 for that pair, step 4 reading the
   pinned certificates (`certificate_malformed`). `cryptography` absent: `not_evaluated` / `backend_missing`.
5. Window, rule 5, in the order written there (`pack_not_valid`, `time_anchor_not_verified`, `pack_not_valid`,
   `ledger_not_in_pack`, `window_inverted`, `window_too_wide`, `trusted_list_malformed`).
6. Fixed in one history, rule 6, in the order written there (`checkpoint_malformed`, `checkpoint_not_in_pack`,
   `checkpoint_malformed`, `checkpoint_log_not_trusted`, `checkpoint_not_witnessed`, `checkpoint_cosigned_after_gen_time`, `checkpoint_not_covering_entry`,
   `checkpoint_root_mismatch`).
7. Receipt: `status` (`verified` | `invalid` | `refused` | `not_evaluated`), `reason` (one code above or null), `bounds`
   (rule 4), `window`, `unique`, `disclosed`, `scope` (rule 7), `record_complete`.

With one entry and a proof (rule 14), step 1 is rule 14's items 1-2 (`input_unreadable`, `input_too_large`,
`entry_malformed`, `entry_hash_mismatch`, `proof_malformed`, `proof_mismatch`) and step 6 ends with rule 14's item 4
(`proof_mismatch`, `inclusion_proof_invalid`).

Status `refused` (malformed input, exit 2) has exactly the codes `input_unreadable`, `input_too_large`,
`entry_not_a_payment`, `payment_malformed`, `source_not_supported`, `disclosure_malformed`, `pulse_malformed`,
`certificate_malformed`, `checkpoint_malformed`, `trusted_list_malformed`, `entry_malformed`, `proof_malformed`; every other code is `invalid` (exit 1).
Conformance vectors: `spec/vectors/beacon/conformance.json`, at least one case for every code of this rule and a
complete record.

**9. Security considerations.**

- *The operator.* A single source gives no lower bound against an operator that does not keep its promises (rule 4).
  Values of several independent beacons would reduce the trust to "not all their operators colluding"; `beacons` is a
  list for that purpose, and v0.10 implements one source.
- *Many values.* One pulse admits many records; rule 6 fixes the entry only through a witnessed checkpoint inside the
  pack.
- *Pins.* Every key, certificate and list is the verifier's caller's (rule 5, "Pins"). A record that is complete needs
  several of them (beacon certificate, TSA certificate, CRL, log key, witness key, maximum width): a single "trust
  profile" file that holds a circuit's anchors and thresholds is not part of this version.
- *Revocation.* The TSA's revocation is checked only with pinned CRLs (§11 step 8); the beacon certificate's, the
  witness's and the log's are not.
- *Window width and clocks.* The caller chooses the maximum width and the clock tolerance (rule 5).
- *Guessable fields.* The 128-bit salts of §18 keep the committed values, and the record salt the members in clear, from
  being searched behind a hash given to third parties.
- *Erasure.* See §18 "Personal data": a statement of the provider, under EDPB Guidelines 02/2025 v2.0 §52.
- *Legal weight.* The beacon value is technical evidence; only a token whose TSA is qualified in a pinned Trusted List
  snapshot is reported as qualified (rule 5).

**10. Prior art.** The idea is not new, and this section does not present it as new: it is a profile for payments that
combines existing standards (the NIST beacon, RFC 3161, C2SP checkpoints and witnesses, ISO 13616, ISO 4217). Tierion's
Chainpoint put the value of the NIST beacon into every proof so that a proof was created after the beacon's timestamp,
and replaced the NIST beacon with drand (a beacon run by several operators, the League of Entropy) on 2020-07-09, citing
the NIST beacon's single operator, its once-a-minute cadence and intermittent reliability; Tierion's own account of 2020
dates the first announcement to May 2017 (W. Vaughan, "Tierion Joins the League of Entropy — Replaces NIST Randomness
Beacon with Drand in Chainpoint Proofs", medium.com/tierion, 2020-08-10, read on 2026-11-16 in the Internet Archive's
copy of 2020-09-25: the page answered 403 to a direct read; the 2017 announcement itself was not found). A formal
treatment of timestamping that separates security against postdating and against backdating is Abadi, Ciampi, Kiayias,
Zikas, "Timed Signatures and Zero-Knowledge Proofs — Timestamping in the Blockchain Era", IACR ePrint 2019/644 (read on
2026-11-16).

**11. Command.** `cryptovalid-verify beacon <ledger> --entry <idx> --pulse <file> --previous <file> [--pulse <file>
--previous <file> ...] --certificate <file> [--certificate <file> ...] [--pack <dir> --tsa-cert <pem> ... --max-window
<s> [--clock-tolerance <s>] [--tsa-crl <crl> ...] [--tsa-trusted-list <xml>] [--checkpoint <note> --log-vkey <vkey>
--witness-vkey <vkey> ... [--min-witnesses <n>]]] [--disclosure <file> ...] [--require-disclosure <member> ...]
[--currency-table <file>]`; for
one entry without its ledger (rule 14), `--entry-file <entry> --proof <proof>` in place of `<ledger> --entry <idx>`, with
`--pack` and `--checkpoint`. The i-th `--pulse` and the i-th
`--previous` are the pair of the i-th element of `beacons`. Each `--disclosure` is a JSON file holding one disclosure of
§18 (read as the pulses are, at most 64 KiB); the receipt lists the members disclosed and matched, never the values.
Options that need `--pack` without it, `--log-vkey` and `--witness-vkey` without `--checkpoint` and the reverse, a
number of `--previous` other than of `--pulse`, a value option given twice or given empty (§17) are usage errors (exit
2). The receipt is one JSON object on stdout. Exit 0 `verified`, 1 `invalid` or `not_evaluated`, 2 a usage error or a
`refused` input, 74 a receipt not written whole or a check that could not run (§10). `auto` (§12) does not change: a
ledger carrying a payment entry is a ledger.

**13. References, as checked on 2026-11-16.** Each with the version in force and where it was read; "not confirmed"
marks what could not be checked against its issuer today.

| Reference | Version and status | Read on |
|---|---|---|
| Regulation (EU) 2023/1113, Art. 4, 5, 26 | OJ L 150, 9.6.2023; "In force", no consolidated amendment listed | EUR-Lex (ELI page and status page) |
| Regulation (EU) 2024/1624, Art. 77 | "In force"; applies from 2027-07-10 (Art. 90, as read) | EUR-Lex |
| Regulation (EU) No 260/2012, Art. 5c | inserted by Regulation (EU) 2024/886 ("In force"); compliance 2025-10-09 (euro), 2027-07-09 (others) | EUR-Lex (2024/886) |
| Commission Implementing Regulation (EU) 2025/2531 of 16 December 2025, Annex | "In force" | EUR-Lex |
| Regulation (EU) No 910/2014 (eIDAS), Art. 41(2) | consolidated version of 2024-10-18 (after Regulation (EU) 2024/1183): Art. 41(2) unchanged | EUR-Lex |
| Regulation (EU) 2016/679, Art. 5(1)(c), 17 | OJ L 119, 4.5.2016; in force | EUR-Lex (ELI page; consolidation not checked) |
| EDPB Guidelines 02/2025 | version 2.0 adopted 2026-07-07 (its version history: 1.1 of 2025-04-08, 2.0 after public consultation); no later version found | edpb.europa.eu, PDF sha256 e90cc80ef9ba6c26… |
| NIST IR 8213 | Initial Public Draft, May 2019, never finalised; NIST planning note of 2025-01-23: "NIST continues to develop this publication" | csrc.nist.gov |
| RFC 3161 | Proposed Standard (2001), updated by RFC 5816 (ESSCertIDv2); not obsoleted (checked on 2026-11-18) | rfc-editor.org |
| RFC 5816 (§11 step 7) | Proposed Standard (March 2010); not updated, not obsoleted (checked on 2026-11-18) | rfc-editor.org |
| RFC 5652 (§11 step 7) | Internet Standard (2009), updated by RFC 8933 and RFC 9629; not obsoleted | rfc-editor.org |
| RFC 2634 (§11 step 7) | Proposed Standard (1999), updated by RFC 5035; not obsoleted (checked on 2026-11-18) | rfc-editor.org |
| RFC 5035 (§11 step 7) | Proposed Standard (2007); not updated, not obsoleted (checked on 2026-11-18) | rfc-editor.org |
| RFC 4055 (§11 step 7, RSASSA-PSS parameters) | Proposed Standard (June 2005), updated by RFC 5756; not obsoleted (checked on 2026-11-17) | rfc-editor.org |
| Commission Implementing Regulation (EU) 2025/1929 (§11, qualified statement) | OJ L 30.9.2025; in force since 2025-10-20; no amending act listed by CELLAR on 2026-11-17 (CELEX 32025R1929) | CELLAR, English OJ text |
| ETSI EN 319 422 (§11, qualified statement) | V1.1.1 (2016-03), the version the Regulation names, as adapted by its Annex | etsi.org, PDF sha256 b8dce6e415c90687… |
| RFC 3739 (§11, qcStatements) | Proposed Standard (March 2004); not updated, not obsoleted (checked on 2026-11-17) | rfc-editor.org |
| NIST IR 8547 (§15) | final, October 2026 (document history: final 10/27/26; the 2024 initial public draft superseded) | csrc.nist.gov, PDF sha256 3049cdfdd7c20417… |
| NIST SP 800-131A (§11 step 7, SHA-1) | Rev. 2, March 2019, final; Rev. 3 initial public draft of 2024-10-21 (comments closed 2024-12-04), not final on 2026-11-17 | csrc.nist.gov |
| RFC 5280 | Proposed Standard (2008), updated by RFC 6818, 8398, 8399, 9549, 9598, 9608, 9618, 9925, 10007; not obsoleted | rfc-editor.org |
| RFC 6962 | Experimental (2013), obsoleted by RFC 9162: cited only for the Merkle tree hash that C2SP tlog-checkpoint and this format's §9 use | rfc-editor.org |
| RFC 9562 (UUID) | Proposed Standard (May 2024), obsoletes RFC 4122 | rfc-editor.org |
| RFC 4998 | Proposed Standard (2007), not updated | rfc-editor.org |
| ISO 4217 list one (§18 currencies, the caller's pinned table) | published 2026-09-17 (attribute `Pblshd`), read on 2026-11-17; not distributed here | six-group.com |
| ISO 13616-1, ISO/IEC 7064 | not confirmed: the ISO catalogue was not read; the rule applied is the one stated in §18 | — |
| ETSI TS 119 612, TS 119 615, EN 319 102-1 | not confirmed: versions not re-read; the rules applied are the ones written in rule 5 | — |
| C2SP tlog-checkpoint, tlog-witness | as in §16 (C2SP commit 09f3e519fe79, read 2026-11-15) | github.com/C2SP |

**14. One entry without the ledger.** Rule 5 binds the token to the whole ledger file, so a third party that verifies
one payment receives every other payment of that ledger, with their amounts and identifiers in clear (found on
2026-11-16 by a sample built for a public-sector receipt). A provider can instead give one entry and an inclusion proof:
`cryptovalid-verify beacon --entry-file <entry> --proof <proof> ...` (library `verify_beacon_entry_proof`), with `--pack`,
`--checkpoint`, `--log-vkey` and `--witness-vkey` required. The pack need not hold the ledger: it holds the witnessed
checkpoint (rule 6), whose RFC 6962 root covers every entry up to its size, and the token over the pack is the upper bound
for all of them. The third party receives the entry, the proof, the pack with the checkpoint, the pulses and the
disclosures; no other entry of the ledger, and the test of this rule checks that the other entries are absent from
everything it is given. Checks, replacing step 1 of rule 8 and completing step 6:

1. **The entry**: a UTF-8 JSON document of at most 1 MiB with no white space around it but one final line feed
   (this rule and item 2), whose value is one entry of §2 with
   the closed members of §2.1 (`entry_malformed`); its `self_hash` is the SHA-256 or SHA3-256 of its canonical form (§3;
   `entry_hash_mismatch`).
2. **The proof**: a UTF-8 JSON document of at most 64 KiB, read the same way, whose value is exactly `{"format":
   "cryptovalid-inclusion-proof/1", "leaf_index": <integer ≥ 0>, "tree_size": <integer ≥ 1>, "hashes": [<64 lowercase
   hex>, ...]}` with `leaf_index` < `tree_size` and at most 64 hashes (`proof_malformed`); `leaf_index` equals the entry's
   `idx` (`proof_mismatch`).
3. Steps 2-5 of rule 8, without the uniqueness of `payment_id` (the ledger is not given: the scope says
   `payment_id_uniqueness`) and without `ledger_not_in_pack`.
4. Rule 6 on the checkpoint, then: `tree_size` equals the checkpoint's size (`proof_mismatch`), and the Merkle audit path
   of RFC 6962 §2.1.1 for the leaf = the entry's canonical form at `leaf_index` gives the checkpoint's root
   (`inclusion_proof_invalid`).

The entry's `prev_hash` is not checked (its predecessor is not given): the chain is shown by the inclusion under a
checkpoint the log signed and the witnesses cosigned, not by `prev_hash`. What the third party learns of other entries:
the predecessor's `self_hash` (in `prev_hash`) and the proof's node hashes, hashes over entries that carry a random
`record_salt`; no member of them. A pack holds at least one ledger file (§10, measured: a pack with none is not valid): the provider may put there a ledger of its
checkpoints, which carries no payment. A provider makes the proof with
`cryptovalid_beacon.inclusion_proof(ledger, idx, tree_size)`.

**15. Required disclosures.** A verifier's caller can require that named commitment members be opened:
`required_disclosures=[...]`, `--require-disclosure <member>` (repeatable; a name outside the commitment members of §18 is
a usage error). After the disclosures of step 3 of rule 8, each required member that is not in `disclosed` is
`required_disclosure_missing` (invalid): the entry has no such member, or no disclosure of it was given. Without the
option nothing is required, and the scope says which commitments stay closed (`commitments_not_opened`).

**12. Limits of this version, stated** (each with its reason): the trust profile file (rule 9); the token's renewal
(rule 5); `accuracy` (rule 5: read by §11 only as part of the token, not used); the verification of the payee's outcome
(§18: its codes not read on the primary text); drand (no grammar measured yet); the beacon certificate's revocation (no
CRL of the beacon's TLS certificate is meaningful for its signatures); the test suite of this section run without
`cryptography` skips the checks that need RSA and X.509 (they cannot run) and runs the rest. **Origin by a qualified
signature or seal**: the checkpoint of rule 6 is signed with the log's Ed25519 key (§13, §16), not with an advanced
electronic signature or seal based on a qualified certificate. For a printed mark on an analogue copy of an
administrative document, Italian law (D.Lgs. 82/2005, CAD, art. 23 c. 2-bis, text in force on 17/11/2026 as
normattiva.it shows it, the act's last update published on 22/10/2026; read on 2026-11-17) refers to criteria set by
AgID guidelines ("Linee guida") and asks whoever affixes the mark to make free verification means available on its
institutional website; the AgID Circolare n. 62 of 30 April 2013, "Linee guida per il contrassegno generato
elettronicamente" (the PDF AgID publishes, sha256 14024134256e5ac3…, read on 2026-11-17), asks a qualified electronic
signature or a digital signature on the mark's content when the original is not signed (§6.1, §6.2). The Circolare
still refers to "articolo 23-ter, comma 5" of the CAD, which normattiva.it shows as "COMMA ABROGATO DAL D.LGS. 26 AGOSTO
2016, N. 179"; the printed mark is now in art. 23 c. 2-bis. Whether a later AgID guideline replaces the Circolare was
not confirmed. A CAdES/JAdES signature or qualified seal over the checkpoint is a planned extension, not part of
v0.10; this format's output is not such a mark. **A paper pointer** (the text of a printed code that points to the
evidence) is out of scope in v0.10: its fields, alphabet and comparison rule are not defined here.

Vectors: `spec/vectors/beacon/` — six consecutive pulses of NIST chain 2 and the beacon's certificate, fetched on
2026-11-16 with their URLs and hashes (`README.md`), a payment ledger derived from them by code (`test_beacon_20261116.py`
rebuilds it and compares), and `conformance.json` with the inputs under `conformance/`: cases with their expected status,
reason and `record_complete`, a complete record (window, revocation checked, witnessed checkpoint in the pack, qualified
TSA), at least one case for every code of rule 8, built by `make_conformance.py` from these files and from a test TSA, CA,
CRL, trusted list and witness made for the purpose (their private keys are not kept); and window cases as data. Every
refused or invalid input is derived by code, never written by hand.

## 20. Rules written after the security review of 2026-11-19 (NORMATIVE since v0.12)

A review of cryptovalid-opencore 0.26.0 on 2026-11-19 (two reviewers working apart, each finding re-run on the
unmodified code before it was accepted) found inputs that changed a verdict, or left the rule a module states, without
any of them being named in this document. Each rule below was written here before the code. Where a format belongs to
someone else, its own text decides and is cited with the version read; where that text is silent, the closed reading
(a refusal with its reason) is taken and said to be this format's choice. Tests: `test_sentry_20261119.py`.

1. **An outbound URL's host is judged as the address the system connects to, not as text** (`cryptovalid_net`, the
   one module through which this package opens a URL). An IP literal is read in every form the system's resolver
   reads: the one-to-four-part forms of `inet_aton`, each part decimal, octal or hexadecimal (`127.1`, `2130706433`,
   `0x7f000001`, `0177.0.0.1`), the forms of IPv6, and an IPv4-mapped IPv6 address as the IPv4 address inside it
   (`::ffff:127.0.0.1`); a non-ASCII host is read in its IDNA form first. A host with a percent sign is refused
   under every policy, the first URL and every redirect alike (`ValueError("url_not_allowed: a percent sign in the
   host ...")`): urllib decodes `%XX` in the host before it connects, so the host judged would not be the host
   reached (measured on 2026-11-20 on the first draft of this rule: a redirect to `http://%31%32%37.0.0.1/` reached
   127.0.0.1). The `%25` zone of an IPv6 literal is refused with it: RFC 9844 (Proposed Standard, August 2025, read
   at rfc-editor.org on 2026-11-20) obsoleted RFC 6874 and "reverts the change that it made to the URI syntax".
   A redirect is never followed from a host
   that is not loopback to a loopback address (127.0.0.0/8, ::1), to the unspecified address (0.0.0.0, ::) or to a
   link-local address (169.254.0.0/16, fe80::/10): `ValueError("url_not_allowed: a redirect from a remote host to a
   ...")`. The target of such a redirect that is a name is resolved (`getaddrinfo`) and refused when any of its
   addresses is one of the three. The origin of a redirect is the host of the request being redirected, at every hop,
   and it counts as loopback only when the first URL of the call was loopback too. Until 0.26.0 the host was compared
   as a string against `localhost`, 127.0.0.0/8 and `::1`: a redirect from a remote host to `http://127.1/`,
   `http://0.0.0.0/`, `http://2130706433/`, `http://0x7f000001/`, `http://0177.0.0.1/`, `http://[::ffff:127.0.0.1]/`
   or `http://[::]/` was followed (measured on 2026-11-19, Linux, Python 3.11: the system resolves the first, third,
   fourth and fifth to 127.0.0.1 and a service on 127.0.0.1 answered the redirected request). Not closed by this rule,
   stated: the name is resolved when the redirect is judged and again by the connection, and an answer that changes in
   between is not seen; a name that does not resolve here is left to urllib (a proxy of the environment resolves it,
   and without a proxy the connection fails on the same lookup); a redirect to a private address (10.0.0.0/8,
   172.16.0.0/12, 192.168.0.0/16, fc00::/7) is followed as before; the first URL of a call is the caller's and is not
   refused for its address (`http://0.0.0.0/` is not loopback, so plain http to it is refused where only loopback
   http is allowed, as before).
2. **A credential stays with the origin it was given to.** A redirect to another origin (scheme, host and port, the
   default port of the scheme counted, the host compared as an address when it is one and without case otherwise) is
   refused when the request carries a header outside a closed list of headers that name no credential (`Accept`,
   `Accept-Encoding`, `Accept-Language`, `Content-Length`, `Content-Type`, `User-Agent`): `ValueError("url_not_allowed:
   a redirect to another origin for a request that carries <header names> ...")`, the names without their values. A
   redirect to the same origin, and one of a request that carries only headers of the list, is followed as before.
   Refused and not stripped: a signing or key-management endpoint that redirects elsewhere is a fact its caller has to
   see, and the request without its credential would fail there with another error. Until 0.26.0 urllib's rule
   applied, which copies every header except the content headers: `X-Vault-Token`, `Authorization` (AWS SigV4, NetHSM
   Basic, a QEAA bearer token) and `X-Amz-Security-Token` went to the host named by the answer (measured on
   2026-11-19 with a 302 from one host to another). `Proxy-Authorization` is not judged by this rule and is never
   copied to a redirected request, to the same origin or to another: RFC 9110 §11.7.2 (Internet Standard, June 2022,
   read at rfc-editor.org on 2026-11-19), it "applies only to the next inbound proxy". urllib puts that header among
   the request's own when the proxy of the environment carries credentials, and puts it again on the redirected
   request when that one goes through the proxy; copied by the redirect as well, it went to a host reached without
   the proxy. Without this exception the rule would refuse every redirect to another origin behind such a proxy.
3. **JCS is applied only to numbers that are IEEE 754 doubles.** `cryptovalid_acta.jcs` is the one RFC 8785
   serializer of this package, used for formats defined elsewhere (ACTA receipts, Vaara receipts, APS action
   references and accountability records, the Cedulon effect extract and inputs); the ledger profile of §3 is not JCS.
   It refuses an integer that is not exactly an IEEE 754 double, with a `ValueError` that names it, when signing and
   when verifying alike. RFC 8785 §3.1: "JSON number data MUST be expressible as IEEE 754 [IEEE754] double-precision
   values. For applications needing higher precision or longer integers than offered by IEEE 754 double precision, it
   is RECOMMENDED to represent such numbers as JSON strings"; §3.2.2.3 serializes that double as ECMAScript does; RFC
   7493 §2.2, the I-JSON subset RFC 8785 constrains its data to: "An I-JSON sender cannot expect a receiver to treat an
   integer whose absolute value is greater than 9007199254740991 (i.e., that is outside the range [-(2**53)+1,
   (2**53)-1]) as an exact value" (both read at rfc-editor.org on 2026-11-19). An integer beyond that range that IS a
   double (2^53, 2^60, 10^20) is data RFC 8785 accepts, and is serialized as before, as ECMAScript writes it. Until
   0.26.0 an integer beyond ±2^53 was rounded to the nearest double and then serialized: 2^53 and 2^53+1 gave the same
   bytes, so a Vaara receipt signed over `9007199254740992` verified after the number in the file was changed to
   `9007199254740993`, and the caller read from the verified receipt a value nobody signed (measured on 2026-11-19;
   the same collision in `cryptovalid_aps.payload_ref_v2` and in the digests of a Vaara predecessor and evidence).
   A declared difference inside this document: the ledger profile of §3 refuses every integer outside ±(2^53−1), in
   all six verifiers, unchanged; that is this format's own rule for its own entries, and this rule is RFC 8785's for
   the formats that name it. No verifier of this repository in another language implements JCS (searched on
   2026-11-19 in `verifiers/js`, `go`, `java`, `rust`, `swift`), and `spec/vectors/canonical_vs_jcs.json` holds no
   integer beyond ±(2^53−1): neither changes.

Rules 4 to 6 are about `cryptovalid_cedulon`, an experimental reader of a format that is not this one. Its texts, read
on 2026-11-19 at datatracker.ietf.org and www.ietf.org/archive/id: draft-dogru-cedulon-decision-profile-04 (5 October
2026, active; the reader was written from -03), which cites as [CEDULON] draft-dogru-cedulon-09 (6 September 2026;
the datatracker marks it replaced by draft-dogru-cedulon-core, -checkpoint and -threats; core is at -04, 7 October
2026; the reader was written from -08); and the README and verifier of verax-ai/verax at c626c68 (2026-11-16,
Apache-2.0; read, nothing copied). Only the three points below were compared with those versions: the reader as a
whole is still the reader of -03 and -08, and what -04 changed elsewhere (a separate checkpoint key, among others) is
not judged here.

4. **What the `control` and `approval-signature` stages read is bound by a signature.** They read a record's
   context (the `inputs` member of its row in `inputs.jsonl`) only when the record's signed `inputsHash` is not null
   and the row hashed to it at `inputs-binding`; a record whose `inputsHash` is null has no context for these stages.
   An inputs row whose `ref` is not the `ref` of a record with a non-null `inputsHash` is refused: `INVALID`, stage
   `inputs-binding`, "no record's signed inputsHash binds it". Sources: profile-04 §4.2, "inputsHash, when not null, is
   the SHA-256 of whatever further context the Decider consulted"; its "Changes from -03" leaves how that context "is
   presented beside the record" to the deployment; the Verax test-vector README names the stage `control` as "an
   allow inside a halt window opened by a signed halt record". None of them says what a row beside a null
   `inputsHash` is: the refusal is this reader's closed reading. Until 0.26.0 the two stages read any row by `ref`: a
   ledger that was `INVALID` at `control` (an allow inside a halt window) became `VALID` when one line
   `{"ref": <that allow>, "inputs": {"control": {"action": "resume"}}}` was added to the unsigned file (measured on
   2026-11-19). Seen while reading and not changed: Verax's verifier at c626c68 takes the halt and resume from the
   signed claims (`subject` `verax.halt` / `verax.resume` with `effectClass` `verax.control`), not from the inputs
   row; this reader still takes them from the bound row, as its vectors' layout gave them on 2026-10-03.
5. **A ref that repeats on a side is `duplicate-ref`, and the ledger is not valid.** draft-dogru-cedulon-09 §11.4
   step 7 (core-04 §12.1 step 7, the same words): "A ref that appears more than once on either side MUST be reported
   as a repeated reference (MUST-T10-6). The identifier duplicate-ref SHOULD be used for this condition", and its
   table of findings gives `duplicate-ref` the effect "audit fails"; profile-04 §6.1 (and -03 §6.1): "A ref that
   appears more than once on a side is duplicate-ref as in the core, and the repeating reference is then reconciled
   by count". This reader reports the first finding only, so the repeated ref is the verdict: `INVALID`, stage
   `effect-binding`, `duplicate-ref`, for a ref carried by more than one allow (the records that expect a row; a
   refusal's ref is not on that side) or by more than one effect row over all the extracts presented. Until 0.26.0
   the allows were kept by ref in a map, the last one replacing the others, and rows were then counted: with two
   allows under one ref naming the effects H1 and H2, rows carrying H2 twice were `VALID` — H1 never happened, H2
   happened twice (measured on 2026-11-19). And profile §6.1, "a row whose ref a refusal names is
   effect-against-refusal", is applied as written, also when an allow carries the same ref: until 0.26.0 the allow
   was looked up first, the refusal was never seen, and a deny and an allow under one ref with one row were `VALID`
   (found on 2026-11-19 by the generated test of this rule, not by the review). The drafts do not say which of the
   two records such a row binds to; the sentence of §6.1 is the one that names the case.
6. **The WebAuthn assertion of an approval is checked against the RP ID and the origin the relying party expects,
   or the result says they were not.** W3C Web Authentication Level 3 (Recommendation, 25 August 2026,
   https://www.w3.org/TR/2026/REC-webauthn-3-20260825/, read on 2026-11-19) §7.2: "Verify that the value of C.origin
   is an origin expected by the Relying Party" and "Verify that the rpIdHash in authData is the SHA-256 hash of the RP
   ID expected by the Relying Party". `verify_ledger` takes `expected_rp_ids` and `expected_origins` (a string or a
   non-empty list of non-empty strings; anything else is a `ValueError`): given, the assertion's `rpIdHash` must be
   the SHA-256 of one of the RP IDs, the `rpId` member beside the assertion, when present, must be one of them, and
   `origin` of the client data must be one of the origins, else `approval-signature` fails. Not given, the check of
   0.26.0 stays (the `rpIdHash` against the `rpId` the assertion itself carries, no check of the origin) and
   `not_verified` names `approval-rp-id` and `approval-origin`, beside `approval-challenge-binding`, which no
   parameter resolves; in that case an assertion with no `rpId` member fails `approval-signature` (it was
   `malformed`), while with `expected_rp_ids` the member is not needed. Until 0.26.0 the RP ID was always the
   assertion's own and `not_verified` did not say so: an
   assertion made for any other relying party with the operator's passkey passed the stage (measured on 2026-11-19
   with an assertion for `evil.example`). The Cedulon drafts do not define the assertion (core-04, Implementation
   Status: "an approval over HTTP carries a passkey (WebAuthn) assertion bound to the held request"), and the pin file
   of the Verax vectors carries no RP ID.
7. **A Date of a Structured Field is "@" and an Integer, read without recursion.** RFC 9651 §4.2.9 (Proposed
   Standard, September 2024, not obsoleted; read at rfc-editor.org on 2026-11-19): after the "@" the parser runs
   "Parsing an Integer or Decimal (Section 4.2.4)" and fails on a Decimal; §4.2.4 fails when the next character is
   neither "-" nor a digit. `cryptovalid_httpdigest` (the `Content-Digest` / `Repr-Digest` check, whose contract is
   "never raises on `field`") called its bare-item parser again after the "@", so "@@...@1" nested once per "@":
   with 5,000 of them `check_digest` raised `RecursionError` (measured on 2026-11-19, Python 3.11) where every other
   field outside the grammar is the outcome `grammar`. The character after "@" is now looked at first; no outcome
   changes for a field the old code answered.

Rules 8 to 11 are about the ingest archive (`cryptovalid_ingest`: the writer `Ingestor`, the verifier
`verify_archive`, `cryptovalid-ingest verify`, the MCP tool `verify_archive`), a layout of this format: these rules
are its own.

8. **With a pinned key, an archive without its HEAD is not ok.** The HEAD manifest (`<prefix>.head.json`) commits to
   the number of sealed segments and to the last tree head: it is what shows that segments were removed from the tail.
   When `expected_pubkey_hex` is given and the archive holds at least one sealed segment, a missing HEAD is the
   failure `head_missing_but_pubkey_expected` (segment `HEAD`), as a HEAD without a signature already was
   (`head_unsigned_but_pubkey_expected`); the warning `no_head_manifest` stays. Without a pinned key a missing HEAD
   is still a warning only: an unsigned HEAD protects against nobody who can write the directory. Until 0.26.0, with
   the key pinned, removing the HEAD together with the last sealed segments and their tree heads left `ok: true`
   with a warning (measured on 2026-11-19: 3 signed segments, the last one and the HEAD removed, `segments_verified`
   2, no failure), while removing only the signature from the HEAD failed. An archive written without a HEAD by a
   version that did not write one is, with a pinned key, not ok from this version on.
9. **On reopening, the writer truncates only a torn tail.** A torn tail is the last line of the active segment when
   it does not end with a line feed: a write that had not returned. Every complete line (one that ends with a line
   feed) must be a JSON object that continues the chain, or blank; one that is not JSON, not UTF-8 or not an object
   makes `Ingestor` raise `ValueError` ("refusing to resume") and leaves the file as it is, as a complete line that
   breaks the chain already did. Until 0.26.0 the first complete line that was not JSON was taken for the torn tail
   and everything from it on was cut: with 10 entries acknowledged and line 3 damaged, reopening removed 7
   acknowledged entries without an error and the remaining 3 verified (measured on 2026-11-19); a complete line that
   was JSON and not an object raised `AttributeError`.
10. **A segment without a tree head is read, and the result says what no tree head covers.** The writer leaves at
    most one segment without `.sth.json`, the last one in order (the active segment; empty after a seal). The
    verifier reads every segment without a tree head under §5 step 0: one that is not the last segment of the
    archive is the failure `unsealed_segment_not_last`; one that holds anything other than blank lines and does not
    verify as a ledger of §2–§5 is `unsealed_segment_chain_fail`; one that verifies adds the warning
    `unsealed_entries: <n> entries in <k> segment(s) without a tree head (<names>) ...`: their chain is verified, no
    tree head, HEAD or signature covers them, and entries removed from their tail are not detectable by this check.
    An empty one adds nothing. A torn tail in the active segment (rule 9) makes the archive not ok until the writer
    reopens it: the verifier does not repair. Until 0.26.0 such a segment was counted (`unsealed_segments`) and never
    read: a file `ledger-000099.jsonl` holding one line that is not an entry, added to a signed archive verified
    with its key pinned, left `ok: true` with no warning about it (measured on 2026-11-19). A signed tip of the active
    segment (`.tip.json`), where the writer keeps one, is checked by `cryptovalid_tip`, not by this verifier.
11. **Member states of the trusted lists are two ASCII letters.** `lotl_member_states` (the library parameter,
    `--lotl-ms`, the MCP argument) is `None`, or a list, tuple or set whose members are strings of exactly two ASCII
    letters, read without case; an empty one means every member state, as before. Anything else — a bare string, a
    code of another length, a path separator, white space, a member that is not a string — is a `ValueError` before
    any file or network is touched, in `verify_archive` whether or not `lotl_check` is set, and in `Ingestor`. The
    codes name the cache file of the trusted-list fingerprints (`~/.cache/cryptovalid/lotl_<codes>.json`): until
    0.26.0 they were joined into that name as given, so `["X/../../../evil"]` named `~/EVIL.json` (measured on
    2026-11-19; with a directory `lotl_X` present in the cache directory, a file placed there was read as the set of
    qualified TSA certificates, and without it the path did not resolve), a member that is not a string raised
    `AttributeError`, and the string `"ES"` was read as the two states `E` and `S`.

12. **One message never stops the MCP server.** `cryptovalid_mcp.py` reads one JSON-RPC message per line. JSON-RPC
    2.0 (jsonrpc.org/specification, updated 2013-01-04, read on 2026-11-19) §5.1: -32700 "Invalid JSON was received",
    -32600 "The JSON sent is not a valid Request object", -32602 "Invalid method parameter(s)", -32603 "Internal
    JSON-RPC error"; §5: when the id could not be detected the response's id "MUST be Null"; §4: an id is "a String,
    Number, or NULL value"; §4.1: "The Server MUST NOT reply to a Notification". Applied: a line that is not UTF-8,
    that holds `NaN` or `Infinity` (RFC 8259 §6: "not permitted"), or that is nested too deep to parse is -32700; a
    reply that carries a lone surrogate taken from the message (an id, a method, a path) is written with JSON
    escapes, never left unwritable; a message that is not an object (an array too: batches are not supported), or
    whose `id` is not
    a string or a number, is -32600 with id null; a `method` that is not a string is -32600; a message with a method
    and no `id` member is a notification: it is not answered and nothing is run for it (until 0.26.0 a `tools/call`
    without an `id` ran the tool and was answered with id null); a message whose `id` is null is a Request, not a
    notification, and is answered (§5: "the Server MUST reply with a Response, except for in the case of
    Notifications"; until 2026-11-20 an unknown method with id null had no reply); a `params` that is not an object
    is -32602; in
    `tools/call` a `name` that is not a string and
    `arguments` that is not an object (`[]`, `""`, `0`, `false` included; `null` and an absent member mean no
    arguments) are -32602; anything else that goes wrong inside the handling of one message is -32603, and the server
    reads the next line. Until 0.26.0 a line holding `[]`, `5`, `null`, a `params` that is an array or a string, a
    tool `name` that is an array, or 100,000 "[" raised out of the loop (`AttributeError`, `TypeError`,
    `RecursionError`) and the server process ended (measured on 2026-11-19); `"arguments": []` was read as no
    arguments and then refused for the required argument that was missing (the same code, another reason).
    `jsonrpc: "2.0"` is still not required of a message: not changed here.

## 21. Rules written after the re-measurement of 2026-11-20 (NORMATIVE since v0.13)

The findings of the review of 0.26.0 (§20) that §20 did not cover were re-run on 2026-11-20 on 0.26.0 and on the
released 0.27.0; each rule below answers one that 0.27.0 still reproduced, and was written here before the code. Where
a format belongs to someone else its own text decides, cited with the version read; where it is silent, the closed
reading is taken and said to be this format's choice. Rules 2, 7 and 8 were widened by the review of the branch on the
same day, before any release; what that review measured is said in each. Tests: `test_remeasure_20261120.py` (35 tests;
29 fail on 0.27.0, the 6 named `*_control` hold what did not change and pass there too).

1. **An inclusion proof longer than its path fails** (`cryptovalid_merkle.verify_inclusion`). RFC 9162 §2.1.3.2
   (Experimental, December 2021, not obsoleted; read at rfc-editor.org on 2026-11-20), step 4a: "If sn is 0, then
   stop the iteration and fail the proof verification." Until 0.27.0 the step was missing: the proof of leaf 5 of a
   tree of 8 leaves verified as leaf 1 of a tree of 4 against the root of the tree of 8; over the trees of 1 to 33
   leaves, 1,416 of the 81,927 pairs (proof of (M, N), claimed (m, n) whose path is shorter) verified, none now. A leaf
   index or a tree size that is not a non-negative integer (a bool included) fails too: until 0.27.0 the index -1 walked
   the path of the last leaf of a tree of 1, 2, 4, 8 or 16 leaves and verified. The algorithm cannot tell a
   tree size the root was not built with when the proof has the length of that size's path: the caller binds the size
   to the root (a signed tree head; the callers in this repository take both from one checkpoint or recompute them).
2. **A key written twice is refused by the signature verifier and by the JWS verifier.** §3: "duplicate object keys —
   a strict parser MUST reject them". `signer.verify_file` (and `signer.py verify`) read each ledger line keeping the
   last of two equal keys: a line with a key written twice, the signed value last, verified (4 of 8 generated lines,
   one key repeated at the top and inside `data` of each of the 4 entries of a signed ledger), while `verifier.py`
   refused the same file. Such a line is now the failure `duplicate_key` at its index. `cryptovalid_jws.verify`:
   RFC 7515 §10.12 (read at rfc-editor.org on 2026-11-20) lets a JWS parser "either reject JWSs with duplicate Header
   Parameter names" or keep the last; this format rejects (`header_duplicate_key: <name>`, before the signature, 22 of
   40 generated headers were accepted); the payload is a ledger record, read under §3 (`payload_duplicate_key:
   <name>`, with `signature_valid: true`: the signature was checked; 80 of 80 accepted until 0.27.0); the name is
   reported in ASCII. The tree heads and the HEAD of an ingest archive, and the files of `cryptovalid_receipt.py verify`,
   are read the same way: a signed tree head or HEAD with a key written twice, the signed value last, left
   `verify_archive` ok with the signer pinned (measured on 0.27.0), and is now `sth_unreadable: duplicate_key` or
   `head_unreadable: duplicate_key`; a receipt file or an `--entry-json` file with a key written twice was verified
   (exit 0), and is now `receipt unreadable: duplicate_key` or `entry unreadable: duplicate_key`, exit 1. A signed tip
   was already read by the strict parser (`tip_unreadable`).
3. **A document type declaration is refused by the XML parser.** `fundcert_canonical` parses the XML of holdings files
   with `defusedxml` when it is installed; without it, until 0.27.0, it searched for `<!doctype` or `<!entity` in the
   first 4096 bytes decoded as UTF-8: a declaration after a comment or a processing instruction of more than 4096 bytes,
   or in a UTF-16 document, was missed and its internal entities were expanded (218 of 300 generated documents,
   expat 2.5.0). The document is now read once by expat with a handler that refuses a document type declaration and
   an entity declaration, wherever they stand and in whatever encoding the bytes declare, before ElementTree parses
   it (as `cryptovalid_lotl` reads a trusted list). A document without one parses as before.
4. **Vaara receipts: ES256 is P-256, and an evidence record given is bound or the receipt is not ok**
   (`cryptovalid_vaara_receipt`, experimental). RFC 7518 §3.1 (read at rfc-editor.org on 2026-11-20): ES256 is "ECDSA
   using P-256 and SHA-256" (RFC 7518 is updated by RFC 9864, October 2025, which leaves the JOSE ES256 as it is:
   "fully specified"; read the same day). A JWK key was already required to be P-256; a PEM key was not, and an ES256 receipt
   signed and verified with a key on secp192r1, secp224r1, secp256k1 or brainpoolP256r1 was ok. Another curve is now
   refused before the signature check (`why`: "ES256 needs a P-256 key ..."). An evidence record given by the caller
   (`evidence`) for a decision receipt without `evidenceRef` left `evidence_ok` null and the receipt ok: the binding
   the caller asked for does not hold, `evidence_ok` is false. Without `evidence` nothing changes.
5. **An MCP tool argument is of the type its input schema declares** (`cryptovalid_mcp.py`; §17 rule 5 already refuses
   an argument the schema does not name). A value whose JSON type is not the property's `type` (`string`, `boolean`,
   `object`, `array` with `items` of `string`) is JSON-RPC -32602 naming the argument, and the tool is not run. Until
   0.27.0 types were not read: `"lotl_check": "false"` went through Python's `bool` and switched the network check of
   the trusted lists on; over the 13 properties of the 6 tools and 17 values each (221 calls), every value of another
   type is now refused. The description of `verify_ledger` said it checked the ledger's "Ed25519 signatures if
   present"; it never did (the receipt counts them in `signatures_not_checked`), and the description now says so.
6. **A body read from the network is bounded** (`cryptovalid_net.read_body`, `MAX_RESPONSE_BYTES` = 64 MiB). Until
   0.27.0 ten reads in seven modules took a response whole (`cryptovalid_lotl`, `cryptovalid_tsa`, `evidence_pack`
   when it stamps, `cryptovalid_qeas`, `cryptovalid_solana`, `cryptovalid_pruning_probe`, `cryptovalid_kms`: three
   answers and one error body), however long it was. Each now reads at most the bound plus one byte and answers
   `ValueError("response_too_large: ...")` past it (an error body: 1 MiB, then only the status is reported). The
   largest document this package fetches is a trusted list: on 2026-11-20 the EU LOTL and the 31 lists it points to
   were at most 5,367,120 bytes.
7. **The evidence pack reads a ledger once** (`evidence_pack.verify_pack`). Until 0.27.0 the path of a ledger was
   opened up to five times (its digest, its chain, whether it is signed, its signatures, its count and head; four when
   no entry is signed): with another
   file at the path only while the chain was read, a pack whose manifest commits to a ledger with a broken chain was `valid: true`
   (measured by exchanging the file between the reads). Each ledger is now read once, bounded as §5 step 0 says, its
   SHA-256 taken from those bytes, and the chain, the signatures, the count and the head are checked on the same bytes
   in memory (the ledger verifier already held a whole ledger in memory). One file is one read however the manifest
   names it: the bytes are kept under the real path a name resolves to when it is first met, so `./l.jsonl` in
   `file_digests_sha256` and `l.jsonl` in `ledgers`, or a link inside the pack, are the same bytes; a name the system does not open as that file (`l.jsonl/`) is not
   another spelling of it and is refused as before (in the first draft
   of this rule the two spellings were two reads, and a file exchanged between them made the same pack valid: measured
   on the branch on 2026-11-20). A signed ledger with bytes that are not UTF-8 20,000 bytes past its signed entries
   made `verify_pack` raise `UnicodeDecodeError` (measured on 0.27.0; with the bytes right after the entries it did not):
   it is now a failure of the ledger's signature layer, and the pack is not valid.
8. **The signer signs entries, never a hash as written** (`signer.sign_ledger`, `signer.py sign`). An entry is signed
   over its `self_hash` as text; the tree heads and the HEAD of `cryptovalid_ingest` are signed, with the same kind of
   key, over the hex of the SHA-256 of their canonical JSON: the same kind of message, with no tag that tells them
   apart. Until 0.27.0 the signer signed the `self_hash` of each line as written: a "ledger" of two lines whose
   `self_hash` were the hashes of a tree head and a HEAD made by someone else, signed with `signer.py sign`, gave the
   two signatures of an archive the key's holder never sealed, and `verify_archive` with that key pinned answered ok
   (measured on 0.26.0 and 0.27.0). The digest of a pack manifest is the same kind of message: signed the same way, it
   made `verify_pack` with `manifest_signer_hex` pinned answer `producer_signature: verified` for a pack the key's
   holder never built (measured on 0.27.0). Each line is now a JSON object with distinct keys, its members within the entry
   schema of §2.1, and a `self_hash` recomputed from its content (§3), or the signer refuses the whole file and writes
   nothing (`refusing to sign line <n>: ...`). An entry's content is never a tree head or a HEAD: their members are not
   in the entry schema. The signature verifier reads the same closed object (`signer.verify_file`, `signer.py verify`,
   and the signature layer of a pack): a tree head, a HEAD or a signed manifest of the key's holder, written as a
   ledger line with its hash as `self_hash`, verified there under the pinned key (ok, 1 verified, while `verifier.py`
   failed the same file; measured on 0.27.0 and on the first draft of this rule); such a line is now the failure
   `unknown_field:<keys>` at its index. A tag that separates the kinds of signed message is a change of format, not
   made here: it is §22 rule 3.

## 22. Rules written for the decisions of 2026-11-20 (NORMATIVE since v0.14)

The re-measurement of 2026-11-20 (§21) left six findings to a decision of the maintainer (rules 1-6; rule 7 applies
the principle of rule 4 to the TSA pin, decided on 2026-11-21; rule 8 applies §5 step 0 to the other verifiers, after
the review of 2026-11-22; rule 9 bounds what a ledger holds, found while measuring rule 8), each a behaviour the earlier
text of this specification allowed or a format change. The six decisions were taken the same day; each rule below was
written here before the code. Tests: `test_decisions_20261120.py`, 54 tests (one compares the canonicalization of rule
6 with lxml and is skipped where lxml is absent): on the branch before these rules (9b81e9c) 43 fail (44 where lxml is
installed: that comparison fails there too) and the 10 named `*_control`, which hold what the rules do not change, pass. After the review of the branch (2026-11-21):
`test_review_20261121.py`, 46 tests, the cases that mutants of the lines of rules 2, 3, 5 and 6 showed missing, two sentences of
this section, the empty pin of rule 4, the sequence number of rule 6 and the table of the reasons of a tip of rule 2; 34
pass on 9b25d32 (the code already answered so, no test held it), twelve fail there (rule 6, `at` and the five tests of the
sequence number; rule 4, an empty pin and a pin that is not a string; rule 2, the tip of another kind in the Go verifier,
the table, its row 1, and the words of `bad_not_before` after it: without the Go toolchain the first of these four passes
there, 35 and eleven). The paths
`prove_decisioni_D_20261120/cryptovalid/*.py` cited below name measurement scripts kept with the review notes of the
maintainer, outside this repository.

1. **A trusted log key makes the tip required** (`verifier.verify_ledger(trusted_pubkey_hex=...)`, `verifier.py
   --trusted-pubkey`, the JS `verifyLedger({trustedPubkey})` and `cvverify.mjs --trusted-pubkey`, the Go
   `VerifyLedgerWithTip*`/`VerifyLedgerFull` and `cvverify -trusted-pubkey`, the Java `CvVerify -trusted-pubkey`), as
   the oldest acceptable tip (§17 rule 2) and the trusted post-quantum key already did. Until 0.27.0 the key was used
   only when a tip happened to be there: with no tip file the four verifiers answered PASS, exit 0, `tip: null` (§17,
   "Not changed by this section"), so a caller who pinned the log key and lost the tip was not told. Now the verdict
   is FAIL with `tip_missing`, exit 1. In the libraries an empty key is still "not given" (§17 rule 4). The Rust and
   Swift verifiers have no tip options (unchanged).
2. **A tip, a tree head and a HEAD are closed objects.** A member outside the list of its document is a failure that
   names it; until 0.27.0 it was ignored (a tip with `zz_unknown`: PASS; a tree head or a HEAD with `zz_unknown`:
   `verify_archive` ok, no reason). The lists, and nothing else:
   - tip (`cryptovalid_tip/1`): `kind`, `entries`, `ledger_id`, `tip_sha256`, `ts`, `log_pubkey_hex`, `signature_hex`,
     and the two members of the post-quantum layer `signature_pq_hex`, `log_pq_pubkey_b64` (`cryptovalid_tip.TIP_MEMBERS`,
     JS `TIP_MEMBERS`, Go `TipMembers`, Java `TIP_MEMBERS`). The failure is `tip_invalid: unknown_member:<keys>`, the
     same text in Python, JS, Go and Java: the keys outside the list in code-point order, joined by `,`, cut to 120 code
     points (as `unknown_field` of §2.1). The Rust and Swift verifiers do not apply this rule: a tip whose post-quantum
     members are spelled `Signature_PQ_Hex` and `Log_PQ_Pubkey_B64` is PASS in Rust (measured in CI on 2026-11-22,
     declared in `verifiers/differential_oracle.py` as `tip-pq-case`); Swift is not measured. It is checked right after `kind` (a document whose `kind` is not
     `cryptovalid_tip/1` is still `not a cryptovalid_tip/1 document`) and before every other member: the Go verifier
     decoded a tip into a struct whose names match case-insensitively, so `"Kind": 1` there was `tip_unreadable` and in
     Python an ignored member; both now name it. The same decoding made the Go verifier answer `tip_unreadable: json:
     cannot unmarshal ...` to a `kind` that was an integer, a boolean, an array or an object; it reads `kind` first now
     and answers `tip_invalid: not a cryptovalid_tip/1 document` as the other three.
   - **One reason for each form of a tip, the same text in the four verifiers** (Python, JS, Go, Java; decided on
     2026-11-21). Until then a tip whose `kind` is right and another member is of a wrong type, missing or malformed,
     and a tip file that is not a JSON object, got one verdict and each verifier's own words (measured by the second
     review: of 72 such tips one text in the four for 3; of 10 files that are not an object, for 1). The checks run in
     the order of this table and the first that holds gives the reason; the verdict is FAIL, exit 1:

     | # | the tip | reason |
     |---|---|---|
     | 1 | the file cannot be read (absent, not a regular file, too large, an error of the system) | `tip_unreadable: the tip file cannot be read` |
     | 2 | its bytes are not one JSON text of the profile of §3 (strict UTF-8, no byte-order mark, no key written twice, no float lexeme, an integer within ±(2^53-1), nesting within the bound, no lone surrogate; JSON white space around it allowed) | `tip_unreadable: not a JSON text of the profile of SPEC §3` |
     | 3 | the JSON value is not an object | `tip_unreadable: not a JSON object` |
     | 4 | `kind` absent or not the string `cryptovalid_tip/1` | `tip_invalid: not a cryptovalid_tip/1 document` |
     | 5 | a member outside the nine | `tip_invalid: unknown_member:<keys>` (as above) |
     | 6 | `entries`, `ledger_id`, `tip_sha256`, `ts`, `signature_hex`: the first absent, in this order | `tip_invalid: tip missing field <name>` |
     | 7 | `entries` not an integer >= 0 (a boolean is not one) | `tip_invalid: tip entries must be a non-negative integer` |
     | 8 | `ledger_id`, `tip_sha256`, `ts` or `signature_hex` not a string, or `log_pubkey_hex` present and neither null nor a string | `tip_invalid: tip fields must be strings` |
     | 9 | `ledger_id` or `tip_sha256` not 64 lowercase hex characters | `tip_invalid: ledger_id / tip_sha256 must be 64 lowercase hex characters` |
     | 10 | `signature_hex` not 128 lowercase hex characters | `tip_invalid: signature_hex must be 128 lowercase hex characters` |
     | 11 | `signature_pq_hex` or `log_pq_pubkey_b64` present, and `signature_pq_hex` not 6618 lowercase hex characters | `tip_invalid: signature_pq_hex must be 6618 lowercase hex characters (ML-DSA-65)` |
     | 12 | as 11, and `log_pq_pubkey_b64` not strict base64 of 1952 bytes | `tip_invalid: log_pq_pubkey_b64 must be strict base64 of a 1952-byte ML-DSA-65 public key` |
     | 13 | `ts` outside the profile of `spec/CONFORMANCE.md` | `tip_invalid: ts outside the profile YYYY-MM-DDThh:mm:ss[.fraction](Z\|±hh:mm)` |
     | 14 | `log_pubkey_hex` a non-empty string other than the trusted log key | `tip_invalid: tip log key differs from the trusted log key` |
     | 15 | the Ed25519 signature does not verify under the trusted log key | `tip_invalid: tip signature invalid`, with ` (<reason>)` when the strict rule of §5 step 5 names one (`small_order_key`, `mixed_order_key`, `key_not_decodable`, `small_order_r`, `r_not_decodable`) |

     Measured on 2026-11-21 (`prove_decisioni_D_20261120/cryptovalid/d4b_testi_tip.py`, 251 generated tip files: each
     member absent or of 22 other values, 30 with two or three members wrong, 14 files that are not a tip object): one
     text in the four for 40 before this table, for all 245 that fail after (the other 6 pass in the four); one exit
     code changed, the JS verifier's for a `log_pubkey_hex` of `false` or `0`, read as absent (exit 0) where the other
     three refused it (now row 8, exit 1). Held by `test_review_20261121.py`
     (`TestTheReasonsOfATipAreTheSameInTheFourVerifiers`, an oracle written from this table). Row 1 in the JS, Go and
     Java verifiers since 2026-11-22 (third review): until then they waited without end on a FIFO given as the tip,
     and read a device (`/dev/null`) or a file larger than 256 MiB as bytes (row 2; Java: `internal: OutOfMemoryError`);
     now each opens the path once (JS and Go without waiting for a writer; Java reads the attributes first, and since
     rule 8 reads in a second thread that stops waiting after 10 s, so a path swapped for a FIFO between the two is row
     1 too), and a FIFO, a device, a directory or more than 256 MiB
     (`verifier.py` `MAX_INPUT_BYTES`) is row 1, as in Python (`TestRowOneOfTheTableInTheFourVerifiers`). The Go
     verifier built for a platform that is not Unix has no non-blocking open (declared).
     After them, the comparisons with the file keep the texts of JS, Go and Java (`ledger_id_mismatch`,
     `tip_of_another_ledger`, `tip_rolled_back`, `tail_truncated`, `unsealed_tail`, `tail_rewritten`,
     `bad_not_before`); in the Python reference `tip_rolled_back`, `unsealed_tail` and `bad_not_before` carried a longer
     tail and now have their words (the same text in the four measured for `unsealed_tail` and `tip_rolled_back`, read
     in the code for the others). A text that names a
     command-line option spells it as that verifier does (`--trusted-pubkey`, `-trusted-pubkey`). Not in this table:
     the post-quantum layer checked under a trusted ML-DSA-65 key, which the JS verifier does not check (§15).
   - tree head (`<segment>.sth.json` of `cryptovalid_ingest`): `tree_size`, `root_sha256`, `signed`, `note`, `segment`,
     `sealed_utc`, `last_self_hash`, `prev_sth_sha256`, `signature`, `signer`, and `sig_domain` of rule 3
     (`cryptovalid_ingest.STH_MEMBERS`, eleven members: every member the writer has written since 2026-08-16; `signed`
     since 2026-09-14, so an older tree head without it verifies as before). The failure is `sth_unknown_member:<keys>`
     (the keys as for the tip: code-point order, joined by `,`, cut to 120 code points; the same for the HEAD).
   - HEAD (`<prefix>.head.json`): `prefix`, `segments_sealed`, `last_segment`, `last_sth_sha256`, `updated_utc`,
     `signature`, `signer`, and `sig_domain` of rule 3 (`cryptovalid_ingest.HEAD_MEMBERS`, eight members). The failure
     is `head_unknown_member:<keys>`.
   A key written twice in any of the three is already refused by the reader (§21 rule 2: for a tip row 2 of the table
   above, the same text in the four since 2026-11-21; `sth_unreadable: duplicate_key`, `head_unreadable: duplicate_key`).
3. **Tree heads, HEADs and pack manifests are signed over a domain-tagged message.** An entry signature is over the
   `self_hash` as text, 64 lowercase hex characters (§2); until 0.27.0 the tree heads and the HEAD of
   `cryptovalid_ingest` were signed over the hex of the SHA-256 of their canonical body, and a pack manifest over its
   `manifest_digest_sha256`, with the same kind of key: four kinds of document over one kind of message. §21 rule 8
   closed the one oracle found (`signer.sign_ledger`) and the one confusion on the verifying side (`signer.verify_file`);
   this rule makes the separation part of the signed bytes. The new form:
   - a tree head or a HEAD signed from now on carries the member `sig_domain`, `"cryptovalid-sth/2"` or
     `"cryptovalid-head/2"`, inside the body that is hashed, and its signature is over the UTF-8 bytes of
     `<sig_domain> + ":" + <hex of the SHA-256 of the canonical body>` (the body is, as before, the document without
     `signature` and `signer`). `sig_domain`, when present, MUST be exactly the tag of its document, signed or not:
     another value is `sth_signature_domain_mismatch` / `head_signature_domain_mismatch` (and the signature, checked
     over the document's own tag, fails). A document without `sig_domain` is checked as before, over the bare hex.
   - pack format `cryptovalid-evidence-pack/1.2` has the members of 1.1; its `manifest_signature` is over the UTF-8
     bytes of `"cryptovalid-pack-manifest/2:" + manifest_digest_sha256`. `build_pack` writes 1.2. In a 1.1 pack the
     signature is over the bare digest, as before. The message follows the format: a 1.1 pack signed over the tagged
     message, or a 1.2 pack signed over the bare digest, is `producer_signature: contradicted / signature_invalid`.
   - Every message of the new form is longer than 64 characters and starts with its tag, so no entry signature, no other
     kind of these documents, and no tip (signed over a JSON object, `{"entries":...`) is over the same bytes.
   Documents written until 0.27.0 verify as before, and are named: `verify_archive` adds the warning
   `untagged_signatures: <segments>, HEAD signed without sig_domain ...`; a 1.1 pack names its format. A caller who
   wants the separation of every signature passes `require_signature_domain=True` (`verify_archive`, `verify_pack`;
   `cryptovalid_ingest.py verify --require-signature-domain`): a signed tree head or HEAD without `sig_domain` is then
   `sth_signature_domain_untagged` / `head_signature_domain_untagged`, and a 1.1 pack is refused `format_unsupported`.
   Measured on the branch (`prove_decisioni_D_20261120/cryptovalid/d5_vecchi_archivi.py`): the 12 packs of this
   repository give the same `valid`, `admission`, `states` and `ledgers` before and after; 8 archives and packs written
   by the code before this rule (signed and unsigned, 1 to 3 segments) give the same verdict, failures and states, and
   the 3 signed archives gain only the warning. A signed archive or a pack written now is refused by 0.27.0 (measured:
   a signed archive is `sth_signature_invalid`, `head_signature_invalid`; a 1.2 pack `format_unsupported`), never
   accepted. An archive written now without a signing key carries no `sig_domain`: it is the document 0.27.0 wrote, and
   0.27.0 verifies it (measured: ok).
   Entry signatures and the tip do not change.
4. **A pin given to the pack verifier decides `valid`** (`evidence_pack.verify_pack`; the command line has no pins).
   Until 0.27.0 `valid` was "not derived from `states`" (§10, Disposition): with `signer_pubkey_hex` pinned, a ledger
   with no signature at all left `sig_pass: true` and the pack `valid: true` (its layer was simply absent); with
   `manifest_signer_hex` pinned, a manifest not signed, or signed by another key, left `valid` as it was ("by design"):
   a caller who pinned a key and read `valid` accepted a pack that anyone could have built. Now:
   - with `signer_pubkey_hex`, every ledger must carry signatures: a ledger with no signature field is `sig_pass: false`,
     `pq_reason: "unsigned_but_signer_pinned"`, a `producer_signature` element `not_evaluated / not_present` naming it,
     and the pack is not valid (a ledger signed by another key, or broken, was already not valid);
   - with `manifest_signer_hex`, the manifest-signature element must be `verified`: `not_present` (unsigned) and
     `key_unresolved` (another key) make the pack not valid; the element stays in `producer_signature` even when signed
     ledgers follow it (until 0.27.0 an unsigned manifest's element was dropped there).
   - `pq_pubkey_b64` sits on `signer_pubkey_hex` (unchanged): a post-quantum layer it pins that is absent or broken was
     already not valid.
   - an empty pin is not "no pin" (as §17 rule 4 in the archive verifier, and as `tsa_certs=[]` since v0.8): `""`, or a
     value that is not a string, given as `signer_pubkey_hex`, `manifest_signer_hex` or `pq_pubkey_b64` is a `ValueError`
     before the pack is read. Until 0.27.0 it meant "not pinned": an unsigned pack verified with `signer_pubkey_hex=""`
     was `valid: true` (measured on 0.27.0 and on 9b25d32).
   Without pins nothing changes. The two rules of §10 Disposition become: a `valid` pack is admitted and has no
   `contradicted` subject; an admitted pack that is not valid and has no `contradicted` subject has a
   `producer_signature` reason `key_unresolved`, `backend_missing` or, under a pin, `not_present`, or, under pinned
   TSA certificates (rule 7), a `time_anchor` that is not `verified` (measured: a pack signed by the pinned keys, without a
   token, verified with a TSA pin, is admitted, not valid, nothing `contradicted`, `producer_signature: verified`). The sentence "the
   converse does not hold, by design" no longer holds for a pinned manifest signer: it holds for a post-quantum layer
   nobody pinned. Measured (`prove_decisioni_D_20261120/cryptovalid/d1_verdetti.py`, and the oracle of
   `test_decisions_20261120.py`): 36 combinations of manifest signer (none, the pinned key, another) x ledger signer
   (the same three) x each pin given or not; 14 change verdict, all from `true` to `false`, the 22 others do not; the
   12 packs of this repository, verified without pins, give the same receipt before and after.
5. **The MCP tool `verify_ledger` verifies the entry signatures against a key given as an argument**
   (`cryptovalid_mcp.py`). Until 0.27.0 it checked only the chain; since §21 rule 5 its description says so. It now
   takes `expected_pubkey_hex` (64 lowercase hex, an Ed25519 public key; any other string is an `error`, the tool
   does nothing else). Given, the file is read once (§5 step 0), the chain is checked on those bytes and the signature
   of every entry against that key on the same bytes (`signer.verify_ledger_signatures`, the closed entry of §2.1, as
   `signer.py verify --pubkey`); the answer carries `signatures` (`checked: true`, `pinned_key`, the counts and failures)
   and `valid`, true only when the chain is PASS and every entry is signed by that key and verifies (an unsigned entry,
   another key, a broken signature: false). Without `cryptography` the signatures cannot be checked: `checked: false`,
   `ok: false`, `valid: false`. Not given, the tool answers as before and adds `signatures: {"checked": false, "note":
   "signatures NOT verified: ..."}`, with no `valid`. The input schema gains the one property: the tools now have 14
   (the 221 calls of §21 rule 5 are 238).
6. **A trusted list counts only when its XAdES signature verifies, and only over https** (`cryptovalid_lotl`,
   EXPERIMENTAL: outside the maintained core, no new scope). Until 0.27.0 a list and the LOTL were trusted for the channel
   they came over: a LOTL and a national list without any `ds:Signature` made a token qualified, and one of the 31
   national lists the EU LOTL points to is served over http only (`http://tl.nbu.gov.sk/kca/tsl/tsl.xml`, measured on
   2026-11-15 and 2026-11-20): whoever sits on that path could add a qualified timestamp service. Now
   (`verify_list_signature`, `lotl_signers`, `load_qualified_status`):
   - **The LOTL** must carry an enveloped XAdES signature that verifies under a certificate of the Official Journal
     publication in force, C/2026/1944 of 15.4.2026 (read at eur-lex.europa.eu on 2026-11-20: it replaces OJ C 276,
     16.8.2019, p. 1; the LOTL of that day, sequence 398, names it first in `SchemeInformationURI`): the SHA-256 digests
     of its six LOTL-signing certificates are `OJ_LOTL_SIGNERS_SHA256`. The publication's pivot mechanism (its section 2)
     is followed: the URIs before the OJ's in `SchemeInformationURI` are pivot LOTLs, newest first; from the OJ's
     certificates each pivot, oldest first and over https, must verify under the current set and gives the next one
     (the certificates of its own pointer, `TSLType` `EUlistofthelists`). A LOTL that does not name this publication is
     refused (`lotl_oj_unknown`): a later publication needs a later version. A LOTL that fails is a `ValueError`: no
     qualified status is built from it.
   - **Each national list** must carry an enveloped XAdES signature that verifies under a certificate (SHA-256 of the
     DER) of the `ServiceDigitalIdentities` of the LOTL's pointer to that location; a list served over http is not
     fetched; a list that fails either check is not covered and is named in the log (`TL skip: <url> (<reason>)`).
   - **The signature read is closed** to the shape every list had on 2026-11-20, anything else refused with its reason:
     one `ds:Signature`, a child of the list's root element; `SignedInfo` = `CanonicalizationMethod` exclusive C14N
     1.0 without parameters, `SignatureMethod` one of RSA PKCS#1 v1.5, RSA-PSS (RFC 6931 §2.3.10 defaults: MGF1 with
     the same hash, salt of the hash's length) or ECDSA (`r || s`) with SHA-256, -384 or -512 and no parameters, then
     exactly two `Reference`s: `URI=""` with the transforms enveloped-signature then exclusive C14N, and
     `Type="http://uri.etsi.org/01903#SignedProperties"` with exclusive C14N, naming by `#Id` the
     `xades:SignedProperties` (ETSI EN 319 132-1, namespace 1.3.2) inside this signature; digests SHA-256, -384 or
     -512; an identifier (`Id`, `ID`, `id`) on two elements refused; `KeyInfo` one `X509Data` with one
     `X509Certificate`, whose digest `xades:SigningCertificateV2/Cert/CertDigest` must match; the signing certificate
     valid now (`notBefore` to `notAfter`); a `NextUpdate/dateTime` of the list, when present, not passed (ETSI TS 119
     612 5.3.15; an empty `NextUpdate`, a closed list, is read as before). Reasons: `xmldsig_missing`, `xmldsig_shape`,
     `xmldsig_algorithm`, `xmldsig_digest_mismatch`, `xmldsig_signing_certificate`, `xmldsig_untrusted_signer`,
     `xmldsig_certificate_not_valid`, `xmldsig_signature_invalid`, `xmldsig_malformed`, `tl_next_update_passed`. The instant the list is checked at (`at`,
     default now) is a timezone-aware datetime: another value is a `ValueError`.
   - **What is read is what is signed:** the content of a list (services, statuses, pointers) is read with its
     `ds:Signature` removed, the node set the enveloped reference covers; an element put inside `ds:Object` is never
     read as a service.
   - **Canonicalization.** Exclusive XML Canonicalization 1.0 (W3C Recommendation of 18 July 2002) without comments is
     written in the module on expat. The standard library has only C14N 2.0 (`xml.etree.ElementTree.canonicalize`),
     which writes the first prefix a namespace was bound to instead of the prefix the element uses: on the LOTL and the
     30 lists of 2026-11-20 it gave other bytes than the signer for 1 of the 31 documents (HU, a default namespace and
     `tsl:` bound to one URI); on 3,000 generated documents it differs from libxml2's exclusive C14N on 1,311. No external dependency is added.
   Measured on 2026-11-20 (`prove_decisioni_D_20261120/cryptovalid/d2_liste_reali.py`, the LOTL of that day, sha256
   `45e0827831e07754c36e456e5e01469b1b8e793c9f29571832c397ef3bde4750`, and the 30 national lists that answered; the
   Cypriot list did not answer in 60 s, twice): the LOTL verifies under the second certificate of the OJ publication; the
   30 lists verify under their pointer's certificates (24 RSA-SHA512, 2 RSA-SHA256, 1 RSA-PSS SHA-256, 2 ECDSA-SHA512,
   1 ECDSA-SHA256); on each of the 30, one byte of the signed content changed, the
   signature removed, another list's certificates as trust, and a `TSPService` put inside `ds:Object` are refused or
   not read (30 of 30 each), and so is each list checked as of 2040-01-01 (30 of 30, every signing certificate expired);
   the LOTL under a national list's certificates is refused; every signing certificate is valid on 2026-11-20 and every
   `NextUpdate` present is later (the EU list of UK services has none). The canonicalization of the module
   against lxml 6.1.1 / libxml2 2.14.6 (`d2_c14n_vs_lxml.py`): 3,000 generated documents, every element as a subtree
   and every whole document, 8,943 canonical forms, 0 different (a mutant that drops `xmlns=""`: 4 different).
   Not read: a revocation status of the signing certificate. The trust is the certificate itself, named by the OJ
   publication or by the LOTL's pointer, and a certificate taken out of service leaves those lists (a new pivot, a new
   LOTL); the publication defines no other source. After a pivot only the set it announces is accepted: the 15 days in
   which the Commission keeps the former certificates usable (the publication's section 2.2) are not used, so a LOTL
   that names the pivot and is still signed with a former certificate in those days is refused, never accepted wrongly.
   **The sequence number** (`TSLSequenceNumber` of `SchemeInformation`, ETSI TS 119 612 5.3.2: an integer, 1 for the
   first issue, incremented at each) is read since the review of 2026-11-21, closed: the root has one
   `SchemeInformation`, it holds exactly one `TSLSequenceNumber`, that element has no child element, and its text, XML
   white space (space, tab, CR, LF) around it apart, is 1 to 18 ASCII digits (the limit XML Schema Part 2, 3.2.3, lets
   a processor set and asks it to document; leading zeros count) with a value of at least 1; anything else refuses the
   list (`tl_sequence_malformed`; every one of the 31 documents of 2026-11-20 has one, the largest 398). It is reported
   (`verify_list_signature(...)["sequence_number"]`; `load_qualified_status(sequences_out={})` fills {location: number}
   for the LOTL and every list that verified, and the cache records them as `sequences`; a `sequences_out` that is not
   a dict is a `ValueError` before anything is fetched). A minimum given by the caller
   (`verify_list_signature(min_sequence=n)`, `load_qualified_status(min_sequences={location: n})`, the LOTL under its
   location; with it the cache is not read) refuses an earlier list: `tl_sequence_rolled_back` (the LOTL: `ValueError`;
   a national list: not covered, named in the log). A location in `min_sequences` that is neither the LOTL's nor one
   the verified LOTL points to is a `ValueError`: a minimum that would apply to no list is not ignored. Without a minimum no state is kept between two calls, so an earlier
   LOTL or national list, signed with a certificate that is still trusted and valid and not past its own `NextUpdate`,
   verifies like the current one: a verifier without memory cannot tell them apart, and a caller who keeps the numbers
   of one run and gives them back as minimums at the next makes it a failure.
7. **Pinned TSA certificates decide `valid` and `ok`** (`evidence_pack.verify_pack(tsa_certs=...)`, `evidence_pack.py
   verify --tsa-cert`, `cryptovalid_ingest.verify_archive(tsa_certs=...)`,
   `cryptovalid_ingest.py verify --tsa-cert`). This rule replaces the sentence of v0.8 in §10 "a pin for another TSA
   does not make the pack false", as rule 4 replaced the Disposition for the signer pins. Until 0.27.0, with TSA
   certificates pinned, a pack whose token was issued by another TSA (`tsa_unresolved`), a pack without a token
   (`not_present`), and a pack whose token openssl could not check (`instrument_failure`) were `valid: true`; an
   archive whose sealed segments had no token, or a token that could not be checked, was `ok: true`. Now:
   - **pack**: with `tsa_certs` given, `valid` is true only when `time_anchor` is `verified`; the state and its reason
     do not change (`not_evaluated / tsa_unresolved`, `not_present`, `instrument_failure`), only `valid`.
   - **archive**: with `tsa_certs` given, every sealed segment must carry a token `verified` under them: a segment
     without one is the failure `tsa_token_missing_but_tsa_pinned`, a token whose check did not run
     (`not_evaluated`, openssl absent) is `tsa_token_not_verified_under_pin`. A token of another TSA was already the
     failure `tsa_token_not_issued_by_pinned_tsa` (§11, unchanged).
   Without a TSA pin nothing changes. The verifiers that already required a verified token under the pin are unchanged:
   the beacon window (§19: `time_anchor_not_verified`) and `cryptovalid_heterogeneous` (a timestamp counts only
   when `verified`). `eidas_ledger_check` counts tokens per status in a self-assessment and gives no `valid`: not
   changed. Measured (`prove_decisioni_D_20261120/cryptovalid/d7_tsa_pin_verdetti.py`, two local TSAs made with
   openssl): 33 combinations of token (the pinned TSA's, another TSA's, none, `anchored: false`, broken, over another
   digest; openssl absent at the check) x pin (none, TSA A, TSA B) x pack or archive; 12 change verdict, all from
   valid/ok to not, 21 do not; none becomes valid.
8. **The JS, Go and Java verifiers read the ledger as §5 step 0 says** (written on 2026-11-22, after the third review of
   the branch found that the tip reader of these three waited on a FIFO, rule 2 row 1, and named their ledger reader as
   the same class, still open). The path given as the ledger is opened once without waiting for a writer and judged
   on what was opened; each verifier writes the reason where it writes its other reasons (Python `parse_errors`, JS
   `error`, Go and Java `failures`):

   | the path | verdict, exit | reason |
   |---|---|---|
   | a regular file of at most 256 MiB (`verifier.py` `MAX_INPUT_BYTES`) | as §5 steps 1-5 | |
   | a regular file larger than that | FAIL, 1 | `input_too_large: file exceeds 268435456 bytes` |
   | a FIFO (a named pipe, `<(cat ledger.jsonl)`), read to its end | as §5 steps 1-5 | |
   | a FIFO that gives more than 256 MiB | FAIL, 1 | `input_too_large: file exceeds 268435456 bytes` |
   | a FIFO that gives no byte and no end of file for 10 s (no writer) | FAIL, 1 | `unreadable: FIFO idle for 10 s` |
   | anything else that opens: a directory, a device (`/dev/null`, `/dev/zero`) | FAIL, 1, no byte read | `unreadable: not a regular file` |

   Only the wait for a byte is bounded, not the whole read, as in §5 step 0. How: JS and Go open with `O_NONBLOCK` and
   judge the open descriptor (`fstat`); a FIFO is read through the event loop (JS) or the runtime poller (Go) with an
   idle timer. The JDK has no non-blocking open: the Java verifier reads the type from the attributes of the path
   (`unix:mode`; where that view is absent, a path that is not a regular file is refused), then opens and reads it in a
   second thread and stops waiting after 10 s without a byte, so a path swapped for a FIFO between the two ends in
   `unreadable: FIFO idle for 10 s` instead of a wait. Java's tip reader (rule 2 row 1) reads through the same thread,
   so a tip path swapped for a FIFO is row 1 after 10 s. A line is read up to the bound in the four, so a ledger
   within the bound is judged on its entries, never on the length of a line: one valid line of 65 MiB and one of
   250 MiB are PASS in the four, and the same line with one byte changed FAIL (measured on 2026-11-22). Before this rule
   the JS verifier ended on the line of 65 MiB without a receipt (Node's `JavaScript heap out of memory`, exit 134:
   its canonical form was built one character at a time) and the Go verifier was FAIL `read: bufio.Scanner: token too
   long` on any line longer than 64 MiB (`MaxLineBytes`, which now bounds only what the Go writer takes); the Go
   verifier reads to the end, within the bound, what its line reader leaves, so a FIFO of more than 256 MiB is
   `input_too_large` there too. An absent file and a file the
   process may not read keep each verifier's own answer (not changed here: Python `FILE_NOT_FOUND` exit 1 and
   `unreadable: PermissionError`, JS `FILE_ERROR` exit 2, Go exit 2 for an absent file and `open: ...` for the other,
   Java `open: NoSuchFileException` and `open: AccessDeniedException`). So does a Unix socket, which the system does not
   open as a file (`ENXIO`): Python `unreadable: OSError`, JS `FILE_ERROR` exit 2, Go `open: ... no such device or
   address`, Java `unreadable: not a regular file` (measured on 2026-11-22; no byte read in the four).
   The Go writer (`cvappend`, `Append`, `AppendSigned`, `SignTip`) follows §5 step 0 (a) and (c): the ledger it appends
   to or signs is a regular file (else `<path>: unreadable: not a regular file`; a directory is the system's `is a
   directory` when it is opened to write), and the key file of `-tipkey` (`LoadTipKey`) is read as (c): a regular file
   or a FIFO of at most 1 MiB (`input_too_large: file exceeds 1048576 bytes`), with the same idle bound; a device or a
   directory is `unreadable: not a regular file`. On Windows a FIFO is a named pipe given by name (`\\.\pipe\<name>`),
   opened once and not looked at before (0.29.0): asking for its attributes opens it and takes one of its instances,
   so Go's `cvverify` does not `stat` it, Java knows it by its name, and `verifier.write_output` writes to one named by
   `--out` the same way. JS judges the mode `fstat` gives (Node's `isFIFO()` is false for every file there). A Windows
   device that has no attributes (`\\.\NUL`) is the last row of the table in Java too. The data `cvappend` reads from stdin becomes one line: at most 64 MiB
   (`MaxLineBytes`), else `data: input_too_large: more than 67108864 bytes`, exit 2, nothing appended (stdin without
   end, `< /dev/zero`, was read until no memory was left: Go's `fatal error: out of memory` under `ulimit -d 524288`).
   The JS verifier's `--conformance <dir>` reads each file of the directory as its tip reader does: one that is not a
   regular file of at most 256 MiB makes its vector not conformant, `unreadable: ...` (a FIFO there waited without end).
   Measured on 2026-11-22 on cfcd05c, each command killed after 40 s (`ledger_inputs.sh`, `cvappend_inputs.sh`, kept
   with the review notes of the maintainer): a FIFO with no writer given as the ledger, or a link to it, was FAIL
   `unreadable: FIFO idle for 10 s` in Python after 10 s and did not return in JS, Go and Java; a FIFO whose writer held
   it 14 s without a byte was read as an empty ledger by the three after the 14 s; a FIFO of 256 MiB + 1 byte was read
   by JS (`json_decode`), by Go up to its line bound (`token too long`), and was `internal: OutOfMemoryError` in Java; a
   link to `/dev/zero` did not return in JS (once ended by the system, exit 137), was `internal: OutOfMemoryError` in
   Java after 12 s (33 s with JDK 27) and `token too long` in Go; `/dev/null` was an empty ledger in the three; a
   directory was `FILE_ERROR` exit 2 in JS, `read: ... is a directory` in Go and `open: IOException` in Java; a sparse
   file of 256 MiB + 1 byte was read by JS (`json_decode`) and by Go up to its line bound (Java refused it already).
   `cvappend -tipkey` waited without end on a FIFO and read a link to `/dev/zero` until the process was killed (exit 137
   after 20 s); `cvappend` given a link to `/dev/zero` as the ledger wrote the entry to it (exit 74, the `fsync`
   refused). Now, of the same 15 forms (a regular file; a FIFO with no writer, a link to it, a writer at once, a writer
   3 s late, a writer that holds it 14 s without a byte, 256 MiB + 1 byte through it; `<(cat ledger.jsonl)`; a
   directory; `/dev/null`; a link to `/dev/zero`; a sparse file of 256 MiB + 1 byte; one of exactly 256 MiB; a file
   without permission; an absent file), the 12 the table names give its row in the four, the same text; the other three
   keep each verifier's answer, as above (256 MiB exactly is within the bound and fails at §5 step 1, in Go too
   since 0.28.0). Held by `test_ledger_input_20261122.py` (16 tests), `verifiers/go/input_test.go` and
   `verifiers/js/test.mjs`.
   Not measured: macOS, where the Go runtime does not poll a FIFO (the Go verifier reads one there with a pause of 10 ms
   between tries, and a FIFO no writer has opened yet reads as empty, `empty_ledger`, where Linux waits for a writer),
   and where Node and Java were not run. The Rust and Swift verifiers read the ledger whole (`std::fs::read`, `FileHandle`): not changed,
   no toolchain on the bench that measured this rule.

9. **What a ledger may hold is counted before it is parsed** (written on 2026-11-22, while rule 8 was measured; the
   same in `verifier.py`, JS, Go and Java). The bound of 256 MiB on the bytes did not bound memory: a file of 16 MiB
   holding 8 Mi lines `0` ended Python in `MemoryError` and Go in `fatal error: out of memory allocating heap arena metadata` under a data limit of
   2 GB, and one line of 64 MiB holding `[{},{},...]` ended JS in `JavaScript heap out of memory` (exit 134), each without a
   receipt, and took Go to 2783 MiB (a receipt under a data limit of 3 GB, `fatal error` under 2.5 GB; measured on
   2026-11-22 on a72d51d). Over the whole input, after the bytes of
   rule 8; the verdict is the one of a count made before any line is parsed (the Go verifier parses the lines within
   the bounds while it counts and discards what it found; `verifier.py` stops reading at the first line past the line
   bound):

   | the input holds | verdict, exit | reason |
   |---|---|---|
   | more than 2^20 lines (a line ends at LF or at the end of the input; blank lines count) | FAIL, 1 | `input_too_large: more than 1048576 lines` |
   | else more than 2^23 tokens (the characters `{` `[` `,` `:` wherever they stand, inside strings too) | FAIL, 1 | `input_too_large: more than 8388608 JSON tokens` |

   The reason is alone, where each verifier writes its reasons (Python `parse_errors`, JS `error`, Go and Java
   `failures`); nothing of the ledger is verified. A tip (rule 2) of more than 2^23 tokens is row 2 of the table,
   `tip_unreadable: not a JSON text of the profile of SPEC §3`, counted before it is parsed; so is an `.expected.json`
   of the JS verifier's `--conformance` (a vector not conformant). Why these two counts: every JSON value of a line
   but the first follows one of the four characters, so values are at most tokens plus lines, and each verifier's
   memory grows with values and with lines (the per-line reasons). Measured on 2026-11-22 at the bounds (2^20 lines of
   `0`, of `{}`; 762 600 entry lines of 8 388 600 tokens; one line of 2^23 tokens as `{}`, `0`, `[]`, `""` elements and
   as 4 Mi keys of one object): read and parsed, FAIL with a receipt in the four, peak memory at most 1097 MiB in
   Python, 1359 MiB in JS, 1931 MiB in Go (the object of 4 Mi keys) and 1822 MiB in Java (its default heap; the
   entry lines); one line or one token more, 200 MiB of blank lines and 256 MiB of lines `0`, FAIL with the reason in
   the four in at most 8 s (`verifier.py` counted every line of the 200 MiB, 64 to 76 s, until the review of
   2026-11-22; it stops at the first line past the bound, 0.5 s). Eight ledgers of real entries of this author hold 0.042 to
   0.112 tokens per byte, counted as this rule counts, and 299 to 14 512 bytes per line (measured on 2026-11-22): the
   token bound is reached between 72 and 192 MiB, the line bound only by lines shorter than 256 bytes on average; a
   longer ledger is to be sealed in segments (the ingest archive, §20 rules 8 to 11). Its writer (`Ingestor`) seals
   the open segment before an entry would take it past 2^23 tokens (outside the lock of `append`, as its rotation by
   entries, so a slow TSA anchor never holds the other appends), takes no `rotate_entries` above 2^20 and refuses
   an entry of more than 2^23 tokens (`ValueError`): until the review of 2026-11-22 it sealed on the number of entries
   alone, 100 000 by default, and 100 000 entries of 104 tokens each made a segment `verify_archive` refused (ok on
   a72d51d). The readers of a ledger beside the verifier apply the same count to its bytes and parse no line of a
   ledger over a bound: the signature layer (`signer.verify_file` and the MCP tool `verify_ledger`: the one failure
   `{"idx": 0, "reason": "input_too_large"}`) and the evidence pack (`verify_pack`: the ledger is `hash_pass`,
   `sig_pass` and `untruncated` false, `artifact_invalid` with the reason of the table). Until that review they parsed
   every line: `evidence_pack.py verify` on a pack whose ledger was 128 MiB of 8 Mi lines `{"signature":1}` ended in
   `MemoryError`, no receipt, under a data limit of 3 GB. Held by `test_ledger_budget_20261122.py`
   (16 tests; of the 7 written with the rule, 5 fail on a72d51d and the 2 named `*_control` pass; of the 9 added on
   review, 5 fail on 33678c9), `TestRule9TheBudgetOfALedger` in `verifiers/go/input_test.go` and twelve checks in
   `verifiers/js/test.mjs`.
   Not bounded by this rule: the readers that take a ledger one line at a time and keep nothing (`cryptovalid_tip.chain_tip`,
   `evidence_pack._entries_and_head` when a pack is built, `cryptovalid_monitor`: a line of at most 256 MiB), the
   other JSON readers of the Python package (documents of at most 64 MiB, §5 step 0)
   and the Rust and Swift verifiers (no toolchain on the bench; they read the ledger whole). By the measurement of the
   ledger path, one 64 MiB line of `{}` values reached 1631 MiB in Python (a receipt; not measured reader by reader).

## 23. What `cryptovalid-verify` checks, and what a verification profile adds (NORMATIVE since v0.15, 2026-11-23)

A relying party must be able to see what a verifier checks before it trusts a verdict, and to ask for more than the
default without being able to ask for less. This section was written before the code. Direction followed (sources read
on 2026-11-23): in-toto 1.0 §5.2 runs every step of the final-product verification in order, with no step the verifier
may skip; Sigstore's policy-controller combines the matching ClusterImagePolicies with AND, and an image that matches no
policy is refused by default; sigstore-python takes a verification policy for every verification, on top of the
signature, inclusion and certificate checks; RFC 9943 (SCITT architecture, June 2026) §7.1 lets a relying party apply
its own validation policies after the Transparent Statement (the signed statement with its receipts) has been verified
and validated. Differences, declared: cosign `verify` has options that turn
checks off (`--insecure-ignore-tlog`, `--insecure-ignore-sct`, `--check-claims=false`), policy-controller has
`mode: warn` and a `static` authority that passes without any signature, sigstore-python has `UnsafeNoOp` ("This policy
is fundamentally insecure"); this format has none of these, by rule 3. A profile here is a closed JSON document, not a
policy language (CUE, Rego): it names pins the verifiers of this repository already take.

1. **The list of checks.** `cryptovalid-verify --list-checks [COMMAND] [--format text|json]` prints, for each check
   of the commands `auto`, `pack`, `archive`, `ledger`, `ap2` and `cldma`: a stable `id`, the commands that run it,
   whether it always runs (`required: "always"`) or is added by a profile (`required: "profile"`, with the profile
   member that adds it in `enabled_by`), when it can be SKIP, and the norm that asks for it. The list is the table the
   code reads to write each layer of a receipt (`verify_evidence.CHECKS`) and the table the profile reader accepts
   (`verify_evidence.REQUIREMENTS`): a layer whose id is not in the table cannot be written, and an entry of the table
   that no code writes is a test failure (`test_checks_profile_20261123.py`). Each layer of a receipt carries its `id`.
   The JSON form is `{"list_format": "cryptovalid-verify-checks/1", "checks": [...]}`. The commands `checkpoint`,
   `tiles`, `vkey-rfc6962` and `beacon` are run by their own modules (§13, §14, §19): `--list-checks` names each in one
   row (`id` the command, `layer: null`) with the section that defines it; their checks are not in this list.
2. **The profile document** (`--profile FILE`) is read under §5 step 0 (a regular file, opened once without
   blocking), at most 1 MiB, UTF-8 without a byte order mark, one JSON object. It is refused (rule 4) when a key is
   written twice in any object, when it holds `NaN` or `Infinity`, or when any member is outside these lists:
   - top level, all three required: `profile_format`, the string `"cryptovalid-verify-profile/1"`; `name`, a string
     of 1 to 200 characters without control characters; `require`, an object with at least one of `ledger`, `pack`,
     `archive`, each a non-empty object.
   - `require.ledger` (`verifier.verify_ledger`): `log_key` (`trusted_pubkey_hex`: a signed tip verified with this
     key is required, §22 rule 1), `log_pq_key` (`trusted_pq_pubkey_b64`, needs `log_key`, §17), `tip_not_before`
     (needs `log_key`, §17 rule 2, the instant profile of `cryptovalid_tip.parse_instant`), `ledger_id`
     (`expect_ledger_id`, §17 rule 1). There is no member for `require_tip`: a tip is checked only with a trusted log
     key (§17), so alone it can only fail, and `log_key` already requires the tip.
   - `require.pack` (`evidence_pack.verify_pack`): `manifest_signer` (`manifest_signer_hex`, §10), `ledger_signer`
     (`signer_pubkey_hex`, §5 step 5), `ledger_pq_key` (`pq_pubkey_b64`, needs `ledger_signer`, §10, §15),
     `tsa_certs` (§10, §11, §22 rule 7: the RFC 3161 token is required and `time_anchor` must be `verified`),
     `tsa_crls` (§11 step 8, needs `tsa_certs`), `signature_domain` (`true`: `require_signature_domain`, §22 rule 3:
     a 1.1 pack is refused; it does not ask for a signature, an unsigned 1.2 pack meets it: `manifest_signer` does).
   - `require.archive` (`cryptovalid_ingest.verify_archive`): `head_key` (`expected_pubkey_hex`, §17 rule 4, §20
     rule 8), `tsa_certs` (§22 rule 7), `signature_domain` (`true`, §22 rule 3: a signed tree head or HEAD without
     `sig_domain` is refused; an unsigned archive meets it: `head_key` asks for the signature).
   A key is 64 lowercase hexadecimal characters (an Ed25519 public key; `ledger_id`, a `self_hash` of §3); a
   post-quantum key is strict base64 of 1952 bytes (ML-DSA-65); `tsa_certs` and `tsa_crls` are non-empty arrays of
   distinct strings, each the path of a file of certificates (§11) or of one CRL, relative paths read from the
   directory of the profile file; each file is read once, when the profile is read, and parsed (a CRL only where
   `cryptography` is installed: without it the run of rule 3 decides, and it is not valid); the bytes read are the
   bytes every run of rule 3 is given, and the ones rule 5 names.
3. **A profile only adds.** No member and no command-line option turns a check of rule 1 off; the only boolean value a
   profile takes is `true`, and `false` is refused with the reason. The verification of a profiled run is, in order:
   (a) the verification without a profile, unchanged; (b) for each requirement, the same verification with the pins
   of that requirement and of the requirements it needs; (c) when there is more than one requirement, the same
   verification with all of them. Each requirement is `met` when its run (b) is valid, `not_met` when it is not,
   `not_evaluated` when a check of that run could not run here (`CheckNotRun`); `valid` is true only when (a) is valid,
   every requirement is `met` and (c), when run, is valid. So a profile cannot turn a verdict of (a) from not valid to
   valid, and a requirement that cannot be evaluated here leaves the result not valid.
   Runs (b) and (c) read the evidence again from the path. A ledger that is not a regular file (a pipe,
   `ledger <(...)`, read once by (a)) cannot be read again: every requirement is `not_evaluated`, nothing more is
   read, the result is not valid. (d) Before (a) and after the last run, the command takes a fingerprint of the
   path and, for a directory, of every entry under it (at most 2^20): what `lstat` says (device, inode, type and
   mode, size, mtime and ctime in nanoseconds; on Windows, where `st_ctime` is the creation time, also the file's
   ChangeTime, since 0.29.0); for a symbolic link also what `stat` says of what it names, since
   the runs follow links; and the SHA-256 of the bytes of every regular file, since a file rewritten in the clock
   tick of its last change keeps its timestamps (measured on Linux 6.6, btrfs: 1952 of 2000 files rewritten in
   place right after they were written kept size, mtime and ctime). A link below the path that names a directory is
   not walked (a run may follow it): the fingerprint cannot be taken. If the two fingerprints differ, or either
   could not be taken, a file was replaced, rewritten or renamed between the runs, or that cannot be excluded:
   `outcome` is `not_evaluated` and the result is not valid. Outside this rule: a change inside the reading of a
   single run, and a change made and undone between the two fingerprints that restores the bytes and all these
   values (it needs both writes in the clock tick of the file's last change, or privileges to set ctime back).
4. **Refusals.** A profile that is not readable, not valid JSON, not closed as in rule 2, of a wrong type, with a
   value `false`, with a requirement missing what it needs, or with a file it names unreadable or not a certificate /
   CRL (rule 2), is a usage error: exit 2, the reason on stderr, nothing on stdout, nothing verified. `--profile` given with
   `ap2` or `cldma` (no requirement is defined for them) or given twice is exit 2. The commands of rule 1's last
   sentence take their own options: `checkpoint`, `vkey-rfc6962` and `beacon` refuse `--profile` as an unknown
   option, exit 2; `tiles` has its own `--profile`, the name of a C2SP log profile (§14: `static-ct-api` or
   `tlog-tiles`), unrelated to this section.
5. **The receipt names the profile.** Without `--profile` the receipt has `"profile": "default"`. With it,
   `profile` is an object: `profile_format`, `name`, `sha256` (of the bytes of the file as read), `files` (one
   `{"requirement", "path", "sha256"}` for each certificate or CRL file the profile names, in any section: the path
   as written and the SHA-256 of the bytes read; `[]` when it names none), `applies_to` (the
   kind verified, the one `auto` chose), `requirements` (each `{"id", "state", "detail"}` in the order of the
   table), `together` (the state of run (c), or `null` when there was one requirement), `evidence_unchanged` (the
   comparison of rule 3 (d); `null` when no requirement was run), and `outcome`: `not_evaluated` when `evidence_unchanged` is false, otherwise `met` when
   every state is `met`, otherwise `not_met` when one is, otherwise `not_evaluated`; or `not_applicable` when the profile has no section for the kind verified (`auto` routed
   the path to another kind; then `valid` is false). When the verification without a profile could not run a check
   (exit 74, §10), the receipt carries the profile with `outcome: "not_evaluated"` and no requirement run.
6. **Without `--profile` nothing changes** but the two added members (`profile`, and `id` in each layer): the layers,
   their order, their names and statuses, `valid` and the exit status are those of v0.14.

Not in this section: requirements for the experimental `ap2` and `cldma` commands (ap2-evidence-pack has its own
pins), for the modules without a `cryptovalid-verify` command (`cryptovalid_acta.py`, `cryptovalid_aps.py`), and the
`lotl_check` of the archive verifier (it reads the EU trusted lists from the network).

## 24. SLH-DSA archival anchors, `omega-slhdsa-anchor-v2` (NORMATIVE since v0.15, 2026-11-23)

An archival anchor binds a hash (a checkpoint root, a segment root) to a signature whose security rests on hash
functions only: SLH-DSA, FIPS 205 (CSRC document history, read on 2026-11-23: draft 08/24/23, final 08/13/24, nothing
later). It is the leg of an archive that is meant to outlast the Ed25519 and ECDSA signatures NIST IR 8547 (§15)
deprecates after 2030 and disallows after 2035. This section was written before the code. The format is that of
pq-scitt (`src/pq_scitt/anchors/slh_dsa.py`, commit 9692a74, Apache-2.0, same author); `cryptovalid_slhdsa.py` ports
its verification only (no key generation, no signing).

1. **The anchor** is one JSON object with exactly the members `schema`, `backend`, `param`, `root`, `ts`, `sig`,
   `pub`; a missing or an extra member is a refusal. `schema` is the string `"omega-slhdsa-anchor-v2"`; `backend` is
   `"slhdsa"` or `"oqs"` (the library that signed; informative only: the signature is the same scheme for both and is
   verified the same way); `param` is one of the twelve FIPS 205 parameter sets, written `sha2_128s`, `sha2_128f`,
   `sha2_192s`, `sha2_192f`, `sha2_256s`, `sha2_256f`, `shake_128s`, `shake_128f`, `shake_192s`, `shake_192f`,
   `shake_256s`, `shake_256f`; `root` a non-empty string that has a UTF-8 encoding (a lone surrogate, which JSON can write as `"\ud800"`, has
   none: refused, `type`); `ts` a finite JSON number (not a boolean; an integer of at most 4300 digits, §30); `sig` and `pub`
   lowercase hexadecimal of a whole number of bytes, `pub` of the parameter set's public key length (2n: 32, 48 or 64
   bytes) and `sig` of its signature length (FIPS 205 Table 2: 7856, 17088, 16224, 35664, 29792, 49856 bytes for 128s,
   128f, 192s, 192f, 256s, 256f, SHA2 and SHAKE alike).
2. **The signed message** is the UTF-8 bytes of the JSON object `{"param", "root", "schema", "ts"}` with the values of
   the anchor, serialised as Python's `json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)`
   writes it: not the canonical form of §3 (non-ASCII characters are written as UTF-8, not escaped, and `ts` is
   usually a float, written as Python's shortest round-trip representation, e.g. `1763900000.123456`). An
   implementation in another language must reproduce these bytes; a float whose Python representation differs from
   its language's (`1e+16` and `10000000000000000`) is a known source of a false refusal, never of a false acceptance.
3. **The signature** is FIPS 205 "pure" SLH-DSA, `slh_verify` (Algorithm 24), with an empty context string, over the
   message of rule 2, with the public key `pub` (or the pinned key, rule 4).
4. **Pinning.** Without a pin the key is the one the anchor carries: the result says the anchor is intact, not who
   signed it. With a pin (the caller's expected public key), a `pub` that differs from it is a refusal (`pin`) before
   any signature is checked.
5. **Result, closed.** `verify_anchor(anchor, pub=None)` returns `{"valid", "code", "detail"}` with `valid` true only
   for `code: "ok"`. The refusals, in the order they are checked: `not_object`, `schema` (another value of `schema`;
   `omega-slhdsa-anchor-v1` is refused here: its `slhdsa` backend signed with the library's internal interface,
   `slh_verify_internal` without the FIPS 205 domain prefix, measured by pq-scitt on the NIST vectors),
   `members`, `type` (a member of the wrong type, or a value outside rule 1), `encoding` (`sig` or `pub` not
   lowercase hexadecimal), `length` (rule 1's lengths), `pin`, `signature` (it does not verify). A pin that is not a
   string or bytes is a TypeError, a pin string that is not hexadecimal a ValueError: errors of the caller, not
   verdicts on the anchor.
6. **A check that cannot run here.** The signature is checked with the `slh-dsa` package (PyPI, LGPL-3.0-or-later,
   the library pq-scitt uses; the optional extra `slh` of this package). Where it is not installed, an anchor that
   passes rules 1 and 4 raises `verifier.CheckNotRun` with the reason: never `valid: true`, never a refusal of an
   anchor that may be valid. Rules 1, 4 and 5 run without it.
7. **Vectors.** `spec/vectors/slhdsa/nist_acvp_slhdsa_sigver.jsonl.gz`: 84 cases of the NIST ACVP SLH-DSA sigVer
   file (FIPS 205, external interface, pure, every parameter set, the first case of each of the seven reasons; NOTICE
   and `tools/build_nist_acvp_slhdsa.py` say what was selected and how). The primitive of rule 3 must give each case's
   `testPassed`, with the case's context.

Not in this section: the `oqs` backend (liboqs, which `pq-scitt` uses when it is installed: importing its Python
binding without the C library starts a download and a build, so it is never imported here), the HashSLH-DSA
(pre-hash) variants, the creation of anchors, and what `ts` means: it is the signer's statement of the time, not a
time proof (§11 and §19 are the time proofs of this format).

## 25. DSSE envelopes carrying in-toto Statements (NORMATIVE since v0.15, 2026-11-23)

DSSE (Dead Simple Signing Envelope) with an in-toto Statement is the format of GitHub artifact attestations, of
Sigstore's attestations and of SLSA provenance. This section says how `cryptovalid_dsse.verify_envelope` reads one; it
was written before the code. Versions in force on 2026-11-23: DSSE v1.0.2 (secure-systems-lab/dsse, tag v1.0.2; master
is 27 commits ahead, changing governance/, README.md, MAINTAINERS.md and background.md, not protocol.md or envelope.md)
and the in-toto Attestation Framework v1.2.0 (in-toto/attestation, release of 2026-03-18; Statement v1). The code is
ported from omega-evidence (`omega_evidence/interop/dsse.py`, commit c26f4e6, Apache-2.0, same author): verification
only.

1. **The envelope** is the JSON text (UTF-8, at most 64 MiB) of the DSSE JSON envelope: an object with `payload` (a
   string), `payloadType` (a string) and `signatures` (an array of objects, each with `sig`, a string, and optionally
   `keyid`, a string). A `payloadType` that has no UTF-8 encoding (a lone surrogate, which JSON can write as
   `"\ud800"`) has no PAE (rule 2): code `envelope`. JSON is read with a name written twice in one object, `NaN` / `Infinity`, a byte order mark and
   nesting deeper than 512 refused (code `envelope`), as the payload is (rule 3). Members outside these are ignored, as
   envelope.md requires ("Consumers MUST ignore unrecognized fields"), and named in `unrecognized_fields`. `payload`
   and each `sig` are base64, standard or URL-safe (DSSE: "verifiers MUST accept either"), one alphabet per string,
   padded, with nothing else (code `base64`).
2. **Signatures.** Each signature is checked over PAE(`payloadType`, payload) — `"DSSEv1" SP len(type) SP type SP
   len(body) SP body`, the lengths in decimal bytes — with the keys the caller trusts, and only those: a key the
   envelope carries is never used, and `keyid` is not read (DSSE: it "MUST NOT be used for security decisions"). Keys
   are Ed25519, or ECDSA P-256 with SHA-256 whose signature is DER (re-encoded byte for byte) or the raw 64 bytes r||s
   of DSSE's own test vector; given as an SPKI or an X.509 certificate (its chain, validity and identity are not
   checked here). The envelope passes this rule when the number of distinct keys that verify a signature is at least
   the threshold (default 1; DSSE "Multi-signature Verification"); the same key given twice is an error of the caller.
   Otherwise the code is `signature`.
3. **The statement** (in-toto docs/validation.md, Statement layer, after the signature): `payloadType` must be
   `application/vnd.in-toto+json` or `application/vnd.in-toto.<predicate>+json` (validation.md writes the test with
   "OR"; read as the two accepted forms), else `payload_type`. The payload is JSON read as in rule 1, an object whose
   `_type` is `https://in-toto.io/Statement/v1`, whose `subject` is an array of objects each with a non-empty `digest`
   object of strings, whose `predicateType` is a non-empty string, and whose `predicate`, when present, is an object;
   else `statement`. Other members are ignored (in-toto "Parsing rules": "Consumers MUST ignore unrecognized fields unless
   otherwise noted in the predicate specification"; the predicate is not read here, rule 5).
4. **The artifact.** When the caller gives the artifact's bytes, at least one subject must carry, for an algorithm the
   caller accepts (default `sha256`; `sha384`, `sha512`, `sha3_256`, `sha3_384`, `sha3_512`), the hex digest of those
   bytes, compared without regard to case (validation.md, `matchedSubjects`); else `subject`. Without an artifact no
   subject is matched and the result says so.
5. **What is not checked here:** who the key belongs to (a Sigstore certificate's chain to Fulcio, its identity, the
   Rekor inclusion or the signed timestamp), what the predicate says (SLSA provenance or any other type), and the
   policy a relying party applies to it.
6. **Result, closed.** `{"valid", "code", "detail", "payload_type", "statement", "verified_keys", "matched_subjects",
   "unrecognized_fields"}`; `valid` is true only for `code: "ok"`. The codes, in the order they are decided:
   `envelope`, `base64`, `signature`, `payload_type`, `statement`, `subject`. Errors of the caller (no key, a key
   that does not load or is of another type, a threshold out of range, an unknown digest algorithm, an artifact that
   is not bytes) raise ValueError or TypeError and decide nothing. Without `cryptography` the keys cannot be loaded:
   `verifier.CheckNotRun`, never a verdict.
7. **Vectors.** DSSE's test vector (protocol.md v1.0.2: its signature verifies, its payload type is not in-toto, so
   the code is `payload_type`), and `testdata/dsse/github_attestation_cvo_0.28.1_wheel.json`, the Sigstore bundle
   GitHub's attestation service made for this repository's 0.28.1 wheel (`ok` with the key of its certificate).

## 26. What the weekly fuzz run holds the readers to (NORMATIVE since v0.15, 2026-11-23)

Written before the workflow. `.github/workflows/fuzz-weekly.yml` runs `tools/fuzz_readers.py` every week on a new seed
(the run number; a finding is reproduced with `--seed`), for a time budget, under Python 3.9, 3.11 and 3.13, with and
without `cryptography` and `slh-dsa`. It mutates the bytes of a valid input (bits, bytes, truncation, lines; JSON
members removed, added, renamed, written twice, of another type, nested) and requires of the reader:

1. **A changed input is accepted only when its signed content is unchanged.** `verifier.verify_ledger` says PASS only
   when the entries, parsed by the fuzzer's own JSON reader (a name written twice refused), are a non-empty prefix of
   the original entries (a chain cut at its tail is still a chain, §5); `cryptovalid_dsse.verify_envelope` is valid
   only when the decoded payload and `payloadType` are the original ones; `cryptovalid_slhdsa.verify_anchor` is valid
   only when the anchor is the original, `ts` of the same JSON type.
2. **No undeclared exception.** On these inputs none of the three raises.
3. **The run can fail.** Before it is trusted, each property is shown to catch a reader whose check is disabled in
   the fuzzer's process (`--ablate ledger|dsse|slhdsa`: the chain verdict, the DSSE signature, the SLH-DSA signature):
   the same seed must then report violations, or the job fails.
A violation fails the job; the inputs that broke a rule are kept as an artifact of the run. CodeQL (`codeql.yml`)
analyses the Python code on every push and pull request and every week; its findings go to code scanning.

## 27. The verification Action (NORMATIVE since v0.15, 2026-11-23)

Written before `action.yml`. `uses: robertolocatelli81-dev/cryptovalid-opencore@v<version>` with `args` runs
`cryptovalid-verify <args>` in a GitHub Actions job, in this order, each step stopping the job when it fails:

1. `version` (default: the version of the release the action is taken from) must be three dot-separated numbers and
   `cryptography` `true` or `false`, before anything is downloaded.
2. The wheel `cryptovalid_opencore-<version>-py3-none-any.whl` is downloaded from this repository's GitHub Release
   `v<version>`, and its build provenance is verified with `gh attestation verify` for exactly the signer
   `https://github.com/robertolocatelli81-dev/cryptovalid-opencore/.github/workflows/release-build.yml@refs/tags/v<version>`,
   the source ref `refs/tags/v<version>`, on a GitHub-hosted runner. A release without that attestation (0.24.0 and
   earlier: the first wheel with one is that of 0.25.0, measured with `gh attestation verify` on 2026-11-23) is refused.
3. Only then the wheel is installed, without dependencies, into a new virtual environment; with `cryptography: true`
   (default) `cryptography>=48` is installed from PyPI as well, by version range, not by hash.
4. `args` is split on whitespace and passed as separate arguments, never through a shell (no quoting, globbing or
   substitution). The step's exit status is that of `cryptovalid-verify` (0 valid, 1 not valid, 2 usage, 74 a check
   that could not run here, or a receipt not written whole), also given as the output `exit-code`; the output `wheel-sha256` is the SHA-256 of the
   wheel that was verified.
Inputs reach the scripts only through environment variables. Not done by the action: pinning the PyPI dependency by
hash, and any check of the evidence beyond what `cryptovalid-verify` does with the given arguments.
## 28. COSE Receipts of an MMR, vds 3 (NORMATIVE since v0.15, 2026-11-23)

`cryptovalid_cose_receipts.py` (experimental module) verifies the COSE Receipts of RFC 9942 for vds 1 (RFC9162_SHA256)
and vds 2 (CCF, draft-ietf-scitt-receipts-ccf-profile-06). This section adds the verifiable data structure of
draft-ietf-scitt-receipts-mmr-profile-00, "COSE Receipts for MMRs" (R. Bryce, J. Geater; SCITT working group document,
posted 2026-11-21; datatracker read on 2026-11-23: revision 00 current, it replaces draft-bryce-cose-receipts-mmr-profile
whose last revision is -05). It was written before the code. The draft is a working document: a later revision may
change what this section follows, and the section will be revised against it.

1. **The value of vds.** The draft registers `MMR_SHA256` as `TBD_1` and does not request a value; IANA's "COSE
   Verifiable Data Structure Algorithms" registry holds only 1 (read on 2026-11-23). This verifier reads **3**:
   draft-bryce-cose-receipts-mmr-profile-04 §12 wrote "TBD_1 (requested assignment 3)", and the implementation of the
   draft's author (forestrie/protocol, `spec/label-registry.md`) writes 3 and says it is not registered. 2 is the value
   requested by the CCF profile. The label `tree-size-2` is `-65933`, the private-use value the draft names until
   `TBD_2` is assigned (§12.1.3). Both change here when IANA assigns them.
2. **The protected header** of an MMR receipt is read under the draft's §7, for inclusion and consistency alike (§5
   refers to it): Core Deterministic Encoding of RFC 8949 §4.2.1 (definite lengths, arguments and floating-point values
   in shortest form, map keys in strictly increasing bytewise order of their encodings, so no duplicate), one map
   filling the whole byte string. Anything else is `PROTECTED_HEADER_ENCODING`. Labels are COSE labels (RFC 9052 §1.4:
   int or text). A label the verifier does not read is ignored whatever its value (draft §7: "MUST ignore protected
   header labels it does not recognise, whatever the type of their values"), and reported in `ignored_labels`; a label
   listed in `crit` that is not 1 or 395 (and -65933 for consistency, 15 under profile `rfc9943`) is refused, as RFC
   9052 §3.1 asks. The unprotected header is not signed and no rule asks it to be deterministic: it is read as
   well-formed CBOR, and only `vdp` (396) is read from it.
3. **A receipt of inclusion** (draft §4, §5, §5.1, §5.2): `vdp` is exactly `{-1: [+ bstr]}`; each bstr is the CBOR
   `[uint index, [* bstr .size 32]]` with an index below 2^64 - 1 and at most 64 hashes (§2: a tree is at most 63
   high); the payload MUST be detached; the caller's `entry` is the **node value** (32 bytes), which the caller computes
   under the log's leaf commitment scheme (the draft leaves it to the application, §11.2); `included_root` gives the
   peak, and the log signature is checked over it. Every proof must be well formed and give the same peak, since one
   payload is signed (`PROOFS_DISAGREE`; the draft speaks of one proof). The result reports `node_height` (whether the
   node is a leaf is read from its height, §11.2) and `index_bound`: false when a path is empty, since then the index
   is not bound (§11.1). A `vdp` holding only `-2` is a receipt of consistency (`OTHER_RECEIPT_KIND`).
4. **A receipt of consistency** (draft §6, §7, §7.1, §7.1.1) is verified by `verify_mmr_consistency(receipt, log_key,
   trusted_size, trusted_accumulator)`: `vdp` is exactly `{-2: [+ bstr]}`; `tree-size-2` present (else
   `SIGNED_SIZE_MISSING`) and an unsigned integer; equal to the last proof's (`SIGNED_SIZE_MISMATCH`); each proof's
   `tree-size-1` equal to the state reached so far, starting from the trusted size (`CHAIN_NOT_CONTIGUOUS`); every
   proof folded by `consistent_roots` with each of its "-> ERROR" a refusal naming the class; the right-peaks of the
   count it returns; the log signature over the final accumulator, peaks concatenated highest first. The trusted
   state must be a complete MMR size (0 is the empty tree) with one 32-byte value per peak (`TRUSTED_STATE_INVALID`).
   The trusted vds is MMR_SHA256, the only one supported, so step 2 of §7.1 is `vds == 3`. The result is the new
   state; the caller keeps it (the draft: trusted state advances only forwards).
5. **Signature algorithms** are those of vds 1 and 2: EdDSA with Ed25519, ES256 with P-256, ES384 with P-384.
6. **Vectors.** `spec/vectors/forestrie-mmr/` holds the KAT-39 file of forestrie/protocol (MIT; generated by the
   reference implementation of the draft's author): receipts of consistency and the fold. No public vector of a
   receipt of inclusion in the form of draft -00 was found on 2026-11-23: Forestrie's inclusion receipts carry the
   proof as a `{1, 2}` map, not a bstr, and no vds (its `spec/checkpoints-and-receipts.md` §4.2 lists these
   departures); this verifier refuses them. The inclusion tests sign their own receipts over a tree built with the
   draft's `add_leaf_hash`, and check `included_root` against the 21 accumulators of the KAT-39 tree: vectors of this
   repository, no external confirmation of an inclusion receipt. `spec/vectors/aac-cll-mmr/` holds 184 unsigned
   proofs of action-state-group/agent-action-capsule (BSD-3-Clause, written from draft-bryce -02): 92/92 inclusion
   proofs reach a peak and 79/79 consistency proofs give the new peaks; its 13 cases from a size to the same size are
   refused, since draft -00 §7.1.1 writes "if sizeto <= sizefrom -> ERROR". They confirm the two algorithms, not a
   signed receipt.

Where Forestrie's rules (its ADR-0066, D9) and this verifier answer differently, measured on 2026-11-23 on the KAT-39
file, this verifier follows the draft's text:

- **Bare proof.** Forestrie's older receipts carry one `bstr` under `vdp` -2; draft -00 §7 has `consistency-proofs = [
  + consistency-proof ]`. Refused here (`MALFORMED_PROOF`); the ten `receipts` and five `receipt_negatives` rows are
  in that form, and their ES256 rows verify, or are refused for the reason the file expects, once that unprotected
  value is put in an array.
- **Low s.** Forestrie refuses an ES256 signature with a high `s`; RFC 9053 §2.1 has no such rule and the draft adds
  none. `reject/es256-high-s` is accepted here.
- **KS256** (secp256k1 with Keccak-256, the five KS256 rows) is not a COSE algorithm this verifier implements:
  `UNSUPPORTED_ALG`.
- **Seven of the 52 protected-header rows.** Forestrie sorts map keys shorter encoding first, then bytewise (the order of
  RFC 8949 §4.2.3); the draft and RFC 8949 §4.2.1 sort bytewise, so the row `skip/two-unread-labels-length-first-order`
  (`-1` before `24`) is refused here. Forestrie refuses an array, a map, a tag, `undefined`, simple value 40 and a
  negative label beyond 64 bits under a label it does not read; the draft ignores such a label "whatever the type of
  its values": the six rows are accepted here. The other 45 rows agree.

## 29. Verification of a composite ML-DSA signature, RFC 10073 (NORMATIVE since v0.15, 2026-11-23)

`cryptovalid_composite.py` (experimental module) verifies a signature of RFC 10073, *Composite Module-Lattice-Based
Digital Signature Algorithm (ML-DSA) for Use in X.509 Public Key Infrastructure* (Proposed Standard, November 2026;
rfc-editor.org read on 2026-11-23: not obsoleted, not updated; one erratum, 9300, Reported on 2026-11-10, on the
`CODE STARTS` tag of the ASN.1 module of §7, which this section does not use). It does not sign,
and nothing in this format is signed with it: §15 stays, the hybrid of this format is not a composite. This section
was written before the code.

1. **Algorithms** (RFC 10073 §6), each by its name or its OID: `id-MLDSA65-Ed25519-SHA512` (1.3.6.1.5.5.7.6.48),
   `id-MLDSA65-ECDSA-P256-SHA512` (1.3.6.1.5.5.7.6.45, ecdsa-with-SHA256 on secp256r1) and
   `id-MLDSA65-ECDSA-P384-SHA512` (1.3.6.1.5.5.7.6.46, ecdsa-with-SHA384 on secp384r1): ML-DSA-65 with the
   traditional algorithms the COSE verifiers of this repository already check. Any other name is refused
   (`UNSUPPORTED_ALG`); the RSA, brainpool, Ed448, ML-DSA-44 and ML-DSA-87 combinations are not verified here.
2. **Verify** follows §3.3: `ctx` longer than 255 bytes is an error; `M' = Prefix || Label || len(ctx) || ctx ||
   SHA512(M)` with Prefix the ASCII bytes of `CompositeAlgorithmSignatures2025` (§2.2) and the algorithm's Label; the
   ML-DSA-65 signature is checked over `M'` with the Label as its context, the traditional one over `M'`; the result is
   valid if and only if both are, and the answer names the component that failed.
3. **Keys and signatures are closed** (§4.1, §4.3; §3.3 step 2: "if any of the component keys or signature values are not of
   the correct type or length ... output Invalid signature"): the public key is `mldsaPK || tradPK` with the 1952 bytes
   of ML-DSA-65 first; the traditional key is 32 bytes for Ed25519, and for ECDSA an uncompressed X9.62 point (0x04,
   then 64 or 96 bytes; a compressed point is refused) on the algorithm's curve. The signature is `mldsaSig ||
   tradSig` with the 3309 bytes of ML-DSA-65 first; Ed25519 64 bytes; ECDSA an `Ecdsa-Sig-Value` in DER (RFC 3279
   §2.2.3; §4: "All ASN.1 objects SHALL be encoded using DER"): a value that is not DER (a long-form length, a
   superfluous leading zero, a byte after the SEQUENCE, COSE's raw r || s) is refused before any signature check.
4. **Keys do not move between the two constructions** (§15 rule 3; RFC 10073 §5.3, §9.3): the verifier takes the
   composite public key as one value and never reads the `signer` / `signer_pq` fields of a ledger entry, and the
   ledger verifier never reads a composite key. A relying party that holds a hybrid pair of this format has no
   composite key: it MUST NOT concatenate them into one.
5. **Vectors.** `spec/vectors/rfc10073/rfc10073.txt` is the RFC's text from rfc-editor.org, kept in full and without
   modification as the IETF Trust Legal Provisions 5.0 §3.c.i allow (read on 2026-11-23), pinned by SHA-256. The test
   extracts the vectors of Appendix E from it at run time and fails, never skips, when the file is missing or its hash
   differs; with `CV_COMPOSITE_VECTORS` it also compares the copy of lamps-wg/draft-composite-sigs
   (`src/testvectors.json`, commit b9e2674): identical for the three algorithms. Measured on 2026-11-23: the signatures `s`
   (empty ctx) and `sWithContext` of the three algorithms verify, and are refused with one bit changed, with the
   other ctx, under another of the three algorithms and with the ECDSA signature re-encoded in non-minimal BER.

## 30. One nesting bound for every JSON text (NORMATIVE since v0.15, 2026-11-24)

Every JSON text the reference implementation reads — ledger lines, tree heads and HEADs, manifests, receipts, tips,
profiles, state files, MCP messages, documents of other formats — is refused when its nesting exceeds 512 levels
(`MAX_JSON_DEPTH`, the bound §3 already set for a ledger line), measured by a linear scan before it is parsed. Each
reader answers such a text as it answers a text too deep to parse (the same reason and the same outcome), at every depth
over 512 and on every Python. Until 0.29.0 most readers left the depth to Python's parser, whose limit moved with the
version (the first `RecursionError` of a bare `json.loads`, measured on 2026-11-25 on Linux: at 995 levels under Python 3.9
and 3.11, 9 998 under 3.12, 9 999 under 3.13, 65 168 under 3.14; fewer inside a chain of calls): a text 5 000 levels deep was refused under 3.9 and read under 3.13. Bytes are decoded as `json.loads` decodes them (UTF-8, UTF-16 or UTF-32) before
the scan, which reads characters. A format with a lower bound
of its own (Cedulon: 500) keeps it.

An integer of more than 4300 digits (the sign not counted) is refused too, in the same texts and as the `ts` of §24 rule
1: 4300 is the default limit of Python's own conversion since 3.9.14, 3.10.7 and 3.11, and a Python without one (3.9.13)
read the number and went on. The integers of a ledger line and of a tip keep the narrower bound of §3: such a line is
refused by the six verifiers at any length (measured on 2026-11-25 with 4300 and 4301 digits, positive and negative:
verifier.py, JS, Go, Java and Rust on a ledger, the JSON reader of the Swift verifier alone; verifier.py, JS, Go and
Java on a tip), and past 4300 digits verifier.py names this bound as the reason of a ledger line, the others the
range of §3. An outcome changes only under a Python without the limit (3.9.0 to 3.9.13, 3.10.0 to 3.10.6, or one
started with `PYTHONINTMAXSTRDIGITS=0`), where such a text was read before this rule; under the others the refusal
was already there, with the interpreter's own words.

## 31. A file name of a pack names one file on every system (NORMATIVE since v0.15, 2026-11-24)

A name in `file_digests_sha256` or in `ledgers[i].file` of `MANIFEST.json` is a relative path whose components are
separated by `/` only. It is refused (`malformed`, the reason naming the first such name and why) when it is empty or
not a string, contains NUL, is not encodable as UTF-8 (a lone surrogate), contains a backslash `\`, contains a colon `:`
(a drive or a device, and on Windows an alternate data stream), starts with `/` or is absolute on the system, has a
`..` component, or ends with `/` or `/.` (`l.jsonl/` fails on POSIX, `l.jsonl/.` opens the file on Windows; `./l.jsonl`
is admitted: it names the same file everywhere), contains a control character (U+0001 to U+001F) or one of
`* ? " < > |` (no file name on Windows holds them), has a component that ends with a dot or a space (Windows drops
them: `l.jsonl.` opens `l.jsonl` there), or has a component whose part before the first dot, less trailing spaces, is
a DOS device name in any case: `CON`, `PRN`, `AUX`, `NUL`, `CONIN$`, `CONOUT$`, `COM1` to `COM9`, `LPT1` to `LPT9`, and
`COM`/`LPT` followed by `¹`, `²` or `³` (`NUL.jsonl` is the null device on Windows; Microsoft, "Naming Files, Paths, and
Namespaces"). Not covered by this rule, and declared: a file system that folds case (the default on Windows and macOS)
or normalises Unicode (macOS) opens `L.jsonl` for `l.jsonl`; there the same manifest can name a file that another
system does not find. `evidence_pack.py build` refuses a ledger whose file name would break the rule, before writing anything.
The same rule is PKWARE's for ZIP (APPNOTE 6.3.10, 2022-11-01, §4.4.17.1, read on 2026-11-24 at
https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT: "The path stored MUST NOT contain a drive or device
letter, or a leading slash. All slashes MUST be forward slashes '/' as opposed to backwards slashes '\'").

Until 0.29.0 the check used the separators of the system running it: `\` was an ordinary character on POSIX (a choice
of the review of 2026-10-01, NEMESIS P2) and a separator on Windows, and a drive was refused only on Windows, so the same
pack named a file inside it on Linux (`a\..\b.jsonl`) and a file beside the pack on Windows. That choice is reversed:
the same manifest now gets the same answer on every system.

## 32. A secret that comes in never goes out (NORMATIVE since v0.16, 2026-11-26)

A private key, a PIN, a token or a password given to a command or to the library of the reference implementation does
not appear in what it writes: standard output, standard error, files, the answers of the MCP server. Written after a
review of 0.29.0 for this one class.

1. **A pack holds ledgers.** `evidence_pack.py build` takes as a ledger only a file that has the form of one. Read as
   bytes, after a UTF-8 byte order mark if there is one, and divided at LF: every line that is not blank (spaces, tabs,
   CR) begins with `{`; a line that parses as JSON (§30) has the member `prev_hash` or `self_hash`; and at least one
   line so parses. A file with nothing but blank lines has the form too (the empty ledger). A line that begins with `{`
   and does not parse, or is past the bounds of §5 and §22 rule 9, is admitted: a damaged ledger is evidence, and its
   verdict in the pack is FAIL as before. Anything else is refused before anything is written, with the number of the
   first line at fault and never its content: so also a ledger damaged in another way (a line that is an array or
   plain text, zero bytes after its last line, CR alone between the lines, UTF-16), which 0.29.0 packed with FAIL. A file whose bytes changed between the judgement and the copy is judged
   again on the copy, which is removed if it has not the form. Every line of a ledger that verifies is an object with
   both members, so no ledger that passes is refused. Measured on 2026-11-25 on the 145 `.jsonl` files of the
   repository: the 139 ledgers (tampered, broken and empty ones included) have the form, the 6 that are not ledgers
   (one benchmark result, five Acta receipt sequences) do not.
2. **A key is not a ledger.** Before rule 1, a file of at most 1 MiB that is a private key is refused as one, and so is
   the `--sign-key` file itself under any name. The forms: 64 hexadecimal digits alone (the seed of `signer.py keygen`);
   a line `-----BEGIN ... PRIVATE KEY-----` or `... PRIVATE KEY BLOCK-----`; PKCS#8 (not encrypted), PKCS#1, SEC 1 or PKCS#12 in DER, or
   their base64; a JWK or JWKS with a member `d` beside `kty`. The key given with `--sign-key` is read before anything is
   written.
3. **An output never replaces a key.** An output path at which a file stands is refused (exit 74, the file intact) when
   the file is, byte for byte, a key file the process has read (whatever its name: a link, a hard link, another letter
   case, a copy), or has one of the forms of rule 2. 64 hexadecimal digits are a seed or a digest, which have the same form: they
   are taken as a seed when the file is private to its owner (no permission bit for group or others; on Windows an
   access list that inherits nothing, as `keygen` sets it) or its name ends in `.key` or `.seed`; otherwise the file is
   replaced. So a digest file that is not private is still rewritten, and a seed that is neither private nor named as a
   key nor read by the command is not recognised. `cryptovalid_scitt register` and `cryptovalid_witness cosign` compare their
   output with their key files before they change the ledger or the state.
4. **A key that cannot be used is an error of use.** A key file that is not what the command reads (not text, not a
   32-byte hexadecimal seed, not the base64 of a PKCS#8 key) ends in a one-line refusal without a traceback, and the
   message does not hold the content.
5. **An argument that can be a secret is not repeated.** Where a usage error (exit 2: an option that does not exist, a
   value that is not accepted) repeats an argument of the command line, a run of 43 or more hexadecimal or base64 digits
   (32 bytes or more) is replaced by a fixed text. `/` is a digit of standard base64 and the separator of a path: a run
   with `/` in it is kept when the folder it names exists, and replaced otherwise. A key given in the place of the path
   of its file, or of the selector of a signing backend, is refused without repeating it. The error for another path
   that names no file (a ledger, a statement) still names the path as given. An argument of a command line is visible
   to other processes of the machine whatever the command does with it.
6. **What is signed is not the key.** `cryptovalid_scitt sign` refuses an attached statement that contains the key it is
   to be signed with (32 bytes, or their hexadecimal digits); `cryptovalid_jws sign` refuses a private key as an `x5c`
   certificate. Otherwise `scitt sign` and `cryptovalid_worm put` take any bytes, by contract: another secret given to them
   as the data is kept as the data.
7. **A witness is not the log.** `cryptovalid_witness` (`cosign`, `serve`, `witness_cosign`, `WitnessService`) refuses to
   cosign when its own public key is the public key of a log it is told to trust, whatever the name and the type byte
   (`NoteError`, before any state is written). §16 rule 4 compares (name, key id) pairs; this rule compares the keys.
8. **A URL in a record has no credentials.** A URL with `user:password@` before the host is refused by the network rule of
   §20 without being repeated. The URL of a time-stamp authority written into a record is its scheme, host, port and path,
   without query and fragment.
9. **The name of a variable is not repeated.** Where an option takes the NAME of an environment variable (`token_env=`,
   `pass_env=`, `pin=env:`), the error for an empty or unset variable does not repeat the name given, which can be the
   secret itself.

Held by `test_secrets_20261125.py`, which also runs the commands with a key in the place of every input and every output
and searches what they print and write for eleven forms of the seed. Not covered: what a process is made to keep in
memory, in a core dump or in swap; the arguments of other programs; a key already in the folder a pack is built in (the
manifest does not list it, but it is in the folder).
