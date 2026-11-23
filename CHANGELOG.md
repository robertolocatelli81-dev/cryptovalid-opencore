<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# Changelog

Release notes and assets: [GitHub Releases](https://github.com/robertolocatelli81-dev/cryptovalid-opencore/releases).
Until 0.22.0 the history was written in README.md; on 2026-11-12 those sections were moved here unchanged (headings
one level down), under the release that shipped them. Dates in the moved headings are the authors' dates; the date
next to each version is the date of its git tag. Where these sections call a review or a red-team "independent", it was
run by the same author, not by a third party.

## Unreleased: verdicts change

### `cryptovalid_acta` follows draft-farley-acta-signed-receipts-04

The -04 of the draft was posted on 2026-11-22 (datatracker, checked on 2026-11-23: revision 04, no -05; individual
draft, not adopted by a working group). The module was written against -03. Measured on 2026-11-23 on b784901, before
this change, against every published vector set for the draft that runs offline: 106 of 115 cases agreed —
ScopeBlind/agent-governance-testvectors at 5c749de (chain-link 21/27, key-window 6/6, signing-input 4/4, revocation 2/2,
timeliness 3/3, negative/embedded-key 3/4), probityai/agent-evidence-vectors `vectors-receipt-signature` at 127cf14
(graded against -03, both key-set passes, 56/58) and the TRACE Acta fixtures of agentrust-io/trace-spec at 6f04de6 (the
signature, signing-input, key-window and chain columns, 11/11). After it: 115/115; with one hex digit of each
signature flipped, 115/115 refused. Each change below follows the text of -04:

- **Three outcomes (§5.4).** `verify_receipt` and `verify_chain` return `outcome` (valid | invalid | undecidable), the
  code that decided and `checks` (each check's result); every check runs and the outcome is invalid if one that ran
  failed, undecidable if none failed and one could not run, valid only if all ran and passed. Until now the first
  refusal returned, so a receipt whose link names SHA3-256 and whose key window had ended was refused for the link
  instead of the window. `verdict` and `assessed` stay, with the same values; the exit status stays 0 / 1 / 77.
- **Now undecidable, was invalid:** a link whose prefix names another hash algorithm (§5.7,
  `unsupported_chain_hash_algorithm`); an `alg` this verifier does not implement (§5.9, `unsupported_algorithm`); a
  receipt shape not recognized, an envelope with a member beside payload and signature or a signature object with
  one beside alg, kid and sig included (§5.2/§5.4, `unrecognized_shape`); a receipt file that is not JSON this verifier
  reads, which ended the command with exit 2 (`input_not_json`, exit 77; the other files are still judged); a
  receipt that cannot be canonicalized (`not_canonicalizable`); an unknown kid with `--keys-are-complete`
  (`issuer_not_trusted`: no key from a trust anchor is available, §5.4); a key window that cannot be applied because
  the signed `issued_at` is absent or not an instant (§5.6); a key window with one bound malformed and the other
  excluding the receipt, or with `valid_until` not after `valid_from`. A null bound ("A bound present
  as null is not a valid timestamp", §5.6) was read as absent: now undecidable in the library, and `--jwks` refuses it
  (exit 2) as it already refused a malformed one.
- **Now valid, was invalid:** a null `previousReceiptHash` on a receipt checked alone, read as omitted with a warning
  (§5.7.1); a payload that lacks a member §2.2 requires or does not conform to its type (`decision`, `tool_name`,
  `issued_at` without a key window): listed in `payload_problems`, the outcome unchanged (§5.4).
- **Sequences (§5.7.1).** `verify --sequence` (`verify_chain(..., sequence=True)`) reads a log that holds one chain
  after another: a receipt without a link, or with null, begins a new chain (`chains` lists where each begins) instead
  of breaking the one before. Without the flag each file is asserted to follow the one before, as until now, and an
  absent or null link there is `chain_break`.
- **Carried keys (§8.5).** A `public_key`, `verification_key` or `verification_jwk` member of the signed bytes is never
  used: with no key from the relying party the outcome is undecidable `embedded_key_rejected` (was `key_not_supplied`,
  and invalid for a flat receipt without `issuer_id`); with one, a carried key that is not that key is invalid
  `key_mismatch`. Keys are compared as the reference verifier documents it (@veritasacta/verify 0.11.1, ERRORS.md).
- Codes on every refusal of the chain: `malformed_chain_link`, `chain_break`, `policy_digest_*`; the draft's section
  numbers of -04 in every message (-03 §6.6, §6.7, §6.8, §6.9, §9.2, §9.5, §9.7 are -04 §5.2, §5.7, §5.8, §5.9, §5.6,
  §8.5, §8.7).

`examples/acta/chain-link/` and `examples/acta/embedded-key/`: the chain-link suite (27 cases) and the two
embedded-key receipts of agent-governance-testvectors at 5c749de (Apache-2.0), pinned by SHA-256 and run through the
command by `test_cryptovalid_acta.py`. Nine tests more (`Draft04_20261123`), among them an exhaustive one over 1 024
combinations of ten defects against the outcome §5.4 predicts and §5.7 link forms against an independent reading on
5 026 values; eight are red on b784901 (the ninth checks the vendored bytes). Twelve mutants of the new lines: eleven
caught, one equivalent (the bare-link comparison after the exact one). Eleven existing tests changed with the rules above (one renamed).
Not run: `@veritasacta/verify` itself (its vectors' expected outcomes are those of the suite above).

## 0.28.1 (2026-11-23): verdicts change

### The segment writer seals before a segment is longer than a verifier reads (SPEC §5 step 0)

`cryptovalid_ingest.Ingestor` rotated on the number of entries (100 000 by default) and, since 0.28.0, on the tokens
of SPEC v0.14 §22 rule 9, but it did not count bytes. Measured on 2026-11-22 on 0.27.0 and 0.28.0 (from PyPI), one core:
70 000 entries of about 4 KiB went into one segment of 300 289 112 bytes, past the 268 435 456 bytes a verifier reads;
`seal()` could not read it back (`InputTooLarge`), so `close()` failed, the segment stayed unsealed and `verify_archive`
refused it; from the entry that reaches `rotate_entries` on, every `append` raised the same error after writing its
entry into that segment. The writer now counts the bytes of the open segment, its line feeds included (a resumed writer
counts the bytes already in the file), seals before an entry would take it past the bound, outside the lock as its other
rotations, and refuses an entry longer than the bound alone (`ValueError`). The same 70 000 entries now make a segment
of 268 431 350 bytes and a second one, and `verify_archive` is ok. A segment already past the bound, left open by an
earlier version, is not repaired: the writer resumes it and stops at the next seal with the same `InputTooLarge`.
`test_ledger_budget_20261122.py`: five tests more (a writer whose bound is lowered to 64 KiB, resumed; an entry over
the bound refused; the bound to the byte; a resumed segment with empty lines after its entries, and one of empty lines
alone), each red on 0.28.0.

### The segment writer refuses an entry a verifier would not read (SPEC §3, CONFORMANCE.md acceptance profile)

`Ingestor.append` wrote a float, NaN, an integer outside ±(2^53−1), a lone surrogate or a line nested past 512 levels
(its data past 511), and `verify_archive` then refused the archive (`hash_chain_fail`; found in the review of 0.28.1, the
same on 0.28.0). Each line is now read back as a verifier reads it before it is queued, and such an entry is a
`ValueError`, nothing written; so is data nested deeper than the JSON encoder goes, which was never written (a
`RecursionError` until now). Data that is not JSON (bytes, a set, keys that do not sort) is a `TypeError`, as before.
The price, on one core with 200 000 lines of about 1.2 kB, a batch of 256 with fsync: 5 582 entries a second
written (2026-11-23), 15 058 on 0.28.0, which has no check (2026-11-22); measured again on 2026-11-23, CPython 3.11:
5 628 and 15 475. `test_ledger_budget_20261122.py`: two tests more (the bounds to the unit; data changed while a segment
is sealed), red without the check.

### `external_action_ref` refuses by default what the other implementations refuse

draft-pidlisnyi-aps-04 §5.2 says the external form ("action-ref-v1-jcs-sha256") "exists for cross-ecosystem byte
parity" and that its field values are "hashed as supplied"; it states no rule on ASCII or on an empty `scope`. The two
other implementations read on 2026-11-22 refuse, before hashing, a non-ASCII `agent_id`, `action_type` or `scope` and an
empty `scope`: argentum-core at `217009a` (`docs/spec/action-ref.md`, Domain) and the APS SDK at `638ac26`
(`docs/specs/action-ref-v1.md`, Input domain, which notes that §5.2 does not state the ASCII rule). argentum-core also
refuses the year 0000, which the APS SDK hashes (the same document lists the difference). Up to 0.28.0 this module,
written from the text alone, hashed all of these: a non-ASCII value or an empty `scope` got a digest neither of them
reproduces, the year 0000 a digest argentum-core does not. `ascii_domain=True` is now the default and refuses them
(`ApsError`, `ascii_domain: ...`); `ascii_domain=False` keeps the reading of the text alone. A declared reading, not a
rule of the draft; every value inside that domain keeps its digest. Run on 2026-11-22: on the four action-ref fixture
files of argentum-core at `217009a` the module now agrees with argentum on 22 of 22 v1 cases (18 of 22 before: the four
out-of-domain vectors av-003, av-007, nfc-001 and nfc-002 were hashed); on the vectors of the APS SDK at `638ac26`
(`conformance/action-ref-v1/vectors.json`) that give their preimage as an object, on 15 of 15 (11 of 15 before: av-003,
av-007, rj-006 and rj-007 were hashed). Its two vectors with a key written twice give the preimage as JSON text and are
not run: this function takes a parsed object. One difference between the two stays outside this change: the APS SDK
hashes a second 60 at 23:59 on the last day of a month, which argentum-core and this module refuse (§5.2: "a second
value from 00 through 59"). `test_aps.py`: `TestExternalAsciiDomain`.

## 0.28.0 (2026-11-22): verdicts change

### APS action references: the revision in force, draft-pidlisnyi-aps-04 (2026-09-28)

`cryptovalid_aps.action_ref_v2` and `external_action_ref` were written from -03 (§4.1, §4.2); -04 (§5.1, §5.2) adds "a
second value from 00 through 59" to `issued_at` and `timestamp`. Up to 0.27.0 both took 23:59:60 on the last day of a month
(`2016-12-31T23:59:60.000Z` gave an external reference); they now refuse it, and their messages name -04 §5.1 and §5.2.
Compared on 2026-11-22, -03 §4.1–4.2 against -04 §5.1–5.2: the other additions already hold here (an empty
`scope_required` only by the caller's profile context, `empty_scope_permitted`, False by default; any number spelling
I-JSON admits, which these functions never see: they take parsed values, and the module reads no JSON text).
-04 §5.1 refers a scope value to §4.2 ("Scope grants use ASCII colon-separated segments") and forbids rejecting a scope
"against a pattern this document does not state", while it still requires NFC: read here (declared) as no refusal of a
non-ASCII scope. `test_aps.py`: one test more, `test_v2_and_external_refuse_a_leap_second` (red on 0.27.0, with the
positive control that took a leap second now taking 23:59:59).

### What a ledger may hold, counted before it is parsed (SPEC §22 rule 9; verdicts change)

The bound of 256 MiB on the bytes did not bound memory. Measured on 2026-11-22 on a72d51d: a file of 16 MiB of 8 Mi
lines `0` ended Python in `MemoryError` (exit 1, no receipt) and Go in `fatal error: out of memory allocating heap
arena metadata` under a data limit of 2 GB; one line of 64 MiB of `[{},{},...]` ended JS in `JavaScript heap out of
memory` (exit 134) and took Go to 2783 MiB (out of memory under a data limit of 2.5 GB). Now Python, JS, Go and Java count lines and tokens before a verdict: more than
2^20 lines is FAIL `input_too_large: more than 1048576 lines`, else more than 2^23 of the characters `{ [ , :`
(inside strings too) is FAIL `input_too_large: more than 8388608 JSON tokens`, the reason alone, exit 1; a tip of more
than 2^23 tokens is row 2 of the table of rule 2 (`tip_unreadable: not a JSON text of the profile of SPEC §3`), as is
an `.expected.json` of the JS `--conformance`. The eleven forms measured at and past the bounds are FAIL with a receipt in
the four, peak memory at most 1097 MiB (Python), 1359 MiB (JS), 1931 MiB (Go) and 1822 MiB (Java). A ledger that
verified before and holds more than 2^20 lines or 2^23 tokens is now FAIL: eight real ledgers of this author hold
0.042 to 0.112 tokens per byte, so the token bound is reached between 72 and 192 MiB (seal longer ledgers in
segments: the ingest writer now seals a segment before it would hold more than 2^23 tokens, outside the lock of
`append` as its rotation by entries (a slow TSA anchor never holds the other appends), and refuses an `append` after
`close()` (`ValueError`; it returned a reference to an entry never written); with its default of
100 000 entries, entries of 104 tokens made a segment `verify_archive` refused). The same count is applied by the
readers of a ledger beside the verifier, which parsed every line: `signer.verify_file`, the MCP `verify_ledger`
(failure `{"idx": 0, "reason": "input_too_large"}`) and `verify_pack` (`evidence_pack.py verify` ended in
`MemoryError`, no receipt, under a data limit of 3 GB on 128 MiB of 8 Mi lines). In Go the reason was not alone when
the caller asked for a ledger id, a tip or a trusted key (`ledger_id_mismatch`, `tip_missing` after it): it is now.
`verifier.py` stops at the first line past the line bound (200 MiB of blank lines took 64 to 76 s, now 0.5 s).
`test_ledger_budget_20261122.py`, 16 tests (of the 7 written with the rule, 5 fail on a72d51d and the 2 `*_control`
pass there; of the 9 added on review, 5 fail on 33678c9);
`TestRule9TheBudgetOfALedger` in `verifiers/go/input_test.go`; twelve checks in `verifiers/js/test.mjs`. Not bounded:
the readers that take a ledger one line at a time (`chain_tip`, the pack builder, the monitor), the other JSON readers
of the Python package (at most 64 MiB each) and the Rust and Swift verifiers.

### A long line within the bound: the four verifiers agree (SPEC §22 rule 8)

A ledger with one valid line of 65 MiB was PASS in Python and Java, ended without a receipt in JS (Node's `JavaScript
heap out of memory`, exit 134, after 21 to 31 s: `pyEscape` built the canonical form one character at a time) and was
FAIL `read: bufio.Scanner: token too long` in Go, whose line reader stopped at 64 MiB. JS now escapes in one regex
pass (the same bytes as before: 0 differences on 200 000 random strings and on every BMP character, measured against
the old function; a mutant that leaves 0x7f unescaped gives 22 159); Go reads a line up to the input bound, 256 MiB
(`MaxLineBytes`, 64 MiB, bounds only what the Go writer takes). Measured on 2026-11-22: one valid line of 65 MiB and
one of 250 MiB PASS in the four (peak memory at 250 MiB: Python 1055 MiB, JS 2064 MiB, Go 1402 MiB, Java 1595 MiB),
one byte changed FAIL in the four; a sparse file of 256 MiB exactly fails at §5 step 1 in the four (Go said `token
too long`). `test_ledger_input_20261122.py`: `test_a_valid_line_of_65_mib_is_verified_in_the_four` (red on 287482e:
JS out of memory), and `test_exactly_the_bound_is_within_it` gives the file to the four;
`test_every_character_below_0x80_in_a_string_is_verified_in_the_four` holds the escapes of the new `pyEscape` (no test
or vector held DEL or `\b`: two mutants of it lived through every suite that runs the JS verifier). 16 tests in the file. `spec/CONFORMANCE.md` "Size"
said the Go and JS verifiers bound no file: stale since rule 8, rewritten.

### Changed by the decisions of 2026-11-20 (SPEC §22, written before the code; verdicts change)

`test_decisions_20261120.py`, 54 tests (one compares the canonicalization with lxml and is skipped where lxml is absent):
on the branch before these rules (9b81e9c) 43 fail (44 where lxml is installed) and the 10 named `*_control` pass. 62 mutants
of the changed lines (Python, JS, Go, Java): all killed.

After the review of the branch (2026-11-21), `test_review_20261121.py`, 46 tests: 34 pass on 9b25d32 (they hold what the
code already did and no test held), twelve fail there (the instant without a time zone, two of the empty pin, five of the
sequence number, the tip of another kind in the Go verifier, the table of the reasons of a tip, its row 1, and the words
of `bad_not_before`: without the Go toolchain the tip of another kind passes there, 35 and eleven). 58 further mutants of the lines of rule 6 (`cryptovalid_lotl.py`): 33
were killed by the tests above and 25 lived. 24 of the 25 dropped a check that the code made (each refusal measured)
and no test held: the closed shape of the signature (the children of `ds:Signature`, `SignedInfo`, a `Reference` and
`KeyInfo`, an algorithm with parameters, the transforms, a SHA-1 digest), a certificate not yet valid, `NextUpdate` at
its own instant and malformed, the length of an ECDSA value, the salt of RSA-PSS, base64, two pivots in a row, a pivot
without certificates, and canonical forms the ones copied from libxml2 did not have (a TAB in an attribute, a processing
instruction after the document element); each has its test and is killed now. One gives the same answers: a second
`Transforms` in a `Reference` is refused first by the check of the children of a `Reference` (1,562 generated references
and 3,000 random ones, no different answer; a mutant of that other check, as control, differs on 1,558 and on 3,000).
`verify_pack` refuses an empty pin (`""`, or a value that is not a string, as `signer_pubkey_hex`, `manifest_signer_hex`
or `pq_pubkey_b64`: `ValueError`, as the archive verifier since SPEC §17 rule 4); it meant "not pinned", and an unsigned
pack was `valid: true` under `signer_pubkey_hex=""`.
Of 37 further mutants of the other lines of §22 (`evidence_pack.py`, `cryptovalid_ingest.py`, `cryptovalid_mcp.py`,
`verifier.py`, `cryptovalid_tip.py`) 32 were killed and 5 lived, each a case without a test, now held: the cut at 120 code
points of the names of the unknown members of a tree head and of a HEAD, the option `--require-signature-domain` of
`cryptovalid_ingest.py verify`, the `valid` of the MCP tool when every signature holds and the chain is broken, its
answer without `cryptography` (the tests of rule 5 are skipped without the package and do not reach that branch with
it), and a ledger that is not UTF-8 (one failure `not_utf8`, not "no entry").
`verify_list_signature(at=...)` with an instant without a time zone was a `TypeError`; it is a `ValueError` that says so.
The sequence number of a trusted list (`TSLSequenceNumber`) is now read: required and well formed (`tl_sequence_malformed`;
all 31 documents of 2026-11-20 have one), reported (`sequence_number`, `sequences_out`, the cache's `sequences`), and a
minimum the caller gives (`min_sequence`, `min_sequences`) refuses an earlier list (`tl_sequence_rolled_back`): the
review had found that an earlier list still within its `NextUpdate` verified like the current one, with nothing to
tell them apart.
A second review (2026-11-21, of 9874e32) closed how the number is read: a second `SchemeInformation`, a child element
inside `TSLSequenceNumber`, a no-break space (or another Unicode space) around the digits and a number of 19 digits were
accepted, and one of 4,301 digits was refused in the words of the Python interpreter, not as `tl_sequence_malformed`;
now one `SchemeInformation`, one `TSLSequenceNumber` without child elements, 1 to 18 ASCII digits between XML white
space. `load_qualified_status`: a location in `min_sequences` that named no list (a trailing space, another case) was
ignored and its minimum applied to nothing, and a `sequences_out` that was not a dict was an `AttributeError` after
every list had been fetched; both are a `ValueError` now, and the `sequences` of a cache are read back only when they
are {location: integer >= 1}. The clauses of ETSI TS 119 612 V2.4.1 (2025-08) cited for the sequence number and for
`NextUpdate` were 5.3.3 and 5.3.14; they are 5.3.2 and 5.3.15.
The Go verifier answered `tip_unreadable: json: cannot unmarshal ...` to a tip whose `kind` was an integer, a boolean, an
array or an object, where Python, JS and Java answer `tip_invalid: not a cryptovalid_tip/1 document` (exit 1 in the
four); it answers as they do now. The reasons of a tip with a right `kind` and a member of a wrong type, missing or
malformed, and of a tip file that cannot be read or is not a JSON object, differed between the four verifiers (of 72
such tips one text in the four for 3, of 10 files for 1); SPEC §22 rule 2 now has a table, form -> reason, and the four
give its text for each form: Python, JS, Go and Java check the rows in the same order (Go before any typed decode, JS
with an integer beyond 2^53-1 refused as in an entry, Go trimming only JSON white space around the file), and the Python
reference takes the shorter words of the other three for `tip signature invalid`, `tip_rolled_back`, `unsealed_tail`
and `bad_not_before`. Measured on 251 generated tip files (`d4b_testi_tip.py`): one text in the four for 40 before, for
all 245 that fail after (the other 6 pass in the four). One verdict changes: the JS verifier read a `log_pubkey_hex` of
`false` or `0` as absent and passed the tip (exit 0) where the other three refused it; now exit 1, `tip fields must be
strings`, as they do. Row 1 of the table (a FIFO, a device, a directory, more than 256 MiB: `the tip file cannot be
read`) held only in Python: the JS, Go and Java verifiers waited without end on a FIFO given as the tip and read a device
or a larger file as bytes (row 2; Java `internal: OutOfMemoryError`); a third review (2026-11-22) found it, and the three
now open the path once and check it as Python does (Java reads the attributes before the open; since rule 8 below a path
swapped for a FIFO between the two is row 1 after 10 s, not a wait).
Sentences corrected by the review: the README said that a token of another TSA under `--tsa-cert` is "not a failure"
(since rule 7 the pack is not valid, exit 1); rule 2 listed the members of a tree head and of a HEAD without
`sig_domain`; rule 4 gave the reasons of an admitted pack that is not valid without the case of rule 7; "a document
written now is refused by 0.27.0" holds for a signed archive and for a pack, not for an unsigned archive; a comment
said the deepest of the lists of 2026-11-20 is 12 elements deep (17, of 31 documents).

- **A trusted log key makes the tip required** (§22 rule 1), in the Python, JS, Go and Java verifiers: with
  `--trusted-pubkey` and no tip the verdict was PASS, exit 0, `tip: null`; it is now FAIL with `tip_missing`, exit 1.
- **A tip, a tree head and a HEAD are closed objects** (§22 rule 2): a member outside the list of its document was
  ignored (PASS; `verify_archive` ok); it is now `tip_invalid: unknown_member:<keys>` (the same text in Python, JS, Go
  and Java), `sth_unknown_member:<keys>` or `head_unknown_member:<keys>`. Every member written since 2026-08-16 is in
  the lists, so archives and tips written by earlier versions verify as before. The Rust and Swift verifiers do not
  apply the rule: the differential oracle declares the case `tip-pq-case` (Rust PASS, measured in CI on 2026-11-22).
- **Tree heads, HEADs and pack manifests are signed over a domain-tagged message** (§22 rule 3, a format change). They
  were signed over a bare SHA-256 hex, the same kind of message as an entry signature. A tree head or HEAD signed now
  carries `sig_domain` (`cryptovalid-sth/2`, `cryptovalid-head/2`) and is signed over `<sig_domain>:<hex>`; packs are
  written in format `cryptovalid-evidence-pack/1.2`, whose manifest signature is over
  `cryptovalid-pack-manifest/2:<digest>`. Archives and 1.1 packs written before verify as before (the 12 packs of this
  repository and 8 archives and packs written by the previous code: same verdicts; signed archives gain the warning
  `untagged_signatures`); `require_signature_domain=True` / `--require-signature-domain` refuses them. A signed archive
  or a pack written now is refused by 0.27.0 (`sth_signature_invalid`, `head_signature_invalid`, `format_unsupported`);
  an unsigned archive written now is the document 0.27.0 wrote, and 0.27.0 verifies it.
- **A pin given to `verify_pack` decides `valid`** (§22 rule 4, library only): with `signer_pubkey_hex` a ledger with no
  signature, and with `manifest_signer_hex` a manifest not signed or signed by another key, left `valid: true` (SPEC §10
  said "by design"); the pack is now not valid, the reason in `producer_signature`. Of 36 combinations of manifest
  signer x ledger signer x pins, 14 change from `true` to `false`; without pins nothing changes.
- **A trusted list counts only when its XAdES signature verifies, and only over https** (§22 rule 6;
  `cryptovalid_lotl` is experimental). A LOTL and a list without any signature made a token qualified, and one national
  list is served over http. The LOTL must now verify under a certificate of the Official Journal publication in force
  (C/2026/1944, through the pivot LOTLs it names), each list under a certificate of the LOTL's pointer to it; a list over
  http is not fetched; the signature is read closed to the shape every list had on 2026-11-20, its certificate must be
  valid now and a `NextUpdate` present must not have passed. Exclusive C14N is written
  in the module (the standard library's C14N 2.0 gave other bytes than the signer on 1 of 31 real documents); no
  dependency is added. Measured on 2026-11-20: the LOTL and the 30 lists that answered verify; on each list a changed
  byte, a removed signature, another list's certificates and a service put inside the signature's Object are refused or
  not read. The cache rule is `/3`: caches built before are rebuilt.
- **Pinned TSA certificates decide `valid` and `ok`** (§22 rule 7, replacing the v0.8 sentence "a pin for another TSA does
  not make the pack false"): with `tsa_certs` / `--tsa-cert`, a pack whose token is another TSA's, absent, or not
  checked, was `valid: true`, and an archive with a sealed segment without a token, or with one not checked, was ok;
  now not valid (`time_anchor` keeps its state) and `tsa_token_missing_but_tsa_pinned` /
  `tsa_token_not_verified_under_pin`. Of 33 combinations of token x pin x pack/archive, 12 change from valid/ok to not.
- **An empty pin given to `verify_pack` is refused** (§22 rule 4, after the review): `signer_pubkey_hex`,
  `manifest_signer_hex` or `pq_pubkey_b64` given as `""` or as a value that is not a string meant "not pinned" (an unsigned
  pack was `valid: true` under `signer_pubkey_hex=""`, on 0.27.0 too); it is now a `ValueError` before the pack is read,
  as the archive verifier since SPEC §17 rule 4 and `tsa_certs=[]` since v0.8. `None` is still "no pin".
- **The MCP tool `verify_ledger` verifies the entry signatures** (§22 rule 5) when it is given `expected_pubkey_hex`:
  the chain and the signatures are checked on one read of the file, and `valid` is true only when both hold. Without
  the key it answers as before and says `signatures: {"checked": false, ...}`.
- **The JS, Go and Java verifiers read the ledger as `verifier.py` does** (§22 rule 8, after the third review): given a
  FIFO with no writer as the ledger the three waited without end (Python: FAIL after 10 s); JS read a link to
  `/dev/zero` without end and Java until `internal: OutOfMemoryError`; the three read `/dev/null` as an empty ledger; JS
  read a file larger than 256 MiB and Go read it up to its line bound. Now the path is opened once without waiting and
  the same text comes out of the four: a directory or a device is `unreadable: not a regular file`, more than 256 MiB (a
  file or a FIFO) `input_too_large: file exceeds 268435456 bytes`, a FIFO that gives nothing for 10 s `unreadable: FIFO
  idle for 10 s`, FAIL, exit 1 (JS: a directory was `FILE_ERROR`, exit 2). A FIFO with a writer, `<(cat ledger.jsonl)`
  included, is read as before. The Go writer (`cvappend`) appends only to a regular file (a link to `/dev/zero` was
  written to) and reads `-tipkey` as `signer.py` reads a key, a regular file or a FIFO of at most 1 MiB, 10 s idle at
  most (a FIFO waited without end, a link to `/dev/zero` was read until the process was killed), and at most 64 MiB of
  data from stdin (`data: input_too_large: more than 67108864 bytes`, exit 2: a line holds no more; stdin without end,
  `< /dev/zero`, was read until no memory was left: Go's `fatal error: out of memory` under `ulimit -d 524288`). The JS
  verifier's `--conformance <dir>` reads each file there as its tip reader does (a FIFO waited without end; now a vector
  not conformant). `test_ledger_input_20261122.py` (14 tests: 7 fail on cfcd05c; the 4 named `*_control`, a FIFO whose
  writer leaves without a byte, 256 MiB exactly in Java and a tip that is a FIFO, row 1 of rule 2, pass on both),
  `verifiers/go/input_test.go` and `verifiers/js/test.mjs`.

### Fixed

Eight rules of SPEC v0.13 §21, written before the code. The findings come from the security review of 0.26.0 that
§20 did not cover; on 2026-11-20 each was re-run on 0.26.0 and on the released 0.27.0, and each one below still
reproduced on 0.27.0. `test_remeasure_20261120.py`, 35 tests: 29 fail on 0.27.0 (ec56b3c), the 6 named `*_control`
hold what did not change and pass there too. 72 mutants of the lines changed since 0.27.0: 68 killed; the 4
that live give the same answers (an `EntityDecl` handler: an entity is declared only inside a document type
declaration, which the other handler refuses first: in 4,000 generated documents, 869 with an entity declaration, never
before it; a body loop without its bound: the read before it asks for 0 bytes, and `HTTPResponse.read(0)` is `b""`;
the test that a `self_hash` is a string before it is compared with two hashes: a value of another type equals
neither; a second test that a ledger is inside the pack, for a name whose bytes were read only because it was).

- **An RFC 9162 inclusion proof longer than the path of its leaf index and tree size verified** (rule 1).
  `cryptovalid_merkle.verify_inclusion` lacked step 4a of RFC 9162 §2.1.3.2 ("If sn is 0, then stop the iteration and
  fail the proof verification"): the proof of leaf 5 of a tree of 8 verified as leaf 1 of a tree of 4 against the root
  of the tree of 8; over trees of 1 to 33 leaves, 1,416 of 81,927 such pairs verified, none now. A leaf index or a
  tree size that is not a non-negative integer fails too (the index -1 verified as the last leaf of a tree of 1, 2, 4, 8
  or 16 leaves). The caller still binds the size to the root (a signed tree
  head): a proof of the right length can verify against the root of another size, as RFC 9162 writes the algorithm.
- **A key written twice was read as its last value by the signature verifier and the JWS verifier** (rule 2).
  `signer.verify_file` and `signer.py verify` verified a ledger line with a key written twice and the signed value
  last (4 of 8 generated lines), while `verifier.py` refused the same file: now `duplicate_key` at that index (SPEC
  §3). `cryptovalid_jws.verify` refuses a header with a name twice (`header_duplicate_key`, RFC 7515 §10.12 allows a
  parser to reject; 22 of 40 generated headers were accepted) and a payload with a key twice
  (`payload_duplicate_key`, `signature_valid: true`; 80 of 80 were accepted). The same for the tree heads and the HEAD of
  an ingest archive (a signed one with a key written twice, the signed value last, left `verify_archive` ok with the
  signer pinned: now `sth_unreadable: duplicate_key`, `head_unreadable: duplicate_key`) and for the receipt and entry
  files of `cryptovalid_receipt.py verify` (were verified, exit 0: now `... unreadable: duplicate_key`, exit 1).
- **Without `defusedxml`, a document type declaration past the first 4096 bytes, or in UTF-16, was not refused and its
  entities were expanded** (rule 3). `fundcert_canonical` searched the first 4096 bytes as UTF-8 text: 218 of 300
  generated documents with a declaration after a long comment, a processing instruction or blank lines, in four
  encodings or as a str, were parsed (expat 2.5.0). The document is now read by expat with handlers that refuse the declaration,
  as `cryptovalid_lotl` reads a trusted list; a document without one parses as before.
- **Vaara receipts: ES256 verified with a key of another curve, and an evidence record the receipt does not bind left
  it ok** (rule 4; `cryptovalid_vaara_receipt` is experimental). A PEM key on secp192r1, secp224r1, secp256k1 or
  brainpoolP256r1 verified an ES256 receipt its private key signed; ES256 is P-256 (RFC 7518 §3.1), as the JWK branch
  already required: another curve is refused before the signature. An `evidence` given for a decision receipt without
  `evidenceRef` is `evidence_ok: false` (was null, receipt ok).
- **MCP: an argument of another JSON type than its schema's was used as it came** (rule 5). `"lotl_check": "false"`
  went through `bool()` and switched the trusted-list network check on. Each argument is now checked against the type
  its tool's input schema declares, `-32602` naming it and the tool not run (221 generated calls over the 13
  properties of the 6 tools). The description of `verify_ledger` said it checked "Ed25519 signatures if present"; it
  never did (the receipt counts them in `signatures_not_checked`): the description now says so.
- **A network response was read whole however long it was** (rule 6). Ten reads in seven modules (`cryptovalid_lotl`,
  `cryptovalid_tsa`, `evidence_pack` when it stamps, `cryptovalid_qeas`, `cryptovalid_solana`,
  `cryptovalid_pruning_probe`, `cryptovalid_kms`) now go through `cryptovalid_net.read_body`: at most
  `MAX_RESPONSE_BYTES` (64 MiB; 1 MiB for an error body), else `ValueError("response_too_large: ...")`. Measured on
  2026-11-20: the EU LOTL and the 31 trusted lists it points to are at most 5,367,120 bytes.
- **The evidence pack read a ledger's path up to five times, so the file checked could change between the reads** (rule 7).
  With another file at the path only while the chain was read, a pack whose manifest commits to a ledger with a broken
  chain was `valid: true`. `verify_pack` now reads each ledger once, bounded, takes its digest from those bytes and
  runs every check on them in memory, however the manifest spells the file's name (`./l.jsonl`, a link inside the
  pack). A signed ledger with bytes that are not UTF-8 20,000 bytes past its entries made `verify_pack` raise
  `UnicodeDecodeError`:
  now a failure of its signature layer, the pack not valid.
- **`signer.py sign` signed a `self_hash` as written, so it could be made to sign an archive's tree heads** (rule 8).
  The tree heads and the HEAD of an ingest archive are signed over the same kind of message as an entry (the hex of a
  SHA-256): a two-line "ledger" whose `self_hash` were the hashes of a tree head and a HEAD, signed with
  `signer.py sign`, gave signatures under which `verify_archive`, with that key pinned, accepted an archive the key's
  holder never sealed (measured on 0.26.0 and 0.27.0); the digest of a pack manifest, signed the same way, gave
  `producer_signature: verified` under the pinned manifest signer (0.27.0). The signer now refuses, and writes nothing for, a ledger with
  a line that is not an entry: a member outside the entry schema, a key written twice, a `self_hash` that is not the
  hash of the line's content. `signer.py verify` fails a line with a member outside the entry schema
  (`unknown_field:<keys>`): a tree head, a HEAD or a manifest the key's holder signed, written as a ledger line,
  verified there as a signed entry.

## 0.27.0 (2026-11-20): reasons change

### Added

- **A FAIL ledger receipt tells the chain's breaks apart from entries that are not in this format** (SPEC v0.12 §5
  "Failure classes", written before the code). Measured on 2026-11-18 on a third-party ledger of 179 entries (another
  schema: its own fields, no `idx`, `self_hash`/`prev_hash` by the rule of §3; not shipped here, it has no licence):
  0.26.0 named its 4 true link breaks among one `unknown_field` and one `idx_mismatch` per entry, and `cryptovalid-verify
  ledger` listed 4 + 10 + 10 reasons. The receipt of `verifier.py` for a FAIL of a file it read (zero entries included,
  counted in `other`; not the FAILs of §5 step 0: unreadable, too large, a FIFO idle) now carries `failure_classes`, counts over
  every entry with a closed set of members: `chain` (`link_mismatch`, `hash_mismatch`), `format` (`unknown_field`,
  `idx_mismatch`, `missing_self_hash`, `missing_prev_hash`) and `other`; on that ledger `chain` 4 link / 0 hash, `format`
  179 / 179. `cryptovalid-verify ledger` (and `auto` on a ledger) writes the classes first in the layer's `detail`,
  copies `failure_classes` into the layer and lists the links, then the hashes, before the schema. The verdict does not
  change, and the receipt of a PASS ledger is the receipt of 0.26.0; the other five verifiers do not emit the member.
  `test_real_tokens_and_failure_classes_20261118.py`: the shape of that ledger made here, and 300 ledgers with random
  mutations of six kinds against an oracle that counts each class from §2 and §3.

### Fixed

- **A redirect from a remote host reached this host's loopback through another spelling of the address, and carried
  the request's credentials to another host** (SPEC v0.12 §20 rules 1 and 2, written before the tests and the
  CHANGELOG; from a security review of 0.26.0, each finding re-run on 2026-11-19 on the unmodified code).
  `cryptovalid_net` compared the host of a redirect as text with `localhost`, 127.0.0.0/8 and `::1`: a redirect from a
  remote host to `http://127.1/`, `http://0.0.0.0/`, `http://2130706433/`, `http://0x7f000001/`, `http://0177.0.0.1/`,
  `http://[::ffff:127.0.0.1]/` or `http://[::]/` was followed (Linux, Python 3.11: a service on 127.0.0.1 answered
  the request redirected to `127.1`). The host is now judged as the address the system connects to: every form
  `inet_aton` reads, an IPv4-mapped IPv6 address by the address inside it, a name by every address `getaddrinfo`
  gives; a redirect from a host that is not loopback to a loopback, unspecified or link-local address is a
  `ValueError("url_not_allowed: ...")`, judged at every hop. A host with a percent sign is refused under every policy,
  first URL and redirect alike: urllib decodes `%XX` in the host before it connects, so `http://%31%32%37.0.0.1/`
  reaches 127.0.0.1 (measured 2026-11-20 on the first draft of this rule, which judged the host still encoded); the
  `%25` zone of an IPv6 literal is refused with it (RFC 9844, August 2025, obsoleted RFC 6874 and its zone syntax).
  `is_loopback("127.1")` is now true, so plain http to it
  is allowed where loopback http is, and it is reached without the environment's proxy. And urllib copies every header
  of a request to the redirected one: `X-Vault-Token`, `Authorization` (AWS SigV4, NetHSM Basic, the QEAA bearer token)
  and `X-Amz-Security-Token` went to the host a 302 named. A redirect to another origin (scheme, host, port) is now
  refused when the request carries a header outside a closed list of six that name no credential
  (`cryptovalid_net.FORWARDED_ACROSS_ORIGINS`); refused, not stripped. A redirect to the same origin, and a redirect
  of a request without such a header (the TSA client, the trusted lists, the witness, the Solana clients), is followed
  as before. `Proxy-Authorization` is never copied to a redirected request (RFC 9110 §11.7.2: it "applies only to the
  next inbound proxy"; urllib puts it on a request that goes through a proxy with credentials, and the redirect
  copied it on: measured, a host reached directly after a 302 received it) and does not count for the refusal, or
  every redirect to another origin behind such a proxy would be refused. The address is read with the system's own
  readers (`inet_aton`, `inet_pton`), not with `ipaddress`, which before Python 3.9.5 read `0177.0.0.1` as
  177.0.0.1. Not closed, and said in §20: a name whose answer changes between the check and the connection; a
  redirect to a private address. `test_sentry_20261119.py`, 10 tests on these two rules: 5,416 spellings of loopback,
  link-local, unspecified and other addresses, each compared with what this system's resolver gives for it; names
  answered by a resolver replaced in the test; 4,000 pairs of origins with generated header sets; redirects served on
  127.0.0.1. All 10 fail on 22d342c; 18 mutants of the changed lines, 18 killed. `test_net_mcp_review_20261120.py`, 4
  tests on the percent sign (800 encoded hosts, each under 2 schemes and 3 policies; IPv6 zones; redirects served on
  127.0.0.1); 3 of them fail on the first draft of the rule, the fourth checks that urllib decodes the host.

- **A signature over JCS verified after an integer beyond 2^53 was changed** (SPEC v0.12 §20 rule 3, written before
  the code; same review, re-run on 2026-11-19). `cryptovalid_acta.jcs`, the RFC 8785 serializer of the ACTA, Vaara,
  APS and Cedulon readers, rounded an integer beyond ±2^53 to the nearest double before writing it: `jcs(2**53)` and
  `jcs(2**53 + 1)` were the same bytes. A Vaara receipt signed (ES256) over `"amount_wei": 9007199254740992` verified
  with `9007199254740993` in its place, and the caller read from it a value nobody signed; `payload_ref_v2` of
  `cryptovalid_aps` and the digests of a Vaara predecessor and evidence collided the same way. `jcs` now refuses an
  integer that is not exactly an IEEE 754 double, with a `ValueError` that names it (RFC 8785 §3.1, "JSON number data
  MUST be expressible as IEEE 754 double-precision values"; RFC 7493 §2.2; read at rfc-editor.org on 2026-11-19), when
  signing and when verifying; the readers report it as their own refusal (`verify_receipt`: `ok` false, the reason in
  `why`). An integer beyond 2^53 that is a double (2^53, 2^60, 10^20) is written as before, as ECMAScript writes it.
  The ledger profile of §3 already refuses every integer outside ±(2^53−1), in the six verifiers, and does not
  change; no verifier in another language implements JCS, and the vectors hold no such integer.
  `test_sentry_20261119.py`, 4 tests: 3,854 integers of 50 to 1,100 bits and around 2^53, 2^63 and 2^64 of both signs
  (1,630 doubles, 2,224 not, told apart here by integer arithmetic), refused exactly when not a double and never two
  with the same bytes; the same integers given to Node, whose `JSON.stringify(JSON.parse(text))` equals the bytes of
  every accepted one and loses the value of every refused one; 420 receipts signed here and changed. All 4 fail on
  22d342c (199 of the 420 changed receipts verified there); 4 mutants of the changed lines, 4 killed.

- **A Cedulon ledger that was INVALID became VALID with one unsigned line, or with two allows under one ref** (SPEC
  v0.12 §20 rules 4 to 6, written before the code; same review, re-run on 2026-11-19; `cryptovalid_cedulon` is
  experimental). The texts were read again that day where they live: draft-dogru-cedulon-decision-profile-04 (5
  October 2026, active), draft-dogru-cedulon-09 (6 September 2026, which profile-04 cites; replaced on the datatracker
  by draft-dogru-cedulon-core, at -04 of 7 October 2026), W3C Web Authentication Level 3 (Recommendation, 25 August
  2026), and the README and verifier of verax-ai/verax at c626c68 (Apache-2.0, read only). Three points were compared;
  the reader as a whole is still the reader of profile-03 and cedulon-08.
  (1) The `control` and `approval-signature` stages read a record's context from any row of the unsigned
  `inputs.jsonl` with its ref, also for a record whose `inputsHash` is null: a ledger `INVALID` at `control` (an allow
  inside a halt window) was `VALID` after a line `{"ref": ..., "inputs": {"control": {"action": "resume"}}}` was
  added. They now read only a context the record's signed `inputsHash` binds, and a row that no signed `inputsHash`
  binds is `INVALID` at `inputs-binding`.
  (2) Allows were kept in a map by ref, the last replacing the others: two allows under ref X naming effects H1 and
  H2, with rows carrying H2 twice, were `VALID`. A ref on more than one allow, or on more than one effect row, is now
  `INVALID` at `effect-binding` with `duplicate-ref` (cedulon-09 §11.4 step 7 and MUST-T10-6, finding "audit fails";
  profile §6.1). One outcome named differently: two allows under one ref with one row was `decision-without-effect`
  and is `duplicate-ref` (`test_cedulon.py` changed there). And a row under a ref that a refusal AND an allow carry is
  `effect-against-refusal` as profile §6.1 writes it (was `VALID`: the allow was looked up first; found by the
  generated test).
  (3) The approval's WebAuthn assertion was checked against the RP ID the assertion itself carries, and the origin
  not at all, without the result saying so: an assertion made with the operator's passkey for `evil.example` passed.
  `verify_ledger` takes `expected_rp_ids` and `expected_origins` (WebAuthn §7.2: "expected by the Relying Party");
  without them the check is the one of 0.26.0 and `not_verified` now names `approval-rp-id` and `approval-origin`
  (`test_cedulon.py` changed there). Without `expected_rp_ids`, an assertion with no `rpId` member fails
  `approval-signature` (was `malformed`); with them, the RP ID is the expected one whose SHA-256 is the `rpIdHash`,
  and the member is not needed.
  `test_sentry_20261119.py`, 8 tests: 250 generated ledgers with halts and resumes against an oracle that reads only
  what the Decider signed, each with 4 unsigned rows added (1,000); 400 ledgers with repeated refs and bent rows; 300
  assertions over 7 RP IDs and 6 origins. All 8 fail on 22d342c; 13 mutants of the changed lines, 12 killed. The one
  that survives (the approver read from any row, not only a bound one) gives the same verdict and stage: a row is
  accepted only when some record's signed `inputsHash` binds it, and that record is checked with the same approver.
  Seen and not changed: Verax's verifier at c626c68 reads the halt and resume from the signed claims (`subject`),
  not from the inputs row.

- **`check_digest` raised `RecursionError` on a field of nested "@"** (SPEC v0.12 §20 rule 7, written before the
  code; same review, re-run on 2026-11-19). `cryptovalid_httpdigest.check_digest` says it never raises on `field`;
  its Date branch called the bare-item parser again after the "@", one call per "@", and
  `"sha-256=" + "@" * 5000 + "1"` raised `RecursionError` (Python 3.11). RFC 9651 §4.2.9 reads an Integer after the
  "@" (§4.2.4 fails on a character that is neither "-" nor a digit; read at rfc-editor.org on 2026-11-19): the next
  character is now looked at before parsing, and the answer is `grammar`. No outcome changes for a field the old code
  answered. `test_sentry_20261119.py`, 3 tests: 2 to 100,000 "@" in five positions (fails on 22d342c, 16 errors); the
  Date grammar on 3,026 tails against a regular expression written from the RFC, and 20,000 random fields in both
  syntaxes that must not raise (these two hold the grammar where it was and pass on 22d342c too). 3 mutants: 2
  killed; the third (no test for the end of the field after "@") gives the same outcome, the item parser refuses it.

- **An ingest archive with its key pinned was `ok` after the HEAD and the last segments were removed, and three
  more defects of the archive** (SPEC v0.12 §20 rules 8 to 11, written before the code; same review, each re-run on
  2026-11-19).
  (1) `verify_archive` with `expected_pubkey_hex`: a HEAD without a signature was a failure, a HEAD that is not there
  only the warning `no_head_manifest`. With 3 signed segments, removing `ledger.head.json` and the last segment with
  its tree head left `ok: true`, `segments_verified` 2. A missing HEAD with a pinned key and a sealed segment is now
  the failure `head_missing_but_pubkey_expected`. Without a pin it stays a warning. An archive that never had a HEAD
  is, with a pin, not ok from this version.
  (2) `Ingestor`, reopening a segment, took the first complete line that was not JSON for a torn tail and cut the
  file there: 10 acknowledged entries with line 3 damaged became 3, without an error, and the 3 verified. Only a last
  line without its line feed is a torn tail; a complete line that is not a JSON object is a `ValueError` ("refusing
  to resume") and the file is left as it is (a complete line that was JSON and not an object raised
  `AttributeError`).
  (3) A segment without `.sth.json` was counted and never read: `ledger-000099.jsonl` holding one line that is not an
  entry, added to a signed archive verified with its key, left `ok: true` and no warning. Such a segment is now
  read: `unsealed_segment_not_last` when it is not the last segment (the writer leaves at most one, the active one),
  `unsealed_segment_chain_fail` when it holds something that does not verify as a ledger, and when it verifies the
  warning `unsealed_entries: <n> entries in <k> segment(s) without a tree head (...)`. An empty active segment adds
  nothing; one with a torn tail is not ok until the writer reopens it.
  (4) `lotl_member_states` named the cache file of the trusted-list fingerprints as given: `["X/../../../evil"]`
  named `~/EVIL.json` and, with a directory `lotl_X` present in `~/.cache/cryptovalid`, a file placed there was read
  as the set of qualified TSA certificates (without that directory the path does not resolve); the argument reaches
  the function from the MCP tool `verify_archive`. Member states are now a list, tuple or set of strings of two
  ASCII letters, or a `ValueError` before anything is read, in `verify_archive` and in `Ingestor`; the string `"ES"`
  (read until now as the states `E` and `S`) is refused too.
  `test_sentry_20261119.py`, 9 tests: 22 archives with the HEAD and 0 to 4 tail segments removed, each under three
  forms of pin (66 verifications); 180 damaged complete lines (10 kinds at every position of segments of 1, 2, 5 and
  10 entries) that must raise and leave the file byte for byte, and over 100 torn tails that must be cut; 120
  generated archives with 12
  kinds of change to the segments without a tree head, against the rule written out in the test; 840 values of
  member states. 6 of the 9 fail on 22d342c; the other 3 hold what did not change (a torn tail is cut, a line of
  another chain is refused, an archive with nothing sealed) and pass there too. 15 mutants of the changed lines, 15
  killed.

- **One malformed line stopped the MCP server** (SPEC v0.12 §20 rule 12; the code was drafted before the SPEC
  paragraph, both before the tests; same review, measured on 2026-11-19). `cryptovalid_mcp.py` took for granted that
  a message is an object and its `params` an object: a line holding `[]`, `5` or `null`, a request whose `params` is
  an array or a string, a `tools/call` whose `name` is an array, or 100,000 "[" raised `AttributeError`, `TypeError`
  or `RecursionError` out of the read loop, and the process ended (exit 1). Each is now a JSON-RPC 2.0 error
  (jsonrpc.org/specification, read on 2026-11-19): -32700 for a line that cannot be parsed (not UTF-8, `NaN` or
  `Infinity`, which RFC 8259 §6 does not permit, or nested too deep), -32600 for a message that
  is not an object or whose `id` or `method` has the wrong type (id null where it could not be read), -32602 for
  `params`, a tool `name` or `arguments` of the wrong type, -32603 for anything else inside one message; the server
  reads the next line. One answer changes besides: a message without an `id` is a notification, not answered and
  not run (§4.1: until now a `tools/call` without an `id` ran the tool and was answered with id null); a message with
  `"id": null` is a Request and is answered (§5), also for an unknown method (-32601), which had no reply. And
  `"arguments": []` (or `""`, `0`, `false`) is refused as not an object; it was read as no arguments and refused for
  the required one that was missing, the same code -32602 (every tool has a required argument). `test_sentry_20261119.py`, 2 tests over
  the real stdio transport: 14 lines named by the review and 1,500 generated messages, each followed by a ping that
  the same process must answer, the expected code written out in the test. Both fail on 22d342c (the server ends at
  the first such line). A reply that carries a lone surrogate taken from the message (`"\ud800"` as an id, a method or
  a path) is written with JSON escapes: written as UTF-8 it ended the server (exit 74), and a line that is not UTF-8
  ended it too (exit 1), measured 2026-11-20 on the first draft of this rule; an id `NaN` was echoed as `NaN`.
  `test_net_mcp_review_20261120.py`, 2 tests over stdio (9 named lines and 300 generated ones, every line written
  back read as strict JSON); both fail on the first draft. 10 mutants of the changed lines: 9 killed; the one that
  survives (falsy `arguments` read as none) gives the same code, as said above.

- **A real DigiCert token was refused because its nonce is negative** (SPEC v0.12 §11 step 3, written before the code).
  `cryptovalid_tsa.parse_token` read the TSTInfo's `nonce` with the reader of non-negative INTEGERs and answered
  `invalid / malformed` ("nonce: negative INTEGER") for a TimeStampResp of DigiCert SHA256 RSA4096 Timestamp Responder
  2025 1 committed in thebristolsound/birdbrain (nonce -0x5BDDFD8205AA38EC, genTime 2026-05-30), which OpenSSL 3.0
  `ts -verify` accepts under the DigiCert Trusted Root G4. RFC 3161 §2.4.2 writes `nonce INTEGER OPTIONAL` and sets no
  sign; SPEC §11 asked "not negative" only of `serialNumber`, so the code was stricter than its own specification. The
  nonce is now an INTEGER of either sign in minimal form, and so is `serialNumber`: RFC 3161 §2.4.2 writes
  `serialNumber INTEGER` with no sign either, and §11 asked it "not negative" (measured on 2026-11-18: a TSTInfo
  re-signed here with serialNumber -5 or -2^63 is `ts -verify` OK, 0.26.0 said `malformed`); the versions and PKIStatus
  keep the non-negative rule. The token is `verified` with the root pinned and `signature_only` without a pin; another digest is
  `imprint_mismatch`, a nonce changed inside it does not verify. The five verifiers in other languages do not read RFC
  3161 tokens (they keep `tsa_token` outside the canonical form, §3) and the conformance vectors do not change.
  New vectors in `spec/vectors/rfc3161/third_party/` with their licences (manifest.json: repository, commit, sha256):
  that token (MIT) and the DigiCert root; `eurocert_signeddata_v1.tst` of esig/dss (LGPL-2.1), a real EuroCert QTSA
  token whose SignedData.version is 1 with eContentType id-ct-TSTInfo, still refused `malformed` "SignedData version
  is not 3 (RFC 5652 §5.1)" ("version MUST be 3" when the content type is not id-data; OpenSSL 3.0 parses it without a remark on the
  version: `ts -reply -token_in -text` prints it, `ts -verify` stops later, at "ess cert id not found"); and
  the token of a Sigstore bundle of dfandrich/fileviewinfo (MIT) without any certificate, `signer_certificate_absent`
  (0.26.0: `signature_invalid`, the entry below). `test_real_tokens_and_failure_classes_20261118.py`: the vectors, 610
  INTEGER encodings (10 chosen, 600 drawn at random) for the nonce and for serialNumber against an oracle from X.690
  §8.3.2, tokens signed here with 11 nonces and 6 serial numbers of either sign, SignedData versions -1 to 6 and 256 on
  two real tokens; 8 of its first 11 tests fail on 255eec5, the two that read a negative serialNumber fail on 54fc7eb,
  all pass here.

- **A listed file was read whole into memory, and a FIFO could block the verifier** (SPEC v0.11 §5 step 0, §10, §11,
  written before the code; from an external review of 0.26.0, re-measured on 2026-11-18). `evidence_pack.verify_pack`
  read every file of `file_digests_sha256` whole before any size bound: peak memory 20 / 219 / 519 MiB for a listed
  sparse file of 1 / 200 / 500 MiB (`ru_maxrss`, Python 3.11); now each is opened once without blocking, judged on the
  open descriptor and hashed in 1 MiB blocks (21 MiB for 200 MiB), and a file over the verifier's bound (256 MiB) is
  refused before reading (`refused` / `malformed`, `input_too_large: file <name> ...`); a listed file that exists and
  cannot be opened is `input_unreadable: file <name> ...` (until now an exception). The pinned TSA certificates and
  CRLs were checked with `os.stat` and then opened: a FIFO put in between blocked (`timeout 5`, exit 124; opening and
  then calling `fstat` blocks too, the open waits for a writer); now they are read the same way, at most 64 MiB each.
  The same class, found by running every sub-command of `cryptovalid-verify` on a FIFO and reading the readers of this
  repository: `verifier.py <a FIFO>` (the core ledger verifier), a pack whose MANIFEST.json is a FIFO and
  `cryptovalid-verify cldma <a FIFO>` blocked outright when no writer came; a pack's manifest and `cldma` are now
  refused `manifest_unreadable: not a regular file` and a FAIL layer. The ledger verifier reads a FIFO (SPEC v0.12 §5
  step 0): `verifier.py <(cat ledger.jsonl)` and `cryptovalid-verify ledger <(cat ...)` give the verdict of the same
  bytes, as the five other verifiers do since 0.20.2, read without blocking, at most 256 MiB, and a pipe idle for 10 s
  (no writer) is FAIL `unreadable: FIFO idle for 10 s`. A first version of this change refused every FIFO in
  `verifier.py`; the differential oracle (`verifiers/differential_oracle.py`, case `input-fifo`) found the disagreement
  with JS before release. A directory given to `verifier.py` is now named the same
  way (was `unreadable: IsADirectoryError`). `test_input_regular_bounded_20261118.py` (the cases that could block run
  in a child process with a timeout): 10 of its 12 tests fail on 4f15a65 (the control passes, and so does the pipe
  read whole, which 4f15a65 already did), all pass here, with and without `cryptography`.

- **The files inside a pack and an archive, the tip and `signer.py verify` could still wait on a FIFO** (SPEC v0.12 §5
  step 0 "every path read", written before the code). Measured on 2026-11-18 on the branch itself by replacing every file
  of an evidence pack, of an ingest archive and of a tile directory, one at a time, with a FIFO, a link to `/dev/zero`
  and a directory and running the commands (100 cases, each in a child process with a timeout): `cryptovalid-verify pack` and `auto` on a
  pack whose MANIFEST.json is a FIFO did not return (`evidence_pack.verify_pack` refused it, then the front-end opened
  the manifest again); `cryptovalid-verify archive` and `auto` did not return on an archive whose `*.sth.json` or
  `*.head.json` is a FIFO; `signer.py verify <a FIFO>` did not return, and `verifier.py --tip <a FIFO>
  --trusted-pubkey ...` neither; a `*.sth.tsr` of an archive was read whole whatever it was. The readers of
  `cryptovalid_beacon`, `cryptovalid_checkpoint` (notes), `cryptovalid_merkle` (tiles) and `auto` checked the path with
  `os.stat` / `os.lstat` and then opened it: the same window as the pins above. Each now opens once without blocking
  and judges the open descriptor, and answers with a named failure of its own receipt: `sth_unreadable` /
  `head_unreadable` (`InputNotRegular`), `tsa_token_invalid` with `unreadable: ...`, `tip_unreadable`, `not a regular
  file`, `input_unreadable`; `signer.py verify` on a path it cannot read (a FIFO, a device, a directory, an absent
  file) writes `{"ok": false, "error": "unreadable: ..."}` and exits 1 (until now a traceback for an absent file).
  A review of 54fc7eb then found the sentence "every reader" false: `cryptovalid_jws verify`, `cryptovalid_scitt
  verify`, `cryptovalid_witness verify`, `cryptovalid_receipt verify`, `cryptovalid_monitor` (its state),
  `eidas_ledger_check`, `cryptovalid_heterogeneous`, `cryptovalid_reanchor`, `tx_evidence verify`, `dora_incident
  verify`, `cryptovalid_report` (MANIFEST.json, SOLANA_ANCHOR.json) and the MCP server's `verify_pack` (its provenance
  hash) did not return on a FIFO with no writer (`timeout 25`, exit 124). A bench then gave every string argument of
  every command of the repository, one at a time, a FIFO with no writer and a link to `/dev/zero` (716 cases: 179
  arguments of 44 commands in 22 modules; the commands that go to the network or serve were not run, and
  `cryptovalid-verify` was measured apart with 210 cases): on 54fc7eb the command waited, or read the device without
  bound, for 41 arguments that it reads (the ten commands above, and `cryptovalid_tip check`, the key files of every
  signer, the inputs of `sign`, `register`, `cosign`, `attest`, `build`, `put`, the profiles of `refresh_regulatory`).
  Now for none. The rule is one sentence with three readers (SPEC v0.12 §5 step 0): what a verifier, a checker or a
  report reads is a regular file (`verifier.open_regular`, `read_regular`, `read_text_regular`, `sha256_regular`);
  the ledger of `verifier.py` is a regular file or a pipe; what a writer reads once, a key file or the data it signs
  or stores, is a regular file or a pipe read within a size bound and FAIL after 10 s without a byte
  (`verifier.read_input`, new), so `signer.py sign ledger out <(a command that prints the key)` works as before and a
  key path that is a FIFO with no writer is an error after 10 s (it waited without end). Readers the bench does not
  reach from a command line were changed too: `cryptovalid_monitor --sth-file` and `--match`, the object
  `cryptovalid_worm get` reads back, `cryptovalid_qeas`, `fundcert_crosssource` (the XLSX too), the LOTL cache, the
  witness's state, the ingest writer's own segments, the source of `verifier.copy_output`.
  The PKCS#11 module the token backend of `cryptovalid_kms` loads is judged on a descriptor before `dlopen` (a FIFO
  there blocked `dlopen` with the interpreter lock held, past the backend's own timeout: `timeout=3`, still waiting
  after 20 s; found by a second review, of 55e2e3f). Only the wait for each byte of a pipe is bounded, not the whole
  read (as for the ledger).
  `test_every_open_is_bounded_20261118.py` keeps the sentence true: it reads every module that is not a test and
  fails on an `open()` of a path outside a closed list of 14 entries (a temporary file the module has just written, a
  directory opened to fsync it, this distribution's `pyproject.toml`, the expected verdicts of `conformance.py`, the
  development tools); on 54fc7eb it lists 52 calls outside the list and 6 of its first 7 tests fail (the control
  passes). A second closed list, of 5 entries, holds the calls of the loaders the test names (`ctypes.CDLL`,
  `zipfile`, `shutil` copies, an import by name); the test of the PKCS#11 module does not return on 55e2e3f.
  An ingest archive whose segment without STH is a directory, a device or a FIFO was `ok` (the segment is not read);
  it is now `unsealed_segment_not_regular`, judged on a descriptor without reading it.
  `test_verifier_readers_no_block_20261118.py`: 3 of its 4 tests fail on 54fc7eb (the fourth, a regular file read as
  before, is the control), all pass here.
  Not covered (SPEC §5 step 0): a path a command writes: six output arguments (`--out`, `--cose`) still wait when the
  path is a FIFO with no reader; and the form of the error: for 48 of the 179 arguments the command given a FIFO or
  `/dev/zero` ends in a traceback and exit 1, not in a named failure.
  `test_every_reader_no_block_20261118.py`: 9 of its 10 tests fail on e5037e0 (the control passes), all pass here,
  with and without `cryptography`. Two faults of the two changes above, found by the full suite before release and
  corrected here: `test_packaging.py` reported the ledger's conditional `open` in `verifier.py` as a handle that is
  not closed by a `with` (now one wrapper over the descriptor or over the pipe's bytes), and `test_verify_evidence.py`
  still expected the `detail` of a FAIL ledger layer without the failure classes (now it asserts the classes first and
  the `failure_classes` member).

- **Messages in Italian in an English package.** `cryptovalid_receipt.cbor_decode` said "CBOR: byte in eccesso" for
  too much data (now "CBOR: trailing bytes"), and other messages for people were in Italian: the reasons, notes and
  errors of `cldma_confidential`, `committed_attestation`, `cryptovalid_heterogeneous`, `cryptovalid_jws`,
  `cryptovalid_monitor`, `cryptovalid_qeas`, `cryptovalid_reanchor`, `cryptovalid_receipt`, `cryptovalid_worm`,
  `dora_incident`, `eidas_ledger_check`, `fundcert_canonical`, `fundcert_crosssource`, `microfinance`,
  `pedersen_commit`, `signer` and `verify_evidence`, and two help texts of `cryptovalid_ingest`. Found by reading every
  string literal of the 46 packaged modules and of the `cryptovalid` package for Italian words (101 replacements,
  some of a message written over two lines, in 18 files); API.md: the wording of
  messages is not part of the API. Not changed, because they are keys or values of a closed vocabulary that a program
  may read (API.md §3: renamed only after the deprecation period): the witness's and checkpoint commands' `stato`,
  `motivo`, `tipo` and the value `ERRORE`, the keys and states of `eidas_ledger_check` (`stato`,
  `DICHIARATO_NON_VERIFICATO`, ...), the layer names of `verify_evidence` ("manifest autenticato (Ed25519)", ...) and
  `cryptovalid_monitor`'s `baseline_non_avanzata`. Docstrings and comments in Italian (141 docstrings in 29 modules)
  are not changed here. Four tests that matched the old wording now match the new one ("OUT OF RANGE",
  "trailing bytes", "chain not established", "NOT DEMONSTRATED").

- **A missing `cryptography` was reported as a malformed input** (rule first in each module's docstring, "Backend").
  Measured on 2026-11-18 on the wheel 0.26.0 installed without the `[sign]` extra: `cryptovalid_cose_receipts.
  verify_statement` answered a valid Signed Statement `MALFORMED_STATEMENT | ModuleNotFoundError: No module named
  'cryptography'`, and `verify_receipt` a valid receipt `MALFORMED_RECEIPT`. Now the stage is `BACKEND_MISSING` and
  `verify_statement_with_receipt` answers `result: "NOT_EVALUATED"` (a new value beside VALID and INVALID) unless a part
  was refused for another stage, which stays `INVALID`. The same class, found by reading every module that imports
  `cryptography` inside a function under a broad `except` (6 places in 5 modules) and measured with `cryptography` made
  unimportable: `cryptovalid_cedulon.verify_ledger` said `INVALID` / `malformed`, now `NOT_EVALUATED` /
  `backend_missing`; `cryptovalid_vaara_receipt.verify_receipt` said `signature_ok: false`, now `None` with `why`
  "backend_missing: ..." (its own rule: a check that cannot run is None). The other places read are not verdicts:
  `cryptovalid_jws.verify` loads the backend before its `try` and raises ImportError, `evidence_pack.build_pack` raises
  "manifest signing failed: ..." while building. All three modules are experimental. Without the backend a receipt
  whose key is read before its structure (most refusals of `verify_receipt`) is `BACKEND_MISSING`, not its refusal:
  nothing becomes VALID. `test_backend_missing_20261118.py` (the checks in a child process where `cryptography` cannot
  be imported, on an interpreter with or without it): red on 5dce401 (4 failures with `cryptography`, 2 without), green
  here.

- **A token under a pinned CA was "not issued by the pinned TSA" when its signing-certificate attribute lists more
  certificates than the chain to that CA** (SPEC v0.11 §11 step 7, written before the code). RFC 2634 §5.4 and RFC 5035
  (§5.4.1, §5.4.2 of ESS as it rewrites them): the first ESSCertID MUST be the certificate that verifies the signature;
  the ones after it "limit the set of certificates that are used during validation". openssl `ts -verify` asks more:
  every ESSCertID must be in the chain it built (`OSSL_ESS_check_signing_certs`, OpenSSL 3.0 and master), and with a
  pinned CA below the last certificate listed `-partial_chain` stops the chain at the pin. Measured on 2026-11-18 with
  OpenSSL 3.0.22 and 0.26.0: sectigo.tsr of spec/vectors/rfc3161 (ESSCertIDs of its signer, the CA R41, the Root R46)
  was `invalid / not_issued_by_pinned_tsa` ("ess cert id not found") with R41 pinned, alone or with R46 or with the
  signer too, and `verified` with the signer or R46 pinned; never `contradicted` (the pack said `tsa_unresolved`), but
  the reason was false. Now a token whose signing-certificate attribute lists more than one ESSCertID is checked as a
  signer named by subjectKeyIdentifier already was: the first ESSCertID is the signer certificate (hash; issuerSerial
  when present), every ESSCertID has a closed shape (hash of its algorithm's length, issuerSerial of one directoryName,
  no certificate listed twice),
  and openssl `verify -purpose timestampsign` builds the path through the pinned certificates and only the token's
  certificates a later ESSCertID identifies. sectigo.tsr is `verified` with R41 pinned. Verdicts that change, both
  ways: a signer named by subjectKeyIdentifier with more than one ESSCertID was refused whatever the pin ("exactly one is
  evaluated here") and is now checked; a path that goes through a certificate of the token the list leaves out (OpenSSL
  asks only that the listed ones be in the chain) is now refused. Tokens whose attributes list one ESSCertID
  each go through `ts -verify` as before, and so do the other 6 vectors of spec/vectors/rfc3161 except accv_qualified
  (two ESSCertIDs: its signer and its root, `verified` with each pin, as in 0.26.0).
  `test_tsa_ess_cert_ids_20261118.py`: 848 tokens made here (sid issuerAndSerialNumber or subjectKeyIdentifier x
  signingCertificate SHA-1 / signingCertificateV2 SHA-256 or SHA-384 x lists of 1 to 3 ESSCertIDs, the signer first or
  not, its hash altered x issuerSerial absent, present, wrong on the first or on a later one x the pin at the signer, the
  intermediate CA, the root, an unrelated CA), the outcome computed from the rule as written; on 0.26.0 (747086e)
  94 of them differ; a first ESSCertID that is not the signer's is refused in every combination; the sectigo vector with each
  pin of its chain.

- **A token without its signer certificate was "signature invalid"** (SPEC v0.11 §11 step 6, written before the code).
  `cryptovalid_tsa.verify_token` answered `invalid / signature_invalid` for a token whose signer certificate is neither
  in the token nor among the pinned certificates (a token requested with certReq FALSE, RFC 3161 §2.4.1): openssl never
  evaluated the signature ("signer certificate not found"). Measured on 2026-11-18 with the published wheel 0.26.0
  (sha256 32301998…8de4f) on the RFC 3161 token of a sigstore bundle (stacklok/toolhive 0.66.0
  `linux_amd64.tar.gz.sigstore.json`, its `[0] certificates` present and empty): `signature_invalid` without a pin,
  `verified` with the TSA chain of sigstore's trusted_root.json; and on the tokens of spec/vectors/rfc3161 with their
  certificates removed. The reason is now `signer_certificate_absent` (the status stays `invalid`: it does not count as a
  timestamp; ETSI EN 319 102-1 V1.4.1 §5.2.3.3, INDETERMINATE / NO_SIGNING_CERTIFICATE_FOUND). The absence is read from
  the SignerInfo's `sid` and every certificate in the token and pinned, and openssl must have stopped at the lookup of
  the signer certificate; anything not read, and a token openssl cannot parse, keeps `signature_invalid`.
  Verdicts that change: the evidence pack with a pin of another TSA said `time_anchor` `contradicted / token_invalid` for
  such a token, now `not_evaluated / tsa_unresolved`; the ingest's verify names it `tsa_token_signer_certificate_absent`
  (was `tsa_token_cms_invalid`); the report shows "IMPRINT BOUND, SIGNATURE NOT CHECKED" (was "TOKEN INVALID"). Every
  token that carries its signer certificate, or whose signer is pinned, has the outcome of 0.26.0
  (`test_tsa_signer_absent_20261118.py`: 7 vectors of spec/vectors/rfc3161 and 3 tokens made here — issuerAndSerialNumber,
  subjectKeyIdentifier, a written subjectKeyIdentifier — x certificates kept/removed x no pin/own/other x intact/altered
  signature, the shapes of the certificates field, a token openssl cannot parse and an issuer Name that does not decode;
  on 0.26.0, 45 of its cases fail and 84 are errors, the function they call being new; each of the four lookups of
  the new function, removed alone, turns it red).

## 0.26.0 (2026-11-17): verdicts change

### Added

- **A "not before" bound from the NIST Randomness Beacon 2.0, inside a payment entry** (experimental; SPEC v0.10 §18-§19,
  written before the code; revised after two reviews and a sample built for a public-sector payment receipt, 16/11/2026).
  Until 0.25.1 every time proof this repository verified was an upper bound (an RFC 3161 token, a signed tip, a
  checkpoint): nothing showed that a record was not prepared in advance. `cryptovalid_beacon.py` and
  `cryptovalid-verify beacon <ledger> --entry <idx> --pulse <f> --previous <f> --certificate <f>` (options: `--help`)
  check, offline, in the closed order of §19 rule 8:
  - a closed payment entry profile, `cryptovalid-payment/1` (§18): `payment_id`, a version 4 UUID in lowercase
    canonical form drawn by the provider (unique in the ledger); `amount` in one canonical form (exactly the minor units
    of its currency); `currency` three capital letters, checked against ISO 4217 only through a currency table the caller pins
    (`--currency-table`, `currency_table`; `tools/iso4217_table.py` writes it from the caller's own download of list
    one), with `amount` then in exactly the currency's minor units; without a table, a check of form only (at most 4
    decimals) and the scope does not prove `currency_not_checked`. No table is shipped: list one's publisher provides
    it for personal and information use, and the open sources measured on 2026-11-17 are not ISO 4217 (CLDR 49
    `digits`: HUF, IDR, COP, IQD 0; the EU authority table: COP, HUF, IDR, LAK 0, no XAD). Two drafts of this release
    carried a table (copied from list one, then generated from CLDR); neither was published; `beacons`, a list of 1 to 8
    beacon values; a `record_salt` of at least 128 bits; in clear only `execution_date`, `payee_entity_id` (a payee
    that is not a natural person) and `psp_id`; everything else that can identify a person or a payment of one only as
    commitments, SHA-256("cryptovalid-payment/1/" || member || 0x00 || 16-byte salt || normalised value): IBANs of
    payer and payee (optional: a card payment has none, a creditor may not know the payer's), names, tax identifiers,
    debtor, payer details, EndToEndId, notice code, purpose, receipt identifier, RRN; at least one party identifier.
    An IBAN is committed without spaces, in upper case, ASCII and passing ISO 7064 MOD 97-10; the rest in Unicode
    NFC. The provider keeps values and salts outside the ledger; `--disclosure` opens a commitment and
    `--require-disclosure` makes an opening required (`required_disclosure_missing`). Worded after EDPB Guidelines
    02/2025 v2.0 §52: a salted hash "will also be considered personal data", and after the salt is deleted "should not be
    linkable to the original data" under that paragraph's conditions. A committed or disclosed name uses only code points
    assigned in Unicode 13.0.0, so that NFC gives the same bytes in every runtime (measured: with later code points
    CPython 3.9, 3.13 and Node 22 disagree);
  - for each beacon value, the named pulse and its predecessor of NIST chain 2, version "2.0", in their closed grammar,
    against the beacon certificates the caller pins: signature (RSA PKCS#1 v1.5 SHA-512), outputValue, link, period,
    commitment, and the entry's value; the lower bound is the latest pulse;
  - with `--pack`, pinned TSA certificates and `--max-window`, the window [T, genTime] with the evidence pack's RFC 3161
    token (`window_inverted`, `window_too_wide`, a `--clock-tolerance` the caller gives), the TSA's revocation with
    `--tsa-crl`, and "qualified" only through a pinned Trusted List (`--tsa-trusted-list`, `cryptovalid_lotl`);
  - with `--checkpoint` (a file of the pack, under its token), `--log-vkey` and `--witness-vkey`, the entry fixed at its
    position in the history the pinned witnesses cosigned before genTime (`checkpoint_not_in_pack`,
    `checkpoint_log_not_trusted` for a note the pinned log did not sign, `checkpoint_not_witnessed`,
    `checkpoint_cosigned_after_gen_time`). A checkpoint outside the pack, or a cosignature after genTime, fixes
    nothing: an independent review measured on the first version 20 variants made "unique" by a cosignature added 400
    days later; now none;
  - **one entry without its ledger** (§19 rule 14): `cryptovalid-verify beacon --entry-file <entry> --proof <proof>`
    with the pack and the checkpoint, the RFC 6962 inclusion proof of the entry under the witnessed checkpoint
    (`cryptovalid_beacon.inclusion_proof` makes it). A third party that verifies one payment no longer receives the
    other payers' entries: the sample of 16/11 showed amounts and identifiers of two other payers in clear in the
    ledger it had to receive; the test checks that no member of the other entries is in anything given.
  The receipt states `not_before` = T against anyone but the beacon's operator, T minus one period only under the
  operator's freshness promise, and no bound against an operator that breaks its promises (§19 rule 4); a closed
  `scope` that always keeps `not_unique` and names the commitments not opened (`commitments_not_opened`) and, for one
  entry without its ledger, `payment_id_uniqueness`; and `record_complete` only with a window, a revocation check and
  a witnessed checkpoint in the pack. Exit 0 verified, 1 invalid or not evaluated, 2 usage error or refused input.
  Stated as limits in §19 rule 12, with their reasons: drand (planned), CURBy, a trust-profile file, the token's
  renewal, the TSA's `accuracy`, the outcome of the verification of the payee, the beacon certificate's revocation,
  a qualified signature or seal over the checkpoint (planned; Ed25519 today), a paper pointer format.
- **The TSA certificate's revocation, against CRLs the caller pins** (SPEC v0.10 §11 step 8):
  `cryptovalid_tsa.verify_token(..., crls=[...])` and `evidence_pack.verify_pack(..., tsa_crls=[...])` (library). After RFC
  3161 §4: unspecified, affiliationChanged, superseded and cessationOfOperation leave valid a token whose genTime is
  before the revocation date; no reason code, a compromise or any other reason makes every token of the certificate
  invalid (`tsa_certificate_revoked`); certificateHold, removeFromCRL, a CRL that does not apply, CRLs that disagree, a
  CRL with an extension the check does not process (a delta CRL, an issuing distribution point), and CRLs whose latest
  thisUpdate is before genTime give `tsa_revocation_unknown`. Without `crls` nothing changes. Measured on 16/11/2026 on
  0.25.1: a token issued after its TSA certificate was revoked for key compromise is `verified`;
  `openssl ts -verify -crl_check` with the CRL refuses it.
- `spec/vectors/beacon/`: six consecutive pulses of NIST chain 2 and the beacon's certificate, fetched on 2026-11-16; a
  payment ledger rebuilt from them by the tests (published example IBANs and fictitious names and identifiers, only as
  commitments); `conformance.json` (format `cryptovalid-beacon-conformance/4`) with 74 cases, among them a complete
  record of a ledger entry and of one entry alone, and at least one case for every one of the 46 result codes of §19
  rule 8, and 8 window cases, built by `make_conformance.py` with TSAs, CRLs, a trusted list and witnesses made for
  the purpose.
- **`cryptovalid_sri`: SRI integrity metadata, closed** (experimental; e.g. the `vct#integrity` claims of SD-JWT VC,
  draft -27 §6). `parse_integrity(value, grammar)` and `check_integrity(body, value, grammar)`, the grammar named by the
  caller: `sri-2016` (W3C SRI Recommendation 2016-06-23 with CSP Level 2, what SD-JWT VC references) or `sri-l2` (SRI
  Level 2 Working Draft 2026-03-20 with CSP Level 3, what https://www.w3.org/TR/SRI/ opens today); status read on
  w3.org on 2026-11-17. A value outside the grammar, with no recognised algorithm, or with a digest of the wrong length
  is refused with a closed code (`empty`, `grammar`, `alg_not_recognised`, `digest_length`); every refusal reports
  `sri_match_would_accept: true` when the SRI matching algorithm (REC §3.3.3, §3.3.5) would have returned true for any
  bytes. `test_sri_20261117.py`: 8 tests; the five real values of IT-Wallet (two `vct#integrity` examples) and EUDI TS12
  v1.0.1 (lines 523-525), taken from the files saved by the reviews of 16-17/11, are all `grammar`, each one accepted by
  a plain SRI matcher; the SRI Recommendation's own example and the SHA-256 of empty input verify; 8 000 generated
  values agree with an oracle written apart (one regular expression of each ABNF). 14 hand mutants: 13 detected,
  1 equivalent (the "-" made optional: the base64 part is then empty, which the grammar refuses).
- **`cryptovalid_httpdigest`: HTTP message digests against the body** (experimental). `check_digest(field, body,
  syntax)`, the syntax named by the caller: `rfc3230` (`Digest`, RFC 3230, obsoleted by RFC 9530 and still cited, e.g.
  by the Italian ModI guidelines) or `rfc9530` (`Content-Digest` / `Repr-Digest`, Structured Fields of RFC 9651);
  status read on rfc-editor.org on 2026-11-17. As both RFCs say ("A recipient MAY ignore any or all digests"), unknown
  and deprecated algorithms are listed in `ignored`, not refused; a duplicated dictionary key keeps its last value and
  base64 without padding or with non-zero pad bits is read (RFC 9651 §4.2.2, §4.2.7), both reported. Outcomes: `ok`,
  `not_text`, `grammar`, `digest_length`, `mismatch`, `no_supported_alg`. `test_httpdigest_20261117.py`: 11 tests; the
  ModI INTEGRITY_REST_01 example (the `Digest` is the SHA-256 of `{"testo": "ciao mondo"}`, not of the body shown with
  "Ciao") gives `ok` and `mismatch`; the digests of RFC 9530 verify; 3 000 dictionaries serialized by RFC 9651 §4.1
  apart from the parser and 3 000 mutated fields. 17 hand mutants: 14 detected, 3 equivalent (a first key character
  outside `[a-z*]` is never consumed and the field fails anyway; ";" is consumed by the parameter parser before the
  separator is read; a character outside base64 inside a Byte Sequence also fails the base64 decoding).
- **`sha1_signature_legacy` in the outcome of `cryptovalid_tsa.verify_token`** (SPEC v0.10 §11 step 7, written
  before the code): a certificate of the TSA chain signed with SHA-1 stays accepted, as in 0.25.1 (OpenSSL 3.0.22 accepts
  it, in both forms of `sid`), and is now reported. NIST SP 800-131A Rev. 2 (§9 Table 8; Rev. 3 is an initial public
  draft, not final on 2026-11-17) disallows SHA-1 for generating signatures and allows it for verifying them as legacy
  use. A closed member: `null` unless step 7 passed (and when a certificate of the path cannot be read here), then
  `true` or `false`; the path is read by names from the signer certificate among the pinned certificates and the
  token's, a self-issued certificate excepted (OpenSSL does not check a trust anchor's signature on itself), so it can
  report more than the chain OpenSSL built, never less. The evidence pack's `tsa_check` (§10) carries the same member
  and the beacon window carries it as `tsa_sha1_signature_legacy` (§19). Verdicts do not change.
  `test_tsa_sha1_legacy_20261117.py`: 14 tests, each case in both forms (a SHA-1 TSA certificate, a SHA-1 intermediate
  carried only by the token, a SHA-1 self-signature of the root, two certificates with the issuer's name, a cycle of
  cross certificates, RSASSA-PSS with SHA-1 or its default, each OID of the list, unreadable certificates, the pack's
  `tsa_check`); on the code before this change 13 fail (the fourteenth checks the bench; on 0.25.1 the file fails at
  its import); `test_beacon_20261116.py` checks the window's
  member. 33 hand mutants of the new lines: 33 detected (one, the path without its record of certificates already
  read, by a 60 s timeout on the cycle).
- `bench/beacon_cost/`: the cost of one check, measured (below).
- `test_review3_20261117.py`: 7 tests added after the third review, a control and six that each fail against a mutant
  of the new lines that the suite let live: an ESS attribute given twice, both ESS attributes present with the second
  wrong, an ESSCertID with a third element or with an issuerSerial that is not a SEQUENCE, an issuerSerial with two
  names, a `tsa` field right after genTime (a TSTInfo without accuracy, ordering or nonce), a COSE receipt whose attached
  payload is the root of its second proof.
- `test_beacon_review2_20261116.py`: 8 tests added after the second review (Unicode version of the commitments, a payee
  entity as the only party identifier, a CRL entry extension and a freshestCRL extension, the scope sentences against
  this SPEC, `ts` of one entry, the 1 MiB bound of one entry); each fails against the mutant or the defect it was written
  for.
- `test_beacon_20261116.py`: 95 tests, among them every pair of 15 faults of different steps (105 pairs: the code is
  always the earlier step's), the reviewer's 20-variants and 400-days case, one entry by its proof (and its control:
  the ledger's pack carries the other entries), the conformance cases; on 0.25.1 the file fails at its import (the
  module is absent) and `cryptovalid-verify beacon` exits 2. Without `cryptography`: 42 run and pass, 53 skipped (the
  RSA, X.509 and Ed25519 checks cannot run). `test_tsa_revocation_20261116.py`: 18 tests on CAs, TSAs and CRLs made
  with openssl and `cryptography`; on 0.25.1 `test_defect_of_0_25_1_through_public_behaviour` fails by assertion (the
  token after a keyCompromise revocation is `verified`), the others by the missing `crls` parameter. 206 hand mutants of the new lines (`cryptovalid_beacon.py`,
  `cryptovalid_tsa.py`, `evidence_pack.py`), run on the branch before the second review: 200 detected (one by a 300 s timeout: a FIFO read that
  blocks); 3 more detected by tests added after the run (each run against its mutant); 3 equivalent: an entry looked up
  by `idx >=` instead of `==` on a ledger whose `idx` equals its position (SPEC §5 step 4); the log's signature
  status dropped from `checkpoint_log_not_trusted` (the origin is read only from a note whose signature verified, so a
  failed signature already leaves it outside the pinned names); `tree_size >= 1` dropped from the proof's grammar
  (implied by 0 <= leaf_index < tree_size).

### Fixed

- **An RFC 3161 token whose SignerInfo names its signer by subjectKeyIdentifier** (allowed by RFC 5652 §5.3) was
  `not_issued_by_pinned_tsa` (in an evidence pack, `tsa_unresolved`) even when valid: openssl `ts -verify` reads the token
  as PKCS #7 and refuses that form with an ASN.1 error. Measured on 2026-11-16 with OpenSSL 3.0.22: the TSTInfo of a
  valid token re-signed by `openssl cms -sign -keyid -cades` with the same TSA key verified at §11 step 6 and failed
  step 7. Step 7 (SPEC v0.10) now makes the same checks one by one for that form, names compared as OpenSSL's
  `X509_NAME_cmp` compares them (the first version of this fix compared them byte for byte: measured on 2026-11-17 by the
  third review and again here, a `tsa` field differing from the subject only in case, spaces or string type was refused
  in this form and verified in the other, 15 of 64 pairs on our bench, 0 now): the ESS signingCertificate or
  signingCertificateV2 attribute against the signer certificate, the TSTInfo `tsa` field against its subject or
  subjectAltName, and `openssl verify -purpose timestampsign -partial_chain -attime` against the pinned certificates
  only. Found while extracting the payment profile into a separate repository. `test_tsa_signer_key_id_20261116.py`:
  21 tests on CAs, TSAs and tokens made with openssl; the valid token is `not_issued_by_pinned_tsa` on 0.25.1 and verified now; another
  key identifier, another TSA's key, no ESS attribute, a certificate without timeStamping, a `tsa` field naming another
  TSA, a system certificate directory and a CA without keyCertSign behind a pinned leaf are refused; names in another
  case, with other spaces, as a PrintableString, and the rules of the comparison (22 tests in all); 35 hand mutants of
  the new lines, 34 detected, 1 equivalent (the sid tag compared with `!= 0x30` instead of `== 0x80`: `parse_token`
  admits no other tag).

- **The step for a signer named by subjectKeyIdentifier, closed by construction** (SPEC v0.10 §11 step 7 "Closed
  shapes", written before the code). The port of this step to omega-cra-evol was stricter in three points; each was
  measured here on 2026-11-17 with that port's generative bench (every DER element of a key-identified token dropped,
  duplicated, retagged, given a stranger or flipped: 536 variants): (a) two SignerInfos: `verify_token` already refused
  them at step 1 (`malformed`); the step's helper alone took the first, and now refuses; (b) the helper accepted 9
  changes inside the ESS attribute and 8 signed attributes retagged or extended (the attribute's tag, elements after
  attrValues, the SET tag, elements after `certs`, the ESSCertID's tag were not read; none of them made §11 accept a
  token, the CMS signature of step 6 covering the signed attributes): now every signed attribute is {OID, SET}, a
  SigningCertificate(V2) {certs, policies?} with `policies` a SEQUENCE OF PolicyInformation, the ESSCertID a SEQUENCE;
  0 accepted, none raises; (c) an openssl whose `verify` does not know `-no-CAstore` (before OpenSSL 3.0) was
  `not_issued_by_pinned_tsa`; it is now a check not run (`CheckNotRun`, exit 74 in a command).
  `test_tsa_closed_shapes_20261117.py`: 5 tests, 4 of them fail on the code before. 14 hand mutants: 14 detected.

### Measured

- The deployed NIST Beacon 2.0 does not serialize as the draft NIST IR 8213 (May 2019, still an initial public draft on
  2026-11-16) says: 4-byte length prefixes, not 8; `external.statusCode` in 4 bytes, not 8; outputValue over the raw
  signature. On the six pulses of the vectors the draft's rules verify 0 signatures and 0 output values, the deployed
  rules 6 and 6.
- Cost of one check (`bench/beacon_cost/README.md`, Intel Core i3-N305, Python 3.13): about 2.5 ms for one entry with
  its two pulses read from disk (0.5 ms of it the two RSA-4096 signatures and the commitment), 53 to 56 ms with the
  evidence pack's window, a complete record, or one entry alone by its inclusion proof (pack verify and two openssl
  processes).

### Changed

- README: "Try it in 30 seconds", three commands on the NIST pulses and public RFC 3161 tokens shipped in
  `spec/vectors/`, with their output as measured; the beacon module is listed with the experimental ones.
- **"Qualified" needs the qualified statement of Commission Implementing Regulation (EU) 2025/1929** (SPEC v0.10 §11,
  §19; written before the code). The Regulation (OJ L 30.9.2025, in force since 2025-10-20; read on CELLAR on
  2026-11-17), Annex, adapting ETSI EN 319 422 V1.1.1 clause 9.1: a time stamp declared qualified "shall contain one
  instance of the qcStatements extension" (RFC 3739 §3.2.6), holding one `esi4-qtstStatement-1` (0.4.0.19422.1.1),
  "not ... marked as critical". Until 0.25.1 a token whose signer was a granted QTST certificate in the trusted lists
  was `qualified` whatever it carried; now `cryptovalid_lotl.qualification` says `qualified` only when the token also
  carries the statement, and otherwise `not_qualified` with the closed reason `qualified_statement_missing` or
  `qualified_statement_malformed` (new `qualified_statement_problem`). Where it shows: the `cryptovalid_lotl` command
  (`not_qualified_reason`; `indeterminate` stays for the trusted-list history only), `cryptovalid_ingest verify --lotl`
  (such a token is not counted as qualified nor, without `--tsa-cert`, as a timestamp; warning
  `tsa_qualified_statement_missing`; segment meta `eidas_not_qualified_reason`), `cryptovalid_report` (`reason`), the
  beacon window (`tsa_qualification_reason`, null unless that reason applies; the `stamped_by_qualified_tsa` sentence
  names the statement). `parse_token` returns the TSTInfo's non-critical extensions (`extensions`). §11 verdicts do not
  change. Real tokens requested on 2026-11-17, now in `spec/vectors/rfc3161/` with their signer certificates: BOSA
  (`tsa.belgium.be/connect`), Izenpe and ACCV carry the statement; Sectigo's qualified endpoint writes the DEFAULT
  `critical` FALSE in its Extension, which DER leaves out, so §11 refuses that token as `malformed` (RFC 3161 §2.4.2;
  unchanged, reported); the tokens of 2026-11-13 carry none. `test_tsa_qualified_statement_20261117.py`: 8 tests, 17
  generated shapes in both forms of `sid` (made by re-signing an `openssl ts` TSTInfo with `openssl cms -cades`); the
  tests of the lotl, the ingest, the 2026-11-13 tokens and the beacon window updated to the rule (each fails on the
  code before this change; 6 of the 8 new ones too). 19 hand mutants of the changed lines: 19 detected.
- **NIST IR 8547 is final (October 2026)**: the limit is stated in SPEC §15 (Table 2: ECDSA, EdDSA and RSA "Deprecated
  after 2030", "Disallowed after 2035"; the hybrid Ed25519 + ML-DSA-65 path this format has), `docs/KEY_LIFECYCLE.md`,
  `docs/THREAT_MODEL.md`, and the `pq_note` of an Ed25519-only ledger in `signer.py`, the Go and the Java verifiers
  ("NIST IR 8547 final, October 2026: EdDSA deprecated after 2030, disallowed after 2035"; until now "NIST IR 8547
  draft"). A note of the result, not a verdict.
- **CCF receipts (vds 2) read after draft-ietf-scitt-receipts-ccf-profile-06** (2026-11-11, current on datatracker on
  2026-11-17; -05 was cited until now; the module's docstring, its normative text, written before the code). Verdicts
  that change: an inclusion proof with an empty path (a tree of size 1, root = leaf hash) verifies (refused under -05);
  every proof's data-hash must equal the entry ("Every proof in the receipt MUST", §3.2), so a proof of another leaf
  of the same tree beside a bound one is `LEAF_NOT_THIS_STATEMENT` (accepted until now); a vdp map with a key other
  than -1 and -2 is `MALFORMED_PROOF` (ignored until now), and one with consistency proofs is
  `CONSISTENCY_NOT_EVALUATED` (§5: every proof present MUST recompute the same root; consistency proofs are not
  evaluated here). New: `ccf_statement_digest(statement)`, the data-hash of §2.2 (SHA-256 of the Signed Statement with
  tag 18 kept and an empty unprotected header, the rest as received); on the public vector `valid-ccf-vds2` it equals
  the recorded leaf entry. VDS 1 is unchanged. `test_ccf_profile06_20261117.py`: 7 tests, 6 of them fail on the -05
  code. 10 hand mutants: 7 detected, 3 equivalent (trailing bytes, a wrong array head and indefinite lengths are
  refused by the strict CBOR decoding that runs before the byte walk).
- **Verdicts of 0.25.x that change in 0.26.0** (`cryptovalid_cose_receipts`, profiles `rfc9942` and `rfc9943`; rules in
  its docstring, decided on 2026-11-17 after a cross-verification matrix measured 0.25.1 on the scitt-cose public vectors,
  action-state-group/scitt-cose at commit e76bbfdf7a02, now in `spec/vectors/scitt-cose/` with their SHA-256 pinned).
  PASS in 0.25.x, FAIL now, measured on the 25 vectors with the 0.25.1 tag and with this branch:
  - `receipt-v1/fail-es256-secp256k1-key`: ES256 (-7) over a secp256k1 key, now `KEY_CURVE_MISMATCH`;
  - `receipt-v1/fail-es384-p256-key`: ES384 (-35) over a P-256 key, now `KEY_CURVE_MISMATCH`;
  - `receipt-v1/fail-malformed-tail-proof`: a valid inclusion proof followed by a malformed one, `[0, 0, []]`, now
    `MALFORMED_PROOF` (0.25.x skipped a malformed proof when another one verified).
  ES256 is bound to P-256 and ES384 to P-384 for a Signed Statement too (a statement signed with ES256 over a secp256k1
  key passed in 0.25.x; no public vector, tested with keys made in the test). Basis: RFC 9053 §2.1 (Informational, 2022,
  updated by RFC 9864) "defines ECDSA as working only with the curves P-256, P-384, and P-521" and says that
  "Implementations need to check that the key type and curve are correct when creating and verifying a signature"
  (secp256k1 has its own algorithm, ES256K, RFC 8812), and "it is suggested that SHA-256 be used only with curve P-256,
  SHA-384 be used only with curve P-384" (binding ES256 to P-256 and ES384 to P-384 follows this suggestion); RFC 9864 (Proposed Standard, October 2025) §2.1 calls these COSE algorithms polymorphic and §4.2.2 registers
  them as Deprecated (status read on rfc-editor.org on 2026-11-17). Refusals that keep their verdict and change only
  their stage: a receipt with a malformed or unwalkable proof, as `v1/fail-zero-size-proof` and
  `receipt-v1/fail-malformed-proof` (`INCLUSION_ROOT_SIGNATURE_INVALID` → `MALFORMED_PROOF`); an ES256 or ES384 header
  over a key of another type or curve, in a Signed Statement (`BAD_STATEMENT_SIGNATURE` → `KEY_CURVE_MISMATCH`) or in a
  Receipt (`INCLUSION_ROOT_SIGNATURE_INVALID` → `KEY_CURVE_MISMATCH`, measured on 0.25.1 and now with an Ed25519 and a
  P-384 key under an ES256 header).
  Unchanged and now reported: a receipt whose payload is attached and equal to the rebuilt root stays accepted (RFC 9942
  §4.4: the payload "SHOULD be detached"; the vector `fail-attached-payload-root` expects a refusal, a declared
  difference) and its result carries `payload_attached: true`. Unchanged and stated: `cryptovalid_acta` keeps refusing
  `"previousReceiptHash": null`, an ambiguity of draft-farley-acta-signed-receipts-03 (still the current revision on the
  IETF datatracker on 2026-11-17). `test_scitt_cose_vectors_20261117.py`: 6 tests, 4 of which fail on 0.25.1 (the 2 that check the pinned files pass
  there); 13 hand mutants
  of the changed lines, 12 detected, 1 equivalent (the curve test inside the signature helper: every call to it comes
  after the same test with a refusal).
- `test_pyc_cut_20261014.py` counts 34 commands carrying the bytecode wrapper (33 until 0.25.1): the new module is one.
- `cryptovalid/__init__.pyi` and `API.md` declare the new parameters `crls` of `verify_token` and `tsa_crls` of
  `verify_pack`.

## 0.25.1 (2026-11-16)

### Fixed

- **`--expect-ledger-id` and `--tip-not-before` are applied without a tip** (SPEC v0.9 §17, written before the code).
  Until 0.25.0 both were read only inside the check of a signed tip, so without a tip file, or with a tip and no trusted
  log key, they were accepted and left out: measured on 16/11/2026 on 0.25.0, `verifier.py examples/sample_ledger.jsonl
  --expect-ledger-id <the id of another ledger>` and `--tip-not-before 2099-01-01T00:00:00Z` were PASS, exit 0, and the
  receipt did not name the option; the JS, Go and Java verifiers answered the same (exit 0). Reported by Athena on
  16/11/2026. Now, in `verifier.py` / `cryptovalid.verify_ledger` and in the JS, Go and Java verifiers:
  - the expected identity is compared with the `self_hash` of entry 0, with or without a tip, trusted or not: a
    different value, or a file with no entry, is FAIL with `ledger_id_mismatch`; a match is named in the receipt's
    `scope.proves` (the receipt keeps its keys);
  - the expected identity is 64 lowercase hex characters; any other value (empty, upper case, with spaces, other
    characters) is a usage error, exit 2, in the four command lines and in `cryptovalid_tip.py check`, and a
    `ValueError` in `verify_ledger` and `cryptovalid_tip.check_tip` (until 0.25.0 an empty value given to the Python
    functions meant "not given");
  - `--tip-not-before` makes the tip required, as `--trusted-pq-pubkey` already did: without a tip FAIL `tip_missing`,
    with a tip and no trusted key FAIL `tip_untrusted`; an empty value given to the Python functions is a given value
    (the tip is required, and a checked tip FAILs with `bad_not_before`).
  - a value option given twice is a usage error, exit 2, in the four command lines, in `cryptovalid_tip.py check` and
    in `cryptovalid-ingest verify` (until 0.25.0 the last value was kept: `--expect-ledger-id <another ledger's id>
    --expect-ledger-id <this ledger's id>` was PASS, exit 0, in the four verifiers);
  - `cryptovalid_tip.py check` refuses an empty `--tip` or `--trusted-pq-pubkey`, exit 2 (until 0.25.0 an empty
    `--trusted-pq-pubkey` dropped the post-quantum check: ok, exit 0);
  - `ledger_id_mismatch` comes first in `parse_errors`, which keeps 10 lines (after 10 earlier errors it was not in
    the receipt; the verdict was FAIL).
  Unchanged, and written in §17: `--trusted-pubkey` without a tip file is still the bare chain's verdict (the tip is
  required only with `--require-tip`); the Rust and Swift verifiers have none of these options and refuse them (exit 2:
  Rust measured, Swift by its code).
- **An empty pin in the archive verifier is refused** (SPEC §17 rule 4): `cryptovalid_ingest.verify_archive` with
  `expected_pubkey_hex` `""` or `[]` was ok true with the warning `no_pinned_pubkey` (measured on 0.25.0 on a signed
  archive; a list holding an empty key was already not ok, `sth_signer_mismatch`), and `cryptovalid-ingest verify
  --pubkey ""` the same, exit 0. Now all three are a `ValueError`, and exit 2 for `--pubkey ""`.
- **The MCP server refuses an argument a tool does not take** (JSON-RPC `-32602`, the schemas say
  `additionalProperties: false`). Until 0.25.0 it was dropped: `verify_ledger` with `{"path": …, "expect_ledger_id":
  <another id>}` answered PASS (measured on 0.25.0).
- `test_expect_applied_20261116.py`: 16 tests — the reported case; 840 generated combinations of expected identity
  (none, right, another ledger's, a random one, 17 malformed values) x tip (none, untrusted, trusted, another
  ledger's) x oldest tip (none, empty, past, future, malformed) x `--require-tip` on `verify_ledger`, checked against
  an oracle written from §17 and spec/CONFORMANCE.md (680 refusals, 148 FAIL, 12 PASS; 420 cases without
  `cryptography`, where no tip can be signed); 300 random identities; 72 of these combinations (identity none, this
  ledger's or another's x oldest tip none, past or future x `--require-tip` x the four tip states) on the command lines
  of Python, JS, Go and Java (exit code and verdict) and the malformed values in each (exit 2, nothing on stdout);
  `check_tip` and `cryptovalid_tip.py check`; the archive pins; the MCP arguments. 15 of the 16 fail on 0.25.0 (the
  sixteenth is the negative control: without options the receipt is the receipt of 0.25.0). `verifiers/js/test.mjs`
  and `verifiers/go/tip_test.go` gain the same checks on their libraries. `test_expect_once_20261116.py`: 4 tests
  (a value option given twice in the four command lines, `cryptovalid_tip.py check` and `cryptovalid-ingest verify`;
  empty values in `cryptovalid_tip.py check`; `ledger_id_mismatch` after 10 earlier errors), all 4 failing on
  0.25.0.

## 0.25.0 (2026-11-16)

- **The witness module accepts a log that signs with ML-DSA-44, and tells the log from a witness by the list a key is
  in** (SPEC v0.8 §16). c2sp.org/tlog-checkpoint (C2SP/C2SP @ 09f3e519fe79, read on 15/11/2026): an ML-DSA-44 signature
  "can be used either by the log to authenticate itself, or by an arbitrary cosigner role". `cryptovalid_witness` took
  the type of a key for its role. `verify_witnessed` and the `verify` command (exit 2), `witness_cosign`,
  `WitnessService` and `submit_checkpoint` refused a 0x06 log key ("a log key must be an Ed25519 (0x01) or ECDSA (0x02)
  note key") before reading any signature: measured on 15/11/2026 with a live checkpoint of the Sigstore staging log
  `pqc27-a1.us-east4.rekor.sigstage.dev` (its log key from the TUF `trusted_root.json` of tuf.v2.sigstage.dev, three
  ML-DSA-44 witnesses), which `cryptovalid-verify checkpoint` verifies, and with torchwood's litewitness vector
  (`testdata/interop/torchwood_mldsa44_log.*`), which that witness cosigns. And `verify_witnessed` counted every
  verified 0x04 or 0x06 line as a witness, so a 0x06 log line would have counted as one more. Now log keys are 0x01,
  0x02 or 0x06 and witness keys 0x04 or 0x06; a line counts for the role of the list its key is in; a key (name and
  key id) in both lists, or a trusted log key equal to the witness's own ML-DSA-44 key, is refused (`NoteError`); a
  checkpoint with extension lines whose only trusted log signatures are ML-DSA-44 (which do not sign them) is refused
  by the witness (400) and by the relying party (`NON_VALIDA`). Unchanged: a 0x01 or 0x02 key in the witness list is
  refused, and an Ed25519 key used under one name as a 0x01 log key and as a 0x04 witness key counts once in each role.
  The Sigstore checkpoint now verifies with `min_witnesses` 3 and not with 4. `test_witness_mldsa_log_20261115.py`:
  14 tests, one of them only with `CV_SIGSTAGE_DIR` (the Sigstore checkpoint is not shipped), including 600 generated
  cases (keys of five types in both lists, repeated and in any order: 100 OK, 413 NON_VALIDA, 87 refused) checked
  against an oracle written from §16; the 14 fail on the code before this change, and 19 hand mutants of the changed
  lines are killed by this file and `test_cryptovalid_witness.py` (two of them found in review: the rule on extension
  lines read over the witnesses' lines as well as the log's, and a witness key of an unassigned type refused by
  `submit_checkpoint` instead of ignored).
- **SPEC §15: the hybrid signature of this format is not the composite ML-DSA of RFC 10073.** Half a page with the
  sections of RFC 10073 it rests on (§2.1, §2.2, §3.1–§3.3, §4.1, §4.3, §5.3, §9.3, read in full on 15/11/2026): what
  both algorithms sign, the ML-DSA context, one value or two fields, "both or nothing" or per layer; the keys of a
  hybrid ledger are standalone keys and are not republished as a composite key (RFC 10073 §5.3: "Component keys of a
  composite MUST NOT be used in any other type of key or as a standalone key"). No verifier changes.
  `test_hybrid_is_not_composite_20261115.py` measures the difference in both directions with the same two keys over the
  same message: neither crossing verifies, both direct checks do; its composite helper is a test helper, checked
  against the two signatures of the RFC's Appendix E for `id-MLDSA65-Ed25519-SHA512` when the RFC's text is given
  (`CV_RFC10073_TXT`; they verified on 15/11/2026). Proposed by Athena's review of 15/11/2026.
- **A pinned TSA certificate must be shaped as a certificate** (SPEC v0.8 §10, found by the NEMESIS review of
  15/11/2026). `tsa_certs` / `--tsa-cert` accepted any item whose first byte was 0x30; openssl could not load such a pin
  and refused the token's signature, so the real DigiCert token of `spec/vectors/rfc3161`, pinned with its own
  certificate plus such a file, was `tsa_unresolved`, and pinned with the file alone `contradicted / token_invalid` (the
  pack not valid). Each PEM block or DER item must now be a SEQUENCE of two SEQUENCEs and a BIT STRING (RFC 5280 §4.1),
  checked before the pack is read: otherwise `ValueError`, exit 2 for `--tsa-cert` (also for the ingest, the receipt
  and `eidas_ledger_check.py`, which share the check). `test_tsa_pin_shape_20261115.py`.
- **The evidence pack's verify checks the RFC 3161 token against a TSA the caller pins** (SPEC v0.8, §10–§11):
  `evidence_pack.py verify DIR --tsa-cert PEM` (repeatable) and `verify_pack(..., tsa_certs=[...])`. Until now the
  pack's token was read for its status and imprint only, `time_anchor` was never `verified`, and a token whose signature
  was broken left the pack valid (`tsa_not_checked`). With a pin the token goes through SPEC §11 (`verify_token`):
  `verified` (the receipt's `rfc3161.tsa_check` carries `gen_time` and the signer's SHA-256); a token valid but not
  established under the pinned certificates, such as one of another TSA, is `not_evaluated / tsa_unresolved` and leaves
  the pack valid, as `key_unresolved` does for a producer key (ETSI EN 319 102-1 V1.4.1 §5.1.3: INDETERMINATE,
  NO_CERTIFICATE_CHAIN_FOUND); a token whose signature does not verify, or that §11 refuses at steps 1–6, is
  `contradicted / token_invalid` and the pack is not valid. A receipt computed with a pin names
  `states_vocabulary: cryptovalid-evidence-pack/states-2`; without a pin nothing changes: on 5 191 packs of the
  generative bench (`verifiers/pack_states_bench.py`: its base packs, every mutation, each also re-digested) the
  receipts of this code and of the code before are equal, and with a pin the only change is `tsa_not_checked` →
  `verified` on the 156 packs whose token binds. The SPEC §11 now says which refusals show a token false (steps 1–4
  and 6) and which leave it unestablished (step 7); the ingest's verify and `eidas_ledger_check.py` keep reading step 7
  as before (named in §11). The real tokens of `spec/vectors/rfc3161` are checked under all 31 sets of the five pins;
  `test_pack_time_anchor_pin_20261115.py`. Proposed by Athena's review of 15/11/2026.
- **The stage `MALFORMED_STATEMENT` of the COSE receipts has a test, and the CBOR decoder names a cut-short input.**
  `test_scitt_malformed_statement_20261115.py` runs the 94 examples of RFC 8949 Appendix F.1 (CBOR data items that are
  not well-formed; compared byte for byte with the text of the RFC on 15/11/2026) in five positions each against
  `cryptovalid_cose_receipts.verify_statement`: 470 inputs, all `MALFORMED_STATEMENT`, none raises (as before: the
  stage was right, only untested). `cryptovalid_receipt.cbor_decode` raises only `ValueError` on bytes: a head cut short
  raised `IndexError` (16 of the 94 examples), and a head or a string cut short was reported as "byte in eccesso" (bytes
  in excess, the opposite of what happened); now "input ends inside …", and additional information 28–30 is named
  reserved instead of "indefinite form". One outcome changes: in `cryptovalid_cedulon`, a record whose COSE bytes end
  inside a head was refused at stage `malformed` (the `IndexError` reached the catch-all); it is now refused at
  `record-header`, the stage that reads the record. Proposed by Athena's review of 15/11/2026.
- **A declared, typed API: the package `cryptovalid`** (`API.md`). `import cryptovalid` exports the 18 names of its `__all__`:
  11 functions of the core (`verify_ledger`, `verify_pack`, `verify_note`, `verify_tiles`, …), `LedgerReceipt`, four
  exception classes, the deprecation warning class and `__version__`, with a stub (`__init__.pyi`), `py.typed` (PEP 561)
  and `LedgerReceipt`, the receipt of `verify_ledger` declared key by key; the flat modules stay as they are and are
  not declared API. Checked in CI (`governance.yml`, job `api`): `mypy --strict` (mypy 2.4.1, pinned by hash; target
  3.10, the oldest it accepts), `python -m mypy.stubtest` and `tools/check_stub.py`, and `test_declared_api.py`, which
  also builds the wheel and finds the stub and the marker inside it. stubtest found that the stub of `TokenError`
  lacked its constructor (`reason`, `detail`); fixed. SemVer and the deprecation period for the 0.y line, and the
  conditions for 1.0, are written in `API.md`. Proposed by Athena's review of 15/11/2026.
- **Governance files.** `CONTRIBUTING.md` (reports and interoperability results welcome; code contributions not
  accepted at present; the maintainer's commits carry a DCO 1.1 sign-off since 15/11/2026, checked on pull requests
  by `tools/check_dco.py`), `GOVERNANCE.md` (one maintainer; no second reviewer), `SUPPORT.md` (the latest release only;
  no paid support), `.github/CODEOWNERS`, `DCO` (the text of developercertificate.org). No contributor licence
  agreement: no commercial licence is offered and no external code is accepted.

- **The sdist is complete and reproducible.** The 0.24.0 sdist held 56 entries (54 files): no test, specification, vector or
  CHANGELOG, so nobody could run the suite from it; and two builds of one commit with the same `SOURCE_DATE_EPOCH`
  gave different sdists (build time in the tar members and the gzip header; measured 15/11/2026, the wheels were
  identical). `MANIFEST.in` now puts every tracked file in it (on this branch: the same list as `git ls-files`), and
  `.github/reproducible_sdist.py` rewrites it with sorted members, the commit's date, owner 0 and normalised modes;
  `release-build.yml` sets `SOURCE_DATE_EPOCH` from the commit, rewrites the sdist and checks that it carries every
  test file. Its build step no longer dies on an unset `GITHUB_REF_TYPE` / `RUNNER_TEMP` when run outside
  GitHub (`set -u`; found by the local CI bench). Two builds from two copies: wheel and sdist byte-identical. The suite runs from the unpacked sdist (no git
  metadata): `test_spdx_headers.py` and `test_cli_help_english_20261115.py` list the files of an unpacked sdist
  (PKG-INFO at the top) when there is no git checkout, and still fail anywhere else.
- **Go verifier: what Go < 1.27 does, measured and written down.** `go.mod` declares Go 1.24 while ML-DSA-65 needs
  `crypto/mldsa` (Go 1.27); the declaration stays (the hash chain, the Ed25519 tip and the writer build from 1.24) and
  `verifiers/go/README.md` now says what happens below 1.27, measured on 15/11/2026 with go1.24.13 and go1.27.0:
  tests pass on both; with a trusted ML-DSA-65 key a hybrid tip is FAIL (`pq_unverifiable`) on 1.24 and PASS on 1.27.
- **What the differential oracle guarantees, said as it is.** A comment of `verify.yml` said "a pack accepted by one
  is accepted by all, or the build fails" and the README "fails on any disagreement"; the oracle itself declares
  divergences by name and exact pattern (7 on a local run of 15/11/2026 with Python, JS and Go: e.g. `sig-broken`
  PASS for Python, FAIL for JS and Go; `hybrid-tip-bad-pq` FAIL for Python and Go, PASS for JS). Both texts now say
  that the build fails on any disagreement outside those declared cases, and name what they are.
- **`--version`, and `cryptovalid-verify` calls itself by its name.** Neither front-end had a `--version`, and the
  help of the installed command introduced itself as `verify_evidence` (measured 15/11/2026 on an installed wheel).
  `cryptovalid-verify --version` and `verifier.py --version` print the version on stdout (written whole or exit 74, like
  every output of these commands): from a source checkout the version in its pyproject.toml, said as such; otherwise
  the installed distribution's metadata; otherwise "unknown". `verifier.py`'s usage line no longer says
  `opencore/verifier.py`. `test_cli_version_20261115.py` (4 tests; all four fail on 0.24.0).
- **Seven tests on behaviours of `verifier.py` no suite observed** (`test_verifier_gaps_20261115.py`, proposed by
  Athena's review of 15/11/2026): brackets inside strings and after escapes, `\n` before hex digits, the receipt's
  `hash_recompute_passed` / `link_passed`, an untrusted or unreadable tip, a PQ key without a log key, the input of
  `receipt_sha256`. Each of 13 mutants that survived 26 suites in that review fails at least one of them
  (`--controls`: 13 of 13 killed, null control green); the reference is unchanged by them.
- **`verify_ledger` leaves the host's recursion limit as it found it.** Used as a library it raised the interpreter
  limit for its decoder and left it raised (1000 → 1796 after one call, measured 15/11/2026). The headroom now covers
  the whole call and the caller's limit is restored when it returns, on PASS, FAIL or an exception, from a 600-frame
  caller and from 8 threads at once; a higher limit the host set itself is kept. `test_verifier_host_process_20261115.py`
  (5 tests; on 0.24.0 four of them fail).
- **One rule for every URL the modules open (`cryptovalid_net.py`, core).** Measured on 0.24.0 (15/11/2026): five call
  sites passed any URL to `urlopen` (TSA client, NetHSM backend, EU trusted lists, Solana pruning probe, witness
  client), so `file:///etc/hostname` given as a TSA or trusted-list URL was read from disk; the AWS KMS endpoint check
  accepted `file://localhost/...`; and with `HTTP_PROXY` / `HTTPS_PROXY` in the environment every loopback endpoint (a
  local Vault, NetHSM, KMS emulator, TSA, witness, RPC) was asked through the proxy, which cannot reach this host's
  loopback and received the request (3 suites red behind a proxy). Now each caller names the schemes it accepts:
  https only (QEAS), https or http to a loopback host (Vault, NetHSM, AWS KMS endpoint), http or https (RFC 3161 TSAs,
  the trusted lists — on 15/11/2026 one of the 31 national lists the EU list of lists points to was http-only —, Solana
  RPCs, regulatory sources, witnesses: answers checked by signature or public data). Any other scheme, a URL with white
  space or a control character, without a host or with a bad port is refused with `url_not_allowed: <reason>` before
  any I/O; schemes compare case-insensitively (RFC 3986 §3.1). A loopback host is reached directly; any other host goes
  through the environment's proxy as urllib reads it, with an opener built per call. Redirects are followed only to a
  URL the same rule accepts (urllib alone follows one to `ftp:`) and never from a remote host to a loopback one.
  `test_net_rule_20261115.py`: 12 000 generated URLs against the rule written out independently, every call site
  refusing `file:`/`ftp:`/`data:` without I/O, a fresh interpreter started behind a recording proxy (nine call sites
  reach the loopback stub directly, a remote host still goes to the proxy; on 0.24.0 all nine went through the proxy),
  redirects. bandit `-ll`: the five B310 findings are gone.
- **Test children see the parent's packages.** `test_cli_c2sp_commands_20261115.py` and
  `test_cli_help_english_20261115.py` started their child interpreters with `-E -s` whatever the parent did: with
  `cryptography` installed by `pip install --user`, the parent found it and the children did not (3 failures, measured
  15/11/2026). The children now take `-E` / `-s` only when the parent runs with them, and the parent's user base when
  they get another HOME; a test checks that parent and child agree on `cryptography` (it fails with the old flags).
- **Every suite green without `cryptography`.** Without the `sign` extra 20 of the 66 suites broke instead of skipping
  (5 at import, 14 with errors, 1 with a failure; the same 20 on Python 3.9.25 and 3.11.2, measured 15/11/2026), and two
  suites (`test_ingest.py`, `test_tip.py`) decided that the library was present from `import signer`, which succeeds
  without it. The cases that need the library are now skipped with the reason "needs `cryptography` (the `sign`
  extra)"; with `CV_REQUIRE_CRYPTO=1` each of these suites exits non-zero when the library is missing, so the jobs that
  install it cannot pass on skips (with cryptography the skipped tests are the same 13 of 789 as before). The CI job
  without cryptography runs every suite and prints how many tests ran and how many were skipped (it ran only the
  witness suite). `test_dependency_versions.py` reads "from PyPI" in the README, as the README says since the entry
  "Install from PyPI" below (the test was red from that change).
- **No commercial offer.** The README offered "a commercial licence of the same code", while SECURITY.md declares the
  project non-commercial open source; it now states that no commercial licence, paid pilot or support contract is
  offered at present (free and open-source software, without warranty as the licence states). ECOSYSTEM_FIT.md welcomes
  pilots with real operators as non-commercial ones (no fee, no service contract).
- **Supply chain of the release, measurable by third parties.** `release-build.yml` builds the wheel and the sdist on a
  GitHub-hosted runner from the tag, with the build front-end and setuptools pinned by hash
  (`.github/build-requirements.txt`, `pip install --require-hashes`, `python -m build --no-isolation`), and signs SLSA
  build provenance for both files (`actions/attest`, Sigstore; SLSA v1.0 Build Level 2 per GitHub's documentation); the
  bundle is kept as `build-provenance.sigstore.json`. `gh attestation verify <file> --repo <owner>/<repo>` checks it.
- **CI hygiene.** Every `uses:` of the workflows is pinned to a commit SHA (the tag in a comment); the CI workflow runs
  with a read-only token (`permissions: contents: read`); `scorecard.yml` publishes the OpenSSF Scorecard result;
  `.github/dependabot.yml` proposes weekly updates of the pinned actions and the Python dependencies.
- **Licence metadata (PEP 639).** `license = "AGPL-3.0-or-later"` as an SPDX expression and `license-files` in
  `pyproject.toml` (setuptools ≥ 77); the wheel's METADATA carries `License-Expression` and the licence files.
- **Install from PyPI.** The README installs from PyPI; the index that links only the release files is named as an
  alternative. Private vulnerability reporting, which SECURITY.md names, is enabled on the repository (15/11/2026; it
  was off).

## 0.24.0 (2026-11-15)

- **`cryptovalid-verify checkpoint`, `tiles` and `vkey-rfc6962`; `auto` names them** (SPEC v0.7, §12 two rows added
  before the code). The commands of SPEC §13-§14 were only in `cryptovalid_checkpoint.py`, which has no installed
  command, and `cryptovalid-verify auto` answered "format not recognised" on a checkpoint and on a directory of tiles. The
  installed command now runs them with the code of `cryptovalid_checkpoint.py` (`checkpoint` is its `verify`; same
  output and exit status, compared argument by argument in the test), each with its own English `--help`. `auto`
  recognises a regular file of at most 1 MiB that is a signed note whose text is a checkpoint, and a directory holding a
  directory `tile` (after the pack and archive rows): it verifies nothing, since it has no trusted key, and its receipt
  (`kind` `checkpoint` or `tiles`, one SKIP layer, `valid` false, exit 1) names the command to run with the path.
  A note whose origin line is also a ledger's first line is refused as ambiguous. The command is named so that it runs as
  written: the path shell-quoted, and `./` before a relative path that starts with `-`. §12 names the control characters a note may not hold as c2sp.org/signed-note does: those below U+0020 other than newline (it said "control characters", while DEL and the C1 controls were, and are, accepted, as in golang.org/x/mod/sumdb/note). One of the three commands after
  `--` (`cryptovalid-verify -- checkpoint …`) is a usage error, exit 2. `test_cli_c2sp_commands_20261115.py`.

- **Tiles of C2SP tiled logs are read and checked; `cryptovalid_merkle.py` is core** (SPEC v0.7, §14 new; additive).
  `cryptovalid_merkle.verify_tiles` reads, from a directory laid out as the log serves it, the hash tiles of a tree
  (full and partial, a partial absent read from the full tile as both specifications allow), and the data tiles of a
  static CT log (c2sp.org/static-ct-api, TileLeaf with its leaf_index) or the entry bundles of a tlog-tiles log; every
  length is checked before the bytes it covers, the root from the level-0 tiles must be the checkpoint's, every upper
  tile present must agree with level 0, every entry must hash to its leaf. Refused with the reason: a missing level-0 tile
  or entry file, a link at a tile or at any directory under the given one, a tile of the wrong length, an unknown entry type or extension type, a duplicate or wrong leaf_index,
  bytes after the entries, more than one gzip member. `cryptovalid_checkpoint.py tiles <dir> --vkey ... --profile
  static-ct-api|tlog-tiles` verifies the checkpoint, then its tiles. The pre_certificate and certificate_chain of a data
  tile are outside every leaf hash and are read for their structure only (stated in SPEC §14). Vectors from
  FiloSottile/sunlight (ISC) in `testdata/interop/`: the skylight mirror (root of a tree of 300 from its tiles = the
  cosigned checkpoint) and the navigli2025h2 tiles (10 real precertificates). `test_c2sp_tiles_20261115.py`; with Go,
  `verifiers/tile_oracle` (golang.org/x/mod/sumdb/tlog, filippo.io/sunlight, filippo.io/torchwood) reads the same
  generated and altered directories. The module leaves the experimental list (README). A log pruned as tlog-tiles
  §Pruning allows cannot be checked: the whole tree is read from leaf 0 (SPEC §14, rule 6).
  `cryptovalid_witness.submit_checkpoint` refuses a log key that no witness verifies here (0x05 included) before the
  network round trip, as `verify_witnessed` does; with a 0x05 log key it reached the witness first.
  `cryptovalid_checkpoint.py verify` and `tiles` read the note from a regular file of at most 1 MiB, otherwise exit 2
  with the reason: a FIFO given as the note blocked the command, and `/dev/zero` was read until memory ran out (a
  MemoryError traceback and exit 1 under a 1.5 GB limit).

- **A final newline no longer passes two whole-string patterns.** In Python `re`, `$` also matches just before a newline
  that ends the string. `cryptovalid_kms.VaultTransitBackend.sign` matched Vault's answer with `^vault:v(\d+):(.+)$`
  and `.match`, so `"vault:v1:<base64>\n"` was accepted (measured with a stubbed answer); it now uses `fullmatch` and
  `\Z`, and such an answer is "unexpected Vault signature format". `cryptovalid_solana._HEX64` had the same form; there
  the digest is stripped of whitespace first, so a final newline never reached the check, and the pattern is changed the
  same way. An audit of every string with `$` in the modules found no other pattern used with `match`/`search`;
  the JS and Go verifiers match `$` at the end only and the Java timestamp pattern is applied with `matches()`.
  `test_regex_final_newline_20261115.py`; on the code before, 2 of its 3 tests fail.

- **Checkpoints of static CT logs verify (signature type 0x05); `cryptovalid_checkpoint.py` is core** (SPEC v0.7, §13
  new; not additive for `verify_note`). Until now a 0x05 vkey (the RFC 6962 key of a Sunlight or TesseraCT log) was
  ignored as an unknown key, so the checkpoint of such a log was NON_VALIDA, "no signature from a known key" — measured on
  2026-11-14 with the checkpoint of sunlight's test log rome2026h1 (5eed85d). Now the vkey (`0x05 || DER SPKI`, key ID
  over the RFC 6962 LogID, as c2sp.org/static-ct-api defines it) is read, the line's body (timestamp, hash and signature
  algorithms, length, signature) is read with each length checked first, and the ECDSA P-256 signature over the RFC 6962
  TreeHeadSignature is verified; a line that fails gives the reason (body shorter than 12 bytes, length field, algorithm,
  extension lines, origin other than the key name, signature). A 0x05 vkey whose key is not a canonical ECDSA P-256 key is
  refused (exit 2 on the command line). `cryptovalid_checkpoint.py vkey-rfc6962 --name <origin> --key-b64 <DER>` prints
  the vkey from a CT log list entry. `parse_vkey` now returns a 0x05 vkey whose key ID matches (with `strict=True` it
  raised "unsupported vkey type 0x05") and refuses one whose key ID does not (with `strict=False` it returned it
  unchecked). The module leaves the experimental list (README). Vector: the rome2026h1 checkpoint and
  log list entry in `testdata/interop/` (ISC, notice kept); `test_c2sp_static_ct_20261115.py` checks every body length,
  every bit of the real body, unknown types, refused vkeys and 300 notes signed with keys made in the test, and asks
  github.com/transparency-dev/formats (`verifiers/note_oracle`, which now opens 0x05 keys) on the same notes.

- **ML-DSA-44 note signatures with timestamp 0 are verified** (`cryptovalid_checkpoint.verify_note`). c2sp.org/tlog-cosignature
  lets an ML-DSA-44 signature over a subtree starting at 0 carry timestamp 0 ("may be zero or the current time"); 0.23.0
  required a timestamp of at least 1 and returned NON_VALIDA for a valid note. Found on 2026-11-14 with the checkpoint of
  FiloSottile/torchwood's litewitness ML-DSA-44 test (1c05157), which that witness accepts; the vector is now in
  `testdata/interop/` (BSD-3-Clause, notice kept) and in `test_interop_mldsa_timestamp_zero_20261114.py`, with negative
  controls (altered signature, timestamp 1, other tree size, timestamp 2^63). A zero timestamp is reported as 0, with no
  freshness; the witness still never emits one. Ed25519 cosignature/v1 is unchanged. In
  `cryptovalid_witness.verify_witnessed` an ML-DSA-44 witness line with timestamp 0 (a subtree cosignature over
  [0, size): it states consistency, not age) now counts toward `min_witnesses`, where 0.23.0 answered NON_VALIDA; with
  `max_age_s` it is never fresh.

- **Command line help in English.** `cryptovalid-verify --help` (and the same help after each of its commands) said
  "Un verificatore per TUTTA l'evidenza CryptoValid, offline" and listed the commands without saying what they take; it
  now describes each command and the exit status. The --help of `verifier.py`, `cryptovalid_heterogeneous.py`,
  `cryptovalid_reanchor.py` and `cryptovalid_worm.py` had Italian descriptions or option help, now English.
  `test_cli_help_english_20261115.py` runs --help of every top-level module that builds a parser, and of each command its
  usage lists, and refuses Italian letters and words (the detector is checked on the old texts first). The layer names
  and notes inside the JSON receipt of `cryptovalid-verify` are unchanged (still partly Italian): they are output that
  callers may match, and changing them is a separate, announced change.

- **`cryptovalid-verify auto` recognises by a closed list, or says "format not recognised"** (SPEC v0.7, §12 new; not
  additive for `auto`). Measured on 0.23.0 on 2026-11-14 with the release files of omega-cra-evol 0.10.0: on
  `cra_pack.json`, `sbom.cdx.json`, `cra_pack.json.sig.json` and `trust.json` (JSON documents of other kinds) `auto`
  answered `kind: "ledger"`, FAIL, with `json_decode` errors on its lines; on a binary file it ended with a
  UnicodeDecodeError traceback (exit 1); an AP2 or CLDMA document was recognised by a substring in its first 2048
  bytes. Now a directory is a pack (MANIFEST.json) or an ingest archive; a regular file is AP2 evidence or a CLDMA
  attestation when its whole content is one JSON object with their members, a ledger when its first non-blank line is a
  JSON object with `prev_hash` and `self_hash`; anything else, a pipe, an unreadable directory, a file that matches two
  rows, bytes that are not UTF-8 up to the first non-blank line or a byte order mark is `kind: "auto"`, `format not
  recognised: <reason>`, exit 1 (a later line of a ledger that is not UTF-8 is named by the ledger verifier). A document
  on one line is parsed once (a 60 MiB one-line JSON array was parsed twice: 3 GB peak, 1.6 GB now). The ledger in the
  same release is still a ledger and passes. `test_auto_closed_20261115.py`: the release files (SHA-256 pinned, in
  `testdata/interop/`), and 1500 generated inputs of every shape against an oracle written from SPEC §12; on the code
  before, 13 of its 16 tests that do not use a pipe fail (the pipe test blocks there).

- **`cryptovalid_tsa.verify_with_openssl` states what it checks** (registry item 21; behaviour unchanged). Measured on
  2026-11-15 with OpenSSL 3.0.22: it reads a whole TimeStampResp (a bare token is always False), hashes the data it is
  given, and validates the chain against /etc/ssl/certs at the time of the call, not at genTime: the replies of
  spec/vectors/rfc3161 that verify today fail with `-attime` 2100-01-01. Its docstring and SPEC §11 now say so;
  `test_tsa_verify_with_openssl_rule_20261115.py` pins the command line and the bare-token case.

## 0.23.0 (2026-11-13)

- **One check of an RFC 3161 token, read closed** (SPEC v0.6, §11 new; not additive: counts change). Measured on 0.22.0
  on 2026-11-13: a CMS blob signed with an RSA key made on the spot, whose content is only the OCTET STRING of the
  digest, gave `token_contains_digest` True and `verify_cms_signature` True; `cryptovalid_ingest verify` counted it in
  `timestamped_segments` with no warning (exit 0), `eidas_ledger_check.py` in `record_con_token_rfc3161` (REQ-7.5-04-bis
  PARZIALE), the inclusion receipt as `anchored: true`; and `cryptovalid_lotl.qualification` called a token qualified
  when it merely carried a QTST certificate. Now `cryptovalid_tsa.verify_token` is the one check, used by the ingest
  (seal and verify), `eidas_ledger_check.py`, `cryptovalid_receipt.py`, the rfc3161 domain of
  `cryptovalid_heterogeneous.py` and `cryptovalid_tsa.py`: the content must be a TSTInfo (id-ct-TSTInfo), read as DER in
  a closed form (unknown, repeated or out-of-order elements, non-minimal lengths, BER, a second SignerInfo are refused
  with a reason); the imprint compared is `messageImprint.hashedMessage` under a closed list of hash algorithms (SHA-1
  refused); the signature is checked by openssl; `genTime` is returned. A token counts as a timestamp only when it is
  verified against a TSA certificate the caller pins (`--tsa-cert`, new in `cryptovalid_ingest.py verify`,
  `eidas_ledger_check.py`, `cryptovalid_receipt.py inclusion`, `cryptovalid_tsa.py`) or, in the ingest with `--lotl`,
  when the certificate that signed it is a QTST certificate; otherwise the outcome says "signature valid with the
  certificate contained in the token, chain not established" and the token is not counted (ingest warning
  `tsa_chain_not_established`; `record_con_token_firma_senza_catena`; receipt `status: signature_only`,
  `anchored: false`). openssl absent: `not_evaluated`, never counted (until 0.22.0 the ingest counted the token on the
  digest's bytes alone, with a warning). openssl ended by a signal: a check not run (exit 74), as SPEC §10. The LOTL looks
  up the signer's certificate only. `token_contains_digest` now reads the TSTInfo instead of searching the bytes;
  `verify_cms_signature` and `verify_with_openssl` are no longer used here and keep their behaviour.
  Vectors: `spec/vectors/rfc3161/` — tokens of freetsa.org, DigiCert, Sectigo and GlobalSign requested on 2026-11-13
  (and a SHA-512 one), the certificates to pin, five negative tokens. Tests: `test_tsa_token_20261113.py` (the
  regressions fail on 0.22.0 by assertion; generative mutations of the real tokens), and the ingest, eidas, LOTL and
  report tests now build real TSTInfo tokens with a local openssl TSA where they used a CMS blob carrying the digest.
  With `--tsa-cert`, `cryptovalid_ingest.py verify` reports a token of another TSA as a failure
  (`tsa_token_not_issued_by_pinned_tsa`, exit 1); `eidas_ledger_check.py` does not count it. The inclusion receipt's
  `tsa` block drops `cms_signature_ok`, adds `status`, `gen_time` and `signer_sha256`, and keeps `token_b64` only when the
  token is not invalid. A `--tsa-cert` that is not a readable regular file of certificates is a usage error (exit 2).
  The SignerInfo is read too: signedAttrs required, its digest algorithm held to the same closed list (a token signed
  with SHA-1 or MD5 is refused); a critical TSTInfo extension is refused; a token without a certificate (certReq FALSE)
  is checked with the pinned one. The pack report (`cryptovalid_report.py`) no longer says "Token cryptographically
  verified" on the pack's imprint check alone: its RFC 3161 row shows the outcome of `verify_token` (until now a token of
  a TSA made on the spot, or with its signature altered, was shown VERIFIED).
  Not checked: revocation of the TSA certificate, `accuracy`, genTime against the entry's `ts`.
- **SPEC §3 on RFC 8785 corrected**: it said the canonical profile "is a strict subset" of JCS. Measured: the bytes are
  the same only when every character is in U+0000..U+007E; they differ for U+007F and any non-ASCII character, beyond
  the BMP the member order can differ too, and so does an integer that JCS writes as an IEEE 754 double (10^21, 2^53+1). The profile and every hash are unchanged. Vector
  `spec/vectors/canonical_vs_jcs.json`, test `test_canonical_vs_jcs_20261113.py` (two JCS encoders: one from the RFC
  rules, Node's `JSON.stringify`).
- `refresh_regulatory.refresh()` takes an optional timezone-aware `now`; `test_standard` no longer fails because of the
  calendar (it failed from 2026-11-12, 90 days after the oldest `as_of`). The command line still reads the clock.
- The core is narrowed to the evidence format and what cra-evidence relies on; every other module is marked
  experimental in its docstring (README, "Core and experimental modules"). No module, test or CI step was removed.
- README rewritten: problem, demo, proofs, core and experimental modules, guarantees and assumptions. The release
  history moved here.
- `cryptovalid_kms.py`: PKCS#11 signs with a single-part `C_Sign` on the module (pkcs11-tool 0.23 streams inputs over
  1024 bytes and EdDSA is single-part only), serialised with a lock and a timeout; the PIN buffer is zeroed also when
  the login fails. Backend URIs are read in a closed form: an unknown, repeated or empty key is a `ValueError`.
  Backends measured on 2026-11-08 against SoftHSM2 2.6.1, real AWS KMS and Vault 1.20 (logs not in this repository).
  Here the PKCS#11 path runs in `test_kms.py` and in the CI SoftHSM2 step; the tests written for the other changes are
  not in this repository.
- `spec/regulatory_profiles.json`: the eight entries re-read on their primary sources on 2026-11-12 (`as_of`
  2026-11-12, next review due by 2027-02-10); UAE_CBUAE `effective_utc` 2024-06-01 → 2024-08-31 (CBUAE Rulebook);
  each `source_url` is the page that was read.

## 0.22.0 (2026-10-19)

### The evidence pack receipt says what was checked; a claimed token that does not verify is a failure; small-order keys refused in the pack and the ingest (2026-10-19, 0.22.0)

Not additive: verdicts change (SPEC v0.5, §6 lists them; §10 is the receipt). The ledger format, its vectors and the six
ledger verifiers do not change.

- **The pack receipt names admission and states** (SPEC §10; the design of ap2-evidence-pack 1.6.0, aligned with
  draft-krausz-verification-state-03 §3.1, §3.3, §5.4.2, work in progress). `admission` is `admitted` or `refused`; a
  refusal has `refusal_class` (`format_unsupported`, `unknown_member`, `malformed`), `states: null` and its reason in
  `error`. An admitted pack has `states_vocabulary: "cryptovalid-evidence-pack/states-1"` and three subjects —
  `sealed_content`, `producer_signature`, `time_anchor` — each `{state, reasons, detail?}` with the precedence
  contradicted > instrument failure > other not evaluated > verified. `time_anchor` is never `verified`: this verifier
  binds the token to the manifest digest and does not check the TSA's signature (`tsa_not_checked`). `valid` is
  computed as before plus the changes below; how it relates to the states is written in §10 and checked on a generative
  bench (`verifiers/pack_states_bench.py`).
- **A claimed RFC 3161 token that does not verify makes the pack not valid** (the limit declared in 0.21.0): `anchored:
  true` with a token that is not a granted TimeStampResp for this digest, or with no token, is `valid: false`, exit 1
  (`time_anchor: contradicted`, `token_invalid` / `binding_mismatch` / `token_missing`). Until 0.21.0: `valid: true`,
  exit 0. A pack without a token, or whose token cannot be checked because openssl is absent, keeps its verdict.
- **A check that cannot run gives the whole receipt and exit 74.** openssl that cannot start, does not answer in time, or
  is ended by a signal while `evidence_pack.py verify` (or `cryptovalid-verify pack`) checks a token: the complete receipt
  on stdout with `time_anchor: not_evaluated / instrument_failure`, one line `check not run here: <reason>` on stderr,
  exit 74. Until 0.21.0 stdout was empty, and openssl ended by a signal was "token not verified" (the pack stayed valid);
  now that a token that does not verify fails the pack, a crashed tool must not read as a forged token. A receipt that
  cannot be written is still 74 with `receipt not written`. The MCP server returns that receipt (`check_not_run`) where
  it returned only an error string.
- **The manifest is read as a closed, typed object.** An unknown `pack_format` (1.0 included; until 0.21.0 the field was
  not read), a key written twice, and a field this verifier reads with a type `build_pack` never writes are refusals;
  until 0.21.0 `rfc3161_timestamp: []` or `ledgers: true` were a traceback (exit 1) and `anchored: "yes"` counted as a
  claim. The unknown keys of SPEC §2.1 are now `refusal_class: unknown_member` (same exit, same `valid: false`).
- **A ledger's signature layer is opened by any entry**, as SPEC §5 step 5 says: until 0.21.0 the pack checked
  signatures only when the first entry carried `signature`, so a ledger whose first entry was unsigned and whose second
  carried a signature that does not verify was valid. And a manifest that claims a post-quantum layer
  (`pq_protected: true`) for a ledger that does not carry it is not valid (it was valid, with `pq_reason: pq_absent`).
- **Keys and R of small or mixed order are refused in the pack manifest signature and in the ingest's tree-head
  signatures** (the second limit declared in 0.21.0; `ed25519_order`, the rule the ledger verifiers apply since 0.21.0).
  Measured on 0.21.0 on 19/10/2026: a manifest "signed" by the neutral point with R neutral and S = 0 — a signature that
  `cryptography` 50.0.1 accepts for any message under that key — was `manifest_authenticated: true`,
  and an ingest archive whose STH and HEAD carried that signature was `ok: true`, also with that key pinned. The signer
  is read as 64 lowercase hex characters and the signature as strict base64 of 64 bytes (both were read leniently).
- **`cryptovalid-verify ap2` needs ap2-evidence-pack >= 1.6.0** (the `ap2` extra; the floor CI job installs 1.6.0): it
  copies the reference's `admission`, `refusal_class`, `states_vocabulary`, `states` and `policy` into its receipt
  untouched and puts the refusal class first in the reason of the reference's layer. An `Ap2WriteError` that carries the
  reference's complete receipt (SPEC_AP2_EVIDENCE.md §6.10) would become this front-end's receipt and exit 74; 1.6.0 raises
  it only with `tsa_cert` or `trust_anchor`, which the front-end does not pass, so today that branch is not reached
  (measured 19/10/2026: openssl killed, absent or not answering leaves `cryptovalid-verify ap2` at exit 0 on a valid
  vector with a token, whose binding 1.6.0 reads without openssl). A pack with
  zero artifacts no longer passes the signature layer of the front-end (`all()` of nothing was true; the reference's own
  verdict already failed it). CONFORMANCE.md counted 8 ap2 vectors: there are 42 at v1.6.0.
- **Not done in 0.22.0, and why.** The states are not added to the six ledger verifiers: the design's table has no cell
  for a ledger, an unknown key there is a FAIL in normative vectors of six implementations rather than a refusal, and the
  verifiers do not perform the same steps (two do not check signatures, two do not check ML-DSA) — that needs its own
  pre-registered design. The ingest archive gets the small-order rule but no states, for the same first reason.
- **The receipts of `cryptovalid_receipt.py` refuse the same keys** (the JSON tree head `cryptovalid_sth/1` and the COSE
  receipts, formats of this project). Measured on 0.21.0 on 19/10/2026: the forged signature above was
  `signature_valid: true` for any tree head (`ok: false` without a trusted key, `ok: true` with the neutral point as the
  trusted key), and a COSE inclusion receipt re-signed that way was `ok: true` under that key; on one tree head, 13 of the
  14 encodings of points of small order were accepted as a trusted key with an R of small order and S = 0, and a key of
  mixed order (torsion of order 2) with a signature the library accepts. Now `signature_valid: false` / `ok: false` with the reason (`small_order_key`, `mixed_order_key`,
  `small_order_r`).
- **`evidence_pack.py build --tsa`**: openssl ended by a signal while it reads the TSA's reply is exit 74 and no pack (the
  0.20.3 rule for a check that cannot run while building); until 0.21.0 the pack was written unanchored.

## 0.21.0 (2026-10-17)

### A signature layer that does not verify is a FAIL; Ed25519 keys and R of small or mixed order are refused; Merkle leaves follow §3; a cut bytecode cache is compiled again (2026-10-14, 0.21.0)

SPEC v0.4. Every change below has a test that fails on 0.20.3, and the mutants we ran on its lines are killed by the tests (on
17/10 a review found five that lived — the neutral-point test reduced to x = 0 in JS and Go, the list of signature fields
without the ML-DSA ones in JS (two mutants) and Go — and a test now kills them: a key of mixed order whose torsion part has
order 2 or 4, a ledger whose signature layer is `signature_pq` alone or `signer_pq` alone). Receipts in
file mode: the 83 cases of the bench of 0.20.3 (the six verifiers and the Python commands) are identical to 0.20.3 on
Python 3.9, 3.11 and 3.13 (81 byte for byte, 2 by their own rule: generated keys); the bench sees a change made on
purpose (3 cases differ when `verifier.py` prints with another indent). On 458 ledgers of the development machine (every
one of the 2 880 of 12/10 whose text carries a signature field name, 58, and 400 drawn at random) the six verifiers give
the verdict and exit code of 0.20.3 on all; the receipts that change are 25 of those 58 files (FAIL in 0.20.3 and now), which now name the
signature layer or count it. What changes on purpose:

- **The signature profile (SPEC §5 step 5).** In the four verifiers that check signatures (JS, Go, Java, Swift) a
  signature layer that does not verify is a FAIL without `--pubkey` too, the failing entries named (until 0.20.3 the
  verdict was the chain's, PASS, and the failure only reported); the layer is any of `signature`, `signer`,
  `signature_pq`, `signer_pq` in any entry (until 0.20.3 only `signature`). A valid signature by an unknown key stays a
  PASS without a key: pinning the key is the caller's. `verifier.py` and the Rust verifier do not check signatures: their
  receipt now has `signatures_not_checked`, the number of entries carrying a signature field, only when it is not zero.
  ML-DSA-65: Go and Java verify it (a broken one is now a FAIL without a key too) when built with Go 1.27 or run on a
  JDK 24 or later; older ones declare the layer unverifiable (`pq_status: unverifiable`) and the verdict stays the
  Ed25519 layer's (PASS, exit 0, with a well-formed ML-DSA signature that does not verify), as before. JS and Swift count it,
  `pq_not_checked`. The matrix of 12/10 (9 cases, no key / right key / wrong key, six verifiers and `signer.py`) was rerun
  on 0.20.3 before the change and gave the same table. 21 vectors in `spec/vectors/signatures/` (`make_vectors.py`
  regenerates the same bytes): the six verifiers and `signer.py verify` reproduce all 21; the code of 0.20.3 differs on
  129 of the 147 results.
- **Ed25519 keys and R of small or mixed order.** RFC 8032 lets a verifier use either equation, and libraries differ
  outside the subgroup of order L. On the 12 classes of novifinancial/ed25519-speccheck rebuilt on ledger entries (our
  keys: the published cases sign other messages), 0.20.3 verified six with or without a pinned key in JS (Node), Go,
  Swift (swift-crypto) and `signer.py` (OpenSSL through `cryptography`) — a key or an R of small order, a key of mixed
  order, a key with x = 0 and the sign bit set — and four in Java. Now a key must decode as RFC 8032 5.1.3 says, not be of
  small order and lie in the subgroup of order L; R must decode and not be of small order (`small_order_key`,
  `mixed_order_key`, `key_not_decodable`, `small_order_r`, `r_not_decodable`), before the library's equation, for entry
  signatures and the signed chain tip, in the four verifiers, `signer.py` and `cryptovalid_tip.py` (`ed25519_order.py`,
  standard library); all 12 refused, as by the x402 acceptance checker of the same author. One scalar multiplication per
  distinct key, three doublings per signature. Not changed: the other modules that verify Ed25519 (receipts, checkpoints,
  witness, JWS, COSE receipts, SCITT, APS, Cedulon, the evidence pack's manifest signature, the ingest's tree heads) keep
  the library's rule (`cryptovalid_acta.py` already refused keys of small order).
- **Merkle leaves (SPEC §9).** A leaf is the canonical form of §3. Until 0.20.3 it kept `signature_pq`, `signer_pq` and
  `tsa_token`: signing a ledger with ML-DSA, or adding a timestamp token after a tree head, changed the root of entries
  already covered while the chain stayed PASS (`examples/sample_ledger.jsonl`: 95db8b0b... unsigned and signed Ed25519;
  with an ML-DSA layer or a token, a root that depends on their bytes — 264cbff9... and 67d223d0... in the run of 14/10,
  ML-DSA signing is hedged —; now 95db8b0b... for all four). The root of a ledger without those fields is
  unchanged; a tree head, checkpoint or receipt made by 0.20.3 for a ledger that carries them is reproduced by 0.20.3, not
  by 0.21.0 (vector `spec/vectors/merkle_leaves.json`, with both roots, computed by an independent RFC 6962 code).
- **LOTL: a QTST history out of order or with two entries at one instant is an error** (ETSI TS 119 615 PRO-4.3.4-03A;
  TS 119 612 5.5.10 orders the history by descending StatusStartingTime). Such a service is not counted and its
  certificates are named (`qtst_status_at`, `load_qualified_status`; the cache rule moves to /2, so a cache of 0.20.x is
  rebuilt); a token from it is `indeterminate` (`qualification()`), not "not qualified": the ingest warns
  `tsa_qualification_indeterminate`, the seal metadata carries `eidas_indeterminate`, the report says INCONCLUSIVE, the
  `cryptovalid_lotl` command adds `indeterminate` (only then). Until 0.20.3 the service was counted, the first entry of a
  tie taken (the same entry 03 b names). Measured: 39 services tie in their history on 26 national lists of 12/10 and on
  the 30 of 14/10 (one could not be fetched), none of them a QTST: the fingerprints are those of 0.20.3 at three instants
  (12/10, 14/10 and 2019-01-01: 652, 652 and 404 on the lists of 12/10; 1 081, 1 081 and 445 on those of 14/10). A tie between the ServiceInformation and one history entry is not
  03A: the ServiceInformation applies, as before.
- **A bytecode cache already cut is compiled from the source** (the rest of the 0.20.3 note on the cache, "it reads one
  that is there"). Measured on 0.20.3: `verifier`'s `.pyc` cut at any offset from byte 16 on made every command that imports it
  (all but `verifier.py` itself) exit 1, the code of a FAIL, on Python 3.9, 3.11 and 3.13 (3.13 writes no cut cache but
  reads one). Each command's guard now wraps the loader: an `EOFError` or `ValueError` from a cache is followed by a compile of the
  source. Cost: +0.2 to +1.4 ms per start (median of 20 runs, three commands, three Pythons);
  `sys.pycache_prefix = os.devnull` cost +26 to +47 ms (it recompiles the standard library) and is not used.
- **Declared.** An openssl that starts and is then killed by a signal, or a wrapper that exits 127, has answered: the
  token is not verified (`rfc3161.verified: false`), not "check not run" — an input that makes openssl crash does not
  become a check that did not run (the same in 0.20.3, now tested). The pack's `valid` does not depend on the timestamp,
  as before (a claimed token that does not verify leaves `valid: true`: RFC 3161 anchoring is optional). On macOS, read in the XNU
  source and not measured on a Mac (`vn_write`, bsd/vfs/vfs_vnops.c, xnu-12377.1.9): the file size limit is compared with
  the descriptor's offset, not the end of the file, so stdout appended (`>>`) to a file already past the limit takes a
  receipt that fits under the limit whole, exit 0 — the case the macOS job met on 13/10 — and a receipt that crosses the
  limit is cut and exits 74, as on Linux (the Swift suite asserts the first on macOS, the second everywhere).
- **The Kiva pre-registration** (`spec/PREREG_KIVA_20260820.md`) names reviewer roles instead of model names and no
  private note; the pre-registered bytes (SHA3-256 `db5671af...`, cited by the two validation reports) are that file at
  public commit `401e6b2`.
- **Found and not changed in 0.21.0 (planned for 0.22.0; done there, see the 0.22.0 section).** `evidence_pack.py verify` reports a declared RFC 3161
  token that does not verify (`rfc3161.claimed: true`, `verified: false`) and still returns `valid: true`, exit 0
  (measured 17/10/2026 on a pack of `examples/sample_ledger.jsonl` with a token that is not a TimeStampResp): the
  anchor is optional, but one that is claimed and fails is not yet a failure. The evidence pack's manifest signature and
  the ingest's tree heads, both formats of this project, still verify Ed25519 with the library's rule (see above); they
  will refuse keys and R of small or mixed order as the ledger verifiers now do.

## 0.20.3 (2026-10-13)

### An outcome that is not written whole is exit 74; promised files and ledger lines are whole or absent (2026-10-13, 0.20.3)

A defect present in 0.20.2 and before, in every command that prints a receipt. When stdout could not take the receipt
(a full disk, a reader that has gone, stdout closed), the verifier exited with the verdict's code and the receipt was
lost: measured on 0.20.2 (`>/dev/full`, `>&-`, `| head -c 0`, two runs each, a valid and a tampered ledger),
`verifier.py`, `cryptovalid-verify` and `signer.py` exited 0 or 1 with stdout closed and 120 (the interpreter's own
flush, "Exception ignored") on a full disk or a gone reader; the JS and Java verifiers exited 0 or 1 in every case, with
nothing on stderr; Go and Swift exited 0 or 1 on a full disk (Swift also with stdout closed) and died of SIGPIPE (141) on a gone reader; Rust panicked
(exit 101) on a full disk or a gone reader, and exited 0 or 1 with stdout closed (its runtime reopens descriptor 1 on
`/dev/null`). A script that reads only the exit code took a lost PASS for a PASS.

- Since 0.20.3 every command of this repository that verifies, records or signs evidence writes its outcome through one
  writer and only then chooses the exit code (not converted: the development and CI tools under `verifiers/` and
  `bench/` and the test files; `verifiers/closed_schema_mutants.py` on a full stdout still exits 120): when a byte of it was not taken it exits **74** (EX_IOERR in `sysexits.h`), whatever the verdict, and writes one
  line `receipt not written: <reason>` on stderr (if stderr fails too, the exit is still 74). The Python writer lives in
  `verifier.py` (which stays one stdlib-only file) and is imported by `cryptovalid-verify` / `verify_evidence.py`,
  `signer.py` and the 30 other modules with a `__main__`: `cldma_confidential`, `conformance`, `cryptovalid_acta`,
  `cryptovalid_checkpoint`, `cryptovalid_heterogeneous`, `cryptovalid_ingest`, `cryptovalid_jws`, `cryptovalid_kms`, `cryptovalid_lotl`,
  `cryptovalid_mcp`, `cryptovalid_merkle`, `cryptovalid_monitor`, `cryptovalid_pruning_probe`, `cryptovalid_reanchor`,
  `cryptovalid_receipt`, `cryptovalid_report`, `cryptovalid_scitt`, `cryptovalid_solana`, `cryptovalid_tip`,
  `cryptovalid_tsa`, `cryptovalid_witness`, `cryptovalid_worm`, `dora_incident`, `eidas_ledger_check`, `evidence_pack`,
  `fundcert_crosssource`, `mutation_runner`, `pedersen_commit`, `refresh_regulatory`, `tx_evidence`. The JS, Go
  (`cvverify`, `cvappend`), Rust, Java and Swift verifiers follow the same rule. Exit codes 0, 1 and 2 (and 77 where a
  command has it) keep their meaning when the outcome is written; the outcome itself is unchanged: on 83 commands run before and after with stdout on a regular file (the same inputs,
  folder and start time), the exit code and stdout are byte for byte those of 0.20.2 in 81, and in the other 2 (a new
  key, a measured duration) equal apart from that value.
- What the writer does. Python writes the bytes its stdout text layer would write to the byte stream below it, in a
  loop that checks every count, and flushes before the exit code is chosen; Rust, Swift and Java write descriptor 1 in
  such a loop; Node writes a regular file synchronously to its last byte; Go checks the error of its write. A
  non-blocking stdout that is full (a reader that reads late) is waited for as a blocking write waits (Python in
  `select`, Rust and Swift in `poll`, Java in sleeps of 1 to 50 ms). SIGPIPE and SIGXFSZ are ignored, so a gone reader
  and a file size limit are errors the program reads. Usage errors and refusals go to stderr through a write that never
  raises. Measured on 0.20.2 on 13/10 (a bench of real processes, Python 3.11.2; every case below is exit 74 with one
  line, or the whole receipt with the verdict's code, on this code): a non-blocking stdout read late cut a receipt
  larger than the pipe buffer, at 65 536 bytes when the pipe had filled before the reader came (65 536 or 65 537 in Swift,
  by timing; Java, read 1 s after its start, was still writing and lost the bytes past 1 151 646 of 1 438 366; Python 120, or 1 under `-u`; Java and Swift 1, the verdict's code; Rust
  101); a regular file with 24 bytes left under `ulimit -f` took 24 bytes and the code was the verdict's (JS, Go,
  Java) or 120 (Python), or the process was killed by SIGXFSZ (Rust, Swift); stdout opened read-only exited with the verdict's code in JS, Go, Rust,
  Java and Swift, 120 in Python; a usage error with stderr full, closed or its reader gone exited 120 or 1 in Python (with
  stderr closed the usage went to stdout), 101 in Rust (2 with stderr closed), and Swift was killed by SIGILL (`FileHandle.write`); with stderr's
  reader gone Go and Swift died of SIGPIPE; `--help` on a full stdout exited 120 (1 under `-u`).
  `cryptovalid_pruning_probe`, `mutation_runner` and `fundcert_crosssource` print their usage on stderr now (it went to
  stdout).
- **Files a command promises are whole or absent.** `verifier.py --out`, the signed ledger of `signer.py sign`, the chain tip, the monitor and witness state, the checkpoint and SCITT `--out` files,
  `cryptovalid_receipt.py --cose`, the `cryptovalid_acta.py` receipts, the evidence pack's files, the HTML/PDF report, the
  ingest STH and head, the LOTL cache, the regulatory profiles and the QEAS receipt are written to a new temporary file
  in the same folder, of a name nobody can predict (created with `O_EXCL`), fsynced and closed, then renamed over the
  path; on a failure the temporary file is removed, the file that was at the path stays as it was, and the command exits
  74. Measured on 0.20.2: `signer.py keygen` over an existing key under `ulimit -f 0` left the key at 0 bytes (exit 120);
  a symlink planted at the predictable `<tip>.tmp` or `<state>.tmp` was followed and its target overwritten (the tip, the
  monitor). A new key (`keygen`, and `keygen --pq`) and a WORM object are created through a temporary file and a hard link, never over
  an existing path, so they too are whole or absent. A path that exists and is not a regular file (`/dev/stdout`, a FIFO)
  is written directly, every byte. Over an existing file the command keeps what 0.20.2's `open(path, "w")` kept: a
  symlink at the path is followed (its target gets the file, the link stays), the existing file's mode is kept, and a
  file this process may not write (a receipt `chmod 444`) is refused and left as it was (exit 74; it
  was a traceback, exit 1). Changes of behaviour: `signer.py keygen` refuses a path where something already
  exists (a key, writable or not; with `--pq` also `<keyfile>.pq`; a symlink): one line on stderr, exit 2 (the code of a
  usage refusal), nothing written, the key left as it was; to replace a key, move or delete it first (0.20.2 replaced a
  writable key with a new one, exit 0, and refused a read-only one with a traceback, exit 1); the file at the path is a new file, so a hard link to the old one keeps
  the old content and the owner is the user who ran the command; a promised file in a folder this process cannot write is 74 even when
  the file itself is writable (no temporary file can be made there); an evidence pack is a folder: each file is whole,
  `MANIFEST.json` is written last, and a build that fails midway can leave copied ledgers without a new manifest (exit
  74; the pack verifies only with a manifest that matches).
- **A hash-chained ledger gets the whole line or nothing.** `cvappend` (Go), `cryptovalid_scitt.py register`, the
  witness's `.evidence.jsonl` and `.cosigned.jsonl` logs and the ingest writer's batches append with unbuffered writes in
  a loop and fsync; if a write or the fsync fails, the file is truncated back to the bytes it had, under the same lock,
  and the command exits 74 with a line that says nothing was recorded and the ledger is left as it was. Measured on
  0.20.2: `cvappend` under a file size limit exited 1 and left part of a line, which the next append refused as a torn
  last line (the chain could not continue); `cryptovalid_scitt.py register` exited 2 (`File too large`) and left 24
  bytes of a line. The ingest writer keeps
  a batch that failed queued, and a later `flush()` writes it whole. With `-tipkey`, a tip that cannot be written is 74
  and the line says the entry is in the ledger and the tip, if there is one, still names the previous entry. `cryptovalid_scitt.py register`
  refuses a directory as `--out` before it records anything; when `--out` cannot be written after the line is recorded,
  the exit is 74 and the line says the statement is registered (with its index) and only the transparent statement was
  not written. `cryptovalid_witness.py cosign` does the same for its `--out` and its state.
- **A check that cannot be run here is 74, never a verdict on the input.** When openssl cannot be started (fork refused
  under `ulimit -u`, no descriptor left) or the file it reads cannot be written (no usable temporary directory), `evidence_pack.py
  verify`, `cryptovalid-verify pack` and `archive`, `cryptovalid_ingest.py verify` and `eidas_ledger_check.py` exit 74
  with `cannot run openssl here: <reason>` or `cannot write a temporary file for openssl: <reason>` (measured under
  RLIMIT_NPROC 1 and under RLIMIT_FSIZE 0 with TMPDIR set); the same functions raise it to `cryptovalid_heterogeneous`
  and to `cryptovalid_receipt.py inclusion --tsa` (by code, not measured there). Measured on 0.20.2 under RLIMIT_NPROC 1,
  with a valid RFC 3161 token from a local TSA: `cryptovalid-verify pack` (a valid pack) and `cryptovalid-verify
  archive` (a valid ingest archive) said `valid: false`, exit 1; `evidence_pack.py verify` reported the token
  `verified: false`; `cryptovalid_ingest.py verify` and `eidas_ledger_check.py` exited 1 with a traceback. openssl absent stays what it was (the token is recorded, not
  verified). openssl that does not answer within its timeout (15 s for the evidence pack's token, 30 s for the CMS
  signature and for `openssl ts -verify`, which had no limit) is the same case, 74 with `cannot run openssl here: no
  answer within <n> s`, as in ap2-evidence-pack 1.5.2: a slow or loaded machine causes it. Measured on 0.20.2 and on the
  first 0.20.3 commits with an openssl that answers after 20 s: a valid pack `valid: false`, exit 1; after 35 s: a valid
  ingest archive `valid: false`, exit 1 (with the temporary file's path in the receipt) and `cryptovalid_ingest.py
  verify` a traceback, exit 1. `cryptovalid-verify ap2` treats ap2-evidence-pack's `Ap2WriteError` (1.5.2) the same way.
- **A command run under a file size limit no longer breaks the next run.** CPython 3.9 and 3.11 write a module's
  bytecode cache (`__pycache__/*.pyc`) with one raw write and install it even when that write was cut: measured on
  13/10 with `verify_evidence.py ledger` on a valid ledger from a source tree without a cache, one run under `ulimit -f 1`
  left a cut `verifier.cpython-311.pyc` (and `-39`), and every later run, without any limit, exited 1 with `EOFError:
  marshal data too short` (Python 3.13.15 installs no cut file). Since 0.20.3 every module above, when it runs as a
  command, sets `sys.dont_write_bytecode` before importing anything of this repository, so a command writes no bytecode
  cache (it reads one that is there). Not covered: a cache written by another program that imports these modules as a
  library, and the `cryptovalid-verify` entry point of an installed wheel (pip compiles the cache at install time).
- **Corrected with it.** The RFC 3161 domain of `cryptovalid_heterogeneous.py` read `.get()` on the boolean returned by
  `verify_with_openssl`: an `AttributeError` on every token, so that domain never verified (measured on 0.20.2 with a
  token from a local TSA). It now counts when `openssl ts -verify` succeeds: a verdict correction of the library function
  `verify_heterogeneous_anchor` — an anchor that needs that domain went from `ok: false` (the domain listed with
  `errore: 'bool' object has no attribute 'get'`) to `ok: true` when openssl verifies the token against `/etc/ssl/certs`
  (by the test, with openssl's answer simulated); a token openssl does not verify, or one whose TSA root is not in
  `/etc/ssl/certs` (measured with the local TSA), stays a failed domain. Not changed: from the command line the
  `token_der` of an attestation is a JSON string, not bytes, so the domain still does not verify there (library use only).
- **Declared limits.** Started with stdout closed (`>&-`), Node, Go and Rust reopen descriptor 1 on `/dev/null`: the
  write succeeds there and the program cannot tell (exit 0 or 1, as before); Python, Java and Swift see it and exit 74.
  A reader that closes the pipe only after the receipt fitted in the pipe buffer has received the bytes as far as the
  writer can know (with `| head -c 0` started together with a fast binary the writer can win the race; measured: Rust,
  exit 0 in one of two runs on 12/10). `cryptovalid_tsa.py` with a TSA it cannot reach is a traceback and exit 1, as
  before (now written by the stderr writer, so a full stderr keeps exit 1). `mutation_runner.py` rewrites the target
  source file in place to mutate it and restores it after each mutant (a development tool). `cryptovalid_lotl.py`
  (without a fresh cache), `cryptovalid_pruning_probe.py`, `cryptovalid_tsa.py` and `cryptovalid_solana.py` against a
  real network are converted but measured here only offline (LOTL with a fresh cache, Solana and the TSA with the
  connection refused). In process, after text the caller wrote to a `utf-8-sig` pipe, a receipt carries a second byte
  order mark (the command line never does). The CI's macOS job (13/10, run 38403932117) found one case that does not hold
  there: the Swift verifier with stdout appended to a file already 1 000 bytes long under `ulimit -f 1` exited 0 with
  nothing on stderr (with `ulimit -f 0` it exited 74, as on Linux); the cause is not established, and that case of
  `swift test` runs on Linux only. Windows and macOS are not measured: the waiting on a full non-blocking
  stdout uses `select`/`poll` (POSIX).
- Tests with real processes: `test_receipt_not_written.py` (12/10: /dev/full, a gone reader, stdout closed, for the
  Python commands and the Java verifier) and `test_receipt_design_20261013.py` (13/10, 17 tests: unbuffered under a file
  size limit, a non-blocking stdout read only once the pipe is full in Python and Java, usage and `--help` with stderr
  lost, the promised files, a symlink planted at the old temporary names, the two ledgers, the module commands, the
  check that cannot run with a local TSA, the bytecode cache, the shape of the Java wait), `verifiers/js/test.mjs` (a file size limit), `go test`
  (`cmd/cvappend`: a line truncated back, a tip not written, a planted `<tip>.tmp`), `cargo test`
  (`tests/receipt_write.rs`: usage with stderr full, a file size limit, a non-blocking stdout) and `swift test` (the same
  three). Each new test fails on 0.20.2: the 17 Python tests (Python 3.11), the 3 Go `cmd/cvappend` tests, the 3 Rust
  and 3 Swift tests and the 5 JS file-size checks (each run against the code and the binaries of 0.20.2). The review of
  0.20.3 added `test_outcome_review_20261013.py` (21 tests: a promised file over a read-only file, a symlink, a FIFO and an
  existing `.pq`, the existing file's mode, the evidence pack's copies; openssl that times out or cannot be executed,
  also in `evidence_pack.py build`; the SCITT `--out` before and after the line; fsync and a write(2) that takes 0 bytes
  made to fail through an LD_PRELOAD shim, which needs a C compiler; the wait on a full stdout without spinning; a reader
  that drips; the caller's own text first; one byte order mark per stream; an unexpected error with stderr lost;
  ap2-evidence-pack's `Ap2WriteError`; the RFC 3161 domain of `cryptovalid_heterogeneous`; an ingest batch that failed,
  written whole by the next flush), a witness test (`--out` refused before the state, a state that cannot be written is
  74), and native tests: Go (an fsync that fails, through seccomp; the tip next to a relative ledger), Rust (4), Swift (3;
  the tests that need `/dev/full` or Linux pipe sizes are skipped or fall back where those are absent, as on macOS), JS
  (3) and the Java wait (`TestJavaWaitShape`, the 17th test of `test_receipt_design_20261013.py`).
- **Measured on this code** (13/10/2026, Linux; Python 3.9.25, 3.11.2, 3.13.15; Node 22.23.2 and 24.19.0; Go 1.27.0;
  Rust 1.98.1; JDK 27; Swift 6.3.3). A bench of real processes over every command above (60 cases for `verifier.py`,
  `cryptovalid-verify`, `signer.py` and the JS, Go, Rust, Java and Swift verifiers; 48 for the module commands that run
  without a network), each with stdout on a file, `/dev/null`, a slow reader, a late non-blocking reader, `| head -c
  100`, `/dev/full`, a gone reader, `| head -c 0`, closed, read-only, a file size limit with and without room, a
  non-blocking reader that never reads, stderr working, full, closed or with its reader gone, and Python buffered and
  unbuffered: 1 886 + 2 208 cells on each Python, 0 cells where the outcome is lost or cut without exit 74, delivered
  with another code than the verdict's, or 74 without its stderr line; the same bench finds 931 + 1 324 such cells on
  0.20.2. The Python suites (50 files) on 3.9, 3.11, 3.13 and the declared floor (`cryptography` 48.0.0,
  `ap2-evidence-pack` 1.3.0), 50/50 each; JS 150–151 checks (the count moves with a random signature; Node 22 three
  times, Node 24) and `--conformance` 11/11; `cargo test` 17 tests and `clippy -D warnings`; `go vet`, `go test` and
  `go test -race`; `swift test` 25/25 (Linux); `conformance.py` 11/11; differential oracle 0/110 over the six verifiers (26
  declared divergences); `closed_schema_mutants.py` 1 500 mutations, seed 20261011, GREEN. 33 mutants of the
  changed lines (Python 21, Go 3, Rust 3, Java 2, Swift 3, JS 1: the loop on the count, the wait on a full stdout, the
  stderr writer, the temporary names, the truncation back, the 74 for a promised file, the check that cannot run and
  the bytecode cache among them) are each killed by a failing assertion of these suites, which pass on the copy without
  the mutant. The review of 0.20.3 wrote 44 more on the same lines (Python 21, Go 5, Rust 5, Swift 5, Java 4, JS 4): the
  suites above killed 7; with the review's tests 41 are killed, and 3 live: one equivalent (JS: the write callback
  ignoring its error while the 'error' listener stays, the same outcome in 88 of 88 cases), one that changes only how fast
  Java drains after a long wait, and one that differs only under a umask removing the owner's bits (the Go tip's mode);
  and 9 on the review's own lines, all killed. Windows and macOS: not measured here (the CI has a macOS job for Swift).
- **Corrected after 0.20.2.** The 0.20.2 notes said SPEC §6 lists the changes since v0.2 that turn a PASS into a
  FAIL and named three; a fourth is older: a ledger with zero entries is FAIL since 0.9.3 (2026-09-11; the JS
  verifier said PASS on it before). §6 now lists it, says that no verifier states the SPEC version yet (it said
  verifiers do), and the Merkle section, which also carried the number 6, is §9.

## 0.20.2 (2026-10-12)

### Swift reads a FIFO; `tsa_token` leaves the canonical form; the SPEC says who verifies signatures; the LOTL check reads the status in force (2026-10-12, 0.20.2)

Defects present in 0.20.1 and before: three found by the review of 0.20.1, one in the ingest found while correcting them,
the others in `cryptovalid_lotl` and `verify_archive --lotl` (found by a measurement of the EU Trusted Lists and by the
review of this release). One more, in `eidas_ledger_check`, the `tsa_token` change itself would have opened; it is closed
in the same release.

- **SPEC v0.3.** The SPEC header moves from v0.2 (2026-08-13) to v0.3 (2026-10-12). §6 lists the changes since v0.2
  that turn a PASS into a FAIL: the closed entry schema (0.19.0) and `idx` on every path (0.20.0), made without a version
  bump, and `tsa_token` outside the canonical form (0.20.2).
- **Swift did not read a FIFO.** `cvverify <(cat ledger.jsonl)` answered `FILE_ERROR`, exit 2, in the Swift verifier of
  0.20.1 and 0.20.0, while Python, JS, Go, Java and Rust read the bytes and gave the verdict. Swift now reads the file to
  its end through a file handle; a directory and a missing path stay `FILE_ERROR`, an empty file stays FAIL. The oracle
  case `input-fifo` (all six verifiers must answer PASS) is a disagreement with the Swift binary of 0.20.1; a `swift test`
  (FIFO, directory, missing path, empty file) fails when the 0.20.1 read is put back into the new function; the CLI line
  that calls it is covered by the oracle case and, on macOS in CI, by a FIFO gate.
- **`tsa_token` could not be what §2 said.** §2 defines it as an RFC 3161 token over `self_hash`, and §3 kept it inside the
  bytes `self_hash` is computed from. Measured with a local test TSA (`openssl ts`): a real token over an entry's
  `self_hash`, added after hashing, was FAIL in all six verifiers; with `self_hash` recomputed over the token, all six
  said PASS and the token no longer bound the entry's `self_hash`. Since 0.20.2 `tsa_token` is outside the canonical form,
  like the signatures, in the six verifiers and in `signer.py`: the first ledger is PASS in all six, the second FAIL. A
  ledger written with the token hashed as content is FAIL from 0.20.2 on. None was found: on 2 880 `.jsonl` files in four
  directory trees of the development machine, and on 126 more files carrying `self_hash` elsewhere on it (backups and
  copies), the six verifiers give the same verdict and exit code before and after the change on every file (1 527 PASS
  and 1 479 FAIL in each of the six; many of these files are not ledgers), no file was rewritten (sha256 before and
  after), and no line of them carries `tsa_token`, at the top level or nested (355 474 JSON objects). Two normative vectors fix the rule
  (`tsa_token_attached` PASS, `tsa_token_in_hash` FAIL at idx 1); four oracle cases check the verdict, not only the
  agreement; tests in Python, JS, Go, Rust and Swift fail on the code of 0.20.1. No verifier here checks the token itself
  (§5 step 6), and the SPEC now says so.
- **"Verified when present" was not true of every verifier.** Measured on nine three-entry ledgers (unsigned; signed;
  signed by another key; one signature changed, missing, malformed or without `signer`; hybrid; hybrid with one ML-DSA-65
  signature changed), with no key, the right key and another key: `verifier.py` and the Rust verifier verify no signature
  (a changed signature is PASS); `signer.py verify` refuses every broken, missing or malformed signature, with or without
  `--pubkey`; JS, Go, Java and Swift verify Ed25519 and report it, and the verdict depends on it only when a key is given;
  ML-DSA-65 is verified by `signer.py`, Go and Java, not by JS or Swift. SPEC §2 and §5 and `spec/CONFORMANCE.md` (which
  said Swift verifies no signature; it has verified Ed25519 since its first version) now say this. §5 also named
  `evidence_pack.py` as the implementation of step 6: it timestamps the pack's manifest digest, not entries. The
  verifiers' behaviour on signatures is unchanged: the 189 results of the matrix (verdict and exit code) are the same
  before and after.
- **The same list in the ingest.** Resuming a segment, `cryptovalid_ingest` recomputed `self_hash` leaving out
  `self_hash`, `signature` and `signer` only, so a segment whose entries carry `signature_pq`/`signer_pq` (or now
  `tsa_token`) was refused as tampered while the six verifiers PASS it. It now leaves out the six fields of §3; a test
  resumes both kinds of segment, refuses each one with its content changed, and fails on the code of 0.20.1.
  `cryptovalid_merkle` still builds its leaves leaving out the first three only (on a hybrid or timestamped ledger a
  change would change every root and receipt built with the current rule; on 2026-10-12 no ledger on the development
  machine carries `signature_pq`, `signer_pq` or `tsa_token`): not changed here, an open decision. SPEC §6 (Merkle) said
  the leaves are the canonical form of §3, and the module's docstring "the same rule as self_hash": both now say what the
  leaves are.
- **A withdrawn timestamp service counted as qualified.** `cryptovalid_lotl` took a `TSPService` as a qualified
  timestamp service when the text `Svcstatus/granted` appeared anywhere in it, its `ServiceHistory` included. ETSI TS
  119 612 puts the status in `ServiceInformation/ServiceStatus`, in force from its `StatusStartingTime`, and the earlier
  ones in `ServiceHistoryInstance` entries; ETSI TS 119 615 (PRO-4.3.4-03) reads the status at a date the same way and
  matches the certificate against the `ServiceInformation`'s digital identity. A service now counts when the entry in
  force is `TSA/QTST` and `granted`, with the certificates of its `ServiceInformation`. On 26 of the 30 national lists
  the LOTL points to (downloaded on 2026-10-12; PT and SI did not download then; CZ and DK below): 984 certificate
  fingerprints in 0.20.1, 652 in 0.20.2 (332 fewer, none added; 17 lists change). 634 of the 652 have `granted` in
  `ServiceInformation`; the other 18 are 18 services of one list whose `ServiceInformation` says `withdrawn` from a date in
  2027-2029 and whose status in force today is `granted`. A new function, `qtst_fingerprints_at(list, instant)`, gives
  the services qualified at a given instant (a token's genTime, which the caller supplies); `verify_archive`, the ingest
  anchor and `cryptovalid_report --lotl` check the status in force at verification time, or when the cache was built.
- **Two lists the LOTL names were not fetched.** The LOTL pointers were taken by a regex on locations ending in `.xml`:
  the Czech list (`TSL_CZ.xtsl`) and the Danish one (`TSLDK_v6xml`) were skipped, and with them 420 and 6 fingerprints of
  services granted today (measured on the lists of 2026-10-12). The pointers are now read from the LOTL as XML: every
  `OtherTSLPointer` whose MimeType is `application/vnd.etsi.tsl+xml`, the LOTL's own pointer left out — 31 locations (the
  30 national lists and the United Kingdom's last one, which has no granted QTST service).
- **The list parser was not closed.** A document type declaration was refused by a byte search for `<!DOCTYPE`, which a
  UTF-16 list passes: its entities were expanded (measured on Python 3.9, 3.11 and 3.13). TS 119 612 requires UTF-8 for
  XML trusted lists; a list that is not UTF-8 or that carries a document type declaration is now refused by the XML
  parser itself, in any encoding it declares. `StatusStartingTime` is read only in the form TS 119 612 §5.1.3 writes
  (`YYYY-MM-DDThh:mm:ssZ`): `datetime.fromisoformat` also took a value without `Z`, an offset or a fraction, and on Python
  3.11 and 3.13 three forms that 3.9 refused (`.5Z`, `20170301T000000Z`, a week date), so the same list could count a
  service on one Python and not on another. Every `StatusStartingTime` in the lists read on 2026-10-12 (29 national lists,
  PT missing, and the United Kingdom's) has the prescribed form: 9 888 of 9 888.
- **The fingerprint cache had no age.** The ingest keeps it in `~/.cache/cryptovalid` and read it whatever its age, so a
  set built on one day answered for every later day. The cache now records `built_at` and is rebuilt after 24 hours
  (`cache_max_age_s`); a cache of 0.20.1 (no rule) is rebuilt. In `verify_archive --lotl`, a LOTL that cannot be
  fetched or is not a trusted list is the warning `lotl_unavailable` and `eidas_qualified_segments: null`, not a
  traceback (a network error raised out of it until 0.20.1).
- **A presence counted as a timestamp.** `eidas_ledger_check` counted the entries carrying `tsa_token` (REQ-7.5-04-bis and
  the ledger report). With `tsa_token` outside the canonical form, `"tsa_token": "AAAA"` added to every entry of a signed
  ledger keeps every hash and signature valid, and turned REQ-7.5-04-bis from `NON_APPLICABILE` into `PARZIALE`. It now
  counts the tokens that carry the entry's `self_hash` as message imprint and whose CMS signature verifies
  (`cryptovalid_tsa`); the entries that only carry the field are reported apart (`record_con_campo_tsa_token`).
- Tests for each point (synthetic lists and ledgers, a local `openssl ts` TSA) fail on the code of 0.20.1, except the
  granted-today control, which passes there too.
- **Measured on this code.** Differential oracle 0/110 over the six verifiers (26 declared divergences, on signed tips);
  on the 0.20.1 code with the 0.20.1 Swift binary the same oracle counts 5/110. `conformance.py` 11/11; JS
  `--conformance` 11/11 and its suite 117–118 checks (the count moves with a random signature); Rust and Swift binaries 11/11 on `spec/vectors/`; `cargo test` 9 tests
  and `clippy -D warnings`; `swift test` 18/18; `go vet` and `go test`; the 48 Python test files on Python 3.9, 3.11
  and 3.13 and with the declared floor (`cryptography` 48.0.0, `ap2-evidence-pack` 1.3.0), 48/48 each;
  `closed_schema_mutants.py` 1 500 mutations, seed 20261011, GREEN over the six verifiers.

## 0.20.1 (2026-10-12)

### The six verifiers follow one acceptance profile; Swift aligned, defects closed in Python, JS, Rust and Swift (2026-10-12, 0.20.1)

- **The finding.** On 2026-10-11 the differential oracle, run with Swift for the first time, counted 12 Swift-only
  divergences: a valid surrogate pair refused; `+10`, `010` and a raw tab accepted; CRLF lines refused; `FILE_ERROR` on a
  file that is not UTF-8 (×2); five CLI forms answered with a verdict instead of a usage error. Swift had not been updated
  for the profile rules of 15–21/09.
- **The rule, not the case.** The Swift parser reads Unicode scalars (a Swift `Character` is a grapheme cluster: `\r\n` was
  one character, and String equality is canonical equivalence, so `é` and `e` + U+0301 were one key), applies the RFC 8259
  integer grammar, refuses raw control characters, reads `\u` as four ASCII hex digits, combines surrogate pairs and refuses
  unpaired ones, bounds nesting at 512, splits lines on LF only and FAILs a file that is not UTF-8. The CLI takes the ledger
  path first, `--algo sha256|sha3_256` and `--pubkey`, and answers anything else with a usage error (exit 2). The Ed25519
  fields are read strictly, as `signer.py` reads them.
- **Measured.** Oracle with Swift 0/106 (12/89 on 2026-10-11; `deep-valid-600` and `lone-surrogate` no longer declared;
  seventeen cases added on 2026-10-12 that only the rule can fail, on which the previous Swift code counts 23/106);
  `closed_schema_mutants.py` 1 500 mutations, seed 20261011, GREEN over the six verifiers; `swift test` 17/17, of which
  10 new tests fail on the previous Swift code (the eleventh, whitespace between tokens, passed there too).
- **Found by the review and closed the same day.** A raw non-UTF-8 byte hashed over Python's `surrogateescape` code
  point was PASS in `verifier.py` alone; a whole-number float (`1.0`, `0e0`) hashed as an integer was PASS in JS alone,
  and a leading UTF-8 BOM in JS (and in the Swift code of 0.20.0); an `idx` past 2^53-1 made JS throw without a receipt,
  and a JS receipt over 64 KiB was cut on a pipe; `--algo foo` was a PASS in JS and Rust; Swift's `--pubkey` did not
  enter the verdict (a wrong key, an unsigned or a partly signed ledger was PASS, exit 0). Each is now refused, with an
  oracle case or a test that fails on the code before. Rust also printed the `--algo` value into the receipt without
  escaping it, so a crafted value could add a second `verdict` key; JS accepted a signed chain tip that starts with a
  BOM, which Python, Go and Java refuse. Both closed.
- **Found by a second, independent review.** The JS float check added the same day skipped strings with a backtracking
  regex: 72 s on a 400 KB unclosed line of `\"` pairs (0.07 s before). It is now a linear scan, equal to the regex on
  2.4 million short lines and on 6 257 real and fuzz files, with a test that fails on the regex.
- **Chains.** Run before and after over the `.jsonl` files of the development machine (on 2026-10-12: the 2 820 under
  the working trees and the 138 other ledgers found in the home directory) and over new ledgers written by today's
  writers (`PersistentLedger`, the ingest, `signer.py sign`, `omega_evidence`, payloads with hard Unicode): the six
  verifiers agree on every file, the new ledgers are PASS in all six, and no file was rewritten (sha256 before and
  after). A PASS became FAIL in JS on three test files whose `idx` is a float (`0.0`, `1e0`), and in Swift on two test
  files whose `idx` is written `01`, all outside the format (SPEC §2, §3, RFC 8259); every Swift change (27 FAIL to
  PASS, 2 PASS to FAIL, 2 FILE_ERROR to FAIL) moved it to the reference's verdict, among them a real ledger of ours that
  the previous Swift code refused because of an emoji.
- **SPEC corrected.** §2 said `signature` is hex over the canonical form; `signer.py` signs the `self_hash` string (its
  UTF-8 bytes) and writes the signature in base64, and `signer.py verify` and the JS, Go, Java and Swift verifiers check
  it so (`verifier.py` and the Rust verifier do not check signatures). §2 (`signature`, `signature_pq`) and §5 step 5
  now say so, and §3 names the five attestation fields the canonical form leaves out, as every verifier does (it named
  three: `signature_pq` and `signer_pq` were missing). No behaviour changes with this text.

## 0.20.0 (2026-10-11)

### A ledger without `idx` is refused on every path; the ledger front-end names why (2026-10-11, 0.20.0)

- **The shortcut 0.19.0 declared is closed.** Until 0.19.0, with no `--algo`, a ledger whose first three entries carried no
  `idx` was read by a fallback for ledgers of other OMEGA modules (`mode: full_recompute_generic` or `linkage`), which
  applied neither SPEC §2.1 nor §5 step 4: an unknown top-level key passed there, not named. That path is removed from
  `verifier.py`. Such a ledger is now FAIL with or without `--algo`, as in the five other verifiers; the reference names
  each entry in `parse_errors` (`idx_mismatch: expected 0, got (missing)`; the receipt keeps the first ten), Go and Java
  name it `idx "" not sequential`, Rust and Swift carry no reason text. `evidence_pack.py verify` reports it as
  `hash_pass: false`. A ledger written by an earlier tool without `idx` no longer verifies here: it is not a ledger of
  this format.
- **The callers follow the verdict.** `eidas_ledger_check.py` (REQ-7.5-04, `catena_ok`) and `cryptovalid_monitor.py` read
  only the hash and link results: a ledger without `idx`, or with a key nobody defined (FAIL since 0.19.0), was
  `SODDISFATTO_PER_COSTRUZIONE` and green there. Both now use the verifier's verdict; the monitor's alert names the first
  reasons.
- **`idx_mismatch` says what was there.** The value is printed as JSON, and `(missing)` when the key is absent; Python and
  JS print the same text (except an object `idx` with integer-like keys, which JS orders first). Before, Python printed an
  absent key and `null` alike (`None`) and `"1"` like the number `1`; JS printed `undefined`, `null` and `1`.
- **`cryptovalid-verify ledger` names the reasons.** It printed `verdict=FAIL` only; the layer now carries `reasons`
  (hash, link, schema and parse failures, with idx — as JSON — or line) and the first three in `detail`.
- **The benches refuse a stale binary.** The differential oracle had measured a Rust binary built on 21/09, older than its
  sources, as if it were the tree's code. When the toolchain is on PATH the oracle rebuilds Rust (`cargo build`) and, if a
  Swift binary is present, Swift (`swift build`); the closed-schema bench does the same. Without the toolchain, the oracle
  refuses a Rust or Swift binary older than one of its sources (`src/`, `Sources/`), naming the file; the bench does so
  for Swift (it measures Rust only when `cargo` builds it). Tests and manifests are not sources: a
  touched test never relinks the binary, and `swift build` does not relink a source that is only touched.
- **Measured.** The two oracle cases `missing-idx-*` are FAIL in Python, JS, Go, Java and Rust: 0/89 disagreements, the
  two cases no longer declared. `closed_schema_mutants.py` (1 500 mutations, seed 20261011): GREEN over the six verifiers,
  Swift included; the same run with the 0.19.0 `verifier.py` is RED with 7 silent PASS, all `missing_idx` (positive
  control). The 12 older Swift divergences listed in `CONFORMANCE.md` are unchanged.

## 0.19.0 (2026-10-11)

### A field nobody defined is never silent: closed entry and manifest schemas, the entry rule in all six verifiers (2026-10-11, 0.19.0)

- **The finding.** Measured on 0.18.1 on 2026-10-10: a ledger entry written with a top-level key nobody defined (self_hash
  recomputed over it), a MANIFEST or `ledgers[i]` with an extra key, and an extra key in the unsealed `rfc3161_timestamp`
  block all verified PASS / valid with no trace in the receipt of the Python reference; on the entry case the JS, Go, Java,
  Rust and Swift ledger verifiers answered PASS too.
- **The rule, written first (SPEC §2.1), then applied everywhere.** The entry's top level is exactly the core and optional
  fields of SPEC §2; the MANIFEST, each `ledgers[i]` and the `rfc3161_timestamp` block are closed objects. A key outside the
  list FAILS and is named: `unknown_field:<keys>` in the reference's `schema_failures` (`manifest_unknown_field: …` for a
  pack). The five other verifiers, which verify ledgers, apply the entry rule: the same text in the Go and Java `failures[]`
  and the JS `schema_failures[].reason`, the entry in a `schema_failures_idx` list in Rust and Swift. `data`
  stays free (SPEC §4). Two normative vectors (`unknown_top_level_key` FAIL, `unknown_key_in_data` PASS).
- **Measured, not asserted.** The differential oracle: 0/89 disagreements over Python, JS, Go, Java and Rust (28 declared),
  with cases that require the reason text and the idx list to equal the reference's; `verifiers/closed_schema_mutants.py`:
  1 500 generated mutations GREEN over the six verifiers, Swift included, while on 0.18.1 the quick run (150) counted 32
  silent passes in each of Python, JS, Go, Java and Rust. Details and counts in `CONFORMANCE.md`.
- **Declared, not closed in this release.** When no algorithm is forced, a ledger whose first three entries carry no `idx`
  goes to the reference's fallback for ledgers of other OMEGA modules; when its hashes recompute there (receipt
  `mode: full_recompute_generic`), that path applies neither SPEC §2.1 nor §5 step 4: an unknown top-level key passes, not
  named, while the five other verifiers refuse the ledger. With `--algo` the reference applies the profile and names the key.
  The ledger receipt says which path it took (`mode`); the evidence-pack receipt does not: `evidence_pack.py verify` reports
  such a ledger as `hash_pass: true`, `valid: true`. Closed in 0.20.0 (section above). Also declared: the types of
  `ts` and `data` are not checked by any of the six; 12 older Swift divergences are listed in `CONFORMANCE.md`.

## 0.18.1 (2026-10-06)

### The Cedulon index stage checks refs and effect claims, as Verax's verifier does (2026-10-06, 0.18.1)

- **The index stage reads refs, and effect completeness.** Every ref an `index.jsonl` row names must be the ref of a
  decision the ledger holds, and a row that says its ref has an effect (`kind` `effect`, or `hasEffect` true) needs an
  effect row bound under that ref; a row's decision kind is not read, since `index.jsonl` is unsigned. Until now this
  checker held a row's decision kind to the ledger (a `deny` row had to name a deny record under that ref) and did not
  read `hasEffect`. Source: `indexStatement`, `effectRefsInIndex` and `noteEffectCompleteness` in verax-ai/verax
  `packages/proxy/src/verify-ledger.ts` and `parseIndexText` in `ledger-manifest.ts`, the same at `f59ece9` and at
  `e008f55`, and the stage table in `test-vectors/tools/stages.ts`, which files both of their problem lines ("index
  names …", "index says ref … has an effect …") under `index`.
- **Run against Verax's verifier** (`verifyLedger` at `e008f55` and at `f59ece9`, Node 22.23.2, 2026-10-06), on
  `valid-full` unchanged and with lines added to `index.jsonl` (one line in 18 cases, a line before a held row in 4),
  23 cases: the verdicts agree on 13, the unchanged ledger among them (on a line that is JSON `null` Verax's verifier
  fails without naming a stage). Where they differ, this checker fails and Verax's passes for a row that names no
  string `ref`, for a row with no string `piece` whose ref or effect claim fails here (Verax's parser skips such a row;
  this checker does not read `piece`, so a row with a held ref, no effect claim and no string `piece` passes both), for
  a duplicate member (`JSON.parse` keeps the last) and for a last line that is not JSON (Verax tolerates it as a
  half-written append when an earlier line parsed); Verax's fails and this checker passes for a line of spaces, or a
  lone `\r`, before the last, which this checker skips. Measured the same day beyond those 23: a line of other
  whitespace only (a tab, `\x0c`, U+00A0, U+2028) before the last splits the same way; an empty line is skipped by
  both; an integer of more than 4300 digits (Python's limit on converting an integer string) and arrays or objects nested
  more than 500 deep (below) fail here and pass there.
- **A line that is not JSON fails the stage that reads its file.** Until now such a line in `inputs.jsonl` or
  `index.jsonl`, a duplicate member or `NaN` included, was reported under `checkpoint-signature`; the verdict was
  INVALID either way. It now fails `inputs-binding` or `index`. A blank line is skipped, as before.
- **A line nested more than 500 deep fails the stage that reads its file**, on every Python. Until now `json.loads`
  raised `RecursionError` near 1000 levels on 3.9 and 3.11 and near 10000 on 3.13, so an `index.jsonl` line 5000 levels
  deep made the verdict INVALID (`malformed`) on 3.9 and 3.11 and VALID on 3.13 (measured 2026-10-06).
- **A line ends at `\n` only.** Until now `str.splitlines` also cut a line at U+2028, U+0085 and the other Unicode line
  boundaries, which JSON allows raw inside a string, so such a line failed as not JSON in any of the five files.
- **On verax-ai/verax `test-vectors/v1` at `f59ece9`** (the same setup as 0.17.2's run: checkpoint under the witness
  key; inputs, index and operator credentials given), measured 2026-10-06 with Python 3.9, 3.11 and 3.13 and
  cryptography 50.0.2: 20 of 20 verdicts and 16 of 16 first failing stages (0.17.2: 14 of 16; the checker is the same in
  0.18.0). `fail-allow-while-halted` and `fail-allow-while-halted-witnessed` now stop at `control`, as the vectors
  expect; every other verdict, stage and reason is unchanged. With `clock_skew_ms=0`, 15 of 16: `fail-allow-while-halted`
  stops at `effect-binding` (`decision-without-effect`), since no allowance defers its forged allow, as in 0.17.2. The
  positive control (one bit of a record signature flipped in `valid-full`) fails at `record-signature`.
- `test_cedulon.py` (19 tests) holds the index stage to seventeen bent ledgers that must fail it (five of them
  by their reason) and eleven that must pass it, every file to a line that is not JSON, and a line nested past 500
  levels to one verdict on every Python; 41 mutations of the index stage, the line loader and the depth check each turn
  it red on Python 3.9, 3.11 and 3.13.

## 0.18.0 (2026-10-05)

### One copy of the AP2 verifier (2026-10-05, 0.18.0)

- **One copy of the AP2 verifier, in ap2-evidence-pack.** Until 0.17.2 this wheel and ap2-evidence-pack installed the
  same two paths, `ap2_evidence.py` and `pqcrypto/sigsuite.py`; pip overwrote them silently in the order of installation
  and uninstalling either removed them for the other (measured 2026-10-04). The copy here had fallen behind the
  reference: measured 2026-10-05, a pack built with `python3 ap2_evidence.py build` from a 0.17.2 clone is refused by
  ap2-evidence-pack 1.2.2 and by its JS verifier (`honest_scope does not match the canonical scope of this
  evidence_format (SPEC §1)`), and the copy lacked the strict JSON loader, the regular-file check, the x5c chain and the
  RFC 3161 token walk. 0.18.0 ships neither file: `cryptovalid-verify ap2` and the MCP tool import `ap2_evidence` from
  ap2-evidence-pack >= 1.3.0 (extra `ap2`); the two wheels installed together share no path (RECORD intersection 0,
  measured). `ap2_evidence.py`, `pqcrypto/`, `test_ap2_evidence.py`, `test_ap2_shape.py`, `test_ap2_conformance.py`,
  `spec/vectors/ap2/` and the copy of `SPEC_AP2_EVIDENCE.md` are gone from the clone: the normative text and the vectors
  are ap2-evidence-pack's. The documented `python3 ap2_evidence.py build|verify` commands become `ap2-evidence
  build|verify` (the package's console script).
- **The reference's refusal reason reaches the receipt.** `verify_ap2` read `error` from the old copy's receipt; since 1.1.0 the
  reference's receipts carry `refused`, so a refused pack was a FAIL with an empty detail (measured on a too-deep pack and on a
  pack with a non-canonical honest_scope). The last layer now carries it; two tests cover it.
- **`sign` extra: `cryptography >= 48`** (was >= 50): the floor where ML-DSA-65 works (47.0.0 raises
  UnsupportedAlgorithm).
- **`cryptovalid-verify auto` recognises an AP2 pack whose `evidence_format` is past the first 2048 bytes.** A pack is
  one JSON object with sorted keys, so `artifacts` comes first: measured 2026-10-05, a valid pack built by `ap2-evidence
  build` 1.3.0 from two mandates has `evidence_format` at byte 3506, and `auto` verified it as a ledger and said FAIL.
  `auto` now reads the top-level `evidence_format` of a JSON object file; a test builds a pack where it sits past
  byte 2048.
- **The versions of linked projects are written once.** pyproject.toml holds the `ap2` range (ap2-evidence-pack
  >= 1.3.0, < 2) and the `sign` floor; `test_dependency_versions.py` fails when the CI or the README says otherwise, and
  the floor job installs both minimums exactly, so every run shows they exist on the index and work. A weekly scheduled
  run installs the newest ap2-evidence-pack 1.x.

## 0.17.2 (2026-10-05)

### The core's boundary allowance in the Cedulon checker (2026-10-05, 0.17.2)

- **`cryptovalid_cedulon.verify_ledger` applies the boundary rule** that decision-profile-03 takes unchanged from the
  core (cedulon-08 §11.4 step 5, MUST-T10-17; core-03 §12.1 step 5): an allow with no effect row within `clock_skew_ms`
  of the newest attested record, and an effect row that no record names within `clock_skew_ms` of the oldest, are listed
  under `boundary_deferred` and do not fail the verdict; a VALID result with a deferral says so in `why` ("boundary-
  deferred, so the guarantee is conditional"). A count shortfall under a ref that has a row stays a finding. The default
  is 300000 ms, the five minutes the profile names. The profile does not say which edge applies when every effect row
  carries its own one-millisecond extract; this checker reads a one-ledger audit, whose edges are the oldest and the
  newest record: for the closing edge, the reading Verax's own verifier takes since `f59ece9`; Verax applies no
  opening-edge allowance (a row no record names is a finding there), the core's rule has one, and this checker applies
  it. A ledger shorter than the allowance therefore defers every unmatched allow and every unnamed row it holds.
  `clock_skew_ms=0` applies no allowance. 0.17.1 applied none.
- **On verax-ai/verax `test-vectors/v1` at `f59ece9`** (20 vectors; checkpoint under the witness key; inputs, index and
  operator credentials given), measured 2026-10-05: 20 of 20 verdicts and 14 of 16 first failing stages, as with 0.17.1;
  with `clock_skew_ms=0` every verdict, stage and reason equals 0.17.1's (the output gains the key `boundary_deferred`,
  empty there). The forged allow of `fail-allow-while-halted` is now deferred (30 ms from the newest record; it is also
  30 ms after the halt extract's `windowEndMs`, the edge the vectors README measures from) instead of failing
  `effect-binding`. Every ledger in the set spans at most 203 ms, so at the default no unmatched allow or unnamed row in
  it can reach `decision-without-effect` or `effect-without-decision`; the two edges are measured in `test_cedulon.py`.
  `fail-allow-while-halted` and `fail-allow-while-halted-witnessed` expect `control` and stop at `index`, because this
  checker reads an index row by its kind as well as its ref (the index names a deny the ledger no longer holds: the
  record under that ref is now an allow); Verax's verifier compares refs, and effect completeness (corrected 2026-10-06,
  see above). Run without the index stage, both stop
  at `control`.
- `test_cedulon.py` tests both edges at the exact allowance and one millisecond past it, that 0 applies none, also on
  the edge itself, and that a count shortfall is not deferred; nine mutations of the rule, listed in the test, each turn
  it red. A comment in `cldma_confidential.py` no longer names a module outside this repository (`ff1bd73`, on `master`
  since 2026-10-05; 0.17.2 is the first release that carries it).

## 0.17.1 (2026-10-04)

### What the wheel ships (2026-10-04, 0.17.1)

- **AP2 verification works from a pip install.** `ap2_evidence` imports `sigsuite` from `pqcrypto/`, which the 0.17.0
  wheel did not contain: installed from the index, `cryptovalid-verify ap2` and the MCP tool
  `verify_ap2_evidence` failed on every file with `ModuleNotFoundError: sigsuite` (a refusal, never a pass). The wheel
  now ships `pqcrypto/`. From a clone nothing changes.
- **`cryptography` is declared, as the `sign` extra.** The wheel declared no dependency, so a plain install had no
  signature layer. `pip install 'cryptovalid-opencore[sign]'` installed `cryptography` >= 50, the version 0.17.1 was
  measured with (0.18.0 lowered the floor to 48.0.0) (ML-DSA-65 itself works from 48.0.0: generate, sign and verify measured with 48.0.0, 49.0.0 and 50.0.1;
  47.0.0 ships the `mldsa` module but raises `UnsupportedAlgorithm`). The hash-chain verifier still needs only the
  standard library, so the extra stays optional.
- **Eleven file and URL handles closed.** Eleven `open()`/`urlopen()` calls in shipped modules did not close what they
  opened (one wrote a cache file through an unclosed handle); each is now a `with` block. The two long-lived segment
  handles of `cryptovalid_ingest` are closed on rollover and in `close()` (see below for the one path that missed).
- **`pqcrypto/sigsuite.py` is the code of ap2-evidence-pack 1.2.2** (byte-identical except its first lines: there a
  three-line Apache-2.0 header and a one-line title, here this repository's one-line title). The copy shipped here was older: it did not refuse
  small-order Ed25519 keys (with the identity key, R=identity and S=0 verified on every message — the forgery measured
  2026-09-25 and closed in ap2-evidence-pack 1.1.0/1.2.x), it decoded base64 leniently and it crashed on a non-object
  signature entry. `test_ap2_evidence.py` carries the small-order test; on 0.17.0 it fails.
- **Same files as ap2-evidence-pack: install one of the two per environment.** Both wheels install `ap2_evidence.py` and
  `pqcrypto/sigsuite.py`; pip overwrites them silently in the order of installation (`pip check` says nothing) and
  uninstalling either package removes them for the other (`ModuleNotFoundError: ap2_evidence`, measured 2026-10-04 with
  1.2.2 and 0.17.1). Their `ap2_evidence.py` still differ (1.2.2 is ahead); unifying them is open.
- `test_ap2_evidence.py` had two `if __name__ == "__main__"` blocks: run as a script (as the CI does) it stopped after
  the first one and 13 of its 27 tests never ran; they run now. One of them, `test_kb_tampered_sd_hash_refuses_build`,
  tampered the `sd_hash` by setting its first character to `X`, a no-op whenever the digest already began with `X`
  (1 run in 64; measured 2026-10-04: 1 failure in 200 runs, 0 in 200 after the fix); it now puts a character that
  differs from the real one.
- `cryptovalid_ingest.Ingestor.close()` closes the segment handle also when `seal()` raises (a signing backend that
  fails); before, that handle stayed open with no call left to close it.
- `test_packaging.py` gains three tests, one per point, read from `pyproject.toml` and the shipped sources; on 0.17.0
  each of the three fails.

## 0.17.0 (2026-10-04)

### Four clean-room verifiers, an audit of the verifiers, and RFC 3161 marks only for a granted token (2026-10-04, 0.17.0)

- **RFC 3161: `anchored: true` only for a granted token for this digest.** `evidence_pack._rfc3161_stamp` recorded any HTTP
  body as `anchored: true` — an error page, a rejection, a token for another digest. It now records a mark only when the
  reply's status is granted (0 or 1, both carry a token) and the token's message imprint is the requested digest;
  `test_stamp_tsa_locale.py` builds a local TSA with openssl and fails on 0.16.2 for each wrong reply.
- **Audit of the verifiers (thirteen defects: twelve fixed in code, each with a test that failed on the code before the fix; the thirteenth settled in the tip spec and pinned by a test).** `verify_evidence` no longer passes
  a signature that is present but broken (pack and AP2 producer); `verifier.py`, `signer.py`, `cryptovalid_receipt`,
  `cryptovalid_ingest.verify_archive` and `evidence_pack.verify_pack` answer a non-object line, an unreadable HEAD/STH or
  a malformed MANIFEST with a named failure instead of a traceback, and file names outside the pack are refused before
  they are opened; tree sizes and leaf indexes are strict unsigned integers (`true`/`false` refused) in the SCITT and COSE
  readers; JWS and AP2 base64url is strict (RFC 7515: no padding, no standard alphabet, no whitespace, canonical trailing
  bits); the JS verifier decodes signature and signer as strictly as Python and Java, and with `--pubkey` a bad signature
  is FAIL with exit 1; the tip spec states what all verifiers do with `log_pubkey_hex: null` (absent).
- **AP2 evidence of the wrong shape is a refusal receipt**, not a `TypeError`/`AttributeError` (`test_ap2_shape.py`).
- **`cryptovalid_receipt` compares the declared `vds` and `sth.kind`** instead of ignoring them (`test_receipt_identifiers.py`).
- **`cryptovalid_merkle.consistency_verdict`** gives three outcomes — consistent, inconsistent, could not compare (sizes
  out of range); `verify_consistency` is unchanged.
- **Four new modules**, read from the published texts and the IETF AUDIT BoF vector exchange: `cryptovalid_cose_receipts`,
  `cryptovalid_cedulon`, `cryptovalid_aps`, `cryptovalid_vaara_receipt` (see the module table). Measured on 2026-10-04
  against the frozen vector sets: scitt-cose `vectors-ietf126` @`529515ba` 6/6 as RFC 9942 receipts (3/6 with the RFC 9943
  §6 header MUSTs applied); Verax `test-vectors/v1` @`f50c59b`, all stages, checkpoint key =
  the witness key, 16/16 verdicts and 15/16 first failing stages; APS `aps-conformance-suite` @`5500a56` canonical bytes
  18/18, `accountability-record` 12/12, `actionref-canonical` 4/6 against the -01 form; Vaara `tests/vectors` @`ff683c2`,
  only the RFC 9162 proofs and the ML-DSA-65 signatures, 10/10, 7/7, 10/10.
- `test_stamp_tsa_locale.py` closes the files it opens; two source comments no longer name modules outside this repository; the JS README says 93 checks; the stale
  `cryptovalid_opencore.egg-info/` is no longer tracked.

Measured before the tag: 48 of 48 test files on Python 3.9.25, 3.11.2 and 3.13.15, `pqcrypto` 2/2, `conformance.py`
exit 0, the JS verifier 93/93; the Go, Rust, Java and Swift jobs and the differential oracle are measured by the CI run on
the tagged commit.

## 0.16.2 (2026-09-26)

### Vendored key-window vectors restored to the upstream bytes (2026-09-26, 0.16.2)

- **The vendored key-window vectors are now the upstream bytes.** `examples/acta/key-window/SOURCE.md` said the eight
  files were "copied verbatim" from ScopeBlind/agent-governance-testvectors at `1e24b5687`. Compared byte for byte with
  that commit on 2026-09-26, each copy shipped in 0.16.0 and 0.16.1 lacked the file's final newline (one byte); the
  JSON content was identical, so no verdict changes: 6/6 on verdict, `code` and `key_status`, both before and after.
  The files now carry the upstream bytes and `KW_SHA256` pins them; removing the final newline from one file makes the
  pin test fail. The re-fetch recipe in `SOURCE.md` is replaced: the previous command does not run (`gh api` 2.92.0
  rejects `--ref` as an unknown flag, exit 1). The new recipe, run on 2026-09-26, reproduces the eight files byte for
  byte.

## 0.16.1 (2026-09-26)

### OpenTimestamps anchoring in a public install (2026-09-26, 0.16.1)

- **`committed_attestation.anchor_commitment` works in a public install.** From its introduction (0.9.0) through 0.16.0
  it imported a module that is not part of this repository. 0.16.0 installed from the index in a clean virtualenv, run
  with an isolated Python (`-I`), answers `ok: false`, "No module named 'core'" (measured 2026-09-26). It now uses the
  public OpenTimestamps library (python-opentimestamps, LGPL-3.0) as an optional dependency:
  `pip install cryptovalid-opencore[ots]`. Without it the answer is `ok: false` with an `error` that names the missing
  library; with no calendar reachable it is `ok: false`, `status: "failed"`, and `errors` says per calendar what went
  wrong; a root that is not 32 bytes is `ok: false` with an `error`. The return value keeps its fields; `errors` is
  new, and a new `calendars` argument replaces the library's default calendars (an empty list means no calendar).
  Measured 2026-09-26, with this code built as a wheel and installed with `[ots]` and `cryptography` in a clean
  virtualenv, isolated Python: the function committed on 4/4 calendars — `https://a.pool.opentimestamps.org`,
  `https://b.pool.opentimestamps.org`, `https://a.pool.eternitywall.com`, `https://ots.btc.catallaxy.com`. In the same
  install, the test file run against the installed module passed 14/14 with the live test enabled; that test decodes
  each returned proof as an OpenTimestamps Timestamp rooted at the commitment hash (the message is an input to the
  decoder, not carried by the proof) and checks that it holds at least one attestation and that every attestation is
  pending (not yet Bitcoin-confirmed). Upgrading a proof to a confirmed one is not part of this function.
  Tests: two new offline ones — one without the library, one with a stand-in calendar that has three entries:
  committed, unreachable, and answering for another message (a defensive guard: with python-opentimestamps 0.4.5 the
  message is set from the digest we pass, so it cannot trip there) — and one live test, reported as skipped unless
  `CV_ONLINE_OTS=1`. Removing the message guard or the per-calendar error handling turns the offline tests red.
- `test_cryptovalid_acta.py` closes the PEM/DER key files it writes (a `ResourceWarning` in the 0.16.0 CI log).
- A source comment in `cryptovalid_acta.py` said Arabic-Indic and fullwidth digits were accepted "up to 0.16.0";
  0.16.0 refuses them, and they were accepted by 0.15.1 and by the untagged `8de0b72` (measured 2026-09-26).

## 0.16.0 (2026-09-26)

### Key status, refusal codes and strict inputs (2026-09-26, 0.16.0)

Code: `cryptovalid_acta.py` and its tests; the other modules are unchanged since 0.15.1 (the README, the packaging
metadata and the vendored key-window vectors also change). The public master already carried part of this work as
`8de0b72` (25 September, version string 0.16.0, never tagged or released); this is the release. The "before" figures
below are measured on 2026-09-26, unless dated otherwise, on that commit and on the 0.15.1 tag, with the author's probe scripts (not part of this
repository). This release also removes `.nocrypto_test/`, a test virtualenv skeleton (activation scripts, interpreter
and lib symlinks and a `pyvenv.cfg` naming a local path; no packages) that the repository had carried by mistake since the
0.14.0 release commit (`c12d847`, 19 September). Tests: `test_cryptovalid_acta.py` 51/51 with `cedarpy` and
`cryptography` installed (one test is skipped without `cedarpy`).

**Key status is always stated (§5.5).** Every verification outcome — the library's result, and the CLI's output on
exit 0, 1 or 77 — carries `key_status` and a machine-readable `code`; a refusal at load (exit 2: an unusable key set, key
file or input file) reports only `ok: false` and `error`. `key_status` is one of `not_reached` (the receipt was refused
before the key set was consulted — the default, because saying anything else would assert what was not measured),
`unknown_key`, `no_window`, `inside`, `outside`, `undecidable`. `code` is `null` or one of `key_outside_validity_window`,
`key_window_undecidable`, `key_not_supplied`, `issuer_not_trusted`, `key_material_invalid`, `signature_invalid` (the
signature does not verify under the key) and `signature_in_signing_input` (a payload that carries a `signature` member,
§6.6); every other refusal — a malformed envelope, a `sig` that is not lowercase hex — carries its reason in `why` with
`code` null. On `8de0b72` a signature with one bit flipped and a payload carrying `signature` both came back with `code`
null.

**Small-order keys.** A relying-party Ed25519 key that is a point of small order is unusable key material: with such a
key anyone can forge a signature on any message. An invalid or non-canonical encoding (y >= p, or the sign bit set with
x = 0) is refused too, because it does not name one point unambiguously; no forgery is claimed for it. With the identity as key, R=identity and S=0 verifies on every message. With a small-order
key of order n (2, 4 or 8), pick S, guess g = k mod n, set R = [S]B − [g]A and retry until k = H(R‖A‖M) matches the
guess: each try succeeds with probability about 1/n. Measured 2026-09-26 with the probe's own curve arithmetic and
OpenSSL (Python `cryptography`) as the verifier: a signature on a message of the forger's choice verified for all 8
small-order keys, after 1 to 16 tries; the same construction against an ordinary key verified 0 times in 2000 (null
control). Measured 2026-09-25: a receipt forged with R=identity, S=0 against the identity key passed.
`--key`, a key file and `--jwks` refuse such a key at load (exit 2); the library returns
`not_assessed` with `code: key_material_invalid`. The check is curve arithmetic (canonical decoding, then [8]P is not the
identity). Measured 2026-09-26 on the check itself: the 8 distinct small-order points (computed with the probe's own curve
arithmetic, not the library's, as the torsion part of random points), the 2 encodings with the sign bit on x = 0 and 4
encodings with y >= p are all refused, and an ordinary key is accepted; through the CLI, the identity key is refused at
load given as a `--key` hex argument, as a key file (hex, PEM or DER) and inside `--jwks` (exit 2), and the library returns
`not_assessed` / `key_material_invalid`.

**The relying party's keys.** `verify --jwks <file>` reads an Ed25519 key set with its `valid_from`/`valid_until`,
through the same strict JSON parser as the receipts (duplicate member names, `NaN` and nesting deeper than 512 refused).
A key held for another purpose is **ignored and named on stderr**: a `kty` other than `OKP`, a `crv` other than
`Ed25519`, an `alg` other than `EdDSA` or `Ed25519`, a `use` other than `sig`, and `key_ops` without `verify` (RFC 7517 §5
asks implementations to ignore keys whose `kty` they do not understand or whose values are outside the supported
ranges). Refused — exit 2, never resolved
by order or skipped — are a kid that appears twice (in the set, or again through `--key`), a JWK with `x` but without
`kty` or `crv`, an `x` that is not the canonical unpadded base64url encoding of 32 bytes, and a `valid_from` or
`valid_until` that is not an RFC 3339 instant. On a JWK with `x` but without `kty` or `crv`, or with an `x` that does not
decode to 32 bytes, this is stricter than RFC 7517 §5, which would ignore a key missing a required member or with a value
out of range: such an entry is more likely a defect in the relying party's own list than a foreign key, and ignoring it
would turn a configuration error into "key not supplied". On `8de0b72` a
duplicate kid and a JWK without `kty` both verified the receipt (exit 0).

`--key kid=<hex|file>` accepts 64 hex digits in either case, and a key file in SubjectPublicKeyInfo form, PEM or DER; it
refuses at load key material it cannot read as a key (an empty file, a malformed argument). On `8de0b72` a valid Ed25519
key file, PEM or DER, made a valid receipt FAIL (exit 1, "EdDSA needs a 32-byte key and a 64-byte sig…").

**Instants.** Dates are read in ASCII digits only (RFC 3339 §5.6, ABNF `DIGIT`): on 0.15.1 and on `8de0b72` an `issued_at`
written in Arabic-Indic digits was accepted, because Python's `\d` matches every Unicode decimal digit. A leap second is
accepted only when it is 23:59:60 once the offset is applied (RFC 3339 §5.7; `00:59:60+01:00` is accepted); §5.7 also
limits it to the end of a month in which a leap second occurs, which is not checked here — 23:59:60 UTC is accepted on
any day. It sorts after every `23:59:59.x` and before the next second (the comparison is exact by construction;
measured with an 18-digit `.999…`); 0.15.1 and `8de0b72` accepted
`:60` at another minute (`12:00:60Z`, measured). Window comparisons use every fractional digit: on `8de0b72` an
`issued_at` 100 ns before `valid_from` compared equal to it (the comparison had microsecond resolution) and the receipt
passed as `inside`; it is now `outside`. Through the CLI, a receipt whose `issued_at` is one unit in the last digit
before `valid_from` is `outside`, and `inside` when it equals `valid_from`; measured in two runs, one where `issued_at`
and `valid_from` both carry 20 fractional digits and one where both carry 5000.

**Every file is read the same way.** Receipts, `--previous`, `--jwks`, key files and policy files must be regular files
of at most 64 MiB, opened without blocking and judged on the open descriptor: a FIFO, a device or a directory is refused
at once (exit 2). On `8de0b72` a FIFO given as the receipt blocked the verifier until the probe's 10 s timeout, and a
symlink to `/dev/zero` given as the receipt or as `--jwks` was read until the process died of a SIGKILL sent from outside
the probe, before its 20 s timeout ran out (sender not identified). A receipt can still come from standard input through
a redirect (`verify /dev/stdin < r.json`); a pipe is a FIFO and is refused.

**Key validity windows (§9.2 of -03).** `--keys-are-complete` declares the key set to be the whole trust list. The
proposed -04 text of the draft (VeritasActa/drafts#3; the IETF datatracker still lists -03 on 2026-09-26) requires the
window to be applied to `issued_at` and the output to say which case applied, "so that a verifier that does not check
windows cannot be mistaken for one whose check passed". Measured against the six key-window vectors of
ScopeBlind/agent-governance-testvectors (merged to `main` in `1e24b5687`, vendored under `examples/acta/key-window/`),
scoring all three columns the bench states — verdict, `code` and `key_status` — through the CLI with `--jwks`: **6/6,
6/6, 6/6** on this release, and also on `8de0b72` (the window check predates it; the differences between the two are the
ones measured above, which these six vectors do not exercise). The same vectors on 0.15.1, with the bare key material that
release accepts, give **3/6 verdicts, 3/6 `code` (a missing field scored as null), 0/6 `key_status`**: it has no window
check at all (`valid_from` and `valid_until` do not occur in that file), so it accepts all six and gets the three
rejections wrong. The vectors' own declared invocation is `verify <file> --jwks <jwks> --mode receipt --json`; `--mode`
and `--json` are flags of the reference verifier and this CLI does not implement them, so the run is driven with `--jwks`
alone. An earlier version of this paragraph said 6/6 verdicts for 0.15.1; that was wrong and is corrected here.

**The absence side of the verdict.** A check this host could not run is not a finding about the receipt.
`verify_receipt` and `verify_chain` report `verdict` with a total order `FAIL > NOT_ASSESSED > PASS`, and the CLI maps
it to exit `1 / 77 / 0`; `ok` and `assessed` are derived from it for existing readers, and `ok` stays false under
`NOT_ASSESSED` (fail-closed — a signature that was never checked is never a pass). `not_assessed` lists which receipts
of a chain were affected. Measured 2026-09-26 in a virtualenv without `cryptography`: on 0.15.1 a valid receipt and a
forged one both returned `ok: false` and exit 1 — our own missing library reported with the value of a bad signature;
on this release (and already on `8de0b72`) both return `not_assessed` and exit 77; on this release the output reads
`key_status: no_window`, `code: null`.

The boundary is declared, not left implicit. A capability of **this host** (a missing `cryptography`, no ML-DSA
backend) is an absence. A usable input the **relying party** supplies (keys, policy bytes) and the **profile** itself (an
`alg` outside §6.9) are judgments; an unusable one is the relying party's configuration defect (below). An unknown `kid`
is a "could not look" unless the relying party passes `keys_are_complete=True`, declaring its set to be the whole trust
list: answering "invalid" about a signature this host never checked asserts what it did not measure. Key material of the relying party that is not a key in any form read here
(a number, an empty or non-hex string, 5 bytes, a PEM that does not load) is the relying party's configuration defect,
not a finding about the receipt: `not_assessed` with code `key_material_invalid` in the library, exit 2 at load in the
CLI. That test looks at the material alone, never at the receipt, so a usable key of another type than the receipt's
`alg` stays a `fail` — otherwise flipping the unsigned `alg` of a forged receipt would buy it "could not look". An
absence never hides a finding: a forged receipt beside an unverifiable one gives `fail`, and a broken §6.7 link is still
checked above an unassessed receipt, because the link is a hash and needs no signature backend. A window bound of the
relying party that is not an instant is its configuration defect too: the CLI refuses the key set at load, and the
library — given such an entry directly — returns `not_assessed` with `key_window_undecidable` (on `8de0b72`: `fail`). A
bound that CAN be read and excludes the receipt still decides, even when the other bound is unreadable: `fail`,
`key_outside_validity_window` (on `8de0b72`: `key_window_undecidable`).

## 0.15.1 (2026-09-21)

### Verifier hygiene from the cra-evidence review (2026-09-21, 0.15.1)

Twelve review rounds on cra-evidence 0.3.0 — whose verifiers are this repository's, re-implemented — found four classes of
defect in shared code. Measured here on 21/09/2026 with the probe before the fix (a divergence in every case) and with the
differential oracle after it (76 cases, five verifiers, 0 disagreements, five CLI-grammar cases among them):

- **JavaScript dropped an own `__proto__` key from its canonical form** (`d[k] = …` invokes the prototype setter): an entry
  with such a key added and its `self_hash` untouched verified PASS in JS alone; an entry legitimately carrying that key
  failed in JS alone. `Object.fromEntries` keeps the key. Two oracle cases, one in each direction.
- **Rust's JSON parser accepted `+10`, `010` and raw control characters in strings**, whose canonical form is the same as
  the escaped one, so a byte-tampered line verified PASS in Rust alone (Python, JS, Go and Java refuse them as not JSON).
  RFC 8259 number grammar and the control-character rule enforced. Three oracle cases.
- **A file that is not UTF-8 was `FILE_ERROR` in Rust, and JavaScript decoded it lossily** (a raw byte in a value whose
  `self_hash` was computed over U+FFFD verified PASS in JS alone — found by the review of this very section) → strict UTF-8
  and a `FAIL` verdict everywhere; two oracle cases as bytes.
- **CLI grammar was five grammars**: an unknown flag, a value flag without a value or with `""`, or a second positional
  was silently taken as the ledger path by the JS and Rust CLIs (a verdict with the constraint the operator asked for
  dropped — `--trusted-pubkey "$KEY"` with the variable unset verified with the tip unchecked); Go's `flag` and Java
  accepted an empty value as "not given"; the Python CLI validated five of its seven value flags. Now a usage error (exit 2,
  no verdict) in all five; the oracle runs the five CLIs on five such inputs.

No verdict changed on an in-profile ledger; the 42 test suites (Python, Go, Rust, JS) are unchanged and green.

## 0.15.0 (2026-09-20)

### Signed decision receipts for agents (2026-09-20, 0.15.0)

`cryptovalid_acta.py` implements **draft-farley-acta-signed-receipts-03** (T. Farley, ScopeBlind / Veritas Acta, 29 August
2026; an individual Internet-Draft, Informational; copy downloaded 2026-09-20): a signed receipt of an access-control
decision for an AI agent's tool call — the evidence artifact the FINOS AI Governance Framework thread on MI-21 (agent
decision audit) is converging on, and the profile behind the shared conformance vectors at
ScopeBlind/agent-governance-testvectors. Transcribed and enforced: the envelope shape `{payload, signature{alg, kid, sig}}`
(§2.1; the flat shape is read, never emitted), `issuer_id == kid` (§2.2), `protectmcp:decision` payloads (§3.1), PureEdDSA
over the JCS (RFC 8785) bytes of the payload with no pre-hash (§5, §6.6), `previousReceiptHash = "sha256:" +
hex(SHA-256(JCS(entire signed receipt)))` with the member omitted on a genesis and an unknown prefix refused (§6.7), the
normative policy digest `acta-policy-digest-v1` over the exact bytes of every policy file (§6.8), and algorithm agility
(§6.9: EdDSA emitted; ML-DSA-65 and ES256 read against the declared `alg`, never assumed — the ES256 signature encoding is
not in the draft, IEEE P1363 r||s is read and said). The kid follows §2.1.1 (`sb:issuer:` + 12 Base58 characters; checked
against the `base58` 2.1.1 library).

| Measured 2026-09-20 | result |
|---|---|
| Fixture policy digest (`expected/chain.jsonl` of the vectors repository, commit 49ad7c1) | reproduced from the `.cedar` bytes: `sha256:81ba074a…` |
| Fixture key: seed `00…01` → public key `4cb5abf6…` (as published in `fixtures/keys/README.md`); kid `sb:issuer:6ASf5EcmmEHT` computed per §2.1.1 | agrees with the `base58` 2.1.1 library (the repository's own receipts use the kid `conformance`) |
| Our receipts through the repository's own checks (`conformance/verify.sh`) | schema (ajv, draft-07) 4/4; `@veritasacta/verify` 0.10.18 signatures 4/4; chain/outcomes PASS — **6/6**; each of three tampered sets (decision, link, signature) fails checks 2 and 3 (the schema check passes, as it must: the tampered values are well-formed) |
| Decisions | from the official Cedar bindings (`cedarpy` 4.12, the cedar-policy Rust crate) — the fixtures' `expected_decision` is never read |
| Reference receipts of the draft author's implementation (protect-mcp 0.29.0, `sign --cedar`) through `cryptovalid_acta verify` | **4/4**, §6.7 links and §6.8 digest recomputed; the decision altered → refused (`examples/acta/reference_protect-mcp/`) |
| Algorithm-mixed chain (EdDSA then ML-DSA-65, §6.11) | verifies, each receipt against its own `alg` |

```
python3 cryptovalid_acta.py policy-digest examples/acta                       # sha256:81ba074a…
python3 cryptovalid_acta.py sign --key agent.seed --tool Bash --decision deny --policy-dir examples/acta --out r2.json --previous r1.json
python3 cryptovalid_acta.py verify r1.json r2.json --key sb:issuer:6ASf5EcmmEHT=4cb5abf6…29 --policy-dir examples/acta
python3 cryptovalid_acta.py run-vectors <agent-governance-testvectors clone> receipts/cryptovalid-opencore --seed 00…01
```

`examples/acta/testvectors_driver/run.sh` is the driver to drop into that repository's `implementations/`. Review round 1
(independent AI review; every finding re-measured and ablated in the tests): the §2.2 `issuer_id == kid` rule was enforced only on the envelope shape — a flat-shape receipt
signed by any registered key could name another issuer (fixed for both shapes); a valid signature with hostile members
outside the signed bytes (`NaN` inside the signature object, 600-deep nesting) raised instead of returning a verdict (the
whole receipt is canonicalized first; the signature object must carry exactly `alg`, `kid`, `sig`; a payload with a
`signature` member is refused, §6.6); with the policy bytes given, a receipt without `policy_digest` passed as "bound"
(now a problem) and `policy_digest` / `previousReceiptHash` formats were not checked on read; a chain whose earlier receipt
failed raised at the next link; a `--policy-dir` without policy files verified nothing and said ok; the CLI printed a
traceback on 100 000-deep JSON and accepted duplicate JSON keys last-wins (both refused). Round 2: `verify_chain` read the
link and the policy digest from a `payload` member even on a flat-shape receipt, so a signed decoy `payload` could make a
broken chain pass and a good one fail (now one shape decision for signature, link and digest, §6.6); ES256 is read low-S only
(the `(r, n−s)` twin verifies and would change the §6.7 hash of the receipt); `issued_at` must be a real instant, not just
the RFC 3339 shape; `previous` must be a signed receipt; a tool name that cannot sit in a Cedar entity literal is refused
before evaluation; the ML-DSA-65 context choice (empty) is declared as ours, not the draft's. Round 3 (the last; its
findings applied without a further round): an earlier-revision `policy_digest` (16 hex, no prefix — the §6.8
compatibility note) no longer fails the signature check, it is an opaque label the policy binding refuses to bind on; the
ML-DSA-65 and ES256 negative controls now reach the signature check itself (a real key that did not sign), not a length or
format gate; the sentence "tampered sets fail all three checks" was false (the schema check passes on well-formed tampered
values) and is corrected above. Stated limits: a chain truncated
at its end is undetectable without an external commitment to its head (§9.7 — cryptovalid's checkpoints and witnesses are
that commitment); the first receipt of a set may be a genesis or a segment of a longer chain (§2.2 says the format does not
distinguish them; reported as a warning); whether the policy is the one in force is a separate check (§6.8); commitment
mode (§6, Merkle-committed selectively disclosable fields), the evidence predicate (§4) and the other five receipt types are
not implemented; keys come from the relying party — a receipt's embedded `public_key` (the reference implementation adds
one) is never used (§9.5).

## 0.14.0 (2026-09-19)

### Checkpoints, witnesses, split-view (2026-09-19, 0.14.0)

The two limits above were the honest gap between this archive and a transparency log. They are closed the way the
field closes them — with the world's formats, so that the field's own software verifies the result — and the
closure is measured, not asserted (`test_cryptovalid_witness.py`, 27 tests — 26 without a Go toolchain, 5 without `cryptography`; the bench against
the reference witness is in the release dossier):

| Module | What it does | Standard (editor's copies downloaded 2026-09-19) |
|---|---|---|
| `cryptovalid_checkpoint.py` | A **checkpoint** of a ledger: origin, tree size, RFC 6962 root of the canonical entries (the same leaves the receipts prove against), signed as a **note** by the log key (Ed25519, key id = SHA-256(name ‖ 0x0A ‖ type ‖ pubkey)[:4]); `vkey` strings; strict parsing where the spec is strict (tree size without leading zeroes, canonical base64 root, control characters refused, at most 100 signature lines — the ceiling of the Go implementation, the spec floor being 16) and permissive where the spec says so (any non-empty origin line: "go.sum database tree" parses); every line of a known key is verified (the spec's MUST — the Go library verifies the first line per key and drops repeats, so a note with a bogus repeat opens there and is refused here: declared, fail-closed), byte-identical repeats count once, keys of types nobody verifies here (RFC 6962 THS 0x05, unassigned) are ignored, never accepted — ECDSA (0x02) and ML-DSA-44 (0x06) ARE verified, see below — two different trusted keys colliding on one 4-byte id are refused as ambiguous (measured with a real collision); consistency proofs as base64 lists. | c2sp.org/tlog-checkpoint, c2sp.org/signed-note |
| `cryptovalid_witness.py` | A **witness**: keeps the last checkpoint it cosigned per origin (trust on first use, stated; several trusted keys per origin for rotation; an origin that differs from the key name is configured explicitly, as for `sum.golang.org`), cosigns a new one only when the log signature verifies **and** the new tree extends the stored one (same size → same root; larger → a consistency proof that verifies; smaller → rollback). Every refusal that involves two log-signed checkpoints returns both (`evidenza`); the pairs that are **proof** — `split-view`, two log-signed roots at one size, anyone can check both signatures — are appended once each to `<state>.evidence.jsonl` (also when the refusal reaches an HTTP client as a bare status), whether the witness meets them at the size it holds, at a size it cosigned earlier (`<state>.cosigned.jsonl`, one line per cosigned checkpoint; the last 4 MiB are searched) or at a size it refused earlier without proof and is now passing; `rollback` and `unproven-extension` are **not** proof (a log genuinely signed the older checkpoint, a missing proof may be a client error): they are returned and counted (distinct ones), and remembered as size/root/time (last 100 per origin); the log-signed notes refused without proof beyond the stored size — whatever old size the request stated — are kept in a `pending` ring (at most 100 per origin and 256 KiB, notes above 16 KiB kept as root only, smallest sizes dropped first) so that a later cosign, a second root at that size or a later rollback to it can turn them into proof (a cosign consumes the pending roots at its own size and leaves the others in the ring). A second root at a size the witness never cosigned pairs with a root it still remembers (pending ring, or the refusals ring as root only → `split-view-unkept`); one it no longer remembers (never seen, or dropped from the rings) is a `rollback`/`unproven-extension` it cannot turn into proof — stated. The cosignature is **cosignature/v1** (timestamp inside the signed bytes). `serve` exposes the `add-checkpoint` endpoint of the **tlog-witness HTTP interface** (`POST <prefix>/add-checkpoint`; 200 with the signature lines, 400, 403, 404, 409 with the size as `text/x.tlog.size`, 422, in the spec's order; 500 when the witness cannot decide — no Ed25519 implementation (the reason in the body), state file unreadable or unwritable or invalid configuration (the reason on stderr); check-and-persist under a process lock and a file lock, state and evidence fsync'ed before the response); `submit` is the log side (old size 0, then 409 → the witness's size and our proof; from the answer it keeps only the lines of the witness keys it trusts, each replacing that key's older line). `verify_witnessed` is the relying party: log signature (one key or a rotation set), the expected origin, ≥ N distinct trusted witnesses on *this* text — every line of a trusted witness key is verified and its newest counts — and, with `max_age_s`, ≥ N of them younger than it (a witness whose newest cosignature is in the future beyond `clock_skew_s` does not count; without `max_age_s` no clock is consulted). | c2sp.org/tlog-cosignature (Ed25519 v1), c2sp.org/tlog-witness |
| `cryptovalid_scitt.py` | **SCITT** (RFC 9943, Proposed Standard, June 2026): a **Signed Statement** (COSE_Sign1 with the CWT Claims header — iss, sub — content type and kid, payload attached or detached), its **registration** on a cryptovalid ledger (the entry binds the statement's SHA-256), a **Receipt** with the CWT Claims RFC 9943 requires and the RFC 9942 inclusion proof (vds 1, vdp −1; the canonical leaf travels unsigned beside it), and the **Transparent Statement** (receipts under label 394). The relying party verifies offline, fail-closed: Issuer signature, TS signature with ITS trusted key, that the leaf binds THIS statement, and the RFC 6962 path up to the signed root. Measured with **pycose**, an independent COSE implementation: it decodes both messages, verifies both signatures, reads labels 15/394/395, refuses a wrong key or a tampered payload (`test_cryptovalid_scitt.py`, 5 tests, pycose required in CI). Stated: EdDSA only; the `RFC9162_SHA256` profile, not CCF's; no public Transparency Service here. | RFC 9943, RFC 9942, RFC 9052 |
| `cryptovalid_cose_receipts.py` | **COSE Receipts** read from the published texts: profile `rfc9942` (the receipt layer: Issuer signature, log signature over the root rebuilt from the inclusion proof) and profile `rfc9943` (adds the protected-header MUSTs of RFC 9943 §6: CWT Claims with `iss` and `sub`, `kid` when neither `x5t` nor `x5chain` is present). EdDSA, ES256 and ES384, the key type bound to the algorithm; vds 1 (RFC 9162) and vds 2 (CCF, draft-ietf-scitt-receipts-ccf-profile-05, value requested, not yet assigned by IANA). Every refusal names its stage (`test_cose_receipts.py`, 12 tests). | RFC 9942, RFC 9943, RFC 9052, ccf-profile-05 |
| `cryptovalid_cedulon.py` | **Cedulon Decision Records**, a clean-room reader of a Verax-style ledger: record header, signature, claims (the presented claims must equal the signed ones), chain, effect binding (a row presented beside an Effect Extract must be one the extract signs), checkpoints; inputs, index, the WebAuthn approval assertion and halt control when their files are given. The keys are pinned by the caller, the checkpoint key included. Stated: the approval challenge is not rebuilt (its derivation is not written anywhere); the core's boundary allowance is applied (default 300000 ms, `clock_skew_ms=0` applies none); the index stage reads refs and, as Verax's verifier does, effect completeness (`test_cedulon.py`, 19 tests). | decision-profile-03, CEDULON-08, WebAuthn L3 §7.2 |
| `cryptovalid_aps.py` | **APS action_ref** in the three forms, each named after the revision that defines it (-01 native, -03 v2 with domain prefixes, -03 §4.2 external), and the **Accountability Record v0.1** (schema in code, Ed25519 over JCS, digest, action_ref recomputed). `normalizeTimestamp` read as: drop fractional seconds, UTC only (`Z` or `+00:00`; another offset is refused) — an interpretation, stated (`test_aps.py`, 9 tests). | draft-pidlisnyi-aps-01, -03, RFC 8785 |
| `cryptovalid_vaara_receipt.py` | **Vaara Receipt** (draft-sirkkavaara-vaara-receipt-12): decision and execution receipts, signed payload = JCS of exactly the five signed members, ES256 / RS256 / HS256 / ML-DSA-65. The expected algorithm is a required argument: a receipt naming another one is refused before any signature check (without it, an HS256 receipt keyed with the issuer's public key could be forged). Back link, result commitment, evidence digest and timestamp-anchor digests checked when their inputs are given; anchor tokens themselves are not verified, stated (`test_vaara_receipt.py`, 9 tests). | vaara-receipt-12, RFC 8785, FIPS 204 |
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

## 0.13.0 (2026-09-16)

### Java verifier (JDK standard library, 2026-09-16)

`verifiers/java/CvVerify.java` is a single-file, dependency-free Java implementation of the verifier: the strict
JSON acceptance profile, the canonical hash chain (SHA-256 / SHA3-256), per-entry **Ed25519** (JDK 15+) and
**ML-DSA-65** (JDK 24+, `Signature.getInstance("ML-DSA-65")`) signatures with the same tri-state as `signer.py`, and
the signed chain tip including its post-quantum layer. It is possible only because the profile signs with the EMPTY
FIPS 204 context: the JDK (24 → 27) exposes ML-DSA with no context API. It sits in the differential oracle next to
Python, JS, Go and Rust (verdicts, tip tri-state and entry signatures compared on every hostile input) and in CI on
JDK 27. Run: `java verifiers/java/CvVerify.java ledger.jsonl [-pubkey HEX -pq-pubkey B64] [-tip F -trusted-pubkey HEX
-trusted-pq-pubkey B64]`. Measured on a ledger and tip whose ML-DSA-65 signatures were made inside AWS KMS: PASS,
entries and tip `pq_protected: true`.

## 0.10.2 (2026-09-15)

### Go reference: writer + verifier (2026-09-14)

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

## 0.10.0 (2026-09-14)

### Receipts, monitor, eIDAS 2.0 self-assessment, JWS (2026-09-13)

Compared online with the field (Sigstore Rekor v2, immudb, Azure Confidential Ledger, Google Trillian/Tessera,
the IETF SCITT architecture) and with the new EU rules for **qualified electronic ledgers** (eIDAS 2.0,
Regulation (EU) 2024/1183 Art. 45l; Commission Implementing Regulation (EU) 2025/2531 of 16 December 2025),
four pieces were missing and are now here, stdlib-only:

| Module | What it adds | Standard |
|---|---|---|
| `cryptovalid_receipt.py` | **Portable receipts**: inclusion and consistency proofs for one entry / two tree heads, with a tree head **really signed** by the log key (the old `signed_tree_head` in `cryptovalid_merkle` carried no signature — renamed `tree_head`, alias kept). JSON profile and **COSE_Sign1** encoding per RFC 9942 (`vds`=1 RFC9162_SHA256, `vdp` with inclusion −1 / consistency −2 as arrays of bstr, alg EdDSA; consistency receipts carry a **detached** payload and the verifier recomputes root_2); minimal CBOR codec (duplicate keys and deep nesting refused). Verification is fail-closed: it needs **your** entry (inclusion) or **your** previous root (consistency) and a **trusted** log key — nothing named inside the receipt is trusted, and the proof's tree size must equal the signed head's. | RFC 9942, RFC 9162, RFC 9052, RFC 8949 |
| `ed25519_order.py` | **Ed25519 keys and R of small or mixed order** (0.21.0): RFC 8032 5.1.3 decoding, `[8]P` and `[L]P` with the 5.1.4 formulas, standard library only; `key_problem`, `r_problem`, `strict_problem` (with a cache per key). Used by `signer.py verify` and `cryptovalid_tip.py` before the library's equation; the JS, Go, Java and Swift verifiers carry the same rule. Not constant time (public values only). | RFC 8032 §5.1; the 12 classes of novifinancial/ed25519-speccheck |
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

## README sections replaced on 2026-11-12

The feature sections of the README of 0.22.0 that the rewrite replaced, kept here unchanged for reference. Commands,
flags and file names in them still apply; dated statements are as of their dates. The offers they make of paid pilots
and of a commercial licence are withdrawn (0.25.0, "No commercial offer"): none is offered.

### Licensing architecture (dual license, honest and explicit)

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

### What this is

A self-hosted toolkit that turns compliance activities into **evidence anyone can
re-execute**:

- append-only **hash-chained ledgers** (canonical JSON, SHA-256);
- **Ed25519**-signed records (optionally **hybrid Ed25519 + ML-DSA-65**, FIPS 204, since 0.12.0);
- **RFC 3161** independent timestamps;
- a **standalone verifier** (`verifier.py`, in this directory): one command, no
  server, no vendor — a third party replays the chain and reaches the same
  hashes, or the verification fails. Trust is replaced by verification.

### Relevance to the Sustainable Development Goals

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

### Where this fits (honest scope of the demand)

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

### Status (honest)

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

### Quick start

```bash
python3 verifier.py <ledger.jsonl>     # verifies a hash-chained ledger
```

Exit code 0 = chain intact; 1 = broken, and the receipt tells you where; 74 = the receipt could not be written whole
(stdout or `--out` full, closed, or a reader gone), whatever the verdict (since 0.20.3).

### Signed evidence (the enterprise edge)

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
  bytes. Needs `cryptography` ≥ 48 (Python; measured 2026-10-04 with 48.0.0, 49.0.0, 50.0.1 — 47.0.0 raises
  `UnsupportedAlgorithm`) or Go ≥ 1.27; where a REQUIRED layer cannot be verified the result is
  `pq_unverifiable` with `ok: false` / exit 1, never a green.
- `signer verify` re-derives `self_hash` from the content too, so it catches content tampering on its
  own: the full chain is *content → self_hash → signature*.
- **Optional layer, honest scope:** the core hash verifier stays **stdlib-only**; signatures need the
  `cryptography` package. Absence of signatures never weakens the hash chain. By default keys are
  software keys on a file — production should use a KMS/HSM backend (below). Tests:
  `python3 test_signer.py`.

#### KMS/HSM key custody (no private key in process memory)

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

### Auditor-ready evidence pack

Assembling evidence for an auditor is the regtech time-sink. `evidence_pack.py` turns one or more
ledgers into a **self-verifying bundle** (MANIFEST with per-file SHA-256 + per-ledger hash/signature
verdicts + signer keys + an optional RFC 3161 timestamp, a human `SUMMARY.md`, and the ledgers).
A third party re-checks **everything** with nothing but this repository:

```bash
python3 evidence_pack.py build  pack_dir/  ledger.signed.jsonl  --subject "audit CUST-001"
python3 evidence_pack.py verify pack_dir/
```

`verify` returns `valid: true` only if every file digest matches the manifest, the manifest is
self-consistent, every ledger passes its hash chain **and** (if any entry carries a signature field) its signatures, and
a claimed RFC 3161 token is not refuted — no server, no account, no vendor. Tamper any file and it drops to `valid: false`.
RFC 3161 anchoring is optional (needs `openssl` + a TSA): its absence never invalidates the pack; since 0.22.0 a claim
without a token, or a token that openssl reads here as not granted or bound to another digest, does. The TSA's signature
is not checked (`time_anchor: tsa_not_checked`), and where openssl is absent the token is not read at all
(`time_anchor: not_evaluated / instrument_failure`, with the exit `valid` gives). The receipt also says, in one closed field per subject, what was checked and
how it came out (`admission`, `states`: SPEC §10) — a refusal of the manifest itself (`format_unsupported`,
`unknown_member`, `malformed`) is told apart from tampering. Tests: `python3 test_evidence_pack.py`,
`python3 test_pack_states_20261019.py`.

This is the difference from closed GRC evidence tools: **your evidence is a bundle anyone can re-execute
to verify — forever, offline, without trusting us.**

Build a pack with `--sign-key <keyfile>` to **authenticate the manifest** (recommended): it binds the
subject, the file digests, and each ledger's entry count + head hash. `verify_pack` reports
`manifest_authenticated`.

#### Dispute evidence for agentic-payment mandates (AP2 / SD-JWT)

The AP2 spec tells implementers *what* to keep for dispute resolution (the SD-JWTs with their
disclosures) but not *how* — no key snapshotting, no tamper-evidence, no long-term validation.
ap2-evidence-pack turns a set of SD-JWT mandates into **one self-contained evidence file** that
verifies **offline years later**: it validates each ES256 signature at build time, snapshots the
key material with an explicit **provenance class** (`x5c_header` / `jwk_header` / `supplied` /
`jwks_fetched` — declared, never dressed up), recomputes cross-mandate hash **bindings** from the
exact compact serializations, and seals everything under a SHA-256 digest with an optional
RFC 3161 timestamp:

The reference implementation is the ap2-evidence-pack package (Apache-2.0, same author); since 0.18.0 this repository
depends on it instead of carrying a copy:

```bash
pip install --extra-index-url https://robertolocatelli81-dev.github.io/pypi/ 'cryptovalid-opencore[ap2]'
ap2-evidence build ev.json intent=intent.sdjwt cart=cart.sdjwt --tsa http://tsa.izenpe.com
cryptovalid-verify ap2 ev.json     # offline, fail-closed; the reference's own refusal reason is in the receipt
```

Without the `ap2` extra, `cryptovalid-verify ap2` is a refusal receipt that names it (exit 1), never a pass.

Honest scope: proves these exact artifacts verified with this key material at build time (and
existed at the TSA's time, if stamped). It does **not** confer eIDAS art. 45j qualified-archive
legal presumption and does not by itself validate x5c chains to a trust anchor (ap2-evidence-pack does it for a
relying party that gives one, `--trust-anchor`; `cryptovalid-verify ap2` passes none). ES256 only, loudly.
Since 0.22.0 the front-end needs ap2-evidence-pack >= 1.6.0 and copies its `admission`, `refusal_class`,
`states_vocabulary`, `states` and `policy` (SPEC_AP2_EVIDENCE.md §6.9) into its receipt untouched; the refusal class
leads the reason of the reference's layer.
Tests of the format live in ap2-evidence-pack; here `test_verify_evidence.py` and `test_mcp.py` test the front-end and
the MCP tool `verify_ap2_evidence` (read-only), and skip without the package.

#### Auditor-facing report (PDF/HTML)

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

### MCP server — agents that can prove what they did

`cryptovalid_mcp.py` exposes CryptoValid to any MCP client (IDE assistants, desktop agents, other
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

### DORA ICT-incident evidence (EU, evidence-driven enforcement)

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

### Transaction evidence for tax/audit (IRS Form 1099-DA era)

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

### Long-term evidence defenders (WORM · re-anchor · heterogeneous anchors)

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

### Threat model (honest — hardened after adversarial review)

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

### An open standard (not just a tool)

A verifiable-evidence *feature* is copyable; an *adopted format* is not. CryptoValid is defined by
**conformance test vectors** (`spec/vectors/` + `spec/CONFORMANCE.md`), so a verifier in **any language**
proves interoperability by reproducing the same verdicts:

```bash
python3 conformance.py            # exit 0 = the reference verifier conforms (7/7 vectors)
```

Implement it in Go/Rust/JS, match the vectors, and open a PR to the conformance table — the format becomes
a shared standard, not one vendor's tool. Full spec: [`SPEC_EVIDENCE_FORMAT.md`](SPEC_EVIDENCE_FORMAT.md).

### Merkle proofs (optional extension, RFC 6962)

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
at verification time, or when the fingerprint cache was built — at most 24 hours earlier (the status in force then;
until 0.20.1 a service withdrawn today with `granted` in its history counted too, and the cache was read whatever its
age — corrected in 0.20.2, see that section), not at the token's time (`qtst_fingerprints_at`, given the genTime,
answers that; the CLI and the callers do not use it yet); full ETSI TS 119 615 legal validation (chains, revocation, time constraints)
is beyond exact-fingerprint matching, and production use still wants a contracted QTSP with an SLA. The linear hash-chain stays the interoperable core; Merkle is **additive**. Domain separation:
`0x00` leaves, `0x01` nodes. Third-party verification needs only
`(entry, index, tree_size, audit_path, root)`. Tests: `python3 test_merkle.py`.

### High-frequency ingestion (Art. 12 logs at scale)

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

### Self-updating regulatory profiles

`spec/regulatory_profiles.json` maps evidence to EU requirements (MiCA, EU AI Act, DORA, GDPR) with
`status`, `effective_utc`, `source_url` and an `as_of` date. A ledger entry may set
`data.regulatory_ref = "<id>"` to declare what it supports.

```bash
python3 refresh_regulatory.py --check-urls   # re-checks sources, flags stale entries; exit 1 = needs review
```

**Honest scope:** it keeps the mapping fresh and provenance-honest and **flags** stale entries for a human
to re-verify against the primary source — it does not auto-interpret law. Outdated regulatory status is
never allowed to pass silently.

### The next decade (read on 15/09/2026)

What will change under an evidence ledger written today, and what this repository already does about it:

- **Signatures.** NIST IR 8547 (an initial public draft, not a final standard) proposes deprecating the
  112-bit-strength quantum-vulnerable schemes after 2030 and disallowing all of them — Ed25519 and ECDSA included —
  after 2035. A ledger kept for the multi-year retention windows of DORA, the CRA (technical documentation for at
  least 10 years, Art. 13(13)) or eIDAS crosses that line. The signature suite of ap2-evidence-pack
  (a dependency since 0.18.0) lets the **AP2 evidence format**
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

### Contact, pilots, citation

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
