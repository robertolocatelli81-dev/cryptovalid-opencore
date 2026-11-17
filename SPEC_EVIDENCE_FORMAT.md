<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- Copyright (C) 2026 Roberto Locatelli -->

# CryptoValid Evidence Format — candidate standard v0.10 (2026-11-16; v0.9 2026-11-16, v0.8 2026-11-15, v0.7 2026-11-15, v0.6 2026-11-13, v0.5 2026-10-19)

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
tsa_unresolved` (a token valid but not established under the pinned certificates), or `contradicted` for a token whose
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
(`pack_format` absent, not a string, or not `cryptovalid-evidence-pack/1.1`; packs of format 1.0 included), `unknown_member`
(a key outside §2.1's lists: `manifest_unknown_field`), `malformed` (anything else that makes the manifest unreadable as this
format: not readable, not UTF-8 JSON, a key twice in one object, nested deeper than the bound, larger than the bound, not an
object, `file_digests_sha256` not an object of names inside the pack to strings, `ledgers` not a list of objects naming a file inside the pack, `rfc3161_timestamp` not an object,
`anchored` not a boolean, `tsa` / `tsr_b64` / `note` not strings, `tsr_b64` without `anchored: true`,
`manifest_digest_sha256` / `manifest_signer` / `manifest_signature` not strings, `ledgers[i].entries` not an integer
(a boolean is not one), `ledgers[i].head_self_hash` not a string or null, `ledgers[i].pq_protected` not a boolean or null) — `states: null`, `valid: false`, exit 1, and the reason text in `error` (the field this receipt has carried since
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
| `sealed_content` | each name of `file_digests_sha256`; the manifest's own digest; for each `ledgers[i]`: the file inside the pack, its hash chain (§5 steps 1–4), its entry count and head equal to the manifest's | every element holds | `digest_mismatch` (a file absent, outside the pack or of another digest; the manifest digest; no file listed at all), `artifact_invalid` (a ledger that is not a file inside the pack, or whose chain fails), `binding_mismatch` (entry count or head differ from the manifest: truncation or extension) | — |
| `producer_signature` | the manifest signature; then, for each ledger whose entries carry a signature field (any entry, §5 step 5), its signature layer, then its post-quantum layer when the manifest claims one (`pq_protected: true`) | every element verifies under a key the CALLER pinned (`manifest_signer_hex`; `signer_pubkey_hex` and, for the post-quantum layer, `pq_pubkey_b64`) | `signature_invalid` (a signature that was checked and fails: broken, malformed, a key or R of small or mixed order, an entry of a signed ledger unsigned; a post-quantum layer the manifest claims and the file does not carry, carries partly, or carries broken) | `not_present` (no manifest signature, no signed ledger), `self_asserted` (it verifies under the key it carries; nobody pinned one: draft-krausz §5.4.2(a)), `key_unresolved` (a pin was given and the signer is another key), `backend_missing` (`cryptography`, or ML-DSA-65 in it, is not available here) |
| `time_anchor` | the `rfc3161_timestamp` block | only when the caller pins TSA certificates (v0.8, below): §11 gives `verified` for the token, the manifest digest and the pinned certificates. Without a pin never: this verifier does not check the TSA's signature (a self-issued token binds as well as a real one) | `token_missing` (`anchored: true` and no `tsr_b64`), `binding_mismatch` (an imprint was read and is another digest; with a pin also §11's `imprint_mismatch`), `token_invalid` (otherwise: not a TimeStampResp, status not granted, no imprint read; with a pin, any other refusal of §11 steps 1–6, its reason in `detail`: a signature that does not verify, a token that is not DER as §11 reads it, a hash algorithm outside §11's list) | `not_present` (no block, or `anchored: false`), `tsa_not_checked` (no pin; status granted, imprint = the manifest digest), `tsa_unresolved` (a pin was given; §11 steps 1–6 pass and step 7 refuses: the token is not established under the pinned certificates), `instrument_failure` (openssl absent, with or without a pin; openssl that cannot be started, gives no answer in time, is ended by a signal, or no temporary file: exit 74, below) |

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
make the pack false. The receipt's `rfc3161` object gains `tsa_check` = `{status, reason, detail, gen_time,
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
manifest records, as since 0.12.0) is `key_unresolved` and leaves `valid` as it was, and a post-quantum layer that nobody
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
signature removed those of an unsigned pack. Only a pinned manifest signer or a hash of the whole folder tells them apart.

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
   OCTET STRING}, serialNumber INTEGER (not negative), genTime GeneralizedTime}` then, each at most once and in this
   order, `accuracy` (SEQUENCE), `ordering` (BOOLEAN, DER: 00 or FF), `nonce` (INTEGER), `tsa` ([0]), `extensions`
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
7. **Anchor.** With `tsa_certs` (certificates the verifier pins: the TSA certificate or a CA above it), the token is
   checked against them. How depends on how the SignerInfo names its signer (`sid`, RFC 5652 §5.3: both forms are
   allowed, the SignedData version is 3 in both):
   - **issuerAndSerialNumber**: openssl `ts -verify` checks the token against them: signer certificate, ESS
     signing-certificate attribute, extended key usage timeStamping, the `tsa` field against the signer's name, chain to
     a pinned certificate (`-partial_chain`; the pinned certificates are also given as `-untrusted`), validity at genTime
     (`-attime`); it passes on exit 0 with `Verification: OK` on stdout.
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
     attribute signingCertificate (RFC 2634 §5.4, SHA-1) or signingCertificateV2 (RFC 5035, its `hashAlgorithm`, SHA-256
     when absent), each one present checked and at least one present, with exactly one ESSCertID whose `certHash` is the
     hash of the signer certificate and whose `issuerSerial`, when present, is exactly one directoryName equal (as above) to the
     certificate's issuer and whose serial number is the certificate's (compared as integers) (more than one ESSCertID
     is not evaluated here and fails); (b) the TSTInfo `tsa` field, when present: a directoryName equal (as above) to the
     signer's subject, or one of the names of its subjectAltName (a directoryName compared as above, another name of the
     same type with the same bytes, as `GENERAL_NAME_cmp`); (c) openssl `verify -purpose timestampsign -partial_chain -attime <genTime> -CAfile <pinned>
     -no-CApath -no-CAstore -untrusted <pinned and the token's certificates>` over the signer certificate, exit 0: the
     extended key usage timeStamping (OpenSSL's purpose: present, critical, the only one), the chain to a pinned
     certificate and the validity at genTime, with the same OpenSSL chain building as `ts -verify`.
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
| `invalid` | a step fails; `reason` names it (`malformed`, `not_signed_data`, `response_not_granted`, `econtent_type_not_tstinfo`, `tstinfo_unknown_element`, `hash_algorithm_not_allowed`, `hash_algorithm_mismatch`, `imprint_mismatch`, `signature_invalid`, `not_issued_by_pinned_tsa`; with `crls`, v0.10: `tsa_certificate_revoked`, `tsa_revocation_unknown`), `detail` says where | no |
| `not_evaluated` | steps 1–5 pass and openssl is absent; or, with `crls` (v0.10), `cryptography` is absent (`crl_backend_missing`) | no |

openssl present that cannot start, does not answer in time or is ended by a signal is a check not run here
(`CheckNotRun`, exit 74 in a command), as in §10. The outcome carries the parsed `tst_info` (policy, hash algorithm,
hashed message, serial number, `gen_time` as ISO 8601 UTC, nonce) whenever steps 1–4 pass.

**What a refusal shows (v0.8).** ETSI EN 319 102-1 V1.4.1 (2024-06) validates a time-stamp token as a signature (§5.4)
and names the outcomes in §5.1.3, Table 6. A refusal at steps 1–4 or 6 shows that the token is not a valid signed
timestamp: TOTAL-FAILED (FORMAT_FAILURE for a token that cannot be processed; SIG_CRYPTO_FAILURE for the signature;
HASH_FAILURE for the messageDigest attribute). A refusal at step 5 shows that the token is not a timestamp of the digest
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
binary data); JSON nested deeper than the parser allows.

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

Not claimed: that anything in this repository implements RFC 10073. The test builds composite signatures with a helper
of its own; with the RFC's text given (`CV_RFC10073_TXT=<path to rfc10073.txt>`) it also checks that helper against the
two signatures of Appendix E for `id-MLDSA65-Ed25519-SHA512` (they verified on 2026-11-15); the vector is not shipped
here.

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
   and its 0x04 line only for the witness, as before v0.8.
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
key), and without it the receipt's `tip` is `null` and its `scope` says the tail is not covered. The Rust and Swift
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
| `amount` | yes | a string (never a JSON number, §3), in one canonical form: the integer part `0` or 1 to 18 digits not starting with 0; then, when the currency has N > 0 minor units, `.` and exactly N digits (`1.50`, never `1.5`), and when N = 0 nothing; greater than zero |
| `currency` | yes | an ISO 4217 alphabetic code as Unicode CLDR 49 lists it (`common/validity/currency.xml`, `idStatus="regular"`: 153 codes), its minor units the `digits` of CLDR's `currencyData/fractions` (rule below, "Currencies") |
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

**Currencies (v0.10).** The table of `currency` and of the minor units of `amount` is generated, not typed:
`tools/currency_table_from_cldr.py` reads Unicode CLDR release 49 (tag `release-49`, commit
96e54b273d2da4ec6fbad350ba19ff23fa24a588, 2026-10-21, the latest release on 2026-11-17), `common/validity/currency.xml`
(sha256 b046c1fa146666f2…) and `common/supplemental/supplementalData.xml` (sha256 745150ec1408d50e…), checks both hashes,
and takes the codes whose `idStatus` is `regular`, each with the `digits` of `currencyData/fractions` (the `DEFAULT`
entry when the code has none). CLDR's data files are under the Unicode License v3 (read on 2026-11-17 in the
repository's LICENSE: use, copy, modify, publish, distribute and sell, with the copyright and permission notice; see
NOTICE). CLDR's `digits` are the decimals commonly used, not ISO 4217's minor units, and its currency list is not ISO's
list one; the first draft of v0.10 used list one as published by its maintenance agency, whose website terms of use (read on
2026-11-17) provide its content "exclusively for personal use as well as information purposes". Measured on 2026-11-17, the table changes in two ways: 12 codes of list one are not
accepted (CLDR marks them deprecated: BOV, CHE, CHW, CLF, COU, MXV, SVC, USN, UYI, UYW, VED, XAD), and 15 codes take
`digits` 0 where list one gives 2 (AFN, ALL, COP, HUF, IDR, IRR, KPW, LAK, LBP, MGA, MMK, SOS, SYP, YER) or 3 (IQD); no
code is added. CLDR's `cashDigits` were not taken: they differ from list one in 28 codes. A payment in one of those
currencies that the draft accepted is `payment_malformed` here; no published version accepted it.

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
--witness-vkey <vkey> ... [--min-witnesses <n>]]] [--disclosure <file> ...] [--require-disclosure <member> ...]`; for
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
| RFC 3161 | Proposed Standard (2001), updated by RFC 5816 (ESSCertIDv2); not obsoleted | rfc-editor.org |
| RFC 5652 (§11 step 7) | Internet Standard (2009), updated by RFC 8933 and RFC 9629; not obsoleted | rfc-editor.org |
| RFC 2634 (§11 step 7) | Proposed Standard (1999), updated by RFC 5035; not obsoleted | rfc-editor.org |
| RFC 5035 (§11 step 7) | Proposed Standard (2007); not updated, not obsoleted | rfc-editor.org |
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
| Unicode CLDR (§18 currencies) | release 49, 2026-10-21 (tag release-49, commit 96e54b27…), the latest on 2026-11-17; data under the Unicode License v3 | github.com/unicode-org/cldr |
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
