<!-- SPDX-License-Identifier: BSD-3-Clause -->
# MMR proof vectors of agent-action-capsule (CLL material)

`cases.json` is copied unchanged from [action-state-group/agent-action-capsule](https://github.com/action-state-group/agent-action-capsule)
at commit `f812c44d9e4a5d9d1d519cb29b7c8ffb0b44d524` (2026-11-22), path `vectors/cll-material/cases.json`, fetched on
2026-11-23; it matched that directory's `SHA256SUMS`. Under that repository's LICENSING.md §2 it is BSD-3-Clause
(Copyright (c) 2026 Action State Group, Inc.): `LICENSE` and `NOTICE` are that repository's, kept as the licence asks.
`SHA256SUMS` lists the files here; `test_mmr_receipts_20261123.py` checks it before any case is used.

The cases are the encoded inclusion and consistency proofs of a log of 1 to 13 entries, written from
draft-bryce-cose-receipts-mmr-profile-02 (the revision that repository pins). They carry no signature: they confirm
`included_root` and `consistent_roots` of `cryptovalid_cose_receipts`, not a COSE receipt. Measured on 2026-11-23
(SPEC §24): 92/92 inclusion cases reach a peak of the tree; 79/79 consistency cases with fewer entries before than
after give the new peaks; the 13 cases with equal sizes are refused, since draft -00 §7.1.1 writes
"if sizeto <= sizefrom -> ERROR".
