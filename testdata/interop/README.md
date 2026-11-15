# Interoperability vectors from other projects

| File | Source | License |
|---|---|---|
| torchwood_mldsa44_log.note, torchwood_mldsa44_log.vkey | FiloSottile/torchwood @ 1c05157b1fd2dadcd2bfe0ca67f46926bfcd8cb5, `cmd/litewitness/testdata/mldsa.txt` (the checkpoint posted to `/add-checkpoint` and the log key added with `witnessctl add-key`; in that test the witness answers 200) | BSD-3-Clause (Copyright 2009 The Go Authors, Copyright 2023 The Torchwood Authors); full text in `LICENSE.torchwood` |
| omega-cra-evol-0.10.0-cra_pack.json, omega-cra-evol-0.10.0-sbom.cdx.json, omega-cra-evol-0.10.0-cra.ledger.jsonl | release assets of robertolocatelli81-dev/omega-cra-evol v0.10.0 (tag on commit af15f4aacae5f1d85a1d7bd3cbcee9ced799c742), downloaded on 2026-11-15 with `gh release download v0.10.0`; each SHA-256 equals the release's SHA256SUMS and is pinned in `test_auto_closed_20261115.py` | AGPL-3.0-or-later, as this repository |
| sunlight_rome2026h1.checkpoint (SHA-256 0ee6cc89f8017c29990bc1899bd31f0a4f943c8e08c3286ed606cf3ee1200381), sunlight_rome2026h1.log.v3.json (SHA-256 7b8c812923930e27e83027f604892a2df3de9e99d01a3fca6cc95374b91fd382) | FiloSottile/sunlight @ 5eed85d78c103401df28e6d08dce225d984b7b52 (2026-11-12), `cmd/skylight/testdata/tree/checkpoint` and `cmd/skylight/testdata/tree/log.v3.json`, downloaded on 2026-11-15: the checkpoint of the test log `rome2026h1.example.org` (size 300, one RFC 6962 signature, type 0x05) and its log list entry (key, LogID, final tree head) | ISC (Copyright 2023 The Sunlight Authors); full text in `LICENSE.sunlight` |

The bytes are copied unchanged; only the surrounding test-script lines were removed.
