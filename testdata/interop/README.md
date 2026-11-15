# Interoperability vectors from other projects

| File | Source | License |
|---|---|---|
| torchwood_mldsa44_log.note, torchwood_mldsa44_log.vkey | FiloSottile/torchwood @ 1c05157b1fd2dadcd2bfe0ca67f46926bfcd8cb5, `cmd/litewitness/testdata/mldsa.txt` (the checkpoint posted to `/add-checkpoint` and the log key added with `witnessctl add-key`; in that test the witness answers 200) | BSD-3-Clause (Copyright 2009 The Go Authors, Copyright 2023 The Torchwood Authors); full text in `LICENSE.torchwood` |
| omega-cra-evol-0.10.0-cra_pack.json, omega-cra-evol-0.10.0-sbom.cdx.json, omega-cra-evol-0.10.0-cra.ledger.jsonl | release assets of robertolocatelli81-dev/omega-cra-evol v0.10.0 (tag on commit af15f4aacae5f1d85a1d7bd3cbcee9ced799c742), downloaded on 2026-11-15 with `gh release download v0.10.0`; each SHA-256 equals the release's SHA256SUMS and is pinned in `test_auto_closed_20261115.py` | AGPL-3.0-or-later, as this repository |

The bytes are copied unchanged; only the surrounding test-script lines were removed.
