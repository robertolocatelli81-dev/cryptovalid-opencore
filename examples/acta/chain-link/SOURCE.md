# chain-link and embedded-key vectors — vendored, not ours

`chain-link/` holds the 22 `.json`/`.jsonl` files of `verifier-vectors/chain-link/`, and `embedded-key/` the two receipts
of `negative/embedded-key/` (`acta-envelope.json`, `decision-receipt.json`), copied byte for byte from
**ScopeBlind/agent-governance-testvectors** at commit `5c749de569b247b2db7c01bdbe1487267615afc4` (`main` on 2026-11-23;
the chain-link files last changed in `eb14d8e`, 2026-10-20, the embedded-key ones in `0f10d63`, 2026-09-14). Copyright
(c) ScopeBlind Contributors and agent-governance-testvectors contributors, Apache License 2.0, full text in
`../LICENSE.agent-governance-testvectors` (the same bytes as that commit's `LICENSE`, compared on 2026-11-23). Not copied:
the generator scripts (`scripts/`, `make_vectors.py`, `extract_key.py`) and `KEYS.md`.

They are the conformance bench for -04 §5.4, §5.7 and §5.7.1 (chain links: each receipt alone, against a supplied
predecessor, and read as a sequence) and §8.5 (a key carried inside the receipt), and `test_cryptovalid_acta.py` runs
every case through the `verify` command offline. `index.json` cites "-04 Sections 6.7 and 6.7.1"; in the -04 posted on
the datatracker on 2026-11-22 those sections are §5.7 and §5.7.1.

Re-fetch the exact bytes:

    C=5c749de569b247b2db7c01bdbe1487267615afc4
    git clone https://github.com/ScopeBlind/agent-governance-testvectors.git t && cd t && git checkout "$C"
    cp verifier-vectors/chain-link/*.json verifier-vectors/chain-link/*.jsonl <here>/chain-link/
    cp negative/embedded-key/acta-envelope.json negative/embedded-key/decision-receipt.json <here>/embedded-key/

Then compare with `CL_SHA256` in `test_cryptovalid_acta.py` (`sha256sum`).
