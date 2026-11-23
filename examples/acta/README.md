# draft-farley-acta-signed-receipts — reference receipts and policy (downloaded / produced 2026-09-20, under -03; section numbers below are those of -04)

- `autoresearch-safe.cedar`: the Cedar policy of ScopeBlind/agent-governance-testvectors v0.3 (commit 49ad7c1, 2026-09-14);
  its §5.8 policy digest is `sha256:81ba074a4843cb722407feb2a9c43ec1ac4c8e19fd057dc19962af8aef9c05af` (the repository's
  `expected/chain.jsonl` value; `cryptovalid_acta.py policy-digest examples/acta` reproduces it).
- `reference_protect-mcp/`: the four receipts the reference TypeScript implementation (protect-mcp 0.29.0, `sign --cedar`,
  node 22.23.2) produced from the repository's fixtures on 2026-09-20, signed with the published conformance seed
  (`00…01`, public key `4cb5abf6ad79fbf5abbccafcc269d85cd2651ed4b885b5869f241aedf0a5ba29`, kid `conformance`). They are the
  positive control of `verify_receipt` / `verify_chain` (envelope shape, §5.7 links, §5.8 digest) in `test_cryptovalid_acta.py`,
  and each is refused with its decision altered.
- `chain-link/` and `embedded-key/`: vectors of the same repository at commit 5c749de (fetched 2026-11-23) for
  draft-farley-acta-signed-receipts-04 §5.4, §5.7, §5.7.1 and §8.5, run by `test_cryptovalid_acta.py`; source and re-fetch
  recipe in `chain-link/SOURCE.md`.
