# cryptovalid-opencore — driver for agent-governance-testvectors

`run.sh` is the file to drop into `implementations/cryptovalid-opencore/` of ScopeBlind/agent-governance-testvectors.
It installs `cryptovalid-opencore` (from the author's PEP 503 index) and `cedarpy` into a local venv, evaluates the fixtures
with the official Cedar bindings and emits Acta 2.1 envelope receipts (`python -m cryptovalid_acta run-vectors`).
Measured on 2026-09-20 against the repository at commit 49ad7c1: schema 4/4, `@veritasacta/verify` 0.10.18 signatures 4/4,
chain/outcomes PASS; and the reference protect-mcp 0.29.0 receipts verify 4/4 with `cryptovalid_acta verify`.
