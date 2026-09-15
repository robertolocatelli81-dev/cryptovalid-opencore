# Tamper bench — arc #703 audit-log schema

Run: `python3 bench/arc_703/arc_bench.py` from the repository root (Python 3.9+ and `cryptography`; `node` and
`go` optional — they add the JS and Go sweeps). Output: JSON lines, one per measurement; `risultati.jsonl` is
the run of 15/09/2026 (200 rows, 6003 tamperings: bare verifier 6002/6003, the miss being the deletion of the
last row; with the signed chain tip 6003/6003; monitor catches the truncated tail; JS and Go sweeps agree).
The bench first proves it can fail (a fake always-PASS verifier is caught) before any number is reported.
