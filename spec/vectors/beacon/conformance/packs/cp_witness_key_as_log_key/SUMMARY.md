# Evidence pack — beacon test

- Format: `cryptovalid-evidence-pack/1.1` · created 2026-11-16T18:16:45Z
- Signers: 0
- RFC 3161: not anchored

## Ledgers
- `payments.jsonl` — 3 entries · hash **PASS**

## Verify it yourself (vendor-free)
```
python3 evidence_pack.py verify <this-folder>
```
`valid: true` = every file digest matches the manifest, the manifest is self-consistent, every ledger passes its hash chain and (if signed) its signatures, and a claimed RFC 3161 token is not refuted (granted and bound to this manifest's digest where openssl can read it; the TSA's signature is not checked) — checked with nothing but this repository.

**Honest scope:** proves what/when/order/who-signed + non-alteration — not the truth of the facts.
