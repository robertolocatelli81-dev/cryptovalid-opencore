# @cryptovalid/verify — independent JS verifier

Zero-dependency (Node stdlib only) re-implementation of the CryptoValid evidence
verifier. It agrees **byte-for-byte** with the reference (`opencore/verifier.py`) on
the normative conformance vectors, so an auditor can re-check evidence offline in a
different runtime — proof that the format is vendor-neutral, not tool-locked.

```bash
node cvverify.mjs ledger.jsonl                 # verify a hash-chained ledger
node cvverify.mjs ledger.signed.jsonl --pubkey <hex>   # + pin the Ed25519 signer
node cvverify.mjs --conformance <vectors_dir>  # run the normative vector suite
npm test                                        # 38 checks incl. cross-oracle vs Python
```

Verifies: canonical hash-chain (self_hash recompute, prev_hash linkage, sequential
idx) for SHA-256 and SHA3-256, plus optional Ed25519 signatures over `self_hash`.
Library: `import { verifyLedger, conformance } from "./cvverify.mjs"` (no CLI side-effect).

Honest scope: proves integrity, linkage and signature; it does NOT prove the truth of
the recorded facts. Ed25519 is not post-quantum.
