# @cryptovalid/verify — independent JS verifier

Zero-dependency (Node stdlib only) re-implementation of the CryptoValid evidence
verifier. It agrees with the reference (`verifier.py`) on the normative conformance vectors — same verdicts and
same canonical digests (i.e. byte-identical canonical JSON on those vectors) — and on every verdict of the
adversarial corpus (cross-oracle in CI), so an auditor can re-check evidence offline in a
different runtime — proof that the format is vendor-neutral, not tool-locked.

```bash
node cvverify.mjs ledger.jsonl                 # verify a hash-chained ledger
node cvverify.mjs ledger.signed.jsonl --pubkey <hex>   # + pin the Ed25519 signer: a signature that does not verify -> verdict FAIL, exit 1
node cvverify.mjs --conformance <vectors_dir>  # run the normative vector suite
npm test                                        # 151 checks incl. cross-oracle vs Python
```

Verifies: canonical hash-chain (self_hash recompute, prev_hash linkage, sequential
idx) for SHA-256 and SHA3-256, plus optional Ed25519 signatures over `self_hash` (signature: strict standard base64
of 64 bytes; signer: 64 lowercase hex, as the Python reference and the Java verifier). Exit code: 0 on verdict PASS,
1 on FAIL, 2 when the file cannot be read (`FILE_ERROR`) or on a usage error, 74 when the receipt could not be written
whole (stdout full, under a file size limit, or a reader gone; since 0.20.3), whatever the verdict. A regular file is
written in a loop to the last byte (Node's stream took what fitted under `ulimit -f` and the code was the verdict's). With stdout closed (`>&-`) Node reopens it on
`/dev/null`: the write succeeds there and the program cannot tell. Since 0.21.0 (SPEC v0.4 §5 step 5) a signature
layer that does not verify fails the run with or without `--pubkey` (until 0.20.3 it was only reported in `signatures` without
a key), the failing entries named in `signatures.failures`; a key or an R of small order and a key of mixed order are refused
(`small_order_key`, `mixed_order_key`, `small_order_r`, `key_not_decodable`, `r_not_decodable`), the signed tip too; ML-DSA-65
is not verified here: `signatures.pq_not_checked` counts the entries that carry it.
Library: `import { verifyLedger, conformance } from "./cvverify.mjs"` (no CLI side-effect).

Honest scope: proves integrity, linkage and signature; it does NOT prove the truth of
the recorded facts. Ed25519 is not post-quantum.
