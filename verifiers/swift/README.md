# CryptoValidVerify — independent verifier for Apple platforms (Swift)

A clean-room CryptoValid verifier for iOS / iPadOS / macOS (and Linux with
swift-crypto), built the way Apple builds for its own systems: **no third-party
dependencies** — SHA-256 and Ed25519 come from the system **CryptoKit**; SHA3-256
(absent from CryptoKit) is a small pure-Swift Keccak in this package. Canonical JSON
matches the Python reference and the JS verifier on the normative vectors (same canonical digests,
i.e. byte-identical canonical JSON on those vectors; verdict agreement on the adversarial corpus in CI).

```bash
swift build
swift run cvverify ledger.jsonl [--algo sha256|sha3_256] [--pubkey <hex>]
swift test        # runs the SAME normative vectors bundled as test resources
```

- `CryptoValidVerifier.verify(ledgerText:algo:expectedPubkeyHex:)` → `VerifyResult`
- Same verdict as the reference on the shared vectors and on 71 of the 97 oracle cases Swift takes part in (the 9
  tip-ordering cases do not run it); on the other 26 (signed chain tips, ML-DSA) the reference says FAIL and Swift PASS,
  because Swift does not check a tip (declared in the oracle). The
  receipt carries index lists (hash, link, schema failures), not the reference's reason texts.
- Ed25519 fields read as `signer.py` reads them: `signature` canonical standard base64 of 64 bytes, `signer` 64
  lowercase hex digits; anything else is `signatures_all_verified: false`.

Status (measured 2026-10-12 on Linux, Swift 6.3.3 with swift-crypto, 0.20.2): `swift test` 18/18 (25/25 in 0.20.3 on Linux, measured 2026-10-13: the receipt-write test, three for usage with stderr lost, a file size limit and a late non-blocking reader, and three for the final newline, a wait that does not spin, and a write of 0 bytes or EINTR; the last two run on Linux only, and so does the file-size case with room left: on the macOS CI runner, 13/10, run 38403932117, it exited 0 instead of 74, cause not established); the binary reproduces the
normative block of the 11 vectors of `spec/vectors/`; the differential oracle (`../differential_oracle.py`, Swift with
Python, JS, Go, Java and Rust) 0/110 disagreements (26 declared divergences, all on signed tips). The acceptance profile is the reference's: RFC 8259 integers only
within +/-(2^53-1), no raw control character in a string, `\u` = four ASCII hex digits, surrogate pairs combined and
unpaired ones refused, no duplicate key (compared by Unicode scalars), nesting at most 512, LF the only line separator,
a file that is not UTF-8 a FAIL. The file is read to its end through a file handle, so a FIFO (`cvverify <(cat
ledger.jsonl)`) is read as by the other five (0.20.2; it was `FILE_ERROR`). CLI: the ledger path first, then `--algo sha256|sha3_256` and `--pubkey <value>` (every entry must carry a valid signature
whose `signer` equals it, else FAIL — wrong key, unsigned or partly signed ledger — as in JS, Go and Java; since 0.21.0 a
signature layer that does not verify is a FAIL without `--pubkey` too, keys and R values of small or mixed order are refused
(`Ed25519Order.swift`, the same rule on every platform), and `pq_not_checked` counts the entries carrying ML-DSA-65, which this
verifier does not check); an unknown flag, a missing or empty value, a value starting with `-`, an
`--algo` outside the two profiles or a second positional is a usage error (exit 2, no verdict). Exit 0 PASS, 1 FAIL, 2 usage or `FILE_ERROR`, 74 when the receipt could not be written
whole (stdout full, closed, under a file size limit or a reader gone; since 0.20.3), whatever the verdict. A full
non-blocking stdout is waited for in `poll` and the receipt arrives whole (0.20.2 exited 1 with 65 536 or 65 537 of 417 975 bytes in the pipe, by timing); a
usage error stays exit 2 with stderr full or closed (it was SIGILL: `FileHandle.write` traps). Not built on macOS / iOS in this environment (CI has a macOS job). Under a file size limit on macOS (0.21.0, read in the XNU source, not measured on a Mac: `vn_write` in bsd/vfs/vfs_vnops.c, xnu-12377.1.9) the limit is compared with the offset of the descriptor, not with the end of the file: stdout appended (`>>`, offset 0) to a file already past the limit takes a receipt that fits under the limit whole, exit 0 (the case the macOS job met on 13/10, run 38403932117); a receipt that crosses the limit is shortened and the next write fails, exit 74, as on Linux. `testFileSizeLimitMacOS` asserts the first on macOS, `testFileSizeLimitCrossedFromOffsetZeroIs74` the second everywhere.
Honest scope as the JS verifier; no signed-tip or ML-DSA checks (declared in `../../CONFORMANCE.md`).
