<!-- SPDX-License-Identifier: Apache-2.0 -->
# scitt-cose test vectors (RFC 9942 COSE Receipts, RFC 9943 Signed Statements)

Copied unchanged from [action-state-group/scitt-cose](https://github.com/action-state-group/scitt-cose) at commit
`e76bbfdf7a02b23c8fe18656cbe8502f33e2a711`: `test-vectors/manifest.json`, `test-vectors/v1/` (8 vectors: Signed
Statement + Receipt) and `test-vectors/receipt-v1/` (17 receipt-only vectors), with the project's `LICENSE` (Apache
License 2.0) and its `NOTICE` (Copyright 2026 Action State Group, Inc.), kept as Apache-2.0 §4 asks. The bytes are the ones a cross-verification matrix fetched on
2026-11-16 at that commit and pinned by SHA-256; every file matched its pin when copied on 2026-11-17. `SHA256SUMS`
lists them; `test_scitt_cose_vectors_20261117.py` checks it before any vector is used.

What `cryptovalid_cose_receipts` (profile `rfc9942`) answers on them, since 0.26.0: the expected outcome of each vector,
with one declared exception. `receipt-v1/fail-attached-payload-root` expects a refusal ("a receipt's payload must be
detached"); RFC 9942 §4.4 says only that the payload "SHOULD be detached", so the receipt is accepted, as the standard
decides, and the result reports `payload_attached: true`.
