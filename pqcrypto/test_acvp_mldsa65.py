#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Roberto Locatelli
"""NIST ACVP ML-DSA-65 signature-verification vectors (FIPS 204, external interface,
pure mode) run against the EXACT code path producer signatures use on the wire.

Source of the vectors: usnistgov/ACVP-Server, gen-val json-files, ML-DSA-sigVer-FIPS204
(NIST public test data). The curated subset (3 valid + 5 tampered z/hint/commitment/
message classes + the empty-context case) is byte-identical to the one elara-mesh runs
(crates/elara-record/tests/vectors/acvp_mldsa65_sigver.txt,
sha256 7ef50ee7f16c1dc78a9f47ba5c496a08b616cba2d438b52bc4613fe081cfc62c), so both
stacks are checked against the SAME NIST oracle — every remaining difference between
the two evidence formats is format, not primitive.

What passing proves: the `cryptography`-provided ML-DSA-65 backend implements FIPS 204
FINAL external/pure verification (a round-three Dilithium3 fails these vectors), and
`sigsuite.verify("ml-dsa-65", ...)` — the wire path, which pins context = empty — agrees
with the raw backend on every empty-context case. It does NOT prove anything about the
evidence format above the primitive; that is the AP2 conformance vectors' job.
"""
import base64
import os
import sys
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
import sigsuite  # noqa: E402

VECTORS = os.path.join(_HERE, "vectors", "acvp_mldsa65_sigver.txt")
EXPECTED_CASES = 9          # file-truncation guard: the subset is exactly 9 cases
EXPECTED_VALID = 3          # positive controls — a verifier that rejects everything must fail here


def _load_vectors():
    cases = []
    with open(VECTORS, encoding="ascii") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            tc, expect, reason, pk, msg, ctx, sig = line.split("|", 6)
            cases.append({"tc": tc, "expect": expect == "P", "reason": reason,
                          "pk": bytes.fromhex(pk), "msg": bytes.fromhex(msg),
                          "ctx": bytes.fromhex(ctx), "sig": bytes.fromhex(sig)})
    return cases


@unittest.skipUnless(sigsuite.MLDSA_AVAILABLE, "cryptography>=50.0.1 (FIPS 204 ML-DSA) required")
class TestAcvpMlDsa65SigVer(unittest.TestCase):
    def test_acvp_sigver_external_pure(self):
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric import mldsa
        cases = _load_vectors()
        self.assertEqual(len(cases), EXPECTED_CASES, "vector file truncated or grown")
        self.assertEqual(sum(c["expect"] for c in cases), EXPECTED_VALID,
                         "positive controls missing — an always-reject bug would pass")
        wire_ran = 0
        for c in cases:
            pub = mldsa.MLDSA65PublicKey.from_public_bytes(c["pk"])
            try:
                pub.verify(c["sig"], c["msg"], context=c["ctx"])
                got = True
            except (InvalidSignature, ValueError):
                got = False
            self.assertEqual(got, c["expect"],
                             f"ACVP tc{c['tc']} ({c['reason']}): got {got}")
            if not c["ctx"]:
                # the wire path: producer signatures verify via sigsuite with empty context
                wire = sigsuite.verify("ml-dsa-65",
                                       base64.b64encode(c["pk"]).decode("ascii"),
                                       base64.b64encode(c["sig"]).decode("ascii"),
                                       c["msg"])
                self.assertEqual(wire, c["expect"],
                                 f"sigsuite wire path diverges from backend on tc{c['tc']}")
                wire_ran += 1
        self.assertGreaterEqual(wire_ran, 1, "empty-context wire-path case missing")


if __name__ == "__main__":
    unittest.main(verbosity=2)
