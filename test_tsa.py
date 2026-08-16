#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Roberto Locatelli
"""Standalone test of the RFC 3161 TSA client (offline-deterministic; live TSA test opt-in)."""
import hashlib, os, subprocess, shutil, sys, unittest
_HERE = os.path.dirname(os.path.abspath(__file__)); sys.path.insert(0, _HERE)
import cryptovalid_tsa as T  # noqa: E402

class TestTSA(unittest.TestCase):
    def test_request_der_wellformed(self):
        d = hashlib.sha256(b"cryptovalid").digest()
        req = T.build_timestamp_request(d, nonce=b"\x02" * 16)
        self.assertEqual(req[0], 0x30)                      # SEQUENCE
        self.assertIn(bytes([0x04, 0x20]) + d, req)        # OCTET STRING(32) with our digest
        self.assertIn(T._OID_SHA256, req)                  # sha256 algorithm id
    def test_openssl_parses_request(self):
        if not shutil.which("openssl"):
            self.skipTest("openssl not installed")
        d = hashlib.sha256(b"x").digest()
        req = T.build_timestamp_request(d)
        import tempfile
        f = tempfile.NamedTemporaryFile(delete=False); f.write(req); f.close()
        p = subprocess.run(["openssl", "ts", "-query", "-in", f.name, "-text"],
                           capture_output=True, text=True); os.unlink(f.name)
        self.assertEqual(p.returncode, 0)
        self.assertIn("sha256", p.stdout.lower())
    @unittest.skipUnless(os.environ.get("CRYPTOVALID_LIVE_TSA"), "set CRYPTOVALID_LIVE_TSA=1 for live TSA test")
    def test_live_timestamp(self):
        d = hashlib.sha256(b"live").digest()
        granted, token, _ = T.request_timestamp(d, "https://freetsa.org/tsr", timeout=25)
        self.assertTrue(granted)
        self.assertTrue(T.token_contains_digest(token, d))

if __name__ == "__main__":
    unittest.main(verbosity=2)
