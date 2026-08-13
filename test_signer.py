#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Roberto Locatelli
"""Standalone test of the CryptoValid signing layer: sign -> verify (hash + signature) -> tamper fails."""
import json
import os
import subprocess
import sys
import tempfile
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
import signer  # noqa: E402
import verifier  # noqa: E402


def _make_ledger(path):
    import hashlib
    def sh(entry):
        d = {k: v for k, v in entry.items() if k != "self_hash"}
        return hashlib.sha256(json.dumps(d, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    entries = [
        {"idx": 0, "ts": "2026-08-13T10:00:00Z", "data": {"event": "kyc", "subject": "C1", "result": "pass"}},
        {"idx": 1, "ts": "2026-08-13T10:05:00Z", "data": {"event": "decision", "subject": "C1", "d": "onboard"}},
    ]
    prev = "0" * 64
    for e in entries:
        e["prev_hash"] = prev
        e["self_hash"] = sh(e)
        prev = e["self_hash"]
    with open(path, "w") as f:
        for e in entries:
            f.write(json.dumps(e) + "\n")


class TestSigner(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.ledger = os.path.join(self.d, "ledger.jsonl")
        self.signed = os.path.join(self.d, "signed.jsonl")
        self.key = os.path.join(self.d, "signer.key")
        _make_ledger(self.ledger)

    def test_keygen_0600(self):
        info = signer.keygen(self.key)
        self.assertEqual(len(info["public_key_hex"]), 64)
        self.assertEqual(oct(os.stat(self.key).st_mode)[-3:], "600")

    def test_sign_then_verify(self):
        signer.keygen(self.key)
        signer.sign_ledger(self.ledger, self.signed, self.key)
        r = signer.verify_file(self.signed)
        self.assertTrue(r["ok"])
        self.assertEqual(r["verified"], 2)

    def test_hash_verifier_still_passes_on_signed(self):
        signer.keygen(self.key)
        signer.sign_ledger(self.ledger, self.signed, self.key)
        rec = verifier.verify_ledger(self.signed)   # verifier STDLIB-only, invariato
        self.assertEqual(rec["verdict"], "PASS")
        self.assertTrue(rec["chain_integrity"])

    def test_tamper_fails_both(self):
        signer.keygen(self.key)
        signer.sign_ledger(self.ledger, self.signed, self.key)
        rows = [json.loads(x) for x in open(self.signed)]
        rows[1]["data"]["d"] = "reject"             # manomissione del contenuto (senza rifirmare)
        tampered = os.path.join(self.d, "tampered.jsonl")
        with open(tampered, "w") as f:
            for r in rows:
                f.write(json.dumps(r) + "\n")
        self.assertEqual(verifier.verify_ledger(tampered)["verdict"], "FAIL")   # hash
        vr = signer.verify_file(tampered)
        self.assertFalse(vr["ok"])                                              # firma+contenuto
        self.assertEqual(vr["failures"][0]["reason"], "content_hash_mismatch")

    def test_wrong_expected_pubkey(self):
        signer.keygen(self.key)
        signer.sign_ledger(self.ledger, self.signed, self.key)
        r = signer.verify_file(self.signed, pubkey_hex="00" * 32)   # pubblica attesa sbagliata
        self.assertFalse(r["ok"])
        self.assertEqual(r["failures"][0]["reason"], "signer_mismatch")

    def test_cli_roundtrip(self):
        env = {**os.environ}
        subprocess.run([sys.executable, "signer.py", "keygen", self.key], cwd=_HERE, check=True, env=env,
                       capture_output=True)
        subprocess.run([sys.executable, "signer.py", "sign", self.ledger, self.signed, self.key],
                       cwd=_HERE, check=True, env=env, capture_output=True)
        r = subprocess.run([sys.executable, "signer.py", "verify", self.signed],
                           cwd=_HERE, env=env, capture_output=True)
        self.assertEqual(r.returncode, 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
