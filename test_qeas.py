#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Banco QEAS adapter: PRIMA dimostra di saper fallire (pack cambiato dopo il deposito →
digest_match False; stub dichiara NO legal value), poi il roundtrip. Tutto in tempdir."""
import json
import os
import sys
import tempfile
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
import cryptovalid_qeas as Q  # noqa: E402


class TestQeasAdapter(unittest.TestCase):
    def setUp(self):
        import evidence_pack
        import signer
        from test_evidence_pack import _make_ledger
        self.d = tempfile.mkdtemp(prefix="qeas_")
        led = os.path.join(self.d, "l.jsonl")
        signed = os.path.join(self.d, "l.signed.jsonl")
        key = os.path.join(self.d, "k.key")
        _make_ledger(led)
        signer.keygen(key)
        signer.sign_ledger(led, signed, key)
        self.pack = os.path.join(self.d, "pack")
        evidence_pack.build_pack([signed], self.pack, subject="qeas bench", sign_key=key)
        self.store = os.path.join(self.d, "stub.json")

    def _backend(self):
        return Q.LocalQeasStub(self.store)

    def test_deposit_then_verify_roundtrip(self):
        r = Q.archive_pack(self.pack, self._backend(), subject="test", now=1000.0)
        self.assertEqual(r["pack_digest"], Q.pack_digest(self.pack))
        v = Q.verify_pack_archive(self.pack, self._backend())
        self.assertTrue(v["present"] and v["local_digest_match"])
        self.assertTrue(v["remote"]["digest_match"])

    def test_stub_declares_no_legal_value(self):
        # honest-scope: lo stub NON deve MAI dichiarare valore legale
        Q.archive_pack(self.pack, self._backend(), now=1000.0)
        v = Q.verify_pack_archive(self.pack, self._backend())
        self.assertFalse(v["legal_value"])
        self.assertFalse(v["remote"]["qualified"])
        self.assertIn("not eidas", " ".join(str(x) for x in v["remote"].values()).lower())

    def test_tampered_pack_after_deposit_fails(self):
        # il banco sa fallire: se il pack cambia DOPO il deposito, il digest non combacia
        Q.archive_pack(self.pack, self._backend(), now=1000.0)
        p = os.path.join(self.pack, "MANIFEST.json")
        man = json.load(open(p))
        man["subject"] = "riscritto dopo l'archiviazione"
        man["manifest_digest_sha256"] = "0" * 64      # forza un digest diverso
        json.dump(man, open(p, "w"))
        v = Q.verify_pack_archive(self.pack, self._backend())
        self.assertFalse(v["local_digest_match"])
        self.assertFalse(v["legal_value"])

    def test_http_backend_requires_https_and_token(self):
        with self.assertRaises(ValueError):
            Q.HttpQeasBackend("http://insecure.example")     # non-https
        os.environ.pop("QEAS_TOKEN", None)
        with self.assertRaises(RuntimeError):
            Q.HttpQeasBackend("https://qeas.example")        # token mancante

    def test_no_receipt_is_honest_absent(self):
        v = Q.verify_pack_archive(self.pack, self._backend())
        self.assertFalse(v["present"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
