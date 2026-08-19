#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WORM escrow adapter (W2) — banco ermetico che SA FALLIRE (tmpdir, niente produzione).

Prova che i due obblighi in apparente conflitto COESISTONO: WORM (immutabilità write-once) + GDPR
(cancellabilità via crypto-shredding della chiave, non dell'oggetto WORM).
"""
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import cryptovalid_worm as W  # noqa: E402

_REC = b'{"trade":"BUY","qty":100,"px":42.5,"ts":"2026-08-19"}'


@unittest.skipUnless(W._HAVE_CRYPTO, "cryptography (AES-GCM) assente")
class TestWorm(unittest.TestCase):
    def setUp(self):
        self.worm = W.LocalWormStore(tempfile.mkdtemp())
        self.kr = W.KeyRing()

    def test_roundtrip_positivo(self):
        r = W.store_record_escrow(_REC, self.worm, self.kr, "rec-1")
        self.assertIn("ciphertext_sha3_256", r)                 # digest ancorabile presente
        back = W.retrieve_record("rec-1", r["key_id"], self.worm, self.kr)
        self.assertEqual(back, _REC)                            # il DATO è retained e recuperabile

    def test_write_once_rifiuta_overwrite(self):
        W.store_record_escrow(_REC, self.worm, self.kr, "rec-2")
        with self.assertRaises(W.WormError):                   # WORM: seconda scrittura stesso id → RIFIUTATA
            self.worm.put("rec-2", b"altro")

    def test_crypto_shred_cancella_ma_WORM_resta(self):
        r = W.store_record_escrow(_REC, self.worm, self.kr, "rec-3")
        self.assertTrue(self.kr.crypto_shred(r["key_id"]))     # GDPR erasure: distruggo la chiave
        # il dato è cancellato (indecifrabile)...
        with self.assertRaises(W.WormError):
            W.retrieve_record("rec-3", r["key_id"], self.worm, self.kr)
        # ...MA l'oggetto WORM è ancora lì, immutato (immutabilità WORM rispettata)
        self.assertTrue(self.worm.exists("rec-3"))

    def test_manomissione_ciphertext_InvalidTag(self):
        r = W.store_record_escrow(_REC, self.worm, self.kr, "rec-4")
        # corrompo il file WORM (in un backend reale S3-ObjectLock non sarebbe possibile; qui simulo l'attacco)
        p = self.worm._path("rec-4")
        os.chmod(p, 0o600)
        data = bytearray(open(p, "rb").read())
        data[-1] ^= 0x01                                       # flip 1 bit nel ciphertext
        open(p, "wb").write(bytes(data))
        with self.assertRaises(Exception):                     # AES-GCM: tag non valido → decrypt fallisce
            W.retrieve_record("rec-4", r["key_id"], self.worm, self.kr)

    def test_shred_su_chiave_assente_e_falso(self):
        self.assertFalse(self.kr.crypto_shred("k-inesistente"))  # null control


if __name__ == "__main__":
    unittest.main(verbosity=2)
