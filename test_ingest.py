#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Roberto Locatelli
"""Ingestion tests — every bench carries a NEGATIVE control (tamper -> FAIL).
Throughput is MEASURED and printed; the assertion is only a conservative floor."""
import json
import os
import sys
import tempfile
import threading
import time
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
import cryptovalid_ingest as ing  # noqa: E402
import cryptovalid_merkle as merkle  # noqa: E402
import verifier  # noqa: E402

try:
    import signer
    _HAVE_CRYPTO = True
except (ImportError, RuntimeError):  # pragma: no cover
    _HAVE_CRYPTO = False


class TestIngestBasic(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()

    def test_segments_pass_stdlib_verifier_and_sth_matches(self):
        w = ing.Ingestor(self.d, batch_size=64)
        for i in range(1000):
            w.append({"event": "log", "i": i})
        sth = w.seal()
        w.close(seal=False)
        seg = os.path.join(self.d, sth["segment"])
        self.assertEqual(verifier.verify_ledger(seg)["verdict"], "PASS")
        self.assertEqual(sth["tree_size"], 1000)
        self.assertEqual(merkle.mth(merkle.leaves_from_ledger(seg)).hex(),
                         sth["root_sha256"])
        r = ing.verify_archive(self.d)
        self.assertTrue(r["ok"])
        self.assertEqual(r["segments_verified"], 1)

    def test_rotation_and_sth_chain(self):
        w = ing.Ingestor(self.d, batch_size=32, rotate_entries=100)
        for i in range(250):
            w.append({"i": i})
        w.close()                                   # sigilla anche il parziale (50)
        r = ing.verify_archive(self.d)
        self.assertTrue(r["ok"])
        self.assertEqual(r["segments_verified"], 3)
        self.assertEqual(r["unsealed_segments"], 1)  # il nuovo segmento vuoto corrente
        # controllo negativo 1: manomissione di UNA entry in un segmento sigillato
        seg0 = os.path.join(self.d, "ledger-000000.jsonl")
        rows = open(seg0).read().splitlines()
        rows[3] = rows[3].replace('"i": 3', '"i": 999').replace('"i":3', '"i":999')
        open(seg0, "w").write("\n".join(rows) + "\n")
        r2 = ing.verify_archive(self.d)
        self.assertFalse(r2["ok"])
        self.assertIn("hash_chain_fail", [f["reason"] for f in r2["failures"]])

    def test_tail_segment_removal_detected_by_head(self):
        # il buco trovato dalla review avversariale: senza HEAD la coda era invisibile
        w = ing.Ingestor(self.d, batch_size=32, rotate_entries=50)
        for i in range(200):
            w.append({"i": i})
        w.close(seal=False)                        # 4 segmenti sigillati + head
        os.remove(os.path.join(self.d, "ledger-000003.jsonl"))
        os.remove(os.path.join(self.d, "ledger-000003.jsonl.sth.json"))
        r = ing.verify_archive(self.d)
        self.assertFalse(r["ok"])
        self.assertIn("head_count_mismatch", [f["reason"] for f in r["failures"]])

    def test_unsigned_archive_ok_but_loud_warnings(self):
        w = ing.Ingestor(self.d, batch_size=32)
        for i in range(10):
            w.append({"i": i})
        w.close()
        r = ing.verify_archive(self.d)
        self.assertTrue(r["ok"])                   # integrità sì…
        self.assertEqual(r["signed_segments"], 0)  # …ma paternità NO, e lo dice
        self.assertTrue(any("unsigned_archive" in x for x in r["warnings"]))
        self.assertTrue(any("head_unsigned" in x for x in r["warnings"]))

    def test_blank_line_mid_file_does_not_truncate_valid_data(self):
        w = ing.Ingestor(self.d, batch_size=5)
        for i in range(10):
            w.append({"i": i})
        w.close(seal=False)
        seg = os.path.join(self.d, "ledger-000000.jsonl")
        rows = open(seg).read().splitlines()
        rows.insert(5, "")                         # riga vuota in mezzo (verifier la salta)
        open(seg, "w").write("\n".join(rows) + "\n")
        w2 = ing.Ingestor(self.d, batch_size=5)    # non deve troncare né rifiutare
        self.assertEqual(w2.recovered_bytes, 0)
        w2.append({"resumed": True})
        w2.close()
        self.assertTrue(ing.verify_archive(self.d)["ok"])

    def test_sth_chain_break_detected_on_segment_removal(self):
        w = ing.Ingestor(self.d, batch_size=32, rotate_entries=50)
        for i in range(150):
            w.append({"i": i})
        w.close(seal=False)
        # rimuovo in blocco il segmento di mezzo (file + sidecar): la catena STH deve rompersi
        os.remove(os.path.join(self.d, "ledger-000001.jsonl"))
        os.remove(os.path.join(self.d, "ledger-000001.jsonl.sth.json"))
        r = ing.verify_archive(self.d)
        self.assertFalse(r["ok"])
        self.assertIn("sth_chain_break", [f["reason"] for f in r["failures"]])

    def test_inclusion_proof_against_sealed_sth(self):
        w = ing.Ingestor(self.d, batch_size=64)
        for i in range(777):
            w.append({"i": i})
        sth = w.seal(); w.close(seal=False)
        leaves = merkle.leaves_from_ledger(os.path.join(self.d, sth["segment"]))
        proof = merkle.inclusion_proof(123, leaves)
        self.assertTrue(merkle.verify_inclusion(
            123, 777, leaves[123], proof, bytes.fromhex(sth["root_sha256"])))
        self.assertFalse(merkle.verify_inclusion(          # controllo negativo
            124, 777, leaves[123], proof, bytes.fromhex(sth["root_sha256"])))


class TestCrashRecovery(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()

    def test_torn_tail_truncated_and_resumed(self):
        w = ing.Ingestor(self.d, batch_size=10)
        for i in range(20):
            w.append({"i": i})
        w.close(seal=False)
        seg = os.path.join(self.d, "ledger-000000.jsonl")
        with open(seg, "ab") as f:                 # crash simulato: riga strappata
            f.write(b'{"idx": 20, "ts": "2026-08-16T')
        w2 = ing.Ingestor(self.d, batch_size=10)
        self.assertGreater(w2.recovered_bytes, 0)
        for i in range(5):
            w2.append({"resumed": i})
        w2.close()
        r = ing.verify_archive(self.d)
        self.assertTrue(r["ok"])                    # 25 entry, catena integra
        rows = [json.loads(x) for x in open(seg)]
        self.assertEqual(len(rows), 25)
        self.assertEqual([e["idx"] for e in rows], list(range(25)))

    def test_tampered_history_refuses_resume(self):
        w = ing.Ingestor(self.d, batch_size=5)
        for i in range(10):
            w.append({"i": i})
        w.close(seal=False)
        seg = os.path.join(self.d, "ledger-000000.jsonl")
        rows = open(seg).read().splitlines()
        rows[4] = rows[4].replace('"i":4', '"i":666').replace('"i": 4', '"i": 666')
        open(seg, "w").write("\n".join(rows) + "\n")
        with self.assertRaises(ValueError):         # fail-closed: non riprende su storia manomessa
            ing.Ingestor(self.d, batch_size=5)


@unittest.skipUnless(_HAVE_CRYPTO, "requires 'cryptography'")
class TestSignedSth(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        from cryptovalid_kms import FileKeyBackend
        self.key = os.path.join(self.d, "signer.key")
        self.pub = signer.keygen(self.key)["public_key_hex"]
        self.be = FileKeyBackend(self.key)

    def test_signed_sth_verifies_and_tamper_fails(self):
        w = ing.Ingestor(self.d, batch_size=16, backend=self.be)
        for i in range(64):
            w.append({"i": i})
        sth = w.seal(); w.close(seal=False)
        self.assertEqual(sth["signer"], self.pub)
        self.assertTrue(ing.verify_archive(self.d, expected_pubkey_hex=self.pub)["ok"])
        # controllo negativo 1: pubblica attesa sbagliata
        r = ing.verify_archive(self.d, expected_pubkey_hex="00" * 32)
        self.assertFalse(r["ok"])
        # controllo negativo 2: firma manomessa nel sidecar
        sc = os.path.join(self.d, sth["segment"] + ".sth.json")
        doc = json.load(open(sc)); doc["signature"] = "A" + doc["signature"][1:]
        json.dump(doc, open(sc, "w"))
        r2 = ing.verify_archive(self.d, expected_pubkey_hex=self.pub)
        self.assertIn("sth_signature_invalid", [f["reason"] for f in r2["failures"]])

    def test_forged_tail_extension_detected_with_pinned_key(self):
        # attaccante: appende un segmento sigillato con la SUA chiave e riscrive
        # l'HEAD a modo suo — con la pubblica pinnata deve fallire
        w = ing.Ingestor(self.d, batch_size=16, backend=self.be)
        for i in range(100):
            w.append({"i": i})
        w.close()                                   # archivio genuino, head firmato
        atk_key = os.path.join(self.d, "attacker.key")
        signer.keygen(atk_key)
        from cryptovalid_kms import FileKeyBackend
        atk = ing.Ingestor(self.d, batch_size=16, backend=FileKeyBackend(atk_key))
        atk.append({"forged": True})
        atk.close()                                 # coda forgiata + head riscritto
        r = ing.verify_archive(self.d, expected_pubkey_hex=self.pub)
        self.assertFalse(r["ok"])
        reasons = [f["reason"] for f in r["failures"]]
        self.assertTrue(any(x in reasons for x in
                            ("sth_signer_mismatch", "head_signer_mismatch")))

    def test_signed_head_verified_and_reported(self):
        w = ing.Ingestor(self.d, batch_size=16, backend=self.be)
        for i in range(30):
            w.append({"i": i})
        w.close()
        r = ing.verify_archive(self.d, expected_pubkey_hex=self.pub)
        self.assertTrue(r["ok"])
        self.assertTrue(r["head_present"] and r["head_signed"])
        self.assertEqual(r["signers"], [self.pub])
        self.assertFalse(any("unsigned" in x for x in r["warnings"]))


class TestConcurrencyAndThroughput(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()

    def test_concurrent_appends_keep_chain_intact(self):
        w = ing.Ingestor(self.d, batch_size=64)
        n_threads, per = 4, 500

        def worker(t):
            for i in range(per):
                w.append({"t": t, "i": i})

        ths = [threading.Thread(target=worker, args=(t,)) for t in range(n_threads)]
        for t in ths:
            t.start()
        for t in ths:
            t.join()
        sth = w.seal(); w.close(seal=False)
        self.assertEqual(sth["tree_size"], n_threads * per)
        self.assertEqual(verifier.verify_ledger(
            os.path.join(self.d, sth["segment"]))["verdict"], "PASS")

    def test_throughput_measured_with_floor(self):
        n = 20_000
        w = ing.Ingestor(self.d, batch_size=256, rotate_entries=n + 1)
        t0 = time.perf_counter()
        for i in range(n):
            w.append({"event": "bench", "i": i})
        w.close()
        dt = time.perf_counter() - t0
        eps = int(n / dt)
        print(f"\n[bench onesto] {n} eventi in {dt:.2f}s = {eps} ev/s "
              f"(batch=256, fsync per batch, QUESTA macchina)")
        self.assertTrue(ing.verify_archive(self.d)["ok"])   # veloce ≠ rotto
        self.assertGreater(eps, 1000, "floor conservativo: sotto 1000 ev/s c'è un problema reale")


if __name__ == "__main__":
    unittest.main(verbosity=2)
