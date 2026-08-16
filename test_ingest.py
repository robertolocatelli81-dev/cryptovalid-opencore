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


import shutil
import subprocess
_OPENSSL = shutil.which("openssl")


class TestAutoAnchorTSA(unittest.TestCase):
    """Aggancio automatico TSA nel seal: fake TSA iniettata che firma CMS VERI
    (chiave usa-e-getta openssl) — così passa il check di firma come un token reale.
    Il protocollo RFC 3161 vero è coperto da test_tsa.py e dal live gated sotto."""

    @classmethod
    def setUpClass(cls):
        cls.cms_dir = tempfile.mkdtemp()
        if _OPENSSL:
            # EC P-256 (non Ed25519: openssl cms -sign non lo supporta, "no default digest")
            subprocess.run([_OPENSSL, "req", "-x509", "-newkey", "ec",
                            "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
                            "-keyout", f"{cls.cms_dir}/k.pem", "-out", f"{cls.cms_dir}/c.pem",
                            "-days", "1", "-subj", "/CN=FakeTestTSA"],
                           check=True, capture_output=True)

    def setUp(self):
        self.d = tempfile.mkdtemp()

    @classmethod
    def _sign_cms(cls, content: bytes) -> bytes:
        """CMS SignedData REALE (firma valida, cert usa-e-getta) sul contenuto dato.
        Senza openssl: blob nudo (il verify accetta su digest-binding con warning)."""
        if not _OPENSSL:
            return b"\x30\x10" + content
        with tempfile.NamedTemporaryFile(dir=cls.cms_dir, suffix=".bin", delete=False) as f:
            f.write(content); cp = f.name
        tok = cp + ".der"
        subprocess.run([_OPENSSL, "cms", "-sign", "-in", cp, "-binary", "-nodetach",
                        "-outform", "DER", "-inkey", f"{cls.cms_dir}/k.pem",
                        "-signer", f"{cls.cms_dir}/c.pem", "-out", tok],
                       check=True, capture_output=True)
        with open(tok, "rb") as f:
            return f.read()

    @classmethod
    def _fake_tsa_ok(cls, digest, url, timeout=30):
        # token finto: CMS vero il cui contenuto porta il digest (04 20 || digest)
        return True, cls._sign_cms(b"FAKE-TSTINFO" + b"\x04\x20" + digest + b"TAIL"), b""

    def test_seal_writes_token_and_verify_counts_it(self):
        w = ing.Ingestor(self.d, batch_size=16, tsa_url="http://fake.tsa")
        w._request_timestamp = self._fake_tsa_ok
        for i in range(40):
            w.append({"i": i})
        sth = w.seal(); w.close(seal=False)
        seg = os.path.join(self.d, sth["segment"])
        self.assertTrue(os.path.exists(seg + ".sth.tsr"))
        meta = json.load(open(seg + ".sth.tsr.json"))
        self.assertTrue(meta["granted"] and meta["digest_bound"])
        self.assertEqual(meta["sth_canonical_sha256"], ing._sth_canonical_hash(sth))
        r = ing.verify_archive(self.d)
        self.assertTrue(r["ok"])
        self.assertEqual(r["timestamped_segments"], 1)
        self.assertFalse(any("no_rfc3161_anchor" in x for x in r["warnings"]))

    def test_token_not_bound_to_digest_fails_verify(self):
        w = ing.Ingestor(self.d, batch_size=16, tsa_url="http://fake.tsa")
        # CMS con firma VALIDA ma contenuto senza il digest -> deve cadere sul binding
        w._request_timestamp = lambda d, u, timeout=30: (True, self._sign_cms(b"NO-DIGEST-HERE"), b"")
        for i in range(10):
            w.append({"i": i})
        w.seal(); w.close(seal=False)
        r = ing.verify_archive(self.d)
        self.assertFalse(r["ok"])                   # controllo negativo: token scollegato
        self.assertIn("tsa_token_digest_mismatch", [f["reason"] for f in r["failures"]])

    @unittest.skipUnless(_OPENSSL, "needs openssl for CMS check")
    def test_forged_blob_with_digest_fails_cms_check(self):
        # il buco della review: blob NON-CMS che contiene il digest passava come 'timestamped'
        w = ing.Ingestor(self.d, batch_size=16, tsa_url="http://fake.tsa")
        w._request_timestamp = lambda d, u, timeout=30: (
            True, b"\x30\x10NOT-A-TIMESTAMP" + b"\x04\x20" + d + b"TAIL", b"")
        for i in range(10):
            w.append({"i": i})
        w.seal(); w.close(seal=False)
        r = ing.verify_archive(self.d)
        self.assertFalse(r["ok"])
        self.assertIn("tsa_token_cms_invalid", [f["reason"] for f in r["failures"]])

    @unittest.skipUnless(_OPENSSL, "needs openssl for CMS check")
    def test_truncated_token_fails_closed(self):
        w = ing.Ingestor(self.d, batch_size=16, tsa_url="http://fake.tsa")
        w._request_timestamp = self._fake_tsa_ok
        for i in range(10):
            w.append({"i": i})
        sth = w.seal(); w.close(seal=False)
        tsr = os.path.join(self.d, sth["segment"] + ".sth.tsr")
        with open(tsr, "r+b") as f:                 # corruzione: tronco a metà
            f.truncate(os.path.getsize(tsr) // 2)
        r = ing.verify_archive(self.d)
        self.assertFalse(r["ok"])
        self.assertTrue(any(f["reason"].startswith("tsa_token_") for f in r["failures"]))

    def test_lotl_cache_never_colocated_with_archive(self):
        # il buco ALTA della review: cache LOTL nella dir dell'archivio = avvelenabile
        import cryptovalid_lotl as lotl
        seen = {}
        orig = lotl.load_qualified_fingerprints

        def spy(ms, cache_path=None, **kw):
            seen["cache_path"] = cache_path
            return set(), []

        lotl.load_qualified_fingerprints = spy
        try:
            w = ing.Ingestor(self.d, batch_size=16, tsa_url="http://fake.tsa")
            w._request_timestamp = self._fake_tsa_ok
            for i in range(10):
                w.append({"i": i})
            w.seal(); w.close(seal=False)
            r = ing.verify_archive(self.d, lotl_check=True, lotl_member_states=["ES"])
        finally:
            lotl.load_qualified_fingerprints = orig
        self.assertIn("cache_path", seen)
        self.assertFalse(os.path.abspath(seen["cache_path"]).startswith(
            os.path.abspath(self.d)), "cache LOTL dentro l'archivio: avvelenabile")
        # e con zero impronte il verdetto resta onesto: nessun qualified, warning presente
        self.assertEqual(r["eidas_qualified_segments"], 0)
        self.assertTrue(any("tsa_not_qualified" in x for x in r["warnings"]))

    def test_tsa_failure_never_blocks_ingestion(self):
        def boom(digest, url, timeout=30):
            raise OSError("TSA irraggiungibile")
        w = ing.Ingestor(self.d, batch_size=16, tsa_url="http://down.tsa")
        w._request_timestamp = boom
        for i in range(10):
            w.append({"i": i})
        sth = w.seal()                              # NON deve sollevare
        w.close(seal=False)
        self.assertIsNotNone(sth)
        self.assertIn("TSA irraggiungibile", w.last_anchor_error)
        seg = os.path.join(self.d, sth["segment"])
        self.assertFalse(os.path.exists(seg + ".sth.tsr"))
        meta = json.load(open(seg + ".sth.tsr.json"))
        self.assertIn("error", meta)                # l'onestà sta nel receipt
        r = ing.verify_archive(self.d)
        self.assertTrue(r["ok"])                    # integrità intatta…
        self.assertTrue(any("no_rfc3161_anchor" in x for x in r["warnings"]))  # …ma lo dice

    def test_rotation_anchors_every_segment(self):
        w = ing.Ingestor(self.d, batch_size=8, rotate_entries=20, tsa_url="http://fake.tsa")
        w._request_timestamp = self._fake_tsa_ok
        for i in range(60):
            w.append({"i": i})
        w.close(seal=False)                         # 3 segmenti pieni già sigillati
        r = ing.verify_archive(self.d)
        self.assertTrue(r["ok"])
        self.assertEqual(r["timestamped_segments"], 3)

    def test_slow_tsa_does_not_block_concurrent_appends(self):
        # regressione trovata in auto-audit: l'ancora girava sotto il lock (anche via
        # RLock rientrante dalla rotazione dentro append) → TSA lenta = stallo.
        # Discriminante DETERMINISTICO (la review ha mostrato che una soglia larga
        # non distingue): cronometro un append MENTRE l'ancora è bloccata su un Event.
        anchor_started, anchor_release = threading.Event(), threading.Event()

        def blocking_tsa(digest, url, timeout=30):
            anchor_started.set()
            anchor_release.wait(5)                  # l'ancora resta "in volo"
            return self._fake_tsa_ok(digest, url)

        w = ing.Ingestor(self.d, batch_size=4, rotate_entries=8, tsa_url="http://slow.tsa")
        w._request_timestamp = blocking_tsa
        filler = threading.Thread(target=lambda: [w.append({"i": i}) for i in range(8)])
        filler.start()                              # l'8° append innesca seal+ancora
        try:
            self.assertTrue(anchor_started.wait(5), "l'ancora non è mai partita")
            t0 = time.perf_counter()
            w.append({"concurrent": True})          # DEVE passare mentre l'ancora è bloccata
            dt = time.perf_counter() - t0
            self.assertLess(dt, 0.5, f"append bloccato {dt:.2f}s: l'ancora tiene il lock")
        finally:
            anchor_release.set()
            filler.join()
        w.close()
        r = ing.verify_archive(self.d)
        self.assertTrue(r["ok"])
        self.assertGreaterEqual(r["timestamped_segments"], 1)

    @unittest.skipUnless(os.environ.get("CRYPTOVALID_LIVE_TSA"),
                         "set CRYPTOVALID_LIVE_TSA=1 for live QTSP anchor test")
    def test_live_izenpe_qualified_anchor(self):
        w = ing.Ingestor(self.d, batch_size=16, tsa_url="http://tsa.izenpe.com",
                         lotl_check=True, lotl_member_states=["ES"])
        for i in range(20):
            w.append({"i": i})
        sth = w.seal(); w.close(seal=False)
        meta = json.load(open(os.path.join(self.d, sth["segment"] + ".sth.tsr.json")))
        self.assertTrue(meta["granted"] and meta["digest_bound"])
        self.assertTrue(meta["eidas_qualified"])    # validato 2026-08-16: Izenpe in TL ES
        r = ing.verify_archive(self.d, lotl_check=True, lotl_member_states=["ES"])
        self.assertTrue(r["ok"])
        self.assertEqual(r["eidas_qualified_segments"], 1)


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
