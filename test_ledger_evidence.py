#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Receipts (RFC 9942), monitor (append-only), eIDAS 2.0 self-assessment, JWS — 2026-09-13.
Negatives first; every positive has its tampered twin; bench-of-the-bench breaks the Merkle node hash."""
from __future__ import annotations
import hashlib
import json
import os
import shutil
import sys
import tempfile
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
import cryptovalid_merkle as M  # noqa: E402
import cryptovalid_receipt as R  # noqa: E402
import cryptovalid_monitor as MON  # noqa: E402
import eidas_ledger_check as E  # noqa: E402
import cryptovalid_jws as J  # noqa: E402
import signer  # noqa: E402

SAMPLE = os.path.join(_HERE, "examples", "sample_ledger.jsonl")
TAMPERED = os.path.join(_HERE, "examples", "sample_ledger_tampered.jsonl")

try:
    import cryptography  # noqa: F401
    HAVE_CRYPTO = True
except ImportError:
    HAVE_CRYPTO = False


def _entries(path):
    with open(path, encoding="utf-8") as f:
        return [json.loads(l) for l in f if l.strip()]


def _write(path, entries):
    with open(path, "w", encoding="utf-8") as f:
        for e in entries:
            f.write(json.dumps(e) + "\n")


def _append(entries, payload):
    """Append a VALID entry (sha256 chain, same canonical rules as the verifier)."""
    last = entries[-1]
    e = {"idx": last["idx"] + 1, "ts": "2026-09-13T20:00:%02dZ" % (last["idx"] + 1), "prev_hash": last["self_hash"], "payload": payload}
    body = json.dumps(e, sort_keys=True, separators=(",", ":")).encode()
    e["self_hash"] = hashlib.sha256(body).hexdigest()
    return entries + [e]


class TestCBOR(unittest.TestCase):
    def test_roundtrip(self):
        x = {1: -8, 395: 1, 4: b"\x01\x02", -1: [[3, 0, [b"a" * 32, b"b" * 32]]], "s": "città", "b": True, "n": None, 300: 70000, 5: 2 ** 40}
        self.assertEqual(R.cbor_decode(R.cbor_encode(x)), x)
        self.assertEqual(R.cbor_encode({2: 1, 1: 2}), R.cbor_encode({1: 2, 2: 1}))       # deterministic
        with self.assertRaises(ValueError):
            R.cbor_decode(R.cbor_encode([1]) + b"\x00")                                    # trailing bytes


@unittest.skipUnless(HAVE_CRYPTO, "cryptography assente")
class TestReceipts(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="rcpt_")
        cls.key = os.path.join(cls.tmp, "log.key")
        cls.pk = signer.keygen(cls.key)["public_key_hex"]
        cls.other = os.path.join(cls.tmp, "other.key")
        cls.pk_other = signer.keygen(cls.other)["public_key_hex"]
        cls.entries = _entries(SAMPLE)
        cls.leaves = M.leaves_from_ledger(SAMPLE)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_sth_signed_and_trusted_key_required(self):
        sth = R.signed_tree_head(self.leaves, self.key)
        self.assertEqual(sth["tree_size"], len(self.leaves))
        self.assertTrue(R.verify_sth(sth, self.pk)["ok"])
        self.assertFalse(R.verify_sth(sth)["ok"])                       # key from the receipt itself: not trusted
        self.assertFalse(R.verify_sth(sth, self.pk_other)["ok"])
        forged = dict(sth, root_sha256="00" * 32)
        self.assertFalse(R.verify_sth(forged, self.pk)["ok"])
        self.assertFalse(M.tree_head(self.leaves)["signed"])            # the unsigned one says so

    def test_inclusion_every_index_and_tampers(self):
        for i in range(len(self.leaves)):
            r = R.inclusion_receipt(SAMPLE, i, self.key)
            self.assertTrue(R.verify_receipt(r, self.pk, leaf_canonical=self.leaves[i])["ok"], i)
            self.assertTrue(R.verify_receipt(r, self.pk)["ok"])
            # wrong entry for this receipt
            other = self.leaves[(i + 1) % len(self.leaves)]
            self.assertFalse(R.verify_receipt(r, self.pk, leaf_canonical=other)["ok"])
        r = R.inclusion_receipt(SAMPLE, 1, self.key)
        bad = json.loads(json.dumps(r))
        if bad["inclusion_path"]:
            bad["inclusion_path"][0] = "00" * 32
            self.assertFalse(R.verify_receipt(bad, self.pk)["ok"])
        bad = json.loads(json.dumps(r)); bad["leaf_index"] = 0
        self.assertFalse(R.verify_receipt(bad, self.pk)["ok"])
        self.assertFalse(R.verify_receipt(r, self.pk_other)["ok"])
        self.assertFalse(R.verify_receipt({"kind": "x"}, self.pk)["ok"])
        with self.assertRaises(IndexError):
            R.inclusion_receipt(SAMPLE, 99, self.key)

    def test_consistency_growth_rewrite_shrink(self):
        short = os.path.join(self.tmp, "short.jsonl"); _write(short, self.entries[:2])
        old = R.signed_tree_head(M.leaves_from_ledger(short), self.key)
        r = R.consistency_receipt(old, SAMPLE, self.key)
        self.assertTrue(R.verify_receipt(r, self.pk)["ok"], r)
        # rewrite an old entry (keep the chain valid by recomputing): consistency MUST fail
        rew = json.loads(json.dumps(self.entries))
        rew[0]["payload"] = {"rewritten": True}
        body = json.dumps({k: v for k, v in rew[0].items() if k not in ("self_hash", "signature", "signer")}, sort_keys=True, separators=(",", ":")).encode()
        rew[0]["self_hash"] = hashlib.sha256(body).hexdigest()
        rw = os.path.join(self.tmp, "rewritten.jsonl"); _write(rw, rew)
        r2 = R.consistency_receipt(old, rw, self.key)
        self.assertFalse(R.verify_receipt(r2, self.pk)["ok"])
        # shrink
        r3 = R.consistency_receipt(R.signed_tree_head(self.leaves, self.key), short, self.key)
        self.assertFalse(r3["ok"]); self.assertIn("SHRANK", r3["why"])
        self.assertFalse(R.verify_receipt(r3, self.pk)["ok"])

    def test_cose_roundtrip_and_tamper(self):
        r = R.inclusion_receipt(SAMPLE, 2, self.key)
        cose = R.to_cose(r, self.key)
        self.assertEqual(cose[:1], b"\xd2")
        v = R.verify_cose(cose, self.pk, leaf_hash_hex=r["leaf_sha256"])
        self.assertTrue(v["ok"], v); self.assertEqual(v["leaf_index"], 2)
        self.assertFalse(R.verify_cose(cose, self.pk_other, r["leaf_sha256"])["ok"])
        self.assertFalse(R.verify_cose(cose, self.pk, "00" * 32)["ok"])
        self.assertFalse(R.verify_cose(cose, self.pk)["ok"])                  # inclusion needs the leaf hash
        b = bytearray(cose); b[-3] ^= 0x01
        self.assertFalse(R.verify_cose(bytes(b), self.pk, r["leaf_sha256"])["ok"])
        # the vdp proof is an array of bstr (RFC 9942): decode and check the structure
        _, unprot, payload, _ = R.cbor_decode(cose[1:])
        proof = R.cbor_decode(unprot[R.LABEL_VDP][R.PROOF_INCLUSION][0])
        self.assertEqual(proof[0], r["tree_size"]); self.assertEqual(proof[1], 2)
        self.assertEqual(payload.hex(), r["sth"]["root_sha256"])
        c = R.consistency_receipt(R.signed_tree_head(self.leaves[:2], self.key), SAMPLE, self.key)
        self.assertTrue(R.verify_cose(R.to_cose(c, self.key), self.pk)["ok"])

    def test_banco_del_banco_node_hash_rotto(self):
        r = R.inclusion_receipt(SAMPLE, 1, self.key)
        orig = M.node_hash
        try:
            M.node_hash = lambda a, b: hashlib.sha256(b"\x02" + a + b).digest()
            self.assertFalse(R.verify_receipt(r, self.pk)["ok"])
        finally:
            M.node_hash = orig
        self.assertTrue(R.verify_receipt(r, self.pk)["ok"])


class TestMonitor(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="mon_")
        self.ledger = os.path.join(self.tmp, "l.jsonl"); shutil.copy(SAMPLE, self.ledger)
        self.state = os.path.join(self.tmp, "state.json")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_append_only_then_rewrite_truncate(self):
        v1 = MON.run(self.ledger, self.state)
        self.assertTrue(v1["ok"]); self.assertTrue(os.path.exists(self.state)); self.assertFalse(v1["consistency"]["checked"])
        v2 = MON.run(self.ledger, self.state)
        self.assertTrue(v2["ok"]); self.assertEqual(v2["consistency"]["why"], "same size, roots equal")
        es = _append(_append(_entries(self.ledger), {"a": 1}), {"b": 2}); _write(self.ledger, es)
        v3 = MON.run(self.ledger, self.state)
        self.assertTrue(v3["ok"], v3); self.assertTrue(v3["consistency"]["ok"]); self.assertEqual(v3["consistency"]["sizes"], [v1["tree_size"], v1["tree_size"] + 2])
        # rewrite entry 0 keeping the chain formally valid from there on
        rew = _entries(self.ledger); rew[0]["payload"] = {"rewritten": True}
        for i, e in enumerate(rew):
            if i > 0:
                e["prev_hash"] = rew[i - 1]["self_hash"]
            body = json.dumps({k: v for k, v in e.items() if k not in ("self_hash", "signature", "signer")}, sort_keys=True, separators=(",", ":")).encode()
            e["self_hash"] = hashlib.sha256(body).hexdigest()
        _write(self.ledger, rew)
        v4 = MON.run(self.ledger, self.state)
        self.assertFalse(v4["ok"]); self.assertTrue(any("REWRITE" in a for a in v4["alerts"])); self.assertIsNone(v4["state_written"])
        # state did NOT advance: restore the good ledger and the monitor is green again
        _write(self.ledger, es)
        self.assertTrue(MON.run(self.ledger, self.state)["ok"])
        _write(self.ledger, es[:-1])
        v5 = MON.run(self.ledger, self.state)
        self.assertFalse(v5["ok"]); self.assertTrue(any("TRUNCATION" in a for a in v5["alerts"]))

    def test_tampered_snapshot_is_red_even_without_baseline(self):
        shutil.copy(TAMPERED, self.ledger)
        v = MON.run(self.ledger, self.state)
        self.assertFalse(v["ok"]); self.assertFalse(os.path.exists(self.state))

    @unittest.skipUnless(HAVE_CRYPTO, "cryptography assente")
    def test_state_signed_and_key_change_detected(self):
        k1 = os.path.join(self.tmp, "k1"); signer.keygen(k1)
        k2 = os.path.join(self.tmp, "k2"); signer.keygen(k2)
        self.assertTrue(MON.run(self.ledger, self.state, keyfile=k1)["ok"])
        with open(self.state) as f:
            st = json.load(f)
        self.assertTrue(R.verify_sth(st["sth"], st["log_pubkey_hex"])["ok"])
        v = MON.run(self.ledger, self.state, keyfile=k2)
        self.assertFalse(v["ok"]); self.assertTrue(any("LOG KEY CHANGED" in a for a in v["alerts"]))


class TestEidasLedger(unittest.TestCase):
    def test_sample_unsigned(self):
        a = E.assess(SAMPLE)
        by = {r["req"]: r for r in a["requisiti"]}
        self.assertEqual(by["REQ-7.5-04"]["stato"], "SODDISFATTO_PER_COSTRUZIONE")
        self.assertEqual(by["REQ-7.5-05"]["stato"], "NON_SODDISFATTO")
        self.assertEqual(by["Art.45l(a)"]["stato"], "FUORI_PORTATA_DEL_CODICE")
        self.assertIn("NON DIMOSTRATO", a["verdetto"])
        self.assertEqual(by["REQ-7.5-06"]["stato"], "NON_VALUTABILE")

    def test_tampered_fails_ordering(self):
        by = {r["req"]: r for r in E.assess(TAMPERED)["requisiti"]}
        self.assertEqual(by["REQ-7.5-04"]["stato"], "NON_SODDISFATTO")

    @unittest.skipUnless(HAVE_CRYPTO, "cryptography assente")
    def test_signed_and_declared_deployment(self):
        tmp = tempfile.mkdtemp(prefix="eid_")
        try:
            k = os.path.join(tmp, "k"); signer.keygen(k)
            out = os.path.join(tmp, "signed.jsonl"); signer.sign_ledger(SAMPLE, out, keyfile=k)
            by = {r["req"]: r for r in E.assess(out)["requisiti"]}
            self.assertEqual(by["REQ-7.5-05"]["stato"], "PARZIALE")          # signed, but not on qualified certificates
            by = {r["req"]: r for r in E.assess(out, {"qualified_certificates": True, "signing_device": "EUCC"})["requisiti"]}
            # dichiarazioni del fornitore: MAI «SODDISFATTO» (council 13/09), sempre «DICHIARATO_NON_VERIFICATO»
            for rid in ("REQ-7.5-05", "REQ-7.5-06", "REQ-7.5-03"):
                self.assertEqual(by[rid]["stato"], "DICHIARATO_NON_VERIFICATO", rid)
            self.assertNotIn("SODDISFATTO\"", json.dumps([r["stato"] for r in E.assess(out, {"provider_is_qtsp": True, "qualified_certificates": True})["requisiti"]]))
            self.assertIn("NON DIMOSTRATO", E.assess(out, {"provider_is_qtsp": True})["verdetto"])
            ps = E.practice_statement(out, "ACME QTSP", {"qualified_certificates": True})
            self.assertIn("Practice Statement", ps); self.assertIn("to be provided", ps)   # QTSP timestamps, device still missing
            self.assertNotIn("qualified electronic ledger: YES", ps)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_ledger_report_reproducible(self):
        r1, r2 = E.ledger_report(SAMPLE), E.ledger_report(SAMPLE)
        for k in ("record", "catena_ok", "tree_head", "algoritmo", "primo_ts", "ultimo_ts"):
            self.assertEqual(r1[k], r2[k])
        self.assertTrue(r1["catena_ok"]); self.assertFalse(E.ledger_report(TAMPERED)["catena_ok"])


@unittest.skipUnless(HAVE_CRYPTO, "cryptography assente")
class TestJWS(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="jws_")
        self.k = os.path.join(self.tmp, "k"); self.pk = signer.keygen(self.k)["public_key_hex"]
        self.k2 = os.path.join(self.tmp, "k2"); self.pk2 = signer.keygen(self.k2)["public_key_hex"]
        self.e = _entries(SAMPLE)[0]

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_sign_verify_trust(self):
        jws = J.sign_entry(self.e, self.k)
        v = J.verify(jws, self.pk)
        self.assertTrue(v["ok"]); self.assertEqual(v["record"]["idx"], self.e["idx"]); self.assertFalse(v["x5c_present"])
        self.assertFalse(J.verify(jws)["ok"]); self.assertTrue(J.verify(jws)["signature_valid"])   # untrusted kid
        self.assertFalse(J.verify(jws, self.pk2)["ok"])
        h, p, s = jws.split("."); bad = h + "." + p[:-2] + ("AA" if p[-2:] != "AA" else "BB") + "." + s
        self.assertFalse(J.verify(bad, self.pk)["ok"])
        self.assertFalse(J.verify("non.un.jws", self.pk)["ok"])

    def test_x5c_passthrough_and_validation(self):
        import base64
        cert = base64.b64encode(b"\x30\x82fake-der").decode()
        jws = J.sign_entry(self.e, self.k, x5c=[cert])
        v = J.verify(jws, self.pk)
        self.assertTrue(v["ok"] and v["x5c_present"]); self.assertEqual(v["header"]["x5c"], [cert])
        with self.assertRaises(ValueError):
            J.sign_entry(self.e, self.k, x5c=["not base64!!"])
        with self.assertRaises(ValueError):
            J.sign_entry(self.e, self.k, x5c="single-string")


if __name__ == "__main__":
    unittest.main(verbosity=1)
