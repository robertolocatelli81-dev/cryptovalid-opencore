#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Roberto Locatelli
"""Standalone test of the auditor-ready evidence pack: build -> verify -> adversarial tamper fails."""
import json
import os
import sys
import tempfile
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
import evidence_pack  # noqa: E402
import signer  # noqa: E402


def _make_ledger(path):
    import hashlib
    def sh(e):
        d = {k: v for k, v in e.items() if k != "self_hash"}
        return hashlib.sha256(json.dumps(d, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    entries = [{"idx": 0, "ts": "2026-08-13T10:00:00Z", "data": {"event": "kyc", "s": "C1", "r": "pass"}},
               {"idx": 1, "ts": "2026-08-13T10:05:00Z", "data": {"event": "decision", "s": "C1", "d": "onboard"}}]
    prev = "0" * 64
    for e in entries:
        e["prev_hash"] = prev
        e["self_hash"] = sh(e)
        prev = e["self_hash"]
    with open(path, "w") as f:
        for e in entries:
            f.write(json.dumps(e) + "\n")


class TestEvidencePack(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.ledger = os.path.join(self.d, "ledger.jsonl")
        self.signed = os.path.join(self.d, "signed.jsonl")
        self.key = os.path.join(self.d, "k.key")
        self.pack = os.path.join(self.d, "pack")
        _make_ledger(self.ledger)
        signer.keygen(self.key)
        signer.sign_ledger(self.ledger, self.signed, self.key)

    def test_malformed_manifest_is_a_named_fail_never_a_crash(self):
        # audit V1 #5 (30/09/2026): these MANIFEST shapes raised tracebacks; a file name outside the pack was read
        import shutil
        evidence_pack.build_pack([self.signed], self.pack, sign_key=None)
        man = json.load(open(os.path.join(self.pack, "MANIFEST.json")))
        cases = {"notjson": b"{x", "list": b"[]", "notutf8": b"\xff\xfe",
                 "digests_list": json.dumps(dict(man, file_digests_sha256=[1])).encode(),
                 "ledger_nofile": json.dumps(dict(man, ledgers=[{"x": 1}])).encode(),
                 "traversal": json.dumps(dict(man, file_digests_sha256={"../../etc/hostname": "00" * 32})).encode(),
                 "absolute": json.dumps(dict(man, ledgers=[{"file": "/etc/hostname"}])).encode(),
                 "ledger_int": json.dumps(dict(man, ledgers=[5])).encode(),
                 "ledger_list": json.dumps(dict(man, ledgers=[[1]])).encode(),
                 "empty_name": json.dumps(dict(man, file_digests_sha256={"": "00" * 32})).encode()}
        for name, raw in list(cases.items()) + [("missing", None), ("dir", None)]:
            d = os.path.join(self.d, "c_" + name)
            shutil.copytree(self.pack, d)
            p = os.path.join(d, "MANIFEST.json")
            if name == "missing":
                os.remove(p)
            elif name == "dir":
                os.remove(p); os.mkdir(p)
            else:
                open(p, "wb").write(raw)
            r = evidence_pack.verify_pack(d)
            self.assertFalse(r["valid"], name)
            self.assertTrue(r.get("error"), name)

    def test_backslash_is_an_ordinary_character_on_posix(self):
        # NEMESIS V1 P2 (01/10/2026): "\\" was treated as a separator, so a legitimate POSIX name with "\\..\\" failed
        if os.sep != "/":
            self.skipTest("POSIX only")
        odd = os.path.join(self.d, "a\\..\\b.jsonl")
        import shutil
        shutil.copy(self.signed, odd)
        evidence_pack.build_pack([odd], self.pack)
        self.assertTrue(evidence_pack.verify_pack(self.pack)["valid"])

    def test_symlink_out_of_the_pack_is_not_read(self):
        # NEMESIS V1 P3 (01/10/2026): a symlink inside the pack pointing outside counted as a matching file
        import hashlib
        evidence_pack.build_pack([self.signed], self.pack)
        outside = os.path.join(self.d, "outside.txt"); open(outside, "w").write("secret")
        os.symlink(outside, os.path.join(self.pack, "link.txt"))
        p = os.path.join(self.pack, "MANIFEST.json"); man = json.load(open(p))
        man["file_digests_sha256"]["link.txt"] = hashlib.sha256(b"secret").hexdigest()
        json.dump(man, open(p, "w"))
        self.assertFalse(evidence_pack.verify_pack(self.pack)["file_ok"]["link.txt"])

    def test_build_produces_files(self):
        evidence_pack.build_pack([self.signed], self.pack, subject="t")
        for name in ("MANIFEST.json", "SUMMARY.md", "signed.jsonl"):
            self.assertTrue(os.path.exists(os.path.join(self.pack, name)), name)

    def test_verify_valid(self):
        evidence_pack.build_pack([self.signed], self.pack)
        r = evidence_pack.verify_pack(self.pack)
        self.assertTrue(r["valid"])
        self.assertTrue(r["files_ok"] and r["manifest_ok"] and r["ledgers_ok"])
        self.assertTrue(r["ledgers"][0]["hash_pass"] and r["ledgers"][0]["sig_pass"])

    def test_tamper_ledger_in_pack_fails(self):
        evidence_pack.build_pack([self.signed], self.pack)
        p = os.path.join(self.pack, "signed.jsonl")
        rows = [json.loads(x) for x in open(p)]
        rows[1]["data"]["d"] = "reject"
        with open(p, "w") as f:
            for x in rows:
                f.write(json.dumps(x) + "\n")
        r = evidence_pack.verify_pack(self.pack)
        self.assertFalse(r["valid"])            # digest del file non torna → pack invalido
        self.assertFalse(r["files_ok"])

    def test_tamper_manifest_fails(self):
        evidence_pack.build_pack([self.signed], self.pack)
        mp = os.path.join(self.pack, "MANIFEST.json")
        man = json.load(open(mp))
        man["subject"] = "FALSIFICATO"
        json.dump(man, open(mp, "w"))
        self.assertFalse(evidence_pack.verify_pack(self.pack)["manifest_ok"])

    def test_rfc3161_optional_honest(self):
        evidence_pack.build_pack([self.signed], self.pack)          # nessuna TSA
        r = evidence_pack.verify_pack(self.pack)
        self.assertFalse(r["rfc3161"]["claimed"])
        self.assertTrue(r["valid"])             # assenza di RFC3161 non invalida (firme+hash bastano)

    # ── regressioni degli attacchi NEMESIS (devono restare CHIUSI) ─────────────────────────────
    def test_attack_truncation_caught(self):
        evidence_pack.build_pack([self.signed], self.pack)
        p = os.path.join(self.pack, "signed.jsonl")
        rows = [x for x in open(p) if x.strip()][:1]               # tronco: 2 -> 1 entry
        with open(p, "w") as f:
            f.writelines(rows)
        r = evidence_pack.verify_pack(self.pack)
        self.assertFalse(r["valid"])                               # troncamento rilevato
        self.assertFalse(r["ledgers"][0]["untruncated"])

    def test_attack_manifest_reforge_on_signed_caught(self):
        import hashlib
        evidence_pack.build_pack([self.signed], self.pack, sign_key=self.key)  # manifest FIRMATO
        mp = os.path.join(self.pack, "MANIFEST.json")
        m = json.load(open(mp))
        self.assertTrue(evidence_pack.verify_pack(self.pack)["manifest_authenticated"])
        m["subject"] = "FALSIFICATO"                               # attaccante cambia + ricalcola digest
        core = {k: v for k, v in m.items() if k not in
                ("manifest_digest_sha256", "rfc3161_timestamp", "manifest_signature", "manifest_signer")}
        m["manifest_digest_sha256"] = hashlib.sha256(
            json.dumps(core, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        json.dump(m, open(mp, "w"))
        r = evidence_pack.verify_pack(self.pack)
        self.assertFalse(r["manifest_authenticated"])              # firma non combacia col nuovo digest
        self.assertFalse(r["valid"])                               # re-forge su pack firmato = invalido

    def test_attack_bogus_rfc3161_not_verified(self):
        evidence_pack.build_pack([self.signed], self.pack)
        mp = os.path.join(self.pack, "MANIFEST.json")
        m = json.load(open(mp))
        m["rfc3161_timestamp"] = {"anchored": True, "tsa": "http://fake", "tsr_b64": "AAAA"}
        json.dump(m, open(mp, "w"))
        r = evidence_pack.verify_pack(self.pack)
        self.assertFalse(r["rfc3161"]["verified"])                 # token spazzatura NON verificato

    def test_unsigned_ledger_pack_ok(self):
        evidence_pack.build_pack([self.ledger], self.pack)          # ledger NON firmato
        r = evidence_pack.verify_pack(self.pack)
        self.assertTrue(r["valid"])             # hash chain basta; nessuna firma da verificare


if __name__ == "__main__":
    unittest.main(verbosity=2)
