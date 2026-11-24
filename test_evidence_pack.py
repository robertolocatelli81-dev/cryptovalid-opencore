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

try:   # the `sign` extra; without it the cases that need it are skipped with this reason, never an error
    import cryptography  # noqa: F401
    HAVE_CRYPTO = True
except ImportError:
    HAVE_CRYPTO = False
if os.environ.get("CV_REQUIRE_CRYPTO") == "1" and not HAVE_CRYPTO:   # the job with cryptography must not pass on skips
    raise SystemExit("CV_REQUIRE_CRYPTO=1 but `cryptography` is missing: the cases that need it would be skipped")
NEEDS_CRYPTO = unittest.skipUnless(HAVE_CRYPTO, "needs `cryptography` (the `sign` extra)")


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
    with open(path, "w", encoding="utf-8", newline="") as f:
        for e in entries:
            f.write(json.dumps(e) + "\n")


@NEEDS_CRYPTO
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
        man = json.load(open(os.path.join(self.pack, "MANIFEST.json"), encoding="utf-8"))
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

    def test_a_name_is_one_file_on_every_system(self):
        """SPEC §31 (0.29.0): a backslash, a colon, a rooted name or a '..' component is refused on EVERY system, by
        the builder and the verifier, with the reason. This reverses NEMESIS V1 P2 (01/10/2026), which kept "\\" an
        ordinary character on POSIX: the same pack then named a file inside it on Linux (`a\\..\\b.jsonl`) and a file
        beside it on Windows. PKWARE APPNOTE 6.3.10 §4.4.17.1 sets the same rule for ZIP."""
        import shutil
        odd = os.path.join(self.d, "a\\..\\b.jsonl")
        shutil.copy(self.signed, odd)
        with self.assertRaises(ValueError) as c:
            evidence_pack.build_pack([odd], self.pack)
        self.assertIn("backslash", str(c.exception))
        self.assertFalse(os.path.exists(self.pack))   # nothing written
        evidence_pack.build_pack([self.signed], self.pack)
        p = os.path.join(self.pack, "MANIFEST.json")
        with open(p, encoding="utf-8") as f:
            man = json.load(f)
        name = man["ledgers"][0]["file"]
        for bad, why in (("a\\..\\" + name, "backslash"), ("sub\\" + name, "backslash"), ("C:" + name, "colon"),
                         (name + ":s", "colon"), ("/" + name, "absolute"), ("x/../" + name, "'..'")):
            for member in ("ledgers", "file_digests_sha256"):
                m = json.loads(json.dumps(man))
                if member == "ledgers":
                    m["ledgers"][0]["file"] = bad
                else:
                    m["file_digests_sha256"][bad] = m["file_digests_sha256"].pop(name)
                with open(p, "w", encoding="utf-8", newline="") as f:
                    json.dump(m, f)
                r = evidence_pack.verify_pack(self.pack)
                self.assertEqual((r["valid"], r.get("refusal_class")), (False, "malformed"), (bad, member))
                self.assertIn(why, r["error"], (bad, member))

    def test_symlink_out_of_the_pack_is_not_read(self):
        # NEMESIS V1 P3 (01/10/2026): a symlink inside the pack pointing outside counted as a matching file
        import hashlib
        evidence_pack.build_pack([self.signed], self.pack)
        outside = os.path.join(self.d, "outside.txt"); open(outside, "w", encoding="utf-8", newline="").write("secret")
        os.symlink(outside, os.path.join(self.pack, "link.txt"))
        p = os.path.join(self.pack, "MANIFEST.json"); man = json.load(open(p, encoding="utf-8"))
        man["file_digests_sha256"]["link.txt"] = hashlib.sha256(b"secret").hexdigest()
        json.dump(man, open(p, "w", encoding="utf-8", newline=""))
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
        rows = [json.loads(x) for x in open(p, encoding="utf-8")]
        rows[1]["data"]["d"] = "reject"
        with open(p, "w", encoding="utf-8", newline="") as f:
            for x in rows:
                f.write(json.dumps(x) + "\n")
        r = evidence_pack.verify_pack(self.pack)
        self.assertFalse(r["valid"])            # digest del file non torna → pack invalido
        self.assertFalse(r["files_ok"])

    def test_tamper_manifest_fails(self):
        evidence_pack.build_pack([self.signed], self.pack)
        mp = os.path.join(self.pack, "MANIFEST.json")
        man = json.load(open(mp, encoding="utf-8"))
        man["subject"] = "FALSIFICATO"
        json.dump(man, open(mp, "w", encoding="utf-8", newline=""))
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
        rows = [x for x in open(p, encoding="utf-8") if x.strip()][:1]               # tronco: 2 -> 1 entry
        with open(p, "w", encoding="utf-8", newline="") as f:
            f.writelines(rows)
        r = evidence_pack.verify_pack(self.pack)
        self.assertFalse(r["valid"])                               # troncamento rilevato
        self.assertFalse(r["ledgers"][0]["untruncated"])

    def test_attack_manifest_reforge_on_signed_caught(self):
        import hashlib
        evidence_pack.build_pack([self.signed], self.pack, sign_key=self.key)  # manifest FIRMATO
        mp = os.path.join(self.pack, "MANIFEST.json")
        m = json.load(open(mp, encoding="utf-8"))
        self.assertTrue(evidence_pack.verify_pack(self.pack)["manifest_authenticated"])
        m["subject"] = "FALSIFICATO"                               # attaccante cambia + ricalcola digest
        core = {k: v for k, v in m.items() if k not in
                ("manifest_digest_sha256", "rfc3161_timestamp", "manifest_signature", "manifest_signer")}
        m["manifest_digest_sha256"] = hashlib.sha256(
            json.dumps(core, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        json.dump(m, open(mp, "w", encoding="utf-8", newline=""))
        r = evidence_pack.verify_pack(self.pack)
        self.assertFalse(r["manifest_authenticated"])              # firma non combacia col nuovo digest
        self.assertFalse(r["valid"])                               # re-forge su pack firmato = invalido

    def test_attack_bogus_rfc3161_not_verified(self):
        evidence_pack.build_pack([self.signed], self.pack)
        mp = os.path.join(self.pack, "MANIFEST.json")
        m = json.load(open(mp, encoding="utf-8"))
        m["rfc3161_timestamp"] = {"anchored": True, "tsa": "http://fake", "tsr_b64": "AAAA"}
        json.dump(m, open(mp, "w", encoding="utf-8", newline=""))
        r = evidence_pack.verify_pack(self.pack)
        self.assertFalse(r["rfc3161"]["verified"])                 # token spazzatura NON verificato

    def test_unsigned_ledger_pack_ok(self):
        evidence_pack.build_pack([self.ledger], self.pack)          # ledger NON firmato
        r = evidence_pack.verify_pack(self.pack)
        self.assertTrue(r["valid"])             # hash chain basta; nessuna firma da verificare


if __name__ == "__main__":
    unittest.main(verbosity=2)
