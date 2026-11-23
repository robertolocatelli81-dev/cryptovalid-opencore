#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
"""SPEC v0.15 §23: the list of the checks of cryptovalid-verify (`--list-checks`), printed from the tables the code that
writes the layers reads, and the verification profile (`--profile`), which adds requirements and cannot remove a check.
Written with §23, before its code; on 0b0c907 (before §23) these tests fail."""
import ast
import hashlib
import inspect
import itertools
import json
import os
import random
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import verify_evidence as VE  # noqa: E402
import verifier  # noqa: E402

CLI = [sys.executable, os.path.join(HERE, "verify_evidence.py")]
SAMPLE = os.path.join(HERE, "examples", "sample_ledger.jsonl")
TAMPERED = os.path.join(HERE, "examples", "sample_ledger_tampered.jsonl")
TSA_CERT = os.path.join(HERE, "spec", "vectors", "rfc3161", "freetsa_cacert.pem")


def _crypto():
    try:
        import cryptography  # noqa: F401
        return True
    except ImportError:
        return False


def _run(*args):
    p = subprocess.run(CLI + [str(a) for a in args], capture_output=True, text=True, timeout=120)
    return p.returncode, p.stdout, p.stderr


def _bytes(path):
    with open(path, "rb") as f:
        return f.read()


def _first_id(path):
    with open(path, encoding="utf-8") as f:
        return json.loads(f.readline())["self_hash"]


def _strip(r):
    return {k: v for k, v in r.items() if k not in ("profile", "valid", "verified_utc")}


def _profile(require, name="t", **top):
    d = {"profile_format": VE.PROFILE_FORMAT, "name": name, "require": require}
    d.update(top)
    return d


class Tmp(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="cvprof_")
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def write(self, name, content):
        p = os.path.join(self.tmp, name)
        with open(p, "wb") as f:
            f.write(content if isinstance(content, bytes) else json.dumps(content).encode())
        return p


# ─────────────────────────────────────────────── rule 1: the list is the table the code reads

class TestTheListIsTheCode(unittest.TestCase):
    def _ids_written(self):
        src = _bytes(os.path.join(HERE, "verify_evidence.py")).decode("utf-8")
        ids = set()
        for n in ast.walk(ast.parse(src)):
            if isinstance(n, ast.Call) and getattr(n.func, "id", None) == "_check":
                self.assertIsInstance(n.args[0], ast.Constant, "a _check id is a literal")
                ids.add(n.args[0].value)
            if isinstance(n, ast.FunctionDef):
                self.assertNotEqual(n.name, "_layer", "a layer is written only through _check")
        return ids

    def test_every_check_in_the_table_is_written_and_nothing_else(self):
        self.assertEqual(self._ids_written(), set(VE.CHECKS))

    def test_an_id_outside_the_table_cannot_be_written(self):
        with self.assertRaises(KeyError):
            VE._check("ledger.not_a_check", "PASS")

    def test_requirements_are_parameters_of_the_reference_verifiers(self):
        import cryptovalid_ingest
        import evidence_pack
        fns = {"ledger": verifier.verify_ledger, "pack": evidence_pack.verify_pack, "archive": cryptovalid_ingest.verify_archive}
        for (kind, m), (param, _c, needs, norm) in VE.REQUIREMENTS.items():
            self.assertIn(param, inspect.signature(fns[kind]).parameters, (kind, m))
            self.assertTrue(norm.startswith("SPEC §"), (kind, m))
            for n in needs:
                self.assertIn((kind, n), VE.REQUIREMENTS)

    def test_list_json_is_the_tables(self):
        rc, out, err = _run("--list-checks", "--format", "json")
        self.assertEqual(rc, 0, err)
        d = json.loads(out)
        self.assertEqual(d["list_format"], "cryptovalid-verify-checks/1")
        ids = [x["id"] for x in d["checks"]]
        want = list(VE.CHECKS) + [f"{k}.require.{m}" for k, m in VE.REQUIREMENTS] + list(VE._OWN_CHECKS)
        self.assertEqual(ids, want)
        for x in d["checks"]:
            self.assertEqual(set(x), {"id", "layer", "commands", "required", "enabled_by", "when", "norm"})
            self.assertIn(x["required"], ("always", "profile"))
            self.assertEqual(x["enabled_by"] is None, x["required"] == "always", x["id"])
            if x["id"] in VE.CHECKS:
                self.assertEqual(x["layer"], VE.CHECKS[x["id"]][0])

    def test_list_per_command(self):
        for cmd in VE._COMMANDS:
            rc, out, err = _run("--list-checks", cmd, "--format", "json")
            self.assertEqual(rc, 0, (cmd, err))
            rows = json.loads(out)["checks"]
            self.assertTrue(rows, cmd)
            self.assertTrue(all(cmd in x["commands"] for x in rows), cmd)
        rows = json.loads(_run("--list-checks", "ledger", "--format", "json")[1])["checks"]
        self.assertEqual([x["id"] for x in rows], ["ledger.chain"] + [f"ledger.require.{m}" for k, m in VE.REQUIREMENTS
                                                                       if k == "ledger"])
        self.assertNotIn("pack.files", [x["id"] for x in rows])

    def test_list_text_and_usage_errors(self):
        rc, out, _ = _run("--list-checks")
        self.assertEqual(rc, 0)
        for cid in VE.CHECKS:
            self.assertIn(cid + "  [always]", out)
        self.assertIn("pack.require.tsa_certs  [profile]", out)
        self.assertEqual(_run("--list-checks", "nonsense")[0], 2)
        self.assertEqual(_run("--list-checks", "--format", "xml")[0], 2)

    def test_every_layer_of_a_receipt_carries_its_id(self):
        for cmd, path in (("ledger", SAMPLE), ("ledger", TAMPERED), ("auto", SAMPLE), ("auto", HERE),
                          ("cldma", SAMPLE), ("ap2", SAMPLE)):
            rc, out, err = _run(cmd, path)
            r = json.loads(out)
            for x in r["layers"]:
                self.assertIn(x["id"], VE.CHECKS, (cmd, x))
                self.assertEqual(x["layer"], VE.CHECKS[x["id"]][0])
                self.assertIn(cmd if cmd != "auto" else "auto", VE.CHECKS[x["id"]][1])


# ─────────────────────────────────────────────── rule 6: without a profile nothing changes

class TestNoProfile(Tmp):
    def test_receipt_says_default_and_exit_is_the_verdict(self):
        for path, rc_want in ((SAMPLE, 0), (TAMPERED, 1)):
            rc, out, _ = _run("ledger", path)
            r = json.loads(out)
            self.assertEqual(rc, rc_want)
            self.assertEqual(r["profile"], "default")
            self.assertEqual(r["valid"], rc_want == 0)

    def test_check_not_run_receipt_names_the_default_profile(self):
        from verifier import CheckNotRun

        def boom(path, **pins):
            raise CheckNotRun("simulated", receipt={"kind": "pack", "valid": True, "layers": []})
        out = []
        with mock.patch.object(VE, "verify_pack", boom), \
                mock.patch("verifier.check_not_run_exit", lambda e, text: out.append(json.loads(text)) or 74):
            self.assertEqual(VE._main(["pack", self.tmp]), 74)
        self.assertEqual(out[0]["profile"], "default")
        self.assertTrue(out[0]["valid"])


# ─────────────────────────────────────────────── rules 2 and 4: the profile is closed; refusals are exit 2

PQ = __import__("base64").b64encode(bytes(1952)).decode()   # 1952 bytes: the length of an ML-DSA-65 key
GOOD = {"ledger": {"ledger_id": "a" * 64, "log_key": "d" * 64}, "pack": {"signature_domain": True},
        "archive": {"head_key": "b" * 64}}
WRONG_VALUES = [None, 0, 1, -1, 1.5, "", " ", "x", "A" * 64, [], [""], {}, {"a": 1}, True, False, "true"]


MIB = 1 << 20   # SPEC §23 rule 2, written here and not read from the module


class TestProfileIsClosed(Tmp):
    def refused(self, doc_or_bytes, why=None):
        p = self.write("p.json", doc_or_bytes)
        with self.assertRaises(VE.ProfileError) as cm:
            VE.load_profile(p)
        if why:
            self.assertIn(why, str(cm.exception))
        return str(cm.exception)

    def test_good_profile_reads(self):
        p = self.write("p.json", _profile(GOOD))
        prof = VE.load_profile(p)
        self.assertEqual(prof["sha256"], hashlib.sha256(_bytes(p)).hexdigest())
        self.assertEqual(prof["require"]["ledger"], GOOD["ledger"])

    def test_unknown_key_at_every_level(self):
        rnd = random.Random(20261123)
        names = ["x", "skip", "disable", "checks", "chain", "hash", "signature", "signatures", "closed_forms", "mode",
                 "warn", "policy", "Ledger", "ledger ", "LOG_KEY", "log-key", "é", "", "__proto__"]
        names += ["".join(rnd.choice("abcdefghijklmnopqrstuvwxyz_") for _ in range(rnd.randint(1, 12))) for _ in range(20)]
        n = 0
        for nm in names:
            for val in (True, False, None, "off", [], {}):
                d = _profile(json.loads(json.dumps(GOOD)))
                d[nm] = val
                if nm not in ("profile_format", "name", "require"):
                    self.refused(d, "unknown member")
                    n += 1
                d = _profile(json.loads(json.dumps(GOOD)))
                if nm not in VE._PROFILE_KINDS:
                    d["require"][nm] = val
                    self.refused(d)
                    n += 1
                for kind in VE._PROFILE_KINDS:
                    d = _profile(json.loads(json.dumps(GOOD)))
                    if (kind, nm) not in VE.REQUIREMENTS:
                        d["require"][kind][nm] = val
                        self.refused(d, "unknown member")
                        n += 1
        self.assertGreater(n, 1000)

    def test_attempts_to_turn_a_base_check_off(self):
        for kind in VE._PROFILE_KINDS:
            for cid in VE.CHECKS:
                for val in (False, "off", 0, None):
                    self.refused(_profile({kind: {cid: val}}), "unknown member")
                    self.refused(_profile({kind: {cid.split(".")[-1]: val}}))
            for (k, m), (_p, check, _n, _no) in VE.REQUIREMENTS.items():
                if k == kind and check is VE._v_true:
                    self.refused(_profile({kind: {m: False}}), "false turns nothing off")
        self.refused(_profile({"ledger": {"ledger_id": "a" * 64}}, skip=["ledger.chain"]), "unknown member")

    def test_wrong_types_for_every_member(self):
        n = 0
        for (kind, m) in VE.REQUIREMENTS:
            for val in WRONG_VALUES:
                if val is True and VE.REQUIREMENTS[(kind, m)][1] is VE._v_true:
                    continue
                sec = {m: val}
                for need in VE.REQUIREMENTS[(kind, m)][2]:
                    sec[need] = "c" * 64 if need != "tsa_certs" else [TSA_CERT]
                self.refused(_profile({kind: sec}))
                n += 1
        self.assertGreater(n, 150)
        for top, val in itertools.product(("profile_format", "name", "require"), WRONG_VALUES):
            d = _profile({"ledger": {"ledger_id": "a" * 64}})
            if top == "name" and isinstance(val, str) and val:   # 1 to 200 characters, spaces included (rule 2)
                continue
            d[top] = val
            self.refused(d)

    def test_duplicates_at_every_level(self):
        good = '{"profile_format":"%s","name":"t","require":{"ledger":{"ledger_id":"%s"}}}' % (VE.PROFILE_FORMAT, "a" * 64)
        dups = [good.replace('"name":"t"', '"name":"t","name":"t"'),
                good.replace('"name":"t"', '"name":"u","name":"t"'),
                good.replace('{"ledger":', '{"ledger":{"ledger_id":"%s"},"ledger":' % ("a" * 64)),
                good.replace('{"ledger_id"', '{"ledger_id":"%s","ledger_id"' % ("b" * 64)),
                good[:-1] + ',"profile_format":"%s"}' % VE.PROFILE_FORMAT]
        for d in dups:
            self.refused(d.encode(), "written twice")
        self.assertIsNotNone(VE.load_profile(self.write("ok.json", good.encode())))

    def test_empty_and_missing(self):
        self.refused({}, "missing member")
        self.refused(_profile({}), "requires nothing")
        self.refused(_profile({"ledger": {}}), "empty")
        self.refused({"profile_format": VE.PROFILE_FORMAT, "name": "t"}, "missing member require")
        self.refused({"profile_format": VE.PROFILE_FORMAT, "require": GOOD}, "missing member name")
        self.refused(_profile(GOOD, name="a" * 201))
        self.refused(_profile(GOOD, name="a\nb"))
        self.refused(_profile(GOOD, name="a\ud800"))
        self.refused(_profile(GOOD, profile_format="cryptovalid-verify-profile/2"))
        self.refused(_profile({"pack": {"tsa_crls": [TSA_CERT]}}), "needs require.pack.tsa_certs")
        self.refused(_profile({"ledger": {"log_pq_key": PQ}}), "needs require.ledger.log_key")
        self.refused(_profile({"ledger": {"tip_not_before": "2026-01-01T00:00:00Z"}}), "needs require.ledger.log_key")
        self.refused(_profile({"ledger": {"signed_tip": True}}), "unknown member")
        self.refused(_profile({"pack": {"ledger_pq_key": PQ}}), "needs require.pack.ledger_signer")

    def test_malformed_bytes(self):
        good = json.dumps(_profile(GOOD)).encode()
        for raw in (b"", b" ", good[:-1], good + b"x", b"\xef\xbb\xbf" + good, good.replace(b'"t"', b'"\xff"'),
                    b"[" * 100000 + b"]" * 100000, b"[]", b"null", b"1", b'"x"',
                    good.replace(b'"name"', b'"n":NaN,"name"'), good.replace(b'"name"', b'"n":Infinity,"name"'),
                    good.replace(b'"name"', b'"n":-Infinity,"name"'), good + b" " * (MIB + 1)):
            self.refused(raw)
        self.refused(b"\xef\xbb\xbf" + good, "byte order mark")
        for c in (b"NaN", b"Infinity", b"-Infinity"):
            self.refused(good.replace(b'"t"', c), "is not a JSON number")
        self.assertTrue(VE.load_profile(self.write("ws.json", good + b" " * (MIB - len(good)))))

    def test_paths_that_are_not_profiles(self):
        for p in (os.path.join(self.tmp, "missing.json"), self.tmp):
            with self.assertRaises(VE.ProfileError):
                VE.load_profile(p)
        fifo = os.path.join(self.tmp, "fifo")
        os.mkfifo(fifo)
        with self.assertRaises(VE.ProfileError):
            VE.load_profile(fifo)   # opened without blocking (§5 step 0): refused, never waited on

    def test_file_lists(self):
        for v in ([TSA_CERT, TSA_CERT], [os.path.join(self.tmp, "none.pem")], [SAMPLE], [self.tmp], ["a\x00b"]):
            self.refused(_profile({"pack": {"tsa_certs": v}}))
        shutil.copy(TSA_CERT, os.path.join(self.tmp, "ca.pem"))
        prof = VE.load_profile(self.write("p.json", _profile({"pack": {"tsa_certs": ["ca.pem"]}})))
        self.assertEqual(prof["require"]["pack"]["tsa_certs"], [os.path.join(self.tmp, "ca.pem")])   # from the profile's dir

    @unittest.skipUnless(_crypto(), "the CRL parser needs cryptography")
    def test_a_crl_file_that_is_not_a_crl(self):
        self.refused(_profile({"pack": {"tsa_certs": [TSA_CERT], "tsa_crls": [TSA_CERT]}}), "not a CRL")
        self.refused(_profile({"pack": {"tsa_certs": [TSA_CERT], "tsa_crls": [self.tmp]}}))

    def test_values_accepted(self):
        prof = VE.load_profile(self.write("p.json", _profile({"ledger": {
            "tip_not_before": "2026-01-01T00:00:00Z", "log_key": "c" * 64,
            "log_pq_key": PQ, "ledger_id": "e" * 64}})))
        self.assertEqual(len(prof["require"]["ledger"]), 4)
        for bad in ("2026-01-01", "2026-02-30T00:00:00Z", "yesterday", "2026-01-01T00:00:00"):
            self.refused(_profile({"ledger": {"log_key": "c" * 64, "tip_not_before": bad}}))
        for bad in (PQ[:-4], PQ + "\n", "@" * len(PQ), PQ[:-4] + "AAAA" + "AAAA"):
            self.refused(_profile({"ledger": {"log_key": "c" * 64, "log_pq_key": bad}}))

    def test_cli_refusals_write_nothing_on_stdout(self):
        bad = self.write("bad.json", _profile({"ledger": {"chain": False}}))
        good = self.write("good.json", _profile({"ledger": {"ledger_id": _first_id(SAMPLE)}}))
        cases = [("ledger", SAMPLE, "--profile", bad), ("auto", SAMPLE, "--profile", bad),
                 ("ledger", SAMPLE, "--profile", good, "--profile", good),
                 ("ap2", SAMPLE, "--profile", good), ("cldma", SAMPLE, "--profile", good),
                 ("checkpoint", SAMPLE, "--profile", good), ("ledger", SAMPLE, "--profile", self.tmp),
                 ("ledger", SAMPLE, "--profile")]
        for c in cases:
            rc, out, err = _run(*c)
            self.assertEqual(rc, 2, (c, out, err))
            self.assertEqual(out, "", c)
            self.assertNotIn("Traceback", err, c)

    def test_tiles_keeps_its_own_profile_option(self):
        """§23 rule 4: `tiles --profile` is the C2SP log profile of §14, never a profile file"""
        good = self.write("good.json", _profile({"ledger": {"ledger_id": _first_id(SAMPLE)}}))
        rc, out, err = _run("tiles", self.tmp, "--vkey", "x", "--profile", good)
        self.assertEqual(rc, 2, (out, err))
        self.assertIn("static-ct-api", err)


# ─────────────────────────────────────────────── rules 3 and 5: requirements, outcomes, the receipt

@unittest.skipUnless(_crypto(), "the signed tip and the signed pack need cryptography")
class TestProfileOutcomes(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import cryptovalid_tip
        import evidence_pack
        import signer
        cls.tmp = tempfile.mkdtemp(prefix="cvprof_")
        t = cls.tmp
        cls.key = signer.keygen(os.path.join(t, "k.key"))["public_key_hex"]
        cls.other = signer.keygen(os.path.join(t, "o.key"))["public_key_hex"]
        cls.ledger = os.path.join(t, "signed.jsonl")
        subprocess.run([sys.executable, os.path.join(HERE, "signer.py"), "sign", SAMPLE, cls.ledger,
                        os.path.join(t, "k.key")], check=True, capture_output=True)
        cryptovalid_tip.sign_tip(cls.ledger, os.path.join(t, "k.key"))
        cls.notip = os.path.join(t, "notip.jsonl")
        shutil.copy(cls.ledger, cls.notip)
        cls.tampered = os.path.join(t, "tampered.jsonl")
        shutil.copy(TAMPERED, cls.tampered)
        cls.pack = os.path.join(t, "pack")
        evidence_pack.build_pack([cls.ledger], cls.pack, sign_key=os.path.join(t, "k.key"))
        cls.upack = os.path.join(t, "upack")
        evidence_pack.build_pack([cls.notip], cls.upack)
        cls.id = _first_id(cls.ledger)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, True)

    def prof(self, require, name="t"):
        fd, p = tempfile.mkstemp(suffix=".json", dir=self.tmp)
        with os.fdopen(fd, "w") as f:
            json.dump(_profile(require, name), f)
        return p

    def verify(self, cmd, path, require):
        p = self.prof(require)
        rc, out, err = _run(cmd, path, "--profile", p)
        self.assertIn(rc, (0, 1), err)
        r = json.loads(out)
        self.assertEqual(rc, 0 if r["valid"] else 1)
        self.assertEqual(r["profile"]["sha256"], hashlib.sha256(_bytes(p)).hexdigest())
        return r

    def states(self, r):
        return {x["id"]: x["state"] for x in r["profile"]["requirements"]}

    def test_ledger_requirements(self):
        cases = [({"log_key": self.key}, self.ledger, "met"), ({"log_key": self.other}, self.ledger, "not_met"),
                 ({"log_key": self.key}, self.notip, "not_met"),
                 ({"ledger_id": self.id}, self.ledger, "met"), ({"ledger_id": "0" * 64}, self.ledger, "not_met"),
                 ({"tip_not_before": "2000-01-01T00:00:00Z", "log_key": self.key}, self.ledger, "met"),
                 ({"tip_not_before": "2999-01-01T00:00:00Z", "log_key": self.key}, self.ledger, "not_met")]
        for req, path, want in cases:
            r = self.verify("ledger", path, {"ledger": req})
            if want == "met":
                self.assertTrue(r["valid"], req)
                self.assertEqual(r["profile"]["outcome"], "met")
                self.assertTrue(all(s == "met" for s in self.states(r).values()), r["profile"])
            else:
                self.assertFalse(r["valid"], req)
                self.assertEqual(r["profile"]["outcome"], "not_met", req)
                self.assertIn("not_met", self.states(r).values())
            self.assertEqual(r["profile"]["together"] is None, len(req) == 1)
            self.assertEqual(r["profile"]["applies_to"], "ledger")

    def test_pack_requirements(self):
        cases = [({"manifest_signer": self.key}, self.pack, "met"), ({"manifest_signer": self.other}, self.pack, "not_met"),
                 ({"manifest_signer": self.key}, self.upack, "not_met"), ({"ledger_signer": self.key}, self.pack, "met"),
                 ({"ledger_signer": self.other}, self.pack, "not_met"), ({"signature_domain": True}, self.pack, "met"),
                 ({"tsa_certs": [TSA_CERT]}, self.pack, "not_met")]   # §22 rule 7: no token = not verified
        for req, path, want in cases:
            r = self.verify("pack", path, {"pack": req})
            self.assertEqual(r["valid"], want == "met", (req, r["profile"]))
            self.assertEqual(r["profile"]["outcome"], want, req)
            r2 = self.verify("auto", path, {"pack": req})
            self.assertEqual((r2["valid"], r2["profile"]["outcome"]), (r["valid"], want), req)

    def test_a_profile_never_makes_valid_what_is_not(self):
        reqs = [{"ledger": {"ledger_id": _first_id(TAMPERED)}}, {"ledger": {"log_key": self.key}},
                {"ledger": {"ledger_id": self.id}}, {"pack": {"signature_domain": True}}]
        for path, req in itertools.product((self.tampered, os.path.join(self.tmp, "missing.jsonl")), reqs):
            cmd = "auto" if "pack" in req else "ledger"
            base = json.loads(_run(cmd, path)[1])
            self.assertFalse(base["valid"])
            r = self.verify(cmd, path, req)
            self.assertFalse(r["valid"], req)
            self.assertEqual(_strip(r), _strip(base), req)   # the layers of (a), untouched

    def test_profile_for_another_kind_is_not_applicable(self):
        r = self.verify("auto", self.ledger, {"pack": {"signature_domain": True}})
        self.assertEqual((r["valid"], r["profile"]["outcome"], r["profile"]["applies_to"]), (False, "not_applicable", "ledger"))
        r = self.verify("auto", self.pack, {"ledger": {"log_key": self.key}, "pack": {"manifest_signer": self.key}})
        self.assertEqual((r["valid"], r["profile"]["outcome"], r["profile"]["applies_to"]), (True, "met", "pack"))

    def test_requirements_met_do_not_rescue_a_failed_base(self):
        """rule 3: valid needs (a) valid, whatever the requirements say"""
        prof = VE.load_profile(self.prof({"ledger": {"ledger_id": self.id}}))
        with mock.patch.object(VE, "_run_state", lambda k, p, pins: ("met", "")):
            r = VE.apply_profile(VE.verify_ledger(self.tampered), self.tampered, prof)
        self.assertEqual((r["valid"], r["profile"]["outcome"]), (False, "met"))

    def test_together_decides_too(self):
        r = self.verify("ledger", self.ledger, {"ledger": {"log_key": self.key, "ledger_id": self.id}})
        self.assertEqual((r["valid"], r["profile"]["together"]), (True, "met"))
        real = VE._run_state
        with mock.patch.object(VE, "_run_state", lambda k, p, pins: ("not_met", "x") if len(pins) > 1 else real(k, p, pins)):
            r = VE.apply_profile(VE.verify_ledger(self.ledger), self.ledger, VE.load_profile(
                self.prof({"ledger": {"log_key": self.key, "ledger_id": self.id}})))
        self.assertEqual((r["valid"], r["profile"]["together"], r["profile"]["outcome"]), (False, "not_met", "not_met"))

    def test_not_evaluated_is_not_valid(self):
        from verifier import CheckNotRun
        prof = VE.load_profile(self.prof({"pack": {"manifest_signer": self.key}}))
        base = VE.verify_pack(self.pack)
        self.assertTrue(base["valid"])

        def boom(pack_dir, **pins):
            if pins:
                raise CheckNotRun("simulated")
            return base
        with mock.patch.object(VE, "verify_pack", boom):
            r = VE.apply_profile(dict(base), self.pack, prof)
        self.assertEqual((r["valid"], r["profile"]["outcome"], r["profile"]["requirements"][0]["state"]),
                         (False, "not_evaluated", "not_evaluated"))

    def test_check_not_run_with_a_profile(self):
        from verifier import CheckNotRun
        p = self.prof({"pack": {"manifest_signer": self.key}})

        def boom(path, **pins):
            raise CheckNotRun("simulated", receipt={"kind": "pack", "valid": True, "layers": []})
        out = []
        with mock.patch.object(VE, "verify_pack", boom), \
                mock.patch("verifier.check_not_run_exit", lambda e, text: out.append(json.loads(text)) or 74):
            self.assertEqual(VE._main(["pack", self.pack, "--profile", p]), 74)
        self.assertEqual((out[0]["valid"], out[0]["profile"]["outcome"]), (False, "not_evaluated"))

    def test_generated_profiles_only_add(self):
        """every subset of the ledger requirements, with right and wrong values: valid only when the run without a
        profile is valid and each requirement, alone and together, holds"""
        rnd = random.Random(1123)
        vals = {"log_key": [self.key, self.other], "ledger_id": [self.id, "1" * 64],
                "tip_not_before": ["2000-01-01T00:00:00Z", "2999-01-01T00:00:00Z"]}
        n = 0
        for path in (self.ledger, self.notip, self.tampered):
            base_valid = VE.verify_ledger(path)["valid"]
            for k, _draw in itertools.product(range(1, 4), range(3)):
                for names in itertools.combinations(sorted(vals), k):
                    req = {m: rnd.choice(vals[m]) for m in names}
                    if "tip_not_before" in req:
                        req.setdefault("log_key", rnd.choice(vals["log_key"]))
                    r = VE.apply_profile(VE.verify_ledger(path), path, VE.load_profile(self.prof({"ledger": req})))
                    pins = {VE.REQUIREMENTS[("ledger", m)][0]: v for m, v in req.items()}
                    alone = [VE.verify_ledger(path, **{VE.REQUIREMENTS[("ledger", m)][0]: v,
                                                       **({"trusted_pubkey_hex": req["log_key"]} if m == "tip_not_before" else {})})["valid"]
                             for m, v in req.items()] + [VE.verify_ledger(path, **pins)["valid"]]
                    self.assertEqual(r["valid"], base_valid and all(alone), (path, req, r["profile"]))
                    n += 1
        self.assertEqual(n, 3 * 3 * 7)


if __name__ == "__main__":
    unittest.main()
