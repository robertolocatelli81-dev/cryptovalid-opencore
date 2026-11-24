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
    p = subprocess.run(CLI + [str(a) for a in args], capture_output=True, text=True, encoding="utf-8", timeout=120)
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
        from test_platforms_20261124 import fifo as make_fifo   # Windows: a named pipe
        fifo = make_fifo(self, os.path.join(self.tmp, "fifo"))
        with self.assertRaises(VE.ProfileError):
            VE.load_profile(fifo)   # opened without blocking (§5 step 0): refused, never waited on

    def test_file_lists(self):
        for v in ([TSA_CERT, TSA_CERT], [os.path.join(self.tmp, "none.pem")], [SAMPLE], [self.tmp], ["a\x00b"]):
            self.refused(_profile({"pack": {"tsa_certs": v}}))
        shutil.copy(TSA_CERT, os.path.join(self.tmp, "ca.pem"))
        prof = VE.load_profile(self.write("p.json", _profile({"pack": {"tsa_certs": ["ca.pem"]}})))
        self.assertEqual(prof["require"]["pack"]["tsa_certs"], [_bytes(TSA_CERT)])   # from the profile's dir, read once
        self.assertEqual(prof["files"], [{"requirement": "pack.require.tsa_certs", "path": "ca.pem",
                                          "sha256": hashlib.sha256(_bytes(TSA_CERT)).hexdigest()}])

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
            r = VE.apply_profile(VE.verify_ledger(self.tampered), self.tampered, prof, VE.evidence_fingerprint(self.tampered))
        self.assertEqual((r["valid"], r["profile"]["outcome"]), (False, "met"))

    def test_together_decides_too(self):
        r = self.verify("ledger", self.ledger, {"ledger": {"log_key": self.key, "ledger_id": self.id}})
        self.assertEqual((r["valid"], r["profile"]["together"]), (True, "met"))
        real = VE._run_state
        with mock.patch.object(VE, "_run_state", lambda k, p, pins: ("not_met", "x") if len(pins) > 1 else real(k, p, pins)):
            r = VE.apply_profile(VE.verify_ledger(self.ledger), self.ledger, VE.load_profile(
                self.prof({"ledger": {"log_key": self.key, "ledger_id": self.id}})), VE.evidence_fingerprint(self.ledger))
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
            r = VE.apply_profile(dict(base), self.pack, prof, VE.evidence_fingerprint(self.pack))
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
                    r = VE.apply_profile(VE.verify_ledger(path), path, VE.load_profile(self.prof({"ledger": req})),
                                         VE.evidence_fingerprint(path))
                    pins = {VE.REQUIREMENTS[("ledger", m)][0]: v for m, v in req.items()}
                    alone = [VE.verify_ledger(path, **{VE.REQUIREMENTS[("ledger", m)][0]: v,
                                                       **({"trusted_pubkey_hex": req["log_key"]} if m == "tip_not_before" else {})})["valid"]
                             for m, v in req.items()] + [VE.verify_ledger(path, **pins)["valid"]]
                    self.assertEqual(r["valid"], base_valid and all(alone), (path, req, r["profile"]))
                    n += 1
        self.assertEqual(n, 3 * 3 * 7)


# ─────────────────────────────────────────────── review of da0c51a (23/11/2026)

class TestReviewClosed(Tmp):
    def refused(self, doc):
        with self.assertRaises(VE.ProfileError) as cm:
            VE.load_profile(self.write("p.json", doc))
        return str(cm.exception)

    def test_a_member_of_another_kind_is_unknown_in_this_one(self):
        """a known member in the wrong section is refused, never read past"""
        for (kind, m), other in itertools.product(VE.REQUIREMENTS, VE._PROFILE_KINDS):
            if (other, m) not in VE.REQUIREMENTS:
                self.assertIn("unknown member", self.refused(_profile({other: {m: "a" * 64}})), (other, m))

    def test_a_key_ends_where_its_64_characters_end(self):
        for bad in ("a" * 64 + "\n", "\n" + "a" * 64, "a" * 63 + "\n", "a" * 65, "A" * 64):
            for kind, m in (("ledger", "ledger_id"), ("ledger", "log_key"), ("pack", "manifest_signer"),
                            ("pack", "ledger_signer"), ("archive", "head_key")):
                self.refused(_profile({kind: {m: bad}}))

    def test_sha256_is_of_the_bytes_as_read(self):
        raw = b"\n " + json.dumps(_profile({"ledger": {"ledger_id": "a" * 64}})).encode() + b" \n\n"
        self.assertEqual(VE.load_profile(self.write("p.json", raw))["sha256"], hashlib.sha256(raw).hexdigest())

    def test_the_mini_verifier_never_drops_a_requirement(self):
        """rule 3: where only verify_ledger.py is beside this file, a pin is a FAIL, not a verification without it"""
        mini = mock.Mock()   # stands for verify_ledger.py, which takes a path and nothing else
        mini.verify_ledger.side_effect = lambda path: {"verdict": "PASS"}
        with mock.patch.object(VE, "_need_opencore", lambda: False), mock.patch.dict(sys.modules, {"verify_ledger": mini}):
            self.assertTrue(VE.verify_ledger(SAMPLE)["valid"])
            r = VE.verify_ledger(SAMPLE, expect_ledger_id=_first_id(SAMPLE))
        self.assertEqual(mini.verify_ledger.call_count, 1)
        self.assertFalse(r["valid"])
        self.assertIn("need verifier.py", r["layers"][0]["detail"])

    def test_outcome_order_and_requirement_ids(self):
        """rule 5: not_met wins over not_evaluated; the ids are the ones --list-checks prints; a not_met names the layer"""
        prof = VE.load_profile(self.write("p.json", _profile({"ledger": {"log_key": "c" * 64, "ledger_id": "e" * 64}})))
        listed = {x["id"] for x in VE.list_checks("ledger")}
        for states, want in ((("not_evaluated", "not_met", "met"), "not_met"), (("not_met", "not_evaluated", "met"), "not_met"),
                             (("met", "not_evaluated", "met"), "not_evaluated"), (("met", "met", "not_evaluated"), "not_evaluated"),
                             (("met", "met", "not_met"), "not_met"), (("met", "met", "met"), "met")):
            it = iter(states)
            with mock.patch.object(VE, "_run_state", lambda k, p, pins: (next(it), "")):
                r = VE.apply_profile(VE.verify_ledger(SAMPLE), SAMPLE, prof, VE.evidence_fingerprint(SAMPLE))
            self.assertEqual((r["profile"]["outcome"], r["valid"]), (want, want == "met"), states)
            self.assertEqual([x["id"] for x in r["profile"]["requirements"]], ["ledger.require.log_key", "ledger.require.ledger_id"])
            self.assertLessEqual({x["id"] for x in r["profile"]["requirements"]}, listed)
        r = VE.apply_profile(VE.verify_ledger(SAMPLE), SAMPLE, prof, VE.evidence_fingerprint(SAMPLE))
        self.assertEqual([x["detail"].split(":")[0] for x in r["profile"]["requirements"]], ["ledger.chain"] * 2)

    def test_the_layer_names_are_those_of_0_28_1(self):
        """rule 6: the names written in a receipt did not change; the digest is of the sorted names passed to _layer()
        in verify_evidence.py of 0.28.1 (24 names), measured on 16b8e87"""
        names = sorted({v[0] for v in VE.CHECKS.values()})
        self.assertEqual(len(names), 24)
        self.assertEqual(hashlib.sha256(json.dumps(names, ensure_ascii=True).encode()).hexdigest(),
                         "f2eca2976971d8dbf547e1dc799662e6742fb7abfda483bf169be88209642c43")

    def test_layers_of_a_routed_receipt_are_listed_for_auto_and_for_the_kind(self):
        r = json.loads(_run("auto", SAMPLE)[1])
        for cmd in ("auto", r["kind"]):
            self.assertLessEqual({x["id"] for x in r["layers"]}, {x["id"] for x in VE.list_checks(cmd)}, cmd)
        for cid, (_layer, cmds, _when, _norm) in VE.CHECKS.items():
            self.assertEqual(cmds[-1], "auto", cid)   # auto routes to every command of the table (SPEC §12)

    def test_a_ledger_from_a_pipe_is_not_read_again(self):
        """rule 3: (b) and (c) read the path again; a pipe that gave ledger A to (a) and ledger B afterwards was
        `met` for A with B's ledger_id (review of da0c51a): now no requirement is run, not_evaluated, not valid"""
        import threading
        import time
        other = os.path.join(HERE, "spec", "vectors", "beacon", "conformance", "ledgers", "record_salt_120_bits.jsonl")
        self.assertNotEqual(_first_id(other), _first_id(SAMPLE))
        from test_platforms_20261124 import fifo_at
        fifo = fifo_at(self, os.path.join(self.tmp, "l.jsonl"))

        served = []

        def feed():
            try:
                for src in (SAMPLE, other):
                    with open(fifo, "wb") as f:
                        f.write(_bytes(src))
                    served.append(src)
                    time.sleep(1)
            except OSError:   # the second open finds no reader, or the directory is gone: nothing read it again
                pass
        threading.Thread(target=feed, daemon=True).start()
        rc, out, err = _run("ledger", fifo, "--profile", self.write("p.json", _profile({"ledger": {
            "ledger_id": _first_id(other), "log_key": "c" * 64}})))
        r = json.loads(out)
        self.assertEqual((rc, r["valid"], r["layers"][0]["status"], r["profile"]["outcome"]), (1, False, "PASS", "not_evaluated"), err)
        self.assertEqual([(x["state"], "not a regular file" in x["detail"]) for x in r["profile"]["requirements"]],
                         [("not_evaluated", True)] * 2)
        self.assertEqual(r["profile"]["together"], "not_evaluated")
        self.assertEqual(served, [SAMPLE])   # the path was opened once: nothing read it again, nothing waited on
        try:   # let the feeder end
            fd = os.open(fifo, os.O_RDONLY | os.O_NONBLOCK)
            os.close(fd)
        except OSError:
            pass


@unittest.skipUnless(_crypto(), "signed packs and archives need cryptography")
class TestReviewOutcomes(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import cryptovalid_ingest
        import evidence_pack
        import signer
        from cryptovalid_kms import FileKeyBackend
        cls.tmp = t = tempfile.mkdtemp(prefix="cvprof_")
        cls.k1 = signer.keygen(os.path.join(t, "k1.key"))["public_key_hex"]   # signs the ledger and the archive
        cls.k2 = signer.keygen(os.path.join(t, "k2.key"))["public_key_hex"]   # signs the manifest
        led = os.path.join(t, "signed.jsonl")
        subprocess.run([sys.executable, os.path.join(HERE, "signer.py"), "sign", SAMPLE, led, os.path.join(t, "k1.key")],
                       check=True, capture_output=True)
        cls.pack = os.path.join(t, "pack")
        evidence_pack.build_pack([led], cls.pack, sign_key=os.path.join(t, "k2.key"))
        cls.plain = os.path.join(t, "plain")
        evidence_pack.build_pack([SAMPLE], cls.plain)
        cls.arch, cls.uarch = os.path.join(t, "arch"), os.path.join(t, "uarch")
        for d, be in ((cls.arch, FileKeyBackend(os.path.join(t, "k1.key"))), (cls.uarch, None)):
            os.mkdir(d)
            w = cryptovalid_ingest.Ingestor(d, batch_size=4, backend=be)
            for i in range(9):
                w.append({"i": i})
            w.seal()
            w.close()

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, True)

    def outcome(self, cmd, path, require):
        fd, p = tempfile.mkstemp(suffix=".json", dir=self.tmp)
        with os.fdopen(fd, "w") as f:
            json.dump(_profile(require), f)
        rc, out, err = _run(cmd, path, "--profile", p)
        r = json.loads(out)
        self.assertEqual(rc, 0 if r["valid"] else 1, err)
        self.assertEqual(r["valid"], r["profile"]["outcome"] == "met")
        return r["profile"]["outcome"], r

    def test_the_two_signers_of_a_pack_are_two_requirements(self):
        for req, want in (({"ledger_signer": self.k1}, "met"), ({"ledger_signer": self.k2}, "not_met"),
                          ({"manifest_signer": self.k2}, "met"), ({"manifest_signer": self.k1}, "not_met"),
                          ({"manifest_signer": self.k2, "ledger_signer": self.k1}, "met"),
                          ({"manifest_signer": self.k1, "ledger_signer": self.k2}, "not_met")):
            self.assertEqual(self.outcome("pack", self.pack, {"pack": req})[0], want, req)

    def test_signature_domain_does_not_ask_for_a_signature(self):
        """rule 2: an unsigned 1.2 pack and an unsigned archive meet it; the signer members ask for the signature"""
        self.assertEqual(self.outcome("pack", self.plain, {"pack": {"signature_domain": True}})[0], "met")
        self.assertEqual(self.outcome("pack", self.plain, {"pack": {"signature_domain": True, "manifest_signer": self.k2}})[0], "not_met")
        self.assertEqual(self.outcome("archive", self.uarch, {"archive": {"signature_domain": True}})[0], "met")
        self.assertEqual(self.outcome("archive", self.uarch, {"archive": {"signature_domain": True, "head_key": self.k1}})[0], "not_met")

    def test_archive_requirements(self):
        base = json.loads(_run("archive", self.arch)[1])
        self.assertTrue(base["valid"])
        for req, want in (({"head_key": self.k1}, "met"), ({"head_key": self.k2}, "not_met"), ({"signature_domain": True}, "met"),
                          ({"head_key": self.k1, "signature_domain": True}, "met"), ({"tsa_certs": [TSA_CERT]}, "not_met"),
                          ({"head_key": self.k1, "tsa_certs": [TSA_CERT]}, "not_met")):
            for cmd in ("archive", "auto"):
                got, r = self.outcome(cmd, self.arch, {"archive": req})
                self.assertEqual(got, want, (cmd, req, r["profile"]))
                self.assertEqual(_strip(r), _strip(base))
        self.assertEqual(self.outcome("archive", self.uarch, {"archive": {"head_key": self.k1}})[0], "not_met")
        with self.assertRaises(VE.ProfileError):
            VE.load_profile(self.prof_file({"archive": {"signature_domain": "a" * 64}}))

    def prof_file(self, require):
        fd, p = tempfile.mkstemp(suffix=".json", dir=self.tmp)
        with os.fdopen(fd, "w") as f:
            json.dump(_profile(require), f)
        return p

    @unittest.skipUnless(shutil.which("openssl"), "the local TSA needs openssl")
    def test_a_pinned_tsa_is_met_by_its_token_and_the_receipt_names_the_files(self):
        """rule 2: tsa_certs is met by a token of the pinned TSA and by nothing else, tsa_crls by a CRL that does not
        revoke it; rule 5: `files`; the bytes read with the profile are the ones every run uses"""
        import base64
        import evidence_pack
        import test_tsa_revocation_20261116 as TR
        lab, other = TR.Lab(self.tmp, "tsa"), TR.Lab(self.tmp, "tsa2")
        p = os.path.join(self.tmp, "stamped")
        evidence_pack.build_pack([SAMPLE], p)
        mf = os.path.join(p, "MANIFEST.json")
        m = json.loads(_bytes(mf))
        tok = lab.token(bytes.fromhex(m["manifest_digest_sha256"]))
        m["rfc3161_timestamp"] = {"anchored": True, "tsa": "local", "tsr_b64": base64.b64encode(tok).decode()}
        with open(mf, "w", encoding="utf-8", newline="") as f:
            json.dump(m, f)
        self.assertTrue(json.loads(_run("pack", p)[1])["valid"])
        pin, crl = os.path.join(self.tmp, "pin.pem"), os.path.join(self.tmp, "pin.crl")
        shutil.copy(lab.j("ca.crt"), pin)
        shutil.copy(lab.crl(), crl)
        got, r = self.outcome("pack", p, {"pack": {"tsa_certs": ["pin.pem"], "tsa_crls": ["pin.crl"]}})
        self.assertEqual((got, r["profile"]["together"]), ("met", "met"), r["profile"])
        self.assertEqual(r["profile"]["files"], [
            {"requirement": "pack.require.tsa_certs", "path": "pin.pem", "sha256": hashlib.sha256(_bytes(pin)).hexdigest()},
            {"requirement": "pack.require.tsa_crls", "path": "pin.crl", "sha256": hashlib.sha256(_bytes(crl)).hexdigest()}])
        self.assertEqual(self.outcome("pack", p, {"pack": {"tsa_certs": [other.j("ca.crt")]}})[0], "not_met")
        self.assertEqual(self.outcome("pack", self.plain, {"pack": {"tsa_certs": ["pin.pem"]}})[0], "not_met")
        prof = VE.load_profile(self.prof_file({"pack": {"tsa_certs": ["pin.pem"]}}))
        shutil.copy(other.j("ca.crt"), pin)   # replaced after the profile was read: the runs use the bytes read
        r = VE.apply_profile(VE.verify_pack(p), p, prof, VE.evidence_fingerprint(p))
        self.assertEqual((r["valid"], r["profile"]["outcome"]), (True, "met"))
        self.assertNotEqual(r["profile"]["files"][0]["sha256"], hashlib.sha256(_bytes(pin)).hexdigest())
        shutil.copy(lab.j("ca.crt"), pin)
        TR.tick()
        lab.revoke("keyCompromise")
        shutil.copy(lab.crl(), crl)
        got, r = self.outcome("pack", p, {"pack": {"tsa_certs": ["pin.pem"], "tsa_crls": ["pin.crl"]}})
        self.assertEqual([x["state"] for x in r["profile"]["requirements"]] + [r["profile"]["together"], got],
                         ["met", "not_met", "not_met", "not_met"], r["profile"])


# ─────────────────────────────────────────────── rule 3 (d): the evidence read by every run is the same

class TestEvidenceUnchanged(Tmp):
    """SPEC §23 rule 3 (d): runs (a), (b) and (c) read the path more than once; a change in between leaves the outcome
    not_evaluated and the result not valid. Added after the review of a156b15, which left this case declared only.
    Review of 7d87346: this class stood after `unittest.main()` and never ran as `python3 test_....py` (the way the CI
    runs it); run, two of its tests were red in 19 of 25 runs (a file rewritten in the clock tick of its last change
    keeps its timestamps), and a path given as a symbolic link was not seen to change. The fingerprint now follows
    links and holds the SHA-256 of every regular file."""

    def ledger(self):
        p = os.path.join(self.tmp, "l.jsonl")
        shutil.copy(SAMPLE, p)
        return p

    def test_fingerprint_sees_every_kind_of_change(self):
        p = self.ledger()
        d = os.path.join(self.tmp, "d")
        os.mkdir(d)
        shutil.copy(SAMPLE, os.path.join(d, "a.jsonl"))
        f0, g0 = VE.evidence_fingerprint(p), VE.evidence_fingerprint(d)
        self.assertIsNotNone(f0)
        self.assertEqual(VE.evidence_fingerprint(p), f0)          # nothing changed: same
        self.assertEqual(VE.evidence_fingerprint(d), g0)
        st = os.stat(p)
        data = bytearray(_bytes(p))
        data[len(data) // 2] ^= 1
        with open(p, "r+b") as f:                                  # one bit, in place, same size, at once (the same
            f.write(data)                                          # clock tick), times set back: the bytes differ
        os.utime(p, ns=(st.st_atime_ns, st.st_mtime_ns))
        self.assertNotEqual(VE.evidence_fingerprint(p), f0)
        q = os.path.join(self.tmp, "q.jsonl")                       # replaced by rename: another inode
        shutil.copy(SAMPLE, q)
        f1 = VE.evidence_fingerprint(p)
        os.replace(q, p)
        self.assertNotEqual(VE.evidence_fingerprint(p), f1)
        with open(os.path.join(d, "b.jsonl"), "wb") as f:          # an entry added to a directory
            f.write(b"x")
        self.assertNotEqual(VE.evidence_fingerprint(d), g0)
        self.assertIsNone(VE.evidence_fingerprint(os.path.join(self.tmp, "missing")))

    def test_fingerprint_does_not_follow_links_and_is_bounded(self):
        d = os.path.join(self.tmp, "d")
        os.mkdir(d)
        self.assertIsNotNone(VE.evidence_fingerprint(d))
        os.symlink(self.tmp, os.path.join(d, "loop"))               # a link to a directory below the path: not walked
        self.assertIsNone(VE.evidence_fingerprint(d))               # (it would never end), so no fingerprint
        os.remove(os.path.join(d, "loop"))
        shutil.copy(SAMPLE, os.path.join(d, "a.jsonl"))
        with mock.patch.object(VE, "FINGERPRINT_LIMIT", 1):         # the directory and one entry
            self.assertIsNone(VE.evidence_fingerprint(d))
        with mock.patch.object(VE, "FINGERPRINT_LIMIT", 2):
            self.assertIsNotNone(VE.evidence_fingerprint(d))

    def test_fingerprint_follows_links_to_what_the_runs_read(self):
        real = self.ledger()
        link = os.path.join(self.tmp, "link.jsonl")
        os.symlink(real, link)
        f0 = VE.evidence_fingerprint(link)
        self.assertEqual(VE.evidence_fingerprint(link), f0)
        self.assertEqual(f0[0][-1], hashlib.sha256(_bytes(real)).hexdigest())   # the bytes behind the link
        with open(real, "ab") as f:                                 # the file the link names is rewritten
            f.write(b"\n")
        f1 = VE.evidence_fingerprint(link)
        self.assertNotEqual(f1, f0)
        other = os.path.join(self.tmp, "other.jsonl")
        shutil.copy(real, other)
        os.remove(link)
        os.symlink(other, link)                                     # the link names another file with the same bytes
        self.assertNotEqual(VE.evidence_fingerprint(link), f1)
        d = os.path.join(self.tmp, "d")
        os.mkdir(d)
        shutil.copy(SAMPLE, os.path.join(d, "a.jsonl"))
        ld = os.path.join(self.tmp, "ld")
        os.symlink(d, ld)                                           # the path is a link to a directory: walked
        g0 = VE.evidence_fingerprint(ld)
        self.assertEqual(len(g0), 2)
        with open(os.path.join(d, "b"), "wb") as f:
            f.write(b"x")
        self.assertEqual(len(VE.evidence_fingerprint(ld)), 3)
        outside = os.path.join(self.tmp, "outside.bin")
        with open(outside, "wb") as f:
            f.write(b"A" * 64)
        os.symlink(outside, os.path.join(d, "l.bin"))               # a link below the path to a file outside it
        h0 = VE.evidence_fingerprint(d)
        with open(outside, "r+b") as f:
            f.write(b"B" * 64)
        self.assertNotEqual(VE.evidence_fingerprint(d), h0)
        os.symlink(os.path.join(self.tmp, "nothing"), os.path.join(d, "dangling"))
        self.assertIsNone(VE.evidence_fingerprint(d))

    def test_fingerprint_holds_ctime_and_inode(self):
        import time
        p = self.ledger()
        st, data, f0 = os.stat(p), _bytes(p), VE.evidence_fingerprint(p)
        time.sleep(0.05)                                            # past the clock tick of the file's last change
        with open(p, "r+b") as f:                                   # the same bytes, in place, mtime set back:
            f.write(data)                                           # only ctime moved
        os.utime(p, ns=(st.st_atime_ns, st.st_mtime_ns))
        self.assertNotEqual(VE.evidence_fingerprint(p), f0)
        for k in range(20):                                         # a copy with the same bytes and mtime renamed over
            p = os.path.join(self.tmp, "i%d" % k)                   # it at once: within one tick only the inode differs
            shutil.copy(SAMPLE, p)
            f0 = VE.evidence_fingerprint(p)
            shutil.copy2(p, p + ".new")
            os.replace(p + ".new", p)
            self.assertNotEqual(VE.evidence_fingerprint(p), f0, k)

    def test_cli_takes_the_fingerprint_before_the_first_run(self):
        """a ledger that loses its last entry right after run (a) read it: still valid, the requirement still met, but
        the runs did not read the same bytes"""
        p = self.ledger()
        prof = self.write("p.json", _profile({"ledger": {"ledger_id": _first_id(p)}}))
        code = (
            "import sys; sys.path.insert(0, %r); import verify_evidence as VE\n"
            "real, done = VE.verify_ledger, []\n"
            "def once(path, **pins):\n"
            "    r = real(path, **pins)\n"
            "    if not done:\n"
            "        done.append(1)\n"
            "        lines = open(path, 'rb').read().splitlines(keepends=True)\n"
            "        open(path, 'wb').write(b''.join(lines[:-1]))\n"
            "    return r\n"
            "VE.verify_ledger = once\n"
            "sys.exit(VE._main(['ledger', %r, '--profile', %r]))\n" % (HERE, p, prof))
        r = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, encoding="utf-8", timeout=120)
        out = json.loads(r.stdout)
        self.assertEqual((r.returncode, out["valid"], out["profile"]["evidence_unchanged"], out["profile"]["outcome"],
                          [x["state"] for x in out["profile"]["requirements"]]),
                         (1, False, False, "not_evaluated", ["met"]), r.stderr)

    def test_fingerprint_reads_every_byte(self):
        big = os.path.join(self.tmp, "big.bin")
        with open(big, "wb") as f:
            f.write(b"\0" * ((3 << 20) + 5))                        # more than one block of the reader
        st = os.stat(big)
        f0 = VE.evidence_fingerprint(big)
        with open(big, "r+b") as f:
            f.seek(-1, os.SEEK_END)
            f.write(b"\1")
        os.utime(big, ns=(st.st_atime_ns, st.st_mtime_ns))
        f1 = VE.evidence_fingerprint(big)
        self.assertNotEqual(f1, f0)
        self.assertEqual((f0[0][-1], f1[0][-1]), (hashlib.sha256(b"\0" * ((3 << 20) + 5)).hexdigest(),
                                                  hashlib.sha256(_bytes(big)).hexdigest()))

    @unittest.skipUnless(hasattr(os, "mkfifo"), "no FIFO here")
    def test_fingerprint_never_waits_on_a_fifo(self):
        d = os.path.join(self.tmp, "d")
        os.mkdir(d)
        os.mkfifo(os.path.join(d, "pipe"))                           # no writer: an open() would wait without end
        code = "import sys; sys.path.insert(0, %r); import verify_evidence as VE; print(VE.evidence_fingerprint(%r) is not None)" % (HERE, d)
        p = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, encoding="utf-8", timeout=60)
        self.assertEqual((p.returncode, p.stdout.strip()), (0, "True"), p.stderr)

    def _apply(self, path, change, target=None):
        """`change`: None, "rewrite" (the file loses its last entry, in place: still a valid ledger with the same
        first entry, so each run alone is fine) or "rename" (a copy with the same bytes takes its place)"""
        target = target or path
        prof = VE.load_profile(self.write("p.json", _profile({"ledger": {"ledger_id": _first_id(path)}})))
        before = VE.evidence_fingerprint(path)
        r = VE.verify_ledger(path)
        self.assertTrue(r["valid"])
        real = VE._run_state

        def run(kind, p, pins):
            if change == "rewrite":
                lines = _bytes(target).splitlines(keepends=True)
                with open(target, "wb") as f:
                    f.write(b"".join(lines[:-1]))
            elif change == "rename":
                shutil.copy(target, target + ".new")
                os.replace(target + ".new", target)
            return real(kind, p, pins)
        with mock.patch.object(VE, "_run_state", run):
            return VE.apply_profile(r, path, prof, before)

    def test_a_change_between_runs_leaves_it_not_evaluated(self):
        r = self._apply(self.ledger(), change=None)
        self.assertEqual((r["valid"], r["profile"]["outcome"], r["profile"]["evidence_unchanged"]), (True, "met", True))
        link = os.path.join(self.tmp, "link.jsonl")
        os.symlink(self.ledger(), link)
        r = self._apply(link, change=None)                         # a link that does not change: no false refusal
        self.assertEqual((r["valid"], r["profile"]["outcome"], r["profile"]["evidence_unchanged"]), (True, "met", True))
        for change in ("rewrite", "rename"):
            for path, target in ((self.ledger(), None), (link, self.ledger())):
                r = self._apply(path, change, target)
                self.assertEqual([x["state"] for x in r["profile"]["requirements"]], ["met"], change)  # each run alone was fine
                self.assertEqual((r["valid"], r["profile"]["outcome"], r["profile"]["evidence_unchanged"]),
                                 (False, "not_evaluated", False), (change, path))

    def test_no_fingerprint_before_is_not_valid(self):
        p = self.ledger()
        prof = VE.load_profile(self.write("p.json", _profile({"ledger": {"ledger_id": _first_id(p)}})))
        r = VE.apply_profile(VE.verify_ledger(p), p, prof, None)
        self.assertEqual((r["valid"], r["profile"]["outcome"], r["profile"]["evidence_unchanged"]),
                         (False, "not_evaluated", False))

    def test_cli_receipt_says_unchanged(self):
        p = self.ledger()
        rc, out, err = _run("ledger", p, "--profile", self.write("p.json", _profile({"ledger": {"ledger_id": _first_id(p)}})))
        r = json.loads(out)
        self.assertEqual((rc, r["profile"]["evidence_unchanged"], r["profile"]["outcome"]), (0, True, "met"), err)
        rc, out, err = _run("pack", p, "--profile", self.write("q.json", _profile({"pack": {"signature_domain": True}})))
        self.assertIn("evidence_unchanged", json.loads(out)["profile"])   # not_applicable or not valid: the member is there
        link = os.path.join(self.tmp, "cli-link.jsonl")
        os.symlink(p, link)
        rc, out, err = _run("ledger", link, "--profile", self.write("p.json", _profile({"ledger": {"ledger_id": _first_id(p)}})))
        self.assertEqual((rc, json.loads(out)["profile"]["evidence_unchanged"]), (0, True), err)


if __name__ == "__main__":
    unittest.main()
