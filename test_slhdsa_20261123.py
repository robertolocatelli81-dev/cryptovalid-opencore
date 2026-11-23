#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""cryptovalid_slhdsa (SPEC v0.15 §24, 2026-11-23): SLH-DSA archival anchors, verification only.

Data not written here: 84 NIST ACVP SLH-DSA sigVer cases (spec/vectors/slhdsa/nist_acvp_slhdsa_sigver.jsonl.gz, 12
parameter sets, seven reasons each) and two anchors made by pq-scitt's own create_anchor (anchors_pq_scitt.json: one
sha2_128f, one shake_128s with a non-ASCII root). Generated: every member removed, unknown members, every member given
every JSON type, hex variants, lengths, every bit of the signed fields, pins. Without slh-dsa: the format refusals are
the same, a well-formed anchor raises CheckNotRun. CV_REQUIRE_SLHDSA=1 makes the absence of slh-dsa an error.
Positive control: the module did not exist on 5f2d57f (this file fails at its import)."""
import copy
import gzip
import json
import os
import random
import sys
import unittest
from unittest import mock

sys.dont_write_bytecode = True
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import cryptovalid_slhdsa as S  # noqa: E402
import verifier  # noqa: E402

try:
    import slhdsa  # noqa: F401
    HAVE = True
except ImportError:
    HAVE = False
if os.environ.get("CV_REQUIRE_SLHDSA") == "1" and not HAVE:
    raise SystemExit("CV_REQUIRE_SLHDSA=1 but slh-dsa did not import: the signature tests would be skipped")
need = unittest.skipUnless(HAVE, "slh-dsa not installed (pip install 'cryptovalid-opencore[slh]')")
VEC = os.path.join(HERE, "spec", "vectors", "slhdsa")


def acvp():
    with gzip.open(os.path.join(VEC, "nist_acvp_slhdsa_sigver.jsonl.gz"), "rt", encoding="ascii") as f:
        lines = [json.loads(x) for x in f]
    return lines[0], lines[1:]


def anchors():
    with open(os.path.join(VEC, "anchors_pq_scitt.json"), encoding="utf-8") as f:
        return json.load(f)["anchors"]


def no_lib():
    return mock.patch.dict(sys.modules, {"slhdsa": None, "slhdsa.parameters": None})


WRONG = [None, True, False, 0, 1, -1, 1.5, "", "x", [], [1], {}, {"a": 1}]


class Vectors(unittest.TestCase):
    def test_header_and_selection(self):
        h, cases = acvp()
        self.assertEqual((h["commit"], h["sha256"], h["cases"], len(cases)),
                         ("975de31eb83d87039ec88934fdc47d8c312b892d",
                          "a013fc2104f4ed4799d96d51141f65b965969b2cf10646626a021b6d456ce792", 84, 84))
        sets = {c["parameterSet"] for c in cases}
        self.assertEqual(len(sets), 12)
        self.assertEqual(sum(c["testPassed"] for c in cases), 12)

    @need
    def test_every_nist_case(self):
        _, cases = acvp()
        for c in cases:
            param = c["parameterSet"][len("SLH-DSA-"):].lower().replace("-", "_")
            got = S.slh_verify(param, bytes.fromhex(c["pk"]), bytes.fromhex(c["message"]),
                               bytes.fromhex(c["signature"]), bytes.fromhex(c["context"]))
            self.assertIs(got, c["testPassed"], (c["tcId"], c["parameterSet"], c["reason"]))

    @need
    def test_nist_valid_cases_flipped_are_refused(self):
        _, cases = acvp()
        rnd = random.Random(205)
        for c in (c for c in cases if c["testPassed"]):
            param = c["parameterSet"][len("SLH-DSA-"):].lower().replace("-", "_")
            sig = bytearray.fromhex(c["signature"])
            sig[rnd.randrange(len(sig))] ^= 1 << rnd.randrange(8)
            self.assertFalse(S.slh_verify(param, bytes.fromhex(c["pk"]), bytes.fromhex(c["message"]), bytes(sig),
                                          bytes.fromhex(c["context"])))
            if c["context"]:   # the anchor's empty context is not the case's context
                self.assertFalse(S.slh_verify(param, bytes.fromhex(c["pk"]), bytes.fromhex(c["message"]),
                                              bytes.fromhex(c["signature"])))


class Anchors(unittest.TestCase):
    @need
    def test_pq_scitt_anchors_verify_with_and_without_pin(self):
        for a in anchors():
            self.assertEqual(S.verify_anchor(a)["code"], "ok")
            self.assertEqual(S.verify_anchor(a, pub=a["pub"])["code"], "ok")
            self.assertEqual(S.verify_anchor(a, pub=bytes.fromhex(a["pub"]))["code"], "ok")
            self.assertEqual(S.verify_anchor(a, pub=a["pub"].upper())["code"], "ok")
            self.assertEqual(S.verify_anchor(dict(a, backend="oqs"))["code"], "ok")   # informative (rule 1)
            r, rp = S.verify_anchor(a), S.verify_anchor(a, pub=a["pub"])
            self.assertEqual((r["valid"], rp["valid"]), (True, True))
            self.assertIn("not who signed it", r["detail"])
            self.assertIn("pinned", rp["detail"])
            self.assertIs(S.verify_anchor(dict(a, root="x"))["valid"], False)

    @need
    def test_inputs_the_library_refuses_are_a_signature_that_does_not_verify(self):
        for pk, sig in ((b"", b""), (b"\x00" * 5, b"s"), (b"\x00" * 32, b""), (b"\x00" * 33, b"\x00" * 17088)):
            self.assertIs(S.slh_verify("sha2_128f", pk, b"m", sig), False)
        with self.assertRaises(ValueError):
            S.slh_verify("sha2_128", b"\x00" * 32, b"m", b"")

    @need
    def test_signed_fields_changed_are_refused(self):
        for a in anchors():
            for k, v in (("root", a["root"] + "0"), ("root", a["root"][:-1]), ("ts", a["ts"] + 1e-6),
                         ("ts", int(a["ts"])), ("ts", -a["ts"])):
                self.assertEqual(S.verify_anchor(dict(a, **{k: v}))["code"], "signature", (k, v))
            other = "sha2_128s" if a["param"] != "sha2_128s" else "sha2_128f"
            self.assertIn(S.verify_anchor(dict(a, param=other))["code"], ("length", "signature"))

    @need
    def test_every_bit_of_a_sample_of_the_signature(self):
        a = anchors()[0]
        sig = bytes.fromhex(a["sig"])
        rnd = random.Random(24)
        for i in [0, 1, 15, 16, len(sig) - 1] + rnd.sample(range(len(sig)), 40):
            b = bytearray(sig)
            b[i] ^= 1 << rnd.randrange(8)
            self.assertEqual(S.verify_anchor(dict(a, sig=b.hex()))["code"], "signature", i)
        pub = bytearray.fromhex(a["pub"])
        for i in range(len(pub)):
            p = bytearray(pub)
            p[i] ^= 0x80
            self.assertEqual(S.verify_anchor(dict(a, pub=p.hex()))["code"], "signature", i)

    def test_pin_mismatch_is_refused_before_the_signature(self):
        for a in anchors():
            with no_lib():
                self.assertEqual(S.verify_anchor(a, pub="00" * (len(a["pub"]) // 2))["code"], "pin")

    def test_pin_of_a_wrong_type_or_not_hex_is_an_error_of_the_caller(self):
        a = anchors()[0]
        for p in (1, 1.0, [], {}, True, object()):
            with self.assertRaises(TypeError):
                S.verify_anchor(a, pub=p)
        for p in ("xyz", "0", "0g"):
            with self.assertRaises(ValueError):
                S.verify_anchor(a, pub=p)


class Closed(unittest.TestCase):
    """Generated: the format refusals, with and without slh-dsa; each one names the rule's code."""

    def codes(self, a, **kw):
        with no_lib():
            first = S.verify_anchor(a, **kw)
        if HAVE:
            self.assertEqual(S.verify_anchor(a, **kw), first)
        return first["code"]

    def test_not_object_and_schema(self):
        for x in WRONG + ["omega-slhdsa-anchor-v2"]:
            if not isinstance(x, dict):
                self.assertEqual(self.codes(x), "not_object")
        a = anchors()[0]
        for s in ["omega-slhdsa-anchor-v1", "omega-slhdsa-anchor-v3", "OMEGA-SLHDSA-ANCHOR-V2",
                  "omega-slhdsa-anchor-v2 ", None, 2, True, [], {}]:
            self.assertEqual(self.codes(dict(a, schema=s)), "schema", s)
        b = dict(a)
        del b["schema"]
        self.assertEqual(self.codes(b), "schema")

    def test_members_missing_or_unknown(self):
        a = anchors()[0]
        for k in S.MEMBERS - {"schema"}:
            b = dict(a)
            del b[k]
            self.assertEqual(self.codes(b), "members", k)
        rnd = random.Random(7)
        for name in ["x", "", "Schema", "sig ", "ctx", "context", "pub_pq", "é"] + \
                ["".join(rnd.choice("abcdefgh_") for _ in range(rnd.randrange(1, 9))) for _ in range(30)]:
            if name in S.MEMBERS:
                continue
            for v in WRONG:
                self.assertEqual(self.codes(dict(a, **{name: v})), "members", (name, v))

    def test_every_member_every_type(self):
        a = anchors()[0]
        for k in S.MEMBERS - {"schema"}:
            for v in WRONG + [float("nan"), float("inf"), float("-inf")]:
                if k == "ts" and isinstance(v, (int, float)) and not isinstance(v, bool) and v == v \
                        and v not in (float("inf"), float("-inf")):
                    continue   # a number is a valid ts: the signature decides
                if k == "root" and isinstance(v, str) and v:
                    continue   # any non-empty string is a valid root: the signature decides
                code = self.codes(dict(a, **{k: v}))
                want = "encoding" if k in ("sig", "pub") and isinstance(v, str) else "type"
                self.assertEqual(code, want, (k, v))

    def test_backend_and_param_are_closed_lists(self):
        a = anchors()[0]
        for b in ["SLHDSA", "liboqs", "auto", "slhdsa ", "openssl"]:
            self.assertEqual(self.codes(dict(a, backend=b)), "type")
        for p in ["sha2_128F", "SHA2_128f", "sha2-128f", "sha3_128f", "sha2_512f", "SLH-DSA-SHA2-128f", "sha2_128"]:
            self.assertEqual(self.codes(dict(a, param=p)), "type", p)

    def test_hex_encoding_and_lengths(self):
        a = anchors()[0]
        for k in ("sig", "pub"):
            v = a[k]
            for bad in (v.upper(), v[:-1], " " + v, v + "\n", v[:-2] + "zz", v[:-2] + "0X", "0x" + v[2:]):
                self.assertEqual(self.codes(dict(a, **{k: bad})), "encoding", (k, bad[-4:]))
            for good_hex_bad_len in (v[:-2], v + "00", "00"):
                self.assertEqual(self.codes(dict(a, **{k: good_hex_bad_len})), "length", k)
        for p, size in S.PARAMS.items():   # another set's lengths: refused before the signature
            if size != S.PARAMS[a["param"]]:
                self.assertEqual(self.codes(dict(a, param=p)), "length", p)

    def test_without_slh_dsa_a_well_formed_anchor_is_not_checked(self):
        for a in anchors():
            with no_lib():
                with self.assertRaises(verifier.CheckNotRun) as cm:
                    S.verify_anchor(a)
                self.assertIn("slh-dsa", str(cm.exception))
                with self.assertRaises(verifier.CheckNotRun):
                    S.verify_anchor(a, pub=a["pub"])

    def test_every_code_is_reached_and_the_list_is_closed(self):
        self.assertEqual(S.CODES, ("ok", "not_object", "schema", "members", "type", "encoding", "length", "pin",
                                   "signature"))
        a = anchors()[0]
        seen = {self.codes(None), self.codes(dict(a, schema="v1")), self.codes(dict(a, x=1)),
                self.codes(dict(a, ts=None)), self.codes(dict(a, sig="Z")), self.codes(dict(a, sig="00")),
                self.codes(a, pub="00" * 32)}
        self.assertEqual(seen, set(S.CODES) - {"ok", "signature"})


if __name__ == "__main__":
    unittest.main()
