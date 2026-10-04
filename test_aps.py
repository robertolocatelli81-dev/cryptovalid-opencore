#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""cryptovalid_aps: the three action_ref forms and the Accountability Record, on objects built HERE with a fresh key."""
import hashlib
import os
import sys
import unicodedata
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import cryptovalid_aps as A  # noqa: E402
from cryptovalid_acta import jcs  # noqa: E402

from cryptography.hazmat.primitives import serialization as ser  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

NATIVE = {"agentId": "did:aps:zA", "actionType": "doc.sign", "scopeRequired": ["repo:write", "admin"], "timestamp": "2026-07-10T00:00:00Z"}
PAYLOAD = {"amount": "10", "to": "x"}


def v2(**kw):
    o = {"profile": "aps-action-ref-v2", "agent_id": "did:key:z6Mk", "action_type": "commerce_preflight",
         "target": "https://api.example/payments", "payload_ref": A.payload_ref_v2(PAYLOAD),
         "scope_required": ["commerce:read", "commerce:write"], "issued_at": "2026-04-08T12:00:00.000Z", "nonce": "0" * 32}
    o.update(kw)
    return o


class TestActionRefs(unittest.TestCase):
    def test_native_01_positive_and_rules(self):
        ref, order = A.action_ref_native_01(NATIVE)
        self.assertEqual(order, ["admin", "repo:write"])
        self.assertEqual(ref, hashlib.sha256(jcs({**NATIVE, "scopeRequired": ["admin", "repo:write"]})).hexdigest())
        nfd = unicodedata.normalize("NFD", "café:read")
        self.assertEqual(A.action_ref_native_01({**NATIVE, "scopeRequired": [nfd]})[1], ["café:read"])
        astral, bmp = "\U0001F600", ""                              # code-point order: astral AFTER U+E000
        self.assertEqual(A.action_ref_native_01({**NATIVE, "scopeRequired": [astral, bmp]})[1], [bmp, astral])
        for bad in ({**NATIVE, "x": 1}, {k: v for k, v in NATIVE.items() if k != "timestamp"},
                    {**NATIVE, "timestamp": "2026-07-10T00:00:00.000Z"}, {**NATIVE, "timestamp": "2026-07-10T00:00:00+00:00"},
                    {**NATIVE, "scopeRequired": "repo"}, {**NATIVE, "scopeRequired": [1]}, {**NATIVE, "agentId": ""},
                    {**NATIVE, "actionType": "a\ud800"}, {**NATIVE, "scopeRequired": ["\udc00"]}):
            with self.subTest(bad=str(bad)[:60]):
                with self.assertRaises(A.ApsError):
                    A.action_ref_native_01(bad)
        for t in ("2026-07-10T00:00:00.000Z", "2026-07-10T00:00:00.123Z", "2026-07-10T00:00:00+00:00"):
            self.assertEqual(A.action_ref_native_01({**NATIVE, "timestamp": t}, normalize=True), A.action_ref_native_01(NATIVE))
        with self.assertRaises(A.ApsError):
            A.action_ref_native_01({**NATIVE, "timestamp": "2026-07-10T00:00:00+01:00"}, normalize=True)
        dup = {**NATIVE, "scopeRequired": ["café:read", unicodedata.normalize("NFD", "café:read")]}
        self.assertEqual(len(A.action_ref_native_01(dup)[1]), 2)            # -01 has no duplicate rule
        with self.assertRaises(A.ApsError):
            A.action_ref_native_01(dup, reject_duplicate_scopes=True)

    def test_v2(self):
        o = v2()
        self.assertEqual(A.action_ref_v2(o, PAYLOAD), hashlib.sha256(b"APS-ACTION-REF-V2\x00" + jcs(o)).hexdigest())
        self.assertNotEqual(A.action_ref_v2(o), hashlib.sha256(jcs(o)).hexdigest())      # the prefix is there
        self.assertEqual(o["payload_ref"], hashlib.sha256(b"APS-ACTION-PAYLOAD-V1\x00" + jcs(PAYLOAD)).hexdigest())
        bads = {"extra": {**o, "x": 1}, "profile": v2(profile="aps-action-ref-v1"), "hex": v2(nonce="Z" * 32),
                "payload_ref hex": v2(payload_ref="AB" * 32), "seconds": v2(issued_at="2026-04-08T12:00:00Z"),
                "unsorted": v2(scope_required=["commerce:write", "commerce:read"]), "dup": v2(scope_required=["a", "a"]),
                "nfd": v2(scope_required=[unicodedata.normalize("NFD", "café")]), "empty scope": v2(scope_required=[""]),
                "empty target": v2(target=""), "surrogate": v2(target="t\ud800")}
        for name, b in bads.items():
            with self.subTest(name):
                with self.assertRaises(A.ApsError):
                    A.action_ref_v2(b)
        with self.assertRaises(A.ApsError):
            A.action_ref_v2(o, {"amount": "11", "to": "x"})                # payload_ref must match the dispatched payload
        utf8_order = v2(scope_required=["", "\U0001F600"])          # UTF-8 order = code-point order
        self.assertTrue(A.action_ref_v2(utf8_order))
        with self.assertRaises(A.ApsError):
            A.action_ref_v2(v2(scope_required=[]))                        # only a profile may permit an empty array
        self.assertTrue(A.action_ref_v2(v2(scope_required=[]), empty_scope_permitted=True))

    def test_external(self):
        e = {"action_type": "a", "agent_id": "did:x", "scope": "s", "timestamp": "2026-04-08T12:00:00.000Z"}
        self.assertEqual(A.external_action_ref(e), hashlib.sha256(jcs(e)).hexdigest())
        nfd = {**e, "scope": unicodedata.normalize("NFD", "café")}
        self.assertNotEqual(A.external_action_ref(nfd), A.external_action_ref({**e, "scope": "café"}))   # hashed as supplied
        for b in ({**e, "timestamp": "2026-04-08T12:00:00Z"}, {**e, "scope": ["s"]}, {**e, "x": 1}, {**e, "scope": "\ud800"}):
            with self.subTest(b=str(b)[:50]):
                with self.assertRaises(A.ApsError):
                    A.external_action_ref(b)


class TestAccountabilityRecord(unittest.TestCase):
    def setUp(self):
        self.sk = Ed25519PrivateKey.generate()
        self.pub = self.sk.public_key().public_bytes(ser.Encoding.Raw, ser.PublicFormat.Raw).hex()

    def rec(self, sign=True, drop_action=False, **kw):
        action = {"type": "commerce.charge", "scope": ["commerce:charge"], "timestamp": "2026-07-04T12:00:00.250Z"}
        ref, _ = A.action_ref_native_01({"agentId": "did:key:zAgent", "actionType": action["type"],
                                         "scopeRequired": action["scope"], "timestamp": "2026-07-04T12:00:00Z"})
        r = {"spec_version": "0.1.0", "record_type": "accountability_record", "action_ref": ref,
             "action_digest": {"sha256": hashlib.sha256(jcs(action)).hexdigest()}, "signer_did": "did:key:zRec",
             "agent_did": "did:key:zAgent", "delegation_ref": "sha256:x", "principal_ref": "did:key:zP", "decision": "allow",
             "executed": True, "issued_at": "2026-07-04T12:00:01Z", "sig_alg": "Ed25519", "action": action}
        if drop_action:
            r.pop("action")
        r.update(kw)
        r["sig"] = self.sk.sign(jcs(r)).hex() if sign else "00" * 64
        return r

    def check(self, r):
        return A.verify_accountability_record(r, self.pub)

    def test_valid_and_detached(self):
        self.assertTrue(self.check(self.rec())["ok"])
        d = self.check(self.rec(drop_action=True))
        self.assertTrue(d["ok"]); self.assertFalse(d["payload_verified"])
        self.assertTrue(self.check(self.rec(settlement_ref="stl_1", settlement_rail="x"))["ok"])

    def test_schema_layer(self):
        cases = {"decision": {"decision": "permit"}, "record_type": {"record_type": "audit_receipt"},
                 "sig_alg": {"sig_alg": "ed25519"}, "executed": {"executed": "true"}, "extra": {"x": 1},
                 "action_ref hex": {"action_ref": "AB" * 32}, "digest shape": {"action_digest": {"sha256": "0" * 64, "x": 1}},
                 "action shape": {"action": {"type": "t", "scope": "s", "timestamp": "2026-07-04T12:00:00Z"}},
                 "spec_version type": {"spec_version": 1}, "settlement type": {"settlement_ref": 5}}
        for name, kw in cases.items():
            with self.subTest(name):
                r = self.check(self.rec(**kw))
                self.assertEqual((r["ok"], r["layer"]), (False, "schema"), r)
        r = self.rec(); r.pop("principal_ref"); r["sig"] = self.sk.sign(jcs({k: v for k, v in r.items() if k != "sig"})).hex()
        self.assertEqual(self.check(r)["layer"], "schema")
        bad_sig = self.rec(); bad_sig["sig"] = "AB" * 64
        self.assertEqual(self.check(bad_sig)["layer"], "schema")
        for not_an_object in ([1], 5, None, "x"):
            with self.subTest(not_an_object=not_an_object):
                self.assertEqual(self.check(not_an_object)["layer"], "schema")          # a verdict, never an exception
        a = {"type": 5, "scope": ["s"], "timestamp": "2026-07-04T12:00:00Z"}
        self.assertEqual(self.check(self.rec(action=a))["layer"], "schema")
        a = {"type": "t", "scope": ["s"], "timestamp": 5}
        self.assertEqual(self.check(self.rec(action=a))["layer"], "schema")

    def test_crypto_layers(self):
        r = self.rec(); r["delegation_ref"] = "other"
        self.assertEqual(self.check(r)["layer"], "signature")
        other = Ed25519PrivateKey.generate().public_key().public_bytes(ser.Encoding.Raw, ser.PublicFormat.Raw).hex()
        self.assertEqual(A.verify_accountability_record(self.rec(), other)["layer"], "signature")
        swapped = self.rec(action={"type": "commerce.charge", "scope": ["commerce:charge:elevated"], "timestamp": "2026-07-04T12:00:00.250Z"})
        self.assertEqual(self.check(swapped)["layer"], "digest_mismatch")
        a = {"type": "commerce.charge", "scope": ["commerce:charge"], "timestamp": "2026-07-04T12:00:09Z"}
        wrong_ref = self.rec(action=a, action_digest={"sha256": hashlib.sha256(jcs(a)).hexdigest()})
        self.assertEqual(self.check(wrong_ref)["layer"], "action_ref")
        a3 = {"type": "commerce.charge", "scope": ["commerce:charge"], "timestamp": "2026-07-04T12:00:00.250+00:00"}
        utc = self.rec(action=a3, action_digest={"sha256": hashlib.sha256(jcs(a3)).hexdigest()})
        self.assertTrue(self.check(utc)["ok"])                             # +00:00 is UTC
        a2 = {"type": "commerce.charge", "scope": ["commerce:charge"], "timestamp": "2026-07-04T12:00:00+01:00"}
        nonutc = self.rec(action=a2, action_digest={"sha256": hashlib.sha256(jcs(a2)).hexdigest()})
        self.assertEqual(self.check(nonutc)["layer"], "action_ref")



class TestTimestampCalendar(unittest.TestCase):
    """2026-10-04: \\d matched Arabic-Indic and fullwidth digits and no calendar was checked — 25 of 31 hostile timestamps
    (month 13, 30 February, hour 25, minute 60, Unicode digits) were accepted here and refused by agent-passport-system
    7.2.1 (measured 2026-10-04 against the official npm package). Red on the old code."""
    BAD = ("٢٠٢٦-١٠-٠٣T١٢:٠٠:٠٠Z", "２０２６-１０-０３T１２:００:００Z", "2026-13-03T12:00:00Z", "2026-02-30T12:00:00Z",
           "2023-02-29T12:00:00Z", "2026-10-03T25:00:00Z", "2026-10-03T12:60:00Z", "2026-10-03T12:00:60Z",
           "2026-12-31T23:59:60Z", "0000-00-00T00:00:00Z", "2026-00-10T00:00:00Z", "2026-04-31T00:00:00Z")

    def test_positive_control(self):
        self.assertTrue(A.action_ref_native_01(dict(NATIVE, timestamp="2024-02-29T12:00:00Z"))[0])
        self.assertTrue(A.action_ref_v2(v2(issued_at="2026-12-31T23:59:60.000Z")))       # leap second where it can occur
        self.assertTrue(A.external_action_ref({"action_type": "t", "agent_id": "a", "scope": "s", "timestamp": "2026-06-30T23:59:60.000Z"}))
        self.assertEqual(A.normalize_timestamp("2026-10-03T12:00:00.250+00:00"), "2026-10-03T12:00:00Z")

    def test_native_refuses_unicode_digits_and_impossible_dates(self):
        for ts in self.BAD:
            with self.assertRaises(A.ApsError, msg=ts):
                A.action_ref_native_01(dict(NATIVE, timestamp=ts))
            with self.assertRaises(A.ApsError, msg=ts):
                A.normalize_timestamp(ts)

    def test_v2_and_external_refuse_unicode_digits_and_impossible_dates(self):
        for ts in self.BAD:
            ms = ts.replace("Z", ".000Z")
            if ms == "2026-12-31T23:59:60.000Z":
                continue                                     # a leap second at 23:59 on the last day is admitted in these forms
            with self.assertRaises(A.ApsError, msg=ms):
                A.action_ref_v2(v2(issued_at=ms))
            with self.assertRaises(A.ApsError, msg=ms):
                A.external_action_ref({"action_type": "t", "agent_id": "a", "scope": "s", "timestamp": ms})
        with self.assertRaises(A.ApsError):                  # second 60 away from 23:59 / the last day
            A.action_ref_v2(v2(issued_at="2026-10-03T12:00:60.000Z"))


if __name__ == "__main__":
    unittest.main()
