#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""cryptovalid_vaara_receipt on receipts built HERE (fresh ES256 / RS256 / HS256 / ML-DSA-65 keys)."""
import base64
import hashlib
import hmac
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import cryptovalid_vaara_receipt as V  # noqa: E402
from cryptovalid_acta import jcs  # noqa: E402

from cryptography.hazmat.primitives import hashes, serialization as ser  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec, mldsa, padding, rsa  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature  # noqa: E402

PRED = {"version": 1, "alg": "HS256", "issuerAsserted": {"nonce": "n-att", "iss": "i"}, "signature": "00"}
RESULT = {"deleted": True, "path": "/a"}


def keys():
    es, rs, ml = ec.generate_private_key(ec.SECP256R1()), rsa.generate_private_key(65537, 2048), mldsa.MLDSA65PrivateKey.generate()
    pem = lambda k: k.public_key().public_bytes(ser.Encoding.PEM, ser.PublicFormat.SubjectPublicKeyInfo)  # noqa: E731
    def sign(alg, data):
        if alg == "ES256":
            r, s = decode_dss_signature(es.sign(data, ec.ECDSA(hashes.SHA256())))
            return (r.to_bytes(32, "big") + s.to_bytes(32, "big")).hex()
        if alg == "RS256":
            return rs.sign(data, padding.PKCS1v15(), hashes.SHA256()).hex()
        if alg == "HS256":
            return hmac.new(b"secret-32-bytes-secret-32-bytes!", data, hashlib.sha256).hexdigest()
        return ml.sign(data).hex()
    verify = {"ES256": pem(es), "RS256": pem(rs), "HS256": b"secret-32-bytes-secret-32-bytes!",
              "ML-DSA-65": ml.public_key().public_bytes_raw()}
    return sign, verify


def execution(sign, alg="ES256", status="executed", commitment="value", **kw):
    od = {"completedAt": "2026-05-29T10:00:00Z", "status": status}
    if commitment:
        proj = jcs(RESULT).decode() if commitment == "value" else jcs({"digest": V.sha256_jcs(RESULT)}).decode()
        od["resultCommitment"] = {"projection": proj, "projectionDigest": "sha256:" + hashlib.sha256(proj.encode()).hexdigest()}
    r = {"version": 1, "alg": alg, "backLink": {"attestationDigest": V.sha256_jcs(PRED), "attestationNonce": "n-att"},
         "outcomeDerived": od, "receiptAsserted": {"iss": "i", "sub": "s", "nonce": "n-r", "alg": alg}}
    r.update(kw)
    r["signature"] = sign(alg, V.signed_payload(r))
    return r


class TestVaaraReceipt(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        sign, cls.key = keys()
        cls.sign = staticmethod(sign)

    def v(self, r, alg=None, **kw):
        return V.verify_receipt(r, self.key[alg or r["alg"]], alg=alg or r["alg"], **kw)

    def test_every_alg_and_both_commitments(self):
        for alg in V.ALGS:
            for c in ("value", "digest"):
                with self.subTest(alg=alg, c=c):
                    r = self.v(execution(self.sign, alg, commitment=c), predecessor=PRED, runtime_result=RESULT)
                    self.assertTrue(r["ok"], r)
                    self.assertEqual((r["signature_ok"], r["back_link_ok"], r["result_commitment_ok"]), (True, True, True))
        r = self.v(execution(self.sign, status="refused", commitment=None), predecessor=PRED)
        self.assertTrue(r["ok"]); self.assertIsNone(r["result_commitment_ok"])
        r = self.v(execution(self.sign))                                       # nothing given: not checked, never True
        self.assertIsNone(r["back_link_ok"]); self.assertIsNone(r["result_commitment_ok"])

    def test_signature_binds_the_signed_members(self):
        r = execution(self.sign)
        for bent in ({**r, "outcomeDerived": {**r["outcomeDerived"], "status": "refused"}},
                     {**r, "receiptAsserted": {**r["receiptAsserted"], "sub": "other"}},
                     {**r, "backLink": {**r["backLink"], "attestationNonce": "x"}}):
            self.assertFalse(self.v(bent)["signature_ok"])
        self.assertTrue(self.v({**r, "timestampAnchors": []})["signature_ok"])          # anchors are outside the payload
        self.assertFalse(self.v({**r, "signature": r["signature"].upper()})["signature_ok"])
        es = execution(self.sign); sig = es["signature"]
        padded = sig[:64] + "00" + sig[64:]                              # same r and s, a zero byte before s: 65 bytes
        self.assertFalse(self.v({**es, "signature": padded})["signature_ok"])
        self.assertFalse(V.verify_signature("ES256", self.key["RS256"], V.signed_payload(es), sig))   # no exception
        self.assertFalse(V.verify_signature("RS256", self.key["ES256"], V.signed_payload(es), sig))
        self.assertFalse(V.verify_receipt(execution(self.sign, "ES256"), self.key["RS256"], alg="RS256")["signature_ok"])
        self.assertFalse(V.verify_receipt(execution(self.sign, "HS256"), b"other secret", alg="HS256")["signature_ok"])

    def test_refusals(self):
        self.assertFalse(self.v(execution(self.sign), predecessor={**PRED, "signature": "01"})["back_link_ok"])
        self.assertFalse(self.v(execution(self.sign), predecessor={**PRED, "issuerAsserted": {"nonce": "other", "iss": "i"}})["back_link_ok"])
        self.assertFalse(self.v(execution(self.sign), runtime_result={"deleted": False, "path": "/a"})["result_commitment_ok"])
        r = execution(self.sign); r["outcomeDerived"]["resultCommitment"]["projectionDigest"] = "sha256:" + "0" * 64
        r["signature"] = self.sign("ES256", V.signed_payload(r))
        self.assertIs(self.v(r)["result_commitment_ok"], False)
        r = execution(self.sign); r["outcomeDerived"]["resultCommitment"]["projection"] = RESULT     # not a string
        r["signature"] = self.sign("ES256", V.signed_payload(r))
        self.assertIs(self.v(r, runtime_result=RESULT)["result_commitment_ok"], False)
        def resigned(**kw):
            x = execution(self.sign); x.update(kw); x["signature"] = self.sign("ES256", V.signed_payload(x)); return x
        for bad_version in (2, True, "1"):
            with self.subTest(version=bad_version):
                r = self.v(resigned(version=bad_version)); self.assertFalse(r["ok"]); self.assertIn("version", r["why"])
        r = self.v(resigned(alg="EdDSA"), alg="ES256"); self.assertFalse(r["ok"]); self.assertIn("alg", r["why"])
        r = self.v(resigned(backLink={"attestationDigest": V.sha256_jcs(PRED), "attestationNonce": "other"}), predecessor=PRED)
        self.assertIs(r["back_link_ok"], False)
        x = execution(self.sign); del x["backLink"]
        self.assertIn("signed members missing", self.v(x)["why"])
        bad = {"version": 2, "alg": "ES256"}
        for x in (bad, {**execution(self.sign), "alg": "EdDSA"}, {**execution(self.sign), "version": True}, [1], None,
                  execution(self.sign, status="done"), execution(self.sign, status="refused"),
                  {k: v for k, v in execution(self.sign).items() if k != "backLink"},
                  {**execution(self.sign), "issuerAsserted": {}}):
            with self.subTest(x=str(x)[:50]):
                self.assertFalse(self.v(x, alg="ES256")["ok"])

    def test_decision_evidence_and_anchors(self):
        ev = {"rail": "x402", "amount": "10"}
        r = {"version": 1, "alg": "ES256", "backLink": {"attestationDigest": V.sha256_jcs(PRED), "attestationNonce": "n-att"},
             "decisionDerived": {"decision": "allow", "evidenceRef": {"canonicalization": "JCS", "digest": V.sha256_jcs(ev), "ref": "r", "schema": "s"}},
             "issuerAsserted": {"iss": "i", "nonce": "n"}}
        r["signature"] = self.sign("ES256", V.signed_payload(r))
        self.assertTrue(self.v(r, evidence=ev)["evidence_ok"])
        self.assertFalse(self.v(r, evidence={**ev, "amount": "11"})["evidence_ok"])
        for lab in ("jcs-rfc8785", "jcs-json-v1"):
            r2 = {**r, "decisionDerived": {**r["decisionDerived"], "evidenceRef": {**r["decisionDerived"]["evidenceRef"], "canonicalization": lab}}}
            r2["signature"] = self.sign("ES256", V.signed_payload(r2))
            self.assertTrue(self.v(r2, evidence=ev)["ok"])
        r3 = {**r, "decisionDerived": {**r["decisionDerived"], "evidenceRef": {**r["decisionDerived"]["evidenceRef"], "canonicalization": "c14n"}}}
        r3["signature"] = self.sign("ES256", V.signed_payload(r3))
        self.assertFalse(self.v(r3)["ok"])
        good = "sha256:" + hashlib.sha256(V.signed_payload(r)).hexdigest()
        self.assertTrue(self.v({**r, "timestampAnchors": [{"method": "rfc3161", "anchoredDigest": good, "token": "t"}]})["anchors_ok"])
        self.assertFalse(self.v({**r, "timestampAnchors": [{"method": "rfc3161", "anchoredDigest": "sha256:" + "0" * 64}]})["ok"])
        self.assertFalse(V.receipt_kind({**r, "outcomeDerived": {}}))                  # both kinds at once: not a receipt



class TestAlgorithmBinding(unittest.TestCase):
    """2026-10-04: the receipt chose how the relying party's key was used (alg confusion) — with the ES256 public PEM
    (bytes, the form every test here passes) as the HS256 secret, anyone could forge a receipt. Red on the old code."""
    def setUp(self):
        from cryptography.hazmat.primitives import hashes, serialization as ser
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
        self.sk = ec.generate_private_key(ec.SECP256R1())
        self.pem = self.sk.public_key().public_bytes(ser.Encoding.PEM, ser.PublicFormat.SubjectPublicKeyInfo)
        self.pred = {"issuerAsserted": {"nonce": "n1"}, "x": 1}
        self.r = {"version": 1, "alg": "ES256", "backLink": {"attestationDigest": V.sha256_jcs(self.pred), "attestationNonce": "n1"},
                  "outcomeDerived": {"status": "refused", "completedAt": "2026-10-04T08:00:00Z"}, "receiptAsserted": {"iss": "i"}}
        rr, ss = decode_dss_signature(self.sk.sign(V.signed_payload(self.r), ec.ECDSA(hashes.SHA256())))
        self.r["signature"] = (rr.to_bytes(32, "big") + ss.to_bytes(32, "big")).hex()

    def test_positive_control(self):
        self.assertTrue(V.verify_receipt(self.r, self.pem, predecessor=self.pred, alg="ES256")["ok"])
        with self.assertRaises(TypeError):
            V.verify_receipt(self.r, self.pem, predecessor=self.pred)          # the expected alg is not optional

    def test_hs256_with_the_public_pem_as_secret_is_refused(self):
        import hashlib, hmac
        forged = dict(self.r, alg="HS256")
        forged["signature"] = hmac.new(self.pem, V.signed_payload(forged), hashlib.sha256).hexdigest()
        for key in (self.pem, self.pem.decode(), bytearray(self.pem)):
            out = V.verify_receipt(forged, key, predecessor=self.pred, alg="ES256")
            self.assertFalse(out["signature_ok"], out)
            self.assertFalse(out["ok"], out)
        with self.assertRaises(ValueError):
            V.load_key("HS256", self.pem)

    def test_hs256_keyed_with_any_public_key_form_is_refused(self):
        # the residue of the PEM guard alone: a raw ML-DSA-65 key or a DER SPKI used as the HMAC secret
        import hashlib, hmac
        from cryptography.hazmat.primitives.asymmetric import mldsa
        raw = mldsa.MLDSA65PrivateKey.generate().public_key().public_bytes_raw()
        der = self.sk.public_key().public_bytes(ser.Encoding.DER, ser.PublicFormat.SubjectPublicKeyInfo)
        for key, expected in ((raw, "ML-DSA-65"), (der, "ES256")):
            forged = dict(self.r, alg="HS256")
            forged["signature"] = hmac.new(key, V.signed_payload(forged), hashlib.sha256).hexdigest()
            out = V.verify_receipt(forged, key, predecessor=self.pred, alg=expected)
            self.assertFalse(out["ok"], out); self.assertIn("not the expected", out["why"])
        out = V.verify_receipt(self.r, self.pem, predecessor=self.pred, alg="none")
        self.assertFalse(out["ok"]); self.assertIn("not one of", out["why"])

    def test_expected_alg_binds_the_key(self):
        out = V.verify_receipt(self.r, self.pem, predecessor=self.pred, alg="RS256")
        self.assertFalse(out["ok"]); self.assertIn("not the expected", out["why"])

    def test_version_is_the_integer_one(self):
        for v in (1.0, True, "1"):
            out = V.verify_receipt(dict(self.r, version=v), self.pem, predecessor=self.pred, alg="ES256")
            self.assertFalse(out["ok"], v); self.assertIn("version", out["why"])


if __name__ == "__main__":
    unittest.main()
