#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Tests added after the third review (2026-11-17), each written against a mutant of the changed lines that the suite
let live: SPEC v0.10 §11 step 7 for a signer named by subjectKeyIdentifier (an ESS attribute given twice, both ESS
attributes present with the second wrong, an ESSCertID with a third element or a second element that is not a
SEQUENCE, an issuerSerial with two names, a `tsa` field right after genTime), and a COSE receipt whose attached payload
is the root of its second proof (cryptovalid_cose_receipts, 0.26.0)."""
import copy
import hashlib
import os
import shutil
import sys
import tempfile
import time
import unittest

sys.dont_write_bytecode = True
ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)
import cryptovalid_tsa as T  # noqa: E402
from test_tsa_signer_key_id_20261116 import NEEDS, Lab, der, enc, ess_v2, signer_info, tree  # noqa: E402


@NEEDS
class KeyIdAnchorMore(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.td = tempfile.mkdtemp()
        cls.lab = Lab(cls.td, "r3")
        with open(cls.lab.j("tsa.crt"), "rb") as f:
            cls.leaf = T._first_pem_der(f.read())
        cls.pins = T._pem_certs([cls.lab.j("ca.crt")])
        cls.ski = T.parse_token(cls.lab.resign(cls.lab.token()))["token_der"]
        cls.at = int(time.time())

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.td)

    def anchor(self, tok):
        return T._key_id_anchor(tok, self.leaf, self.pins, self.at, self.td)

    def attrs(self, t):
        return signer_info(t)[1][3][1]

    def test_control(self):
        self.assertIsNone(self.anchor(self.ski))

    def test_ess_attribute_given_twice(self):
        t = tree(self.ski)
        a = [x for x in self.attrs(t) if T._der_oid(x[1][0][1], "t") == T.OID_SIGNING_CERTIFICATE_V2][0]
        self.attrs(t).append(copy.deepcopy(a))
        self.assertIn("not exactly one value", self.anchor(enc(t)) or "")

    def _with_v1(self, v1_hash):
        """the token's signedAttrs with a signingCertificate (v1, SHA-1) added next to its signingCertificateV2"""
        t = tree(self.ski)
        oid = bytes([0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x10, 0x02, 0x0C])   # 1.2.840.113549.1.9.16.2.12
        self.assertEqual(T._der_oid(oid, "t"), T.OID_SIGNING_CERTIFICATE)
        v1 = [0x30, [[0x06, oid], [0x31, [[0x30, [[0x30, [[0x30, [[0x04, v1_hash]]]]]]]]]]]
        self.attrs(t).append(v1)
        return t

    def test_both_ess_attributes_each_checked(self):
        sha1 = hashlib.sha1(self.leaf).digest()
        self.assertIsNone(self.anchor(enc(self._with_v1(sha1))))                  # control: both right
        self.assertIn("certHash", self.anchor(enc(self._with_v1(b"\x00" * 20))) or "")   # v1 wrong
        t = self._with_v1(sha1)                                                    # v1 right, v2 wrong
        h = [x for x in ess_v2(signer_info(t))[0][1] if x[0] == 0x04][0]
        h[1] = bytes([h[1][0] ^ 1]) + h[1][1:]
        self.assertIn("certHash", self.anchor(enc(t)) or "")

    def test_ess_cert_id_shape(self):
        t = tree(self.ski)
        cid = ess_v2(signer_info(t))[0][1]
        cid.append(copy.deepcopy(cid[-1]))                                         # a third element
        self.assertIn("not {certHash, issuerSerial?}", self.anchor(enc(t)) or "")
        t = tree(self.ski)
        cid = ess_v2(signer_info(t))[0][1]
        self.assertEqual(cid[-1][0], 0x30)
        cid[-1][0] = 0x31                                                           # issuerSerial as a SET
        self.assertIn("not {certHash, issuerSerial?}", self.anchor(enc(t)) or "")

    def test_issuer_serial_with_two_names(self):
        t = tree(self.ski)
        cid = ess_v2(signer_info(t))[0][1]
        names = [x for x in cid if x[0] == 0x30 and x[1][0][0] == 0x30][0][1][0]
        names[1].append([0x82, b"tsa.example"])                                    # a dNSName after the directoryName
        self.assertIn("issuerSerial", self.anchor(enc(t)) or "")

    def test_tsa_field_right_after_gen_time(self):
        """a TSTInfo with no accuracy, ordering or nonce: the tsa field is its sixth element and is still read"""
        t = tree(self.ski)
        econtent = t[1][1][1][0][1][2][1][1][1][0]
        tst = tree(econtent[1])
        tst[1] = tst[1][:5]                                                         # version .. genTime
        econtent[1] = enc(tst)
        self.assertIsNone(self.anchor(enc(t)))                                      # control
        tst[1].append([0xA0, [[0x82, b"other.example"]]])                           # tsa = a dNSName the signer lacks
        econtent[1] = enc(tst)
        self.assertIn("tsa field", self.anchor(enc(t)) or "")


try:
    import cryptography  # noqa: F401
    HAVE_CRYPTO = True
except ImportError:
    HAVE_CRYPTO = False


@unittest.skipUnless(HAVE_CRYPTO, "needs cryptography")
class AttachedPayloadOfTheSecondProof(unittest.TestCase):
    def test_attached_root_of_the_second_proof(self):
        import cryptovalid_cose_receipts as C
        import cryptovalid_merkle as M
        import cryptovalid_receipt as R
        from cryptovalid_scitt import TAG_COSE_SIGN1, _sig1
        from test_cose_receipts import _key, _pem, _sign
        sk = _key(C.ALG_ES256)
        entry = hashlib.sha256(b"entry").digest()
        trees = {}
        for size in (5, 8):
            leaves = [hashlib.sha256(b"filler %d" % i).digest() for i in range(size)]
            leaves[2] = entry
            trees[size] = (M.mth(leaves), list(M.inclusion_proof(2, leaves)))
        root8 = trees[8][0]
        pb = R.cbor_encode({1: C.ALG_ES256, 395: 1})
        proofs = [R.cbor_encode([5, 2, trees[5][1]]), R.cbor_encode([8, 2, trees[8][1]])]
        rc = TAG_COSE_SIGN1 + R.cbor_encode([pb, {396: {-1: proofs}}, root8, _sign(sk, C.ALG_ES256, _sig1(pb, root8))])
        out = C.verify_receipt(rc, entry, _pem(sk))
        self.assertEqual((out["ok"], out.get("tree_size"), out.get("payload_attached")), (True, 8, True), out)


if __name__ == "__main__":
    unittest.main()
