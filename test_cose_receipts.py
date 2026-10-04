#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""cryptovalid_cose_receipts: statements and receipts built HERE with fresh keys (EdDSA, ES256, ES384), RFC 9162 and
CCF trees built with this repository's Merkle code. Positive controls first; every refusal names its stage."""
import hashlib
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import cryptovalid_cose_receipts as C  # noqa: E402
import cryptovalid_merkle as M  # noqa: E402
import cryptovalid_receipt as R  # noqa: E402
from cryptovalid_scitt import TAG_COSE_SIGN1, _sig1  # noqa: E402

from cryptography.hazmat.primitives import hashes, serialization as ser  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature  # noqa: E402

PAYLOAD = b'{"artifact":"x","v":1}'


def _key(alg):
    return {C.ALG_EDDSA: Ed25519PrivateKey.generate, C.ALG_ES256: lambda: ec.generate_private_key(ec.SECP256R1()),
            C.ALG_ES384: lambda: ec.generate_private_key(ec.SECP384R1())}[alg]()


def _pem(sk):
    return sk.public_key().public_bytes(ser.Encoding.PEM, ser.PublicFormat.SubjectPublicKeyInfo)


def _sign(sk, alg, tbs):
    if alg == C.ALG_EDDSA:
        return sk.sign(tbs)
    size = 32 if alg == C.ALG_ES256 else 48
    r, s = decode_dss_signature(sk.sign(tbs, ec.ECDSA(hashes.SHA256() if alg == C.ALG_ES256 else hashes.SHA384())))
    return r.to_bytes(size, "big") + s.to_bytes(size, "big")


def _cose(sk, alg, ph, uh, payload, detached):
    pb = R.cbor_encode({1: alg, **ph})
    return TAG_COSE_SIGN1 + R.cbor_encode([pb, uh, None if detached else payload, _sign(sk, alg, _sig1(pb, payload))])


def _statement(sk, alg, kid=True, sub=True):
    cwt = {1: "https://issuer.example", **({2: "urn:example:artifact"} if sub else {})}
    return _cose(sk, alg, {3: "application/json", 15: cwt, **({4: b"issuer-kid"} if kid else {})}, {}, PAYLOAD, False)


def _rfc9162_receipt(sk, alg, entry, index=2, size=8, vds=1, cwt=True, protected_extra=None, uh_extra=None):
    entries = [hashlib.sha256(b"filler %d" % i).digest() for i in range(size)]
    entries[index] = entry
    root, path = M.mth(entries), M.inclusion_proof(index, entries)
    ph = {395: vds, **({4: b"log-kid", 15: {1: "https://log.example", 2: "log"}} if cwt else {}), **(protected_extra or {})}
    uh = {396: {-1: [R.cbor_encode([size, index, list(path)])]}, **(uh_extra or {})}
    return _cose(sk, alg, ph, uh, root, True)


def _ccf_receipt(sk, alg, entry, flip_side=False, extra_proof=None, detached=True):
    H = lambda b: hashlib.sha256(b).digest()  # noqa: E731
    leaf = [H(b"tx"), "2.18:evidence", entry]
    sib = [H(b"s1"), H(b"s2")]
    h = H(leaf[0] + H(leaf[1].encode()) + leaf[2])
    h = H(sib[0] + h)                 # left sibling
    h = H(h + sib[1])                 # right sibling
    proof = {1: leaf, 2: [[not flip_side, sib[0]], [False, sib[1]]]}
    proofs = [R.cbor_encode(proof)] + ([R.cbor_encode(extra_proof)] if extra_proof else [])
    return _cose(sk, alg, {395: 2, 4: b"log-kid", 15: {1: "ccf.example", 2: "scitt.ccf.signature.v1"}},
                 {396: {-1: proofs}}, h, detached)


class Base(unittest.TestCase):
    def setUp(self):
        self.isk, self.lsk = _key(C.ALG_ES256), _key(C.ALG_ES384)
        self.st = _statement(self.isk, C.ALG_ES256)
        self.entry = hashlib.sha256(self.st).digest()

    def both(self, st, rc, profile="rfc9942", issuer=None, log=None, entry=None):
        return C.verify_statement_with_receipt(st, rc, issuer or _pem(self.isk), log or _pem(self.lsk),
                                               self.entry if entry is None else entry, None, profile)


class TestPositiveControls(Base):
    def test_every_alg_and_both_vds_verify_in_both_profiles(self):
        for salg in (C.ALG_EDDSA, C.ALG_ES256, C.ALG_ES384):
            for lalg in (C.ALG_EDDSA, C.ALG_ES256, C.ALG_ES384):
                isk, lsk = _key(salg), _key(lalg)
                st = _statement(isk, salg); e = hashlib.sha256(st).digest()
                for rc in (_rfc9162_receipt(lsk, lalg, e), _ccf_receipt(lsk, lalg, e)):
                    for p in C.PROFILES:
                        with self.subTest(salg=salg, lalg=lalg, profile=p):
                            r = C.verify_statement_with_receipt(st, rc, _pem(isk), _pem(lsk), e, None, p)
                            self.assertTrue(r["ok"], r)

    def test_raw_hex_ed25519_key_is_accepted(self):
        sk = Ed25519PrivateKey.generate()
        st = _statement(sk, C.ALG_EDDSA)
        hexkey = sk.public_key().public_bytes(ser.Encoding.Raw, ser.PublicFormat.Raw).hex()
        self.assertTrue(C.verify_statement(st, hexkey)["ok"])


class TestRefusals(Base):
    def stage(self, r):
        self.assertFalse(r["ok"], r)
        return r["stage"]

    def test_statement_signature_and_key(self):
        bad = self.st[:-1] + bytes([self.st[-1] ^ 1])
        self.assertEqual(self.stage(C.verify_statement(bad, _pem(self.isk))), "BAD_STATEMENT_SIGNATURE")
        self.assertEqual(self.stage(C.verify_statement(self.st, _pem(_key(C.ALG_ES256)))), "BAD_STATEMENT_SIGNATURE")
        # the ALG names P-256 but the relying party's key is P-384 / Ed25519: never accepted
        self.assertEqual(self.stage(C.verify_statement(self.st, _pem(_key(C.ALG_ES384)))), "BAD_STATEMENT_SIGNATURE")
        self.assertEqual(self.stage(C.verify_statement(self.st, _pem(_key(C.ALG_EDDSA)))), "BAD_STATEMENT_SIGNATURE")
        # the same r and s with a zero byte inserted before s (65 bytes): a non-canonical encoding, never accepted
        pb, ph, uh, pl, sig = C.parse_cose_sign1(self.st)
        padded = TAG_COSE_SIGN1 + R.cbor_encode([pb, uh, pl, sig[:32] + b"\x00" + sig[32:]])
        self.assertEqual(self.stage(C.verify_statement(padded, _pem(self.isk))), "BAD_STATEMENT_SIGNATURE")
        ed = _statement(_key(C.ALG_EDDSA), C.ALG_EDDSA)        # an EdDSA header over the relying party's EC key
        self.assertEqual(self.stage(C.verify_statement(ed, _pem(self.isk))), "BAD_STATEMENT_SIGNATURE")

    def test_unsupported_alg_and_payload_rules(self):
        st = _cose(self.isk, C.ALG_ES256, {3: "x", 15: {1: "i", 2: "s"}, 4: b"k"}, {}, PAYLOAD, False)
        pb = R.cbor_encode({1: -37, 15: {1: "i", 2: "s"}, 4: b"k"})          # PS256: not supported here
        ps = TAG_COSE_SIGN1 + R.cbor_encode([pb, {}, PAYLOAD, b"\x00" * 64])
        self.assertEqual(self.stage(C.verify_statement(ps, _pem(self.isk))), "UNSUPPORTED_ALG")
        self.assertEqual(self.stage(C.verify_statement(st, _pem(self.isk), payload=b"other")), "PAYLOAD_MISMATCH")
        det = _cose(self.isk, C.ALG_ES256, {15: {1: "i", 2: "s"}, 4: b"k"}, {}, PAYLOAD, True)
        self.assertEqual(self.stage(C.verify_statement(det, _pem(self.isk))), "DETACHED_PAYLOAD_MISSING")
        self.assertTrue(C.verify_statement(det, _pem(self.isk), payload=PAYLOAD)["ok"])

    def test_rfc9162_receipt_refusals(self):
        e = self.entry
        self.assertEqual(self.stage(self.both(self.st, _rfc9162_receipt(self.lsk, C.ALG_ES384, e, vds=99))), "UNSUPPORTED_VDS")
        # vds only in the UNPROTECTED header: never read
        rc = _rfc9162_receipt(self.lsk, C.ALG_ES384, e, protected_extra={395: None}, uh_extra={395: 1})
        self.assertEqual(self.stage(self.both(self.st, rc)), "UNSUPPORTED_VDS")
        other = hashlib.sha256(b"another statement").digest()
        self.assertEqual(self.stage(self.both(self.st, _rfc9162_receipt(self.lsk, C.ALG_ES384, other))),
                         "INCLUSION_ROOT_SIGNATURE_INVALID")
        rc = _rfc9162_receipt(self.lsk, C.ALG_ES384, e)
        self.assertEqual(self.stage(self.both(self.st, rc[:-1] + bytes([rc[-1] ^ 1]))), "INCLUSION_ROOT_SIGNATURE_INVALID")
        self.assertEqual(self.stage(self.both(self.st, rc, log=_pem(_key(C.ALG_ES384)))), "INCLUSION_ROOT_SIGNATURE_INVALID")
        self.assertEqual(self.stage(self.both(self.st, b"\xd2\x80")), "MALFORMED_RECEIPT")

    def test_attached_payload_must_be_the_rebuilt_root(self):
        entries = [hashlib.sha256(b"filler %d" % i).digest() for i in range(8)]
        entries[2] = self.entry
        path = M.inclusion_proof(2, entries)
        wrong = b"\x11" * 32
        pb = R.cbor_encode({1: C.ALG_ES384, 395: 1})
        rc = TAG_COSE_SIGN1 + R.cbor_encode([pb, {396: {-1: [R.cbor_encode([8, 2, list(path)])]}}, wrong,
                                             _sign(self.lsk, C.ALG_ES384, _sig1(pb, wrong))])
        self.assertEqual(self.stage(self.both(self.st, rc)), "INCLUSION_ROOT_SIGNATURE_INVALID")
        # signed over the TRUE root, but another value attached as payload: refused, the payload must be that root
        root = M.mth(entries)
        rc2 = TAG_COSE_SIGN1 + R.cbor_encode([pb, {396: {-1: [R.cbor_encode([8, 2, list(path)])]}}, wrong,
                                              _sign(self.lsk, C.ALG_ES384, _sig1(pb, root))])
        self.assertEqual(self.stage(self.both(self.st, rc2)), "INCLUSION_ROOT_SIGNATURE_INVALID")
        self.assertIn("attached payload", self.both(self.st, rc2)["receipt"]["why"])
        # an index outside the tree: the path cannot be walked
        rc3 = TAG_COSE_SIGN1 + R.cbor_encode([pb, {396: {-1: [R.cbor_encode([8, 9, list(path)])]}}, None,
                                              _sign(self.lsk, C.ALG_ES384, _sig1(pb, root))])
        self.assertIn("does not rebuild a root", self.both(self.st, rc3)["receipt"]["why"])

    def test_ccf_refusals(self):
        e = self.entry
        self.assertEqual(self.stage(self.both(self.st, _ccf_receipt(self.lsk, C.ALG_ES384, e, flip_side=True))),
                         "INCLUSION_ROOT_SIGNATURE_INVALID")
        self.assertEqual(self.stage(self.both(self.st, _ccf_receipt(self.lsk, C.ALG_ES384, hashlib.sha256(b"x").digest()))),
                         "LEAF_NOT_THIS_STATEMENT")
        self.assertEqual(self.stage(self.both(self.st, _ccf_receipt(self.lsk, C.ALG_ES384, e, detached=False))),
                         "PAYLOAD_NOT_DETACHED")
        other = {1: [b"\x00" * 32, "e", e], 2: [[True, b"\x01" * 32]]}
        self.assertEqual(self.stage(self.both(self.st, _ccf_receipt(self.lsk, C.ALG_ES384, e, extra_proof=other))),
                         "PROOFS_DISAGREE")
        bad_shape = {1: [b"\x00" * 32, "", e], 2: [[True, b"\x01" * 32]]}                 # empty internal-evidence
        self.assertEqual(self.stage(self.both(self.st, _ccf_receipt(self.lsk, C.ALG_ES384, e, extra_proof=bad_shape))),
                         "MALFORMED_PROOF")

    def test_rfc9943_header_musts(self):
        lrc = lambda st: _rfc9162_receipt(self.lsk, C.ALG_ES384, hashlib.sha256(st).digest())  # noqa: E731
        no_kid = _statement(self.isk, C.ALG_ES256, kid=False)
        no_sub = _statement(self.isk, C.ALG_ES256, sub=False)
        for st in (no_kid, no_sub):
            e = hashlib.sha256(st).digest()
            self.assertTrue(self.both(st, lrc(st), "rfc9942", entry=e)["ok"])            # not a COSE Receipts rule
            self.assertEqual(self.stage(self.both(st, lrc(st), "rfc9943", entry=e)), "HEADER_MUST")
        bare = _rfc9162_receipt(self.lsk, C.ALG_ES384, self.entry, cwt=False)             # receipt without CWT/kid
        self.assertTrue(self.both(self.st, bare, "rfc9942")["ok"])
        self.assertEqual(self.stage(self.both(self.st, bare, "rfc9943")), "HEADER_MUST")
        x5 = _cose(self.isk, C.ALG_ES256, {15: {1: "i", 2: "s"}, 33: b"cert"}, {}, PAYLOAD, False)   # x5chain stands for kid
        self.assertTrue(C.verify_statement(x5, _pem(self.isk), profile="rfc9943")["ok"])
        long_iss = _cose(self.isk, C.ALG_ES256, {15: {1: "i" * 8193, 2: "s"}, 4: b"k"}, {}, PAYLOAD, False)
        self.assertEqual(self.stage(C.verify_statement(long_iss, _pem(self.isk), profile="rfc9943")), "HEADER_MUST")

    def test_unknown_profile_is_a_usage_error(self):
        with self.assertRaises(ValueError):
            C.verify_statement(self.st, _pem(self.isk), profile="lax")



class TestUintFields(Base):
    """2026-10-04: RFC 9942 tree-size / leaf-index are uint — CBOR true/false and negatives were accepted (the class audit
    V1 #8/#9 closed in cryptovalid_scitt); vds true was read as 1. Red on the old code."""
    def _single_leaf(self, size, index, vds=1):
        leaf = M.leaf_hash(self.entry)                       # one-leaf tree: root = leaf, empty path
        pb = R.cbor_encode({1: C.ALG_ES384, 395: vds, 4: b"log-kid", 15: {1: "https://log.example", 2: "log"}})
        uh = {396: {-1: [R.cbor_encode([size, index, []])]}}
        return TAG_COSE_SIGN1 + R.cbor_encode([pb, uh, None, _sign(self.lsk, C.ALG_ES384, _sig1(pb, leaf))])

    def test_positive_control(self):
        out = C.verify_receipt(self._single_leaf(1, 0), self.entry, _pem(self.lsk))
        self.assertTrue(out["ok"], out); self.assertEqual((out["tree_size"], out["leaf_index"]), (1, 0))

    def test_bool_and_negative_size_index_are_refused(self):
        for size, index in ((True, False), (True, 0), (1, False), (-1, 0), (1, -1)):
            out = C.verify_receipt(self._single_leaf(size, index), self.entry, _pem(self.lsk))
            self.assertFalse(out["ok"], (size, index, out))
            self.assertEqual(out["stage"], "INCLUSION_ROOT_SIGNATURE_INVALID")
            self.assertIn("malformed", out["why"])

    def test_vds_true_is_not_one(self):
        out = C.verify_receipt(self._single_leaf(1, 0, vds=True), self.entry, _pem(self.lsk))
        self.assertFalse(out["ok"]); self.assertEqual(out["stage"], "UNSUPPORTED_VDS")


if __name__ == "__main__":
    unittest.main()
