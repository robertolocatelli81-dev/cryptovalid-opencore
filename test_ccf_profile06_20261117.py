#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""cryptovalid_cose_receipts, vds 2 (CCF_LEDGER_SHA256) after draft-ietf-scitt-receipts-ccf-profile-06 (2026-11-11, the
revision current on datatracker on 2026-11-17), which replaced -05:

- §3: `path` is [* ...]: empty for a tree of size 1, whose root is the leaf hash (-05: [+ ...], refused);
- §3.2: "Every proof in the receipt MUST have a data-hash equal to statement_digest" (-05 code: one bound proof was
  enough, so a proof of another leaf of the same tree passed beside it);
- §5: the vdp map matches Figure 11 (keys -1 and -2 only), and a receipt with consistency proofs is refused here
  (`CONSISTENCY_NOT_EVALUATED`: they are not evaluated, and every proof present MUST recompute the same root);
- §2.2: `ccf_statement_digest`, the data-hash of a Signed Statement (tag 18 kept, unprotected header an empty map, the
  rest as received), equal to the leaf_entry of the public vector valid-ccf-vds2 (scitt-ccf-ledger v7.0.6).

Positive control, measured: on the code of -05 every test here fails except test_the_rfc9162_profile_is_untouched
(and the digest tests fail at the missing function)."""
import hashlib
import json
import os
import sys
import unittest

sys.dont_write_bytecode = True
ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)
import cryptovalid_cose_receipts as C  # noqa: E402
import cryptovalid_receipt as R  # noqa: E402
import test_cose_receipts as TC  # noqa: E402

VEC = os.path.join(ROOT, "spec", "vectors", "scitt-cose", "test-vectors", "v1", "valid-ccf-vds2")
H = lambda b: hashlib.sha256(b).digest()  # noqa: E731
PH = {395: 2, 4: b"log-kid", 15: {1: "ccf.example", 2: "scitt.ccf.signature.v1"}}


def leaf_hash(leaf):
    return H(leaf[0] + H(leaf[1].encode()) + leaf[2])


@TC.NEEDS_CRYPTO
class Ccf06(unittest.TestCase):
    def setUp(self):
        self.isk, self.lsk = TC._key(C.ALG_ES256), TC._key(C.ALG_ES384)
        self.st = TC._statement(self.isk, C.ALG_ES256)
        self.entry = H(self.st)

    def receipt(self, vdp, root):
        return TC._cose(self.lsk, C.ALG_ES384, PH, {396: vdp}, root, True)

    def stage(self, rc):
        r = C.verify_receipt(rc, self.entry, TC._pem(self.lsk))
        return r["stage"]

    def test_empty_path_is_a_tree_of_size_one(self):
        leaf = [H(b"tx"), "2.1:evidence", self.entry]
        rc = self.receipt({-1: [R.cbor_encode({1: leaf, 2: []})]}, leaf_hash(leaf))
        self.assertIsNone(self.stage(rc))
        rc = self.receipt({-1: [R.cbor_encode({1: leaf, 2: []})]}, H(b"another root"))
        self.assertEqual(self.stage(rc), "INCLUSION_ROOT_SIGNATURE_INVALID")

    def test_every_proof_bound_to_the_entry(self):
        ours, other = [H(b"tx1"), "e1", self.entry], [H(b"tx2"), "e2", H(b"another statement")]
        root = H(leaf_hash(ours) + leaf_hash(other))
        pa = R.cbor_encode({1: ours, 2: [[False, leaf_hash(other)]]})
        pb = R.cbor_encode({1: other, 2: [[True, leaf_hash(ours)]]})
        self.assertIsNone(self.stage(self.receipt({-1: [pa]}, root)))                       # control: one bound proof
        self.assertEqual(self.stage(self.receipt({-1: [pa, pb]}, root)), "LEAF_NOT_THIS_STATEMENT")   # same root
        self.assertEqual(self.stage(self.receipt({-1: [pb, pa]}, root)), "LEAF_NOT_THIS_STATEMENT")

    def two_leaves(self):
        """a proof of this entry in a tree of two leaves (a non-empty path, valid under -05 too), and its root"""
        ours, other = [H(b"tx1"), "e1", self.entry], [H(b"tx2"), "e2", H(b"x")]
        return R.cbor_encode({1: ours, 2: [[False, leaf_hash(other)]]}), H(leaf_hash(ours) + leaf_hash(other))

    def test_vdp_map_of_figure_11(self):
        p, root = self.two_leaves()
        self.assertIsNone(self.stage(self.receipt({-1: [p]}, root)))                     # control
        self.assertEqual(self.stage(self.receipt({-1: [p], -3: [p]}, root)), "MALFORMED_PROOF")
        self.assertEqual(self.stage(self.receipt({-1: [p], 7: b"x"}, root)), "MALFORMED_PROOF")

    def test_consistency_proofs_not_evaluated(self):
        p, root = self.two_leaves()
        self.assertEqual(self.stage(self.receipt({-1: [p], -2: [b"\xa0"]}, root)), "CONSISTENCY_NOT_EVALUATED")
        self.assertEqual(self.stage(self.receipt({-2: [b"\xa0"]}, root)), "CONSISTENCY_NOT_EVALUATED")

    def test_the_rfc9162_profile_is_untouched(self):
        """vds 1: Figure 11 is the CCF profile's; a vdp map with another key stays as 0.25.x read it"""
        import cryptovalid_merkle as M
        entries = [b"e%d" % i for i in range(8)]
        entries[2] = self.entry
        root, path = M.mth(entries), M.inclusion_proof(2, entries)
        ph = {395: 1, 4: b"log-kid", 15: {1: "https://log.example", 2: "log"}}
        for extra in ({}, {-2: [b"\xa0"]}, {-3: b"x"}):
            rc = TC._cose(self.lsk, C.ALG_ES384, ph, {396: {-1: [R.cbor_encode([8, 2, list(path)])], **extra}}, root, True)
            self.assertIsNone(self.stage(rc), extra)

    def test_statement_digest_of_the_public_vector(self):
        with open(os.path.join(VEC, "statement.cose"), "rb") as f:
            st = f.read()
        with open(os.path.join(VEC, "expected.json")) as f:
            want = json.load(f)["leaf_entry"]
        self.assertEqual(C.ccf_statement_digest(st).hex(), want)

    def test_statement_digest_rules(self):
        st = self.st
        arr = R.cbor_decode(st[1:])
        with_uh = b"\xd2" + R.cbor_encode([arr[0], {33: b"chain"}, arr[2], arr[3]])   # a non-empty unprotected header
        self.assertNotEqual(H(with_uh), H(st))
        empty_uh = b"\xd2" + R.cbor_encode([arr[0], {}, arr[2], arr[3]])
        self.assertEqual(C.ccf_statement_digest(with_uh), H(empty_uh))
        # the protected header kept as received: a bstr with a one-byte length head where a shorter one would do
        long_head = b"\xd2\x84" + b"\x58" + bytes([len(arr[0])]) + arr[0] + b"\xa0" + R.cbor_encode(arr[2]) + R.cbor_encode(arr[3])
        if len(arr[0]) < 24:
            try:
                d = C.ccf_statement_digest(long_head)
            except ValueError:
                d = None   # a strict decoder may refuse the non-shortest head: then nothing is hashed
            self.assertIn(d, (None, H(long_head)))
        for bad in (st[1:], b"\xd2\x83" + st[2:], st + b"\x00", b"\xd2\x84\x5f", b"", b"\xd2"):
            with self.assertRaises(ValueError, msg=bad[:6].hex()):
                C.ccf_statement_digest(bad)


if __name__ == "__main__":
    unittest.main()
