"""verify_receipt / verify_sth on the JSON profile: the declared VDS and tree-head kind are CHECKED, not ignored.
Found 2026-10-03 by a structural fuzz: a receipt with `vds` absent, null or naming another algorithm, and a tree head
with another `kind`, verified as RFC9162_SHA256 / cryptovalid_sth/1 — while the COSE path already refused an unknown vds."""
import os
import shutil
import tempfile
import unittest

import cryptovalid_receipt as R
import signer

SAMPLE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "examples", "sample_ledger.jsonl")
MISSING = object()


class TestDeclaredIdentifiers(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="rcid_")
        key = os.path.join(cls.tmp, "log.key")
        cls.pk = signer.keygen(key)["public_key_hex"]
        cls.leaves = R.M.leaves_from_ledger(SAMPLE)
        cls.inc = R.inclusion_receipt(SAMPLE, 1, key)
        old = R.signed_tree_head(cls.leaves[:2], key)
        cls.root_1 = old["root_sha256"]
        cls.con = R.consistency_receipt(old, SAMPLE, key)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def _inc(self, r):
        return R.verify_receipt(r, self.pk, leaf_canonical=self.leaves[1])["ok"]

    def _con(self, r):
        return R.verify_receipt(r, self.pk, trusted_root_1_hex=self.root_1)["ok"]

    @staticmethod
    def _with(r, key, value, inner=None):
        r = {**r, "sth": dict(r["sth"])}
        target = r["sth"] if inner else r
        if value is MISSING:
            target.pop(key)
        else:
            target[key] = value
        return r

    def test_genuine_receipts_verify(self):                # positive control
        self.assertTrue(self._inc(self.inc))
        self.assertTrue(self._con(self.con))
        self.assertTrue(R.verify_sth(self.inc["sth"], self.pk)["ok"])

    def test_vds_must_be_rfc9162_sha256(self):
        for v in (MISSING, None, "RFC9162_SHA512", 1, ""):
            with self.subTest(vds=v):
                self.assertFalse(self._inc(self._with(self.inc, "vds", v)))
                self.assertFalse(self._con(self._with(self.con, "vds", v)))

    def test_tree_head_kind_must_be_ours(self):
        for v in (MISSING, None, "cryptovalid_sth/2", 1):
            with self.subTest(kind=v):
                bad = self._with(self.inc, "kind", v, inner=True)
                self.assertFalse(R.verify_sth(bad["sth"], self.pk)["ok"])
                self.assertFalse(self._inc(bad))


if __name__ == "__main__":
    unittest.main()
