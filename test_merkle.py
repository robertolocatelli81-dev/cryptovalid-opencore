#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Roberto Locatelli
"""Standalone test dell'estensione Merkle (RFC 6962): inclusione+consistenza verificano; manomissioni falliscono."""
import hashlib
import os
import sys
import unittest
_HERE = os.path.dirname(os.path.abspath(__file__)); sys.path.insert(0, _HERE)
import cryptovalid_merkle as M  # noqa: E402

class TestMerkle(unittest.TestCase):
    def test_rfc6962_vectors(self):
        self.assertEqual(M.mth([]).hex(), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        self.assertEqual(M.mth([b""]).hex(), hashlib.sha256(b"\x00").hexdigest())
    def test_inclusion_all_leaves(self):
        lv = [os.urandom(20) for _ in range(37)]; root = M.mth(lv)
        for m in range(37):
            self.assertTrue(M.verify_inclusion(m, 37, lv[m], M.inclusion_proof(m, lv), root))
    def test_inclusion_tamper_fails(self):
        lv = [os.urandom(20) for _ in range(20)]; root = M.mth(lv)
        self.assertFalse(M.verify_inclusion(5, 20, lv[5] + b"x", M.inclusion_proof(5, lv), root))
        self.assertFalse(M.verify_inclusion(6, 20, lv[5], M.inclusion_proof(5, lv), root))
    def test_consistency_verdict_is_three_valued(self):
        lv = [b"e%d" % i for i in range(12)]
        r = lambda k: M.mth(lv[:k])  # noqa: E731
        self.assertEqual(M.consistency_verdict(3, 12, M.consistency_proof(3, lv[:12]), r(3), r(12)), "consistent")
        self.assertEqual(M.consistency_verdict(12, 12, [], r(12), r(12)), "consistent")
        bad = M.consistency_proof(3, lv[:12]); bad[0] = bytes([bad[0][0] ^ 1]) + bad[0][1:]
        self.assertEqual(M.consistency_verdict(3, 12, bad, r(3), r(12)), "inconsistent")
        self.assertEqual(M.consistency_verdict(3, 12, M.consistency_proof(3, lv[:12]), r(3), r(11)), "inconsistent")
        for m, n in ((0, 12), (8, 4), (-1, 3), (True, 3)):
            with self.subTest(m=m, n=n):
                self.assertEqual(M.consistency_verdict(m, n, [], r(1), r(4)), "could_not_compare")
                self.assertFalse(M.verify_consistency(m, n, [], r(1), r(4)) if not isinstance(m, bool) and m >= 0 else False)

    def test_consistency_append_only(self):
        lv = [os.urandom(20) for _ in range(37)]
        for m in (1, 10, 32, 37):
            for n in (m, 25, 37):
                if m <= n:
                    self.assertTrue(M.verify_consistency(m, n, M.consistency_proof(m, lv[:n]),
                                                         M.mth(lv[:m]), M.mth(lv[:n])))
    def test_rewritten_history_fails(self):
        lv = [os.urandom(20) for _ in range(37)]; tam = list(lv); tam[3] = os.urandom(20)
        self.assertFalse(M.verify_consistency(20, 37, M.consistency_proof(20, lv[:37]),
                                              M.mth(lv[:20]), M.mth(tam[:37])))
    def test_interop_ledger(self):
        lv = M.leaves_from_ledger(os.path.join(_HERE, "examples", "sample_ledger.jsonl"))
        root = M.mth(lv)
        self.assertTrue(M.verify_inclusion(1, len(lv), lv[1], M.inclusion_proof(1, lv), root))
        self.assertEqual(M.signed_tree_head(lv)["tree_size"], len(lv))

    # 0.21.0 (SPEC §9, v0.4): a leaf is the canonical form of §3. Until 0.20.3 it kept signature_pq, signer_pq and
    # tsa_token, so signing a ledger with ML-DSA or adding a timestamp token AFTER a tree head changed the root of entries
    # already covered (the chain still PASS): measured 14/10/2026 on examples/sample_ledger.jsonl.
    def test_leaves_vector(self):
        import json
        v = json.load(open(os.path.join(_HERE, "spec", "vectors", "merkle_leaves.json"), encoding="utf-8"))
        lv = M.leaves_from_ledger(os.path.join(_HERE, "spec", "vectors", v["input"]))
        self.assertEqual(M.tree_head(lv)["root_sha256"], v["normative"]["root_sha256"])
        self.assertEqual([M.leaf_hash(x).hex() for x in lv], v["normative"]["leaf_hashes"])
    def test_attestation_added_later_keeps_the_root(self):
        import copy, json
        base = [json.loads(l) for l in open(os.path.join(_HERE, "examples", "sample_ledger.jsonl"), encoding="utf-8") if l.strip()]
        root0 = M.mth([M.canonical(e) for e in base])
        for field in ("signature", "signer", "signature_pq", "signer_pq", "tsa_token", "self_hash"):
            with self.subTest(field=field):
                later = copy.deepcopy(base); later[0][field] = "QUJD"
                lv = [M.canonical(e) for e in later]
                self.assertEqual(M.mth(lv), root0)
                self.assertEqual(M.consistency_verdict(len(lv), len(lv), [], root0, M.mth(lv)), "consistent")
    def test_leaf_is_the_self_hash_preimage(self):
        import json
        for line in open(os.path.join(_HERE, "spec", "vectors", "merkle_leaves.jsonl"), encoding="utf-8"):
            e = json.loads(line)
            self.assertEqual(hashlib.sha256(M.canonical(e)).hexdigest(), e["self_hash"])
    def test_content_still_changes_the_root(self):   # control: the leaf is not emptied
        import copy, json
        base = [json.loads(l) for l in open(os.path.join(_HERE, "examples", "sample_ledger.jsonl"), encoding="utf-8") if l.strip()]
        for k in ("idx", "ts", "data", "prev_hash"):
            with self.subTest(k=k):
                t = copy.deepcopy(base); t[1][k] = "x"
                self.assertNotEqual(M.mth([M.canonical(e) for e in t]), M.mth([M.canonical(e) for e in base]))

if __name__ == "__main__":
    unittest.main(verbosity=2)
