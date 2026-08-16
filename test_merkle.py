#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Roberto Locatelli
"""Standalone test dell'estensione Merkle (RFC 6962): inclusione+consistenza verificano; manomissioni falliscono."""
import hashlib, os, sys, unittest
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

if __name__ == "__main__":
    unittest.main(verbosity=2)
