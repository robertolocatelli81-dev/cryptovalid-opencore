#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Roberto Locatelli
"""CI hook for the suites that live OUTSIDE the `opencore/test_*.py` glob:
the ap2-evidence-pack conformance vectors (spec/vectors/ap2/), the NIST ACVP
ML-DSA-65 sigVer subset, and the pqcrypto signature-suite bench (which was
previously never run by ci.sh — a fleet gap this file closes)."""
import importlib
import os
import sys
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
sys.path.insert(0, os.path.join(_HERE, "pqcrypto"))
sys.path.insert(0, os.path.join(_HERE, "spec", "vectors", "ap2"))


class TestAp2ConformanceVectors(unittest.TestCase):
    def test_reference_verifier_is_conformant(self):
        import run_ap2_conformance as rc
        r = rc.run()
        self.assertTrue(r["conformant"], r)
        statuses = {x["vector"]: x["status"] for x in r["results"]}
        self.assertEqual(len(statuses), 6, statuses)
        # the set must contain the positive control — an always-reject verifier must fail
        self.assertEqual(statuses.get("valid_signed"), "PASS", statuses)


def load_tests(loader, tests, pattern):
    # pull the out-of-glob suites into this CI-visible file
    for mod in ("test_acvp_mldsa65", "test_pqsig"):
        tests.addTests(loader.loadTestsFromModule(importlib.import_module(mod)))
    return tests


if __name__ == "__main__":
    unittest.main(verbosity=2)
