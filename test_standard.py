#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Roberto Locatelli
"""Test the open-standard machinery: conformance vectors + self-updating regulatory profiles."""
import json
import os
import sys
import tempfile
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
import conformance  # noqa: E402
import refresh_regulatory  # noqa: E402


class TestConformance(unittest.TestCase):
    def test_reference_verifier_conforms(self):
        r = conformance.run()
        self.assertTrue(r["conformant"])
        self.assertGreaterEqual(r["vectors"], 5)       # copre valido/tampered/broken-link/bad-idx

    def test_a_wrong_verifier_is_caught(self):
        # un "verifier" che dice sempre PASS NON deve risultare conforme (i vettori FAIL lo smascherano)
        always_pass = lambda p: {"verdict": "PASS", "chain_integrity": True, "algorithm_used": "sha256",
                                 "entries_count": 0, "hash_failures": [], "link_failures": []}
        self.assertFalse(conformance.run(always_pass)["conformant"])


class TestRegulatoryProfiles(unittest.TestCase):
    def test_profiles_shape(self):
        prof = json.load(open(os.path.join(_HERE, "spec", "regulatory_profiles.json")))
        ids = {r["id"] for r in prof["regulations"]}
        self.assertTrue({"MiCA", "AI-Act-AnnexIII", "DORA", "GDPR"} <= ids)
        for r in prof["regulations"]:
            self.assertIn(r["status"], ("in_force", "deferred", "repealed"))
            self.assertTrue(r["source_url"].startswith("https://"))

    def test_refresh_flags_stale(self):
        prof = json.load(open(os.path.join(_HERE, "spec", "regulatory_profiles.json")))
        prof["regulations"][0]["as_of"] = "2020-01-01"        # forza uno stantìo
        p = os.path.join(tempfile.mkdtemp(), "p.json")
        json.dump(prof, open(p, "w"))
        r = refresh_regulatory.refresh(p, check_urls=False)   # niente rete
        self.assertIn(prof["regulations"][0]["id"], r["needs_review"])

    def test_refresh_current_is_clean(self):
        prof = json.load(open(os.path.join(_HERE, "spec", "regulatory_profiles.json")))
        p = os.path.join(tempfile.mkdtemp(), "p.json")
        json.dump(prof, open(p, "w"))
        r = refresh_regulatory.refresh(p, check_urls=False)   # date odierne → nulla da rivedere
        self.assertEqual(r["needs_review"], [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
