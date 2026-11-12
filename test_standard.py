#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Roberto Locatelli
"""Test the open-standard machinery: conformance vectors + self-updating regulatory profiles."""
import datetime
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

    def _copy(self, prof):
        p = os.path.join(tempfile.mkdtemp(), "p.json")
        with open(p, "w") as f:
            json.dump(prof, f)
        return p

    def test_refresh_current_is_clean(self):
        # The verdict must not depend on the calendar: "now" is fixed to the newest as_of + STALE_DAYS, the last
        # day on which every entry is still inside the window. Staleness of the shipped file today is reported by
        # the CI step `refresh_regulatory.py --check-urls`, which reads the system clock.
        prof = json.load(open(os.path.join(_HERE, "spec", "regulatory_profiles.json")))
        oldest = min(datetime.date.fromisoformat(r["as_of"]) for r in prof["regulations"])
        now = datetime.datetime.combine(oldest, datetime.time(), datetime.timezone.utc) \
            + datetime.timedelta(days=refresh_regulatory.STALE_DAYS)
        r = refresh_regulatory.refresh(self._copy(prof), check_urls=False, now=now)
        self.assertEqual(r["needs_review"], [])

    def test_refresh_window_boundary(self):
        # positive control for the fixed clock: one day past the window the oldest entry is flagged
        prof = json.load(open(os.path.join(_HERE, "spec", "regulatory_profiles.json")))
        oldest = min(datetime.date.fromisoformat(r["as_of"]) for r in prof["regulations"])
        base = datetime.datetime.combine(oldest, datetime.time(), datetime.timezone.utc)
        first_stale = sorted(r["id"] for r in prof["regulations"] if r["as_of"] == oldest.isoformat())
        r = refresh_regulatory.refresh(self._copy(prof), check_urls=False,
                                       now=base + datetime.timedelta(days=refresh_regulatory.STALE_DAYS + 1))
        self.assertEqual(r["needs_review"], first_stale)
        with self.assertRaises(ValueError):   # a naive instant is a usage error, never compared silently
            refresh_regulatory.refresh(self._copy(prof), now=datetime.datetime(2026, 1, 1))

if __name__ == "__main__":
    unittest.main(verbosity=2)
