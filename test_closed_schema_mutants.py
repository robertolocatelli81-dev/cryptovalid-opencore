#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Roberto Locatelli
"""CI wrapper of verifiers/closed_schema_mutants.py (SPEC §2.1, closed entry schema, generative + differential across the
verifiers that build here: Python, JS, and Go / Rust / Java / Swift when their toolchains are present).

Two tests: the quick bench is GREEN on this tree; and the bench CAN go red — pointed at a copy of the JS verifier whose
schema rule is switched off it must count silent passes (positive control of the bench itself, not of a verifier)."""
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
BENCH = os.path.join(HERE, "verifiers", "closed_schema_mutants.py")
JS = os.path.join(HERE, "verifiers", "js", "cvverify.mjs")


class TestClosedSchemaMutants(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp(prefix="opencore-mutants-")
        self.addCleanup(shutil.rmtree, self.d, ignore_errors=True)

    def _run(self, *extra):
        out = os.path.join(self.d, "out.json")
        r = subprocess.run([sys.executable, BENCH, "--quick", "--seed", "20261011", "--out", out, *extra], capture_output=True, text=True, timeout=1800)
        with open(out, encoding="utf-8") as f:
            return r.returncode, json.load(f), r.stdout[-2000:]

    def test_quick_bench_is_green_on_every_verifier_that_builds(self):
        rc, s, tail = self._run()
        self.assertEqual(rc, 0, tail)
        self.assertEqual(s["disagreements"], 0, tail)
        self.assertFalse(any(s["out_of_class"].values()), s["out_of_class"])
        self.assertFalse(any(s["unnamed_unknown_key"].values()), s["unnamed_unknown_key"])
        self.assertIn("python", s["verifiers"]); self.assertIn("js", s["verifiers"])
        self.assertGreaterEqual(s["per_class"]["FAIL"]["n"], 50)

    def test_bench_can_fail_lax_js_copy_counts_silent_passes(self):
        with open(JS, encoding="utf-8") as f:
            src = f.read()
        lax = src.replace("if (u.length) schemaFailures.push(", "if (false) schemaFailures.push(", 1)
        self.assertNotEqual(lax, src, "the schema rule to switch off was not found: the control is void")
        # the lax copy must sit next to the original so its relative imports (none today) and node resolution behave the same
        lax_path = os.path.join(HERE, "verifiers", "js", "cvverify_lax_control_tmp.mjs")
        with open(lax_path, "w", encoding="utf-8") as f:
            f.write(lax)
        self.addCleanup(lambda: os.path.exists(lax_path) and os.remove(lax_path))
        rc, s, tail = self._run("--only", "python,js", "--js", lax_path)
        self.assertEqual(rc, 1, tail)
        self.assertGreater(s["silent_pass_on_expected_fail"]["js"], 0, s)
        self.assertEqual(s["silent_pass_on_expected_fail"]["python"], 0, s)
        self.assertGreater(s["disagreements"], 0)

    def test_bench_tables_match_the_spec_tables(self):
        # the bench's closed set is copied from the SPEC, the verifiers' from their code: the two copies must be the same list
        sys.path.insert(0, HERE)
        import verifier as V   # noqa: E402
        sys.path.insert(0, os.path.join(HERE, "verifiers"))
        import closed_schema_mutants as B   # noqa: E402
        self.assertEqual(set(B.ENTRY_KEYS), set(V.ENTRY_KEYS))
        with open(os.path.join(HERE, "SPEC_EVIDENCE_FORMAT.md"), encoding="utf-8") as f:
            spec = f.read()
        rows = re.findall(r"^\| `([a-z_]+)` \| ", spec[spec.index("## 2. Entry schema"):spec.index("### 2.1")], re.M)
        self.assertEqual(set(rows), set(B.ENTRY_KEYS), "SPEC §2 tables vs the bench's closed set")



class TestStaleBinary(unittest.TestCase):
    """11/10/2026: the oracle measured a Rust binary of 21/09 as if it were the tree's code. A binary older than one of its
    sources is now named and refused by the oracle and the bench (stale_binary), never measured silently."""
    def test_newer_source_is_named_older_is_not(self):
        sys.path.insert(0, os.path.join(HERE, "verifiers"))
        from differential_oracle import stale_binary   # noqa: E402
        d = tempfile.mkdtemp(); self.addCleanup(shutil.rmtree, d, ignore_errors=True)
        b, src = os.path.join(d, "cvverify"), os.path.join(d, "src", "lib.rs")
        os.makedirs(os.path.dirname(src))
        for f in (b, src):
            open(f, "w").close()
        os.utime(b, (1000, 1000)); os.utime(src, (2000, 2000))
        self.assertEqual(stale_binary(b, d, (".rs",)), src)          # positive control: the stale case is caught
        os.utime(b, (3000, 3000))
        self.assertIsNone(stale_binary(b, d, (".rs",)))
        self.assertIsNone(stale_binary(os.path.join(d, "absent"), d, (".rs",)))
        os.makedirs(os.path.join(d, "target")); t = os.path.join(d, "target", "x.rs"); open(t, "w").close(); os.utime(t, (9000, 9000))
        self.assertIsNone(stale_binary(b, d, (".rs",)))              # build output is not a source
        os.makedirs(os.path.join(d, ".build")); t = os.path.join(d, ".build", "x.rs"); open(t, "w").close(); os.utime(t, (9000, 9000))
        self.assertIsNone(stale_binary(b, d, (".rs",)))              # nor the Swift build directory

    def test_refusal_and_what_counts_as_a_source(self):
        """0.20.0 review: a test file or a manifest newer than the binary refused a CURRENT binary (cargo/swift do not relink
        for them; `swift build` does not relink a source that is only touched): only src/ and Sources/ count, and a binary
        the toolchain has just built is not second-guessed by mtimes."""
        sys.path.insert(0, os.path.join(HERE, "verifiers"))
        import differential_oracle as O   # noqa: E402
        self.assertEqual(os.path.relpath(O.RUST_SRC, O.HERE), os.path.join("rust", "src"))
        self.assertEqual(os.path.relpath(O.SWIFT_SRC, O.HERE), os.path.join("swift", "Sources"))
        d = tempfile.mkdtemp(); self.addCleanup(shutil.rmtree, d, ignore_errors=True)
        b, src = os.path.join(d, "cvverify"), os.path.join(d, "a.swift")
        for f in (b, src):
            open(f, "w").close()
        os.utime(b, (1000, 1000)); os.utime(src, (2000, 2000))
        with self.assertRaises(SystemExit) as cm:
            O.check_fresh("swift", b, d, (".swift",), built=False)
        self.assertIn(src, str(cm.exception))
        O.check_fresh("swift", b, d, (".swift",), built=True)       # just built by the toolchain: no refusal

    def test_bench_generates_idx_removed_from_the_only_entry(self):
        """The mutation that found the 0.19.0 shortcut (7/1500): it must be generated again, not skipped."""
        sys.path.insert(0, os.path.join(HERE, "verifiers"))
        import closed_schema_mutants as B   # noqa: E402

        class R:
            def randrange(self, n): return 0
            def choice(self, xs): return "idx" if xs == B.CORE else xs[0]
        base = B.rechain([{"idx": 0, "ts": "t", "data": {}}], "sha256")
        m = B.m_missing_core(R(), "sha256", base)
        self.assertIsNotNone(m)
        self.assertEqual(m[:2], ("missing_idx", "FAIL"))

if __name__ == "__main__":
    unittest.main(verbosity=2)
