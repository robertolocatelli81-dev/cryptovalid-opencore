# -*- coding: utf-8 -*-
"""Fail-closed on pathological JSON nesting (2026-09-13).

Before this fix the Python reference CRASHED with RecursionError on a ~5000-deep
nested value (exit 1 with a traceback, no receipt) while the JS/Rust verifiers
returned a FAIL receipt. A crash is not a verdict: an operator wrapping the
verifier could read it as "unknown", never as the FAIL the spec vocabulary requires.
These tests were RED on verifier.py @ v0.9.3 (positive control) and GREEN after.
"""
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import verifier as V  # noqa: E402


def _deep_line(depth):
    return '{"idx":0,"ts":"t","data":' + "[" * depth + "]" * depth + ',"prev_hash":"' + "0" * 64 + '","self_hash":"z"}\n'


class DeepNesting(unittest.TestCase):
    def _tmp(self, prefix):
        d = tempfile.mkdtemp(prefix=prefix)
        self.addCleanup(shutil.rmtree, d, True)
        return d

    def _valid_chained(self, depth):
        # total nesting of the LINE = entry object (1) + data object (1) + (depth-2) inner levels = depth
        data = cur = {}
        for _ in range(depth - 2):
            cur["x"] = {}
            cur = cur["x"]
        e = {"idx": 0, "ts": "t", "data": data, "prev_hash": "0" * 64}
        e["self_hash"] = hashlib.sha256(V.canonical_payload(e)).hexdigest()
        line = json.dumps(e, separators=(",", ":"))
        self.assertEqual(V.json_nesting_depth(line), depth)   # the fixture measures what it claims
        p = os.path.join(self._tmp("cv_depth_valid_"), "l.jsonl")
        with open(p, "w") as f:
            f.write(line + "\n")
        return p

    def test_normative_bound_is_a_property_of_the_verifier(self):
        # linear pre-scan: MAX_JSON_DEPTH is refused deterministically, independent of the host stack
        self.assertEqual(V.json_nesting_depth('{"a":[[{"b":"]]}"}]]}'), 4)   # brackets in strings ignored
        ok = V.verify_ledger(self._valid_chained(V.MAX_JSON_DEPTH))          # exactly at the bound: accepted
        self.assertEqual(ok["verdict"], "PASS")
        bad = V.verify_ledger(self._valid_chained(V.MAX_JSON_DEPTH + 1))     # one past the bound: refused
        self.assertEqual(bad["verdict"], "FAIL")
        self.assertIn("json_too_deep", " ".join(e["error"] for e in bad["parse_errors"]))

    def _js(self, path):
        node = shutil.which("node")
        if not node:
            self.skipTest("node not installed: JS parity not measurable here")
        out = subprocess.run([node, os.path.join(HERE, "verifiers", "js", "cvverify.mjs"), path],
                             capture_output=True, text=True, timeout=60)
        return json.loads(out.stdout)

    def test_js_agrees_at_the_bound_and_diverges_beyond_it(self):
        # the claim in spec/CONFORMANCE.md, MEASURED: at 512 both PASS; at 600 JS PASS / Python FAIL (declared)
        at = self._valid_chained(V.MAX_JSON_DEPTH)
        self.assertEqual(V.verify_ledger(at)["verdict"], "PASS")
        self.assertEqual(self._js(at)["verdict"], "PASS")
        beyond = self._valid_chained(600)
        self.assertEqual(V.verify_ledger(beyond)["verdict"], "FAIL")
        self.assertEqual(self._js(beyond)["verdict"], "PASS")

    def test_pass_at_the_bound_does_not_depend_on_caller_stack_depth(self):
        # a deep caller (MCP server, report generator) must not turn an in-profile PASS into a RecursionError FAIL
        p = self._valid_chained(V.MAX_JSON_DEPTH)
        def deep(n):
            return V.verify_ledger(p) if n == 0 else deep(n - 1)
        self.assertEqual(deep(700)["verdict"], "PASS")

    def test_oversized_input_is_refused_not_read(self):
        p = self._write(50)
        old = V.MAX_INPUT_BYTES
        V.MAX_INPUT_BYTES = 10
        try:
            r = V.verify_ledger(p)
        finally:
            V.MAX_INPUT_BYTES = old
        self.assertEqual(r["verdict"], "FAIL")
        self.assertIn("input_too_large", r["parse_errors"][0]["error"])

    def _write(self, depth):
        d = self._tmp("cv_depth_")
        p = os.path.join(d, "l.jsonl")
        with open(p, "w") as f:
            f.write(_deep_line(depth))
        return p

    def test_api_returns_fail_receipt_not_exception(self):
        r = V.verify_ledger(self._write(5000))
        self.assertEqual(r["verdict"], "FAIL")
        errs = " ".join(e["error"] for e in r.get("parse_errors", []))
        self.assertIn("json_too_deep", errs)

    def test_cli_exit_1_with_receipt_and_no_traceback(self):
        p = self._write(5000)
        out = subprocess.run([sys.executable, os.path.join(HERE, "verifier.py"), p],
                             capture_output=True, text=True, timeout=60)
        self.assertEqual(out.returncode, 1)
        self.assertNotIn("Traceback", out.stderr)
        self.assertEqual(json.loads(out.stdout)["verdict"], "FAIL")

    def test_ap2_verify_cli_fail_closed_on_deep_pack(self):
        # same defect class in the AP2 evidence verifier CLI: traceback until 2026-09-13
        d = self._tmp("cv_depth_ap2_"); p = os.path.join(d, "pack.json")
        with open(p, "w") as f:
            f.write('{"x":' + "[" * 5000 + "]" * 5000 + "}")
        out = subprocess.run([sys.executable, os.path.join(HERE, "ap2_evidence.py"), "verify", p],
                             capture_output=True, text=True, timeout=60)
        self.assertEqual(out.returncode, 1)
        self.assertNotIn("Traceback", out.stderr)
        r = json.loads(out.stdout); self.assertFalse(r["valid"]); self.assertIn("json_too_deep", r["error"])

    def test_evidence_pack_verify_cli_fail_closed_on_deep_manifest(self):
        d = self._tmp("cv_depth_pack_")
        with open(os.path.join(d, "MANIFEST.json"), "w") as f:
            f.write('{"x":' + "[" * 5000 + "]" * 5000 + "}")
        out = subprocess.run([sys.executable, os.path.join(HERE, "evidence_pack.py"), "verify", d],
                             capture_output=True, text=True, timeout=60)
        self.assertEqual(out.returncode, 1)
        self.assertNotIn("Traceback", out.stderr)
        r = json.loads(out.stdout); self.assertFalse(r["valid"]); self.assertIn("json_too_deep", r["error"])

    def test_moderate_nesting_is_still_parsed(self):
        # depth 50 is a legitimate (if unusual) payload: it must NOT be refused as too deep
        r = V.verify_ledger(self._write(50))
        errs = " ".join(e["error"] for e in r.get("parse_errors", []))
        self.assertNotIn("json_too_deep", errs)


if __name__ == "__main__":
    unittest.main()
