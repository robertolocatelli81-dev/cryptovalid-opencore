# SPDX-License-Identifier: AGPL-3.0-or-later
"""SPEC v0.9 §17, the cases NEMESIS found on the 0.25.1 draft (16/11/2026).

1. A value option given twice: the last value was kept and the first left out, in the four verifiers
   (`--expect-ledger-id <B> --expect-ledger-id <A>` was PASS against A, exit 0), in `cryptovalid_tip.py check` and in
   `cryptovalid-ingest verify --pubkey`. Now a usage error, exit 2, nothing on stdout.
2. `cryptovalid_tip.py check` took "" as "not given": `--trusted-pq-pubkey ""` dropped the post-quantum check (ok,
   exit 0) and `--tip ""` read the default tip. Now exit 2, like verifier.py since 21/09/2026.
3. `parse_errors` keeps 10 lines: with 10 earlier errors `ledger_id_mismatch` was not in the receipt. It comes first.
"""
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
from test_expect_applied_20261116 import HAVE_CRYPTO, Fixture, _binaries  # noqa: E402

ENV = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}


def _run(argv):
    cp = subprocess.run(argv, capture_output=True, text=True, env=ENV, cwd=HERE)
    return cp.returncode, cp.stdout


class TestGivenTwice(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.f = Fixture()
        cls.bins = _binaries(cls.f.tmp)

    @classmethod
    def tearDownClass(cls):
        cls.f.close()

    def _cli(self, name, flags):
        argv, first, d = self.bins[name]
        flags = [x.replace("@", d) for x in flags]
        return _run(argv + (flags + [self.f.a] if first else [self.f.a] + flags))

    def test_each_verifier_refuses_a_value_option_given_twice(self):
        f = self.f
        f.place("none")
        twice = [["@expect-ledger-id", f.b_id, "@expect-ledger-id", f.a_id],
                 ["@expect-ledger-id", f.a_id, "@expect-ledger-id", f.a_id],
                 ["@tip-not-before", "2000-01-01T00:00:00Z", "@tip-not-before", "2000-01-02T00:00:00Z"],
                 ["@trusted-pubkey", "ab" * 32, "@trusted-pubkey", "cd" * 32],
                 ["@tip", f.a + ".none", "@tip", f.a + ".none"]]
        for name in self.bins:
            # controls: once each, the same flags answer a verdict (exit 0 or 1, a receipt)
            self.assertEqual(self._cli(name, ["@expect-ledger-id", f.a_id])[0], 0, name)
            self.assertEqual(self._cli(name, ["@expect-ledger-id", f.b_id])[0], 1, name)
            for flags in twice:
                self.assertEqual(self._cli(name, flags), (2, ""), (name, flags))

    def test_tip_check_and_ingest_refuse_a_value_option_given_twice(self):
        tip = [sys.executable, os.path.join(HERE, "cryptovalid_tip.py"), "check", self.f.a]
        for flags in (["--expect-ledger-id", self.f.b_id, "--expect-ledger-id", self.f.a_id],
                      ["--trusted-pubkey", "ab" * 32, "--trusted-pubkey", "cd" * 32],
                      ["--trusted-pq-pubkey", "AAAA", "--trusted-pq-pubkey", "AAAA"],
                      ["--not-before", "2000-01-01T00:00:00Z", "--not-before", "2000-01-01T00:00:00Z"],
                      ["--tip", "x", "--tip", "x"]):
            self.assertEqual(_run(tip + flags), (2, ""), flags)
        d = tempfile.mkdtemp(prefix="cv_once_")
        try:
            ing = [sys.executable, os.path.join(HERE, "cryptovalid_ingest.py"), "verify", d]
            self.assertEqual(_run(ing + ["--pubkey", "ab" * 32, "--pubkey", "cd" * 32]), (2, ""))
            self.assertEqual(_run(ing + ["--pubkey", "ab" * 32])[0], 1)   # control: once, a verdict (empty archive: not ok)
        finally:
            shutil.rmtree(d, ignore_errors=True)


@unittest.skipUnless(HAVE_CRYPTO, "needs `cryptography` (a signed tip)")
class TestTipCheckEmptyValues(unittest.TestCase):
    def test_an_empty_value_is_a_usage_error(self):
        f = Fixture()
        try:
            shutil.copyfile(f.tip_a, f.a + ".tip.json")
            base = [sys.executable, os.path.join(HERE, "cryptovalid_tip.py"), "check", f.a, "--trusted-pubkey", f.pk]
            rc, out = _run(base)
            self.assertEqual(rc, 0, out)                                      # control: the tip verifies
            for flag in ("--trusted-pq-pubkey", "--tip", "--expect-ledger-id"):
                self.assertEqual(_run(base + [flag, ""]), (2, ""), flag)       # until 0.25.1 pq/tip: ok, exit 0
            rc, out = _run([sys.executable, os.path.join(HERE, "cryptovalid_tip.py"), "check", f.a, "--trusted-pubkey", ""])
            self.assertEqual(rc, 2)                                           # as before: tip_untrusted, exit 2
            self.assertIn("tip_untrusted", out)
        finally:
            f.close()


class TestMismatchNamedFirst(unittest.TestCase):
    def test_mismatch_is_in_the_receipt_after_ten_earlier_errors(self):
        f = Fixture()
        try:
            with open(f.a, encoding="utf-8") as src:
                first = src.readline()
            p = os.path.join(f.tmp, "many.jsonl")
            with open(p, "w", encoding="utf-8") as out:
                out.write(first + "[]\n" * 12)
            r = V.verify_ledger(p, expect_ledger_id=f.b_id)
            self.assertEqual(r["verdict"], "FAIL")
            self.assertEqual(len(r["parse_errors"]), 10)
            self.assertTrue(r["parse_errors"][0]["error"].startswith("ledger_id_mismatch"), r["parse_errors"][:2])
            r = V.verify_ledger(p, expect_ledger_id=f.a_id)                    # control: the right id adds nothing
            self.assertFalse(any("ledger_id_mismatch" in e["error"] for e in r["parse_errors"]))
        finally:
            f.close()


if __name__ == "__main__":
    unittest.main(verbosity=1)
