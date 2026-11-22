# SPDX-License-Identifier: AGPL-3.0-or-later
"""SPEC §22 rule 9 (2026-11-22): what a ledger may hold is counted over the whole input before any line is parsed, the
same in Python, JS, Go and Java: more than 2^20 lines (a line ends at LF or at the end of the input, blank ones count)
is FAIL `input_too_large: more than 1048576 lines`; else more than 2^23 tokens (the characters { [ , : wherever they
stand, inside strings too) is FAIL `input_too_large: more than 8388608 JSON tokens`; exit 1, nothing parsed. A tip of
more than 2^23 tokens is row 2 of the table of rule 2. Until 0.28.0 a file of 16 MiB of "0" lines ended Python in
MemoryError and Go in "fatal error: out of memory allocating heap arena metadata" under a data limit of
2 GB, and one line of 64 MiB of `{}` values
ended JS in "JavaScript heap out of memory"; each without a receipt.

Needs no `cryptography` but for the tip test. A verifier whose toolchain is absent is not run."""
import json
import os
import shutil
import tempfile
import unittest

from test_ledger_input_20261122 import _all, _verifiers

LINES = 1 << 20
TOKENS = 1 << 23
TOO_MANY_LINES = f"input_too_large: more than {LINES} lines"
TOO_MANY_TOKENS = f"input_too_large: more than {TOKENS} JSON tokens"

try:
    import cryptography  # noqa: F401
    HAVE_CRYPTO = True
except ImportError:
    HAVE_CRYPTO = False


class TestTheBudgetOfALedgerInTheFourVerifiers(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        cls.bins = _verifiers(cls.tmp)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def run_on(self, name, body):
        p = os.path.join(self.tmp, name)
        with open(p, "wb") as f:
            f.write(body)
        try:
            return _all(self.bins, p)
        finally:
            os.remove(p)

    def assertReason(self, body, want, what):
        for name, (rc, verdict, reason, _) in self.run_on(what, body).items():
            self.assertEqual((rc, verdict, reason), (1, "FAIL", want), (what, name))

    def assertParsed(self, body, what):
        """at the bound: read and parsed, FAIL for what the lines hold, never for the budget"""
        for name, (rc, verdict, reason, _) in self.run_on(what, body).items():
            self.assertEqual((rc, verdict), (1, "FAIL"), (what, name))
            self.assertNotIn(reason, (TOO_MANY_LINES, TOO_MANY_TOKENS), (what, name))

    def test_lines_at_the_bound_are_parsed_control(self):
        self.assertParsed(b"0\n" * LINES, "lines_at")
        self.assertParsed(b"0\n" * (LINES - 1) + b"0", "lines_at_no_final_lf")

    def test_one_line_more_is_refused(self):
        self.assertReason(b"0\n" * LINES + b"0", TOO_MANY_LINES, "lines_over_no_final_lf")
        self.assertReason(b"\n" * (LINES + 1), TOO_MANY_LINES, "blank_lines_over")

    def test_tokens_at_the_bound_are_parsed_control(self):
        self.assertParsed(b'"' + b"," * TOKENS + b'"\n', "tokens_at")

    def test_one_token_more_is_refused_inside_a_string_too(self):
        self.assertReason(b'"' + b"," * (TOKENS + 1) + b'"\n', TOO_MANY_TOKENS, "tokens_over_in_a_string")
        self.assertReason(b"[" + b"0," * TOKENS + b"0]\n", TOO_MANY_TOKENS, "tokens_over_in_an_array")

    def test_lines_are_counted_before_tokens(self):
        self.assertReason(b",\n" * (TOKENS + 1) + b"\n" * LINES, TOO_MANY_LINES, "both_over")

    def test_the_valid_example_after_too_many_lines_is_not_verified(self):
        here = os.path.dirname(os.path.abspath(__file__))
        with open(os.path.join(here, "examples", "sample_ledger.jsonl"), "rb") as f:
            sample = f.read()
        self.assertReason(sample + b"\n" * LINES, TOO_MANY_LINES, "sample_then_blank_lines")


@unittest.skipUnless(HAVE_CRYPTO, "needs `cryptography` (the `sign` extra)")
class TestATipOfTooManyTokens(unittest.TestCase):
    def test_row_2_in_the_four(self):
        import signer
        import cryptovalid_tip as T
        from test_decisions_20261120 import _binaries, _ledger, _run
        from test_review_20261121 import _ROW, _reason
        tmp = tempfile.mkdtemp()
        try:
            led = os.path.join(tmp, "l.jsonl")
            _ledger(led, 3)
            key = os.path.join(tmp, "log.key")
            pk = signer.keygen(key)["public_key_hex"]
            tip = T.sign_tip(led, key)
            bins = _binaries(tmp)
            for n, want in ((TOKENS // 2, None), (TOKENS + 1, _ROW[2])):
                # an extra member: under the bound the closed object names it (a later row), over it row 2
                with open(led + ".tip.json", "w") as f:
                    json.dump(dict(tip, zz="," * n), f)
                for name in bins:
                    rc, out, rawout = _run(bins, name, led, [bins[name][2] + "trusted-pubkey", pk])
                    self.assertEqual(rc, 1, (name, rawout[-300:]))
                    got = _reason(name, out)
                    if want is None:
                        self.assertNotEqual(got, _ROW[2], name)
                    else:
                        self.assertEqual(got, want, name)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
