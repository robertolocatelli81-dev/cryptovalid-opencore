#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""cryptovalid_sri (0.26.0, 2026-11-17): integrity metadata parsed closed, against real values and generated ones.

Real values, from the files saved by the reviews of 16-17/11/2026 (never fetched here): the two `vct#integrity` examples
of IT-Wallet (eid-wallet-it-docs b34a1f5, examples/pid-*:24/16 and qeaa-*:24/16) and the three `#integrity` values of
EUDI TS12 v1.0.1 lines 523-525 (eudi-doc-standards cfc383e). All five are refused, and a plain SRI matcher would have
returned true for any bytes on each. The SRI Recommendation's own example (sha384 of "alert('Hello, world.');") and the
SHA-256 of empty input are accepted. Generated values are checked against an independent oracle: one regular expression
of the whole ABNF of each grammar. Positive control: the module did not exist in 0.25.1 (this file fails at its import)."""
import base64
import hashlib
import os
import random
import re
import sys
import unittest

sys.dont_write_bytecode = True
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import cryptovalid_sri as S  # noqa: E402

REAL = {   # value: expected code under both grammars
    "55f5fe57f1e491d49f33672784528532d9d": "grammar",                                    # IT-Wallet PID, 35 hex
    "2e40bcd6799008085ffb1a1f3517efee335298fd976b3e655bfb3f4eaa11d171": "grammar",       # IT-Wallet QEAA, 64 hex
    "sha256-9cLlJNXN-TsMk-..5ca_xGgX3c1VLmXfh-WRL5": "grammar",                          # TS12:523
    "sha256-e3b0c44298fc49afbf4...a495991852b855": "grammar",                            # TS12:524
    "sha256-335f3750519114d2a93...5e6ed24c30c0317": "grammar",                           # TS12:525
}
SRI_EXAMPLE = "sha384-H8BRh8j48O9oYatfu5AZzq6A9RINhZO5H16dQZngK7T62em8MUt1FLm52t+eX6xO"
EMPTY = "sha256-47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU="


def oracle(value, grammar):
    """ok or not, from one regular expression of the whole ABNF (written apart from the module)"""
    b64 = r"[A-Za-z0-9+/]+={0,2}" if grammar == "sri-2016" else r"[A-Za-z0-9+/_-]+={0,2}"
    hwo = r"(?i:sha256|sha384|sha512)-" + b64 + r"(?:\?[\x21-\x7e]*)*"
    if not isinstance(value, str) or not re.fullmatch(r"[ \t]*" + hwo + r"(?:[ \t]+" + hwo + r")*[ \t]*", value):
        return False
    for tok in value.split():
        alg, b = tok.split("?")[0].split("-", 1)
        raw = b.rstrip("=").replace("-", "+").replace("_", "/")
        if len(raw) % 4 == 1:
            return False
        try:
            d = base64.b64decode(raw + "=" * (-len(raw) % 4), validate=True)
        except ValueError:
            return False
        if len(d) != {"sha256": 32, "sha384": 48, "sha512": 64}[alg.lower()]:
            return False
    return True


class Real(unittest.TestCase):
    def test_the_five_real_values(self):
        for v, code in REAL.items():
            for g in S.GRAMMARS:
                r = S.parse_integrity(v, g)
                self.assertEqual((r["ok"], r["why"], r["sri_match_would_accept"]), (False, code, True), (v, g))
                c = S.check_integrity(b"anything at all", v, g)
                self.assertEqual((c["ok"], c["why"], c["sri_match_would_accept"]), (False, code, True), (v, g))

    def test_valid_vectors(self):
        for g in S.GRAMMARS:
            self.assertEqual(S.check_integrity(b"alert('Hello, world.');", SRI_EXAMPLE, g)["matched_alg"], "sha384")
            self.assertTrue(S.check_integrity(b"", EMPTY, g)["ok"])
            r = S.check_integrity(b"x", EMPTY, g)
            self.assertEqual((r["ok"], r["why"], r["sri_match_would_accept"]), (False, "mismatch", False))

    def test_the_two_grammars_differ_on_the_alphabet(self):
        url = EMPTY.replace("+", "-").replace("/", "_")
        self.assertEqual(S.parse_integrity(url, "sri-2016")["why"], "grammar")
        self.assertTrue(S.check_integrity(b"", url, "sri-l2")["ok"])

    def test_codes_and_their_order(self):
        h = base64.b64encode(hashlib.sha256(b"").digest()).decode()
        for v, code, accept in (
                (None, "not_text", True), (b"sha256-x", "not_text", True), ("", "empty", True), (" \t ", "empty", True),
                ("md5-" + h, "alg_not_recognised", True), ("sha1-" + h, "alg_not_recognised", True),
                ("sha384-" + h, "digest_length", False), ("sha256-" + h[:-2], "digest_length", False),
                ("sha256-" + h + " md5-" + h, "alg_not_recognised", False), ("sha256-" + h + " sha256-%%", "grammar", False),
                ("sha256-" + h + "\n", "grammar", True), ("sha256-" + h + "===", "grammar", True),
                ("sha256-" + h + "?opté", "grammar", True), ("sha256" + h, "grammar", True),
                ("md5-" + h + " sha256-%%", "grammar", True)):
            r = S.parse_integrity(v, "sri-2016")
            self.assertEqual((r["ok"], r["why"], r["sri_match_would_accept"]), (False, code, accept), repr(v))
        for v in ("SHA256-" + h, " sha256-" + h + "\t", "sha256-" + h + "?a?b", "sha256-" + h + " sha512-" +
                  base64.b64encode(hashlib.sha512(b"").digest()).decode()):
            self.assertTrue(S.check_integrity(b"", v, "sri-2016")["ok"], v)

    def test_strongest_algorithm_decides(self):
        h256 = base64.b64encode(hashlib.sha256(b"").digest()).decode()
        wrong512 = base64.b64encode(hashlib.sha512(b"other").digest()).decode()
        r = S.check_integrity(b"", "sha256-" + h256 + " sha512-" + wrong512, "sri-2016")
        self.assertEqual((r["ok"], r["why"]), (False, "mismatch"))       # the sha512 expression is the one compared

    def test_grammar_argument(self):
        for g in (None, "", "sri", "SRI-2016"):
            with self.assertRaises(ValueError):
                S.parse_integrity(EMPTY, g)


class Generated(unittest.TestCase):
    def test_against_the_oracle(self):
        rnd = random.Random(20261117)
        sizes = {"sha256": 32, "sha384": 48, "sha512": 64}

        def pick(good, bad):
            return rnd.choice(good) if rnd.random() < 0.85 else rnd.choice(bad)
        n = 0
        outcomes = {}
        for _ in range(4000):
            toks = []
            for _ in range(rnd.randint(0 if rnd.random() < 0.05 else 1, 3)):
                alg = pick(["sha256", "sha384", "sha512", "SHA256", "Sha384"], ["md5", "sha1", "sha-256", "", "sha 256"])
                size = sizes.get(alg.lower()) if rnd.random() < 0.85 else rnd.choice([16, 31, 33, 0])
                b = base64.b64encode(os.urandom(size or 0)).decode()
                b = pick([b, b.rstrip("="), b.replace("+", "-").replace("/", "_")], [b + "=", b[:-1], b + "\u00e9", ""])
                toks.append(alg + pick(["-"], ["", "--"]) + b + pick(["", "?x", "?a?b"], ["?\u00e9", "? "]))
            v = pick([" ", "\t", "  "], ["\n"]).join(toks)
            v = pick(["", " ", "\t"], ["\n"]) + v + pick(["", " "], ["\n"])
            for g in S.GRAMMARS:
                n += 1
                r = S.parse_integrity(v, g)
                self.assertEqual(r["ok"], oracle(v, g), (v, g, r["why"]))
                outcomes[r["why"]] = outcomes.get(r["why"], 0) + 1
        self.assertEqual(n, 8000)
        for code in (None, "empty", "grammar", "alg_not_recognised", "digest_length"):
            self.assertGreaterEqual(outcomes.get(code, 0), 50, outcomes)   # every outcome generated, accepted ones too

    def test_oracle_can_disagree(self):
        """control: the oracle is not the module (a value it refuses that a lax parser would take)"""
        self.assertFalse(oracle("sha256-47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=\n", "sri-2016"))
        self.assertTrue(oracle(EMPTY, "sri-2016"))


if __name__ == "__main__":
    unittest.main()
