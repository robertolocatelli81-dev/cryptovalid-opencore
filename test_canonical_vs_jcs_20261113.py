#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Roberto Locatelli
"""SPEC_EVIDENCE_FORMAT.md §3 (corrected on 2026-11-13, v0.6): where does the canonical profile (`verifier.canonical_payload`:
sorted keys, separators (",", ":"), ASCII-escaped; no floats, integers within ±(2^53−1)) give the same bytes as RFC 8785
(JCS), and where not? Until v0.5 §3 called the profile "a strict subset" of JCS: it is not. No product code changes here.

Adapted from cra-evidence tests/test_canonical_vs_jcs_20261113.py (same author). Two JCS encoders, written apart from each
other, are compared with the profile:
  - `jcs()` below, for the float-free domain, from RFC 8785 §3.2.2.2 (strings: only `"`, `\\` and U+0000..U+001F
    escaped, everything else literal UTF-8) and §3.2.3 (members sorted by UTF-16 code units);
  - Node's own `JSON.stringify` with keys in `Array.prototype.sort` default order (UTF-16 code units). Skipped when `node`
    is not installed.
`jcs()` has known answers: the member-order example of RFC 8785 §3.2.3 and the string of its §3.2.2 example, read on
https://www.rfc-editor.org/rfc/rfc8785.txt on 2026-11-13."""
import json
import os
import random
import shutil
import subprocess
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import verifier as V  # noqa: E402

MAX_SAFE_INT = V._SAFE_INT


def profile(doc) -> bytes:
    return V.canonical_payload(doc)


def jcs(obj) -> bytes:
    """RFC 8785 on the domain the profile accepts (null, bool, int within ±(2^53−1), str, list, dict of str)."""
    def enc(x):
        if x is None:
            return "null"
        if x is True:
            return "true"
        if x is False:
            return "false"
        if isinstance(x, int):
            assert abs(x) <= MAX_SAFE_INT
            return str(x)
        if isinstance(x, str):
            return json.dumps(x, ensure_ascii=False)
        if isinstance(x, list):
            return "[" + ",".join(enc(v) for v in x) + "]"
        if isinstance(x, dict):
            keys = sorted(x, key=lambda k: k.encode("utf-16-be"))
            return "{" + ",".join(json.dumps(k, ensure_ascii=False) + ":" + enc(x[k]) for k in keys) + "}"
        raise TypeError(type(x).__name__)
    return enc(obj).encode("utf-8")


_NODE_JCS = r"""
const canon = (v) => {
  if (v === null || typeof v !== "object") return JSON.stringify(v);
  if (Array.isArray(v)) return "[" + v.map(canon).join(",") + "]";
  return "{" + Object.keys(v).sort().map((k) => JSON.stringify(k) + ":" + canon(v[k])).join(",") + "}";
};
let s = ""; process.stdin.on("data", (d) => (s += d)).on("end", () => {
  const out = JSON.parse(s).map((doc) => Buffer.from(canon(doc), "utf8").toString("hex"));
  process.stdout.write(JSON.stringify(out));
});
"""


def node_jcs(docs):
    """JCS bytes of each document, computed by Node (None if node is absent)."""
    if not shutil.which("node"):
        return None
    p = subprocess.run(["node", "-e", _NODE_JCS], input=json.dumps(docs, ensure_ascii=True).encode(),
                       capture_output=True, timeout=120, check=True)
    return [bytes.fromhex(h) for h in json.loads(p.stdout)]


# (name, document, same bytes as JCS?)
CASES = [
    ("ascii", {"b": [1, "x", None, True], "a": {"k": "v"}}, True),
    ("ascii_escapes", {"q": "a\"b\\c/d<&>", "n": "line\nfeed\ttab"}, True),
    ("control_1f", {"c": "\x1f\x00\x08\x0c"}, True),
    ("int_limits", {"hi": MAX_SAFE_INT, "lo": -MAX_SAFE_INT, "z": 0}, True),
    ("empty", {"": "", "l": [], "o": {}}, True),
    ("del_7f", {"d": "\x7f"}, False),      # ASCII, and still different: the profile escapes U+007F, JCS does not
    ("value_e_grave", {"note": "è"}, False),
    ("key_e_grave", {"è": 1}, False),
    ("value_u0080", {"c1": "\u0080"}, False),
    ("value_u2028", {"ls": " "}, False),
    ("value_astral", {"emoji": "\U0001F600"}, False),
    ("key_order_astral_vs_e000", {"": 1, "\U00010000": 2}, False),
]


class TestProfileVersusJCS(unittest.TestCase):
    def test_jcs_known_answers_rfc8785(self):
        # §3.2.3: the expected member order is CR, "1", U+0080, U+00F6, U+20AC, U+1F600, U+FB33
        doc = {"€": "Euro Sign", "\r": "Carriage Return", "דּ": "Hebrew Letter Dalet With Dagesh",
               "1": "One", "\U0001F600": "Emoji: Grinning Face", "\u0080": "Control",
               "ö": "Latin Small Letter O With Diaeresis"}
        order = list(json.loads(jcs(doc).decode("utf-8")))
        self.assertEqual(order, ["\r", "1", "\u0080", "ö", "€", "\U0001F600", "דּ"])
        # §3.2.2 example: the input string "€$\u000F\u000aA'B"\\\\"\/" is "€$\u000f\nA'B\"\\\\\"/"
        s = json.loads('"\\u20ac$\\u000F\\u000aA\'\\u0042\\u0022\\u005c\\\\\\"\\/"')
        self.assertEqual(jcs(s), '"€$\\u000f\\nA\'B\\"\\\\\\\\\\"/"'.encode("utf-8"))

    def test_cases(self):
        for name, doc, same in CASES:
            with self.subTest(case=name):
                self.assertEqual(profile(doc) == jcs(doc), same, f"{name}: profile={profile(doc)!r} jcs={jcs(doc)!r}")
                # both are the same JSON value: the difference is in the bytes, never in the data
                self.assertEqual(json.loads(profile(doc)), json.loads(jcs(doc).decode("utf-8")))

    def test_vector_file(self):
        with open(os.path.join(HERE, "spec", "vectors", "canonical_vs_jcs.json"), encoding="utf-8") as f:
            vec = json.load(f)
        names = []
        for c in vec["cases"]:
            doc = json.loads(c["document_json_ascii"])
            self.assertEqual(profile(doc).hex(), c["profile_hex"], c["name"])
            self.assertEqual(jcs(doc).hex(), c["jcs_hex"], c["name"])
            self.assertEqual(c["profile_hex"] == c["jcs_hex"], c["same_bytes"], c["name"])
            names.append((c["name"], c["same_bytes"]))
        self.assertEqual(names, [("ascii_only", True), ("u007f", False), ("non_ascii", False),
                                 ("beyond_bmp_member_order", False)])

    def test_exact_bytes_of_the_three_divergences(self):
        self.assertEqual(profile({"note": "è"}), b'{"note":"\\u00e8"}')
        self.assertEqual(jcs({"note": "è"}), b'{"note":"\xc3\xa8"}')
        self.assertEqual(profile({"d": "\x7f"}), b'{"d":"\\u007f"}')
        self.assertEqual(jcs({"d": "\x7f"}), b'{"d":"\x7f"}')
        doc = {"": 1, "\U00010000": 2}
        self.assertEqual(list(json.loads(profile(doc))), ["", "\U00010000"])            # code points
        self.assertEqual(list(json.loads(jcs(doc).decode("utf-8"))), ["\U00010000", ""])   # UTF-16 code units

    def test_node_agrees_with_the_jcs_encoder_here(self):
        docs = [d for _, d, _ in CASES]
        got = node_jcs(docs)
        if got is None:
            self.skipTest("node not installed")
        for (name, doc, _), b in zip(CASES, got):
            with self.subTest(case=name):
                self.assertEqual(b, jcs(doc))

    def _random_doc(self, rng, alphabet, depth=0):
        def s():
            return "".join(rng.choice(alphabet) for _ in range(rng.randint(0, 6)))
        r = rng.random()
        if depth > 3 or r < 0.35:
            return rng.choice([None, True, False, rng.randint(-MAX_SAFE_INT, MAX_SAFE_INT), rng.randint(-9, 9), s()])
        if r < 0.6:
            return [self._random_doc(rng, alphabet, depth + 1) for _ in range(rng.randint(0, 4))]
        return {s(): self._random_doc(rng, alphabet, depth + 1) for _ in range(rng.randint(0, 4))}

    @staticmethod
    def _strings(x):
        if isinstance(x, str):
            yield x
        elif isinstance(x, list):
            for v in x:
                yield from TestProfileVersusJCS._strings(v)
        elif isinstance(x, dict):
            for k, v in x.items():
                yield k
                yield from TestProfileVersusJCS._strings(v)

    def test_property_same_bytes_exactly_when_no_character_is_above_u007e(self):
        ascii_alpha = [chr(c) for c in range(0x00, 0x7f)]          # U+0000..U+007E
        mixed_alpha = ascii_alpha[0x20:] + ["\x7f"] + list("èöß€\u0080 דּ") + ["\U00010000", "\U0001F600"]
        rng = random.Random(20261113)
        # each document under one ASCII key: canonical_payload reads an entry (an object) and drops its attestation fields
        ascii_docs = [{"v": self._random_doc(rng, ascii_alpha)} for _ in range(2000)]
        mixed_docs = [{"v": self._random_doc(rng, mixed_alpha)} for _ in range(2000)]
        n_equal = n_diff = 0
        for doc in ascii_docs + mixed_docs:
            is_ascii = all(ord(c) <= 0x7e for s in self._strings(doc) for c in s)
            self.assertEqual(profile(doc) == jcs(doc), is_ascii, repr(doc))
            n_equal += is_ascii
            n_diff += not is_ascii
        self.assertGreaterEqual(n_equal, 2000)     # the equality side is not vacuous …
        self.assertGreaterEqual(n_diff, 500)       # … and neither is the divergence side
        got = node_jcs(ascii_docs + mixed_docs)
        if got is not None:                        # second JCS encoder: Node's JSON.stringify
            for doc, b in zip(ascii_docs + mixed_docs, got):
                self.assertEqual(b, jcs(doc), repr(doc))


if __name__ == "__main__":
    unittest.main()
