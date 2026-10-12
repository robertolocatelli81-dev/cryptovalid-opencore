#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Unpaired UTF-16 surrogate escapes are outside the acceptance profile (spec/CONFORMANCE.md, 2026-09-14).
Positive control: before this rule verifier.py returned PASS on a lone-surrogate ledger (measured 14/09/2026,
council round 1 on the Go reference) while Go's decoder replaced it with U+FFFD → different self_hash."""
import hashlib, json, os, tempfile, unittest
import verifier as V


def _canon(e):
    return json.dumps({k: v for k, v in e.items() if k != "self_hash"}, sort_keys=True, separators=(",", ":")).encode()


def _ledger(text_data_json: str) -> str:
    """Build a one-entry ledger whose data is given as RAW JSON text (so escapes survive verbatim)."""
    data = json.loads(text_data_json)
    e = {"idx": 0, "ts": "2026-09-14T00:00:00Z", "prev_hash": "0" * 64, "data": data}
    e["self_hash"] = hashlib.sha256(_canon(e)).hexdigest()
    p = os.path.join(tempfile.mkdtemp(), "l.jsonl")
    with open(p, "w", encoding="utf-8") as f:
        f.write(json.dumps(e) + "\n")   # ensure_ascii: a lone surrogate is written back as \\udXXX
    return p


class TestLoneSurrogate(unittest.TestCase):
    def test_scanner(self):
        self.assertTrue(V.has_lone_surrogate('{"k":"\\ud800"}'))
        self.assertTrue(V.has_lone_surrogate('{"k":"\\udc00"}'))
        self.assertTrue(V.has_lone_surrogate('{"k":"\\ud800\\u0041"}'))
        self.assertTrue(V.has_lone_surrogate('{"k":"\\ud800"}'))
        self.assertFalse(V.has_lone_surrogate('{"k":"\\ud83d\\ude00"}'))   # valid pair
        self.assertFalse(V.has_lone_surrogate('{"k":"\\\\ud800"}'))        # escaped backslash + text
        self.assertFalse(V.has_lone_surrogate('{"k":"\\u00e9\\n\\"x\\\\"}'))
        self.assertFalse(V.has_lone_surrogate('{"k":"\\uzzzz"}'))          # malformed: the decoder's job (council r2)
        self.assertTrue(V.has_lone_surrogate('{"k":"\\ud800\\uzzzz"}'))  # high followed by garbage: still unpaired

    def test_malformed_escape_is_a_decode_error_not_a_profile_label(self):
        p = os.path.join(tempfile.mkdtemp(), "m.jsonl")
        with open(p, "w", encoding="utf-8") as f:
            f.write('{"idx":0,"ts":"t","prev_hash":"' + "0" * 64 + '","data":{"k":"\\uzzzz"},"self_hash":"' + "0" * 64 + '"}\n')
        r = V.verify_ledger(p)
        self.assertEqual(r["verdict"], "FAIL")
        errs = " ".join(e["error"] for e in r["parse_errors"])
        self.assertNotIn("lone_surrogate", errs)

    def test_ledger_refused_fail_closed(self):
        for raw in ('{"k":"\\ud800"}', '{"k":"\\udc00"}'):
            r = V.verify_ledger(_ledger(raw))
            self.assertEqual(r["verdict"], "FAIL", raw)
            self.assertIn("lone_surrogate", " ".join(e["error"] for e in r["parse_errors"]))

    def test_valid_pair_and_bmp_still_pass(self):
        for raw in ('{"k":"\\ud83d\\ude00"}', '{"k":"\\uffff \\u00e9 \\u2028"}', '{"k":"\\\\ud800"}'):
            self.assertEqual(V.verify_ledger(_ledger(raw))["verdict"], "PASS", raw)

    def test_shared_vectors_with_go_and_js(self):
        """vectors.json (verifiers/go) is the single source for the three languages."""
        vp = os.path.join(os.path.dirname(os.path.abspath(__file__)), "verifiers", "go", "vectors.json")
        doc = json.load(open(vp, encoding="utf-8"))
        for r in doc["refuse"]:
            with self.assertRaises(Exception, msg=r["why"]):
                V._loads_strict(r["text"])
        for a in doc["accept"]:
            obj = V._loads_strict(a["input"])
            self.assertEqual(json.dumps(obj, sort_keys=True, separators=(",", ":")), a["canonical"])


class TestRawBytesThatAreNotUTF8(unittest.TestCase):
    """NEMESIS 12/10/2026: the file is read with surrogateescape, so a byte that is not UTF-8 became a raw U+DCxx code point
    and a self_hash computed over it made the line PASS (JS, Go, Java, Rust and Swift: FAIL). The hash below is computed
    over exactly what surrogateescape reads, so only the rule can make the line FAIL."""

    @staticmethod
    def _write(raw: bytes, in_key: bool) -> str:
        s = raw.decode("utf-8", "surrogateescape")
        e = {"idx": 0, "ts": "t", "prev_hash": "0" * 64, "data": ({s: 1} if in_key else {"k": "a" + s + "b"})}
        e["self_hash"] = hashlib.sha256(_canon(e)).hexdigest()
        p = os.path.join(tempfile.mkdtemp(), "b.jsonl")
        with open(p, "wb") as f:
            f.write(json.dumps(e, ensure_ascii=False).encode("utf-8", "surrogateescape") + b"\n")
        return p

    def test_refused_in_values_and_keys(self):
        for raw in (b"\xff", b"\xfe", b"\x80", b"\xc0\xaf", b"\xed\xa0\x80", b"\xf0\x9f\x98", b"\xf5\x80\x80\x80", b"\xe2\x82"):
            for in_key in (False, True):
                r = V.verify_ledger(self._write(raw, in_key))
                self.assertEqual(r["verdict"], "FAIL", (raw, in_key))
                self.assertIn("not_utf8", " ".join(e["error"] for e in r["parse_errors"]), (raw, in_key))

    def test_valid_utf8_still_passes(self):   # control: the rule must not touch real UTF-8 (2, 3 and 4 bytes)
        for raw in ("\u00e9".encode(), "\u20ac".encode(), "\U0001F600".encode(), "\ufffd".encode()):
            for in_key in (False, True):
                self.assertEqual(V.verify_ledger(self._write(raw, in_key))["verdict"], "PASS", (raw, in_key))


if __name__ == "__main__":
    unittest.main()
