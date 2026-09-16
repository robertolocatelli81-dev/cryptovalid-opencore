"""Acceptance-profile edges found by the council on 16/09/2026 (round 5, Java verifier review): a boolean idx,
a lone CR between entries, a U+00A0-only line, a signed \\u escape, a tip with duplicate keys / a float / a
non-string log key, a bad --trusted-pubkey. Every case is FAIL in the Python reference (and in the oracle)."""
import hashlib, json, os, shutil, sys, tempfile, unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import verifier as V
try:
    import signer, cryptovalid_tip as T
    signer._ed(); HAVE_CRYPTO = True
except Exception:  # noqa: BLE001
    HAVE_CRYPTO = False


def _canon(e):
    return json.dumps(e, sort_keys=True, separators=(",", ":")).encode()


def _chain(n, idx=None):
    out, prev = [], "0" * 64
    for i in range(n):
        e = {"idx": idx(i) if idx else i, "ts": "t", "data": {"i": i}, "prev_hash": prev}
        e["self_hash"] = hashlib.sha256(_canon(e)).hexdigest(); prev = e["self_hash"]; out.append(e)
    return out


class TestProfileEdges(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(); self.p = os.path.join(self.tmp, "l.jsonl")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _w(self, text):
        with open(self.p, "wb") as f:
            f.write(text.encode("utf-8"))
        return V.verify_ledger(self.p)

    def test_boolean_idx_is_not_sequential(self):
        r = self._w("\n".join(json.dumps(e, separators=(",", ":")) for e in _chain(2, idx=lambda i: bool(i))))
        self.assertEqual(r["verdict"], "FAIL"); self.assertFalse(r["idx_monotonic"])

    def test_lone_cr_is_not_a_line_separator(self):
        a, b = _chain(2)
        r = self._w(json.dumps(a, separators=(",", ":")) + "\r" + json.dumps(b, separators=(",", ":")) + "\n")
        self.assertEqual(r["verdict"], "FAIL"); self.assertEqual(r["entries_count"], 0)

    def test_nbsp_only_line_is_not_blank(self):
        (a,) = _chain(1)
        r = self._w(" \n" + json.dumps(a, separators=(",", ":")) + "\n")
        self.assertEqual(r["verdict"], "FAIL")
        r = self._w(" \t\r\n" + json.dumps(a, separators=(",", ":")) + "\n")   # ASCII blank line: skipped
        self.assertEqual(r["verdict"], "PASS")

    def test_signed_u_escape_is_a_decode_error(self):
        (a,) = _chain(1)
        r = self._w(json.dumps(a, separators=(",", ":")).replace('"t"', '"\\u+041"'))
        self.assertEqual(r["verdict"], "FAIL"); self.assertIn("json_decode", json.dumps(r["parse_errors"]))

    @unittest.skipUnless(HAVE_CRYPTO, "cryptography assente")
    def test_tip_is_parsed_strictly_and_trusted_key_validated(self):
        ch = _chain(3)
        with open(self.p, "w") as f:
            f.write("".join(json.dumps(e) + "\n" for e in ch))
        k = os.path.join(self.tmp, "k"); pk = signer.keygen(k)["public_key_hex"]
        tip = T.sign_tip(self.p, k); tp = self.p + ".tip.json"
        self.assertEqual(V.verify_ledger(self.p, trusted_pubkey_hex=pk)["verdict"], "PASS")
        raw = open(tp).read()
        for bad in (raw[:-1] + ',"ts":"' + tip["ts"] + '"}', json.dumps(dict(tip, note=1.5)), json.dumps(dict(tip, log_pubkey_hex=123))):
            open(tp, "w").write(bad)
            r = V.verify_ledger(self.p, trusted_pubkey_hex=pk)
            self.assertEqual(r["verdict"], "FAIL", bad[:60]); self.assertRegex(r["tip"]["error"], "tip_unreadable|tip_invalid")
        open(tp, "w").write(raw)
        r = V.verify_ledger(self.p, trusted_pubkey_hex=pk.upper())
        self.assertEqual(r["verdict"], "FAIL"); self.assertIn("bad_trusted_key", r["tip"]["error"])


if __name__ == "__main__":
    unittest.main()
