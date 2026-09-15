"""Signed chain tip (15/09/2026): the tail limit of a snapshot chain moves. Every attack below is INVISIBLE to
the bare verifier (positive control asserts PASS without the tip) and a named FAIL with the tip."""
import hashlib, json, os, shutil, sys, tempfile, unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import verifier as V
import cryptovalid_tip as T
try:
    import signer
    HAVE_CRYPTO = True
except Exception:  # noqa: BLE001
    HAVE_CRYPTO = False


def _canon(e):
    return json.dumps(e, sort_keys=True, separators=(",", ":")).encode()


def _ledger(n):
    out, prev = [], "0" * 64
    for i in range(n):
        e = {"idx": i, "ts": f"2026-09-15T07:00:{i:02d}Z", "data": {"i": i}, "prev_hash": prev}
        e["self_hash"] = hashlib.sha256(_canon(e)).hexdigest(); prev = e["self_hash"]; out.append(e)
    return out


def _write(path, entries):
    with open(path, "w") as f:
        for e in entries:
            f.write(json.dumps(e) + "\n")


@unittest.skipUnless(HAVE_CRYPTO, "cryptography assente")
class TestTip(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(); self.led = os.path.join(self.tmp, "l.jsonl")
        self.base = _ledger(20); _write(self.led, self.base)
        self.k = os.path.join(self.tmp, "log.key"); self.pk = signer.keygen(self.k)["public_key_hex"]
        self.other = os.path.join(self.tmp, "other.key"); self.other_pk = signer.keygen(self.other)["public_key_hex"]
        self.tip = T.sign_tip(self.led, self.k)
        self.assertTrue(os.path.exists(self.led + ".tip.json"))

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _v(self, **kw):
        return V.verify_ledger(self.led, trusted_pubkey_hex=self.pk, **kw)

    def _errors(self, r):
        return " ".join(e["error"] for e in r.get("parse_errors", []))

    def test_intact_with_tip_is_pass_and_trusted(self):
        r = self._v()
        self.assertEqual(r["verdict"], "PASS"); self.assertTrue(r["tip"]["ok"]); self.assertTrue(r["tip"]["trusted"])
        self.assertIn("LOG KEY", r["scope"]["does_not_prove"][0])

    def test_tail_deletion_invisible_without_tip_named_with_tip(self):
        _write(self.led, self.base[:-1])
        bare = V.verify_ledger(self.led, tip=None)          # positive control: the bare chain cannot see it
        os.remove(self.led + ".tip.json")
        self.assertEqual(V.verify_ledger(self.led)["verdict"], "PASS")
        _write(self.led, self.base[:-1]); T.sign_tip(self.led, self.k)   # re-sign a shorter file: honest PASS
        self.assertEqual(self._v()["verdict"], "PASS")
        _write(self.led, self.base); T.sign_tip(self.led, self.k)
        for cut in (1, 5, 19):
            _write(self.led, self.base[:-cut])
            r = self._v(); self.assertEqual(r["verdict"], "FAIL"); self.assertIn("tail_truncated", self._errors(r))
        del bare

    def test_suffix_rewrite_and_unsealed_append_are_named(self):
        forged = self.base[:-3] + _ledger(20)[17:]          # same count, re-chained suffix → differs in ts? make it differ
        forged[-1]["data"] = {"forged": True}
        prev = forged[-2]["self_hash"]
        e = {k: v for k, v in forged[-1].items() if k != "self_hash"}; e["prev_hash"] = prev
        e["self_hash"] = hashlib.sha256(_canon(e)).hexdigest(); forged[-1] = e
        _write(self.led, forged)
        r = self._v(); self.assertEqual(r["verdict"], "FAIL"); self.assertIn("tail_rewritten", self._errors(r))
        _write(self.led, _ledger(21))
        r = self._v(); self.assertEqual(r["verdict"], "FAIL"); self.assertIn("unsealed_tail", self._errors(r))

    def test_attacker_without_key_cannot_resign_and_missing_tip_is_named_when_required(self):
        _write(self.led, self.base[:-1]); T.sign_tip(self.led, self.other)   # re-signed with a different key
        r = self._v(); self.assertEqual(r["verdict"], "FAIL"); self.assertIn("tip_invalid", self._errors(r))
        os.remove(self.led + ".tip.json")
        self.assertEqual(self._v()["verdict"], "PASS")                       # not required: limit applies in full
        self.assertIsNone(self._v()["tip"])
        r = self._v(require_tip=True); self.assertEqual(r["verdict"], "FAIL"); self.assertIn("tip_missing", self._errors(r))
        T.sign_tip(self.led, self.k)
        r = V.verify_ledger(self.led)                                        # no trusted key: tip NOT checked, chain verdict only
        self.assertEqual(r["verdict"], "PASS"); self.assertFalse(r["tip"]["checked"]); self.assertIn("tip_untrusted", r["tip"]["error"])
        r = V.verify_ledger(self.led, require_tip=True)                      # ...and required → FAIL, never fail-open
        self.assertEqual(r["verdict"], "FAIL"); self.assertIn("tip_untrusted", self._errors(r))
        # THE attack (council R2, Gemini): attacker's own key inside a forged tip, verifier run without --trusted-pubkey
        _write(self.led, self.base[:-1]); T.sign_tip(self.led, self.other)
        self.assertEqual(V.main([self.led, "--require-tip", "--quiet"]), 1)
        self.assertEqual(T.main(["check", self.led]), 2)                     # check without a trusted key: exit 2
        self.assertEqual(T.main(["check", self.led, "--trusted-pubkey", self.pk]), 1)

    def test_tampered_tip_document_is_refused(self):
        p = self.led + ".tip.json"; d = json.load(open(p))
        for field, val in (("entries", 19), ("tip_sha256", "11" * 32), ("ts", "2030-01-01T00:00:00+00:00"),
                           ("signature_hex", "00" * 64)):
            bad = dict(d); bad[field] = val
            json.dump(bad, open(p, "w"))
            r = self._v(); self.assertEqual(r["verdict"], "FAIL", field); self.assertIn("tip_invalid", self._errors(r))
        for garbage in ("[1]", "{broken", ""):
            open(p, "w").write(garbage)
            r = self._v(); self.assertEqual(r["verdict"], "FAIL"); self.assertIn("tip_", self._errors(r))

    def test_rollback_is_declared_and_refusable(self):
        # truncate + restore an OLDER genuine tip: passes (the tip proves "a signed state", not "the latest") —
        # declared limit; --tip-not-before refuses it; strict types: "10" / 10.0 are not the profile (Go agrees)
        old_tip = open(self.led + ".tip.json").read()
        _write(self.led, _ledger(25)); T.sign_tip(self.led, self.k, ts="2026-09-15T09:00:00+00:00")
        _write(self.led, self.base); open(self.led + ".tip.json", "w").write(old_tip)
        r = self._v(); self.assertEqual(r["verdict"], "PASS")
        self.assertTrue(any("ROLLBACK" in x for x in r["scope"]["does_not_prove"]))
        r = self._v(tip_not_before="2026-09-15T09:00:00+00:00")
        self.assertEqual(r["verdict"], "FAIL"); self.assertIn("tip_rolled_back", self._errors(r))
        # instants, not strings (council R2, Opus): 'Z' form and a different offset of the SAME instant
        _write(self.led, self.base); T.sign_tip(self.led, self.k, ts="2026-09-15T10:00:00+00:00")
        for same in ("2026-09-15T10:00:00Z", "2026-09-15T10:00:00+00:00", "2026-09-15T12:00:00+02:00", "2026-09-15T09:59:59.5Z"):
            self.assertEqual(self._v(tip_not_before=same)["verdict"], "PASS", same)
        self.assertEqual(self._v(tip_not_before="2026-09-15T10:00:01Z")["verdict"], "FAIL")
        # the verifier's argument follows the SAME profile as the tip (Gemini: py/js took a date-only, Go did not)
        for bad in ("not-a-date", "2026-09-15", "2026-09-15T10:00:00", "2026-09-15T10:00Z"):
            r = self._v(tip_not_before=bad); self.assertEqual(r["verdict"], "FAIL", bad); self.assertIn("bad_not_before", self._errors(r))
        # VALUE-layer profile, by hand and identical in the three checkers (review with Fable 5.1): impossible
        # dates, hour 24, year 0000, comma / 10-digit fraction, offset +24:00 are tip_invalid; 4-digit fraction ok
        _write(self.led, self.base)
        for bad_ts in ("2026-02-30T10:25:00Z", "2026-04-31T10:25:00Z", "2026-09-15T24:00:00Z", "0000-01-01T00:00:00Z",
                       "2026-09-15T10:25:60Z", "2026-09-15T10:25:00,5Z", "2026-09-15T10:25:00.1234567890Z",
                       "2026-09-15T10:25:00+24:00", "2026-09-15T10:25:00+05:60"):
            T.sign_tip(self.led, self.k, ts=bad_ts)
            r = self._v(); self.assertEqual(r["verdict"], "FAIL", bad_ts); self.assertIn("tip_invalid", self._errors(r))
        for ok_ts in ("2024-02-29T23:59:59Z", "2026-09-15T10:00:00.1234Z", "2026-09-15T10:00:00.123456789-11:30", "9999-12-31T23:59:59+23:59"):
            T.sign_tip(self.led, self.k, ts=ok_ts)
            self.assertEqual(self._v()["verdict"], "PASS", ok_ts)
        with self.assertRaises(ValueError):
            T.parse_instant("2023-02-29T00:00:00Z")   # not a leap year
        d = json.load(open(self.led + ".tip.json"))
        for bad in ("20", 20.0, True):
            json.dump(dict(d, entries=bad), open(self.led + ".tip.json", "w"))
            r = self._v(); self.assertEqual(r["verdict"], "FAIL", repr(bad)); self.assertIn("integer", self._errors(r))

    def test_payload_bytes_are_the_cross_language_oracle(self):
        self.assertEqual(T.tip_payload(3, "cd" * 32, "ab" * 32, "2026-09-15T07:00:00+00:00"),
                         b'{"entries":3,"kind":"cryptovalid_tip/1","ledger_id":"' + b"cd" * 32 + b'","tip_sha256":"' + b"ab" * 32 + b'","ts":"2026-09-15T07:00:00+00:00"}')

    def test_ledger_identity_same_key_two_ledgers(self):
        # council 15/09 (Sonnet/Gemini/Opus): one log key, two ledgers. B's tip on A's file is named; the WHOLE
        # pair (B's file + B's tip) put in A's place is caught only out of band, with --expect-ledger-id.
        other = os.path.join(self.tmp, "B.jsonl"); b = _ledger(20); b[0]["data"] = {"ledger": "B"}
        prev = "0" * 64
        for e in b:                                    # rechain B so it differs from A from entry 0
            body = {k: v for k, v in e.items() if k != "self_hash"}; body["prev_hash"] = prev
            e.clear(); e.update(body); e["self_hash"] = hashlib.sha256(_canon(body)).hexdigest(); prev = e["self_hash"]
        _write(other, b); T.sign_tip(other, self.k)
        shutil.copy(other + ".tip.json", self.led + ".tip.json")
        r = self._v(); self.assertEqual(r["verdict"], "FAIL"); self.assertIn("tip_of_another_ledger", self._errors(r))
        a_id = self.base[0]["self_hash"]
        shutil.copy(other, self.led); shutil.copy(other + ".tip.json", self.led + ".tip.json")   # whole pair swapped
        self.assertEqual(self._v()["verdict"], "PASS")                                            # declared: blind
        r = self._v(expect_ledger_id=a_id); self.assertEqual(r["verdict"], "FAIL"); self.assertIn("ledger_id_mismatch", self._errors(r))
        _write(self.led, self.base); T.sign_tip(self.led, self.k)
        self.assertEqual(self._v(expect_ledger_id=a_id)["verdict"], "PASS")
        self.assertEqual(V.main([self.led, "--trusted-pubkey", self.pk, "--expect-ledger-id", "00" * 32, "--quiet"]), 1)

    def test_cli(self):
        self.assertEqual(V.main([self.led, "--trusted-pubkey", self.pk, "--quiet"]), 0)
        _write(self.led, self.base[:-1])
        self.assertEqual(V.main([self.led, "--trusted-pubkey", self.pk, "--quiet"]), 1)
        self.assertEqual(T.main(["check", self.led, "--trusted-pubkey", self.pk]), 1)


if __name__ == "__main__":
    unittest.main()
