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
import subprocess
import tempfile
import unittest

from test_ledger_input_20261122 import _all, _reason, _verifiers

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

    def assertParsed(self, body, what, entries=True):
        """at the bound: read and parsed, FAIL for what the lines hold, never for the budget; `entries`: a line that is
        not blank was read (a verifier that left the last line out would say the ledger is empty)"""
        for name, (rc, verdict, reason, _) in self.run_on(what, body).items():
            self.assertEqual((rc, verdict), (1, "FAIL"), (what, name))
            self.assertNotIn(reason, (TOO_MANY_LINES, TOO_MANY_TOKENS), (what, name))
            if entries:
                self.assertNotIn("empty_ledger", reason or "", (what, name))

    def test_lines_at_the_bound_are_parsed_control(self):
        self.assertParsed(b"0\n" * LINES, "lines_at")
        self.assertParsed(b"0\n" * (LINES - 1) + b"0", "lines_at_no_final_lf")
        self.assertParsed(b"\n" * (LINES - 1) + b"0\n", "only_the_last_line_at_the_bound")

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

    def test_the_example_at_the_line_bound_is_verified_control(self):
        """exactly 2^20 lines, the last three the example: PASS (a verifier that kept one line less would lose an entry)"""
        here = os.path.dirname(os.path.abspath(__file__))
        with open(os.path.join(here, "examples", "sample_ledger.jsonl"), "rb") as f:
            sample = f.read()
        self.assertTrue(sample.endswith(b"\n"))
        for name, (rc, verdict, reason, _) in self.run_on("sample_at", b"\n" * (LINES - sample.count(b"\n")) + sample).items():
            self.assertEqual((rc, verdict, reason), (0, "PASS", None), name)

    def test_each_of_the_four_characters_is_a_token(self):
        for c in (b"{", b"[", b",", b":"):
            self.assertReason(b'"' + c * (TOKENS + 1) + b'"\n', TOO_MANY_TOKENS, "tokens_over_%d" % c[0])

    def test_a_cr_ends_no_line_control(self):
        self.assertParsed(b"\r" * (LINES + 1), "cr_over", entries=False)
        self.assertParsed(b"\r\n" * LINES, "crlf_at", entries=False)

    def test_the_reason_is_alone_whatever_the_caller_asks(self):
        """NEMESIS 22/11/2026: the Go verifier added `ledger_id_mismatch` and `tip_missing` to the reason of rule 9"""
        p = os.path.join(self.tmp, "alone")
        asked = [("expect-ledger-id", "a" * 64), ("require-tip",), ("trusted-pubkey", "a" * 64),
                 ("tip-not-before", "2026-01-01T00:00:00Z")]
        for body, want in ((b"\n" * (LINES + 1), TOO_MANY_LINES), (b'"' + b"," * (TOKENS + 1) + b'"\n', TOO_MANY_TOKENS)):
            with open(p, "wb") as f:
                f.write(body)
            for name, argv in self.bins.items():
                dash = "--" if name in ("python", "js") else "-"
                for a in asked:
                    flags = [dash + a[0]] + list(a[1:])
                    cp = subprocess.run(argv + (flags + [p] if name == "go" else [p] + flags), capture_output=True, text=True,
                                        timeout=60, stdin=subprocess.DEVNULL)
                    doc = json.loads(cp.stdout)
                    got = ([e["error"] for e in doc["parse_errors"]] if name == "python" else [doc["error"]] if name == "js"
                           else doc["failures"])
                    self.assertEqual((cp.returncode, doc["verdict"], got), (1, "FAIL", [want]), (name, a[0]))
        os.remove(p)

    @unittest.skipUnless(hasattr(os, "fork"), "needs a data limit (resource)")
    def test_256_mib_of_lines_under_a_data_limit_of_2_gb(self):
        """past the line bound nothing is kept or parsed: 128 Mi lines `0`, the bound of rule 8 exactly, are refused by
        the four, verifier.py and Go under a data limit of 2 GB (Node and Java bound their own heap). Until 0.28.0
        16 MiB of such lines ended verifier.py in MemoryError and Go in `fatal error: out of memory`."""
        import resource
        p = os.path.join(self.tmp, "lines_256mib")
        with open(p, "wb") as f:
            for _ in range(128):
                f.write(b"0\n" * (1 << 20))
        try:
            for name, argv in self.bins.items():
                cap = (lambda: resource.setrlimit(resource.RLIMIT_DATA, (2 << 30, 2 << 30))) if name in ("python", "go") else None
                cp = subprocess.run(argv + [p], capture_output=True, text=True, timeout=120, stdin=subprocess.DEVNULL,
                                    preexec_fn=cap)
                self.assertEqual(cp.returncode, 1, (name, cp.stderr[-200:]))
                self.assertEqual(_reason(name, json.loads(cp.stdout)), TOO_MANY_LINES, name)
        finally:
            os.remove(p)


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
            base = sum(json.dumps(dict(tip, zz="")).count(c) for c in "{[,:")
            for n, want in ((TOKENS, None), (TOKENS + 1, _ROW[2])):
                # an extra member: at the bound the closed object names it (a later row), one token more is row 2
                with open(led + ".tip.json", "w") as f:
                    json.dump(dict(tip, zz="," * (n - base)), f)
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


class TestTheReadersOfALedgerBesideTheVerifier(unittest.TestCase):
    """NEMESIS 22/11/2026: the evidence pack and the signature layer parsed every line of a ledger rule 9 refuses
    (`evidence_pack.py verify` ended in MemoryError, no receipt, under a data limit of 3 GB on 128 MiB of 8 Mi lines)."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.led = os.path.join(self.tmp, "l.jsonl")
        self.body = b'{"signature":1}\n' * (LINES + 1)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def no_line_is_parsed(self):
        from unittest import mock
        import evidence_pack
        import signer
        return (mock.patch.object(signer, "_load_line", side_effect=AssertionError("a line was parsed")),
                mock.patch.object(evidence_pack, "_lines", side_effect=AssertionError("the lines were read")))

    def test_the_pack_verifier_parses_no_line(self):
        import evidence_pack
        here = os.path.dirname(os.path.abspath(__file__))
        shutil.copy(os.path.join(here, "examples", "sample_ledger.jsonl"), self.led)
        pack = os.path.join(self.tmp, "pack")
        evidence_pack.build_pack([self.led], pack)
        self.assertTrue(evidence_pack.verify_pack(pack)["ledgers_ok"])   # control
        with open(os.path.join(pack, "l.jsonl"), "wb") as f:
            f.write(self.body)
        a, b = self.no_line_is_parsed()
        with a, b:
            r = evidence_pack.verify_pack(pack)
        self.assertEqual(r["ledgers"], [{"file": "l.jsonl", "hash_pass": False, "sig_pass": False, "untruncated": False,
                                         "pq_protected": False}])
        self.assertFalse(r["ledgers_ok"])

    @unittest.skipUnless(HAVE_CRYPTO, "needs `cryptography` (the `sign` extra)")
    def test_the_signature_layer_parses_no_line(self):
        import cryptovalid_mcp
        import signer
        with open(self.led, "wb") as f:
            f.write(self.body)
        a, b = self.no_line_is_parsed()
        with a, b:
            sv = signer.verify_file(self.led, "a" * 64)
            m = cryptovalid_mcp.t_verify_ledger({"path": self.led, "expected_pubkey_hex": "a" * 64})
        self.assertFalse(sv["ok"])
        self.assertEqual(sv["failures"], [{"idx": 0, "reason": "input_too_large"}])
        self.assertIs(m["valid"], False)
        self.assertEqual(m["signatures"]["failures"], [{"idx": 0, "reason": "input_too_large"}])
        self.assertEqual(m["result"]["parse_errors"][0]["error"], TOO_MANY_LINES)


class TestTheSegmentWriterKeepsToTheBudget(unittest.TestCase):
    """NEMESIS 22/11/2026: the ingest writer sealed a segment on its entries alone (100 000 by default), so entries of
    more than 83 tokens made segments that `verify_archive` refused once rule 9 was in the verifier."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_a_segment_is_sealed_before_it_holds_too_many_tokens(self):
        import cryptovalid_ingest as I
        g = I.Ingestor(self.tmp, fsync=False)
        for _ in range(20):                      # entries of 400 012 tokens: 20 are within 2^23, 21 are not
            g.append({"v": [0] * 400000})
        g.close(seal=False)
        g = I.Ingestor(self.tmp, fsync=False)    # resumed: the tokens of the open segment are counted again
        for _ in range(2):
            g.append({"v": [0] * 400000})
        g.close()
        counts = []
        for name in sorted(n for n in os.listdir(self.tmp) if n.endswith(".jsonl")):
            with open(os.path.join(self.tmp, name), "rb") as f:
                b = f.read()
            counts.append((b.count(b"\n"), sum(b.count(c) for c in (b"{", b"[", b",", b":")) <= TOKENS))
        self.assertEqual(counts[:2], [(20, True), (2, True)])
        r = I.verify_archive(self.tmp)
        self.assertTrue(r["ok"], r["failures"])
        self.assertEqual(r["segments_verified"], 2)

    def test_what_no_verifier_would_read_is_refused_by_the_writer(self):
        import cryptovalid_ingest as I
        with self.assertRaises(ValueError):
            I.Ingestor(self.tmp, rotate_entries=LINES + 1)
        g = I.Ingestor(self.tmp, rotate_entries=LINES, fsync=False)
        with self.assertRaises(ValueError):
            g.append({"v": [0] * TOKENS})
        self.assertEqual(g.append({"v": 1})["idx"], 0)   # the refused entry left the chain as it was
        g.close()
        self.assertTrue(I.verify_archive(self.tmp)["ok"])

    def test_a_seal_for_tokens_anchors_outside_the_lock(self):
        """The rotation keeps the TSA anchor outside the lock of append (a slow TSA must never block the others): the
        seal a token bound forces does too. A seal run under the lock left another thread's append waiting for it."""
        import threading
        import cryptovalid_ingest as I
        g = I.Ingestor(self.tmp, fsync=False)
        g._tsa_url = "http://anchor.invalid"     # an anchor is due on every seal; _anchor below stands in for the TSA
        other = {}

        def slow_anchor(path, sth):
            t = threading.Thread(target=lambda: other.setdefault("ref", g.append({"v": 1})), daemon=True)
            t.start()
            t.join(5)                            # an append during the anchor: it must not wait for the seal
            other["blocked"], other["thread"] = t.is_alive(), t
        g._anchor = slow_anchor
        for _ in range(21):                      # the 21st entry of 400 012 tokens forces the seal
            g.append({"v": [0] * 400000})
        other["thread"].join(30)                 # under the lock it could only finish once the seal returned
        g.close(seal=False)
        self.assertIs(other.get("blocked"), False, other)
        self.assertTrue(I.verify_archive(self.tmp)["ok"])

    def test_concurrent_appends_that_cross_the_token_bound_lose_nothing(self):
        import threading
        import cryptovalid_ingest as I
        g = I.Ingestor(self.tmp, fsync=False)
        refs = []

        def worker():
            for _ in range(6):
                refs.append(g.append({"s": "," * 3_000_000}))   # 3 000 0xx tokens: two entries per segment
        ts = [threading.Thread(target=worker) for _ in range(4)]
        for t in ts:
            t.start()
        for t in ts:
            t.join()
        g.close()
        r = I.verify_archive(self.tmp)
        self.assertTrue(r["ok"], r["failures"])
        self.assertEqual(len({(x["segment"], x["idx"]) for x in refs}), 24)
        total = 0
        for name in (n for n in os.listdir(self.tmp) if n.endswith(".jsonl")):
            with open(os.path.join(self.tmp, name), "rb") as f:
                b = f.read()
            total += b.count(b"\n")
            self.assertLessEqual(sum(b.count(c) for c in (b"{", b"[", b",", b":")), TOKENS, name)
        self.assertEqual(total, 24)


    # NEMESIS 22/11/2026 (review of 291283c): the loop of append lets the lock go to seal. What another thread does
    # in that window is played here by a thread started from the lock itself, so each case happens every time
    def _watched(self, budget=100):
        import threading
        import cryptovalid_ingest as I

        class Lock:
            """The writer's lock; `release` and `acquire` (the two calls of the loop) run a hook once, in another thread."""
            def __init__(self, inner):
                self.inner, self.after_release, self.before_acquire = inner, None, None

            def __enter__(self):
                return self.inner.__enter__()

            def __exit__(self, *a):
                return self.inner.__exit__(*a)

            def _other_thread(self, hook):
                if hook:
                    t = threading.Thread(target=hook, daemon=True)
                    t.start()
                    t.join(20)
                    assert not t.is_alive(), "the other thread waited for a lock the loop should have let go"

            def release(self):
                self.inner.release()
                hook, self.after_release = self.after_release, None
                self._other_thread(hook)

            def acquire(self, *a, **k):
                hook, self.before_acquire = self.before_acquire, None
                self._other_thread(hook)
                return self.inner.acquire(*a, **k)
        g = I.Ingestor(self.tmp, fsync=False)
        g._max_tokens, g._lock = budget, Lock(g._lock)   # 100 tokens: one entry of 40 numbers, not two
        return g, I

    def _segments(self):
        out = []
        for name in sorted(n for n in os.listdir(self.tmp) if n.endswith(".jsonl")):
            with open(os.path.join(self.tmp, name), "rb") as f:
                b = f.read()
            out.append((b.count(b"\n"), sum(b.count(c) for c in (b"{", b"[", b",", b":"))))
        return out

    def test_a_segment_another_thread_filled_meanwhile_is_sealed_too(self):
        """After its seal the entry is measured against the segment as it is THEN: another thread may have filled it."""
        g, I = self._watched()
        big = {"v": [0] * 40}
        g.append(big)
        g._lock.before_acquire = lambda: g.append(big)   # the new segment is taken before the loop has the lock back
        ref = g.append(big)
        g.close()
        self.assertEqual(ref, {"segment": "ledger-000002.jsonl", "idx": 0})
        segments = self._segments()
        self.assertEqual([n for n, _ in segments[:3]], [1, 1, 1])
        self.assertTrue(all(t <= 100 for _, t in segments), segments)
        self.assertTrue(I.verify_archive(self.tmp)["ok"])

    def test_a_segment_another_thread_has_sealed_is_not_sealed_again(self):
        """`only_seq`: the seal of the loop is for the segment it saw full, not for the one opened meanwhile."""
        g, I = self._watched()
        big = {"v": [0] * 40}
        g.append(big)
        g._lock.after_release = lambda: (g.seal(), g.append({"p": 1}))   # another thread rotates and writes first
        ref = g.append(big)
        g.close()
        self.assertEqual(ref, {"segment": "ledger-000001.jsonl", "idx": 1})   # beside the other entry, not after a seal of one
        self.assertEqual([n for n, _ in self._segments()[:2]], [1, 2])
        self.assertTrue(I.verify_archive(self.tmp)["ok"])

    def test_a_seal_for_tokens_that_fails_leaves_the_lock_and_the_chain_as_they_were(self):
        g, I = self._watched()
        big = {"v": [0] * 40}
        g.append(big)
        flush = g.flush

        def full_disk():
            g.flush = flush
            raise OSError(28, "No space left on device")
        g.flush = full_disk
        with self.assertRaises(OSError) as c:    # the error of the seal, not one about a lock that is not held
            g.append(big)
        self.assertEqual(c.exception.errno, 28)
        g._lock.after_release = lambda: g.append({"p": 1})   # and another thread can append: the lock is free
        self.assertEqual(g.append(big), {"segment": "ledger-000001.jsonl", "idx": 0})
        g.close()
        self.assertEqual([n for n, _ in self._segments()[:2]], [2, 1])
        self.assertTrue(I.verify_archive(self.tmp)["ok"])

    def test_an_append_after_close_is_refused(self):
        """It returned a reference and the entry was never written (NEMESIS 22/11/2026, the same on 33678c9)."""
        import cryptovalid_ingest as I
        g = I.Ingestor(self.tmp, fsync=False)
        g.append({"v": 1})
        g.close()
        with self.assertRaises(ValueError):
            g.append({"v": 2})
        r = I.verify_archive(self.tmp)
        self.assertTrue(r["ok"], r["failures"])

if __name__ == "__main__":
    unittest.main()
