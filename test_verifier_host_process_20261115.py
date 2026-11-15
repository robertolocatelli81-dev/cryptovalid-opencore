#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""verify_ledger used as a library leaves the host process as it found it (15/11/2026).

Until 0.24.0 the recursion headroom of the strict decoder raised the interpreter limit and left it raised: a host that
called verify_ledger once ran with 1796 instead of 1000 for the rest of its life (measured). Now the limit is restored
when the decode ends, on a PASS, on a FAIL, on a refusal raised inside the decoder, from a deep caller and from several
threads at once; a limit the host set higher itself is left alone. On 0.24.0 test_limit_restored_* fail."""
import json
import os
import sys
import tempfile
import threading
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import verifier as V  # noqa: E402

SAMPLE = os.path.join(HERE, "examples", "sample_ledger.jsonl")
TAMPERED = os.path.join(HERE, "examples", "sample_ledger_tampered.jsonl")


def _ledger(path, datas):
    prev = V.GENESIS_PREV
    with open(path, "w", encoding="utf-8") as f:
        for i, d in enumerate(datas):
            e = {"idx": i, "ts": "2026-11-15T00:00:00Z", "data": d, "prev_hash": prev}
            e["self_hash"] = V.hash_with("sha256", V.canonical_payload(e))
            prev = e["self_hash"]
            f.write(json.dumps(e) + "\n")


def _deep(n):
    d = {}
    for _ in range(n):
        d = {"a": d}
    return d


class TestHostProcess(unittest.TestCase):
    def setUp(self):
        self.base = sys.getrecursionlimit()
        self.addCleanup(sys.setrecursionlimit, self.base)
        self.d = tempfile.mkdtemp(prefix="cv_host_")

    def test_limit_restored_after_pass_and_fail(self):
        for path, verdict in ((SAMPLE, "PASS"), (TAMPERED, "FAIL")):
            with self.subTest(path=path):
                self.assertEqual(V.verify_ledger(path)["verdict"], verdict)
                self.assertEqual(sys.getrecursionlimit(), self.base)

    def test_limit_restored_after_a_refusal_inside_the_decoder(self):
        p = os.path.join(self.d, "dup.jsonl")
        with open(p, "w") as f:
            f.write('{"a":1,"a":2}\n')
        self.assertEqual(V.verify_ledger(p)["verdict"], "FAIL")
        self.assertEqual(sys.getrecursionlimit(), self.base)
        for bad in ('{"a":1,"a":2}', '{"x":1.5}', '{"x":NaN}'):
            with self.assertRaises(ValueError):
                V._loads_strict(bad)
            self.assertEqual(sys.getrecursionlimit(), self.base, bad)

    def test_limit_restored_after_a_deep_caller_and_deep_lines(self):
        p = os.path.join(self.d, "deep.jsonl")
        _ledger(p, [_deep(V.MAX_JSON_DEPTH - 8), {"b": 1}])

        def down(n):
            return down(n - 1) if n else V.verify_ledger(p)
        self.assertEqual(down(600)["verdict"], "PASS")    # the guard of 2026-09-13 still holds
        self.assertEqual(sys.getrecursionlimit(), self.base)

    def test_limit_restored_after_threads(self):
        p = os.path.join(self.d, "t.jsonl")
        _ledger(p, [_deep(V.MAX_JSON_DEPTH - 8) for _ in range(20)])
        out, errs = [], []

        def run():
            try:
                out.append(V.verify_ledger(p)["verdict"])
            except BaseException as e:  # noqa: BLE001
                errs.append(repr(e))
        ts = [threading.Thread(target=run) for _ in range(8)]
        for t in ts:
            t.start()
        for t in ts:
            t.join()
        self.assertEqual((errs, out), ([], ["PASS"] * 8))
        self.assertEqual(sys.getrecursionlimit(), self.base)

    def test_a_higher_limit_of_the_host_is_kept(self):
        sys.setrecursionlimit(self.base + 5000)
        self.assertEqual(V.verify_ledger(SAMPLE)["verdict"], "PASS")
        self.assertEqual(sys.getrecursionlimit(), self.base + 5000)


if __name__ == "__main__":
    unittest.main()
