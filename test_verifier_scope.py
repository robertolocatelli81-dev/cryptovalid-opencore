#!/usr/bin/env python3
"""Regressioni del red-team dell'11/09/2026 sul verifier del ledger NUDO.

Cosa aveva trovato: un ledger VUOTO verificava PASS; un ledger troncato o con suffisso riscritto e
ricatenato verificava PASS senza che il ricevuto dicesse che quelle manomissioni sono FUORI dal suo
scope; un timestamp all'indietro passava in silenzio. La catena non firmata non PUÒ vedere troncamento
e fork (è il suo limite matematico): ciò che deve fare è DIRLO nel ricevuto, e non dire PASS sul nulla.
"""
import copy
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import verifier as V  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
SAMPLE = os.path.join(HERE, "examples", "sample_ledger.jsonl")


def _rechain(entries):
    prev, out = V.GENESIS_PREV, []
    for e in entries:
        e = dict(e)
        e["prev_hash"] = prev
        e.pop("self_hash", None)
        e["self_hash"] = V.hash_with("sha256", V.canonical_payload(e))
        prev = e["self_hash"]
        out.append(e)
    return out


class TestBareLedgerScope(unittest.TestCase):
    def setUp(self):
        self.src = [json.loads(ln) for ln in open(SAMPLE) if ln.strip()]
        self.tmp = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.tmp.cleanup()

    def _verify(self, entries):
        p = os.path.join(self.tmp.name, "l.jsonl")
        with open(p, "w") as f:
            f.write("".join(json.dumps(e) + "\n" for e in entries))
        return V.verify_ledger(p)

    def test_positive_control_sample_passes(self):
        r = self._verify(self.src)
        self.assertEqual(r["verdict"], "PASS")
        self.assertIn("scope", r)
        self.assertTrue(any("truncation" in x for x in r["scope"]["does_not_prove"]))

    def test_empty_ledger_is_not_pass(self):
        r = self._verify([])
        self.assertEqual(r["verdict"], "FAIL")
        self.assertFalse(r["chain_integrity"])
        self.assertTrue(any("empty_ledger" in e["error"] for e in r["parse_errors"]))

    def test_empty_ledger_exit_code_is_nonzero(self):
        p = os.path.join(self.tmp.name, "empty.jsonl")
        open(p, "w").close()
        self.assertEqual(V.main([p, "--quiet"]), 1)

    def test_truncation_passes_but_scope_says_so(self):
        # Limite matematico, non bug: il prefisso di una catena è una catena. Il ricevuto deve dirlo.
        r = self._verify(self.src[:-1])
        self.assertEqual(r["verdict"], "PASS")
        self.assertTrue(any("truncation" in x for x in r["scope"]["does_not_prove"]))
        self.assertIn("evidence_pack.py", r["scope"]["to_cover_those"])

    def test_rechained_fork_passes_but_scope_says_so(self):
        fork = copy.deepcopy(self.src)
        fork[1]["data"]["decision"] = "REJECT"
        r = self._verify(_rechain(fork))
        self.assertEqual(r["verdict"], "PASS")
        self.assertTrue(any("re-chained" in x for x in r["scope"]["does_not_prove"]))

    def test_unrechained_tamper_fails(self):
        t = copy.deepcopy(self.src)
        t[1]["data"]["decision"] = "REJECT"
        self.assertEqual(self._verify(t)["verdict"], "FAIL")

    def test_backwards_timestamp_is_reported(self):
        b = copy.deepcopy(self.src)
        b[2]["ts"] = "2020-01-01T00:00:00Z"
        r = self._verify(_rechain(b))
        self.assertFalse(r["ts_monotonic"])
        self.assertEqual(r["ts_backwards"][0]["idx"], 2)
        self.assertTrue(r["ts_monotonic"] is False and r["verdict"] == "PASS")  # riportato, non imposto

    def test_replay_and_idx_gap_fail(self):
        rep = _rechain(self.src[:2] + self.src[1:2] + self.src[2:])
        self.assertEqual(self._verify(rep)["verdict"], "FAIL")
        gap = copy.deepcopy(self.src)
        gap[2]["idx"] = 7
        self.assertEqual(self._verify(_rechain(gap))["verdict"], "FAIL")


if __name__ == "__main__":
    unittest.main()
