#!/usr/bin/env python3
"""Hermetic tests for the pruning/evidence-decay probe (no network — RPC is mocked).

The probe MUST fail-loud on absence: a signature that no RPC returns → verdict 'decayed_or_absent'.
The verdicts must map correctly to witness counts. These mirror the live probe's positive/null control.
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import cryptovalid_pruning_probe as P  # noqa: E402


class _Fake:
    """Fake RPC: `have` = set of urls that 'have' the tx; others return result=null; `dead` raise."""
    def __init__(self, have, dead=()):
        self.have, self.dead = set(have), set(dead)

    def __call__(self, url, method, params, timeout):
        if url in self.dead:
            raise OSError("unreachable")
        return {"result": {"slot": 123} if url in self.have else None}


class TestProbe(unittest.TestCase):
    def setUp(self):
        self.rpcs = ("a", "b", "c", "d")
        self._orig = P._rpc

    def tearDown(self):
        P._rpc = self._orig

    def test_retained_when_two_or_more(self):
        P._rpc = _Fake(have={"a", "b"})
        r = P.probe_retention("sig", rpcs=self.rpcs, timeout=1)
        self.assertEqual(r["witnesses_with_tx"], 2)
        self.assertTrue(r["strict_2of_ok"])
        self.assertEqual(r["verdict"], "retained")

    def test_single_witness(self):
        P._rpc = _Fake(have={"a"})
        r = P.probe_retention("sig", rpcs=self.rpcs, timeout=1)
        self.assertEqual(r["verdict"], "single-witness")
        self.assertFalse(r["strict_2of_ok"])

    def test_null_control_absent_is_detected(self):
        # NULL CONTROL: nobody has it → the probe MUST say decayed_or_absent (it can detect absence)
        P._rpc = _Fake(have=set())
        r = P.probe_retention("does-not-exist", rpcs=self.rpcs, timeout=1)
        self.assertEqual(r["witnesses_with_tx"], 0)
        self.assertEqual(r["verdict"], "decayed_or_absent")

    def test_dead_rpc_does_not_crash_probe(self):
        P._rpc = _Fake(have={"a"}, dead={"b", "c"})
        r = P.probe_retention("sig", rpcs=self.rpcs, timeout=1)
        self.assertEqual(r["rpcs_reachable"], 2)   # a + d reachable, b/c dead
        self.assertEqual(r["witnesses_with_tx"], 1)

    def test_decay_signal_old_vs_fresh(self):
        # old anchor pruned to 1 witness, fresh held by 2 → decay is visible as fewer witnesses
        calls = {"old": _Fake(have={"a"}), "new": _Fake(have={"a", "b"})}
        P._rpc = calls["old"]
        old = P.probe_retention("old", rpcs=self.rpcs, timeout=1)
        P._rpc = calls["new"]
        new = P.probe_retention("new", rpcs=self.rpcs, timeout=1)
        self.assertLess(old["witnesses_with_tx"], new["witnesses_with_tx"])
        self.assertFalse(old["strict_2of_ok"])
        self.assertTrue(new["strict_2of_ok"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
