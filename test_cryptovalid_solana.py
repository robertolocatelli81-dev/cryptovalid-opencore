#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Test del verificatore nativo dell'ancora Solana (cryptovalid_solana).

Il banco DEVE saper fallire (controlli negativi) prima di accettare il vero. La rete non è
richiesta: gli RPC sono iniettati come fake che restituiscono viste controllate, così i vettori
di falso-positivo nominati da Gemini (cluster falso, RPC che mente, memo forgiato) sono
esercitati in modo deterministico e offline.
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import cryptovalid_solana as CS  # noqa: E402

GEN = CS.MAINNET_GENESIS
SIG = "3nsXANdLuTaiyR7yeXdcoE55tWRUXYBuwYnwAZ3VaeCDbc41T3EVA8mkxQHwkFQLU4pdTVH6WMTmNPJgzujaKNic"
HASH = "4986246a5359e7d1cbe1af359395c73eaebde247aa3204324ba52263d7543cd2"
SIGNER = "7mFaieZm7w26rDUMKuSF4iQGjXtK5RcXfp9VWG6ofEE7"


def _tx(digest=HASH, err=None, signer=SIGNER, slot=424705132):
    return {"slot": slot, "blockTime": 1780760144,
            "meta": {"err": err, "innerInstructions": []},
            "transaction": {"message": {
                "accountKeys": [{"pubkey": signer}],
                "instructions": [{"program": "spl-memo",
                                  "programId": "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr",
                                  "parsed": f"OMEGA-LEARNPROOF|sha3:{digest}|items:3"}]}}}


def _patch(fetch_map):
    """Return a _fetch_one replacement driven by {rpc_url: dict}."""
    def _f(rpc, signature, timeout):
        return fetch_map.get(rpc, {"rpc": rpc, "reachable": False, "error": "unreachable"})
    return _f


class TestSolanaAnchor(unittest.TestCase):
    def setUp(self):
        self._orig = CS._fetch_one

    def tearDown(self):
        CS._fetch_one = self._orig

    # ── il banco sa fallire ──
    def test_hash_sbagliato_rifiutato(self):
        CS._fetch_one = _patch({"r1": {"rpc": "r1", "reachable": True, "genesis": GEN, "tx": _tx()}})
        out = CS.verify_solana_anchor(SIG, "0" * 64, rpcs=("r1",))
        self.assertFalse(out["ok"])

    def test_digest_non_64hex_rifiutato(self):
        out = CS.verify_solana_anchor(SIG, "deadbeef", rpcs=("r1",))
        self.assertFalse(out["ok"])

    def test_cluster_falso_rifiutato_da_genesis_pin(self):
        CS._fetch_one = _patch({"fake": {"rpc": "fake", "reachable": True,
                                         "genesis": "FAKECLUSTERGENESIS", "tx": _tx()}})
        out = CS.verify_solana_anchor(SIG, HASH, rpcs=("fake",))
        self.assertFalse(out["ok"])
        gen = next(c for c in out["checks"] if "genesis" in c["check"])
        self.assertFalse(gen["ok"])

    def test_tx_errata_rifiutata(self):
        CS._fetch_one = _patch({"r1": {"rpc": "r1", "reachable": True, "genesis": GEN,
                                       "tx": _tx(err={"InstructionError": [0, "Custom"]})}})
        out = CS.verify_solana_anchor(SIG, HASH, rpcs=("r1",))
        self.assertFalse(out["ok"])

    def test_rpc_che_mente_smascherato_dalla_contraddizione(self):
        # un RPC onesto (hash vero) + uno che MENTE (hash diverso) → contraddizione → reject
        CS._fetch_one = _patch({
            "honest": {"rpc": "honest", "reachable": True, "genesis": GEN, "tx": _tx(digest=HASH)},
            "liar": {"rpc": "liar", "reachable": True, "genesis": GEN, "tx": _tx(digest="a" * 64)},
        })
        out = CS.verify_solana_anchor(SIG, HASH, rpcs=("honest", "liar"))
        self.assertFalse(out["ok"])
        contra = next(c for c in out["checks"] if "contradict" in c["check"])
        self.assertFalse(contra["ok"])

    def test_signer_sbagliato_rifiutato(self):
        CS._fetch_one = _patch({"r1": {"rpc": "r1", "reachable": True, "genesis": GEN, "tx": _tx()}})
        out = CS.verify_solana_anchor(SIG, HASH, rpcs=("r1",), expected_signer="WrongSigner11111")
        self.assertFalse(out["ok"])

    def test_nessun_rpc_ha_la_tx_rifiutato(self):
        CS._fetch_one = _patch({"r1": {"rpc": "r1", "reachable": True, "genesis": GEN, "tx": None}})
        out = CS.verify_solana_anchor(SIG, HASH, rpcs=("r1",))
        self.assertFalse(out["ok"])

    # ── e accetta il vero ──
    def test_positivo_single_source_dichiarato(self):
        CS._fetch_one = _patch({"r1": {"rpc": "r1", "reachable": True, "genesis": GEN, "tx": _tx()}})
        out = CS.verify_solana_anchor(SIG, HASH, rpcs=("r1",), expected_signer=SIGNER)
        self.assertTrue(out["ok"])
        xc = next(c for c in out["checks"] if "cross-confirmed" in c["check"])
        self.assertIsNone(xc["ok"])                       # single-source dichiarato, non nascosto

    def test_positivo_cross_confirmed_due_archivi(self):
        CS._fetch_one = _patch({
            "a1": {"rpc": "a1", "reachable": True, "genesis": GEN, "tx": _tx()},
            "a2": {"rpc": "a2", "reachable": True, "genesis": GEN, "tx": _tx()},
        })
        out = CS.verify_solana_anchor(SIG, HASH, rpcs=("a1", "a2"), expected_signer=SIGNER)
        self.assertTrue(out["ok"])
        xc = next(c for c in out["checks"] if "cross-confirmed" in c["check"])
        self.assertTrue(xc["ok"])                          # due archivi concordi → cross-confirmed


if __name__ == "__main__":
    unittest.main(verbosity=2)
