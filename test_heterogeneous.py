#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Ancoraggio eterogeneo (fault-independence vera) — banco ermetico che SA FALLIRE.

Il caso decisivo: due attestazioni dello STESSO dominio contano UNA (repliche, non testimoni) → annichila
W3 ("rischio se i nodi sono replicati"). Verificatori di dominio INIETTATI (nessuna rete).
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from cryptovalid_heterogeneous import verify_heterogeneous_anchor as V  # noqa: E402

DIG = "ab" * 32
# verificatori finti: la validità di ogni attestazione la decide il campo att['valid']
_FAKE = {"solana": lambda att, d: bool(att.get("valid")),
         "rfc3161": lambda att, d: bool(att.get("valid"))}


def _raise(att, d):
    raise RuntimeError("dominio in errore")


class TestHeterogeneous(unittest.TestCase):
    def test_due_domini_distinti_validi_OK(self):
        r = V(DIG, [{"domain": "solana", "valid": True}, {"domain": "rfc3161", "valid": True}],
              min_domains=2, verifiers=_FAKE)
        self.assertTrue(r["ok"])
        self.assertEqual(r["domains_verified"], 2)
        self.assertEqual(r["verified_domains"], ["rfc3161", "solana"])

    def test_un_solo_dominio_valido_RIFIUTATO(self):
        r = V(DIG, [{"domain": "solana", "valid": True}, {"domain": "rfc3161", "valid": False}],
              min_domains=2, verifiers=_FAKE)
        self.assertFalse(r["ok"])                       # 1 dominio < 2 richiesti
        self.assertEqual(r["domains_verified"], 1)

    def test_repliche_STESSO_dominio_contano_UNA(self):
        # IL CASO CHE ANNICHILA W3: due 'solana' validi NON fanno 2 testimoni indipendenti → resta 1
        r = V(DIG, [{"domain": "solana", "valid": True}, {"domain": "solana", "valid": True}],
              min_domains=2, verifiers=_FAKE)
        self.assertFalse(r["ok"])
        self.assertEqual(r["domains_verified"], 1)      # repliche same-domain = 1
        self.assertEqual(r["distinct_domains_attempted"], 1)

    def test_digest_sbagliato_tutti_falliscono(self):
        r = V(DIG, [{"domain": "solana", "valid": False}, {"domain": "rfc3161", "valid": False}],
              min_domains=2, verifiers=_FAKE)
        self.assertFalse(r["ok"])
        self.assertEqual(r["domains_verified"], 0)

    def test_dominio_sconosciuto_non_conta(self):
        r = V(DIG, [{"domain": "foobar", "valid": True}, {"domain": "rfc3161", "valid": True}],
              min_domains=2, verifiers=_FAKE)
        self.assertFalse(r["ok"])                       # foobar sconosciuto → solo 1 dominio reale
        self.assertEqual(r["domains_verified"], 1)

    def test_soglia_1_positivo_controllo(self):
        # controllo positivo alla soglia minima: 1 dominio valido, min=1 → OK
        r = V(DIG, [{"domain": "solana", "valid": True}], min_domains=1, verifiers=_FAKE)
        self.assertTrue(r["ok"])

    def test_dominio_che_solleva_non_rompe_gli_altri(self):
        r = V(DIG, [{"domain": "solana", "valid": True}, {"domain": "rfc3161", "valid": True}],
              min_domains=2, verifiers={"solana": _raise, "rfc3161": _FAKE["rfc3161"]})
        self.assertFalse(r["ok"])                       # solana erra → 1 dominio buono, < 2
        self.assertEqual(r["domains_verified"], 1)
        self.assertTrue(any(d["domain"] == "solana" and not d["ok"] for d in r["per_domain"]))


if __name__ == "__main__":
    unittest.main(verbosity=2)
