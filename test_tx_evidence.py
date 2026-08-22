#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Banco tx_evidence: PRIMA dimostra di saper FALLIRE (tx manomessa → digest cambia;
FIFO deve dare numeri NOTI; lotti insufficienti dichiarati), poi il roundtrip.
Il cost basis FIFO è verificato contro valori calcolati A MANO (controllo positivo)."""
import os
import sys
import unittest
from decimal import Decimal

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
import tx_evidence as T  # noqa: E402


def _tx(txid, kind, asset, qty, price, ts):
    return T.Tx(txid=txid, kind=kind, asset=asset, qty=qty, unit_price=price,
                currency="USD", ts=ts)


class TestCanonicalAndChain(unittest.TestCase):
    def test_determinism_same_tx_same_digest(self):
        a = _tx("1", "buy", "btc", "0.50", "60000.00", "2026-01-01T00:00:00Z")
        b = _tx("1", "BUY", " btc ", "0.5", "6.0E4", "2026-01-01T00:00:00Z")  # forme diverse, stesso contenuto
        self.assertEqual(T.tx_digest(a), T.tx_digest(b))

    def test_chain_tamper_evident(self):
        txs = [_tx("1", "buy", "BTC", "1", "50000", "2026-01-01T00:00:00Z"),
               _tx("2", "sell", "BTC", "1", "70000", "2026-06-01T00:00:00Z")]
        chain = T.build_chain(txs)
        self.assertTrue(T.verify_chain(chain))
        chain[0]["canonical"]["qty"] = "999"          # manomissione
        self.assertFalse(T.verify_chain(chain))


class TestCostBasisFifoKnownValues(unittest.TestCase):
    """Controllo POSITIVO: FIFO deve dare numeri calcolati a mano."""

    def test_fifo_matches_hand_computation(self):
        # compra 1 BTC @50k, 1 BTC @60k, poi vende 1.5 BTC @80k
        # FIFO: consuma 1@50k + 0.5@60k = basis 80k; proceeds 1.5*80k=120k; gain 40k
        txs = [_tx("1", "buy", "BTC", "1", "50000", "2026-01-01T00:00:00Z"),
               _tx("2", "buy", "BTC", "1", "60000", "2026-02-01T00:00:00Z"),
               _tx("3", "sell", "BTC", "1.5", "80000", "2026-06-01T00:00:00Z")]
        r = T.cost_basis_fifo(txs)
        d = r["by_asset"]["BTC"][0]
        self.assertEqual(Decimal(d["basis"]), Decimal("80000"))
        self.assertEqual(Decimal(d["proceeds"]), Decimal("120000"))
        self.assertEqual(Decimal(d["gain"]), Decimal("40000"))
        self.assertFalse(d["insufficient_lots"])

    def test_insufficient_lots_flagged_not_silenced(self):
        # vendo 2 BTC ma ne ho comprato solo 1 → buco nei dati, DICHIARATO
        txs = [_tx("1", "buy", "BTC", "1", "50000", "2026-01-01T00:00:00Z"),
               _tx("2", "sell", "BTC", "2", "80000", "2026-06-01T00:00:00Z")]
        d = T.cost_basis_fifo(txs)["by_asset"]["BTC"][0]
        self.assertTrue(d["insufficient_lots"])
        self.assertEqual(Decimal(d["unmatched_qty"]), Decimal("1"))


class TestAttestation(unittest.TestCase):
    def setUp(self):
        self.txs = [_tx("1", "buy", "BTC", "1", "50000", "2026-01-01T00:00:00Z"),
                    _tx("2", "sell", "BTC", "1", "70000", "2026-06-01T00:00:00Z")]

    def test_attest_verify_roundtrip(self):
        att = T.attest(self.txs, as_of="2026-12-31")
        v = T.verify_attestation(att, self.txs)
        self.assertTrue(v["valid"], v)

    def test_tampered_records_break_verification(self):
        att = T.attest(self.txs, as_of="2026-12-31")
        self.txs[1] = _tx("2", "sell", "BTC", "1", "1.00", "2026-06-01T00:00:00Z")  # cambia il prezzo
        v = T.verify_attestation(att, self.txs)
        self.assertFalse(v["valid"])

    def test_honest_scope_disclaims_tax_advice(self):
        att = T.attest(self.txs)
        self.assertIn("NOT tax advice", att["honest_scope"])
        self.assertIn("NOT proof of tax-correctness", att["honest_scope"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
