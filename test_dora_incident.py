#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Banco dora_incident: PRIMA dimostra di saper FALLIRE (scadenza VIOLATA rilevata;
timeline manomessa → invalid; classificazione mancante → timer non parte), poi il roundtrip.
Le scadenze DORA sono verificate contro timestamp NOTI (controllo positivo)."""
import os
import sys
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
import dora_incident as D  # noqa: E402


def _ph(phase, ts, **detail):
    return D.Phase(phase=phase, ts=ts, detail=detail)


class TestDeadlines(unittest.TestCase):
    def test_all_deadlines_met_known_times(self):
        # classificato major alle 00:00; initial +3h (≤4), intermediate +50h (≤72), final +20g (≤30)
        phases = [_ph("detected", "2026-01-01T00:00:00Z"),
                  _ph("classified_major", "2026-01-01T00:00:00Z", rationale="downtime > threshold"),
                  _ph("initial_notification", "2026-01-01T03:00:00Z"),
                  _ph("intermediate_report", "2026-01-03T02:00:00Z"),
                  _ph("final_report", "2026-01-21T00:00:00Z")]
        r = D.check_deadlines(phases)
        self.assertTrue(r["applicable"] and r["all_deadlines_met"])
        self.assertTrue(r["checks"]["initial_notification"]["met"])
        self.assertAlmostEqual(r["checks"]["initial_notification"]["elapsed_hours"], 3.0)

    def test_initial_deadline_VIOLATED_detected(self):
        # il banco DEVE fallire: initial a +6h (>4h) → non met, ma entro backstop 24h
        phases = [_ph("classified_major", "2026-01-01T00:00:00Z"),
                  _ph("initial_notification", "2026-01-01T06:00:00Z")]
        r = D.check_deadlines(phases)
        ini = r["checks"]["initial_notification"]
        self.assertFalse(ini["met"])                      # 6h > 4h → VIOLATA
        self.assertTrue(ini["within_backstop_24h"])       # ma dentro le 24h
        self.assertFalse(r["all_deadlines_met"])

    def test_no_major_classification_timer_not_started(self):
        phases = [_ph("detected", "2026-01-01T00:00:00Z"),
                  _ph("initial_notification", "2026-01-01T01:00:00Z")]
        r = D.check_deadlines(phases)
        self.assertFalse(r["applicable"])                 # nessun major → timer non parte


class TestAttestation(unittest.TestCase):
    def setUp(self):
        self.phases = [_ph("detected", "2026-01-01T00:00:00Z"),
                       _ph("classified_major", "2026-01-01T00:30:00Z", rationale="data breach"),
                       _ph("initial_notification", "2026-01-01T03:00:00Z"),
                       _ph("intermediate_report", "2026-01-03T00:00:00Z"),
                       _ph("final_report", "2026-01-20T00:00:00Z")]

    def test_attest_verify_roundtrip(self):
        att = D.attest(self.phases, incident_id="INC-1", as_of="2026-02-01")
        v = D.verify_attestation(att, self.phases)
        self.assertTrue(v["valid"], v)

    def test_chain_tamper_evident(self):
        chain = D.build_chain(self.phases)
        self.assertTrue(D.verify_chain(chain))
        chain[2]["canonical"]["ts"] = "2026-01-01T99:00:00Z"     # retrodata una fase
        self.assertFalse(D.verify_chain(chain))

    def test_tampered_phases_break_attestation(self):
        att = D.attest(self.phases, incident_id="INC-1")
        # sposta l'initial oltre la scadenza dopo aver attestato → digest non combacia
        self.phases[2] = _ph("initial_notification", "2026-01-05T00:00:00Z")
        v = D.verify_attestation(att, self.phases)
        self.assertFalse(v["valid"])

    def test_honest_scope_disclaims_compliance(self):
        att = D.attest(self.phases)
        self.assertIn("NOT proof of DORA compliance", att["honest_scope"])
        self.assertIn("classification is correct", att["honest_scope"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
