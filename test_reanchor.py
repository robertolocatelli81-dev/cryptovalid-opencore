#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Re-ancoraggio schedulato + alert decadimento (W4) — banco ermetico che SA FALLIRE.

Sonda INIETTATA (nessuna rete). Controllo positivo/null: un anchor sano NON va ri-ancorato; uno sotto
soglia SÌ, con alert. now_ts passato da fuori (niente clock → deterministico).
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from cryptovalid_reanchor import assess, plan  # noqa: E402

DAY = 86400.0
NOW = 1_800_000_000.0  # epoch fisso (determinismo)


def _ret(w):
    return {"witnesses_with_tx": w}


class TestReanchor(unittest.TestCase):
    def test_sano_non_va_riancorato(self):
        v = assess(_ret(2), age_days=5, min_witnesses=2)
        self.assertEqual(v["status"], "healthy")
        self.assertFalse(v["needs_reanchor"])

    def test_sotto_soglia_ALERT(self):
        # 1 testimone < 2 richiesti → decayed, needs_reanchor, alert
        v = assess(_ret(1), age_days=80, min_witnesses=2)
        self.assertEqual(v["status"], "decayed")
        self.assertTrue(v["needs_reanchor"])

    def test_decaying_proattivo_vicino_alla_finestra(self):
        # abbastanza testimoni ma età entro il margine di warning (75-15=60) → ri-ancorare proattivo
        v = assess(_ret(3), age_days=62, min_witnesses=2)
        self.assertEqual(v["status"], "decaying")
        self.assertTrue(v["needs_reanchor"])

    def test_giovane_con_testimoni_healthy(self):
        v = assess(_ret(3), age_days=40, min_witnesses=2)
        self.assertEqual(v["status"], "healthy")
        self.assertFalse(v["needs_reanchor"])

    def test_plan_conta_stati_e_alza_alert(self):
        anchors = [
            {"signature": "fresh", "anchored_ts": NOW - 5 * DAY},   # healthy
            {"signature": "old", "anchored_ts": NOW - 65 * DAY},    # decaying (età 65 >= 60)
            {"signature": "gone", "anchored_ts": NOW - 90 * DAY},   # decayed (sotto soglia)
        ]
        witness_by_sig = {"fresh": 3, "old": 3, "gone": 1}
        p = plan(anchors, probe_fn=lambda s: _ret(witness_by_sig[s]), now_ts=NOW, min_witnesses=2)
        self.assertEqual(p["summary"], {"decayed": 1, "decaying": 1, "healthy": 1})
        self.assertTrue(p["alert"])                                 # 'gone' è sotto soglia
        self.assertIn("old", p["to_reanchor"])
        self.assertIn("gone", p["to_reanchor"])
        self.assertNotIn("fresh", p["to_reanchor"])

    def test_null_control_tutti_sani_niente_alert(self):
        anchors = [{"signature": "a", "anchored_ts": NOW - 3 * DAY},
                   {"signature": "b", "anchored_ts": NOW - 10 * DAY}]
        p = plan(anchors, probe_fn=lambda s: _ret(4), now_ts=NOW, min_witnesses=2)
        self.assertFalse(p["alert"])
        self.assertEqual(p["to_reanchor"], [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
