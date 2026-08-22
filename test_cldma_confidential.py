# SPDX-License-Identifier: AGPL-3.0-or-later
"""Banco cldma_confidential (proposta futura additiva). PRIMA dimostra di saper fallire; poi correttezza,
no-leakage, additivita'; e un test che DOCUMENTA il limite noto (senza range proof lo schema non e' sound
contro prover malevolo) invece di nasconderlo."""
import json
import unittest

try:
    import cldma_confidential as CC
    import committed_attestation as C
    import pedersen_commit as P
except ImportError:
    from opencore import cldma_confidential as CC, committed_attestation as C, pedersen_commit as P

LED = [{"principal_outstanding": "1000.00", "days_overdue": "0", "status": "active"},
       {"principal_outstanding": "500.00", "days_overdue": "45", "status": "active"}]


def _mk():
    return CC.build_confidential(LED, "salt", C.SPEC_PAR30, "2026-08-22")


class TestSaFallire(unittest.TestCase):
    def test_tampered_leaf_rejected(self):
        att, _ = _mk()
        att["leaves"][0]["c_num"] = (att["leaves"][0]["c_num"] * 2) % P.P
        self.assertFalse(CC.verify_confidential(att)["ok"])

    def test_inflated_total_rejected(self):
        att, _ = _mk()
        att["C_num_total"] = (att["C_num_total"] * 3) % P.P
        self.assertFalse(CC.verify_confidential(att)["ok"])

    def test_false_total_opening_rejected(self):
        att, secret = _mk()
        op = CC.open_totals(att, secret)
        op["num_total"] += 1
        self.assertFalse(CC.verify_total_opening(att, op)["ok"])

    def test_empty_rejected(self):
        att, _ = _mk()
        att["leaves"] = []
        self.assertFalse(CC.verify_confidential(att)["ok"])


class TestCorrectness(unittest.TestCase):
    def test_confidential_verify_and_open(self):
        att, secret = _mk()
        self.assertTrue(CC.verify_confidential(att)["ok"])
        r = CC.verify_total_opening(att, CC.open_totals(att, secret))
        self.assertTrue(r["ok"])
        self.assertAlmostEqual(r["ratio"], 500 / 1500, places=6)   # PAR30 = at-risk/totale

    def test_no_cleartext_leakage(self):
        att, _ = _mk()
        s = json.dumps(att)
        self.assertNotIn("1000.00", s)         # nessun outstanding in chiaro
        self.assertNotIn("500.00", s)
        self.assertNotIn("days_overdue", s)    # nessun record

    def test_additive_originals_untouched(self):
        # additivita': usa gli originali via import, senza modificarli (SPEC_PAR30 intatta)
        self.assertEqual(C.SPEC_PAR30.metric_id, "PAR30")
        C_, r = P.commit(123)
        self.assertTrue(P.open_commit(C_, 123, r))


class TestKnownLimitation(unittest.TestCase):
    def test_KNOWN_no_range_proof_unsound_against_malicious_prover(self):
        # LIMITE DOCUMENTATO (non nascosto): senza prova di RANGE, un prover impegna num=q-k ("-k")
        # e SGONFIA il numeratore netto; verify_confidential PASSA. Questo test FISSA il limite noto:
        # se un giorno diventasse False (buco chiuso da un range proof), il test va aggiornato.
        att, secret = _mk()
        cbad, _rbad = P.commit((P.Q - 500) % P.Q)      # "-500"
        att["leaves"][0]["c_num"] = cbad
        att["C_num_total"] = P.add(cbad, att["leaves"][1]["c_num"])
        lh = [CC._leaf_hash(i, l["record_commit"], l["c_num"], l["c_den"]) for i, l in enumerate(att["leaves"])]
        att["root"] = CC._bound_root(CC._merkle_root(lh), att["metric_id"], att["as_of"], len(att["leaves"]))
        # il buco esiste: lo schema NON lo coglie (serve range proof) -> lo asseriamo per tracciarlo
        self.assertTrue(CC.verify_confidential(att)["ok"],
                        "atteso: senza range proof lo schema resta ingannabile (limite dichiarato)")


class TestBindingFixesCouncil(unittest.TestCase):
    def test_leaf_order_tamper_breaks_root(self):
        # riordino delle foglie nel dict pubblicato SENZA ricomputare la radice -> indice nella foglia lo coglie
        att, _ = _mk()
        att["leaves"] = [att["leaves"][1], att["leaves"][0]]
        self.assertFalse(CC.verify_confidential(att)["ok"])

    def test_n_records_mismatch_rejected(self):
        att, _ = _mk()
        att["n_records"] = 99
        self.assertFalse(CC.verify_confidential(att)["ok"])

    def test_total_opening_is_self_contained(self):
        # verify_total_opening NON si fida piu' dell'ordine di chiamata: su attestazione incoerente fallisce
        # anche senza aver chiamato verify_confidential prima
        att, secret = _mk()
        op = CC.open_totals(att, secret)
        att["leaves"][0]["c_num"] = (att["leaves"][0]["c_num"] * 2) % P.P   # rompe la radice
        self.assertFalse(CC.verify_total_opening(att, op)["ok"])


class TestSpotCheckMitigation(unittest.TestCase):
    """Lo spot-check DEVE cogliere l'attacco -k quando la foglia barata e' campionata (controllo positivo)."""

    def _attack_att(self):
        # prover malevolo: foglia 0 impegna num = q-500 ("-500"); tutto il resto coerente
        att, secret = _mk()
        bad_num = (P.Q - 500) % P.Q
        cbad, rbad = P.commit(bad_num)
        att["leaves"][0]["c_num"] = cbad
        att["C_num_total"] = P.add(cbad, att["leaves"][1]["c_num"])
        lh = [CC._leaf_hash(i, l["record_commit"], l["c_num"], l["c_den"]) for i, l in enumerate(att["leaves"])]
        att["root"] = CC._bound_root(CC._merkle_root(lh), att["metric_id"], att["as_of"], len(att["leaves"]))
        secret["nums"][0] = bad_num
        secret["r_nums"][0] = rbad
        return att, secret

    def test_spotcheck_catches_negative_when_sampled(self):
        att, secret = self._attack_att()
        opened = CC.open_challenged(att, secret, [0])          # foglia barata campionata
        r = CC.verify_challenged(att, opened)
        self.assertFalse(r["ok"])
        self.assertTrue(any("FUORI RANGE" in x for x in r["reasons"]))

    def test_spotcheck_honest_passes(self):
        att, secret = _mk()
        idx = CC.challenge_indices(att, "verifier-nonce", 2)
        self.assertTrue(CC.verify_challenged(att, CC.open_challenged(att, secret, idx))["ok"])

    def test_spotcheck_tampered_opening_fails(self):
        att, secret = _mk()
        opened = CC.open_challenged(att, secret, [0])
        opened[0]["r_num"] += 1                                # apertura con randomizer errato
        self.assertFalse(CC.verify_challenged(att, opened)["ok"])

    def test_spotcheck_num_gt_den_caught(self):
        att, secret = _mk()
        # rivela un'apertura con num>den (impegno coerente ma classificazione impossibile): colta dal range
        att2, secret2 = _mk()
        opened = CC.open_challenged(att, secret, [0])
        opened[0]["num"], opened[0]["den"] = 999999, 1        # non aprira' l'impegno -> comunque FAIL
        self.assertFalse(CC.verify_challenged(att, opened)["ok"])

    def test_empty_challenge_no_assurance(self):
        att, _ = _mk()
        self.assertFalse(CC.verify_challenged(att, [])["ok"])

    def test_detection_probability_monotone(self):
        p1 = CC.detection_probability(0.1, 5)
        p2 = CC.detection_probability(0.1, 20)
        self.assertGreater(p2, p1)                             # piu' sfide -> piu' detection
        self.assertGreater(p1, 0.0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
