# SPDX-License-Identifier: AGPL-3.0-or-later
"""Banco Pedersen: PRIMA dimostra di saper FALLIRE (binding, apertura/somma errate), poi correttezza,
hiding, omomorfismo, e la SANITY dei parametri di gruppo (g,h nel sottogruppo di ordine primo q)."""
import unittest

try:
    import pedersen_commit as PC
except ImportError:
    from opencore import pedersen_commit as PC


class TestSaFallire(unittest.TestCase):
    def test_open_wrong_value_fails(self):
        C, r = PC.commit(1500)
        self.assertFalse(PC.open_commit(C, 1501, r))
        self.assertFalse(PC.open_commit(C, 1500, r + 1))

    def test_inflated_total_fails(self):
        vs = [100, 250, 175]
        Cs, rs = PC.commit_contributions(vs)
        tv, tr = PC.sum_opening(vs, rs)
        self.assertFalse(PC.verify_confidential_sum(Cs, tv + 1, tr))     # totale gonfiato
        self.assertFalse(PC.verify_confidential_sum(Cs, tv, tr + 1))     # randomizer errato

    def test_tampered_commitment_fails(self):
        vs = [100, 250, 175]
        Cs, rs = PC.commit_contributions(vs)
        tv, tr = PC.sum_opening(vs, rs)
        bad = [(Cs[0] * 2) % PC.P] + Cs[1:]
        self.assertFalse(PC.verify_confidential_sum(bad, tv, tr))

    def test_value_out_of_range_rejected(self):
        with self.assertRaises(ValueError):
            PC.commit(PC.Q)                                             # value deve stare in [0,q)


class TestCorrectness(unittest.TestCase):
    def test_open_roundtrip(self):
        C, r = PC.commit(1500)
        self.assertTrue(PC.open_commit(C, 1500, r))

    def test_confidential_sum_roundtrip(self):
        vs = [10, 20, 30, 40]
        Cs, rs = PC.commit_contributions(vs)
        tv, tr = PC.sum_opening(vs, rs)
        self.assertTrue(PC.verify_confidential_sum(Cs, tv, tr))
        self.assertEqual(tv, 100)                                       # totale reale nascosto ma verificabile

    def test_homomorphic_add(self):
        a, ra = PC.commit(300, r=7)
        b, rb = PC.commit(200, r=9)
        self.assertTrue(PC.open_commit(PC.add(a, b), 500, 16))

    def test_hiding_same_value_different_commitment(self):
        c1, _ = PC.commit(42, r=11111)
        c2, _ = PC.commit(42, r=22222)
        self.assertNotEqual(c1, c2)                                     # nessuna info sul valore

    def test_ratio_relation_confidential(self):
        # PAR30-style: num=at-risk, den=totale. Si prova che il TOTALE num e den impegnati aprono ai
        # valori dichiarati, senza rivelare i singoli prestiti. (Il range num<=den in ZK NON e' qui.)
        num_i = [0, 500, 0]        # solo il 2o prestito e' a rischio
        den_i = [1000, 500, 800]
        Cn, rn = PC.commit_contributions(num_i)
        Cd, rd = PC.commit_contributions(den_i)
        self.assertTrue(PC.verify_confidential_sum(Cn, *PC.sum_opening(num_i, rn)))
        self.assertTrue(PC.verify_confidential_sum(Cd, *PC.sum_opening(den_i, rd)))


class TestGroupParams(unittest.TestCase):
    def test_generators_in_prime_order_subgroup(self):
        # g e h DEVONO stare nel sottogruppo di ordine q (altrimenti hiding/binding sono compromessi)
        self.assertEqual(pow(PC.G, PC.Q, PC.P), 1)
        self.assertEqual(pow(PC.H, PC.Q, PC.P), 1)
        self.assertNotIn(PC.G, (0, 1))
        self.assertNotIn(PC.H, (0, 1))

    def test_q_is_half_p_minus_1(self):
        self.assertEqual(PC.Q * 2 + 1, PC.P)                            # p = 2q+1 (safe prime)

    def test_h_provenance_transparent(self):
        prov = PC.h_provenance()
        self.assertIn("NUMS", prov["note"])                            # nothing-up-my-sleeve dichiarato


if __name__ == "__main__":
    unittest.main(verbosity=2)
