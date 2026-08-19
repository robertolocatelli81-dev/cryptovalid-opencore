#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Il mutation runner deve essere ONESTO: uccide i mutanti coperti dai test E dichiara i sopravvissuti
(non è truccato a 'tutti uccisi'). Controllo su un TOY module+test in tempdir (ermetico, niente produzione).
"""
import os
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from mutation_runner import run_mutation, generate_mutants  # noqa: E402

_TOY = "def is_positive(x):\n    return x > 0\n\n\ndef flag():\n    return True\n"
# il test copre is_positive ma NON flag → la mutazione True→False in flag DEVE sopravvivere
_TOY_TEST = (
    "import os, sys\n"
    "sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))\n"
    "from toy import is_positive\n"
    "assert is_positive(5) is True\n"
    "assert is_positive(-5) is False\n"
)


class TestMutationRunner(unittest.TestCase):
    def test_genera_mutanti_sistematici(self):
        muts = list(generate_mutants(_TOY))
        descs = " ".join(d for d, _ in muts)
        self.assertIn(">", descs)                       # muta l'operatore di confronto
        self.assertIn("True", descs)                    # muta il letterale booleano

    def test_uccide_e_dichiara_i_sopravvissuti(self):
        d = tempfile.mkdtemp()
        toy = os.path.join(d, "toy.py")
        toytest = os.path.join(d, "test_toy.py")
        open(toy, "w").write(_TOY)
        open(toytest, "w").write(_TOY_TEST)
        r = run_mutation(toy, [sys.executable, toytest])
        # NULL CONTROL: la suite passa sul codice non mutato
        self.assertTrue(r["baseline_green"])
        # il runner UCCIDE almeno un mutante (quello coperto: x>0)
        self.assertGreaterEqual(r["killed"], 1)
        # ...e NON è truccato: dichiara almeno un SOPRAVVISSUTO (flag True→False non è testato)
        self.assertTrue(r["survived"])
        self.assertLess(r["score"], 1.0)
        self.assertTrue(any("True" in s for s in r["survived"]))
        # il file toy è stato RIPRISTINATO (restore garantito)
        self.assertEqual(open(toy).read(), _TOY)

    def test_baseline_rossa_blocca_la_misura(self):
        # se la suite è già rossa senza mutazioni, il runner NON misura (non inventa un punteggio)
        d = tempfile.mkdtemp()
        toy = os.path.join(d, "toy.py")
        bad = os.path.join(d, "test_bad.py")
        open(toy, "w").write(_TOY)
        open(bad, "w").write("assert False\n")
        r = run_mutation(toy, [sys.executable, bad])
        self.assertFalse(r["baseline_green"])
        self.assertEqual(r["total"], 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
