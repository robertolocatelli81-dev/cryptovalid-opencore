#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""OMEGA-FUNDCERT canonicalizzazione — banco che SA FALLIRE, su un fixture di dati SPY REALI.

Il fixture sono posizioni reali di SPDR S&P 500 (SPY) as-of 2026-08-18 (holdings pubblici SSGA), scelte per
includere il caso OSTILE che ha rotto la prima versione: interi in NOTAZIONE SCIENTIFICA ('1.275099E7').
Esperimento killer: (1) DETERMINISMO — riordino + riformatto la notazione → STESSO digest; (2) NULL —
cambio una quantità → digest diverso (il differ dice cosa). Regressione esplicita sul bug della notazione.
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fundcert_canonical as F  # noqa: E402

# posizioni REALI di SPY (CUSIP, shares come pubblicate da SSGA, incl. notazione scientifica)
_SPY_REAL = [
    ("67066G104", "2.99181969E8"),   # NVIDIA — scientifica
    ("037833100", "1.81423328E8"),   # APPLE
    ("594918104", "9.1757978E7"),    # MICROSOFT
    ("040413205", "1.275099E7"),     # il CASO che ruppe: intero in notazione scientifica
    ("532457108", "9770360.0"),      # ELI LILLY — decimale .0 su intero
    ("110122108", "2.519937E7"),
]


def _holdings(rows, source="ssga"):
    return F.Holdings(fund_id="SPY", as_of="18-Aug-2026", source=source,
                      positions=[F.Position(identifier=i, id_scheme="CUSIP", quantity=q) for i, q in rows])


class TestFundcert(unittest.TestCase):
    def test_determinismo_riordino_e_notazione(self):
        h = _holdings(_SPY_REAL)
        d0 = F.digest(h)
        # riordino (l'ordine di pubblicazione non conta) + riformatto la notazione (stesso valore, forma diversa)
        import copy
        from decimal import Decimal
        h2 = copy.deepcopy(h)
        h2.positions = list(reversed(h2.positions))
        for p in h2.positions:
            p.quantity = format(Decimal(p.quantity), "f")     # '2.99181969E8' → '299181969'
        self.assertEqual(d0, F.digest(h2))                    # STESSO portafoglio → STESSO digest

    def test_regressione_notazione_scientifica_intera(self):
        # il bug: '1.275099E7' (intero) deve canonicalizzare come '12750990', identico alla forma piena
        a = _holdings([("040413205", "1.275099E7")])
        b = _holdings([("040413205", "12750990")])
        self.assertEqual(F.digest(a), F.digest(b))
        self.assertEqual(F.canonical_form(a)["positions"][0]["qty"], "12750990")

    def test_null_control_cambio_quantita(self):
        h = _holdings(_SPY_REAL)
        import copy
        h2 = copy.deepcopy(h)
        h2.positions[0].quantity = "299181970"                # +1 share su NVDA
        self.assertNotEqual(F.digest(h), F.digest(h2))        # il banco SA fallire
        d = F.diff(h, h2)
        self.assertFalse(d["same_digest"])
        self.assertEqual(d["changed_quantity"][0]["id"], "67066G104")
        # a/b sono multiset [(qty,cash)] per gestire id duplicati/placeholder (id unico → lista di 1)
        self.assertEqual((d["changed_quantity"][0]["a"], d["changed_quantity"][0]["b"]),
                         ([("299181969", "")], [("299181970", "")]))

    def test_quantita_non_numerica_rifiutata(self):
        with self.assertRaises(ValueError):
            F._canon_quantity("N/A")

    def test_audit_skips_footer_vs_materiale(self):
        # trovato dal killer-experiment su dati reali: un cert tool NON deve droppare in silenzio.
        h = F.Holdings("SPY", "d", "ssga", positions=[F.Position("037833100", "CUSIP", "1000")],
                       skipped=[{"name": "Distributor disclaimer", "identifier": "", "has_quantity": False}])
        a = F.audit_skips(h)
        self.assertFalse(a["alert"])                      # solo footer → nessun allarme
        self.assertEqual(a["material_dropped"], 0)
        # una riga con QUANTITA' ma senza id (cash/future droppato) → ALERT: basket incompleto
        h.skipped.append({"name": "CASH", "identifier": "", "has_quantity": True})
        a2 = F.audit_skips(h)
        self.assertTrue(a2["alert"])
        self.assertEqual(a2["material_dropped"], 1)

    def test_determinismo_id_placeholder_duplicati(self):
        # REGRESSIONE dal killer-experiment su N-PORT SPY reale: i fondi riportano N righe con id placeholder
        # '000000000' (futures/cash senza CUSIP). Ordinare solo per (scheme,id) NON era deterministico su quei
        # duplicati → l'ordine d'input filtrava nel digest. La chiave deve includere qty.
        rows = [("000000000", "100"), ("000000000", "300"), ("000000000", "200"), ("037833100", "1000")]
        h = F.Holdings("F", "d", "nport",
                       [F.Position(i, "CUSIP", q) for i, q in rows])
        h2 = F.Holdings("F", "d", "nport",
                        [F.Position(i, "CUSIP", q) for i, q in reversed(rows)])   # ordine opposto
        self.assertEqual(F.digest(h), F.digest(h2))                # STESSO basket → STESSO digest
        # e il diff NON collassa i 3 placeholder in 1: li dichiara come multiset
        d = F.diff(h, h2)
        self.assertTrue(d["same_digest"])
        self.assertIn("CUSIP:000000000(a=3,b=3)", d["duplicate_ids"])
        # cambiare UNA riga placeholder deve essere rilevato (prima veniva perso dal dict)
        h3 = F.Holdings("F", "d", "nport",
                        [F.Position(i, "CUSIP", ("999" if (i, q) == ("000000000", "200") else q)) for i, q in rows])
        self.assertNotEqual(F.digest(h), F.digest(h3))
        self.assertTrue(any(c["id"] == "000000000" for c in F.diff(h, h3)["changed_quantity"]))

    def test_differ_added_removed(self):
        a = _holdings(_SPY_REAL)
        b = _holdings(_SPY_REAL[:-1] + [("11135F101", "58481769")])   # tolgo l'ultima, ne aggiungo una
        d = F.diff(a, b)
        self.assertIn("CUSIP:110122108", d["only_in_a"])
        self.assertIn("CUSIP:11135F101", d["only_in_b"])

    def test_parse_csv_generico(self):
        csv = "ISIN,Name,Shares\nUS0378331005,APPLE,1.81E8\nIE00B,CASH,-\n"
        h = F.parse_holdings_csv(csv, id_col="ISIN", qty_col="Shares", id_scheme="ISIN")
        self.assertEqual(len(h.positions), 1)                 # la riga CASH con '-' è scartata
        self.assertEqual(h.positions[0].identifier, "US0378331005")

    def test_parse_nport_xml_struttura(self):
        xml = ('<edgarSubmission><formData><genInfo><seriesId>S123</seriesId>'
               '<repPdDate>2026-06-30</repPdDate></genInfo>'
               '<invstOrSecs><invstOrSec><name>APPLE INC</name><cusip>037833100</cusip>'
               '<balance>1000000</balance></invstOrSec></invstOrSecs></formData></edgarSubmission>')
        h = F.parse_nport_xml(xml)
        self.assertEqual(h.fund_id, "S123")
        self.assertEqual(len(h.positions), 1)
        self.assertEqual(h.positions[0].identifier, "037833100")
        self.assertEqual(F.canonical_form(h)["positions"][0]["qty"], "1000000")

    def test_cusip_to_isin_check_digit(self):
        # check-digit ISIN verificato su ISIN reali noti
        self.assertEqual(F.cusip_to_isin("037833100"), "US0378331005")   # Apple
        self.assertEqual(F.cusip_to_isin("594918104"), "US5949181045")   # Microsoft
        self.assertIsNone(F.cusip_to_isin("SHORT"))                      # len != 9 → None
        self.assertIsNone(F.cusip_to_isin("0378331!0"))                  # non alfanumerico → None (valida il FORMATO)
        # REGRESSIONE (cross-source SPY/VOO reale): il placeholder '000000000' passa il FORMATO ma NON è un
        # id → NON deve fabbricare un ISIN finto; idem i sentinelli N/A. Un id inventato è peggio di nessun id.
        self.assertIsNone(F.cusip_to_isin("000000000"))
        self.assertIsNone(F.cusip_to_isin("N/A"))
        # e in un basket il placeholder resta CUSIP:000000000 (non normalizzato), col conteggio se ripetuto
        h = F.Holdings("F", "d", "nport",
                       [F.Position("000000000", "CUSIP", "10"), F.Position("000000000", "CUSIP", "20"),
                        F.Position("037833100", "CUSIP", "30")])
        empty = F.Holdings("F", "d", "nport", [F.Position("037833100", "CUSIP", "30")])
        d = F.diff(h, empty, "ISIN")
        self.assertIn("CUSIP:000000000(×2)", d["only_in_a"])              # conteggio esplicito: nulla collassa

    def test_cross_source_CUSIP_vs_ISIN_allineati(self):
        # FIX #4 (supreme-ai): fonte in CUSIP e fonte in ISIN dello STESSO titolo → stesso digest con id_target
        a = F.Holdings("SPY", "d", "ssga", [F.Position("037833100", "CUSIP", "1000000")])
        b = F.Holdings("SPY", "d", "nport", [F.Position("US0378331005", "ISIN", "1000000")])
        self.assertNotEqual(F.digest(a), F.digest(b))            # scheme diversi → digest diversi
        self.assertEqual(F.digest(a, "ISIN"), F.digest(b, "ISIN"))   # allineati su ISIN → stesso digest

    def test_cash_component_entra_nel_digest(self):
        # FIX #3: la componente cash del PCF conta (AP la contestano) → cambiarla cambia il digest
        base = _holdings([("037833100", "1000000")])
        withcash = F.Holdings("SPY", "d", "pcf",
                              [F.Position("037833100", "CUSIP", "1000000", cash_component="12345.67")])
        withcash2 = F.Holdings("SPY", "d", "pcf",
                               [F.Position("037833100", "CUSIP", "1000000", cash_component="99999.99")])
        self.assertNotEqual(F.digest(base), F.digest(withcash))     # aggiungere il cash cambia il digest
        self.assertNotEqual(F.digest(withcash), F.digest(withcash2))  # cambiare il cash cambia il digest

    def test_reconcile_fattore_di_scala(self):
        # DAL KILLER-EXPERIMENT REALE (N-PORT vs N-CSR, Vanguard 500 Index 31/12/2025): due filing autorevoli
        # dello stesso fondo/data differiscono per un FATTORE DI SCALA globale (+0.397%) a composizione identica.
        # reconcile() lo MISURA e separa la scala dalle differenze reali per-titolo.
        import copy
        h = _holdings(_SPY_REAL)
        # fonte B = stessa composizione scalata di +0.397% (come N-CSR vs N-PORT), + UNA differenza reale
        b = copy.deepcopy(h)
        for p in b.positions:
            p.quantity = str(int(round(float(F._canon_quantity(p.quantity)) * 1.00397)))
        b.positions[0].quantity = "999999999"                       # un residuo REALE oltre la scala
        r = F.reconcile(h, b, by="id")
        self.assertAlmostEqual(r["scale_pct"], 0.397, delta=0.02)   # la scala è misurata
        self.assertEqual(r["residual_count"], 1)                    # solo la differenza vera sopravvive alla scala
        self.assertEqual(r["residual_after_scale"][0]["b"], "999999999")
        # NULL control: nomi/id permutati con la stessa scala → i residui esplodono (non è più la stessa composizione)
        perm = copy.deepcopy(b)
        qs = [p.quantity for p in perm.positions]
        for i, p in enumerate(perm.positions):
            p.quantity = qs[(i + 1) % len(qs)]
        self.assertGreater(F.reconcile(h, perm, by="id")["residual_count"], 1)

    def test_norm_name_cross_source_senza_id(self):
        # l'N-CSR non ha CUSIP → match per nome normalizzato
        self.assertEqual(F.norm_name("Alphabet Inc. Class A"), F.norm_name("ALPHABET  CLASS A"))
        self.assertEqual(F.norm_name("Microsoft Corporation"), "MICROSOFT")

    def test_cross_source_stesso_basket_stesso_digest(self):
        # IL TEST CHE VALE: stessa composizione da DUE fonti (ordine/notazione diversi) → STESSO digest
        ssga = _holdings(_SPY_REAL, source="ssga")
        # "N-PORT" della stessa composizione: ordine diverso, notazione piena
        from decimal import Decimal
        nport = F.Holdings(fund_id="SPY", as_of="2026-08-18", source="nport",
                           positions=[F.Position(i, "CUSIP", format(Decimal(q), "f"))
                                      for i, q in reversed(_SPY_REAL)])
        self.assertEqual(F.digest(ssga), F.digest(nport))     # fonti diverse, stesso basket → stesso digest


if __name__ == "__main__":
    unittest.main(verbosity=2)
