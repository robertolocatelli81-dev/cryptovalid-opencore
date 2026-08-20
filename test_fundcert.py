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

    def test_gap_D2_evidence_record_provenienza(self):
        # DEFICIENZA Gemini: un digest è inutile se non è legato all'INPUT + al METODO. evidence_record lega
        # provenienza (sha256 byte grezzi + fonte + quando) → metodo (fingerprint) → risultato (digest).
        raw = b'{"holdings": "raw source bytes"}'
        r = F.evidence_record(raw, source="SEC EDGAR", fetched_at="2026-08-20T11:00:00Z",
                              holdings_digest="deadbeef", fund_id="F", as_of="d")
        self.assertEqual(r["input_sha256"], __import__("hashlib").sha256(raw).hexdigest())
        self.assertEqual(r["canonicalizer_fp"], F.canonicalizer_fingerprint())
        # input alterato → provenienza diversa (rileva input diverso PRIMA del digest)
        r2 = F.evidence_record(raw + b" ", "SEC EDGAR", "2026-08-20T11:00:00Z", "deadbeef")
        self.assertNotEqual(r2["input_sha256"], r["input_sha256"])
        self.assertNotEqual(r2["record_digest"], r["record_digest"])
        # il fingerprint del metodo è stabile per una data versione
        self.assertEqual(F.canonicalizer_fingerprint(), F.canonicalizer_fingerprint())

    def test_gap_D2_resolve_exception_chi_perche(self):
        # DEFICIENZA Gemini: 'un digest non dice CHI ha autorizzato né PERCHÉ'. resolve_exception registra il
        # contesto operativo (chi/perché/decisione/quando) su una voce di triage, con digest per la forensics.
        item = {"key": "TICKER:WOLF", "rel_pct": 2907.0, "severity": "high",
                "action": "confirm_corporate_action", "flag": {"kind": "split_candidate"}, "status": "open"}
        res = F.resolve_exception(item, resolver="R.L.", reason="reverse split 1:30",
                                  decision="accept_corporate_action", at="2026-08-20T11:05:00Z")
        self.assertEqual(res["status"], "resolved")
        self.assertEqual(res["resolution"]["resolver"], "R.L.")
        self.assertEqual(res["resolution"]["decision"], "accept_corporate_action")
        self.assertTrue(res["resolution_digest"])                       # ancorabile per il tamper-evidence
        self.assertEqual(item["status"], "open")                        # non muta l'originale

    def test_conformance_vectors_pinned(self):
        # RIPRODUCIBILITÀ ESTERNA (critica Gemini sopravvissuta): i digest sono PINNATI in vettori versionati.
        # Un terzo ricomputa e ottiene lo STESSO digest; se le regole di canonicalizzazione cambiano, i digest
        # cambiano e questo test FALLISCE → obbliga a un bump esplicito di CANON_VERSION (metodo stabile, non "il codice").
        import json
        path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "spec", "vectors", "fundcert_conformance.json")
        vec = json.load(open(path))
        self.assertEqual(vec["canon_version"], F.CANON_VERSION)      # i vettori valgono per QUESTA versione
        for c in vec["cases"]:
            pos = [F.Position(p[0], p[1], p[2], cash_component=(p[3] if len(p) > 3 else "")) for p in c["positions"]]
            h = F.Holdings("FUND", "2025-12-31", "test", pos)
            self.assertEqual(F.digest(h, c["id_target"]), c["expected_digest"],
                             f"digest cambiato per '{c['name']}' senza bump di CANON_VERSION")

    def test_reconcile_materiale_vs_minore(self):
        # DAL killer-experiment 12-fondi: il rumore di quantizzazione (~costante in assoluto) appare grande in %
        # sulle posizioni PICCOLE. Una soglia relativa cieca fabbricava false anomalie sugli small-cap.
        # material_tol separa la differenza MATERIALE (grande in %) dal residuo MINORE (piccolo in %).
        a = F.Holdings("F", "d", "nport", [
            F.Position("A", "CUSIP", "1000000"),      # posizione grande
            F.Position("B", "CUSIP", "50000"),        # posizione piccola
            F.Position("C", "CUSIP", "2000")])        # posizione minuscola
        b = F.Holdings("F", "d", "ncsr", [
            F.Position("A", "CUSIP", "1000200"),      # +0.02% → MINORE (rumore)
            F.Position("B", "CUSIP", "50050"),        # +0.10% → MINORE (rumore su posizione piccola)
            F.Position("C", "CUSIP", "3000")])        # +50%   → MATERIALE (discrepanza reale)
        r = F.reconcile(a, b, by="id")
        self.assertEqual(r["residual_count"], 1)                         # solo C è materiale
        self.assertEqual(r["residual_after_scale"][0]["key"], "CUSIP:C")
        self.assertGreaterEqual(r["minor_residual_count"], 1)            # A e/o B sono rumore minore
        # con material_tol più stretto, anche lo 0.10% diventa materiale (soglia esplicita, non magia)
        self.assertGreater(F.reconcile(a, b, by="id", material_tol=0.0005)["residual_count"], 1)

    def test_reconcile_auto_identifier_first_risolve_MBS(self):
        # DAL killer-experiment sui BOND: nome+coupon+maturity COLLIDE tra pool MBS diversi (stesso nome/coupon/
        # maturity, CUSIP diverso). by='auto' usa l'IDENTIFICATORE (ISIN, o CUSIP→ISIN) quando c'è → li distingue.
        # Fonte A in CUSIP, fonte B in ISIN degli STESSI due pool → per nome collidono, per auto no.
        a = F.Holdings("F", "d", "nport", [
            F.Position("31418CQM9", "CUSIP", "1000", name="Fannie Mae Pool|3.000|2042-05-01"),
            F.Position("31418CQN7", "CUSIP", "2000", name="Fannie Mae Pool|3.000|2042-05-01")])   # stesso nome!
        b = F.Holdings("F", "d", "ncsr", [
            F.Position(F.cusip_to_isin("31418CQM9"), "ISIN", "1000", name="Fannie Mae Pool|3.000|2042-05-01"),
            F.Position(F.cusip_to_isin("31418CQN7"), "ISIN", "2000", name="Fannie Mae Pool|3.000|2042-05-01")])
        # per NOME: i due pool collassano in una chiave (multiset di 2) → non distinti 1:1
        rn = F.reconcile(a, b, by="name")
        self.assertEqual(rn["matched"], 1)                    # una sola chiave-nome per due pool diversi
        # per AUTO (CUSIP→ISIN): due chiavi distinte, match esatto, zero materiali
        ra = F.reconcile(a, b, by="auto")
        self.assertEqual(ra["matched"], 2)                    # i due pool sono DISTINTI per identificatore
        self.assertEqual(ra["residual_count"], 0)
        self.assertEqual(ra["only_in_a"], 0)

    def test_attest_valuation_identita_e_copertura(self):
        # GAP A1 (il core NAV): FUNDCERT ATTESTA la coerenza interna di un pack di valorizzazione (non calcola
        # il NAV). Identità contabile totAssets−totLiabs==netAssets (esatta sui dati SEC reali) + copertura.
        v = F.Valuation("F", "2025-12-31", total_assets="1000000", total_liabilities="30000",
                        net_assets="970000", securities_value="950000")
        r = F.attest_valuation(v)
        self.assertTrue(r["identity_ok"])                       # 1000000 - 30000 == 970000
        self.assertTrue(r["coverage_ok"])                       # 950000 <= 1000000, cash 50000 >= 0
        self.assertEqual(r["non_security_assets"], "50000")
        # CONTROLLO NEGATIVO: net_assets incoerente → identità ROTTA (il banco sa fallire)
        bad = F.Valuation("F", "d", "1000000", "30000", "969000", "950000")
        self.assertFalse(F.attest_valuation(bad)["identity_ok"])
        # copertura ROTTA: titoli > attivo (impossibile) → coverage_ok False
        over = F.Valuation("F", "d", "1000000", "30000", "970000", "1200000")
        self.assertFalse(F.attest_valuation(over)["coverage_ok"])
        # il digest copre l'INTERO pack: cambiare un totale cambia il digest
        self.assertNotEqual(F.valuation_digest(v), F.valuation_digest(bad))
        # CONFINE: un NAV sbagliato ma coerente supera l'attestazione (proof-of-consistency, non veracity)
        self.assertTrue(r["identity_ok"])                       # non certifica che 970000 sia il NAV "giusto"

    def test_gap_B4_corporate_action_flag(self):
        # B4: un rapporto ~n:m semplice = candidato split/reverse (azione societaria), non discrepanza nuda.
        # Wolfspeed 162764→4895344 ≈ 30:1 (restructuring 2025 reale); Republic 17469→5795 ≈ 1:3 (reverse).
        self.assertEqual(F.corporate_action_flag(162764, 4895344)["kind"], "split_candidate")
        self.assertEqual(F.corporate_action_flag(162764, 4895344)["ratio"], "30:1")
        self.assertEqual(F.corporate_action_flag(17469, 5795)["kind"], "split_candidate")   # ~1:3
        self.assertEqual(F.corporate_action_flag(68552, 64552)["kind"], "discrepancy")       # 5.8%, no ratio
        self.assertEqual(F.corporate_action_flag(1000, 2000)["ratio"], "2:1")                # split netto

    def test_gap_C3_triage_prioritizza(self):
        # C3: da reconcile → worklist ordinato per severità con azione (confirm CA vs investigate).
        a = F.Holdings("F", "d", "n", [F.Position("A", "CUSIP", "1000"), F.Position("B", "CUSIP", "1000")])
        b = F.Holdings("F", "d", "c", [F.Position("A", "CUSIP", "30000"),   # 30:1 → corporate action, high
                                       F.Position("B", "CUSIP", "1080")])   # +8% → discrepancy, low
        t = F.triage(F.reconcile(a, b, by="id"))
        self.assertEqual(t["open"], 2)
        self.assertEqual(t["worklist"][0]["key"], "CUSIP:A")               # il più severo in cima
        self.assertEqual(t["worklist"][0]["action"], "confirm_corporate_action")
        self.assertEqual(t["worklist"][0]["severity"], "high")
        self.assertEqual(t["by_action"]["confirm_corporate_action"], 1)

    def test_gap_C1_parse_mapped_generico(self):
        # C1: ingestion generica — qualsiasi tabella diventa Holdings dichiarando una mappa campo→colonna.
        rows = [{"Tk": "AAPL", "Q": "1000", "Nm": "Apple", "Cy": "USD", "MV": "250000"},
                {"Tk": "", "Q": "5", "Nm": "CASH"}]                 # senza id → saltata, non persa in silenzio
        h = F.parse_mapped(rows, {"identifier": "Tk", "id_scheme": "=TICKER", "quantity": "Q",
                                  "name": "Nm", "currency": "Cy", "value": "MV"})
        self.assertEqual(len(h.positions), 1)
        self.assertEqual(len(h.skipped), 1)
        self.assertEqual((h.positions[0].identifier, h.positions[0].currency, h.positions[0].value),
                         ("AAPL", "USD", "250000"))

    def test_gap_C2_fuzzy_bridge(self):
        # C2: nomi quasi-uguali (share-class, abbreviazioni) recuperati sopra soglia, greedy 1:1.
        self.assertGreater(F.name_similarity("META PLATFORMS", "Meta Platforms Inc. Class A"), 0.6)
        self.assertLess(F.name_similarity("Apple Inc", "Microsoft Corp"), 0.4)
        a = ["Palantir Technologies", "Coinbase Global", "Nvidia Corp"]
        b = ["Palantir Technologies A", "Coinbase Global A", "Nvidia Corporation"]
        br = F.fuzzy_bridge(a, b, threshold=0.85)
        self.assertEqual(len(br), 3)
        self.assertEqual({p["a"] for p in br}, set(a))
        # C4/scala: il blocking (default, sub-quadratico) dà lo STESSO risultato del confronto esatto O(n²)
        exact = F.fuzzy_bridge(a, b, threshold=0.85, blocking=False)
        self.assertEqual({(p["a"], p["b"]) for p in br}, {(p["a"], p["b"]) for p in exact})

    def test_gap_B5_asset_class_exposure(self):
        # B5 (deficienza Gemini 'derivati/asset class'): il tool VEDE e separa le classi (equity/debt/derivato)
        # invece di confonderle. Metadata a parte, l'id le distingue già nel digest. Validato su VTIAX reale
        # (has_derivatives=True). Qui il vettore sintetico con un derivato.
        h = F.Holdings("F", "d", "nport", [
            F.Position("A", "ISIN", "100", value="9000", asset_class="EC"),      # equity
            F.Position("B", "ISIN", "100", value="900", asset_class="DBT"),      # debt
            F.Position("C", "", "1", value="100", asset_class="DE")])            # derivato
        e = F.asset_class_exposure(h)
        self.assertEqual(e["n_classes"], 3)
        self.assertTrue(e["has_derivatives"])                    # il derivato è VISTO, non confuso
        self.assertEqual(e["by_class"]["equity"], "9000")
        self.assertAlmostEqual(e["pct"]["equity"], 90.0, places=1)

    def test_gap_B2_currency_exposure(self):
        # B2: esposizione multi-valuta per valuta locale del titolo (valore in base). La riconciliazione per
        # shares resta currency-independent; questa è la vista rischio-valuta dei fondi internazionali.
        h = F.Holdings("F", "d", "nport", [
            F.Position("A", "ISIN", "100", currency="EUR", value="600"),
            F.Position("B", "ISIN", "100", currency="JPY", value="300"),
            F.Position("C", "ISIN", "100", currency="EUR", value="100"),
            F.Position("D", "ISIN", "100", currency="USD", value="")])   # senza value → non perso in silenzio
        e = F.currency_exposure(h)
        self.assertEqual(e["n_currencies"], 2)                 # EUR, JPY (USD senza value escluso)
        self.assertEqual(e["by_currency"]["EUR"], "700")       # 600+100
        self.assertEqual(e["positions_without_value"], 1)
        self.assertAlmostEqual(e["pct"]["EUR"], 70.0, places=1)

    def test_gap_B3_inflation_linked(self):
        self.assertTrue(F.is_inflation_linked("United States Treasury Inflation Indexed Bond"))
        self.assertTrue(F.is_inflation_linked("US TIPS 0.125% 2031"))
        self.assertFalse(F.is_inflation_linked("Apple Inc"))

    def test_norm_name_cross_source_senza_id(self):
        # l'N-CSR non ha CUSIP → match per nome normalizzato
        self.assertEqual(F.norm_name("Alphabet Inc. Class A"), F.norm_name("ALPHABET  CLASS A"))
        self.assertEqual(F.norm_name("Microsoft Corporation"), "MICROSOFT")

    def test_parse_ncsr_soi_marcatori_e_isolamento(self):
        # dal killer-experiment multi-fondo: l'N-CSR ha righe con MARCATORI DI NOTA ('*,1') che spostano le
        # colonne — [*,1, Nome, Shares, Valore] invece di [Nome, Shares, Valore]. E due fondi nello stesso doc
        # non devono contaminarsi. Regressione su entrambi.
        html_doc = (
            '<div>Alpha Index Fund Financial Statements Schedule of Investments</div>'
            '<table>'
            '<tr><td>Shares</td><td>Market Value ($000)</td></tr>'
            '<tr><td>Common Stocks (99.0%)</td></tr>'
            '<tr><td>Apple Inc.</td><td>1,000,000</td><td>250,000</td></tr>'      # riga normale
            '<tr><td>*,1</td><td>MP Materials Corp.</td><td>5,020,434</td><td>253,632</td></tr>'  # con marcatore
            '</table>'
            '<div>Statement of Assets and Liabilities</div>'
            '<div>Beta Index Fund Financial Statements Schedule of Investments</div>'
            '<table><tr><td>Microsoft Corp.</td><td>999</td><td>1</td></tr></table>'
            '<div>Statement of Assets and Liabilities</div>')
        h = F.parse_ncsr_soi(html_doc, "Alpha Index Fund")
        got = {F.norm_name(p.name): p.quantity for p in h.positions}
        self.assertEqual(got.get(F.norm_name("Apple Inc.")), "1000000")
        self.assertEqual(got.get(F.norm_name("MP Materials Corp.")), "5020434")   # marcatore tollerato
        self.assertNotIn(F.norm_name("Microsoft Corp."), got)                     # sezione Beta NON contamina
        self.assertNotIn(F.norm_name("Common Stocks"), got)                       # header di gruppo scartato
        # e la riconciliazione per nome con l'N-PORT dello stesso basket → residuo 0
        nport = F.Holdings("Alpha", "d", "nport", [
            F.Position("037833100", "CUSIP", "1000000", name="Apple Inc."),
            F.Position("55405G102", "CUSIP", "5020434", name="MP Materials Corp.")])
        self.assertEqual(F.reconcile(nport, h, by="name")["residual_count"], 0)

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
