#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Banco per OMEGA-MICROFINANCE — che SA FALLIRE (controllo positivo + negativo prima delle misure)."""
import copy
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import microfinance as M  # noqa: E402


def _portfolio():
    # portafoglio MFI realistico: erogato = in-essere + rimborsato + svalutato per ogni prestito
    loans = [
        M.LoanRecord("L001", M.hash_borrower("Amina K.", "salt-mfi"), "1000", "600", "400", "0", "KES", "0"),
        M.LoanRecord("L002", M.hash_borrower("Joseph M.", "salt-mfi"), "500", "500", "0", "0", "KES", "45"),
        M.LoanRecord("L003", M.hash_borrower("Grace O.", "salt-mfi"), "800", "0", "700", "100", "KES", "0"),
    ]
    return M.LoanPortfolio("MFI-KE-01", "2026-06-30", "core-banking", loans, "KES")


class TestMicrofinance(unittest.TestCase):
    def test_privacy_no_pii(self):
        # il borrower_ref è un HASH, non il nome (no-PII by design)
        ref = M.hash_borrower("Amina K.", "salt-mfi")
        self.assertNotIn("Amina", ref)
        self.assertEqual(len(ref), 32)
        self.assertEqual(ref, M.hash_borrower("Amina K.", "salt-mfi"))          # deterministico con lo stesso salt
        self.assertNotEqual(ref, M.hash_borrower("Amina K.", "altro-salt"))     # salt diverso → ref diverso

    def test_digest_determinismo(self):
        p = _portfolio()
        d0 = M.portfolio_digest(p)
        p2 = copy.deepcopy(p)
        p2.loans = list(reversed(p2.loans))                                     # ordine irrilevante
        self.assertEqual(d0, M.portfolio_digest(p2))
        p2.loans[0].principal_outstanding = "601"                              # +1 → digest cambia (sa fallire)
        self.assertNotEqual(d0, M.portfolio_digest(p2))

    def test_attest_identita_contabile(self):
        p = _portfolio()
        r = M.attest_portfolio(p)
        self.assertTrue(r["identity_ok"])                                       # 2300 erogato == 1100+1100+100
        self.assertEqual(r["loans_inconsistent"], [])
        self.assertEqual(r["total_disbursed"], "2300")
        # CONTROLLO NEGATIVO: conti che non tornano → identità rotta + prestito segnalato
        bad = copy.deepcopy(p)
        bad.loans[0].principal_repaid = "999"                                  # 1000 != 600+999+0
        rb = M.attest_portfolio(bad)
        self.assertFalse(rb["identity_ok"])
        self.assertIn("L001", rb["loans_inconsistent"])

    def test_portfolio_at_risk(self):
        p = _portfolio()
        # solo L002 (500 in essere) è in ritardo > 30 giorni; outstanding totale = 600+500+0 = 1100
        par30 = M.portfolio_at_risk(p, 30)
        self.assertEqual(par30["at_risk"], "500")
        self.assertAlmostEqual(par30["par_pct"], 500 / 1100 * 100, places=2)
        self.assertEqual(M.portfolio_at_risk(p, 90)["at_risk"], "0")            # nessuno oltre 90 giorni

    def test_reconcile_mfi_vs_donor(self):
        mfi = _portfolio()
        donor = copy.deepcopy(mfi)
        donor.loans[0].principal_outstanding = "600"                           # concorda
        donor.loans[1].principal_outstanding = "250"                           # -50% → materiale (discrepanza)
        r = M.reconcile_portfolios(mfi, donor)
        self.assertEqual(r["residual_count"], 1)
        self.assertEqual(r["residual_after_scale"][0]["key"], "LOANID:L002")

    def test_microdebito_sovraindebitamento_cross_mfi(self):
        # MICRO-DEBITO: lo stesso beneficiario (stesso hash) con prestiti in DUE MFI → rilevato senza PII.
        ref_amina = M.hash_borrower("Amina K.", "shared-scheme")
        mfi1 = M.LoanPortfolio("MFI-A", "2026-06-30", "cb", [
            M.LoanRecord("A1", ref_amina, "1000", "600"),
            M.LoanRecord("A2", M.hash_borrower("Joseph M.", "shared-scheme"), "500", "500")], "KES")
        mfi2 = M.LoanPortfolio("MFI-B", "2026-06-30", "cb", [
            M.LoanRecord("B1", ref_amina, "800", "800")], "KES")               # Amina ha un 2° prestito altrove
        exp = M.borrower_debt_exposure([mfi1, mfi2])
        self.assertEqual(exp["by_borrower"][ref_amina]["n_institutions"], 2)   # cross-MFI
        self.assertEqual(exp["by_borrower"][ref_amina]["outstanding"], "1400") # 600+800 aggregato senza PII
        # allerta sovra-indebitamento: chi è in >1 istituto
        oi = M.over_indebtedness([mfi1, mfi2], max_institutions=1)
        self.assertEqual(oi["n_flagged"], 1)
        self.assertEqual(oi["flags"][0]["borrower_ref"], ref_amina)
        self.assertIn(">1 istituti", oi["flags"][0]["reasons"])
        # e nessun nome in chiaro da nessuna parte
        self.assertNotIn("Amina", str(exp) + str(oi))

    def test_evidence_record_provenienza(self):
        p = _portfolio()
        raw = b'{"mfi":"raw core-banking export"}'
        rec = M.portfolio_evidence(p, raw, source="MFI-KE-01 core-banking", fetched_at="2026-08-20T11:00:00Z")
        import hashlib
        self.assertEqual(rec["input_sha256"], hashlib.sha256(raw).hexdigest())
        self.assertEqual(rec["kind"], "microfinance_evidence")
        self.assertEqual(rec["holdings_digest"], M.portfolio_digest(p))


if __name__ == "__main__":
    unittest.main(verbosity=2)
