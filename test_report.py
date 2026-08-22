#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Roberto Locatelli
"""Standalone test of the auditor report: the bench proves it can FAIL first
(tampered pack -> RED report), then the positive path, PDF when WeasyPrint exists,
HTML injection safety, and the no-renderer-verdict invariant."""
import json
import os
import sys
import tempfile
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
import cryptovalid_report as report  # noqa: E402
import evidence_pack  # noqa: E402
import signer  # noqa: E402
from test_evidence_pack import _make_ledger  # noqa: E402  (same fixture, no duplication)

try:
    import weasyprint  # noqa: F401
    _HAVE_WEASY = True
except Exception:  # noqa: BLE001
    _HAVE_WEASY = False


class _Base(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        ledger = os.path.join(self.d, "ledger.jsonl")
        self.signed = os.path.join(self.d, "signed.jsonl")
        key = os.path.join(self.d, "k.key")
        self.pack = os.path.join(self.d, "pack")
        _make_ledger(ledger)
        signer.keygen(key)
        signer.sign_ledger(ledger, self.signed, key)
        evidence_pack.build_pack([self.signed], self.pack, subject="report bench")

    def _tamper(self):
        p = os.path.join(self.pack, "signed.jsonl")
        rows = [json.loads(x) for x in open(p)]
        rows[1]["data"]["d"] = "reject"
        with open(p, "w") as f:
            for x in rows:
                f.write(json.dumps(x) + "\n")


class TestBenchCanFail(_Base):
    """Controllo positivo del banco: PRIMA dimostriamo che una manomissione produce ROSSO."""

    def test_tampered_pack_yields_red_report(self):
        self._tamper()
        r = report.generate_report(self.pack, html_only=True)
        self.assertFalse(r["valid"])
        doc = open(r["html"], encoding="utf-8").read()
        self.assertIn("INVALID", doc)
        self.assertIn('class="status bad"', doc.replace("'", '"'))
        self.assertNotIn("VALID — evidence verified", doc)

    def test_cli_exit_code_nonzero_on_tamper(self):
        self._tamper()
        self.assertEqual(report.main([self.pack, "--html-only"]), 1)


class TestReportPositive(_Base):
    def test_valid_pack_yields_green_report(self):
        r = report.generate_report(self.pack, html_only=True)
        self.assertTrue(r["valid"])
        doc = open(r["html"], encoding="utf-8").read()
        self.assertIn("VALID — evidence verified", doc)
        # dettaglio ledger: file, conteggio entry e testa presenti
        self.assertIn("signed.jsonl", doc)
        self.assertIn("<td>2</td>", doc)                      # entry count dal manifest
        man = json.load(open(os.path.join(self.pack, "MANIFEST.json")))
        self.assertIn(man["manifest_digest_sha256"], doc)     # report ID = digest manifest
        self.assertIn(man["signer_pubkeys"][0], doc)          # chiave firmataria mostrata
        self.assertIn("NOT ANCHORED", doc)                    # niente TSA -> dichiarato, non nascosto
        self.assertIn("NOT CHECKED", doc)                     # LOTL non chiesto -> nessun verde finto
        self.assertEqual(len(r["report_sha256"]), 64)

    def test_lotl_not_run_by_default(self):
        r = report.generate_report(self.pack, html_only=True)
        self.assertFalse(r["eidas"]["checked"])               # rete solo opt-in

    @unittest.skipUnless(_HAVE_WEASY, "WeasyPrint not installed (honest skip)")
    def test_pdf_rendered_when_weasyprint_present(self):
        r = report.generate_report(self.pack)
        self.assertTrue(r["pdf"] and os.path.exists(r["pdf"]))
        with open(r["pdf"], "rb") as f:
            self.assertEqual(f.read(5), b"%PDF-")

    def test_html_injection_escaped(self):
        mp = os.path.join(self.pack, "MANIFEST.json")
        man = json.load(open(mp))
        man["subject"] = "<script>alert(1)</script>"
        json.dump(man, open(mp, "w"))                          # rompe anche il digest: doppio uso
        r = report.generate_report(self.pack, html_only=True)
        doc = open(r["html"], encoding="utf-8").read()
        self.assertNotIn("<script>alert(1)</script>", doc)     # escapato SEMPRE
        self.assertFalse(r["valid"])                           # e il pack manomesso resta ROSSO


class TestReviewFollowups(_Base):
    """Rifiniture della review avversariale pre-publish (17/08): injection su pack
    VERDE, degrade pulito su manifest assente/corrotto."""

    def test_injection_escaped_in_green_pack(self):
        # subject ostile con digest RICOMPUTATO: il pack resta VERDE e
        # l'escaping deve tenere lo stesso (attacco più forte della review)
        import hashlib
        mp = os.path.join(self.pack, "MANIFEST.json")
        man = json.load(open(mp))
        man["subject"] = '"><script>alert(1)</script>'
        m2 = {k: v for k, v in man.items()
              if k not in ("manifest_digest_sha256", "rfc3161_timestamp",
                           "manifest_signature", "manifest_signer")}
        man["manifest_digest_sha256"] = hashlib.sha256(
            json.dumps(m2, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        json.dump(man, open(mp, "w"))
        r = report.generate_report(self.pack, html_only=True)
        self.assertTrue(r["valid"])                            # verde davvero
        doc = open(r["html"], encoding="utf-8").read()
        self.assertNotIn("<script>alert(1)</script>", doc)     # niente breakout
        self.assertNotIn('""><script>', doc)                   # né in attributo

    def test_missing_manifest_clean_error(self):
        empty = tempfile.mkdtemp()
        r = report.generate_report(empty, html_only=True)
        self.assertFalse(r["valid"])
        self.assertIn("MANIFEST.json unreadable", r.get("error", ""))

    def test_corrupt_manifest_clean_error(self):
        with open(os.path.join(self.pack, "MANIFEST.json"), "w") as f:
            f.write("{not json")
        r = report.generate_report(self.pack, html_only=True)
        self.assertFalse(r["valid"])
        self.assertIn("MANIFEST.json unreadable", r.get("error", ""))


class TestNoRendererVerdict(_Base):
    """Invariante: il renderer non possiede un verdetto suo — riflette verify_pack()."""

    def test_render_reflects_forced_failure(self):
        man = json.load(open(os.path.join(self.pack, "MANIFEST.json")))
        verification = evidence_pack.verify_pack(self.pack)
        verification["valid"] = False                          # il checker dice NO
        doc = report.render_html(man, verification, {"checked": False, "qualified": None})
        self.assertIn("INVALID", doc)                          # il renderer obbedisce


if __name__ == "__main__":
    unittest.main(verbosity=2)


class TestSolanaAnchor(_Base):
    """Seconda ancora (Solana) nel report: 4 stati onesti, legatura al pack, rete stubbata
    (il protocollo on-chain vero è coperto da test_cryptovalid_solana)."""

    def _manifest(self):
        with open(os.path.join(self.pack, "MANIFEST.json"), encoding="utf-8") as f:
            return json.load(f)

    def _write_anchor(self, digest):
        with open(os.path.join(self.pack, "SOLANA_ANCHOR.json"), "w", encoding="utf-8") as f:
            json.dump({"tx_signature": "5" * 64, "digest_sha3_hex": digest}, f)

    def test_absent_anchor_is_honest_na(self):
        r = report.generate_report(self.pack, html_only=True)
        self.assertEqual(r["solana"], {"present": False, "checked": False, "verified": None})
        doc = open(r["html"], encoding="utf-8").read()
        self.assertIn("Solana mainnet anchor", doc)
        self.assertIn("NOT ANCHORED", doc)

    def test_unbound_anchor_fails_offline(self):
        # il banco deve saper fallire: ancora valida-ma-ESTRANEA respinta SENZA rete
        self._write_anchor("a" * 64)
        r = report.generate_report(self.pack, html_only=True)
        self.assertIs(r["solana"]["verified"], False)
        self.assertIn("NOT bound", r["solana"]["note"])
        self.assertIn("VERIFICATION FAILED", open(r["html"], encoding="utf-8").read())

    def test_bound_anchor_recorded_not_checked_by_default(self):
        self._write_anchor(report.solana_anchor_digest(self._manifest()))
        r = report.generate_report(self.pack, html_only=True)
        self.assertIsNone(r["solana"]["verified"])
        self.assertFalse(r["solana"]["checked"])
        self.assertIn("RECORDED, NOT VERIFIED", open(r["html"], encoding="utf-8").read())

    def test_bound_anchor_checked_with_injected_verifier(self):
        d = report.solana_anchor_digest(self._manifest())
        self._write_anchor(d)
        import cryptovalid_solana as sol
        orig, calls = sol.verify_solana_anchor, {}

        def fake_ok(sig, exp, **kw):
            calls["args"] = (sig, exp)
            return {"ok": True, "checks": [],
                    "onchain": {"signature": sig, "slot": 1, "witnesses": 2,
                                "block_time": 0, "signer": "S", "digests": [exp]}}

        def fake_bad(sig, exp, **kw):
            return {"ok": False, "onchain": None,
                    "checks": [{"check": "expected digest present in canonical spl-memo",
                                "ok": False, "note": ""}]}

        sol.verify_solana_anchor = fake_ok
        try:
            r = report.generate_report(self.pack, html_only=True, solana=True)
        finally:
            sol.verify_solana_anchor = orig
        self.assertIs(r["solana"]["verified"], True)
        self.assertEqual(calls["args"][1], d)          # verifica ESATTAMENTE il digest legato
        self.assertIn("VERIFIED", open(r["html"], encoding="utf-8").read())

        sol.verify_solana_anchor = fake_bad
        try:
            r2 = report.generate_report(self.pack, html_only=True, solana=True)
        finally:
            sol.verify_solana_anchor = orig
        self.assertIs(r2["solana"]["verified"], False)
        self.assertIn("spl-memo", r2["solana"]["note"])
