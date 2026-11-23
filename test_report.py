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

try:   # the `sign` extra; without it the cases that need it are skipped with this reason, never an error
    import cryptography  # noqa: F401
    HAVE_CRYPTO = True
except ImportError:
    HAVE_CRYPTO = False
if os.environ.get("CV_REQUIRE_CRYPTO") == "1" and not HAVE_CRYPTO:   # the job with cryptography must not pass on skips
    raise SystemExit("CV_REQUIRE_CRYPTO=1 but `cryptography` is missing: the cases that need it would be skipped")
NEEDS_CRYPTO = unittest.skipUnless(HAVE_CRYPTO, "needs `cryptography` (the `sign` extra)")

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


@NEEDS_CRYPTO
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
    @NEEDS_CRYPTO
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

    @NEEDS_CRYPTO
    def test_lotl_not_run_by_default(self):
        r = report.generate_report(self.pack, html_only=True)
        self.assertFalse(r["eidas"]["checked"])               # rete solo opt-in

    @NEEDS_CRYPTO
    def test_lotl_history_error_is_inconclusive(self):
        # 0.21.0, ETSI TS 119 615 PRO-4.3.4-03A: neither QUALIFIED nor NOT QUALIFIED
        import base64 as _b64
        import cryptovalid_lotl as lotl
        man = {"rfc3161_timestamp": {"anchored": True, "tsr_b64": _b64.b64encode(b"tok").decode(), "tsa": "t"}}
        orig = lotl.load_qualified_status, lotl.token_cert_fingerprints, lotl.signer_fingerprints
        lotl.token_cert_fingerprints = lambda tok: {"ab" * 32}
        lotl.signer_fingerprints = lambda tok: {"ab" * 32}   # v0.6 (2026-11-13): the qualification reads the signer
        try:
            for herr, qual in (({"ab" * 32: "history_not_ordered u"}, None), ({}, False)):
                lotl.load_qualified_status = lambda member_states=None, cache_path=None, h=herr: (set(), [], h)
                r = report.lotl_status(man)
                self.assertIs(r["qualified"], qual, r)
                self.assertEqual("history_not_ordered" in r.get("note", ""), qual is None, r)
        finally:
            lotl.load_qualified_status, lotl.token_cert_fingerprints, lotl.signer_fingerprints = orig

    @unittest.skipUnless(_HAVE_WEASY, "WeasyPrint not installed (honest skip)")
    def test_pdf_rendered_when_weasyprint_present(self):
        r = report.generate_report(self.pack)
        self.assertTrue(r["pdf"] and os.path.exists(r["pdf"]))
        with open(r["pdf"], "rb") as f:
            self.assertEqual(f.read(5), b"%PDF-")

    @NEEDS_CRYPTO
    def test_html_injection_escaped(self):
        mp = os.path.join(self.pack, "MANIFEST.json")
        man = json.load(open(mp))
        man["subject"] = "<script>alert(1)</script>"
        json.dump(man, open(mp, "w"))                          # rompe anche il digest: doppio uso
        r = report.generate_report(self.pack, html_only=True)
        doc = open(r["html"], encoding="utf-8").read()
        self.assertNotIn("<script>alert(1)</script>", doc)     # escapato SEMPRE
        self.assertFalse(r["valid"])                           # e il pack manomesso resta ROSSO


@NEEDS_CRYPTO
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


@NEEDS_CRYPTO
class TestNoRendererVerdict(_Base):
    """Invariante: il renderer non possiede un verdetto suo — riflette verify_pack()."""

    def test_render_reflects_forced_failure(self):
        man = json.load(open(os.path.join(self.pack, "MANIFEST.json")))
        verification = evidence_pack.verify_pack(self.pack)
        verification["valid"] = False                          # il checker dice NO
        doc = report.render_html(man, verification, {"checked": False, "qualified": None})
        self.assertIn("INVALID", doc)                          # il renderer obbedisce


@NEEDS_CRYPTO
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

    def test_anchor_digest_is_sha3_256_of_the_manifest_digest_hex(self):   # expected: SHA3-256 of b"ab"
        self.assertEqual(report.solana_anchor_digest({"manifest_digest_sha256": "ab"}),
                         "5c828b33397f4762922e39a60c35699d2550466a52dd15ed44da37eb0bdc61e6")

    def _with_verifier(self, fake):
        import cryptovalid_solana as sol
        orig, sol.verify_solana_anchor = sol.verify_solana_anchor, fake
        try:
            return report.generate_report(self.pack, html_only=True, solana=True)
        finally:
            sol.verify_solana_anchor = orig

    def test_verifier_error_is_inconclusive_and_signer_is_passed(self):
        d = report.solana_anchor_digest(self._manifest())
        with open(os.path.join(self.pack, "SOLANA_ANCHOR.json"), "w", encoding="utf-8") as f:
            json.dump({"tx_signature": "5" * 64, "digest_sha3_hex": " " + d.upper() + "\n", "expected_signer": "S1"}, f)
        seen = {}

        def fake_ok(sig, exp, **kw):
            seen.update(kw, sig=sig, exp=exp)
            return {"ok": True, "checks": [], "onchain": {"slot": 7, "witnesses": 2}}

        r = self._with_verifier(fake_ok)
        self.assertIs(r["solana"]["verified"], True)
        self.assertEqual(seen, {"expected_signer": "S1", "sig": "5" * 64, "exp": d})

        def boom(sig, exp, **kw):
            raise OSError("no network")

        r = self._with_verifier(boom)
        self.assertEqual((r["solana"]["checked"], r["solana"]["verified"]), (True, None))
        with open(r["html"], encoding="utf-8") as f:
            self.assertIn("INCONCLUSIVE", f.read())

    def test_malformed_anchor_is_a_failure_never_a_traceback(self):
        d = report.solana_anchor_digest(self._manifest())

        def never(sig, exp, **kw):
            raise AssertionError("the verifier must not be reached")

        bodies = ["[]", '"x"', "null", "1", "{}", "{not json", "[" * 100000,
                  json.dumps({"tx_signature": "5" * 64, "digest_sha3_hex": 1}),
                  json.dumps({"tx_signature": "5" * 64, "digest_sha3_hex": [d]}),
                  json.dumps({"tx_signature": "5" * 64}),
                  json.dumps({"digest_sha3_hex": d}),
                  json.dumps({"tx_signature": "", "digest_sha3_hex": d}),
                  json.dumps({"tx_signature": 5, "digest_sha3_hex": d}),
                  json.dumps({"tx_signature": ["5"], "digest_sha3_hex": d}),
                  json.dumps({"tx_signature": "\ud800", "digest_sha3_hex": d}),
                  '{"tx_signature":NaN,"digest_sha3_hex":"%s"}' % d]
        for body in bodies:
            with self.subTest(body=body[:40]):
                with open(os.path.join(self.pack, "SOLANA_ANCHOR.json"), "w", encoding="utf-8") as f:
                    f.write(body)
                r = self._with_verifier(never)
                self.assertEqual((r["solana"]["present"], r["solana"]["checked"], r["solana"]["verified"]),
                                 (True, False, False))
                self.assertTrue(r["valid"])            # the pack itself is untouched
                with open(r["html"], encoding="utf-8") as f:
                    self.assertIn("VERIFICATION FAILED", f.read())

    def test_manifest_that_is_not_an_object_clean_error(self):
        for body in ("[]", '"x"', "null", "1", "[" * 100000):
            with self.subTest(body=body[:10]):
                with open(os.path.join(self.pack, "MANIFEST.json"), "w", encoding="utf-8") as f:
                    f.write(body)
                r = report.generate_report(self.pack, html_only=True)
                self.assertIs(r["valid"], False)
                self.assertIn("MANIFEST.json unreadable", r.get("error", ""))


class SolanaDigestCli(unittest.TestCase):
    """--solana-digest prints a memo only for a readable MANIFEST.json that carries a 64-hex manifest_digest_sha256;
    anything else is a usage error with the reason (exit 2), never a traceback and never the digest of "" (2026-11-23)."""

    def run_cli(self, manifest_bytes):
        import subprocess
        with tempfile.TemporaryDirectory() as d:
            if manifest_bytes is not None:
                with open(os.path.join(d, "MANIFEST.json"), "wb") as f:
                    f.write(manifest_bytes)
            return subprocess.run([sys.executable, report.__file__, d, "--solana-digest"],
                                  capture_output=True, text=True, timeout=60)

    def test_bad_manifests_are_usage_errors(self):
        for m in (b"[]", b"null", b"{}", b'{"manifest_digest_sha256": "ab"}', b'{"manifest_digest_sha256": 1}',
                  b'{"manifest_digest_sha256": "' + b"A" * 64 + b'"}', b"[[[[", b"\xff\xfe", b"[" * 100000, None):
            r = self.run_cli(m)
            self.assertEqual(r.returncode, 2, (m[:20] if m else m, r.stderr[-200:]))
            self.assertNotIn("Traceback", r.stderr)
            self.assertEqual(r.stdout, "")

    def test_a_good_manifest_prints_its_digest(self):
        md = "a" * 64
        r = self.run_cli(json.dumps({"manifest_digest_sha256": md}).encode())
        self.assertEqual(r.returncode, 0, r.stderr)
        out = json.loads(r.stdout)
        self.assertEqual(out["digest_sha3_hex"], report.solana_anchor_digest({"manifest_digest_sha256": md}))
        self.assertEqual(out["solana_memo"], "sha3:" + out["digest_sha3_hex"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
