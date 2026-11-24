#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""A pinned TSA certificate must be shaped as a certificate (RFC 5280 §4.1) before any token is read with it.

Found by the NEMESIS review of 15/11/2026: `_pem_certs` accepted any item whose first byte was 0x30 (a PEM block
`MAA=`, the DER bytes 30 03 02 01 01). openssl could not load it and refused the token's signature: the real DigiCert
token of spec/vectors/rfc3161, pinned with its own certificate plus such a file, became `tsa_unresolved`, and pinned with
the file alone `contradicted / token_invalid` (the pack not valid) — a fault of the verifier's input reported as a fault
of the evidence. Now such a pin is a ValueError (exit 2 on the command line) before the pack is read."""
import base64
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True
ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)
import cryptovalid_tsa as T  # noqa: E402
import evidence_pack as EP  # noqa: E402

V = os.path.join(ROOT, "spec", "vectors", "rfc3161")
JUNK = {"pem_30_00": b"-----BEGIN CERTIFICATE-----\nMAA=\n-----END CERTIFICATE-----\n",
        "pem_int": b"-----BEGIN CERTIFICATE-----\n" + base64.b64encode(b"\x30\x03\x02\x01\x01") + b"\n-----END CERTIFICATE-----\n",
        "der_int": b"\x30\x03\x02\x01\x01", "der_empty_seq": b"\x30\x00",
        "der_two_seq": b"\x30\x04\x30\x00\x30\x00", "der_trailing": b"\x30\x06\x30\x00\x30\x00\x03\x00\x00"}


class PinShape(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.td, True)

    def _file(self, name, data):
        p = os.path.join(self.td, name)
        with open(p, "wb") as f:
            f.write(data)
        return p

    def test_every_certificate_of_the_vectors_is_accepted(self):
        pems = [n for n in os.listdir(V) if n.endswith(".pem")]
        self.assertTrue(pems)
        for n in pems:
            T._pem_certs([os.path.join(V, n)])            # no ValueError
            der = T._first_pem_der(open(os.path.join(V, n), "rb").read())
            self.assertTrue(T._is_certificate_der(der), n)
            T._pem_certs([der])                           # the same certificate as DER bytes

    def test_junk_that_begins_with_0x30_is_refused(self):
        for name, data in JUNK.items():
            with self.subTest(name):
                with self.assertRaises(ValueError):
                    T._pem_certs([data])
                with self.assertRaises(ValueError):
                    T._pem_certs([os.path.join(V, "digicert.signer.pem"), self._file(name, data)])

    def test_verify_pack_and_command_refuse_the_pin_before_reading(self):
        p = self._file("junk.pem", JUNK["pem_int"])
        with self.assertRaises(ValueError):
            EP.verify_pack(os.path.join(self.td, "no-such-pack"), tsa_certs=[os.path.join(V, "digicert.signer.pem"), p])
        r = subprocess.run([sys.executable, os.path.join(ROOT, "evidence_pack.py"), "verify", self.td, "--tsa-cert", p],
                           capture_output=True, text=True, encoding="utf-8", timeout=60)
        self.assertEqual(r.returncode, 2, r.stderr)
        self.assertEqual(r.stdout, "")

    @unittest.skipIf(shutil.which("openssl") is None, "needs openssl")
    def test_the_real_token_is_verified_under_its_own_pin(self):
        with open(os.path.join(V, "manifest.json"), encoding="utf-8") as f:
            dig = json.load(f)["digest_sha256"]
        tok = base64.b64encode(open(os.path.join(V, "digicert.tsr"), "rb").read()).decode()
        el, _ = EP._pinned_time_anchor(tok, dig, [os.path.join(V, "digicert.signer.pem")])
        self.assertEqual(el[:2], ("verified", None))


class BuildRefusesTsaSchemes(unittest.TestCase):
    """NEMESIS 15/11/2026: no suite observed the refusal of a TSA URL scheme in `build` (a mutant that wrote
    `anchored: true` there survived the pack suites)."""
    def test_file_ftp_data_are_not_anchored(self):
        td = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, td, True)
        sample = os.path.join(ROOT, "examples", "sample_ledger.jsonl")
        for i, url in enumerate(("file:///etc/hostname", "ftp://127.0.0.1/x", "data:,x", "FILE:///etc/hostname")):
            with self.subTest(url):
                out = os.path.join(td, f"p{i}")
                EP.build_pack([sample], out, subject="t", tsa_url=url)
                with open(os.path.join(out, "MANIFEST.json"), encoding="utf-8") as f:
                    ts = json.load(f).get("rfc3161_timestamp") or {}
                self.assertIs(ts.get("anchored"), False)
                self.assertNotIn("tsr_b64", ts)


@unittest.skipIf(shutil.which("openssl") is None, "needs openssl (a local TSA)")
class PinnedCheckNotRun(unittest.TestCase):
    """NEMESIS 15/11/2026: no suite observed openssl failing to run DURING the pinned check (SPEC §10: exit 74 with the
    complete receipt, `instrument_failure`, states-2). Mutants that dropped `not_run = e` or the states-2 mark survived."""
    def test_check_not_run_during_the_pinned_check(self):
        from unittest import mock
        sys.path.insert(0, os.path.join(ROOT, "verifiers"))
        from pack_states_bench import LocalTsa, _load, _store
        td = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, td, True)
        os.makedirs(os.path.join(td, "tsa"))
        tsa = LocalTsa(os.path.join(td, "tsa"))
        p = os.path.join(td, "pack")
        EP.build_pack([os.path.join(ROOT, "examples", "sample_ledger.jsonl")], p, subject="t")
        m = _load(p)
        m["rfc3161_timestamp"] = {"anchored": True, "tsa": "local", "tsr_b64": tsa.token(m["manifest_digest_sha256"])}
        _store(p, m)
        self.assertEqual(EP.verify_pack(p, tsa_certs=[tsa.j("ca.crt")])["states"]["time_anchor"]["state"], "verified")
        boom = T._not_run("cannot run openssl here", OSError("terminated by signal 9"))
        with mock.patch.object(T, "verify_token", side_effect=boom):
            with self.assertRaises(EP.CheckNotRun) as cm:
                EP.verify_pack(p, tsa_certs=[tsa.j("ca.crt")])
        r = cm.exception.receipt
        self.assertIsInstance(r, dict)
        self.assertEqual(r["states_vocabulary"], EP.STATES_VOCABULARY_PINNED_TSA)
        with mock.patch.object(EP, "_verify_rfc3161", side_effect=boom):   # without a pin the receipt stays states-1
            with self.assertRaises(EP.CheckNotRun) as cm2:
                EP.verify_pack(p)
        self.assertEqual(cm2.exception.receipt["states_vocabulary"], EP.STATES_VOCABULARY)
        self.assertEqual((r["states"]["time_anchor"]["state"], r["states"]["time_anchor"]["reasons"][0]),
                         ("not_evaluated", "instrument_failure"))


if __name__ == "__main__":
    unittest.main()
