#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""SPEC v0.10 §11 "The qualified statement" (17/11/2026): Commission Implementing Regulation (EU) 2025/1929, Annex
(ETSI EN 319 422 V1.1.1 clause 9.1 as adapted): a time stamp declared qualified carries one non-critical qcStatements
extension (RFC 3739 §3.2.6) in its TSTInfo with one esi4-qtstStatement-1 (0.4.0.19422.1.1).
`cryptovalid_lotl.qualification` says `qualified` only when the signer is a granted QTST certificate AND the token
carries the statement; otherwise `not_qualified` with `qualified_statement_missing` or `qualified_statement_malformed`.

Real tokens requested on 2026-11-17 (spec/vectors/rfc3161/) from four public TSA endpoints that put the statement in
their tokens: three are read and carry it; Sectigo's writes the DEFAULT `critical FALSE` of its Extension (not DER, RFC
3161 §2.4.2), so §11 refuses the token as malformed (step 1: DER) and the statement is not read (a verdict this change does not touch). The
real tokens of 13/11/2026 (freetsa, DigiCert, Sectigo, GlobalSign) carry no statement. Generated tokens: a TSTInfo of `openssl ts -reply` with extensions inserted and
re-signed by `openssl cms -sign -cades`, in both forms of `sid`; their verdict under pinned certificates does not
change. Positive control: on the code before this change the tokens without the statement, signer listed, are
`qualified` (the tests that assert `not_qualified` fail there)."""
import base64
import hashlib
import json
import os
import shutil
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True
ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)
import cryptovalid_lotl as L  # noqa: E402
import cryptovalid_tsa as T  # noqa: E402

VEC = os.path.join(ROOT, "spec", "vectors", "rfc3161")
OID_QC = "1.3.6.1.5.5.7.1.3"
OID_QTST = "0.4.0.19422.1.1"
OID_QCS_COMPLIANCE = "0.4.0.1862.1.1"   # ETSI EN 319 412-5 esi4-qcStatement-1: a statement of certificates, not of tokens
REAL_QUALIFIED = ("bosa_qualified", "izenpe_qualified", "accv_qualified")
REAL_NOT_DER = "sectigo_qualified"        # its qcStatements Extension writes critical FALSE: not DER, malformed (§11 step 1)
REAL_WITHOUT = ("freetsa", "digicert", "sectigo", "globalsign")   # the vectors of 13/11/2026


def tlv(tag: int, v: bytes) -> bytes:
    return T._tlv_bytes(tag, v)


def oid_tlv(dotted: str) -> bytes:
    parts = [int(x) for x in dotted.split(".")]
    body = bytes([40 * parts[0] + parts[1]])
    for n in parts[2:]:
        enc = [n & 0x7F]
        while n > 0x7F:
            n >>= 7
            enc.insert(0, 0x80 | (n & 0x7F))
        body += bytes(enc)
    return tlv(0x06, body)


def qc_value(*statements) -> bytes:
    """DER QCStatements; each statement (oid, statementInfo DER or None)"""
    return tlv(0x30, b"".join(tlv(0x30, oid_tlv(o) + (info or b"")) for o, info in statements))


def extension(oid: str, value: bytes, critical=False) -> bytes:
    return tlv(0x30, oid_tlv(oid) + (tlv(0x01, b"\xff") if critical else b"") + tlv(0x04, value))


def resign_with_extensions(token_or_resp: bytes, exts, signer_crt, signer_key, certfile, workdir, key_id=False) -> bytes:
    """the TSTInfo of `token_or_resp` with `exts` (DER Extension TLVs) as its [1] extensions, signed again by openssl cms
    with the given TSA certificate and key (ESS signingCertificateV2 by -cades); a granted TimeStampResp"""
    import subprocess
    tok = T._token_of(bytes(token_or_resp))
    ci = T._der_items(T._der_one(tok, "ContentInfo", 0x30), "ContentInfo")
    sd = T._der_items(T._der_one(ci[1][1], "SignedData", 0x30), "SignedData")
    eci = T._der_items(sd[2][1], "encapContentInfo")
    tst = T._der_items(T._der_one(T._der_one(eci[1][1], "eContent", 0x04), "TSTInfo", 0x30), "TSTInfo")
    tst = [x for x in tst if x[0] != 0xA1]
    if exts:
        tst.append((0xA1, b"".join(exts)))
    j = lambda n: os.path.join(workdir, n)  # noqa: E731
    with open(j("tst.der"), "wb") as f:
        f.write(tlv(0x30, b"".join(tlv(t, v) for t, v in tst)))
    subprocess.run(["openssl", "cms", "-sign", "-binary", "-nodetach", "-econtent_type", "1.2.840.113549.1.9.16.1.4",
                    *(["-keyid"] if key_id else []), "-cades", "-md", "sha256", "-nosmimecap", "-signer", signer_crt,
                    "-inkey", signer_key, *(["-certfile", certfile] if certfile != signer_crt else []),
                    "-in", j("tst.der"), "-outform", "DER",
                    "-out", j("qtok.der")], check=True, capture_output=True)
    with open(j("qtok.der"), "rb") as f:
        new_tok = f.read()
    return tlv(0x30, tlv(0x30, tlv(0x02, b"\x00")) + new_tok)


def statement_ext() -> bytes:
    return extension(OID_QC, qc_value((OID_QTST, None)))


def _read(name):
    with open(os.path.join(VEC, name), "rb") as f:
        return f.read()


def _signer_sha256(pem_name):
    return hashlib.sha256(T._first_pem_der(_read(pem_name))).hexdigest()


class RealTokens(unittest.TestCase):
    """tokens requested on 2026-11-17 from public TSA endpoints (manifest.json gives the source and the time)"""

    def test_the_statement_in_real_tokens(self):
        for name in REAL_QUALIFIED:
            self.assertIsNone(L.qualified_statement_problem(_read(f"{name}.tsr")), name)
        for name in REAL_WITHOUT:
            self.assertEqual(L.qualified_statement_problem(_read(f"{name}.tsr")), "qualified_statement_missing", name)
        self.assertEqual(L.qualified_statement_problem(_read(f"{REAL_NOT_DER}.tsr")), "qualified_statement_malformed")
        with self.assertRaises(T.TokenError) as e:
            T.parse_token(_read(f"{REAL_NOT_DER}.tsr"))
        self.assertEqual(e.exception.reason, "malformed")

    @unittest.skipUnless(shutil.which("openssl"), "needs openssl")
    def test_qualification_of_real_tokens(self):
        """the signer looked up in a list given here (the four are not asserted to be in the EU lists)"""
        digest = hashlib.sha256(_read("data.txt")).digest()
        for name in REAL_QUALIFIED + REAL_WITHOUT:
            tok = _read(f"{name}.tsr")
            listed = {_signer_sha256(f"{name}.signer.pem")}
            want = ("qualified", None) if name in REAL_QUALIFIED else ("not_qualified", "qualified_statement_missing")
            self.assertEqual(L.qualification(tok, listed, {}), want, name)
            self.assertEqual(L.qualification(tok, {"ab" * 32}, {}), ("not_qualified", None), name)   # not listed
            v = T.verify_token(tok, digest, "sha256", [os.path.join(VEC, f"{name}.signer.pem")])
            self.assertEqual(v["status"], "verified", (name, v))   # the verdict of §11 does not depend on the statement
        tok, signer = _read(f"{REAL_NOT_DER}.tsr"), _signer_sha256(f"{REAL_NOT_DER}.signer.pem")
        self.assertEqual(L.qualification(tok, {signer}, {}, signer_sha256=signer), ("not_qualified", "qualified_statement_malformed"))
        v = T.verify_token(tok, digest, "sha256", [os.path.join(VEC, f"{REAL_NOT_DER}.signer.pem")])
        self.assertEqual((v["status"], v["reason"]), ("invalid", "malformed"), v)

    def test_manifest_lists_them(self):
        with open(os.path.join(VEC, "manifest.json"), encoding="utf-8") as f:
            files = {v["file"] for v in json.load(f)["vectors"]}
        for name in REAL_QUALIFIED + (REAL_NOT_DER,):
            self.assertIn(f"{name}.tsr", files)


@unittest.skipUnless(shutil.which("openssl"), "needs openssl")
class Generated(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from test_tsa_revocation_20261116 import Lab, DIGEST
        cls.td = tempfile.mkdtemp()
        cls.lab, cls.digest = Lab(cls.td), DIGEST
        cls.base = cls.lab.token()
        with open(cls.lab.j("tsa.crt"), "rb") as f:
            cls.signer = hashlib.sha256(T._first_pem_der(f.read())).hexdigest()

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.td)

    def make(self, exts, key_id=False):
        lab = self.lab
        return resign_with_extensions(self.base, exts, lab.j("tsa.crt"), lab.j("tsa.key"), lab.j("ca.crt"), self.td, key_id)

    def cases(self):
        info = tlv(0x30, oid_tlv("1.2.3"))
        return [
            ("statement", [statement_ext()], None),
            ("statement_and_another", [extension(OID_QC, qc_value((OID_QCS_COMPLIANCE, None), (OID_QTST, None)))], None),
            ("statement_and_other_extension", [extension("1.2.3.4", b"\x05\x00"), statement_ext()], None),
            ("no_extensions", [], "qualified_statement_missing"),
            ("other_extension_only", [extension("1.2.3.4", b"\x05\x00")], "qualified_statement_missing"),
            ("qc_without_the_statement", [extension(OID_QC, qc_value((OID_QCS_COMPLIANCE, None)))], "qualified_statement_missing"),
            ("qc_empty", [extension(OID_QC, qc_value())], "qualified_statement_missing"),
            ("qc_twice", [statement_ext(), statement_ext()], "qualified_statement_malformed"),
            ("statement_twice", [extension(OID_QC, qc_value((OID_QTST, None), (OID_QTST, None)))], "qualified_statement_malformed"),
            ("statement_with_info", [extension(OID_QC, qc_value((OID_QTST, info)))], "qualified_statement_malformed"),
            ("value_not_der", [extension(OID_QC, b"\x30\x05\x30\x03\x06")], "qualified_statement_malformed"),
            ("value_not_sequence", [extension(OID_QC, tlv(0x31, tlv(0x30, oid_tlv(OID_QTST))))], "qualified_statement_malformed"),
            ("statement_not_sequence", [extension(OID_QC, tlv(0x30, oid_tlv(OID_QTST)))], "qualified_statement_malformed"),
            ("statement_id_not_oid", [extension(OID_QC, tlv(0x30, tlv(0x30, tlv(0x04, b"x"))))], "qualified_statement_malformed"),
            ("statement_in_a_set", [extension(OID_QC, tlv(0x30, tlv(0x31, oid_tlv(OID_QTST))))], "qualified_statement_malformed"),
            ("other_statement_three_elements", [extension(OID_QC, tlv(0x30, tlv(0x30, oid_tlv(OID_QCS_COMPLIANCE) + info + info)
                                                                        + tlv(0x30, oid_tlv(OID_QTST))))], "qualified_statement_malformed"),
            ("statement_three_elements", [extension(OID_QC, tlv(0x30, tlv(0x30, oid_tlv(OID_QTST) + info + info)))],
             "qualified_statement_malformed"),
        ]

    def test_cases_in_both_forms(self):
        pins = [self.lab.j("ca.crt")]
        for key_id in (False, True):
            for name, exts, why in self.cases():
                tok = self.make(exts, key_id)
                v = T.verify_token(tok, self.digest, "sha256", pins)
                self.assertEqual((v["status"], v["reason"]), ("verified", None), (name, key_id, v))   # verdict unchanged
                self.assertEqual(L.qualified_statement_problem(tok), why, (name, key_id))
                want = ("qualified", None) if why is None else ("not_qualified", why)
                self.assertEqual(L.qualification(tok, {self.signer}, {}), want, (name, key_id))
                self.assertEqual(L.qualification(tok, {self.signer}, {}, signer_sha256=self.signer), want, (name, key_id))
                self.assertEqual(L.qualification(tok, {"ab" * 32}, {}), ("not_qualified", None), (name, key_id))

    def test_critical_statement_is_refused_at_step_3(self):
        tok = self.make([extension(OID_QC, qc_value((OID_QTST, None)), critical=True)])
        v = T.verify_token(tok, self.digest, "sha256", [self.lab.j("ca.crt")])
        self.assertEqual((v["status"], v["reason"]), ("invalid", "tstinfo_unknown_element"), v)
        self.assertEqual(L.qualified_statement_problem(tok), "qualified_statement_malformed")
        self.assertEqual(L.qualification(tok, {self.signer}, {}, signer_sha256=self.signer),
                         ("not_qualified", "qualified_statement_malformed"))
        self.assertEqual(L.qualification(tok, {self.signer}, {}), ("not_qualified", None))   # signer not established

    def test_history_error_stays_indeterminate(self):
        tok = self.make([])
        self.assertEqual(L.qualification(tok, set(), {self.signer: "history_not_ordered x"}),
                         ("indeterminate", "history_not_ordered x"))

    def test_parse_token_returns_the_extensions(self):
        tok = self.make([extension("1.2.3.4", b"\x05\x00"), statement_ext()])
        exts = T.parse_token(tok)["extensions"]
        self.assertEqual([(o, c) for o, c, _v in exts], [("1.2.3.4", False), (OID_QC, False)])
        self.assertEqual(exts[1][2], qc_value((OID_QTST, None)))
        self.assertEqual(T.parse_token(self.base)["extensions"], [])

    def test_lotl_command_reports_the_reason(self):
        import io
        from contextlib import redirect_stdout
        from unittest import mock
        for exts, want in (([], {"qualified": False, "not_qualified_reason": "qualified_statement_missing"}),
                           ([statement_ext()], {"qualified": True})):
            tok = self.make(exts)
            buf = io.StringIO()
            with mock.patch.object(L, "load_qualified_status", return_value=({self.signer}, ["ES"], {})), \
                    redirect_stdout(buf):
                try:
                    rc = L.main([base64.b64encode(tok).decode()])
                except SystemExit as e:
                    rc = e.code
            out = json.loads(buf.getvalue()[buf.getvalue().index("{"):])
            self.assertEqual({k: out.get(k) for k in want}, want, out)
            self.assertNotIn("indeterminate", out)
            self.assertEqual(rc, 0 if want["qualified"] else 1)


if __name__ == "__main__":
    unittest.main()
