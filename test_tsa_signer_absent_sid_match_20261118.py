#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""SPEC v0.11 §11 step 6, the two rules of `_signer_certificate_absent` that no other test reached (review of
18/11/2026, mutation testing of the added lines: both mutants survived the suite).

1. issuerAndSerialNumber is matched on the issuer AND the serial number: a certificate in the token with the signer's
   serial number under another issuer is not the signer, so the token is `signer_certificate_absent` (a match on the
   serial alone answered `signature_invalid`).
2. "Another CertificateChoices keeps signature_invalid": a token whose `certificates` holds an `other` [3]
   OtherCertificateFormat (RFC 5652 §10.2.2), not read here, is never presumed to lack its signer.

Positive control, measured: with `_name_canon(...) == want_issuer` replaced by `True` test 1 fails; with the
`return False` of another CertificateChoices replaced by `continue` test 2 fails."""
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

NEEDS = unittest.skipUnless(shutil.which("openssl"), "needs openssl")


def tlv(tag, v):
    return T._tlv_bytes(tag, v)


def with_certs(tok, certs_value):
    """the token with SignedData's [0] certificates replaced by `certs_value` (the bytes inside [0])"""
    ci = T._der_items(T._der_one(tok, "ContentInfo", 0x30), "ContentInfo")
    sd = T._der_items(T._der_one(ci[1][1], "SignedData", 0x30), "SignedData")
    out, done = [], False
    for t, v in sd:
        if t == 0xA0:
            continue
        if t == 0x31 and not done and out and out[-1][0] == 0x30:   # after encapContentInfo: certificates go here
            out.append((0xA0, certs_value))
            done = True
        out.append((t, v))
    assert done
    body = b"".join(tlv(t, v) for t, v in out)
    return tlv(0x30, tlv(*ci[0]) + tlv(0xA0, tlv(0x30, body)))


def run(*cmd, cwd=None):
    return subprocess.run(cmd, check=True, capture_output=True, cwd=cwd)


@NEEDS
class SignerMatch(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import test_tsa_signer_key_id_20261116 as K
        cls.K = K
        cls.td = tempfile.mkdtemp()
        cls.lab = K.Lab(cls.td, "a")
        cls.tok = cls.lab.token()
        j = cls.lab.j
        serial = run("openssl", "x509", "-in", j("tsa.crt"), "-noout", "-serial").stdout.decode().strip().split("=")[1]
        # another CA, and a certificate it issues with the serial number of lab a's TSA certificate
        cls.other = K.Lab(cls.td, "b")
        o = cls.other.j
        run("openssl", "x509", "-req", "-in", o("tsa.csr"), "-CA", o("ca.crt"), "-CAkey", o("ca.key"), "-set_serial",
            "0x" + serial, "-out", o("same_serial.crt"), "-days", "2", "-extfile", o("ext.cnf"), "-extensions", "v3_tsa")
        cls.same_serial_der = run("openssl", "x509", "-in", o("same_serial.crt"), "-outform", "DER").stdout
        assert run("openssl", "x509", "-in", o("same_serial.crt"), "-noout", "-serial").stdout.decode().strip() == \
            "serial=" + serial

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.td)

    def test_same_serial_other_issuer_is_absent(self):
        tok = with_certs(self.tok, self.same_serial_der)
        r = T.verify_token(tok, self.K.DIGEST, "sha256", None)
        self.assertEqual((r["status"], r["reason"]), ("invalid", "signer_certificate_absent"), r)
        # control: with its own certificate the same token is signature_only
        r = T.verify_token(self.tok, self.K.DIGEST, "sha256", None)
        self.assertEqual(r["status"], "signature_only", r)

    def test_other_certificate_choice_is_not_presumed_absent(self):
        other = tlv(0xA3, tlv(0x06, b"\x2a\x03") + tlv(0x05, b""))   # [3] OtherCertificateFormat {1.2.3, NULL}
        tok = with_certs(self.tok, other)
        p = subprocess.run(["openssl", "cms", "-verify", "-noverify", "-binary", "-inform", "DER", "-out", os.devnull],
                           input=tok, capture_output=True)
        self.assertIn(b"signer certificate not found", p.stderr)   # openssl reads it and stops at the lookup
        r = T.verify_token(tok, self.K.DIGEST, "sha256", None)
        self.assertEqual((r["status"], r["reason"]), ("invalid", "signature_invalid"), r)


if __name__ == "__main__":
    unittest.main(verbosity=2)
