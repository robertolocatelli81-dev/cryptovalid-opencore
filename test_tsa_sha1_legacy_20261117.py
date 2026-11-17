#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""SPEC v0.10 §11 step 7 (17/11/2026): a certificate of the TSA chain signed with SHA-1 is legacy verification.

NIST SP 800-131A Rev. 2 (§9 Table 8) disallows SHA-1 for generating signatures and allows it for verifying them as
legacy use. The verdict does not change (OpenSSL 3.0.22 accepts such a chain); the outcome reports it in the closed
member `sha1_signature_legacy`: None unless step 7 passed, then True or False. Every case in both forms of `sid`
(issuerAndSerialNumber: a token of `openssl ts -reply`; subjectKeyIdentifier: the same TSTInfo re-signed by `openssl
cms -sign -keyid`). Positive control: on the code before this change the outcome has no such member: 13 of the 14
tests fail (the fourteenth, test_signature_algorithms_as_made, checks the bench itself)."""
import base64
import os
import shutil
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True
ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)
import cryptovalid_tsa as T  # noqa: E402
import test_tsa_signer_key_id_20261116 as K  # noqa: E402


def reissue_tsa(lab, md):
    """the TSA certificate issued again by the lab's CA, same key and name, signed with `md`"""
    j = lab.j
    K._run("openssl", "x509", "-req", "-in", j("tsa.csr"), "-CA", j("ca.crt"), "-CAkey", j("ca.key"), "-CAcreateserial",
           f"-{md}", "-out", j("tsa.crt"), "-days", "2", "-extfile", j("ext.cnf"), "-extensions", "v3_tsa")


def self_sign_ca(lab, md, name):
    """the lab's CA certificate made again, same key and name, self-signed with `md`"""
    j = lab.j
    K._run("openssl", "req", "-x509", "-new", "-key", j("ca.key"), f"-{md}", "-subj", f"/CN={name}-ca", "-days", "2",
           "-config", j("req.cnf"), "-extensions", "v3_ca", "-out", j("ca.crt"))


def pem(path):
    with open(path, "rb") as f:
        return f.read()


@K.NEEDS
class Sha1Legacy(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.td = tempfile.mkdtemp()
        cls.plain, cls.leaf1, cls.root1 = (K.Lab(cls.td, n) for n in ("p", "l", "r"))
        reissue_tsa(cls.leaf1, "sha1")       # the TSA certificate signed with SHA-1 (ecdsa-with-SHA1)
        self_sign_ca(cls.root1, "sha1", "r")  # only the self-signature of the root uses SHA-1
        cls.toks = {}
        for lab in (cls.plain, cls.leaf1, cls.root1):
            tok = lab.token()
            cls.toks[lab] = {"issuer_serial": tok, "key_id": lab.resign(tok)}

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.td)

    def outcomes(self, lab, pins=None):
        pins = [lab.j("ca.crt")] if pins is None else pins
        return {form: T.verify_token(tok, K.DIGEST, "sha256", pins) for form, tok in self.toks[lab].items()}

    def test_signature_algorithms_as_made(self):
        """the control of the bench: the certificates carry the algorithms these tests claim"""
        alg = lambda p: K._run("openssl", "x509", "-in", p, "-noout", "-text").stdout.decode()  # noqa: E731
        self.assertIn("ecdsa-with-SHA1", alg(self.leaf1.j("tsa.crt")))
        self.assertIn("ecdsa-with-SHA256", alg(self.plain.j("tsa.crt")))
        self.assertIn("ecdsa-with-SHA1", alg(self.root1.j("ca.crt")))
        self.assertIn("ecdsa-with-SHA256", alg(self.root1.j("tsa.crt")))

    def test_sha256_chain_is_false(self):
        for form, v in self.outcomes(self.plain).items():
            self.assertEqual((v["status"], v["sha1_signature_legacy"]), ("verified", False), (form, v))

    def test_sha1_tsa_certificate_is_verified_and_reported(self):
        for pins in ([self.leaf1.j("ca.crt")], [self.leaf1.j("tsa.crt")], [self.leaf1.j("tsa.crt"), self.leaf1.j("ca.crt")]):
            for form, v in self.outcomes(self.leaf1, pins).items():
                self.assertEqual((v["status"], v["counts_as_timestamp"], v["reason"], v["sha1_signature_legacy"]),
                                 ("verified", True, None, True), (form, pins, v))

    def test_sha1_self_signature_of_the_root_is_not_reported(self):
        """OpenSSL does not check the self-signature of a trust anchor: a self-issued certificate is not read"""
        for form, v in self.outcomes(self.root1).items():
            self.assertEqual((v["status"], v["sha1_signature_legacy"]), ("verified", False), (form, v))

    def test_null_unless_step_7_passed(self):
        for form, v in self.outcomes(self.leaf1, [self.plain.j("ca.crt")]).items():   # another TSA's pin
            self.assertEqual((v["reason"], v["sha1_signature_legacy"]), ("not_issued_by_pinned_tsa", None), (form, v))
        for form, tok in self.toks[self.leaf1].items():
            v = T.verify_token(tok, K.DIGEST, "sha256")                                 # nothing pinned
            self.assertEqual((v["status"], v["sha1_signature_legacy"]), ("signature_only", None), (form, v))
            v = T.verify_token(tok, b"\0" * 32, "sha256", [self.leaf1.j("ca.crt")])    # another digest
            self.assertEqual((v["reason"], v["sha1_signature_legacy"]), ("imprint_mismatch", None), (form, v))

    def test_two_certificates_with_the_issuer_name(self):
        """the path is read by names: a pinned SHA-1 certificate with the CA's name makes it True (more, never less)"""
        lab = self.plain
        other = os.path.join(self.td, "other_ca.crt")
        K._run("openssl", "req", "-new", "-key", lab.j("ca.key"), "-subj", "/CN=p-ca", "-config", lab.j("req.cnf"),
               "-out", os.path.join(self.td, "other_ca.csr"))
        K._run("openssl", "x509", "-req", "-in", os.path.join(self.td, "other_ca.csr"), "-CA", self.root1.j("ca.crt"),
               "-CAkey", self.root1.j("ca.key"), "-CAcreateserial", "-sha1", "-days", "2", "-extfile",
               lab.j("ext.cnf"), "-extensions", "v3_ca", "-out", other)
        for form, v in self.outcomes(lab, [lab.j("ca.crt"), other]).items():
            self.assertEqual((v["status"], v["sha1_signature_legacy"]), ("verified", True), (form, v))

    def test_same_names_two_signature_algorithms(self):
        """two certificates with the same issuer and subject, one signed with SHA-256 and one with SHA-1: both are read"""
        lab = self.plain
        made = []
        for md in ("sha1", "sha256"):
            out = os.path.join(self.td, f"twin_{md}.crt")
            K._run("openssl", "req", "-new", "-key", lab.j("ca.key"), "-subj", "/CN=p-ca", "-config", lab.j("req.cnf"),
                   "-out", os.path.join(self.td, "twin.csr"))
            K._run("openssl", "x509", "-req", "-in", os.path.join(self.td, "twin.csr"), "-CA", self.root1.j("ca.crt"),
                   "-CAkey", self.root1.j("ca.key"), "-CAcreateserial", f"-{md}", "-days", "2", "-extfile",
                   lab.j("ext.cnf"), "-extensions", "v3_ca", "-out", out)
            made.append(out)
        for pins in ([lab.j("ca.crt"), *made], [lab.j("ca.crt"), *made[::-1]]):
            for form, v in self.outcomes(lab, pins).items():
                self.assertEqual((v["status"], v["sha1_signature_legacy"]), ("verified", True), (form, pins, v))

    def test_sha1_intermediate_only_in_the_token(self):
        """the token's certificates are read: a CA certificate the token carries, signed with SHA-1 by the pinned root"""
        lab = K.Lab(self.td, "i")
        j = lab.j
        K._run("openssl", "req", "-new", "-key", j("ca.key"), "-subj", "/CN=i-ca", "-config", j("req.cnf"),
               "-out", j("ca.csr"))
        K._run("openssl", "x509", "-req", "-in", j("ca.csr"), "-CA", self.plain.j("ca.crt"), "-CAkey",
               self.plain.j("ca.key"), "-CAcreateserial", "-sha1", "-days", "2", "-extfile", j("ext.cnf"),
               "-extensions", "v3_ca", "-out", j("ca.crt"))
        tok = lab.token()
        for form, t in (("issuer_serial", tok), ("key_id", lab.resign(tok))):
            v = T.verify_token(t, K.DIGEST, "sha256", [self.plain.j("ca.crt")])
            self.assertEqual((v["status"], v["sha1_signature_legacy"]), ("verified", True), (form, v))

    def test_a_cycle_of_names_ends(self):
        """two cross certificates that name each other as issuer (p-ca by c-b, c-b by p-ca): the path ends, both read"""
        lab = self.plain
        j = lambda n: os.path.join(self.td, n)  # noqa: E731
        K._run("openssl", "req", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-keyout", j("cb.key"),
               "-out", j("cb.csr"), "-subj", "/CN=c-b", "-config", lab.j("req.cnf"))
        K._run("openssl", "req", "-x509", "-new", "-key", j("cb.key"), "-subj", "/CN=c-b", "-days", "2",
               "-config", lab.j("req.cnf"), "-extensions", "v3_ca", "-out", j("cb_self.crt"))
        K._run("openssl", "req", "-new", "-key", lab.j("ca.key"), "-subj", "/CN=p-ca", "-config", lab.j("req.cnf"),
               "-out", j("pa.csr"))
        K._run("openssl", "x509", "-req", "-in", j("pa.csr"), "-CA", j("cb_self.crt"), "-CAkey", j("cb.key"),
               "-CAcreateserial", "-sha256", "-days", "2", "-extfile", lab.j("ext.cnf"), "-extensions", "v3_ca",
               "-out", j("pa_by_cb.crt"))
        K._run("openssl", "x509", "-req", "-in", j("cb.csr"), "-CA", lab.j("ca.crt"), "-CAkey", lab.j("ca.key"),
               "-CAcreateserial", "-sha1", "-days", "2", "-extfile", lab.j("ext.cnf"), "-extensions", "v3_ca",
               "-out", j("cb_by_pa.crt"))
        signer = T._first_pem_der(pem(lab.j("tsa.crt")))
        tok = T.parse_token(self.toks[lab]["issuer_serial"])["token_der"]
        self.assertTrue(T.sha1_signature_legacy(signer, pem(j("pa_by_cb.crt")) + pem(j("cb_by_pa.crt")), tok))
        self.assertFalse(T.sha1_signature_legacy(signer, pem(j("pa_by_cb.crt")), tok))

    def test_the_pack_reports_it(self):
        """SPEC §10: the pack's tsa_check carries the member of §11 (the beacon window copies it, test_beacon)"""
        import evidence_pack as E
        for lab, want in ((self.leaf1, True), (self.plain, False)):
            for form, tok in self.toks[lab].items():
                state, check = E._pinned_time_anchor(base64.b64encode(tok).decode(), K.DIGEST.hex(), [lab.j("ca.crt")])
                self.assertEqual((state, check["sha1_signature_legacy"]), (("verified", None), want), (form, check))
        state, check = E._pinned_time_anchor(base64.b64encode(self.toks[self.leaf1]["key_id"]).decode(), K.DIGEST.hex(),
                                             [self.plain.j("ca.crt")])
        self.assertEqual((state[1], check["sha1_signature_legacy"]), ("tsa_unresolved", None), check)

    def test_signer_read_again_must_be_the_same(self):
        """issuerAndSerialNumber form: the signer certificate is read again for the flag; another one gives None"""
        from unittest import mock
        tok = self.toks[self.leaf1]["issuer_serial"]
        with mock.patch.object(T, "token_signer", return_value=("valid", "00" * 32, None)):
            v = T.verify_token(tok, K.DIGEST, "sha256", [self.leaf1.j("ca.crt")])
        self.assertEqual((v["status"], v["sha1_signature_legacy"]), ("verified", None), v)

    def test_unreadable_certificate_gives_null(self):
        signer = T._first_pem_der(pem(self.plain.j("tsa.crt")))
        junk = b"-----BEGIN CERTIFICATE-----\n" + base64.encodebytes(b"\x30\x03\x02\x01\x01") + b"-----END CERTIFICATE-----\n"
        tok = T.parse_token(self.toks[self.plain]["issuer_serial"])["token_der"]
        self.assertFalse(T.sha1_signature_legacy(signer, pem(self.plain.j("ca.crt")), tok))
        self.assertIsNone(T.sha1_signature_legacy(signer, pem(self.plain.j("ca.crt")) + junk, tok))
        self.assertIsNone(T.sha1_signature_legacy(b"\x30\x00", pem(self.plain.j("ca.crt")), tok))
        cert = T._der_items(T._der_one(signer, "certificate", 0x30), "certificate")   # signature: OCTET STRING
        bad = T._tlv_bytes(0x30, T._tlv_bytes(*cert[0]) + T._tlv_bytes(*cert[1]) + T._tlv_bytes(0x04, cert[2][1]))
        self.assertIsNone(T.sha1_signature_legacy(bad, pem(self.plain.j("ca.crt")), tok))
        four = T._tlv_bytes(0x30, b"".join(T._tlv_bytes(*c) for c in cert) + T._tlv_bytes(0x05, b""))  # a 4th element
        self.assertIsNone(T.sha1_signature_legacy(four, pem(self.plain.j("ca.crt")), tok))
        tbs = T._der_items(cert[0][1], "tbsCertificate")                              # issuer: a SET, not a Name
        k = 1 if tbs[0][0] == 0xA0 else 0
        tbs[k + 2] = (0x31, tbs[k + 2][1])
        wrong = T._tlv_bytes(0x30, T._tlv_bytes(0x30, b"".join(T._tlv_bytes(*x) for x in tbs))
                             + T._tlv_bytes(*cert[1]) + T._tlv_bytes(*cert[2]))
        self.assertIsNone(T.sha1_signature_legacy(wrong, pem(self.plain.j("ca.crt")), tok))

    def test_rsa_pss_hash_algorithm(self):
        """RFC 4055 §3.1: RSASSA-PSS whose hashAlgorithm is SHA-1, or absent (its default), is SHA-1"""
        d = os.path.join(self.td, "pss")
        os.makedirs(d)
        j = lambda n: os.path.join(d, n)  # noqa: E731
        K._run("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", j("ca.key"), "-out", j("ca.crt"),
               "-subj", "/CN=pss-ca", "-days", "2")
        K._run("openssl", "req", "-newkey", "rsa:2048", "-nodes", "-keyout", j("l.key"), "-out", j("l.csr"),
               "-subj", "/CN=pss-leaf")
        got = {}
        for md in ("sha1", "sha256"):
            K._run("openssl", "x509", "-req", "-in", j("l.csr"), "-CA", j("ca.crt"), "-CAkey", j("ca.key"),
                   "-CAcreateserial", f"-{md}", "-sigopt", "rsa_padding_mode:pss", "-days", "2", "-out", j(f"{md}.crt"))
            text = K._run("openssl", "x509", "-in", j(f"{md}.crt"), "-noout", "-text").stdout.decode()
            self.assertIn("rsassaPss", text)
            got[md] = T._cert_sig_names(T._first_pem_der(pem(j(f"{md}.crt"))))[0]
        self.assertEqual(got, {"sha1": True, "sha256": False})
        # hashAlgorithm absent: the DEFAULT sha1 of RFC 4055 (the parameters made empty by hand)
        der = T._first_pem_der(pem(j("sha256.crt")))
        cert = T._der_items(T._der_one(der, "certificate", 0x30), "certificate")
        alg = T._tlv_bytes(0x30, T._tlv_bytes(0x06, bytes.fromhex("2a864886f70d01010a")) + T._tlv_bytes(0x30, b""))
        made = T._tlv_bytes(0x30, T._tlv_bytes(*cert[0]) + alg + T._tlv_bytes(*cert[2]))
        self.assertTrue(T._cert_sig_names(made)[0])
        for params in (b"", T._tlv_bytes(0x05, b""), T._tlv_bytes(0x04, T._tlv_bytes(0xA0, b""))):   # absent, NULL,
            alg = T._tlv_bytes(0x30, T._tlv_bytes(0x06, bytes.fromhex("2a864886f70d01010a")) + params)  # not a SEQUENCE
            made = T._tlv_bytes(0x30, T._tlv_bytes(*cert[0]) + alg + T._tlv_bytes(*cert[2]))
            with self.assertRaises(T.TokenError):                                   # RFC 4055 §3.1: MUST be present
                T._cert_sig_names(made)
            self.assertIsNone(T.sha1_signature_legacy(made, b"", T.parse_token(self.toks[self.plain]["issuer_serial"])["token_der"]))

    def test_other_signature_oids(self):
        """the closed list of SPEC §11 step 7, each OID with an empty certificate around it"""
        der = T._first_pem_der(pem(self.plain.j("tsa.crt")))
        cert = T._der_items(T._der_one(der, "certificate", 0x30), "certificate")
        for oid, want in (("1.2.840.113549.1.1.5", True), ("1.3.14.3.2.29", True), ("1.2.840.10045.4.1", True),
                          ("1.2.840.10040.4.3", True), ("1.3.14.3.2.27", True), ("1.2.840.113549.1.1.11", False),
                          ("1.2.840.10045.4.3.2", False), ("1.3.101.112", False), ("1.2.840.113549.1.1.4", False)):
            parts = [int(x) for x in oid.split(".")]
            body = bytes([40 * parts[0] + parts[1]])
            for n in parts[2:]:
                enc = [n & 0x7F]
                while n > 0x7F:
                    n >>= 7
                    enc.insert(0, 0x80 | (n & 0x7F))
                body += bytes(enc)
            made = T._tlv_bytes(0x30, T._tlv_bytes(*cert[0]) + T._tlv_bytes(0x30, T._tlv_bytes(0x06, body))
                                + T._tlv_bytes(*cert[2]))
            self.assertEqual(T._cert_sig_names(made)[0], want, oid)


if __name__ == "__main__":
    unittest.main()
