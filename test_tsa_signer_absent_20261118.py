#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""SPEC v0.11 §11 step 6 (18/11/2026): a token whose signer certificate is neither in the token nor pinned.

Until 0.26.0 `verify_token` answered `invalid / signature_invalid` for it ("signer certificate not found": openssl never
evaluated the signature), with or without a pin of another TSA; the pack with such a pin said `contradicted /
token_invalid`. Measured on 2026-11-18 with the published wheel 0.26.0 on the RFC 3161 token of a sigstore bundle
(stacklok/toolhive 0.66.0, `[0] certificates` present and empty) and on the vectors below with their certificates
removed. Now the reason is `signer_certificate_absent` (status `invalid`: it does not count as a timestamp) and the pack
says `not_evaluated / tsa_unresolved`. ETSI EN 319 102-1 V1.4.1 §5.2.3.3: INDETERMINATE / NO_SIGNING_CERTIFICATE_FOUND.

Generative: every vector of spec/vectors/rfc3161 with its signer certificate file x {certificates kept, removed} x
{no pin, its own signer pinned, another TSA pinned} x {intact, signature altered}, and the same over tokens named by
subjectKeyIdentifier made with openssl on this machine. The absence is never presumed: an unreadable pin or certificate
keeps `signature_invalid`."""
import base64
import hashlib
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
from test_platforms_20261124 import cnf_path  # noqa: E402
import cryptovalid_tsa as T  # noqa: E402

NEEDS = unittest.skipUnless(shutil.which("openssl"), "needs openssl")
V = os.path.join(ROOT, "spec", "vectors", "rfc3161")
# measured on 2026-11-18, the same with 0.26.0: sectigo's token was refused at step 7 whenever its CA "Sectigo Public
# Time Stamping CA R41" was pinned (openssl ts -verify asks each of its 3 ESSCertIDs to be in the chain, which stops at
# R41); since SPEC v0.11 step 7 (test_tsa_ess_cert_ids_20261118.py) it is `verified`, and no vector is refused here
STEP7_REFUSES_CHAIN = set()
VECTORS = ["freetsa", "digicert", "sectigo", "globalsign", "bosa_qualified", "izenpe_qualified", "accv_qualified"]


def tlv(tag, v):
    return T._tlv_bytes(tag, v)


def strip_certs(tok):
    """the same token without SignedData's [0] certificates, as a token requested with certReq FALSE"""
    ci = T._der_items(T._der_one(tok, "ContentInfo", 0x30), "ContentInfo")
    sd = T._der_items(T._der_one(ci[1][1], "SignedData", 0x30), "SignedData")
    assert any(t == 0xA0 for t, _ in sd[3:-1])
    body = b"".join(tlv(t, v) for t, v in sd if t != 0xA0)
    return tlv(0x30, tlv(*ci[0]) + tlv(0xA0, tlv(0x30, body)))


def alter_signature(tok):
    """the SignerInfo's signature value with one bit flipped"""
    sig = [v for t, v in T._signer_info(tok)[0] if t == 0x04][-1]
    assert tok.count(sig) == 1
    i = tok.index(sig) + len(sig) // 2
    return tok[:i] + bytes([tok[i] ^ 1]) + tok[i + 1:]


def pem(path):
    with open(path, "rb") as f:
        return f.read()


def outcome(tok, digest, pins):
    r = T.verify_token(tok, digest, None, pins)
    return r["status"], r["reason"]


def expected(kept, pin, intact):
    """the rule of SPEC v0.11 §11 steps 6-7 for these cases"""
    if pin == "own":
        return ("verified", None) if intact else ("invalid", "signature_invalid")
    if not kept:
        return ("invalid", "signer_certificate_absent")
    if not intact:
        return ("invalid", "signature_invalid")
    return ("signature_only", None) if pin is None else ("invalid", "not_issued_by_pinned_tsa")


@NEEDS
class SignerAbsentVectors(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with open(os.path.join(V, "manifest.json")) as f:
            cls.digest = bytes.fromhex(json.load(f)["digest_sha256"])

    def tok(self, name):
        with open(os.path.join(V, name + ".tsr"), "rb") as f:
            return T.parse_token(f.read())["token_der"]

    def chain(self, name):
        """the signer certificate file and the CAs the original token carries, as PEM (a pinned leaf alone does not end
        the chain, SPEC §11 step 7, and the stripped token no longer carries the CAs)"""
        return pem(os.path.join(V, name + ".signer.pem")) + b"".join(
            b"-----BEGIN CERTIFICATE-----\n" + base64.encodebytes(d) + b"-----END CERTIFICATE-----\n"
            for d in T._token_certificates(self.tok(name))[1:])

    def test_generative_over_the_vectors(self):
        n = 0
        for i, name in enumerate(VECTORS):
            other = VECTORS[(i + 1) % len(VECTORS)]
            for kept in (True, False):
                for pin in (None, "own", "other"):
                    for intact in (True, False):
                        tok = self.tok(name) if kept else strip_certs(self.tok(name))
                        tok = tok if intact else alter_signature(tok)
                        pins = None if pin is None else [self.chain(name if pin == "own" else other)]
                        want = expected(kept, pin, intact)
                        if name in STEP7_REFUSES_CHAIN and pin == "own" and intact:
                            want = ("invalid", "not_issued_by_pinned_tsa")   # step 6 passed; step 7, as in 0.26.0
                        with self.subTest(name=name, kept=kept, pin=pin, intact=intact):
                            self.assertEqual(outcome(tok, self.digest, pins), want)
                            self.assertEqual(T._signer_certificate_absent(tok, pins and T._pem_certs(pins)),
                                             not kept and pin != "own")   # the lookup alone, without openssl
                        n += 1
        self.assertEqual(n, len(VECTORS) * 12)

    def test_certificates_field_shapes(self):
        """[0] certificates present and empty (the sigstore token measured), the CAs kept and the signer removed, the
        signer repeated: the reason follows the certificates actually there"""
        tok = self.tok("digicert")
        ci = T._der_items(T._der_one(tok, "ContentInfo", 0x30), "ContentInfo")
        sd = T._der_items(T._der_one(ci[1][1], "SignedData", 0x30), "SignedData")
        certs = T._token_certificates(tok)

        def with_certs(cs):
            body = b"".join(tlv(t, v) if t != 0xA0 else tlv(0xA0, b"".join(cs)) for t, v in sd)
            return tlv(0x30, tlv(*ci[0]) + tlv(0xA0, tlv(0x30, body)))
        signer = [c for c in certs if c == T._first_pem_der(pem(os.path.join(V, "digicert.signer.pem")))]
        self.assertEqual(len(signer), 1)
        others = [c for c in certs if c not in signer]
        cases = {"empty": ([], "signer_certificate_absent"), "cas only": (others, "signer_certificate_absent"),
                 "signer twice": (signer + others + signer, None), "signer last": (others + signer, None)}
        for label, (cs, reason) in cases.items():
            with self.subTest(label):
                self.assertEqual(outcome(with_certs(cs), self.digest, None)[1], reason)

    def test_the_outcome_names_what_was_not_done(self):
        r = T.verify_token(strip_certs(self.tok("freetsa")), self.digest, "sha256")
        self.assertEqual((r["status"], r["counts_as_timestamp"], r["signer_sha256"], r["imprint_ok"]),
                         ("invalid", False, None, True))
        self.assertIn("signature not evaluated", r["detail"])

    def test_imprint_still_comes_first(self):
        r = T.verify_token(strip_certs(self.tok("freetsa")), hashlib.sha256(b"x").digest())
        self.assertEqual(r["reason"], "imprint_mismatch")

    def test_absence_is_never_presumed(self):
        tok = strip_certs(self.tok("freetsa"))
        good = pem(os.path.join(V, "digicert.signer.pem"))
        self.assertTrue(T._signer_certificate_absent(tok, good))
        broken = b"-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"
        self.assertFalse(T._signer_certificate_absent(tok, good + broken))      # a pin not read: not absent
        self.assertFalse(T._signer_certificate_absent(tok, good + b"-----BEGIN CERTIFICATE-----\n!!\n"))
        self.assertFalse(T._signer_certificate_absent(b"\x30\x00"))               # a token not read: not absent
        with self.assertRaises(ValueError):                                       # and verify_token refuses such a pin
            T.verify_token(tok, self.digest, None, [good, broken])

    def test_the_pack_reads_it_as_unresolved(self):
        import evidence_pack as EP
        tok = strip_certs(self.tok("freetsa"))
        b64 = base64.b64encode(tok).decode()
        el, chk = EP._pinned_time_anchor(b64, self.digest.hex(), [os.path.join(V, "digicert.signer.pem")])
        self.assertEqual((el[0], el[1], chk["reason"]), ("not_evaluated", "tsa_unresolved", "signer_certificate_absent"))
        el, _ = EP._pinned_time_anchor(base64.b64encode(alter_signature(self.tok("freetsa"))).decode(), self.digest.hex(),
                                       [os.path.join(V, "freetsa.signer.pem")])
        self.assertEqual(el[:2], ("contradicted", "token_invalid"))                 # a signature that fails stays so
        el, _ = EP._pinned_time_anchor(b64, self.digest.hex(), [self.chain("freetsa")])
        self.assertEqual(el, ("verified", None))


@NEEDS
class SignerAbsentKeyId(unittest.TestCase):
    """tokens whose SignerInfo names the signer by subjectKeyIdentifier (RFC 5652 §5.3), made with openssl here"""

    @classmethod
    def setUpClass(cls):
        try:
            import cryptography  # noqa: F401
        except ImportError:
            raise unittest.SkipTest("the key-id lab needs cryptography")
        import test_tsa_signer_key_id_20261116 as K
        cls.K = K
        cls.td = tempfile.mkdtemp()
        cls.lab, cls.other = K.Lab(cls.td, "a"), K.Lab(cls.td, "b")
        cls.tokens = {"ias": (cls.lab, T.parse_token(cls.lab.token())["token_der"])}
        cls.tokens["ski"] = (cls.lab, T.parse_token(cls.lab.resign(cls.tokens["ias"][1]))["token_der"])
        # a TSA certificate whose subjectKeyIdentifier is a written value, not the SHA-1 of its key: the sid matches the
        # extension only (OpenSSL looks the signer up by the extension)
        ext = K.EXT
        try:
            K.EXT = ext + ("[ v3_tsa_skix ]\nextendedKeyUsage = critical,timeStamping\nbasicConstraints = CA:FALSE\n"
                           "subjectKeyIdentifier = 0102030405060708090a0b0c0d0e0f1011121314\nauthorityKeyIdentifier = keyid\n")
            cls.labx = K.Lab(cls.td, "x", tsa_ext="v3_tsa_skix")
        finally:
            K.EXT = ext
        cls.tokens["ski_written"] = (cls.labx, T.parse_token(cls.labx.resign(T.parse_token(cls.labx.token())["token_der"]))["token_der"])

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.td)

    def test_generative_key_id_and_issuer_serial(self):
        self.assertIn(bytes.fromhex("0102030405060708090a0b0c0d0e0f1011121314"), self.tokens["ski_written"][1])
        for form, (own, base) in self.tokens.items():
            for kept in (True, False):
                for pin in (None, "own", "other"):
                    for intact in (True, False):
                        tok = base if kept else strip_certs(base)
                        tok = tok if intact else alter_signature(tok)
                        lab = own if pin == "own" else self.other
                        pins = None if pin is None else [lab.j("tsa.crt"), lab.j("ca.crt")]
                        with self.subTest(form=form, kept=kept, pin=pin, intact=intact):
                            self.assertEqual(outcome(tok, self.K.DIGEST, pins), expected(kept, pin, intact))
                            self.assertEqual(T._signer_certificate_absent(tok, pins and T._pem_certs(pins)),
                                             not kept and pin != "own")

    def test_same_issuer_other_serial_is_not_the_signer(self):
        """issuerAndSerialNumber needs both: another certificate of the same CA (same issuer, other serial) is not it"""
        own, base = self.tokens["ias"]
        tok = strip_certs(base)
        with open(own.j("plain.crt"), "rb") as f:
            plain = f.read()
        self.assertTrue(T._signer_certificate_absent(tok, plain))
        r = T.verify_token(tok, self.K.DIGEST, None, [own.j("plain.crt")])
        self.assertEqual((r["status"], r["reason"]), ("invalid", "signer_certificate_absent"))
        self.assertIn("nor among the pinned certificates", r["detail"])
        r = T.verify_token(tok, self.K.DIGEST, None)
        self.assertIn("(pin the TSA certificate)", r["detail"])


@NEEDS
class AbsentOnlyWhenOpensslLookedUp(unittest.TestCase):
    """the absence needs two witnesses: no certificate read here is the one the sid names, AND openssl stopped at the
    signer lookup. A token openssl cannot parse (FORMAT_FAILURE) keeps `signature_invalid`, with or without certificates;
    an issuer Name that cannot be read here is not "another issuer" (review of 18/11/2026: both were
    `signer_certificate_absent` in the first version of this change)"""

    def setUp(self):
        self.td = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.td)

    def test_token_openssl_cannot_parse_is_not_absent(self):
        with open(os.path.join(V, "manifest.json")) as f:
            digest = bytes.fromhex(json.load(f)["digest_sha256"])
        with open(os.path.join(V, "freetsa.tsr"), "rb") as f:
            tok = strip_certs(T.parse_token(f.read())["token_der"])
        ci = T._der_items(T._der_one(tok, "ContentInfo", 0x30), "ContentInfo")
        sd = T._der_items(T._der_one(ci[1][1], "SignedData", 0x30), "SignedData")
        algs = T._der_items(sd[1][1], "digestAlgorithms")
        bad_algs = tlv(0x31, b"".join(tlv(0x31 if j == 0 else t, v) for j, (t, v) in enumerate(algs)))
        body = b"".join(bad_algs if j == 1 else tlv(t, v) for j, (t, v) in enumerate(sd))
        bad = tlv(0x30, tlv(*ci[0]) + tlv(0xA0, tlv(0x30, body)))
        T.parse_token(bad)                                    # steps 1-4 read it
        self.assertTrue(T._signer_certificate_absent(bad))    # no certificate at all
        st, _, why = T.token_signer(bad)
        self.assertEqual(st, "invalid")
        self.assertNotIn("signer certificate not found", why)   # openssl did not get to the lookup
        self.assertEqual(outcome(bad, digest, None), ("invalid", "signature_invalid"))
        self.assertEqual(outcome(bad, digest, [os.path.join(V, "digicert.signer.pem")]), ("invalid", "signature_invalid"))

    def test_issuer_name_not_read_is_not_another_issuer(self):
        j = lambda n: os.path.join(self.td, n)  # noqa: E731
        with open(j("req.cnf"), "w") as f:      # BMPString names (B_ASN1_BMPSTRING = 0x800)
            f.write("[ req ]\ndistinguished_name = dn\nstring_mask = MASK:0x800\n[ dn ]\n[ ca ]\n"
                    "basicConstraints = critical,CA:TRUE\nkeyUsage = critical,keyCertSign\nsubjectKeyIdentifier = hash\n"
                    "[ tsa ]\nextendedKeyUsage = critical,timeStamping\nbasicConstraints = CA:FALSE\n")
        run = lambda *c: subprocess.run(c, check=True, capture_output=True)  # noqa: E731
        ec = ("-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes")
        run("openssl", "req", "-x509", *ec, "-keyout", j("ca.key"), "-out", j("ca.crt"), "-subj", "/CN=QQ", "-days", "2",
            "-config", j("req.cnf"), "-extensions", "ca")
        run("openssl", "req", *ec, "-keyout", j("tsa.key"), "-out", j("tsa.csr"), "-subj", "/CN=tsa", "-config", j("req.cnf"))
        run("openssl", "x509", "-req", "-in", j("tsa.csr"), "-CA", j("ca.crt"), "-CAkey", j("ca.key"), "-CAcreateserial",
            "-out", j("tsa.crt"), "-days", "2", "-extfile", j("req.cnf"), "-extensions", "tsa")
        with open(j("serial"), "w") as f:
            f.write("01\n")
        with open(j("tsa.cnf"), "w") as f:
            f.write(f"[ tsa ]\ndefault_tsa = t1\n[ t1 ]\nserial = {cnf_path(j('serial'))}\ncrypto_device = builtin\n"
                    f"signer_cert = {cnf_path(j('tsa.crt'))}\nsigner_key = {cnf_path(j('tsa.key'))}\nsigner_digest = sha256\n"
                    "default_policy = 1.2.3.4.1\ndigests = sha256\ness_cert_id_alg = sha256\ness_cert_id_chain = no\n")
        digest = hashlib.sha256(b"x").digest()
        run("openssl", "ts", "-query", "-digest", digest.hex(), "-sha256", "-cert", "-out", j("q.tsq"))
        run("openssl", "ts", "-reply", "-queryfile", j("q.tsq"), "-config", j("tsa.cnf"), "-section", "t1",
            "-token_out", "-out", j("tok.der"))
        with open(j("tok.der"), "rb") as f:
            tok = f.read()
        qq = b"\x1e\x04\x00\x51\x00\x51"                    # BMPString "QQ": the certificate's issuer and the sid
        self.assertEqual(tok.count(qq), 2)
        self.assertEqual(outcome(tok, digest, None), ("signature_only", None))   # control
        lone = tok.replace(qq, b"\x1e\x04\xd8\x00\x00\x51")   # a lone surrogate, the same bytes in both
        for t in (lone, alter_signature(lone)):
            self.assertFalse(T._signer_certificate_absent(t))    # the certificate is there, its Name not read
            self.assertEqual(outcome(t, digest, None), ("invalid", "signature_invalid"))

    def test_report_and_ingest_name_it(self):
        """the callers named in CHANGELOG 0.27.0: the report's badge and the ingest's failure reason"""
        import cryptovalid_ingest as I
        import cryptovalid_report as R
        with open(os.path.join(V, "manifest.json")) as f:
            digest = bytes.fromhex(json.load(f)["digest_sha256"])
        with open(os.path.join(V, "freetsa.tsr"), "rb") as f:
            tok = T.parse_token(f.read())["token_der"]
        badge, text = R._token_badge({"manifest_digest_sha256": digest.hex()},
                                     {"tsr_b64": base64.b64encode(strip_certs(tok)).decode(), "tsa": "x"})
        self.assertIn("SIGNATURE NOT CHECKED", badge)
        self.assertIn("does not carry its signer certificate", text)
        badge, _ = R._token_badge({"manifest_digest_sha256": digest.hex()},
                                  {"tsr_b64": base64.b64encode(alter_signature(tok)).decode(), "tsa": "x"})
        self.assertIn("TOKEN INVALID", badge)                                    # control: a signature that fails
        self.assertEqual(I._TSA_FAILURE["signer_certificate_absent"], "tsa_token_signer_certificate_absent")

if __name__ == "__main__":
    unittest.main()
