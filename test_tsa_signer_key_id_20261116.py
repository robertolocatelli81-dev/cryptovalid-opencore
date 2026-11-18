#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""SPEC v0.10 §11 step 7 (16/11/2026): a token whose SignerInfo names its signer by subjectKeyIdentifier.

RFC 5652 §5.3 allows `sid` to be issuerAndSerialNumber or subjectKeyIdentifier. openssl `ts -verify` reads the token as
PKCS #7 and refuses the second form with an ASN.1 error, so until v0.10 a valid token of that kind was
`not_issued_by_pinned_tsa` here (found on 16/11/2026 while extracting the payment profile into a separate repository).

Everything is made with openssl on this machine: a CA and TSA certificates carrying a subjectKeyIdentifier, a token from
`openssl ts -reply`, and the same TSTInfo re-signed by `openssl cms -sign -keyid -cades` (sid = subjectKeyIdentifier, an
ESS signingCertificateV2 attribute). Positive control: openssl `ts -verify` refuses the re-signed token, cryptovalid
0.25.1 refused it too (`test_openssl_ts_refuses_it`; measured on 0.25.1: `not_issued_by_pinned_tsa`); now it is `verified`. Negatives: the key
identifier of another certificate, another TSA's key, no ESS attribute, a certificate without timeStamping, a `tsa` field
naming another TSA."""
import copy
import hashlib
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest

sys.dont_write_bytecode = True
ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)
import cryptovalid_tsa as T  # noqa: E402

NEEDS = unittest.skipUnless(shutil.which("openssl"), "needs openssl")
try:
    import cryptography  # noqa: F401
    HAVE_CRYPTO = True
except ImportError:   # the CI job without cryptography: this file must skip, not fail
    HAVE_CRYPTO = False
NEEDS_CRYPTO = unittest.skipUnless(HAVE_CRYPTO, "needs cryptography (the names are built with it)")
DIGEST = hashlib.sha256(b"a payment ledger head").digest()
OID_TSTINFO = "1.2.840.113549.1.9.16.1.4"
EXT = ("[ v3_ca ]\nbasicConstraints = critical,CA:TRUE\nkeyUsage = critical,keyCertSign,cRLSign\n"
       "subjectKeyIdentifier = hash\n"
       "[ v3_tsa ]\nextendedKeyUsage = critical,timeStamping\nbasicConstraints = CA:FALSE\n"
       "subjectKeyIdentifier = hash\nauthorityKeyIdentifier = keyid\n"
       "[ v3_plain ]\nbasicConstraints = CA:FALSE\nkeyUsage = critical,digitalSignature\nsubjectKeyIdentifier = hash\n"
       "[ v3_tsa_san ]\nextendedKeyUsage = critical,timeStamping\nbasicConstraints = CA:FALSE\n"
       "subjectKeyIdentifier = hash\nsubjectAltName = DNS:tsa.example\n"
       "[ v3_badca ]\nbasicConstraints = critical,CA:TRUE\nkeyUsage = critical,digitalSignature\n"
       "subjectKeyIdentifier = hash\n")


def _run(*cmd, cwd=None):
    return subprocess.run(cmd, check=True, capture_output=True, cwd=cwd)


class Lab:
    """a CA with a subjectKeyIdentifier and certificates it issued; tokens by openssl ts, re-signed by openssl cms"""

    def __init__(self, td, name, ca_ext="v3_ca", tsa_ext="v3_tsa"):
        self.d = os.path.join(td, name)
        os.makedirs(self.d)
        j = self.j
        with open(j("ext.cnf"), "w") as f:
            f.write(EXT)
        with open(j("req.cnf"), "w") as f:
            f.write("[ req ]\ndistinguished_name = dn\n[ dn ]\n" + EXT)
        _run("openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
             "-keyout", j("ca.key"), "-out", j("ca.crt"), "-subj", f"/CN={name}-ca", "-days", "2",
             "-config", j("req.cnf"), "-extensions", ca_ext)
        for cert, ext in (("tsa", tsa_ext), ("plain", "v3_plain")):
            _run("openssl", "req", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
                 "-keyout", j(f"{cert}.key"), "-out", j(f"{cert}.csr"), "-subj", f"/CN={name}-{cert}",
                 "-config", j("req.cnf"))
            _run("openssl", "x509", "-req", "-in", j(f"{cert}.csr"), "-CA", j("ca.crt"), "-CAkey", j("ca.key"),
                 "-CAcreateserial", "-out", j(f"{cert}.crt"), "-days", "2", "-extfile", j("ext.cnf"), "-extensions", ext)
        with open(j("serial"), "w") as f:
            f.write("01\n")

    ess_alg = "sha256"

    def j(self, n):
        return os.path.join(self.d, n)

    def token(self, tsa_name=False, chain=False):
        """a token of `openssl ts -reply` (sid = issuerAndSerialNumber); `tsa_name`: the TSTInfo carries the tsa field"""
        j = self.j
        with open(j("tsa.cnf"), "w") as f:
            f.write(f"[ tsa ]\ndefault_tsa = t1\n[ t1 ]\nserial = {j('serial')}\ncrypto_device = builtin\n"
                    f"signer_cert = {j('tsa.crt')}\ncerts = {j('ca.crt')}\nsigner_key = {j('tsa.key')}\n"
                    "signer_digest = sha256\ndefault_policy = 1.2.3.4.1\ndigests = sha256\naccuracy = secs:1\n"
                    f"ordering = yes\ntsa_name = {'yes' if tsa_name else 'no'}\ness_cert_id_chain = {'yes' if chain else 'no'}\n"
                    f"ess_cert_id_alg = {self.ess_alg}\n")
        _run("openssl", "ts", "-query", "-digest", DIGEST.hex(), "-sha256", "-cert", "-out", j("q.tsq"))
        _run("openssl", "ts", "-reply", "-queryfile", j("q.tsq"), "-config", j("tsa.cnf"), "-section", "t1",
             "-token_out", "-out", j("tok.der"))
        with open(j("tok.der"), "rb") as f:
            return f.read()

    def resign(self, token, signer="tsa", ess=True):
        """the TSTInfo of `token` signed again by openssl cms with `signer`'s key, the signer named by its key identifier"""
        j = self.j
        with open(j("in.der"), "wb") as f:
            f.write(token)
        _run("openssl", "cms", "-verify", "-noverify", "-inform", "DER", "-in", j("in.der"), "-out", j("tst.der"))
        _run("openssl", "cms", "-sign", "-binary", "-nodetach", "-econtent_type", OID_TSTINFO, "-keyid",
             *(["-cades"] if ess else []), "-md", "sha256", "-nosmimecap", "-signer", j(f"{signer}.crt"),
             "-inkey", j(f"{signer}.key"), "-certfile", j("ca.crt"), "-in", j("tst.der"), "-outform", "DER",
             "-out", j("ski.der"))
        with open(j("ski.der"), "rb") as f:
            return f.read()


def der(tag, v):
    n = len(v)
    ln = bytes([n]) if n < 0x80 else bytes([0x80 | ((n.bit_length() + 7) // 8)]) + n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([tag]) + ln + v


def tree(b):
    """a DER element as [tag, children] when constructed, [tag, bytes] when primitive (eContent's OCTET STRING too)"""
    (t, v), = T._der_items(b, "test")
    return [t, [tree(der(ct, cv)) for ct, cv in T._der_items(v, "test")]] if t & 0x20 else [t, v]


def enc(n):
    return der(n[0], b"".join(enc(c) for c in n[1]) if isinstance(n[1], list) else n[1])


def signer_info(tok):
    """the SignerInfo node of a token's tree (ContentInfo / [0] / SignedData / signerInfos / SignerInfo)"""
    return tok[1][1][1][0][1][-1][1][0]


def ess_v2(si):
    """the ESSCertIDv2 list of the signingCertificateV2 attribute of a SignerInfo node"""
    for a in si[1][3][1]:
        if T._der_oid(a[1][0][1], "t") == T.OID_SIGNING_CERTIFICATE_V2:
            return a[1][1][1][0][1][0][1]
    raise AssertionError("no signingCertificateV2")


def ski_of(cert_path):
    """the subjectKeyIdentifier of a certificate, as openssl prints it"""
    out = _run("openssl", "x509", "-in", cert_path, "-noout", "-ext", "subjectKeyIdentifier").stdout.decode()
    return bytes.fromhex(out.strip().splitlines()[-1].strip().replace(":", ""))


@NEEDS
class SignerByKeyId(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.td = tempfile.mkdtemp()
        cls.lab, cls.other = Lab(cls.td, "a"), Lab(cls.td, "b")
        cls.tok = cls.lab.token()
        cls.ski = cls.lab.resign(cls.tok)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.td)

    def check(self, tok, pins=None):
        return T.verify_token(tok, DIGEST, "sha256", pins or [self.lab.j("ca.crt")])

    def test_the_token_is_named_by_key_id(self):
        self.assertFalse(T._signer_named_by_key_id(T.parse_token(self.tok)["token_der"]))
        self.assertTrue(T._signer_named_by_key_id(T.parse_token(self.ski)["token_der"]))
        self.assertIn(ski_of(self.lab.j("tsa.crt")), self.ski)   # the sid carries the TSA certificate's key identifier

    def test_openssl_ts_refuses_it(self):
        """the defect's cause: openssl ts -verify cannot read the SignerInfo, the issuerAndSerialNumber token passes"""
        for tok, ok in ((self.tok, True), (self.ski, False)):
            p = os.path.join(self.td, "t.der")
            with open(p, "wb") as f:
                f.write(tok)
            r = subprocess.run(["openssl", "ts", "-verify", "-token_in", "-in", p, "-digest", DIGEST.hex(), "-CAfile",
                                self.lab.j("ca.crt"), "-untrusted", self.lab.j("ca.crt"), "-partial_chain"],
                               capture_output=True)
            self.assertEqual(r.returncode == 0 and b"Verification: OK" in r.stdout, ok, r.stderr[-300:])

    def test_valid_token_named_by_key_id_is_verified(self):
        with open(self.lab.j("tsa.crt"), "rb") as f:
            leaf = T._first_pem_der(f.read())
        for pins in ([self.lab.j("ca.crt")], [self.lab.j("tsa.crt")]):
            v = self.check(self.ski, pins)
            self.assertEqual((v["status"], v["reason"], v["counts_as_timestamp"]), ("verified", None, True), (pins, v))
            self.assertEqual(v["signer_sha256"], hashlib.sha256(leaf).hexdigest())
            self.assertEqual(v["tst_info"], self.check(self.tok, pins)["tst_info"])   # the same TSTInfo
        self.assertEqual(self.check(self.tok)["status"], "verified")              # the other form, unchanged

    def test_key_id_of_another_certificate(self):
        """the sid rewritten to the key identifier of another certificate (sid is not signed): never verified"""
        mine, theirs = ski_of(self.lab.j("tsa.crt")), ski_of(self.other.j("tsa.crt"))
        sid = bytes([0x80, len(mine)]) + mine                             # [0] subjectKeyIdentifier in the SignerInfo
        self.assertEqual(self.ski.count(sid), 1)
        forged = self.ski.replace(sid, bytes([0x80, len(theirs)]) + theirs)
        self.assertTrue(T._signer_named_by_key_id(T.parse_token(forged)["token_der"]))
        for pins in ([self.lab.j("ca.crt")], [self.lab.j("ca.crt"), self.other.j("tsa.crt")],
                     [self.other.j("ca.crt"), self.other.j("tsa.crt")]):
            v = self.check(forged, pins)
            self.assertEqual(v["status"], "invalid", (pins, v))
            # SPEC v0.11 §11 step 6: with no certificate of that key identifier in the token or the pins, the signature is
            # not evaluated (`signer_certificate_absent`; `signature_invalid` until 0.26.0)
            want = ("signer_certificate_absent",) if pins == [self.lab.j("ca.crt")] else ("signature_invalid", "not_issued_by_pinned_tsa")
            self.assertIn(v["reason"], want, v)

    def test_another_tsa_key(self):
        v = self.check(self.other.resign(self.tok))   # signed by b's TSA, a's CA pinned
        self.assertEqual((v["status"], v["reason"]), ("invalid", "not_issued_by_pinned_tsa"), v)
        self.assertEqual(self.check(self.other.resign(self.tok), [self.other.j("ca.crt")])["status"], "verified")

    def test_the_system_store_is_not_a_pin(self):
        """only the pinned certificates anchor: a system certificate directory (SSL_CERT_DIR, read by openssl when it is
        not told otherwise) that trusts b's CA does not make b's token verified under a's pin"""
        store = os.path.join(self.td, "store")
        os.makedirs(store, exist_ok=True)
        shutil.copy(self.other.j("ca.crt"), os.path.join(store, "b-ca.pem"))
        _run("openssl", "rehash", store)
        tok = self.other.resign(self.tok)
        old = os.environ.get("SSL_CERT_DIR")
        os.environ["SSL_CERT_DIR"] = store
        try:
            r = subprocess.run(["openssl", "verify", "-purpose", "timestampsign", self.other.j("tsa.crt")],
                               capture_output=True)
            self.assertEqual(r.returncode, 0, r.stderr)                  # control: openssl trusts the directory
            v = self.check(tok)
        finally:
            if old is None:
                del os.environ["SSL_CERT_DIR"]
            else:
                os.environ["SSL_CERT_DIR"] = old
        self.assertEqual((v["status"], v["reason"]), ("invalid", "not_issued_by_pinned_tsa"), v)

    def test_no_ess_attribute(self):
        v = self.check(self.lab.resign(self.tok, ess=False))
        self.assertEqual((v["status"], v["reason"]), ("invalid", "not_issued_by_pinned_tsa"), v)
        self.assertIn("ESS", v["detail"])

    def test_certificate_without_time_stamping(self):
        v = self.check(self.lab.resign(self.tok, signer="plain"))
        self.assertEqual((v["status"], v["reason"]), ("invalid", "not_issued_by_pinned_tsa"), v)

    def test_tsa_field(self):
        named = self.lab.token(tsa_name=True)
        self.assertEqual(self.check(self.lab.resign(named))["status"], "verified")      # names this TSA
        v = self.check(self.lab.resign(self.other.token(tsa_name=True)))                 # names b's TSA
        self.assertEqual((v["status"], v["reason"]), ("invalid", "not_issued_by_pinned_tsa"), v)
        self.assertIn("tsa field", v["detail"])


@NEEDS
class AnchorParts(unittest.TestCase):
    """each check of step 7 for a key-identified signer, called on the step's own function with one field changed (the
    signature is step 6's, checked apart): the ESS hash, the ESS issuerSerial, a second ESSCertID, genTime, and a
    pinned leaf whose CA in the token is not a CA that may sign certificates"""

    @classmethod
    def setUpClass(cls):
        cls.td = tempfile.mkdtemp()
        cls.lab = Lab(cls.td, "a")
        with open(cls.lab.j("tsa.crt"), "rb") as f:
            cls.leaf = T._first_pem_der(f.read())
        cls.pins = T._pem_certs([cls.lab.j("ca.crt")])
        cls.ski = T.parse_token(cls.lab.resign(cls.lab.token()))["token_der"]
        cls.at = int(time.time())

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.td)

    def anchor(self, tok, at=None, pins=None, leaf=None):
        return T._key_id_anchor(tok, leaf or self.leaf, pins or self.pins, at or self.at, self.td)

    def test_control(self):
        self.assertIsNone(self.anchor(self.ski))
        self.assertIsNone(self.anchor(enc(tree(self.ski))))           # the tree rebuilds the same bytes
        self.assertEqual(enc(tree(self.ski)), self.ski)

    def test_ess_cert_hash(self):
        t = tree(self.ski)
        cid = ess_v2(signer_info(t))[0][1]
        h = [x for x in cid if x[0] == 0x04][0]
        h[1] = bytes([h[1][0] ^ 1]) + h[1][1:]
        self.assertIn("certHash", self.anchor(enc(t)))

    def test_ess_issuer_serial(self):
        t = tree(self.ski)
        cid = ess_v2(signer_info(t))[0][1]
        iss = [x for x in cid if x[0] == 0x30 and x[1][0][0] == 0x30]
        self.assertEqual(len(iss), 1, "openssl -cades writes issuerSerial")
        serial = iss[0][1][1]
        serial[1] = serial[1][:-1] + bytes([serial[1][-1] ^ 1])
        self.assertIn("issuerSerial", self.anchor(enc(t)))

    def test_ess_issuer_name(self):
        t = tree(self.ski)
        cid = ess_v2(signer_info(t))[0][1]
        names = [x for x in cid if x[0] == 0x30 and x[1][0][0] == 0x30][0][1][0]
        name = names[1][0][1][0]                                          # [4] directoryName / Name
        rdn = name[1][-1][1][0][1][1]                                     # the last RDN's value
        rdn[1] = rdn[1][:-1] + b"X"
        self.assertIn("issuerSerial", self.anchor(enc(t)))

    def test_attribute_with_two_values(self):
        t = tree(self.ski)
        for a in signer_info(t)[1][3][1]:
            if T._der_oid(a[1][0][1], "t") == T.OID_SIGNING_CERTIFICATE_V2:
                a[1][1][1].append(copy.deepcopy(a[1][1][1][0]))
        self.assertIn("not exactly one value", self.anchor(enc(t)))

    def to_key_id(self, tok):
        """the tree of an issuerAndSerialNumber token with its sid rewritten to the TSA's key identifier"""
        t = tree(T.parse_token(tok)["token_der"])
        signer_info(t)[1][1] = [0x80, ski_of(self.lab.j("tsa.crt"))]
        return enc(t)

    def test_ess_v1_with_sha1(self):
        """signingCertificate (RFC 2634, SHA-1), as openssl ts -reply writes it with ess_cert_id_alg = sha1"""
        self.lab.ess_alg = "sha1"
        try:
            tok = self.to_key_id(self.lab.token())
        finally:
            self.lab.ess_alg = "sha256"
        self.assertIsNone(self.anchor(tok))
        t = tree(tok)
        for a in signer_info(t)[1][3][1]:
            if T._der_oid(a[1][0][1], "t") == T.OID_SIGNING_CERTIFICATE:
                h = a[1][1][1][0][1][0][1][0][1][0]
                h[1] = bytes([h[1][0] ^ 1]) + h[1][1:]
        self.assertIn("certHash", self.anchor(enc(t)))

    def test_ess_chain_of_ids(self):
        """openssl ts -reply with ess_cert_id_chain = yes: two ESSCertIDs. openssl ts -verify takes the issuerAndSerialNumber
        form (verified); the key-identifier form refused more than one until SPEC v0.11 (0.26.0: "2 ESSCertIDs (exactly
        one is evaluated here)") and now evaluates them: the first is the signer's, the second limits the path to the CA
        (test_tsa_ess_cert_ids_20261118.py)"""
        tok = self.lab.token(chain=True)
        self.assertEqual(T.verify_token(tok, DIGEST, "sha256", [self.lab.j("ca.crt")])["status"], "verified")
        self.assertTrue(T._ess_lists_more_than_one(T.parse_token(tok)["token_der"]))
        self.assertIsNone(self.anchor(self.to_key_id(tok)))

    def test_ess_v2_hash_algorithm(self):
        """ESSCertIDv2 with an explicit hashAlgorithm (sha384): verified; with a parameter that is not NULL: refused"""
        self.lab.ess_alg = "sha384"
        try:
            tok = self.to_key_id(self.lab.token())
        finally:
            self.lab.ess_alg = "sha256"
        self.assertIsNone(self.anchor(tok))
        t = tree(tok)
        ai = ess_v2(signer_info(t))[0][1][0]
        self.assertEqual((ai[0], len(ai[1])), (0x30, 1))                  # {OID}, no parameter
        ai[1].append([0x02, b"\x01"])
        self.assertIn("hash algorithm", self.anchor(enc(t)))

    def test_tsa_field_in_subject_alt_name(self):
        """the tsa field as a dNSName that the signer's subjectAltName carries (and one it does not)"""
        san = Lab(self.td, "san", tsa_ext="v3_tsa_san")
        with open(san.j("tsa.crt"), "rb") as f:
            leaf = T._first_pem_der(f.read())
        pins = T._pem_certs([san.j("ca.crt")])
        base = T.parse_token(san.resign(san.token()))["token_der"]
        now = int(time.time()) + 1                                       # this lab is younger than the class's instant
        self.assertIsNone(self.anchor(base, pins=pins, leaf=leaf, at=now))
        for name, ok in ((b"tsa.example", True), (b"other.example", False)):
            t = tree(base)
            econtent = t[1][1][1][0][1][2][1][1][1][0]                  # SignedData / encapContentInfo / [0] / OCTET STRING
            tst = tree(econtent[1])
            tst[1].insert(len(tst[1]), [0xA0, [[0x82, name]]])           # tsa [0] GeneralName dNSName, the last element
            econtent[1] = enc(tst)
            why = self.anchor(enc(t), pins=pins, leaf=leaf, at=now)
            self.assertEqual(why is None, ok, why)

    @NEEDS_CRYPTO
    def test_names_compared_as_openssl(self):
        """SPEC §11 step 7: the tsa field and the ESS issuerSerial name are compared as X509_NAME_cmp compares names
        (string values in UTF-8, white space trimmed and folded, ASCII letters lowercased), not byte for byte"""
        from cryptography import x509
        from cryptography.x509.name import _ASN1Type
        from cryptography.x509.oid import NameOID
        with open(self.lab.j("tsa.crt"), "rb") as f:
            cn = x509.load_pem_x509_certificate(f.read()).subject.rfc4514_string()[3:]

        def with_tsa(name):
            t = tree(self.ski)
            econtent = t[1][1][1][0][1][2][1][1][1][0]
            tst = tree(econtent[1])
            tst[1].append([0xA0, [[0xA4, [tree(name.public_bytes())]]]])
            econtent[1] = enc(tst)
            return enc(t)
        for value, typ, ok in ((cn, None, True), (cn.upper(), None, True), ("  " + cn + " ", None, True),
                               (cn, _ASN1Type.PrintableString, True), (cn.replace("-", " - "), None, False),
                               (cn + "x", None, False)):
            attr = x509.NameAttribute(NameOID.COMMON_NAME, value, typ) if typ else x509.NameAttribute(NameOID.COMMON_NAME, value)
            why = self.anchor(with_tsa(x509.Name([attr])))
            self.assertEqual(why is None, ok, (value, typ, why))
        t = tree(self.ski)                                                # the issuerSerial name in other case
        cid = ess_v2(signer_info(t))[0][1]
        name = [x for x in cid if x[0] == 0x30 and x[1][0][0] == 0x30][0][1][0][1][0][1][0]
        rdn = name[1][-1][1][0][1][1]
        rdn[1] = rdn[1].upper()
        self.assertIsNone(self.anchor(enc(t)))
        self.assertTrue(T._names_equal(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "A\tB")]).public_bytes(),
                                       x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "a b")]).public_bytes()))
        self.assertFalse(T._names_equal(b"\x30\x00", b"\x31\x00"))      # not a Name: never equal
        N, A_ = x509.Name, x509.NameAttribute
        cn_o = N([A_(NameOID.COMMON_NAME, "x"), A_(NameOID.ORGANIZATION_NAME, "y")]).public_bytes()
        o_cn = N([A_(NameOID.ORGANIZATION_NAME, "y"), A_(NameOID.COMMON_NAME, "x")]).public_bytes()
        self.assertFalse(T._names_equal(cn_o, o_cn))                      # RDNs in order
        multi1 = N([x509.RelativeDistinguishedName([A_(NameOID.COMMON_NAME, "x"), A_(NameOID.ORGANIZATION_NAME, "y")])])
        multi2 = N([x509.RelativeDistinguishedName([A_(NameOID.ORGANIZATION_NAME, "y"), A_(NameOID.COMMON_NAME, "x")])])
        self.assertTrue(T._names_equal(multi1.public_bytes(), multi2.public_bytes()))   # one RDN: any order
        atv = [enc(x) for x in tree(multi1.public_bytes())[1][0][1]]      # the two attributes of the RDN, swapped by hand
        swapped = der(0x30, der(0x31, atv[1] + atv[0]))
        self.assertNotEqual(swapped, multi1.public_bytes())
        self.assertTrue(T._names_equal(swapped, multi1.public_bytes()))
        self.assertFalse(T._names_equal(N([A_(NameOID.COMMON_NAME, "\u00c9")]).public_bytes(),
                                        N([A_(NameOID.COMMON_NAME, "\u00e9")]).public_bytes()))   # ASCII letters only
        self.assertFalse(T._names_equal(N([A_(NameOID.COMMON_NAME, "x")]).public_bytes(),
                                        N([A_(NameOID.ORGANIZATION_NAME, "x")]).public_bytes()))   # the OID counts
        self.assertFalse(T._general_names_equal((0x82, cn_o), (0xA4, cn_o)))    # the GeneralName type counts
        self.assertTrue(T._general_names_equal((0x82, b"tsa.example"), (0x82, b"tsa.example")))
        self.assertFalse(T._general_names_equal((0x82, b"tsa.example"), (0x82, b"TSA.example")))   # bytes, not a Name

    def test_more_than_one_ess_cert_id(self):
        t = tree(self.ski)
        ids = ess_v2(signer_info(t))
        ids.append(copy.deepcopy(ids[0]))
        self.assertIn("same certificate hash", self.anchor(enc(t)))   # SPEC v0.11: the signer listed twice is refused
        h = [x for x in ids[-1][1] if x[0] == 0x04][0]
        h[1] = bytes([h[1][0] ^ 1]) + h[1][1:]       # a hash of no certificate here: its issuerSerial is not compared
        self.assertIsNone(self.anchor(enc(t)))   # the path limited to the signer, whose CA is pinned
        h[1] = h[1][:-1]                             # a hash of the wrong length
        self.assertIn("certHash is not sha256-long", self.anchor(enc(t)))

    def test_validity_at_gen_time(self):
        self.assertIsNotNone(self.anchor(self.ski, at=self.at + 10 * 86400))   # certificates of 2 days
        self.assertIsNotNone(self.anchor(self.ski, at=self.at - 10 * 86400))

    def test_pinned_leaf_and_the_ca_in_the_token(self):
        """a pinned leaf does not end the chain: the CA the token carries is checked too, as openssl ts -verify does for
        the other form of the same token"""
        bad = Lab(self.td, "badca", ca_ext="v3_badca")
        tok = bad.token()
        with open(bad.j("tsa.crt"), "rb") as f:
            leaf = T._first_pem_der(f.read())
        p = os.path.join(self.td, "bad.der")
        with open(p, "wb") as f:
            f.write(tok)
        r = subprocess.run(["openssl", "ts", "-verify", "-token_in", "-in", p, "-digest", DIGEST.hex(), "-CAfile",
                            bad.j("tsa.crt"), "-untrusted", bad.j("tsa.crt"), "-partial_chain"], capture_output=True)
        ski = T.parse_token(bad.resign(tok))["token_der"]
        mine = self.anchor(ski, pins=T._pem_certs([bad.j("tsa.crt")]), leaf=leaf)
        self.assertEqual(r.returncode == 0, mine is None, (r.stderr[-200:], mine))
        self.assertIsNotNone(mine)                                        # measured: both refuse
        good = T._pem_certs([self.lab.j("tsa.crt")])
        self.assertIsNone(self.anchor(self.ski, pins=good))               # control: a CA that may sign, leaf pinned


if __name__ == "__main__":
    unittest.main()
