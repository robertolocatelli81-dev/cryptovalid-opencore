#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""SPEC v0.11 §11 step 7 (18/11/2026): a signing-certificate attribute that lists more than one ESSCertID.

RFC 2634 §5.4 and RFC 5035 §3 (§5.4.1 of RFC 2634 as updated): the FIRST ESSCertID MUST be the certificate used to verify
the signature (a hash that does not match makes the signature invalid); the ones after it "limit the set of certificates
that are used during validation". OpenSSL's `ts -verify` asks more: every ESSCertID must identify a certificate of the
chain it built (OSSL_ESS_check_signing_certs, 3.0 and master). With a CA pinned below the last certificate listed,
`-partial_chain` ends the chain at the pin and the token was refused ("ess cert id not found"). Measured on 2026-11-18
with OpenSSL 3.0.22 and 0.26.0: sectigo.tsr of spec/vectors/rfc3161 (ESSCertIDs of its signer, of the CA R41 and of the
Root R46) is `verified` with the signer or R46 pinned and `not_issued_by_pinned_tsa` with R41 pinned, although
`openssl verify -partial_chain` establishes the signer under R41. A signer named by subjectKeyIdentifier with more than one
ESSCertID was refused whatever the pin ("not evaluated here").

Generative: tokens made here (a root, an intermediate CA, a TSA certificate; an unrelated CA X) whose SignedData is
written by this file and signed by `openssl dgst`, x sid issuerAndSerialNumber / subjectKeyIdentifier x
signingCertificate (SHA-1) / signingCertificateV2 (SHA-256 by default, SHA-384 explicit) x ESSCertID lists of 1..3 with the
signer first or not, the first hash wrong x issuerSerial absent / present / wrong on the first / wrong on a later one x
the pin at the signer, the intermediate, the root, X. The expected outcome is computed by `expected` below from the
rule as the SPEC writes it, not from the code. Positive control: a first ESSCertID that is not the signer's is refused
in every combination."""
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
DIGEST = hashlib.sha256(b"ESSCertID lists").digest()
EXT = ("[ req ]\ndistinguished_name = dn\n[ dn ]\n"
       "[ ca ]\nbasicConstraints = critical,CA:TRUE\nkeyUsage = critical,keyCertSign,cRLSign\nsubjectKeyIdentifier = hash\n"
       "[ tsa ]\nextendedKeyUsage = critical,timeStamping\nbasicConstraints = CA:FALSE\nsubjectKeyIdentifier = hash\n"
       "authorityKeyIdentifier = keyid\n")


def der(tag, v):
    return T._tlv_bytes(tag, v)


def oid(dotted):
    a = [int(x) for x in dotted.split(".")]
    body = bytes([40 * a[0] + a[1]])
    for n in a[2:]:
        enc = [n & 0x7F]
        n >>= 7
        while n:
            enc.append(0x80 | (n & 0x7F))
            n >>= 7
        body += bytes(reversed(enc))
    return der(0x06, body)


def integer(n):
    return der(0x02, n.to_bytes(n.bit_length() // 8 + 1, "big", signed=True))


def pem(d):
    return b"-----BEGIN CERTIFICATE-----\n" + base64.encodebytes(d) + b"-----END CERTIFICATE-----\n"


def issuer_serial_of(cert):
    """(issuer Name TLV, serial int) of a DER certificate"""
    tbs = T._der_items(T._der_items(T._der_one(cert, "c", 0x30), "c")[0][1], "tbs")
    k = 1 if tbs[0][0] == 0xA0 else 0
    return der(0x30, tbs[k + 2][1]), int.from_bytes(tbs[k][1], "big", signed=True)


class Pki:
    """root R -> intermediate I -> TSA certificate S (timeStamping, subjectKeyIdentifier); X an unrelated CA"""

    def __init__(self, d):
        self.d = d
        j = self.j
        with open(j("ext.cnf"), "w") as f:
            f.write(EXT)
        ec = ("-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes")
        run = lambda *c: subprocess.run(c, check=True, capture_output=True)  # noqa: E731
        for n in ("R", "X"):
            run("openssl", "req", "-x509", *ec, "-keyout", j(n + ".key"), "-out", j(n + ".crt"), "-subj", f"/CN=ess-{n}",
                "-days", "2", "-config", j("ext.cnf"), "-extensions", "ca")
        for n, ca, ext in (("I", "R", "ca"), ("S", "I", "tsa")):
            run("openssl", "req", *ec, "-keyout", j(n + ".key"), "-out", j(n + ".csr"), "-subj", f"/CN=ess-{n}",
                "-config", j("ext.cnf"))
            run("openssl", "x509", "-req", "-in", j(n + ".csr"), "-CA", j(ca + ".crt"), "-CAkey", j(ca + ".key"),
                "-CAcreateserial", "-out", j(n + ".crt"), "-days", "2", "-extfile", j("ext.cnf"), "-extensions", ext)
        self.cert = {}
        for n in ("R", "X", "I", "S"):
            with open(j(n + ".crt"), "rb") as f:
                self.cert[n] = T._first_pem_der(f.read())
        with open(j("serial"), "w") as f:
            f.write("01\n")
        with open(j("tsa.cnf"), "w") as f:
            f.write(f"[ tsa ]\ndefault_tsa = t1\n[ t1 ]\nserial = {cnf_path(j('serial'))}\ncrypto_device = builtin\n"
                    f"signer_cert = {cnf_path(j('S.crt'))}\nsigner_key = {cnf_path(j('S.key'))}\nsigner_digest = sha256\n"
                    "default_policy = 1.2.3.4.1\ndigests = sha256\ness_cert_id_alg = sha256\ness_cert_id_chain = no\n")
        run("openssl", "ts", "-query", "-digest", DIGEST.hex(), "-sha256", "-cert", "-out", j("q.tsq"))
        run("openssl", "ts", "-reply", "-queryfile", j("q.tsq"), "-config", j("tsa.cnf"), "-section", "t1",
            "-token_out", "-out", j("tok.der"))
        with open(j("tok.der"), "rb") as f:
            tok = f.read()
        ci = T._der_items(T._der_one(tok, "ContentInfo", 0x30), "ContentInfo")
        sd = T._der_items(T._der_one(ci[1][1], "SignedData", 0x30), "SignedData")
        eci = T._der_items(sd[2][1], "encapContentInfo")
        self.tstinfo = T._der_one(eci[1][1], "eContent", 0x04)
        out = run("openssl", "x509", "-in", j("S.crt"), "-noout", "-ext", "subjectKeyIdentifier").stdout.decode()
        self.ski = bytes.fromhex(out.strip().splitlines()[-1].strip().replace(":", ""))

    def j(self, n):
        return os.path.join(self.d, n)

    def ess_id(self, name, alg, is_mode, wrong_hash=False):
        """one ESSCertID(v2) for certificate `name`; is_mode: None (absent), "ok", "bad" (serial + 1)"""
        c = self.cert[name]
        h = hashlib.new(alg, c).digest()
        if wrong_hash:
            h = bytes([h[0] ^ 1]) + h[1:]
        body = b""
        if alg == "sha384":
            body += der(0x30, oid("2.16.840.1.101.3.4.2.2"))
        body += der(0x04, h)
        if is_mode is not None:
            iss, serial = issuer_serial_of(c)
            body += der(0x30, der(0x30, der(0xA4, iss)) + integer(serial + (1 if is_mode == "bad" else 0)))
        return der(0x30, body)

    def token(self, sid, attrs):
        """a TimeStampToken over the TSTInfo, signed with S's key; attrs: [(version "v1"/"v2", [ESSCertID DER])]"""
        a = [der(0x30, oid("1.2.840.113549.1.9.3") + der(0x31, oid("1.2.840.113549.1.9.16.1.4"))),
             der(0x30, oid("1.2.840.113549.1.9.4") + der(0x31, der(0x04, hashlib.sha256(self.tstinfo).digest())))]
        for ver, ids in attrs:
            o = T.OID_SIGNING_CERTIFICATE if ver == "v1" else T.OID_SIGNING_CERTIFICATE_V2
            a.append(der(0x30, oid(o) + der(0x31, der(0x30, der(0x30, b"".join(ids))))))
        signed = b"".join(sorted(a))                       # DER SET OF: sorted by encoding
        with open(self.j("attrs.der"), "wb") as f:
            f.write(der(0x31, signed))
        sig = subprocess.run(["openssl", "dgst", "-sha256", "-sign", self.j("S.key"), self.j("attrs.der")],
                             check=True, capture_output=True).stdout
        if sid == "ias":
            iss, serial = issuer_serial_of(self.cert["S"])
            version, sid_der = 1, der(0x30, iss + integer(serial))
        else:
            version, sid_der = 3, der(0x80, self.ski)
        si = der(0x30, integer(version) + sid_der + der(0x30, oid("2.16.840.1.101.3.4.2.1")) + der(0xA0, signed)
                 + der(0x30, oid("1.2.840.10045.4.3.2")) + der(0x04, sig))
        sd = der(0x30, integer(3) + der(0x31, der(0x30, oid("2.16.840.1.101.3.4.2.1")))
                 + der(0x30, oid("1.2.840.113549.1.9.16.1.4") + der(0xA0, der(0x04, self.tstinfo)))
                 + der(0xA0, self.cert["S"] + self.cert["I"] + self.cert["R"]) + der(0x31, si))
        return der(0x30, oid("1.2.840.113549.1.7.2") + der(0xA0, sd))


# the lists: each a list of (certificate, wrong hash)
LISTS = {
    "S": [("S", False)], "S,I": [("S", False), ("I", False)], "S,I,R": [("S", False), ("I", False), ("R", False)],
    "S,R": [("S", False), ("R", False)], "S,X": [("S", False), ("X", False)], "S,S": [("S", False), ("S", False)],
    "I,S": [("I", False), ("S", False)], "X,S": [("X", False), ("S", False)], "S~": [("S", True)],
    "S~,I,R": [("S", True), ("I", False), ("R", False)],
}


def expected(ids, is_mode, pin):
    """SPEC v0.11 §11 step 7 for one attribute: (status, reason). ids: [(cert, wrong)] as LISTS; is_mode: None, "ok",
    "first_bad", "later_bad" (the issuerSerial of the second ESSCertID wrong)"""
    refused = ("invalid", "not_issued_by_pinned_tsa")
    if len(set(ids)) != len(ids):
        return refused                                     # the same certificate listed twice (closed)
    if ids[0] != ("S", False) or is_mode == "first_bad":
        return refused                                     # the first ESSCertID is the signer's, or the token is refused
    pool = {"S", "I", "R", pin}                            # the token's certificates and the pinned one
    if is_mode == "later_bad" and ids[1][0] in pool:
        return refused                                     # an issuerSerial that does not name the certificate it hashes
    if pin == "X":
        return refused
    allowed = None if len(ids) == 1 else {c for c, _ in ids}
    if pin == "R" and allowed is not None and "I" not in allowed:
        return refused                                     # the path needs I, which the list leaves out
    return ("verified", None)


@NEEDS
class EssCertIdLists(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.td = tempfile.mkdtemp()
        cls.pki = Pki(cls.td)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.td)

    def ids(self, spec, alg, is_mode):
        out = []
        for n, (c, wrong) in enumerate(spec):
            m = None if is_mode is None else "ok"
            if (is_mode == "first_bad" and n == 0) or (is_mode == "later_bad" and n == 1):
                m = "bad"
            out.append(self.pki.ess_id(c, alg, m, wrong))
        return out

    def run_case(self, sid, ver, alg, name, is_mode, pin, attrs_extra=()):
        tok = self.pki.token(sid, [(ver, self.ids(LISTS[name], alg, is_mode)), *attrs_extra])
        v = T.verify_token(tok, DIGEST, "sha256", [pem(self.pki.cert[pin])])
        return v

    def test_generative(self):
        n, bad = 0, []
        for sid in ("ias", "ski"):
            for ver, alg in (("v1", "sha1"), ("v2", "sha256"), ("v2", "sha384")):
                for name, spec in LISTS.items():
                    if alg == "sha384" and len(spec) > 2:
                        continue
                    for is_mode in (None, "ok", "first_bad", "later_bad"):
                        if is_mode == "later_bad" and len(spec) < 2:
                            continue
                        for pin in ("S", "I", "R", "X"):
                            want = expected(spec, is_mode, pin)
                            v = self.run_case(sid, ver, alg, name, is_mode, pin)
                            n += 1
                            if (v["status"], v["reason"]) != want:
                                bad.append((sid, ver, alg, name, is_mode, pin, want, v["status"], v["reason"],
                                            (v["detail"] or "")[:80]))
        self.assertGreater(n, 300)
        self.assertEqual(bad, [], f"{len(bad)} of {n} cases differ")

    def test_positive_control_first_not_the_signer(self):
        """a first ESSCertID that does not identify the signer certificate is refused, whatever follows and whatever
        the pin (RFC 2634 §5.4: the signature MUST be considered invalid)"""
        for sid in ("ias", "ski"):
            for name in ("I,S", "X,S", "S~", "S~,I,R"):
                for pin in ("S", "I", "R"):
                    v = self.run_case(sid, "v2", "sha256", name, "ok", pin)
                    self.assertEqual((v["status"], v["reason"]), ("invalid", "not_issued_by_pinned_tsa"),
                                     (sid, name, pin, v))

    def test_two_attributes_limit_together(self):
        """signingCertificate and signingCertificateV2 both present (RFC 5816 §2.2.1): each limits the path; a certificate
        is usable only when every attribute that lists more than one ESSCertID identifies it"""
        def S(c, a):
            return self.pki.ess_id(c, a, "ok")
        for sid in ("ias", "ski"):
            for v1, v2, want in ((["S"], ["S", "I"], "verified"), (["S", "R"], ["S", "I"], "invalid"),
                                 (["S", "I", "R"], ["S", "I"], "verified"), (["S", "I"], ["I", "S"], "invalid")):
                tok = self.pki.token(sid, [("v1", [S(c, "sha1") for c in v1]), ("v2", [S(c, "sha256") for c in v2])])
                v = T.verify_token(tok, DIGEST, "sha256", [pem(self.pki.cert["R"])])
                self.assertEqual(v["status"], want, (sid, v1, v2, v))

    def test_malformed_later_id_is_refused(self):
        """closed: a later ESSCertID with a hash of the wrong length, an unknown v2 algorithm, or an issuerSerial that is
        not {one directoryName, serialNumber} is refused, never skipped"""
        p = self.pki
        good = p.ess_id("S", "sha256", "ok")
        short = der(0x30, der(0x04, hashlib.sha256(p.cert["I"]).digest()[:20]))
        unknown_alg = der(0x30, der(0x30, oid("1.2.3.4")) + der(0x04, b"\0" * 32))
        two_names = der(0x30, der(0x04, hashlib.sha256(p.cert["I"]).digest())
                        + der(0x30, der(0x30, der(0xA4, issuer_serial_of(p.cert["I"])[0]) * 2)
                              + integer(issuer_serial_of(p.cert["I"])[1])))
        not_seq = der(0x04, hashlib.sha256(p.cert["I"]).digest())
        for sid in ("ias", "ski"):     # pinned I: the path S -> I needs no later ESSCertID, so only the shape refuses
            ok = T.verify_token(p.token(sid, [("v2", [good, p.ess_id("X", "sha256", "ok")])]), DIGEST, "sha256",
                                [pem(p.cert["I"])])
            self.assertEqual(ok["status"], "verified", ok)                 # control
            for later in (short, unknown_alg, two_names, not_seq):
                v = T.verify_token(p.token(sid, [("v2", [good, later])]), DIGEST, "sha256", [pem(p.cert["I"])])
                self.assertEqual((v["status"], v["reason"]), ("invalid", "not_issued_by_pinned_tsa"), (sid, v))

    def test_one_id_still_by_ts_verify(self):
        """issuerAndSerialNumber with one ESSCertID per attribute: openssl ts -verify, as in 0.26.0 (the route is told
        by _ess_lists_more_than_one)"""
        p = self.pki
        tok = T.parse_token(p.token("ias", [("v2", [p.ess_id("S", "sha256", "ok")])]))["token_der"]
        self.assertFalse(T._ess_lists_more_than_one(tok))
        tok2 = T.parse_token(p.token("ias", [("v2", [p.ess_id("S", "sha256", "ok"), p.ess_id("I", "sha256", None)])]))
        self.assertTrue(T._ess_lists_more_than_one(tok2["token_der"]))


@NEEDS
class SectigoVector(unittest.TestCase):
    """the measured case: sectigo.tsr with its CA R41 pinned"""

    def test_each_pin_of_the_chain(self):
        with open(os.path.join(V, "manifest.json")) as f:
            digest = bytes.fromhex(json.load(f)["digest_sha256"])
        with open(os.path.join(V, "sectigo.tsr"), "rb") as f:
            tok = T.parse_token(f.read())["token_der"]
        certs = T._token_certificates(tok)                 # signer R37, CA R41, Root R46 (cross-signed by USERTrust)
        self.assertEqual(len(certs), 3)
        self.assertTrue(T._ess_lists_more_than_one(tok))
        for idx in ([0], [1], [2], [1, 2], [0, 1, 2]):
            v = T.verify_token(tok, digest, None, [b"".join(pem(certs[i]) for i in idx)])
            self.assertEqual((v["status"], v["reason"]), ("verified", None), (idx, v["detail"]))
        other = os.path.join(V, "digicert.signer.pem")      # control: another TSA pinned
        v = T.verify_token(tok, digest, None, [other])
        self.assertEqual((v["status"], v["reason"]), ("invalid", "not_issued_by_pinned_tsa"))


if __name__ == "__main__":
    unittest.main()
