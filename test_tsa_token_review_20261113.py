#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Roberto Locatelli
"""SPEC_EVIDENCE_FORMAT.md §11 (v0.6), review of 2026-11-13: tokens built here field by field (CMS SignedData written by
hand, signed with `cryptography`) and checked by `cryptovalid_tsa.verify_token` against a pinned certificate.
Each case below was `verified` (or a traceback, or a hang) on the draft of §11 before this review:
- a token signed with ecdsa-with-SHA1 or md5WithRSAEncryption (SignerInfo digest algorithm outside the closed list);
- a TSTInfo with a critical extension;
- a SignerInfo with a non-minimal length (BER) inside it, or without signedAttrs (it was signature_only unpinned);
- a token requested with certReq FALSE (no certificate inside) was `signature_invalid` even with the TSA pinned;
- an openssl whose `ts -verify` exits 0 without saying "Verification: OK" made a token of a TSA made on the spot verified;
- `--tsa-cert` missing, a directory, empty, not a certificate: a traceback; a FIFO: read forever;
- the pack report said "Token cryptographically verified" for a token of a TSA made on the spot or with its signature altered.
"""
import base64
import datetime
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import cryptovalid_tsa as T  # noqa: E402

try:
    from cryptography import x509
    from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
    HAVE_CRYPTO = True
except ImportError:   # pragma: no cover
    HAVE_CRYPTO = False
if os.environ.get("CV_REQUIRE_CRYPTO") == "1" and not HAVE_CRYPTO:
    raise SystemExit("CV_REQUIRE_CRYPTO=1 and cryptography is not importable")
HAVE_OPENSSL = shutil.which("openssl") is not None


def _len(n):
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b


def tlv(t, v):
    return bytes([t]) + _len(len(v)) + v


def seq(*a):
    return tlv(0x30, b"".join(a))


def set_(*a):
    return tlv(0x31, b"".join(sorted(a)))


def integer(n):
    b = n.to_bytes((n.bit_length() + 7) // 8 or 1, "big")
    return tlv(0x02, b"\x00" + b if b[0] & 0x80 else b)


def oid(s):
    a = [int(x) for x in s.split(".")]
    out = bytes([40 * a[0] + a[1]])
    for x in a[2:]:
        enc = [x & 0x7F]
        x >>= 7
        while x:
            enc.append(0x80 | (x & 0x7F))
            x >>= 7
        out += bytes(reversed(enc))
    return tlv(0x06, out)


NULL = b"\x05\x00"
SHA256, SHA1, MD5 = "2.16.840.1.101.3.4.2.1", "1.3.14.3.2.26", "1.2.840.113549.2.5"
TSTINFO, SIGNED_DATA = "1.2.840.113549.1.9.16.1.4", "1.2.840.113549.1.7.2"
DIGEST = hashlib.sha256(b"review of SPEC 11, 2026-11-13").digest()


@unittest.skipUnless(HAVE_CRYPTO and HAVE_OPENSSL, "needs cryptography and openssl")
class HandBuiltTokens(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.now = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)
        cls.d = tempfile.mkdtemp(prefix="cv-review-")
        cls.k = ec.generate_private_key(ec.SECP256R1())
        cls.c = cls._cert("Review TSA", cls.k)
        cls.k_rsa = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.c_rsa = cls._cert("Review RSA TSA", cls.k_rsa)
        cls.pin = cls._pem("pin.pem", cls.c)
        cls.pin_rsa = cls._pem("pin_rsa.pem", cls.c_rsa)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.d, ignore_errors=True)

    @classmethod
    def _cert(cls, cn, key):
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
        return (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(cls.now - datetime.timedelta(days=1)).not_valid_after(cls.now + datetime.timedelta(days=2))
                .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.TIME_STAMPING]), critical=True)
                .sign(key, hashes.SHA256()))

    @classmethod
    def _pem(cls, name, cert):
        p = os.path.join(cls.d, name)
        with open(p, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        return p

    def tstinfo(self, extra=b""):
        return seq(integer(1), oid("1.2.3.4.1"), seq(seq(oid(SHA256), NULL), tlv(0x04, DIGEST)), integer(7),
                   tlv(0x18, self.now.strftime("%Y%m%d%H%M%SZ").encode()), extra)

    def token(self, key, cert, tst, h="sha256", signed_attrs=True, certs=True, si_version=b"\x02\x01\x01"):
        hobj, hoid = {"sha256": (hashes.SHA256(), SHA256), "sha1": (hashes.SHA1(), SHA1), "md5": (hashes.MD5(), MD5)}[h]
        der = cert.public_bytes(serialization.Encoding.DER)
        sign = (lambda data: key.sign(data, padding.PKCS1v15(), hobj)) if isinstance(key, rsa.RSAPrivateKey) \
            else (lambda data: key.sign(data, ec.ECDSA(hobj)))
        if isinstance(key, rsa.RSAPrivateKey):
            salg = seq(oid({"sha256": "1.2.840.113549.1.1.11", "sha1": "1.2.840.113549.1.1.5",
                            "md5": "1.2.840.113549.1.1.4"}[h]), NULL)
        else:
            salg = seq(oid({"sha256": "1.2.840.10045.4.3.2", "sha1": "1.2.840.10045.4.1"}[h]))
        if signed_attrs:
            attrs = set_(seq(oid("1.2.840.113549.1.9.3"), set_(oid(TSTINFO))),
                         seq(oid("1.2.840.113549.1.9.4"), set_(tlv(0x04, hashlib.new(h, tst).digest()))),
                         seq(oid("1.2.840.113549.1.9.16.2.47"), set_(seq(seq(seq(tlv(0x04, hashlib.sha256(der).digest())))))))
            sig, sa = sign(attrs), b"\xa0" + attrs[1:]
        else:
            sig, sa = sign(tst), b""
        si_body = si_version + seq(cert.issuer.public_bytes(), integer(cert.serial_number)) + seq(oid(hoid), NULL) + sa \
            + salg + tlv(0x04, sig)
        si = b"\x30" + _len(len(si_body)) + si_body
        sd = seq(integer(3), set_(seq(oid(hoid), NULL)), seq(oid(TSTINFO), tlv(0xA0, tlv(0x04, tst))),
                 tlv(0xA0, der) if certs else b"", tlv(0x31, si))
        return seq(oid(SIGNED_DATA), tlv(0xA0, sd))

    def outcome(self, tok, pin):
        r = T.verify_token(tok, DIGEST, "sha256", [pin] if pin else None)
        return r["status"], r["reason"]

    def test_control_hand_built_token_is_verified(self):
        # the builder makes tokens openssl accepts: without this control the refusals below would prove nothing
        self.assertEqual(self.outcome(self.token(self.k, self.c, self.tstinfo()), self.pin), ("verified", None))
        self.assertEqual(self.outcome(self.token(self.k_rsa, self.c_rsa, self.tstinfo()), self.pin_rsa), ("verified", None))
        noncrit = tlv(0xA1, seq(oid("1.2.3.4.99"), tlv(0x04, NULL)))
        self.assertEqual(self.outcome(self.token(self.k, self.c, self.tstinfo(noncrit)), self.pin), ("verified", None))

    def test_signature_digest_outside_the_closed_list(self):
        for key, cert, pin, h in ((self.k, self.c, self.pin, "sha1"), (self.k_rsa, self.c_rsa, self.pin_rsa, "sha1"),
                                  (self.k_rsa, self.c_rsa, self.pin_rsa, "md5")):
            with self.subTest(h=h, key=type(key).__name__):
                tok = self.token(key, cert, self.tstinfo(), h=h)
                self.assertEqual(self.outcome(tok, pin), ("invalid", "hash_algorithm_not_allowed"))
                self.assertEqual(self.outcome(tok, None), ("invalid", "hash_algorithm_not_allowed"))

    def test_critical_tstinfo_extension(self):
        crit = tlv(0xA1, seq(oid("1.2.3.4.99"), b"\x01\x01\xff", tlv(0x04, NULL)))
        tok = self.token(self.k, self.c, self.tstinfo(crit))
        self.assertEqual(self.outcome(tok, self.pin), ("invalid", "tstinfo_unknown_element"))
        false_explicit = tlv(0xA1, seq(oid("1.2.3.4.99"), b"\x01\x01\x00", tlv(0x04, NULL)))   # DEFAULT FALSE written: not DER
        self.assertEqual(self.outcome(self.token(self.k, self.c, self.tstinfo(false_explicit)), self.pin),
                         ("invalid", "malformed"))
        self.assertEqual(self.outcome(self.token(self.k, self.c, self.tstinfo(tlv(0xA1, b""))), self.pin),
                         ("invalid", "malformed"))

    def test_signer_info_read_closed(self):
        ber = self.token(self.k, self.c, self.tstinfo(), si_version=b"\x02\x81\x01\x01")
        self.assertEqual(self.outcome(ber, self.pin), ("invalid", "malformed"))
        no_attrs = self.token(self.k, self.c, self.tstinfo(), signed_attrs=False)
        self.assertEqual(self.outcome(no_attrs, None), ("invalid", "malformed"))

    def test_validity_read_at_gen_time(self):
        # mutants left alive by the suite of c1e0943: `-attime genTime` removed (a genTime before the certificate's
        # notBefore was then verified), indefinite length read as "the rest of the buffer"
        early = self.tstinfo().replace(tlv(0x18, self.now.strftime("%Y%m%d%H%M%SZ").encode()),
                                       tlv(0x18, (self.now - datetime.timedelta(days=5)).strftime("%Y%m%d%H%M%SZ").encode()))
        self.assertEqual(self.outcome(self.token(self.k, self.c, early), self.pin), ("invalid", "not_issued_by_pinned_tsa"))
        self.assertEqual(self.outcome(self.token(self.k, self.c, self.tstinfo()), self.pin), ("verified", None))

    def test_indefinite_length_inside_tstinfo(self):
        acc = b"\x30\x80" + integer(1) + b"\x00\x00"          # accuracy, last element, BER indefinite length
        self.assertEqual(self.outcome(self.token(self.k, self.c, self.tstinfo(acc)), self.pin), ("invalid", "malformed"))

    @unittest.skipUnless(os.name == "posix", "a shell wrapper")
    def test_ts_verify_killed_by_a_signal_is_a_check_not_run(self):
        from verifier import CheckNotRun
        b = os.path.join(self.d, "binkill")
        os.makedirs(b, exist_ok=True)
        real = shutil.which("openssl")
        with open(os.path.join(b, "openssl"), "w") as f:
            f.write('#!/bin/sh\nif [ "$1" = ts ]; then kill -9 $$; fi\nexec "%s" "$@"\n' % real)
        os.chmod(os.path.join(b, "openssl"), 0o755)
        old = os.environ["PATH"]
        os.environ["PATH"] = b + os.pathsep + old
        try:
            with self.assertRaises(CheckNotRun):
                T.verify_token(self.token(self.k, self.c, self.tstinfo()), DIGEST, "sha256", [self.pin])
        finally:
            os.environ["PATH"] = old

    def test_lotl_signer_set(self):
        import cryptovalid_lotl as L
        bad = bytearray(self.token(self.k, self.c, self.tstinfo()))
        bad[-1] ^= 1
        self.assertEqual(L.signer_fingerprints(bytes(bad)), set())
        der = self.c.public_bytes(serialization.Encoding.DER)
        self.assertEqual(L.signer_fingerprints(self.token(self.k, self.c, self.tstinfo())), {hashlib.sha256(der).hexdigest()})

    def test_token_without_certificate_checked_with_the_pin(self):
        tok = self.token(self.k, self.c, self.tstinfo(), certs=False)
        self.assertEqual(self.outcome(tok, self.pin), ("verified", None))
        self.assertEqual(self.outcome(tok, None), ("invalid", "signature_invalid"))   # nothing to check it with
        self.assertEqual(self.outcome(tok, self.pin_rsa), ("invalid", "signature_invalid"))

    @unittest.skipUnless(os.name == "posix", "a shell wrapper")
    def test_ts_verify_exit_0_without_ok_is_not_verified(self):
        other = ec.generate_private_key(ec.SECP256R1())
        tok = self.token(other, self._cert("Review TSA", other), self.tstinfo())   # same name, another key
        self.assertEqual(self.outcome(tok, self.pin), ("invalid", "not_issued_by_pinned_tsa"))
        b = os.path.join(self.d, "bin")
        os.makedirs(b, exist_ok=True)
        real = shutil.which("openssl")
        with open(os.path.join(b, "openssl"), "w") as f:
            f.write('#!/bin/sh\nif [ "$1" = ts ]; then exit 0; fi\nexec "%s" "$@"\n' % real)
        os.chmod(os.path.join(b, "openssl"), 0o755)
        old = os.environ["PATH"]
        os.environ["PATH"] = b + os.pathsep + old
        try:
            self.assertEqual(self.outcome(tok, self.pin), ("invalid", "not_issued_by_pinned_tsa"))
        finally:
            os.environ["PATH"] = old


class IngestLotlNotEvaluated(unittest.TestCase):
    def test_openssl_absent_tokens_not_sent_to_the_lotl(self):
        # mutant left alive: tokens `not_evaluated` (openssl absent) passed to the LOTL became "indeterminate" there
        import cryptovalid_ingest as ing
        import cryptovalid_lotl as L
        from unittest import mock
        d = tempfile.mkdtemp(prefix="cv-review-lotl-")
        try:
            w = ing.Ingestor(d, batch_size=4)
            for i in range(4):
                w.append({"i": i})
            w.seal()
            w.close(seal=False)
            seg = sorted(f for f in os.listdir(d) if f.endswith(".jsonl"))[0]
            with open(os.path.join(d, seg + ".sth.tsr"), "wb") as f:
                f.write(b"token")
            ne = {"status": "not_evaluated", "counts_as_timestamp": False, "reason": "openssl_absent", "detail": None,
                  "tst_info": None, "imprint_ok": True, "signer_sha256": None, "note": "openssl absent"}
            with mock.patch.object(T, "verify_token", return_value=ne), \
                    mock.patch.object(T, "token_signer", return_value=("not_evaluated", None, "openssl absent")), \
                    mock.patch.object(L, "load_qualified_status", return_value=({"ab" * 32}, [], {})):
                r = ing.verify_archive(d, lotl_check=True)
            self.assertEqual(r["timestamped_segments"], 0)
            self.assertIsNone(r["eidas_qualified_segments"])
            self.assertFalse(any(w.startswith("tsa_qualification_indeterminate") for w in r["warnings"]), r["warnings"])
            self.assertTrue(any(w.startswith("tsa_not_evaluated: 1 ") for w in r["warnings"]), r["warnings"])
        finally:
            shutil.rmtree(d, ignore_errors=True)


@unittest.skipUnless(HAVE_OPENSSL, "needs openssl")
class TsaCertOption(unittest.TestCase):
    def test_bad_tsa_cert_is_a_usage_error(self):
        d = tempfile.mkdtemp(prefix="cv-review-cli-")
        try:
            led = os.path.join(d, "l.jsonl")
            with open(led, "w") as f:
                f.write("")
            empty, notcert, fifo = os.path.join(d, "e.pem"), os.path.join(d, "n.pem"), os.path.join(d, "fifo")
            open(empty, "w").close()
            with open(notcert, "w") as f:
                f.write("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n")
            bad = [os.path.join(d, "missing.pem"), d, empty, notcert]
            if hasattr(os, "mkfifo"):
                os.mkfifo(fifo)
                bad.append(fifo)
            cmds = [[sys.executable, "-B", os.path.join(HERE, "cryptovalid_ingest.py"), "verify", d],
                    [sys.executable, "-B", os.path.join(HERE, "eidas_ledger_check.py"), led],
                    [sys.executable, "-B", os.path.join(HERE, "cryptovalid_tsa.py"), "00" * 32, "--tsa", "http://127.0.0.1:9/"]]
            for cmd in cmds:
                for pin in bad:
                    with self.subTest(cmd=os.path.basename(cmd[2]), pin=os.path.basename(pin)):
                        p = subprocess.run(cmd + ["--tsa-cert", pin], capture_output=True, text=True, timeout=60)
                        self.assertEqual(p.returncode, 2, p.stderr[-300:])
                        self.assertNotIn("Traceback", p.stderr)
                        self.assertIn("tsa_certs", p.stderr)
        finally:
            shutil.rmtree(d, ignore_errors=True)


@unittest.skipUnless(HAVE_OPENSSL, "needs openssl")
class PackReportRow(unittest.TestCase):
    """cryptovalid_report: the RFC 3161 row shows the outcome of verify_token, not the pack's imprint check alone."""

    def test_report_row(self):
        import evidence_pack as EP
        import cryptovalid_report as REP
        d = tempfile.mkdtemp(prefix="cv-review-pack-")
        orig = EP._rfc3161_stamp
        try:
            cnf = os.path.join(d, "tsa.cnf")
            with open(cnf, "w") as f:
                f.write("[req]\ndistinguished_name=dn\nprompt=no\n[dn]\nCN=TSA made here\n[ext]\n"
                        "extendedKeyUsage=critical,timeStamping\n[tsa]\ndefault_tsa=t1\n[t1]\nserial=%s\nsigner_cert=%s\n"
                        "signer_key=%s\nsigner_digest=sha256\ndefault_policy=1.2.3.4.1\ndigests=sha256\n"
                        "ess_cert_id_alg=sha256\n" % (os.path.join(d, "serial"), os.path.join(d, "tsa.crt"),
                                                    os.path.join(d, "tsa.key")))
            with open(os.path.join(d, "serial"), "w") as f:
                f.write("01\n")
            subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
                            "-keyout", os.path.join(d, "tsa.key"), "-out", os.path.join(d, "tsa.crt"), "-days", "2",
                            "-config", cnf, "-extensions", "ext"], check=True, capture_output=True)

            def stamp(digest_hex, url, timeout=20, alter=False):
                q, r = os.path.join(d, "q.tsq"), os.path.join(d, "r.tsr")
                subprocess.run(["openssl", "ts", "-query", "-digest", digest_hex, "-sha256", "-cert", "-out", q],
                               check=True, capture_output=True)
                subprocess.run(["openssl", "ts", "-reply", "-config", cnf, "-queryfile", q, "-out", r],
                               check=True, capture_output=True)
                with open(r, "rb") as f:
                    b = bytearray(f.read())
                if alter:
                    b[-1] ^= 1   # the last byte of the signature value
                return {"anchored": True, "tsa": "http://tsa.made.here", "tsr_b64": base64.b64encode(bytes(b)).decode()}

            led = os.path.join(d, "l.jsonl")
            e = {"idx": 0, "ts": "2026-11-13T00:00:00Z", "data": {"a": 1}, "prev_hash": "0" * 64}
            e["self_hash"] = hashlib.sha256(json.dumps(e, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
            with open(led, "w") as f:
                f.write(json.dumps(e) + "\n")
            for alter, badge in ((False, "IMPRINT BOUND, TSA NOT PINNED"), (True, "TOKEN INVALID")):
                with self.subTest(alter=alter):
                    EP._rfc3161_stamp = lambda dh, url, timeout=20, alter=alter: stamp(dh, url, timeout, alter)
                    out = os.path.join(d, "pack%d" % alter)
                    EP.build_pack([led], out, tsa_url="http://tsa.made.here")
                    self.assertIs(EP.verify_pack(out)["rfc3161"]["verified"], True)   # the pack's imprint check, unchanged
                    r = REP.generate_report(out, html_only=True)
                    with open(r["html"], encoding="utf-8") as f:
                        html = f.read()
                    self.assertNotIn("cryptographically verified", html)
                    self.assertIn(badge, html)
        finally:
            EP._rfc3161_stamp = orig
            shutil.rmtree(d, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
