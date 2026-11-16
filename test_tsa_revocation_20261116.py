#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""SPEC v0.10 §11 step 8 (16/11/2026): the TSA certificate's revocation, checked against CRLs the caller pins.

Reported by Athena's review of 16/11/2026 (bench/payment_window, measure M6): `cryptovalid_tsa.verify_token` answered
`verified` for a token issued after its TSA certificate was revoked for key compromise; `openssl ts -verify -crl_check`
with the CRL refused it. Here a CA, a TSA and its CRL are made with openssl on this machine (`openssl ca -revoke`,
`openssl ca -gencrl`), the tokens with `openssl ts -reply`.

Positive control: without `crls` (the code of 0.25.1) the token issued after the revocation is `verified`
(`test_positive_control_without_crls`); with them it is refused. The rule: keyCompromise, cACompromise, aACompromise
make every token of the certificate invalid; another reason leaves valid a token whose genTime is before the revocation
date."""
import base64
import hashlib
import json
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
import evidence_pack as EP  # noqa: E402

try:
    import cryptography  # noqa: F401
    HAVE_CRYPTO = True
except ImportError:
    HAVE_CRYPTO = False
if os.environ.get("CV_REQUIRE_CRYPTO") == "1" and not HAVE_CRYPTO:
    raise RuntimeError("CV_REQUIRE_CRYPTO=1 and cryptography is not importable")
NEEDS = unittest.skipUnless(HAVE_CRYPTO and shutil.which("openssl"), "needs openssl and cryptography")
DIGEST = hashlib.sha256(b"a payment ledger head").digest()


def _run(*cmd, cwd=None):
    subprocess.run(cmd, check=True, capture_output=True, cwd=cwd)


class Lab:
    """a CA with an index (openssl ca), a TSA certificate it issued, tokens and CRLs, all made by openssl"""

    def __init__(self, td, name="lab"):
        self.d = os.path.join(td, name)
        os.makedirs(self.d)
        j = self.j
        with open(j("ca.cnf"), "w") as f:
            f.write(f"[ ca ]\ndefault_ca = CA_default\n[ CA_default ]\ndatabase = {j('index.txt')}\n"
                    f"crlnumber = {j('crlnumber')}\ncertificate = {j('ca.crt')}\nprivate_key = {j('ca.key')}\n"
                    "default_md = sha256\ndefault_crl_days = 1\n[ v3_tsa ]\nextendedKeyUsage = critical,timeStamping\n"
                    "basicConstraints = CA:FALSE\n")
        with open(j("tsa.cnf"), "w") as f:
            f.write(f"[ tsa ]\ndefault_tsa = t1\n[ t1 ]\nserial = {j('serial')}\ncrypto_device = builtin\n"
                    f"signer_cert = {j('tsa.crt')}\ncerts = {j('ca.crt')}\nsigner_key = {j('tsa.key')}\n"
                    "signer_digest = sha256\ndefault_policy = 1.2.3.4.1\ndigests = sha256\naccuracy = secs:1\n"
                    "ordering = yes\ntsa_name = no\ness_cert_id_chain = no\ness_cert_id_alg = sha256\n")
        open(j("index.txt"), "w").close()
        for n in ("crlnumber", "serial"):
            with open(j(n), "w") as f:
                f.write("01\n")
        _run("openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
             "-keyout", j("ca.key"), "-out", j("ca.crt"), "-subj", f"/CN={name}-ca", "-days", "2")
        _run("openssl", "req", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-keyout", j("tsa.key"),
             "-out", j("tsa.csr"), "-subj", f"/CN={name}-tsa")
        _run("openssl", "x509", "-req", "-in", j("tsa.csr"), "-CA", j("ca.crt"), "-CAkey", j("ca.key"), "-CAcreateserial",
             "-out", j("tsa.crt"), "-days", "2", "-extfile", j("ca.cnf"), "-extensions", "v3_tsa")

    def j(self, n):
        return os.path.join(self.d, n)

    def token(self, digest=None):
        _run("openssl", "ts", "-query", "-digest", (digest or DIGEST).hex(), "-sha256", "-cert", "-out", self.j("q.tsq"))
        _run("openssl", "ts", "-reply", "-queryfile", self.j("q.tsq"), "-config", self.j("tsa.cnf"), "-section", "t1",
             "-out", self.j("r.tsr"))
        with open(self.j("r.tsr"), "rb") as f:
            return f.read()

    def revoke(self, reason=None):
        _run("openssl", "ca", "-config", self.j("ca.cnf"), "-revoke", self.j("tsa.crt"),
             *(["-crl_reason", reason] if reason else []))

    def crl(self, der=False):
        _run("openssl", "ca", "-config", self.j("ca.cnf"), "-gencrl", "-out", self.j("crl.pem"))
        if der:
            _run("openssl", "crl", "-in", self.j("crl.pem"), "-outform", "DER", "-out", self.j("crl.der"))
            return self.j("crl.der")
        return self.j("crl.pem")

    def openssl_crl_check(self, tok):
        p = self.j("t.tsr")
        with open(p, "wb") as f:
            f.write(tok)
        with open(self.j("ca.crt"), "rb") as f, open(self.j("crl.pem"), "rb") as g, open(self.j("ca+crl.pem"), "wb") as h:
            h.write(f.read() + g.read())   # openssl ts has no -CRLfile: the CRL goes into the CAfile
        r = subprocess.run(["openssl", "ts", "-verify", "-in", p, "-digest", DIGEST.hex(), "-CAfile", self.j("ca+crl.pem"),
                            "-untrusted", self.j("tsa.crt"), "-crl_check"], capture_output=True)
        return r.returncode == 0


def tick():
    time.sleep(1.2)   # a CRL's revocation date has one-second resolution, a token's genTime too


@NEEDS
class Revocation(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.td)

    def check(self, lab, tok, crls=None):
        return T.verify_token(tok, DIGEST, "sha256", [lab.j("ca.crt")], crls)

    def test_positive_control_without_crls(self):
        lab = Lab(self.td)
        lab.revoke("keyCompromise")
        tick()
        tok = lab.token()
        crl = lab.crl()
        v = self.check(lab, tok)
        self.assertEqual(v["status"], "verified")           # the defect Athena measured: revocation not seen
        self.assertNotIn("revocation", v)                    # and the outcome is the one of 0.25.1
        self.assertFalse(lab.openssl_crl_check(tok))         # openssl with the CRL refuses it
        v = self.check(lab, tok, [crl])
        self.assertEqual((v["status"], v["reason"], v["counts_as_timestamp"]), ("invalid", "tsa_certificate_revoked", False))

    def test_not_revoked(self):
        lab = Lab(self.td)
        tok = lab.token()
        for crl in (lab.crl(), lab.crl(der=True)):
            v = self.check(lab, tok, [crl])
            self.assertEqual((v["status"], v["revocation"]["status"]), ("verified", "not_revoked"), v)
        self.assertTrue(lab.openssl_crl_check(tok))

    def test_compromise_reasons_invalidate_every_token(self):
        for reason in ("keyCompromise", "CACompromise"):
            lab = Lab(self.td, reason)
            before = lab.token()
            tick()
            lab.revoke(reason)
            tick()
            after = lab.token()
            crl = lab.crl()
            for tok in (before, after):
                v = self.check(lab, tok, [crl])
                self.assertEqual((v["status"], v["reason"]), ("invalid", "tsa_certificate_revoked"), (reason, v))
                self.assertEqual(v["revocation"]["status"], "revoked")

    def test_other_reasons_keep_earlier_tokens(self):
        for reason in ("superseded", "cessationOfOperation", "affiliationChanged", None):
            lab = Lab(self.td, str(reason))
            before = lab.token()
            tick()
            lab.revoke(reason)
            tick()
            after = lab.token()
            crl = lab.crl()
            v = self.check(lab, before, [crl])
            self.assertEqual((v["status"], v["revocation"]["status"]), ("verified", "revoked_after_gen_time"), (reason, v))
            v = self.check(lab, after, [crl])
            self.assertEqual((v["status"], v["reason"]), ("invalid", "tsa_certificate_revoked"), (reason, v))

    def test_remove_from_crl_is_unknown(self):
        lab = Lab(self.td)
        tok = lab.token()
        tick()
        lab.revoke("removeFromCRL")
        v = self.check(lab, tok, [lab.crl()])
        self.assertEqual((v["status"], v["reason"], v["revocation"]["status"]), ("invalid", "tsa_revocation_unknown", "unknown"))

    def test_revocation_unknown(self):
        lab, other = Lab(self.td, "a"), Lab(self.td, "b")
        tok = lab.token()
        v = self.check(lab, tok, [other.crl()])                      # a CRL of another CA
        self.assertEqual((v["status"], v["reason"]), ("invalid", "tsa_revocation_unknown"))
        crl = lab.crl(der=True)
        with open(crl, "rb") as f:
            b = bytearray(f.read())
        b[-3] ^= 0x01                                                # its signature broken
        v = self.check(lab, tok, [bytes(b)])
        self.assertEqual((v["status"], v["reason"]), ("invalid", "tsa_revocation_unknown"))
        with open(lab.crl(), "rb") as f:
            good = f.read()                                          # the CRL before the revocation, kept as bytes
        lab.revoke("superseded")
        tick()
        later = lab.token()
        v = self.check(lab, later, [good, lab.crl()])                # two CRLs that disagree
        self.assertEqual((v["status"], v["reason"]), ("invalid", "tsa_revocation_unknown"))
        v = T.verify_token(tok, DIGEST, "sha256", [lab.j("ca.crt"), other.j("ca.crt")], [other.crl()])
        self.assertEqual(v["reason"], "tsa_revocation_unknown")      # the other CA pinned too: still not the issuer

    def test_signer_not_readable_here(self):
        """the token's certificates field in BER (a certificate with a length in long form), which openssl reads and the
        DER reader of this module does not: the signer certificate is not found for step 8, so revocation is unknown,
        never assumed absent. The CMS signature does not cover the certificates field, so the token still verifies."""
        lab = Lab(self.td)
        tok = T._token_of(lab.token())

        def tlv(tag, v, extra=0):
            n = len(v)
            k = (n.bit_length() + 7) // 8 + extra
            ln = bytes([n]) if n < 0x80 and not extra else bytes([0x80 | k]) + n.to_bytes(k, "big")
            return bytes([tag]) + ln + v
        ci = T._der_items(T._der_one(tok, "ci", 0x30), "ci")
        sd = T._der_items(T._der_one(ci[1][1], "sd", 0x30), "sd")
        items = []
        for tag, val in sd:
            if tag == 0xA0:
                val = b"".join(tlv(t, v, extra=1) for t, v in T._der_items(val, "certs"))
            items.append(tlv(tag, val))
        ber = tlv(0x30, tlv(ci[0][0], ci[0][1]) + tlv(0xA0, tlv(0x30, b"".join(items))))
        self.assertEqual(T._token_certificates(ber), [])                   # not read here
        self.assertEqual(self.check(lab, ber)["status"], "verified")        # openssl reads it: steps 1-7 pass
        v = self.check(lab, ber, [lab.crl()])
        self.assertEqual((v["status"], v["reason"], v["revocation"]["detail"]),
                         ("invalid", "tsa_revocation_unknown", "signer certificate not found"))
        v = T.verify_token(ber, DIGEST, "sha256", [lab.j("ca.crt"), lab.j("tsa.crt")], [lab.crl()])
        self.assertEqual(v["revocation"]["status"], "not_revoked")         # control: the pinned TSA certificate is found

    def test_caller_errors(self):
        lab = Lab(self.td)
        tok = lab.token()
        with open(lab.j("ca.crt"), "rb") as f:
            cert = f.read()
        with open(lab.crl(), "rb") as f:
            crl_bytes = f.read()
        for bad in ([], [b""], [cert], [b"not a crl"], lab.crl(), crl_bytes, {lab.crl()}, [lab.j("absent")], [self.td], [1]):
            with self.assertRaises(ValueError, msg=repr(bad)[:40]):
                self.check(lab, tok, bad)
        with open(lab.crl(), "rb") as f:
            pem = f.read()
        with self.assertRaises(ValueError):
            self.check(lab, tok, [pem + pem])                        # two blocks in one item
        with self.assertRaises(ValueError):
            T.verify_token(tok, DIGEST, "sha256", None, [lab.crl()])   # a CRL needs pinned certificates

    def test_steps_before_are_unchanged(self):
        lab = Lab(self.td)
        tok = lab.token()
        crl = lab.crl()
        v = T.verify_token(tok, hashlib.sha256(b"other").digest(), "sha256", [lab.j("ca.crt")], [crl])
        self.assertEqual(v["reason"], "imprint_mismatch")
        other = Lab(self.td, "other")
        v = T.verify_token(tok, DIGEST, "sha256", [other.j("ca.crt")], [other.crl()])
        self.assertEqual(v["reason"], "not_issued_by_pinned_tsa")
        self.assertNotIn("revocation", v)

    def test_pack_with_crls(self):
        import contextlib
        import io
        lab = Lab(self.td)
        pack = os.path.join(self.td, "pack")
        with contextlib.redirect_stdout(io.StringIO()):
            EP.build_pack([os.path.join(ROOT, "examples", "sample_ledger.jsonl")], pack, subject="revocation")
        with open(os.path.join(pack, "MANIFEST.json")) as f:
            m = json.load(f)
        tok = lab.token(bytes.fromhex(m["manifest_digest_sha256"]))
        m["rfc3161_timestamp"] = {"anchored": True, "tsa": "local", "tsr_b64": base64.b64encode(tok).decode()}
        with open(os.path.join(pack, "MANIFEST.json"), "w") as f:
            json.dump(m, f)
        pins = [lab.j("ca.crt")]
        r0 = EP.verify_pack(pack, tsa_certs=pins)
        self.assertNotIn("revocation", r0["rfc3161"]["tsa_check"])                 # without CRLs: as in 0.25.1
        r = EP.verify_pack(pack, tsa_certs=pins, tsa_crls=[lab.crl()])
        self.assertEqual((r["valid"], r["states"]["time_anchor"]["state"], r["rfc3161"]["tsa_check"]["revocation"]["status"]),
                         (True, "verified", "not_revoked"))
        tick()
        lab.revoke("keyCompromise")
        r = EP.verify_pack(pack, tsa_certs=pins, tsa_crls=[lab.crl()])
        self.assertEqual((r["valid"], r["states"]["time_anchor"]["state"], r["states"]["time_anchor"]["reasons"]),
                         (False, "contradicted", ["token_invalid"]))
        with self.assertRaises(ValueError):
            EP.verify_pack(pack, tsa_crls=[lab.crl()])


if __name__ == "__main__":
    unittest.main()
