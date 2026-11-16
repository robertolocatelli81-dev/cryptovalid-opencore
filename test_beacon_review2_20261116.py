# SPDX-License-Identifier: AGPL-3.0-or-later
"""Tests added after the second review of SPEC v0.10 §18-§19 (16/11/2026): the Unicode version of the committed values,
a payee entity as the only party identifier, two CRL extensions, the scope sentences against the SPEC, the `ts` and the
size of one entry. Each was written against a mutant that the suite let live, or a defect measured by the review."""
import datetime
import json
import os
import re
import shutil
import tempfile
import time
import unittest

import cryptovalid_beacon as B
import verifier
from test_beacon_20261116 import PIDS, beacon_of, pulse, record_salt_of
from test_tsa_revocation_20261116 import DIGEST, NEEDS, Lab

ROOT = os.path.dirname(os.path.abspath(__file__))


class UnicodeVersion(unittest.TestCase):
    def test_a_value_outside_unicode_13_is_refused(self):
        salt = bytes(16)
        # U+1E08F (Unicode 15.0) before U+0316: NFC reorders it in Unicode 15.1, not in 13.0; U+105D2 U+0307 (Unicode 16.0)
        # is composed by Unicode 17.0; U+0378 is unassigned; U+D800 alone is not UTF-8
        for v in ("a\U0001e08f̖", "Ra\U000105d2̇", "x͸", "x\ud800"):
            with self.assertRaises(ValueError, msg=ascii(v)):
                B.commitment("payer_name_commitment", salt, v)
            d = json.dumps({"member": "payer_name_commitment", "salt": "00" * 16, "value": v}).encode()
            with self.assertRaises(B.Refused, msg=ascii(v)) as cm:
                B.parse_disclosure(d)
            self.assertEqual(cm.exception.reason, "disclosure_malformed")

    def test_unicode_13_code_points_still_normalise(self):
        salt = bytes(16)
        self.assertEqual(B.commitment("payee_name_commitment", salt, "Café"),
                         B.commitment("payee_name_commitment", salt, "Café"))
        # added in Unicode 13.0 (U+08BE, U+1F6D7) and private use: assigned; U+1F6D8 (Unicode 14.0): not
        self.assertTrue(B.portable("ࢾ\U0001f6d7\U000f0000"))
        self.assertFalse(B.portable("\U0001f6d8"))


class PartyIdentifier(unittest.TestCase):
    def test_payee_entity_id_alone_is_a_party_identifier(self):
        d = {"profile": B.PAYMENT_PROFILE, "payment_id": PIDS[0], "amount": "1.00", "currency": "EUR",
             "beacons": [beacon_of(pulse(2030303))], "record_salt": record_salt_of(1), "payee_entity_id": "EXAMPLE0001"}
        self.assertEqual(B.check_payment(dict(d)), d)
        del d["payee_entity_id"]
        with self.assertRaises(B.Refused) as cm:
            B.check_payment(d)
        self.assertEqual(cm.exception.detail.split(":")[0], "party_identifier_missing")


@NEEDS
class CrlExtensions(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.mkdtemp()
        self.lab = Lab(self.td)
        self.tok = self.lab.token()
        time.sleep(1.2)   # the CRL is issued after genTime (whole seconds)

    def tearDown(self):
        shutil.rmtree(self.td)

    def crl(self, entry_ext=False, freshest=False):
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.x509.oid import NameOID
        with open(self.lab.j("ca.crt"), "rb") as f:
            ca = x509.load_pem_x509_certificate(f.read())
        with open(self.lab.j("ca.key"), "rb") as f:
            key = serialization.load_pem_private_key(f.read(), None)
        with open(self.lab.j("tsa.crt"), "rb") as f:
            tsa = x509.load_pem_x509_certificate(f.read())
        now = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)
        b = x509.CertificateRevocationListBuilder().issuer_name(ca.subject).last_update(now).next_update(
            now + datetime.timedelta(days=1))
        if freshest:
            b = b.add_extension(x509.FreshestCRL([x509.DistributionPoint(
                [x509.UniformResourceIdentifier("http://crl.example/delta.crl")], None, None, None)]), critical=False)
        if entry_ext:   # an indirect CRL's entry: the certificate of another issuer with the same serial
            other = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "another-ca")])
            b = b.add_revoked_certificate(x509.RevokedCertificateBuilder().serial_number(tsa.serial_number)
                                          .revocation_date(now).add_extension(
                x509.CertificateIssuer([x509.DirectoryName(other)]), critical=True).build())
        p = os.path.join(self.td, "x.crl")
        with open(p, "wb") as f:
            f.write(b.sign(key, hashes.SHA256()).public_bytes(serialization.Encoding.PEM))
        return p

    def check(self, crl):
        import cryptovalid_tsa as T
        return T.verify_token(self.tok, DIGEST, "sha256", [self.lab.j("ca.crt")], [crl])

    def test_an_entry_extension_not_processed_is_unknown(self):
        v = self.check(self.crl(entry_ext=True))
        self.assertEqual((v["status"], v["reason"]), ("invalid", "tsa_revocation_unknown"), v)

    def test_freshest_crl_is_read(self):
        v = self.check(self.crl(freshest=True))
        self.assertEqual((v["status"], v["revocation"]["status"]), ("verified", "not_revoked"), v)


class ScopeSentences(unittest.TestCase):
    def test_every_scope_sentence_is_the_one_of_rule_7(self):
        with open(os.path.join(ROOT, "SPEC_EVIDENCE_FORMAT.md"), encoding="utf-8") as f:
            s = f.read()
        sec = " ".join(s[s.index("**7. Scope, closed.**"):s.index("`record_complete` is true only")].split())
        names = re.findall(r"- (?:does not )?proves? `([a-z_]+)`", sec)
        self.assertEqual(sorted(names), sorted(B.SCOPE))
        for k, v in B.SCOPE.items():
            m = re.search(r"`%s`[^:]*: \"([^\"]+)\"" % k, sec)
            self.assertEqual(m and m.group(1), v, k)


class OneEntry(unittest.TestCase):
    def entry(self, **change):
        e = {"idx": 1, "ts": "2026-11-16T13:05:30Z", "data": {"x": 1}, "prev_hash": "0" * 64}
        e.update(change)
        e["self_hash"] = verifier.hash_with("sha256", verifier.canonical_payload(e))
        return json.dumps(e).encode()

    def test_ts_not_a_string_is_malformed(self):
        B.read_entry(self.entry())
        for ts in (5, None, ["2026-11-16T13:05:30Z"]):
            with self.assertRaises(B.Refused) as cm:
                B.read_entry(self.entry(ts=ts))
            self.assertEqual(cm.exception.reason, "entry_malformed", ts)

    def test_an_entry_over_1_mib_is_too_large(self):
        mib = 1024 * 1024   # SPEC §19 rule 14 item 1: at most 1 MiB
        big = self.entry(data={"x": "a" * (mib - 300)})
        self.assertLessEqual(len(big), mib)
        B.read_entry(big)
        with self.assertRaises(B.Refused) as cm:
            B.read_entry(self.entry(data={"x": "a" * mib}))
        self.assertEqual(cm.exception.reason, "input_too_large")


if __name__ == "__main__":
    unittest.main()
