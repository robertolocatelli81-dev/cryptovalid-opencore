#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Roberto Locatelli
"""SPEC_EVIDENCE_FORMAT.md §11 (v0.6, 2026-11-13): the one check of an RFC 3161 token, `cryptovalid_tsa.verify_token`.

Measured on 0.22.0 (2026-11-13) before the change: a CMS blob signed with an RSA key made on the spot, whose content is
only the OCTET STRING of the digest, gave token_contains_digest True and verify_cms_signature True; the ingest counted it
in `timestamped_segments` with no warning, eidas_ledger_check in `record_con_token_rfc3161`, the inclusion receipt as
`anchored: true`; and the LOTL called a token "qualified" when it merely carried a QTST certificate. The tests marked
"0.22.0:" fail by assertion on that code.

Real tokens: spec/vectors/rfc3161/ (freetsa.org, DigiCert, Sectigo, GlobalSign, requested on 2026-11-13; manifest.json).
The generative tests read the tokens with a small DER codec written here (not the module's reader) and mutate them."""
import base64
import hashlib
import json
import os
import random
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import cryptovalid_tsa as T  # noqa: E402

V = os.path.join(HERE, "spec", "vectors", "rfc3161")
OPENSSL = shutil.which("openssl")
CLOSED = {"malformed", "not_signed_data", "response_not_granted", "econtent_type_not_tstinfo", "tstinfo_unknown_element",
          "hash_algorithm_not_allowed", "hash_algorithm_mismatch", "imprint_mismatch", "signature_invalid",
          "not_issued_by_pinned_tsa"}
REAL = ("freetsa", "digicert", "sectigo", "globalsign")


def _read(name):
    with open(os.path.join(V, name), "rb") as f:
        return f.read()


DATA = _read("data.txt")
DIGEST = hashlib.sha256(DATA).digest()


# ── a DER codec of its own for the mutations (not the module's reader) (constructed = tag bit 0x20) ──
def dec(b):
    out, i = [], 0
    while i < len(b):
        tag, ln, j = b[i], b[i + 1], i + 2
        if ln & 0x80:
            k = ln & 0x7F
            ln, j = int.from_bytes(b[j:j + k], "big"), j + k
        v = b[j:j + ln]
        out.append([tag, dec(v) if tag & 0x20 else v])
        i = j + ln
    return out


def length(n):
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b


def enc(nodes):
    out = b""
    for tag, v in nodes:
        body = enc(v) if isinstance(v, list) else v
        out += bytes([tag]) + length(len(body)) + body
    return out


def token_of(resp):
    return enc([dec(resp)[0][1][1]])            # TimeStampResp → its TimeStampToken


def tree(tok):
    """(ContentInfo nodes, SignedData children, TSTInfo children): the TSTInfo is decoded out of its OCTET STRING."""
    ci = dec(tok)
    sd = ci[0][1][1][1][0][1]
    eci = sd[2][1]
    tst = dec(eci[1][1][0][1])[0][1]
    return ci, sd, tst


def rebuild(ci, sd, tst):
    sd[2][1][1][1][0][1] = enc([[0x30, tst]])
    return enc(ci)


class TestRealTokens(unittest.TestCase):
    def test_parse_every_real_token(self):
        for n in REAL:
            for der in (_read(n + ".tsr"), token_of(_read(n + ".tsr"))):
                t = T.parse_token(der)
                self.assertEqual((t["hash_algorithm"], t["hashed_message"]), ("sha256", DIGEST), n)
                self.assertRegex(t["gen_time"], r"^2026-11-13T12:40:4[0-2](\.\d+)?Z$", n)
                self.assertTrue(T.token_contains_digest(der, DIGEST))
                self.assertFalse(T.token_contains_digest(der, hashlib.sha256(b"x").digest()))
        t = T.parse_token(_read("freetsa_sha512.tsr"))
        self.assertEqual((t["hash_algorithm"], t["hashed_message"]), ("sha512", hashlib.sha512(DATA).digest()))

    @unittest.skipUnless(OPENSSL, "openssl absent")
    def test_manifest(self):
        m = json.loads(_read("manifest.json"))
        n_checked = 0
        for v in m["vectors"]:
            der = _read(v["file"])
            digest = hashlib.sha512(DATA).digest() if v.get("hash_alg") == "sha512" else DIGEST
            if v.get("digest", "").startswith("sha256 of b'x'"):
                digest = hashlib.sha256(b"x").digest()
            if "sha1" in v["file"]:
                digest = hashlib.sha1(DATA).digest()
            for how, want in v["expect"].items():
                if how.startswith("until"):
                    continue
                if how == "unpinned":
                    r = T.verify_token(der, digest, v.get("hash_alg"))
                elif how.startswith("pinned "):
                    r = T.verify_token(der, digest, v.get("hash_alg"), [os.path.join(V, how.split()[1])])
                elif how == "hash_alg sha256 expected":
                    r = T.verify_token(der, digest, "sha256")
                else:
                    self.fail(how)
                got = r["status"] if r["status"] != "invalid" else "invalid/" + r["reason"]
                self.assertTrue(want.startswith(got), (v["file"], how, got, r["detail"]))
                self.assertEqual(r["counts_as_timestamp"], got == "verified")
                n_checked += 1
        self.assertGreaterEqual(n_checked, 20)

    @unittest.skipUnless(OPENSSL, "openssl absent")
    def test_gen_time_and_signer_are_returned(self):
        r = T.verify_token(_read("digicert.tsr"), DIGEST, "sha256", [os.path.join(V, "digicert.signer.pem")])
        self.assertEqual(r["tst_info"]["gen_time"], "2026-11-13T12:40:41Z")
        self.assertEqual(r["tst_info"]["policy"], "2.16.840.1.114412.7.1")
        pem = _read("digicert.signer.pem").decode()
        der = base64.b64decode("".join(ln for ln in pem.splitlines() if "-----" not in ln))
        self.assertEqual(r["signer_sha256"], hashlib.sha256(der).hexdigest())

    def test_openssl_absent_is_not_evaluated_never_true(self):
        with mock.patch("shutil.which", return_value=None):
            r = T.verify_token(_read("freetsa.tsr"), DIGEST, "sha256", [os.path.join(V, "freetsa_cacert.pem")])
        self.assertEqual((r["status"], r["counts_as_timestamp"], r["imprint_ok"]), ("not_evaluated", False, True))

    @unittest.skipUnless(OPENSSL, "openssl absent")
    def test_openssl_ended_by_a_signal_is_a_check_not_run(self):
        from verifier import CheckNotRun
        done = subprocess.CompletedProcess([], -9, b"", b"")
        with mock.patch.object(T, "_run_openssl", return_value=done):
            with self.assertRaises(CheckNotRun):
                T.verify_token(_read("freetsa.tsr"), DIGEST)


@unittest.skipUnless(OPENSSL, "openssl absent")
class TestTheDefectOf0220(unittest.TestCase):
    """The blob of the measurement of 2026-11-13, rebuilt here with a key made on the spot."""

    @classmethod
    def setUpClass(cls):
        cls.d = d = tempfile.mkdtemp()
        j = lambda n: os.path.join(d, n)  # noqa: E731
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", j("k.pem"), "-out", j("c.pem"),
                        "-subj", "/CN=nobody", "-days", "1"], check=True, capture_output=True)
        with open(j("content.bin"), "wb") as f:
            f.write(b"\x04\x20" + DIGEST)
        subprocess.run(["openssl", "cms", "-sign", "-binary", "-nodetach", "-in", j("content.bin"), "-signer", j("c.pem"),
                        "-inkey", j("k.pem"), "-certfile", os.path.join(V, "digicert.signer.pem"), "-outform", "DER",
                        "-out", j("f.der")], check=True, capture_output=True)
        with open(j("f.der"), "rb") as f:
            cls.forged = f.read()

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.d, ignore_errors=True)

    def test_forged_blob_is_not_a_token(self):
        self.assertIs(T.verify_cms_signature(self.forged), True)           # the CMS signature itself is valid …
        self.assertFalse(T.token_contains_digest(self.forged, DIGEST))     # 0.22.0: True (a search in the bytes)
        r = T.verify_token(self.forged, DIGEST, "sha256", [os.path.join(V, "digicert.signer.pem")])
        self.assertEqual((r["status"], r["reason"], r["counts_as_timestamp"]), ("invalid", "malformed", False))

    def test_lotl_reads_the_signer_not_the_carried_certificates(self):
        import cryptovalid_lotl as L
        pem = _read("digicert.signer.pem").decode()
        listed = {hashlib.sha256(base64.b64decode("".join(ln for ln in pem.splitlines() if "-----" not in ln))).hexdigest()}
        self.assertTrue(L.token_cert_fingerprints(self.forged) & listed)    # it carries the listed certificate
        self.assertEqual(L.qualification(self.forged, listed, {}), ("not_qualified", None))   # 0.22.0: qualified
        self.assertEqual(L.qualification(token_of(_read("digicert.tsr")), listed, {}), ("qualified", None))                               # positive control: the real DigiCert token

    def test_inclusion_receipt_anchors_only_a_pinned_token(self):
        import cryptovalid_receipt as CR
        with mock.patch.object(T, "request_timestamp", return_value=(True, self.forged, b"")):
            r = CR._stamp(DIGEST.hex(), "http://fake")
        self.assertEqual((r["anchored"], r["status"], r["imprint_ok"]), (False, "invalid", False))   # 0.22.0: anchored True
        self.assertNotIn("token_b64", r)
        real = _read("sectigo.tsr")
        with mock.patch.object(T, "request_timestamp", return_value=(True, real, b"")):
            r = CR._stamp(DIGEST.hex(), "http://fake")
            self.assertEqual((r["anchored"], r["status"], r["gen_time"]), (False, "signature_only", "2026-11-13T12:40:41Z"))
            self.assertIn("chain not established", r["note"])
            r = CR._stamp(DIGEST.hex(), "http://fake", [os.path.join(V, "sectigo.signer.pem")])
            self.assertEqual((r["anchored"], r["status"]), (True, "verified"))
            self.assertIn("token_b64", r)


class TestParserClosedGenerative(unittest.TestCase):
    """Every input outside SPEC §11 steps 1-4 is a TokenError with a closed reason; nothing else escapes."""

    def setUp(self):
        self.tok = token_of(_read("freetsa.tsr"))

    def assertRefused(self, der, why, msg=None):
        with self.assertRaises(T.TokenError, msg=msg) as cm:
            T.parse_token(der)
        self.assertIn(cm.exception.reason, CLOSED)
        if why:
            self.assertEqual(cm.exception.reason, why, (msg, cm.exception.detail))

    def test_codec_round_trip_is_the_positive_control(self):
        for n in REAL:
            tok = token_of(_read(n + ".tsr"))
            ci, sd, tst = tree(tok)
            self.assertEqual(rebuild(ci, sd, tst), tok, n)
            self.assertEqual(T.parse_token(rebuild(ci, sd, tst))["hashed_message"], DIGEST)

    def test_every_truncation_and_every_extension(self):
        for der in (self.tok, _read("freetsa.tsr")):
            for k in range(len(der)):
                self.assertRefused(der[:k], "malformed", k)
            for extra in (b"\x00", b"\x30\x00", b"\x04\x20" + DIGEST):
                self.assertRefused(der + extra, "malformed")

    def test_every_single_byte_change_is_refused_or_parses(self):
        rng = random.Random(20261113)
        for n in REAL:
            tok = token_of(_read(n + ".tsr"))
            for i in range(len(tok)):
                b = bytearray(tok)
                b[i] ^= 1 << rng.randrange(8)
                try:
                    T.parse_token(bytes(b))
                except T.TokenError as e:
                    self.assertIn(e.reason, CLOSED)

    def test_length_encodings(self):
        ci_body = self.tok[4:] if self.tok[1] == 0x82 else None
        self.assertIsNotNone(ci_body)
        self.assertRefused(b"\x30\x83\x00" + self.tok[2:], "malformed")                 # long form with a leading zero
        self.assertRefused(b"\x30\x80" + ci_body + b"\x00\x00", "malformed")            # indefinite length (BER)
        self.assertRefused(b"\x30\x85" + len(ci_body).to_bytes(5, "big") + ci_body, "malformed")
        self.assertRefused(b"\x30\x81\x05" + b"\x06\x03\x2a\x03\x04", "malformed")      # long form for a short length
        self.assertRefused(b"\x3f\x01\x00", "malformed")                               # high tag number
        self.assertRefused(b"", "malformed")
        self.assertRefused(b"\x30", "malformed")

    def test_tstinfo_closed(self):
        unknown = [[0x04, b"x"], [0x0C, b"x"], [0x80, b""], [0xA2, []], [0x31, []], [0x17, b"261113124040Z"]]
        n_positions = 0
        for node in unknown:
            for pos in range(5, 6 + 3):
                ci, sd, tst = tree(self.tok)
                if pos > len(tst):
                    continue
                tst.insert(pos, node)
                self.assertRefused(rebuild(ci, sd, tst), "tstinfo_unknown_element", (node[0], pos))
                n_positions += 1
        self.assertGreaterEqual(n_positions, 18)
        ci, sd, tst = tree(self.tok)
        opt = [x for x in tst[5:]]
        self.assertTrue(opt, "freetsa carries optional elements")
        tst.append(opt[0])                                                               # repeated
        self.assertRefused(rebuild(ci, sd, tst), "tstinfo_unknown_element")
        ci, sd, tst = tree(self.tok)
        if len(tst) > 6:
            tst[5], tst[6] = tst[6], tst[5]                                              # out of order
            self.assertRefused(rebuild(ci, sd, tst), "tstinfo_unknown_element")
        for idx in range(5):                                                             # a required element missing
            ci, sd, tst = tree(self.tok)
            del tst[idx]
            self.assertRefused(rebuild(ci, sd, tst), None)

    def test_tstinfo_fields(self):
        def mut(f):
            ci, sd, tst = tree(self.tok)
            f(tst)
            return rebuild(ci, sd, tst)
        self.assertRefused(mut(lambda t: t.__setitem__(0, [0x02, b"\x02"])), "malformed")          # version 2
        self.assertRefused(mut(lambda t: t.__setitem__(0, [0x02, b"\x00\x01"])), "malformed")      # INTEGER not minimal
        self.assertRefused(mut(lambda t: t.__setitem__(3, [0x02, b"\xff"])), "malformed")          # negative serial
        self.assertRefused(mut(lambda t: t.__setitem__(1, [0x06, b"\x2a\x80\x03"])), "malformed")  # OID arc not minimal
        self.assertRefused(mut(lambda t: t.__setitem__(1, [0x06, b"\x2a\x83"])), "malformed")      # OID truncated
        for gt in (b"20261113124040", b"20261113124040.50Z", b"20261113124040.Z", b"20261130250000Z", b"20260230124040Z",
                   b"20261113124040+0100", b"2026111312404Z", b"20261113124040,5Z", b"\xff" * 15):
            self.assertRefused(mut(lambda t: t.__setitem__(4, [0x18, gt])), "malformed", gt)
        ok = mut(lambda t: t.__setitem__(4, [0x18, b"20261113124040.123Z"]))
        self.assertEqual(T.parse_token(ok)["gen_time"], "2026-11-13T12:40:40.123Z")
        mi = lambda alg, h: [0x30, [[0x30, alg], [0x04, h]]]  # noqa: E731
        oid = lambda arcs: [0x06, bytes(arcs)]  # noqa: E731
        sha256 = oid([0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01])
        self.assertRefused(mut(lambda t: t.__setitem__(2, mi([oid([0x2b, 0x0e, 0x03, 0x02, 0x1a]), [0x05, b""]], b"\x00" * 20))),
                           "hash_algorithm_not_allowed")                                           # SHA-1
        self.assertRefused(mut(lambda t: t.__setitem__(2, mi([oid([0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x05])], b"\x00" * 16))),
                           "hash_algorithm_not_allowed")                                           # MD5
        self.assertRefused(mut(lambda t: t.__setitem__(2, mi([sha256, [0x05, b""]], DIGEST[:31]))), "malformed")
        self.assertRefused(mut(lambda t: t.__setitem__(2, mi([sha256, [0x04, b""]], DIGEST))), "malformed")   # params not NULL
        self.assertRefused(mut(lambda t: t.__setitem__(2, mi([sha256, [0x05, b""], [0x05, b""]], DIGEST))), "malformed")
        self.assertEqual(T.parse_token(mut(lambda t: t.__setitem__(2, mi([sha256], DIGEST))))["hashed_message"], DIGEST)
        self.assertRefused(mut(lambda t: t.insert(5, [0x01, b"\x01"])), "malformed")              # BOOLEAN not DER

    def test_signed_data_closed(self):
        def mut(f, raw=False):
            ci, sd, tst = tree(self.tok)
            f(ci, sd)
            return enc(ci) if raw else rebuild(ci, sd, tst)
        self.assertRefused(mut(lambda ci, sd: sd.__setitem__(0, [0x02, b"\x01"])), "malformed")            # version 1
        self.assertRefused(mut(lambda ci, sd: sd.insert(4, [0xA2, []])), "malformed")                      # unknown [2]
        self.assertRefused(mut(lambda ci, sd: sd[-1][1].append(sd[-1][1][0])), "malformed")               # two SignerInfos
        self.assertRefused(mut(lambda ci, sd: sd[2][1][0].__setitem__(1, b"\x2a\x03\x04")), "econtent_type_not_tstinfo")
        self.assertRefused(mut(lambda ci, sd: ci[0][1][0].__setitem__(1, b"\x2a\x86\x48\x86\xf7\x0d\x01\x07\x01")),
                           "not_signed_data")
        self.assertRefused(mut(lambda ci, sd: sd[2][1].pop(), True), "malformed")                          # detached
        self.assertRefused(mut(lambda ci, sd: sd[2][1][1][1].__setitem__(0, [0x24, [[0x04, b"x"]]]), True), "malformed")   # BER
        has_certs = any(n[0] == 0xA0 for n in tree(self.tok)[1][3:])
        if has_certs:
            self.assertRefused(mut(lambda ci, sd: sd.insert(3, list(sd[3]))), "malformed")                 # [0] twice

    def test_response_status(self):
        resp = dec(_read("freetsa.tsr"))
        for st in (b"\x02", b"\x03", b"\x05"):
            m = dec(_read("freetsa.tsr"))
            m[0][1][0][1][0][1] = st
            self.assertRefused(enc(m), "response_not_granted", st)
        m = dec(_read("freetsa.tsr"))
        m[0][1][0][1][0][1] = b"\x01"                                                    # grantedWithMods
        self.assertEqual(T.parse_token(enc(m))["hashed_message"], DIGEST)
        m = [[0x30, [resp[0][1][0]]]]                                                    # granted, no token
        self.assertRefused(enc(m), "malformed")

    def test_random_structural_mutations(self):
        rng = random.Random(1311)
        kinds = 0
        for _ in range(3000):
            ci, sd, tst = tree(self.tok)
            target = rng.choice([tst, sd, ci[0][1], sd[2][1]])
            op = rng.randrange(4)
            if op == 0 and target:
                target.insert(rng.randrange(len(target) + 1), [rng.choice([0x01, 0x02, 0x04, 0x05, 0x06, 0x0C, 0x13, 0x18, 0x30,
                                                                         0x31, 0x80, 0xA0, 0xA1, 0xA3]), b"\x00"])
            elif op == 1 and len(target) > 1:
                i, j = rng.sample(range(len(target)), 2)
                target[i], target[j] = target[j], target[i]
            elif op == 2 and target:
                del target[rng.randrange(len(target))]
            elif target:
                i = rng.randrange(len(target))
                target.insert(i, list(target[i]))
            try:
                der = rebuild(ci, sd, tst)
            except (IndexError, TypeError, AttributeError):
                continue                                                                  # the mutation broke the codec's path
            try:
                T.parse_token(der)
            except T.TokenError as e:
                self.assertIn(e.reason, CLOSED)
                kinds += 1
        self.assertGreater(kinds, 2000)

    def test_verify_token_never_raises_on_garbage(self):
        rng = random.Random(7)
        for _ in range(2000):
            der = bytes(rng.randrange(256) for _ in range(rng.randrange(0, 64)))
            r = T.verify_token(der, DIGEST)
            self.assertEqual((r["status"], r["counts_as_timestamp"]), ("invalid", False))
            self.assertIn(r["reason"], CLOSED)
        for bad in (None, "text", 7, b""):
            self.assertEqual(T.verify_token(bad, DIGEST)["reason"], "malformed")
        self.assertEqual(T.verify_token(self.tok, "not bytes")["reason"], "imprint_mismatch")


if __name__ == "__main__":
    unittest.main(verbosity=1)
