#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""SPEC v0.10 §11 step 7, "Closed shapes" (17/11/2026), for a signer named by subjectKeyIdentifier. Found by the port
of this step to omega-cra-evol, whose generative test was stricter in three points, then measured here:

(a) exactly one SignerInfo: `verify_token` already refused two at step 1; the step's helper alone took the first one;
(b) every signed attribute is {attrType OID, attrValues SET} and nothing else, the ESS attribute {certs, policies?}
    with `policies` a SEQUENCE OF PolicyInformation, the ESSCertID a SEQUENCE: the bench of omega-cra-evol (every DER
    element dropped, duplicated, retagged, given a stranger or flipped) found 9 changes inside the ESS attribute and 8
    retagged or extended attributes accepted by the helper (none by §11: the CMS signature covers them);
(c) an openssl whose `verify` does not know -no-CAstore (before 3.0) was `not_issued_by_pinned_tsa`; it is a check
    not run (CheckNotRun).

Positive control, measured: on the code before this correction 4 of the 5 tests fail (all but test_control).
"""
import copy
import os
import shutil
import stat
import sys
import tempfile
import time
import unittest

sys.dont_write_bytecode = True
ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)
import cryptovalid_tsa as T  # noqa: E402
import test_tsa_signer_key_id_20261116 as K  # noqa: E402


def nodes(n, path=()):
    yield path, n
    if isinstance(n[1], list):
        for i, c in enumerate(n[1]):
            yield from nodes(c, path + (i,))


def at_(t, path):
    for i in path:
        t = t[1][i]
    return t


@K.NEEDS
class ClosedShapes(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.td = tempfile.mkdtemp()
        cls.lab, cls.other = K.Lab(cls.td, "a"), K.Lab(cls.td, "b")
        cls.tok = cls.lab.token()
        cls.ski = cls.lab.resign(cls.tok)
        cls.pins = T._pem_certs([cls.lab.j("ca.crt")])
        with open(cls.lab.j("tsa.crt"), "rb") as f:
            cls.leaf = T._first_pem_der(f.read())
        cls.at = int(time.time())

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.td)

    def anchor(self, tok):
        return T._key_id_anchor(tok, self.leaf, self.pins, self.at, self.td)

    def test_control(self):
        self.assertIsNone(self.anchor(self.ski))

    def test_two_signer_infos_in_the_helper(self):
        j, o = self.lab.j, self.other.j
        K._run("openssl", "cms", "-verify", "-noverify", "-binary", "-inform", "DER", "-in", j("ski.der"), "-out", j("tst2.der"))
        K._run("openssl", "cms", "-sign", "-binary", "-nodetach", "-econtent_type", K.OID_TSTINFO, "-keyid", "-cades",
               "-md", "sha256", "-nosmimecap", "-signer", j("tsa.crt"), "-inkey", j("tsa.key"), "-signer", o("tsa.crt"),
               "-inkey", o("tsa.key"), "-certfile", j("ca.crt"), "-in", j("tst2.der"), "-outform", "DER", "-out", j("two.der"))
        with open(j("two.der"), "rb") as f:
            two = f.read()
        self.assertIn("2 SignerInfos", self.anchor(two))
        v = T.verify_token(two, K.DIGEST, "sha256", [j("ca.crt"), o("ca.crt")])
        self.assertEqual((v["status"], v["reason"]), ("invalid", "malformed"), v)   # step 1, as before

    def variants(self):
        base = K.tree(self.ski)
        for path, _n in list(nodes(base)):
            if not path:
                continue
            for how in ("drop", "dup", "retag", "stranger", "flip"):
                t = copy.deepcopy(base)
                parent, i = at_(t, path[:-1]), path[-1]
                node = parent[1][i]
                if how == "drop":
                    del parent[1][i]
                elif how == "dup":
                    parent[1].insert(i, copy.deepcopy(node))
                elif how == "retag":
                    content = b"".join(K.enc(c) for c in node[1]) if isinstance(node[1], list) else node[1]
                    parent[1][i] = [0x04 if node[0] != 0x04 else 0x0C, content]
                elif how == "stranger":
                    if not isinstance(node[1], list):
                        continue
                    node[1].append([0x8A, b"\x01"])
                elif how == "flip":
                    if isinstance(node[1], list):
                        continue
                    node[1] = bytes([node[1][0] ^ 0x01]) + node[1][1:] if node[1] else b"\x00"
                yield path, how, K.enc(t)

    def test_every_change_of_an_attribute_is_refused(self):
        """the bench of omega-cra-evol: the step never raises; every change inside the ESS attribute, and every signed
        attribute retagged or given a stranger, is refused (dropping the ESSCertIDv2's OPTIONAL issuerSerial excepted)"""
        base = K.tree(self.ski)
        si = K.signer_info(base)
        attrs_path = (1, 0, len(base[1][1][1][0][1]) - 1, 0, 3)
        self.assertIs(at_(base, attrs_path), si[1][3])
        k = [k for k, a in enumerate(si[1][3][1]) if T._der_oid(a[1][0][1], "o") == T.OID_SIGNING_CERTIFICATE_V2][0]
        ess_path = attrs_path + (k,)
        n, accepted = 0, []
        for path, how, tok in self.variants():
            why = self.anchor(tok)
            self.assertTrue(why is None or isinstance(why, str), (path, how, why))
            n += 1
            in_ess = path[:len(ess_path)] == ess_path and (path, how) != (ess_path + (1, 0, 0, 0, 1), "drop")
            attr_shape = path[:len(attrs_path)] == attrs_path and len(path) == len(attrs_path) + 1 and how in ("retag", "stranger")
            if (in_ess or attr_shape) and why is None:
                accepted.append((path[len(attrs_path):], how))
        self.assertEqual(accepted, [])
        self.assertGreater(n, 400)

    def with_policies(self, policies):
        t = K.tree(self.ski)
        si = K.signer_info(t)
        for a in si[1][3][1]:
            if T._der_oid(a[1][0][1], "o") == T.OID_SIGNING_CERTIFICATE_V2:
                a[1][1][1][0][1].append(policies)          # SigningCertificateV2 gains a second element
        return K.enc(t)

    def test_policies_shape(self):
        oid = [0x06, bytes.fromhex("2a0304")]               # 1.2.3.4
        self.assertIsNone(self.anchor(self.with_policies([0x30, [[0x30, [oid]]]])))          # a valid policies
        self.assertIsNone(self.anchor(self.with_policies([0x30, [[0x30, [oid, [0x30, []]]]]])))   # with qualifiers
        self.assertIsNone(self.anchor(self.with_policies([0x30, []])))                        # SEQUENCE OF, empty
        for bad in ([0x31, [[0x30, [oid]]]], [0x30, [[0x31, [oid]]]], [0x30, [[0x30, []]]], [0x30, [[0x30, [[0x02, b"\x01"]]]]],
                    [0x04, b"x"]):
            self.assertIn("not {certs, policies?}", self.anchor(self.with_policies(bad)), bad)
        t = K.tree(self.with_policies([0x30, [[0x30, [oid]]]]))   # a valid policies, then a third element
        for a in K.signer_info(t)[1][3][1]:
            if T._der_oid(a[1][0][1], "o") == T.OID_SIGNING_CERTIFICATE_V2:
                a[1][1][1][0][1].append([0x30, []])
        self.assertIn("not {certs, policies?}", self.anchor(K.enc(t)))

    def test_openssl_without_no_castore(self):
        from test_platforms_20261124 import fake_openssl   # Windows: an openssl.exe that runs the same logic
        bindir = os.path.join(self.td, "bin")
        env = fake_openssl(self, bindir,
                           "#!/bin/sh\nif [ \"$1\" = verify ]; then echo 'verify: Unknown option: -no-CAstore' >&2; exit 1; fi\n"
                           f"exec {shutil.which('openssl')} \"$@\"\n",
                           "import os, subprocess, sys\n"
                           "if sys.argv[1:2] == ['verify']:\n    sys.stderr.write('verify: Unknown option: -no-CAstore\\n'); sys.exit(1)\n"
                           "sys.exit(subprocess.call([os.environ['CV_REAL_OPENSSL']] + sys.argv[1:], stdin=0, stdout=1, stderr=2))")
        fake = shutil.which("openssl", path=bindir)
        old = {k: os.environ.get(k) for k in env}
        os.environ.update(env)

        def restore():
            for k, v in old.items():
                os.environ.pop(k, None) if v is None else os.environ.__setitem__(k, v)
        try:
            self.assertEqual(os.path.normcase(shutil.which("openssl")), os.path.normcase(fake))
            from verifier import CheckNotRun
            from test_platforms_20261124 import fake_calls
            try:
                T.verify_token(self.ski, K.DIGEST, "sha256", [self.lab.j("ca.crt")])
            except CheckNotRun:
                pass
            else:
                self.fail("CheckNotRun not raised; " + fake_calls(bindir))
            v = T.verify_token(self.tok, K.DIGEST, "sha256", [self.lab.j("ca.crt")])   # the other form: no `verify`
            self.assertEqual(v["status"], "verified", v)
        finally:
            restore()
        v = T.verify_token(self.ski, K.DIGEST, "sha256", [self.other.j("ca.crt")])   # a real refusal stays one
        self.assertEqual(v["reason"], "not_issued_by_pinned_tsa")


if __name__ == "__main__":
    unittest.main()
