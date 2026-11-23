#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""cryptovalid_composite: verification of composite ML-DSA signatures of RFC 10073 (SPEC §29).

Vectors: RFC 10073 Appendix E, read from CV_RFC10073_TXT=<rfc10073.txt> and/or CV_COMPOSITE_VECTORS=<testvectors.json of
lamps-wg/draft-composite-sigs> (IETF contributions under BCP 78: not shipped here, as in SPEC §15). Without either the
vector test is skipped and says so. The other tests sign with a helper of this file written from §3.2 (not a product
function) and attack every input: lengths, curves, point and DER encodings, labels, ctx, the hybrid's own bytes.

Positive control, measured: on a156b15 (no cryptovalid_composite) every test here errors at the import."""
import base64
import hashlib
import json
import os
import random
import re
import sys
import unittest

sys.dont_write_bytecode = True
ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)
import cryptovalid_composite as CC  # noqa: E402

try:
    from cryptography.hazmat.primitives.asymmetric import mldsa  # noqa: F401
    HAVE = True
except ImportError:
    HAVE = False
NEEDS = unittest.skipUnless(HAVE, "needs `cryptography` with ML-DSA (the `sign` extra)")
MSG = b"The quick brown fox jumps over the lazy dog."


def rfc_vectors():
    """the Appendix E JSON of the RFC text (lines unwrapped) and the lamps-wg file, each when its path is given"""
    out = {}
    txt = os.environ.get("CV_RFC10073_TXT")
    if txt:
        with open(txt, encoding="utf-8-sig") as f:
            t = f.read()
        t = t[t.index("Appendix E.  Test Vectors", t.index("Appendix E.  Test Vectors") + 30):]
        t = t[t.index("\n   {") + 1:]
        out["rfc10073.txt"] = json.JSONDecoder().raw_decode(re.sub(r"\n\s*", "", t).strip())[0]
    js = os.environ.get("CV_COMPOSITE_VECTORS")
    if js:
        with open(js, encoding="utf-8") as f:
            out["testvectors.json"] = json.load(f)
    return out


class Signer:
    """§3.2 for the three algorithms (test helper)"""
    def __init__(self, name):
        from cryptography.hazmat.primitives import serialization as ser
        from cryptography.hazmat.primitives.asymmetric import ec, ed25519, mldsa
        self.name, (_, self.label, self.trad) = name, CC.ALGORITHMS[name]
        self.m = mldsa.MLDSA65PrivateKey.generate()
        self.t = ed25519.Ed25519PrivateKey.generate() if self.trad == "ed25519" else ec.generate_private_key(
            ec.SECP256R1() if self.trad == "p256" else ec.SECP384R1())
        tp = self.t.public_key()
        traw = tp.public_bytes(ser.Encoding.Raw, ser.PublicFormat.Raw) if self.trad == "ed25519" else \
            tp.public_bytes(ser.Encoding.X962, ser.PublicFormat.UncompressedPoint)
        self.pk = self.m.public_key().public_bytes_raw() + traw

    def sign(self, msg, ctx=b"", mp=None, mctx=None):
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec
        mp = CC.m_prime(self.label, msg, ctx) if mp is None else mp
        ml = self.m.sign(mp, self.label if mctx is None else mctx)
        if self.trad == "ed25519":
            return ml + self.t.sign(mp)
        return ml + self.t.sign(mp, ec.ECDSA(hashes.SHA256() if self.trad == "p256" else hashes.SHA384()))


@NEEDS
class Vectors(unittest.TestCase):
    def test_appendix_e(self):
        sets = rfc_vectors()
        if not sets:
            self.skipTest("RFC 10073 vectors not given (CV_RFC10073_TXT / CV_COMPOSITE_VECTORS)")
        for src, d in sets.items():
            m, ctx = base64.b64decode(d["m"]), base64.b64decode(d["ctx"])
            self.assertEqual(m, MSG)
            seen = 0
            for t in d["tests"]:
                if t["tcId"] not in CC.ALGORITHMS:
                    continue
                seen += 1
                pk, s, sc = (base64.b64decode(t[k]) for k in ("pk", "s", "sWithContext"))
                self.assertTrue(CC.verify(t["tcId"], pk, m, s)["ok"], (src, t["tcId"]))
                self.assertTrue(CC.verify(CC.ALGORITHMS[t["tcId"]][0], pk, m, sc, ctx)["ok"], (src, t["tcId"]))
                self.assertFalse(CC.verify(t["tcId"], pk, m, sc)["ok"])                 # the other ctx
                self.assertFalse(CC.verify(t["tcId"], pk, m, s, ctx)["ok"])
                flipped = bytearray(s)
                flipped[random.Random(seen).randrange(len(s))] ^= 1
                self.assertFalse(CC.verify(t["tcId"], pk, m, bytes(flipped))["ok"])
                for other in CC.ALGORITHMS:
                    if other != t["tcId"]:
                        self.assertFalse(CC.verify(other, pk, m, s)["ok"], (t["tcId"], other))
                if CC.ALGORITHMS[t["tcId"]][2] != "ed25519":                            # BER: long-form length
                    der = s[CC.MLDSA65_SIG:]
                    ber = der[:1] + b"\x81" + der[1:] if der[1] < 0x80 else None
                    if ber:
                        out = CC.verify(t["tcId"], pk, m, s[:CC.MLDSA65_SIG] + ber)
                        self.assertEqual(out["stage"], "MALFORMED_KEY_OR_SIGNATURE", out)
            self.assertEqual(seen, 3, src)
        if len(sets) == 2:
            pick = lambda d: {t["tcId"]: t for t in d["tests"] if t["tcId"] in CC.ALGORITHMS}  # noqa: E731
            self.assertEqual(pick(sets["rfc10073.txt"]), pick(sets["testvectors.json"]))


@NEEDS
class Generated(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.s = {n: Signer(n) for n in CC.ALGORITHMS}

    def test_valid_with_name_and_oid_and_every_ctx_length(self):
        for n, sg in self.s.items():
            for ctx in (b"", b"x", bytes(range(255))):
                sig = sg.sign(MSG, ctx)
                for alg in (n, CC.ALGORITHMS[n][0]):
                    out = CC.verify(alg, sg.pk, MSG, sig, ctx)
                    self.assertEqual((out["ok"], out["alg"], out["oid"]), (True, n, CC.ALGORITHMS[n][0]), out)
                self.assertEqual(CC.verify(n, bytearray(sg.pk), bytearray(MSG), bytearray(sig), bytearray(ctx))["ok"], True)

    def test_each_component_fails_alone(self):
        for n, sg in self.s.items():
            good = sg.sign(MSG)
            other = Signer(n).sign(MSG)
            mixed_ml = other[:CC.MLDSA65_SIG] + good[CC.MLDSA65_SIG:]
            mixed_tr = good[:CC.MLDSA65_SIG] + other[CC.MLDSA65_SIG:]
            self.assertEqual(CC.verify(n, sg.pk, MSG, mixed_ml)["stage"], "MLDSA_SIGNATURE_INVALID")
            self.assertEqual(CC.verify(n, sg.pk, MSG, mixed_tr)["stage"], "TRADITIONAL_SIGNATURE_INVALID")
            self.assertEqual(CC.verify(n, sg.pk, MSG + b"!", good)["stage"], "MLDSA_SIGNATURE_INVALID")

    def test_the_hybrids_bytes_are_not_a_composite(self):
        """SPEC §15: two signatures over the message itself, ML-DSA with the empty context, are refused"""
        for n, sg in self.s.items():
            for mp, mctx in ((MSG, b""), (CC.m_prime(sg.label, MSG), b""), (MSG, sg.label)):
                self.assertFalse(CC.verify(n, sg.pk, MSG, sg.sign(MSG, mp=mp, mctx=mctx))["ok"], (n, mctx))
            wrong_label = sg.sign(MSG, mp=CC.m_prime(b"COMPSIG-MLDSA44-Ed25519-SHA512", MSG))
            self.assertFalse(CC.verify(n, sg.pk, MSG, wrong_label)["ok"])

    def test_closed_inputs(self):
        rng = random.Random(20261123)
        for n, sg in self.s.items():
            sig = sg.sign(MSG)
            trad, tpk = sg.trad, sg.pk[CC.MLDSA65_PK:]
            bad_keys = [sg.pk[:-1], sg.pk + b"\x00", sg.pk[:CC.MLDSA65_PK], b"", sg.pk[1:]]
            if trad != "ed25519":
                bad_keys += [sg.pk[:CC.MLDSA65_PK] + bytes([2 + (tpk[-1] & 1)]) + tpk[1:1 + (len(tpk) - 1) // 2],   # compressed
                             sg.pk[:CC.MLDSA65_PK] + b"\x04" + bytes(len(tpk) - 1),                              # not on curve
                             sg.pk[:CC.MLDSA65_PK] + bytes([6 + (tpk[-1] & 1)]) + tpk[1:]]                         # X9.62 hybrid form
            for k in bad_keys:
                self.assertFalse(CC.verify(n, k, MSG, sig)["ok"], (n, len(k)))
                self.assertIn(CC.verify(n, k, MSG, sig)["stage"], ("MALFORMED_KEY", "MALFORMED_KEY_OR_SIGNATURE"))
            for s in (sig[:CC.MLDSA65_SIG], sig[:-1], sig + b"\x00", b"", sig[:100]):
                out = CC.verify(n, sg.pk, MSG, s)
                self.assertFalse(out["ok"])
                self.assertIn(out["stage"], ("MALFORMED_SIGNATURE", "MALFORMED_KEY_OR_SIGNATURE"), out)
            self.assertEqual(CC.verify(n, sg.pk, MSG, sig, bytes(256))["stage"], "CTX_TOO_LONG")
            for _ in range(60):
                b = bytearray(sig)
                b[rng.randrange(len(b))] ^= 1 << rng.randrange(8)
                self.assertFalse(CC.verify(n, sg.pk, MSG, bytes(b))["ok"])
        for alg in ("id-MLDSA44-Ed25519-SHA512", "1.3.6.1.5.5.7.6.39", "ID-MLDSA65-ED25519-SHA512", "", None, ["x"], 48):
            self.assertEqual(CC.verify(alg, b"", MSG, b"")["stage"], "UNSUPPORTED_ALG")
        sg = self.s["id-MLDSA65-Ed25519-SHA512"]
        for bad in (("x", sg.pk, MSG, sg.sign(MSG)), (None, sg.pk, MSG, sg.sign(MSG))):
            self.assertEqual(CC.verify("id-MLDSA65-Ed25519-SHA512", bad[1], bad[0], bad[3])["stage"], "MALFORMED_INPUT")
        self.assertEqual(CC.verify("id-MLDSA65-Ed25519-SHA512", sg.pk, MSG, sg.sign(MSG), "ctx")["stage"], "MALFORMED_INPUT")

    def test_ecdsa_der_only(self):
        from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
        for n in ("id-MLDSA65-ECDSA-P256-SHA512", "id-MLDSA65-ECDSA-P384-SHA512"):
            sg = self.s[n]
            sig = sg.sign(MSG)
            der = sig[CC.MLDSA65_SIG:]
            r, s = decode_dss_signature(der)
            size = 32 if "P256" in n else 48
            raw = r.to_bytes(size, "big") + s.to_bytes(size, "big")          # COSE's r || s is not RFC 10073's form
            padded = b"\x30" + bytes([der[1] + 1]) + der[2:] + b"\x00"         # trailing byte inside the SEQUENCE
            ri = r.to_bytes((r.bit_length() + 7) // 8, "big")
            if ri[0] < 0x80:                                                   # r with a superfluous leading zero
                body = b"\x02" + bytes([len(ri) + 1]) + b"\x00" + ri + der[4 + der[3]:]
                nonmin = b"\x30" + bytes([len(body)]) + body
            else:
                nonmin = b"\x30" + bytes([der[1] + 1]) + b"\x02" + bytes([der[3] + 1]) + b"\x00" + der[4:]
            for t in (raw, der + b"\x00", padded, der[:1] + b"\x81" + der[1:], nonmin):
                out = CC.verify(n, sg.pk, MSG, sig[:CC.MLDSA65_SIG] + t)
                self.assertEqual(out["stage"], "MALFORMED_KEY_OR_SIGNATURE", (n, t.hex()[:12], out))
            self.assertTrue(CC.verify(n, sg.pk, MSG, sig)["ok"])

    def test_m_prime(self):
        """RFC 10073 Appendix D: the two M' of id-MLDSA65-ECDSA-P256-SHA512 for M = 00..09, without and with a ctx"""
        head = ("436f6d706f73697465416c676f726974686d5369676e61747572657332303235"
                "434f4d505349472d4d4c44534136352d45434453412d503235362d534841353132")
        ph = ("0f89ee1fcb7b0a4f7809d1267a029719004c5a5e5ec323a7c3523a20974f9a3f"
              "202f56fadba4cd9e8d654ab9f2e96dc5c795ea176fa20ede8d854c342f903533")
        label, m = CC.ALGORITHMS["id-MLDSA65-ECDSA-P256-SHA512"][1], bytes(range(10))
        self.assertEqual(CC.m_prime(label, m).hex(), head + "00" + ph)
        self.assertEqual(CC.m_prime(label, m, bytes.fromhex("0813061205162623")).hex(), head + "080813061205162623" + ph)

if __name__ == "__main__":
    unittest.main()
