#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""SPEC §15 (v0.8): the hybrid signature of this format (Ed25519 + ML-DSA-65 with the empty context, two fields, over the
`self_hash` string) is not the composite ML-DSA of RFC 10073 (`id-MLDSA65-Ed25519-SHA512`), with the same two keys.

A hybrid ledger is made by signer.py; its two signatures concatenated in RFC 10073's order are presented as a composite
signature, and a composite signature made with the same two keys over the same message is presented to
signer.verify_ledger_signatures, whole and one half at a time. Every crossing must fail, both direct checks pass: the
difference is measured in both directions. Proposed by Athena's review of 15/11/2026 (prototypes p6_composite.py and
test_hybrid_is_not_composite_20261115.py), rewritten here.

The composite below is a test helper written from RFC 10073 §2.1, §2.2, §3.2, §3.3, §4.1 and §4.3, not a product
function. With CV_RFC10073_TXT=<path to https://www.rfc-editor.org/rfc/rfc10073.txt> the helper is also checked against
the two signatures of the RFC's Appendix E for id-MLDSA65-Ed25519-SHA512 (not shipped: the vector stays in the RFC).
Positive control in the file: a "composite" that signs the message itself with the empty context, i.e. the hybrid's
bytes, makes the crossing check report failures."""
import base64
import hashlib
import json
import os
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True
ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)
import signer as S  # noqa: E402

PREFIX = b"CompositeAlgorithmSignatures2025"            # RFC 10073 §2.2
LABEL = b"COMPSIG-MLDSA65-Ed25519-SHA512"               # RFC 10073 §6, id-MLDSA65-Ed25519-SHA512
MLDSA65_PK, MLDSA65_SIG, ED_PK, ED_SIG = 1952, 3309, 32, 64


def m_prime(message, ctx=b""):
    """RFC 10073 §2.1 / §3.2: M' := Prefix || Label || len(ctx) || ctx || PH( M ), PH = SHA512, len(ctx) one byte."""
    if len(ctx) > 255:
        raise ValueError("ctx longer than 255 bytes")
    return PREFIX + LABEL + bytes([len(ctx)]) + ctx + hashlib.sha512(message).digest()


class Composite:
    """The composite of RFC 10073 §3.2-§3.3 for id-MLDSA65-Ed25519-SHA512 (test helper). `mp` and `mldsa_ctx` are
    attributes so that the positive control can replace them with the hybrid's own bytes."""
    mp = staticmethod(m_prime)
    mldsa_ctx = LABEL

    @classmethod
    def sign(cls, mldsa_sk, ed_sk, message, ctx=b""):
        mp = cls.mp(message, ctx)
        ml = mldsa_sk.sign(mp, cls.mldsa_ctx) if cls.mldsa_ctx is not None else mldsa_sk.sign(mp)
        return ml + ed_sk.sign(mp)                                         # §4.3: mldsaSig || tradSig

    @classmethod
    def verify(cls, public_key, message, signature, ctx=b""):
        from cryptography.hazmat.primitives.asymmetric import mldsa
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        if len(public_key) != MLDSA65_PK + ED_PK or len(signature) != MLDSA65_SIG + ED_SIG:
            return False                                                   # §3.3 step 2: not of the correct length
        mp = cls.mp(message, ctx)
        try:
            pk = mldsa.MLDSA65PublicKey.from_public_bytes(public_key[:MLDSA65_PK])
            if cls.mldsa_ctx is not None:
                pk.verify(signature[:MLDSA65_SIG], mp, cls.mldsa_ctx)
            else:
                pk.verify(signature[:MLDSA65_SIG], mp)
            Ed25519PublicKey.from_public_bytes(public_key[MLDSA65_PK:]).verify(signature[MLDSA65_SIG:], mp)
        except Exception:  # noqa: BLE001 — §3.3: "Invalid signature" if either fails
            return False
        return True


class Hybrid:
    """One hybrid ledger of signer.py, its keys, and the crossings in both directions."""

    def __init__(self, td):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        j = lambda n: os.path.join(td, n)  # noqa: E731
        S.keygen(j("ed.key")); S.keygen_pq(j("pq.key"))
        S.sign_ledger(os.path.join(ROOT, "examples", "sample_ledger.jsonl"), j("signed.jsonl"), keyfile=j("ed.key"),
                      pq_keyfile=j("pq.key"))
        with open(j("signed.jsonl"), encoding="utf-8") as f:
            self.entries = [json.loads(ln) for ln in f if ln.strip()]
        self.e = self.entries[0]
        self.pq_sk, _ = S.load_pq_key(j("pq.key"))
        with open(j("ed.key"), encoding="utf-8") as f:
            self.ed_sk = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(f.read().strip()))
        self.msg = self.e["self_hash"].encode()
        self.comp_pk = base64.b64decode(self.e["signer_pq"]) + bytes.fromhex(self.e["signer"])   # §4.1: mldsaPK || tradPK

    def ledger_ok(self, first):
        return S.verify_ledger_signatures([first] + self.entries[1:], self.e["signer"], self.e["signer_pq"])

    def crossing_failures(self, composite=Composite):
        """Every crossing that verifies (should be none), and every direct check that does not (should be none)."""
        bad = []
        if not S.verify_ledger_signatures(self.entries, self.e["signer"], self.e["signer_pq"])["ok"]:
            bad.append("direct: the hybrid ledger does not verify")
        sig = composite.sign(self.pq_sk, self.ed_sk, self.msg)
        if not composite.verify(self.comp_pk, self.msg, sig):
            bad.append("direct: the composite does not verify")
        hybrid_pair = base64.b64decode(self.e["signature_pq"]) + base64.b64decode(self.e["signature"])
        if composite.verify(self.comp_pk, self.msg, hybrid_pair):
            bad.append("crossing: the hybrid's two signatures verify as a composite signature")
        halves = {"both halves": dict(self.e, signature=base64.b64encode(sig[MLDSA65_SIG:]).decode(),
                                      signature_pq=base64.b64encode(sig[:MLDSA65_SIG]).decode()),
                  "the Ed25519 half": dict(self.e, signature=base64.b64encode(sig[MLDSA65_SIG:]).decode()),
                  "the ML-DSA half": dict(self.e, signature_pq=base64.b64encode(sig[:MLDSA65_SIG]).decode()),
                  "the whole value as signature_pq": dict(self.e, signature_pq=base64.b64encode(sig).decode()),
                  "the whole value as signature": dict(self.e, signature=base64.b64encode(sig).decode())}
        for name, entry in halves.items():
            r = self.ledger_ok(entry)
            if r["ok"] or r.get("pq_protected") is True:
                bad.append(f"crossing: {name} of a composite signature verifies as the hybrid entry")
        return bad


@unittest.skipIf(S._mldsa() is None, "needs `cryptography` with ML-DSA (the `sign` extra)")
class HybridIsNotComposite(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.td = tempfile.TemporaryDirectory()
        cls.h = Hybrid(cls.td.name)

    @classmethod
    def tearDownClass(cls):
        cls.td.cleanup()

    def test_both_directions(self):
        self.assertEqual(self.h.crossing_failures(), [])

    def test_positive_control_the_hybrids_own_bytes_are_caught(self):
        class SameBytes(Composite):            # signs the message itself, empty ML-DSA context: what the hybrid signs
            mp = staticmethod(lambda message, ctx=b"": message)
            mldsa_ctx = None
        bad = self.h.crossing_failures(SameBytes)
        self.assertIn("crossing: the hybrid's two signatures verify as a composite signature", bad)
        self.assertIn("crossing: both halves of a composite signature verifies as the hybrid entry", bad)

    def test_the_helper_refuses_what_rfc_10073_refuses(self):
        sig = Composite.sign(self.h.pq_sk, self.h.ed_sk, self.h.msg)
        self.assertEqual((len(sig), len(self.h.comp_pk)), (MLDSA65_SIG + ED_SIG, MLDSA65_PK + ED_PK))
        self.assertFalse(Composite.verify(self.h.comp_pk, self.h.msg + b"x", sig))
        self.assertFalse(Composite.verify(self.h.comp_pk, self.h.msg, sig, ctx=b"other"))
        self.assertFalse(Composite.verify(self.h.comp_pk, self.h.msg, sig[:-1]))
        for i in (0, MLDSA65_SIG - 1, MLDSA65_SIG, len(sig) - 1):          # one bit in either component: invalid (§3.3)
            b = bytearray(sig); b[i] ^= 1
            self.assertFalse(Composite.verify(self.h.comp_pk, self.h.msg, bytes(b)), i)
        with self.assertRaises(ValueError):
            m_prime(b"m", bytes(256))

    def test_m_prime_bytes(self):
        mp = m_prime(b"abc")
        self.assertEqual(mp[:32].hex().upper(), "436F6D706F73697465416C676F726974686D5369676E61747572657332303235")
        self.assertEqual(mp[32:62], LABEL)
        self.assertEqual(mp[62], 0); self.assertEqual(mp[63:], hashlib.sha512(b"abc").digest())
        self.assertEqual(m_prime(b"abc", b"xy")[62:65], b"\x02xy")

    def test_the_mldsa_half_is_bound_to_the_label(self):
        from cryptography.exceptions import InvalidSignature
        sig = Composite.sign(self.h.pq_sk, self.h.ed_sk, self.h.msg)[:MLDSA65_SIG]
        pk = self.h.pq_sk.public_key()
        pk.verify(sig, m_prime(self.h.msg), LABEL)
        with self.assertRaises(InvalidSignature):
            pk.verify(sig, m_prime(self.h.msg))                 # the empty context: the hybrid's profile

    @unittest.skipUnless(os.environ.get("CV_RFC10073_TXT"), "the RFC 10073 text is not given (CV_RFC10073_TXT)")
    def test_helper_against_rfc_10073_appendix_e(self):
        m, ctx, tc = _appendix_e(os.environ["CV_RFC10073_TXT"], "id-MLDSA65-Ed25519-SHA512")
        pk, s, sc = (base64.b64decode(tc[k]) for k in ("pk", "s", "sWithContext"))
        self.assertTrue(Composite.verify(pk, m, s))
        self.assertTrue(Composite.verify(pk, m, sc, ctx))
        self.assertFalse(Composite.verify(pk, m, sc))            # null controls: the other context, another message
        self.assertFalse(Composite.verify(pk, m + b".", s))


def _appendix_e(path, tc_id):
    """(m, ctx, test case) of RFC 10073 Appendix E, read from the RFC's text (page breaks dropped, wrapped strings
    joined)."""
    with open(path, encoding="utf-8") as f:
        t = f.read()
    t = t[t.rindex("Appendix E.  Test Vectors"):]
    lines = [ln for ln in t.splitlines() if "\f" not in ln and not ln.startswith(("Ounsworth", "RFC 10073 "))]
    blob = "\n".join(lines)
    blob = blob[blob.index("{"):]
    out, inq, i = [], False, 0
    while i < len(blob):
        c = blob[i]
        if c == '"':
            inq = not inq
        if inq and c == "\n":
            i += 1
            while i < len(blob) and blob[i] == " ":
                i += 1
            continue
        out.append(c)
        i += 1
    s = "".join(out)
    d, _ = json.JSONDecoder().raw_decode(s)
    tc = next(x for x in d["tests"] if x["tcId"] == tc_id)
    return base64.b64decode(d["m"]), base64.b64decode(d["ctx"]), tc


if __name__ == "__main__":
    unittest.main(verbosity=1)
