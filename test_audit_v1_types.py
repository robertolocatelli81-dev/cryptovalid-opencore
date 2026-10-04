#!/usr/bin/env python3
"""audit V1 #8-#11 (30/09/2026): integer and base64url fields read strictly.
#8 SCITT and #9 COSE receipts: an inclusion proof's tree-size / leaf-index is a CBOR uint (RFC 9942); true/false is not.
#10 JWS and #11 AP2 signature segments: strict BASE64URL (RFC 7515 §2) — no '=' padding, no standard alphabet, no whitespace,
canonical. Each test fails on the code before the fix; fixtures are built here, in a temporary directory."""
import base64
import copy
import hashlib
import json
import os
import sys
import tempfile
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
import cryptovalid_receipt as R  # noqa: E402
import cryptovalid_scitt as S  # noqa: E402
import cryptovalid_jws as J  # noqa: E402
import ap2_evidence  # noqa: E402
import signer  # noqa: E402


def _flip(b):
    return b[:-1] + bytes([b[-1] ^ 1])


class TestCoseAndScittProofIntegers(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.d = tempfile.mkdtemp(prefix="v1types_")
        cls.key = os.path.join(cls.d, "k.key")
        cls.pk = signer.keygen(cls.key)["public_key_hex"]

    def _mut_proof(self, blob, fn, vdp_label, incl):
        p, uh, pl, sig = R.cbor_decode(blob[1:])
        uh = dict(uh); vdp = dict(uh[vdp_label])
        vdp[incl] = [R.cbor_encode(fn(R.cbor_decode(vdp[incl][0])))]
        uh[vdp_label] = vdp
        return b"\xd2" + R.cbor_encode([p, uh, pl, sig])

    def test_cose_receipt_tree_size_and_leaf_index_are_uint(self):
        led = os.path.join(self.d, "one.jsonl")
        e = {"idx": 0, "ts": "t", "data": {"a": 1}, "prev_hash": "0" * 64}
        e["self_hash"] = hashlib.sha256(json.dumps(e, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        open(led, "w").write(json.dumps(e) + "\n")
        r1 = R.inclusion_receipt(led, 0, self.key)
        c = R.to_cose(r1, self.key)
        leaf = r1["leaf_sha256"]
        self.assertTrue(R.verify_cose(c, self.pk, leaf_hash_hex=leaf)["ok"])          # control
        self.assertFalse(R.verify_cose(b"\xd2" + R.cbor_encode((lambda p, u, pl, s: [p, u, pl, _flip(s)])(*R.cbor_decode(c[1:]))),
                                       self.pk, leaf_hash_hex=leaf)["ok"])            # control: a broken signature fails
        for fn in (lambda d: [True, d[1], d[2]], lambda d: [d[0], False, d[2]],
                   lambda d: [d[0], d[1], b"\x00" * 32], lambda d: [d[0], d[1], {1: 2}],
                   lambda d: [d[0], d[1], {}]):   # path must be a list (NEMESIS RC7): on a one-leaf tree list({}) == [] would verify
            bad = self._mut_proof(c, fn, R.LABEL_VDP, R.PROOF_INCLUSION)
            self.assertFalse(R.verify_cose(bad, self.pk, leaf_hash_hex=leaf)["ok"])

    def test_scitt_receipt_tree_size_and_leaf_index_are_uint(self):
        ledger = os.path.join(self.d, "sc.jsonl")
        c = S.signed_statement(b"hello", "text/plain", "iss-a", "sub-a", self.key)
        reg = S.register(c, ledger, self.pk)
        rc = S.receipt(ledger, reg["index"], self.key, "ts-a")
        ok = S.verify_transparent_statement if hasattr(S, "verify_transparent_statement") else None
        self.assertIsNotNone(ok, "cryptovalid_scitt.verify_transparent_statement not found")
        good = S.transparent_statement(c, [rc])
        res = ok(good, self.pk, self.pk, expected_ts_iss="ts-a")
        self.assertTrue(res["ok"], res)                                                # control
        for fn in (lambda d: [True, d[1], d[2]], lambda d: [d[0], False, d[2]]):
            bad = S.transparent_statement(c, [self._mut_proof(rc, fn, S.L_VDP, S.VDP_INCLUSION)])
            self.assertFalse(ok(bad, self.pk, self.pk, expected_ts_iss="ts-a")["ok"])


class TestStrictBase64url(unittest.TestCase):
    def test_jws_signature_segment(self):
        d = tempfile.mkdtemp()
        key = os.path.join(d, "k.key"); signer.keygen(key)
        e = {"idx": 1, "ts": "t", "data": {"a": 1}, "prev_hash": "0" * 64, "self_hash": "ab" * 32}
        tok = J.sign_entry(e, key)
        pk = json.loads(base64.urlsafe_b64decode(tok.split(".")[0] + "=="))["kid"]
        h, p, s = tok.split(".")
        raw = base64.urlsafe_b64decode(s + "==")
        self.assertTrue(J.verify(tok, pk)["ok"])                                      # control
        variants = [s + "==", s[:10] + "!" + s[10:], s[:20] + " " + s[20:]]
        std = base64.b64encode(raw).decode().rstrip("=")
        if std != s:
            variants.append(std)
        alph = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
        variants.append(s[:-1] + alph[alph.index(s[-1]) ^ 1])                         # non-canonical unused bits
        for v in variants:
            self.assertFalse(J.verify(f"{h}.{p}.{v}", pk)["ok"], repr(v[-6:]))

    def test_ap2_signature_segment(self):
        import test_ap2_evidence as fx
        d = tempfile.mkdtemp()
        sk, jwk = fx._make_signer()
        sd = fx._make_sd_jwt(sk, {"iss": "wallet"}, {"amount": "9.99"}, header_extra={"jwk": jwk})
        out = os.path.join(d, "ev.json")
        ap2_evidence.build_evidence([{"name": "intent", "sd_jwt": sd}], out)
        self.assertTrue(ap2_evidence.verify_evidence(out)["valid"])                    # control
        ev0 = json.load(open(out))

        def with_sig(fn):
            ev = copy.deepcopy(ev0)
            comp = ev["artifacts"][0]["sd_jwt_compact"]
            jwt, rest = comp.split("~", 1)
            h, p, s = jwt.split(".")
            ev["artifacts"][0]["sd_jwt_compact"] = f"{h}.{p}.{fn(s)}~{rest}"
            body = {k: v for k, v in ev.items() if k not in ("evidence_digest_sha256", "rfc3161_timestamp", "producer_signatures")}
            ev["evidence_digest_sha256"] = hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
            json.dump(ev, open(out, "w"))
            return ap2_evidence.verify_evidence(out)

        self.assertTrue(with_sig(lambda s: s)["valid"])                                 # control: re-digest alone keeps it valid
        alph = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
        for fn in (lambda s: s + "=", lambda s: s + " ", lambda s: s[:-1] + alph[alph.index(s[-1]) ^ 1],   # unused bits (NEMESIS AP2)
                   lambda s: base64.b64encode(base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))).decode().rstrip("=")):
            sig = ev0["artifacts"][0]["sd_jwt_compact"].split("~", 1)[0].split(".")[2]
            if fn(sig) == sig:
                continue                                                               # no '+' or '/' in this signature
            self.assertFalse(with_sig(fn)["valid"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
