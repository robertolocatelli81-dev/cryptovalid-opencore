#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""cryptovalid_cose_receipts against the scitt-cose public vectors (0.26.0, 2026-11-17).

A cross-verification matrix measured 0.25.1 on these vectors: three refusals the vectors expect were accepted (ES256 over
a secp256k1 key, ES384 over a P-256 key, a valid inclusion proof followed by a malformed one). The rules of 0.26.0 are in
the module's docstring. Positive control: on 0.25.1 those three vectors are `ok: True` (measured on 2026-11-17 on the
0.25.1 tag), here they are refused; the vectors' SHA-256 are pinned in spec/vectors/scitt-cose/SHA256SUMS."""
import hashlib
import json
import os
import sys
import unittest

sys.dont_write_bytecode = True
ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)
VD = os.path.join(ROOT, "spec", "vectors", "scitt-cose")
TV = os.path.join(VD, "test-vectors")

try:
    import cryptography  # noqa: F401
    HAVE_CRYPTO = True
except ImportError:
    HAVE_CRYPTO = False
if os.environ.get("CV_REQUIRE_CRYPTO") == "1" and not HAVE_CRYPTO:
    raise RuntimeError("CV_REQUIRE_CRYPTO=1 and cryptography is not importable")
NEEDS = unittest.skipUnless(HAVE_CRYPTO, "needs cryptography")

# 0.26.0: what the module answers, vector by vector (stage None = accepted); the one declared exception is marked
EXPECTED = {
    "v1/fail-bad-statement-sig": "BAD_STATEMENT_SIGNATURE",
    "v1/fail-tampered-path": "INCLUSION_ROOT_SIGNATURE_INVALID",
    "v1/fail-unsupported-vds": "MALFORMED_PROOF",
    "v1/fail-zero-size-proof": "MALFORMED_PROOF",
    "v1/valid-ccf-vds2": None,
    "v1/valid-eddsa": None,
    "v1/valid-eddsa-multi-proof": None,
    "v1/valid-es256": None,
    "receipt-v1/fail-attached-payload": "INCLUSION_ROOT_SIGNATURE_INVALID",
    "receipt-v1/fail-attached-payload-root": None,          # declared: RFC 9942 §4.4 SHOULD, accepted and reported
    "receipt-v1/fail-eddsa-p256-key": "INCLUSION_ROOT_SIGNATURE_INVALID",
    "receipt-v1/fail-es256-secp256k1-key": "KEY_CURVE_MISMATCH",
    "receipt-v1/fail-es384-p256-key": "KEY_CURVE_MISMATCH",
    "receipt-v1/fail-malformed-proof": "MALFORMED_PROOF",
    "receipt-v1/fail-malformed-tail-proof": "MALFORMED_PROOF",
    "receipt-v1/fail-tampered-grade": "INCLUSION_ROOT_SIGNATURE_INVALID",
    "receipt-v1/fail-tampered-iat": "INCLUSION_ROOT_SIGNATURE_INVALID",
    "receipt-v1/fail-undefined-payload": "MALFORMED_RECEIPT",
    "receipt-v1/fail-unsupported-alg": "UNSUPPORTED_ALG",
    "receipt-v1/fail-wrong-log-key": "INCLUSION_ROOT_SIGNATURE_INVALID",
    "receipt-v1/synthetic-eddsa-iat-grade": None,
    "receipt-v1/synthetic-eddsa-iat-only": None,
    "receipt-v1/synthetic-es256-iat-grade": None,
    "receipt-v1/synthetic-es256-iat-grade-observed-only": None,
    "receipt-v1/trace-sept7-witness": None,
}
DECLARED = {"receipt-v1/fail-attached-payload-root"}
ACCEPTED_ON_0_25_1 = {"receipt-v1/fail-es256-secp256k1-key", "receipt-v1/fail-es384-p256-key",
                      "receipt-v1/fail-malformed-tail-proof"}


def _read(*p):
    with open(os.path.join(*p), "rb") as f:
        return f.read()


def run(name):
    import cryptovalid_cose_receipts as C
    d = os.path.join(TV, name)
    e = json.loads(_read(d, "expected.json"))
    if name.startswith("v1/"):
        o = C.verify_statement_with_receipt(_read(d, "statement.cose"), _read(d, "receipt.cose"), _read(d, "issuer-key.pub"),
                                            _read(d, "log-key.pub"), bytes.fromhex(e["leaf_entry"]),
                                            payload=_read(d, "payload.bin"))
        return o, e["result"] == "VALID", o["receipt"]
    o = C.verify_receipt(_read(d, "receipt.cose"), bytes.fromhex(e["leaf_entry_hex"]), _read(d, "log-key.pub"))
    return o, e["ok"], o


class Pinned(unittest.TestCase):
    def test_sha256_of_every_file(self):
        lines = _read(VD, "SHA256SUMS").decode().splitlines()
        self.assertEqual(len(lines), 102)
        for line in lines:
            h, name = line.split("  ", 1)
            self.assertEqual(hashlib.sha256(_read(VD, name)).hexdigest(), h, name)
        listed = {line.split("  ", 1)[1][2:] for line in lines}
        on_disk = {os.path.relpath(os.path.join(dp, f), VD) for dp, _, fs in os.walk(VD) for f in fs}
        self.assertEqual(on_disk - listed, {"SHA256SUMS", "README.md"})   # nothing unpinned

    def test_every_vector_is_listed_here(self):
        found = {f"{s}/{v}" for s in ("v1", "receipt-v1") for v in os.listdir(os.path.join(TV, s))
                 if os.path.isdir(os.path.join(TV, s, v))}
        self.assertEqual(found, set(EXPECTED))


@NEEDS
class Vectors(unittest.TestCase):
    def test_each_vector(self):
        for name, stage in EXPECTED.items():
            o, ok_expected, rc = run(name)
            self.assertEqual((o["ok"], o["stage"]), (stage is None, stage), name)
            if name not in DECLARED:
                self.assertEqual(o["ok"], ok_expected, name)                   # the vector's own expectation
            if o["ok"]:
                self.assertIs(rc["payload_attached"], name in DECLARED, name)

    def test_declared_exception_is_reported(self):
        o, ok_expected, _ = run("receipt-v1/fail-attached-payload-root")
        self.assertFalse(ok_expected)
        self.assertEqual((o["ok"], o["payload_attached"]), (True, True))
        o, _, _ = run("receipt-v1/fail-attached-payload")                    # attached and NOT the root: refused
        self.assertFalse(o["ok"])

    def test_verdicts_that_change_from_0_25_1(self):
        for name in ACCEPTED_ON_0_25_1:
            self.assertFalse(run(name)[0]["ok"], name)


@NEEDS
class CurveOfTheStatement(unittest.TestCase):
    """the same rule for a Signed Statement: keys and statements made here"""

    def statement(self, key, alg):
        import cryptovalid_receipt as R
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
        from cryptovalid_scitt import _sig1
        size, digest = {-7: (32, hashes.SHA256), -35: (48, hashes.SHA384)}[alg]
        pb = R.cbor_encode({1: alg})
        payload = b"a statement"
        r, s = decode_dss_signature(key.sign(_sig1(pb, payload), ec.ECDSA(digest())))
        sig = r.to_bytes(size, "big") + s.to_bytes(size, "big")
        return b"\xd2" + R.cbor_encode([pb, {}, payload, sig])

    def pem(self, key):
        from cryptography.hazmat.primitives import serialization as ser
        return key.public_key().public_bytes(ser.Encoding.PEM, ser.PublicFormat.SubjectPublicKeyInfo)

    def test_curves(self):
        import cryptovalid_cose_receipts as C
        from cryptography.hazmat.primitives.asymmetric import ec
        n = 0
        for curve, alg, ok in ((ec.SECP256R1(), -7, True), (ec.SECP256K1(), -7, False), (ec.SECP384R1(), -35, True),
                               (ec.SECP256R1(), -35, False), (ec.SECP384R1(), -7, False)):
            k = ec.generate_private_key(curve)
            try:
                st = self.statement(k, alg)
            except Exception:  # noqa: BLE001 — a signature size that does not fit the alg: cannot be made, nothing to test
                continue
            o = C.verify_statement(st, self.pem(k))
            self.assertEqual((o["ok"], o["stage"]), (ok, None if ok else "KEY_CURVE_MISMATCH"), (curve.name, alg))
            n += 1
        self.assertEqual(n, 4)                                            # P-384 r, s do not fit ES256's 32 bytes


if __name__ == "__main__":
    unittest.main()
