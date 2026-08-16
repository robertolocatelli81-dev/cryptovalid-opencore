#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Roberto Locatelli
"""KMS/HSM backend tests — honest scope of each bench:
  - file backend + SPKI parsing: fully exercised in-process;
  - pkcs11: REAL end-to-end against SoftHSM2 (its own throwaway token) when
    softhsm2+opensc are installed, honest skip otherwise;
  - vault: protocol test against a local stub that signs with a real Ed25519 key
    (client logic real, server stubbed — NOT a live Vault);
  - awskms: API-contract test with an injected fake client (checks MessageType RAW +
    ED25519_SHA_512 + SPKI parsing — NOT a live AWS call).
Every bench includes a negative control (tamper -> must FAIL)."""
import base64
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
import cryptovalid_kms as kms  # noqa: E402
import signer  # noqa: E402
import verifier  # noqa: E402
from test_signer import _make_ledger  # noqa: E402

try:
    from cryptography.hazmat.primitives import serialization as _ser
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey, Ed25519PublicKey)
    _HAVE_CRYPTO = True
except ImportError:  # pragma: no cover
    _HAVE_CRYPTO = False

import glob
_SOFTHSM = next(iter(glob.glob("/usr/lib/softhsm/libsofthsm2.so")
                     + glob.glob("/usr/lib/*/softhsm/libsofthsm2.so")), None)
_HAVE_SOFTHSM = (_SOFTHSM and shutil.which("pkcs11-tool")
                 and shutil.which("softhsm2-util"))


def _verify_raw(pub_hex, sig, msg):
    Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub_hex)).verify(sig, msg)


@unittest.skipUnless(_HAVE_CRYPTO, "requires 'cryptography'")
class TestSpkiAndFileBackend(unittest.TestCase):
    def test_spki_der_pem_raw(self):
        sk = Ed25519PrivateKey.generate()
        raw = sk.public_key().public_bytes(_ser.Encoding.Raw, _ser.PublicFormat.Raw)
        der = sk.public_key().public_bytes(_ser.Encoding.DER,
                                           _ser.PublicFormat.SubjectPublicKeyInfo)
        pem = sk.public_key().public_bytes(_ser.Encoding.PEM,
                                           _ser.PublicFormat.SubjectPublicKeyInfo)
        for enc in (der, pem, raw):
            self.assertEqual(kms._raw_from_spki(enc), raw)
        with self.assertRaises(ValueError):
            kms._raw_from_spki(b"\x30\x82garbage-not-ed25519-spki")

    def test_file_backend_matches_legacy_signer(self):
        d = tempfile.mkdtemp()
        keyfile = os.path.join(d, "signer.key")
        info = signer.keygen(keyfile)
        be = kms.backend_from_uri(f"file:{keyfile}")
        self.assertEqual(be.public_key_hex(), info["public_key_hex"])
        sig = be.sign(b"msg")
        _verify_raw(be.public_key_hex(), sig, b"msg")
        self.assertTrue(be.describe()["key_in_process_memory"])

    def test_sign_ledger_via_backend_equals_keyfile_path(self):
        d = tempfile.mkdtemp()
        ledger, keyfile = os.path.join(d, "l.jsonl"), os.path.join(d, "k.key")
        _make_ledger(ledger); signer.keygen(keyfile)
        s1, s2 = os.path.join(d, "s1.jsonl"), os.path.join(d, "s2.jsonl")
        signer.sign_ledger(ledger, s1, keyfile)                       # legacy path
        signer.sign_ledger(ledger, s2, backend=kms.FileKeyBackend(keyfile))  # backend path
        self.assertEqual(open(s1).read(), open(s2).read())            # Ed25519 = deterministico
        self.assertTrue(signer.verify_file(s2)["ok"])

    def test_unknown_scheme_and_missing_key(self):
        with self.assertRaises(ValueError):
            kms.backend_from_uri("gcpkms:key=x")
        with self.assertRaises(ValueError):
            signer.sign_ledger("in", "out")   # né keyfile né backend

    def test_uri_missing_required_keys_clean_error(self):
        for bad in ("pkcs11:module=/x/y.so", "awskms:region=eu-south-1", "vault:key=cv"):
            with self.assertRaises(ValueError) as cm:
                kms.backend_from_uri(bad)
            self.assertIn("missing required", str(cm.exception))

    def test_post_sign_self_check_catches_wrong_key(self):
        # backend che DICHIARA una pubblica ma firma con un'ALTRA chiave
        # (es. rotazione a metà ledger): sign_ledger deve fallire subito
        class RottenBackend:
            def __init__(self):
                self.declared = Ed25519PrivateKey.generate()
                self.actual = Ed25519PrivateKey.generate()

            def public_key_hex(self):
                return self.declared.public_key().public_bytes(
                    _ser.Encoding.Raw, _ser.PublicFormat.Raw).hex()

            def sign(self, message):
                return self.actual.sign(message)

        d = tempfile.mkdtemp()
        ledger = os.path.join(d, "l.jsonl"); _make_ledger(ledger)
        with self.assertRaises(Exception):
            signer.sign_ledger(ledger, os.path.join(d, "s.jsonl"), backend=RottenBackend())

    def test_cli_sign_without_keyfile_or_backend_clean_error(self):
        r = subprocess.run([sys.executable, "signer.py", "sign", "a.jsonl", "b.jsonl"],
                           cwd=_HERE, capture_output=True, text=True)
        self.assertEqual(r.returncode, 2)                     # errore argparse, non traceback
        self.assertNotIn("Traceback", r.stderr)
        self.assertIn("--backend", r.stderr)

    def test_vault_plain_http_non_loopback_refused(self):
        os.environ["VAULT_TOKEN"] = "t"
        try:
            with self.assertRaises(RuntimeError) as cm:
                kms.VaultTransitBackend(url="http://10.0.0.5:8200", key="cv")
            self.assertIn("cleartext", str(cm.exception))
        finally:
            os.environ.pop("VAULT_TOKEN", None)


@unittest.skipUnless(_HAVE_CRYPTO and _HAVE_SOFTHSM,
                     "requires softhsm2 + opensc (real PKCS#11 bench)")
class TestPkcs11SoftHsm(unittest.TestCase):
    """REAL end-to-end HSM bench: throwaway SoftHSM2 token, non-exportable key,
    ledger signed via PKCS#11, verified by the unchanged stdlib verifier."""

    @classmethod
    def setUpClass(cls):
        cls.d = tempfile.mkdtemp()
        tokens = os.path.join(cls.d, "tokens"); os.makedirs(tokens)
        cls.conf = os.path.join(cls.d, "softhsm2.conf")
        with open(cls.conf, "w") as f:
            f.write(f"directories.tokendir = {tokens}\n")
        cls.env = {**os.environ, "SOFTHSM2_CONF": cls.conf, "CRYPTOVALID_PIN": "1234"}
        subprocess.run(["softhsm2-util", "--init-token", "--free", "--label", "cvtest",
                        "--pin", "1234", "--so-pin", "5678"],
                       env=cls.env, check=True, capture_output=True)
        os.environ.update({"SOFTHSM2_CONF": cls.conf, "CRYPTOVALID_PIN": "1234"})
        cls.be = kms.backend_from_uri(
            f"pkcs11:module={_SOFTHSM};token=cvtest;key=evidence;pin=env:CRYPTOVALID_PIN")
        cls.pub = cls.be.keygen()

    def test_keygen_pubkey_shape(self):
        self.assertEqual(len(self.pub), 64)
        self.assertEqual(self.be.public_key_hex(), self.pub)
        self.assertFalse(self.be.describe()["key_in_process_memory"])

    def test_hsm_signature_verifies_offline(self):
        msg = b"self-hash-of-a-ledger-entry"
        sig = self.be.sign(msg)
        self.assertEqual(len(sig), 64)
        _verify_raw(self.pub, sig, msg)                    # controllo positivo
        with self.assertRaises(Exception):                  # controllo negativo
            _verify_raw(self.pub, bytes([sig[0] ^ 1]) + sig[1:], msg)

    def test_sign_ledger_e2e_and_tamper_fails(self):
        ledger = os.path.join(self.d, "l.jsonl"); _make_ledger(ledger)
        signed = os.path.join(self.d, "signed.jsonl")
        r = signer.sign_ledger(ledger, signed, backend=self.be)
        self.assertEqual(r["signer"], self.pub)
        self.assertTrue(signer.verify_file(signed, pubkey_hex=self.pub)["ok"])
        self.assertEqual(verifier.verify_ledger(signed)["verdict"], "PASS")
        rows = [json.loads(x) for x in open(signed)]
        rows[0]["data"]["result"] = "fail"                 # manomissione
        tampered = os.path.join(self.d, "tampered.jsonl")
        with open(tampered, "w") as f:
            for row in rows:
                f.write(json.dumps(row) + "\n")
        self.assertFalse(signer.verify_file(tampered)["ok"])

    def test_pin_must_be_env(self):
        with self.assertRaises(ValueError):
            kms.Pkcs11Backend(module=_SOFTHSM, token="cvtest", key="evidence", pin="1234")


@unittest.skipUnless(_HAVE_CRYPTO, "requires 'cryptography'")
class TestVaultTransitStub(unittest.TestCase):
    """Protocol bench: VaultTransitBackend against a local stub speaking the Transit API,
    backed by a REAL Ed25519 key. Honest: validates the client, not a live Vault."""

    @classmethod
    def setUpClass(cls):
        cls.sk = Ed25519PrivateKey.generate()
        raw_pub = cls.sk.public_key().public_bytes(_ser.Encoding.Raw, _ser.PublicFormat.Raw)
        sk = cls.sk

        class H(BaseHTTPRequestHandler):
            def _json(self, code, obj):
                body = json.dumps(obj).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.end_headers(); self.wfile.write(body)

            def do_GET(self):
                if self.headers.get("X-Vault-Token") != "test-token":
                    return self._json(403, {"errors": ["permission denied"]})
                if self.path == "/v1/transit/keys/cv":
                    return self._json(200, {"data": {"latest_version": 1, "keys": {
                        "1": {"public_key": base64.b64encode(raw_pub).decode()}}}})
                self._json(404, {"errors": []})

            def do_POST(self):
                if self.headers.get("X-Vault-Token") != "test-token":
                    return self._json(403, {"errors": ["permission denied"]})
                if self.path == "/v1/transit/sign/cv":
                    body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                    msg = base64.b64decode(body["input"])
                    sig = base64.b64encode(sk.sign(msg)).decode()
                    return self._json(200, {"data": {"signature": f"vault:v1:{sig}"}})
                self._json(404, {"errors": []})

            def log_message(self, *_):
                pass

        cls.srv = HTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
        os.environ["VAULT_TOKEN"] = "test-token"
        cls.be = kms.backend_from_uri(
            f"vault:url=http://127.0.0.1:{cls.srv.server_port};key=cv")

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()

    def test_pubkey_and_sign_roundtrip(self):
        pub = self.be.public_key_hex()
        sig = self.be.sign(b"entry-self-hash")
        _verify_raw(pub, sig, b"entry-self-hash")
        with self.assertRaises(Exception):
            _verify_raw(pub, sig, b"different-message")     # controllo negativo

    def test_missing_token_fails_closed(self):
        old = os.environ.pop("VAULT_TOKEN")
        try:
            with self.assertRaises(RuntimeError):
                kms.VaultTransitBackend(url="http://127.0.0.1:1", key="cv")
        finally:
            os.environ["VAULT_TOKEN"] = old


@unittest.skipUnless(_HAVE_CRYPTO, "requires 'cryptography'")
class TestAwsKmsContract(unittest.TestCase):
    """API-contract bench with an injected fake client holding a REAL Ed25519 key:
    checks exact request params (MessageType RAW + ED25519_SHA_512) and SPKI parsing.
    Honest: NOT a live AWS KMS call — that needs a real account/key."""

    def setUp(self):
        self.sk = Ed25519PrivateKey.generate()
        self.der = self.sk.public_key().public_bytes(
            _ser.Encoding.DER, _ser.PublicFormat.SubjectPublicKeyInfo)
        self.calls = []
        outer = self

        class FakeKms:
            def get_public_key(self, KeyId):
                outer.calls.append(("get_public_key", KeyId))
                return {"PublicKey": outer.der}

            def sign(self, **kw):
                outer.calls.append(("sign", kw))
                assert kw["MessageType"] == "RAW"
                assert kw["SigningAlgorithm"] == "ED25519_SHA_512"
                return {"Signature": outer.sk.sign(kw["Message"])}

        self.be = kms.AwsKmsBackend(key_id="alias/cryptovalid", client=FakeKms())

    def test_contract_and_verify(self):
        pub = self.be.public_key_hex()
        sig = self.be.sign(b"entry-self-hash")
        _verify_raw(pub, sig, b"entry-self-hash")
        self.assertEqual(self.calls[0], ("get_public_key", "alias/cryptovalid"))
        self.assertEqual(self.calls[1][1]["KeyId"], "alias/cryptovalid")

    def test_bad_signature_length_rejected(self):
        class BadKms:
            def sign(self, **kw):
                return {"Signature": b"\x00" * 63}
        be = kms.AwsKmsBackend(key_id="k", client=BadKms())
        with self.assertRaises(RuntimeError):
            be.sign(b"x")


if __name__ == "__main__":
    unittest.main(verbosity=2)
