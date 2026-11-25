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
# the module where each system installs it; CV_SOFTHSM_MODULE overrides (the Windows CI builds it: no binary exists)
_SOFTHSM = os.environ.get("CV_SOFTHSM_MODULE") or next(iter(
    glob.glob("/usr/lib/softhsm/libsofthsm2.so") + glob.glob("/usr/lib/*/softhsm/libsofthsm2.so")
    + glob.glob("/opt/homebrew/lib/softhsm/libsofthsm2.so") + glob.glob("/usr/local/lib/softhsm/libsofthsm2.so")), None)
if os.environ.get("CV_REQUIRE_SOFTHSM") == "1" and not (_SOFTHSM and os.path.exists(_SOFTHSM)
                                                         and shutil.which("pkcs11-tool")):
    raise RuntimeError(f"CV_REQUIRE_SOFTHSM=1 and SoftHSM2/pkcs11-tool missing ({_SOFTHSM})")
_HAVE_SOFTHSM = bool(_SOFTHSM and os.path.exists(_SOFTHSM) and shutil.which("pkcs11-tool"))


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
        self.assertEqual(open(s1, encoding="utf-8").read(), open(s2, encoding="utf-8").read())            # Ed25519 = deterministico
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
                           cwd=_HERE, capture_output=True, text=True, encoding="utf-8")
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


_NETHSM_DEMO = os.environ.get("NETHSM_TEST_URL", "https://nethsmdemo.nitrokey.com")


def _nethsm_demo_reachable():
    """La demo pubblica si resetta ogni 8h e può essere giù: skip ONESTO, mai un
    finto verde. Raggiungibile = /health/state risponde 'Operational'."""
    import urllib.request
    try:
        with urllib.request.urlopen(f"{_NETHSM_DEMO}/api/v1/health/state",
                                    timeout=10) as r:
            return b"Operational" in r.read()
    except Exception:  # noqa: BLE001
        return False


class TestNetHsmMalformedAnswers(unittest.TestCase):
    """every malformed NetHSM answer is a named RuntimeError (until 0.29.0 a KeyError or a TypeError)"""

    def test_each_shape(self):
        from unittest import mock
        import cryptovalid_kms as K
        with mock.patch.dict(os.environ, {"NETHSM_PASS": "p"}):
            b = K.NetHsmBackend("http://127.0.0.1:9", "k", "u")
        answers = [{}, [], None, 5, {"public": None}, {"public": {"data": 5}}, {"public": {"data": "!!"}},
                   {"public": {"data": "AAAA"}}, {"signature": None}, {"signature": "@@"}, {"signature": "AAAA"}]
        for a in answers:
            with mock.patch.object(b, "_req", lambda *x, a=a, **k: a):
                for call in (b.public_key_hex, lambda: b.sign(b"m")):
                    with self.assertRaises(RuntimeError, msg=(a, call)):
                        call()
        raw = [b"\xff", b"{", b"[" * 600 + b"]" * 600]
        for body in raw:
            class R:
                def __enter__(self):
                    return self

                def __exit__(self, *x):
                    return False
            with mock.patch.object(K._net, "open_url", lambda *x, **k: R()), \
                    mock.patch.object(K._net, "read_body", lambda r, *x, body=body: body):
                with self.assertRaises(RuntimeError, msg=body):
                    b._req("GET", "keys/k")


class TestNetHsmUriAndErrors(unittest.TestCase):
    """Rami senza rete: contratto URI e errori puliti."""

    def test_missing_pass_env_clean_error(self):
        os.environ.pop("NETHSM_PASS_MANCANTE", None)
        with self.assertRaises(RuntimeError):
            kms.NetHsmBackend(url="https://x", key="k", user="u",
                              pass_env="NETHSM_PASS_MANCANTE")

    def test_plain_http_non_loopback_refused(self):
        os.environ["NETHSM_PASS"] = "x"
        with self.assertRaises(RuntimeError):
            kms.NetHsmBackend(url="http://nethsm.example.com", key="k", user="u")

    def test_uri_missing_required_keys(self):
        for bad in ("nethsm:url=https://x", "nethsm:key=k;user=u"):
            with self.assertRaises(ValueError):
                kms.backend_from_uri(bad)


@unittest.skipUnless(_HAVE_CRYPTO and _nethsm_demo_reachable(),
                     "NetHSM public demo unreachable (honest skip)")
class TestNetHsmDemoLive(unittest.TestCase):
    """Banco d'INTEGRAZIONE live contro la demo pubblica Nitrokey (reset ogni 8h,
    credenziali note): prova il backend remoto REALE. Non è custodia."""

    @classmethod
    def setUpClass(cls):
        import uuid
        os.environ["NETHSM_PASS"] = "adminadmin"        # credenziali PUBBLICHE demo
        cls.key_id = f"cvtest{uuid.uuid4().hex[:12]}"
        admin = kms.backend_from_uri(
            f"nethsm:url={_NETHSM_DEMO};key={cls.key_id};user=admin")
        cls.pub = admin.keygen()                         # nasce SULL'HSM remoto (Admin)
        # separazione ruoli NetHSM: l'Administrator NON firma — serve un Operator
        op_user, op_pass = f"op{uuid.uuid4().hex[:10]}", uuid.uuid4().hex
        admin._req("PUT", f"users/{op_user}",
                   {"realName": "bench", "role": "Operator", "passphrase": op_pass})
        os.environ["NETHSM_OP_PASS"] = op_pass
        cls.be = kms.backend_from_uri(
            f"nethsm:url={_NETHSM_DEMO};key={cls.key_id};user={op_user};"
            "pass_env=NETHSM_OP_PASS")

    def test_remote_sign_verifies_and_tamper_fails(self):
        self.assertEqual(len(self.pub), 64)
        self.assertFalse(self.be.describe()["key_in_process_memory"])
        msg = b"sth-canonical-hash-bench-remoto"
        sig = self.be.sign(msg)
        self.assertEqual(len(sig), 64)
        _verify_raw(self.pub, sig, msg)                  # controllo positivo
        with self.assertRaises(Exception):                # controllo negativo
            _verify_raw(self.pub, bytes([sig[0] ^ 1]) + sig[1:], msg)

    def test_sign_ledger_e2e_via_nethsm(self):
        import tempfile
        d = tempfile.mkdtemp()
        ledger = os.path.join(d, "l.jsonl"); _make_ledger(ledger)
        signed = os.path.join(d, "signed.jsonl")
        r = signer.sign_ledger(ledger, signed, backend=self.be)
        self.assertEqual(r["signer"], self.pub)
        self.assertTrue(signer.verify_file(signed, pubkey_hex=self.pub)["ok"])


@unittest.skipUnless(_HAVE_CRYPTO and _HAVE_SOFTHSM,
                     "requires the SoftHSM2 module + OpenSC pkcs11-tool (real PKCS#11 bench)")
class TestPkcs11SoftHsm(unittest.TestCase):
    """REAL end-to-end HSM bench: throwaway SoftHSM2 token, non-exportable key,
    ledger signed via PKCS#11, verified by the unchanged stdlib verifier."""

    @classmethod
    def setUpClass(cls):
        cls.d = tempfile.mkdtemp()
        tokens = os.path.join(cls.d, "tokens"); os.makedirs(tokens)
        cls.conf = os.path.join(cls.d, "softhsm2.conf")
        with open(cls.conf, "w", encoding="utf-8", newline="") as f:
            f.write(f"directories.tokendir = {tokens}\nobjectstore.backend = file\nlog.level = ERROR\n")
        cls.env = {**os.environ, "SOFTHSM2_CONF": cls.conf, "CRYPTOVALID_PIN": "1234", "CV_SO_PIN": "5678"}
        # the token made through the module with pkcs11-tool, on every system (the SoftHSM2 build for Windows has no
        # softhsm2-util on PATH: CI run 45437498313); a failure names pkcs11-tool's own words
        for argv in (["--init-token", "--label", "cvtest", "--so-pin", "env:CV_SO_PIN", "--slot-index", "0"],
                     ["--token-label", "cvtest", "--init-pin", "--login", "--login-type", "so", "--so-pin",
                      "env:CV_SO_PIN", "--pin", "env:CRYPTOVALID_PIN"]):
            r = subprocess.run(["pkcs11-tool", "--module", _SOFTHSM] + argv, env=cls.env, capture_output=True, timeout=60)
            if r.returncode:
                raise RuntimeError("token initialisation failed: %r" % r.stderr[-300:])
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
        rows = [json.loads(x) for x in open(signed, encoding="utf-8")]
        rows[0]["data"]["result"] = "fail"                 # manomissione
        tampered = os.path.join(self.d, "tampered.jsonl")
        with open(tampered, "w", encoding="utf-8", newline="") as f:
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


class TestPkcs11ChildAndShapes(unittest.TestCase):
    """Fleet audit of 2026-11-24 (pq-scitt 4aff166 + 61ab771, NEMESIS): the PKCS#11 calls run in a child process
    with an enforced time limit; the public key is read through the module (CKA_EC_POINT); the structures are packed
    on Windows."""

    def test_ec_point_forms_and_refusals(self):
        pub = bytes(range(32))
        oid, name = bytes.fromhex("06032b6570"), b"\x13\x0cedwards25519"
        for p in (oid, name):
            self.assertEqual(kms._ed25519_from_ec_point(b"\x04\x20" + pub, p), pub)
            self.assertEqual(kms._ed25519_from_ec_point(pub, p), pub)
        for point, p in ((b"\x04\x20" + pub, bytes.fromhex("06032b6571")), (b"\x04\x21" + pub + b"\x00", oid),
                         (pub[:31], oid), (b"\x04\x20" + pub[:31], oid), (b"\x05\x20" + pub, oid), (pub, b""),
                         (pub + b"\x00", oid)):
            with self.assertRaises(ValueError, msg=(point.hex(), p.hex())):
                kms._ed25519_from_ec_point(point, p)

    def test_a_blocked_call_is_stopped(self):
        import time
        c = kms._Pkcs11Child(1.0)
        c.command = [sys.executable, "-c", "import time; time.sleep(600)"]
        t0 = time.monotonic()
        with self.assertRaises(RuntimeError) as e:
            c.call({"op": "pub"}, "read public key")
        self.assertIn("timeout after 1.0 s", str(e.exception))
        self.assertLess(time.monotonic() - t0, 15)
        self.assertIsNone(c._proc)   # killed and dropped
        c = kms._Pkcs11Child(30.0)   # control: an answer is read, a child that ends without one is an error
        c.command = [sys.executable, "-c", "import sys; sys.stdin.readline(); print('{\"ok\": \"00ff\"}', flush=True)"]
        self.assertEqual(c.call({"op": "pub"}, "x"), b"\x00\xff")
        c.command = [sys.executable, "-c", "import sys; sys.stdin.readline(); sys.exit(3)"]
        with self.assertRaises(RuntimeError) as e:
            c.call({"op": "pub"}, "x")
        self.assertIn("ended", str(e.exception))

    def test_a_child_that_does_not_read_is_stopped_at_the_limit(self):
        import time
        c = kms._Pkcs11Child(1.0)
        c.command = [sys.executable, "-c", "import time; time.sleep(60)"]
        t0 = time.monotonic()
        with self.assertRaises(RuntimeError) as e:
            c.call({"op": "sign", "msg": "00" * (1 << 20)}, "sign")
        self.assertIn("timeout after 1.0 s", str(e.exception))
        self.assertLess(time.monotonic() - t0, 15)

    def test_the_child_imports_nothing_from_the_current_folder(self):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "json.py"), "w", encoding="utf-8", newline="") as f:
                f.write("open(%r, 'w').close()\nraise SystemExit(3)\n" % os.path.join(d, "RAN"))
            r = subprocess.run(kms._Pkcs11Child(5.0).command, cwd=d, input=b'{"op": "x"}\n', capture_output=True,
                               timeout=120)
            self.assertFalse(os.path.exists(os.path.join(d, "RAN")), "the child ran json.py of the current folder")
            self.assertEqual((r.returncode, r.stdout.strip()), (0, b'{"err": "unknown request"}'), r.stderr[-300:])

    def test_a_module_printing_on_stdout_stays_out_of_the_protocol(self):
        code = ("import os, sys; sys.path[:] = [p for p in sys.path if p != '']; sys.path.append(sys.argv[1]); "
                "import cryptovalid_kms as k; "
                "k._p11_public_key = lambda *a: (os.write(1, b'vendor debug line\\n'), b'\\x01' * 32)[1]; "
                "k._p11_worker()")
        r = subprocess.run([sys.executable, "-B", "-c", code, kms._Pkcs11Child(5.0).command[-1]],
                           input=b'{"op": "pub", "module": "m", "token": "t", "key": "k"}\n', capture_output=True,
                           timeout=120)
        self.assertEqual(r.stdout.splitlines(), [('{"ok": "%s"}' % ("01" * 32)).encode()], r.stderr[-300:])

    def test_an_answer_out_of_form_stops_the_child(self):
        for line in ("vendor debug", "1", "[]", "{}", '{"ok": "zz"}', '{"ok": 5}', '{"err": 5}', '{"other": "00"}',
                     '{"ok": "00", "err": "x"}'):
            c = kms._Pkcs11Child(30.0)
            c.command = [sys.executable, "-c", "import sys, time; sys.stdin.readline(); print(sys.argv[1], flush=True); "
                                               "print('{\"ok\": \"aa\"}', flush=True); time.sleep(600)", line]
            with self.assertRaises(RuntimeError, msg=line) as e:
                c.call({"op": "pub"}, "x")
            self.assertIn("out of form", str(e.exception), line)
            self.assertIsNone(c._proc, line)

    def test_structures_as_pkcs11_h(self):
        import ctypes
        a, m = kms._p11_structures()
        u, p = ctypes.sizeof(ctypes.c_ulong), ctypes.sizeof(ctypes.c_void_p)
        natural = ctypes.sizeof(type("N", (ctypes.Structure,), {"_fields_": [("a", ctypes.c_ulong), ("b", ctypes.c_void_p),
                                                                             ("c", ctypes.c_ulong)]}))
        want = 2 * u + p if os.name == "nt" else natural
        self.assertEqual((ctypes.sizeof(a), ctypes.sizeof(m)), (want, want))
        if os.name == "nt":
            self.assertEqual((u, ctypes.sizeof(a), a.ulValueLen.offset), (4, 16, 12))   # Win64, pack(1)


class TestPkcs11ToolByItsPath(unittest.TestCase):
    """pkcs11-tool is run by the path shutil.which names (a bare name on Windows: program folder, current folder and
    System32 come before PATH)"""

    def test_the_path_which_names_is_run(self):
        from unittest import mock
        seen, exe = [], os.path.abspath("/opt/opensc/bin/pkcs11-tool")   # Windows: on this drive
        with mock.patch.object(kms.shutil, "which", lambda n: exe if n == "pkcs11-tool" else None), \
                mock.patch.dict(os.environ, {"CV_TEST_PIN": "1"}):
            b = kms.Pkcs11Backend("m.so", "t", "k", pin="env:CV_TEST_PIN")
            with mock.patch.object(kms.subprocess, "run",
                                   lambda cmd, **kw: (seen.append(cmd[0]), subprocess.CompletedProcess(cmd, 0, b"", b""))[1]):
                b._run(["--list-objects"])
        self.assertEqual(seen, [exe])

    def test_without_the_tool_no_backend(self):
        from unittest import mock
        with mock.patch.object(kms.shutil, "which", lambda n: None), mock.patch.dict(os.environ, {"CV_TEST_PIN": "1"}):
            with self.assertRaises(RuntimeError) as c:
                kms.Pkcs11Backend("m.so", "t", "k", pin="env:CV_TEST_PIN")
        self.assertIn("pkcs11-tool not found", str(c.exception))


if __name__ == "__main__":
    unittest.main(verbosity=2)
