#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CryptoValid Open Core — KMS/HSM signing backends (the private key leaves the process).

SPDX-License-Identifier: AGPL-3.0-or-later
Copyright (C) 2026 Roberto Locatelli

Closes the gap "Ed25519 seed read from a local file into process memory": the signature
operation is delegated to a backend where the private key is NON-EXPORTABLE — a PKCS#11
HSM (YubiHSM 2, SoftHSM2, smartcard), AWS KMS (key spec ECC_NIST_EDWARDS25519, available
since 2025-11), or HashiCorp Vault Transit (key type ed25519). The evidence format does
NOT change: signatures stay 64-byte Ed25519 over `self_hash`, so `verifier.py` and
`signer.py verify` keep working unchanged, offline, stdlib-only.

Backends (URI-style selector, `backend_from_uri`):
  file:signer.key
      Legacy: hex seed on disk (0600). Key IS in process memory — kept for
      compatibility and tests; use an HSM/KMS backend in production.
  pkcs11:module=/usr/lib/softhsm/libsofthsm2.so;token=cryptovalid;key=evidence;pin=env:CRYPTOVALID_PIN
      Any PKCS#11 token via OpenSC `pkcs11-tool` (subprocess; no extra Python deps).
      The PIN is passed as `env:VAR` (never on argv → not visible in `ps`).
      Tested end-to-end against SoftHSM2 (mechanism EDDSA); YubiHSM 2 exposes the
      same mechanism via its PKCS#11 module (not tested on real hardware here — honest).
  awskms:key_id=<arn-or-id>;region=eu-south-1;profile=<optional>
      AWS KMS asymmetric key, KeySpec ECC_NIST_EDWARDS25519, SigningAlgorithm
      ED25519_SHA_512, MessageType RAW. Needs `boto3` (optional dep) + credentials.
      Provenance of the spec (verified 2026-08-16 against the official docs, not from
      memory): EdDSA support announced 2025-11-07
      (https://aws.amazon.com/about-aws/whats-new/2025/11/aws-kms-edwards-curve-digital-signature-algorithm/);
      per the key-spec reference, ED25519_SHA_512 is "NIST FIPS 186-5, Section 7.6"
      EdDSA — i.e. PureEdDSA/RFC 8032, same as every other backend here — and
      REQUIRES MessageType RAW (ED25519_PH_SHA_512/DIGEST is prehashed and NOT
      interchangeable; this module deliberately never uses it)
      (https://docs.aws.amazon.com/kms/latest/developerguide/symm-asymm-choose-key-spec.html).
      Exercised against that API contract with an injected client in tests — a live
      signature still requires a real AWS account (honest).
  vault:url=https://vault:8200;key=cryptovalid;mount=transit
  nethsm:url=https://nethsm.example.com;key=cryptovalid;user=operator;pass_env=NETHSM_PASS
      Nitrokey NetHSM (REST, basic-auth). Public demo nethsmdemo.nitrokey.com =
      integration bench ONLY (known credentials, reset every 8h), never custody.
      HashiCorp Vault Transit engine, key type ed25519. stdlib-only client
      (urllib); token from $VAULT_TOKEN. Protocol tested against a local stub
      that signs with a real Ed25519 key (honest: stub, not a live Vault).

Threat model (honest): these backends remove the *private key* from this process.
They do NOT protect against a compromised host that asks the HSM/KMS to sign
attacker-chosen data (use KMS policies/audit + HSM touch-policy for that), and the
file: backend keeps the old caveat entirely.
"""
from __future__ import annotations

import base64
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.parse
import urllib.request
from typing import Dict, Optional

ED25519_SPKI_PREFIX = bytes.fromhex("302a300506032b6570032100")  # RFC 8410 SPKI header


def _raw_from_spki(der_or_pem: bytes) -> bytes:
    """Extract the raw 32-byte Ed25519 public key from DER or PEM SPKI (RFC 8410)."""
    data = der_or_pem
    if b"-----BEGIN" in data:
        b64 = b"".join(l for l in data.splitlines() if b"-----" not in l)
        data = base64.b64decode(b64)
    if data.startswith(ED25519_SPKI_PREFIX) and len(data) == 44:
        return data[-32:]
    if len(data) == 32:               # already raw
        return data
    raise ValueError("not an Ed25519 SubjectPublicKeyInfo (RFC 8410)")


class FileKeyBackend:
    """Legacy backend: hex seed file. Private key IS loaded in memory (documented caveat)."""

    name = "file"

    def __init__(self, path: str):
        self._path = path
        self._cached = None

    def _sk(self):
        # cache: una lettura sola (evita N read + TOCTOU a metà ledger)
        if self._cached is None:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
            with open(self._path, encoding="utf-8") as f:
                self._cached = Ed25519PrivateKey.from_private_bytes(
                    bytes.fromhex(f.read().strip()))
        return self._cached

    def public_key_hex(self) -> str:
        from cryptography.hazmat.primitives import serialization as ser
        return self._sk().public_key().public_bytes(
            ser.Encoding.Raw, ser.PublicFormat.Raw).hex()

    def sign(self, message: bytes) -> bytes:
        return self._sk().sign(message)

    def describe(self) -> Dict:
        return {"backend": "file", "keyfile": self._path,
                "key_in_process_memory": True}


class Pkcs11Backend:
    """PKCS#11 token via OpenSC pkcs11-tool. The private key never enters this process."""

    name = "pkcs11"

    def __init__(self, module: str, token: str, key: str, pin: str = "env:CRYPTOVALID_PIN"):
        if shutil.which("pkcs11-tool") is None:
            raise RuntimeError("pkcs11-tool not found (install opensc)")
        if not pin.startswith("env:"):
            raise ValueError("pin must be 'env:VARNAME' (argv PINs leak via ps)")
        if not os.environ.get(pin[4:]):
            raise RuntimeError(f"PIN environment variable {pin[4:]!r} is empty/unset")
        self._module, self._token, self._key, self._pin = module, token, key, pin

    def _run(self, extra, login=False):
        cmd = ["pkcs11-tool", "--module", self._module, "--token-label", self._token]
        if login:
            cmd += ["--login", "--pin", self._pin]
        r = subprocess.run(cmd + extra, capture_output=True, timeout=60)
        if r.returncode != 0:
            raise RuntimeError(f"pkcs11-tool failed: {r.stderr.decode(errors='replace').strip()}")
        return r

    def keygen(self) -> str:
        """Generate a NON-EXPORTABLE Ed25519 keypair on the token. Returns public key hex."""
        self._run(["--keypairgen", "--key-type", "EC:edwards25519",
                   "--label", self._key], login=True)
        return self.public_key_hex()

    def public_key_hex(self) -> str:
        with tempfile.NamedTemporaryFile(suffix=".spki") as t:
            self._run(["--read-object", "--type", "pubkey",
                       "--label", self._key, "--output-file", t.name])
            with open(t.name, "rb") as f:
                return _raw_from_spki(f.read()).hex()

    def sign(self, message: bytes) -> bytes:
        with tempfile.NamedTemporaryFile(suffix=".msg") as m, \
             tempfile.NamedTemporaryFile(suffix=".sig") as s:
            m.write(message); m.flush()
            self._run(["--sign", "-m", "EDDSA", "--label", self._key,
                       "--input-file", m.name, "--output-file", s.name], login=True)
            with open(s.name, "rb") as f:
                sig = f.read()
        if len(sig) != 64:
            raise RuntimeError(f"expected 64-byte Ed25519 signature, got {len(sig)}")
        return sig

    def describe(self) -> Dict:
        return {"backend": "pkcs11", "module": self._module, "token": self._token,
                "key_label": self._key, "key_in_process_memory": False}


class AwsKmsBackend:
    """AWS KMS, KeySpec ECC_NIST_EDWARDS25519 (EdDSA support since 2025-11).
    SigningAlgorithm ED25519_SHA_512 requires MessageType RAW (PureEdDSA — same as the
    other backends, so verifier.py verifies these signatures unchanged)."""

    name = "awskms"

    def __init__(self, key_id: str, region: Optional[str] = None,
                 profile: Optional[str] = None, client=None):
        self._key_id = key_id
        if client is not None:          # test/DI hook
            self._client = client
        else:  # pragma: no cover - needs boto3 + real credentials
            try:
                import boto3
            except ImportError as e:
                raise RuntimeError("awskms backend requires 'boto3' (pip install boto3)") from e
            session = boto3.Session(profile_name=profile) if profile else boto3.Session()
            self._client = session.client("kms", region_name=region)

    def public_key_hex(self) -> str:
        der = self._client.get_public_key(KeyId=self._key_id)["PublicKey"]
        return _raw_from_spki(bytes(der)).hex()

    def sign(self, message: bytes) -> bytes:
        r = self._client.sign(KeyId=self._key_id, Message=message,
                              MessageType="RAW", SigningAlgorithm="ED25519_SHA_512")
        sig = bytes(r["Signature"])
        if len(sig) != 64:
            raise RuntimeError(f"expected 64-byte Ed25519 signature, got {len(sig)}")
        return sig

    def describe(self) -> Dict:
        return {"backend": "awskms", "key_id": self._key_id,
                "signing_algorithm": "ED25519_SHA_512", "key_in_process_memory": False}


class VaultTransitBackend:
    """HashiCorp Vault Transit engine, key type ed25519. stdlib-only (urllib).
    Token from $VAULT_TOKEN (never a constructor literal — avoids source-code leaks)."""

    name = "vault"
    _SIG_RE = re.compile(r"^vault:v(\d+):(.+)$")

    def __init__(self, url: str, key: str, mount: str = "transit",
                 token_env: str = "VAULT_TOKEN"):
        token = os.environ.get(token_env, "")
        if not token:
            raise RuntimeError(f"Vault token env var {token_env!r} is empty/unset")
        host = (urllib.parse.urlsplit(url).hostname or "").lower()
        if url.startswith("http://") and host not in ("127.0.0.1", "localhost", "::1"):
            raise RuntimeError("refusing plain http:// to a non-loopback Vault: "
                               "the token would travel in cleartext (use https)")
        self._url, self._key, self._mount, self._token = url.rstrip("/"), key, mount, token

    def _req(self, method: str, path: str, body: Optional[Dict] = None) -> Dict:
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(f"{self._url}/v1/{path}", data=data, method=method,
                                     headers={"X-Vault-Token": self._token,
                                              "Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.loads(r.read().decode())

    def public_key_hex(self) -> str:
        d = self._req("GET", f"{self._mount}/keys/{self._key}")["data"]
        latest = str(d["latest_version"])
        pk_b64 = d["keys"][latest]["public_key"]
        return _raw_from_spki(base64.b64decode(pk_b64)).hex()

    def sign(self, message: bytes) -> bytes:
        d = self._req("POST", f"{self._mount}/sign/{self._key}",
                      {"input": base64.b64encode(message).decode()})["data"]
        m = self._SIG_RE.match(d["signature"])
        if not m:
            raise RuntimeError("unexpected Vault signature format")
        sig = base64.b64decode(m.group(2))
        if len(sig) != 64:
            raise RuntimeError(f"expected 64-byte Ed25519 signature, got {len(sig)}")
        return sig

    def describe(self) -> Dict:
        return {"backend": "vault", "url": self._url, "key": self._key,
                "mount": self._mount, "key_in_process_memory": False}


def _parse_kv(spec: str) -> Dict[str, str]:
    out = {}
    for part in spec.split(";"):
        if part:
            k, _, v = part.partition("=")
            out[k.strip()] = v.strip()
    return out


class NetHsmBackend:
    """Nitrokey NetHSM via REST API (stdlib urllib, basic-auth; passphrase da env,
    mai literal nel codice). La chiave vive nell'HSM di rete: mai nel processo.
    Nota onesta: l'istanza DEMO pubblica (nethsmdemo.nitrokey.com, credenziali note,
    reset ogni 8 ore) è un BANCO DI INTEGRAZIONE, non custodia — per la custodia
    serve un NetHSM proprio (o l'operatore con passphrase segreta)."""

    name = "nethsm"

    def __init__(self, url: str, key: str, user: str,
                 pass_env: str = "NETHSM_PASS"):
        passphrase = os.environ.get(pass_env, "")
        if not passphrase:
            raise RuntimeError(f"NetHSM passphrase env var {pass_env!r} is empty/unset")
        host = (urllib.parse.urlsplit(url).hostname or "").lower()
        if url.startswith("http://") and host not in ("127.0.0.1", "localhost", "::1"):
            raise RuntimeError("refusing plain http:// to a non-loopback NetHSM: "
                               "credentials would travel in cleartext (use https)")
        self._url, self._key = url.rstrip("/"), key
        self._auth = base64.b64encode(f"{user}:{passphrase}".encode()).decode()

    def _req(self, method: str, path: str, body: Optional[Dict] = None) -> Dict:
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(f"{self._url}/api/v1/{path}", data=data,
                                     method=method,
                                     headers={"Authorization": f"Basic {self._auth}",
                                              "Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=30) as r:
            raw = r.read()
            return json.loads(raw.decode()) if raw else {}

    def keygen(self) -> str:
        """Genera la Ed25519 SULL'HSM (serve il ruolo Administrator)."""
        self._req("POST", "keys/generate",
                  {"mechanisms": ["EdDSA_Signature"], "type": "Curve25519",
                   "id": self._key})
        return self.public_key_hex()

    def public_key_hex(self) -> str:
        d = self._req("GET", f"keys/{self._key}")
        return _raw_from_spki(base64.b64decode(d["public"]["data"])).hex()

    def sign(self, message: bytes) -> bytes:
        d = self._req("POST", f"keys/{self._key}/sign",
                      {"mode": "EdDSA",
                       "message": base64.b64encode(message).decode()})
        sig = base64.b64decode(d["signature"])
        if len(sig) != 64:
            raise RuntimeError(f"expected 64-byte Ed25519 signature, got {len(sig)}")
        return sig

    def describe(self) -> Dict:
        return {"backend": "nethsm", "url": self._url, "key": self._key,
                "key_in_process_memory": False}


_REQUIRED_KEYS = {"pkcs11": ("module", "token", "key"),
                  "awskms": ("key_id",), "vault": ("url", "key"),
                  "nethsm": ("url", "key", "user")}


def backend_from_uri(uri: str, **extra):
    """Build a signing backend from a URI-style selector (see module docstring).
    Limite documentato: i valori non possono contenere ';' o '=' (nessun escaping)."""
    scheme, _, rest = uri.partition(":")
    if scheme == "file":
        return FileKeyBackend(rest)
    kv = _parse_kv(rest)
    missing = [k for k in _REQUIRED_KEYS.get(scheme, ()) if not kv.get(k)]
    if missing:
        raise ValueError(f"{scheme}: backend URI is missing required key(s): "
                         f"{', '.join(missing)} (got: {sorted(kv) or 'nothing'})")
    if scheme == "pkcs11":
        return Pkcs11Backend(module=kv["module"], token=kv["token"], key=kv["key"],
                             pin=kv.get("pin", "env:CRYPTOVALID_PIN"))
    if scheme == "awskms":
        return AwsKmsBackend(key_id=kv["key_id"], region=kv.get("region"),
                             profile=kv.get("profile"), **extra)
    if scheme == "vault":
        return VaultTransitBackend(url=kv["url"], key=kv["key"],
                                   mount=kv.get("mount", "transit"),
                                   token_env=kv.get("token_env", "VAULT_TOKEN"))
    if scheme == "nethsm":
        return NetHsmBackend(url=kv["url"], key=kv["key"], user=kv["user"],
                             pass_env=kv.get("pass_env", "NETHSM_PASS"))
    raise ValueError(f"unknown backend scheme {scheme!r} "
                     "(expected file: | pkcs11: | awskms: | vault: | nethsm:)")


def main(argv=None) -> int:  # pragma: no cover - thin CLI
    import argparse
    p = argparse.ArgumentParser(prog="cryptovalid-kms",
                                description="KMS/HSM signing backends for CryptoValid.")
    sub = p.add_subparsers(dest="cmd")
    for c in ("pubkey", "keygen-hsm", "selftest"):
        s = sub.add_parser(c); s.add_argument("--backend", required=True)
    a = p.parse_args(sys.argv[1:] if argv is None else argv)
    if not a.cmd:
        p.print_help(); return 2
    be = backend_from_uri(a.backend)
    if a.cmd == "keygen-hsm":
        if not isinstance(be, Pkcs11Backend):
            print("keygen-hsm only applies to pkcs11 backends", file=sys.stderr); return 2
        print(json.dumps({"public_key_hex": be.keygen(), **be.describe()}, indent=1)); return 0
    if a.cmd == "pubkey":
        print(json.dumps({"public_key_hex": be.public_key_hex(), **be.describe()}, indent=1)); return 0
    if a.cmd == "selftest":
        msg = b"cryptovalid-kms-selftest"
        sig = be.sign(msg)
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(be.public_key_hex())).verify(sig, msg)
        print(json.dumps({"selftest": "ok", **be.describe()}, indent=1)); return 0
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
