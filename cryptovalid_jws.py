#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Roberto Locatelli
"""
CryptoValid Open Core — JWS (RFC 7515) container for a ledger record, EdDSA (RFC 8037), optional `x5c`.

Why (2026-09-13): Implementing Regulation (EU) 2025/2531 names JAdES (ETSI TS 119 182-1) among the signature
formats for qualified electronic ledgers and requires the `x5c` header (RFC 7515 §4.1.6) to be present. This
module produces and verifies the JWS COMPACT SERIALISATION of a record's canonical form with `alg: EdDSA`,
`kid` = the Ed25519 public key (hex) and, when the caller supplies a certificate chain, `x5c` (base64 DER).

Honest scope: this is the JWS/JOSE container with the JAdES-relevant header, NOT a full JAdES signature
(no JAdES `sigT`/`x5t#o`/`srCms` profile, no qualified certificate issued here). The qualified certificate
and the CA validation are the user's and the QTSP's; the toolkit only puts them in the right place.
"""
from __future__ import annotations
import base64
import json
import os
import sys
from typing import Dict, List, Optional

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import cryptovalid_merkle as M  # noqa: E402


def _b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _b64u_dec(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _ed():
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
    return Ed25519PrivateKey, Ed25519PublicKey, serialization


def sign_entry(entry: Dict, keyfile: str, x5c: Optional[List[str]] = None) -> str:
    """JWS compact of the record's CANONICAL form (same bytes the ledger hashes). x5c: list of base64 DER
    certificates (leaf first), passed through untouched — a qualified certificate makes it JAdES-relevant."""
    Ed25519PrivateKey, _, ser = _ed()
    with open(keyfile, encoding="utf-8") as f:
        sk = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(f.read().strip()))
    pk = sk.public_key().public_bytes(ser.Encoding.Raw, ser.PublicFormat.Raw).hex()
    header = {"alg": "EdDSA", "typ": "JOSE", "kid": pk, "cty": "application/cryptovalid-record+json"}
    if x5c:
        if not isinstance(x5c, list) or not all(isinstance(c, str) for c in x5c):
            raise ValueError("x5c: lista di certificati DER in base64")
        for c in x5c:
            base64.b64decode(c, validate=True)     # must be standard base64 (RFC 7515 §4.1.6), not base64url
        header["x5c"] = x5c
    h = _b64u(json.dumps(header, sort_keys=True, separators=(",", ":")).encode())
    p = _b64u(M.canonical(entry))
    sig = sk.sign(f"{h}.{p}".encode("ascii"))
    return f"{h}.{p}.{_b64u(sig)}"


def verify(jws: str, trusted_pubkey_hex: Optional[str] = None) -> Dict:
    """Verifies the EdDSA signature; the key must be the TRUSTED one given by the relying party (`kid` in the
    header is informative). Returns the decoded record and the header (x5c passed back for CA validation)."""
    _, Ed25519PublicKey, _ = _ed()
    try:
        h, p, s = jws.split(".")
        header = json.loads(_b64u_dec(h))
        if header.get("alg") != "EdDSA":
            return {"ok": False, "why": f"alg non supportato: {header.get('alg')!r}"}
        kid = header.get("kid")
        pk = trusted_pubkey_hex or kid
        if trusted_pubkey_hex and kid != trusted_pubkey_hex:
            return {"ok": False, "why": "kid diverso dalla chiave fidata"}
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(pk)).verify(_b64u_dec(s), f"{h}.{p}".encode("ascii"))
        payload = json.loads(_b64u_dec(p))
        return {"ok": bool(trusted_pubkey_hex), "signature_valid": True, "header": header, "record": payload,
                "x5c_present": "x5c" in header,
                "why": ("firma valida contro la chiave fidata" if trusted_pubkey_hex else
                        "firma valida ma chiave presa dall'header: NON fidata (passare trusted_pubkey_hex)")}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "signature_valid": False, "why": f"{type(e).__name__}"}


def main(argv: Optional[List[str]] = None) -> int:
    import argparse
    p = argparse.ArgumentParser(prog="cryptovalid_jws", description="JWS (EdDSA, optional x5c) for a ledger record")
    sub = p.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("sign"); a.add_argument("ledger"); a.add_argument("index", type=int); a.add_argument("keyfile"); a.add_argument("--x5c", nargs="*")
    v = sub.add_parser("verify"); v.add_argument("jws_file"); v.add_argument("trusted_pubkey_hex")
    args = p.parse_args(argv)
    if args.cmd == "sign":
        entries = [json.loads(l) for l in open(args.ledger, encoding="utf-8") if l.strip()]
        print(sign_entry(entries[args.index], args.keyfile, args.x5c)); return 0
    with open(args.jws_file, encoding="utf-8") as f:
        r = verify(f.read().strip(), args.trusted_pubkey_hex)
    print(json.dumps(r, indent=1, ensure_ascii=False)); return 0 if r["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
