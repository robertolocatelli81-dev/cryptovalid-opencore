#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CryptoValid Open Core — Ed25519 signing layer for the evidence format.

SPDX-License-Identifier: AGPL-3.0-or-later
Copyright (C) 2026 Roberto Locatelli

Makes each hash-chained ledger entry cryptographically ATTRIBUTABLE and INDEPENDENTLY
VERIFIABLE: the signature commits to the entry's `self_hash`, so a third party checks
*who* sealed *what* — with nothing but this file and a public key. This is the enterprise
edge that closed, cloud GRC evidence tools (which say "trust our database") do not give
you: signed, self-hosted, offline-verifiable evidence.

Design (honest, minimal):
  - The CORE hash verifier stays STDLIB-ONLY. Signatures are an OPTIONAL layer that needs
    the `cryptography` package. Absence of signatures never weakens the hash chain.
  - The signature covers `self_hash` (which already commits to {idx, ts, data, prev_hash}).
    `signature` and `signer` are attestation fields excluded from the content hash — so a
    signed ledger still passes the stdlib hash verification unchanged.

Usage:
  python3 signer.py keygen  signer.key
  python3 signer.py sign    ledger.jsonl  ledger.signed.jsonl  signer.key
  python3 signer.py verify  ledger.signed.jsonl  [--pubkey <hex>]
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import sys
from typing import Dict, List, Optional


def _content_self_hash_ok(entry: Dict) -> bool:
    """Ricomputa self_hash dal CONTENUTO (esclude self_hash/signature/signer) e lo confronta.
    Così la verifica di firma cattura anche la manomissione del contenuto: contenuto→self_hash→firma."""
    sh = entry.get("self_hash")
    if not sh:
        return False
    body = {k: v for k, v in entry.items() if k not in ("self_hash", "signature", "signer")}
    payload = json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
    return sh in (hashlib.sha256(payload).hexdigest(), hashlib.sha3_256(payload).hexdigest())


def _ed():
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PrivateKey, Ed25519PublicKey)
        return Ed25519PrivateKey, Ed25519PublicKey, serialization
    except ImportError as e:  # pragma: no cover
        raise RuntimeError("the signature layer requires 'cryptography' (pip install cryptography); "
                           "the core hash verifier stays stdlib-only") from e


def keygen(path: str) -> Dict:
    """Genera una chiave Ed25519 e la salva (seed hex, chmod 600). Ritorna la pubblica (hex)."""
    Ed25519PrivateKey, _, ser = _ed()
    sk = Ed25519PrivateKey.generate()
    seed = sk.private_bytes(ser.Encoding.Raw, ser.PrivateFormat.Raw, ser.NoEncryption())
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(seed.hex())
    pk = sk.public_key().public_bytes(ser.Encoding.Raw, ser.PublicFormat.Raw)
    return {"keyfile": path, "public_key_hex": pk.hex()}


def _pubkey_hex(seed_hex: str) -> str:
    Ed25519PrivateKey, _, ser = _ed()
    sk = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(seed_hex))
    return sk.public_key().public_bytes(ser.Encoding.Raw, ser.PublicFormat.Raw).hex()


def sign_ledger(in_path: str, out_path: str, keyfile: str) -> Dict:
    """Firma ogni entry di un ledger hash-chained: aggiunge `signature` (Ed25519 sul self_hash) +
    `signer` (pubblica hex). Il file resta verificabile come hash-chain E ora come firmato."""
    Ed25519PrivateKey, _, _ = _ed()
    with open(keyfile, encoding="utf-8") as f:
        seed = f.read().strip()
    sk = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(seed))
    pk_hex = _pubkey_hex(seed)
    out: List[Dict] = []
    with open(in_path, encoding="utf-8") as f:
        for ln in f:
            if not ln.strip():
                continue
            e = json.loads(ln)
            sh = e.get("self_hash")
            if not sh:
                raise ValueError("entry senza self_hash: firma un ledger già hash-chained")
            e["signature"] = base64.b64encode(sk.sign(sh.encode())).decode()
            e["signer"] = pk_hex
            out.append(e)
    with open(out_path, "w", encoding="utf-8") as f:
        for e in out:
            f.write(json.dumps(e) + "\n")
    return {"signed": len(out), "signer": pk_hex, "out": out_path}


def verify_ledger_signatures(entries: List[Dict], expected_pubkey_hex: Optional[str] = None) -> Dict:
    """Verifica INDIPENDENTE delle firme: per ogni entry, la firma valida su self_hash con la pubblica
    EMBEDDED (`signer`), e — se dato — che coincida con `expected_pubkey_hex`. Fail-closed."""
    _, Ed25519PublicKey, _ = _ed()
    verified, failures, signers = 0, [], set()
    for i, e in enumerate(entries):
        sig, signer, sh = e.get("signature"), e.get("signer"), e.get("self_hash")
        if not (sig and signer and sh):
            failures.append({"idx": i, "reason": "missing signature/signer/self_hash"})
            continue
        if not _content_self_hash_ok(e):
            failures.append({"idx": i, "reason": "content_hash_mismatch"})   # contenuto manomesso
            continue
        if expected_pubkey_hex and signer != expected_pubkey_hex:
            failures.append({"idx": i, "reason": "signer_mismatch"})
            continue
        try:
            Ed25519PublicKey.from_public_bytes(bytes.fromhex(signer)).verify(
                base64.b64decode(sig), sh.encode())
            verified += 1
            signers.add(signer)
        except Exception:  # noqa: BLE001
            failures.append({"idx": i, "reason": "bad_signature"})
    return {"ok": bool(not failures and verified == len(entries) and entries),
            "verified": verified, "total": len(entries), "failures": failures,
            "signers": sorted(signers)}


def verify_file(path: str, pubkey_hex: Optional[str] = None) -> Dict:
    with open(path, encoding="utf-8") as f:
        entries = [json.loads(ln) for ln in f if ln.strip()]
    return verify_ledger_signatures(entries, pubkey_hex)


def main(argv: Optional[List[str]] = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    p = argparse.ArgumentParser(prog="cryptovalid-signer")
    sub = p.add_subparsers(dest="cmd")
    kg = sub.add_parser("keygen"); kg.add_argument("keyfile")
    sg = sub.add_parser("sign"); sg.add_argument("ledger"); sg.add_argument("out"); sg.add_argument("keyfile")
    vf = sub.add_parser("verify"); vf.add_argument("ledger"); vf.add_argument("--pubkey")
    a = p.parse_args(argv)
    if a.cmd == "keygen":
        print(json.dumps(keygen(a.keyfile), indent=1)); return 0
    if a.cmd == "sign":
        print(json.dumps(sign_ledger(a.ledger, a.out, a.keyfile), indent=1)); return 0
    if a.cmd == "verify":
        r = verify_file(a.ledger, a.pubkey)
        print(json.dumps(r, indent=1)); return 0 if r["ok"] else 1
    p.print_help(); return 2


if __name__ == "__main__":
    raise SystemExit(main())
