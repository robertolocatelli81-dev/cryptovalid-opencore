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
import base64, binascii, re
import hashlib
import json
import os
import sys
from typing import Dict, List, Optional


# attestation fields excluded from the content hash: classical (signature/signer) and, since 0.12.0, the
# post-quantum companion (signature_pq/signer_pq, ML-DSA-65 FIPS 204 over the same self_hash bytes)
ATTEST = ("self_hash", "signature", "signer", "signature_pq", "signer_pq")
# ML-DSA-65 (FIPS 204) profile of the hybrid layer — pure ML-DSA (NOT HashML-DSA) with a DOMAIN-SEPARATION context
# (council 15/09, five minds: the context costs nothing while the field is new and separates entries from tips);
# message = the UTF-8 bytes of the 64-char lowercase-hex `self_hash` string (the same bytes Ed25519 signs);
# signature 3309 bytes (randomized: two signatures of one message differ), public key 1952 bytes (pkEncode), both
# base64 standard alphabet with padding, decoded STRICTLY (no whitespace, no stray characters, canonical length).
PQ_CTX_ENTRY = b"cryptovalid/entry/1"
PQ_SIG_LEN, PQ_PK_LEN = 3309, 1952
_HEX64 = re.compile(r"[0-9a-f]{64}")


def _b64_strict(s, n: int):
    """Strict standard base64 of exactly n bytes, or None (Python's lenient decoder took spaces and '!')."""
    if not isinstance(s, str) or len(s) != ((n + 2) // 3) * 4:
        return None
    try:
        raw = base64.b64decode(s, validate=True)
    except (ValueError, binascii.Error):
        return None
    return raw if len(raw) == n and base64.b64encode(raw).decode() == s else None


def _content_self_hash_ok(entry: Dict) -> bool:
    """Ricomputa self_hash dal CONTENUTO (esclude self_hash/signature/signer) e lo confronta.
    Così la verifica di firma cattura anche la manomissione del contenuto: contenuto→self_hash→firma."""
    sh = entry.get("self_hash")
    if not sh:
        return False
    body = {k: v for k, v in entry.items() if k not in ATTEST}
    payload = json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
    return sh in (hashlib.sha256(payload).hexdigest(), hashlib.sha3_256(payload).hexdigest())


def _mldsa():
    """ML-DSA-65 (FIPS 204) from `cryptography` >= 50; None when not available (verdicts then say 'not verified')."""
    try:
        from cryptography.hazmat.primitives.asymmetric import mldsa
        return mldsa
    except ImportError:
        return None


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


def keygen_pq(path: str) -> Dict:
    """ML-DSA-65 keypair (FIPS 204): private key as PKCS#8 DER base64 in `path` (chmod 600), public raw base64
    returned — the post-quantum half of a HYBRID signature. NIST IR 8547 (draft) proposes disallowing Ed25519 after
    2035: a ledger kept for the 10-year retention windows crosses that line."""
    m = _mldsa()
    if m is None:
        raise RuntimeError("ML-DSA-65 needs cryptography >= 50.0.1")
    from cryptography.hazmat.primitives import serialization as ser
    sk = m.MLDSA65PrivateKey.generate()
    der = sk.private_bytes(ser.Encoding.DER, ser.PrivateFormat.PKCS8, ser.NoEncryption())
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(base64.b64encode(der).decode())
    return {"keyfile": path, "alg": "ml-dsa-65", "public_key_b64": base64.b64encode(sk.public_key().public_bytes_raw()).decode()}


def load_pq_key(path: str):
    """(private_key, public_key_b64) from a keygen_pq file."""
    m = _mldsa()
    if m is None:
        raise RuntimeError("ML-DSA-65 needs cryptography >= 50.0.1")
    from cryptography.hazmat.primitives import serialization as ser
    with open(path, encoding="utf-8") as f:
        sk = ser.load_der_private_key(base64.b64decode(f.read().strip()), password=None)
    if not isinstance(sk, m.MLDSA65PrivateKey):
        raise ValueError("not an ML-DSA-65 private key")
    return sk, base64.b64encode(sk.public_key().public_bytes_raw()).decode()


class _InlineFileBackend:
    """Fallback legacy quando cryptovalid_kms non è distribuito accanto a signer.py."""

    def __init__(self, keyfile: str):
        Ed25519PrivateKey, _, _ = _ed()
        with open(keyfile, encoding="utf-8") as f:
            self._sk = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(f.read().strip()))

    def public_key_hex(self) -> str:
        from cryptography.hazmat.primitives import serialization as ser
        return self._sk.public_key().public_bytes(ser.Encoding.Raw, ser.PublicFormat.Raw).hex()

    def sign(self, message: bytes) -> bytes:
        return self._sk.sign(message)


def _pubkey_hex(seed_hex: str) -> str:
    Ed25519PrivateKey, _, ser = _ed()
    sk = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(seed_hex))
    return sk.public_key().public_bytes(ser.Encoding.Raw, ser.PublicFormat.Raw).hex()


def sign_ledger(in_path: str, out_path: str, keyfile: Optional[str] = None,
                backend=None, pq_keyfile: Optional[str] = None) -> Dict:
    """Firma ogni entry di un ledger hash-chained: aggiunge `signature` (Ed25519 sul self_hash) +
    `signer` (pubblica hex). Il file resta verificabile come hash-chain E ora come firmato.

    `backend` (cryptovalid_kms.SignerBackend) delega la firma a un HSM/KMS dove la chiave
    privata NON entra in questo processo; `keyfile` resta il percorso legacy (seed su file).
    Ogni firma è AUTO-VERIFICATA post-firma contro la pubblica dichiarata (controllo
    positivo nel percorso di produzione: una rotazione chiave a metà ledger fallisce
    subito, non alla verifica del terzo)."""
    if backend is None:
        if not keyfile:
            raise ValueError("serve un keyfile oppure un backend KMS/HSM (cryptovalid_kms)")
        try:
            from cryptovalid_kms import FileKeyBackend
            backend = FileKeyBackend(keyfile)
        except ImportError:      # signer.py vendored da solo: percorso legacy inline
            backend = _InlineFileBackend(keyfile)
    pk_hex = backend.public_key_hex()
    _, Ed25519PublicKey, _ = _ed()
    pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(pk_hex))
    pq_sk, pq_pk_b64 = load_pq_key(pq_keyfile) if pq_keyfile else (None, None)
    out: List[Dict] = []
    with open(in_path, encoding="utf-8") as f:
        for ln in f:
            if not ln.strip():
                continue
            e = json.loads(ln)
            sh = e.get("self_hash")
            if not sh:
                raise ValueError("entry senza self_hash: firma un ledger già hash-chained")
            sig = backend.sign(sh.encode())
            pub.verify(sig, sh.encode())   # fail-fast se il backend firma con altra chiave
            e["signature"] = base64.b64encode(sig).decode()
            e["signer"] = pk_hex
            if pq_sk is not None:   # HYBRID: the same bytes signed by ML-DSA-65 too (own context); both must verify
                pq_sig = pq_sk.sign(sh.encode(), context=PQ_CTX_ENTRY)
                pq_sk.public_key().verify(pq_sig, sh.encode(), context=PQ_CTX_ENTRY)
                e["signature_pq"] = base64.b64encode(pq_sig).decode()
                e["signer_pq"] = pq_pk_b64
            else:                   # re-signing WITHOUT a PQ key strips stale PQ fields: never mix keys silently
                e.pop("signature_pq", None); e.pop("signer_pq", None)
            out.append(e)
    with open(out_path, "w", encoding="utf-8") as f:
        for e in out:
            f.write(json.dumps(e) + "\n")
    return {"signed": len(out), "signer": pk_hex, "out": out_path, "signer_pq": pq_pk_b64,
            "scheme": "hybrid ed25519+ml-dsa-65" if pq_sk is not None else "ed25519"}


def verify_ledger_signatures(entries: List[Dict], expected_pubkey_hex: Optional[str] = None,
                             expected_pq_pubkey_b64: Optional[str] = None, require_pq: bool = False) -> Dict:
    """Verifica INDIPENDENTE delle firme: per ogni entry, la firma valida su self_hash con la pubblica
    EMBEDDED (`signer`), e — se dato — che coincida con `expected_pubkey_hex`. Fail-closed.

    Post-quantum layer (council 15/09, five minds — no self-declared protection, no fail-open on stripping):
    `pq_protected` is **True** only when EVERY entry carries a valid ML-DSA-65 signature by the EXPECTED key
    (`expected_pq_pubkey_b64` given and matched) AND its Ed25519 signature is valid too; **None** when the
    layer is present but not PINNED (no expected key: verified against the embedded key only, which anyone can
    put there) or not verifiable on this host; **False** when absent, invalid, foreign or partial. Giving the
    expected key (or `require_pq`) REQUIRES the layer: a stripped or partial ledger is then `pq_missing` and
    `ok` is False at library level, not only in the CLI. `pq_status` names the state."""
    _, Ed25519PublicKey, _ = _ed()
    m = _mldsa()
    # council 16/09 round 2: the LIBRARY contract must be as strict as the CLI and the tip — a required layer that is
    # not pinned or not verifiable is never `ok`; a PQ key is meaningless without the Ed25519 key it sits on top of
    if require_pq and not expected_pq_pubkey_b64:
        raise ValueError("require_pq needs expected_pq_pubkey_b64: a post-quantum layer verified against the key inside the ledger is self-declared")
    if expected_pq_pubkey_b64 and not expected_pubkey_hex:
        raise ValueError("expected_pq_pubkey_b64 needs expected_pubkey_hex: hybrid means BOTH keys are pinned (with only the PQ key, a re-signed Ed25519 layer by a foreign key would still verify)")
    if expected_pq_pubkey_b64 and _b64_strict(expected_pq_pubkey_b64, PQ_PK_LEN) is None:
        raise ValueError("bad_expected_pq_key: expected_pq_pubkey_b64 must be strict base64 of a 1952-byte ML-DSA-65 public key")
    require = bool(require_pq or expected_pq_pubkey_b64)
    verified, failures, signers = 0, [], set()
    pq_ok, pq_failures, pq_signers, pq_present = 0, [], set(), 0
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
        raw_sig = _b64_strict(sig, 64) if isinstance(sig, str) else None
        if raw_sig is None or not (isinstance(signer, str) and _HEX64.fullmatch(signer)):
            failures.append({"idx": i, "reason": "malformed_signature_field"})   # strict, like the PQ fields and the tip
            continue
        try:
            Ed25519PublicKey.from_public_bytes(bytes.fromhex(signer)).verify(raw_sig, sh.encode())
            verified += 1
            signers.add(signer)
        except Exception:  # noqa: BLE001
            failures.append({"idx": i, "reason": "bad_signature"})
        pq_sig, pq_signer = e.get("signature_pq"), e.get("signer_pq")
        if not (pq_sig or pq_signer):
            if require:
                pq_failures.append({"idx": i, "reason": "pq_missing"})      # stripped: the required layer is gone
            continue
        pq_present += 1
        if not (isinstance(pq_sig, str) and isinstance(pq_signer, str) and pq_sig and pq_signer):
            pq_failures.append({"idx": i, "reason": "missing signature_pq/signer_pq"}); continue
        if expected_pq_pubkey_b64 and pq_signer != expected_pq_pubkey_b64:
            pq_failures.append({"idx": i, "reason": "pq_signer_mismatch"}); continue
        raw_sig, raw_pk = _b64_strict(pq_sig, PQ_SIG_LEN), _b64_strict(pq_signer, PQ_PK_LEN)
        if raw_sig is None or raw_pk is None:
            pq_failures.append({"idx": i, "reason": "malformed_pq_field"}); continue   # same refusal as Go's decoder
        if m is None:
            if require:       # required and NOT verifiable here: a failure, like the tip's pq_unverifiable
                pq_failures.append({"idx": i, "reason": "pq_unverifiable"})
            continue          # present, not verifiable, not required: reported as None below
        try:
            m.MLDSA65PublicKey.from_public_bytes(raw_pk).verify(raw_sig, sh.encode(), context=PQ_CTX_ENTRY)
            pq_ok += 1
            pq_signers.add(pq_signer)
        except Exception:  # noqa: BLE001
            pq_failures.append({"idx": i, "reason": "bad_pq_signature"})
    if pq_failures:
        reasons = {f["reason"] for f in pq_failures}
        pq_protected = None if reasons == {"pq_unverifiable"} else False
        pq_status = "unverifiable" if reasons == {"pq_unverifiable"} else ("missing" if reasons == {"pq_missing"} else "invalid")
        pq_note = {"unverifiable": "post-quantum layer required but ML-DSA-65 cannot be verified here (cryptography >= 50 not available): not a pass",
                   "missing": "post-quantum layer required but absent on some entries (stripped or never signed)",
                   "invalid": "post-quantum layer invalid, foreign or malformed on some entries"}[pq_status]
    elif pq_present == 0:
        pq_protected, pq_status = False, "absent"
        pq_note = "no post-quantum signatures (Ed25519 only: not quantum-resistant, NIST IR 8547 draft)"
    elif m is None:
        pq_protected, pq_status = None, "unverifiable"
        pq_note = "ML-DSA-65 signatures present but NOT verified (cryptography >= 50 not available)"
    elif pq_ok != len(entries) or not entries:
        pq_protected, pq_status = False, "partial"
        pq_note = "post-quantum signatures on some entries only: not a protected ledger"
    elif failures:
        pq_protected, pq_status = False, "classical_broken"
        pq_note = "ML-DSA-65 signatures valid but an Ed25519 signature is not: hybrid means BOTH hold"
    elif not expected_pq_pubkey_b64:
        pq_protected, pq_status = None, "unpinned"
        pq_note = "ML-DSA-65 signatures verified against the EMBEDDED key only (anyone can add their own): pass --pq-pubkey to pin"
    else:
        pq_protected, pq_status = True, "protected"
        pq_note = "hybrid: every entry carries a valid ML-DSA-65 (FIPS 204) signature by the expected key, besides Ed25519"
    # a PRESENT post-quantum signature that is invalid / from another key, or a REQUIRED one that is missing, is a
    # broken attestation: FAIL even though Ed25519 still verifies (hybrid = both must hold)
    return {"ok": bool(not failures and verified == len(entries) and entries and not pq_failures),
            "verified": verified, "total": len(entries), "failures": failures,
            "signers": sorted(signers),
            "pq_protected": pq_protected, "pq_status": pq_status, "pq_verified": pq_ok, "pq_failures": pq_failures,
            "pq_signers": sorted(pq_signers), "pq_note": pq_note}


def verify_file(path: str, pubkey_hex: Optional[str] = None, pq_pubkey_b64: Optional[str] = None,
                require_pq: bool = False) -> Dict:
    with open(path, encoding="utf-8") as f:
        entries = [json.loads(ln) for ln in f if ln.strip()]
    return verify_ledger_signatures(entries, pubkey_hex, pq_pubkey_b64, require_pq=require_pq)


def main(argv: Optional[List[str]] = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    p = argparse.ArgumentParser(prog="cryptovalid-signer")
    sub = p.add_subparsers(dest="cmd")
    kg = sub.add_parser("keygen"); kg.add_argument("keyfile")
    kg.add_argument("--pq", action="store_true", help="also generate the ML-DSA-65 (FIPS 204) key in <keyfile>.pq for HYBRID signatures")
    sg = sub.add_parser("sign"); sg.add_argument("ledger"); sg.add_argument("out")
    sg.add_argument("keyfile", nargs="?"); sg.add_argument(
        "--backend", help="KMS/HSM backend URI (vedi cryptovalid_kms), es. pkcs11:module=...;token=...;key=...")
    sg.add_argument("--pq-key", help="ML-DSA-65 key file (keygen --pq): sign every entry with Ed25519 AND ML-DSA-65")
    vf = sub.add_parser("verify"); vf.add_argument("ledger"); vf.add_argument("--pubkey")
    vf.add_argument("--pq-pubkey", help="expected ML-DSA-65 public key (base64) of the post-quantum signatures")
    vf.add_argument("--require-pq", action="store_true", help="exit 1 unless every entry carries a VALID ML-DSA-65 signature by --pq-pubkey (which it needs)")
    a = p.parse_args(argv)
    if a.cmd == "keygen":
        out = keygen(a.keyfile)
        if a.pq:
            out["pq"] = keygen_pq(a.keyfile + ".pq")
        print(json.dumps(out, indent=1)); return 0
    if a.cmd == "sign":
        be = None
        if getattr(a, "backend", None):
            if a.keyfile:
                print("warning: sia keyfile che --backend indicati — uso --backend, "
                      "il keyfile è ignorato", file=sys.stderr)
            from cryptovalid_kms import backend_from_uri
            be = backend_from_uri(a.backend)
        elif not a.keyfile:
            p.error("sign richiede un keyfile oppure --backend <uri>")
        print(json.dumps(sign_ledger(a.ledger, a.out, a.keyfile, backend=be, pq_keyfile=a.pq_key), indent=1)); return 0
    if a.cmd == "verify":
        if a.require_pq and not a.pq_pubkey:
            p.error("verify: --require-pq needs --pq-pubkey (a post-quantum layer verified against the key INSIDE the ledger is self-declared)")
        if a.pq_pubkey and not a.pubkey:
            p.error("verify: --pq-pubkey needs --pubkey (hybrid = both keys pinned; the same rule as the tip's --trusted-pq-pubkey)")
        r = verify_file(a.ledger, a.pubkey, a.pq_pubkey, require_pq=a.require_pq)
        print(json.dumps(r, indent=1))
        return 0 if (r["ok"] and (r["pq_protected"] is True or not a.pq_pubkey)) else 1
    p.print_help(); return 2


if __name__ == "__main__":
    raise SystemExit(main())
