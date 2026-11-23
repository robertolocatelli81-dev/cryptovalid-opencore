# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Roberto Locatelli
"""Verification of composite ML-DSA signatures of RFC 10073 (Proposed Standard, November 2026), SPEC §29.

Status: EXPERIMENTAL. Outside the maintained core of cryptovalid-opencore (README, "Core and experimental
modules"): kept, installed and tested, no new scope is added here.

Three algorithms, the ML-DSA-65 ones whose traditional half the COSE verifiers of this repository already check:
id-MLDSA65-Ed25519-SHA512, id-MLDSA65-ECDSA-P256-SHA512, id-MLDSA65-ECDSA-P384-SHA512 (RFC 10073 §6). Verify is §3.3:
M' = Prefix || Label || len(ctx) || ctx || SHA512(M); ML-DSA-65 over M' with the Label as its context, the traditional
signature over M'; valid if and only if both are. Keys and signatures are closed (§4, §4.1, §4.3): exact lengths, an
uncompressed point on the algorithm's curve, an ECDSA signature in DER and nothing else.

This module verifies and signs nothing. The hybrid signature of this format (SPEC §15: Ed25519 and ML-DSA-65 with the
empty context, two fields, over the message itself) is not a composite one, and the keys of one are not used for the
other: `verify` takes the composite public key as one value and never reads a ledger entry's `signer`/`signer_pq`.

Usage:
    import cryptovalid_composite as CC
    CC.verify("id-MLDSA65-Ed25519-SHA512", public_key, message, signature, ctx=b"")
    → {"ok": bool, "stage": None | str, "why": str, "alg": name, "oid": dotted OID}

Backend: ML-DSA-65, Ed25519 and ECDSA come from `cryptography` (the `[sign]` extra, >= 48 for ML-DSA). Without it the
signature was not evaluated: stage BACKEND_MISSING, `ok: false`.
"""
from __future__ import annotations

import hashlib
from typing import Dict, Optional

PREFIX = b"CompositeAlgorithmSignatures2025"       # RFC 10073 §2.2
MLDSA65_PK, MLDSA65_SIG = 1952, 3309                # RFC 10073 §4, Table 1
# name → (OID, Label, traditional algorithm, its curve and hash): RFC 10073 §6
ALGORITHMS = {
    "id-MLDSA65-Ed25519-SHA512": ("1.3.6.1.5.5.7.6.48", b"COMPSIG-MLDSA65-Ed25519-SHA512", "ed25519"),
    "id-MLDSA65-ECDSA-P256-SHA512": ("1.3.6.1.5.5.7.6.45", b"COMPSIG-MLDSA65-ECDSA-P256-SHA512", "p256"),
    "id-MLDSA65-ECDSA-P384-SHA512": ("1.3.6.1.5.5.7.6.46", b"COMPSIG-MLDSA65-ECDSA-P384-SHA512", "p384"),
}
_BY_OID = {v[0]: k for k, v in ALGORITHMS.items()}
_TRAD_PK = {"ed25519": 32, "p256": 65, "p384": 97}   # §4: raw Ed25519 key; uncompressed X9.62 point
BACKEND_MISSING_WHY = "cryptography is not installed here (pip install 'cryptovalid-opencore[sign]'): not evaluated"


def m_prime(label: bytes, message: bytes, ctx: bytes = b"") -> bytes:
    """RFC 10073 §2.1, §3.3 step 3 (PH = SHA512 for the three algorithms here)."""
    return PREFIX + label + bytes([len(ctx)]) + ctx + hashlib.sha512(message).digest()


def _refuse(stage: str, why: str, name: Optional[str]) -> Dict:
    return {"ok": False, "stage": stage, "why": why, "alg": name, "oid": ALGORITHMS[name][0] if name else None}


def verify(alg: str, public_key: bytes, message: bytes, signature: bytes, ctx: bytes = b"") -> Dict:
    """Composite-ML-DSA<alg>.Verify(pk, M, s, ctx) of RFC 10073 §3.3; `alg` is a name of ALGORITHMS or its OID."""
    name = (alg if alg in ALGORITHMS else _BY_OID.get(alg)) if isinstance(alg, str) else None
    if name is None:
        return _refuse("UNSUPPORTED_ALG", f"{alg!r} is not one of {sorted(ALGORITHMS)} (nor their OIDs)", None)
    if not all(isinstance(x, (bytes, bytearray)) for x in (public_key, message, signature, ctx)):
        return _refuse("MALFORMED_INPUT", "public key, message, signature and ctx are byte strings", name)
    if len(ctx) > 255:
        return _refuse("CTX_TOO_LONG", f"ctx of {len(ctx)} bytes: at most 255 (§3.3 step 1)", name)
    _, label, trad = ALGORITHMS[name]
    pk, sig = bytes(public_key), bytes(signature)
    if len(pk) != MLDSA65_PK + _TRAD_PK[trad]:     # an ECDSA point that is not 0x04 || x || y: from_encoded_point refuses
        return _refuse("MALFORMED_KEY", f"the key must be 1952 bytes of ML-DSA-65 then the {trad} key of "
                                        f"{_TRAD_PK[trad]} bytes (§4, §4.1); it is {len(pk)} bytes", name)
    if len(sig) <= MLDSA65_SIG:
        return _refuse("MALFORMED_SIGNATURE", f"the signature must be 3309 bytes of ML-DSA-65 then the {trad} "
                                              f"signature (§4.3); it is {len(sig)} bytes", name)
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec, mldsa
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
    except ImportError as e:
        return _refuse("BACKEND_MISSING", BACKEND_MISSING_WHY + f" ({e})"[:120], name)
    tsig = sig[MLDSA65_SIG:]
    try:
        mpk = mldsa.MLDSA65PublicKey.from_public_bytes(pk[:MLDSA65_PK])
        if trad == "ed25519":
            if len(tsig) != 64:
                raise ValueError(f"an Ed25519 signature is 64 bytes, not {len(tsig)}")
            tpk = Ed25519PublicKey.from_public_bytes(pk[MLDSA65_PK:])
        else:
            curve = ec.SECP256R1() if trad == "p256" else ec.SECP384R1()
            tpk = ec.EllipticCurvePublicKey.from_encoded_point(curve, pk[MLDSA65_PK:])
            decode_dss_signature(tsig)          # DER only (§4): BER, a superfluous zero, trailing bytes raise ValueError
    except ValueError as e:
        return _refuse("MALFORMED_KEY_OR_SIGNATURE", f"{e}"[:200], name)
    mp = m_prime(label, bytes(message), bytes(ctx))
    try:
        mpk.verify(sig[:MLDSA65_SIG], mp, label)
    except InvalidSignature:
        return _refuse("MLDSA_SIGNATURE_INVALID", "the ML-DSA-65 component does not verify over M' (§3.3 step 4)", name)
    try:
        if trad == "ed25519":
            tpk.verify(tsig, mp)
        else:
            tpk.verify(tsig, mp, ec.ECDSA(hashes.SHA256() if trad == "p256" else hashes.SHA384()))
    except InvalidSignature:
        return _refuse("TRADITIONAL_SIGNATURE_INVALID", f"the {trad} component does not verify over M' (§3.3 step 4)", name)
    return {"ok": True, "stage": None, "why": "both component signatures valid over M' (RFC 10073 §3.3)",
            "alg": name, "oid": ALGORITHMS[name][0]}
