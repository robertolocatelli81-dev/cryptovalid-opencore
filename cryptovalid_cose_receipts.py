# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Roberto Locatelli
"""COSE Receipts (RFC 9942, VDS 1 = RFC9162_SHA256) and SCITT Signed Statements (RFC 9943) from ANY implementation —
offline, fail-closed, two declared profiles.

cryptovalid_scitt verifies what THIS repository's Transparency Service emits (EdDSA, its own ledger entry as the leaf).
This module verifies receipts and statements produced elsewhere, as exchanged between implementers (IETF AUDIT BoF
preparation, 2026-10-03):

  profile "rfc9942"  the COSE Receipt layer only: alg EdDSA (-8), ES256 (-7) or ES384 (-35) with a key of the matching
                     type; vds (label 395) read from the PROTECTED header and equal to 1; the RFC 9162 inclusion proof
                     (vdp label 396, key -1) rebuilds the root the log signed (detached payload = that root).
                     Also vds 2 = CCF_LEDGER_SHA256 (draft-ietf-scitt-receipts-ccf-profile-05 §2.2, §3.1, §3.2, §5):
                     leaf HASH(internal-transaction-hash || HASH(internal-evidence) || data-hash), the path walked
                     with its left bits, payload detached (MUST), every proof to the same root (MUST), and data-hash
                     equal to the caller's entry.
  profile "rfc9943"  the same, plus the header MUSTs of RFC 9943 §6 on BOTH the Signed Statement and the Receipt:
                     CWT Claims (15) with iss (1) and sub (2), iss of 1..8192 characters, kid (4) when neither x5t (34)
                     nor x5chain (33) is in the protected header.

The leaf ENTRY is the Transparency Service's choice (RFC 9943 leaves it to the TS): the caller passes the entry bytes,
the receipt never chooses them. Keys are the relying party's: a kid or a certificate inside a message is never trusted
by itself. Every hostile input is a refusal with a named stage, never an exception.
"""
from __future__ import annotations

import hashlib
from typing import Dict, List, Optional

import cryptovalid_merkle as M
import cryptovalid_receipt as R
from cryptovalid_scitt import (L_ALG, L_CWT, L_KID, L_VDP, L_VDS, CWT_ISS, CWT_SUB, MAX_ISS, VDP_INCLUSION,
                               VDS_RFC9162_SHA256, ScittError, _root_from_inclusion, _sig1, parse_cose_sign1)

ALG_EDDSA, ALG_ES256, ALG_ES384 = -8, -7, -35
VDS_CCF_LEDGER_SHA256 = 2        # draft-ietf-scitt-receipts-ccf-profile-05: TBD_1, "requested assignment 2" (not yet IANA)
L_X5CHAIN, L_X5T = 33, 34
PROFILES = ("rfc9942", "rfc9943")


def load_public_key(key):
    """A PEM public key (bytes or str), or 64 hex characters of a raw Ed25519 key."""
    from cryptography.hazmat.primitives import serialization as ser
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    if isinstance(key, str) and len(key) == 64 and all(c in "0123456789abcdefABCDEF" for c in key):
        return Ed25519PublicKey.from_public_bytes(bytes.fromhex(key))
    data = key.encode("ascii") if isinstance(key, str) else bytes(key)
    return ser.load_pem_public_key(data)


def _verify_sig(alg: int, pub, to_be_signed: bytes, sig: bytes) -> bool:
    """COSE signature check with the key TYPE bound to the algorithm (an ES256 header over an Ed25519 key is refused)."""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
    try:
        if alg == ALG_EDDSA:
            if not isinstance(pub, Ed25519PublicKey):
                return False
            pub.verify(sig, to_be_signed)
            return True
        digest, size = {ALG_ES256: (hashes.SHA256, 32), ALG_ES384: (hashes.SHA384, 48)}[alg]
        if not isinstance(pub, ec.EllipticCurvePublicKey) or len(sig) != 2 * size:
            return False                 # r || s of the alg's fixed length (RFC 9053 §2.1); a key on another curve cannot verify it
        r, s = int.from_bytes(sig[:size], "big"), int.from_bytes(sig[size:], "big")
        pub.verify(encode_dss_signature(r, s), to_be_signed, ec.ECDSA(digest()))
        return True
    except (InvalidSignature, KeyError, ValueError):
        return False


def _header_musts(ph: Dict, what: str) -> Optional[str]:
    """RFC 9943 §6 header MUSTs; None when satisfied, else the reason."""
    cwt = ph.get(L_CWT)
    if not isinstance(cwt, dict) or not isinstance(cwt.get(CWT_ISS), str) or not isinstance(cwt.get(CWT_SUB), str):
        return f"{what}: protected header lacks CWT Claims (15) with iss (1) and sub (2) — RFC 9943 §6"
    if not 1 <= len(cwt[CWT_ISS]) <= MAX_ISS:
        return f"{what}: iss length outside 1..{MAX_ISS} — RFC 9943 §6"
    if L_KID not in ph and L_X5T not in ph and L_X5CHAIN not in ph:
        return f"{what}: kid (4) absent while neither x5t (34) nor x5chain (33) is present — RFC 9943 §6"
    return None


def _refuse(stage: str, why: str, **kw) -> Dict:
    return {"ok": False, "stage": stage, "why": why, **kw}


def verify_statement(cose: bytes, issuer_key, payload: Optional[bytes] = None, profile: str = "rfc9942") -> Dict:
    """The Signed Statement's signature with the relying party's Issuer key (+ the RFC 9943 header MUSTs in that profile)."""
    if profile not in PROFILES:
        raise ValueError(f"profile must be one of {PROFILES}")
    try:
        pbytes, ph, _, pl, sig = parse_cose_sign1(cose)
        alg = ph.get(L_ALG)
        if alg not in (ALG_EDDSA, ALG_ES256, ALG_ES384):
            return _refuse("UNSUPPORTED_ALG", f"statement alg {alg!r} not supported")
        if profile == "rfc9943":
            why = _header_musts(ph, "statement")
            if why:
                return _refuse("HEADER_MUST", why)
        if pl is None:
            if payload is None:
                return _refuse("DETACHED_PAYLOAD_MISSING", "detached payload: pass the Statement bytes")
            pl = bytes(payload)
        elif payload is not None and bytes(payload) != pl:
            return _refuse("PAYLOAD_MISMATCH", "the attached payload differs from the given Statement")
        if not _verify_sig(alg, load_public_key(issuer_key), _sig1(pbytes, pl), sig):
            return _refuse("BAD_STATEMENT_SIGNATURE", "statement signature does not verify with the Issuer key")
        return {"ok": True, "stage": None, "why": "statement signature valid", "alg": alg,
                "payload_sha256": hashlib.sha256(pl).hexdigest()}
    except Exception as e:  # noqa: BLE001 — hostile bytes are a refusal, never a crash
        return _refuse("MALFORMED_STATEMENT", f"{type(e).__name__}: {e}"[:200])


def verify_receipt(receipt: bytes, entry: bytes, log_key, profile: str = "rfc9942") -> Dict:
    """An RFC 9942 COSE Receipt with VDS RFC9162_SHA256 for the leaf entry `entry` (the caller's bytes)."""
    if profile not in PROFILES:
        raise ValueError(f"profile must be one of {PROFILES}")
    try:
        rp, ph, uh, rpl, sig = parse_cose_sign1(receipt)
        vds = ph.get(L_VDS)                              # protected header only: an unprotected vds is never read
        if type(vds) is not int or vds not in (VDS_RFC9162_SHA256, VDS_CCF_LEDGER_SHA256):   # CBOR true is not the uint 1
            return _refuse("UNSUPPORTED_VDS", f"protected vds {vds!r} is neither 1 (RFC9162_SHA256) nor 2 (CCF_LEDGER_SHA256)")
        alg = ph.get(L_ALG)
        if alg not in (ALG_EDDSA, ALG_ES256, ALG_ES384):
            return _refuse("UNSUPPORTED_ALG", f"receipt alg {alg!r} not supported")
        if profile == "rfc9943":
            why = _header_musts(ph, "receipt")
            if why:
                return _refuse("HEADER_MUST", why)
        vdp = uh.get(L_VDP)
        proofs = vdp.get(VDP_INCLUSION) if isinstance(vdp, dict) else None
        if not isinstance(proofs, list) or not proofs or not all(isinstance(p, bytes) for p in proofs):
            return _refuse("MALFORMED_PROOF", "no inclusion proof (vdp 396, key -1: [+ bstr .cbor proof])")
        pub = load_public_key(log_key)
        if vds == VDS_CCF_LEDGER_SHA256:
            return _verify_ccf(rp, rpl, sig, alg, pub, proofs, bytes(entry))
        leaf = M.leaf_hash(bytes(entry))
        tried: List[str] = []
        for i, pb in enumerate(proofs):                  # RFC 9942: one or more proofs; any one that verifies suffices
            dec = R.cbor_decode(pb)
            # RFC 9942: tree-size and leaf-index are uint — a CBOR true/false or a negative is not (as audit V1 #8/#9
            # fixed in cryptovalid_scitt, 30/09/2026; ported here 04/10/2026)
            if not (isinstance(dec, list) and len(dec) == 3 and type(dec[0]) is int and type(dec[1]) is int
                    and dec[0] >= 0 and dec[1] >= 0
                    and isinstance(dec[2], list) and all(isinstance(h, bytes) and len(h) == 32 for h in dec[2])):
                tried.append(f"proof {i}: malformed"); continue
            size, index, path = dec
            root = _root_from_inclusion(index, size, leaf, path)
            if root is None:                 # a path that cannot be walked (index ≥ size, path too long) proves nothing
                tried.append(f"proof {i}: the path does not rebuild a root"); continue
            if rpl is not None and rpl != root:
                tried.append(f"proof {i}: the attached payload is not the rebuilt root"); continue
            if _verify_sig(alg, pub, _sig1(rp, root), sig):
                return {"ok": True, "stage": None, "why": "log signature valid over the root rebuilt from the entry and the path",
                        "alg": alg, "tree_size": size, "leaf_index": index, "root": root.hex()}
            tried.append(f"proof {i}: the log signature does not verify over the rebuilt root")
        return _refuse("INCLUSION_ROOT_SIGNATURE_INVALID", "; ".join(tried))
    except Exception as e:  # noqa: BLE001
        return _refuse("MALFORMED_RECEIPT", f"{type(e).__name__}: {e}"[:200])


def _ccf_root(proof) -> bytes:
    """compute_root of draft-ietf-scitt-receipts-ccf-profile-05 Figure 7; ValueError on any shape outside its CDDL."""
    if not (isinstance(proof, dict) and set(proof) == {1, 2}):
        raise ValueError("ccf-inclusion-proof must be {1: leaf, 2: path}")
    leaf, path = proof[1], proof[2]
    if not (isinstance(leaf, list) and len(leaf) == 3 and isinstance(leaf[0], bytes) and len(leaf[0]) == 32
            and isinstance(leaf[1], str) and 1 <= len(leaf[1].encode("utf-8")) <= 1024
            and isinstance(leaf[2], bytes) and len(leaf[2]) == 32):
        raise ValueError("ccf-leaf must be [bstr .size 32, tstr .size (1..1024), bstr .size 32]")
    if not (isinstance(path, list) and path and all(isinstance(e, list) and len(e) == 2 and isinstance(e[0], bool)
                                                   and isinstance(e[1], bytes) and len(e[1]) == 32 for e in path)):
        raise ValueError("path must be [+ [bool, bstr .size 32]]")
    H = lambda b: hashlib.sha256(b).digest()  # noqa: E731
    h = H(leaf[0] + H(leaf[1].encode("utf-8")) + leaf[2])
    for left, x in path:
        h = H(x + h) if left else H(h + x)
    return h


def _verify_ccf(rp: bytes, rpl, sig: bytes, alg: int, pub, proofs: List[bytes], entry: bytes) -> Dict:
    if rpl is not None:
        return _refuse("PAYLOAD_NOT_DETACHED", "a CCF inclusion receipt's payload MUST be detached (§3.1)")
    roots, bound = set(), False
    for i, pb in enumerate(proofs):
        try:
            dec = R.cbor_decode(pb)
            roots.add(_ccf_root(dec))
        except ValueError as e:
            return _refuse("MALFORMED_PROOF", f"proof {i}: {e}")
        bound = bound or dec[1][2] == entry
    if len(roots) != 1:
        return _refuse("PROOFS_DISAGREE", "the inclusion proofs do not compute the same root (§3.1 MUST)")
    if not bound:
        return _refuse("LEAF_NOT_THIS_STATEMENT", "no proof's data-hash equals the entry for this statement")
    root = roots.pop()
    if not _verify_sig(alg, pub, _sig1(rp, root), sig):
        return _refuse("INCLUSION_ROOT_SIGNATURE_INVALID", "the log signature does not verify over the rebuilt root")
    return {"ok": True, "stage": None, "why": "CCF: log signature valid over the root rebuilt from the leaf and the path",
            "alg": alg, "root": root.hex(), "vds": VDS_CCF_LEDGER_SHA256}


def verify_statement_with_receipt(statement: bytes, receipt: bytes, issuer_key, log_key, entry: bytes,
                                  payload: Optional[bytes] = None, profile: str = "rfc9942") -> Dict:
    """Both checks; VALID only when the statement AND the receipt verify. `entry` is the TS's leaf entry for THIS
    statement, computed by the caller from the statement bytes under the TS's published rule."""
    st = verify_statement(statement, issuer_key, payload, profile)
    rc = verify_receipt(receipt, entry, log_key, profile)
    first = st if not st["ok"] else rc
    return {"ok": st["ok"] and rc["ok"], "result": "VALID" if st["ok"] and rc["ok"] else "INVALID",
            "stage": first["stage"], "statement": st, "receipt": rc, "profile": profile}
