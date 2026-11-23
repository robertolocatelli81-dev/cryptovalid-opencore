# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Roberto Locatelli
"""COSE Receipts (RFC 9942, VDS 1 = RFC9162_SHA256) and SCITT Signed Statements (RFC 9943) from ANY implementation —
offline, fail-closed, two declared profiles.

Status: EXPERIMENTAL. Outside the maintained core of cryptovalid-opencore (README, "Core and experimental
modules"): kept, installed and tested, no new scope is added here.

cryptovalid_scitt verifies what THIS repository's Transparency Service emits (EdDSA, its own ledger entry as the leaf).
This module verifies receipts and statements produced elsewhere, as exchanged between implementers (IETF AUDIT BoF
preparation, 2026-10-03):

  profile "rfc9942"  the COSE Receipt layer only: alg EdDSA (-8) with an Ed25519 key, ES256 (-7) with a P-256 key
                     only, ES384 (-35) with a P-384 key only; vds (label 395) read from the PROTECTED header and equal
                     to 1; every RFC 9162 inclusion proof (vdp label 396, key -1) is well formed and rebuilds a root,
                     and one of them rebuilds the root the log signed (detached payload = that root).
                     Also vds 2 = CCF_LEDGER_SHA256 (draft-ietf-scitt-receipts-ccf-profile-06, 2026-11-11, the
                     revision current on datatracker on 2026-11-17; §2.2, §3, §3.1, §3.2, §5): the vdp map is
                     exactly {-1: [+ proof]} or with -2 (Figure 11); each inclusion proof validated against Figures 6
                     and 4 before compute_root (CBOR without duplicate keys, keys 1 and 2, 32-byte hashes,
                     internal-evidence 1..1024 bytes of UTF-8, path [* [bool, bstr .size 32]], empty for a tree of
                     size 1 whose root is the leaf hash); leaf HASH(internal-transaction-hash ||
                     HASH(internal-evidence) || data-hash), the path walked with its left bits, payload detached
                     (MUST), every proof to the same root (MUST), and EVERY proof's data-hash equal to the caller's
                     entry, the statement digest of §2.2 (`ccf_statement_digest` computes it from the Signed
                     Statement: SHA-256 of its COSE_Sign1 with tag 18 kept and the unprotected header made an empty
                     map). Consistency proofs (-2, Figure 9) are not evaluated here: a receipt that carries them is
                     `CONSISTENCY_NOT_EVALUATED` (§5: "A Verifier MUST reject a receipt in which any proof present in
                     the vdp map recomputes a different root"; refusing them all never accepts one that does).
                     Also vds 3 = MMR_SHA256 (draft-ietf-scitt-receipts-mmr-profile-00, 2026-11-21, the WG document
                     current on datatracker on 2026-11-23; SPEC §28): receipts of inclusion through verify_receipt, the
                     caller's `entry` being the 32-byte NODE VALUE (the leaf commitment is the application's, §11.2);
                     receipts of consistency through verify_mmr_consistency, from a trusted size and accumulator. The
                     protected header must be Core Deterministic CBOR (§7); labels not read are ignored and reported
                     (`ignored_labels`). vds 3 and tree-size-2 -65933 are not IANA values (SPEC §28 rule 1).
  profile "rfc9943"  the same, plus the header MUSTs of RFC 9943 §6 on BOTH the Signed Statement and the Receipt:
                     CWT Claims (15) with iss (1) and sub (2), iss of 1..8192 characters, kid (4) when neither x5t (34)
                     nor x5chain (33) is in the protected header.

Rules of 0.26.0 (decided 2026-11-17 after a cross-verification against the scitt-cose vectors, receipt-v1 at
action-state-group/scitt-cose e76bbfdf7a02; each turns a 0.25.x acceptance into a refusal or a reported fact):

  Curve.     ES256 and ES384 are "polymorphic" in COSE (RFC 9864 §2.1, Proposed Standard, October 2025, which updates
             RFC 9053 and marks them Deprecated in §4.2.2; status read on rfc-editor.org on 2026-11-17); RFC 9053 §2.1
             (Informational, August 2022, updated by RFC 9864) "defines ECDSA as working only with the curves P-256,
             P-384, and P-521" ("Implementations need to check that the key type and curve are correct"; secp256k1 is
             ES256K, RFC 8812) and adds: "it is suggested that SHA-256 be used only with curve P-256, SHA-384 be used
             only with curve P-384". Here ES256 is P-256 only and ES384 P-384 only, for a Signed
             Statement and a Receipt: another curve is `KEY_CURVE_MISMATCH`, never a signature check (0.25.x checked
             the key type, not the curve: ES256 over secp256k1 and ES384 over P-256 verified). The fully-specified
             ESP256 (-9) and ESP384 (-51) of RFC 9864 are not supported (`UNSUPPORTED_ALG`).
  Proofs.    Every inclusion proof of a VDS 1 receipt is checked before any is used, none is skipped: one that is
             not [uint tree-size, uint leaf-index, [* 32-byte bstr]] or whose path does not rebuild a root is
             `MALFORMED_PROOF` (naming it); then one well-formed proof whose root the log signature covers suffices
             (a well-formed proof for another tree does not mask it, as the public vector valid-eddsa-multi-proof
             expects). 0.25.x skipped a malformed proof and accepted the receipt when another one verified.
  CCF -06.   draft-ietf-scitt-receipts-ccf-profile-06 replaced -05 (cited until this version): an empty path is
             valid (refused under -05's [+ ...]); every proof's data-hash must equal the entry (under -05 one bound
             proof sufficed); a vdp map with another key, or with consistency proofs, is refused (-05 ignored them).
             The public vector valid-ccf-vds2 (scitt-ccf-ledger v7.0.6) still verifies, and its leaf_entry is the
             statement digest of -06 §2.2 computed from its statement.cose (measured on 2026-11-17).
  Payload.   RFC 9942 §4.4: "The payload in such definitions SHOULD be detached". A receipt whose payload is attached
             and equal to the rebuilt root is accepted, as the standard decides, and the result says so:
             `payload_attached: true` (false when detached). An attached payload that is not the root is refused.

The leaf ENTRY is the Transparency Service's choice (RFC 9943 leaves it to the TS): the caller passes the entry bytes,
the receipt never chooses them. Keys are the relying party's: a kid or a certificate inside a message is never trusted
by itself. Every hostile input is a refusal with a named stage, never an exception.

Backend (0.27.0, 2026-11-18). The keys and signatures are read with `cryptography` (the `[sign]` extra). When it is
not installed, the check that needs it did not run: the stage is `BACKEND_MISSING` (`ok: false`), and
verify_statement_with_receipt answers `result: "NOT_EVALUATED"` when no part was refused for another stage (a part
refused before it needed `cryptography` stays `INVALID`). Until 0.26.0 the missing module was caught as hostile input:
measured on 2026-11-18 on the wheel 0.26.0 installed without `[sign]`, a valid statement was `MALFORMED_STATEMENT |
ModuleNotFoundError: No module named 'cryptography'` and a valid receipt `MALFORMED_RECEIPT`.
"""
from __future__ import annotations

import hashlib
from typing import Dict, List, Optional

import cryptovalid_merkle as M
import cryptovalid_receipt as R
from cryptovalid_scitt import (L_ALG, L_CWT, L_KID, L_VDP, L_VDS, CWT_ISS, CWT_SUB, MAX_ISS, VDP_INCLUSION,
                               VDS_RFC9162_SHA256, ScittError, _root_from_inclusion, _sig1, parse_cose_sign1)

ALG_EDDSA, ALG_ES256, ALG_ES384 = -8, -7, -35
VDS_CCF_LEDGER_SHA256 = 2        # draft-ietf-scitt-receipts-ccf-profile-06 §5: TBD_1, "Requested assignment" 2 (not yet IANA)
VDS_MMR_SHA256 = 3               # draft-ietf-scitt-receipts-mmr-profile-00 §3: TBD_1; 3 as requested by draft-bryce-...-04 (not IANA)
L_TREE_SIZE_2 = -65933           # draft-ietf-scitt-receipts-mmr-profile-00 §12.1.3: TBD_2, "private use until assigned"
L_X5CHAIN, L_X5T = 33, 34
PROFILES = ("rfc9942", "rfc9943")
BACKEND_MISSING_WHY = "cryptography is not installed here (pip install 'cryptovalid-opencore[sign]'): the signature was not evaluated"


def load_public_key(key):
    """A PEM public key (bytes or str), or 64 hex characters of a raw Ed25519 key."""
    from cryptography.hazmat.primitives import serialization as ser
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    if isinstance(key, str) and len(key) == 64 and all(c in "0123456789abcdefABCDEF" for c in key):
        return Ed25519PublicKey.from_public_bytes(bytes.fromhex(key))
    data = key.encode("ascii") if isinstance(key, str) else bytes(key)
    return ser.load_pem_public_key(data)


_CURVE_OF = {ALG_ES256: "secp256r1", ALG_ES384: "secp384r1"}   # 0.26.0: RFC 9053 §2.1 pairs, RFC 9864 §2.1


def _curve_problem(alg: int, pub) -> Optional[str]:
    """None when the key may verify `alg`: ES256 a P-256 key, ES384 a P-384 key (another curve is refused before any
    signature check); EdDSA keys are checked by _verify_sig."""
    from cryptography.hazmat.primitives.asymmetric import ec
    want = _CURVE_OF.get(alg)
    if want is None:
        return None
    if not isinstance(pub, ec.EllipticCurvePublicKey):
        return f"alg {alg} needs an EC key on {want}, the key is {type(pub).__name__}"
    if pub.curve.name != want:
        return f"alg {alg} needs a key on {want}, the key is on {pub.curve.name}"
    return None


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
        if _curve_problem(alg, pub) is not None or len(sig) != 2 * size:
            return False                 # r || s of the alg's fixed length (RFC 9053 §2.1); a key on another curve cannot verify it
        r, s = int.from_bytes(sig[:size], "big"), int.from_bytes(sig[size:], "big")
        pub.verify(encode_dss_signature(r, s), to_be_signed, ec.ECDSA(digest()))
        return True
    except (InvalidSignature, KeyError, ValueError):
        return False


# RFC 9052 §3.1 `crit`, per verifier and profile: the labels whose value that path compares or validates (see
# cryptovalid_receipt). CWT Claims (15) are read only with the RFC 9943 header MUSTs, kid (4) only seen as present.
_CRIT_STATEMENT = {"rfc9942": frozenset({1}), "rfc9943": frozenset({1, 15})}
_CRIT_RECEIPT = {"rfc9942": frozenset({1, 395}), "rfc9943": frozenset({1, 15, 395})}


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
        pbytes, ph, _, pl, sig = parse_cose_sign1(cose, _CRIT_STATEMENT[profile])
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
        pub = load_public_key(issuer_key)
        why = _curve_problem(alg, pub)
        if why:
            return _refuse("KEY_CURVE_MISMATCH", f"statement: {why}")
        if not _verify_sig(alg, pub, _sig1(pbytes, pl), sig):
            return _refuse("BAD_STATEMENT_SIGNATURE", "statement signature does not verify with the Issuer key")
        return {"ok": True, "stage": None, "why": "statement signature valid", "alg": alg,
                "payload_sha256": hashlib.sha256(pl).hexdigest()}
    except ImportError as e:   # the module's docstring, Backend: not run here, not a malformed input
        return _refuse("BACKEND_MISSING", BACKEND_MISSING_WHY + f" ({e})"[:120])
    except Exception as e:  # noqa: BLE001 — hostile bytes are a refusal, never a crash
        return _refuse("MALFORMED_STATEMENT", f"{type(e).__name__}: {e}"[:200])


def verify_receipt(receipt: bytes, entry: bytes, log_key, profile: str = "rfc9942") -> Dict:
    """An RFC 9942 COSE Receipt with VDS RFC9162_SHA256 for the leaf entry `entry` (the caller's bytes)."""
    if profile not in PROFILES:
        raise ValueError(f"profile must be one of {PROFILES}")
    if _mmr_vds(receipt) is not None:              # vds 3: the protected header is read under the MMR profile's rules
        return _verify_mmr_inclusion(receipt, entry, log_key, profile)
    try:
        rp, ph, uh, rpl, sig = parse_cose_sign1(receipt, _CRIT_RECEIPT[profile])
        vds = ph.get(L_VDS)                              # protected header only: an unprotected vds is never read
        if type(vds) is not int or vds not in (VDS_RFC9162_SHA256, VDS_CCF_LEDGER_SHA256):   # CBOR true is not the uint 1
            return _refuse("UNSUPPORTED_VDS", f"protected vds {vds!r} is not 1 (RFC9162_SHA256), 2 (CCF_LEDGER_SHA256) "
                           "or 3 (MMR_SHA256)")
        alg = ph.get(L_ALG)
        if alg not in (ALG_EDDSA, ALG_ES256, ALG_ES384):
            return _refuse("UNSUPPORTED_ALG", f"receipt alg {alg!r} not supported")
        if profile == "rfc9943":
            why = _header_musts(ph, "receipt")
            if why:
                return _refuse("HEADER_MUST", why)
        vdp = uh.get(L_VDP)
        if vds == VDS_CCF_LEDGER_SHA256 and isinstance(vdp, dict):   # ccf-profile-06 §5, Figure 11
            if not vdp or set(vdp) - {VDP_INCLUSION, -2}:
                return _refuse("MALFORMED_PROOF", f"vdp map keys {sorted(vdp, key=repr)!r}: only -1 and -2 (Figure 11)")
            if -2 in vdp:
                return _refuse("CONSISTENCY_NOT_EVALUATED", "a CCF receipt with consistency proofs (vdp -2): they are "
                               "not evaluated here, and every proof present MUST recompute the same root (-06 §5)")
        proofs = vdp.get(VDP_INCLUSION) if isinstance(vdp, dict) else None
        if not isinstance(proofs, list) or not proofs or not all(isinstance(p, bytes) for p in proofs):
            return _refuse("MALFORMED_PROOF", "no inclusion proof (vdp 396, key -1: [+ bstr .cbor proof])")
        pub = load_public_key(log_key)
        why = _curve_problem(alg, pub)
        if why:
            return _refuse("KEY_CURVE_MISMATCH", f"receipt: {why}")
        if vds == VDS_CCF_LEDGER_SHA256:
            return _verify_ccf(rp, rpl, sig, alg, pub, proofs, bytes(entry))
        leaf = M.leaf_hash(bytes(entry))
        walked = []
        for i, pb in enumerate(proofs):                  # 0.26.0: every proof is checked, a malformed one is never skipped
            dec = R.cbor_decode(pb)
            # RFC 9942: tree-size and leaf-index are uint — a CBOR true/false or a negative is not (as audit V1 #8/#9
            # fixed in cryptovalid_scitt, 30/09/2026; ported here 04/10/2026)
            if not (isinstance(dec, list) and len(dec) == 3 and type(dec[0]) is int and type(dec[1]) is int
                    and dec[0] >= 0 and dec[1] >= 0
                    and isinstance(dec[2], list) and all(isinstance(h, bytes) and len(h) == 32 for h in dec[2])):
                return _refuse("MALFORMED_PROOF", f"proof {i}: not [uint tree-size, uint leaf-index, [* 32-byte bstr]]")
            size, index, path = dec
            root = _root_from_inclusion(index, size, leaf, path)
            if root is None:                 # a path that cannot be walked (index ≥ size, path too long) proves nothing
                return _refuse("MALFORMED_PROOF", f"proof {i}: the path does not rebuild a root (tree size {size}, "
                                                  f"leaf index {index}, {len(path)} hashes)")
            walked.append((i, size, index, root))
        tried: List[str] = []
        for i, size, index, root in walked:              # then one whose root the log signed suffices
            if rpl is not None and rpl != root:
                tried.append(f"proof {i}: the attached payload is not the rebuilt root")
                continue
            if _verify_sig(alg, pub, _sig1(rp, root), sig):
                return {"ok": True, "stage": None, "why": "log signature valid over the root rebuilt from the entry and the path",
                        "alg": alg, "tree_size": size, "leaf_index": index, "root": root.hex(),
                        "payload_attached": rpl is not None}
            tried.append(f"proof {i}: the log signature does not verify over the rebuilt root")
        return _refuse("INCLUSION_ROOT_SIGNATURE_INVALID", "; ".join(tried))
    except ImportError as e:   # the module's docstring, Backend: not run here, not a malformed input
        return _refuse("BACKEND_MISSING", BACKEND_MISSING_WHY + f" ({e})"[:120])
    except Exception as e:  # noqa: BLE001
        return _refuse("MALFORMED_RECEIPT", f"{type(e).__name__}: {e}"[:200])


def _cbor_end(b: bytes, i: int, depth: int = 0) -> int:
    """the end of the definite-length CBOR item at `i` (major types 0-5, 6 for one tag, 7 simple values); ValueError else"""
    if depth > 64 or i >= len(b):
        raise ValueError("CBOR item cut short or nested too deep")
    major, info = b[i] >> 5, b[i] & 0x1F
    i += 1
    if info < 24:
        n = info
    elif info <= 27:
        k = 1 << (info - 24)
        if i + k > len(b):
            raise ValueError("CBOR head cut short")
        n, i = int.from_bytes(b[i:i + k], "big"), i + k
    else:
        raise ValueError("indefinite length or reserved CBOR encoding")
    if major in (0, 1, 7):
        return i
    if major in (2, 3):
        if i + n > len(b):
            raise ValueError("CBOR string cut short")
        return i + n
    if major == 6:
        return _cbor_end(b, i, depth + 1)
    for _ in range(n * (2 if major == 5 else 1)):
        i = _cbor_end(b, i, depth + 1)
    return i


def ccf_statement_digest(statement: bytes) -> bytes:
    """draft-ietf-scitt-receipts-ccf-profile-06 §2.2: the data-hash of a Signed Statement, SHA-256 of its COSE_Sign1
    as registered: tag 18 kept, the unprotected header an empty map, the protected header, payload and signature as
    received. ValueError for bytes that are not one tagged COSE_Sign1 (RFC 9943 §6.1: tag 18)."""
    b = bytes(statement)
    if b[:2] != b"\xd2\x84":
        raise ValueError("not a tagged COSE_Sign1 (tag 18, array of 4)")
    arr = R.cbor_decode(b[1:])            # the structure, strictly
    if not (isinstance(arr, list) and len(arr) == 4 and isinstance(arr[0], bytes) and isinstance(arr[1], dict)
            and (arr[2] is None or isinstance(arr[2], bytes)) and isinstance(arr[3], bytes)):
        raise ValueError("COSE_Sign1 must be [bstr, map, bstr / nil, bstr]")
    ends, i = [], 2
    for _ in range(4):
        j = _cbor_end(b, i)
        ends.append((i, j))
        i = j
    if i != len(b):
        raise ValueError("bytes after the COSE_Sign1")
    (p0, p1), _u, (l0, l1), (s0, s1) = ends
    return hashlib.sha256(b"\xd2\x84" + b[p0:p1] + b"\xa0" + b[l0:l1] + b[s0:s1]).digest()


def _ccf_root(proof) -> bytes:
    """compute_root of draft-ietf-scitt-receipts-ccf-profile-06 Figure 7, after the checks of its §3.2 (Figures 6 and
    4); ValueError on any shape outside them. An empty path is a tree of size 1: the root is the leaf hash."""
    if not (isinstance(proof, dict) and set(proof) == {1, 2}):
        raise ValueError("ccf-inclusion-proof must be {1: leaf, 2: path}")
    leaf, path = proof[1], proof[2]
    if not (isinstance(leaf, list) and len(leaf) == 3 and isinstance(leaf[0], bytes) and len(leaf[0]) == 32
            and isinstance(leaf[1], str) and 1 <= len(leaf[1].encode("utf-8")) <= 1024
            and isinstance(leaf[2], bytes) and len(leaf[2]) == 32):
        raise ValueError("ccf-leaf must be [bstr .size 32, tstr .size (1..1024), bstr .size 32]")
    if not (isinstance(path, list) and all(isinstance(e, list) and len(e) == 2 and isinstance(e[0], bool)
                                           and isinstance(e[1], bytes) and len(e[1]) == 32 for e in path)):
        raise ValueError("path must be [* [bool, bstr .size 32]]")
    H = lambda b: hashlib.sha256(b).digest()  # noqa: E731
    h = H(leaf[0] + H(leaf[1].encode("utf-8")) + leaf[2])
    for left, x in path:
        h = H(x + h) if left else H(h + x)
    return h


def _verify_ccf(rp: bytes, rpl, sig: bytes, alg: int, pub, proofs: List[bytes], entry: bytes) -> Dict:
    if rpl is not None:
        return _refuse("PAYLOAD_NOT_DETACHED", "a CCF inclusion receipt's payload MUST be detached (§3.1)")
    roots, decoded = set(), []
    for i, pb in enumerate(proofs):
        try:
            dec = R.cbor_decode(pb)
            roots.add(_ccf_root(dec))
        except ValueError as e:
            return _refuse("MALFORMED_PROOF", f"proof {i}: {e}")
        decoded.append(dec)
    for i, dec in enumerate(decoded):   # -06 §3.2: "Every proof in the receipt MUST have a data-hash equal to statement_digest"
        if dec[1][2] != entry:
            return _refuse("LEAF_NOT_THIS_STATEMENT", f"proof {i}: its data-hash is not the entry for this statement")
    if len(roots) != 1:
        return _refuse("PROOFS_DISAGREE", "the inclusion proofs do not compute the same root (§3.1 MUST)")
    root = roots.pop()
    if not _verify_sig(alg, pub, _sig1(rp, root), sig):
        return _refuse("INCLUSION_ROOT_SIGNATURE_INVALID", "the log signature does not verify over the rebuilt root")
    return {"ok": True, "stage": None, "why": "CCF: log signature valid over the root rebuilt from the leaf and the path",
            "alg": alg, "root": root.hex(), "vds": VDS_CCF_LEDGER_SHA256, "payload_attached": False}


def verify_statement_with_receipt(statement: bytes, receipt: bytes, issuer_key, log_key, entry: bytes,
                                  payload: Optional[bytes] = None, profile: str = "rfc9942") -> Dict:
    """Both checks; VALID only when the statement AND the receipt verify. `entry` is the TS's leaf entry for THIS
    statement, computed by the caller from the statement bytes under the TS's published rule."""
    st = verify_statement(statement, issuer_key, payload, profile)
    rc = verify_receipt(receipt, entry, log_key, profile)
    first = st if not st["ok"] else rc
    refused = [x for x in (st, rc) if not x["ok"] and x["stage"] != "BACKEND_MISSING"]
    if refused:
        first = refused[0]
    result = "VALID" if st["ok"] and rc["ok"] else "INVALID" if refused else "NOT_EVALUATED"
    return {"ok": st["ok"] and rc["ok"], "result": result,
            "stage": first["stage"], "statement": st, "receipt": rc, "profile": profile}


# ── vds 3 = MMR_SHA256, draft-ietf-scitt-receipts-mmr-profile-00 (2026-11-21) ────────────────────────────────────────
_U64 = 1 << 64
_MMR_MAX_PATH = 64                   # §2: a tree is at most 63 high, so no path is longer


class _Tag(tuple):
    """a CBOR tag (number, content) read inside an unread header value"""


class _Simple(int):
    """a CBOR simple value other than false, true and null"""


def _cbor_read(b: bytes, i: int, det: bool, depth: int = 0):
    """→ (value, end): one well-formed CBOR item (RFC 8949 §3; definite lengths only). With `det` also the Core
    Deterministic Encoding of §4.2.1: arguments and floats in shortest form, map keys in strictly increasing bytewise
    order of their encodings (no duplicates). Map keys are COSE labels, int or text (RFC 9052 §1.4). ValueError else."""
    if depth > 64 or i >= len(b):
        raise ValueError("CBOR item cut short or nested too deep")
    major, info = b[i] >> 5, b[i] & 0x1F
    i += 1
    if info >= 28:
        raise ValueError("indefinite length" if info == 31 else f"reserved additional information {info}")
    if major == 7 and info in (25, 26, 27):           # floats: half, single, double
        import struct
        k = {25: 2, 26: 4, 27: 8}[info]
        if i + k > len(b):
            raise ValueError("float cut short")
        raw = b[i:i + k]
        v = struct.unpack({2: ">e", 4: ">f", 8: ">d"}[k], raw)[0]
        if det and k > 2:
            for fmt in ((">e", ">f") if k == 8 else (">e",)):
                try:
                    if v != v:      # NaN: shorter when the payload bits a narrower float drops are zero
                        bits = int.from_bytes(raw, "big")
                        drop = {(8, ">f"): 29, (8, ">e"): 42, (4, ">e"): 13}[(k, fmt)]
                        if bits & ((1 << drop) - 1) == 0:
                            raise ValueError("float not in shortest form")
                    elif struct.unpack(fmt, struct.pack(fmt, v))[0] == v:
                        raise ValueError("float not in shortest form")
                except (OverflowError, struct.error):
                    pass
        return v, i + k
    if info < 24:
        n = info
    else:
        k = 1 << (info - 24)
        if i + k > len(b):
            raise ValueError("CBOR head cut short")
        n, i = int.from_bytes(b[i:i + k], "big"), i + k
        if det and n < (24 if k == 1 else 1 << (4 * k)):
            raise ValueError("argument not in shortest form")
    if major == 0:
        return n, i
    if major == 1:
        return -1 - n, i
    if major in (2, 3):
        if i + n > len(b):
            raise ValueError("string cut short")
        return (b[i:i + n] if major == 2 else b[i:i + n].decode("utf-8")), i + n    # invalid UTF-8: ValueError
    if major == 4:
        out = []
        for _ in range(n):
            v, i = _cbor_read(b, i, det, depth + 1)
            out.append(v)
        return out, i
    if major == 5:
        out, last = {}, None
        for _ in range(n):
            k0 = i
            key, i = _cbor_read(b, i, det, depth + 1)
            if type(key) not in (int, str):
                raise ValueError("map key is not a COSE label (int or text)")
            if key in out:
                raise ValueError("duplicate map key")
            if det and last is not None and b[k0:i] <= last:
                raise ValueError("map keys not in bytewise order")
            last = b[k0:i]
            out[key], i = _cbor_read(b, i, det, depth + 1)
        return out, i
    if major == 6:
        v, i = _cbor_read(b, i, det, depth + 1)
        return _Tag((n, v)), i
    if info == 24 and n < 32:                         # major 7: two-byte simple values below 32 are not well-formed
        raise ValueError("simple value below 32 in two bytes")
    return {20: False, 21: True, 22: None}.get(n, _Simple(n)), i


def _mmr_parse(cose: bytes, understood: frozenset):
    """→ (protected bytes, protected map, unprotected map, payload | None, signature) of a tagged COSE_Sign1 whose
    protected header is deterministically encoded as -00 §7 requires (the whole bstr one map); `crit` as RFC 9052 §3.1."""
    v, end = _cbor_read(bytes(cose), 0, False)
    if end != len(cose):
        raise ValueError("bytes after the COSE_Sign1")
    if not (isinstance(v, _Tag) and v[0] == 18 and isinstance(v[1], list) and len(v[1]) == 4):
        raise ValueError("not a tagged COSE_Sign1 (tag 18, array of 4)")
    pb, uh, pl, sig = v[1]
    if not (isinstance(pb, bytes) and isinstance(uh, dict) and (pl is None or isinstance(pl, bytes))
            and isinstance(sig, bytes)):
        raise ValueError("COSE_Sign1 must be [bstr protected, map unprotected, bstr / nil payload, bstr signature]")
    try:
        ph, pend = _cbor_read(pb, 0, True)
        if not isinstance(ph, dict) or pend != len(pb):
            raise ValueError("not one map filling the byte string")
    except ValueError as e:
        raise ScittError(f"protected header not deterministically encoded (-00 §7, RFC 8949 §4.2.1): {e}") from None
    crit = R.cose_crit_problem(ph, uh, understood)
    if crit:
        raise ValueError(crit)
    return pb, ph, uh, pl, sig


def _mmr_vds(cose) -> Optional[int]:
    """3 when the protected header reads vds 3 (routing only: everything is checked again by the verifier)"""
    try:
        pb = _cbor_read(bytes(cose), 0, False)[0][1][0]
        ph = _cbor_read(pb, 0, False)[0]
        return VDS_MMR_SHA256 if ph.get(L_VDS) == VDS_MMR_SHA256 else None      # 3.0 routes too, and is refused there
    except Exception:  # noqa: BLE001 — not an MMR receipt; the other paths refuse it with their own stage
        return None


def _mmr_height(i: int) -> int:
    """index_height, -00 §9.1"""
    pos = i + 1
    while pos & (pos + 1):                            # not all ones
        pos = pos - (1 << (pos.bit_length() - 1)) + 1
    return pos.bit_length() - 1


def _mmr_pospair(pos: int, a: bytes, b: bytes) -> bytes:
    """hash_pospair64, -00 §8.2.1 (pos < 2^64)"""
    if not 0 < pos < _U64:
        raise ValueError(f"position {pos} outside 64 bits")
    return hashlib.sha256(pos.to_bytes(8, "big") + a + b).digest()


def mmr_included_root(i: int, nodehash: bytes, proof: List[bytes]) -> bytes:
    """included_root, -00 §5.2: the peak the path implies for the node value `nodehash` at index `i`."""
    root, g = nodehash, _mmr_height(i)
    for sibling in proof:
        if _mmr_height(i + 1) > g:
            i += 1
            root = _mmr_pospair(i + 1, sibling, root)
        else:
            i += 2 << g
            root = _mmr_pospair(i + 1, root, sibling)
        g += 1
    return root


def _leaf_count(i: int) -> int:
    """leaf_count, -00 §9.3: the leaves of MMR(i+1), whose set bits are the heights of the peaks"""
    s = i + 1
    peaksize, peakmap = (1 << s.bit_length()) - 1, 0
    while peaksize > 0:
        peakmap <<= 1
        if s >= peaksize:
            s -= peaksize
            peakmap |= 1
        peaksize >>= 1
    return peakmap


def _complete(size: int) -> bool:
    """mmr_size_for_leaf_count(leaf_count(size - 1)) == size, -00 §9.4 (0, the empty tree, is complete)"""
    lc = _leaf_count(size - 1) if size else 0
    return 2 * lc - bin(lc).count("1") == size


class MmrShapeError(ValueError):
    """a consistency proof that is not of the shape its two sizes imply; `cls` names the class"""
    def __init__(self, cls: str, why: str):
        super().__init__(f"{cls}: {why}")
        self.cls = cls


def mmr_consistent_roots(sizefrom: int, sizeto: int, accumulatorfrom: List[bytes], proofs: List[List[bytes]]):
    """consistent_roots, -00 §7.1.1, with each "-> ERROR" of the draft an MmrShapeError. → (roots, nright)."""
    if sizeto <= sizefrom:
        raise MmrShapeError("size_must_increase", f"tree-size-2 {sizeto} is not above tree-size-1 {sizefrom}")
    if not 0 < sizeto < _U64 or not _complete(sizeto):
        raise MmrShapeError("incomplete_tree_size", f"tree-size-2 {sizeto} is not a complete MMR size")
    leavesto = _leaf_count(sizeto - 1)
    leavesfrom = _leaf_count(sizefrom - 1) if sizefrom > 0 else 0
    n = bin(leavesfrom).count("1")
    if len(accumulatorfrom) != n or len(proofs) != n:
        raise MmrShapeError("peak_count_mismatch", f"{n} peaks at size {sizefrom}, {len(accumulatorfrom)} "
                                                   f"accumulator values and {len(proofs)} paths")
    nto = bin(leavesto).count("1")
    if n == 0:
        return [], nto
    split = (leavesfrom ^ leavesto).bit_length() - 1
    roots: List[bytes] = []
    offset = i = 0
    for h in range(leavesfrom.bit_length() - 1, split, -1):
        if not (leavesfrom >> h) & 1:
            continue
        if len(proofs[i]) != 0:
            raise MmrShapeError("path_length_mismatch", f"path {i}: the peak is also a peak of tree-size-2, its path must be empty")
        roots.append(accumulatorfrom[i])
        offset += (1 << (h + 1)) - 1
        i += 1
    above, root = len(roots), None
    for h in range(split - 1, -1, -1):
        if not (leavesfrom >> h) & 1:
            continue
        if len(proofs[i]) != split - h:
            raise MmrShapeError("path_length_mismatch", f"path {i}: {len(proofs[i])} hashes, {split - h} expected")
        subtree = (1 << (h + 1)) - 1
        proven = mmr_included_root(offset + subtree - 1, accumulatorfrom[i], proofs[i])
        if i == above:
            root = proven
        elif proven != root:
            raise MmrShapeError("root_mismatch", f"path {i} produces another value than path {above}")
        offset += subtree
        i += 1
    if n > above:
        roots.append(root)
    return roots, nto - len(roots)


_CRIT_MMR_INCLUSION = {"rfc9942": frozenset({1, 395}), "rfc9943": frozenset({1, 15, 395})}
_CRIT_MMR_CONSISTENCY = {p: c | {L_TREE_SIZE_2} for p, c in _CRIT_MMR_INCLUSION.items()}
_MMR_READ = frozenset({1, 2, 15, 395, L_TREE_SIZE_2})   # protected labels the MMR paths read (4, 33, 34: seen as present)


def _mmr_common(receipt: bytes, log_key, profile: str, understood: Dict, vdp_key: int):
    """the checks inclusion and consistency share; → (refusal, None) or (None, (rp, ph, sig, alg, pub, proofs))"""
    if profile not in PROFILES:
        raise ValueError(f"profile must be one of {PROFILES}")
    try:
        rp, ph, uh, rpl, sig = _mmr_parse(receipt, understood[profile])
    except ScittError as e:
        return _refuse("PROTECTED_HEADER_ENCODING", str(e)[:200]), None
    vds = ph.get(L_VDS)
    if type(vds) is not int or vds != VDS_MMR_SHA256:
        return _refuse("UNSUPPORTED_VDS", f"protected vds {vds!r} is not 3 (MMR_SHA256)"), None
    alg = ph.get(L_ALG)
    if type(alg) is not int or alg not in (ALG_EDDSA, ALG_ES256, ALG_ES384):
        return _refuse("UNSUPPORTED_ALG", f"receipt alg {alg!r} not supported"), None
    if profile == "rfc9943":
        why = _header_musts(ph, "receipt")
        if why:
            return _refuse("HEADER_MUST", why), None
    vdp = uh.get(L_VDP)
    if not isinstance(vdp, dict) or set(vdp) != {vdp_key}:
        keys = sorted(vdp, key=repr) if isinstance(vdp, dict) else vdp
        other = -1 if vdp_key == -2 else -2
        if isinstance(vdp, dict) and set(vdp) == {other}:
            fn = "an inclusion receipt: verify_receipt" if other == -1 else "a consistency receipt: verify_mmr_consistency"
            return _refuse("OTHER_RECEIPT_KIND", f"vdp holds {other} only, {fn}"), None
        return _refuse("MALFORMED_PROOF", f"vdp {keys!r}: an MMR receipt's vdp map is exactly {{{vdp_key}: [+ bstr]}}"), None
    proofs = vdp[vdp_key]
    if not isinstance(proofs, list) or not proofs or not all(isinstance(p, bytes) for p in proofs):
        return _refuse("MALFORMED_PROOF", f"vdp {vdp_key} is not [+ bstr .cbor proof]"), None
    if rpl is not None:
        return _refuse("PAYLOAD_NOT_DETACHED", "an MMR receipt's payload MUST be detached (-00 §5, §7)"), None
    pub = load_public_key(log_key)
    why = _curve_problem(alg, pub)
    if why:
        return _refuse("KEY_CURVE_MISMATCH", f"receipt: {why}"), None
    return None, (rp, ph, sig, alg, pub, proofs)


def _hashes(x, what: str) -> List[bytes]:
    if not (isinstance(x, list) and len(x) <= _MMR_MAX_PATH and all(isinstance(h, bytes) and len(h) == 32 for h in x)):
        raise ValueError(f"{what} must be [* bstr .size 32] (node values of MMR_SHA256, -00 §4), at most {_MMR_MAX_PATH}")
    return x


def _verify_mmr_inclusion(receipt: bytes, entry: bytes, log_key, profile: str) -> Dict:
    """-00 §5.1. `entry` is the NODE VALUE (32 bytes), computed by the caller under the log's leaf commitment scheme
    (§11.2: the profile leaves it to the application)."""
    try:
        bad, got = _mmr_common(receipt, log_key, profile, _CRIT_MMR_INCLUSION, -1)
        if bad:
            return bad
        rp, ph, sig, alg, pub, proofs = got
        node = bytes(entry)
        if len(node) != 32:
            return _refuse("ENTRY_NOT_A_NODE_VALUE", f"an MMR_SHA256 entry is a 32-byte node value, not {len(node)} bytes")
        peaks, walked = set(), []
        for k, pb in enumerate(proofs):
            try:
                dec = R.cbor_decode(pb)
                if not (isinstance(dec, list) and len(dec) == 2 and type(dec[0]) is int and 0 <= dec[0] < _U64 - 1):
                    raise ValueError("not [uint index, [* hash]] with an index below 2^64 - 1")
                path = _hashes(dec[1], "inclusion-path")
                peaks.add(mmr_included_root(dec[0], node, path))
            except ValueError as e:
                return _refuse("MALFORMED_PROOF", f"proof {k}: {e}"[:200])
            walked.append((dec[0], len(path)))
        if len(peaks) != 1:     # one detached payload is signed: a proof for another peak is unverified material
            return _refuse("PROOFS_DISAGREE", "the inclusion proofs do not produce the same peak")
        peak = peaks.pop()
        if not _verify_sig(alg, pub, _sig1(rp, peak), sig):
            return _refuse("INCLUSION_ROOT_SIGNATURE_INVALID", "the log signature does not verify over the peak "
                                                               "included_root produces (-00 §5.1 step 3)")
        index, plen = walked[0]
        return {"ok": True, "stage": None, "why": "MMR: log signature valid over the peak rebuilt from the node value and the path",
                "alg": alg, "vds": VDS_MMR_SHA256, "root": peak.hex(), "leaf_index": index, "node_height": _mmr_height(index),
                "index_bound": all(p > 0 for _, p in walked),   # -00 §11.1: an empty path does not bind the index
                "payload_attached": False, "ignored_labels": sorted((k for k in ph if k not in _MMR_READ), key=repr)}
    except ImportError as e:
        return _refuse("BACKEND_MISSING", BACKEND_MISSING_WHY + f" ({e})"[:120])
    except Exception as e:  # noqa: BLE001
        return _refuse("MALFORMED_RECEIPT", f"{type(e).__name__}: {e}"[:200])


def verify_mmr_consistency(receipt: bytes, log_key, trusted_size: int, trusted_accumulator: List[bytes],
                           profile: str = "rfc9942") -> Dict:
    """A COSE Receipt of consistency of draft-ietf-scitt-receipts-mmr-profile-00 §7.1, from the trusted state
    (`trusted_size`, `trusted_accumulator`: the peaks, highest first; size 0 and [] is the empty tree). The trusted vds
    is MMR_SHA256, the one this verifier supports, so step 2 is `vds == 3`. On success `tree_size_2` and `accumulator`
    are the new trusted state (§7.1: it advances only forwards; a caller that holds a later state passes that one)."""
    try:
        if not (type(trusted_size) is int and 0 <= trusted_size < _U64 and _complete(trusted_size)
                and isinstance(trusted_accumulator, list)
                and all(isinstance(h, bytes) and len(h) == 32 for h in trusted_accumulator)
                and len(trusted_accumulator) == bin(_leaf_count(trusted_size - 1) if trusted_size else 0).count("1")):
            return _refuse("TRUSTED_STATE_INVALID", "the trusted state is not a complete MMR size with one 32-byte "
                                                    "value per peak")
        bad, got = _mmr_common(receipt, log_key, profile, _CRIT_MMR_CONSISTENCY, -2)
        if bad:
            return bad
        rp, ph, sig, alg, pub, proofs = got
        if L_TREE_SIZE_2 not in ph:
            return _refuse("SIGNED_SIZE_MISSING", "the protected header has no tree-size-2 (-65933): MUST be rejected (-00 §7)")
        signed = ph[L_TREE_SIZE_2]
        if type(signed) is not int or signed < 0:
            return _refuse("SIGNED_SIZE_NOT_UINT", f"tree-size-2 {signed!r} is not an unsigned integer (-00 §7.1 step 1)")
        steps = []
        for k, pb in enumerate(proofs):
            try:
                dec = R.cbor_decode(pb)
                if not (isinstance(dec, list) and len(dec) == 4 and type(dec[0]) is int and type(dec[1]) is int
                        and dec[0] >= 0 and dec[1] >= 0 and isinstance(dec[2], list) and len(dec[2]) <= _MMR_MAX_PATH):
                    raise ValueError("not [uint tree-size-1, uint tree-size-2, [* consistency-path], [* hash]]")
                steps.append((dec[0], dec[1], [_hashes(p, "consistency-path") for p in dec[2]],
                              _hashes(dec[3], "right-peaks")))
            except ValueError as e:
                return _refuse("MALFORMED_PROOF", f"proof {k}: {e}"[:200])
        if signed != steps[-1][1]:
            return _refuse("SIGNED_SIZE_MISMATCH", f"protected tree-size-2 {signed} is not the last proof's "
                                                   f"{steps[-1][1]} (-00 §7.1 step 3)")
        size, acc = trusted_size, list(trusted_accumulator)
        for k, (s1, s2, paths, right) in enumerate(steps):
            if s1 != size:
                return _refuse("CHAIN_NOT_CONTIGUOUS", f"proof {k}: tree-size-1 {s1}, the state is at {size} "
                                                       "(-00 §7.1 steps 4, 6.1)")
            try:
                roots, nright = mmr_consistent_roots(size, s2, acc, paths)
            except MmrShapeError as e:
                return _refuse("MALFORMED_PROOF", f"proof {k}: {e}"[:200], shape=e.cls)
            if len(right) != nright:
                return _refuse("MALFORMED_PROOF", f"proof {k}: {len(right)} right-peaks, {nright} expected",
                               shape="right_peak_count_mismatch")
            size, acc = s2, roots + right
        if not _verify_sig(alg, pub, _sig1(rp, b"".join(acc)), sig):
            return _refuse("CONSISTENCY_SIGNATURE_INVALID", "the log signature does not verify over the accumulator "
                                                            f"of tree size {size} (-00 §7.1 step 7)")
        return {"ok": True, "stage": None, "why": "MMR: log signature valid over the accumulator the proofs produce",
                "alg": alg, "vds": VDS_MMR_SHA256, "tree_size_2": size, "accumulator": [h.hex() for h in acc],
                "payload_attached": False, "ignored_labels": sorted((k for k in ph if k not in _MMR_READ), key=repr)}
    except ImportError as e:
        return _refuse("BACKEND_MISSING", BACKEND_MISSING_WHY + f" ({e})"[:120])
    except Exception as e:  # noqa: BLE001
        return _refuse("MALFORMED_RECEIPT", f"{type(e).__name__}: {e}"[:200])
