#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""cryptovalid-opencore — SCITT Signed Statements and Transparent Statements (RFC 9943, 0.14.0, 2026-09-19).

RFC 9943 (IETF SCITT architecture, Proposed Standard, June 2026 — copy downloaded 2026-09-19):
  * a Signed Statement is a COSE_Sign1 (tag 18) whose protected header MUST carry the CWT Claims parameter (label 15)
    with iss (1) and sub (2); alg (1), content type (3) and kid (4, MUST be present without x5t/x5chain) — §6, Fig. 3/5;
  * a Receipt is a COSE_Sign1 too, with the same CWT Claims requirement and the RFC 9942 proof in its unprotected
    header (vds 395 in the protected header, vdp 396 unprotected) — §6, "A Receipt is a Signed Statement … See RFC 9942";
  * a Transparent Statement is the Signed Statement with `receipts` (label 394) = [+ bstr .cbor Receipt] in its
    unprotected header — Fig. 7/8.
Here the Transparency Service (TS) is a cryptovalid ledger: registering a Signed Statement appends an entry whose data
binds the statement's SHA-256 (`data.scitt.statement_sha256`), and the Receipt proves that entry's inclusion under the
ledger's signed tree head. A relying party verifies, offline: the Issuer's signature, that the leaf named by the
receipt binds THIS statement, and the RFC 6962 inclusion path up to the root the TS key signed.

Honest scope: EdDSA (Ed25519) only; the COSE structures are measured against an independent implementation (pycose)
in the tests; there is no public SCITT Transparency Service here, and CCF's receipt profile (pyscitt) is a different
VDS — this is the RFC 9942 `RFC9162_SHA256` profile. Registration policies (RFC 9943 §4.1) are the deployment's.
"""
from __future__ import annotations
import hashlib
import json
import os
import sys
import time
from typing import Dict, List, Optional, Tuple
try:
    import fcntl
except ImportError:                  # pragma: no cover
    fcntl = None

import cryptovalid_merkle as M
import cryptovalid_receipt as R

TAG_COSE_SIGN1 = b"\xd2"
ALG_EDDSA = -8
L_ALG, L_CTY, L_KID, L_CWT = 1, 3, 4, 15
CWT_ISS, CWT_SUB, CWT_IAT = 1, 2, 6
L_RECEIPTS, L_VDS, L_VDP = 394, 395, 396
VDS_RFC9162_SHA256, VDP_INCLUSION = 1, -1
L_LEAF = "cryptovalid.leaf"      # unprotected, private label: the canonical entry bytes the receipt's leaf commits to
MAX_ISS = 8192                   # RFC 9943: "The iss Claim value's length MUST be between 1 and 8192 characters"


class ScittError(ValueError):
    pass


def _sig1(protected: bytes, payload: bytes, external_aad: bytes = b"") -> bytes:
    return R.cbor_encode(["Signature1", protected, external_aad, payload])


def _ed():
    from cryptography.hazmat.primitives import serialization as ser
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
    from cryptography.exceptions import InvalidSignature
    return Ed25519PrivateKey, Ed25519PublicKey, ser, InvalidSignature


def statement_id(cose: bytes) -> str:
    """The identity a receipt binds: SHA-256 over the SIGNED parts of the COSE_Sign1 — protected header bytes, payload
    (or the empty string when detached) and signature — each length-prefixed. Independent of the unprotected header
    (RFC 9943 §6.3: it is emptied before a statement enters a Statement Sequence, and receipts are added there) and of
    the encoder that produced the outer array, so a Transparent Statement of one TS registers at another (§6.3)."""
    pb, _, _, pl, sig = parse_cose_sign1(cose)
    h = hashlib.sha256()
    for part in (pb, pl or b"", sig):
        h.update(len(part).to_bytes(8, "big")); h.update(part)
    return h.hexdigest()


def _load_sk(keyfile: str):
    Ed, _, ser, _ = _ed()
    with open(keyfile, encoding="utf-8") as f:
        sk = Ed.from_private_bytes(bytes.fromhex(f.read().strip()))
    return sk, sk.public_key().public_bytes(ser.Encoding.Raw, ser.PublicFormat.Raw)


def _check_claims(iss: str, sub: str) -> None:
    if not isinstance(iss, str) or not (1 <= len(iss) <= MAX_ISS):
        raise ScittError("iss must be a string of 1..8192 characters (RFC 9943 §6)")
    if not isinstance(sub, str) or not sub:
        raise ScittError("sub must be a non-empty string")


# ── Signed Statement ─────────────────────────────────────────────────────────────────────────────────────────────
def signed_statement(payload: bytes, content_type: str, iss: str, sub: str, keyfile: str, detached: bool = False,
                     iat: Optional[int] = None) -> bytes:
    """COSE_Sign1 (tag 18): protected {alg EdDSA, content type, kid = Ed25519 public key, CWT {iss, sub, iat}};
    payload attached, or detached (nil) when the Statement is stored elsewhere (RFC 9943 Fig. 4)."""
    _check_claims(iss, sub)
    if not isinstance(payload, (bytes, bytearray)):
        raise ScittError("payload must be bytes")
    if not isinstance(content_type, str) or not content_type or "\n" in content_type:
        raise ScittError("content_type must be a media type string")
    sk, pk = _load_sk(keyfile)
    claims = {CWT_ISS: iss, CWT_SUB: sub}
    if iat is not None:
        claims[CWT_IAT] = int(iat)
    protected = R.cbor_encode({L_ALG: ALG_EDDSA, L_CTY: content_type, L_KID: pk, L_CWT: claims})
    sig = sk.sign(_sig1(protected, bytes(payload)))
    return TAG_COSE_SIGN1 + R.cbor_encode([protected, {}, None if detached else bytes(payload), sig])


def parse_cose_sign1(cose: bytes) -> Tuple[bytes, Dict, Dict, Optional[bytes], bytes]:
    """→ (protected bytes, protected map, unprotected map, payload | None, signature); structural checks only."""
    if not isinstance(cose, (bytes, bytearray)) or cose[:1] != TAG_COSE_SIGN1:
        raise ScittError("not a tagged COSE_Sign1 (tag 18)")
    arr = R.cbor_decode(bytes(cose[1:]))
    if not (isinstance(arr, list) and len(arr) == 4 and isinstance(arr[0], bytes) and isinstance(arr[1], dict)
            and (arr[2] is None or isinstance(arr[2], bytes)) and isinstance(arr[3], bytes)):
        raise ScittError("COSE_Sign1 must be [bstr protected, map unprotected, bstr / nil payload, bstr signature]")
    ph = R.cbor_decode(arr[0])
    if not isinstance(ph, dict):
        raise ScittError("protected header must be a map")
    return arr[0], ph, arr[1], arr[2], arr[3]


def verify_signed_statement(cose: bytes, issuer_pubkey_hex: str, payload: Optional[bytes] = None) -> Dict:
    """Fail-closed: the Issuer key is the relying party's (kid inside the message is never trusted by itself); the
    protected header must carry alg EdDSA and CWT iss/sub; a detached payload must be supplied."""
    out = {"ok": False, "why": None, "iss": None, "sub": None, "content_type": None, "payload_sha256": None}
    _, EdPub, _, InvalidSignature = _ed()
    try:
        pbytes, ph, uh, pl, sig = parse_cose_sign1(cose)
        if ph.get(L_ALG) != ALG_EDDSA:
            out["why"] = "alg is not EdDSA"; return out
        cwt = ph.get(L_CWT)
        if not isinstance(cwt, dict) or not isinstance(cwt.get(CWT_ISS), str) or not isinstance(cwt.get(CWT_SUB), str):
            out["why"] = "protected header lacks CWT Claims (15) with iss (1) and sub (2) — RFC 9943 §6"; return out
        _check_claims(cwt[CWT_ISS], cwt[CWT_SUB])
        if ph.get(L_KID) is None and 33 not in ph and 34 not in ph:
            out["why"] = "kid (4) must be present when x5t/x5chain are absent — RFC 9943 §6"; return out
        pk = bytes.fromhex(issuer_pubkey_hex)   # kid is an opaque identifier (COSE): the trusted key decides, not the kid
        if pl is None:
            if payload is None:
                out["why"] = "detached payload: pass the Statement bytes"; return out
            pl = bytes(payload)
        elif payload is not None and bytes(payload) != pl:
            out["why"] = "the attached payload differs from the given Statement"; return out
        EdPub.from_public_bytes(pk).verify(sig, _sig1(pbytes, pl))
        out.update(ok=True, why="Issuer signature valid; CWT iss/sub present", iss=cwt[CWT_ISS], sub=cwt[CWT_SUB],
                   content_type=ph.get(L_CTY), payload_sha256=hashlib.sha256(pl).hexdigest())
        return out
    except Exception as e:  # noqa: BLE001 — fail-closed on any hostile input (IndexError/AttributeError from CBOR included)
        out["why"] = f"invalid: {e if isinstance(e, (ScittError, ValueError)) else type(e).__name__}"; return out


# ── Transparency Service: registration, receipts, transparent statements ─────────────────────────────────────────
def register(cose: bytes, ledger_path: str, issuer_pubkey_hex: str, payload: Optional[bytes] = None) -> Dict:
    """Register a Signed Statement: verify it (a TS MUST NOT register what it cannot validate — §4), then append to
    the ledger an entry whose data binds the statement: {"scitt": {"statement_sha256", "iss", "sub", "content_type"}}.
    The ledger is the hash-chained JSONL of this repository (idx, ts, data, prev_hash, self_hash). Returns the index."""
    v = verify_signed_statement(cose, issuer_pubkey_hex, payload)
    if not v["ok"]:
        raise ScittError(f"registration refused: {v['why']}")
    sid = statement_id(cose)
    lock_fd = None
    if fcntl is not None:                # the read-append is atomic across processes (POSIX flock on <ledger>.lock)
        lock_fd = os.open(ledger_path + ".lock", os.O_RDWR | os.O_CREAT, 0o600); fcntl.flock(lock_fd, fcntl.LOCK_EX)
    try:
        entries = []
        if os.path.exists(ledger_path):
            with open(ledger_path, encoding="utf-8") as f:
                entries = [json.loads(l) for l in f if l.strip()]
        prev = entries[-1]["self_hash"] if entries else "0" * 64
        e = {"idx": len(entries), "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
             "data": {"scitt": {"statement_sha256": sid, "iss": v["iss"], "sub": v["sub"],
                                "content_type": v["content_type"], "payload_sha256": v["payload_sha256"]}},
             "prev_hash": prev}
        e["self_hash"] = hashlib.sha256(json.dumps(e, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        with open(ledger_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(e) + "\n"); f.flush(); os.fsync(f.fileno())
    finally:
        if lock_fd is not None:
            fcntl.flock(lock_fd, fcntl.LOCK_UN); os.close(lock_fd)
    return {"index": e["idx"], "self_hash": e["self_hash"], "statement_sha256": sid}


def receipt(ledger_path: str, index: int, ts_keyfile: str, ts_iss: str, ts_sub: Optional[str] = None, detached: bool = True) -> bytes:
    """An RFC 9943 Receipt for entry `index`: COSE_Sign1 with protected {alg, vds=1 (RFC9162_SHA256), kid = TS key,
    CWT {iss = the TS, sub}} — the CWT Claims RFC 9943 requires in a Receipt — payload = signed tree root, unprotected
    {vdp: {-1: [bstr .cbor [tree-size, leaf-index, path]]}, "cryptovalid.leaf": canonical entry bytes}; the root payload
    is detached by default (RFC 9942 §4.4 SHOULD) — a verifier recomputes it — or attached with detached=False."""
    _check_claims(ts_iss, ts_sub or ts_iss)
    leaves = M.leaves_from_ledger(ledger_path)
    if not (0 <= index < len(leaves)):
        raise ScittError(f"index {index} outside the ledger ({len(leaves)} entries)")
    sk, pk = _load_sk(ts_keyfile)
    root = M.mth(leaves)
    path = M.inclusion_proof(index, leaves)
    protected = R.cbor_encode({L_ALG: ALG_EDDSA, L_VDS: VDS_RFC9162_SHA256, L_KID: pk, L_CWT: {CWT_ISS: ts_iss, CWT_SUB: ts_sub or ts_iss}})
    sig = sk.sign(_sig1(protected, root))
    unprotected = {L_VDP: {VDP_INCLUSION: [R.cbor_encode([len(leaves), index, list(path)])]}, L_LEAF: leaves[index]}
    # RFC 9942 §4.4: the payload (the root) SHOULD be detached — the verifier recomputes it from the leaf and the path
    return TAG_COSE_SIGN1 + R.cbor_encode([protected, unprotected, None if detached else root, sig])


def _root_from_inclusion(m: int, n: int, leaf: bytes, proof: List[bytes]) -> Optional[bytes]:
    """RFC 9162 §2.1.3.2 walked to the root (None when the path cannot be walked)."""
    if m >= n or m < 0:
        return None
    fn, sn, r = m, n - 1, leaf
    for p in proof:
        if sn == 0:
            return None
        if fn & 1 or fn == sn:
            r = M.node_hash(p, r)
            while not (fn & 1) and fn != 0:
                fn >>= 1; sn >>= 1
            fn >>= 1; sn >>= 1
        else:
            r = M.node_hash(r, p)
            fn >>= 1; sn >>= 1
    return r if sn == 0 else None


def transparent_statement(cose: bytes, receipts: List[bytes]) -> bytes:
    """The Signed Statement with `receipts` (394) = [+ bstr .cbor Receipt] in its unprotected header; protected
    header, payload and signature are copied byte for byte (a Transparent Statement is the same COSE_Sign1)."""
    if not receipts:
        raise ScittError("at least one receipt (RFC 9943 Fig. 7: [+ bstr])")
    pbytes, _, uh, pl, sig = parse_cose_sign1(cose)
    for r in receipts:
        parse_cose_sign1(r)              # each must itself be a COSE_Sign1
    uh = dict(uh); uh[L_RECEIPTS] = list(uh.get(L_RECEIPTS, [])) + [bytes(r) for r in receipts]
    return TAG_COSE_SIGN1 + R.cbor_encode([pbytes, uh, pl, sig])


def verify_transparent_statement(cose: bytes, issuer_pubkey_hex: str, ts_pubkey_hex: str, payload: Optional[bytes] = None,
                                 expected_ts_iss: Optional[str] = None) -> Dict:
    """Relying-party check, offline and fail-closed: (1) the Issuer signature and CWT claims of the Signed Statement;
    (2) at least one Receipt whose TS signature verifies with the TRUSTED TS key, whose CWT iss is the expected TS,
    whose leaf (the canonical ledger entry, given unsigned in the receipt) binds THIS statement's SHA-256, and whose
    RFC 6962 inclusion path rebuilds the root the TS signed. A receipt naming another statement, another root or
    another key does not count."""
    out = {"ok": False, "why": None, "statement": None, "receipts": []}
    st = verify_signed_statement(cose, issuer_pubkey_hex, payload)
    out["statement"] = st
    if not st["ok"]:
        out["why"] = f"signed statement: {st['why']}"; return out
    try:
        _, _, uh, _, _ = parse_cose_sign1(cose)
        want = statement_id(cose)        # the signed parts only: unprotected header and encoder do not matter
    except Exception as e:  # noqa: BLE001
        out["why"] = f"invalid: {e if isinstance(e, ScittError) else type(e).__name__}"; return out
    recs = uh.get(L_RECEIPTS)
    if not isinstance(recs, list) or not recs or not all(isinstance(r, bytes) for r in recs):
        out["why"] = "no receipts (label 394) in the unprotected header"; return out
    _, EdPub, _, InvalidSignature = _ed()
    good = 0
    for i, rb in enumerate(recs):
        res = {"index": i, "ok": False, "why": None}
        out["receipts"].append(res)
        try:
            rp, rph, ruh, rpl, rsig = parse_cose_sign1(rb)
            if rph.get(L_ALG) != ALG_EDDSA or rph.get(L_VDS) != VDS_RFC9162_SHA256:
                res["why"] = "unsupported alg/vds"; continue
            cwt = rph.get(L_CWT)
            if not isinstance(cwt, dict) or not isinstance(cwt.get(CWT_ISS), str) or not isinstance(cwt.get(CWT_SUB), str):
                res["why"] = "receipt lacks CWT Claims iss/sub (RFC 9943 §6)"; continue
            if expected_ts_iss is not None and cwt[CWT_ISS] != expected_ts_iss:
                res["why"] = f"receipt iss {cwt[CWT_ISS]!r} is not the expected TS"; continue
            tpk = bytes.fromhex(ts_pubkey_hex)
            if rph.get(L_KID) != tpk:
                res["why"] = "receipt kid differs from the trusted TS key"; continue
            leaf_canon = ruh.get(L_LEAF)
            if not isinstance(leaf_canon, bytes):
                res["why"] = "receipt carries no canonical leaf (cryptovalid.leaf)"; continue
            entry = json.loads(leaf_canon.decode("utf-8"))
            if not (isinstance(entry, dict) and isinstance(entry.get("data"), dict) and isinstance(entry["data"].get("scitt"), dict)):
                res["why"] = "the receipt's leaf is not a SCITT registration entry"; continue
            if entry["data"]["scitt"].get("statement_sha256") != want:
                res["why"] = "the receipt's leaf binds another statement"; continue
            vdp = ruh.get(L_VDP)
            proofs = vdp.get(VDP_INCLUSION) if isinstance(vdp, dict) else None
            if not isinstance(proofs, list) or not proofs or not isinstance(proofs[0], bytes):
                res["why"] = "no inclusion proof (vdp -1)"; continue
            dec = R.cbor_decode(proofs[0])
            if not (isinstance(dec, list) and len(dec) == 3):
                res["why"] = "malformed inclusion proof"; continue
            n, idx, path = dec
            if not (isinstance(n, int) and isinstance(idx, int) and isinstance(path, list) and all(isinstance(h, bytes) and len(h) == 32 for h in path)):
                res["why"] = "malformed inclusion proof"; continue
            if idx != entry.get("idx"):
                res["why"] = "leaf index differs from the entry's idx"; continue
            # the root: recomputed from the leaf and the (unsigned) path — RFC 9942 §5.2.1 — then the TS signature is
            # checked over THAT root; an attached payload must equal it
            recomputed = _root_from_inclusion(idx, n, M.leaf_hash(leaf_canon), path)
            if recomputed is None:
                res["why"] = "inclusion path does not rebuild a root"; continue
            if rpl is not None and rpl != recomputed:
                res["why"] = "inclusion path does not rebuild the signed root"; continue
            EdPub.from_public_bytes(tpk).verify(rsig, _sig1(rp, recomputed))
            res.update(ok=True, why="TS signature valid over the root rebuilt from the leaf and the path; the leaf binds this statement",
                       tree_size=n, leaf_index=idx, ts_iss=cwt[CWT_ISS], signed_root=recomputed.hex(), payload_detached=rpl is None)
            good += 1
        except Exception as e:  # noqa: BLE001 — every hostile receipt is a refused receipt, never a crash
            res["why"] = f"invalid: {e if isinstance(e, (ScittError, ValueError)) else type(e).__name__}"
    out["ok"] = good > 0
    out["why"] = f"{good} of {len(recs)} receipt(s) valid" if good else "no valid receipt"
    return out


def main(argv=None) -> int:
    import argparse
    ap = argparse.ArgumentParser(description="SCITT (RFC 9943) signed / transparent statements over a cryptovalid ledger")
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("sign"); s.add_argument("statement"); s.add_argument("--cty", required=True); s.add_argument("--iss", required=True)
    s.add_argument("--sub", required=True); s.add_argument("--key", required=True); s.add_argument("--out", required=True); s.add_argument("--detached", action="store_true")
    r = sub.add_parser("register"); r.add_argument("signed"); r.add_argument("--ledger", required=True); r.add_argument("--issuer-pubkey", required=True)
    r.add_argument("--ts-key", required=True); r.add_argument("--ts-iss", required=True); r.add_argument("--out", required=True, help="transparent statement")
    r.add_argument("--statement", help="the Statement bytes when the payload is detached")
    v = sub.add_parser("verify"); v.add_argument("transparent"); v.add_argument("--issuer-pubkey", required=True); v.add_argument("--ts-pubkey", required=True)
    v.add_argument("--ts-iss"); v.add_argument("--statement")
    a = ap.parse_args(argv)
    try:
        if a.cmd == "sign":
            with open(a.statement, "rb") as f:
                pl = f.read()
            cose = signed_statement(pl, a.cty, a.iss, a.sub, a.key, detached=a.detached)
            with open(a.out, "wb") as f:
                f.write(cose)
            print(json.dumps({"stato": "OK", "bytes": len(cose), "sha256": hashlib.sha256(cose).hexdigest()})); return 0
        if a.cmd == "register":
            with open(a.signed, "rb") as f:
                cose = f.read()
            pl = open(a.statement, "rb").read() if a.statement else None
            reg = register(cose, a.ledger, a.issuer_pubkey, pl)
            rc = receipt(a.ledger, reg["index"], a.ts_key, a.ts_iss)
            ts = transparent_statement(cose, [rc])
            with open(a.out, "wb") as f:
                f.write(ts)
            print(json.dumps({"stato": "OK", **reg, "transparent_bytes": len(ts)})); return 0
        with open(a.transparent, "rb") as f:
            ts = f.read()
        pl = open(a.statement, "rb").read() if a.statement else None
        res = verify_transparent_statement(ts, a.issuer_pubkey, a.ts_pubkey, pl, a.ts_iss)
        print(json.dumps(res, ensure_ascii=False)); return 0 if res["ok"] else 1
    except (ScittError, OSError, ValueError) as e:
        print(json.dumps({"stato": "ERRORE", "motivo": str(e)}, ensure_ascii=False)); return 2


if __name__ == "__main__":
    sys.exit(main())
