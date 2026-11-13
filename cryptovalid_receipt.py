#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Roberto Locatelli
"""
CryptoValid Open Core — portable RECEIPTS for ledger entries (RFC 9942 semantics, RFC 6962/9162 proofs).

Status: EXPERIMENTAL. Outside the maintained core of cryptovalid-opencore (README, "Core and experimental
modules"): kept, installed and tested, no new scope is added here.

What a receipt is (2026-09-13, after comparing with Sigstore Rekor, immudb, Azure Confidential Ledger and
the IETF SCITT architecture): a small, self-contained proof that ONE entry is included in the ledger at a
given tree head — signed by the LOG KEY — that a relying party verifies OFFLINE without the ledger.
Two proof types, both from RFC 6962 / RFC 9162 (SHA-256 profile):

  * inclusion receipt   — leaf index, tree size, audit path, root; signed tree head (STH) over the root;
  * consistency receipt — tree size 1 → tree size 2, consistency path, both roots; proves the ledger only
                          GREW (append-only, no fork, no rewrite): the "non-equivocation" a monitor needs.

Two encodings of the same content:
  * JSON profile (this project's canonical form, `kind: cryptovalid_receipt/1`), human-readable;
  * COSE_Sign1 (RFC 9052) per RFC 9942 "COSE Receipts": header `vds`=1 (RFC9162_SHA256), `vdp` map with
    inclusion proof (label -1) / consistency proof (label -2), payload = tree root, alg EdDSA (-8).
    A minimal CBOR encoder/decoder is included (stdlib only) for exactly the types used here.

Honest scope: the STH is signed with the ledger's Ed25519 log key (signer.py keyfile or a KMS backend).
That proves "this root was published by whoever holds the log key" — NOT a qualified electronic seal nor
a qualified timestamp (eIDAS): add `tsa` (RFC 3161) via cryptovalid_tsa and, for qualified evidence, a
QTSP. IANA labels checked on the live COSE registries on 2026-09-13: receipts=394, vds=395, vdp=396; VDS 1 =
RFC9162_SHA256 with inclusion proofs at -1 and consistency proofs at -2, each an array of bstr.
"""
from __future__ import annotations
import sys as _sys_0203
if __name__ == "__main__":   # 0.20.3: run as a command, never write the bytecode cache: CPython 3.9 and 3.11 write
    _sys_0203.dont_write_bytecode = True   # a .pyc with one raw write; cut by a file size limit, every later run died (13/10/2026)
    _L0210 = type(__loader__)   # 0.21.0: a .pyc already cut (CPython 3.9/3.11 installed one) is compiled from the source
    if _L0210.__name__ == "SourceFileLoader":   # instead of failing every later run (EOFError: marshal data too short)
        def _get_code_0210(self, fullname, _get_code=_L0210.get_code):
            try:
                return _get_code(self, fullname)
            except (EOFError, ValueError):
                path = self.get_filename(fullname)
                return self.source_to_code(self.get_data(path), path)
        _L0210.get_code = _get_code_0210
import base64
import hashlib
import json
import os
import sys
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import cryptovalid_merkle as M  # noqa: E402

KIND = "cryptovalid_receipt/1"
VDS_RFC9162_SHA256 = 1          # COSE Verifiable Data Structure Algorithms registry: RFC9162_SHA256
LABEL_RECEIPTS, LABEL_VDS, LABEL_VDP = 394, 395, 396
PROOF_INCLUSION, PROOF_CONSISTENCY = -1, -2
COSE_ALG_EDDSA = -8


# ── minimal CBOR (RFC 8949) for: unsigned/negative ints, bytes, text, arrays, maps, bool/null ────
def cbor_encode(x: Any) -> bytes:
    def head(major: int, n: int) -> bytes:
        if n < 24:
            return bytes([(major << 5) | n])
        if n < 0x100:
            return bytes([(major << 5) | 24, n])
        if n < 0x10000:
            return bytes([(major << 5) | 25]) + n.to_bytes(2, "big")
        if n < 0x100000000:
            return bytes([(major << 5) | 26]) + n.to_bytes(4, "big")
        return bytes([(major << 5) | 27]) + n.to_bytes(8, "big")
    if x is True:
        return b"\xf5"
    if x is False:
        return b"\xf4"
    if x is None:
        return b"\xf6"
    if isinstance(x, int):
        return head(0, x) if x >= 0 else head(1, -1 - x)
    if isinstance(x, bytes):
        return head(2, len(x)) + x
    if isinstance(x, str):
        b = x.encode("utf-8")
        return head(3, len(b)) + b
    if isinstance(x, (list, tuple)):
        return head(4, len(x)) + b"".join(cbor_encode(i) for i in x)
    if isinstance(x, dict):
        # deterministic encoding (RFC 8949 §4.2): keys sorted by their encoded form
        items = sorted(((cbor_encode(k), cbor_encode(v)) for k, v in x.items()), key=lambda kv: kv[0])
        return head(5, len(items)) + b"".join(k + v for k, v in items)
    raise TypeError(f"CBOR: tipo non supportato {type(x).__name__}")


CBOR_MAX_DEPTH = 64


def cbor_decode(b: bytes) -> Any:
    def rd(i: int, depth: int = 0):
        if depth > CBOR_MAX_DEPTH:
            raise ValueError("CBOR: annidamento oltre il limite")
        ib = b[i]
        major, info = ib >> 5, ib & 0x1f
        i += 1
        if major == 7 and info in (20, 21, 22):          # false / true / null (simple values)
            return {20: False, 21: True, 22: None}[info], i
        if info < 24:
            n = info
        elif info == 24:
            n = b[i]; i += 1
        elif info == 25:
            n = int.from_bytes(b[i:i + 2], "big"); i += 2
        elif info == 26:
            n = int.from_bytes(b[i:i + 4], "big"); i += 4
        elif info == 27:
            n = int.from_bytes(b[i:i + 8], "big"); i += 8
        else:
            raise ValueError("CBOR: forma indefinita non supportata")
        if major == 0:
            return n, i
        if major == 1:
            return -1 - n, i
        if major == 2:
            return b[i:i + n], i + n
        if major == 3:
            return b[i:i + n].decode("utf-8"), i + n
        if major == 4:
            out = []
            for _ in range(n):
                v, i = rd(i, depth + 1)
                out.append(v)
            return out, i
        if major == 5:
            out = {}
            for _ in range(n):
                k, i = rd(i, depth + 1)
                v, i = rd(i, depth + 1)
                # chiavi ammesse da QUESTO decoder: int, str, bytes. bool/None sono rifiutati esplicitamente (in
                # Python 1 == True e collidono in una mappa: darebbero un «duplicato» spurio); array/mappe come
                # chiavi non sono hashabili qui.
                if isinstance(k, bool) or k is None or not isinstance(k, (int, str, bytes)):
                    raise ValueError("CBOR: chiave di mappa non ammessa da questo decoder (ammesse: int, str, bytes)")
                if k in out:
                    raise ValueError("CBOR: chiave duplicata (RFC 8949 §5.6)")
                out[k] = v
            return out, i
        raise ValueError(f"CBOR: major type {major} non supportato")
    v, end = rd(0)
    if end != len(b):
        raise ValueError("CBOR: byte in eccesso")
    return v


# ── log key (Ed25519, same keyfile format as signer.py) ──────────────────────────────────────
def _ed():
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
    return Ed25519PrivateKey, Ed25519PublicKey, serialization


def _order_problem(pub: bytes, sig: bytes):
    """0.22.0 (NEMESIS 19/10/2026): keys of small or mixed order and R of small order are refused here too, by the rule the
    ledger verifiers apply since 0.21.0 (ed25519_order). Until then the neutral point, with R neutral and S = 0, was
    `signature_valid: true` for ANY tree head (JSON `cryptovalid_sth/1`) and `ok: true` for any COSE receipt under that
    key — `cryptography` accepts it. None when the key and R are usable."""
    try:
        import ed25519_order as _o
    except ImportError:   # python3 -m opencore.<module> from the parent directory
        from opencore import ed25519_order as _o
    return _o.strict_problem(pub, sig)   # a key or a signature of another length: key_not_decodable / r_not_decodable


def _load_sk(keyfile: str):
    Ed25519PrivateKey, _, ser = _ed()
    with open(keyfile, encoding="utf-8") as f:
        sk = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(f.read().strip()))
    pk = sk.public_key().public_bytes(ser.Encoding.Raw, ser.PublicFormat.Raw).hex()
    return sk, pk


def _sth_payload(tree_size: int, root_hex: str, ts: str) -> bytes:
    return json.dumps({"kind": "cryptovalid_sth/1", "root_sha256": root_hex, "tree_size": tree_size, "ts": ts},
                      sort_keys=True, separators=(",", ":")).encode()


def signed_tree_head(leaves: List[bytes], keyfile: str) -> Dict:
    """Tree head REALLY signed (until 2026-09-13 `cryptovalid_merkle.signed_tree_head` returned an unsigned
    root: a misnomer, now renamed there). Signature: Ed25519 over the canonical STH payload."""
    sk, pk = _load_sk(keyfile)
    ts = datetime.now(timezone.utc).isoformat(timespec="seconds")
    root = M.mth(leaves).hex()
    sig = sk.sign(_sth_payload(len(leaves), root, ts))
    return {"kind": "cryptovalid_sth/1", "tree_size": len(leaves), "root_sha256": root, "ts": ts,
            "signature_hex": sig.hex(), "log_pubkey_hex": pk}


def verify_sth(sth: Dict, trusted_pubkey_hex: Optional[str] = None) -> Dict:
    """The STH signature is checked against the TRUSTED log key given by the relying party (the key
    inside the STH is informative only — trusting it would let anyone forge a tree head)."""
    _, Ed25519PublicKey, _ = _ed()
    if sth.get("kind") != "cryptovalid_sth/1":     # the signed payload fixes this kind: a head that declares another is not ours
        return {"ok": False, "why": f"unsupported tree head kind {sth.get('kind')!r}"}
    pk = trusted_pubkey_hex or sth.get("log_pubkey_hex")
    if not trusted_pubkey_hex:
        note = "log key taken from the receipt itself: NOT trusted (pass trusted_pubkey_hex)"
    elif trusted_pubkey_hex != sth.get("log_pubkey_hex"):
        return {"ok": False, "why": "receipt log key differs from the trusted log key"}
    else:
        note = "signature verified against the trusted log key"
    try:
        why = _order_problem(bytes.fromhex(pk), bytes.fromhex(sth["signature_hex"]))
        if why is not None:
            return {"ok": False, "signature_valid": False, "why": f"STH signature invalid: {why}"}
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(pk)).verify(
            bytes.fromhex(sth["signature_hex"]), _sth_payload(sth["tree_size"], sth["root_sha256"], sth["ts"]))
        return {"ok": bool(trusted_pubkey_hex), "signature_valid": True, "why": note}
    except Exception:  # noqa: BLE001
        return {"ok": False, "signature_valid": False, "why": "STH signature invalid"}


# ── receipts ───────────────────────────────────────────────────────────────────────────────
def inclusion_receipt(ledger_path: str, index: int, keyfile: str, tsa_url: Optional[str] = None, tsa_certs=None) -> Dict:
    leaves = M.leaves_from_ledger(ledger_path)
    if not (0 <= index < len(leaves)):
        raise IndexError(f"index {index} fuori dal ledger ({len(leaves)} entry)")
    sth = signed_tree_head(leaves, keyfile)
    path = [h.hex() for h in M.inclusion_proof(index, leaves)]
    with open(ledger_path, encoding="utf-8") as f:
        entry = [json.loads(l) for l in f if l.strip()][index]
    r = {"kind": KIND, "proof_type": "inclusion", "vds": "RFC9162_SHA256",
         "leaf_index": index, "tree_size": len(leaves), "inclusion_path": path,
         "leaf_sha256": M.leaf_hash(leaves[index]).hex(), "entry_self_hash": entry.get("self_hash"),
         "sth": sth, "issued": sth["ts"],
         "scope": ("proves the entry's canonical form is a leaf of the tree whose root the log key signed; "
                   "not a qualified seal nor a qualified timestamp")}
    if tsa_url:
        r["tsa"] = _stamp(sth["root_sha256"], tsa_url, tsa_certs)
    return r


def consistency_receipt(old_sth: Dict, ledger_path: str, keyfile: str) -> Dict:
    leaves = M.leaves_from_ledger(ledger_path)
    n1, n2 = int(old_sth["tree_size"]), len(leaves)
    if n1 == 0:
        return {"kind": KIND, "proof_type": "consistency", "ok": False, "tree_size_1": 0, "tree_size_2": n2,
                "why": "old tree empty: nothing to prove (RFC 9162 defines no consistency from size 0) — use an inclusion receipt"}
    if n2 < n1:
        return {"kind": KIND, "proof_type": "consistency", "ok": False,
                "why": f"ledger SHRANK: {n1} → {n2} (truncation)", "tree_size_1": n1, "tree_size_2": n2}
    sth = signed_tree_head(leaves, keyfile)
    path = [h.hex() for h in M.consistency_proof(n1, leaves)] if 0 < n1 < n2 else []
    return {"kind": KIND, "proof_type": "consistency", "vds": "RFC9162_SHA256",
            "tree_size_1": n1, "tree_size_2": n2, "root_1": old_sth["root_sha256"], "root_2": sth["root_sha256"],
            "consistency_path": path, "sth": sth, "issued": sth["ts"]}


def verify_receipt(r: Dict, trusted_pubkey_hex: str, leaf_canonical: Optional[bytes] = None,
                   trusted_root_1_hex: Optional[str] = None) -> Dict:
    """Offline verification, fail-closed (council 14/09):
    Inclusion: `leaf_canonical` (the relying party's OWN entry, canonical bytes) is REQUIRED — a receipt only
    proves the inclusion of the leaf you hand it, never of a leaf it names itself; `tree_size` must equal the
    signed STH size (a forged size with a reused path is refused); root recomputed from leaf + path.
    Consistency: `trusted_root_1_hex` (the relying party's OWN previous root) is REQUIRED; `tree_size_2` must
    equal the signed STH size; the path must connect trusted root_1 to the signed root_2."""
    if not trusted_pubkey_hex:
        return {"ok": False, "why": "trusted_pubkey_hex is required: the key inside a receipt is never trusted"}
    if not isinstance(r, dict) or r.get("kind") != KIND:   # a list/number/null is not a receipt (audit V1 #7, 30/09/2026)
        return {"ok": False, "why": "not a cryptovalid receipt"}
    if r.get("ok") is not False and r.get("vds") != "RFC9162_SHA256":    # as the COSE path: an unknown or absent VDS is refused,
        return {"ok": False, "why": f"unsupported vds {r.get('vds')!r}"}  # never verified as if it were RFC9162_SHA256
    sth = r.get("sth") or {}
    if not isinstance(sth, dict):
        return {"ok": False, "why": "STH: not a JSON object"}
    s = verify_sth(sth, trusted_pubkey_hex)
    if not s.get("ok"):
        return {"ok": False, "why": f"STH: {s.get('why')}"}
    try:
        if r["proof_type"] == "inclusion":
            if leaf_canonical is None:
                return {"ok": False, "why": "leaf_canonical is required: pass YOUR entry, the receipt must not choose the leaf"}
            if int(r["tree_size"]) != int(sth["tree_size"]):
                return {"ok": False, "why": "tree_size of the proof differs from the signed tree head"}
            path = [bytes.fromhex(h) for h in r["inclusion_path"]]
            leaf = M.leaf_hash(leaf_canonical)
            if leaf.hex() != r["leaf_sha256"]:
                return {"ok": False, "why": "leaf hash does not match the given entry"}
            root = bytes.fromhex(sth["root_sha256"])
            ok = _verify_inclusion_from_leaf_hash(r["leaf_index"], r["tree_size"], leaf, path, root)
            return {"ok": ok, "why": "inclusion proof valid against the signed root" if ok else "inclusion proof INVALID",
                    "tree_size": r["tree_size"], "leaf_index": r["leaf_index"]}
        if r["proof_type"] == "consistency":
            if r.get("ok") is False:
                return {"ok": False, "why": r.get("why")}
            n1, n2 = int(r["tree_size_1"]), int(r["tree_size_2"])
            if not trusted_root_1_hex:
                return {"ok": False, "why": "trusted_root_1_hex is required: pass YOUR previous root, not the receipt's"}
            if r["root_1"].lower() != trusted_root_1_hex.lower():
                return {"ok": False, "why": "root_1 in the receipt differs from your trusted previous root"}
            if sth["root_sha256"] != r["root_2"] or n2 != int(sth["tree_size"]):
                return {"ok": False, "why": "root_2 / tree_size_2 differ from the signed tree head"}
            if n1 == 0:
                return {"ok": False, "why": "old tree empty: nothing to prove — use an inclusion receipt"}
            if n1 == n2:
                ok = r["root_1"] == r["root_2"]
                return {"ok": ok, "why": "same size: roots must be equal" + ("" if ok else " — they are NOT (rewrite)")}
            path = [bytes.fromhex(h) for h in r["consistency_path"]]
            ok = M.verify_consistency(n1, n2, path, bytes.fromhex(r["root_1"]), bytes.fromhex(r["root_2"]))
            return {"ok": ok, "why": "consistency proof valid (append-only growth)" if ok else "consistency proof INVALID (fork or rewrite)"}
        return {"ok": False, "why": "unknown proof_type"}
    except (KeyError, ValueError, TypeError) as e:
        return {"ok": False, "why": f"malformed receipt: {type(e).__name__}"}


def _verify_inclusion_from_leaf_hash(m: int, n: int, leaf: bytes, proof: List[bytes], root: bytes) -> bool:
    """RFC 9162 §2.1.3.2 with the LEAF HASH as input (cryptovalid_merkle.verify_inclusion takes leaf data)."""
    if m >= n or (n > 0 and m < 0):
        return False
    fn, sn, r = m, n - 1, leaf
    for p in proof:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            r = M.node_hash(p, r)
            while not (fn & 1) and fn != 0:
                fn >>= 1
                sn >>= 1
            fn >>= 1
            sn >>= 1
        else:
            r = M.node_hash(r, p)
            fn >>= 1
            sn >>= 1
    return sn == 0 and r == root


def consistency_roots(m: int, n: int, proof: List[bytes], old_root: bytes):
    """RFC 9162 §2.1.4.2: from a consistency path and the OLD root, recompute (old_root', new_root).
    Returns None if the path is malformed. Used to rebuild the DETACHED payload of a consistency receipt."""
    if m == n:
        return (old_root, old_root) if not proof else None
    if m <= 0 or m > n:
        return None
    path = ([old_root] + list(proof)) if (m & (m - 1)) == 0 else list(proof)
    if not path:
        return None
    fn, sn = m - 1, n - 1
    while fn & 1:
        fn >>= 1
        sn >>= 1
    fr = sr = path[0]
    for c in path[1:]:
        if sn == 0:
            return None
        if fn & 1 or fn == sn:
            fr = M.node_hash(c, fr)
            sr = M.node_hash(c, sr)
            while not (fn & 1) and fn != 0:
                fn >>= 1
                sn >>= 1
        else:
            sr = M.node_hash(sr, c)
        fn >>= 1
        sn >>= 1
    return (fr, sr) if sn == 0 else None


def _stamp(digest_hex: str, tsa_url: str, tsa_certs=None) -> Dict:
    """RFC 3161 token over the signed root, checked by SPEC §11 (v0.6). `anchored` is true only for a token `verified`
    against `tsa_certs` (the TSA certificates the caller pins); a token whose signature verifies only with the certificate
    it carries is kept (`token_b64`, `status: signature_only`) and is not anchored. Until 0.22.0 `anchored` was the
    presence of the digest's bytes anywhere in the token (a CMS blob signed with any key was anchored: measured
    2026-11-13)."""
    try:
        import cryptovalid_tsa as T
        granted, tok, raw = T.request_timestamp(bytes.fromhex(digest_hex), tsa_url)
        if not granted or not tok:
            return {"anchored": False, "note": "TSA did not grant the timestamp"}
        chk = T.verify_token(tok, bytes.fromhex(digest_hex), "sha256", tsa_certs)
        r = {"anchored": chk["status"] == "verified", "tsa": tsa_url, "status": chk["status"],
             "imprint_ok": chk["imprint_ok"], "gen_time": (chk["tst_info"] or {}).get("gen_time"),
             "signer_sha256": chk["signer_sha256"],
             "note": {"verified": "RFC 3161 token over the signed root, verified against the pinned TSA certificate; "
                                  "qualified only if the TSA is a QTSP",
                      "signature_only": "RFC 3161 token over the signed root: " + T.SIGNATURE_ONLY_NOTE + " (pin the TSA "
                                        "certificate to anchor it); qualified only if the TSA is a QTSP",
                      "not_evaluated": "RFC 3161 token over the signed root: signature not checked, openssl absent",
                      "invalid": f"the TSA's token does not pass SPEC §11: {chk['reason']}"}[chk["status"]]}
        if chk["status"] != "invalid":
            r["token_b64"] = base64.b64encode(tok).decode()
        return r
    except Exception as e:  # noqa: BLE001
        if type(e).__name__ == "CheckNotRun":   # openssl cannot be run here (0.20.3): exit 74, not "not anchored"
            raise
        return {"anchored": False, "note": f"{type(e).__name__}: {str(e)[:80]}"}


# ── COSE_Sign1 (RFC 9052) per RFC 9942 ────────────────────────────────────────────────────
def _sig_structure(protected: bytes, payload: bytes) -> bytes:
    return cbor_encode(["Signature1", protected, b"", payload])


def to_cose(r: Dict, keyfile: str) -> bytes:
    """COSE Receipt: protected {alg: EdDSA, vds: 1, kid: log key}; unprotected {vdp: {-1: [ts, idx, path]}}
    or {-2: [ts1, ts2, path]}; payload = tree root (bytes); signature Ed25519 over Sig_structure."""
    sk, pk = _load_sk(keyfile)
    # RFC 9942 §5.2/5.3 (IANA, checked 2026-09-13): each proof type is an ARRAY OF BSTR, every bstr being the
    # CBOR encoding of the proof structure [tree-size, leaf-index, inclusion-path] / [size-1, size-2, path]
    if r["proof_type"] == "inclusion":
        proof = {PROOF_INCLUSION: [cbor_encode([r["tree_size"], r["leaf_index"], [bytes.fromhex(h) for h in r["inclusion_path"]]])]}
        payload = bytes.fromhex(r["sth"]["root_sha256"])
    else:
        if r.get("ok") is False or "consistency_path" not in r:
            raise ValueError("cannot encode a failed/incomplete consistency receipt as COSE")
        # RFC 9942: for consistency proofs the newer root is a DETACHED payload — the verifier MUST recompute it
        # from its own trusted root_1 and the path (council 14/09: it was attached and never recomputed)
        proof = {PROOF_CONSISTENCY: [cbor_encode([r["tree_size_1"], r["tree_size_2"], [bytes.fromhex(h) for h in r["consistency_path"]]])]}
        payload = bytes.fromhex(r["root_2"])
        protected = cbor_encode({1: COSE_ALG_EDDSA, LABEL_VDS: VDS_RFC9162_SHA256, 4: bytes.fromhex(pk)})
        sig = sk.sign(_sig_structure(protected, payload))
        return b"\xd2" + cbor_encode([protected, {LABEL_VDP: proof}, None, sig])   # payload nil = detached
    protected = cbor_encode({1: COSE_ALG_EDDSA, LABEL_VDS: VDS_RFC9162_SHA256, 4: bytes.fromhex(pk)})
    sig = sk.sign(_sig_structure(protected, payload))
    return b"\xd2" + cbor_encode([protected, {LABEL_VDP: proof}, payload, sig])     # tag 18 = COSE_Sign1


# RFC 9052 §3.1 "crit": the labels an application "is required to understand"; at least one value; a label listed and not in
# the protected bucket is "a fatal error". Understood = its value is compared, validated or returned by the verifier that
# calls, so each verifier has its own list: seen as present only (x5chain 33, x5t 34, and kid 4 where the trusted key decides)
# is not understood, and neither is a label that verifier never reads. cryptovalid_cose_receipts keeps its lists per profile.
COSE_CRIT_STATEMENT = frozenset({1, 3, 15})          # verify_signed_statement: alg, content type (returned), CWT Claims
COSE_CRIT_SCITT_RECEIPT = frozenset({1, 4, 15, 395})  # the receipts of verify_transparent_statement: alg, kid, CWT Claims, vds
COSE_CRIT_RECEIPT = frozenset({1, 4, 395})           # verify_cose: alg, kid, vds


def cose_crit_problem(protected: Dict, unprotected: Dict, understood: frozenset) -> Optional[str]:
    """None, or why the `crit` header parameter (label 2) makes this COSE_Sign1 one these verifiers must not accept."""
    if 2 in unprotected:
        return "crit_unprotected"
    if 2 not in protected:
        return None
    crit = protected[2]
    if (not isinstance(crit, list) or not crit
            or not all(isinstance(x, str) or (isinstance(x, int) and not isinstance(x, bool)) for x in crit)):
        return "crit_malformed"
    if any(x not in protected for x in crit):
        return "crit_label_not_in_protected"
    if any(x not in understood for x in crit):
        return "crit_unsupported"
    return None


def verify_cose(cose: bytes, trusted_pubkey_hex: str, leaf_hash_hex: Optional[str] = None,
                trusted_root_1_hex: Optional[str] = None) -> Dict:
    _, Ed25519PublicKey, _ = _ed()
    try:
        if cose[:1] != b"\xd2":
            return {"ok": False, "why": "not a tagged COSE_Sign1 (tag 18)"}
        protected, unprotected, payload, sig = cbor_decode(cose[1:])
        ph = cbor_decode(protected)
        crit = cose_crit_problem(ph, unprotected, COSE_CRIT_RECEIPT)
        if crit:
            return {"ok": False, "why": crit}
        if ph.get(1) != COSE_ALG_EDDSA or ph.get(LABEL_VDS) != VDS_RFC9162_SHA256:
            return {"ok": False, "why": "unsupported alg/vds"}
        if ph.get(4) != bytes.fromhex(trusted_pubkey_hex):
            return {"ok": False, "why": "kid differs from the trusted log key"}
        pk = Ed25519PublicKey.from_public_bytes(bytes.fromhex(trusted_pubkey_hex))
        why = _order_problem(bytes.fromhex(trusted_pubkey_hex), sig if isinstance(sig, bytes) else b"")
        if why is not None:   # 0.22.0: small/mixed-order log key or small-order R (NEMESIS 19/10/2026)
            return {"ok": False, "why": f"signature invalid: {why}"}
        vdp = unprotected.get(LABEL_VDP) or {}          # proofs live in the UNPROTECTED header (RFC 9942): not signed
        if PROOF_INCLUSION in vdp:
            if payload is None:
                return {"ok": False, "why": "inclusion receipt with detached payload not supported by this verifier"}
            pk.verify(sig, _sig_structure(protected, payload))
            ts, idx, path = cbor_decode(vdp[PROOF_INCLUSION][0])
            if not (type(ts) is int and type(idx) is int and ts >= 0 and idx >= 0 and isinstance(path, list)):
                return {"ok": False, "why": "malformed inclusion proof: tree-size and leaf-index are uint (RFC 9942)"}   # audit V1 #9
            if leaf_hash_hex is None:
                return {"ok": False, "why": "inclusion receipt: pass leaf_hash_hex (YOUR entry's leaf hash)"}
            ok = _verify_inclusion_from_leaf_hash(idx, ts, bytes.fromhex(leaf_hash_hex), list(path), payload)
            return {"ok": ok, "proof": "inclusion", "tree_size_from_unsigned_proof": ts, "leaf_index_from_unsigned_proof": idx,
                    "signed_root": payload.hex(),
                    "why": "signature valid and the proof rebuilds the signed root" if ok else "inclusion proof INVALID"}
        if PROOF_CONSISTENCY in vdp:
            n1, n2, path = cbor_decode(vdp[PROOF_CONSISTENCY][0])
            if not trusted_root_1_hex:
                return {"ok": False, "why": "consistency receipt: pass trusted_root_1_hex (YOUR previous root)"}
            roots = consistency_roots(int(n1), int(n2), list(path), bytes.fromhex(trusted_root_1_hex))
            if roots is None or roots[0].hex() != trusted_root_1_hex.lower():
                return {"ok": False, "why": "consistency path does not connect your trusted root_1"}
            new_root = roots[1] if payload is None else payload
            if payload is not None and payload != roots[1]:
                return {"ok": False, "why": "attached payload differs from the recomputed root_2"}
            pk.verify(sig, _sig_structure(protected, new_root))      # detached: the payload is the RECOMPUTED root
            return {"ok": True, "proof": "consistency", "sizes_from_unsigned_proof": [n1, n2], "root_2": new_root.hex(),
                    "why": "signature valid over the root_2 recomputed from your root_1 and the path (append-only growth)"}
        return {"ok": False, "why": "no proof in vdp"}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "why": f"{type(e).__name__}"}


# ── CLI ────────────────────────────────────────────────────────────────────────────────────


try:   # 0.20.3: the one writer of every command (verifier.py): an outcome is written whole, or exit 74
    from verifier import Parser, emit, receipt_cli, say, write_output
except ImportError:   # python3 -m opencore.<module> from the parent directory
    from opencore.verifier import Parser, emit, receipt_cli, say, write_output


@receipt_cli
def main(argv: Optional[List[str]] = None) -> int:
    import argparse
    try:
        import cryptovalid_tsa as _T_arg
    except ImportError:   # python3 -m opencore.<module>
        from opencore import cryptovalid_tsa as _T_arg
    p = Parser(prog="cryptovalid_receipt", description="RFC 9942-style receipts for a cryptovalid ledger")
    sub = p.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("sth"); a.add_argument("ledger"); a.add_argument("keyfile")
    b = sub.add_parser("inclusion"); b.add_argument("ledger"); b.add_argument("index", type=int); b.add_argument("keyfile")
    b.add_argument("--tsa"); b.add_argument("--cose", help="write the COSE_Sign1 bytes to this file")
    b.add_argument("--tsa-cert", action="append", default=None, metavar="PEM", type=_T_arg.tsa_cert_arg,
                   help="pin the TSA certificate (or a CA above it), repeatable: `tsa.anchored` needs it (SPEC §11)")
    c = sub.add_parser("consistency"); c.add_argument("old_sth_json"); c.add_argument("ledger"); c.add_argument("keyfile")
    v = sub.add_parser("verify"); v.add_argument("receipt_json"); v.add_argument("trusted_pubkey_hex")
    v.add_argument("--entry-json", help="inclusion: file with YOUR entry (JSON object)"); v.add_argument("--trusted-root-1", help="consistency: YOUR previous root (hex)")
    args = p.parse_args(argv)
    if args.cmd == "sth":
        emit(json.dumps(signed_tree_head(M.leaves_from_ledger(args.ledger), args.keyfile), indent=1)); return 0
    if args.cmd == "inclusion":
        r = inclusion_receipt(args.ledger, args.index, args.keyfile, args.tsa, args.tsa_cert)
        if args.cose:
            write_output(args.cose, to_cose(r, args.keyfile))   # 0.20.3: whole, or exit 74
        emit(json.dumps(r, indent=1)); return 0
    if args.cmd == "consistency":
        with open(args.old_sth_json, encoding="utf-8") as f:
            old = json.load(f)
        r = consistency_receipt(old.get("sth", old), args.ledger, args.keyfile)
        emit(json.dumps(r, indent=1)); return 0 if r.get("ok", True) else 1
    def _load(path, what):   # unreadable / not JSON / not an object: a verdict, never a traceback (audit V1 #7)
        try:
            with open(path, encoding="utf-8") as f:
                obj = json.load(f)
        except (OSError, ValueError, RecursionError) as e:
            return None, f"{what} unreadable: {type(e).__name__}"
        return (obj, None) if isinstance(obj, dict) else (None, f"{what} is not a JSON object")
    rcpt, why = _load(args.receipt_json, "receipt")
    if why:
        emit(json.dumps({"ok": False, "why": why}, indent=1)); return 1
    leaf = None
    if args.entry_json:
        entry, why = _load(args.entry_json, "entry")
        if why:
            emit(json.dumps({"ok": False, "why": why}, indent=1)); return 1
        leaf = M.canonical(entry)
    res = verify_receipt(rcpt, args.trusted_pubkey_hex, leaf_canonical=leaf, trusted_root_1_hex=args.trusted_root_1)
    emit(json.dumps(res, indent=1)); return 0 if res["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
