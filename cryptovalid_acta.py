#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""cryptovalid-opencore — Signed Decision Receipts, draft-farley-acta-signed-receipts-03 (0.15.0, 2026-09-20).

draft-farley-acta-signed-receipts-03 (T. Farley, ScopeBlind / Veritas Acta, 29 August 2026, expires 2 March 2027;
individual Internet-Draft, Informational — copy downloaded 2026-09-20): a portable, signed receipt of a machine-to-machine
access-control decision (an AI agent calling a tool). What this module implements, transcribed from the draft:

  §2.1   envelope shape {payload, signature{alg, kid, sig}}; the flat shape (payload fields at the top level, signature a hex
         string) is READ, never emitted (§6.6: new implementations SHOULD emit the envelope).
  §2.2   payload members: type, issued_at (RFC 3339 with zone), issuer_id (MUST equal signature.kid), previousReceiptHash
         (inside the payload, omitted — not null — on a genesis), payload_digest, action_ref, ...
  §3.1   protectmcp:decision: tool_name, decision ∈ {allow, deny, rate_limit, require_approval}, reason, policy_digest, session_id.
  §5/§6.6 signing input = JCS(payload) (RFC 8785, ES6 numbers), PureEdDSA over the canonical bytes — no pre-hash; sig hex.
  §6.7   previousReceiptHash = "sha256:" + hex(SHA-256(JCS(receipt))) over the ENTIRE signed receipt including the signature
         member; a bare hex digest MAY be accepted on read, is never emitted; an unknown prefix is refused.
  §6.8   policy_digest = "sha256:" + hex(SHA-256(JCS({construction: "acta-policy-digest-v1", engine, files: [{name, sha256}]
         sorted by name}))) — every file hashed over its exact bytes; recomputed by the verifier from the policy bytes.
  §6.9   alg agility: "EdDSA" (MTI), "ML-DSA-65" (FIPS 204) and "ES256" are read against the declared alg; only EdDSA is emitted.
  §2.1.1 kid RECOMMENDED "sb:issuer:" + first 12 characters of the Base58 (Bitcoin alphabet) encoding of the Ed25519 key.

Measured on 2026-09-20 against ScopeBlind/agent-governance-testvectors v0.3 (commit 49ad7c1): the fixture policy digest
(sha256:81ba074a…) is reproduced from the .cedar bytes; the decisions come from the official Cedar bindings (cedarpy 4.12,
the cedar-policy Rust crate), never from the fixtures' expected_decision; the receipts pass the repository's three checks
(JSON schema, @veritasacta/verify 0.10.18 signatures, chain/outcomes) — see `run-vectors`. Declared (the draft does not say):
ES256 is read as IEEE P1363 r||s, 64 bytes, hex, low-S only (the (r, n−s) twin would verify and change the §6.7 hash);
ML-DSA-65 is read as pure ML-DSA with the EMPTY context over the same canonical bytes (raw 3309-byte signature, hex,
verified through `cryptography` ≥ 48 — not measured against another implementation: the public vectors are Ed25519 only);
a flat receipt without `alg` is read as EdDSA (the MTI) and one without `kid` takes its `issuer_id` as the kid (an envelope re-emitted
flat, or the reverse, verifies with a different §6.7 hash — inherent to the draft's two shapes, caught by the chain link);
an earlier-revision `policy_digest` (16 hex, no prefix) is an opaque label the signature check tolerates and the policy
binding refuses (§6.8 compatibility note); a receipt signed under an algorithm this host cannot verify is a
problem, never a pass; the chain check does not know whether a receipt without previousReceiptHash is a genesis or
unchained (§2.2 says the format does not distinguish).
"""
from __future__ import annotations
import argparse
import base64
import hashlib
import json
import os
import re
import sys
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

DRAFT = "draft-farley-acta-signed-receipts-03 (2026-08-29, expires 2027-03-02; individual Internet-Draft)"
DECISIONS = ("allow", "deny", "rate_limit", "require_approval")
ALGS = ("EdDSA", "ML-DSA-65", "ES256")
_RFC3339 = re.compile(r"^\d{4}-\d{2}-\d{2}[Tt]\d{2}:\d{2}:\d{2}(\.\d+)?([Zz]|[+-]\d{2}:\d{2})\Z")
_HEX = re.compile(r"^[0-9a-f]+\Z")
_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
JCS_MAX_DEPTH = 512


# ── RFC 8785 JCS (same rules as omega-evidence's, self-contained) ────────────────────────────
def _es6_number(f: float) -> str:
    if f == 0:
        return "0"
    sign = "-" if f < 0 else ""
    r = repr(abs(f))
    if "e" in r:
        mant, exp = r.split("e")
        exp = int(exp)
    else:
        mant, exp = r, 0
    ip, fp = (mant.split(".") + [""])[:2]
    fp = fp.rstrip("0") if fp != "0" else ""
    if not ip.lstrip("0"):
        digits = fp.lstrip("0")
        n = exp - (len(fp) - len(fp.lstrip("0")))
    else:
        digits = (ip + fp).lstrip("0")
        n = len(ip.lstrip("0")) + exp
    digits = digits.rstrip("0") or "0"
    k = len(digits)
    if k <= n <= 21:
        out = digits + "0" * (n - k)
    elif 0 < n <= 21:
        out = digits[:n] + "." + digits[n:]
    elif -6 < n <= 0:
        out = "0." + "0" * (-n) + digits
    else:
        e = n - 1
        out = (digits[0] + ("." + digits[1:] if k > 1 else "")) + "e" + ("+" if e >= 0 else "-") + str(abs(e))
    return sign + out


def jcs(obj: Any) -> bytes:
    """RFC 8785: keys sorted by UTF-16 code units, no whitespace, JSON.stringify escapes, ES6 numbers; NaN/Infinity,
    integers beyond the double range, non-string keys and nesting deeper than 512 are refused (ValueError/TypeError)."""
    def enc(x: Any, depth: int = 0) -> str:
        if depth > JCS_MAX_DEPTH:
            raise ValueError("JCS: nesting deeper than 512 refused")
        if x is None:
            return "null"
        if x is True:
            return "true"
        if x is False:
            return "false"
        if isinstance(x, int):
            if abs(x) > 2 ** 53:
                try:
                    return _es6_number(float(x))
                except OverflowError:
                    raise ValueError("JCS: integer beyond the double range") from None
            return str(x)
        if isinstance(x, float):
            if x != x or x in (float("inf"), float("-inf")):
                raise ValueError("JCS: NaN/Infinity are not JSON")
            return _es6_number(x)
        if isinstance(x, str):
            return json.dumps(x, ensure_ascii=False)
        if isinstance(x, (list, tuple)):
            parts = []
            for i in x:
                parts.append(enc(i, depth + 1))
            return "[" + ",".join(parts) + "]"
        if isinstance(x, dict):
            if not all(isinstance(k, str) for k in x):
                raise TypeError("JCS: object keys must be strings")
            parts = []
            for k in sorted(x.keys(), key=lambda k: k.encode("utf-16-be")):
                parts.append(json.dumps(k, ensure_ascii=False) + ":" + enc(x[k], depth + 1))
            return "{" + ",".join(parts) + "}"
        raise TypeError(f"JCS: unsupported type {type(x).__name__}")
    try:
        return enc(obj).encode("utf-8")
    except UnicodeEncodeError:
        raise ValueError("JCS: lone surrogate is not encodable as UTF-8") from None


def _valid_instant(t: str) -> bool:
    """RFC 3339 form AND a real calendar instant (month/day/hour/minute/second, offset < 24:00 / 60); a leap second (:60)
    is accepted as the form allows it."""
    m = re.match(r"^(\d{4})-(\d{2})-(\d{2})[Tt](\d{2}):(\d{2}):(\d{2})(\.\d+)?(?:[Zz]|([+-])(\d{2}):(\d{2}))\Z", t)
    if not m:
        return False
    y, mo, d, h, mi, se = (int(m.group(i)) for i in range(1, 7))
    if se > 60:
        return False
    try:
        datetime(y, mo, d, h, mi, 59 if se == 60 else se)
    except ValueError:
        return False
    if m.group(9) is not None and (int(m.group(9)) > 23 or int(m.group(10)) > 59):
        return False
    return True


# ── keys, kids, digests ──────────────────────────────────────────────────────────────────────
def base58(b: bytes) -> str:
    n = int.from_bytes(b, "big")
    out = ""
    while n:
        n, r = divmod(n, 58)
        out = _B58[r] + out
    return "1" * (len(b) - len(b.lstrip(b"\x00"))) + out


def issuer_kid(pub: bytes) -> str:
    """§2.1.1 RECOMMENDED kid: sb:issuer:<first 12 Base58 characters of the Ed25519 public key>."""
    if len(pub) != 32:
        raise ValueError("Ed25519 public key is 32 bytes")
    return "sb:issuer:" + base58(pub)[:12]


def policy_digest(files: Dict[str, bytes], engine: str = "cedar") -> str:
    """§6.8 acta-policy-digest-v1 over the exact bytes of every policy file, sorted by name (code point order)."""
    if not files:
        raise ValueError("a policy digest needs at least one file")
    m = {"construction": "acta-policy-digest-v1", "engine": engine,
         "files": [{"name": n, "sha256": hashlib.sha256(files[n]).hexdigest()} for n in sorted(files)]}
    return "sha256:" + hashlib.sha256(jcs(m)).hexdigest()


def policy_digest_from_dir(path: str, engine: str = "cedar", ext: str = ".cedar") -> str:
    files = {}
    for n in os.listdir(path):
        if n.endswith(ext):
            with open(os.path.join(path, n), "rb") as f:
                files[n] = f.read()
    return policy_digest(files, engine)


def receipt_hash(receipt: Dict[str, Any]) -> str:
    """§6.7: "sha256:" + hex(SHA-256(JCS(entire signed receipt)))."""
    return "sha256:" + hashlib.sha256(jcs(receipt)).hexdigest()


P256_ORDER = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551


def _unsupported():
    try:
        from cryptography.exceptions import UnsupportedAlgorithm
        return UnsupportedAlgorithm
    except ImportError:
        return ImportError


def _ed():
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
    return Ed25519PrivateKey, Ed25519PublicKey, serialization


def pubkey_from_seed(seed_hex: str) -> bytes:
    Ed25519PrivateKey, _, ser = _ed()
    sk = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(seed_hex))
    return sk.public_key().public_bytes(ser.Encoding.Raw, ser.PublicFormat.Raw)


# ── build and sign ───────────────────────────────────────────────────────────────────────────
def decision_payload(tool_name: str, decision: str, issuer_id: str, issued_at: Optional[str] = None,
                     policy_digest_value: Optional[str] = None, session_id: Optional[str] = None, reason: Optional[str] = None,
                     previous: Optional[Dict[str, Any]] = None, extra: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """§3.1 protectmcp:decision payload. `previous` = the preceding SIGNED receipt (its §6.7 hash becomes
    previousReceiptHash); a genesis omits the member. `extra` members (e.g. sequence, tool_input digest) are added as given."""
    if decision not in DECISIONS:
        raise ValueError(f"decision must be one of {DECISIONS}")
    if not isinstance(tool_name, str) or not tool_name:
        raise ValueError("tool_name must be a non-empty string")
    if issued_at:
        ts = issued_at
    else:
        now = datetime.now(timezone.utc)
        ts = now.strftime("%Y-%m-%dT%H:%M:%S.") + f"{now.microsecond // 1000:03d}Z"
    if not _valid_instant(ts):
        raise ValueError("issued_at must be an RFC 3339 instant with a zone designator")
    p: Dict[str, Any] = {"type": "protectmcp:decision", "tool_name": tool_name, "decision": decision,
                         "issued_at": ts, "issuer_id": issuer_id}
    if policy_digest_value is not None:
        if not re.match(r"^sha256:[0-9a-f]{64}\Z", policy_digest_value):
            raise ValueError("policy_digest must be sha256:<64 lowercase hex> (§6.8)")
        p["policy_digest"] = policy_digest_value
    if session_id is not None:
        p["session_id"] = session_id
    if reason is not None:
        p["reason"] = reason
    if previous is not None:
        if _shape(previous)[0] == "invalid":
            raise ValueError("previous must be a SIGNED receipt (the §6.7 pre-image includes its signature)")
        p["previousReceiptHash"] = receipt_hash(previous)
    for k, v in (extra or {}).items():
        if k in p:
            raise ValueError(f"extra member {k!r} would overwrite a draft member")
        p[k] = v
    return p


def sign_receipt(payload: Dict[str, Any], seed_hex: str, kid: Optional[str] = None) -> Dict[str, Any]:
    """§5.1 with EdDSA: PureEd25519 over JCS(payload); sig lowercase hex; kid defaults to the §2.1.1 form and MUST equal
    payload.issuer_id (checked here: a receipt whose issuer_id is not its kid is not signed)."""
    Ed25519PrivateKey, _, ser = _ed()
    sk = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(seed_hex))
    pub = sk.public_key().public_bytes(ser.Encoding.Raw, ser.PublicFormat.Raw)
    kid = kid or issuer_kid(pub)
    if payload.get("issuer_id") != kid:
        raise ValueError("payload.issuer_id MUST equal signature.kid (§2.2)")
    if "signature" in payload:
        raise ValueError("the signing input never contains a signature member (§6.6)")
    sig = sk.sign(jcs(payload))
    return {"payload": payload, "signature": {"alg": "EdDSA", "kid": kid, "sig": sig.hex()}}


# ── verify ───────────────────────────────────────────────────────────────────────────────────
def _shape(receipt: Any) -> Tuple[str, Optional[Dict[str, Any]], Optional[Dict[str, Any]], str]:
    """(shape, signing-input object, signature object {alg, kid, sig}, why). §6.6: envelope = exactly {payload, signature{}}."""
    if not isinstance(receipt, dict):
        return "invalid", None, None, "receipt is not a JSON object"
    if isinstance(receipt.get("signature"), dict) and isinstance(receipt.get("payload"), dict):
        if set(receipt) != {"payload", "signature"}:
            return "invalid", None, None, "envelope receipt must carry exactly payload and signature (§6.6)"
        s = receipt["signature"]
        if set(s) != {"alg", "kid", "sig"}:
            return "invalid", None, None, "signature object must carry exactly alg, kid and sig (§2.1.1/§6.6)"
        if "signature" in receipt["payload"]:
            return "invalid", None, None, "payload contains a signature member (§6.6 MUST NOT)"
        return "envelope", receipt["payload"], {"alg": s.get("alg"), "kid": s.get("kid"), "sig": s.get("sig")}, ""
    if isinstance(receipt.get("signature"), str):
        body = {k: v for k, v in receipt.items() if k != "signature"}
        return "flat", body, {"alg": receipt.get("alg", "EdDSA"), "kid": receipt.get("kid", receipt.get("issuer_id")),
                              "sig": receipt["signature"]}, ""
    return "invalid", None, None, "no signature member in either shape (§6.6)"


def verify_receipt(receipt: Any, keys: Dict[str, Any]) -> Dict[str, Any]:
    """`keys` = {kid: public key} — 32 raw Ed25519 bytes or 64-hex str for EdDSA, 1952 raw bytes or a base64 str for ML-DSA-65,
    P-256 SubjectPublicKeyInfo PEM bytes for ES256. Keys come from the relying party, never from the receipt (§9.5).
    Returns {ok, shape, alg, kid, why, hash}."""
    shape, body, sig, why = _shape(receipt)
    out: Dict[str, Any] = {"ok": False, "shape": shape, "alg": None, "kid": None, "why": why, "hash": None, "notes": []}
    if shape == "invalid":
        return out
    alg, kid, sigv = sig["alg"], sig["kid"], sig["sig"]
    out.update({"alg": alg, "kid": kid})
    try:
        whole = jcs(receipt)                          # the entire receipt must canonicalize: it is the §6.7 pre-image
        msg = jcs(body)
    except (ValueError, TypeError) as ex:
        out["why"] = f"receipt not canonicalizable (§6.7): {ex}"; return out
    if alg not in ALGS:
        out["why"] = f"alg {alg!r} not in {ALGS} (§6.9): not verifiable here, never a pass"; return out
    if not isinstance(kid, str) or not kid:
        out["why"] = "kid missing"; return out
    if body.get("issuer_id") != kid:                  # both shapes: attribution is issuer_id, resolution is kid — they MUST agree
        out["why"] = "payload.issuer_id != signature.kid (§2.2 MUST)"; return out
    if not isinstance(sigv, str) or not _HEX.match(sigv) or len(sigv) % 2:
        out["why"] = "sig is not lowercase hex"; return out
    if not isinstance(body.get("issued_at"), str) or not _valid_instant(body["issued_at"]):
        out["why"] = "issued_at is not an RFC 3339 instant with a zone (§2.2)"; return out
    if not isinstance(body.get("type"), str) or not body["type"]:
        out["why"] = "type missing (§2.2)"; return out
    if body.get("type") == "protectmcp:decision":
        if body.get("decision") not in DECISIONS:
            out["why"] = f"decision not in {DECISIONS} (§3.1)"; return out
        if not isinstance(body.get("tool_name"), str) or not body["tool_name"]:
            out["why"] = "tool_name missing (§3.1)"; return out
    if "previousReceiptHash" in body:
        v = body["previousReceiptHash"]
        if not isinstance(v, str) or not v:
            out["why"] = "previousReceiptHash is not a non-empty string (§2.2: omit it on a genesis, never null or empty)"; return out
        if ":" in v and not v.startswith("sha256:"):
            out["why"] = f"previousReceiptHash names an algorithm this verifier does not implement: {v.split(':')[0]!r} (§6.7)"; return out
        if not re.match(r"^(sha256:)?[0-9a-f]{64}\Z", v):
            out["why"] = "previousReceiptHash is not sha256:<64 lowercase hex> (§6.7)"; return out
    if "policy_digest" in body and not (isinstance(body["policy_digest"], str) and re.match(r"^sha256:[0-9a-f]{64}\Z", body["policy_digest"])):
        # §6.8 compatibility note: an earlier-revision digest (16 hex, no prefix) is an opaque LABEL, not a commitment —
        # the signature is still checked; the chain's policy binding refuses to bind on it
        out["notes"].append("policy_digest is not an acta-policy-digest-v1 commitment (sha256:<64 hex>): an opaque label, not recomputable (§6.8)")
    key = keys.get(kid)
    if key is None:
        out["why"] = f"no key for kid {kid!r} (keys come from the relying party, §9.5)"; return out
    raw = bytes.fromhex(sigv)
    try:
        if alg == "EdDSA":
            _, Ed25519PublicKey, _ = _ed()
            pk = bytes.fromhex(key) if isinstance(key, str) else bytes(key)
            if len(pk) != 32 or len(raw) != 64:
                out["why"] = "EdDSA needs a 32-byte key and a 64-byte signature"; return out
            Ed25519PublicKey.from_public_bytes(pk).verify(raw, msg)
        elif alg == "ML-DSA-65":
            try:
                from cryptography.hazmat.primitives.asymmetric import mldsa
            except ImportError:
                out["why"] = "ML-DSA-65 not verifiable on this host (cryptography >= 48): NOT verified"; return out
            pk = base64.b64decode(key, validate=True) if isinstance(key, str) else bytes(key)
            if len(pk) != 1952 or len(raw) != 3309:
                out["why"] = "ML-DSA-65 needs a 1952-byte key and a 3309-byte signature"; return out
            mldsa.MLDSA65PublicKey.from_public_bytes(pk).verify(raw, msg)
        else:  # ES256 — the draft names the algorithm but not the signature encoding: IEEE P1363 r||s is read (declared)
            from cryptography.hazmat.primitives import hashes, serialization
            from cryptography.hazmat.primitives.asymmetric import ec
            from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
            pk = serialization.load_pem_public_key(key if isinstance(key, bytes) else str(key).encode())
            if not isinstance(pk, ec.EllipticCurvePublicKey) or pk.curve.name != "secp256r1" or len(raw) != 64:
                out["why"] = "ES256 needs a P-256 key and a 64-byte r||s signature (encoding declared, not in the draft)"; return out
            s_int = int.from_bytes(raw[32:], "big")
            if s_int == 0 or s_int > P256_ORDER // 2:   # (r, n−s) verifies too and would change the §6.7 hash: only low-S is a receipt
                out["why"] = "ES256 signature is not low-S canonical (malleable twin would change the receipt hash, §6.7)"; return out
            pk.verify(encode_dss_signature(int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big")), msg, ec.ECDSA(hashes.SHA256()))
    except ImportError:
        out["why"] = "cryptography not installed: NOT verified"; return out
    except _unsupported() as ex:
        out["why"] = f"{alg} not verifiable on this host ({ex}): NOT verified"; return out
    except Exception as ex:  # noqa: BLE001 — any failure is one verdict
        out["why"] = f"signature invalid ({type(ex).__name__})"; return out
    out.update({"ok": True, "why": "ok", "hash": "sha256:" + hashlib.sha256(whole).hexdigest()})    # §6.7 pre-image: the whole receipt, both shapes
    return out


def verify_chain(receipts: List[Any], keys: Dict[str, Any], policy_files: Optional[Dict[str, bytes]] = None,
                 engine: str = "cedar") -> Dict[str, Any]:
    """Every receipt verified (§5.2); §6.7 links: receipt i's previousReceiptHash == hash of receipt i-1; a genesis omits
    it; a bare-hex link is accepted on read and reported; policy_digest recomputed from `policy_files` when given."""
    problems: List[Dict[str, Any]] = []
    warnings: List[Dict[str, Any]] = []
    if not isinstance(receipts, list) or not receipts:
        return {"ok": False, "problems": [{"i": -1, "why": "no receipts"}], "warnings": [], "verified": 0, "draft": DRAFT}
    expected_pd = policy_digest(policy_files, engine) if policy_files is not None else None      # {} raises: no policy is not a policy
    ok_n = 0
    prev: Optional[Dict[str, Any]] = None
    for i, r in enumerate(receipts):
        v = verify_receipt(r, keys)
        if not v["ok"]:
            problems.append({"i": i, "why": v["why"]})
        else:
            ok_n += 1
        _sh, body, _sig, _why = _shape(r)                  # ONE shape decision (§6.6): the same members verify_receipt signed over
        body = body if body is not None else {}
        link = body.get("previousReceiptHash")
        if i == 0:
            if "previousReceiptHash" in body:
                warnings.append({"i": i, "why": "first receipt carries previousReceiptHash: a segment of a longer chain, its first link is not checkable here (§2.2)"})
        else:
            if link is None:
                problems.append({"i": i, "why": "no previousReceiptHash: the receipt is not linked to the preceding one (§6.7)"})
            elif prev is None:
                problems.append({"i": i, "why": "previous receipt did not verify: the link cannot be checked (§6.7)"})
            elif v["shape"] != "invalid":
                exp = receipt_hash(prev)
                if link == exp:
                    pass
                elif isinstance(link, str) and link == exp.split(":", 1)[1]:
                    warnings.append({"i": i, "why": "previousReceiptHash is a bare hex digest (earlier revisions): accepted on read, never emitted (§6.7)"})
                else:
                    problems.append({"i": i, "why": "previousReceiptHash does not match SHA-256(JCS(previous signed receipt)) (§6.7)"})
        if v["ok"] and v["notes"]:
            warnings.append({"i": i, "why": v["notes"][0]})
        if expected_pd is not None:
            if "policy_digest" not in body:
                problems.append({"i": i, "why": "policy binding requested but the receipt carries no policy_digest (§6.8)"})
            elif v["notes"]:
                problems.append({"i": i, "why": "policy binding requested but the receipt's policy_digest is an opaque label, not a recomputable commitment (§6.8)"})
            elif body["policy_digest"] != expected_pd:
                problems.append({"i": i, "why": f"policy_digest {body['policy_digest']!r} != recomputed {expected_pd!r} from the policy bytes (§6.8)"})
        prev = r if v["ok"] else None
    return {"ok": not problems, "problems": problems, "warnings": warnings, "verified": ok_n, "receipts": len(receipts), "draft": DRAFT,
            "scope": "signatures against the relying party's keys, §6.7 links, §6.8 policy digest when the policy bytes are given: integrity "
                     "and attribution only — a chain truncated at its end is undetectable without an external commitment to its head (§9.7), "
                     "the first receipt may be a genesis or a segment, and whether the policy is the one in force is a separate check"}


# ── Cedar evaluation (official bindings) and the test-vectors driver ─────────────────────────
def evaluate_cedar(policy_text: str, tool_name: str, context: Dict[str, Any], principal: str = 'Agent::"agent"',
                   resource: str = 'Tool::"tool"') -> Tuple[str, List[str]]:
    """Decision from the official Cedar bindings (cedarpy, the cedar-policy Rust crate); never a guess. Returns
    (allow|deny, matched policy ids)."""
    import cedarpy  # optional dependency: pip install cedarpy
    if not isinstance(tool_name, str) or not tool_name or any(c in tool_name for c in '"\\') or not tool_name.isprintable():
        raise ValueError("tool_name cannot be placed in a Cedar entity literal (quote, backslash or non-printable): refused")
    req = {"principal": principal, "action": f'Action::"{tool_name}"', "resource": resource, "context": context or {}}
    res = cedarpy.is_authorized(req, policy_text, [])
    decision = "allow" if str(res.decision).endswith("Allow") else "deny"
    reasons = [str(x) for x in getattr(res.diagnostics, "reasons", [])]
    return decision, reasons


def run_vectors(repo_root: str, out_dir: str, seed_hex: str, issued_at_base: Optional[str] = None) -> Dict[str, Any]:
    """Driver for ScopeBlind/agent-governance-testvectors: fixtures/inputs/*.json evaluated against fixtures/policy/*.cedar
    with cedarpy, one envelope receipt per input written to out_dir/receipt-NNNN.json, chained per §6.7, policy_digest per
    §6.8. The fixtures' expected_decision is NOT read (a driver that copied it would prove nothing)."""
    inputs_dir = os.path.join(repo_root, "fixtures", "inputs")
    policy_dir = os.path.join(repo_root, "fixtures", "policy")
    files = {}
    for n in sorted(os.listdir(policy_dir)):
        if n.endswith(".cedar"):
            with open(os.path.join(policy_dir, n), "rb") as f:
                files[n] = f.read()
    pd = policy_digest(files, "cedar")
    policy_text = "\n".join(f.decode("utf-8") for f in files.values())
    pub = pubkey_from_seed(seed_hex)
    kid = issuer_kid(pub)
    os.makedirs(out_dir, exist_ok=True)
    prev = None
    summary = {"kid": kid, "public_key_hex": pub.hex(), "policy_digest": pd, "receipts": []}
    inputs = sorted(f for f in os.listdir(inputs_dir) if f.endswith(".json"))
    for n, fname in enumerate(inputs, 1):
        with open(os.path.join(inputs_dir, fname), encoding="utf-8") as f:
            inp = json.load(f)
        seq = inp.get("sequence", n)
        if not isinstance(seq, int) or isinstance(seq, bool) or not 1 <= seq <= 999:
            raise ValueError(f"{fname}: sequence must be an integer in 1..999 (it becomes the millisecond of issued_at)")
        decision, reasons = evaluate_cedar(policy_text, inp["tool_name"], inp.get("context") or {})
        # issued_at: the run's UTC clock, or a fixed base (reproducible signatures across runs); the sequence is the millisecond
        if issued_at_base is not None and not (re.match(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\Z", issued_at_base) and _valid_instant(issued_at_base)):
            raise ValueError("issued_at_base must be a UTC instant of the form YYYY-MM-DDThh:mm:ssZ")
        base = issued_at_base[:19] if issued_at_base else datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")
        ts = f"{base}.{seq:03d}Z"
        extra = {"sequence": seq,
                 "payload_digest": {"hash": hashlib.sha256(jcs(inp.get("tool_input", {}))).hexdigest(), "size": len(jcs(inp.get("tool_input", {})))},
                 "reason": "policy:" + ",".join(reasons) if reasons else "policy:no-matching-policy"}
        payload = decision_payload(inp["tool_name"], decision, kid, issued_at=ts, policy_digest_value=pd,
                                   session_id=inp.get("session_id"), previous=prev, extra=extra)
        rec = sign_receipt(payload, seed_hex, kid)
        with open(os.path.join(out_dir, f"receipt-{seq:04d}.json"), "w", encoding="utf-8") as f:
            json.dump(rec, f, indent=2)
            f.write("\n")
        summary["receipts"].append({"file": f"receipt-{seq:04d}.json", "tool_name": inp["tool_name"], "decision": decision, "reasons": reasons,
                                    "hash": receipt_hash(rec)})
        prev = rec
    summary["jwks"] = {"keys": [{"kty": "OKP", "crv": "Ed25519", "kid": kid, "x": base64.urlsafe_b64encode(pub).rstrip(b"=").decode(), "use": "sig"}]}   # §5.3
    return summary


def _no_constant(name: str) -> Any:
    raise ValueError(f"{name} is not JSON")


def _no_dup_keys(pairs: List[Tuple[str, Any]]) -> Dict[str, Any]:
    d: Dict[str, Any] = {}
    for k, v in pairs:
        if k in d:
            raise ValueError(f"duplicate key {k!r} (RFC 8785 §3.1: names are unique)")
        d[k] = v
    return d


def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(prog="cryptovalid-acta", description=DRAFT)
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("sign", help="sign a protectmcp:decision receipt")
    s.add_argument("--key", required=True, help="Ed25519 seed file (hex) — the cryptovalid signer keyfile")
    s.add_argument("--tool", required=True); s.add_argument("--decision", required=True, choices=DECISIONS)
    s.add_argument("--policy-dir", help="directory of policy files: policy_digest per §6.8"); s.add_argument("--policy-ext", default=".cedar")
    s.add_argument("--session"); s.add_argument("--reason"); s.add_argument("--previous", help="preceding signed receipt (JSON file)")
    s.add_argument("--issued-at"); s.add_argument("--out", required=True)
    v = sub.add_parser("verify", help="verify one receipt or a chain (JSON files in order)")
    v.add_argument("files", nargs="+"); v.add_argument("--key", action="append", default=[], help="kid=<64 hex Ed25519 | file>")
    v.add_argument("--policy-dir"); v.add_argument("--policy-ext", default=".cedar")
    d = sub.add_parser("policy-digest"); d.add_argument("policy_dir"); d.add_argument("--engine", default="cedar"); d.add_argument("--ext", default=".cedar")
    r = sub.add_parser("run-vectors", help="drive ScopeBlind/agent-governance-testvectors")
    r.add_argument("repo_root"); r.add_argument("out_dir"); r.add_argument("--seed", required=True, help="64-hex Ed25519 seed"); r.add_argument("--issued-at-base")
    a = p.parse_args(argv)
    try:
        if a.cmd == "policy-digest":
            print(policy_digest_from_dir(a.policy_dir, a.engine, a.ext)); return 0
        if a.cmd == "sign":
            with open(a.key, encoding="utf-8") as f:
                seed = f.read().strip()
            pub = pubkey_from_seed(seed); kid = issuer_kid(pub)
            prev = None
            if a.previous:
                with open(a.previous, encoding="utf-8") as f:
                    prev = json.load(f, parse_constant=_no_constant, object_pairs_hook=_no_dup_keys)
            pd = policy_digest_from_dir(a.policy_dir, "cedar", a.policy_ext) if a.policy_dir else None
            rec = sign_receipt(decision_payload(a.tool, a.decision, kid, a.issued_at, pd, a.session, a.reason, prev), seed, kid)
            with open(a.out, "w", encoding="utf-8") as f:
                json.dump(rec, f, indent=2); f.write("\n")
            print(json.dumps({"ok": True, "kid": kid, "hash": receipt_hash(rec)})); return 0
        if a.cmd == "verify":
            keys: Dict[str, Any] = {}
            for spec in a.key:
                kid, val = spec.split("=", 1)
                if _HEX.match(val) and len(val) == 64:
                    keys[kid] = val
                else:
                    with open(val, "rb") as f:
                        data = f.read()
                    txt = data.decode("ascii", "replace").strip()
                    keys[kid] = txt if (_HEX.match(txt) and len(txt) == 64) else data       # a cryptovalid hex keyfile, or raw / PEM bytes
            recs = []
            for fn in a.files:
                with open(fn, encoding="utf-8") as f:
                    recs.append(json.load(f, parse_constant=_no_constant, object_pairs_hook=_no_dup_keys))
            files = None
            if a.policy_dir:
                files = {}
                for n in os.listdir(a.policy_dir):
                    if n.endswith(a.policy_ext):
                        with open(os.path.join(a.policy_dir, n), "rb") as f:
                            files[n] = f.read()
                if not files:
                    raise ValueError(f"--policy-dir {a.policy_dir} holds no {a.policy_ext} file: nothing to bind the receipts to")
            out = verify_chain(recs, keys, files) if len(recs) > 1 or a.policy_dir else verify_receipt(recs[0], keys)
            print(json.dumps(out, indent=1)); return 0 if out["ok"] else 1
        if a.cmd == "run-vectors":
            print(json.dumps(run_vectors(a.repo_root, a.out_dir, a.seed, a.issued_at_base), indent=1)); return 0
    except (OSError, ValueError, TypeError, KeyError, RecursionError, json.JSONDecodeError) as ex:
        print(json.dumps({"ok": False, "error": f"{type(ex).__name__}: {ex}"})); return 2
    except ImportError as ex:
        print(json.dumps({"ok": False, "error": f"dependency missing: {ex}"})); return 77
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
