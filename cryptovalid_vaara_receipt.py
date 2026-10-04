# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Roberto Locatelli
"""The Vaara Receipt (draft-sirkkavaara-vaara-receipt-12) — a verifier written from the draft, not from any
implementation (2026-10-03, vector exchange of the IETF AUDIT BoF preparation).

  §2    every digest and signed payload is over JCS (RFC 8785); digests are "sha256:" + lowercase hex; the
        evidenceRef canonicalization labels "jcs-rfc8785", "JCS", "jcs-json-v1" MUST all be accepted.
  §3    envelope: version 1; alg ES256 (64-byte r||s, RFC 7518), RS256 (RSASSA-PKCS1-v1_5/SHA-256), HS256 (HMAC-SHA-256,
        verified with the shared secret) or ML-DSA-65 (FIPS 204); signature lowercase hex of the raw bytes.
  §3.1  signed payload = JCS of EXACTLY (version, alg, backLink, decisionDerived, issuerAsserted) for a decision receipt,
        (version, alg, backLink, outcomeDerived, receiptAsserted) for an execution receipt; signature and
        timestampAnchors are outside it.
  §3.2  outcomeDerived.status "executed" | "refused"; a refused outcome carries no resultCommitment; projectionDigest =
        "sha256:" of the UTF-8 bytes of projection; projection is the JCS of the runtime result or the JCS of
        {"digest": "sha256:" of the JCS result}. backLink.attestationDigest = "sha256:" JCS(predecessor) and
        attestationNonce = predecessor.issuerAsserted.nonce.
  §4    evidenceRef.digest = "sha256:" JCS(evidence record); ref is advisory and is never used to resolve.
  §5    each timestamp anchor's anchoredDigest = "sha256:" JCS(signed payload). The token itself is method-specific and
        is NOT verified here (stated in the result).
Keys are the relying party's (a PEM, a JWK, a raw ML-DSA-65 key, or the HS256 secret); nothing inside a receipt is
trusted to name its own key. Every check that cannot run (no predecessor, no result, no evidence given) is reported
as None, never as True.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
from typing import Any, Dict, Optional

from cryptovalid_acta import jcs

KINDS = {"decision": ("decisionDerived", "issuerAsserted"), "execution": ("outcomeDerived", "receiptAsserted")}
ALGS = ("ES256", "RS256", "HS256", "ML-DSA-65")
CANONICALIZATIONS = ("jcs-rfc8785", "JCS", "jcs-json-v1")


def sha256_jcs(obj: Any) -> str:
    return "sha256:" + hashlib.sha256(jcs(obj)).hexdigest()


def _b64u(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def load_key(alg: str, key):
    """PEM (bytes/str), JWK dict (EC P-256, RSA, AKP ML-DSA-65), raw ML-DSA-65 bytes, or the HS256 secret (bytes)."""
    from cryptography.hazmat.primitives import serialization as ser
    from cryptography.hazmat.primitives.asymmetric import ec, rsa
    if alg == "HS256":
        # a PEM public key is public: used as an HMAC secret it lets anyone who holds it forge an HS256 receipt whose
        # alg field they chose themselves (algorithm confusion, measured 2026-10-04 with the ES256 key of the test
        # suite as the relying party's key) — a key that looks like a PEM or a JWK is never a shared secret
        if not isinstance(key, (bytes, bytearray)) or not key or bytes(key).lstrip().startswith(b"-----BEGIN"):
            raise ValueError("HS256 needs the shared secret as bytes (a PEM public key is not a secret)")
        return bytes(key)
    if isinstance(key, dict):
        if alg == "ES256" and key.get("kty") == "EC" and key.get("crv") == "P-256":
            return ec.EllipticCurvePublicNumbers(int.from_bytes(_b64u(key["x"]), "big"), int.from_bytes(_b64u(key["y"]), "big"),
                                                 ec.SECP256R1()).public_key()
        if alg == "RS256" and key.get("kty") == "RSA":
            return rsa.RSAPublicNumbers(int.from_bytes(_b64u(key["e"]), "big"), int.from_bytes(_b64u(key["n"]), "big")).public_key()
        if alg == "ML-DSA-65" and key.get("kty") == "AKP" and key.get("alg") == "ML-DSA-65":
            return _b64u(key["pub"])
        raise ValueError(f"JWK does not fit alg {alg}")
    if alg == "ML-DSA-65":
        return bytes(key)
    return ser.load_pem_public_key(key.encode("ascii") if isinstance(key, str) else bytes(key))


def verify_signature(alg: str, key, payload: bytes, sig_hex: str) -> bool:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, padding
    from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
    if not isinstance(sig_hex, str) or not sig_hex or sig_hex != sig_hex.lower():
        return False
    try:
        sig = bytes.fromhex(sig_hex)
        k = load_key(alg, key)
        if alg == "HS256":
            return hmac.compare_digest(hmac.new(k, payload, hashlib.sha256).digest(), sig)
        if alg == "ES256":
            if len(sig) != 64:           # r||s of RFC 7518; a non-EC key raises TypeError below: False
                return False
            k.verify(encode_dss_signature(int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big")), payload,
                     ec.ECDSA(hashes.SHA256()))
            return True
        if alg == "RS256":
            k.verify(sig, payload, padding.PKCS1v15(), hashes.SHA256())   # a non-RSA key raises TypeError: False
            return True
        if alg == "ML-DSA-65":
            from cryptography.hazmat.primitives.asymmetric import mldsa
            mldsa.MLDSA65PublicKey.from_public_bytes(k).verify(sig, payload)
            return True
    except (InvalidSignature, ValueError, TypeError, KeyError):
        return False
    return False


def receipt_kind(r: Dict[str, Any]) -> Optional[str]:
    have = [k for k, (d, a) in KINDS.items() if d in r and a in r]
    other = [k for k, (d, a) in KINDS.items() if d in r or a in r]
    return have[0] if len(have) == 1 and len(other) == 1 else None


def signed_payload(r: Dict[str, Any]) -> bytes:
    kind = receipt_kind(r)
    if kind is None:
        raise ValueError("not exactly one receipt kind (decision: decisionDerived+issuerAsserted; execution: "
                         "outcomeDerived+receiptAsserted)")
    names = ("version", "alg", "backLink") + KINDS[kind]
    missing = [n for n in names if n not in r]
    if missing:
        raise ValueError(f"signed members missing: {missing}")
    return jcs({n: r[n] for n in names})


def _commitment_ok(od: Dict[str, Any], result: Any) -> Optional[bool]:
    rc = od.get("resultCommitment")
    if not isinstance(rc, dict) or set(rc) != {"projection", "projectionDigest"} or not isinstance(rc["projection"], str):
        return False
    if rc["projectionDigest"] != "sha256:" + hashlib.sha256(rc["projection"].encode("utf-8")).hexdigest():
        return False
    if result is None:
        return None                                   # the commitment is self-consistent; the binding is not checked
    by_value = jcs(result).decode("utf-8")
    by_digest = jcs({"digest": sha256_jcs(result)}).decode("utf-8")
    return rc["projection"] in (by_value, by_digest)


def verify_receipt(r: Any, key, *, alg: str, predecessor: Any = None, runtime_result: Any = None,
                   evidence: Any = None) -> Dict[str, Any]:
    """{ok, signature_ok, back_link_ok, result_commitment_ok, evidence_ok, anchors_ok, why}; a check that cannot run
    is None. ok = signature_ok and no check that ran is False. `alg` is REQUIRED: the algorithm the relying party
    expects for `key`. A receipt that names another is refused before any signature check — the receipt never chooses
    how its own key is used (algorithm confusion: an HS256 receipt keyed with a PUBLIC key, PEM or raw, is forgeable
    by anyone who holds that key; measured 2026-10-04 with PEM, DER and raw ML-DSA-65 keys)."""
    out = {"ok": False, "kind": None, "signature_ok": False, "back_link_ok": None, "result_commitment_ok": None,
           "evidence_ok": None, "anchors_ok": None, "anchor_tokens_verified": False, "why": None}
    try:
        if not isinstance(r, dict):
            raise ValueError("receipt is not an object")
        if type(r.get("version")) is not int or r["version"] != 1:     # the integer 1: not true, not 1.0
            raise ValueError("version is not the integer 1")
        if r.get("alg") not in ALGS:
            raise ValueError(f"alg {r.get('alg')!r} not one of {ALGS}")
        if alg not in ALGS:
            raise ValueError(f"expected alg {alg!r} not one of {ALGS}")
        if r["alg"] != alg:
            raise ValueError(f"alg {r['alg']!r} is not the expected {alg!r}")
        payload = signed_payload(r)
        kind = out["kind"] = receipt_kind(r)
        out["signature_ok"] = verify_signature(r["alg"], key, payload, r.get("signature"))
        bl = r["backLink"]
        if not isinstance(bl, dict) or not isinstance(bl.get("attestationDigest"), str):
            raise ValueError("backLink must carry attestationDigest")
        if predecessor is not None:
            ia = predecessor.get("issuerAsserted") if isinstance(predecessor, dict) else None
            out["back_link_ok"] = (bl["attestationDigest"] == sha256_jcs(predecessor) and isinstance(ia, dict)
                                   and bl.get("attestationNonce") == ia.get("nonce"))
        if kind == "execution":
            od = r["outcomeDerived"]
            if not isinstance(od, dict) or od.get("status") not in ("executed", "refused"):
                raise ValueError('outcomeDerived.status must be "executed" or "refused"')
            if od["status"] == "refused":
                if "resultCommitment" in od:
                    raise ValueError("a refused outcome carries no resultCommitment (§3.2)")
            else:
                out["result_commitment_ok"] = _commitment_ok(od, runtime_result)
        else:
            er = r["decisionDerived"].get("evidenceRef") if isinstance(r["decisionDerived"], dict) else None
            if er is not None:
                if not isinstance(er, dict) or er.get("canonicalization") not in CANONICALIZATIONS:
                    raise ValueError("evidenceRef.canonicalization is not jcs-rfc8785 / JCS / jcs-json-v1")
                if evidence is not None:
                    out["evidence_ok"] = er.get("digest") == sha256_jcs(evidence)
        anchors = r.get("timestampAnchors")
        if anchors is not None:
            want = "sha256:" + hashlib.sha256(payload).hexdigest()
            out["anchors_ok"] = isinstance(anchors, list) and all(isinstance(a, dict) and a.get("anchoredDigest") == want
                                                                  for a in anchors)
        ran = [out[k] for k in ("back_link_ok", "result_commitment_ok", "evidence_ok", "anchors_ok") if out[k] is not None]
        out["ok"] = bool(out["signature_ok"]) and all(ran)
        out["why"] = "verified" if out["ok"] else "a check failed: " + ", ".join(
            k for k in ("signature_ok", "back_link_ok", "result_commitment_ok", "evidence_ok", "anchors_ok") if out[k] is False)
        return out
    except Exception as e:  # noqa: BLE001 — hostile input is a verdict
        out["why"] = f"{type(e).__name__}: {e}"[:300]
        return out
