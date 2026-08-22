#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CryptoValid Open Core — ap2-evidence-pack: dispute evidence for agentic-payment mandates.

SPDX-License-Identifier: AGPL-3.0-or-later
Copyright (C) 2026 Roberto Locatelli

WHY (measured, 2026-08-21): the AP2 spec (Agent Payments Protocol, ap2-protocol.org) tells
implementers WHAT to keep for dispute resolution — "storing the SD-JWTs, along with their
disclosures, for the Mandates in their compact serialization" — but not HOW: no retention
mechanics, no issuer-key snapshotting, no long-term validation, no tamper-evidence; mandate
retrieval is declared outside the scope. An ECDSA JWT is verifiable at dispute time ONLY if
the issuer's key material is still resolvable; years later JWKS endpoints die and keys rotate.

WHAT THIS IS (deliberately thin — an adversarial review killed the "full vault" idea):
a library + CLI that turns a set of AP2-style SD-JWT mandates into ONE self-contained
evidence file that verifies OFFLINE years later:
  - parses SD-JWT compact serialization (issuer-JWT ~ disclosure* ~ [kb-jwt]) and resolves
    selective disclosures fail-closed (unmatched/duplicate/malformed disclosure -> reject);
  - verifies the ES256 (ECDSA P-256) signature and SNAPSHOTS the key material used, tagging
    it with an explicit PROVENANCE CLASS instead of pretending all captures are equal:
      x5c_header          key from the JWT's x5c leaf cert (chain recorded, PKI path NOT
                          validated to a trust anchor here — declared)
      jwk_header          key embedded in the protected header (self-asserted)
      supplied            key material handed in by the caller (caller vouches)
      jwks_fetched        key fetched from an https JWKS URL at build time (TLS witness
                          at capture — a witness, not a proof of issuer control)
  - discovers hash BINDINGS between artifacts (e.g. a cart mandate committing to the
    checkout_jwt) by recomputing sha-256 over each artifact's exact compact serialization
    and matching it against every string claim of the others — the primary quantity,
    not a proxy field;
  - seals everything into a canonical JSON evidence file with a SHA-256 digest and an
    OPTIONAL RFC 3161 timestamp (reuses evidence_pack's TSA client/verifier), so the
    "key material existed and verified at time T" claim is anchored to a third party.

HONEST SCOPE: proves that these exact artifacts, with this key material, verified at
build time, and (if stamped) that all of it existed at the TSA's time — offline,
vendor-free, years later. It does NOT prove the issuer authorised the key (that is the
provenance class's job to DECLARE), does NOT confer eIDAS art. 45j qualified-archive legal
presumption (a QTSP service does), and does NOT validate x5c chains to a trust anchor.
ES256 only, by design; other algs are rejected loudly, never half-verified.

Usage:
  python3 ap2_evidence.py build out.json intent=intent.sdjwt cart=cart.sdjwt \
          [--key name=jwk.json] [--jwks-url name=https://...] [--tsa URL]
  python3 ap2_evidence.py verify out.json
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import sys
import urllib.request
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
import evidence_pack  # noqa: E402  (RFC 3161 stamp + cryptographic token verify)

EVIDENCE_FORMAT = "ap2-evidence-pack/1.0"

HONEST_SCOPE = (
    "Proves: these exact SD-JWT artifacts, with the snapshotted key material (see each "
    "key's provenance_class), verified at build time; the RFC 3161 token (if present) "
    "anchors their existence to the TSA's clock. Does NOT prove the issuer authorised "
    "the key beyond what the provenance class states, does NOT confer eIDAS qualified-"
    "archive legal presumption, does NOT validate x5c chains to a trust anchor, and "
    "never proves the truth of the recorded transaction itself. 'valid' means each "
    "artifact verifies and the file is intact — NOT that the mandates form a bound "
    "chain (read `bindings`) nor that self-asserted keys prove issuer identity (read "
    "`provenance_classes`/`self_asserted_only`). KB-JWT holder binding is verified "
    "when the issuer payload carries cnf.jwk; without cnf.jwk it is recorded as "
    "present-but-unverifiable, never painted green. KB-JWT aud/nonce/iat are RECORDED "
    "for the auditor, not validated — their expected values are transaction context "
    "this tool cannot know offline.")


class Ap2EvidenceError(ValueError):
    """Fail-closed parse/verify error (message is auditor-readable, never a traceback)."""


# ────────────────────────────────────────────────────────── b64url / hashing

def _b64url_decode(s: str) -> bytes:
    s = s.strip()
    pad = -len(s) % 4
    try:
        return base64.urlsafe_b64decode(s + "=" * pad)
    except Exception as e:  # noqa: BLE001
        raise Ap2EvidenceError(f"invalid base64url segment: {type(e).__name__}") from e


def _b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def _sha256_b64url(data: bytes) -> str:
    return _b64url(hashlib.sha256(data).digest())


def _canon(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


def _utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ────────────────────────────────────────────────────────── SD-JWT parsing

def parse_sd_jwt(compact: str) -> Dict:
    """Split an SD-JWT compact serialization: <jwt>~<disclosure>*~[<kb-jwt>].
    A trailing '~' means no key-binding JWT. Returns raw parts, decoded header/payload."""
    compact = compact.strip()
    if "~" in compact:
        parts = compact.split("~")
        jwt, middle, kb = parts[0], parts[1:-1], parts[-1] or None
    else:
        jwt, middle, kb = compact, [], None
    seg = jwt.split(".")
    if len(seg) != 3:
        raise Ap2EvidenceError("issuer JWT must have 3 dot-separated segments")
    try:
        header = json.loads(_b64url_decode(seg[0]))
        payload = json.loads(_b64url_decode(seg[1]))
    except (ValueError, Ap2EvidenceError) as e:
        raise Ap2EvidenceError(f"JWT header/payload not valid JSON/base64url: {e}") from e
    return {"compact": compact, "jwt": jwt, "header": header, "payload": payload,
            "signature": _b64url_decode(seg[2]),
            "signing_input": f"{seg[0]}.{seg[1]}".encode("ascii"),
            "disclosures": [d for d in middle if d], "kb_jwt": kb}


def _disclosure_digest(disclosure_b64: str) -> str:
    # SD-JWT: digest = b64url(sha-256(ASCII of the base64url-encoded disclosure))
    return _sha256_b64url(disclosure_b64.encode("ascii"))


def resolve_disclosures(payload: Dict, disclosures: List[str]) -> Dict:
    """Replace _sd digests / '...' array placeholders with the disclosed claims.
    Fail-closed: duplicate digests, malformed disclosures, or disclosures that match
    nothing are ERRORS (per SD-JWT processing rules), never silently ignored."""
    alg = payload.get("_sd_alg", "sha-256")
    if alg != "sha-256":
        raise Ap2EvidenceError(f"_sd_alg {alg!r} unsupported (sha-256 only, declared)")
    by_digest: Dict[str, Tuple[str, list]] = {}
    for d in disclosures:
        try:
            arr = json.loads(_b64url_decode(d))
        except (ValueError, Ap2EvidenceError) as e:
            raise Ap2EvidenceError(f"malformed disclosure: {e}") from e
        if not isinstance(arr, list) or len(arr) not in (2, 3):
            raise Ap2EvidenceError("disclosure must be [salt,name,value] or [salt,value]")
        dig = _disclosure_digest(d)
        if dig in by_digest:
            raise Ap2EvidenceError("duplicate disclosure digest (rejected fail-closed)")
        by_digest[dig] = (d, arr)
    used = set()

    def walk(node):
        if isinstance(node, dict):
            out = {}
            for k, v in node.items():
                if k in ("_sd", "_sd_alg"):
                    continue
                out[k] = walk(v)
            for dig in node.get("_sd", []):
                if dig in by_digest:
                    d, arr = by_digest[dig]
                    if len(arr) != 3:
                        raise Ap2EvidenceError("object disclosure must be [salt,name,value]")
                    if arr[1] in out:
                        raise Ap2EvidenceError(f"disclosed claim {arr[1]!r} collides")
                    out[arr[1]] = walk(arr[2])
                    used.add(dig)
            return out
        if isinstance(node, list):
            out_l = []
            for item in node:
                if isinstance(item, dict) and set(item.keys()) == {"..."}:
                    dig = item["..."]
                    if dig in by_digest:
                        d, arr = by_digest[dig]
                        if len(arr) != 2:
                            raise Ap2EvidenceError("array disclosure must be [salt,value]")
                        out_l.append(walk(arr[1]))
                        used.add(dig)
                    # undisclosed array element: omitted (that is selective disclosure)
                else:
                    out_l.append(walk(item))
            return out_l
        return node

    resolved = walk(payload)
    unused = set(by_digest) - used
    if unused:
        raise Ap2EvidenceError(f"{len(unused)} disclosure(s) match no digest in the "
                               "payload (rejected fail-closed)")
    return resolved


# ────────────────────────────────────────────────────────── ES256 verification

def _pubkey_from_jwk(jwk: Dict):
    from cryptography.hazmat.primitives.asymmetric import ec
    if jwk.get("kty") != "EC" or jwk.get("crv") != "P-256":
        raise Ap2EvidenceError("only EC/P-256 JWKs are supported (ES256, declared)")
    x = int.from_bytes(_b64url_decode(jwk["x"]), "big")
    y = int.from_bytes(_b64url_decode(jwk["y"]), "big")
    return ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key()


def _pubkey_from_x5c_leaf(x5c: List[str]):
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import ec
    leaf = x509.load_der_x509_certificate(base64.b64decode(x5c[0]))
    pub = leaf.public_key()
    if not isinstance(pub, ec.EllipticCurvePublicKey) or pub.curve.name != "secp256r1":
        raise Ap2EvidenceError("x5c leaf key is not EC P-256 (ES256 only, declared)")
    return pub


def _jwk_from_pubkey(pub) -> Dict:
    nums = pub.public_numbers()
    return {"kty": "EC", "crv": "P-256",
            "x": _b64url(nums.x.to_bytes(32, "big")),
            "y": _b64url(nums.y.to_bytes(32, "big"))}


def verify_es256(signing_input: bytes, signature: bytes, jwk: Dict) -> bool:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
    if len(signature) != 64:
        raise Ap2EvidenceError(f"ES256 signature must be 64 bytes, got {len(signature)}")
    r = int.from_bytes(signature[:32], "big")
    s = int.from_bytes(signature[32:], "big")
    try:
        _pubkey_from_jwk(jwk).verify(encode_dss_signature(r, s), signing_input,
                                     ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature:
        return False


def _snapshot_key(parsed: Dict, supplied_jwk: Optional[Dict] = None,
                  jwks_url: Optional[str] = None, timeout: int = 20) -> Dict:
    """Choose the verification key and record WHERE it came from (provenance class).
    Precedence: SUPPLIED key first (the caller's explicit trust decision MUST override
    self-asserted header material — otherwise a self-consistent forgery with an embedded
    jwk would outrank the genuine key an auditor provides; found by pro-level self-attack
    2026-08-21), then x5c header > jwk header > fetched JWKS. Fail-closed if none."""
    header = parsed["header"]
    if header.get("alg") != "ES256":
        raise Ap2EvidenceError(f"alg {header.get('alg')!r} unsupported: ES256 only "
                               "(other algs are rejected, never half-verified)")
    if supplied_jwk:
        return {"jwk": supplied_jwk, "provenance_class": "supplied",
                "note": "key material supplied by the caller (caller vouches); "
                        "overrides any self-asserted header key by design"}
    if header.get("x5c"):
        if not isinstance(header["x5c"], list) or len(header["x5c"]) > 10:
            raise Ap2EvidenceError("x5c chain absent or too long (>10 certs): refused "
                                   "(a huge chain is a DoS vector, not a key)")
        pub = _pubkey_from_x5c_leaf(header["x5c"])
        chain_fp = [hashlib.sha256(base64.b64decode(c)).hexdigest() for c in header["x5c"]]
        return {"jwk": _jwk_from_pubkey(pub), "provenance_class": "x5c_header",
                "x5c_chain_sha256": chain_fp,
                "note": "leaf cert key verified the signature; chain recorded, PKI path "
                        "NOT validated to a trust anchor here (declared)"}
    if header.get("jwk"):
        return {"jwk": {k: header["jwk"][k] for k in ("kty", "crv", "x", "y")
                        if k in header["jwk"]},
                "provenance_class": "jwk_header",
                "note": "key embedded in the protected header (self-asserted)"}
    if jwks_url:
        if not jwks_url.startswith("https://"):
            raise Ap2EvidenceError("JWKS URL must be https:// (TLS is the whole witness)")
        with urllib.request.urlopen(jwks_url, timeout=timeout) as r:  # nosec B310 - https enforced above
            raw = r.read(1024 * 1024 + 1)          # cap: un JWKS gigante = DoS, non una chiave
        if len(raw) > 1024 * 1024:
            raise Ap2EvidenceError("JWKS response exceeds 1MB cap (refused fail-closed)")
        jwks = json.loads(raw.decode())
        kid = parsed["header"].get("kid")
        keys = jwks.get("keys", [])
        match = [k for k in keys if not kid or k.get("kid") == kid]
        if not match:
            raise Ap2EvidenceError(f"no key in JWKS matches kid={kid!r}")
        return {"jwk": {k: match[0][k] for k in ("kty", "crv", "x", "y", "kid")
                        if k in match[0]},
                "provenance_class": "jwks_fetched",
                "jwks_url": jwks_url, "jwks_sha256": hashlib.sha256(raw).hexdigest(),
                "fetched_utc": _utcnow(),
                "note": "fetched over TLS at build time — a capture witness, "
                        "not proof of issuer control of the key"}
    raise Ap2EvidenceError("no key material: JWT has neither x5c nor jwk header, and no "
                           "supplied key or JWKS URL was given (fail-closed)")


def verify_kb_jwt(parsed: Dict, resolved_claims: Dict) -> Dict:
    """Holder binding (SD-JWT KB-JWT): verified against the holder key in the issuer
    payload's cnf.jwk, plus the sd_hash commitment over the exact presentation
    (<jwt>~<disclosures>*~). Three honest states: absent / verified true-false /
    present-but-unverifiable (no cnf.jwk — declared, never a fake green)."""
    kb = parsed.get("kb_jwt")
    if not kb:
        return {"present": False}
    seg = kb.split(".")
    if len(seg) != 3:
        raise Ap2EvidenceError("kb-jwt must have 3 dot-separated segments")
    try:
        header = json.loads(_b64url_decode(seg[0]))
        payload = json.loads(_b64url_decode(seg[1]))
    except (ValueError, Ap2EvidenceError) as e:
        raise Ap2EvidenceError(f"kb-jwt header/payload invalid: {e}") from e
    if header.get("alg") != "ES256":
        raise Ap2EvidenceError(f"kb-jwt alg {header.get('alg')!r} unsupported (ES256 only)")
    jwk = (resolved_claims or {}).get("cnf", {}).get("jwk")
    if not jwk:
        return {"present": True, "verified": None,
                "note": "no cnf.jwk in issuer payload — holder key unknown (declared)"}
    sig_ok = verify_es256(f"{seg[0]}.{seg[1]}".encode("ascii"),
                          _b64url_decode(seg[2]), jwk)
    presentation = parsed["compact"].rsplit("~", 1)[0] + "~"
    sd_hash_ok = payload.get("sd_hash") == _sha256_b64url(presentation.encode("ascii"))
    return {"present": True, "verified": bool(sig_ok and sd_hash_ok),
            "signature_ok": sig_ok, "sd_hash_ok": sd_hash_ok,
            "claims_recorded_not_validated": {k: payload.get(k)
                                              for k in ("aud", "nonce", "iat")
                                              if k in payload}}


# ────────────────────────────────────────────────────────── bindings

def find_bindings(artifacts: List[Dict]) -> List[Dict]:
    """Cross-artifact hash commitments, recomputed from the PRIMARY quantity: sha-256 over
    each artifact's exact compact serialization (hex and b64url forms), matched against
    every string claim of the other artifacts. Deterministic; found-or-absent, never guessed."""
    digests = {}
    for a in artifacts:
        raw = a["compact"].encode("ascii")
        digests[a["name"]] = {"hex": hashlib.sha256(raw).hexdigest(),
                              "b64url": _sha256_b64url(raw)}
    found = []

    def scan(node, path, holder):
        if isinstance(node, dict):
            for k, v in node.items():
                scan(v, f"{path}.{k}" if path else k, holder)
        elif isinstance(node, list):
            for i, v in enumerate(node):
                scan(v, f"{path}[{i}]", holder)
        elif isinstance(node, str):
            for other, d in digests.items():
                if other == holder:
                    continue
                if node == d["hex"] or node == d["b64url"]:
                    found.append({"in": holder, "claim": path, "commits_to": other,
                                  "encoding": "hex" if node == d["hex"] else "b64url"})

    for a in artifacts:
        scan(a["resolved_claims"], "", a["name"])
    return found


# ────────────────────────────────────────────────────────── build / verify

def _verify_one(parsed: Dict, key: Dict) -> Dict:
    sig_ok = verify_es256(parsed["signing_input"], parsed["signature"], key["jwk"])
    resolved = resolve_disclosures(parsed["payload"], parsed["disclosures"])
    return {"signature_ok": sig_ok, "resolved_claims": resolved,
            "disclosures_ok": True}     # resolve_disclosures raised otherwise


def build_evidence(artifacts: List[Dict], out_path: str,
                   keys: Optional[Dict[str, Dict]] = None,
                   jwks_urls: Optional[Dict[str, str]] = None,
                   tsa_url: Optional[str] = None,
                   subject: str = "agentic-payment mandate evidence") -> Dict:
    """artifacts: [{name, sd_jwt}]. Verifies every artifact NOW, snapshots the key material
    used, records bindings, and writes ONE self-contained evidence file. Any artifact that
    fails to verify aborts the build (an evidence file must never contain a red light
    dressed as evidence — fail-closed at the source)."""
    keys, jwks_urls = keys or {}, jwks_urls or {}
    names = [a["name"] for a in artifacts]
    if len(set(names)) != len(names):
        raise Ap2EvidenceError("duplicate artifact names (bindings would silently "
                               "overwrite each other — refused fail-closed)")
    entries, for_bindings = [], []
    for a in artifacts:
        parsed = parse_sd_jwt(a["sd_jwt"])
        key = _snapshot_key(parsed, supplied_jwk=keys.get(a["name"]),
                            jwks_url=jwks_urls.get(a["name"]))
        v = _verify_one(parsed, key)
        if not v["signature_ok"]:
            raise Ap2EvidenceError(f"artifact {a['name']!r}: ES256 signature INVALID "
                                   "(build refused — no evidence file for a red light)")
        kb = verify_kb_jwt(parsed, v["resolved_claims"])
        if kb.get("verified") is False:
            raise Ap2EvidenceError(f"artifact {a['name']!r}: KB-JWT holder binding "
                                   "INVALID (build refused — no evidence file for a red light)")
        entries.append({"name": a["name"], "sd_jwt_compact": parsed["compact"],
                        "header": parsed["header"], "key": key,
                        "resolved_claims": v["resolved_claims"],
                        "kb_jwt": kb,
                        "verified_at_build": {"signature_ok": True,
                                              "disclosures_ok": True}})
        for_bindings.append({"name": a["name"], "compact": parsed["compact"],
                             "resolved_claims": v["resolved_claims"]})
    evidence = {
        "evidence_format": EVIDENCE_FORMAT, "subject": subject,
        "created_utc": _utcnow(), "artifacts": entries,
        "bindings": find_bindings(for_bindings),
        "honest_scope": HONEST_SCOPE,
    }
    evidence["evidence_digest_sha256"] = hashlib.sha256(_canon(evidence)).hexdigest()
    evidence["rfc3161_timestamp"] = (
        evidence_pack._rfc3161_stamp(evidence["evidence_digest_sha256"], tsa_url)
        if tsa_url else {"anchored": False, "note": "no TSA provided"})
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(evidence, f, ensure_ascii=False, indent=1, sort_keys=True)
    return {"out": out_path, "artifacts": len(entries),
            "bindings": len(evidence["bindings"]),
            "evidence_digest_sha256": evidence["evidence_digest_sha256"],
            "rfc3161_anchored": evidence["rfc3161_timestamp"].get("anchored", False)}


def verify_evidence(path: str) -> Dict:
    """OFFLINE re-verification from the evidence file alone: digest, every signature with
    the SNAPSHOTTED key, every disclosure, every binding, and the RFC 3161 token
    cryptographically (via openssl when present; honest None when absent). Fail-closed."""
    with open(path, encoding="utf-8") as f:
        ev = json.load(f)
    e2 = {k: v for k, v in ev.items()
          if k not in ("evidence_digest_sha256", "rfc3161_timestamp")}
    digest_ok = hashlib.sha256(_canon(e2)).hexdigest() == ev.get("evidence_digest_sha256")

    art_results, all_ok = [], True
    for_bindings = []
    for a in ev.get("artifacts", []):
        try:
            parsed = parse_sd_jwt(a["sd_jwt_compact"])
            sig_ok = verify_es256(parsed["signing_input"], parsed["signature"],
                                  a["key"]["jwk"])
            resolved = resolve_disclosures(parsed["payload"], parsed["disclosures"])
            claims_ok = _canon(resolved) == _canon(a.get("resolved_claims"))
            kb = verify_kb_jwt(parsed, resolved)
            art_results.append({"name": a["name"], "signature_ok": sig_ok,
                                "claims_match": claims_ok, "kb_jwt": kb,
                                "provenance_class": a["key"].get("provenance_class")})
            all_ok = (all_ok and sig_ok and claims_ok
                      and kb.get("verified") is not False)
            for_bindings.append({"name": a["name"], "compact": a["sd_jwt_compact"],
                                 "resolved_claims": resolved})
        except (Ap2EvidenceError, KeyError, ValueError) as e:
            art_results.append({"name": a.get("name"), "error": str(e)})
            all_ok = False

    bindings_ok = find_bindings(for_bindings) == ev.get("bindings", []) if all_ok else False

    ts = ev.get("rfc3161_timestamp", {})
    rfc = {"claimed": ts.get("anchored", False), "verified": None}
    if ts.get("anchored") and ts.get("tsr_b64"):
        rfc = {"claimed": True, **evidence_pack._verify_rfc3161(
            ts["tsr_b64"], ev.get("evidence_digest_sha256", ""))}

    classes = sorted({r.get("provenance_class") for r in art_results
                      if r.get("provenance_class")})
    return {"digest_ok": digest_ok, "artifacts": art_results,
            "bindings_ok": bindings_ok, "rfc3161": rfc,
            "provenance_classes": classes,
            # tutto auto-asserito = la firma prova solo coerenza interna, mai identita'
            "self_asserted_only": bool(classes) and set(classes) <= {"jwk_header"},
            # un evidence senza artefatti non prova NULLA: mai 'valid' (falso-verde per l'auditor)
            "valid": bool(art_results and digest_ok and all_ok and bindings_ok
                          and rfc.get("verified") is not False),
            "honest_scope": ev.get("honest_scope")}


# ────────────────────────────────────────────────────────── CLI

def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(prog="ap2-evidence-pack",
                                description="Self-contained, offline-verifiable dispute "
                                            "evidence for agentic-payment SD-JWT mandates")
    sub = p.add_subparsers(dest="cmd")
    b = sub.add_parser("build")
    b.add_argument("out")
    b.add_argument("artifacts", nargs="+", metavar="name=path",
                   help="e.g. intent=intent.sdjwt cart=cart.sdjwt")
    b.add_argument("--key", action="append", default=[], metavar="name=jwk.json",
                   help="supplied verification JWK for an artifact")
    b.add_argument("--jwks-url", action="append", default=[], metavar="name=https://...",
                   help="fetch the key from a JWKS at build time (TLS witness)")
    b.add_argument("--tsa", help="RFC 3161 TSA URL (optional third-party time anchor)")
    b.add_argument("--subject", default="agentic-payment mandate evidence")
    v = sub.add_parser("verify")
    v.add_argument("evidence")
    a = p.parse_args(sys.argv[1:] if argv is None else argv)
    if a.cmd == "build":
        arts = []
        for spec in a.artifacts:
            name, _, path = spec.partition("=")
            if not path:
                p.error(f"artifact {spec!r}: expected name=path")
            with open(path, encoding="utf-8") as f:
                arts.append({"name": name, "sd_jwt": f.read()})
        keys = {}
        for spec in a.key:
            name, _, path = spec.partition("=")
            with open(path, encoding="utf-8") as f:
                keys[name] = json.load(f)
        jwks = dict(s.partition("=")[::2] for s in a.jwks_url)
        try:
            print(json.dumps(build_evidence(arts, a.out, keys=keys, jwks_urls=jwks,
                                            tsa_url=a.tsa, subject=a.subject), indent=1))
            return 0
        except Ap2EvidenceError as e:
            print(json.dumps({"error": str(e)}), file=sys.stderr)
            return 1
    if a.cmd == "verify":
        r = verify_evidence(a.evidence)
        print(json.dumps(r, indent=1))
        return 0 if r["valid"] else 1
    p.print_help()
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
