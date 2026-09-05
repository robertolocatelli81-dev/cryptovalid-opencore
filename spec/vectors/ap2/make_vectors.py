#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Roberto Locatelli
"""Generator for the ap2-evidence-pack conformance vectors (provenance: how the frozen
vectors in this directory were made). The vectors are FROZEN artifacts — regenerating
produces new keys/timestamps, so a regeneration replaces the vector set, it does not
reproduce it byte-for-byte. Run only to rebuild the set deliberately.

Vector set (each <name>.json pack + <name>.expected.json policy/verdict):
  valid_signed        hybrid-signed pack, producer keys pinned, require_pq+producer -> ACCEPT
  stripped_signature  same pack with producer_signatures REMOVED, same policy -> REJECT (downgrade)
  unpinned_producer   pack signed by a DIFFERENT identity, verified against the pinned set
                      (no require flags) -> REJECT (a valid-but-unpinned signature is not authentic)
  digest_mismatch     one content field altered after sealing -> REJECT (digest + producer sigs fail)
  anchor_missing      valid signed pack, policy adds require_anchor -> REJECT (existed-by unproven)
  anchor_invalid      claimed RFC 3161 anchor whose token is garbage -> REJECT (requires openssl)
"""
import base64
import copy
import hashlib
import json
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_OPENCORE = os.path.abspath(os.path.join(_HERE, "..", "..", ".."))
sys.path.insert(0, _OPENCORE)
import ap2_evidence as ap2  # noqa: E402
import sigsuite as _sigsuite  # noqa: E402  (resolved via ap2_evidence's pqcrypto path hook)

from cryptography.hazmat.primitives import hashes  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature  # noqa: E402


def _b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def _make_signer():
    sk = ec.generate_private_key(ec.SECP256R1())
    nums = sk.public_key().public_numbers()
    jwk = {"kty": "EC", "crv": "P-256",
           "x": _b64u(nums.x.to_bytes(32, "big")),
           "y": _b64u(nums.y.to_bytes(32, "big"))}
    return sk, jwk


def _sign_jwt(sk, header: dict, payload: dict) -> str:
    si = f"{_b64u(json.dumps(header).encode())}.{_b64u(json.dumps(payload).encode())}"
    der = sk.sign(si.encode("ascii"), ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der)
    return f"{si}.{_b64u(r.to_bytes(32, 'big') + s.to_bytes(32, 'big'))}"


def _disclosure(salt: str, name, value) -> str:
    return _b64u(json.dumps([salt, name, value]).encode())


def _make_sd_jwt(sk, claims_open: dict, claims_sd: dict, jwk: dict) -> str:
    discs = [_disclosure(f"salt{i}", k, v) for i, (k, v) in enumerate(claims_sd.items())]
    payload = dict(claims_open)
    payload["_sd"] = sorted(ap2._disclosure_digest(d) for d in discs)
    payload["_sd_alg"] = "sha-256"
    header = {"alg": "ES256", "typ": "ap2-mandate+sd-jwt", "jwk": jwk}
    return _sign_jwt(sk, header, payload) + "~" + "~".join(discs) + "~"


def _write(name: str, pack: dict, expected: dict) -> None:
    with open(os.path.join(_HERE, f"{name}.json"), "w", encoding="utf-8") as f:
        json.dump(pack, f, ensure_ascii=False, indent=1, sort_keys=True)
    with open(os.path.join(_HERE, f"{name}.expected.json"), "w", encoding="utf-8") as f:
        json.dump(expected, f, ensure_ascii=False, indent=1, sort_keys=True)


def _expected(name, desc, policy, normative, requires=None):
    e = {"vector": name, "description": desc, "policy": policy, "normative": normative}
    if requires:
        e["requires"] = requires
    return e


def main() -> int:
    # one mandate pair with a REAL hash binding (cart commits to the intent's compact form)
    sk, jwk = _make_signer()
    intent = _make_sd_jwt(sk, {"iss": "user-wallet", "mandate_type": "intent"},
                          {"max_amount": "150.00 EUR", "merchant_scope": "books"}, jwk)
    cart = _make_sd_jwt(sk, {"iss": "shopping-agent", "mandate_type": "cart",
                             "intent_mandate_hash":
                                 hashlib.sha256(intent.encode("ascii")).hexdigest()},
                        {"items": ["book-123"]}, jwk)
    arts = [{"name": "intent", "sd_jwt": intent}, {"name": "cart", "sd_jwt": cart}]

    base = os.path.join(_HERE, "_base.json")
    ap2.build_evidence(arts, base, subject="ap2 conformance vector")

    identity_a = _sigsuite.ProducerIdentity.create()   # the legitimate, PINNED producer
    identity_b = _sigsuite.ProducerIdentity.create()   # a valid but UNPINNED producer
    pins_a = {alg: [pk] for alg, pk in identity_a.public_keys().items()}

    ap2.sign_evidence(base, identity=identity_a)
    with open(base, encoding="utf-8") as f:
        signed_a = json.load(f)
    os.remove(base)

    policy_strict = {"trusted_producer_keys": pins_a, "require_pq": True,
                     "require_producer": True, "require_anchor": False}

    _write("valid_signed", signed_a, _expected(
        "valid_signed",
        "Hybrid-signed pack (ed25519 + ML-DSA-65), producer keys pinned, PQ and producer "
        "required. The one ACCEPT of the set — a verifier that rejects everything fails here.",
        policy_strict,
        {"valid": True, "digest_ok": True, "bindings_ok": True, "policy_ok": True,
         "pq_protected": True, "producer_present": True, "producer_ok": True,
         "producer_trusted": True, "rfc3161_claimed": False, "rfc3161_verified": None,
         "self_asserted_only": True}))

    stripped = {k: v for k, v in signed_a.items() if k != "producer_signatures"}
    _write("stripped_signature", stripped, _expected(
        "stripped_signature",
        "The signed pack with producer_signatures REMOVED (downgrade attack). The digest "
        "still verifies — only the require_producer/require_pq policy rejects the strip.",
        policy_strict,
        {"valid": False, "digest_ok": True, "bindings_ok": True, "policy_ok": False,
         "pq_protected": False, "producer_present": False, "producer_ok": None,
         "producer_trusted": None, "rfc3161_claimed": False, "rfc3161_verified": None,
         "self_asserted_only": True}))

    unpinned = copy.deepcopy(stripped)
    tmp = os.path.join(_HERE, "_unpinned.json")
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(unpinned, f, ensure_ascii=False, indent=1, sort_keys=True)
    ap2.sign_evidence(tmp, identity=identity_b)
    with open(tmp, encoding="utf-8") as f:
        unpinned = json.load(f)
    os.remove(tmp)
    _write("unpinned_producer", unpinned, _expected(
        "unpinned_producer",
        "Pack signed by a DIFFERENT (cryptographically valid) identity, verified against "
        "the pinned trust set with NO require flags: an embedded key proves consistency, "
        "never authenticity — the unpinned signature must reject on its own.",
        {"trusted_producer_keys": pins_a, "require_pq": False,
         "require_producer": False, "require_anchor": False},
        {"valid": False, "digest_ok": True, "bindings_ok": True, "policy_ok": True,
         "pq_protected": False, "producer_present": True, "producer_ok": True,
         "producer_trusted": False, "rfc3161_claimed": False, "rfc3161_verified": None,
         "self_asserted_only": True}))

    tampered = copy.deepcopy(signed_a)
    tampered["subject"] = "ap2 conformance vector (altered after sealing)"
    _write("digest_mismatch", tampered, _expected(
        "digest_mismatch",
        "One content field altered after sealing: the recomputed digest no longer matches, "
        "and the producer signatures (over the recomputed digest) fail with it.",
        {"trusted_producer_keys": None, "require_pq": False,
         "require_producer": False, "require_anchor": False},
        {"valid": False, "digest_ok": False, "bindings_ok": True, "policy_ok": True,
         "pq_protected": False, "producer_present": True, "producer_ok": False,
         "producer_trusted": None, "rfc3161_claimed": False, "rfc3161_verified": None,
         "self_asserted_only": True}))

    anchor_policy = dict(policy_strict, require_anchor=True)
    _write("anchor_missing", signed_a, _expected(
        "anchor_missing",
        "The valid signed pack under a policy that REQUIRES a proven time anchor: with no "
        "RFC 3161 token the existed-by claim is unproven, so the policy rejects. Same bytes "
        "as valid_signed — only the policy differs; 'claimed' never upgrades to 'proven'.",
        anchor_policy,
        {"valid": False, "digest_ok": True, "bindings_ok": True, "policy_ok": False,
         "pq_protected": True, "producer_present": True, "producer_ok": True,
         "producer_trusted": True, "rfc3161_claimed": False, "rfc3161_verified": None,
         "self_asserted_only": True}))

    bad_anchor = copy.deepcopy(signed_a)
    bad_anchor["rfc3161_timestamp"] = {
        "anchored": True,
        "tsa_url": "https://tsa.invalid/example",
        "tsr_b64": base64.b64encode(b"not an RFC 3161 token").decode("ascii")}
    _write("anchor_invalid", bad_anchor, _expected(
        "anchor_invalid",
        "A CLAIMED RFC 3161 anchor whose token is garbage: cryptographic token verification "
        "fails, so the pack rejects even without policy flags — a claimed-but-false anchor "
        "is tamper, never a soft warning.",
        anchor_policy,
        {"valid": False, "digest_ok": True, "bindings_ok": True, "policy_ok": False,
         "pq_protected": True, "producer_present": True, "producer_ok": True,
         "producer_trusted": True, "rfc3161_claimed": True, "rfc3161_verified": False,
         "self_asserted_only": True},
        requires=["openssl"]))

    print("vectors written to", _HERE)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
