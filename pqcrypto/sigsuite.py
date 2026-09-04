# CryptoValid — crypto-agile signature suite.
# One registry, three declared signature CLASSES, so the signature scheme is a
# DECLARED dimension of the evidence (a declared-class design point), not a
# hardcoded assumption for a 5-7 year retention window:
#
#   ed25519      classical (fast, small)                          — 32B key / 64B sig
#   ecdsa-p256   classical (Secure Enclave / StrongBox / TPM)     — 33B key / 64B sig (raw r||s)
#   ml-dsa-65    POST-QUANTUM, FIPS 204 (NIST)                    — 1952B key / ~3309B sig
#
# ML-DSA is provided by the AUDITED `cryptography` library (>=50.0.1), never home-grown.
# A HYBRID pack carries a classical + a PQ signature: it is `pq_protected` when a valid
# ML-DSA signature is present, so the pack's integrity/authenticity survives the quantum
# transition (NIST IR 8547: deprecate classical ~2030, disallow ~2035 — inside a window
# opened today). Honest scope: a PQ signature protects THIS pack's integrity/authenticity;
# it does not retro-protect an underlying classical mandate signature, and does not confer
# qualified-archive legal presumption — for the "existed before a quantum adversary" claim
# you still need a trusted time anchor (RFC 3161 / RFC 4998 renewal).
from __future__ import annotations

import base64
import json
import os
from typing import Dict, List, Optional, Tuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature, encode_dss_signature)
from cryptography.hazmat.primitives import hashes

try:
    from cryptography.hazmat.primitives.asymmetric import mldsa
    MLDSA_AVAILABLE = True
except Exception:  # pragma: no cover - old cryptography
    MLDSA_AVAILABLE = False

CLASSICAL = ("ed25519", "ecdsa-p256")
POST_QUANTUM = ("ml-dsa-65",)
KNOWN = CLASSICAL + POST_QUANTUM


class SigError(ValueError):
    pass


def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def _unb64(s: str) -> bytes:
    return base64.b64decode(s)


# --- keygen -------------------------------------------------------------------

def generate(alg: str) -> Tuple[object, str]:
    """Return (private_key_obj, public_key_b64) for a declared alg."""
    if alg == "ed25519":
        sk = ed25519.Ed25519PrivateKey.generate()
        pk = sk.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    elif alg == "ecdsa-p256":
        sk = ec.generate_private_key(ec.SECP256R1())
        pk = sk.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
    elif alg == "ml-dsa-65":
        if not MLDSA_AVAILABLE:
            raise SigError("ml-dsa-65 needs cryptography>=50.0.1 (FIPS 204 ML-DSA)")
        sk = mldsa.MLDSA65PrivateKey.generate()
        pk = sk.public_key().public_bytes_raw()
    else:
        raise SigError(f"unknown signature class {alg!r}; known: {KNOWN}")
    return sk, _b64(pk)


# --- sign ---------------------------------------------------------------------

def sign(alg: str, private_key, message: bytes) -> str:
    if alg == "ed25519":
        return _b64(private_key.sign(message))
    if alg == "ecdsa-p256":
        der = private_key.sign(message, ec.ECDSA(hashes.SHA256()))
        r, s = decode_dss_signature(der)
        return _b64(r.to_bytes(32, "big") + s.to_bytes(32, "big"))  # raw r||s (P1363), interop
    if alg == "ml-dsa-65":
        return _b64(private_key.sign(message))
    raise SigError(f"unknown signature class {alg!r}")


# --- verify (fail-closed; None = unsupported class, never a false green) -------

def verify(alg: str, public_key_b64: str, signature_b64: str, message: bytes) -> Optional[bool]:
    try:
        pk = _unb64(public_key_b64)
        sig = _unb64(signature_b64)
    except (ValueError, TypeError):
        return False
    try:
        if alg == "ed25519":
            ed25519.Ed25519PublicKey.from_public_bytes(pk).verify(sig, message)
            return True
        if alg == "ecdsa-p256":
            if len(sig) != 64 or len(pk) != 65 or pk[0] != 4:
                return False
            r, s = int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big")
            key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), pk)
            key.verify(encode_dss_signature(r, s), message, ec.ECDSA(hashes.SHA256()))
            return True
        if alg == "ml-dsa-65":
            if not MLDSA_AVAILABLE:
                return None
            mldsa.MLDSA65PublicKey.from_public_bytes(pk).verify(sig, message)
            return True
    except InvalidSignature:
        return False
    except (ValueError, TypeError):
        return False
    return None  # unknown alg




# --- persistent, pinnable producer identity ----------------------------------
# A self-embedded public key proves only INTERNAL CONSISTENCY, never authenticity:
# an attacker can re-sign tampered content with a fresh key and embed it (verified
# by adversarial review). Authenticity requires the relying party to PIN the
# producer's public key(s) out of band. This identity is a STABLE keypair so its
# public keys can be pinned; store the keyfile like a signing key (0600 / HSM).

def _priv_to_der_b64(sk) -> str:
    der = sk.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8,
                           serialization.NoEncryption())
    return _b64(der)


def _der_b64_to_priv(b64: str):
    return serialization.load_der_private_key(_unb64(b64), password=None)


class ProducerIdentity:
    """Stable classical + ML-DSA-65 signing identity. `public_keys()` is what a
    relying party pins; `sign_block()` produces the hybrid producer-signature block."""

    def __init__(self, keys: Dict[str, object]):
        self._keys = keys  # {alg: private_key_obj}

    @classmethod
    def create(cls, classical_alg: str = "ed25519", post_quantum: bool = True) -> "ProducerIdentity":
        keys = {classical_alg: generate(classical_alg)[0] if False else _gen_priv(classical_alg)}
        if post_quantum and MLDSA_AVAILABLE:
            keys["ml-dsa-65"] = _gen_priv("ml-dsa-65")
        return cls(keys)

    def public_keys(self) -> Dict[str, str]:
        return {alg: _pub_b64(alg, sk) for alg, sk in self._keys.items()}

    def save(self, path: str) -> str:
        data = {"format": "cryptovalid-producer-identity/1",
                "keys": {alg: _priv_to_der_b64(sk) for alg, sk in self._keys.items()}}
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f)
        return path

    @classmethod
    def load(cls, path: str) -> "ProducerIdentity":
        with open(path, encoding="utf-8") as f:
            d = json.load(f)
        return cls({alg: _der_b64_to_priv(b64) for alg, b64 in d["keys"].items()})

    def sign_block(self, message: bytes) -> Dict:
        sigs = []
        for alg, sk in self._keys.items():
            sigs.append({"sig_alg": alg, "public_key_b64": _pub_b64(alg, sk),
                         "signature_b64": sign(alg, sk, message),
                         "post_quantum": alg in POST_QUANTUM})
        return {"scheme": "hybrid" if any(a in POST_QUANTUM for a in self._keys) else "classical-only",
                "over": "evidence_digest_sha256", "signatures": sigs}


def _gen_priv(alg: str):
    if alg == "ed25519":
        return ed25519.Ed25519PrivateKey.generate()
    if alg == "ecdsa-p256":
        return ec.generate_private_key(ec.SECP256R1())
    if alg == "ml-dsa-65":
        if not MLDSA_AVAILABLE:
            raise SigError("ml-dsa-65 needs cryptography>=50.0.1")
        return mldsa.MLDSA65PrivateKey.generate()
    raise SigError(f"unknown alg {alg!r}")


def _pub_b64(alg: str, sk) -> str:
    if alg == "ed25519":
        return _b64(sk.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw))
    if alg == "ecdsa-p256":
        return _b64(sk.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint))
    if alg == "ml-dsa-65":
        return _b64(sk.public_key().public_bytes_raw())
    raise SigError(f"unknown alg {alg!r}")


# --- hybrid producer signatures over an evidence digest -----------------------

def sign_hybrid(message: bytes, classical_alg: str = "ed25519") -> Dict:
    """Sign `message` with a fresh classical key AND ML-DSA-65 (when available).
    Returns the producer-signature block to embed in an evidence pack: a list of
    {sig_alg, public_key_b64, signature_b64, post_quantum} entries."""
    sigs = []
    sk_c, pk_c = generate(classical_alg)
    sigs.append({"sig_alg": classical_alg, "public_key_b64": pk_c,
                 "signature_b64": sign(classical_alg, sk_c, message), "post_quantum": False})
    if MLDSA_AVAILABLE:
        sk_q, pk_q = generate("ml-dsa-65")
        sigs.append({"sig_alg": "ml-dsa-65", "public_key_b64": pk_q,
                     "signature_b64": sign("ml-dsa-65", sk_q, message), "post_quantum": True})
    return {"scheme": "hybrid" if MLDSA_AVAILABLE else "classical-only",
            "over": "evidence_digest_sha256", "signatures": sigs}


def verify_producer_block(block: Dict, message: bytes, trusted: Optional[Dict[str, str]] = None) -> Dict:
    """Verify every producer signature. Fail-closed: any present-but-invalid signature
    makes the block invalid. `pq_protected` is true only on a VALID ML-DSA signature.

    `trusted` = {sig_alg: public_key_b64} (or {sig_alg: [b64,...]}) PINS the producer key.
    Without it, a valid signature proves only INTERNAL CONSISTENCY, never authenticity
    (an attacker can re-sign tampered content with a fresh embedded key) -> `trusted` is
    reported None and callers MUST NOT treat the pack as authentic. With it, `trusted` is
    True only when every present signature's key is pinned, and `pq_protected` additionally
    requires the ML-DSA key to be pinned."""
    results, pq = [], False
    all_keys_pinned = trusted is not None
    n_pass = n_fail = n_skip = 0
    for s in block.get("signatures", []):
        alg = s.get("sig_alg")
        pub = s.get("public_key_b64", "")
        v = verify(alg, pub, s.get("signature_b64", ""), message)
        status = "PASS" if v is True else ("SKIP" if v is None else "FAIL")
        if v is True:
            n_pass += 1
        elif v is False:
            n_fail += 1
        else:
            n_skip += 1        # unknown alg / missing PQ backend = a verification GAP, never a pass
        key_trusted = None
        if trusted is not None:
            allowed = trusted.get(alg, [])
            allowed = [allowed] if isinstance(allowed, str) else list(allowed)
            key_trusted = pub in allowed
            if not key_trusted:
                all_keys_pinned = False
        if v is True and alg in POST_QUANTUM and (trusted is None or key_trusted):
            pq = True
        results.append({"sig_alg": alg, "status": status,
                        "post_quantum": alg in POST_QUANTUM, "key_trusted": key_trusted})
    # FAIL-CLOSED: ok requires at least one real PASS and zero failures AND zero unverifiable
    # (an all-SKIP block verified NOTHING -> must not be a green ok). `incomplete` is distinct.
    ok = n_pass >= 1 and n_fail == 0 and n_skip == 0
    trusted_ok = None if trusted is None else (bool(results) and all_keys_pinned and n_skip == 0)
    return {"ok": ok, "incomplete": n_skip > 0 and n_fail == 0, "pq_protected": pq,
            "trusted": trusted_ok, "results": results, "scheme": block.get("scheme")}
