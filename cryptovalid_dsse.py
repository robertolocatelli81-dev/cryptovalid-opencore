# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Roberto Locatelli
"""DSSE envelopes carrying in-toto Statements: verification only (SPEC v0.15 §25, 2026-11-23).

Status: EXPERIMENTAL (README, "Core and experimental modules").

Ported from omega-evidence, `omega_evidence/interop/dsse.py` (`pae`, `from_dsse`, `load_public_key`, commit c26f4e6,
Apache-2.0, same author; NOTICE): the verification and nothing else (no envelope is written here, no key the envelope
carries is ever used). Standards, the versions in force on 2026-11-23: DSSE v1.0.2 (secure-systems-lab/dsse,
protocol.md and envelope.md; master changed only governance files since the tag) and the in-toto Attestation Framework
v1.2.0 (in-toto/attestation, spec/v1/statement.md, spec/v1/README.md "Parsing rules", docs/validation.md).

    verify_envelope(envelope, keys, artifact=None, digest_algorithms=("sha256",), threshold=1)
        -> {"valid", "code", "detail", "payload_type", "statement", "verified_keys", "matched_subjects",
            "unrecognized_fields"}

`envelope` is the JSON text (bytes or str) of a DSSE JSON envelope; `keys` the caller's trusted public keys (PEM text, or
PEM / DER bytes, of a SubjectPublicKeyInfo or of an X.509 certificate whose chain is NOT checked): Ed25519 or ECDSA
P-256 with SHA-256. `code` is one of CODES (SPEC §25 rule 6). The keys are loaded and the signatures checked with
`cryptography`; without it every call with keys raises verifier.CheckNotRun, before the envelope is read.
"""
import base64
import binascii
import hashlib
import json
import re
from typing import Any, Dict, List, Optional, Sequence, Tuple, Union

import verifier

PAYLOAD_TYPE = "application/vnd.in-toto+json"
_PAYLOAD_TYPE_PREDICATE = re.compile(r"application/vnd\.in-toto\.[A-Za-z0-9][A-Za-z0-9._-]*\+json")
STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
DIGESTS = {"sha256": hashlib.sha256, "sha384": hashlib.sha384, "sha512": hashlib.sha512,
           "sha3_256": hashlib.sha3_256, "sha3_384": hashlib.sha3_384, "sha3_512": hashlib.sha3_512}
CODES = ("ok", "envelope", "base64", "signature", "payload_type", "statement", "subject")
MAX_ENVELOPE = 64 * 1024 * 1024   # the bound of a ledger line (SPEC §22 rule 8)
_STD = re.compile(r"[A-Za-z0-9+/]*={0,2}")
_URL = re.compile(r"[A-Za-z0-9_-]*={0,2}")


def pae(payload_type: str, payload: bytes) -> bytes:
    """DSSE v1.0.2 Pre-Authentication Encoding: "DSSEv1" SP LEN(type) SP type SP LEN(body) SP body."""
    pt = payload_type.encode("utf-8")
    return b"DSSEv1 %d %s %d %s" % (len(pt), pt, len(payload), payload)


def _unb64(s: Any) -> bytes:
    """Standard or URL-safe base64 (DSSE: verifiers MUST accept either), one alphabet per string, padding only at the
    end, length a multiple of 4. ValueError otherwise."""
    if not isinstance(s, str) or len(s) % 4 or not (_STD.fullmatch(s) or _URL.fullmatch(s)):
        raise ValueError("not base64")
    return base64.b64decode(s, altchars=b"-_", validate=True)   # "+" and "/" pass unchanged; the regex allowed one alphabet


def _loads(text: str) -> Any:
    """JSON with a name written twice in one object, NaN / Infinity and nesting over 512 refused."""
    if verifier.json_nesting_depth(text) > verifier.MAX_JSON_DEPTH:
        raise ValueError(f"nesting over {verifier.MAX_JSON_DEPTH}")
    return json.loads(text, object_pairs_hook=verifier._reject_dup,
                      parse_constant=lambda c: (_ for _ in ()).throw(ValueError(f"JSON constant {c}")))


def _crypto():
    try:
        from cryptography import x509
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec, ed25519
        from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature
    except ImportError:
        raise verifier.CheckNotRun("DSSE signatures need the cryptography package (pip install "
                                   "'cryptovalid-opencore[sign]'): not checked") from None
    return x509, InvalidSignature, hashes, serialization, ec, ed25519, decode_dss_signature, encode_dss_signature


def load_key(key: Union[str, bytes]) -> Tuple[str, Any]:
    """("ed25519" | "ecdsa-p256", key object) from PEM text, or PEM / DER bytes, of an SPKI or an X.509 certificate.
    ValueError with the reason for anything else (another key type, another curve, several PEM blocks)."""
    x509, _, _, serialization, ec, ed25519, _, _ = _crypto()
    if isinstance(key, str):
        key = key.encode("ascii", "strict") if key.isascii() else b""
    if not isinstance(key, (bytes, bytearray)) or not key:
        raise ValueError("a key is PEM text or PEM / DER bytes")
    data = bytes(key)
    if b"-----BEGIN" in data:
        blocks = re.findall(rb"-----BEGIN ([A-Z0-9 ]+)-----\r?\n([A-Za-z0-9+/=\r\n]+?)-----END \1-----", data)
        if len(blocks) != 1 or data.count(b"-----BEGIN") != 1 or blocks[0][0] not in (b"PUBLIC KEY", b"CERTIFICATE"):
            raise ValueError("a PEM key holds exactly one PUBLIC KEY or CERTIFICATE block")
        try:
            data = base64.b64decode(b"".join(blocks[0][1].split()), validate=True)
        except (ValueError, binascii.Error):
            raise ValueError("the PEM block is not base64") from None
    try:
        k = serialization.load_der_public_key(data)
    except Exception:  # noqa: BLE001 - not an SPKI: a certificate?
        try:
            k = x509.load_der_x509_certificate(data).public_key()
        except Exception:  # noqa: BLE001
            raise ValueError("the key is neither a SubjectPublicKeyInfo nor an X.509 certificate") from None
    if isinstance(k, ed25519.Ed25519PublicKey):
        return ("ed25519", k)
    if isinstance(k, ec.EllipticCurvePublicKey) and k.curve.name == "secp256r1":
        return ("ecdsa-p256", k)
    raise ValueError(f"unsupported key {type(k).__name__}"
                     f"{' on ' + k.curve.name if isinstance(k, ec.EllipticCurvePublicKey) else ''} "
                     "(supported: Ed25519, ECDSA P-256 with SHA-256)")


def _verify_one(kind: str, key: Any, sig: bytes, message: bytes) -> bool:
    _, InvalidSignature, hashes, _, ec, _, decode_dss, encode_dss = _crypto()
    if kind == "ed25519":
        candidates = [sig] if len(sig) == 64 else []
    else:   # ECDSA: strict DER (sigstore, GitHub) or raw r||s of 64 bytes (the DSSE test vector)
        candidates = []
        if sig[:1] == b"\x30":
            try:
                if encode_dss(*decode_dss(sig)) == sig:
                    candidates.append(sig)
            except ValueError:
                pass
        if len(sig) == 64:
            candidates.append(encode_dss(int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big")))
    for c in candidates:
        try:
            if kind == "ed25519":
                key.verify(c, message)
            else:
                key.verify(c, message, ec.ECDSA(hashes.SHA256()))
            return True
        except InvalidSignature:
            continue
    return False


def _out(code: str, detail: str, **kw) -> Dict[str, Any]:
    r = {"valid": code == "ok", "code": code, "detail": detail, "payload_type": None, "statement": None,
         "verified_keys": [], "matched_subjects": [], "unrecognized_fields": []}
    r.update(kw)
    return r


def verify_envelope(envelope: Union[bytes, str], keys: Sequence[Union[str, bytes]], artifact: Optional[bytes] = None,
                    digest_algorithms: Sequence[str] = ("sha256",), threshold: int = 1) -> Dict[str, Any]:
    """SPEC §25. Errors of the caller (no key, a key that does not load, a threshold or a digest algorithm out of range,
    an artifact that is not bytes) raise ValueError / TypeError before the envelope is read."""
    if isinstance(keys, (str, bytes, bytearray)) or not isinstance(keys, (list, tuple)) or not keys:
        raise ValueError("keys: a non-empty list of trusted public keys")
    if isinstance(threshold, bool) or not isinstance(threshold, int) or not 1 <= threshold <= len(keys):
        raise ValueError("threshold: an integer from 1 to the number of keys")
    if isinstance(digest_algorithms, str) or not digest_algorithms or \
            any(not isinstance(a, str) or a not in DIGESTS for a in digest_algorithms):
        raise ValueError(f"digest_algorithms: a non-empty list from {sorted(DIGESTS)}")
    if artifact is not None and not isinstance(artifact, (bytes, bytearray)):
        raise TypeError("artifact: bytes")
    loaded = [load_key(k) for k in keys]
    _, _, _, serialization, _, _, _, _ = _crypto()
    spki = [k.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo) for _, k in loaded]
    if len(set(spki)) != len(spki):   # the threshold counts unique keys (DSSE, Multi-signature Verification)
        raise ValueError("keys: the same public key is given twice")
    # rule 1: the envelope
    if isinstance(envelope, (bytes, bytearray)):
        if len(envelope) > MAX_ENVELOPE:
            return _out("envelope", f"the envelope is longer than {MAX_ENVELOPE} bytes")
        try:
            envelope = bytes(envelope).decode("utf-8")
        except UnicodeDecodeError:
            return _out("envelope", "the envelope is not UTF-8")
    if not isinstance(envelope, str):
        raise TypeError("envelope: the JSON text, bytes or str")
    if len(envelope) > MAX_ENVELOPE:
        return _out("envelope", f"the envelope is longer than {MAX_ENVELOPE} characters")
    try:
        env = _loads(envelope)
    except (ValueError, RecursionError) as e:
        return _out("envelope", f"the envelope is not JSON as rule 1 reads it: {str(e)[:120]}")
    if not isinstance(env, dict):
        return _out("envelope", "the envelope is not a JSON object")
    missing = [k for k in ("payload", "payloadType", "signatures") if k not in env]
    if missing:
        return _out("envelope", f"required members missing: {missing}")
    if not isinstance(env["payload"], str) or not isinstance(env["payloadType"], str) or \
            not isinstance(env["signatures"], list):
        return _out("envelope", "payload and payloadType must be strings, signatures an array")
    try:
        env["payloadType"].encode("utf-8")
    except UnicodeEncodeError:      # a lone surrogate (JSON "\ud800"): the PAE of rule 2 has no bytes
        return _out("envelope", "payloadType has no UTF-8 encoding (a lone surrogate)")
    unrecognized = sorted(k for k in env if k not in ("payload", "payloadType", "signatures"))
    for n, s in enumerate(env["signatures"]):
        if not isinstance(s, dict) or "sig" not in s or not isinstance(s["sig"], str) or \
                not isinstance(s.get("keyid", ""), str):
            return _out("envelope", f"signatures[{n}]: an object with a string sig and, if present, a string keyid")
        unrecognized += sorted(f"signatures[{n}].{k}" for k in s if k not in ("sig", "keyid"))
    try:
        payload = _unb64(env["payload"])
        sigs = [_unb64(s["sig"]) for s in env["signatures"]]
    except (ValueError, binascii.Error):
        return _out("base64", "payload or a sig is not base64 (standard or URL-safe, padded)",
                    unrecognized_fields=unrecognized)
    # rule 2: signatures, with the caller's keys only; the keyid is not used (DSSE: not for security decisions)
    message = pae(env["payloadType"], payload)
    verified = sorted({i for i, (kind, k) in enumerate(loaded) for s in sigs if _verify_one(kind, k, s, message)})
    if len(verified) < threshold:
        return _out("signature", f"{len(verified)} of the given keys verified a signature, {threshold} needed",
                    verified_keys=verified, unrecognized_fields=unrecognized)
    # rule 3: the payload type, then the statement (in-toto docs/validation.md, Statement layer)
    pt = env["payloadType"]
    if pt != PAYLOAD_TYPE and not _PAYLOAD_TYPE_PREDICATE.fullmatch(pt):
        return _out("payload_type", f"payloadType {pt[:80]!r} is not an in-toto type", verified_keys=verified,
                    unrecognized_fields=unrecognized)

    def bad(why):
        return _out("statement", why, payload_type=pt, verified_keys=verified, unrecognized_fields=unrecognized)
    try:
        st = _loads(payload.decode("utf-8"))
    except (ValueError, RecursionError) as e:
        return bad(f"the payload is not JSON as rule 1 reads it: {str(e)[:120]}")
    if not isinstance(st, dict):
        return bad("the statement is not a JSON object")
    if st.get("_type") != STATEMENT_TYPE:
        return bad(f"_type is not {STATEMENT_TYPE}")
    subject = st.get("subject")
    if not isinstance(subject, list) or not all(
            isinstance(x, dict) and isinstance(x.get("digest"), dict) and x["digest"]
            and all(isinstance(v, str) for v in x["digest"].values()) for x in subject):
        return bad("subject is not an array of objects each with a non-empty digest of strings")
    if not isinstance(st.get("predicateType"), str) or not st["predicateType"]:
        return bad("predicateType is not a non-empty string")
    if "predicate" in st and not isinstance(st["predicate"], dict):
        return bad("predicate is not an object")
    matched: List[int] = []
    if artifact is not None:   # rule 4: matchedSubjects
        want = {a: DIGESTS[a](bytes(artifact)).hexdigest() for a in digest_algorithms}
        matched = [i for i, x in enumerate(subject)
                   if any(a in want and isinstance(v, str) and v.lower() == want[a] for a, v in x["digest"].items())]
        if not matched:
            return _out("subject", "no subject carries the artifact's digest", payload_type=pt, statement=st,
                        verified_keys=verified, unrecognized_fields=unrecognized)
    return _out("ok", "signature verified with the caller's keys" +
                (f"; subject {matched} matches the artifact" if matched else "; no artifact given: no subject matched"),
                payload_type=pt, statement=st, verified_keys=verified, matched_subjects=matched,
                unrecognized_fields=unrecognized)
