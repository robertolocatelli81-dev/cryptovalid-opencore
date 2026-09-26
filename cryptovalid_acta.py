#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""cryptovalid-opencore — Signed Decision Receipts, draft-farley-acta-signed-receipts-03 (0.16.0, 2026-09-24).

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
import binascii
import hashlib
import json
import os
import re
import stat
import sys
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

DRAFT = "draft-farley-acta-signed-receipts-03 (2026-08-29, expires 2027-03-02; individual Internet-Draft)"
DECISIONS = ("allow", "deny", "rate_limit", "require_approval")
ALGS = ("EdDSA", "ML-DSA-65", "ES256")
# Every pattern here is ASCII-only, by construction ([0-9], never \d) AND by flag (re.ASCII): in Python `\d` matches any
# Unicode decimal digit, and up to 0.16.0 an `issued_at` written in Arabic-Indic or fullwidth digits was accepted,
# signed and compared against the key window as if it were an RFC 3339 instant. RFC 3339 §5.6 is ABNF: DIGIT is %x30-39.
_RFC3339 = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}[Tt][0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]+)?([Zz]|[+-][0-9]{2}:[0-9]{2})\Z", re.ASCII)
_HEX = re.compile(r"^[0-9a-f]+\Z", re.ASCII)
_HEX64_ANYCASE = re.compile(r"^[0-9a-fA-F]{64}\Z", re.ASCII)
_SHA256_PREFIXED = re.compile(r"^sha256:[0-9a-f]{64}\Z", re.ASCII)
_PREV_HASH = re.compile(r"^(sha256:)?[0-9a-f]{64}\Z", re.ASCII)
_UTC_SECONDS = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z", re.ASCII)
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


_INSTANT_RE = re.compile(r"^([0-9]{4})-([0-9]{2})-([0-9]{2})[Tt]([0-9]{2}):([0-9]{2}):([0-9]{2})(\.[0-9]+)?(?:[Zz]|([+-])([0-9]{2}):([0-9]{2}))\Z", re.ASCII)


def _instant(t: Any) -> Optional[datetime]:
    """RFC 3339 instant -> aware datetime, or None when the text is not one.

    Built from this regex's own groups rather than from `fromisoformat`, because the two disagreed: this form accepts a
    leap second (:60), which `fromisoformat` rejects, and before Python 3.11 `fromisoformat` also rejected fractional
    parts other than 3 or 6 digits — while `pyproject` declares a 3.9 floor. Two parsers that disagree meant a value
    accepted as valid could not be compared, and the caller skipped the comparison: a bypass. There is one parser now.

    A leap second is mapped to :59.999999 of the same minute: it keeps the ordering (it sits before the next minute)
    without claiming the 61st second exists in the proleptic calendar Python models.
    """
    if not isinstance(t, str):
        return None
    m = _INSTANT_RE.match(t)
    if not m:
        return None
    y, mo, d, h, mi, se = (int(m.group(i)) for i in range(1, 7))
    if se > 60:
        return None
    if se == 60:
        # RFC 3339 §5.7: a leap second exists only as 23:59:60 UTC. At any other position (10:15:60) it is not an
        # instant; before 26/09/2026 this parser accepted :60 at every minute (measured).
        if m.group(8) is None:
            utc_min = h * 60 + mi
        else:
            off = int(m.group(9)) * 60 + int(m.group(10))
            utc_min = (h * 60 + mi - (off if m.group(8) == "+" else -off)) % 1440
        if utc_min != 23 * 60 + 59:
            return None
    frac = m.group(7)
    micro = 999999 if se == 60 else (int(round(float(frac) * 1_000_000)) if frac else 0)
    if m.group(8) is None:
        off = timezone.utc
    else:
        oh, om = int(m.group(9)), int(m.group(10))
        if oh > 23 or om > 59:
            return None
        delta = timedelta(hours=oh, minutes=om)
        off = timezone(-delta if m.group(8) == "-" else delta)
    try:
        return datetime(y, mo, d, h, mi, 59 if se == 60 else se, min(micro, 999999), tzinfo=off)
    except ValueError:
        return None


def _instant_exact(t: Any) -> Optional[Tuple[int, int, str]]:
    """The same instant as `_instant`, as an EXACT ordered key: every fractional digit counts.
    `_instant` rounds to microseconds, and a window bound 100 ns after issued_at compared equal to it — a receipt
    issued BEFORE valid_from came back `inside` (measured 26/09/2026). Window comparisons use this.

    Returned as an ordered key (whole UTC second, leap flag, fractional digits with trailing zeros removed): digit
    strings normalized that way compare, as strings, exactly as the fractions they write — in linear time, with no int()
    (a first version used int() and raised ValueError past 4300 digits on Python >= 3.11: Gemini Pro review 26/09/2026).
    A leap second 23:59:60.f is (:59, 1, f), after
    every :59.x — however many digits x has — and before the next second. A first version added a 12-digit offset
    instead, and a 13-digit :59 bound then sorted after :60 (independent review 26/09/2026: PASS after valid_until)."""
    d = _instant(t)
    if d is None:
        return None
    m = _INSTANT_RE.match(t)
    frac = m.group(7)[1:].rstrip("0") if m.group(7) else ""
    whole = int((d.replace(microsecond=0) - datetime(1970, 1, 1, tzinfo=timezone.utc)).total_seconds())
    return (whole, 1 if int(m.group(6)) == 60 else 0, frac)


def _valid_instant(t: str) -> bool:
    """RFC 3339 form AND a real calendar instant. One parser only: see `_instant`."""
    return _instant(t) is not None


def _outside_window(issued_at: str, entry: Any) -> Optional[Tuple[str, str]]:
    """§9.2: 'Verifiers SHOULD check key validity windows when available.' Returns a reason when the receipt's
    issued_at falls outside the window declared for its key, or None when it does not — including when no window
    is declared, which is the common case and is not an error.

    The draft states the SHOULD and nothing about the boundaries, so the choice is ours and is declared here:
    the window is [valid_from, valid_until), start inclusive and end exclusive. The reason is the JOSE convention
    the draft sits in — RFC 7519 §4.1.5 says `nbf` is met when the time is "after or equal to" it, and §4.1.4 that
    `exp` is the time "on or after which" a token MUST NOT be accepted. X.509 (RFC 5280 §4.1.2.5) includes both
    ends instead, which is equally defensible; the two readings differ by exactly one instant, and the exclusive
    end is the more conservative of the two on expiry. (An earlier note here claimed this was the only reading
    that keeps consecutive keys disjoint — that was wrong: (from, until] does too.)

    What this does NOT do: it compares an instant the SIGNER asserts against a window the relying party holds.
    It catches a key used after an honest rotation; it cannot catch a compromised key whose receipts are
    backdated inside the window. §9.2 is a SHOULD and this check is only as good as the window's source.
    """
    # Returns None, or (kind, reason) with kind "outside" (the receipt falls outside a window that could be read),
    # "bound" (the RELYING PARTY's bound is not an instant: a configuration defect, never a finding about the receipt)
    # or "instant" (the receipt's issued_at cannot be compared). The kind used to be inferred from the reason's wording.
    if not isinstance(entry, dict):
        return None
    vf, vu = entry.get("valid_from"), entry.get("valid_until")
    if vf is None and vu is None:
        return None
    a = _instant_exact(vf) if vf is not None else None
    b = _instant_exact(vu) if vu is not None else None
    t = _instant_exact(issued_at)
    if t is None:
        # A window was declared and the instant cannot be compared against it: refuse rather than skip.
        return "instant", "issued_at cannot be compared with the key validity window (§9.2)"
    # A bound that CAN be read and excludes the receipt decides, even if the other bound is unreadable: an unreadable
    # bound must not turn a definite "outside" into "not assessed" (independent review 26/09/2026).
    if a is not None and t < a:
        return "outside", "issued_at precedes the key validity window (§9.2)"
    if b is not None and t >= b:
        return "outside", "issued_at is at or after the key validity window ends (§9.2)"
    if vf is not None and a is None:
        return "bound", "the relying party's key valid_from is not an RFC 3339 instant (§9.2)"
    if vu is not None and b is None:
        return "bound", "the relying party's key valid_until is not an RFC 3339 instant (§9.2)"
    return None


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


MAX_INPUT_BYTES = 64 * 1024 * 1024       # every file this module reads: receipts, --previous, --jwks, key files, policies


def read_regular(path: str, limit: int = MAX_INPUT_BYTES) -> bytes:
    """The bytes of a REGULAR file of at most `limit` bytes. Opened without blocking and judged on the OPEN descriptor,
    so a FIFO, a device (/dev/zero) or a directory is refused at once instead of blocking or filling memory (measured
    26/09/2026: a FIFO given as a JSON input blocked the verifier indefinitely). Raises OSError."""
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOCTTY", 0))
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise OSError(f"{path} is not a regular file")
        if st.st_size > limit:
            raise OSError(f"{path} is larger than {limit} bytes")
        with os.fdopen(os.dup(fd), "rb") as f:
            data = f.read(limit + 1)
        if len(data) > limit:
            raise OSError(f"{path} is larger than {limit} bytes")
        return data
    finally:
        os.close(fd)


def policy_digest_from_dir(path: str, engine: str = "cedar", ext: str = ".cedar") -> str:
    files = {}
    for n in os.listdir(path):
        if n.endswith(ext):
            files[n] = read_regular(os.path.join(path, n))
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
        if not _SHA256_PREFIXED.match(policy_digest_value):
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
def _pem_problem(data: bytes) -> Optional[str]:
    try:
        from cryptography.hazmat.primitives import serialization
    except ImportError:
        return None                    # cannot tell on this host: the verification path reports the absence itself
    try:
        serialization.load_pem_public_key(data)
    except Exception as ex:  # noqa: BLE001 — any failure means the PEM is not a public key
        return f"PEM that does not load as a public key ({type(ex).__name__})"
    return None


_ED_P = 2 ** 255 - 19
_ED_D = (-121665 * pow(121666, _ED_P - 2, _ED_P)) % _ED_P


def _ed25519_problem(pk: bytes) -> Optional[str]:
    """Why 32 bytes cannot be an Ed25519 verification key, or None. A canonical encoding of a point of SMALL order (the
    identity, and the other torsion points) makes R=identity, S=0 a valid signature on EVERY message, and OpenSSL — hence
    `cryptography` — accepts it (measured 25/09/2026). So the key must be a canonical encoding (y < p, and no sign bit on
    x = 0) of a curve point whose [8]P is not the identity. Pure integer arithmetic (RFC 8032 §5.1.3 decoding)."""
    if len(pk) != 32:
        return f"Ed25519 key is {len(pk)} bytes, not 32"
    y = int.from_bytes(pk, "little") & ((1 << 255) - 1)
    sign = pk[31] >> 7
    if y >= _ED_P:
        return "Ed25519 key is a non-canonical encoding (y >= p)"
    u, v = (y * y - 1) % _ED_P, (_ED_D * y * y + 1) % _ED_P
    x = (u * pow(v, 3, _ED_P) * pow(u * pow(v, 7, _ED_P), (_ED_P - 5) // 8, _ED_P)) % _ED_P
    if (v * x * x - u) % _ED_P != 0:
        x = (x * pow(2, (_ED_P - 1) // 4, _ED_P)) % _ED_P
        if (v * x * x - u) % _ED_P != 0:
            return "Ed25519 key does not decode to a curve point"
    if x == 0 and sign:
        return "Ed25519 key is a non-canonical encoding (sign bit set on x = 0)"
    if (x & 1) != sign:
        x = _ED_P - x
    # [8]P with extended coordinates (X:Y:Z:T); identity is X = 0, Y = Z
    X, Y, Z, T = x, y, 1, (x * y) % _ED_P
    for _ in range(3):
        A, B = (X * X) % _ED_P, (Y * Y) % _ED_P
        C, H = (2 * Z * Z) % _ED_P, (A + B) % _ED_P
        E, G = (H - (X + Y) * (X + Y)) % _ED_P, (A - B) % _ED_P
        F = (C + G) % _ED_P
        X, Y, Z, T = (E * F) % _ED_P, (G * H) % _ED_P, (F * G) % _ED_P, (E * H) % _ED_P
    if X % _ED_P == 0 and (Y - Z) % _ED_P == 0:
        return "Ed25519 key is a point of small order: anyone can forge a signature on any message (R=identity, S=0 for the identity key; a few tries for the other small-order points)"
    return None


def _key_material_problem(key: Any) -> Optional[str]:
    """Why the relying party's key material cannot be a key in ANY form this module reads, or None when it can.

    It is a function of the material alone, never of the receipt, on purpose: the answer turns a verdict into
    `not_assessed` (a configuration defect of the relying party, not a finding about the receipt), so nothing the
    receipt carries may reach it. A usable key of another type than the receipt's `alg` (an Ed25519 key under a receipt
    that declares ES256) is NOT covered here and stays a judgment: otherwise flipping the unsigned `alg` of a forged
    receipt would downgrade its `fail` to "could not look". Forms read: 32 bytes or 64 hex (Ed25519), 1952 bytes or
    their base64 (ML-DSA-65), a PEM public key (ES256)."""
    if key is None:
        return "no key material (the entry has no 'key' member)"
    if isinstance(key, bool) or not isinstance(key, (bytes, bytearray, str)):
        return f"key material is a {type(key).__name__}, not bytes or a string"
    if isinstance(key, str):
        if _HEX64_ANYCASE.match(key):
            return _ed25519_problem(bytes.fromhex(key))
        if "-----BEGIN" in key:
            return _pem_problem(key.encode("utf-8", "replace"))
        try:
            if len(base64.b64decode(key, validate=True)) == 1952:
                return None
        except (binascii.Error, ValueError):
            pass
        return "key material string is neither 64 hex (Ed25519), base64 of 1952 bytes (ML-DSA-65) nor a PEM public key"
    b = bytes(key)
    if len(b) == 32:
        return _ed25519_problem(b)
    if len(b) == 1952:
        return None
    if b.lstrip().startswith(b"-----BEGIN"):
        return _pem_problem(b)
    return f"key material is {len(b)} bytes: neither 32 (Ed25519), 1952 (ML-DSA-65) nor a PEM public key"


# The §6.6 refusal for a signing input that carries a signature member (null and "" included). A constant, so that
# verify_receipt attaches its code by identity with THIS return, never by searching the free text.
SIGNATURE_IN_SIGNING_INPUT_WHY = "payload contains a signature member (§6.6 MUST NOT)"


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
            return "invalid", None, None, SIGNATURE_IN_SIGNING_INPUT_WHY
        return "envelope", receipt["payload"], {"alg": s.get("alg"), "kid": s.get("kid"), "sig": s.get("sig")}, ""
    if isinstance(receipt.get("signature"), str):
        body = {k: v for k, v in receipt.items() if k != "signature"}
        return "flat", body, {"alg": receipt.get("alg", "EdDSA"), "kid": receipt.get("kid", receipt.get("issuer_id")),
                              "sig": receipt["signature"]}, ""
    return "invalid", None, None, "no signature member in either shape (§6.6)"


def verify_receipt(receipt: Any, keys: Dict[str, Any], *, keys_are_complete: bool = False) -> Dict[str, Any]:
    """`keys` = {kid: public key} — 32 raw Ed25519 bytes or 64-hex str for EdDSA, 1952 raw bytes or a base64 str for ML-DSA-65,
    P-256 SubjectPublicKeyInfo PEM bytes for ES256. Keys come from the relying party, never from the receipt (§9.5).

    A value may also be `{"key": <material>, "valid_from": <RFC 3339>, "valid_until": <RFC 3339>}`; when a window is
    present the receipt's `issued_at` must fall in `[valid_from, valid_until)` (§9.2, a SHOULD that applies only when
    the window is available — see `_outside_window` for why the end is exclusive and what the check cannot catch).

    Key material that cannot be a key in any form read here (a float, an empty string, "!!!!", 5 bytes, a PEM that does
    not load) is the relying party's configuration defect, not the receipt's: the verdict is `not_assessed` with code
    `key_material_invalid`, never `fail` (see `_key_material_problem` for why it looks at the material only).

    Returns {ok, verdict, assessed, key_status, code, shape, alg, kid, why, hash, notes}. `keys` must be a mapping:
    anything else is a programming error and raises TypeError."""
    if not isinstance(keys, dict):
        raise TypeError(f"keys must be a dict {{kid: key}}, not {type(keys).__name__}")
    shape, body, sig, why = _shape(receipt)
    # `assessed` separates the absence side INSIDE the verdict: False = this host could not judge the receipt at all
    # (a missing library, an algorithm this build cannot verify, key material of the relying party that is not a key in
    # any form read here). ok=False then means "not assessed", not "invalid":
    # reporting our own missing input as a finding about the artifact is the defect this field exists to prevent.
    # `key_status` is stated in EVERY outcome (§5.5 of -04): "a verifier that does not check windows cannot be
    # mistaken for one whose check passed". Values: not_reached (the receipt was refused before the key set was even
    # consulted — the default, because saying anything else would assert what we did not measure), unknown_key,
    # no_window, inside, outside, undecidable. `code` is the machine-readable reason, null when there is none; the codes
    # emitted are issuer_not_trusted, key_not_supplied, key_outside_validity_window, key_window_undecidable and
    # key_material_invalid, and — since 26/09/2026, because agent-evidence-vectors requires a code on every refusal —
    # signature_invalid (the signature does not verify under the key) and signature_in_signing_input (§6.6). Every
    # other refusal still carries its reason in `why` and code null.
    out: Dict[str, Any] = {"ok": False, "verdict": "fail", "assessed": True, "key_status": "not_reached",
                           "code": None, "shape": shape, "alg": None, "kid": None, "why": why, "hash": None,
                           "notes": []}
    if shape == "invalid":
        if why is SIGNATURE_IN_SIGNING_INPUT_WHY:
            out["code"] = "signature_in_signing_input"
        return out
    alg, kid, sigv = sig["alg"], sig["kid"], sig["sig"]
    out.update({"alg": alg, "kid": kid})
    try:
        whole = jcs(receipt)                          # the entire receipt must canonicalize: it is the §6.7 pre-image
        msg = jcs(body)
    except (ValueError, TypeError) as ex:
        out["why"] = f"receipt not canonicalizable (§6.7): {ex}"; return out
    if alg not in ALGS:
        out["why"] = f"alg {alg!r} is outside the §6.9 profile {ALGS}: rejected (a profile judgment, not a missing capability)"; return out
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
        if not _PREV_HASH.match(v):
            out["why"] = "previousReceiptHash is not sha256:<64 lowercase hex> (§6.7)"; return out
    if "policy_digest" in body and not (isinstance(body["policy_digest"], str) and _SHA256_PREFIXED.match(body["policy_digest"])):
        # §6.8 compatibility note: an earlier-revision digest (16 hex, no prefix) is an opaque LABEL, not a commitment —
        # the signature is still checked; the chain's policy binding refuses to bind on it
        out["notes"].append("policy_digest is not an acta-policy-digest-v1 commitment (sha256:<64 hex>): an opaque label, not recomputable (§6.8)")
    entry = keys.get(kid)
    if entry is None:
        # A kid absent from `keys` is ambiguous and the caller is the only one who can resolve it: "this IS my complete
        # trust list, so that issuer is refused" (a judgment) versus "these are the keys I happen to hold" (an absence).
        # Default is the absence, because answering "invalid" about a signature this host never checked asserts
        # something it did not measure — the objection @TKCollective raised as AC-11 and @babyblueviper1 independently
        # reached in preaction-governance-conformance. `ok` stays False either way: fail-closed, never a pass.
        out["key_status"] = "unknown_key"
        if keys_are_complete:
            out["code"] = "issuer_not_trusted"
            out["why"] = f"no key for kid {kid!r}: not in the relying party's complete trust list (§9.5)"
        else:
            out["code"] = "key_not_supplied"
            out["why"] = f"no key for kid {kid!r}: the relying party supplied no key for this issuer, so the signature was NOT checked (§9.5)"
            out["assessed"] = False; out["verdict"] = "not_assessed"
        return out
    # A key may be given as the material alone (as before) or as {"key": material, "valid_from":…, "valid_until":…}.
    # The window is only checked when the relying party supplies one: §9.2 is a SHOULD "when available".
    key = entry.get("key") if isinstance(entry, dict) else entry
    has_window = isinstance(entry, dict) and (entry.get("valid_from") is not None or entry.get("valid_until") is not None)
    window = _outside_window(body["issued_at"], entry)
    if window is None:
        out["key_status"] = "inside" if has_window else "no_window"
    else:
        kind, why_w = window
        out["why"] = why_w
        if kind == "outside":
            out.update(key_status="outside", code="key_outside_validity_window")
        elif kind == "bound":
            # the relying party's window is unreadable: like unusable key material, a configuration defect — NOT a
            # finding about the receipt (26/09/2026: this was a FAIL on a valid receipt)
            out.update(key_status="undecidable", code="key_window_undecidable", assessed=False, verdict="not_assessed")
        else:
            out.update(key_status="undecidable", code="key_window_undecidable")
        return out
    problem = _key_material_problem(key)
    if problem is not None:
        out.update({"code": "key_material_invalid", "assessed": False, "verdict": "not_assessed",
                    "why": f"the relying party's key for kid {kid!r} is unusable: {problem} — a configuration defect, not a "
                           "finding about the receipt: the signature was NOT checked"})
        return out
    raw = bytes.fromhex(sigv)
    try:
        if alg == "EdDSA":
            _, Ed25519PublicKey, _ = _ed()
            if isinstance(key, str) and not _HEX64_ANYCASE.match(key):
                out["why"] = f"the key for kid {kid!r} is not an Ed25519 key, and the receipt declares EdDSA"; return out
            pk = bytes.fromhex(key) if isinstance(key, str) else bytes(key)
            if len(pk) != 32 or len(raw) != 64:
                out["why"] = "EdDSA needs a 32-byte key and a 64-byte signature"; return out
            Ed25519PublicKey.from_public_bytes(pk).verify(raw, msg)
        elif alg == "ML-DSA-65":
            try:
                from cryptography.hazmat.primitives.asymmetric import mldsa
            except ImportError:
                out["why"] = "ML-DSA-65 not verifiable on this host (cryptography >= 48): NOT verified"; out["assessed"] = False; out["verdict"] = "not_assessed"; return out
            try:
                pk = base64.b64decode(key, validate=True) if isinstance(key, str) else bytes(key)
            except (binascii.Error, ValueError):
                out["why"] = f"the key for kid {kid!r} is not an ML-DSA-65 key, and the receipt declares ML-DSA-65"; return out
            if len(pk) != 1952 or len(raw) != 3309:
                out["why"] = "ML-DSA-65 needs a 1952-byte key and a 3309-byte signature"; return out
            mldsa.MLDSA65PublicKey.from_public_bytes(pk).verify(raw, msg)
        else:  # ES256 — the draft names the algorithm but not the signature encoding: IEEE P1363 r||s is read (declared)
            from cryptography.hazmat.primitives import hashes, serialization
            from cryptography.hazmat.primitives.asymmetric import ec
            from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
            try:
                pk = serialization.load_pem_public_key(bytes(key) if isinstance(key, (bytes, bytearray)) else str(key).encode())
            except ValueError:
                out["why"] = f"the key for kid {kid!r} is not a PEM public key, and the receipt declares ES256"; return out
            if not isinstance(pk, ec.EllipticCurvePublicKey) or pk.curve.name != "secp256r1" or len(raw) != 64:
                out["why"] = "ES256 needs a P-256 key and a 64-byte r||s signature (encoding declared, not in the draft)"; return out
            s_int = int.from_bytes(raw[32:], "big")
            if s_int == 0 or s_int > P256_ORDER // 2:   # (r, n−s) verifies too and would change the §6.7 hash: only low-S is a receipt
                out["why"] = "ES256 signature is not low-S canonical (malleable twin would change the receipt hash, §6.7)"; return out
            pk.verify(encode_dss_signature(int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big")), msg, ec.ECDSA(hashes.SHA256()))
    except ImportError:
        out["why"] = "cryptography not installed: NOT verified"; out["assessed"] = False; out["verdict"] = "not_assessed"; return out
    except _unsupported() as ex:
        out["why"] = f"{alg} not verifiable on this host ({ex}): NOT verified"; out["assessed"] = False; out["verdict"] = "not_assessed"; return out
    except Exception as ex:  # noqa: BLE001 — any failure is one verdict
        out["why"] = f"signature invalid ({type(ex).__name__})"; out["code"] = "signature_invalid"; return out
    out.update({"ok": True, "verdict": "pass", "why": "ok", "hash": "sha256:" + hashlib.sha256(whole).hexdigest()})    # §6.7 pre-image: the whole receipt, both shapes
    return out


def verify_chain(receipts: List[Any], keys: Dict[str, Any], policy_files: Optional[Dict[str, bytes]] = None,
                 engine: str = "cedar", *, keys_are_complete: bool = False) -> Dict[str, Any]:
    """Every receipt verified (§5.2); §6.7 links: receipt i's previousReceiptHash == hash of receipt i-1; a genesis omits
    it; a bare-hex link is accepted on read and reported; policy_digest recomputed from `policy_files` when given."""
    problems: List[Dict[str, Any]] = []
    warnings: List[Dict[str, Any]] = []
    not_assessed: List[Dict[str, Any]] = []
    if not isinstance(receipts, list) or not receipts:
        return {"ok": False, "verdict": "fail", "assessed": True, "problems": [{"i": -1, "why": "no receipts"}],
                "warnings": [], "not_assessed": [], "verified": 0, "draft": DRAFT}
    expected_pd = policy_digest(policy_files, engine) if policy_files is not None else None      # {} raises: no policy is not a policy
    ok_n = 0
    prev: Optional[Dict[str, Any]] = None
    prev_absent = False        # the preceding receipt was NOT assessed here (not: it failed) — the link inherits that
    for i, r in enumerate(receipts):
        v = verify_receipt(r, keys, keys_are_complete=keys_are_complete)
        if not v["ok"]:
            # A not-assessed receipt stays in `problems` on purpose: `ok` must never read True over a receipt this host
            # could not verify (fail-closed). `not_assessed` says WHY the run is inconclusive rather than adverse.
            problems.append({"i": i, "why": v["why"], "assessed": v["assessed"]})
            if not v.get("assessed", True):
                not_assessed.append({"i": i, "why": v["why"]})
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
                why = "previous receipt did not verify: the link cannot be checked (§6.7)"
                problems.append({"i": i, "why": why, "assessed": True})
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
        # The §6.7 link is a hash: it needs no signature backend. Keeping `prev` over a receipt this host could not
        # ASSESS (rather than one that failed) keeps the link checkable, so a broken link stays a judgment.
        prev = r if (v["ok"] or not v.get("assessed", True)) else None
    # One total order, FAIL > NOT_ASSESSED > PASS: an adverse finding always wins, an absence never hides one and
    # never becomes a pass. Two independent booleans could not express this — that is how the first fix got it wrong.
    adverse = any(p.get("assessed", True) for p in problems)
    verdict = "fail" if adverse else ("not_assessed" if problems else "pass")
    return {"ok": not problems, "verdict": verdict, "assessed": verdict != "not_assessed",
            "problems": problems, "warnings": warnings,
            "not_assessed": not_assessed, "verified": ok_n, "receipts": len(receipts), "draft": DRAFT,
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
            files[n] = read_regular(os.path.join(policy_dir, n))
    pd = policy_digest(files, "cedar")
    policy_text = "\n".join(f.decode("utf-8") for f in files.values())
    pub = pubkey_from_seed(seed_hex)
    kid = issuer_kid(pub)
    os.makedirs(out_dir, exist_ok=True)
    prev = None
    summary = {"kid": kid, "public_key_hex": pub.hex(), "policy_digest": pd, "receipts": []}
    inputs = sorted(f for f in os.listdir(inputs_dir) if f.endswith(".json"))
    for n, fname in enumerate(inputs, 1):
        inp = json.loads(read_regular(os.path.join(inputs_dir, fname)).decode("utf-8"))
        seq = inp.get("sequence", n)
        if not isinstance(seq, int) or isinstance(seq, bool) or not 1 <= seq <= 999:
            raise ValueError(f"{fname}: sequence must be an integer in 1..999 (it becomes the millisecond of issued_at)")
        decision, reasons = evaluate_cedar(policy_text, inp["tool_name"], inp.get("context") or {})
        # issued_at: the run's UTC clock, or a fixed base (reproducible signatures across runs); the sequence is the millisecond
        if issued_at_base is not None and not (isinstance(issued_at_base, str) and _UTC_SECONDS.match(issued_at_base) and _valid_instant(issued_at_base)):
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


def _json_nesting_exceeds(text: str, limit: int) -> bool:
    """True when `text` nests arrays/objects deeper than `limit`. A linear scan that skips string contents, run BEFORE
    the parser: Python's json module recurses once per level and raised RecursionError on 100 000-deep input, whose
    message named the interpreter rather than the input."""
    depth, in_str, esc = 0, False, False
    for ch in text:
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
        elif ch == '"':
            in_str = True
        elif ch in "[{":
            depth += 1
            if depth > limit:
                return True
        elif ch in "]}":
            depth -= 1
    return False


def load_json_strict(path: str, what: str = "JSON") -> Any:
    """The one reader for every JSON input of the CLI (receipts, --previous, --jwks): duplicate member names refused
    (RFC 8785 §3.1 — last-wins would let the file say two things), NaN/Infinity refused, and nesting deeper than
    JCS_MAX_DEPTH (512) refused before parsing, with a message that says so."""
    text = read_regular(path).decode("utf-8")
    if _json_nesting_exceeds(text, JCS_MAX_DEPTH):
        raise ValueError(f"{what} {path}: nesting deeper than {JCS_MAX_DEPTH} levels refused (the JCS limit of this module)")
    return json.loads(text, parse_constant=_no_constant, object_pairs_hook=_no_dup_keys)


def _b64url_ed25519_x(kid: str, x: Any) -> bytes:
    """RFC 8037 §2 `x` of an Ed25519 key: base64url WITHOUT padding (RFC 7515 §2), exactly 32 bytes, canonical. The
    decoder of the standard library is not validating — it drops characters outside the alphabet and accepts padding —
    so a JWK with `=` or trailing junk used to load as the same key; here the text itself is checked: decoded, it must
    be 32 bytes, and re-encoded it must give back exactly `x` (which admits only the 43 url-safe characters, no padding,
    no alternative last character)."""
    bad = ValueError(f"kid {kid!r}: x is not the canonical unpadded base64url encoding of 32 bytes (RFC 8037 §2, RFC 7515 §2)")
    if not isinstance(x, str):
        raise bad
    try:
        raw = base64.urlsafe_b64decode(x + "=" * (-len(x) % 4))
    except (binascii.Error, ValueError):
        raise bad from None
    if len(raw) != 32 or base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii") != x:
        raise bad
    problem = _ed25519_problem(raw)
    if problem:
        raise ValueError(f"kid {kid!r}: {problem}")
    return raw


# JWK members that name what a key is for. When present they must say "Ed25519 signature verification": a key published
# for encryption (`use: enc`) or for another algorithm must not verify receipts because this reader never looked.
_JWK_COMPATIBLE = {"kty": ("OKP",), "crv": ("Ed25519",), "alg": ("EdDSA", "Ed25519"), "use": ("sig",)}


def keys_from_jwks(doc: Any, ignored: Optional[List[str]] = None) -> Dict[str, Any]:
    """A JWK Set (RFC 7517 §5, `{"keys": [...]}`) → the `keys` argument of `verify_receipt`: {kid: {"key": 32 bytes,
    "valid_from"?, "valid_until"?}}. Ed25519 verification keys only (OKP, RFC 8037).

    IGNORED (RFC 7517 §5: "SHOULD ignore JWKs ... not understood ... or out of the supported ranges"; since 26/09/2026,
    before which one such key made the whole set unusable): a JWK whose `kty`/`crv`/`alg`/`use` do not say OKP /
    Ed25519 / EdDSA or Ed25519 / sig, or whose `key_ops` does not include "verify". An ignored key verifies nothing — a
    receipt under its kid finds no key — and is listed in `ignored` when the caller passes a list (the CLI prints it).
    Library callers that pass no list are not told.

    REFUSED (ValueError), never skipped or resolved by order: a kid that appears twice, ignored entries included (RFC 7517
    §4.5); a JWK of OUR type with `x` but without `kty` or `crv`; `x` that is not strict base64url of 32 bytes; a small-
    order key; `x` and `public_key_hex` together; a valid_from/valid_until that is not an RFC 3339 instant (null =
    absent). `public_key_hex` (64 hex) is read as a non-JWK extension, with the same compatibility rule."""
    if not isinstance(doc, dict) or not isinstance(doc.get("keys"), list):
        raise ValueError("expected an object with a 'keys' array (RFC 7517 §5)")
    out: Dict[str, Any] = {}
    seen = set()
    for n, k in enumerate(doc["keys"]):
        if not isinstance(k, dict) or not isinstance(k.get("kid"), str) or not k["kid"]:
            raise ValueError(f"keys[{n}]: every key needs a non-empty string kid")
        kid = k["kid"]
        if kid in seen:        # over EVERY entry, ignored ones included: two entries under one kid stay ambiguous
            raise ValueError(f"kid {kid!r} appears twice: ambiguous (RFC 7517 §4.5), refused rather than resolved by order")
        seen.add(kid)
        # RFC 7517 §5: implementations SHOULD IGNORE JWKs whose kty they do not understand or whose values are outside
        # the supported ranges. Refusing the whole set for one EC key beside ours made the set unusable (measured
        # 26/09/2026). An ignored key verifies nothing: a receipt under its kid finds no key (never a pass).
        # key_ops (RFC 7517 §4.3), when present, must include "verify": a key published only for other operations
        # verified receipts before 26/09/2026 because this reader never looked at the member (measured).
        why_not = next((f"{member}={k[member]!r}" for member, allowed in _JWK_COMPATIBLE.items()
                        if member in k and k[member] not in allowed), None)
        if why_not is None and "key_ops" in k and not (isinstance(k["key_ops"], list) and "verify" in k["key_ops"]):
            why_not = f"key_ops={k['key_ops']!r} does not include verify"
        if why_not is not None:
            if ignored is not None:
                ignored.append(f"kid {kid!r} ignored: {why_not} (not an Ed25519 verification key; RFC 7517 §5)")
            continue
        if "x" in k and "public_key_hex" in k:
            raise ValueError(f"kid {kid!r}: carries both x and public_key_hex: ambiguous, refused")
        if "x" in k:
            for member in ("kty", "crv"):
                if member not in k:
                    raise ValueError(f"kid {kid!r}: a JWK must carry {member} (RFC 7517 §4.1 / RFC 8037 §2)")
            mat: Any = _b64url_ed25519_x(kid, k["x"])
        elif isinstance(k.get("public_key_hex"), str) and _HEX64_ANYCASE.match(k["public_key_hex"]):
            mat = bytes.fromhex(k["public_key_hex"])
            problem = _ed25519_problem(mat)
            if problem:
                raise ValueError(f"kid {kid!r}: {problem}")
        else:
            raise ValueError(f"kid {kid!r} carries no readable key material (x per RFC 8037, or public_key_hex of 64 hex)")
        entry: Dict[str, Any] = {"key": mat}
        for w in ("valid_from", "valid_until"):
            if w in k and k[w] is not None:            # null = absent
                if _instant_exact(k[w]) is None:
                    raise ValueError(f"kid {kid!r}: {w}={k[w]!r} is not an RFC 3339 instant: the key set is unusable as given")
                entry[w] = k[w]
        out[kid] = entry
    return out


def _cli_key(spec: str) -> Tuple[str, Any]:
    """`--key kid=<64 hex | file>` → (kid, material). The material is checked here, at load: a keyfile the verifier
    cannot read as a key is a usage error (exit 2), never a verdict on the receipt."""
    if "=" not in spec:
        raise ValueError(f"--key expects kid=<64 hex Ed25519 public key | file>, got {spec!r} (no '=')")
    kid, val = spec.split("=", 1)
    if not kid or not val:
        raise ValueError(f"--key expects kid=<64 hex Ed25519 public key | file>, got {spec!r} (empty kid or value)")
    if _HEX64_ANYCASE.match(val):
        problem = _ed25519_problem(bytes.fromhex(val))
        if problem:
            raise ValueError(f"--key {kid}=…: unusable key material: {problem}")
        return kid, val.lower()
    data = read_regular(val)
    try:
        txt = data.decode("ascii").strip()
    except UnicodeDecodeError:
        txt = ""
    mat: Any = txt.lower() if _HEX64_ANYCASE.match(txt) else _spki_material(data)   # hex keyfile (any case), or raw / PEM / DER
    problem = _key_material_problem(mat)
    if problem is not None:
        raise ValueError(f"--key {kid}={val}: unusable key material: {problem}")
    return kid, mat


def _spki_material(data: bytes) -> Any:
    """A public key file in SubjectPublicKeyInfo form, PEM or DER. An Ed25519 key becomes its 32 raw bytes — what
    verify_receipt expects for EdDSA; before, a VALID Ed25519 PEM key was loaded as PEM text and every receipt it should
    have verified came back FAIL "EdDSA needs a 32-byte key" (measured 26/09/2026), and DER was refused. A P-256 key is
    kept (DER re-encoded as PEM) for ES256. Anything else is returned unchanged for the material check to judge."""
    try:
        from cryptography.hazmat.primitives import serialization as ser
        from cryptography.hazmat.primitives.asymmetric import ec, ed25519
    except ImportError:
        return data
    for load in (ser.load_pem_public_key, ser.load_der_public_key):
        try:
            pk = load(data)
        except (ValueError, TypeError):
            continue
        if isinstance(pk, ed25519.Ed25519PublicKey):
            return pk.public_bytes(ser.Encoding.Raw, ser.PublicFormat.Raw)
        if isinstance(pk, ec.EllipticCurvePublicKey):
            return pk.public_bytes(ser.Encoding.PEM, ser.PublicFormat.SubjectPublicKeyInfo)
        return data
    return data


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
    v.add_argument("files", nargs="+", help="receipt files; every input must be a regular file (a FIFO or device is refused, "
                                            "so a pipe or /dev/stdin is not accepted: use a redirect, `verify /dev/stdin < r.json`)")
    v.add_argument("--key", action="append", default=[],
                                                       help="kid=<64 hex Ed25519 | file>; unusable key material is refused at load (exit 2)")
    v.add_argument("--jwks", help="JWKS file: the relying party's Ed25519 key set, with valid_from/valid_until when it declares them "
                                  "(§5.5). Keys of another type or use (kty/crv/alg/use, key_ops without verify) are ignored and named on stderr "
                                  "(RFC 7517 §5); duplicate kids, a malformed Ed25519 key or window are refused (exit 2)")
    v.add_argument("--keys-are-complete", action="store_true",
                   help="declare this key set to be the whole trust list: an unknown kid is then a refusal, not an absence")
    v.add_argument("--policy-dir"); v.add_argument("--policy-ext", default=".cedar")
    d = sub.add_parser("policy-digest"); d.add_argument("policy_dir"); d.add_argument("--engine", default="cedar"); d.add_argument("--ext", default=".cedar")
    r = sub.add_parser("run-vectors", help="drive ScopeBlind/agent-governance-testvectors")
    r.add_argument("repo_root"); r.add_argument("out_dir"); r.add_argument("--seed", required=True, help="64-hex Ed25519 seed"); r.add_argument("--issued-at-base")
    a = p.parse_args(argv)
    try:
        if a.cmd == "policy-digest":
            print(policy_digest_from_dir(a.policy_dir, a.engine, a.ext)); return 0
        if a.cmd == "sign":
            seed = read_regular(a.key, 4096).decode("utf-8").strip()      # a FIFO/device seed file no longer blocks
            pub = pubkey_from_seed(seed); kid = issuer_kid(pub)
            prev = None
            if a.previous:
                prev = load_json_strict(a.previous, "--previous")
            pd = policy_digest_from_dir(a.policy_dir, "cedar", a.policy_ext) if a.policy_dir else None
            rec = sign_receipt(decision_payload(a.tool, a.decision, kid, a.issued_at, pd, a.session, a.reason, prev), seed, kid)
            with open(a.out, "w", encoding="utf-8") as f:
                json.dump(rec, f, indent=2); f.write("\n")
            print(json.dumps({"ok": True, "kid": kid, "hash": receipt_hash(rec)})); return 0
        if a.cmd == "verify":
            keys: Dict[str, Any] = {}
            if a.jwks:
                # A JWKS is how a relying party normally holds keys, and it is the invocation the public conformance
                # vectors declare. Windows are carried over when the set states them: §5.5 applies them to issued_at.
                # Read with the same strict parser as the receipts, and by `keys_from_jwks`: every refusal is exit 2.
                try:
                    ignored: List[str] = []
                    keys.update(keys_from_jwks(load_json_strict(a.jwks, "file"), ignored))
                    for note in ignored:
                        print(f"note: --jwks {note}", file=sys.stderr)
                except ValueError as ex:
                    print(json.dumps({"ok": False, "error": f"--jwks: {ex}"})); return 2
            for spec in a.key:
                kid, mat = _cli_key(spec)
                if kid in keys:
                    # Two sources for one kid: the later one used to replace the earlier one silently, dropping its window.
                    raise ValueError(f"--key {kid}: this kid is already supplied (by --jwks or an earlier --key): ambiguous, refused")
                keys[kid] = mat
            recs = []
            for fn in a.files:
                recs.append(load_json_strict(fn, "receipt"))
            files = None
            if a.policy_dir:
                files = {}
                for n in os.listdir(a.policy_dir):
                    if n.endswith(a.policy_ext):
                        files[n] = read_regular(os.path.join(a.policy_dir, n))
                if not files:
                    raise ValueError(f"--policy-dir {a.policy_dir} holds no {a.policy_ext} file: nothing to bind the receipts to")
            complete = bool(getattr(a, "keys_are_complete", False))
            out = (verify_chain(recs, keys, files, keys_are_complete=complete) if len(recs) > 1 or a.policy_dir
                   else verify_receipt(recs[0], keys, keys_are_complete=complete))
            print(json.dumps(out, indent=1))
            return {"pass": 0, "fail": 1, "not_assessed": 77}[out["verdict"]]   # 77 only when NOTHING adverse was found
        if a.cmd == "run-vectors":
            print(json.dumps(run_vectors(a.repo_root, a.out_dir, a.seed, a.issued_at_base), indent=1)); return 0
    except (OSError, ValueError, TypeError, KeyError, RecursionError, json.JSONDecodeError) as ex:
        print(json.dumps({"ok": False, "error": f"{type(ex).__name__}: {ex}"})); return 2
    except ImportError as ex:
        print(json.dumps({"ok": False, "error": f"dependency missing: {ex}"})); return 77
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
