#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""cryptovalid-opencore — transparency-log CHECKPOINTS and SIGNED NOTES (0.14.0, 2026-09-19).

Implements, byte for byte, three public specifications used by the transparency ecosystem (Sigstore, Go sum DB, the
transparency-dev witnesses; editor's copies downloaded 2026-09-19 from github.com/C2SP/C2SP):
  - c2sp.org/tlog-checkpoint  : note text = origin \\n tree size \\n base64(RFC 6962 root) [\\n extension lines]
  - c2sp.org/signed-note      : text \\n blank line \\n "— <key name> base64(4-byte key ID || signature)" lines
  - c2sp.org/tlog-cosignature : Ed25519 cosignature/v1 = type 0x04, signature over
                                "cosignature/v1\\ntime <unix>\\n" || note text, prefixed by the 8-byte big-endian timestamp

The root hash is the RFC 6962 Merkle tree hash of the ledger's entries (cryptovalid_merkle.leaves_from_ledger: the
canonical entry bytes, the same leaves the inclusion and consistency proofs use), so a checkpoint of a cryptovalid ledger
is a standard checkpoint that any C2SP verifier can check — the Go reference (golang.org/x/mod/sumdb/note and
github.com/transparency-dev/formats/note) is the oracle in tests/CI.

Why this exists (README "Declared limits", 2026-08-17): split-view/equivocation and rollback/freshness were "future
work". A witness that keeps the last checkpoint it cosigned, demands a consistency proof for every new one and refuses to
cosign an inconsistent one, turns two contradicting log-signed checkpoints into EVIDENCE of equivocation, and its
timestamped cosignature gives a relying party freshness — see cryptovalid_witness.py.

Honest scope: signing needs `cryptography` (Ed25519); without it a well-formed note is NON_VERIFICATA, never OK or
NON_VALIDA on its signatures (a structurally malformed note is NON_VALIDA on structure alone, with or without it).
Verified: Ed25519 log signatures (0x01), ECDSA log signatures (0x02, P-256/384/521 — Rekor v1), Ed25519 cosignature/v1
(0x04) and ML-DSA-44 cosignature/v1 (0x06, `cryptography` with the `mldsa` module — measured with 49.0.0). Emitted: 0x01,
0x04, 0x06. RFC 6962 THS keys (0x05) and unassigned types are UNKNOWN keys here and are ignored as the spec allows.
"""
from __future__ import annotations
import base64
import hashlib
import json
import re
import struct
import sys
from typing import Dict, List, Optional, Tuple

TYPE_ED25519 = 0x01
TYPE_ECDSA = 0x02        # ECDSA (P-256/384/521, SHA-256 digest, ASN.1 signature) as transparency-dev/witness implements it:
                         # key id = SHA-256(DER SPKI)[:4]; the type of Rekor v1's log key. Verified here, never emitted.
TYPE_COSIG_V1 = 0x04
TYPE_MLDSA44 = 0x06      # ML-DSA-44 cosignature/v1 (FIPS 204, empty context): key id = SHA-256(name || 0x0A || 0x06 || pub)[:4]
MLDSA44_PUB, MLDSA44_SIG = 1312, 2420
SUPPORTED_TYPES = (TYPE_ED25519, TYPE_ECDSA, TYPE_COSIG_V1, TYPE_MLDSA44)
EM_DASH = "—"
_NAME_OK = re.compile(r"[^\s+\x00-\x1f]+")       # signed-note: key names have no Unicode spaces and no '+'; fullmatch
# origins: any non-empty line without control characters, on emission and on parsing alike — the schema-less-URL form
# is a SHOULD of tlog-checkpoint and production logs ("Armory Drive Prod 2", "go.sum database tree") do not follow it
_MAX_SIGS = 100                               # signed-note: "MUST accept at least up to 16"; 100 = golang.org/x/mod/sumdb/note (parity)
_MAX_NAME_BYTES = 255                         # cosigner names: transparency-dev/formats (2026-09) refuses longer vkeys; we emit none longer
_MAX_SIG_BYTES = 8192                         # per line, decoded: Ed25519 lines are 68/76 bytes, ML-DSA-44 ≈ 2.5 KB (a stated limit,
                                              # the spec lets verifiers cap the size; a note is not a channel for padding)


class NoteError(ValueError):
    pass


_B64_STRICT = re.compile(r"(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?")


def b64decode_strict(s: str) -> bytes:
    """Standard base64 exactly as Go's encoding/base64 accepts it: full quanta, padding only inside the last one.
    Python's validate=True lets an extra '=' open a new quantum (and 3.9 is laxer still): a note Go would call
    malformed must not open here (round 8)."""
    if not isinstance(s, str) or not _B64_STRICT.fullmatch(s):
        raise ValueError("not strict standard base64")
    return base64.b64decode(s, validate=True)


def _ed():
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
        from cryptography.exceptions import InvalidSignature
        return Ed25519PrivateKey, Ed25519PublicKey, InvalidSignature
    except ImportError:
        return None, None, None


# ── keys ──────────────────────────────────────────────────────────────────────────────────────────────────────────
def key_id(name: str, sig_type: int, pub: bytes) -> bytes:
    """SHA-256(name || 0x0A || type || public key)[:4] — signed-note §Signatures."""
    return hashlib.sha256(name.encode("utf-8") + b"\n" + bytes([sig_type]) + pub).digest()[:4]


def vkey(name: str, sig_type: int, pub: bytes) -> str:
    """Verifier key string: <name>+<hex key id>+base64(type || public key)."""
    if not _NAME_OK.fullmatch(name or ""):
        raise NoteError("key name must be non-empty, without spaces, '+' or control characters")
    if len(name.encode("utf-8")) > _MAX_NAME_BYTES:
        raise NoteError(f"key name longer than {_MAX_NAME_BYTES} bytes (transparency-dev formats refuses such a vkey)")
    if sig_type in (TYPE_ED25519, TYPE_COSIG_V1):
        if len(pub) != 32:
            raise NoteError("Ed25519 public key must be 32 bytes")
    elif sig_type == TYPE_MLDSA44:
        if len(pub) != MLDSA44_PUB:
            raise NoteError(f"ML-DSA-44 public key must be {MLDSA44_PUB} bytes")
    else:
        raise NoteError("this implementation emits Ed25519 (0x01), cosignature/v1 (0x04) and ML-DSA-44 (0x06) keys only")
    return f"{name}+{key_id(name, sig_type, pub).hex()}+{base64.b64encode(bytes([sig_type]) + pub).decode('ascii')}"


def vkey_ecdsa(name: str, der_spki: bytes) -> str:
    """Verifier key of an ECDSA log key from its DER SPKI (what `rekor.sigstore.dev/api/v1/log/publicKey` serves as
    PEM): id = SHA-256(DER)[:4], as transparency-dev/formats computes it."""
    if not _NAME_OK.fullmatch(name or ""):
        raise NoteError("key name must be non-empty, without spaces, '+' or control characters")
    kid = hashlib.sha256(der_spki).digest()[:4]
    return f"{name}+{kid.hex()}+{base64.b64encode(bytes([TYPE_ECDSA]) + der_spki).decode('ascii')}"


def parse_vkey(s: str, strict: bool = True) -> Tuple[str, bytes, int, bytes]:
    """→ (name, key id, type, public key). The key id MUST match the recomputed one (a mistyped vkey is refused).
    strict=False returns a well-formed vkey of a type this implementation cannot verify (RFC 6962 THS 0x05, unassigned
    types) instead of raising, so that verify_note can IGNORE it as an unknown key."""
    parts = (s or "").split("+", 2)      # at most two cuts: the base64 material may itself contain '+'
    if len(parts) != 3 or not _NAME_OK.fullmatch(parts[0]):
        raise NoteError("vkey must be <name>+<hex id>+<base64>")
    if not re.fullmatch(r"[0-9a-fA-F]{8}", parts[1]):   # exactly 8 hex digits (bytes.fromhex would accept spaces)
        raise NoteError("vkey id must be 8 hex digits")
    try:
        kid = bytes.fromhex(parts[1]); mat = b64decode_strict(parts[2])
    except ValueError as e:              # binascii.Error is a ValueError; so is a non-ASCII string
        raise NoteError(f"vkey encoding: {e}") from None
    if len(mat) < 2:
        raise NoteError("vkey material must be at least 2 bytes")
    typ, pub = mat[0], mat[1:]
    if typ in (TYPE_COSIG_V1, TYPE_MLDSA44) and len(parts[0].encode("utf-8")) > _MAX_NAME_BYTES:
        raise NoteError(f"cosigner key name longer than {_MAX_NAME_BYTES} bytes (transparency-dev formats refuses it)")
    if typ == TYPE_ECDSA:                 # id = SHA-256(DER SPKI)[:4]; the curve is checked when the key is loaded
        if hashlib.sha256(pub).digest()[:4] != kid:
            raise NoteError("ECDSA vkey key id does not match the DER key")
        return parts[0], kid, typ, pub
    if typ not in SUPPORTED_TYPES:
        # RFC 6962 THS (0x05) hashes a hash of the SPKI, unassigned types are unknown: their ids are not ours to
        # recompute; the vkey is returned as-is for the caller to IGNORE (round 4: a real Rekor v1 vkey raised here)
        if strict:
            raise NoteError(f"unsupported vkey type 0x{typ:02x}")
        return parts[0], kid, typ, pub
    want = MLDSA44_PUB if typ == TYPE_MLDSA44 else 32
    if len(pub) != want:
        raise NoteError(f"vkey material for type 0x{typ:02x} must be {want} bytes, got {len(pub)}")
    if key_id(parts[0], typ, pub) != kid:
        raise NoteError("vkey key id does not match name/type/key")
    return parts[0], kid, typ, pub


def load_seed_hex(path: str) -> bytes:
    with open(path, encoding="utf-8") as f:
        try:
            seed = bytes.fromhex(f.read().strip())
        except ValueError:
            raise NoteError("key file is not hex") from None
    if len(seed) != 32:
        raise NoteError("key file must hold a 32-byte hex seed (signer.py keygen)")
    return seed


def pubkey_from_seed(seed: bytes) -> bytes:
    Ed, _, _ = _ed()
    if Ed is None:
        raise NoteError("signing needs `cryptography`")
    from cryptography.hazmat.primitives import serialization as ser
    return Ed.from_private_bytes(seed).public_key().public_bytes(ser.Encoding.Raw, ser.PublicFormat.Raw)


# ── checkpoint text ────────────────────────────────────────────────────────────────────────────────────────────────
def checkpoint_text(origin: str, size: int, root: bytes, extensions: Optional[List[str]] = None) -> str:
    if not origin or any(ord(c) < 0x20 for c in origin):   # tlog-checkpoint: non-empty; a schema-less URL is only a SHOULD
        raise NoteError("origin must be a non-empty line without control characters")   # ("Armory Drive Prod 2" is a real origin)
    if not isinstance(size, int) or isinstance(size, bool) or not (0 <= size <= 2 ** 64 - 1):
        raise NoteError("tree size must be an integer in [0, 2^64-1]")
    if len(root) != 32:
        raise NoteError("root must be 32 bytes (SHA-256 RFC 6962 tree hash)")
    lines = [origin, str(size), base64.b64encode(root).decode("ascii")]
    for e in extensions or []:
        if not e or any(ord(c) < 0x20 for c in e):
            raise NoteError("extension lines must be non-empty and without control characters")
        lines.append(e)
    return "\n".join(lines) + "\n"


def parse_checkpoint(text: str) -> Dict:
    """→ {origin, size, root (bytes), extensions}. Strict on size and root (no leading zeroes, canonical base64 of 32
    bytes); the origin is any non-empty line without control characters — production origins such as
    "go.sum database tree" or "rekor.sigstore.dev - 3904496407287907110" contain spaces (review of 2026-09-19)."""
    if not text.endswith("\n"):
        raise NoteError("checkpoint text must end with a newline")
    lines = text[:-1].split("\n")
    if len(lines) < 3 or any(not l for l in lines):
        raise NoteError("checkpoint needs at least three non-empty lines")
    if any(ord(c) < 0x20 for c in text[:-1].replace("\n", "")):
        raise NoteError("checkpoint contains control characters")
    origin, size_s, root_s = lines[0], lines[1], lines[2]
    if not re.fullmatch(r"0|[1-9][0-9]{0,19}", size_s) or int(size_s) > 2 ** 64 - 1:   # uint64 (≤ 20 digits: int() never
        raise NoteError("tree size must be ASCII decimal without leading zeroes, at most 2^64-1")   # sees a huge string)
    try:
        root = b64decode_strict(root_s)
    except ValueError:                   # binascii.Error or non-ASCII
        raise NoteError("root hash is not standard base64") from None
    if len(root) != 32 or base64.b64encode(root).decode("ascii") != root_s:
        raise NoteError("root hash must be the canonical base64 of 32 bytes")
    return {"origin": origin, "size": int(size_s), "root": root, "extensions": lines[3:]}


# ── notes ──────────────────────────────────────────────────────────────────────────────────────────────────────────
def _check_note_bytes(b: bytes) -> str:
    try:
        s = b.decode("utf-8")
    except UnicodeDecodeError:
        raise NoteError("note is not valid UTF-8") from None
    if any(ord(c) < 0x20 and c != "\n" for c in s):   # signed-note: below U+0020 other than newline (Go: the same)
        raise NoteError("note contains ASCII control characters")
    return s


def split_note(b: bytes) -> Tuple[str, List[Tuple[str, bytes]]]:
    """→ (text with its final newline, [(key name, raw 4+n bytes)]) — the text is separated from the signatures by the
    LAST empty line; every signature line is '— <name> <base64>'."""
    s = _check_note_bytes(b)
    if not s.endswith("\n"):
        raise NoteError("note must end with a newline")
    i = s.rfind("\n\n")
    if i < 0:
        raise NoteError("note has no blank line separating text and signatures")
    text, sig_block = s[:i + 1], s[i + 2:]   # like Go's note.Open: the text may be a single empty line
    sigs = []
    for line in sig_block[:-1].split("\n"):
        if len(sigs) >= _MAX_SIGS:       # refused before decoding the next line (no work on an oversized note)
            raise NoteError(f"more than {_MAX_SIGS} signature lines")
        parts = line.split(" ")
        if len(parts) != 3 or parts[0] != EM_DASH or not _NAME_OK.fullmatch(parts[1]):
            raise NoteError("malformed signature line")
        if len(parts[2]) > (_MAX_SIG_BYTES * 4 + 2) // 3 + 3:   # refused before decoding a huge line
            raise NoteError(f"signature line longer than {_MAX_SIG_BYTES} bytes")
        try:
            raw = b64decode_strict(parts[2])
        except ValueError:
            raise NoteError("signature is not standard base64") from None
        if len(raw) < 5:
            raise NoteError("signature shorter than key id + 1 byte")
        if len(raw) > _MAX_SIG_BYTES:
            raise NoteError(f"signature line longer than {_MAX_SIG_BYTES} bytes")
        sigs.append((parts[1], raw))
    return text, sigs      # never empty: an empty signature block is one empty line, refused above as malformed


def _sig_line(name: str, kid: bytes, sig: bytes) -> str:
    if not _NAME_OK.fullmatch(name or ""):   # a name with a space would produce a line no parser (ours, Go) can read
        raise NoteError("key name must be non-empty, without spaces, '+' or control characters")
    if len(name.encode("utf-8")) > _MAX_NAME_BYTES:
        raise NoteError(f"key name longer than {_MAX_NAME_BYTES} bytes")
    return f"{EM_DASH} {name} {base64.b64encode(kid + sig).decode('ascii')}\n"


def sign_note(text: str, name: str, seed: bytes) -> bytes:
    """Log signature (type 0x01): Ed25519 over the note text. Returns the whole note (text, blank line, one signature)."""
    if not text.endswith("\n") or not text:
        raise NoteError("text must be non-empty and end with a newline")
    _check_note_bytes(text.encode("utf-8"))   # empty lines inside the text are fine: the separator is the LAST empty line
    Ed, _, _ = _ed()
    if Ed is None:
        raise NoteError("signing needs `cryptography`")
    sk = Ed.from_private_bytes(seed); pub = pubkey_from_seed(seed)
    sig = sk.sign(text.encode("utf-8"))
    return (text + "\n" + _sig_line(name, key_id(name, TYPE_ED25519, pub), sig)).encode("utf-8")


def cosign_v1(note: bytes, name: str, seed: bytes, timestamp: int) -> bytes:
    """Append an Ed25519 cosignature/v1 (type 0x04) line to a checkpoint note; returns the new note bytes."""
    text, sigs = split_note(note)
    parse_checkpoint(text)
    if len(sigs) >= _MAX_SIGS:
        raise NoteError(f"no room for a cosignature line: {len(sigs)} signature lines, verifiers accept {_MAX_SIGS}")
    if not isinstance(timestamp, int) or isinstance(timestamp, bool) or not (1 <= timestamp <= 2 ** 63 - 1):
        raise NoteError("timestamp must be a POSIX integer in [1, 2^63-1] (tlog-witness: MUST NOT be zero)")
    Ed, _, _ = _ed()
    if Ed is None:
        raise NoteError("signing needs `cryptography`")
    sk = Ed.from_private_bytes(seed); pub = pubkey_from_seed(seed)
    msg = f"cosignature/v1\ntime {timestamp}\n".encode("utf-8") + text.encode("utf-8")
    sig = struct.pack(">Q", timestamp) + sk.sign(msg)
    return note + _sig_line(name, key_id(name, TYPE_COSIG_V1, pub), sig).encode("utf-8")


def _mldsa():
    try:
        from cryptography.hazmat.primitives.asymmetric import mldsa
        return mldsa
    except ImportError:
        return None


def mldsa44_pubkey_from_seed(seed: bytes) -> bytes:
    m = _mldsa()
    if m is None:
        raise NoteError("ML-DSA-44 needs `cryptography` with the `mldsa` module (measured with 49.0.0)")
    return m.MLDSA44PrivateKey.from_seed_bytes(seed).public_key().public_bytes_raw()


def mldsa44_message(cosigner: str, timestamp: int, origin: str, start: int, end: int, root: bytes) -> bytes:
    """tlog-cosignature §"ML-DSA-44 signed message": TLS presentation encoding of cosigned_message."""
    cn, og = cosigner.encode("utf-8"), origin.encode("utf-8")
    if not (1 <= len(cn) <= 255 and 1 <= len(og) <= 255):
        raise NoteError("cosigner name and origin must be 1..255 bytes")
    if start and timestamp:
        raise NoteError("a subtree cosignature (start > 0) has timestamp 0")
    if len(root) != 32:
        raise NoteError("root must be 32 bytes")
    return (b"subtree/v1\n\x00" + bytes([len(cn)]) + cn + struct.pack(">Q", timestamp) + bytes([len(og)]) + og
            + struct.pack(">QQ", start, end) + root)


def cosign_v1_mldsa44(note: bytes, name: str, seed: bytes, timestamp: int) -> bytes:
    """Append an ML-DSA-44 cosignature/v1 (type 0x06, FIPS 204 pure mode, empty context) over the checkpoint's
    origin/size/root — the spec's signed message, which does NOT cover extension lines (stated by the spec)."""
    text, sigs = split_note(note)
    cp = parse_checkpoint(text)
    if len(sigs) >= _MAX_SIGS:
        raise NoteError(f"no room for a cosignature line: {len(sigs)} signature lines, verifiers accept {_MAX_SIGS}")
    if not isinstance(timestamp, int) or isinstance(timestamp, bool) or not (1 <= timestamp <= 2 ** 63 - 1):
        raise NoteError("timestamp must be a POSIX integer in [1, 2^63-1] (tlog-witness: MUST NOT be zero)")
    m = _mldsa()
    if m is None:
        raise NoteError("ML-DSA-44 needs `cryptography` with the `mldsa` module (measured with 49.0.0)")
    sk = m.MLDSA44PrivateKey.from_seed_bytes(seed); pub = sk.public_key().public_bytes_raw()
    sig = sk.sign(mldsa44_message(name, timestamp, cp["origin"], 0, cp["size"], cp["root"]))
    return note + _sig_line(name, key_id(name, TYPE_MLDSA44, pub), struct.pack(">Q", timestamp) + sig).encode("utf-8")


def verify_note(note: bytes, vkeys: List[str]) -> Dict:
    """Verify a note against known vkeys (signed-note §Signatures): signatures from unknown (name, id) pairs are
    ignored — including vkeys of types this implementation cannot verify (0x05, unassigned: `ignored_vkeys`); a
    known key that fails → the whole note is NON_VALIDA; no known key verifying → NON_VALIDA. EVERY line whose
    (name, id) matches a known key is verified — the spec's MUST; golang.org/x/mod/sumdb/note verifies the first
    line per key and drops repeats, so a note with a bogus repeat opens there and is NON_VALIDA here (declared
    divergence, in the fail-closed direction); byte-identical repeated lines count once. Two DIFFERENT trusted keys
    with the same (name, id) are an error (ambiguous, as in Go); at most 100 lines.
    Returns {stato: OK | NON_VALIDA | NON_VERIFICATA, text, verified: [{name, type, timestamp?}] (one entry per
    distinct verified line, so a witness may appear twice with two timestamps), ignored: n, ignored_vkeys: n, motivo}."""
    out = {"stato": "NON_VALIDA", "text": None, "verified": [], "ignored": 0, "ignored_vkeys": 0, "motivo": None}
    known = {}
    for v in vkeys:
        name, kid, typ, pub = parse_vkey(v, strict=False)
        if typ not in SUPPORTED_TYPES:
            out["ignored_vkeys"] += 1; continue
        if known.get((name, kid), (typ, pub)) != (typ, pub):
            raise NoteError(f"ambiguous key {name}+{kid.hex()}: two different trusted keys")
        known[(name, kid)] = (typ, pub)
    try:
        text, sigs = split_note(note)
    except NoteError as e:
        out["motivo"] = str(e); return out
    out["text"] = text
    _, EdPub, InvalidSignature = _ed()
    if EdPub is None:
        out.update(stato="NON_VERIFICATA", motivo="no Ed25519 implementation (`cryptography` missing)"); return out
    seen = set(); unverifiable = 0
    for name, raw in sigs:
        kid, body = raw[:4], raw[4:]
        if (name, kid) not in known:
            out["ignored"] += 1; continue
        if (name, raw) in seen:              # the same line twice: counted once; a DIFFERENT line of a known key is verified
            continue
        seen.add((name, raw))
        typ, pub = known[(name, kid)]
        try:
            if typ == TYPE_ED25519:
                if len(body) != 64:
                    raise InvalidSignature()
                EdPub.from_public_bytes(pub).verify(body, text.encode("utf-8"))
                out["verified"].append({"name": name, "type": typ})
            elif typ == TYPE_ECDSA:      # as transparency-dev/formats: SHA-256 digest, ASN.1 signature, key from DER SPKI
                from cryptography.hazmat.primitives import hashes, serialization as ser
                from cryptography.hazmat.primitives.asymmetric import ec
                try:
                    k = ser.load_der_public_key(pub)
                except Exception:        # noqa: BLE001 — unknown OID, not a key: a failing known key, never a crash
                    raise InvalidSignature() from None
                if not isinstance(k, ec.EllipticCurvePublicKey) or k.curve.name not in ("secp256r1", "secp384r1", "secp521r1"):
                    raise InvalidSignature()
                k.verify(body, text.encode("utf-8"), ec.ECDSA(hashes.SHA256()))
                out["verified"].append({"name": name, "type": typ})
            elif typ == TYPE_MLDSA44:    # cosignature/v1 over the spec's cosigned_message (origin, size, root; not the extensions)
                m = _mldsa()
                if m is None:
                    unverifiable += 1; continue   # decided at the end: a failing known key elsewhere still wins
                if len(body) != 8 + MLDSA44_SIG:
                    raise InvalidSignature()
                ts = struct.unpack(">Q", body[:8])[0]
                if not (1 <= ts <= 2 ** 63 - 1):
                    raise InvalidSignature()
                cp = parse_checkpoint(text)
                m.MLDSA44PublicKey.from_public_bytes(pub).verify(body[8:], mldsa44_message(name, ts, cp["origin"], 0, cp["size"], cp["root"]))
                out["verified"].append({"name": name, "type": typ, "timestamp": ts})
            else:   # cosignature/v1
                if len(body) != 72 or text.count("\n") < 2:   # Go parity: bytes.Split(text, "\n") needs ≥ 3 elements,
                    raise InvalidSignature()                    # i.e. ≥ 2 newlines (a one-line text is refused there too)
                ts = struct.unpack(">Q", body[:8])[0]
                if not (1 <= ts <= 2 ** 63 - 1):           # tlog-cosignature: "MUST NOT exceed 2^63 - 1"; tlog-witness: "MUST NOT be zero"
                    raise InvalidSignature()
                msg = f"cosignature/v1\ntime {ts}\n".encode("utf-8") + text.encode("utf-8")
                EdPub.from_public_bytes(pub).verify(body[8:], msg)
                out["verified"].append({"name": name, "type": typ, "timestamp": ts})
        except (InvalidSignature, ValueError, NoteError):
            out.update(stato="NON_VALIDA", verified=[], motivo=f"signature from known key {name} does not verify"); return out
    if unverifiable:                     # an ML-DSA-44 line of a trusted key that this process cannot check
        out.update(stato="NON_VERIFICATA", motivo="a trusted ML-DSA-44 line cannot be verified here (`cryptography` without `mldsa`)")
        return out
    if not out["verified"]:
        out["motivo"] = "no signature from a known key"; return out
    out["stato"] = "OK"
    return out


# ── ledger → checkpoint ────────────────────────────────────────────────────────────────────────────────────────────
def ledger_checkpoint(ledger_path: str, origin: str) -> Tuple[str, List[bytes]]:
    """Checkpoint text of a cryptovalid ledger: size = number of entries, root = RFC 6962 MTH of the canonical entries."""
    import cryptovalid_merkle as M
    leaves = M.leaves_from_ledger(ledger_path)
    return checkpoint_text(origin, len(leaves), M.mth(leaves)), leaves


def consistency_proof_b64(leaves: List[bytes], old_size: int) -> List[str]:
    import cryptovalid_merkle as M
    if not (0 < old_size <= len(leaves)):
        raise NoteError("old size must be in (0, size]")
    return [base64.b64encode(h).decode("ascii") for h in M.consistency_proof(old_size, leaves)]


def verify_consistency_b64(old_size: int, old_root: bytes, new_size: int, new_root: bytes, proof_b64: List[str]) -> bool:
    import cryptovalid_merkle as M
    try:
        proof = [b64decode_strict(p) for p in proof_b64]
    except ValueError:                   # binascii.Error or non-ASCII: not consistent, never a crash
        return False
    if any(len(h) != 32 for h in proof):
        return False
    if old_size == new_size:
        return old_root == new_root and proof == []
    if not (0 < old_size < new_size):
        return False
    try:
        return bool(M.verify_consistency(old_size, new_size, proof, old_root, new_root))
    except Exception:      # noqa: BLE001 — a malformed proof is "not consistent", never a crash
        return False


def main(argv=None) -> int:
    import argparse
    ap = argparse.ArgumentParser(description="C2SP checkpoints / signed notes for a cryptovalid ledger")
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("sign", help="write the signed checkpoint note of a ledger")
    s.add_argument("ledger"); s.add_argument("--origin", required=True); s.add_argument("--key", required=True, help="hex seed file (signer.py keygen)")
    s.add_argument("--out", required=True); s.add_argument("--name", help="signer key name when it differs from the origin (default: the origin)")
    v = sub.add_parser("verify", help="verify a note against vkeys"); v.add_argument("note"); v.add_argument("--vkey", action="append", required=True)
    k = sub.add_parser("vkey", help="print the vkey of a key file"); k.add_argument("--key", required=True); k.add_argument("--name", required=True)
    k.add_argument("--cosigner", action="store_true", help="type 0x04 (cosignature/v1) instead of 0x01")
    k.add_argument("--mldsa44", action="store_true", help="type 0x06 (ML-DSA-44 cosignature/v1) from the same 32-byte seed file")
    a = ap.parse_args(argv)
    if a.cmd == "sign":
        try:
            text, _ = ledger_checkpoint(a.ledger, a.origin)
            note = sign_note(text, a.name or a.origin, load_seed_hex(a.key))
            with open(a.out, "wb") as f:
                f.write(note)
        except (NoteError, OSError) as e:
            print(json.dumps({"stato": "ERRORE", "motivo": str(e)}, ensure_ascii=False)); return 2
        print(note.decode("utf-8"), end=""); return 0
    if a.cmd == "verify":
        try:
            with open(a.note, "rb") as f:
                note = f.read()
            r = verify_note(note, a.vkey)
        except (NoteError, OSError) as e:   # a malformed vkey or an unreadable file is the caller's error: JSON, exit 2
            print(json.dumps({"stato": "ERRORE", "motivo": str(e)}, ensure_ascii=False)); return 2
        print(json.dumps({k: (v if k != "text" else None) for k, v in r.items()}, ensure_ascii=False))
        return 0 if r["stato"] == "OK" else 1
    try:
        seed = load_seed_hex(a.key)
        if a.mldsa44:
            print(vkey(a.name, TYPE_MLDSA44, mldsa44_pubkey_from_seed(seed))); return 0
        print(vkey(a.name, TYPE_COSIG_V1 if a.cosigner else TYPE_ED25519, pubkey_from_seed(seed))); return 0
    except (NoteError, OSError) as e:
        print(json.dumps({"stato": "ERRORE", "motivo": str(e)}, ensure_ascii=False)); return 2


if __name__ == "__main__":
    sys.exit(main())
