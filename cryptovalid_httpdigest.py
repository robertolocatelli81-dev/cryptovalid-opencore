# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Roberto Locatelli
"""HTTP message digests checked against the body they name: the `Digest` header of RFC 3230 and the `Content-Digest` /
`Repr-Digest` fields of RFC 9530 (0.26.0, 2026-11-17).

Status: EXPERIMENTAL (README, "Core and experimental modules").

Versions, read on rfc-editor.org on 2026-11-17: RFC 9530 "Digest Fields" (Proposed Standard, February 2024) obsoletes
RFC 3230 "Instance Digests in HTTP" (Proposed Standard, January 2002); RFC 9530 fields are Structured Fields of RFC 9651
(Proposed Standard, September 2024, which obsoletes RFC 8941). RFC 3230 is still what some profiles cite (the Italian
ModI guidelines, pattern INTEGRITY_REST_01: `Digest: SHA-256=<base64>`), so the caller names the syntax; there is no
default:

  "rfc3230"   Digest = #( instance-digest );  instance-digest = digest-algorithm "=" <encoded digest output>
              digest-algorithm a token, case-insensitive (RFC 3230 §4.1.1); list elements separated by "," with optional
              spaces or tabs around it. The encodings of the IANA registry: SHA-256 and SHA-512 (RFC 5843) in base64
              (RFC 4648 §4, padded, canonical).
  "rfc9530"   an sf-dictionary (RFC 9651 §3.2, parsed as §4.2.2 says): keys lowercase, `[a-z*][a-z0-9_.*-]*`, each value
              a Byte Sequence `:base64:` (RFC 9651 §3.3.5) with optional parameters; members separated by "," with
              optional spaces or tabs. sha-256 and sha-512 are the "Active" algorithms of the RFC 9530 registry (§5).

Unknown algorithms. Both RFCs say "A recipient MAY ignore any or all digests" (RFC 3230 §4.3.2, RFC 9530 §2-§3): where
the standard decides, it is followed and the report says what was ignored. An algorithm this module does not verify
(an unknown one, or md5, sha, unixsum, unixcksum, adler, crc32c, "Deprecated" in RFC 9530 §5) is listed in `ignored`,
never a refusal. Also as the standards say, and reported: in "rfc9530" a key given twice keeps its last value (RFC 9651
§4.2.2, listed in `duplicate_keys`), a Byte Sequence without "=" padding or with non-zero pad bits is read ("parsers
SHOULD NOT fail", RFC 9651 §4.2.7; listed in `noncanonical`), and parameters are kept and not interpreted (RFC 9530
defines none; listed in `parameters`). In "rfc3230" every instance-digest is checked, a repeated algorithm too, and its
base64 must be canonical (RFC 3230 says nothing else; RFC 4648 §3.5 lets a decoder refuse non-canonical data). The
outcome, closed: `ok` when at least one supported digest was checked and every supported digest matches the body;
otherwise `why` is one of `not_text`, `grammar` (the field is outside the syntax named, or a member value is not a Byte
Sequence), `digest_length` (a supported algorithm with a decoded length other than 32 or 64 bytes), `mismatch` (a
supported digest does not match the body), `no_supported_alg` (nothing left to check after the ignored ones). A `syntax`
outside the two is a ValueError.

What this module does not do: it does not know which representation a Repr-Digest covers (the caller passes the bytes),
does not read Want-*-Digest, and does not decode content codings.
"""
import base64
import hashlib
import re
from typing import Dict, List, Tuple

SYNTAXES = ("rfc3230", "rfc9530")
SUPPORTED = {"sha-256": ("sha256", 32), "sha-512": ("sha512", 64)}   # RFC 5843 names (3230), RFC 9530 §5 "Active"
CODES = ("not_text", "grammar", "digest_length", "mismatch", "no_supported_alg")
_TOKEN = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+")                 # RFC 9110 §5.6.2 tchar
_B64_STRICT = re.compile(r"(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?")


class _Bad(ValueError):
    pass


# ---- RFC 9651 §4.2 (the parts a dictionary needs) ----

class _P:
    def __init__(self, s: str):
        self.s, self.i = s, 0

    def peek(self) -> str:
        return self.s[self.i] if self.i < len(self.s) else ""

    def take(self) -> str:
        c = self.peek()
        if not c:
            raise _Bad("end of field")
        self.i += 1
        return c


def _key(p: _P) -> str:
    c = p.peek()
    if not (c == "*" or "a" <= c <= "z"):
        raise _Bad("key")
    start = p.i
    while p.peek() and (p.peek() in "_-.*" or "a" <= p.peek() <= "z" or "0" <= p.peek() <= "9"):
        p.i += 1
    return p.s[start:p.i]


def _bare(p: _P):
    c = p.peek()
    if c == "-" or c.isdigit():                                    # Integer or Decimal (§4.2.4)
        m = re.compile(r"-?[0-9]{1,15}(\.[0-9]{1,3})?").match(p.s, p.i)
        if not m or (m.group(1) is None and len(m.group(0).lstrip("-")) > 15) \
                or (m.group(1) is not None and len(m.group(0).lstrip("-").split(".")[0]) > 12):
            raise _Bad("number")
        p.i = m.end()
        return ("number", m.group(0))
    if c == '"':                                                   # String (§4.2.5)
        p.take()
        out = []
        while True:
            ch = p.take()
            if ch == "\\":
                nx = p.take()
                if nx not in '"\\':
                    raise _Bad("string escape")
                out.append(nx)
            elif ch == '"':
                return ("string", "".join(out))
            elif not (0x20 <= ord(ch) <= 0x7E):
                raise _Bad("string character")
            else:
                out.append(ch)
    if c == "*" or c.isalpha() and c.isascii():                     # Token (§4.2.6)
        m = re.compile(r"[A-Za-z*][!#$%&'*+.^_`|~0-9A-Za-z:/-]*").match(p.s, p.i)
        p.i = m.end()
        return ("token", m.group(0))
    if c == ":":                                                   # Byte Sequence (§4.2.7)
        p.take()
        end = p.s.find(":", p.i)
        if end < 0:
            raise _Bad("byte sequence not closed")
        b64 = p.s[p.i:end]
        if not re.fullmatch(r"[A-Za-z0-9+/=]*", b64):
            raise _Bad("byte sequence character")
        p.i = end + 1
        return ("bytes", b64)
    if c == "?":                                                   # Boolean (§4.2.8)
        p.take()
        v = p.take()
        if v not in "01":
            raise _Bad("boolean")
        return ("boolean", v == "1")
    if c == "@":                                                   # Date (§4.2.9)
        p.take()
        n = _bare(p)
        if n[0] != "number" or "." in n[1]:
            raise _Bad("date")
        return ("date", n[1])
    if c == "%":                                                   # Display String (§4.2.10)
        p.take()
        if p.take() != '"':
            raise _Bad("display string")
        out = bytearray()
        while True:
            ch = p.take()
            if ch == "%":
                h = p.take() + p.take()
                if not re.fullmatch(r"[0-9a-f]{2}", h):
                    raise _Bad("display string escape")
                out.append(int(h, 16))
            elif ch == '"':
                try:
                    return ("display", out.decode("utf-8"))
                except UnicodeDecodeError:
                    raise _Bad("display string utf-8") from None
            elif not (0x20 <= ord(ch) <= 0x7E):
                raise _Bad("display string character")
            else:
                out += ch.encode()
    raise _Bad("item")


def _params(p: _P) -> Dict:
    out = {}
    while p.peek() == ";":
        p.take()
        while p.peek() == " ":
            p.take()
        k = _key(p)
        v = ("boolean", True)
        if p.peek() == "=":
            p.take()
            v = _bare(p)
        out[k] = v
    return out


def _item_or_inner(p: _P):
    if p.peek() == "(":
        p.take()
        items = []
        while True:
            while p.peek() == " ":
                p.take()
            if p.peek() == ")":
                p.take()
                return (("inner", items), _params(p))
            items.append((_bare(p), _params(p)))
            if p.peek() not in " )":
                raise _Bad("inner list")
    return (_bare(p), _params(p))


def _sf_dictionary(field: str) -> Tuple[Dict, List[str]]:
    """RFC 9651 §4.2.2 on the field value (§4.2: leading and trailing SP discarded); (members, keys given twice)"""
    p = _P(field.strip(" "))
    out, dup = {}, []
    while p.peek():
        k = _key(p)
        if p.peek() == "=":
            p.take()
            member = _item_or_inner(p)
        else:
            member = (("boolean", True), _params(p))
        if k in out:
            dup.append(k)
            del out[k]                                             # overwritten: the last value, in its new place
        out[k] = member
        while p.peek() in (" ", "\t"):
            p.take()
        if not p.peek():
            break
        if p.take() != ",":
            raise _Bad("member separator")
        while p.peek() in (" ", "\t"):
            p.take()
        if not p.peek():
            raise _Bad("trailing comma")
    return out, dup


def check_digest(field, body: bytes, syntax: str) -> Dict:
    """{"ok", "why", "algs_checked", "ignored", "duplicate_keys", "noncanonical", "parameters"}; never raises on `field`"""
    if syntax not in SYNTAXES:
        raise ValueError(f"syntax: one of {SYNTAXES}, named by the caller (no default)")
    if not isinstance(body, (bytes, bytearray)):
        raise ValueError("body: bytes")
    out = {"ok": False, "why": None, "algs_checked": [], "ignored": [], "duplicate_keys": [], "noncanonical": [],
           "parameters": {}}
    if not isinstance(field, str):
        out["why"] = "not_text"
        return out
    pairs = []                                                     # (algorithm as written, digest bytes or None)
    try:
        if syntax == "rfc3230":
            for el in field.split(","):
                el = el.strip(" \t")
                alg, eq, val = el.partition("=")
                if not eq or not _TOKEN.fullmatch(alg) or not val:
                    raise _Bad("instance-digest")
                if alg.lower() in SUPPORTED:
                    if not _B64_STRICT.fullmatch(val) or base64.b64encode(base64.b64decode(val)).decode() != val:
                        raise _Bad("base64")                      # canonical: padded, zero pad bits
                    pairs.append((alg, base64.b64decode(val)))
                else:
                    pairs.append((alg, None))
        else:
            members, out["duplicate_keys"] = _sf_dictionary(field)
            for k, (item, params) in members.items():
                if params:
                    out["parameters"][k] = sorted(params)
                if item[0] != "bytes":
                    raise _Bad(f"{k}: not a Byte Sequence")
                if k in SUPPORTED:
                    raw, core = item[1], item[1].rstrip("=")
                    if "=" in core or len(core) % 4 == 1 or len(raw) - len(core) > 2:
                        raise _Bad("base64")
                    data = base64.b64decode(core + "=" * (-len(core) % 4), validate=True)
                    if base64.b64encode(data).decode() != raw:   # no padding, or non-zero pad bits: read, reported
                        out["noncanonical"].append(k)
                    pairs.append((k, data))
                else:
                    pairs.append((k, None))
    except (_Bad, ValueError):
        out["why"] = "grammar"
        return out
    for alg, data in pairs:
        if data is None:
            out["ignored"].append(alg)
            continue
        name, size = SUPPORTED[alg.lower()]
        if len(data) != size:
            out["why"] = "digest_length"
            return out
        out["algs_checked"].append(alg)
        if hashlib.new(name, bytes(body)).digest() != data:
            out["why"] = "mismatch"
            return out
    if not out["algs_checked"]:
        out["why"] = "no_supported_alg"
        return out
    out["ok"] = True
    return out
