# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Roberto Locatelli
"""Subresource Integrity "integrity metadata" (e.g. the `vct#integrity` claims of SD-JWT VC), parsed closed and checked
against the bytes they name (0.26.0, 2026-11-17).

Status: EXPERIMENTAL (README, "Core and experimental modules").

Which grammar. SD-JWT VC (draft-ietf-oauth-sd-jwt-vc-27, the current revision on the IETF datatracker on 2026-11-17,
§6; -16 §5 says the same): "The value MUST be an "integrity metadata" string as defined in Section 3 of [W3C.SRI]",
[W3C.SRI] being the W3C Recommendation of 23 June 2016. https://www.w3.org/TR/SRI/ opens, on 2026-11-17, the SRI
Level 2 Working Draft of 20 March 2026, which takes its productions from CSP Level 3. The two differ in base64-value.
The caller names the grammar; there is no default:

  "sri-2016"  W3C SRI Recommendation 2016-06-23 §3.5 with CSP Level 2 §4.2:
              metadata = *WSP hash-with-options *( 1*WSP hash-with-options ) *WSP / *WSP
              hash-with-options = hash-expression *( "?" option-expression );  option-expression = *VCHAR
              hash-expression = hash-algo "-" base64-value;  hash-algo = "sha256" / "sha384" / "sha512"
              base64-value = 1*( ALPHA / DIGIT / "+" / "/" ) *2( "=" )
  "sri-l2"    W3C SRI Level 2 Working Draft 2026-03-20 §3.5 with CSP Level 3: the same, with hash-algorithm for
              hash-algo and base64-value = 1*( ALPHA / DIGIT / "+" / "/" / "-" / "_" ) *2( "=" )

(ABNF strings are case-insensitive, RFC 5234 §2.3: "SHA256-" is the algorithm sha256; WSP is space or tab.)

Closed by construction. `parse_integrity(value, grammar)` returns the hash expressions, or a refusal with one closed
code, in this order: `not_text` (not a str), `empty` (no hash expression), `grammar` (an expression outside the
grammar: a character, a missing "-", padding not at the end, more than two "="), `alg_not_recognised` (a hash-algo
outside sha256/sha384/sha512, which the grammar does not admit either), `digest_length` (the base64 decodes to another
length than the algorithm's 32/48/64 bytes, or is not decodable). Options are kept and not interpreted (SRI defines none).

Where the format and the SRI matching algorithm differ, and why this module refuses: the matching algorithm (REC
§3.3.3 "parse metadata" and §3.3.5 "does response match metadataList"; Level 2 §3.3.2, §3.3.4) skips every token it
cannot parse or whose algorithm it does not know, and "if parsedMetadata is the empty set, return true". So a value with
no recognised, well-formed expression passes an SRI matcher for ANY bytes. Integrity metadata is a MUST of the claim's
format, so here such a value is refused, and every refusal says `sri_match_would_accept: true` when a plain SRI matcher
would have returned true whatever the bytes (the format decides; the divergence is reported, not hidden).

`check_integrity(body, value, grammar)` parses, then compares the SHA-2 digest of `body` with the expressions of the
strongest algorithm present (sha512 > sha384 > sha256, as the matching algorithm's getPrioritizedHashFunction): `ok`
when one matches, `mismatch` otherwise. It never raises on the value; a `grammar` argument outside the two is a
ValueError.
"""
import base64
import hashlib
import re
from typing import Dict

GRAMMARS = ("sri-2016", "sri-l2")
ALGS = {"sha256": 32, "sha384": 48, "sha512": 64}
STRENGTH = ("sha512", "sha384", "sha256")      # getPrioritizedHashFunction: the strongest first
_B64 = {"sri-2016": re.compile(r"[A-Za-z0-9+/]+={0,2}"), "sri-l2": re.compile(r"[A-Za-z0-9+/_-]+={0,2}")}
_ALG_TOKEN = re.compile(r"[A-Za-z0-9]+")
_WSP = re.compile(r"[ \t]+")
_VCHAR = re.compile(r"[\x21-\x7e]*")
CODES = ("not_text", "empty", "grammar", "alg_not_recognised", "digest_length")


def _grammar(grammar: str) -> None:
    if grammar not in GRAMMARS:
        raise ValueError(f"grammar: one of {GRAMMARS}, named by the caller (no default)")


def parse_integrity(value, grammar: str) -> Dict:
    """{"ok", "why", "expressions": [{"alg", "digest" (hex), "options"}], "sri_match_would_accept"}; never raises on
    `value`. `sri_match_would_accept`: a plain SRI matcher would return true for any bytes (no expression it keeps)."""
    _grammar(grammar)
    out = {"ok": False, "why": None, "expressions": [], "sri_match_would_accept": True}
    if not isinstance(value, str):
        out["why"] = "not_text"
        return out
    tokens = [t for t in _WSP.split(value.strip(" \t")) if t] if value.strip(" \t") else []
    if not tokens:
        out["why"] = "empty"
        return out
    problems, kept = set(), []
    for t in tokens:
        expr, *options = t.split("?")
        alg, dash, b64 = expr.partition("-")
        if not dash or not _ALG_TOKEN.fullmatch(alg) or not _B64[grammar].fullmatch(b64) \
                or not all(_VCHAR.fullmatch(o) for o in options):
            problems.add("grammar")
            continue
        if alg.lower() not in ALGS:
            problems.add("alg_not_recognised")
            continue
        out["sri_match_would_accept"] = False      # the matcher keeps this expression
        raw = b64.rstrip("=").replace("-", "+").replace("_", "/")
        try:
            digest = base64.b64decode(raw + "=" * (-len(raw) % 4), validate=True)
        except ValueError:
            digest = None
        if digest is None or len(digest) != ALGS[alg.lower()]:
            problems.add("digest_length")
            continue
        kept.append({"alg": alg.lower(), "digest": digest.hex(), "options": options})
    for code in CODES[2:]:                         # the closed order of the docstring
        if code in problems:
            out["why"] = code
            return out
    out.update(ok=True, expressions=kept)
    return out


def check_integrity(body: bytes, value, grammar: str) -> Dict:
    """{"ok", "why" (a code of parse_integrity, or "mismatch"), "matched_alg", "sri_match_would_accept"}"""
    p = parse_integrity(value, grammar)
    out = {"ok": False, "why": p["why"], "matched_alg": None, "sri_match_would_accept": p["sri_match_would_accept"]}
    if not p["ok"]:
        return out
    if not isinstance(body, (bytes, bytearray)):
        raise ValueError("body: bytes")
    alg = next(a for a in STRENGTH if any(e["alg"] == a for e in p["expressions"]))
    digest = hashlib.new(alg, bytes(body)).hexdigest()
    if any(e["alg"] == alg and e["digest"] == digest for e in p["expressions"]):
        out.update(ok=True, why=None, matched_alg=alg)
    else:
        out["why"] = "mismatch"
    return out
