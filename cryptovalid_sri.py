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
