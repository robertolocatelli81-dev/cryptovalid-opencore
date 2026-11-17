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
never a refusal. The outcome, closed: `ok` when at least one supported digest was checked and every supported digest
matches the body; otherwise `why` is one of `not_text`, `grammar` (the field is outside the syntax named, a key twice,
a value that is not canonical base64, a parameter or member value of the wrong type), `digest_length` (a supported
algorithm with a decoded length other than 32 or 64 bytes), `mismatch` (a supported digest does not match the body),
`no_supported_alg` (nothing left to check after the ignored ones). A `syntax` outside the two is a ValueError.

What this module does not do: it does not know which representation a Repr-Digest covers (the caller passes the bytes),
does not read Want-*-Digest, and does not decode content codings.
"""
