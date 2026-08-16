#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Roberto Locatelli
"""RFC 3161 timestamping client for cryptovalid-opencore — real (qualified) TSP integration.

Requests an RFC 3161 timestamp over a digest (e.g. a Merkle Signed Tree Head root) from a
Time-Stamping Authority, stores the token, and verifies it. Point `tsa_url` at a **qualified**
TSP in the eIDAS EU Trusted List to obtain a *qualified* timestamp with enhanced legal presumption
(Art. 41/42 Reg. 910/2014); the RFC 3161 protocol is identical for qualified and non-qualified TSAs.

Stdlib-only for the protocol (hand-rolled DER TimeStampReq + response parsing). Optional full
token signature verification via the `openssl ts` CLI when available. No new Python dependencies.
"""
import hashlib
import os
import struct
import urllib.request

# ── minimal DER ──
def _der_len(n):
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b
def _tlv(tag, value):
    return bytes([tag]) + _der_len(len(value)) + value
def _der_int(n):
    b = n.to_bytes((n.bit_length() + 7) // 8 or 1, "big")
    if b[0] & 0x80:
        b = b"\x00" + b
    return _tlv(0x02, b)

_OID_SHA256 = bytes([0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01])
_NULL = bytes([0x05, 0x00])

def build_timestamp_request(digest: bytes, cert_req: bool = True, nonce: bytes = None) -> bytes:
    """RFC 3161 TimeStampReq (DER) over a 32-byte SHA-256 digest."""
    assert len(digest) == 32, "digest must be SHA-256 (32 bytes)"
    alg = _tlv(0x30, _OID_SHA256 + _NULL)                       # AlgorithmIdentifier sha256
    imprint = _tlv(0x30, alg + _tlv(0x04, digest))              # MessageImprint
    body = _der_int(1) + imprint                               # version + messageImprint
    if nonce is None:
        nonce = os.urandom(16)
    body += _der_int(int.from_bytes(nonce, "big"))             # nonce
    if cert_req:
        body += _tlv(0x01, b"\xff")                            # certReq BOOLEAN TRUE
    return _tlv(0x30, body)                                    # TimeStampReq SEQUENCE

def _read_tlv(b, i):
    tag = b[i]; i += 1
    ln = b[i]; i += 1
    if ln & 0x80:
        k = ln & 0x7F; ln = int.from_bytes(b[i:i + k], "big"); i += k
    return tag, b[i:i + ln], i + ln, i - (i - (i)) # value, next
def _parse_seq_children(seq):
    out = []; i = 0
    while i < len(seq):
        tag = seq[i]; j = i + 1
        ln = seq[j]; j += 1
        if ln & 0x80:
            k = ln & 0x7F; ln = int.from_bytes(seq[j:j + k], "big"); j += k
        out.append((tag, seq[j:j + ln], seq[i:j + ln]))       # (tag, value, full_tlv)
        i = j + ln
    return out

def request_timestamp(digest: bytes, tsa_url: str, timeout: int = 30):
    """POST a TimeStampReq to a TSA; return (granted: bool, token_der: bytes|None, raw: bytes)."""
    req_der = build_timestamp_request(digest)
    r = urllib.request.Request(tsa_url, data=req_der,
                               headers={"Content-Type": "application/timestamp-query"})
    raw = urllib.request.urlopen(r, timeout=timeout).read()
    # TimeStampResp ::= SEQUENCE { status PKIStatusInfo, timeStampToken OPTIONAL }
    _, respval, _ = _parse_seq_children(_parse_seq_children(raw)[0][2])[0], None, None  # noqa
    top = _parse_seq_children(raw)[0][1]                       # inner of outer SEQUENCE
    kids = _parse_seq_children(top)
    status_seq = kids[0][1]
    status = _parse_seq_children(status_seq)[0]               # PKIStatus INTEGER
    granted = (status[1] in (b"\x00", b"\x01"))               # 0 granted, 1 grantedWithMods
    token = kids[1][2] if len(kids) > 1 else None             # TimeStampToken (full TLV)
    return granted, token, raw

def token_contains_digest(token_der: bytes, digest: bytes) -> bool:
    """Pragmatic check: the token's messageImprint carries our digest (the OCTET STRING is present)."""
    return _tlv(0x04, digest) in token_der

def verify_cms_signature(token_der: bytes):
    """Firma CMS del token valida? (openssl cms -verify -noverify: verifica la FIRMA
    col certificato embedded, NON la catena di trust — la qualificazione della catena
    è il lavoro della LOTL, per impronta). Ritorna True/False, o None se openssl manca.
    Serve a respingere blob forgiati che contengono il digest senza essere CMS firmati."""
    import shutil, subprocess, tempfile
    if not shutil.which("openssl"):
        return None
    with tempfile.NamedTemporaryFile(delete=False) as tf:
        tf.write(token_der); tp = tf.name
    try:
        p = subprocess.run(["openssl", "cms", "-verify", "-noverify", "-inform", "DER",
                            "-in", tp, "-out", os.devnull],
                           capture_output=True, timeout=30)
        return p.returncode == 0
    finally:
        os.unlink(tp)


def verify_with_openssl(token_der: bytes, digest_data: bytes):
    """Full RFC 3161 verification via `openssl ts` (signature + TSA cert), if openssl is installed."""
    import shutil, subprocess, tempfile
    if not shutil.which("openssl"):
        return None
    with tempfile.NamedTemporaryFile(delete=False) as tf, tempfile.NamedTemporaryFile(delete=False) as df:
        tf.write(token_der); df.write(digest_data); tp, dp = tf.name, df.name
    try:
        p = subprocess.run(["openssl", "ts", "-verify", "-in", tp, "-data", dp, "-CApath", "/etc/ssl/certs"],
                           capture_output=True, text=True)
        return p.returncode == 0
    finally:
        os.unlink(tp); os.unlink(dp)

# EU Trusted List (LOTL) root — the value of a *qualified* timestamp; verifying the TSA cert against
# it is the remaining step to certify eIDAS-qualified status (documented, not yet automated here).
EU_LOTL_URL = "https://ec.europa.eu/tools/lotl/eu-lotl.xml"

def timestamp_sth(root_hex: str, tsa_url: str, timeout: int = 30):
    """Timestamp a Merkle Signed Tree Head root (hex) — the recommended cryptovalid anchor."""
    digest = bytes.fromhex(root_hex)
    granted, token, _ = request_timestamp(digest, tsa_url, timeout)
    import base64
    return {"root_sha256": root_hex, "granted": granted,
            "tsa_token": base64.b64encode(token).decode() if token else None,
            "tsa_url": tsa_url}

def main(argv=None):
    import argparse, base64, json
    p = argparse.ArgumentParser(prog="cryptovalid_tsa",
                                description="RFC 3161 (qualified) timestamp over a digest / Merkle STH.")
    p.add_argument("digest_hex", help="SHA-256 digest hex (e.g. a Merkle STH root_sha256)")
    p.add_argument("--tsa", default="https://freetsa.org/tsr",
                   help="TSA URL (point at an eIDAS qualified TSP for a QUALIFIED timestamp)")
    a = p.parse_args(argv)
    granted, token, _ = request_timestamp(bytes.fromhex(a.digest_hex), a.tsa)
    ok = granted and token is not None and token_contains_digest(token, bytes.fromhex(a.digest_hex))
    print(json.dumps({"granted": granted, "digest_bound": ok,
                      "token_b64_len": len(base64.b64encode(token)) if token else 0,
                      "tsa": a.tsa}, indent=2))
    return 0 if ok else 1

if __name__ == "__main__":
    raise SystemExit(main())
