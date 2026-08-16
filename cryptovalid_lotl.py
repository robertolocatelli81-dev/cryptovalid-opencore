#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Roberto Locatelli
"""eIDAS LOTL validation for cryptovalid-opencore — certify a timestamp as QUALIFIED.

Fetches the EU List of Trusted Lists (LOTL), then each member-state Trusted List
(ETSI TS 119 612), extracts the certificates of **qualified timestamping** services
(ServiceTypeIdentifier .../Svctype/TSA/QTST, status 'granted'), and checks whether the
RFC 3161 token's TSA certificate is among them. A match => the timestamp is *qualified*
(enhanced eIDAS legal presumption, Art. 41/42 Reg. 910/2014).

Protocol/XML parsing is stdlib (urllib, re, hashlib); the TSA cert is pulled from the CMS
token via `cryptography` (already a dependency). Results cache locally; network failures on a
single Trusted List are skipped, not fatal (honest partial coverage is logged by the caller)."""
import hashlib
import json
import os
import re
import urllib.request

LOTL_URL = "https://ec.europa.eu/tools/lotl/eu-lotl.xml"
_QTST = "Svctype/TSA/QTST"                 # qualified timestamping service type (namespace-agnostic tail)
_GRANTED = "Svcstatus/granted"

def _get(url, timeout=45):
    return urllib.request.urlopen(url, timeout=timeout).read()

def lotl_pointers(lotl_xml: bytes):
    """National Trusted List URLs from the LOTL (excludes the LOTL self-pointer)."""
    urls = re.findall(rb"<[\w:]*TSLLocation>\s*([^<]+?\.xml)\s*</[\w:]*TSLLocation>", lotl_xml)
    out, seen = [], set()
    for u in urls:
        s = u.decode().strip()
        if s not in seen and "eu-lotl.xml" not in s:
            seen.add(s); out.append(s)
    return out

def _cert_fpr(b64der: str):
    import base64
    try:
        return hashlib.sha256(base64.b64decode(b64der)).hexdigest()
    except Exception:
        return None

def qtst_fingerprints(tl_xml: bytes):
    """SHA-256 fingerprints of certs of QUALIFIED timestamp services in one Trusted List."""
    text = tl_xml.decode("utf-8", "replace")
    fprs = set()
    # split into TSPService blocks (namespace-agnostic), keep only QTST + granted
    for m in re.finditer(r"<[\w:]*TSPService\b.*?</[\w:]*TSPService>", text, re.S):
        blk = m.group(0)
        if _QTST in blk and _GRANTED in blk:
            for c in re.findall(r"<[\w:]*X509Certificate>\s*([A-Za-z0-9+/=\s]+?)\s*</[\w:]*X509Certificate>", blk):
                fp = _cert_fpr(re.sub(r"\s+", "", c))
                if fp:
                    fprs.add(fp)
    return fprs

def load_qualified_fingerprints(member_states=None, cache_path=None, timeout=45, log=lambda *_: None):
    """Build the set of qualified-TSA cert fingerprints from the EU LOTL.
    member_states: optional iterable of 2-letter codes to restrict fetching (else all)."""
    if cache_path and os.path.exists(cache_path):
        d = json.load(open(cache_path))
        return set(d["fingerprints"]), d.get("coverage", [])
    lotl = _get(LOTL_URL, timeout)
    ptrs = lotl_pointers(lotl)
    fprs, coverage = set(), []
    for url in ptrs:
        cc = url.split("/")[2].split(".")[-1].upper()  # rough hint; real code = SchemeTerritory
        if member_states and not any(url for ms in member_states if ms.lower() in url.lower()):
            continue
        try:
            tl = _get(url, timeout); n0 = len(fprs); fprs |= qtst_fingerprints(tl)
            coverage.append(url); log(f"TL ok: {url} (+{len(fprs)-n0} QTST cert)")
        except Exception as e:  # una TL irraggiungibile non e' fatale
            log(f"TL skip: {url} ({type(e).__name__})")
    if cache_path:
        json.dump({"fingerprints": sorted(fprs), "coverage": coverage}, open(cache_path, "w"))
    return fprs, coverage

def token_cert_fingerprints(token_der: bytes):
    """SHA-256 fingerprints of every certificate embedded in an RFC 3161 token (CMS)."""
    from cryptography.hazmat.primitives.serialization import pkcs7, Encoding
    certs = pkcs7.load_der_pkcs7_certificates(token_der)
    return {hashlib.sha256(c.public_bytes(Encoding.DER)).hexdigest() for c in certs}

def is_qualified(token_der: bytes, qualified_fingerprints: set):
    """True iff the token's TSA certificate is a qualified-timestamp service in the EU LOTL."""
    return bool(token_cert_fingerprints(token_der) & qualified_fingerprints)

def main(argv=None):
    import argparse, base64
    p = argparse.ArgumentParser(prog="cryptovalid_lotl",
                                description="Certify an RFC 3161 token as eIDAS-qualified via the EU LOTL.")
    p.add_argument("token_b64", help="RFC 3161 TimeStampToken, base64 (from cryptovalid_tsa)")
    p.add_argument("--cache", default=None, help="cache file for qualified fingerprints")
    p.add_argument("--ms", nargs="*", default=None, help="restrict to member-state codes (e.g. IT DE)")
    a = p.parse_args(argv)
    fprs, cov = load_qualified_fingerprints(a.ms, a.cache, log=lambda m: print("  " + m))
    tok = base64.b64decode(a.token_b64)
    q = is_qualified(tok, fprs)
    print(json.dumps({"qualified": q, "qualified_certs_in_lotl": len(fprs),
                      "trusted_lists_covered": len(cov)}, indent=2))
    return 0 if q else 1

if __name__ == "__main__":
    raise SystemExit(main())
