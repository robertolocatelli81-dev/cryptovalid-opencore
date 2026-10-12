#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Roberto Locatelli
"""eIDAS LOTL validation for cryptovalid-opencore — certify a timestamp as QUALIFIED.

Fetches the EU List of Trusted Lists (LOTL), then each member-state Trusted List
(ETSI TS 119 612), extracts the certificates of **qualified timestamping** services
(ServiceTypeIdentifier .../Svctype/TSA/QTST, status 'granted' IN FORCE NOW: ServiceInformation from its
StatusStartingTime, ServiceHistory before it), and checks whether the RFC 3161 token's TSA certificate is among them. A
match says the issuing service is a qualified timestamp service NOW; whether it was at the token's time is
`qtst_fingerprints_at(tl, genTime)`, which needs the token's genTime from the caller (not extracted here).

Protocol/XML parsing is stdlib (urllib, xml.etree with the ETSI namespace for the LOTL and every list, UTF-8 only, DTDs refused); the TSA cert is pulled from the CMS
token via `cryptography` (already a dependency). Results cache locally; network failures on a
single Trusted List are skipped, not fatal (honest partial coverage is logged by the caller)."""
import hashlib
import json
import os
import re
import urllib.request

LOTL_URL = "https://ec.europa.eu/tools/lotl/eu-lotl.xml"
_TSL_NS = "http://uri.etsi.org/02231/v2#"   # ETSI TS 119 612 trusted list namespace
_QTST_URI = "http://uri.etsi.org/TrstSvc/Svctype/TSA/QTST"
_GRANTED_URI = "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted"
# The rule the fingerprints are built with (also written into the cache: a cache built by another rule is not read;
# a cache also holds the status of the day it was built, so it carries built_at and is rebuilt after CACHE_MAX_AGE_S).
# Until 0.20.1 a TSPService counted as qualified when the text "Svcstatus/granted" appeared ANYWHERE in it, its
# ServiceHistory included: a service withdrawn today with "granted" in its history was qualified (measured 12/10/2026 on 26
# of the 30 national lists the LOTL points to: 984 fingerprints against 652 in force on that day).
RULE = "etsi-ts-119612/status-in-force:QTST+granted/1"

def _get(url, timeout=45):
    with urllib.request.urlopen(url, timeout=timeout) as r:
        return r.read()

_TSLX_NS = "http://uri.etsi.org/02231/v2/additionaltypes#"   # ETSI TS 119 612 additional types (MimeType)
_TSL_MIME = "application/vnd.etsi.tsl+xml"
_LOTL_TYPE = "http://uri.etsi.org/TrstSvc/TrustedList/TSLType/EUlistofthelists"

def lotl_pointers(lotl_xml: bytes):
    """National Trusted List URLs from the LOTL: every PointersToOtherTSL/OtherTSLPointer whose MimeType is
    application/vnd.etsi.tsl+xml (the XML list, not its PDF twin), the LOTL's own pointer (TSLType EUlistofthelists)
    left out. The LOTL is parsed as a TrustServiceStatusList like any list (`_parse_tl`). Until 0.20.2 a regex took the
    locations ending in ".xml", which dropped two lists the LOTL names (CZ `.xtsl`, DK `TSLDK_v6xml`: 426 granted QTST
    fingerprints on 12/10/2026)."""
    root = _parse_tl(lotl_xml)
    out, seen = [], set()
    for ptr in root.iter(_q("OtherTSLPointer")):
        loc = _text(ptr, "TSLLocation")
        mimes = [(m.text or "").strip() for m in ptr.iter("{" + _TSLX_NS + "}MimeType")]
        types = [(t.text or "").strip() for t in ptr.iter(_q("TSLType"))]
        if not loc or mimes != [_TSL_MIME] or _LOTL_TYPE in types or loc == LOTL_URL:
            continue
        if loc not in seen:
            seen.add(loc); out.append(loc)
    return out

def _cert_fpr(b64der: str):
    import base64
    try:
        return hashlib.sha256(base64.b64decode(b64der, validate=True)).hexdigest()
    except Exception:
        return None

def _q(local):
    return "{" + _TSL_NS + "}" + local

def _refuse(*_a):   # an entity can only be declared inside a document type declaration
    raise ValueError("trusted list carries a DTD/entity declaration: refused")

def _parse_tl(tl_xml: bytes):
    """The TrustServiceStatusList root (ETSI TS 119 612), parsed as XML with its namespace. The list must be UTF-8 (TS 119
    612: "Applications shall use UTF-8 encoding for XML TLs"); a document type declaration (DTD, entities) is refused by
    the XML parser itself, in whatever encoding the bytes claim (until 0.20.2 a byte search for "<!DOCTYPE" missed a
    UTF-16 list, whose entities were then expanded). Anything that is not a TrustServiceStatusList in the ETSI namespace
    is a ValueError, never an empty answer."""
    import xml.etree.ElementTree as ET
    import xml.parsers.expat as expat
    if not isinstance(tl_xml, (bytes, bytearray)):
        raise ValueError("trusted list must be bytes")
    tl_xml = bytes(tl_xml)
    if b"\x00" in tl_xml:   # UTF-16/32 (expat reads them; a declared non-UTF-8 encoding is refused by _decl, bad UTF-8 by expat)
        raise ValueError("trusted list is not UTF-8 (ETSI TS 119 612: XML trusted lists are UTF-8)")

    def _decl(_version, encoding, _standalone):
        if encoding is not None and encoding.lower() not in ("utf-8", "utf8"):
            raise ValueError(f"trusted list declares encoding {encoding!r}: ETSI TS 119 612 XML trusted lists are UTF-8")
    pre = expat.ParserCreate()
    pre.XmlDeclHandler = _decl
    pre.StartDoctypeDeclHandler = _refuse
    try:
        pre.Parse(tl_xml, True)
    except expat.ExpatError as e:
        raise ValueError(f"trusted list is not well-formed XML: {e}") from None
    try:
        root = ET.fromstring(tl_xml)
    except ET.ParseError as e:
        raise ValueError(f"trusted list is not well-formed XML: {e}") from None
    if root.tag != _q("TrustServiceStatusList"):
        raise ValueError(f"not an ETSI TS 119 612 TrustServiceStatusList: root {root.tag!r}")
    return root

def _text(el, local):
    c = el.find(_q(local)) if el is not None else None
    return (c.text or "").strip() if c is not None else None

def _certs(el):
    """SHA-256 fingerprints of the X509Certificate values in the ServiceDigitalIdentity of THIS block only."""
    out = set()
    sdi = el.find(_q("ServiceDigitalIdentity"))
    if sdi is None:
        return out
    for did in sdi.findall(_q("DigitalId")):
        for c in did.findall(_q("X509Certificate")):
            fp = _cert_fpr(re.sub(r"\s+", "", c.text or ""))
            if fp:
                out.add(fp)
    return out

_DATETIME = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z")

def _when(s):
    """StatusStartingTime as an aware UTC datetime, only in the form ETSI TS 119 612 clause 5.1.3 prescribes
    (YYYY-MM-DDThh:mm:ssZ: UTC designator, no fraction); None otherwise. Until 0.20.2 `datetime.fromisoformat` read it,
    which also took a value without "Z" (as UTC), an offset, a fraction, and on Python 3.11+ more ISO 8601 forms
    (20170301T000000Z, week dates) that 3.9 refused: the same list gave a different answer by Python version."""
    from datetime import datetime, timezone
    if not isinstance(s, str) or not _DATETIME.fullmatch(s):
        return None
    try:
        return datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError:   # e.g. month 13
        return None

def services(tl_xml: bytes):
    """Every TSPService of one trusted list as {"certs", "timeline"}: `certs` are the fingerprints in its
    ServiceInformation/ServiceDigitalIdentity (the service's identity); `timeline` lists (start, type, status, certs) for
    ServiceInformation and for each ServiceHistory/ServiceHistoryInstance, each read from ITS OWN block, newest first."""
    root = _parse_tl(tl_xml)
    out = []
    for svc in root.iter(_q("TSPService")):
        si = svc.find(_q("ServiceInformation"))
        if si is None:
            continue
        tl = [(_when(_text(si, "StatusStartingTime")), _text(si, "ServiceTypeIdentifier"), _text(si, "ServiceStatus"), _certs(si))]
        hist = svc.find(_q("ServiceHistory"))
        for h in (hist.findall(_q("ServiceHistoryInstance")) if hist is not None else []):
            tl.append((_when(_text(h, "StatusStartingTime")), _text(h, "ServiceTypeIdentifier"), _text(h, "ServiceStatus"), _certs(h)))
        out.append({"certs": tl[0][3], "timeline": tl})
    return out

def qtst_fingerprints(tl_xml: bytes, now=None):
    """SHA-256 fingerprints of certs of services that are QUALIFIED timestamp services NOW in one Trusted List: the status
    in force at `now` (default: the system clock, UTC), read as ETSI TS 119 612 defines it — ServiceInformation's
    ServiceStatus from its StatusStartingTime on, the ServiceHistoryInstance entries before it — with type TSA/QTST and
    status granted; certificates from ServiceInformation's ServiceDigitalIdentity. A list can publish a status that
    starts in the future (measured 12/10/2026: 18 QTST services of one list, withdrawn from 2027-2029, granted today):
    such a service is qualified until that instant."""
    from datetime import datetime, timezone
    return qtst_fingerprints_at(tl_xml, now or datetime.now(timezone.utc))

def qtst_fingerprints_at(tl_xml: bytes, at):
    """Fingerprints of services that were qualified timestamp services AT the instant `at` (an aware datetime, e.g. the
    genTime of a token): the entry in force is the one, among ServiceInformation and the ServiceHistoryInstance entries,
    with the latest StatusStartingTime <= `at` (an entry applies from its starting time, inclusive); its type must be
    TSA/QTST and its status granted. The service is identified by the certificates of its ServiceInformation, as ETSI TS
    119 615 (PRO-4.3.4-03) matches a certificate against the 'Service digital identity' of the ServiceInformation entry;
    a certificate found only in a history instance is not counted (none on 12/10/2026 in 30 lists). A service with
    an entry whose StatusStartingTime is missing or not a dateTime is not counted at any instant (its timeline cannot be
    ordered). The genTime is NOT extracted from the token here: the caller gives it."""
    from datetime import datetime
    if not isinstance(at, datetime) or at.tzinfo is None:
        raise ValueError("`at` must be a timezone-aware datetime")
    fprs = set()
    for svc in services(tl_xml):
        tl = svc["timeline"]
        if any(start is None for start, *_ in tl):
            continue
        in_force = [e for e in tl if e[0] <= at]
        if not in_force:
            continue
        _start, typ, status, _certs_of_entry = max(in_force, key=lambda e: e[0])
        if typ == _QTST_URI and status == _GRANTED_URI:
            fprs |= svc["certs"]
    return fprs

def _ms_of_url(url: str) -> str:
    """Member-state hint dal TLD dell'host della Trusted List (crc.bg -> BG).
    Hint approssimato (il codice vero è SchemeTerritory nel puntatore LOTL): una TL
    ospitata su dominio .eu/.com non matcherebbe — il filtro è SOLO un'ottimizzazione
    opzionale di velocità; senza filtro si scarica tutto (default, copertura piena)."""
    return url.split("/")[2].split(".")[-1].upper()


CACHE_MAX_AGE_S = 24 * 3600   # a cache holds the statuses in force on the day it was built: older than this, it is rebuilt

def load_qualified_fingerprints(member_states=None, cache_path=None, timeout=45, log=lambda *_: None,
                                cache_max_age_s=CACHE_MAX_AGE_S):
    """Build the set of qualified-TSA cert fingerprints from the EU LOTL.
    member_states: optional iterable of 2-letter codes to restrict fetching (else all).
    A cache is read only when it was built by this RULE and less than `cache_max_age_s` seconds ago (it records
    `built_at`): the set is the status in force when it was built, so an old cache would answer for an old day."""
    from datetime import datetime, timezone
    if cache_path and os.path.exists(cache_path):
        with open(cache_path) as f:
            d = json.load(f)
        built = _when(d.get("built_at")) if isinstance(d, dict) and isinstance(d.get("built_at"), str) else None
        age = (datetime.now(timezone.utc) - built).total_seconds() if built else None
        if isinstance(d, dict) and d.get("rule") == RULE and isinstance(d.get("fingerprints"), list) \
                and age is not None and 0 <= age <= cache_max_age_s:
            return set(d["fingerprints"]), d.get("coverage", [])
        log(f"LOTL cache {cache_path} not used (rule {d.get('rule') if isinstance(d, dict) else None!r}, "
            f"built_at {d.get('built_at') if isinstance(d, dict) else None!r}): rebuilt")
    lotl = _get(LOTL_URL, timeout)
    ptrs = lotl_pointers(lotl)
    fprs, coverage = set(), []
    wanted = {m.upper() for m in member_states} if member_states else None
    for url in ptrs:
        if wanted and _ms_of_url(url) not in wanted:
            continue
        try:
            tl = _get(url, timeout); n0 = len(fprs); fprs |= qtst_fingerprints(tl)
            coverage.append(url); log(f"TL ok: {url} (+{len(fprs)-n0} QTST cert)")
        except Exception as e:  # una TL irraggiungibile non e' fatale
            log(f"TL skip: {url} ({type(e).__name__})")
    if cache_path:
        with open(cache_path, "w") as f:
            json.dump({"rule": RULE, "built_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                       "fingerprints": sorted(fprs), "coverage": coverage}, f)
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
    import argparse
    import base64
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
