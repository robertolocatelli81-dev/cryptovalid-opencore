#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Roberto Locatelli
"""eIDAS LOTL validation for cryptovalid-opencore — certify a timestamp as QUALIFIED.

Status: EXPERIMENTAL. Outside the maintained core of cryptovalid-opencore (README, "Core and experimental
modules"): kept, installed and tested, no new scope is added here.

Fetches the EU List of Trusted Lists (LOTL), then each member-state Trusted List
(ETSI TS 119 612), extracts the certificates of **qualified timestamping** services
(ServiceTypeIdentifier .../Svctype/TSA/QTST, status 'granted' IN FORCE NOW: ServiceInformation from its
StatusStartingTime, ServiceHistory before it), and checks whether the RFC 3161 token's TSA certificate is among them. A
match says the issuing service is a qualified timestamp service NOW; whether it was at the token's time is
`qtst_fingerprints_at(tl, genTime)`, which needs the token's genTime from the caller (not extracted here). Since 0.21.0 a
QTST service whose ServiceHistoryInstance entries are out of order or share a StatusStartingTime is an error (ETSI TS 119
615 PRO-4.3.4-03A): not counted, named (`qtst_status_at`, `load_qualified_status`), and a token from it is
"indeterminate" (`qualification`), neither qualified nor not. Since v0.6 of the spec (2026-11-13) the certificate looked up is
the one that verified the token's signature (SPEC §11 step 6), not any certificate the token carries.

Since SPEC v0.14 §22 rule 6 a list counts only when its XAdES signature verifies: the LOTL under a certificate of the
Official Journal publication in force (OJ_LOTL_SIGNERS_SHA256), each national list under a certificate of the LOTL's pointer
to it, over https only (verify_list_signature: exclusive C14N written here on expat, the signature with `cryptography`).
Protocol/XML parsing is stdlib (urllib, xml.etree with the ETSI namespace for the LOTL and every list, UTF-8 only, DTDs refused); the TSA cert is pulled from the CMS
token via `cryptography` (already a dependency). Results cache locally; network failures on a
single Trusted List are skipped, not fatal (honest partial coverage is logged by the caller)."""
import sys as _sys_0203
if __name__ == "__main__":   # 0.20.3: run as a command, never write the bytecode cache: CPython 3.9 and 3.11 write
    _sys_0203.dont_write_bytecode = True   # a .pyc with one raw write; cut by a file size limit, every later run died (13/10/2026)
    _L0210 = type(__loader__)   # 0.21.0: a .pyc already cut (CPython 3.9/3.11 installed one) is compiled from the source
    if _L0210.__name__ == "SourceFileLoader":   # instead of failing every later run (EOFError: marshal data too short)
        def _get_code_0210(self, fullname, _get_code=_L0210.get_code):
            try:
                return _get_code(self, fullname)
            except (EOFError, ValueError):
                path = self.get_filename(fullname)
                return self.source_to_code(self.get_data(path), path)
        _L0210.get_code = _get_code_0210
import hashlib
import json
import os
import re
import cryptovalid_net as _net

LOTL_URL = "https://ec.europa.eu/tools/lotl/eu-lotl.xml"
_TSL_NS = "http://uri.etsi.org/02231/v2#"   # ETSI TS 119 612 trusted list namespace
_QTST_URI = "http://uri.etsi.org/TrstSvc/Svctype/TSA/QTST"
_GRANTED_URI = "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted"
# The rule the fingerprints are built with (also written into the cache: a cache built by another rule is not read;
# a cache also holds the status of the day it was built, so it carries built_at and is rebuilt after CACHE_MAX_AGE_S).
# Until 0.20.1 a TSPService counted as qualified when the text "Svcstatus/granted" appeared ANYWHERE in it, its
# ServiceHistory included: a service withdrawn today with "granted" in its history was qualified (measured 12/10/2026 on 26
# of the 30 national lists the LOTL points to: 984 fingerprints against 652 in force on that day).
# 0.21.0 (rule /2): ETSI TS 119 615 PRO-4.3.4-03A — a QTST service whose ServiceHistoryInstance entries are not in
# descending order of StatusStartingTime (TS 119 612 5.5.10), or two of which share one StatusStartingTime, is an ERROR
# for that service: not counted, and its certificates named with the reason (until 0.20.3 it was counted, the first
# entry of the tie taken; measured 14/10/2026 on 26 lists of 12/10: 39 services with such a tie, none of them QTST).
RULE = "etsi-ts-119612/status-in-force:QTST+granted/3"   # /3 (SPEC §22 rule 6): built only from lists whose signature verified
HISTORY_NOT_ORDERED = "history_not_ordered"           # PRO-4.3.4-03A a)
HISTORY_DUPLICATE_START = "history_duplicate_start"   # PRO-4.3.4-03A b)

def _get(url, timeout=45):
    # SPEC v0.14 §22 rule 6: https only. Until 0.27.0 http was allowed because one of the 31 national lists the EU
    # LOTL points to is served over http only (tl.nbu.gov.sk, measured 15/11 and 20/11/2026); that list is now refused.
    with _net.open_url(url, timeout, _net.ALLOW_HTTPS) as r:
        return _net.read_body(r)   # SPEC v0.13 §21 rule 6: bounded

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
    for s in root.findall("{http://www.w3.org/2000/09/xmldsig#}Signature"):
        root.remove(s)   # SPEC §22 rule 6: the content read is what the enveloped signature covers, never its Objects
    return root

# ── SPEC v0.14 §22 rule 6: the XAdES signature of the LOTL and of every trusted list ─────────────────────────────
# Until 0.27.0 a list was trusted for the channel it came over (a list and a LOTL without any ds:Signature made a token
# qualified; one national list is served over http). Now a list counts only when its enveloped XAdES signature verifies:
# the LOTL under a certificate of the Official Journal publication in force, each national list under a certificate the
# LOTL's pointer to it names. Exclusive XML Canonicalization 1.0 (without comments) is written here on expat: the
# standard library has only C14N 2.0 (xml.etree.ElementTree.canonicalize), which writes the prefix a namespace was FIRST
# bound to instead of the one the element uses, and gave other bytes than the signer on 1 of the 31 lists of 20/11/2026
# (HU: a default namespace and `tsl:` bound to the same URI). The shape accepted is closed: the one every list had on
# 2026-11-20 (one signature, child of the root; exclusive C14N; two references, the document with the enveloped
# transform and the XAdES SignedProperties; one certificate; SigningCertificateV2), anything else is refused, named.

# Official Journal of the EU, C/2026/1944 (15.4.2026), "Information related to data on Member States' trusted lists as
# notified under Commission Implementing Decision (EU) 2015/1505 as amended by Commission Implementing Decision (EU)
# 2025/2164", read at eur-lex.europa.eu on 2026-11-20: it replaces OJ C 276, 16.8.2019, p. 1, and the LOTL of that day
# (sequence 398) names it first in SchemeInformationURI. The SHA-256 digests of its six LOTL-signing certificates:
OJ_LOTL_URL = "https://eur-lex.europa.eu/eli/C/2026/1944/oj"
OJ_LOTL_SIGNERS_SHA256 = frozenset({
    "c0641c4f7d56c431b1c924742db7fce9c1eef7d7fd212113a2768486b3abcdc5",
    "e0a620fbb6747362bb933ac44169d676a553444716cf5f31605f12a22b8396b1",
    "df7e29360c34b2b8d6d5f40325c1d4d12c9922cecd33b7407674a74b2b3ca1e5",
    "b63d416744e7098bf9ec2caa596a93bc2468e37f8284ba65ecc061711bcbaa18",
    "236103f03a8031ae8f47f9059bf8de38564cdbfebedde4a597d50f8980aa653b",
    "d2064fdd70f6982dcc516b86d9d5c56aea939417c624b2e478c0b29de54f8474",
})

_DS = "http://www.w3.org/2000/09/xmldsig#"
_XADES = "http://uri.etsi.org/01903/v1.3.2#"
_XML_NS = "http://www.w3.org/XML/1998/namespace"
_EXC_C14N = "http://www.w3.org/2001/10/xml-exc-c14n#"
_ENVELOPED = "http://www.w3.org/2000/09/xmldsig#enveloped-signature"
_SIGNED_PROPERTIES_TYPE = "http://uri.etsi.org/01903#SignedProperties"
_DIGESTS = {"http://www.w3.org/2001/04/xmlenc#sha256": "sha256", "http://www.w3.org/2001/04/xmldsig-more#sha384": "sha384",
            "http://www.w3.org/2001/04/xmlenc#sha512": "sha512"}
_SIG_ALGS = {   # RFC 6931 identifiers: (family, hash)
    "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256": ("rsa", "sha256"),
    "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384": ("rsa", "sha384"),
    "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512": ("rsa", "sha512"),
    "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256": ("ecdsa", "sha256"),
    "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384": ("ecdsa", "sha384"),
    "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512": ("ecdsa", "sha512"),
    "http://www.w3.org/2007/05/xmldsig-more#sha256-rsa-MGF1": ("rsa-pss", "sha256"),
    "http://www.w3.org/2007/05/xmldsig-more#sha384-rsa-MGF1": ("rsa-pss", "sha384"),
    "http://www.w3.org/2007/05/xmldsig-more#sha512-rsa-MGF1": ("rsa-pss", "sha512"),
}
_MAX_DEPTH = 64   # the deepest of the 31 documents of 2026-11-20 (the LOTL and 30 lists) is 17 elements deep


class _Node:
    """An element as expat gives it without namespace processing: the qualified name as written, the attributes in
    document order, the children (text, ("pi", target, data), _Node), and the namespaces in scope."""
    __slots__ = ("qname", "attrs", "children", "parent", "ns")

    def __init__(self, qname, attrs, parent):
        self.qname, self.attrs, self.children, self.parent = qname, attrs, [], parent
        self.ns = dict(parent.ns) if parent is not None else {"": "", "xml": _XML_NS}
        for k, v in attrs:
            if k == "xmlns":
                self.ns[""] = v
            elif k.startswith("xmlns:"):
                self.ns[k[6:]] = v

    def name(self):
        """(namespace URI, local name); an unbound prefix is a ValueError."""
        pfx, local = _split(self.qname)
        if pfx not in self.ns:
            raise ValueError(f"xmldsig_malformed: unbound prefix {pfx!r}")
        return self.ns[pfx], local

    def kids(self, uri, local):
        return [c for c in self.children if isinstance(c, _Node) and c.name() == (uri, local)]

    def elements(self):
        return [c for c in self.children if isinstance(c, _Node)]

    def text(self):
        return "".join(c for c in self.children if isinstance(c, str))

    def attr(self, name):
        for k, v in self.attrs:
            if k == name:
                return v
        return None


def _split(qname):
    return tuple(qname.split(":", 1)) if ":" in qname else ("", qname)


def _xml_tree(data: bytes):
    """(document element, PIs before it, PIs after it), with every element's namespaces resolved and checked (an unbound
    prefix, two attributes with one expanded name, deeper than _MAX_DEPTH: ValueError). DTDs are refused (_parse_tl)."""
    import xml.parsers.expat as expat
    p = expat.ParserCreate()
    p.buffer_text = True
    p.ordered_attributes = True
    root, stack, before, after = [None], [], [], []

    def start(name, attrs):
        if len(stack) >= _MAX_DEPTH:
            raise ValueError(f"xmldsig_malformed: deeper than {_MAX_DEPTH} elements")
        n = _Node(name, list(zip(attrs[0::2], attrs[1::2])), stack[-1] if stack else None)
        n.name()
        seen = set()
        for k, _v in n.attrs:
            if k == "xmlns" or k.startswith("xmlns:"):
                continue
            pfx, local = _split(k)
            if pfx and pfx not in n.ns:
                raise ValueError(f"xmldsig_malformed: unbound prefix {pfx!r}")
            key = (n.ns[pfx] if pfx else "", local)
            if key in seen:
                raise ValueError("xmldsig_malformed: two attributes with one expanded name")
            seen.add(key)
        if stack:
            stack[-1].children.append(n)
        else:
            root[0] = n
        stack.append(n)

    def end(_name):
        stack.pop()

    def chars(d):
        if stack:
            stack[-1].children.append(d)

    def pi(target, d):
        (stack[-1].children if stack else (after if root[0] is not None else before)).append(("pi", target, d))
    p.StartElementHandler, p.EndElementHandler, p.CharacterDataHandler = start, end, chars
    p.ProcessingInstructionHandler = pi
    p.StartDoctypeDeclHandler = _refuse
    p.EntityDeclHandler = _refuse
    try:
        p.Parse(data, True)
    except expat.ExpatError as e:
        raise ValueError(f"trusted list is not well-formed XML: {e}") from None
    return root[0], before, after


def _esc_text(s):
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\r", "&#xD;")


def _esc_attr(s):
    return (s.replace("&", "&amp;").replace("<", "&lt;").replace('"', "&quot;")
             .replace("\t", "&#x9;").replace("\n", "&#xA;").replace("\r", "&#xD;"))


def exc_c14n(node, exclude=None, before=(), after=()) -> bytes:
    """Exclusive XML Canonicalization 1.0 without comments (W3C REC 2002-07-18) of the subtree of `node`, without the
    subtree `exclude` (the enveloped-signature transform). `before`/`after`: the PIs outside the document element, when
    the whole document is canonicalized. No InclusiveNamespaces PrefixList (refused where the signature is read)."""
    out = []
    for _pi, t, d in before:
        out.append(f"<?{t} {d}?>\n" if d else f"<?{t}?>\n")

    def walk(n, rendered):
        pfx, _ = _split(n.qname)
        used = {pfx}
        attrs = []
        for k, v in n.attrs:
            if k == "xmlns" or k.startswith("xmlns:"):
                continue
            ap, al = _split(k)
            if ap:
                used.add(ap)
            attrs.append(((n.ns[ap] if ap else "", al), k, v))
        new = dict(rendered)
        decl = []
        for q in sorted(used):
            if q == "xml":
                continue
            uri = n.ns[q]
            if (rendered.get(q, "") if q == "" else rendered.get(q)) != uri:
                decl.append((q, uri))
                new[q] = uri
        out.append("<" + n.qname)
        for q, uri in decl:
            out.append(f' xmlns="{_esc_attr(uri)}"' if q == "" else f' xmlns:{q}="{_esc_attr(uri)}"')
        for _key, k, v in sorted(attrs, key=lambda a: a[0]):
            out.append(f' {k}="{_esc_attr(v)}"')
        out.append(">")
        for c in n.children:
            if isinstance(c, str):
                out.append(_esc_text(c))
            elif isinstance(c, tuple):
                out.append(f"<?{c[1]} {c[2]}?>" if c[2] else f"<?{c[1]}?>")
            elif c is not exclude:
                walk(c, new)
        out.append("</" + n.qname + ">")
    walk(node, {})
    for _pi, t, d in after:
        out.append(f"\n<?{t} {d}?>" if d else f"\n<?{t}?>")
    return "".join(out).encode("utf-8")


def _one(node, uri, local, where):
    k = node.kids(uri, local)
    if len(k) != 1:
        raise ValueError(f"xmldsig_shape: {where} has {len(k)} {local} (one expected)")
    return k[0]


def _algorithm(node, where, allowed):
    a = node.attr("Algorithm")
    if a not in allowed:
        raise ValueError(f"xmldsig_algorithm: {where} {a!r} is not one this verifier reads")
    if node.elements():
        raise ValueError(f"xmldsig_shape: {where} carries parameters")
    return a


def _b64(text, where):
    import base64
    import binascii
    s = re.sub(r"[ \t\r\n]+", "", text)
    try:
        return base64.b64decode(s, validate=True)
    except (binascii.Error, ValueError):
        raise ValueError(f"xmldsig_malformed: {where} is not base64") from None


def _all_nodes(n):
    stack = [n]
    while stack:
        x = stack.pop()
        yield x
        stack.extend(reversed(x.elements()))


def _transforms(ref):
    tr = ref.kids(_DS, "Transforms")
    if len(tr) > 1:
        raise ValueError("xmldsig_shape: a Reference has two Transforms")
    out = []
    for t in (tr[0].elements() if tr else []):
        if t.name() != (_DS, "Transform"):
            raise ValueError("xmldsig_shape: Transforms holds an element that is not a Transform")
        if t.elements():
            raise ValueError("xmldsig_shape: a Transform carries parameters (InclusiveNamespaces is not read)")
        out.append(t.attr("Algorithm"))
    return out


_SEQ_MAX_DIGITS = 18   # XML Schema Part 2, 3.2.3: a processor supports at least 18 decimal digits and documents its limit


def _sequence_number(root) -> int:
    """TSLSequenceNumber of SchemeInformation (ETSI TS 119 612 5.3.2: an integer, 1 for the first list, incremented at each
    issue): one SchemeInformation child of the root holding exactly one TSLSequenceNumber, which has no child element
    and whose text, XML white space (space, tab, CR, LF) around it apart, is 1 to 18 ASCII digits, the number >= 1; else
    ValueError (every one of the 31 documents of 2026-11-20 has one, the largest 398)."""
    sis = root.findall(_q("SchemeInformation"))
    seq = sis[0].findall(_q("TSLSequenceNumber")) if len(sis) == 1 else []
    text = (seq[0].text or "").strip(" \t\r\n") if len(seq) == 1 and len(seq[0]) == 0 else ""
    if not (text.isascii() and text.isdigit()) or len(text) > _SEQ_MAX_DIGITS or int(text) < 1:
        raise ValueError("tl_sequence_malformed: one SchemeInformation must hold one TSLSequenceNumber, an integer >= 1 "
                         f"of at most {_SEQ_MAX_DIGITS} digits")
    return int(text)


def verify_list_signature(xml: bytes, trusted_sha256, at=None, min_sequence=None) -> dict:
    """The enveloped XAdES signature of a trusted list or of the LOTL (SPEC §22 rule 6): {"signer_sha256", "signing_time",
    "signature_method"} when it verifies under a certificate whose SHA-256 is in `trusted_sha256`; else ValueError naming
    why (xmldsig_missing, xmldsig_shape, xmldsig_algorithm, xmldsig_digest_mismatch, xmldsig_signature_invalid,
    xmldsig_signing_certificate, xmldsig_untrusted_signer, xmldsig_certificate_not_valid, xmldsig_malformed,
    tl_next_update_passed, tl_sequence_malformed, tl_sequence_rolled_back). `at` (aware datetime, default now): the
    instant the signing certificate must be valid at and the list's NextUpdate must not be before. The result carries
    the list's TSLSequenceNumber (`sequence_number`); `min_sequence` (an int >= 1, e.g. the number a caller kept from an
    earlier run): a list with a lower number is refused, `tl_sequence_rolled_back` (an earlier list, still signed with
    a trusted certificate and within its NextUpdate, verifies otherwise: no state is kept here)."""
    if min_sequence is not None and (isinstance(min_sequence, bool) or not isinstance(min_sequence, int) or min_sequence < 1):
        raise ValueError("min_sequence: an integer >= 1, or None")
    import hashlib as _h
    from datetime import datetime, timezone
    at = at or datetime.now(timezone.utc)
    if not isinstance(at, datetime) or at.tzinfo is None:   # as qtst_status_at: a naive instant cannot be compared
        raise ValueError("`at` must be a timezone-aware datetime")
    if not isinstance(xml, (bytes, bytearray)):
        raise ValueError("trusted list must be bytes")
    _parse_tl(bytes(xml))   # UTF-8, no DTD, a TrustServiceStatusList: the checks of the content's parser come first
    root, before, after = _xml_tree(bytes(xml))
    sigs = [n for n in _all_nodes(root) if n.name() == (_DS, "Signature")]
    if not sigs:
        raise ValueError("xmldsig_missing: the list carries no ds:Signature")
    if len(sigs) != 1 or sigs[0].parent is not root:
        raise ValueError("xmldsig_shape: one ds:Signature, a child of the list's root element, expected")
    sig = sigs[0]
    ids = {}
    for n in _all_nodes(root):
        for k, v in n.attrs:
            if k in ("Id", "ID", "id"):
                if v in ids:
                    raise ValueError(f"xmldsig_shape: the identifier {v[:40]!r} is on two elements")
                ids[v] = n
    names = [c.name() for c in sig.elements()]
    allowed_children = {(_DS, "SignedInfo"), (_DS, "SignatureValue"), (_DS, "KeyInfo"), (_DS, "Object")}
    if names[:3] != [(_DS, "SignedInfo"), (_DS, "SignatureValue"), (_DS, "KeyInfo")] or set(names) - allowed_children:
        raise ValueError("xmldsig_shape: ds:Signature must be SignedInfo, SignatureValue, KeyInfo, then Objects")
    si = _one(sig, _DS, "SignedInfo", "ds:Signature")
    if [c.name()[1] for c in si.elements()][:2] != ["CanonicalizationMethod", "SignatureMethod"] \
            or any(c.name() != (_DS, "Reference") for c in si.elements()[2:]) or any(c.name()[0] != _DS for c in si.elements()):
        raise ValueError("xmldsig_shape: SignedInfo must be CanonicalizationMethod, SignatureMethod, then References")
    _algorithm(si.elements()[0], "CanonicalizationMethod", {_EXC_C14N})
    family, hname = _SIG_ALGS[_algorithm(si.elements()[1], "SignatureMethod", _SIG_ALGS)]
    refs = si.elements()[2:]
    doc_refs = [r for r in refs if r.attr("URI") == ""]
    sp_refs = [r for r in refs if r.attr("Type") == _SIGNED_PROPERTIES_TYPE]
    if len(refs) != 2 or len(doc_refs) != 1 or len(sp_refs) != 1 or doc_refs[0] is sp_refs[0]:
        raise ValueError("xmldsig_shape: two References expected, the list (URI=\"\") and the XAdES SignedProperties")
    for r in refs:
        for k, _v in r.attrs:
            if k not in ("URI", "Type", "Id"):
                raise ValueError(f"xmldsig_shape: a Reference carries the attribute {k[:40]!r}")
        if [c.name() for c in r.elements()] != [(_DS, "Transforms"), (_DS, "DigestMethod"), (_DS, "DigestValue")]:
            raise ValueError("xmldsig_shape: a Reference must be Transforms, DigestMethod, DigestValue")
    if doc_refs[0].attr("Type") is not None:
        raise ValueError("xmldsig_shape: the reference to the list carries a Type")
    if _transforms(doc_refs[0]) != [_ENVELOPED, _EXC_C14N]:
        raise ValueError("xmldsig_shape: the reference to the list must be enveloped-signature then exclusive C14N")
    if _transforms(sp_refs[0]) != [_EXC_C14N]:
        raise ValueError("xmldsig_shape: the reference to SignedProperties must be exclusive C14N")
    sp_uri = sp_refs[0].attr("URI") or ""
    target = ids.get(sp_uri[1:]) if sp_uri.startswith("#") else None
    if target is None or target.name() != (_XADES, "SignedProperties") or not any(a is sig for a in _ancestors(target)):
        raise ValueError("xmldsig_shape: the SignedProperties reference does not name a SignedProperties of this signature")
    for r, content in ((doc_refs[0], exc_c14n(root, exclude=sig, before=before, after=after)), (sp_refs[0], exc_c14n(target))):
        alg = _DIGESTS[_algorithm(r.kids(_DS, "DigestMethod")[0], "DigestMethod", _DIGESTS)]
        if getattr(_h, alg)(content).digest() != _b64(r.kids(_DS, "DigestValue")[0].text(), "DigestValue"):
            raise ValueError("xmldsig_digest_mismatch: " + ("the list" if r is doc_refs[0] else "SignedProperties")
                             + " is not what was signed")
    ki = _one(sig, _DS, "KeyInfo", "ds:Signature")
    certs = [c for x in ki.kids(_DS, "X509Data") for c in x.kids(_DS, "X509Certificate")]
    if len(certs) != 1 or len(ki.elements()) != 1:
        raise ValueError("xmldsig_shape: KeyInfo must hold one X509Data with one X509Certificate")
    der = _b64(certs[0].text(), "X509Certificate")
    signer_sha256 = _h.sha256(der).hexdigest()
    # XAdES (ETSI EN 319 132-1) SigningCertificateV2: the certificate the signature is bound to, one Cert, its digest
    ssp = _one(target, _XADES, "SignedSignatureProperties", "SignedProperties")
    scv2 = _one(ssp, _XADES, "SigningCertificateV2", "SignedSignatureProperties")
    cert_el = _one(scv2, _XADES, "Cert", "SigningCertificateV2")
    cd = _one(cert_el, _XADES, "CertDigest", "Cert")
    calg = _DIGESTS[_algorithm(_one(cd, _DS, "DigestMethod", "CertDigest"), "CertDigest DigestMethod", _DIGESTS)]
    if getattr(_h, calg)(der).digest() != _b64(_one(cd, _DS, "DigestValue", "CertDigest").text(), "CertDigest"):
        raise ValueError("xmldsig_signing_certificate: SigningCertificateV2 names another certificate than KeyInfo")
    if signer_sha256 not in trusted_sha256:
        raise ValueError(f"xmldsig_untrusted_signer: certificate sha256 {signer_sha256} is not one the list may be signed with")
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa, utils
    try:
        cert = x509.load_der_x509_certificate(der)
        pub = cert.public_key()
        nvb, nva = cert.not_valid_before_utc, cert.not_valid_after_utc
    except (ValueError, AttributeError):   # not_valid_*_utc: cryptography >= 42, below the floor of 48
        raise ValueError("xmldsig_malformed: X509Certificate is not a certificate") from None
    if not nvb <= at <= nva:
        raise ValueError(f"xmldsig_certificate_not_valid: the signing certificate is valid from {nvb:%Y-%m-%dT%H:%M:%SZ} "
                         f"to {nva:%Y-%m-%dT%H:%M:%SZ}")
    nu = [d for n in _parse_tl(bytes(xml)).iter(_q("NextUpdate")) for d in n.findall(_q("dateTime"))]
    if nu:   # ETSI TS 119 612 5.3.15; an empty NextUpdate (a closed list, the same clause) is read as before
        when = _when((nu[0].text or "").strip())
        if len(nu) != 1 or when is None:
            raise ValueError("xmldsig_malformed: NextUpdate is not one dateTime of the form of TS 119 612 5.1.3")
        if when < at:
            raise ValueError(f"tl_next_update_passed: the list announced its next update for {nu[0].text.strip()}")
    h = {"sha256": hashes.SHA256(), "sha384": hashes.SHA384(), "sha512": hashes.SHA512()}[hname]
    sv = _b64(_one(sig, _DS, "SignatureValue", "ds:Signature").text(), "SignatureValue")
    signed = exc_c14n(si)
    try:
        if family == "ecdsa":
            if not isinstance(pub, ec.EllipticCurvePublicKey):
                raise ValueError("key")
            size = (pub.curve.key_size + 7) // 8
            if len(sv) != 2 * size:   # XML ECDSA: r || s, each the size of the curve (RFC 4050, RFC 6931 §2.3.6)
                raise ValueError("length")
            pub.verify(utils.encode_dss_signature(int.from_bytes(sv[:size], "big"), int.from_bytes(sv[size:], "big")),
                       signed, ec.ECDSA(h))
        else:
            if not isinstance(pub, rsa.RSAPublicKey):
                raise ValueError("key")
            pad = (padding.PSS(padding.MGF1(h), h.digest_size) if family == "rsa-pss"   # RFC 6931 §2.3.10 defaults
                   else padding.PKCS1v15())
            pub.verify(sv, signed, pad, h)
    except Exception:  # noqa: BLE001 — a key of another type, a length, a signature that fails: one verdict
        raise ValueError("xmldsig_signature_invalid: the signature value does not verify") from None
    st = ssp.kids(_XADES, "SigningTime")
    seqn = _sequence_number(_parse_tl(bytes(xml)))   # read once the signature holds: a forged list is named as such
    if min_sequence is not None and seqn < min_sequence:
        raise ValueError(f"tl_sequence_rolled_back: TSLSequenceNumber {seqn}, below the minimum {min_sequence} given")
    return {"signer_sha256": signer_sha256, "signing_time": st[0].text() if st else None,
            "signature_method": si.elements()[1].attr("Algorithm"), "sequence_number": seqn}


def _ancestors(n):
    while n is not None:
        n = n.parent
        yield n


def _pointer_certs(lotl_xml: bytes):
    """{TSLLocation: SHA-256 of every certificate of its OtherTSLPointer's ServiceDigitalIdentities} (the LOTL's own
    pointer, TSLType EUlistofthelists, under the key "")."""
    root = _parse_tl(lotl_xml)
    out = {}
    for ptr in root.iter(_q("OtherTSLPointer")):
        loc = _text(ptr, "TSLLocation") or ""
        types = [(t.text or "").strip() for t in ptr.iter(_q("TSLType"))]
        key = "" if _LOTL_TYPE in types else loc
        fp = out.setdefault(key, set())
        for c in ptr.iter(_q("X509Certificate")):
            f = _cert_fpr(re.sub(r"\s+", "", c.text or ""))
            if f:
                fp.add(f)
    return out


def lotl_signers(lotl_xml: bytes, get=None, timeout=45, anchors=OJ_LOTL_SIGNERS_SHA256, oj_url=OJ_LOTL_URL):
    """The certificates (SHA-256) the LOTL may be signed with, by the pivot mechanism of the OJ publication (its section
    2): SchemeInformationURI lists, newest first, the pivot LOTLs published after the latest OJ publication, then that
    publication. From the OJ's certificates, each pivot (oldest first, https) must verify under the current set and gives
    the next one (the certificates of its own pointer). A LOTL that does not name `oj_url` is refused: this version knows
    no other publication."""
    root = _parse_tl(lotl_xml)
    si = root.find(_q("SchemeInformation"))
    uris = [(u.text or "").strip() for u in (si.find(_q("SchemeInformationURI")) if si is not None else []) or []]
    if oj_url not in uris:
        raise ValueError(f"lotl_oj_unknown: the LOTL does not name {oj_url}, the Official Journal publication this "
                         "version trusts (a newer publication needs a newer version)")
    trusted = set(anchors)
    for url in reversed(uris[:uris.index(oj_url)]):
        pivot = (get or _get)(url, timeout)
        verify_list_signature(pivot, trusted)
        trusted = _pointer_certs(pivot).get("", set())
        if not trusted:
            raise ValueError(f"lotl_pivot_without_certificates: {url}")
    return trusted


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

def _history_error(timeline):
    """PRO-4.3.4-03A over the ServiceHistoryInstance entries (timeline[1:], document order): None, or the reason."""
    starts = [e[0] for e in timeline[1:]]
    if len(set(starts)) < len(starts):
        return HISTORY_DUPLICATE_START
    if any(starts[i] < starts[i + 1] for i in range(len(starts) - 1)):
        return HISTORY_NOT_ORDERED
    return None

def qtst_status_at(tl_xml: bytes, at):
    """{"granted": fingerprints, "errors": {fingerprint: reason}} at the instant `at` (aware datetime). `granted` is
    qtst_fingerprints_at; `errors` names the certificates of QTST services (type of their ServiceInformation, as TS 119 615
    PRO-4.3.4-03 selects them) whose history TS 119 615 PRO-4.3.4-03A makes an error: such a service is in neither set
    of `granted`, and a token from it is neither qualified nor not qualified (see qualification)."""
    from datetime import datetime
    if not isinstance(at, datetime) or at.tzinfo is None:
        raise ValueError("`at` must be a timezone-aware datetime")
    fprs, errors = set(), {}
    for svc in services(tl_xml):
        tl = svc["timeline"]
        if any(start is None for start, *_ in tl):
            continue
        if tl[0][1] == _QTST_URI:
            why = _history_error(tl)
            if why:
                for f in svc["certs"]:
                    errors[f] = why
                continue
        in_force = [e for e in tl if e[0] <= at]
        if not in_force:
            continue
        _start, typ, status, _certs_of_entry = max(in_force, key=lambda e: e[0])
        if typ == _QTST_URI and status == _GRANTED_URI:
            fprs |= svc["certs"]
    return {"granted": fprs - set(errors), "errors": errors}

def qtst_fingerprints_at(tl_xml: bytes, at):
    """Fingerprints of services that were qualified timestamp services AT the instant `at` (an aware datetime, e.g. the
    genTime of a token): the entry in force is the one, among ServiceInformation and the ServiceHistoryInstance entries,
    with the latest StatusStartingTime <= `at` (an entry applies from its starting time, inclusive); its type must be
    TSA/QTST and its status granted. The service is identified by the certificates of its ServiceInformation, as ETSI TS
    119 615 (PRO-4.3.4-03) matches a certificate against the 'Service digital identity' of the ServiceInformation entry;
    a certificate found only in a history instance is not counted (none on 12/10/2026 in 30 lists). A service with
    an entry whose StatusStartingTime is missing or not a dateTime is not counted at any instant (its timeline cannot be
    ordered). A QTST service whose history TS 119 615 PRO-4.3.4-03A makes an error is not counted
    (qtst_status_at names it). The genTime is NOT extracted from the token here: the caller gives it."""
    return qtst_status_at(tl_xml, at)["granted"]

def _ms_of_url(url: str) -> str:
    """Member-state hint dal TLD dell'host della Trusted List (crc.bg -> BG).
    Hint approssimato (il codice vero è SchemeTerritory nel puntatore LOTL): una TL
    ospitata su dominio .eu/.com non matcherebbe — il filtro è SOLO un'ottimizzazione
    opzionale di velocità; senza filtro si scarica tutto (default, copertura piena)."""
    return url.split("/")[2].split(".")[-1].upper()


CACHE_MAX_AGE_S = 24 * 3600   # a cache holds the statuses in force on the day it was built: older than this, it is rebuilt

def load_qualified_fingerprints(member_states=None, cache_path=None, timeout=45, log=lambda *_: None,
                                cache_max_age_s=CACHE_MAX_AGE_S, trusted_lotl_signers=None):
    """(fingerprints, coverage) of load_qualified_status, without the history errors."""
    fprs, coverage, _errors = load_qualified_status(member_states, cache_path, timeout, log, cache_max_age_s,
                                                    trusted_lotl_signers)
    return fprs, coverage

def load_qualified_status(member_states=None, cache_path=None, timeout=45, log=lambda *_: None,
                          cache_max_age_s=CACHE_MAX_AGE_S, trusted_lotl_signers=None, min_sequences=None,
                          sequences_out=None):
    """Build the set of qualified-TSA cert fingerprints from the EU LOTL, with the history errors (fingerprint ->
    "<reason> <list url>", qtst_status_at): returns (fingerprints, coverage, errors).
    member_states: optional iterable of 2-letter codes to restrict fetching (else all).
    A cache is read only when it was built by this RULE and less than `cache_max_age_s` seconds ago (it records
    `built_at`): the set is the status in force when it was built, so an old cache would answer for an old day.
    SPEC §22 rule 6: the LOTL's XAdES signature must verify under `trusted_lotl_signers` (SHA-256 of certificates; None =
    those of the Official Journal publication in force, OJ_LOTL_SIGNERS_SHA256, through the pivot LOTLs it names), else
    ValueError and nothing is built; each list's under the certificates the LOTL's pointer to it names, else it is
    skipped and logged; a list served over http is skipped.
    `min_sequences` ({location: int}, the LOTL under LOTL_URL): a list whose TSLSequenceNumber is lower is refused (the
    LOTL: ValueError; a national list: skipped and logged, `tl_sequence_rolled_back`); with it the cache is not read. A
    location that is neither the LOTL's nor one the verified LOTL points to is a ValueError (a minimum that would apply
    to no list is not ignored).
    `sequences_out` (a dict, else ValueError): filled with {location: TSLSequenceNumber} of every list that verified, so a
    caller can keep them and give them back as `min_sequences` next time; the cache records them too (`sequences`, read
    back only when they are {location: integer >= 1})."""
    from datetime import datetime, timezone
    if min_sequences is not None:
        if not isinstance(min_sequences, dict) or not all(isinstance(k, str) and isinstance(v, int) and not isinstance(v, bool)
                                                         and v >= 1 for k, v in min_sequences.items()):
            raise ValueError("min_sequences: a dict of list location -> integer >= 1, or None")
    if sequences_out is not None and not isinstance(sequences_out, dict):
        raise ValueError("sequences_out: a dict to fill, or None")
    if cache_path and os.path.exists(cache_path) and min_sequences is None:
        try:   # SPEC §5 step 0: a regular file, opened once without blocking
            from verifier import read_text_regular
        except ImportError:   # python3 -m opencore.<module> from the parent directory
            from opencore.verifier import read_text_regular
        d = json.loads(read_text_regular(cache_path))
        built = _when(d.get("built_at")) if isinstance(d, dict) and isinstance(d.get("built_at"), str) else None
        age = (datetime.now(timezone.utc) - built).total_seconds() if built else None
        if isinstance(d, dict) and d.get("rule") == RULE and isinstance(d.get("fingerprints"), list) \
                and age is not None and 0 <= age <= cache_max_age_s:
            errs = d.get("history_errors", {})
            if sequences_out is not None:
                sq = d.get("sequences")
                sequences_out.clear()
                sequences_out.update(sq if isinstance(sq, dict) and all(
                    isinstance(n, int) and not isinstance(n, bool) and n >= 1 for n in sq.values()) else {})
            return set(d["fingerprints"]), d.get("coverage", []), dict(errs) if isinstance(errs, dict) else {}
        log(f"LOTL cache {cache_path} not used (rule {d.get('rule') if isinstance(d, dict) else None!r}, "
            f"built_at {d.get('built_at') if isinstance(d, dict) else None!r}): rebuilt")
    lotl = _get(LOTL_URL, timeout)
    # SPEC §22 rule 6: the LOTL counts only under a certificate of the OJ publication (or of a pivot it leads to), and
    # each list only under a certificate of the LOTL's pointer to it; a list that fails is not covered, and named
    mins = min_sequences or {}
    v = verify_list_signature(lotl, lotl_signers(lotl, timeout=timeout) if trusted_lotl_signers is None
                              else set(trusted_lotl_signers), min_sequence=mins.get(LOTL_URL))
    log(f"LOTL signature verified (signer certificate sha256 {v['signer_sha256']}, sequence {v['sequence_number']})")
    seqs = {LOTL_URL: v["sequence_number"]}
    ptr_certs = _pointer_certs(lotl)
    ptrs = lotl_pointers(lotl)
    unknown = sorted(set(mins) - {LOTL_URL} - set(ptrs))
    if unknown:
        raise ValueError(f"min_sequences: {unknown[0]!r} is neither the LOTL's location nor a list the LOTL points to")
    from datetime import datetime as _dt, timezone as _tz
    now = _dt.now(_tz.utc)
    fprs, coverage, errors = set(), [], {}
    wanted = {m.upper() for m in member_states} if member_states else None
    for url in ptrs:
        if wanted and _ms_of_url(url) not in wanted:
            continue
        if not url.startswith("https://"):
            log(f"TL skip: {url} (served over {url.split(':', 1)[0]}: refused, SPEC §22 rule 6)")
            continue
        try:
            tl = _get(url, timeout)
            tv = verify_list_signature(tl, ptr_certs.get(url, set()), min_sequence=mins.get(url))
            seqs[url] = tv["sequence_number"]
            n0 = len(fprs); st = qtst_status_at(tl, now); fprs |= st["granted"]
            errors.update({f: f"{why} {url}" for f, why in st["errors"].items()})
            coverage.append(url); log(f"TL ok: {url} (+{len(fprs)-n0} QTST cert)"
                                      + (f", {len(st['errors'])} cert in a history error" if st["errors"] else ""))
        except Exception as e:  # una TL irraggiungibile (o la cui firma non verifica) non e' fatale: non coperta, nominata
            log(f"TL skip: {url} ({type(e).__name__}: {str(e)[:160]})")
    if cache_path:
        write_output(cache_path, json.dumps({"rule": RULE, "built_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                                             "fingerprints": sorted(fprs - set(errors)), "coverage": coverage,
                                             "history_errors": dict(sorted(errors.items())),
                                             "sequences": dict(sorted(seqs.items()))}))   # whole, or not at all (0.20.3)
    if sequences_out is not None:
        sequences_out.clear()
        sequences_out.update(seqs)
    return fprs - set(errors), coverage, errors

def token_cert_fingerprints(token_der: bytes):
    """SHA-256 fingerprints of every certificate embedded in an RFC 3161 token (CMS)."""
    from cryptography.hazmat.primitives.serialization import pkcs7, Encoding
    certs = pkcs7.load_der_pkcs7_certificates(token_der)
    return {hashlib.sha256(c.public_bytes(Encoding.DER)).hexdigest() for c in certs}

def signer_fingerprints(token_der: bytes):
    """{SHA-256 of the certificate that verified the token's signature} (SPEC §11 step 6), an empty set when the token is
    not an RFC 3161 token or its signature does not verify, None when openssl is absent. Since v0.6 of the spec the
    qualification looks at this certificate only: until then it looked at every certificate the token carried, so a CMS
    blob signed with any key that carried a QTST certificate was "qualified" (measured 2026-11-13)."""
    try:
        import cryptovalid_tsa as tsa
    except ImportError:   # imported as opencore.cryptovalid_lotl
        from opencore import cryptovalid_tsa as tsa
    state, fpr, _why = tsa.token_signer(token_der)
    if state == "not_evaluated":
        return None
    return {fpr} if state == "valid" else set()

OID_QC_STATEMENTS = "1.3.6.1.5.5.7.1.3"   # RFC 3739 §3.2.6, id-pe-qcStatements
OID_QTST_STATEMENT = "0.4.0.19422.1.1"    # ETSI EN 319 422 Annex B, esi4-qtstStatement-1 (id-etsi-tsts-EuQCompliance)


def qualified_statement_problem(token_der: bytes):
    """SPEC §11 "The qualified statement" (v0.10, Regulation (EU) 2025/1929, Annex, EN 319 422 clause 9.1): None when the
    token's TSTInfo carries exactly one qcStatements extension (non-critical: step 3 refuses a critical one) holding exactly
    one esi4-qtstStatement-1 without statementInfo; else "qualified_statement_missing" or "qualified_statement_malformed"."""
    try:
        import cryptovalid_tsa as tsa
    except ImportError:   # imported as opencore.cryptovalid_lotl
        from opencore import cryptovalid_tsa as tsa
    try:
        exts = tsa.parse_token(token_der)["extensions"]
    except (tsa.TokenError, ValueError, TypeError):
        return "qualified_statement_malformed"
    qc = [v for oid, _crit, v in exts if oid == OID_QC_STATEMENTS]
    if not qc:
        return "qualified_statement_missing"
    if len(qc) > 1:
        return "qualified_statement_malformed"
    try:
        ids = []
        for tag, sv in tsa._der_items(tsa._der_one(qc[0], "QCStatements", 0x30), "QCStatements"):
            st = tsa._der_items(sv, "QCStatement")
            if tag != 0x30 or not st or st[0][0] != 0x06 or len(st) > 2:
                return "qualified_statement_malformed"
            ids.append((tsa._der_oid(st[0][1], "statementId"), len(st)))
    except (tsa.TokenError, ValueError, IndexError):
        return "qualified_statement_malformed"
    hits = [n for oid, n in ids if oid == OID_QTST_STATEMENT]
    if not hits:
        return "qualified_statement_missing"
    if len(hits) > 1 or hits[0] != 1:
        return "qualified_statement_malformed"
    return None


def is_qualified(token_der: bytes, qualified_fingerprints: set):
    """True iff the certificate that signed the token is a qualified-timestamp service in the EU LOTL."""
    return qualification(token_der, qualified_fingerprints)[0] == "qualified"

def qualification(token_der: bytes, qualified_fingerprints: set, history_errors=None, signer_sha256=None):
    """("qualified", None), ("not_qualified", None), ("not_qualified", reason) or ("indeterminate", reason), on the
    certificate that signed the token (SPEC §11): `signer_sha256` when the caller has it from
    `cryptovalid_tsa.verify_token`, else `signer_fingerprints`. Since v0.10 a signer in the lists gives "qualified" only when
    the token carries the qualified statement of Regulation (EU) 2025/1929, else ("not_qualified",
    "qualified_statement_missing" | "qualified_statement_malformed"). Indeterminate when the signer is not a qualified
    certificate and is one of a QTST service whose history TS 119 615 PRO-4.3.4-03A makes an error, or when openssl is
    absent (the signer is not established)."""
    got = {signer_sha256} if signer_sha256 else signer_fingerprints(token_der)
    if got is None:
        return "indeterminate", "openssl absent: the token's signer is not established"
    if got & qualified_fingerprints:
        why = qualified_statement_problem(token_der)
        return ("qualified", None) if why is None else ("not_qualified", why)
    hit = sorted(f for f in got if f in (history_errors or {}))
    if hit:
        return "indeterminate", (history_errors or {})[hit[0]]
    return "not_qualified", None


try:   # 0.20.3: the one writer of every command (verifier.py): an outcome is written whole, or exit 74
    from verifier import Parser, emit, receipt_cli, say, write_output
except ImportError:   # python3 -m opencore.<module> from the parent directory
    from opencore.verifier import Parser, emit, receipt_cli, say, write_output


@receipt_cli
def main(argv=None):
    import argparse
    import base64
    p = Parser(prog="cryptovalid_lotl",
                                description="Certify an RFC 3161 token as eIDAS-qualified via the EU LOTL.")
    p.add_argument("token_b64", help="RFC 3161 TimeStampToken, base64 (from cryptovalid_tsa)")
    p.add_argument("--cache", default=None, help="cache file for qualified fingerprints")
    p.add_argument("--ms", nargs="*", default=None, help="restrict to member-state codes (e.g. IT DE)")
    a = p.parse_args(argv)
    fprs, cov, errs = load_qualified_status(a.ms, a.cache, log=lambda m: emit("  " + m))
    tok = base64.b64decode(a.token_b64)
    verdict, why = qualification(tok, fprs, errs)
    q = verdict == "qualified"
    out = {"qualified": q, "qualified_certs_in_lotl": len(fprs), "trusted_lists_covered": len(cov)}
    if verdict == "indeterminate":   # 0.21.0: only then, so every other output is the one of 0.20.3
        out["indeterminate"] = why
    elif why:                        # v0.10: a QTST signer whose token lacks the qualified statement
        out["not_qualified_reason"] = why
    emit(json.dumps(out, indent=2))
    return 0 if q else 1

if __name__ == "__main__":
    raise SystemExit(main())
