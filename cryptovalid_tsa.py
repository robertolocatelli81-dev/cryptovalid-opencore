#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Roberto Locatelli
"""RFC 3161 timestamping client for cryptovalid-opencore — real (qualified) TSP integration.

Requests an RFC 3161 timestamp over a digest (e.g. a Merkle Signed Tree Head root) from a
Time-Stamping Authority, stores the token, and verifies it. Point `tsa_url` at a **qualified**
TSP in the eIDAS EU Trusted List to obtain a *qualified* timestamp with enhanced legal presumption
(Art. 41/42 Reg. 910/2014); the RFC 3161 protocol is identical for qualified and non-qualified TSAs.

Stdlib-only for the protocol (hand-rolled DER TimeStampReq + response parsing). The token check is `verify_token`
(SPEC_EVIDENCE_FORMAT.md §11): the TSTInfo read closed in stdlib, the signature and the pinned TSA through the `openssl`
CLI when available. No new Python dependencies.
"""
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
import os
import urllib.request

import cryptovalid_net as _net

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
    # http or https only (RFC 3161 §3.4 is HTTP; the token is signed and checked): `file:`, `ftp:`, `data:` are refused
    with _net.open_url(r, timeout, _net.ALLOW_HTTP_OR_HTTPS) as resp:
        raw = resp.read()
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
    """True iff the token parses as an RFC 3161 token (SPEC §11 steps 1-4) whose messageImprint.hashedMessage is `digest`.
    No signature is checked here: `verify_token` is the check. Until 0.22.0 this searched the bytes `04 20 <digest>`
    anywhere in the blob, so any blob that merely contained them passed (SPEC §6, v0.6)."""
    try:
        return parse_token(token_der)["hashed_message"] == bytes(digest)
    except TokenError:
        return False


# ── RFC 3161 token, read closed (SPEC §11, v0.6, 2026-11-13) ──
class TokenError(ValueError):
    """A token refused by SPEC §11: `reason` is one of the closed reasons, `detail` says where."""
    def __init__(self, reason: str, detail: str):
        super().__init__(f"{reason}: {detail}")
        self.reason, self.detail = reason, detail


OID_SIGNED_DATA = "1.2.840.113549.1.7.2"
OID_TSTINFO = "1.2.840.113549.1.9.16.1.4"
HASH_ALGORITHMS = {   # SPEC §11 step 4: the closed list (name, digest length); SHA-1 and anything else refused
    "2.16.840.1.101.3.4.2.1": ("sha256", 32), "2.16.840.1.101.3.4.2.2": ("sha384", 48),
    "2.16.840.1.101.3.4.2.3": ("sha512", 64), "2.16.840.1.101.3.4.2.8": ("sha3-256", 32),
    "2.16.840.1.101.3.4.2.9": ("sha3-384", 48), "2.16.840.1.101.3.4.2.10": ("sha3-512", 64)}


def _der_items(buf: bytes, where: str):
    """Every TLV of `buf`, in order: [(tag, value)]. DER only: definite length in the shortest form, low tag numbers, the
    elements fill `buf` exactly. Anything else is TokenError('malformed')."""
    out, i, n = [], 0, len(buf)
    while i < n:
        tag = buf[i]
        if tag & 0x1F == 0x1F:
            raise TokenError("malformed", f"{where}: high tag number at offset {i}")
        if i + 1 >= n:
            raise TokenError("malformed", f"{where}: truncated at offset {i}")
        first, j = buf[i + 1], i + 2
        if first < 0x80:
            ln = first
        elif first == 0x80:
            raise TokenError("malformed", f"{where}: indefinite length at offset {i}")
        else:
            k = first & 0x7F
            if k > 4 or j + k > n:
                raise TokenError("malformed", f"{where}: length of {k} bytes at offset {i}")
            ln = int.from_bytes(buf[j:j + k], "big")
            if buf[j] == 0 or ln < 0x80:
                raise TokenError("malformed", f"{where}: length not in the shortest form at offset {i}")
            j += k
        if j + ln > n:
            raise TokenError("malformed", f"{where}: element at offset {i} runs past the end")
        out.append((tag, bytes(buf[j:j + ln])))
        i = j + ln
    return out


def _der_one(buf: bytes, where: str, tag: int):
    items = _der_items(buf, where)
    if len(items) != 1 or items[0][0] != tag:
        raise TokenError("malformed", f"{where}: expected one element of tag 0x{tag:02x}")
    return items[0][1]


def _der_uint(v: bytes, where: str) -> int:
    if not v or (len(v) > 1 and ((v[0] == 0 and v[1] < 0x80) or (v[0] == 0xFF and v[1] >= 0x80))):
        raise TokenError("malformed", f"{where}: INTEGER not in minimal form")
    if v[0] & 0x80:
        raise TokenError("malformed", f"{where}: negative INTEGER")
    return int.from_bytes(v, "big")


def _der_oid(v: bytes, where: str) -> str:
    if not v or v[-1] & 0x80:
        raise TokenError("malformed", f"{where}: OBJECT IDENTIFIER truncated")
    arcs, cur, start = [], 0, True
    for b in v:
        if start and b == 0x80:
            raise TokenError("malformed", f"{where}: OBJECT IDENTIFIER arc not in minimal form")
        cur = (cur << 7) | (b & 0x7F)
        start = not (b & 0x80)
        if start:
            arcs.append(cur)
            cur = 0
    first = min(arcs[0] // 40, 2)
    return ".".join(str(a) for a in [first, arcs[0] - 40 * first] + arcs[1:])


def _check(cond, reason, detail):
    if not cond:
        raise TokenError(reason, detail)


def _gen_time(v: bytes) -> str:
    """GeneralizedTime of RFC 3161 §2.4.2: YYYYMMDDhhmmss[.f+]Z, no trailing zero in the fraction; returned ISO 8601 UTC."""
    import re
    from datetime import datetime
    try:
        t = v.decode("ascii")
    except UnicodeDecodeError:
        t = ""
    m = re.fullmatch(r"([0-9]{14})(?:\.([0-9]*[1-9]))?Z", t)
    _check(m, "malformed", "genTime: not YYYYMMDDhhmmss[.f]Z")
    try:
        d = datetime.strptime(m.group(1), "%Y%m%d%H%M%S")
    except ValueError:
        raise TokenError("malformed", "genTime: not a calendar time") from None
    return d.strftime("%Y-%m-%dT%H:%M:%S") + ("." + m.group(2) if m.group(2) else "") + "Z"


def _token_of(der: bytes) -> bytes:
    """The TimeStampToken: `der` itself, or the token of a granted TimeStampResp (status 0 or 1)."""
    outer = _der_one(der, "token", 0x30)
    kids = _der_items(outer, "token")
    if kids and kids[0][0] == 0x06:
        return bytes(der)
    _check(kids and kids[0][0] == 0x30, "malformed", "neither a TimeStampToken nor a TimeStampResp")
    status = _der_items(kids[0][1], "PKIStatusInfo")
    _check(status and status[0][0] == 0x02, "malformed", "PKIStatusInfo without a status")
    st = _der_uint(status[0][1], "PKIStatus")
    _check(st in (0, 1), "response_not_granted", f"PKIStatus {st}")
    _check(len(kids) == 2 and kids[1][0] == 0x30, "malformed", "granted TimeStampResp without exactly one token")
    return _tlv(0x30, kids[1][1])


def parse_token(der: bytes) -> dict:
    """SPEC §11 steps 1-4: the token read closed. Returns the TSTInfo fields and the TimeStampToken's DER (`token_der`);
    raises TokenError with a closed reason. Stdlib only, no signature checked."""
    _check(isinstance(der, (bytes, bytearray)) and len(der) > 0, "malformed", "empty or not bytes")
    tok = _token_of(bytes(der))
    ci = _der_items(_der_one(tok, "ContentInfo", 0x30), "ContentInfo")
    _check(len(ci) == 2 and ci[0][0] == 0x06 and ci[1][0] == 0xA0, "malformed", "ContentInfo is not {OID, [0]}")
    _check(_der_oid(ci[0][1], "contentType") == OID_SIGNED_DATA, "not_signed_data", "contentType is not id-signedData")
    sd = _der_items(_der_one(ci[1][1], "SignedData", 0x30), "SignedData")
    _check(len(sd) >= 4 and sd[0][0] == 0x02 and sd[1][0] == 0x31 and sd[2][0] == 0x30, "malformed",
           "SignedData does not start with version, digestAlgorithms, encapContentInfo")
    _check(_der_uint(sd[0][1], "SignedData.version") == 3, "malformed", "SignedData version is not 3 (RFC 5652 §5.1)")
    rest = [t for t, _ in sd[3:]]
    _check(rest[-1] == 0x31, "malformed", "SignedData does not end with signerInfos")
    _check(rest[:-1] in ([], [0xA0], [0xA1], [0xA0, 0xA1]), "malformed", "SignedData: an element other than "
           "[0] certificates and [1] crls, repeated or out of order")
    sis = _der_items(sd[-1][1], "signerInfos")
    _check(len(sis) == 1 and sis[0][0] == 0x30, "malformed", "not exactly one SignerInfo (RFC 3161 §2.4.2)")
    si = _der_items(sis[0][1], "SignerInfo")   # review of 13/11/2026: its elements read too (DER, closed, digest algorithm)
    _check([t for t, _ in si[:6]] in ([0x02, 0x30, 0x30, 0xA0, 0x30, 0x04], [0x02, 0x80, 0x30, 0xA0, 0x30, 0x04])
           and [t for t, _ in si[6:]] in ([], [0xA1]), "malformed", "SignerInfo is not {version, sid, digestAlgorithm, "
           "signedAttrs, signatureAlgorithm, signature[, unsignedAttrs]} (RFC 5652 §5.3: signedAttrs present for a TSTInfo)")
    sdal = _der_items(si[2][1], "SignerInfo.digestAlgorithm")
    _check(sdal and sdal[0][0] == 0x06 and (len(sdal) == 1 or (len(sdal) == 2 and sdal[1] == (0x05, b""))), "malformed",
           "SignerInfo.digestAlgorithm is not {OID, NULL or absent}")
    sdoid = _der_oid(sdal[0][1], "SignerInfo.digestAlgorithm")
    _check(sdoid in HASH_ALGORITHMS, "hash_algorithm_not_allowed", f"SignerInfo digest algorithm {sdoid}")
    eci = _der_items(sd[2][1], "encapContentInfo")
    _check(eci and eci[0][0] == 0x06, "malformed", "encapContentInfo without eContentType")
    ctype = _der_oid(eci[0][1], "eContentType")
    _check(ctype == OID_TSTINFO, "econtent_type_not_tstinfo", f"eContentType {ctype}")
    _check(len(eci) == 2 and eci[1][0] == 0xA0, "malformed", "encapContentInfo without one [0] eContent")
    tst = _der_items(_der_one(_der_one(eci[1][1], "eContent", 0x04), "TSTInfo", 0x30), "TSTInfo")
    _check(len(tst) >= 5 and [t for t, _ in tst[:5]] == [0x02, 0x06, 0x30, 0x02, 0x18], "malformed",
           "TSTInfo does not start with version, policy, messageImprint, serialNumber, genTime")
    _check(_der_uint(tst[0][1], "TSTInfo.version") == 1, "malformed", "TSTInfo version is not 1")
    optional, nonce, pos, extensions = (0x30, 0x01, 0x02, 0xA0, 0xA1), None, -1, []
    for t, v in tst[5:]:
        _check(t in optional and optional.index(t) > pos, "tstinfo_unknown_element",
               f"TSTInfo element of tag 0x{t:02x} unknown, repeated or out of order")
        pos = optional.index(t)
        if t == 0x01:
            _check(v in (b"\x00", b"\xff"), "malformed", "ordering is not a DER BOOLEAN")
        if t == 0x02:
            nonce = _der_uint(v, "nonce")
        if t == 0xA1:   # review of 13/11/2026: Extensions (RFC 5280 §4.1): a critical one is not understood here, so refused
            exts = _der_items(v, "extensions")
            _check(exts and all(et == 0x30 for et, _ in exts), "malformed", "extensions is not SEQUENCE SIZE (1..MAX) OF Extension")
            for _et, ev in exts:
                e = _der_items(ev, "Extension")
                _check(len(e) in (2, 3) and e[0][0] == 0x06 and e[-1][0] == 0x04 and (len(e) == 2 or e[1] == (0x01, b"\xff")),
                       "malformed", "Extension is not {OID, critical TRUE (DER: absent when FALSE), OCTET STRING}")
                if len(e) == 3:
                    raise TokenError("tstinfo_unknown_element", f"critical extension {_der_oid(e[0][1], 'extnID')} not understood")
                extensions.append((_der_oid(e[0][1], "extnID"), False, e[-1][1]))   # v0.10: read by the qualified statement
    mi = _der_items(tst[2][1], "messageImprint")
    _check(len(mi) == 2 and mi[0][0] == 0x30 and mi[1][0] == 0x04, "malformed", "messageImprint is not {alg, OCTET STRING}")
    alg = _der_items(mi[0][1], "hashAlgorithm")
    _check(alg and alg[0][0] == 0x06 and (len(alg) == 1 or (len(alg) == 2 and alg[1] == (0x05, b""))), "malformed",
           "hashAlgorithm is not {OID, NULL or absent}")
    oid = _der_oid(alg[0][1], "hashAlgorithm")
    _check(oid in HASH_ALGORITHMS, "hash_algorithm_not_allowed", f"hash algorithm {oid}")
    name, size = HASH_ALGORITHMS[oid]
    _check(len(mi[1][1]) == size, "malformed", f"hashedMessage of {len(mi[1][1])} bytes for {name}")
    return {"token_der": tok, "policy": _der_oid(tst[1][1], "policy"), "hash_algorithm": name,
            "hashed_message": mi[1][1], "serial_number": _der_uint(tst[3][1], "serialNumber"),
            "gen_time": _gen_time(tst[4][1]), "nonce": nonce, "extensions": extensions}

def _not_run(what: str, e: BaseException):
    try:
        from verifier import CheckNotRun
    except ImportError:   # imported as opencore.cryptovalid_tsa
        from opencore.verifier import CheckNotRun
    why = os.strerror(e.errno) if isinstance(getattr(e, "errno", None), int) else str(e)
    return CheckNotRun(f"{what}: {type(e).__name__}: {why}")


def _openssl_tmpdir() -> str:
    """A private directory for the files openssl reads. One this process cannot create or write is CheckNotRun (the
    check cannot be run here: exit 74 in a CLI), never a traceback or a check reported as failed (0.20.3, as
    ap2-evidence-pack 1.5.2). The reason never lists the candidate paths: it would change with the environment."""
    import tempfile
    try:
        base = tempfile.gettempdir()   # it probes every candidate by writing a file there
    except OSError as e:
        raise _not_run("cannot write a temporary file for openssl", OSError("no usable temporary directory")) from e
    try:
        return tempfile.mkdtemp(prefix="cv-openssl-", dir=base)
    except OSError as e:
        raise _not_run("cannot write a temporary file for openssl", e) from e


def _tmp_write(path: str, data: bytes) -> None:
    try:
        with open(path, "wb") as f:
            f.write(data)
    except OSError as e:
        raise _not_run("cannot write a temporary file for openssl", e) from e


def _run_openssl(cmd, **kw):
    """subprocess.run of openssl for a check. openssl that cannot be started HERE (fork refused under `ulimit -u` or low
    memory, no descriptor left for its pipes, the binary gone since `which`) is CheckNotRun: until 0.20.2 it was a
    traceback (ingest verify, eidas_ledger_check) or the check reported as failed (verify_evidence pack: a valid pack
    `valid: false`, exit 1). openssl that does not answer within the timeout is the same case (the check did not finish
    HERE; a slow or loaded machine causes it: measured 13/10/2026, an openssl answering after 20 s made a valid pack
    `valid: false`, exit 1), as in ap2-evidence-pack 1.5.2. Declared (0.21.0; measured 14/10/2026, the same on 0.20.3):
    openssl that STARTED and then ended by a signal (SIGKILL, SIGSEGV), or a wrapper that exits 127, answered — the token is
    not verified (False), not CheckNotRun: an input that makes openssl crash does not become a check that did not run."""
    import subprocess
    try:
        return subprocess.run(cmd, **kw)
    except subprocess.TimeoutExpired as e:
        raise _not_run("cannot run openssl here", OSError(f"no answer within {e.timeout:g} s")) from e
    except OSError as e:
        raise _not_run("cannot run openssl here", e) from e


SIGNATURE_ONLY_NOTE = "signature valid with the certificate contained in the token, chain not established"
SIGNER_NOT_FOUND = "signer certificate not found"   # OpenSSL CMS_R_SIGNER_CERTIFICATE_NOT_FOUND (CMS_verify)
SIGNER_ABSENT_DETAIL = "signature not evaluated: the signer certificate the SignerInfo names is not in the token"


def _der_tlv(b: bytes, i: int) -> "tuple | None":
    """(tag, start of content, end of content) of the DER element at `i`, or None if it does not fit in `b`."""
    if i + 2 > len(b):
        return None
    tag, n, j = b[i], b[i + 1], i + 2
    if n & 0x80:
        k = n & 0x7f
        if k == 0 or k > 4 or j + k > len(b):
            return None
        n, j = int.from_bytes(b[j:j + k], "big"), j + k
    return (tag, j, j + n) if j + n <= len(b) else None


def _is_certificate_der(der: bytes) -> bool:
    """RFC 5280 §4.1 shape: Certificate ::= SEQUENCE { tbsCertificate SEQUENCE, signatureAlgorithm SEQUENCE,
    signatureValue BIT STRING }, exactly filling the bytes. A shape check only: openssl reads the certificate itself.
    Since 2026-11-15 (NEMESIS review): a pinned file that only began with 0x30 was accepted as a certificate, and openssl,
    unable to load it, refused the token's signature (a valid token of the pinned TSA became `contradicted`)."""
    top = _der_tlv(der, 0)
    if top is None or top[0] != 0x30 or top[2] != len(der):
        return False
    i, tags = top[1], []
    while i < top[2]:
        el = _der_tlv(der, i)
        if el is None:
            return False
        tags.append(el[0])
        i = el[2]
    return i == top[2] and tags == [0x30, 0x30, 0x03]


def _pem_certs(items) -> bytes:
    """The pinned certificates as one PEM file: each item a path or bytes, PEM or DER. Anything else is a ValueError,
    a PEM block or DER item that is not shaped as an X.509 certificate (RFC 5280 §4.1) included."""
    import base64
    out = []
    import stat
    for it in items:
        if isinstance(it, str):   # review of 13/11/2026: a FIFO hung, a missing file or a directory was a traceback
            try:
                if not stat.S_ISREG(os.stat(it).st_mode):
                    raise ValueError(f"tsa_certs: {it!r} is not a regular file")
                with open(it, "rb") as f:
                    it = f.read()
            except OSError as e:
                raise ValueError(f"tsa_certs: cannot read {it!r}: {e.strerror or e}") from None
        if not isinstance(it, (bytes, bytearray)) or not it:
            raise ValueError("tsa_certs: each item is a path or the bytes of a certificate")
        it = bytes(it)
        if b"-----BEGIN CERTIFICATE-----" in it:
            blocks = it.split(b"-----BEGIN CERTIFICATE-----")[1:]
            if not all(b"-----END CERTIFICATE-----" in bl and _is_certificate_der(_first_pem_der(b"-----BEGIN CERTIFICATE-----" + bl)
                                                                               or b"") for bl in blocks):
                raise ValueError("tsa_certs: a PEM block is not a certificate")
            out.append(it if it.endswith(b"\n") else it + b"\n")
        elif _is_certificate_der(it):
            b64 = base64.encodebytes(it).replace(b"\n", b"")
            out.append(b"-----BEGIN CERTIFICATE-----\n" + b"\n".join(b64[i:i + 64] for i in range(0, len(b64), 64))
                       + b"\n-----END CERTIFICATE-----\n")
        else:
            raise ValueError("tsa_certs: an item is neither a PEM nor a DER certificate")
    return b"".join(out)


def tsa_cert_arg(path: str) -> str:
    """argparse `type` of --tsa-cert (review of 13/11/2026): a path that is not a readable regular file holding certificates
    is a usage error (exit 2) named on stderr, never a traceback or a FIFO read forever."""
    import argparse
    try:
        _pem_certs([path])
    except ValueError as e:
        raise argparse.ArgumentTypeError(str(e)) from None
    return path


def _first_pem_der(pem: bytes):
    import base64
    try:
        body = pem.split(b"-----BEGIN CERTIFICATE-----", 1)[1].split(b"-----END CERTIFICATE-----", 1)[0]
        return base64.b64decode(b"".join(body.split()), validate=True)
    except (IndexError, ValueError):
        return None


def _last_line(err: bytes, default: str) -> str:
    import re
    lines = [ln for ln in (err or b"").decode("utf-8", "replace").splitlines() if ln.strip()]
    return re.sub(r"^[0-9A-Fa-f]+:error:", "", lines[-1].strip())[:200] if lines else default   # no thread id


# SPEC v0.10 §11 step 8, after RFC 3161 §4 item 1: only these reasons (RFC 5280 §5.3.1) leave valid the tokens generated
# before the revocation time; a reason code absent, a compromise or any other reason makes every token of the certificate
# invalid; certificateHold and removeFromCRL decide nothing (closed list: what is not named here is revoked for all)
KEEPS_EARLIER_TOKENS = frozenset({"unspecified", "affiliation_changed", "superseded", "cessation_of_operation"})
UNDECIDED_REASONS = frozenset({"certificate_hold", "remove_from_crl"})


def _load_crls(crls) -> list:
    """the CRLs the caller pins (paths or bytes, PEM or DER, one CRL each): cryptography CRL objects, ValueError otherwise"""
    from cryptography import x509
    import stat
    if not isinstance(crls, (list, tuple)) or not crls:   # a str or bytes is not a list of CRLs
        raise ValueError("crls: a non-empty list of CRL files or bytes, or None for no revocation check")
    out = []
    for it in crls:
        if isinstance(it, str):
            try:
                if not stat.S_ISREG(os.stat(it).st_mode):
                    raise ValueError(f"crls: {it!r} is not a regular file")
                with open(it, "rb") as f:
                    it = f.read()
            except OSError as e:
                raise ValueError(f"crls: cannot read {it!r}: {e.strerror or e}") from None
        if not isinstance(it, (bytes, bytearray)) or not it:
            raise ValueError("crls: each item is a path or the bytes of a CRL")
        it = bytes(it)
        try:
            if b"-----BEGIN" in it:
                if it.count(b"-----BEGIN") != 1 or it.count(b"-----BEGIN X509 CRL-----") != 1:
                    raise ValueError("one PEM block, an X509 CRL")
                out.append(x509.load_pem_x509_crl(it))
            else:
                out.append(x509.load_der_x509_crl(it))
        except ValueError as e:
            raise ValueError(f"crls: an item is not a CRL ({str(e)[:80]})") from None
    return out


def _token_certificates(token_der: bytes) -> list:
    """the DER of each certificate in the token's SignedData `[0] certificates` (read with this module's DER reader)"""
    def tlv(tag, v):
        n = len(v)
        ln = bytes([n]) if n < 0x80 else bytes([0x80 | ((n.bit_length() + 7) // 8)]) + n.to_bytes((n.bit_length() + 7) // 8, "big")
        return bytes([tag]) + ln + v
    try:
        ci = _der_items(_der_one(_token_of(bytes(token_der)), "ContentInfo", 0x30), "ContentInfo")
        sd = _der_items(_der_one(ci[1][1], "SignedData", 0x30), "SignedData")
        return [tlv(t, v) for tag, val in sd[3:] if tag == 0xA0 for t, v in _der_items(val, "certificates") if t == 0x30]
    except (TokenError, IndexError):
        return []


def _revocation(token_der: bytes, signer_sha256: str, pins_pem: bytes, crls: list, gen_time: str):
    """SPEC v0.10 §11 step 8: (reason or None, revocation dict). reason None = the token stays verified."""
    import hashlib
    from datetime import datetime, timezone
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    pinned = x509.load_pem_x509_certificates(pins_pem)
    carried = []
    for der in _token_certificates(token_der):
        try:
            carried.append(x509.load_der_x509_certificate(der))
        except ValueError:
            pass
    signer = [c for c in list(carried) + pinned
              if hashlib.sha256(c.public_bytes(serialization.Encoding.DER)).hexdigest() == signer_sha256]
    if not signer:
        return "tsa_revocation_unknown", {"status": "unknown", "detail": "signer certificate not found"}
    cert = signer[0]

    def _signed_by_pin(crl):
        for p in pinned:
            if p.subject == crl.issuer:
                try:
                    if crl.is_signature_valid(p.public_key()):
                        return True
                except (TypeError, ValueError):
                    pass
        return False
    applicable = [c for c in crls if c.issuer == cert.issuer and _signed_by_pin(c)]
    if not applicable:
        return "tsa_revocation_unknown", {"status": "unknown",
                                          "detail": "no pinned CRL of the signer's issuer verifies under a pinned certificate"}
    from cryptography.x509.oid import CRLEntryExtensionOID, ExtensionOID
    read_crl = {ExtensionOID.CRL_NUMBER, ExtensionOID.AUTHORITY_KEY_IDENTIFIER, ExtensionOID.AUTHORITY_INFORMATION_ACCESS,
                ExtensionOID.FRESHEST_CRL}
    read_entry = {CRLEntryExtensionOID.CRL_REASON, CRLEntryExtensionOID.INVALIDITY_DATE}
    for c in applicable:   # RFC 5280 §5.2, §6.3.3: a delta CRL or one with a distribution point does not cover every
        other = [e.oid.dotted_string for e in c.extensions if e.oid not in read_crl]   # certificate and reason: not used
        other += [e.oid.dotted_string for r in c for e in r.extensions if e.oid not in read_entry]
        if other:
            return "tsa_revocation_unknown", {"status": "unknown", "detail": "a pinned CRL carries an extension this check "
                                              f"does not process ({', '.join(sorted(set(other)))[:120]}): not a complete CRL"}
    this_update = max(c.last_update_utc for c in applicable).strftime("%Y-%m-%dT%H:%M:%SZ")
    # genTime with its fraction (whole microseconds, truncated: a CRL's times are whole seconds, RFC 5280 §5.1.2.4)
    m = gen_time[:19] + "." + (gen_time[20:-1] + "000000")[:6] if "." in gen_time else gen_time[:19] + ".000000"
    gt = datetime.strptime(m, "%Y-%m-%dT%H:%M:%S.%f").replace(tzinfo=timezone.utc)
    if max(c.last_update_utc for c in applicable) < gt:   # SPEC v0.10 §11 step 8: CRLs older than genTime cannot speak
        return "tsa_revocation_unknown", {"status": "unknown", "crl_this_update": this_update,   # for genTime
                                          "detail": f"the latest pinned CRL was issued before genTime {gen_time}"}
    found = []
    for c in applicable:
        e = c.get_revoked_certificate_by_serial_number(cert.serial_number)
        if e is None:
            found.append(None)
            continue
        try:
            reason = e.extensions.get_extension_for_class(x509.CRLReason).value.reason.name
        except x509.ExtensionNotFound:
            reason = None
        found.append((reason, e.revocation_date_utc))
    if len(set(found)) != 1:
        return "tsa_revocation_unknown", {"status": "unknown", "detail": "the pinned CRLs disagree on the signer",
                                          "crl_this_update": this_update}
    if found[0] is None:
        return None, {"status": "not_revoked", "crl_this_update": this_update}
    reason, when = found[0]
    rev = {"crl_this_update": this_update, "revocation_reason": reason,
           "revocation_date": when.strftime("%Y-%m-%dT%H:%M:%SZ")}
    if reason in UNDECIDED_REASONS:
        return "tsa_revocation_unknown", dict(rev, status="unknown", detail=f"{reason} in a CRL")
    if reason not in KEEPS_EARLIER_TOKENS:   # RFC 3161 §4: no reason code, a compromise, or a reason outside its list
        return "tsa_certificate_revoked", dict(rev, status="revoked")
    if gt < when:
        return None, dict(rev, status="revoked_after_gen_time")
    return "tsa_certificate_revoked", dict(rev, status="revoked")


OID_SIGNING_CERTIFICATE = "1.2.840.113549.1.9.16.2.12"      # RFC 2634 §5.4, ESSCertID with SHA-1
OID_SIGNING_CERTIFICATE_V2 = "1.2.840.113549.1.9.16.2.47"   # RFC 5035, ESSCertIDv2
OID_SUBJECT_ALT_NAME = "2.5.29.17"
ESS_HASHES = {"1.3.14.3.2.26": "sha1", "2.16.840.1.101.3.4.2.4": "sha224", "2.16.840.1.101.3.4.2.1": "sha256",
              "2.16.840.1.101.3.4.2.2": "sha384", "2.16.840.1.101.3.4.2.3": "sha512", "2.16.840.1.101.3.4.2.8": "sha3_256",
              "2.16.840.1.101.3.4.2.9": "sha3_384", "2.16.840.1.101.3.4.2.10": "sha3_512"}


def _tlv_bytes(tag: int, v: bytes) -> bytes:
    n = len(v)
    ln = bytes([n]) if n < 0x80 else bytes([0x80 | ((n.bit_length() + 7) // 8)]) + n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([tag]) + ln + v


# OpenSSL's canonical form of a Name (crypto/x509/x_name.c x509_name_canon, asn1_string_canon), the comparison
# X509_NAME_cmp makes and `openssl ts -verify` uses for the tsa field and the ESS issuerSerial (SPEC §11 step 7)
_CANON_STRING = {0x0C: "utf-8", 0x13: "latin-1", 0x14: "latin-1", 0x16: "latin-1", 0x1A: "latin-1",
                 0x1E: "utf-16-be", 0x1C: "utf-32-be"}
_C_SPACE = b" \t\n\v\f\r"


def _canon_value(tag: int, value: bytes):
    """a string type: UTF-8, white space trimmed and runs made one space, ASCII letters lowercased; other types as encoded"""
    enc = _CANON_STRING.get(tag)
    if enc is None:
        return ("raw", tag, value)
    b = value.decode(enc).encode("utf-8")                 # ValueError when not decodable: the names are not equal
    b = b.strip(_C_SPACE)
    out, i = bytearray(), 0
    while i < len(b):
        c = b[i]
        if c >= 0x80:
            out.append(c)
            i += 1
        elif c in _C_SPACE:
            out.append(0x20)
            while i < len(b) and b[i] in _C_SPACE:
                i += 1
        else:
            out.append(c + 32 if 0x41 <= c <= 0x5A else c)
            i += 1
    return ("str", bytes(out))


def _name_canon(name_tlv: bytes):
    """the canonical form of a DER Name (SEQUENCE OF RDN): RDNs in order, each a sorted tuple of (OID, value)"""
    rdns = []
    for t, rdn in _der_items(_der_one(name_tlv, "Name", 0x30), "Name"):
        if t != 0x31:
            raise TokenError("malformed", "Name: an RDN is not a SET")
        attrs = []
        for t2, atv in _der_items(rdn, "RDN"):
            a = _der_items(atv, "AttributeTypeAndValue")
            if t2 != 0x30 or len(a) != 2 or a[0][0] != 0x06:
                raise TokenError("malformed", "Name: AttributeTypeAndValue")
            attrs.append((a[0][1], _canon_value(a[1][0], a[1][1])))
        rdns.append(tuple(sorted(attrs, key=repr)))
    return tuple(rdns)


def _names_equal(a_tlv: bytes, b_tlv: bytes) -> bool:
    try:
        return _name_canon(a_tlv) == _name_canon(b_tlv)
    except (TokenError, ValueError):
        return False


def _general_names_equal(a: tuple, b: tuple) -> bool:
    """GENERAL_NAME_cmp: the same type; a directoryName compared as a Name, any other type by its bytes"""
    if a[0] != b[0]:
        return False
    return _names_equal(a[1], b[1]) if a[0] == 0xA4 else a[1] == b[1]


def _signer_info(token_der: bytes):
    """the SignerInfo and the TSTInfo elements of a token that passed parse_token: ([(tag, value)], [(tag, value)])"""
    ci = _der_items(_der_one(token_der, "ContentInfo", 0x30), "ContentInfo")
    sd = _der_items(_der_one(ci[1][1], "SignedData", 0x30), "SignedData")
    si = _der_items(_der_items(sd[-1][1], "signerInfos")[0][1], "SignerInfo")
    eci = _der_items(sd[2][1], "encapContentInfo")
    tst = _der_items(_der_one(_der_one(eci[1][1], "eContent", 0x04), "TSTInfo", 0x30), "TSTInfo")
    return si, tst


def _signer_named_by_key_id(token_der: bytes) -> bool:
    """SPEC §11 step 7: the SignerInfo's sid is [0] subjectKeyIdentifier (RFC 5652 §5.3), not issuerAndSerialNumber"""
    return _signer_info(token_der)[0][1][0] == 0x80


def _signer_certificate_absent(token_der: bytes, pins_pem: bytes = None) -> bool:
    """SPEC §11 step 6 (v0.11): True only when every certificate in the token and among the pinned ones was read and none
    is the one the SignerInfo's sid names (RFC 5652 §5.3: issuerAndSerialNumber, the issuer compared as X509_NAME_cmp and
    the serial as an integer; or subjectKeyIdentifier, against the certificate's subjectKeyIdentifier extension, as
    OpenSSL looks it up: measured on 2026-11-18 with OpenSSL 3.0.22, a certificate without the extension cannot sign with
    `cms -sign -keyid`, "certificate has no keyid"). Anything not read (a certificate, the sid, a certificates field)
    answers False: the absence is never presumed."""
    try:
        sid = _signer_info(token_der)[0][1]
        ci = _der_items(_der_one(token_der, "ContentInfo", 0x30), "ContentInfo")
        sd = _der_items(_der_one(ci[1][1], "SignedData", 0x30), "SignedData")
        certs = []
        for tag, val in sd[3:-1]:
            if tag == 0xA0:
                for t, v in _der_items(val, "certificates"):
                    if t != 0x30:                       # another CertificateChoices: not read here
                        return False
                    certs.append(_tlv_bytes(t, v))
        if pins_pem:
            pinned = _pem_ders(pins_pem)
            if pins_pem.count(b"-----BEGIN") != len(pinned):
                return False
            certs += pinned
        if sid[0] == 0x30:
            ias = _der_items(sid[1], "issuerAndSerialNumber")
            if len(ias) != 2 or ias[0][0] != 0x30 or ias[1][0] != 0x02:
                return False
            # the canonical form, not _names_equal: a Name not read here raises (absence not presumed), it is not "unequal"
            want_issuer, want_serial = _name_canon(_tlv_bytes(0x30, ias[0][1])), int.from_bytes(ias[1][1], "big", signed=True)
        elif sid[0] == 0x80:
            want_ski = sid[1]
        else:
            return False
        for der in certs:
            cert = _der_items(_der_one(der, "certificate", 0x30), "certificate")
            tbs = _der_items(cert[0][1], "tbsCertificate")
            k = 1 if tbs[0][0] == 0xA0 else 0
            if tbs[k][0] != 0x02 or tbs[k + 2][0] != 0x30 or tbs[k + 5][0] != 0x30:
                return False
            if sid[0] == 0x30:
                if _name_canon(_tlv_bytes(0x30, tbs[k + 2][1])) == want_issuer and \
                        int.from_bytes(tbs[k][1], "big", signed=True) == want_serial:
                    return False
                continue
            for t, v in tbs[k + 6:]:
                if t != 0xA3:
                    continue
                for et, ev in _der_items(_der_one(v, "extensions", 0x30), "extensions"):
                    ext = _der_items(ev, "Extension") if et == 0x30 else []
                    if not ext or ext[0][0] != 0x06:
                        return False
                    if _der_oid(ext[0][1], "extnID") == "2.5.29.14" and ext[-1][0] == 0x04 and \
                            _der_one(ext[-1][1], "SubjectKeyIdentifier", 0x04) == want_ski:
                        return False
        return True
    except (TokenError, IndexError, ValueError):
        return False


def _policies_shape(el: tuple) -> bool:
    """ESS `policies` (RFC 2634 §5.4.1): SEQUENCE OF PolicyInformation, each a SEQUENCE that starts with an OID"""
    if el[0] != 0x30:
        return False
    for t, v in _der_items(el[1], "policies"):
        pi = _der_items(v, "PolicyInformation") if t == 0x30 else []
        if not pi or pi[0][0] != 0x06:
            return False
    return True


def _ess_lists_more_than_one(token_der: bytes) -> bool:
    """SPEC §11 step 7 (v0.11): True when a signingCertificate or signingCertificateV2 attribute of the token's SignerInfo
    lists more than one ESSCertID. Anything not read here answers False (the route of v0.10, openssl ts -verify)."""
    try:
        for t, av in _der_items(_signer_info(token_der)[0][3][1], "signedAttrs"):
            a = _der_items(av, "Attribute") if t == 0x30 else []
            if len(a) != 2 or a[0][0] != 0x06 or a[1][0] != 0x31:
                continue
            if _der_oid(a[0][1], "attrType") not in (OID_SIGNING_CERTIFICATE, OID_SIGNING_CERTIFICATE_V2):
                continue
            for _t, v in _der_items(a[1][1], "attrValues"):
                sc = _der_items(v, "SigningCertificate") if _t == 0x30 else []
                if sc and sc[0][0] == 0x30 and len(_der_items(sc[0][1], "certs")) > 1:
                    return True
        return False
    except (TokenError, IndexError, ValueError):
        return False


def _issuer_serial(der: bytes):
    """(issuer Name TLV, serial number as an integer) of a DER certificate"""
    tbs = _der_items(_der_items(_der_one(der, "certificate", 0x30), "certificate")[0][1], "tbsCertificate")
    k = 1 if tbs[0][0] == 0xA0 else 0
    if tbs[k][0] != 0x02 or tbs[k + 2][0] != 0x30:
        raise TokenError("malformed", "certificate serialNumber or issuer not read")
    return _tlv_bytes(0x30, tbs[k + 2][1]), int.from_bytes(tbs[k][1], "big", signed=True)


def _ess_cert_ids(o: str, certs: bytes):
    """the ESSCertID(v2)s of one attribute, closed: [(hash algorithm, certHash, (issuer Name TLV, serial) or None)], or
    the reason why not (RFC 2634 §5.4, RFC 5035 §3: ESSCertID ::= {certHash, issuerSerial OPTIONAL}; ESSCertIDv2 ::=
    {hashAlgorithm DEFAULT sha256, certHash, issuerSerial OPTIONAL}; IssuerSerial ::= {issuer GeneralNames,
    serialNumber}, its GeneralNames one directoryName, as OpenSSL compares it)"""
    import hashlib
    ids = _der_items(certs, "certs")
    if not ids:
        return f"ESS attribute {o}: no ESSCertID"
    out = []
    for n, (t, v) in enumerate(ids, 1):
        if t != 0x30:
            return f"ESS attribute {o}: ESSCertID {n} is not a SEQUENCE"
        cid = _der_items(v, "ESSCertID")
        alg = "sha1"
        if o == OID_SIGNING_CERTIFICATE_V2:
            alg = "sha256"
            if cid and cid[0][0] == 0x30:
                ai = _der_items(cid[0][1], "hashAlgorithm")
                alg = ESS_HASHES.get(_der_oid(ai[0][1], "hashAlgorithm")) if ai and ai[0][0] == 0x06 else None
                if alg is None or not (len(ai) == 1 or (len(ai) == 2 and ai[1] == (0x05, b""))):
                    return f"ESSCertIDv2 {n}: hash algorithm not known"
                cid = cid[1:]
        if not cid or cid[0][0] != 0x04 or len(cid) > 2 or (len(cid) == 2 and cid[1][0] != 0x30):
            return f"ESSCertID {n}: not {{certHash, issuerSerial?}}"
        if len(cid[0][1]) != hashlib.new(alg).digest_size:
            return f"ESSCertID {n}: certHash is not {alg}-long"
        isr = None
        if len(cid) == 2:
            iss = _der_items(cid[1][1], "IssuerSerial")
            names = _der_items(_der_one(_tlv_bytes(0x30, iss[0][1]), "GeneralNames", 0x30), "GeneralNames") \
                if iss and iss[0][0] == 0x30 else None
            if not (len(iss) == 2 and iss[1][0] == 0x02 and names is not None and len(names) == 1
                    and names[0][0] == 0xA4):
                return f"ESSCertID {n}: issuerSerial is not {{one directoryName, serialNumber}}"
            isr = (names[0][1], int.from_bytes(iss[1][1], "big", signed=True))
        out.append((alg, cid[0][1], isr))
    return out


def _ess_names(isr, der: bytes) -> bool:
    """an ESS issuerSerial (Name TLV, serial) names the certificate `der`: the issuer compared as X509_NAME_cmp, the serial
    as an integer"""
    issuer, serial = _issuer_serial(der)
    return _names_equal(isr[0], issuer) and isr[1] == serial


def _key_id_anchor(token_der: bytes, signer_der: bytes, pins_pem: bytes, at: int, tmp: str):
    """SPEC §11 step 7, the checks made one by one (a signer named by subjectKeyIdentifier, and since v0.11 any signer
    whose signing-certificate attribute lists more than one ESSCertID): None when the token is established under the
    pinned certificates, else why not. (a) ESS signing-certificate attribute(s): the first ESSCertID identifies the signer
    certificate, the ones after it limit the certificates of the path; (b) the `tsa` field; (c) openssl verify with the
    timestampsign purpose, the chain to a pinned certificate (through the certificates (a) allows) and the validity at
    genTime."""
    import base64
    import hashlib
    try:
        ci = _der_items(_der_one(token_der, "ContentInfo", 0x30), "ContentInfo")
        sis = _der_items(_der_items(_der_one(ci[1][1], "SignedData", 0x30), "SignedData")[-1][1], "signerInfos")
        if len(sis) != 1 or sis[0][0] != 0x30:   # SPEC §11 step 7, closed shapes (step 1 asks it of the token too)
            return f"{len(sis)} SignerInfos (exactly one is evaluated here)"
        si, tst = _signer_info(token_der)
        cert = _der_items(_der_one(signer_der, "certificate", 0x30), "certificate")
        tbs = _der_items(cert[0][1], "tbsCertificate")
        k = 1 if tbs[0][0] == 0xA0 else 0
        subject = _tlv_bytes(0x30, tbs[k + 4][1])
        san = []
        for tag, v in tbs[k + 6:]:
            if tag == 0xA3:
                for _t, ev in _der_items(_der_one(v, "extensions", 0x30), "extensions"):
                    e = _der_items(ev, "Extension")
                    if _der_oid(e[0][1], "extnID") == OID_SUBJECT_ALT_NAME:
                        san = [_tlv_bytes(gt, gv) for gt, gv in _der_items(_der_one(e[-1][1], "subjectAltName", 0x30),
                                                                              "GeneralNames")]
        # (a) ESS
        attrs = {}
        for t, av in _der_items(si[3][1], "signedAttrs"):   # Attribute ::= SEQUENCE { attrType OID, attrValues SET }
            a = _der_items(av, "Attribute") if t == 0x30 else []
            if len(a) != 2 or a[0][0] != 0x06 or a[1][0] != 0x31:
                return "a signed attribute is not {attrType, attrValues SET}"
            attrs.setdefault(_der_oid(a[0][1], "attrType"), []).append(a[1][1])
        found = [o for o in (OID_SIGNING_CERTIFICATE, OID_SIGNING_CERTIFICATE_V2) if o in attrs]
        if not found:
            return "no signingCertificate or signingCertificateV2 attribute (ESS)"
        token_certs = _token_certificates(token_der)
        pool = token_certs + _pem_ders(pins_pem)
        allowed = None                                  # None: no attribute limits the path (one ESSCertID each)
        for o in found:
            vals = attrs[o]
            if len(vals) != 1 or len(_der_items(vals[0], "attrValues")) != 1:
                return f"ESS attribute {o}: not exactly one value"
            sc = _der_items(_der_one(vals[0], "SigningCertificate", 0x30), "SigningCertificate")
            if not 1 <= len(sc) <= 2 or sc[0][0] != 0x30 or (len(sc) == 2 and not _policies_shape(sc[1])):
                return f"ESS attribute {o}: not {{certs, policies?}}"   # RFC 2634 §5.4, RFC 5035 §3
            ids = _ess_cert_ids(o, sc[0][1])
            if isinstance(ids, str):
                return ids
            alg, h, isr = ids[0]                        # RFC 2634 §5.4, RFC 5035 §3: the first is the signer certificate
            if h != hashlib.new(alg, signer_der).digest():
                return "ESS certHash is not the hash of the signer certificate"
            if isr is not None and not _ess_names(isr, signer_der):
                return "ESS issuerSerial does not name the signer certificate's issuer and serial number"
            if len(ids) > 1:                            # the ones after it "limit the set of certificates" (SPEC v0.11)
                ok = {signer_der}
                for n, (alg, h, isr) in enumerate(ids[1:], 2):
                    for c in pool:
                        if hashlib.new(alg, c).digest() == h:
                            if isr is not None and not _ess_names(isr, c):
                                return f"ESSCertID {n}: issuerSerial does not name the certificate whose hash it carries"
                            ok.add(c)
                allowed = ok if allowed is None else allowed & ok
    # (b) the tsa field
        tsa = [v for tag, v in tst[5:] if tag == 0xA0]
        if tsa:   # ts_check_signer_name: the subject (a directoryName), then each name of the subjectAltName
            gn = _der_items(tsa[0], "tsa")
            if len(gn) != 1 or not (_general_names_equal(gn[0], (0xA4, subject))
                                    or any(_general_names_equal(gn[0], _der_items(n, "GeneralName")[0]) for n in san)):
                return "the TSTInfo tsa field names neither the signer's subject nor one of its subjectAltName"
    except (TokenError, IndexError, ValueError) as e:
        return f"signer certificate or attributes not read: {e}"[:160]
    # (c) chain, purpose, validity at genTime: the OpenSSL chain building of ts -verify
    pem = lambda der: b"-----BEGIN CERTIFICATE-----\n" + base64.encodebytes(der) + b"-----END CERTIFICATE-----\n"  # noqa: E731
    sp, cp, up = (os.path.join(tmp, n) for n in ("ski_signer.pem", "ski_pinned.pem", "ski_untrusted.pem"))
    _tmp_write(sp, pem(signer_der))
    _tmp_write(cp, pins_pem)
    _tmp_write(up, pins_pem + b"".join(pem(c) for c in token_certs if allowed is None or c in allowed))
    p = _run_openssl(["openssl", "verify", "-purpose", "timestampsign", "-partial_chain", "-attime", str(at),
                      "-CAfile", cp, "-no-CApath", "-no-CAstore", "-untrusted", up, sp], capture_output=True, timeout=30)
    if p.returncode < 0:
        raise _not_run("cannot run openssl here", OSError(f"terminated by signal {-p.returncode}"))
    if p.returncode != 0 and b"nknown option" in (p.stderr or b"") + (p.stdout or b""):   # SPEC §11 step 7: before 3.0
        raise _not_run("this openssl does not know an option of `verify` (OpenSSL 3.0 or later is needed)",
                       OSError(_last_line(p.stderr or p.stdout, "unknown option")))
    if p.returncode != 0:
        return _last_line(p.stderr or p.stdout, "openssl verify refused the signer certificate")
    return None



SHA1_SIGNATURE_OIDS = {"1.2.840.113549.1.1.5", "1.3.14.3.2.29", "1.2.840.10045.4.1", "1.2.840.10040.4.3", "1.3.14.3.2.27"}
OID_RSASSA_PSS = "1.2.840.113549.1.1.10"


def _cert_sig_names(der: bytes):
    """(signed with SHA-1, issuer Name TLV, subject Name TLV) of one certificate (SPEC §11 step 7, SHA-1 legacy)"""
    cert = _der_items(_der_one(der, "certificate", 0x30), "certificate")
    if len(cert) != 3 or cert[0][0] != 0x30 or cert[1][0] != 0x30 or cert[2][0] != 0x03:
        raise TokenError("malformed", "certificate is not {tbsCertificate, signatureAlgorithm, signature}")
    tbs = _der_items(cert[0][1], "tbsCertificate")
    k = 1 if tbs[0][0] == 0xA0 else 0
    if tbs[k + 2][0] != 0x30 or tbs[k + 4][0] != 0x30:
        raise TokenError("malformed", "certificate issuer or subject is not a Name")
    alg = _der_items(cert[1][1], "signatureAlgorithm")
    oid = _der_oid(_der_one(_tlv_bytes(*alg[0]), "signatureAlgorithm", 0x06), "signatureAlgorithm")
    sha1 = oid in SHA1_SIGNATURE_OIDS
    if oid == OID_RSASSA_PSS:   # RFC 4055 §3.1: hashAlgorithm [0] DEFAULT sha1; the parameters MUST be present
        if len(alg) != 2 or alg[1][0] != 0x30:
            raise TokenError("malformed", "RSASSA-PSS signatureAlgorithm without RSASSA-PSS-params (RFC 4055 §3.1)")
        params = _der_items(alg[1][1], "RSASSA-PSS-params")
        h = [v for t, v in params if t == 0xA0]
        sha1 = not h or _der_oid(_der_items(_der_one(h[0], "hashAlgorithm", 0x30), "hashAlgorithm")[0][1],
                                 "hashAlgorithm") == "1.3.14.3.2.26"
    return sha1, _tlv_bytes(0x30, tbs[k + 2][1]), _tlv_bytes(0x30, tbs[k + 4][1])


def _pem_ders(pem: bytes) -> list:
    import base64
    import re
    return [base64.b64decode(b) for b in re.findall(rb"-----BEGIN CERTIFICATE-----([A-Za-z0-9+/=\s]+?)-----END CERTIFICATE-----",
                                                    pem or b"")]


def sha1_signature_legacy(signer_der: bytes, pins_pem: bytes, token_der: bytes):
    """SPEC §11 step 7, SHA-1 legacy (v0.10): True when the signer certificate, or a certificate reached from it by names
    among the pinned certificates and the token's (a self-issued one excepted and not followed), is signed with SHA-1;
    None when one of them cannot be read here"""
    try:
        pool = [(d, *_cert_sig_names(d)) for d in _pem_ders(pins_pem) + _token_certificates(token_der)]
        todo, seen, found = [(signer_der, *_cert_sig_names(signer_der))], set(), False
    except (TokenError, IndexError, ValueError):
        return None
    while todo:
        der, sha1, issuer, subject = todo.pop()
        if der in seen or _names_equal(issuer, subject):
            continue
        seen.add(der)
        found = found or sha1
        todo.extend(c for c in pool if _names_equal(c[3], issuer))
    return found


def verify_token(token_der: bytes, digest: bytes, hash_alg: str = None, tsa_certs=None, crls=None) -> dict:
    """SPEC §11 (v0.6): the one check of an RFC 3161 token in this repository. `token_der` is a TimeStampToken or a granted
    TimeStampResp; `digest` the expected messageImprint.hashedMessage; `hash_alg` (optional) the algorithm it was stamped
    with ("sha256", ...); `tsa_certs` (optional) the TSA certificates the caller pins (paths or bytes, PEM or DER: the
    TSA certificate or a CA above it).
    Returns {"status", "counts_as_timestamp", "reason", "detail", "tst_info", "imprint_ok", "signer_sha256", "note",
    "sha1_signature_legacy"} (the last: None unless step 7 passed, then whether a certificate of the chain read by names
    is signed with SHA-1, NIST SP 800-131A Rev. 2 legacy verification; None too when one cannot be read here):
    status `verified` (pinned TSA, the only one that counts), `signature_only` (no pin: signature valid with the certificate
    contained in the token, chain not established), `invalid` (a closed `reason`), `not_evaluated` (openssl absent).
    `invalid` with reason `signer_certificate_absent` (SPEC v0.11): the certificate the SignerInfo names is neither in the
    token nor pinned, so the signature was not evaluated (a token requested with certReq FALSE; pin the TSA certificate).
    openssl present that cannot run here, does not answer, or is ended by a signal: CheckNotRun (SPEC §10, §11).
    `crls` (SPEC v0.10 §11 step 8, needs `tsa_certs`): CRLs the caller pins; a `verified` token is then checked for the
    revocation of its signer certificate, and the outcome gains `revocation`. None: no revocation check, as before."""
    import hashlib
    import shutil
    from datetime import datetime, timezone
    out = {"status": "invalid", "counts_as_timestamp": False, "reason": None, "detail": None, "tst_info": None,
           "imprint_ok": False, "signer_sha256": None, "note": None, "sha1_signature_legacy": None}
    crl_objs = None
    if crls is not None:
        if not tsa_certs:
            raise ValueError("crls need tsa_certs: revocation is checked only for a token verified under pinned certificates")
        try:
            crl_objs = _load_crls(crls)
        except ImportError:
            crl_objs = ImportError
    try:
        t = parse_token(token_der)
        if hash_alg is not None and t["hash_algorithm"] != hash_alg:
            raise TokenError("hash_algorithm_mismatch", f"token {t['hash_algorithm']}, expected {hash_alg}")
        out["tst_info"] = {"policy": t["policy"], "hash_algorithm": t["hash_algorithm"],
                           "hashed_message": t["hashed_message"].hex(), "serial_number": str(t["serial_number"]),
                           "gen_time": t["gen_time"], "nonce": None if t["nonce"] is None else str(t["nonce"])}
        if not isinstance(digest, (bytes, bytearray)) or t["hashed_message"] != bytes(digest):
            raise TokenError("imprint_mismatch", "messageImprint.hashedMessage is not the expected digest")
        out["imprint_ok"] = True
    except TokenError as e:
        out.update(reason=e.reason, detail=e.detail)
        return out
    pins = _pem_certs(tsa_certs) if tsa_certs else None
    state, signer, why = token_signer(t["token_der"], pins)   # the public step 6 (callers and tests replace it)
    if state == "not_evaluated":
        out.update(status="not_evaluated", reason="openssl_absent", note="openssl absent: signature not checked")
        return out
    if state == "invalid":
        # SPEC §11 step 6 (v0.11): the signature was not evaluated. Both must say so: the sid matches no certificate read
        # here AND openssl stopped at the signer lookup (a token openssl cannot parse is not "absent": FORMAT_FAILURE)
        if SIGNER_NOT_FOUND in (why or "") and _signer_certificate_absent(t["token_der"], pins):
            out.update(reason="signer_certificate_absent", detail=SIGNER_ABSENT_DETAIL + (
                " (pin the TSA certificate)" if pins is None else " nor among the pinned certificates"))
            return out
        out.update(reason="signature_invalid", detail=why)
        return out
    out["signer_sha256"] = signer
    if pins is None:
        out.update(status="signature_only", note=SIGNATURE_ONLY_NOTE)
        return out
    d = _openssl_tmpdir()
    try:
        tp, cp = os.path.join(d, "t.der"), os.path.join(d, "pinned.pem")
        _tmp_write(tp, t["token_der"])
        _tmp_write(cp, pins)
        at = int(datetime.strptime(t["gen_time"][:19], "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc).timestamp())
        signer_der = None
        # SPEC §11 step 7: subjectKeyIdentifier, which openssl ts cannot read; more than one ESSCertID (v0.11), where
        # openssl ts asks every ESSCertID to be in the chain it built, which RFC 2634 §5.4 and RFC 5035 §3 do not ask
        if _signer_named_by_key_id(t["token_der"]) or _ess_lists_more_than_one(t["token_der"]):
            state6, signer_der, why = _token_signer(t["token_der"], pins)
            if state6 != "valid" or hashlib.sha256(signer_der).hexdigest() != signer:
                out.update(reason="not_issued_by_pinned_tsa", detail=f"signer certificate not read again: {why}"[:200])
                return out
            why = _key_id_anchor(t["token_der"], signer_der, pins, at, d)
            if why is not None:
                out.update(reason="not_issued_by_pinned_tsa", detail=why[:200])
                return out
        else:
            p = _run_openssl(["openssl", "ts", "-verify", "-token_in", "-in", tp, "-digest", t["hashed_message"].hex(),
                              "-CAfile", cp, "-untrusted", cp, "-partial_chain", "-attime", str(at)],
                             capture_output=True, timeout=30)
            if p.returncode < 0:
                raise _not_run("cannot run openssl here", OSError(f"terminated by signal {-p.returncode}"))
            if p.returncode != 0 or b"Verification: OK" not in (p.stdout or b"").splitlines():
                out.update(reason="not_issued_by_pinned_tsa", detail=_last_line(p.stderr, "openssl ts -verify refused it"))
                return out
        out.update(status="verified", counts_as_timestamp=True, note="verified against the pinned TSA certificate(s)")
        if signer_der is None:
            state6, signer_der, _why = _token_signer(t["token_der"], pins)
        out["sha1_signature_legacy"] = None if signer_der is None or hashlib.sha256(signer_der).hexdigest() != signer \
            else sha1_signature_legacy(signer_der, pins, t["token_der"])
        if crl_objs is ImportError:
            out.update(status="not_evaluated", counts_as_timestamp=False, reason="crl_backend_missing",
                       note="cryptography absent: the pinned CRLs were not read")
        elif crl_objs is not None:
            why, out["revocation"] = _revocation(t["token_der"], signer, pins, crl_objs, t["gen_time"])
            if why is not None:
                out.update(status="invalid", counts_as_timestamp=False, reason=why,
                           detail=out["revocation"].get("detail") or f"signer certificate revoked "
                           f"({out['revocation'].get('revocation_reason')}, {out['revocation'].get('revocation_date')})",
                           note=None)
        return out
    finally:
        shutil.rmtree(d, ignore_errors=True)


def token_signer(token_der: bytes, pins_pem: bytes = None):
    """SPEC §11 step 6 (see _token_signer): ("valid", signer certificate SHA-256 hex, None), ("invalid", None, reason) or
    ("not_evaluated", None, "openssl absent")."""
    import hashlib
    state, der, why = _token_signer(token_der, pins_pem)
    return state, (None if der is None else hashlib.sha256(der).hexdigest()), why


def _token_signer(token_der: bytes, pins_pem: bytes = None):
    """SPEC §11 step 6 on a token that passes steps 1-4: ("valid", signer certificate DER, None), ("invalid", None,
    reason) or ("not_evaluated", None, "openssl absent"). openssl `cms -verify -noverify`: the CMS signature and the
    messageDigest attribute, with the certificate the SignerInfo names, looked up in the token and, when given, in
    `pins_pem` (a token requested with certReq FALSE carries no certificate, RFC 3161 §2.4.1); no chain. openssl present
    that cannot run here, does not answer or is ended by a signal: CheckNotRun."""
    import shutil
    try:
        tok = parse_token(token_der)["token_der"]
    except TokenError as e:
        return "invalid", None, str(e)
    if not shutil.which("openssl"):
        return "not_evaluated", None, "openssl absent"
    d = _openssl_tmpdir()
    try:
        tp, sp = os.path.join(d, "t.der"), os.path.join(d, "signer.pem")
        _tmp_write(tp, tok)
        extra = []
        if pins_pem:
            _tmp_write(os.path.join(d, "pinned.pem"), pins_pem)
            extra = ["-certfile", os.path.join(d, "pinned.pem")]
        p = _run_openssl(["openssl", "cms", "-verify", "-noverify", "-binary", "-inform", "DER", "-in", tp, *extra,
                          "-signer", sp, "-out", os.devnull], capture_output=True, timeout=30)
        if p.returncode < 0:
            raise _not_run("cannot run openssl here", OSError(f"terminated by signal {-p.returncode}"))
        der = None
        if p.returncode == 0 and os.path.exists(sp):
            with open(sp, "rb") as f:
                der = _first_pem_der(f.read())
        if der is None:
            return "invalid", None, _last_line(p.stderr, "openssl cms -verify refused it")
        return "valid", der, None
    finally:
        shutil.rmtree(d, ignore_errors=True)


def verify_cms_signature(token_der: bytes):
    """Does the CMS signature of the blob verify? (openssl cms -verify -noverify: the signature with the certificate the
    blob carries, no chain, no check that the content is a TSTInfo.) True/False, or None if openssl is absent. openssl
    present but not startable, or no temporary file: CheckNotRun (0.20.3).
    Not a token check: any CMS blob signed with a key made on the spot passes (measured 2026-11-13). No caller in this
    repository uses it since v0.6 of the spec; `verify_token` (SPEC §11) is the check. Kept for callers outside it."""
    import shutil
    if not shutil.which("openssl"):
        return None
    d = _openssl_tmpdir()
    try:
        tp = os.path.join(d, "t.der")
        _tmp_write(tp, token_der)
        p = _run_openssl(["openssl", "cms", "-verify", "-noverify", "-inform", "DER",
                          "-in", tp, "-out", os.devnull],
                         capture_output=True, timeout=30)
        return p.returncode == 0
    finally:
        shutil.rmtree(d, ignore_errors=True)


def verify_with_openssl(token_der: bytes, digest_data: bytes):
    """`openssl ts -verify -data` against the system CA store (/etc/ssl/certs), if openssl is installed (None if not).
    openssl present but not startable, or no temporary file: CheckNotRun (0.20.3). No caller in this repository uses it
    since v0.6 of the spec (`verify_token`, SPEC §11); kept for callers outside it.

    What it checks, as written (measured 2026-11-15 with OpenSSL 3.0.22 and the tokens of spec/vectors/rfc3161):
    - `token_der` is read as a DER TimeStampResp (the TSA's whole reply): no `-token_in` is passed, so a bare
      TimeStampToken is always False (digicert, sectigo, globalsign: reply True, the token taken out of it False).
    - `digest_data` is the timestamped DATA, which openssl hashes with the token's algorithm; it is not a digest.
    - Time: the chain is validated at the time of the call, not at the token's genTime (no `-attime`): a token that
      verifies today is False once the TSA certificate or a CA above it has expired or the system store has dropped the
      root (the same three replies are False with `-attime` 2100-01-01; their signer certificates end in 2037), and
      True or False can differ between machines with different stores. Revocation is not checked.
    - Trust: any CA in /etc/ssl/certs, not a pinned TSA (freetsa.org's reply is False: its root is not in that store).
    None of SPEC §11's closed structure checks are made. For a verdict that does not depend on the day or the machine,
    use `verify_token` with pinned `tsa_certs`."""
    import shutil
    if not shutil.which("openssl"):
        return None
    d = _openssl_tmpdir()
    try:
        tp, dp = os.path.join(d, "t.der"), os.path.join(d, "d.bin")
        _tmp_write(tp, token_der)
        _tmp_write(dp, digest_data)
        p = _run_openssl(["openssl", "ts", "-verify", "-in", tp, "-data", dp, "-CApath", "/etc/ssl/certs"],
                         capture_output=True, text=True, timeout=30)   # 0.20.3: it had no limit (a hang)
        return p.returncode == 0
    finally:
        shutil.rmtree(d, ignore_errors=True)

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


try:   # 0.20.3: the one writer of every command (verifier.py): an outcome is written whole, or exit 74
    from verifier import Parser, emit, receipt_cli, say
except ImportError:   # python3 -m opencore.<module> from the parent directory
    from opencore.verifier import Parser, emit, receipt_cli, say


@receipt_cli
def main(argv=None):
    import argparse
    import base64
    import json
    p = Parser(prog="cryptovalid_tsa",
                                description="RFC 3161 (qualified) timestamp over a digest / Merkle STH.")
    p.add_argument("digest_hex", help="SHA-256 digest hex (e.g. a Merkle STH root_sha256)")
    p.add_argument("--tsa", default="https://freetsa.org/tsr",
                   help="TSA URL (point at an eIDAS qualified TSP for a QUALIFIED timestamp)")
    p.add_argument("--tsa-cert", action="append", default=None, metavar="PEM", type=tsa_cert_arg,
                   help="pin the TSA certificate (or a CA above it); repeatable. Without it the outcome is at most "
                        "signature_only (SPEC §11)")
    a = p.parse_args(argv)
    granted, token, _ = request_timestamp(bytes.fromhex(a.digest_hex), a.tsa)
    chk = verify_token(token, bytes.fromhex(a.digest_hex), "sha256", a.tsa_cert) if (granted and token) else None
    ok = bool(chk and chk["status"] in ("verified", "signature_only"))
    emit(json.dumps({"granted": granted, "digest_bound": bool(chk and chk["imprint_ok"]),
                     "status": chk["status"] if chk else None, "reason": chk["reason"] if chk else None,
                     "gen_time": (chk["tst_info"] or {}).get("gen_time") if chk else None,
                     "counts_as_timestamp": bool(chk and chk["counts_as_timestamp"]),
                     "token_b64_len": len(base64.b64encode(token)) if token else 0,
                     "tsa": a.tsa}, indent=2))
    return 0 if ok else 1

if __name__ == "__main__":
    raise SystemExit(main())
