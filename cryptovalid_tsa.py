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
    with urllib.request.urlopen(r, timeout=timeout) as resp:
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
    _check(len(_der_items(sd[-1][1], "signerInfos")) == 1, "malformed", "not exactly one SignerInfo (RFC 3161 §2.4.2)")
    eci = _der_items(sd[2][1], "encapContentInfo")
    _check(eci and eci[0][0] == 0x06, "malformed", "encapContentInfo without eContentType")
    ctype = _der_oid(eci[0][1], "eContentType")
    _check(ctype == OID_TSTINFO, "econtent_type_not_tstinfo", f"eContentType {ctype}")
    _check(len(eci) == 2 and eci[1][0] == 0xA0, "malformed", "encapContentInfo without one [0] eContent")
    tst = _der_items(_der_one(_der_one(eci[1][1], "eContent", 0x04), "TSTInfo", 0x30), "TSTInfo")
    _check(len(tst) >= 5 and [t for t, _ in tst[:5]] == [0x02, 0x06, 0x30, 0x02, 0x18], "malformed",
           "TSTInfo does not start with version, policy, messageImprint, serialNumber, genTime")
    _check(_der_uint(tst[0][1], "TSTInfo.version") == 1, "malformed", "TSTInfo version is not 1")
    optional, nonce, pos = (0x30, 0x01, 0x02, 0xA0, 0xA1), None, -1
    for t, v in tst[5:]:
        _check(t in optional and optional.index(t) > pos, "tstinfo_unknown_element",
               f"TSTInfo element of tag 0x{t:02x} unknown, repeated or out of order")
        pos = optional.index(t)
        if t == 0x01:
            _check(v in (b"\x00", b"\xff"), "malformed", "ordering is not a DER BOOLEAN")
        if t == 0x02:
            nonce = _der_uint(v, "nonce")
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
            "gen_time": _gen_time(tst[4][1]), "nonce": nonce}

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


def _pem_certs(items) -> bytes:
    """The pinned certificates as one PEM file: each item a path or bytes, PEM or DER. Anything else is a ValueError."""
    import base64
    out = []
    for it in items:
        if isinstance(it, str):
            with open(it, "rb") as f:
                it = f.read()
        if not isinstance(it, (bytes, bytearray)) or not it:
            raise ValueError("tsa_certs: each item is a path or the bytes of a certificate")
        it = bytes(it)
        if b"-----BEGIN CERTIFICATE-----" in it:
            out.append(it if it.endswith(b"\n") else it + b"\n")
        elif it[:1] == b"\x30":
            b64 = base64.encodebytes(it).replace(b"\n", b"")
            out.append(b"-----BEGIN CERTIFICATE-----\n" + b"\n".join(b64[i:i + 64] for i in range(0, len(b64), 64))
                       + b"\n-----END CERTIFICATE-----\n")
        else:
            raise ValueError("tsa_certs: an item is neither a PEM nor a DER certificate")
    return b"".join(out)


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


def verify_token(token_der: bytes, digest: bytes, hash_alg: str = None, tsa_certs=None) -> dict:
    """SPEC §11 (v0.6): the one check of an RFC 3161 token in this repository. `token_der` is a TimeStampToken or a granted
    TimeStampResp; `digest` the expected messageImprint.hashedMessage; `hash_alg` (optional) the algorithm it was stamped
    with ("sha256", ...); `tsa_certs` (optional) the TSA certificates the caller pins (paths or bytes, PEM or DER: the
    TSA certificate or a CA above it).
    Returns {"status", "counts_as_timestamp", "reason", "detail", "tst_info", "imprint_ok", "signer_sha256", "note"}:
    status `verified` (pinned TSA, the only one that counts), `signature_only` (no pin: signature valid with the certificate
    contained in the token, chain not established), `invalid` (a closed `reason`), `not_evaluated` (openssl absent).
    openssl present that cannot run here, does not answer, or is ended by a signal: CheckNotRun (SPEC §10, §11)."""
    import shutil
    from datetime import datetime, timezone
    out = {"status": "invalid", "counts_as_timestamp": False, "reason": None, "detail": None, "tst_info": None,
           "imprint_ok": False, "signer_sha256": None, "note": None}
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
    state, signer, why = token_signer(t["token_der"])
    if state == "not_evaluated":
        out.update(status="not_evaluated", reason="openssl_absent", note="openssl absent: signature not checked")
        return out
    if state == "invalid":
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
        p = _run_openssl(["openssl", "ts", "-verify", "-token_in", "-in", tp, "-digest", t["hashed_message"].hex(),
                          "-CAfile", cp, "-partial_chain", "-attime", str(at)], capture_output=True, timeout=30)
        if p.returncode < 0:
            raise _not_run("cannot run openssl here", OSError(f"terminated by signal {-p.returncode}"))
        if p.returncode != 0:
            out.update(reason="not_issued_by_pinned_tsa", detail=_last_line(p.stderr, "openssl ts -verify refused it"))
            return out
        out.update(status="verified", counts_as_timestamp=True, note="verified against the pinned TSA certificate(s)")
        return out
    finally:
        shutil.rmtree(d, ignore_errors=True)


def token_signer(token_der: bytes):
    """SPEC §11 step 6 on a token that passes steps 1-4: ("valid", signer certificate SHA-256 hex, None), ("invalid", None,
    reason) or ("not_evaluated", None, "openssl absent"). openssl `cms -verify -noverify`: the CMS signature and the
    messageDigest attribute, with the certificate the SignerInfo names; no chain. openssl present that cannot run here,
    does not answer or is ended by a signal: CheckNotRun."""
    import hashlib
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
        p = _run_openssl(["openssl", "cms", "-verify", "-noverify", "-binary", "-inform", "DER", "-in", tp,
                          "-signer", sp, "-out", os.devnull], capture_output=True, timeout=30)
        if p.returncode < 0:
            raise _not_run("cannot run openssl here", OSError(f"terminated by signal {-p.returncode}"))
        der = None
        if p.returncode == 0 and os.path.exists(sp):
            with open(sp, "rb") as f:
                der = _first_pem_der(f.read())
        if der is None:
            return "invalid", None, _last_line(p.stderr, "openssl cms -verify refused it")
        return "valid", hashlib.sha256(der).hexdigest(), None
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
    since v0.6 of the spec (`verify_token`, SPEC §11); kept for callers outside it."""
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
    p.add_argument("--tsa-cert", action="append", default=None, metavar="PEM",
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
