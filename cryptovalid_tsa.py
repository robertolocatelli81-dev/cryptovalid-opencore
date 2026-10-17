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
    """Pragmatic check: the token's messageImprint carries our digest (the OCTET STRING is present)."""
    return _tlv(0x04, digest) in token_der

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


def verify_cms_signature(token_der: bytes):
    """Firma CMS del token valida? (openssl cms -verify -noverify: verifica la FIRMA
    col certificato embedded, NON la catena di trust — la qualificazione della catena
    è il lavoro della LOTL, per impronta). Ritorna True/False, o None se openssl manca.
    Serve a respingere blob forgiati che contengono il digest senza essere CMS firmati.
    openssl presente ma non avviabile, o nessun file temporaneo: CheckNotRun (0.20.3)."""
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
    """Full RFC 3161 verification via `openssl ts` (signature + TSA cert), if openssl is installed (None if not).
    openssl present but not startable, or no temporary file: CheckNotRun (0.20.3)."""
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
    a = p.parse_args(argv)
    granted, token, _ = request_timestamp(bytes.fromhex(a.digest_hex), a.tsa)
    ok = granted and token is not None and token_contains_digest(token, bytes.fromhex(a.digest_hex))
    emit(json.dumps({"granted": granted, "digest_bound": ok,
                      "token_b64_len": len(base64.b64encode(token)) if token else 0,
                      "tsa": a.tsa}, indent=2))
    return 0 if ok else 1

if __name__ == "__main__":
    raise SystemExit(main())
