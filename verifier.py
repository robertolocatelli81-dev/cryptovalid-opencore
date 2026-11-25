#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
"""
CryptoValid Open Core - standalone ledger verifier (auditor-grade)
==================================================================

SPDX-License-Identifier: AGPL-3.0-or-later
Copyright (C) 2026 Roberto Locatelli

This file is part of CryptoValid Open Core (the AGPL-3.0 carve-out of the
OMEGA Ecosystem, relicensed by its author on 2026-08-08). You can redistribute
it and/or modify it under the terms of the GNU Affero General Public License
as published by the Free Software Foundation, either version 3 of the License,
or (at your option) any later version. See LICENSE in this directory.

Independently verifies a hash-chained ledger (*.jsonl) with NOTHING but the
Python standard library (hashlib, json, sys, argparse).

Verified schema:
  - each line is JSON with at least: {idx, ts, data, prev_hash, self_hash}
  - self_hash = SHA-256( JSON(entry without self_hash, sort_keys, separators (',',':')) )
  - prev_hash of entry i = self_hash of entry i-1 (the first has 64 zeros)

Output: structured JSON receipt with an explicit `scope` (what PASS proves and does not prove).
Exit code 0 = chain intact, 1 = failure (a file with zero entries is a failure: nothing was verified), 74 = the receipt
could not be written whole (stdout or the --out file: full, closed, a reader gone), whatever the verdict.

Example:
    python3 opencore/verifier.py exports/omega_audit_ledger.jsonl
    python3 opencore/verifier.py ledger.jsonl --algo sha3_256

Reproducible by any third-party auditor: same file, same schema -> same receipt.
"""

from __future__ import annotations

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
import argparse
import errno
import hashlib
import json
import os
import re
import sys
import threading
from datetime import datetime, timezone
from typing import Dict, List, Optional

GENESIS_PREV = "0" * 64
SUPPORTED_ALGOS = ("sha256", "sha3_256")
ENTRY_KEYS = frozenset({"idx", "ts", "data", "prev_hash", "self_hash", "signature", "signer", "tsa_token", "signature_pq", "signer_pq"})   # SPEC §2.1: the closed entry schema

EX_IOERR = 74   # sysexits.h: the receipt could not be written whole (0.20.3); never the verdict's 0/1 in that case

# ── The one writer of every command in this repository (0.20.3) ─────────────────────────────────────────────────────
# A command that has computed an outcome (verdict, receipt, record, key, pack) delivers it WHOLE — to stdout, to the
# file it promises, to the ledger — or exits 74 (EX_IOERR) with one line `receipt not written: <reason>` on stderr.
# The other modules with a `__main__` import these functions from here, so verifier.py stays one stdlib-only file.
# Measured on Linux (13/10/2026); macOS and Windows are not measured.


class ReceiptNotWritten(OSError):
    """stdout refused the outcome (ENOSPC, EPIPE, EBADF, EFBIG, a closed or absent stdout): the exit code becomes 74"""


class OutputNotWritten(OSError):
    """a file the command promises (--out, a sidecar, a pack file, a state file) or a ledger line could not be written
    whole: the exit code becomes 74, and nothing half-written is left at the promised path"""


class CheckNotRun(OutputNotWritten):
    """a check the input asks for that cannot be RUN here (openssl cannot be started: fork refused, no descriptor left;
    no temporary file for the bytes openssl reads): exit 74, never a verdict on the input — it is neither the PASS nor
    the FAIL of that check (measured 13/10/2026 on 0.20.2 under RLIMIT_NPROC 1: a valid pack was `valid: false`, exit 1)

    0.22.0: a verifier that computed everything else may attach its COMPLETE receipt (`receipt`, a dict) — the check that
    did not run marked there (`not_evaluated` / `instrument_failure`, SPEC §10); the command writes it with
    check_not_run_exit() (stderr `check not run here: <reason>`, exit 74). Without one, receipt_cli says `receipt not
    written: <reason>` and exits 74, as before."""

    def __init__(self, *args, receipt=None):
        super().__init__(*args)
        self.receipt = receipt


def _text_layer_bytes(out, buf, text: str) -> bytes:
    """The bytes Python's own stdout text layer writes for `text`: its encoding and error handler, and a byte order
    mark only where that layer puts one — utf-16 / utf-32 only on a stdout seekable at offset 0, utf-8-sig on a pipe
    too, none on a seekable stdout past offset 0 (str.encode would put one on a pipe too). Lines end in "\\n" on every
    system: until 0.29.0 Windows got "\\r\\n" (os.linesep; `--quiet` wrote b"PASS\\r\\n", CI of f1e95d5) and a receipt
    of the same verdict had other bytes there."""
    import codecs
    encoding = out.encoding or "utf-8"
    if os.name == "nt" and not os.environ.get("PYTHONIOENCODING"):
        # Windows gives a pipe or a file the ANSI code page (cp1252): a reason with a character outside it was a
        # UnicodeEncodeError, exit 74, where Linux and macOS wrote the receipt. UTF-8 there too, as on a Windows
        # console (Python writes UTF-8 to it), as RFC 8259 §8.1 asks of JSON and as PEP 686 makes the default
        encoding = "utf-8"
    enc = codecs.getincrementalencoder(encoding)(out.errors or "strict")
    try:
        seekable = buf.seekable()
        at_start = seekable and buf.tell() == 0
    except (OSError, ValueError):
        seekable = at_start = False
    if (seekable and not at_start) or (not seekable and codecs.lookup(encoding).name in ("utf-16", "utf-32")) \
            or getattr(out, "_cv_bytes_written", False):   # the text layer's encoder writes its mark once per stream
        enc.setstate(0)   # no byte order mark
    return enc.encode(text, final=True)


def _wait_writable(buf) -> None:
    """stdout is non-blocking and full: wait until it can take more, as a blocking write would (the reader is slow, not
    gone; one that goes away makes the next write EPIPE). `select` sleeps in the kernel and Python retries it after a
    signal (PEP 475). A byte stream with no descriptor (io.BytesIO under a TextIOWrapper) never blocks. Windows, where
    select waits on sockets only: _wait_pipe_writable_windows."""
    import select
    if os.name == "nt":
        try:
            fd = buf.fileno()
        except (OSError, ValueError) as e:
            raise OSError(f"stdout is non-blocking and cannot be waited for: {e}")
        _wait_pipe_writable_windows(fd)
        return
    try:
        select.select([], [buf.fileno()], [])
    except (OSError, ValueError) as e:   # no descriptor, or one select cannot wait on
        raise OSError(f"stdout is non-blocking and cannot be waited for: {e}")


def _wait_pipe_writable_windows(fd: int) -> None:
    """Windows' equivalent of select for a pipe set non-blocking (PIPE_NOWAIT; os.set_blocking since Python 3.12): ask
    the pipe how much it can take (NtQueryInformationFile, FilePipeLocalInformation: WriteQuotaAvailable, the call libuv
    makes for the same purpose) and sleep between questions, 1 ms doubling to 50 ms, so a slow reader costs no CPU. It
    returns when the pipe has room, when it is no longer connected (the next write then fails: the reader is gone),
    or after 0.5 s (the caller's next write answers).
    An anonymous pipe has no overlapped I/O to wait on; a handle that is not a pipe returns at once."""
    import ctypes
    import msvcrt
    import time
    from ctypes import wintypes

    class _Iosb(ctypes.Structure):
        _fields_ = [("Status", ctypes.c_void_p), ("Information", ctypes.c_void_p)]

    class _PipeInfo(ctypes.Structure):
        _fields_ = [(n, wintypes.ULONG) for n in ("NamedPipeType", "NamedPipeConfiguration", "MaximumInstances",
                                                  "CurrentInstances", "InboundQuota", "ReadDataAvailable",
                                                  "OutboundQuota", "WriteQuotaAvailable", "NamedPipeState",
                                                  "NamedPipeEnd")]
    query = ctypes.WinDLL("ntdll").NtQueryInformationFile
    query.argtypes = (wintypes.HANDLE, ctypes.POINTER(_Iosb), ctypes.c_void_p, wintypes.ULONG, ctypes.c_int)
    query.restype = ctypes.c_long
    handle = msvcrt.get_osfhandle(fd)
    delay, waited = 0.001, 0.0
    while waited < 0.5:   # then the caller writes again: if the quota read wrong, the write itself is the answer
        iosb, info = _Iosb(), _PipeInfo()
        if query(handle, ctypes.byref(iosb), ctypes.byref(info), ctypes.sizeof(info), 24) != 0:   # 24: FilePipeLocalInformation
            return
        if info.WriteQuotaAvailable > 0 or info.NamedPipeState != 3:   # 3: FILE_PIPE_CONNECTED_STATE
            return
        time.sleep(delay)
        waited += delay
        delay = min(delay * 2, 0.05)


def write_all(text: str) -> None:
    """Write the whole text to stdout and flush it; ReceiptNotWritten when it did not all get there (see _write_stdout)."""
    _write_stdout(text, None)


def write_all_bytes(raw: bytes) -> None:
    """write_all for bytes that are the outcome as they are (a stored object): no text layer encoding"""
    _write_stdout(None, raw)


def _write_stdout(text, raw) -> None:
    """Write the whole text to stdout and flush it; ReceiptNotWritten when it did not all get there. The bytes go to
    `sys.stdout.buffer` in a loop that checks the count: with -u or PYTHONUNBUFFERED that is a raw FileIO whose write()
    can take part of the data (a file size limit, a disk nearly full) and return the count without raising, or None (a
    full non-blocking pipe) — the text layer above dropped the rest in silence. A full non-blocking stdout is waited for,
    never given up on. An in-process text stream with no bytes below it (io.StringIO) gets the text."""
    out = sys.stdout
    if out is None:   # started with fd 1 closed: print() would drop the outcome and say nothing
        raise ReceiptNotWritten("stdout is closed")
    try:
        buf = getattr(out, "buffer", None)
        while True:   # whatever the text layer still holds goes first, waited for like the outcome
            try:
                out.flush()
                break
            except BlockingIOError:
                if buf is None:
                    raise
                _wait_writable(buf)
        if buf is None:
            if text is None:
                raise OSError("stdout has no byte layer for a binary outcome")
            out.write(text)
            out.flush()
            return
        data = memoryview(_text_layer_bytes(out, buf, text) if text is not None else raw)
        try:
            out._cv_bytes_written = True   # a second outcome on this stream gets no second byte order mark
        except (AttributeError, TypeError):
            pass
        while data:
            try:
                n = buf.write(data)
                waited = False
            except BlockingIOError as e:   # buffered stdout on a full non-blocking pipe: part of it taken
                n, waited = e.characters_written, True
            if n is None:   # raw stdout on a full non-blocking pipe: nothing taken
                n, waited = 0, True
            if n < 0 or n > len(data) or (n == 0 and not waited):
                raise OSError(f"short write: {len(data)} bytes not written")
            data = data[n:]
            if data and waited:
                _wait_writable(buf)
        while True:   # flushed HERE, before the exit code is chosen, not by the interpreter at exit
            try:
                buf.flush()
                return
            except BlockingIOError:
                _wait_writable(buf)
    except ReceiptNotWritten:
        raise
    except (OSError, ValueError) as e:   # ValueError: I/O on a closed file, or text the stream cannot encode
        raise ReceiptNotWritten(f"{type(e).__name__}: {e}") from None


def emit(*parts, sep: str = " ", end: str = "\n", flush: bool = True) -> None:
    """print() for an outcome: the same text, written by write_all (ReceiptNotWritten when not written whole)"""
    write_all(sep.join(str(p) for p in parts) + end)


def say(text: str) -> bool:
    """Write `text` to stderr without ever raising; True when it was written. If stderr is full, closed or its reader
    gone, its descriptor is pointed at the null device (the interpreter's last flush cannot fail again and turn the
    exit code into 120) and the caller's exit code stands. Windows: in UTF-8, as stdout (_text_layer_bytes), unless
    PYTHONIOENCODING chooses another: in the ANSI code page "§" was a byte no UTF-8 reader takes (run 45356889667)."""
    err = sys.stderr
    if os.name == "nt" and err is not None and not os.environ.get("PYTHONIOENCODING") \
            and (getattr(err, "encoding", "") or "").lower().replace("-", "") != "utf8":
        try:
            err.reconfigure(encoding="utf-8", errors="backslashreplace")
        except (AttributeError, OSError, ValueError):   # not a text stream that can change: written as it is
            pass
    if err is None:   # started with fd 2 closed
        return False
    try:
        err.write(text)
        err.flush()
        return True
    except (OSError, ValueError):
        silence(err)
        return False


def silence(stream) -> None:
    """Point the descriptor BEHIND `stream` at /dev/null so the interpreter's own flush at exit does not fail again on
    what is still buffered ("Exception ignored", exit 120). The stream's own descriptor, never a fixed number: with fd
    1 closed at start, a file this run opened may hold descriptor 1."""
    try:
        if stream is None:
            return
        fd = stream.fileno()
    except (OSError, ValueError, AttributeError):
        return
    try:
        null = os.open(os.devnull, os.O_WRONLY)
        try:
            os.dup2(null, fd)
        finally:
            os.close(null)
    except OSError:
        pass


def receipt_lost(reason: str, stdout_failed: bool = True) -> int:
    """One line `receipt not written: <reason>` on stderr (nothing raised if stderr fails too) and EX_IOERR."""
    if stdout_failed:
        silence(sys.stdout)
    say(f"receipt not written: {reason}\n")
    return EX_IOERR


def check_not_run_exit(e: "CheckNotRun", text: str) -> int:
    """0.22.0 (SPEC §10): write the COMPLETE receipt `text` a verifier computed although one check could not run here,
    then `check not run here: <reason>` on stderr, exit 74; if the receipt is not taken whole, `receipt not written`."""
    why = write_stdout(text)
    if why is not None:
        return receipt_not_written(why)
    say(f"check not run here: {e}\n")
    return EX_IOERR


def receipt_not_written(why: str) -> int:
    """the 0.20.3 name of receipt_lost(why): stdout's descriptor is already silenced by write_stdout"""
    return receipt_lost(why, stdout_failed=False)


def write_stdout(text: str) -> Optional[str]:
    """Write `text` and a newline to stdout (write_all). None when every byte was taken, else the reason (and stdout's
    descriptor then points at /dev/null)."""
    try:
        write_all(text + "\n")
        return None
    except ReceiptNotWritten as e:
        silence(sys.stdout)
        return str(e)


def _unlink_quietly(path: str) -> None:
    try:
        os.unlink(path)
    except OSError:
        pass


def _write_fd(fd: int, data) -> None:
    data = memoryview(data)
    while data:
        n = os.write(fd, data)
        if n <= 0:
            raise OSError(f"short write: {len(data)} bytes not written")
        data = data[n:]


def os_reason(e: BaseException) -> str:
    """The text of an OSError in a reason: the C library's text for its errno (os.strerror), the same on every system,
    else its own text. Windows' own text differs ("The system cannot find the file specified" where Linux and macOS
    say "No such file or directory"), so a reason, and the receipt that carries it, depended on the system."""
    n = getattr(e, "errno", None)
    return os.strerror(n) if isinstance(n, int) else str(getattr(e, "strerror", None) or e)


def os_error_text(e: BaseException) -> str:
    """str(e), with an OSError that carries an errno written as POSIX writes it on every system: "[Errno 2] No such file
    or directory: 'x'" where Windows' own API says "[WinError 2] The system cannot find the file specified: 'x'"."""
    if isinstance(e, OSError) and isinstance(e.errno, int) and type(e).__str__ is OSError.__str__:
        text = f"[Errno {e.errno}] {os.strerror(e.errno)}"
        if e.filename is not None:
            text += f": {e.filename!r}" + (f" -> {e.filename2!r}" if e.filename2 is not None else "")
        return text
    return str(e)


def _fchmod(fd: int, path: str, mode: int) -> None:
    """os.fchmod, or os.chmod by name where there is none (Windows before Python 3.13): there a mode only sets or
    clears the read-only attribute"""
    if hasattr(os, "fchmod"):
        os.fchmod(fd, mode)
    else:
        os.chmod(path, mode)


def owner_only(path: str) -> None:
    """Windows' equivalent of mode 0600 / 0400 (a mode there only sets the read-only attribute): the file's access list
    is replaced by one entry, the user running this process, full control, protected from inheritance (SDDL
    "D:P(A;;FA;;;<SID>)", SetFileSecurityW; the SID from whoami). OSError when it cannot be set: a private file is
    then not written. (icacls /inheritance:r /grant:r left the explicit entries a new file gets on a runner: SYSTEM,
    Administrators, OWNER RIGHTS; CI run 45356889667.)"""
    import ctypes
    import re
    import subprocess
    from ctypes import wintypes
    sysdir = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32")
    who = subprocess.run([os.path.join(sysdir, "whoami.exe"), "/user", "/fo", "csv", "/nh"], capture_output=True,
                         timeout=60)
    sid = re.findall(rb'"(S-1-[0-9-]+)"', who.stdout)
    if who.returncode != 0 or len(sid) != 1:
        raise OSError(f"cannot read the SID of this user (whoami exit {who.returncode})")
    adv = ctypes.WinDLL("advapi32", use_last_error=True)
    conv = adv.ConvertStringSecurityDescriptorToSecurityDescriptorW
    conv.argtypes = (wintypes.LPCWSTR, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p)
    conv.restype = wintypes.BOOL
    setsec = adv.SetFileSecurityW
    setsec.argtypes = (wintypes.LPCWSTR, wintypes.DWORD, ctypes.c_void_p)
    setsec.restype = wintypes.BOOL
    sd = ctypes.c_void_p()
    if not conv("D:P(A;;FA;;;%s)" % sid[0].decode("ascii"), 1, ctypes.byref(sd), None):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        if not setsec(os.fspath(path), 0x4 | 0x80000000, sd):   # DACL | PROTECTED_DACL_SECURITY_INFORMATION
            raise ctypes.WinError(ctypes.get_last_error())
    finally:
        ctypes.WinDLL("kernel32").LocalFree(sd)


def _copy_dacl(src: str, dst: str) -> None:
    """Windows: `dst` gets the access list of `src` (GetFileSecurityW / SetFileSecurityW, DACL and its protection): the
    equivalent of keeping the mode of the file a temporary replaces (a private receipt replaced by a rename was given
    the folder's inherited list: run 45356889667, test_outcome_review "the receipt's mode was widened")."""
    import ctypes
    from ctypes import wintypes
    adv = ctypes.WinDLL("advapi32", use_last_error=True)
    get = adv.GetFileSecurityW
    get.argtypes = (wintypes.LPCWSTR, wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD))
    get.restype = wintypes.BOOL
    ctl = adv.GetSecurityDescriptorControl
    ctl.argtypes = (ctypes.c_void_p, ctypes.POINTER(wintypes.WORD), ctypes.POINTER(wintypes.DWORD))
    setsec = adv.SetFileSecurityW
    setsec.argtypes = (wintypes.LPCWSTR, wintypes.DWORD, ctypes.c_void_p)
    setsec.restype = wintypes.BOOL
    need = wintypes.DWORD(0)
    get(os.fspath(src), 0x4, None, 0, ctypes.byref(need))   # DACL_SECURITY_INFORMATION: the size first
    buf = ctypes.create_string_buffer(need.value or 1)
    if not get(os.fspath(src), 0x4, buf, need, ctypes.byref(need)):
        raise ctypes.WinError(ctypes.get_last_error())
    c, rev = wintypes.WORD(0), wintypes.DWORD(0)
    ctl(buf, ctypes.byref(c), ctypes.byref(rev))
    info = 0x4 | (0x80000000 if c.value & 0x1000 else 0x20000000)   # SE_DACL_PROTECTED: PROTECTED_ / UNPROTECTED_DACL
    if not setsec(os.fspath(dst), info, buf):
        raise ctypes.WinError(ctypes.get_last_error())


_WINDOWS_ABSOLUTE = re.compile(r"[A-Za-z]:[\\/]|[\\/]{2}[^\\/]+[\\/]+[^\\/]")   # X:\ or \\server\share


def _is_absolute(path: str) -> bool:
    """os.path.isabs, and on Windows one rule on every Python: a drive with its root, or \\\\server\\share (ntpath.isabs
    called `\\tools`, a folder of the current drive, absolute until Python 3.12)"""
    return _WINDOWS_ABSOLUTE.match(path) is not None if os.name == "nt" else os.path.isabs(path)


def which(name: str) -> Optional[str]:
    """shutil.which, never the current folder. On Windows shutil.which looks in the current folder before PATH (as
    cmd.exe does), and on every system an empty or relative PATH entry is the current folder: a program placed beside
    the evidence would be the one found, and the one run. An answer that is not an absolute path is dropped, and the
    absolute folders of PATH are searched."""
    import shutil
    exe = shutil.which(name)
    if exe is None or _is_absolute(exe):
        return exe
    exts = [e for e in os.environ.get("PATHEXT", ".COM;.EXE;.BAT;.CMD").split(os.pathsep) if e] if os.name == "nt" else [""]
    for folder in os.environ.get("PATH", "").split(os.pathsep):
        if _is_absolute(folder):
            for ext in exts:
                path = os.path.join(folder, name + ext)
                if os.path.isfile(path) and os.access(path, os.X_OK):
                    return path
    return None


def _refuse_taken(path: str) -> None:
    """Windows, before a creation that must be exclusive: O_CREAT|O_EXCL there follows a link to nothing and creates its
    target, and a folder at the name is a PermissionError, not FileExistsError (CI run 45565069144). Anything that
    stands at the name is FileExistsError, as on POSIX."""
    if os.name == "nt" and os.path.lexists(path):
        raise FileExistsError(errno.EEXIST, os.strerror(errno.EEXIST), path)


def create_private(folder: str, prefix: str, suffix: str = "", directory: bool = False):
    """A new file (fd, path) or folder (None, path) under `folder`, private to this user (0o600 / 0o700), at a random
    name made with O_CREAT|O_EXCL|O_NOFOLLOW (mkdir for a folder). Only a name already taken is tried again, at most 64
    times; any other OSError is raised at once. tempfile.mkstemp/mkdtemp retry a PermissionError on Windows while
    os.access(folder, W_OK) is true, and os.access reads only the read-only attribute, not the access list: in a
    folder an access list denies, that is up to 10000 tries (the class found in ap2-evidence-pack, 0.29.0)."""
    import secrets
    flags = os.O_RDWR | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
    for _ in range(64):
        path = os.path.join(folder, prefix + secrets.token_hex(8) + suffix)
        try:
            _refuse_taken(path)
            if directory:
                os.mkdir(path, 0o700)
                return None, path
            return os.open(path, flags, 0o600), path
        except FileExistsError:
            continue
    raise FileExistsError(errno.EEXIST, "64 random names already taken", folder)


def write_tmp(path: str, data, mode: int = 0o666, exact_mode: Optional[int] = None, like: Optional[str] = None) -> str:
    """Write `data` (str as UTF-8, or bytes) to a NEW temporary file next to `path` and return its name; on failure
    remove it and raise OutputNotWritten. The name is `<path>.<16 random hex>.tmp`, created with O_CREAT|O_EXCL (never
    an existing file, a symlink or a FIFO planted at a predictable name); written in a loop that checks the count,
    fsynced and closed inside the try (a deferred error at close is a failed write too); `mode` less the umask, or
    `exact_mode` as it is (the mode of the file the temporary will replace)."""
    import secrets
    raw = data if isinstance(data, (bytes, bytearray)) else data.encode("utf-8")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
    tmp = f"{path}.{secrets.token_hex(8)}.tmp"
    try:
        _refuse_taken(tmp)
        fd = os.open(tmp, flags, mode)
    except OSError as e:
        raise OutputNotWritten(f"{path}: {os_reason(e)}") from None
    try:
        try:
            if exact_mode is not None:
                _fchmod(fd, tmp, exact_mode)
            if os.name == "nt" and like is not None:
                _copy_dacl(like, tmp)   # before the first byte: the access list of the file it will replace
            elif os.name == "nt" and (mode if exact_mode is None else exact_mode) & 0o077 == 0:
                owner_only(tmp)   # before the first byte: a key is never readable by another user, even for a moment
            _write_fd(fd, raw)
            os.fsync(fd)
        finally:
            os.close(fd)
    except OSError as e:
        _unlink_quietly(tmp)
        raise OutputNotWritten(f"{path}: {os_reason(e)}") from None
    return tmp


def _replace_target(path: str):
    """Where a promised file goes and the mode it keeps, as 0.20.2's open(path, "w") had it: a symlink at `path` is
    followed (its target gets the file, the link stays); an existing file this process may not write (chmod 444 / 400)
    is refused (OutputNotWritten), never replaced by a rename behind its owner's back — the kernel's own check, opened
    for writing WITHOUT truncating; an existing file's mode is kept. Returns (real path, os.stat or None)."""
    real = os.path.realpath(path)
    try:
        st = os.stat(real)
    except OSError:
        return real, None
    import stat
    if stat.S_ISREG(st.st_mode):
        try:
            os.close(os.open(real, os.O_WRONLY | getattr(os, "O_CLOEXEC", 0)))
        except OSError as e:
            raise OutputNotWritten(f"{path}: {os_reason(e)}") from None
    return real, st


def _replace(tmp: str, path: str) -> None:
    """os.replace, and on Windows MoveFileExW with MOVEFILE_WRITE_THROUGH: the call returns once the rename is on the
    disk, the equivalent of the directory fsync POSIX needs after rename (a directory cannot be fsynced there)"""
    if os.name != "nt":
        os.replace(tmp, path)
        return
    import ctypes
    from ctypes import wintypes
    move = ctypes.WinDLL("kernel32", use_last_error=True).MoveFileExW
    move.argtypes = (wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD)
    move.restype = wintypes.BOOL
    if not move(os.fspath(tmp), os.fspath(path), 0x1 | 0x8):   # MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH
        err = ctypes.get_last_error()
        raise OSError(None, ctypes.FormatError(err).strip(), os.fspath(tmp), err, os.fspath(path))


def commit_tmp(tmp: str, path: str) -> None:
    """rename `tmp` over `path`; on failure remove `tmp` and raise OutputNotWritten"""
    try:
        _replace(tmp, path)
    except OSError as e:
        _unlink_quietly(tmp)
        raise OutputNotWritten(f"{path}: {os_reason(e)}") from None


def _is_windows_pipe(path) -> bool:
    """Windows: `path` names a pipe (\\\\.\\pipe\\name), known by its name. Looking at it (isdir, realpath, stat) opens
    it, which takes one of its instances from the write (CI run 45565069144: exit 74)."""
    return os.name == "nt" and str(path).replace("/", "\\").lower().startswith("\\\\.\\pipe\\")


def refuse_directory(path: str) -> None:
    """a path that names a directory (or ends with a separator) can never receive the file: OutputNotWritten"""
    if _is_windows_pipe(path):
        return
    p = str(path)
    if p.endswith(("/", os.sep)) or os.path.isdir(p):
        raise OutputNotWritten(f"{path}: is a directory")


def write_output(path: str, data, mode: int = 0o666) -> None:
    """The whole `data` at `path`, or nothing new there and OutputNotWritten. A regular file (or a new path) is written
    through a temporary file renamed over it once complete, so a file already at `path` stays intact on failure. A path
    that exists and is not a regular file (a FIFO, a Windows named pipe, /dev/stdout, a device) is written directly,
    every byte as it is, in a loop."""
    import stat
    refuse_directory(path)
    pipe = _is_windows_pipe(path)
    path, st = (path, None) if pipe else _replace_target(path)
    if pipe or (st is not None and not stat.S_ISREG(st.st_mode)):
        raw = data if isinstance(data, (bytes, bytearray)) else data.encode("utf-8")
        try:
            fd = os.open(path, os.O_WRONLY | getattr(os, "O_NOCTTY", 0) | getattr(os, "O_BINARY", 0))
            try:
                _write_fd(fd, raw)
            finally:
                os.close(fd)
        except OSError as e:
            raise OutputNotWritten(f"{path}: {os_reason(e)}") from None
        return
    # an existing file keeps its mode (a caller that asks for a mode, the key files, gets that mode)
    keep = stat.S_IMODE(st.st_mode) if st is not None and mode == 0o666 else None
    commit_tmp(write_tmp(path, data, mode, exact_mode=keep, like=path if st is not None and os.name == "nt" else None), path)


def write_new(path: str, data, mode: int = 0o600) -> None:
    """Create `path` with the whole `data`, never over an existing path: the bytes go to a temporary file (write_tmp),
    which is then hard-linked at `path` (FileExistsError, as O_EXCL, when something is already there) and removed. A
    key or a WORM object is either absent or whole at its path, never cut. Windows: a read-only file cannot be
    removed, so a read-only `mode` (a WORM object, 0400) is set on `path` after the temporary name is gone."""
    late = os.name == "nt" and not mode & 0o200
    tmp = write_tmp(path, data, (mode | 0o200) if late else mode)
    try:
        os.link(tmp, path)
    except FileExistsError:
        raise
    except OSError as e:
        raise OutputNotWritten(f"{path}: {os_reason(e)}") from None
    finally:
        _unlink_quietly(tmp)
    if late:
        try:
            os.chmod(path, mode)
        except OSError as e:
            raise OutputNotWritten(f"{path}: {os_reason(e)}") from None


def copy_output(src: str, path: str) -> None:
    """Copy the file `src` to `path` whole, or leave nothing new at `path` (OutputNotWritten): read in chunks into a
    temporary file next to `path` (O_EXCL, random name), fsync, close, rename. An error READING `src` stays an OSError
    (the caller's input), with the temporary file removed."""
    import secrets
    import stat
    refuse_directory(path)
    path, st = _replace_target(path)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
    tmp = f"{path}.{secrets.token_hex(8)}.tmp"

    def lost(e):
        return OutputNotWritten(f"{path}: {os_reason(e)}")
    with os.fdopen(open_regular(src, float("inf")), "rb") as f:   # SPEC §5 step 0: a regular file, opened once without blocking
        try:
            _refuse_taken(tmp)
            fd = os.open(tmp, flags, 0o666)
        except OSError as e:
            raise lost(e) from None
        try:
            try:
                if st is not None:
                    try:
                        _fchmod(fd, tmp, stat.S_IMODE(st.st_mode))   # the existing file's mode, as shutil.copyfile kept it
                        if os.name == "nt":
                            _copy_dacl(path, tmp)   # and on Windows its access list, the mode's equivalent there
                    except OSError as e:
                        raise lost(e) from None
                while True:
                    chunk = f.read(1 << 20)
                    if not chunk:
                        break
                    try:
                        _write_fd(fd, chunk)
                    except OSError as e:
                        raise lost(e) from None
                try:
                    os.fsync(fd)
                except OSError as e:
                    raise lost(e) from None
            finally:
                try:
                    os.close(fd)
                except OSError as e:   # a deferred error at close is a failed write too
                    raise lost(e) from None
        except BaseException:
            _unlink_quietly(tmp)
            raise
    commit_tmp(tmp, path)


def write_file(path: str, text: str) -> Optional[str]:
    """write_output(path, text): None on success, else the reason (0.20.3 interface)"""
    try:
        write_output(path, text)
        return None
    except OutputNotWritten as e:
        return str(e)


class file_lock:
    """An exclusive lock between processes on `path` (created if absent), held for the `with` block: flock on POSIX;
    on Windows, which has no flock, its equivalent, a byte-range lock (msvcrt.locking on byte 0, retried until taken:
    LK_LOCK gives up after 10 one-second tries). Until 0.29.0 the witness and the SCITT ledger had no lock there."""

    def __init__(self, path: str):
        self.path = path

    def __enter__(self):
        self.fd = os.open(self.path, os.O_RDWR | os.O_CREAT | getattr(os, "O_BINARY", 0), 0o600)
        try:
            if os.name == "nt":
                import msvcrt
                while True:
                    try:
                        os.lseek(self.fd, 0, os.SEEK_SET)
                        msvcrt.locking(self.fd, msvcrt.LK_LOCK, 1)
                        break
                    except OSError:   # EDEADLOCK: still held by another process after 10 s; wait again
                        continue
            else:
                import fcntl
                fcntl.flock(self.fd, fcntl.LOCK_EX)
        except BaseException:
            os.close(self.fd)
            raise
        return self

    def __exit__(self, *exc):
        try:
            if os.name == "nt":
                import msvcrt
                os.lseek(self.fd, 0, os.SEEK_SET)
                msvcrt.locking(self.fd, msvcrt.LK_UNLCK, 1)
            else:
                import fcntl
                fcntl.flock(self.fd, fcntl.LOCK_UN)
        finally:
            os.close(self.fd)
        return False


def append_line(path: str, line: bytes, *, mode: int = 0o666, opened=None, sync: bool = True) -> None:
    """Append whole ledger lines (bytes ending in b"\\n") or nothing: unbuffered os.write in a loop, fsync (`sync`); on any
    failure the file is truncated back to the bytes it had and OutputNotWritten names what is left. `opened` = an
    already open binary file the caller holds a lock on (its descriptor is used); else `path` is opened O_APPEND."""
    if not line.endswith(b"\n"):
        raise ValueError("a ledger line ends with a newline")
    own = opened is None
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND | getattr(os, "O_BINARY", 0), mode) if own else opened.fileno()
    try:
        if not own:
            opened.flush()
        end = os.lseek(fd, 0, os.SEEK_END)
        try:
            _write_fd(fd, line)
            if sync:
                os.fsync(fd)
        except BaseException as e:
            try:
                os.ftruncate(fd, end)   # back to the bytes this call found: never half a line in a hash-chained file
            except OSError:
                left = "the ledger could not be truncated back and may end in part of the line"
            else:
                try:
                    os.fsync(fd)
                    left = "the ledger is left as it was"
                except OSError:   # the truncation happened; only its flush to the disk failed
                    left = "the ledger was truncated back to the bytes it had (that truncation could not be synced)"
            if isinstance(e, OSError):
                raise OutputNotWritten(f"ledger {path}: {os_reason(e)}; nothing was recorded, {left}") from None
            raise
    finally:
        if own:
            os.close(fd)


class Parser(argparse.ArgumentParser):
    """argparse with its output through the writers above: usage and error lines (exit 2) go to stderr with a write that
    never raises (argparse's own exited 120 with stderr full, and with stderr closed it printed the usage to STDOUT);
    `--help` prints through write_all, and a help that is not written whole is exit 74."""

    def print_help(self, file=None):
        if file is not None:
            return super().print_help(file)
        try:
            write_all(self.format_help())
        except ReceiptNotWritten as e:
            raise SystemExit(receipt_lost(str(e)))

    def _print_message(self, message, file=None):   # argparse's only writer: error() and exit() print through it
        if not message:
            return
        if file is not None and file is not sys.stdout and file is not sys.stderr:   # a file the caller passed itself
            file.write(message)
        else:
            say(message)


def receipt_cli(main_fn):
    """Decorator for a command's main(): ReceiptNotWritten → 74 (stdout silenced), OutputNotWritten → 74; any other
    exception keeps exit 1 with its traceback written by say() (a full stderr no longer turns it into 120)."""
    import functools

    @functools.wraps(main_fn)
    def wrapper(*a, **kw):
        try:
            return main_fn(*a, **kw)
        except ReceiptNotWritten as e:
            return receipt_lost(str(e))
        except OutputNotWritten as e:
            return receipt_lost(str(e), stdout_failed=False)
        except Exception:
            import traceback
            say(traceback.format_exc())
            return 1
    return wrapper




def _reject_dup(pairs):
    seen = {}
    for k, v in pairs:
        if k in seen:
            raise ValueError(f"duplicate JSON key {k!r}")
        seen[k] = v
    return seen


_SAFE_INT = 2 ** 53 - 1   # portable across Python/JS/Rust/Swift; decimals travel as strings


def _no_float(x):
    raise ValueError(f"non-portable float {x!r} (use a string; the format forbids floats)")


MAX_INT_DIGITS = 4300   # SPEC §30


def _portable_int(x: str) -> int:
    """SPEC §30: an integer of more than 4300 digits is refused on every Python. 4300 is the default limit of the
    interpreter's own conversion (3.9.14+, 3.10.7+, 3.11+); a Python without one (3.9.13) read such a number."""
    if len(x) - x.startswith("-") > MAX_INT_DIGITS:
        raise ValueError(f"integer of more than {MAX_INT_DIGITS} digits")
    return int(x)


def _bounded_int(x):
    n = _portable_int(x)
    if abs(n) > _SAFE_INT:
        raise ValueError(f"integer {x} outside the portable range +/-(2**53-1)")
    return n


MAX_JSON_DEPTH = 512  # normative acceptance-profile bound (spec/CONFORMANCE.md, 2026-09-13)
MAX_INPUT_BYTES = 256 * 1024 * 1024  # a ledger/pack larger than this is refused fail-closed (input_too_large)
# SPEC §22 rule 9: what a ledger may hold, counted before any line is parsed (16 MiB of "0\n" lines took more than 2 GB)
MAX_INPUT_LINES = 1 << 20
MAX_JSON_TOKENS = 1 << 23   # the characters { [ , : wherever they stand


def input_too_complex(lines: int, tokens: int) -> Optional[str]:
    """SPEC §22 rule 9: the reason a ledger of `lines` lines (blank ones included) and `tokens` tokens holds too much,
    else None; lines first."""
    if lines > MAX_INPUT_LINES:
        return f"input_too_large: more than {MAX_INPUT_LINES} lines"
    if tokens > MAX_JSON_TOKENS:
        return f"input_too_large: more than {MAX_JSON_TOKENS} JSON tokens"
    return None


def ledger_too_complex(data: bytes) -> Optional[str]:
    """input_too_complex of the bytes of a ledger: for the readers of a ledger beside verify_ledger (the signature layer,
    the evidence pack), which until NEMESIS 22/11/2026 parsed every line of a ledger this rule refuses."""
    return input_too_complex(data.count(b"\n") + (1 if data and not data.endswith(b"\n") else 0),
                             sum(data.count(c) for c in (b"{", b"[", b",", b":")))


_RECURSION_HEADROOM = 3 * MAX_JSON_DEPTH + 256  # frames the C decoder + object_pairs_hook may need per line


_HEADROOM_LOCK = threading.Lock()
_HEADROOM = {"users": 0, "saved": None, "set": None}


class _RecursionHeadroom:
    """The PASS side of the bound must not depend on how deep the CALLER's stack already is (an MCP
    server or a report generator invoking verify_ledger from many frames down). Raise the interpreter
    recursion limit so that an in-profile line (<= MAX_JSON_DEPTH) can always be decoded (2026-09-13).
    Limits (declared in spec/CONFORMANCE.md): this raises the interpreter limit, not the thread's C stack;
    on CPython >= 3.12 the C decoder keeps its own counter, so the positive control for this guard was
    reproduced on 3.11.
    Since 15/11/2026 the limit is put back when the decode ends (also on an exception): until 0.24.0 a library caller
    was left with the raised limit for the rest of its process (1000 -> 1796, measured). The interpreter limit is one
    per process, so the first decode that raises it saves the caller's value and the last one to finish, in any thread,
    restores it; if someone else changed the limit meanwhile, their value is kept. Restoring is safe: the caller ran at
    its own depth under its own limit before the call."""

    def __enter__(self):
        depth = 0
        f = sys._getframe()
        while f is not None:
            depth += 1
            f = f.f_back
        need = depth + _RECURSION_HEADROOM
        with _HEADROOM_LOCK:
            h = _HEADROOM
            if h["users"] == 0:
                h["saved"], h["set"] = sys.getrecursionlimit(), None
            h["users"] += 1
            if sys.getrecursionlimit() < need:
                sys.setrecursionlimit(need)
                h["set"] = need
        return self

    def __exit__(self, *exc):
        with _HEADROOM_LOCK:
            h = _HEADROOM
            h["users"] -= 1
            if h["users"] == 0:
                if h["set"] is not None and sys.getrecursionlimit() == h["set"]:
                    sys.setrecursionlimit(h["saved"])
                h["saved"] = h["set"] = None
        return False


class InputNotRegular(OSError):
    """SPEC §5 step 0: the path is not a regular file (a FIFO, a device, a directory)"""


class InputTooLarge(OSError):
    """SPEC §5 step 0: the file is larger than the bound"""


def _open_input(path: str) -> int:
    """os.open for reading without blocking. Windows cannot open a directory as a file (PermissionError): that is a
    directory, not a file this user may not read, so InputNotRegular as on POSIX (where fstat says so). Until 0.29.0 an
    archive segment that was a directory was read there as a missing file and the archive was valid (run 45377477990)."""
    try:
        return os.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOCTTY", 0)
                       | getattr(os, "O_BINARY", 0))
    except PermissionError:
        if os.name == "nt" and os.path.isdir(path):
            raise InputNotRegular(f"{path}: not a regular file") from None
        raise


def open_regular(path: str, limit: int = MAX_INPUT_BYTES) -> int:
    """SPEC §5 step 0 (v0.11): a descriptor of a REGULAR file of at most `limit` bytes, opened once WITHOUT blocking and
    judged on the open descriptor (fstat), so a FIFO put at the path is never waited on and nothing is checked on one
    file and read from another. Raises InputNotRegular, InputTooLarge, or the OSError of os.open (FileNotFoundError...).
    O_NONBLOCK does not change reads of a regular file."""
    import stat
    fd = _open_input(path)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise InputNotRegular(f"{path}: not a regular file")
        if st.st_size > limit:
            raise InputTooLarge(f"{path}: larger than {limit} bytes")
        return fd
    except BaseException:
        os.close(fd)
        raise


FIFO_IDLE_SECONDS = 10   # SPEC §5 step 0 (v0.12): a pipe that gives no byte and no end of file for this long is FAIL


class InputIdle(OSError):
    """SPEC §5 step 0 (v0.12): a FIFO that gave no byte and no end of file within FIFO_IDLE_SECONDS"""


def open_ledger_input(path: str, limit: int = MAX_INPUT_BYTES, idle: float = FIFO_IDLE_SECONDS):
    """SPEC §5 step 0 (v0.12), the ledger verifier only: a descriptor of a regular file (as open_regular), or, for a FIFO
    (`verifier.py <(cat ledger.jsonl)`, read by the six verifiers since 0.20.2), its bytes read to the end without ever
    blocking: at most `limit` bytes, and InputIdle when `idle` seconds pass with no byte and no end of file (a pipe with
    no writer). Returns (fd, None) or (None, bytes). Raises InputNotRegular (a device, a directory), InputTooLarge,
    InputIdle, or the OSError of os.open."""
    import select
    import stat
    fd = _open_input(path)
    try:
        st = os.fstat(fd)
        if stat.S_ISREG(st.st_mode):
            if st.st_size > limit:
                raise InputTooLarge(f"{path}: larger than {limit} bytes")
            return fd, None
    except BaseException:
        os.close(fd)
        raise
    try:
        if not stat.S_ISFIFO(st.st_mode):
            raise InputNotRegular(f"{path}: not a regular file")
        data = bytearray()
        if os.name == "nt":
            return None, _read_pipe_windows(fd, path, limit, idle, data)
        while True:
            # select, not poll: poll on a FIFO is unreliable on macOS. Linux: no writer yet = not ready (it waits); the
            # writer gone = ready, and read gives b"" (the end)
            ready, _, _ = select.select([fd], [], [], idle)
            if not ready:
                raise InputIdle(f"{path}: FIFO gave no byte and no end of file in {idle:g} s")
            try:
                b = os.read(fd, 1 << 16)
            except BlockingIOError:
                continue
            if not b:
                return None, bytes(data)
            data += b
            if len(data) > limit:
                raise InputTooLarge(f"{path}: larger than {limit} bytes")
    finally:
        os.close(fd)


def _read_pipe_windows(fd: int, path: str, limit: int, idle: float, data: bytearray) -> bytes:
    """Windows' equivalent of the select loop of open_ledger_input (select waits on sockets only there): ask the pipe
    how many bytes wait (PeekNamedPipe) and read only those, so a read never blocks; the writer gone
    (ERROR_BROKEN_PIPE) is the end of file; no byte and no end for `idle` seconds is InputIdle. Polled every 10 ms,
    as the JS verifier polls a FIFO, and without a pause for the 20 ms after a byte: a pipe of 64 KiB refilled by a
    fast writer would otherwise give 64 KiB per pause (15.6 ms, the Windows clock before Python 3.11)."""
    import ctypes
    import msvcrt
    import time
    from ctypes import wintypes
    peek = ctypes.WinDLL("kernel32", use_last_error=True).PeekNamedPipe
    peek.argtypes = (wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD, ctypes.c_void_p, ctypes.POINTER(wintypes.DWORD),
                     ctypes.c_void_p)
    peek.restype = wintypes.BOOL
    handle = msvcrt.get_osfhandle(fd)
    last = time.monotonic()
    while True:
        n = wintypes.DWORD(0)
        if not peek(handle, None, 0, None, ctypes.byref(n), None):
            err = ctypes.get_last_error()
            if err in (109, 233):   # ERROR_BROKEN_PIPE, ERROR_PIPE_NOT_CONNECTED: the writer is gone, the end
                return bytes(data)
            raise ctypes.WinError(err)
        if n.value:
            data += os.read(fd, min(n.value, 1 << 16))
            last = time.monotonic()
            if len(data) > limit:
                raise InputTooLarge(f"{path}: larger than {limit} bytes")
            continue
        waited = time.monotonic() - last
        if waited >= idle:
            raise InputIdle(f"{path}: FIFO gave no byte and no end of file in {idle:g} s")
        time.sleep(0 if data and waited < 0.02 else 0.01)


def read_bounded(f, limit: int) -> bytes:
    """At most `limit` + 1 bytes of the open file `f`, with a buffer of its size, not of the bound: f.read(limit + 1)
    asked for 256 MiB to read a file of 7 bytes (MemoryError under a data limit of 100 MB on Linux, measured
    2026-11-25; a peak working set of 270 MiB on Windows, where the system touches the whole buffer)."""
    parts, n, want = [], 0, os.fstat(f.fileno()).st_size + 1   # one more than the size: the end, or a file that grew
    while n <= limit:
        b = f.read(min(want, limit + 1 - n))
        if not b:
            break
        parts.append(b)
        n, want = n + len(b), 1 << 20
    return b"".join(parts)


def read_regular(path: str, limit: int = MAX_INPUT_BYTES) -> bytes:
    """the bytes of a regular file of at most `limit` bytes (open_regular), read bounded: a file that grew past the
    bound after the fstat is InputTooLarge too"""
    with os.fdopen(open_regular(path, limit), "rb") as f:
        data = read_bounded(f, limit)
    if len(data) > limit:
        raise InputTooLarge(f"{path}: larger than {limit} bytes")
    return data


def sha256_regular(path: str, limit: int = MAX_INPUT_BYTES, block: int = 1 << 20) -> str:
    """SHA-256 hex of a regular file of at most `limit` bytes (open_regular), read in blocks of `block` bytes"""
    h, n = hashlib.sha256(), 0
    with os.fdopen(open_regular(path, limit), "rb") as f:
        while True:
            b = f.read(block)
            if not b:
                break
            n += len(b)
            if n > limit:
                raise InputTooLarge(f"{path}: larger than {limit} bytes")
            h.update(b)
    return h.hexdigest()


def read_text_regular(path: str, limit: int = MAX_INPUT_BYTES) -> str:
    """the text of a regular file of at most `limit` bytes (read_regular), decoded as open(path, encoding="utf-8")
    decodes it (strict UTF-8, universal newlines): for the readers that used open() on a path (SPEC §5 step 0)"""
    import io
    return io.TextIOWrapper(io.BytesIO(read_regular(path, limit)), encoding="utf-8").read()


KEY_MAX_BYTES = 1 << 20   # a key file read by a signer (hex seed, base64 DER): far above any key this package reads


def read_input(path: str, limit: int = MAX_INPUT_BYTES, idle: float = FIFO_IDLE_SECONDS) -> bytes:
    """SPEC §5 step 0 (v0.12), what a WRITER reads from a path it was given (the data it signs or stores, a key file):
    a regular file of at most `limit` bytes, or a FIFO read to its end as the ledger verifier reads one
    (open_ledger_input: `<(command)` works, bounded in size, and a pipe that gives no byte and no end of file for `idle`
    seconds is InputIdle; only the wait for a byte is bounded, not the whole read: a writer that keeps giving bytes is
    read up to `limit`, however slowly). A device or a directory is InputNotRegular. All are OSError."""
    fd, piped = open_ledger_input(path, limit, idle)
    if piped is not None:
        return piped
    with os.fdopen(fd, "rb") as f:
        data = read_bounded(f, limit)
    if len(data) > limit:
        raise InputTooLarge(f"{path}: larger than {limit} bytes")
    return data


def read_input_text(path: str, limit: int = MAX_INPUT_BYTES, idle: float = FIFO_IDLE_SECONDS) -> str:
    """read_input decoded as open(path, encoding="utf-8") decodes it (strict UTF-8, universal newlines)"""
    import io
    return io.TextIOWrapper(io.BytesIO(read_input(path, limit, idle)), encoding="utf-8").read()


def input_too_large(path: str) -> bool:
    try:
        return os.path.getsize(path) > MAX_INPUT_BYTES
    except OSError:
        return False


_DEPTH_OUT = re.compile(r'["\[\]{}]')
_DEPTH_IN = re.compile(r'["\\]')


def json_nesting_depth(text: str) -> int:
    """Maximum bracket nesting of a JSON text, by a LINEAR scan (no recursion, no parsing):
    brackets inside strings are ignored, escapes honoured. Used to refuse pathological nesting
    deterministically BEFORE the recursive stdlib decoder can hit the interpreter's stack."""
    depth = max_depth = 0
    i = 0
    while True:                                  # jumps to the next character that matters (same result as a char loop)
        m = _DEPTH_OUT.search(text, i)
        if m is None:
            break
        ch, i = m.group(), m.end()
        if ch == '"':
            while True:
                m = _DEPTH_IN.search(text, i)
                if m is None:
                    return max_depth             # unterminated string: nothing after it counts
                i = m.end()
                if m.group() == '"':
                    break
                i += 1                           # a backslash escapes the next character, whatever it is
        elif ch in "[{":
            depth += 1
            if depth > max_depth:
                max_depth = depth
        else:
            depth -= 1
    return max_depth


class JsonTooDeep(ValueError):
    pass


class JsonTooDeepToRead(JsonTooDeep, RecursionError):
    """A JSON text nested deeper than MAX_JSON_DEPTH, refused before the parser (SPEC §30). Both a ValueError and a
    RecursionError: each reader keeps the answer it gave when Python's parser ran out of stack, now at one depth on
    every Python (a bare json.loads gives up at 995 levels under 3.9 and 3.11, 9 999 under 3.13, 65 168 under 3.14)."""


def json_loads_bounded(s, **kw):
    """json.loads, with an integer of more than MAX_INT_DIGITS digits refused (ValueError) and nesting deeper than MAX_JSON_DEPTH refused first by a linear scan (JsonTooDeepToRead). Bytes
    are decoded first, as json.loads decodes them (UTF-8, UTF-16 or UTF-32, by json.detect_encoding): the scan reads
    characters. Scanned as bytes, a UTF-16 text hid its brackets behind a code unit with the byte 0x22 or 0x5C (U+2201):
    1 100 levels were read under Python 3.13 and a RecursionError under 3.9."""
    if isinstance(s, (bytes, bytearray)):
        s = s.decode(json.detect_encoding(s), "surrogatepass")
    if isinstance(s, str) and json_nesting_depth(s) > MAX_JSON_DEPTH:
        raise JsonTooDeepToRead(f"JSON nested deeper than {MAX_JSON_DEPTH} levels")
    kw.setdefault("parse_int", _portable_int)
    return json.loads(s, **kw)


# A raw surrogate code point in the decoded text can only come from bytes that are not UTF-8 (the file is read with
# errors="surrogateescape", which maps each such byte to U+DC80..U+DCFF): valid UTF-8 never decodes to one. SPEC §1/§3:
# a ledger is UTF-8 and MUST NOT contain non-UTF-8 bytes — refused, never hashed as the code point the decoder made up
# (NEMESIS 12/10/2026: a 0xFF inside a value, self_hash computed over \udcff, was PASS here and FAIL in the five others).
_RAW_SURROGATE = re.compile("[\ud800-\udfff]")


def has_lone_surrogate(text: str) -> bool:
    """True if a `\\uD800-\\uDFFF` escape in the JSON text is not part of a proper high+low pair.
    Linear scan honouring backslash escapes (a `\\\\uD800` is literal text, not an escape). A lone surrogate is
    not a Unicode scalar value, cannot be UTF-8 encoded, and the stdlib decoders of the three reference
    languages disagree on it (Python/JS keep it, Go's replaces it with U+FFFD): the profile refuses it
    (council 14/09/2026, spec/CONFORMANCE.md)."""
    i, n = 0, len(text)
    while i < n:
        i = text.find("\\", i)                  # only escapes matter: jump to the next backslash
        if i < 0:
            break
        if i + 1 < n and text[i + 1] == "u" and i + 5 < n:
            try:
                cp = int(text[i + 2:i + 6], 16)
            except ValueError:
                i += 2                           # malformed escape: not this rule's business, the decoder refuses it
                continue
            if 0xD800 <= cp <= 0xDBFF:           # high: needs an immediate low
                if text[i + 6:i + 8] != "\\u":
                    return True
                try:
                    lo = int(text[i + 8:i + 12], 16)
                except ValueError:
                    return True                  # a high surrogate followed by a broken escape is still unpaired
                if not (0xDC00 <= lo <= 0xDFFF):
                    return True
                i += 12
                continue
            if 0xDC00 <= cp <= 0xDFFF:           # low without a preceding high
                return True
            i += 6
            continue
        i += 2                                   # any other escape (\\\\, \\", \\n, ...)
    return False


def _loads_strict(text):
    d = json_nesting_depth(text)
    if d > MAX_JSON_DEPTH:
        raise JsonTooDeep(f"json_too_deep: nesting {d} exceeds the acceptance-profile bound {MAX_JSON_DEPTH}")
    if _RAW_SURROGATE.search(text):
        raise ValueError("not_utf8: the line holds bytes that are not UTF-8 (SPEC §3)")
    if has_lone_surrogate(text):
        raise ValueError("lone_surrogate: unpaired UTF-16 surrogate escape is outside the acceptance profile")
    with _RecursionHeadroom():
        return json.loads(text, object_pairs_hook=_reject_dup, parse_float=_no_float, parse_int=_bounded_int,
                          parse_constant=lambda c: (_ for _ in ()).throw(ValueError(f"JSON constant {c}")))

def canonical_payload(entry: Dict) -> bytes:
    """Stringa canonica dell'entry per ricomputare self_hash. Esclude self_hash E le attestazioni
    aggiunte DOPO (signature/signer): il self_hash impegna il CONTENUTO, la firma impegna il self_hash.
    Così un ledger firmato supera comunque la verifica di hash stdlib-only, senza toccare le firme."""
    # attestation fields (outside the content hash): classical and, since 0.12.0, the ML-DSA-65 companion; since 0.20.2
    # tsa_token too (SPEC §2: an RFC 3161 token over self_hash cannot sit inside the bytes self_hash is computed from)
    d = {k: v for k, v in entry.items() if k not in ("self_hash", "signature", "signer", "signature_pq", "signer_pq", "tsa_token")}
    return json.dumps(d, sort_keys=True, separators=(",", ":")).encode()


def hash_with(algo: str, payload: bytes) -> str:
    if algo == "sha256":
        return hashlib.sha256(payload).hexdigest()
    if algo == "sha3_256":
        return hashlib.sha3_256(payload).hexdigest()
    raise ValueError(f"unsupported_algo:{algo}")


def detect_algo(entries: List[Dict]) -> Optional[str]:
    """Auto-detect: prova entrambi gli algoritmi sulla prima entry."""
    if not entries:
        return None
    e0 = entries[0]
    if "self_hash" not in e0:
        return None
    payload = canonical_payload(e0)
    for algo in SUPPORTED_ALGOS:
        if hash_with(algo, payload) == e0["self_hash"]:
            return algo
    return None


_LEDGER_ID_RE = re.compile(r"[0-9a-f]{64}\Z")


def check_ledger_id_arg(expect_ledger_id: Optional[str]) -> None:
    """SPEC v0.9 §17 rule 1: an expected ledger identity is 64 lowercase hex characters (the form of every self_hash) or
    None (not given). Anything else can match no ledger: the caller's error, refused before the file is judged."""
    if expect_ledger_id is not None and not (isinstance(expect_ledger_id, str) and _LEDGER_ID_RE.match(expect_ledger_id)):
        raise ValueError("expect_ledger_id: 64 lowercase hex characters, the self_hash of entry 0 "
                         f"(got {expect_ledger_id!r:.80})")


def verify_ledger(path: str, algo: Optional[str] = None, tip: Optional[str] = None,
                  trusted_pubkey_hex: Optional[str] = None, require_tip: bool = False,
                  tip_not_before: Optional[str] = None, expect_ledger_id: Optional[str] = None,
                  trusted_pq_pubkey_b64: Optional[str] = None) -> Dict:
    """Verifica integrità del ledger. Restituisce receipt JSON-serializable.

    `tip`: path of a signed chain tip (cryptovalid_tip.py); None = use `<path>.tip.json` when it exists. With a
    tip the tail limit moves: truncation, suffix rewrite and unsealed appends become named FAILs (the chain
    alone cannot see them). `require_tip`: a missing tip is a FAIL. `trusted_pubkey_hex`: the log key the
    relying party trusts; given, it makes the tip required (SPEC §22 rule 1); without it a tip is not checked.
    The recursion headroom covers the whole verification (the entries decoded at the bound are hashed again), and the
    caller's recursion limit is back when this returns (15/11/2026).
    `expect_ledger_id` (SPEC v0.9 §17): compared with the self_hash of entry 0 with or without a tip (until 0.25.0 only
    inside the tip check: without a tip another ledger was PASS); a value that is not 64 lowercase hex is a ValueError.
    `tip_not_before` makes the tip required (§17 rule 2)."""
    check_ledger_id_arg(expect_ledger_id)
    with _RecursionHeadroom():
        return _verify_ledger(path, algo, tip, trusted_pubkey_hex, require_tip, tip_not_before, expect_ledger_id,
                              trusted_pq_pubkey_b64)


def _verify_ledger_data(path: str, data: bytes) -> Dict:
    """verify_ledger(path) for a file that held `data`, bytes the caller has already read once (the evidence pack, SPEC
    v0.13 §21 rule 7): the file is not opened again; `path` names it in the receipt and locates its tip, as there."""
    with _RecursionHeadroom():
        return _verify_ledger(path, None, None, None, False, None, None, None, _data=data)


def _verify_ledger(path, algo, tip, trusted_pubkey_hex, require_tip, tip_not_before, expect_ledger_id,
                   trusted_pq_pubkey_b64, _data: Optional[bytes] = None) -> Dict:
    started = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    errors: List[Dict] = []

    try:
        # SPEC §5 step 0 (v0.11): opened once without blocking, judged on the descriptor (a FIFO hung until 0.26.0);
        # v0.12: a FIFO is read to its end, bounded in size and in idle time (`<(cat ledger)`, the six verifiers since 0.20.2)
        # v0.13 §21 rule 7: bytes already read by the caller (_verify_ledger_data) are not read again
        fd, piped = (None, _data) if _data is not None else open_ledger_input(path, MAX_INPUT_BYTES)   # the module value at call time
    except InputIdle:
        return {"verdict": "FAIL", "path": path, "verified_utc": started, "entries_count": 0,
                "parse_errors": [{"line": -1, "error": f"unreadable: FIFO idle for {FIFO_IDLE_SECONDS} s"}]}
    except InputTooLarge:
        # fail-closed on size too: reading it would exhaust memory and die without a receipt (council 13/09)
        return {"verdict": "FAIL", "path": path, "verified_utc": started, "entries_count": 0,
                "parse_errors": [{"line": -1, "error": f"input_too_large: file exceeds {MAX_INPUT_BYTES} bytes"}]}
    except InputNotRegular:
        return {"verdict": "FAIL", "path": path, "verified_utc": started, "entries_count": 0,
                "parse_errors": [{"line": -1, "error": "unreadable: not a regular file"}]}
    except FileNotFoundError:
        return {"verdict": "FILE_NOT_FOUND", "path": path, "verified_utc": started}
    except OSError as e:   # a permission error: a receipt, never a traceback
        return {"verdict": "FAIL", "path": path, "verified_utc": started, "entries_count": 0,
                "parse_errors": [{"line": -1, "error": f"unreadable: {type(e).__name__}"}]}
    try:
        # ONE line rule in the five verifiers (council 16/09 r5): lines are separated by LF only (no universal
        # newlines: a lone CR is data inside the line, hence a decode error), and a line is blank when it holds
        # nothing but ASCII space / tab / CR — never Unicode whitespace (str.strip() took U+00A0).
        import io
        # the layers open() builds on a descriptor, or the bytes of the pipe: one wrapper, closed here with what it wraps
        with io.TextIOWrapper(io.BufferedReader(io.FileIO(fd)) if piped is None else io.BytesIO(piped),
                              encoding="utf-8", errors="surrogateescape", newline="\n") as f:
            n = tokens = 0
            raw_lines = []
            for ln in f:   # SPEC §22 rule 9: lines and tokens are counted before any line is parsed
                n += 1
                if n > MAX_INPUT_LINES:   # lines come first: the reason is known, the rest is not read (200 MiB of blank lines took 64 s)
                    break
                tokens += ln.count("{") + ln.count("[") + ln.count(",") + ln.count(":")
                if ln.strip(" \t\r\n"):
                    raw_lines.append(ln)
    except FileNotFoundError:
        return {
            "verdict": "FILE_NOT_FOUND",
            "path": path,
            "verified_utc": started,
        }
    except OSError as e:   # a directory, a permission error: a receipt, never a traceback
        return {"verdict": "FAIL", "path": path, "verified_utc": started, "entries_count": 0,
                "parse_errors": [{"line": -1, "error": f"unreadable: {type(e).__name__}"}]}

    too_much = input_too_complex(n, tokens)
    if too_much:   # nothing parsed: the reason alone, as input_too_large of the bytes
        return {"verdict": "FAIL", "path": path, "verified_utc": started, "entries_count": 0,
                "parse_errors": [{"line": -1, "error": too_much}]}
    entries: List[Dict] = []
    for i, line in enumerate(raw_lines):
        try:
            obj = _loads_strict(line)
            if not isinstance(obj, dict):
                # a line that is JSON but not an object ([], 1, "x", null): named, like JS/Java/Rust — never a crash
                # further down (audit V1 #3, 30/09/2026: AttributeError/TypeError tracebacks, no receipt)
                errors.append({"line": i, "error": "not_a_json_object"})
                continue
            entries.append(obj)
        except JsonTooDeep as e:
            # Nesting beyond the NORMATIVE bound (MAX_JSON_DEPTH, measured by a linear scan, never by
            # recursion): a FAIL with a named error, never a crash (2026-09-13).
            errors.append({"line": i, "error": str(e)})
        except (json.JSONDecodeError, ValueError) as e:
            errors.append({"line": i, "error": f"json_decode:{e}"})
        except RecursionError as e:
            # Belt-and-braces: the pre-scan already refused > MAX_JSON_DEPTH, so reaching here means the
            # host process had less stack than the bound assumes (deep caller). Named, not disguised.
            errors.append({"line": i, "error": f"recursion_error: {str(e)[:120]}"})

    # No `idx` → the profile, like every other entry (0.20.0, closed by construction): the reference no longer takes a
    # native-schema fallback for ledgers whose first three entries lack idx (0.19.0 declared it: §2.1 and §5 step 4 were
    # not applied there, an unknown key passed). Such a ledger is FAIL, idx_mismatch named, as in the five other verifiers.
    if algo is None:
        algo = detect_algo(entries) or "sha256"

    # SPEC §2.1 (2026-10-10): the entry is a CLOSED object — a top-level key outside the core + optional fields is a named
    # FAIL, never a silent pass (measured: entries written with an extra key, hash recomputed over it, were PASS)
    schema_failures: List[Dict] = []
    for i, e in enumerate(entries):
        unknown = sorted(k for k in e if k not in ENTRY_KEYS)
        if unknown:
            schema_failures.append({"idx": e.get("idx", i), "reason": "unknown_field:" + ",".join(unknown)[:120]})

    # Re-hash check
    hash_recomputed = 0
    hash_failures: List[Dict] = []
    for i, e in enumerate(entries):
        expected = e.get("self_hash")
        if expected is None:
            hash_failures.append({"idx": e.get("idx", i), "reason": "missing_self_hash"})
            continue
        computed = hash_with(algo, canonical_payload(e))
        if computed == expected:
            hash_recomputed += 1
        else:
            hash_failures.append(
                {
                    "idx": e.get("idx", i),
                    "reason": "hash_mismatch",
                    "expected": expected,
                    "computed": computed,
                }
            )

    # Chain linkage check
    link_ok = 0
    link_failures: List[Dict] = []
    for i, e in enumerate(entries):
        expected_prev = entries[i - 1].get("self_hash") if i > 0 else GENESIS_PREV
        actual_prev = e.get("prev_hash")
        if actual_prev == expected_prev:
            link_ok += 1
        else:
            link_failures.append(
                {
                    "idx": e.get("idx", i),
                    "expected_prev": expected_prev,
                    "actual_prev": actual_prev,
                }
            )

    # Idx monotonicity
    idx_ok = True
    for i, e in enumerate(entries):
        idx = e.get("idx")
        if isinstance(idx, bool) or idx != i:   # True == 1 in Python: a boolean idx is NOT sequential (r5)
            idx_ok = False
            errors.append({"line": i, "error": f"idx_mismatch: expected {i}, got " + (json.dumps(idx, ensure_ascii=False, separators=(",", ":")) if "idx" in e else "(missing)")})   # 0.20.0: absent ≠ null ≠ "1"

    # Timestamp monotonicity: REPORTED, not enforced. A backwards `ts` does not break the hash chain
    # (the chain proves order of *appending*, not wall-clock time), but an auditor must see it.
    ts_ok, ts_backwards = True, []
    for i in range(1, len(entries)):
        a, b = entries[i - 1].get("ts"), entries[i].get("ts")
        if isinstance(a, str) and isinstance(b, str) and b < a:
            ts_ok = False
            ts_backwards.append({"idx": entries[i].get("idx", i), "prev_ts": a, "ts": b})

    chain_integrity = len(hash_failures) == 0 and len(link_failures) == 0 and idx_ok and len(errors) == 0 and len(schema_failures) == 0   # SPEC §2.1
    # A ledger with ZERO entries has no chain to verify: "PASS" on nothing was a false green (found
    # by the 2026-09-11 red-team pass: truncation to zero entries verified as PASS — in all four
    # verifiers of this family). The spec vocabulary is PASS/FAIL, so it is a FAIL with a named error.
    if not entries:
        chain_integrity = False
        errors.append({"line": 0, "error": "empty_ledger: zero entries, nothing to verify"})

    # SPEC v0.9 §17 rule 1 (16/11/2026): the ledger identity is entry 0's self_hash, readable without a tip, so the expected
    # identity is compared here, in every branch (until 0.25.0 only inside the tip check: no tip, or a tip without a trusted
    # key, and another ledger was PASS, exit 0, the option not named; reported by Athena on 16/11/2026)
    ledger_id_matched = False
    if expect_ledger_id is not None:
        first_id = entries[0].get("self_hash") if entries else None
        ledger_id_matched = first_id == expect_ledger_id
        if not ledger_id_matched:
            chain_integrity = False
            # first: parse_errors keeps 10 lines, and with 10 earlier errors the reason was not in the receipt (NEMESIS 16/11/2026)
            errors.insert(0, {"line": 0, "error": "ledger_id_mismatch: entry 0's self_hash is not the ledger id you expect "
                                                  "(--expect-ledger-id)" + ("" if entries else "; the file has no entry")})

    # Signed chain tip (15/09/2026): the only way a SNAPSHOT verifier can see tail truncation / suffix rewrite.
    tip_check: Optional[Dict] = None
    tip_file = tip if tip is not None else (path + ".tip.json" if os.path.exists(path + ".tip.json") else None)
    if tip_not_before is not None:
        # SPEC v0.9 §17 rule 2: the oldest acceptable tip is a requirement on a tip, which it makes required (until 0.25.0
        # it was read only inside the tip check: without a tip, PASS)
        require_tip = True
    if trusted_pubkey_hex:
        # SPEC v0.14 §22 rule 1: the trusted log key is a requirement on a tip, as the oldest tip and the trusted
        # post-quantum key are (until 0.27.0 it was used only when a tip happened to be there: without one, PASS)
        require_tip = True
    if trusted_pq_pubkey_b64:
        # a trusted post-quantum key is a REQUIREMENT: it implies a required tip, and it is meaningless without the
        # trusted log key (council 15/09: PQ key alone → tip never checked → PASS, a fail-open)
        require_tip = True
        if not trusted_pubkey_hex:
            chain_integrity = False
            errors.append({"line": len(entries), "error": "pq_key_without_log_key: --trusted-pq-pubkey needs --trusted-pubkey "
                                                            "(the post-quantum layer sits on top of the Ed25519 tip, never instead of it)"})
    if tip_file is not None and not trusted_pubkey_hex:
        # a tip is there but no trusted log key: it is NOT checked (the key inside the tip proves nothing), and
        # the verdict is the bare chain's — with require_tip that is a FAIL (council 15/09: no fail-open)
        tip_check = {"ok": False, "checked": False, "tip_path": tip_file, "pq_protected": None,   # not read: unknown
                     "error": "tip_untrusted: a signed tip is present but no trusted log key was given (--trusted-pubkey); "
                              "the tail limit applies in full"}
        if require_tip:
            chain_integrity = False
            errors.append({"line": len(entries), "error": tip_check["error"]})
    elif tip_file is not None:
        try:
            import cryptovalid_tip as _tip
            last = entries[-1].get("self_hash", "") if entries else _tip.GENESIS
            first = entries[0].get("self_hash", "") if entries else _tip.GENESIS
            tip_check = _tip.check_tip(len(entries), last if isinstance(last, str) else "", _tip.load_tip(tip_file),
                                       trusted_pubkey_hex, tip_not_before,
                                       first_self_hash=first if isinstance(first, str) else "",
                                       expect_ledger_id=expect_ledger_id,
                                       trusted_pq_pubkey_b64=trusted_pq_pubkey_b64)
        except (OSError, ValueError, ImportError) as e:   # SPEC §22 rule 2, rows 1-3: load_tip's ValueError carries the text
            tip_check = {"ok": False, "error": (str(e) if str(e).startswith("tip_unreadable:")
                                                else f"tip_unreadable: {type(e).__name__}: {os_error_text(e)[:120]}"),
                         "pq_protected": False}
        tip_check["tip_path"] = tip_file
        tip_check["checked"] = True
        if not tip_check["ok"]:
            chain_integrity = False
            errors.append({"line": len(entries), "error": tip_check["error"]})
    elif require_tip:
        chain_integrity = False
        errors.append({"line": len(entries), "error": "tip_missing: a signed chain tip is required and none was found"})

    receipt: Dict = {
        "verified_utc": started,
        "verifier": "OMEGA core.verify_ledger v1.0 (stdlib-only)",
        "path": path,
        "algorithm_used": algo,
        "algorithm_supported": list(SUPPORTED_ALGOS),
        "entries_count": len(entries),
        "hash_recomputed_ok": hash_recomputed,
        "hash_recomputed_total": len(entries),
        "hash_recompute_passed": len(hash_failures) == 0,
        "hash_failures": hash_failures[:10],  # cap
        "link_ok": link_ok,
        "link_total": len(entries),
        "link_passed": len(link_failures) == 0,
        "link_failures": link_failures[:10],
        "idx_monotonic": idx_ok,
        "ts_monotonic": ts_ok,
        "ts_backwards": ts_backwards[:10],
        "parse_errors": errors[:10],
        "schema_failures": schema_failures[:10],   # SPEC §2.1 (2026-10-10): top-level entry keys outside the closed schema
        "chain_integrity": chain_integrity,
        "tip": tip_check,   # None = no signed tip checked (the tail limit below applies in full)
        "verdict": "PASS" if chain_integrity else "FAIL",
        # What this verdict does and does not prove. A bare hash chain is internally consistent
        # evidence: anyone with write access to the file can truncate it or rewrite a suffix and
        # re-chain it, and this verifier will not see that. Those attacks are caught one layer up —
        # a signed evidence pack commits to entry count + head hash (evidence_pack.py) and RFC 3161 /
        # public anchors commit to time. Stated here so that "PASS" is never read as more than it is.
        "scope": {
            "proves": ["every self_hash recomputes from its entry (canonical JSON)",
                       "every prev_hash links to the previous self_hash (genesis = 64 zeros)",
                       "idx is contiguous from 0"] + (
                          ["entry 0's self_hash is the ledger id you expect (--expect-ledger-id)"]
                          if ledger_id_matched else []),
            "does_not_prove": (["no truncation / suffix rewrite by a party holding the LOG KEY (key custody is "
                                "the limit: HSM/KMS, copies of the tip outside the writer's reach)",
                                "no ROLLBACK to an older signed state (truncation + an older genuine tip restored): "
                                "pass --tip-not-before, or compare with the monitor state / receipts / an anchor",
                                ] + ([] if expect_ledger_id is not None else [
                                "not that this is the ledger YOU expect when the log key signs several ledgers: pass "
                                "--expect-ledger-id (self_hash of entry 0)"])
                               if tip_check and tip_check.get("ok") else
                               ["no truncation (a shorter prefix is a valid chain)",
                                "no suffix rewrite by a party with write access (re-chained fork)"]) + [
                               "authorship (use signer.py / a signed evidence pack)",
                               "wall-clock time (ts is reported, not attested: use RFC 3161 / anchors)"],
            "to_cover_those": ("a signed chain tip (cryptovalid_tip.py, --tip/--require-tip) turns truncation, "
                               "suffix rewrite and unsealed appends into named FAILs; evidence_pack.py verify <pack> "
                               "(signed manifest: entry count + head); receipts / monitor for time-ordered proof"),
        },
    }

    # SPEC v0.12 §5 "Failure classes" (18/11/2026): on a ledger written in another schema the real breaks of the chain
    # came out mixed with one unknown_field and one idx_mismatch per entry (measured on a third-party ledger of 179
    # entries: 4 true link breaks among 20 listed reasons). A FAIL receipt now counts every finding, uncapped, by class;
    # only a FAIL, so the receipt of a PASS ledger is the one of 0.26.0
    if not chain_integrity:
        idx_n = sum(1 for x in errors if str(x.get("error", "")).startswith("idx_mismatch:"))
        receipt["failure_classes"] = {
            "chain": {"link_mismatch": sum(1 for i, e in enumerate(entries) if "prev_hash" in e and e["prev_hash"] != (
                          entries[i - 1].get("self_hash") if i > 0 else GENESIS_PREV)),
                      "hash_mismatch": sum(1 for x in hash_failures if x.get("reason") == "hash_mismatch")},
            "format": {"unknown_field": len(schema_failures), "idx_mismatch": idx_n,
                       "missing_self_hash": sum(1 for x in hash_failures if x.get("reason") == "missing_self_hash"),
                       "missing_prev_hash": sum(1 for e in entries if "prev_hash" not in e)},
            "other": len(errors) - idx_n,
        }

    # 0.21.0 (SPEC v0.4 §5 step 5): this verifier does not check signatures; when the ledger carries a signature layer it
    # says how many entries carry one (only then, so the receipt of a ledger without signatures is the one of 0.20.3)
    signed_n = sum(1 for e in entries if isinstance(e, dict) and any(k in e for k in ("signature", "signer", "signature_pq", "signer_pq")))
    if signed_n:
        receipt["signatures_not_checked"] = signed_n

    # Receipt-of-receipt: hash del receipt stesso (deterministico, escluso verified_utc)
    receipt_canonical = {k: v for k, v in receipt.items() if k != "verified_utc"}
    receipt_payload = json.dumps(
        receipt_canonical, sort_keys=True, separators=(",", ":"), default=str
    ).encode()
    receipt["receipt_sha256"] = hashlib.sha256(receipt_payload).hexdigest()
    receipt["receipt_sha3_256"] = hashlib.sha3_256(receipt_payload).hexdigest()
    return receipt


DIST_NAME = "cryptovalid-opencore"


def package_version() -> str:
    """The version these modules belong to, for `--version` (15/11/2026). From a source checkout (a pyproject.toml of
    this distribution next to this file) the version written there, said as such: an installed copy of another version
    must not answer for the files that actually run. Otherwise the installed distribution's metadata; "unknown" when
    neither exists (a module copied on its own)."""
    here = os.path.dirname(os.path.abspath(__file__))
    try:
        with open(os.path.join(here, "pyproject.toml"), encoding="utf-8") as f:
            text = f.read()
    except OSError:
        text = ""
    if re.search(r'^name\s*=\s*"%s"\s*$' % re.escape(DIST_NAME), text, re.M):
        m = re.search(r'^version\s*=\s*"([^"\n]+)"\s*$', text, re.M)
        if m:
            return f"{m.group(1)} (source checkout, from pyproject.toml)"
    try:
        from importlib.metadata import PackageNotFoundError, version
        try:
            return version(DIST_NAME)
        except PackageNotFoundError:
            pass
    except ImportError:  # pragma: no cover — importlib.metadata exists from Python 3.8
        pass
    return "unknown (neither a source checkout nor an installed distribution)"


class _Once(argparse.Action):
    """A value option given twice is a usage error, exit 2: argparse keeps the last value, so the first expectation would
    be accepted and left out (SPEC v0.9 §17; NEMESIS 16/11/2026: `--expect-ledger-id <B> --expect-ledger-id <A>` was
    PASS against A in the four verifiers)."""

    def __call__(self, parser, namespace, values, option_string=None):
        if getattr(namespace, self.dest, None) is not None:
            parser.error(f"{option_string} given twice (a second value would silently replace the first)")
        setattr(namespace, self.dest, values)


class VersionAction(argparse.Action):
    """`--version`: "<prog> <package_version()>" on STDOUT, written whole or exit 74 (argparse's own action prints
    through _print_message, which the Parser above sends to stderr)."""

    def __init__(self, option_strings, dest=argparse.SUPPRESS, default=argparse.SUPPRESS, help=None):
        super().__init__(option_strings=option_strings, dest=dest, default=default, nargs=0,
                         help=help or "print the version of this distribution and exit")

    def __call__(self, parser, namespace, values, option_string=None):
        try:
            write_all(f"{parser.prog} {package_version()}\n")
        except ReceiptNotWritten as e:
            raise SystemExit(receipt_lost(str(e)))
        raise SystemExit(0)


@receipt_cli
def main(argv: Optional[List[str]] = None) -> int:
    parser = Parser(allow_abbrev=False, 
        prog="verifier.py",
        description="Independent verification of an OMEGA .jsonl ledger (auditor-grade, stdlib-only).",
    )
    parser.add_argument("ledger_path", help="path of the .jsonl file to verify")
    parser.add_argument("--version", action=VersionAction)
    parser.add_argument(
        "--algo", choices=SUPPORTED_ALGOS, default=None, action=_Once, help="force the hash algorithm (default: the one that matches the first entry, sha256 if neither does)"
    )
    parser.add_argument(
        "--quiet", action="store_true", help="print only the verdict (PASS/FAIL, and the exit code)"
    )
    parser.add_argument("--out", default=None, help="also write the JSON receipt to this file")
    parser.add_argument("--tip", default=None, action=_Once, help="signed chain tip to check (default: <ledger>.tip.json if present)")
    parser.add_argument("--trusted-pubkey", default=None, action=_Once, help="log key (hex) the tip must be signed with; makes the tip required (SPEC §22 rule 1)")
    parser.add_argument("--trusted-pq-pubkey", default=None, action=_Once,
                        help="ML-DSA-65 log key (base64) a hybrid tip must ALSO be signed with (FAIL if missing/invalid)")
    parser.add_argument("--require-tip", action="store_true", help="FAIL when no signed tip is available")
    parser.add_argument("--tip-not-before", default=None, action=_Once, help="refuse a tip dated before this ISO-8601 instant (rollback)")
    parser.add_argument("--expect-ledger-id", default=None, action=_Once, help="the chain identity (self_hash of entry 0) you expect: refuses another ledger's pair")
    args = parser.parse_args(argv)
    for flag in ("algo", "pubkey", "tip", "trusted_pubkey", "trusted_pq_pubkey", "tip_not_before", "expect_ledger_id"):
        v = getattr(args, flag, None)
        if v is not None and (v == "" or v.startswith("-")):   # "" or a flag as a value would silently mean "not given" (21/09/2026: one grammar in the four)
            parser.error(f"--{flag.replace('_', '-')} needs a value (got {v!r})")
    try:
        check_ledger_id_arg(args.expect_ledger_id)   # SPEC v0.9 §17: a value that can match no ledger is a usage error
    except ValueError:
        parser.error(f"--expect-ledger-id needs 64 lowercase hex characters, the self_hash of entry 0 (got {args.expect_ledger_id!r})")

    try:
        receipt = verify_ledger(args.ledger_path, algo=args.algo, tip=args.tip,
                                trusted_pubkey_hex=args.trusted_pubkey, require_tip=args.require_tip,
                                tip_not_before=args.tip_not_before, expect_ledger_id=args.expect_ledger_id,
                                trusted_pq_pubkey_b64=args.trusted_pq_pubkey)
    except RecursionError as e:  # last-resort fail-closed: a receipt, never a traceback (2026-09-13).
        # Not labelled json_too_deep on purpose: here the cause is unknown (council review 13/09 —
        # a recursion bug in the verifier itself must not be disguised as a malformed input).
        receipt = {"verdict": "FAIL", "path": args.ledger_path,
                   "verified_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                   "parse_errors": [{"line": -1, "error": f"recursion_error: {str(e)[:120]}"}]}

    # 0.20.3: a receipt that is not written whole (the --out file or stdout) is exit 74, whatever the verdict; both are
    # attempted, and the code is decided after the flush
    failed = []
    if args.out:
        why = write_file(args.out, json.dumps(receipt, indent=2, default=str))
        if why is not None:
            failed.append(why)
    why = write_stdout(receipt["verdict"] if args.quiet else json.dumps(receipt, indent=2, default=str))
    if why is not None:
        failed.append(why)
    if failed:
        return receipt_not_written("; ".join(failed))
    return 0 if receipt.get("verdict") == "PASS" else 1


if __name__ == "__main__":  # pragma: no cover - entrypoint CLI (main() è coperto direttamente)
    sys.exit(main())
