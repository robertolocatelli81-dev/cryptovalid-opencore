#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Roberto Locatelli
"""0.29.0: the same bytes get the same verdict on Linux, macOS and Windows.

Each case names what differs on a system and the equivalent the code uses there; where a case can only run on one
system it is measured by the CI job `other-os` (macos-latest, windows-latest) and skipped elsewhere with the reason."""
import os
import shutil
import subprocess
import sys
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)

def cnf_path(path: str) -> str:
    """`path` as a value of an OpenSSL configuration file: there a backslash escapes the next character, `$` expands a
    variable, `#` starts a comment and quotes are removed, so a Windows path (C:\\Users\\...) or a directory named
    with one of them was read as another path (50 openssl failures in the CI of f1e95d5). Each is escaped."""
    return "".join("\\" + c if c in "\\$#\"'" else c for c in path)

def assert_private(tc, path, mode=0o600):
    """A key (0600) or a WORM object (0400) is the owner's alone. POSIX: the mode. Windows, where a mode only sets the
    read-only attribute: one access entry, the user running the test, full control, nothing inherited (icacls), and
    the read-only attribute exactly when `mode` has no write bit."""
    import stat
    if os.name != "nt":
        tc.assertEqual(stat.S_IMODE(os.stat(path).st_mode), mode, path)
        return
    import re
    sysdir = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32")
    out = subprocess.run([os.path.join(sysdir, "icacls.exe"), path], capture_output=True).stdout.decode("utf-8", "replace")
    who = subprocess.run([os.path.join(sysdir, "whoami.exe")], capture_output=True).stdout.decode("utf-8", "replace").strip()
    aces = [x.strip() for x in out.replace(path, "", 1).splitlines() if re.search(r":\(", x)]
    tc.assertEqual(len(aces), 1, out)
    name, _, rights = aces[0].partition(":")
    tc.assertEqual(name.lower(), who.lower(), out)
    tc.assertEqual(rights, "(F)", out)
    readonly = bool(os.stat(path).st_file_attributes & stat.FILE_ATTRIBUTE_READONLY)
    tc.assertEqual(readonly, not mode & 0o200, path)


# Windows: CreateProcess looks for "bash" in System32 before PATH, and System32\\bash.exe is the launcher of the Windows
# Subsystem for Linux ("has no installed distributions", CI of f1e95d5); shutil.which reads PATH: Git's bash there
BASH = shutil.which("bash") or "bash"


def full_sink(tc=None):
    """A path whose writes fail with ENOSPC: Linux's /dev/full; on macOS and Windows, which have no such device, an
    empty file on a full volume named by CV_FULL_DIR (the other-os job makes one: hdiutil, diskpart). Skipped with
    the reason where neither exists."""
    if os.path.exists("/dev/full") and sys.platform.startswith("linux"):
        return "/dev/full"
    d = os.environ.get("CV_FULL_DIR")
    if d and os.path.isfile(os.path.join(d, "sink")):
        return os.path.join(d, "sink")
    raise unittest.SkipTest("no full device here: Linux has /dev/full; elsewhere set CV_FULL_DIR to a full volume with an empty "
                "file `sink` (the other-os job makes one)")


def pipe_capacity(fd):
    """How many bytes a pipe holds before a writer waits. Linux: F_GETPIPE_SZ (1032, the read end will do). macOS has
    no such fcntl (1032 there is another operation: EBADF, CI of f1e95d5): measured on a fresh pipe filled by 64 KiB
    writes, the size the writers use (macOS grows a pipe to 64 KiB under large writes)."""
    if sys.platform.startswith("linux"):
        import fcntl
        return fcntl.fcntl(fd, 1032)
    return _measured_pipe_capacity()


def _measured_pipe_capacity():
    r, w = os.pipe()
    try:
        set_nonblocking(w)
        n = 0
        try:
            while True:
                n += os.write(w, b"\0" * 65536)
        except BlockingIOError:
            return n
    finally:
        os.close(r)
        os.close(w)


def fifo(tc, path):
    """A pipe a reader is given by name, to be refused without waiting: a FIFO at `path` on POSIX; on Windows, which
    has no FIFO in a directory, its equivalent, a named pipe \\\\.\\pipe\\cv-<random> with 64 listening instances (each
    reader that opens it takes one; it is a pipe to fstat: S_IFIFO). Returns the name to give the reader."""
    if hasattr(os, "mkfifo"):
        os.mkfifo(path)
        return path
    import _winapi
    import secrets
    name = r"\\.\pipe\cv-" + secrets.token_hex(8)
    for _ in range(64):
        h = _winapi.CreateNamedPipe(name, _winapi.PIPE_ACCESS_DUPLEX, 0,   # 0: PIPE_TYPE_BYTE | PIPE_WAIT (_winapi has no names)
                                    _winapi.PIPE_UNLIMITED_INSTANCES, 65536, 65536, 0, _winapi.NULL)
        tc.addCleanup(_winapi.CloseHandle, h)
    return name


def fifo_at(tc, path):
    """A FIFO at a given name inside a directory (a pack member): POSIX only; Windows has named pipes only under
    \\\\.\\pipe\\, so no pipe can stand at that name there (skipped with this reason)."""
    if not hasattr(os, "mkfifo"):
        tc.skipTest("a FIFO at a name inside a directory: Windows has named pipes only under \\\\.\\pipe\\")
    os.mkfifo(path)
    return path


# the device a reader must refuse at once: Linux and macOS /dev/zero, Windows NUL (\\.\NUL, a character device)
DEVICE = r"\\.\NUL" if os.name == "nt" else "/dev/zero"


def set_nonblocking(fd):
    """O_NONBLOCK on POSIX; on Windows PIPE_NOWAIT, which os.set_blocking sets on a pipe since Python 3.12"""
    os.set_blocking(fd, False)


NONBLOCKING_PIPES = os.name != "nt" or sys.version_info >= (3, 12)
NEEDS_NONBLOCKING_PIPES = unittest.skipUnless(NONBLOCKING_PIPES, "a non-blocking pipe on Windows needs Python 3.12 "
                                              "(os.set_blocking on a pipe)")


def pipe_bytes(r):
    """bytes waiting in a pipe: FIONREAD on POSIX, PeekNamedPipe (TotalBytesAvail) on Windows"""
    if os.name == "nt":
        import ctypes
        import msvcrt
        from ctypes import wintypes
        n = wintypes.DWORD(0)
        peek = ctypes.WinDLL("kernel32", use_last_error=True).PeekNamedPipe
        peek.argtypes = (wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD, ctypes.c_void_p, ctypes.POINTER(wintypes.DWORD),
                         ctypes.c_void_p)
        peek.restype = wintypes.BOOL
        if not peek(msvcrt.get_osfhandle(r), None, 0, None, ctypes.byref(n), None):
            raise ctypes.WinError(ctypes.get_last_error())
        return n.value
    import array
    import fcntl
    import termios
    n = array.array("i", [0])
    fcntl.ioctl(r, termios.FIONREAD, n, True)
    return n[0]


def cpu_seconds(p):
    """user + system CPU seconds of the running child `p` (a Popen): /proc on Linux, ps on macOS, GetProcessTimes on
    Windows"""
    if os.name == "nt":
        import ctypes
        from ctypes import wintypes
        t = [wintypes.FILETIME() for _ in range(4)]
        k = ctypes.WinDLL("kernel32", use_last_error=True)
        k.GetProcessTimes.argtypes = (wintypes.HANDLE,) + (ctypes.POINTER(wintypes.FILETIME),) * 4
        if not k.GetProcessTimes(int(p._handle), *[ctypes.byref(x) for x in t]):
            raise ctypes.WinError(ctypes.get_last_error())
        return sum((x.dwHighDateTime << 32 | x.dwLowDateTime) for x in t[2:]) / 1e7
    if os.path.exists(f"/proc/{p.pid}/stat"):
        with open(f"/proc/{p.pid}/stat", encoding="utf-8") as f:
            fields = f.read().rsplit(")", 1)[1].split()
        return (int(fields[11]) + int(fields[12])) / os.sysconf("SC_CLK_TCK")
    t = subprocess.run(["ps", "-o", "time=", "-p", str(p.pid)], capture_output=True).stdout.decode().strip()
    parts = [float(x) for x in t.replace("-", ":").split(":")]
    return sum(v * m for v, m in zip(reversed(parts), (1, 60, 3600, 86400)))


def run_with_memory_limit(argv, limit, timeout=120):
    """Run `argv` (stdin from the null device, stdout and stderr captured as UTF-8) with its memory bounded by `limit`
    bytes; returns (returncode, stdout, stderr, peak bytes or None). Linux: RLIMIT_DATA. Windows, which has neither fork
    nor setrlimit: a Job Object with JOB_OBJECT_LIMIT_PROCESS_MEMORY, the child started suspended and put in the job
    before its first instruction (a venv's python.exe is a redirector that starts the base interpreter as its child:
    the job covers both), peak = the job's PeakProcessMemoryUsed (the way of agent-payment-chain b37f230, same author).
    macOS, which neither sets nor enforces RLIMIT_DATA: no limit, peak = the children's ru_maxrss."""
    if sys.platform.startswith("linux") or sys.platform == "darwin":
        import resource
        cap = (lambda: resource.setrlimit(resource.RLIMIT_DATA, (limit, limit))) if sys.platform.startswith("linux") else None
        cp = subprocess.run(argv, capture_output=True, stdin=subprocess.DEVNULL, timeout=timeout, preexec_fn=cap)
        peak = None if cap else resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss   # bytes on macOS
        return cp.returncode, cp.stdout.decode("utf-8"), cp.stderr.decode("utf-8", "replace"), peak
    import ctypes
    import tempfile
    from ctypes import wintypes

    class BASIC(ctypes.Structure):
        _fields_ = [("PerProcessUserTimeLimit", ctypes.c_int64), ("PerJobUserTimeLimit", ctypes.c_int64),
                    ("LimitFlags", wintypes.DWORD), ("MinimumWorkingSetSize", ctypes.c_size_t),
                    ("MaximumWorkingSetSize", ctypes.c_size_t), ("ActiveProcessLimit", wintypes.DWORD),
                    ("Affinity", ctypes.c_size_t), ("PriorityClass", wintypes.DWORD), ("SchedulingClass", wintypes.DWORD)]

    class IO(ctypes.Structure):
        _fields_ = [(n, ctypes.c_uint64) for n in ("Read", "Write", "Other", "ReadT", "WriteT", "OtherT")]

    class EXTENDED(ctypes.Structure):   # JOBOBJECT_EXTENDED_LIMIT_INFORMATION, class 9
        _fields_ = [("Basic", BASIC), ("Io", IO), ("ProcessMemoryLimit", ctypes.c_size_t),
                    ("JobMemoryLimit", ctypes.c_size_t), ("PeakProcessMemoryUsed", ctypes.c_size_t),
                    ("PeakJobMemoryUsed", ctypes.c_size_t)]

    class THREADENTRY32(ctypes.Structure):
        _fields_ = [("dwSize", wintypes.DWORD), ("cntUsage", wintypes.DWORD), ("th32ThreadID", wintypes.DWORD),
                    ("th32OwnerProcessID", wintypes.DWORD), ("tpBasePri", wintypes.LONG), ("tpDeltaPri", wintypes.LONG),
                    ("dwFlags", wintypes.DWORD)]
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    for f in ("CreateJobObjectW", "CreateToolhelp32Snapshot", "OpenThread"):
        getattr(k32, f).restype = wintypes.HANDLE
    k32.ResumeThread.restype = wintypes.DWORD

    def check(ok, what):
        if not ok:
            raise OSError(ctypes.get_last_error(), what + " failed")
        return ok
    job = wintypes.HANDLE(check(k32.CreateJobObjectW(None, None), "CreateJobObjectW"))
    try:
        ext = EXTENDED()
        ext.Basic.LimitFlags = 0x100 | 0x2000   # JOB_OBJECT_LIMIT_PROCESS_MEMORY | _KILL_ON_JOB_CLOSE (no breakaway)
        ext.ProcessMemoryLimit = limit
        check(k32.SetInformationJobObject(job, 9, ctypes.byref(ext), ctypes.sizeof(ext)), "SetInformationJobObject")
        with tempfile.TemporaryFile() as fo, tempfile.TemporaryFile() as fe:
            p = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=fo, stderr=fe, creationflags=0x4)   # SUSPENDED
            try:
                check(k32.AssignProcessToJobObject(job, wintypes.HANDLE(int(p._handle))), "AssignProcessToJobObject")
                snap = wintypes.HANDLE(check(k32.CreateToolhelp32Snapshot(0x4, 0), "CreateToolhelp32Snapshot"))
                resumed = 0
                try:
                    te = THREADENTRY32()
                    te.dwSize = ctypes.sizeof(te)
                    more = k32.Thread32First(snap, ctypes.byref(te))
                    while more:
                        if te.th32OwnerProcessID == p.pid:
                            th = wintypes.HANDLE(check(k32.OpenThread(0x2, False, te.th32ThreadID), "OpenThread"))
                            try:
                                check(k32.ResumeThread(th) != 0xFFFFFFFF, "ResumeThread")
                                resumed += 1
                            finally:
                                k32.CloseHandle(th)
                        more = k32.Thread32Next(snap, ctypes.byref(te))
                finally:
                    k32.CloseHandle(snap)
                check(resumed, "resuming the child")
                p.wait(timeout=timeout)
            except BaseException:
                k32.TerminateJobObject(job, 1)
                p.wait()
                raise
            check(k32.QueryInformationJobObject(job, 9, ctypes.byref(ext), ctypes.sizeof(ext), None), "peak memory")
            fo.seek(0)
            fe.seek(0)
            return p.returncode, fo.read().decode("utf-8"), fe.read().decode("utf-8", "replace"), ext.PeakProcessMemoryUsed
    finally:
        k32.CloseHandle(job)


def _windows_dacl(path, sddl):
    import ctypes
    from ctypes import wintypes
    adv = ctypes.WinDLL("advapi32", use_last_error=True)
    conv = adv.ConvertStringSecurityDescriptorToSecurityDescriptorW
    conv.argtypes = (wintypes.LPCWSTR, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p)
    setsec = adv.SetFileSecurityW
    setsec.argtypes = (wintypes.LPCWSTR, wintypes.DWORD, ctypes.c_void_p)
    sd = ctypes.c_void_p()
    if not conv(sddl, 1, ctypes.byref(sd), None):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        if not setsec(path, 0x4 | 0x80000000, sd):   # DACL | PROTECTED_DACL_SECURITY_INFORMATION
            raise ctypes.WinError(ctypes.get_last_error())
    finally:
        ctypes.WinDLL("kernel32").LocalFree(sd)


def make_unreadable(tc, path):
    """`path` (a file or a directory) that this user cannot read: mode 0 on POSIX (skipped as root, who reads
    anything); on Windows an empty protected access list (no one may read; the owner may still change the list, which
    the cleanup does). Restored at cleanup."""
    if os.name == "nt":
        import re
        sysdir = os.path.join(os.environ.get("SystemRoot", r"C:\\Windows"), "System32")
        who = subprocess.run([os.path.join(sysdir, "whoami.exe"), "/user", "/fo", "csv", "/nh"], capture_output=True)
        sid = re.findall(rb'"(S-1-[0-9-]+)"', who.stdout)[0].decode("ascii")
        # every entry below too: Windows lets anyone with "bypass traverse checking" (everyone) open an entry of a
        # directory it may not list, so an unreadable directory alone was read through its MANIFEST.json (run
        # 45377477990); on POSIX a directory without x keeps its entries out of reach
        targets = [path] + ([os.path.join(r, n) for r, ds, fs in os.walk(path) for n in ds + fs]
                            if os.path.isdir(path) else [])
        for t in reversed(targets):
            _windows_dacl(t, "D:P")
        restore = lambda: [_windows_dacl(t, "D:P(A;OICI;FA;;;%s)" % sid) for t in targets]   # noqa: E731
    else:
        if hasattr(os, "geteuid") and os.geteuid() == 0:
            tc.skipTest("root reads any file")
        mode = os.stat(path).st_mode & 0o777
        os.chmod(path, 0)
        restore = lambda: os.chmod(path, mode or 0o700)   # noqa: E731

    def cleanup():   # a tearDown may already have removed it
        if os.path.lexists(path):
            restore()
    tc.addCleanup(cleanup)


def make_private(path):
    """mode 0600 on POSIX; on Windows the access list of a key (verifier.owner_only)"""
    if os.name == "nt":
        import verifier
        verifier.owner_only(path)
    else:
        os.chmod(path, 0o600)


_FAKE_SITE = r'''
import os, sys
if os.path.basename(sys.executable).lower() == "openssl.exe" and os.environ.get("CV_FAKE_OPENSSL"):
    sys.argv = list(sys.orig_argv[1:])   # the arguments openssl was given (sys.argv is not set yet here)
    code = 0
    try:
        exec(os.environ["CV_FAKE_OPENSSL"])
    except SystemExit as e:
        code = e.code if isinstance(e.code, int) else 1
    sys.stdout.flush()
    sys.stderr.flush()
    os._exit(code)
'''


def fake_openssl(tc, bindir, sh_body, py_body):
    """An `openssl` that the code finds first on PATH and that behaves as the test wants: on POSIX a shell script
    (`sh_body`); on Windows, where a script cannot stand in for openssl.exe, the venv launcher of this Python copied as
    bindir\\openssl.exe with a pyvenv.cfg beside it: it starts this Python, and a sitecustomize runs `py_body` with
    openssl's arguments (CV_REAL_OPENSSL names the real one). `py_body` None: a file named openssl.exe that is not a
    program (it cannot be started, as a script with a missing interpreter). Returns the variables to add to the
    environment (PATH with bindir first)."""
    import sysconfig
    real = shutil.which("openssl") or "openssl"
    os.makedirs(bindir, exist_ok=True)
    env = {"PATH": bindir + os.pathsep + os.environ.get("PATH", ""), "CV_REAL_OPENSSL": real}
    if os.name != "nt":
        p = os.path.join(bindir, "openssl")
        with open(p, "w", encoding="utf-8", newline="") as f:
            f.write(sh_body)
        os.chmod(p, 0o755)
        return env
    exe = os.path.join(bindir, "openssl.exe")
    if py_body is not None and sys.version_info < (3, 10):
        tc.skipTest("the Windows fake openssl reads sys.orig_argv, new in Python 3.10")
    if py_body is None:
        with open(exe, "wb") as f:
            f.write(b"not a program\r\n")
        return env
    import venv
    nt = os.path.join(os.path.dirname(venv.__file__), "scripts", "nt")
    launcher = next((os.path.join(nt, n) for n in ("venvlauncher.exe", "python.exe") if os.path.isfile(os.path.join(nt, n))),
                    None)
    if launcher is None:
        tc.skipTest("this Python has no venv launcher to stand in for openssl.exe")
    shutil.copy(launcher, exe)
    base = os.path.dirname(getattr(sys, "_base_executable", sys.executable))
    with open(os.path.join(bindir, "pyvenv.cfg"), "w", encoding="utf-8", newline="") as f:
        f.write("home = %s\ninclude-system-site-packages = true\nversion = %s\n" % (base, sysconfig.get_python_version()))
    site = os.path.join(bindir, "site")
    os.makedirs(site, exist_ok=True)
    with open(os.path.join(site, "sitecustomize.py"), "w", encoding="utf-8", newline="") as f:
        f.write(_FAKE_SITE)
    env.update(PYTHONPATH=site, CV_FAKE_OPENSSL=py_body)
    return env



def _git(*args):
    return subprocess.run(["git", "-C", _HERE] + list(args), capture_output=True)




class CheckoutBytes(unittest.TestCase):
    """Git for Windows installs with core.autocrlf=true: without .gitattributes every text file was checked out with
    CRLF and each pinned digest (RFC text, vectors, notes, ledgers, the DCO) differed from the repository's bytes."""

    def test_gitattributes_turns_conversion_off(self):
        with open(os.path.join(_HERE, ".gitattributes"), "rb") as f:
            lines = [x.strip() for x in f.read().split(b"\n")]
        self.assertIn(b"* -text", lines)

    def test_every_tracked_file_is_checked_out_as_stored(self):
        """the end-of-line state in the working tree is the one in the index, for every tracked file (git ls-files
        --eol); a clone with core.autocrlf=true and no .gitattributes fails this (780 files w/crlf, 24/11/2026)"""
        if shutil.which("git") is None or _git("rev-parse", "--is-inside-work-tree").stdout.strip() != b"true":
            self.skipTest("not a git checkout (an sdist or a wheel has the bytes as packed)")
        r = _git("ls-files", "--eol", "-z")
        self.assertEqual(r.returncode, 0, r.stderr)
        differ = []
        for rec in r.stdout.split(b"\0"):
            if not rec:
                continue
            meta, _, name = rec.partition(b"\t")
            i, w = meta.split()[:2]
            if w != b"w/" and i[2:] != w[2:]:   # w/ (empty): not in the working tree (a sparse or deleted path)
                differ.append((name, i, w))
        self.assertEqual(differ, [])


class DirectoryFsync(unittest.TestCase):
    """Windows cannot open a directory as a file: os.open(dir) is PermissionError (86 errors in the CI of f1e95d5, every
    Ingestor). There the rename is made with MoveFileExW(MOVEFILE_WRITE_THROUGH) and the directory is not fsynced."""

    def test_no_directory_open_where_the_system_refuses_it(self):
        import tempfile
        from unittest import mock
        import cryptovalid_ingest as I
        real_open = os.open

        def windows_open(path, flags, *a):
            if os.path.isdir(path):
                raise PermissionError(13, "Permission denied", path)
            return real_open(path, flags, *a)
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d)
        with mock.patch.object(os, "open", windows_open):
            with self.assertRaises(PermissionError):   # control: this is what Windows answers
                os.open(d, os.O_RDONLY)
            with mock.patch.object(os, "name", "nt"):
                I._fsync_dir(d)

    def test_the_rename_replaces_and_leaves_no_temporary(self):
        import tempfile
        import verifier as V
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d)
        p = os.path.join(d, "out.json")
        for data in (b"first", b"second, longer"):
            V.write_output(p, data)
            with open(p, "rb") as f:
                self.assertEqual(f.read(), data)
        self.assertEqual(os.listdir(d), ["out.json"])

    @unittest.skipUnless(os.name == "nt", "MoveFileExW is a Windows call: measured by the other-os job on windows-latest")
    def test_movefileexw_names_the_windows_error(self):
        import tempfile
        import verifier as V
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d)
        with self.assertRaises(OSError) as c:
            V._replace(os.path.join(d, "absent"), os.path.join(d, "x"))
        self.assertEqual(c.exception.winerror, 2)   # ERROR_FILE_NOT_FOUND
        self.assertIsInstance(c.exception, FileNotFoundError)


class ReceiptBytes(unittest.TestCase):
    """Windows gives a pipe or a file the ANSI code page and os.linesep "\\r\\n": a receipt with a reason outside
    cp1252 was exit 74 there (the MCP server ended on a method named U+1F600, 298 failures) and `--quiet` wrote
    b"PASS\\r\\n". The bytes are now UTF-8 with "\\n" on every system, unless PYTHONIOENCODING chooses another."""

    def _emit(self, text, env=None):
        import io
        from unittest import mock
        import verifier as V
        raw = io.BytesIO()
        out = io.TextIOWrapper(raw, encoding="cp1252", errors="strict", newline="\n")
        with mock.patch.object(os, "name", "nt"), mock.patch.object(os, "linesep", "\r\n"), \
                mock.patch.dict(os.environ, env or {}), mock.patch.object(sys, "stdout", out):
            if not env:
                os.environ.pop("PYTHONIOENCODING", None)
            V.write_all(text)
        return raw.getvalue()

    def test_windows_stdout_is_utf8_with_line_feeds(self):
        text = 'idx_mismatch: expected 1, got "\u00e9" \u200b \U0001f600\nPASS\n'
        self.assertEqual(self._emit(text), text.encode("utf-8"))

    def test_windows_stderr_is_utf8_too(self):
        import io
        from unittest import mock
        import verifier as V
        raw = io.BytesIO()
        err = io.TextIOWrapper(raw, encoding="cp1252", errors="backslashreplace", newline="\n")
        with mock.patch.object(os, "name", "nt"), mock.patch.dict(os.environ), mock.patch.object(sys, "stderr", err):
            os.environ.pop("PYTHONIOENCODING", None)
            V.say("check not run here: SPEC \u00a723 \U0001f600\n")
        self.assertEqual(raw.getvalue(), "check not run here: SPEC \u00a723 \U0001f600\n".encode("utf-8"))

    def test_an_encoding_the_user_chose_is_kept(self):
        import verifier as V
        with self.assertRaises(V.ReceiptNotWritten):   # cp1252 chosen on purpose: the receipt cannot be written whole
            self._emit("\U0001f600\n", {"PYTHONIOENCODING": "cp1252"})
        self.assertEqual(self._emit("\u00e9\n", {"PYTHONIOENCODING": "cp1252"}), b"\xe9\n")


class OpensslConfigPaths(unittest.TestCase):
    """The TSA labs of the tests write paths into OpenSSL configuration files; on Windows each path has backslashes."""

    @unittest.skipUnless(shutil.which("openssl"), "needs the openssl command")
    def test_a_lab_in_a_directory_with_every_special_character(self):
        import tempfile
        from test_tsa_revocation_20261116 import Lab
        prefix = "s$x#y'" if os.name == "nt" else "b\\s$x#y'q\"z"   # Windows: its own separators are the backslashes
        d = tempfile.mkdtemp(prefix=prefix)
        self.addCleanup(shutil.rmtree, d)
        lab = Lab(d)
        self.assertTrue(lab.token().startswith(b"\x30"))
        lab.revoke("keyCompromise")
        with open(lab.crl(), "rb") as f:
            self.assertIn(b"BEGIN X509 CRL", f.read())


def _text_calls_without_encoding(path):
    """open() in text mode without encoding= (or, writing, without newline=), and a call with text=True or
    universal_newlines=True without encoding=: on Windows each reads or writes in the ANSI code page, a write
    turns "\\n" into "\\r\\n", and a child's UTF-8 output undecodable there was an IndexError (CPython reads a
    pipe in a thread on Windows; a decoding error leaves the result empty)"""
    import ast
    with open(path, encoding="utf-8") as f:
        tree = ast.parse(f.read())
    bad = []
    for n in ast.walk(tree):
        if not isinstance(n, ast.Call):
            continue
        kws = {k.arg: k.value for k in n.keywords}
        if None in kws:
            continue
        if isinstance(n.func, ast.Name) and n.func.id == "open":
            m = n.args[1] if len(n.args) >= 2 else kws.get("mode")
            mode = "r" if m is None else (m.value if isinstance(m, ast.Constant) and isinstance(m.value, str) else None)
            if mode is None or "b" in mode:
                continue
            if "encoding" not in kws or (any(c in mode for c in "wax") and "newline" not in kws):
                bad.append((os.path.basename(path), n.lineno, "open"))
        for k in ("text", "universal_newlines"):
            v = kws.get(k)
            if isinstance(v, ast.Constant) and v.value is True and "encoding" not in kws:
                bad.append((os.path.basename(path), n.lineno, k))
    return bad


class TextModeEverywhere(unittest.TestCase):
    """Closed by construction: every Python file of the repository names the encoding of its text I/O."""

    def test_no_text_call_without_an_encoding(self):
        files = []
        for root, dirs, names in os.walk(_HERE):
            dirs[:] = [d for d in dirs if not d.startswith(".") and d not in ("__pycache__", "node_modules", "target")]
            files += [os.path.join(root, n) for n in names if n.endswith(".py")]
        self.assertGreater(len(files), 150)
        bad = [b for p in files for b in _text_calls_without_encoding(p)]
        self.assertEqual(bad, [])

    def test_the_check_finds_each_form(self):
        import tempfile
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d)
        p = os.path.join(d, "x.py")
        with open(p, "w", encoding="utf-8", newline="") as f:
            f.write('open(a)\nopen(a, "w", encoding="utf-8")\nopen(a, "rb")\nopen(a, "a", encoding="utf-8", newline="")\n'
                    'run(c, text=True)\nrun(c, universal_newlines=True, encoding="utf-8")\nPopen(c, text=True)\n')
        self.assertEqual(_text_calls_without_encoding(p), [("x.py", 1, "open"), ("x.py", 2, "open"), ("x.py", 5, "text"),
                                                           ("x.py", 7, "text")])


class PrivateFiles(unittest.TestCase):
    """Keys (0600) and WORM objects (0400): Windows has no POSIX mode (st_mode read 0o666 after keygen, CI of f1e95d5);
    its equivalent is the access control list, restricted before the first byte is written."""

    def test_write_new_restricts_before_the_first_byte_on_windows(self):
        import tempfile
        from unittest import mock
        import verifier as V
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d)
        events = []
        real_write = V._write_fd
        with mock.patch.object(os, "name", "nt"), \
                mock.patch.object(V, "owner_only", lambda p: events.append(("acl", os.path.basename(p)))), \
                mock.patch.object(V, "_write_fd", lambda fd, raw: (events.append(("write",)), real_write(fd, raw))), \
                mock.patch.object(os, "chmod", lambda p, m: events.append(("chmod", os.path.basename(p), m))):
            V.write_new(os.path.join(d, "k.key"), "seed", mode=0o600)
            V.write_new(os.path.join(d, "obj"), b"blob", mode=0o400)
            V.write_new(os.path.join(d, "r.json"), "{}", mode=0o644)   # not private: no access list change
        self.assertEqual([e[0] for e in events], ["acl", "write", "acl", "write", "chmod", "write"])
        self.assertTrue(events[0][1].startswith("k.key.") and events[2][1].startswith("obj."))
        self.assertEqual(events[4], ("chmod", "obj", 0o400))   # read-only once the temporary name is gone
        self.assertEqual(sorted(os.listdir(d)), ["k.key", "obj", "r.json"])

    def test_a_replaced_file_keeps_its_access_list_on_windows(self):
        """the mode of a file write_output or copy_output replaces is kept; on Windows its access list is (run
        45356889667: a private receipt replaced by the rename got the folder's list)"""
        import tempfile
        from unittest import mock
        import verifier as V
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d)
        p, src = os.path.join(d, "r.json"), os.path.join(d, "src")
        for q in (p, src):
            with open(q, "wb") as f:
                f.write(b"old")
        copied = []
        with mock.patch.object(os, "name", "nt"), mock.patch.object(V, "_replace", os.replace), \
                mock.patch.object(V, "_copy_dacl", lambda a, b: copied.append((a, os.path.basename(b)))):
            V.write_output(p, "{}")
            V.copy_output(src, p)
        self.assertEqual([a for a, _ in copied], [os.path.realpath(p)] * 2)
        self.assertTrue(all(b.startswith("r.json.") and b.endswith(".tmp") for _, b in copied), copied)

    def test_a_key_and_a_worm_object_are_private(self):
        import tempfile
        import verifier as V
        d = tempfile.mkdtemp()
        self.addCleanup(lambda: (os.name == "nt" and [os.chmod(os.path.join(d, n), 0o600) for n in os.listdir(d)],
                                 shutil.rmtree(d)))
        V.write_new(os.path.join(d, "k.key"), "seed", mode=0o600)
        V.write_new(os.path.join(d, "obj"), b"blob", mode=0o400)
        assert_private(self, os.path.join(d, "k.key"), 0o600)
        assert_private(self, os.path.join(d, "obj"), 0o400)
        self.assertEqual(sorted(os.listdir(d)), ["k.key", "obj"])   # no temporary name left


class FileLock(unittest.TestCase):
    """The witness state and the SCITT ledger are locked between processes: flock on POSIX, a byte-range lock on
    Windows (until 0.29.0 no lock at all there: fcntl does not exist)."""

    def test_a_second_process_waits_for_the_lock(self):
        import tempfile
        import time
        import verifier as V
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d)
        lock, flag = os.path.join(d, "s.lock"), os.path.join(d, "held")
        child = ("import os, sys, time; sys.path.insert(0, sys.argv[1]); import verifier as V\n"
                 "with V.file_lock(sys.argv[2]):\n    open(sys.argv[3], 'wb').close(); time.sleep(2)\n")
        p = subprocess.Popen([sys.executable, "-c", child, _HERE, lock, flag])
        self.addCleanup(p.wait)
        t0 = time.monotonic()
        while not os.path.exists(flag):
            self.assertLess(time.monotonic() - t0, 60, "the child never took the lock")
            time.sleep(0.02)
        t1 = time.monotonic()
        with V.file_lock(lock):
            waited = time.monotonic() - t1
        self.assertGreater(waited, 1.0)   # the child held it for 2 s from just before the flag
        self.assertEqual(p.wait(timeout=60), 0)
        t2 = time.monotonic()
        with V.file_lock(lock):           # control: free, taken at once
            self.assertLess(time.monotonic() - t2, 1.0)


class ErrorTexts(unittest.TestCase):
    """Windows' API texts differ from the C library's ("The system cannot find the file specified" for ENOENT), so a
    reason that carried e.strerror or str(e) depended on the system (test_auto_closed on windows-latest)."""

    WIN = FileNotFoundError(2, "The system cannot find the file specified", "C:\\x\\nope.jsonl")

    def test_the_c_library_text_on_every_system(self):
        import verifier as V
        self.assertEqual(V.os_reason(self.WIN), os.strerror(2))
        self.assertEqual(V.os_error_text(self.WIN), "[Errno 2] %s: 'C:\\\\x\\\\nope.jsonl'" % os.strerror(2))
        self.assertEqual(V.os_error_text(ValueError("tip_unreadable: x")), "tip_unreadable: x")   # not an OSError: as is
        self.assertEqual(V.os_error_text(OSError("short write")), "short write")                   # no errno: as is

    def test_verify_auto_names_the_missing_path_as_everywhere(self):
        from unittest import mock
        import verify_evidence as VE

        def windows_stat(path, *a, **k):
            raise ErrorTexts.WIN
        with mock.patch.object(os, "stat", windows_stat):
            r = VE.verify_auto("C:\\x\\nope.jsonl")
        self.assertIn("cannot read the path (FileNotFoundError: %s);" % os.strerror(2), r["layers"][0]["detail"])


class OneNestingBound(unittest.TestCase):
    """Python's JSON parser recurses once per level and its limit moved with the version (measured 24/11/2026: a
    RecursionError from 1 100 levels under 3.9 and 3.11, 20 000 under 3.13, 100 000 under 3.14), so a reader that
    relied on it answered a text 5 000 deep one way on 3.9 and another on 3.13. SPEC §30: past 512 every reader
    refuses before parsing, the same answer at every depth and on every Python."""

    DEPTHS = (513, 1100, 5000, 30000)

    @staticmethod
    def _deep(d):
        return '{"a":' * (d - 1) + '[1]' + '}' * (d - 1)   # d levels: d - 1 objects and one array

    def test_the_depth_scan_counts_levels(self):
        import verifier as V
        self.assertEqual(V.json_nesting_depth(self._deep(513)), 513)
        V.json_loads_bounded(self._deep(512))   # control: the bound itself is read
        with self.assertRaises(RecursionError):
            V.json_loads_bounded(self._deep(513))
        with self.assertRaises(ValueError):
            V.json_loads_bounded(self._deep(513).encode())

    def _same_everywhere(self, outcome):
        got = {d: outcome(self._deep(d)) for d in self.DEPTHS}
        self.assertEqual(len(set(got.values())), 1, got)
        return got[513]

    def test_readers_answer_alike_at_every_depth(self):
        import tempfile
        import cryptovalid_ingest as I
        import verify_evidence as VE
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d)

        def at(text, name="x.json"):
            p = os.path.join(d, name)
            with open(p, "w", encoding="utf-8", newline="") as f:
                f.write(text)
            return p

        def auto(text):
            try:
                VE._json_value(text, "the file")
                return "read"
            except VE._NotRecognised as e:
                return str(e)

        def profile(text):
            try:
                VE.load_profile(at(text, "p.json"))
                return "read"
            except VE.ProfileError as e:
                return str(e)
        self.assertIn("deeper", self._same_everywhere(auto))
        self.assertIn("deeper", self._same_everywhere(profile))
        self.assertIsNotNone(self._same_everywhere(lambda t: I._load_json_object(at(t))[1]))

    def test_the_mcp_server_answers_alike_at_every_depth(self):
        out = []
        for depth in self.DEPTHS:
            line = '{"jsonrpc":"2.0","id":1,"method":"ping","params":' + self._deep(depth) + "}\n"
            p = subprocess.run([sys.executable, os.path.join(_HERE, "cryptovalid_mcp.py")], input=line.encode(),
                               capture_output=True, timeout=120)
            out.append(p.stdout)
        self.assertEqual(len(set(out)), 1, out)
        self.assertIn(b"-32700", out[0])

    def test_no_reader_calls_the_parser_directly(self):
        """closed by construction: json.loads / json.load appear only inside verifier's two bounded readers"""
        import ast
        bad = []
        for root, dirs, names in os.walk(_HERE):
            dirs[:] = [x for x in dirs if not x.startswith(".") and x not in ("__pycache__", "node_modules", "target",
                                                                              "verifiers", "tools", "bench", "spec",
                                                                              "examples")]
            for n in names:
                if not n.endswith(".py") or n.startswith("test_") or root != _HERE and "cryptovalid" not in root:
                    continue
                p = os.path.join(root, n)
                with open(p, encoding="utf-8") as f:
                    tree = ast.parse(f.read())
                funcs = {}
                for fn in ast.walk(tree):
                    if isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        for c in ast.walk(fn):
                            funcs.setdefault(id(c), fn.name)
                for c in ast.walk(tree):
                    if isinstance(c, ast.Call) and isinstance(c.func, ast.Attribute) and c.func.attr in ("loads", "load") \
                            and isinstance(c.func.value, ast.Name) and c.func.value.id == "json":
                        where = funcs.get(id(c))
                        if not (n == "verifier.py" and where in ("_loads_strict", "json_loads_bounded")):
                            bad.append((n, c.lineno, where))
        self.assertEqual(bad, [])


class PipeCapacity(unittest.TestCase):
    @unittest.skipUnless(sys.platform.startswith("linux"), "the control needs F_GETPIPE_SZ (Linux)")
    def test_the_measure_agrees_with_the_kernel(self):
        """control of the macOS branch: on Linux the measure equals F_GETPIPE_SZ of a fresh pipe"""
        import fcntl
        r, w = os.pipe()
        try:
            self.assertEqual(_measured_pipe_capacity(), fcntl.fcntl(r, 1032))
        finally:
            os.close(r)
            os.close(w)


class ManifestNamesOnWindows(unittest.TestCase):
    """Python 3.13 no longer calls a rooted name absolute on Windows ("/etc/hostname"), so a MANIFEST.json naming it
    passed the name check there and was read as D:\\etc\\hostname (test_evidence_pack on windows-latest: no named
    refusal). Each Windows form that leaves the pack is refused by name."""

    def test_windows_forms_are_refused(self):
        import ntpath
        from unittest import mock
        import evidence_pack as E
        with mock.patch.object(os, "path", ntpath), mock.patch.object(os, "sep", "\\"), \
                mock.patch.object(os, "altsep", "/"), mock.patch.object(os, "name", "nt"):
            for bad in ("/etc/hostname", "\\etc\\hostname", "C:x.jsonl", "C:\\x.jsonl", "\\\\host\\share\\x",
                        "a.jsonl:stream", "..\\x", "a/../../x", "dir\\signed.jsonl"):
                self.assertFalse(E._manifest_name_inside(bad), bad)
            for good in ("signed.jsonl", "dir/signed.jsonl"):
                self.assertTrue(E._manifest_name_inside(good), good)
        # SPEC §31: the same answers on this system, whatever it is
        for bad in ("/etc/hostname", "\\etc\\hostname", "C:x.jsonl", "a.jsonl:stream", "a\\..\\b.jsonl", "a/../b"):
            self.assertFalse(E._manifest_name_inside(bad), bad)
        for good in ("signed.jsonl", "dir/signed.jsonl"):
            self.assertTrue(E._manifest_name_inside(good), good)


class NonBlockingStdoutOnWindows(unittest.TestCase):
    """A full non-blocking stdout was waited for with select, which Windows has for sockets only ("stdout is
    non-blocking and cannot be waited for", exit 74). There the wait asks the pipe (NtQueryInformationFile)."""

    def test_the_windows_wait_is_used_there(self):
        import io
        from unittest import mock
        import verifier as V
        calls = []
        r, w = os.pipe()
        self.addCleanup(os.close, r)
        self.addCleanup(os.close, w)
        with mock.patch.object(os, "name", "nt"), mock.patch.object(V, "_wait_pipe_writable_windows", calls.append):
            V._wait_writable(io.FileIO(w, "wb", closefd=False))
        self.assertEqual(calls, [w])

    @unittest.skipUnless(os.name == "nt" and NONBLOCKING_PIPES, "the Windows pipe API: measured by the other-os job")
    def test_a_full_pipe_is_waited_for_then_written(self):
        import threading
        import time
        import verifier as V
        r, w = os.pipe()
        set_nonblocking(w)
        n = 0
        try:
            while True:
                n += os.write(w, b"x" * 4096)
        except BlockingIOError:
            pass
        threading.Thread(target=lambda: (time.sleep(1), os.read(r, 1 << 16)), daemon=True).start()
        t0 = time.monotonic()
        while True:   # as _write_stdout does: wait, write again
            V._wait_pipe_writable_windows(w)
            try:
                self.assertGreater(os.write(w, b"y"), 0)
                break
            except BlockingIOError:
                self.assertLess(time.monotonic() - t0, 30, "the reader drained the pipe after 1 s")
        self.assertGreater(time.monotonic() - t0, 0.5)   # it waited for the reader
        os.close(w)
        os.close(r)


class MemoryLimit(unittest.TestCase):
    """RLIMIT_DATA on Linux, a Job Object on Windows (until 0.29.0 the 256 MiB case was skipped there: no fork)"""

    @unittest.skipIf(sys.platform == "darwin", "macOS neither sets nor enforces a data limit: its peak is measured")
    def test_an_allocation_past_the_limit_fails_and_one_under_it_does_not(self):
        code = "import sys; b = bytearray(int(sys.argv[1])); print(len(b))"
        rc, out, err, _ = run_with_memory_limit([sys.executable, "-c", code, str(512 << 20)], 256 << 20)
        self.assertNotEqual(rc, 0)
        self.assertIn("MemoryError", err)
        rc, out, err, peak = run_with_memory_limit([sys.executable, "-c", code, str(64 << 20)], 256 << 20)   # control
        self.assertEqual((rc, out.strip()), (0, str(64 << 20)), err)
        if peak is not None:   # Windows: the job's own measure covers the allocation
            self.assertGreater(peak, 64 << 20)


class FingerprintOnWindows(unittest.TestCase):
    """SPEC §23 rule 3: an in-place rewrite with mtime set back moves ctime on POSIX; on Windows st_ctime is the
    creation time, so the fingerprint did not change (test_checks_profile on windows-latest). There ChangeTime is
    read from the file."""

    def test_the_change_time_enters_the_fingerprint_there(self):
        import tempfile
        from unittest import mock
        import verify_evidence as VE
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d)
        p = os.path.join(d, "l.jsonl")
        with open(p, "wb") as f:
            f.write(b"{}\n")
        ticks = iter(range(100, 200))
        with mock.patch.object(os, "name", "nt"), \
                mock.patch.object(VE, "_windows_change_time", lambda fd: next(ticks), create=True):
            self.assertNotEqual(VE.evidence_fingerprint(p), VE.evidence_fingerprint(p))   # the change time moved


class CrashedOpenssl(unittest.TestCase):
    """SPEC §10: openssl that crashed did not answer (a check not run here). POSIX: a signal, a negative exit. Windows
    has no signals: a crash is an NTSTATUS error as the exit code (0xC0000005), read until 0.29.0 as an answer."""

    def test_a_crash_is_known_on_each_system(self):
        from unittest import mock
        import cryptovalid_tsa as T
        self.assertTrue(T._crashed(-11))
        self.assertFalse(T._crashed(1) or T._crashed(127))
        with mock.patch.object(os, "name", "nt"):
            self.assertTrue(T._crashed(0xC0000005) and T._crashed(0xC0000409))
            self.assertFalse(T._crashed(1))
        with mock.patch.object(os, "name", "posix"):
            self.assertFalse(T._crashed(0xC0000005))   # on POSIX an exit code is at most 255
        self.assertEqual(T._crash_text(0xC0000005), "ended by exception 0xC0000005")

    def test_the_pack_check_says_not_run(self):
        import subprocess as sp
        from unittest import mock
        import cryptovalid_tsa as T
        import evidence_pack as E
        import verifier as V
        crash = sp.CompletedProcess(["openssl"], 0xC0000005, "", "")
        with mock.patch.object(os, "name", "nt"), mock.patch.object(T, "_run_openssl", lambda *a, **k: crash), \
                mock.patch.object(E.shutil, "which", lambda n: "openssl"):
            with self.assertRaises(V.CheckNotRun) as c:
                E._verify_rfc3161("MAA=", "00" * 32)
        self.assertIn("0xC0000005", str(c.exception))


class DirectoryAsInput(unittest.TestCase):
    """Windows refuses to open a directory as a file with PermissionError: an input that is a directory was taken for
    an unreadable (or, as an archive segment, a missing) file; on POSIX fstat says "not a regular file". Same answer
    now (run 45377477990: an archive with a directory as its unsealed segment was valid on Windows)."""

    def test_a_directory_is_not_a_regular_file_on_windows_too(self):
        import tempfile
        from unittest import mock
        import verifier as V
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d)
        real_open = os.open

        def windows_open(path, flags, *a):
            if os.path.isdir(path):
                raise PermissionError(13, "Permission denied", path)
            return real_open(path, flags, *a)
        with mock.patch.object(os, "open", windows_open), mock.patch.object(os, "name", "nt"):
            for reader in (V.open_regular, V.open_ledger_input):
                with self.assertRaises(V.InputNotRegular, msg=reader.__name__):
                    reader(d)


class FakeOpensslOnWindows(unittest.TestCase):
    """The Windows stand-in of a fake openssl: a Python started as openssl.exe runs the body with openssl's arguments.
    Measured here through a link named openssl.exe to this Python (the launcher itself runs on Windows only)."""

    @unittest.skipIf(os.name == "nt", "the launcher route is measured by the tests that use it on Windows")
    @unittest.skipIf(sys.version_info < (3, 10), "the hook reads sys.orig_argv, new in Python 3.10")
    def test_the_site_hook_runs_the_body_with_the_arguments(self):
        import tempfile
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d)
        site = os.path.join(d, "site")
        os.makedirs(site)
        with open(os.path.join(site, "sitecustomize.py"), "w", encoding="utf-8", newline="") as f:
            f.write(_FAKE_SITE)
        exe = os.path.join(d, "openssl.exe")
        os.symlink(sys.executable, exe)
        env = dict(os.environ, PYTHONPATH=site,
                   CV_FAKE_OPENSSL="import sys; print('|'.join(sys.argv)); sys.exit(127)")
        r = subprocess.run([exe, "ts", "-verify", "-in", "x"], capture_output=True, env=env, timeout=60)
        self.assertEqual((r.returncode, r.stdout.strip()), (127, b"ts|-verify|-in|x"), r.stderr[-300:])
        r = subprocess.run([sys.executable, "-c", "print('python')"], capture_output=True, env=env, timeout=60)
        self.assertEqual(r.stdout.strip(), b"python")   # control: any other Python is not touched


class JavaSourceIsAscii(unittest.TestCase):
    """javac before JDK 18 reads a source in the platform encoding: on Windows (cp1252) the UTF-8 "±" and "§" of
    CvVerify.java became other characters and the Java verifier's texts differed from the other three (CI run
    45437498313). The source is ASCII, the characters written as Unicode escapes."""

    JAVA = os.path.join(_HERE, "verifiers", "java", "CvVerify.java")

    def test_the_source_is_ascii(self):
        with open(self.JAVA, "rb") as f:
            raw = f.read()
        self.assertEqual([i for i, b in enumerate(raw) if b > 0x7F][:5], [])

    @unittest.skipUnless(shutil.which("javac") and shutil.which("java"), "needs a JDK")
    def test_the_texts_are_the_same_whatever_encoding_javac_reads(self):
        import tempfile
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d)
        subprocess.run(["javac", "-encoding", "windows-1252", "-d", d, self.JAVA], check=True, capture_output=True)
        tip = os.path.join(d, "tip.json")
        with open(tip, "wb") as f:
            f.write(b"x")
        r = subprocess.run(["java", "-cp", d, "CvVerify", "-tip", tip, "-trusted-pubkey", "00" * 32,
                            os.path.join(_HERE, "examples", "sample_ledger.jsonl")], capture_output=True, timeout=120)
        import json
        self.assertIn("entry 3: tip_unreadable: not a JSON text of the profile of SPEC \u00a73",
                      json.loads(r.stdout)["failures"], r.stdout[-300:])


if __name__ == "__main__":
    unittest.main()
