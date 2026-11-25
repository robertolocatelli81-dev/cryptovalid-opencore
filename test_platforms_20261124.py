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


_PIPE_WRITER = r"""
import json, os, sys, time
chunks, pause, delay = [bytes.fromhex(c) for c in json.loads(sys.argv[2])], float(sys.argv[3]), float(sys.argv[4])
chunks = chunks * int(sys.argv[5])
if os.name == "nt":
    import _winapi
    h = _winapi.CreateNamedPipe(sys.argv[1], _winapi.PIPE_ACCESS_OUTBOUND, 0, 1, 1 << 16, 1 << 16, 0, _winapi.NULL)
    print("ready", flush=True)
    try:
        _winapi.ConnectNamedPipe(h, False)
    except OSError:
        pass   # ERROR_PIPE_CONNECTED: the reader opened it first
    time.sleep(delay)
    try:
        for c in chunks:
            if c:
                _winapi.WriteFile(h, c)
            time.sleep(pause)
        import ctypes
        ctypes.WinDLL("kernel32").FlushFileBuffers(h)   # until the reader has read every byte
    except OSError:
        pass   # the reader stopped (at its bound): as a POSIX writer's BrokenPipeError
    finally:
        _winapi.CloseHandle(h)
else:
    print("ready", flush=True)
    try:
        with open(sys.argv[1], "wb") as f:   # waits for the reader
            time.sleep(delay)
            for c in chunks:
                f.write(c)
                f.flush()
                time.sleep(pause)
    except OSError:
        pass   # BrokenPipeError: the reader stopped (at its bound)
"""


def pipe_writer(tc, path, chunks, pause=0.0, delay=0.0, times=1):
    """A pipe a reader is given by name, with a writer process that waits `delay` s, writes `chunks` (bytes) with `pause`
    s between them (the list `times` times over) and leaves (no chunk: it leaves without a byte). POSIX: a FIFO at `path`; Windows: a named pipe
    \\\\.\\pipe\\cv-<random>, the writer its server. Returns (the name to give the reader, the writer's Popen); the
    writer is waited for at cleanup."""
    import json
    import secrets
    if hasattr(os, "mkfifo"):
        os.mkfifo(path)
        name = path
    else:
        name = r"\\.\pipe\cv-" + secrets.token_hex(8)
    w = subprocess.Popen([sys.executable, "-c", _PIPE_WRITER, name, json.dumps([bytes(c).hex() for c in chunks]),
                          str(pause), str(delay), str(times)], stdout=subprocess.PIPE)
    tc.addCleanup(lambda: (w.kill() if w.poll() is None else None, w.wait(30), w.stdout.close()))
    tc.assertEqual(w.stdout.readline().strip(), b"ready")   # on Windows the pipe exists from here on
    return name, w


PEAK_RSS_KIB = """
def peak_rss_kib():
    import os, sys
    if os.name == "nt":   # Windows: the peak working set of this process (GetProcessMemoryInfo), the equivalent of ru_maxrss
        import ctypes
        from ctypes import wintypes
        class C(ctypes.Structure):
            _fields_ = [("cb", wintypes.DWORD), ("PageFaultCount", wintypes.DWORD)] + [
                (n, ctypes.c_size_t) for n in ("PeakWorkingSetSize", "WorkingSetSize", "QuotaPeakPagedPoolUsage",
                                               "QuotaPagedPoolUsage", "QuotaPeakNonPagedPoolUsage",
                                               "QuotaNonPagedPoolUsage", "PagefileUsage", "PeakPagefileUsage")]
        c = C()
        c.cb = ctypes.sizeof(c)
        k = ctypes.WinDLL("kernel32")
        k.GetCurrentProcess.restype = wintypes.HANDLE
        if not ctypes.WinDLL("psapi").GetProcessMemoryInfo(k.GetCurrentProcess(), ctypes.byref(c), c.cb):
            raise OSError("GetProcessMemoryInfo failed")
        return c.PeakWorkingSetSize // 1024
    import resource
    return resource.getrusage(resource.RUSAGE_SELF).ru_maxrss // (1024 if sys.platform == "darwin" else 1)
"""   # source for a child process: the peak memory of that process in KiB on Linux, macOS and Windows


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
        for t in reversed(targets):   # a deny entry for everyone: an empty list still let the runner list the folder
            _windows_dacl(t, "D:P(D;OICI;FA;;;WD)")   # (run 45437498313); the owner keeps the right to restore the list
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
    if os.name == "nt":   # measured, not assumed: the account must really be refused
        try:
            os.listdir(path) if os.path.isdir(path) else open(path, "rb").close()
        except OSError:
            return
        tc.skipTest("this Windows account still reads %s through an access list that denies it to everyone (CI runs "
                    "45437498313, 45460009605: an administrator's privilege lists such a folder): no unreadable %s can "
                    "be made here" % ("the folder" if os.path.isdir(path) else "the file",
                                      "folder" if os.path.isdir(path) else "file"))


def make_private(path):
    """mode 0600 on POSIX; on Windows the access list of a key (verifier.owner_only)"""
    if os.name == "nt":
        import verifier
        verifier.owner_only(path)
    else:
        os.chmod(path, 0o600)


_FAKE_SITE = r'''
import os, sys
try:   # every start of a Python that loads this hook, whatever it is: the trace a failing test shows
    with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "hook_trace.log"), "a", encoding="utf-8") as _f:
        _f.write("%r %r %r %r\n" % (sys.executable, getattr(sys, "orig_argv", None), sys.prefix,
                                    sorted(k for k in os.environ if k.upper().startswith(("PYTHON", "__PYVENV")))))
except OSError:
    pass
_body = os.path.join(os.path.dirname(os.path.abspath(sys.executable)), "fake_body.py")
if os.path.basename(sys.executable).lower() == "openssl.exe" and os.path.isfile(_body):
    # sys.argv as a program sees it: [the program, its arguments] (sys.argv is not set yet here). Until b6de430 it was the
    # arguments alone, so a body's sys.argv[1:] dropped the first one: `cms -verify ...` passed through as `-verify ...`,
    # exit 1 (run 45515804628), and a body never saw `ts` or `verify`
    # sys.orig_argv is new in Python 3.10; under 3.9 sys.argv is already [the first argument, the rest] when this hook
    # runs (the interpreter took the openssl command for a script name): the same list for every command openssl has
    sys.argv = [sys.executable] + list(sys.orig_argv[1:] if hasattr(sys, "orig_argv") else sys.argv)
    with open(os.path.join(os.path.dirname(_body), "fake_calls.log"), "a", encoding="utf-8") as _f:
        _f.write(repr(sys.argv[1:]) + "\n")   # what the stand-in was asked, for a failing test to show
    import subprocess as _sp
    _call = _sp.call

    def _logged_call(cmd, **kw):   # the binary the body starts and what it says on stderr, in the log, then passed on
        kw["stderr"] = _sp.PIPE
        r = _sp.run(cmd, **kw)
        with open(os.path.join(os.path.dirname(_body), "fake_calls.log"), "a", encoding="utf-8") as _f:
            _f.write("  ran %r -> %s, stderr %r\n" % (cmd[0], r.returncode, r.stderr[-400:]))
        os.write(2, r.stderr)
        return r.returncode
    _sp.call = _logged_call
    code = 0
    try:
        with open(_body, encoding="utf-8") as _f:
            exec(compile(_f.read(), _body, "exec"))
    except SystemExit as e:
        code = e.code if isinstance(e.code, int) else 1
    except BaseException as e:   # a body that breaks says so in the log, not as a silent exit 1
        code = 1
        with open(os.path.join(os.path.dirname(_body), "fake_calls.log"), "a", encoding="utf-8") as _f:
            _f.write("  body raised %r\n" % (e,))
    with open(os.path.join(os.path.dirname(_body), "fake_calls.log"), "a", encoding="utf-8") as _f:
        _f.write("  -> exit %s\n" % code)
    sys.stdout.flush()
    sys.stderr.flush()
    os._exit(code)
'''


def fake_calls(bindir):
    """what the stand-in openssl was called with (Windows) and every start of a Python that loaded its hook; read when
    a test fails, not before the call"""
    if os.name != "nt":
        return "(POSIX shell stand-in)"
    out = []
    for n in ("fake_calls.log", os.path.join("Lib", "site-packages", "hook_trace.log")):
        try:
            with open(os.path.join(bindir, n), encoding="utf-8") as f:
                out.append("%s: %s" % (n, f.read()))
        except OSError:
            out.append("%s: absent" % n)
    return "; ".join(out)


def _write_fake_body(d, body, real):
    with open(os.path.join(d, "fake_body.py"), "w", encoding="utf-8", newline="") as f:
        f.write("import os\nos.environ.setdefault('CV_REAL_OPENSSL', %r)\n%s\n" % (real, body))


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
    # everything the stand-in needs lies beside it, nothing in the environment: the venv's own site-packages holds the
    # hook (the base Python reads it as the venv's), fake_body.py the body (run 45474879960: the stand-in answered the
    # probe but not the calls the code made, the environment variables it relied on were not what that run had)
    site = os.path.join(bindir, "Lib", "site-packages")
    os.makedirs(site, exist_ok=True)
    with open(os.path.join(site, "sitecustomize.py"), "w", encoding="utf-8", newline="") as f:
        f.write(_FAKE_SITE)
    _write_fake_body(bindir, py_body, real)
    env["PYTHONPATH"] = site   # the hook also through PYTHONPATH (without it, run 45490534605: test_outcome_review red)
    probe_dir = os.path.join(bindir, "probe")
    os.makedirs(probe_dir, exist_ok=True)
    for n in os.listdir(bindir):   # a second stand-in, for the probe only, with its own body
        if n.lower() in ("openssl.exe", "pyvenv.cfg"):
            shutil.copy(os.path.join(bindir, n), os.path.join(probe_dir, n))
    shutil.copytree(os.path.join(bindir, "Lib"), os.path.join(probe_dir, "Lib"))
    # the probe also goes through to the real openssl, as the bodies do
    # with the handles the stand-in was given (stdin=0, stdout=1, stderr=2), as the bodies pass through: without them
    # subprocess on Windows (close_fds) gives the child no handle to write to, and openssl ends with 1 (run 45503450377:
    # every `cms -verify` passed through exited 1)
    _write_fake_body(probe_dir, "import os, subprocess, sys\nprint('FAKE', sys.argv[1:], flush=True)\n"
                     "sys.exit(subprocess.call([os.environ['CV_REAL_OPENSSL'], 'version'], stdin=0, stdout=1, stderr=2))", real)
    # the probe is started as the code starts openssl: cryptovalid_tsa._run_openssl, in this process, with the
    # environment the tests set (PATH with the probe's folder first)
    import cryptovalid_tsa
    penv = dict(env, PATH=probe_dir + os.pathsep + env["PATH"], PYTHONPATH=os.path.join(probe_dir, "Lib", "site-packages"))
    old = {k: os.environ.get(k) for k in penv}
    os.environ.update(penv)
    try:
        probe = cryptovalid_tsa._run_openssl(["openssl", "probe-1", "probe 2"], capture_output=True, timeout=120)
    finally:
        for k, v in old.items():
            os.environ.pop(k, None) if v is None else os.environ.__setitem__(k, v)
    if probe.returncode != 0 or probe.stdout.splitlines()[:1] != [b"FAKE ['probe-1', 'probe 2']"] \
            or not probe.stdout.splitlines()[1:2] or not probe.stdout.splitlines()[1].startswith(b"OpenSSL"):
        tc.fail("the fake openssl.exe did not run its body: rc %s, stdout %r, stderr %r, %s"
                % (probe.returncode, probe.stdout[-300:], probe.stderr[-300:], fake_calls(probe_dir)))
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
    """Python's JSON parser recurses once per level and its limit moved with the version (measured 25/11/2026: a bare
    json.loads gives up at 995 levels under 3.9 and 3.11, 9 999 under 3.13, 65 168 under 3.14), so a reader that
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

    def test_bytes_in_utf16_or_utf32_are_bounded_too(self):
        """json.loads reads UTF-16 and UTF-32 bytes too. Scanned as bytes, the code unit U+2201 (a byte 0x22) closed
        the scan's string and the brackets after it were not counted: the same JWS payload 1 100 levels deep was read
        under 3.13 and a RecursionError under 3.9 (review of 2026-11-25)."""
        import verifier as V
        for enc in ("utf-8", "utf-16", "utf-16-le", "utf-16-be", "utf-32", "utf-32-le", "utf-32-be"):
            for odd in ("\u2201", "\u5c01", "\u2222", "a"):
                def doc(d):
                    return ('["%s",%s]' % (odd, "[" * (d - 1) + "]" * (d - 1))).encode(enc)
                self.assertEqual(V.json_loads_bounded(doc(2)), [odd, []], (enc, odd))   # control: read as json.loads reads it
                V.json_loads_bounded(doc(512))
                for d in self.DEPTHS:
                    with self.assertRaises(V.JsonTooDeepToRead, msg=(enc, odd, d)):
                        V.json_loads_bounded(doc(d))
        self.assertEqual(V.json_loads_bounded(b"\xef\xbb\xbf[1]"), [1])   # a UTF-8 signature in bytes: as json.loads
        import json
        cesu = b'"\xed\xa0\x80"'                                             # an encoded surrogate: as json.loads
        self.assertEqual(V.json_loads_bounded(cesu), json.loads(cesu))

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
                mock.patch.object(E.shutil, "which", lambda n: os.path.abspath("openssl")):   # a path, as on PATH
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
        # as the bodies read it: sys.argv[0] the program, sys.argv[1:2] the openssl command
        _write_fake_body(d, "import sys; print('|'.join(sys.argv[1:])); sys.exit(127 if sys.argv[1:2] == ['ts'] else 3)",
                         "openssl")
        env = dict(os.environ, PYTHONPATH=site)   # here the hook is found through PYTHONPATH (not a venv)
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


class OpensslByItsPath(unittest.TestCase):
    """the openssl run is the one shutil.which names (Windows' CreateProcess searches other folders before PATH)"""

    def test_the_path_which_names_is_run(self):
        import subprocess as sp
        from unittest import mock
        import cryptovalid_tsa as T
        seen = []
        with mock.patch.object(shutil, "which", lambda n: "/opt/fake/bin/openssl" if n == "openssl" else None), \
                mock.patch.object(sp, "run", lambda cmd, **kw: (seen.append(cmd), sp.CompletedProcess(cmd, 0))[1]):
            T._run_openssl(["openssl", "version"], capture_output=True)
        self.assertEqual(seen, [["/opt/fake/bin/openssl", "version"]])
        with mock.patch.object(shutil, "which", lambda n: None):
            from verifier import CheckNotRun
            with self.assertRaises(CheckNotRun):
                T._run_openssl(["openssl", "version"], capture_output=True)


class NeverTheProgramOfTheCurrentFolder(unittest.TestCase):
    """shutil.which looks in the current folder first on Windows, and at an empty PATH entry everywhere: a program
    placed beside the evidence was the one named, and the one run (review of 2026-11-25). verifier.which drops an
    answer that is not an absolute path and searches the absolute folders of PATH."""

    def _program(self, folder, name):
        os.makedirs(folder, exist_ok=True)
        if os.name == "nt":
            p = os.path.join(folder, name + ".exe")
            shutil.copy(sys.executable, p)
        else:
            p = os.path.join(folder, name)
            with open(p, "w", encoding="utf-8", newline="") as f:
                f.write("#!/bin/sh\nexit 0\n")
            os.chmod(p, 0o755)
        return p

    def test_the_one_on_path_is_named_not_the_one_beside_the_evidence(self):
        import tempfile
        from unittest import mock
        import cryptovalid_tsa as T
        import verifier as V
        d = os.path.realpath(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, d)
        here, there = os.path.join(d, "evidence"), os.path.join(d, "bin")
        self._program(here, "openssl")
        good = self._program(there, "openssl")
        # Windows: the current folder comes first by itself; POSIX: an empty PATH entry is the current folder, and a
        # file that is not executable, in a folder before the good one, is not a program; nor is a folder of that name
        dirf = os.path.join(d, "dirf")
        os.makedirs(os.path.join(dirf, "openssl.exe" if os.name == "nt" else "openssl"))
        path = dirf + os.pathsep + there
        if os.name != "nt":
            nox = os.path.join(d, "nox")
            os.chmod(self._program(nox, "openssl"), 0o644)
            path = os.pathsep + nox + os.pathsep + path
        cwd = os.getcwd()
        os.chdir(here)
        try:
            with mock.patch.dict(os.environ, {"PATH": path}):
                planted = shutil.which("openssl")
                self.assertFalse(os.path.isabs(planted), planted)   # control: shutil.which names the planted one
                self.assertEqual(os.path.normcase(V.which("openssl")), os.path.normcase(good))
                seen = []
                with mock.patch.object(subprocess, "run",
                                       lambda cmd, **kw: (seen.append(cmd[0]), subprocess.CompletedProcess(cmd, 0))[1]):
                    T._run_openssl(["openssl", "version"], capture_output=True)
                self.assertEqual([os.path.normcase(x) for x in seen], [os.path.normcase(good)])
            with mock.patch.dict(os.environ, {"PATH": "" if os.name == "nt" else os.pathsep}):
                self.assertIsNone(V.which("openssl"))   # only the planted one: none
                with self.assertRaises(V.CheckNotRun):
                    T._run_openssl(["openssl", "version"], capture_output=True)
        finally:
            os.chdir(cwd)

    def test_no_production_module_asks_shutil_which(self):
        for name in sorted(os.listdir(_HERE)):
            if name.endswith(".py") and not name.startswith("test_") and name != "verifier.py":
                with open(os.path.join(_HERE, name), encoding="utf-8") as f:
                    self.assertNotIn("shutil.which(", f.read(), name)


class TemporaryNamesOnWindows(unittest.TestCase):
    """tempfile.mkstemp/mkdtemp retry a PermissionError on Windows while os.access(dir, W_OK) is true, which reads only
    the read-only attribute: in a folder an access list denies, thousands of tries. verifier.create_private tries
    again only a name already taken (the class found in ap2-evidence-pack df398fa)"""

    def _denied(self, counter):
        from unittest import mock

        def deny(*a, **k):
            counter.append(1)
            raise PermissionError(13, "Permission denied")
        # the Windows conditions: os.name nt, os.access true, every creation refused
        return [mock.patch.object(os, "open", deny), mock.patch.object(os, "mkdir", deny),
                mock.patch.object(os, "access", lambda *a, **k: True), mock.patch.object(os, "name", "nt")]

    def _with(self, patches, fn):
        import contextlib
        with contextlib.ExitStack() as st:
            for p in patches:
                st.enter_context(p)
            return fn()

    def test_mkstemp_loops_there(self):   # positive control: the defect is what the bench sees
        import tempfile
        from unittest import mock
        n = []
        # TMP_MAX bounded for the control, whatever the C library of this system says
        with tempfile.TemporaryDirectory() as d, mock.patch.object(tempfile, "TMP_MAX", 10000):
            with self.assertRaises((PermissionError, FileExistsError)):
                self._with(self._denied(n), lambda: tempfile.mkstemp(dir=d))
        self.assertEqual(len(n), 10000)

    def test_one_try_on_a_refusal(self):
        import tempfile
        import verifier
        import cryptovalid_tsa as T
        import cryptovalid_beacon as B
        with tempfile.TemporaryDirectory() as d:
            for directory in (False, True):
                n = []
                with self.assertRaises(PermissionError):
                    self._with(self._denied(n), lambda: verifier.create_private(d, "x-", directory=directory))
                self.assertEqual(len(n), 1)
            n = []
            with self.assertRaises(verifier.CheckNotRun):
                self._with(self._denied(n), T._openssl_tmpdir)
            self.assertEqual(len(n), 1)
            n = []
            with self.assertRaises(verifier.CheckNotRun):
                self._with(self._denied(n), lambda: B._entries(b""))
            self.assertEqual(len(n), 1)

    def test_a_taken_name_is_tried_again_64_times(self):
        import tempfile
        from unittest import mock
        import verifier
        n = []

        def taken(*a, **k):
            n.append(1)
            raise FileExistsError(17, "File exists")
        with tempfile.TemporaryDirectory() as d, mock.patch.object(os, "open", taken):
            with self.assertRaises(FileExistsError):
                verifier.create_private(d, "x-")
        self.assertEqual(len(n), 64)

    def test_what_stands_at_the_name_is_never_opened(self):
        """O_EXCL: a file, a link (to a file, to nothing) or a folder already at the name is not opened, not followed
        and not written: the name counts as taken (review of 2026-11-25: without O_EXCL the suite stayed green)"""
        import tempfile
        from unittest import mock
        import secrets
        import verifier
        for kind in ("file", "link", "dangling", "folder"):
            for directory in (False, True):
                with tempfile.TemporaryDirectory() as d:
                    p, target = os.path.join(d, "x-" + "00" * 8), os.path.join(d, "target")
                    if kind == "file":
                        with open(p, "wb") as f:
                            f.write(b"kept")
                    elif kind == "folder":
                        os.mkdir(p)
                    else:
                        if kind == "link":
                            with open(target, "wb") as f:
                                f.write(b"kept")
                        try:
                            os.symlink(target, p)
                        except OSError:   # Windows without the right to make links
                            continue
                    with mock.patch.object(secrets, "token_hex", lambda n: "00" * n):
                        with self.assertRaises(FileExistsError, msg=(kind, directory)):
                            verifier.create_private(d, "x-", directory=directory)
                    if kind == "link":
                        with open(target, "rb") as f:
                            self.assertEqual(f.read(), b"kept")
                    if kind == "dangling":
                        self.assertFalse(os.path.exists(target))
                    if kind == "file":
                        with open(p, "rb") as f:
                            self.assertEqual(f.read(), b"kept")

    def test_a_real_private_file_and_folder(self):
        import tempfile
        import verifier
        with tempfile.TemporaryDirectory() as d:
            fd, p = verifier.create_private(d, "y-", ".z")
            os.close(fd)
            self.assertTrue(os.path.basename(p).startswith("y-") and p.endswith(".z") and os.path.isfile(p))
            _, q = verifier.create_private(d, "w-", directory=True)
            self.assertTrue(os.path.isdir(q))
            if os.name != "nt":
                um = os.umask(0)
                os.umask(um)
                self.assertEqual((os.stat(p).st_mode & 0o777, os.stat(q).st_mode & 0o777), (0o600 & ~um, 0o700 & ~um))


if __name__ == "__main__":
    unittest.main()
