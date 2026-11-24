#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
"""The review of 0.20.3 (13/10/2026): cases the first 0.20.3 tests did not hold, each with real processes.

- a promised file over an existing one keeps what 0.20.2's open(path, "w") kept: a symlink at the path is followed (its
  target gets the file), the existing file's mode stays, a file made read-only (a receipt chmod 444) is refused — never
  replaced by a rename behind its owner's back; a FIFO is written directly; `signer.py keygen` never writes over an
  existing key or `.pq` file (exit 2, nothing written);
- openssl that does not answer within its timeout is a check that could not run here (74), never `valid: false`; so is
  an openssl that cannot be executed (a bad interpreter: ENOENT, not only a refused fork);
- `cryptovalid_scitt.py register` refuses a directory as --out before the ledger line, and when --out cannot be written
  after the line the stderr line says the statement IS registered;
- the writer: text the caller left in stdout's text layer goes out first; a full non-blocking stdout is waited for in
  the kernel (no CPU spent spinning); the last flush is waited for too (a reader that drips); a write(2) that returns 0
  is an error; fsync failing is an error (a file, a ledger line); a second outcome on a utf-8-sig stream carries no
  second byte order mark; a utf-16 stdout past offset 0 gets none;
- library paths: ap2-evidence-pack's Ap2WriteError is 74 in `verify_evidence.py ap2`; the RFC 3161 domain of
  cryptovalid_heterogeneous counts when openssl verifies and lets CheckNotRun through; an evidence pack build whose
  stamp cannot run openssl is 74.
The fsync and write faults: an LD_PRELOAD shim on Linux (C); on macOS and Windows a sitecustomize that wraps os.fsync
and stdout's raw write, the same failures seen by the same code (os.fsync, FileIO.write). Non-blocking pipes: O_NONBLOCK
on POSIX, PIPE_NOWAIT on Windows (os.set_blocking, Python 3.12+), read with FIONREAD / PeekNamedPipe."""
import json
import os
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from test_platforms_20261124 import (BASH, NEEDS_NONBLOCKING_PIPES, cpu_seconds, full_sink, pipe_bytes,  # noqa: E402
                                     pipe_capacity, set_nonblocking)

FAULTS_PY = r'''
import io, os, sys
if os.environ.get("CV_FSYNC_EIO"):
    _sub, _paths, _open, _fsync = os.environ.get("CV_SHIM_SUB"), {}, os.open, os.fsync

    def _o(path, *a, **k):
        fd = _open(path, *a, **k)
        _paths[fd] = os.fspath(path)
        return fd

    def _f(fd):
        n = fd if isinstance(fd, int) else fd.fileno()
        if _sub is None or _sub in str(_paths.get(n, "")):
            raise OSError(5, os.strerror(5))
        return _fsync(fd)
    os.open, os.fsync = _o, _f
if os.environ.get("CV_WRITE0_FD") == "1":
    class _Zero(io.FileIO):
        done = False

        def write(self, b):
            if not _Zero.done and len(b):
                _Zero.done = True
                return 0
            return super().write(b)
    sys.stdout = io.TextIOWrapper(_Zero(1, "wb", closefd=False), encoding=sys.stdout.encoding,
                                  errors=sys.stdout.errors, write_through=True)
'''
sys.path.insert(0, HERE)
PY = sys.executable
SAMPLE = os.path.join(HERE, "examples", "sample_ledger.jsonl")
ENV = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
EX_IOERR = 74

SHIM_C = r'''
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
static int done0 = 0;
static int match(int fd) {
    const char *sub = getenv("CV_SHIM_SUB"); char p[64], b[4096];
    if (!sub) return 1;
    snprintf(p, sizeof p, "/proc/self/fd/%d", fd);
    ssize_t n = readlink(p, b, sizeof b - 1); if (n < 0) return 0; b[n] = 0;
    return strstr(b, sub) != NULL;
}
int fsync(int fd) {
    static int (*r)(int) = 0; if (!r) r = (int (*)(int))dlsym(RTLD_NEXT, "fsync");
    if (getenv("CV_FSYNC_EIO") && match(fd)) { errno = EIO; return -1; }
    return r(fd);
}
ssize_t write(int fd, const void *b, size_t n) {
    static ssize_t (*r)(int, const void *, size_t) = 0; if (!r) r = (ssize_t (*)(int, const void *, size_t))dlsym(RTLD_NEXT, "write");
    const char *w = getenv("CV_WRITE0_FD");
    if (w && !done0 && fd == atoi(w) && n > 0) { done0 = 1; return 0; }
    return r(fd, b, n);
}
'''


def big_unsigned(d):
    p = os.path.join(d, "big.jsonl")
    with open(p, "w", encoding="utf-8", newline="") as f:
        for i in range(3000):
            f.write('{"ts":%d,"v":%d,"self_hash":"%s"}\n' % (i, i, "0" * 64))
    return p


def _crypto():
    try:
        import cryptography  # noqa: F401
        return True
    except ImportError:
        if os.environ.get("CV_REQUIRE_CRYPTO") == "1":
            raise
        return False


NEEDS_CRYPTO = unittest.skipUnless(_crypto(), "needs `cryptography` (the `sign` extra)")


class _Tmp(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp(prefix="cv-review-")

    def tearDown(self):
        for root, dirs, _ in os.walk(self.d):
            for x in dirs:
                try:
                    os.chmod(os.path.join(root, x), 0o700)
                except OSError:
                    pass
        shutil.rmtree(self.d, ignore_errors=True)

    def run_py(self, args, env=None, **kw):
        p = subprocess.run([PY] + args, capture_output=True, env=env or ENV, timeout=kw.pop("timeout", 120), **kw)
        return p.returncode, p.stdout, p.stderr

    def faults(self, **env):
        """the environment that makes the child's fsync (CV_FSYNC_EIO, on paths containing CV_SHIM_SUB) or its first
        write to stdout (CV_WRITE0_FD=1) fail: LD_PRELOAD of the C shim on Linux; elsewhere the Python equivalent"""
        if sys.platform.startswith("linux") and not os.environ.get("CV_FAULTS_PY"):
            return dict(ENV, LD_PRELOAD=self.shim(), **env)
        d = os.path.join(self.d, "faults")
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, "sitecustomize.py"), "w", encoding="utf-8", newline="") as f:
            f.write(FAULTS_PY)
        return dict(ENV, PYTHONPATH=d, **env)

    def shim(self):
        cc = shutil.which("cc") or shutil.which("gcc")
        if not cc:
            if os.environ.get("CV_REQUIRE_CC") == "1":
                self.fail("no C compiler for the LD_PRELOAD shim")
            self.skipTest("no C compiler")
        src = os.path.join(self.d, "shim.c")
        with open(src, "w", encoding="utf-8", newline="") as f:
            f.write(SHIM_C)
        so = os.path.join(self.d, "shim.so")
        subprocess.run([cc, "-shared", "-fPIC", "-o", so, src, "-ldl"], check=True, capture_output=True)
        return so


class TestPromisedFileOverExisting(_Tmp):
    def test_keygen_never_replaces_a_key(self):
        """Roberto's decision (13/10/2026): keygen refuses a path where something exists — a key, writable or not, the
        `.pq` file with --pq, a symlink — with one stderr line and exit 2 (a usage refusal); nothing is written. 0.20.2
        replaced a writable key (exit 0); the first 0.20.3 commits replaced even a read-only one"""
        if not _crypto():
            self.skipTest("cryptography not installed")
        sg = os.path.join(HERE, "signer.py")
        key = os.path.join(self.d, "k.key")
        rc, _, err = self.run_py([sg, "keygen", key])
        self.assertEqual(rc, 0, err)
        with open(key, "rb") as f:
            before = f.read()
        for mode in (0o600, 0o400):
            os.chmod(key, mode)
            mode = stat.S_IMODE(os.stat(key).st_mode)   # Windows: only the read-only bit follows the mode
            rc, out, err = self.run_py([sg, "keygen", key])
            self.assertEqual((rc, out), (2, b""), err)
            self.assertEqual(err.count(b"\n"), 1, err)
            self.assertIn(b"already exists", err)
            with open(key, "rb") as f:
                self.assertEqual(f.read(), before, "an existing private key was replaced")
            self.assertEqual(stat.S_IMODE(os.stat(key).st_mode), mode)
        fresh = os.path.join(self.d, "f.key")   # --pq: an existing .pq refuses BEFORE the Ed25519 key is written
        with open(fresh + ".pq", "w", encoding="utf-8", newline="") as f:
            f.write("PQ")
        rc, out, err = self.run_py([sg, "keygen", fresh, "--pq"])
        self.assertEqual((rc, out), (2, b""), err)
        self.assertFalse(os.path.lexists(fresh), "the Ed25519 key was written before the refusal")
        link = os.path.join(self.d, "l.key")   # a dangling symlink is something at the path too
        os.symlink(os.path.join(self.d, "nowhere"), link)
        rc, _, err = self.run_py([sg, "keygen", link])
        self.assertEqual(rc, 2, err)
        self.assertFalse(os.path.exists(os.path.join(self.d, "nowhere")))
        fresh2 = os.path.join(self.d, "g.key")   # a dangling symlink at <keyfile>.pq refuses before the Ed25519 key too
        os.symlink(os.path.join(self.d, "nowhere2"), fresh2 + ".pq")
        rc, _, err = self.run_py([sg, "keygen", fresh2, "--pq"])
        self.assertEqual(rc, 2, err)
        self.assertFalse(os.path.lexists(fresh2), "the Ed25519 key was written before the refusal")
        self.assertEqual([n for n in os.listdir(self.d) if n.endswith(".tmp")], [])
        os.chmod(key, 0o600)
        import signer   # the library refuses too, a writable key included
        with self.assertRaises(FileExistsError):
            signer.keygen(key)
        with open(key, "rb") as f:
            self.assertEqual(f.read(), before)

    def test_keygen_pq_never_over_existing(self):
        if not _crypto():
            self.skipTest("cryptography not installed")
        key = os.path.join(self.d, "k.key")
        with open(key + ".pq", "w", encoding="utf-8", newline="") as f:
            f.write("EXISTING")
        rc, _, _ = self.run_py([os.path.join(HERE, "signer.py"), "keygen", key, "--pq"])
        self.assertNotEqual(rc, 0)
        with open(key + ".pq", encoding="utf-8") as f:
            self.assertEqual(f.read(), "EXISTING")

    def test_out_read_only_symlink_mode(self):
        v = os.path.join(HERE, "verifier.py")
        ro = os.path.join(self.d, "ro.json")
        with open(ro, "w", encoding="utf-8", newline="") as f:
            f.write("KEEP")
        os.chmod(ro, 0o444)
        rc, _, err = self.run_py([v, SAMPLE, "--out", ro])
        self.assertEqual(rc, EX_IOERR, err)
        with open(ro, encoding="utf-8") as f:
            self.assertEqual(f.read(), "KEEP")
        os.mkdir(os.path.join(self.d, "real"))
        target = os.path.join(self.d, "real", "r.json")
        with open(target, "w", encoding="utf-8", newline="") as f:
            f.write("x")
        link = os.path.join(self.d, "link.json")
        os.symlink(os.path.join("real", "r.json"), link)
        rc, _, err = self.run_py([v, SAMPLE, "--out", link])
        self.assertEqual(rc, 0, err)
        self.assertTrue(os.path.islink(link), "the symlink at --out was replaced by a file")
        with open(target, encoding="utf-8") as f:
            self.assertEqual(json.load(f)["verdict"], "PASS")
        priv = os.path.join(self.d, "priv.json")
        with open(priv, "w", encoding="utf-8", newline="") as f:
            f.write("x")
        from test_platforms_20261124 import assert_private, make_private   # Windows: the access list
        make_private(priv)
        p = subprocess.run([BASH, "-c", 'umask 022; exec "$@"', "_", PY, v, SAMPLE, "--out", priv], capture_output=True, env=ENV)
        self.assertEqual(p.returncode, 0, p.stderr)
        assert_private(self, priv, 0o600)   # the receipt's mode (Windows: its access list) was not widened

    def test_pack_copy_keeps_mode_and_refuses_read_only(self):
        from verifier import OutputNotWritten, copy_output
        src = os.path.join(self.d, "src.jsonl")
        shutil.copy(SAMPLE, src)
        dst = os.path.join(self.d, "dst.jsonl")
        with open(dst, "w", encoding="utf-8", newline="") as f:
            f.write("old")
        from test_platforms_20261124 import assert_private, make_private   # Windows: the access list
        make_private(dst)
        old = os.umask(0o022)
        try:
            copy_output(src, dst)
        finally:
            os.umask(old)
        assert_private(self, dst, 0o600)
        with open(dst, "rb") as a, open(SAMPLE, "rb") as b:
            self.assertEqual(a.read(), b.read())
        os.chmod(dst, 0o444)
        if not os.access(dst, os.W_OK):
            with self.assertRaises(OutputNotWritten):
                copy_output(src, dst)

    def test_out_fifo_written_directly(self):
        from test_platforms_20261124 import fifo_at   # a FIFO at a name in a directory: POSIX only
        fifo = fifo_at(self, os.path.join(self.d, "f"))
        got = []

        def reader():
            with open(fifo, "rb") as f:
                got.append(f.read())
        t = threading.Thread(target=reader, daemon=True)
        t.start()
        rc, _, err = self.run_py([os.path.join(HERE, "verifier.py"), SAMPLE, "--out", fifo])
        t.join(30)
        if t.is_alive():   # nobody wrote to the FIFO: release the reader, then fail below
            os.close(os.open(fifo, os.O_WRONLY | os.O_NONBLOCK))
            t.join(10)
        self.assertEqual(rc, 0, err)
        self.assertTrue(got, "the FIFO got nothing")
        self.assertTrue(stat.S_ISFIFO(os.stat(fifo).st_mode), "the FIFO was replaced by a file")
        self.assertEqual(json.loads(got[0])["verdict"], "PASS")


class TestCheckNotRunMore(_Tmp):
    def _pack(self):
        sys.path.insert(0, HERE)
        led = os.path.join(self.d, "l.jsonl")
        shutil.copy(SAMPLE, led)
        out = os.path.join(self.d, "pack")
        rc, _, err = self.run_py([os.path.join(HERE, "evidence_pack.py"), "build", out, led])
        self.assertEqual(rc, 0, err)
        man = os.path.join(out, "MANIFEST.json")
        with open(man, encoding="utf-8") as f:
            m = json.load(f)
        # a claimed token: the bytes do not matter, openssl never answers in these cases
        m["rfc3161_timestamp"] = {"anchored": True, "tsa": "http://127.0.0.1:9/", "tsr_b64": "MAA="}
        with open(man, "w", encoding="utf-8", newline="") as f:
            json.dump(m, f, ensure_ascii=False, indent=1, sort_keys=True)
        return out

    # each fake as a POSIX shell script, and its Windows equivalent run by test_platforms.fake_openssl: a crash there
    # is an NTSTATUS exit (0xC0000005), since Windows has no signals; None = a file that is not a program
    _WINDOWS_FAKES = {
        "#!/bin/sh\nsleep 25\nexec /usr/bin/env -i openssl \"$@\"\n":
            "import os, subprocess, sys, time; time.sleep(25); "
            "sys.exit(subprocess.call([os.environ['CV_REAL_OPENSSL']] + sys.argv[1:]))",
        "#!/nonexistent/interpreter\n": None,
        "#!/bin/sh\nkill -KILL $$\n": "import os; os._exit(-1073741819)",
        "#!/bin/sh\nkill -SEGV $$\n": "import os; os._exit(-1073741819)",
        "#!/bin/sh\nexit 127\n": "import os; os._exit(127)",
    }

    def _fake_openssl(self, body):
        from test_platforms_20261124 import fake_openssl
        return dict(ENV, **fake_openssl(self, os.path.join(self.d, "bin"), body, self._WINDOWS_FAKES[body]))

    def test_openssl_timeout_is_74(self):
        if not shutil.which("openssl"):
            self.skipTest("openssl absent")
        pack = self._pack()
        env = self._fake_openssl("#!/bin/sh\nsleep 25\nexec /usr/bin/env -i openssl \"$@\"\n")
        rc, out, err = self.run_py([os.path.join(HERE, "evidence_pack.py"), "verify", pack], env=env, timeout=90)
        from test_platforms_20261124 import fake_calls
        self.assertEqual(rc, EX_IOERR, out + err + fake_calls(os.path.join(self.d, "bin")).encode())
        self.assertIn(b"no answer within", err)
        self._assert_whole_receipt_74(out, err)

    def _assert_whole_receipt_74(self, out, err):
        # 0.22.0 — SPEC §10: the COMPLETE receipt on stdout (time_anchor not_evaluated / instrument_failure, the other subjects
        # evaluated), one line `check not run here: ...` on stderr; until 0.21.0 stdout was empty
        r = json.loads(out)
        self.assertEqual(r["admission"], "admitted")
        self.assertEqual(r["states"]["time_anchor"]["state"], "not_evaluated")
        self.assertEqual(r["states"]["time_anchor"]["reasons"], ["instrument_failure"])
        self.assertEqual(r["states"]["sealed_content"]["state"], "verified")
        lines = err.decode("utf-8", "replace").splitlines()
        self.assertEqual(len(lines), 1, err)
        self.assertTrue(lines[0].startswith("check not run here: cannot run openssl here"), lines)

    def test_openssl_that_cannot_exec_is_74(self):
        pack = self._pack()
        env = self._fake_openssl("#!/nonexistent/interpreter\n")
        rc, out, err = self.run_py([os.path.join(HERE, "evidence_pack.py"), "verify", pack], env=env)
        self.assertEqual(rc, EX_IOERR, out + err)
        self.assertIn(b"cannot run openssl here", err)
        self._assert_whole_receipt_74(out, err)

    def test_openssl_ended_by_a_signal_is_74_and_127_is_not_verified(self):
        # 0.21.0 declared (audit R2 of class 16, 13/10/2026) that openssl killed by a signal, or a wrapper that exits 127,
        # had answered: `verified: false` with the pack valid, exit 0. 0.22.0 (SPEC §10, as ap2-evidence-pack 1.6.0 §6.10;
        # draft-krausz-verification-state-03 §3.1 "a crashed dependency"): in `evidence_pack.py verify` a tool ended by a
        # signal is a check NOT run here — the complete receipt, time_anchor instrument_failure, exit 74 (74 is never a pass,
        # so an input that makes openssl crash gains nothing); an exit 127 without a signal is an answer: the token does not
        # verify, `time_anchor: contradicted`, and since 0.22.0 the pack is not valid (exit 1). The other commands that run
        # openssl through cryptovalid_tsa keep the 0.21.0 rule (`verify_with_openssl`, `verify_cms_signature`: False).
        import cryptovalid_tsa as T
        for body, expect in (("#!/bin/sh\nkill -KILL $$\n", 74), ("#!/bin/sh\nkill -SEGV $$\n", 74), ("#!/bin/sh\nexit 127\n", 1)):
            with self.subTest(body=body):
                shutil.rmtree(os.path.join(self.d, "bin"), ignore_errors=True)
                shutil.rmtree(os.path.join(self.d, "pack"), ignore_errors=True)
                pack = self._pack()
                env = self._fake_openssl(body)
                rc, out, err = self.run_py([os.path.join(HERE, "evidence_pack.py"), "verify", pack], env=env)
                from test_platforms_20261124 import fake_calls
                self.assertEqual(rc, expect, out + err + fake_calls(os.path.join(self.d, "bin")).encode())
                if expect == 74:   # POSIX: a signal; Windows: an NTSTATUS exit
                    self.assertTrue(b"terminated by signal" in err or b"ended by exception 0xC0000005" in err, err)
                    self._assert_whole_receipt_74(out, err)
                else:
                    r = json.loads(out)
                    self.assertEqual((r["valid"], r["rfc3161"]["claimed"], r["rfc3161"]["verified"]), (False, True, False), out + err)
                    self.assertEqual(r["states"]["time_anchor"]["state"], "contradicted")
                old = os.environ["PATH"]
                os.environ["PATH"] = env["PATH"]
                try:
                    self.assertIs(T.verify_with_openssl(b"x", b"y"), False)
                    self.assertIs(T.verify_cms_signature(b"x"), False)
                finally:
                    os.environ["PATH"] = old

    def test_pack_build_stamp_not_run_is_74(self):
        if not shutil.which("openssl"):
            self.skipTest("openssl absent")
        led = os.path.join(self.d, "l.jsonl")
        shutil.copy(SAMPLE, led)
        out = os.path.join(self.d, "pack")
        env = self._fake_openssl("#!/nonexistent/interpreter\n")
        rc, so, err = self.run_py([os.path.join(HERE, "evidence_pack.py"), "build", out, led, "--tsa", "http://127.0.0.1:9/"], env=env)
        self.assertEqual(rc, EX_IOERR, so + err)
        self.assertFalse(os.path.exists(os.path.join(out, "MANIFEST.json")))


class TestScittOut(_Tmp):
    def _setup(self):
        if not _crypto():
            self.skipTest("cryptography not installed")
        key = os.path.join(self.d, "k.key")
        rc, out, err = self.run_py([os.path.join(HERE, "signer.py"), "keygen", key])
        pub = json.loads(out)["public_key_hex"]
        st = os.path.join(self.d, "st.json")
        with open(st, "w", encoding="utf-8", newline="") as f:
            f.write('{"x":1}')
        sc = os.path.join(HERE, "cryptovalid_scitt.py")
        signed = os.path.join(self.d, "s.cose")
        rc, _, err = self.run_py([sc, "sign", st, "--cty", "application/json", "--iss", "i", "--sub", "s", "--key", key, "--out", signed])
        self.assertEqual(rc, 0, err)
        led = os.path.join(self.d, "l.jsonl")
        return [sc, "register", signed, "--ledger", led, "--issuer-pubkey", pub, "--ts-key", key, "--ts-iss", "t", "--out"], led

    def test_out_directory_refused_before_the_line(self):
        reg, led = self._setup()
        rc, out, err = self.run_py(reg + [self.d + os.sep])
        self.assertEqual(rc, EX_IOERR, err)
        self.assertFalse(os.path.exists(led) and os.path.getsize(led), "a ledger line was recorded before --out was refused")

    def test_out_unwritable_says_registered(self):
        reg, led = self._setup()
        ro = os.path.join(self.d, "ro")
        os.mkdir(ro)
        os.chmod(ro, 0o555)
        if os.access(ro, os.W_OK):
            self.skipTest("running as a user that writes read-only folders")
        rc, out, err = self.run_py(reg + [os.path.join(ro, "t.cose")])
        self.assertEqual(rc, EX_IOERR, err)
        self.assertIn(b"the statement is registered in the ledger", err)
        with open(led, encoding="utf-8") as f:
            self.assertEqual(len(f.read().splitlines()), 1)

    def test_ledger_fsync_failure_is_74_and_whole(self):
        reg, led = self._setup()
        rc, _, err = self.run_py(reg + [os.path.join(self.d, "t0.cose")])
        self.assertEqual(rc, 0, err)
        with open(led, "rb") as f:
            before = f.read()
        rc, out, err = self.run_py(reg + [os.path.join(self.d, "t1.cose")],
                                   env=self.faults(CV_FSYNC_EIO="1", CV_SHIM_SUB="l.jsonl"))
        self.assertEqual(rc, EX_IOERR, err)
        self.assertIn(b"nothing was recorded", err)
        with open(led, "rb") as f:
            self.assertEqual(f.read(), before)


class TestWriter(_Tmp):
    def test_fsync_failure_of_out_is_74(self):
        out = os.path.join(self.d, "r.json")
        rc, _, err = self.run_py([os.path.join(HERE, "verifier.py"), SAMPLE, "--out", out],
                                 env=self.faults(CV_FSYNC_EIO="1", CV_SHIM_SUB=".tmp"))
        self.assertEqual(rc, EX_IOERR, err)
        self.assertFalse(os.path.exists(out))
        self.assertEqual([n for n in os.listdir(self.d) if n.endswith(".tmp")], [])

    def test_write_returning_zero_is_an_error(self):
        f = os.path.join(self.d, "o.txt")
        with open(f, "wb") as fh:
            p = subprocess.run([PY, os.path.join(HERE, "verifier.py"), SAMPLE], stdout=fh, stderr=subprocess.PIPE,
                               env=self.faults(CV_WRITE0_FD="1", PYTHONUNBUFFERED="1"), timeout=60)
        self.assertEqual(p.returncode, EX_IOERR, p.stderr)
        self.assertIn(b"short write", p.stderr)

    def _nonblocking(self, args, env=None):
        r, w = os.pipe()
        set_nonblocking(w)
        p = subprocess.Popen([PY] + args, stdout=w, stderr=subprocess.PIPE, env=env or ENV)
        os.close(w)
        return r, p

    @NEEDS_CRYPTO
    @NEEDS_NONBLOCKING_PIPES
    def test_waits_in_the_kernel_not_spinning(self):
        big = big_unsigned(self.d)
        r, p = self._nonblocking([os.path.join(HERE, "signer.py"), "verify", big])

        def cpu():
            return cpu_seconds(p)
        cap = pipe_capacity(r)
        t0 = time.time()
        while time.time() - t0 < 60:   # the pipe full: from here on the writer only waits
            if pipe_bytes(r) >= cap:
                break
            time.sleep(0.02)
        time.sleep(0.2)
        c0 = cpu()
        time.sleep(1.5)
        spent = cpu() - c0
        data = b""
        while True:
            c = os.read(r, 65536)
            if not c:
                break
            data += c
        os.close(r)
        rc = p.wait(60)
        p.stderr.close()
        self.assertEqual(rc, 1)
        self.assertLess(spent, 0.1, "the writer spent CPU while waiting for a full pipe (a loop instead of a wait)")
        self.assertTrue(json.loads(data))

    @NEEDS_CRYPTO
    @NEEDS_NONBLOCKING_PIPES
    def test_last_flush_waited_for(self):
        big = big_unsigned(self.d)
        for _ in range(3):
            r, p = self._nonblocking([os.path.join(HERE, "signer.py"), "verify", big])
            time.sleep(0.5)
            data = b""
            while True:
                c = os.read(r, 1024)
                if not c:
                    break
                data += c
                time.sleep(0.002)   # a reader that drips: the last buffered bytes meet a full pipe
            os.close(r)
            rc = p.wait(60)
            tail = p.stderr.read()[-300:]
            p.stderr.close()
            self.assertEqual(rc, 1, tail)
            self.assertTrue(json.loads(data))

    @NEEDS_NONBLOCKING_PIPES
    def test_caller_text_first_in_process(self):
        script = r'''
import os, sys, threading, time
sys.path.insert(0, sys.argv[1]); import verifier
r, w = os.pipe(); os.set_blocking(w, False)
try:
    while True: os.write(w, b"P" * 4096)
except BlockingIOError: pass
got = []
def rd():
    time.sleep(0.5)
    while True:
        c = os.read(r, 65536)
        if not c: break
        got.append(c)
t = threading.Thread(target=rd); t.start()
f = open(w, "w", encoding="utf-8", newline=""); sys.stdout = f
print("CALLER-TEXT")
rc = verifier.main([sys.argv[2], "--quiet"])
sys.stdout = sys.__stdout__; f.close(); t.join()
print(rc, b"".join(got).lstrip(b"P").decode())
'''
        p = subprocess.run([PY, "-c", script, HERE, SAMPLE], capture_output=True, text=True, encoding="utf-8", env=ENV, timeout=60)
        self.assertEqual(p.stdout, "0 CALLER-TEXT\nPASS\n\n", p.stderr[-400:])

    def test_one_byte_order_mark_per_stream(self):
        reqs = b'{"jsonrpc":"2.0","id":1,"method":"ping"}\n{"jsonrpc":"2.0","id":2,"method":"ping"}\n'
        p = subprocess.run([PY, os.path.join(HERE, "cryptovalid_mcp.py")], input=reqs, capture_output=True,
                           env=dict(ENV, PYTHONIOENCODING="utf-8-sig"), timeout=60)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(p.stdout.count(b"\xef\xbb\xbf"), 1, p.stdout[:200])
        with open(os.path.join(self.d, "o16"), "wb") as o16:
            subprocess.run([BASH, "-c", 'printf AB; exec "$@"', "_", PY, os.path.join(HERE, "verifier.py"), "--quiet", SAMPLE],
                           stdout=o16, env=dict(ENV, PYTHONIOENCODING="utf-16"), timeout=60)
        with open(os.path.join(self.d, "o16"), "rb") as f:
            self.assertEqual(f.read(), b"AB" + "PASS\n".encode("utf-16-le"))   # past offset 0: no mark, as the text layer


class TestTracebackWithStderrLost(_Tmp):
    def test_unexpected_error_keeps_exit_1(self):
        """README: a TSA that cannot be reached is a traceback and exit 1, written by the stderr writer, so a full stderr
        keeps exit 1 (an uncaught traceback on a full stderr is the interpreter's 120)"""
        for redir in ("2>" + shlex.quote(full_sink()), "2>&-"):
            p = subprocess.run([BASH, "-c", 'exec "$@" ' + redir, "_", PY, os.path.join(HERE, "cryptovalid_tsa.py"), "ab" * 32,
                                "--tsa", "http://127.0.0.1:9/"], capture_output=True, env=ENV, timeout=60)
            self.assertEqual(p.returncode, 1, (redir, p.stdout))
            self.assertEqual(p.stdout, b"")


class TestLibraryPaths(unittest.TestCase):
    def test_heterogeneous_rfc3161_domain(self):
        import cryptovalid_heterogeneous as H
        import cryptovalid_tsa as T
        from verifier import CheckNotRun
        import hashlib
        dig = hashlib.sha256(b"d").hexdigest()
        att = [{"domain": "rfc3161", "token_der": b"x", "digest_data": b"d", "tsa_certs": [b"pin"]}]
        # since v0.6 of the spec (2026-11-13) the domain reads one outcome, cryptovalid_tsa.verify_token (SPEC §11)
        ok = {"status": "verified", "tst_info": {"hash_algorithm": "sha256"}}
        with mock.patch.object(T, "verify_token", return_value=ok):
            r = H.verify_heterogeneous_anchor(dig, att, min_domains=1)
        self.assertTrue(r["ok"], r)
        for st in ("signature_only", "not_evaluated", "invalid"):
            with mock.patch.object(T, "verify_token", return_value=dict(ok, status=st)):
                self.assertFalse(H.verify_heterogeneous_anchor(dig, att, min_domains=1)["ok"], st)
        with mock.patch.object(T, "verify_token", return_value=ok):   # digest_data whose hash is not the digest
            self.assertFalse(H.verify_heterogeneous_anchor(dig, [dict(att[0], digest_data=b"e")], min_domains=1)["ok"])
        with mock.patch.object(T, "verify_token", side_effect=CheckNotRun("cannot run openssl here: x")):
            with self.assertRaises(CheckNotRun):
                H.verify_heterogeneous_anchor(dig, att, min_domains=1)

    def test_ap2_write_error_is_74(self):
        try:
            import ap2_evidence
        except ImportError:
            self.skipTest("ap2-evidence-pack not installed")
        import verify_evidence as VE

        class Ap2WriteError(OSError):
            pass
        with mock.patch.object(ap2_evidence, "verify_evidence", side_effect=Ap2WriteError("cannot run openssl here: x")), \
                mock.patch("sys.stderr", new=__import__("io").StringIO()):
            self.assertEqual(VE.main(["ap2", SAMPLE]), EX_IOERR)


class TestIngestBatchKept(unittest.TestCase):
    def test_failed_batch_written_by_the_next_flush(self):
        if os.name == "nt":
            self.skipTest("Windows has no per-process file-size limit (RLIMIT_FSIZE): a write cut at a chosen byte "
                          "cannot be made there")
        d = tempfile.mkdtemp(prefix="cv-review-")
        script = r'''
import resource, signal, sys
sys.path.insert(0, sys.argv[1])
import cryptovalid_ingest as I, verifier
ing = I.Ingestor(sys.argv[2], batch_size=1000, rotate_entries=10**6)
for i in range(3): ing.append({"i": i})
ing.flush()
seg = ing._seg_path(ing._seq); n0 = len(open(seg, "rb").read())
for i in range(40): ing.append({"pad": "z" * 100, "i": i})
signal.signal(signal.SIGXFSZ, signal.SIG_IGN)
resource.setrlimit(resource.RLIMIT_FSIZE, (n0 + 200, resource.RLIM_INFINITY))
try:
    ing.flush()
except OSError:
    pass
resource.setrlimit(resource.RLIMIT_FSIZE, (resource.RLIM_INFINITY, resource.RLIM_INFINITY))
ing.flush(); ing.close()
print(sum(1 for l in open(seg) if l.strip()), verifier.verify_ledger(seg)["verdict"])
'''
        try:
            p = subprocess.run([PY, "-c", script, HERE, d], capture_output=True, text=True, encoding="utf-8", env=ENV, timeout=120)
            self.assertEqual(p.stdout.split(), ["43", "PASS"], p.stdout + p.stderr[-400:])
        finally:
            shutil.rmtree(d, ignore_errors=True)


if __name__ == "__main__":
    unittest.main(verbosity=2)
