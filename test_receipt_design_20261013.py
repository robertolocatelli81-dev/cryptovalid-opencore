#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
"""The outcome is written whole, or exit 74 — the cases measured on 13/10/2026 (0.20.3), with real processes.

test_receipt_not_written.py covers stdout on /dev/full, on a pipe whose reader is gone and closed. This file covers what
the 13/10 bench found still open after the first 0.20.3 commits, and the commands that were not converted then:
- unbuffered Python (-u / PYTHONUNBUFFERED) under a file size limit: the raw write took part of the receipt and the rest
  was dropped in silence (the verdict's exit code with the receipt cut);
- a non-blocking stdout that is full (read only once the pipe is full): the receipt must arrive whole (it was 74, or cut
  with exit 1);
- usage errors with stderr full, closed or with its reader gone: exit 2 and nothing on stdout (it was 120 or 1, and the
  usage text went to stdout with stderr closed); `--help` that is not written whole is 74 (it was 120);
- files a command promises (`verifier.py --out`, `signer.py sign` and `keygen`, the chain tip, the monitor state, the
  WORM object): a write that fails leaves the file that was there intact and no temporary behind, exit 74; a symlink
  planted at the old predictable `<path>.tmp` is never followed;
- hash-chained ledgers (`cryptovalid_scitt.py register`, the ingest writer): the whole line or nothing, the ledger byte
  for byte as it was after a failed append;
- every other module with a `__main__`: its outcome on /dev/full is 74, on a file the verdict's code;
- a check that cannot be RUN here (openssl that cannot be started under RLIMIT_NPROC 1, no temporary file for it) is 74,
  never a verdict on the input (a valid evidence pack was `valid: false`, exit 1);
- a command run under a file size limit no longer leaves a cut .pyc that makes every later run exit 1 (CPython 3.9, 3.11).
Every test here fails on 0.20.2 (c289480). Linux only (bash `ulimit`, O_NONBLOCK pipes); macOS and Windows not measured."""
import fcntl
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
PY = sys.executable
SAMPLE = os.path.join(HERE, "examples", "sample_ledger.jsonl")
TAMPERED = os.path.join(HERE, "examples", "sample_ledger_tampered.jsonl")
EX_IOERR = 74
ENV = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}


def _crypto():
    try:
        import cryptography  # noqa: F401
        return True
    except ImportError:
        if os.environ.get("CV_REQUIRE_CRYPTO") == "1":
            raise
        return False


def sh(script, argv, env=None, timeout=120):
    """bash -c script with "$@" = argv; returns (rc, stdout, stderr)"""
    p = subprocess.run(["bash", "-c", script, "_"] + list(argv), capture_output=True, timeout=timeout, env=env or ENV)
    return p.returncode, p.stdout, p.stderr


def big_unsigned(d):
    """3 000 entries without a signature: `signer.py verify` names each one, a receipt of about 300 KB"""
    p = os.path.join(d, "big.jsonl")
    with open(p, "w") as f:
        for i in range(3000):
            f.write('{"ts":%d,"v":%d,"self_hash":"%s"}\n' % (i, i, "0" * 64))
    return p


def read_after_full(r, p, timeout=120):
    """Read the pipe's read end only once the writer has FILLED the pipe (FIONREAD = its capacity) or exited: a fixed
    sleep was not late for a slow starter (the JVM needs about 1 s to reach its write), so the EAGAIN path was not
    always exercised (a mutant that gives up on EAGAIN survived 2 runs of 3, 13/10/2026). Returns all the bytes."""
    import array
    import termios
    cap = fcntl.fcntl(r, getattr(fcntl, "F_GETPIPE_SZ", 1032))   # the pipe's capacity (Linux: F_GETPIPE_SZ = 1032)
    t0 = time.time()
    while time.time() - t0 < timeout and p.poll() is None:
        n = array.array("i", [0])
        fcntl.ioctl(r, termios.FIONREAD, n, True)
        if n[0] >= cap:
            break
        time.sleep(0.02)
    time.sleep(0.3)
    chunks = []
    while True:
        b = os.read(r, 1 << 16)
        if not b:
            break
        chunks.append(b)
    os.close(r)
    return b"".join(chunks)


class _Tmp(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp(prefix="cv0203_")
        self.addCleanup(shutil.rmtree, self.d, True)

    def assertOneLine74(self, rc, err, label):
        self.assertEqual(rc, EX_IOERR, f"{label}: rc {rc}, stderr {err[-400:]!r}")
        lines = err.decode("utf-8", "replace").splitlines()
        self.assertEqual(len(lines), 1, f"{label}: {err[-400:]!r}")
        self.assertTrue(lines[0].startswith("receipt not written: "), f"{label}: {lines!r}")


class TestUnbufferedFileSizeLimit(_Tmp):
    """-u: a raw write that takes part of the receipt returns the count; the rest must not be dropped in silence"""

    def test_cut_receipt_is_74(self):
        for cmd in ([PY, os.path.join(HERE, "verifier.py"), SAMPLE], [PY, os.path.join(HERE, "verifier.py"), TAMPERED]):
            out = os.path.join(self.d, "o")
            with open(out, "wb") as f:
                f.write(b"x" * 1000)   # 24 bytes left under a 1 024-byte limit
            env = dict(ENV, PYTHONUNBUFFERED="1")
            rc, _, err = sh('ulimit -f 1; exec "$@" >>"$OUT"', cmd, env=dict(env, OUT=out))
            self.assertOneLine74(rc, err, f"-u {cmd[-1]}")


class TestNonBlockingStdout(_Tmp):
    """a non-blocking pipe read only once it is full: the receipt arrives whole and the code is the verdict's"""

    def test_large_receipt_whole(self):
        if not _crypto():
            self.skipTest("cryptography not installed")
        big = big_unsigned(self.d)
        for unbuffered in ("", "1"):
            r, w = os.pipe()
            fcntl.fcntl(w, fcntl.F_SETFL, fcntl.fcntl(w, fcntl.F_GETFL) | os.O_NONBLOCK)
            env = dict(ENV, PYTHONUNBUFFERED=unbuffered) if unbuffered else ENV
            p = subprocess.Popen([PY, os.path.join(HERE, "signer.py"), "verify", big], stdout=w, stderr=subprocess.PIPE, env=env)
            os.close(w)
            data = read_after_full(r, p)
            err = p.stderr.read()
            p.stderr.close()
            rc = p.wait(timeout=120)
            self.assertEqual(rc, 1, f"-u={unbuffered!r}: rc {rc} {err[-300:]!r}")
            self.assertGreater(len(data), 65536)
            self.assertIs(json.loads(data)["ok"], False)


class TestJavaNonBlocking(_Tmp):
    """CvVerify.java: a non-blocking stdout read once full gets a receipt larger than the pipe buffer whole, exit 1 (it was
    74 with 65 536 bytes in the pipe: FileOutputStream.write threw EAGAIN); stdout opened read-only (EBADF) is 74"""

    def test_java(self):
        home = os.environ.get("JAVA_HOME")
        javac = os.path.join(home, "bin", "javac") if home and os.path.exists(os.path.join(home, "bin", "javac")) else shutil.which("javac")
        java = os.path.join(home, "bin", "java") if home and os.path.exists(os.path.join(home, "bin", "java")) else shutil.which("java")
        if not (javac and java):
            if os.environ.get("CV_REQUIRE_JAVA") == "1":
                raise RuntimeError("CV_REQUIRE_JAVA=1 and no JDK")
            self.skipTest("no JDK")
        cp = os.path.join(self.d, "cls")
        subprocess.run([javac, "-d", cp, os.path.join(HERE, "verifiers", "java", "CvVerify.java")], check=True, capture_output=True)
        big = os.path.join(self.d, "big_bad.jsonl")
        with open(big, "w") as f:
            for i in range(20000):
                f.write(json.dumps({"idx": i, "ts": "2026-08-13T10:00:00Z", "data": {"e": i}, "prev_hash": "%064x" % (i + 1),
                                    "self_hash": "%064x" % (i + 7)}) + "\n")
        r, w = os.pipe()
        fcntl.fcntl(w, fcntl.F_SETFL, fcntl.fcntl(w, fcntl.F_GETFL) | os.O_NONBLOCK)
        p = subprocess.Popen([java, "-cp", cp, "CvVerify", big], stdout=w, stderr=subprocess.PIPE, env=ENV)
        os.close(w)
        data = read_after_full(r, p)
        err = p.stderr.read()
        p.stderr.close()
        rc = p.wait(timeout=120)
        self.assertEqual(rc, 1, err[-300:])
        self.assertGreater(len(data), 65536)
        self.assertEqual(json.loads(data)["verdict"], "FAIL")
        ro = os.path.join(self.d, "ro")
        open(ro, "w").close()
        rc, _, err = sh('exec "$@" 1<"$RO"', [java, "-cp", cp, "CvVerify", SAMPLE], env=dict(ENV, RO=ro))
        self.assertOneLine74(rc, err, "java stdout read-only")


class TestJavaWaitShape(_Tmp):
    """review of 0.20.3, 13/10: the Java wait is sleeps of 1 to 50 ms, not a spin and not an unbounded back-off: under 0.3 s of CPU
    in 3 s of waiting on a full non-blocking stdout, the receipt whole within 0.6 s of the reader starting, and it ends
    with the line separator (each property had a surviving mutant: Thread.onSpinWait, no 50 ms cap, no separator)"""

    def test_java_wait(self):
        home = os.environ.get("JAVA_HOME")
        javac = os.path.join(home, "bin", "javac") if home and os.path.exists(os.path.join(home, "bin", "javac")) else shutil.which("javac")
        java = os.path.join(home, "bin", "java") if home and os.path.exists(os.path.join(home, "bin", "java")) else shutil.which("java")
        if not (javac and java):
            if os.environ.get("CV_REQUIRE_JAVA") == "1":
                raise RuntimeError("CV_REQUIRE_JAVA=1 and no JDK")
            self.skipTest("no JDK")
        if not os.path.exists("/proc/self/stat"):
            self.skipTest("no /proc")
        cp = os.path.join(self.d, "cls")
        subprocess.run([javac, "-d", cp, os.path.join(HERE, "verifiers", "java", "CvVerify.java")], check=True, capture_output=True)
        small = subprocess.run([java, "-cp", cp, "CvVerify", SAMPLE], capture_output=True, env=ENV)
        self.assertTrue(small.stdout.endswith(os.linesep.encode()), small.stdout[-4:])
        big = os.path.join(self.d, "big_bad.jsonl")
        with open(big, "w") as f:
            for i in range(20000):
                f.write(json.dumps({"idx": i, "ts": "2026-08-13T10:00:00Z", "data": {"e": i}, "prev_hash": "%064x" % (i + 1),
                                    "self_hash": "%064x" % (i + 7)}) + "\n")
        import array
        import termios
        r, w = os.pipe()
        fcntl.fcntl(w, fcntl.F_SETFL, fcntl.fcntl(w, fcntl.F_GETFL) | os.O_NONBLOCK)
        p = subprocess.Popen([java, "-cp", cp, "CvVerify", big], stdout=w, stderr=subprocess.DEVNULL, env=ENV)
        os.close(w)
        cap = fcntl.fcntl(r, getattr(fcntl, "F_GETPIPE_SZ", 1032))
        t0 = time.time()
        while time.time() - t0 < 120 and p.poll() is None:
            n = array.array("i", [0])
            fcntl.ioctl(r, termios.FIONREAD, n, True)
            if n[0] >= cap:
                break
            time.sleep(0.02)
        time.sleep(0.3)

        def cpu():
            f = open("/proc/%d/stat" % p.pid).read().rsplit(")", 1)[1].split()
            return (int(f[11]) + int(f[12])) / os.sysconf("SC_CLK_TCK")
        c1 = cpu()
        time.sleep(3)
        c2 = cpu()
        t1 = time.time()
        chunks = []
        while True:
            b = os.read(r, 1 << 16)
            if not b:
                break
            chunks.append(b)
        os.close(r)
        rc = p.wait(timeout=120)
        late = time.time() - t1
        data = b"".join(chunks)
        self.assertEqual(rc, 1)
        self.assertTrue(len(data) > 65536 and data.endswith(os.linesep.encode()), len(data))
        self.assertLess(c2 - c1, 0.3, "CPU while waiting")
        self.assertLess(late, 0.6, "seconds from the first read to the end")


class TestUsageWithStderrLost(_Tmp):
    """usage errors keep exit 2 and write nothing on stdout, whatever stderr is"""

    CMDS = (["verifier.py"], ["verifier.py", SAMPLE, "--bogus"], ["verify_evidence.py"], ["signer.py", "verify"],
            ["cryptovalid_merkle.py"], ["cryptovalid_jws.py", "verify"], ["evidence_pack.py", "verify"])

    def test_usage(self):
        for c in self.CMDS:
            cmd = [PY, os.path.join(HERE, c[0])] + c[1:]
            for pre in ("exec 2>/dev/full; ", "exec 2>&-; "):
                rc, out, err = sh(pre + 'exec "$@"', cmd)
                self.assertEqual((rc, out), (2, b""), f"{c} {pre}: rc {rc} stdout {out[:200]!r}")
            r, w = os.pipe()
            os.close(r)
            try:
                p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=w, env=ENV, timeout=60)
            finally:
                os.close(w)
            self.assertEqual((p.returncode, p.stdout), (2, b""), f"{c} stderr gone")

    def test_help_not_written_is_74(self):
        for c in (["verifier.py", "--help"], ["verify_evidence.py", "--help"], ["cryptovalid_merkle.py", "--help"]):
            rc, _, err = sh('exec "$@" >/dev/full', [PY, os.path.join(HERE, c[0])] + c[1:])
            self.assertOneLine74(rc, err, str(c))


class TestPromisedFiles(_Tmp):
    """a promised file that cannot be written whole: exit 74, what was at the path intact, no temporary left"""

    def assertIntactNoTmp(self, path, before, label):
        with open(path, "rb") as f:
            self.assertEqual(f.read(), before, f"{label}: the file at the path changed")
        left = [n for n in os.listdir(os.path.dirname(path)) if n.endswith(".tmp")]
        self.assertEqual(left, [], f"{label}: temporary left: {left}")

    def test_verifier_out(self):
        out = os.path.join(self.d, "r.json")
        before = b'{"previous": "receipt"}\n' + b" " * 2000
        with open(out, "wb") as f:
            f.write(before)
        rc, stdout, err = sh('ulimit -f 1; exec "$@"', [PY, os.path.join(HERE, "verifier.py"), SAMPLE, "--out", out])
        self.assertEqual(rc, EX_IOERR, err[-300:])
        self.assertEqual(json.loads(stdout)["verdict"], "PASS")   # stdout still carries the receipt
        self.assertIntactNoTmp(out, before, "verifier --out")

    def test_signer_sign_and_keygen(self):
        if not _crypto():
            self.skipTest("cryptography not installed")
        sg = os.path.join(HERE, "signer.py")
        key = os.path.join(self.d, "k.key")
        subprocess.run([PY, sg, "keygen", key], check=True, capture_output=True, env=ENV)
        with open(key, "rb") as f:
            seed = f.read()
        new = os.path.join(self.d, "new.key")   # keygen never writes over an existing key (exit 2): a NEW path here
        rc, _, err = sh('ulimit -f 0; exec "$@"', [PY, sg, "keygen", new])
        self.assertEqual(rc, EX_IOERR, err[-300:])
        self.assertFalse(os.path.lexists(new), "a cut key was left at the path")
        self.assertEqual([n for n in os.listdir(self.d) if n.endswith(".tmp")], [])
        rc, _, err = sh('ulimit -f 0; exec "$@"', [PY, sg, "keygen", key])
        self.assertEqual(rc, 2, err[-300:])
        self.assertIntactNoTmp(key, seed, "keygen over an existing key")
        out = os.path.join(self.d, "s.jsonl")
        before = b"previous signed ledger\n" * 100
        with open(out, "wb") as f:
            f.write(before)
        rc, _, err = sh('ulimit -f 1; exec "$@"', [PY, sg, "sign", SAMPLE, out, key])
        self.assertEqual(rc, EX_IOERR, err[-300:])
        self.assertIntactNoTmp(out, before, "sign")

    def test_tip_never_follows_planted_tmp(self):
        if not _crypto():
            self.skipTest("cryptography not installed")
        key = os.path.join(self.d, "k.key")
        subprocess.run([PY, os.path.join(HERE, "signer.py"), "keygen", key], check=True, capture_output=True, env=ENV)
        led = os.path.join(self.d, "l.jsonl")
        shutil.copy(SAMPLE, led)
        victim = os.path.join(self.d, "victim")
        with open(victim, "wb") as f:
            f.write(b"untouched")
        os.symlink(victim, led + ".tip.json.tmp")   # the predictable name of 0.20.2
        rc, out, err = sh('exec "$@"', [PY, os.path.join(HERE, "cryptovalid_tip.py"), "sign", led, key])
        self.assertEqual(rc, 0, err[-300:])
        with open(victim, "rb") as f:
            self.assertEqual(f.read(), b"untouched")
        with open(led + ".tip.json", encoding="utf-8") as f:
            self.assertEqual(json.load(f)["entries"], 3)

    def test_monitor_state_never_follows_planted_tmp(self):
        state = os.path.join(self.d, "state.json")
        victim = os.path.join(self.d, "victim")
        with open(victim, "wb") as f:
            f.write(b"untouched")
        os.symlink(victim, state + ".tmp")
        rc, out, err = sh('exec "$@"', [PY, os.path.join(HERE, "cryptovalid_monitor.py"), SAMPLE, state])
        self.assertEqual(rc, 0, err[-300:])
        with open(victim, "rb") as f:
            self.assertEqual(f.read(), b"untouched")
        with open(state, encoding="utf-8") as f:
            self.assertTrue(json.load(f))

    def test_worm_object_whole_or_absent(self):
        store = os.path.join(self.d, "store")
        blob = os.path.join(self.d, "blob")
        with open(blob, "wb") as f:
            f.write(b"y" * 5000)
        rc, _, err = sh('ulimit -f 1; exec "$@"', [PY, os.path.join(HERE, "cryptovalid_worm.py"), "put", store, "k", blob])
        self.assertEqual(rc, EX_IOERR, err[-300:])
        self.assertEqual([n for n in os.listdir(store)], [], "a cut or temporary object was left in the WORM store")
        rc, out, err = sh('exec "$@"', [PY, os.path.join(HERE, "cryptovalid_worm.py"), "put", store, "k", blob])
        self.assertEqual(rc, 0, err[-300:])   # the key is still free: nothing half-written took it


class TestLedgerWholeLine(_Tmp):
    """an append that cannot be written whole leaves the hash-chained ledger byte for byte as it was"""

    def test_scitt_register(self):
        if not _crypto():
            self.skipTest("cryptography not installed")
        key = os.path.join(self.d, "k.key")
        pub = json.loads(subprocess.run([PY, os.path.join(HERE, "signer.py"), "keygen", key], check=True, capture_output=True,
                                        env=ENV).stdout)["public_key_hex"]
        st = os.path.join(self.d, "st.json")
        with open(st, "w") as f:
            f.write('{"x":1}')
        sc = os.path.join(HERE, "cryptovalid_scitt.py")
        signed = os.path.join(self.d, "s.cose")
        subprocess.run([PY, sc, "sign", st, "--cty", "application/json", "--iss", "i", "--sub", "s", "--key", key, "--out", signed],
                       check=True, capture_output=True, env=ENV)
        led = os.path.join(self.d, "l.jsonl")
        reg = [PY, sc, "register", signed, "--ledger", led, "--issuer-pubkey", pub, "--ts-key", key, "--ts-iss", "t",
               "--out", os.path.join(self.d, "t.cose")]
        subprocess.run(reg, check=True, capture_output=True, env=ENV)
        with open(led, "ab") as f:   # pad the ledger to 1 000 bytes with blank lines: 24 bytes left under the limit
            f.write(b"\n" * (1000 - os.path.getsize(led)))
        with open(led, "rb") as f:
            before = f.read()
        rc, out, err = sh('ulimit -f 1; exec "$@"', reg)
        self.assertEqual(rc, EX_IOERR, err[-300:])
        self.assertIn(b"nothing was recorded, the ledger is left as it was", err)
        with open(led, "rb") as f:
            self.assertEqual(f.read(), before)

    def test_ingest_flush(self):
        script = r'''
import os, resource, sys, json
sys.path.insert(0, sys.argv[1])
import cryptovalid_ingest as I
d = sys.argv[2]
ing = I.Ingestor(d, batch_size=1000, rotate_entries=10**6)
for i in range(3):
    ing.append({"i": i})
ing.flush()
seg = ing._seg_path(ing._seq)
before = open(seg, "rb").read()
for i in range(40):
    ing.append({"pad": "z" * 100, "i": i})
resource.setrlimit(resource.RLIMIT_FSIZE, (len(before) + 200, resource.RLIM_INFINITY))
import signal; signal.signal(signal.SIGXFSZ, signal.SIG_IGN)
try:
    ing.flush()
    print("NO-ERROR")
except OSError as e:
    print("ERR", type(e).__name__)
print("SAME" if open(seg, "rb").read() == before else "CHANGED")
resource.setrlimit(resource.RLIMIT_FSIZE, (resource.RLIM_INFINITY, resource.RLIM_INFINITY))
ing.flush(); ing.close()
import verifier
print(verifier.verify_ledger(seg)["verdict"])
'''
        p = subprocess.run([PY, "-c", script, HERE, os.path.join(self.d, "a")], capture_output=True, text=True, env=ENV, timeout=120)
        self.assertEqual(p.stdout.split(), ["ERR", "OutputNotWritten", "SAME", "PASS"], p.stdout + p.stderr[-600:])


class TestBytecodeCache(_Tmp):
    """CPython 3.9 and 3.11 write a module's .pyc with one raw write and install it even when the write was cut (a file size
    limit): every LATER run of a command importing that module then dies with `EOFError: marshal data too short`, exit 1
    (measured 13/10/2026; 3.13 installs no cut .pyc). Since 0.20.3 a command run as a script writes no bytecode cache. On
    0.20.2 the run after the limited ones exits 1 on 3.9 and 3.11; on 3.13 only the second check fails (a cache was
    written, whole)."""

    def test_limited_run_does_not_break_the_next(self):
        d = os.path.join(self.d, "tree")
        os.mkdir(d)
        for n in os.listdir(HERE):
            if n.endswith(".py") and not n.startswith("test_"):
                shutil.copy(os.path.join(HERE, n), d)
        led = os.path.join(d, "ok.jsonl")
        shutil.copy(SAMPLE, led)
        for c in (["verify_evidence.py", "ledger", led], ["cryptovalid_merkle.py", "sth", led], ["signer.py", "verify", led]):
            sh('cd "$D"; ulimit -f 1; exec "$@" >/dev/null', [PY, os.path.join(d, c[0])] + c[1:], env=dict(ENV, D=d))
        rc, out, err = sh('exec "$@"', [PY, os.path.join(d, "verify_evidence.py"), "ledger", led])
        self.assertEqual(rc, 0, err[-300:])
        self.assertIs(json.loads(out)["valid"], True)
        self.assertFalse(os.path.isdir(os.path.join(d, "__pycache__")) and os.listdir(os.path.join(d, "__pycache__")),
                         "a command run as a script wrote a bytecode cache")


MODULE_CASES = (   # (name, argv after the script, code on a regular file)
    ("conformance.py", [], 0), ("cldma_confidential.py", [], 0), ("pedersen_commit.py", [], 0),
    ("cryptovalid_merkle.py", ["sth", SAMPLE], 0), ("cryptovalid_merkle.py", ["verify", SAMPLE, "1"], 0),
    ("eidas_ledger_check.py", [SAMPLE], 0), ("eidas_ledger_check.py", [SAMPLE, "--report"], 0),
    ("dora_incident.py", [], 2),
)


class TestModuleCommands(_Tmp):
    """every module with a __main__: the outcome on /dev/full is 74 with one line; on a file, the verdict's code"""

    def test_modules(self):
        for name, args, code in MODULE_CASES:
            cmd = [PY, os.path.join(HERE, name)] + args
            rc, out, err = sh('exec "$@"', cmd)
            self.assertEqual(rc, code, f"{name} {args}: {err[-300:]!r}")
            self.assertTrue(out)
            rc, _, err = sh('exec "$@" >/dev/full', cmd)
            self.assertOneLine74(rc, err, f"{name} {args}")
            rc, _, err = sh('exec "$@" >&-', cmd)
            self.assertOneLine74(rc, err, f"{name} {args} closed")

    def test_modules_with_keys(self):
        if not _crypto():
            self.skipTest("cryptography not installed")
        key = os.path.join(self.d, "k.key")
        pub = json.loads(subprocess.run([PY, os.path.join(HERE, "signer.py"), "keygen", key], check=True, capture_output=True,
                                        env=ENV).stdout)["public_key_hex"]
        cases = [("cryptovalid_receipt.py", ["sth", SAMPLE, key], 0), ("cryptovalid_jws.py", ["sign", SAMPLE, "0", key], 0),
                 ("cryptovalid_kms.py", ["pubkey", "--backend", "file:" + key], 0),
                 ("cryptovalid_checkpoint.py", ["vkey", "--key", key, "--name", "o"], 0),
                 ("evidence_pack.py", ["build", os.path.join(self.d, "p"), SAMPLE], 0)]
        for name, args, code in cases:
            cmd = [PY, os.path.join(HERE, name)] + args
            rc, out, err = sh('exec "$@"', cmd)
            self.assertEqual(rc, code, f"{name}: {err[-300:]!r}")
            rc, _, err = sh('exec "$@" >/dev/full', cmd)
            self.assertOneLine74(rc, err, name)
        self.assertTrue(pub)


class TestCheckThatCannotRun(_Tmp):
    """openssl that cannot be started (fork refused: RLIMIT_NPROC 1) or no temporary file for it (RLIMIT_FSIZE 0):
    exit 74 with one line, never `valid: false` or a traceback. The fixture is a real RFC 3161 token from a local TSA."""

    @classmethod
    def setUpClass(cls):
        if not shutil.which("openssl") or not _crypto():
            if os.environ.get("CV_REQUIRE_OPENSSL") == "1":
                raise RuntimeError("CV_REQUIRE_OPENSSL=1 and no openssl/cryptography")
            raise unittest.SkipTest("openssl or cryptography absent")
        cls.td = tempfile.mkdtemp(prefix="cv0203_tsa_")
        j = lambda n: os.path.join(cls.td, n)  # noqa: E731
        cnf = ("[ tsa ]\ndefault_tsa = t1\n[ t1 ]\nserial = {d}/serial\ncrypto_device = builtin\nsigner_cert = {d}/tsa.crt\n"
               "certs = {d}/ca.crt\nsigner_key = {d}/tsa.key\nsigner_digest = sha256\ndefault_policy = 1.2.3.4.1\n"
               "digests = sha256\naccuracy = secs:1\nordering = yes\ntsa_name = no\ness_cert_id_chain = no\n"
               "ess_cert_id_alg = sha256\n[ v3_tsa ]\nextendedKeyUsage = critical,timeStamping\nbasicConstraints = CA:FALSE\n")
        with open(j("tsa.cnf"), "w") as f:
            f.write(cnf.format(d=cls.td))
        with open(j("serial"), "w") as f:
            f.write("01\n")
        run = lambda *a: subprocess.run(list(a), check=True, capture_output=True)  # noqa: E731
        run("openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-keyout", j("ca.key"),
            "-out", j("ca.crt"), "-subj", "/CN=cv-ca", "-days", "2")
        run("openssl", "req", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-keyout", j("tsa.key"),
            "-out", j("tsa.csr"), "-subj", "/CN=cv-tsa")
        run("openssl", "x509", "-req", "-in", j("tsa.csr"), "-CA", j("ca.crt"), "-CAkey", j("ca.key"), "-CAcreateserial",
            "-out", j("tsa.crt"), "-days", "2", "-extfile", j("tsa.cnf"), "-extensions", "v3_tsa")
        sys.path.insert(0, HERE)
        import evidence_pack
        import base64
        pack = j("pack")
        evidence_pack.build_pack([SAMPLE], pack, subject="cv0203")
        man_p = os.path.join(pack, "MANIFEST.json")
        with open(man_p, encoding="utf-8") as f:
            man = json.load(f)
        run("openssl", "ts", "-query", "-digest", man["manifest_digest_sha256"], "-sha256", "-cert", "-out", j("q.tsq"))
        run("openssl", "ts", "-reply", "-queryfile", j("q.tsq"), "-config", j("tsa.cnf"), "-section", "t1", "-out", j("r.tsr"))
        with open(j("r.tsr"), "rb") as f:
            man["rfc3161_timestamp"] = {"anchored": True, "tsa": "local", "tsr_b64": base64.b64encode(f.read()).decode()}
        with open(man_p, "w", encoding="utf-8") as f:   # the stamp is outside manifest_digest_sha256, as build_pack writes it
            json.dump(man, f, ensure_ascii=False, indent=1, sort_keys=True)
        cls.pack = pack

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.td, True)

    def test_pack_check_not_run(self):
        ve = [PY, os.path.join(HERE, "verify_evidence.py"), "pack", self.pack]
        ep = [PY, os.path.join(HERE, "evidence_pack.py"), "verify", self.pack]
        rc, out, err = sh('exec "$@"', ve)
        self.assertEqual(rc, 0, out[-500:] + err[-300:])   # control: the token verifies, the pack is valid
        rc, out, err = sh('exec "$@"', ep)
        self.assertEqual((rc, json.loads(out)["rfc3161"]["verified"]), (0, True))
        for pre, why in (("ulimit -u 1; ", b"cannot run openssl here"), ("ulimit -f 0; ", b"cannot write a temporary file for openssl")):
            for cmd in (ve, ep):
                rc, out, err = sh(pre + 'exec "$@"', cmd, env=dict(ENV, TMPDIR=self.d))
                self.assertOneLine74(rc, err, f"{pre}{cmd[2]}")
                self.assertIn(why, err)
                self.assertEqual(out, b"")


if __name__ == "__main__":
    unittest.main(verbosity=2)
