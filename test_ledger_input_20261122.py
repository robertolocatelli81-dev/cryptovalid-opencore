# SPDX-License-Identifier: AGPL-3.0-or-later
"""SPEC §22 rule 8 (2026-11-22): the JS, Go and Java verifiers read the ledger as §5 step 0 says for verifier.py. The
path is opened once without waiting for a writer and judged on what was opened: a regular file or a FIFO of at most
256 MiB is verified, a FIFO that gives no byte and no end of file for 10 s is `unreadable: FIFO idle for 10 s`, a
directory or a device is `unreadable: not a regular file`, more than 256 MiB is `input_too_large: file exceeds
268435456 bytes`; FAIL, exit 1, the same text in the four. Until then the three waited without end on a FIFO with no
writer, JS read a link to /dev/zero without end and Java until it had no memory left (`internal: OutOfMemoryError`),
and the three read /dev/null as an empty ledger. The Go writer
(cvappend) appends only to a regular file and reads its key file as §5 step 0 (c).

Needs no `cryptography`: the ledger is the unsigned example. A verifier whose toolchain is absent is not run."""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SAMPLE = os.path.join(HERE, "examples", "sample_ledger.jsonl")
BOUND = 256 * 1024 * 1024
IDLE = "unreadable: FIFO idle for 10 s"
NOT_REGULAR = "unreadable: not a regular file"
TOO_LARGE = f"input_too_large: file exceeds {BOUND} bytes"


def _verifiers(tmp):
    """{name: argv prefix} of the ledger verifiers whose toolchain is here (the reference always)."""
    out = {"python": [sys.executable, os.path.join(HERE, "verifier.py")]}
    if shutil.which("node"):
        out["js"] = ["node", os.path.join(HERE, "verifiers", "js", "cvverify.mjs")]
    if shutil.which("go"):
        b = os.path.join(tmp, "cvverify-go")
        subprocess.run(["go", "build", "-o", b, "./cmd/cvverify"], cwd=os.path.join(HERE, "verifiers", "go"), check=True,
                       capture_output=True)
        out["go"] = [b]
    home = os.environ.get("JAVA_HOME")
    javac = os.path.join(home, "bin", "javac") if home and os.path.exists(os.path.join(home, "bin", "javac")) else shutil.which("javac")
    java = os.path.join(home, "bin", "java") if home and os.path.exists(os.path.join(home, "bin", "java")) else shutil.which("java")
    if javac and java:
        cp = os.path.join(tmp, "cls")
        subprocess.run([javac, "-d", cp, os.path.join(HERE, "verifiers", "java", "CvVerify.java")], check=True,
                       capture_output=True)
        out["java"] = [java, "-cp", cp, "CvVerify"]
    return out


def _reason(name, doc):
    """the first reason of a receipt, where each verifier writes it"""
    if name == "python":
        errs = doc.get("parse_errors") or []
        return errs[0].get("error") if errs else None
    if name == "js":
        return doc.get("error")
    fails = doc.get("failures") or []
    return fails[0] if fails else None


def _verify(name, argv, path, timeout=60):
    """(exit code, verdict, first reason, seconds)"""
    t0 = time.monotonic()
    try:
        cp = subprocess.run(argv + [path], capture_output=True, text=True, timeout=timeout, stdin=subprocess.DEVNULL)
    except subprocess.TimeoutExpired:   # it waited: the defect of 2026-11-22 itself
        return "timeout", None, None, time.monotonic() - t0
    dt = time.monotonic() - t0
    try:
        doc = json.loads(cp.stdout)
    except ValueError:
        return cp.returncode, None, cp.stderr[:200], dt
    return cp.returncode, doc.get("verdict"), _reason(name, doc), dt


def _all(bins, path, feed=None):
    """each verifier on `path`, one after the other; `feed(path)` runs in a thread beside each (a FIFO's writer)"""
    out = {}
    for name, argv in bins.items():
        t = threading.Thread(target=feed, args=(path,), daemon=True) if feed else None
        if t:
            t.start()
        try:
            out[name] = _verify(name, argv, path)
        finally:
            if t:
                t.join(1)
                if t.is_alive():   # the verifier did not open the pipe: release the writer
                    try:
                        os.close(os.open(path, os.O_RDONLY | os.O_NONBLOCK))
                    except OSError:
                        pass
                    t.join(5)
    return out


@unittest.skipUnless(hasattr(os, "mkfifo"), "no FIFOs on this platform")
class TestTheLedgerInputInTheFourVerifiers(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        cls.bins = _verifiers(cls.tmp)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def path(self, name):
        p = os.path.join(self.tmp, name)
        if os.path.lexists(p):
            os.rmdir(p) if os.path.isdir(p) and not os.path.islink(p) else os.remove(p)
        return p

    def assertAll(self, got, want, what):
        for name, (rc, verdict, reason, _) in got.items():
            self.assertEqual((rc, verdict, reason), want, (what, name))

    def test_a_regular_file_is_verified_control(self):
        self.assertAll(_all(self.bins, SAMPLE), (0, "PASS", None), "the example ledger")

    def test_a_valid_line_of_65_mib_is_verified_in_the_four(self):
        """NEMESIS R3 (22/11): until 0.28.0 JS ended in `JavaScript heap out of memory` (exit 134, no receipt) and Go
        was FAIL `token too long` on this ledger, which verifier.py and Java verify; one byte changed is FAIL in the four."""
        sys.path.insert(0, HERE)
        import verifier
        e = {"idx": 0, "ts": "2026-11-22T15:00:00Z", "data": "x" * (65 << 20), "prev_hash": "0" * 64}
        e["self_hash"] = verifier.hash_with("sha256", verifier.canonical_payload(e))
        p = self.path("line65.jsonl")
        with open(p, "w") as f:
            f.write(json.dumps(e, separators=(",", ":")) + "\n")
        del e
        self.assertAll(_all(self.bins, p), (0, "PASS", None), "one valid line of 65 MiB")
        with open(p, "r+b") as f:
            f.seek(1 << 20)
            f.write(b"y")
        for name, (rc, verdict, _, _) in _all(self.bins, p).items():
            self.assertEqual((rc, verdict), (1, "FAIL"), name)

    def test_every_character_below_0x80_in_a_string_is_verified_in_the_four(self):
        """the canonical form of the JS verifier is one regex since 0.28.0: each control character, DEL (escaped as
        \\u007f), the short escapes and characters past the BMP give the bytes verifier.py hashes"""
        sys.path.insert(0, HERE)
        import verifier
        e = {"idx": 0, "ts": "2026-11-22T15:00:00Z", "data": "".join(map(chr, range(0x80))) + "\x80\xff\u2028\ufeff\U0001f600",
             "prev_hash": "0" * 64}
        e["self_hash"] = verifier.hash_with("sha256", verifier.canonical_payload(e))
        p = self.path("ascii.jsonl")
        for ensure_ascii in (True, False):
            with open(p, "w", encoding="utf-8") as f:
                f.write(json.dumps(e, ensure_ascii=ensure_ascii) + "\n")
            self.assertAll(_all(self.bins, p), (0, "PASS", None), "every character below 0x80")

    def test_a_fifo_with_no_writer_is_idle_after_10_s(self):
        fifo = self.path("idle.fifo")
        os.mkfifo(fifo)
        out, threads = {}, []
        for name, argv in self.bins.items():   # side by side: each waits its 10 s
            th = threading.Thread(target=lambda n=name, a=argv: out.__setitem__(n, _verify(n, a, fifo)))
            th.start()
            threads.append(th)
        for th in threads:
            th.join(90)
        for name, (rc, verdict, reason, dt) in out.items():
            self.assertEqual((rc, verdict, reason), (1, "FAIL", IDLE), name)
            self.assertGreaterEqual(dt, 9.5, name)
            self.assertLess(dt, 18, name)   # one wait of 10 s, not two

    def test_a_fifo_whose_writer_holds_it_without_a_byte_is_idle(self):
        fifo = self.path("held.fifo")
        os.mkfifo(fifo)

        def hold(p):
            fd = os.open(p, os.O_WRONLY)   # waits for the verifier, then gives nothing for 20 s
            time.sleep(20)
            os.close(fd)
        for name, (rc, verdict, reason, dt) in _all(self.bins, fifo, hold).items():
            self.assertEqual((rc, verdict, reason), (1, "FAIL", IDLE), name)
            self.assertLess(dt, 15, name)   # it ends at the first 10 s, not when the writer goes

    def test_a_fifo_whose_writer_leaves_without_a_byte_is_empty_at_once(self):
        fifo = self.path("empty.fifo")
        os.mkfifo(fifo)

        def leave(p):   # opens the FIFO after the verifier, gives nothing, closes after 2 s: the end, not an idle FIFO
            fd = os.open(p, os.O_WRONLY)
            time.sleep(2)
            os.close(fd)
        for name, (rc, verdict, reason, dt) in _all(self.bins, fifo, leave).items():
            self.assertEqual((rc, verdict), (1, "FAIL"), name)
            self.assertNotEqual(reason, IDLE, name)
            self.assertLess(dt, 8, name)

    def test_a_device_or_a_directory_is_not_read(self):
        d = self.path("dir")
        os.mkdir(d)
        z = self.path("zero")
        os.symlink("/dev/zero", z)
        for p in ("/dev/null", z, d):
            if os.path.exists(p):
                self.assertAll(_all(self.bins, p), (1, "FAIL", NOT_REGULAR), p)

    def test_a_file_larger_than_the_bound(self):
        big = self.path("big.jsonl")
        with open(big, "wb") as f:   # sparse: no disk used
            f.truncate(BOUND + 1)
        for name, (rc, verdict, reason, dt) in _all(self.bins, big).items():
            self.assertEqual((rc, verdict, reason), (1, "FAIL", TOO_LARGE), name)
            self.assertLess(dt, 4, name)   # judged on its size, not read (Java read it through in 6.8 s when it was not)

    def test_a_fifo_larger_than_the_bound(self):
        fifo = self.path("big.fifo")
        os.mkfifo(fifo)

        def feed(p):
            try:
                with open(p, "wb") as w:
                    block = b"\0" * (1 << 20)
                    for _ in range(257):   # 257 MiB: the verifier stops past 256 MiB and closes
                        w.write(block)
            except OSError:   # BrokenPipeError: the reader stopped at the bound
                pass
        self.assertAll(_all(self.bins, fifo, feed), (1, "FAIL", TOO_LARGE), "a FIFO of 257 MiB")

    def test_exactly_the_bound_is_within_it(self):
        """256 MiB exactly is read, as a file and through a FIFO, and fails at §5 step 1 (it holds no entry). The file is
        given to the four: until 0.28.0 Go stopped at its line bound (`token too long`). The FIFO only to Java: its bound
        is reached with 256 MiB alone, where the Go and JS readers take the bound as an argument (input_test.go,
        test.mjs: 10 and 16 bytes) and verifier.py has its own tests."""
        at = self.path("at.jsonl")
        with open(at, "wb") as f:   # sparse: no disk used
            f.truncate(BOUND)
        for name, (rc, verdict, reason, _) in _all(self.bins, at).items():
            self.assertEqual((rc, verdict), (1, "FAIL"), name)
            self.assertNotIn(reason, (TOO_LARGE, "read: bufio.Scanner: token too long"), name)
        if "java" not in self.bins:
            self.skipTest("the FIFO needs the Java toolchain")
        fifo = self.path("at.fifo")
        os.mkfifo(fifo)

        def feed(p):
            try:
                with open(p, "wb") as w:
                    block = b"\0" * (1 << 20)
                    for _ in range(256):
                        w.write(block)
            except OSError:
                pass
        java = {"java": self.bins["java"]}
        for what, got in (("a file", _all(java, at)), ("a FIFO", _all(java, fifo, feed))):
            rc, verdict, reason, _ = got["java"]
            self.assertEqual((rc, verdict), (1, "FAIL"), what)
            self.assertNotEqual(reason, TOO_LARGE, what)

    def test_a_fifo_whose_writer_comes_late_is_read_control(self):
        fifo = self.path("late.fifo")
        os.mkfifo(fifo)
        with open(SAMPLE, "rb") as f:
            data = f.read()

        def late(p):
            time.sleep(2)   # the verifier has opened the FIFO and waits: on Linux it reads as its end until a writer comes
            with open(p, "wb") as w:
                w.write(data)
        self.assertAll(_all(self.bins, fifo, late), (0, "PASS", None), "a writer 2 s late")

    def test_a_fifo_whose_writer_is_slow_is_read_control(self):
        fifo = self.path("slow.fifo")
        os.mkfifo(fifo)
        with open(SAMPLE, "rb") as f:
            lines = f.read().splitlines(keepends=True)

        def slow(p):   # a line every 6 s, 12 s in all: only the wait for a byte is bounded
            with open(p, "wb", buffering=0) as w:
                for i, chunk in enumerate((b"".join(lines[:1]), b"".join(lines[1:2]), b"".join(lines[2:]))):
                    if i:
                        time.sleep(6)
                    w.write(chunk)
        self.assertGreaterEqual(len(lines), 3)
        self.assertAll(_all(self.bins, fifo, slow), (0, "PASS", None), "a writer that gives a line every 6 s")

    def test_a_tip_that_is_a_fifo_is_refused_at_once(self):
        """SPEC §22 rule 2 row 1: a tip is a regular file; a FIFO is refused without a wait, in Java too (its reader
        takes a FIFO for the ledger only)"""
        led = self.path("t.jsonl")
        shutil.copyfile(SAMPLE, led)
        tip = self.path("t.jsonl.tip.json")
        os.mkfifo(tip)
        key = "58" + "66" * 31   # any key: row 1 comes before the signature
        for name, argv in self.bins.items():
            flag = "--trusted-pubkey" if name in ("python", "js") else "-trusted-pubkey"
            args = argv + ([led, flag, key] if name in ("python", "js") else [flag, key, led])
            t0 = time.monotonic()
            cp = subprocess.run(args, capture_output=True, text=True, timeout=60, stdin=subprocess.DEVNULL)
            doc = json.loads(cp.stdout).get("tip") or {}
            self.assertEqual((cp.returncode, doc.get("error") if name in ("python", "js") else doc.get("why")),
                             (1, "tip_unreadable: the tip file cannot be read"), name)
            self.assertLess(time.monotonic() - t0, 8, name)

    @unittest.skipUnless(shutil.which("bash"), "needs bash for <(...)")
    def test_process_substitution_is_read_control(self):
        for name, argv in self.bins.items():
            cp = subprocess.run(["bash", "-c", '"$@" <(cat "$0")', SAMPLE] + argv, capture_output=True, text=True,
                                timeout=60)
            self.assertEqual((cp.returncode, json.loads(cp.stdout)["verdict"]), (0, "PASS"), name)


def _cap_memory():
    """512 MiB of data for the writer: a writer that reads /dev/zero without end (the code before 2026-11-22) then dies
    at once instead of growing to 5 GB until the system's OOM killer takes the whole session with it"""
    import resource
    resource.setrlimit(resource.RLIMIT_DATA, (512 << 20, 512 << 20))


@unittest.skipUnless(hasattr(os, "mkfifo") and shutil.which("go"), "needs FIFOs and the Go toolchain")
class TestTheGoWriterInputs(unittest.TestCase):
    """SPEC §5 step 0 (a) and (c), §22 rule 8: cvappend appends to a regular file only, and reads -tipkey as a regular
    file or a FIFO of at most 1 MiB. Until 2026-11-22 a FIFO as the key waited without end, a link to /dev/zero as the
    key was read until the process was killed, and a link to /dev/zero as the ledger was written to."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        cls.bin = os.path.join(cls.tmp, "cvappend")
        subprocess.run(["go", "build", "-o", cls.bin, "./cmd/cvappend"], cwd=os.path.join(HERE, "verifiers", "go"),
                       check=True, capture_output=True)
        cls.key = os.path.join(cls.tmp, "seed.hex")
        with open(cls.key, "w") as f:
            f.write("11" * 32 + "\n")

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def append(self, ledger, key=None):
        argv = [self.bin] + (["-tipkey", key] if key else []) + [ledger, "2026-11-22T00:00:00Z"]
        cp = subprocess.run(argv, input='{"a":1}', capture_output=True, text=True, timeout=60, preexec_fn=_cap_memory)
        return cp.returncode, cp.stderr.strip()

    def test_the_ledger_is_a_regular_file(self):
        d = os.path.join(self.tmp, "dir")
        os.mkdir(d)
        z = os.path.join(self.tmp, "zero")
        os.symlink("/dev/zero", z)
        f = os.path.join(self.tmp, "l.fifo")
        os.mkfifo(f)
        for p in (z, f):
            self.assertEqual(self.append(p), (1, f"{p}: {NOT_REGULAR}"), p)
        rc, err = self.append(d)   # a directory: opening it to write is the system's error
        self.assertEqual(rc, 1)
        self.assertTrue(err.endswith("is a directory"), err)

    def test_the_key_file(self):
        led = os.path.join(self.tmp, "k.jsonl")
        z = os.path.join(self.tmp, "kzero")
        os.symlink("/dev/zero", z)
        d = os.path.join(self.tmp, "kdir")
        os.mkdir(d)
        for p in (z, d):   # a device or a directory: not read (until 2026-11-22 /dev/zero was read until the kill)
            self.assertEqual(self.append(led, p), (2, NOT_REGULAR), p)
        big = os.path.join(self.tmp, "kbig")
        with open(big, "wb") as fh:
            fh.truncate((1 << 20) + 1)
        self.assertEqual(self.append(led, big), (2, "input_too_large: file exceeds 1048576 bytes"))
        f = os.path.join(self.tmp, "k.fifo")
        os.mkfifo(f)
        t0 = time.monotonic()
        self.assertEqual(self.append(led, f), (2, IDLE))
        self.assertGreaterEqual(time.monotonic() - t0, 9.5)
        self.assertFalse(os.path.exists(led), "nothing appended when the key cannot be read")
        # control: the same seed through a FIFO with a writer, and as a regular file
        def give_key():
            with open(f, "w") as w:
                w.write("11" * 32 + "\n")
        threading.Thread(target=give_key, daemon=True).start()
        rc, _ = self.append(led, f)
        self.assertEqual(rc, 0)
        self.assertEqual(self.append(led, self.key)[0], 0)
        with open(led) as fh:
            self.assertEqual(len(fh.readlines()), 2)


if __name__ == "__main__":
    unittest.main()
