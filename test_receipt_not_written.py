#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""A receipt that is not written whole is exit 74 (sysexits EX_IOERR), never the verdict's code (0.20.3).

Real processes, no mock of the write: each CLI runs with its stdout on /dev/full (ENOSPC), on a pipe whose read end is
already closed (EPIPE) and closed (`>&-`), on a valid and an invalid input. Expected: exit 74 and one stderr line
`receipt not written: <reason>`, no traceback. The control is the same command with stdout on a file: the verdict's exit
code (0/1) and a receipt that parses. On 0.20.2 these CLIs exit 120 (Python's final flush), 0/1 (stdout closed, Java)
or die of SIGPIPE: every loss case below fails there.

Python CLIs: verifier.py (default, --quiet, --out), verify_evidence.py (every subcommand), signer.py (verify, sign, keygen).
Java: verifiers/java/CvVerify.java, compiled with the JDK's javac when one is found (CV_REQUIRE_JAVA=1: a missing JDK is
a failure, not a skip). JS, Go, Rust and Swift have the same cases in their own suites.
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
PY = sys.executable
SAMPLE = os.path.join(HERE, "examples", "sample_ledger.jsonl")
TAMPERED = os.path.join(HERE, "examples", "sample_ledger_tampered.jsonl")
EX_IOERR = 74
LOSS_MODES = ("devfull", "epipe", "closed")


def run(cmd, mode, stderr_devfull=False, timeout=120):
    """Run `cmd` with stdout per `mode`; return (rc, stdout bytes or None, stderr bytes)."""
    err_target = open("/dev/full", "wb") if stderr_devfull else subprocess.PIPE
    try:
        if mode == "file":
            with tempfile.TemporaryFile() as f:
                p = subprocess.run(cmd, stdout=f, stderr=err_target, timeout=timeout)
                f.seek(0)
                return p.returncode, f.read(), p.stderr or b""
        if mode == "devfull":
            with open("/dev/full", "wb") as f:
                p = subprocess.run(cmd, stdout=f, stderr=err_target, timeout=timeout)
            return p.returncode, None, p.stderr or b""
        if mode == "epipe":   # the reader is gone before the first byte: EPIPE, deterministic (no race with `head`)
            r, w = os.pipe()
            os.close(r)
            try:
                p = subprocess.run(cmd, stdout=w, stderr=err_target, timeout=timeout)
            finally:
                os.close(w)
            return p.returncode, None, p.stderr or b""
        if mode == "closed":
            p = subprocess.run(["bash", "-c", 'exec "$@" >&-', "_"] + list(cmd), stderr=err_target, timeout=timeout)
            return p.returncode, None, p.stderr or b""
        raise ValueError(mode)
    finally:
        if stderr_devfull:
            err_target.close()


class _Base(unittest.TestCase):
    def assertLost(self, cmd, mode, label):
        rc, _, err = run(cmd, mode)
        self.assertEqual(rc, EX_IOERR, f"{label} [{mode}]: rc {rc}, stderr {err[-300:]!r}")
        self.assertIn(b"receipt not written: ", err, f"{label} [{mode}]")
        self.assertNotIn(b"Traceback", err, f"{label} [{mode}]")
        self.assertNotIn(b"Exception ignored", err, f"{label} [{mode}]")

    def assertWritten(self, cmd, code, label, verdict_key=None, verdict=None):
        rc, out, err = run(cmd, "file")
        self.assertEqual(rc, code, f"{label} [file]: rc {rc}, stderr {err[-300:]!r}")
        self.assertNotIn(b"receipt not written", err, label)
        if verdict_key is not None:
            self.assertEqual(json.loads(out)[verdict_key], verdict, label)
        return out

    def check(self, cmd, code, label, verdict_key=None, verdict=None):
        self.assertWritten(cmd, code, label, verdict_key, verdict)
        for mode in LOSS_MODES:
            self.assertLost(cmd, mode, label)


class TestVerifierPy(_Base):
    def test_default_receipt(self):
        self.check([PY, os.path.join(HERE, "verifier.py"), SAMPLE], 0, "verifier valid", "verdict", "PASS")
        self.check([PY, os.path.join(HERE, "verifier.py"), TAMPERED], 1, "verifier invalid", "verdict", "FAIL")

    def test_quiet(self):
        for path, code, word in ((SAMPLE, 0, b"PASS\n"), (TAMPERED, 1, b"FAIL\n")):
            cmd = [PY, os.path.join(HERE, "verifier.py"), path, "--quiet"]
            rc, out, _ = run(cmd, "file")
            self.assertEqual((rc, out), (code, word))
            for mode in LOSS_MODES:
                self.assertLost(cmd, mode, f"verifier --quiet {word!r}")

    def test_out_file_and_stdout_lost(self):
        d = tempfile.mkdtemp(prefix="cv74_")
        self.addCleanup(shutil.rmtree, d, True)
        f = os.path.join(d, "r.json")
        cmd = [PY, os.path.join(HERE, "verifier.py"), SAMPLE, "--out", f]
        out = self.assertWritten(cmd, 0, "verifier --out")
        self.assertEqual(json.loads(out)["verdict"], "PASS")
        for mode in LOSS_MODES:
            os.unlink(f)
            self.assertLost(cmd, mode, "verifier --out, stdout lost")
            with open(f, encoding="utf-8") as fh:   # the file receipt is still written whole
                self.assertEqual(json.load(fh)["verdict"], "PASS")

    def test_out_not_writable(self):
        d = tempfile.mkdtemp(prefix="cv74_")
        self.addCleanup(shutil.rmtree, d, True)
        for target in (os.path.join(d, "no", "such", "dir", "r.json"), "/dev/full", d):
            for path, verdict in ((SAMPLE, "PASS"), (TAMPERED, "FAIL")):
                rc, out, err = run([PY, os.path.join(HERE, "verifier.py"), path, "--out", target], "file")
                self.assertEqual(rc, EX_IOERR, f"--out {target}: rc {rc} {err[-300:]!r}")
                self.assertIn(b"receipt not written: ", err)
                self.assertNotIn(b"Traceback", err)
                self.assertEqual(json.loads(out)["verdict"], verdict)   # stdout still carries the receipt

    def test_stderr_also_full(self):
        # nowhere to say why: still 74, and nothing raised out of the interpreter
        for path in (SAMPLE, TAMPERED):
            rc, _, _ = run([PY, os.path.join(HERE, "verifier.py"), path], "devfull", stderr_devfull=True)
            self.assertEqual(rc, EX_IOERR)

    def test_large_receipt_slow_reader_whole(self):
        # a receipt larger than a pipe buffer, read late, still arrives whole (exit 1 = the verdict). signer.py verify
        # names every unsigned entry (no cap): 3 000 entries, a receipt of about 220 KB
        d = tempfile.mkdtemp(prefix="cv74_")
        self.addCleanup(shutil.rmtree, d, True)
        big = os.path.join(d, "big.jsonl")
        z = "0" * 64
        with open(big, "w") as fh:
            for i in range(3000):
                fh.write('{"ts":%d,"v":%d,"self_hash":"%s"}\n' % (i, i, z))
        p = subprocess.run(["bash", "-c", '"$0" "$1" verify "$2" | { sleep 0.5; cat; }; exit "${PIPESTATUS[0]}"',
                            PY, os.path.join(HERE, "signer.py"), big], capture_output=True, timeout=120)
        self.assertEqual(p.returncode, 1, p.stderr[-300:])
        self.assertGreater(len(p.stdout), 65536)
        self.assertIs(json.loads(p.stdout)["ok"], False)


class TestVerifyEvidence(_Base):
    def setUp(self):
        self.d = tempfile.mkdtemp(prefix="cv74_ve_")
        self.addCleanup(shutil.rmtree, self.d, True)
        self.empty_dir = os.path.join(self.d, "empty")
        os.mkdir(self.empty_dir)
        self.obj = os.path.join(self.d, "x.json")
        with open(self.obj, "w") as fh:
            fh.write("{}")

    def ve(self, *a):
        return [PY, os.path.join(HERE, "verify_evidence.py")] + list(a)

    def test_ledger_and_auto(self):
        for sub in ("ledger", "auto"):
            self.check(self.ve(sub, SAMPLE), 0, f"{sub} valid", "valid", True)
            self.check(self.ve(sub, TAMPERED), 1, f"{sub} invalid", "valid", False)

    def test_other_subcommands(self):
        # each one prints a receipt (valid: false here): the loss is 74 whatever the verdict
        for sub, path in (("pack", self.empty_dir), ("archive", self.empty_dir), ("ap2", self.obj), ("cldma", self.obj)):
            self.check(self.ve(sub, path), 1, f"{sub} invalid", "valid", False)

    def test_pack_valid(self):
        try:
            import cryptography  # noqa: F401
        except ImportError:
            if os.environ.get("CV_REQUIRE_CRYPTO") == "1":
                raise
            self.skipTest("cryptography not installed")
        sys.path.insert(0, HERE)
        import evidence_pack
        import signer
        key = os.path.join(self.d, "k.key")
        signed = os.path.join(self.d, "s.jsonl")
        signer.keygen(key)
        signer.sign_ledger(SAMPLE, signed, key)
        pack = os.path.join(self.d, "pack")
        evidence_pack.build_pack([signed], pack, subject="cv74", sign_key=key)
        self.check(self.ve("pack", pack), 0, "pack valid", "valid", True)


class TestSigner(_Base):
    def setUp(self):
        try:
            import cryptography  # noqa: F401
        except ImportError:
            if os.environ.get("CV_REQUIRE_CRYPTO") == "1":
                raise
            self.skipTest("cryptography not installed")
        self.d = tempfile.mkdtemp(prefix="cv74_sg_")
        self.addCleanup(shutil.rmtree, self.d, True)
        sys.path.insert(0, HERE)
        import signer
        self.key = os.path.join(self.d, "k.key")
        self.other = os.path.join(self.d, "o.key")
        self.pk = signer.keygen(self.key)["public_key_hex"]
        signer.keygen(self.other)
        self.good = os.path.join(self.d, "good.jsonl")
        self.bad = os.path.join(self.d, "bad.jsonl")
        signer.sign_ledger(SAMPLE, self.good, self.key)
        signer.sign_ledger(SAMPLE, self.bad, self.other)

    def test_verify(self):
        sg = os.path.join(HERE, "signer.py")
        self.check([PY, sg, "verify", self.good, "--pubkey", self.pk], 0, "signer verify valid", "ok", True)
        self.check([PY, sg, "verify", self.bad, "--pubkey", self.pk], 1, "signer verify invalid", "ok", False)

    def test_sign(self):
        sg = os.path.join(HERE, "signer.py")
        for mode in ("file",) + LOSS_MODES:
            out = os.path.join(self.d, f"signed_{mode}.jsonl")
            cmd = [PY, sg, "sign", SAMPLE, out, self.key]
            if mode == "file":
                self.assertWritten(cmd, 0, "sign")
            else:
                self.assertLost(cmd, mode, "sign")
            self.assertTrue(os.path.getsize(out) > 0)   # the signed ledger is written before the summary is printed

    def test_keygen(self):
        sg = os.path.join(HERE, "signer.py")
        for mode in ("file",) + LOSS_MODES:
            k = os.path.join(self.d, f"kg_{mode}.key")
            if mode == "file":
                self.assertWritten([PY, sg, "keygen", k], 0, "keygen")
            else:
                self.assertLost([PY, sg, "keygen", k], mode, "keygen")


def _jdk():
    home = os.environ.get("JAVA_HOME")
    cands = [os.path.join(home, "bin")] if home else []
    javac = next((os.path.join(c, "javac") for c in cands if os.path.exists(os.path.join(c, "javac"))), shutil.which("javac"))
    java = next((os.path.join(c, "java") for c in cands if os.path.exists(os.path.join(c, "java"))), shutil.which("java"))
    return javac, java


class TestJavaCvVerify(_Base):
    @classmethod
    def setUpClass(cls):
        javac, java = _jdk()
        if not (javac and java):
            if os.environ.get("CV_REQUIRE_JAVA") == "1":
                raise RuntimeError("CV_REQUIRE_JAVA=1 and no JDK (javac/java) found")
            raise unittest.SkipTest("no JDK")
        cls.cp = tempfile.mkdtemp(prefix="cv74_java_")
        subprocess.run([javac, "-d", cls.cp, os.path.join(HERE, "verifiers", "java", "CvVerify.java")], check=True,
                       capture_output=True)
        cls.java = java

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.cp, True)

    def test_receipt(self):
        j = [self.java, "-cp", self.cp, "CvVerify"]
        self.check(j + [SAMPLE], 0, "java valid", "verdict", "PASS")
        self.check(j + [TAMPERED], 1, "java invalid", "verdict", "FAIL")

    def test_stderr_also_full(self):
        rc, _, _ = run([self.java, "-cp", self.cp, "CvVerify", SAMPLE], "devfull", stderr_devfull=True)
        self.assertEqual(rc, EX_IOERR)


if __name__ == "__main__":
    unittest.main(verbosity=2)
