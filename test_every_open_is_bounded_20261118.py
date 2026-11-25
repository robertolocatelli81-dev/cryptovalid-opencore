#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""SPEC v0.12 §5 step 0, the sentence about the readers kept true by construction (18/11/2026).

A review of 54fc7eb found the sentence "every reader" false: commands outside `cryptovalid-verify` still opened the
path they were given with open(), which waits without end on a FIFO that has no writer. A bench then replaced every
string argument of every command of this repository, one at a time, with a FIFO and with a link to /dev/zero (716
cases: 179 arguments of 44 commands in 22 modules; the network commands were not run): on 54fc7eb the command waited,
or read the device without bound, for 41 arguments that it reads (and for 6 that it writes, which this rule does not
cover).

1. `test_no_plain_open_of_a_path`: no module that is not a test opens a path for reading with open() or os.open()
   outside the closed list below (files the module has just written itself, directories, development tools). Every
   other read goes through verifier.open_regular / read_regular / read_text_regular / sha256_regular (a regular file
   only), verifier.open_ledger_input (the ledger of `verifier.py`) or verifier.read_input (what a writer reads: a
   regular file or a pipe, bounded in size and in idle time). A new open() of a path fails this test.
2. The readers the bench does not reach from a command line, called in a child process with a timeout.
3. What a writer reads: a pipe with a writer is read (`signer.py sign ledger out <(cat key)` works as before), a pipe
   with no writer is an error after FIFO_IDLE_SECONDS, a device is refused.

4. The other ways of loading a path (review of 55e2e3f): `test_no_other_load_of_a_path` keeps a second closed list
   (ctypes.CDLL, zipfile, pathlib read_text / read_bytes, shutil copies, imports by path), and the PKCS#11 module that
   `cryptovalid_kms` loads is judged on a descriptor before `dlopen`.

Positive control, measured: on 54fc7eb test 1 lists 52 calls outside the list and 6 of the first 7 tests fail (the
control of the scan passes); on 55e2e3f the PKCS#11 test fails (it does not return)."""
import ast
import glob
import json
import os
import shutil
import subprocess
import sys
import tempfile
import textwrap
import unittest

sys.dont_write_bytecode = True
ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)
ENV = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_platforms_20261124 import DEVICE, fifo, pipe_writer  # noqa: E402  (Windows: named pipes given by name, NUL)

# (file, the text of the call's first argument): the closed list of reads that are not of a path the caller gives
ALLOWED = {
    ("conformance.py", "exp_path"),                      # the expected verdict of a vector of this repository
    ("cryptovalid_ingest.py", "path"),                   # os.open of a DIRECTORY, to fsync it
    ("cryptovalid_witness.py", "os.path.dirname(os.path.abspath(path)) or '.'"),   # the same
    ("cryptovalid_tsa.py", "sp"),                        # the same (the signer openssl wrote)
    ("evidence_pack.py", "tsq"),                         # the same (the time-stamp query)
    ("verifier.py", "tmp"),                              # os.open of a temporary file to WRITE (O_EXCL)
    ("verifier.py", "os.path.join(here, 'pyproject.toml')"),   # this distribution's own version
    ("mutation_runner.py", "target_path"),               # development tools: the sources of this repository
    ("tools/check_stub.py", "stub"),
    ("tools/iso4217_table.py", "sys.argv[1]"),
    ("tools/misura_api.py", "os.path.join(root, 'pyproject.toml')"),
    ("tools/misura_api.py", "os.path.join(root, m + '.py')"),
    ("tools/misura_api.py", "os.path.join(root, path)"),
}


def plain_opens():
    """(file, first argument) of every open()/os.open() that reads a path, in the modules that are not tests"""
    files = sorted(f for f in glob.glob(os.path.join(ROOT, "*.py")) + glob.glob(os.path.join(ROOT, "cryptovalid", "*.py"))
                   + glob.glob(os.path.join(ROOT, "tools", "*.py")) if not os.path.basename(f).startswith("test_"))
    out = []
    for f in files:
        with open(f, encoding="utf-8") as fh:
            tree = ast.parse(fh.read())
        for node in ast.walk(tree):
            if not (isinstance(node, ast.Call) and node.args):
                continue
            fn = node.func
            name = fn.id if isinstance(fn, ast.Name) else fn.attr if isinstance(fn, ast.Attribute) else ""
            owner = fn.value.id if isinstance(fn, ast.Attribute) and isinstance(fn.value, ast.Name) else \
                ("" if isinstance(fn, ast.Name) else "?")
            if name != "open" or owner not in ("", "os", "io", "codecs"):
                continue
            first = node.args[0]
            if isinstance(first, ast.Name) and first.id == "fd":
                continue                                         # open(<a descriptor>): opened elsewhere, judged there
            text = ast.unparse(node)
            if owner == "os":
                if "O_NONBLOCK" in text or ("O_WRONLY" in text or "O_RDWR" in text or "flags" in text) and "tmp" not in text:
                    continue                                     # opened without blocking, or opened to write
            else:
                mode = node.args[1] if len(node.args) > 1 else next((k.value for k in node.keywords if k.arg == "mode"), None)
                if isinstance(mode, ast.Constant) and any(c in str(mode.value) for c in "wax+"):
                    continue                                     # opened to write
            out.append((os.path.relpath(f, ROOT).replace(os.sep, "/"), ast.unparse(first)))
    return out


# the other ways a module opens a path it is given (review of 55e2e3f: the scan above sees open() only, and
# ctypes.CDLL of the PKCS#11 module was found by hand): the closed list of such calls, (file, call, first argument)
OTHER_ALLOWED = {
    ("cryptovalid_kms.py", "CDLL", "module"),            # judged on a descriptor by verifier.open_regular just before
    ("fundcert_canonical.py", "ZipFile", "io.BytesIO(read_regular(path))"),   # bytes already read by read_regular
    ("mutation_runner.py", "copy", "target_path"),       # development tool: the sources of this repository
    ("mutation_runner.py", "copy", "bak"),
    ("tools/check_stub.py", "import_module", "argv[1]"),   # development tool: imports the package it checks
}
OTHER_LOADERS = {"CDLL", "PyDLL", "LoadLibrary", "dlopen", "ZipFile", "is_zipfile", "read_text", "read_bytes", "copy", "copy2",
                 "copyfile", "copytree", "import_module", "spec_from_file_location", "run_path", "fromfile", "memmap"}


def other_loads():
    """(file, call, first argument) of every call that loads or reads a path without open(), in the modules that are
    not tests; `tarfile.open` and the like are seen by plain_opens only when called as open(): named here too"""
    files = sorted(f for f in glob.glob(os.path.join(ROOT, "*.py")) + glob.glob(os.path.join(ROOT, "cryptovalid", "*.py"))
                   + glob.glob(os.path.join(ROOT, "tools", "*.py")) if not os.path.basename(f).startswith("test_"))
    out = []
    for f in files:
        with open(f, encoding="utf-8") as fh:
            tree = ast.parse(fh.read())
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            fn = node.func
            name = fn.id if isinstance(fn, ast.Name) else fn.attr if isinstance(fn, ast.Attribute) else ""
            owner = fn.value.id if isinstance(fn, ast.Attribute) and isinstance(fn.value, ast.Name) else ""
            if name in OTHER_LOADERS or (name == "open" and owner in ("tarfile", "zipfile", "gzip", "bz2", "lzma", "shelve", "dbm")):
                if name == "copy" and owner not in ("shutil",):
                    continue                                     # dict.copy(), list.copy()
                out.append((os.path.relpath(f, ROOT).replace(os.sep, "/"), name,
                            ast.unparse(node.args[0]) if node.args else ""))
    return out


def child(code: str, *args, timeout: int = 25):
    """(returncode, stdout + stderr) of `code` run with the repository on sys.path; 124 when it did not finish"""
    pre = "import sys, json, os\nsys.dont_write_bytecode = True\nsys.path.insert(0, %r)\n" % ROOT
    try:
        p = subprocess.run([sys.executable, "-c", pre + textwrap.dedent(code), *args], capture_output=True, text=True, encoding="utf-8",
                           timeout=timeout, env=ENV, stdin=subprocess.DEVNULL)
        return p.returncode, p.stdout + p.stderr
    except subprocess.TimeoutExpired:
        return 124, "timeout"


class ClosedList(unittest.TestCase):
    def test_no_plain_open_of_a_path(self):
        found = plain_opens()
        self.assertEqual(sorted(set(found) - ALLOWED), [], "a path opened for reading with open(): use verifier.read_regular "
                         "(a verifier) or verifier.read_input (a writer), SPEC §5 step 0")
        self.assertEqual(sorted(ALLOWED - set(found)), [], "an entry of the closed list no longer exists: remove it")

    def test_no_other_load_of_a_path(self):
        found = other_loads()
        self.assertEqual(sorted(set(found) - OTHER_ALLOWED), [], "a path loaded or read without open(): judge it first "
                         "with verifier.open_regular / read_regular, SPEC §5 step 0")
        self.assertEqual(sorted(OTHER_ALLOWED - set(found)), [], "an entry of the closed list no longer exists: remove it")

    def test_control_the_scan_sees_an_open(self):
        """the scan reports a plain open() of a path in a module made here (it is not blind)"""
        td = tempfile.mkdtemp()
        try:
            with open(os.path.join(td, "m.py"), "w", encoding="utf-8", newline="") as f:
                f.write("import os\ndef r(p):\n    with open(p, 'rb') as f:\n        return f.read()\n"
                        "def w(p):\n    open(p, 'w').close()\n    os.open(p, os.O_RDONLY | os.O_NONBLOCK)\n")
            global ROOT
            keep, ROOT = ROOT, td
            try:
                self.assertEqual(plain_opens(), [("m.py", "p")])
                with open(os.path.join(td, "m.py"), "a", encoding="utf-8", newline="") as f:
                    f.write("import ctypes, zipfile, shutil\ndef l(p):\n    ctypes.CDLL(p)\n    zipfile.ZipFile(p)\n"
                            "    shutil.copy(p, p + '.b')\n    {}.copy()\n")
                self.assertEqual(other_loads(), [("m.py", "CDLL", "p"), ("m.py", "ZipFile", "p"), ("m.py", "copy", "p")])
            finally:
                ROOT = keep
        finally:
            shutil.rmtree(td)


class NotReachedFromACommandLine(unittest.TestCase):
    """each reader is given a FIFO with no writer and a link to /dev/zero (Windows: a named pipe whose server never
    writes, and NUL): an OSError at once, never a wait"""

    def setUp(self):
        self.td = tempfile.mkdtemp()
        self.fifo = fifo(self, os.path.join(self.td, "fifo"))
        if os.name == "nt":
            self.zero = DEVICE
        else:
            self.zero = os.path.join(self.td, "zero")
            os.symlink("/dev/zero", self.zero)

    def tearDown(self):
        shutil.rmtree(self.td)

    CALLS = {
        "monitor --match": "import cryptovalid_monitor as M; M.find_matches(sys.argv[1], ['x'])",
        "tip check": "import cryptovalid_tip as T; T.chain_tip(sys.argv[1])",
        "worm get": "import cryptovalid_worm as W; s = W.LocalWormStore(sys.argv[2]); "
                    "s._path = lambda key: sys.argv[1]; s.get('k')",
        "qeas receipt": "import cryptovalid_qeas as Q; Q._read_text(sys.argv[1])",
        "fundcert csv": "import fundcert_crosssource as F; F._load(sys.argv[1], 'csv')",
        "fundcert nport": "import fundcert_crosssource as F; F._load(sys.argv[1], 'nport-xml')",
        "fundcert xlsx": "import fundcert_crosssource as F; F._load(sys.argv[1], 'ssga-xlsx')",
        "lotl cache": "import cryptovalid_lotl as L; L.load_qualified_status(cache_path=sys.argv[1])",
        "regulatory profiles": "import refresh_regulatory as R; R.refresh(sys.argv[1])",
        "witness state": "import cryptovalid_witness as W; W._load_state(sys.argv[1])",
        "ingest previous STH": "import verifier; verifier.read_text_regular(sys.argv[1])",
        "copy_output source": "import verifier; verifier.copy_output(sys.argv[1], sys.argv[1] + '.out')",
    }

    def test_each_reader(self):
        for name, code in self.CALLS.items():
            for bad in (self.fifo, self.zero):
                rc, out = child("""
                    try:
                        %s
                        print("READ")
                    except OSError as e:
                        print("OSError", type(e).__name__)
                    except Exception as e:
                        print("other", type(e).__name__, str(e)[:80])
                """ % code, bad, self.td)
                where = (name, os.path.basename(bad), out[-300:])
                self.assertNotEqual(rc, 124, where)
                self.assertNotIn("READ", out, where)
                self.assertNotIn("MemoryError", out, where)
                self.assertTrue("OSError InputNotRegular" in out or "other NoteError" in out, where)

    def test_monitor_sth_file(self):
        """--sth-file as a FIFO: not read, the monitor answers as for an STH it cannot use (0.26.0 and 54fc7eb: a wait)"""
        led = os.path.join(ROOT, "examples", "sample_ledger.jsonl")
        rc, out = child("""
            import cryptovalid_monitor as M
            try:
                r = M.run(sys.argv[1], sys.argv[2], trusted_pubkey_hex="ab" * 32, sth_path=sys.argv[3])
                print(json.dumps(sorted(r)))
            except ImportError:
                print(json.dumps(["no cryptography"]))
        """, led, os.path.join(self.td, "state.json"), self.fifo)
        self.assertEqual(rc, 0, out[-400:])


class WhatAWriterReads(unittest.TestCase):
    """Windows: the pipes are named pipes given by name (test_platforms_20261124.fifo, pipe_writer), the device NUL"""

    def setUp(self):
        self.td = tempfile.mkdtemp()
        self.fifo = fifo(self, os.path.join(self.td, "fifo"))

    def tearDown(self):
        shutil.rmtree(self.td)

    def test_read_input(self):
        import verifier
        reg = os.path.join(self.td, "r")
        with open(reg, "wb") as f:
            f.write(b"abc\r\ndef")
        self.assertEqual(verifier.read_input(reg), b"abc\r\ndef")
        self.assertEqual(verifier.read_input_text(reg), "abc\ndef")          # as open(path, encoding="utf-8") reads it
        with self.assertRaises(verifier.InputTooLarge):
            verifier.read_input(reg, 3)
        for dev in (DEVICE, self.td) + (() if os.name == "nt" else ("/dev/null",)):
            with self.assertRaises(verifier.InputNotRegular):
                verifier.read_input(dev)
        with self.assertRaises(FileNotFoundError):
            verifier.read_input(os.path.join(self.td, "absent"))

    def test_a_pipe_with_a_writer_is_read_and_one_without_is_an_error(self):
        slow, _ = pipe_writer(self, os.path.join(self.td, "slow"), [b"12", b"34"], 0.5)
        big, _ = pipe_writer(self, os.path.join(self.td, "big"), [b"12345"])
        rc, out = child("""
            import verifier
            got = verifier.read_input(sys.argv[1]).decode()
            try:
                verifier.read_input(sys.argv[2], 3, 1)
            except verifier.InputIdle:
                idle = True
            try:
                verifier.read_input(sys.argv[3], 3)
                big = False
            except verifier.InputTooLarge:
                big = True
            print(json.dumps([got, idle, big]))
        """, slow, self.fifo, big)
        self.assertEqual(rc, 0, out[-400:])
        self.assertEqual(json.loads(out), ["1234", True, True])

    def test_signer_sign_with_the_key_through_a_pipe(self):
        """`signer.py sign ledger out <(cat key)` works as before; a key path that is a FIFO with no writer is an error
        after FIFO_IDLE_SECONDS (0.26.0 and 54fc7eb: a wait without end), a device is refused at once"""
        try:
            import cryptography  # noqa: F401
        except ImportError:
            self.skipTest("signer.py needs cryptography")
        key, out1 = os.path.join(self.td, "k"), os.path.join(self.td, "o1.jsonl")
        led = os.path.join(ROOT, "examples", "sample_ledger.jsonl")
        signer = os.path.join(ROOT, "signer.py")
        subprocess.run([sys.executable, signer, "keygen", key], check=True, capture_output=True, env=ENV)
        subprocess.run([sys.executable, signer, "sign", led, out1, key], check=True, capture_output=True, env=ENV)
        with open(key, "rb") as f:
            fed, feeder = pipe_writer(self, os.path.join(self.td, "keypipe"), [f.read()])
        out2 = os.path.join(self.td, "o2.jsonl")
        p = subprocess.run([sys.executable, signer, "sign", led, out2, fed], capture_output=True, text=True, encoding="utf-8", env=ENV,
                           timeout=30)
        feeder.wait(30)
        self.assertEqual(p.returncode, 0, p.stderr[-300:])
        with open(out1, "rb") as a, open(out2, "rb") as b:
            self.assertEqual(a.read(), b.read())                 # Ed25519 is deterministic: the same signed ledger
        import time
        for bad, least in ((self.fifo, 9), (DEVICE, 0)):
            t = time.monotonic()
            try:
                p = subprocess.run([sys.executable, signer, "sign", led, os.path.join(self.td, "o3.jsonl"), bad],
                                   capture_output=True, text=True, encoding="utf-8", env=ENV, timeout=25)
            except subprocess.TimeoutExpired:
                self.fail(f"signer.py sign did not return on the key {bad}")
            self.assertNotEqual(p.returncode, 0, bad)
            self.assertGreaterEqual(time.monotonic() - t, least, bad)
            self.assertFalse(os.path.exists(os.path.join(self.td, "o3.jsonl")), bad)


class Pkcs11Module(unittest.TestCase):
    def test_module_path_fifo_is_refused_not_loaded(self):
        """review of 55e2e3f: ctypes.CDLL of a FIFO blocks in dlopen holding the GIL, so Pkcs11Backend.sign's own timeout
        never fired (measured: a backend with timeout=3 still waiting after 20 s). The module path is now judged on a
        descriptor opened without blocking before it is loaded."""
        td = tempfile.mkdtemp()
        try:
            pipe = fifo(self, os.path.join(td, "m.so"))   # Windows: a named pipe whose server never writes
            rc, out = child("""
                import cryptovalid_kms as K
                try:
                    K._p11_sign_direct(sys.argv[1], "t", "k", b"1", b"x")
                except RuntimeError as e:
                    print("refused:", e)
                """, pipe, timeout=15)
            self.assertEqual(rc, 0, out)
            self.assertIn("cannot be loaded", out)
        finally:
            shutil.rmtree(td)


if __name__ == "__main__":
    unittest.main()
