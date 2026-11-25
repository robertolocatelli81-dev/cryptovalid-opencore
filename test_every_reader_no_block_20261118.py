#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""SPEC v0.12 §5 step 0 (18/11/2026): every file a verifier of this repository reads from a path is opened once without
blocking and judged on the open descriptor: the files INSIDE a pack or an archive too, the tip, the ledger given to
`signer.py verify`, and the readers that checked with os.stat / os.lstat and then opened.

Measured on 2026-11-18 on e5037e0 by replacing, one at a time, every file of an evidence pack, of an ingest archive
and of a tile directory with a FIFO, a link to /dev/zero and a directory, and running the commands on it (100 cases): `cryptovalid-verify pack`
and `auto` on a pack whose MANIFEST.json is a FIFO did not return (evidence_pack.verify_pack refused it, then the
front-end opened the manifest again), `cryptovalid-verify archive` and `auto` on an archive whose *.sth.json or
*.head.json is a FIFO did not return, and `signer.py verify <a FIFO>` did not return. `verifier.py --tip <a FIFO>
--trusted-pubkey ...` did not return either. The readers of cryptovalid_beacon, cryptovalid_checkpoint, the tiles and
`auto` checked with os.stat / os.lstat and then opened: a FIFO put at the path between the two was waited on.

Every case runs in a child process with a timeout: a regression is a failure (exit 124), not a hung suite.
Positive control: on e5037e0 9 of the 10 tests fail (the control passes). Linux (mkfifo, /dev/zero)."""
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
# Linux and macOS have all of it (mkfifo, /dev/zero, ru_maxrss); Windows has no FIFO at a name in a directory
LINUX = unittest.skipUnless(hasattr(os, "mkfifo"), "a FIFO at a name inside a directory and a link to /dev/zero: POSIX only")
ENV = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
KINDS = ("fifo", "devzero", "dir")


def run(argv, timeout=40):
    """(returncode, stdout + stderr); returncode 124 when it did not finish"""
    try:
        p = subprocess.run([sys.executable] + argv, capture_output=True, text=True, encoding="utf-8", timeout=timeout, env=ENV,
                           stdin=subprocess.DEVNULL)
        return p.returncode, p.stdout + p.stderr
    except subprocess.TimeoutExpired:
        return 124, "timeout"


def child(code: str, *args, timeout: int = 20):
    pre = "import sys, json, os, stat\nsys.dont_write_bytecode = True\nsys.path.insert(0, %r)\n" % ROOT
    return run(["-c", pre + textwrap.dedent(code), *args], timeout)


def put(path: str, kind: str):
    """replace what is at `path` with a FIFO (no writer), a link to /dev/zero or a directory"""
    if os.path.lexists(path):
        os.remove(path)
    if kind == "fifo":
        os.mkfifo(path)
    elif kind == "devzero":
        os.symlink("/dev/zero", path)
    else:
        os.mkdir(path)


@LINUX
class InsideADirectory(unittest.TestCase):
    """every file of a pack and of an archive, replaced one at a time"""

    @classmethod
    def setUpClass(cls):
        cls.td = tempfile.mkdtemp()
        cls.pack, cls.arch = os.path.join(cls.td, "pack"), os.path.join(cls.td, "arch")
        os.mkdir(cls.arch)
        rc, out = child("""
            import evidence_pack as E, cryptovalid_ingest as I
            E.build_pack([os.path.join(%r, "examples", "sample_ledger.jsonl")], sys.argv[1])
            w = I.Ingestor(sys.argv[2], batch_size=4, rotate_entries=100)
            for i in range(8):
                w.append({"i": i})
            w.close(seal=True)
        """ % ROOT, cls.pack, cls.arch, timeout=60)
        assert rc == 0, out[-800:]

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.td)

    def variants(self, src):
        """(file, kind, directory): a copy of `src` where `file` is of `kind`"""
        names = sorted(os.listdir(src))
        self.assertGreaterEqual(len(names), 3, names)
        for name in names:
            for kind in KINDS:
                d = tempfile.mkdtemp(dir=self.td)
                dst = os.path.join(d, "x")
                shutil.copytree(src, dst)
                put(os.path.join(dst, name), kind)
                yield name, kind, dst

    def check(self, src, commands, must_fail):
        n = 0
        for name, kind, dst in self.variants(src):
            for label, argv in commands:
                rc, out = run([a if a != "@" else dst for a in argv])
                where = (label, name, kind, out[-300:])
                self.assertNotEqual(rc, 124, where)                     # it returned
                self.assertNotIn("Traceback", out, where)               # with a receipt or a named error
                self.assertIn(rc, (0, 1), where)
                if must_fail(name):
                    self.assertEqual(rc, 1, where)
                n += 1
        return n

    def test_control_the_pack_and_the_archive_are_valid(self):
        for cmd, d in (("pack", self.pack), ("archive", self.arch), ("auto", self.pack), ("auto", self.arch)):
            rc, out = run([os.path.join(ROOT, "verify_evidence.py"), cmd, d])
            self.assertEqual(rc, 0, (cmd, out[-300:]))
            self.assertIs(json.loads(out)["valid"], True)

    def test_every_file_of_a_pack(self):
        ve = os.path.join(ROOT, "verify_evidence.py")
        n = self.check(self.pack, [("pack", [ve, "pack", "@"]), ("auto", [ve, "auto", "@"]),
                                   ("evidence_pack verify", [os.path.join(ROOT, "evidence_pack.py"), "verify", "@"])],
                       lambda name: name != "SUMMARY.md")   # SUMMARY.md is for people: not listed in the manifest, not read
        self.assertEqual(n, 3 * 3 * 3)

    def test_every_file_of_an_archive(self):
        ve = os.path.join(ROOT, "verify_evidence.py")
        sealed = [f for f in os.listdir(self.arch) if f.endswith(".sth.json")]
        self.assertEqual(len(sealed), 1, sealed)
        self.assertEqual(len(os.listdir(self.arch)), 4, os.listdir(self.arch))   # segment, its STH, the open segment, HEAD
        open_segment = max(f for f in os.listdir(self.arch) if f.endswith(".jsonl"))   # the segment still open: not sealed, not read
        n = self.check(self.arch, [("archive", [ve, "archive", "@"]), ("auto", [ve, "auto", "@"])],
                       lambda name: name != open_segment)
        self.assertEqual(n, 4 * 3 * 2)

    def test_a_token_of_an_archive(self):
        """<segment>.sth.tsr of every kind: a named failure of the archive (tsa_token_invalid), never read without end"""
        seg = [f for f in os.listdir(self.arch) if f.endswith(".sth.json")][0][:-len(".sth.json")]
        for kind in KINDS:
            d = tempfile.mkdtemp(dir=self.td)
            dst = os.path.join(d, "x")
            shutil.copytree(self.arch, dst)
            put(os.path.join(dst, seg + ".sth.tsr"), kind)
            rc, out = child("""
                import cryptovalid_ingest as I
                r = I.verify_archive(sys.argv[1])
                print(json.dumps([r["ok"], [f for f in r["failures"] if f["reason"].startswith("tsa")]]))
            """, dst)
            self.assertEqual(rc, 0, (kind, out[-300:]))
            valid, fails = json.loads(out)
            self.assertIs(valid, False, kind)
            self.assertEqual([f["reason"] for f in fails], ["tsa_token_invalid"], kind)
            self.assertTrue(fails[0]["detail"].startswith("unreadable: "), fails)


@LINUX
class OnePath(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.mkdtemp()
        self.fifo = os.path.join(self.td, "fifo")
        os.mkfifo(self.fifo)
        self.ledger = os.path.join(ROOT, "examples", "sample_ledger.jsonl")

    def tearDown(self):
        shutil.rmtree(self.td)

    def test_signer_verify(self):
        """`signer.py verify`: a FIFO, a device, a directory, an absent path are named, exit 1 (0.26.0: a wait or a
        traceback); a regular ledger is read as before"""
        for path in (self.fifo, "/dev/zero", self.td, os.path.join(self.td, "absent")):
            rc, out = run([os.path.join(ROOT, "signer.py"), "verify", path])
            self.assertEqual(rc, 1, (path, out[-300:]))
            self.assertNotIn("Traceback", out, path)
            r = json.loads(out)
            self.assertIs(r["ok"], False)
            self.assertTrue(r["error"].startswith("unreadable: "), r)
        try:
            import cryptography  # noqa: F401
        except ImportError:
            return   # the control needs the signature backend: signer.py verify cannot run without it
        rc, out = run([os.path.join(ROOT, "signer.py"), "verify", self.ledger])
        self.assertNotIn("Traceback", out)
        self.assertNotIn("unreadable", out)

    def test_tip(self):
        """--tip <a FIFO> with a trusted key: tip_unreadable, FAIL (0.26.0: a wait)"""
        for path in (self.fifo, "/dev/zero", self.td):
            rc, out = run([os.path.join(ROOT, "verifier.py"), self.ledger, "--tip", path, "--trusted-pubkey", "ab" * 32])
            self.assertEqual(rc, 1, (path, out[-300:]))
            self.assertNotIn("Traceback", out, path)
            self.assertIn("tip_unreadable", out, path)

    def window(self, code, lie="stat"):
        """os.stat (or os.lstat) made to see a regular file of 10 bytes where the FIFO is: the window between the check
        and the open of 0.26.0"""
        return child(textwrap.dedent("""
            real = os.%s
            class S: st_mode = stat.S_IFREG | 0o644; st_size = 10
            os.%s = lambda q, *a, **k: S() if q == sys.argv[1] else real(q, *a, **k)
        """ % (lie, lie)) + textwrap.dedent(code), self.fifo)

    def test_beacon_reader_in_the_window(self):
        rc, out = self.window("""
            import cryptovalid_beacon as B
            try:
                B._read(sys.argv[1], "pulse", 1000)
            except B.Refused as e:
                print(json.dumps([e.reason, e.detail]))
        """)
        self.assertEqual(rc, 0, out[-300:])
        self.assertEqual(json.loads(out), ["input_unreadable", "pulse: not a regular file"])

    def test_note_reader_in_the_window(self):
        rc, out = self.window("""
            import cryptovalid_checkpoint as C
            try:
                C.read_note_file(sys.argv[1])
            except C.NoteError as e:
                print(json.dumps(str(e)))
        """)
        self.assertEqual(rc, 0, out[-300:])
        self.assertIn("not a regular file", json.loads(out))

    def test_tile_reader_in_the_window(self):
        rc, out = self.window("""
            import cryptovalid_merkle as M
            try:
                M._read_file(sys.argv[1])
            except M.TileError as e:
                print(json.dumps(str(e)))
        """, lie="lstat")
        self.assertEqual(rc, 0, out[-300:])
        self.assertIn("not a regular file", json.loads(out))

    def test_auto_in_the_window(self):
        rc, out = self.window("""
            import verify_evidence as V
            r = V.verify_auto(sys.argv[1])
            print(json.dumps([r["valid"], r["layers"][0]["detail"]]))
        """)
        self.assertEqual(rc, 0, out[-300:])
        valid, detail = json.loads(out)
        self.assertIs(valid, False)
        self.assertIn("not a regular file", detail)


if __name__ == "__main__":
    unittest.main()
