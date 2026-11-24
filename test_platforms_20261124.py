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


if __name__ == "__main__":
    unittest.main()
