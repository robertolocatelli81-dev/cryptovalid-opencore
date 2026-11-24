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


if __name__ == "__main__":
    unittest.main()
