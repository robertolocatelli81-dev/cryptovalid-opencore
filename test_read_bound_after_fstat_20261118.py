#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""SPEC §5 step 0: `read_regular` and `sha256_regular` bound what they READ, not only the size `fstat` gave (a file that
grows after the fstat). Review of 18/11/2026: both checks survived the suite as mutants. A Linux /proc file is a
regular file whose st_size is 0 and whose read gives bytes: the case of a file larger than its fstat, made without a
race. Positive control, measured: with the check after the read removed, both tests fail. macOS and Windows have no such
file: there a regular file of 4096 bytes is given, with os.fstat answering size 0 for it (the same case, made by hand)."""
import os
import sys
import unittest

sys.dont_write_bytecode = True
ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)
import verifier  # noqa: E402

PROC = "/proc/self/status"
HAS_PROC = os.path.exists(PROC) and os.stat(PROC).st_size == 0


class BoundAfterFstat(unittest.TestCase):
    def setUp(self):
        global PROC
        if HAS_PROC:
            return
        import tempfile
        from unittest import mock
        fd, PROC = tempfile.mkstemp()
        os.write(fd, b"x" * 4096)
        os.close(fd)
        self.addCleanup(os.remove, PROC)
        real = os.fstat
        ino = os.stat(PROC).st_ino

        def fstat(n):   # the size of that file is 0 to fstat, as a /proc file's is
            st = real(n)
            if st.st_ino != ino:
                return st
            return os.stat_result(st[:6] + (0,) + st[7:10])
        p = mock.patch.object(os, "fstat", fstat)
        p.start()
        self.addCleanup(p.stop)

    def test_read_regular(self):
        with self.assertRaises(verifier.InputTooLarge):
            verifier.read_regular(PROC, 10)
        self.assertTrue(len(verifier.read_regular(PROC, 1 << 20)) > 10)   # control: within the bound it is read

    def test_sha256_regular(self):
        with self.assertRaises(verifier.InputTooLarge):
            verifier.sha256_regular(PROC, 10, block=4)
        self.assertEqual(len(verifier.sha256_regular(PROC, 1 << 20)), 64)

    def test_read_input(self):
        """the writers' reader (SPEC §5 step 0 (c)) on a regular file: the bound holds on what is read (review of 55e2e3f:
        this check survived as a mutant)"""
        with self.assertRaises(verifier.InputTooLarge):
            verifier.read_input(PROC, 10)
        self.assertTrue(len(verifier.read_input(PROC, 1 << 20)) > 10)


if __name__ == "__main__":
    unittest.main(verbosity=2)
