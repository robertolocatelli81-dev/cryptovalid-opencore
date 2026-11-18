#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""SPEC §5 step 0: `read_regular` and `sha256_regular` bound what they READ, not only the size `fstat` gave (a file that
grows after the fstat). Review of 18/11/2026: both checks survived the suite as mutants. A Linux /proc file is a
regular file whose st_size is 0 and whose read gives bytes: the case of a file larger than its fstat, made without a
race. Positive control, measured: with the check after the read removed, both tests fail."""
import os
import sys
import unittest

sys.dont_write_bytecode = True
ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)
import verifier  # noqa: E402

PROC = "/proc/self/status"
NEEDS = unittest.skipUnless(os.path.exists(PROC) and os.stat(PROC).st_size == 0, "needs a Linux /proc file of size 0")


@NEEDS
class BoundAfterFstat(unittest.TestCase):
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
