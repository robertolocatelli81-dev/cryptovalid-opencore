# SPDX-License-Identifier: AGPL-3.0-or-later
"""Every tracked Python file names its licence in its first five lines (REUSE-style SPDX header): 52 of the files did
not on 14/11/2026, so a licence scanner reading files one by one could not attribute them."""
import os
import subprocess
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
HEADER = "SPDX-License-Identifier: AGPL-3.0-or-later"


class TestSpdxHeaders(unittest.TestCase):
    def test_every_python_file(self):
        files = subprocess.run(["git", "-C", HERE, "ls-files", "*.py"], capture_output=True, text=True, check=True).stdout.split()
        self.assertGreater(len(files), 100)
        missing = []
        for f in files:
            with open(os.path.join(HERE, f), encoding="utf-8", errors="replace") as fh:
                if not any(HEADER in fh.readline() for _ in range(5)):
                    missing.append(f)
        self.assertEqual(missing, [])


if __name__ == "__main__":
    unittest.main()
