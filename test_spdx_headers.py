# SPDX-License-Identifier: AGPL-3.0-or-later
"""Every tracked Python file names its licence in its first five lines (REUSE-style SPDX header): 52 of the files did
not on 14/11/2026, so a licence scanner reading files one by one could not attribute them."""
import os
import subprocess
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
HEADER = "SPDX-License-Identifier: AGPL-3.0-or-later"


def _tracked_py() -> list:
    """The repository's Python files: `git ls-files` in a checkout; in an unpacked sdist (PKG-INFO at the top, no git
    metadata), every .py it holds, since the sdist is the released file list (15/11/2026: the sdist carries the suite).
    Anywhere else: a failure that says so, never an empty list."""
    try:
        r = subprocess.run(["git", "-C", HERE, "ls-files", "*.py"], capture_output=True, text=True)
        if r.returncode == 0:
            return r.stdout.split()
        why = r.stderr.strip()
    except OSError as e:
        why = repr(e)
    if os.path.isfile(os.path.join(HERE, "PKG-INFO")):
        return sorted(os.path.relpath(os.path.join(d, f), HERE) for d, _, fs in os.walk(HERE)
                      if "__pycache__" not in d.split(os.sep) for f in fs if f.endswith(".py"))
    raise AssertionError(f"neither a git checkout nor an unpacked sdist: {why}")


class TestSpdxHeaders(unittest.TestCase):
    def test_every_python_file(self):
        files = _tracked_py()
        self.assertGreater(len(files), 100)
        missing = []
        for f in files:
            with open(os.path.join(HERE, f), encoding="utf-8", errors="replace") as fh:
                if not any(HEADER in fh.readline() for _ in range(5)):
                    missing.append(f)
        self.assertEqual(missing, [])


if __name__ == "__main__":
    unittest.main()
