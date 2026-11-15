#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""`--version` and the command's own name (15/11/2026). Until 0.24.0 neither `cryptovalid-verify` nor `verifier.py`
had a `--version`, and the help of `cryptovalid-verify` called itself `verify_evidence` (measured on an installed
wheel). The version comes from the pyproject.toml of a source checkout (said as such: an installed copy of another
version must not answer for the files that run), else from the installed distribution's metadata, else "unknown"."""
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)


def _pyproject_version():
    with open(os.path.join(HERE, "pyproject.toml"), encoding="utf-8") as f:
        return re.search(r'^version\s*=\s*"([^"]+)"', f.read(), re.M).group(1)


def _run(args, stdout=subprocess.PIPE, cwd=HERE):
    env = {k: v for k, v in os.environ.items() if k not in ("PYTHONPATH", "PYTHONHOME", "PYTHONSTARTUP")}
    return subprocess.run([sys.executable, *args], cwd=cwd, env=env, stdout=stdout, stderr=subprocess.PIPE,
                          text=True, timeout=120)


class TestVersion(unittest.TestCase):
    def test_both_front_ends_print_their_version_on_stdout(self):
        want = f"{_pyproject_version()} (source checkout, from pyproject.toml)\n"
        for script, prog in (("verify_evidence.py", "cryptovalid-verify"), ("verifier.py", "verifier.py")):
            with self.subTest(script=script):
                r = _run([os.path.join(HERE, script), "--version"])
                self.assertEqual((r.returncode, r.stdout, r.stderr), (0, f"{prog} {want}", ""))

    def test_the_help_names_the_installed_command(self):
        r = _run([os.path.join(HERE, "verify_evidence.py"), "--help"])
        self.assertEqual(r.returncode, 0)
        self.assertTrue(r.stdout.startswith("usage: cryptovalid-verify "), r.stdout[:80])
        self.assertNotIn("verify_evidence", r.stdout)
        self.assertIn("--version", r.stdout)

    @unittest.skipUnless(os.path.exists("/dev/full"), "needs /dev/full")
    def test_a_version_not_written_is_exit_74(self):
        for script in ("verify_evidence.py", "verifier.py"):
            with open("/dev/full", "w") as full:
                r = _run([os.path.join(HERE, script), "--version"], stdout=full)
            self.assertEqual(r.returncode, 74, (script, r.stderr))
            self.assertIn("receipt not written", r.stderr)

    def test_outside_a_checkout_the_metadata_or_unknown(self):
        """verifier.py copied alone (no pyproject.toml next to it), and next to a pyproject.toml of another project:
        the installed distribution's version if there is one, otherwise "unknown" — never the other project's."""
        try:
            from importlib.metadata import PackageNotFoundError, version
            try:
                installed = version("cryptovalid-opencore")
            except PackageNotFoundError:
                installed = None
        except ImportError:  # pragma: no cover
            installed = None
        for other in (None, '[project]\nname = "someone-else"\nversion = "9.9.9"\n'):
            with tempfile.TemporaryDirectory() as d:
                shutil.copy(os.path.join(HERE, "verifier.py"), d)
                if other:
                    with open(os.path.join(d, "pyproject.toml"), "w") as f:
                        f.write(other)
                r = _run(["-c", "import verifier; print(verifier.package_version())"], cwd=d)
            with self.subTest(other=bool(other)):
                self.assertEqual(r.returncode, 0, r.stderr)
                got = r.stdout.strip()
                if installed:
                    self.assertEqual(got, installed)
                else:
                    self.assertTrue(got.startswith("unknown"), got)
                self.assertNotIn("9.9.9", got)


if __name__ == "__main__":
    unittest.main()
