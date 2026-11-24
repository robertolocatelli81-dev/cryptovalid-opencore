#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""action.yml (2026-11-23): the GitHub Action that verifies the release wheel's provenance, then runs cryptovalid-verify.

The two `run:` scripts of action.yml are taken from the file and run here with bash, offline, with a `gh` that records
its calls instead of reaching GitHub: inputs reach the scripts only through `env:` (never `${{ inputs.* }}` inside a
script, where a value would be shell code), a version that is not X.Y.Z or a `cryptography` that is neither true nor
false stops before any `gh` call, a provenance check that fails stops before anything is installed, the signer identity
is release-build.yml at the tag, the arguments are split on whitespace and never expanded, and the exit status of
cryptovalid-verify is the step's and the `exit-code` output. The default version is the package's. The real path
(gh against GitHub, the 0.28.1 wheel) was measured by hand on 2026-11-23 and is in the CHANGELOG, not here.
Positive control: action.yml did not exist on 5f2d57f (setUpClass fails)."""
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True
HERE = os.path.dirname(os.path.abspath(__file__))
BASH = shutil.which("bash")


def read(name):
    with open(os.path.join(HERE, name), encoding="utf-8") as f:
        return f.read()


def slurp(path):
    with open(path, encoding="utf-8") as f:
        return f.read()


def run_blocks(text):
    """{step id: script} from the composite steps: the lines under `run: |`, indented deeper than `run:`."""
    out, cur, ind, sid = {}, None, 0, None
    for line in text.splitlines():
        m = re.match(r"\s*- id: (\S+)$", line)
        if m:
            sid = m.group(1)
        if cur is not None:
            if line.strip() and len(line) - len(line.lstrip()) <= ind:
                out[sid_run], cur = "\n".join(cur) + "\n", None
            else:
                cur.append(line[ind + 2:] if line.strip() else "")
                continue
        m = re.match(r"(\s*)run: \|$", line)
        if m:
            cur, ind, sid_run = [], len(m.group(1)), sid
    if cur is not None:
        out[sid_run] = "\n".join(cur) + "\n"
    return out


@unittest.skipUnless(BASH, "bash not found")
class Action(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = read("action.yml")
        cls.blocks = run_blocks(cls.text)

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="cv-action-")
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.bin = os.path.join(self.tmp, "bin")
        os.mkdir(self.bin)
        self.calls = os.path.join(self.tmp, "gh-calls")
        self.out = os.path.join(self.tmp, "github-output")

    def gh(self, attest_rc=0):
        p = os.path.join(self.bin, "gh")
        with open(p, "w", encoding="utf-8", newline="") as f:
            f.write('#!/bin/sh\nprintf "%s\\n" "$*" >> "$GH_CALLS"\n'
                    'if [ "$1" = attestation ]; then exit ' + str(attest_rc) + '; fi\n'
                    'if [ "$1" = release ]; then : > "$9/$7"; fi\nexit 0\n')
        os.chmod(p, 0o755)

    def step(self, sid, **env):
        e = {"PATH": self.bin + os.pathsep + os.environ.get("PATH", ""), "RUNNER_TEMP": self.tmp,
             "GITHUB_OUTPUT": self.out, "GH_CALLS": self.calls, "HOME": self.tmp, "USERPROFILE": self.tmp}
        e.update(env)
        return subprocess.run([BASH, "-e", "-c", self.blocks[sid]], env=e, cwd=self.tmp, capture_output=True,
                              text=True, encoding="utf-8", timeout=120)

    def calls_made(self):
        return slurp(self.calls).splitlines() if os.path.exists(self.calls) else []

    def test_inputs_reach_the_scripts_only_through_env(self):
        self.assertEqual(set(self.blocks), {"verify", "run"})
        for sid, script in self.blocks.items():
            self.assertNotIn("${{", script, sid)
        self.assertTrue(self.blocks["verify"].startswith("set -euo pipefail\n"))
        self.assertTrue(self.blocks["run"].startswith("set -uo pipefail\nset -f\n"))

    def test_default_version_is_the_package_version(self):
        v = re.search(r'^version = "([^"]+)"', read("pyproject.toml"), re.M).group(1)
        self.assertIn(f'default: "{v}"', self.text)
        self.assertIn(f"cryptovalid-opencore@v{v}", self.text)

    def test_signer_identity_is_release_build_at_the_tag(self):
        v = self.blocks["verify"]
        self.assertIn('--cert-identity "https://github.com/$REPO/.github/workflows/release-build.yml@refs/tags/v$V"', v)
        self.assertIn('--source-ref "refs/tags/v$V" --deny-self-hosted-runners', v)
        self.assertIn("REPO: robertolocatelli81-dev/cryptovalid-opencore", self.text)

    def test_bad_inputs_stop_before_any_call(self):
        self.gh()
        for ver, crypto in (("1.2", "true"), ("1.2.3;id", "true"), ("../1.2.3", "true"), ("1.2.3 ", "true"),
                            ("1.2.3.4", "true"), ("1..3", "true"), ("1x2.3", "true"), ("1.2x3", "true"), (".2.3", "true"), ("1.2.", "true"), ("1.2.3\n4.5.6", "true"),
                            ("", "true"), ("v1.2.3", "true"), ("1.2.3", "yes"), ("1.2.3", "")):
            r = self.step("verify", V=ver, CRYPTO=crypto, REPO="o/r", GH_TOKEN="t")
            self.assertEqual(r.returncode, 1, (ver, crypto, r.stderr))
            self.assertIn("::error::", r.stdout)
        self.assertEqual(self.calls_made(), [])

    def test_a_failed_provenance_check_installs_nothing(self):
        self.gh(attest_rc=1)
        r = self.step("verify", V="0.28.1", CRYPTO="false", REPO="o/r", GH_TOKEN="t")
        self.assertNotEqual(r.returncode, 0)
        calls = self.calls_made()
        self.assertEqual(len(calls), 2, calls)
        self.assertTrue(calls[0].startswith("release download v0.28.1 --repo o/r --pattern "
                                            "cryptovalid_opencore-0.28.1-py3-none-any.whl --dir "))
        self.assertIn("--cert-identity https://github.com/o/r/.github/workflows/release-build.yml@refs/tags/v0.28.1",
                      calls[1])
        self.assertFalse(os.path.exists(os.path.join(self.tmp, "cryptovalid-0.28.1", "venv")))
        self.assertFalse(os.path.exists(self.out) and "bin=" in slurp(self.out))

    def test_arguments_are_split_and_never_expanded_and_the_status_is_kept(self):
        rec = os.path.join(self.tmp, "argv")
        os.mkdir(os.path.join(self.tmp, "a dir"))
        stub = os.path.join(self.tmp, "a dir", "cv")   # a path with a space: BIN is quoted
        with open(stub, "w", encoding="utf-8", newline="") as f:
            f.write('#!/bin/sh\nfor a in "$@"; do printf "[%s]\\n" "$a"; done > "$REC"\nexit "$RC"\n')
        os.chmod(stub, 0o755)
        for rc in (0, 1, 2, 74):
            with open(self.out, "w", encoding="utf-8", newline=""):
                pass
            r = self.step("run", BIN=stub, CV_ARGS="  auto  evidence/*  $(id) ;x `id` \"a b\"\n--k\tv ", REC=rec,
                          RC=str(rc))
            self.assertEqual(r.returncode, rc)
            self.assertEqual(slurp(rec).splitlines(),
                             ["[auto]", "[evidence/*]", "[$(id)]", "[;x]", "[`id`]", '["a]', '[b"]', "[--k]", "[v]"])
            self.assertEqual(slurp(self.out), f"exit-code={rc}\n")
        r = self.step("run", BIN=stub, CV_ARGS=" \n\t", REC=rec, RC="0")
        self.assertEqual(r.returncode, 1)
        self.assertIn("args is empty", r.stdout)


if __name__ == "__main__":
    unittest.main()
