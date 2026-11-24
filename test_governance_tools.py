#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
"""The rules of CONTRIBUTING.md are checked by code that can say no: tools/check_dco.py (sign-off on every commit),
and the governance files name only things that exist.

Every check is run on an input that must pass and on inputs that must be refused (positive controls)."""
import datetime
import hashlib
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
TOOLS = os.path.join(HERE, "tools")
sys.path.insert(0, TOOLS)

import check_dco  # noqa: E402
import misura_api  # noqa: E402

DOCS = ["CONTRIBUTING.md", "GOVERNANCE.md", "SUPPORT.md", "API.md", "SECURITY.md"]
# SHA-256 of the DCO file: the certificate may be copied verbatim, never changed ("changing it is not allowed")
DCO_SHA256 = "f7ac75b443f4ca16b503241344b41aeff9503b0c30bedc2b119551d83cb0fa90"


def git(repo, *args, **env):
    e = dict(os.environ, GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_SYSTEM=os.devnull,
             GIT_AUTHOR_NAME="Ada Example", GIT_AUTHOR_EMAIL="ada@example.org",
             GIT_COMMITTER_NAME="Ada Example", GIT_COMMITTER_EMAIL="ada@example.org")
    e.update(env)
    r = subprocess.run(["git", "-C", repo, "-c", "commit.gpgsign=false"] + list(args), capture_output=True, text=True, env=e)
    if r.returncode != 0:
        raise RuntimeError(r.stderr)
    return r.stdout.strip()


class TestDco(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.repo = self.tmp.name
        git(self.repo, "init", "-q", "-b", "main")
        self.n = 0
        self.base = self.commit("base\n\nSigned-off-by: Ada Example <ada@example.org>")

    def tearDown(self):
        self.tmp.cleanup()

    def commit(self, message, **env):
        self.n += 1
        with open(os.path.join(self.repo, "f.txt"), "a") as f:
            f.write("%d\n" % self.n)
        git(self.repo, "add", "f.txt")
        git(self.repo, "commit", "-q", "-m", message, **env)
        return git(self.repo, "rev-parse", "HEAD")

    def run_tool(self, *args):
        r = subprocess.run([sys.executable, os.path.join(TOOLS, "check_dco.py"), "-C", self.repo] + list(args),
                           capture_output=True, text=True)
        return r.returncode, r.stdout + r.stderr

    def test_signed_commits_pass(self):
        self.commit("one\n\nSigned-off-by: Ada Example <ada@example.org>")
        self.commit("two, case of the address\n\nReviewed-by: X <x@example.org>\nSigned-off-by: Ada Example <ADA@example.org>")
        rc, out = self.run_tool(self.base + "..HEAD")
        self.assertEqual(rc, 0, out)
        self.assertIn("2 of 2 commits pass", out)

    def test_git_commit_s_is_what_passes(self):
        self.n += 1
        with open(os.path.join(self.repo, "f.txt"), "a") as f:
            f.write("s\n")
        git(self.repo, "add", "f.txt")
        git(self.repo, "commit", "-q", "-s", "-m", "with -s")
        self.assertEqual(self.run_tool(self.base + "..HEAD")[0], 0)

    def test_positive_control_unsigned_commit_is_refused(self):
        self.commit("signed\n\nSigned-off-by: Ada Example <ada@example.org>")
        bad = self.commit("no sign-off at all")
        rc, out = self.run_tool(self.base + "..HEAD")
        self.assertEqual(rc, 1, out)
        self.assertIn(bad[:12], out)
        self.assertIn("no Signed-off-by trailer", out)
        self.assertIn("1 of 2 commits pass", out)

    def test_positive_control_sign_off_of_someone_else_is_refused(self):
        self.commit("signed by another person\n\nSigned-off-by: Bob Other <bob@example.org>")
        rc, out = self.run_tool(self.base + "..HEAD")
        self.assertEqual(rc, 1, out)
        self.assertIn("no Signed-off-by with the email of the author (ada@example.org)", out)

    def test_positive_control_sign_off_in_the_body_or_malformed_is_refused(self):
        self.commit("in the text, not a trailer\n\nSigned-off-by: Ada Example <ada@example.org>\n\nmore text after it, so it is not a trailer")
        self.assertEqual(self.run_tool(self.base + "..HEAD")[0], 1)
        self.commit("malformed\n\nSigned-off-by: ada@example.org")
        rc, out = self.run_tool("HEAD~1..HEAD")
        self.assertEqual(rc, 1)
        self.assertIn("not of the form", out)

    def test_exempt_author_is_named_one_by_one(self):
        self.commit("bump x\n\nSigned-off-by: dependabot[bot] <support@github.com>",
                    GIT_AUTHOR_NAME="dependabot[bot]", GIT_AUTHOR_EMAIL="1+dependabot[bot]@users.noreply.github.com",
                    GIT_COMMITTER_NAME="GitHub", GIT_COMMITTER_EMAIL="noreply@github.com")
        self.assertEqual(self.run_tool(self.base + "..HEAD")[0], 1)
        self.assertEqual(self.run_tool("--exempt-author", "1+dependabot[bot]@users.noreply.github.com", self.base + "..HEAD")[0], 0)
        self.assertEqual(self.run_tool("--exempt-author", "someone@else.org", self.base + "..HEAD")[0], 1)

    def test_empty_range_bad_range_and_usage(self):
        rc, out = self.run_tool("HEAD..HEAD")
        self.assertEqual(rc, 0)
        self.assertIn("nothing was checked", out)
        self.assertEqual(self.run_tool("no-such-ref..HEAD")[0], 2)
        self.assertEqual(self.run_tool()[0], 2)
        self.assertEqual(self.run_tool("--unknown", "HEAD")[0], 2)

    def test_count_never_fails(self):
        self.commit("unsigned")
        rc, out = self.run_tool("--count", "HEAD")
        self.assertEqual(rc, 0)
        self.assertIn("commits: 2  signed off: 1  not signed off: 1", out)

    def test_dco_text_is_unchanged(self):
        with open(os.path.join(HERE, "DCO"), "rb") as f:
            raw = f.read()
        self.assertEqual(hashlib.sha256(raw).hexdigest(), DCO_SHA256)
        text = raw.decode("ascii")
        self.assertIn("Developer Certificate of Origin\nVersion 1.1\n", text)
        for clause in ("(a) The contribution was created", "(b) The contribution is based upon", "(c) The contribution was provided", "(d) I understand and agree"):
            self.assertEqual(text.count(clause), 1)


def missing_references(text, root):
    """Paths a governance text names that do not exist under `root`: relative Markdown links, and `code` spans that look
    like a file or a directory of the repository."""
    refs = set(re.findall(r"\]\((?!https?://|mailto:|#)([^)#\s]+)", text))
    for span in re.findall(r"`([^`\n]+)`", text):
        for tok in span.split():
            tok = tok.strip(",;:()\"'")
            if re.fullmatch(r"[A-Za-z0-9_./-]+", tok) and "*" not in tok and "<" not in tok and \
                    (re.search(r"\.(py|md|yml|toml|json|jsonl|cff)$", tok) or tok.endswith("/") or tok in ("DCO", "LICENSE", "NOTICE")):
                refs.add(tok)
    return sorted(r for r in refs if not os.path.exists(os.path.join(root, r)))


class TestGovernanceFilesNameRealThings(unittest.TestCase):
    def read(self, name):
        with open(os.path.join(HERE, name), encoding="utf-8") as f:
            return f.read()

    def test_every_file_and_directory_named_exists(self):
        for name in DOCS:
            self.assertEqual(missing_references(self.read(name), HERE), [], name)

    def test_positive_control_a_missing_file_is_reported(self):
        text = "see [x](NOT_THERE.md), run `python3 tools/absent.py a..b`, read `spec/nowhere/` and [ok](README.md) and `verifier.py`"
        self.assertEqual(missing_references(text, HERE), ["NOT_THERE.md", "spec/nowhere/", "tools/absent.py"])

    def test_contributing_commands_are_the_ones_ci_runs(self):
        contributing, ci = self.read("CONTRIBUTING.md"), self.read(os.path.join(".github", "workflows", "verify.yml"))
        for cmd in ("for t in test_*.py; do", "python3 conformance.py", "python3 verifiers/differential_oracle.py"):
            self.assertIn(cmd, contributing)
            self.assertIn(cmd, ci)
        self.assertIn('python-version: ["3.9", "3.10", "3.11", "3.12", "3.13", "3.14"]', ci)   # what CONTRIBUTING.md and SUPPORT.md state
        self.assertIn("os: [macos-latest, windows-latest]", ci)
        for doc in ("CONTRIBUTING.md", "SUPPORT.md"):
            self.assertRegex(self.read(doc), r"3\.9 to 3\.14 on Linux, and 3\.13\s+on macOS and Windows")
        gov = self.read(os.path.join(".github", "workflows", "governance.yml"))
        for script in re.findall(r"python3 ((?:tools/)?[a-z_]+\.py)", contributing + gov):
            self.assertTrue(os.path.isfile(os.path.join(HERE, script)), script)
        self.assertIn("python3 tools/check_dco.py", gov)

    def test_codeowners_paths_exist_and_have_the_maintainer(self):
        rows = [ln.split() for ln in self.read(os.path.join(".github", "CODEOWNERS")).split("\n") if ln.strip() and not ln.startswith("#")]
        self.assertGreaterEqual(len(rows), 10)
        self.assertEqual(rows[0], ["*", "@robertolocatelli81-dev"])      # the last match wins: the catch-all is first
        for path, *owners in rows:
            self.assertEqual(owners, ["@robertolocatelli81-dev"], path)
            if path != "*":
                self.assertTrue(path.startswith("/") and os.path.exists(os.path.join(HERE, path.lstrip("/"))), path)

    def test_documents_agree_with_each_other(self):
        contributing = self.read("CONTRIBUTING.md")
        self.assertIn("Signed-off-by:", contributing)
        self.assertIn("not accepted at present", contributing)
        self.assertFalse(os.path.exists(os.path.join(HERE, "CLA.md")))
        security = self.read("SECURITY.md")
        for doc in ("SUPPORT.md",):
            self.assertIn("latest release", self.read(doc))
        self.assertIn("latest tagged release", security)
        with open(os.path.join(HERE, "pyproject.toml"), encoding="utf-8") as f:
            self.assertIn('requires-python = ">=3.9"', f.read())


class TestMeasureScript(unittest.TestCase):
    SRC = ('from __future__ import annotations\n'
           'def a(x: int, y, *args, k: str = "", **kw) -> dict:\n    def inner(z): pass\n    return {}\n'
           'def _b(x): pass\n'
           'class C:\n    def m(self, p: int) -> None: pass\n    @classmethod\n    def n(cls): pass\n'
           'def full(x: int) -> int: return x\n')

    def test_positive_control_counts_on_a_known_source(self):
        m = misura_api.measure_source(self.SRC)
        self.assertEqual((m["defs"], m["ret"], m["params"], m["ann"], m["bare_dict"]), (6, 3, 9, 4, 1))
        self.assertEqual((m["public"], m["public_funcs"], m["public_funcs_fully_annotated"]), (["a", "C", "full"], 2, 1))
        self.assertEqual((m["has_all"], m["future_annotations"]), (False, True))
        self.assertTrue(misura_api.measure_source("__all__ = ['x']\n")["has_all"])

    def test_uses_seen_through_import_alias_and_from(self):
        used, star = misura_api.uses_in_source("import verifier as V\nfrom signer import keygen, _x\nfrom tsa import *\nV.verify_ledger\nV._private()\n",
                                               {"verifier", "signer", "tsa"})
        self.assertEqual(used, {"verifier": {"verify_ledger", "_private"}, "signer": {"keygen", "_x"}})
        self.assertEqual(star, {"tsa"})

    def test_the_repository_as_measured(self):
        res = misura_api.measure(HERE)
        self.assertEqual(len(res["core"]), 11)
        for m in res["core"]:
            self.assertIn(m, res["modules"])
        self.assertEqual(res["star_imports"], {})
        self.assertIn("verify_ledger", res["modules"]["verifier"]["public_used_by_non_tests"])


if __name__ == "__main__":
    unittest.main()
