#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""tools/fuzz_readers.py and the two workflows of 2026-11-23 (SPEC v0.15 §26): the fuzz run and CodeQL.

1. A short run of the fuzzer on fixed seeds finds no violation, on every target this Python can load.
2. Positive control, as the weekly job runs it: each target with its check disabled (`--ablate`) reports violations
   on the same seeds; the ledger target always, the DSSE target with `cryptography`, the anchor target with `slh-dsa`.
3. The workflows: every action pinned to a 40-hex commit with its version in a comment, read-only `contents`, CodeQL
   with `security-events: write` in its job only, inputs reaching scripts only through `env:`, both triggers present.
Positive control of this file: tools/fuzz_readers.py and the workflows did not exist on 5f2d57f (tests 1-3 fail)."""
import json
import os
import re
import subprocess
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True
HERE = os.path.dirname(os.path.abspath(__file__))
FUZZ = os.path.join(HERE, "tools", "fuzz_readers.py")
WF = os.path.join(HERE, ".github", "workflows")


def have(mod):
    try:
        __import__(mod)
        return True
    except ImportError:
        return False


def read(p):
    with open(p, encoding="utf-8") as f:
        return f.read()


def fuzz(*args):
    with tempfile.TemporaryDirectory() as d:
        r = subprocess.run([sys.executable, FUZZ, "--findings-dir", os.path.join(d, "f")] + list(args),
                           capture_output=True, text=True, encoding="utf-8", timeout=60, cwd=d)
    return r.returncode, json.loads(r.stdout.strip().splitlines()[-1]) if r.stdout.strip() else None, r.stderr


class Fuzzer(unittest.TestCase):
    def test_clean_runs_find_nothing(self):
        for seed in (1, 2, 3):
            rc, summary, err = fuzz("--seed", str(seed), "--iterations", "600")
            self.assertEqual(rc, 0, err[-600:])
            self.assertEqual((summary["violations"], summary["iterations"]), (0, 600))
            self.assertIn("ledger", summary["targets"])
            self.assertLessEqual(sum(summary["accepted"].values()), summary["iterations"])
            self.assertEqual("dsse" in summary["targets"], have("cryptography"))
            self.assertEqual("slhdsa" in summary["targets"], have("slhdsa"))

    def test_each_disabled_check_is_seen(self):
        targets = ["ledger"] + (["dsse"] if have("cryptography") else []) + (["slhdsa"] if have("slhdsa") else [])
        for t in targets:
            rc, summary, err = fuzz("--seed", "1", "--iterations", "1500", "--ablate", t)
            self.assertEqual(rc, 0, (t, err[-400:]))
            self.assertGreater(summary["violations"], 0, t)
            self.assertEqual([list(x) for x in summary["by_property"]], [[t, "P1"]])

    def test_ablation_of_a_target_that_is_not_here_is_a_refusal(self):
        if have("slhdsa"):
            self.skipTest("slh-dsa installed")
        rc, _, err = fuzz("--ablate", "slhdsa", "--iterations", "10")
        self.assertEqual(rc, 2)
        self.assertIn("not available", err)

    def test_the_same_seed_gives_the_same_verdicts(self):
        a = fuzz("--seed", "9", "--iterations", "300")[1]
        b = fuzz("--seed", "9", "--iterations", "300")[1]
        self.assertEqual((a["verdicts_sha256"], a["accepted"]), (b["verdicts_sha256"], b["accepted"]))


class Oracle(unittest.TestCase):
    """The fuzzer's own judgement of "unchanged", on inputs whose answer is known."""

    @classmethod
    def setUpClass(cls):
        sys.path.insert(0, os.path.join(HERE, "tools"))
        try:
            import fuzz_readers
        except SystemExit:
            raise AssertionError("importing tools/fuzz_readers.py ran it") from None
        cls.F = fuzz_readers
        cls.tmp = tempfile.mkdtemp(prefix="cvfz-")

    def targets(self):
        out = [self.F.Ledger(self.tmp)]
        for cls in (self.F.Dsse, self.F.Anchor):
            try:
                out.append(cls(self.tmp))
            except ImportError:
                pass
        return out

    def test_unchanged_changed_and_garbage(self):
        for t in self.targets():
            self.assertTrue(t.allowed(t.orig), t.name)
            for bad in (b"", b"not json", b"\xff", b"[]", b"{}"):
                self.assertFalse(t.allowed(bad), (t.name, bad))
            obj = json.loads(t.orig.split(b"\n")[0])
            key = sorted(obj)[0]
            obj[key] = "changed"
            self.assertFalse(t.allowed(json.dumps(obj).encode()), (t.name, key))
        if have("slhdsa"):
            a = self.F.Anchor(self.tmp)
            for k, v in (("root", "00"), ("ts", int(a.anchor["ts"])), ("ts", str(a.anchor["ts"]))):
                self.assertFalse(a.allowed(json.dumps(dict(a.anchor, **{k: v})).encode()), k)

    def test_a_time_budget_ends_and_a_findings_dir_can_be_reused(self):
        rc, summary, err = fuzz("--seed", "4", "--iterations", "0", "--seconds", "1")
        self.assertEqual(rc, 0, err[-400:])
        self.assertGreater(summary["iterations"], 0)
        with tempfile.TemporaryDirectory() as d:
            for _ in range(2):
                r = subprocess.run([sys.executable, FUZZ, "--ablate", "ledger", "--iterations", "300",
                                    "--findings-dir", d], capture_output=True, text=True, encoding="utf-8", timeout=60)
                self.assertEqual(r.returncode, 0, r.stderr[-400:])


class Workflows(unittest.TestCase):
    def test_actions_pinned_and_permissions_minimal(self):
        for name in ("codeql.yml", "fuzz-weekly.yml"):
            text = read(os.path.join(WF, name))
            uses = re.findall(r"uses: (\S+)(.*)", text)
            self.assertTrue(uses, name)
            for ref, comment in uses:
                self.assertRegex(ref, r"^[\w.-]+/[\w./-]+@[0-9a-f]{40}$", name)
                self.assertRegex(comment, r"^ # v\d+\.\d+\.\d+$", (name, ref))
            self.assertIn("\npermissions:\n  contents: read\n", text, name)
            self.assertNotIn("write-all", text)
            for script in re.findall(r"run: \|\n((?:          .*\n|\n)+)", text):
                self.assertNotIn("${{", script, name)
        codeql = read(os.path.join(WF, "codeql.yml"))
        self.assertEqual(codeql.count("security-events: write"), 1)
        self.assertIn("languages: python", codeql)
        for trig in ("push:", "pull_request:", "schedule:"):
            self.assertIn(trig, codeql)
        fz = read(os.path.join(WF, "fuzz-weekly.yml"))
        self.assertNotIn(": write", fz)
        self.assertIn("--ablate", fz)
        self.assertIn('python-version: ["3.9", "3.11", "3.13"]', fz)

    def test_the_same_commits_as_the_other_workflows(self):
        pins = {}
        for name in sorted(os.listdir(WF)):
            for ref in re.findall(r"uses: ([\w.-]+/[\w.-]+)(?:/[\w./-]+)?@([0-9a-f]{40})", read(os.path.join(WF, name))):
                pins.setdefault(ref[0], set()).add(ref[1])
        for action in ("actions/checkout", "actions/setup-python", "actions/upload-artifact"):
            self.assertEqual(len(pins[action]), 1, (action, pins[action]))


if __name__ == "__main__":
    unittest.main()
