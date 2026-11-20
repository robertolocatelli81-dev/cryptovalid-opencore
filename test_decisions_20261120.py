# SPDX-License-Identifier: AGPL-3.0-or-later
"""SPEC §22 (Unreleased): the decisions taken on 2026-11-20 after the re-measurement of 0.27.0.

Each class holds one rule of §22 and fails on the branch before it (9b81e9c, 0.27.0 + the rules of §21); the tests named
`*_control` hold what the rule does not change and pass there too. Cross-language parts run the JS (node), Java (javac)
and Go (go) verifiers when present (CV_REQUIRE_JAVA=1 / CV_REQUIRE_GO=1 make their absence an error).
"""
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import verifier as V  # noqa: E402
import cryptovalid_tip as T  # noqa: E402
import cryptovalid_ingest as I  # noqa: E402

try:   # `import signer` succeeds without cryptography (lazy import): the library itself is the test
    import cryptography  # noqa: F401
    import signer
    HAVE_CRYPTO = True
except ImportError:
    HAVE_CRYPTO = False
if os.environ.get("CV_REQUIRE_CRYPTO") == "1" and not HAVE_CRYPTO:
    raise SystemExit("CV_REQUIRE_CRYPTO=1 but `cryptography` is missing: the cases that need it would be skipped")

ENV = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}


def _canon(e):
    return json.dumps(e, sort_keys=True, separators=(",", ":")).encode()


def _ledger(path, n, tag="d"):
    prev, out = "0" * 64, []
    for i in range(n):
        e = {"idx": i, "ts": f"2026-11-20T07:00:{i:02d}Z", "data": {"tag": tag, "i": i}, "prev_hash": prev}
        e["self_hash"] = hashlib.sha256(_canon(e)).hexdigest()
        prev = e["self_hash"]
        out.append(e)
    with open(path, "w", encoding="utf-8") as f:
        for e in out:
            f.write(json.dumps(e) + "\n")
    return out


def _binaries(tmp):
    """{name: (argv prefix, flags first, flag prefix)} for the ledger verifiers that check a tip."""
    out = {"python": ([sys.executable, os.path.join(HERE, "verifier.py")], False, "--")}
    if shutil.which("node"):
        out["js"] = (["node", os.path.join(HERE, "verifiers", "js", "cvverify.mjs")], False, "--")
    home = os.environ.get("JAVA_HOME")
    javac = os.path.join(home, "bin", "javac") if home and os.path.exists(os.path.join(home, "bin", "javac")) else shutil.which("javac")
    java = os.path.join(home, "bin", "java") if home and os.path.exists(os.path.join(home, "bin", "java")) else shutil.which("java")
    if javac and java:
        cp = os.path.join(tmp, "cls")
        subprocess.run([javac, "-d", cp, os.path.join(HERE, "verifiers", "java", "CvVerify.java")], check=True, capture_output=True)
        out["java"] = ([java, "-cp", cp, "CvVerify"], True, "-")
    elif os.environ.get("CV_REQUIRE_JAVA") == "1":
        raise RuntimeError("CV_REQUIRE_JAVA=1 and no JDK")
    if shutil.which("go"):
        b = os.path.join(tmp, "cvverify-go")
        subprocess.run(["go", "build", "-o", b, "./cmd/cvverify"], cwd=os.path.join(HERE, "verifiers", "go"), check=True, capture_output=True)
        out["go"] = ([b], True, "-")
    elif os.environ.get("CV_REQUIRE_GO") == "1":
        raise RuntimeError("CV_REQUIRE_GO=1 and no Go toolchain")
    return out


def _strings(v):
    """Every string inside a decoded JSON value (a receipt names its failures in different fields per language)."""
    if isinstance(v, str):
        yield v
    elif isinstance(v, dict):
        for k, x in v.items():
            yield from _strings(k)
            yield from _strings(x)
    elif isinstance(v, list):
        for x in v:
            yield from _strings(x)


def _run(bins, name, ledger, flags):
    argv, first, _ = bins[name]
    cp = subprocess.run(argv + (flags + [ledger] if first else [ledger] + flags), capture_output=True, text=True, env=ENV)
    try:
        doc = json.loads(cp.stdout)
    except ValueError:
        doc = None
    return cp.returncode, doc, cp.stdout + cp.stderr


@unittest.skipUnless(HAVE_CRYPTO, "needs `cryptography` (the `sign` extra)")
class TestTrustedLogKeyRequiresTip(unittest.TestCase):
    """§22 rule 1: a trusted log key makes the tip required, in the four verifiers that check a tip."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        cls.led = os.path.join(cls.tmp, "l.jsonl")
        _ledger(cls.led, 4)
        cls.pk = signer.keygen(os.path.join(cls.tmp, "log.key"))["public_key_hex"]
        cls.bins = _binaries(cls.tmp)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_library_without_tip_is_tip_missing(self):
        r = V.verify_ledger(self.led, trusted_pubkey_hex=self.pk)
        self.assertEqual(r["verdict"], "FAIL")
        self.assertIsNone(r["tip"])
        self.assertTrue(any(e["error"].startswith("tip_missing") for e in r["parse_errors"]), r["parse_errors"])

    def test_library_without_key_and_without_tip_control(self):
        r = V.verify_ledger(self.led)
        self.assertEqual(r["verdict"], "PASS")
        self.assertIsNone(r["tip"])

    def test_every_verifier_fails_without_tip_and_passes_with_it(self):
        for name in self.bins:
            d = self.bins[name][2]
            rc, doc, raw = _run(self.bins, name, self.led, [d + "trusted-pubkey", self.pk])
            self.assertEqual(rc, 1, (name, raw[-400:]))
            self.assertTrue(any(s.startswith("tip_missing") for s in _strings(doc)), (name, raw[-400:]))
        T.sign_tip(self.led, os.path.join(self.tmp, "log.key"))
        try:
            for name in self.bins:
                d = self.bins[name][2]
                rc, _doc, raw = _run(self.bins, name, self.led, [d + "trusted-pubkey", self.pk])
                self.assertEqual(rc, 0, (name, raw[-400:]))
        finally:
            os.remove(self.led + ".tip.json")

    def test_every_verifier_without_key_control(self):
        for name in self.bins:
            rc, _doc, raw = _run(self.bins, name, self.led, [])
            self.assertEqual(rc, 0, (name, raw[-400:]))


if __name__ == "__main__":
    unittest.main()
