# SPDX-License-Identifier: AGPL-3.0-or-later
"""SPEC v0.9 §17 (16/11/2026): what the caller of a ledger verifier asks for is applied in every branch, or refused.

Until 0.25.0 `--expect-ledger-id` and `--tip-not-before` were read only inside the check of a signed tip: without a tip
file (or with a tip and no trusted log key) `verifier.py examples/sample_ledger.jsonl --expect-ledger-id <another id>`
was PASS, exit 0, and the receipt did not name the option; the JS, Go and Java verifiers answered the same. Reported by
Athena on 16/11/2026. These tests fail on that code (positive control) and pass from 0.25.1.

The generated cases are checked against an oracle written from §17 and the tip rules of spec/CONFORMANCE.md, not from
the code: every combination of expected identity (none, right, another ledger's, malformed) x tip (none, present but
untrusted, trusted, another ledger's) x oldest tip (none, empty, past, future, malformed) x --require-tip.
Cross-language parts run the JS (node), Java (javac) and Go (go) verifiers when present.
"""
import hashlib
import itertools
import json
import os
import random
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import verifier as V  # noqa: E402
import cryptovalid_tip as T  # noqa: E402
import cryptovalid_mcp as M  # noqa: E402

try:   # `import signer` succeeds without cryptography (lazy import): the library itself is the test
    import cryptography  # noqa: F401
    import signer
    HAVE_CRYPTO = True
except ImportError:
    HAVE_CRYPTO = False
if os.environ.get("CV_REQUIRE_CRYPTO") == "1" and not HAVE_CRYPTO:
    raise SystemExit("CV_REQUIRE_CRYPTO=1 but `cryptography` is missing: the cases that need it would be skipped")

LEDGER_ID = re.compile(r"[0-9a-f]{64}\Z")
PAST, FUTURE = "2000-01-01T00:00:00Z", "2099-01-01T00:00:00Z"


def _canon(e):
    return json.dumps(e, sort_keys=True, separators=(",", ":")).encode()


def _ledger(path, n, tag):
    prev, out = "0" * 64, []
    for i in range(n):
        e = {"idx": i, "ts": f"2026-11-16T07:00:{i:02d}Z", "data": {"tag": tag, "i": i}, "prev_hash": prev}
        e["self_hash"] = hashlib.sha256(_canon(e)).hexdigest()
        prev = e["self_hash"]
        out.append(e)
    with open(path, "w", encoding="utf-8", newline="") as f:
        for e in out:
            f.write(json.dumps(e) + "\n")
    return out[0]["self_hash"]


def _malformed(good):
    """Values that can match no ledger: §17 rule 1 refuses them (usage exit 2 / ValueError)."""
    return ["", " ", good.upper(), " " + good, good + " ", good + "\n", "\t" + good, good[:63], good + "0",
            good[:62] + "é", "ａ" * 64, "Ａ" * 64, good[:32] + "​" + good[32:63], "0x" + good[:62], "ledger-di-un-altro",
            good[:63] + "g", "٠" * 64]


def _oracle(expect, tip_state, nb, require, first_id, other_id):
    """Expected (verdict, set of error names) from SPEC §17 + spec/CONFORMANCE.md (signed chain tip), or "ValueError"."""
    if expect is not None and not LEDGER_ID.match(expect):
        return "ValueError"
    errs = set()
    if expect is not None and expect != first_id:
        errs.add("ledger_id_mismatch")                          # §17 rule 1: in every branch
    req = require or nb is not None                             # §17 rule 2
    if tip_state == "none":
        if req:
            errs.add("tip_missing")
    elif tip_state == "untrusted":
        if req:
            errs.add("tip_untrusted")
    else:                                                       # a tip checked with the trusted key: check_tip's order
        tip_id = first_id if tip_state == "trusted" else other_id
        if expect is not None and expect != tip_id:
            errs.add("ledger_id_mismatch")
        elif tip_id != first_id:
            errs.add("tip_of_another_ledger")
        elif nb is not None:
            if nb in ("", "yesterday"):
                errs.add("bad_not_before")
            elif nb == FUTURE:
                errs.add("tip_rolled_back")
    return ("FAIL" if errs else "PASS"), errs


def _names(receipt):
    return {str(e.get("error", "")).split(":")[0] for e in receipt.get("parse_errors") or []}


class Fixture:
    def __init__(self):
        self.tmp = tempfile.mkdtemp(prefix="cv_expect_")
        self.a = os.path.join(self.tmp, "a.jsonl")
        self.b = os.path.join(self.tmp, "b.jsonl")
        self.a_id = _ledger(self.a, 5, "A")
        self.b_id = _ledger(self.b, 4, "B")
        self.pk = None
        if HAVE_CRYPTO:
            k = os.path.join(self.tmp, "log.key")
            self.pk = signer.keygen(k)["public_key_hex"]
            self.tip_a = os.path.join(self.tmp, "a.tip")
            self.tip_b = os.path.join(self.tmp, "b.tip")
            T.sign_tip(self.a, k, self.tip_a)
            T.sign_tip(self.b, k, self.tip_b)

    def place(self, tip_state):
        """Make the default tip file next to a.jsonl match the state; returns the trusted key to pass (or None)."""
        dst = self.a + ".tip.json"
        if os.path.exists(dst):
            os.remove(dst)
        if tip_state == "none":
            return None
        src = self.tip_b if tip_state == "trusted_other" else (self.tip_a if HAVE_CRYPTO else None)
        if src is None:   # an untrusted tip is never read: any document will do without cryptography
            with open(dst, "w", encoding="utf-8", newline="") as f:
                f.write('{"kind":"cryptovalid_tip/1"}')
        else:
            shutil.copyfile(src, dst)
        return None if tip_state == "untrusted" else self.pk

    def close(self):
        shutil.rmtree(self.tmp, ignore_errors=True)


def _tip_states():
    return ["none", "untrusted"] + (["trusted", "trusted_other"] if HAVE_CRYPTO else [])


class TestReproduced(unittest.TestCase):
    """The case reported on 16/11/2026, on the file the README uses."""

    def _cli(self, *args):
        cp = subprocess.run([sys.executable, os.path.join(HERE, "verifier.py"), os.path.join(HERE, "examples", "sample_ledger.jsonl"), *args],
                            capture_output=True, text=True, encoding="utf-8", cwd=HERE, env={k: v for k, v in os.environ.items() if k != "PYTHONPATH"})
        return cp.returncode, cp.stdout, cp.stderr

    def test_another_ledgers_id_without_tip_is_fail(self):
        other = hashlib.sha256(b"another ledger").hexdigest()
        rc, out, _ = self._cli("--expect-ledger-id", other)
        self.assertEqual(rc, 1, out[-400:])
        r = json.loads(out)
        self.assertEqual(r["verdict"], "FAIL")
        self.assertIn("ledger_id_mismatch", _names(r))
        self.assertIn("--expect-ledger-id", json.dumps(r["parse_errors"]))
        self.assertIsNone(r["tip"])

    def test_the_reported_command_is_refused_not_pass(self):
        rc, out, err = self._cli("--expect-ledger-id", "ledger-di-un-altro")
        self.assertEqual(rc, 2)
        self.assertEqual(out, "")
        self.assertIn("--expect-ledger-id", err)

    def test_the_right_id_is_pass_and_named(self):
        with open(os.path.join(HERE, "examples", "sample_ledger.jsonl"), encoding="utf-8") as f:
            first = json.loads(f.readline())["self_hash"]
        rc, out, _ = self._cli("--expect-ledger-id", first)
        self.assertEqual(rc, 0, out[-400:])
        r = json.loads(out)
        self.assertIn("entry 0's self_hash is the ledger id you expect (--expect-ledger-id)", r["scope"]["proves"])

    def test_not_before_without_tip_is_fail(self):
        rc, out, _ = self._cli("--tip-not-before", FUTURE)
        self.assertEqual(rc, 1, out[-400:])
        self.assertIn("tip_missing", _names(json.loads(out)))

    def test_without_options_the_receipt_is_unchanged(self):
        """Negative control: no option, no tip — the receipt of 0.25.0 (no word on the expected identity)."""
        rc, out, _ = self._cli()
        self.assertEqual(rc, 0)
        r = json.loads(out)
        self.assertEqual(r["scope"]["proves"], ["every self_hash recomputes from its entry (canonical JSON)",
                                                "every prev_hash links to the previous self_hash (genesis = 64 zeros)",
                                                "idx is contiguous from 0"])


class TestGeneratedApi(unittest.TestCase):
    """verifier.verify_ledger on every combination, against the oracle."""

    @classmethod
    def setUpClass(cls):
        cls.f = Fixture()

    @classmethod
    def tearDownClass(cls):
        cls.f.close()

    def test_all_combinations(self):
        f = self.f
        expects = [None, f.a_id, f.b_id, hashlib.sha256(b"x").hexdigest()] + _malformed(f.a_id)
        nbs = [None, "", PAST, FUTURE, "yesterday"]
        n = 0
        counts = {"PASS": 0, "FAIL": 0, "ValueError": 0}
        for tip_state in _tip_states():
            key = f.place(tip_state)
            for expect, nb, req in itertools.product(expects, nbs, (False, True)):
                want = _oracle(expect, tip_state, nb, req, f.a_id, f.b_id)
                case = (tip_state, expect, nb, req)
                if want == "ValueError":
                    with self.assertRaises(ValueError, msg=repr(case)):
                        V.verify_ledger(f.a, trusted_pubkey_hex=key, require_tip=req, tip_not_before=nb, expect_ledger_id=expect)
                    counts["ValueError"] += 1
                else:
                    r = V.verify_ledger(f.a, trusted_pubkey_hex=key, require_tip=req, tip_not_before=nb, expect_ledger_id=expect)
                    self.assertEqual((r["verdict"], _names(r)), want, repr(case))
                    named = "entry 0's self_hash is the ledger id you expect (--expect-ledger-id)" in r["scope"]["proves"]
                    self.assertEqual(named, expect is not None and expect == f.a_id, repr(case))
                    if r["tip"] and r["tip"].get("ok"):   # the tip's scope: "pass --expect-ledger-id" only when it was not
                        hint = any("--expect-ledger-id" in x for x in r["scope"]["does_not_prove"])
                        self.assertEqual(hint, expect is None, repr(case))
                    counts[want[0]] += 1
                n += 1
        self.assertEqual(n, len(_tip_states()) * len(expects) * len(nbs) * 2)
        self.assertTrue(all(counts.values()), counts)   # the oracle reaches all three outcomes

    def test_random_ids_never_pass_unless_equal(self):
        rnd = random.Random(20261116)
        self.f.place("none")
        for _ in range(300):
            cand = "".join(rnd.choice("0123456789abcdef") for _ in range(64))
            if rnd.random() < 0.3:   # one changed character of the right id
                i = rnd.randrange(64)
                cand = self.f.a_id[:i] + rnd.choice([c for c in "0123456789abcdef" if c != self.f.a_id[i]]) + self.f.a_id[i + 1:]
            self.assertEqual(V.verify_ledger(self.f.a, expect_ledger_id=cand)["verdict"], "FAIL", cand)
        self.assertEqual(V.verify_ledger(self.f.a, expect_ledger_id=self.f.a_id)["verdict"], "PASS")

    def test_empty_ledger_with_an_expected_id(self):
        p = os.path.join(self.f.tmp, "empty.jsonl")
        open(p, "w", encoding="utf-8", newline="").close()
        r = V.verify_ledger(p, expect_ledger_id=self.f.a_id)
        self.assertEqual(r["verdict"], "FAIL")
        self.assertEqual(_names(r), {"empty_ledger", "ledger_id_mismatch"})

    def test_non_string_expected_id_is_refused(self):
        class Id:   # an object whose str() is a well-formed id is still not a string
            def __str__(self):
                return "ab" * 32
        for bad in (0, int("1" * 64), b"\x00" * 32, b"ab" * 32, ["a" * 64], {"id": "a" * 64}, True, Id()):
            with self.assertRaises(ValueError, msg=repr(bad)):
                V.verify_ledger(self.f.a, expect_ledger_id=bad)


@unittest.skipUnless(HAVE_CRYPTO, "needs `cryptography` (a signed tip)")
class TestTipModule(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.f = Fixture()

    @classmethod
    def tearDownClass(cls):
        cls.f.close()

    def test_check_tip_refuses_a_malformed_id_and_reads_an_empty_not_before(self):
        f = self.f
        tip = T.load_tip(f.tip_a)
        t = T.chain_tip(f.a)
        for bad in _malformed(f.a_id):
            with self.assertRaises(ValueError, msg=repr(bad)):
                T.check_tip(t["entries"], t["tip_sha256"], tip, f.pk, first_self_hash=t["ledger_id"], expect_ledger_id=bad)
        r = T.check_tip(t["entries"], t["tip_sha256"], tip, f.pk, "", first_self_hash=t["ledger_id"])
        self.assertFalse(r["ok"])
        self.assertTrue(r["error"].startswith("bad_not_before"), r)
        self.assertTrue(T.check_tip(t["entries"], t["tip_sha256"], tip, f.pk, first_self_hash=t["ledger_id"], expect_ledger_id=f.a_id)["ok"])

    def test_check_cli(self):
        f = self.f
        base = [sys.executable, os.path.join(HERE, "cryptovalid_tip.py"), "check", f.a, "--tip", f.tip_a, "--trusted-pubkey", f.pk]
        env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
        for bad in _malformed(f.a_id):
            cp = subprocess.run(base + ["--expect-ledger-id", bad], capture_output=True, text=True, encoding="utf-8", env=env, cwd=HERE)
            self.assertEqual((cp.returncode, cp.stdout), (2, ""), repr(bad))
        cp = subprocess.run(base + ["--not-before", ""], capture_output=True, text=True, encoding="utf-8", env=env, cwd=HERE)
        self.assertEqual(cp.returncode, 1)
        self.assertIn("bad_not_before", cp.stdout)
        cp = subprocess.run(base + ["--expect-ledger-id", f.b_id], capture_output=True, text=True, encoding="utf-8", env=env, cwd=HERE)
        self.assertEqual(cp.returncode, 1)
        self.assertIn("ledger_id_mismatch", cp.stdout)
        cp = subprocess.run(base + ["--expect-ledger-id", f.a_id], capture_output=True, text=True, encoding="utf-8", env=env, cwd=HERE)
        self.assertEqual(cp.returncode, 0, cp.stdout[-400:])


class TestMcpArguments(unittest.TestCase):
    """The MCP tools take the arguments of their schema; any other is refused (-32602), never dropped."""

    def _call(self, name, args):
        return M.handle({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": name, "arguments": args}})

    def test_unknown_arguments_are_refused(self):
        p = os.path.join(HERE, "examples", "sample_ledger.jsonl")
        for extra in ({"expect_ledger_id": "a" * 64}, {"tip": p}, {"trusted_pubkey_hex": "ab" * 32}, {"Path": p}, {"": 1}):
            r = self._call("verify_ledger", dict({"path": p}, **extra))
            self.assertEqual(r.get("error", {}).get("code"), -32602, (extra, r))
        r = self._call("verify_pack", {"pack_dir": HERE, "pq_pubkey_b64": "x"})
        self.assertEqual(r["error"]["code"], -32602)
        r = self._call("verify_ledger", ["path"])
        self.assertEqual(r["error"]["code"], -32602)
        for pin in ([], [""]):   # SPEC §17 rule 4 through the MCP tool: an error result naming the empty pin
            r = self._call("verify_archive", {"directory": HERE, "expected_pubkey_hex": pin})
            self.assertTrue(r["result"]["isError"], r)
            self.assertIn("empty pin", r["result"]["content"][0]["text"])
        r = self._call("verify_ledger", {"path": p})
        self.assertNotIn("error", r)
        self.assertEqual(json.loads(r["result"]["content"][0]["text"])["result"]["verdict"], "PASS")

    def test_every_schema_is_closed(self):
        for name, t in M._TOOLS.items():
            self.assertIs(t["schema"].get("additionalProperties"), False, name)


class TestIngestPin(unittest.TestCase):
    """The same class in the archive verifier: an empty pin pinned nothing (ok true, warning no_pinned_pubkey)."""

    def test_empty_pins_are_refused(self):
        import cryptovalid_ingest as I
        d = tempfile.mkdtemp(prefix="cv_ingest_")
        try:
            for bad in ("", [], [""], ["ab" * 32, ""], [None], (k for k in ())):
                with self.assertRaises(ValueError, msg=repr(bad)):
                    I.verify_archive(d, "ledger", bad)
            self.assertIn("ok", I.verify_archive(d, "ledger", None))           # control: no pin is still allowed
            self.assertIn("ok", I.verify_archive(d, "ledger", ["ab" * 32]))    # and a real pin goes through
            cp = subprocess.run([sys.executable, os.path.join(HERE, "cryptovalid_ingest.py"), "verify", d, "--pubkey", ""],
                                capture_output=True, text=True, encoding="utf-8", cwd=HERE, env={k: v for k, v in os.environ.items() if k != "PYTHONPATH"})
            self.assertEqual((cp.returncode, cp.stdout), (2, ""), cp.stderr[-300:])
        finally:
            shutil.rmtree(d, ignore_errors=True)


def _binaries(tmp):
    """{name: (argv prefix, flags first, flag prefix)} for the other verifiers that have these options."""
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


class TestCrossLanguage(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.f = Fixture()
        cls.bins = _binaries(cls.f.tmp)

    @classmethod
    def tearDownClass(cls):
        cls.f.close()

    def _run(self, name, flags):
        argv, first, _ = self.bins[name]
        cp = subprocess.run(argv + (flags + [self.f.a] if first else [self.f.a] + flags), capture_output=True, text=True, encoding="utf-8",
                            env={k: v for k, v in os.environ.items() if k != "PYTHONPATH"})
        return cp.returncode, cp.stdout

    def _flags(self, name, expect, nb, req, key):
        d = self.bins[name][2]
        fl = []
        if key:
            fl += [d + "trusted-pubkey", key]
        if expect is not None:
            fl += [d + "expect-ledger-id", expect]
        if nb is not None:
            fl += [d + "tip-not-before", nb]
        if req:
            fl += [d + "require-tip"]
        return fl

    def test_combinations_in_every_verifier(self):
        f = self.f
        seen = set()
        for tip_state in _tip_states():
            key = f.place(tip_state)
            for expect, nb, req in itertools.product([None, f.a_id, f.b_id], [None, PAST, FUTURE], (False, True)):
                want = _oracle(expect, tip_state, nb, req, f.a_id, f.b_id)
                for name in self.bins:
                    rc, out = self._run(name, self._flags(name, expect, nb, req, key))
                    case = (name, tip_state, expect, nb, req)
                    self.assertEqual(rc, 0 if want[0] == "PASS" else 1, (case, out[-300:]))
                    self.assertEqual(json.loads(out)["verdict"], want[0], case)
                    if expect == f.b_id:
                        self.assertIn("ledger_id_mismatch", out, case)
                    seen.add(name)
        self.assertEqual(seen, set(self.bins))

    def test_malformed_id_is_usage_in_every_verifier(self):
        self.f.place("none")
        for name in self.bins:
            for bad in _malformed(self.f.a_id):
                if bad.startswith("-"):
                    continue
                rc, out = self._run(name, self._flags(name, bad, None, False, None))
                self.assertEqual((rc, out), (2, ""), (name, repr(bad)))


if __name__ == "__main__":
    unittest.main(verbosity=1)
