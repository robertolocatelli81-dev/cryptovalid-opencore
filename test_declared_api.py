#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
"""The declared API (API.md): the package `cryptovalid`, its stub, the receipt types and the wheel that carries them.

Each check has its positive control in the same class: the checker is run on a broken input and must object.
Before this file existed nothing in the repository declared a public name (`__all__`: 0 occurrences, 15/11/2026) and
the wheel could not carry type information at all (42 flat modules: PEP 561 does not support module-only
distributions)."""
import ast
import glob
import os
import re
import subprocess
import sys
import tempfile
import typing
import unittest
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "tools"))

import check_stub  # noqa: E402
import cryptovalid  # noqa: E402
import cryptovalid.receipts as receipts  # noqa: E402
import verifier  # noqa: E402

STUB = os.path.join(HERE, "cryptovalid", "__init__.pyi")
ORIGIN = {  # declared name -> flat module that defines it
    "verify_ledger": "verifier", "canonical_payload": "verifier", "hash_with": "verifier", "CheckNotRun": "verifier",
    "verify_pack": "evidence_pack", "verify_ledger_signatures": "signer",
    "verify_note": "cryptovalid_checkpoint", "parse_checkpoint": "cryptovalid_checkpoint", "NoteError": "cryptovalid_checkpoint",
    "verify_inclusion": "cryptovalid_merkle", "verify_consistency": "cryptovalid_merkle",
    "verify_tiles": "cryptovalid_merkle", "TileError": "cryptovalid_merkle",
    "verify_token": "cryptovalid_tsa", "TokenError": "cryptovalid_tsa",
}
OWN = {"CryptovalidDeprecationWarning", "LedgerReceipt", "__version__"}


def _stub_text():
    with open(STUB, encoding="utf-8") as f:
        return f.read()


class TestStubMatchesRuntime(unittest.TestCase):
    def test_no_difference(self):
        self.assertEqual(check_stub.compare(_stub_text(), cryptovalid), [])

    def test_positive_controls_a_wrong_stub_is_reported(self):
        good = _stub_text()
        broken = {
            "a parameter renamed": good.replace("def hash_with(algo: str,", "def hash_with(algorithm: str,"),
            "a default dropped": good.replace("    require_tip: bool = False,\n    tip_not_before", "    require_tip: bool,\n    tip_not_before"),
            "a parameter removed": good.replace("    expect_ledger_id: Optional[str] = None,\n", ""),
            "a function that does not exist": good + "\ndef verify_everything(path: str) -> bool: ...\n",
            "a name missing from __all__": good.replace('    "verify_token",\n', "", 1),
            "a wrong base class": good.replace("class TileError(ValueError): ...", "class TileError(KeyError): ..."),
            "an untyped parameter": good.replace("def hash_with(algo: str,", "def hash_with(algo,"),
            "not Python": good + "\ndef (:\n",
        }
        for what, text in broken.items():
            self.assertNotEqual(text, good, what + ": the mutation did not apply")
            self.assertNotEqual(check_stub.compare(text, cryptovalid), [], what + ": not reported")

    def test_command_exit_codes(self):
        cmd = [sys.executable, os.path.join(HERE, "tools", "check_stub.py"), HERE, "cryptovalid"]
        r = subprocess.run(cmd, capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("0 difference(s)", r.stdout)
        self.assertEqual(subprocess.run(cmd[:2], capture_output=True).returncode, 2)


class TestDeclaredNames(unittest.TestCase):
    def test_all_is_exactly_the_declared_set(self):
        self.assertEqual(set(cryptovalid.__all__), set(ORIGIN) | OWN)
        self.assertEqual(len(cryptovalid.__all__), len(set(cryptovalid.__all__)))

    def test_each_name_is_the_object_of_the_flat_module(self):
        for name, mod in ORIGIN.items():
            self.assertIs(getattr(cryptovalid, name), getattr(__import__(mod), name), name)

    def test_warning_class_is_shown_by_default(self):
        self.assertTrue(issubclass(cryptovalid.CryptovalidDeprecationWarning, UserWarning))
        self.assertFalse(issubclass(cryptovalid.CryptovalidDeprecationWarning, DeprecationWarning))

    def test_api_md_lists_every_name_and_no_other(self):
        with open(os.path.join(HERE, "API.md"), encoding="utf-8") as f:
            text = f.read()
        section = text.split("## 1. Python: the package `cryptovalid`")[1].split("**Not declared:**")[0]
        rows = [ln for ln in section.split("\n") if ln.startswith("| `")]
        named = set()
        for ln in rows:
            named |= set(re.findall(r"`([A-Za-z_][A-Za-z0-9_]*)(?:\(|`)", ln.split("|")[1]))
        self.assertEqual(named, set(cryptovalid.__all__))

    def test_api_md_signatures_are_the_runtime_ones(self):
        import inspect
        with open(os.path.join(HERE, "API.md"), encoding="utf-8") as f:
            text = f.read()
        found = 0
        for name, params in re.findall(r"`([a-z_]+)\(([^)]*)\) -> ", text):
            want = [p.split("=")[0].strip() for p in params.split(",")]
            self.assertEqual(want, list(inspect.signature(getattr(cryptovalid, name)).parameters), name)
            found += 1
        self.assertEqual(found, len([n for n in ORIGIN if n[0].islower()]))

    def test_import_needs_the_standard_library_only(self):
        code = ("import sys\n"
                "class Block:\n"
                "    def find_spec(self, name, path=None, target=None):\n"
                "        if name.split('.')[0] in ('cryptography', 'ap2_evidence', 'pqcrypto'):\n"
                "            raise ImportError('blocked: ' + name)\n"
                "sys.meta_path.insert(0, Block())\n"
                "sys.path.insert(0, sys.argv[1])\n"
                "import cryptovalid\n"
                "print(cryptovalid.verify_ledger(sys.argv[2])['verdict'])\n")
        r = subprocess.run([sys.executable, "-B", "-c", code, HERE, os.path.join(HERE, "examples", "sample_ledger.jsonl")],
                           capture_output=True, text=True)
        self.assertEqual((r.returncode, r.stdout.strip()), (0, "PASS"), r.stderr)
        # positive control: the block is real -- a module that needs cryptography at import time fails under it
        r = subprocess.run([sys.executable, "-B", "-c", code.replace("import cryptovalid\n", "import cryptography\nimport cryptovalid\n"),
                            HERE, "x"], capture_output=True, text=True)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("blocked: cryptography", r.stderr)


def _matches(value, tp):
    """True when `value` has the declared type `tp` (the subset of typing used in receipts.py)."""
    origin = typing.get_origin(tp)
    if tp is typing.Any:
        return True
    if origin is typing.Union:
        return any(_matches(value, a) for a in typing.get_args(tp))
    if tp is type(None):
        return value is None
    if origin in (list, typing.List):
        return isinstance(value, list) and all(_matches(v, typing.get_args(tp)[0]) for v in value)
    if origin in (dict, typing.Dict):
        return isinstance(value, dict) and all(isinstance(k, str) for k in value)
    if tp is int:
        return isinstance(value, int) and not isinstance(value, bool)
    return isinstance(value, tp)


def receipt_problems(receipt, typed_dict=receipts.LedgerReceipt):
    hints = typing.get_type_hints(typed_dict)
    out = ["key not declared: %s" % k for k in receipt if k not in hints]
    out += ["required key missing: %s" % k for k in typed_dict.__required_keys__ if k not in receipt]
    out += ["%s: %r is not %s" % (k, type(v).__name__, hints[k]) for k, v in receipt.items()
            if k in hints and not _matches(v, hints[k])]
    return out


def keys_built_by_verify_ledger():
    """(every top-level key the function can put in its receipt, the keys present in every dict it returns) -- read from
    the source with ast, so that a branch no test input reaches is still seen."""
    with open(os.path.join(HERE, "verifier.py"), encoding="utf-8") as f:
        tree = ast.parse(f.read())
    # verify_ledger may be a wrapper (it restores the recursion limit) around _verify_ledger, which builds the receipt
    fns = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name in ("verify_ledger", "_verify_ledger")]
    literals, added = [], set()
    for node in (x for fn in fns for x in ast.walk(fn)):
        d = None
        if isinstance(node, ast.Return) and isinstance(node.value, ast.Dict):
            d = node.value
        elif isinstance(node, (ast.Assign, ast.AnnAssign)) and isinstance(node.value, ast.Dict) and \
                any(isinstance(t, ast.Name) and t.id == "receipt"
                    for t in (node.targets if isinstance(node, ast.Assign) else [node.target])):
            d = node.value
        if d is not None:
            literals.append({k.value for k in d.keys})
        if isinstance(node, ast.Assign):
            for t in node.targets:
                if isinstance(t, ast.Subscript) and isinstance(t.value, ast.Name) and t.value.id == "receipt":
                    added.add(ast.literal_eval(t.slice))
    if not literals:
        raise AssertionError("no receipt dict found in verify_ledger / _verify_ledger: the reader of the source is out of date")
    return set().union(*literals) | added, set.intersection(*literals)


class TestLedgerReceiptType(unittest.TestCase):
    def test_declared_keys_are_the_keys_the_code_builds(self):
        every, always = keys_built_by_verify_ledger()
        self.assertEqual(every, set(typing.get_type_hints(receipts.LedgerReceipt)))
        self.assertEqual(always, set(receipts.LedgerReceipt.__required_keys__))
        self.assertEqual(len(every), 26)

    def test_real_receipts_have_the_declared_shape(self):
        paths = sorted(glob.glob(os.path.join(HERE, "spec", "vectors", "*.jsonl"))) + \
            sorted(glob.glob(os.path.join(HERE, "examples", "*.jsonl"))) + [os.path.join(HERE, "no_such_file.jsonl"), HERE]
        self.assertGreaterEqual(len(paths), 15)
        verdicts = set()
        for p in paths:
            r = cryptovalid.verify_ledger(p)
            verdicts.add(r["verdict"])
            self.assertEqual(receipt_problems(r), [], p)
        self.assertEqual(verdicts, {"PASS", "FAIL", "FILE_NOT_FOUND"})

    def test_receipt_with_signed_tip_and_signature_layer(self):
        try:
            import cryptography  # noqa: F401
        except ImportError:
            if os.environ.get("CV_REQUIRE_CRYPTO") == "1":
                raise
            self.skipTest("cryptography not installed")
        import cryptovalid_tip
        import signer
        with tempfile.TemporaryDirectory() as d:
            key = os.path.join(d, "k.key")
            pub = signer.keygen(key)["public_key_hex"]
            signed = os.path.join(d, "signed.jsonl")
            signer.sign_ledger(os.path.join(HERE, "examples", "sample_ledger.jsonl"), signed, key)
            cryptovalid_tip.sign_tip(signed, key)
            r = cryptovalid.verify_ledger(signed, trusted_pubkey_hex=pub, require_tip=True)
            self.assertEqual((r["verdict"], r["tip"]["ok"], r["signatures_not_checked"]), ("PASS", True, 3))
            self.assertEqual(receipt_problems(r), [])
            os.remove(signed + ".tip.json")
            r = cryptovalid.verify_ledger(signed, trusted_pubkey_hex=pub, require_tip=True)
            self.assertEqual(r["verdict"], "FAIL")
            self.assertEqual(receipt_problems(r), [])

    def test_positive_controls_a_wrong_receipt_is_reported(self):
        good = cryptovalid.verify_ledger(os.path.join(HERE, "examples", "sample_ledger.jsonl"))
        self.assertEqual(receipt_problems(good), [])
        self.assertEqual(receipt_problems(dict(good, new_key=1)), ["key not declared: new_key"])
        self.assertEqual(len(receipt_problems(dict(good, entries_count="3"))), 1)
        self.assertEqual(len(receipt_problems(dict(good, chain_integrity=1))), 1)
        self.assertEqual(len(receipt_problems(dict(good, entries_count=True))), 1)
        self.assertEqual(len(receipt_problems(dict(good, tip="x"))), 1)
        self.assertEqual(len(receipt_problems(dict(good, algorithm_supported=["sha256", 3]))), 1)
        self.assertEqual(receipt_problems({k: v for k, v in good.items() if k != "verdict"}), ["required key missing: verdict"])


def build_wheel(tree, out):
    """Build the wheel of `tree` with the installed setuptools (no network, no isolation). -> path of the wheel."""
    code = "import sys, setuptools.build_meta as b; print(b.build_wheel(sys.argv[1]))"
    r = subprocess.run([sys.executable, "-c", code, out], cwd=tree, capture_output=True, text=True)
    if r.returncode != 0:
        raise RuntimeError(r.stderr[-2000:])
    return os.path.join(out, r.stdout.strip().split("\n")[-1])


def copy_sources(dst):
    import shutil
    for n in os.listdir(HERE):
        if (n.endswith(".py") and not n.startswith("test_")) or n in ("pyproject.toml", "README.md", "LICENSE", "NOTICE"):
            shutil.copyfile(os.path.join(HERE, n), os.path.join(dst, n))
    shutil.copytree(os.path.join(HERE, "cryptovalid"), os.path.join(dst, "cryptovalid"),
                    ignore=shutil.ignore_patterns("__pycache__"))


TYPED_FILES = {"cryptovalid/py.typed", "cryptovalid/__init__.pyi", "cryptovalid/__init__.py", "cryptovalid/receipts.py"}


class TestWheelCarriesTheTypes(unittest.TestCase):
    """PEP 561: `py.typed` and the stub must be INSIDE the installed package; listing the package is not enough."""

    @classmethod
    def setUpClass(cls):
        # the build requirement of pyproject.toml is setuptools>=77 (PEP 639 licence expression); an older setuptools
        # installed here cannot build the wheel at all, which says nothing about the types: skip, naming it
        try:
            import setuptools
            import setuptools.build_meta  # noqa: F401
            installed = setuptools.__version__          # the module that build_wheel will import, not other metadata
            major = int(installed.split(".")[0])
        except (ImportError, ValueError):
            raise unittest.SkipTest("setuptools is not installed: the wheel cannot be built here")
        if major < 77:
            raise unittest.SkipTest(f"setuptools {installed} < 77, the build requirement of pyproject.toml")
        cls.tmp = tempfile.TemporaryDirectory()
        cls.tree = os.path.join(cls.tmp.name, "tree")
        os.mkdir(cls.tree)
        copy_sources(cls.tree)
        os.mkdir(os.path.join(cls.tmp.name, "out"))
        cls.wheel = build_wheel(cls.tree, os.path.join(cls.tmp.name, "out"))
        with zipfile.ZipFile(cls.wheel) as z:
            cls.names = set(z.namelist())

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_wheel_has_marker_stub_package_and_flat_modules(self):
        self.assertEqual(TYPED_FILES - self.names, set())
        for flat in ("verifier.py", "evidence_pack.py", "signer.py", "cryptovalid_merkle.py", "verify_evidence.py"):
            self.assertIn(flat, self.names)
        self.assertFalse([n for n in self.names if n.startswith(("tools/", "test_", "proposte_governo/"))])

    def test_installed_wheel_imports_and_reports_its_version(self):
        site = os.path.join(self.tmp.name, "site")
        with zipfile.ZipFile(self.wheel) as z:
            z.extractall(site)
        with open(os.path.join(HERE, "pyproject.toml"), encoding="utf-8") as f:
            version = re.search(r'^version\s*=\s*"([^"]+)"', f.read(), re.M).group(1)
        code = ("import sys; sys.path.insert(0, sys.argv[1]); import cryptovalid, verifier, os\n"
                "assert os.path.dirname(cryptovalid.__file__).startswith(sys.argv[1]), cryptovalid.__file__\n"
                "assert os.path.dirname(verifier.__file__) == sys.argv[1], verifier.__file__\n"
                "print(cryptovalid.__version__, cryptovalid.verify_ledger(sys.argv[2])['verdict'])\n")
        r = subprocess.run([sys.executable, "-B", "-c", code, site, os.path.join(HERE, "examples", "sample_ledger.jsonl")],
                           capture_output=True, text=True, cwd=self.tmp.name)
        self.assertEqual(r.stdout.strip(), version + " PASS", r.stderr)

    def test_positive_controls_a_wheel_without_the_package_or_the_marker_is_seen(self):
        # (1) the 0.24.0 pyproject (no `packages` line): the directory is there, the wheel does not contain it
        tree = os.path.join(self.tmp.name, "tree_nopkg")
        os.mkdir(tree)
        copy_sources(tree)
        p = os.path.join(tree, "pyproject.toml")
        with open(p, encoding="utf-8") as f:
            text = f.read()
        cut = re.sub(r"^packages\s*=.*\n", "", text[:text.index("\n[tool.setuptools.package-data]")] + "\n", flags=re.M)
        self.assertNotIn("packages", cut.split("[tool.setuptools]")[1].replace("no `packages`", ""))
        with open(p, "w", encoding="utf-8") as f:
            f.write(cut)
        out = os.path.join(self.tmp.name, "out_nopkg")
        os.mkdir(out)
        with zipfile.ZipFile(build_wheel(tree, out)) as z:
            names = set(z.namelist())
        self.assertIn("verifier.py", names)
        self.assertEqual(TYPED_FILES - names, TYPED_FILES)
        # (2) the package without its marker: only py.typed is missing, and the check says so
        tree = os.path.join(self.tmp.name, "tree_nomarker")
        os.mkdir(tree)
        copy_sources(tree)
        os.remove(os.path.join(tree, "cryptovalid", "py.typed"))
        out = os.path.join(self.tmp.name, "out_nomarker")
        os.mkdir(out)
        with zipfile.ZipFile(build_wheel(tree, out)) as z:
            names = set(z.namelist())
        self.assertEqual(TYPED_FILES - names, {"cryptovalid/py.typed"})


if __name__ == "__main__":
    unittest.main()
