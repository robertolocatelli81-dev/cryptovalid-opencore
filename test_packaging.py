#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
"""The wheel must contain EVERY product module: pyproject lists them by hand (lesson from omega-health-companion
0.4.0 on 2026-09-13, whose wheel shipped without four modules). Red whenever a module is missing from the list.

0.17.1: also every local module that a shipped module imports (`ap2_evidence` imports `sigsuite` from pqcrypto/, which
the 0.17.0 wheel did not contain), the `sign` extra, and no file or URL handle left open in a shipped module; on 0.17.0
each of these three tests fails."""
import os, re, unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
EXCLUDE = {"demo", "setup"}


class TestPackaging(unittest.TestCase):
    def test_every_product_module_is_packaged(self):
        with open(os.path.join(_HERE, "pyproject.toml"), encoding="utf-8") as f:
            m = re.search(r"py-modules\s*=\s*\[(.*?)\]", f.read(), re.S)
        listed = set(re.findall(r"'([A-Za-z0-9_]+)'", m.group(1)))
        on_disk = {n[:-3] for n in os.listdir(_HERE) if n.endswith(".py") and not n.startswith("test_") and n[:-3] not in EXCLUDE}
        self.assertEqual(on_disk - listed, set(), f"modules not packaged: {sorted(on_disk - listed)}")
        self.assertEqual(listed - on_disk, set(), f"listed but absent: {sorted(listed - on_disk)}")


import ast
import sys

HERE = _HERE

try:
    import tomllib
except ModuleNotFoundError:  # Python < 3.11
    tomllib = None

# Kept open on purpose: the segment file of an append-only writer, closed on rollover and in close().
LONG_LIVED = {("cryptovalid_ingest.py", "self._fh")}


def shipped_files(pyproject_path: str) -> list:
    with open(pyproject_path, "rb") as f:
        st = tomllib.load(f)["tool"]["setuptools"]
    files = [m + ".py" for m in st.get("py-modules", [])]
    for pkg in st.get("packages", []):
        d = os.path.join(HERE, pkg.replace(".", os.sep))
        files += [os.path.join(pkg, n) for n in sorted(os.listdir(d)) if n.endswith(".py")]
    return files


def local_modules() -> dict:
    """Module name -> repository path, for the .py files at the root and in pqcrypto/ (where ap2_evidence looks)."""
    out = {}
    for sub in ("", "pqcrypto"):
        d = os.path.join(HERE, sub)
        for n in os.listdir(d):
            if n.endswith(".py"):
                out.setdefault(n[:-3], os.path.join(sub, n) if sub else n)
    return out


def imported_names(path: str) -> set:
    with open(os.path.join(HERE, path), encoding="utf-8") as f:
        tree = ast.parse(f.read())
    names = set()
    for n in ast.walk(tree):
        if isinstance(n, ast.Import):
            names |= {a.name.split(".")[0] for a in n.names}
        elif isinstance(n, ast.ImportFrom) and n.module and n.level == 0:
            names.add(n.module.split(".")[0])
    return names


def missing_from_wheel(pyproject_path: str) -> list:
    shipped = shipped_files(pyproject_path)
    local = local_modules()
    missing = []
    for path in shipped:
        if os.path.basename(path).startswith("test_"):
            continue
        for name in sorted(imported_names(path)):
            if name in local and local[name] not in shipped and not local[name].startswith("test_"):
                missing.append(f"{path} imports {name} ({local[name]}), not in the wheel")
    return missing


def unclosed_handles(path: str) -> list:
    """open()/urlopen() calls that are not a `with` item and whose result is not kept as a long-lived handle."""
    with open(os.path.join(HERE, path), encoding="utf-8") as f:
        tree = ast.parse(f.read())
    managed, kept = set(), set()
    for n in ast.walk(tree):
        if isinstance(n, (ast.With, ast.AsyncWith)):
            managed |= {id(i.context_expr) for i in n.items}
        if isinstance(n, ast.Assign) and len(n.targets) == 1 and \
                (os.path.basename(path), ast.unparse(n.targets[0])) in LONG_LIVED:
            kept.add(id(n.value))
    out = []
    for n in ast.walk(tree):
        if isinstance(n, ast.Call) and id(n) not in managed and id(n) not in kept:
            f = n.func
            name = f.id if isinstance(f, ast.Name) else f.attr if isinstance(f, ast.Attribute) else ""
            is_os = isinstance(f, ast.Attribute) and isinstance(f.value, ast.Name) and f.value.id == "os"
            if name in ("open", "urlopen") and not is_os:
                out.append(f"{path}:{n.lineno}")
    return out


@unittest.skipIf(tomllib is None, "tomllib needs Python 3.11+")
class TestWheelContents(unittest.TestCase):
    def test_every_imported_local_module_is_shipped(self):
        self.assertEqual(missing_from_wheel(os.path.join(HERE, "pyproject.toml")), [])

    def test_sign_extra_declares_cryptography(self):
        with open(os.path.join(HERE, "pyproject.toml"), "rb") as f:
            extras = tomllib.load(f)["project"]["optional-dependencies"]
        self.assertIn("cryptography>=50", extras.get("sign", []))

    def test_no_unclosed_handle_in_shipped_modules(self):
        files = [p for p in shipped_files(os.path.join(HERE, "pyproject.toml"))
                 if not os.path.basename(p).startswith("test_")]
        self.assertEqual([x for p in files for x in unclosed_handles(p)], [])


if __name__ == "__main__":
    unittest.main()
