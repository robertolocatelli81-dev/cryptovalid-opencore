#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Measure, with ast only (no import, no execution), how much of the shipped modules is annotated and which
top-level names are used from outside the module that defines them.

    python3 tools/misura_api.py            # Markdown tables on stdout
    python3 tools/misura_api.py --json     # the same numbers as JSON

What it counts, per module listed in `py-modules` of pyproject.toml:
  defs            every `def` / `async def`, nested ones and methods included
  ret             ... of which carry a return annotation
  params/ann      parameters (self and cls excluded; *args and **kwargs included) and how many are annotated
  bare_dict       return annotations that are exactly `dict` or `Dict` (a receipt without a declared shape)
  public          top-level `def` / `class` whose name does not start with "_"
  used_outside    public top-level names read from another file of the repository (`from m import n`, or `m.n` after
                  `import m` / `import m as x`), split into: other shipped modules, test_*.py, anything else

Limits: a name reached through getattr(), importlib or a string is not seen; `from m import *` is reported apart.
"""
import ast
import json
import os
import re
import subprocess
import sys

def _root():
    """The repository root: the nearest directory above this file that holds pyproject.toml."""
    d = os.path.dirname(os.path.abspath(__file__))
    while not os.path.isfile(os.path.join(d, "pyproject.toml")):
        up = os.path.dirname(d)
        if up == d:
            raise SystemExit("misura_api: no pyproject.toml above " + __file__)
        d = up
    return d


HERE = _root()

# The "Core" table of README.md (0.24.0): the 11 Python modules the project maintains as its core.
CORE = ["verifier", "cryptovalid_tip", "ed25519_order", "signer", "cryptovalid_kms", "cryptovalid_tsa",
        "cryptovalid_merkle", "cryptovalid_checkpoint", "evidence_pack", "verify_evidence", "conformance"]


def shipped_modules(root=HERE):
    with open(os.path.join(root, "pyproject.toml"), encoding="utf-8") as f:
        m = re.search(r"py-modules\s*=\s*\[(.*?)\]", f.read(), re.S)
    return sorted(re.findall(r"'([A-Za-z0-9_]+)'", m.group(1)))


def measure_source(src, filename="<src>"):
    """Counts for one source text. Pure function: the positive control of the test calls it on a known text."""
    tree = ast.parse(src, filename)
    out = {"defs": 0, "ret": 0, "params": 0, "ann": 0, "bare_dict": 0, "public": [], "public_funcs": 0,
           "public_funcs_fully_annotated": 0, "has_all": False, "future_annotations": False}

    def fully(fn):
        a = fn.args
        ps = a.posonlyargs + a.args + a.kwonlyargs + ([a.vararg] if a.vararg else []) + ([a.kwarg] if a.kwarg else [])
        ps = [p for i, p in enumerate(ps) if not (i == 0 and p.arg in ("self", "cls"))]
        return ps, [p for p in ps if p.annotation is not None]

    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            out["defs"] += 1
            ps, ann = fully(node)
            out["params"] += len(ps)
            out["ann"] += len(ann)
            if node.returns is not None:
                out["ret"] += 1
                r = node.returns
                if (isinstance(r, ast.Name) and r.id in ("dict", "Dict")) or \
                   (isinstance(r, ast.Constant) and r.value in ("dict", "Dict")):
                    out["bare_dict"] += 1
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and not node.name.startswith("_"):
            out["public"].append(node.name)
            if not isinstance(node, ast.ClassDef):
                out["public_funcs"] += 1
                ps, ann = fully(node)
                if node.returns is not None and len(ps) == len(ann):
                    out["public_funcs_fully_annotated"] += 1
        if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "__all__" for t in node.targets):
            out["has_all"] = True
        if isinstance(node, ast.ImportFrom) and node.module == "__future__" and any(a.name == "annotations" for a in node.names):
            out["future_annotations"] = True
    return out


def uses_in_source(src, modules, filename="<src>"):
    """{module: set(names)} read by this source from the given modules, and the set of modules star-imported."""
    tree = ast.parse(src, filename)
    alias = {}          # local name -> module
    used = {}
    star = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                if a.name in modules:
                    alias[a.asname or a.name] = a.name
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module in modules:
            for a in node.names:
                if a.name == "*":
                    star.add(node.module)
                else:
                    used.setdefault(node.module, set()).add(a.name)
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) and node.value.id in alias:
            used.setdefault(alias[node.value.id], set()).add(node.attr)
    return used, star


def tracked_python(root=HERE):
    r = subprocess.run(["git", "-C", root, "ls-files", "*.py"], capture_output=True, text=True, check=True)
    return [f for f in r.stdout.split() if not f.startswith("proposte_governo/")]


def measure(root=HERE):
    mods = shipped_modules(root)
    per = {}
    for m in mods:
        with open(os.path.join(root, m + ".py"), encoding="utf-8") as f:
            per[m] = measure_source(f.read(), m + ".py")
        per[m]["used_by_modules"], per[m]["used_by_tests"], per[m]["used_by_other"] = set(), set(), set()
    star = {}
    for path in tracked_python(root):
        with open(os.path.join(root, path), encoding="utf-8") as f:
            src = f.read()
        try:
            used, st = uses_in_source(src, set(mods), path)
        except SyntaxError:
            continue
        base = os.path.basename(path)
        me = path[:-3] if "/" not in path else None
        for m in st:
            star.setdefault(m, []).append(path)
        for m, names in used.items():
            if m == me:
                continue
            kind = "used_by_tests" if base.startswith("test_") else ("used_by_modules" if me in per else "used_by_other")
            per[m][kind] |= names
    for m in mods:
        pub = set(per[m]["public"])
        allu = per[m]["used_by_modules"] | per[m]["used_by_tests"] | per[m]["used_by_other"]
        per[m]["private_used_outside"] = sorted(n for n in allu if n.startswith("_") and not n.startswith("__"))
        per[m]["public_used_outside"] = sorted(allu & pub)
        per[m]["public_used_by_non_tests"] = sorted((per[m]["used_by_modules"] | per[m]["used_by_other"]) & pub)
        for k in ("used_by_modules", "used_by_tests", "used_by_other"):
            per[m][k] = sorted(per[m][k])
    return {"modules": per, "core": CORE, "star_imports": star}


def _sum(per, mods, key):
    return sum(len(per[m][key]) if isinstance(per[m][key], list) else per[m][key] for m in mods)


def markdown(res):
    per, core = res["modules"], res["core"]
    mods = sorted(per)
    L = []
    row = "| {} | {} | {} | {} | {}/{} | {} | {} | {}/{} | {} | {} | {} |"
    L.append("| module | core | defs | with return type | params annotated | bare dict returns | public top-level | "
             "public funcs fully annotated | public used outside | private used outside | `__all__` |")
    L.append("|---|---|---|---|---|---|---|---|---|---|---|")
    for m in core + [x for x in mods if x not in core]:
        p = per[m]
        L.append("| `{}` | {} | {} | {} | {}/{} | {} | {} | {}/{} | {} | {} | {} |".format(
            m, "yes" if m in core else "", p["defs"], p["ret"], p["ann"], p["params"], p["bare_dict"], len(p["public"]),
            p["public_funcs_fully_annotated"], p["public_funcs"], len(p["public_used_outside"]),
            len(p["private_used_outside"]), "yes" if p["has_all"] else "no"))
    for label, ms in (("**core (11)**", core), ("**all shipped (%d)**" % len(mods), mods)):
        L.append("| {} | | {} | {} | {}/{} | {} | {} | {}/{} | {} | {} | {} |".format(
            label, _sum(per, ms, "defs"), _sum(per, ms, "ret"), _sum(per, ms, "ann"), _sum(per, ms, "params"),
            _sum(per, ms, "bare_dict"), _sum(per, ms, "public"), _sum(per, ms, "public_funcs_fully_annotated"),
            _sum(per, ms, "public_funcs"), _sum(per, ms, "public_used_outside"), _sum(per, ms, "private_used_outside"),
            sum(1 for m in ms if per[m]["has_all"])))
    return "\n".join(L)


def main(argv):
    res = measure()
    if "--json" in argv:
        json.dump(res, sys.stdout, indent=1, sort_keys=True)
        print()
    else:
        print(markdown(res))
        print()
        print("star imports of shipped modules:", res["star_imports"] or "none")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
