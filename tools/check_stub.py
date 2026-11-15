#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Compare a PEP 561 stub (`__init__.pyi`) with the package it describes, at runtime. Standard library only.

    python3 check_stub.py <directory that contains the package> <package> [<directory of the flat modules>]
    exit 0 no difference, 1 differences (one per line), 2 usage

It is what `python -m mypy.stubtest` does for names and signatures, written here because mypy is not available where
this was developed; when mypy is installed, stubtest is the reference and this stays as a second, dependency-free check.

Checked: the stub parses; `__all__` of the stub == `__all__` at runtime; every function, class and annotated variable of
the stub exists at runtime; for a function: same parameter names, order and kind, and a default in the stub exactly
where the runtime has one; for a class: it is a class and its bases have the names the stub gives; every public name
defined at runtime is in `__all__`. NOT checked: that the annotated types are true (a type checker on the callers and
the receipt tests do that).
"""
import ast
import importlib
import inspect
import os
import sys


def stub_signature(fn):
    a = fn.args
    out = []
    n_pos = len(a.posonlyargs) + len(a.args)
    first_default = n_pos - len(a.defaults)
    for i, p in enumerate(a.posonlyargs + a.args):
        kind = "POSITIONAL_ONLY" if i < len(a.posonlyargs) else "POSITIONAL_OR_KEYWORD"
        out.append((p.arg, kind, i >= first_default))
    if a.vararg:
        out.append((a.vararg.arg, "VAR_POSITIONAL", False))
    for p, d in zip(a.kwonlyargs, a.kw_defaults):
        out.append((p.arg, "KEYWORD_ONLY", d is not None))
    if a.kwarg:
        out.append((a.kwarg.arg, "VAR_KEYWORD", False))
    return out


def runtime_signature(obj):
    return [(p.name, p.kind.name, p.default is not inspect.Parameter.empty)
            for p in inspect.signature(obj).parameters.values()]


def literal_all(tree):
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "__all__" for t in node.targets):
            return list(ast.literal_eval(node.value))
    return None


def compare(stub_source, module):
    """-> list of differences between the stub text and the imported module."""
    diffs = []
    try:
        tree = ast.parse(stub_source)
    except SyntaxError as e:
        return ["the stub does not parse: %s" % e]
    s_all, r_all = literal_all(tree), getattr(module, "__all__", None)
    if s_all is None:
        diffs.append("the stub has no __all__")
    if r_all is None:
        diffs.append("the runtime package has no __all__")
    if s_all is not None and r_all is not None and sorted(s_all) != sorted(r_all):
        diffs.append("__all__ differs: only in stub %s, only at runtime %s"
                     % (sorted(set(s_all) - set(r_all)), sorted(set(r_all) - set(s_all))))
    declared = set()
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            declared.add(node.name)
            obj = getattr(module, node.name, None)
            if obj is None or not callable(obj):
                diffs.append("%s: in the stub, not a callable at runtime" % node.name)
                continue
            s, r = stub_signature(node), runtime_signature(obj)
            if s != r:
                diffs.append("%s: signature differs: stub %s, runtime %s" % (node.name, s, r))
            if node.returns is None or any(p.annotation is None for p in ast.walk(node.args) if isinstance(p, ast.arg)):
                diffs.append("%s: the stub leaves a parameter or the return without a type" % node.name)
        elif isinstance(node, ast.ClassDef):
            declared.add(node.name)
            obj = getattr(module, node.name, None)
            if not inspect.isclass(obj):
                diffs.append("%s: a class in the stub, not at runtime" % node.name)
                continue
            s_bases = [ast.unparse(b).split(".")[-1] for b in node.bases]
            mro = [c.__name__ for c in obj.__mro__[1:]]
            for b in s_bases:
                if b not in mro:
                    diffs.append("%s: the stub gives the base %s, the runtime bases are %s" % (node.name, b, mro))
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            declared.add(node.target.id)
            if not hasattr(module, node.target.id):
                diffs.append("%s: in the stub, absent at runtime" % node.target.id)
        elif isinstance(node, ast.ImportFrom):
            for a in node.names:
                if a.asname and a.asname == a.name:          # `import X as X`: a re-export
                    declared.add(a.name)
                    if not hasattr(module, a.name):
                        diffs.append("%s: re-exported by the stub, absent at runtime" % a.name)
    if s_all is not None:
        for n in sorted(set(s_all) - declared):
            diffs.append("%s: in __all__ of the stub but not declared in it" % n)
    if r_all is not None:
        for n, v in sorted(vars(module).items()):
            if n.startswith("_") or inspect.ismodule(v) or n in r_all:
                continue
            diffs.append("%s: public at runtime, not in __all__" % n)
    return diffs


def main(argv):
    if len(argv) not in (2, 3):
        sys.stderr.write(__doc__.split("\n\n")[1] + "\n")
        return 2
    sys.dont_write_bytecode = True
    for d in argv[2:3] + argv[:1]:
        sys.path.insert(0, os.path.abspath(d))
    module = importlib.import_module(argv[1])
    stub = os.path.join(os.path.dirname(module.__file__), "__init__.pyi")
    with open(stub, encoding="utf-8") as f:
        diffs = compare(f.read(), module)
    for d in diffs:
        print(d)
    print("stub %s: %d difference(s)" % (stub, len(diffs)))
    return 1 if diffs else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
