#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Roberto Locatelli
"""0.21.0 (14/10/2026): a .pyc already cut is compiled from the source, not read.

CPython 3.9 and 3.11 write a bytecode cache with one raw write; cut by a file size limit, it stays, and every later import
of that module failed with EOFError: marshal data too short (exit 1, the code of a FAIL for most commands). 0.20.3 stopped
the commands from writing a cache (sys.dont_write_bytecode) but a cache cut by another program, or by an earlier version,
was still read: measured 14/10 on 0.20.3, verifier's cache cut at any of 233 to 346 offsets from byte 16 on (3.9, 3.11,
3.13) made `cryptovalid_merkle.py sth` exit 1. Every command now wraps the loader's get_code: an EOFError or ValueError from
a cache is followed by a compile of the source. Measured cost: at most 1.4 ms (median of 20 runs, three commands, Python
3.9, 3.11, 3.13). This test cuts the cache of `verifier` (imported by every command) and of `cryptovalid_merkle` at many
offsets and asks for the receipt of a run without a cache, byte for byte."""
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ENV = {k: v for k, v in os.environ.items() if k not in ("PYTHONDONTWRITEBYTECODE", "PYTHONPYCACHEPREFIX")}


class TestCutBytecodeCache(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp(); self.addCleanup(shutil.rmtree, self.d, True)
        for f in os.listdir(HERE):
            if f.endswith(".py"):
                shutil.copy(os.path.join(HERE, f), self.d)
        shutil.copy(os.path.join(HERE, "examples", "sample_ledger.jsonl"), self.d)

    def run_cmd(self, *args):
        p = subprocess.run([sys.executable] + list(args), cwd=self.d, capture_output=True, text=True, env=ENV)
        # the eIDAS report carries the time of its run: the instant, not the content, is masked
        return p.returncode, re.sub(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d+)?\+00:00", "<t>", p.stdout), p.stderr

    def cut_at_offsets(self, module, cmd):
        shutil.rmtree(os.path.join(self.d, "__pycache__"), ignore_errors=True)
        ref = self.run_cmd(*cmd)
        self.assertEqual(ref[0], 0, ref[2])
        src = os.path.join(self.d, module + ".py")
        import importlib.util
        import py_compile
        cfile = importlib.util.cache_from_source(src)
        py_compile.compile(src, cfile=cfile, doraise=True)
        with open(cfile, "rb") as f:
            full = f.read()
        offsets = sorted(set(list(range(0, 40)) + list(range(40, len(full), max(1, len(full) // 40))) + [len(full) - 1]))
        for off in offsets:
            with open(cfile, "wb") as f:
                f.write(full[:off])
            got = self.run_cmd(*cmd)
            self.assertEqual(got[:2], ref[:2], f"{module}.pyc cut at {off} of {len(full)}: {got[2][-200:]}")
            self.assertEqual(got[2], "", f"{module}.pyc cut at {off}")
        return len(offsets)

    def test_verifier_cache_cut(self):
        self.assertGreater(self.cut_at_offsets("verifier", ["cryptovalid_merkle.py", "sth", "sample_ledger.jsonl"]), 40)

    def test_merkle_cache_cut(self):
        self.assertGreater(self.cut_at_offsets("cryptovalid_merkle", ["eidas_ledger_check.py", "sample_ledger.jsonl"]), 40)

    def test_a_cache_with_bad_marshal_data(self):
        # a cache whose header is valid and whose body is not marshal data (ValueError: bad marshal data), not only cut
        shutil.rmtree(os.path.join(self.d, "__pycache__"), ignore_errors=True)
        ref = self.run_cmd("cryptovalid_merkle.py", "sth", "sample_ledger.jsonl")
        import importlib.util
        import py_compile
        src = os.path.join(self.d, "verifier.py"); cfile = importlib.util.cache_from_source(src)
        py_compile.compile(src, cfile=cfile, doraise=True)
        with open(cfile, "rb") as f:
            head = f.read(16)
        for body in (b"\xff" * 64, b"\x00" * 64):
            with open(cfile, "wb") as f:
                f.write(head + body)
            self.assertEqual(self.run_cmd("cryptovalid_merkle.py", "sth", "sample_ledger.jsonl"), ref, body[:1])

    def test_a_whole_cache_gives_the_same_receipt(self):   # control: nothing changes when the cache is whole
        shutil.rmtree(os.path.join(self.d, "__pycache__"), ignore_errors=True)
        ref = self.run_cmd("cryptovalid_merkle.py", "sth", "sample_ledger.jsonl")
        subprocess.run([sys.executable, "-c", "import verifier, cryptovalid_merkle"], cwd=self.d, check=True, env=ENV)
        self.assertTrue(any(x.startswith("verifier.") for x in os.listdir(os.path.join(self.d, "__pycache__"))))
        self.assertEqual(self.run_cmd("cryptovalid_merkle.py", "sth", "sample_ledger.jsonl"), ref)

    def test_every_command_carries_the_wrapper(self):
        guard = "    _sys_0203.dont_write_bytecode = True"
        n = 0
        for f in sorted(os.listdir(HERE)):
            if f.endswith(".py") and not f.startswith("test_"):
                with open(os.path.join(HERE, f), encoding="utf-8") as fh:
                    s = fh.read()
                if guard in s:
                    n += 1
                    self.assertIn("        _L0210.get_code = _get_code_0210", s, f)
        self.assertEqual(n, 33)


if __name__ == "__main__":
    unittest.main(verbosity=2)
