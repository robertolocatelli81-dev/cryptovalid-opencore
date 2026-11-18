#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""SPEC v0.12 §5 step 0 "every path read", the verifiers that the first sweep did not reach (review of 18/11/2026: a FIFO
with no writer given to each of them did not return in 25 s on 54fc7eb): `cryptovalid_jws verify`, `cryptovalid_scitt
verify`, `cryptovalid_witness verify`, `cryptovalid_receipt verify`, `cryptovalid_monitor` (the ledger and the state),
`eidas_ledger_check`, `cryptovalid_heterogeneous`, `cryptovalid_reanchor`, `tx_evidence verify`, `dora_incident verify`,
`cryptovalid_report` (MANIFEST.json and SOLANA_ANCHOR.json of the pack) and the MCP server's provenance hash.
Each now opens the path once without blocking and judges the open descriptor: a FIFO, a device or a directory is the
error the command gives for a file it cannot read, never a wait. A regular file is read as before (the control).

Each case runs in a child process with a timeout. Positive control, measured: on 54fc7eb 2 of the 3 tests fail
(every FIFO case times out); the control on a regular file passes there."""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True
ROOT = os.path.dirname(os.path.abspath(__file__))
K = "00" * 32
WAIT = 15   # above FIFO_IDLE_SECONDS: eidas_ledger_check runs verifier.verify_ledger first, which reads a FIFO ledger


def commands(bad, good_json):
    """(name, argv) with `bad` in the place of the file the command reads"""
    ledger = os.path.join(ROOT, "examples", "sample_ledger.jsonl")
    return [
        ("jws verify", ["cryptovalid_jws.py", "verify", bad, K]),
        ("scitt verify", ["cryptovalid_scitt.py", "verify", bad, "--issuer-pubkey", K, "--ts-pubkey", K]),
        ("witness verify", ["cryptovalid_witness.py", "verify", "--log-vkey", "x+00000000+AAAA", bad]),
        ("receipt verify", ["cryptovalid_receipt.py", "verify", bad, K]),
        ("monitor state", ["cryptovalid_monitor.py", ledger, bad]),
        ("eidas ledger", ["eidas_ledger_check.py", bad]),
        ("heterogeneous", ["cryptovalid_heterogeneous.py", "a" * 64, bad]),
        ("reanchor", ["cryptovalid_reanchor.py", "--age-days", "1", bad]),
        ("tx verify", ["tx_evidence.py", "verify", bad, good_json]),
        ("dora verify", ["dora_incident.py", "verify", bad, good_json]),
    ]


class Readers(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.mkdtemp()
        self.good = os.path.join(self.td, "good.json")
        with open(self.good, "w") as f:
            json.dump([], f)

    def tearDown(self):
        shutil.rmtree(self.td)

    def run_cmd(self, argv):
        env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
        env["HOME"] = self.td
        try:
            p = subprocess.run([sys.executable] + argv, cwd=ROOT, capture_output=True, text=True, timeout=WAIT, env=env)
        except subprocess.TimeoutExpired:
            return None
        return p

    def test_fifo_device_directory_never_wait(self):
        fifo = os.path.join(self.td, "f.fifo")
        os.mkfifo(fifo)
        dev = os.path.join(self.td, "zero")
        os.symlink("/dev/zero", dev)
        sub = os.path.join(self.td, "d")
        os.mkdir(sub)
        for bad in (fifo, dev, sub):
            for name, argv in commands(bad, self.good):
                with self.subTest(name=name, bad=os.path.basename(bad)):
                    p = self.run_cmd(argv)
                    self.assertIsNotNone(p, f"{name} did not return in {WAIT} s on {bad}")
                    self.assertNotEqual(p.returncode, 0, (name, p.stdout[-300:], p.stderr[-300:]))

    def test_regular_file_still_read(self):
        """control: the same readers on a regular file read it (the outcome is the command's, never an unreadable)"""
        p = self.run_cmd(["cryptovalid_reanchor.py", "--age-days", "1", self.good])
        self.assertIsNotNone(p)
        self.assertNotIn("not a regular file", p.stdout + p.stderr)
        p = self.run_cmd(["eidas_ledger_check.py", os.path.join(ROOT, "examples", "sample_ledger.jsonl")])
        self.assertEqual(p.returncode, 0, p.stderr[-300:])


class PackReaders(unittest.TestCase):
    """the MCP server's provenance hash and the report read MANIFEST.json / SOLANA_ANCHOR.json of a pack again after
    verify_pack: a FIFO there left the server and the report waiting on 54fc7eb"""

    def test_mcp_and_report(self):
        td = tempfile.mkdtemp()
        try:
            env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
            env["HOME"] = td
            pack = os.path.join(td, "pack")
            subprocess.run([sys.executable, "evidence_pack.py", "build", pack, os.path.join("examples", "sample_ledger.jsonl"),
                            "--subject", "t"], cwd=ROOT, check=True, capture_output=True, env=env)
            os.mkfifo(os.path.join(pack, "SOLANA_ANCHOR.json"))
            p = subprocess.run([sys.executable, "cryptovalid_report.py", "--html-only", "--out", os.path.join(td, "r.html"),
                                pack], cwd=ROOT, capture_output=True, text=True, timeout=WAIT, env=env)
            self.assertIn("SOLANA_ANCHOR.json unreadable: InputNotRegular", p.stdout)
            os.remove(os.path.join(pack, "MANIFEST.json"))
            os.mkfifo(os.path.join(pack, "MANIFEST.json"))
            code = ("import json, sys, cryptovalid_mcp as M; r = M.t_verify_pack({'pack_dir': sys.argv[1]}); "
                    "print(json.dumps([r['result']['valid'], r['provenance']['sha256']]))")
            p = subprocess.run([sys.executable, "-c", code, pack], cwd=ROOT, capture_output=True, text=True, timeout=WAIT, env=env)
            self.assertEqual(json.loads(p.stdout), [False, None], p.stderr[-300:])
            p = subprocess.run([sys.executable, "cryptovalid_report.py", "--html-only", "--out", os.path.join(td, "r.html"),
                                pack], cwd=ROOT, capture_output=True, text=True, timeout=WAIT, env=env)
            self.assertIn("MANIFEST.json unreadable: InputNotRegular", p.stdout)
        finally:
            shutil.rmtree(td)


if __name__ == "__main__":
    unittest.main(verbosity=2)
