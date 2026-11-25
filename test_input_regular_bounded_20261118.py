#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""SPEC v0.11 §5 step 0, §10, §11 (18/11/2026): a path is opened once without blocking, judged on the open descriptor
(a regular file, within the size bound), and a file is hashed in blocks.

Measured on 2026-11-18 on 0.26.0 (external review, re-measured): `evidence_pack.verify_pack` read every file listed in
`file_digests_sha256` whole into memory before any size bound (peak 515 MB for a 500 MiB sparse file); the pinned TSA
certificates and CRLs were checked with `os.stat` and then opened, so a FIFO put in their place between the two blocked
the program; and, found while auditing the same class here, `verifier.py <a FIFO>`, a pack whose MANIFEST.json is a
FIFO and `cryptovalid-verify cldma <a FIFO>` blocked outright. Every check that could block runs in a child process with a timeout, so a regression is a
failure, not a hung suite. Linux, macOS and Windows: a FIFO there is a named pipe given by name, the device NUL, the
peak memory the peak working set (test_platforms_20261124); only a FIFO at a name inside a pack has no Windows
equivalent and is skipped there with that reason.

SPEC v0.12 §5 step 0: the ledger verifier reads a FIFO (`verifier.py <(cat ledger)`, the six verifiers since 0.20.2),
bounded in size and in idle time; a FIFO with no writer is FAIL after 10 s. Positive control: on 4f15a65 10 of the 12
tests fail (the control and the pipe read whole pass), on 255eec5 the 3 pipe tests fail."""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import textwrap
import unittest

sys.dont_write_bytecode = True
ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)
from test_platforms_20261124 import DEVICE, PEAK_RSS_KIB, fifo, fifo_at, pipe_writer  # noqa: E402


def child(code: str, *args, timeout: int = 60):
    """run `code` with the repository on sys.path; (returncode, stdout, stderr); returncode 124 when it did not finish"""
    pre = "import sys, json, os\nsys.dont_write_bytecode = True\nsys.path.insert(0, %r)\n" % ROOT
    try:
        p = subprocess.run([sys.executable, "-c", pre + textwrap.dedent(code), *args], capture_output=True, text=True, encoding="utf-8",
                           timeout=timeout, env={k: v for k, v in os.environ.items() if k != "PYTHONPATH"})
        return p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired:
        return 124, "", "timeout"


class Bounded(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.mkdtemp()
        self.pack = os.path.join(self.td, "pack")
        rc, out, err = child("""
            import evidence_pack as E
            E.build_pack([os.path.join(%r, "examples", "sample_ledger.jsonl")], sys.argv[1])
        """ % ROOT, self.pack)
        self.assertEqual(rc, 0, err[-500:])

    def tearDown(self):
        shutil.rmtree(self.td)

    def add_listed(self, name, size, digest="00" * 32):
        """a sparse file of `size` bytes inside the pack, listed in the manifest (the manifest digest is not updated:
        a pack changed by hand, as a reviewer would)"""
        p = os.path.join(self.pack, name)
        with open(p, "wb") as f:
            f.truncate(size)
        m = os.path.join(self.pack, "MANIFEST.json")
        with open(m, encoding="utf-8") as f:
            man = json.load(f)
        man["file_digests_sha256"][name] = digest
        with open(m, "w", encoding="utf-8", newline="") as f:
            json.dump(man, f)

    VERIFY_RSS = PEAK_RSS_KIB + """
import evidence_pack as E
r = E.verify_pack(sys.argv[1])
print(json.dumps({"valid": r["valid"], "admission": r.get("admission"), "error": r.get("error"),
                  "maxrss_kib": peak_rss_kib()}))
"""

    def test_a_listed_file_over_the_bound_is_refused_before_reading(self):
        import verifier
        self.add_listed("big.bin", verifier.MAX_INPUT_BYTES + 1)
        rc, out, err = child(self.VERIFY_RSS, self.pack, timeout=300)
        self.assertEqual(rc, 0, err[-500:])
        r = json.loads(out)
        self.assertEqual((r["valid"], r["admission"]), (False, "refused"), r)
        self.assertTrue(r["error"].startswith("input_too_large: file big.bin"), r)
        self.assertLess(r["maxrss_kib"], 120 * 1024, r)              # 0.26.0: over 256 MiB

    def test_a_listed_file_under_the_bound_is_hashed_in_blocks(self):
        """64 MiB of zeros, listed with another digest: contradicted as before (digest_mismatch), the peak memory far
        below the file (0.26.0: the whole file in memory). Controls: the same verification with the file read whole is seen
        by the measure, and the digest is the file's."""
        import hashlib
        self.add_listed("mid.bin", 64 * 1024 * 1024)
        rc, out, err = child(self.VERIFY_RSS, self.pack, timeout=300)
        self.assertEqual(rc, 0, err[-500:])
        r = json.loads(out)
        self.assertEqual((r["valid"], r["admission"]), (False, "admitted"), r)
        self.assertLess(r["maxrss_kib"], 60 * 1024, r)
        rc, out, err = child("""
import evidence_pack as E, hashlib
E._sha256_file = lambda p, limit=None: hashlib.sha256(open(p, "rb").read()).hexdigest()   # 0.26.0: the whole file
""" + self.VERIFY_RSS, self.pack, timeout=300)
        self.assertEqual(rc, 0, err[-500:])
        self.assertGreater(json.loads(out)["maxrss_kib"], r["maxrss_kib"] + 40 * 1024, (r, out))
        rc, out, err = child("""
            import evidence_pack as E
            print(E._sha256_file(sys.argv[1]))
        """, os.path.join(self.pack, "mid.bin"))
        self.assertEqual(out.strip(), hashlib.sha256(b"\0" * (64 * 1024 * 1024)).hexdigest())

    def test_a_fifo_as_manifest_does_not_block(self):
        m = os.path.join(self.pack, "MANIFEST.json")
        os.remove(m)
        fifo_at(self, m)
        rc, out, err = child(self.VERIFY_RSS, self.pack, timeout=20)
        self.assertEqual(rc, 0, err[-300:])
        r = json.loads(out)
        self.assertEqual((r["valid"], r["admission"]), (False, "refused"), r)
        self.assertIn("not a regular file", r["error"])

    def test_a_listed_fifo_in_the_window_does_not_block(self):
        """the window between the check and the open: os.path.isfile is made to say True for a FIFO; 0.26.0 then
        opened it and waited for a writer"""
        p = os.path.join(self.pack, "pipe.bin")
        self.add_listed("pipe.bin", 0)
        os.remove(p)
        fifo_at(self, p)
        rc, out, err = child("""
            import evidence_pack as E
            real = os.path.isfile
            os.path.isfile = lambda q: True if q.endswith("pipe.bin") else real(q)
            r = E.verify_pack(sys.argv[1])
            print(json.dumps({"valid": r["valid"], "file_ok": r["file_ok"].get("pipe.bin"), "admission": r["admission"]}))
        """, self.pack, timeout=20)
        self.assertEqual(rc, 0, err[-300:])
        self.assertEqual(json.loads(out), {"valid": False, "file_ok": False, "admission": "admitted"})


class Fifos(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.mkdtemp()
        self.fifo = fifo(self, os.path.join(self.td, "f"))   # Windows: a named pipe whose server never writes

    def tearDown(self):
        shutil.rmtree(self.td)

    def test_ledger_verifier_on_a_fifo(self):
        """SPEC v0.12 §5 step 0: a FIFO with no writer is FAIL after FIFO_IDLE_SECONDS (10 s), never a hang (0.26.0)"""
        rc, out, err = child("""
            import verifier as V
            r = V.verify_ledger(sys.argv[1])
            print(json.dumps([r["verdict"], r["parse_errors"][0]["error"]]))
        """, self.fifo, timeout=20)
        self.assertEqual(rc, 0, err[-300:])
        self.assertEqual(json.loads(out), ["FAIL", "unreadable: FIFO idle for 10 s"])

    def run_fed(self, chunks, pause, limit=None):
        """verify_ledger on a pipe while a writer process writes `chunks` with `pause` seconds between them"""
        name, w = pipe_writer(self, os.path.join(self.td, "fed%d" % len(os.listdir(self.td))),
                              [c.encode() for c in chunks], pause)
        try:
            return child("""
                import verifier as V
                limit = %r
                if limit:
                    V.MAX_INPUT_BYTES = limit
                r = V.verify_ledger(sys.argv[1])
                print(json.dumps([r["verdict"], r.get("entries_count"), [e["error"] for e in r.get("parse_errors", [])]]))
            """ % (limit,), name, timeout=30)
        finally:
            w.wait(10)

    def test_a_pipe_is_read_as_in_the_other_verifiers(self):
        """`verifier.py <(cat ledger)`: the bytes of the pipe, the verdict of the same bytes in a file (0.20.2 contract,
        the oracle case input-fifo); a writer slower than one block, and a tampered ledger, read whole"""
        with open(os.path.join(ROOT, "examples", "sample_ledger.jsonl"), encoding="utf-8") as f:
            lines = f.read().splitlines(True)
        rc, out, err = self.run_fed(lines, 0.3)
        self.assertEqual((rc, json.loads(out)), (0, ["PASS", len(lines), []]), err[-300:])
        with open(os.path.join(ROOT, "examples", "sample_ledger_tampered.jsonl"), encoding="utf-8") as f:
            rc, out, err = self.run_fed([f.read()], 0)
        self.assertEqual(json.loads(out)[0], "FAIL")

    def test_a_pipe_over_the_bound(self):
        with open(os.path.join(ROOT, "examples", "sample_ledger.jsonl"), encoding="utf-8") as f:
            text = f.read()
        rc, out, err = self.run_fed([text], 0, limit=len(text) - 1)
        self.assertEqual(json.loads(out)[0], "FAIL", err[-300:])
        self.assertTrue(json.loads(out)[2][0].startswith("input_too_large"), out)

    def test_a_device_is_not_read(self):
        rc, out, err = child("""
            import verifier as V
            r = V.verify_ledger(sys.argv[1])
            print(json.dumps([r["verdict"], r["parse_errors"][0]["error"]]))
        """, DEVICE, timeout=20)
        self.assertEqual(json.loads(out), ["FAIL", "unreadable: not a regular file"], err[-300:])

    def test_cldma_command_on_a_fifo(self):
        """found by running every sub-command of cryptovalid-verify on a FIFO (18/11/2026): only `cldma` blocked"""
        rc, out, err = child("""
            import verify_evidence as VE
            r = VE.verify_cldma(sys.argv[1])
            print(json.dumps([r["valid"], r["layers"][0]["detail"]]))
        """, self.fifo, timeout=20)
        self.assertEqual(rc, 0, err[-300:])
        valid, detail = json.loads(out)
        self.assertFalse(valid)
        self.assertIn("not a regular file", detail)

    def test_pins_in_the_window(self):
        """os.stat made to see a regular file where a FIFO is (the window of 0.26.0's check-then-open): the pinned
        certificate and the pinned CRL paths are refused at once, never waited on"""
        for what in ("tsa", "crl"):
            rc, out, err = child("""
                import stat, cryptovalid_tsa as T
                real = os.stat
                class S: st_mode = stat.S_IFREG | 0o644; st_size = 10
                os.stat = lambda q, *a, **k: S() if q == sys.argv[1] else real(q, *a, **k)
                try:
                    T._pem_certs([sys.argv[1]]) if sys.argv[2] == "tsa" else T._load_crls([sys.argv[1]])
                except ValueError as e:
                    print(json.dumps(str(e)))
                except ImportError:
                    print(json.dumps("no cryptography: not a regular file"))
            """, self.fifo, what, timeout=20)
            self.assertEqual(rc, 0, (what, err[-300:]))
            self.assertIn("not a regular file", json.loads(out), what)

    def test_pins_too_large(self):
        big = os.path.join(self.td, "big.pem")
        with open(big, "wb") as f:
            f.truncate(64 * 1024 * 1024 + 1)
        rc, out, err = child("""
            import cryptovalid_tsa as T
            try:
                T._pem_certs([sys.argv[1]])
            except ValueError as e:
                print(json.dumps(str(e)))
        """, big)
        self.assertIn("larger than", json.loads(out))

    def test_control_regular_pin_still_reads(self):
        rc, out, err = child("""
            import cryptovalid_tsa as T
            print(len(T._pem_certs([os.path.join(sys.argv[1], "spec", "vectors", "rfc3161", "freetsa.signer.pem")])))
        """, ROOT)
        self.assertEqual(rc, 0, err[-300:])
        self.assertGreater(int(out), 500)


if __name__ == "__main__":
    unittest.main()
