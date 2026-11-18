#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""SPEC v0.12 §5 "Failure classes", the two sentences about `cryptovalid-verify ledger` that no other test reached
(review of 18/11/2026: both mutants survived the suite): the chain's reasons are listed links first, then hashes,
then the schema's; and `other` is written in the layer's `detail` when it is not zero. Also the branch of the member
on a FAIL with zero entries (`other` counts `empty_ledger`) and its absence on the FAILs of §5 step 0.

Positive control, measured: with the order of 0.26.0 (hash, link, schema) test 1 fails; without the `other` part of
the detail test 2 fails."""
import hashlib
import json
import os
import shutil
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True
ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)
import verifier  # noqa: E402
import verify_evidence  # noqa: E402


def chain_of(rows):
    out, prev = [], verifier.GENESIS_PREV
    for r in rows:
        e = dict(r, prev_hash=prev)
        e["self_hash"] = hashlib.sha256(verifier.canonical_payload(e)).hexdigest()
        out.append(e)
        prev = e["self_hash"]
    return out


class Detail(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.td)

    def write(self, lines, name="l.jsonl"):
        p = os.path.join(self.td, name)
        with open(p, "w") as f:
            f.write("".join(x + "\n" for x in lines))
        return p

    def test_links_before_hashes(self):
        led = chain_of([{"idx": i, "ts": "2026-11-18T00:00:%02dZ" % i, "data": {"v": i}} for i in range(4)])
        led[1]["data"] = {"v": -1}               # entry 1: its self_hash no longer recomputes (hash_mismatch)
        led[3]["prev_hash"] = "f" * 64           # entry 3: a link break (and its hash too)
        p = self.write([json.dumps(e) for e in led])
        r = verifier.verify_ledger(p)
        self.assertEqual(r["failure_classes"]["chain"], {"link_mismatch": 1, "hash_mismatch": 2})
        lay = verify_evidence.verify_ledger(p)["layers"][0]
        self.assertEqual([x.split(" idx ")[0] for x in lay["reasons"]], ["link", "hash", "hash"], lay["reasons"])

    def test_other_in_detail(self):
        led = chain_of([{"idx": i, "ts": "2026-11-18T00:00:%02dZ" % i, "data": {"v": i}} for i in range(2)])
        p = self.write([json.dumps(e) for e in led] + ["[1]"])
        r = verifier.verify_ledger(p)
        self.assertEqual(r["failure_classes"]["other"], 1)
        lay = verify_evidence.verify_ledger(p)["layers"][0]
        self.assertIn("other: 1", lay["detail"])

    def test_zero_entries_and_step_0(self):
        r = verifier.verify_ledger(self.write([], "empty.jsonl"))
        self.assertEqual((r["verdict"], r["entries_count"], r["failure_classes"]["other"]), ("FAIL", 0, 1))
        r = verifier.verify_ledger(self.td)       # a directory: §5 step 0, nothing read
        self.assertEqual(r["verdict"], "FAIL")
        self.assertNotIn("failure_classes", r)


if __name__ == "__main__":
    unittest.main(verbosity=2)
