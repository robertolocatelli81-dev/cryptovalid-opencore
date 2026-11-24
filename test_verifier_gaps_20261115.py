#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Behaviours of verifier.py that no other suite observed: proposed by Athena's review of 15/11/2026 (its file
athena_misure/test_buchi_verifier.py, adapted here to the names of this repository). In that review 223 mutants of
verifier.py were run against 26 suites and 34 survived; each test below passes on the reference and fails on at least
one of 13 of those survivors, named in CONTROLS (line numbers of this verifier.py). They are not defects of the
reference: on every case it answers as SPEC says; they are places where a regression turned no suite red.

Run:               python3 test_verifier_gaps_20261115.py
Positive control:  python3 test_verifier_gaps_20261115.py --controls   (each named mutant, in a copy: this file must
                   go red on all 13; it prints one line per mutant and "killed N of 13")."""
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True
ROOT = os.environ.get("CV_ROOT") or os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)
import verifier as V  # noqa: E402


def ledger(path, datas):
    prev = V.GENESIS_PREV
    with open(path, "w", encoding="utf-8", newline="") as f:
        for i, d in enumerate(datas):
            e = {"idx": i, "ts": "2026-11-15T00:00:0%dZ" % i, "data": d, "prev_hash": prev}
            e["self_hash"] = V.hash_with("sha256", V.canonical_payload(e)); prev = e["self_hash"]
            f.write(json.dumps(e) + "\n")


def rd(path):
    with open(path, encoding="utf-8") as f:
        return f.read()

def wr(path, text):
    with open(path, "w", encoding="utf-8", newline="") as f:
        f.write(text)


class TestVerifierGaps(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp(prefix="cv_gap_"); self.p = os.path.join(self.d, "l.jsonl")
    def tearDown(self):
        shutil.rmtree(self.d)

    def test_brackets_inside_strings_are_not_nesting(self):
        """mutants L611, L613, L614, L617 (json_nesting_depth: string and escape state)"""
        deep = V.MAX_JSON_DEPTH + 100
        self.assertEqual(V.json_nesting_depth('{"a":"' + "[" * deep + '"}'), 1)
        self.assertEqual(V.json_nesting_depth('{"a":"\\"' + "{" * deep + '"}'), 1)        # after an escaped quote
        self.assertEqual(V.json_nesting_depth('{"a":"\\\\","b":[[1]]}'), 3)                 # an escaped backslash ends
        self.assertEqual(V.json_nesting_depth('{"a":"x\\\\\\"' + "[" * deep + '"}'), 1)   # \\ then \" : still inside
        ledger(self.p, [{"note": "[" * deep}, {"note": 'q"' + "{" * deep}, {"note": "\\" + "[" * 3}])
        r = V.verify_ledger(self.p)
        self.assertEqual((r["verdict"], r["entries_count"], r["parse_errors"]), ("PASS", 3, []))

    def test_surrogate_escape_at_the_end_of_the_text(self):
        """mutants L649 (has_lone_surrogate: bounds of the \\uXXXX window)"""
        self.assertFalse(V.has_lone_surrogate("\\"))            # a backslash as the last character
        self.assertFalse(V.has_lone_surrogate("\\n"))
        self.assertFalse(V.has_lone_surrogate("\\uD8"))          # too short to be an escape: the decoder's business
        self.assertFalse(V.has_lone_surrogate("ab\\x"))
        self.assertFalse(V.has_lone_surrogate('"\\nD800 and more"'))   # \n followed by hex digits is not an escape of them
        self.assertFalse(V.has_lone_surrogate('"\\tDC00 and more"'))
        self.assertTrue(V.has_lone_surrogate("\\uD800"))
        self.assertTrue(V.has_lone_surrogate('"\\uDC00"'))
        self.assertFalse(V.has_lone_surrogate('"\\uD83D\\uDE00"'))

    def test_receipt_flags_follow_the_failures(self):
        """mutants L908, L912 (hash_recompute_passed / link_passed)"""
        ledger(self.p, [{"a": "1"}, {"a": "2"}, {"a": "3"}])
        r = V.verify_ledger(self.p)
        self.assertEqual((r["verdict"], r["hash_recompute_passed"], r["link_passed"]), ("PASS", True, True))
        lines = rd(self.p).splitlines()
        e = json.loads(lines[1]); e["data"] = {"a": "changed"}; lines[1] = json.dumps(e)       # content edited
        wr(self.p, "\n".join(lines) + "\n")
        r = V.verify_ledger(self.p)
        self.assertEqual((r["verdict"], r["hash_recompute_passed"], r["link_passed"]), ("FAIL", False, True))
        ledger(self.p, [{"a": "1"}, {"a": "2"}, {"a": "3"}])
        lines = rd(self.p).splitlines()
        e = json.loads(lines[2]); e["prev_hash"] = "1" * 64                                    # link broken, hash redone
        e.pop("self_hash"); e["self_hash"] = V.hash_with("sha256", V.canonical_payload(e)); lines[2] = json.dumps(e)
        wr(self.p, "\n".join(lines) + "\n")
        r = V.verify_ledger(self.p)
        self.assertEqual((r["verdict"], r["hash_recompute_passed"], r["link_passed"]), ("FAIL", True, False))

    def test_untrusted_tip_is_reported_unchecked(self):
        """mutant L872 (tip present, no trusted key: ok False, checked False)"""
        ledger(self.p, [{"a": "1"}])
        wr(self.p + ".tip.json", "{}")
        r = V.verify_ledger(self.p)
        self.assertEqual((r["verdict"], r["tip"]["ok"], r["tip"]["checked"]), ("PASS", False, False))
        self.assertEqual(V.verify_ledger(self.p, require_tip=True)["verdict"], "FAIL")

    def test_unreadable_tip_with_a_trusted_key_fails(self):
        """mutants L889, L891 (tip_unreadable: pq_protected False; checked True)"""
        ledger(self.p, [{"a": "1"}])
        for junk in ("not json", "[]", '{"a":1,"a":2}'):
            wr(self.p + ".tip.json", junk)
            r = V.verify_ledger(self.p, trusted_pubkey_hex="ab" * 32)
            self.assertEqual(r["verdict"], "FAIL", junk)
            self.assertEqual((r["tip"]["ok"], r["tip"]["checked"], r["tip"]["pq_protected"]), (False, True, False), junk)

    def test_pq_key_without_log_key_fails(self):
        """the mutant on L866 survives this test too: verdict and chain_integrity come out FAIL / False from the error
        that the same branch appends, so the assignment on L866 is redundant (an equivalent mutant, by reading)"""
        ledger(self.p, [{"a": "1"}])
        r = V.verify_ledger(self.p, trusted_pq_pubkey_b64="AAAA")
        self.assertEqual((r["verdict"], r["chain_integrity"]), ("FAIL", False))
        self.assertTrue(any("pq_key_without_log_key" in e["error"] for e in r["parse_errors"]))

    def test_receipt_hash_ignores_only_the_time(self):
        """mutants L955, L957 (receipt_sha256 over the receipt without verified_utc, keys sorted)"""
        ledger(self.p, [{"a": "1"}])
        r = V.verify_ledger(self.p)
        body = {k: v for k, v in r.items() if k not in ("verified_utc", "receipt_sha256", "receipt_sha3_256")}
        want = hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":"), default=str).encode()).hexdigest()
        self.assertEqual(r["receipt_sha256"], want)


CONTROLS = ["L611: 'False'→'True' @col22", "L613: 'True'→'False' @col22", "L614: '=='→'!=' @col20", "L617: 'True'→'False' @col21",
            "L649: 'and'→'or' @col20", "L649: 'and'→'or' @col43", "L872: 'False'→'True' @col27",
            "L889: 'False'→'True' @col118", "L891: 'True'→'False' @col31", "L908: '=='→'!=' @col52", "L912: '=='→'!=' @col42",
            "L955: '!='→'==' @col63", "L957: 'True'→'False' @col37"]

def run_controls():
    """each named mutant of verifier.py, in a copy: this file must go red on it. Prints one line per mutant."""
    import mutation_runner
    base = rd(os.path.join(ROOT, "verifier.py"))
    muts = dict(mutation_runner.generate_mutants(base))
    d = tempfile.mkdtemp(prefix="cv_gapctl_"); missed = 0
    for n in ("cryptovalid_tip.py", "ed25519_order.py", "mutation_runner.py"):
        shutil.copy(os.path.join(ROOT, n), d)
    def go():
        try:
            return subprocess.run([sys.executable, os.path.abspath(__file__)], cwd=d, env=dict(os.environ, CV_ROOT=d),
                                  capture_output=True, timeout=120).returncode
        except subprocess.TimeoutExpired:
            return "timeout"
    wr(os.path.join(d, "verifier.py"), base)
    print("null control (no mutation): rc=%s" % go())
    for name in CONTROLS:
        wr(os.path.join(d, "verifier.py"), muts[name])
        rc = go(); missed += rc == 0
        print("%-34s %s" % (name, "killed" if rc != 0 else "SURVIVED"))
    shutil.rmtree(d)
    print("killed %d of %d" % (len(CONTROLS) - missed, len(CONTROLS)))
    return 1 if missed else 0

if __name__ == "__main__":
    if "--controls" in sys.argv:
        sys.exit(run_controls())
    unittest.main()
