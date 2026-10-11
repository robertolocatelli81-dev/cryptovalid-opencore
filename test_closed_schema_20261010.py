#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Roberto Locatelli
"""SPEC §2.1 (2026-10-10) — closed entry and manifest schemas: a top-level key nobody defined is a NAMED FAIL, never a
silent PASS. The ledger is built here in a temporary directory (removed at the end) — not read from
examples/sample_ledger.jsonl, which is gitignored; the intact ledger and pack are the positive controls."""
import copy
import json
import os
import shutil
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import verifier as V          # noqa: E402
import evidence_pack as EP    # noqa: E402

KEY = "x_unknown_2026"


def _sample_entries():
    """Three entries of the native schema, built here (examples/sample_ledger.jsonl is not tracked: *.jsonl is gitignored)."""
    datas = [{"event": "kyc_check", "subject": "CUST-001", "result": "pass"}, {"event": "decision", "subject": "CUST-001", "decision": "onboard"},
             {"event": "note", "subject": "CUST-001", "text": "ok"}]
    prev, out = "0" * 64, []
    for i, d in enumerate(datas):
        e = {"idx": i, "ts": f"2026-10-10T10:0{i}:00Z", "data": d, "prev_hash": prev}
        e["self_hash"] = V.hash_with("sha256", V.canonical_payload(e)); prev = e["self_hash"]; out.append(e)
    return out


def _rechain(entries, algo):
    prev = "0" * 64
    out = []
    for e in entries:
        e = dict(e); e["prev_hash"] = prev; e.pop("self_hash", None)
        e["self_hash"] = V.hash_with(algo, V.canonical_payload(e)); prev = e["self_hash"]; out.append(e)
    return out


class TestClosedSchema(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp(prefix="opencore-closed-")
        self.addCleanup(shutil.rmtree, self.d, ignore_errors=True)
        self.entries = _sample_entries()
        self.algo = V.detect_algo(self.entries) or "sha256"

    def _write(self, name, entries):
        p = os.path.join(self.d, name)
        with open(p, "w", encoding="utf-8") as f:
            for e in entries:
                f.write(json.dumps(e, ensure_ascii=False) + "\n")
        return p

    def test_intact_ledger_passes_and_lists_no_schema_failure(self):
        r = V.verify_ledger(self._write("ok.jsonl", self.entries))
        self.assertEqual(r["verdict"], "PASS"); self.assertEqual(r["schema_failures"], [])

    def test_unknown_top_level_entry_key_written_at_creation_is_a_named_fail(self):
        es = copy.deepcopy(self.entries); es[1][KEY] = "x"
        r = V.verify_ledger(self._write("unk.jsonl", _rechain(es, self.algo)))
        self.assertEqual(r["verdict"], "FAIL")
        self.assertEqual(r["hash_failures"], [], "the hash was recomputed over the key: only the schema rule can see it")
        self.assertEqual(r["schema_failures"], [{"idx": 1, "reason": "unknown_field:" + KEY}])

    def test_data_payload_stays_free_form(self):
        es = copy.deepcopy(self.entries); es[1]["data"][KEY] = "x"
        r = V.verify_ledger(self._write("data.jsonl", _rechain(es, self.algo)))
        self.assertEqual(r["verdict"], "PASS")       # SPEC §4: data is domain-specific

    def test_optional_fields_stay_in_schema(self):
        self.assertTrue({"signature", "signer", "tsa_token", "signature_pq", "signer_pq"} <= set(V.ENTRY_KEYS))

    def test_manifest_unknown_keys_are_a_named_fail(self):
        base = self._write("base.jsonl", self.entries)
        out = os.path.join(self.d, "pack"); EP.build_pack([base], out)
        mp = os.path.join(out, "MANIFEST.json")
        with open(mp, encoding="utf-8") as f:
            man = json.load(f)
        self.assertTrue(EP.verify_pack(out)["valid"])          # positive control
        for where, mut in (("MANIFEST." + KEY, lambda m: m.__setitem__(KEY, "x")),
                           ("ledgers[0]." + KEY, lambda m: m["ledgers"][0].__setitem__(KEY, "x")),
                           ("rfc3161_timestamp." + KEY, lambda m: m["rfc3161_timestamp"].__setitem__(KEY, "x"))):
            m = copy.deepcopy(man); mut(m)
            if not where.startswith("rfc3161"):               # inside the digest: reseal, so only the schema rule can see it
                m2 = {k: v for k, v in m.items() if k not in ("manifest_digest_sha256", "rfc3161_timestamp", "manifest_signer", "manifest_signature")}
                import hashlib
                m["manifest_digest_sha256"] = hashlib.sha256(EP._canon(m2)).hexdigest()
            with open(mp, "w", encoding="utf-8") as f:
                json.dump(m, f)
            r = EP.verify_pack(out)
            self.assertFalse(r["valid"], where); self.assertIn("manifest_unknown_field", r.get("error", ""), where); self.assertIn(where, r["error"], where)
        with open(mp, "w", encoding="utf-8") as f:
            json.dump(man, f)
        self.assertTrue(EP.verify_pack(out)["valid"])

    def _pack_digest(self, m):
        import hashlib
        m2 = {k: v for k, v in m.items() if k not in ("manifest_digest_sha256", "rfc3161_timestamp", "manifest_signer", "manifest_signature")}
        m["manifest_digest_sha256"] = hashlib.sha256(EP._canon(m2)).hexdigest()

    def test_unknown_key_in_the_second_ledger_of_a_pack_is_named(self):
        a = self._write("a.jsonl", self.entries); b = self._write("b.jsonl", self.entries)
        out = os.path.join(self.d, "pack2"); EP.build_pack([a, b], out)
        mp = os.path.join(out, "MANIFEST.json")
        with open(mp, encoding="utf-8") as f:
            man = json.load(f)
        self.assertTrue(EP.verify_pack(out)["valid"])          # positive control
        man["ledgers"][1][KEY] = "x"; self._pack_digest(man)
        with open(mp, "w", encoding="utf-8") as f:
            json.dump(man, f)
        r = EP.verify_pack(out)
        self.assertFalse(r["valid"]); self.assertIn("ledgers[1]." + KEY, r.get("error", ""))

    def test_rfc3161_block_is_exactly_what_the_builder_writes(self):
        self.assertEqual(set(EP.RFC3161_KEYS), {"anchored", "tsa", "tsr_b64", "note"})
        base = self._write("base.jsonl", self.entries)
        out = os.path.join(self.d, "pack3"); EP.build_pack([base], out)
        mp = os.path.join(out, "MANIFEST.json")
        with open(mp, encoding="utf-8") as f:
            man = json.load(f)
        man["rfc3161_timestamp"]["tsa_url"] = "https://tsa.example"   # never written by any build_pack
        with open(mp, "w", encoding="utf-8") as f:
            json.dump(man, f)
        r = EP.verify_pack(out)
        self.assertFalse(r["valid"]); self.assertIn("rfc3161_timestamp.tsa_url", r.get("error", ""))

    def test_every_entry_with_an_unknown_key_is_listed(self):
        es = copy.deepcopy(self.entries)
        for e in es:
            e[KEY] = 1
        r = V.verify_ledger(self._write("all.jsonl", _rechain(es, self.algo)))
        self.assertEqual(r["verdict"], "FAIL")
        self.assertEqual(r["schema_failures"], [{"idx": i, "reason": "unknown_field:" + KEY} for i in range(3)])

    def test_ledger_without_idx_is_refused_with_or_without_algo(self):
        """0.20.0 closes the shortcut 0.19.0 declared: first three entries without idx (or none at all), no --algo, used to
        take a generic native-schema path (PASS, §2.1 and §5 step 4 not applied, the unknown key not named). Now the
        profile applies on every path: FAIL, idx_mismatch and the unknown key named; the pack is not valid."""
        es = copy.deepcopy(self.entries) + [dict(idx=3, ts="2026-10-10T10:03:00Z", data={"n": 3})]
        for e in es[:3]:
            e.pop("idx")
        es[3][KEY] = 1
        p = self._write("short.jsonl", _rechain(es, "sha256"))
        for algo in (None, "sha256"):
            r = V.verify_ledger(p, algo=algo)
            self.assertEqual(r["verdict"], "FAIL", algo)
            self.assertNotIn("mode", r)
            self.assertIn({"idx": 3, "reason": "unknown_field:" + KEY}, r["schema_failures"])
            self.assertEqual([x["line"] for x in r["parse_errors"] if x["error"].startswith("idx_mismatch")], [0, 1, 2])
        none = [dict(e) for e in self.entries]
        for e in none:
            e.pop("idx")
        r = V.verify_ledger(self._write("none.jsonl", _rechain(none, "sha256")))
        self.assertEqual(r["verdict"], "FAIL")
        self.assertEqual(len([x for x in r["parse_errors"] if x["error"].startswith("idx_mismatch")]), 3)
        out = os.path.join(self.d, "pack4"); EP.build_pack([p], out)
        rp = EP.verify_pack(out)
        self.assertFalse(rp["valid"]); self.assertFalse(rp["ledgers"][0]["hash_pass"])

if __name__ == "__main__":
    unittest.main(verbosity=2)
