#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Roberto Locatelli
"""
CryptoValid Evidence Format — conformance runner.

A standard is defined by INTEROPERABILITY, not by a single implementation. Any verifier that
claims CryptoValid conformance MUST reproduce the NORMATIVE verdicts in `spec/vectors/*.expected.json`
on the matching input ledgers — same verdict, same chain integrity, same failing entry indices.

This runner checks the reference `verifier.py`. A third-party implementation (Go, Rust, JS, …) claims
conformance the same way: run each `spec/vectors/*.jsonl` through its own verifier and compare its
result to the vector's `normative` block. Exit code 0 = conformant.

  python3 conformance.py
"""
from __future__ import annotations

import glob
import json
import os
import sys
from typing import Callable, Dict

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
import verifier  # noqa: E402

VDIR = os.path.join(_HERE, "spec", "vectors")

# The normative fields a conformant verifier MUST reproduce (nothing else is required — a different
# implementation may format its receipt however it likes, as long as these facts match).
NORMATIVE_KEYS = ("verdict", "chain_integrity", "algorithm", "entries",
                  "hash_failures_idx", "link_failures_idx")


def _normalize(rec: Dict) -> Dict:
    return {
        "verdict": rec.get("verdict"),
        "chain_integrity": rec.get("chain_integrity"),
        "algorithm": rec.get("algorithm_used"),
        "entries": rec.get("entries_count"),
        "hash_failures_idx": sorted(x["idx"] for x in rec.get("hash_failures", [])),
        "link_failures_idx": sorted(x["idx"] for x in rec.get("link_failures", [])),
    }


def run(verify_fn: Callable[[str], Dict] = verifier.verify_ledger) -> Dict:
    results, conformant = [], True
    for exp_path in sorted(glob.glob(os.path.join(VDIR, "*.expected.json"))):
        with open(exp_path, encoding="utf-8") as f:
            exp = json.load(f)
        n = exp["normative"]
        got = _normalize(verify_fn(os.path.join(VDIR, exp["input"])))
        ok = all(got[k] == n[k] for k in NORMATIVE_KEYS)
        conformant = conformant and ok
        entry = {"vector": exp["input"], "conform": ok}
        if not ok:
            entry["expected"], entry["got"] = n, got
        results.append(entry)
    return {"conformant": conformant, "vectors": len(results), "results": results}


if __name__ == "__main__":
    r = run()
    print(json.dumps(r, indent=1, ensure_ascii=False))
    raise SystemExit(0 if r["conformant"] else 1)
