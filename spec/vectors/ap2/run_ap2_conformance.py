#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Roberto Locatelli
"""ap2-evidence-pack conformance runner (reference implementation side).

A verifier claims ap2-evidence-pack conformance iff, for every <name>.json in this
directory, verified under the policy in <name>.expected.json, it reproduces the
vector's `normative` block exactly. This runner checks the reference
`ap2_evidence.verify_evidence`; a third-party implementation (Rust, Go, JS, …)
claims conformance the same way against its own verifier, mapping its receipt onto
the normative fields (see SPEC_AP2_EVIDENCE.md §6 for their definitions).

A vector whose `requires` lists a tool absent on this machine is reported SKIP —
honestly not verified, never silently passed. Exit 0 = conformant (no FAIL).

  python3 run_ap2_conformance.py
"""
from __future__ import annotations

import glob
import json
import os
import shutil
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_OPENCORE = os.path.abspath(os.path.join(_HERE, "..", "..", ".."))
sys.path.insert(0, _OPENCORE)
import ap2_evidence as ap2  # noqa: E402


def _normalize(r: dict) -> dict:
    """Map a verify receipt onto the NORMATIVE fields — nothing else is compared, so an
    implementation may format its receipt however it likes as long as these facts match."""
    prod = r.get("producer_signatures", {})
    rfc = r.get("rfc3161", {})
    return {"valid": r.get("valid"), "digest_ok": r.get("digest_ok"),
            "bindings_ok": r.get("bindings_ok"), "policy_ok": r.get("policy_ok"),
            "pq_protected": r.get("pq_protected"),
            "producer_present": prod.get("present"), "producer_ok": prod.get("ok"),
            "producer_trusted": prod.get("trusted"),
            "rfc3161_claimed": rfc.get("claimed"), "rfc3161_verified": rfc.get("verified"),
            "self_asserted_only": r.get("self_asserted_only")}


def run(verify_fn=None) -> dict:
    verify_fn = verify_fn or ap2.verify_evidence
    results, conformant = [], True
    for exp_path in sorted(glob.glob(os.path.join(_HERE, "*.expected.json"))):
        with open(exp_path, encoding="utf-8") as f:
            exp = json.load(f)
        name = exp["vector"]
        missing = [t for t in exp.get("requires", []) if not shutil.which(t)]
        if missing:
            results.append({"vector": name, "status": "SKIP",
                            "note": f"requires {missing} — NOT verified on this machine"})
            continue
        pol = exp.get("policy", {})
        got = _normalize(verify_fn(
            os.path.join(_HERE, f"{name}.json"),
            trusted_producer_keys=pol.get("trusted_producer_keys"),
            require_pq=bool(pol.get("require_pq")),
            require_producer=bool(pol.get("require_producer")),
            require_anchor=bool(pol.get("require_anchor"))))
        want = exp["normative"]
        diffs = {k: {"want": want[k], "got": got.get(k)}
                 for k in want if got.get(k) != want[k]}
        ok = not diffs
        conformant = conformant and ok
        results.append({"vector": name, "status": "PASS" if ok else "FAIL",
                        **({"diffs": diffs} if diffs else {})})
    return {"conformant": conformant and any(r["status"] == "PASS" for r in results),
            "results": results}


def main() -> int:
    r = run()
    print(json.dumps(r, indent=1))
    return 0 if r["conformant"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
