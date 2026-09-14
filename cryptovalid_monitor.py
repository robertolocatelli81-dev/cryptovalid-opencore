#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Roberto Locatelli
"""
CryptoValid Open Core — MONITOR / AUDITOR of a ledger over time (append-only, non-equivocation).

What Sigstore's rekor-monitor and immudb's auditor do, for a cryptovalid ledger, stdlib-only: the monitor keeps
the LAST tree head it saw (state file) and, at every run, proves that the ledger only GREW from that head
(RFC 6962/9162 consistency proof). What it catches — and the verifier of a single snapshot cannot:

  * truncation  — the ledger got shorter (tail cut, then possibly re-appended);
  * rewrite     — same size or larger, but the old root is not a prefix of the new tree (an old entry changed);
  * fork        — two different ledgers presented under the same identity across runs;
  * silence     — the head is unchanged for longer than `max_silence_h` (declared, not an error by itself).

Plus the snapshot checks of verifier.verify_ledger (hash chain, self_hash recompute, timestamps monotonic).
State is written ONLY after a green run (a red run never advances the baseline). The state carries the STH
signed by the log key when a keyfile is given, so a third party can audit the monitor's own history.
"""
from __future__ import annotations
import json
import os
import sys
from datetime import datetime, timezone
from typing import Dict, List, Optional

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import cryptovalid_merkle as M  # noqa: E402
import verifier as V  # noqa: E402


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _load_state(path: str) -> Optional[Dict]:
    if not os.path.exists(path):
        return None
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def run(ledger_path: str, state_path: str, keyfile: Optional[str] = None, max_silence_h: Optional[float] = None) -> Dict:
    """One monitor run. Returns a verdict dict with `ok`, `alerts`, `tree_size`, `root_sha256`."""
    alerts: List[str] = []
    snap = V.verify_ledger(ledger_path)
    if snap.get("verdict") not in ("PASS",) and not (snap.get("hash_recompute_passed") and snap.get("link_passed")):
        alerts.append(f"snapshot: verifier verdict {snap.get('verdict')} (chain/hash failures)")
    if snap.get("ts_monotonic") is False:
        alerts.append("snapshot: timestamps not monotonic")
    leaves = M.leaves_from_ledger(ledger_path)
    n2, root2 = len(leaves), M.mth(leaves).hex()
    prev = _load_state(state_path)
    consistency: Dict = {"checked": False}
    if prev:
        n1, root1 = int(prev["tree_size"]), prev["root_sha256"]
        if n2 < n1:
            alerts.append(f"TRUNCATION: tree size {n1} → {n2}")
            consistency = {"checked": True, "ok": False, "why": "shrank"}
        elif n2 == n1:
            ok = root1 == root2
            consistency = {"checked": True, "ok": ok, "why": "same size, roots " + ("equal" if ok else "DIFFERENT (rewrite)")}
            if not ok:
                alerts.append("REWRITE: same size but a different root")
        elif n1 == 0:
            consistency = {"checked": True, "ok": True, "why": "old tree empty"}
        else:
            proof = M.consistency_proof(n1, leaves)
            ok = M.verify_consistency(n1, n2, proof, bytes.fromhex(root1), bytes.fromhex(root2))
            consistency = {"checked": True, "ok": ok, "sizes": [n1, n2], "path_len": len(proof),
                           "why": "append-only growth proven" if ok else "consistency proof FAILED (fork or rewrite of old entries)"}
            if not ok:
                alerts.append(f"FORK/REWRITE: tree {n1}→{n2} is not append-only")
        if prev.get("log_pubkey_hex") and keyfile:
            import cryptovalid_receipt as R
            _, pk = R._load_sk(keyfile)
            if pk != prev["log_pubkey_hex"]:
                alerts.append("LOG KEY CHANGED between runs (state signed by a different key)")
        if max_silence_h is not None and n2 == n1:
            try:
                age_h = (datetime.now(timezone.utc) - datetime.fromisoformat(prev["ts"])).total_seconds() / 3600
                if age_h > max_silence_h:
                    alerts.append(f"SILENCE: no new entries for {age_h:.1f} h (> {max_silence_h} h)")
            except (KeyError, ValueError):
                pass
    ok = not alerts
    verdict = {"kind": "cryptovalid_monitor/1", "ts": _now(), "ledger": os.path.abspath(ledger_path),
               "ok": ok, "alerts": alerts, "tree_size": n2, "root_sha256": root2,
               "previous": ({"tree_size": prev["tree_size"], "root_sha256": prev["root_sha256"], "ts": prev.get("ts")} if prev else None),
               "consistency": consistency,
               "snapshot": {k: snap.get(k) for k in ("verdict", "entries_count", "hash_recompute_passed", "link_passed", "ts_monotonic")},
               "scope": ("proves append-only growth relative to the LAST GREEN state of THIS monitor; a first run has no "
                         "baseline. BLIND WINDOW (declared): an entry appended AND rewritten/removed between two runs, beyond "
                         "the old size, is invisible to the consistency proof — only receipts issued at write time "
                         "(cryptovalid_receipt) or a shorter run interval close it")}
    if ok:
        state = {"kind": "cryptovalid_monitor_state/1", "tree_size": n2, "root_sha256": root2, "ts": verdict["ts"],
                 "ledger": verdict["ledger"]}
        if keyfile:
            import cryptovalid_receipt as R
            sth = R.signed_tree_head(leaves, keyfile)
            state.update({"sth": sth, "log_pubkey_hex": sth["log_pubkey_hex"]})
        tmp = state_path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(state, f, indent=1)
        os.replace(tmp, state_path)
        verdict["state_written"] = state_path
    else:
        verdict["state_written"] = None      # a red run never advances the baseline
    return verdict


def main(argv: Optional[List[str]] = None) -> int:
    import argparse
    p = argparse.ArgumentParser(prog="cryptovalid_monitor", description="append-only / non-equivocation monitor for a cryptovalid ledger")
    p.add_argument("ledger"); p.add_argument("state", help="state file (last green tree head)")
    p.add_argument("--keyfile", help="log key: sign the state's tree head"); p.add_argument("--max-silence-h", type=float)
    a = p.parse_args(argv)
    v = run(a.ledger, a.state, a.keyfile, a.max_silence_h)
    print(json.dumps(v, indent=1))
    return 0 if v["ok"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
