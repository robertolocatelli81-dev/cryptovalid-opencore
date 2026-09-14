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


def run(ledger_path: str, state_path: str, keyfile: Optional[str] = None, max_silence_h: Optional[float] = None,
        trusted_pubkey_hex: Optional[str] = None, sth_path: Optional[str] = None) -> Dict:
    """One monitor run. Returns a verdict dict with `ok`, `alerts`, `tree_size`, `root_sha256`.
    Three modes, stated plainly (council 14/09, rounds 2-3):
      * WRITER (keyfile): the saved head is verified on load against the log key; a state without a signed
        head is an alert; a green run writes a NEW signed head.
      * AUDITOR (trusted_pubkey_hex, no keyfile): verifies the saved signed head against the trusted key and
        NEVER writes an unsigned state — the baseline advances only with a signed head for the current tree
        given via `sth_path` (published by the writer), verified here. Without it the baseline stays where it
        was (reported, not an alert).
      * NONE (no key): the state is trusted blindly — declared limit."""
    alerts: List[str] = []
    stato_auth = ("auditor senza chiave privata: stato non firmabile (limite dichiarato)" if (trusted_pubkey_hex and not keyfile)
                  else "firmato con la log key" if keyfile else "non autenticato (nessuna chiave: limite dichiarato)")
    import cryptovalid_receipt as R
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
        pk_trusted = trusted_pubkey_hex
        if keyfile and not pk_trusted:
            _, pk_trusted = R._load_sk(keyfile)
        if pk_trusted:
            sth = prev.get("sth")
            if not sth:
                # Writer: poteva firmare e non l'ha fatto. Auditor: non scrive MAI uno stato non firmato (round 3),
                # quindi uno stato senza STH sotto una chiave fidata può venire solo da altri → alert in entrambi i casi.
                alerts.append("STATE UNSIGNED: baseline without a signed tree head under a trusted log key")
                stato_auth = "stato senza STH firmato"
            else:
                v = R.verify_sth(sth, pk_trusted)
                if not v.get("ok"):
                    alerts.append(f"STATE TAMPERED: saved tree head signature invalid ({v.get('why')})")
                    stato_auth = "STH dello stato NON valido"
                elif int(sth["tree_size"]) != int(prev["tree_size"]) or sth["root_sha256"] != prev["root_sha256"]:
                    alerts.append("STATE TAMPERED: top-level size/root differ from the signed tree head")
                    stato_auth = "stato incoerente con lo STH firmato"
                else:
                    stato_auth = "STH dello stato verificato contro la chiave fidata"
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
            consistency = {"checked": False, "why": "old tree empty: nothing to prove (same verdict as the receipt verifiers)"}
        else:
            proof = M.consistency_proof(n1, leaves)
            ok = M.verify_consistency(n1, n2, proof, bytes.fromhex(root1), bytes.fromhex(root2))
            consistency = {"checked": True, "ok": ok, "sizes": [n1, n2], "path_len": len(proof),
                           "why": "append-only growth proven" if ok else "consistency proof FAILED (fork or rewrite of old entries)"}
            if not ok:
                alerts.append(f"FORK/REWRITE: tree {n1}→{n2} is not append-only")
        if prev.get("log_pubkey_hex") and keyfile:
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
               "consistency": consistency, "stato_baseline": stato_auth,
               "snapshot": {k: snap.get(k) for k in ("verdict", "entries_count", "hash_recompute_passed", "link_passed", "ts_monotonic")},
               "scope": ("proves append-only growth relative to the LAST GREEN state of THIS monitor; a first run has no "
                         "baseline. DECLARED LIMITS (council 14/09): (1) blind window — an entry appended AND "
                         "rewritten/removed between two runs, beyond the old size, is invisible to the consistency proof: "
                         "receipts at write time or a shorter interval close it; (2) the state file is the baseline — "
                         "deleting it, or replaying an OLDER signed state, resets/regresses the baseline without an alert: "
                         "keep the state where the ledger writer cannot write (separate host, WORM, or an external "
                         "anchor of each signed head); (3) without a key the state is trusted blindly")}
    verdict["state_written"] = None      # a red run never advances the baseline
    if ok:
        state = {"kind": "cryptovalid_monitor_state/1", "tree_size": n2, "root_sha256": root2, "ts": verdict["ts"],
                 "ledger": verdict["ledger"]}
        scrivi = True
        if keyfile:
            sth = R.signed_tree_head(leaves, keyfile)
            state.update({"sth": sth, "log_pubkey_hex": sth["log_pubkey_hex"]})
        elif trusted_pubkey_hex:
            # AUDITOR: never degrade the baseline to an unsigned one (round 3: it did). Advance only with a
            # signed head for THIS tree, published by the writer and verified here.
            sth_ext = None
            if sth_path and os.path.exists(sth_path):
                try:
                    with open(sth_path, encoding="utf-8") as f:
                        doc = json.load(f)
                    # accetta sia {"sth": {...}} (stato del writer) sia lo STH nudo; tutto il resto è «non valido»
                    sth_ext = doc.get("sth", doc) if isinstance(doc, dict) else None
                    if not isinstance(sth_ext, dict):
                        sth_ext = None
                except (ValueError, OSError):
                    sth_ext = None
            if sth_ext and R.verify_sth(sth_ext, trusted_pubkey_hex).get("ok") and int(sth_ext["tree_size"]) == n2 and sth_ext["root_sha256"] == root2:
                state.update({"sth": sth_ext, "log_pubkey_hex": trusted_pubkey_hex})
            elif prev and prev.get("sth") and int(prev["tree_size"]) == n2 and prev["root_sha256"] == root2:
                state.update({"sth": prev["sth"], "log_pubkey_hex": prev.get("log_pubkey_hex")})   # unchanged tree: keep the signed head
            else:
                scrivi = False
                verdict["baseline_non_avanzata"] = ("auditor: nessuno STH firmato per l'albero corrente (passare --sth-file "
                                                    "pubblicato dal writer); la baseline resta quella precedente")
        if scrivi:
            tmp = state_path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(state, f, indent=1)
            os.replace(tmp, state_path)
            verdict["state_written"] = state_path
    return verdict


def main(argv: Optional[List[str]] = None) -> int:
    import argparse
    p = argparse.ArgumentParser(prog="cryptovalid_monitor", description="append-only / non-equivocation monitor for a cryptovalid ledger")
    p.add_argument("ledger"); p.add_argument("state", help="state file (last green tree head)")
    p.add_argument("--keyfile", help="log key: sign the state's tree head"); p.add_argument("--max-silence-h", type=float)
    p.add_argument("--trusted-pubkey", help="verify the saved tree head against this log key (auditor without the private key)")
    p.add_argument("--sth-file", help="auditor: signed tree head for the current tree, published by the writer")
    a = p.parse_args(argv)
    v = run(a.ledger, a.state, a.keyfile, a.max_silence_h, a.trusted_pubkey, a.sth_file)
    print(json.dumps(v, indent=1))
    return 0 if v["ok"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
