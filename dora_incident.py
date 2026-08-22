#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
dora_incident — tamper-evident, verifiable evidence for the DORA ICT-incident lifecycle.

WHY (measured, 2026-08-21): under EU DORA, supervisors moved to *evidence-driven* enforcement in
2026 — they want "timestamps, classification rationales, log trails", not policy PDFs. Major ICT
incidents have a hard reporting lifecycle: initial notification within 4h of major classification
(24h backstop), intermediate report within 72h, final report within 1 month (Delegated Reg.
2024/1772 thresholds). Existing anchoring tools (e.g. GetProofAnchor) cover *web* evidence
(screenshots/pages) but NOT the incident lifecycle, the deadline compliance, or the log trail.

WHAT THIS IS (and is NOT — the boundary never moves):
  - Each phase of an incident (detected → classified → initial/intermediate/final report) is a
    canonical, hash-chained record: append-only, any later edit changes the head (tamper-evident).
  - It checks the DORA reporting DEADLINES against the *recorded* timestamps and attests, for each,
    whether it was met and by how much — reproducibly, from the records alone.
  - It is proof-of-integrity + timeline + deadline-check, NOT proof of DORA COMPLIANCE and NOT
    proof that the major/significant CLASSIFICATION is correct (that is the entity's judgement,
    reviewed by its auditor). It does not verify the truth of the recorded facts. Garbage in →
    garbage attested faithfully (same confine as CryptoValid).

Stdlib only.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional

DORA_VERSION = "dora-incident-1.0"
# scadenze DORA (ore/giorni) — ancorate al testo, ri-configurabili se la normativa cambia
DEADLINES = {"initial_hours": 4.0, "initial_backstop_hours": 24.0,
             "intermediate_hours": 72.0, "final_days": 30.0}
_PHASES = ("detected", "classified_major", "initial_notification",
           "intermediate_report", "final_report")


@dataclass
class Phase:
    """Una fase del ciclo di vita dell'incident. `ts` = ISO8601 UTC (con Z o offset)."""
    phase: str
    ts: str
    detail: Dict = field(default_factory=dict)     # rationale di classificazione, ref, ecc.


def _parse(ts: str) -> datetime:
    s = ts.strip().replace("Z", "+00:00")
    d = datetime.fromisoformat(s)
    return d if d.tzinfo else d.replace(tzinfo=timezone.utc)


def _canon_bytes(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def canonical_phase(p: Phase) -> Dict:
    return {"phase": p.phase.strip().lower(), "ts": p.ts.strip(),
            "detail": p.detail or {}}


def build_chain(phases: List[Phase]) -> List[Dict]:
    """Hash-chain append-only delle fasi: ogni entry lega la precedente (tamper-evident)."""
    chain, prev = [], "GENESIS"
    for p in phases:
        cp = canonical_phase(p)
        h = hashlib.sha3_256(_canon_bytes({"canonical": cp, "prev": prev})).hexdigest()
        chain.append({"canonical": cp, "prev": prev, "self_hash": h})
        prev = h
    return chain


def verify_chain(chain: List[Dict]) -> bool:
    prev = "GENESIS"
    for e in chain:
        h = hashlib.sha3_256(_canon_bytes({"canonical": e["canonical"], "prev": prev})).hexdigest()
        if h != e.get("self_hash") or e.get("prev") != prev:
            return False
        prev = h
    return True


def _find(phases: List[Phase], name: str) -> Optional[Phase]:
    for p in phases:
        if p.phase.strip().lower() == name:
            return p
    return None


def check_deadlines(phases: List[Phase]) -> Dict:
    """Verifica le scadenze DORA contro i timestamp REGISTRATI. Il timer parte dalla
    classificazione 'major'. Ogni scadenza: met (bool), elapsed, limit, margin. Riproducibile."""
    base = _find(phases, "classified_major")
    if base is None:
        return {"applicable": False,
                "note": "nessuna classificazione 'classified_major' → il timer DORA non parte "
                        "(incident non-major o classificazione mancante)"}
    t0 = _parse(base.ts)
    checks = {}

    def _chk(name, phase_name, limit_h):
        p = _find(phases, phase_name)
        if p is None:
            checks[name] = {"present": False, "met": None,
                            "note": "fase non registrata"}
            return
        elapsed_h = (_parse(p.ts) - t0).total_seconds() / 3600.0
        checks[name] = {"present": True, "elapsed_hours": round(elapsed_h, 3),
                        "limit_hours": limit_h, "met": elapsed_h <= limit_h,
                        "margin_hours": round(limit_h - elapsed_h, 3)}

    _chk("initial_notification", "initial_notification", DEADLINES["initial_hours"])
    # se l'initial supera 4h ma sta nel backstop 24h, lo segnaliamo distinto
    ini = checks.get("initial_notification", {})
    if ini.get("present") and not ini.get("met"):
        ini["within_backstop_24h"] = ini["elapsed_hours"] <= DEADLINES["initial_backstop_hours"]
    _chk("intermediate_report", "intermediate_report", DEADLINES["intermediate_hours"])
    _chk("final_report", "final_report", DEADLINES["final_days"] * 24.0)
    all_present = all(c.get("present") for c in checks.values())
    all_met = all(c.get("met") for c in checks.values() if c.get("present"))
    return {"applicable": True, "classified_major_at": base.ts, "checks": checks,
            "all_phases_present": all_present, "all_deadlines_met": bool(all_met)}


def attest(phases: List[Phase], incident_id: str = "", as_of: str = "") -> Dict:
    """Attestazione: hash-chain delle fasi + verifica scadenze DORA + digest. Un terzo
    (il regolatore) ricostruisce dai record e ottiene lo STESSO digest e gli STESSI esiti."""
    chain = build_chain(phases)
    head = chain[-1]["self_hash"] if chain else "EMPTY"
    body = {"dora_version": DORA_VERSION, "incident_id": incident_id, "as_of": as_of,
            "n_phases": len(phases), "chain_head": head,
            "deadlines": check_deadlines(phases)}
    body["attestation_digest_sha3"] = hashlib.sha3_256(_canon_bytes(body)).hexdigest()
    body["honest_scope"] = (
        "Proves the incident phases are tamper-evident (hash chain), in recorded order, and "
        "whether each DORA reporting deadline was met per the RECORDED timestamps — reproducibly. "
        "NOT proof of DORA compliance, NOT proof the major/significant classification is correct "
        "(the entity's judgement, reviewed by its auditor), and not the truth of the facts. For "
        "legal-grade time, seal the chain head with a qualified eIDAS timestamp (cryptovalid_tsa).")
    return body


def verify_attestation(att: Dict, phases: List[Phase]) -> Dict:
    """Ricostruisce dai record e confronta con l'attestazione. Fail-closed."""
    chain = build_chain(phases)
    chain_ok = verify_chain(chain)
    head = chain[-1]["self_hash"] if chain else "EMPTY"
    recomputed = {"dora_version": att.get("dora_version"), "incident_id": att.get("incident_id"),
                  "as_of": att.get("as_of"), "n_phases": len(phases), "chain_head": head,
                  "deadlines": check_deadlines(phases)}
    digest = hashlib.sha3_256(_canon_bytes(recomputed)).hexdigest()
    return {"chain_ok": chain_ok, "head_match": head == att.get("chain_head"),
            "digest_match": digest == att.get("attestation_digest_sha3"),
            "valid": bool(chain_ok and head == att.get("chain_head")
                          and digest == att.get("attestation_digest_sha3"))}


def _load_phases(path: str) -> List[Phase]:
    with open(path, encoding="utf-8") as f:
        rows = json.load(f)
    return [Phase(phase=r["phase"], ts=r["ts"], detail=r.get("detail", {})) for r in rows]


def main(argv=None) -> int:
    import argparse
    import sys
    p = argparse.ArgumentParser(
        prog="dora-incident",
        description="Tamper-evident evidence for the DORA ICT-incident lifecycle (NOT a compliance certificate).")
    sub = p.add_subparsers(dest="cmd")
    a1 = sub.add_parser("attest")
    a1.add_argument("phases_json")
    a1.add_argument("--incident-id", default="")
    a1.add_argument("--as-of", default="")
    a2 = sub.add_parser("verify")
    a2.add_argument("attestation_json")
    a2.add_argument("phases_json")
    a = p.parse_args(sys.argv[1:] if argv is None else argv)
    if a.cmd == "attest":
        print(json.dumps(attest(_load_phases(a.phases_json), a.incident_id, a.as_of),
                         ensure_ascii=False, indent=1))
        return 0
    if a.cmd == "verify":
        with open(a.attestation_json, encoding="utf-8") as f:
            att = json.load(f)
        r = verify_attestation(att, _load_phases(a.phases_json))
        print(json.dumps(r, ensure_ascii=False, indent=1))
        return 0 if r["valid"] else 1
    p.print_help()
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
