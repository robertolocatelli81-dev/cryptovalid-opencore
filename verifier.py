#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CryptoValid Open Core - standalone ledger verifier (auditor-grade)
==================================================================

SPDX-License-Identifier: AGPL-3.0-or-later
Copyright (C) 2026 Roberto Locatelli

This file is part of CryptoValid Open Core (the AGPL-3.0 carve-out of the
OMEGA Ecosystem, relicensed by its author on 2026-08-08). You can redistribute
it and/or modify it under the terms of the GNU Affero General Public License
as published by the Free Software Foundation, either version 3 of the License,
or (at your option) any later version. See LICENSE in this directory.

Independently verifies a hash-chained ledger (*.jsonl) with NOTHING but the
Python standard library (hashlib, json, sys, argparse).

Verified schema:
  - each line is JSON with at least: {idx, ts, data, prev_hash, self_hash}
  - self_hash = SHA-256( JSON(entry without self_hash, sort_keys, separators (',',':')) )
  - prev_hash of entry i = self_hash of entry i-1 (the first has 64 zeros)

Output: structured JSON receipt. Exit code 0 = chain intact, 1 = failure.

Example:
    python3 opencore/verifier.py exports/omega_audit_ledger.jsonl
    python3 opencore/verifier.py ledger.jsonl --algo sha3_256

Reproducible by any third-party auditor: same file, same schema -> same receipt.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import datetime, timezone
from typing import Dict, List, Optional

GENESIS_PREV = "0" * 64
SUPPORTED_ALGOS = ("sha256", "sha3_256")


def canonical_payload(entry: Dict) -> bytes:
    """Stringa canonica dell'entry per ricomputare self_hash. Esclude self_hash E le attestazioni
    aggiunte DOPO (signature/signer): il self_hash impegna il CONTENUTO, la firma impegna il self_hash.
    Così un ledger firmato supera comunque la verifica di hash stdlib-only, senza toccare le firme."""
    d = {k: v for k, v in entry.items() if k not in ("self_hash", "signature", "signer")}
    return json.dumps(d, sort_keys=True, separators=(",", ":")).encode()


def hash_with(algo: str, payload: bytes) -> str:
    if algo == "sha256":
        return hashlib.sha256(payload).hexdigest()
    if algo == "sha3_256":
        return hashlib.sha3_256(payload).hexdigest()
    raise ValueError(f"unsupported_algo:{algo}")


def detect_algo(entries: List[Dict]) -> Optional[str]:
    """Auto-detect: prova entrambi gli algoritmi sulla prima entry."""
    if not entries:
        return None
    e0 = entries[0]
    if "self_hash" not in e0:
        return None
    payload = canonical_payload(e0)
    for algo in SUPPORTED_ALGOS:
        if hash_with(algo, payload) == e0["self_hash"]:
            return algo
    return None


def _generic_recompute_verify(entries: List[Dict], started: str, path: str) -> Optional[Dict]:
    """Tentativo di verifica COMPLETA (ricomputo hash) per ledger senza `idx` ma con una
    regola di hashing GENERICA rilevabile: hash_key = ALGO( canonical(entry senza hash_key
    [e senza signature]) ). Ritorna un receipt PASS solo se il ricomputo combacia su TUTTE
    le voci E la catena è integra (nessun rischio di falso PASS: PASS solo se ogni hash torna).
    Se la regola non combacia ovunque → None (si ripiega su linkage)."""
    if not entries:
        return None
    keys = list(entries[-1].keys())
    prev_keys = [k for k in keys if "prev" in k.lower() and "hash" in k.lower()]
    hash_cands = [k for k in keys if "hash" in k.lower() and "prev" not in k.lower()]
    if not prev_keys or not hash_cands:
        return None
    pk = prev_keys[0]
    sig_keys = [k for k in keys if k in ("signature", "sig")]
    total = len(entries)

    def _matches(hk, algo, drop):
        idxs = []
        for i, e in enumerate(entries):
            body = {k: v for k, v in e.items() if k not in drop}
            payload = json.dumps(body, sort_keys=True, separators=(",", ":"), default=str).encode()
            if hash_with(algo, payload) == e.get(hk):
                idxs.append(i)
        return idxs

    # trova la regola (hk, algo, drop) che ricompone il PIÙ POSSIBILE delle voci
    best = None  # (n_ok, hk, algo, drop, ok_idxs)
    for hk in hash_cands:
        for algo in SUPPORTED_ALGOS:
            for drop in ({hk}, {hk, *sig_keys}):
                ok_idxs = _matches(hk, algo, drop)
                if best is None or len(ok_idxs) > best[0]:
                    best = (len(ok_idxs), hk, algo, drop, ok_idxs)

    if best is None:  # pragma: no cover - difensivo: hash_cands è già garantito non-vuoto sopra
        return None
    n_ok, hk, algo, drop, ok_idxs = best
    # regola NON rilevata (nessuna maggioranza) → schema module-specifico → ripiega su linkage
    if n_ok < max(1, (total + 1) // 2):
        return None

    # regola RILEVATA: da qui la verifica completa è OBBLIGATORIA (niente fallback che nasconda tamper)
    hash_failures = [i for i in range(total) if i not in set(ok_idxs)]
    # linkage sotto la stessa regola
    link_failures = []
    prev = GENESIS_PREV
    for i, e in enumerate(entries):
        if i > 0 and e.get(pk) not in (prev, None):
            link_failures.append(i)
        prev = e.get(hk)
    passed = (not hash_failures) and (not link_failures)
    receipt = {
        "verified_utc": started,
        "verifier": "OMEGA core.verify_ledger v1.1 (stdlib-only, generic full-recompute)",
        "path": path,
        "mode": "full_recompute_generic",
        "algorithm_used": algo,
        "hash_key": hk,
        "prev_key": pk,
        "drop_fields": sorted(drop),
        "entries_count": total,
        "hash_recomputed_ok": n_ok,
        "hash_failures_idx": hash_failures[:10],
        "link_failures_idx": link_failures[:10],
        "hash_recompute_passed": not hash_failures,
        "chain_integrity": passed,
        "verdict": "PASS" if passed else "FAIL",
    }
    rc = {k: v for k, v in receipt.items() if k != "verified_utc"}
    payload = json.dumps(rc, sort_keys=True, separators=(",", ":"), default=str).encode()
    receipt["receipt_sha256"] = hashlib.sha256(payload).hexdigest()
    return receipt


def _linkage_verify(entries: List[Dict], started: str, path: str) -> Optional[Dict]:
    """Verifica di LINKAGE per ledger OMEGA con schema di hash module-specifico
    (lens/nous/m5/qraft ecc.): questi non hanno `idx` e usano una regola di hashing
    propria che verify_ledger non ricomputa indipendentemente. Qui verifichiamo che la
    CATENA sia integra — ogni `prev_hash` == hash dell'entry precedente — il che rileva
    riordino / cancellazione / inserimento. Verdetto onesto: LINKED (non PASS: la
    ricomputazione completa dell'hash richiede il verificatore nativo del modulo)."""
    if not entries:
        return None
    keys = list(entries[-1].keys())
    prev_keys = [k for k in keys if "prev" in k.lower() and "hash" in k.lower()]
    hash_cands = [k for k in keys if "hash" in k.lower() and "prev" not in k.lower()]
    if not prev_keys or not hash_cands:
        return None
    pk = prev_keys[0]
    # scegli la hash-key che rende la catena più coerente
    best = None
    for hk in hash_cands:
        prev = None
        fails: List[Dict] = []
        for i, e in enumerate(entries):
            if i > 0 and e.get(pk) != prev:
                fails.append({"index": i, "expected_prev": prev, "actual_prev": e.get(pk)})
            prev = e.get(hk)
        if best is None or len(fails) < len(best[1]):
            best = (hk, fails)
    hk, link_failures = best
    linked = len(link_failures) == 0
    receipt = {
        "verified_utc": started,
        "verifier": "OMEGA core.verify_ledger v1.1 (stdlib-only, linkage mode)",
        "path": path,
        "mode": "linkage",
        "scheme_note": (
            "schema di hash module-specifico: verificata la CATENA "
            "(prev==hash precedente), NON la ricomputazione completa dell'hash "
            "(usa il verificatore nativo del modulo per quella)."
        ),
        "hash_key": hk,
        "prev_key": pk,
        "entries_count": len(entries),
        "link_ok": len(entries) - len(link_failures),
        "link_total": len(entries),
        "link_failures": link_failures[:10],
        "chain_linkage_integrity": linked,
        "verdict": "LINKED" if linked else "FAIL",
    }
    rc = {k: v for k, v in receipt.items() if k != "verified_utc"}
    payload = json.dumps(rc, sort_keys=True, separators=(",", ":"), default=str).encode()
    receipt["receipt_sha256"] = hashlib.sha256(payload).hexdigest()
    return receipt


def verify_ledger(path: str, algo: Optional[str] = None) -> Dict:
    """Verifica integrità del ledger. Restituisce receipt JSON-serializable."""
    started = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    errors: List[Dict] = []

    try:
        with open(path) as f:
            raw_lines = [ln for ln in f if ln.strip()]
    except FileNotFoundError:
        return {
            "verdict": "FILE_NOT_FOUND",
            "path": path,
            "verified_utc": started,
        }

    entries: List[Dict] = []
    for i, line in enumerate(raw_lines):
        try:
            entries.append(json.loads(line))
        except json.JSONDecodeError as e:
            errors.append({"line": i, "error": f"json_decode:{e}"})

    # Schema NATIVO (non-PersistentLedger): niente `idx` → verifica di linkage onesta,
    # senza fingere una ricomputazione completa dell'hash che non conosciamo.
    if algo is None and entries and not any("idx" in e for e in entries[:3]):
        # 1) prova la verifica COMPLETA generica (ricomputo hash su tutte le voci)
        full = _generic_recompute_verify(entries, started, path)
        if full is not None:
            return full
        # 2) altrimenti verifica di LINKAGE onesta (schema module-specifico)
        linkage = _linkage_verify(entries, started, path)
        if linkage is not None:
            return linkage

    if algo is None:
        algo = detect_algo(entries) or "sha256"

    # Re-hash check
    hash_recomputed = 0
    hash_failures: List[Dict] = []
    for i, e in enumerate(entries):
        expected = e.get("self_hash")
        if expected is None:
            hash_failures.append({"idx": e.get("idx", i), "reason": "missing_self_hash"})
            continue
        computed = hash_with(algo, canonical_payload(e))
        if computed == expected:
            hash_recomputed += 1
        else:
            hash_failures.append(
                {
                    "idx": e.get("idx", i),
                    "reason": "hash_mismatch",
                    "expected": expected,
                    "computed": computed,
                }
            )

    # Chain linkage check
    link_ok = 0
    link_failures: List[Dict] = []
    for i, e in enumerate(entries):
        expected_prev = entries[i - 1].get("self_hash") if i > 0 else GENESIS_PREV
        actual_prev = e.get("prev_hash")
        if actual_prev == expected_prev:
            link_ok += 1
        else:
            link_failures.append(
                {
                    "idx": e.get("idx", i),
                    "expected_prev": expected_prev,
                    "actual_prev": actual_prev,
                }
            )

    # Idx monotonicity
    idx_ok = True
    for i, e in enumerate(entries):
        if e.get("idx") != i:
            idx_ok = False
            errors.append({"line": i, "error": f"idx_mismatch: expected {i}, got {e.get('idx')}"})

    chain_integrity = len(hash_failures) == 0 and len(link_failures) == 0 and idx_ok and len(errors) == 0

    receipt: Dict = {
        "verified_utc": started,
        "verifier": "OMEGA core.verify_ledger v1.0 (stdlib-only)",
        "path": path,
        "algorithm_used": algo,
        "algorithm_supported": list(SUPPORTED_ALGOS),
        "entries_count": len(entries),
        "hash_recomputed_ok": hash_recomputed,
        "hash_recomputed_total": len(entries),
        "hash_recompute_passed": len(hash_failures) == 0,
        "hash_failures": hash_failures[:10],  # cap
        "link_ok": link_ok,
        "link_total": len(entries),
        "link_passed": len(link_failures) == 0,
        "link_failures": link_failures[:10],
        "idx_monotonic": idx_ok,
        "parse_errors": errors[:10],
        "chain_integrity": chain_integrity,
        "verdict": "PASS" if chain_integrity else "FAIL",
    }

    # Receipt-of-receipt: hash del receipt stesso (deterministico, escluso verified_utc)
    receipt_canonical = {k: v for k, v in receipt.items() if k != "verified_utc"}
    receipt_payload = json.dumps(
        receipt_canonical, sort_keys=True, separators=(",", ":"), default=str
    ).encode()
    receipt["receipt_sha256"] = hashlib.sha256(receipt_payload).hexdigest()
    receipt["receipt_sha3_256"] = hashlib.sha3_256(receipt_payload).hexdigest()
    return receipt


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="opencore/verifier.py",
        description="Verifica indipendente di un OMEGA ledger .jsonl (auditor-grade, stdlib-only).",
    )
    parser.add_argument("ledger_path", help="Path del file .jsonl da verificare")
    parser.add_argument(
        "--algo", choices=SUPPORTED_ALGOS, default=None, help="Forza algoritmo (default: auto-detect)"
    )
    parser.add_argument(
        "--quiet", action="store_true", help="Stampa solo il verdetto sintetico (PASS/FAIL + exit code)"
    )
    parser.add_argument("--out", default=None, help="Scrivi receipt JSON anche su file")
    args = parser.parse_args(argv)

    receipt = verify_ledger(args.ledger_path, algo=args.algo)

    if args.out:
        with open(args.out, "w") as f:
            json.dump(receipt, f, indent=2, default=str)

    if args.quiet:
        print(receipt["verdict"])
    else:
        print(json.dumps(receipt, indent=2, default=str))

    return 0 if receipt.get("verdict") == "PASS" else 1


if __name__ == "__main__":  # pragma: no cover - entrypoint CLI (main() è coperto direttamente)
    sys.exit(main())
