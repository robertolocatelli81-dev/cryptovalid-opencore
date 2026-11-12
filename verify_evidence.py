#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
verify_evidence.py — UN verificatore per TUTTA l'evidenza CryptoValid, offline, senza
fidarsi dell'autore. Chiude il gap #1 (council OMEGA 2026-08-21): finora la verifica
pubblica copriva solo la hash-chain del ledger; ogni altro strato viveva in un modulo
separato. Questo è l'ENTRY-POINT UNICO.

SCELTA DI RIGORE (dichiarata, non nascosta): questo file NON reimplementa la
crittografia. ORCHESTRA i verificatori di RIFERIMENTO in `opencore/` — gli stessi,
testati, che il prodotto usa. Reimplementarli qui creerebbe DIVERGENZA: un verificatore
"standalone" che diverge da quello reale darebbe un falso-verde. Riusarli garantisce che
ciò che verifichi TU è esattamente ciò che verifica il sistema. Serve il repo clonato
(che un auditor open-source ha comunque) + stdlib; `cryptography` per le firme Ed25519 e
`openssl` per RFC 3161 sono dichiarati per-strato: se mancano, lo strato risulta
"non verificato" (onesto), MAI un verde finto.

Uso:
  python3 verify_evidence.py auto     <path>         # rileva il tipo e verifica tutto
  python3 verify_evidence.py pack     <pack_dir>     # evidence pack (evidence_pack.py)
  python3 verify_evidence.py archive  <dir>          # archivio ingest: STH+HEAD+firma
  python3 verify_evidence.py ledger   <file.jsonl>   # sola hash-chain (come verify_ledger)
  python3 verify_evidence.py ap2      <evidence.json># mandati agentici SD-JWT (AP2)
  python3 verify_evidence.py cldma    <attest.json>  # attestazione CLDMA (ratio impegnato)

Status: `auto`, `pack` and `ledger` are the maintained core; `archive`, `ap2` and `cldma` are EXPERIMENTAL
(README, "Core and experimental modules"): kept and tested, no new scope is added to them.

Esce 0 se l'evidenza è valida per ciò che era verificabile, 1 altrimenti; 74 se la ricevuta non è stata scritta per
intero su stdout (pieno, chiuso, lettore assente), qualunque sia il verdetto (0.20.3).
"""
from __future__ import annotations

import sys as _sys_0203
if __name__ == "__main__":   # 0.20.3: run as a command, never write the bytecode cache: CPython 3.9 and 3.11 write
    _sys_0203.dont_write_bytecode = True   # a .pyc with one raw write; cut by a file size limit, every later run died (13/10/2026)
    _L0210 = type(__loader__)   # 0.21.0: a .pyc already cut (CPython 3.9/3.11 installed one) is compiled from the source
    if _L0210.__name__ == "SourceFileLoader":   # instead of failing every later run (EOFError: marshal data too short)
        def _get_code_0210(self, fullname, _get_code=_L0210.get_code):
            try:
                return _get_code(self, fullname)
            except (EOFError, ValueError):
                path = self.get_filename(fullname)
                return self.source_to_code(self.get_data(path), path)
        _L0210.get_code = _get_code_0210
import argparse
import json
import os
import sys
from datetime import datetime, timezone

_HERE = os.path.dirname(os.path.abspath(__file__))
# i verificatori di riferimento (verifier.py, evidence_pack.py…) possono stare:
#  - ACCANTO a questo file — quando è in `opencore/` (repo omega) o alla root del repo
#    pubblico cryptovalid-opencore (dove il sync copia l'intera dir opencore);
#  - in `<repo>/opencore/` — quando questo file vive in `docs/public_verify/`.
# Path robusto = funziona in ENTRAMBI i contesti (una sola copia, nessun doppione).
_REPO = os.path.dirname(os.path.dirname(_HERE))
_CANDIDATES = [_HERE, os.path.join(_REPO, "opencore")]


def _need_opencore():
    for cand in _CANDIDATES:
        if os.path.exists(os.path.join(cand, "verifier.py")):
            if cand not in sys.path:
                sys.path.insert(0, cand)
            return True
    return False


_OPENCORE = next((c for c in _CANDIDATES if os.path.exists(os.path.join(c, "verifier.py"))), _HERE)


def _not_run(e: BaseException) -> bool:
    """an exception that says a check could not be RUN here (openssl not startable, no temporary file): 0.20.3 lets it
    through (exit 74) instead of turning it into a FAIL layer on the input. ap2-evidence-pack >= 1.5.2 raises
    Ap2WriteError for the same case inside verify_evidence()."""
    try:
        from verifier import CheckNotRun
    except ImportError:
        return False
    if type(e).__name__ == "Ap2WriteError" and not isinstance(e, CheckNotRun):
        raise CheckNotRun(str(e)) from e
    return isinstance(e, CheckNotRun)


def _layer(name, status, detail=""):
    """Un esito di strato. status: 'PASS' | 'FAIL' | 'SKIP' (non verificabile qui, onesto)."""
    return {"layer": name, "status": status, "detail": detail}


# ─────────────────────────────────────────────────── verificatori per tipo

def _ledger_reasons(r: dict) -> list:
    """Every failure the reference receipt names, one string each: where (idx / line) and why."""
    out = []
    for k in ("hash_failures", "link_failures", "schema_failures"):
        for x in r.get(k) or []:
            why = x.get("reason") or ("prev_hash does not link to the previous self_hash" if k == "link_failures" else "unnamed")
            out.append(f"{k[:-9]} idx {json.dumps(x.get('idx'), ensure_ascii=False)}: {why}" if isinstance(x, dict) else f"{k[:-9]}: {x}")
    for x in r.get("parse_errors") or []:
        out.append(f"line {x.get('line')}: {x.get('error')}" if isinstance(x, dict) else f"parse: {x}")
    if r.get("verdict") == "FILE_NOT_FOUND":
        out.append("file not found")
    return out


def verify_ledger(path: str) -> dict:
    """Sola hash-chain del ledger (riusa il verificatore di riferimento se presente,
    altrimenti il mini-verificatore stdlib in questa stessa cartella)."""
    layers = []
    try:
        if _need_opencore():
            import verifier
            r = verifier.verify_ledger(path)
        else:
            import verify_ledger as vl  # il mini-verificatore stdlib vicino
            r = vl.verify_ledger(path)
        ok = r.get("verdict") in ("PASS", "LINKED")
        layer = _layer("ledger hash-chain", "PASS" if ok else "FAIL", f"verdict={r.get('verdict')}")
        if not ok:
            # 0.20.0: the reasons the receipt names, not the bare verdict (the receipt keeps the first 10 per field)
            layer["reasons"] = _ledger_reasons(r)
            layer["detail"] += "; " + ("; ".join(layer["reasons"][:3]) if layer["reasons"] else "no reason named by the receipt")
        layers.append(layer)
    except Exception as e:  # noqa: BLE001
        layers.append(_layer("ledger hash-chain", "FAIL", f"{type(e).__name__}: {e}"))
    return _rollup("ledger", layers)


_REFERENCE_STATE_KEYS = ("admission", "refusal_class", "states_vocabulary", "states", "policy")


def _with_reference_states(rollup: dict, r: dict) -> dict:
    """0.22.0: the reference's own admission and states, copied untouched (this front-end derives none)."""
    for k in _REFERENCE_STATE_KEYS:
        if isinstance(r, dict) and k in r:
            rollup[k] = r[k]
    return rollup


def _pack_layers(r: dict, pack_dir: str) -> list:
    layers = [_layer("file digests == manifest", "PASS" if r.get("files_ok") else "FAIL"),
              _layer("manifest auto-consistente", "PASS" if r.get("manifest_ok") else "FAIL")]
    auth = r.get("manifest_authenticated")
    try:
        with open(os.path.join(pack_dir, "MANIFEST.json"), encoding="utf-8") as fh:
            sig_present = bool(json.load(fh).get("manifest_signature"))
    except (OSError, ValueError, AttributeError):
        sig_present = False
    # a manifest signature that is PRESENT but does not verify is tampering, never "unsigned" (audit V1 #1, 30/09/2026)
    layers.append(_layer("manifest autenticato (Ed25519)",
                         "PASS" if auth else ("FAIL" if sig_present else "SKIP"),
                         "firmato" if auth else ("firma presente ma NON valida" if sig_present
                                                 else "non firmato o cryptography assente")))
    layers.append(_layer("ledger: hash+firma+anti-troncamento", "PASS" if r.get("ledgers_ok") else "FAIL"))
    rfc = r.get("rfc3161") or {}
    ta = (r.get("states") or {}).get("time_anchor") or {}
    if rfc.get("claimed"):
        v = rfc.get("verified")
        # 0.22.0: the reference's time_anchor decides FAIL (contradicted: token missing, invalid, another digest) vs SKIP
        layers.append(_layer("RFC 3161 timestamp",
                             "PASS" if v is True else ("FAIL" if ta.get("state") == "contradicted" or v is False else "SKIP"),
                             "" if v is True else str(ta.get("detail") or rfc.get("note") or "openssl assente")))
    else:
        layers.append(_layer("RFC 3161 timestamp", "SKIP", "nessun timestamp nel pack"))
    # the reference verifier's own verdict is a mandatory layer: this front-end never passes what it rejects
    layers.append(_layer("verdetto del verificatore di riferimento (evidence_pack.verify_pack)",
                         "PASS" if r.get("valid") is True else "FAIL",
                         "" if r.get("valid") is True else str(r.get("error") or "")))
    return layers


def verify_pack(pack_dir: str) -> dict:
    """Evidence pack completo: digest dei file, manifest auto-consistente, ogni ledger
    (hash+firma+anti-troncamento), token RFC 3161. Riusa evidence_pack.verify_pack.
    0.22.0: copies the reference's `admission` / `states` (SPEC §10); a check that cannot run here is the COMPLETE
    receipt and exit 74 (CheckNotRun carries it), as in evidence_pack.py verify."""
    if not _need_opencore():
        return _rollup("pack", [_layer("evidence pack", "SKIP",
                                       "opencore/ non trovato: serve il repo per la verifica completa")])
    try:
        import evidence_pack
        r = evidence_pack.verify_pack(pack_dir)
    except Exception as e:  # noqa: BLE001
        rec = getattr(e, "receipt", None)
        if _not_run(e) and isinstance(rec, dict):
            from verifier import CheckNotRun
            raise CheckNotRun(str(e), receipt=_with_reference_states(_rollup("pack", _pack_layers(rec, pack_dir)), rec)) from e
        if _not_run(e):
            raise
        return _rollup("pack", [_layer("evidence pack", "FAIL", f"{type(e).__name__}: {e}")])
    return _with_reference_states(_rollup("pack", _pack_layers(r, pack_dir)), r)


def verify_archive(directory: str, prefix: str = "ledger") -> dict:
    """Archivio ingest: catene dei segmenti, Merkle STH, HEAD firmato (tail guard)."""
    layers = []
    if not _need_opencore():
        return _rollup("archive", [_layer("archive", "SKIP", "opencore/ non trovato")])
    try:
        import cryptovalid_ingest as ingest
        r = ingest.verify_archive(directory, prefix=prefix)
        layers.append(_layer("segmenti + Merkle STH + HEAD", "PASS" if r.get("ok") else "FAIL",
                             f"segmenti={r.get('segments_verified')} STH={r.get('head_present')}"))
        for w in (r.get("warnings") or [])[:5]:
            layers.append(_layer("avviso", "SKIP", w))
    except Exception as e:  # noqa: BLE001
        if _not_run(e):
            raise
        layers.append(_layer("archive", "FAIL", f"{type(e).__name__}: {e}"))
    return _rollup("archive", layers)


def _ap2_layers(r: dict) -> list:
    layers = [_layer("digest file", "PASS" if r.get("digest_ok") else "FAIL")]
    arts = r.get("artifacts") or []
    # 0.22.0: zero artifacts is not a pass of this layer (ap2-evidence-pack 1.6.0 refuses with `artifacts: []`; all() of
    # nothing is True)
    layers.append(_layer("firme ES256 + disclosure + binding",
                         "PASS" if arts and all(a.get("signature_ok") and a.get("claims_match") for a in arts)
                         and r.get("bindings_ok") else "FAIL"))
    rfc = r.get("rfc3161") or {}
    v = rfc.get("verified")
    layers.append(_layer("RFC 3161", "PASS" if v is True else ("SKIP" if v in (None,) and not rfc.get("claimed") else ("SKIP" if v is None else "FAIL"))))
    prod = r.get("producer_signatures") or {}
    if prod.get("present"):
        # a producer signature that is PRESENT but does not verify is tampering (audit V1 #2, 30/09/2026)
        layers.append(_layer("firma producer", "PASS" if prod.get("ok") else "FAIL",
                             "" if prod.get("ok") else "firma presente ma NON valida"))
    if r.get("self_asserted_only"):
        layers.append(_layer("provenienza chiavi", "SKIP",
                             "solo jwk auto-asserito: firma prova coerenza, non identità"))
    # the reference's own reason reaches the auditor: 1.2.x receipts carry `refused` (the copy shipped until 0.17.2
    # wrote `error`); without it a refused pack was a FAIL with an empty detail (measured 2026-10-05); 1.6.0 adds the class
    why = str(r.get("refused") or r.get("error") or "")
    if r.get("refusal_class"):
        why = f"{r['refusal_class']}: {why}"
    layers.append(_layer("verdetto del verificatore di riferimento (ap2_evidence.verify_evidence)",
                         "PASS" if r.get("valid") is True else "FAIL", "" if r.get("valid") is True else why))
    return layers


def verify_ap2(path: str) -> dict:
    """Evidenza di mandati agentici SD-JWT (AP2): firme ES256, disclosure, binding, KB-JWT.
    0.22.0: copies the reference's `admission`, `refusal_class`, `states_vocabulary`, `states`, `policy` (ap2-evidence-pack
    >= 1.6.0, SPEC §6.9) untouched; an `Ap2WriteError` carrying the reference's COMPLETE receipt (a check that could not run
    here, SPEC §6.10) becomes this front-end's complete receipt and exit 74 — 1.6.0 raises it only with tsa_cert or
    trust_anchor, which this function does not pass (measured 19/10/2026: unreachable from here today, kept for a later 1.x)."""
    if not _need_opencore():
        return _rollup("ap2", [_layer("ap2 evidence", "SKIP", "opencore/ non trovato")])
    try:
        import ap2_evidence   # ap2-evidence-pack (0.18.0: no longer shipped here; the `ap2` extra installs it)
    except ImportError:
        return _rollup("ap2", [_layer("ap2 evidence", "FAIL",
                                      "ap2-evidence-pack not installed: pip install 'cryptovalid-opencore[ap2]'")])
    try:
        r = ap2_evidence.verify_evidence(path)
    except Exception as e:  # noqa: BLE001
        rec = getattr(e, "receipt", None)
        if type(e).__name__ == "Ap2WriteError" and isinstance(rec, dict):
            from verifier import CheckNotRun
            raise CheckNotRun(str(e), receipt=_with_reference_states(_rollup("ap2", _ap2_layers(rec)), rec)) from e
        if _not_run(e):
            raise
        return _rollup("ap2", [_layer("ap2 evidence", "FAIL", f"{type(e).__name__}: {e}")])
    return _with_reference_states(_rollup("ap2", _ap2_layers(r)), r)


def verify_cldma(path: str) -> dict:
    """Attestazione CLDMA: i totali pubblicati sono legati alla radice + ratio coerente."""
    layers = []
    if not _need_opencore():
        return _rollup("cldma", [_layer("cldma", "SKIP", "opencore/ non trovato")])
    try:
        import committed_attestation as cldma
        with open(path, encoding="utf-8") as f:
            att = json.load(f)
        ok = cldma.verify_attestation(att)
        layers.append(_layer("totali legati alla radice + ratio", "PASS" if ok else "FAIL"))
        # disciplina dual-hash (2026-08-22): guardia di coerenza che SA fallire — riproducibilita' del calcolo
        # (numerical_hash) + invariante num<=den per metriche limitate (coglie il ratio IMPOSSIBILE che
        # verify_attestation da solo accetta). Il verificatore usa KNOWN_BOUNDED per metric_id, non il campo del prover.
        cons = cldma.verify_metric_consistency(att)
        detail = "" if cons["ok"] else "; ".join(cons.get("reasons", []))
        layers.append(_layer("coerenza metrica (riproducibilita' + ratio possibile)",
                             "PASS" if cons["ok"] else "FAIL", detail))
    except Exception as e:  # noqa: BLE001
        layers.append(_layer("cldma", "FAIL", f"{type(e).__name__}: {e}"))
    return _rollup("cldma", layers)


# ─────────────────────────────────────────────────── auto-detect

def verify_auto(path: str) -> dict:
    """Rileva il tipo dell'artefatto e instrada al verificatore giusto."""
    if os.path.isdir(path):
        if os.path.exists(os.path.join(path, "MANIFEST.json")):
            return verify_pack(path)
        # archivio ingest: cerca un HEAD o segmenti
        import glob
        if glob.glob(os.path.join(path, "*.head.json")) or glob.glob(os.path.join(path, "*-*.jsonl")):
            return verify_archive(path)
        return _rollup("auto", [_layer("auto-detect", "FAIL",
                                       "directory non riconosciuta (né pack né archivio)")])
    # file: sniff del contenuto
    try:
        with open(path, encoding="utf-8") as f:
            head = f.read(2048)
    except OSError as e:
        return _rollup("auto", [_layer("auto-detect", "FAIL", str(e))])
    if '"evidence_format"' in head and "ap2-evidence" in head:
        return verify_ap2(path)
    if '"root_hash"' in head and ('"metric_id"' in head or "CLDMA" in head):
        return verify_cldma(path)
    if head.lstrip().startswith("{") and _top_level_evidence_format(path).startswith("ap2-evidence"):
        # 0.18.0: an AP2 pack is one JSON object whose keys are sorted, so `artifacts` comes first and `evidence_format`
        # can sit past the 2048-byte sniff (measured 2026-10-05: 2 artifacts built by `ap2-evidence build` put it at
        # byte 3506; `auto` then verified the file as a ledger and said FAIL on a valid pack).
        return verify_ap2(path)
    return verify_ledger(path)


def _top_level_evidence_format(path: str, limit: int = 64 * 1024 * 1024) -> str:
    """The `evidence_format` of a single JSON object file, "" when the file is not one (or is larger than `limit`)."""
    try:
        if os.path.getsize(path) > limit:
            return ""
        with open(path, encoding="utf-8") as f:
            obj = json.load(f)
    except (OSError, ValueError, RecursionError):
        return ""
    fmt = obj.get("evidence_format") if isinstance(obj, dict) else None
    return fmt if isinstance(fmt, str) else ""


def _rollup(kind: str, layers: list) -> dict:
    checked = [x for x in layers if x["status"] in ("PASS", "FAIL")]
    valid = bool(checked) and all(x["status"] == "PASS" for x in checked)
    return {"kind": kind, "valid": valid, "layers": layers,
            "verified_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "note": ("verificati %d strati; %d non verificabili qui (SKIP, onesto)"
                     % (len(checked), len(layers) - len(checked)))}


def main(argv=None) -> int:
    _need_opencore()
    from verifier import receipt_cli
    return receipt_cli(_main)(argv)


def _main(argv=None) -> int:
    from verifier import Parser, receipt_not_written, write_stdout   # 0.20.3: the same write rule as verifier.py
    p = Parser(prog="verify_evidence",
                                description="Un verificatore per TUTTA l'evidenza CryptoValid, offline")
    p.add_argument("cmd", choices=["auto", "pack", "archive", "ledger", "ap2", "cldma"])
    p.add_argument("path")
    a = p.parse_args(sys.argv[1:] if argv is None else argv)
    fn = {"auto": verify_auto, "pack": verify_pack, "archive": verify_archive,
          "ledger": verify_ledger, "ap2": verify_ap2, "cldma": verify_cldma}[a.cmd]
    from verifier import CheckNotRun, check_not_run_exit
    try:
        r = fn(a.path)
    except CheckNotRun as e:   # 0.22.0: a check that could not run here, with the complete receipt: written whole, then 74
        if getattr(e, "receipt", None) is None:
            raise
        return check_not_run_exit(e, json.dumps(e.receipt, ensure_ascii=False, indent=1))
    why = write_stdout(json.dumps(r, ensure_ascii=False, indent=1))
    if why is not None:   # the receipt was not written whole: 74 (EX_IOERR), whatever `valid` says
        return receipt_not_written(why)
    return 0 if r["valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
