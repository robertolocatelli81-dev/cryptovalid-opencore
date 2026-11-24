#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
"""
verify_evidence.py — ONE verifier for ALL CryptoValid evidence, offline, without trusting the author. It closes gap #1
of the 2026-08-21 review: until then the public verification covered only the ledger hash chain and every other layer
lived in a separate module. This is the single entry point (`cryptovalid-verify`).

Design choice (declared): this file does NOT reimplement the cryptography. It ORCHESTRATES the reference verifiers of
this repository (verifier.py, evidence_pack.py, ...), the same tested code the product uses: a "standalone" verifier
that diverged from the real one would give a false green. Needs the repository (or the installed package) and the
standard library; `cryptography` for Ed25519 signatures and `openssl` for RFC 3161 are declared per layer: when one is
missing that layer is "not verified" (SKIP), never a false green.

Usage:
  cryptovalid-verify auto     <path>           # detect the type and verify everything
  cryptovalid-verify pack     <pack_dir>       # evidence pack (evidence_pack.py)
  cryptovalid-verify archive  <dir>            # ingest archive: STH + HEAD + signature
  cryptovalid-verify ledger   <file.jsonl>     # hash chain only (as verifier.py)
  cryptovalid-verify ap2      <evidence.json>  # SD-JWT agent mandates (AP2)
  cryptovalid-verify cldma    <attest.json>    # CLDMA attestation (committed ratio)
  cryptovalid-verify checkpoint <note> --vkey <vkey>   # C2SP checkpoint / signed note (SPEC §13)
  cryptovalid-verify tiles <dir> --vkey <vkey> --profile static-ct-api|tlog-tiles   # C2SP tiles (SPEC §14)
  cryptovalid-verify vkey-rfc6962 --name <origin> --key-b64 <DER>   # vkey (0x05) of a static CT log
  (the last three are the commands of cryptovalid_checkpoint.py, run by the same code; since 2026-11-15)
  cryptovalid-verify beacon <ledger> --entry <idx> --pulse <f> --previous <f> --certificate <f>
                     [--pack <dir> --tsa-cert <pem> --max-window <s>] [--checkpoint <note> ...] (options: --help)
  (a "not before" bound from the NIST Randomness Beacon inside a payment entry, SPEC §18-§19; cryptovalid_beacon.py)
  cryptovalid-verify --list-checks [command] [--format text|json]    # every check, its id and its norm (SPEC §23)
  cryptovalid-verify auto|pack|ledger|archive <path> --profile <file.json>   # add requirements, never remove (SPEC §23)

Status: `auto`, `pack` and `ledger` are the maintained core; `archive`, `ap2` and `cldma` are EXPERIMENTAL
(README, "Core and experimental modules"): kept and tested, no new scope is added to them.

Exits 0 if the evidence is valid for what could be verified, 1 otherwise, 2 on a usage error; 74 if a check could not run
here (the receipt is written whole, 0.22.0) or the receipt was not written whole to stdout (full, closed, no reader),
whatever the verdict (0.20.3).
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
import re
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


# SPEC v0.15 §23 rule 1: THE table of the checks. Every layer of a receipt is written through _check() with an id of this
# table (an id not here is a KeyError), `--list-checks` prints this table, and a test fails when an id here is written by
# no _check() call. id -> (layer name in the receipt, commands that run it, when it is not PASS/FAIL, norm)
_ROUTED = ("auto",)   # `auto` runs the checks of the command it routes the path to (SPEC §12)
CHECKS = {
    "auto.format": ("auto-detect", ("auto",), "FAIL when the path is none of the formats of the closed list", "SPEC §12"),
    "auto.checkpoint": ("checkpoint", ("auto",), "always SKIP: auto holds no trusted key; names the command to run",
                        "SPEC §12, §13"),
    "auto.tiles": ("tiles", ("auto",), "always SKIP: auto holds no trusted key; names the command to run", "SPEC §12, §14"),
    "ledger.chain": ("ledger hash-chain", ("ledger",) + _ROUTED, "never SKIP", "SPEC §2.1, §3, §5, §17, §22 rule 9"),
    "pack.run": ("evidence pack", ("pack",) + _ROUTED, "SKIP without the reference modules; FAIL when the reference raises",
                 "SPEC §10"),
    "pack.files": ("file digests == manifest", ("pack",) + _ROUTED, "never SKIP", "SPEC §10"),
    "pack.manifest": ("manifest auto-consistente", ("pack",) + _ROUTED, "never SKIP", "SPEC §10"),
    "pack.manifest_signature": ("manifest autenticato (Ed25519)", ("pack",) + _ROUTED,
                                "SKIP when the manifest carries no signature; FAIL when one is present and does not verify",
                                "SPEC §10, §5 step 5"),
    "pack.ledgers": ("ledger: hash+firma+anti-troncamento", ("pack",) + _ROUTED, "never SKIP", "SPEC §5, §10, §21 rule 7"),
    "pack.rfc3161": ("RFC 3161 timestamp", ("pack",) + _ROUTED,
                     "SKIP when the pack claims no token or it is not established here; FAIL when contradicted",
                     "SPEC §10, §11; RFC 3161"),
    "pack.reference": ("verdetto del verificatore di riferimento (evidence_pack.verify_pack)", ("pack",) + _ROUTED,
                       "never SKIP: the reference's own verdict", "SPEC §10"),
    "archive.run": ("archive", ("archive",) + _ROUTED, "SKIP without the reference modules; FAIL when the reference raises",
                    "SPEC §20 rules 8-11"),
    "archive.chain": ("segmenti + Merkle STH + HEAD", ("archive",) + _ROUTED, "never SKIP",
                      "SPEC §9 (RFC 6962), §20 rules 8-11, §22 rules 3, 7"),
    "archive.warning": ("avviso", ("archive",) + _ROUTED, "always SKIP: a warning of the reference (at most 5)",
                        "SPEC §20 rules 8-11"),
    "ap2.run": ("ap2 evidence", ("ap2",) + _ROUTED, "SKIP without the reference modules; FAIL without ap2-evidence-pack",
                "ap2-evidence-pack SPEC (separate package)"),
    "ap2.digest": ("digest file", ("ap2",) + _ROUTED, "never SKIP", "ap2-evidence-pack SPEC"),
    "ap2.signatures": ("firme ES256 + disclosure + binding", ("ap2",) + _ROUTED, "never SKIP; zero artifacts is FAIL",
                       "ap2-evidence-pack SPEC (SD-JWT)"),
    "ap2.rfc3161": ("RFC 3161", ("ap2",) + _ROUTED, "SKIP when no token is claimed or it is not established here",
                    "ap2-evidence-pack SPEC; RFC 3161"),
    "ap2.producer": ("firma producer", ("ap2",) + _ROUTED, "written only when a producer signature is present",
                     "ap2-evidence-pack SPEC"),
    "ap2.key_provenance": ("provenienza chiavi", ("ap2",) + _ROUTED, "always SKIP: written when the keys are self-asserted only",
                           "ap2-evidence-pack SPEC"),
    "ap2.reference": ("verdetto del verificatore di riferimento (ap2_evidence.verify_evidence)", ("ap2",) + _ROUTED,
                      "never SKIP: the reference's own verdict", "ap2-evidence-pack SPEC"),
    "cldma.run": ("cldma", ("cldma",) + _ROUTED, "SKIP without the reference modules; FAIL when reading fails",
                  "none: committed_attestation.py of this repository (experimental)"),
    "cldma.totals": ("totali legati alla radice + ratio", ("cldma",) + _ROUTED, "never SKIP",
                     "none: committed_attestation.py of this repository (experimental)"),
    "cldma.consistency": ("coerenza metrica (riproducibilita' + ratio possibile)", ("cldma",) + _ROUTED, "never SKIP",
                          "none: committed_attestation.py of this repository (experimental)"),
}
# SPEC §23 rule 1: commands whose checks are run by their own modules, not by the layers above
_OWN_CHECKS = {"checkpoint": "SPEC §13 (cryptovalid_checkpoint.py)", "tiles": "SPEC §14 (cryptovalid_checkpoint.py)",
               "vkey-rfc6962": "SPEC §13 (prints a key, checks nothing)", "beacon": "SPEC §18-§19 (cryptovalid_beacon.py)"}


def _check(cid, status, detail=""):
    """the layer of check `cid` of CHECKS (KeyError for an id not in the table). status: 'PASS' | 'FAIL' | 'SKIP'"""
    return {"layer": CHECKS[cid][0], "id": cid, "status": status, "detail": detail}


# ─────────────────────────────────────────────────── verificatori per tipo

def _ledger_classes(r: dict) -> str:
    """SPEC v0.12 §5 "Failure classes": the chain's findings told apart from the entries that are not in this format"""
    fc = r.get("failure_classes")
    if not isinstance(fc, dict):
        return ""
    ch, fo = fc.get("chain") or {}, fc.get("format") or {}
    parts = ["chain: %d link_mismatch, %d hash_mismatch" % (ch.get("link_mismatch", 0), ch.get("hash_mismatch", 0))]
    if any(fo.values()):
        parts.append("format (entries not in this format's schema, SPEC §2; they say nothing on the links): "
                     + ", ".join("%d %s" % (n, k) for k, n in fo.items() if n))
    if fc.get("other"):
        parts.append("other: %d" % fc["other"])
    return "; ".join(parts)


def _ledger_reasons(r: dict) -> list:
    """Every failure the reference receipt names, one string each: where (idx / line) and why. The chain's findings first
    (links, then hashes), then the entries outside the schema (SPEC v0.12 §5 "Failure classes")."""
    out = []
    for k in ("link_failures", "hash_failures", "schema_failures"):
        for x in r.get(k) or []:
            why = x.get("reason") or ("prev_hash does not link to the previous self_hash" if k == "link_failures" else "unnamed")
            out.append(f"{k[:-9]} idx {json.dumps(x.get('idx'), ensure_ascii=False)}: {why}" if isinstance(x, dict) else f"{k[:-9]}: {x}")
    for x in r.get("parse_errors") or []:
        out.append(f"line {x.get('line')}: {x.get('error')}" if isinstance(x, dict) else f"parse: {x}")
    if r.get("verdict") == "FILE_NOT_FOUND":
        out.append("file not found")
    return out


def verify_ledger(path: str, **pins) -> dict:
    """Sola hash-chain del ledger (riusa il verificatore di riferimento se presente,
    altrimenti il mini-verificatore stdlib in questa stessa cartella).
    `pins` (SPEC §23): keyword arguments of verifier.verify_ledger, only from a profile."""
    layers = []
    try:
        if _need_opencore():
            import verifier
            r = verifier.verify_ledger(path, **pins)
        elif pins:   # SPEC §23 rule 3: a requirement the mini-verifier cannot apply is a FAIL, never dropped
            raise RuntimeError("the profile's requirements need verifier.py")
        else:
            import verify_ledger as vl  # il mini-verificatore stdlib vicino
            r = vl.verify_ledger(path)
        ok = r.get("verdict") in ("PASS", "LINKED")
        layer = _check("ledger.chain", "PASS" if ok else "FAIL", f"verdict={r.get('verdict')}")
        if not ok:
            # 0.20.0: the reasons the receipt names, not the bare verdict (the receipt keeps the first 10 per field)
            layer["reasons"] = _ledger_reasons(r)
            if isinstance(r.get("failure_classes"), dict):
                layer["failure_classes"] = r["failure_classes"]
                layer["detail"] += "; " + _ledger_classes(r)
            layer["detail"] += "; " + ("; ".join(layer["reasons"][:3]) if layer["reasons"] else "no reason named by the receipt")
        layers.append(layer)
    except Exception as e:  # noqa: BLE001
        layers.append(_check("ledger.chain", "FAIL", f"{type(e).__name__}: {e}"))
    return _rollup("ledger", layers)


_REFERENCE_STATE_KEYS = ("admission", "refusal_class", "states_vocabulary", "states", "policy")


def _with_reference_states(rollup: dict, r: dict) -> dict:
    """0.22.0: the reference's own admission and states, copied untouched (this front-end derives none)."""
    for k in _REFERENCE_STATE_KEYS:
        if isinstance(r, dict) and k in r:
            rollup[k] = r[k]
    return rollup


def _open_regular(path: str) -> int:
    """SPEC §5 step 0: a descriptor of a regular file, opened once without blocking and judged on the open descriptor
    (a FIFO or a device at the path is an OSError, never waited on). Here and not from verifier.py: this front-end also
    runs where only the mini-verifier is beside it."""
    import stat
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOCTTY", 0) | getattr(os, "O_BINARY", 0))
    if not stat.S_ISREG(os.fstat(fd).st_mode):
        os.close(fd)
        raise OSError(f"{path}: not a regular file")
    return fd


def _pack_layers(r: dict, pack_dir: str) -> list:
    layers = [_check("pack.files", "PASS" if r.get("files_ok") else "FAIL"),
              _check("pack.manifest", "PASS" if r.get("manifest_ok") else "FAIL")]
    auth = r.get("manifest_authenticated")
    try:
        # SPEC §5 step 0: opened once without blocking (a FIFO as MANIFEST.json blocked here until 0.26.0)
        with os.fdopen(_open_regular(os.path.join(pack_dir, "MANIFEST.json")), encoding="utf-8") as fh:
            sig_present = bool(json.load(fh).get("manifest_signature"))
    except (OSError, ValueError, AttributeError, RecursionError):   # nesting past the parser: unreadable, never a traceback
        sig_present = False
    # a manifest signature that is PRESENT but does not verify is tampering, never "unsigned" (audit V1 #1, 30/09/2026)
    layers.append(_check("pack.manifest_signature",
                         "PASS" if auth else ("FAIL" if sig_present else "SKIP"),
                         "signed" if auth else ("signature present but NOT valid" if sig_present
                                                 else "not signed, or cryptography absent")))
    layers.append(_check("pack.ledgers", "PASS" if r.get("ledgers_ok") else "FAIL"))
    rfc = r.get("rfc3161") or {}
    ta = (r.get("states") or {}).get("time_anchor") or {}
    if rfc.get("claimed"):
        v = rfc.get("verified")
        # 0.22.0: the reference's time_anchor decides FAIL (contradicted: token missing, invalid, another digest) vs SKIP
        layers.append(_check("pack.rfc3161",
                             "PASS" if v is True else ("FAIL" if ta.get("state") == "contradicted" or v is False else "SKIP"),
                             "" if v is True else str(ta.get("detail") or rfc.get("note") or "openssl absent")))
    else:
        layers.append(_check("pack.rfc3161", "SKIP", "no timestamp in the pack"))
    # the reference verifier's own verdict is a mandatory layer: this front-end never passes what it rejects
    layers.append(_check("pack.reference",
                         "PASS" if r.get("valid") is True else "FAIL",
                         "" if r.get("valid") is True else str(r.get("error") or "")))
    return layers


def verify_pack(pack_dir: str, **pins) -> dict:
    """Evidence pack completo: digest dei file, manifest auto-consistente, ogni ledger
    (hash+firma+anti-troncamento), token RFC 3161. Riusa evidence_pack.verify_pack.
    0.22.0: copies the reference's `admission` / `states` (SPEC §10); a check that cannot run here is the COMPLETE
    receipt and exit 74 (CheckNotRun carries it), as in evidence_pack.py verify."""
    if not _need_opencore():
        return _rollup("pack", [_check("pack.run", "SKIP",
                                       "opencore/ not found: the full check needs the repository")])
    try:
        import evidence_pack
        r = evidence_pack.verify_pack(pack_dir, **pins)
    except Exception as e:  # noqa: BLE001
        rec = getattr(e, "receipt", None)
        if _not_run(e) and isinstance(rec, dict):
            from verifier import CheckNotRun
            raise CheckNotRun(str(e), receipt=_with_reference_states(_rollup("pack", _pack_layers(rec, pack_dir)), rec)) from e
        if _not_run(e):
            raise
        return _rollup("pack", [_check("pack.run", "FAIL", f"{type(e).__name__}: {e}")])
    return _with_reference_states(_rollup("pack", _pack_layers(r, pack_dir)), r)


def verify_archive(directory: str, prefix: str = "ledger", **pins) -> dict:
    """Archivio ingest: catene dei segmenti, Merkle STH, HEAD firmato (tail guard)."""
    layers = []
    if not _need_opencore():
        return _rollup("archive", [_check("archive.run", "SKIP", "opencore/ not found")])
    try:
        import cryptovalid_ingest as ingest
        r = ingest.verify_archive(directory, prefix=prefix, **pins)
        layers.append(_check("archive.chain", "PASS" if r.get("ok") else "FAIL",
                             f"segmenti={r.get('segments_verified')} STH={r.get('head_present')}"))
        for w in (r.get("warnings") or [])[:5]:
            layers.append(_check("archive.warning", "SKIP", w))
    except Exception as e:  # noqa: BLE001
        if _not_run(e):
            raise
        layers.append(_check("archive.run", "FAIL", f"{type(e).__name__}: {e}"))
    return _rollup("archive", layers)


def _ap2_layers(r: dict) -> list:
    layers = [_check("ap2.digest", "PASS" if r.get("digest_ok") else "FAIL")]
    arts = r.get("artifacts") or []
    # 0.22.0: zero artifacts is not a pass of this layer (ap2-evidence-pack 1.6.0 refuses with `artifacts: []`; all() of
    # nothing is True)
    layers.append(_check("ap2.signatures",
                         "PASS" if arts and all(a.get("signature_ok") and a.get("claims_match") for a in arts)
                         and r.get("bindings_ok") else "FAIL"))
    rfc = r.get("rfc3161") or {}
    v = rfc.get("verified")
    layers.append(_check("ap2.rfc3161", "PASS" if v is True else ("SKIP" if v in (None,) and not rfc.get("claimed") else ("SKIP" if v is None else "FAIL"))))
    prod = r.get("producer_signatures") or {}
    if prod.get("present"):
        # a producer signature that is PRESENT but does not verify is tampering (audit V1 #2, 30/09/2026)
        layers.append(_check("ap2.producer", "PASS" if prod.get("ok") else "FAIL",
                             "" if prod.get("ok") else "signature present but NOT valid"))
    if r.get("self_asserted_only"):
        layers.append(_check("ap2.key_provenance", "SKIP",
                             "self-asserted jwk only: the signature proves consistency, not identity"))
    # the reference's own reason reaches the auditor: 1.2.x receipts carry `refused` (the copy shipped until 0.17.2
    # wrote `error`); without it a refused pack was a FAIL with an empty detail (measured 2026-10-05); 1.6.0 adds the class
    why = str(r.get("refused") or r.get("error") or "")
    if r.get("refusal_class"):
        why = f"{r['refusal_class']}: {why}"
    layers.append(_check("ap2.reference",
                         "PASS" if r.get("valid") is True else "FAIL", "" if r.get("valid") is True else why))
    return layers


def verify_ap2(path: str) -> dict:
    """Evidenza di mandati agentici SD-JWT (AP2): firme ES256, disclosure, binding, KB-JWT.
    0.22.0: copies the reference's `admission`, `refusal_class`, `states_vocabulary`, `states`, `policy` (ap2-evidence-pack
    >= 1.6.0, SPEC §6.9) untouched; an `Ap2WriteError` carrying the reference's COMPLETE receipt (a check that could not run
    here, SPEC §6.10) becomes this front-end's complete receipt and exit 74 — 1.6.0 raises it only with tsa_cert or
    trust_anchor, which this function does not pass (measured 19/10/2026: unreachable from here today, kept for a later 1.x)."""
    if not _need_opencore():
        return _rollup("ap2", [_check("ap2.run", "SKIP", "opencore/ not found")])
    try:
        import ap2_evidence   # ap2-evidence-pack (0.18.0: no longer shipped here; the `ap2` extra installs it)
    except ImportError:
        return _rollup("ap2", [_check("ap2.run", "FAIL",
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
        return _rollup("ap2", [_check("ap2.run", "FAIL", f"{type(e).__name__}: {e}")])
    return _with_reference_states(_rollup("ap2", _ap2_layers(r)), r)


def verify_cldma(path: str) -> dict:
    """Attestazione CLDMA: i totali pubblicati sono legati alla radice + ratio coerente."""
    layers = []
    if not _need_opencore():
        return _rollup("cldma", [_check("cldma.run", "SKIP", "opencore/ not found")])
    try:
        import committed_attestation as cldma
        import verifier
        # SPEC §5 step 0 (v0.11): opened once without blocking, bounded (a FIFO here hung until 0.26.0)
        att = json.loads(verifier.read_regular(path, _AUTO_JSON_LIMIT).decode("utf-8"))
        ok = cldma.verify_attestation(att)
        layers.append(_check("cldma.totals", "PASS" if ok else "FAIL"))
        # disciplina dual-hash (2026-08-22): guardia di coerenza che SA fallire — riproducibilita' del calcolo
        # (numerical_hash) + invariante num<=den per metriche limitate (coglie il ratio IMPOSSIBILE che
        # verify_attestation da solo accetta). Il verificatore usa KNOWN_BOUNDED per metric_id, non il campo del prover.
        cons = cldma.verify_metric_consistency(att)
        detail = "" if cons["ok"] else "; ".join(cons.get("reasons", []))
        layers.append(_check("cldma.consistency",
                             "PASS" if cons["ok"] else "FAIL", detail))
    except Exception as e:  # noqa: BLE001
        layers.append(_check("cldma.run", "FAIL", f"{type(e).__name__}: {e}"))
    return _rollup("cldma", layers)


# ─────────────────────────────────────────────────── auto-detect

_AUTO_JSON_LIMIT = 64 * 1024 * 1024   # SPEC §12: the two JSON documents are read whole up to this size
_RECOGNISED = ("evidence pack directory (MANIFEST.json), ingest archive directory (*.head.json or *-*.jsonl), "
               "AP2 evidence (one JSON object, evidence_format ap2-evidence*), CLDMA attestation (one JSON object with "
               "root_hash and metric_id), ledger (JSONL whose first line is an object with prev_hash and self_hash), "
               "C2SP checkpoint (a signed note of at most 1 MiB whose text is a checkpoint), C2SP tiled log directory "
               "(a directory tile)")
_NOTE_LIMIT = 1 << 20   # SPEC §12: a file is read as a signed note up to the limit of a note file on the command line


class _NotRecognised(Exception):
    """SPEC §12: the path is none of the recognised formats; the message is the reason"""


def _not_recognised(why: str) -> dict:
    return _rollup("auto", [_check("auto.format", "FAIL", f"format not recognised: {why}; recognised: {_RECOGNISED}")])


def _json_value(text: str, what: str):
    try:
        return json.loads(text)
    except RecursionError:
        raise _NotRecognised(f"{what}: JSON nested deeper than the parser allows") from None
    except ValueError as e:
        raise _NotRecognised(f"{what} is not JSON ({e})") from None


def _utf8(raw: bytes, what: str) -> str:
    if raw.startswith(b"\xef\xbb\xbf"):
        raise _NotRecognised(f"{what} starts with a UTF-8 byte order mark")
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as e:
        raise _NotRecognised(f"{what} is not UTF-8 text (byte {e.start}: {raw[e.start:e.start + 1].hex()})") from None


_NO_JSON = object()


def _checkpoint_note(raw: bytes):
    """SPEC §12, row C2SP checkpoint: the parsed checkpoint when the bytes are a signed note whose text is a checkpoint,
    read by the code of `cryptovalid-verify checkpoint`; else None"""
    _need_opencore()
    import cryptovalid_checkpoint as C
    try:
        text, _sigs = C.split_note(raw)
        return C.parse_checkpoint(text)
    except C.NoteError:
        return None


def _file_format(path: str, found: dict = None) -> str:
    """'ap2', 'cldma', 'ledger' or 'checkpoint' for a regular file (SPEC §12), else _NotRecognised with the reason;
    `found` receives the parsed checkpoint"""
    with os.fdopen(_open_regular(path), "rb") as fh:   # SPEC §5 step 0: judged on the open descriptor
        raw = fh.read(_AUTO_JSON_LIMIT + 1)
    whole_read = len(raw) <= _AUTO_JSON_LIMIT
    rows, whole, doc = [], _NO_JSON, None
    if whole_read and len(raw) <= _NOTE_LIMIT and not raw.startswith(b"\xef\xbb\xbf"):
        cp = _checkpoint_note(raw)
    else:
        cp = None
    if whole_read:
        try:
            doc = _utf8(raw, "the file")
            whole = _json_value(doc, "the file")
        except _NotRecognised:
            doc = None   # not one JSON document (whole stays _NO_JSON): it can still be a ledger; free the decoded copy
        if isinstance(whole, dict):
            fmt = whole.get("evidence_format")
            if isinstance(fmt, str) and fmt.startswith("ap2-evidence"):
                rows.append("ap2")
            if "root_hash" in whole and "metric_id" in whole:
                rows.append("cldma")
    lines = raw.split(b"\n")
    if not whole_read:
        if len(lines) == 1:
            raise _NotRecognised("the file is larger than 64 MiB and its first line longer than 64 MiB")
        lines = lines[:-1]   # the last piece read may be a cut line
    first = None
    for i, line in enumerate(lines):
        text = _utf8(line, f"line {i + 1}")
        if text.strip(" \t\r"):
            first = text
            break
    if first is None:
        raise _NotRecognised("the file is empty or blank" if whole_read else "no non-blank line in the first 64 MiB")
    try:
        if whole is not _NO_JSON and doc.strip(" \t\r\n") == first.strip(" \t\r"):
            # the document is this one line: parse it once (measured 15/11/2026: a 60 MiB one-line JSON array of empty
            # objects was parsed twice, 3 GB peak instead of 1.5 GB)
            entry = whole
        else:
            entry = _json_value(first, "the first non-blank line")
    except _NotRecognised as e:
        entry, why_not_ledger = _NO_JSON, str(e)
    else:
        why_not_ledger = ("the first non-blank line is " + _json_kind(entry) if not isinstance(entry, dict) else
                          "the first non-blank line is a JSON object without " + " and ".join(
                              k for k in ("prev_hash", "self_hash") if k not in entry))
    if isinstance(entry, dict) and "prev_hash" in entry and "self_hash" in entry:
        rows.append("ledger")
    if cp is not None:
        rows.append("checkpoint")
        if found is not None:
            found["checkpoint"] = cp
    if len(rows) > 1:
        raise _NotRecognised("ambiguous: the file matches " + " and ".join(rows) + "; name the verifier")
    if rows:
        return rows[0]
    if isinstance(whole, dict):
        keys = sorted(whole)
        shown = ", ".join(json.dumps(k, ensure_ascii=True) for k in keys[:8]) + (", ..." if len(keys) > 8 else "")
        raise _NotRecognised(f"the file is a JSON object of another kind (members: {shown or 'none'})")
    if whole is not _NO_JSON:
        raise _NotRecognised("the file is " + _json_kind(whole))
    raise _NotRecognised(why_not_ledger)


def _json_kind(v) -> str:
    return {list: "a JSON array", str: "a JSON string", bool: "a JSON boolean", type(None): "JSON null",
            int: "a JSON number", float: "a JSON number", dict: "a JSON object"}.get(type(v), "a JSON value")


def verify_auto(path: str) -> dict:
    """Route the artefact to its verifier by the closed list of SPEC §12, or refuse it with the reason (v0.7: until
    then every file that was not AP2 or CLDMA went to the ledger verifier, and a JSON document of another kind was
    answered with json_decode errors per line)."""
    import stat
    try:
        mode = os.stat(path).st_mode
    except OSError as e:
        return _not_recognised(f"cannot read the path ({type(e).__name__}: {os.strerror(e.errno) if isinstance(e.errno, int) else e})")
    if stat.S_ISDIR(mode):
        try:
            os.listdir(path)
        except OSError as e:   # SPEC §12: a path that cannot be read; without this an unreadable pack "has no MANIFEST.json"
            return _not_recognised(f"cannot read the directory ({type(e).__name__}: {os.strerror(e.errno) if isinstance(e.errno, int) else e})")
        if os.path.exists(os.path.join(path, "MANIFEST.json")):
            return verify_pack(path)
        import glob
        if glob.glob(os.path.join(glob.escape(path), "*.head.json")) or glob.glob(os.path.join(glob.escape(path), "*-*.jsonl")):
            return verify_archive(path)
        try:
            tile_dir = stat.S_ISDIR(os.lstat(os.path.join(path, "tile")).st_mode)
        except OSError:
            tile_dir = False
        if tile_dir:
            return _c2sp_tiles(path)
        return _not_recognised("a directory with neither MANIFEST.json (evidence pack) nor *.head.json / *-*.jsonl "
                               "(ingest archive) nor a directory tile (C2SP tiled log)")
    if not stat.S_ISREG(mode):
        return _not_recognised("neither a directory nor a regular file (for a pipe use `cryptovalid-verify ledger`)")
    found = {}
    try:
        fmt = _file_format(path, found)
    except _NotRecognised as e:
        return _not_recognised(str(e))
    except OSError as e:
        return _not_recognised(f"cannot read the file ({type(e).__name__}: {os.strerror(e.errno) if isinstance(e.errno, int) else e})")
    if fmt == "checkpoint":
        cp = found["checkpoint"]
        return _rollup("checkpoint", [_check("auto.checkpoint", "SKIP", (
            f"C2SP checkpoint (origin {json.dumps(cp['origin'], ensure_ascii=False)}, size {cp['size']}): auto holds no "
            f"trusted key and verifies nothing; run: cryptovalid-verify checkpoint {_quote(path)} --vkey <vkey of the log>"))])
    return {"ap2": verify_ap2, "cldma": verify_cldma, "ledger": verify_ledger}[fmt](path)


def _quote(path: str) -> str:
    """the path as the named command reads it: shell-quoted, and "./" before a relative path that starts with "-" (the
    command's parser would take it for an option)"""
    import shlex
    return shlex.quote(os.path.join(".", path) if path.startswith("-") else path)


def _c2sp_tiles(path: str) -> dict:
    """SPEC §12, row C2SP tiled log: the command that verifies it, which needs a trusted key and the profile"""
    import stat
    cp = os.path.join(path, "checkpoint")
    try:
        has_cp = stat.S_ISREG(os.stat(cp).st_mode)
    except OSError:
        has_cp = False
    cmd = f"cryptovalid-verify tiles {_quote(path)} --vkey <vkey of the log> --profile <static-ct-api or tlog-tiles>"
    if not has_cp:
        cmd += " --checkpoint <checkpoint file>"
    return _rollup("tiles", [_check("auto.tiles", "SKIP", "C2SP tiled log (directory tile): auto holds no trusted key and "
                                                       f"verifies nothing; run: {cmd}")])


def _rollup(kind: str, layers: list) -> dict:
    checked = [x for x in layers if x["status"] in ("PASS", "FAIL")]
    valid = bool(checked) and all(x["status"] == "PASS" for x in checked)
    return {"kind": kind, "valid": valid, "layers": layers,
            "verified_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "note": ("%d layers verified; %d not verifiable here (SKIP)"
                     % (len(checked), len(layers) - len(checked)))}


# ─────────────────────────────────────────────────── verification profile (SPEC v0.15 §23)

PROFILE_FORMAT = "cryptovalid-verify-profile/1"
PROFILE_LIMIT = 1 << 20   # SPEC §23 rule 2
_HEX64 = re.compile(r"[0-9a-f]{64}\Z")


class ProfileError(ValueError):
    """SPEC §23 rule 4: the profile is refused (exit 2); the message is the reason"""


def _v_true(v, where, _base):
    if v is not True:
        raise ProfileError(f"{where}: false turns nothing off (a profile only adds requirements)" if v is False
                           else f"{where}: must be true")
    return True


def _v_hex(v, where, _base):
    if not (isinstance(v, str) and _HEX64.match(v)):
        raise ProfileError(f"{where}: 64 lowercase hex characters")
    return v


def _v_pq(v, where, _base):
    import base64
    import binascii
    try:
        ok = isinstance(v, str) and len(base64.b64decode(v.encode("ascii"), validate=True)) == 1952
    except (ValueError, binascii.Error, UnicodeEncodeError):
        ok = False
    if not ok:
        raise ProfileError(f"{where}: strict base64 of a 1952-byte ML-DSA-65 public key")
    return v


def _v_instant(v, where, _base):
    import cryptovalid_tip
    try:
        cryptovalid_tip.parse_instant(v)
    except ValueError:
        raise ProfileError(f"{where}: an instant YYYY-MM-DDThh:mm:ss[.f](Z|±hh:mm)") from None
    return v


def _v_files(load):
    def check(v, where, base):
        if not (isinstance(v, list) and v and all(isinstance(x, str) and x for x in v)):
            raise ProfileError(f"{where}: a non-empty array of paths")
        if len(set(v)) != len(v):
            raise ProfileError(f"{where}: a path written twice")
        import cryptovalid_tsa
        out = []
        for x in v:
            try:
                # read ONCE (relative paths: from the profile's directory): the bytes checked here are the bytes the
                # receipt names by their SHA-256 and the bytes every run is given (SPEC §23 rules 2 and 5)
                data = cryptovalid_tsa._read_pin(os.path.join(base, x), where.rsplit(".", 1)[-1])
                out.append(data)
                load(data)
            except ImportError:   # the CRL parser needs cryptography: then the run decides (SPEC §23 rule 3)
                pass
            except (ValueError, OSError) as e:
                raise ProfileError(f"{where}: {str(e)[:200]}") from None
        return out
    return check


def _load_certs(data):
    import cryptovalid_tsa
    cryptovalid_tsa._pem_certs([data])


def _load_crl(data):
    import cryptovalid_tsa
    cryptovalid_tsa._load_crls([data])


# SPEC §23 rule 2: THE table of the requirements a profile may add. (kind, member) -> (keyword argument of the reference
# verifier, value check, members it needs, norm). The profile reader accepts these members and no other; `--list-checks`
# prints them. No `require_tip`: alone it can only fail (a tip is checked only with a trusted log key, §17), and
# `log_key` already makes the tip required (§22 rule 1).
REQUIREMENTS = {
    ("ledger", "log_key"): ("trusted_pubkey_hex", _v_hex, (), "SPEC §22 rule 1"),
    ("ledger", "log_pq_key"): ("trusted_pq_pubkey_b64", _v_pq, ("log_key",), "SPEC §17, §15"),
    ("ledger", "tip_not_before"): ("tip_not_before", _v_instant, ("log_key",), "SPEC §17 rule 2"),
    ("ledger", "ledger_id"): ("expect_ledger_id", _v_hex, (), "SPEC §17 rule 1"),
    ("pack", "manifest_signer"): ("manifest_signer_hex", _v_hex, (), "SPEC §10"),
    ("pack", "ledger_signer"): ("signer_pubkey_hex", _v_hex, (), "SPEC §5 step 5, §10"),
    ("pack", "ledger_pq_key"): ("pq_pubkey_b64", _v_pq, ("ledger_signer",), "SPEC §10, §15"),
    ("pack", "tsa_certs"): ("tsa_certs", _v_files(_load_certs), (), "SPEC §10, §11, §22 rule 7; RFC 3161"),
    ("pack", "tsa_crls"): ("tsa_crls", _v_files(_load_crl), ("tsa_certs",), "SPEC §11 step 8; RFC 5280"),
    ("pack", "signature_domain"): ("require_signature_domain", _v_true, (), "SPEC §22 rule 3"),
    ("archive", "head_key"): ("expected_pubkey_hex", _v_hex, (), "SPEC §17 rule 4, §20 rule 8"),
    ("archive", "tsa_certs"): ("tsa_certs", _v_files(_load_certs), (), "SPEC §11, §22 rule 7; RFC 3161"),
    ("archive", "signature_domain"): ("require_signature_domain", _v_true, (), "SPEC §22 rule 3"),
}
_PROFILE_KINDS = ("ledger", "pack", "archive")


def _no_duplicates(pairs):
    keys = [k for k, _ in pairs]
    if len(set(keys)) != len(keys):
        raise ProfileError("a key written twice in one object: " + json.dumps(sorted({k for k in keys if keys.count(k) > 1})[0]))
    return dict(pairs)


def _no_constant(c):
    raise ProfileError(f"{c} is not a JSON number")


def _closed(obj, allowed, where):
    if not isinstance(obj, dict):
        raise ProfileError(f"{where}: must be a JSON object")
    extra = sorted(set(obj) - set(allowed))
    if extra:
        raise ProfileError(f"{where}: unknown member {json.dumps(extra[0], ensure_ascii=True)} (allowed: {', '.join(allowed)})")


def load_profile(path: str) -> dict:
    """SPEC §23 rule 2: the profile at `path`, read and checked whole; ProfileError with the reason otherwise.
    Returns {"profile_format", "name", "sha256", "require": {kind: {member: value as checked}}}"""
    import hashlib
    import unicodedata
    _need_opencore()
    import verifier
    try:
        raw = verifier.read_regular(path, PROFILE_LIMIT)
    except verifier.InputTooLarge:
        raise ProfileError(f"larger than {PROFILE_LIMIT} bytes") from None
    except (OSError, ValueError) as e:   # InputNotRegular is an OSError or ValueError there
        raise ProfileError(f"cannot read it ({type(e).__name__}: {os.strerror(e.errno) if isinstance(getattr(e, 'errno', None), int) else e})") from None
    if raw.startswith(b"\xef\xbb\xbf"):
        raise ProfileError("starts with a UTF-8 byte order mark")
    try:
        doc = json.loads(raw.decode("utf-8"), object_pairs_hook=_no_duplicates, parse_constant=_no_constant)
    except UnicodeDecodeError as e:
        raise ProfileError(f"not UTF-8 (byte {e.start})") from None
    except RecursionError:
        raise ProfileError("JSON nested deeper than the parser allows") from None
    except ProfileError:
        raise
    except ValueError as e:
        raise ProfileError(f"not JSON ({e})") from None
    _closed(doc, ("profile_format", "name", "require"), "the profile")
    for k in ("profile_format", "name", "require"):
        if k not in doc:
            raise ProfileError(f"the profile: missing member {k}")
    if doc["profile_format"] != PROFILE_FORMAT:
        raise ProfileError(f"profile_format: must be {json.dumps(PROFILE_FORMAT)}")
    name = doc["name"]
    if not (isinstance(name, str) and 1 <= len(name) <= 200
            and not any(unicodedata.category(c) in ("Cc", "Cs") for c in name)):
        raise ProfileError("name: a string of 1 to 200 characters without control characters")
    req = doc["require"]
    _closed(req, _PROFILE_KINDS, "require")
    if not req:
        raise ProfileError("require: the profile requires nothing (name at least one requirement)")
    base = os.path.dirname(os.path.abspath(path))
    out, files = {}, []
    for kind in _PROFILE_KINDS:
        if kind not in req:
            continue
        sec = req[kind]
        members = [m for (k, m) in REQUIREMENTS if k == kind]
        _closed(sec, members, f"require.{kind}")
        if not sec:
            raise ProfileError(f"require.{kind}: empty (name at least one requirement or leave the section out)")
        out[kind] = {}
        for m in members:
            if m in sec:
                _param, check, needs, _norm = REQUIREMENTS[(kind, m)]
                for n in needs:
                    if n not in sec:
                        raise ProfileError(f"require.{kind}.{m}: needs require.{kind}.{n}")
                val = out[kind][m] = check(sec[m], f"require.{kind}.{m}", base)
                if isinstance(val, list):   # rule 5: the files the profile names, by the bytes read
                    files += [{"requirement": f"{kind}.require.{m}", "path": p, "sha256": hashlib.sha256(b).hexdigest()}
                              for p, b in zip(sec[m], val)]
    return {"profile_format": PROFILE_FORMAT, "name": name, "sha256": hashlib.sha256(raw).hexdigest(), "require": out,
            "files": files}


def _profile_head(prof: dict, kind) -> dict:
    return {"profile_format": prof["profile_format"], "name": prof["name"], "sha256": prof["sha256"],
            "files": prof["files"], "applies_to": kind}


_VERIFY_BY_KIND = {"ledger": "verify_ledger", "pack": "verify_pack", "archive": "verify_archive"}


def _run_state(kind: str, path: str, pins: dict):
    """SPEC §23 rule 3 (b)/(c): (state, detail) of the verification of `kind` with `pins`"""
    from verifier import CheckNotRun
    try:
        r = globals()[_VERIFY_BY_KIND[kind]](path, **pins)
    except CheckNotRun as e:
        return "not_evaluated", f"a check could not run here: {str(e)[:200]}"
    if r["valid"]:
        return "met", ""
    failed = [f"{x['id']}: {x['detail']}" if x.get("detail") else x["id"] for x in r["layers"] if x["status"] == "FAIL"]
    return "not_met", "; ".join(failed)[:400] or "no layer verified"


FINGERPRINT_LIMIT = 1 << 20   # SPEC §23 rule 3 (d): entries walked at most; past it the evidence counts as changed


def evidence_fingerprint(path: str):
    """SPEC §23 rule 3 (d): of the path and, for a directory, of every entry under it: what lstat says (device, inode,
    type and mode, size, mtime and ctime in nanoseconds); for a symbolic link also what stat says of what it names (the
    runs follow links); and the SHA-256 of the bytes of every regular file (timestamps move in ticks: a file rewritten
    in the tick of its last change keeps them). A file replaced, rewritten or renamed between two readings changes it.
    None when it cannot be taken (then the evidence counts as changed): an entry that cannot be read, a link below the
    path that names a directory (the walk does not follow it, a run may), more entries than the limit."""
    import hashlib
    import stat

    def what(s):
        return (s.st_dev, s.st_ino, s.st_mode, s.st_size, s.st_mtime_ns, s.st_ctime_ns)

    def one(p, rel):
        s = os.lstat(p)
        row = (rel,) + what(s)
        if stat.S_ISLNK(s.st_mode):
            s = os.stat(p)
            if rel != "." and stat.S_ISDIR(s.st_mode):
                raise OSError(f"{p}: a link to a directory")
            row += what(s)
        if stat.S_ISREG(s.st_mode):
            h = hashlib.sha256()
            with os.fdopen(_open_regular(p), "rb") as f:
                for block in iter(lambda: f.read(1 << 20), b""):
                    h.update(block)
            row += (h.hexdigest(),)
        return row, stat.S_ISDIR(s.st_mode)
    try:
        row, is_dir = one(path, ".")
        out = [row]
        if is_dir:
            def fail(e):
                raise e
            for d, dirs, files in os.walk(path, onerror=fail, followlinks=False):
                for n in dirs + files:
                    p = os.path.join(d, n)
                    out.append(one(p, os.path.relpath(p, path))[0])
                    if len(out) > FINGERPRINT_LIMIT:
                        return None
        return tuple(sorted(out))
    except OSError:
        return None


def apply_profile(r: dict, path: str, prof: dict, before=None) -> dict:
    """SPEC §23 rules 3 and 5: `r` is the receipt of the verification without a profile (a), unchanged but for `valid`
    and `profile`; `before` is evidence_fingerprint(path) taken before (a)"""
    kind = r.get("kind")
    sec = prof["require"].get(kind) if kind in _PROFILE_KINDS else None
    head = _profile_head(prof, kind)
    if not sec:
        r["profile"] = dict(head, requirements=[], together=None, evidence_unchanged=None, outcome="not_applicable")
        r["valid"] = False
        return r
    # rule 3: (b) and (c) read the evidence again. A ledger given as a pipe (read once by (a)) would give no bytes,
    # or other bytes: no requirement is run on it
    again = ("the ledger is not a regular file: a requirement reads it again (SPEC §23 rule 3)"
             if kind == "ledger" and os.path.exists(path) and not os.path.isfile(path) else None)
    pins_of = {m: {REQUIREMENTS[(kind, m)][0]: v} for m, v in sec.items()}
    reqs = []
    for m in sec:
        pins = dict(pins_of[m])
        for n in REQUIREMENTS[(kind, m)][2]:
            pins.update(pins_of[n])
        state, detail = ("not_evaluated", again) if again else _run_state(kind, path, pins)
        reqs.append({"id": f"{kind}.require.{m}", "state": state, "detail": detail})
    together = None
    if len(sec) > 1:
        allpins = {}
        for p in pins_of.values():
            allpins.update(p)
        together = "not_evaluated" if again else _run_state(kind, path, allpins)[0]
    states = [x["state"] for x in reqs] + ([together] if together else [])
    outcome = "met" if all(s == "met" for s in states) else ("not_met" if "not_met" in states else "not_evaluated")
    # rule 3 (d): (a), (b) and (c) read the path more than once; if what is at the path changed in between, their
    # results may be about different bytes, so none of them decides
    stable = before is not None and evidence_fingerprint(path) == before
    if not stable:
        outcome = "not_evaluated"
    r["profile"] = dict(head, requirements=reqs, together=together, evidence_unchanged=stable, outcome=outcome)
    r["valid"] = bool(r["valid"]) and outcome == "met"
    return r


def list_checks(command=None) -> list:
    """SPEC §23 rule 1: the checks of `command` (all when None), from CHECKS and REQUIREMENTS"""
    out = []
    for cid, (layer, cmds, when, norm) in CHECKS.items():
        if command is None or command in cmds:
            out.append({"id": cid, "layer": layer, "commands": list(cmds), "required": "always", "enabled_by": None,
                        "when": when, "norm": norm})
    for (kind, m), (_param, _check_fn, needs, norm) in REQUIREMENTS.items():
        cmds = (kind,) + _ROUTED
        if command is None or command in cmds:
            out.append({"id": f"{kind}.require.{m}", "layer": None, "commands": list(cmds), "required": "profile",
                        "enabled_by": f"--profile: require.{kind}.{m}", "when": "needs " + ", ".join(
                            f"require.{kind}.{n}" for n in needs) if needs else "", "norm": norm})
    for cmd, where in _OWN_CHECKS.items():
        if command is None or command == cmd:
            out.append({"id": cmd, "layer": None, "commands": [cmd], "required": "always", "enabled_by": None,
                        "when": "checks run by its own module, not listed here", "norm": where})
    return out


def _list_checks_main(args) -> int:
    from verifier import Parser, receipt_not_written, write_stdout
    p = Parser(prog=PROG + " --list-checks", description="Print the checks of cryptovalid-verify (SPEC §23 rule 1).")
    p.add_argument("command", nargs="?", choices=list(_COMMANDS), help="only the checks this command runs")
    p.add_argument("--format", choices=("text", "json"), default="text")
    a = p.parse_args(args)
    rows = list_checks(a.command)
    if a.format == "json":
        text = json.dumps({"list_format": "cryptovalid-verify-checks/1", "checks": rows}, ensure_ascii=False, indent=1)
    else:
        text = "\n".join(f"{x['id']}  [{x['required']}]  {', '.join(x['commands'])}  {x['norm']}"
                         + (f"\n    {x['enabled_by']}" if x["enabled_by"] else "")
                         + (f"\n    {x['when']}" if x["when"] else "") for x in rows)
    why = write_stdout(text)
    return receipt_not_written(why) if why is not None else 0


_COMMANDS = {
    "auto": "recognise the path by the closed list of SPEC §12 and verify it with the command below\n"
            "               that fits; anything else is refused as 'format not recognised', with the reason",
    "pack": "evidence pack directory (evidence_pack.py)",
    "archive": "ingest archive directory: segments, Merkle STH, signed HEAD (experimental)",
    "ledger": "hash chain of a .jsonl ledger only",
    "ap2": "AP2 SD-JWT mandate evidence, through ap2-evidence-pack (experimental)",
    "cldma": "CLDMA committed attestation (experimental)",
    "checkpoint": "C2SP checkpoint or signed note, verified against trusted vkeys (SPEC §13; options: --help)",
    "tiles": "C2SP tiles of a log directory, with its checkpoint (SPEC §14; options: --help)",
    "vkey-rfc6962": "print the vkey (type 0x05) of a static CT log from its public key (SPEC §13)",
    "beacon": "a 'not before' bound from the NIST Randomness Beacon inside a payment entry, and its window\n"
              "               with an evidence pack's RFC 3161 token (SPEC §18-§19; options: --help)",
}
# SPEC §13-§14: the commands of cryptovalid_checkpoint.py, run by its own code (cryptovalid-verify name -> its command)
_C2SP_COMMANDS = {"checkpoint": "verify", "tiles": "tiles", "vkey-rfc6962": "vkey-rfc6962"}
_COMMANDS_HELP = ("commands:\n" + "".join(f"  {k:<12} {v}\n" for k, v in _COMMANDS.items())
                  + "\nexit status: 0 the evidence is valid for what could be checked here, 1 it is not, 2 usage error,\n"
                    "74 a check could not run here (the receipt is written whole) or the receipt was not written whole\n"
                    "to stdout (whatever the verdict).")


# the name of the installed command (pyproject [project.scripts]); until 0.24.0 its help said "verify_evidence"
PROG = "cryptovalid-verify"


def main(argv=None) -> int:
    _need_opencore()
    from verifier import receipt_cli
    return receipt_cli(_main)(argv)


def _main(argv=None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if args and args[0] in _C2SP_COMMANDS:   # SPEC §13-§14, their own arguments and --help
        _need_opencore()
        import cryptovalid_checkpoint as C
        return C.main([_C2SP_COMMANDS[args[0]]] + args[1:], prog=PROG, cmd_name=args[0])
    if args and args[0] == "beacon":   # SPEC §19, its own arguments and --help
        _need_opencore()
        import cryptovalid_beacon as B
        return B.main(args[1:], prog=PROG, cmd_name="beacon")
    if args and args[0] == "--list-checks":   # SPEC §23 rule 1
        return _list_checks_main(args[1:])
    from verifier import Parser, VersionAction, _Once, receipt_not_written, write_stdout   # 0.20.3: the write rule of verifier.py
    p = Parser(prog=PROG, formatter_class=argparse.RawDescriptionHelpFormatter,
               description="One offline verifier for every kind of CryptoValid evidence.",
               epilog=_COMMANDS_HELP)
    p.add_argument("cmd", choices=list(_COMMANDS), help="what the path holds (see the commands below)")
    p.add_argument("path", help="file or directory to verify")
    p.add_argument("--version", action=VersionAction)
    p.add_argument("--profile", action=_Once, metavar="FILE",
                   help="a verification profile (SPEC §23): requirements added to the checks, never removed; "
                        "see --list-checks")
    a = p.parse_args(sys.argv[1:] if argv is None else argv)
    if a.cmd in _C2SP_COMMANDS or a.cmd == "beacon":   # reached only when it is not the first argument (e.g. after "--"): a usage error, not a traceback
        p.error(f"{a.cmd} takes its own options and must come first: cryptovalid-verify {a.cmd} --help")
    prof = None
    if a.profile is not None:   # SPEC §23 rule 4: refused before anything is verified, exit 2
        if a.cmd not in ("auto",) + _PROFILE_KINDS:
            p.error(f"--profile: no requirement is defined for {a.cmd} (SPEC §23)")
        try:
            prof = load_profile(a.profile)
        except ProfileError as e:
            p.error(f"--profile refused: {e}")
    fn = {"auto": verify_auto, "pack": verify_pack, "archive": verify_archive,
          "ledger": verify_ledger, "ap2": verify_ap2, "cldma": verify_cldma}[a.cmd]
    from verifier import CheckNotRun, check_not_run_exit
    before = evidence_fingerprint(a.path) if prof is not None else None   # SPEC §23 rule 3 (d)
    try:
        r = fn(a.path)
    except CheckNotRun as e:   # 0.22.0: a check that could not run here, with the complete receipt: written whole, then 74
        if getattr(e, "receipt", None) is None:
            raise
        e.receipt["profile"] = "default" if prof is None else dict(   # SPEC §23 rule 5: no requirement run
            _profile_head(prof, e.receipt.get("kind")), requirements=[], together=None, evidence_unchanged=None,
            outcome="not_evaluated")
        if prof is not None:
            e.receipt["valid"] = False
        return check_not_run_exit(e, json.dumps(e.receipt, ensure_ascii=False, indent=1))
    if prof is None:
        r["profile"] = "default"   # SPEC §23 rule 5-6: the only change without a profile
    else:
        r = apply_profile(r, a.path, prof, before)
    why = write_stdout(json.dumps(r, ensure_ascii=False, indent=1))
    if why is not None:   # the receipt was not written whole: 74 (EX_IOERR), whatever `valid` says
        return receipt_not_written(why)
    return 0 if r["valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
