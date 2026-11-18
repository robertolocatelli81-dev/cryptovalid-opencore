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

Status: `auto`, `pack` and `ledger` are the maintained core; `archive`, `ap2` and `cldma` are EXPERIMENTAL
(README, "Core and experimental modules"): kept and tested, no new scope is added to them.

Exits 0 if the evidence is valid for what could be verified, 1 otherwise; 74 if the receipt was not written whole to
stdout (full, closed, no reader), whatever the verdict (0.20.3).
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
            if isinstance(r.get("failure_classes"), dict):
                layer["failure_classes"] = r["failure_classes"]
                layer["detail"] += "; " + _ledger_classes(r)
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
    layers = [_layer("file digests == manifest", "PASS" if r.get("files_ok") else "FAIL"),
              _layer("manifest auto-consistente", "PASS" if r.get("manifest_ok") else "FAIL")]
    auth = r.get("manifest_authenticated")
    try:
        # SPEC §5 step 0: opened once without blocking (a FIFO as MANIFEST.json blocked here until 0.26.0)
        with os.fdopen(_open_regular(os.path.join(pack_dir, "MANIFEST.json")), encoding="utf-8") as fh:
            sig_present = bool(json.load(fh).get("manifest_signature"))
    except (OSError, ValueError, AttributeError):
        sig_present = False
    # a manifest signature that is PRESENT but does not verify is tampering, never "unsigned" (audit V1 #1, 30/09/2026)
    layers.append(_layer("manifest autenticato (Ed25519)",
                         "PASS" if auth else ("FAIL" if sig_present else "SKIP"),
                         "signed" if auth else ("signature present but NOT valid" if sig_present
                                                 else "not signed, or cryptography absent")))
    layers.append(_layer("ledger: hash+firma+anti-troncamento", "PASS" if r.get("ledgers_ok") else "FAIL"))
    rfc = r.get("rfc3161") or {}
    ta = (r.get("states") or {}).get("time_anchor") or {}
    if rfc.get("claimed"):
        v = rfc.get("verified")
        # 0.22.0: the reference's time_anchor decides FAIL (contradicted: token missing, invalid, another digest) vs SKIP
        layers.append(_layer("RFC 3161 timestamp",
                             "PASS" if v is True else ("FAIL" if ta.get("state") == "contradicted" or v is False else "SKIP"),
                             "" if v is True else str(ta.get("detail") or rfc.get("note") or "openssl absent")))
    else:
        layers.append(_layer("RFC 3161 timestamp", "SKIP", "no timestamp in the pack"))
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
                                       "opencore/ not found: the full check needs the repository")])
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
        return _rollup("archive", [_layer("archive", "SKIP", "opencore/ not found")])
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
                             "" if prod.get("ok") else "signature present but NOT valid"))
    if r.get("self_asserted_only"):
        layers.append(_layer("provenienza chiavi", "SKIP",
                             "self-asserted jwk only: the signature proves consistency, not identity"))
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
        return _rollup("ap2", [_layer("ap2 evidence", "SKIP", "opencore/ not found")])
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
        return _rollup("cldma", [_layer("cldma", "SKIP", "opencore/ not found")])
    try:
        import committed_attestation as cldma
        import verifier
        # SPEC §5 step 0 (v0.11): opened once without blocking, bounded (a FIFO here hung until 0.26.0)
        att = json.loads(verifier.read_regular(path, _AUTO_JSON_LIMIT).decode("utf-8"))
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
    return _rollup("auto", [_layer("auto-detect", "FAIL", f"format not recognised: {why}; recognised: {_RECOGNISED}")])


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
        return _not_recognised(f"cannot read the path ({type(e).__name__}: {e.strerror or e})")
    if stat.S_ISDIR(mode):
        try:
            os.listdir(path)
        except OSError as e:   # SPEC §12: a path that cannot be read; without this an unreadable pack "has no MANIFEST.json"
            return _not_recognised(f"cannot read the directory ({type(e).__name__}: {e.strerror or e})")
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
        return _not_recognised(f"cannot read the file ({type(e).__name__}: {e.strerror or e})")
    if fmt == "checkpoint":
        cp = found["checkpoint"]
        return _rollup("checkpoint", [_layer("checkpoint", "SKIP", (
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
    return _rollup("tiles", [_layer("tiles", "SKIP", "C2SP tiled log (directory tile): auto holds no trusted key and "
                                                       f"verifies nothing; run: {cmd}")])


def _rollup(kind: str, layers: list) -> dict:
    checked = [x for x in layers if x["status"] in ("PASS", "FAIL")]
    valid = bool(checked) and all(x["status"] == "PASS" for x in checked)
    return {"kind": kind, "valid": valid, "layers": layers,
            "verified_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "note": ("%d layers verified; %d not verifiable here (SKIP)"
                     % (len(checked), len(layers) - len(checked)))}


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
                    "74 the receipt was not written whole to stdout (whatever the verdict).")


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
    from verifier import Parser, VersionAction, receipt_not_written, write_stdout   # 0.20.3: the write rule of verifier.py
    p = Parser(prog=PROG, formatter_class=argparse.RawDescriptionHelpFormatter,
               description="One offline verifier for every kind of CryptoValid evidence.",
               epilog=_COMMANDS_HELP)
    p.add_argument("cmd", choices=list(_COMMANDS), help="what the path holds (see the commands below)")
    p.add_argument("path", help="file or directory to verify")
    p.add_argument("--version", action=VersionAction)
    a = p.parse_args(sys.argv[1:] if argv is None else argv)
    if a.cmd in _C2SP_COMMANDS or a.cmd == "beacon":   # reached only when it is not the first argument (e.g. after "--"): a usage error, not a traceback
        p.error(f"{a.cmd} takes its own options and must come first: cryptovalid-verify {a.cmd} --help")
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
