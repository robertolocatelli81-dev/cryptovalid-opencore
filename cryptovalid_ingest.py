#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CryptoValid Open Core — high-frequency ingestion into court-admissible evidence.

Status: EXPERIMENTAL. Outside the maintained core of cryptovalid-opencore (README, "Core and experimental
modules"): kept, installed and tested, no new scope is added here.

SPDX-License-Identifier: AGPL-3.0-or-later
Copyright (C) 2026 Roberto Locatelli

Turns a high-rate event stream (EU AI Act Art. 12 automatic logs, telemetry, decision
records) into the CryptoValid evidence format WITHOUT changing it: every segment this
module writes is a plain hash-chained JSONL ledger that `verifier.py` (stdlib-only)
verifies unchanged, and every sealed segment gets an RFC 6962 Merkle **Signed Tree
Head** sidecar (`cryptovalid_merkle`) so a single O(log n) inclusion proof replaces
re-reading millions of rows.

Design (honest, minimal):
  - **Segments**: `<prefix>-NNNNNN.jsonl`, each independently verifiable (idx from 0,
    genesis prev_hash) — an auditor needs one file, not the whole archive.
  - **STH chain + HEAD manifest**: sealing a segment writes `<segment>.sth.json` with
    the RFC 6962 root and `prev_sth_sha256` (hash-chain ACROSS segments: removing or
    reordering *interior* segments is detectable), plus an archive **HEAD manifest**
    (`<prefix>.head.json`, rewritten at every seal) committing to the segment COUNT and
    the last STH — because a bare STH chain, like any bare hash chain, cannot detect
    truncation or forged extension of its own TAIL. Honest scope: the HEAD closes the
    tail gap only if it is **Ed25519-signed** (any `cryptovalid_kms` backend:
    file/PKCS#11 HSM/AWS KMS/Vault) and the verifier pins the public key — an unsigned
    HEAD can be rewritten by whoever rewrites the archive. For third-party-proof time,
    anchor the HEAD hash (or last STH root) via RFC 3161 (`cryptovalid_tsa`),
    qualified per eIDAS via `cryptovalid_lotl`.
  - **Batched fsync**: entries are buffered and fsync'd per batch — the throughput
    lever is the batch, the durability unit is the flush. An entry is DURABLE only
    after `flush()` returned (callers needing per-event durability use batch_size=1).
  - **Crash recovery, fail-closed**: on reopen, a torn trailing line (crash mid-write)
    is truncated and REPORTED (`recovered_bytes`); it can only be an entry whose
    flush() never returned. Sealed segments are never reopened.

Honest limits: timestamps come from the HOST clock (pair the STH with RFC 3161 for
independent time); ingestion proves *what/when-order/non-alteration*, not the truth
of the events; throughput numbers are MEASURED by `test_ingest.py`/`bench` on the
machine at hand, never quoted from this docstring.
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
import glob
import hashlib
import json
import os
import sys
import threading
import time
from datetime import datetime, timezone
from typing import Dict, List, Optional

import cryptovalid_merkle as merkle

GENESIS_PREV = "0" * 64


def _canonical(d: Dict) -> bytes:
    return json.dumps(d, sort_keys=True, separators=(",", ":")).encode()


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _sth_canonical_hash(sth: Dict) -> str:
    body = {k: v for k, v in sth.items() if k not in ("signature", "signer")}
    return hashlib.sha256(_canonical(body)).hexdigest()


def _fsync_dir(path: str):
    """fsync della DIRECTORY: senza, la voce di directory di un file appena creato
    può non sopravvivere a un crash anche se il suo contenuto è fsync'd."""
    fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _write_json_atomic(path: str, doc: Dict):
    write_output(path, json.dumps(doc, indent=1))   # 0.20.3: random O_EXCL temporary (was <path>.tmp), fsync, rename
    _fsync_dir(os.path.dirname(path) or ".")


def _write_bytes_atomic(path: str, data: bytes):
    write_output(path, data)   # 0.20.3: random O_EXCL temporary (was <path>.tmp), fsync, rename
    _fsync_dir(os.path.dirname(path) or ".")


def _default_lotl_cache(member_states) -> str:
    """Cache LOTL FUORI dall'archivio: una cache co-locata coi dati non fidati è
    avvelenabile da chi scrive nella dir (fingerprint finti -> qualified finto —
    trovato dalla review avversariale). ~/.cache è del VERIFICATORE, non dell'archivio."""
    tag = "-".join(sorted(m.upper() for m in member_states)) if member_states else "all"
    d = os.path.join(os.path.expanduser("~"), ".cache", "cryptovalid")
    os.makedirs(d, exist_ok=True)
    return os.path.join(d, f"lotl_{tag}.json")


class Ingestor:
    """Append-only, thread-safe, batched writer of CryptoValid evidence segments."""

    def __init__(self, directory: str, prefix: str = "ledger", batch_size: int = 256,
                 rotate_entries: int = 100_000, fsync: bool = True, backend=None,
                 tsa_url: Optional[str] = None, lotl_check: bool = False,
                 lotl_member_states=None, tip_keyfile: Optional[str] = None):
        """`tsa_url`: se impostato, ogni seal() ancora l'STH con un timestamp RFC 3161
        LIVE (token in `<segmento>.sth.tsr` + metadata `.sth.tsr.json`). `lotl_check`:
        certifica anche il token come eIDAS-qualified contro le EU Trusted Lists
        (rete; cache in `<prefix>.lotl_cache.json`). L'ancoraggio è BEST-EFFORT:
        un errore TSA/LOTL non blocca mai l'ingestione né tocca l'integrità — resta
        registrato nei metadata e in `last_anchor_error` (l'onestà sta nel receipt,
        il fail-closed sta nella verifica: un token presente ma non legato al digest
        FALLISCE verify_archive)."""
        if batch_size < 1 or rotate_entries < 1:
            raise ValueError("batch_size and rotate_entries must be >= 1")
        self._dir, self._prefix = directory, prefix
        self._batch, self._rotate, self._fsync = batch_size, rotate_entries, fsync
        self._backend = backend
        self._tsa_url, self._lotl_check = tsa_url, lotl_check
        self._lotl_ms = lotl_member_states
        self._request_timestamp = None    # iniettabile nei test; default: cryptovalid_tsa
        self.last_anchor_error: Optional[str] = None
        # Signed chain tip (15/09/2026, council: «the production writer does not maintain the tip»): with a
        # log key, every flush() also writes `<segment>.tip.json` (O(1): entries + first/last self_hash are
        # already known here) under the same lock — a snapshot verifier then sees tail truncation, suffix
        # rewrite and unsealed appends of the ACTIVE segment (sealed segments have their STH).
        self._tip_key = None
        if tip_keyfile:
            import cryptovalid_tip
            self._tip_key = cryptovalid_tip.load_key(tip_keyfile)   # loaded ONCE, not at every flush
        self._first = GENESIS_PREV        # self_hash of entry 0 of the active segment = the chain's identity
        self._lock = threading.RLock()
        self._buf: List[str] = []
        self._fh = None
        self.recovered_bytes = 0          # torn-tail bytes truncated on reopen (0 = clean)
        os.makedirs(directory, exist_ok=True)
        self._open_or_resume()

    # ── segment bookkeeping ──────────────────────────────────────────────────
    def _seg_path(self, seq: int) -> str:
        return os.path.join(self._dir, f"{self._prefix}-{seq:06d}.jsonl")

    def _segments(self) -> List[str]:
        return sorted(glob.glob(os.path.join(self._dir, f"{self._prefix}-[0-9]*.jsonl")))

    def _open_or_resume(self):
        segs = self._segments()
        if segs and not os.path.exists(segs[-1] + ".sth.json"):
            self._seq = int(os.path.basename(segs[-1]).rsplit("-", 1)[1].split(".")[0])
            self._resume(segs[-1])
        else:
            self._seq = (int(os.path.basename(segs[-1]).rsplit("-", 1)[1].split(".")[0]) + 1
                         if segs else 0)
            self._idx, self._prev, self._first = 0, GENESIS_PREV, GENESIS_PREV
        self._fh = open(self._seg_path(self._seq), "ab")
        _fsync_dir(self._dir)                     # la voce di directory del nuovo segmento

    def _resume(self, path: str):
        """Fail-closed recovery: keep every complete line, truncate a torn tail (it can
        only be an un-acknowledged write: flush() had not returned), resume the chain."""
        good_end, self._idx, self._prev, self._first = 0, 0, GENESIS_PREV, GENESIS_PREV
        with open(path, "rb") as f:
            for line in f:
                if not line.endswith(b"\n"):
                    break                                     # torn tail
                if not line.strip():                          # riga vuota: come verifier.py
                    good_end += len(line)
                    continue
                try:
                    e = json.loads(line)
                except json.JSONDecodeError:
                    break                                     # torn/corrupt tail
                # the attestation fields of SPEC §3 (the verifiers' list): until 0.20.2 only the first three were
                # left out here, so a segment carrying signature_pq/signer_pq or tsa_token was refused as tampered
                body = {k: v for k, v in e.items()
                        if k not in ("self_hash", "signature", "signer", "signature_pq", "signer_pq", "tsa_token")}
                recomputed = hashlib.sha256(_canonical(body)).hexdigest()
                if (e.get("idx") != self._idx or e.get("prev_hash") != self._prev
                        or e.get("self_hash") != recomputed):
                    raise ValueError(f"{path}: broken/tampered chain at idx {self._idx} — "
                                     "refusing to resume (run the verifier on it)")
                good_end += len(line)
                if self._idx == 0:
                    self._first = e["self_hash"]
                self._idx += 1
                self._prev = e["self_hash"]
        size = os.path.getsize(path)
        if size > good_end:
            self.recovered_bytes = size - good_end
            with open(path, "ab") as f:
                f.truncate(good_end)

    # ── ingestion ────────────────────────────────────────────────────────────
    def append(self, data: Dict) -> Dict:
        """Queue one event. Returns {segment, idx}. Durable only after flush()."""
        with self._lock:
            e = {"idx": self._idx, "ts": _utc_now(), "data": data, "prev_hash": self._prev}
            e["self_hash"] = hashlib.sha256(_canonical(e)).hexdigest()
            self._buf.append(json.dumps(e, sort_keys=True, separators=(",", ":")))
            if self._idx == 0:
                self._first = e["self_hash"]
            self._prev = e["self_hash"]
            self._idx += 1
            ref = {"segment": os.path.basename(self._seg_path(self._seq)), "idx": e["idx"]}
            if len(self._buf) >= self._batch:
                self.flush()
            due = self._idx >= self._rotate
        # rotazione FUORI dal lock di append: così l'ancora TSA del seal non blocca
        # mai gli altri append; min_entries evita seal duplicati da thread concorrenti
        if due:
            self.seal(min_entries=self._rotate)
        return ref

    def flush(self):
        with self._lock:
            if self._buf:
                # 0.20.3: the whole batch or nothing: unbuffered writes on the segment's descriptor, truncated back to the
                # bytes it had on a failure (the batch stays queued: a later flush() writes it whole, never after a torn part)
                append_line(self._seg_path(self._seq), ("\n".join(self._buf) + "\n").encode(), opened=self._fh, sync=self._fsync)
                self._buf.clear()
                if self._tip_key is not None:
                    import cryptovalid_tip
                    path = self._seg_path(self._seq)
                    cryptovalid_tip.write_tip(path + ".tip.json", self._tip_key, self._idx, self._first, self._prev)

    # ── sealing ──────────────────────────────────────────────────────────────
    def seal(self, min_entries: int = 1) -> Optional[Dict]:
        """Flush, write the STH sidecar (chained to the previous STH, signed if a
        backend is configured), and rotate to a fresh segment. No-op when the segment
        has fewer than `min_entries` entries (default: no-op only when empty)."""
        with self._lock:
            self.flush()
            if self._idx < max(1, min_entries):
                return None
            path = self._seg_path(self._seq)
            leaves = merkle.leaves_from_ledger(path)
            sth = merkle.tree_head(leaves)          # unsigned head (renamed 2026-09-13); signed just below when a backend is given
            sth.update({"segment": os.path.basename(path), "sealed_utc": _utc_now(),
                        "last_self_hash": self._prev,
                        "prev_sth_sha256": self._prev_sth_hash()})
            if self._backend is not None:
                import base64
                # stessa convenzione di signer.py: si firmano i byte della stringa hex
                sig = self._backend.sign(_sth_canonical_hash(sth).encode())
                sth["signature"] = base64.b64encode(sig).decode()
                sth["signer"] = self._backend.public_key_hex()
            _write_json_atomic(path + ".sth.json", sth)
            self._write_head(sth)
            self._fh.close()
            self._seq += 1
            self._idx, self._prev, self._first = 0, GENESIS_PREV, GENESIS_PREV
            self._fh = open(self._seg_path(self._seq), "ab")
            _fsync_dir(self._dir)
        # ancora TSA FUORI dal lock: una TSA lenta (fino a 30s) non deve mai
        # bloccare gli append concorrenti; l'STH è già sigillato e immutabile
        if self._tsa_url:
            self._anchor(path, sth)
        return sth

    def _anchor(self, seg_path: str, sth: Dict):
        """Timestamp RFC 3161 automatico dell'STH canonico (l'ancora di tempo TERZA).
        Best-effort: qualunque errore finisce nei metadata, mai sull'ingestione."""
        meta: Dict = {"tsa_url": self._tsa_url, "requested_utc": _utc_now(),
                      "sth_canonical_sha256": _sth_canonical_hash(sth)}
        try:
            import cryptovalid_tsa as tsa_mod
            with self._lock:
                if self._request_timestamp is None:
                    self._request_timestamp = tsa_mod.request_timestamp
            digest = bytes.fromhex(meta["sth_canonical_sha256"])
            granted, token, _ = self._request_timestamp(digest, self._tsa_url)
            meta["granted"] = bool(granted)
            # SPEC §11 (v0.6): the TSTInfo's messageImprint, not a search in the bytes; no pin here (verify pins)
            chk = tsa_mod.verify_token(token, digest, "sha256") if (granted and token) else None
            meta["digest_bound"] = bool(chk and chk["imprint_ok"])
            if chk:
                meta["token_status"] = chk["status"]
                if chk["reason"]:
                    meta["token_reason"] = chk["reason"]
                if chk["tst_info"]:
                    meta["gen_time"] = chk["tst_info"]["gen_time"]
            if token:
                _write_bytes_atomic(seg_path + ".sth.tsr", token)
                meta["token_file"] = os.path.basename(seg_path) + ".sth.tsr"
            if self._lotl_check and token:
                import cryptovalid_lotl as lotl
                fprs, _cov, herr = lotl.load_qualified_status(
                    self._lotl_ms, cache_path=_default_lotl_cache(self._lotl_ms))
                verdict, why = lotl.qualification(token, fprs, herr,
                                                  signer_sha256=(chk or {}).get("signer_sha256"))
                meta["eidas_qualified"] = verdict == "qualified"
                if why:   # 0.21.0: TS 119 615 PRO-4.3.4-03A, neither qualified nor not
                    meta["eidas_indeterminate"] = why
            with self._lock:
                self.last_anchor_error = None
        except Exception as e:  # noqa: BLE001 — l'ancora è best-effort, l'errore va nel receipt
            meta["error"] = f"{type(e).__name__}: {e}"[:300]
            with self._lock:
                self.last_anchor_error = meta["error"]
        _write_json_atomic(seg_path + ".sth.tsr.json", meta)

    def _write_head(self, last_sth: Dict):
        """HEAD manifest: impegna CONTEGGIO segmenti e ultimo STH — chiude il buco
        della coda (troncamento/estensione) che la sola catena STH non vede.
        Vale come protezione solo se FIRMATO e con pubblica pinnata dal verificatore."""
        sealed = [s for s in self._segments() if os.path.exists(s + ".sth.json")]
        head = {"prefix": self._prefix, "segments_sealed": len(sealed),
                "last_segment": last_sth["segment"],
                "last_sth_sha256": _sth_canonical_hash(last_sth),
                "updated_utc": _utc_now()}
        if self._backend is not None:
            import base64
            sig = self._backend.sign(_sth_canonical_hash(head).encode())
            head["signature"] = base64.b64encode(sig).decode()
            head["signer"] = self._backend.public_key_hex()
        _write_json_atomic(os.path.join(self._dir, f"{self._prefix}.head.json"), head)

    def _prev_sth_hash(self) -> str:
        prev = self._seg_path(self._seq - 1) + ".sth.json" if self._seq > 0 else None
        if prev and os.path.exists(prev):
            with open(prev, encoding="utf-8") as f:
                return _sth_canonical_hash(json.load(f))
        return GENESIS_PREV

    def close(self, seal: bool = True):
        """Seal (or only flush) and close the segment handle — also when seal()/flush() raise (a signing backend that
        fails, a full disk): the exception propagates, the handle does not stay open (0.17.1)."""
        with self._lock:
            try:
                if seal:
                    self.seal()
                else:
                    self.flush()
            finally:
                if self._fh and not self._fh.closed:
                    self._fh.close()


# ── auditor path (read-only) ─────────────────────────────────────────────────
def _check_signature(doc: Dict, expected_pubkey_hex) -> Optional[str]:
    """None se la firma del doc (STH o HEAD) è valida; altrimenti la ragione.
    expected_pubkey_hex: None, UNA chiave hex, o un ITERABILE di chiavi fidate —
    la rotazione delle chiavi (es. file→HSM) lascia in archivio segmenti firmati
    dalla chiave precedente: restano validi se quella chiave è nel set fidato."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    try:
        if expected_pubkey_hex:
            allowed = ({expected_pubkey_hex} if isinstance(expected_pubkey_hex, str)
                       else set(expected_pubkey_hex))
            if doc.get("signer") not in allowed:
                return "signer_mismatch"
        # 0.22.0: the signer as 64 lowercase hex, the signature as strict base64 of 64 bytes, and keys and R of small or
        # mixed order refused (ed25519_order, SPEC §5 step 5's rule; until 0.21.0 the neutral point with R neutral and
        # S = 0 was accepted for any tree head, measured 19/10/2026)
        try:
            import signer as _sg
        except ImportError:   # python3 -m opencore.<module> from the parent directory
            from opencore import signer as _sg
        pub, raw_sig = doc.get("signer"), _sg._b64_strict(doc.get("signature"), 64)
        if not (isinstance(pub, str) and _sg._HEX64.fullmatch(pub)) or raw_sig is None:
            return "signature_invalid"
        if _sg._edo().strict_problem(bytes.fromhex(pub), raw_sig) is not None:
            return "signature_invalid"
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub)).verify(raw_sig, _sth_canonical_hash(doc).encode())
        return None
    except Exception:
        return "signature_invalid"


def _load_json_object(path):
    """(object, None) or (None, reason): a file that is not UTF-8 JSON, or not a JSON object, is a named failure."""
    try:
        with open(path, encoding="utf-8") as f:
            obj = json.load(f)
    except (OSError, ValueError, RecursionError) as e:   # UnicodeDecodeError and JSONDecodeError are ValueError
        return None, type(e).__name__
    return (obj, None) if isinstance(obj, dict) else (None, "not_a_json_object")


# SPEC §11 reason → the failure reason of verify_archive (the names of 0.22.0 kept where they existed)
_TSA_FAILURE = {"imprint_mismatch": "tsa_token_digest_mismatch", "hash_algorithm_mismatch": "tsa_token_digest_mismatch",
                "signature_invalid": "tsa_token_cms_invalid", "malformed": "tsa_token_cms_invalid",
                "not_signed_data": "tsa_token_cms_invalid", "response_not_granted": "tsa_token_cms_invalid",
                "econtent_type_not_tstinfo": "tsa_token_not_tstinfo", "tstinfo_unknown_element": "tsa_token_not_tstinfo",
                "hash_algorithm_not_allowed": "tsa_token_hash_algorithm_not_allowed",
                "not_issued_by_pinned_tsa": "tsa_token_not_issued_by_pinned_tsa"}
_SIGNATURE_ONLY = "signature valid with the certificate contained in the token, chain not established"


def verify_archive(directory: str, prefix: str = "ledger",
                   expected_pubkey_hex=None,
                   lotl_check: bool = False, lotl_member_states=None, tsa_certs=None) -> Dict:
    """Third-party verification of a whole archive: every sealed segment's hash chain
    (verifier.py rules), Merkle root vs sidecar, STH chain across segments, the HEAD
    manifest (segment count + last STH — the tail-truncation guard), and signatures.
    Fail-closed on any mismatch; honest `warnings` for what is NOT protected:
    without a signed HEAD + pinned pubkey, tail removal/extension is NOT detectable
    (whoever rewrites the archive rewrites an unsigned HEAD too).
    RFC 3161 tokens (`.sth.tsr`) are checked by SPEC §11 (`cryptovalid_tsa.verify_token`, v0.6): a segment counts as
    timestamped only when its token is `verified` against `tsa_certs` (the TSA certificates the caller pins) or, with
    `lotl_check`, when the certificate that signed it is a QTST certificate of the EU trusted lists; a token whose
    signature verifies only with the certificate it carries is reported (`tsa_tokens`, a warning), not counted."""
    import verifier
    failures: List[Dict] = []
    warnings: List[str] = []
    signers: set = set()
    signed_count = 0
    timestamped: List = []            # segments whose token counts (SPEC §11: pinned, or LOTL-qualified signer below)
    checked: List = []                # (segment name, token DER, verify_token outcome) for every token that is not invalid
    tsa_tokens: List[Dict] = []       # one line per token: segment, status, reason, gen_time, signer_sha256
    segs = sorted(glob.glob(os.path.join(directory, f"{prefix}-[0-9]*.jsonl")))
    sealed = [s for s in segs if os.path.exists(s + ".sth.json")]
    prev_sth = GENESIS_PREV
    for s in sealed:
        name = os.path.basename(s)
        if verifier.verify_ledger(s)["verdict"] != "PASS":
            failures.append({"segment": name, "reason": "hash_chain_fail"})
            continue
        sth, why = _load_json_object(s + ".sth.json")
        if sth is None:   # not JSON / not an object / unreadable: named, never a traceback (audit V1 #6, 30/09/2026)
            failures.append({"segment": name, "reason": f"sth_unreadable: {why}"})
            prev_sth = None
            continue
        leaves = merkle.leaves_from_ledger(s)
        if merkle.mth(leaves).hex() != sth.get("root_sha256") \
                or len(leaves) != sth.get("tree_size"):
            failures.append({"segment": name, "reason": "merkle_root_mismatch"})
        if sth.get("prev_sth_sha256") != prev_sth:
            failures.append({"segment": name, "reason": "sth_chain_break"})
        if sth.get("signature"):
            signed_count += 1
            if isinstance(sth.get("signer"), str):   # NEMESIS 19/10/2026: a list or object here was a TypeError traceback
                signers.add(sth.get("signer"))       # (0.21.0 and 0.22.0 draft); any other type is sth_signature_invalid below
            reason = _check_signature(sth, expected_pubkey_hex)
            if reason:
                failures.append({"segment": name, "reason": f"sth_{reason}"})
        elif expected_pubkey_hex:
            failures.append({"segment": name, "reason": "sth_unsigned_but_pubkey_expected"})
        prev_sth = _sth_canonical_hash(sth)
        # RFC 3161 anchor (if present): SPEC §11 — a TSTInfo read closed, its messageImprint = the STH's canonical hash
        # (sha256), the CMS signature, and the pinned TSA when given. Until 0.22.0 this searched the digest's bytes anywhere
        # in the blob and checked the signature with the blob's own certificate: a CMS blob signed with a key made on the
        # spot, content = the digest's OCTET STRING, counted as timestamped (measured 2026-11-13).
        if os.path.exists(s + ".sth.tsr"):
            import cryptovalid_tsa as tsa_mod
            with open(s + ".sth.tsr", "rb") as f:
                token = f.read()
            chk = tsa_mod.verify_token(token, bytes.fromhex(prev_sth), "sha256", tsa_certs)
            tsa_tokens.append({"segment": name, "status": chk["status"], "reason": chk["reason"],
                               "gen_time": (chk["tst_info"] or {}).get("gen_time"), "signer_sha256": chk["signer_sha256"]})
            if chk["status"] == "invalid":
                failures.append({"segment": name, "reason": _TSA_FAILURE.get(chk["reason"], "tsa_token_invalid"),
                                 "detail": f"{chk['reason']}: {chk['detail']}"[:300]})
            else:
                checked.append((name, token, chk))
                if chk["status"] == "verified":
                    timestamped.append(name)

    # HEAD manifest: guardia della CODA (conteggio + ultimo STH)
    head_path = os.path.join(directory, f"{prefix}.head.json")
    head_signed = False
    head = None
    if os.path.exists(head_path):
        head, why = _load_json_object(head_path)
        if head is None:
            failures.append({"segment": "HEAD", "reason": f"head_unreadable: {why}"})
    if head is not None:
        if head.get("segments_sealed") != len(sealed):
            failures.append({"segment": "HEAD", "reason": "head_count_mismatch",
                             "expected": head.get("segments_sealed"), "found": len(sealed)})
        if sealed and head.get("last_sth_sha256") != prev_sth:
            failures.append({"segment": "HEAD", "reason": "head_last_sth_mismatch"})
        if head.get("signature"):
            head_signed = True
            reason = _check_signature(head, expected_pubkey_hex)
            if reason:
                failures.append({"segment": "HEAD", "reason": f"head_{reason}"})
        elif expected_pubkey_hex:
            failures.append({"segment": "HEAD", "reason": "head_unsigned_but_pubkey_expected"})
    elif sealed and not os.path.exists(head_path):
        warnings.append("no_head_manifest: tail segment removal/extension NOT detectable")
    if sealed and not head_signed:
        warnings.append("head_unsigned: tail guard only as strong as file access "
                        "(sign with a KMS/HSM backend and pin the pubkey)")
    if sealed and signed_count == 0:
        warnings.append("unsigned_archive: integrity verified, authorship NOT "
                        "(no STH signatures; anyone could have produced this archive)")
    if sealed and not expected_pubkey_hex:
        warnings.append("no_pinned_pubkey: signatures (if any) checked against their "
                        "own embedded key, not an expected signer")
    # certificazione eIDAS dei token (opt-in: tocca la rete/EU Trusted Lists).
    # La cache sta FUORI dall'archivio: una cache co-locata è avvelenabile.
    # SPEC §11 (v0.6): the certificate looked up is the one that signed the token; a token whose signer is a QTST
    # certificate counts as timestamped (the trusted list is its anchor), pinned or not.
    signed_tokens = [(n, tok, c) for n, tok, c in checked if c["status"] in ("verified", "signature_only")]
    qualified_count: Optional[int] = None
    if lotl_check and signed_tokens:
        import cryptovalid_lotl as lotl
        try:
            fprs, _cov, herr = lotl.load_qualified_status(
                lotl_member_states, cache_path=_default_lotl_cache(lotl_member_states))
        except Exception as e:  # noqa: BLE001 — network, or a LOTL that is not a trusted list (0.20.2: parsed as XML)
            fprs = None
            warnings.append(f"lotl_unavailable: {type(e).__name__}: {e}"[:300])
        if fprs is not None:
            verdicts = [(n, lotl.qualification(tok, fprs, herr, signer_sha256=c["signer_sha256"]))
                        for n, tok, c in signed_tokens]
            qualified = [n for n, (v, _w) in verdicts if v == "qualified"]
            qualified_count = len(qualified)
            timestamped += [n for n in qualified if n not in timestamped]
            undecided = [w for _n, (v, w) in verdicts if v == "indeterminate"]
            if undecided:   # 0.21.0: TS 119 615 PRO-4.3.4-03A
                warnings.append(f"tsa_qualification_indeterminate: {len(undecided)} token(s) from a QTST service whose "
                                f"trusted-list history is an error ({undecided[0]})"[:300])
            if qualified_count + len(undecided) < len(signed_tokens):
                warnings.append(f"tsa_not_qualified: {len(signed_tokens) - qualified_count - len(undecided)} "
                                "token(s) from a TSA not in the EU Trusted Lists (QTST)")
    chain_open = [n for n, _t, c in checked if c["status"] == "signature_only" and n not in timestamped]
    if chain_open:
        warnings.append(f"tsa_chain_not_established: {len(chain_open)} token(s): {_SIGNATURE_ONLY}; not counted as "
                        "timestamped (pin the TSA certificate with --tsa-cert, or --lotl)")
    not_evaluated = sum(1 for _n, _t, c in checked if c["status"] == "not_evaluated")
    if not_evaluated:
        warnings.append(f"tsa_not_evaluated: {not_evaluated} token(s) not checked, openssl absent; not counted as "
                        "timestamped")
    if sealed and not timestamped:
        warnings.append("no_rfc3161_anchor: time rests on the HOST clock only "
                        "(configure tsa_url to anchor each seal externally)")

    return {"ok": bool(sealed) and not failures,
            "segments_verified": len(sealed),
            "unsealed_segments": len(segs) - len(sealed),
            "signed_segments": signed_count, "signers": sorted(signers),
            "timestamped_segments": len(timestamped),
            "eidas_qualified_segments": qualified_count,
            "tsa_tokens": tsa_tokens,
            "head_present": os.path.exists(head_path), "head_signed": head_signed,
            "warnings": warnings, "failures": failures}


try:   # 0.20.3: the one writer of every command (verifier.py): an outcome is written whole, or exit 74
    from verifier import Parser, append_line, emit, receipt_cli, say, write_output
except ImportError:   # python3 -m opencore.<module> from the parent directory
    from opencore.verifier import Parser, append_line, emit, receipt_cli, say, write_output


@receipt_cli
def main(argv=None) -> int:  # pragma: no cover - thin CLI
    import argparse
    try:
        import cryptovalid_tsa as _T_arg
    except ImportError:   # python3 -m opencore.<module>
        from opencore import cryptovalid_tsa as _T_arg
    p = Parser(prog="cryptovalid-ingest",
                                description="High-frequency ingestion + archive verify.")
    sub = p.add_subparsers(dest="cmd", required=True)
    v = sub.add_parser("verify"); v.add_argument("directory")
    v.add_argument("--prefix", default="ledger"); v.add_argument("--pubkey")
    v.add_argument("--lotl", action="store_true",
                   help="certifica i token RFC 3161 come eIDAS-qualified via EU Trusted Lists (rete)")
    v.add_argument("--lotl-ms", nargs="*", default=None, help="restringi alle member state (es. ES IT)")
    v.add_argument("--tsa-cert", action="append", default=None, metavar="PEM", type=_T_arg.tsa_cert_arg,
                   help="pin the TSA certificate (or a CA above it), repeatable: a token counts as timestamped only "
                        "when verified against it, or with --lotl (SPEC §11)")
    b = sub.add_parser("bench"); b.add_argument("directory")
    b.add_argument("--n", type=int, default=50_000); b.add_argument("--batch", type=int, default=256)
    a = p.parse_args(sys.argv[1:] if argv is None else argv)
    if a.cmd == "verify":
        r = verify_archive(a.directory, a.prefix, a.pubkey,
                           lotl_check=a.lotl, lotl_member_states=a.lotl_ms, tsa_certs=a.tsa_cert)
        emit(json.dumps(r, indent=1)); return 0 if r["ok"] else 1
    ing = Ingestor(a.directory, prefix="bench", batch_size=a.batch,
                   rotate_entries=a.n + 1)
    t0 = time.perf_counter()
    for i in range(a.n):
        ing.append({"event": "bench", "i": i})
    ing.close()
    dt = time.perf_counter() - t0
    emit(json.dumps({"events": a.n, "seconds": round(dt, 3),
                      "events_per_second_measured": int(a.n / dt),
                      "note": "measured on THIS machine/filesystem, batch fsync",
                      "verify_with": f"python3 cryptovalid_ingest.py verify {a.directory} --prefix bench"},
                     indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
