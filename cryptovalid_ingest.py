#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
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
import re
import sys
import threading
import time
from datetime import datetime, timezone
from typing import Dict, List, Optional

import cryptovalid_merkle as merkle

GENESIS_PREV = "0" * 64
# SPEC v0.14 §22 rule 2: a tree head (<segment>.sth.json) and the HEAD (<prefix>.head.json) are CLOSED objects, these
# members and no other: every member this module has written since 2026-08-16 (`signed` since 2026-09-14). A member outside
# the list is the failure sth_unknown_member:<keys> / head_unknown_member:<keys> (until 0.27.0 ignored: ok, no reason).
STH_MEMBERS = frozenset({"tree_size", "root_sha256", "signed", "note", "segment", "sealed_utc", "last_self_hash",
                         "prev_sth_sha256", "signature", "signer", "sig_domain"})
HEAD_MEMBERS = frozenset({"prefix", "segments_sealed", "last_segment", "last_sth_sha256", "updated_utc", "signature",
                          "signer", "sig_domain"})
# SPEC v0.14 §22 rule 3: a tree head or a HEAD signed from now on carries `sig_domain`, inside the hashed body, and
# its signature is over the UTF-8 bytes of "<sig_domain>:<hex of the SHA-256 of the canonical body>": never 64 hex
# characters alone, the message of an entry signature (§2). Without `sig_domain` (written until 0.27.0) the signature is
# over the bare hex, as before, and verify_archive names those documents in a warning; require_signature_domain refuses them.
STH_SIG_DOMAIN = "cryptovalid-sth/2"
HEAD_SIG_DOMAIN = "cryptovalid-head/2"


def _unknown_members(doc: Dict, members) -> Optional[str]:
    """The members of `doc` outside `members`, in code-point order, joined and cut to 120 code points; None if none."""
    unknown = sorted(k for k in doc if k not in members)
    return ",".join(unknown)[:120] if unknown else None


def _canonical(d: Dict) -> bytes:
    return json.dumps(d, sort_keys=True, separators=(",", ":")).encode()


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _sth_canonical_hash(sth: Dict) -> str:
    body = {k: v for k, v in sth.items() if k not in ("signature", "signer")}
    return hashlib.sha256(_canonical(body)).hexdigest()


def _signed_message(doc: Dict, domain: str) -> bytes:
    """The bytes the signature of a tree head or a HEAD is over (SPEC §22 rule 3): tagged when `sig_domain` is there."""
    if "sig_domain" in doc:
        return (domain + ":" + _sth_canonical_hash(doc)).encode()
    return _sth_canonical_hash(doc).encode()


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


_MEMBER_STATE = re.compile(r"[A-Za-z]{2}")


def _member_states(member_states):
    """None, or the codes upper-cased and sorted. SPEC v0.12 §20 rule 11 (19/11/2026): a list, tuple or set of strings
    of exactly two ASCII letters; anything else is a ValueError. The codes name the cache file below: until 0.26.0
    they were joined into its name as given, and ["X/../../../evil"] named ~/EVIL.json."""
    if member_states is None:
        return None
    if isinstance(member_states, (str, bytes)) or not isinstance(member_states, (list, tuple, set, frozenset)) \
            or not all(isinstance(m, str) and _MEMBER_STATE.fullmatch(m) for m in member_states):
        raise ValueError("lotl_member_states: a list of member-state codes of two ASCII letters (e.g. [\"ES\", \"IT\"]), "
                         "or None for every member state")
    return sorted({m.upper() for m in member_states})


def _default_lotl_cache(member_states) -> str:
    """Cache LOTL FUORI dall'archivio: una cache co-locata coi dati non fidati è
    avvelenabile da chi scrive nella dir (fingerprint finti -> qualified finto —
    trovato dalla review avversariale). ~/.cache è del VERIFICATORE, non dell'archivio."""
    codes = _member_states(member_states)
    tag = "-".join(codes) if codes else "all"
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
        import verifier
        if rotate_entries > verifier.MAX_INPUT_LINES:   # SPEC §22 rule 9: a segment no verifier would read
            raise ValueError(f"rotate_entries must be <= {verifier.MAX_INPUT_LINES} (SPEC §22 rule 9: a ledger holds no more lines)")
        self._max_tokens, self._tokens = verifier.MAX_JSON_TOKENS, 0   # the tokens of the active segment, counted as rule 9 counts
        self._dir, self._prefix = directory, prefix
        self._batch, self._rotate, self._fsync = batch_size, rotate_entries, fsync
        self._backend = backend
        self._tsa_url, self._lotl_check = tsa_url, lotl_check
        _member_states(lotl_member_states)   # SPEC v0.12 §20 rule 11: refused here, not at the first seal
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
        only be an un-acknowledged write: flush() had not returned), resume the chain.
        SPEC v0.12 §20 rule 9 (19/11/2026): the torn tail is the LAST line when it does not end with a line feed. A
        complete line that is not a JSON object is damage, not a torn write: ValueError, the file left as it is. Until
        0.26.0 it was taken for the tail and every acknowledged entry after it was cut without an error."""
        good_end, self._idx, self._prev, self._first = 0, 0, GENESIS_PREV, GENESIS_PREV
        import verifier
        with os.fdopen(verifier.open_regular(path, float("inf")), "rb") as f:   # SPEC §5 step 0: its own segment, a regular file
            for line in f:
                if not line.endswith(b"\n"):
                    break                                     # torn tail
                if not line.strip():                          # riga vuota: come verifier.py
                    good_end += len(line)
                    continue
                try:
                    e = json.loads(line)
                except (ValueError, RecursionError):          # not JSON, not UTF-8, nested too deep to parse
                    e = None
                if not isinstance(e, dict):
                    raise ValueError(f"{path}: the complete line at byte {good_end}, after {self._idx} entries, is not "
                                     "a JSON object — refusing to resume and leaving the file as it is (only a last "
                                     "line without its line feed is a torn tail; run the verifier on it)")
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
                self._tokens += sum(line.count(c) for c in (b"{", b"[", b",", b":"))
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
            def entry():
                e = {"idx": self._idx, "ts": _utc_now(), "data": data, "prev_hash": self._prev}
                e["self_hash"] = hashlib.sha256(_canonical(e)).hexdigest()
                line = json.dumps(e, sort_keys=True, separators=(",", ":"))
                return e, line, sum(line.count(c) for c in "{[,:")
            def closed():   # after close() an entry would be queued and never written: refused (NEMESIS 22/11/2026)
                if self._fh is None or self._fh.closed:
                    raise ValueError("the Ingestor is closed: the entry was not appended")
            closed()
            e, line, tokens = entry()
            # SPEC §22 rule 9: a segment is a ledger, and a verifier reads at most 2^23 tokens of one. Until NEMESIS
            # 22/11/2026 the segment was sealed on its entries alone: 100 000 entries of 104 tokens each made a segment
            # that verify_archive refused (input_too_large: more than 8388608 JSON tokens)
            if tokens > self._max_tokens:
                raise ValueError(f"the entry holds more than {self._max_tokens} JSON tokens (SPEC §22 rule 9): no "
                                 "verifier would read its segment")
            while self._idx and self._tokens + tokens > self._max_tokens:
                # this entry opens the next segment; the seal (and its TSA anchor) runs OUTSIDE the lock, as the
                # rotation below, and only if no other thread has rotated meanwhile
                seq = self._seq
                self._lock.release()
                try:
                    self.seal(only_seq=seq)
                finally:
                    self._lock.acquire()
                closed()                         # close() may have run while the lock was free
                e, line, tokens = entry()
            self._tokens += tokens
            self._buf.append(line)
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
    def seal(self, min_entries: int = 1, only_seq: Optional[int] = None) -> Optional[Dict]:
        """Flush, write the STH sidecar (chained to the previous STH, signed if a
        backend is configured), and rotate to a fresh segment. No-op when the segment
        has fewer than `min_entries` entries (default: no-op only when empty), or when
        `only_seq` is given and the active segment is no longer that one."""
        with self._lock:
            self.flush()
            if self._idx < max(1, min_entries) or (only_seq is not None and self._seq != only_seq):
                return None
            path = self._seg_path(self._seq)
            leaves = merkle.leaves_from_ledger(path)
            sth = merkle.tree_head(leaves)          # unsigned head (renamed 2026-09-13); signed just below when a backend is given
            sth.update({"segment": os.path.basename(path), "sealed_utc": _utc_now(),
                        "last_self_hash": self._prev,
                        "prev_sth_sha256": self._prev_sth_hash()})
            if self._backend is not None:
                import base64
                sth["sig_domain"] = STH_SIG_DOMAIN   # SPEC §22 rule 3: in the hashed body, and the message is tagged
                sig = self._backend.sign(_signed_message(sth, STH_SIG_DOMAIN))
                sth["signature"] = base64.b64encode(sig).decode()
                sth["signer"] = self._backend.public_key_hex()
            _write_json_atomic(path + ".sth.json", sth)
            self._write_head(sth)
            self._fh.close()
            self._seq += 1
            self._idx, self._prev, self._first = 0, GENESIS_PREV, GENESIS_PREV
            self._tokens = 0
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
                if verdict == "indeterminate":   # 0.21.0: TS 119 615 PRO-4.3.4-03A, neither qualified nor not
                    meta["eidas_indeterminate"] = why
                elif why:                        # SPEC v0.10 §11: a QTST signer, the qualified statement missing
                    meta["eidas_not_qualified_reason"] = why
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
            head["sig_domain"] = HEAD_SIG_DOMAIN   # SPEC §22 rule 3
            sig = self._backend.sign(_signed_message(head, HEAD_SIG_DOMAIN))
            head["signature"] = base64.b64encode(sig).decode()
            head["signer"] = self._backend.public_key_hex()
        _write_json_atomic(os.path.join(self._dir, f"{self._prefix}.head.json"), head)

    def _prev_sth_hash(self) -> str:
        prev = self._seg_path(self._seq - 1) + ".sth.json" if self._seq > 0 else None
        if prev and os.path.exists(prev):
            import verifier
            return _sth_canonical_hash(json.loads(verifier.read_text_regular(prev)))   # SPEC §5 step 0
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
def _check_signature(doc: Dict, expected_pubkey_hex, domain: str = STH_SIG_DOMAIN,
                     require_signature_domain: bool = False) -> Optional[str]:
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
        if "sig_domain" not in doc and require_signature_domain:   # SPEC §22 rule 3
            return "signature_domain_untagged"
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub)).verify(raw_sig, _signed_message(doc, domain))
        return None
    except Exception:
        return "signature_invalid"


def _load_json_object(path):
    """(object, None) or (None, reason): a file that is not UTF-8 JSON, or not a JSON object, is a named failure."""
    import verifier
    try:   # SPEC §5 step 0: opened once without blocking (a FIFO as *.sth.json or *.head.json blocked here, 18/11/2026)
        obj = json.loads(verifier.read_regular(path).decode("utf-8"), object_pairs_hook=verifier._reject_dup)
    except (OSError, ValueError, RecursionError) as e:   # UnicodeDecodeError and JSONDecodeError are ValueError
        if str(e).startswith("duplicate JSON key"):   # SPEC v0.13 §21 rule 2: a tree head or a HEAD with a key written
            return None, "duplicate_key"              # twice is refused (until 0.27.0 the last value was read, ok true)
        return None, type(e).__name__
    return (obj, None) if isinstance(obj, dict) else (None, "not_a_json_object")


# SPEC §11 reason → the failure reason of verify_archive (the names of 0.22.0 kept where they existed)
_TSA_FAILURE = {"imprint_mismatch": "tsa_token_digest_mismatch", "hash_algorithm_mismatch": "tsa_token_digest_mismatch",
                "signature_invalid": "tsa_token_cms_invalid", "malformed": "tsa_token_cms_invalid",
                "not_signed_data": "tsa_token_cms_invalid", "response_not_granted": "tsa_token_cms_invalid",
                "econtent_type_not_tstinfo": "tsa_token_not_tstinfo", "tstinfo_unknown_element": "tsa_token_not_tstinfo",
                "hash_algorithm_not_allowed": "tsa_token_hash_algorithm_not_allowed",
                "not_issued_by_pinned_tsa": "tsa_token_not_issued_by_pinned_tsa",
                "signer_certificate_absent": "tsa_token_signer_certificate_absent"}   # SPEC v0.11 §11 step 6
_SIGNATURE_ONLY = "signature valid with the certificate contained in the token, chain not established"


def verify_archive(directory: str, prefix: str = "ledger",
                   expected_pubkey_hex=None,
                   lotl_check: bool = False, lotl_member_states=None, tsa_certs=None,
                   require_signature_domain: bool = False) -> Dict:
    """Third-party verification of a whole archive: every sealed segment's hash chain
    (verifier.py rules), Merkle root vs sidecar, STH chain across segments, the HEAD
    manifest (segment count + last STH — the tail-truncation guard), and signatures.
    Fail-closed on any mismatch; honest `warnings` for what is NOT protected:
    without a signed HEAD + pinned pubkey, tail removal/extension is NOT detectable
    (whoever rewrites the archive rewrites an unsigned HEAD too).
    RFC 3161 tokens (`.sth.tsr`) are checked by SPEC §11 (`cryptovalid_tsa.verify_token`, v0.6): a segment counts as
    timestamped only when its token is `verified` against `tsa_certs` (the TSA certificates the caller pins) or, with
    `lotl_check`, when the certificate that signed it is a QTST certificate of the EU trusted lists; a token whose
    signature verifies only with the certificate it carries is reported (`tsa_tokens`, a warning), not counted.
    SPEC §22 rule 7: with `tsa_certs` every sealed segment needs a token verified under them (`tsa_token_missing_but_tsa_pinned`,
    `tsa_token_not_verified_under_pin`); until 0.27.0 such an archive was ok.
    An empty pin ("" or an empty list, or a list holding an empty or non-string key) pins nothing and is a ValueError
    (SPEC v0.9 §17, 16/11/2026: until 0.25.0 it meant "not pinned", ok true with the warning no_pinned_pubkey).
    `require_signature_domain` (SPEC §22 rule 3): a signed tree head or HEAD without `sig_domain` (signed over the bare
    hash, as until 0.27.0) is a failure (`..._signature_domain_untagged`); by default it verifies and is named in a warning."""
    if expected_pubkey_hex is not None:
        if not isinstance(expected_pubkey_hex, str):
            expected_pubkey_hex = list(expected_pubkey_hex)
        keys = [expected_pubkey_hex] if isinstance(expected_pubkey_hex, str) else expected_pubkey_hex
        if not keys or not all(isinstance(k, str) and k for k in keys):
            raise ValueError("expected_pubkey_hex: an empty pin pins nothing: give a key, a non-empty list of keys, or None")
    _member_states(lotl_member_states)   # SPEC v0.12 §20 rule 11: refused before any file is read, with or without lotl_check
    import verifier
    failures: List[Dict] = []
    warnings: List[str] = []
    signers: set = set()
    signed_count = 0
    untagged: List[str] = []          # signed documents without sig_domain (SPEC §22 rule 3)
    timestamped: List = []            # segments whose token counts (SPEC §11: pinned, or LOTL-qualified signer below)
    checked: List = []                # (segment name, token DER, verify_token outcome) for every token that is not invalid
    tsa_tokens: List[Dict] = []       # one line per token: segment, status, reason, gen_time, signer_sha256
    segs = sorted(glob.glob(os.path.join(directory, f"{prefix}-[0-9]*.jsonl")))
    sealed = [s for s in segs if os.path.exists(s + ".sth.json")]
    # SPEC §5 step 0 (review of 18/11/2026): a segment without STH is not read (nothing seals it), but one that is not a
    # regular file (a directory, a device, a FIFO in its place) is not a segment this format writes: a named failure, judged
    # on a descriptor opened without blocking, never a read and never a wait
    # SPEC v0.12 §20 rule 10 (19/11/2026): a regular one IS read. The writer leaves at most one, the last in order: any
    # other is a failure; one that holds entries must verify as a ledger; what verifies is named in a warning, since no
    # tree head covers it. Until 0.26.0 it was only counted: a file of anything, added as <prefix>-000099.jsonl, left ok.
    unsealed_entries: List = []       # (segment name, entries) of the segments without STH whose chain verifies
    for s in segs:
        if s in sealed:
            continue
        name = os.path.basename(s)
        try:
            os.close(verifier.open_regular(s, float("inf")))
        except verifier.InputNotRegular:
            failures.append({"segment": name, "reason": "unsealed_segment_not_regular"})
            continue
        except OSError:
            continue   # gone or unreadable since the listing: as before, it is not read
        if s != segs[-1]:
            failures.append({"segment": name, "reason": "unsealed_segment_not_last"})
        try:
            blank = not verifier.read_regular(s).strip()
        except OSError as e:   # over the verifier's bound, or gone since the open above
            failures.append({"segment": name, "reason": "unsealed_segment_chain_fail", "detail": f"unreadable: {type(e).__name__}"})
            continue
        if blank:
            continue           # the active segment after a seal
        r = verifier.verify_ledger(s)
        if r["verdict"] != "PASS":
            failures.append({"segment": name, "reason": "unsealed_segment_chain_fail"})
        else:
            unsealed_entries.append((name, r["entries_count"]))
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
        unknown = _unknown_members(sth, STH_MEMBERS)
        if unknown is not None:   # SPEC §22 rule 2
            failures.append({"segment": name, "reason": "sth_unknown_member:" + unknown})
        if "sig_domain" in sth and sth["sig_domain"] != STH_SIG_DOMAIN:   # SPEC §22 rule 3: present = exactly the tag
            failures.append({"segment": name, "reason": "sth_signature_domain_mismatch"})
        try:
            leaves = merkle.leaves_from_ledger(s)
        except OSError:   # a segment read through a pipe by the chain check cannot be read a second time for its leaves
            failures.append({"segment": name, "reason": "hash_chain_fail"})
            prev_sth = None
            continue
        if merkle.mth(leaves).hex() != sth.get("root_sha256") \
                or len(leaves) != sth.get("tree_size"):
            failures.append({"segment": name, "reason": "merkle_root_mismatch"})
        if sth.get("prev_sth_sha256") != prev_sth:
            failures.append({"segment": name, "reason": "sth_chain_break"})
        if sth.get("signature"):
            signed_count += 1
            if isinstance(sth.get("signer"), str):   # NEMESIS 19/10/2026: a list or object here was a TypeError traceback
                signers.add(sth.get("signer"))       # (0.21.0 and 0.22.0 draft); any other type is sth_signature_invalid below
            reason = _check_signature(sth, expected_pubkey_hex, STH_SIG_DOMAIN, require_signature_domain)
            if reason:
                failures.append({"segment": name, "reason": f"sth_{reason}"})
            elif "sig_domain" not in sth:
                untagged.append(name)
        elif expected_pubkey_hex:
            failures.append({"segment": name, "reason": "sth_unsigned_but_pubkey_expected"})
        prev_sth = _sth_canonical_hash(sth)
        # RFC 3161 anchor (if present): SPEC §11 — a TSTInfo read closed, its messageImprint = the STH's canonical hash
        # (sha256), the CMS signature, and the pinned TSA when given. Until 0.22.0 this searched the digest's bytes anywhere
        # in the blob and checked the signature with the blob's own certificate: a CMS blob signed with a key made on the
        # spot, content = the digest's OCTET STRING, counted as timestamped (measured 2026-11-13).
        if os.path.exists(s + ".sth.tsr"):
            import cryptovalid_tsa as tsa_mod
            try:   # SPEC §5 step 0: a token file that is a FIFO, a device or over the bound is a named failure
                token = verifier.read_regular(s + ".sth.tsr", tsa_mod.PIN_MAX_BYTES)
            except OSError as e:
                failures.append({"segment": name, "reason": "tsa_token_invalid",
                                 "detail": f"unreadable: {type(e).__name__}"})
                continue
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
                elif tsa_certs is not None:   # SPEC §22 rule 7: under a TSA pin a token not verified is a failure
                    failures.append({"segment": name, "reason": "tsa_token_not_verified_under_pin",
                                     "detail": f"{chk['status']}: {chk['reason']}"[:300]})
        elif tsa_certs is not None:   # SPEC §22 rule 7: under a TSA pin a sealed segment without a token is a failure
            failures.append({"segment": name, "reason": "tsa_token_missing_but_tsa_pinned"})

    # HEAD manifest: guardia della CODA (conteggio + ultimo STH)
    head_path = os.path.join(directory, f"{prefix}.head.json")
    head_signed = False
    head = None
    if os.path.exists(head_path):
        head, why = _load_json_object(head_path)
        if head is None:
            failures.append({"segment": "HEAD", "reason": f"head_unreadable: {why}"})
    if head is not None:
        unknown = _unknown_members(head, HEAD_MEMBERS)
        if unknown is not None:   # SPEC §22 rule 2
            failures.append({"segment": "HEAD", "reason": "head_unknown_member:" + unknown})
        if "sig_domain" in head and head["sig_domain"] != HEAD_SIG_DOMAIN:   # SPEC §22 rule 3
            failures.append({"segment": "HEAD", "reason": "head_signature_domain_mismatch"})
        if head.get("segments_sealed") != len(sealed):
            failures.append({"segment": "HEAD", "reason": "head_count_mismatch",
                             "expected": head.get("segments_sealed"), "found": len(sealed)})
        if sealed and head.get("last_sth_sha256") != prev_sth:
            failures.append({"segment": "HEAD", "reason": "head_last_sth_mismatch"})
        if head.get("signature"):
            head_signed = True
            reason = _check_signature(head, expected_pubkey_hex, HEAD_SIG_DOMAIN, require_signature_domain)
            if reason:
                failures.append({"segment": "HEAD", "reason": f"head_{reason}"})
            elif "sig_domain" not in head:
                untagged.append("HEAD")
        elif expected_pubkey_hex:
            failures.append({"segment": "HEAD", "reason": "head_unsigned_but_pubkey_expected"})
    elif sealed and not os.path.exists(head_path):
        if expected_pubkey_hex:   # SPEC v0.12 §20 rule 8 (19/11/2026): removing the HEAD is not weaker than unsigning it
            failures.append({"segment": "HEAD", "reason": "head_missing_but_pubkey_expected"})
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
    if untagged:   # SPEC §22 rule 3: verified, over the bare hash an entry signature could also be over
        warnings.append(f"untagged_signatures: {', '.join(untagged)} signed without sig_domain (written before SPEC §22 "
                        "rule 3): verified over the bare hash; require_signature_domain refuses them"[:400])
    if unsealed_entries:
        warnings.append(f"unsealed_entries: {sum(n for _s, n in unsealed_entries)} entries in {len(unsealed_entries)} "
                        f"segment(s) without a tree head ({', '.join(s for s, _n in unsealed_entries)}): their chain is "
                        "verified, but no tree head, HEAD or signature covers them (entries removed from their tail are "
                        "NOT detectable here; seal the segment)"[:400])
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
            no_statement = [w for _n, (v, w) in verdicts if v == "not_qualified" and w]
            if no_statement:   # SPEC v0.10 §11, Regulation (EU) 2025/1929: the signer is listed, the token is not declared
                warnings.append(f"tsa_qualified_statement_missing: {len(no_statement)} token(s) signed by a QTST certificate "
                                f"of the EU Trusted Lists without the qcStatements esi4-qtstStatement-1 of Regulation (EU) "
                                f"2025/1929 ({no_statement[0]}): not qualified"[:300])
            if qualified_count + len(undecided) + len(no_statement) < len(signed_tokens):
                warnings.append(f"tsa_not_qualified: {len(signed_tokens) - qualified_count - len(undecided) - len(no_statement)} "
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
    from verifier import MAX_INPUT_LINES, _Once, Parser, append_line, emit, receipt_cli, say, write_output
except ImportError:   # python3 -m opencore.<module> from the parent directory
    from opencore.verifier import MAX_INPUT_LINES, _Once, Parser, append_line, emit, receipt_cli, say, write_output


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
    v.add_argument("--prefix", default="ledger"); v.add_argument("--pubkey", action=_Once)
    v.add_argument("--require-signature-domain", action="store_true",
                   help="refuse a tree head or HEAD signed without sig_domain, over the bare hash (SPEC §22 rule 3)")
    v.add_argument("--lotl", action="store_true",
                   help="qualify the RFC 3161 tokens as eIDAS-qualified through the EU Trusted Lists (network)")
    v.add_argument("--lotl-ms", nargs="*", default=None, help="restrict to these member states (e.g. ES IT)")
    v.add_argument("--tsa-cert", action="append", default=None, metavar="PEM", type=_T_arg.tsa_cert_arg,
                   help="pin the TSA certificate (or a CA above it), repeatable: a token counts as timestamped only "
                        "when verified against it, or with --lotl (SPEC §11)")
    b = sub.add_parser("bench"); b.add_argument("directory")
    b.add_argument("--n", type=int, default=50_000); b.add_argument("--batch", type=int, default=256)
    a = p.parse_args(sys.argv[1:] if argv is None else argv)
    if a.cmd == "verify":
        if a.pubkey is not None and (a.pubkey == "" or a.pubkey.startswith("-")):   # one grammar (verifier.py): "" is not "not given"
            p.error(f"--pubkey needs a value (got {a.pubkey!r})")
        r = verify_archive(a.directory, a.prefix, a.pubkey,
                           lotl_check=a.lotl, lotl_member_states=a.lotl_ms, tsa_certs=a.tsa_cert,
                           require_signature_domain=a.require_signature_domain)
        emit(json.dumps(r, indent=1)); return 0 if r["ok"] else 1
    ing = Ingestor(a.directory, prefix="bench", batch_size=a.batch,
                   rotate_entries=min(a.n + 1, MAX_INPUT_LINES))
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
