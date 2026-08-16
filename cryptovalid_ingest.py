#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CryptoValid Open Core — high-frequency ingestion into court-admissible evidence.

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
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(doc, f, indent=1)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)
    _fsync_dir(os.path.dirname(path) or ".")


class Ingestor:
    """Append-only, thread-safe, batched writer of CryptoValid evidence segments."""

    def __init__(self, directory: str, prefix: str = "ledger", batch_size: int = 256,
                 rotate_entries: int = 100_000, fsync: bool = True, backend=None):
        if batch_size < 1 or rotate_entries < 1:
            raise ValueError("batch_size and rotate_entries must be >= 1")
        self._dir, self._prefix = directory, prefix
        self._batch, self._rotate, self._fsync = batch_size, rotate_entries, fsync
        self._backend = backend
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
            self._idx, self._prev = 0, GENESIS_PREV
        self._fh = open(self._seg_path(self._seq), "ab")
        _fsync_dir(self._dir)                     # la voce di directory del nuovo segmento

    def _resume(self, path: str):
        """Fail-closed recovery: keep every complete line, truncate a torn tail (it can
        only be an un-acknowledged write: flush() had not returned), resume the chain."""
        good_end, self._idx, self._prev = 0, 0, GENESIS_PREV
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
                body = {k: v for k, v in e.items()
                        if k not in ("self_hash", "signature", "signer")}
                recomputed = hashlib.sha256(_canonical(body)).hexdigest()
                if (e.get("idx") != self._idx or e.get("prev_hash") != self._prev
                        or e.get("self_hash") != recomputed):
                    raise ValueError(f"{path}: broken/tampered chain at idx {self._idx} — "
                                     "refusing to resume (run the verifier on it)")
                good_end += len(line)
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
            self._prev = e["self_hash"]
            self._idx += 1
            ref = {"segment": os.path.basename(self._seg_path(self._seq)), "idx": e["idx"]}
            if len(self._buf) >= self._batch:
                self.flush()
            if self._idx >= self._rotate:
                self.seal()
            return ref

    def flush(self):
        with self._lock:
            if self._buf:
                self._fh.write(("\n".join(self._buf) + "\n").encode())
                self._fh.flush()
                if self._fsync:
                    os.fsync(self._fh.fileno())
                self._buf.clear()

    # ── sealing ──────────────────────────────────────────────────────────────
    def seal(self) -> Optional[Dict]:
        """Flush, write the STH sidecar (chained to the previous STH, signed if a
        backend is configured), and rotate to a fresh segment. No-op when empty."""
        with self._lock:
            self.flush()
            if self._idx == 0:
                return None
            path = self._seg_path(self._seq)
            leaves = merkle.leaves_from_ledger(path)
            sth = merkle.signed_tree_head(leaves)
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
            self._idx, self._prev = 0, GENESIS_PREV
            self._fh = open(self._seg_path(self._seq), "ab")
            _fsync_dir(self._dir)
            return sth

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
        with self._lock:
            if seal:
                self.seal()
            else:
                self.flush()
            if self._fh and not self._fh.closed:
                self._fh.close()


# ── auditor path (read-only) ─────────────────────────────────────────────────
def _check_signature(doc: Dict, expected_pubkey_hex: Optional[str]) -> Optional[str]:
    """None se la firma del doc (STH o HEAD) è valida; altrimenti la ragione."""
    import base64
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    try:
        if expected_pubkey_hex and doc.get("signer") != expected_pubkey_hex:
            return "signer_mismatch"
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(doc["signer"])).verify(
            base64.b64decode(doc["signature"]), _sth_canonical_hash(doc).encode())
        return None
    except Exception:
        return "signature_invalid"


def verify_archive(directory: str, prefix: str = "ledger",
                   expected_pubkey_hex: Optional[str] = None) -> Dict:
    """Third-party verification of a whole archive: every sealed segment's hash chain
    (verifier.py rules), Merkle root vs sidecar, STH chain across segments, the HEAD
    manifest (segment count + last STH — the tail-truncation guard), and signatures.
    Fail-closed on any mismatch; honest `warnings` for what is NOT protected:
    without a signed HEAD + pinned pubkey, tail removal/extension is NOT detectable
    (whoever rewrites the archive rewrites an unsigned HEAD too)."""
    import verifier
    failures: List[Dict] = []
    warnings: List[str] = []
    signers: set = set()
    signed_count = 0
    segs = sorted(glob.glob(os.path.join(directory, f"{prefix}-[0-9]*.jsonl")))
    sealed = [s for s in segs if os.path.exists(s + ".sth.json")]
    prev_sth = GENESIS_PREV
    for s in sealed:
        name = os.path.basename(s)
        if verifier.verify_ledger(s)["verdict"] != "PASS":
            failures.append({"segment": name, "reason": "hash_chain_fail"})
            continue
        with open(s + ".sth.json", encoding="utf-8") as f:
            sth = json.load(f)
        leaves = merkle.leaves_from_ledger(s)
        if merkle.mth(leaves).hex() != sth.get("root_sha256") \
                or len(leaves) != sth.get("tree_size"):
            failures.append({"segment": name, "reason": "merkle_root_mismatch"})
        if sth.get("prev_sth_sha256") != prev_sth:
            failures.append({"segment": name, "reason": "sth_chain_break"})
        if sth.get("signature"):
            signed_count += 1
            signers.add(sth.get("signer"))
            reason = _check_signature(sth, expected_pubkey_hex)
            if reason:
                failures.append({"segment": name, "reason": f"sth_{reason}"})
        elif expected_pubkey_hex:
            failures.append({"segment": name, "reason": "sth_unsigned_but_pubkey_expected"})
        prev_sth = _sth_canonical_hash(sth)

    # HEAD manifest: guardia della CODA (conteggio + ultimo STH)
    head_path = os.path.join(directory, f"{prefix}.head.json")
    head_signed = False
    if os.path.exists(head_path):
        with open(head_path, encoding="utf-8") as f:
            head = json.load(f)
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
    elif sealed:
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

    return {"ok": bool(sealed) and not failures,
            "segments_verified": len(sealed),
            "unsealed_segments": len(segs) - len(sealed),
            "signed_segments": signed_count, "signers": sorted(signers),
            "head_present": os.path.exists(head_path), "head_signed": head_signed,
            "warnings": warnings, "failures": failures}


def main(argv=None) -> int:  # pragma: no cover - thin CLI
    import argparse
    p = argparse.ArgumentParser(prog="cryptovalid-ingest",
                                description="High-frequency ingestion + archive verify.")
    sub = p.add_subparsers(dest="cmd", required=True)
    v = sub.add_parser("verify"); v.add_argument("directory")
    v.add_argument("--prefix", default="ledger"); v.add_argument("--pubkey")
    b = sub.add_parser("bench"); b.add_argument("directory")
    b.add_argument("--n", type=int, default=50_000); b.add_argument("--batch", type=int, default=256)
    a = p.parse_args(sys.argv[1:] if argv is None else argv)
    if a.cmd == "verify":
        r = verify_archive(a.directory, a.prefix, a.pubkey)
        print(json.dumps(r, indent=1)); return 0 if r["ok"] else 1
    ing = Ingestor(a.directory, prefix="bench", batch_size=a.batch,
                   rotate_entries=a.n + 1)
    t0 = time.perf_counter()
    for i in range(a.n):
        ing.append({"event": "bench", "i": i})
    ing.close()
    dt = time.perf_counter() - t0
    print(json.dumps({"events": a.n, "seconds": round(dt, 3),
                      "events_per_second_measured": int(a.n / dt),
                      "note": "measured on THIS machine/filesystem, batch fsync",
                      "verify_with": f"python3 cryptovalid_ingest.py verify {a.directory} --prefix bench"},
                     indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
