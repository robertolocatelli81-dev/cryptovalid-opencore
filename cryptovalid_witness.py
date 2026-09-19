#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""cryptovalid-opencore — a transparency-log WITNESS for checkpoints (0.14.0, 2026-09-19).

What Certificate Transparency does with gossip and what Sigstore does with witnesses (c2sp.org/tlog-witness): an
independent party keeps the LAST checkpoint it cosigned for each log origin, and cosigns a new one only if the log
proves (RFC 6962 consistency proof) that the new tree extends the old one. Consequences, measured in the tests:
  - a log that shows two different roots for the same size gets NO cosignature and the witness returns BOTH
    log-signed checkpoints (`evidenza`, tipo `split-view`): that pair IS proof of misbehaviour, anyone can verify
    both signatures. An older checkpoint (`rollback`) or an extension without a valid proof (`unproven-extension`)
    is refused too and both checkpoints are returned, but they are NOT proof by themselves (a log genuinely signed
    the older one; a missing proof may be a client error) — `evidenza.prova` says which is which;
  - a relying party that requires N witness cosignatures younger than T seconds (`verify_witnessed`) gets freshness
    RELATIVE TO WHAT THOSE WITNESSES HAVE COSIGNED: a view a witness has already moved past cannot get a fresh
    cosignature from it; a view the witness has not yet seen superseded can (the witness re-cosigns the same
    checkpoint with a new timestamp, as the spec allows).
This turns the two README limits declared on 2026-08-17 as "future work" (split-view / equivocation, rollback /
freshness) into the property the transparency ecosystem gives: for a relying party that trusts at least one honest
witness that has seen the newer tree. What it does NOT give: a witness is a party; a colluding log + witness set can
still equivocate (the same limit CT and Sigstore state); the per-entry timestamps stay local-clock claims (pre-anchor
window); selective omission is inherent.

Honest scope: signing needs `cryptography`; the witness refuses to cosign when the log signature cannot be verified
(NON_VERIFICATA is not a green light); the witness state is a local JSON file, its integrity is the operator's.
"""
from __future__ import annotations
import base64
import contextlib
import hashlib
import json
import os
import re
import sys
import threading
import time
try:
    import fcntl                     # POSIX: a cross-process lock on the state file (two witness processes, CLI + server)
except ImportError:                  # pragma: no cover — Windows: single-process assumption, stated in witness_cosign
    fcntl = None
from typing import Dict, List, Optional, Union

import cryptovalid_checkpoint as C

STATO_OK = "COSIGNED"
STATO_RIFIUTO = "REFUSED"


def _load_state(path: str) -> Dict:
    if not os.path.exists(path):
        return {"origins": {}}
    try:
        with open(path, encoding="utf-8") as f:
            st = json.load(f)
    except (OSError, ValueError) as e:      # unreadable or not JSON: a clear error, not a dead connection
        raise C.NoteError(f"witness state file unreadable: {e}") from None
    if not isinstance(st, dict) or not isinstance(st.get("origins"), dict):
        raise C.NoteError("witness state file malformed")
    if not isinstance(st.get("pending", {}), dict) or not isinstance(st.get("proofs_seen", []), list) or not isinstance(st.get("refusals", {}), dict):
        raise C.NoteError("witness state file malformed")
    for o, sizes in st.get("pending", {}).items():
        if not (isinstance(sizes, dict) and all(isinstance(k, str) and re.fullmatch(r"0|[1-9][0-9]{0,19}", k) and isinstance(r, dict)
                                                and all(isinstance(a, str) and (b is None or isinstance(b, str)) for a, b in r.items())
                                                for k, r in sizes.items())):
            raise C.NoteError(f"witness state pending index for origin {o!r} malformed")
    for o, ring in st.get("refusals", {}).items():
        if not (isinstance(ring, dict) and isinstance(ring.get("count"), int) and isinstance(ring.get("last"), list)
                and all(isinstance(e, dict) and isinstance(e.get("root_b64"), str) and isinstance(e.get("size"), int) for e in ring["last"])):
            raise C.NoteError(f"witness state refusals for origin {o!r} malformed")
    for o, e in st["origins"].items():
        if not (isinstance(e, dict) and isinstance(e.get("size"), int) and not isinstance(e["size"], bool) and e["size"] >= 0
                and isinstance(e.get("root_b64"), str) and isinstance(e.get("note"), str)
                and isinstance(e.get("cosigned_at", 0), int) and not isinstance(e.get("cosigned_at", 0), bool)):
            raise C.NoteError(f"witness state entry for origin {o!r} malformed")
        try:
            if len(C.b64decode_strict(e["root_b64"])) != 32:
                raise ValueError
        except ValueError:
            raise C.NoteError(f"witness state entry for origin {o!r}: root is not 32 bytes base64") from None
    return st


@contextlib.contextmanager
def _state_lock(path: str):
    """Exclusive advisory lock on <state>.lock for the whole read-check-write of witness_cosign (POSIX flock). On a
    platform without fcntl the lock is a no-op and the single-process assumption holds."""
    if fcntl is None:
        yield; return
    fd = os.open(path + ".lock", os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN); os.close(fd)


def _save_state(path: str, st: Dict) -> None:
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(st, f, ensure_ascii=False, indent=1)
        f.flush(); os.fsync(f.fileno())
    os.replace(tmp, path)
    try:                                   # durable rename: the spec wants the checkpoint persisted BEFORE the response
        dfd = os.open(os.path.dirname(os.path.abspath(path)) or ".", os.O_RDONLY)
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)
    except OSError:                        # pragma: no cover — a platform where directories cannot be fsync'ed
        pass


EMPTY_ROOT = hashlib.sha256(b"").digest()   # RFC 6962 §2.1: MTH({}) = SHA-256 of the empty string
_RING = 100                                   # non-proof refusals remembered per origin (size, root, when): bounded by design
_PENDING_BYTES = 256 * 1024                   # pending log-signed notes per origin: at most _RING notes and this many bytes
_PENDING_NOTE = 16 * 1024                     # a pending note larger than this is compared but not kept
_HISTORY_SCAN = 4 * 1024 * 1024               # a rollback is compared with the last 4 MiB of the cosigned history (bounded read)
_PROOFS_SEEN = 10000                          # pair keys remembered for dedupe of proof records (bounded; beyond it a duplicate record)
_MAX_PROOF = 63                                # tlog-witness: the client MUST NOT send more than 63 proof lines


LOG_KEY_TYPES = (C.TYPE_ED25519, C.TYPE_ECDSA)   # log signatures this witness verifies: Ed25519 (ours) and ECDSA (Rekor v1)


def witness_cosign(state_path: str, note: bytes, log_vkey: Union[str, List[str]], witness_name: str, witness_seed: bytes,
                   consistency_proof_b64: Optional[List[str]] = None, timestamp: Optional[int] = None,
                   old_size: Optional[int] = None, expected_origin: Optional[str] = None,
                   pq_seed: Optional[bytes] = None) -> Dict:
    """Try to cosign `note` (a checkpoint signed by the log). Returns
    {stato: COSIGNED|REFUSED, motivo, note (bytes, cosigned) | None, cosignature (the line added) | None,
     evidenza: {tipo, prova, precedente, presentato}|None, origin, size, http_status, stored_size}.
    Rules (c2sp.org/tlog-witness, HTTP status in brackets, checked in the spec's order): a malformed note [400]; the
    log signature MUST verify against `log_vkey` — one vkey or the list of keys trusted for this origin (key
    rotation: the spec says "public key(s)") [403; 500 when this process has no Ed25519 implementation at all];
    the origin MUST be `expected_origin` — the origin the operator trusts those keys for; by default the key name,
    which the checkpoint spec says SHOULD match the origin, but production logs differ ("go.sum database tree" is
    signed by `sum.golang.org`) [400]; when the client states `old_size` it MUST NOT exceed the checkpoint size
    [400] and MUST equal the size last cosigned for that origin (0 if none) [409, `stored_size` returned]; a size-0
    checkpoint MUST carry the empty-tree root [422]; the first checkpoint of an origin (stored size 0) is accepted
    as is with an EMPTY proof (trust on first use — stated) [422 if a proof is sent]; afterwards the same size MUST
    have the same root [422] and a larger size MUST come with a consistency proof from the stored (size, root)
    that verifies [422]; a smaller size is a rollback [400; over HTTP it is already a 400/409 by the old-size rule].
    Without `old_size` (library use) the stored size is taken as the old size. Every refusal that involves two
    log-signed checkpoints returns both in `evidenza`; the pairs that are PROOF (`split-view`: two log-signed roots
    at one size) are appended once each to `<state>.evidence.jsonl` (also over HTTP, where the client only sees the
    status), whether met at the stored size, at a size this witness cosigned earlier (<state>.cosigned.jsonl), among
    the roots refused without proof beyond the stored size (`pending`), or when a cosign passes such a size;
    `rollback` and `unproven-extension` are counted and remembered as size/root/time (last 100 per origin); every
    log-signed root beyond the stored size (a discovery request with the wrong old size included) is kept in
    `pending` — at most 100 notes and 256 KiB per origin, notes above 16 KiB kept as root only, the SMALLEST sizes
    dropped first (a dropped root cannot become proof later). So a client replaying the log's public history,
    backwards or forwards, cannot grow the evidence file, and grows the state only up to those two rings — every
    request rewrites and fsyncs the state file at most once (the cost of remembering it).
    The read-check-write on the state file is under an exclusive file lock (POSIX flock on <state>.lock), so a
    CLI `cosign` and a `serve` process on the same state cannot interleave; on a platform without fcntl the
    assumption is one process per state file."""
    out = {"stato": STATO_RIFIUTO, "motivo": None, "note": None, "cosignature": None, "evidenza": None, "origin": None,
           "size": None, "http_status": 400, "stored_size": None}
    try:
        C.split_note(note)
    except C.NoteError as e:
        out["motivo"] = f"malformed note: {e}"; return out
    log_vkeys = [log_vkey] if isinstance(log_vkey, str) else list(log_vkey)
    if not log_vkeys:
        raise C.NoteError("at least one trusted log vkey is required")
    if any(C.parse_vkey(k)[2] not in LOG_KEY_TYPES for k in log_vkeys):
        raise C.NoteError("a log key must be an Ed25519 (0x01) or ECDSA (0x02) note key, not a cosigner key")
    v = C.verify_note(note, log_vkeys)
    if v["stato"] != "OK":
        out.update(motivo=f"log signature: {v['stato']} ({v['motivo']})", http_status=403 if v["stato"] == "NON_VALIDA" else 500)
        return out
    log_names = {C.parse_vkey(k)[0] for k in log_vkeys}
    if not any(s["name"] in log_names and s["type"] in LOG_KEY_TYPES for s in v["verified"]):
        out.update(motivo="no log signature (type 0x01/0x02) from a trusted log key", http_status=403); return out
    if expected_origin is None and len(log_names) != 1:
        raise C.NoteError("trusted keys with different names for one origin need an explicit expected_origin")
    try:
        cp = C.parse_checkpoint(v["text"])
    except C.NoteError as e:
        out["motivo"] = f"checkpoint text: {e}"; return out
    out["origin"], out["size"] = cp["origin"], cp["size"]
    if cp["origin"] != (next(iter(log_names)) if expected_origin is None else expected_origin):
        out["motivo"] = "checkpoint origin is not the origin trusted for this log key"; return out
    proof = list(consistency_proof_b64 or [])
    if len(proof) > _MAX_PROOF:
        out["motivo"] = f"more than {_MAX_PROOF} consistency proof lines"; return out
    trusted = {(C.parse_vkey(k)[0], C.parse_vkey(k)[1]) for k in log_vkeys}
    lines = note.decode("utf-8")[len(v["text"]) + 1:].split("\n")[:-1]     # exactly the lines split_note validated
    _, sigs = C.split_note(note)
    trusted_lines = list(dict.fromkeys(l + "\n" for l, (name, raw) in zip(lines, sigs) if (name, raw[:4]) in trusted))
    own_kids = {C.key_id(witness_name, C.TYPE_COSIG_V1, C.pubkey_from_seed(witness_seed))}
    if pq_seed is not None:
        own_kids.add(C.key_id(witness_name, C.TYPE_MLDSA44, C.mldsa44_pubkey_from_seed(pq_seed)))
    kept = [l for l, (name, raw) in zip(lines, sigs) if not (name == witness_name and raw[:4] in own_kids)]
    if pq_seed is not None and len(cp["origin"].encode("utf-8")) > 255:
        out["motivo"] = "an ML-DSA-44 cosignature cannot cover an origin longer than 255 bytes (tlog-cosignature)"; return out
    n_lines = 1 + (1 if pq_seed is not None else 0)
    if len(kept) + n_lines > C._MAX_SIGS:   # our line(s) would pass 100: no conformant verifier could open the result
        out["motivo"] = f"no room for a cosignature line: {len(kept)} signature lines, verifiers accept {C._MAX_SIGS}"; return out
    with _state_lock(state_path):
        return _cosign_locked(state_path, cp, proof, witness_name, witness_seed, timestamp, old_size, out, v, trusted_lines, kept, pq_seed)


def _cosign_locked(state_path, cp, proof, witness_name, witness_seed, timestamp, old_size, out, v, trusted_lines, kept, pq_seed=None) -> Dict:
    st = _load_state(state_path)
    origin = cp["origin"]
    prev = st["origins"].get(origin)
    stored_size = prev["size"] if prev is not None else 0
    out["stored_size"] = stored_size
    if timestamp is not None and prev is not None and timestamp < prev.get("cosigned_at", 0):   # before ANY effect
        raise C.NoteError("the cosignature timestamp is older than the last one stored for this origin")
    presentato = v["text"] + "\n" + "".join(trusted_lines)   # text + the trusted log key's lines only (no padding)
    root_b64 = base64.b64encode(cp["root"]).decode("ascii")
    if timestamp is not None and (not isinstance(timestamp, int) or isinstance(timestamp, bool) or not (1 <= timestamp <= 2 ** 63 - 1)):
        raise C.NoteError("the timestamp must be a POSIX integer in [1, 2^63-1] (the spec: MUST NOT be zero)")
    registrato = int(time.time()) if timestamp is None else timestamp

    def _record(ev):
        with open(state_path + ".evidence.jsonl", "a", encoding="utf-8") as f:   # under the same lock as the state
            f.write(json.dumps(ev, ensure_ascii=False) + "\n"); f.flush(); os.fsync(f.fileno())

    def _ev(tipo, prova, precedente_note, size_prec):
        return {"tipo": tipo, "prova": prova, "origin": origin, "size_precedente": size_prec, "size_presentato": cp["size"],
                "precedente": precedente_note, "presentato": presentato, "registrato": registrato}

    dirty = [False]                        # the state is written ONCE per request, at the end (round 9: it was twice)

    def _flush():
        if dirty[0]:
            _save_state(state_path, st); dirty[0] = False

    def _proof(other_note, other_root):
        """A split-view pair (two log-signed roots at one size): written ONCE per pair to the evidence file (a half
        record — the other note not kept — does not stop the full pair from being written later). Only proofs are
        persisted there, so its growth is bounded by the log's own misbehaviour."""
        key = hashlib.sha256((origin + "\x00" + str(cp["size"]) + "\x00" + "\x00".join(sorted((other_root, root_b64)))).encode()).hexdigest()
        key += "|full" if other_note is not None else "|half"
        seen = st.setdefault("proofs_seen", [])
        if key in seen:
            return                         # already recorded: nothing changes, nothing is written
        dirty[0] = True
        seen.append(key)
        if len(seen) > _PROOFS_SEEN:       # bounded: after that a very old pair could be recorded twice (a duplicate, not a loss)
            del seen[:-_PROOFS_SEEN]
        if other_note is None:             # the earlier note was above _PENDING_NOTE and not kept: the pair is half here
            _record(_ev("split-view-unkept", False, None, cp["size"]) | {"precedente_root_b64": other_root})
        else:
            _record(_ev("split-view", True, other_note, cp["size"]))
        # the state (proofs_seen) is saved once by the caller at the end of the request, not per pair

    def _cosigned_at(size):
        """The checkpoints this witness COSIGNED at `size`, from the LAST _HISTORY_SCAN bytes of <state>.cosigned.jsonl
        (one line per cosign): a rollback is compared with the recent cosigned history, not the whole file, so an
        unauthenticated refusal costs a bounded read under the lock — stated. {root_b64: note}."""
        found = {}
        try:
            with open(state_path + ".cosigned.jsonl", "rb") as f:
                f.seek(0, os.SEEK_END); end = f.tell()
                start = max(0, end - _HISTORY_SCAN)
                cut_mid_line = False
                if start > 0:
                    f.seek(start - 1); cut_mid_line = f.read(1) != b"\n"
                f.seek(start); chunk = f.read()
            lines = chunk.split(b"\n")
            if cut_mid_line:
                lines = lines[1:]           # the first piece is the tail of a cut line (a full line is kept)
            for line in lines:
                try:
                    rec = json.loads(line.decode("utf-8"))
                except ValueError:
                    continue
                if not isinstance(rec, dict):
                    continue
                if (rec.get("origin") == origin and rec.get("size") == size and isinstance(rec.get("root_b64"), str)
                        and isinstance(rec.get("note"), str) and rec["note"]):
                    found.setdefault(rec["root_b64"], rec["note"])
        except FileNotFoundError:
            pass
        return found

    def _refused(tipo):
        """A refusal that is NOT proof (`rollback`, `unproven-extension`): the pair goes back to the caller, the
        state keeps a per-origin counter and the last 100 (_RING) refusals as size/root/time. Any proof hidden in a
        rollback is extracted: a different log-signed root at a size this witness cosigned (history file) is a
        split-view pair. (Roots beyond the stored size are handled by _note_future, before the old-size gate.)"""
        ev = out["evidenza"] or _ev(tipo, False, prev["note"], prev["size"])
        ring = st.setdefault("refusals", {}).setdefault(origin, {"count": 0, "last": []})
        if not any(e.get("tipo") == tipo and e.get("size") == cp["size"] and e.get("root_b64") == root_b64 for e in ring["last"]):
            ring["count"] += 1             # distinct refusals remembered; a replay of one already in the ring changes nothing
            ring["last"] = (ring["last"] + [{"tipo": tipo, "size": cp["size"], "root_b64": root_b64, "quando": registrato}])[-_RING:]
            dirty[0] = True
        if cp["size"] < stored_size:
            candidates = {e["root_b64"]: None for e in ring["last"] if e.get("size") == cp["size"] and e["root_b64"] != root_b64}   # refused here before (root only)
            candidates.update(st.get("pending", {}).get(origin, {}).get(str(cp["size"]), {}))   # roots refused earlier at that size
            candidates.update(_cosigned_at(cp["size"]))
            for other_root, other_note in sorted(candidates.items(), key=lambda kv: kv[1] is None):   # a full note first
                if other_root != root_b64:
                    _proof(other_note, other_root)
                    ev = (_ev("split-view", True, other_note, cp["size"]) if other_note is not None
                          else _ev("split-view-unkept", False, None, cp["size"]) | {"precedente_root_b64": other_root})
                    break                  # one pair is proof; a log signing many roots does not buy many fsyncs
        _flush()
        return ev

    def _note_future():
        """A log-signed root BEYOND the stored size, seen before the old-size gate (so the discovery request "old 0"
        counts too): compared with the roots already pending at that size — two log-signed roots at one size are
        proof — then kept in `pending` so that a later cosign at that size can turn it into proof. Bounded per origin
        in count (_RING notes) and in bytes (_PENDING_BYTES), the SMALLEST pending sizes dropped first (by size, not by
        insertion time: a recorded proof is never erased, only a root still waiting for a partner); a note above _PENDING_NOTE
        bytes is compared but not kept. A dropped root cannot become proof later — stated."""
        pend_o = st.setdefault("pending", {}).setdefault(origin, {})
        pend = pend_o.setdefault(str(cp["size"]), {})
        # one pair per request is proof enough: a log signing many roots at one size does not buy a record and an
        # fsync per pair (round 8: the pairing was quadratic); the preferred partner is one whose note was kept
        partner = next((r for r, n in pend.items() if r != root_b64 and n is not None),
                       next((r for r in pend if r != root_b64), None))
        if partner is not None:
            other_note = pend[partner]
            _proof(other_note, partner)
            out["evidenza"] = (_ev("split-view", True, other_note, cp["size"]) if other_note is not None
                               else _ev("split-view-unkept", False, None, cp["size"]) | {"precedente_root_b64": partner})
        # a note above _PENDING_NOTE is remembered by its root only (None): a later conflicting root still pairs
        # with it, as a `split-view-unkept` record (the root, not the note — stated), never silently; a root seen
        # oversized first and small later is upgraded to its note. Nothing new → nothing written.
        small = presentato if len(presentato.encode("utf-8")) <= _PENDING_NOTE else None
        if root_b64 not in pend or (pend[root_b64] is None and small is not None):
            pend[root_b64] = small; dirty[0] = True
        while pend_o and (sum(len(r) for r in pend_o.values()) > _RING
                          or sum(len(n.encode("utf-8")) for r in pend_o.values() for n in r.values() if n) > _PENDING_BYTES):
            oldest = min(pend_o, key=int)
            pend_o[oldest].pop(next(iter(pend_o[oldest])))
            if not pend_o[oldest]:
                del pend_o[oldest]
            dirty[0] = True
    # before the old-size gate (over HTTP the rule answers 400/409 first — the discovery request "old 0" included —
    # and no proof must be lost to that): an older checkpoint than the last cosigned one, a DIFFERENT root at the
    # stored size, or a root beyond the stored size are all looked at now
    if cp["size"] == 0 and cp["root"] != EMPTY_ROOT:
        pass                               # a malformed size-0 checkpoint: the 422 below, no evidence from it
    elif prev is not None and cp["size"] < prev["size"]:
        out["evidenza"] = _refused("rollback")
    elif prev is not None and cp["size"] == prev["size"] and root_b64 != prev["root_b64"]:
        _proof(prev["note"], prev["root_b64"]); out["evidenza"] = _ev("split-view", True, prev["note"], prev["size"])
        _flush()
    elif cp["size"] > stored_size and not (cp["size"] == 0):
        _note_future()                     # also for an origin never cosigned (stored size 0): "beyond" is beyond
    if old_size is not None:
        if not isinstance(old_size, int) or isinstance(old_size, bool) or old_size < 0 or old_size > cp["size"]:
            out["motivo"] = f"old size {old_size} is not a valid size at most {cp['size']}"; _flush(); return out
        if old_size != stored_size:
            out.update(motivo=f"old size {old_size} != last cosigned {stored_size}", http_status=409); _flush(); return out
    if cp["size"] == 0 and cp["root"] != EMPTY_ROOT:
        out.update(motivo="a size-0 checkpoint must carry the empty-tree root", http_status=422); _flush(); return out
    if prev is not None:
        prev_root = base64.b64decode(prev["root_b64"])
        if cp["size"] < prev["size"]:
            out["motivo"] = f"rollback: size {cp['size']} < last cosigned {prev['size']}"
            _flush(); return out
        if cp["size"] == prev["size"] and cp["root"] != prev_root:
            out.update(motivo="equivocation: same size, different root", http_status=422)   # proof recorded above
            _flush(); return out
        if prev["size"] == 0 or cp["size"] == prev["size"]:
            if proof:                       # the empty tree is consistent with any tree; the same tree needs no proof
                out.update(motivo="a proof was sent where none is possible (old size 0 or same size)", http_status=422); _flush(); return out
        elif not C.verify_consistency_b64(prev["size"], prev_root, cp["size"], cp["root"], proof):
            out.update(motivo="no valid consistency proof from the last cosigned checkpoint", http_status=422)
            out["evidenza"] = _refused("unproven-extension")   # saves once
            return out
    elif proof:
        out.update(motivo="a proof was sent for a first checkpoint (old size 0)", http_status=422); _flush(); return out
    # about to cosign: a root the log signed at this size that we refused earlier without proof (pending) is now
    # contradicted by a log-signed one that extends the tree — proof. Pending roots at OTHER sizes we are passing are
    # kept (the ring bounds them): a later rollback to one of those sizes with a different root still pairs up
    pend_origin = st.get("pending", {}).get(origin, {})
    if out["evidenza"] is None:            # _note_future already paired this root once in this request: one pair per request
        for other_root, other_note in pend_origin.get(str(cp["size"]), {}).items():
            if other_root != root_b64:
                _proof(other_note, other_root)
                break
    pend_origin.pop(str(cp["size"]), None)
    if timestamp is None:                 # the clock, as the reference witness does (time.Now()): a stored timestamp
        ts = int(time.time())             # from a clock that was once ahead must not be carried forward (round 10)
    else:
        ts = timestamp
        if not isinstance(ts, int) or isinstance(ts, bool) or ts <= 0:
            raise C.NoteError("the cosignature timestamp must be a positive integer (the spec: MUST NOT be zero)")
    # a note that already carries this witness's line (re-cosign of the same view) gets it REPLACED, not appended:
    # Go's verifier keeps the first line per key, so an appended fresher line would never count there
    base = (v["text"] + "\n" + "".join(l + "\n" for l in kept)).encode("utf-8")
    cosigned = C.cosign_v1(base, witness_name, witness_seed, ts)
    if pq_seed is not None:                # the ML-DSA-44 line the witness spec now recommends, beside the Ed25519 one
        cosigned = C.cosign_v1_mldsa44(cosigned, witness_name, pq_seed, ts)
    # the state keeps text + trusted log lines + our own line: lines from keys this witness does not know are not
    # evidence of anything and would otherwise be rewritten on every cosign and copied into every record
    stored = presentato + cosigned[len(base):].decode("utf-8")
    if prev is None or prev["root_b64"] != root_b64 or prev["size"] != cp["size"]:   # a NEW cosigned checkpoint: to the history
        with open(state_path + ".cosigned.jsonl", "a", encoding="utf-8") as f:
            f.write(json.dumps({"origin": origin, "size": cp["size"], "root_b64": root_b64, "note": stored, "cosigned_at": ts},
                               ensure_ascii=False) + "\n"); f.flush(); os.fsync(f.fileno())
    st["origins"][origin] = {"size": cp["size"], "root_b64": root_b64, "note": stored, "cosigned_at": ts}
    _save_state(state_path, st)
    out.update(stato=STATO_OK, note=cosigned, cosignature=cosigned[len(base):], http_status=200)
    return out


def verify_witnessed(note: bytes, log_vkey: Union[str, List[str]], witness_vkeys: List[str], min_witnesses: int = 1,
                     max_age_s: Optional[int] = None, now: Optional[int] = None, clock_skew_s: int = 0,
                     expected_origin: Optional[str] = None) -> Dict:
    """Relying-party check: log signature OK (one vkey or a list, for rotation), the checkpoint origin is
    `expected_origin` (default: the log key name — pass it explicitly for logs such as sum.golang.org whose origin
    differs), at least `min_witnesses` (≥ 1) DISTINCT trusted witnesses — distinct by NAME: two keys of one name are
    one witness (rotation) — cosigned this
    exact text — and, if max_age_s is given, at least `min_witnesses` of them with a cosignature younger than
    max_age_s (each witness counted by its newest verified cosignature, whatever the line order; a stale witness
    does not count); with max_age_s, a witness whose newest cosignature is more than `clock_skew_s` in the future
    does not count either (`future_witnesses`; the spec: MAY reject) — without max_age_s no clock is consulted. Returns {stato: OK|NON_VALIDA|NON_VERIFICATA, witnesses: [all trusted], fresh_witnesses, future_witnesses,
    freshness_s (age of the newest non-future cosignature), motivo, checkpoint}."""
    if not isinstance(min_witnesses, int) or isinstance(min_witnesses, bool) or min_witnesses < 1:
        raise C.NoteError("min_witnesses must be an integer >= 1 (a relying party that needs no witness has no freshness)")
    if not isinstance(clock_skew_s, int) or isinstance(clock_skew_s, bool) or clock_skew_s < 0:
        raise C.NoteError("clock_skew_s must be a non-negative integer")
    out = {"stato": "NON_VALIDA", "witnesses": [], "fresh_witnesses": None, "future_witnesses": None, "freshness_s": None,
           "motivo": None, "checkpoint": None}
    log_vkeys = [log_vkey] if isinstance(log_vkey, str) else list(log_vkey)
    if not log_vkeys:
        raise C.NoteError("at least one trusted log vkey is required")
    log_names = {C.parse_vkey(k)[0] for k in log_vkeys}
    if any(C.parse_vkey(k)[2] not in LOG_KEY_TYPES for k in log_vkeys):
        raise C.NoteError("a log key must be an Ed25519 (0x01) or ECDSA (0x02) note key, not a cosigner key")
    if expected_origin is None and len(log_names) != 1:
        raise C.NoteError("trusted log keys with different names need an explicit expected_origin")
    origin = next(iter(log_names)) if expected_origin is None else expected_origin
    usable = []
    for wv in witness_vkeys:                 # Ed25519 (0x04) and ML-DSA-44 (0x06) cosigners are verified; other types
        typ = C.parse_vkey(wv, strict=False)[2]   # are ignored as verify_note does; a log key in the witness list is a caller error
        if typ in LOG_KEY_TYPES:
            raise C.NoteError("witness vkeys must be cosigner keys (type 0x04 or 0x06): a log key is not a witness")
        if typ in (C.TYPE_COSIG_V1, C.TYPE_MLDSA44):
            usable.append(wv)
    witness_vkeys = usable
    v = C.verify_note(note, log_vkeys + list(witness_vkeys))
    if v["stato"] == "NON_VERIFICATA":
        out.update(stato="NON_VERIFICATA", motivo=v["motivo"]); return out
    if v["stato"] != "OK":
        out["motivo"] = v["motivo"]; return out
    if not any(s["name"] in log_names and s["type"] in LOG_KEY_TYPES for s in v["verified"]):
        out["motivo"] = "no log signature from a trusted log key"; return out
    try:
        out["checkpoint"] = {k: (base64.b64encode(val).decode("ascii") if k == "root" else val) for k, val in C.parse_checkpoint(v["text"]).items()}
    except C.NoteError as e:
        out["motivo"] = f"checkpoint text: {e}"; return out
    if out["checkpoint"]["origin"] != origin:
        out["motivo"] = f"checkpoint origin {out['checkpoint']['origin']!r} is not the expected {origin!r}"; return out
    wits: Dict[str, int] = {}
    for s_ in v["verified"]:                 # every line of a trusted witness key was verified: the newest per witness counts
        if s_["type"] in (C.TYPE_COSIG_V1, C.TYPE_MLDSA44):
            wits[s_["name"]] = max(wits.get(s_["name"], 0), s_["timestamp"])
    out["witnesses"] = sorted(wits)
    if len(wits) < min_witnesses:
        out["motivo"] = f"{len(wits)} trusted witness cosignature(s), {min_witnesses} required"; return out
    if max_age_s is not None:
        now = int(time.time()) if now is None else now
        future = sorted(n for n, t in wits.items() if t > now + clock_skew_s)   # not trusted for freshness (spec: MAY reject)
        out["future_witnesses"] = future
        present = {n: t for n, t in wits.items() if n not in future}
        out["freshness_s"] = now - max(present.values()) if present else None
        out["fresh_witnesses"] = sorted(n for n, t in present.items() if now - t <= max_age_s)
        if len(out["fresh_witnesses"]) < min_witnesses:
            out["motivo"] = (f"{len(out['fresh_witnesses'])} witness cosignature(s) younger than {max_age_s} s, "
                             f"{min_witnesses} required" + (f" (newest is {out['freshness_s']} s old)" if present else "")
                             + (f"; in the future: {', '.join(future)}" if future else "")); return out
    out["stato"] = "OK"
    return out


# ── tlog-witness HTTP interface (c2sp.org/tlog-witness §HTTP Interface) ──────────────────────────────────────────
def parse_add_checkpoint_body(body: bytes):
    """→ (old_size, proof_b64 list, checkpoint note bytes) or raises NoteError. Body = "old <n>\\n", proof lines,
    an empty line, then the checkpoint note (which itself ends with its signature lines)."""
    try:
        s = body.decode("utf-8")
    except UnicodeDecodeError:
        raise C.NoteError("body is not UTF-8") from None
    head, sep, note = s.partition("\n\n")
    if not sep:
        raise C.NoteError("body has no empty line between the proof and the checkpoint")
    if not note:
        raise C.NoteError("missing checkpoint")
    if note.startswith("\n"):               # "old 0\n\n\n<note>": an empty proof line, not an unknown origin
        raise C.NoteError("empty proof line")
    lines = head.split("\n")
    m = re.fullmatch(r"old (0|[1-9][0-9]{0,19})", lines[0])   # a uint64 has at most 20 digits
    if not m:
        raise C.NoteError("first line must be 'old <size>'")
    proof = lines[1:]
    if len(proof) > _MAX_PROOF:
        raise C.NoteError(f"more than {_MAX_PROOF} proof lines")
    for p_ in proof:
        try:
            if len(C.b64decode_strict(p_)) != 32:
                raise C.NoteError("proof hash must be 32 bytes")
        except ValueError:               # binascii.Error or non-ASCII (round 2: the same defect as in the checkpoint module)
            raise C.NoteError("proof line is not standard base64") from None
    return int(m.group(1)), proof, note.encode("utf-8")


def format_add_checkpoint_body(old_size: int, proof_b64: List[str], note: bytes) -> bytes:
    return (f"old {old_size}\n" + "".join(p + "\n" for p in proof_b64) + "\n").encode("utf-8") + note


class WitnessService:
    """One witness key, a set of trusted logs (origin → vkey), a state file, one lock: the check-and-persist of
    `add_checkpoint` is atomic (the race the spec describes: two requests interleaving would roll the state back)."""

    def __init__(self, state_path: str, name: str, seed: bytes, log_vkeys: List[str],
                 origins: Optional[Dict[str, Union[str, List[str]]]] = None, pq_seed: Optional[bytes] = None):
        """`log_vkeys`: logs whose origin IS the key name; `origins`: {origin: vkey | [vkeys]} for logs whose origin
        differs. Several vkeys for one origin = key rotation: any of them may sign (the spec: "public key(s) it trusts")."""
        self.state_path, self.name, self.seed, self.pq_seed = state_path, name, seed, pq_seed
        self.logs: Dict[str, List[str]] = {}

        def _log_key(v):
            name, _, typ, _ = C.parse_vkey(v)
            if typ not in LOG_KEY_TYPES:
                raise C.NoteError(f"{name}: a log key must be an Ed25519 (0x01) or ECDSA (0x02) note key, not a cosigner key")
            return name
        for v in log_vkeys:
            self.logs.setdefault(_log_key(v), []).append(v)
        for origin, vs in (origins or {}).items():
            if not origin or any(ord(c) < 0x20 for c in origin):
                raise C.NoteError("origin must be a non-empty line without control characters")
            for v in ([vs] if isinstance(vs, str) else vs):
                _log_key(v); self.logs.setdefault(origin, []).append(v)
        if not self.logs:
            raise C.NoteError("a witness needs at least one trusted log")
        self.lock = threading.Lock()

    def add_checkpoint(self, body: bytes, timestamp: Optional[int] = None):
        """→ (http status, response body bytes, content type). 200: the witness signature line(s) only."""
        try:
            old_size, proof, note = parse_add_checkpoint_body(body)
        except C.NoteError as e:
            return 400, (str(e) + "\n").encode(), "text/plain"
        origin = note.split(b"\n", 1)[0].decode("utf-8", "replace")
        vk = self.logs.get(origin)
        if vk is None:
            return 404, b"unknown log origin\n", "text/plain"
        try:
            with self.lock:
                r = witness_cosign(self.state_path, note, vk, self.name, self.seed, proof, timestamp, old_size=old_size,
                                   expected_origin=origin, pq_seed=self.pq_seed)
        except (C.NoteError, OSError) as e:   # state file unreadable, disk full, config error: 500 with the reason, never a dropped connection
            sys.stderr.write(f"witness: {e}\n")
            return 500, b"witness error\n", "text/plain"
        if r["http_status"] == 409:
            return 409, f"{r['stored_size']}\n".encode(), "text/x.tlog.size"
        if r["stato"] != STATO_OK:
            return r["http_status"], (str(r["motivo"]) + "\n").encode(), "text/plain"
        return 200, r["cosignature"], "text/plain"   # the line cosign_v1 appended (the note may have lost our old line)


def serve(service: WitnessService, host: str = "127.0.0.1", port: int = 0, prefix: str = ""):
    """Start the stdlib HTTP server (returns it; `serve_forever` is the caller's). POST <prefix>/add-checkpoint."""
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    class H(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"   # keep-alive, which the spec says witnesses SHOULD support (Content-Length is always sent)
        timeout = 30                 # a client that never sends its body does not hold the thread forever

        def log_message(self, *a):   # quiet
            pass

        def do_POST(self):
            if self.path != prefix + "/add-checkpoint":
                self.send_response(404); self.send_header("Content-Length", "0"); self.send_header("Connection", "close"); self.end_headers(); return
            try:
                cls = self.headers.get_all("Content-Length") or []
                if len(set(cls)) != 1 or "Transfer-Encoding" in self.headers:   # RFC 9112 §6.3: one length, no chunked
                    raise ValueError(cls)
                cl = cls[0]
                if not re.fullmatch(r"0|[1-9][0-9]{0,9}", cl):   # strict decimal, as everywhere else (no '+', '_', spaces)
                    raise ValueError(cl)
                n = int(cl)
            except ValueError:
                self.send_response(400); self.send_header("Content-Length", "0"); self.send_header("Connection", "close"); self.end_headers(); return
            if n < 0:
                self.send_response(400); self.send_header("Content-Length", "0"); self.send_header("Connection", "close"); self.end_headers(); return
            if n > 2 << 20:                  # 2 MiB: room for a note with 100 lines of 8 KiB plus the proof
                self.send_response(413); self.send_header("Content-Length", "0"); self.send_header("Connection", "close"); self.end_headers(); return
            try:
                status, body, ctype = service.add_checkpoint(self.rfile.read(n))
            except Exception as e:           # noqa: BLE001 — the spec wants a status for every outcome
                sys.stderr.write(f"witness: unexpected {e!r}\n")
                status, body, ctype = 500, b"witness error\n", "text/plain"; self.close_connection = True
            self.send_response(status)
            self.send_header("Content-Type", ctype); self.send_header("Content-Length", str(len(body)))
            self.end_headers(); self.wfile.write(body)

    return ThreadingHTTPServer((host, port), H)


def add_checkpoint(url: str, note: bytes, old_size: int, proof_b64: List[str], timeout: float = 30.0):
    """Client side: POST to <url>/add-checkpoint → (status, body bytes). No retry, no interpretation."""
    import urllib.request, urllib.error
    req = urllib.request.Request(url.rstrip("/") + "/add-checkpoint", data=format_add_checkpoint_body(old_size, proof_b64, note),
                                 method="POST", headers={"Content-Type": "text/plain"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read(1 << 20)     # a hostile witness cannot make us read more than 1 MiB
    except urllib.error.HTTPError as e:
        return e.code, e.read(1 << 20)
    except (urllib.error.URLError, OSError, ValueError) as e:   # unreachable, timeout, bad URL: status 0, never a traceback
        return 0, f"no response: {e}".encode("utf-8")


def submit_checkpoint(url: str, note: bytes, leaves: List[bytes], witness_vkeys: List[str], log_vkey: str,
                      expected_origin: Optional[str] = None) -> Dict:
    """Submit a log-signed checkpoint of `leaves` to a witness: first with old size 0; on 409 again with the size the
    witness answered and our consistency proof from that size. The returned cosignature lines are appended to the
    note and verified with the trusted witness keys BEFORE being accepted (unknown keys ignored, as the spec says).
    → {stato: OK|NON_VALIDA, status, note, witnesses, motivo}."""
    out = {"stato": "NON_VALIDA", "status": None, "note": None, "witnesses": [], "motivo": None}
    for w in witness_vkeys:                  # validated BEFORE the network round trip (the witness would persist first)
        if C.parse_vkey(w, strict=False)[2] in LOG_KEY_TYPES:
            raise C.NoteError("witness vkeys must be cosigner keys (type 0x04 or 0x06): a log key is not a witness")
    C.parse_vkey(log_vkey) if isinstance(log_vkey, str) else [C.parse_vkey(k) for k in log_vkey]
    status, body = add_checkpoint(url, note, 0, [])
    if status == 409:
        m = re.fullmatch(r"(0|[1-9][0-9]{0,19})\n", body.decode("ascii", "replace"))   # decimal (uint64) + newline, nothing else
        if not m:
            out.update(status=status, motivo="409 without a parsable size"); return out
        old = int(m.group(1))
        if not (0 < old <= len(leaves)):
            out.update(status=status, motivo=f"witness knows size {old}, we have {len(leaves)}"); return out
        status, body = add_checkpoint(url, note, old, C.consistency_proof_b64(leaves, old) if old < len(leaves) else [])
    out["status"] = status
    if status != 200:
        out["motivo"] = f"HTTP {status}: {body.decode('utf-8', 'replace').strip()[:200]}"; return out
    if not body.endswith(b"\n") or not all(l.startswith("— ") for l in body.decode("utf-8", "replace").rstrip("\n").split("\n")):
        out["motivo"] = "response is not a sequence of signature lines"; return out
    # only lines from TRUSTED witness keys are taken from the response (the spec: the client MUST ignore cosignatures
    # from unknown keys — a witness answering with padding lines must not fill our note); each one REPLACES an older
    # line of the same key already in our note (Go verifiers keep the first line per key)
    try:
        trusted = {(C.parse_vkey(w, strict=False)[0], C.parse_vkey(w, strict=False)[1]) for w in witness_vkeys}
        text, own = C.split_note(note)
        _, new = C.split_note(note + body)
        body_lines = body.decode("utf-8").split("\n")[:-1]
        keep_new = [(l, n, r) for l, (n, r) in zip(body_lines, new[len(own):]) if (n, r[:4]) in trusted]
        if not keep_new:
            out["motivo"] = "200 without a cosignature line from a trusted witness key"; return out
        new_keys = {(n, r[:4]) for _, n, r in keep_new}
        lines = note.decode("utf-8")[len(text) + 1:].split("\n")[:-1]
        kept = "".join(l + "\n" for l, (n, r) in zip(lines, own) if (n, r[:4]) not in new_keys)
        cosigned = (text + "\n" + kept + "".join(l + "\n" for l, _, _ in keep_new)).encode("utf-8")
    except (C.NoteError, UnicodeDecodeError) as e:
        out["motivo"] = f"response is not a sequence of signature lines: {e}"; return out
    v = verify_witnessed(cosigned, log_vkey, witness_vkeys, min_witnesses=1, expected_origin=expected_origin)
    if v["stato"] != "OK":
        out["motivo"] = f"cosignature does not verify with the trusted witness keys: {v['motivo']}"; return out
    out.update(stato="OK", note=cosigned, witnesses=sorted({n for _, n, _ in keep_new}))   # the witnesses that answered NOW
    return out


def main(argv=None) -> int:
    import argparse
    ap = argparse.ArgumentParser(description="witness for C2SP checkpoints of cryptovalid ledgers")
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("cosign"); c.add_argument("note"); c.add_argument("--state", required=True); c.add_argument("--log-vkey", required=True)
    c.add_argument("--name", required=True); c.add_argument("--key", required=True); c.add_argument("--proof", help="JSON list of base64 hashes")
    c.add_argument("--pq-key", help="32-byte hex seed of an ML-DSA-44 cosigner key: adds a type-0x06 line beside the Ed25519 one")
    c.add_argument("--out", required=True)
    w = sub.add_parser("verify"); w.add_argument("note"); w.add_argument("--log-vkey", required=True); w.add_argument("--witness-vkey", action="append", default=[])
    w.add_argument("--min-witnesses", type=int, default=1); w.add_argument("--max-age", type=int)
    w.add_argument("--clock-skew", type=int, default=0); w.add_argument("--origin", help="expected origin when it differs from the log key name")
    sv = sub.add_parser("serve", help="tlog-witness HTTP witness: POST <prefix>/add-checkpoint")
    sv.add_argument("--state", required=True); sv.add_argument("--name", required=True); sv.add_argument("--key", required=True)
    sv.add_argument("--pq-key", help="32-byte hex seed of an ML-DSA-44 cosigner key (the cosignature type the witness spec recommends)")
    sv.add_argument("--log-vkey", action="append", default=[], help="trusted log key whose name is the origin")
    sv.add_argument("--log-origin", action="append", nargs=2, default=[], metavar=("ORIGIN", "VKEY"), help="trusted log key for an origin that differs from the key name (repeatable: key rotation)")
    sv.add_argument("--host", default="127.0.0.1")
    sv.add_argument("--port", type=int, default=8477); sv.add_argument("--prefix", default="")
    sm = sub.add_parser("submit", help="sign a ledger checkpoint and submit it to a tlog-witness URL")
    sm.add_argument("ledger"); sm.add_argument("--origin", required=True); sm.add_argument("--key", required=True, help="log key (hex seed)")
    sm.add_argument("--url", required=True); sm.add_argument("--witness-vkey", action="append", required=True); sm.add_argument("--out", required=True)
    a = ap.parse_args(argv)
    if a.cmd == "serve":
        if not a.log_vkey and not a.log_origin:
            ap.error("at least one --log-vkey or --log-origin is required")
        origins: Dict[str, List[str]] = {}
        for origin, vk in a.log_origin:
            origins.setdefault(origin, []).append(vk)
        try:
            svc = WitnessService(a.state, a.name, C.load_seed_hex(a.key), a.log_vkey, origins,
                                 pq_seed=C.load_seed_hex(a.pq_key) if a.pq_key else None)
        except (C.NoteError, OSError) as e:
            print(json.dumps({"stato": "ERRORE", "motivo": str(e)}, ensure_ascii=False)); return 2
        httpd = serve(svc, a.host, a.port, a.prefix)
        try:
            print(json.dumps({"listening": f"http://{httpd.server_address[0]}:{httpd.server_address[1]}{a.prefix}/add-checkpoint",
                              "witness": C.vkey(a.name, C.TYPE_COSIG_V1, C.pubkey_from_seed(svc.seed)),
                              "witness_mldsa44": C.vkey(a.name, C.TYPE_MLDSA44, C.mldsa44_pubkey_from_seed(svc.pq_seed)) if svc.pq_seed else None,
                              "logs": sorted(svc.logs)}), flush=True)
        except C.NoteError as e:
            print(json.dumps({"stato": "ERRORE", "motivo": str(e)}, ensure_ascii=False)); return 2
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            pass
        return 0
    if a.cmd == "submit":
        try:
            seed = C.load_seed_hex(a.key)
            text, leaves = C.ledger_checkpoint(a.ledger, a.origin)
            note = C.sign_note(text, a.origin, seed)
            r = submit_checkpoint(a.url, note, leaves, a.witness_vkey, C.vkey(a.origin, C.TYPE_ED25519, C.pubkey_from_seed(seed)))
            if r["note"]:
                with open(a.out, "wb") as f:
                    f.write(r["note"])
        except (C.NoteError, OSError, ValueError) as e:
            print(json.dumps({"stato": "ERRORE", "motivo": str(e)}, ensure_ascii=False)); return 2
        print(json.dumps({k: v for k, v in r.items() if k != "note"}, ensure_ascii=False)); return 0 if r["stato"] == "OK" else 1
    if a.cmd == "cosign":
        try:
            with open(a.note, "rb") as f:
                note = f.read()
            proof = json.loads(a.proof) if a.proof else None
            if proof is not None and not (isinstance(proof, list) and all(isinstance(x, str) for x in proof)):
                raise C.NoteError("--proof must be a JSON list of base64 strings")
            r = witness_cosign(a.state, note, a.log_vkey, a.name, C.load_seed_hex(a.key), proof,
                               pq_seed=C.load_seed_hex(a.pq_key) if a.pq_key else None)
        except (C.NoteError, OSError, ValueError) as e:
            print(json.dumps({"stato": "ERRORE", "motivo": str(e)}, ensure_ascii=False)); return 2
        if r["note"]:
            with open(a.out, "wb") as f:
                f.write(r["note"])
        r["cosignature"] = r["cosignature"].decode("utf-8") if r["cosignature"] else None
        print(json.dumps({k: v for k, v in r.items() if k != "note"}, ensure_ascii=False)); return 0 if r["stato"] == STATO_OK else 1
    try:
        with open(a.note, "rb") as f:
            note = f.read()
        r = verify_witnessed(note, a.log_vkey, a.witness_vkey, a.min_witnesses, a.max_age, clock_skew_s=a.clock_skew, expected_origin=a.origin)
    except (C.NoteError, OSError) as e:
        print(json.dumps({"stato": "ERRORE", "motivo": str(e)}, ensure_ascii=False)); return 2
    print(json.dumps(r, ensure_ascii=False)); return 0 if r["stato"] == "OK" else 1


if __name__ == "__main__":
    sys.exit(main())
