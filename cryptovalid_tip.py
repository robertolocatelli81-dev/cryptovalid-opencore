#!/usr/bin/env python3
"""Signed chain tip — pushes the tail limit of a snapshot hash chain (15/09/2026, Roberto: «allunga il limite
della coda»).

A bare hash chain cannot see that its LAST entries were deleted (a shorter prefix is a valid chain), nor a
re-chained suffix written by someone with write access. The tip is a tiny signed statement, written by the
writer after EVERY append in O(1): {entries, tip_sha256 = last self_hash, ts}, Ed25519 over the canonical JSON.
A verifier holding the tip (sidecar `<ledger>.tip.json`, or a copy kept elsewhere) and the TRUSTED log key
turns three invisible attacks into named failures:
  * tail_truncated   — the file has fewer entries than the tip commits to;
  * tail_rewritten   — same count, different last self_hash (re-chained suffix);
  * unsealed_tail    — more entries than the tip: appended after the last signed head (stale tip, or an append by
                       someone without the key).
What it still does NOT prove: an attacker WITH the log key can truncate and re-sign (key custody is the limit —
HSM/KMS, and copies of the tip outside the writer's reach: the monitor state, receipts, an external anchor);
ROLLBACK: truncating the file and restoring an OLDER genuine tip passes (the tip proves "a signed state", not
"the latest") — `--tip-not-before <ts>` refuses tips older than a moment the relying party knows about, and the
monitor/receipts see it systematically;
deleting the tip file itself is visible only when the verifier REQUIRES a tip (`--require-tip`), or when a copy
exists elsewhere; without the TRUSTED log key the tip is not checked at all (the key inside it proves nothing);
in a segmented archive (cryptovalid_ingest) each segment is its own chain with its own tip and ledger_id — the
cross-segment continuity is the STH chain (`.sth.json`, `verify_archive`), not the tip. Rust and Swift verifiers do not check the tip (declared, spec/CONFORMANCE.md).

Byte-identical payload in every language (Python is the oracle of the bytes):
    {"entries":N,"kind":"cryptovalid_tip/1","ledger_id":"<hex>","tip_sha256":"<hex>","ts":"<iso>"}
`ledger_id` = self_hash of entry 0 (the chain's identity; council 15/09: without it a log key shared by two
ledgers lets the pair file+tip of B be substituted for A). The verifier checks it against the file
(`tip_of_another_ledger`) and, out of band, against `--expect-ledger-id` (`ledger_id_mismatch`).
"""
import argparse
import calendar
import hashlib
import json
import os
import re
import sys
from datetime import datetime, timedelta, timezone
from typing import Dict, Optional

KIND = "cryptovalid_tip/1"
GENESIS = "0" * 64
_HEX64 = re.compile(r"[0-9a-f]{64}")


def tip_path_for(ledger_path: str) -> str:
    return ledger_path + ".tip.json"


def tip_payload(entries: int, ledger_id: str, tip_sha256: str, ts: str) -> bytes:
    return json.dumps({"entries": entries, "kind": KIND, "ledger_id": ledger_id, "tip_sha256": tip_sha256, "ts": ts},
                      sort_keys=True, separators=(",", ":")).encode()


def _ed():
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
    return Ed25519PrivateKey, Ed25519PublicKey, serialization


def _load_sk(keyfile):
    """keyfile: path of the hex seed, or an already loaded (sk, pk_hex) pair (writers load the key ONCE —
    council 15/09, Gemini: re-reading and re-deriving it at every flush is I/O and CPU in the hot path)."""
    if isinstance(keyfile, tuple):
        return keyfile
    Ed25519PrivateKey, _, ser = _ed()
    with open(keyfile, encoding="utf-8") as f:
        sk = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(f.read().strip()))
    return sk, sk.public_key().public_bytes(ser.Encoding.Raw, ser.PublicFormat.Raw).hex()


def load_key(keyfile: str):
    """(sk, pk_hex) to pass to write_tip/sign_tip repeatedly without touching the disk again."""
    return _load_sk(keyfile)


# [0-9] and not \d: in Python `\d` matches every Unicode decimal digit (Arabic-Indic, fullwidth…) and int() converts
# them, while Go (RE2) and JS mean ASCII — measured divergence, review round 3 with Fable 5.1
_TS_FIELDS = re.compile(r"([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})(?:\.([0-9]{1,9}))?(Z|[+-][0-9]{2}:[0-9]{2})")


def parse_instant(ts: str) -> datetime:
    """The ONE timestamp profile of the three checkers, validated by HAND and identically in Python, Go and JS
    (review with Fable 5.1, 15/09/2026: the format rule was shared but the VALUE went to three library parsers
    that disagreed on 2026-02-30, hour 24, year 0000, a comma fraction, a 10-digit fraction, offset +24:00, and
    Python < 3.11 on fraction length). Profile: `YYYY-MM-DDThh:mm:ss[.f{1,9}](Z|±hh:mm)`, year 0001-9999, real
    calendar day (leap years), hour 0-23, minute/second 0-59 (no leap second), offset hour 0-23, minute 0-59.
    Returns the instant as the integer pair (epoch seconds, nanoseconds) — compared as a pair in the three
    checkers, so the fraction precision (µs / ms / ns of the three standard libraries) never orders two instants
    differently at a `--tip-not-before` boundary (review round 3). Raises ValueError for anything else."""
    if not isinstance(ts, str):
        raise ValueError("timestamp is not a string")
    m = _TS_FIELDS.fullmatch(ts)
    if not m:
        raise ValueError("timestamp outside the profile YYYY-MM-DDThh:mm:ss[.fraction](Z|±hh:mm)")
    y, mo, d, h, mi, sec = (int(m.group(i)) for i in range(1, 7))
    frac, off = m.group(7), m.group(8)
    if not (1 <= y <= 9999 and 1 <= mo <= 12 and 0 <= h <= 23 and 0 <= mi <= 59 and 0 <= sec <= 59):
        raise ValueError("timestamp field out of range")
    leap = (y % 4 == 0 and y % 100 != 0) or y % 400 == 0
    dim = [31, 29 if leap else 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31][mo - 1]
    if not 1 <= d <= dim:
        raise ValueError("timestamp day does not exist in that month")
    off_sec = 0
    if off != "Z":
        oh, om = int(off[1:3]), int(off[4:6])
        if oh > 23 or om > 59:
            raise ValueError("timestamp offset out of range")
        off_sec = (oh * 3600 + om * 60) * (-1 if off[0] == "-" else 1)
    nanos = int((frac or "0").ljust(9, "0")[:9])
    return (calendar.timegm((y, mo, d, h, mi, sec)) - off_sec, nanos)


def chain_tip(ledger_path: str) -> Dict:
    """(entries, ledger_id = first self_hash, last self_hash) read from the file — no verification here."""
    n, first, last = 0, GENESIS, GENESIS
    with open(ledger_path, "rb") as f:
        for line in f:
            if not line.strip():
                continue
            n += 1
            try:
                obj = json.loads(line)
                h = obj["self_hash"]
            except (ValueError, KeyError, TypeError):
                raise ValueError(f"line {n}: not a JSON object with a self_hash — cannot compute the tip of a broken file")
            if not isinstance(h, str) or not _HEX64.fullmatch(h):
                raise ValueError(f"line {n}: self_hash is not 64 hex characters")
            last = h
            if n == 1:
                first = last
    return {"entries": n, "ledger_id": first, "tip_sha256": last}


def write_tip(out: str, keyfile: str, entries: int, ledger_id: str, tip_sha256: str, ts: Optional[str] = None) -> Dict:
    """O(1): sign the given tail state and write `out` atomically (fsync). Writers that already know their
    tail (cryptovalid_ingest, Go AppendSigned) use this under their own lock."""
    sk, pk = _load_sk(keyfile)
    ts = ts or datetime.now(timezone.utc).isoformat(timespec="seconds")
    sig = sk.sign(tip_payload(entries, ledger_id, tip_sha256, ts))
    tip = {"kind": KIND, "entries": entries, "ledger_id": ledger_id, "tip_sha256": tip_sha256, "ts": ts,
           "log_pubkey_hex": pk, "signature_hex": sig.hex()}
    tmp = out + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(tip, f, separators=(",", ":"), sort_keys=True)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, out)
    return tip


def sign_tip(ledger_path: str, keyfile: str, tip_path: Optional[str] = None, ts: Optional[str] = None) -> Dict:
    """Write `<ledger>.tip.json` (atomic replace) for the CURRENT file (reads it: O(n)). Call after every append."""
    t = chain_tip(ledger_path)
    return write_tip(tip_path or tip_path_for(ledger_path), keyfile, t["entries"], t["ledger_id"], t["tip_sha256"], ts)


def verify_tip_signature(tip: Dict, trusted_pubkey_hex: Optional[str]) -> Dict:
    """Signature against the TRUSTED key (the key inside the tip is informative only)."""
    _, Ed25519PublicKey, _ = _ed()
    if not isinstance(tip, dict) or tip.get("kind") != KIND:
        return {"ok": False, "why": "not a cryptovalid_tip/1 document"}
    for k in ("entries", "ledger_id", "tip_sha256", "ts", "signature_hex"):
        if k not in tip:
            return {"ok": False, "why": f"tip missing field {k}"}
    # strict types AND formats, the same in Python, Go and JS (council R3: Python validated only `str`, Go hex64
    # + a plain timestamp — a signed tip with ts="garbage" was ok here and tip_invalid there)
    if isinstance(tip["entries"], bool) or not isinstance(tip["entries"], int) or tip["entries"] < 0:
        return {"ok": False, "why": "tip entries must be a non-negative integer"}
    if not all(isinstance(tip[k], str) for k in ("ledger_id", "tip_sha256", "ts", "signature_hex")):
        return {"ok": False, "why": "tip fields must be strings"}
    if not (_HEX64.fullmatch(tip["ledger_id"]) and _HEX64.fullmatch(tip["tip_sha256"])):
        return {"ok": False, "why": "ledger_id / tip_sha256 must be 64 lowercase hex characters"}
    try:
        parse_instant(tip["ts"])          # format AND value, by hand, identical in the three checkers
    except ValueError as e:
        return {"ok": False, "why": f"ts outside the profile: {e}"}
    # The key INSIDE the tip is informative only: verifying against it proves nothing (anyone can sign a tip
    # with a key of their own and put it there). Without the trusted log key there is NO verification —
    # ok=False, never a "PASS but untrusted" an automation would read as 0 (council 15/09, Gemini).
    if not trusted_pubkey_hex:
        return {"ok": False, "why": "tip_untrusted: no trusted log key given (pass --trusted-pubkey); the key inside "
                                    "the tip cannot be trusted", "trusted": False}
    if tip.get("log_pubkey_hex") not in (None, "", trusted_pubkey_hex):   # "" = absent, as in Go/JS
        return {"ok": False, "why": "tip log key differs from the trusted log key"}
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(trusted_pubkey_hex)).verify(
            bytes.fromhex(tip["signature_hex"]), tip_payload(int(tip["entries"]), tip["ledger_id"], tip["tip_sha256"], tip["ts"]))
    except Exception as e:  # noqa: BLE001 — any failure is one verdict
        return {"ok": False, "why": f"tip signature invalid: {type(e).__name__}"}
    return {"ok": True, "why": "signature verified against the trusted log key", "trusted": True}


def check_tip(entries_count: int, last_self_hash: str, tip: Dict, trusted_pubkey_hex: Optional[str],
              not_before: Optional[str] = None, first_self_hash: Optional[str] = None,
              expect_ledger_id: Optional[str] = None) -> Dict:
    """Compare the verified file (count + last self_hash) with the signed tip. Returns {ok, error?, ...}.

    ROLLBACK (declared limit): a tip proves the file matches SOME state the log key signed, not the LATEST —
    truncating the file and restoring an OLDER genuine tip passes. `not_before` (an ISO-8601 instant; instants
    are compared, never strings; resolution = 1 s, two tips in the same second are indistinguishable) lets a
    relying party who knows a later tip existed refuse older ones (`tip_rolled_back`); the monitor state /
    receipts / an external anchor are the systematic answer."""
    sig = verify_tip_signature(tip, trusted_pubkey_hex)
    if not sig["ok"]:
        return {"ok": False, "error": (sig["why"] if sig["why"].startswith("tip_untrusted") else "tip_invalid: " + sig["why"]),
                "trusted": False}
    n = int(tip["entries"])
    # identity: the tip must be THIS chain's (first self_hash) — and, out of band, the chain the relying party
    # expects (a whole pair file+tip of another ledger signed by the same key is caught only by expect_ledger_id)
    if expect_ledger_id and tip["ledger_id"] != expect_ledger_id:
        return {"ok": False, "error": "ledger_id_mismatch: the tip belongs to a different ledger than the one you expect",
                "signature": sig["why"]}
    if first_self_hash is not None and entries_count > 0 and tip["ledger_id"] != first_self_hash:
        return {"ok": False, "error": "tip_of_another_ledger: the tip's ledger_id is not this file's first self_hash",
                "signature": sig["why"]}
    if not_before:
        try:
            nb = parse_instant(not_before)   # same profile as the tip's ts, in the three checkers (Gemini: py/js took a date-only)
        except ValueError as e:
            # the VERIFIER's argument is wrong, not the tip: never blame the file (review with Fable, Gemini)
            return {"ok": False, "error": f"bad_not_before: --tip-not-before must be YYYY-MM-DDThh:mm:ss[.f](Z|±hh:mm) ({str(e)[:60]})",
                    "signature": sig["why"]}
        if parse_instant(tip["ts"]) < nb:
            return {"ok": False, "error": f"tip_rolled_back: the tip is dated {tip['ts']}, before the required {not_before} "
                                          "(an older genuine tip restored after a truncation looks exactly like this)",
                    "signature": sig["why"]}
    if entries_count < n:
        return {"ok": False, "error": f"tail_truncated: file has {entries_count} entries, the signed tip commits to {n}",
                "signature": sig["why"]}
    if entries_count > n:
        return {"ok": False, "error": f"unsealed_tail: file has {entries_count} entries, the signed tip commits to {n} "
                                      "(appended after the last signed head: stale tip, or an append without the key)",
                "signature": sig["why"]}
    if last_self_hash != tip["tip_sha256"]:
        return {"ok": False, "error": "tail_rewritten: same entry count but the last self_hash differs from the signed tip",
                "signature": sig["why"]}
    return {"ok": True, "entries": n, "ledger_id": tip["ledger_id"], "tip_sha256": tip["tip_sha256"], "ts": tip["ts"],
            "signature": sig["why"], "trusted": sig["trusted"]}


def load_tip(path: str) -> Dict:
    with open(path, encoding="utf-8") as f:
        doc = json.load(f)
    if not isinstance(doc, dict):
        raise ValueError("tip file is not a JSON object")
    return doc


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="cryptovalid_tip.py", description="signed chain tip: sign after each append")
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("sign", help="write <ledger>.tip.json for the current file")
    s.add_argument("ledger"); s.add_argument("keyfile"); s.add_argument("--out")
    c = sub.add_parser("check", help="compare a ledger with a tip (chain itself is NOT verified here: use verifier.py --tip)")
    c.add_argument("ledger"); c.add_argument("--tip"); c.add_argument("--trusted-pubkey"); c.add_argument("--not-before")
    c.add_argument("--expect-ledger-id")
    a = p.parse_args(argv)
    if a.cmd == "sign":
        print(json.dumps(sign_tip(a.ledger, a.keyfile, a.out), indent=1))
        return 0
    if not a.trusted_pubkey:
        print(json.dumps({"ok": False, "error": "tip_untrusted: --trusted-pubkey is required (the key inside the tip "
                                                "proves nothing); exit 2"}, indent=1))
        return 2
    try:
        t = chain_tip(a.ledger)
        tip = load_tip(a.tip or tip_path_for(a.ledger))
    except (OSError, ValueError) as e:      # a missing/malformed file is a JSON error, never a traceback
        print(json.dumps({"ok": False, "error": f"tip_unreadable: {type(e).__name__}: {str(e)[:160]}"}, indent=1))
        return 1
    r = check_tip(t["entries"], t["tip_sha256"], tip, a.trusted_pubkey, a.not_before,
                  first_self_hash=t["ledger_id"], expect_ledger_id=a.expect_ledger_id)
    r["note"] = "the CHAIN is not verified by this command (fields are read as written): use verifier.py --trusted-pubkey"
    print(json.dumps(r, indent=1))
    return 0 if (r["ok"] and r.get("trusted")) else 1


if __name__ == "__main__":
    sys.exit(main())
