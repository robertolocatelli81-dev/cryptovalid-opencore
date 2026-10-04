# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Roberto Locatelli
"""Agent Passport System (APS) action references and Accountability Records — written from the published texts, not
from any implementation (2026-10-03, vector exchange of the IETF AUDIT BoF preparation).

The draft moved under the vectors (draft-pidlisnyi-aps-01 → -03 → -04 rewrote §4), so each form is named by the
revision that defines it, and none is silently substituted for another:

  action_ref_native_01   -01 §4.1: exactly {agentId, actionType, scopeRequired, timestamp}; each scope NFC-normalised,
                         the array sorted by code point; timestamp RFC 3339 UTC at second precision with "Z";
                         SHA-256(JCS). -01 states no duplicate rule: `reject_duplicate_scopes=True` applies the
                         rule the conformance suite takes from -03 (stated, never on by default).
  action_ref_v2          -03 §4.1 ("aps-action-ref-v2"): the eight members, payload_ref and action_ref with their
                         domain-separation prefixes; a verifier accepts only NFC, sorted (UTF-8 order), duplicate-free
                         scopes and never normalises an untrusted wire object.
  external_action_ref    -03 §4.2 ("action-ref-v1-jcs-sha256"): {action_type, agent_id, scope, timestamp}, hashed as
                         supplied, millisecond "Z" timestamp; never to be presented as an action_ref.
  verify_accountability_record
                         the Accountability Record v0.1 of the APS conformance corpus (its README and JSON schema):
                         the schema rules (closed object, required members, consts, enum, patterns, types), Ed25519
                         over JCS(record without sig) with the relying party's key, action_digest = SHA-256(JCS(action))
                         and action_ref recomputable from an inline action. "format" (date-time, uri) is an annotation
                         in JSON Schema 2020-12 and is not asserted. normalizeTimestamp is not defined in any text: it is
                         read as "drop the fractional seconds of a UTC timestamp ('Z' or '+00:00')", which equals the
                         official agent-passport-system 7.2.1 on 32/32 measured cases (2026-10-03). A non-UTC offset
                         ("+02:00") is refused here and converted to UTC by 7.2.1 (measured 2026-10-04): a declared
                         divergence, since the draft text names no conversion rule.
"""
from __future__ import annotations

import hashlib
import re
import unicodedata
from typing import Any, Dict, List, Optional, Tuple

from cryptovalid_acta import jcs

HEX64 = re.compile(r"[0-9a-f]{64}")
HEX32 = re.compile(r"[0-9a-f]{32}")
HEX128 = re.compile(r"[0-9a-f]{128}")
# ASCII digits only: Python's \d also matches Arabic-Indic and fullwidth digits, which the official implementation and
# RFC 3339 refuse; the calendar (month, day, hour, minute, second) is checked by _calendar_ok, as RFC 3339 §5.6 requires
# (2026-10-04: 25 of 31 hostile timestamps — month 13, 30 February, hour 25, Unicode digits — were accepted here and
# refused by agent-passport-system 7.2.1)
TS_SECONDS = re.compile(r"([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})Z")
TS_MILLIS = re.compile(r"([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})\.[0-9]{3}Z")
TS_UTC_FRACTION = re.compile(r"(([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2}))(\.[0-9]+)?(?:Z|\+00:00)")
DAYS_IN_MONTH = (31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31)


def _calendar_ok(y: str, mo: str, d: str, h: str, mi: str, s: str, leap_second: bool) -> bool:
    """RFC 3339 §5.6 date-time fields with a real calendar; second 60 only where a leap second can occur (23:59 on the
    last day of a month) and only when the form admits it (-03 §4.1 issued_at and §4.2 timestamp do; the second-precision
    native form and normalizeTimestamp refuse it, as the official implementation does)."""
    y, mo, d, h, mi, s = (int(x) for x in (y, mo, d, h, mi, s))
    if not (1 <= mo <= 12 and h <= 23 and mi <= 59):
        return False
    max_day = 29 if mo == 2 and (y % 4 == 0 and (y % 100 != 0 or y % 400 == 0)) else DAYS_IN_MONTH[mo - 1]
    if not 1 <= d <= max_day:
        return False
    if s <= 59:
        return True
    return leap_second and s == 60 and h == 23 and mi == 59 and d == max_day


class ApsError(ValueError):
    pass


def _no_lone_surrogate(s: str, what: str) -> None:
    try:
        s.encode("utf-8")
    except UnicodeEncodeError:
        raise ApsError(f"{what}: unpaired surrogate (no UTF-8 encoding; never repaired)")


def _strings(obj: Dict[str, Any], names, what: str) -> None:
    for n in names:
        if not isinstance(obj.get(n), str) or not obj[n]:
            raise ApsError(f"{what}: {n} must be a non-empty string")
        _no_lone_surrogate(obj[n], f"{what}.{n}")


def normalize_timestamp(ts: str) -> str:
    """-01 §4.1 "MUST format the timestamp to second precision": drop the fractional seconds of a UTC timestamp ('Z' or
    '+00:00'). Measured 2026-10-03 against agent-passport-system 7.2.1 computeActionRef: 32/32 identical."""
    m = TS_UTC_FRACTION.fullmatch(ts) if isinstance(ts, str) else None
    if not m or not _calendar_ok(*m.groups()[1:7], leap_second=False):
        raise ApsError("timestamp is not an RFC 3339 UTC timestamp ('Z' or '+00:00') on a real calendar date")
    return m.group(1) + "Z"


def action_ref_native_01(obj: Dict[str, Any], reject_duplicate_scopes: bool = False,
                         normalize: bool = False) -> Tuple[str, List[str]]:
    """(action_ref hex, canonical scope order) under draft-pidlisnyi-aps-01 §4.1. A verifier takes the object as given
    (strict second precision); `normalize=True` is the PRODUCER side: the timestamp is brought to second precision first."""
    if not isinstance(obj, dict) or set(obj) != {"agentId", "actionType", "scopeRequired", "timestamp"}:
        raise ApsError("-01 §4.1: the input object has exactly agentId, actionType, scopeRequired, timestamp")
    if normalize:
        obj = {**obj, "timestamp": normalize_timestamp(obj["timestamp"])}
    _strings(obj, ("agentId", "actionType", "timestamp"), "-01 §4.1")
    m = TS_SECONDS.fullmatch(obj["timestamp"])
    if not m or not _calendar_ok(*m.groups(), leap_second=False):
        raise ApsError("-01 §4.1: timestamp must be RFC 3339 UTC at second precision with 'Z' on a real calendar date")
    sc = obj["scopeRequired"]
    if not isinstance(sc, list) or not all(isinstance(x, str) for x in sc):
        raise ApsError("-01 §4.1: scopeRequired must be an array of strings")
    for x in sc:
        _no_lone_surrogate(x, "-01 §4.1 scope")
    scopes = sorted(unicodedata.normalize("NFC", x) for x in sc)     # Python str order = code-point order
    if reject_duplicate_scopes and len(set(scopes)) != len(scopes):
        raise ApsError("duplicate scope after NFC (rule of -03 §4.1, applied on request)")
    return hashlib.sha256(jcs({**obj, "scopeRequired": scopes})).hexdigest(), scopes


def payload_ref_v2(payload: Any) -> str:
    return hashlib.sha256(b"APS-ACTION-PAYLOAD-V1\x00" + jcs(payload)).hexdigest()


def action_ref_v2(obj: Dict[str, Any], payload: Any = None, empty_scope_permitted: bool = False) -> str:
    """action_ref under -03 §4.1; with `payload`, payload_ref is recomputed and must match (the boundary's duty).
    "All string fields MUST be non-empty except that a profile MAY permit an empty scope_required array": the permission
    is the profile's, so an empty array is refused unless the caller holding that profile passes empty_scope_permitted."""
    members = {"profile", "agent_id", "action_type", "target", "payload_ref", "scope_required", "issued_at", "nonce"}
    if not isinstance(obj, dict) or set(obj) != members:
        raise ApsError("-03 §4.1: unknown or missing member")
    if obj["profile"] != "aps-action-ref-v2":
        raise ApsError('-03 §4.1: profile MUST equal "aps-action-ref-v2"')
    _strings(obj, ("agent_id", "action_type", "target", "payload_ref", "issued_at", "nonce"), "-03 §4.1")
    if not HEX64.fullmatch(obj["payload_ref"]) or not HEX32.fullmatch(obj["nonce"]):
        raise ApsError("-03 §4.1: invalid hexadecimal field")
    m = TS_MILLIS.fullmatch(obj["issued_at"])
    if not m or not _calendar_ok(*m.groups(), leap_second=True):
        raise ApsError("-03 §4.1: issued_at must be RFC 3339 UTC with exactly three fractional digits and 'Z' on a real calendar date")
    sc = obj["scope_required"]
    if not isinstance(sc, list) or not all(isinstance(x, str) and x for x in sc):
        raise ApsError("-03 §4.1: scope_required must be an array of non-empty strings")
    if not sc and not empty_scope_permitted:
        raise ApsError("-03 §4.1: an empty scope_required is permitted only by an applicable profile")
    for x in sc:
        _no_lone_surrogate(x, "-03 §4.1 scope")
    canon = sorted(set(unicodedata.normalize("NFC", x) for x in sc), key=lambda x: x.encode("utf-8"))
    if sc != canon:                      # the verifier does not normalise an untrusted wire object: it refuses it
        raise ApsError("-03 §4.1: non-canonical scope array (NFC, UTF-8 order, duplicate-free)")
    if payload is not None and payload_ref_v2(payload) != obj["payload_ref"]:
        raise ApsError("-03 §4.1: payload_ref does not match the payload")
    return hashlib.sha256(b"APS-ACTION-REF-V2\x00" + jcs(obj)).hexdigest()


def external_action_ref(obj: Dict[str, Any]) -> str:
    """"action-ref-v1-jcs-sha256" under -03 §4.2: hashed as supplied, no transformation."""
    if not isinstance(obj, dict) or set(obj) != {"action_type", "agent_id", "scope", "timestamp"}:
        raise ApsError("-03 §4.2: exactly action_type, agent_id, scope, timestamp")
    for n in ("action_type", "agent_id", "scope", "timestamp"):
        if not isinstance(obj[n], str):
            raise ApsError(f"-03 §4.2: {n} must be a string")
        _no_lone_surrogate(obj[n], f"-03 §4.2 {n}")
    m = TS_MILLIS.fullmatch(obj["timestamp"])
    if not m or not _calendar_ok(*m.groups(), leap_second=True):
        raise ApsError("-03 §4.2: timestamp at exactly millisecond precision with 'Z' on a real calendar date (never coerced)")
    return hashlib.sha256(jcs(obj)).hexdigest()


# ── Accountability Record v0.1 ───────────────────────────────────────────────────────────────────────────────────
RECORD_REQUIRED = ("spec_version", "record_type", "action_ref", "action_digest", "signer_did", "agent_did",
                   "delegation_ref", "principal_ref", "decision", "executed", "issued_at", "sig", "sig_alg")
RECORD_OPTIONAL = ("action", "settlement_ref", "settlement_rail")


def _schema(rec: Any) -> Optional[str]:
    """The schema rules, as code; None when the record conforms, else the rule that fails."""
    if not isinstance(rec, dict):
        return "record is not an object"
    extra = set(rec) - set(RECORD_REQUIRED) - set(RECORD_OPTIONAL)
    if extra:
        return f"additional member(s) {sorted(extra)}"
    missing = [k for k in RECORD_REQUIRED if k not in rec]
    if missing:
        return f"missing member(s) {missing}"
    for k in ("spec_version", "action_ref", "signer_did", "agent_did", "delegation_ref", "principal_ref", "issued_at",
              "sig", "settlement_ref", "settlement_rail"):
        if k in rec and not isinstance(rec[k], str):
            return f"{k} is not a string"
    if rec["record_type"] != "accountability_record":
        return "record_type is not the const accountability_record"
    if rec["sig_alg"] != "Ed25519":
        return "sig_alg is not the const Ed25519"
    if rec["decision"] not in ("allow", "deny", "halt"):
        return "decision is not one of allow, deny, halt"
    if not isinstance(rec["executed"], bool):
        return "executed is not a boolean"
    if not HEX64.fullmatch(rec["action_ref"]):
        return "action_ref does not match ^[0-9a-f]{64}$"
    if not HEX128.fullmatch(rec["sig"]):
        return "sig does not match ^[0-9a-f]{128}$"
    d = rec["action_digest"]
    if not (isinstance(d, dict) and set(d) == {"sha256"} and isinstance(d["sha256"], str) and HEX64.fullmatch(d["sha256"])):
        return "action_digest must be exactly {sha256: 64 lowercase hex}"
    if "action" in rec:
        a = rec["action"]
        if not (isinstance(a, dict) and set(a) == {"type", "scope", "timestamp"} and isinstance(a["type"], str)
                and isinstance(a["timestamp"], str) and isinstance(a["scope"], list)
                and all(isinstance(x, str) for x in a["scope"])):
            return "action must be exactly {type: string, scope: [string], timestamp: string}"
    return None


def verify_accountability_record(rec: Any, signer_pubkey_hex: str) -> Dict[str, Any]:
    """Verdict over one record; the key is the relying party's (what signer_did resolves to, held out of band)."""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    why = _schema(rec)
    if why:
        return {"ok": False, "layer": "schema", "why": why}
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(signer_pubkey_hex)).verify(
            bytes.fromhex(rec["sig"]), jcs({k: v for k, v in rec.items() if k != "sig"}))
    except (InvalidSignature, ValueError):
        return {"ok": False, "layer": "signature", "why": "Ed25519 over JCS(record without sig) does not verify"}
    out = {"ok": True, "layer": None, "payload_verified": "action" in rec}
    if "action" in rec:
        a = rec["action"]
        if hashlib.sha256(jcs(a)).hexdigest() != rec["action_digest"]["sha256"]:
            return {"ok": False, "layer": "digest_mismatch", "why": "SHA-256(JCS(action)) != action_digest.sha256"}
        try:
            ref, _ = action_ref_native_01({"agentId": rec["agent_did"], "actionType": a["type"],
                                           "scopeRequired": a["scope"], "timestamp": a["timestamp"]}, normalize=True)
        except ApsError as e:
            return {"ok": False, "layer": "action_ref", "why": str(e)}
        if ref != rec["action_ref"]:
            return {"ok": False, "layer": "action_ref", "why": "action_ref is not recomputable from the inline action"}
    out["why"] = "schema, signature" + (", action_digest and action_ref" if "action" in rec else " (detached payload: not verified)")
    return out
