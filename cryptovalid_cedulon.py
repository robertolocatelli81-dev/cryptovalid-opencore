# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Roberto Locatelli
"""Cedulon Decision Records — a clean-room verifier written from the drafts, not from any implementation (2026-10-03,
for the vector exchange of the IETF AUDIT BoF preparation).

Sources, and nothing else: draft-dogru-cedulon-decision-profile-03 (§4.1 claim labels, §4.2 claim rules, §4.3
presentation, §4.4 chain and checkpoints, §5.1/§5.2 Effect Extract, §6.1 binding); draft-dogru-cedulon-08, the document
that profile cites as [CEDULON] (§6.2 COSE_Sign1 headers, §6.1 checkpoint labels, §11.1 checkpoint claims); RFC 9864
(alg -19 = Ed25519); RFC 9052 (Sig_structure); RFC 8785 (the extract's signed octets). Not normative, and named where
used: the README and files of verax-ai/verax test-vectors/v1 (the stage names, the inputs / index / control layout) and
W3C WebAuthn Level 3 §7.2 (the approval assertion; the challenge derivation is not written anywhere and is not checked).

Stages, in this order; the first that fails is the verdict:
  record-header         untagged COSE_Sign1 of four; protected header deterministic CBOR with alg -19, the decision
                        content type, kid = first 8 bytes of SHA-256(SPKI DER of the PINNED Decider key); unprotected {}
  record-signature      Ed25519 over ["Signature1", protected, h'', payload] with the pinned key
  record-claims         exactly the 13 labels -70501..-70513 with their types; the §4.2 rules applied HERE; the decoded
                        claims equal the claims presented beside the record
  chain                 prevRecordHash null first, then SHA-256 of the previous record's COSE_Sign1 octets
  effect-binding        each Effect Extract: §5.1 schema (exact members, hash grammar, safe integers, half-open window,
                        rows inside it), §5.2 Ed25519 over JCS(body) under the PINNED extract key; a row presented
                        beside the extract must be one the extract signs (for records the core states the rule:
                        CEDULON-08 MUST-T4-2 and §11.4 step 4, which profile-03 §6 runs unchanged, restated by the Verax
                        test-vector README step 4; for a row list beside an extract the nearest rule is CEDULON-08
                        MUST-T10-12, extract-settlement-mismatch, audit fails; CEDULON-08 §6.3 names presented members
                        as a surface anyone can rewrite); then §6.1 binding
  checkpoint-signature  the §6.2 header profile with the checkpoint content type, signed by the PINNED checkpoint key
  checkpoint-coverage   receiptCount = records with timestampMs in [startMs, endMs); chainHeadHash = hash of the last
                        record of the window in chain order; prevCheckpointHash links checkpoints
  checkpoint-totals     the signed totals = {"allow","deny","defer"} counts in the window, as decimal strings
Verified only when their files are given (inputs_text, index_text, operator_credentials): inputs-binding, index,
approval-signature, control; each stage not given is named under `not_verified`, never silently passed, and
"approval-challenge-binding" always stays there (sources below).
"""
from __future__ import annotations

import base64
import hashlib
import json
from typing import Any, Dict, List, Optional

import cryptovalid_receipt as R
from cryptovalid_acta import _no_dup_keys, jcs

ALG_ED25519 = -19
CT_RECORD = "application/cedulon-decision-record+cbor"
CT_CHECKPOINT = "application/cedulon-checkpoint+cbor"
RECORD_LABELS = {-70501: "decider", -70502: "subject", -70503: "requestHash", -70504: "policyHash", -70505: "inputsHash",
                 -70506: "decision", -70507: "reasonCode", -70508: "ref", -70509: "effectHash", -70510: "timestampMs",
                 -70511: "nonce", -70512: "prevRecordHash", -70513: "effectClass"}
HASH_CLAIMS = {"requestHash", "policyHash", "inputsHash", "effectHash", "prevRecordHash"}
NULLABLE = {"inputsHash", "ref", "effectHash", "prevRecordHash", "effectClass"}
CHECKPOINT_LABELS = {-70101: "epoch", -70102: "startMs", -70103: "endMs", -70104: "receiptCount", -70105: "chainHeadHash",
                     -70106: "totals", -70107: "prevCheckpointHash"}
DECISIONS = ("allow", "deny", "defer")
MAX_SAFE = 2 ** 53 - 1
NOT_VERIFIED = ["inputs-binding", "index", "approval-signature", "control"]
# The four stages above run when their inputs are given (verify_ledger: inputs_text, index_text, operator_credentials).
# Sources, stated: inputs-binding — decision-profile-03 §4.1 (inputsHash = SHA-256 of the context, canonical encoding of
# CEDULON-08 §7 = RFC 8785). index, control, approval-signature — the stage table of the Verax test-vector README and the
# Implementation Status of core-03 (no normative text). approval-signature verifies the WebAuthn assertion as W3C
# WebAuthn Level 3 §7.2 defines it and binds it to the held record through deferRecordHash; how the CHALLENGE is derived
# from the held record is not written anywhere, so "approval-challenge-binding" always stays in not_verified.
STAGES = ["record-header", "record-signature", "record-claims", "chain", "effect-binding",
          "checkpoint-signature", "checkpoint-coverage", "checkpoint-totals"]


class CedulonError(ValueError):
    def __init__(self, stage: str, msg: str):
        super().__init__(f"{stage}: {msg}")
        self.stage = stage


def _is_hash(v) -> bool:
    return isinstance(v, str) and len(v) == 64 and all(c in "0123456789abcdef" for c in v)


def _is_uint(v) -> bool:
    return isinstance(v, int) and not isinstance(v, bool) and 0 <= v <= MAX_SAFE


def _spki_der(pem) -> bytes:
    from cryptography.hazmat.primitives import serialization as ser
    key = ser.load_pem_public_key(pem.encode("ascii") if isinstance(pem, str) else bytes(pem))
    return key.public_bytes(ser.Encoding.DER, ser.PublicFormat.SubjectPublicKeyInfo)


def _cose(octets: bytes, pinned_pem, content_type: str, stage_header: str, stage_sig: str):
    """§6.2 header profile + signature; returns the decoded payload map."""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import serialization as ser
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    try:
        arr = R.cbor_decode(octets)
    except ValueError as e:
        raise CedulonError(stage_header, f"not CBOR: {e}")
    if not (isinstance(arr, list) and len(arr) == 4 and isinstance(arr[0], bytes) and isinstance(arr[2], bytes)
            and isinstance(arr[3], bytes)):
        raise CedulonError(stage_header, "not an untagged COSE_Sign1 [bstr, map, bstr, bstr]")
    if arr[1] != {}:
        raise CedulonError(stage_header, "cose-sign1-unprotected: the unprotected header is not an empty map")
    try:
        ph = R.cbor_decode(arr[0])
    except ValueError as e:
        raise CedulonError(stage_header, f"protected header not CBOR: {e}")
    if not isinstance(ph, dict) or R.cbor_encode(ph) != arr[0]:
        raise CedulonError(stage_header, "protected header is not a deterministic CBOR map")
    if ph.get(1) != ALG_ED25519:
        raise CedulonError(stage_header, f"alg {ph.get(1)!r} is not -19 (Ed25519, RFC 9864)")
    if ph.get(3) != content_type:
        raise CedulonError(stage_header, f"content type {ph.get(3)!r} is not {content_type}")
    der = _spki_der(pinned_pem)
    if ph.get(4) != hashlib.sha256(der).digest()[:8]:
        raise CedulonError(stage_header, "kid is not the first 8 bytes of SHA-256 over the pinned key's SPKI DER")
    pub = ser.load_der_public_key(der)
    if not isinstance(pub, Ed25519PublicKey):
        raise CedulonError(stage_header, "the pinned key is not an Ed25519 key")
    try:
        pub.verify(arr[3], R.cbor_encode(["Signature1", arr[0], b"", arr[2]]))
    except InvalidSignature:
        raise CedulonError(stage_sig, "Ed25519 signature does not verify under the pinned key")
    try:
        payload = R.cbor_decode(arr[2])
    except ValueError as e:
        raise CedulonError(stage_sig, f"payload not CBOR: {e}")
    return payload


def _record_claims(payload, presented) -> Dict[str, Any]:
    st = "record-claims"
    if not isinstance(payload, dict) or set(payload) != set(RECORD_LABELS):
        raise CedulonError(st, "the claim map does not have exactly the labels -70501..-70513 (§4.1)")
    c = {RECORD_LABELS[k]: v for k, v in payload.items()}
    for name, v in c.items():
        if v is None:
            if name not in NULLABLE:
                raise CedulonError(st, f"{name} is null but not nullable")
        elif name == "timestampMs":
            if not _is_uint(v):
                raise CedulonError(st, "timestampMs is not a uint at most 2^53 - 1 (§4.2)")
        elif not isinstance(v, str):
            raise CedulonError(st, f"{name} is not a text string")
        elif name in HASH_CLAIMS and not _is_hash(v):
            raise CedulonError(st, f"{name} is outside the hash grammar (§4.2)")
    if c["decision"] not in DECISIONS:
        raise CedulonError(st, "decision is not allow / deny / defer (§4.2)")
    if c["decision"] == "allow":
        if not c["ref"] or c["effectHash"] is None or not c["effectClass"]:
            raise CedulonError(st, "an allow without a non-empty ref, effectHash or effectClass (§4.2)")
    elif c["effectHash"] is not None:
        raise CedulonError(st, "a refusal carries a non-null effectHash (§4.2)")
    if presented != c:
        raise CedulonError(st, "the decoded claims differ from the claims presented beside the record")
    return c


def _loads_lines(text: str, what: str) -> List[Dict[str, Any]]:
    out = []
    for i, line in enumerate(text.splitlines()):
        if line.strip():
            try:
                v = json.loads(line, object_pairs_hook=_no_dup_keys,
                               parse_constant=lambda x: (_ for _ in ()).throw(ValueError(f"non-JSON constant {x}")))
            except ValueError as e:
                raise CedulonError("record-header" if what == "decisions" else "effect-binding" if what == "effects"
                                   else "checkpoint-signature", f"{what} line {i + 1}: {e}")
            out.append(v)
    return out


def _extract(body, sig_b64, pinned_pem) -> List[Dict[str, Any]]:
    """§5.1 schema + §5.2 signature; returns the rows."""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import serialization as ser
    st = "effect-binding"
    if not isinstance(body, dict) or set(body) != {"deciderId", "channelId", "windowStartMs", "windowEndMs", "effects"}:
        raise CedulonError(st, "extract body does not have exactly the §5.1 members")
    if not (isinstance(body["deciderId"], str) and body["deciderId"] and isinstance(body["channelId"], str) and body["channelId"]):
        raise CedulonError(st, "deciderId / channelId not a non-empty string")
    ws, we = body["windowStartMs"], body["windowEndMs"]
    if not (_is_uint(ws) and _is_uint(we) and we > ws):
        raise CedulonError(st, "window not safe integers with windowEndMs > windowStartMs")
    if not isinstance(body["effects"], list):
        raise CedulonError(st, "effects is not an array")
    for row in body["effects"]:
        if not isinstance(row, dict) or not {"ref", "effectHash", "effectClass", "timestampMs"} <= set(row) \
                or not set(row) <= {"ref", "effectHash", "effectClass", "timestampMs", "actor"}:
            raise CedulonError(st, "effect row does not have the §5.1 members")
        if not (isinstance(row["ref"], str) and row["ref"] and _is_hash(row["effectHash"])
                and isinstance(row["effectClass"], str) and row["effectClass"] and _is_uint(row["timestampMs"])
                and ("actor" not in row or isinstance(row["actor"], str))):
            raise CedulonError(st, "effect row member of the wrong type or outside its grammar")
        if not ws <= row["timestampMs"] < we:
            raise CedulonError(st, "effect-outside-window")
    pub = ser.load_der_public_key(_spki_der(pinned_pem))
    try:
        sig = base64.b64decode(sig_b64, validate=True)
        pub.verify(sig, jcs(body))
    except (InvalidSignature, ValueError, TypeError):
        raise CedulonError(st, "extract-key-mismatch: the extract signature does not verify under the pinned key")
    return body["effects"]


def _b64u(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _webauthn_ok(sig: Dict[str, Any], cred: Dict[str, Any]) -> bool:
    """W3C WebAuthn L3 §7.2 steps on an assertion: type webauthn.get, rpIdHash = SHA-256(rpId), user-present flag, and
    the signature over authenticatorData || SHA-256(clientDataJSON) with the credential's COSE key (Ed25519 or ES256)."""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    ad, cdj, sg = _b64u(sig["authenticatorData"]), _b64u(sig["clientDataJSON"]), _b64u(sig["signature"])
    cd = json.loads(cdj, object_pairs_hook=_no_dup_keys)
    if cd.get("type") != "webauthn.get" or len(ad) < 37 or ad[:32] != hashlib.sha256(sig["rpId"].encode()).digest():
        return False
    if not ad[32] & 0x01:                               # UP: user present
        return False
    key = R.cbor_decode(_b64u(cred["publicKey"]))
    signed = ad + hashlib.sha256(cdj).digest()
    try:
        if key.get(1) == 1 and key.get(3) == -8 and key.get(-1) == 6:
            Ed25519PublicKey.from_public_bytes(key[-2]).verify(sg, signed)
        elif key.get(1) == 2 and key.get(3) == -7 and key.get(-1) == 1:
            ec.EllipticCurvePublicNumbers(int.from_bytes(key[-2], "big"), int.from_bytes(key[-3], "big"),
                                          ec.SECP256R1()).public_key().verify(sg, signed, ec.ECDSA(hashes.SHA256()))
        else:
            return False
        return True
    except (InvalidSignature, ValueError, KeyError, TypeError):
        return False


def verify_ledger(decisions_text: str, effects_text: str, checkpoints_text: str, record_key_pem, extract_key_pem,
                  checkpoint_key_pem, inputs_text: Optional[str] = None, index_text: Optional[str] = None,
                  operator_credentials: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """The verdict over one Decider's ledger. Keys are the relying party's pins (SPKI PEM); operator_credentials is the
    relying party's pin of the operator's passkeys ({"credentials": [{id, publicKey (COSE, base64url), sub}]})."""
    nv = [s for s in NOT_VERIFIED if not ((s == "inputs-binding" and inputs_text is not None)
                                          or (s == "index" and index_text is not None)
                                          or (s == "approval-signature" and operator_credentials is not None and inputs_text is not None)
                                          or (s == "control" and inputs_text is not None))]
    if operator_credentials is not None:
        nv.append("approval-challenge-binding")
    out = {"result": "INVALID", "stage": None, "why": None, "not_verified": nv, "records": 0}
    try:
        lines = _loads_lines(decisions_text, "decisions")
        records, hashes = [], []
        for i, line in enumerate(lines):
            if not isinstance(line, dict) or not isinstance(line.get("coseHex"), str):
                raise CedulonError("record-header", f"record {i}: no coseHex")
            try:
                octets = bytes.fromhex(line["coseHex"])
            except ValueError:
                raise CedulonError("record-header", f"record {i}: coseHex is not hex")
            payload = _cose(octets, record_key_pem, CT_RECORD, "record-header", "record-signature")
            records.append(_record_claims(payload, line.get("claims")))
            hashes.append(hashlib.sha256(octets).hexdigest())
        for i, c in enumerate(records):                   # §4.4: walk the chain over every presented record
            want = None if i == 0 else hashes[i - 1]
            if c["prevRecordHash"] != want:
                raise CedulonError("chain", f"record {i}: prevRecordHash does not link to the previous record")
        out["records"] = len(records)
        inputs = {}
        if inputs_text is not None:                       # inputs-binding (profile §4.1 + CEDULON §7)
            for i, row in enumerate(_loads_lines(inputs_text, "inputs")):
                if not (isinstance(row, dict) and isinstance(row.get("ref"), str) and "inputs" in row):
                    raise CedulonError("inputs-binding", f"inputs row {i}: not {{ref, inputs}}")
                if row["ref"] in inputs:
                    raise CedulonError("inputs-binding", f"inputs row {i}: duplicate ref")
                inputs[row["ref"]] = row["inputs"]
            for i, c in enumerate(records):
                if c["inputsHash"] is None:
                    continue
                if c["ref"] not in inputs:
                    raise CedulonError("inputs-binding", f"record {i}: no inputs row for its ref")
                if hashlib.sha256(jcs(inputs[c["ref"]])).hexdigest() != c["inputsHash"]:
                    raise CedulonError("inputs-binding", f"record {i}: SHA-256(JCS(inputs)) != the signed inputsHash")

        rows = []
        for i, e in enumerate(_loads_lines(effects_text, "effects")):
            rc = e.get("receipt") if isinstance(e, dict) else None
            if not isinstance(rc, dict):
                raise CedulonError("effect-binding", f"effect {i}: no extract")
            signed = _extract(rc.get("body"), rc.get("signature"), extract_key_pem)
            if "row" in e:                                # a row presented beside the extract is one the extract signs
                pres = e["row"]                           # (MUST-T4-2's rule for records, applied to rows; JCS bytes)
                if not isinstance(pres, dict) or not any(jcs(pres) == jcs(r) for r in signed):
                    raise CedulonError("effect-binding", f"effect {i}: the row presented beside the extract is not one it signs")
            rows += signed
        allows = {c["ref"]: c for c in records if c["decision"] == "allow"}
        refused = {c["ref"] for c in records if c["decision"] != "allow" and c["ref"]}
        seen = {}
        for row in rows:
            seen[row["ref"]] = seen.get(row["ref"], 0) + 1
            if row["ref"] in allows:
                a = allows[row["ref"]]
                if row["effectHash"] != a["effectHash"]:
                    raise CedulonError("effect-binding", f"effect-mismatch under ref {row['ref']}")
                if row["effectClass"] != a["effectClass"]:
                    raise CedulonError("effect-binding", f"effect-class-mismatch under ref {row['ref']}")
            elif row["ref"] in refused:
                raise CedulonError("effect-binding", f"effect-against-refusal under ref {row['ref']}")
            else:
                raise CedulonError("effect-binding", f"effect-without-decision under ref {row['ref']}")
        per_ref = {}
        for c in records:
            if c["decision"] == "allow":
                per_ref[c["ref"]] = per_ref.get(c["ref"], 0) + 1
        for ref, n in per_ref.items():
            if seen.get(ref, 0) < n:
                raise CedulonError("effect-binding", f"decision-without-effect under ref {ref}")
            if seen.get(ref, 0) > n:
                raise CedulonError("effect-binding", f"effect-without-decision under ref {ref}")

        if index_text is not None:                        # index: every row names something the ledger holds
            effect_refs = {r["ref"] for r in rows}
            for i, row in enumerate(_loads_lines(index_text, "index")):
                kind, ref = (row.get("kind"), row.get("ref")) if isinstance(row, dict) else (None, None)
                if kind == "effect":
                    held = ref in effect_refs
                elif kind in DECISIONS:
                    held = any(c["ref"] == ref and c["decision"] == kind for c in records)
                else:
                    raise CedulonError("index", f"index row {i}: unknown kind {kind!r}")
                if not held:
                    raise CedulonError("index", f"index row {i}: names a {kind} under ref {ref} the ledger does not hold")
        if operator_credentials is not None and inputs_text is not None:     # approval-signature
            creds = {c.get("id"): c for c in (operator_credentials or {}).get("credentials", []) if isinstance(c, dict)}
            for i, c in enumerate(records):
                ap = (inputs.get(c["ref"]) or {}).get("approver") if isinstance(inputs.get(c["ref"]), dict) else None
                if ap is None:
                    continue
                sig = ap.get("signature") if isinstance(ap, dict) else None
                if not isinstance(sig, dict):
                    raise CedulonError("approval-signature", f"record {i}: approval without an assertion")
                held = [j for j, d in enumerate(records) if d["ref"] == ap.get("resolves") and d["decision"] == "defer"]
                if not held or hashes[held[0]] != sig.get("deferRecordHash"):
                    raise CedulonError("approval-signature", f"record {i}: deferRecordHash is not the held defer record")
                cred = creds.get(sig.get("credentialId"))
                if cred is None or cred.get("sub") != sig.get("sub") or not _webauthn_ok(sig, cred):
                    raise CedulonError("approval-signature", f"record {i}: the operator's WebAuthn assertion does not verify")
        prev_cp = None
        for i, cp in enumerate(_loads_lines(checkpoints_text, "checkpoints")):
            if not isinstance(cp, dict) or not isinstance(cp.get("coseHex"), str):
                raise CedulonError("checkpoint-signature", f"checkpoint {i}: no coseHex")
            octets = bytes.fromhex(cp["coseHex"])
            p = _cose(octets, checkpoint_key_pem, CT_CHECKPOINT, "checkpoint-signature", "checkpoint-signature")
            if not isinstance(p, dict) or set(p) != set(CHECKPOINT_LABELS):
                raise CedulonError("checkpoint-signature", "checkpoint claim map without exactly -70101..-70107")
            k = {CHECKPOINT_LABELS[l]: v for l, v in p.items()}
            if not all(_is_uint(k[n]) for n in ("epoch", "startMs", "endMs", "receiptCount")):
                raise CedulonError("checkpoint-signature", "structural checkpoint claim not a uint")
            if cp.get("claims") != k:
                raise CedulonError("checkpoint-signature", "decoded checkpoint claims differ from those presented")
            win = [j for j, c in enumerate(records) if k["startMs"] <= c["timestampMs"] < k["endMs"]]
            if k["receiptCount"] != len(win):
                raise CedulonError("checkpoint-coverage", f"receiptCount {k['receiptCount']} but {len(win)} records in the window")
            head = hashes[max(win)] if win else None
            if k["chainHeadHash"] != head:
                raise CedulonError("checkpoint-coverage", "chainHeadHash is not the last record of the window")
            if k["prevCheckpointHash"] != prev_cp:
                raise CedulonError("checkpoint-coverage", "prevCheckpointHash does not link to the previous checkpoint")
            if k["totals"] is not None:
                want = {d: str(sum(1 for j in win if records[j]["decision"] == d)) for d in DECISIONS}
                if k["totals"] != want:
                    raise CedulonError("checkpoint-totals", f"checkpoint-total-mismatch: signed {k['totals']}, counted {want}")
            prev_cp = hashlib.sha256(octets).hexdigest()
        if inputs_text is not None:                       # control: no allow inside a halt window
            halted = False
            for i, c in enumerate(records):
                ctl = (inputs.get(c["ref"]) or {}).get("control") if isinstance(inputs.get(c["ref"]), dict) else None
                action = ctl.get("action") if isinstance(ctl, dict) else None
                if action == "halt" and c["decision"] == "allow":
                    halted = True
                elif action == "resume" and c["decision"] == "allow":
                    halted = False
                elif halted and c["decision"] == "allow":
                    raise CedulonError("control", f"record {i}: an allow inside a halt window")
        out.update(result="VALID", why="every in-scope stage verifies")
        return out
    except CedulonError as e:
        out.update(stage=e.stage, why=str(e)[:300])
        return out
    except Exception as e:  # noqa: BLE001 — hostile input is a verdict, never a crash
        out.update(stage="malformed", why=f"{type(e).__name__}: {e}"[:300])
        return out
