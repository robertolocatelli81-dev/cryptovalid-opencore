#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
"""
CryptoValid Open Core — auditor-ready evidence pack (build + vendor-free verify).

SPDX-License-Identifier: AGPL-3.0-or-later
Copyright (C) 2026 Roberto Locatelli

The regtech time-sink is assembling evidence for an auditor. This turns one or more
hash-chained (and optionally Ed25519-signed) ledgers into a self-verifying BUNDLE:
  - MANIFEST.json  — subject, SHA-256 of every file, per-ledger hash/signature verdicts,
                     signer public keys, a manifest digest, and an OPTIONAL RFC 3161 stamp;
  - SUMMARY.md     — human-readable receipt + the exact command to re-verify;
  - the ledgers    — copied verbatim.

`verify_pack()` re-checks EVERYTHING with nothing but this repo (verifier.py + signer.py):
file digests == manifest, manifest self-consistent, and every ledger passes hash + signature.
No server, no account, no vendor — "trust replaced by verification". Closed GRC tools do not
give you this: their evidence lives in a vendor database and dies with the subscription.

Honest scope: proves what was recorded, when, in which order, and who signed — plus that it was
not altered afterwards. NOT the truth of the recorded facts. RFC 3161 is optional (needs openssl
+ a TSA); its absence never invalidates the pack (signatures + hash chain already stand); a claim without a token, or a
token that openssl reads here as not granted or bound to another digest, does (0.22.0, SPEC §10; the TSA's signature is
checked only when the caller pins the TSA's certificate, `--tsa-cert`, SPEC v0.8; without openssl the token is not read:
`time_anchor: instrument_failure`).

Usage:
  python3 evidence_pack.py build  out_dir/  ledger1.jsonl [ledger2.jsonl ...] [--subject "..."] [--tsa URL]
  python3 evidence_pack.py verify out_dir/ [--tsa-cert PEM ...]
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
import base64
import hashlib
import json
try:  # depth bound shared with the reference verifier (same repo, flat layout)
    from verifier import MAX_JSON_DEPTH as _MAX_JSON_DEPTH, json_nesting_depth as _json_depth
except Exception:  # noqa: BLE001 — packaged/relative layouts
    from .verifier import MAX_JSON_DEPTH as _MAX_JSON_DEPTH, json_nesting_depth as _json_depth  # type: ignore
import os
import shutil
import sys
from datetime import datetime, timezone
from typing import Dict, List, Optional

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
import signer  # noqa: E402
import verifier  # noqa: E402


def _sha256_file(p: str, limit: Optional[int] = None) -> str:
    """SHA-256 hex of a regular file, read in blocks (SPEC §5 step 0, §10, v0.11: 0.26.0 read the whole file into memory);
    `limit` None for the files build_pack has just copied, the verifier's bound in verify_pack"""
    return verifier.sha256_regular(p, 1 << 62 if limit is None else limit)


def _lines(data: bytes):
    """The lines of `data` as open(path, encoding="utf-8") gives them (strict UTF-8, universal newlines): what the readers
    of a ledger read from its path until 0.27.0, here from bytes read once (SPEC v0.13 §21 rule 7)."""
    import io
    return io.TextIOWrapper(io.BytesIO(data), encoding="utf-8")


def _canon(obj: Dict) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


def _first_entry(path: str) -> Dict:
    try:
        with os.fdopen(verifier.open_regular(path), encoding="utf-8") as f:   # SPEC §5 step 0
            return json.loads(f.readline() or "{}")
    except Exception:  # noqa: BLE001
        return {}


def _entries_and_head(path: str):
    """Ritorna (numero_entry, self_hash dell'ultima entry). Serve a rilevare il TRONCAMENTO: una catena
    append-only troncata resta valida da sola, ma non combacia con conteggio+testa impegnati nel manifest."""
    try:
        return _entries_and_head_data(verifier.read_regular(path))   # SPEC §5 step 0
    except OSError:
        return 0, None


def _entries_and_head_data(data: bytes):
    """_entries_and_head on the bytes of the file (SPEC v0.13 §21 rule 7)."""
    n, head = 0, None
    try:
        with _lines(data) as f:
            for ln in f:
                if ln.strip():
                    n += 1
                    head = json.loads(ln).get("self_hash")
    except Exception:  # noqa: BLE001
        pass
    return n, head


def _verify_rfc3161(tsr_b64: str, expected_digest_hex: str, timeout: int = 15) -> Dict:
    """Legame del token RFC 3161: status Granted E message-imprint == digest atteso. La firma della TSA NON è verificata qui
    (SPEC §10 `tsa_not_checked`; il controllo del token è `cryptovalid_tsa.verify_token`, SPEC §11).
    Chiude il buco 'token spazzatura creduto ancorato'. Se openssl assente: verified=None (onesto:
    'registrato ma NON verificato'), mai un falso True. openssl presente ma non avviabile qui, o nessun file
    temporaneo: CheckNotRun (exit 74), mai `verified: false` (0.20.3: con fork negato un pack valido era `valid: false`)."""
    exe = shutil.which("openssl")
    if not exe:
        return {"verified": None, "note": "openssl absent — token recorded but NOT verified"}
    import cryptovalid_tsa as _T
    d = _T._openssl_tmpdir()
    try:
        tsr = os.path.join(d, "t.tsr")
        _T._tmp_write(tsr, base64.b64decode(tsr_b64))
        r = _T._run_openssl(  # nosec B603 - exe da shutil.which('openssl'), args FISSI, no shell
            [exe, "ts", "-reply", "-in", tsr, "-text"], capture_output=True, text=True, timeout=timeout)
        if r.returncode < 0:   # 0.22.0 — SPEC §10, as ap2-evidence-pack 1.6.0 §6.10: a crashed tool is a check not run here
            raise CheckNotRun(f"cannot run openssl here: terminated by signal {-r.returncode}")
        text = r.stdout or ""
        granted = "Status: Granted" in text or "Granted." in text
        # estrai i BYTE della sezione 'Message data' dal dump openssl:
        #   "    0000 - 3d 56 2b 8b ... 8e   =V+.2(..F.4P.."  -> prendi solo i byte fra ' - ' e la colonna ASCII
        grab, hexbytes = False, []
        for ln in text.splitlines():
            if "Message data:" in ln:
                grab = True
                continue
            if grab:
                if ln.strip() and ln[0] not in " \t":
                    break
                if " - " not in ln:
                    continue
                hexpart = ln.split(" - ", 1)[1].split("   ")[0]      # scarta offset e colonna ASCII
                for tok in hexpart.replace("-", " ").split():
                    if len(tok) == 2 and all(c in "0123456789abcdefABCDEF" for c in tok):
                        hexbytes.append(tok.lower())
        imprint = "".join(hexbytes)
        imprint_ok = imprint == expected_digest_hex.lower()
        return {"verified": bool(granted and imprint_ok), "granted": granted, "imprint_ok": imprint_ok,
                "imprint_read": bool(imprint)}   # 0.22.0: internal (binding_mismatch vs token_invalid, SPEC §10); not in the receipt
    except CheckNotRun:
        raise
    except Exception as e:  # noqa: BLE001
        return {"verified": False, "note": f"{type(e).__name__}: {str(e)[:80]}"}
    finally:
        shutil.rmtree(d, ignore_errors=True)


def _rfc3161_stamp(digest_hex: str, tsa_url: str, timeout: int = 20) -> Dict:
    """Timestamp RFC 3161 OPZIONALE via openssl (graceful se assente). Non invalida mai il pack. openssl presente ma non
    avviabile qui, o nessun file temporaneo: CheckNotRun (exit 74, nessun pack scritto; 0.20.3)."""
    import cryptovalid_net as _net
    try:
        _net.check_url(tsa_url, _net.ALLOW_HTTP_OR_HTTPS)   # no file:// etc.
    except ValueError:
        return {"anchored": False, "note": "TSA URL scheme not allowed (http/https only)"}
    exe = shutil.which("openssl")
    if not exe:
        return {"anchored": False, "note": "openssl absent (RFC 3161 optional)"}
    import urllib.request
    import cryptovalid_tsa as _T
    d = _T._openssl_tmpdir()
    try:
        tsq = os.path.join(d, "q.tsq")
        r = _T._run_openssl(  # nosec B603 - exe da shutil.which('openssl'), argomenti list FISSI, no shell
            [exe, "ts", "-query", "-digest", digest_hex, "-sha256", "-cert", "-out", tsq],
            capture_output=True, timeout=timeout)
        if r.returncode != 0 or not os.path.exists(tsq):
            return {"anchored": False, "note": "openssl ts-query failed"}
        with open(tsq, "rb") as f:
            req = f.read()
        http = urllib.request.Request(tsa_url, data=req, method="POST",
                                      headers={"Content-Type": "application/timestamp-query"})
        with _net.open_url(http, timeout, _net.ALLOW_HTTP_OR_HTTPS) as r:
            resp = _net.read_body(r)   # SPEC v0.13 §21 rule 6: bounded
        tsr_b64 = base64.b64encode(resp).decode()
        # anchored only on a token whose imprint is THIS digest (2026-10-03: any HTTP body — an error page, a rejection, a token
        # for another digest — was recorded as anchored: True)
        chk = _verify_rfc3161(tsr_b64, digest_hex, timeout)
        if not chk.get("imprint_ok"):     # a token exists only on a granted status: openssl refuses a non-granted reply carrying one
            return {"anchored": False, "tsa": tsa_url, "note": "TSA reply carries no token for this digest"}
        return {"anchored": True, "tsa": tsa_url, "tsr_b64": tsr_b64}
    except CheckNotRun:
        raise
    except Exception as e:  # noqa: BLE001
        return {"anchored": False, "note": f"{type(e).__name__}: {str(e)[:80]}"}
    finally:
        shutil.rmtree(d, ignore_errors=True)


def _summary_md(m: Dict) -> str:
    lines = "\n".join(
        f"- `{l['file']}` — {l['entries']} entries · hash **{l['hash_verdict']}**"
        + (f" · signatures **{'OK' if l.get('signatures_ok') else 'FAIL'}**" if "signatures_ok" in l else "")
        for l in m.get("ledgers", []))
    ts = m.get("rfc3161_timestamp", {})
    return (
        f"# Evidence pack — {m.get('subject')}\n\n"
        f"- Format: `{m.get('pack_format')}` · created {m.get('created_utc')}\n"
        f"- Signers: {len(m.get('signer_pubkeys', []))}\n"
        f"- RFC 3161: {'anchored (' + str(ts.get('tsa')) + ')' if ts.get('anchored') else 'not anchored'}\n\n"
        f"## Ledgers\n{lines}\n\n"
        "## Verify it yourself (vendor-free)\n```\npython3 evidence_pack.py verify <this-folder>\n```\n"
        "`valid: true` = every file digest matches the manifest, the manifest is self-consistent, "
        "every ledger passes its hash chain and (if signed) its signatures, and a claimed RFC 3161 token is not refuted "
        "(granted and bound to this manifest's digest where openssl can read it; the TSA's signature is not checked) — "
        "checked with nothing but this repository.\n\n"
        "**Honest scope:** proves what/when/order/who-signed + non-alteration — not the truth of the facts.\n")


def build_pack(ledger_paths: List[str], out_dir: str, subject: str = "compliance evidence",
               tsa_url: Optional[str] = None, sign_key: Optional[str] = None,
               pq_pubkey_b64: Optional[str] = None, signer_pubkey_hex: Optional[str] = None) -> Dict:
    """`pq_pubkey_b64` + `signer_pubkey_hex`: the ML-DSA-65 AND Ed25519 keys the hybrid ledgers must be signed with
    (both pinned, or neither). Without them a ledger's `pq_protected` is recorded as null (present, unpinned) —
    never true on a self-declared key (council 15/09). With them, a ledger whose layer does not verify makes the
    build FAIL (council 16/09: a "hybrid pack" with a broken layer must not be written silently)."""
    if pq_pubkey_b64 and not signer_pubkey_hex:   # asymmetric, like the library: the PQ key sits on top of the Ed25519 key
        raise ValueError("pq_pubkey_b64 needs signer_pubkey_hex: hybrid means both keys are pinned (a classical pack may pin the Ed25519 key alone)")
    os.makedirs(out_dir, exist_ok=True)
    ledgers_meta: List[Dict] = []
    file_digests: Dict[str, str] = {}
    signers = set()
    for lp in ledger_paths:
        name = os.path.basename(lp)
        dst = os.path.join(out_dir, name)
        copy_output(lp, dst)   # 0.20.3: whole (temporary + rename) or nothing new; the digest is of the bytes at dst
        file_digests[name] = _sha256_file(dst)
        rec = verifier.verify_ledger(dst)
        n_entries, head = _entries_and_head(dst)
        entry = {"file": name, "entries": n_entries, "head_self_hash": head,   # commit vs TRONCAMENTO
                 "hash_verdict": rec.get("verdict"), "chain_integrity": rec.get("chain_integrity")}
        if _first_entry(dst).get("signature"):
            sv = signer.verify_file(dst, signer_pubkey_hex, pq_pubkey_b64)
            if pq_pubkey_b64 and sv.get("pq_protected") is not True:
                raise RuntimeError(f"{name}: the pinned post-quantum layer does not verify ({sv.get('pq_status')}): "
                                   "refusing to write a hybrid pack with a broken layer")
            entry["signatures_ok"] = sv["ok"]
            entry["signers"] = sv["signers"]
            # hybrid (0.12.0): true = every entry also carries a VALID ML-DSA-65 signature by the PINNED key
            # (pq_pubkey_b64) and Ed25519 holds; null = present but unpinned / unverifiable here; false = absent or
            # broken. The manifest itself is signed with Ed25519 only (manifest_signature): the flag is a
            # per-ledger statement, not a post-quantum signature of the pack.
            entry["pq_protected"] = sv.get("pq_protected", False)
            entry["pq_status"] = sv.get("pq_status", "absent")
            if sv.get("pq_signers"):
                entry["pq_signers"] = sv["pq_signers"]
            signers.update(sv["signers"])
        ledgers_meta.append(entry)
    manifest = {
        "pack_format": PACK_FORMAT, "subject": subject,
        "created_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "ledgers": ledgers_meta, "file_digests_sha256": file_digests,
        "signer_pubkeys": sorted(signers),
        "honest_scope": ("Proves what/when/order/who-signed + non-alteration + entry count & head per "
                         "ledger (so truncation is detectable when the manifest is signed). Not the truth "
                         "of the facts. An UNSIGNED manifest is integrity-checked, NOT authenticated: its "
                         "metadata (e.g. subject) is trustworthy only if manifest_signature verifies."),
    }
    manifest["manifest_digest_sha256"] = hashlib.sha256(_canon(manifest)).hexdigest()
    # FIRMA OPZIONALE del manifest (autentica i metadati + impegna conteggio/testa → chiude re-forge)
    if sign_key:
        try:
            from cryptography.hazmat.primitives import serialization as _ser
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey as _Sk
            sk = _Sk.from_private_bytes(bytes.fromhex(   # SPEC §5 step 0: a regular file or a pipe, bounded
                verifier.read_input_text(sign_key, verifier.KEY_MAX_BYTES).strip()))
            manifest["manifest_signer"] = sk.public_key().public_bytes(
                _ser.Encoding.Raw, _ser.PublicFormat.Raw).hex()
            manifest["manifest_signature"] = base64.b64encode(   # SPEC §22 rule 3: the tagged message of format 1.2
                sk.sign(manifest_signed_message(PACK_FORMAT, manifest["manifest_digest_sha256"]))).decode()
        except Exception as e:  # noqa: BLE001
            raise RuntimeError(f"manifest signing failed: {e}")
    manifest["rfc3161_timestamp"] = (_rfc3161_stamp(manifest["manifest_digest_sha256"], tsa_url)
                                     if tsa_url else {"anchored": False, "note": "no TSA provided"})
    write_output(os.path.join(out_dir, "MANIFEST.json"), json.dumps(manifest, ensure_ascii=False, indent=1, sort_keys=True))
    write_output(os.path.join(out_dir, "SUMMARY.md"), _summary_md(manifest))
    return {"pack_dir": out_dir, "manifest_digest": manifest["manifest_digest_sha256"],
            "ledgers": len(ledgers_meta), "signers": len(signers),
            "manifest_signed": bool(sign_key)}


# Closed manifest schema (SPEC §2.1, 2026-10-10): exactly what build_pack writes. Measured on 0.18.1: a MANIFEST written with an
# extra top-level key (digest recomputed over it), an extra key inside ledgers[0], or inside rfc3161_timestamp (outside the
# digest) all verified valid: true with no trace in the receipt.
MANIFEST_KEYS = frozenset({"pack_format", "subject", "created_utc", "ledgers", "file_digests_sha256", "signer_pubkeys", "honest_scope",
                           "manifest_digest_sha256", "manifest_signer", "manifest_signature", "rfc3161_timestamp"})
LEDGER_ENTRY_KEYS = frozenset({"file", "entries", "head_self_hash", "hash_verdict", "chain_integrity", "signatures_ok", "signers", "pq_protected", "pq_status", "pq_signers"})
RFC3161_KEYS = frozenset({"anchored", "tsa", "tsr_b64", "note"})   # every key _rfc3161_stamp and build_pack write (0.9.0-0.19.0)


def _manifest_unknown_fields(man: Dict) -> List[str]:
    out = [f"MANIFEST.{k}" for k in man if k not in MANIFEST_KEYS]
    leds = man.get("ledgers")
    for i, led in enumerate(leds if isinstance(leds, list) else []):   # 0.22.0: `ledgers: true` was a traceback
        if isinstance(led, dict):
            out += [f"ledgers[{i}].{k}" for k in led if k not in LEDGER_ENTRY_KEYS]
    ts = man.get("rfc3161_timestamp")
    if isinstance(ts, dict):
        out += [f"rfc3161_timestamp.{k}" for k in ts if k not in RFC3161_KEYS]
    return sorted(out)


STATES_VOCABULARY = "cryptovalid-evidence-pack/states-1"   # 0.22.0 — SPEC §10: immutable; a change of meaning is a new identifier
# SPEC v0.8 §10: a receipt computed with pinned TSA certificates (`tsa_certs`): states-1 plus `verified` and `tsa_unresolved`
# on time_anchor and the wider `token_invalid`. A receipt without a pin keeps states-1.
STATES_VOCABULARY_PINNED_TSA = "cryptovalid-evidence-pack/states-2"
# SPEC §22 rule 3 (Unreleased): format 1.2 has the members of 1.1; its manifest signature is over the domain-tagged message
# "cryptovalid-pack-manifest/2:" + manifest_digest_sha256, never a bare hash an entry signature could also be over.
# build_pack writes 1.2; a pack of 1.1 (signature over the bare digest) verifies as before. 1.0 is refused (SPEC §10).
PACK_FORMAT = "cryptovalid-evidence-pack/1.2"
PACK_FORMAT_1_1 = "cryptovalid-evidence-pack/1.1"
PACK_FORMATS = (PACK_FORMAT_1_1, PACK_FORMAT)                   # the formats this verifier admits
MANIFEST_SIGNATURE_DOMAIN = "cryptovalid-pack-manifest/2"


def manifest_signed_message(pack_format: str, digest_hex: str) -> bytes:
    """The bytes the manifest signature is over (SPEC §22 rule 3): tagged in format 1.2, the bare digest in 1.1."""
    if pack_format == PACK_FORMAT_1_1:
        return digest_hex.encode()
    return (MANIFEST_SIGNATURE_DOMAIN + ":" + digest_hex).encode()
_SIG_FIELDS = ("signature", "signer", "signature_pq", "signer_pq")   # SPEC §5 step 5: any of them opens the layer


def _subject(elements: List[tuple]) -> Dict:
    """SPEC §10 (the precedence of ap2-evidence-pack 1.6.0 §6.9): contradicted > not_evaluated/instrument_failure > other
    not_evaluated > verified; `verified` only when every element is; one reason per element that is not verified."""
    def rank(e):
        return 3 if e[0] == "contradicted" else 2 if e[1] == "instrument_failure" else 1 if e[0] == "not_evaluated" else 0
    state = max(elements, key=rank)[0]
    out = {"state": state, "reasons": [e[1] for e in elements if e[0] != "verified"]}
    details = [e[2] for e in elements if len(e) > 2 and e[2]]
    if details:
        out["detail"] = "; ".join(details)
    return out


def _refused(error: str, cls: str) -> Dict:
    """A refusal (SPEC §10): the fail values of every 0.21 field, the reason in `error`, no states."""
    return {"files_ok": False, "file_ok": {}, "manifest_ok": False, "manifest_authenticated": False,
            "ledgers_ok": False, "ledgers": [], "rfc3161": {}, "valid": False, "error": error,
            "admission": "refused", "refusal_class": cls, "states_vocabulary": STATES_VOCABULARY, "states": None}


def _manifest_type_problem(man: Dict) -> Optional[str]:
    """SPEC §10, class malformed: a field this verifier reads, of a type build_pack never writes. None when all hold."""
    for k in ("manifest_digest_sha256", "manifest_signer", "manifest_signature"):
        if k in man and not isinstance(man[k], str):
            return f"manifest_bad_type: {k} must be a string"
    if "rfc3161_timestamp" in man:
        ts = man["rfc3161_timestamp"]
        if not isinstance(ts, dict):
            return "manifest_bad_type: rfc3161_timestamp must be an object"
        if "anchored" not in ts or not isinstance(ts["anchored"], bool):
            return "manifest_bad_type: rfc3161_timestamp.anchored must be true or false"
        for k in ("tsa", "tsr_b64", "note"):
            if k in ts and not isinstance(ts[k], str):
                return f"manifest_bad_type: rfc3161_timestamp.{k} must be a string"
        if "tsr_b64" in ts and ts["anchored"] is not True:
            return "manifest_bad_type: rfc3161_timestamp.tsr_b64 without anchored: true"
    for i, lm in enumerate(man.get("ledgers") or []):
        if "entries" in lm and (not isinstance(lm["entries"], int) or isinstance(lm["entries"], bool)):
            return f"manifest_bad_type: ledgers[{i}].entries must be an integer"
        if "head_self_hash" in lm and not (lm["head_self_hash"] is None or isinstance(lm["head_self_hash"], str)):
            return f"manifest_bad_type: ledgers[{i}].head_self_hash must be a string or null"
        if "pq_protected" in lm and lm["pq_protected"] not in (True, False, None):
            return f"manifest_bad_type: ledgers[{i}].pq_protected must be true, false or null"
    return None


def _has_signature_field(path: str) -> bool:
    """SPEC §5 step 5: the signature layer is opened by a signature field on ANY entry (0.21.0 read entry 0 only)."""
    try:
        return _has_signature_field_data(verifier.read_regular(path))   # SPEC §5 step 0
    except OSError:
        return False


def _has_signature_field_data(data: bytes) -> bool:
    """_has_signature_field on the bytes of the file (SPEC v0.13 §21 rule 7)."""
    try:
        with _lines(data) as f:
            for ln in f:
                if not ln.strip():
                    continue
                try:
                    e = json.loads(ln)
                except (ValueError, RecursionError):
                    continue
                if isinstance(e, dict) and any(k in e for k in _SIG_FIELDS):
                    return True
    except (OSError, UnicodeDecodeError):
        pass
    return False


def _manifest_signature_element(man: Dict, manifest_signer_hex: Optional[str]) -> tuple:
    """(state, reason, detail) of the manifest signature, and whether it authenticates (SPEC §10, producer_signature)."""
    sig, pub = man.get("manifest_signature"), man.get("manifest_signer")
    if not sig:
        return ("not_evaluated", "not_present"), False
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey as _Pk
    except ImportError:
        return ("not_evaluated", "backend_missing", "manifest signature: cryptography not available"), False
    raw_sig = signer._b64_strict(sig, 64)
    if not (isinstance(pub, str) and signer._HEX64.fullmatch(pub)) or raw_sig is None:
        return ("contradicted", "signature_invalid", "manifest signature: manifest_signer must be 64 lowercase hex, "
                "manifest_signature strict base64 of 64 bytes"), False
    why = signer._edo().strict_problem(bytes.fromhex(pub), raw_sig)   # 0.22.0: small/mixed-order key or R refused
    if why is None:
        try:
            _Pk.from_public_bytes(bytes.fromhex(pub)).verify(
                raw_sig, manifest_signed_message(man.get("pack_format"), man["manifest_digest_sha256"]))
        except Exception:  # noqa: BLE001
            why = "bad_signature"
    if why is not None:
        return ("contradicted", "signature_invalid", f"manifest signature: {why}"), False
    if not manifest_signer_hex:
        return ("not_evaluated", "self_asserted"), True
    if pub != manifest_signer_hex:
        return ("not_evaluated", "key_unresolved", "manifest signature: signer is not the pinned manifest signer"), True
    return ("verified", None), True


def _ed_layer_element(name: str, sv: Dict, pinned: bool) -> tuple:
    fails = sv.get("failures") or []
    if fails:
        if all(f.get("reason") == "signer_mismatch" for f in fails):
            return ("not_evaluated", "key_unresolved", f"{name}: signer is not the pinned key")
        return ("contradicted", "signature_invalid", f"{name}: " + ", ".join(sorted({str(f.get('reason')) for f in fails}))[:160])
    if not sv.get("total") or sv.get("verified") != sv.get("total"):
        return ("contradicted", "signature_invalid", f"{name}: no entry verified")
    return ("verified", None) if pinned else ("not_evaluated", "self_asserted")


def _pq_layer_element(name: str, sv: Dict, claimed: bool, pinned: bool, pq, pq_reason: str) -> Optional[tuple]:
    """The post-quantum layer, an element only when the manifest claims it, a key pins it, or it is carried broken."""
    pqf = sv.get("pq_failures") or []
    if not (claimed or pinned or pqf):
        return None
    reasons = {f.get("reason") for f in pqf}
    if pqf:
        if reasons == {"pq_unverifiable"}:
            return ("not_evaluated", "backend_missing", f"{name}: ML-DSA-65 cannot be checked here")
        if reasons == {"pq_signer_mismatch"}:
            return ("not_evaluated", "key_unresolved", f"{name}: ML-DSA-65 signer is not the pinned key")
        return ("contradicted", "signature_invalid", f"{name}: ML-DSA-65 " + ", ".join(sorted(map(str, reasons))))
    if pq is True:
        return ("verified", None)
    if pq_reason in ("pq_absent", "pq_partial", "pq_invalid", "pq_layer_lost"):
        return ("contradicted", "signature_invalid", f"{name}: the manifest claims a post-quantum layer ({pq_reason})")
    if pq_reason == "pq_unverifiable" or sv.get("pq_status") == "unverifiable":
        return ("not_evaluated", "backend_missing", f"{name}: ML-DSA-65 cannot be checked here")
    return ("not_evaluated", "self_asserted", f"{name}: ML-DSA-65 verified against the key it carries")


def _time_anchor_element(ts, rfc: Dict) -> tuple:
    if not isinstance(ts, dict) or ts.get("anchored") is not True:
        return ("not_evaluated", "not_present")
    if "tsr_b64" not in ts:
        return ("contradicted", "token_missing", "anchored: true and no tsr_b64")
    v = rfc.get("verified")
    if v is True:
        return ("not_evaluated", "tsa_not_checked")
    if v is None:
        return ("not_evaluated", "instrument_failure", str(rfc.get("note") or "token not checked"))
    if rfc.get("imprint_read") and rfc.get("imprint_ok") is False:
        return ("contradicted", "binding_mismatch", "the token's imprint is another digest")
    return ("contradicted", "token_invalid", str(rfc.get("note") or ("status not granted" if rfc.get("granted") is False
                                                                     else "no imprint read")))


def _pinned_time_anchor(tsr_b64: str, digest_hex: str, tsa_certs, tsa_crls=None) -> tuple:
    """SPEC v0.8 §10, a pinned TSA: the token's element by §11 (cryptovalid_tsa.verify_token), and the `tsa_check` the
    receipt reports. Called only when the checks of §10 left `tsa_not_checked`. ETSI EN 319 102-1 V1.4.1 §5.1.3: a token
    not established under the pinned certificates (§11 step 7) is INDETERMINATE (`tsa_unresolved`), a token that fails
    its own checks (steps 1-6) is a contradiction. Proposed by Athena's review of 15/11/2026."""
    import cryptovalid_tsa as _T
    v = _T.verify_token(base64.b64decode(tsr_b64), bytes.fromhex(digest_hex), "sha256", tsa_certs,
                        **({"crls": tsa_crls} if tsa_crls is not None else {}))   # without CRLs: the call of v0.9
    check = {"status": v["status"], "reason": v["reason"], "detail": v["detail"],
             "gen_time": (v["tst_info"] or {}).get("gen_time"), "signer_sha256": v["signer_sha256"],
             "sha1_signature_legacy": v["sha1_signature_legacy"]}   # SPEC v0.10 §11 step 7
    if "revocation" in v:   # SPEC v0.10 §11 step 8: only with tsa_crls (a receipt without them is unchanged)
        check["revocation"] = v["revocation"]
    if v["status"] == "verified" and v["counts_as_timestamp"] is True:
        return ("verified", None), check
    if v["status"] == "not_evaluated":   # openssl absent: the signature was not checked here
        return ("not_evaluated", "instrument_failure", f"TSA pinned, token not checked: {v['reason']}"), check
    if v["status"] == "invalid" and v["reason"] == "not_issued_by_pinned_tsa":
        return ("not_evaluated", "tsa_unresolved", f"not established under the pinned TSA certificates: {v['detail']}"), check
    if v["status"] == "invalid" and v["reason"] == "signer_certificate_absent":   # SPEC v0.11 §11 step 6: not evaluated
        return ("not_evaluated", "tsa_unresolved", f"signer certificate neither in the token nor pinned: {v['detail']}"), check
    if v["status"] == "invalid" and v["reason"] == "imprint_mismatch":
        return ("contradicted", "binding_mismatch", "the token's imprint is another digest"), check
    if v["status"] == "invalid":
        return ("contradicted", "token_invalid", f"{v['reason']}: {v['detail']}"), check
    raise ValueError(f"verify_token with pinned certificates gave status {v['status']!r}")   # signature_only: impossible


def verify_pack(pack_dir: str, pq_pubkey_b64: Optional[str] = None, signer_pubkey_hex: Optional[str] = None,
                manifest_signer_hex: Optional[str] = None, tsa_certs: Optional[List] = None,
                tsa_crls: Optional[List] = None, require_signature_domain: bool = False) -> Dict:
    """The evidence pack's verify (SPEC §10). `tsa_certs` (SPEC v0.8): the TSA certificates the caller pins (paths or bytes,
    PEM or DER: the TSA certificate or a CA above it, as SPEC §11); then a token that binds the manifest digest is checked
    by §11, `time_anchor` can be `verified`, and the receipt names `states_vocabulary` states-2. None: as before v0.8.
    `tsa_crls` (SPEC v0.10 §11 step 8, needs `tsa_certs`): CRLs the caller pins for the TSA certificate's revocation.
    `require_signature_domain` (SPEC §22 rule 3): admit format 1.2 only (a 1.1 pack, whose manifest signature is over the
    bare digest, is format_unsupported); by default both are admitted."""
    if tsa_crls is not None and tsa_certs is None:
        raise ValueError("tsa_crls need tsa_certs: revocation is checked only for a token verified under pinned certificates")
    if tsa_certs is not None:
        import cryptovalid_tsa as _T
        if isinstance(tsa_certs, (str, bytes, bytearray)) or not isinstance(tsa_certs, (list, tuple)) or not tsa_certs:
            raise ValueError("tsa_certs: a non-empty list of certificate files or bytes, or None for no pin")
        _T._pem_certs(tsa_certs)   # a path that is not a readable file of certificates: ValueError naming it
    try:
        r = _verify_pack(pack_dir, pq_pubkey_b64, signer_pubkey_hex, manifest_signer_hex, tsa_certs, tsa_crls,
                         require_signature_domain)
    except CheckNotRun as e:
        if tsa_certs is not None and isinstance(getattr(e, "receipt", None), dict):
            e.receipt["states_vocabulary"] = STATES_VOCABULARY_PINNED_TSA
        raise
    if tsa_certs is not None:
        r["states_vocabulary"] = STATES_VOCABULARY_PINNED_TSA
    return r


def _verify_pack(pack_dir: str, pq_pubkey_b64: Optional[str], signer_pubkey_hex: Optional[str],
                 manifest_signer_hex: Optional[str], tsa_certs, tsa_crls=None, require_signature_domain: bool = False) -> Dict:
    """Verifica INDIPENDENTE dell'intero pack (l'auditor non usa alcun vendor): digest dei file ==
    manifest, manifest auto-consistente, ogni ledger passa hash + firme. Fail-closed.
    Post-quantum (council 16/09 round 2 — no circular pin): the layer is confirmed ONLY against keys the caller
    pins — `pq_pubkey_b64` + `signer_pubkey_hex` directly, or the keys recorded in the manifest when the caller
    pins the manifest signer (`manifest_signer_hex`) and the manifest signature verifies against it. Otherwise a
    ledger marked `pq_protected: true` is reported null with `pq_reason: manifest_unpinned` (the pack is NOT
    quantum-resistant on its own: its manifest is signed with Ed25519 only). A lost/invalid layer → sig_pass false
    (`pq_layer_lost`); a host that cannot verify ML-DSA → sig_pass false (`pq_unverifiable`).

    0.22.0 (SPEC §10): the receipt also carries `admission` / `refusal_class`, `states_vocabulary` and `states` (three
    subjects); a claimed RFC 3161 token that does not verify (or a claim without a token) makes the pack not valid; when
    openssl cannot be run here, CheckNotRun carries the COMPLETE receipt (`.receipt`)."""
    if pq_pubkey_b64 and not signer_pubkey_hex:
        raise ValueError("pq_pubkey_b64 needs signer_pubkey_hex: hybrid means both keys are pinned (a classical pack may pin the Ed25519 key alone)")
    try:   # SPEC §5 step 0 (v0.11): opened once without blocking (a FIFO here hung until 0.26.0), bounded
        raw = verifier.read_regular(os.path.join(pack_dir, "MANIFEST.json")).decode("utf-8")
    except verifier.InputTooLarge:
        return _refused("input_too_large: MANIFEST exceeds the verifier's size bound", "malformed")
    except verifier.InputNotRegular:
        return _refused("manifest_unreadable: not a regular file", "malformed")
    except (OSError, UnicodeDecodeError) as e:   # missing, not UTF-8 (audit V1 #5, 30/09/2026)
        return _refused(f"manifest_unreadable: {type(e).__name__}", "malformed")
    depth = _json_depth(raw)
    if depth > _MAX_JSON_DEPTH:
        # Nesting beyond the normative bound (linear pre-scan, same rule as verifier.py, 2026-09-13)
        return _refused(f"json_too_deep: MANIFEST nesting {depth} exceeds the acceptance-profile bound {_MAX_JSON_DEPTH}", "malformed")
    try:
        man = json.loads(raw, object_pairs_hook=verifier._reject_dup)   # 0.22.0: a key twice is a refusal, not "last wins"
    except ValueError as e:
        if str(e).startswith("duplicate JSON key"):
            return _refused(f"manifest_duplicate_key: {str(e)[19:][:120]}", "malformed")
        return _refused(f"manifest_not_json: {type(e).__name__}", "malformed")
    except RecursionError as e:
        return _refused(f"manifest_not_json: {type(e).__name__}", "malformed")
    # shape of the parts this function reads (audit V1 #5): anything else is a named refusal, never a traceback; a file
    # name must stay inside the pack (no absolute path, no '..' component), like a vector name in the runners
    def _inside(name):
        # separators of THIS platform only (on POSIX "\\" is an ordinary character, not a separator: NEMESIS P2, 01/10/2026)
        if not (isinstance(name, str) and name != "" and not os.path.isabs(name) and "\0" not in name):
            return False
        parts = name
        for sep in {os.sep, os.altsep or os.sep, "/"}:
            parts = parts.replace(sep, "/")
        return ".." not in parts.split("/")
    if not isinstance(man, dict):
        return _refused("manifest_not_an_object", "malformed")
    # 0.22.0 — SPEC §10: the format first (until 0.21.0 the field was not read). A later revision may add members: its
    # pack is format_unsupported, not unknown_member (the order of ap2-evidence-pack 1.6.0; NEMESIS 19/10/2026)
    admitted = (PACK_FORMAT,) if require_signature_domain else PACK_FORMATS
    if man.get("pack_format") not in admitted:
        return _refused(f"pack_format_unsupported: {json.dumps(man.get('pack_format'), ensure_ascii=False)[:80]} "
                        f"(this verifier admits {', '.join(admitted)})", "format_unsupported")
    unknown = _manifest_unknown_fields(man)
    if unknown:   # SPEC §2.1: the manifest is a closed object — named, never silent
        return _refused("manifest_unknown_field: " + ", ".join(unknown)[:200], "unknown_member")
    digs, leds = man.get("file_digests_sha256", {}), man.get("ledgers", [])
    if not isinstance(digs, dict) or not all(_inside(k) and isinstance(v, str) for k, v in digs.items()):
        return _refused("manifest_bad_file_digests: an object of file name (inside the pack) -> sha256 hex", "malformed")
    if not isinstance(leds, list) or not all(isinstance(lm, dict) and _inside(lm.get("file")) for lm in leds):
        return _refused("manifest_bad_ledgers: a list of objects with a file name inside the pack", "malformed")
    bad = _manifest_type_problem(man)
    if bad:
        return _refused(bad, "malformed")
    root = os.path.realpath(pack_dir)

    def _real_inside(path):   # where the file REALLY is: a symlink out of the pack is not read (NEMESIS P3, 01/10/2026)
        rp = os.path.realpath(path)
        return rp == root or rp.startswith(root + os.sep)
    sealed: List[tuple] = []
    file_ok = {}
    # SPEC v0.13 §21 rule 7: a ledger is read ONCE (bounded, as §5 step 0 says), and its digest, its chain, its
    # signatures and its count and head are all checked on those bytes. Until 0.27.0 the pack opened the ledger's path
    # five times: a ledger whose chain fails, committed to by the manifest, was valid when another file stood at the path
    # while the chain was read (measured with the file exchanged between the reads)
    # One file, one read, however the manifest spells its name ("l.jsonl", "./l.jsonl", a link inside the pack): the
    # bytes are kept under the real path each name had when it was first resolved. With file_digests_sha256 naming
    # "./l.jsonl" and ledgers naming "l.jsonl" the file was read twice, and a file exchanged between the two reads
    # made a pack whose manifest commits to a broken chain valid (measured on the first draft of this rule, 2026-11-20)
    key_of: Dict[str, str] = {}

    def _file_key(name: str) -> str:
        if name not in key_of:
            # a name the system does not open as a file ("l.jsonl/", "l.jsonl/.") is not another spelling of that file:
            # it keeps a key of its own and is read, and refused, under its own name as before
            last = name.replace(os.sep, "/").rsplit("/", 1)[-1]
            key_of[name] = "\0" + name if last in ("", ".") else os.path.realpath(os.path.join(pack_dir, name))
        return key_of[name]
    ledger_keys = {_file_key(lm["file"]) for lm in leds}
    snap_of: Dict[str, bytes] = {}

    def _take_snapshot(name: str, p: str) -> str:
        k = _file_key(name)
        if k not in snap_of:
            snap_of[k] = verifier.read_regular(p, verifier.MAX_INPUT_BYTES)
        return hashlib.sha256(snap_of[k]).hexdigest()
    for name, dig in man.get("file_digests_sha256", {}).items():
        p = os.path.join(pack_dir, name)
        try:   # SPEC §10 (v0.11): opened once without blocking, judged on the descriptor, bounded, hashed in blocks
            if _file_key(name) in ledger_keys:
                file_ok[name] = _real_inside(p) and _take_snapshot(name, p) == dig
            else:
                file_ok[name] = _real_inside(p) and _sha256_file(p, verifier.MAX_INPUT_BYTES) == dig
        except verifier.InputTooLarge:
            return _refused(f"input_too_large: file {name} exceeds the verifier's size bound ({verifier.MAX_INPUT_BYTES} "
                            "bytes)", "malformed")
        except (verifier.InputNotRegular, FileNotFoundError, NotADirectoryError):
            file_ok[name] = False              # absent or not a regular file: digest_mismatch, as before
        except OSError as e:
            return _refused(f"input_unreadable: file {name}: {e.strerror or type(e).__name__}", "malformed")
        sealed.append(("verified", None) if file_ok[name] else ("contradicted", "digest_mismatch", f"file {name}"))
    if not file_ok:
        sealed.append(("contradicted", "digest_mismatch", "no file listed in file_digests_sha256"))
    m2 = {k: v for k, v in man.items()
          if k not in ("manifest_digest_sha256", "rfc3161_timestamp",
                       "manifest_signature", "manifest_signer")}
    manifest_ok = hashlib.sha256(_canon(m2)).hexdigest() == man.get("manifest_digest_sha256")
    sealed.append(("verified", None) if manifest_ok else ("contradicted", "digest_mismatch", "manifest digest"))

    # FIX C — autenticità del manifest: se firmato, la firma DEVE verificare (chiude il re-forge); 0.22.0: chiavi e R di
    # ordine piccolo o misto rifiutati, manifest_signer e manifest_signature letti in modo stretto (SPEC §10)
    man_elem, manifest_authenticated = _manifest_signature_element(man, manifest_signer_hex)
    producer: List[tuple] = [man_elem]

    ledger_results, ledgers_ok = [], True
    for lm in man.get("ledgers", []):
        p = os.path.join(pack_dir, lm["file"])
        if _file_key(lm["file"]) not in snap_of and _real_inside(p):
            try:   # a ledger the manifest does not list in file_digests_sha256 (or one absent at that step): read once now
                _take_snapshot(lm["file"], p)
            except verifier.InputTooLarge:
                return _refused(f"input_too_large: file {lm['file']} exceeds the verifier's size bound "
                                f"({verifier.MAX_INPUT_BYTES} bytes)", "malformed")
            except (verifier.InputNotRegular, FileNotFoundError, NotADirectoryError):
                pass   # not a regular file: refused just below, as before
            except OSError as e:
                return _refused(f"input_unreadable: file {lm['file']}: {e.strerror or type(e).__name__}", "malformed")
        if not (_real_inside(p) and _file_key(lm["file"]) in snap_of):
            ledger_results.append({"file": lm["file"], "hash_pass": False, "sig_pass": False, "untruncated": False,
                                   "pq_protected": False, "pq_reason": "not_a_file_inside_the_pack"})
            sealed.append(("contradicted", "artifact_invalid", f"ledger {lm['file']}: not a file inside the pack"))
            ledgers_ok = False
            continue
        data = snap_of[_file_key(lm["file"])]   # the bytes read once (rule 7): every check below reads them, never the path again
        hp = verifier._verify_ledger_data(p, data).get("verdict") == "PASS"
        sealed.append(("verified", None) if hp else ("contradicted", "artifact_invalid", f"ledger {lm['file']}: hash chain"))
        sp = True
        pq, pq_reason = False, ""
        if _has_signature_field_data(data):
            expected_pq, expected_ed = pq_pubkey_b64, signer_pubkey_hex
            # council 16/09 round 3: the manifest signature covers the DECLARED digest string; the body is bound to it
            # only by manifest_ok — both must hold before any key recorded in the body is trusted, and the recorded
            # keys must be exactly one well-formed string each (a malformed manifest is "not pinned", never an exception)
            manifest_pinned = (bool(manifest_signer_hex) and manifest_authenticated and manifest_ok
                               and man.get("manifest_signer") == manifest_signer_hex)
            rec_pq, rec_ed = lm.get("pq_signers"), lm.get("signers")
            rec_ok = (isinstance(rec_pq, list) and len(rec_pq) == 1 and isinstance(rec_pq[0], str) and signer._b64_strict(rec_pq[0], signer.PQ_PK_LEN) is not None
                      and isinstance(rec_ed, list) and len(rec_ed) == 1 and isinstance(rec_ed[0], str) and signer._HEX64.fullmatch(rec_ed[0]))
            if expected_pq is None and lm.get("pq_protected") is True and manifest_pinned and rec_ok:
                expected_pq, expected_ed = rec_pq[0], rec_ed[0]   # pinned by a manifest the CALLER trusts, digest AND signature verified
            try:   # signer.verify_file(p, ...) on the bytes read once: the same lines, the same reader
                try:
                    with _lines(data) as f:
                        sig_lines = [signer._load_line(ln) for ln in f if ln.strip()]
                except UnicodeDecodeError:
                    # bytes that are not UTF-8 past the first block read (the signature field was found before them):
                    # a named failure of the layer. Until 0.27.0 verify_pack raised UnicodeDecodeError
                    sig_lines = [signer._Undecodable("not_utf8")]
                sv = signer.verify_ledger_signatures(sig_lines, expected_ed, expected_pq)
            except RuntimeError as e:   # no `cryptography` here: the layer cannot be checked (0.21.0: a traceback, exit 1)
                sp, pq, pq_reason = False, False, "signature_layer_unverifiable"
                producer.append(("not_evaluated", "backend_missing", f"ledger {lm['file']}: {str(e)[:80]}"))
                sv = None
            if sv is not None:
                sp = sv["ok"]
                pq = sv.get("pq_protected", False)
                if lm.get("pq_protected") is True and pq is not True:
                    if expected_pq is None:
                        if sv.get("pq_status") in ("absent", "partial", "invalid"):
                            pq_reason = "pq_" + sv["pq_status"]         # refuted by the file itself, whoever pins (round 3: never soften a fact)
                            sp = False                                   # 0.22.0 — SPEC §10: a claim the file refutes is not valid
                        else:
                            pq, pq_reason = None, "manifest_unpinned"   # nobody pinned a key: the claim is not confirmed, not refuted
                    else:
                        sp = False        # the manifest promised a post-quantum layer and it cannot be confirmed now
                        pq_reason = "pq_unverifiable" if sv.get("pq_status") == "unverifiable" else "pq_layer_lost"
                producer.append(_ed_layer_element(f"ledger {lm['file']}", sv, bool(expected_ed)))
                pqe = _pq_layer_element(f"ledger {lm['file']}", sv, lm.get("pq_protected") is True, expected_pq is not None,
                                        pq, pq_reason)
                if pqe is not None:
                    producer.append(pqe)
        elif signer_pubkey_hex:
            # SPEC §22 rule 4 (Unreleased): a pinned signer is a requirement on every ledger. Until 0.27.0 a ledger with no
            # signature at all left sig_pass true and the pack valid under the pin, the state alone saying not_present
            sp, pq_reason = False, "unsigned_but_signer_pinned"
            producer.append(("not_evaluated", "not_present", f"ledger {lm['file']}: not signed, a signer is pinned"))
        # FIX B — anti-troncamento: conteggio+testa devono combaciare col manifest
        n_entries, head = _entries_and_head_data(data)
        untruncated = (n_entries == lm.get("entries") and head == lm.get("head_self_hash"))
        if not untruncated:
            sealed.append(("contradicted", "binding_mismatch", f"ledger {lm['file']}: entry count or head"))
        ledger_results.append({"file": lm["file"], "hash_pass": hp, "sig_pass": sp,
                               "untruncated": untruncated, "pq_protected": pq, **({"pq_reason": pq_reason} if pq_reason else {})})
        ledgers_ok = ledgers_ok and hp and sp and untruncated
    files_ok = all(file_ok.values()) if file_ok else False
    if len(producer) > 1 and producer[0][1] == "not_present" and not manifest_signer_hex:
        producer = producer[1:]   # an unsigned manifest next to signed ledgers: the subject is the ledgers' layers
    # SPEC §22 rule 4 (Unreleased): a pinned manifest signer is a requirement. Until 0.27.0 a manifest not signed, or signed
    # by another key, left `valid` as it was under the pin (SPEC §10 "by design"); the pinned element must now be verified
    manifest_pin_holds = not manifest_signer_hex or man_elem[0] == "verified"

    # FIX D — RFC3161: verifica CRITTOGRAFICA del token (non credere al campo 'anchored'); 0.22.0: un token dichiarato che
    # non verifica, o dichiarato senza token, rende il pack non valido (SPEC §10)
    ts = man.get("rfc3161_timestamp", {})
    rfc = {"claimed": ts.get("anchored", False), "verified": None}
    not_run = None
    if ts.get("anchored") and "tsr_b64" in ts:
        try:
            rfc = {"claimed": True, **_verify_rfc3161(ts["tsr_b64"], man.get("manifest_digest_sha256", ""))}
        except CheckNotRun as e:
            not_run = e
            rfc = {"claimed": True, "verified": None, "note": f"check not run here: {e}"}
    anchor = _time_anchor_element(ts, rfc)
    if tsa_certs is not None and anchor == ("not_evaluated", "tsa_not_checked"):   # SPEC v0.8 §10: a pinned TSA
        try:
            anchor, rfc["tsa_check"] = _pinned_time_anchor(ts["tsr_b64"], man.get("manifest_digest_sha256", ""), tsa_certs,
                                                           tsa_crls)
        except CheckNotRun as e:
            not_run = e
            anchor = ("not_evaluated", "instrument_failure", f"check not run here: {e}")
    rfc.pop("imprint_read", None)

    # una firma manifest PRESENTE ma ROTTA = manomissione → invalida; assente = onesto non-autenticato
    signature_broken = bool(man.get("manifest_signature")) and not manifest_authenticated
    receipt = {"files_ok": files_ok, "file_ok": file_ok, "manifest_ok": manifest_ok,
               "manifest_authenticated": manifest_authenticated,
               "ledgers_ok": ledgers_ok, "ledgers": ledger_results,
               "rfc3161": rfc,
               "valid": bool(files_ok and manifest_ok and ledgers_ok and not signature_broken and anchor[0] != "contradicted"
                             and manifest_pin_holds),
               "admission": "admitted", "refusal_class": None, "states_vocabulary": STATES_VOCABULARY,
               "states": {"sealed_content": _subject(sealed), "producer_signature": _subject(producer),
                          "time_anchor": _subject([anchor])}}
    if not_run is not None:
        raise CheckNotRun(str(not_run), receipt=receipt)
    return receipt


try:   # 0.20.3: the one writer of every command (verifier.py): an outcome is written whole, or exit 74
    from verifier import CheckNotRun, Parser, check_not_run_exit, copy_output, emit, receipt_cli, say, write_output
except ImportError:   # python3 -m opencore.<module> from the parent directory
    from opencore.verifier import CheckNotRun, Parser, check_not_run_exit, copy_output, emit, receipt_cli, say, write_output


@receipt_cli
def main(argv: Optional[List[str]] = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    p = Parser(prog="cryptovalid-evidence-pack")
    sub = p.add_subparsers(dest="cmd")
    b = sub.add_parser("build")
    b.add_argument("out_dir"); b.add_argument("ledgers", nargs="+")
    b.add_argument("--subject", default="compliance evidence"); b.add_argument("--tsa")
    b.add_argument("--sign-key", help="Ed25519 keyfile to AUTHENTICATE the manifest (recommended)")
    v = sub.add_parser("verify"); v.add_argument("dir")
    import cryptovalid_tsa as _T
    v.add_argument("--tsa-cert", action="append", default=None, metavar="PEM", type=_T.tsa_cert_arg,
                   help="pin a TSA certificate (or a CA above it) and check the RFC 3161 token with it (SPEC §10-§11, "
                        "v0.8; repeat for several)")
    a = p.parse_args(argv)
    if a.cmd == "build":
        emit(json.dumps(build_pack(a.ledgers, a.out_dir, subject=a.subject, tsa_url=a.tsa,
                                    sign_key=a.sign_key), indent=1))
        return 0
    if a.cmd == "verify":
        try:
            r = verify_pack(a.dir, tsa_certs=a.tsa_cert)
        except CheckNotRun as e:   # 0.22.0 — SPEC §10: the complete receipt, then 74 (without one: receipt_cli, 74)
            if e.receipt is None:
                raise
            return check_not_run_exit(e, json.dumps(e.receipt, indent=1))
        emit(json.dumps(r, indent=1))
        return 0 if r["valid"] else 1
    p.print_help(); return 2


if __name__ == "__main__":
    raise SystemExit(main())
