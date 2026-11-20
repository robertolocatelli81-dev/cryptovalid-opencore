#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
"""
CryptoValid Open Core — MCP server (stdio): agents that can PROVE what they did.

Status: EXPERIMENTAL. Outside the maintained core of cryptovalid-opencore (README, "Core and experimental
modules"): kept, installed and tested, no new scope is added here.

SPDX-License-Identifier: AGPL-3.0-or-later
Copyright (C) 2026 Roberto Locatelli

Exposes CryptoValid to any MCP client (IDE assistants, desktop agents, other agents)
so an agent can VERIFY evidence anyone hands it — and, behind an explicit human
gate, SEAL its own actions into a tamper-evident, signed, RFC 3161-anchorable
archive that any third party re-verifies offline with nothing but this repo.

Design rules (they ARE the security model):
  - READ-ONLY BY DEFAULT. The verification tools are always available and touch
    nothing. Every read returns PROVENANCE (source path + SHA-256 + UTC time):
    a reading without provenance is not a CryptoValid reading.
  - WRITES ARE HUMAN-GATED, twice. `append_event` / `seal_segment` refuse unless
    the human set CRYPTOVALID_MCP_ALLOW_WRITE=1 (opt-in, never default) AND the
    call carries the confirm_token equal to CRYPTOVALID_MCP_CONFIRM. The archive
    written is itself the hash-chained audit trail of every gated action.
  - LEAST PRIVILEGE. No tool reads keys or secrets; signing happens only through
    the backend URI the human configured (CRYPTOVALID_SIGNING_BACKEND — file:,
    pkcs11:, awskms:, vault:, nethsm:), where the private key never enters this
    process for the HSM/KMS backends.
  - ZERO DEPENDENCIES. The MCP stdio transport is newline-delimited JSON-RPC 2.0,
    implemented here with the Python stdlib only — same ethos as the rest of the
    repo ("verify with nothing but this repository").

Usage (stdio):   python3 cryptovalid_mcp.py
Client config:   {"command": "python3", "args": ["/path/to/opencore/cryptovalid_mcp.py"]}
Enable writes:   CRYPTOVALID_MCP_ALLOW_WRITE=1 CRYPTOVALID_MCP_CONFIRM=<token> \
                 CRYPTOVALID_SIGNING_BACKEND='vault:url=...;key=...' [CRYPTOVALID_TSA_URL=...]

Honest scope: sealing proves what was recorded, when, in which order and who
signed — never the truth of the recorded facts.
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
import hashlib
import json
import os
import sys
from datetime import datetime, timezone
from typing import Dict, Optional

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
import cryptovalid_ingest as ingest  # noqa: E402
import evidence_pack  # noqa: E402
import verifier  # noqa: E402

SERVER_NAME = "cryptovalid"
SERVER_VERSION = "1.0.0"
PROTOCOL_FALLBACK = "2024-11-05"

_WRITE_ENABLED = os.environ.get("CRYPTOVALID_MCP_ALLOW_WRITE") == "1"


# ────────────────────────────────────────────────────────────── provenance

def _sha256_file(p: str) -> Optional[str]:
    try:   # SPEC §5 step 0: opened once without blocking, hashed in blocks (a FIFO left the server waiting, 18/11/2026)
        return verifier.sha256_regular(p, float("inf"))
    except OSError:   # not a regular file (InputNotRegular), absent, unreadable: no provenance hash, never a wait
        return None


def _prov(source: str, digest: Optional[str]) -> Dict:
    return {"source": os.path.abspath(source), "sha256": digest,
            "verified_at_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "verifier": f"{SERVER_NAME}-mcp/{SERVER_VERSION}"}


def _gate(args: Dict) -> Optional[Dict]:
    """Double human gate for every write. Returns a refusal dict, or None to pass."""
    if not _WRITE_ENABLED:
        return {"blocked": True,
                "reason": "writes disabled: the human must set CRYPTOVALID_MCP_ALLOW_WRITE=1"}
    expected = os.environ.get("CRYPTOVALID_MCP_CONFIRM", "")
    if not expected or args.get("confirm_token") != expected:
        return {"blocked": True,
                "reason": "confirm_token missing/incorrect: human confirmation required"}
    return None


def _backend():
    """Signing backend from the URI the human configured; None = unsigned (declared)."""
    uri = os.environ.get("CRYPTOVALID_SIGNING_BACKEND", "")
    if not uri:
        return None
    from cryptovalid_kms import backend_from_uri
    return backend_from_uri(uri)


# ────────────────────────────────────────────────────────────── tools (read)

_HEX_DIGITS = "0123456789abcdef"


def t_verify_ledger(args: Dict) -> Dict:
    """SPEC §22 rule 5 (Unreleased): with `expected_pubkey_hex` the Ed25519 signature of every entry is verified against
    that key, on the same bytes the chain was checked on (one read), and `valid` says whether both hold; without it the
    chain is checked as before and `signatures.checked: false` says the signatures were not."""
    path = args["path"]
    pk = args.get("expected_pubkey_hex")
    if pk is None:
        r = verifier.verify_ledger(path)
        return {"result": r,
                "signatures": {"checked": False,
                               "note": "signatures NOT verified: pass expected_pubkey_hex (the Ed25519 key you trust) "
                                       "to verify the signature of every entry"},
                "provenance": _prov(path, _sha256_file(path))}
    if len(pk) != 64 or any(c not in _HEX_DIGITS for c in pk):
        return {"error": "expected_pubkey_hex must be 64 lowercase hex characters (an Ed25519 public key)"}
    try:
        data = verifier.read_regular(path)   # SPEC §5 step 0, read once: the chain and the signatures on the same bytes
    except OSError as e:
        return {"error": f"unreadable: {type(e).__name__}"}
    r = verifier._verify_ledger_data(path, data)
    import signer
    try:
        try:
            with evidence_pack._lines(data) as f:
                lines = [signer._load_line(ln) for ln in f if ln.strip()]
        except UnicodeDecodeError:
            lines = [signer._Undecodable("not_utf8")]
        sv = signer.verify_ledger_signatures(lines, pk)
        sigs = {"checked": True, "pinned_key": pk, **sv}
    except RuntimeError as e:   # no `cryptography` here: the signatures cannot be checked, never a pass
        sigs = {"checked": False, "pinned_key": pk, "ok": False, "error": f"backend_missing: {str(e)[:120]}"}
    return {"result": r, "signatures": sigs,
            "valid": r.get("verdict") == "PASS" and sigs.get("ok") is True,
            "provenance": {**_prov(path, None), "sha256": hashlib.sha256(data).hexdigest()}}


def t_verify_pack(args: Dict) -> Dict:
    d = args["pack_dir"]
    r = evidence_pack.verify_pack(d)
    man = os.path.join(d, "MANIFEST.json")
    return {"result": r, "provenance": _prov(man, _sha256_file(man))}


def t_verify_ap2_evidence(args: Dict) -> Dict:
    try:
        import ap2_evidence   # ap2-evidence-pack (0.18.0: no longer shipped here; the `ap2` extra installs it)
    except ImportError:
        return {"error": "ap2-evidence-pack not installed: pip install 'cryptovalid-opencore[ap2]'"}
    path = args["path"]
    r = ap2_evidence.verify_evidence(path)
    return {"result": r, "provenance": _prov(path, _sha256_file(path))}


def t_verify_archive(args: Dict) -> Dict:
    d = args["directory"]
    r = ingest.verify_archive(
        d, prefix=args.get("prefix", "ledger"),
        expected_pubkey_hex=args.get("expected_pubkey_hex"),
        lotl_check=bool(args.get("lotl_check", False)),      # network, opt-in per call
        lotl_member_states=args.get("lotl_member_states"))
    head = os.path.join(d, f"{args.get('prefix', 'ledger')}.head.json")
    return {"result": r, "provenance": _prov(head, _sha256_file(head))}


# ────────────────────────────────────────────────────────────── tools (write, gated)

def _ingestor(directory: str):
    return ingest.Ingestor(directory, batch_size=1, backend=_backend(),
                           tsa_url=os.environ.get("CRYPTOVALID_TSA_URL"))


def t_append_event(args: Dict) -> Dict:
    refusal = _gate(args)
    if refusal:
        return refusal
    if not isinstance(args.get("event"), dict):
        return {"error": "event must be a JSON object"}
    w = _ingestor(args["directory"])
    try:
        rec = w.append(args["event"])
    finally:
        w.close(seal=False)
    return {"appended": True, "record": rec,
            "signed": _backend() is not None,
            "note": None if _backend() else
            "UNSIGNED archive (no CRYPTOVALID_SIGNING_BACKEND): integrity yes, authorship no"}


def t_seal_segment(args: Dict) -> Dict:
    refusal = _gate(args)
    if refusal:
        return refusal
    w = _ingestor(args["directory"])
    try:
        sth = w.seal()
    finally:
        w.close(seal=False)
    return {"sealed": bool(sth), "sth": sth or {"reason": "empty segment"}}


_TOOLS = {
    "verify_ledger": {
        "fn": t_verify_ledger, "readonly": True,
        "description": ("Verify one hash-chained JSONL ledger: every self_hash and prev_hash link (SPEC §5). "
                        "With expected_pubkey_hex, also the Ed25519 signature of every entry against that key "
                        "(signatures, and valid = chain and signatures both hold); without it the signatures are "
                        "NOT checked and the answer says so (signatures.checked: false). "
                        "READ-ONLY; returns verdict + provenance (path, SHA-256, UTC)."),
        "schema": {"type": "object", "additionalProperties": False, "required": ["path"],
                   "properties": {"path": {"type": "string",
                                           "description": "path to the .jsonl ledger"},
                                  "expected_pubkey_hex": {
                                      "type": "string",
                                      "description": "the Ed25519 public key (64 lowercase hex) every entry must be "
                                                     "signed by; absent = signatures not checked"}}}},
    "verify_pack": {
        "fn": t_verify_pack, "readonly": True,
        "description": ("Independently verify a CryptoValid evidence pack (file digests, "
                        "manifest, every ledger's chain+signatures, truncation guard, RFC 3161 "
                        "token). READ-ONLY, fail-closed; returns verdict + provenance."),
        "schema": {"type": "object", "additionalProperties": False, "required": ["pack_dir"],
                   "properties": {"pack_dir": {"type": "string"}}}},
    "verify_ap2_evidence": {
        "fn": t_verify_ap2_evidence, "readonly": True,
        "description": ("Offline re-verification of an ap2-evidence-pack file (agentic-payment "
                        "SD-JWT mandates): digest, every ES256 signature with the SNAPSHOTTED "
                        "key material, disclosures, cross-artifact hash bindings, RFC 3161 token. "
                        "READ-ONLY, fail-closed; reports each key's provenance_class honestly."),
        "schema": {"type": "object", "additionalProperties": False, "required": ["path"],
                   "properties": {"path": {"type": "string",
                                           "description": "path to the evidence .json file"}}}},
    "verify_archive": {
        "fn": t_verify_archive, "readonly": True,
        "description": ("Verify a whole ingestion archive: segment chains, Merkle STH chain, "
                        "signed HEAD (tail guard), signatures against an optional trusted-signer "
                        "set, RFC 3161 anchors; optional eIDAS/LOTL qualification (network, "
                        "opt-in via lotl_check). READ-ONLY; verdict + provenance."),
        "schema": {"type": "object", "additionalProperties": False, "required": ["directory"],
                   "properties": {"directory": {"type": "string"},
                                  "prefix": {"type": "string", "default": "ledger"},
                                  "expected_pubkey_hex": {
                                      "type": "array", "items": {"type": "string"},
                                      "description": "trusted signer set (hex pubkeys)"},
                                  "lotl_check": {"type": "boolean", "default": False},
                                  "lotl_member_states": {
                                      "type": "array", "items": {"type": "string"}}}}},
    "append_event": {
        "fn": t_append_event, "readonly": False,
        "description": ("WRITE (human-gated): append one event to the agent's tamper-evident "
                        "archive. Refuses unless CRYPTOVALID_MCP_ALLOW_WRITE=1 and confirm_token "
                        "matches CRYPTOVALID_MCP_CONFIRM. The archive is the audit trail."),
        "schema": {"type": "object", "additionalProperties": False, "required": ["directory", "event", "confirm_token"],
                   "properties": {"directory": {"type": "string"},
                                  "event": {"type": "object"},
                                  "confirm_token": {"type": "string"}}}},
    "seal_segment": {
        "fn": t_seal_segment, "readonly": False,
        "description": ("WRITE (human-gated): seal the current segment into a signed Merkle STH "
                        "(RFC 3161-anchored when CRYPTOVALID_TSA_URL is set). Same double gate "
                        "as append_event."),
        "schema": {"type": "object", "additionalProperties": False, "required": ["directory", "confirm_token"],
                   "properties": {"directory": {"type": "string"},
                                  "confirm_token": {"type": "string"}}}},
}


# ────────────────────────────────────────── MCP stdio transport (stdlib JSON-RPC)

def _rpc_result(id_, result: Dict) -> Dict:
    return {"jsonrpc": "2.0", "id": id_, "result": result}


def _rpc_error(id_, code: int, message: str) -> Dict:
    return {"jsonrpc": "2.0", "id": id_, "error": {"code": code, "message": message}}


_JSON_TYPES = {"string": str, "boolean": bool, "object": dict, "array": list}


def _argument_type_problem(args: Dict, properties: Dict) -> Optional[str]:
    """SPEC v0.13 §21 rule 5: an argument is of the JSON type its tool's input schema declares (`string`, `boolean`,
    `object`, `array` with `items` of a declared type); None, or what is wrong. Until 0.27.0 the types were not read:
    `"lotl_check": "false"` went through bool() and switched the network check ON."""
    for k, v in args.items():
        sch = properties.get(k, {})
        want = sch.get("type")
        if want is None:
            continue
        typ = _JSON_TYPES.get(want)
        if typ is None:   # a schema of this server with a type this check does not know: refused, never skipped
            return f"{k!r}: the schema type {want!r} is not checked by this server"
        if not isinstance(v, typ):
            return f"{k!r} must be a JSON {want}, got {type(v).__name__}"
        if want == "array" and "items" in sch:
            ityp = _JSON_TYPES.get(sch["items"].get("type"))
            if ityp is None or not all(isinstance(x, ityp) for x in v):
                return f"{k!r} must be an array of JSON {sch['items'].get('type')}"
    return None


def handle(msg) -> Optional[Dict]:
    """One JSON-RPC message in, zero/one out (notifications get no reply).
    SPEC v0.12 §20 rule 12 (19/11/2026), JSON-RPC 2.0 §4, §4.2 and §5.1: a message that is not an object, an id that
    is not a string or a number, a method that is not a string: -32600 with id null where the id could not be read; a
    message without an id is a notification: no reply, nothing run; a `params` that is not an object, a tool name that
    is not a string, `arguments` that is not an object: -32602.
    Until 0.26.0 each of these raised AttributeError or TypeError out of this function and the server stopped."""
    if not isinstance(msg, dict):
        return _rpc_error(None, -32600, "invalid request: a message is a JSON object"
                          + (" (batches are not supported)" if isinstance(msg, list) else ""))
    method, id_ = msg.get("method"), msg.get("id")
    if isinstance(id_, bool) or not (id_ is None or isinstance(id_, (str, int, float))):
        return _rpc_error(None, -32600, "invalid request: id is a string or a number")
    if not isinstance(method, str):
        return _rpc_error(id_, -32600, "invalid request: method is a string")
    if "id" not in msg:                  # a notification (e.g. notifications/initialized): JSON-RPC 2.0 §4.1, "The Server
        return None                      # MUST NOT reply"; nothing is run for it. Until 0.26.0 a tools/call without an id
    params = msg.get("params")           # ran the tool and was answered with id null
    if params is not None and not isinstance(params, dict):
        return _rpc_error(id_, -32602, "invalid params: params is a JSON object")
    params = params or {}
    if method == "initialize":
        proto = params.get("protocolVersion")
        if not isinstance(proto, str) or not proto:
            proto = PROTOCOL_FALLBACK
        return _rpc_result(id_, {
            "protocolVersion": proto,
            "capabilities": {"tools": {}},
            "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION}})
    if method == "ping":
        return _rpc_result(id_, {})
    if method == "tools/list":
        return _rpc_result(id_, {"tools": [
            {"name": n, "description": t["description"], "inputSchema": t["schema"]}
            for n, t in _TOOLS.items()]})
    if method == "tools/call":
        name = params.get("name")
        tool = _TOOLS.get(name) if isinstance(name, str) else None
        if not tool:
            return _rpc_error(id_, -32602, f"unknown tool {name!r}"[:200])
        args = params.get("arguments", {})
        if args is None:
            args = {}
        if not isinstance(args, dict):   # [] , "" , 0 and false too: until 0.26.0 `or {}` read them as "no arguments"
            return _rpc_error(id_, -32602, "arguments must be a JSON object")
        # closed by construction (SPEC v0.9 §17, 16/11/2026): an argument the tool does not take is refused, never ignored —
        # until 0.25.0 verify_ledger with {"expect_ledger_id": …} or verify_pack with a key to pin dropped it and answered PASS
        unknown = sorted(k for k in args if k not in tool["schema"].get("properties", {}))
        if unknown:
            return _rpc_error(id_, -32602, f"unknown argument(s) for {name}: {', '.join(repr(k) for k in unknown)[:200]} "
                                           f"(it takes: {', '.join(sorted(tool['schema'].get('properties', {})))})")
        bad = _argument_type_problem(args, tool["schema"].get("properties", {}))
        if bad:
            return _rpc_error(id_, -32602, f"invalid argument for {name}: {bad}"[:300])
        try:
            out = tool["fn"](args)
            is_err = bool(out.get("blocked") or out.get("error"))
            return _rpc_result(id_, {"content": [
                {"type": "text", "text": json.dumps(out, ensure_ascii=False)}],
                "isError": is_err})
        except KeyError as e:
            return _rpc_error(id_, -32602, f"missing required argument: {e}")
        except Exception as e:  # noqa: BLE001 - fail-honest: tipo+messaggio, mai traceback su stdout
            rec = getattr(e, "receipt", None)
            if isinstance(rec, dict):   # 0.22.0: a check that could not run here, with the verifier's COMPLETE receipt
                return _rpc_result(id_, {"content": [   # (evidence pack SPEC §10, ap2-evidence-pack 1.6.0 §6.10): never dropped
                    {"type": "text", "text": json.dumps({"result": rec, "check_not_run": str(e)[:200]}, ensure_ascii=False)}],
                    "isError": True})
            return _rpc_result(id_, {"content": [
                {"type": "text",
                 "text": json.dumps({"error": f"{type(e).__name__}: {str(e)[:200]}"})}],
                "isError": True})
    # a notification (no "id" member) was answered above with nothing; an id null is a Request (JSON-RPC 2.0 §4, §5:
    # the Server MUST reply): until 2026-11-20 an unknown method with id null was left without a reply
    return _rpc_error(id_, -32601, f"method not found: {method}")


try:   # 0.20.3: the one writer of every command (verifier.py): an outcome is written whole, or exit 74
    from verifier import Parser, emit, receipt_cli, say
except ImportError:   # python3 -m opencore.<module> from the parent directory
    from opencore.verifier import Parser, emit, receipt_cli, say


@receipt_cli
def main() -> int:
    for raw in getattr(sys.stdin, "buffer", sys.stdin):   # bytes: a line that is not UTF-8 is one bad message, not the end
        try:
            line = (raw.decode("utf-8") if isinstance(raw, bytes) else raw).strip()
        except UnicodeDecodeError:
            emit(json.dumps(_rpc_error(None, -32700, "parse error: the line is not UTF-8")), flush=True)
            continue
        if not line:
            continue
        try:   # NaN / Infinity are not JSON (RFC 8259 §6): a parse error, never an id echoed back as NaN
            msg = json.loads(line, parse_constant=_not_json)
        except (ValueError, RecursionError):   # RecursionError: a line nested deeper than the parser goes
            emit(json.dumps(_rpc_error(None, -32700, "parse error")), flush=True)
            continue
        try:
            reply = handle(msg)
        except Exception as e:  # noqa: BLE001 - one message never stops the server: JSON-RPC 2.0 §5.1, internal error
            reply = _rpc_error(None, -32603, f"internal error: {type(e).__name__}")
        if reply is not None:
            text = json.dumps(reply, ensure_ascii=False)
            try:
                text.encode("utf-8")
            except UnicodeEncodeError:   # a lone surrogate ("\ud800" in an id, a method, a path): written escaped
                text = json.dumps(reply)
            emit(text, flush=True)
    return 0


def _not_json(constant: str):
    raise ValueError(f"{constant} is not JSON")


if __name__ == "__main__":
    raise SystemExit(main())
