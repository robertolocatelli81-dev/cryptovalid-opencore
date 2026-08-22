#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CryptoValid Open Core — MCP server (stdio): agents that can PROVE what they did.

SPDX-License-Identifier: AGPL-3.0-or-later
Copyright (C) 2026 Roberto Locatelli

Exposes CryptoValid to any MCP client (Claude Code, Claude Desktop, other agents)
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
    try:
        with open(p, "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()
    except OSError:
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

def t_verify_ledger(args: Dict) -> Dict:
    path = args["path"]
    r = verifier.verify_ledger(path)
    return {"result": r, "provenance": _prov(path, _sha256_file(path))}


def t_verify_pack(args: Dict) -> Dict:
    d = args["pack_dir"]
    r = evidence_pack.verify_pack(d)
    man = os.path.join(d, "MANIFEST.json")
    return {"result": r, "provenance": _prov(man, _sha256_file(man))}


def t_verify_ap2_evidence(args: Dict) -> Dict:
    import ap2_evidence
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
        "description": ("Verify one hash-chained JSONL ledger (and its Ed25519 signatures "
                        "if present). READ-ONLY; returns verdict + provenance (path, SHA-256, UTC)."),
        "schema": {"type": "object", "required": ["path"],
                   "properties": {"path": {"type": "string",
                                           "description": "path to the .jsonl ledger"}}}},
    "verify_pack": {
        "fn": t_verify_pack, "readonly": True,
        "description": ("Independently verify a CryptoValid evidence pack (file digests, "
                        "manifest, every ledger's chain+signatures, truncation guard, RFC 3161 "
                        "token). READ-ONLY, fail-closed; returns verdict + provenance."),
        "schema": {"type": "object", "required": ["pack_dir"],
                   "properties": {"pack_dir": {"type": "string"}}}},
    "verify_ap2_evidence": {
        "fn": t_verify_ap2_evidence, "readonly": True,
        "description": ("Offline re-verification of an ap2-evidence-pack file (agentic-payment "
                        "SD-JWT mandates): digest, every ES256 signature with the SNAPSHOTTED "
                        "key material, disclosures, cross-artifact hash bindings, RFC 3161 token. "
                        "READ-ONLY, fail-closed; reports each key's provenance_class honestly."),
        "schema": {"type": "object", "required": ["path"],
                   "properties": {"path": {"type": "string",
                                           "description": "path to the evidence .json file"}}}},
    "verify_archive": {
        "fn": t_verify_archive, "readonly": True,
        "description": ("Verify a whole ingestion archive: segment chains, Merkle STH chain, "
                        "signed HEAD (tail guard), signatures against an optional trusted-signer "
                        "set, RFC 3161 anchors; optional eIDAS/LOTL qualification (network, "
                        "opt-in via lotl_check). READ-ONLY; verdict + provenance."),
        "schema": {"type": "object", "required": ["directory"],
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
        "schema": {"type": "object", "required": ["directory", "event", "confirm_token"],
                   "properties": {"directory": {"type": "string"},
                                  "event": {"type": "object"},
                                  "confirm_token": {"type": "string"}}}},
    "seal_segment": {
        "fn": t_seal_segment, "readonly": False,
        "description": ("WRITE (human-gated): seal the current segment into a signed Merkle STH "
                        "(RFC 3161-anchored when CRYPTOVALID_TSA_URL is set). Same double gate "
                        "as append_event."),
        "schema": {"type": "object", "required": ["directory", "confirm_token"],
                   "properties": {"directory": {"type": "string"},
                                  "confirm_token": {"type": "string"}}}},
}


# ────────────────────────────────────────── MCP stdio transport (stdlib JSON-RPC)

def _rpc_result(id_, result: Dict) -> Dict:
    return {"jsonrpc": "2.0", "id": id_, "result": result}


def _rpc_error(id_, code: int, message: str) -> Dict:
    return {"jsonrpc": "2.0", "id": id_, "error": {"code": code, "message": message}}


def handle(msg: Dict) -> Optional[Dict]:
    """One JSON-RPC message in, zero/one out (notifications get no reply)."""
    method, id_ = msg.get("method"), msg.get("id")
    if method == "initialize":
        proto = (msg.get("params") or {}).get("protocolVersion") or PROTOCOL_FALLBACK
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
        params = msg.get("params") or {}
        name = params.get("name")
        tool = _TOOLS.get(name)
        if not tool:
            return _rpc_error(id_, -32602, f"unknown tool {name!r}")
        try:
            out = tool["fn"](params.get("arguments") or {})
            is_err = bool(out.get("blocked") or out.get("error"))
            return _rpc_result(id_, {"content": [
                {"type": "text", "text": json.dumps(out, ensure_ascii=False)}],
                "isError": is_err})
        except KeyError as e:
            return _rpc_error(id_, -32602, f"missing required argument: {e}")
        except Exception as e:  # noqa: BLE001 - fail-honest: tipo+messaggio, mai traceback su stdout
            return _rpc_result(id_, {"content": [
                {"type": "text",
                 "text": json.dumps({"error": f"{type(e).__name__}: {str(e)[:200]}"})}],
                "isError": True})
    if id_ is None:                      # notification (e.g. notifications/initialized)
        return None
    return _rpc_error(id_, -32601, f"method not found: {method}")


def main() -> int:
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except ValueError:
            print(json.dumps(_rpc_error(None, -32700, "parse error")), flush=True)
            continue
        reply = handle(msg)
        if reply is not None:
            print(json.dumps(reply, ensure_ascii=False), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
