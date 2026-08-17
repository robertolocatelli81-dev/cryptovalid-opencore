#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Roberto Locatelli
"""Bench for the MCP server, over the REAL stdio JSON-RPC transport (subprocess).
Order of proof: the bench fails first (tamper -> FAIL, gate -> blocked), then the
positive path (handshake, verify, gated append+seal, archive verifies)."""
import json
import os
import subprocess
import sys
import tempfile
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
import signer  # noqa: E402
from test_evidence_pack import _make_ledger  # noqa: E402

_SERVER = os.path.join(_HERE, "cryptovalid_mcp.py")


class _Client:
    """Minimal MCP stdio client: newline-delimited JSON-RPC over a subprocess."""

    def __init__(self, env=None):
        self.p = subprocess.Popen([sys.executable, _SERVER],
                                  stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                  text=True, env={**os.environ, **(env or {})})
        self._id = 0
        r = self.request("initialize", {"protocolVersion": "2024-11-05",
                                        "clientInfo": {"name": "bench", "version": "0"}})
        assert r["result"]["serverInfo"]["name"] == "cryptovalid"
        self.notify("notifications/initialized")

    def request(self, method, params=None):
        self._id += 1
        self.p.stdin.write(json.dumps(
            {"jsonrpc": "2.0", "id": self._id, "method": method,
             "params": params or {}}) + "\n")
        self.p.stdin.flush()
        return json.loads(self.p.stdout.readline())

    def notify(self, method):
        self.p.stdin.write(json.dumps({"jsonrpc": "2.0", "method": method}) + "\n")
        self.p.stdin.flush()

    def call(self, name, arguments):
        r = self.request("tools/call", {"name": name, "arguments": arguments})
        body = json.loads(r["result"]["content"][0]["text"])
        return body, r["result"].get("isError", False)

    def close(self):
        self.p.stdin.close()
        self.p.wait(timeout=10)


class TestMcpBenchFailsFirst(unittest.TestCase):
    """Controllo positivo del banco: manomissioni e gate DEVONO fallire."""

    @classmethod
    def setUpClass(cls):
        cls.d = tempfile.mkdtemp()
        cls.ledger = os.path.join(cls.d, "l.jsonl")
        _make_ledger(cls.ledger)
        cls.c = _Client()

    @classmethod
    def tearDownClass(cls):
        cls.c.close()

    def test_tampered_ledger_fails(self):
        bad = os.path.join(self.d, "bad.jsonl")
        rows = [json.loads(x) for x in open(self.ledger)]
        rows[1]["data"]["r"] = "FORGED"
        with open(bad, "w") as f:
            for x in rows:
                f.write(json.dumps(x) + "\n")
        body, _ = self.c.call("verify_ledger", {"path": bad})
        self.assertNotEqual(body["result"]["verdict"], "PASS")

    def test_write_blocked_without_gate(self):
        body, is_err = self.c.call("append_event",
                                   {"directory": self.d, "event": {"x": 1},
                                    "confirm_token": "whatever"})
        self.assertTrue(body["blocked"] and is_err)
        self.assertIn("CRYPTOVALID_MCP_ALLOW_WRITE", body["reason"])

    def test_unknown_tool_is_rpc_error(self):
        r = self.c.request("tools/call", {"name": "rm_rf", "arguments": {}})
        self.assertIn("error", r)

    def test_missing_required_arg_clean_error(self):
        r = self.c.request("tools/call", {"name": "verify_ledger", "arguments": {}})
        self.assertIn("error", r)


class TestMcpPositive(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.d = tempfile.mkdtemp()
        cls.key = os.path.join(cls.d, "k.key")
        cls.pub = signer.keygen(cls.key)["public_key_hex"]
        ledger = os.path.join(cls.d, "l.jsonl")
        _make_ledger(ledger)
        cls.signed = os.path.join(cls.d, "signed.jsonl")
        signer.sign_ledger(ledger, cls.signed, cls.key)
        cls.archive = os.path.join(cls.d, "archive")
        cls.c = _Client(env={"CRYPTOVALID_MCP_ALLOW_WRITE": "1",
                             "CRYPTOVALID_MCP_CONFIRM": "si-roberto-conferma",
                             "CRYPTOVALID_SIGNING_BACKEND": f"file:{cls.key}"})

    @classmethod
    def tearDownClass(cls):
        cls.c.close()

    def test_tools_list_marks_gated_writes(self):
        r = self.c.request("tools/list")
        tools = {t["name"]: t["description"] for t in r["result"]["tools"]}
        self.assertEqual(len(tools), 5)
        for w in ("append_event", "seal_segment"):
            self.assertIn("human-gated", tools[w])

    def test_verify_ledger_with_provenance(self):
        body, is_err = self.c.call("verify_ledger", {"path": self.signed})
        self.assertFalse(is_err)
        self.assertEqual(body["result"]["verdict"], "PASS")
        self.assertEqual(len(body["provenance"]["sha256"]), 64)   # provenienza SEMPRE
        self.assertIn("verified_at_utc", body["provenance"])

    def test_wrong_token_still_blocked_even_with_gate_open(self):
        body, is_err = self.c.call("append_event",
                                   {"directory": self.archive, "event": {"x": 1},
                                    "confirm_token": "sbagliato"})
        self.assertTrue(body["blocked"] and is_err)

    def test_gated_append_seal_then_archive_verifies(self):
        for i in range(3):
            body, is_err = self.c.call("append_event",
                                       {"directory": self.archive,
                                        "event": {"agent_action": f"step-{i}"},
                                        "confirm_token": "si-roberto-conferma"})
            self.assertFalse(is_err)
            self.assertTrue(body["appended"] and body["signed"])
        body, is_err = self.c.call("seal_segment",
                                   {"directory": self.archive,
                                    "confirm_token": "si-roberto-conferma"})
        self.assertFalse(is_err)
        self.assertTrue(body["sealed"])
        self.assertEqual(body["sth"]["signer"], self.pub)
        # l'agente ha sigillato il proprio operato: ora CHIUNQUE lo riverifica
        body, is_err = self.c.call("verify_archive",
                                   {"directory": self.archive,
                                    "expected_pubkey_hex": [self.pub]})
        self.assertFalse(is_err)
        self.assertTrue(body["result"]["ok"])
        self.assertEqual(body["result"]["signers"], [self.pub])


if __name__ == "__main__":
    unittest.main(verbosity=2)
