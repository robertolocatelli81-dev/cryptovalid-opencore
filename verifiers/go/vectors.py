#!/usr/bin/env python3
"""Genera vectors.json: forma canonica e SHA-256 calcolati dal riferimento Python (stdlib json, ensure_ascii).
Ogni altro linguaggio deve riprodurre gli stessi byte. Eseguire: python3 vectors.py > vectors.json"""
import json, hashlib
cases = [
    {"a": "<>&'/"},
    {"b": "\b\f\n\r\t\"\\", "ctl": "\x01\x1f", "del": "\x7f"},
    {"emoji": "\U0001F600", "bmp": "￿", "sep": " ", "nbsp": " "},
    {"￿": 1, "\U0001F600": 2, "z": 3, "Z": 4, "a b": 5, "": 6},
    {"neg": -5, "zero": 0, "t": True, "f": False, "n": None, "arr": [1, "x", [None, {}], {"k": []}]},
    {"nested": {"deep": {"deeper": {"é": "é", "é": "é"}}}},
    {"empty_s": "", "empty_o": {}, "empty_a": []},
    {"max": 2**53 - 1, "min": -(2**53 - 1)},
    {"idx": 0, "ts": "2026-09-14T00:00:00Z", "prev_hash": "0" * 64, "data": {"actor": "müller", "path": "/api/v1/query", "status_code": 200, "detail": ""}},
]
deep = "[" * 513 + "]" * 513
refuse = [  # texts every reference MUST refuse (Python verifier._loads_strict, JS cvverify, Go Parse)
    {"why": "float", "text": '{"x":1.5}'}, {"why": "exponent", "text": '{"x":1e3}'},
    {"why": "duplicate key", "text": '{"x":1,"x":2}'},
    {"why": "int above 2^53-1", "text": '{"x":9007199254740992}'}, {"why": "int below -(2^53-1)", "text": '{"x":-9007199254740992}'},
    {"why": "nesting 513 > 512", "text": '{"d":' + deep + "}"},
    {"why": "lone high surrogate", "text": '{"k":"\\ud800"}'}, {"why": "lone low surrogate", "text": '{"k":"\\udc00"}'},
    {"why": "high surrogate followed by non-low", "text": '{"k":"\\ud800\\u0041"}'},
    {"why": "trailing data", "text": '{"x":1} x'},
]
accept_escapes = [  # escapes that look like surrogates but are not: an escaped backslash, a valid pair
    '{"k":"\\\\ud800"}', '{"k":"\\ud83d\\ude00"}']
out = []
for c in cases:
    canon = json.dumps(c, sort_keys=True, separators=(",", ":"))
    out.append({"input": json.dumps(c, ensure_ascii=False), "canonical": canon, "sha256": hashlib.sha256(canon.encode()).hexdigest()})
for t in accept_escapes:
    c = json.loads(t); canon = json.dumps(c, sort_keys=True, separators=(",", ":"))
    out.append({"input": t, "canonical": canon, "sha256": hashlib.sha256(canon.encode()).hexdigest()})
print(json.dumps({"accept": out, "refuse": refuse}, indent=1, ensure_ascii=False))
