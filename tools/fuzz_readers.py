#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Roberto Locatelli
"""Seeded mutation fuzzer of three readers of untrusted input (stdlib; deterministic per seed). Run every week by
.github/workflows/fuzz-weekly.yml on a new seed; the workflow is ported from omega-evidence (Apache-2.0, same author).

    python3 tools/fuzz_readers.py [--seed S] [--iterations N | --seconds T] [--json OUT] [--findings-dir DIR]
    python3 tools/fuzz_readers.py --ablate ledger|dsse|slhdsa   (positive control: exit 0 only if violations are seen)

Corpus, each valid before any mutation (else the run refuses, exit 2): `examples/sample_ledger.jsonl` for
verifier.verify_ledger; with `cryptography`, a DSSE envelope signed here with a fixed Ed25519 key for
cryptovalid_dsse.verify_envelope; with `slh-dsa`, the first anchor of spec/vectors/slhdsa/anchors_pq_scitt.json for
cryptovalid_slhdsa.verify_anchor. A target whose library is missing is left out and named in the summary.

Each iteration picks a target and one mutation of its bytes (bit flip, byte set, delete, insert, truncate, line removed /
duplicated / swapped; JSON: member removed, added, renamed, duplicated, value of another type, nesting) and calls it.

The summary (stdout, and --json) gives the seed, the iterations, the mutants each target accepted (an input left
equivalent, e.g. a ledger line re-serialised) and the SHA-256 of the sequence of verdicts.

Properties (a violation is written to the findings dir; exit 1):
  P1  ledger: PASS only if the entries, parsed HERE (json, a name twice refused), are a non-empty prefix of the
      original's. DSSE: valid only if the payload and payloadType, decoded HERE, are the original's. Anchor: valid only
      if the anchor, parsed HERE, is the original (and its `ts` of the same type).
  P2  no exception but the declared ones: verify_ledger, verify_envelope and verify_anchor raise nothing on these inputs.

--ablate replaces, in this process only, the check that each property rests on (the chain recomputation, the DSSE
signature, the SLH-DSA signature) with one that always passes: the same run must then report violations. A fuzzer that
cannot see a disabled check measures nothing.
"""
import argparse
import base64
import hashlib
import json
import os
import random
import sys
import tempfile
import time
import traceback

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)
import verifier  # noqa: E402
import cryptovalid_dsse  # noqa: E402
import cryptovalid_slhdsa  # noqa: E402


def _dup(pairs):
    d = {}
    for k, v in pairs:
        if k in d:
            raise ValueError("duplicate")
        d[k] = v
    return d


def parse(b: bytes):
    """The oracle's own parser: None when the bytes are not one JSON value (UTF-8, no name twice)."""
    try:
        return json.loads(b.decode("utf-8"), object_pairs_hook=_dup)
    except (ValueError, RecursionError):
        return None


WRONG = [None, True, 0, -1, 1.5, "", "x", [], {}, "00", 10 ** 30]


def mutate(b: bytes, rnd: random.Random) -> bytes:
    op = rnd.randrange(12)
    if not b:
        return b"{}"
    i = rnd.randrange(len(b))
    if op == 0:
        return b[:i] + bytes([b[i] ^ (1 << rnd.randrange(8))]) + b[i + 1:]
    if op == 1:
        return b[:i] + bytes([rnd.choice(b'{}[]",:\\0123456789abcdefAZ \n\t\x00\xff')]) + b[i + 1:]
    if op == 2:
        return b[:i] + b[i + 1:]
    if op == 3:
        return b[:i] + bytes([rnd.randrange(256)]) + b[i:]
    if op == 4:
        return b[:i]
    lines = b.split(b"\n")
    if op == 5 and len(lines) > 1:
        j = rnd.randrange(len(lines))
        return b"\n".join(lines[:j] + lines[j + 1:])
    if op == 6:
        j = rnd.randrange(len(lines))
        return b"\n".join(lines[:j + 1] + lines[j:])
    if op == 7 and len(lines) > 2:
        j = rnd.randrange(len(lines) - 1)
        lines[j], lines[j + 1] = lines[j + 1], lines[j]
        return b"\n".join(lines)
    # JSON-level mutations of one line / document
    j = rnd.randrange(len(lines))
    obj = parse(lines[j])
    if not isinstance(obj, dict) or not obj:
        return b[:i] + b"," + b[i:]
    tgt = obj
    for _ in range(rnd.randrange(3)):   # descend into a nested object or array element sometimes
        kids = [v for v in (tgt.values() if isinstance(tgt, dict) else tgt) if isinstance(v, (dict, list)) and v]
        if not kids:
            break
        tgt = rnd.choice(kids)
    if isinstance(tgt, list):
        k = rnd.randrange(len(tgt))
        tgt[k] = rnd.choice(WRONG)
    else:
        k = rnd.choice(list(tgt))
        if op == 8:
            del tgt[k]
        elif op == 9:
            tgt["x" + str(rnd.randrange(9))] = rnd.choice(WRONG)
        elif op == 10:
            tgt[k + rnd.choice(["_", " ", "X"])] = tgt.pop(k)
        else:
            tgt[k] = rnd.choice(WRONG + [[tgt[k]], {"v": tgt[k]}])
    text = json.dumps(obj, separators=(",", ":"), sort_keys=rnd.random() < 0.5).encode()
    if op == 11 and rnd.random() < 0.3:   # a name written twice, in the text
        text = text[:1] + json.dumps(rnd.choice(list(obj))).encode() + b":0," + text[1:] if len(obj) else text
    lines[j] = text
    return b"\n".join(lines)


class Ledger:
    name = "ledger"

    def __init__(self, tmp):
        self.orig = verifier.read_regular(os.path.join(HERE, "examples", "sample_ledger.jsonl"))
        self.entries = [parse(x) for x in self.orig.split(b"\n") if x.strip()]
        self.path = os.path.join(tmp, "ledger.jsonl")

    def run(self, data):
        with open(self.path, "wb") as f:
            f.write(data)
        return verifier.verify_ledger(self.path)["verdict"] == "PASS"

    def allowed(self, data):
        lines = [x for x in data.split(b"\n") if x.strip()]
        got = [parse(x) for x in lines]
        return bool(got) and None not in got and got == self.entries[:len(got)]

    def ablate(self):
        real = verifier._verify_ledger

        def lax(*a, **kw):
            r = real(*a, **kw)
            if not r["parse_errors"] and r["entries_count"]:
                r["verdict"] = "PASS"
            return r
        verifier._verify_ledger = lax


class Dsse:
    name = "dsse"

    def __init__(self, tmp):
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ed25519
        k = ed25519.Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
        self.key = k.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        self.payload = json.dumps({"_type": cryptovalid_dsse.STATEMENT_TYPE, "subject": [
            {"name": "a", "digest": {"sha256": hashlib.sha256(b"a").hexdigest()}}],
            "predicateType": "https://example.org/fuzz/v1", "predicate": {"n": 1}}).encode()
        sig = k.sign(cryptovalid_dsse.pae(cryptovalid_dsse.PAYLOAD_TYPE, self.payload))
        self.orig = json.dumps({"payload": base64.b64encode(self.payload).decode(), "payloadType":
                                cryptovalid_dsse.PAYLOAD_TYPE, "signatures": [
                                    {"keyid": "", "sig": base64.b64encode(sig).decode()}]}).encode()

    def run(self, data):
        return cryptovalid_dsse.verify_envelope(data, [self.key])["valid"]

    def allowed(self, data):
        env = parse(data)
        try:
            return (env["payloadType"] == cryptovalid_dsse.PAYLOAD_TYPE
                    and cryptovalid_dsse._unb64(env["payload"]) == self.payload)
        except Exception:  # noqa: BLE001 - anything else is not the original
            return False

    def ablate(self):
        cryptovalid_dsse._verify_one = lambda *a: True


class Anchor:
    name = "slhdsa"

    def __init__(self, tmp):
        import slhdsa  # noqa: F401 - the target needs the library
        self.anchor = json.loads(verifier.read_regular(
            os.path.join(HERE, "spec", "vectors", "slhdsa", "anchors_pq_scitt.json")))["anchors"][0]
        self.orig = json.dumps(self.anchor).encode()

    def run(self, data):
        a = parse(data)
        return cryptovalid_slhdsa.verify_anchor(a)["valid"] if a is not None else False

    def allowed(self, data):
        a = parse(data)
        return a == self.anchor and type(a.get("ts")) is type(self.anchor["ts"])

    def ablate(self):
        cryptovalid_slhdsa.slh_verify = lambda *a, **kw: True


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--iterations", type=int, default=2000, help="0 = until --seconds")
    ap.add_argument("--seconds", type=float, default=0)
    ap.add_argument("--json")
    ap.add_argument("--findings-dir", default="fuzz-findings")
    ap.add_argument("--ablate", choices=["ledger", "dsse", "slhdsa"])
    a = ap.parse_args(argv)
    rnd = random.Random(a.seed)
    tmp = tempfile.mkdtemp(prefix="cvfuzz-")
    targets, missing = [], []
    for cls in (Ledger, Dsse, Anchor):
        try:
            targets.append(cls(tmp))
        except ImportError as e:
            missing.append(f"{cls.name}: {e}")
    for t in targets:
        if not t.run(t.orig):
            print(f"corpus of {t.name} is not valid before any mutation: refusing to run", file=sys.stderr)
            return 2
    if a.ablate:
        t = [t for t in targets if t.name == a.ablate]
        if not t:
            print(f"--ablate {a.ablate}: that target is not available here ({missing})", file=sys.stderr)
            return 2
        t[0].ablate()
        targets = t
    deadline = time.monotonic() + a.seconds if a.seconds else None
    n, violations, verdicts, accepted = 0, [], hashlib.sha256(), {}
    while (a.iterations and n < a.iterations) or (not a.iterations and deadline and time.monotonic() < deadline):
        t = rnd.choice(targets)
        data = t.orig
        for _ in range(1 + (rnd.random() < 0.3)):
            data = mutate(data, rnd)
        n += 1
        try:
            ok = t.run(data)
        except Exception:  # noqa: BLE001 - P2: any exception is a finding
            violations.append({"target": t.name, "property": "P2", "detail": traceback.format_exc()[-400:], "data": data})
            continue
        verdicts.update(b"1" if ok else b"0")
        accepted[t.name] = accepted.get(t.name, 0) + ok
        if ok and not t.allowed(data):
            violations.append({"target": t.name, "property": "P1", "detail": "accepted a changed input", "data": data})
    if violations:
        os.makedirs(a.findings_dir, exist_ok=True)
        for i, v in enumerate(violations[:50]):
            with open(os.path.join(a.findings_dir, f"{i:03d}-{v['target']}-{v['property']}.bin"), "wb") as f:
                f.write(v["data"])
    summary = {"seed": a.seed, "iterations": n, "targets": [t.name for t in targets], "missing": missing,
               "ablate": a.ablate, "accepted": accepted, "violations": len(violations),
               "by_property": sorted({(v["target"], v["property"]) for v in violations}),
               "verdicts_sha256": verdicts.hexdigest(), "python": sys.version.split()[0]}
    for v in violations[:3]:
        print(v["target"], v["property"], v["detail"][-200:], file=sys.stderr)
    if a.json:
        with open(a.json, "w", encoding="utf-8", newline="") as f:
            json.dump(summary, f, indent=1, default=list)
    print(json.dumps(summary, default=list))
    if a.ablate:
        return 0 if violations else 1
    return 1 if violations else 0


if __name__ == "__main__":
    if hasattr(sys.stdout, "reconfigure"):   # Windows: a pipe gets the ANSI code page; this tool writes UTF-8 everywhere
        sys.stdout.reconfigure(encoding="utf-8", errors="backslashreplace")
    sys.exit(main())
