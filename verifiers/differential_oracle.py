#!/usr/bin/env python3
# Differential cross-oracle: feed an adversarial corpus to ALL FOUR verifiers
# (Python reference + JS + Rust + Swift) and FAIL on any verdict disagreement.
# This turns "we believe they agree" into a machine-checked invariant (Mind 4's rec).
import hashlib
import json
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
SWIFT = os.path.join(HERE, "swift", ".build", "debug", "cvverify")
RUST = os.path.join(HERE, "rust", "target", "release", "cvverify")


def canon(o):
    return json.dumps(o, sort_keys=True, separators=(",", ":")).encode()


def build(data_line):
    """A one-entry ledger whose self_hash is computed the reference way (if possible)."""
    return data_line


def valid_entry(data):
    e = {"idx": 0, "ts": "t", "data": data, "prev_hash": "0" * 64}
    e["self_hash"] = hashlib.sha256(canon(e)).hexdigest()
    return json.dumps(e)


def verdict(cmd, path):
    try:
        out = subprocess.run(cmd + [path], capture_output=True, text=True, timeout=30)
        return json.loads(out.stdout)["verdict"]
    except Exception:
        return "NONJSON/CRASH"


CORPUS = {
    "valid-string-amount": valid_entry({"amount": "10.00"}),
    "valid-int": valid_entry({"n": 42}),
    "float-1.5": valid_entry({"amount": 1.5}),
    "float-whole": valid_entry({"x": 1.0}),
    "bigint->2^53": valid_entry({"n": 10 ** 16}),
    "bigint->i64": valid_entry({"n": 10 ** 30}),
    "nan": '{"idx":0,"ts":"t","data":{"x":NaN},"prev_hash":"' + "0" * 64 + '","self_hash":"z"}',
    "dup-key": '{"idx":0,"ts":"t","data":{"a":1,"a":2},"prev_hash":"' + "0" * 64 + '","self_hash":"z"}',
    "escaped-dup": '{"idx":0,"ts":"t","data":{"a":1,"\\u0061":2},"prev_hash":"' + "0" * 64 + '","self_hash":"z"}',
    "garbage": "not json",
}


def main():
    verifiers = {
        "python": ["python3", os.path.join(ROOT, "opencore", "verifier.py")],
        "js": ["node", os.path.join(HERE, "js", "cvverify.mjs")],
        "rust": [RUST],
        "swift": [SWIFT],
    }
    available = {k: v for k, v in verifiers.items() if k in ("python", "js")
                 or os.path.exists(v[0])}
    disagreements = 0
    print(f"differential oracle over {len(available)} verifiers: {sorted(available)}")
    with tempfile.TemporaryDirectory() as tmp:
        for name, line in CORPUS.items():
            p = os.path.join(tmp, "l.jsonl")
            with open(p, "w") as f:
                f.write(line + "\n")
            verdicts = {k: verdict(cmd, p) for k, cmd in available.items()}
            uniq = set(verdicts.values())
            ok = len(uniq) == 1
            if not ok:
                disagreements += 1
            print(f"  [{'OK ' if ok else 'DIFF'}] {name:22} {verdicts}")
    print(f"\ndisagreements: {disagreements}/{len(CORPUS)}")
    return 0 if disagreements == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
