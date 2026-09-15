#!/usr/bin/env python3
# Differential cross-oracle: feed an adversarial corpus to ALL FIVE verifiers
# (Python reference + JS + Go + Rust + Swift) and FAIL on any verdict disagreement.
# This turns "we believe they agree" into a machine-checked invariant (Mind 4's rec).
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
SWIFT = os.path.join(HERE, "swift", ".build", "debug", "cvverify")
RUST = os.path.join(HERE, "rust", "target", "release", "cvverify")
GO_SRC = os.path.join(HERE, "go")


def build_go(tmp):
    """Build verifiers/go/cmd/cvverify into `tmp` when a Go toolchain is on PATH (added 15/09/2026: the Go
    reference answered "EMPTY" on an empty ledger, an undeclared divergence nobody measured). None if no Go."""
    if not shutil.which("go"):
        return None
    out = os.path.join(tmp, "cvverify-go")
    r = subprocess.run(["go", "build", "-o", out, "./cmd/cvverify"], cwd=GO_SRC, capture_output=True, text=True)
    if r.returncode != 0:
        # a Go toolchain is present but the verifier does not build: that IS a regression of a reference,
        # never a silent "measured without Go" (council round 4, Gemini)
        raise SystemExit("go build failed — the Go reference verifier is broken: " + r.stderr.strip()[:400])
    return out


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
    "empty": "",   # zero entries: all four verifiers said PASS until 2026-09-11 — MUST be FAIL
    # 2000 levels: far beyond the normative bound (512) and beyond CPython's decoder stack (~1000) — the Python
    # reference CRASHED with a traceback (no receipt) until 2026-09-13; now FAIL `json_too_deep` by linear pre-scan.
    # Every verifier the oracle can run must answer FAIL (a crash is counted as a disagreement, not ignored).
    "deep-nesting-2000": '{"idx":0,"ts":"t","data":' + "[" * 2000 + "]" * 2000 + ',"prev_hash":"' + "0" * 64 + '","self_hash":"z"}',
}


def _valid_nested(levels):
    """A VALID chained entry nested `levels` deep in `data` (the line's total nesting = levels + 2)."""
    data = cur = {}
    for _ in range(levels):
        cur["x"] = {}
        cur = cur["x"]
    return valid_entry(data)


# The one divergence we DECLARE instead of hiding: the reference enforces the normative bound
# MAX_JSON_DEPTH = 512 (spec/CONFORMANCE.md); the other verifiers do not. A valid entry nested deeper
# is FAIL (json_too_deep) on Python and PASS elsewhere. It stays in the corpus so the disagreement is
# measured on every run and reported as DECLARED, never counted as interop (council review 2026-09-13).
DECLARED_DIVERGENCE = {
    # name -> (expected verdict PER verifier, reason). A value may be a string (exact) or a set (any of).
    # Only this pattern is accepted as declared; anything else on the same case (an inverted regression,
    # a crash) is a real DIFF. Since 15/09/2026 the bound and the surrogate rule are enforced by Python, JS, Go
    # AND Rust (one rule, four references); Swift was not updated (no toolchain) — declared in CONFORMANCE §.
    "deep-valid-600": ({"python": "FAIL", "js": "FAIL", "go": "FAIL", "rust": "FAIL", "swift": "PASS"},
                       "outside the acceptance profile (nesting > MAX_JSON_DEPTH=512): references FAIL, Swift PASS"),
    "lone-surrogate": ({"python": "FAIL", "js": "FAIL", "go": "FAIL", "rust": "FAIL", "swift": {"PASS", "FAIL"}},
                       "unpaired \\ud800 escape: refused by the four references (lone_surrogate); Swift not updated"),
}
CORPUS["deep-valid-600"] = _valid_nested(598)
CORPUS["deep-valid-512"] = _valid_nested(510)   # exactly at the bound: must AGREE (PASS everywhere)
# an unpaired UTF-16 surrogate escape: not a Unicode scalar, decoders disagree (Go stdlib → U+FFFD) → refused
CORPUS["lone-surrogate"] = '{"idx":0,"ts":"t","data":{"k":"\\ud800"},"prev_hash":"' + "0" * 64 + '","self_hash":"z"}'
CORPUS["valid-surrogate-pair"] = valid_entry({"k": "\U0001F600"})   # a proper pair (U+1F600) must PASS everywhere


def _matches(expected, got):
    return got in expected if isinstance(expected, (set, frozenset, tuple, list)) else got == expected


def main():
    verifiers = {
        "python": ["python3", os.path.join(ROOT, "verifier.py")],   # radice del repo pubblico (layout piatto)
        "js": ["node", os.path.join(HERE, "js", "cvverify.mjs")],
        "rust": [RUST],
        "swift": [SWIFT],
    }
    available = {k: v for k, v in verifiers.items() if k in ("python", "js")
                 or os.path.exists(v[0])}
    disagreements = 0
    declared = 0
    with tempfile.TemporaryDirectory() as tmp:
        go_bin = build_go(tmp)
        if go_bin:
            available["go"] = [go_bin]
        print(f"differential oracle over {len(available)} verifiers: {sorted(available)}")
        for name, line in CORPUS.items():
            p = os.path.join(tmp, "l.jsonl")
            with open(p, "w") as f:
                f.write(line + "\n")
            verdicts = {k: verdict(cmd, p) for k, cmd in available.items()}
            uniq = set(verdicts.values())
            ok = len(uniq) == 1
            if not ok and name in DECLARED_DIVERGENCE:
                expected, why = DECLARED_DIVERGENCE[name]
                if all(_matches(expected.get(k), verdicts[k]) for k in verdicts):
                    declared += 1
                    print(f"  [DECL] {name:22} {verdicts}  <- declared: {why}")
                    continue
                # a different pattern than the declared one is NOT covered by the declaration
            if not ok:
                disagreements += 1
            print(f"  [{'OK ' if ok else 'DIFF'}] {name:22} {verdicts}")
    print(f"\ndisagreements: {disagreements}/{len(CORPUS)} (declared out-of-profile divergences: {declared})")
    return 0 if disagreements == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
