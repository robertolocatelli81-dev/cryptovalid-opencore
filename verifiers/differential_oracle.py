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


def verdict(cmd, path, extra=(), flags_first=False):
    args = cmd + (list(extra) + [path] if flags_first else [path] + list(extra))   # Go's flag package: flags first
    try:
        out = subprocess.run(args, capture_output=True, text=True, timeout=30)
        return json.loads(out.stdout)["verdict"]
    except Exception:
        return "NONJSON/CRASH"


def tip_pq(cmd, path, extra=(), flags_first=False):
    """The tri-state `pq_protected` of the tip check (True/False/None), or 'ABSENT' when no tip object is reported."""
    args = cmd + (list(extra) + [path] if flags_first else [path] + list(extra))
    try:
        out = subprocess.run(args, capture_output=True, text=True, timeout=30)
        t = json.loads(out.stdout).get("tip")
        return "ABSENT" if not isinstance(t, dict) or "pq_protected" not in t else t["pq_protected"]
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


# Signed chain tip (15/09/2026): a truncated ledger WITH a tip next to it. Python, JS and Go check the sidecar
# (named FAIL: tail_truncated); Rust and Swift do not (declared: no Ed25519 without dependencies) → PASS.
def _tip_case():
    sys.path.insert(0, ROOT)
    try:
        import cryptovalid_tip as T
        import signer
        signer._ed()   # 'cryptography' is imported lazily: probe it HERE, not at the first keygen (CI 15/09: traceback)
    except Exception as e:  # noqa: BLE001 — cryptography absent: the tip cases are skipped, and SAID
        print("  tip cases NOT measured (%s: %s)" % (type(e).__name__, str(e)[:80]))
        return None
    d = tempfile.mkdtemp()
    led = os.path.join(d, "l.jsonl")
    chain, prev = [], "0" * 64
    for i in range(3):
        e = {"idx": i, "ts": "t", "data": {"i": i}, "prev_hash": prev}
        e["self_hash"] = hashlib.sha256(canon(e)).hexdigest(); prev = e["self_hash"]; chain.append(e)
    with open(led, "w") as f:
        f.write("".join(json.dumps(e) + "\n" for e in chain))
    pk = signer.keygen(os.path.join(d, "k"))["public_key_hex"]
    T.sign_tip(led, os.path.join(d, "k"))
    with open(led + ".tip.json") as f:
        tip = f.read()
    # council R3: a SIGNED tip with a garbage ts / uppercase hex was ok in Python, tip_invalid in Go — measured now
    sk, _ = T._load_sk(os.path.join(d, "k"))
    def signed(entries, ledger_id, tip_sha256, ts):
        sig = sk.sign(T.tip_payload(entries, ledger_id, tip_sha256, ts)).hex()
        return json.dumps({"kind": T.KIND, "entries": entries, "ledger_id": ledger_id, "tip_sha256": tip_sha256, "ts": ts,
                           "log_pubkey_hex": pk, "signature_hex": sig})
    full = "".join(json.dumps(e) + "\n" for e in chain)
    # HYBRID Ed25519 + ML-DSA-65 (0.12.0): entries and tip carry a post-quantum companion signature. The hash
    # verifiers must all ignore the new attestation fields (signature_pq/signer_pq); the PQ layer of the tip is
    # checked by Python and Go (crypto/mldsa) only — JS/Rust/Swift declared (Node 22 / OpenSSL 3.5 has no ML-DSA).
    hybrid = {}
    try:
        pq = signer.keygen_pq(os.path.join(d, "k.pq"))["public_key_b64"]
        hs = os.path.join(d, "h.jsonl")
        signer.sign_ledger(led, hs, os.path.join(d, "k"), pq_keyfile=os.path.join(d, "k.pq"))
        with open(hs) as f:
            hybrid["hybrid_full"] = f.read()
        tip_h = T.write_tip(os.path.join(d, "t.json"), os.path.join(d, "k"), 3, chain[0]["self_hash"], chain[2]["self_hash"],
                            "2026-09-15T07:00:00+00:00", pq_keyfile=os.path.join(d, "k.pq"))
        bad = dict(tip_h); s_ = bytearray(bytes.fromhex(bad["signature_pq_hex"])); s_[7] ^= 1; bad["signature_pq_hex"] = s_.hex()
        # council 15/09: hostile TYPES / formats in the optional PQ fields, and a lax hex decoder on signature_hex —
        # measured: three verdicts on one file (Python ok, Go unreadable, JS pq false). Now tip_invalid everywhere.
        cls = signed(3, chain[0]["self_hash"], chain[2]["self_hash"], "2026-09-15T07:00:00+00:00")
        cls_d = json.loads(cls)
        hybrid.update({"pq_pubkey": pq, "tip_hybrid": json.dumps(tip_h), "tip_hybrid_bad_pq": json.dumps(bad),
                       "tip_classical": cls,
                       "tip_pq_int": json.dumps(dict(tip_h, signature_pq_hex=123)),
                       "tip_pq_null": json.dumps(dict(tip_h, signature_pq_hex=None)),     # round 2: Go mapped null → "" → absent
                       "tip_pq_empty": json.dumps(dict(tip_h, signature_pq_hex="")),
                       # round 3: Go's encoding/json matches struct tags case-insensitively — a case-variant key must be
                       # IGNORED like Python/JS do (classical tip, PASS), not read as the PQ field
                       "tip_pq_case": json.dumps(dict(cls_d, Signature_PQ_Hex=tip_h["signature_pq_hex"], Log_PQ_Pubkey_B64=tip_h["log_pq_pubkey_b64"])),
                       "tip_pq_short": json.dumps(dict(tip_h, signature_pq_hex="abcd")),
                       "tip_pq_badkey": json.dumps(dict(tip_h, log_pq_pubkey_b64="!!!!")),
                       "tip_sig_upper": json.dumps(dict(cls_d, signature_hex=cls_d["signature_hex"].upper())),
                       "tip_sig_space": json.dumps(dict(cls_d, signature_hex=cls_d["signature_hex"][:2] + " " + cls_d["signature_hex"][3:]))})
    except Exception as e:  # noqa: BLE001 — cryptography < 50: the hybrid cases are skipped, and SAID
        print("  hybrid (ML-DSA-65) cases NOT measured (%s: %s)" % (type(e).__name__, str(e)[:80]))
    return {"text": "".join(json.dumps(e) + "\n" for e in chain[:2]), "tip": tip, "pubkey": pk, "full": full, **hybrid,
            "tip_garbage_ts": signed(3, chain[0]["self_hash"], chain[2]["self_hash"], "garbage"),
            "tip_upper_hex": signed(3, chain[0]["self_hash"].upper(), chain[2]["self_hash"], "2026-09-15T07:00:00+00:00"),
            # review with Fable 5.1 (15/09): validly signed, oddly formatted — Python/JS PASSED, Go refused
            "tip_date_only_ts": signed(3, chain[0]["self_hash"], chain[2]["self_hash"], "2026-09-15"),
            "tip_no_seconds_ts": signed(3, chain[0]["self_hash"], chain[2]["self_hash"], "2026-09-15T09:00+02:00"),
            # and the mirror: an EMPTY log_pubkey_hex was tip_invalid in Python, ok in Go/JS → now "absent" everywhere
            "tip_empty_pubkey": signed(3, chain[0]["self_hash"], chain[2]["self_hash"], "2026-09-15T07:00:00+00:00").replace(
                '"log_pubkey_hex": "%s"' % pk, '"log_pubkey_hex": ""'),
            # VALUE layer (review with Fable 5.1, 15/09, measured: JS rolled 02-30 over, accepted 24:00 and year 0000;
            # Go accepted a comma fraction, 10 digits, +24:00). One hand-written validator now, enumerated here.
            "tip_feb30": signed(3, chain[0]["self_hash"], chain[2]["self_hash"], "2026-02-30T10:25:00Z"),
            "tip_hour24": signed(3, chain[0]["self_hash"], chain[2]["self_hash"], "2026-09-15T24:00:00Z"),
            "tip_year0": signed(3, chain[0]["self_hash"], chain[2]["self_hash"], "0000-01-01T00:00:00Z"),
            "tip_comma_frac": signed(3, chain[0]["self_hash"], chain[2]["self_hash"], "2026-09-15T10:25:00,5Z"),
            "tip_frac10": signed(3, chain[0]["self_hash"], chain[2]["self_hash"], "2026-09-15T10:25:00.1234567890Z"),
            "tip_off24": signed(3, chain[0]["self_hash"], chain[2]["self_hash"], "2026-09-15T10:25:00+24:00"),
            "tip_leap60": signed(3, chain[0]["self_hash"], chain[2]["self_hash"], "2026-09-15T10:25:60Z"),
            "tip_frac4_ok": signed(3, chain[0]["self_hash"], chain[2]["self_hash"], "2026-09-15T10:25:00.1234Z"),
            "tip_leapday_ok": signed(3, chain[0]["self_hash"], chain[2]["self_hash"], "2024-02-29T23:59:59-11:30"),
            # round 3 with Fable: Python's \d matched Unicode digits (Go/JS: ASCII) → measured, now refused everywhere
            "tip_arabic_digits": signed(3, chain[0]["self_hash"], chain[2]["self_hash"], "٢٠٢٦-٠٩-١٥T10:00:00Z"),
            "tip_fullwidth_digits": signed(3, chain[0]["self_hash"], chain[2]["self_hash"], "２０２６-０９-１５T１０:２５:００Z"),
            # ORDERING vectors (checked below with --tip-not-before, Python/JS/Go only): same accept set is not
            # enough — sub-ms / sub-µs fractions and years < 100 ordered differently until 0.11.3
            "ordering": [(signed(3, chain[0]["self_hash"], chain[2]["self_hash"], ts), nb, ex) for ts, nb, ex in (
                ("2026-09-15T10:00:00.0001Z", "2026-09-15T10:00:00.0004Z", "FAIL"),
                ("2026-09-15T10:00:00.0000001Z", "2026-09-15T10:00:00.0000004Z", "FAIL"),
                ("2026-09-15T10:00:00.0000004Z", "2026-09-15T10:00:00.0000001Z", "PASS"),
                ("0050-06-15T12:00:00Z", "0100-01-01T00:00:00Z", "FAIL"),
                ("2026-09-15T12:00:00+02:00", "2026-09-15T10:00:00Z", "PASS"),
                # round 4 with Fable: pre-1970 with fraction (negative epoch seconds, positive nanos), and the extremes
                ("1969-12-31T23:59:59.9Z", "1969-12-31T23:59:59.5Z", "PASS"),
                ("1969-12-31T23:59:59.5Z", "1969-12-31T23:59:59.9Z", "FAIL"),
                ("0001-01-01T00:00:00+23:59", "0001-01-01T00:00:00Z", "FAIL"),
                ("9999-12-31T23:59:59.999999999-23:59", "9999-12-31T23:59:59Z", "PASS"))]}


TIP_CASE = _tip_case()
TIP_CASES = {}   # name -> (ledger text, tip document)
if TIP_CASE:
    TIP_CASES = {"tip-truncated": (TIP_CASE["text"], TIP_CASE["tip"]),
                 "tip-garbage-ts": (TIP_CASE["full"], TIP_CASE["tip_garbage_ts"]),
                 "tip-upper-hex": (TIP_CASE["full"], TIP_CASE["tip_upper_hex"]),
                 "tip-date-only-ts": (TIP_CASE["full"], TIP_CASE["tip_date_only_ts"]),
                 "tip-no-seconds-ts": (TIP_CASE["full"], TIP_CASE["tip_no_seconds_ts"]),
                 "tip-empty-pubkey": (TIP_CASE["full"], TIP_CASE["tip_empty_pubkey"]),
                 "tip-feb30": (TIP_CASE["full"], TIP_CASE["tip_feb30"]),
                 "tip-hour24": (TIP_CASE["full"], TIP_CASE["tip_hour24"]),
                 "tip-year0": (TIP_CASE["full"], TIP_CASE["tip_year0"]),
                 "tip-comma-frac": (TIP_CASE["full"], TIP_CASE["tip_comma_frac"]),
                 "tip-frac10": (TIP_CASE["full"], TIP_CASE["tip_frac10"]),
                 "tip-off24": (TIP_CASE["full"], TIP_CASE["tip_off24"]),
                 "tip-leap60": (TIP_CASE["full"], TIP_CASE["tip_leap60"]),
                 "tip-frac4-ok": (TIP_CASE["full"], TIP_CASE["tip_frac4_ok"]),
                 "tip-leapday-ok": (TIP_CASE["full"], TIP_CASE["tip_leapday_ok"]),
                 "tip-arabic-digits": (TIP_CASE["full"], TIP_CASE["tip_arabic_digits"]),
                 "tip-fullwidth-digits": (TIP_CASE["full"], TIP_CASE["tip_fullwidth_digits"])}
    for name, (text, _) in TIP_CASES.items():
        CORPUS[name] = text.rstrip("\n")
    DECLARED_DIVERGENCE["tip-truncated"] = (
        {"python": "FAIL", "js": "FAIL", "go": "FAIL", "rust": "PASS", "swift": "PASS"},
        "tail truncated but a signed chain tip sits next to the file: checked by Python/JS/Go (tail_truncated), "
        "not by Rust/Swift (declared: no Ed25519 without dependencies)")
    for name in ("tip-garbage-ts", "tip-upper-hex", "tip-date-only-ts", "tip-no-seconds-ts",
                 "tip-feb30", "tip-hour24", "tip-year0", "tip-comma-frac", "tip-frac10", "tip-off24", "tip-leap60",
                 "tip-arabic-digits", "tip-fullwidth-digits"):
        DECLARED_DIVERGENCE[name] = (
            {"python": "FAIL", "js": "FAIL", "go": "FAIL", "rust": "PASS", "swift": "PASS"},
            "intact chain, SIGNED tip outside the profile (ts not RFC 3339 with seconds+zone / uppercase hex): "
            "tip_invalid on Python/JS/Go, unchecked by Rust/Swift (declared)")
    # tip-empty-pubkey, tip-frac4-ok, tip-leapday-ok: valid everywhere → must AGREE (PASS)
    if TIP_CASE.get("pq_pubkey"):
        CORPUS["hybrid-entries-valid"] = TIP_CASE["hybrid_full"].rstrip("\n")   # new attestation fields: PASS everywhere
        TIP_CASES["hybrid-tip-valid"] = (TIP_CASE["hybrid_full"], TIP_CASE["tip_hybrid"])
        TIP_CASES["hybrid-tip-bad-pq"] = (TIP_CASE["hybrid_full"], TIP_CASE["tip_hybrid_bad_pq"])
        TIP_CASES["hybrid-tip-pq-required-missing"] = (TIP_CASE["hybrid_full"], TIP_CASE["tip_classical"])
        for hostile in ("tip_pq_int", "tip_pq_null", "tip_pq_empty", "tip_pq_short", "tip_pq_badkey", "tip_sig_upper", "tip_sig_space", "tip_pq_case"):
            TIP_CASES[hostile.replace("_", "-")] = (TIP_CASE["hybrid_full"], TIP_CASE[hostile])
        for name in ("hybrid-tip-valid", "hybrid-tip-bad-pq", "hybrid-tip-pq-required-missing",
                     "tip-pq-int", "tip-pq-null", "tip-pq-empty", "tip-pq-short", "tip-pq-badkey", "tip-sig-upper", "tip-sig-space", "tip-pq-case"):
            CORPUS[name] = TIP_CASES[name][0].rstrip("\n")   # tip-pq-case: PASS everywhere, pq_protected False everywhere (must AGREE)
        for name in ("tip-pq-int", "tip-pq-null", "tip-pq-empty", "tip-pq-short", "tip-pq-badkey", "tip-sig-upper", "tip-sig-space"):
            DECLARED_DIVERGENCE[name] = ({"python": "FAIL", "js": "FAIL", "go": "FAIL", "rust": "PASS", "swift": "PASS"},
                                         "malformed optional PQ field / lax hex in a signed tip: tip_invalid on Python/JS/Go, unchecked by Rust/Swift (declared)")
        # hybrid-tip-valid: PASS everywhere (must AGREE). The two negatives: Python/Go check the PQ layer against the
        # trusted ML-DSA-65 key (FAIL: invalid / pq_missing); JS, Rust and Swift cannot (declared, never counted as interop)
        for name, why in (("hybrid-tip-bad-pq", "tampered ML-DSA-65 tip signature: FAIL on Python/Go (crypto/mldsa), unchecked by JS/Rust/Swift (declared: no ML-DSA)"),
                          ("hybrid-tip-pq-required-missing", "trusted ML-DSA-65 key given, Ed25519-only tip: pq_missing on Python/Go, unchecked by JS/Rust/Swift (declared)")):
            DECLARED_DIVERGENCE[name] = ({"python": "FAIL", "js": "PASS", "go": "FAIL", "rust": "PASS", "swift": "PASS"}, why)
PQ_CASES = {"hybrid-tip-valid", "hybrid-tip-bad-pq", "hybrid-tip-pq-required-missing"}


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
            if os.path.exists(p + ".tip.json"):
                os.remove(p + ".tip.json")
            if name in TIP_CASES:
                with open(p + ".tip.json", "w") as f:
                    f.write(TIP_CASES[name][1])
            # the tip cases need the TRUSTED log key (without it the tip is, by contract, not checked)
            extra = {}
            if name in TIP_CASES:
                pk = TIP_CASE["pubkey"]
                extra = {"python": ["--trusted-pubkey", pk], "js": ["--trusted-pubkey", pk], "go": ["-trusted-pubkey", pk]}
                if name in PQ_CASES:
                    extra["python"] += ["--trusted-pq-pubkey", TIP_CASE["pq_pubkey"]]
                    extra["go"] += ["-trusted-pq-pubkey", TIP_CASE["pq_pubkey"]]
            verdicts = {k: verdict(cmd, p, extra.get(k, ()), flags_first=(k == "go")) for k, cmd in available.items()}
            uniq = set(verdicts.values())
            ok = len(uniq) == 1
            # the PQ tri-state must agree between the two verifiers that CHECK it (Python, Go); JS reports
            # null-when-present / false-when-absent and must never say true (council 15/09: the oracle compared
            # verdicts only, so Go's bool-instead-of-null was invisible)
            if name in TIP_CASES and "python" in available and "go" in available:
                pq_py = tip_pq(available["python"], p, extra.get("python", ()))
                pq_go = tip_pq(available["go"], p, extra.get("go", ()), flags_first=True)
                pq_js = tip_pq(available["js"], p, extra.get("js", ())) if "js" in available else None
                if pq_py != pq_go or pq_js is True:
                    disagreements += 1
                    print(f"  [DIFF] {name:22} pq_protected python={pq_py!r} go={pq_go!r} js={pq_js!r}")
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
        # ORDERING oracle: the three tip checkers must ORDER instants identically, not only accept identically
        if TIP_CASE:
            pk = TIP_CASE["pubkey"]
            p = os.path.join(tmp, "o.jsonl")
            with open(p, "w") as f:
                f.write(TIP_CASE["full"])
            for i, (tipdoc, nb, expect) in enumerate(TIP_CASE["ordering"]):
                with open(p + ".tip.json", "w") as f:
                    f.write(tipdoc)
                vs = {}
                for k in ("python", "js", "go"):
                    if k not in available:
                        continue
                    ex = {"python": ["--trusted-pubkey", pk, "--tip-not-before", nb], "js": ["--trusted-pubkey", pk, "--tip-not-before", nb],
                          "go": ["-trusted-pubkey", pk, "-tip-not-before", nb]}[k]
                    vs[k] = verdict(available[k], p, ex, flags_first=(k == "go"))
                ok = all(v == expect for v in vs.values())
                if not ok:
                    disagreements += 1
                print(f"  [{'OK ' if ok else 'DIFF'}] ordering-{i:<14} expect {expect}: {vs}")
    print(f"\ndisagreements: {disagreements}/{len(CORPUS) + (len(TIP_CASE['ordering']) if TIP_CASE else 0)} (declared out-of-profile divergences: {declared})")
    return 0 if disagreements == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
