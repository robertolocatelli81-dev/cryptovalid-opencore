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
SWIFT = os.environ.get("CVVERIFY_SWIFT") or os.path.join(HERE, "swift", ".build", "debug", "cvverify")   # CVVERIFY_SWIFT: a binary built with --scratch-path elsewhere
RUST = os.path.join(HERE, "rust", "target", "release", "cvverify")
GO_SRC = os.path.join(HERE, "go")


def stale_binary(binary, src_dir, exts):
    """The newest source under `src_dir` with one of `exts` when it is newer than `binary`, else None. A prebuilt verifier
    older than its sources measures OLD code (11/10/2026: the oracle ran a Rust binary of 21/09, before the closed schema,
    and reported its divergences as the code's); callers refuse it, they never measure it silently."""
    if not os.path.exists(binary):
        return None
    t = os.path.getmtime(binary)
    for d, dirs, files in os.walk(src_dir):
        dirs[:] = [x for x in dirs if x not in (".build", "target", ".git")]
        for f in files:
            if f.endswith(exts) and os.path.getmtime(os.path.join(d, f)) > t:
                return os.path.join(d, f)
    return None


# what the binary is built from (tests, manifests and the build dir are not: editing a test never relinks the binary, and
# `swift build` does not relink when a source is only touched — measured 11/10/2026, review of 0.20.0)
RUST_SRC = os.path.join(HERE, "rust", "src")
SWIFT_SRC = os.path.join(HERE, "swift", "Sources")


def build_swift(swift_dir):
    """`swift build --product cvverify` when a Swift toolchain is on PATH (the build system decides freshness, as cargo does
    for Rust); True when it built, False without a toolchain. A failing build is an error, never a silent old binary."""
    if not shutil.which("swift"):
        return False
    r = subprocess.run(["swift", "build", "--product", "cvverify"], cwd=swift_dir, capture_output=True, text=True)
    if r.returncode != 0:
        raise SystemExit("swift build failed — the Swift verifier is broken: " + (r.stderr or r.stdout).strip()[:400])
    return True


def check_fresh(name, binary, src_dir, exts, built):
    """Refuse a prebuilt binary older than one of its sources. When the toolchain has just built it, the build system's
    own freshness check is the authority (mtimes would refuse a current binary)."""
    if built:
        return
    newer = stale_binary(binary, src_dir, exts)
    if newer:
        raise SystemExit(f"{name} binary {binary} is older than {newer}: rebuild it (a stale binary measures old code)")


def build_go(tmp):
    """Build verifiers/go/cmd/cvverify into `tmp` when a Go toolchain is on PATH (added 15/09/2026: the Go
    reference answered "EMPTY" on an empty ledger, an undeclared divergence nobody measured). None if no Go."""
    if not shutil.which("go"):
        return None
    out = os.path.join(tmp, "cvverify-go")
    r = subprocess.run(["go", "build", "-o", out, "./cmd/cvverify"], cwd=GO_SRC, capture_output=True, text=True)
    if r.returncode != 0:
        # a Go toolchain is present but the verifier does not build: that IS a regression of a reference,
        # never a silent "measured without Go" (council round 4)
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
    # AND Rust; Swift since 12/10/2026 (deep-valid-600 and lone-surrogate were declared here with Swift PASS / either: no
    # longer declared). A Swift regression past the bound is a DIFF on deep-valid-600; on surrogates the cases that can show
    # one are the hashed ones (lone-surrogate-hashed-*, surrogate-split-by-escape): lone-surrogate fails on its hash alone.
}
# council 16/09 r5 — JSON escapes and line rules the 54 cases did not cover (Java took "\\u+041" via Integer.parseInt;
# Python's universal newlines split on a lone CR; str.strip()/trim()/TrimSpace disagreed on U+00A0; Python took a
# boolean idx as 1). One rule now: \u = 4 ASCII hex digits; LF is the only separator; blank = ASCII space/tab/CR only.
CORPUS["u-escape-plus"] = '{"idx":0,"ts":"t","data":{"k":"\\u+041"},"prev_hash":"' + "0" * 64 + '","self_hash":"z"}'
CORPUS["u-escape-fullwidth"] = '{"idx":0,"ts":"t","data":{"k":"\\uＤ８００"},"prev_hash":"' + "0" * 64 + '","self_hash":"z"}'
CORPUS["cr-only-newline"] = valid_entry({"a": 1}) + "\r" + valid_entry({"b": 2})     # ONE line with a CR inside → trailing data
CORPUS["nbsp-only-line"] = "\u00a0\n" + valid_entry({"a": 1})                       # a line of U+00A0 is NOT blank → decode error
def _idx_bool():
    out, prev = [], "0" * 64
    for i, b in enumerate((False, True)):
        e = {"idx": b, "ts": "t", "data": {"i": i}, "prev_hash": prev}
        e["self_hash"] = hashlib.sha256(canon(e)).hexdigest(); prev = e["self_hash"]; out.append(e)
    return "\n".join(json.dumps(x, separators=(",", ":")) for x in out)
CORPUS["idx-bool"] = _idx_bool()                                                      # True == 1 in Python: refused now
CORPUS["deep-valid-600"] = _valid_nested(598)
CORPUS["deep-valid-512"] = _valid_nested(510)   # exactly at the bound: must AGREE (PASS everywhere)
# an unpaired UTF-16 surrogate escape: not a Unicode scalar, decoders disagree (Go stdlib → U+FFFD) → refused
CORPUS["lone-surrogate"] = '{"idx":0,"ts":"t","data":{"k":"\\ud800"},"prev_hash":"' + "0" * 64 + '","self_hash":"z"}'
CORPUS["valid-surrogate-pair"] = valid_entry({"k": "\U0001F600"})   # a proper pair (U+1F600) must PASS everywhere


# review 12/10/2026 (Swift alignment): cases that only the RULE can refuse — the self_hash is computed over what a lax decoder
# reads. `lone-surrogate` above carries self_hash "z": it fails on the hash in every verifier, so it cannot see a verifier that
# drops, replaces or keeps an unpaired escape (the Swift code before 12/10 dropped it and said PASS on the -dropped case).
def _lax_anchored(raw_value, read_value):
    e = {"idx": 0, "ts": "t", "data": {"k": read_value}, "prev_hash": "0" * 64}
    h = hashlib.sha256(canon(e)).hexdigest()
    return '{"idx":0,"ts":"t","data":{"k":"' + raw_value + '"},"prev_hash":"' + "0" * 64 + '","self_hash":"' + h + '"}'
CORPUS["lone-surrogate-hashed-dropped"] = _lax_anchored("a\\ud800b", "ab")
CORPUS["lone-surrogate-hashed-fffd"] = _lax_anchored("a\\ud800b", "a\ufffdb")
CORPUS["lone-surrogate-hashed-kept"] = _lax_anchored("a\\ud800b", "a\ud800b")
CORPUS["low-surrogate-hashed-dropped"] = _lax_anchored("a\\udc00b", "ab")
CORPUS["surrogate-split-by-escape"] = _lax_anchored("\\ud800\\\\dc00", "\U00010000")   # \ud800 then \\ then "dc00": not a pair
# Int64.min, hashed as written: out of the portable range; abs() of it traps (the Swift code before 12/10 died, SIGILL)
CORPUS["int64-min"] = '{"idx":0,"ts":"t","data":{"n":-9223372036854775808},"prev_hash":"' + "0" * 64 + '","self_hash":"' + \
    hashlib.sha256(b'{"data":{"n":-9223372036854775808},"idx":0,"prev_hash":"' + b"0" * 64 + b'","ts":"t"}').hexdigest() + '"}'
# the depth bound counts nesting, not containers: 600 siblings at depth 3 are in profile (PASS everywhere)
CORPUS["siblings-600"] = valid_entry({"k": [[] for _ in range(600)]})
# 21/09/2026 — classes found on cra-evidence 0.3.0 (same verifier code) and measured here: JS dropped an own "__proto__" key
# from its canonical form (an entry with that key added and self_hash untouched was PASS in JS alone); Rust's JSON accepted
# "+10", "010" and raw control characters (same canonical form → PASS in Rust alone); a non-UTF-8 file was FILE_ERROR in Rust
def _proto_rehashed():
    e = {"idx": 0, "ts": "t", "data": {"i": 0}, "prev_hash": "0" * 64, "__proto__": {"evil": 1}}
    e["self_hash"] = hashlib.sha256(canon(e)).hexdigest(); return json.dumps(e)
# since SPEC §2.1 (2026-10-10) `__proto__` is a top-level key nobody defined: FAIL everywhere, named (it was "a legal key: PASS
# everywhere" — measured 2026-10-11 on f9cd1957: Python FAIL, JS/Go/Java/Rust PASS, the oracle was red and nobody had rerun it)
CORPUS["proto-key-rehashed"] = _proto_rehashed()
_t = valid_entry({"i": 0}); CORPUS["proto-key-hash-untouched"] = _t[:1] + '"__proto__": {"evil": 1}, ' + _t[1:]   # FAIL everywhere
CORPUS["plus-number-same-canon"] = valid_entry({"n": 10}).replace('"n": 10', '"n": +10')       # not JSON: FAIL everywhere
CORPUS["leading-zero-same-canon"] = valid_entry({"n": 10}).replace('"n": 10', '"n": 010')
CORPUS["raw-tab-same-canon"] = valid_entry({"k": "a\tb"}).replace("\\t", "\t")
CORPUS["crlf-endings"] = valid_entry({"a": 1}).replace("\n", "") + "\r"                       # one entry, CRLF: PASS everywhere
CORPUS["idx-neg-zero"] = valid_entry({"a": 1}).replace('"idx": 0', '"idx": -0')                # -0 is the integer 0: PASS everywhere
CORPUS["non-utf8-byte"] = valid_entry({"a": 1}).encode().replace(b'"ts"', b'"t\xffs"', 1)         # bytes: FAIL everywhere (Rust said FILE_ERROR)
# review 21/09: a raw byte INSIDE A VALUE, self_hash computed over U+FFFD — a lossy decoder reads exactly the hashed text and
# says PASS (JS did, alone); a strict one refuses the file
def _fffd_line():
    e = {"idx": 0, "ts": "t", "data": {"k": "\ufffd"}, "prev_hash": "0" * 64}
    e["self_hash"] = hashlib.sha256(canon(e)).hexdigest()
    return json.dumps(e, ensure_ascii=False).encode("utf-8").replace("\ufffd".encode("utf-8"), b"\xff", 1)   # the raw byte where U+FFFD was hashed
CORPUS["non-utf8-byte-hashed-as-fffd"] = _fffd_line()
# a truncated 4-byte sequence decodes to ONE U+FFFD of the same length (3 bytes): a lossy decoder plus a length check passes it
CORPUS["non-utf8-truncated-hashed-as-fffd"] = _fffd_line().replace(b"\xff", b"\xf0\x9f\x98", 1)
# NEMESIS 12/10/2026: a byte that is not UTF-8, self_hash computed over the code point Python's surrogateescape gives it
# (U+DCFF for 0xFF): the reference said PASS, the five others FAIL (SPEC §3: no non-UTF-8 bytes)
def _surrogateescape_line(raw, in_key):
    s = raw.decode("utf-8", "surrogateescape")
    e = {"idx": 0, "ts": "t", "data": ({s: 1} if in_key else {"k": "a" + s + "b"}), "prev_hash": "0" * 64}
    e["self_hash"] = hashlib.sha256(canon(e)).hexdigest()
    return json.dumps(e, ensure_ascii=False).encode("utf-8", "surrogateescape")
CORPUS["non-utf8-byte-hashed-as-surrogateescape"] = _surrogateescape_line(b"\xff", False)
CORPUS["non-utf8-byte-in-key-hashed-as-surrogateescape"] = _surrogateescape_line(b"\xc0\xaf", True)
# a UTF-8 BOM at the start of the file is not JSON whitespace: FAIL everywhere (JS stripped it and said PASS)
CORPUS["bom-start"] = b"\xef\xbb\xbf" + valid_entry({"a": 1}).encode()
CORPUS["bom-then-blank-line"] = b"\xef\xbb\xbf\n" + valid_entry({"a": 1}).encode()
# NEMESIS 12/10/2026 (found on real files): a whole-number float LEXEME hashed as the integer a lax parser reads — JS read
# 1.0 / 0e0 as 1 / 0 and said PASS alone (`float-whole` above hashes "1.0", so it fails on the hash in every verifier)
def _int_hashed(idx_raw, data_raw, data_read):
    e = {"idx": 0, "ts": "t", "data": data_read, "prev_hash": "0" * 64}
    h = hashlib.sha256(canon(e)).hexdigest()
    return '{"idx":' + idx_raw + ',"ts":"t","data":' + data_raw + ',"prev_hash":"' + "0" * 64 + '","self_hash":"' + h + '"}'
CORPUS["float-whole-hashed-as-int"] = _int_hashed("0", '{"a":1.0}', {"a": 1})
CORPUS["float-exp-idx-hashed-as-int"] = _int_hashed("0e0", '{"a":1}', {"a": 1})
# an integer idx past 2^53-1: FAIL with a receipt everywhere (JS threw uncaught: no receipt, counted as a crash here)
CORPUS["idx-past-2^53"] = '{"idx":9007199254740992,"ts":"t","data":{},"prev_hash":"' + "0" * 64 + '","self_hash":"' + "0" * 64 + '"}'


# SPEC §2.1 (2026-10-10) — the entry is a CLOSED object: a top-level key nobody defined, self_hash recomputed over it (only the
# schema rule can see it), is a NAMED failure in every verifier (`unknown_field:<keys>`, keys in code-point order), never a silent
# PASS. Keys inside `data` (SPEC §4) and the optional keys of §2 stay PASS: the rule must not reject too much either. Measured
# 2026-10-11 before the alignment of the other languages: Python FAIL, JS/Go/Java/Rust PASS on every "unknown-key-*" case.
UNKNOWN_KEY = "x_unknown_2026"
def _rehashed(extra, n=1, at=0, algo="sha256"):
    """An n-entry chain whose entry `at` carries the extra top-level keys, self_hash recomputed over them."""
    out, prev = [], "0" * 64
    for i in range(n):
        e = {"idx": i, "ts": "t", "data": {"i": i}, "prev_hash": prev}
        if i == at:
            e.update(extra)
        h = hashlib.sha256 if algo == "sha256" else hashlib.sha3_256
        e["self_hash"] = h(canon(e)).hexdigest(); prev = e["self_hash"]; out.append(e)
    return "\n".join(json.dumps(x, ensure_ascii=False) for x in out)
CORPUS["unknown-key-rehashed"] = _rehashed({UNKNOWN_KEY: "written at creation"})
CORPUS["unknown-key-case-variant"] = _rehashed({"Idx": 0})            # a case variant of a known key is an unknown key
CORPUS["unknown-key-empty-name"] = _rehashed({"": 1})
CORPUS["unknown-key-unicode"] = _rehashed({"clé": 1})
CORPUS["unknown-keys-two"] = _rehashed({"zz_b": 1, "aa_a": 2})       # the reason lists both, code-point sorted: aa_a,zz_b
CORPUS["unknown-key-entry-1-of-3"] = _rehashed({UNKNOWN_KEY: True}, n=3, at=1)
CORPUS["unknown-key-sha3-rehashed"] = _rehashed({UNKNOWN_KEY: None}, algo="sha3_256")
CORPUS["unknown-key-in-data"] = valid_entry({UNKNOWN_KEY: "payload"})   # SPEC §4: data is domain-specific → PASS everywhere
# tsa_token (12/10/2026, 0.20.2): an RFC 3161 token over self_hash is an ATTESTATION, outside the canonical form like the
# signatures (SPEC §3). Until 0.20.1 it was inside, so the only tsa_token that could PASS was one that did not bind its own
# self_hash (PASS in all six on "tsa-token-inside-hash"), and a token attached after hashing was a hash failure in all six.
def _attached(extra, n=1, at=0, algo="sha256"):
    """An n-entry chain hashed WITHOUT `extra`, then `extra` added to entry `at` (as signer.py adds signatures)."""
    out = [json.loads(x) for x in _rehashed({}, n=n, algo=algo).split("\n")]
    out[at].update(extra)
    return "\n".join(json.dumps(x, ensure_ascii=False) for x in out)
CORPUS["optional-tsa-token-attached"] = _attached({"tsa_token": "AAAA"})            # an optional key of §2, outside the hash → PASS
CORPUS["tsa-token-attached-entry-1-of-3"] = _attached({"tsa_token": "MIIBzjCCAbQCAQEwDQYJ"}, n=3, at=1)
CORPUS["tsa-token-attached-sha3"] = _attached({"tsa_token": "AAAA"}, algo="sha3_256")   # the profile is detected on entry 0
CORPUS["tsa-token-inside-hash"] = _rehashed({"tsa_token": "AAAA"})   # hashed as content (the 0.20.1 rule) → hash failure: FAIL
# agreement is not enough here: the verdict itself is the rule (all six could agree on the old rule)
EXPECT_VERDICT = {"optional-tsa-token-attached": "PASS", "tsa-token-attached-entry-1-of-3": "PASS", "tsa-token-attached-sha3": "PASS",
                  "tsa-token-inside-hash": "FAIL"}
# 11/10/2026 — found by closed_schema_mutants.py (full run: 7 of 1 500 mutations, all of this shape): a chain whose first three
# entries lacked `idx` took the reference's native-schema path in 0.19.0 (PASS, SPEC §2.1 and §5 step 4 not applied: an unknown
# top-level key passed, case missing-idx-first-three-unknown-key). 0.20.0 removed that path: FAIL in all six, no longer declared.
def _no_idx_entry():
    e = {"ts": "t", "data": {"i": 0}, "prev_hash": "0" * 64}
    e["self_hash"] = hashlib.sha256(canon(e)).hexdigest(); return json.dumps(e)
CORPUS["missing-idx-every-entry"] = _no_idx_entry()
def _no_idx_first_three_unknown():
    out, prev = [], "0" * 64
    for i in range(5):
        e = {"ts": "t", "data": {"i": i}, "prev_hash": prev}
        if i >= 3:
            e["idx"] = i
        if i == 4:
            e[UNKNOWN_KEY] = 1
        e["self_hash"] = hashlib.sha256(canon(e)).hexdigest(); prev = e["self_hash"]; out.append(e)
    return "\n".join(json.dumps(x) for x in out)
CORPUS["missing-idx-first-three-unknown-key"] = _no_idx_first_three_unknown()
# the reason TEXT and the idx list must be the reference's, not only contain the key: keys longer than the 120-code-point cut
# (one outside the BMP, so a UTF-16 sort or a UTF-16 cut would differ) and an entry whose idx is not its position
CORPUS["unknown-keys-long-cut"] = _rehashed({"\U0001F511" + "y" * 70: 1, "\uFF49\uFF44\uFF58" + "z" * 70: 2, "aa": 3})
def _unknown_wrong_idx():
    out, prev = [], "0" * 64
    for i, ix in enumerate((0, 7, 2)):
        e = {"idx": ix, "ts": "t", "data": {"i": i}, "prev_hash": prev}
        if i == 1:
            e[UNKNOWN_KEY] = 1
        e["self_hash"] = hashlib.sha256(canon(e)).hexdigest(); prev = e["self_hash"]; out.append(e)
    return "\n".join(json.dumps(x, ensure_ascii=False) for x in out)
CORPUS["unknown-key-wrong-idx"] = _unknown_wrong_idx()
EXACT_REASON = {"unknown-keys-long-cut", "unknown-key-wrong-idx", "unknown-keys-two", "unknown-key-unicode"}
# name -> the `<keys>` the reason must carry (Python/JS: schema_failures[].reason; Go/Java: a failures[] string; Rust/Swift: a
# receipt without reason text, so their schema_failures_idx must be non-empty)
NAMED_UNKNOWN = {"unknown-key-rehashed": UNKNOWN_KEY, "unknown-key-case-variant": "Idx", "unknown-key-empty-name": "",
                 "unknown-key-unicode": "clé", "unknown-keys-two": "aa_a,zz_b", "unknown-key-entry-1-of-3": UNKNOWN_KEY,
                 "unknown-key-sha3-rehashed": UNKNOWN_KEY, "proto-key-rehashed": "__proto__",
                 "unknown-keys-long-cut": "aa,", "unknown-key-wrong-idx": UNKNOWN_KEY}


def closed_details(kind, cmd, path, extra=(), flags_first=False):
    """(reasons, idxs) of the closed-schema failures in one receipt: Python/JS schema_failures[] (reason and idx); Go/Java the
    text after `entry N: ` of their unknown_field failures (their N is the position, not compared); Rust/Swift only idxs."""
    args = cmd + (list(extra) + [path] if flags_first else [path] + list(extra))
    try:
        r = json.loads(subprocess.run(args, capture_output=True, text=True, timeout=30).stdout)
    except Exception:
        return None, None
    if kind in ("python", "js"):
        sf = r.get("schema_failures") or []
        return [x.get("reason") for x in sf], [x.get("idx") for x in sf]
    if kind in ("go", "java"):
        return [f.split(": ", 1)[1] for f in (r.get("failures") or []) if isinstance(f, str) and ": unknown_field:" in f], None
    return None, r.get("schema_failures_idx")


def names_unknown(kind, cmd, path, key, extra=(), flags_first=False):
    """True when the receipt NAMES the closed-schema failure (SPEC §2.1) — never only a bare FAIL."""
    args = cmd + (list(extra) + [path] if flags_first else [path] + list(extra))
    try:
        r = json.loads(subprocess.run(args, capture_output=True, text=True, timeout=30).stdout)
    except Exception:
        return False
    if kind in ("rust", "swift"):
        return bool(r.get("schema_failures_idx"))
    def strings(o):   # decoded string values, so a key with a quote or a newline is searched as itself, not as its JSON escape
        if isinstance(o, str):
            yield o
        elif isinstance(o, dict):
            for v in o.values():
                yield from strings(v)
        elif isinstance(o, list):
            for v in o:
                yield from strings(v)
    return any(("unknown_field:" + key) in s for s in strings(r))


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
                       # r5: the tip is a SIGNED document and is parsed with the strict profile everywhere
                       "tip_dup_key": json.dumps(cls_d)[:-1] + ',"ts":"' + cls_d["ts"] + '"}',
                       "tip_float_extra": json.dumps(dict(cls_d, note=1.5)),
                       "tip_logpk_int": json.dumps(dict(cls_d, log_pubkey_hex=123)),
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
            # review of 15/09: validly signed, oddly formatted — Python/JS PASSED, Go refused
            "tip_date_only_ts": signed(3, chain[0]["self_hash"], chain[2]["self_hash"], "2026-09-15"),
            "tip_no_seconds_ts": signed(3, chain[0]["self_hash"], chain[2]["self_hash"], "2026-09-15T09:00+02:00"),
            # and the mirror: an EMPTY log_pubkey_hex was tip_invalid in Python, ok in Go/JS → now "absent" everywhere
            "tip_empty_pubkey": signed(3, chain[0]["self_hash"], chain[2]["self_hash"], "2026-09-15T07:00:00+00:00").replace(
                '"log_pubkey_hex": "%s"' % pk, '"log_pubkey_hex": ""'),
            # VALUE layer (review of 15/09, measured: JS rolled 02-30 over, accepted 24:00 and year 0000;
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
            # round 3: Python's \d matched Unicode digits (Go/JS: ASCII) → measured, now refused everywhere
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
                # round 4: pre-1970 with fraction (negative epoch seconds, positive nanos), and the extremes
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
        {"python": "FAIL", "js": "FAIL", "go": "FAIL", "java": "FAIL", "rust": "PASS", "swift": "PASS"},
        "tail truncated but a signed chain tip sits next to the file: checked by Python/JS/Go/Java (tail_truncated), "
        "not by Rust/Swift (declared: no Ed25519 without dependencies)")
    for name in ("tip-garbage-ts", "tip-upper-hex", "tip-date-only-ts", "tip-no-seconds-ts",
                 "tip-feb30", "tip-hour24", "tip-year0", "tip-comma-frac", "tip-frac10", "tip-off24", "tip-leap60",
                 "tip-arabic-digits", "tip-fullwidth-digits"):
        DECLARED_DIVERGENCE[name] = (
            {"python": "FAIL", "js": "FAIL", "go": "FAIL", "java": "FAIL", "rust": "PASS", "swift": "PASS"},
            "intact chain, SIGNED tip outside the profile (ts not RFC 3339 with seconds+zone / uppercase hex): "
            "tip_invalid on Python/JS/Go/Java, unchecked by Rust/Swift (declared)")
    # tip-empty-pubkey, tip-frac4-ok, tip-leapday-ok: valid everywhere → must AGREE (PASS)
    if TIP_CASE.get("pq_pubkey"):
        CORPUS["hybrid-entries-valid"] = TIP_CASE["hybrid_full"].rstrip("\n")   # new attestation fields: PASS everywhere
        TIP_CASES["hybrid-tip-valid"] = (TIP_CASE["hybrid_full"], TIP_CASE["tip_hybrid"])
        TIP_CASES["hybrid-tip-bad-pq"] = (TIP_CASE["hybrid_full"], TIP_CASE["tip_hybrid_bad_pq"])
        TIP_CASES["hybrid-tip-pq-required-missing"] = (TIP_CASE["hybrid_full"], TIP_CASE["tip_classical"])
        for hostile in ("tip_pq_int", "tip_pq_null", "tip_pq_empty", "tip_pq_short", "tip_pq_badkey", "tip_sig_upper", "tip_sig_space", "tip_pq_case",
                        "tip_dup_key", "tip_float_extra", "tip_logpk_int"):
            TIP_CASES[hostile.replace("_", "-")] = (TIP_CASE["hybrid_full"], TIP_CASE[hostile])
        for name in ("hybrid-tip-valid", "hybrid-tip-bad-pq", "hybrid-tip-pq-required-missing",
                     "tip-pq-int", "tip-pq-null", "tip-pq-empty", "tip-pq-short", "tip-pq-badkey", "tip-sig-upper", "tip-sig-space", "tip-pq-case",
                     "tip-dup-key", "tip-float-extra", "tip-logpk-int"):
            CORPUS[name] = TIP_CASES[name][0].rstrip("\n")   # tip-pq-case: PASS everywhere, pq_protected False everywhere (must AGREE)
        for name in ("tip-pq-int", "tip-pq-null", "tip-pq-empty", "tip-pq-short", "tip-pq-badkey", "tip-sig-upper", "tip-sig-space",
                     "tip-dup-key", "tip-float-extra", "tip-logpk-int"):
            DECLARED_DIVERGENCE[name] = ({"python": "FAIL", "js": "FAIL", "go": "FAIL", "java": "FAIL", "rust": "PASS", "swift": "PASS"},
                                         "malformed optional PQ field / lax hex in a signed tip: tip_invalid on Python/JS/Go/Java, unchecked by Rust/Swift (declared)")
        # hybrid-tip-valid: PASS everywhere (must AGREE). The two negatives: Python/Go check the PQ layer against the
        # trusted ML-DSA-65 key (FAIL: invalid / pq_missing); JS, Rust and Swift cannot (declared, never counted as interop)
        for name, why in (("hybrid-tip-bad-pq", "tampered ML-DSA-65 tip signature: FAIL on Python/Go/Java (crypto/mldsa, JDK 24+), unchecked by JS/Rust/Swift (declared: no ML-DSA)"),
                          ("hybrid-tip-pq-required-missing", "trusted ML-DSA-65 key given, Ed25519-only tip: pq_missing on Python/Go/Java, unchecked by JS/Rust/Swift (declared)")):
            DECLARED_DIVERGENCE[name] = ({"python": "FAIL", "js": "PASS", "go": "FAIL", "java": "FAIL", "rust": "PASS", "swift": "PASS"}, why)
PQ_CASES = {"hybrid-tip-valid", "hybrid-tip-bad-pq", "hybrid-tip-pq-required-missing"}


def build_java(tmp):
    """Compile verifiers/java/CvVerify.java with a JDK >= 24 (ML-DSA) if one is available: $JAVA_HOME, then PATH,
    then ~/.local/jdk/jdk-*; returns the command list or None (the Java verifier is then NOT measured, and said)."""
    import glob
    cands = []
    if os.environ.get("JAVA_HOME"):
        cands.append(os.path.join(os.environ["JAVA_HOME"], "bin"))
    if shutil.which("javac"):
        cands.append(os.path.dirname(shutil.which("javac")))
    cands += sorted(glob.glob(os.path.expanduser("~/.local/jdk/jdk-*/bin")), reverse=True)
    for b in cands:
        javac, java = os.path.join(b, "javac"), os.path.join(b, "java")
        if not (os.path.exists(javac) and os.path.exists(java)):
            continue
        try:
            ver = subprocess.run([java, "-version"], capture_output=True, text=True, timeout=30).stderr
            major = int((ver.split('"')[1].split(".")[0]) if '"' in ver else 0)
        except Exception:  # noqa: BLE001
            continue
        if major < 24:
            print(f"  java verifier NOT measured: JDK {major} at {b} has no ML-DSA (needs 24+)")
            continue
        out = os.path.join(tmp, "cvj")
        r = subprocess.run([javac, "-d", out, os.path.join(HERE, "java", "CvVerify.java")], capture_output=True, text=True, timeout=120)
        if r.returncode != 0:
            print("  java verifier NOT measured: javac failed:", r.stderr[:200])
            return None
        return [java, "-cp", out, "CvVerify"]
    print("  java verifier NOT measured: no JDK >= 24 found (JAVA_HOME / PATH / ~/.local/jdk)")
    return None


def _matches(expected, got):
    return got in expected if isinstance(expected, (set, frozenset, tuple, list)) else got == expected


def main():
    verifiers = {
        "python": ["python3", os.path.join(ROOT, "verifier.py")],   # radice del repo pubblico (layout piatto)
        "js": ["node", os.path.join(HERE, "js", "cvverify.mjs")],
        "rust": [RUST],
        "swift": [SWIFT],
    }
    built = {"rust": False, "swift": False}
    if shutil.which("cargo"):   # as the closed-schema bench: measure the Rust of THIS tree, not a binary left from an older one
        r = subprocess.run(["cargo", "build", "--release", "--quiet"], cwd=os.path.join(HERE, "rust"), capture_output=True, text=True)
        if r.returncode != 0:
            raise SystemExit("cargo build failed — the Rust reference verifier is broken: " + r.stderr.strip()[:400])
        built["rust"] = True
    if os.environ.get("CVVERIFY_SWIFT"):
        built["swift"] = True   # a binary named by the caller (built elsewhere): theirs to vouch for, as in the bench
    elif os.path.exists(SWIFT):   # Swift is measured only when its binary is there (opt-in); then this tree's code is rebuilt
        built["swift"] = build_swift(os.path.join(HERE, "swift"))
    check_fresh("rust", RUST, RUST_SRC, (".rs",), built["rust"])
    check_fresh("swift", SWIFT, SWIFT_SRC, (".swift",), built["swift"])
    available = {k: v for k, v in verifiers.items() if k in ("python", "js")
                 or os.path.exists(v[0])}
    disagreements = 0
    declared = 0
    with tempfile.TemporaryDirectory() as tmp:
        go_bin = build_go(tmp)
        if go_bin:
            available["go"] = [go_bin]
        java_cmd = build_java(tmp)
        if java_cmd:
            available["java"] = java_cmd
        print(f"differential oracle over {len(available)} verifiers: {sorted(available)}")
        for name, line in CORPUS.items():
            p = os.path.join(tmp, "l.jsonl")
            with open(p, "wb") as f:                      # bytes: the corpus may carry a byte that is not UTF-8
                f.write((line + "\n").encode("utf-8", "surrogateescape") if isinstance(line, str) else line + b"\n")
            if os.path.exists(p + ".tip.json"):
                os.remove(p + ".tip.json")
            if name in TIP_CASES:
                with open(p + ".tip.json", "w") as f:
                    f.write(TIP_CASES[name][1])
            # the tip cases need the TRUSTED log key (without it the tip is, by contract, not checked)
            extra = {}
            if name in TIP_CASES:
                pk = TIP_CASE["pubkey"]
                extra = {"python": ["--trusted-pubkey", pk], "js": ["--trusted-pubkey", pk], "go": ["-trusted-pubkey", pk],
                         "java": ["-trusted-pubkey", pk]}
                if name in PQ_CASES:
                    extra["python"] += ["--trusted-pq-pubkey", TIP_CASE["pq_pubkey"]]
                    extra["go"] += ["-trusted-pq-pubkey", TIP_CASE["pq_pubkey"]]
                    extra["java"] += ["-trusted-pq-pubkey", TIP_CASE["pq_pubkey"]]
            verdicts = {k: verdict(cmd, p, extra.get(k, ()), flags_first=(k in ("go", "java"))) for k, cmd in available.items()}
            uniq = set(verdicts.values())
            ok = len(uniq) == 1 and (name not in EXPECT_VERDICT or uniq == {EXPECT_VERDICT[name]})
            # the PQ tri-state must agree between the two verifiers that CHECK it (Python, Go); JS reports
            # null-when-present / false-when-absent and must never say true (council 15/09: the oracle compared
            # verdicts only, so Go's bool-instead-of-null was invisible)
            if name in TIP_CASES and "python" in available and "go" in available:
                pq_py = tip_pq(available["python"], p, extra.get("python", ()))
                pq_go = tip_pq(available["go"], p, extra.get("go", ()), flags_first=True)
                pq_js = tip_pq(available["js"], p, extra.get("js", ())) if "js" in available else None
                pq_java = tip_pq(available["java"], p, extra.get("java", ()), flags_first=True) if "java" in available else pq_go
                if pq_py != pq_go or pq_java != pq_go or pq_js is True:
                    disagreements += 1
                    print(f"  [DIFF] {name:22} pq_protected python={pq_py!r} go={pq_go!r} java={pq_java!r} js={pq_js!r}")
            if name in NAMED_UNKNOWN:
                # the verdict is not enough: every verifier must NAME the key nobody defined (SPEC §2.1)
                named = {k: names_unknown(k, cmd, p, NAMED_UNKNOWN[name], extra.get(k, ()), flags_first=(k in ("go", "java")))
                         for k, cmd in available.items()}
                if not all(named.values()):
                    disagreements += 1
                    print(f"  [DIFF] {name:22} not named (unknown_field:{NAMED_UNKNOWN[name]}): {named}")
            if name in EXACT_REASON and "python" in available:
                det = {k: closed_details(k, cmd, p, extra.get(k, ()), flags_first=(k in ("go", "java"))) for k, cmd in available.items()}
                ref_reasons, ref_idx = det["python"]
                bad = {k: d for k, d in det.items() if (d[0] is not None and d[0] != ref_reasons) or (d[1] is not None and d[1] != ref_idx)}
                if bad or not ref_reasons:
                    disagreements += 1
                    print(f"  [DIFF] {name:22} closed-schema reason/idx differ from python's {(ref_reasons, ref_idx)}: {bad}")
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
        # SIGNATURE-LAYER oracle (0.13.0): per-entry Ed25519 + ML-DSA-65 — Python (signer.py) vs Go (-pubkey/-pq-pubkey)
        # must give the same (ok, pq_protected, pq_status); JS verifies Ed25519 only (all_verified) and must agree on it
        if TIP_CASE and TIP_CASE.get("pq_pubkey") and "go" in available:
            sys.path.insert(0, ROOT)
            import signer as _signer
            hf = TIP_CASE["hybrid_full"]; lines = [json.loads(l) for l in hf.splitlines() if l.strip()]
            bad = json.loads(json.dumps(lines)); raw = bytearray(__import__("base64").b64decode(bad[1]["signature_pq"])); raw[5] ^= 1
            bad[1]["signature_pq"] = __import__("base64").b64encode(bytes(raw)).decode()
            stripped = [{k: v for k, v in e.items() if k not in ("signature_pq", "signer_pq")} for e in lines]
            SIG_CASES = {"sig-hybrid-valid": lines, "sig-hybrid-bad-pq": bad, "sig-stripped": stripped}
            pk, pq = TIP_CASE["pubkey"], TIP_CASE["pq_pubkey"]
            for name, ents in SIG_CASES.items():
                p = os.path.join(tmp, "s.jsonl")
                with open(p, "w") as f:
                    f.write("".join(json.dumps(e) + "\n" for e in ents))
                if os.path.exists(p + ".tip.json"):
                    os.remove(p + ".tip.json")
                py = _signer.verify_file(p, pk, pq)
                out = subprocess.run(available["go"] + ["-pubkey", pk, "-pq-pubkey", pq, p], capture_output=True, text=True, timeout=30)
                try:
                    g = json.loads(out.stdout)["signatures"]
                    go_t = (g["ok"], g["pq_protected"], g["pq_status"])
                except Exception:  # noqa: BLE001
                    go_t = ("NONJSON/CRASH",)
                py_t = (py["ok"], py["pq_protected"], py["pq_status"])
                java_t = go_t
                if "java" in available:
                    o3 = subprocess.run(available["java"] + ["-pubkey", pk, "-pq-pubkey", pq, p], capture_output=True, text=True, timeout=60)
                    try:
                        gj = json.loads(o3.stdout)["signatures"]
                        java_t = (gj["ok"], gj["pq_protected"], gj["pq_status"])
                    except Exception:  # noqa: BLE001
                        java_t = ("NONJSON/CRASH",)
                js_ok = None
                if "js" in available:
                    o2 = subprocess.run(available["js"] + [p, "--pubkey", pk], capture_output=True, text=True, timeout=30)
                    try:
                        js_ok = json.loads(o2.stdout)["signatures"]["all_verified"]
                    except Exception:  # noqa: BLE001
                        js_ok = "NONJSON/CRASH"
                ed_ok = not py["failures"] and py["verified"] == py["total"]
                ok = py_t == go_t == java_t and (js_ok is None or js_ok == ed_ok)
                if not ok:
                    disagreements += 1
                print(f"  [{'OK ' if ok else 'DIFF'}] {name:22} python={py_t} go={go_t} java={java_t} js_ed25519={js_ok}")
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
                for k in ("python", "js", "go", "java"):
                    if k not in available:
                        continue
                    ex = {"python": ["--trusted-pubkey", pk, "--tip-not-before", nb], "js": ["--trusted-pubkey", pk, "--tip-not-before", nb],
                          "go": ["-trusted-pubkey", pk, "-tip-not-before", nb], "java": ["-trusted-pubkey", pk, "-tip-not-before", nb]}[k]
                    vs[k] = verdict(available[k], p, ex, flags_first=(k in ("go", "java")))
                ok = all(v == expect for v in vs.values())
                if not ok:
                    disagreements += 1
                print(f"  [{'OK ' if ok else 'DIFF'}] ordering-{i:<14} expect {expect}: {vs}")
        # CLI grammar (21/09/2026, found on cra-evidence): an unknown flag, a value flag without a value or with "", a second
        # positional must be a usage error (exit 2, no verdict) in EVERY CLI — never a verdict with the constraint dropped
        valid = os.path.join(tmp, "v.jsonl")
        with open(valid, "w") as f:
            f.write(valid_entry({"a": 1}) + "\n")
        cli_cases = {"cli-unknown-flag": ["--no-such-flag"], "cli-trusted-pubkey-empty": ["--trusted-pubkey", ""],
                     "cli-trusted-pubkey-missing-value": ["--trusted-pubkey"], "cli-two-positionals": [valid],
                     "cli-algo-empty": ["--algo", ""],   # review 21/09: Python validated five value flags of seven
                     # NEMESIS 12/10/2026: --algo outside the two profiles (JS and Rust hashed SHA-256 and reported "algorithm":
                     # "foo"); only the four CLIs that have --algo take part (Go and Java auto-detect only)
                     "cli-algo-unknown": ["--algo", "foo"], "cli-algo-uppercase": ["--algo", "SHA256"]}
        only = {"cli-algo-unknown": {"python", "js", "rust", "swift"}, "cli-algo-uppercase": {"python", "js", "rust", "swift"}}
        n_cli = len(cli_cases)
        for name, extra in cli_cases.items():
            row = {}
            for k, cmd in available.items():
                if name in only and k not in only[name]:
                    continue
                ex = [(a.replace("--", "-", 1) if k in ("go", "java") and a.startswith("--") else a) for a in extra]
                if k == "rust" and extra[0] == "--trusted-pubkey":
                    ex = ["--algo"] + extra[1:]   # the Rust CLI has only --algo: same grammar, its own value flag
                if k == "java" and extra[0] == "--algo":
                    ex = ["-tip"] + extra[1:]     # the Java CLI has no -algo: same grammar, its own value flag
                args = cmd + (ex + [valid] if k in ("go", "java") else [valid] + ex)
                try:
                    out = subprocess.run(args, capture_output=True, text=True, timeout=30)
                    try:
                        v = json.loads(out.stdout).get("verdict"); row[k] = f"verdict:{v}"
                    except Exception:
                        row[k] = "usage" if out.returncode == 2 else f"exit{out.returncode}"
                except Exception:
                    row[k] = "CRASH"
            ok = all(v == "usage" for v in row.values())
            if not ok:
                disagreements += 1
            print(f"  [{'OK ' if ok else 'DIFF'}] {name:22} expect usage(exit 2): {row}")
        # INPUT FROM A FIFO (12/10/2026, NEMESIS of 0.20.1): `cvverify <(cat ledger)` — a named pipe, no size, not seekable.
        # Python, JS, Go, Java and Rust read it; Swift answered FILE_ERROR, exit 2 (FileManager.contents(atPath:) on Linux,
        # 0.20.0 and 0.20.1). Every verifier must give the verdict of the same bytes read from a regular file: PASS.
        n_fifo = 0
        if hasattr(os, "mkfifo"):
            import threading
            n_fifo = 1
            row = {}
            for k, cmd in available.items():
                fifo = os.path.join(tmp, f"in-{k}.fifo")
                os.mkfifo(fifo)

                def feed(path=fifo):
                    try:
                        with open(path, "wb") as w:   # blocks until the verifier opens the pipe
                            w.write((valid_entry({"a": 1}) + "\n").encode())
                    except OSError:                   # the reader closed early: its verdict shows it
                        pass
                t = threading.Thread(target=feed, daemon=True)
                t.start()
                row[k] = verdict(cmd, fifo)
                if t.is_alive():                      # the verifier never opened the pipe: release the writer
                    try:
                        os.close(os.open(fifo, os.O_RDONLY | os.O_NONBLOCK))
                    except OSError:
                        pass
                    t.join(5)
                os.remove(fifo)
            ok = all(v == "PASS" for v in row.values())
            if not ok:
                disagreements += 1
            print(f"  [{'OK ' if ok else 'DIFF'}] {'input-fifo':22} expect PASS: {row}")
    print(f"\ndisagreements: {disagreements}/{len(CORPUS) + (len(TIP_CASE['ordering']) if TIP_CASE else 0) + n_cli + n_fifo} (declared out-of-profile divergences: {declared})")
    return 0 if disagreements == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
