#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Roberto Locatelli
"""Generative, DIFFERENTIAL bench for the closed entry schema (SPEC_EVIDENCE_FORMAT §2.1, 2026-10-10) across every
verifier of the family: Python reference, JS, Go, Java, Rust (and Swift when its binary is built).

Method (the same as ap2-evidence-pack's schema_mutants.py): the expected class of every mutation comes from the SPEC
tables, never from a verifier; each mutation is fed to all the verifiers that can be built here, and three things
must hold — (1) every verifier gives the class the SPEC prescribes, (2) all verifiers AGREE, (3) a key nobody defined
is NAMED in the receipt (`unknown_field:<keys>`; Rust/Swift: a non-empty `schema_failures_idx`).

Mutation classes and the SPEC rule behind each expected class:
  top_unknown / top_unknown_multi / top_unknown_all_entries / top_unknown_escaped  §2.1: FAIL, named
  top_unknown_no_rehash                                   §5 step 2: FAIL (hash mismatch; naming not required)
  data_unknown                                            §4: data is domain-specific → the base verdict (PASS)
  optional_known (tsa_token with a string)                §2 optional fields → PASS (the rule must not reject too much;
                                                          tsa_token is outside the canonical form since 0.20.2, §3)
  wrong_type_idx / missing_idx                            §5 step 4: FAIL (idx must equal the position)
  wrong_type_prev_hash / missing_prev_hash                §5 step 3: FAIL (chain rule)
  wrong_type_self_hash                                    §5 step 2: FAIL
  dup_key_top / dup_key_data                              §3: duplicate object keys MUST be rejected → FAIL
  float_in_data / bigint_in_data                          §3 + acceptance profile (spec/CONFORMANCE.md) → FAIL
  reorder_top_keys / known_key_escaped                    §3 canonical form (sorted keys; \\u escape decodes to the same key) → base verdict
  wrong_type_ts / wrong_type_data / missing_ts / missing_data   §2 gives the types, §5 does not verify them: NO class
                                                          prescribed → the verifiers must only AGREE; the measured
                                                          verdict is reported (see RAPPORTO_LINGUE.md, 11/10/2026)

Usage:
  python3 closed_schema_mutants.py [--quick | --n N] [--seed S] [--tree DIR] [--only python,js,...] [--js PATH] [--out FILE]
  --tree points the bench at ANOTHER copy of opencore/ (positive control: the tree before the alignment must go red);
  --js overrides the JS verifier path (the CI test points it at a lax copy: the bench must go red).
Exit 0 = every mutation in class, every verifier agreeing, every unknown key named; 1 otherwise.
"""
import argparse
import glob
import hashlib
import json
import os
import random
import shutil
import subprocess
import sys
import tempfile
from differential_oracle import build_swift, check_fresh   # one copy of the stale-binary rule (oracle and bench)

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_TREE = os.path.dirname(HERE)

# SPEC §2 core + optional fields (the closed schema of §2.1), copied from the SPEC tables — not read from a verifier
ENTRY_KEYS = ("idx", "ts", "data", "prev_hash", "self_hash", "signature", "signer", "tsa_token", "signature_pq", "signer_pq")
CORE = ("idx", "ts", "data", "prev_hash")
ATTEST = ("self_hash", "signature", "signer", "signature_pq", "signer_pq", "tsa_token")   # outside the canonical form (§3; tsa_token since 0.20.2)


def canon(o):
    return json.dumps(o, sort_keys=True, separators=(",", ":")).encode()


def digest(algo, b):
    return (hashlib.sha256 if algo == "sha256" else hashlib.sha3_256)(b).hexdigest()


def rechain(entries, algo):
    prev, out = "0" * 64, []
    for e in entries:
        e = dict(e)
        e["prev_hash"] = prev
        e.pop("self_hash", None)
        e["self_hash"] = digest(algo, canon({k: v for k, v in e.items() if k not in ATTEST}))
        prev = e["self_hash"]
        out.append(e)
    return out


def base_ledgers():
    """The sources: small valid chains of both profiles, with varied payload shapes."""
    srcs = {}
    srcs["one-sha256"] = ("sha256", rechain([{"idx": 0, "ts": "2026-10-11T08:00:00Z", "data": {"a": "1"}}], "sha256"))
    srcs["three-sha256"] = ("sha256", rechain([{"idx": i, "ts": f"2026-10-11T08:0{i}:00Z", "data": {"event": "e%d" % i, "n": i}} for i in range(3)], "sha256"))
    srcs["three-sha3"] = ("sha3_256", rechain([{"idx": i, "ts": f"2026-10-11T08:0{i}:00Z", "data": {"event": "e%d" % i}} for i in range(3)], "sha3_256"))
    srcs["nested-unicode"] = ("sha256", rechain([{"idx": i, "ts": "t", "data": {"k": {"deep": [1, "é", None, {"z": True}]}, "s": "日本"}} for i in range(2)], "sha256"))
    return srcs


# ---------------------------------------------------------------- random material
KNOWN_VARIANTS = ["Idx", "TS", "Data", "PREV_HASH", "Self_Hash", "idx2", "data_", "self_hash ", " idx", "idx​", "tsa", "signer_pq2", "signatures"]
JS_SPECIAL = ["__proto__", "constructor", "prototype", "toString", "hasOwnProperty", "valueOf", "__defineGetter__"]
UNICODE_KEYS = ["clé", "ключ", "鍵", "🔑", "ﬁeld", "Á", " ", "ｉｄｘ"]
ODD_KEYS = ["", "0", "-1", "a b", "data.x", "a\"b", "a\\b", "a\nb", "a\tb", "\u0000", "x" * 40, "unknown_field", "verdict"]


def rand_key(rng):
    pool = rng.choice([KNOWN_VARIANTS, JS_SPECIAL, UNICODE_KEYS, ODD_KEYS, None, None])
    if pool is None:
        k = "".join(rng.choice("abcdefghijklmnopqrstuvwxyz0123456789_") for _ in range(rng.randint(1, 12)))
    else:
        k = rng.choice(pool)
    return k if k not in ENTRY_KEYS else k + "_x"


def rand_value(rng, depth=0):
    c = rng.randint(0, 8 if depth < 2 else 5)
    if c == 0:
        return None
    if c == 1:
        return rng.choice([True, False])
    if c == 2:
        return rng.choice([0, -1, 1, 2 ** 53 - 1, -(2 ** 53 - 1), rng.randint(-10 ** 6, 10 ** 6)])
    if c in (3, 4, 5):
        return rng.choice(["", "x", "é", "\u0000", "a\"b", "日本", "\U0001F600", "x" * 50, "0" * 64])
    if c == 6:
        return [rand_value(rng, depth + 1) for _ in range(rng.randint(0, 3))]
    return {rand_key(rng): rand_value(rng, depth + 1) for _ in range(rng.randint(0, 3))}


def text_of(entries):
    return "".join(json.dumps(e, ensure_ascii=False) + "\n" for e in entries)


def json_escape_key(k):
    """The same key written with \\u escapes for every ASCII letter: decodes to the same string (§3)."""
    return "".join("\\u%04x" % ord(c) if c.isascii() and c.isalpha() else c for c in k)


# ---------------------------------------------------------------- mutations: (name, class, ledger_text, named_keys|None)
def mutations(rng, srcs, n):
    out = []
    makers = [m_top_unknown, m_top_unknown_multi, m_top_unknown_all, m_top_unknown_escaped, m_top_unknown_no_rehash, m_data_unknown,
              m_optional_known, m_wrong_type_idx, m_missing_core, m_wrong_type_prev, m_wrong_type_self, m_dup_key_top, m_dup_key_data,
              m_float_in_data, m_bigint_in_data, m_reorder_top, m_known_key_escaped, m_wrong_type_ts, m_wrong_type_data]
    i = 0
    while len(out) < n:
        maker = makers[i % len(makers)]
        i += 1
        src_name, (algo, base) = rng.choice(list(srcs.items()))
        r = maker(rng, algo, base)
        if r is None:
            continue
        name, cls, text, named = r
        out.append((f"{name}@{src_name}#{len(out)}", cls, text, named))
    return out


def m_top_unknown(rng, algo, base):
    es = json.loads(json.dumps(base)); at = rng.randrange(len(es)); k = rand_key(rng)
    es[at][k] = rand_value(rng)
    return "top_unknown", "FAIL", text_of(rechain(es, algo)), [k]


def m_top_unknown_multi(rng, algo, base):
    es = json.loads(json.dumps(base)); at = rng.randrange(len(es)); ks = []
    while len(ks) < rng.randint(2, 4):
        k = rand_key(rng)
        if k not in ks:
            ks.append(k)
    for k in ks:
        es[at][k] = rand_value(rng)
    if sum(len(k) + 1 for k in ks) > 118:   # the reference cuts the joined keys at 120 code points: keep the name checkable
        return None
    return "top_unknown_multi", "FAIL", text_of(rechain(es, algo)), sorted(ks)


def m_top_unknown_all(rng, algo, base):
    es = json.loads(json.dumps(base)); k = rand_key(rng)
    for e in es:
        e[k] = rand_value(rng)
    return "top_unknown_all_entries", "FAIL", text_of(rechain(es, algo)), [k]


def m_top_unknown_escaped(rng, algo, base):
    """The unknown key written with \\u escapes in the file: the parser decodes it, the schema rule sees the decoded key."""
    es = json.loads(json.dumps(base)); at = rng.randrange(len(es))
    k = "".join(rng.choice("abcdefghijklmnopqrstuvwxyz") for _ in range(rng.randint(2, 10)))
    if k in ENTRY_KEYS:
        k += "q"
    es[at][k] = "v"
    es = rechain(es, algo)
    lines = [json.dumps(e, ensure_ascii=False) for e in es]
    lines[at] = lines[at].replace('"%s": "v"' % k, '"%s": "v"' % json_escape_key(k), 1)
    return "top_unknown_escaped", "FAIL", "".join(ln + "\n" for ln in lines), [k]


def m_top_unknown_no_rehash(rng, algo, base):
    es = json.loads(json.dumps(base)); at = rng.randrange(len(es)); es[at][rand_key(rng)] = rand_value(rng)
    return "top_unknown_no_rehash", "FAIL", text_of(es), None


def m_data_unknown(rng, algo, base):
    es = json.loads(json.dumps(base)); at = rng.randrange(len(es)); k = rand_key(rng)
    tgt = es[at]["data"]
    for _ in range(rng.randint(0, 2)):          # a random depth inside data
        subs = [v for v in tgt.values() if isinstance(v, dict)]
        if not subs:
            break
        tgt = rng.choice(subs)
    tgt[k] = rand_value(rng)
    return "data_unknown", "PASS", text_of(rechain(es, algo)), None


def m_optional_known(rng, algo, base):
    es = json.loads(json.dumps(base)); at = rng.randrange(len(es))
    es[at]["tsa_token"] = rng.choice(["AAAA", "MIIBzjCCAbQCAQEwDQYJKoZIhvcNAQ", ""])
    return "optional_known", "PASS", text_of(rechain(es, algo)), None


def m_wrong_type_idx(rng, algo, base):
    es = json.loads(json.dumps(base)); at = rng.randrange(len(es))
    es[at]["idx"] = rng.choice([str(at), True if at == 1 else False, None, [at], {"v": at}, "0" if at else "00", -1, 2 ** 53 - 1])
    return "wrong_type_idx", "FAIL", text_of(rechain(es, algo)), None


def m_missing_core(rng, algo, base):
    es = json.loads(json.dumps(base)); at = rng.randrange(len(es)); k = rng.choice(CORE)
    # idx removed from the only entry: the reference took a native-schema path there until 0.19.0 (PASS, found by this bench
    # 2026-10-11, 7/1500); 0.20.0 removed it, so the mutation is generated again and is FAIL in all six (SPEC §5 step 4)
    del es[at][k]
    cls = "FAIL" if k in ("idx", "prev_hash") else "AGREE"   # §5 checks idx and the chain rule; it never checks that ts/data exist
    es = rechain(es, algo)
    if k == "prev_hash":
        del es[at]["prev_hash"]; es[at]["self_hash"] = digest(algo, canon({kk: v for kk, v in es[at].items() if kk not in ATTEST}))
        if at + 1 < len(es):
            es[at + 1]["prev_hash"] = es[at]["self_hash"]
            for j in range(at + 1, len(es)):
                es[j]["self_hash"] = digest(algo, canon({kk: v for kk, v in es[j].items() if kk not in ATTEST}))
                if j + 1 < len(es):
                    es[j + 1]["prev_hash"] = es[j]["self_hash"]
    return "missing_" + k, cls, text_of(es), None


def m_wrong_type_prev(rng, algo, base):
    es = json.loads(json.dumps(base)); at = rng.randrange(len(es))
    es = rechain(es, algo)
    orig = es[at]["prev_hash"]
    es[at]["prev_hash"] = rng.choice([0, None, True, [], {}, orig.upper(), orig[:63]])
    if es[at]["prev_hash"] == orig:   # genesis "000…".upper() is the same string: not a mutation (the first run counted it as a miss)
        return None
    es[at]["self_hash"] = digest(algo, canon({k: v for k, v in es[at].items() if k not in ATTEST}))
    for j in range(at + 1, len(es)):   # keep the rest of the chain consistent: only the typed field is wrong
        es[j]["prev_hash"] = es[j - 1]["self_hash"]
        es[j]["self_hash"] = digest(algo, canon({k: v for k, v in es[j].items() if k not in ATTEST}))
    return "wrong_type_prev_hash", "FAIL", text_of(es), None


def m_wrong_type_self(rng, algo, base):
    es = json.loads(json.dumps(base)); at = rng.randrange(len(es))
    es[at]["self_hash"] = rng.choice([0, None, True, [], {}, "abc", es[at]["self_hash"].upper()])
    return "wrong_type_self_hash", "FAIL", text_of(es), None


def m_dup_key_top(rng, algo, base):
    es = json.loads(json.dumps(base)); at = rng.randrange(len(es)); k = rng.choice(CORE)
    lines = [json.dumps(e, ensure_ascii=False) for e in es]
    lines[at] = lines[at][:-1] + ', "%s": %s}' % (k, json.dumps(rand_value(rng), ensure_ascii=False))
    return "dup_key_top", "FAIL", "".join(ln + "\n" for ln in lines), None


def m_dup_key_data(rng, algo, base):
    es = json.loads(json.dumps(base)); at = rng.randrange(len(es))
    k = rand_key(rng); es[at]["data"][k] = 1; es = rechain(es, algo)
    lines = [json.dumps(e, ensure_ascii=False) for e in es]
    needle = json.dumps(k, ensure_ascii=False) + ": 1"
    if needle not in lines[at]:
        return None
    lines[at] = lines[at].replace(needle, needle + ", " + json.dumps(k, ensure_ascii=False) + ": 2", 1)
    return "dup_key_data", "FAIL", "".join(ln + "\n" for ln in lines), None


def m_float_in_data(rng, algo, base):
    es = json.loads(json.dumps(base)); at = rng.randrange(len(es)); es[at]["data"]["f"] = rng.choice([1.5, 1.0, 1e3, -0.0])
    return "float_in_data", "FAIL", text_of(rechain(es, algo)), None


def m_bigint_in_data(rng, algo, base):
    es = json.loads(json.dumps(base)); at = rng.randrange(len(es)); es[at]["data"]["n"] = rng.choice([2 ** 53, -(2 ** 53), 10 ** 30])
    return "bigint_in_data", "FAIL", text_of(rechain(es, algo)), None


def m_reorder_top(rng, algo, base):
    es = json.loads(json.dumps(base)); at = rng.randrange(len(es)); ks = list(es[at].keys()); rng.shuffle(ks)
    es[at] = {k: es[at][k] for k in ks}
    return "reorder_top_keys", "PASS", text_of(es), None


def m_known_key_escaped(rng, algo, base):
    es = json.loads(json.dumps(base)); at = rng.randrange(len(es)); k = rng.choice(CORE)
    lines = [json.dumps(e, ensure_ascii=False) for e in es]
    lines[at] = lines[at].replace('"%s":' % k, '"%s":' % json_escape_key(k), 1)
    return "known_key_escaped", "PASS", "".join(ln + "\n" for ln in lines), None


def m_wrong_type_ts(rng, algo, base):
    es = json.loads(json.dumps(base)); at = rng.randrange(len(es)); es[at]["ts"] = rng.choice([0, None, True, [], {"t": 1}])
    return "wrong_type_ts", "AGREE", text_of(rechain(es, algo)), None


def m_wrong_type_data(rng, algo, base):
    es = json.loads(json.dumps(base)); at = rng.randrange(len(es)); es[at]["data"] = rng.choice(["x", 0, None, True, [1, 2]])
    return "wrong_type_data", "AGREE", text_of(rechain(es, algo)), None


# ---------------------------------------------------------------- the verifiers of a tree
def find_java():
    cands = []
    if os.environ.get("JAVA_HOME"):
        cands.append(os.path.join(os.environ["JAVA_HOME"], "bin"))
    if shutil.which("javac"):
        cands.append(os.path.dirname(shutil.which("javac")))
    cands += sorted(glob.glob(os.path.expanduser("~/.local/jdk/jdk-*/bin")), reverse=True)
    best = None
    for b in cands:
        javac, java = os.path.join(b, "javac"), os.path.join(b, "java")
        if not (os.path.exists(javac) and os.path.exists(java)):
            continue
        try:
            ver = subprocess.run([java, "-version"], capture_output=True, text=True, timeout=30).stderr
            major = int(ver.split('"')[1].split(".")[0]) if '"' in ver else 0
        except Exception:  # noqa: BLE001
            continue
        if best is None or major > best[0]:
            best = (major, javac, java)
    return best


def discover(tree, tmp, only=None, js_override=None):
    """Build/locate every verifier of `tree`; returns name -> (cmd, flags_first). A toolchain that is present but whose
    verifier does not build is an error (never a silent 'measured without')."""
    v = {"python": (["python3", os.path.join(tree, "verifier.py")], False),
         "js": (["node", js_override or os.path.join(tree, "verifiers", "js", "cvverify.mjs")], False)}
    if shutil.which("go"):
        out = os.path.join(tmp, "cvverify-go")
        r = subprocess.run(["go", "build", "-o", out, "./cmd/cvverify"], cwd=os.path.join(tree, "verifiers", "go"), capture_output=True, text=True)
        if r.returncode != 0:
            raise SystemExit("go build failed: " + r.stderr[:400])
        v["go"] = ([out], True)
    if shutil.which("cargo"):
        r = subprocess.run(["cargo", "build", "--release", "--quiet"], cwd=os.path.join(tree, "verifiers", "rust"), capture_output=True, text=True)
        if r.returncode != 0:
            raise SystemExit("cargo build failed: " + r.stderr[:400])
        v["rust"] = ([os.path.join(tree, "verifiers", "rust", "target", "release", "cvverify")], False)
    jdk = find_java()
    if jdk:
        out = os.path.join(tmp, "cvj")
        r = subprocess.run([jdk[1], "-d", out, os.path.join(tree, "verifiers", "java", "CvVerify.java")], capture_output=True, text=True, timeout=180)
        if r.returncode != 0:
            raise SystemExit("javac failed: " + r.stderr[:400])
        v["java"] = ([jdk[2], "-cp", out, "CvVerify"], True)
    swift = os.environ.get("CVVERIFY_SWIFT") or os.path.join(tree, "verifiers", "swift", ".build", "debug", "cvverify")   # as the oracle
    if os.path.exists(swift):
        built = bool(os.environ.get("CVVERIFY_SWIFT")) or build_swift(os.path.join(tree, "verifiers", "swift"))
        check_fresh("swift", swift, os.path.join(tree, "verifiers", "swift", "Sources"), (".swift",), built)
        v["swift"] = ([swift], False)
    if only:
        v = {k: x for k, x in v.items() if k in only}
    return v


def run_one(kind, cmd, path):
    try:
        out = subprocess.run(cmd + [path], capture_output=True, text=True, timeout=60)
        r = json.loads(out.stdout)
    except Exception:  # noqa: BLE001
        return "NONJSON/CRASH", None
    return r.get("verdict", "NOVERDICT"), r


def _strings(o):
    """Every string value inside a parsed receipt (decoded: a key `a"b` is searched as a"b, not as its JSON escape)."""
    if isinstance(o, str):
        yield o
    elif isinstance(o, dict):
        for v in o.values():
            yield from _strings(v)
    elif isinstance(o, list):
        for v in o:
            yield from _strings(v)


def named_in(kind, receipt, keys):
    if receipt is None:
        return False
    if kind in ("rust", "swift"):
        return bool(receipt.get("schema_failures_idx"))
    want = "unknown_field:" + ",".join(keys)
    return any(want in s for s in _strings(receipt))


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--n", type=int, default=None, help="number of mutations (default: 1500; --quick = 150)")
    ap.add_argument("--quick", action="store_true")
    ap.add_argument("--seed", type=int, default=20261011)
    ap.add_argument("--tree", default=DEFAULT_TREE, help="the opencore/ directory whose verifiers are measured")
    ap.add_argument("--only", default=None, help="comma-separated verifier names")
    ap.add_argument("--js", default=None, help="path of the JS verifier to use instead of the tree's")
    ap.add_argument("--out", default=None, help="write the JSON summary here")
    ap.add_argument("--keep", action="store_true", help="keep the corpus directory (printed)")
    a = ap.parse_args(argv)
    n = a.n or (150 if a.quick else 1500)
    rng = random.Random(a.seed)
    srcs = base_ledgers()
    muts = mutations(rng, srcs, n)
    tmp = tempfile.mkdtemp(prefix="closed-schema-mutants-")
    try:
        verifiers = discover(os.path.abspath(a.tree), tmp, set(a.only.split(",")) if a.only else None, a.js)
        print(f"closed-schema bench: {n} mutations from {len(srcs)} sources, seed {a.seed}, tree {a.tree}")
        print(f"verifiers: {sorted(verifiers)}")
        out_of_class = {k: 0 for k in verifiers}
        silent = {k: 0 for k in verifiers}         # expected FAIL, verdict PASS
        unnamed = {k: 0 for k in verifiers}
        disagree = 0
        per_class = {}
        agree_only = {}                              # class -> verdict tuple -> count (no SPEC class: reported)
        failures = []
        for name, cls, text, named in muts:
            p = os.path.join(tmp, "m.jsonl")
            with open(p, "w", encoding="utf-8") as f:
                f.write(text)
            res = {k: run_one(k, cmd, p) for k, (cmd, _) in verifiers.items()}
            verdicts = {k: r[0] for k, r in res.items()}
            pc = per_class.setdefault(cls if cls != "AGREE" else name.split("@")[0], {"n": 0, "bad": 0})
            pc["n"] += 1
            bad = False
            if len(set(verdicts.values())) != 1:
                disagree += 1; bad = True
            if cls in ("PASS", "FAIL"):
                for k, vd in verdicts.items():
                    if vd != cls:
                        out_of_class[k] += 1; bad = True
                        if cls == "FAIL" and vd == "PASS":
                            silent[k] += 1
            else:
                agree_only.setdefault(name.split("@")[0], {}).setdefault(verdicts.get("python", "?"), 0)
                agree_only[name.split("@")[0]][verdicts.get("python", "?")] += 1
            if named:
                for k, (vd, rec) in res.items():
                    if not named_in(k, rec, named):
                        unnamed[k] += 1; bad = True
            if bad:
                pc["bad"] += 1
                if len(failures) < 40:
                    failures.append({"mutation": name, "expected": cls, "verdicts": verdicts, "named": named})
                if a.keep:
                    shutil.copy(p, os.path.join(tmp, name.replace("/", "_").replace("#", "_") + ".jsonl"))
        summary = {"mutations": n, "sources": len(srcs), "seed": a.seed, "tree": os.path.abspath(a.tree), "verifiers": sorted(verifiers),
                   "disagreements": disagree, "out_of_class": out_of_class, "silent_pass_on_expected_fail": silent, "unnamed_unknown_key": unnamed,
                   "per_class": per_class, "agree_only_measured": agree_only, "first_failures": failures}
        print(json.dumps({k: v for k, v in summary.items() if k != "first_failures"}, indent=1, ensure_ascii=False))
        for f_ in failures[:12]:
            print("  [BAD]", f_["mutation"], "expected", f_["expected"], f_["verdicts"], "named", f_["named"])
        if a.out:
            with open(a.out, "w", encoding="utf-8") as f:
                json.dump(summary, f, indent=1, ensure_ascii=False)
        ok = disagree == 0 and not any(out_of_class.values()) and not any(unnamed.values())
        print("RESULT:", "GREEN" if ok else "RED")
        if a.keep:
            print("corpus kept in", tmp)
        return 0 if ok else 1
    finally:
        if not a.keep:
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
