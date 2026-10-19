#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Roberto Locatelli
"""Generative bench of the evidence pack receipt (SPEC §10, cryptovalid-opencore 0.22.0). Development tool, not a command.

It builds base packs (unsigned; manifest + ledger signed; hybrid; with a token from a local TSA, for this digest and for
another), mutates each MANIFEST over the whole input space this verifier reads — a new key at every level (15 names), every
key removed, every value replaced by each JSON type, a key written twice, the format string — and verifies every file under
three pin policies (none, the right keys, other keys). On every receipt it checks:

  C1  no exception other than CheckNotRun (which must carry a COMPLETE receipt);
  C2  the vocabulary is closed (admission, refusal_class, three subjects, states, reasons per subject; refused ⇒ states null);
  C3  valid ⇒ admitted ∧ no subject contradicted; admitted ∧ ¬valid ∧ no contradicted ⇒ a producer reason key_unresolved or
      backend_missing (SPEC §10, "Disposition");
  C4  no `verified` on a check that did not run: sealed_content verified ⇒ an INDEPENDENT recomputation (sha256 of every file,
      the manifest digest, entry count and head, chain verdict) agrees; producer_signature verified ⇒ a pin was given;
      time_anchor is never verified;
  C5  no `contradicted` without a check that ran and failed: time_anchor contradicted ⇒ anchored true and (no token, or the
      token's bytes do not carry a granted imprint of this digest — recomputed with openssl here); sealed_content
      contradicted ⇒ the independent recomputation disagrees somewhere.
With --old <opencore 0.21.0 tree>: `valid` of 0.22.0 vs 0.21.0 on the same files, every difference put in one class of
SPEC §6 v0.5 (D1 token, D2 format, D3 types, D4 layer opened by any entry, D5 small order/strict encoding, D8 claimed PQ
layer, D74 openssl); a difference in no class, or a pack valid now that was not valid before, is a violation.
--sabotage <name> corrupts the receipts in a known way: the checks above must then report violations (the bench can fail).
Exit 0 = no violation."""
from __future__ import annotations

import argparse
import base64
import collections
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.dont_write_bytecode = True
import evidence_pack as EP  # noqa: E402
import signer  # noqa: E402
import verifier  # noqa: E402

STATES = {"verified", "contradicted", "indeterminate", "not_evaluated"}
REASONS = {"sealed_content": {"digest_mismatch", "artifact_invalid", "binding_mismatch"},
           "producer_signature": {"signature_invalid", "not_present", "self_asserted", "key_unresolved", "backend_missing"},
           "time_anchor": {"token_missing", "token_invalid", "binding_mismatch", "not_present", "tsa_not_checked",
                           "instrument_failure"}}
CLASSES = {"format_unsupported", "unknown_member", "malformed"}
NAMES = ["constructor", "__proto__", "toString", "hasOwnProperty", "valueOf", "isPrototypeOf", "10", "9", "", "é", "😀",
         "Name", "name ", "zz", "x_unknown"]
VALUES = [None, True, False, 0, 1, -1, 1.5, "", "x", "AAAA", [], [1], {}, {"a": 1}]
SABOTAGES = ("tsa_not_checked_is_verified", "precedence_reversed", "valid_ignores_anchor", "refused_with_states",
             "self_asserted_is_verified", "unknown_reason")


# ── base packs ───────────────────────────────────────────────────────────────────────────────────────────────────────────
def _run(*a, **kw):
    return subprocess.run(list(a), check=True, capture_output=True, **kw)


class LocalTsa:
    """A TSA of this machine (openssl ts -reply), as in test_receipt_design_20261013.py: real tokens, self-issued."""

    def __init__(self, td):
        self.td = td
        j = self.j
        cnf = ("[ tsa ]\ndefault_tsa = t1\n[ t1 ]\nserial = {d}/serial\ncrypto_device = builtin\nsigner_cert = {d}/tsa.crt\n"
               "certs = {d}/ca.crt\nsigner_key = {d}/tsa.key\nsigner_digest = sha256\ndefault_policy = 1.2.3.4.1\n"
               "digests = sha256\naccuracy = secs:1\nordering = yes\ntsa_name = no\ness_cert_id_chain = no\n"
               "ess_cert_id_alg = sha256\n[ v3_tsa ]\nextendedKeyUsage = critical,timeStamping\nbasicConstraints = CA:FALSE\n")
        with open(j("tsa.cnf"), "w") as f:
            f.write(cnf.format(d=td))
        with open(j("serial"), "w") as f:
            f.write("01\n")
        _run("openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-keyout", j("ca.key"),
             "-out", j("ca.crt"), "-subj", "/CN=bench-ca", "-days", "2")
        _run("openssl", "req", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-keyout", j("tsa.key"),
             "-out", j("tsa.csr"), "-subj", "/CN=bench-tsa")
        _run("openssl", "x509", "-req", "-in", j("tsa.csr"), "-CA", j("ca.crt"), "-CAkey", j("ca.key"), "-CAcreateserial",
             "-out", j("tsa.crt"), "-days", "2", "-extfile", j("tsa.cnf"), "-extensions", "v3_tsa")

    def j(self, n):
        return os.path.join(self.td, n)

    def token(self, digest_hex):
        _run("openssl", "ts", "-query", "-digest", digest_hex, "-sha256", "-cert", "-out", self.j("q.tsq"))
        _run("openssl", "ts", "-reply", "-queryfile", self.j("q.tsq"), "-config", self.j("tsa.cnf"), "-section", "t1",
             "-out", self.j("r.tsr"))
        with open(self.j("r.tsr"), "rb") as f:
            return base64.b64encode(f.read()).decode()


def _quiet(fn, *a, **kw):
    import contextlib
    import io
    with contextlib.redirect_stdout(io.StringIO()):
        return fn(*a, **kw)


def base_packs(td):
    """[(name, pack_dir, pins)] — pins: dict of name -> (signer_pubkey_hex, pq_pubkey_b64, manifest_signer_hex)."""
    sample = os.path.join(ROOT, "examples", "sample_ledger.jsonl")
    out = []
    p = os.path.join(td, "unsigned")
    EP.build_pack([sample], p, subject="bench")
    other = "ab" * 32
    out.append(("unsigned", p, {"none": (None, None, None), "other": (other, None, other)}))
    k = os.path.join(td, "k")
    pub = signer.keygen(k)["public_key_hex"]
    led = os.path.join(td, "signed.jsonl")
    _quiet(signer.sign_ledger, sample, led, k)
    p = os.path.join(td, "signed")
    EP.build_pack([led], p, subject="bench", sign_key=k)
    out.append(("signed", p, {"none": (None, None, None), "right": (pub, None, pub), "other": (other, None, other)}))
    try:
        from cryptography.hazmat.primitives.asymmetric import mldsa  # noqa: F401
        kq = os.path.join(td, "kq")
        info = signer.keygen(kq)
        pqpub = signer.keygen_pq(kq + ".pq")["public_key_b64"]
        ledq = os.path.join(td, "hybrid.jsonl")
        _quiet(signer.sign_ledger, sample, ledq, kq, pq_keyfile=kq + ".pq")
        p = os.path.join(td, "hybrid")
        EP.build_pack([ledq], p, subject="bench", sign_key=kq, pq_pubkey_b64=pqpub, signer_pubkey_hex=info["public_key_hex"])
        out.append(("hybrid", p, {"none": (None, None, None), "right": (info["public_key_hex"], pqpub, info["public_key_hex"]),
                                  "manifest_pin": (None, None, info["public_key_hex"])}))
    except ImportError:
        pass
    # a signed ledger in an unsigned manifest (the post-quantum claim can then be rewritten with the digest), and a ledger
    # whose first entry is unsigned and whose second carries a signature that does not verify (SPEC §5 step 5)
    p = os.path.join(td, "ledger_signed_only")
    EP.build_pack([led], p, subject="bench")
    out.append(("ledger_signed_only", p, {"none": (None, None, None), "right": (pub, None, None), "other": (other, None, None)}))
    rows = [json.loads(x) for x in open(sample, encoding="utf-8") if x.strip()]
    rows[1]["signature"], rows[1]["signer"] = base64.b64encode(bytes(64)).decode(), pub
    part = os.path.join(td, "partial.jsonl")
    with open(part, "w", encoding="utf-8") as f:
        f.write("".join(json.dumps(x) + "\n" for x in rows))
    p = os.path.join(td, "partial_layer")
    EP.build_pack([part], p, subject="bench")
    out.append(("partial_layer", p, {"none": (None, None, None)}))
    if shutil.which("openssl"):
        os.makedirs(os.path.join(td, "tsa"))
        tsa = LocalTsa(os.path.join(td, "tsa"))
        for name, digest_of in (("token_ok", None), ("token_other", "00" * 32)):
            p = os.path.join(td, name)
            EP.build_pack([sample], p, subject="bench")
            m = _load(p)
            m["rfc3161_timestamp"] = {"anchored": True, "tsa": "local", "tsr_b64": tsa.token(digest_of or m["manifest_digest_sha256"])}
            _store(p, m)
            out.append((name, p, {"none": (None, None, None)}))
    return out


def _load(p):
    with open(os.path.join(p, "MANIFEST.json"), encoding="utf-8") as f:
        return json.load(f)


def _store(p, m, text=None):
    with open(os.path.join(p, "MANIFEST.json"), "w", encoding="utf-8") as f:
        f.write(text if text is not None else json.dumps(m, ensure_ascii=False, indent=1, sort_keys=True))


def _redigest(m):
    m2 = {k: v for k, v in m.items() if k not in ("manifest_digest_sha256", "rfc3161_timestamp", "manifest_signature", "manifest_signer")}
    try:
        m["manifest_digest_sha256"] = hashlib.sha256(json.dumps(m2, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    except (TypeError, ValueError):
        pass


# ── mutations ────────────────────────────────────────────────────────────────────────────────────────────────────────────
def _paths(m):
    """Every object of the manifest this verifier reads, as (label, getter)."""
    yield "top", lambda x: x
    if isinstance(m.get("rfc3161_timestamp"), dict):
        yield "rfc3161_timestamp", lambda x: x["rfc3161_timestamp"]
    if isinstance(m.get("file_digests_sha256"), dict):
        yield "file_digests_sha256", lambda x: x["file_digests_sha256"]
    for i, _ in enumerate(m.get("ledgers") or []):
        yield f"ledgers[{i}]", (lambda i: lambda x: x["ledgers"][i])(i)


def mutations(m):
    """(label, manifest or None, raw text or None). Digest recomputed in a second copy of each, so the content checks pass
    and the mutation itself is what the verifier meets."""
    import copy
    for where, get in _paths(m):
        for name in NAMES:
            x = copy.deepcopy(m)
            get(x)[name] = "v"
            yield f"{where}+{name!r}", x
        for key in list(get(m)):
            x = copy.deepcopy(m)
            del get(x)[key]
            yield f"{where}-{key}", x
            for i, v in enumerate(VALUES):
                x = copy.deepcopy(m)
                get(x)[key] = copy.deepcopy(v)
                yield f"{where}.{key}=V{i}", x
    for fmt in (None, "cryptovalid-evidence-pack/1.0", "cryptovalid-evidence-pack/1.2", "CRYPTOVALID-EVIDENCE-PACK/1.1",
                "cryptovalid-evidence-pack/1.1 ", 1.1):
        x = copy.deepcopy(m)
        if fmt is None:
            x.pop("pack_format", None)
        else:
            x["pack_format"] = fmt
        yield f"format={fmt!r}", x
    # anchors without a token, with an empty token, with garbage
    for ts in ({"anchored": True}, {"anchored": True, "tsr_b64": ""}, {"anchored": True, "tsr_b64": "AAAA"},
               {"anchored": False, "tsr_b64": "AAAA"}, {"anchored": True, "tsr_b64": "!!!"}):
        x = copy.deepcopy(m)
        x["rfc3161_timestamp"] = ts
        yield f"ts={sorted(ts.items())!r}", x
    # signatures: the neutral point, a broken signature, non-strict encodings
    ident = (bytes([1]) + bytes(31)).hex()
    forged = base64.b64encode(bytes([1]) + bytes(63)).decode()
    for sig_set in ({"manifest_signer": ident, "manifest_signature": forged},
                    {"manifest_signature": base64.b64encode(bytes(64)).decode(), "manifest_signer": "11" * 32}):
        x = copy.deepcopy(m)
        x.update(sig_set)
        yield f"sig={list(sig_set.values())[0][:6]}", x
    if m.get("manifest_signature"):
        x = copy.deepcopy(m)
        x["manifest_signer"] = x["manifest_signer"].upper()
        yield "signer_upper", x
        x = copy.deepcopy(m)
        x["manifest_signature"] = " " + x["manifest_signature"]
        yield "signature_space", x
    # claimed post-quantum layer on a ledger without one / pq claim removed
    for i, _ in enumerate(m.get("ledgers") or []):
        x = copy.deepcopy(m)
        x["ledgers"][i]["pq_protected"] = True
        yield f"ledgers[{i}].pq_claimed", x


def raw_mutations(text):
    """A key written twice, at the top and inside a ledger entry."""
    yield "dup_top", text.replace('"subject":', '"subject": "dup",\n "subject":', 1)
    yield "dup_ledger", text.replace('"file":', '"file": "x",\n   "file":', 1)


# ── checks ───────────────────────────────────────────────────────────────────────────────────────────────────────────────
def _independent(pack, m):
    """Recompute, without evidence_pack: every listed file's sha256, the manifest digest, each ledger's count/head/chain."""
    ok = True
    digs = m.get("file_digests_sha256")
    if not isinstance(digs, dict) or not digs:
        return False
    root = os.path.realpath(pack)
    for name, dig in digs.items():
        p = os.path.join(pack, name)
        rp = os.path.realpath(p)
        if not (rp.startswith(root + os.sep) and os.path.isfile(p)):
            return False
        with open(p, "rb") as f:
            ok = ok and hashlib.sha256(f.read()).hexdigest() == dig
    m2 = {k: v for k, v in m.items() if k not in ("manifest_digest_sha256", "rfc3161_timestamp", "manifest_signature", "manifest_signer")}
    ok = ok and hashlib.sha256(json.dumps(m2, sort_keys=True, separators=(",", ":")).encode()).hexdigest() == m.get("manifest_digest_sha256")
    for lm in m.get("ledgers") or []:
        p = os.path.join(pack, lm["file"])
        if not os.path.isfile(p):
            return False
        lines = [ln for ln in open(p, encoding="utf-8") if ln.strip()]
        head = json.loads(lines[-1]).get("self_hash") if lines else None
        ok = ok and len(lines) == lm.get("entries") and type(lm.get("entries")) is int and head == lm.get("head_self_hash")
        ok = ok and verifier.verify_ledger(p).get("verdict") == "PASS"
    return ok


def _token_binds(tsr_b64, digest_hex):
    """Independent of evidence_pack: openssl ts -reply -text on the bytes; granted and the imprint is this digest."""
    try:
        raw = base64.b64decode(tsr_b64, validate=True)
    except Exception:  # noqa: BLE001
        return False
    if not raw or not (isinstance(digest_hex, str) and len(digest_hex) == 64):
        return False
    with tempfile.NamedTemporaryFile(suffix=".tsr") as f:
        f.write(raw)
        f.flush()
        r = subprocess.run(["openssl", "ts", "-reply", "-in", f.name, "-text"], capture_output=True, text=True)
    t = r.stdout
    if "Granted" not in t or "Message data:" not in t:
        return False
    hexs = "".join(t.split("Message data:", 1)[1].split("Serial number")[0].split())
    return digest_hex.lower() in "".join(c for c in hexs.lower() if c in "0123456789abcdef")


def sabotage(r, how):
    import copy
    r = copy.deepcopy(r)
    st = r.get("states")
    if how == "refused_with_states" and r.get("admission") == "refused":
        r["states"] = {"sealed_content": {"state": "verified", "reasons": []}}
    if not isinstance(st, dict):
        return r
    if how == "tsa_not_checked_is_verified" and st["time_anchor"]["reasons"] == ["tsa_not_checked"]:
        st["time_anchor"] = {"state": "verified", "reasons": []}
    if how == "self_asserted_is_verified" and "self_asserted" in st["producer_signature"]["reasons"] \
            and set(st["producer_signature"]["reasons"]) == {"self_asserted"}:
        st["producer_signature"] = {"state": "verified", "reasons": []}
    if how == "precedence_reversed":
        for s in st.values():
            if s["state"] == "contradicted" and s["reasons"] and len(s["reasons"]) >= 1:
                s["state"] = "not_evaluated"
    if how == "valid_ignores_anchor" and st["time_anchor"]["state"] == "contradicted":
        r["valid"] = bool(r["files_ok"] and r["manifest_ok"] and r["ledgers_ok"])
    if how == "unknown_reason" and st["time_anchor"]["reasons"] == ["not_present"]:
        st["time_anchor"]["reasons"] = ["absent"]
    return r


def check(r, pack, m, pins, violations, label):
    def bad(c, why):
        violations[c].append(f"{label}: {why}")
    if not isinstance(r, dict):
        return bad("C1", f"no receipt: {r!r}"[:200])
    adm = r.get("admission")
    if adm not in ("admitted", "refused"):
        return bad("C2", f"admission {adm!r}")
    if adm == "refused":
        if r.get("refusal_class") not in CLASSES or r.get("states") is not None or r.get("valid") is not False:
            bad("C2", f"refused receipt {r.get('refusal_class')!r} states {r.get('states')!r} valid {r.get('valid')!r}")
        return
    st = r.get("states")
    if r.get("refusal_class") is not None or not isinstance(st, dict) or set(st) != set(REASONS):
        return bad("C2", f"admitted receipt with states {st!r}"[:200])
    for subj, s in st.items():
        if set(s) - {"state", "reasons", "detail"} or s.get("state") not in STATES or s["state"] == "indeterminate":
            bad("C2", f"{subj} {s!r}")
        if not set(s.get("reasons") or []) <= REASONS[subj]:
            bad("C2", f"{subj} reasons {s.get('reasons')!r}")
        if s.get("state") == "verified" and s.get("reasons"):
            bad("C2", f"{subj} verified with reasons {s['reasons']!r}")
        if s.get("state") != "verified" and not s.get("reasons"):
            bad("C2", f"{subj} {s['state']} without a reason")
    contradicted = [k for k, s in st.items() if s.get("state") == "contradicted"]
    if r.get("valid") is True and contradicted:
        bad("C3", f"valid with {contradicted}")
    if r.get("valid") is False and not contradicted and \
            not ({"key_unresolved", "backend_missing"} & set(st["producer_signature"]["reasons"])):
        bad("C3", f"not valid, nothing contradicted, producer {st['producer_signature']!r}")
    indep = _independent(pack, m) if isinstance(m, dict) else None
    if st["sealed_content"]["state"] == "verified" and indep is not True:
        bad("C4", "sealed_content verified, independent recomputation disagrees")
    if st["sealed_content"]["state"] == "contradicted" and indep is True:
        bad("C5", f"sealed_content contradicted, independent recomputation agrees: {st['sealed_content']!r}")
    if st["producer_signature"]["state"] == "verified" and not any(pins):
        bad("C4", "producer verified without a pin")
    if st["time_anchor"]["state"] == "verified":
        bad("C4", "time_anchor verified (this verifier never checks the TSA)")
    if st["time_anchor"]["state"] == "contradicted":
        ts = m.get("rfc3161_timestamp") if isinstance(m, dict) else None
        if not (isinstance(ts, dict) and ts.get("anchored") is True):
            bad("C5", "time_anchor contradicted with no claim")
        elif "tsr_b64" in ts and _token_binds(ts["tsr_b64"], m.get("manifest_digest_sha256", "")):
            bad("C5", "time_anchor contradicted, the token binds this digest")


def verify_one(pack, pins, how):
    ed, pq, man = pins
    try:
        r = EP.verify_pack(pack, pq_pubkey_b64=pq, signer_pubkey_hex=ed, manifest_signer_hex=man)
    except verifier.CheckNotRun as e:
        r = e.receipt if e.receipt is not None else f"CheckNotRun without receipt: {e}"
    except Exception as e:  # noqa: BLE001
        r = f"{type(e).__name__}: {e}"
    return sabotage(r, how) if how and isinstance(r, dict) else r


# ── 0.21.0 comparison ────────────────────────────────────────────────────────────────────────────────────────────────────
_OLD_DRIVER = r'''
import json, sys
sys.dont_write_bytecode = True
sys.path.insert(0, sys.argv[1])
import evidence_pack as EP
for line in sys.stdin:
    pack, ed, pq, man = json.loads(line)
    try:
        v = EP.verify_pack(pack, pq_pubkey_b64=pq, signer_pubkey_hex=ed, manifest_signer_hex=man).get("valid")
    except Exception as e:
        v = "exc:" + type(e).__name__
    print(json.dumps(v), flush=True)
'''


def old_valids(old, jobs):
    r = subprocess.run([sys.executable, "-B", "-c", _OLD_DRIVER, os.path.abspath(old)], input="".join(json.dumps(j) + "\n" for j in jobs),
                       capture_output=True, text=True, env=dict(os.environ, PYTHONPATH=""))
    if r.returncode != 0:
        raise SystemExit(f"old driver failed: {r.stderr[-500:]}")
    return [json.loads(x) for x in r.stdout.splitlines()]


def classify(r, m, label):
    """The SPEC §6 (v0.5) class of a valid 0.21.0 → not valid 0.22.0 difference, or None."""
    if not isinstance(r, dict):
        return None
    if r.get("admission") == "refused":
        if r.get("refusal_class") == "format_unsupported":
            return "D2"
        if r.get("refusal_class") == "malformed":
            return "D3"
        return None
    st = r["states"]
    if st["time_anchor"]["state"] == "contradicted":
        return "D1"
    det = st["producer_signature"].get("detail", "")
    if st["producer_signature"]["state"] == "contradicted":
        if "claims a post-quantum layer" in det:
            return "D8"
        if "manifest signature" in det:
            return "D5"
        return "D4"
    return None


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--old", help="an opencore 0.21.0 tree: compare `valid` on the same files")
    ap.add_argument("--sabotage", choices=SABOTAGES)
    ap.add_argument("--json", help="write counts here")
    a = ap.parse_args(argv)
    td = tempfile.mkdtemp(prefix="cv_pack_states_")
    violations = collections.defaultdict(list)
    counts = collections.Counter()
    diffs = collections.Counter()
    try:
        bases = base_packs(os.path.join(td, "base"))
        jobs, cases = [], []
        n = 0
        for bname, bpack, pins in bases:
            m0 = _load(bpack)
            with open(os.path.join(bpack, "MANIFEST.json"), encoding="utf-8") as f:
                text0 = f.read()
            variants = [("as_built", m0, None)]
            for label, x in mutations(m0):
                variants.append((label, x, None))
                y = json.loads(json.dumps(x)) if isinstance(x, dict) else x
                if isinstance(y, dict):
                    _redigest(y)
                    variants.append((label + "+redigest", y, None))
            for label, text in raw_mutations(text0):
                variants.append((label, None, text))
            for label, x, text in variants:
                n += 1
                p = os.path.join(td, f"v{n}")
                shutil.copytree(bpack, p)
                _store(p, x, text)
                for pname, pv in pins.items():
                    lab = f"{bname}/{label}/{pname}"
                    r = verify_one(p, pv, a.sabotage)
                    counts["receipts"] += 1
                    counts["refused" if isinstance(r, dict) and r.get("admission") == "refused" else "admitted"] += 1
                    check(r, p, x if x is not None else None, pv, violations, lab)
                    jobs.append([p, *pv])
                    cases.append((lab, r, x))
            counts["files"] = n
        if a.old:
            for (lab, r, x), v_old in zip(cases, old_valids(a.old, jobs)):
                v_new = r.get("valid") if isinstance(r, dict) else None
                if v_old == v_new:
                    continue
                if v_new is True:
                    violations["C6"].append(f"{lab}: valid now, {v_old!r} on 0.21.0")
                    continue
                if isinstance(v_old, str):   # 0.21.0 raised (a traceback at the CLI): now a receipt
                    diffs["exception_0210"] += 1
                    continue
                cls = classify(r, x, lab)
                if cls is None:
                    violations["C6"].append(f"{lab}: valid {v_old!r} → {v_new!r}, no class: {json.dumps(r.get('states') if isinstance(r, dict) else r)[:200]}")
                else:
                    diffs[cls] += 1
    finally:
        shutil.rmtree(td, True)
    out = {"bases": [b[0] for b in bases], "counts": dict(counts), "violations": {k: len(v) for k, v in violations.items()},
           "valid_differences_vs_0210": dict(diffs), "sabotage": a.sabotage}
    print(json.dumps(out, sort_keys=True))
    for k, v in sorted(violations.items()):
        for x in v[:5]:
            print(f"[{k}] {x}", file=sys.stderr)
    if a.json:
        with open(a.json, "w") as f:
            json.dump(out, f, sort_keys=True, indent=1)
    return 1 if any(violations.values()) else 0


if __name__ == "__main__":
    raise SystemExit(main())
