#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Roberto Locatelli
"""0.21.0 (14/10/2026), SPEC v0.4 §5 step 5 — the signature profile and Ed25519 points of small and mixed order.

- Without a key, a signature layer that does not verify is a FAIL in the verifiers that perform step 5 (JS, Go, Java, Swift)
  and `ok: false` in signer.py verify, with the failing entries named (spec/vectors/signatures, 21 vectors); until 0.20.3 the
  four verifiers said PASS. verifier.py and the Rust verifier do not perform step 5: their receipt counts the entries that
  carry a signature field (`signatures_not_checked`), and only then.
- ed25519_order: a key or an R of small order, a key of mixed order, a key or an R that does not decode, refused before the
  library; on 0.20.3 OpenSSL (cryptography), Node, Go and swift-crypto verified 6 of the 12 classes of ed25519-speccheck
  rebuilt on ledger entries, the JDK 4. The same rule for the signed chain tip.
- ML-DSA-65: Go and Java verify it, so a broken one is a FAIL there without a key; JS and Swift count it (`pq_not_checked`).
Cross-language parts run the JS verifier (node), Java (javac) and Go (go) when present; CV_REQUIRE_JAVA=1 / CV_REQUIRE_GO=1
make their absence an error; CV_SWIFT_BIN / CV_RUST_BIN name built binaries to include."""
import base64
import glob
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import ed25519_order as E  # noqa: E402

SDIR = os.path.join(HERE, "spec", "vectors", "signatures")
ENV = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
SMALL = ["0100000000000000000000000000000000000000000000000000000000000000",
         "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
         "0000000000000000000000000000000000000000000000000000000000000000",
         "0000000000000000000000000000000000000000000000000000000000000080",
         "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
         "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
         "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
         "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa"]


def _crypto():
    try:
        import cryptography  # noqa: F401
        return True
    except ImportError:
        if os.environ.get("CV_REQUIRE_CRYPTO") == "1":
            raise
        return False


def _vectors():
    out = []
    for p in sorted(glob.glob(os.path.join(SDIR, "*.expected.json"))):
        with open(p, encoding="utf-8") as f:
            out.append(json.load(f))
    return out


def _run(cmd):
    p = subprocess.run(cmd, capture_output=True, text=True, env=ENV, timeout=300)
    try:
        return p.returncode, json.loads(p.stdout)
    except ValueError:
        return p.returncode, None


class TestEd25519Order(unittest.TestCase):
    B = E.decode((4 * pow(5, E.p - 2, E.p)).to_bytes(32, "little"))   # RFC 8032 5.1: y = 4/5, x positive

    def test_small_order_points(self):
        # the eight canonical encodings of the points of small order: enumerated here from an order-8 point
        y = 2
        while True:
            P = E.decode(y.to_bytes(32, "little"))
            if P is not None and not E.is_neutral(E.scalar_mul(4, E.scalar_mul(E.L, P))):
                T = E.scalar_mul(E.L, P)
                break
            y += 1
        self.assertEqual(sorted(E.encode(E.scalar_mul(i, T)).hex() for i in range(8)), sorted(SMALL))
        for h in SMALL:
            self.assertEqual(E.key_problem(bytes.fromhex(h)), "small_order_key", h)
            self.assertEqual(E.r_problem(bytes.fromhex(h) + b"\0" * 32), "small_order_r", h)
        # mixed order: a key of prime order plus T
        A = E.scalar_mul(123456789, self.B)
        self.assertIsNone(E.key_problem(E.encode(A)))
        self.assertEqual(E.key_problem(E.encode(E.add(A, T))), "mixed_order_key")
        self.assertIsNone(E.r_problem(E.encode(E.add(A, T)) + b"\0" * 32))   # R of mixed order: left to the equation
        # not decodable: y >= p, x = 0 with the sign bit, a y with no x, wrong lengths
        # (y = p + 1 is y = 1 read without the y < p rule: the neutral point; y = 2 has no x on the curve)
        for bad in ((E.p).to_bytes(32, "little"), (E.p + 1).to_bytes(32, "little"), (1 | 1 << 255).to_bytes(32, "little"),
                    (2).to_bytes(32, "little"), b"\1" * 31, b""):
            self.assertIsNone(E.decode(bad), bad.hex())
            self.assertEqual(E.key_problem(bad), "key_not_decodable", bad.hex())
            self.assertEqual(E.r_problem(bad + b"\0" * 32), "r_not_decodable", bad.hex())
        self.assertEqual(E.r_problem(b"\0" * 63), "r_not_decodable")

    @unittest.skipUnless(_crypto(), "cryptography not installed")
    def test_positive_control_library_keys(self):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        cache = {}
        for i in range(64):
            sk = Ed25519PrivateKey.from_private_bytes(bytes([i, 0x5A]) + b"\0" * 30)
            pk = sk.public_key().public_bytes_raw()
            sig = sk.sign(b"m")
            self.assertIsNone(E.key_problem(pk), i)
            self.assertIsNone(E.strict_problem(pk, sig, cache), i)
        self.assertEqual(len(cache), 64)
        # a refused key stays refused when it comes back from the cache
        small = bytes.fromhex(SMALL[4])
        self.assertEqual([E.strict_problem(small, sig, cache) for _ in range(2)], ["small_order_key"] * 2)


class TestSignatureVectors(unittest.TestCase):
    def test_vectors_are_regenerated_identically(self):
        d = tempfile.mkdtemp(); self.addCleanup(shutil.rmtree, d, True)
        # make_vectors.py reads ../../../ed25519_order.py: the generator three levels below a copy of the module
        gen = os.path.join(d, "x", "y", "z"); os.makedirs(gen)
        shutil.copy(os.path.join(SDIR, "make_vectors.py"), gen)
        shutil.copy(os.path.join(HERE, "ed25519_order.py"), d)
        subprocess.run([sys.executable, os.path.join(gen, "make_vectors.py")], check=True, capture_output=True, env=ENV,
                       cwd=gen)
        for f in sorted(os.listdir(gen)):
            if f.endswith((".jsonl", ".json")):
                with open(os.path.join(gen, f), "rb") as a, open(os.path.join(SDIR, f), "rb") as b:
                    self.assertEqual(a.read(), b.read(), f)
        self.assertEqual(len([f for f in os.listdir(gen) if f.endswith(".expected.json")]), 21)

    def test_reference_counts_not_checks(self):
        for v in _vectors():
            rc, o = _run([sys.executable, os.path.join(HERE, "verifier.py"), os.path.join(SDIR, v["input"])])
            self.assertEqual((rc, o["verdict"]), (0, "PASS"), v["input"])
            self.assertEqual(o.get("signatures_not_checked"), v["without_step5"]["signatures_not_checked"], v["input"])
        rc, o = _run([sys.executable, os.path.join(HERE, "verifier.py"), os.path.join(HERE, "examples", "sample_ledger.jsonl")])
        self.assertNotIn("signatures_not_checked", o)   # no signature field: the receipt of 0.20.3

    @unittest.skipUnless(_crypto(), "cryptography not installed")
    def test_signer_py_names_every_failure(self):
        for v in _vectors():
            rc, o = _run([sys.executable, os.path.join(HERE, "signer.py"), "verify", os.path.join(SDIR, v["input"])])
            want = v["signature_profile"]
            self.assertEqual(o["ok"], want["verdict"] == "PASS", v["input"])
            self.assertEqual(rc, 0 if want["verdict"] == "PASS" else 1, v["input"])
            self.assertEqual(sorted((f["idx"], f["reason"]) for f in o["failures"]),
                             sorted((f["idx"], f["reason"]) for f in want["failures"]), v["input"])


def _binaries(tmp):
    """{name: argv prefix, flags-first} for the step-5 verifiers available here."""
    out = {}
    if shutil.which("node"):
        out["js"] = (["node", os.path.join(HERE, "verifiers", "js", "cvverify.mjs")], False)
    home = os.environ.get("JAVA_HOME")
    javac = os.path.join(home, "bin", "javac") if home and os.path.exists(os.path.join(home, "bin", "javac")) else shutil.which("javac")
    java = os.path.join(home, "bin", "java") if home and os.path.exists(os.path.join(home, "bin", "java")) else shutil.which("java")
    if javac and java:
        cp = os.path.join(tmp, "cls")
        subprocess.run([javac, "-d", cp, os.path.join(HERE, "verifiers", "java", "CvVerify.java")], check=True, capture_output=True)
        out["java"] = ([java, "-cp", cp, "CvVerify"], True)
    elif os.environ.get("CV_REQUIRE_JAVA") == "1":
        raise RuntimeError("CV_REQUIRE_JAVA=1 and no JDK")
    if shutil.which("go"):
        b = os.path.join(tmp, "cvverify-go")
        subprocess.run(["go", "build", "-o", b, "./cmd/cvverify"], cwd=os.path.join(HERE, "verifiers", "go"), check=True, capture_output=True)
        out["go"] = ([b], True)
    elif os.environ.get("CV_REQUIRE_GO") == "1":
        raise RuntimeError("CV_REQUIRE_GO=1 and no Go toolchain")
    if os.environ.get("CV_SWIFT_BIN"):
        out["swift"] = ([os.environ["CV_SWIFT_BIN"]], False)
    return out


class TestCrossLanguage(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        cls.bins = _binaries(cls.tmp)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, True)

    def run_v(self, name, path, flags=()):
        argv, first = self.bins[name]
        return _run(argv + (list(flags) + [path] if first else [path] + list(flags)))

    def test_vectors_in_every_step5_verifier(self):
        if not self.bins:
            self.skipTest("no step-5 verifier here (node, a JDK, Go)")
        for v in _vectors():
            for name in self.bins:
                rc, o = self.run_v(name, os.path.join(SDIR, v["input"]))
                self.assertIsNotNone(o, (name, v["input"]))
                self.assertEqual(o["verdict"], v["signature_profile"]["verdict"], (name, v["input"]))
                self.assertEqual(rc, 0 if o["verdict"] == "PASS" else 1, (name, v["input"]))

    @unittest.skipUnless(_crypto(), "cryptography not installed")   # cryptovalid_tip needs it
    def test_tip_signed_by_a_small_order_key(self):
        # a log key of small order and a signature (R small, S = 0) that the library's equation accepts on this payload:
        # the ts is ground until R + k*A is the neutral point. Refused everywhere (named), as an entry signature is.
        import cryptovalid_tip as TIP
        led = os.path.join(SDIR, "signed_valid.jsonl")
        with open(led, encoding="utf-8") as f:
            entries = [json.loads(line) for line in f]
        A_enc = bytes.fromhex(SMALL[4]); A = E.decode(A_enc)
        R_enc = bytes.fromhex(SMALL[5]); R = E.decode(R_enc)
        for s in range(3600):
            ts = "2026-10-14T10:%02d:%02dZ" % (s // 60, s % 60)
            payload = TIP.tip_payload(3, entries[0]["self_hash"], entries[2]["self_hash"], ts)
            k = int.from_bytes(hashlib.sha512(R_enc + A_enc + payload).digest(), "little") % E.L
            if E.is_neutral(E.add(R, E.scalar_mul(k, A))):
                break
        else:
            self.fail("no ts makes the equation hold")
        tip = {"kind": TIP.KIND, "entries": 3, "ledger_id": entries[0]["self_hash"], "tip_sha256": entries[2]["self_hash"],
               "ts": ts, "log_pubkey_hex": A_enc.hex(), "signature_hex": (R_enc + b"\0" * 32).hex()}
        tp = os.path.join(self.tmp, "small.tip.json")
        with open(tp, "w") as f:
            json.dump(tip, f)
        r = TIP.verify_tip_signature(tip, A_enc.hex())
        self.assertFalse(r["ok"]); self.assertIn("small_order_key", r["why"])
        if _crypto():   # control: the library alone accepts it (what 0.20.3 did)
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
            Ed25519PublicKey.from_public_bytes(A_enc).verify(bytes.fromhex(tip["signature_hex"]), TIP.tip_payload(3, tip["ledger_id"], tip["tip_sha256"], ts))
        flags = {"js": ["--tip", tp, "--trusted-pubkey", A_enc.hex()], "go": ["-tip", tp, "-trusted-pubkey", A_enc.hex()],
                 "java": ["-tip", tp, "-trusted-pubkey", A_enc.hex()], "swift": None}
        for name in self.bins:
            if not flags.get(name):
                continue
            rc, o = self.run_v(name, led, flags[name])
            self.assertEqual((rc, o["verdict"]), (1, "FAIL"), name)
            self.assertIn("small_order_key", json.dumps(o), name)

    def test_mixed_order_2_and_4_torsion_and_a_layer_of_ml_dsa_only(self):
        # NEMESIS 17/10: the 21 vectors carry no key whose torsion part has order 2 or 4 and no ledger whose layer is
        # signature_pq/signer_pq alone; a neutral-point test reduced to x = 0, or a layer list without the two ML-DSA
        # fields, passed the suites of 0.21.0. A = a*B + T (T of order 2, then 4), R = r*B, k even: the cofactorless equation holds.
        sys.path.insert(0, SDIR)
        import make_vectors as MV
        cases = {}
        for name, T in (("mixed_t2", MV.T2), ("mixed_t4", E.scalar_mul(2, MV.T8))):
            A = E.add(MV.aB, T)
            self.assertEqual(E.key_problem(E.encode(A)), "mixed_order_key", name)
            for nonce in range(1000):
                e = MV.chain([{"case": name, "nonce": nonce}])[0]
                k = int.from_bytes(hashlib.sha512(E.encode(MV.rB) + E.encode(A) + e["self_hash"].encode()).digest(), "little") % E.L
                if E.is_neutral(E.scalar_mul(k, T)):
                    break
            e["signature"] = base64.b64encode(E.encode(MV.rB) + ((MV.r + k * MV.a) % E.L).to_bytes(32, "little")).decode()
            e["signer"] = E.encode(A).hex()
            cases[name] = ([e], "mixed_order_key")
        for field in ("signature_pq", "signer_pq"):   # each of the two alone opens the layer
            pq = MV.chain([{"event": "%s-%d" % (field, i)} for i in range(2)])
            for e in pq:
                e[field] = "AAAA"
            cases[field + "_only"] = (pq, "missing signature/signer/self_hash")
        for name, (entries, why) in cases.items():
            path = os.path.join(self.tmp, name + ".jsonl")
            with open(path, "w", encoding="utf-8") as f:
                f.write("".join(json.dumps(e) + "\n" for e in entries))
            if _crypto():
                rc, o = _run([sys.executable, os.path.join(HERE, "signer.py"), "verify", path])
                self.assertEqual((rc, o["ok"]), (1, False), name)
                self.assertIn(why, json.dumps(o), name)
            for vname in self.bins:
                rc, o = self.run_v(vname, path)
                self.assertEqual((rc, o["verdict"]), (1, "FAIL"), (vname, name))
                if vname != "swift":   # Swift reports a boolean only
                    self.assertIn(why, json.dumps(o), (vname, name))

    @unittest.skipUnless(_crypto(), "cryptography not installed")
    def test_broken_ml_dsa_without_a_key(self):
        try:
            from cryptography.hazmat.primitives.asymmetric import mldsa  # noqa: F401
        except ImportError:
            self.skipTest("cryptography without ML-DSA")
        d = self.tmp
        kf = os.path.join(d, "hy.key")
        subprocess.run([sys.executable, os.path.join(HERE, "signer.py"), "keygen", "--pq", kf], check=True, capture_output=True, env=ENV)
        hy = os.path.join(d, "hy.jsonl")
        subprocess.run([sys.executable, os.path.join(HERE, "signer.py"), "sign", os.path.join(HERE, "examples", "sample_ledger.jsonl"),
                        hy, kf, "--pq-key", kf + ".pq"], check=True, capture_output=True, env=ENV)
        with open(hy, encoding="utf-8") as f:
            lines = [json.loads(x) for x in f]
        raw = bytearray(base64.b64decode(lines[1]["signature_pq"])); raw[9] ^= 1
        lines[1]["signature_pq"] = base64.b64encode(bytes(raw)).decode()
        bad = os.path.join(d, "hy_bad.jsonl")
        with open(bad, "w", encoding="utf-8") as f:
            f.write("".join(json.dumps(e) + "\n" for e in lines))
        want = {"go": "FAIL", "java": "FAIL", "js": "PASS", "swift": "PASS"}   # Go/Java verify ML-DSA; JS/Swift count it
        for name in self.bins:
            rc, o = self.run_v(name, bad)
            if name in ("java", "go") and "unverifiable" in json.dumps(o):   # a JDK below 24, a Go below 1.27: no ML-DSA
                self.assertNotEqual(o["signatures"].get("pq_protected"), True, (name, o.get("signatures")))   # declared,
                continue                                                                                       # never green
            self.assertEqual(o["verdict"], want[name], (name, o.get("signatures")))
            if name in ("js",):
                self.assertEqual(o["signatures"]["pq_not_checked"], len(lines))
            if name == "swift":
                self.assertEqual(o["pq_not_checked"], len(lines))
        rc, o = _run([sys.executable, os.path.join(HERE, "verifier.py"), bad])
        self.assertEqual((rc, o["verdict"], o["signatures_not_checked"]), (0, "PASS", len(lines)))


if __name__ == "__main__":
    unittest.main(verbosity=2)
