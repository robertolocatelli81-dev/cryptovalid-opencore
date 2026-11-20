# SPDX-License-Identifier: AGPL-3.0-or-later
"""SPEC §22 (Unreleased): the decisions taken on 2026-11-20 after the re-measurement of 0.27.0.

Each class holds one rule of §22 and fails on the branch before it (9b81e9c, 0.27.0 + the rules of §21); the tests named
`*_control` hold what the rule does not change and pass there too. Cross-language parts run the JS (node), Java (javac)
and Go (go) verifiers when present (CV_REQUIRE_JAVA=1 / CV_REQUIRE_GO=1 make their absence an error).
"""
import hashlib
import json
import os
import random
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import verifier as V  # noqa: E402
import cryptovalid_tip as T  # noqa: E402
import cryptovalid_ingest as I  # noqa: E402

try:   # `import signer` succeeds without cryptography (lazy import): the library itself is the test
    import cryptography  # noqa: F401
    import signer
    HAVE_CRYPTO = True
except ImportError:
    HAVE_CRYPTO = False
if os.environ.get("CV_REQUIRE_CRYPTO") == "1" and not HAVE_CRYPTO:
    raise SystemExit("CV_REQUIRE_CRYPTO=1 but `cryptography` is missing: the cases that need it would be skipped")

ENV = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}


def _canon(e):
    return json.dumps(e, sort_keys=True, separators=(",", ":")).encode()


def _ledger(path, n, tag="d"):
    prev, out = "0" * 64, []
    for i in range(n):
        e = {"idx": i, "ts": f"2026-11-20T07:00:{i:02d}Z", "data": {"tag": tag, "i": i}, "prev_hash": prev}
        e["self_hash"] = hashlib.sha256(_canon(e)).hexdigest()
        prev = e["self_hash"]
        out.append(e)
    with open(path, "w", encoding="utf-8") as f:
        for e in out:
            f.write(json.dumps(e) + "\n")
    return out


def _binaries(tmp):
    """{name: (argv prefix, flags first, flag prefix)} for the ledger verifiers that check a tip."""
    out = {"python": ([sys.executable, os.path.join(HERE, "verifier.py")], False, "--")}
    if shutil.which("node"):
        out["js"] = (["node", os.path.join(HERE, "verifiers", "js", "cvverify.mjs")], False, "--")
    home = os.environ.get("JAVA_HOME")
    javac = os.path.join(home, "bin", "javac") if home and os.path.exists(os.path.join(home, "bin", "javac")) else shutil.which("javac")
    java = os.path.join(home, "bin", "java") if home and os.path.exists(os.path.join(home, "bin", "java")) else shutil.which("java")
    if javac and java:
        cp = os.path.join(tmp, "cls")
        subprocess.run([javac, "-d", cp, os.path.join(HERE, "verifiers", "java", "CvVerify.java")], check=True, capture_output=True)
        out["java"] = ([java, "-cp", cp, "CvVerify"], True, "-")
    elif os.environ.get("CV_REQUIRE_JAVA") == "1":
        raise RuntimeError("CV_REQUIRE_JAVA=1 and no JDK")
    if shutil.which("go"):
        b = os.path.join(tmp, "cvverify-go")
        subprocess.run(["go", "build", "-o", b, "./cmd/cvverify"], cwd=os.path.join(HERE, "verifiers", "go"), check=True, capture_output=True)
        out["go"] = ([b], True, "-")
    elif os.environ.get("CV_REQUIRE_GO") == "1":
        raise RuntimeError("CV_REQUIRE_GO=1 and no Go toolchain")
    return out


def _strings(v):
    """Every string inside a decoded JSON value (a receipt names its failures in different fields per language)."""
    if isinstance(v, str):
        yield v
    elif isinstance(v, dict):
        for k, x in v.items():
            yield from _strings(k)
            yield from _strings(x)
    elif isinstance(v, list):
        for x in v:
            yield from _strings(x)


def _run(bins, name, ledger, flags):
    argv, first, _ = bins[name]
    cp = subprocess.run(argv + (flags + [ledger] if first else [ledger] + flags), capture_output=True, text=True, env=ENV)
    try:
        doc = json.loads(cp.stdout)
    except ValueError:
        doc = None
    return cp.returncode, doc, cp.stdout + cp.stderr


@unittest.skipUnless(HAVE_CRYPTO, "needs `cryptography` (the `sign` extra)")
class TestTrustedLogKeyRequiresTip(unittest.TestCase):
    """§22 rule 1: a trusted log key makes the tip required, in the four verifiers that check a tip."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        cls.led = os.path.join(cls.tmp, "l.jsonl")
        _ledger(cls.led, 4)
        cls.pk = signer.keygen(os.path.join(cls.tmp, "log.key"))["public_key_hex"]
        cls.bins = _binaries(cls.tmp)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_library_without_tip_is_tip_missing(self):
        r = V.verify_ledger(self.led, trusted_pubkey_hex=self.pk)
        self.assertEqual(r["verdict"], "FAIL")
        self.assertIsNone(r["tip"])
        self.assertTrue(any(e["error"].startswith("tip_missing") for e in r["parse_errors"]), r["parse_errors"])

    def test_library_without_key_and_without_tip_control(self):
        r = V.verify_ledger(self.led)
        self.assertEqual(r["verdict"], "PASS")
        self.assertIsNone(r["tip"])

    def test_every_verifier_fails_without_tip_and_passes_with_it(self):
        for name in self.bins:
            d = self.bins[name][2]
            rc, doc, raw = _run(self.bins, name, self.led, [d + "trusted-pubkey", self.pk])
            self.assertEqual(rc, 1, (name, raw[-400:]))
            self.assertTrue(any(s.startswith("tip_missing") for s in _strings(doc)), (name, raw[-400:]))
        T.sign_tip(self.led, os.path.join(self.tmp, "log.key"))
        try:
            for name in self.bins:
                d = self.bins[name][2]
                rc, _doc, raw = _run(self.bins, name, self.led, [d + "trusted-pubkey", self.pk])
                self.assertEqual(rc, 0, (name, raw[-400:]))
        finally:
            os.remove(self.led + ".tip.json")

    def test_every_verifier_without_key_control(self):
        for name in self.bins:
            rc, _doc, raw = _run(self.bins, name, self.led, [])
            self.assertEqual(rc, 0, (name, raw[-400:]))


_NEAR = ["Kind", "kind ", "KIND", "signature_pq_HEX", "Signature_PQ_Hex", "log_pubkey", "signature", "signer", "__proto__",
         "constructor", "toString", "", " ", "zz", "entries\u0000", "ts​", "é", "\U0001f600", "ｋｉｎｄ",
         "a" * 130]


def _random_key(rng):
    alphabet = "abcXYZ_-.:/ 0éıKａ\U0001f600\U00010348\u0000\u007f"
    return "".join(rng.choice(alphabet) for _ in range(rng.randint(0, 8)))


def _random_value(rng):
    return rng.choice([None, True, 0, -1, 2 ** 40, "", "x", "\U0001f600", [], [1, "a"], {}, {"k": [None]}])


@unittest.skipUnless(HAVE_CRYPTO, "needs `cryptography` (the `sign` extra)")
class TestTipIsClosed(unittest.TestCase):
    """§22 rule 2: a member outside the nine of a tip is `tip_invalid: unknown_member:<keys>`, the same text in Python,
    JS, Go and Java (keys in code-point order, cut to 120 code points)."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        cls.led = os.path.join(cls.tmp, "l.jsonl")
        _ledger(cls.led, 3)
        cls.key = os.path.join(cls.tmp, "log.key")
        cls.pk = signer.keygen(cls.key)["public_key_hex"]
        cls.tip = T.sign_tip(cls.led, cls.key)
        cls.bins = _binaries(cls.tmp)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def _place(self, extra):
        doc = dict(self.tip)
        doc.update(extra)
        with open(self.led + ".tip.json", "w", encoding="utf-8") as f:
            f.write(json.dumps(doc))
        return doc

    @staticmethod
    def _want(extra):
        return "tip_invalid: unknown_member:" + ",".join(sorted(extra))[:120]

    def test_python_library_names_the_member(self):
        self._place({"zz_unknown": 1})
        r = V.verify_ledger(self.led, trusted_pubkey_hex=self.pk)
        self.assertEqual(r["verdict"], "FAIL")
        self.assertEqual(r["tip"]["error"], "tip_invalid: unknown_member:zz_unknown")
        r = T.check_tip(3, self.tip["tip_sha256"], self._place({"zz_unknown": 1}), self.pk, first_self_hash=self.tip["ledger_id"])
        self.assertEqual(r["error"], "tip_invalid: unknown_member:zz_unknown")

    def test_the_nine_members(self):
        self.assertEqual(T.TIP_MEMBERS, {"kind", "entries", "ledger_id", "tip_sha256", "ts", "log_pubkey_hex", "signature_hex",
                                         "signature_pq_hex", "log_pq_pubkey_b64"})

    def test_a_tip_of_the_nine_members_control(self):
        self._place({})
        for name in self.bins:
            d = self.bins[name][2]
            rc, _doc, raw = _run(self.bins, name, self.led, [d + "trusted-pubkey", self.pk])
            self.assertEqual(rc, 0, (name, raw[-400:]))

    def test_generated_members_same_text_in_every_verifier(self):
        rng = random.Random(20261120)
        cases = [{k: 1} for k in _NEAR]
        for _ in range(25):
            extra = {}
            for _ in range(rng.randint(1, 3)):
                k = _random_key(rng)
                if k not in T.TIP_MEMBERS:
                    extra[k] = _random_value(rng)
            if extra:
                cases.append(extra)
        for extra in cases:
            self._place(extra)
            want = self._want(extra)
            for name in self.bins:
                d = self.bins[name][2]
                rc, doc, raw = _run(self.bins, name, self.led, [d + "trusted-pubkey", self.pk])
                self.assertEqual(rc, 1, (name, extra, raw[-400:]))
                self.assertIn(want, list(_strings(doc)) if doc is not None else [], (name, extra, raw[-600:]))


class TestTreeHeadAndHeadAreClosed(unittest.TestCase):
    """§22 rule 2: a tree head or a HEAD with a member outside its list is `sth_unknown_member:<keys>` /
    `head_unknown_member:<keys>`, and the archive is not ok."""

    def setUp(self):
        self.d = tempfile.mkdtemp()
        w = I.Ingestor(self.d, batch_size=1)
        for i in range(3):
            w.append({"i": i})
        w.seal()
        w.append({"i": 3})
        w.close()
        self.sth = os.path.join(self.d, "ledger-000000.jsonl.sth.json")
        self.head = os.path.join(self.d, "ledger.head.json")

    def tearDown(self):
        shutil.rmtree(self.d, ignore_errors=True)

    def _edit(self, path, fn):
        with open(path, encoding="utf-8") as f:
            doc = json.load(f)
        fn(doc)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(doc, f)

    def test_intact_archive_control(self):
        self.assertTrue(I.verify_archive(self.d)["ok"])

    def test_an_older_tree_head_without_signed_control(self):
        # tree heads written before 2026-09-14 had no `signed` member: a subset of the list still verifies
        def drop(doc):
            doc.pop("signed")
        # the chain of tree heads and the HEAD commit to canonical hashes: rewritten as the writer of that day did
        last = None
        for seg in sorted(f for f in os.listdir(self.d) if f.endswith(".sth.json")):
            p = os.path.join(self.d, seg)
            self._edit(p, drop)
            if last is not None:
                self._edit(p, lambda s: s.__setitem__("prev_sth_sha256", last))
            with open(p, encoding="utf-8") as f:
                last = I._sth_canonical_hash(json.load(f))
        self._edit(self.head, lambda h: h.__setitem__("last_sth_sha256", last))
        r = I.verify_archive(self.d)
        self.assertTrue(r["ok"], r["failures"])

    def test_unknown_member_in_tree_head(self):
        rng = random.Random(7)
        for k in ["zz_unknown", "", "Signature", "\U0001f600"] + [_random_key(rng) for _ in range(10)]:
            if k in I.STH_MEMBERS:
                continue
            self.setUp()
            self._edit(self.sth, lambda doc: doc.__setitem__(k, 1))
            r = I.verify_archive(self.d)
            self.assertFalse(r["ok"])
            self.assertIn("sth_unknown_member:" + k[:120], [f["reason"] for f in r["failures"]], (k, r["failures"]))
            shutil.rmtree(self.d, ignore_errors=True)

    def test_unknown_member_in_head(self):
        for k in ["zz_unknown", "", "Prefix", "\U0001f600"]:
            self.setUp()
            self._edit(self.head, lambda doc: doc.__setitem__(k, [1]))
            r = I.verify_archive(self.d)
            self.assertFalse(r["ok"])
            self.assertIn("head_unknown_member:" + k, [f["reason"] for f in r["failures"]], (k, r["failures"]))
            shutil.rmtree(self.d, ignore_errors=True)

    def test_two_unknown_members_in_code_point_order(self):
        self._edit(self.head, lambda doc: doc.update({"\U0001f600": 1, "￿": 2, "b": 3}))
        r = I.verify_archive(self.d)
        self.assertIn("head_unknown_member:b,￿,\U0001f600", [f["reason"] for f in r["failures"]])


def _sign_raw(keyfile, msg):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    with open(keyfile, encoding="utf-8") as f:
        sk = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(f.read().strip()))
    import base64
    return base64.b64encode(sk.sign(msg)).decode()


@unittest.skipUnless(HAVE_CRYPTO, "needs `cryptography` (the `sign` extra)")
class TestSignatureDomains(unittest.TestCase):
    """§22 rule 3: tree heads, HEADs and pack manifests are signed over a domain-tagged message; documents signed over the
    bare hash (until 0.27.0) verify as before, named, and are refused on request."""

    def setUp(self):
        from cryptovalid_kms import FileKeyBackend
        self.d = tempfile.mkdtemp()
        self.key = os.path.join(self.d, "k.key")
        self.pk = signer.keygen(self.key)["public_key_hex"]
        self.arch = os.path.join(self.d, "arch")
        w = I.Ingestor(self.arch, batch_size=1, backend=FileKeyBackend(self.key))
        for i in range(3):
            w.append({"i": i})
        w.close()
        self.sth = os.path.join(self.arch, "ledger-000000.jsonl.sth.json")
        self.head = os.path.join(self.arch, "ledger.head.json")

    def tearDown(self):
        shutil.rmtree(self.d, ignore_errors=True)

    def _load(self, p):
        with open(p, encoding="utf-8") as f:
            return json.load(f)

    def _dump(self, p, doc):
        with open(p, "w", encoding="utf-8") as f:
            json.dump(doc, f)

    def test_written_tagged_and_verified(self):
        sth, head = self._load(self.sth), self._load(self.head)
        self.assertEqual((sth["sig_domain"], head["sig_domain"]), ("cryptovalid-sth/2", "cryptovalid-head/2"))
        r = I.verify_archive(self.arch, expected_pubkey_hex=self.pk, require_signature_domain=True)
        self.assertTrue(r["ok"], r["failures"])
        self.assertFalse(any(w.startswith("untagged_signatures") for w in r["warnings"]))

    def test_the_signature_is_not_over_the_bare_hash(self):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        import base64
        for p, tag in ((self.sth, "cryptovalid-sth/2"), (self.head, "cryptovalid-head/2")):
            doc = self._load(p)
            pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(self.pk))
            h = I._sth_canonical_hash(doc)
            sig = base64.b64decode(doc["signature"])
            pub.verify(sig, (tag + ":" + h).encode())
            with self.assertRaises(Exception):   # the message of an entry signature (64 hex) is never signed here
                pub.verify(sig, h.encode())

    def _retag_v1(self):
        """Rewrite the archive as the writer of 0.27.0 did: no sig_domain, signature over the bare hex."""
        last = None
        for seg in sorted(f for f in os.listdir(self.arch) if f.endswith(".sth.json")):
            p = os.path.join(self.arch, seg)
            doc = self._load(p)
            doc.pop("sig_domain")
            if last is not None:
                doc["prev_sth_sha256"] = last
            doc["signature"] = _sign_raw(self.key, I._sth_canonical_hash(doc).encode())
            self._dump(p, doc)
            last = I._sth_canonical_hash(doc)
        head = self._load(self.head)
        head.pop("sig_domain")
        head["last_sth_sha256"] = last
        head["signature"] = _sign_raw(self.key, I._sth_canonical_hash(head).encode())
        self._dump(self.head, head)

    def test_an_archive_of_0_27_0_verifies_and_is_named(self):
        self._retag_v1()
        r = I.verify_archive(self.arch, expected_pubkey_hex=self.pk)
        self.assertTrue(r["ok"], r["failures"])
        self.assertTrue(any(w.startswith("untagged_signatures") and "HEAD" in w for w in r["warnings"]), r["warnings"])

    def test_required_domain_refuses_the_old_signatures(self):
        self._retag_v1()
        r = I.verify_archive(self.arch, expected_pubkey_hex=self.pk, require_signature_domain=True)
        self.assertFalse(r["ok"])
        reasons = {f["reason"] for f in r["failures"]}
        self.assertIn("sth_signature_domain_untagged", reasons)
        self.assertIn("head_signature_domain_untagged", reasons)

    def test_a_tag_of_another_kind_fails(self):
        for other, name in (("cryptovalid-head/2", "sth"), ("cryptovalid-sth/2", "head")):
            self.tearDown()
            self.setUp()
            p = self.sth if name == "sth" else self.head
            doc = self._load(p)
            doc["sig_domain"] = other
            doc["signature"] = _sign_raw(self.key, (other + ":" + I._sth_canonical_hash(doc)).encode())
            self._dump(p, doc)
            r = I.verify_archive(self.arch, expected_pubkey_hex=self.pk)
            reasons = {f["reason"] for f in r["failures"]}
            self.assertIn(name + "_signature_domain_mismatch", reasons)
            self.assertIn(name + "_signature_invalid", reasons)

    def test_the_tag_removed_from_a_tagged_document_fails(self):
        doc = self._load(self.sth)
        doc.pop("sig_domain")   # the signature stays the tagged one: over the bare hash it does not verify
        self._dump(self.sth, doc)
        r = I.verify_archive(self.arch, expected_pubkey_hex=self.pk)
        self.assertIn("sth_signature_invalid", {f["reason"] for f in r["failures"]})

    def _pack(self, sign=True):
        import evidence_pack as EP
        led = os.path.join(self.d, "p.jsonl")
        _ledger(led, 3)
        out = os.path.join(self.d, "pack")
        EP.build_pack([led], out, sign_key=self.key if sign else None)
        return EP, out

    def test_pack_format_1_2_and_tagged_manifest_signature(self):
        EP, out = self._pack()
        man = self._load(os.path.join(out, "MANIFEST.json"))
        self.assertEqual(man["pack_format"], "cryptovalid-evidence-pack/1.2")
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        import base64
        pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(self.pk))
        pub.verify(base64.b64decode(man["manifest_signature"]),
                   ("cryptovalid-pack-manifest/2:" + man["manifest_digest_sha256"]).encode())
        r = EP.verify_pack(out, manifest_signer_hex=self.pk, require_signature_domain=True)
        self.assertTrue(r["valid"], r)
        self.assertEqual(r["states"]["producer_signature"]["state"], "verified")

    def _as_1_1(self, out, tagged=False):
        """The pack as 0.27.0 wrote it: format 1.1, the manifest signed over the bare digest (or, wrongly, tagged)."""
        import evidence_pack as EP
        p = os.path.join(out, "MANIFEST.json")
        man = self._load(p)
        man["pack_format"] = "cryptovalid-evidence-pack/1.1"
        body = {k: v for k, v in man.items() if k not in ("manifest_digest_sha256", "rfc3161_timestamp", "manifest_signature",
                                                         "manifest_signer")}
        man["manifest_digest_sha256"] = hashlib.sha256(EP._canon(body)).hexdigest()
        msg = ("cryptovalid-pack-manifest/2:" if tagged else "") + man["manifest_digest_sha256"]
        man["manifest_signature"] = _sign_raw(self.key, msg.encode())
        self._dump(p, man)

    def test_a_pack_of_format_1_1_verifies_as_before_control(self):
        EP, out = self._pack()
        self._as_1_1(out)
        r = EP.verify_pack(out, manifest_signer_hex=self.pk)
        self.assertTrue(r["valid"], r)
        self.assertEqual(r["states"]["producer_signature"]["state"], "verified")

    def test_required_domain_refuses_format_1_1(self):
        EP, out = self._pack()
        self._as_1_1(out)
        r = EP.verify_pack(out, manifest_signer_hex=self.pk, require_signature_domain=True)
        self.assertEqual((r["admission"], r["refusal_class"], r["valid"]), ("refused", "format_unsupported", False))

    def test_the_message_follows_the_format(self):
        EP, out = self._pack()
        self._as_1_1(out, tagged=True)   # 1.1 with the tagged message: not the message of 1.1
        r = EP.verify_pack(out, manifest_signer_hex=self.pk)
        self.assertFalse(r["valid"])
        self.assertEqual(r["states"]["producer_signature"]["state"], "contradicted")
        EP, out2 = self._pack()
        p = os.path.join(out2, "MANIFEST.json")
        man = self._load(p)   # 1.2 with the bare digest signed: not the message of 1.2
        man["manifest_signature"] = _sign_raw(self.key, man["manifest_digest_sha256"].encode())
        self._dump(p, man)
        r = EP.verify_pack(out2, manifest_signer_hex=self.pk)
        self.assertFalse(r["valid"])
        self.assertEqual(r["states"]["producer_signature"]["state"], "contradicted")


@unittest.skipUnless(HAVE_CRYPTO, "needs `cryptography` (the `sign` extra)")
class TestMcpVerifyLedgerSignatures(unittest.TestCase):
    """§22 rule 5: the MCP tool verify_ledger verifies the entry signatures against a pinned key passed as an argument;
    without it, the answer says that the signatures were not verified."""

    def setUp(self):
        import cryptovalid_mcp as M
        self.M = M
        self.d = tempfile.mkdtemp()
        self.key = os.path.join(self.d, "k.key")
        self.pk = signer.keygen(self.key)["public_key_hex"]
        self.other = signer.keygen(os.path.join(self.d, "o.key"))["public_key_hex"]
        self.plain = os.path.join(self.d, "plain.jsonl")
        _ledger(self.plain, 4)
        self.signed = os.path.join(self.d, "signed.jsonl")
        signer.sign_ledger(self.plain, self.signed, self.key)

    def tearDown(self):
        shutil.rmtree(self.d, ignore_errors=True)

    def call(self, args):
        r = self.M.handle({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "verify_ledger", "arguments": args}})
        return json.loads(r["result"]["content"][0]["text"]) if "result" in r else r

    def test_pinned_key_verifies(self):
        out = self.call({"path": self.signed, "expected_pubkey_hex": self.pk})
        self.assertTrue(out["valid"], out)
        self.assertTrue(out["signatures"]["checked"])
        self.assertEqual(out["signatures"]["verified"], 4)

    def test_other_key_fails(self):
        out = self.call({"path": self.signed, "expected_pubkey_hex": self.other})
        self.assertFalse(out["valid"])
        self.assertEqual({f["reason"] for f in out["signatures"]["failures"]}, {"signer_mismatch"})
        self.assertEqual(out["result"]["verdict"], "PASS")   # the chain itself holds: the signatures are what fails

    def test_a_forged_signature_fails(self):
        lines = open(self.signed, encoding="utf-8").read().splitlines()
        e = json.loads(lines[2])
        e["signature"] = e["signature"][:10] + ("A" if e["signature"][10] != "A" else "B") + e["signature"][11:]
        lines[2] = json.dumps(e)
        with open(self.signed, "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")
        out = self.call({"path": self.signed, "expected_pubkey_hex": self.pk})
        self.assertFalse(out["valid"])
        self.assertEqual(out["result"]["verdict"], "PASS")

    def test_unsigned_ledger_with_a_pin_is_not_valid(self):
        out = self.call({"path": self.plain, "expected_pubkey_hex": self.pk})
        self.assertFalse(out["valid"], out)

    def test_without_key_says_not_checked(self):
        out = self.call({"path": self.signed})
        self.assertIs(out["signatures"]["checked"], False)
        self.assertIn("NOT verified", out["signatures"]["note"])
        self.assertNotIn("valid", out)
        self.assertEqual(out["result"]["verdict"], "PASS")

    def test_malformed_key_is_an_error_control(self):
        for k in ["", "AB" * 32, self.pk[:-1], self.pk + "0", " " + self.pk[1:], "\u0661" * 64]:
            out = self.call({"path": self.signed, "expected_pubkey_hex": k})
            self.assertIn("error", out, (k, out))
            self.assertNotIn("valid", out)


@unittest.skipUnless(HAVE_CRYPTO, "needs `cryptography` (the `sign` extra)")
class TestPackPinsDecideValid(unittest.TestCase):
    """§22 rule 4: with a pin given (manifest_signer_hex, signer_pubkey_hex), `valid` is false when the pinned element
    is not verified. Every combination of manifest signer x ledger signer x pins, against an oracle written from the rule."""

    @classmethod
    def setUpClass(cls):
        import evidence_pack as EP
        cls.EP = EP
        cls.d = tempfile.mkdtemp()
        cls.k = {n: os.path.join(cls.d, n + ".key") for n in ("k1", "k2")}
        cls.pk = {n: signer.keygen(p)["public_key_hex"] for n, p in cls.k.items()}
        plain = os.path.join(cls.d, "plain.jsonl")
        _ledger(plain, 3)
        cls.led = {None: plain}
        for n in ("k1", "k2"):
            cls.led[n] = os.path.join(cls.d, f"signed_{n}.jsonl")
            signer.sign_ledger(plain, cls.led[n], cls.k[n])
        cls.packs = {}
        for man in (None, "k1", "k2"):
            for led in (None, "k1", "k2"):
                out = os.path.join(cls.d, f"pack_{man}_{led}")
                EP.build_pack([cls.led[led]], out, sign_key=cls.k[man] if man else None)
                cls.packs[(man, led)] = out

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.d, ignore_errors=True)

    @staticmethod
    def oracle(man, led, man_pin, led_pin):
        if led_pin and led != led_pin:
            return False          # pinned signer: unsigned or another key (another key was already false before the rule)
        if man_pin and man != man_pin:
            return False          # pinned manifest signer: unsigned or another key
        return True

    def test_every_combination(self):
        n = 0
        for (man, led), out in self.packs.items():
            for man_pin in (None, "k1"):
                for led_pin in (None, "k1"):
                    r = self.EP.verify_pack(out, manifest_signer_hex=self.pk[man_pin] if man_pin else None,
                                            signer_pubkey_hex=self.pk[led_pin] if led_pin else None)
                    want = self.oracle(man, led, man_pin, led_pin)
                    self.assertEqual(r["valid"], want, (man, led, man_pin, led_pin, r["states"]))
                    if want is False and r["admission"] == "admitted":
                        # the reason is in the states: never a not-valid pack whose states say nothing
                        self.assertNotEqual(r["states"]["producer_signature"]["state"], "verified", (man, led, man_pin, led_pin))
                    n += 1
        self.assertEqual(n, 36)

    def test_the_three_findings(self):
        r = self.EP.verify_pack(self.packs[(None, None)], signer_pubkey_hex=self.pk["k1"])
        self.assertEqual((r["valid"], r["ledgers"][0]["sig_pass"], r["ledgers"][0].get("pq_reason")),
                         (False, False, "unsigned_but_signer_pinned"))
        r = self.EP.verify_pack(self.packs[(None, "k1")], manifest_signer_hex=self.pk["k1"])
        self.assertFalse(r["valid"])
        self.assertEqual(r["states"]["producer_signature"]["reasons"][0], "not_present")
        r = self.EP.verify_pack(self.packs[("k2", "k1")], manifest_signer_hex=self.pk["k1"])
        self.assertFalse(r["valid"])
        self.assertIn("key_unresolved", r["states"]["producer_signature"]["reasons"])

    def test_without_pins_nothing_changes_control(self):
        for out in self.packs.values():
            r = self.EP.verify_pack(out)
            self.assertTrue(r["valid"], r["states"])


_TSL = "http://uri.etsi.org/02231/v2#"
_QTST_SVC = ('<TrustServiceProviderList><TrustServiceProvider><TSPServices><TSPService><ServiceInformation>'
             '<ServiceTypeIdentifier>http://uri.etsi.org/TrstSvc/Svctype/TSA/QTST</ServiceTypeIdentifier>'
             '<ServiceStatus>http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted</ServiceStatus>'
             '<StatusStartingTime>2017-03-01T00:00:00Z</StatusStartingTime><ServiceDigitalIdentity><DigitalId>'
             '<X509Certificate>{c}</X509Certificate></DigitalId></ServiceDigitalIdentity></ServiceInformation></TSPService>'
             '</TSPServices></TrustServiceProvider></TrustServiceProviderList>')


def _b64(b):
    import base64
    return base64.b64encode(b).decode()


def _pointer(loc, cert_der, lotl=False):
    typ = "EUlistofthelists" if lotl else "EUgeneric"
    return (f"<OtherTSLPointer><ServiceDigitalIdentities><ServiceDigitalIdentity><DigitalId><X509Certificate>{_b64(cert_der)}"
            f"</X509Certificate></DigitalId></ServiceDigitalIdentity></ServiceDigitalIdentities><TSLLocation>{loc}</TSLLocation>"
            f"<AdditionalInformation><OtherInformation><TSLType>http://uri.etsi.org/TrstSvc/TrustedList/TSLType/{typ}</TSLType>"
            "</OtherInformation><OtherInformation><a:MimeType>application/vnd.etsi.tsl+xml</a:MimeType></OtherInformation>"
            "</AdditionalInformation></OtherTSLPointer>")


def _lotl(uris, pointers):
    return (f'<TrustServiceStatusList xmlns="{_TSL}" xmlns:a="http://uri.etsi.org/02231/v2/additionaltypes#"><SchemeInformation>'
            "<SchemeInformationURI>" + "".join(f'<URI xml:lang="en">{u}</URI>' for u in uris) + "</SchemeInformationURI>"
            "<PointersToOtherTSL>" + "".join(pointers) + "</PointersToOtherTSL></SchemeInformation></TrustServiceStatusList>").encode()


@unittest.skipUnless(HAVE_CRYPTO, "needs `cryptography` (the `sign` extra)")
class TestTrustedListsSigned(unittest.TestCase):
    """§22 rule 6: the LOTL under the OJ certificates (through the pivots), each list under its pointer's certificates,
    https only, the signature read closed, the content read without the signature."""

    @classmethod
    def setUpClass(cls):
        import cryptovalid_lotl as L
        from test_lotl import make_signer, sign_list
        cls.L, cls.sign = L, staticmethod(sign_list)
        cls.oj = make_signer(name="oj")
        cls.piv = make_signer("rsa", name="pivot")
        cls.tl = make_signer(name="tl")
        cls.qtst = b"QTST-CERT-DER"
        cls.tl_url = "https://tl.example/a.xml"
        cls.list_xml = (f'<TrustServiceStatusList xmlns="{_TSL}">' + _QTST_SVC.format(c=_b64(cls.qtst))
                        + "</TrustServiceStatusList>").encode()

    def _load(self, lotl, tl, anchors=None, http=False):
        L = self.L
        url = self.tl_url.replace("https:", "http:") if http else self.tl_url
        fetched, log = [], []

        def get(u, timeout=45):
            fetched.append(u)
            if u == L.LOTL_URL:
                return lotl
            if u == url:
                return tl
            raise OSError("not found " + u)
        orig = L._get
        L._get = get
        try:
            if isinstance(lotl, bytes) and url != self.tl_url:
                lotl = lotl.replace(self.tl_url.encode(), url.encode())
            fprs, cov, _e = L.load_qualified_status(log=log.append, trusted_lotl_signers=anchors)
        finally:
            L._get = orig
        return fprs, cov, log, fetched

    def _good(self, anchors_key=None):
        k, der, fp = anchors_key or self.oj
        lotl = self.sign(_lotl([self.L.OJ_LOTL_URL], [_pointer(self.tl_url, self.tl[1])]), k, der)
        return lotl, self.sign(self.list_xml, self.tl[0], self.tl[1]), fp

    def test_signed_lists_count(self):
        lotl, tl, fp = self._good()
        fprs, cov, _log, _f = self._load(lotl, tl, {fp})
        self.assertEqual(fprs, {hashlib.sha256(self.qtst).hexdigest()})
        self.assertEqual(cov, [self.tl_url])

    def test_unsigned_lotl_is_refused(self):
        with self.assertRaises(ValueError) as c:
            self._load(_lotl([self.L.OJ_LOTL_URL], [_pointer(self.tl_url, self.tl[1])]), self.list_xml, {self.oj[2]})
        self.assertIn("xmldsig_missing", str(c.exception))

    def test_lotl_under_another_certificate_is_refused(self):
        lotl, tl, _fp = self._good(self.tl)
        with self.assertRaises(ValueError) as c:
            self._load(lotl, tl, {self.oj[2]})
        self.assertIn("xmldsig_untrusted_signer", str(c.exception))

    def test_default_trust_is_the_official_journal(self):
        lotl, tl, _fp = self._good()
        with self.assertRaises(ValueError) as c:   # a LOTL signed by a key of ours is not one the OJ names
            self._load(lotl, tl, None)
        self.assertIn("xmldsig_untrusted_signer", str(c.exception))
        self.assertEqual(len(self.L.OJ_LOTL_SIGNERS_SHA256), 6)
        unnamed = self.sign(_lotl(["https://eur-lex.europa.eu/eli/C/2019/276/oj"], []), self.oj[0], self.oj[1])
        with self.assertRaises(ValueError) as c:
            self.L.lotl_signers(unnamed)
        self.assertIn("lotl_oj_unknown", str(c.exception))

    def test_unsigned_tampered_or_foreign_list_is_not_covered(self):
        lotl, tl, fp = self._good()
        other = __import__("test_lotl").make_signer(name="other")
        cases = {"unsigned": self.list_xml,
                 "tampered": tl.replace(b"Svcstatus/granted", b"Svcstatus/grantee"),
                 "foreign signer": self.sign(self.list_xml, other[0], other[1])}
        for name, x in cases.items():
            fprs, cov, log, _f = self._load(lotl, x, {fp})
            self.assertEqual((fprs, cov), (set(), []), name)
            self.assertTrue(any("TL skip" in m and "xmldsig_" in m for m in log), (name, log))

    def test_http_list_is_not_fetched(self):
        lotl, tl, fp = self._good()
        lotl = self.sign(_lotl([self.L.OJ_LOTL_URL], [_pointer(self.tl_url.replace("https:", "http:"), self.tl[1])]),
                         self.oj[0], self.oj[1])
        fprs, cov, log, fetched = self._load(lotl, tl, {fp}, http=True)
        self.assertEqual((fprs, cov), (set(), []))
        self.assertEqual(fetched, [self.L.LOTL_URL])
        self.assertTrue(any("served over http" in m for m in log), log)

    def test_a_service_inside_the_signature_object_is_not_read(self):
        lotl, _tl, fp = self._good()
        inj = (f'<ds:Object xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><Wrap xmlns="{_TSL}">'
               + _QTST_SVC.format(c=_b64(b"INJECTED")) + "</Wrap></ds:Object>")
        tl = self.sign(self.list_xml, self.tl[0], self.tl[1], edit=lambda p: p.__setitem__("objects", inj))
        fprs, cov, _log, _f = self._load(lotl, tl, {fp})
        self.assertEqual(cov, [self.tl_url])   # the signature verifies: the Object is outside what is signed
        self.assertEqual(fprs, {hashlib.sha256(self.qtst).hexdigest()})   # and what is outside is not read

    def test_pivot_chain(self):
        L = self.L
        pk, pder, pfp = self.piv
        pivot_url = "https://ec.europa.eu/tools/lotl/eu-lotl-pivot-999.xml"
        pivot = self.sign(_lotl([L.OJ_LOTL_URL], [_pointer(L.LOTL_URL, pder, lotl=True)]), self.oj[0], self.oj[1])
        lotl = self.sign(_lotl([pivot_url, L.OJ_LOTL_URL], [_pointer(L.LOTL_URL, pder, lotl=True)]), pk, pder, alg="rsa-pss-sha256")
        got = L.lotl_signers(lotl, get=lambda u, t: pivot, anchors={self.oj[2]})
        self.assertEqual(got, {pfp})
        L.verify_list_signature(lotl, got)
        # the pivot signed by a key the OJ does not name: refused
        bad_pivot = self.sign(_lotl([L.OJ_LOTL_URL], [_pointer(L.LOTL_URL, pder, lotl=True)]), pk, pder)
        with self.assertRaises(ValueError):
            L.lotl_signers(lotl, get=lambda u, t: bad_pivot, anchors={self.oj[2]})
        # after a pivot the OJ key alone no longer signs the LOTL
        old = self.sign(_lotl([pivot_url, L.OJ_LOTL_URL], []), self.oj[0], self.oj[1])
        with self.assertRaises(ValueError):
            L.verify_list_signature(old, L.lotl_signers(old, get=lambda u, t: pivot, anchors={self.oj[2]}))

    def test_closed_shape(self):
        L = self.L
        k, der, fp = self.tl
        exc = "http://www.w3.org/2001/10/xml-exc-c14n#"
        edits = {
            "inclusive c14n": lambda p: p.__setitem__("c14n", "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"),
            "sha1 signature": lambda p: p.__setitem__("sig_uri", "http://www.w3.org/2000/09/xmldsig#rsa-sha1"),
            "no enveloped transform": lambda p: p.__setitem__("doc_transforms", f'<ds:Transform Algorithm="{exc}"/>'),
            "transforms reversed": lambda p: p.__setitem__("doc_transforms", p["doc_transforms"].split("/>")[1] + "/>"
                                                           + p["doc_transforms"].split("/>")[0] + "/>"),
            "InclusiveNamespaces": lambda p: p.__setitem__("sp_transforms", f'<ds:Transform Algorithm="{exc}"><ec:InclusiveNamespaces '
                                                           f'xmlns:ec="{exc}" PrefixList="ds"/></ds:Transform>'),
            "third reference": lambda p: p.__setitem__("extra_refs", '<ds:Reference URI="#sp-1"><ds:Transforms/><ds:DigestMethod '
                                                       'Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue>AA==</ds:DigestValue></ds:Reference>'),
            "SignedProperties named elsewhere": lambda p: p.__setitem__("sp_uri", "#elsewhere"),
            "two certificates": lambda p: p.__setitem__("keyinfo", p["keyinfo"].replace("</ds:X509Data>", "<ds:X509Certificate>"
                                                        + _b64(b"x") + "</ds:X509Certificate></ds:X509Data>")),
            "signing certificate of another": lambda p: p.__setitem__("sp", p["sp"].replace(
                "<ds:DigestValue>", "<ds:DigestValue>AAAA", 1)),
            "duplicate identifier": lambda p: p.__setitem__("objects", '<ds:Object Id="sp-1"/>'),
            "bad doc digest": lambda p: p.__setitem__("doc_digest", _b64(b"\0" * 32)),
            "bad SignedProperties digest": lambda p: p.__setitem__("sp_digest", _b64(b"\0" * 32)),
        }
        good = self.sign(self.list_xml, k, der)
        L.verify_list_signature(good, {fp})   # control
        for name, e in edits.items():
            x = self.sign(self.list_xml, k, der, edit=e)
            with self.assertRaises(ValueError, msg=name) as c:
                L.verify_list_signature(x, {fp})
            self.assertTrue(str(c.exception).startswith("xmldsig_"), (name, str(c.exception)))
        from datetime import datetime, timezone
        with self.assertRaises(ValueError) as c:   # the signing certificate is valid 30 days from today
            L.verify_list_signature(good, {fp}, at=datetime(2099, 1, 1, tzinfo=timezone.utc))
        self.assertTrue(str(c.exception).startswith("xmldsig_certificate_not_valid"))
        stale = self.sign(self.list_xml.replace(b"<TrustServiceProviderList>", b"<SchemeInformation><NextUpdate><dateTime>"
                                                b"2000-01-01T00:00:00Z</dateTime></NextUpdate></SchemeInformation>"
                                                b"<TrustServiceProviderList>"), k, der)
        with self.assertRaises(ValueError) as c:
            L.verify_list_signature(stale, {fp})
        self.assertTrue(str(c.exception).startswith("tl_next_update_passed"))
        fresh = self.sign(self.list_xml.replace(b"<TrustServiceProviderList>", b"<SchemeInformation><NextUpdate><dateTime>"
                                                b"2099-01-01T00:00:00Z</dateTime></NextUpdate></SchemeInformation>"
                                                b"<TrustServiceProviderList>"), k, der)
        L.verify_list_signature(fresh, {fp})   # control
        moved = good.replace(b"<TrustServiceProviderList>", b"<TrustServiceProviderList>" + good[good.index(b"<ds:Signature"):
                                                                                                   good.index(b"</ds:Signature>") + 15], 1)
        with self.assertRaises(ValueError):   # two signatures, or one that is not a child of the root
            L.verify_list_signature(moved, {fp})

    def test_canonicalization_against_lxml(self):
        try:
            import lxml.etree as LE
        except ImportError:
            self.skipTest("lxml is not installed here (it is an oracle of this test only, not a dependency)")
        docs = ['<a xmlns="urn:x" xmlns:p="urn:p"><b xmlns=""><p:c p:x="1" y="&#10;2"/></b><?pi d?></a>',
                '<p:a xmlns:p="urn:p" xmlns:q="urn:p"><q:b xml:lang="it">t&amp;&#13;</q:b><!-- c --></p:a>',
                '<a xmlns:t="urn:t" xmlns="urn:t"><t:b/><b attr="\t"/></a>']
        for d in docs:
            root, before, after = self.L._xml_tree(d.encode())
            lx = LE.fromstring(d.encode())
            mine = [self.L.exc_c14n(root)] + [self.L.exc_c14n(x) for x in list(self.L._all_nodes(root))[1:]]
            theirs = [LE.tostring(lx, method="c14n", exclusive=True, with_comments=False)] + \
                     [LE.tostring(x, method="c14n", exclusive=True, with_comments=False) for x in lx.iter() if isinstance(x.tag, str)][1:]
            self.assertEqual(mine, theirs, d)


if __name__ == "__main__":
    unittest.main()
