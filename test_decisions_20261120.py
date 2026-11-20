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

    def test_the_nine_members_control(self):
        self.assertEqual(T.TIP_MEMBERS, {"kind", "entries", "ledger_id", "tip_sha256", "ts", "log_pubkey_hex", "signature_hex",
                                         "signature_pq_hex", "log_pq_pubkey_b64"})
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

    def test_an_archive_of_0_27_0_verifies_named_control(self):
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

    def test_without_key_says_not_checked_control(self):
        out = self.call({"path": self.signed})
        self.assertIs(out["signatures"]["checked"], False)
        self.assertIn("NOT verified", out["signatures"]["note"])
        self.assertNotIn("valid", out)
        self.assertEqual(out["result"]["verdict"], "PASS")

    def test_malformed_key_is_an_error(self):
        for k in ["", "AB" * 32, self.pk[:-1], self.pk + "0", " " + self.pk[1:], "\u0661" * 64]:
            out = self.call({"path": self.signed, "expected_pubkey_hex": k})
            self.assertIn("error", out, (k, out))
            self.assertNotIn("valid", out)


if __name__ == "__main__":
    unittest.main()
