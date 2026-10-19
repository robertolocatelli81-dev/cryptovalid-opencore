# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Roberto Locatelli
"""0.22.0 — the evidence pack receipt of SPEC §10 (admission, states) and the two limits 0.21.0 declared for this release:
a claimed RFC 3161 token that does not verify left the pack valid; the manifest signature and the ingest's tree heads took
Ed25519 keys of small order. One test per cell of the table of §10 and per refusal rule. Each test that is not about a new
field fails on 0.21.0 (measured 19/10/2026 on `git archive 5b422a5b:opencore` with this file copied in); a test about a new
field fails there because the field is absent. The generative bench (verifiers/pack_states_bench.py) runs at the end."""
import base64
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import evidence_pack as EP  # noqa: E402
import signer  # noqa: E402

SAMPLE = os.path.join(HERE, "examples", "sample_ledger.jsonl")
IDENT = bytes([1]) + bytes(31)                            # the neutral point: a key of small order
FORGED = base64.b64encode(IDENT + bytes(32)).decode()     # R neutral, S = 0: `cryptography` accepts it for ANY message under IDENT
EX_IOERR = 74


def _crypto():
    try:
        import cryptography  # noqa: F401
        return True
    except ImportError:
        if os.environ.get("CV_REQUIRE_CRYPTO") == "1":
            raise
        return False


def _mldsa():
    try:
        from cryptography.hazmat.primitives.asymmetric import mldsa  # noqa: F401
        return True
    except ImportError:
        return False


def _ap2():
    try:
        import ap2_evidence  # noqa: F401
        return True
    except ImportError:
        return False


class _Pack(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp(prefix="cv0220_")

    def tearDown(self):
        shutil.rmtree(self.d, True)

    def build(self, ledger=SAMPLE, **kw):
        p = os.path.join(self.d, "pack")
        shutil.rmtree(p, True)
        EP.build_pack([ledger], p, subject="t", **kw)
        return p

    def man(self, p, fn=None, redigest=False, text=None):
        mp = os.path.join(p, "MANIFEST.json")
        if text is not None:
            with open(mp, "w", encoding="utf-8") as f:
                f.write(text)
            return None
        with open(mp, encoding="utf-8") as f:
            m = json.load(f)
        if fn:
            fn(m)
            if redigest:
                import hashlib
                m2 = {k: v for k, v in m.items() if k not in ("manifest_digest_sha256", "rfc3161_timestamp", "manifest_signature",
                                                             "manifest_signer")}
                m["manifest_digest_sha256"] = hashlib.sha256(json.dumps(m2, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
            with open(mp, "w", encoding="utf-8") as f:
                json.dump(m, f, ensure_ascii=False, indent=1, sort_keys=True)
        return m

    def st(self, r, subject):
        return (r["states"][subject]["state"], r["states"][subject]["reasons"])

    def signed_ledger(self, pq=False):
        k = os.path.join(self.d, "k")
        pub = signer.keygen(k)["public_key_hex"]
        out = os.path.join(self.d, "signed.jsonl")
        kw = {}
        if pq:
            kw["pq_keyfile"] = k + ".pq"
            pqpub = signer.keygen_pq(k + ".pq")["public_key_b64"]
        import contextlib
        import io
        with contextlib.redirect_stdout(io.StringIO()):
            signer.sign_ledger(SAMPLE, out, k, **kw)
        return (out, k, pub, pqpub) if pq else (out, k, pub)


class TestAdmission(_Pack):
    def test_clean_pack_is_admitted_with_three_subjects(self):
        r = EP.verify_pack(self.build())
        self.assertEqual((r["admission"], r["refusal_class"], r["states_vocabulary"]),
                         ("admitted", None, "cryptovalid-evidence-pack/states-1"))
        self.assertEqual(set(r["states"]), {"sealed_content", "producer_signature", "time_anchor"})
        self.assertEqual(self.st(r, "sealed_content"), ("verified", []))
        self.assertEqual(self.st(r, "producer_signature"), ("not_evaluated", ["not_present"]))
        self.assertEqual(self.st(r, "time_anchor"), ("not_evaluated", ["not_present"]))
        self.assertTrue(r["valid"])

    def test_format_unsupported(self):
        for fmt in ("cryptovalid-evidence-pack/1.0", "cryptovalid-evidence-pack/1.2", "x", 1.1, None, "DELETE"):
            with self.subTest(fmt=fmt):
                p = self.build()
                self.man(p, lambda m: m.pop("pack_format") if fmt == "DELETE" else m.update(pack_format=fmt), redigest=True)
                r = EP.verify_pack(p)
                self.assertEqual((r["admission"], r["refusal_class"], r["states"], r["valid"]),
                                 ("refused", "format_unsupported", None, False), r)

    def test_a_later_revision_with_a_new_member_is_format_unsupported(self):
        # NEMESIS 19/10/2026: the format is read before the members (as ap2-evidence-pack 1.6.0) — a revision that adds a
        # member is format_unsupported, not unknown_member; with 1.1 the same member stays unknown_member
        for fmt, cls in (("cryptovalid-evidence-pack/1.2", "format_unsupported"), ("cryptovalid-evidence-pack/1.1", "unknown_member")):
            for where in ("top", "ledger", "rfc3161"):
                with self.subTest(fmt=fmt, where=where):
                    p = self.build()
                    tgt = {"top": lambda m: m, "ledger": lambda m: m["ledgers"][0], "rfc3161": lambda m: m["rfc3161_timestamp"]}[where]
                    self.man(p, lambda m: (m.update(pack_format=fmt), tgt(m).update(x_new_in_a_later_revision=1)), redigest=True)
                    r = EP.verify_pack(p)
                    self.assertEqual((r["admission"], r["refusal_class"], r["states"], r["valid"]), ("refused", cls, None, False), r)

    def test_unknown_member(self):
        for where in ("top", "ledger", "rfc3161"):
            with self.subTest(where=where):
                p = self.build()
                tgt = {"top": lambda m: m, "ledger": lambda m: m["ledgers"][0], "rfc3161": lambda m: m["rfc3161_timestamp"]}[where]
                self.man(p, lambda m: tgt(m).update(x_unknown=1), redigest=True)
                r = EP.verify_pack(p)
                self.assertEqual((r["admission"], r["refusal_class"], r["valid"]), ("refused", "unknown_member", False))
                self.assertTrue(r["error"].startswith("manifest_unknown_field: "), r["error"])

    def test_malformed_types(self):
        cases = {"rfc3161_timestamp is a list": lambda m: m.update(rfc3161_timestamp=[]),
                 "anchored is a string": lambda m: m.update(rfc3161_timestamp={"anchored": "yes", "tsr_b64": "AAAA"}),
                 "anchored missing": lambda m: m.update(rfc3161_timestamp={"note": "x"}),
                 "tsr_b64 a number": lambda m: m.update(rfc3161_timestamp={"anchored": True, "tsr_b64": 1}),
                 "tsr_b64 without anchored true": lambda m: m.update(rfc3161_timestamp={"anchored": False, "tsr_b64": "AAAA"}),
                 "manifest_signature a list": lambda m: m.update(manifest_signature=[], manifest_signer="ab" * 32),
                 "manifest_digest a number": lambda m: m.update(manifest_digest_sha256=1),
                 "entries a boolean": lambda m: m["ledgers"][0].update(entries=True),
                 "entries a float": lambda m: m["ledgers"][0].update(entries=3.0),
                 "head a number": lambda m: m["ledgers"][0].update(head_self_hash=1),
                 "pq_protected a string": lambda m: m["ledgers"][0].update(pq_protected="true"),
                 "ledgers a boolean": lambda m: m.update(ledgers=True)}
        for name, fn in cases.items():
            with self.subTest(case=name):
                p = self.build()
                self.man(p, fn)
                r = EP.verify_pack(p)
                self.assertEqual((r["admission"], r["refusal_class"], r["states"], r["valid"]), ("refused", "malformed", None, False), r)

    def test_duplicate_key_is_malformed(self):
        p = self.build()
        with open(os.path.join(p, "MANIFEST.json"), encoding="utf-8") as f:
            text = f.read()
        self.man(p, text=text.replace('"subject":', '"subject": "first",\n "subject":', 1))
        r = EP.verify_pack(p)
        self.assertEqual((r["admission"], r["refusal_class"]), ("refused", "malformed"))
        self.assertTrue(r["error"].startswith("manifest_duplicate_key: "), r["error"])

    def test_cli_refusal_exit_1_one_receipt(self):
        p = self.build()
        self.man(p, lambda m: m.update(rfc3161_timestamp=[]))
        r = subprocess.run([sys.executable, "-B", os.path.join(HERE, "evidence_pack.py"), "verify", p], capture_output=True, text=True)
        self.assertEqual(r.returncode, 1, r.stderr)
        self.assertNotIn("Traceback", r.stderr)
        self.assertEqual(json.loads(r.stdout)["refusal_class"], "malformed")


class TestSealedContent(_Pack):
    def test_file_changed_is_digest_mismatch(self):
        p = self.build()
        with open(os.path.join(p, "sample_ledger.jsonl"), "a") as f:
            f.write("\n")
        r = EP.verify_pack(p)
        self.assertEqual(self.st(r, "sealed_content"), ("contradicted", ["digest_mismatch"]))
        self.assertFalse(r["valid"])

    def test_manifest_digest_is_digest_mismatch(self):
        p = self.build()
        self.man(p, lambda m: m.update(subject="changed"))
        r = EP.verify_pack(p)
        self.assertEqual(self.st(r, "sealed_content"), ("contradicted", ["digest_mismatch"]))

    def test_no_file_listed(self):
        p = self.build()
        self.man(p, lambda m: m.update(file_digests_sha256={}), redigest=True)
        r = EP.verify_pack(p)
        self.assertEqual(r["states"]["sealed_content"]["state"], "contradicted")
        self.assertIn("no file listed", r["states"]["sealed_content"]["detail"])

    def test_ledger_missing_is_artifact_invalid(self):
        p = self.build()
        os.unlink(os.path.join(p, "sample_ledger.jsonl"))
        r = EP.verify_pack(p)
        self.assertEqual(self.st(r, "sealed_content"), ("contradicted", ["digest_mismatch", "artifact_invalid"]))

    def test_chain_broken_is_artifact_invalid(self):
        rows = [json.loads(x) for x in open(SAMPLE) if x.strip()]
        rows[1]["data"] = {"changed": True}
        led = os.path.join(self.d, "broken.jsonl")
        with open(led, "w") as f:
            f.write("".join(json.dumps(x) + "\n" for x in rows))
        r = EP.verify_pack(self.build(led))
        self.assertEqual(self.st(r, "sealed_content"), ("contradicted", ["artifact_invalid"]))
        self.assertFalse(r["valid"])

    def test_truncation_is_binding_mismatch(self):
        p = self.build()
        self.man(p, lambda m: m["ledgers"][0].update(entries=2), redigest=True)
        r = EP.verify_pack(p)
        self.assertEqual(self.st(r, "sealed_content"), ("contradicted", ["binding_mismatch"]))
        self.assertFalse(r["valid"])


@unittest.skipUnless(_crypto(), "requires 'cryptography'")
class TestProducerSignature(_Pack):
    def test_self_asserted_and_verified_and_key_unresolved(self):
        led, k, pub = self.signed_ledger()
        p = self.build(led, sign_key=k)
        r = EP.verify_pack(p)
        self.assertEqual(self.st(r, "producer_signature"), ("not_evaluated", ["self_asserted", "self_asserted"]))
        self.assertTrue(r["valid"])
        r = EP.verify_pack(p, signer_pubkey_hex=pub, manifest_signer_hex=pub)
        self.assertEqual(self.st(r, "producer_signature"), ("verified", []))
        self.assertTrue(r["valid"])
        r = EP.verify_pack(p, signer_pubkey_hex="ab" * 32)      # a ledger pinned to another key: not valid, not tampered
        self.assertEqual(self.st(r, "producer_signature"), ("not_evaluated", ["self_asserted", "key_unresolved"]))
        self.assertFalse(r["valid"])
        r = EP.verify_pack(p, manifest_signer_hex="ab" * 32)    # the manifest pin does not decide valid (SPEC §10)
        self.assertEqual(self.st(r, "producer_signature"), ("not_evaluated", ["key_unresolved", "self_asserted"]))
        self.assertTrue(r["valid"])

    def test_manifest_signature_broken_is_signature_invalid(self):
        led, k, pub = self.signed_ledger()
        p = self.build(led, sign_key=k)
        self.man(p, lambda m: m.update(manifest_signature=base64.b64encode(bytes(64)).decode()))
        r = EP.verify_pack(p)
        self.assertEqual(r["states"]["producer_signature"]["state"], "contradicted")
        self.assertFalse(r["valid"])

    def test_manifest_signed_by_a_small_order_key(self):
        # 0.21.0: manifest_authenticated true and valid true — the neutral point with R neutral and S = 0 verifies any digest
        p = self.build()
        self.man(p, lambda m: m.update(manifest_signer=IDENT.hex(), manifest_signature=FORGED))
        r = EP.verify_pack(p)
        self.assertFalse(r["manifest_authenticated"])
        self.assertFalse(r["valid"])
        self.assertEqual(self.st(r, "producer_signature"), ("contradicted", ["signature_invalid"]))
        self.assertIn("small_order_key", r["states"]["producer_signature"]["detail"])

    def test_manifest_signature_fields_read_strictly(self):
        led, k, pub = self.signed_ledger()
        for name, fn in (("signer upper case", lambda m: m.update(manifest_signer=m["manifest_signer"].upper())),
                         ("signature with a space", lambda m: m.update(manifest_signature=" " + m["manifest_signature"]))):
            with self.subTest(case=name):
                p = self.build(led, sign_key=k)
                self.man(p, fn)
                r = EP.verify_pack(p)
                self.assertFalse(r["manifest_authenticated"])
                self.assertEqual(r["states"]["producer_signature"]["state"], "contradicted")

    def test_layer_opened_by_any_entry(self):
        # SPEC §5 step 5; 0.21.0 opened the layer only when entry 0 carried `signature`: valid true here
        rows = [json.loads(x) for x in open(SAMPLE) if x.strip()]
        rows[1]["signature"], rows[1]["signer"] = base64.b64encode(bytes(64)).decode(), "11" * 32
        led = os.path.join(self.d, "partial.jsonl")
        with open(led, "w") as f:
            f.write("".join(json.dumps(x) + "\n" for x in rows))
        r = EP.verify_pack(self.build(led))
        self.assertEqual(self.st(r, "producer_signature"), ("contradicted", ["signature_invalid"]))
        self.assertFalse(r["valid"])
        self.assertFalse(r["ledgers"][0]["sig_pass"])

    def test_layer_opened_by_each_signature_field(self):
        # NEMESIS 19/10/2026: each of the four fields of SPEC §5 step 5 opens the layer on its own (a mutant that read only
        # `signature` survived the suite): an entry that carries only `signer`, `signature_pq` or `signer_pq` is a signed
        # ledger whose Ed25519 signature is missing — signature_invalid, not valid
        rows = [json.loads(x) for x in open(SAMPLE) if x.strip()]
        for field, val in (("signer", "11" * 32), ("signature_pq", "AAAA"), ("signer_pq", "AAAA"), ("signature", "AAAA")):
            with self.subTest(field=field):
                rr = [dict(x) for x in rows]
                rr[1][field] = val
                led = os.path.join(self.d, f"only_{field}.jsonl")
                with open(led, "w") as f:
                    f.write("".join(json.dumps(x) + "\n" for x in rr))
                r = EP.verify_pack(self.build(led))
                self.assertEqual(self.st(r, "producer_signature")[0], "contradicted", r["states"])
                self.assertFalse(r["valid"])

    def test_claimed_post_quantum_layer_absent(self):
        # the manifest (unsigned, digest recomputed) claims a layer the file does not carry: 0.21.0 valid true, pq_absent
        led, k, pub = self.signed_ledger()
        p = self.build(led)
        self.man(p, lambda m: m["ledgers"][0].update(pq_protected=True), redigest=True)
        r = EP.verify_pack(p)
        self.assertEqual(r["ledgers"][0]["pq_reason"], "pq_absent")
        self.assertEqual(self.st(r, "producer_signature"), ("contradicted", ["self_asserted", "signature_invalid"]))
        self.assertFalse(r["valid"])

    @unittest.skipUnless(_mldsa(), "ML-DSA-65 needs cryptography >= 50")
    def test_hybrid_pinned_verified_unpinned_self_asserted(self):
        led, k, pub, pqpub = self.signed_ledger(pq=True)
        p = self.build(led, sign_key=k, pq_pubkey_b64=pqpub, signer_pubkey_hex=pub)
        r = EP.verify_pack(p, pq_pubkey_b64=pqpub, signer_pubkey_hex=pub, manifest_signer_hex=pub)
        self.assertEqual(self.st(r, "producer_signature"), ("verified", []))
        r = EP.verify_pack(p)
        self.assertEqual(self.st(r, "producer_signature"), ("not_evaluated", ["self_asserted", "self_asserted", "self_asserted"]))
        self.assertTrue(r["valid"])

    def test_backend_missing(self):
        led, k, pub = self.signed_ledger()
        p = self.build(led, sign_key=k)
        with mock.patch.dict(sys.modules, {"cryptography.hazmat.primitives.asymmetric.ed25519": None}), \
                mock.patch.object(signer, "_ed", side_effect=RuntimeError("the signature layer requires 'cryptography'")):
            r = EP.verify_pack(p)
        self.assertEqual(self.st(r, "producer_signature"), ("not_evaluated", ["backend_missing", "backend_missing"]))
        self.assertFalse(r["valid"])   # as 0.21.0 for the signed manifest (fail-closed); the ledger was a traceback there

    def test_backend_missing_on_a_signed_ledger_alone_is_not_valid(self):
        # NEMESIS 19/10/2026: with the manifest unsigned, the ledger's own layer decides — a mutant that left sig_pass true
        # when the layer cannot be checked survived the suite (the signed manifest above already made the pack not valid)
        led, k, pub = self.signed_ledger()
        p = self.build(led)
        with mock.patch.object(signer, "_ed", side_effect=RuntimeError("the signature layer requires 'cryptography'")):
            r = EP.verify_pack(p)
        self.assertEqual(self.st(r, "producer_signature"), ("not_evaluated", ["backend_missing"]))
        self.assertFalse(r["ledgers"][0]["sig_pass"])
        self.assertFalse(r["valid"])


class TestTimeAnchor(_Pack):
    def test_token_missing(self):
        p = self.build()
        self.man(p, lambda m: m.update(rfc3161_timestamp={"anchored": True, "tsa": "x"}))
        r = EP.verify_pack(p)
        self.assertEqual(self.st(r, "time_anchor"), ("contradicted", ["token_missing"]))
        self.assertFalse(r["valid"])

    @unittest.skipUnless(shutil.which("openssl"), "openssl absent")
    def test_token_invalid_is_not_valid_exit_1(self):
        # the limit 0.21.0 declared for this release: `valid: true`, exit 0 on a claimed token that is not a TimeStampResp
        p = self.build()
        self.man(p, lambda m: m.update(rfc3161_timestamp={"anchored": True, "tsa": "x", "tsr_b64": "AAAA"}))
        r = subprocess.run([sys.executable, "-B", os.path.join(HERE, "evidence_pack.py"), "verify", p], capture_output=True, text=True)
        self.assertEqual(r.returncode, 1, r.stderr)
        out = json.loads(r.stdout)
        self.assertEqual((out["valid"], out["rfc3161"]["claimed"], out["rfc3161"]["verified"]), (False, True, False))
        self.assertEqual(self.st(out, "time_anchor"), ("contradicted", ["token_invalid"]))
        self.assertNotIn("imprint_read", out["rfc3161"])   # internal field, not in the receipt (NEMESIS 19/10/2026: a mutant survived)

    def test_empty_token_is_token_invalid(self):
        # NEMESIS 19/10/2026: `tsr_b64: ""` with `anchored: true` is a claimed token that is read and refuted, not a claim
        # without a token and not "not checked" (a mutant reading `ts.get("tsr_b64")` made it instrument_failure, valid)
        if not shutil.which("openssl"):
            self.skipTest("openssl absent")
        p = self.build()
        self.man(p, lambda m: m.update(rfc3161_timestamp={"anchored": True, "tsa": "x", "tsr_b64": ""}))
        r = EP.verify_pack(p)
        self.assertEqual((self.st(r, "time_anchor"), r["valid"]), (("contradicted", ["token_invalid"]), False))

    def test_openssl_absent_is_instrument_failure(self):
        p = self.build()
        self.man(p, lambda m: m.update(rfc3161_timestamp={"anchored": True, "tsa": "x", "tsr_b64": "AAAA"}))
        with mock.patch.object(EP.shutil, "which", return_value=None):
            r = EP.verify_pack(p)
        self.assertEqual(self.st(r, "time_anchor"), ("not_evaluated", ["instrument_failure"]))
        self.assertTrue(r["valid"])   # an absent tool is not a failed run (SPEC §10)


@unittest.skipUnless(shutil.which("openssl") and _crypto(), "openssl and cryptography needed for a local TSA")
class TestTimeAnchorRealTokens(_Pack):
    @classmethod
    def setUpClass(cls):
        sys.path.insert(0, os.path.join(HERE, "verifiers"))
        import pack_states_bench as B
        cls.td = tempfile.mkdtemp(prefix="cv0220_tsa_")
        cls.tsa = B.LocalTsa(cls.td)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.td, True)

    def test_token_of_this_digest_is_tsa_not_checked(self):
        p = self.build()
        self.man(p, lambda m: m.update(rfc3161_timestamp={"anchored": True, "tsa": "l", "tsr_b64": self.tsa.token(m["manifest_digest_sha256"])}))
        r = EP.verify_pack(p)
        self.assertEqual(self.st(r, "time_anchor"), ("not_evaluated", ["tsa_not_checked"]))
        self.assertTrue(r["valid"])

    def test_token_of_another_digest_is_binding_mismatch(self):
        p = self.build()
        self.man(p, lambda m: m.update(rfc3161_timestamp={"anchored": True, "tsa": "l", "tsr_b64": self.tsa.token("00" * 32)}))
        r = EP.verify_pack(p)
        self.assertEqual(self.st(r, "time_anchor"), ("contradicted", ["binding_mismatch"]))
        self.assertFalse(r["valid"])


@unittest.skipUnless(_crypto(), "requires 'cryptography'")
class TestIngestSmallOrder(unittest.TestCase):
    def test_tree_heads_signed_by_the_neutral_point(self):
        # 0.21.0: ok true (also with that key pinned), no `unsigned_archive` warning
        import glob
        import cryptovalid_ingest as ing
        d = tempfile.mkdtemp(prefix="cv0220_ing_")
        try:
            w = ing.Ingestor(d, batch_size=8)
            for i in range(20):
                w.append({"i": i})
            w.seal()
            w.close(seal=False)
            for p in sorted(glob.glob(os.path.join(d, "*.sth.json"))) + [os.path.join(d, "ledger.head.json")]:
                with open(p) as f:
                    doc = json.load(f)
                doc["signer"], doc["signature"] = IDENT.hex(), FORGED
                with open(p, "w") as f:
                    json.dump(doc, f)
            for pin in (None, IDENT.hex()):
                r = ing.verify_archive(d, expected_pubkey_hex=pin)
                self.assertFalse(r["ok"])
                self.assertIn("sth_signature_invalid", [x["reason"] for x in r["failures"]])
                self.assertIn("head_signature_invalid", [x["reason"] for x in r["failures"]])
        finally:
            shutil.rmtree(d, True)


class TestIngestTreeHeadTypes(unittest.TestCase):
    def test_a_tree_head_signer_of_any_json_type_is_named_never_a_traceback(self):
        # NEMESIS 19/10/2026: an STH `signer` that is a list or an object was a TypeError traceback (0.21.0 and the 0.22.0
        # draft: `signers.add`), and an int next to a string broke `sorted(signers)`
        import glob
        import cryptovalid_ingest as ing
        for vals in ((["a"],), ({"a": 1},), (1, "b" * 64), (None, True)):
            with self.subTest(vals=vals):
                d = tempfile.mkdtemp(prefix="cv0220_ingt_")
                try:
                    w = ing.Ingestor(d, batch_size=4)
                    for i in range(12):
                        w.append({"i": i})
                        if i % 6 == 5:
                            w.seal()   # two sealed segments: two tree heads
                    w.close(seal=False)
                    sths = sorted(glob.glob(os.path.join(d, "*.sth.json")))
                    self.assertGreaterEqual(len(sths), len(vals))
                    for p, v in zip(sths, vals):
                        with open(p) as f:
                            doc = json.load(f)
                        doc["signer"], doc["signature"] = v, "AAAA"
                        with open(p, "w") as f:
                            json.dump(doc, f)
                    r = ing.verify_archive(d)
                    self.assertFalse(r["ok"])
                    self.assertIn("sth_signature_invalid", [x["reason"] for x in r["failures"]])
                    self.assertTrue(all(isinstance(s, str) for s in r["signers"]), r["signers"])
                finally:
                    shutil.rmtree(d, True)


def _ed_sign_mixed(a, A_enc, msg, r):
    """a genuine Ed25519 signature by scalar a published under A_enc (which may be a·B + T: a key of mixed order)"""
    import hashlib
    from ed25519_order import L, decode, encode, scalar_mul
    B = decode(bytes.fromhex("58" + "66" * 31))
    Re = encode(scalar_mul(r, B))
    k = int.from_bytes(hashlib.sha512(Re + A_enc + msg).digest(), "little") % L
    return Re + ((r + k * a) % L).to_bytes(32, "little")


def _mixed_key(a, t_enc):
    from ed25519_order import add, decode, encode, scalar_mul
    return encode(add(scalar_mul(a, decode(bytes.fromhex("58" + "66" * 31))), decode(t_enc)))


class TestReceiptSmallOrder(unittest.TestCase):
    """NEMESIS 19/10/2026: cryptovalid_receipt (JSON `cryptovalid_sth/1` and the COSE receipts, formats of this project)
    verified Ed25519 with the library's rule: the neutral point with R neutral and S = 0 was `signature_valid: true` for
    any tree head and `ok: true` for any COSE receipt under that key."""

    def _sth(self, pub_hex, sig):
        return {"kind": "cryptovalid_sth/1", "tree_size": 3, "root_sha256": "ab" * 32, "ts": "2026-10-19T00:00:00+00:00",
                "log_pubkey_hex": pub_hex, "signature_hex": sig.hex()}

    def test_neutral_point_tree_head(self):
        import cryptovalid_receipt as R
        sth = self._sth(IDENT.hex(), IDENT + bytes(32))
        for pin in (None, IDENT.hex()):
            v = R.verify_sth(sth, pin)
            self.assertEqual((v["ok"], v.get("signature_valid")), (False, False), v)
            self.assertIn("small_order_key", v["why"])

    def test_mixed_order_key_tree_head(self):
        import cryptovalid_receipt as R
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        A = _mixed_key(987654321, bytes.fromhex("ec" + "ff" * 30 + "7f"))   # torsion part of order 2
        sth = self._sth(A.hex(), b"")
        msg = R._sth_payload(3, "ab" * 32, sth["ts"])
        for r in range(1, 200):   # a signature the library accepts: [k]T = 0 for half of the nonces
            sig = _ed_sign_mixed(987654321, A, msg, r)
            try:
                Ed25519PublicKey.from_public_bytes(A).verify(sig, msg)
                break
            except Exception:  # noqa: BLE001
                continue
        else:
            self.fail("no accepted signature found")
        sth["signature_hex"] = sig.hex()
        v = R.verify_sth(sth, A.hex())
        self.assertEqual((v["ok"], v.get("signature_valid")), (False, False), v)
        self.assertIn("mixed_order_key", v["why"])

    def test_neutral_point_cose_receipt(self):
        import cryptovalid_receipt as R
        d = tempfile.mkdtemp(prefix="cv0220_rcpt_")
        try:
            k = os.path.join(d, "k")
            pub = signer.keygen(k)["public_key_hex"]
            r = R.inclusion_receipt(SAMPLE, 1, k)
            cose = R.to_cose(r, k)
            self.assertTrue(R.verify_cose(cose, pub, leaf_hash_hex=r["leaf_sha256"])["ok"])   # control: the real receipt
            prot, unprot, payload, _ = R.cbor_decode(cose[1:])
            ph = R.cbor_decode(prot)
            ph[4] = IDENT
            forged = b"\xd2" + R.cbor_encode([R.cbor_encode(ph), unprot, payload, IDENT + bytes(32)])
            v = R.verify_cose(forged, IDENT.hex(), leaf_hash_hex=r["leaf_sha256"])
            self.assertFalse(v["ok"], v)
            self.assertIn("small_order_key", v["why"])
        finally:
            shutil.rmtree(d, True)


class TestIngestSignatureRead(unittest.TestCase):
    def test_tree_head_signature_checked_and_signer_read_strictly(self):
        # NEMESIS 19/10/2026: a genuine signature passes; the same signer in capitals, or one byte of S changed, is
        # sth_signature_invalid (mutants that dropped the hex rule or the verify call itself survived the suite: the
        # suite's tamper changed R, which the order rule refuses first)
        import glob
        import hashlib
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        import cryptovalid_ingest as ing
        sk = Ed25519PrivateKey.generate()
        pub = sk.public_key().public_bytes_raw().hex()
        for case in ("genuine", "upper", "s_changed"):
            with self.subTest(case=case):
                d = tempfile.mkdtemp(prefix="cv0220_ings_")
                try:
                    w = ing.Ingestor(d, batch_size=8)
                    for i in range(8):
                        w.append({"i": i})
                    w.seal()
                    w.close(seal=False)
                    p = sorted(glob.glob(os.path.join(d, "*.sth.json")))[0]
                    with open(p) as f:
                        doc = json.load(f)
                    sig = bytearray(sk.sign(ing._sth_canonical_hash(doc).encode()))
                    if case == "s_changed":
                        sig[40] ^= 1
                    doc["signer"] = pub.upper() if case == "upper" else pub
                    doc["signature"] = base64.b64encode(bytes(sig)).decode()
                    with open(p, "w") as f:
                        json.dump(doc, f)
                    r = ing.verify_archive(d)
                    reasons = [x["reason"] for x in r["failures"]]
                    if case == "genuine":
                        self.assertNotIn("sth_signature_invalid", reasons, r)
                    else:
                        self.assertIn("sth_signature_invalid", reasons, r)
                finally:
                    shutil.rmtree(d, True)


class TestFrontEndCheckNotRun(_Pack):
    def test_pack_74_receipt_is_the_front_end_receipt(self):
        # NEMESIS 19/10/2026: the 74 receipt of `cryptovalid-verify pack` is the front-end's (layers + the reference's states),
        # not the reference's raw receipt; a CheckNotRun WITHOUT a receipt (e.g. the archive's token check) stays
        # `receipt not written`, stdout empty — two mutants survived the suite
        import io
        import verify_evidence as VE
        from verifier import CheckNotRun
        p = self.build()
        rec = EP.verify_pack(p)
        with mock.patch.object(EP, "verify_pack", side_effect=CheckNotRun("cannot run openssl here: test", receipt=rec)):
            with self.assertRaises(CheckNotRun) as cm:
                VE.verify_pack(p)
        self.assertIn("layers", cm.exception.receipt)
        self.assertEqual(cm.exception.receipt["states"], rec["states"])
        out, er = io.StringIO(), io.StringIO()
        with mock.patch.object(VE, "verify_archive", side_effect=CheckNotRun("cannot run openssl here: test")), \
                mock.patch.object(sys, "stdout", out), mock.patch.object(sys, "stderr", er):
            rc = VE.main(["archive", self.d])
        self.assertEqual(rc, EX_IOERR)
        self.assertEqual(out.getvalue(), "")


class TestFrontEnd(_Pack):
    def test_pack_copies_admission_and_states(self):
        sys.path.insert(0, HERE)
        import verify_evidence as VE
        p = self.build()
        self.man(p, lambda m: m.update(rfc3161_timestamp={"anchored": True, "tsa": "x"}))
        r = VE.verify_pack(p)
        ref = EP.verify_pack(p)
        for k in ("admission", "refusal_class", "states_vocabulary", "states"):
            self.assertEqual(r[k], ref[k], k)
        self.assertFalse(r["valid"])
        self.assertEqual([x["status"] for x in r["layers"] if x["layer"] == "RFC 3161 timestamp"], ["FAIL"])

    @unittest.skipUnless(_ap2(), "ap2-evidence-pack not installed (pip install 'cryptovalid-opencore[ap2]')")
    def test_ap2_copies_admission_states_policy_and_74_with_receipt(self):
        import ap2_evidence
        import verify_evidence as VE
        if not hasattr(ap2_evidence, "STATES_VOCABULARY"):
            self.skipTest("ap2-evidence-pack < 1.6.0")
        ev = os.path.join(self.d, "ev.json")
        r0 = ap2_evidence.verify_evidence(os.path.join(HERE, "examples", "sample_ledger.jsonl"))   # not an ap2 file: a refusal
        self.assertEqual(r0["admission"], "refused")
        r = VE.verify_ap2(os.path.join(HERE, "examples", "sample_ledger.jsonl"))
        for k in ("admission", "refusal_class", "states_vocabulary", "states", "policy"):
            self.assertEqual(r[k], r0[k], k)
        self.assertTrue(r["layers"][-1]["detail"].startswith(r0["refusal_class"] + ": "))
        # a check the reference could not run here: its COMPLETE receipt becomes this front-end's, exit 74
        with open(ev, "w") as f:
            json.dump({"x": 1}, f)
        err = ap2_evidence.Ap2WriteError("cannot run openssl here: test", receipt=r0)
        with mock.patch.object(ap2_evidence, "verify_evidence", side_effect=err):
            from verifier import CheckNotRun
            with self.assertRaises(CheckNotRun) as cm:
                VE.verify_ap2(ev)
            self.assertEqual(cm.exception.receipt["states_vocabulary"], r0["states_vocabulary"])
            import io
            out, er = io.StringIO(), io.StringIO()
            with mock.patch.object(sys, "stdout", out), mock.patch.object(sys, "stderr", er):
                rc = VE.main(["ap2", ev])
        self.assertEqual(rc, EX_IOERR)
        self.assertEqual(json.loads(out.getvalue())["admission"], "refused")
        self.assertTrue(er.getvalue().startswith("check not run here: cannot run openssl here: test"), er.getvalue())


class TestAp2LayerWithoutArtifacts(unittest.TestCase):
    def test_zero_artifacts_do_not_pass_the_signature_layer(self):
        # 0.21.0: all() of no artifact was True, so this layer said PASS (the reference's own layer still failed the pack)
        import verify_evidence as VE
        layers = VE._ap2_layers({"digest_ok": True, "artifacts": [], "bindings_ok": True, "valid": False})
        self.assertEqual([x["status"] for x in layers if x["layer"].startswith("firme ES256")], ["FAIL"])


class TestMcpKeepsTheReceipt(_Pack):
    def test_check_not_run_returns_the_complete_receipt(self):
        # 0.21.0: {"error": "CheckNotRun: ..."} only — the receipt the verifier had computed was dropped
        import cryptovalid_mcp as M
        from verifier import CheckNotRun
        p = self.build()
        rec = EP.verify_pack(p)
        with mock.patch.object(EP, "verify_pack", side_effect=CheckNotRun("cannot run openssl here: test", receipt=rec)):
            out = M.handle({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                            "params": {"name": "verify_pack", "arguments": {"pack_dir": p}}})
        res = out["result"]
        self.assertTrue(res["isError"])
        body = json.loads(res["content"][0]["text"])
        self.assertEqual(body["result"], rec)
        self.assertEqual(body["check_not_run"], "cannot run openssl here: test")


class TestGenerativeBench(unittest.TestCase):
    """The bench of SPEC §10 (C1–C5) on this tree: 0 violations; one sabotage must make it report violations."""

    def run_bench(self, *args):
        r = subprocess.run([sys.executable, "-B", os.path.join(HERE, "verifiers", "pack_states_bench.py"), *args],
                           capture_output=True, text=True, env=dict(os.environ, PYTHONPATH=""), timeout=1800)
        return r.returncode, json.loads(r.stdout.splitlines()[-1]), r.stderr

    def test_bench_clean_and_a_sabotage_turns_it_red(self):
        if not _crypto():
            self.skipTest("cryptography absent")
        rc, out, err = self.run_bench()
        self.assertEqual((rc, out["violations"]), (0, {}), err[-2000:])
        self.assertGreater(out["counts"]["refused"], 0)
        self.assertGreater(out["counts"]["admitted"], 0)
        rc, out, _ = self.run_bench("--sabotage", "precedence_reversed")
        self.assertEqual(rc, 1)
        self.assertGreater(out["violations"].get("C3", 0), 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
