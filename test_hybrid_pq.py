"""Hybrid Ed25519 + ML-DSA-65 (FIPS 204) signatures on entries, chain tip and evidence pack (0.12.0).

Rules under test: the post-quantum layer is `pq_protected` True ONLY when verified against the trusted key;
absent = False; present-but-unverifiable = None (never a pass); with a trusted PQ key a tip/ledger without a
valid ML-DSA-65 signature is a FAIL; a tampered PQ signature fails even when Ed25519 still verifies."""
import base64, hashlib, json, os, shutil, subprocess, sys, tempfile, unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import verifier as V
import cryptovalid_tip as T
try:
    import signer
    from cryptography.hazmat.primitives.asymmetric import mldsa  # noqa: F401
    HAVE_PQ = True
except Exception:  # noqa: BLE001
    HAVE_PQ = False

GO_BIN = os.environ.get("CVVERIFY_GO")
JAVA_CMD = os.environ.get("CVVERIFY_JAVA")   # e.g. "/path/jdk-27/bin/java -cp /tmp/cvj CvVerify" (JDK 24+ for ML-DSA)


def _canon(e):
    return json.dumps(e, sort_keys=True, separators=(",", ":")).encode()


def _ledger(n):
    out, prev = [], "0" * 64
    for i in range(n):
        e = {"idx": i, "ts": f"2026-09-15T07:00:{i:02d}Z", "data": {"i": i}, "prev_hash": prev}
        e["self_hash"] = hashlib.sha256(_canon(e)).hexdigest(); prev = e["self_hash"]; out.append(e)
    return out


def _write(path, entries):
    with open(path, "w") as f:
        for e in entries:
            f.write(json.dumps(e) + "\n")


@unittest.skipUnless(HAVE_PQ, "cryptography >= 50 (ML-DSA) assente")
class TestHybridEntries(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(); self.led = os.path.join(self.tmp, "l.jsonl"); _write(self.led, _ledger(5))
        self.k = os.path.join(self.tmp, "log.key"); kg = signer.keygen(self.k)
        self.pk = kg["public_key_hex"]; self.pq = signer.keygen_pq(self.k + ".pq"); self.pq_pk = self.pq["public_key_b64"]
        self.signed = os.path.join(self.tmp, "signed.jsonl")
        self.res = signer.sign_ledger(self.led, self.signed, self.k, pq_keyfile=self.k + ".pq")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_keygen_pq_is_0600_and_refuses_overwrite(self):
        self.assertEqual(oct(os.stat(self.k + ".pq").st_mode & 0o777), "0o600")
        with self.assertRaises(FileExistsError):
            signer.keygen_pq(self.k + ".pq")

    def test_hybrid_sign_and_verify(self):
        self.assertEqual(self.res["scheme"], "hybrid ed25519+ml-dsa-65")
        r = signer.verify_file(self.signed, self.pk, self.pq_pk)
        self.assertTrue(r["ok"]); self.assertIs(r["pq_protected"], True); self.assertEqual(r["pq_verified"], 5)
        self.assertEqual(r["pq_status"], "protected")
        # council 15/09: WITHOUT the expected key the layer is verified against the embedded key only → None, never True
        u = signer.verify_file(self.signed, self.pk)
        self.assertTrue(u["ok"]); self.assertIsNone(u["pq_protected"]); self.assertEqual(u["pq_status"], "unpinned")
        self.assertEqual(V.verify_ledger(self.signed)["verdict"], "PASS")      # hash verifier unaffected by ATTEST fields

    def test_ed25519_only_ledger_is_not_pq_protected(self):
        out = os.path.join(self.tmp, "ed.jsonl"); signer.sign_ledger(self.led, out, self.k)
        r = signer.verify_file(out, self.pk)
        self.assertTrue(r["ok"]); self.assertIs(r["pq_protected"], False); self.assertIn("not quantum-resistant", r["pq_note"])

    def test_tampered_pq_signature_fails_even_if_ed25519_holds(self):
        lines = open(self.signed).read().splitlines(); e = json.loads(lines[2])
        raw = bytearray(base64.b64decode(e["signature_pq"])); raw[10] ^= 0xFF
        e["signature_pq"] = base64.b64encode(bytes(raw)).decode(); lines[2] = json.dumps(e)
        open(self.signed, "w").write("\n".join(lines) + "\n")
        r = signer.verify_file(self.signed, self.pk, self.pq_pk)
        self.assertFalse(r["ok"]); self.assertIs(r["pq_protected"], False)
        self.assertEqual(r["pq_failures"], [{"idx": 2, "reason": "bad_pq_signature"}])

    def test_wrong_expected_pq_key(self):
        other = signer.keygen_pq(os.path.join(self.tmp, "o.pq"))["public_key_b64"]
        r = signer.verify_file(self.signed, self.pk, other)
        self.assertFalse(r["ok"]); self.assertEqual(r["pq_failures"][0]["reason"], "pq_signer_mismatch")

    def test_pq_layer_stripped_is_detected(self):
        # an attacker who removes the PQ signatures from a hybrid ledger leaves a VALID Ed25519 ledger: only the
        # relying party's expectation (--require-pq / expected key) catches it — pq_protected is False, not True
        lines = [json.loads(l) for l in open(self.signed)]
        for e in lines:
            e.pop("signature_pq"); e.pop("signer_pq")
        _write(self.signed, lines)
        # council 15/09 (Gemini, Opus): with the EXPECTED key given the layer is REQUIRED at library level: ok False
        r = signer.verify_file(self.signed, self.pk, self.pq_pk)
        self.assertFalse(r["ok"]); self.assertIs(r["pq_protected"], False); self.assertEqual(r["pq_status"], "missing")
        self.assertEqual(r["pq_failures"][0]["reason"], "pq_missing")
        self.assertTrue(signer.verify_file(self.signed, self.pk)["ok"])      # not required: a valid Ed25519 ledger
        with self.assertRaises(ValueError):                                  # round 2: library as strict as the CLI
            signer.verify_file(self.signed, self.pk, require_pq=True)
        with self.assertRaises(ValueError):                                  # PQ key without the Ed25519 key
            signer.verify_file(self.signed, None, self.pq_pk)
        here = os.path.dirname(os.path.abspath(__file__))
        cp = subprocess.run([sys.executable, "signer.py", "verify", self.signed, "--pubkey", self.pk, "--pq-pubkey", self.pq_pk, "--require-pq"],
                            capture_output=True, text=True, cwd=here)
        self.assertEqual(cp.returncode, 1)
        cp = subprocess.run([sys.executable, "signer.py", "verify", self.signed, "--pubkey", self.pk, "--require-pq"], capture_output=True, text=True, cwd=here)
        self.assertEqual(cp.returncode, 2)     # --require-pq without --pq-pubkey is refused (self-declared protection)

    def test_foreign_pq_key_added_to_ed25519_ledger_is_never_protected(self):
        # council 15/09 (Sonnet, Opus): an attacker ADDS their own ML-DSA layer to an Ed25519-only ledger
        ed = os.path.join(self.tmp, "ed.jsonl"); signer.sign_ledger(self.led, ed, self.k)
        forged = os.path.join(self.tmp, "forged.jsonl"); signer.sign_ledger(ed, forged, self.k, pq_keyfile=signer.keygen_pq(os.path.join(self.tmp, "att.pq")) and os.path.join(self.tmp, "att.pq"))
        r = signer.verify_file(forged, self.pk)                       # no expected PQ key: unpinned → None
        self.assertTrue(r["ok"]); self.assertIsNone(r["pq_protected"])
        r = signer.verify_file(forged, self.pk, self.pq_pk)           # the relying party's key: mismatch → FAIL
        self.assertFalse(r["ok"]); self.assertEqual(r["pq_failures"][0]["reason"], "pq_signer_mismatch")

    def test_ed25519_corrupted_with_valid_pq_is_not_protected(self):
        # council 15/09 (Sonnet): hybrid = BOTH hold; a broken classical signature must not leave pq_protected True
        lines = [json.loads(l) for l in open(self.signed)]
        raw = bytearray(base64.b64decode(lines[1]["signature"])); raw[3] ^= 1; lines[1]["signature"] = base64.b64encode(bytes(raw)).decode()
        _write(self.signed, lines)
        r = signer.verify_file(self.signed, self.pk, self.pq_pk)
        self.assertFalse(r["ok"]); self.assertIs(r["pq_protected"], False); self.assertEqual(r["pq_status"], "classical_broken")

    def test_empty_context_and_strict_decoding(self):
        # 0.13.0: EMPTY FIPS 204 context on purpose — the JDK (24-27, JEP 497) and AWS KMS RAW have no context API;
        # a plain verify(sig, msg) with no context must succeed, and a context MUST NOT be needed
        from cryptography.hazmat.primitives.asymmetric import mldsa
        sk, pk_b64 = signer.load_pq_key(self.k + ".pq")
        e = json.loads(open(self.signed).readline())
        sig = base64.b64decode(e["signature_pq"]); msg = e["self_hash"].encode()
        sk.public_key().verify(sig, msg)
        self.assertEqual(signer.PQ_CTX_ENTRY, b"")
        with self.assertRaises(Exception):                            # a context would make it another domain: not ours
            sk.public_key().verify(sig, msg, context=b"cryptovalid/entry/1")
        self.assertEqual(len(sig), signer.PQ_SIG_LEN); self.assertEqual(len(base64.b64decode(pk_b64)), signer.PQ_PK_LEN)
        lines = [json.loads(l) for l in open(self.signed)]
        lines[0]["signature_pq"] = lines[0]["signature_pq"][:10] + " " + lines[0]["signature_pq"][10:]   # Python's lenient decoder took this
        _write(self.signed, lines)
        r = signer.verify_file(self.signed, self.pk, self.pq_pk)
        self.assertFalse(r["ok"]); self.assertEqual(r["pq_failures"][0]["reason"], "malformed_pq_field")

    def test_required_but_unverifiable_is_not_ok_at_library_level(self):
        # council 16/09 round 2: with the pinned key and no ML-DSA library `ok` was True (pq_failures empty)
        real = signer._mldsa
        signer._mldsa = lambda: None
        try:
            r = signer.verify_file(self.signed, self.pk, self.pq_pk)
        finally:
            signer._mldsa = real
        self.assertFalse(r["ok"]); self.assertIsNone(r["pq_protected"]); self.assertEqual(r["pq_status"], "unverifiable")
        u = signer.verify_file(self.signed, self.pk)                          # not required: None, ok stays True
        self.assertTrue(u["ok"])

    def test_malformed_ed25519_fields_are_refused_strictly(self):
        lines = [json.loads(l) for l in open(self.signed)]
        lines[0]["signer"] = lines[0]["signer"].upper(); _write(self.signed, lines)
        r = signer.verify_file(self.signed)
        self.assertFalse(r["ok"]); self.assertEqual(r["failures"][0]["reason"], "malformed_signature_field")

    def test_resign_without_pq_key_strips_stale_pq_fields(self):
        out = os.path.join(self.tmp, "re.jsonl"); signer.sign_ledger(self.signed, out, self.k)
        e = json.loads(open(out).readline())
        self.assertNotIn("signature_pq", e); self.assertNotIn("signer_pq", e)

    def test_kms_mldsa_backend_with_stub_client(self):
        # AwsKmsMlDsaBackend shape (GetPublicKey DER SPKI → raw 1952; Sign RAW ML_DSA_SHAKE_256 → 3309 bytes),
        # exercised with a stub client backed by a local key: the live round-trip against AWS KMS is separate
        import cryptovalid_kms as K
        from cryptography.hazmat.primitives import serialization as ser
        sk, pk_b64 = signer.load_pq_key(self.k + ".pq")
        spki = sk.public_key().public_bytes(ser.Encoding.DER, ser.PublicFormat.SubjectPublicKeyInfo)
        self.assertIn(K.MLDSA65_SPKI_OID, spki[:32]); self.assertEqual(spki[-1952:], base64.b64decode(pk_b64))
        calls = []
        class Stub:
            def get_public_key(self, KeyId): return {"PublicKey": spki, "KeyId": "arn:aws:kms:eu-central-1:1:key/x"}
            def sign(self, KeyId, Message, MessageType, SigningAlgorithm):
                calls.append((MessageType, SigningAlgorithm)); return {"Signature": sk.sign(Message), "KeyId": "arn:aws:kms:eu-central-1:1:key/x", "SigningAlgorithm": "ML_DSA_SHAKE_256"}
        be = K.AwsKmsMlDsaBackend("alias/x", client=Stub())
        self.assertEqual(be.public_key_b64, pk_b64)
        out = os.path.join(self.tmp, "kms.jsonl")
        r = signer.sign_ledger(self.led, out, self.k, pq_backend=be)
        self.assertEqual(r["pq_backend"]["key_in_process_memory"], False); self.assertEqual(set(calls), {("RAW", "ML_DSA_SHAKE_256")})
        v = signer.verify_file(out, self.pk, pk_b64); self.assertTrue(v["ok"]); self.assertIs(v["pq_protected"], True)
        tip = T.sign_tip(self.led, self.k, pq_backend=be)
        self.assertEqual(tip["log_pq_pubkey_b64"], pk_b64)
        self.assertEqual(V.verify_ledger(self.led, trusted_pubkey_hex=self.pk, trusted_pq_pubkey_b64=pk_b64)["verdict"], "PASS")
        with self.assertRaises(RuntimeError):
            K._mldsa65_raw_from_spki(b"\x30\x0a" + b"\x00" * 2000)         # not an ML-DSA-65 SPKI
        with self.assertRaises(RuntimeError):
            K._mldsa65_raw_from_spki(spki + b"\x00")                         # round 4: exact length, unused-bits byte
        # round 4 (Fable): a KMS alias re-pointed between GetPublicKey and Sign → the Sign KeyId differs → refused
        class Repointed(Stub):
            def sign(self, KeyId, Message, MessageType, SigningAlgorithm):
                return {"Signature": sk.sign(Message), "KeyId": "arn:aws:kms:eu-central-1:1:key/OTHER", "SigningAlgorithm": "ML_DSA_SHAKE_256"}
        with self.assertRaises(RuntimeError):
            K.AwsKmsMlDsaBackend("alias/x", client=Repointed()).sign(b"m")
        # and a backend that signs with a key other than the declared one is caught by the tip's self-verify
        other_sk, _ = signer.load_pq_key(signer.keygen_pq(os.path.join(self.tmp, "o2.pq")) and os.path.join(self.tmp, "o2.pq"))
        class WrongKey:
            public_key_b64 = pk_b64
            def sign(self, m): return other_sk.sign(m)
        with self.assertRaises(Exception):
            T.sign_tip(self.led, self.k, pq_backend=WrongKey())
        with self.assertRaises(ValueError):                                   # backend AND keyfile together
            signer.sign_ledger(self.led, out, self.k, pq_keyfile=self.k + ".pq", pq_backend=be)

    def test_cli_keygen_pq_sign_verify(self):
        d = os.path.join(self.tmp, "cli"); os.makedirs(d); kf = os.path.join(d, "k")
        here = os.path.dirname(os.path.abspath(__file__))
        kg = json.loads(subprocess.check_output([sys.executable, "signer.py", "keygen", kf, "--pq"], cwd=here))
        self.assertTrue(os.path.exists(kf + ".pq")); pq_pk = kg["pq"]["public_key_b64"]
        out = os.path.join(d, "s.jsonl")
        subprocess.check_output([sys.executable, "signer.py", "sign", self.led, out, kf, "--pq-key", kf + ".pq"], cwd=here)
        cp = subprocess.run([sys.executable, "signer.py", "verify", out, "--pubkey", kg["public_key_hex"], "--pq-pubkey", pq_pk, "--require-pq"],
                            capture_output=True, text=True, cwd=here)
        self.assertEqual(cp.returncode, 0, cp.stdout + cp.stderr)
        self.assertIs(json.loads(cp.stdout)["pq_protected"], True)


@unittest.skipUnless(HAVE_PQ and GO_BIN and os.path.exists(GO_BIN or ""), "needs ML-DSA and the Go verifier binary (CVVERIFY_GO)")
class TestGoEntrySignaturesAgreeWithPython(unittest.TestCase):
    """0.13.0: the Go verifier checks per-entry Ed25519 + ML-DSA-65 with the SAME tri-state as signer.py — a
    mini-oracle over the cases the council named (valid, stripped, tampered, foreign key, broken Ed25519, malformed)."""
    def setUp(self):
        self.tmp = tempfile.mkdtemp(); self.led = os.path.join(self.tmp, "l.jsonl"); _write(self.led, _ledger(4))
        self.k = os.path.join(self.tmp, "k"); self.pk = signer.keygen(self.k)["public_key_hex"]; self.pq_pk = signer.keygen_pq(self.k + ".pq")["public_key_b64"]
        self.signed = os.path.join(self.tmp, "s.jsonl"); signer.sign_ledger(self.led, self.signed, self.k, pq_keyfile=self.k + ".pq")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _go(self, path, *flags):
        cp = subprocess.run([GO_BIN, *flags, path], capture_output=True, text=True)
        return cp.returncode, json.loads(cp.stdout)

    def _both(self, path, ed, pq):
        py = signer.verify_file(path, ed, pq)
        flags = [*(["-pubkey", ed] if ed else []), *(["-pq-pubkey", pq] if pq else [])]
        rc, go = self._go(path, *flags)
        g = go["signatures"]
        self.assertEqual((py["ok"], py["pq_protected"], py["pq_status"]), (g["ok"], g["pq_protected"], g["pq_status"]), (path, py, g))
        if JAVA_CMD:   # the Java verifier must say the same as Python and Go, case by case
            cp = subprocess.run([*JAVA_CMD.split(), *flags, path], capture_output=True, text=True)
            jv = json.loads(cp.stdout)["signatures"]
            self.assertEqual((py["ok"], py["pq_protected"], py["pq_status"]), (jv["ok"], jv["pq_protected"], jv["pq_status"]), (path, "java", jv))
            self.assertEqual(cp.returncode, rc, "java exit code differs from go")
        return py, go, rc

    def test_cases_agree(self):
        py, go, rc = self._both(self.signed, self.pk, self.pq_pk); self.assertEqual(rc, 0); self.assertIs(py["pq_protected"], True)
        py, go, rc = self._both(self.signed, self.pk, None); self.assertIsNone(py["pq_protected"]); self.assertEqual(rc, 0)
        lines = [json.loads(l) for l in open(self.signed)]
        # stripped, key pinned → missing, FAIL in both
        s1 = os.path.join(self.tmp, "stripped.jsonl"); _write(s1, [{k: v for k, v in e.items() if k not in ("signature_pq", "signer_pq")} for e in lines])
        py, go, rc = self._both(s1, self.pk, self.pq_pk); self.assertEqual(py["pq_status"], "missing"); self.assertEqual(rc, 1)
        # tampered PQ signature
        s2 = os.path.join(self.tmp, "badpq.jsonl"); l2 = json.loads(json.dumps(lines)); raw = bytearray(base64.b64decode(l2[1]["signature_pq"])); raw[9] ^= 1
        l2[1]["signature_pq"] = base64.b64encode(bytes(raw)).decode(); _write(s2, l2)
        py, go, rc = self._both(s2, self.pk, self.pq_pk); self.assertEqual(py["pq_status"], "invalid"); self.assertEqual(rc, 1)
        # foreign PQ key expected
        other = signer.keygen_pq(os.path.join(self.tmp, "o.pq"))["public_key_b64"]
        py, go, rc = self._both(self.signed, self.pk, other); self.assertEqual(py["pq_failures"][0]["reason"], "pq_signer_mismatch"); self.assertEqual(rc, 1)
        # broken Ed25519, valid PQ → classical_broken
        s3 = os.path.join(self.tmp, "baded.jsonl"); l3 = json.loads(json.dumps(lines)); raw = bytearray(base64.b64decode(l3[2]["signature"])); raw[3] ^= 1
        l3[2]["signature"] = base64.b64encode(bytes(raw)).decode(); _write(s3, l3)
        py, go, rc = self._both(s3, self.pk, self.pq_pk); self.assertEqual(py["pq_status"], "classical_broken")
        # uppercase signer hex → malformed in both
        s4 = os.path.join(self.tmp, "upper.jsonl"); l4 = json.loads(json.dumps(lines)); l4[0]["signer"] = l4[0]["signer"].upper(); _write(s4, l4)
        py, go, rc = self._both(s4, None, None); self.assertEqual(py["failures"][0]["reason"], "malformed_signature_field")
        # partial layer
        s5 = os.path.join(self.tmp, "partial.jsonl"); l5 = json.loads(json.dumps(lines)); l5[3].pop("signature_pq"); l5[3].pop("signer_pq"); _write(s5, l5)
        py, go, rc = self._both(s5, self.pk, None); self.assertEqual(py["pq_status"], "partial")
        # Ed25519-only ledger, no keys → absent
        ed = os.path.join(self.tmp, "ed.jsonl"); signer.sign_ledger(self.led, ed, self.k)
        py, go, rc = self._both(ed, None, None); self.assertEqual(py["pq_status"], "absent"); self.assertEqual(rc, 0)
        # round 4: combinations outside the eight — wrong pinned Ed25519 key with a valid PQ layer (signer_mismatch),
        # and a stripped ledger under a wrong Ed25519 key: labels may be imprecise but Python/Go/Java must AGREE and FAIL
        wrong = signer.keygen(os.path.join(self.tmp, "w"))["public_key_hex"]
        py, go, rc = self._both(self.signed, wrong, self.pq_pk); self.assertFalse(py["ok"]); self.assertEqual(rc, 1)
        py, go, rc = self._both(s1, wrong, self.pq_pk); self.assertFalse(py["ok"]); self.assertEqual(rc, 1)

    def test_go_refuses_the_same_key_combinations(self):
        rc, go = self._go(self.signed, "-pq-pubkey", self.pq_pk); self.assertEqual(rc, 1); self.assertIn("pq_key_without_ed25519_key", json.dumps(go["failures"]))
        rc, go = self._go(self.signed, "-pubkey", self.pk, "-require-pq"); self.assertEqual(rc, 1); self.assertIn("require_pq_without_key", json.dumps(go["failures"]))


@unittest.skipUnless(HAVE_PQ, "cryptography >= 50 (ML-DSA) assente")
class TestHybridTip(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(); self.led = os.path.join(self.tmp, "l.jsonl"); self.base = _ledger(8); _write(self.led, self.base)
        self.k = os.path.join(self.tmp, "log.key"); self.pk = signer.keygen(self.k)["public_key_hex"]
        self.pq_pk = signer.keygen_pq(self.k + ".pq")["public_key_b64"]
        self.tip = T.sign_tip(self.led, self.k, pq_keyfile=self.k + ".pq")
        self.tp = self.led + ".tip.json"

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _v(self, **kw):
        return V.verify_ledger(self.led, trusted_pubkey_hex=self.pk, **kw)

    def test_hybrid_tip_verifies_with_both_keys(self):
        self.assertIn("signature_pq_hex", self.tip); self.assertEqual(self.tip["log_pq_pubkey_b64"], self.pq_pk)
        r = self._v(trusted_pq_pubkey_b64=self.pq_pk)
        self.assertEqual(r["verdict"], "PASS"); self.assertIs(r["tip"]["pq_protected"], True)

    def test_without_trusted_pq_key_layer_is_unchecked_not_protected(self):
        r = self._v()
        self.assertEqual(r["verdict"], "PASS"); self.assertIsNone(r["tip"]["pq_protected"])

    def test_ed25519_only_tip_fails_when_pq_required(self):
        T.sign_tip(self.led, self.k)                    # overwrite with a classical tip
        r = self._v(trusted_pq_pubkey_b64=self.pq_pk)
        self.assertEqual(r["verdict"], "FAIL"); self.assertIn("pq_missing", r["tip"]["error"])
        self.assertIs(self._v()["tip"]["pq_protected"], False)

    def test_tampered_pq_signature_is_fail(self):
        t = json.load(open(self.tp)); s = bytearray(bytes.fromhex(t["signature_pq_hex"])); s[5] ^= 1
        t["signature_pq_hex"] = s.hex(); json.dump(t, open(self.tp, "w"))
        r = self._v(trusted_pq_pubkey_b64=self.pq_pk)
        self.assertEqual(r["verdict"], "FAIL"); self.assertIn("post-quantum signature invalid", r["tip"]["error"])
        self.assertEqual(self._v()["verdict"], "PASS")   # the classical layer alone still passes: the PQ key must be REQUIRED

    def test_other_pq_key_is_fail(self):
        other = signer.keygen_pq(os.path.join(self.tmp, "o.pq"))["public_key_b64"]
        r = self._v(trusted_pq_pubkey_b64=other)
        self.assertEqual(r["verdict"], "FAIL"); self.assertIn("post-quantum key differs", r["tip"]["error"])

    def test_truncation_still_caught_with_pq(self):
        _write(self.led, self.base[:6])
        r = self._v(trusted_pq_pubkey_b64=self.pq_pk)
        self.assertEqual(r["verdict"], "FAIL"); self.assertIn("tail_truncated", r["tip"]["error"])

    def test_pq_key_without_log_key_and_without_tip_are_fail(self):
        r = V.verify_ledger(self.led, trusted_pq_pubkey_b64=self.pq_pk)
        self.assertEqual(r["verdict"], "FAIL"); self.assertIn("pq_key_without_log_key", json.dumps(r["parse_errors"]))
        os.remove(self.tp)
        r = self._v(trusted_pq_pubkey_b64=self.pq_pk)
        self.assertEqual(r["verdict"], "FAIL"); self.assertIn("tip_missing", json.dumps(r["parse_errors"]))

    def test_hostile_pq_fields_are_tip_invalid(self):
        t0 = json.load(open(self.tp))
        for bad in ({"signature_pq_hex": 123}, {"signature_pq_hex": None}, {"signature_pq_hex": ""}, {"signature_pq_hex": "abcd"}, {"log_pq_pubkey_b64": "!!!!"},
                    {"signature_hex": t0["signature_hex"].upper()}, {"signature_hex": t0["signature_hex"][:2] + " " + t0["signature_hex"][3:]}):
            json.dump(dict(t0, **bad), open(self.tp, "w"))
            r = self._v()
            self.assertEqual(r["verdict"], "FAIL", bad); self.assertIn("tip_invalid", r["tip"]["error"])

    def test_tip_empty_context(self):
        sk, _ = signer.load_pq_key(self.k + ".pq")
        payload = T.tip_payload(self.tip["entries"], self.tip["ledger_id"], self.tip["tip_sha256"], self.tip["ts"])
        sk.public_key().verify(bytes.fromhex(self.tip["signature_pq_hex"]), payload)    # empty context, JDK-verifiable
        self.assertEqual(T.PQ_CTX_TIP, b"")

    def test_cli_flag(self):
        here = os.path.dirname(os.path.abspath(__file__))
        cp = subprocess.run([sys.executable, "verifier.py", self.led, "--trusted-pubkey", self.pk, "--trusted-pq-pubkey", self.pq_pk],
                            capture_output=True, text=True, cwd=here)
        out = json.loads(cp.stdout)
        self.assertEqual(out["verdict"], "PASS", cp.stderr); self.assertIs(out["tip"]["pq_protected"], True)

    @unittest.skipUnless(GO_BIN and os.path.exists(GO_BIN or ""), "Go verifier binary not given (CVVERIFY_GO)")
    def test_go_verifier_agrees(self):
        def go(*extra):
            cp = subprocess.run([GO_BIN, "-tip", self.tp, "-trusted-pubkey", self.pk, *extra, self.led], capture_output=True, text=True)
            return cp.returncode, json.loads(cp.stdout)
        rc, out = go("-trusted-pq-pubkey", self.pq_pk)
        self.assertEqual(rc, 0, out); self.assertTrue(out["tip"]["pq_protected"])
        rc, out = go()
        self.assertEqual(rc, 0); self.assertIsNone(out["tip"]["pq_protected"]); self.assertIn("pq_unchecked", out["tip"]["pq_why"])
        # council 15/09 (Fable): a trusted PQ key WITHOUT the trusted log key, or without any tip, must never PASS
        cp = subprocess.run([GO_BIN, "-tip", self.tp, "-trusted-pq-pubkey", self.pq_pk, self.led], capture_output=True, text=True)
        self.assertNotEqual(cp.returncode, 0); self.assertIn("pq_key_without_log_key", cp.stdout)
        os.rename(self.tp, self.tp + ".away")
        cp = subprocess.run([GO_BIN, "-trusted-pubkey", self.pk, "-trusted-pq-pubkey", self.pq_pk, self.led], capture_output=True, text=True)
        self.assertNotEqual(cp.returncode, 0); self.assertIn("tip_missing", cp.stdout)
        os.rename(self.tp + ".away", self.tp)
        # hostile types / formats in the optional PQ fields: tip_invalid, not silence
        t0 = json.load(open(self.tp))
        for bad in ({"signature_pq_hex": 123}, {"signature_pq_hex": None}, {"signature_pq_hex": ""}, {"signature_pq_hex": "abcd"},
                    {"log_pq_pubkey_b64": "!!!!"}, {"signature_hex": t0["signature_hex"].upper()}):
            json.dump(dict(t0, **bad), open(self.tp, "w"))
            cp = subprocess.run([GO_BIN, "-tip", self.tp, "-trusted-pubkey", self.pk, self.led], capture_output=True, text=True)
            self.assertNotEqual(cp.returncode, 0, bad)
        json.dump(t0, open(self.tp, "w"))
        t = json.load(open(self.tp)); s = bytearray(bytes.fromhex(t["signature_pq_hex"])); s[5] ^= 1
        t["signature_pq_hex"] = s.hex(); json.dump(t, open(self.tp, "w"))
        rc, out = go("-trusted-pq-pubkey", self.pq_pk)
        self.assertNotEqual(rc, 0); self.assertIn("post-quantum signature invalid", out["tip"]["why"])
        T.sign_tip(self.led, self.k)
        rc, out = go("-trusted-pq-pubkey", self.pq_pk)
        self.assertNotEqual(rc, 0); self.assertIn("pq_missing", out["tip"]["why"])


@unittest.skipUnless(HAVE_PQ, "cryptography >= 50 (ML-DSA) assente")
class TestHybridPack(unittest.TestCase):
    """Council 16/09 round 2: the pack never confirms the PQ layer on a self-declared key — only on keys the caller
    pins (directly, or through a manifest signer the caller pins); a hybrid build with a broken layer fails loudly."""
    def setUp(self):
        self.tmp = tempfile.mkdtemp(); self.led = os.path.join(self.tmp, "l.jsonl"); _write(self.led, _ledger(4))
        self.k = os.path.join(self.tmp, "k"); self.pk = signer.keygen(self.k)["public_key_hex"]; self.pq_pk = signer.keygen_pq(self.k + ".pq")["public_key_b64"]
        self.signed = os.path.join(self.tmp, "s.jsonl"); signer.sign_ledger(self.led, self.signed, self.k, pq_keyfile=self.k + ".pq")
        self.mk = os.path.join(self.tmp, "m.key"); self.mpk = signer.keygen(self.mk)["public_key_hex"]

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_unpinned_build_records_null_and_pinned_build_records_true(self):
        import evidence_pack as P
        out0 = os.path.join(self.tmp, "pack0"); P.build_pack([self.signed], out0, subject="t")
        self.assertIsNone(json.load(open(os.path.join(out0, "MANIFEST.json")))["ledgers"][0]["pq_protected"])
        with self.assertRaises(ValueError):                                  # PQ key without the Ed25519 key
            P.build_pack([self.signed], os.path.join(self.tmp, "x"), pq_pubkey_b64=self.pq_pk)
        P.build_pack([self.signed], os.path.join(self.tmp, "y"), signer_pubkey_hex=self.pk)   # round 3: Ed25519 alone is legitimate
        out = os.path.join(self.tmp, "pack"); P.build_pack([self.signed], out, subject="t", pq_pubkey_b64=self.pq_pk, signer_pubkey_hex=self.pk, sign_key=self.mk)
        man = json.load(open(os.path.join(out, "MANIFEST.json")))
        self.assertIs(man["ledgers"][0]["pq_protected"], True); self.assertEqual(man["ledgers"][0]["pq_signers"], [self.pq_pk])
        # verification: caller pins the keys → True; caller pins the manifest signer → True; nobody pins → null
        v = P.verify_pack(out, pq_pubkey_b64=self.pq_pk, signer_pubkey_hex=self.pk); self.assertTrue(v["valid"]); self.assertIs(v["ledgers"][0]["pq_protected"], True)
        v = P.verify_pack(out, manifest_signer_hex=self.mpk); self.assertTrue(v["valid"]); self.assertIs(v["ledgers"][0]["pq_protected"], True)
        v = P.verify_pack(out); self.assertTrue(v["valid"]); self.assertIsNone(v["ledgers"][0]["pq_protected"]); self.assertEqual(v["ledgers"][0]["pq_reason"], "manifest_unpinned")
        v = P.verify_pack(out, manifest_signer_hex="00" * 32); self.assertIsNone(v["ledgers"][0]["pq_protected"])   # wrong manifest signer: not pinned
        # foreign key pinned by the caller → the layer is lost
        other = signer.keygen_pq(os.path.join(self.tmp, "o.pq"))["public_key_b64"]
        v = P.verify_pack(out, pq_pubkey_b64=other, signer_pubkey_hex=self.pk); self.assertFalse(v["valid"]); self.assertEqual(v["ledgers"][0]["pq_reason"], "pq_layer_lost")

    def test_forged_unsigned_manifest_never_yields_true(self):
        # round 2 (Fable, measured): attacker re-signs with own keys, rewrites pq_signers and digests, drops the signature
        import evidence_pack as P, hashlib
        out = os.path.join(self.tmp, "pack"); P.build_pack([self.signed], out, subject="t", pq_pubkey_b64=self.pq_pk, signer_pubkey_hex=self.pk, sign_key=self.mk)
        man = json.load(open(os.path.join(out, "MANIFEST.json"))); name = man["ledgers"][0]["file"]
        ak = os.path.join(self.tmp, "att"); apk = signer.keygen(ak)["public_key_hex"]; apq = signer.keygen_pq(ak + ".pq")["public_key_b64"]
        signer.sign_ledger(self.led, os.path.join(out, name), ak, pq_keyfile=ak + ".pq")
        man["ledgers"][0].update({"signers": [apk], "pq_signers": [apq]})
        man["file_digests_sha256"][name] = hashlib.sha256(open(os.path.join(out, name), "rb").read()).hexdigest()
        for k in ("manifest_signature", "manifest_signer", "manifest_digest_sha256"):
            man.pop(k, None)
        m2 = {k: v for k, v in man.items() if k != "rfc3161_timestamp"}
        man["manifest_digest_sha256"] = hashlib.sha256(json.dumps(m2, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()
        json.dump(man, open(os.path.join(out, "MANIFEST.json"), "w"), indent=1, sort_keys=True, ensure_ascii=False)
        v = P.verify_pack(out)
        self.assertIsNot(v["ledgers"][0]["pq_protected"], True)                 # never true on a self-declared key
        self.assertFalse(v["manifest_authenticated"])
        self.assertFalse(P.verify_pack(out, pq_pubkey_b64=self.pq_pk, signer_pubkey_hex=self.pk)["valid"])
        self.assertFalse(P.verify_pack(out, manifest_signer_hex=self.mpk)["ledgers"][0]["pq_protected"] is True)

    def test_manifest_body_tampered_under_intact_signature_is_not_pinned(self):
        # round 3 (Fable, measured): keep the vendor's digest+signature, rewrite signers/pq_signers, re-sign the ledger
        import evidence_pack as P
        out = os.path.join(self.tmp, "pack"); P.build_pack([self.signed], out, subject="t", pq_pubkey_b64=self.pq_pk, signer_pubkey_hex=self.pk, sign_key=self.mk)
        mp = os.path.join(out, "MANIFEST.json"); man = json.load(open(mp)); name = man["ledgers"][0]["file"]
        ak = os.path.join(self.tmp, "att"); apk = signer.keygen(ak)["public_key_hex"]; apq = signer.keygen_pq(ak + ".pq")["public_key_b64"]
        signer.sign_ledger(self.led, os.path.join(out, name), ak, pq_keyfile=ak + ".pq")
        man["ledgers"][0].update({"signers": [apk], "pq_signers": [apq]})
        json.dump(man, open(mp, "w"), indent=1, sort_keys=True, ensure_ascii=False)
        v = P.verify_pack(out, manifest_signer_hex=self.mpk)
        self.assertTrue(v["manifest_authenticated"]); self.assertFalse(v["manifest_ok"]); self.assertFalse(v["valid"])
        self.assertIsNot(v["ledgers"][0]["pq_protected"], True)               # attacker-chosen keys are never "pinned"
        man["ledgers"][0]["pq_signers"] = "junk"                               # malformed recorded key: a verdict, not an exception
        json.dump(man, open(mp, "w"), indent=1, sort_keys=True, ensure_ascii=False)
        v = P.verify_pack(out, manifest_signer_hex=self.mpk); self.assertFalse(v["valid"])

    def test_hybrid_build_with_broken_layer_fails_loudly(self):
        import evidence_pack as P
        ed = os.path.join(self.tmp, "ed.jsonl"); signer.sign_ledger(self.led, ed, self.k)
        with self.assertRaises(RuntimeError):
            P.build_pack([ed], os.path.join(self.tmp, "p"), pq_pubkey_b64=self.pq_pk, signer_pubkey_hex=self.pk)


if __name__ == "__main__":
    unittest.main()
