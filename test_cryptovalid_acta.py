#!/usr/bin/env python3
"""cryptovalid_acta — draft-farley-acta-signed-receipts-03: KATs from the primary sources, the reference implementation's
receipts as positive control (every positive has its tampered twin), chain/§6.7/§6.8 rules, hostile inputs, the Cedar
driver when cedarpy is present. CV_REQUIRE_CRYPTO=1 makes a missing `cryptography` a failure (CI)."""
import base64, hashlib, json, os, subprocess, sys, tempfile, unittest
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import cryptovalid_acta as A  # noqa: E402
try:
    import cryptography  # noqa: F401
    HAVE_CRYPTO = True
except ImportError:
    HAVE_CRYPTO = False
    if os.environ.get("CV_REQUIRE_CRYPTO"):
        raise SystemExit("CV_REQUIRE_CRYPTO=1 but cryptography is missing")
SEED = "0000000000000000000000000000000000000000000000000000000000000001"
PUB_HEX = "4cb5abf6ad79fbf5abbccafcc269d85cd2651ed4b885b5869f241aedf0a5ba29"       # fixtures/keys/README.md of the vectors repo
KID = "sb:issuer:6ASf5EcmmEHT"                                                     # base58 2.1.1 gives the same 12 characters
POLICY_DIR = os.path.join(HERE, "examples", "acta")
REF_DIR = os.path.join(POLICY_DIR, "reference_protect-mcp")
POLICY_DIGEST = "sha256:81ba074a4843cb722407feb2a9c43ec1ac4c8e19fd057dc19962af8aef9c05af"   # expected/chain.jsonl


def _policy_files():
    out = {}
    for n in os.listdir(POLICY_DIR):
        if n.endswith(".cedar"):
            with open(os.path.join(POLICY_DIR, n), "rb") as f:
                out[n] = f.read()
    return out


class TestKATs(unittest.TestCase):
    def test_policy_digest_and_kid(self):
        self.assertEqual(A.policy_digest(_policy_files(), "cedar"), POLICY_DIGEST)
        self.assertEqual(A.policy_digest_from_dir(POLICY_DIR), POLICY_DIGEST)
        self.assertNotEqual(A.policy_digest({"autoresearch-safe.cedar": _policy_files()["autoresearch-safe.cedar"] + b"\n"}), POLICY_DIGEST)
        self.assertNotEqual(A.policy_digest({"renamed.cedar": _policy_files()["autoresearch-safe.cedar"]}), POLICY_DIGEST)   # names are in the manifest
        self.assertEqual(A.issuer_kid(bytes.fromhex(PUB_HEX)), KID)
        self.assertEqual(A.base58(b"\x00\x00\x01"), "112")
        with self.assertRaises(ValueError):
            A.policy_digest({})
        two = {"b.cedar": b"permit(principal, action, resource);", "a.cedar": b"forbid(principal, action, resource);"}
        manifest = {"construction": "acta-policy-digest-v1", "engine": "cedar",
                    "files": [{"name": "a.cedar", "sha256": hashlib.sha256(two["a.cedar"]).hexdigest()}, {"name": "b.cedar", "sha256": hashlib.sha256(two["b.cedar"]).hexdigest()}]}
        self.assertEqual(A.policy_digest(two), "sha256:" + hashlib.sha256(A.jcs(manifest)).hexdigest())            # sorted by name, not by insertion
        self.assertEqual(A.policy_digest(two), A.policy_digest({k: two[k] for k in sorted(two)}))

    def test_jcs(self):
        self.assertEqual(A.jcs({"b": 1, "a": [True, None, "é"], "n": 1e21}), '{"a":[true,null,"é"],"b":1,"n":1e+21}'.encode())
        for f, exp in ((295147905179352825856.0, "295147905179352830000"), (5e-324, "5e-324"), (0.000001, "0.000001"), (1e-7, "1e-7"), (-0.0, "0")):
            self.assertEqual(A._es6_number(f), exp)
        for bad in ({"x": float("nan")}, json.loads("[" * 600 + "]" * 600), {"x": int("1" + "0" * 400)}):
            with self.assertRaises(ValueError):
                A.jcs(bad)
        with self.assertRaises(TypeError):
            A.jcs({1: 2})

    @unittest.skipUnless(HAVE_CRYPTO, "cryptography assente")
    def test_seed_to_pubkey(self):
        self.assertEqual(A.pubkey_from_seed(SEED).hex(), PUB_HEX)


@unittest.skipUnless(HAVE_CRYPTO, "cryptography assente")
class TestReferenceReceipts(unittest.TestCase):
    """protect-mcp 0.29.0 receipts (the draft author's implementation): verified, chained, policy-bound — and refused when altered."""

    def _refs(self):
        out = []
        for n in sorted(os.listdir(REF_DIR)):
            if n.endswith(".json"):
                with open(os.path.join(REF_DIR, n), encoding="utf-8") as f:
                    out.append(json.load(f))
        return out

    def test_reference_chain_verifies_and_tampers_fail(self):
        refs = self._refs(); self.assertEqual(len(refs), 4)
        v = A.verify_chain(refs, {"conformance": PUB_HEX}, _policy_files())
        self.assertTrue(v["ok"], v["problems"]); self.assertEqual(v["verified"], 4); self.assertEqual(v["warnings"], [])
        self.assertEqual(refs[1]["payload"]["previousReceiptHash"], A.receipt_hash(refs[0]))         # §6.7 over the whole signed receipt
        self.assertFalse(A.verify_chain(refs, {"conformance": "11" * 32}, _policy_files())["ok"])      # wrong key
        self.assertFalse(A.verify_chain(refs, {"other": PUB_HEX})["ok"])                               # kid unknown
        for mut in (lambda r: r[2]["payload"].__setitem__("decision", "allow"), lambda r: r[2]["signature"].__setitem__("sig", "00" * 64),
                    lambda r: r[2]["payload"].__setitem__("previousReceiptHash", "sha256:" + "0" * 64),
                    lambda r: r[2]["payload"].__setitem__("previousReceiptHash", "sha512:" + "0" * 64),
                    lambda r: r[0]["payload"].__setitem__("previousReceiptHash", "sha256:" + "0" * 64),
                    lambda r: r.__setitem__(2, r[1]), lambda r: r[2]["signature"].__setitem__("kid", "other"),
                    lambda r: r[2]["signature"].__setitem__("alg", "HS256"), lambda r: r[2].__setitem__("extra", 1)):
            m = json.loads(json.dumps(refs)); mut(m)
            self.assertFalse(A.verify_chain(m, {"conformance": PUB_HEX, "other": PUB_HEX})["ok"])
        wrong_policy = dict(_policy_files()); wrong_policy["autoresearch-safe.cedar"] += b"\n// changed"
        self.assertTrue(any("6.8" in p["why"] for p in A.verify_chain(refs, {"conformance": PUB_HEX}, wrong_policy)["problems"]))
        # a bare-hex link (earlier revisions) is accepted on read with a warning, never emitted
        bare = json.loads(json.dumps(refs)); bare[1]["payload"]["previousReceiptHash"] = A.receipt_hash(refs[0]).split(":")[1]
        bare[1] = A.sign_receipt({k: v for k, v in bare[1]["payload"].items()}, SEED, "conformance")
        v = A.verify_chain(bare[:2], {"conformance": PUB_HEX}); self.assertTrue(v["ok"]); self.assertTrue(any("bare hex" in w["why"] for w in v["warnings"]))


@unittest.skipUnless(HAVE_CRYPTO, "cryptography assente")
class TestSignVerify(unittest.TestCase):
    def test_sign_chain_shapes_algs_hostile(self):
        p1 = A.decision_payload("Read", "allow", KID, "2026-09-20T09:00:00.001Z", POLICY_DIGEST, "s1", extra={"sequence": 1})
        r1 = A.sign_receipt(p1, SEED)
        self.assertEqual(r1["signature"]["kid"], KID); self.assertEqual(len(r1["signature"]["sig"]), 128)
        self.assertNotIn("previousReceiptHash", r1["payload"])
        p2 = A.decision_payload("Bash", "deny", KID, "2026-09-20T09:00:00.002Z", POLICY_DIGEST, previous=r1, reason="policy2")
        r2 = A.sign_receipt(p2, SEED)
        self.assertEqual(r2["payload"]["previousReceiptHash"], A.receipt_hash(r1))
        v = A.verify_chain([r1, r2], {KID: PUB_HEX}, _policy_files()); self.assertTrue(v["ok"], v["problems"])
        self.assertTrue(A.verify_receipt(r2, {KID: bytes.fromhex(PUB_HEX)})["ok"])
        # the signing input is JCS(payload) — PureEdDSA, no pre-hash; a re-serialised payload still verifies
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(PUB_HEX)).verify(bytes.fromhex(r2["signature"]["sig"]), A.jcs(r2["payload"]))
        reser = json.loads(json.dumps({"signature": r2["signature"], "payload": dict(reversed(list(r2["payload"].items())))}))
        self.assertTrue(A.verify_receipt(reser, {KID: PUB_HEX})["ok"])
        # §2.2: issuer_id MUST equal kid — a receipt whose payload names another issuer but whose kid resolves to the signing key
        alias = A.sign_receipt(dict(p1, issuer_id="conformance"), SEED, "conformance")
        alias["signature"]["kid"] = KID
        v = A.verify_receipt(alias, {KID: PUB_HEX, "conformance": PUB_HEX}); self.assertFalse(v["ok"]); self.assertIn("2.2", v["why"])
        # §6.6: an envelope carries exactly payload and signature
        v = A.verify_receipt(dict(r1, public_key=PUB_HEX), {KID: PUB_HEX}); self.assertFalse(v["ok"]); self.assertIn("6.6", v["why"])
        # never signs: issuer_id != kid, a signature member inside the payload, bad decision, bad policy digest, bad time
        with self.assertRaises(ValueError):
            A.sign_receipt(dict(p1, issuer_id="sb:issuer:other"), SEED)
        with self.assertRaises(ValueError):
            A.sign_receipt(dict(p1, signature="x"), SEED)
        for bad in (dict(decision="maybe"), dict(policy_digest_value="81ba"), dict(issued_at="2026-09-20 09:00")):
            with self.assertRaises(ValueError):
                A.decision_payload("Read", bad.get("decision", "allow"), KID, bad.get("issued_at", "2026-09-20T09:00:00Z"), bad.get("policy_digest_value"))
        with self.assertRaises(ValueError):
            A.decision_payload("Read", "allow", KID, extra={"decision": "deny"})
        # flat shape is read (signing input = receipt minus signature), never emitted
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        sk = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(SEED))
        flat = {"type": "protectmcp:decision", "tool_name": "Read", "decision": "allow", "issued_at": "2026-09-20T09:00:00Z", "issuer_id": "conformance", "kid": "conformance"}
        flat["signature"] = sk.sign(A.jcs(flat)).hex()
        v = A.verify_receipt(flat, {"conformance": PUB_HEX}); self.assertTrue(v["ok"]); self.assertEqual(v["shape"], "flat")
        flat2 = dict(flat, decision="deny"); self.assertFalse(A.verify_receipt(flat2, {"conformance": PUB_HEX})["ok"])
        spoof = {k: v for k, v in flat.items() if k != "signature"}; spoof["issuer_id"] = "sb:issuer:victim"      # attacker's key, victim's name
        spoof["signature"] = sk.sign(A.jcs(spoof)).hex()
        v = A.verify_receipt(spoof, {"conformance": PUB_HEX, "sb:issuer:victim": "22" * 32}); self.assertFalse(v["ok"]); self.assertIn("2.2", v["why"])
        self.assertTrue(A._RFC3339.match(A.decision_payload("Read", "allow", KID)["issued_at"]))                     # clock read once
        # ES256 (P1363 r||s, declared) and ML-DSA-65 (raw, empty context) are read against the declared alg
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
        ek = ec.generate_private_key(ec.SECP256R1()); pem = ek.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        pay = dict(p1, issuer_id="es")
        rr, ss = decode_dss_signature(ek.sign(A.jcs(pay), ec.ECDSA(hashes.SHA256())))
        ss = min(ss, A.P256_ORDER - ss)                                                      # low-S: the only canonical form read
        es = {"payload": pay, "signature": {"alg": "ES256", "kid": "es", "sig": (rr.to_bytes(32, "big") + ss.to_bytes(32, "big")).hex()}}
        self.assertTrue(A.verify_receipt(es, {"es": pem})["ok"]); self.assertFalse(A.verify_receipt(es, {"es": PUB_HEX})["ok"])
        pem2 = ec.generate_private_key(ec.SECP256R1()).public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        v = A.verify_receipt(es, {"es": pem2}); self.assertFalse(v["ok"]); self.assertIn("InvalidSignature", v["why"])          # a real P-256 key that did not sign
        try:
            from cryptography.hazmat.primitives.asymmetric import mldsa
            mk = mldsa.MLDSA65PrivateKey.generate(); mpub = mk.public_key().public_bytes_raw()
            pay = dict(p1, issuer_id="pq"); ml = {"payload": pay, "signature": {"alg": "ML-DSA-65", "kid": "pq", "sig": mk.sign(A.jcs(pay)).hex()}}
            self.assertTrue(A.verify_receipt(ml, {"pq": mpub})["ok"])
            other = mldsa.MLDSA65PrivateKey.generate().public_key().public_bytes_raw()
            v = A.verify_receipt(ml, {"pq": other}); self.assertFalse(v["ok"]); self.assertIn("InvalidSignature", v["why"])        # the signature check itself
            flipped = json.loads(json.dumps(ml)); flipped["signature"]["sig"] = ("00" if flipped["signature"]["sig"][:2] != "00" else "11") + flipped["signature"]["sig"][2:]
            self.assertFalse(A.verify_receipt(flipped, {"pq": mpub})["ok"])
            mixed = [r1, dict(ml, payload=dict(pay, previousReceiptHash=A.receipt_hash(r1)))]
            mixed[1] = {"payload": mixed[1]["payload"], "signature": {"alg": "ML-DSA-65", "kid": "pq", "sig": mk.sign(A.jcs(mixed[1]["payload"])).hex()}}
            self.assertTrue(A.verify_chain(mixed, {KID: PUB_HEX, "pq": mpub})["ok"])            # §6.11 algorithm-mixed chain
        except ImportError:
            if os.environ.get("CV_REQUIRE_CRYPTO"):
                raise
        # hostile: verdicts, never exceptions
        for h in ("junk", 5, [], {"payload": "x", "signature": {}}, {"payload": {}, "signature": {"alg": "EdDSA", "kid": KID, "sig": "zz"}},
                  {"payload": {"type": "t", "issued_at": "x", "issuer_id": KID}, "signature": {"alg": "EdDSA", "kid": KID, "sig": "00"}},
                  {"payload": {"type": "t", "issued_at": "2026-09-20T09:00:00Z", "issuer_id": KID, "previousReceiptHash": None}, "signature": {"alg": "EdDSA", "kid": KID, "sig": "00"}},
                  {"payload": dict(p1, x=float("nan")), "signature": {"alg": "EdDSA", "kid": KID, "sig": "00" * 64}},
                  {"payload": p1, "signature": {"alg": "EdDSA", "kid": KID, "sig": "00" * 64}, "extra": 1}):
            self.assertFalse(A.verify_receipt(h, {KID: PUB_HEX})["ok"])
        self.assertFalse(A.verify_chain([], {KID: PUB_HEX})["ok"]); self.assertFalse(A.verify_chain("x", {})["ok"])
        # round 1 (Opus): a valid signature with hostile members OUTSIDE the signed bytes is a verdict, never an exception
        nan_sig = json.loads(json.dumps(r2)); nan_sig["signature"]["junk"] = float("nan")
        v = A.verify_receipt(nan_sig, {KID: PUB_HEX}); self.assertFalse(v["ok"]); self.assertIn("6.6", v["why"])
        deep = json.loads(json.dumps(r2)); deep["payload"]["deep"] = json.loads("[" * 600 + "]" * 600)
        self.assertFalse(A.verify_receipt(deep, {KID: PUB_HEX})["ok"])
        bad0 = {"payload": dict(p1, x=float("nan")), "signature": {"alg": "EdDSA", "kid": KID, "sig": "00" * 64}}
        v = A.verify_chain([bad0, r2], {KID: PUB_HEX}); self.assertFalse(v["ok"]); self.assertEqual(len(v["problems"]), 2)
        # §6.8: binding requested → a receipt without policy_digest is a problem; digest formats checked on read; {} policy refused
        nopd = {k: v for k, v in p1.items() if k != "policy_digest"}
        self.assertFalse(A.verify_chain([A.sign_receipt(nopd, SEED)], {KID: PUB_HEX}, _policy_files())["ok"])
        self.assertTrue(A.verify_chain([A.sign_receipt(nopd, SEED)], {KID: PUB_HEX})["ok"])
        with self.assertRaises(ValueError):
            A.verify_chain([r1], {KID: PUB_HEX}, {})
        legacy_pd = A.sign_receipt(dict(p1, policy_digest="81ba074a4843cb72"), SEED)                                        # pre-0.10.0 protect-mcp label
        v = A.verify_receipt(legacy_pd, {KID: PUB_HEX}); self.assertTrue(v["ok"]); self.assertTrue(any("opaque label" in n for n in v["notes"]))
        v = A.verify_chain([legacy_pd], {KID: PUB_HEX}); self.assertTrue(v["ok"]); self.assertTrue(v["warnings"])
        self.assertFalse(A.verify_chain([legacy_pd], {KID: PUB_HEX}, _policy_files())["ok"])                                   # cannot bind on a label
        self.assertEqual(A.verify_receipt(flat, {"conformance": PUB_HEX})["hash"], A.receipt_hash(flat))
        badlink = A.sign_receipt(dict(p2, previousReceiptHash="sha256:zz"), SEED)
        self.assertFalse(A.verify_receipt(badlink, {KID: PUB_HEX})["ok"])
        # a segment of a longer chain: the first link is a warning, not a problem
        v = A.verify_chain([r2], {KID: PUB_HEX}); self.assertTrue(v["ok"]); self.assertTrue(any("segment" in w["why"] for w in v["warnings"]))
        # a payload carrying a signature member is refused on read (§6.6)
        # round 2 (Opus): verify_chain reads the link from the SAME shape as the signature — a flat receipt with a decoy `payload`
        flat_g = {"type": "protectmcp:decision", "tool_name": "Read", "decision": "allow", "issued_at": "2026-09-20T09:00:00Z", "issuer_id": "conformance", "policy_digest": POLICY_DIGEST}
        flat_g["signature"] = sk.sign(A.jcs(flat_g)).hex()
        flat_h = {"type": "protectmcp:decision", "tool_name": "Bash", "decision": "deny", "issued_at": "2026-09-20T09:00:01Z", "issuer_id": "conformance",
                  "previousReceiptHash": "sha256:" + "0" * 64, "policy_digest": "sha256:" + "0" * 64,
                  "payload": {"previousReceiptHash": A.receipt_hash(flat_g), "policy_digest": POLICY_DIGEST}}                 # decoy members
        flat_h["signature"] = sk.sign(A.jcs(flat_h)).hex()
        v = A.verify_chain([flat_g, flat_h], {"conformance": PUB_HEX}, _policy_files()); self.assertFalse(v["ok"])
        self.assertTrue(any("6.7" in p["why"] for p in v["problems"]) and any("6.8" in p["why"] for p in v["problems"]), v["problems"])
        flat_ok = {k: v for k, v in flat_h.items() if k not in ("signature", "payload")}; flat_ok["previousReceiptHash"] = A.receipt_hash(flat_g); flat_ok["policy_digest"] = POLICY_DIGEST
        flat_ok["signature"] = sk.sign(A.jcs(flat_ok)).hex()
        self.assertTrue(A.verify_chain([flat_g, flat_ok], {"conformance": PUB_HEX}, _policy_files())["ok"])
        # round 2 (Sonnet): an ES256 high-S twin verifies mathematically but would change the §6.7 hash → refused
        hi = json.loads(json.dumps(es)); hi["signature"]["sig"] = (rr.to_bytes(32, "big") + (A.P256_ORDER - ss).to_bytes(32, "big")).hex()
        self.assertTrue(A.verify_receipt(es, {"es": pem})["ok"]); v = A.verify_receipt(hi, {"es": pem}); self.assertFalse(v["ok"]); self.assertIn("low-S", v["why"])
        # instants, not just shapes; previous must be signed; issued_at_base UTC; Cedar literal safety
        for bad_ts in ("2026-99-99T99:99:99Z", "2026-02-30T00:00:00Z", "2026-09-20T09:00:00+25:00"):
            v = A.verify_receipt(A.sign_receipt(dict(p1, issued_at=bad_ts), SEED), {KID: PUB_HEX})      # correctly signed, not an instant
            self.assertFalse(v["ok"]); self.assertIn("instant", v["why"])
            with self.assertRaises(ValueError):
                A.decision_payload("Read", "allow", KID, bad_ts)
        with self.assertRaises(ValueError):
            A.decision_payload("Read", "allow", KID, previous=p1)
        pay_s = dict(p1, signature="x")
        ps = {"payload": pay_s, "signature": {"alg": "EdDSA", "kid": KID, "sig": sk.sign(A.jcs(pay_s)).hex()}}   # signed as-is by a sloppy signer
        v = A.verify_receipt(ps, {KID: PUB_HEX}); self.assertFalse(v["ok"]); self.assertIn("6.6", v["why"])


class TestDriverAndCLI(unittest.TestCase):
    def test_cli_and_driver(self):
        if not HAVE_CRYPTO:
            self.skipTest("cryptography assente")
        with tempfile.TemporaryDirectory() as tmp:
            with open(os.path.join(tmp, "seed"), "w") as f:
                f.write(SEED + "\n")
            run = lambda *a: subprocess.run([sys.executable, os.path.join(HERE, "cryptovalid_acta.py"), *a], capture_output=True, text=True, cwd=HERE)
            r = run("policy-digest", POLICY_DIR); self.assertEqual(r.stdout.strip(), POLICY_DIGEST)
            r = run("sign", "--key", os.path.join(tmp, "seed"), "--tool", "Read", "--decision", "allow", "--policy-dir", POLICY_DIR, "--issued-at", "2026-09-20T09:00:00Z", "--out", os.path.join(tmp, "r1.json"))
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
            r = run("sign", "--key", os.path.join(tmp, "seed"), "--tool", "Bash", "--decision", "deny", "--policy-dir", POLICY_DIR, "--previous", os.path.join(tmp, "r1.json"), "--issued-at", "2026-09-20T09:00:01Z", "--out", os.path.join(tmp, "r2.json"))
            self.assertEqual(r.returncode, 0)
            r = run("verify", os.path.join(tmp, "r1.json"), os.path.join(tmp, "r2.json"), "--key", f"{KID}={PUB_HEX}", "--policy-dir", POLICY_DIR)
            self.assertEqual(r.returncode, 0, r.stdout); self.assertTrue(json.loads(r.stdout)["ok"])
            r = run("verify", os.path.join(tmp, "r2.json"), os.path.join(tmp, "r1.json"), "--key", f"{KID}={PUB_HEX}"); self.assertEqual(r.returncode, 1)
            r = run("verify", os.path.join(tmp, "nope.json")); self.assertEqual(r.returncode, 2); self.assertIn('"ok": false', r.stdout)
            with open(os.path.join(tmp, "deep.json"), "w") as f:
                f.write("[" * 100000)
            r = run("verify", os.path.join(tmp, "deep.json")); self.assertEqual(r.returncode, 2); self.assertNotIn("Traceback", r.stderr)
            with open(os.path.join(tmp, "dup.json"), "w") as f:
                f.write('{"payload": {"a": 1, "a": 2}, "signature": {"alg": "EdDSA", "kid": "k", "sig": "00"}}')
            r = run("verify", os.path.join(tmp, "dup.json")); self.assertEqual(r.returncode, 2); self.assertIn("duplicate", r.stdout)
            os.makedirs(os.path.join(tmp, "nopolicy"))
            r = run("verify", os.path.join(tmp, "r1.json"), "--key", f"{KID}={PUB_HEX}", "--policy-dir", os.path.join(tmp, "nopolicy")); self.assertEqual(r.returncode, 2)
            r = run("verify", os.path.join(tmp, "r1.json"), "--key", f"{KID}={os.path.join(tmp, 'seed')}")            # a hex keyfile: not a public key → refused
            self.assertEqual(r.returncode, 1)
            with open(os.path.join(tmp, "pub.hex"), "w") as f:
                f.write(PUB_HEX + "\n")
            r = run("verify", os.path.join(tmp, "r1.json"), "--key", f"{KID}={os.path.join(tmp, 'pub.hex')}"); self.assertEqual(r.returncode, 0, r.stdout)
            try:
                import cedarpy  # noqa: F401
            except ImportError:
                if os.environ.get("CV_REQUIRE_CEDAR"):
                    raise SystemExit("CV_REQUIRE_CEDAR=1 but cedarpy is missing")
                self.skipTest("cedarpy assente: the driver needs the official Cedar bindings")
            root = os.path.join(tmp, "vectors"); os.makedirs(os.path.join(root, "fixtures", "inputs")); os.makedirs(os.path.join(root, "fixtures", "policy"))
            open(os.path.join(root, "fixtures", "policy", "autoresearch-safe.cedar"), "wb").write(_policy_files()["autoresearch-safe.cedar"])
            for i, (tool, ctx, exp) in enumerate((("Read", {}, "allow"), ("Bash", {"command_pattern": "git"}, "allow"), ("Bash", {"command_pattern": "rm -rf"}, "deny"), ("Write", {"path_starts_with": "./"}, "allow")), 1):
                with open(os.path.join(root, "fixtures", "inputs", f"{i:03d}.json"), "w") as f:
                    json.dump({"sequence": i, "tool_name": tool, "tool_input": {"x": i}, "session_id": "s", "context": ctx, "expected_decision": "WRONG"}, f)
            with self.assertRaises(ValueError):
                A.run_vectors(root, os.path.join(tmp, "o2"), SEED, "2026-09-20T09:00:00+02:00")
            with self.assertRaises(ValueError):
                A.evaluate_cedar("permit(principal, action, resource);", 'Re\\u{61}d"', {})
            out = os.path.join(tmp, "out"); summary = A.run_vectors(root, out, SEED, "2026-09-20T09:00:00Z")
            self.assertEqual([r["decision"] for r in summary["receipts"]], ["allow", "allow", "deny", "allow"])     # from Cedar, not from expected_decision
            recs = []
            for fn in sorted(os.listdir(out)):
                if fn.startswith("receipt-"):
                    with open(os.path.join(out, fn), encoding="utf-8") as f:
                        recs.append(json.load(f))
            v = A.verify_chain(recs, {KID: PUB_HEX}, _policy_files()); self.assertTrue(v["ok"], v["problems"]); self.assertEqual(v["verified"], 4)
            self.assertEqual(recs[0]["payload"]["policy_digest"], POLICY_DIGEST)


if __name__ == "__main__":
    unittest.main(verbosity=2)
