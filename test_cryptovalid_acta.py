#!/usr/bin/env python3
"""cryptovalid_acta — draft-farley-acta-signed-receipts-03: KATs from the primary sources, the reference implementation's
receipts as positive control (every positive has its tampered twin), chain/§6.7/§6.8 rules, hostile inputs, the Cedar
driver when cedarpy is present. CV_REQUIRE_CRYPTO=1 makes a missing `cryptography` a failure (CI)."""
import base64, hashlib, json, os, subprocess, sys, tempfile, unittest
import unittest.mock
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


class KeyValidityWindow(unittest.TestCase):
    """§9.2: 'Verifiers SHOULD check key validity windows when available.'

    Added after running the conformance corpus published with draft-farley-acta-signed-receipts-03
    (giskard09/argentum-core, examples/conformance/farley-receipt-signature) against this verifier:
    its `superseded-key.reject` case — a valid signature under a key whose window had ended — was
    ACCEPTED here, the same gap its author had just reported in the reference verifier.
    """

    def _signed(self, issued_at):
        import hashlib
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        sk = Ed25519PrivateKey.from_private_bytes(hashlib.sha256(b"test-only/window").digest())
        pk = sk.public_key().public_bytes_raw()
        kid = A.issuer_kid(pk)
        body = {"type": "protectmcp:decision", "issued_at": issued_at, "issuer_id": kid,
                "tool_name": "payments.transfer", "decision": "allow"}
        receipt = {"payload": body, "signature": {"alg": "EdDSA", "kid": kid,
                                                  "sig": sk.sign(A.jcs(body)).hex()}}
        return receipt, kid, pk

    def test_inside_the_window_is_accepted(self):
        r, kid, pk = self._signed("2026-03-15T12:00:00Z")
        keys = {kid: {"key": pk, "valid_from": "2026-01-01T00:00:00Z", "valid_until": "2026-06-01T00:00:00Z"}}
        self.assertTrue(A.verify_receipt(r, keys)["ok"])

    def test_after_the_window_is_refused(self):
        r, kid, pk = self._signed("2026-07-15T12:00:00Z")
        keys = {kid: {"key": pk, "valid_from": "2026-01-01T00:00:00Z", "valid_until": "2026-06-01T00:00:00Z"}}
        out = A.verify_receipt(r, keys)
        self.assertFalse(out["ok"])
        self.assertIn("§9.2", out["why"])

    def test_before_the_window_is_refused(self):
        r, kid, pk = self._signed("2025-12-31T23:59:59Z")
        keys = {kid: {"key": pk, "valid_from": "2026-01-01T00:00:00Z"}}
        self.assertFalse(A.verify_receipt(r, keys)["ok"])

    def test_the_end_of_the_window_is_exclusive(self):
        # The draft states the SHOULD and nothing about boundaries. [from, until) is the only reading under which
        # two consecutive keys do not both own the instant of a rotation; this test pins the choice so it cannot
        # drift silently.
        r, kid, pk = self._signed("2026-06-01T00:00:00Z")
        keys = {kid: {"key": pk, "valid_until": "2026-06-01T00:00:00Z"}}
        self.assertFalse(A.verify_receipt(r, keys)["ok"])
        keys_next = {kid: {"key": pk, "valid_from": "2026-06-01T00:00:00Z"}}
        self.assertTrue(A.verify_receipt(r, keys_next)["ok"])

    def test_without_a_window_nothing_changes(self):
        # §9.2 applies "when available": a relying party that supplies no window must see the previous behaviour,
        # in both the bare and the dict form.
        r, kid, pk = self._signed("2026-07-15T12:00:00Z")
        self.assertTrue(A.verify_receipt(r, {kid: pk})["ok"])
        self.assertTrue(A.verify_receipt(r, {kid: {"key": pk}})["ok"])

    def test_a_leap_second_is_compared_and_not_skipped(self):
        # `_valid_instant` accepts :60 because RFC 3339 allows the form; before this, parsing it failed and the
        # window check was skipped, so a receipt could pass a window it should have been compared against.
        # Found by Gemini Pro reviewing the change, 23/09/2026.
        r, kid, pk = self._signed("2026-06-30T23:59:60Z")
        keys = {kid: {"key": pk, "valid_until": "2026-01-01T00:00:00Z"}}
        out = A.verify_receipt(r, keys)
        self.assertFalse(out["ok"])
        self.assertIn("§9.2", out["why"])
        # A leap second maps to :59.999999 of the same minute: ordered after :59 and before the next minute,
        # without asserting that a 61st second exists in the calendar Python models.
        self.assertLess(A._instant("2026-06-30T23:59:59Z"), A._instant("2026-06-30T23:59:60Z"))
        self.assertLess(A._instant("2026-06-30T23:59:60Z"), A._instant("2026-07-01T00:00:00Z"))

    def test_one_parser_only(self):
        # The two parsers disagreed before: `_valid_instant` accepted a leap second and the comparison parser did
        # not, so a value accepted as valid could not be compared and the window check was skipped. Found by Fable
        # 5.1 and by Gemini Pro independently, 23/09/2026.
        for t in ("2026-06-30T23:59:60Z", "2026-03-15T12:00:00.12Z", "2026-03-15T12:00:00.1234567Z"):
            self.assertEqual(A._valid_instant(t), A._instant(t) is not None, t)

    def test_an_extreme_date_gives_a_verdict_not_an_exception(self):
        # `.astimezone()` raised OverflowError on dates at the edges of the calendar, which `except ValueError`
        # did not catch: a traceback where the suite requires a verdict.
        r, kid, pk = self._signed("2026-03-15T12:00:00Z")
        for t in ("9999-12-31T23:00:00-05:00", "0001-01-01T00:00:00+01:00"):
            self.assertIsInstance(A._outside_window(t, {"valid_until": "2026-01-01T00:00:00Z"}), (str, type(None)), t)

    def test_an_uncomparable_instant_refuses_when_a_window_is_declared(self):
        r, kid, pk = self._signed("2026-03-15T12:00:00Z")
        self.assertIsNotNone(A._outside_window("not-an-instant", {"valid_until": "2026-06-01T00:00:00Z"}))
        self.assertIsNone(A._outside_window("not-an-instant", {"key": pk}))   # nessuna finestra: nulla da confrontare

    def test_a_malformed_window_refuses_rather_than_ignoring_it(self):
        r, kid, pk = self._signed("2026-03-15T12:00:00Z")
        keys = {kid: {"key": pk, "valid_until": "not-an-instant"}}
        out = A.verify_receipt(r, keys)
        self.assertFalse(out["ok"])
        self.assertIn("§9.2", out["why"])


# SHA-256 of the vendored key-window vectors, as merged into ScopeBlind/agent-governance-testvectors main at
# 1e24b5687 and copied here on 24/09/2026. examples/acta/key-window/SOURCE.md says "copied verbatim"; without this
# pin nothing in the repository could tell whether that stayed true, and a silently edited vector would make the
# suite pass for the wrong reason.
KW_SHA256 = {
    "after-valid-until.json": "0f53f76d5f4efaa34c698273b1f1b71b2770c09bd7c19fb7d1998ab5d399b047",
    "at-valid-from.json": "e0b4b42dbf7c963f8521de36a416ef10874ea8b3025ca1df33ec64f77248dee2",
    "at-valid-until.json": "5baa0a89c12412f783dbbb88906839b942c90e940eba08365ff76100c6529311",
    "before-valid-from.json": "cb3daa1ce9e88b4309e5d143785d5244d70d70c36597f5fad272bae8e57fbe8a",
    "index.json": "e206bcd0671f671d2dfe436245be95e9d79f139c2021d72c36266b03655b596f",
    "inside.json": "a7a971e1611b1dbdda4962a4e50444145338d246afaec4b54573795a5247e033",
    "jwks-no-window.json": "97a4c73529a3281664178d83652e5c44e5bc2f7126b146b7761cde0d1793a76c",
    "jwks.json": "1431ea457943455d7852d0d94a016de5a13a27442a9c901d5d09e074fc84a539"
}


class VendoredVectorsAreTheOnesPublished(unittest.TestCase):
    def test_the_vendored_bytes_match_their_pinned_digests(self):
        here = os.path.join(os.path.dirname(os.path.abspath(__file__)), "examples", "acta", "key-window")
        on_disk = sorted(f for f in os.listdir(here) if f.endswith(".json"))
        self.assertEqual(on_disk, sorted(KW_SHA256), "a vendored vector was added or removed")
        for name, want in sorted(KW_SHA256.items()):
            with open(os.path.join(here, name), "rb") as fh:
                got = hashlib.sha256(fh.read()).hexdigest()
            self.assertEqual(got, want, f"{name} no longer matches the bytes we vendored")


class AbsenceSideOfTheVerdict(unittest.TestCase):
    """A missing tool on this host must not be reported with the same verdict value as a bad signature.

    Measured before the fix: with `cryptography` absent, a valid receipt and a forged one both returned
    ok=False and CLI exit 1 — our own missing input reported as a finding about the artifact. The
    `assessed` field carries the absence side inside the verdict; `why` remains the sibling reason.
    """

    def _pair(self):
        import hashlib
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        sk = Ed25519PrivateKey.from_private_bytes(hashlib.sha256(b"test-only/absence").digest())
        pk = sk.public_key().public_bytes_raw()
        kid = A.issuer_kid(pk)
        body = {"type": "protectmcp:decision", "issued_at": "2026-03-15T12:00:00Z", "issuer_id": kid,
                "tool_name": "payments.transfer", "decision": "allow"}
        good = {"payload": body, "signature": {"alg": "EdDSA", "kid": kid, "sig": sk.sign(A.jcs(body)).hex()}}
        forged = json.loads(json.dumps(good))
        forged["signature"]["sig"] = ("0" if forged["signature"]["sig"][0] != "0" else "1") + forged["signature"]["sig"][1:]
        return good, forged, {kid: pk}

    def test_a_judgment_is_marked_assessed(self):
        good, forged, keys = self._pair()
        self.assertTrue(A.verify_receipt(good, keys)["ok"])
        v = A.verify_receipt(forged, keys)
        self.assertFalse(v["ok"])
        self.assertTrue(v["assessed"], "a forged signature is a judgment about the receipt, not an absence")

    def test_a_missing_library_is_not_a_finding_about_the_receipt(self):
        good, forged, keys = self._pair()
        with unittest.mock.patch.object(A, "_ed", side_effect=ImportError("cryptography not installed")):
            for name, r in (("valid", good), ("forged", forged)):
                v = A.verify_receipt(r, keys)
                self.assertFalse(v["ok"], name)                  # fail-closed: never a pass
                self.assertFalse(v["assessed"], f"{name}: the host could not judge it at all")
                self.assertEqual(v["verdict"], "not_assessed", name)
                self.assertIn("NOT verified", v["why"])

    def test_every_algorithm_of_the_profile_reports_its_own_absence(self):
        """The EdDSA path is not the only one: §6.9 names three algorithms and each has its own backend."""
        good, _forged, keys = self._pair()
        pq_kid, es_kid = "sb:issuer:PQPQPQPQPQPQ", "sb:issuer:ESESESESESES"
        keys = dict(keys, **{pq_kid: {"key": base64.b64encode(b"\0" * 1952).decode()}, es_kid: {"key": b"-----BEGIN PUBLIC KEY-----\n"}})
        pq = {"payload": {"type": "protectmcp:decision", "issued_at": "2026-03-15T12:00:01Z", "issuer_id": pq_kid,
                          "tool_name": "t", "decision": "allow"},
              "signature": {"alg": "ML-DSA-65", "kid": pq_kid, "sig": "ab" * 3309}}
        with self._no_pq_backend():
            v = A.verify_receipt(pq, keys)
        self.assertEqual(v["verdict"], "not_assessed", "a missing ML-DSA backend is an absence, not a bad signature")
        with unittest.mock.patch.object(A, "_ed", side_effect=ImportError("no backend")):
            self.assertEqual(A.verify_receipt(good, keys)["verdict"], "not_assessed")

    def test_the_chain_reports_which_receipts_were_not_assessed(self):
        good, _forged, keys = self._pair()
        with unittest.mock.patch.object(A, "_ed", side_effect=ImportError("cryptography not installed")):
            out = A.verify_chain([good], keys)
        self.assertFalse(out["ok"])                              # fail-closed
        self.assertFalse(out["assessed"])
        self.assertEqual([x["i"] for x in out["not_assessed"]], [0])
        self.assertTrue(out["problems"], "a not-assessed receipt still counts as a problem: ok must never read True")

    def _no_pq_backend(self):
        """An import hook that removes the ML-DSA backend, the way a host without cryptography>=48 has it."""
        import builtins
        real = builtins.__import__

        def hooked(name, *a, **k):
            if "mldsa" in name:
                raise ImportError("no ML-DSA backend on this host")
            if name.endswith("asymmetric") and len(a) > 2 and a[2] and "mldsa" in a[2]:
                raise ImportError("no ML-DSA backend on this host")
            return real(name, *a, **k)
        return unittest.mock.patch.object(builtins, "__import__", hooked)

    def test_an_absence_in_one_receipt_does_not_hide_a_judgment_on_another(self):
        """The level rule cuts both ways. A chain whose problems are ALL absences is not assessed; one that also
        carries a forged receipt is a judgment, and must not exit as "I could not look"."""
        good, forged, keys = self._pair()
        pq_kid = "sb:issuer:PQPQPQPQPQPQ"
        pq = {"payload": {"type": "protectmcp:decision", "issued_at": "2026-03-15T12:00:01Z", "issuer_id": pq_kid,
                          "tool_name": "payments.transfer", "decision": "allow"},
              "signature": {"alg": "ML-DSA-65", "kid": pq_kid, "sig": "ab" * 3309}}
        keys = dict(keys, **{pq_kid: {"key": base64.b64encode(b"\0" * 1952).decode()}})
        with self._no_pq_backend():
            mixed = A.verify_chain([forged, pq], keys)
            only_absent = A.verify_chain([pq], keys)
        self.assertFalse(mixed["ok"])
        self.assertEqual(mixed["verdict"], "fail", "a forged receipt beside an unverifiable one is still a judgment")
        self.assertEqual([x["i"] for x in mixed["not_assessed"]], [1])
        self.assertFalse(only_absent["ok"])
        self.assertEqual(only_absent["verdict"], "not_assessed", "every problem here is an absence")

    def test_a_broken_link_above_an_unassessed_receipt_is_still_a_judgment(self):
        """The §6.7 link is a hash: it needs no signature backend, so it stays checkable over a receipt this host
        could not verify. Skipping it there would hand a real finding to the absence side."""
        _good, _forged, keys = self._pair()
        pq_kid = "sb:issuer:PQPQPQPQPQPQ"
        keys = dict(keys, **{pq_kid: {"key": base64.b64encode(b"\0" * 1952).decode()}})
        pq = {"payload": {"type": "protectmcp:decision", "issued_at": "2026-03-15T12:00:01Z", "issuer_id": pq_kid,
                          "tool_name": "t", "decision": "allow"},
              "signature": {"alg": "ML-DSA-65", "kid": pq_kid, "sig": "ab" * 3309}}
        kid = next(k for k in keys if k != pq_kid)
        import hashlib as _h
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        sk = Ed25519PrivateKey.from_private_bytes(_h.sha256(b"test-only/absence").digest())

        def linked(prev_hash):
            b = {"type": "protectmcp:decision", "issued_at": "2026-03-15T12:00:02Z", "issuer_id": kid,
                 "tool_name": "t", "decision": "allow", "previousReceiptHash": prev_hash}
            return {"payload": b, "signature": {"alg": "EdDSA", "kid": kid, "sig": sk.sign(A.jcs(b)).hex()}}
        with self._no_pq_backend():
            right = A.verify_chain([pq, linked(A.receipt_hash(pq))], keys)
            wrong = A.verify_chain([pq, linked("sha256:" + "0" * 64)], keys)
        self.assertEqual(right["verdict"], "not_assessed", "only the unverifiable signature remains")
        self.assertEqual(wrong["verdict"], "fail", "the broken link is a finding and must outrank the absence")

    def test_an_unknown_issuer_is_an_absence_unless_the_caller_declares_its_list_complete(self):
        """A kid absent from `keys` is ambiguous: "not in my complete trust list" is a judgment, "I hold no key for
        that issuer" is an absence. Only the caller knows which, so it declares it; the default is the absence,
        because answering "invalid" about a signature never checked asserts something this host did not measure.
        Raised as AC-11 by @TKCollective and reached independently by @babyblueviper1 (x402-foundation/tsc#4)."""
        good, forged, keys = self._pair()
        v = A.verify_receipt(good, {})                       # valid receipt, issuer unknown here
        self.assertFalse(v["ok"])                            # fail-closed: never a pass
        self.assertEqual(v["verdict"], "not_assessed")
        self.assertIn("NOT checked", v["why"])
        v2 = A.verify_receipt(good, {}, keys_are_complete=True)
        self.assertEqual(v2["verdict"], "fail", "a complete trust list makes an unknown issuer a refusal")
        self.assertEqual(A.verify_receipt(forged, keys)["verdict"], "fail")   # a checked signature still judges
        self.assertEqual(A.verify_receipt(good, keys)["verdict"], "pass")

    def test_the_public_key_window_vectors_agree_on_all_three_columns(self):
        """The bench of ScopeBlind/agent-governance-testvectors (verifier-vectors/key-window, vendored from main at
        1e24b5687) states a verdict, a `code` and a `key_status` per case. Scoring only the verdict would pass a
        verifier that reaches the right answer for the wrong reason — which is what §5.5 exists to prevent."""
        here = os.path.join(os.path.dirname(os.path.abspath(__file__)), "examples", "acta", "key-window")
        with open(os.path.join(here, "index.json"), encoding="utf-8") as fh:
            idx = json.load(fh)

        def key_set(name):
            with open(os.path.join(here, name), encoding="utf-8") as fh:
                ks = {}
                for k in json.load(fh)["keys"]:
                    raw = (base64.urlsafe_b64decode(k["x"] + "=" * (-len(k["x"]) % 4)) if "x" in k
                           else bytes.fromhex(k["public_key_hex"]))
                    e = {"key": raw}
                    for w in ("valid_from", "valid_until"):
                        if w in k:
                            e[w] = k[w]
                    ks[k["kid"]] = e
                return ks

        self.assertEqual(len(idx["cases"]), 6)
        for case in idx["cases"]:
            with open(os.path.join(here, case["file"]), encoding="utf-8") as fh:
                receipt = json.load(fh)
            out = A.verify_receipt(receipt, key_set(case["jwks"]))
            got = "ACCEPT" if out["ok"] else "REJECT"
            label = f"{case['file']} / {case['jwks']}"
            self.assertEqual(got, case["expected"], label)
            self.assertEqual(out["code"], case["code"], label)
            self.assertEqual(out["key_status"], case["key_status"], label)

    def test_key_status_never_asserts_what_was_not_measured(self):
        """The cases the public bench does NOT exercise. A receipt refused before the key set is consulted must not
        claim anything about the key: it reports `not_reached`, not `unknown_key`."""
        good, _forged, keys = self._pair()
        kid = next(iter(keys))
        windowed = {kid: {"key": keys[kid], "valid_from": "2026-01-01T00:00:00Z", "valid_until": "2026-06-01T00:00:00Z"}}
        early = json.loads(json.dumps(good))
        early["signature"]["alg"] = "RS256"                       # refused at §6.9, long before the key set
        self.assertEqual(A.verify_receipt(early, windowed)["key_status"], "not_reached")
        del early["payload"]["tool_name"]
        self.assertEqual(A.verify_receipt(early, windowed)["key_status"], "not_reached")

        self.assertEqual(A.verify_receipt(good, {})["key_status"], "unknown_key")
        self.assertEqual(A.verify_receipt(good, {})["code"], "key_not_supplied")
        declared = A.verify_receipt(good, {}, keys_are_complete=True)
        self.assertEqual(declared["key_status"], "unknown_key")
        self.assertEqual(declared["code"], "issuer_not_trusted")

        bad_window = {kid: {"key": keys[kid], "valid_from": "not-an-instant"}}
        undec = A.verify_receipt(good, bad_window)
        self.assertEqual(undec["key_status"], "undecidable")
        self.assertEqual(undec["code"], "key_window_undecidable")

    def test_the_cli_reads_a_jwks_so_the_bench_runs_on_the_product(self):
        """The bench's declared invocation passes a JWKS. Without `--jwks` our §5.5 conformance would live only in
        the library, reachable through an adapter we wrote ourselves."""
        here = os.path.join(os.path.dirname(os.path.abspath(__file__)), "examples", "acta", "key-window")
        for name, want in (("inside.json", 0), ("after-valid-until.json", 1)):
            r = subprocess.run([sys.executable, A.__file__, "verify", os.path.join(here, name),
                                "--jwks", os.path.join(here, "jwks.json")], capture_output=True, text=True)
            self.assertEqual(r.returncode, want, r.stdout[:200])
            out = json.loads(r.stdout)
            self.assertIn(out["key_status"], ("inside", "outside"))

    def test_the_cli_exit_code_separates_absence_from_invalidity(self):
        good, forged, keys = self._pair()
        kid, pk = next(iter(keys.items()))
        with tempfile.TemporaryDirectory() as d:
            gp, fp = os.path.join(d, "g.json"), os.path.join(d, "f.json")
            for path, obj in ((gp, good), (fp, forged)):
                with open(path, "w") as fh:
                    fh.write(json.dumps(obj))
            key = f"{kid}={pk.hex()}"
            env = dict(os.environ)
            # A host without the signing library: exit 77 (not assessed), never 1 (invalid).
            stub = os.path.join(d, "stub")
            os.makedirs(stub)
            with open(os.path.join(stub, "cryptography.py"), "w") as fh:
                fh.write("raise ImportError('cryptography not installed')\n")
            env["PYTHONPATH"] = stub + os.pathsep + os.path.dirname(os.path.abspath(A.__file__))
            for path in (gp, fp):
                r = subprocess.run([sys.executable, A.__file__, "verify", "--key", key, path],
                                   capture_output=True, text=True, env=env)
                self.assertEqual(r.returncode, 77, f"{path}: {r.stdout[:200]}")
            # With the library present the verdicts stand apart: 0 for the valid one, 1 for the forged one.
            self.assertEqual(subprocess.run([sys.executable, A.__file__, "verify", "--key", key, gp],
                                            capture_output=True, text=True).returncode, 0)
            self.assertEqual(subprocess.run([sys.executable, A.__file__, "verify", "--key", key, fp],
                                            capture_output=True, text=True).returncode, 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
