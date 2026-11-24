#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""cryptovalid_acta — draft-farley-acta-signed-receipts-04 (-03 before 2026-11-23): KATs from the primary sources, the reference implementation's
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
NEEDS_CRYPTO = unittest.skipUnless(HAVE_CRYPTO, "needs `cryptography` (the `sign` extra)")
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
        self.assertTrue(any("5.8" in p["why"] for p in A.verify_chain(refs, {"conformance": PUB_HEX}, wrong_policy)["problems"]))   # -03 §6.8 = -04 §5.8
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
        # -04 §5.2: an envelope carries exactly payload and signature; anything else is a shape not recognized, which
        # -04 §5.4 makes undecidable (under -03 this module answered invalid)
        v = A.verify_receipt(dict(r1, public_key=PUB_HEX), {KID: PUB_HEX}); self.assertFalse(v["ok"]); self.assertIn("5.2", v["why"])
        self.assertEqual((v["outcome"], v["code"]), ("undecidable", "unrecognized_shape"))
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
        # round 1: a valid signature with hostile members OUTSIDE the signed bytes is a verdict, never an exception
        nan_sig = json.loads(json.dumps(r2)); nan_sig["signature"]["junk"] = float("nan")
        v = A.verify_receipt(nan_sig, {KID: PUB_HEX}); self.assertFalse(v["ok"]); self.assertIn("5.2", v["why"])
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
        # round 2: verify_chain reads the link from the SAME shape as the signature — a flat receipt with a decoy `payload`
        flat_g = {"type": "protectmcp:decision", "tool_name": "Read", "decision": "allow", "issued_at": "2026-09-20T09:00:00Z", "issuer_id": "conformance", "policy_digest": POLICY_DIGEST}
        flat_g["signature"] = sk.sign(A.jcs(flat_g)).hex()
        flat_h = {"type": "protectmcp:decision", "tool_name": "Bash", "decision": "deny", "issued_at": "2026-09-20T09:00:01Z", "issuer_id": "conformance",
                  "previousReceiptHash": "sha256:" + "0" * 64, "policy_digest": "sha256:" + "0" * 64,
                  "payload": {"previousReceiptHash": A.receipt_hash(flat_g), "policy_digest": POLICY_DIGEST}}                 # decoy members
        flat_h["signature"] = sk.sign(A.jcs(flat_h)).hex()
        v = A.verify_chain([flat_g, flat_h], {"conformance": PUB_HEX}, _policy_files()); self.assertFalse(v["ok"])
        self.assertTrue(any("5.7" in p["why"] for p in v["problems"]) and any("5.8" in p["why"] for p in v["problems"]), v["problems"])
        flat_ok = {k: v for k, v in flat_h.items() if k not in ("signature", "payload")}; flat_ok["previousReceiptHash"] = A.receipt_hash(flat_g); flat_ok["policy_digest"] = POLICY_DIGEST
        flat_ok["signature"] = sk.sign(A.jcs(flat_ok)).hex()
        self.assertTrue(A.verify_chain([flat_g, flat_ok], {"conformance": PUB_HEX}, _policy_files())["ok"])
        # round 2: an ES256 high-S twin verifies mathematically but would change the §6.7 hash → refused
        hi = json.loads(json.dumps(es)); hi["signature"]["sig"] = (rr.to_bytes(32, "big") + (A.P256_ORDER - ss).to_bytes(32, "big")).hex()
        self.assertTrue(A.verify_receipt(es, {"es": pem})["ok"]); v = A.verify_receipt(hi, {"es": pem}); self.assertFalse(v["ok"]); self.assertIn("low-S", v["why"])
        # instants, not just shapes; previous must be signed; issued_at_base UTC; Cedar literal safety
        for bad_ts in ("2026-99-99T99:99:99Z", "2026-02-30T00:00:00Z", "2026-09-20T09:00:00+25:00"):
            # correctly signed, not an instant: -04 §5.4 reports it apart (outcome unchanged); with a window, §5.6 undecidable
            v = A.verify_receipt(A.sign_receipt(dict(p1, issued_at=bad_ts), SEED), {KID: PUB_HEX})
            self.assertEqual(v["outcome"], "valid"); self.assertTrue(any("instant" in p for p in v["payload_problems"]))
            v = A.verify_receipt(A.sign_receipt(dict(p1, issued_at=bad_ts), SEED), {KID: {"key": PUB_HEX, "valid_from": "2026-01-01T00:00:00Z"}})
            self.assertEqual(v["outcome"], "undecidable"); self.assertIn("instant", v["why"])
            with self.assertRaises(ValueError):
                A.decision_payload("Read", "allow", KID, bad_ts)
        with self.assertRaises(ValueError):
            A.decision_payload("Read", "allow", KID, previous=p1)
        pay_s = dict(p1, signature="x")
        ps = {"payload": pay_s, "signature": {"alg": "EdDSA", "kid": KID, "sig": sk.sign(A.jcs(pay_s)).hex()}}   # signed as-is by a sloppy signer
        v = A.verify_receipt(ps, {KID: PUB_HEX}); self.assertFalse(v["ok"]); self.assertIn("5.2", v["why"])


class TestDriverAndCLI(unittest.TestCase):
    def test_cli_and_driver(self):
        if not HAVE_CRYPTO:
            self.skipTest("cryptography assente")
        with tempfile.TemporaryDirectory() as tmp:
            with open(os.path.join(tmp, "seed"), "w", encoding="utf-8", newline="") as f:
                f.write(SEED + "\n")
            run = lambda *a: subprocess.run([sys.executable, os.path.join(HERE, "cryptovalid_acta.py"), *a], capture_output=True, text=True, encoding="utf-8", cwd=HERE)
            r = run("policy-digest", POLICY_DIR); self.assertEqual(r.stdout.strip(), POLICY_DIGEST)
            r = run("sign", "--key", os.path.join(tmp, "seed"), "--tool", "Read", "--decision", "allow", "--policy-dir", POLICY_DIR, "--issued-at", "2026-09-20T09:00:00Z", "--out", os.path.join(tmp, "r1.json"))
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
            r = run("sign", "--key", os.path.join(tmp, "seed"), "--tool", "Bash", "--decision", "deny", "--policy-dir", POLICY_DIR, "--previous", os.path.join(tmp, "r1.json"), "--issued-at", "2026-09-20T09:00:01Z", "--out", os.path.join(tmp, "r2.json"))
            self.assertEqual(r.returncode, 0)
            r = run("verify", os.path.join(tmp, "r1.json"), os.path.join(tmp, "r2.json"), "--key", f"{KID}={PUB_HEX}", "--policy-dir", POLICY_DIR)
            self.assertEqual(r.returncode, 0, r.stdout); self.assertTrue(json.loads(r.stdout)["ok"])
            r = run("verify", os.path.join(tmp, "r2.json"), os.path.join(tmp, "r1.json"), "--key", f"{KID}={PUB_HEX}"); self.assertEqual(r.returncode, 1)
            r = run("verify", os.path.join(tmp, "nope.json")); self.assertEqual(r.returncode, 2); self.assertIn('"ok": false', r.stdout)
            with open(os.path.join(tmp, "deep.json"), "w", encoding="utf-8", newline="") as f:
                f.write("[" * 100000)
            # -04 §5.4: input that is not JSON this verifier reads is undecidable (exit 77), its cause named
            r = run("verify", os.path.join(tmp, "deep.json")); self.assertEqual(r.returncode, 77); self.assertNotIn("Traceback", r.stderr)
            self.assertEqual(json.loads(r.stdout)["code"], "input_not_json")
            with open(os.path.join(tmp, "dup.json"), "w", encoding="utf-8", newline="") as f:
                f.write('{"payload": {"a": 1, "a": 2}, "signature": {"alg": "EdDSA", "kid": "k", "sig": "00"}}')
            r = run("verify", os.path.join(tmp, "dup.json")); self.assertEqual(r.returncode, 77); self.assertIn("duplicate", r.stdout)
            os.makedirs(os.path.join(tmp, "nopolicy"))
            r = run("verify", os.path.join(tmp, "r1.json"), "--key", f"{KID}={PUB_HEX}", "--policy-dir", os.path.join(tmp, "nopolicy")); self.assertEqual(r.returncode, 2)
            r = run("verify", os.path.join(tmp, "r1.json"), "--key", f"{KID}={os.path.join(tmp, 'seed')}")            # a hex keyfile: not a public key → refused
            # 25/09: 32 seed bytes that are not even a curve point are unusable key material, refused at load (exit 2);
            # seed bytes that happen to decode stay a failed signature check (exit 1)
            with open(os.path.join(tmp, "seed"), encoding="utf-8") as sf:
                seed_bytes = bytes.fromhex(sf.read().strip())
            self.assertEqual(r.returncode, 2 if A._ed25519_problem(seed_bytes) else 1, r.stdout)
            with open(os.path.join(tmp, "pub.hex"), "w", encoding="utf-8", newline="") as f:
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
                with open(os.path.join(root, "fixtures", "inputs", f"{i:03d}.json"), "w", encoding="utf-8", newline="") as f:
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

    @NEEDS_CRYPTO
    def test_inside_the_window_is_accepted(self):
        r, kid, pk = self._signed("2026-03-15T12:00:00Z")
        keys = {kid: {"key": pk, "valid_from": "2026-01-01T00:00:00Z", "valid_until": "2026-06-01T00:00:00Z"}}
        self.assertTrue(A.verify_receipt(r, keys)["ok"])

    @NEEDS_CRYPTO
    def test_after_the_window_is_refused(self):
        r, kid, pk = self._signed("2026-07-15T12:00:00Z")
        keys = {kid: {"key": pk, "valid_from": "2026-01-01T00:00:00Z", "valid_until": "2026-06-01T00:00:00Z"}}
        out = A.verify_receipt(r, keys)
        self.assertFalse(out["ok"])
        self.assertIn("§5.6", out["why"])   # -03 §9.2 = -04 §5.6

    @NEEDS_CRYPTO
    def test_before_the_window_is_refused(self):
        r, kid, pk = self._signed("2025-12-31T23:59:59Z")
        keys = {kid: {"key": pk, "valid_from": "2026-01-01T00:00:00Z"}}
        self.assertFalse(A.verify_receipt(r, keys)["ok"])

    @NEEDS_CRYPTO
    def test_the_end_of_the_window_is_exclusive(self):
        # The draft states the SHOULD and nothing about boundaries. [from, until) is the only reading under which
        # two consecutive keys do not both own the instant of a rotation; this test pins the choice so it cannot
        # drift silently.
        r, kid, pk = self._signed("2026-06-01T00:00:00Z")
        keys = {kid: {"key": pk, "valid_until": "2026-06-01T00:00:00Z"}}
        self.assertFalse(A.verify_receipt(r, keys)["ok"])
        keys_next = {kid: {"key": pk, "valid_from": "2026-06-01T00:00:00Z"}}
        self.assertTrue(A.verify_receipt(r, keys_next)["ok"])

    @NEEDS_CRYPTO
    def test_without_a_window_nothing_changes(self):
        # §9.2 applies "when available": a relying party that supplies no window must see the previous behaviour,
        # in both the bare and the dict form.
        r, kid, pk = self._signed("2026-07-15T12:00:00Z")
        self.assertTrue(A.verify_receipt(r, {kid: pk})["ok"])
        self.assertTrue(A.verify_receipt(r, {kid: {"key": pk}})["ok"])

    @NEEDS_CRYPTO
    def test_a_leap_second_is_compared_and_not_skipped(self):
        # `_valid_instant` accepts :60 because RFC 3339 allows the form; before this, parsing it failed and the
        # window check was skipped, so a receipt could pass a window it should have been compared against.
        # Found by an independent review of the change, 23/09/2026.
        r, kid, pk = self._signed("2026-06-30T23:59:60Z")
        keys = {kid: {"key": pk, "valid_until": "2026-01-01T00:00:00Z"}}
        out = A.verify_receipt(r, keys)
        self.assertFalse(out["ok"])
        self.assertIn("§5.6", out["why"])   # -03 §9.2 = -04 §5.6
        # A leap second maps to :59.999999 of the same minute: ordered after :59 and before the next minute,
        # without asserting that a 61st second exists in the calendar Python models.
        self.assertLess(A._instant("2026-06-30T23:59:59Z"), A._instant("2026-06-30T23:59:60Z"))
        self.assertLess(A._instant("2026-06-30T23:59:60Z"), A._instant("2026-07-01T00:00:00Z"))

    def test_one_parser_only(self):
        # The two parsers disagreed before: `_valid_instant` accepted a leap second and the comparison parser did
        # not, so a value accepted as valid could not be compared and the window check was skipped. Found by two
        # independent reviews, 23/09/2026.
        for t in ("2026-06-30T23:59:60Z", "2026-03-15T12:00:00.12Z", "2026-03-15T12:00:00.1234567Z"):
            self.assertEqual(A._valid_instant(t), A._instant(t) is not None, t)

    @NEEDS_CRYPTO
    def test_an_extreme_date_gives_a_verdict_not_an_exception(self):
        # `.astimezone()` raised OverflowError on dates at the edges of the calendar, which `except ValueError`
        # did not catch: a traceback where the suite requires a verdict.
        r, kid, pk = self._signed("2026-03-15T12:00:00Z")
        for t in ("9999-12-31T23:00:00-05:00", "0001-01-01T00:00:00+01:00"):
            self.assertIsInstance(A._outside_window(t, {"valid_until": "2026-01-01T00:00:00Z"}), (tuple, type(None)), t)   # (kind, reason) since 26/09

    @NEEDS_CRYPTO
    def test_an_uncomparable_instant_refuses_when_a_window_is_declared(self):
        r, kid, pk = self._signed("2026-03-15T12:00:00Z")
        self.assertIsNotNone(A._outside_window("not-an-instant", {"valid_until": "2026-06-01T00:00:00Z"}))
        self.assertIsNone(A._outside_window("not-an-instant", {"key": pk}))   # nessuna finestra: nulla da confrontare

    @NEEDS_CRYPTO
    def test_a_malformed_window_refuses_rather_than_ignoring_it(self):
        r, kid, pk = self._signed("2026-03-15T12:00:00Z")
        keys = {kid: {"key": pk, "valid_until": "not-an-instant"}}
        out = A.verify_receipt(r, keys)
        self.assertFalse(out["ok"])
        self.assertIn("§5.6", out["why"])   # -03 §9.2 = -04 §5.6


# SHA-256 of the vendored key-window vectors, as merged into ScopeBlind/agent-governance-testvectors main at
# 1e24b5687 (the upstream bytes, re-fetched 26/09/2026: the 24/09 copies lacked their final newline, one byte per
# file, although SOURCE.md said "copied verbatim"). SOURCE.md documents the source and the re-fetch recipe; without this
# pin nothing in the repository could tell whether the bytes stayed the upstream ones, and a silently edited vector would make the
# suite pass for the wrong reason.
KW_SHA256 = {
    "after-valid-until.json": "a673b681b782dc21037038c5ee0a48f4147e842001ae54f52511be99a7a16083",
    "at-valid-from.json": "865ca94a14445cc5d7bd48351b7b9f7bd9df91f6c358484f47b4ae02894a25cb",
    "at-valid-until.json": "0b5751d679e10cbb1641253a02405d8a7e39fe1565314f120a091e232c01a631",
    "before-valid-from.json": "40ef841a77e51b27da749250ff33f7c0073e6637b89d42700344cb7f12f8b2bd",
    "index.json": "ba1ff57c97cb06bedee035dceeaa50bfb6fac4fbe9af21a4c91e00bbbca3e8f0",
    "inside.json": "ba3e6b02f2f1a0c9f6bb2339d7834404ae8603f5808ebabefa4c45885ab6dcbc",
    "jwks-no-window.json": "2c202b2a8618274325ead9855838cf454b4e51a33fd747e2bf1d9d4cc12e53b4",
    "jwks.json": "12652824994ccfbaa54cef1dc69ed55d62dbadcc288c4c6032e44ce0ed5a7111"
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


@NEEDS_CRYPTO
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
        # -04 §5.4: no key from a trust anchor = undecidable, complete list or not; the declaration changes the code only
        self.assertEqual((v2["verdict"], v2["code"]), ("not_assessed", "issuer_not_trusted"))
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
        """The cases the public bench does NOT exercise. Under -04 §5.4 every check runs, so `key_status` reports the
        window check that ran; a receipt whose shape is not recognized never reaches the key set: `not_reached`."""
        good, _forged, keys = self._pair()
        kid = next(iter(keys))
        windowed = {kid: {"key": keys[kid], "valid_from": "2026-01-01T00:00:00Z", "valid_until": "2026-06-01T00:00:00Z"}}
        early = json.loads(json.dumps(good))
        early["signature"]["alg"] = "RS256"                       # §5.9: undecidable, the window still measured
        v = A.verify_receipt(early, windowed)
        self.assertEqual((v["outcome"], v["code"], v["key_status"]), ("undecidable", "unsupported_algorithm", "inside"))
        self.assertNotIn("signature", v["checks"])                # never reported as checked
        early["extra"] = 1                                         # not an envelope any more (§5.2)
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
                                "--jwks", os.path.join(here, "jwks.json")], capture_output=True, text=True, encoding="utf-8")
            self.assertEqual(r.returncode, want, r.stdout[:200])
            out = json.loads(r.stdout)
            self.assertIn(out["key_status"], ("inside", "outside"))

    def test_the_cli_exit_code_separates_absence_from_invalidity(self):
        good, forged, keys = self._pair()
        kid, pk = next(iter(keys.items()))
        with tempfile.TemporaryDirectory() as d:
            gp, fp = os.path.join(d, "g.json"), os.path.join(d, "f.json")
            for path, obj in ((gp, good), (fp, forged)):
                with open(path, "w", encoding="utf-8", newline="") as fh:
                    fh.write(json.dumps(obj))
            key = f"{kid}={pk.hex()}"
            env = dict(os.environ)
            # A host without the signing library: exit 77 (not assessed), never 1 (invalid).
            stub = os.path.join(d, "stub")
            os.makedirs(stub)
            with open(os.path.join(stub, "cryptography.py"), "w", encoding="utf-8", newline="") as fh:
                fh.write("raise ImportError('cryptography not installed')\n")
            env["PYTHONPATH"] = stub + os.pathsep + os.path.dirname(os.path.abspath(A.__file__))
            for path in (gp, fp):
                r = subprocess.run([sys.executable, A.__file__, "verify", "--key", key, path],
                                   capture_output=True, text=True, encoding="utf-8", env=env)
                self.assertEqual(r.returncode, 77, f"{path}: {r.stdout[:200]}")
            # With the library present the verdicts stand apart: 0 for the valid one, 1 for the forged one.
            self.assertEqual(subprocess.run([sys.executable, A.__file__, "verify", "--key", key, gp],
                                            capture_output=True, text=True, encoding="utf-8").returncode, 0)
            self.assertEqual(subprocess.run([sys.executable, A.__file__, "verify", "--key", key, fp],
                                            capture_output=True, text=True, encoding="utf-8").returncode, 1)


B64U = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"


@unittest.skipUnless(HAVE_CRYPTO, "cryptography assente")
class MalformedInputsFound20260925(unittest.TestCase):
    """Malformed-input review of 25/09/2026 (NEMESIS + independent AI reviewers; each finding reproduced before
    the fix). Every test here was red on 0.16.0 and names the finding it pins."""

    def setUp(self):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        self.sk = Ed25519PrivateKey.from_private_bytes(hashlib.sha256(b"test-only/malformed").digest())
        self.pk = self.sk.public_key().public_bytes_raw()
        self.kid = A.issuer_kid(self.pk)
        self.x = base64.urlsafe_b64encode(self.pk).rstrip(b"=").decode()
        self.tmp = tempfile.TemporaryDirectory()
        self.d = self.tmp.name

    def tearDown(self):
        self.tmp.cleanup()

    def _receipt(self, issued_at="2026-09-25T00:00:00Z"):
        body = {"type": "protectmcp:decision", "issued_at": issued_at, "issuer_id": self.kid, "tool_name": "t", "decision": "allow"}
        return {"payload": body, "signature": {"alg": "EdDSA", "kid": self.kid, "sig": self.sk.sign(A.jcs(body)).hex()}}

    def _write(self, name, text):
        path = os.path.join(self.d, name)
        with open(path, "w", encoding="utf-8", newline="") as fh:
            fh.write(text if isinstance(text, str) else json.dumps(text))
        return path

    def _cli(self, *args):
        r = subprocess.run([sys.executable, A.__file__, "verify", *args], capture_output=True, text=True, encoding="utf-8")
        return r.returncode, r.stdout, r.stderr

    def _jwk(self, **over):
        """A JWK for the test key; a member set to None is removed."""
        k = {"kty": "OKP", "crv": "Ed25519", "kid": self.kid, "x": self.x, "use": "sig"}
        k.update(over)
        return {k2: v for k2, v in k.items() if v is not None}

    # 1 — a kid twice in the JWKS: the verdict depended on the order of the entries
    def test_1_a_duplicate_kid_in_the_jwks_is_refused_in_either_order(self):
        rp = self._write("r.json", self._receipt())
        expired, open_ = self._jwk(valid_until="2020-01-01T00:00:00Z"), self._jwk()
        for keys in ([expired, open_], [open_, expired]):
            code, out, err = self._cli(rp, "--jwks", self._write("j.json", {"keys": keys}))
            self.assertEqual(code, 2, out)
            self.assertIn("twice", json.loads(out)["error"])
        # the same ambiguity across sources: --jwks with a window, then --key for the same kid without one
        code, out, _ = self._cli(rp, "--jwks", self._write("j.json", {"keys": [expired]}), "--key", f"{self.kid}={self.pk.hex()}")
        self.assertEqual(code, 2, out)
        code, out, _ = self._cli(rp, "--key", f"{self.kid}={self.pk.hex()}", "--key", f"{self.kid}={self.pk.hex()}")
        self.assertEqual(code, 2, out)

    # 2 — the JWKS was read with plain json.load: a duplicate member resolved last-wins
    def test_2_the_jwks_is_read_with_the_strict_parser(self):
        rp = self._write("r.json", self._receipt())
        text = ('{"keys":[{"kty":"OKP","crv":"Ed25519","kid":"%s","x":"%s","valid_until":"2020-01-01T00:00:00Z","valid_until":null}]}'
                % (self.kid, self.x))
        code, out, _ = self._cli(rp, "--jwks", self._write("j.json", text))
        self.assertEqual(code, 2, out)
        self.assertIn("duplicate", json.loads(out)["error"])
        code, out, _ = self._cli(rp, "--jwks", self._write("j.json", '{"keys":[{"kty":"OKP","crv":"Ed25519","kid":"%s","x":"%s","valid_until":NaN}]}' % (self.kid, self.x)))
        self.assertEqual(code, 2, out)

    # 3 — kty/crv/alg/use were never read; x was decoded by a non-validating decoder
    def test_3_jwk_members_must_describe_an_ed25519_signature_key(self):
        rp = self._write("r.json", self._receipt())
        code, out, _ = self._cli(rp, "--jwks", self._write("ok.json", {"keys": [self._jwk(alg="EdDSA")]}))
        self.assertEqual(code, 0, out)                                       # positive control: a well-formed JWK passes
        # 26/09/2026 (A3): a JWK of another type or for another use is IGNORED (RFC 7517 §5), no longer refused with the
        # set: the receipt under its kid then finds no key — exit 77, never a pass — and the CLI says what it ignored.
        other = {"kty EC": self._jwk(kty="EC"), "crv X25519": self._jwk(crv="X25519"), "use enc": self._jwk(use="enc"),
                 "alg RS256": self._jwk(alg="RS256"), "key_ops sign only": self._jwk(key_ops=["sign"])}
        for name, jwk in other.items():
            code, out, err = self._cli(rp, "--jwks", self._write("j.json", {"keys": [jwk]}))
            self.assertEqual(code, 77, f"{name}: {out[:300]}")
            self.assertIn("ignored", err, name)
        # a key of OUR type that is malformed stays a configuration error of the key set: exit 2
        bad = {"no kty": self._jwk(kty=None), "no crv": self._jwk(crv=None),
               "x padded": self._jwk(x=self.x + "="), "x trailing junk": self._jwk(x=self.x + "!!"),
               "x trailing chars": self._jwk(x=self.x + "AAAA"), "x !!!!": self._jwk(x="!!!!"),
               "x standard alphabet": self._jwk(x="+" + self.x[1:]),
               "x non-canonical last char": self._jwk(x=self.x[:42] + B64U[B64U.index(self.x[42]) | 1]),   # same 32 bytes, other text
               "x and public_key_hex": self._jwk(public_key_hex=self.pk.hex())}
        for name, jwk in bad.items():
            code, out, _ = self._cli(rp, "--jwks", self._write("j.json", {"keys": [jwk]}))
            self.assertEqual(code, 2, f"{name}: {out[:300]}")
            self.assertIn("--jwks", json.loads(out)["error"], name)

    # 4 — `\d` is Unicode in Python: an issued_at in Arabic-Indic or fullwidth digits passed, and "inside" a window
    def test_4_issued_at_digits_are_ascii_only(self):
        window = {self.kid: {"key": self.pk, "valid_from": "2020-01-01T00:00:00Z", "valid_until": "2030-01-01T00:00:00Z"}}
        for t in ("٢٠٢٦-٠٩-٢٥T٠٠:٠٠:٠٠Z", "２０２６-０９-２５T００:００:００Z", "2026-09-25T00:00:0٠Z", "2026-09-25T00:00:00.٥Z"):
            self.assertIsNone(A._instant(t), t)
            self.assertFalse(A._valid_instant(t), t)
            self.assertIsNone(A._RFC3339.match(t), t)
            # -04 §5.4: a payload member that does not conform is reported apart and does not change the outcome;
            # -04 §5.6: with a window, an issued_at that is not an instant leaves it unapplied: undecidable
            v = A.verify_receipt(self._receipt(t), {self.kid: self.pk})
            self.assertEqual(v["outcome"], "valid", t)
            self.assertTrue(any("RFC 3339" in p for p in v["payload_problems"]), t)
            v = A.verify_receipt(self._receipt(t), window)
            self.assertEqual((v["outcome"], v["code"]), ("undecidable", "key_window_undecidable"), t)
            self.assertIn("RFC 3339", v["why"], t)
            with self.assertRaises(ValueError):
                A.decision_payload("t", "allow", self.kid, t)
        # the audit, as a guard: every compiled pattern of the module is ASCII-only
        import re as _re
        pats = {n: o for n, o in vars(A).items() if isinstance(o, _re.Pattern)}
        self.assertGreaterEqual(len(pats), 5)
        for n, o in pats.items():
            self.assertTrue(o.flags & _re.ASCII, f"{n} is not compiled with re.ASCII")
            self.assertNotIn(r"\d", o.pattern, n)

    # 5 — the relying party's unusable key was reported as a finding about the receipt
    def test_5_unusable_key_material_is_not_a_finding_about_the_receipt(self):
        r = self._receipt()
        for name, key in (("float", 1.5), ("int", 7), ("bool", True), ("list", [1, 2]), ("None in dict", {}),
                          ("empty str", ""), ("!!!!", "!!!!"), ("odd hex", "abc"), ("non-hex 64", "zz" * 32),
                          ("5 bytes", b"12345"), ("empty bytes", b""), ("broken PEM", b"-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n")):
            entry = key if name == "None in dict" else {"key": key}
            v = A.verify_receipt(r, {self.kid: entry})
            self.assertEqual(v["verdict"], "not_assessed", name)
            self.assertFalse(v["ok"], name)                                    # fail-closed: never a pass
            self.assertFalse(v["assessed"], name)
            self.assertEqual(v["code"], "key_material_invalid", name)
            self.assertEqual(v["key_status"], "no_window", name)               # the key set WAS consulted
        # uppercase hex is a key, not a defect
        self.assertEqual(A.verify_receipt(r, {self.kid: self.pk.hex().upper()})["verdict"], "pass")
        # a USABLE key of another type than the receipt's alg stays a judgment: flipping the unsigned alg of a forged
        # receipt must not buy it "could not look"
        flipped = json.loads(json.dumps(r)); flipped["signature"]["alg"] = "ES256"
        self.assertEqual(A.verify_receipt(flipped, {self.kid: self.pk.hex()})["verdict"], "fail")
        flipped["signature"]["alg"] = "ML-DSA-65"
        self.assertEqual(A.verify_receipt(flipped, {self.kid: self.pk})["verdict"], "fail")
        forged = json.loads(json.dumps(r)); forged["payload"]["decision"] = "deny"
        self.assertEqual(A.verify_receipt(forged, {self.kid: self.pk})["verdict"], "fail")
        # a `keys` argument that is not a mapping is a programming error, named as such
        for bad_keys in (None, [self.kid], "abc"):
            with self.assertRaises(TypeError):
                A.verify_receipt(r, bad_keys)
        # the total order still holds in a chain: a forged receipt beside an unusable key is a fail
        other = "sb:issuer:OTHEROTHEROT"
        body = dict(r["payload"], issuer_id=other)
        r2 = {"payload": body, "signature": {"alg": "EdDSA", "kid": other, "sig": self.sk.sign(A.jcs(body)).hex()}}
        mixed = A.verify_chain([forged, r2], {self.kid: self.pk, other: 1.5})
        self.assertEqual(mixed["verdict"], "fail")
        only = A.verify_chain([r2], {other: 1.5})
        self.assertEqual(only["verdict"], "not_assessed")
        # CLI: refused at load (exit 2); uppercase hex accepted, inline and in a keyfile
        rp = self._write("r.json", r)
        self.assertEqual(self._cli(rp, "--key", f"{self.kid}={self.pk.hex().upper()}")[0], 0)
        self.assertEqual(self._cli(rp, "--key", f"{self.kid}={self._write('up.hex', self.pk.hex().upper() + chr(10))}")[0], 0)
        for name, content in (("empty", ""), ("junk", "not a key\n"), ("63 hex", self.pk.hex()[:63])):
            code, out, _ = self._cli(rp, "--key", f"{self.kid}={self._write('k.' + name, content)}")
            self.assertEqual(code, 2, f"{name}: {out[:300]}")
            self.assertIn("unusable key material", json.loads(out)["error"], name)
        code, out, _ = self._cli(rp, "--jwks", self._write("j.json", {"keys": [self._jwk(x="!!!!")]}))
        self.assertEqual(code, 2, out)

    # 6 — internal exceptions reached the user as the error message
    def test_6_malformed_arguments_and_deep_nesting_get_explicit_messages(self):
        rp = self._write("r.json", self._receipt())
        code, out, err = self._cli(rp, "--key", self.pk.hex())
        self.assertEqual(code, 2, out)
        msg = json.loads(out)["error"]
        self.assertIn("kid=", msg)
        self.assertNotIn("unpack", msg)
        for flag in ("receipt", "--jwks"):
            deep = self._write("deep.json", "[" * 200000 + "]" * 200000)
            args = (deep,) if flag == "receipt" else (rp, "--jwks", deep)
            code, out, err = self._cli(*args)
            # a receipt that is not JSON this verifier reads is undecidable (-04 §5.4, exit 77); a key set is a usage error
            self.assertEqual(code, 77 if flag == "receipt" else 2, out[:300])
            msg = json.loads(out)["why" if flag == "receipt" else "error"]
            self.assertIn("nesting deeper than 512", msg, flag)
            self.assertNotIn("Recursion", msg, flag)
            self.assertNotIn("Traceback", err, flag)
        # brackets inside strings are not nesting
        shallow = self._receipt(); shallow["payload"]["reason"] = "[" * 5000
        body = shallow["payload"]; shallow["signature"]["sig"] = self.sk.sign(A.jcs(body)).hex()
        self.assertEqual(self._cli(self._write("s.json", shallow), "--key", f"{self.kid}={self.pk.hex()}")[0], 0)


@NEEDS_CRYPTO
class SmallOrderKeys20260925(unittest.TestCase):
    """A small-order Ed25519 key makes R=identity, S=0 a signature on EVERY message, and OpenSSL accepts it (measured
    25/09/2026, 4-mind review round 2, finding A1). Red before the check: the forged receipt passed."""
    TORSION = ["01" + "00" * 31, "ec" + "ff" * 30 + "7f", "00" * 32, "00" * 31 + "80",
               "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
               "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
               "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
               "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa"]

    def setUp(self):
        self.seed = "33" * 32
        self.kid = A.issuer_kid(A.pubkey_from_seed(self.seed))
        self.rec = A.sign_receipt(A.decision_payload("t", "allow", self.kid, "2026-09-25T00:00:00Z", None, "s", "r"), self.seed, self.kid)

    def _forged(self, key_hex):
        f = json.loads(json.dumps(self.rec))
        f["payload"]["tool_name"] = "anything-at-all"
        f["signature"]["sig"] = ("01" + "00" * 31) + "00" * 32      # R = identity, S = 0
        return f

    def test_library_never_passes_a_small_order_key(self):
        for h in self.TORSION:
            for key in (bytes.fromhex(h), h):
                out = A.verify_receipt(self._forged(h), {self.kid: key})
                self.assertNotEqual(out["verdict"], "pass", h)
                self.assertEqual((out["verdict"], out.get("code")), ("not_assessed", "key_material_invalid"), h)

    def test_non_canonical_encodings_refused(self):
        p = 2 ** 255 - 19
        for y in (p, p + 1):
            self.assertIsNotNone(A._ed25519_problem(y.to_bytes(32, "little")))

    def test_real_keys_are_not_refused(self):
        for i in range(200):
            pk = A.pubkey_from_seed(hashlib.sha256(bytes([i])).hexdigest())
            self.assertIsNone(A._ed25519_problem(pk))
        self.assertEqual(A.verify_receipt(self.rec, {self.kid: A.pubkey_from_seed(self.seed)})["verdict"], "pass")

    def test_cli_and_jwks_refuse_at_load(self):
        ident = "01" + "00" * 31
        x = base64.urlsafe_b64encode(bytes.fromhex(ident)).decode().rstrip("=")
        with self.assertRaises(ValueError):
            A.keys_from_jwks({"keys": [{"kid": self.kid, "kty": "OKP", "crv": "Ed25519", "x": x}]})
        with self.assertRaises(ValueError):
            A.keys_from_jwks({"keys": [{"kid": self.kid, "public_key_hex": ident}]})
        with self.assertRaises(ValueError):
            A._cli_key(f"{self.kid}={ident}")




@unittest.skipUnless(HAVE_CRYPTO, "cryptography assente")
class RefusalCodes20260926(unittest.TestCase):
    """26/09: agent-evidence-vectors 0.13.0 (vectors-receipt-signature) requires `code` on every refusal. All 26 verdicts
    agreed, but 8 refusals carried code null: the reason was only in the free-text `why`."""

    def _signed(self):
        p = A.decision_payload("Read", "allow", KID, "2026-09-20T09:00:00.001Z", POLICY_DIGEST, "s1", extra={"sequence": 1})
        return A.sign_receipt(p, SEED)

    def test_bad_signature_is_signature_invalid(self):
        r = self._signed(); sig = r["signature"]["sig"]
        r["signature"]["sig"] = ("0" if sig[0] != "0" else "1") + sig[1:]
        v = A.verify_receipt(r, {KID: PUB_HEX})
        self.assertEqual((v["verdict"], v["code"]), ("fail", "signature_invalid"))

    def test_signature_member_in_payload_is_signature_in_signing_input(self):
        for member in (None, "", "abc"):
            r = self._signed(); r["payload"]["signature"] = member
            v = A.verify_receipt(r, {KID: PUB_HEX})
            self.assertEqual((v["verdict"], v["code"]), ("fail", "signature_in_signing_input"), member)

    def test_valid_receipt_still_has_no_code(self):
        v = A.verify_receipt(self._signed(), {KID: PUB_HEX})
        self.assertEqual((v["verdict"], v["code"]), ("pass", None))


@unittest.skipUnless(HAVE_CRYPTO, "cryptography assente")
class OpenPointsA3_20260926(unittest.TestCase):
    """The seven ACTA points left open on 25/09, each measured on the code of 26/09 before the fix (probe in the
    session): 2 undue PASS, 2 undue FAIL, 1 whole-set refusal, 1 accepted impossible leap second, 1 hang."""

    def setUp(self):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives import serialization as S
        self.S = S
        self.sk = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(SEED))
        pub = self.sk.public_key().public_bytes(S.Encoding.Raw, S.PublicFormat.Raw)
        self.okp = {"kty": "OKP", "crv": "Ed25519", "kid": KID, "x": base64.urlsafe_b64encode(pub).rstrip(b"=").decode()}

    def _rec(self, issued_at="2026-09-20T09:00:00.001Z"):
        return A.sign_receipt(A.decision_payload("Read", "allow", KID, issued_at, POLICY_DIGEST, "s1", extra={"sequence": 1}), SEED)

    def test_1_a_key_this_reader_does_not_understand_is_ignored_not_the_whole_set(self):
        ec = {"kty": "EC", "crv": "P-256", "kid": "other-ec", "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
              "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"}
        keys = A.keys_from_jwks({"keys": [ec, self.okp]})            # RFC 7517 §5: SHOULD ignore kty not understood
        self.assertNotIn("other-ec", keys)
        self.assertEqual(A.verify_receipt(self._rec(), keys)["verdict"], "pass")
        with self.assertRaises(ValueError):                           # a duplicate kid stays refused, ignored entry or not
            A.keys_from_jwks({"keys": [dict(ec, kid=KID), self.okp]})

    def test_2_key_ops_without_verify_does_not_verify(self):
        keys = A.keys_from_jwks({"keys": [dict(self.okp, key_ops=["encrypt"])]})
        self.assertNotEqual(A.verify_receipt(self._rec(), keys)["verdict"], "pass")
        keys = A.keys_from_jwks({"keys": [dict(self.okp, key_ops=["verify"])]})
        self.assertEqual(A.verify_receipt(self._rec(), keys)["verdict"], "pass")

    def test_3_a_leap_second_exists_only_at_23_59_utc(self):
        self.assertFalse(A._valid_instant("2026-09-20T10:15:60Z"))
        self.assertTrue(A._valid_instant("2016-12-31T23:59:60Z"))
        self.assertTrue(A._valid_instant("2017-01-01T00:59:60+01:00"))     # 23:59:60 UTC written with an offset

    def test_4_window_bounds_are_compared_exactly_not_at_microseconds(self):
        keys = A.keys_from_jwks({"keys": [dict(self.okp, valid_from="2026-09-20T09:00:00.0000001Z")]})
        v = A.verify_receipt(self._rec("2026-09-20T09:00:00.0000000Z"), keys)
        self.assertEqual((v["verdict"], v["code"]), ("fail", "key_outside_validity_window"))
        v = A.verify_receipt(self._rec("2026-09-20T09:00:00.0000001Z"), keys)
        self.assertEqual(v["verdict"], "pass")

    def test_5_a_malformed_window_of_the_relying_party_is_not_a_finding_about_the_receipt(self):
        v = A.verify_receipt(self._rec(), {KID: {"key": self.okp and bytes.fromhex(PUB_HEX), "valid_until": "tomorrow"}})
        self.assertEqual((v["verdict"], v["assessed"]), ("not_assessed", False))
        with self.assertRaises(ValueError):                           # and the CLI loader refuses it (exit 2)
            A.keys_from_jwks({"keys": [dict(self.okp, valid_until="tomorrow")]})

    def test_6_an_ed25519_key_file_in_pem_or_der_verifies(self):
        with tempfile.TemporaryDirectory() as d:
            for enc, name in ((self.S.Encoding.PEM, "k.pem"), (self.S.Encoding.DER, "k.der")):
                p = os.path.join(d, name)
                with open(p, "wb") as f:
                    f.write(self.sk.public_key().public_bytes(enc, self.S.PublicFormat.SubjectPublicKeyInfo))
                kid, mat = A._cli_key(f"{KID}={p}")
                self.assertEqual(A.verify_receipt(self._rec(), {kid: mat})["verdict"], "pass", name)

    def test_7_a_fifo_is_refused_not_waited_on(self):
        import threading
        with tempfile.TemporaryDirectory() as d:
            fifo = os.path.join(d, "f.json"); os.mkfifo(fifo)
            res = {}
            def run():
                try:
                    A.load_json_strict(fifo); res["r"] = "read"
                except (OSError, ValueError) as e:
                    res["r"] = "refused: " + str(e)
            th = threading.Thread(target=run, daemon=True); th.start(); th.join(3)
            self.assertIn("not a regular file", res.get("r", "blocked"))     # the reason, not any refusal (a JSON error would pass)
        with self.assertRaises(OSError) as cm:                                  # a device is refused before any read
            A.load_json_strict("/dev/zero")
        self.assertIn("not a regular file", str(cm.exception))


class ReviewFindings20260926(unittest.TestCase):
    """Independent review of the A3 change (26/09/2026), each finding reproduced before the fix."""

    def test_leap_second_orders_after_every_digit_of_59(self):
        # the 12-digit offset used for :60 let a 13-digit :59 bound sort after it: a receipt issued at 23:59:60.5 passed
        # a valid_until of 23:59:59.99999999999999 (PASS after valid_until)
        self.assertLess(A._instant_exact("2016-12-31T23:59:59.9999999999999999Z"), A._instant_exact("2016-12-31T23:59:60Z"))
        self.assertLess(A._instant_exact("2016-12-31T23:59:60.999999999999999Z"), A._instant_exact("2017-01-01T00:00:00Z"))
        w = A._outside_window("2016-12-31T23:59:60.5Z", {"valid_until": "2016-12-31T23:59:59.99999999999999Z"})
        self.assertEqual(w[0] if w else None, "outside")

    def test_a_very_long_fraction_gives_a_verdict_not_an_exception(self):
        # review 26/09: int() of >4300 digits raised ValueError out of verify_receipt (Python >= 3.11)
        t = "2026-09-20T09:00:00." + "1" * 5000 + "Z"
        key = A._instant_exact(t)
        self.assertIsNotNone(key)
        self.assertLess(A._instant_exact("2026-09-20T09:00:00.1111Z"), key)
        self.assertLess(key, A._instant_exact("2026-09-20T09:00:00.2Z"))
        self.assertEqual(A._instant_exact("2026-09-20T09:00:00.50Z"), A._instant_exact("2026-09-20T09:00:00.5Z"))
        self.assertEqual(A._instant_exact("2026-09-20T09:00:00.000Z"), A._instant_exact("2026-09-20T09:00:00Z"))
        self.assertIsNone(A._outside_window(t, {"valid_from": "2026-01-01T00:00:00Z"}))

    def test_a_malformed_bound_leaves_the_window_unapplied(self):
        # Under -03 a readable bound that excluded the receipt decided (review of 26/09). -04 §5.6: "If the window
        # cannot be applied, because a bound is not a valid timestamp ... the outcome is undecidable".
        w = A._outside_window("2026-01-01T00:00:00Z", {"valid_from": "2026-06-01T00:00:00Z", "valid_until": "garbage"})
        self.assertEqual(w[0], "bound")
        w = A._outside_window("2026-07-01T00:00:00Z", {"valid_from": "2026-06-01T00:00:00Z", "valid_until": "garbage"})
        self.assertEqual(w[0], "bound")                       # inside the readable bound: the unreadable one decides nothing


# SHA-256 of the vendored chain-link and embedded-key vectors (ScopeBlind/agent-governance-testvectors at 5c749de,
# fetched 2026-11-23; examples/acta/chain-link/SOURCE.md has the source and the re-fetch recipe).
CL_SHA256 = {
    "chain-link/bare-hex-link.json": "2ad6bea058a1a847e0b8f99bb8e6274c31decfb554a59f20740a65cec0abdaba",
    "chain-link/base64url-link.json": "fcf8eb0711dd3a24007212775af0febe7a2ce90b261fc4943e0b0a8362852ce0",
    "chain-link/empty-link.json": "a72d8be59b76a18b3a35fd952c6201e552255e181b2781bdb432379b2c6b06d7",
    "chain-link/genesis.json": "90613a05be1864856f141114e748e51d6bd1bca75083086a098f0d491405cc17",
    "chain-link/index.json": "b92533bc792e1e8de608e3b5855c22b12752685e41d9c18b55eb47e3e4ec1616",
    "chain-link/jwks.json": "5de65661ae63403fc6db476c7d21f603bd6084bc30135dac6cd23a4840f4a947",
    "chain-link/jwks-window-ended.json": "5e6d9f41c3b6a4b4196efc993c8d939503cbd4b0a5081318a76eb206ed34e749",
    "chain-link/linked.json": "1625248b8808cd59f47a0111481ed6e2de049af7bd0d6aaa9456015c115a137f",
    "chain-link/malformed-digest.json": "e50911404d120601ece20b5401572a9626d3a979b0ee903bc73123b3105b0031",
    "chain-link/no-link.json": "1d48d567e3604b906233eb509be51f0b1c7fc3e930c2847ebca8b56962bad452",
    "chain-link/non-string-link.json": "4e8237536b9a3bbaa4ccfdd035821a388a29c3f50417e789b9033af8fa4eb071",
    "chain-link/null-link.json": "f7a53aa50119572a18be90f723f3b5550b2d6df5e756124432bd0020139cfa76",
    "chain-link/payload-only-link.json": "26625f8254aa7c19f817c15432a2d1da21f3b579a8f67b89b14a31d805664ae7",
    "chain-link/sequence-first-linked.jsonl": "7b83c5882ef4d199d2542cd3e0857eff90feae5512a40bdc6ac5fd8f84d1cbbb",
    "chain-link/sequence-linked.jsonl": "1af763974c9147b17bc030ac16b078a5ffce1366f00e65e6452eec8fd34b0fea",
    "chain-link/sequence-new-chain.jsonl": "94f14d6db83bc88d9bd13346f7e0dfb813c908cf873a660266eb2538b3f62786",
    "chain-link/sequence-null-link.jsonl": "5f58a4d1d23010ce008c33fd3352fb38183f212e6c2b890b36c5d3c4afc8b2cd",
    "chain-link/sequence-payload-only.jsonl": "f4dbb63d271e82913b665a60d166113ad8ffb981cb0088450d93e6c90992ffb3",
    "chain-link/sha3-256-link.json": "3233f39aa5ba30f8e5dcfcd1532047074fe9e30bb285cf7ed330e09dc0fcd2b9",
    "chain-link/sha512-link.json": "26867357901907160a2bfaed03a644fb1a243bce81e1e5e3770f55f76dc74f55",
    "chain-link/short-digest.json": "538d8e07ca4029f1ffb84dfd07e9a7495ad7ffe6feee1d235f8c644e4d144367",
    "chain-link/uppercase-hex.json": "30dd91d8f72dfe1a47ed65b4dd8a1d8292f98853ac0d8261430f1f8124f41edb",
    "embedded-key/acta-envelope.json": "54281d5aa54b80d66d9ffe48f8dcd3c7935f763e724c3aaa6071500278d1ac2c",
    "embedded-key/decision-receipt.json": "ecc93bdcbaa4dce42d6ea70b84b7e58ce07850dd7d9b8b168447fc7d3a421455",
}
EXIT_OF = {"valid": 0, "invalid": 1, "undecidable": 77}


def _link_form_oracle(v):
    """-04 §5.7 read independently of `link_form`: character by character, no regular expression."""
    if v is None:
        return "null"
    if not isinstance(v, str):
        return "malformed"
    lower_hex = set("0123456789abcdef")
    body = v[7:] if v.startswith("sha256:") else v
    if len(body) == 64 and all(c in lower_hex for c in body):
        return "link"
    if ":" in v:
        name = v.split(":", 1)[0]
        ascii_alnum = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")
        if name and name[0] in ascii_alnum and all(c in ascii_alnum or c in "._+-" for c in name) \
                and name.translate(str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz")) != "sha256":
            return "other_algorithm"
    return "malformed"


@NEEDS_CRYPTO
class Draft04_20261123(unittest.TestCase):
    """draft-farley-acta-signed-receipts-04 (datatracker, 2026-11-22). Every test here fails on the -03 code (commit
    b784901): measured on 2026-11-23 by running this class against that module."""

    VEC = os.path.join(HERE, "examples", "acta")

    def _cli(self, *args):
        r = subprocess.run([sys.executable, A.__file__, "verify", *args], capture_output=True, text=True, encoding="utf-8")
        try:
            return r.returncode, json.loads(r.stdout), r.stderr
        except ValueError:
            return r.returncode, {}, r.stdout + r.stderr

    def test_vendored_vectors_are_the_published_bytes(self):
        on_disk = sorted(f"{d}/{f}" for d in ("chain-link", "embedded-key") for f in os.listdir(os.path.join(self.VEC, d))
                         if f.endswith((".json", ".jsonl")))
        self.assertEqual(on_disk, sorted(CL_SHA256))
        for name, want in CL_SHA256.items():
            with open(os.path.join(self.VEC, name), "rb") as fh:
                self.assertEqual(hashlib.sha256(fh.read()).hexdigest(), want, name)

    def test_the_chain_link_suite_through_the_command(self):
        """All 27 cases of verifier-vectors/chain-link: outcome as exit status, the code that decided, and for a
        sequence the number of chains and the warning on a null link."""
        d = os.path.join(self.VEC, "chain-link")
        with open(os.path.join(d, "index.json"), encoding="utf-8") as fh:
            idx = json.load(fh)
        self.assertEqual(len(idx["cases"]), 27)
        with tempfile.TemporaryDirectory() as tmp:
            for n, c in enumerate(idx["cases"]):
                args = []
                if c["check"] == "sequence":
                    with open(os.path.join(d, c["file"]), encoding="utf-8") as fh:
                        for i, line in enumerate(row for row in fh if row.strip()):
                            p = os.path.join(tmp, f"{n}-{i}.json")
                            with open(p, "w", encoding="utf-8", newline="") as out:
                                out.write(line)
                            args.append(p)
                    args.append("--sequence")
                else:
                    args = ([os.path.join(d, c["previous"])] if c.get("previous") else []) + [os.path.join(d, c["file"])]
                if c.get("jwks"):
                    args += ["--jwks", os.path.join(d, c["jwks"])]
                rc, out, err = self._cli(*args)
                label = f"{c['file']} / {c['check']} / {c.get('previous')} / {c.get('jwks')}"
                self.assertEqual(rc, EXIT_OF[c["outcome"]], f"{label}: {out or err}")
                self.assertEqual(out["outcome"], c["outcome"], label)
                self.assertEqual(out["code"], c["code"], label)
                if c["check"] == "sequence":
                    self.assertEqual(len(out["chains"]), c["chains"], label)
                    self.assertEqual(len(out["chain_breaks"]), c["chain_breaks"], label)
                if c.get("warn"):
                    notes = out.get("notes", []) + [w["why"] for w in out.get("warnings", [])]
                    self.assertTrue(any("null" in w and "MUST NOT" in w for w in notes), label)

    def test_a_carried_key_is_never_trusted(self):
        """negative/embedded-key: no key from outside -> undecidable `embedded_key_rejected`; a valid key that did not
        sign -> invalid; and the positive control the suite's script asks for: under the key it carries the receipt
        verifies, so the refusal above is the rule of §8.5 and not a receipt that cannot verify at all."""
        bystander = "7422b9887598068e32c4448a949adb290d0f4e35b9e01b0ee5f1a1e600fe2674"
        for name in ("acta-envelope.json", "decision-receipt.json"):
            path = os.path.join(self.VEC, "embedded-key", name)
            with open(path, encoding="utf-8") as fh:
                r = json.load(fh)
            kid = r["signature"]["kid"] if isinstance(r["signature"], dict) else r["kid"]
            carried = (r["payload"] if isinstance(r["signature"], dict) else r)["public_key"]
            rc, out, _ = self._cli(path)
            self.assertEqual((rc, out["outcome"], out["code"]), (77, "undecidable", "embedded_key_rejected"), name)
            rc, out, _ = self._cli(path, "--key", f"{kid}={bystander}")
            self.assertEqual((rc, out["outcome"]), (1, "invalid"), name)
            rc, out, _ = self._cli(path, "--key", f"{kid}={carried}")
            self.assertEqual((rc, out["outcome"], out["checks"].get("carried_key")), (0, "valid", "pass"), name)
        # every documented form of the same key is that key, on every Python (padded base64 was key_mismatch on 3.11/3.13)
        import base64
        sk, pk = self._keyed()
        base = {"type": "x:y", "issued_at": "2026-03-01T00:00:00Z", "issuer_id": "k04"}
        b64, b64u = base64.b64encode(pk).decode(), base64.urlsafe_b64encode(pk).decode()
        self.assertTrue(b64.endswith("="))
        jwk = {"kty": "OKP", "crv": "Ed25519", "x": b64u.rstrip("=")}
        for same in (pk.hex(), pk.hex().upper(), b64, b64u, b64.rstrip("="), b64u.rstrip("="), b64 + "=", jwk, dict(jwk, x=b64u)):
            v = A.verify_receipt(self._env(sk, dict(base, public_key=same)), {"k04": pk})
            self.assertEqual((v["outcome"], v["checks"]["carried_key"]), ("valid", "pass"), same)
        other = hashlib.sha256(b"other").digest()
        for not_it in (other.hex(), base64.b64encode(other).decode(), None, "zz", [pk.hex()], pk.hex() + "00", b64[:-2],
                       dict(jwk, kty="EC"), dict(jwk, crv="X25519"), dict(jwk, x=None)):
            v = A.verify_receipt(self._env(sk, dict(base, public_key=not_it)), {"k04": pk})
            self.assertEqual((v["outcome"], v["code"]), ("invalid", "key_mismatch"), not_it)
        # each carried member is compared: one that is the key does not hide one that is not, in either order
        for first, second in ((pk.hex(), other.hex()), (other.hex(), pk.hex())):
            v = A.verify_receipt(self._env(sk, dict(base, public_key=first, verification_jwk=second)), {"k04": pk})
            self.assertEqual((v["outcome"], v["code"]), ("invalid", "key_mismatch"))
        # a relying-party key held as PEM (ES256) is not compared: undecidable, never a mismatch and never valid
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
        ek = ec.generate_private_key(ec.SECP256R1())
        pem = ek.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        pay = dict(base, issuer_id="es", public_key=pk.hex())
        while True:
            rr, ss = decode_dss_signature(ek.sign(A.jcs(pay), ec.ECDSA(hashes.SHA256())))
            if ss <= A.P256_ORDER // 2:
                break
        es = {"payload": pay, "signature": {"alg": "ES256", "kid": "es", "sig": (rr.to_bytes(32, "big") + ss.to_bytes(32, "big")).hex()}}
        v = A.verify_receipt(es, {"es": pem})
        self.assertEqual((v["outcome"], v["code"], v["checks"]["signature"]), ("undecidable", "carried_key_not_comparable", "pass"))

    def test_link_form_against_an_independent_reading_of_5_7(self):
        import random
        rnd = random.Random(20261123)
        alphabet = "0123456789abcdefABCDEF:sha256SHA3-512._+-/= é٠\n"
        samples = [None, 0, 1.5, True, [], {}, "", ":", "sha256:", "SHA256:" + "a" * 64, "sha256:" + "A" * 64,
                   "sha256:" + "a" * 63, "sha256:" + "a" * 65, "a" * 64, "A" * 64, "sha3-256:" + "a" * 64, "sha3-256:",
                   "-x:" + "a" * 64, ".x:1", "x y:1", "é:1", "sha256 :" + "a" * 64, "Sha256:x", "s:", "1:2", "sha256:" + "a" * 64 + "\n"]
        for _ in range(5000):
            n = rnd.choice((0, 1, 5, 9, 64, 71, 72, 80))
            s = "".join(rnd.choice(alphabet) for _ in range(n))
            if rnd.random() < 0.3:
                s = rnd.choice(("sha256:", "sha512:", "SHA256:", "x:", "")) + "".join(rnd.choice("0123456789abcdef") for _ in range(64))
            samples.append(s)
        for s in samples:
            self.assertEqual(A.link_form(s)[0], _link_form_oracle(s), repr(s))

    def _keyed(self):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        sk = Ed25519PrivateKey.from_private_bytes(hashlib.sha256(b"test-only/acta-04").digest())
        return sk, sk.public_key().public_bytes_raw()

    def _env(self, sk, payload, alg="EdDSA", kid="k04"):
        return {"payload": payload, "signature": {"alg": alg, "kid": kid, "sig": sk.sign(A.jcs(payload)).hex()}}

    def test_every_combination_of_defects_gets_the_outcome_of_5_4(self):
        """Exhaustive over 10 independent defects (1024 receipts): the outcome predicted from the text of §5.4/§5.6/
        §5.7/§8.5 — invalid if a check that ran failed, undecidable if none failed and one could not run — never
        from the code under test."""
        import itertools
        sk, pk = self._keyed()
        other = hashlib.sha256(b"other").digest()
        names = ("sig_tampered", "link_malformed", "link_other_alg", "carried_other", "carried_same", "window_outside",
                 "window_null_bound", "no_key", "alg_unknown", "issuer_mismatch")
        payload_noise = 0
        for bits in itertools.product((0, 1), repeat=len(names)):
            d = dict(zip(names, bits))
            p = {"type": "protectmcp:decision", "tool_name": "t", "decision": "allow", "issued_at": "2026-03-01T00:00:00Z",
                 "issuer_id": "other-issuer" if d["issuer_mismatch"] else "k04"}
            if sum(bits) % 3 == 0:                      # a payload problem rides along: it must change nothing (§5.4)
                p["decision"] = "maybe"; payload_noise += 1
            if d["link_malformed"]:
                p["previousReceiptHash"] = "sha256:" + "A" * 64
            elif d["link_other_alg"]:
                p["previousReceiptHash"] = "sha3-256:" + "a" * 64
            if d["carried_other"]:
                p["public_key"] = other.hex()
            elif d["carried_same"]:
                p["verification_jwk"] = {"kty": "OKP", "crv": "Ed25519", "x": base64.urlsafe_b64encode(pk).rstrip(b"=").decode()}
            r = self._env(sk, p, alg="RS256" if d["alg_unknown"] else "EdDSA")
            if d["sig_tampered"]:
                s = r["signature"]["sig"]; r["signature"]["sig"] = ("0" if s[0] != "0" else "1") + s[1:]
            entry = {"key": pk}
            if d["window_outside"]:
                entry["valid_until"] = "2026-02-01T00:00:00Z"
            if d["window_null_bound"]:
                entry["valid_from"] = None
            keys = {} if d["no_key"] else {"k04": entry}
            fails, cannot = set(), set()
            if d["link_malformed"]:
                fails.add("link")
            elif d["link_other_alg"]:
                cannot.add("link")
            if d["issuer_mismatch"]:
                fails.add("issuer")
            if d["alg_unknown"]:
                cannot.add("alg")
            if d["no_key"]:
                cannot.add("key")
            else:
                if d["sig_tampered"] and not d["alg_unknown"]:
                    fails.add("sig")
                if d["carried_other"]:
                    fails.add("carried")
                if d["window_null_bound"]:
                    cannot.add("window")            # a window that cannot be applied, whatever the other bound says
                elif d["window_outside"]:
                    fails.add("window")
            want = "invalid" if fails else ("undecidable" if cannot else "valid")
            v = A.verify_receipt(r, keys)
            self.assertEqual(v["outcome"], want, d)
            self.assertEqual((v["ok"], v["assessed"]), (want == "valid", want != "undecidable"), d)
            self.assertEqual(v["code"] is None, want == "valid", d)
        self.assertGreater(payload_noise, 300)

    def test_unknown_members_around_the_signature_are_never_valid(self):
        """Closed by construction where the draft closes it (§5.2: exactly payload and signature; exactly alg, kid,
        sig): any other member makes the shape unrecognized — undecidable, its cause named. Members inside the payload
        are the issuer's signed content (§2.2, §3) and stay valid."""
        import random
        rnd = random.Random(4)
        sk, pk = self._keyed()
        base = self._env(sk, {"type": "x:y", "issued_at": "2026-03-01T00:00:00Z", "issuer_id": "k04"})
        values = (None, 0, "", "x", [], {}, True, 1e300, {"kid": "k04"})
        for _ in range(300):
            name = "".join(rnd.choice("abcdefghijklmnopqrstuvwxyz_$é0") for _ in range(rnd.randint(1, 8)))
            where = rnd.choice(("envelope", "signature", "payload"))
            r = json.loads(json.dumps(base))
            target = r if where == "envelope" else r["signature"] if where == "signature" else r["payload"]
            if name in target:
                continue
            target[name] = rnd.choice(values)
            if where == "payload":
                if name in ("signature", "previousReceiptHash", "issuer_id") or name in A.CARRIED_KEY_MEMBERS:
                    continue
                r = self._env(sk, r["payload"])
            v = A.verify_receipt(r, {"k04": pk})
            if where == "payload":
                self.assertEqual(v["outcome"], "valid", (where, name))
            else:
                self.assertEqual((v["outcome"], v["code"]), ("undecidable", "unrecognized_shape"), (where, name))

    def test_a_sequence_holds_chains_and_a_chain_asserts_each_link(self):
        sk, pk = self._keyed()

        def mk(t, **kw):
            return self._env(sk, dict({"type": "x:y", "issued_at": t, "issuer_id": "k04"}, **kw))
        a = mk("2026-03-01T00:00:00Z")
        b = mk("2026-03-01T00:00:01Z", previousReceiptHash=A.receipt_hash(a))
        c = mk("2026-03-01T00:00:02Z")
        d = mk("2026-03-01T00:00:03Z", previousReceiptHash=None)
        e = mk("2026-03-01T00:00:04Z", previousReceiptHash=A.receipt_hash(d).split(":")[1])
        keys = {"k04": pk}
        v = A.verify_chain([a, b, c, d, e], keys, sequence=True)
        self.assertEqual((v["outcome"], v["chains"], v["chain_breaks"]), ("valid", [0, 2, 3], []))
        self.assertTrue(any(w["i"] == 3 and "null" in w["why"] for w in v["warnings"]))
        v = A.verify_chain([a, b, c, d, e], keys)
        self.assertEqual((v["outcome"], v["chain_breaks"]), ("invalid", [2, 3]))
        self.assertEqual({p["code"] for p in v["problems"]}, {"chain_break"})
        v = A.verify_chain([b], keys, sequence=True)            # first receipt's link: reported, not failed
        self.assertEqual(v["outcome"], "valid"); self.assertTrue(any("not checked" in w["why"] for w in v["warnings"]))
        payload_only = mk("2026-03-01T00:00:05Z", previousReceiptHash="sha256:" + hashlib.sha256(A.jcs(a["payload"])).hexdigest())
        for seq in (False, True):
            self.assertEqual(A.verify_chain([a, payload_only], keys, sequence=seq)["chain_breaks"], [1])
        with tempfile.TemporaryDirectory() as tmp:
            paths = []
            for i, r in enumerate((a, b, c, d, e)):
                paths.append(os.path.join(tmp, f"{i}.json"))
                with open(paths[-1], "w", encoding="utf-8", newline="") as fh:
                    json.dump(r, fh)
            self.assertEqual(self._cli(*paths, "--key", f"k04={pk.hex()}", "--sequence")[0], 0)
            self.assertEqual(self._cli(*paths, "--key", f"k04={pk.hex()}")[0], 1)
            # §5.4 over a run: an input that is not JSON is undecidable, but a receipt that ran and failed wins
            bad = os.path.join(tmp, "bad.json")
            with open(bad, "w", encoding="utf-8", newline="") as fh:
                fh.write("{not json")
            rc, out, _ = self._cli(bad, "--key", f"k04={pk.hex()}")
            self.assertEqual((rc, out["code"]), (77, "input_not_json"))
            forged = json.loads(json.dumps(c)); forged["payload"]["tool_name"] = "x"
            with open(os.path.join(tmp, "f.json"), "w", encoding="utf-8", newline="") as fh:
                json.dump(forged, fh)
            self.assertEqual(self._cli(bad, os.path.join(tmp, "f.json"), "--key", f"k04={pk.hex()}", "--sequence")[0], 1)
        # an input whose shape is not read, between two receipts: in a sequence it stands where a chain begins and its
        # link is not judged; in a chain, whether it follows the one before could not be checked — never valid either way
        for hole in (A.Unparsed("not JSON"), [], {"x": 1}):
            v = A.verify_chain([a, hole, a], keys, sequence=True)
            self.assertEqual((v["outcome"], v["chains"], [p["code"] for p in v["problems"]]),
                             ("undecidable", [0, 1, 2], ["input_not_json" if isinstance(hole, A.Unparsed) else "unrecognized_shape"]))
            v = A.verify_chain([a, hole], keys)
            self.assertEqual((v["outcome"], v["chains"], v["problems"][-1]["code"]), ("undecidable", [0], "chain_link_undecidable"))

    def test_a_window_that_cannot_be_applied_is_undecidable(self):
        sk, pk = self._keyed()
        r = self._env(sk, {"type": "x:y", "issued_at": "2026-03-01T00:00:00Z", "issuer_id": "k04"})
        for entry in ({"valid_from": None}, {"valid_until": None}, {"valid_from": "2026-06-01T00:00:00Z", "valid_until": "2026-01-01T00:00:00Z"},
                      {"valid_from": "2026-01-01T00:00:00Z", "valid_until": "2026-01-01T00:00:00Z"},
                      {"valid_from": "2026-06-01T00:00:00Z", "valid_until": "garbage"}):
            v = A.verify_receipt(r, {"k04": dict(entry, key=pk)})
            self.assertEqual((v["outcome"], v["code"], v["key_status"]), ("undecidable", "key_window_undecidable", "undecidable"), entry)
        nots = A.verify_receipt(self._env(sk, {"type": "x:y", "issuer_id": "k04"}), {"k04": {"key": pk, "valid_from": "2026-01-01T00:00:00Z"}})
        self.assertEqual(nots["outcome"], "undecidable")                     # no signed issued_at to apply the window to
        none = A.verify_receipt(r, {"k04": pk})
        self.assertEqual((none["outcome"], none["key_status"], none["checks"]["key_window"]), ("valid", "no_window", "not_established"))
        jwk = {"kty": "OKP", "crv": "Ed25519", "kid": "k04", "x": base64.urlsafe_b64encode(pk).rstrip(b"=").decode(), "valid_until": None}
        with self.assertRaises(ValueError):                                  # §5.6: null is not a timestamp, not "absent"
            A.keys_from_jwks({"keys": [jwk]})

    def test_an_unsupported_algorithm_is_undecidable_but_a_failed_check_still_wins(self):
        sk, pk = self._keyed()
        for alg in ("RS256", "ML-KEM-768", "", None, 7, "eddsa"):
            r = self._env(sk, {"type": "x:y", "issued_at": "2026-03-01T00:00:00Z", "issuer_id": "k04"}, alg=alg)
            v = A.verify_receipt(r, {"k04": pk})
            self.assertEqual((v["outcome"], v["code"]), ("undecidable", "unsupported_algorithm"), alg)
            v = A.verify_receipt(r, {"k04": {"key": pk, "valid_until": "2026-02-01T00:00:00Z"}})
            self.assertEqual((v["outcome"], v["code"]), ("invalid", "key_outside_validity_window"), alg)
        # a check that failed is reported as failed even when the same receipt cannot be canonicalized
        p = {"type": "x:y", "issued_at": "2026-03-01T00:00:00Z", "issuer_id": "k04", "signature": None}
        r = self._env(sk, p)
        r["payload"]["x"] = "\ud800"
        v = A.verify_receipt(r, {"k04": pk})
        self.assertEqual((v["outcome"], v["code"], v["checks"]["signing_input"]), ("invalid", "signature_in_signing_input", "fail"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
