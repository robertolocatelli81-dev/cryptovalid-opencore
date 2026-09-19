"""SCITT (RFC 9943) signed / transparent statements over a cryptovalid ledger, and the monitor's identity search
(0.14.0, 2026-09-19). Every negative has its positive; pycose — an independent COSE implementation — is the oracle
for the COSE_Sign1 structures when it is installed (CV_REQUIRE_PYCOSE=1 makes its absence an error, as CI does)."""
import hashlib, json, os, shutil, sys, tempfile, unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import cryptovalid_monitor as MON
import cryptovalid_receipt as R
import cryptovalid_scitt as SC
import verifier as V
try:
    from cryptography.hazmat.primitives.asymmetric import ed25519 as _ed  # noqa: F401
    import signer
    HAVE_CRYPTO = True
except Exception:  # noqa: BLE001
    HAVE_CRYPTO = False
try:
    import cbor2  # noqa: F401
    from pycose.messages import Sign1Message
    from pycose.keys import OKPKey
    from pycose.keys.curves import Ed25519
    HAVE_PYCOSE = True
except Exception:  # noqa: BLE001
    HAVE_PYCOSE = False
if os.environ.get("CV_REQUIRE_PYCOSE") == "1" and not (HAVE_PYCOSE and HAVE_CRYPTO):
    raise SystemExit("CV_REQUIRE_PYCOSE=1 but pycose/cbor2/cryptography did not import: the oracle tests would be skipped")

T0 = 1_789_776_000   # 2026-09-19T00:00:00Z


def _canon(e):
    return json.dumps(e, sort_keys=True, separators=(",", ":")).encode()


def _ledger(path, n, marker=lambda i: "AI-9"):
    prev, rows = "0" * 64, []
    for i in range(n):
        e = {"idx": i, "ts": f"2026-09-19T10:00:{i:02d}Z", "data": {"agent_id": marker(i), "act": "x"}, "prev_hash": prev}
        e["self_hash"] = hashlib.sha256(_canon(e)).hexdigest(); prev = e["self_hash"]; rows.append(e)
    with open(path, "w") as f:
        for r in rows:
            f.write(json.dumps(r) + "\n")
    return rows


class TestMonitorIdentitySearch(unittest.TestCase):
    def test_match_reports_new_matches_since_last_green_state(self):
        tmp = tempfile.mkdtemp(); led = os.path.join(tmp, "l.jsonl"); st = os.path.join(tmp, "s.json")
        rows = _ledger(led, 12, lambda i: "AI-123" if i in (3, 7) else "AI-9")
        v = MON.run(led, st, match=[r'"agent_id":"AI-123"'])
        self.assertTrue(v["ok"]); self.assertEqual([m["index"] for m in v["identity"]["matches"]], [3, 7])
        self.assertEqual(len(v["identity"]["new_matches"]), 2); self.assertEqual(v["identity"]["scanned"], 12)
        self.assertEqual(v["identity"]["matches"][0]["self_hash"], rows[3]["self_hash"])
        prev = rows[-1]["self_hash"]
        with open(led, "a") as f:
            for i in (12, 13):
                e = {"idx": i, "ts": f"2026-09-19T10:00:{i:02d}Z", "data": {"agent_id": "AI-123" if i == 13 else "AI-9"}, "prev_hash": prev}
                e["self_hash"] = hashlib.sha256(_canon(e)).hexdigest(); prev = e["self_hash"]; f.write(json.dumps(e) + "\n")
        v = MON.run(led, st, match=[r'"agent_id":"AI-123"'])
        self.assertEqual(([m["index"] for m in v["identity"]["matches"]], [m["index"] for m in v["identity"]["new_matches"]]), ([3, 7, 13], [13]))
        # no match → empty, never an error; a bad regex → ValueError (CLI: JSON error, exit 2)
        self.assertEqual(MON.run(led, st, match=["nothing-here"])["identity"]["matches"], [])
        with self.assertRaises(ValueError):
            MON.run(led, st, match=["("])
        self.assertIsNone(MON.run(led, st)["identity"])
        shutil.rmtree(tmp, ignore_errors=True)


@unittest.skipUnless(HAVE_CRYPTO, "cryptography assente")
class TestScitt(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.ik = os.path.join(self.tmp, "issuer.key"); self.ipk = signer.keygen(self.ik)["public_key_hex"]
        self.tk = os.path.join(self.tmp, "ts.key"); self.tpk = signer.keygen(self.tk)["public_key_hex"]
        self.ok = os.path.join(self.tmp, "other.key"); self.opk = signer.keygen(self.ok)["public_key_hex"]
        self.payload = b'{"bomFormat":"CycloneDX","version":"1.2.3"}'
        self.led = os.path.join(self.tmp, "ts.jsonl")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _flow(self, detached=False):
        ss = SC.signed_statement(self.payload, "application/vnd.cyclonedx+json", "vendor.example", "vendor.example/product", self.ik,
                                 detached=detached, iat=T0)
        pl = self.payload if detached else None
        SC.register(SC.signed_statement(b"first", "text/plain", "vendor.example", "x", self.ik), self.led, self.ipk)
        reg = SC.register(ss, self.led, self.ipk, pl)
        rc = SC.receipt(self.led, reg["index"], self.tk, "ts.example/ledger")
        return ss, reg, rc, SC.transparent_statement(ss, [rc]), pl

    def test_signed_statement_structure_and_negatives(self):
        ss = SC.signed_statement(self.payload, "application/vnd.cyclonedx+json", "vendor.example", "vendor.example/product", self.ik, iat=T0)
        pb, ph, uh, pl, sig = SC.parse_cose_sign1(ss)
        self.assertEqual((ph[1], ph[3], ph[4], ph[15][1], ph[15][2], ph[15][6], uh, pl), (-8, "application/vnd.cyclonedx+json", bytes.fromhex(self.ipk),
                         "vendor.example", "vendor.example/product", T0, {}, self.payload))
        v = SC.verify_signed_statement(ss, self.ipk); self.assertTrue(v["ok"]); self.assertEqual(v["sub"], "vendor.example/product")
        self.assertEqual(SC.verify_signed_statement(ss, self.opk)["why"], "invalid: InvalidSignature")   # kid is opaque: the key decides
        self.assertFalse(SC.verify_signed_statement(ss.replace(b"1.2.3", b"1.2.4"), self.ipk)["ok"])
        self.assertFalse(SC.verify_signed_statement(ss[:-1] + bytes([ss[-1] ^ 1]), self.ipk)["ok"])
        # a COSE_Sign1 WITHOUT CWT claims (an RFC 9942 receipt of this repository) is not a Signed Statement
        _ledger(self.led, 3); rcpt = R.to_cose(R.inclusion_receipt(self.led, 1, self.tk), self.tk)
        self.assertIn("CWT Claims", SC.verify_signed_statement(rcpt, self.tpk)["why"])
        # detached payload: required at verification, refused when it differs
        sd = SC.signed_statement(self.payload, "text/plain", "i", "s", self.ik, detached=True)
        self.assertIsNone(SC.parse_cose_sign1(sd)[3])
        self.assertIn("detached payload", SC.verify_signed_statement(sd, self.ipk)["why"])
        self.assertTrue(SC.verify_signed_statement(sd, self.ipk, self.payload)["ok"])
        self.assertFalse(SC.verify_signed_statement(sd, self.ipk, b"other")["ok"])
        for bad in (("", "s"), ("i" * 8193, "s"), ("i", "")):
            with self.assertRaises(SC.ScittError):
                SC.signed_statement(b"x", "text/plain", bad[0], bad[1], self.ik)
        with self.assertRaises(SC.ScittError):
            SC.parse_cose_sign1(b"\xd2" + b"\x80")

    def test_register_receipt_transparent_statement(self):
        ss, reg, rc, ts, _ = self._flow()
        self.assertEqual((reg["index"], V.verify_ledger(self.led)["verdict"]), (1, "PASS"))
        with open(self.led) as f:
            entry = [json.loads(l) for l in f][1]
        self.assertEqual(entry["data"]["scitt"]["statement_sha256"], SC.statement_id(ss))
        # the identity is over the SIGNED parts: the same statement re-encoded by another encoder (pycose/cbor2 order,
        # non-minimal lengths) or carrying receipts of another TS keeps its identity (round 13, Opus)
        pb, ph, uh, pl, sig = SC.parse_cose_sign1(ss)
        other_encoding = b"\xd2" + b"\x84" + b"\x58" + bytes([len(pb)]) + pb + b"\xa0" + b"\x58" + bytes([len(pl)]) + pl + b"\x58\x40" + sig
        self.assertEqual(SC.statement_id(other_encoding), SC.statement_id(ss))
        self.assertTrue(SC.verify_transparent_statement(SC.transparent_statement(other_encoding, [rc]), self.ipk, self.tpk)["ok"])
        self.assertEqual(SC.statement_id(ts), SC.statement_id(ss))
        # the receipt: CWT claims (RFC 9943 requires them in a Receipt), vds 1, kid = TS key, root as payload
        rp, rph, ruh, rpl, _ = SC.parse_cose_sign1(rc)
        self.assertEqual((rph[1], rph[395], rph[4], rph[15][1]), (-8, 1, bytes.fromhex(self.tpk), "ts.example/ledger"))
        self.assertIsNone(rpl); self.assertIn(-1, ruh[396])                 # detached root (RFC 9942 §4.4 SHOULD)
        attached = SC.receipt(self.led, reg["index"], self.tk, "ts.example/ledger", detached=False)
        self.assertEqual(len(SC.parse_cose_sign1(attached)[3]), 32)
        self.assertTrue(SC.verify_transparent_statement(SC.transparent_statement(ss, [attached]), self.ipk, self.tpk)["ok"])
        v = SC.verify_transparent_statement(ts, self.ipk, self.tpk, expected_ts_iss="ts.example/ledger")
        self.assertTrue(v["ok"], v); self.assertEqual((v["receipts"][0]["tree_size"], v["receipts"][0]["leaf_index"]), (2, 1))
        # registration refuses what it cannot validate
        with self.assertRaises(SC.ScittError):
            SC.register(ss, self.led, self.opk)
        # negatives, each on a different link of the chain
        self.assertEqual(SC.verify_transparent_statement(ts, self.opk, self.tpk)["why"][:16], "signed statement")
        self.assertEqual(SC.verify_transparent_statement(ts, self.ipk, self.opk)["receipts"][0]["why"], "receipt kid differs from the trusted TS key")
        self.assertIn("not the expected TS", SC.verify_transparent_statement(ts, self.ipk, self.tpk, expected_ts_iss="evil")["receipts"][0]["why"])
        other = SC.receipt(self.led, 0, self.tk, "ts.example/ledger")
        self.assertEqual(SC.verify_transparent_statement(SC.transparent_statement(ss, [other]), self.ipk, self.tpk)["receipts"][0]["why"],
                         "the receipt's leaf binds another statement")
        # a receipt forged by another key over the same proof: refused
        forged = SC.receipt(self.led, 1, self.ok, "ts.example/ledger")
        self.assertFalse(SC.verify_transparent_statement(SC.transparent_statement(ss, [forged]), self.ipk, self.tpk)["ok"])
        # the UNSIGNED fields under a VALID TS signature (the real attack surface): a forged leaf that claims the
        # right statement and idx, a zeroed path, a wrong idx, a missing/malformed proof — each refused by name
        def rebuild(leaf=None, proof=None, drop_vdp=False):
            rp_, rph_, ruh_, rpl_, rsig_ = SC.parse_cose_sign1(rc)
            u = dict(ruh_)
            if leaf is not None:
                u[SC.L_LEAF] = leaf
            if proof is not None:
                u[SC.L_VDP] = {-1: [proof]}
            if drop_vdp:
                u.pop(SC.L_VDP)
            return SC.transparent_statement(ss, [SC.TAG_COSE_SIGN1 + R.cbor_encode([rp_, u, rpl_, rsig_])])
        with open(self.led) as f:
            e1 = json.loads(f.readlines()[1])
        fake = dict(e1); fake["ts"] = "1999-01-01T00:00:00Z"   # same statement hash and idx, different leaf bytes
        # with a DETACHED root the walk always yields some root, so the TS signature over it is what fails
        res = SC.verify_transparent_statement(rebuild(leaf=json.dumps(fake, sort_keys=True, separators=(",", ":")).encode()), self.ipk, self.tpk)
        self.assertEqual((res["ok"], res["receipts"][0]["why"]), (False, "invalid: InvalidSignature"))
        n_, i_, path_ = R.cbor_decode(SC.parse_cose_sign1(rc)[2][SC.L_VDP][-1][0])
        res = SC.verify_transparent_statement(rebuild(proof=R.cbor_encode([n_, i_, [bytes(32) for _ in path_]])), self.ipk, self.tpk)
        self.assertEqual(res["receipts"][0]["why"], "invalid: InvalidSignature")
        # with an ATTACHED root the mismatch is named before any signature check
        ap_, aph_, auh_, apl_, asig_ = SC.parse_cose_sign1(attached)
        u2 = dict(auh_); u2[SC.L_VDP] = {-1: [R.cbor_encode([n_, i_, [bytes(32) for _ in path_]])]}
        res = SC.verify_transparent_statement(SC.transparent_statement(ss, [SC.TAG_COSE_SIGN1 + R.cbor_encode([ap_, u2, apl_, asig_])]), self.ipk, self.tpk)
        self.assertEqual(res["receipts"][0]["why"], "inclusion path does not rebuild the signed root")
        res = SC.verify_transparent_statement(rebuild(proof=R.cbor_encode([n_, 0, path_])), self.ipk, self.tpk)
        self.assertEqual(res["receipts"][0]["why"], "leaf index differs from the entry's idx")
        res = SC.verify_transparent_statement(rebuild(drop_vdp=True), self.ipk, self.tpk)
        self.assertEqual(res["receipts"][0]["why"], "no inclusion proof (vdp -1)")
        res = SC.verify_transparent_statement(rebuild(proof=b"\x82\x01\x02"), self.ipk, self.tpk)
        self.assertEqual(res["receipts"][0]["why"], "malformed inclusion proof")
        for hostile in (b"\x82", b'{"idx":1,"data":[1]}', b'{"data":{"scitt":5}}', b"[1,2]"):
            res = SC.verify_transparent_statement(rebuild(leaf=hostile), self.ipk, self.tpk)
            self.assertFalse(res["ok"]); self.assertTrue(res["receipts"][0]["why"])
        # hostile bytes as statement / receipt: ok=False, never an exception
        for hostile in (b"\xd2\x84", b"", b"\xd2\x80"):
            self.assertFalse(SC.verify_transparent_statement(hostile, self.ipk, self.tpk)["ok"])
            self.assertFalse(SC.verify_signed_statement(hostile, self.ipk)["ok"])
        truncated = SC.TAG_COSE_SIGN1 + R.cbor_encode([SC.parse_cose_sign1(ss)[0], {394: [rc[:20]]}, self.payload, SC.parse_cose_sign1(ss)[4]])
        self.assertFalse(SC.verify_transparent_statement(truncated, self.ipk, self.tpk)["ok"])
        # a Transparent Statement of THIS TS registered at a second TS (RFC 9943 §6.3): the second receipt verifies
        led2 = os.path.join(self.tmp, "ts2.jsonl"); tk2 = os.path.join(self.tmp, "ts2.key"); tpk2 = signer.keygen(tk2)["public_key_hex"]
        reg2 = SC.register(ts, led2, self.ipk)
        rc_b = SC.receipt(led2, reg2["index"], tk2, "ts2.example/ledger")
        both = SC.transparent_statement(ts, [rc_b])
        self.assertEqual([r["ok"] for r in SC.verify_transparent_statement(both, self.ipk, self.tpk)["receipts"]], [True, False])
        self.assertEqual([r["ok"] for r in SC.verify_transparent_statement(both, self.ipk, tpk2)["receipts"]], [False, True])
        # the ledger grows: a NEW receipt for the same entry verifies (bigger tree), the old one still does
        SC.register(SC.signed_statement(b"later", "text/plain", "vendor.example", "y", self.ik), self.led, self.ipk)
        rc2 = SC.receipt(self.led, 1, self.tk, "ts.example/ledger")
        v = SC.verify_transparent_statement(SC.transparent_statement(ss, [rc, rc2]), self.ipk, self.tpk)
        self.assertEqual((v["ok"], [r["tree_size"] for r in v["receipts"]]), (True, [2, 3]))
        with self.assertRaises(SC.ScittError):
            SC.transparent_statement(ss, [])
        # detached flow
        ss2, reg2, rc2b, ts2, pl = self._flow(detached=True)
        self.assertTrue(SC.verify_transparent_statement(ts2, self.ipk, self.tpk, pl)["ok"])
        self.assertFalse(SC.verify_transparent_statement(ts2, self.ipk, self.tpk, b"other")["ok"])

    def test_cli(self):
        import subprocess
        st = os.path.join(self.tmp, "stmt.json"); open(st, "wb").write(self.payload)
        cmd = [sys.executable, os.path.join(os.path.dirname(os.path.abspath(__file__)), "cryptovalid_scitt.py")]
        r = subprocess.run(cmd + ["sign", st, "--cty", "application/json", "--iss", "vendor.example", "--sub", "p", "--key", self.ik,
                                  "--out", st + ".cose"], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        r = subprocess.run(cmd + ["register", st + ".cose", "--ledger", self.led, "--issuer-pubkey", self.ipk, "--ts-key", self.tk,
                                  "--ts-iss", "ts.example/ledger", "--out", st + ".transparent"], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr); self.assertEqual(json.loads(r.stdout)["index"], 0)
        r = subprocess.run(cmd + ["verify", st + ".transparent", "--issuer-pubkey", self.ipk, "--ts-pubkey", self.tpk, "--ts-iss", "ts.example/ledger"],
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stdout)
        r = subprocess.run(cmd + ["verify", st + ".transparent", "--issuer-pubkey", self.ipk, "--ts-pubkey", self.opk], capture_output=True, text=True)
        self.assertEqual(r.returncode, 1)
        r = subprocess.run(cmd + ["verify", "/nonexistent", "--issuer-pubkey", self.ipk, "--ts-pubkey", self.opk], capture_output=True, text=True)
        self.assertEqual(r.returncode, 2)

    @unittest.skipUnless(HAVE_PYCOSE, "pycose assente")
    def test_pycose_oracle(self):
        """pycose (an independent COSE_Sign1 implementation) decodes our structures, verifies the Issuer and TS
        signatures with the right keys and refuses them with the wrong key or a tampered payload."""
        ss, reg, rc, ts, _ = self._flow()
        m = Sign1Message.decode(ts); m.key = OKPKey(crv=Ed25519, x=bytes.fromhex(self.ipk))
        self.assertTrue(m.verify_signature())
        ph = {getattr(k, "identifier", k): v for k, v in m.phdr.items()}
        self.assertEqual(ph[15], {1: "vendor.example", 2: "vendor.example/product", 6: T0})
        uh = {getattr(k, "identifier", k): v for k, v in m.uhdr.items()}
        self.assertEqual(len(uh[394]), 1)
        # the receipt's root is DETACHED (RFC 9942): pycose verifies it with the root our relying party recomputed
        v = SC.verify_transparent_statement(ts, self.ipk, self.tpk); self.assertTrue(v["ok"])
        r = Sign1Message.decode(uh[394][0]); r.key = OKPKey(crv=Ed25519, x=bytes.fromhex(self.tpk))
        self.assertTrue(r.verify_signature(detached_payload=bytes.fromhex(v["receipts"][0]["signed_root"])))
        self.assertFalse(r.verify_signature(detached_payload=bytes(32)))
        r2 = Sign1Message.decode(SC.receipt(self.led, reg["index"], self.tk, "ts.example/ledger", detached=False)); r2.key = OKPKey(crv=Ed25519, x=bytes.fromhex(self.tpk))
        self.assertTrue(r2.verify_signature())
        rph = {getattr(k, "identifier", k): v for k, v in r.phdr.items()}
        self.assertEqual((rph[395], rph[15][1]), (1, "ts.example/ledger"))
        m2 = Sign1Message.decode(ts); m2.key = OKPKey(crv=Ed25519, x=bytes.fromhex(self.opk)); self.assertFalse(m2.verify_signature())
        m3 = Sign1Message.decode(ts.replace(b"1.2.3", b"1.2.4")); m3.key = OKPKey(crv=Ed25519, x=bytes.fromhex(self.ipk)); self.assertFalse(m3.verify_signature())


if __name__ == "__main__":
    unittest.main(verbosity=1)
