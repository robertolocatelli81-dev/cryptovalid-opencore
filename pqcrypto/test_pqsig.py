# Tests for the crypto-agile signature suite + AP2 PQ producer signatures (private).
import base64
import hashlib
import importlib.util
import json
import os
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
for _oc in (os.path.dirname(HERE), os.path.join(os.path.dirname(HERE), "opencore")):
    if os.path.isfile(os.path.join(_oc, "ap2_evidence.py")):
        sys.path.insert(0, _oc); _OPENCORE = _oc; break
import sigsuite as S  # noqa: E402
import ap2_evidence as A  # noqa: E402


def _load_test_helpers():
    spec = importlib.util.spec_from_file_location(
        "t_ap2", os.path.join(_OPENCORE, "test_ap2_evidence.py"))
    t = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(t)
    return t


class TestSigSuite(unittest.TestCase):
    def test_each_class_roundtrip_and_negatives(self):
        msg = b"digest-under-signature"
        for alg in S.KNOWN:
            sk, pk = S.generate(alg)
            sig = S.sign(alg, sk, msg)
            self.assertIs(S.verify(alg, pk, sig, msg), True, alg)
            self.assertIs(S.verify(alg, pk, sig, b"other"), False, alg)
            raw = base64.b64decode(sig)
            flipped = base64.b64encode(bytes([raw[0] ^ 1]) + raw[1:]).decode()
            self.assertIs(S.verify(alg, pk, flipped, msg), False, alg)
            _, pk2 = S.generate(alg)
            self.assertIs(S.verify(alg, pk2, sig, msg), False, alg + " wrong key")

    def test_mldsa_is_real_fips204_sizes(self):
        self.assertTrue(S.MLDSA_AVAILABLE, "cryptography>=50.0.1 required")
        sk, pk = S.generate("ml-dsa-65")
        self.assertEqual(len(base64.b64decode(pk)), 1952)          # FIPS 204 ML-DSA-65 pubkey
        self.assertEqual(len(base64.b64decode(S.sign("ml-dsa-65", sk, b"x"))), 3309)  # sig

    def test_unknown_alg_is_none_not_green(self):
        self.assertIsNone(S.verify("rsa-1024", "AAAA", "AAAA", b"x"))

    def test_hybrid_block_and_fail_closed(self):
        msg = b"pack-digest"
        blk = S.sign_hybrid(msg)
        r = S.verify_producer_block(blk, msg)
        self.assertTrue(r["ok"] and r["pq_protected"])
        self.assertFalse(S.verify_producer_block(blk, b"tampered")["ok"])
        forged = dict(blk, signatures=[
            dict(s, signature_b64=base64.b64encode(b"\x00" * 3309).decode()) if s["post_quantum"] else s
            for s in blk["signatures"]])
        self.assertFalse(S.verify_producer_block(forged, msg)["ok"])   # fail-closed
        classical = dict(blk, signatures=[s for s in blk["signatures"] if not s["post_quantum"]])
        rc = S.verify_producer_block(classical, msg)
        self.assertTrue(rc["ok"] and not rc["pq_protected"])


class TestAp2ProducerSignature(unittest.TestCase):
    def setUp(self):
        self.t = _load_test_helpers()
        self.sk, self.jwk = self.t._make_signer()
        self.sdjwt = self.t._make_sd_jwt(self.sk, {"iss": "merchant"}, {"amount": "10.00"})
        self.tmp = tempfile.mkdtemp()

    def _build(self):
        p = os.path.join(self.tmp, "ev.json")
        A.build_evidence([{"name": "m", "sd_jwt": self.sdjwt}], p, keys={"m": self.jwk})
        return p

    def test_backward_compatible_without_signature(self):
        v = A.verify_evidence(self._build())
        self.assertTrue(v["valid"])
        self.assertFalse(v["pq_protected"])
        self.assertFalse(v["producer_signatures"]["present"])

    def test_hybrid_sign_makes_pack_pq_protected(self):
        p = self._build()
        sg = A.sign_evidence(p)
        self.assertIn("ml-dsa-65", sg["sig_algs"])
        v = A.verify_evidence(p)
        self.assertTrue(v["valid"] and v["pq_protected"] and v["producer_signatures"]["ok"])

    def test_tampered_digest_and_forged_pq_fail_closed(self):
        p = self._build()
        A.sign_evidence(p)
        ev = json.load(open(p))
        ev["evidence_digest_sha256"] = "00" * 32
        json.dump(ev, open(p, "w"))
        v = A.verify_evidence(p)
        self.assertFalse(v["valid"])
        # content-binding: la firma è verificata sul digest RICALCOLATO (contenuto intatto),
        # quindi producer.ok resta True; è digest_ok=False a rendere valid=False (fail-closed).
        self.assertFalse(v["digest_ok"])
        # forged PQ
        p2 = self._build()
        A.sign_evidence(p2)
        ev = json.load(open(p2))
        for s in ev["producer_signatures"]["signatures"]:
            if s["post_quantum"]:
                s["signature_b64"] = "AAAA"
        json.dump(ev, open(p2, "w"))
        v2 = A.verify_evidence(p2)
        self.assertFalse(v2["valid"] and v2["producer_signatures"]["ok"])

    def test_honest_scope_declares_pq_and_time_anchor_caveat(self):
        v = A.verify_evidence(self._build())
        self.assertIn("ML-DSA-65", v["honest_scope"])
        self.assertIn("time anchor", v["honest_scope"])





class TestProducerPinningAndPolicy(unittest.TestCase):
    """Regressions from adversarial review: self-embedded key = no
    authenticity (key substitution), downgrade-to-unsigned, duplicate JSON keys."""

    def setUp(self):
        self.t = _load_test_helpers()
        self.sk, self.jwk = self.t._make_signer()
        self.sdjwt = self.t._make_sd_jwt(self.sk, {"iss": "merchant"}, {"amount": "10.00"})
        self.tmp = tempfile.mkdtemp()
        self.ident = S.ProducerIdentity.create()
        self.pin = self.ident.public_keys()

    def _signed_pack(self, identity=None):
        p = os.path.join(self.tmp, "ev.json")
        A.build_evidence([{"name": "m", "sd_jwt": self.sdjwt}], p, keys={"m": self.jwk})
        A.sign_evidence(p, identity=identity or self.ident)
        return p

    def _recompute(self, p, mutate):
        ev = json.load(open(p))
        mutate(ev)
        e2 = {k: v for k, v in ev.items()
              if k not in ("evidence_digest_sha256", "rfc3161_timestamp", "producer_signatures")}
        ev["evidence_digest_sha256"] = hashlib.sha256(
            json.dumps(e2, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        ev.pop("producer_signatures", None)
        json.dump(ev, open(p, "w"))
        return p

    def test_pinned_and_require_pq_valid(self):
        v = A.verify_evidence(self._signed_pack(), trusted_producer_keys=self.pin, require_pq=True)
        self.assertTrue(v["valid"] and v["pq_protected"] and v["producer_signatures"]["trusted"])

    def test_key_substitution_blocked_by_pinning(self):
        p = self._recompute(self._signed_pack(), lambda ev: ev.__setitem__("subject", "TAMPERED"))
        A.sign_evidence(p, identity=S.ProducerIdentity.create())     # attacker's fresh keys
        v = A.verify_evidence(p, trusted_producer_keys=self.pin, require_pq=True)
        self.assertFalse(v["valid"])
        self.assertIs(v["producer_signatures"]["trusted"], False)

    def test_downgrade_to_unsigned_blocked_by_require_pq(self):
        p = self._recompute(self._signed_pack(), lambda ev: ev.__setitem__("subject", "TAMPERED"))
        v = A.verify_evidence(p, trusted_producer_keys=self.pin, require_pq=True)
        self.assertFalse(v["valid"])
        self.assertFalse(v["policy_ok"])

    def test_unpinned_signature_is_not_authentic(self):
        v = A.verify_evidence(self._signed_pack())     # no trust set
        self.assertIsNone(v["producer_signatures"]["trusted"])
        self.assertTrue(v["valid"])                    # internally consistent, but...
        self.assertIn("consistency, not authenticity", v["honest_scope"])

    def test_duplicate_json_key_rejected(self):
        p = os.path.join(self.tmp, "dup.json")
        open(p, "w").write('{"evidence_format":"x","subject":"A","subject":"B","artifacts":[]}')
        with self.assertRaises(A.Ap2EvidenceError):
            A.verify_evidence(p)


if __name__ == "__main__":
    unittest.main()
