#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Roberto Locatelli
"""ap2-evidence-pack bench. NEGATIVE CONTROLS FIRST (the bench must know how to fail):
tampered signature, tampered disclosure, foreign disclosure, unsupported alg, tampered
evidence file. Fixtures are REAL: ECDSA P-256 keys and SD-JWTs built here, no canned
strings. All writes go to tempdirs (production paths never touched)."""
import base64
import hashlib
import json
import os
import sys
import tempfile
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
import ap2_evidence as ap2  # noqa: E402

from cryptography.hazmat.primitives import hashes  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature  # noqa: E402


def _b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def _make_signer():
    sk = ec.generate_private_key(ec.SECP256R1())
    nums = sk.public_key().public_numbers()
    jwk = {"kty": "EC", "crv": "P-256",
           "x": _b64u(nums.x.to_bytes(32, "big")),
           "y": _b64u(nums.y.to_bytes(32, "big"))}
    return sk, jwk


def _sign_jwt(sk, header: dict, payload: dict) -> str:
    si = f"{_b64u(json.dumps(header).encode())}.{_b64u(json.dumps(payload).encode())}"
    der = sk.sign(si.encode("ascii"), ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der)
    return f"{si}.{_b64u(r.to_bytes(32, 'big') + s.to_bytes(32, 'big'))}"


def _disclosure(salt: str, name, value) -> str:
    arr = [salt, name, value] if name is not None else [salt, value]
    return _b64u(json.dumps(arr).encode())


def _make_sd_jwt(sk, claims_open: dict, claims_sd: dict, header_extra: dict = None) -> str:
    """A real SD-JWT: open claims + selectively-disclosed claims via _sd digests."""
    discs = [_disclosure(f"salt{i}", k, v) for i, (k, v) in enumerate(claims_sd.items())]
    digests = [ap2._disclosure_digest(d) for d in discs]
    payload = dict(claims_open)
    payload["_sd"] = sorted(digests)
    payload["_sd_alg"] = "sha-256"
    header = {"alg": "ES256", "typ": "ap2-mandate+sd-jwt"}
    header.update(header_extra or {})
    return _sign_jwt(sk, header, payload) + "~" + "~".join(discs) + "~"


class _Base(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp(prefix="ap2ev_")
        self.sk, self.jwk = _make_signer()
        self.intent = _make_sd_jwt(
            self.sk, {"iss": "user-wallet", "mandate_type": "intent"},
            {"max_amount": "150.00 EUR", "merchant_scope": "books"},
            header_extra={"jwk": self.jwk})
        # cart COMMITS to the intent: sha-256 hex of the intent's exact compact form
        intent_hash = hashlib.sha256(self.intent.encode("ascii")).hexdigest()
        self.cart = _make_sd_jwt(
            self.sk, {"iss": "shopping-agent", "mandate_type": "cart",
                      "intent_mandate_hash": intent_hash},
            {"items": ["book-123"]}, header_extra={"jwk": self.jwk})
        self.arts = [{"name": "intent", "sd_jwt": self.intent},
                     {"name": "cart", "sd_jwt": self.cart}]
        self.out = os.path.join(self.d, "evidence.json")


class TestBenchCanFail(_Base):
    """Negative controls FIRST."""

    def test_tampered_signature_refuses_build(self):
        bad = self.intent[:-30] + ("A" if self.intent[-30] != "A" else "B") + self.intent[-29:]
        with self.assertRaises(ap2.Ap2EvidenceError):
            ap2.build_evidence([{"name": "intent", "sd_jwt": bad}], self.out)
        self.assertFalse(os.path.exists(self.out))     # nessun file per una luce rossa

    def test_wrong_key_fails_signature(self):
        _, other_jwk = _make_signer()
        parsed = ap2.parse_sd_jwt(self.intent)
        self.assertFalse(ap2.verify_es256(parsed["signing_input"],
                                          parsed["signature"], other_jwk))

    def test_foreign_disclosure_rejected(self):
        # una disclosure che non matcha alcun digest = fail-closed, non ignorata
        foreign = _disclosure("saltX", "sneaky", "claim")
        parts = self.intent.rstrip("~") + "~" + foreign + "~"
        parsed = ap2.parse_sd_jwt(parts)
        with self.assertRaises(ap2.Ap2EvidenceError):
            ap2.resolve_disclosures(parsed["payload"], parsed["disclosures"])

    def test_unsupported_alg_rejected_loudly(self):
        jwt = _sign_jwt(self.sk, {"alg": "ES384"}, {"iss": "x"})
        with self.assertRaises(ap2.Ap2EvidenceError):
            ap2._snapshot_key(ap2.parse_sd_jwt(jwt + "~"))

    def test_no_key_material_fails_closed(self):
        jwt = _sign_jwt(self.sk, {"alg": "ES256"}, {"iss": "x"})
        with self.assertRaises(ap2.Ap2EvidenceError):
            ap2._snapshot_key(ap2.parse_sd_jwt(jwt + "~"))

    def test_tampered_evidence_file_is_invalid(self):
        ap2.build_evidence(self.arts, self.out)
        ev = json.load(open(self.out))
        ev["subject"] = "riscritto dopo il sigillo"
        json.dump(ev, open(self.out, "w"))
        r = ap2.verify_evidence(self.out)
        self.assertFalse(r["digest_ok"])
        self.assertFalse(r["valid"])

    def test_swapped_artifact_in_file_is_invalid(self):
        ap2.build_evidence(self.arts, self.out)
        ev = json.load(open(self.out))
        other_sk, other_jwk = _make_signer()
        ev["artifacts"][0]["sd_jwt_compact"] = _make_sd_jwt(
            other_sk, {"iss": "forger"}, {"a": 1}, header_extra={"jwk": other_jwk})
        json.dump(ev, open(self.out, "w"))
        r = ap2.verify_evidence(self.out)
        self.assertFalse(r["valid"])

    def test_jwks_url_must_be_https(self):
        jwt = _sign_jwt(self.sk, {"alg": "ES256", "kid": "k1"}, {"iss": "x"})
        with self.assertRaises(ap2.Ap2EvidenceError):
            ap2._snapshot_key(ap2.parse_sd_jwt(jwt + "~"),
                              jwks_url="http://insecure.example/jwks.json")


class TestPositive(_Base):
    def test_parse_and_resolve_roundtrip(self):
        parsed = ap2.parse_sd_jwt(self.intent)
        resolved = ap2.resolve_disclosures(parsed["payload"], parsed["disclosures"])
        self.assertEqual(resolved["max_amount"], "150.00 EUR")
        self.assertEqual(resolved["merchant_scope"], "books")
        self.assertNotIn("_sd", resolved)

    def test_build_verify_offline_roundtrip(self):
        r = ap2.build_evidence(self.arts, self.out)
        self.assertEqual(r["artifacts"], 2)
        self.assertEqual(r["bindings"], 1)                     # cart -> intent
        v = ap2.verify_evidence(self.out)
        self.assertTrue(v["valid"], v)
        self.assertTrue(v["digest_ok"] and v["bindings_ok"])
        self.assertEqual(v["provenance_classes"], ["jwk_header"])
        self.assertIsNone(v["rfc3161"]["verified"])            # nessun TSA: onesto None

    def test_binding_found_on_primary_quantity(self):
        ap2.build_evidence(self.arts, self.out)
        ev = json.load(open(self.out))
        b = ev["bindings"][0]
        self.assertEqual((b["in"], b["commits_to"], b["encoding"]),
                         ("cart", "intent", "hex"))
        self.assertEqual(b["claim"], "intent_mandate_hash")

    def test_supplied_key_provenance(self):
        jwt = _sign_jwt(self.sk, {"alg": "ES256"}, {"iss": "no-header-key"})
        ap2.build_evidence([{"name": "solo", "sd_jwt": jwt + "~"}], self.out,
                           keys={"solo": self.jwk})
        v = ap2.verify_evidence(self.out)
        self.assertTrue(v["valid"], v)
        self.assertEqual(v["provenance_classes"], ["supplied"])

    def test_x5c_provenance_class(self):
        from datetime import datetime, timedelta, timezone
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "ap2 test issuer")])
        now = datetime.now(timezone.utc)
        cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
                .public_key(self.sk.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(now - timedelta(days=1))
                .not_valid_after(now + timedelta(days=1))
                .sign(self.sk, hashes.SHA256()))
        from cryptography.hazmat.primitives import serialization as ser
        x5c = [base64.b64encode(cert.public_bytes(ser.Encoding.DER)).decode()]
        jwt = _sign_jwt(self.sk, {"alg": "ES256", "x5c": x5c}, {"iss": "certified"})
        ap2.build_evidence([{"name": "c", "sd_jwt": jwt + "~"}], self.out)
        v = ap2.verify_evidence(self.out)
        self.assertTrue(v["valid"], v)
        self.assertEqual(v["provenance_classes"], ["x5c_header"])

    def test_cli_build_and_verify(self):
        ip = os.path.join(self.d, "intent.sdjwt")
        cp = os.path.join(self.d, "cart.sdjwt")
        open(ip, "w").write(self.intent)
        open(cp, "w").write(self.cart)
        rc = ap2.main(["build", self.out, f"intent={ip}", f"cart={cp}"])
        self.assertEqual(rc, 0)
        self.assertEqual(ap2.main(["verify", self.out]), 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)


class TestProLevelSelfAttack(_Base):
    """Trovati dall'auto-attacco a rigore Pro (2026-08-21): correzioni nei DUE sensi."""

    def test_supplied_key_beats_self_asserted_header_jwk(self):
        # forge auto-coerente (firma con B, jwk B nell'header) + chiave VERA fornita:
        # PRIMA del fix passava come jwk_header; ORA la chiave del chiamante vince → rosso
        skB, jwkB = _make_signer()
        forged = _make_sd_jwt(skB, {"iss": "impersonated"}, {"amount": "9999"},
                              header_extra={"jwk": jwkB})
        _, true_jwk = _make_signer()
        with self.assertRaises(ap2.Ap2EvidenceError):
            ap2.build_evidence([{"name": "i", "sd_jwt": forged}], self.out,
                               keys={"i": true_jwk})
        self.assertFalse(os.path.exists(self.out))

    def test_supplied_matching_key_still_green(self):
        # correzione nell'ALTRO senso: chiave fornita GIUSTA su jwt con header jwk → verde,
        # con classe 'supplied' (la scelta del chiamante domina, dichiarata)
        jwt_with_hdr = _make_sd_jwt(self.sk, {"iss": "wallet"}, {"a": 1},
                                    header_extra={"jwk": self.jwk})
        ap2.build_evidence([{"name": "i", "sd_jwt": jwt_with_hdr}], self.out,
                           keys={"i": self.jwk})
        v = ap2.verify_evidence(self.out)
        self.assertTrue(v["valid"], v)
        self.assertEqual(v["provenance_classes"], ["supplied"])
        self.assertFalse(v["self_asserted_only"])

    def test_self_asserted_forgery_is_valid_but_flagged(self):
        # limite INERENTE dichiarato, non nascosto: un forge auto-coerente senza chiave
        # esterna e' 'valid' (coerenza interna) ma self_asserted_only=True lo smaschera
        skB, jwkB = _make_signer()
        forged = _make_sd_jwt(skB, {"iss": "impersonated"}, {"amount": "9999"},
                              header_extra={"jwk": jwkB})
        ap2.build_evidence([{"name": "i", "sd_jwt": forged}], self.out)
        v = ap2.verify_evidence(self.out)
        self.assertTrue(v["valid"])
        self.assertTrue(v["self_asserted_only"])
        self.assertIn("self_asserted_only", ap2.HONEST_SCOPE)


class TestKbJwtHolderBinding(_Base):
    """KB-JWT (holder binding): verificato con cnf.jwk; tre stati onesti."""

    def _with_kb(self, holder_sk, holder_jwk, tamper_sd_hash=False):
        # issuer JWT che lega il holder via cnf.jwk
        sd = _make_sd_jwt(self.sk, {"iss": "wallet", "cnf": {"jwk": holder_jwk}},
                          {"amount": "10.00"}, header_extra={"jwk": self.jwk})
        presentation = sd            # termina gia' con '~'
        sd_hash = _b64u(hashlib.sha256(presentation.encode("ascii")).digest())
        if tamper_sd_hash:
            sd_hash = "X" + sd_hash[1:]
        kb = _sign_jwt(holder_sk, {"alg": "ES256", "typ": "kb+jwt"},
                       {"aud": "merchant", "nonce": "n1", "sd_hash": sd_hash})
        return presentation + kb

    def test_kb_verified_green(self):
        hsk, hjwk = _make_signer()
        ap2.build_evidence([{"name": "i", "sd_jwt": self._with_kb(hsk, hjwk)}], self.out)
        v = ap2.verify_evidence(self.out)
        self.assertTrue(v["valid"], v)
        self.assertTrue(v["artifacts"][0]["kb_jwt"]["verified"])

    def test_kb_wrong_holder_key_refuses_build(self):
        hsk, hjwk = _make_signer()
        wrong_sk, _ = _make_signer()          # firma il kb con la chiave SBAGLIATA
        sd = self._with_kb(wrong_sk, hjwk)
        with self.assertRaises(ap2.Ap2EvidenceError):
            ap2.build_evidence([{"name": "i", "sd_jwt": sd}], self.out)
        self.assertFalse(os.path.exists(self.out))

    def test_kb_tampered_sd_hash_refuses_build(self):
        hsk, hjwk = _make_signer()
        sd = self._with_kb(hsk, hjwk, tamper_sd_hash=True)
        with self.assertRaises(ap2.Ap2EvidenceError):
            ap2.build_evidence([{"name": "i", "sd_jwt": sd}], self.out)

    def test_kb_without_cnf_recorded_honestly(self):
        # kb presente ma issuer senza cnf.jwk: presente-ma-non-verificabile, MAI verde finto
        hsk, _ = _make_signer()
        sd = _make_sd_jwt(self.sk, {"iss": "wallet"}, {"a": 1},
                          header_extra={"jwk": self.jwk})
        kb = _sign_jwt(hsk, {"alg": "ES256", "typ": "kb+jwt"},
                       {"sd_hash": _b64u(hashlib.sha256(sd.encode()).digest())})
        ap2.build_evidence([{"name": "i", "sd_jwt": sd + kb}], self.out)
        v = ap2.verify_evidence(self.out)
        self.assertTrue(v["valid"], v)
        kbr = v["artifacts"][0]["kb_jwt"]
        self.assertTrue(kbr["present"])
        self.assertIsNone(kbr["verified"])


class TestFullContextReviewFindings(_Base):
    """Finding della review a contesto pieno (Gemini flash su repo-pack, 21/08)."""

    def test_duplicate_artifact_names_refused(self):
        with self.assertRaises(ap2.Ap2EvidenceError):
            ap2.build_evidence([{"name": "intent", "sd_jwt": self.intent},
                                {"name": "intent", "sd_jwt": self.cart}], self.out)
        self.assertFalse(os.path.exists(self.out))

    def test_kb_claims_recorded_not_validated(self):
        hsk, hjwk = _make_signer()
        sd = _make_sd_jwt(self.sk, {"iss": "wallet", "cnf": {"jwk": hjwk}},
                          {"amount": "1.00"}, header_extra={"jwk": self.jwk})
        kb = _sign_jwt(hsk, {"alg": "ES256", "typ": "kb+jwt"},
                       {"aud": "merchant-x", "nonce": "n42",
                        "sd_hash": _b64u(hashlib.sha256(sd.encode("ascii")).digest())})
        ap2.build_evidence([{"name": "i", "sd_jwt": sd + kb}], self.out)
        v = ap2.verify_evidence(self.out)
        rec = v["artifacts"][0]["kb_jwt"]["claims_recorded_not_validated"]
        self.assertEqual(rec, {"aud": "merchant-x", "nonce": "n42"})
        self.assertIn("not validated", ap2.HONEST_SCOPE)


class TestTripleMindReviewFixes(_Base):
    """Fix dal controllo delle tre menti (21/08): zero-artefatti, cap x5c."""

    def test_zero_artifacts_is_not_valid(self):
        import ap2_evidence as ap2mod
        ap2.build_evidence([{"name": "i", "sd_jwt": self.intent}], self.out)
        ev = json.load(open(self.out))
        ev["artifacts"] = []
        # ricalcola il digest così digest_ok resta True: isoliamo il SOLO effetto zero-artefatti
        e2 = {k: v for k, v in ev.items()
              if k not in ("evidence_digest_sha256", "rfc3161_timestamp")}
        ev["evidence_digest_sha256"] = ap2mod.hashlib.sha256(ap2mod._canon(e2)).hexdigest()
        json.dump(ev, open(self.out, "w"))
        v = ap2.verify_evidence(self.out)
        self.assertTrue(v["digest_ok"])          # il file è intatto...
        self.assertFalse(v["valid"])             # ...ma non prova nulla → non valido

    def test_x5c_chain_too_long_refused(self):
        # 11 certificati (>10) = vettore DoS, non una chiave
        fake = _b64u(b"x" * 20)
        jwt = _sign_jwt(self.sk, {"alg": "ES256", "x5c": [fake] * 11}, {"iss": "y"})
        with self.assertRaises(ap2.Ap2EvidenceError):
            ap2._snapshot_key(ap2.parse_sd_jwt(jwt + "~"))
