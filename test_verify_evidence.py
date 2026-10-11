#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Banco del verificatore unico: PRIMA dimostra di saper FALLIRE (ogni strato manomesso
-> valid False), poi il positivo. Fixture reali costruite qui (evidence pack firmato,
archivio ingest, ap2, cldma). Tutto in tempdir: nessun path di produzione toccato."""
import json
import os
import sys
import tempfile
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
import verify_evidence as VE  # noqa: E402


class TestPackLayer(unittest.TestCase):
    def setUp(self):
        import evidence_pack
        import signer
        from test_evidence_pack import _make_ledger
        self.d = tempfile.mkdtemp(prefix="ve_pack_")
        led = os.path.join(self.d, "l.jsonl")
        signed = os.path.join(self.d, "l.signed.jsonl")
        key = os.path.join(self.d, "k.key")
        _make_ledger(led)
        signer.keygen(key)
        signer.sign_ledger(led, signed, key)
        self.pack = os.path.join(self.d, "pack")
        evidence_pack.build_pack([signed], self.pack, subject="ve bench", sign_key=key)

    def test_pack_sano_valido(self):
        r = VE.verify_pack(self.pack)
        self.assertTrue(r["valid"], r)

    def test_pack_manomesso_invalido(self):
        # il banco DEVE fallire: cambia un byte in un file del pack
        p = os.path.join(self.pack, "l.signed.jsonl")
        rows = [json.loads(x) for x in open(p)]
        rows[1]["data"]["d"] = "reject"
        with open(p, "w") as f:
            for x in rows:
                f.write(json.dumps(x) + "\n")
        r = VE.verify_pack(self.pack)
        self.assertFalse(r["valid"], "manomissione non rilevata!")

    def test_pack_firma_presente_rotta_invalido(self):
        # audit V1 #1 (30/09/2026): one byte of manifest_signature changed -> evidence_pack says invalid; so must this front-end
        import base64
        p = os.path.join(self.pack, "MANIFEST.json")
        man = json.load(open(p))
        sig = bytearray(base64.b64decode(man["manifest_signature"]))
        sig[0] ^= 1
        man["manifest_signature"] = base64.b64encode(bytes(sig)).decode()
        json.dump(man, open(p, "w"), indent=2, sort_keys=True)
        r = VE.verify_pack(self.pack)
        self.assertFalse(r["valid"], r)
        self.assertIn("FAIL", [x["status"] for x in r["layers"] if x["layer"].startswith("manifest autenticato")])

    def test_auto_detect_pack(self):
        r = VE.verify_auto(self.pack)
        self.assertEqual(r["kind"], "pack")
        self.assertTrue(r["valid"])


try:
    import ap2_evidence as _ap2_pkg   # the reference verifier is a dependency since 0.18.0 (extra `ap2`)
except ImportError:
    _ap2_pkg = None

# SD-JWT fixtures (a real ES256 signer + selective disclosures), used also by test_mcp.py and test_audit_v1_types.py.
# They were in test_ap2_evidence.py until 0.17.2; that file went to ap2-evidence-pack with the module it tested.
import base64 as _b64
import hashlib as _hl
from cryptography.hazmat.primitives import hashes as _hashes
from cryptography.hazmat.primitives.asymmetric import ec as _ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature as _dds


def _b64u(b: bytes) -> str:
    return _b64.urlsafe_b64encode(b).decode().rstrip("=")


def _make_signer():
    sk = _ec.generate_private_key(_ec.SECP256R1())
    nums = sk.public_key().public_numbers()
    return sk, {"kty": "EC", "crv": "P-256", "x": _b64u(nums.x.to_bytes(32, "big")), "y": _b64u(nums.y.to_bytes(32, "big"))}


def _sign_jwt(sk, header: dict, payload: dict) -> str:
    si = f"{_b64u(json.dumps(header).encode())}.{_b64u(json.dumps(payload).encode())}"
    r, s = _dds(sk.sign(si.encode("ascii"), _ec.ECDSA(_hashes.SHA256())))
    return f"{si}.{_b64u(r.to_bytes(32, 'big') + s.to_bytes(32, 'big'))}"


def _make_sd_jwt(sk, claims_open: dict, claims_sd: dict, header_extra: dict = None) -> str:
    """A real SD-JWT: open claims + selectively-disclosed claims via _sd digests (SD-JWT: base64url(sha-256(disclosure)))."""
    discs = [_b64u(json.dumps([f"salt{i}", k, v]).encode()) for i, (k, v) in enumerate(claims_sd.items())]
    payload = dict(claims_open, _sd=sorted(_b64u(_hl.sha256(d.encode("ascii")).digest()) for d in discs), _sd_alg="sha-256")
    header = {"alg": "ES256", "typ": "ap2-mandate+sd-jwt"}
    header.update(header_extra or {})
    return _sign_jwt(sk, header, payload) + "~" + "~".join(discs) + "~"


@unittest.skipUnless(_ap2_pkg, "ap2-evidence-pack not installed (pip install 'cryptovalid-opencore[ap2]')")
class TestAp2Layer(unittest.TestCase):
    def setUp(self):
        import ap2_evidence
        import test_verify_evidence as fx
        self.d = tempfile.mkdtemp(prefix="ve_ap2_")
        sk, jwk = fx._make_signer()
        sd = fx._make_sd_jwt(sk, {"iss": "wallet"}, {"amount": "9.99"},
                             header_extra={"jwk": jwk})
        self.out = os.path.join(self.d, "ev.json")
        ap2_evidence.build_evidence([{"name": "intent", "sd_jwt": sd}], self.out)

    def test_ap2_refusal_reason_reaches_the_receipt(self):
        # a pack whose honest_scope is not the canonical one is refused by the reference (SPEC §1); the front-end must say why.
        # Before 0.18.0 the detail was empty (the front-end read `error`; the receipt says `refused` since ap2-evidence-pack 1.1.0).
        ev = json.load(open(self.out))
        ev["honest_scope"] = "not the canonical scope"
        json.dump(ev, open(self.out, "w"))
        r = VE.verify_ap2(self.out)
        self.assertFalse(r["valid"])
        last = r["layers"][-1]
        self.assertEqual(last["status"], "FAIL")
        self.assertIn("honest_scope", last["detail"])

    def test_ap2_sano_valido(self):
        r = VE.verify_ap2(self.out)
        self.assertTrue(r["valid"], r)

    def test_ap2_manomesso_invalido(self):
        ev = json.load(open(self.out))
        ev["subject"] = "tampered"
        json.dump(ev, open(self.out, "w"))
        r = VE.verify_ap2(self.out)
        self.assertFalse(r["valid"], "manomissione ap2 non rilevata!")

    def test_ap2_firma_producer_presente_rotta_invalido(self):
        # audit V1 #2 (30/09/2026): one byte of the producer signature changed -> ap2_evidence says invalid; so must this front-end
        import ap2_evidence
        ap2_evidence.sign_evidence(self.out)
        self.assertTrue(VE.verify_ap2(self.out)["valid"])          # control: the signed pack passes
        ev = json.load(open(self.out))
        s0 = ev["producer_signatures"]["signatures"][0]
        v = s0["signature_b64"]
        s0["signature_b64"] = v[:-2] + ("A" if v[-2] != "A" else "B") + v[-1:]   # the digest stays valid: only the signature breaks
        json.dump(ev, open(self.out, "w"), ensure_ascii=False, indent=1, sort_keys=True)
        r = VE.verify_ap2(self.out)
        self.assertFalse(r["valid"], r)

    def test_ap2_without_artifacts_is_invalid(self):
        # NEMESIS V1 (01/10/2026), mutant VE6: an evidence with no artifacts proves nothing; only the reference-verdict
        # layer catches it here (the per-artifact layer is vacuously true on an empty list)
        import hashlib
        import ap2_evidence
        ev = json.load(open(self.out))
        ev["artifacts"] = []
        body = {k: v for k, v in ev.items() if k not in ("evidence_digest_sha256", "rfc3161_timestamp", "producer_signatures")}
        ev["evidence_digest_sha256"] = hashlib.sha256(ap2_evidence._canon(body)).hexdigest()
        json.dump(ev, open(self.out, "w"))
        self.assertTrue(ap2_evidence.verify_evidence(self.out)["digest_ok"])        # control: the digest itself is right
        self.assertFalse(VE.verify_ap2(self.out)["valid"])

    def test_auto_detect_ap2(self):
        r = VE.verify_auto(self.out)
        self.assertEqual(r["kind"], "ap2")

    def test_auto_detect_ap2_when_evidence_format_is_past_the_sniff_window(self):
        # 0.18.0: `ap2-evidence build` with two mandates puts `evidence_format` at byte 3506 (keys sorted, `artifacts`
        # first); a 2048-byte sniff routed the file to the ledger verifier (FAIL on a valid pack). Without the check (48fca5d) this fails.
        import ap2_evidence
        import test_verify_evidence as fx
        sk, jwk = fx._make_signer()
        arts = [{"name": n, "sd_jwt": fx._make_sd_jwt(sk, {"iss": "wallet", "pad": "x" * 600}, {"amount": "9.99"},
                                                      header_extra={"jwk": jwk})} for n in ("intent", "cart", "payment")]
        out = os.path.join(self.d, "ev3.json")
        ap2_evidence.build_evidence(arts, out)
        with open(out, encoding="utf-8") as f:
            text = f.read()
        self.assertGreater(text.find('"evidence_format"'), 2048, "fixture too small to exercise the window")
        self.assertTrue(ap2_evidence.verify_evidence(out)["valid"])          # control: the reference accepts the pack
        r = VE.verify_auto(out)
        self.assertEqual(r["kind"], "ap2")
        self.assertTrue(r["valid"])


class TestCldmaLayer(unittest.TestCase):
    def setUp(self):
        import committed_attestation as C
        self.d = tempfile.mkdtemp(prefix="ve_cldma_")
        led = [{"loan_id": "L", "principal_outstanding": "100.00",
                "days_overdue": "40", "status": "active"}]
        c = C.commit_ledger(led, "s", C.SPEC_PAR30, "2026-08-20")
        self.att = os.path.join(self.d, "att.json")
        json.dump(C.attestation(c), open(self.att, "w"))

    def test_cldma_sano_valido(self):
        r = VE.verify_cldma(self.att)
        self.assertTrue(r["valid"], r)

    def test_cldma_totali_falsi_invalido(self):
        # il buco A chiuso ieri: totali falsi con radice reale -> DEVE fallire
        att = json.load(open(self.att))
        att["numerator_minor"] = 0
        att["ratio"] = "0.000000"
        json.dump(att, open(self.att, "w"))
        r = VE.verify_cldma(self.att)
        self.assertFalse(r["valid"], "totali falsi non rilevati!")


class TestArchiveLayer(unittest.TestCase):
    def test_archive_sano_valido(self):
        import cryptovalid_ingest as ingest
        d = tempfile.mkdtemp(prefix="ve_arch_")
        i = ingest.Ingestor(os.path.join(d, "arch"), batch_size=4)
        for k in range(6):
            i.append({"event": "x", "n": k})
        i.seal()
        r = VE.verify_archive(os.path.join(d, "arch"))
        self.assertTrue(r["valid"], r)



class TestLedgerReasons(unittest.TestCase):
    """0.20.0: `cryptovalid-verify ledger` names WHY a ledger fails (it printed only verdict=FAIL); a PASS carries no reasons."""
    def _chain(self, mutate=None):
        import verifier as V
        prev, es = "0" * 64, []
        for i in range(3):
            e = {"idx": i, "ts": f"2026-10-11T10:0{i}:00Z", "data": {"n": i}, "prev_hash": prev}
            if mutate:
                mutate(i, e)
            e["self_hash"] = V.hash_with("sha256", V.canonical_payload(e)); prev = e["self_hash"]; es.append(e)
        return es

    def _run(self, es, post=None):
        d = tempfile.mkdtemp(); self.addCleanup(lambda: __import__("shutil").rmtree(d, ignore_errors=True))
        if post:
            post(es)
        p = os.path.join(d, "l.jsonl")
        with open(p, "w", encoding="utf-8") as f:
            f.write("".join(json.dumps(e) + "\n" for e in es))
        return VE.verify_ledger(p)["layers"][0]

    def test_intact_has_no_reasons(self):
        lay = self._run(self._chain())
        self.assertEqual((lay["status"], lay["detail"]), ("PASS", "verdict=PASS")); self.assertNotIn("reasons", lay)

    def test_each_failure_class_is_named(self):
        cases = {
            "hash idx 1: hash_mismatch": dict(post=lambda es: es[1]["data"].update(n=9)),
            "link idx 2: prev_hash does not link": dict(post=lambda es: es[2].update(prev_hash="f" * 64)),
            "schema idx 1: unknown_field:zz": dict(mutate=lambda i, e: e.update(zz=1) if i == 1 else None),
            "line 0: idx_mismatch": dict(mutate=lambda i, e: e.pop("idx")),
        }
        for want, kw in cases.items():
            lay = self._run(self._chain(kw.get("mutate")), kw.get("post"))
            self.assertEqual(lay["status"], "FAIL", want)
            self.assertTrue(any(r.startswith(want) for r in lay["reasons"]), (want, lay["reasons"]))
            self.assertIn(want, lay["detail"]) if want.startswith(lay["reasons"][0][:8]) else None
            self.assertNotIn("None", " ".join(lay["reasons"]), lay["reasons"])

    def test_idx_value_is_printed_as_json_and_absent_is_missing(self):
        """README 0.20.0: «idx_mismatch says what was there»: null, "1", an absent key are three different texts, and the
        reasons never print Python's None (absent vs null, the class 0.20.0 closes)."""
        want = {"absent": "(missing)", "null": "null", "str": '"1"', "bool": "true", "nonascii": '"\u00e9"',
                "list": "[1,2]"}
        vals = {"null": None, "str": "1", "bool": True, "nonascii": "\u00e9", "list": [1, 2]}
        for name, text in want.items():
            def mut(i, e, name=name):
                if i == 1:
                    e.pop("idx") if name == "absent" else e.update(idx=vals[name])
            es = self._chain(mut)
            es[1]["data"]["n"] = 9                                  # a hash failure on the same entry: its idx is printed too
            lay = self._run(es)
            self.assertIn(f"line 1: idx_mismatch: expected 1, got {text}", lay["reasons"], (name, lay["reasons"]))
            self.assertNotIn("None", " ".join(lay["reasons"]), lay["reasons"])
            self.assertEqual(lay["detail"], "verdict=FAIL; " + "; ".join(lay["reasons"][:3]))

    @unittest.skipUnless(__import__("shutil").which("node"), "node not on PATH")
    def test_js_prints_the_same_idx_text(self):
        import subprocess, verifier as V
        js = os.path.join(_HERE, "verifiers", "js", "cvverify.mjs")
        for v in ("absent", None, "1", True, "\u00e9", [1, 2]):
            es = self._chain(lambda i, e, v=v: (e.pop("idx") if v == "absent" else e.update(idx=v)) if i == 1 else None)
            d = tempfile.mkdtemp(); self.addCleanup(lambda d=d: __import__("shutil").rmtree(d, ignore_errors=True))
            p = os.path.join(d, "l.jsonl")
            with open(p, "w", encoding="utf-8") as f:
                f.write("".join(json.dumps(e) + "\n" for e in es))
            py = [x["error"] for x in V.verify_ledger(p)["parse_errors"]]
            out = json.loads(subprocess.run(["node", js, p], capture_output=True, text=True).stdout)
            self.assertEqual([x["error"] for x in out["errors"]], py, v)

    def test_missing_file_is_named(self):
        lay = VE.verify_ledger("/nonexistent/cv-0200.jsonl")["layers"][0]
        self.assertEqual(lay["status"], "FAIL"); self.assertIn("file not found", lay["reasons"])

if __name__ == "__main__":
    unittest.main(verbosity=2)
