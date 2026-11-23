#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""cryptovalid_dsse (SPEC v0.15 §25, 2026-11-23): DSSE envelopes with in-toto Statements, verification only.

Data not written here: the test vector of the DSSE specification (protocol.md at v1.0.2, "Test Vectors": an ECDSA P-256
key, raw r||s) and the GitHub artifact attestation of this repository's 0.28.1 wheel (testdata/dsse/, a Sigstore
bundle: DSSE envelope, Fulcio certificate, SLSA provenance v1 statement), each verified with the key it was made with.
Generated: envelopes signed here with Ed25519 and P-256 keys, then every member removed, unknown members at each level,
every JSON type in every member, base64 variants, JSON outside the profile, statements outside in-toto v1, thresholds,
duplicate keys, subjects against an artifact. Without cryptography: CheckNotRun, never a verdict.
Positive control: the module did not exist on 5f2d57f (this file fails at its import)."""
import base64
import copy
import json
import os
import random
import sys
import unittest
from unittest import mock

sys.dont_write_bytecode = True
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import cryptovalid_dsse as D  # noqa: E402
import verifier  # noqa: E402

try:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519
    HAVE = True
except ImportError:
    HAVE = False
if os.environ.get("CV_REQUIRE_CRYPTO") == "1" and not HAVE:
    raise SystemExit("CV_REQUIRE_CRYPTO=1 but cryptography did not import")
need = unittest.skipUnless(HAVE, "cryptography not installed")
WRONG = [None, True, False, 0, 1, 1.5, "", "x", [], [1], {}, {"a": 1}]


def pem(k):
    return k.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)


def b64(b, url=False):
    return (base64.urlsafe_b64encode if url else base64.standard_b64encode)(b).decode()


def statement(**kw):
    st = {"_type": D.STATEMENT_TYPE, "subject": [{"name": "a.txt", "digest": {"sha256": D.DIGESTS["sha256"](b"A").hexdigest()}},
                                                  {"name": "b.txt", "digest": {"sha512": D.DIGESTS["sha512"](b"B").hexdigest()}}],
          "predicateType": "https://example.org/p/v1", "predicate": {"x": 1.5}}
    st.update(kw)
    return st


def envelope(keys, payload=None, pt=D.PAYLOAD_TYPE, url=False):
    payload = json.dumps(statement()).encode() if payload is None else payload
    sigs = []
    for k in keys:
        m = D.pae(pt, payload)
        s = k.sign(m) if isinstance(k, ed25519.Ed25519PrivateKey) else k.sign(m, ec.ECDSA(hashes.SHA256()))
        sigs.append({"keyid": "", "sig": b64(s, url)})
    return {"payload": b64(payload, url), "payloadType": pt, "signatures": sigs}


def js(o):
    return json.dumps(o).encode()


class Real(unittest.TestCase):
    @need
    def test_dsse_specification_vector(self):
        # protocol.md v1.0.2, Test Vectors
        self.assertEqual(D.pae("http://example.com/HelloWorld", b"hello world"),
                         b"DSSEv1 29 http://example.com/HelloWorld 11 hello world")
        X = 46950820868899156662930047687818585632848591499744589407958293238635476079160
        Y = 5640078356564379163099075877009565129882514886557779369047442380624545832820
        key = ec.EllipticCurvePublicNumbers(X, Y, ec.SECP256R1()).public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        env = {"payload": "aGVsbG8gd29ybGQ=", "payloadType": "http://example.com/HelloWorld",
               "signatures": [{"sig": "A3JqsQGtVsJ2O2xqrI5IcnXip5GToJ3F+FnZ+O88SjtR6rDAajabZKciJTfUiHqJPcIAriEGAHTVeCUjW2JIZA=="}]}
        r = D.verify_envelope(js(env), [key])
        self.assertEqual((r["code"], r["verified_keys"]), ("payload_type", [0]))   # the signature holds; not in-toto
        env["payload"] = "aGVsbG8gd29ybGQh"
        self.assertEqual(D.verify_envelope(js(env), [key])["code"], "signature")

    @need
    def test_github_attestation_of_the_0_28_1_wheel(self):
        with open(os.path.join(HERE, "testdata", "dsse", "github_attestation_cvo_0.28.1_wheel.json"), "rb") as f:
            bundle = json.load(f)
        cert = base64.b64decode(bundle["verificationMaterial"]["certificate"]["rawBytes"])
        env = bundle["dsseEnvelope"]
        r = D.verify_envelope(js(env), [cert])
        self.assertEqual(r["code"], "ok", r["detail"])
        self.assertEqual(r["statement"]["predicateType"], "https://slsa.dev/provenance/v1")
        self.assertEqual(r["statement"]["subject"][0]["digest"]["sha256"],
                         "2f5f302ceb76873bd24da38aeadf7f767da9a8d5dfca6b623f0cafbde0e709d9")
        pem_cert = b"-----BEGIN CERTIFICATE-----\n" + base64.encodebytes(cert) + b"-----END CERTIFICATE-----\n"
        self.assertEqual(D.verify_envelope(js(env), [pem_cert])["code"], "ok")
        st = json.loads(base64.b64decode(env["payload"]))
        st["subject"][0]["digest"]["sha256"] = "0" * 64
        self.assertEqual(D.verify_envelope(js(dict(env, payload=b64(json.dumps(st).encode()))), [cert])["code"],
                         "signature")
        other = pem(ec.generate_private_key(ec.SECP256R1()))
        self.assertEqual(D.verify_envelope(js(env), [other])["code"], "signature")


@need
class Generated(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ed = ed25519.Ed25519PrivateKey.generate()
        cls.p256 = ec.generate_private_key(ec.SECP256R1())
        cls.env = envelope([cls.ed])

    def v(self, env, keys=None, **kw):
        return D.verify_envelope(env if isinstance(env, (bytes, str)) else js(env), keys or [pem(self.ed)], **kw)

    def test_valid_both_alphabets_both_key_types(self):
        for k in (self.ed, self.p256):
            for url in (False, True):
                r = self.v(envelope([k], url=url), [pem(k)])
                self.assertEqual((r["code"], r["valid"], r["verified_keys"]), ("ok", True, [0]))
        self.assertEqual(self.v(self.env)["statement"]["predicate"], {"x": 1.5})

    def test_artifact_matching(self):
        r = self.v(self.env, artifact=b"A")
        self.assertEqual((r["code"], r["matched_subjects"]), ("ok", [0]))
        self.assertEqual(self.v(self.env, artifact=b"B")["code"], "subject")             # sha512 not acceptable
        self.assertEqual(self.v(self.env, artifact=b"B", digest_algorithms=["sha256", "sha512"])["matched_subjects"], [1])
        self.assertEqual(self.v(self.env, artifact=b"C")["code"], "subject")
        up = envelope([self.ed], json.dumps(statement(subject=[{"digest": {"sha256": D.DIGESTS["sha256"](b"A").hexdigest().upper()}}])).encode())
        self.assertEqual(self.v(up, artifact=b"A")["code"], "ok")                        # hexDecode: case does not matter
        self.assertEqual(self.v(self.env)["matched_subjects"], [])

    def test_threshold_counts_unique_keys(self):
        two = envelope([self.ed, self.p256])
        keys = [pem(self.ed), pem(self.p256)]
        self.assertEqual(self.v(two, keys, threshold=2)["verified_keys"], [0, 1])
        self.assertEqual(self.v(self.env, keys, threshold=2)["code"], "signature")
        dup = dict(self.env, signatures=self.env["signatures"] * 2)
        self.assertEqual(self.v(dup, keys, threshold=2)["code"], "signature")            # one signer twice
        with self.assertRaises(ValueError):
            self.v(dup, [pem(self.ed), pem(self.ed)], threshold=2)                       # the same key twice

    def test_keyid_is_not_used_and_unknown_members_are_reported(self):
        e = copy.deepcopy(self.env)
        e["signatures"][0]["keyid"] = "someone-else"
        e["signatures"][0]["publicKeyB64"] = b64(b"\0" * 32)
        e["extra"] = {"a": 1}
        r = self.v(e)
        self.assertEqual((r["code"], r["unrecognized_fields"]), ("ok", ["extra", "signatures[0].publicKeyB64"]))
        e2 = copy.deepcopy(self.env)
        del e2["signatures"][0]["keyid"]
        self.assertEqual(self.v(e2)["code"], "ok")

    def test_envelope_members_missing_and_of_every_type(self):
        for k in ("payload", "payloadType", "signatures"):
            e = dict(self.env)
            del e[k]
            self.assertEqual(self.v(e)["code"], "envelope", k)
            for w in WRONG:
                if k == "payload" and w in ("", "x") or k == "payloadType" and isinstance(w, str):
                    continue
                if k == "signatures" and w in ([],):
                    self.assertEqual(self.v(dict(self.env, **{k: w}))["code"], "signature")
                    continue
                self.assertEqual(self.v(dict(self.env, **{k: w}))["code"], "envelope", (k, w))
        for w in WRONG:
            if isinstance(w, str):
                continue
            for member in ("sig", "keyid"):
                e = copy.deepcopy(self.env)
                e["signatures"][0][member] = w
                self.assertEqual(self.v(e)["code"], "envelope", (member, w))
            e = copy.deepcopy(self.env)
            e["signatures"] = [w]
            self.assertEqual(self.v(e)["code"], "envelope", w)
        e = copy.deepcopy(self.env)
        del e["signatures"][0]["sig"]
        self.assertEqual(self.v(e)["code"], "envelope")
        for w in WRONG + ["[]", "1"]:
            if not isinstance(w, dict):
                self.assertEqual(self.v(js(w) if not isinstance(w, str) else w.encode())["code"], "envelope", w)

    def test_json_outside_the_profile(self):
        good = js(self.env).decode()
        cases = [good.replace('{"payload"', '{"payload": "", "payload"', 1), good.replace("}", ', "a": NaN}', 1),
                 "﻿" + good, good[:-1], "[" * 600 + "]" * 600, good + "x"]
        for c in cases:
            self.assertEqual(self.v(c.encode("utf-8"))["code"], "envelope", c[:40])
        self.assertEqual(self.v(b"\xff" + js(self.env))["code"], "envelope")
        self.assertEqual(self.v(good)["code"], "ok")   # str is read as well as bytes

    def test_base64_variants(self):
        p = self.env["payload"]
        for bad in (p + "=", p.rstrip("=") if p.endswith("=") else p[:-1], " " + p, p + "\n", p[:4] + "-" + p[5:].replace("/", "+") + "/" if len(p) > 6 else p + "!", "!" * 8):
            r = self.v(dict(self.env, payload=bad))
            self.assertIn(r["code"], ("base64", "signature"), bad)
            self.assertFalse(r["valid"])
        e = copy.deepcopy(self.env)
        e["signatures"][0]["sig"] = "a=b="
        self.assertEqual(self.v(e)["code"], "base64")

    def test_signature_bits_and_payload_type_bound(self):
        rnd = random.Random(25)
        sig = base64.b64decode(self.env["signatures"][0]["sig"])
        for _ in range(64):
            b = bytearray(sig)
            b[rnd.randrange(len(b))] ^= 1 << rnd.randrange(8)
            e = copy.deepcopy(self.env)
            e["signatures"][0]["sig"] = b64(bytes(b))
            self.assertEqual(self.v(e)["code"], "signature")
        self.assertEqual(self.v(dict(self.env, payloadType="application/vnd.in-toto.slsa+json"))["code"], "signature")
        for pt in ("application/vnd.in-toto.provenance+json", "application/vnd.in-toto+json"):
            self.assertEqual(self.v(envelope([self.ed], pt=pt))["code"], "ok", pt)
        for pt in ("application/json", "application/vnd.in-toto+JSON", "application/vnd.in-toto.+json",
                   "application/vnd.in-toto.a/b+json", "", "application/vnd.in-toto+json "):
            self.assertEqual(self.v(envelope([self.ed], pt=pt))["code"], "payload_type", pt)

    def test_statement_layer(self):
        bad = [b"not json", b"[]", b"\xff", json.dumps(statement(_type="https://in-toto.io/Statement/v0.1")).encode(),
               b'{"_type": "https://in-toto.io/Statement/v1", "_type": "https://in-toto.io/Statement/v1"}']
        for st in (statement(subject=w) for w in WRONG if not isinstance(w, list) or w == [1]):
            bad.append(json.dumps(st).encode())
        for sub in ([{}], [{"digest": {}}], [{"digest": {"sha256": 1}}], [{"digest": []}], [{"name": "x"}]):
            bad.append(json.dumps(statement(subject=sub)).encode())
        for pt in (None, "", 1, [], {}):
            bad.append(json.dumps(statement(predicateType=pt)).encode())
        for pr in (None, 1, "x", []):
            bad.append(json.dumps(statement(predicate=pr)).encode())
        no_type = statement()
        del no_type["predicateType"]
        bad.append(json.dumps(no_type).encode())
        for p in bad:
            self.assertEqual(self.v(envelope([self.ed], payload=p))["code"], "statement", p[:60])
        ok = statement(subject=[], extension={"a": [1]})
        del ok["predicate"]
        self.assertEqual(self.v(envelope([self.ed], payload=json.dumps(ok).encode()))["code"], "ok")

    def test_base64_reader(self):
        self.assertEqual(D._unb64("YQ=="), b"a")
        self.assertEqual(D._unb64("+/8="), b"\xfb\xff")
        self.assertEqual(D._unb64("-_8="), b"\xfb\xff")
        self.assertEqual(D._unb64(""), b"")
        # "YWJj=" and "YWJj==": whole quads, then padding; base64.b64decode(validate=True) of Python 3.9 and 3.11 reads
        # them as b"abc" (3.13 refuses): the length rule is what makes the three agree (review of 7d87346)
        for bad in ("YQ", "YQ=", "YQ===", "+_8=", "YQ==YQ==", "Y Q==", "YQ==\n", "YQ!=", None, b"YQ==", 1, "YWJj=",
                    "YWJj==", "YWJjYWJj="):
            with self.assertRaises(ValueError, msg=repr(bad)):
                D._unb64(bad)

    def test_key_reader_messages(self):
        p = pem(self.ed)
        D.load_key(p)
        D.load_key(p.decode())
        D.load_key(serialization.load_pem_public_key(p).public_bytes(serialization.Encoding.DER,
                                                                         serialization.PublicFormat.SubjectPublicKeyInfo))
        for bad, msg in ((b"", "PEM text or PEM / DER"), (1, "PEM text or PEM / DER"), (p + p, "exactly one"),
                         (p + b"-----BEGIN X-----\n", "exactly one"),
                         (p.replace(b"PUBLIC KEY", b"RSA PUBLIC KEY"), "exactly one"),
                         (b"-----BEGIN PUBLIC KEY-----\nAA==\n-----END PUBLIC KEY-----\n", "neither")):
            with self.assertRaisesRegex(ValueError, msg):
                D.load_key(bad)
        self.assertEqual(self.v(self.env, keys=(pem(self.ed),))["code"], "ok")
        for keys in ({pem(self.ed)}, b"", "", None, ()):
            with self.assertRaisesRegex(ValueError, "non-empty list"):
                D.verify_envelope(js(self.env), keys)

    def test_errors_of_the_caller(self):
        e = js(self.env)
        for kw in ({"keys": []}, {"keys": pem(self.ed)}, {"keys": [b"junk"]}, {"keys": ["é"]},
                   {"keys": [pem(self.ed) + pem(self.p256)]}, {"keys": [pem(ec.generate_private_key(ec.SECP384R1()))]},
                   {"threshold": 0}, {"threshold": 2}, {"threshold": True}, {"digest_algorithms": []},
                   {"digest_algorithms": "sha256"}, {"digest_algorithms": ["md5"]}):
            kw = dict({"keys": [pem(self.ed)]}, **kw)
            with self.assertRaises(ValueError, msg=str(kw)[:80]):
                D.verify_envelope(e, **kw)
        for bad in ({"artifact": "A"}, {"envelope": 1}):
            with self.assertRaises(TypeError):
                D.verify_envelope(bad.get("envelope", e), [pem(self.ed)], artifact=bad.get("artifact"))

    def test_generated_mutations_never_raise_and_never_pass_unless_ignorable(self):
        rnd = random.Random(2511)
        base = js(self.env).decode()
        for _ in range(400):
            obj = json.loads(base)
            path = rnd.choice(["top", "sig"])
            tgt = obj if path == "top" else obj["signatures"][0]
            k = rnd.choice(list(tgt) + ["new" + str(rnd.randrange(5))])
            op = rnd.choice(["del", "set"])
            if op == "del" and k in tgt:
                del tgt[k]
            else:
                tgt[k] = rnd.choice(WRONG + ["AAAA", obj["payload"][::-1]])
            r = self.v(obj)
            ignorable = k.startswith("new") or (path == "sig" and k == "keyid" and (op == "del" or isinstance(tgt.get(k), str)))
            self.assertIn(r["code"], D.CODES)
            if r["valid"]:
                self.assertTrue(ignorable, (path, k, op))


class Without(unittest.TestCase):
    def test_without_cryptography_nothing_is_decided(self):
        blocked = {m: None for m in ("cryptography", "cryptography.x509", "cryptography.exceptions",
                                     "cryptography.hazmat.primitives", "cryptography.hazmat.primitives.asymmetric",
                                     "cryptography.hazmat.primitives.asymmetric.utils")}
        with mock.patch.dict(sys.modules, blocked):
            with self.assertRaises(verifier.CheckNotRun) as cm:
                D.verify_envelope(b"{}", ["-----BEGIN PUBLIC KEY-----\nAA==\n-----END PUBLIC KEY-----\n"])
        self.assertIn("cryptography", str(cm.exception))

    def test_codes_are_closed(self):
        self.assertEqual(D.CODES, ("ok", "envelope", "base64", "signature", "payload_type", "statement", "subject"))


@need
class Review(unittest.TestCase):
    """review of 7d87346"""

    @classmethod
    def setUpClass(cls):
        cls.ed = ed25519.Ed25519PrivateKey.generate()
        cls.env = envelope([cls.ed])

    def v(self, env):
        return D.verify_envelope(env if isinstance(env, (bytes, str)) else js(env), [pem(self.ed)])

    def test_a_payload_type_without_utf8_is_a_code_not_an_exception(self):
        """JSON "\\ud800" parses to a lone surrogate; the PAE has no bytes for it and verify_envelope raised
        UnicodeEncodeError"""
        for pt in ('"\\ud800"', '"application/vnd.in-toto+json\\udfff"'):
            for sigs in ("[]", '[{"sig": "AAAA"}]'):
                out = self.v('{"payload": "", "payloadType": %s, "signatures": %s}' % (pt, sigs))
                self.assertEqual((out["valid"], out["code"]), (False, "envelope"), (pt, sigs))
        self.assertEqual(self.v(dict(self.env, keyid_hint="\ud800"))["code"], "ok")   # an unread member: ignored

    def test_nesting_at_the_bound(self):
        """rule 1: 512 levels are read, 513 refused (the envelope is one level, the member's arrays the others)"""
        good = js(self.env).decode()
        for extra, code in ((511, "ok"), (512, "envelope")):
            text = good[:-1] + ', "x": ' + "[" * extra + "]" * extra + "}"
            self.assertEqual(verifier.json_nesting_depth(text), extra + 1)
            self.assertEqual(self.v(text)["code"], code, extra)
        for extra, code in ((511, "ok"), (512, "statement")):   # the same bound on the payload (rule 3)
            payload = json.dumps(statement())[:-1] + ', "x": ' + "[" * extra + "]" * extra + "}"
            self.assertEqual(self.v(envelope([self.ed], payload.encode()))["code"], code, extra)

    def test_the_size_bound_is_exact(self):
        raw = js(self.env)
        for limit, code in ((len(raw), "ok"), (len(raw) - 1, "envelope")):
            with mock.patch.object(D, "MAX_ENVELOPE", limit):
                self.assertEqual(self.v(raw)["code"], code, limit)
                self.assertEqual(self.v(raw.decode())["code"], code, limit)
        wide = json.dumps(dict(self.env, note="\u00e9"), ensure_ascii=False)   # one character, two bytes
        with mock.patch.object(D, "MAX_ENVELOPE", len(wide)):
            self.assertEqual(self.v(wide)["code"], "ok")                         # the text: characters
            self.assertEqual(self.v(wide.encode("utf-8"))["code"], "envelope")   # the bytes: one too many


if __name__ == "__main__":
    unittest.main()
