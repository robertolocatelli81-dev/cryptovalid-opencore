#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""SPEC v0.12 (18/11/2026), from a measurement of 0.26.0 over 126 files committed in other projects on GitHub.

1. §11 step 3: the TSTInfo's `nonce` is an INTEGER of either sign (RFC 3161 §2.4.2 sets none). 0.26.0 refused a real
   DigiCert token whose nonce is negative as `malformed` ("nonce: negative INTEGER"), stricter than its own SPEC, which
   asks "not negative" only of serialNumber; OpenSSL `ts -verify` says OK. Now `verified` under the DigiCert root.
2. §5 "Failure classes": a FAIL receipt counts the chain's findings apart from the entries that are not in this format.
   On a ledger of another schema 0.26.0 named the true link breaks among one `unknown_field` and one `idx_mismatch` per
   entry; now `failure_classes` gives the counts by class and `cryptovalid-verify ledger` writes the chain first.
3. §11 step 1: a SignedData whose version is not 3 with eContentType id-ct-TSTInfo stays refused (RFC 5652 §5.1); the
   EuroCert token of esig/dss is the real case.
4. §11 step 6: the token of a Sigstore bundle that carries no certificate is `signer_certificate_absent` (0.26.0:
   `signature_invalid`).

The real tokens are in spec/vectors/rfc3161/third_party/ (manifest.json: source, commit, licence). Generative: every
INTEGER encoding of 0 to 9 bytes drawn at random for the nonce and for serialNumber against an oracle written from
X.690 §8.3.2 and RFC 3161; tokens signed by an openssl TSA made on this machine with negative, zero, positive and
boundary nonces; the SignedData version 0 to 6 and -1 on real tokens; ledgers with random mutations of six kinds and an
oracle that counts each class independently of the verifier.

Positive control, measured: on 255eec5 (before this change) 8 of the 11 tests of this file fail; the three that pass
there are the file hashes, the EuroCert refusal (already right) and the PASS receipt without classes."""
import hashlib
import json
import os
import random
import shutil
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True
ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)
import cryptovalid_tsa as T  # noqa: E402
import verifier  # noqa: E402
import verify_evidence  # noqa: E402

OPENSSL = shutil.which("openssl") is not None
NEEDS = unittest.skipUnless(OPENSSL, "needs openssl")
V3 = os.path.join(ROOT, "spec", "vectors", "rfc3161")
TP = os.path.join(V3, "third_party")


def _read(path):
    with open(path, "rb") as f:
        return f.read()


def der(tag, v):
    n = len(v)
    ln = bytes([n]) if n < 0x80 else bytes([0x80 | ((n.bit_length() + 7) // 8)]) + n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([tag]) + ln + v


def items(b):
    out, i = [], 0
    while i < len(b):
        t = b[i]
        n = b[i + 1]
        j = i + 2
        if n & 0x80:
            k = n & 0x7F
            n = int.from_bytes(b[j:j + k], "big")
            j += k
        out.append((t, b[j:j + n]))
        i = j + n
    return out


def tstinfo_elements(token):
    (_, ci), = items(token)
    _, (_, sd0) = items(ci)
    (_, sd), = items(sd0)
    (_, octet), = items(items(items(sd)[2][1])[1][1])
    (_, tst), = items(octet)
    return items(tst)


def with_tstinfo(token, change):
    """the token with its TSTInfo elements passed through `change` (a list of (tag, value) -> list), lengths re-encoded;
    the signature no longer matches: for the reading of steps 1-4 only"""
    (_, ci), = items(token)
    oid, (_, sd0) = items(ci)
    (_, sd), = items(sd0)
    sde = items(sd)
    eci = items(sde[2][1])
    (_, octet), = items(eci[1][1])
    (_, tst), = items(octet)
    new_tst = der(0x30, b"".join(der(t, v) for t, v in change(items(tst))))
    new_eci = der(0x30, der(*eci[0]) + der(0xA0, der(0x04, new_tst)))
    new_sd = der(0x30, der(*sde[0]) + der(*sde[1]) + new_eci + b"".join(der(t, v) for t, v in sde[3:]))
    return der(0x30, der(*oid) + der(0xA0, new_sd))


def with_signeddata_version(token, vbytes):
    (_, ci), = items(token)
    oid, (_, sd0) = items(ci)
    (_, sd), = items(sd0)
    sde = items(sd)
    new_sd = der(0x30, der(0x02, vbytes) + b"".join(der(t, v) for t, v in sde[1:]))
    return der(0x30, der(*oid) + der(0xA0, new_sd))


def minimal(v):
    """X.690 §8.3.2: at least one octet; the first nine bits are not all 0 nor all 1"""
    return len(v) >= 1 and not (len(v) > 1 and ((v[0] == 0 and v[1] < 0x80) or (v[0] == 0xFF and v[1] >= 0x80)))


def sint(n):
    k = 1
    while True:
        try:
            return n.to_bytes(k, "big", signed=True)
        except OverflowError:
            k += 1


def manifest():
    with open(os.path.join(TP, "manifest.json")) as f:
        return json.load(f)


class RealTokens(unittest.TestCase):
    def test_files_are_the_ones_named(self):
        m = manifest()
        for v in m["vectors"]:
            if "sha256" in v:
                self.assertEqual(hashlib.sha256(_read(os.path.join(TP, v["file"]))).hexdigest(), v["sha256"], v["file"])
        for lic in ("LICENSE.birdbrain", "LICENSE.dss", "LICENSE.fileviewinfo"):
            self.assertTrue(os.path.getsize(os.path.join(TP, lic)) > 0, lic)

    def test_digicert_negative_nonce_is_read(self):
        t = T.parse_token(_read(os.path.join(TP, "digicert_negative_nonce.tsr")))
        self.assertEqual(t["nonce"], -0x5BDDFD8205AA38EC)
        self.assertEqual((t["gen_time"], t["hash_algorithm"]), ("2026-05-30T19:31:07Z", "sha256"))

    def test_eurocert_signeddata_version_1(self):
        with self.assertRaises(T.TokenError) as cm:
            T.parse_token(_read(os.path.join(TP, "eurocert_signeddata_v1.tst")))
        self.assertEqual((cm.exception.reason, cm.exception.detail), ("malformed", "SignedData version is not 3 (RFC 5652 §5.1)"))

    @NEEDS
    def test_manifest_outcomes(self):
        n = 0
        for v in manifest()["vectors"]:
            if "expect" not in v:
                continue
            tok = _read(os.path.join(TP, v["file"]))
            digest = bytes.fromhex(v.get("digest_sha256", "00" * 32))
            for how, want in v["expect"].items():
                if how.startswith("until"):
                    continue
                pins = None if how == "unpinned" else [os.path.normpath(os.path.join(TP, how.split()[1]))]
                r = T.verify_token(tok, digest, "sha256", pins)
                got = r["status"] if r["status"] != "invalid" else "invalid/" + r["reason"]
                self.assertTrue(want.startswith(got), (v["file"], how, got, r["detail"]))
                self.assertEqual(r["counts_as_timestamp"], got == "verified")
                n += 1
        self.assertEqual(n, 6)

    @NEEDS
    def test_digicert_negative_nonce_verified_and_still_bound(self):
        tok = _read(os.path.join(TP, "digicert_negative_nonce.tsr"))
        root = [os.path.join(TP, "digicert_trusted_root_g4.pem")]
        digest = bytes.fromhex(manifest()["vectors"][0]["digest_sha256"])
        r = T.verify_token(tok, digest, "sha256", root)
        self.assertEqual((r["status"], r["tst_info"]["nonce"]), ("verified", str(-0x5BDDFD8205AA38EC)), r)
        self.assertEqual(T.verify_token(tok, hashlib.sha256(b"x").digest(), "sha256", root)["reason"], "imprint_mismatch")
        # the signature still counts: the nonce changed inside the TSTInfo is a signature that does not verify
        inner = T.parse_token(tok)["token_der"]
        other = with_tstinfo(inner, lambda els: [(t, sint(-5) if t == 0x02 and i == 5 else v) for i, (t, v) in enumerate(els)])
        self.assertEqual(T.parse_token(other)["nonce"], -5)
        self.assertNotEqual(T.verify_token(other, digest, "sha256", root)["status"], "verified")


class IntegerGenerative(unittest.TestCase):
    """every nonce and serialNumber encoding of 0..9 bytes drawn at random, against the oracle"""

    def test_nonce_and_serial_number(self):
        inner = T.parse_token(_read(os.path.join(TP, "digicert_negative_nonce.tsr")))["token_der"]
        els = tstinfo_elements(inner)
        pos_nonce = [i for i, (t, _) in enumerate(els) if t == 0x02][-1]
        self.assertEqual(pos_nonce, 5)   # version, policy, imprint, serial, genTime, nonce (no accuracy here)
        rnd = random.Random(20261118)
        cases = [b"", b"\x00", b"\x7f", b"\x80", b"\xff", b"\x00\x80", b"\xff\x7f", b"\x00\x7f", b"\xff\x80", b"\x01\x00"]
        cases += [bytes(rnd.randrange(256) for _ in range(rnd.randrange(10))) for _ in range(600)]
        seen = {"nonce ok": 0, "nonce neg ok": 0, "serial neg refused": 0, "not minimal refused": 0}
        for v in cases:
            for field, at in (("nonce", pos_nonce), ("serialNumber", 3)):
                tok = with_tstinfo(inner, lambda e, at=at, v=v: [(t, v if i == at else x) for i, (t, x) in enumerate(e)])
                try:
                    got = T.parse_token(tok)
                    out = ("ok", got["nonce"] if field == "nonce" else got["serial_number"])
                except T.TokenError as ex:
                    out = (ex.reason, ex.detail)
                if not minimal(v):
                    want = ("malformed", f"{field}: INTEGER not in minimal form")
                    seen["not minimal refused"] += 1
                elif field == "serialNumber" and v[0] & 0x80:
                    want = ("malformed", "serialNumber: negative INTEGER")
                    seen["serial neg refused"] += 1
                else:
                    want = ("ok", int.from_bytes(v, "big", signed=True))
                    if field == "nonce":
                        seen["nonce ok"] += 1
                        seen["nonce neg ok"] += want[1] < 0
                self.assertEqual(out, want, (field, v.hex()))
        self.assertTrue(all(n > 20 for n in seen.values()), seen)

    def test_eurocert_like_versions(self):
        """SignedData.version on two real tokens: only 3 passes step 1 (RFC 5652 §5.1 with eContentType id-ct-TSTInfo)"""
        for name in ("freetsa.tsr", os.path.join("third_party", "digicert_negative_nonce.tsr")):
            inner = T.parse_token(_read(os.path.join(V3, name)))["token_der"]
            for n in (-1, 0, 1, 2, 3, 4, 5, 6, 256):
                tok = with_signeddata_version(inner, sint(n))
                if n == 3:
                    T.parse_token(tok)
                    continue
                with self.assertRaises(T.TokenError, msg=(name, n)) as cm:
                    T.parse_token(tok)
                self.assertEqual(cm.exception.reason, "malformed")


@NEEDS
class SignedNonces(unittest.TestCase):
    """tokens of an openssl TSA made here, the request's nonce copied into the TSTInfo, verified under its CA"""

    def test_signed_nonces_of_every_sign(self):
        import subprocess
        import test_tsa_signer_key_id_20261116 as K
        td = tempfile.mkdtemp()
        try:
            lab = K.Lab(td, "n")
            j = lab.j
            with open(j("tsa.cnf"), "w") as f:
                f.write(f"[ tsa ]\ndefault_tsa = t1\n[ t1 ]\nserial = {j('serial')}\ncrypto_device = builtin\n"
                        f"signer_cert = {j('tsa.crt')}\ncerts = {j('ca.crt')}\nsigner_key = {j('tsa.key')}\n"
                        "signer_digest = sha256\ndefault_policy = 1.2.3.4.1\ndigests = sha256\ness_cert_id_alg = sha256\n")
            alg = T._tlv(0x30, T._OID_SHA256 + T._NULL)
            imprint = T._tlv(0x30, alg + T._tlv(0x04, K.DIGEST))
            for n in (-0x5BDDFD8205AA38EC, -1, -128, -129, 0, 1, 127, 128, 2 ** 63, -(2 ** 63), -(2 ** 127) + 3):
                with open(j("q.tsq"), "wb") as f:
                    f.write(T._tlv(0x30, T._der_int(1) + imprint + T._tlv(0x02, sint(n)) + T._tlv(0x01, b"\xff")))
                subprocess.run(["openssl", "ts", "-reply", "-queryfile", j("q.tsq"), "-config", j("tsa.cnf"), "-section",
                                "t1", "-token_out", "-out", j("tok.der")], check=True, capture_output=True)
                tok = _read(j("tok.der"))
                r = T.verify_token(tok, K.DIGEST, "sha256", [j("ca.crt")])
                self.assertEqual((r["status"], r["tst_info"]["nonce"]), ("verified", str(n)), (n, r))
        finally:
            shutil.rmtree(td)


def chain_of(rows):
    """rows: dicts without hashes; prev_hash/self_hash filled by §3 (the rule of verifier.canonical_payload)"""
    out, prev = [], verifier.GENESIS_PREV
    for r in rows:
        e = dict(r, prev_hash=prev)
        e["self_hash"] = hashlib.sha256(verifier.canonical_payload(e)).hexdigest()
        out.append(e)
        prev = e["self_hash"]
    return out


class FailureClasses(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.td)

    def run_ledger(self, entries, name="l.jsonl"):
        p = os.path.join(self.td, name)
        with open(p, "w") as f:
            f.write("".join(json.dumps(e, ensure_ascii=False) + "\n" for e in entries))
        return p, verifier.verify_ledger(p)

    def test_foreign_schema_with_real_breaks(self):
        """the shape measured on 2026-11-18 (a third-party ledger, not shipped: no licence): own fields, no idx, §3 hashes,
        a fork that breaks the links of 2 entries"""
        rows = [{"claim_id": "c%d" % i, "verdict": "pass", "ts": "2026-08-06T03:44:%02d+00:00" % i} for i in range(30)]
        led = chain_of(rows)
        for k in (12, 20):   # prev_hash points to an older entry, the entry re-hashed: only the link is broken
            led[k]["prev_hash"] = led[k - 3]["self_hash"]
            led[k]["self_hash"] = hashlib.sha256(verifier.canonical_payload(led[k])).hexdigest()
            for m in range(k + 1, 30):
                led[m]["prev_hash"] = led[m - 1]["self_hash"] if m != 20 else led[m]["prev_hash"]
                led[m]["self_hash"] = hashlib.sha256(verifier.canonical_payload(led[m])).hexdigest()
        p, r = self.run_ledger(led)
        self.assertEqual(r["verdict"], "FAIL")
        self.assertEqual(r["failure_classes"], {
            "chain": {"link_mismatch": 2, "hash_mismatch": 0},
            "format": {"unknown_field": 30, "idx_mismatch": 30, "missing_self_hash": 0, "missing_prev_hash": 0},
            "other": 0})
        lay = verify_evidence.verify_ledger(p)["layers"][0]
        self.assertEqual(lay["failure_classes"], r["failure_classes"])
        self.assertIn("chain: 2 link_mismatch, 0 hash_mismatch; format", lay["detail"])
        self.assertEqual([x.split(":")[0] for x in lay["reasons"][:2]], ["link idx 12", "link idx 20"])

    def test_pass_receipt_has_no_classes(self):
        _, r = self.run_ledger(chain_of([{"idx": i, "ts": "2026-11-18T00:00:00Z", "data": {"i": i}} for i in range(3)]))
        self.assertEqual(r["verdict"], "PASS")
        self.assertNotIn("failure_classes", r)

    def test_generative_mutations(self):
        rnd = random.Random(1118)
        kinds = ("extra_key", "drop_idx", "drop_prev", "drop_self", "alter_prev", "alter_data")
        for trial in range(300):
            n = rnd.randrange(1, 9)
            led = chain_of([{"idx": i, "ts": "2026-11-18T00:00:%02dZ" % i, "data": {"v": i}} for i in range(n)])
            for _ in range(rnd.randrange(0, 4)):
                k, e = rnd.choice(kinds), led[rnd.randrange(n)]
                if k == "extra_key":
                    e["x%d" % rnd.randrange(3)] = 1
                elif k == "drop_idx":
                    e.pop("idx", None)
                elif k == "drop_prev":
                    e.pop("prev_hash", None)
                elif k == "drop_self":
                    e.pop("self_hash", None)
                elif k == "alter_prev" and "prev_hash" in e:
                    e["prev_hash"] = "f" * 64
                elif k == "alter_data":
                    e["data"] = {"v": -1}
            _, r = self.run_ledger(led, "g%d.jsonl" % trial)
            # the oracle, from §2 and §3, not from the verifier's lists
            prevs = [verifier.GENESIS_PREV] + [e.get("self_hash") for e in led[:-1]]
            want_chain = {
                "link_mismatch": sum(1 for e, p in zip(led, prevs) if "prev_hash" in e and e["prev_hash"] != p),
                "hash_mismatch": sum(1 for e in led if "self_hash" in e and e["self_hash"] != hashlib.sha256(
                    verifier.canonical_payload(e)).hexdigest())}
            want_format = {
                "unknown_field": sum(1 for e in led if set(e) - set(verifier.ENTRY_KEYS)),
                "idx_mismatch": sum(1 for i, e in enumerate(led) if e.get("idx") != i),
                "missing_self_hash": sum(1 for e in led if "self_hash" not in e),
                "missing_prev_hash": sum(1 for e in led if "prev_hash" not in e)}
            bad = any(want_chain.values()) or any(want_format.values())
            self.assertEqual(r["verdict"], "FAIL" if bad else "PASS", trial)
            if bad:
                self.assertEqual(r["failure_classes"], {"chain": want_chain, "format": want_format, "other": 0}, trial)
            else:
                self.assertNotIn("failure_classes", r)


if __name__ == "__main__":
    unittest.main(verbosity=2)
