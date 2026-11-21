#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""SPEC v0.8 §10-§11: the evidence pack's verify with pinned TSA certificates (`tsa_certs`, `--tsa-cert`).

Until v0.8 the pack's token was read for its status and imprint only and `time_anchor` was never `verified`
(`tsa_not_checked`): a token whose signature was broken, or that a TSA the caller does not trust had issued, left the
pack valid with the same receipt. With a pin the token is checked by §11 and mapped as ETSI EN 319 102-1 V1.4.1 §5.1.3
maps a signature validation: steps 1-6 refused -> contradicted; step 7 refused (another TSA) -> not_evaluated /
tsa_unresolved, NOT contradicted; verified -> verified. Proposed by Athena's review of 15/11/2026 (its prototype
p5_pack_time_anchor.py), the mapping decided before the code and written in the SPEC first.

The real tokens are those of spec/vectors/rfc3161 (freetsa.org, DigiCert, Sectigo, GlobalSign, requested on
2026-11-13); the packs use tokens of a TSA made on this machine (verifiers/pack_states_bench.LocalTsa). Each check has
its positive control: a mapping that ignores the pin, or that calls the token of another TSA a contradiction, must make
the checker report failures. On the code before v0.8 (no `tsa_certs`) every test of the pack fails."""
import base64
import itertools
import json
import os
import random
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.dont_write_bytecode = True
ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "verifiers"))
import cryptovalid_tsa as T  # noqa: E402
import evidence_pack as EP  # noqa: E402
from pack_states_bench import LocalTsa, _load, _store  # noqa: E402

V = os.path.join(ROOT, "spec", "vectors", "rfc3161")
SAMPLE = os.path.join(ROOT, "examples", "sample_ledger.jsonl")
NEEDS_OPENSSL = unittest.skipIf(shutil.which("openssl") is None, "needs openssl (the TSA's signature is checked with it)")
with open(os.path.join(V, "manifest.json"), encoding="utf-8") as _f:
    DIGEST = bytes.fromhex(json.load(_f)["digest_sha256"])
# token -> the pins of its own TSA among the files of spec/vectors/rfc3161
OWN = {"freetsa.tsr": {"freetsa.signer.pem", "freetsa_cacert.pem"}, "digicert.tsr": {"digicert.signer.pem"},
       "sectigo.tsr": {"sectigo.signer.pem"}, "globalsign.tsr": {"globalsign.signer.pem"}}
PINS = sorted(set().union(*OWN.values()))
STATES = {"verified", "contradicted", "not_evaluated"}
REASONS = {None, "binding_mismatch", "token_invalid", "tsa_unresolved", "instrument_failure"}


def _read(name):
    with open(os.path.join(V, name), "rb") as f:
        return f.read()


def _element(tok_name, pins, digest=DIGEST):
    el, _ = EP._pinned_time_anchor(base64.b64encode(_read(tok_name)).decode(), digest.hex(), [os.path.join(V, p) for p in pins])
    return el[:2]


def real_vector_failures(subsets=None):
    """Every (token, pin set) whose element is not the expected one: verified iff a pin of its own TSA is in the set,
    else not_evaluated / tsa_unresolved (never contradicted: a pin for another TSA does not make the token false)."""
    bad = []
    subsets = subsets or [c for k in range(1, len(PINS) + 1) for c in itertools.combinations(PINS, k)]
    for tok, own in OWN.items():
        for pins in subsets:
            want = ("verified", None) if own & set(pins) else ("not_evaluated", "tsa_unresolved")
            got = _element(tok, pins)
            if got != want:
                bad.append((tok, pins, got, want))
    return bad


@NEEDS_OPENSSL
class RealTokens(unittest.TestCase):
    def test_generative_every_pin_set_on_the_four_public_tsas(self):
        subsets = [c for k in range(1, len(PINS) + 1) for c in itertools.combinations(PINS, k)]
        self.assertEqual(len(subsets), 31)
        self.assertEqual(real_vector_failures(subsets), [])

    def test_tokens_that_fail_their_own_checks_are_contradicted(self):
        self.assertEqual(_element("freetsa_signature_altered.tsr", ["freetsa_cacert.pem"]), ("contradicted", "token_invalid"))
        self.assertEqual(_element("freetsa.tsr", ["freetsa_cacert.pem"], digest=bytes(32)), ("contradicted", "binding_mismatch"))
        self.assertEqual(_element("forged_cms_octet_string.der", ["digicert.signer.pem"]), ("contradicted", "token_invalid"))
        self.assertEqual(_element("forged_cms_not_tstinfo.der", ["digicert.signer.pem"]), ("contradicted", "token_invalid"))
        self.assertEqual(_element("freetsa_sha512.tsr", ["freetsa_cacert.pem"]), ("contradicted", "token_invalid"))

    def test_a_self_issued_token_under_a_public_pin_is_unresolved(self):
        self.assertEqual(_element("self_tsa.tsr", ["digicert.signer.pem"]), ("not_evaluated", "tsa_unresolved"))

    def test_positive_control_wrong_mappings_are_caught(self):
        few = [("freetsa_cacert.pem",), ("digicert.signer.pem",), ("freetsa.signer.pem", "sectigo.signer.pem")]
        real = T.verify_token

        def ignore_pin(der, digest, hash_alg=None, tsa_certs=None):   # the certificate inside the token decides
            v = real(der, digest, hash_alg, None)
            return {**v, "status": "verified", "counts_as_timestamp": True} if v["status"] == "signature_only" else v

        def step7_is_false(der, digest, hash_alg=None, tsa_certs=None):   # the reading of SPEC v0.7: "invalid" = false
            v = real(der, digest, hash_alg, tsa_certs)
            return {**v, "reason": "signature_invalid"} if v["reason"] == "not_issued_by_pinned_tsa" else v
        for sabotage in (ignore_pin, step7_is_false):
            with mock.patch.object(T, "verify_token", sabotage):
                self.assertGreater(len(real_vector_failures(few)), 0, sabotage.__name__)

    def test_generative_byte_flips_of_a_real_token(self):
        """One byte of the DigiCert token changed, pinned to its own certificate: a closed element, never a raise; never
        `verified` when the TSTInfo read from the token changed or the flip is in the signature (the last 16 bytes)."""
        tok = _read("digicert.tsr")
        orig = T.parse_token(tok)
        rnd = random.Random(2026111561)
        positions = sorted(rnd.sample(range(len(tok)), 160)) + list(range(len(tok) - 16, len(tok)))
        pins = [os.path.join(V, "digicert.signer.pem")]
        verified_after_flip = 0
        for i in positions:
            b = bytearray(tok)
            b[i] ^= 1 << rnd.randrange(8)
            el, check = EP._pinned_time_anchor(base64.b64encode(bytes(b)).decode(), DIGEST.hex(), pins)
            self.assertIn(el[0], STATES, i)
            self.assertIn(el[1], REASONS, i)
            if el[0] == "verified":
                verified_after_flip += 1
                t = T.parse_token(bytes(b))
                self.assertEqual({k: t[k] for k in ("hashed_message", "gen_time", "serial_number", "policy")},
                                 {k: orig[k] for k in ("hashed_message", "gen_time", "serial_number", "policy")}, i)
                self.assertLess(i, len(tok) - 16, i)
        print(f"  {len(positions)} flips of digicert.tsr, {verified_after_flip} still verified (outside the signed content)")


@NEEDS_OPENSSL
class PackWithPinnedTsa(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.td = tempfile.mkdtemp()
        os.makedirs(os.path.join(cls.td, "tsa")); os.makedirs(os.path.join(cls.td, "tsa2"))
        cls.tsa, cls.other = LocalTsa(os.path.join(cls.td, "tsa")), LocalTsa(os.path.join(cls.td, "tsa2"))

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.td, ignore_errors=True)

    def pack(self, name, block=None, digest=None, tsa=None):
        p = os.path.join(self.td, name)
        if os.path.exists(p):
            shutil.rmtree(p)
        EP.build_pack([SAMPLE], p, subject="pin")
        m = _load(p)
        if block is None:
            block = {"anchored": True, "tsa": "local", "tsr_b64": (tsa or self.tsa).token(digest or m["manifest_digest_sha256"])}
        if block != "none":
            m["rfc3161_timestamp"] = block
            _store(p, m)
        return p

    def ta(self, r):
        return r["states"]["time_anchor"]["state"], (r["states"]["time_anchor"]["reasons"] or [None])[0]

    def test_pinned_tsa_verifies(self):
        p = self.pack("ok")
        for pin in ("ca.crt", "tsa.crt"):
            r = EP.verify_pack(p, tsa_certs=[self.tsa.j(pin)])
            self.assertEqual((self.ta(r), r["valid"], r["states_vocabulary"]),
                             (("verified", None), True, "cryptovalid-evidence-pack/states-2"))
            self.assertEqual(r["rfc3161"]["tsa_check"]["status"], "verified")
            self.assertRegex(r["rfc3161"]["tsa_check"]["gen_time"], r"^20\d\d-\d\d-\d\dT")
            self.assertEqual(len(r["rfc3161"]["tsa_check"]["signer_sha256"]), 64)

    def test_without_a_pin_nothing_changes(self):
        p = self.pack("nopin")
        r = EP.verify_pack(p)
        self.assertEqual((self.ta(r), r["valid"], r["states_vocabulary"]),
                         (("not_evaluated", "tsa_not_checked"), True, "cryptovalid-evidence-pack/states-1"))
        self.assertNotIn("tsa_check", r["rfc3161"])
        self.assertEqual(r, EP.verify_pack(p, tsa_certs=None))

    def test_another_tsa_pinned_is_unresolved_and_the_pack_is_not_valid(self):
        # SPEC §22 rule 7 (Unreleased): the TSA pin decides valid (until 0.27.0, SPEC v0.8: the pack stayed valid)
        r = EP.verify_pack(self.pack("other"), tsa_certs=[self.other.j("ca.crt")])
        self.assertEqual((self.ta(r), r["valid"]), (("not_evaluated", "tsa_unresolved"), False))
        self.assertEqual((r["rfc3161"]["tsa_check"]["status"], r["rfc3161"]["tsa_check"]["reason"]),
                         ("invalid", "not_issued_by_pinned_tsa"))

    def test_a_broken_signature_is_contradicted_with_a_pin_only(self):
        p = self.pack("broken")
        m = _load(p)
        der = bytearray(base64.b64decode(m["rfc3161_timestamp"]["tsr_b64"])); der[-1] ^= 1
        m["rfc3161_timestamp"]["tsr_b64"] = base64.b64encode(bytes(der)).decode(); _store(p, m)
        r0 = EP.verify_pack(p)
        self.assertEqual((self.ta(r0), r0["valid"]), (("not_evaluated", "tsa_not_checked"), True))   # as before v0.8
        r = EP.verify_pack(p, tsa_certs=[self.tsa.j("ca.crt")])
        self.assertEqual((self.ta(r), r["valid"]), (("contradicted", "token_invalid"), False))
        self.assertIn("signature_invalid", r["states"]["time_anchor"]["detail"])
        r2 = EP.verify_pack(p, tsa_certs=[self.other.j("ca.crt")])   # a broken token is false under any pin
        self.assertEqual((self.ta(r2), r2["valid"]), (("contradicted", "token_invalid"), False))

    def test_the_outcomes_the_pin_does_not_touch(self):
        pin = [self.tsa.j("ca.crt")]
        cases = {"none": (self.pack("none", block="none"), ("not_evaluated", "not_present")),
                 "missing": (self.pack("missing", block={"anchored": True, "tsa": "local"}), ("contradicted", "token_missing")),
                 "digest": (self.pack("digest", digest="00" * 32), ("contradicted", "binding_mismatch")),
                 "garbage": (self.pack("garbage", block={"anchored": True, "tsa": "x", "tsr_b64": "AAAA"}),
                             ("contradicted", "token_invalid"))}
        for name, (p, want) in cases.items():
            r0, r = EP.verify_pack(p), EP.verify_pack(p, tsa_certs=pin)
            self.assertEqual(self.ta(r), want, name)
            self.assertEqual(r0["states"], r["states"], name)
            # SPEC §22 rule 7: no token under a TSA pin is not valid (until 0.27.0 as without the pin); the rest as before
            self.assertEqual(r["valid"], False if name == "none" else r0["valid"], name)
            self.assertNotIn("tsa_check", r["rfc3161"], name)

    def test_openssl_absent_with_a_pin_is_instrument_failure(self):
        p = self.pack("noossl")
        with mock.patch("shutil.which", return_value=None):
            r = EP.verify_pack(p, tsa_certs=[self.tsa.j("ca.crt")])
        self.assertEqual(self.ta(r), ("not_evaluated", "instrument_failure"))

    def test_openssl_absent_at_the_pinned_check_is_instrument_failure(self):
        p = self.pack("noossl2")   # the imprint was read (openssl present), the signature check finds no openssl
        with mock.patch.object(T, "token_signer", return_value=("not_evaluated", None, "openssl absent")):
            r = EP.verify_pack(p, tsa_certs=[self.tsa.j("ca.crt")])
        self.assertEqual((self.ta(r), r["valid"]), (("not_evaluated", "instrument_failure"), False))   # §22 rule 7
        self.assertEqual(r["rfc3161"]["tsa_check"]["status"], "not_evaluated")

    def test_the_pin_is_given_or_refused(self):
        for p in (self.pack("args"), self.pack("args_none", block="none")):   # refused before the pack is read
            for bad in ([], (), "x.pem", b"pem", ("",), [os.path.join(self.td, "absent.pem")]):
                with self.assertRaises(ValueError, msg=repr(bad)):
                    EP.verify_pack(p, tsa_certs=bad)

    def test_cli_tsa_cert(self):
        p = self.pack("cli")
        env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
        run = lambda *a: subprocess.run([sys.executable, os.path.join(ROOT, "evidence_pack.py"), "verify", p, *a],  # noqa: E731
                                        capture_output=True, text=True, env=env, timeout=120)
        r = run("--tsa-cert", self.tsa.j("ca.crt"))
        self.assertEqual(r.returncode, 0, r.stderr)
        out = json.loads(r.stdout)
        self.assertEqual((out["states"]["time_anchor"]["state"], out["states_vocabulary"]),
                         ("verified", "cryptovalid-evidence-pack/states-2"))
        r = run("--tsa-cert", self.other.j("ca.crt"), "--tsa-cert", self.tsa.j("ca.crt"))   # several pins: any of them
        self.assertEqual(json.loads(r.stdout)["states"]["time_anchor"]["state"], "verified")
        r = run("--tsa-cert", os.path.join(self.td, "absent.pem"))
        self.assertEqual(r.returncode, 2, r.stdout)
        self.assertEqual(r.stdout, "")


if __name__ == "__main__":
    unittest.main(verbosity=1)
