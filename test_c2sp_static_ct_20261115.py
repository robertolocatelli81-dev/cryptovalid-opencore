#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Checkpoint signatures of static CT logs, note signature type 0x05 (SPEC §13, 2026-11-15).

Until 2026-11-15 cryptovalid_checkpoint ignored a 0x05 vkey as an unknown key: the checkpoint of a static CT log (Sunlight,
TesseraCT) signed only by its log key was NON_VALIDA, "no signature from a known key". This suite checks the rule of SPEC
§13 on the real checkpoint of sunlight's test log rome2026h1 (testdata/interop/README.md: source, commit, SHA-256), on
every altered form of it, on every body length, on unknown keys and on notes signed with keys made here; where Go is
installed the same notes go to github.com/transparency-dev/formats (verifiers/note_oracle). CV_REQUIRE_GO_ORACLE=1 makes
a missing Go an error.
"""
import base64
import hashlib
import json
import os
import random
import shutil
import struct
import subprocess
import tempfile
import unittest

import cryptovalid_checkpoint as C

HERE = os.path.dirname(os.path.abspath(__file__))
D = os.path.join(HERE, "testdata", "interop")
ORACLE_SRC = os.path.join(HERE, "verifiers", "note_oracle")
try:
    from cryptography.hazmat.primitives import hashes, serialization as ser
    from cryptography.hazmat.primitives.asymmetric import ec, rsa
    HAVE_CRYPTO = True
except ImportError:
    HAVE_CRYPTO = False
if os.environ.get("CV_REQUIRE_CRYPTO") == "1" and not HAVE_CRYPTO:
    raise SystemExit("CV_REQUIRE_CRYPTO=1 but `cryptography` is missing")
if os.environ.get("CV_REQUIRE_GO_ORACLE") == "1" and not HAVE_CRYPTO:
    raise SystemExit("CV_REQUIRE_GO_ORACLE=1 needs `cryptography` (the oracle tests would be skipped)")

SHA = {"sunlight_rome2026h1.checkpoint": "0ee6cc89f8017c29990bc1899bd31f0a4f943c8e08c3286ed606cf3ee1200381",
       "sunlight_rome2026h1.log.v3.json": "7b8c812923930e27e83027f604892a2df3de9e99d01a3fca6cc95374b91fd382"}
NAME = "rome2026h1.example.org"


def _read(n):
    with open(os.path.join(D, n), "rb") as f:
        return f.read()


NOTE = _read("sunlight_rome2026h1.checkpoint")
LOG = json.loads(_read("sunlight_rome2026h1.log.v3.json"))
DER = base64.b64decode(LOG["key"])
VK = ("rome2026h1.example.org+91507526+BTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABDyHHq+0Qd9o7eG0xG4YFCiyrznLRQ/iNoaAyLRcVAZSYhhb37Q"
      "bkZN3zu3tU+4AtnpMny+16DtqDfzm3GcnOBA=")   # written out: the same string transparency-dev/formats RFC6962VerifierString gives
TEXT, SIGS = C.split_note(NOTE)
KID, BODY = SIGS[0][1][:4], SIGS[0][1][4:]


def note_with(body, text=TEXT, name=NAME, kid=KID):
    return (text + "\n" + "— %s %s\n" % (name, base64.b64encode(kid + body).decode())).encode()


def ths(ts, size, root):
    return b"\x00\x01" + struct.pack(">QQ", ts, size) + root


def sign_ct(key, text, ts, name):
    """A 0x05 note made here: the body static-ct-api defines, over the TreeHeadSignature of RFC 6962 §3.5."""
    cp = C.parse_checkpoint(text)
    sig = key.sign(ths(ts, cp["size"], cp["root"]), ec.ECDSA(hashes.SHA256()))
    der = key.public_key().public_bytes(ser.Encoding.DER, ser.PublicFormat.SubjectPublicKeyInfo)
    body = struct.pack(">Q", ts) + b"\x04\x03" + struct.pack(">H", len(sig)) + sig
    return note_with(body, text, name, C.rfc6962_key_id(name, der)), C.vkey_rfc6962(name, der)


class Vector(unittest.TestCase):
    def test_bytes_are_the_pinned_ones(self):
        for n, h in SHA.items():
            self.assertEqual(hashlib.sha256(_read(n)).hexdigest(), h, n)

    def test_vkey_matches_the_note_and_the_log_list(self):
        self.assertEqual(C.vkey_rfc6962(NAME, DER), VK)
        self.assertEqual(VK.split("+")[1], "91507526")
        self.assertEqual(KID.hex(), "91507526")
        self.assertEqual(base64.b64encode(hashlib.sha256(DER).digest()).decode(), LOG["log_id"])
        self.assertEqual(VK.split("+")[0], LOG["description"])
        cp = C.parse_checkpoint(TEXT)
        fth = LOG["final_tree_head"]
        self.assertEqual((cp["origin"], cp["size"], base64.b64encode(cp["root"]).decode()),
                         (NAME, fth["tree_size"], fth["sha256_root_hash"]))
        self.assertEqual(C.parse_vkey(VK)[2], C.TYPE_RFC6962)

    @unittest.skipUnless(HAVE_CRYPTO, "cryptography")
    def test_real_checkpoint_verifies(self):
        r = C.verify_note(NOTE, [VK])
        self.assertEqual(r["stato"], "OK", r)
        self.assertEqual(r["verified"], [{"name": NAME, "type": 5, "timestamp_ms": LOG["final_tree_head"]["timestamp"]}])
        self.assertEqual(r["ignored_vkeys"], 0)

    @unittest.skipUnless(HAVE_CRYPTO, "cryptography")
    def test_altered_checkpoint_fails_with_the_reason(self):
        cp = C.parse_checkpoint(TEXT)
        root2 = bytes([cp["root"][0] ^ 1]) + cp["root"][1:]
        cases = {
            "other root": (note_with(BODY, C.checkpoint_text(NAME, 300, root2)), "does not verify"),
            "other size": (note_with(BODY, C.checkpoint_text(NAME, 301, cp["root"])), "does not verify"),
            "other timestamp": (note_with(struct.pack(">Q", 1767139200001) + BODY[8:]), "does not verify"),
            "extension line": (note_with(BODY, TEXT + "ext\n"), "extension lines"),
            "hash algorithm": (note_with(BODY[:8] + b"\x05" + BODY[9:]), "hash algorithm 5"),
            "signature algorithm": (note_with(BODY[:9] + b"\x01" + BODY[10:]), "signature algorithm 1"),
            "byte appended": (note_with(BODY + b"\x00"), "length field says"),
        }
        for what, (n, reason) in cases.items():
            r = C.verify_note(n, [VK])
            self.assertEqual(r["stato"], "NON_VALIDA", what)
            self.assertIn("signature from known key %s does not verify: " % NAME, r["motivo"], what)
            self.assertIn(reason, r["motivo"], what)

    @unittest.skipUnless(HAVE_CRYPTO, "cryptography")
    def test_origin_must_equal_the_key_name(self):
        k = ec.generate_private_key(ec.SECP256R1())
        n, vk = sign_ct(k, C.checkpoint_text("log.example/a", 5, b"\x07" * 32), 9, "log.example/a")
        self.assertEqual(C.verify_note(n, [vk])["stato"], "OK")
        der = k.public_key().public_bytes(ser.Encoding.DER, ser.PublicFormat.SubjectPublicKeyInfo)
        # the same signature under another name: the signature does not cover the origin (static-ct-api says so),
        # the name/origin rule is what refuses it
        text_b = C.checkpoint_text("log.example/b", 5, b"\x07" * 32)
        cp_sig = C.split_note(n)[1][0][1][4:]
        nb = note_with(cp_sig, text_b, "log.example/a", C.rfc6962_key_id("log.example/a", der))
        r = C.verify_note(nb, [vk])
        self.assertEqual(r["stato"], "NON_VALIDA")
        self.assertIn("differs from the checkpoint origin", r["motivo"])

    @unittest.skipUnless(HAVE_CRYPTO, "cryptography")
    def test_text_must_be_a_canonical_checkpoint(self):
        """SPEC §13 step 3: the text as parse_checkpoint reads it; the signature covers numbers, the rule covers bytes."""
        cp = C.parse_checkpoint(TEXT)
        root64 = base64.b64encode(cp["root"]).decode()
        noncanon = root64[:-2] + chr(ord(root64[-2]) + 1) + "="   # same 32 bytes in Python's lax decoder, other text
        for text in (NAME + "\n0300\n" + root64 + "\n", NAME + "\n+300\n" + root64 + "\n", NAME + "\n300\n" + noncanon + "\n",
                     NAME + "\n300\n", "hello\n", NAME + "\n300\n" + root64 + "\n\n"):
            r = C.verify_note(note_with(BODY, text), [VK])
            self.assertEqual(r["stato"], "NON_VALIDA", text)
            if text.endswith("\n\n"):          # an empty line ends the text one line early: no signature of a known key
                continue
            self.assertIn("note text is not a checkpoint", r["motivo"], text)

    def test_vkey_rfc6962_arguments(self):
        for name in ("", "a b", "a+b", "a\x01"):
            with self.assertRaises(C.NoteError):
                C.vkey_rfc6962(name, DER)
        for der in (b"", "MFkw", None, bytearray()):
            with self.assertRaises(C.NoteError):
                C.vkey_rfc6962(NAME, der)
        self.assertEqual(C.vkey_rfc6962(NAME, bytearray(DER)), VK)

    def test_wrong_key_id_is_an_unknown_key(self):
        r = C.verify_note(note_with(BODY, kid=b"\x91\x50\x75\x27"), [VK]) if HAVE_CRYPTO else None
        if r is not None:
            self.assertEqual((r["stato"], r["ignored"], r["motivo"]), ("NON_VALIDA", 1, "no signature from a known key"))

    @unittest.skipIf(HAVE_CRYPTO, "only without cryptography")
    def test_without_cryptography_not_verified(self):
        r = C.verify_note(NOTE, [VK])
        self.assertEqual(r["stato"], "NON_VERIFICATA")


@unittest.skipUnless(HAVE_CRYPTO, "cryptography")
class Lengths(unittest.TestCase):
    """Every body length from 0 to the real one plus 64: a reason, never an exception (SPEC §13 step 2)."""

    def test_every_prefix_and_every_random_body(self):
        rnd = random.Random(20261115)
        for n in range(0, len(BODY) + 65):
            for body in (BODY[:n] if n <= len(BODY) else BODY + bytes(n - len(BODY)),
                         bytes(rnd.randrange(256) for _ in range(n))):
                r = C.verify_note(note_with(body), [VK])
                self.assertEqual(r["stato"], "OK" if body == BODY else "NON_VALIDA", n)
                if body == BODY:
                    continue
                self.assertTrue(r["motivo"], n)
                if n == 0:
                    self.assertEqual(r["motivo"], "signature shorter than key id + 1 byte")
                elif n < 12:
                    self.assertIn("shorter than the 12 bytes", r["motivo"])
                else:
                    self.assertIn("signature from known key", r["motivo"])
                    self.assertNotIn("shorter than the 12 bytes", r["motivo"])

    def test_length_field_every_value_around_the_real_one(self):
        real = len(BODY) - 12
        for L in list(range(0, real + 40)) + [0xFFFF]:
            body = BODY[:10] + struct.pack(">H", L) + BODY[12:]
            r = C.verify_note(note_with(body), [VK])
            if L == real:
                self.assertEqual(r["stato"], "OK")
            else:
                self.assertIn("length field says %d bytes, %d follow" % (L, real), r["motivo"])


@unittest.skipUnless(HAVE_CRYPTO, "cryptography")
class Vkeys(unittest.TestCase):
    """A 0x05 vkey is read whole or refused with the reason (SPEC §13 step 1)."""

    def _vk(self, name, mat, kid=None):
        kid = kid if kid is not None else C.rfc6962_key_id(name, mat[1:])
        return "%s+%s+%s" % (name, kid.hex(), base64.b64encode(mat).decode())

    def test_refused(self):
        p384 = ec.generate_private_key(ec.SECP384R1()).public_key().public_bytes(ser.Encoding.DER, ser.PublicFormat.SubjectPublicKeyInfo)
        rsa2k = rsa.generate_private_key(public_exponent=65537, key_size=2048).public_key().public_bytes(
            ser.Encoding.DER, ser.PublicFormat.SubjectPublicKeyInfo)
        xy = DER[-64:]   # P-256 SPKI: the uncompressed point 04 || X || Y ends the DER
        compressed = (b"\x30\x39" + DER[2:23] + b"\x03\x22\x00" + bytes([2 + (xy[-1] & 1)]) + xy[:32])
        cases = {
            "wrong id": (self._vk(NAME, b"\x05" + DER, b"\x91\x50\x75\x27"), "key id does not match"),
            "trailing byte": (self._vk(NAME, b"\x05" + DER + b"\x00"), "not a DER"),
            "compressed point": (self._vk(NAME, b"\x05" + compressed), "canonical form"),
            "not DER": (self._vk(NAME, b"\x05" + b"\x30\x03abc"), "not a DER"),
            "only the type": (self._vk(NAME, b"\x05" + b"\x00"), "not a DER"),
            "P-384": (self._vk(NAME, b"\x05" + p384), "only ECDSA P-256"),
            "RSA": (self._vk(NAME, b"\x05" + rsa2k), "only ECDSA P-256"),
            "DER cut": (self._vk(NAME, b"\x05" + DER[:-1]), "not a DER"),
        }
        for what, (vk, reason) in cases.items():
            with self.assertRaises(C.NoteError, msg=what) as cm:
                C.verify_note(NOTE, [vk])
            self.assertIn(reason, str(cm.exception), what)
        for bad in (VK.replace("+91507526+", "+9150752+"), VK + "=", VK.replace(NAME, NAME + " x"), VK.replace(NAME, "a+b")):
            with self.assertRaises(C.NoteError, msg=bad):
                C.verify_note(NOTE, [bad])

    def test_unassigned_types_stay_ignored(self):
        for t in [0, 3] + list(range(7, 256)):
            vk = "%s+%s+%s" % (NAME, "00000000", base64.b64encode(bytes([t]) + DER).decode())
            r = C.verify_note(NOTE, [vk])
            self.assertEqual((r["stato"], r["ignored_vkeys"]), ("NON_VALIDA", 1), t)
            r = C.verify_note(NOTE, [vk, VK])
            self.assertEqual((r["stato"], r["ignored_vkeys"]), ("OK", 1), t)

    def test_cli(self):
        import io, contextlib
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            rc = C.main(["vkey-rfc6962", "--name", NAME, "--key-b64", LOG["key"]])
        self.assertEqual((rc, out.getvalue().strip()), (0, VK))
        for missing in (["vkey-rfc6962", "--name", NAME], ["vkey-rfc6962", "--key-b64", LOG["key"]]):
            with self.assertRaises(SystemExit) as cm, contextlib.redirect_stderr(io.StringIO()):
                C.main(missing)
            self.assertEqual(cm.exception.code, 2)
        for bad in (LOG["key"] + "=", LOG["key"][:-4]):
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                rc = C.main(["vkey-rfc6962", "--name", NAME, "--key-b64", bad])
            self.assertEqual(rc, 2, bad)
            self.assertEqual(json.loads(out.getvalue())["stato"], "ERRORE")


@unittest.skipUnless(HAVE_CRYPTO, "cryptography")
class Generated(unittest.TestCase):
    """Notes signed here with P-256 keys: sizes, roots, names and timestamps across their ranges, mixed with other types."""

    def test_many(self):
        rnd = random.Random(15112026)
        keys = [ec.generate_private_key(ec.SECP256R1()) for _ in range(4)]
        for i in range(300):
            k = keys[i % 4]
            name = "log%d.example.org/%s" % (i, "x" * rnd.randrange(0, 40))
            size = rnd.choice([0, 1, 255, 256, 2 ** 63, 2 ** 64 - 1, rnd.randrange(2 ** 64)])
            ts = rnd.choice([0, 1, 2 ** 63, 2 ** 64 - 1, rnd.randrange(2 ** 64)])
            root = bytes(rnd.randrange(256) for _ in range(32))
            n, vk = sign_ct(k, C.checkpoint_text(name, size, root), ts, name)
            r = C.verify_note(n, [vk])
            self.assertEqual(r["verified"], [{"name": name, "type": 5, "timestamp_ms": ts}], i)
            other = keys[(i + 1) % 4]
            vk2 = C.vkey_rfc6962(name, other.public_key().public_bytes(ser.Encoding.DER, ser.PublicFormat.SubjectPublicKeyInfo))
            r2 = C.verify_note(n, [vk2])   # same name, another key: another id, an unknown key
            self.assertEqual((r2["stato"], r2["ignored"]), ("NON_VALIDA", 1), i)

    def test_with_an_ed25519_cosignature(self):
        seed = bytes(range(32))
        cos = C.cosign_v1(NOTE, "witness.example", seed, 1767139300)
        wvk = C.vkey("witness.example", C.TYPE_COSIG_V1, C.pubkey_from_seed(seed))
        r = C.verify_note(cos, [VK, wvk])
        self.assertEqual(r["stato"], "OK")
        self.assertEqual([v["type"] for v in r["verified"]], [5, 4])
        self.assertEqual(C.verify_note(cos, [wvk])["stato"], "OK")       # the 0x05 line of an untrusted log: ignored

    def test_signature_encodings(self, oracle=None):
        """High S verifies (RFC 6962 sets no low-S rule); a BER signature (long-form length, a leading zero) does not."""
        k = ec.generate_private_key(ec.SECP256R1())
        text = C.checkpoint_text("e.example", 3, b"\x01" * 32)
        n, vk = sign_ct(k, text, 5, "e.example")
        body = C.split_note(n)[1][0][1][4:]
        from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature
        r_, s_ = decode_dss_signature(body[12:])
        order = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
        kid = C.split_note(n)[1][0][1][:4]

        def with_sig(sig):
            return note_with(body[:10] + struct.pack(">H", len(sig)) + sig, text, "e.example", kid)

        def check(n, want):
            self.assertEqual(C.verify_note(n, [vk])["stato"], want)
            if oracle is not None:
                self.assertEqual(oracle(n, vk), 0 if want == "OK" else 1)
        check(with_sig(encode_dss_signature(r_, order - s_)), "OK")
        der = body[12:]
        check(with_sig(b"\x30\x81" + der[1:]), "NON_VALIDA")                    # long-form length
        ri_len = der[3]
        padded_r = b"\x02" + bytes([ri_len + 1]) + b"\x00" + der[4:4 + ri_len]
        rest = der[4 + ri_len:]
        check(with_sig(b"\x30" + bytes([len(padded_r) + len(rest)]) + padded_r + rest), "NON_VALIDA")   # leading zero


@unittest.skipUnless(HAVE_CRYPTO, "cryptography")
class GoOracle(unittest.TestCase):
    """github.com/transparency-dev/formats opens the same notes (verifiers/note_oracle). Skipped without Go unless
    CV_REQUIRE_GO_ORACLE=1. The rule of SPEC §13 decides; the oracle is asked on bodies of at least 12 bytes over
    canonical checkpoint texts, where its answer is defined by the same structure."""

    @classmethod
    def setUpClass(cls):
        if shutil.which("go") is None:
            if os.environ.get("CV_REQUIRE_GO_ORACLE") == "1":
                raise AssertionError("CV_REQUIRE_GO_ORACLE=1 but no Go toolchain on PATH")
            raise unittest.SkipTest("no Go toolchain")
        cls.tmp = tempfile.mkdtemp(); cls.bin = os.path.join(cls.tmp, "cvnote-oracle")
        r = subprocess.run(["go", "build", "-o", cls.bin, "."], cwd=ORACLE_SRC, capture_output=True, text=True, timeout=600)
        if r.returncode != 0:
            raise AssertionError("note_oracle build failed: " + r.stderr[-800:])

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(getattr(cls, "tmp", ""), ignore_errors=True)

    def _oracle(self, note, *vkeys):
        p = os.path.join(self.tmp, "n")
        with open(p, "wb") as f:
            f.write(note)
        r = subprocess.run([self.bin, p, *vkeys], capture_output=True, text=True, timeout=60)
        self.assertIn(r.returncode, (0, 1), r.stdout + r.stderr)
        return r.returncode

    def test_real_and_altered(self):
        self.assertEqual(self._oracle(NOTE, VK), 0)
        agree = 0
        for i in range(len(BODY)):
            for bit in range(8):
                b = bytearray(BODY); b[i] ^= 1 << bit
                n = note_with(bytes(b))
                ours = C.verify_note(n, [VK])["stato"] == "OK"
                self.assertEqual(ours, self._oracle(n, VK) == 0, (i, bit))
                agree += 1
        self.assertEqual(agree, len(BODY) * 8)

    def test_generated_and_cosigned(self):
        rnd = random.Random(7)
        for i in range(40):
            k = ec.generate_private_key(ec.SECP256R1())
            name = "o%d.example/log" % i
            text = C.checkpoint_text(name, rnd.randrange(2 ** 64), bytes(rnd.randrange(256) for _ in range(32)))
            n, vk = sign_ct(k, text, rnd.randrange(2 ** 64), name)
            self.assertEqual(self._oracle(n, vk), 0, i)
            self.assertEqual(C.verify_note(n, [vk])["stato"], "OK", i)
        seed = bytes(range(32))
        cos = C.cosign_v1(NOTE, "witness.example", seed, 1767139300)
        wvk = C.vkey("witness.example", C.TYPE_COSIG_V1, C.pubkey_from_seed(seed))
        self.assertEqual(self._oracle(cos, VK, wvk), 0)

    def test_signature_encodings(self):
        Generated.test_signature_encodings(self, oracle=self._oracle)

    def test_length_field_and_algorithms(self):
        real = len(BODY) - 12
        for L in range(0, real + 8):
            n = note_with(BODY[:10] + struct.pack(">H", L) + BODY[12:])
            self.assertEqual(self._oracle(n, VK) == 0, L == real, L)
        for h in range(256):
            n = note_with(BODY[:8] + bytes([h]) + BODY[9:])
            self.assertEqual(self._oracle(n, VK) == 0, h == 4, h)
            self.assertEqual(C.verify_note(n, [VK])["stato"] == "OK", h == 4, h)
        for s in range(256):
            n = note_with(BODY[:9] + bytes([s]) + BODY[10:])
            self.assertEqual(self._oracle(n, VK) == 0, s == 3, s)
            self.assertEqual(C.verify_note(n, [VK])["stato"] == "OK", s == 3, s)


if __name__ == "__main__":
    unittest.main(verbosity=1)
