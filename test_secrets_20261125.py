#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Roberto Locatelli
"""SPEC §32 (0.29.1), a secret that comes in never goes out: a private key given as a ledger of a pack, an output path
that is a key file, a key that cannot be used, credentials in a URL, the secret given where the NAME of its environment
variable goes, a witness that cosigns with the log's own key. The last class is the bench: every command with a key,
the key in the place of every input, the key as every output; stdout, stderr and every file written are searched for
every form of the seed, and the search is shown to find one."""
import base64
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import cryptovalid_net as net   # noqa: E402
import evidence_pack   # noqa: E402
import verifier   # noqa: E402
from test_platforms_20261124 import make_private   # noqa: E402

try:
    from cryptography.hazmat.primitives import serialization as ser
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    HAVE_CRYPTO = True
except ImportError:
    HAVE_CRYPTO = False
NEEDS_CRYPTO = unittest.skipUnless(HAVE_CRYPTO, "needs the cryptography package")

SEED = hashlib.sha256(b"test seed, not a key in use").digest()
LEDGER = os.path.join(HERE, "examples", "sample_ledger.jsonl")
# a PKCS#8 PrivateKeyInfo (RFC 8410 §10.3 layout: version 0, Ed25519, 32-byte key), built here: no library needed
PKCS8 = bytes.fromhex("302e020100300506032b657004220420") + SEED


def forms(secret):
    """every form of a 32-byte secret a program may write it in"""
    h, b = secret.hex().encode(), base64.b64encode(secret)
    return {"raw": secret, "reversed": secret[::-1], "hex": h, "HEX": h.upper(), "hex of reversed": secret[::-1].hex().encode(),
            "base64": b.rstrip(b"="), "base64url": base64.urlsafe_b64encode(secret).rstrip(b"="), "decimal": str(int.from_bytes(secret, "big")).encode(),
            "decimal, little-endian": str(int.from_bytes(secret, "little")).encode(), "base64 of hex": base64.b64encode(h).rstrip(b"="), "hex of hex": h.hex().encode()}


def _tree_bytes(root):
    out = b""
    for d, _, fs in os.walk(root):
        for n in fs:
            with open(os.path.join(d, n), "rb") as f:
                out += f.read()
    return out


def _pem(label, data=PKCS8):
    return b"-----BEGIN " + label + b"-----\n" + base64.encodebytes(data) + b"-----END " + label + b"-----\n"


JWK = json.dumps({"kty": "OKP", "crv": "Ed25519", "x": "AA", "d": base64.urlsafe_b64encode(SEED).decode()}).encode()
# the layouts by hand: PKCS#1 (RFC 8017 A.1.2), SEC 1 (RFC 5915), PKCS#12 (RFC 7292: version 3, ContentInfo)
PKCS1 = bytes.fromhex("3082010202010002818100") + SEED * 5
SEC1 = bytes.fromhex("30770201010420") + SEED + bytes(80)
PKCS12 = bytes.fromhex("308203e802010330820300") + bytes.fromhex("06092a864886f70d010701") + SEED * 4
KEY_FORMS = {"hex": SEED.hex().encode(), "HEX": b"  " + SEED.hex().upper().encode() + b"\r\n", "pem": _pem(b"PRIVATE KEY"),
             "pem_ec": _pem(b"EC PRIVATE KEY"), "pem_enc": _pem(b"ENCRYPTED PRIVATE KEY"), "openssh": _pem(b"OPENSSH PRIVATE KEY"),
             "pgp": _pem(b"PGP PRIVATE KEY BLOCK"), "der": PKCS8, "der_b64": base64.b64encode(PKCS8) + b"\n",
             "der_b64_lines": base64.encodebytes(PKCS8 + bytes(100)), "der_long": bytes.fromhex("3082000e020101300506032b6570") + SEED,
             "pkcs1": PKCS1, "sec1": SEC1, "pkcs12": PKCS12, "jwk": JWK, "jwks": b'{"keys": [{"kty": "EC"}, ' + JWK + b"]}"}


class Shape(unittest.TestCase):
    def test_every_private_form_is_named(self):
        for name, data in KEY_FORMS.items():
            with self.subTest(name):
                self.assertIsNotNone(verifier.private_key_shape(data))

    def test_what_is_not_a_private_key_is_not_named(self):
        pub_jwk = {"kty": "OKP", "crv": "Ed25519", "x": "AA"}
        spki = bytes.fromhex("302a300506032b6570032100") + SEED   # a PUBLIC key (RFC 8410 SubjectPublicKeyInfo)
        tsq = bytes.fromhex("30390201013031300d060960864801650304020105000420") + SEED   # an RFC 3161 request: INTEGER 1, SEQUENCE {SEQUENCE
        with open(LEDGER, "rb") as f:
            ledger = f.read()
        in_data = b'{"idx":0,"data":"a PEM: -----BEGIN ' + b'PRIVATE KEY-----","prev_hash":"0","self_hash":"1"}\n'
        for data in (b"", b"\n", SEED.hex().encode()[:-1], SEED.hex().encode() + b"0", SEED.hex().encode() + b"\n" + SEED.hex().encode(),
                     b"zz" + SEED.hex().encode()[2:], b"{" + b'"a":[' * 30000, b'{"keys":5,"kty":1,"d":2}'[:9],
                     json.dumps(pub_jwk).encode(), json.dumps({"keys": [pub_jwk]}).encode(), json.dumps({"d": 1}).encode(),
                     spki, base64.b64encode(spki), tsq, base64.b64encode(tsq), ledger, in_data, b"{not json", b"\xff\xfe\x00",
                     _pem(b"PUBLIC KEY"), _pem(b"CERTIFICATE"), b"\x30" * 40, b"\x30\x80" + bytes(40), b"\x30\xff" + bytes(20),
                     b"\x30\x8c" + bytes(12) + b"\x02\x01\x00", b"\x30\x8c" + bytes(12) + b"\x02\x01\x00\x30",   # cut inside
                     bytes.fromhex("312e020100300506032b657004220420") + SEED,   # a SET, not a SEQUENCE
                     bytes.fromhex("302e040100300506032b657004220420") + SEED,   # the version is not an INTEGER
                     bytes.fromhex("302e020102300506032b657004220420") + SEED,   # version 2
                     bytes.fromhex("302e020100040506032b657004220420") + SEED,   # version 0, OCTET STRING
                     bytes.fromhex("302e020101020506032b657004220420") + SEED,   # version 1, INTEGER
                     bytes.fromhex("302e020101020506032b657004220420") + SEED * 5,   # version 1, INTEGER, long
                     bytes.fromhex("302e020100020506032b657004220420") + SEED,   # version 0, INTEGER, too short for RSA
                     bytes.fromhex("302e020100300502032b657004220420") + SEED):  # no OID in the AlgorithmIdentifier
            with self.subTest(data=data[:24]):
                self.assertIsNone(verifier.private_key_shape(data))

    def test_no_input_raises(self):
        import random
        rnd = random.Random(20261125)
        for _ in range(4000):
            base = bytearray(rnd.choice(list(KEY_FORMS.values()))[:200])
            for _ in range(rnd.randrange(4)):
                base[rnd.randrange(len(base))] = rnd.randrange(256)
            verifier.private_key_shape(bytes(base[:rnd.randrange(len(base) + 1)]))

    def test_file_reader_bounds_and_never_raises(self):
        d = tempfile.mkdtemp()
        try:
            p = os.path.join(d, "k")
            with open(p, "wb") as f:
                f.write(SEED.hex().encode())
            self.assertIn("hex seed", verifier.private_key_file(p))
            self.assertIsNone(verifier.private_key_file(os.path.join(d, "absent")))
            self.assertIsNone(verifier.private_key_file(d))
            self.assertIsNone(verifier.private_key_file("a\0b"))
            pem = b"-----BEGIN " + b"PRIVATE KEY-----\n"
            with open(p, "wb") as f:   # exactly the bound: read; one byte more: not judged
                f.write(pem + b"A" * (verifier.KEY_MAX_BYTES - len(pem)))
            self.assertIn("PEM", verifier.private_key_file(p))
            with open(p, "ab") as f:
                f.write(b"A")
            self.assertIsNone(verifier.private_key_file(p))
        finally:
            shutil.rmtree(d)


class _Tmp(unittest.TestCase):
    def setUp(self):
        self.d = os.path.realpath(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.d, ignore_errors=True)
        self.key = os.path.join(self.d, "signer.key")
        self.put(self.key, SEED.hex().encode())
        make_private(self.key)
        self.ledger = os.path.join(self.d, "ledger.jsonl")
        shutil.copy(LEDGER, self.ledger)
        self.out = os.path.join(self.d, "pack")

    def put(self, path, data):
        with open(path, "wb") as f:
            f.write(data)
        return path

    def get(self, path):
        with open(path, "rb") as f:
            return f.read()


class PackHoldsOnlyLedgers(_Tmp):
    """SPEC §32 rules 1 and 2"""

    def refused(self, paths, **kw):
        with self.assertRaises(evidence_pack.PackInputRefused) as c:
            evidence_pack.build_pack(paths, self.out, **kw)
        self.assertNotIn(SEED.hex(), str(c.exception))
        self.assertFalse(os.path.exists(self.out))
        return str(c.exception)

    def test_a_key_in_any_form_is_refused_and_nothing_is_written(self):
        for name, data in KEY_FORMS.items():
            with self.subTest(name):
                p = self.put(os.path.join(self.d, "k_" + name), data)
                for paths in ([self.ledger, p], [p, self.ledger], [p]):   # the ledger before it must not be copied either
                    self.assertIn("is not a ledger: it holds ", self.refused(paths))

    def test_any_other_file_is_refused_whatever_it_is(self):
        png = bytes.fromhex("89504e470d0a1a0a0000000d49484452") + bytes(64)
        other = {"a.env": b"API_KEY=S3GRETO\nTOKEN=x\n", "b.png": png, "c.csv": b"a,b\n1,2\n", "d.json": b'{\n "a": 1\n}\n',
                 "e.jsonl": b'{"a":1}\n{"a":2}\n', "f.txt": b"notes", "g.gz": bytes.fromhex("1f8b0800") + bytes(20),
                 "h.pub": b"ssh-ed25519 AAAA user", "i.bin": bytes(range(256)), "j.list": b'[{"prev_hash":"0","self_hash":"1"}]\n',
                 "k.str": b'"self_hash"\n', "l.open": b'{"self_hash": ', "m.nest": b'{"a":{"self_hash":"1","prev_hash":"0"}}\n',
                 "n.mix": self.get(LEDGER) + b"API_KEY=S3GRETO\n", "o.mix": b"API_KEY=S3GRETO\n" + self.get(LEDGER),
                 "p.mix": self.get(LEDGER) + b'{"password":"S3GRETO"}\n', "q.ndjson": self.get(LEDGER) + JWK + b"\n",
                 "r.utf16": self.get(LEDGER).decode("utf-8").encode("utf-16"), "s.esc": self.get(LEDGER) + b"\x0bAPI_KEY=S3GRETO\n",
                 "v.byte": self.get(LEDGER) + b'{"password":"S3GRETO\xff"}\n', "t.vt": b'\x0b{"self_hash":"1"}\n', "u.bom": self.get(LEDGER) + b'\xef\xbb\xbf{"self_hash":"1"}\n'}
        for name, data in other.items():
            with self.subTest(name):
                why = self.refused([self.ledger, self.put(os.path.join(self.d, name), data)])
                self.assertNotIn("S3GRETO", why)
                self.assertIn("is not a ledger", why)

    def test_every_ledger_of_the_repository_goes_into_a_pack_whatever_its_verdict(self):
        """measured before the rule was written: no ledger here is refused by it, broken or not"""
        import glob
        ledgers = [p for pat in ("spec/vectors/*.jsonl", "spec/vectors/signatures/*.jsonl", "spec/vectors/beacon/**/*.jsonl", "examples/*.jsonl",
                                 "testdata/interop/*.jsonl", "verifiers/*/**/ectors/**/*.jsonl") for p in glob.glob(os.path.join(HERE, pat), recursive=True)]
        self.assertGreater(len(ledgers), 60)
        for p in ledgers:
            self.assertIsNone(evidence_pack._ledger_form(p)[0], p)

    def test_damaged_ledgers_stay_evidence(self):
        raw = self.get(LEDGER)
        lines = raw.splitlines(keepends=True)
        for name, data in {"empty": b"", "blank": b"\r\n \t\n", "bom": b"\xef\xbb\xbf" + raw, "crlf": raw.replace(b"\n", b"\r\n"),
                           "cut": raw[:-30], "cut_first": lines[0][:40] + b"\n" + b"".join(lines[1:]), "byte": raw.replace(b"idx", b"i\xffx", 1),
                           "no_self_hash": b'{"idx":0,"prev_hash":"0"}\n', "no_prev": b'{"idx":0,"self_hash":"0"}\n', "nan": lines[0].replace(b'"idx":0', b'"idx":NaN') + lines[1],
                           "reordered": b"".join(reversed(lines)), "deep": lines[0] + b'{"a":' + b"[" * 600 + b"]" * 600 + b"}\n"}.items():
            with self.subTest(name):
                p = self.put(os.path.join(self.d, name + ".jsonl"), data)
                out = os.path.join(self.d, "pk_" + name)
                evidence_pack.build_pack([p], out)
                self.assertEqual(self.get(os.path.join(out, name + ".jsonl")), data)

    def test_what_verifies_as_a_ledger_is_never_refused(self):
        """every line of a ledger that passes has both members (SPEC §2): PASS implies the form; one million random
        lines are not needed, the two readings are compared on mutations of a real one"""
        import random
        rnd = random.Random(1)
        raw = self.get(LEDGER)
        p = os.path.join(self.d, "m.jsonl")
        for _ in range(150):
            b = bytearray(raw)
            for _ in range(rnd.randrange(1, 3)):
                k = rnd.randrange(len(b))
                b[k:k + rnd.randrange(2)] = bytes([rnd.choice(b' \n{}"0aZ\xff')])
            self.put(p, bytes(b))
            if verifier.verify_ledger(p)["verdict"] == "PASS":
                self.assertIsNone(evidence_pack._ledger_form(p)[0], bytes(b))

    def test_a_file_swapped_after_it_was_judged_is_not_packed(self):
        from unittest import mock
        real = evidence_pack.copy_output

        def swap(src, dst):
            self.put(src, b"API_KEY=S3GRETO\n")
            return real(src, dst)
        with mock.patch.object(evidence_pack, "copy_output", swap):
            with self.assertRaises(evidence_pack.PackInputRefused) as c:
                evidence_pack.build_pack([self.ledger], self.out)
        self.assertIn("changed while it was read", str(c.exception))
        self.assertEqual(os.listdir(self.out), [])

    def test_a_ledger_that_grows_while_it_is_packed_is_packed(self):
        from unittest import mock
        real = evidence_pack.copy_output

        def grow(src, dst):
            with open(src, "ab") as f:
                f.write(b'{"idx":9,"prev_hash":"0","self_hash":"1"}\n')
            return real(src, dst)
        with mock.patch.object(evidence_pack, "copy_output", grow):
            evidence_pack.build_pack([self.ledger], self.out)
        self.assertIn(b'"idx":9', self.get(os.path.join(self.out, "ledger.jsonl")))

    def test_a_line_past_the_bound_is_not_parsed_and_is_hashed_whole(self):
        from unittest import mock
        with mock.patch.object(verifier, "MAX_INPUT_BYTES", 64):
            p = self.put(os.path.join(self.d, "l.jsonl"), b'{"self_hash":"0"}\n{"x":"' + b"a" * 3000000 + b'"}\n{"self_hash":"1"}\n')
            why, digest = evidence_pack._ledger_form(p)
            self.assertIsNone(evidence_pack._ledger_form(self.put(os.path.join(self.d, "m"), b'{"self_hash":"0"}\n{"x":1}' + b" " * 200))[0])
        self.assertIsNone(why)
        self.assertEqual(digest, hashlib.sha256(self.get(p)).hexdigest())
        with mock.patch.object(verifier, "MAX_JSON_TOKENS", 3):   # SPEC §22 rule 9: not parsed
            self.assertEqual(evidence_pack._ledger_form(self.put(p, b'{"self_hash":"0"}\n{"a":[1,2,3]}\n'))[0], None)

    def test_the_sign_key_under_another_name(self):
        self.put(self.key, b'{"self_hash":"0"}\n')   # a file whose content is not recognised: the same file still is
        other = os.path.join(self.d, "other.jsonl")
        os.link(self.key, other)
        self.assertIn("--sign-key file", self.refused([self.ledger, other], sign_key=self.key))

    @NEEDS_CRYPTO
    def test_a_key_that_cannot_sign_leaves_nothing(self):
        self.put(self.key, SEED.hex().encode() + b"zz")
        with self.assertRaises(verifier.KeyNotUsable) as c:
            evidence_pack.build_pack([self.ledger], self.out, sign_key=self.key)
        self.assertNotIn(SEED.hex(), str(c.exception))
        self.assertFalse(os.path.exists(self.out))

    @NEEDS_CRYPTO
    def test_a_pack_built_with_sign_key_holds_no_form_of_the_seed(self):
        evidence_pack.build_pack([self.ledger], self.out, sign_key=self.key)
        blob = _tree_bytes(self.out)
        for name, form in forms(SEED).items():
            self.assertNotIn(form, blob, name)
        pub = Ed25519PrivateKey.from_private_bytes(SEED).public_key().public_bytes(ser.Encoding.Raw, ser.PublicFormat.Raw).hex()
        self.assertIn(pub.encode(), blob)   # the scan sees the tree: the PUBLIC key is there

    def test_command_line_refusal_is_one_line_exit_2(self):
        r = subprocess.run([sys.executable, os.path.join(HERE, "evidence_pack.py"), "build", self.out, self.ledger, self.key],
                           capture_output=True, text=True, encoding="utf-8")
        self.assertEqual((r.returncode, r.stdout, r.stderr.count("\n")), (2, "", 1), r.stderr)
        self.assertFalse(os.path.exists(self.out))


class OutputNeverReplacesAKey(_Tmp):
    """SPEC §32 rule 3"""

    def intact(self, path, data):
        self.assertEqual(self.get(path), data)
        self.assertEqual([n for n in os.listdir(self.d) if n.endswith(".tmp")], [])   # no temporary left

    def test_a_key_in_any_form_is_not_replaced(self):
        for name, data in KEY_FORMS.items():
            with self.subTest(name):
                p = self.put(os.path.join(self.d, name + (".key" if name.lower() == "hex" else ".bin")), data)
                os.chmod(p, 0o644)   # the form alone, except for the 64 digits
                for write in (lambda: verifier.write_output(p, "{}"), lambda: verifier.copy_output(LEDGER, p)):
                    with self.assertRaises(verifier.OutputNotWritten) as c:
                        write()
                    self.assertNotIn(SEED.hex(), str(c.exception))
                    self.intact(p, data)

    def test_64_hex_digits_are_a_seed_only_when_kept_as_one(self):
        """a digest has the form of a seed: private to its owner, or named as a key, it is a seed; else it is replaced"""
        digest = hashlib.sha256(b"x").hexdigest().encode() + b"\n"
        for name, private, replaced in (("head.sha256", False, True), ("digest.txt", False, True), ("digest", True, False),
                                        ("a.key", False, False), ("A.KEY", False, False), ("b.seed", False, False)):
            with self.subTest(name=name, private=private):
                p = self.put(os.path.join(self.d, name), digest)
                if private:
                    make_private(p)
                elif os.name != "nt":
                    os.chmod(p, 0o640 if name == "head.sha256" else 0o604)
                if replaced:
                    verifier.write_output(p, "new")
                    self.assertEqual(self.get(p), b"new")
                else:
                    with self.assertRaises(verifier.OutputNotWritten):
                        verifier.write_output(p, "new")
                    self.intact(p, digest)
                os.remove(p)

    def test_the_key_this_process_read_is_not_replaced_under_any_name(self):
        raw = b"00" * 32 + b"\n"
        p = self.put(os.path.join(self.d, "open.txt"), raw)   # not private, not named as a key: only the reading tells
        if os.name != "nt":
            os.chmod(p, 0o644)
        self.assertNotIn(hashlib.sha256(raw).digest(), verifier._KEYS_READ)
        self.assertEqual(verifier.read_seed(p), bytes(32))
        self.addCleanup(verifier._KEYS_READ.discard, hashlib.sha256(raw).digest())
        names = [p]
        hard = os.path.join(self.d, "hard.txt")
        os.link(p, hard)
        names.append(hard)
        soft = os.path.join(self.d, "soft.txt")
        try:
            os.symlink(p, soft)
            names.append(soft)
        except (OSError, NotImplementedError):   # Windows without the right to make links
            pass
        if os.path.exists(os.path.join(self.d, "OPEN.TXT")):   # a file system that ignores the letter case
            names.append(os.path.join(self.d, "OPEN.TXT"))
        for n in names:
            with self.subTest(n):
                with self.assertRaises(verifier.OutputNotWritten) as c:
                    verifier.write_output(n, "x")
                self.assertIn("key file this command read", str(c.exception))
                self.intact(p, raw)
        self.put(p, b"not the key any more")
        verifier.write_output(p, "x")   # the same path, another content: not the key
        self.assertEqual(self.get(p), b"x")

    def test_before_a_key_is_read(self):
        p = self.put(os.path.join(self.d, "open.txt"), b"11" * 32)
        hard = os.path.join(self.d, "hard.txt")
        os.link(p, hard)
        with self.assertRaises(verifier.OutputNotWritten):
            verifier.refuse_directory(hard, None, p)
        verifier.refuse_directory(os.path.join(self.d, "new"), p)
        verifier.refuse_directory(self.ledger, p, os.path.join(self.d, "absent"))

    @NEEDS_CRYPTO
    def test_before_the_ledger_and_the_state_change(self):
        import cryptovalid_checkpoint as C
        import cryptovalid_scitt as S
        import cryptovalid_witness as W
        p = self.put(os.path.join(self.d, "open.txt"), hashlib.sha256(b"open").hexdigest().encode())   # recognised by nothing but the option
        if os.name != "nt":
            os.chmod(p, 0o644)
        cose, led = os.path.join(self.d, "s.cose"), os.path.join(self.d, "led")
        self.put(cose, S.signed_statement(b"{}", "a/b", "i", "s", self.key))
        pub = C.pubkey_from_seed(SEED).hex()
        note = self.put(os.path.join(self.d, "note"), C.sign_note(C.ledger_checkpoint(LEDGER, "o")[0], "o", SEED))
        vk = C.vkey("o", C.TYPE_ED25519, C.pubkey_from_seed(SEED))
        pq = self.put(os.path.join(self.d, "pq.txt"), hashlib.sha256(b"pq").hexdigest().encode())
        for out in (p, pq):
            for main, args, made in ((S.main, ["register", cose, "--ledger", led, "--issuer-pubkey", pub, "--ts-key", out, "--ts-iss", "t", "--out", out], led),
                                     (W.main, ["cosign", note, "--state", led, "--log-vkey", vk, "--name", "w", "--key", p, "--pq-key", pq, "--out", out], led)):
                with self.subTest(args[0]):
                    verifier._KEYS_READ.clear()
                    self.assertEqual(main(args), 74)
                    self.assertFalse(os.path.exists(made))
        self.intact(p, hashlib.sha256(b"open").hexdigest().encode())

    def test_every_other_existing_file_is_still_replaced(self):
        p = os.path.join(self.d, "receipt.json")
        for old in (b"", b"{}", SEED.hex().encode() + b"0", b'{"kty":"OKP","x":"AA"}', self.get(LEDGER), _pem(b"CERTIFICATE"), b"\x00" * 100,
                    b"x" * (verifier.KEY_MAX_BYTES + 1)):
            self.put(p, old)
            make_private(p)
            verifier.write_output(p, "new")
            self.assertEqual(self.get(p), b"new")

    @unittest.skipUnless(os.name == "nt", "the access list of keygen: measured by the other-os job")
    def test_windows_owner_only_is_read_back(self):
        self.assertTrue(verifier._owner_alone(self.key))
        self.assertFalse(verifier._owner_alone(self.ledger))


class KeysThatCannotBeUsed(_Tmp):
    """SPEC §32 rules 4 and 5"""

    def test_a_malformed_key_is_named_without_its_content(self):
        for data in (b"", b"zz" * 32, SEED.hex().encode() + b"zz", SEED.hex().encode()[:-2], SEED.hex().encode() * 2, b"\xff" + SEED, PKCS8, _pem(b"PRIVATE KEY")):
            with self.subTest(data[:16]):
                self.put(self.key, data)
                with self.assertRaises(verifier.KeyNotUsable) as c:
                    verifier.read_seed(self.key)
                self.assertIsNone(c.exception.__cause__)
                self.assertTrue(c.exception.__suppress_context__ or c.exception.__context__ is None)
                for form in forms(SEED).values():
                    self.assertNotIn(form.decode("latin-1"), str(c.exception))

    def test_the_key_itself_in_the_place_of_its_path(self):
        for arg in ('{"kty":"OKP","d":"AAECAw"}', SEED.hex(), base64.b64encode(PKCS8).decode(), base64.urlsafe_b64encode(SEED).decode(), JWK.decode(), _pem(b"PRIVATE KEY").decode(), "a\0" + SEED.hex()):
            with self.subTest(arg[:12]):
                with self.assertRaises(verifier.KeyNotUsable) as c:
                    verifier.read_key_text(arg)
                self.assertIn("never the key itself", str(c.exception))
                self.assertNotIn(arg, str(c.exception))
        with self.assertRaises(FileNotFoundError):   # an absent file keeps its error and its name
            verifier.read_key_text(os.path.join(self.d, "absent.key"))

    @NEEDS_CRYPTO
    def test_a_malformed_pq_key_and_a_checkpoint_key(self):
        import cryptovalid_checkpoint as C
        import signer
        for data in (b"", b"AAAA", SEED.hex().encode(), base64.b64encode(SEED + PKCS8), base64.b64encode(PKCS8[:-3]), b"not base64 !", PKCS1, base64.b64encode(PKCS12)):
            with self.subTest(data[:16]):
                self.put(self.key, data)
                with self.assertRaises(verifier.KeyNotUsable) as c:
                    signer.load_pq_key(self.key)
                self.assertNotIn(SEED.hex(), str(c.exception))
        with self.assertRaises(C.NoteError):
            C.load_seed_hex(self.key)

    def test_a_usage_error_repeats_no_long_value(self):
        self.assertEqual(verifier.redact("got '" + SEED.hex() + "'"), "got '<long value, not repeated>'")
        self.assertEqual(verifier.redact("a" * 43 + "/" + "b" * 42), "<long value, not repeated>/" + "b" * 42)
        for short in ("--pubkey needs a value (got '-x')", "a" * 42, "/home/user/some/very/long/path/that/is/not/a/secret/ledger.jsonl"):
            self.assertEqual(verifier.redact(short), short)
        r = subprocess.run([sys.executable, os.path.join(HERE, "verifier.py"), LEDGER, "--expect-ledger-id", SEED.hex().upper()],
                           capture_output=True, text=True, encoding="utf-8")
        self.assertEqual(r.returncode, 2)
        self.assertNotIn(SEED.hex().upper(), r.stderr)
        self.assertIn("not repeated", r.stderr)


@NEEDS_CRYPTO
class OneKeyOneRole(_Tmp):
    """SPEC §32 rule 7"""

    def test_a_witness_does_not_cosign_with_the_key_of_the_log(self):
        import cryptovalid_checkpoint as C
        import cryptovalid_witness as W
        text, _ = C.ledger_checkpoint(LEDGER, "log.example/a")
        other = hashlib.sha256(b"witness").digest()
        log = C.vkey("log.example/a", C.TYPE_ED25519, C.pubkey_from_seed(SEED))
        note = C.sign_note(text, "log.example/a", SEED)
        st = os.path.join(self.d, "st.json")
        for name in ("log.example/a", "another.name"):
            with self.assertRaises(C.NoteError) as c:
                W.witness_cosign(st, note, log, name, SEED)
            self.assertIn("a log does not witness itself", str(c.exception))
            with self.assertRaises(C.NoteError):
                W.WitnessService(st, name, SEED, [log])
            with self.assertRaises(C.NoteError):
                W.WitnessService(st, name, SEED, [], {"log.example/a": [log]})
        self.assertFalse(os.path.exists(st))
        self.assertEqual(W.witness_cosign(st, note, log, "w.example", other)["stato"], "COSIGNED")   # control
        W.WitnessService(st, "w.example", other, [log])
        if C._mldsa() is not None:
            mlog = C.vkey("log.example/a", C.TYPE_MLDSA44, C.mldsa44_pubkey_from_seed(SEED))
            with self.assertRaises(C.NoteError) as c:
                W.WitnessService(st, "another.name", other, [mlog], pq_seed=SEED)
            self.assertIn("a log does not witness itself", str(c.exception))


@NEEDS_CRYPTO
class AStatementIsNotItsKey(_Tmp):
    """SPEC §32 rule 6"""

    def test_scitt_statement_and_jws_certificate(self):
        import cryptovalid_jws as J
        import cryptovalid_scitt as S
        for payload in (SEED.hex().encode(), SEED, b"key=" + SEED.hex().upper().encode() + b"\n", _pem(b"X") + SEED):
            with self.assertRaises(S.ScittError) as c:
                S.signed_statement(payload, "a/b", "iss", "sub", self.key)
            self.assertNotIn(SEED.hex(), str(c.exception))
        S.signed_statement(SEED.hex().encode(), "a/b", "iss", "sub", self.key, detached=True)   # only its digest is signed over
        S.signed_statement(hashlib.sha256(SEED).hexdigest().encode(), "a/b", "iss", "sub", self.key)   # a digest is a statement
        with open(LEDGER, encoding="utf-8") as f:
            e = json.loads(f.readline())
        for c in (base64.b64encode(PKCS8).decode(), SEED.hex()):
            with self.assertRaises(ValueError):
                J.sign_entry(e, self.key, [c])


class UrlCredentials(unittest.TestCase):
    def test_check_url_refuses_userinfo_and_does_not_repeat_it(self):
        for url in ("https://user:S3GRETO@tsa.example/tsr", "https://S3GRETO@tsa.example/", "http://u:S3GRETO@127.0.0.1:8200",
                    "https://@tsa.example/", "HTTPS://u:S3GRETO@[::1]:8200/"):
            for allow in (net.ALLOW_HTTPS, net.ALLOW_HTTPS_OR_LOOPBACK_HTTP, net.ALLOW_HTTP_OR_HTTPS):
                with self.subTest(url=url, allow=allow):
                    with self.assertRaises(ValueError) as c:
                        net.check_url(url, allow)
                    self.assertNotIn("S3GRETO", str(c.exception))
                    if not (url.startswith("http:") and allow == net.ALLOW_HTTPS):
                        self.assertIn("credentials in the URL", str(c.exception))

    def test_an_at_sign_after_the_host_is_not_userinfo(self):
        for url in ("https://tsa.example/a@b", "https://tsa.example/?q=a@b", "https://tsa.example/#a@b"):
            self.assertEqual(net.check_url(url, net.ALLOW_HTTPS).hostname, "tsa.example")

    def test_url_for_record(self):
        for url, want in (("https://tsa.example/tsr", "https://tsa.example/tsr"),
                          ("https://tsa.example:8443/tsr?apikey=S3GRETO#f", "https://tsa.example:8443/tsr"),
                          ("https://u:S3GRETO@tsa.example/tsr", "https://tsa.example/tsr"),
                          ("https://a@b:S3GRETO@tsa.example/", "https://tsa.example/"),
                          ("http://[::1]:8080/x?k=S3GRETO", "http://[::1]:8080/x"),
                          ("S3GRETO", "<url>"), ("", "<url>"), (None, "<url>"), (5, "<url>"), ("http://[S3GRETO/", "<url>")):
            with self.subTest(url=url):
                self.assertEqual(net.url_for_record(url), want)

    def test_ingestor_record_of_a_timestamp_holds_no_credential(self):
        import cryptovalid_ingest as ingest
        d = tempfile.mkdtemp()
        try:
            for url in ("http://utente:S3GRETO@127.0.0.1:1/tsr", "http://127.0.0.1:1/tsr?apikey=S3GRETO"):
                a = os.path.join(d, hashlib.sha256(url.encode()).hexdigest()[:8])
                g = ingest.Ingestor(a, batch_size=1, tsa_url=url)
                g.append({"a": 1})
                g.seal()
                g.close()
                self.assertTrue([n for n in os.listdir(a) if n.endswith(".sth.tsr.json")], "the record of the attempt is written")
                self.assertNotIn(b"S3GRETO", _tree_bytes(a))
                self.assertIn(b'"tsa_url": "http://127.0.0.1:1/tsr"', _tree_bytes(a))
        finally:
            shutil.rmtree(d)


class RecordedUrl(unittest.TestCase):
    """every place a TSA URL is written into a record: without credentials, query and fragment"""
    URL = "https://tsa.example/tsr?apikey=S3GRETO#S3GRETO"
    CLEAN = "https://tsa.example/tsr"

    @unittest.skipUnless(verifier.which("openssl"), "needs the openssl program")
    def test_pack_manifest(self):
        from unittest import mock

        class Reply:
            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False
        for imprint_ok in (True, False):
            with mock.patch.object(net, "open_url", return_value=Reply()), mock.patch.object(net, "read_body", return_value=b"reply"), \
                    mock.patch.object(evidence_pack, "_verify_rfc3161", return_value={"imprint_ok": imprint_ok}):
                r = evidence_pack._rfc3161_stamp("ab" * 32, self.URL)
            self.assertEqual(r["anchored"], imprint_ok)
            self.assertEqual(r["tsa"], self.CLEAN)
            self.assertNotIn("S3GRETO", json.dumps(r))

    def test_receipt_and_tsa_module(self):
        from unittest import mock
        import cryptovalid_receipt as receipt
        import cryptovalid_tsa as T
        chk = {"status": "signature_only", "imprint_ok": True, "tst_info": {"gen_time": "2026-11-25T00:00:00Z"}, "signer_sha256": "00",
               "reason": None, "counts_as_timestamp": True}
        with mock.patch.object(T, "request_timestamp", return_value=(True, b"token", b"raw")), \
                mock.patch.object(T, "verify_token", return_value=chk):
            r = receipt._stamp("ab" * 32, self.URL)
            self.assertEqual(r["tsa"], self.CLEAN)
            self.assertNotIn("S3GRETO", json.dumps(r))
            r = T.timestamp_sth("ab" * 32, self.URL)
            self.assertEqual(r["tsa_url"], self.CLEAN)
            self.assertNotIn("S3GRETO", json.dumps(r))
            said = []
            with mock.patch.object(T, "emit", side_effect=said.append):
                T.main(["ab" * 32, "--tsa", self.URL])
            self.assertEqual(json.loads(said[0])["tsa"], self.CLEAN)
            self.assertNotIn("S3GRETO", said[0])


class EnvNameIsNotRepeated(unittest.TestCase):
    """`token_env=<the token>`: the secret where the name of its variable goes"""

    def test_backends_do_not_repeat_the_name_given(self):
        import cryptovalid_kms as kms
        import cryptovalid_qeas as qeas
        secret = "S3GRETO-hvs.token-0123"
        cases = [(lambda: kms.backend_from_uri(f"vault:url=https://vault.example;key=k;token_env={secret}"), "token_env="),
                 (lambda: kms.backend_from_uri(f"nethsm:url=https://hsm.example;key=k;user=op;pass_env={secret}"), "pass_env="),
                 (lambda: qeas.HttpQeasBackend("https://qeas.example", token_env=secret), "token_env")]
        if verifier.which("pkcs11-tool"):
            cases.append((lambda: kms.backend_from_uri(f"pkcs11:module=/nonexistent.so;token=t;key=k;pin=env:{secret}"), "pin=env:"))
        for build, option in cases:
            with self.subTest(option=option):
                with self.assertRaises(RuntimeError) as c:
                    build()
                self.assertNotIn("S3GRETO", str(c.exception))
                self.assertIn(option, str(c.exception))
                self.assertIn("empty/unset", str(c.exception))

    def test_pkcs11_at_signing_time_and_in_the_child(self):
        """the variable emptied after the backend was built, and the child that reads it for each signature"""
        import subprocess
        import cryptovalid_kms as kms
        name = "S3GRETO_1234"
        r = subprocess.run([sys.executable, "-c", "import sys; sys.path.insert(0, sys.argv[1]); import cryptovalid_kms as k; k._p11_worker()", HERE],
                           input=json.dumps({"op": "sign", "pin_env": name, "module": "m", "token": "t", "key": "k", "msg": "00"}).encode() + b"\n",
                           capture_output=True, env={k: v for k, v in os.environ.items() if k != name})
        self.assertEqual(r.returncode, 0, r.stderr)
        answer = json.loads(r.stdout.decode("ascii"))
        self.assertIn("pin=env:", answer["err"])
        self.assertNotIn("S3GRETO", r.stdout.decode("ascii") + r.stderr.decode("utf-8", "replace"))
        if not verifier.which("pkcs11-tool"):
            self.skipTest("needs pkcs11-tool for the constructor")
        os.environ[name] = "1234"
        try:
            b = kms.Pkcs11Backend("/nonexistent.so", "t", "k", pin="env:" + name)
            del os.environ[name]
            with self.assertRaises(RuntimeError) as c:
                b.sign(b"x")
            self.assertNotIn("S3GRETO", str(c.exception))
            self.assertIn("pin=env:", str(c.exception))
        finally:
            os.environ.pop(name, None)

    def test_url_with_credentials_is_refused_by_every_backend_without_repeating_it(self):
        import cryptovalid_kms as kms
        env = {"VAULT_TOKEN": "t", "NETHSM_PASS": "p", "AWS_ACCESS_KEY_ID": "a", "AWS_SECRET_ACCESS_KEY": "s"}
        old = {k: os.environ.get(k) for k in env}
        os.environ.update(env)
        try:
            for uri in ("vault:url=https://u:S3GRETO@vault.example;key=k", "nethsm:url=https://op:S3GRETO@hsm.example;key=k;user=op",
                        "awskms-http:key_id=k;region=eu-central-1;endpoint=https://u:S3GRETO@kms.example",
                        "vault:url=http://u:S3GRETO@127.0.0.1:8200;key=k", "nethsm:url=http://op:S3GRETO@localhost:8443;key=k;user=op",
                        "awskms-http:key_id=k;region=eu-central-1;endpoint=http://u:S3GRETO@127.0.0.1:4566"):
                with self.subTest(uri=uri.split("@")[0][:24]):
                    with self.assertRaises((ValueError, RuntimeError)) as c:
                        kms.backend_from_uri(uri)
                    self.assertNotIn("S3GRETO", str(c.exception))
                    self.assertIn("credentials in the URL", str(c.exception))
                    self.assertNotIn("non-loopback", str(c.exception))   # the host IS loopback: not that refusal
            for uri, word in (("vault:url=http://vault.example;key=k", "non-loopback Vault"),   # that refusal keeps its words
                              ("nethsm:url=http://hsm.example;key=k;user=op", "non-loopback NetHSM")):
                with self.assertRaises(RuntimeError) as c:
                    kms.backend_from_uri(uri)
                self.assertIn(word, str(c.exception))
        finally:
            for k, v in old.items():
                os.environ.pop(k, None) if v is None else os.environ.__setitem__(k, v)


class Bench(_Tmp):
    """every command, run as a user runs it; what it prints and writes is searched for every form of the secret"""

    def setUp(self):
        super().setUp()
        self.tmp = os.path.join(self.d, "tmp")
        os.mkdir(self.tmp)
        self.put(os.path.join(self.d, "W.key"), hashlib.sha256(b"another seed").hexdigest().encode())
        self.put(os.path.join(self.d, "s.json"), b'{"a":1}')
        self.needles = forms(SEED)
        self.fails = []

    def run_one(self, args, cwd):
        env = {k: v for k, v in os.environ.items() if not k.startswith(("CV_", "PYTHON"))}
        env.update(PYTHONPATH=HERE, PYTHONDONTWRITEBYTECODE="1", TMPDIR=self.tmp, TEMP=self.tmp, TMP=self.tmp, PYTHONIOENCODING="utf-8")
        r = subprocess.run([sys.executable, "-m"] + args, cwd=cwd, env=env, capture_output=True, stdin=subprocess.DEVNULL, timeout=120)
        return r

    def hits(self, r, cwd, skip=("signer.key", "bad.key")):
        blobs = {"<stdout>": r.stdout, "<stderr>": r.stderr}
        for root in (cwd, self.tmp):
            for dd, _, fs in os.walk(root):
                for n in fs:
                    if n not in skip:
                        blobs[os.path.relpath(os.path.join(dd, n), self.d)] = self.get(os.path.join(dd, n))
        return sorted((w, k) for w, b in blobs.items() for k, f in self.needles.items() if f in b)

    def case(self, i, args, key=None, text=None):
        """run in a folder of its own with a fresh signer.key; (returncode, leaks, key intact, traceback)"""
        cwd = os.path.join(self.d, "c%03d" % i)
        os.mkdir(cwd)
        for n in ("ledger.jsonl", "W.key", "s.json"):
            shutil.copy(os.path.join(self.d, n), cwd)
        k = self.put(os.path.join(cwd, "signer.key"), SEED.hex().encode() if key is None else key)
        before = self.get(k)
        r = self.run_one(args, cwd)
        return r.returncode, self.hits(r, cwd), os.path.exists(k) and self.get(k) == before, b"Traceback" in r.stderr, (r.stdout + r.stderr)[-200:]

    def all_cases(self, cases):
        from concurrent.futures import ThreadPoolExecutor
        with ThreadPoolExecutor(4) as ex:
            return list(zip(cases, ex.map(lambda c: self.case(*c), [(i, a) for i, a in enumerate(cases)])))

    def test_the_search_finds_a_leak_control(self):
        for code in ("print(open('signer.key').read())", "import sys; sys.stderr.write(open('signer.key').read().upper())",
                     "open('x.bin','wb').write(bytes.fromhex(open('signer.key').read()))",
                     "import base64; open('x','wb').write(base64.urlsafe_b64encode(bytes.fromhex(open('signer.key').read())))"):
            cwd = os.path.join(self.d, hashlib.sha256(code.encode()).hexdigest()[:8])
            os.mkdir(cwd)
            self.put(os.path.join(cwd, "signer.key"), SEED.hex().encode())
            r = subprocess.run([sys.executable, "-c", code], cwd=cwd, capture_output=True)
            self.assertTrue(self.hits(r, cwd), code)

    SIGNING = [["signer", "sign", "ledger.jsonl", "o.jsonl", "@"], ["cryptovalid_tip", "sign", "ledger.jsonl", "@"],
               ["cryptovalid_checkpoint", "sign", "ledger.jsonl", "--origin", "o", "--key", "@", "--out", "cp"],
               ["cryptovalid_checkpoint", "vkey", "--key", "@", "--name", "o"], ["cryptovalid_receipt", "sth", "ledger.jsonl", "@"],
               ["cryptovalid_receipt", "inclusion", "ledger.jsonl", "1", "@", "--cose", "i.cose"], ["cryptovalid_jws", "sign", "ledger.jsonl", "1", "@"],
               ["cryptovalid_scitt", "sign", "s.json", "--cty", "a/b", "--iss", "i", "--sub", "s", "--key", "@", "--out", "s.cose"],
               ["cryptovalid_acta", "sign", "--key", "@", "--tool", "t", "--decision", "allow", "--out", "a.json"],
               ["evidence_pack", "build", "pack", "ledger.jsonl", "--sign-key", "@"], ["cryptovalid_monitor", "ledger.jsonl", "state.json", "--keyfile", "@"],
               ["cryptovalid_kms", "pubkey", "--backend", "file:@"]]

    @NEEDS_CRYPTO
    def test_every_signing_command_signs_and_repeats_nothing(self):
        for args, (rc, hits, intact, tb, tail) in self.all_cases([[x.replace("@", "signer.key") for x in a] for a in self.SIGNING]):
            with self.subTest(args):
                self.assertEqual((rc, hits, intact, tb), (0, [], True, False), tail)

    @NEEDS_CRYPTO
    def test_a_malformed_key_is_a_clean_refusal_everywhere(self):
        for n, bad in enumerate((SEED.hex().encode() + b"zz", _pem(b"PRIVATE KEY"), PKCS8, b"")):
            self.put(os.path.join(self.d, "bad.key"), bad)
            for m, a in enumerate(self.SIGNING):
                args = [x.replace("@", "signer.key") for x in a]
                with self.subTest(args=args, n=n):
                    rc, hits, _, tb, tail = self.case(100 * (n + 1) + m, args, key=bad)
                    self.assertIn(rc, (1, 2), tail)
                    self.assertEqual((hits, tb), ([], False), tail)
                    self.assertFalse(os.path.exists(os.path.join(self.d, "c%03d" % (100 * (n + 1) + m), "pack")))

    def test_the_key_itself_in_the_place_of_the_path_or_of_a_public_value(self):
        h = SEED.hex()
        cases = [[x.replace("@", h) for x in a] for a in self.SIGNING] + [
            ["cryptovalid_witness", "cosign", "s.json", "--state", "st", "--log-vkey", "x", "--name", "w", "--key", "signer.key", "--pq-key", h, "--out", "o"],
            ["signer", "verify", "ledger.jsonl", "--pubkey", h], ["verifier", "ledger.jsonl", "--trusted-pubkey", h, "--out", "r.json"],
            ["verify_evidence", "ledger", "ledger.jsonl", "--nonesuch", h], ["evidence_pack", "verify", "x", "--signer-pubkey", h],
            ["cryptovalid_acta", "verify", "s.json", "--key", h], ["cryptovalid_acta", "verify", "s.json", "--key", "=" + h],
            ["cryptovalid_jws", "verify", "s.json", h], ["cryptovalid_receipt", "verify", "s.json", h]]
        for args, (rc, hits, _, _, tail) in self.all_cases(cases):
            with self.subTest([x if x != h else "<hex>" for x in args]):
                self.assertNotEqual(rc, 0, tail)
                self.assertEqual(hits, [], tail)

    def test_the_key_in_the_place_of_every_input(self):
        cases = [["verifier", "@", "--out", "r.json"], ["verifier", "ledger.jsonl", "--tip", "@"], ["cryptovalid_tip", "check", "ledger.jsonl", "--tip", "@"],
                 ["signer", "sign", "@", "o", "W.key"], ["signer", "verify", "@"], ["cryptovalid_tip", "sign", "@", "W.key", "--out", "t"],
                 ["cryptovalid_checkpoint", "sign", "@", "--origin", "o", "--key", "W.key", "--out", "c"], ["cryptovalid_checkpoint", "verify", "@", "--vkey", "x"],
                 ["cryptovalid_merkle", "sth", "@"], ["cryptovalid_merkle", "prove", "@", "0"], ["cryptovalid_receipt", "sth", "@", "W.key"],
                 ["cryptovalid_receipt", "inclusion", "@", "0", "W.key"], ["cryptovalid_receipt", "verify", "@", "00" * 32], ["cryptovalid_jws", "sign", "@", "0", "W.key"],
                 ["cryptovalid_jws", "sign", "ledger.jsonl", "1", "W.key", "--x5c", "@"], ["cryptovalid_jws", "verify", "@", "00" * 32],
                 ["cryptovalid_scitt", "verify", "@", "--issuer-pubkey", "00" * 32, "--ts-pubkey", "00" * 32],
                 ["cryptovalid_scitt", "sign", "@", "--cty", "a/b", "--iss", "i", "--sub", "s", "--key", "@", "--out", "s.cose"],
                 ["cryptovalid_acta", "verify", "@", "--key", "k=" + "00" * 32], ["cryptovalid_acta", "verify", "s.json", "--jwks", "@"],
                 ["cryptovalid_acta", "sign", "--key", "W.key", "--tool", "t", "--decision", "allow", "--previous", "@", "--out", "a"],
                 ["evidence_pack", "build", "pack", "ledger.jsonl", "@"], ["evidence_pack", "build", "pack", "@", "ledger.jsonl", "--sign-key", "@"],
                 ["cryptovalid_monitor", "@", "m"], ["cryptovalid_monitor", "ledger.jsonl", "@"], ["cryptovalid_monitor", "ledger.jsonl", "m", "--sth-file", "@", "--trusted-pubkey", "00" * 32],
                 ["cryptovalid_witness", "cosign", "@", "--state", "w", "--log-vkey", "x", "--name", "w", "--key", "W.key", "--out", "o"],
                 ["cryptovalid_witness", "verify", "@", "--log-vkey", "x"], ["cryptovalid_heterogeneous", "00" * 32, "@"], ["dora_incident", "attest", "@"],
                 ["tx_evidence", "attest", "@"], ["cryptovalid_reanchor", "@", "--age-days", "1"], ["eidas_ledger_check", "@", "--report"],
                 ["eidas_ledger_check", "ledger.jsonl", "--deployment", "@"], ["verify_evidence", "ledger", "ledger.jsonl", "--profile", "@"]]
        cases += [["verify_evidence", c, "@"] for c in ("ledger", "auto", "pack", "archive", "ap2", "cldma")]
        for args, (rc, hits, intact, _, tail) in self.all_cases([[x.replace("@", "signer.key") for x in a] for a in cases]):
            with self.subTest(args):
                self.assertEqual((hits, intact), ([], True), tail)

    @NEEDS_CRYPTO
    def test_the_key_as_every_output(self):
        cases = [["signer", "sign", "ledger.jsonl", "@", "@"], ["cryptovalid_tip", "sign", "ledger.jsonl", "@", "--out", "@"],
                 ["cryptovalid_checkpoint", "sign", "ledger.jsonl", "--origin", "o", "--key", "@", "--out", "@"],
                 ["cryptovalid_receipt", "inclusion", "ledger.jsonl", "1", "@", "--cose", "@"],
                 ["cryptovalid_scitt", "sign", "s.json", "--cty", "a/b", "--iss", "i", "--sub", "s", "--key", "@", "--out", "@"],
                 ["cryptovalid_acta", "sign", "--key", "@", "--tool", "t", "--decision", "allow", "--out", "@"],
                 ["verifier", "ledger.jsonl", "--out", "@"], ["cryptovalid_monitor", "ledger.jsonl", "@", "--keyfile", "@"],
                 ["signer", "keygen", "@"], ["evidence_pack", "build", ".", os.path.join("..", "ledger.jsonl"), "--sign-key", "@"]]
        for args, (rc, hits, intact, _, tail) in self.all_cases([[x.replace("@", "signer.key") for x in a] for a in cases]):
            with self.subTest(args):
                self.assertTrue(intact, tail)
                self.assertEqual(hits, [], tail)
                self.assertEqual(rc, 0 if args[1] == "build" else 2 if args[1] in ("keygen",) or args[0] == "cryptovalid_monitor" else 74, tail)

    @NEEDS_CRYPTO
    def test_every_command_rewrites_its_own_output(self):
        """rule 3 refuses no rewrite: each output written twice, with the modes a shell gives (022) and a strict one gives (077)"""
        import cryptovalid_checkpoint as C
        vk = C.vkey("o", C.TYPE_ED25519, C.pubkey_from_seed(SEED))
        cases = [a for a in self.SIGNING] + [["verifier", "ledger.jsonl", "--out", "r.json"],
                 ["cryptovalid_witness", "cosign", "cp", "--state", "st", "--log-vkey", vk, "--name", "w", "--key", "W.key", "--out", "cos"],
                 ["cryptovalid_scitt", "register", "s.cose", "--ledger", "led2", "--issuer-pubkey", C.pubkey_from_seed(SEED).hex(), "--ts-key", "W.key", "--ts-iss", "t", "--out", "ts.cose"],
                 ["cryptovalid_report", "pack", "--html-only"]]
        for umask in ((0o022, 0o077) if os.name != "nt" else (0,)):
            cwd = os.path.join(self.d, "rw%o" % umask)
            os.mkdir(cwd)
            for n in ("ledger.jsonl", "W.key", "s.json", "signer.key"):
                shutil.copy(os.path.join(self.d, n), cwd)
            old = os.umask(umask)
            try:
                for turn in (1, 2):
                    for a in cases:
                        with self.subTest(args=a[:2], umask=umask, turn=turn):
                            r = self.run_one([x.replace("@", "signer.key") for x in a], cwd)
                            if a[:2] == ["cryptovalid_scitt", "register"] and turn == 2:   # registered once: its own refusal, not rule 3
                                self.assertNotIn(b"key file", r.stderr + r.stdout)
                                continue
                            self.assertEqual(r.returncode, 0, r.stdout[-200:] + r.stderr[-300:])
            finally:
                os.umask(old)


if __name__ == "__main__":
    unittest.main()
