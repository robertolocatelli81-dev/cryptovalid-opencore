#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""The stage MALFORMED_STATEMENT of cryptovalid_cose_receipts.verify_statement, and the CBOR decoder under it.

Until this file no test named that stage. The hostile inputs are the 94 examples of RFC 8949 Appendix F.1 ("Examples of
CBOR Data Items That Are Not Well-Formed", https://www.rfc-editor.org/rfc/rfc8949.txt), proposed by Athena's review of
15/11/2026 and compared byte for byte with the text of the RFC on 15/11/2026 (94 of 94 equal, in order). They are cited
as data (the example byte sequences, grouped as the appendix groups them), not as text of the RFC.

Each example e in five positions: e alone; 0xd2 || e; a COSE_Sign1 whose first element is e; a COSE_Sign1 whose
protected bstr holds e; a valid Signed Statement followed by e. Expected for all 470: ok False, stage
MALFORMED_STATEMENT, no exception. Positive controls in the same file: the valid statement is ok True, a decoder that
accepts what it cannot read makes the check report failures, and the stages of a well-formed statement that is refused
for another reason are not MALFORMED_STATEMENT.

The decoder (cryptovalid_receipt.cbor_decode) raises only ValueError on bytes since 15/11/2026, and names "too little
data" as such: on the code before, 16 of the 94 examples raised IndexError and the cut-short ones were reported as
"byte in eccesso" (bytes in excess)."""
import os
import random
import sys
import unittest
from unittest import mock

sys.dont_write_bytecode = True
ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)
import cryptovalid_cose_receipts as CR  # noqa: E402
import cryptovalid_receipt as R  # noqa: E402
from cryptovalid_scitt import TAG_COSE_SIGN1, _sig1  # noqa: E402

try:   # the `sign` extra; without it the cases that need a signed statement are skipped with this reason
    from cryptography.hazmat.primitives import serialization as ser
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    HAVE_CRYPTO = True
except ImportError:
    HAVE_CRYPTO = False
if os.environ.get("CV_REQUIRE_CRYPTO") == "1" and not HAVE_CRYPTO:   # the job with cryptography must not pass on skips
    raise SystemExit("CV_REQUIRE_CRYPTO=1 but `cryptography` is missing: the cases that need it would be skipped")
NEEDS_CRYPTO = unittest.skipUnless(HAVE_CRYPTO, "needs `cryptography` (the `sign` extra)")

# RFC 8949 Appendix F.1, in the order of the appendix; "short" marks the groups of error kind 2 (too little data)
F1 = [
    ("End of input in a head", True,
     "18|19|1a|1b|19 01|1a 01 02|1b 01 02 03 04 05 06 07|38|58|78|98|9a 01 ff 00|b8|d8|f8|f9 00|fa 00 00|fb 00 00 00"),
    ("Definite-length strings with short data", True,
     "41|61|5a ff ff ff ff 00|5b ff ff ff ff ff ff ff ff 01 02 03|7a ff ff ff ff 00|7b 7f ff ff ff ff ff ff ff 01 02 03"),
    ("Definite-length maps and arrays not closed with enough items", True,
     "81|81 81 81 81 81 81 81 81 81|82 00|a1|a2 01 02|a1 00|a2 00 00 00"),
    ("Tag number not followed by tag content", True, "c0"),
    ("Indefinite-length strings not closed by a break stop code", True, "5f 41 00|7f 61 00"),
    ("Indefinite-length maps and arrays not closed by a break stop code", True,
     "9f|9f 01 02|bf|bf 01 02 01 02|81 9f|9f 80 00|9f 9f 9f 9f 9f ff ff ff ff|9f 81 9f 81 9f 9f ff ff ff"),
    ("Reserved additional information values", False,
     "1c|1d|1e|3c|3d|3e|5c|5d|5e|7c|7d|7e|9c|9d|9e|bc|bd|be|dc|dd|de|fc|fd|fe"),
    ("Reserved two-byte encodings of simple values", False, "f8 00|f8 01|f8 18|f8 1f"),
    ("Indefinite-length string chunks not of the correct type", False,
     "5f 00 ff|5f 21 ff|5f 61 00 ff|5f 80 ff|5f a0 ff|5f c0 00 ff|5f e0 ff|7f 41 00 ff"),
    ("Indefinite-length string chunks not definite length", False, "5f 5f 41 00 ff ff|7f 7f 61 00 ff ff"),
    ("Break occurring on its own outside of an indefinite-length item", False, "ff"),
    ("Break occurring in a definite-length array or map or a tag", False,
     "81 ff|82 00 ff|a1 ff|a1 ff 00|a1 00 ff|a2 00 00 ff|9f 81 ff|9f 82 9f 81 9f 9f ff ff ff ff"),
    ("Break in an indefinite-length map that would lead to an odd number of items (break in a value position)", False,
     "bf 00 ff|bf 00 00 00 ff"),
    ("Major type 0, 1, 6 with additional information 31", False, "1f|3f|df"),
]
COUNTS = [18, 6, 7, 1, 2, 8, 24, 4, 8, 2, 1, 8, 2, 3]   # per group, counted on the RFC text (94)


def examples():
    return [(group, short, bytes.fromhex(h)) for group, short, hs in F1 for h in hs.split("|")]


PAYLOAD = b'{"artifact":"x","v":1}'
if HAVE_CRYPTO:
    SK = Ed25519PrivateKey.generate()
    PEM = SK.public_key().public_bytes(ser.Encoding.PEM, ser.PublicFormat.SubjectPublicKeyInfo)
    PB = R.cbor_encode({1: CR.ALG_EDDSA})
    SIG = SK.sign(_sig1(PB, PAYLOAD))
    VALID = TAG_COSE_SIGN1 + R.cbor_encode([PB, {}, PAYLOAD, SIG])


def positions(e):
    bstr = R.cbor_encode
    return {"alone": e,
            "tagged": TAG_COSE_SIGN1 + e,
            "as_first_element": TAG_COSE_SIGN1 + b"\x84" + e + b"\xa0" + bstr(PAYLOAD) + bstr(SIG),
            "inside_protected_bstr": TAG_COSE_SIGN1 + b"\x84" + bstr(bytes(e)) + b"\xa0" + bstr(PAYLOAD) + bstr(SIG),
            "appended": VALID + e}


def f1_failures():
    """Every (example, position) whose answer is not ok False / MALFORMED_STATEMENT, or that raised."""
    bad = []
    for group, _, e in examples():
        for pos, data in positions(e).items():
            try:
                r = CR.verify_statement(data, PEM)
            except Exception as ex:  # noqa: BLE001
                bad.append((e.hex(), pos, f"raised {type(ex).__name__}"))
                continue
            if (r.get("ok"), r.get("stage")) != (False, "MALFORMED_STATEMENT"):
                bad.append((e.hex(), pos, (r.get("ok"), r.get("stage"))))
    return bad


class TheExamplesAreTheRFCs(unittest.TestCase):
    def test_counts_and_no_duplicate(self):
        self.assertEqual([len(hs.split("|")) for _, _, hs in F1], COUNTS)
        self.assertEqual(len(examples()), 94)
        self.assertEqual(len({e for _, _, e in examples()}), 94)


class DecoderOnTheExamples(unittest.TestCase):
    def test_each_example_alone_is_refused_with_value_error_only(self):
        for group, _, e in examples():
            with self.assertRaises(ValueError, msg=f"{group}: {e.hex()}"):
                R.cbor_decode(e)
            try:
                R.cbor_decode(e)
            except ValueError:
                pass
            except Exception as ex:  # noqa: BLE001 — on the code before 15/11/2026: IndexError for 16 of them
                self.fail(f"{e.hex()} raised {type(ex).__name__}, not ValueError")

    def test_too_little_data_is_named_as_such(self):
        # the groups of error kind 2 whose first missing byte this decoder reaches (the others stop earlier, on an
        # encoding it does not support: indefinite length, tags)
        for group, short, e in examples():
            try:
                R.cbor_decode(e)
            except ValueError as ex:
                msg = str(ex)
            self.assertNotIn("trailing bytes", msg, f"{group}: {e.hex()}")
            if short and e[0] >> 5 not in (6,) and (e[0] & 0x1f) != 31 and b"\x9f" not in e[:2]:
                self.assertIn("input ends inside", msg, f"{group}: {e.hex()}")

    def test_reserved_additional_information_is_named(self):
        for e in (b"\x1c", b"\x5d", b"\xfe"):
            with self.assertRaisesRegex(ValueError, "is reserved"):
                R.cbor_decode(e)
        with self.assertRaisesRegex(ValueError, "trailing bytes"):   # too much data ("byte in eccesso" until 0.26.0)
            R.cbor_decode(b"\x00\x00")

    def test_generative_every_prefix_of_well_formed_items_is_too_little_data(self):
        rnd = random.Random(20261115)
        items = [0, 23, 24, 255, 256, 65535, 65536, 2 ** 32, 2 ** 64 - 1, -1, -2 ** 64, b"", b"x" * 300, "é" * 40,
                 [1, [2, [3]]], {1: b"a", "k": [None, True, False]}]
        for _ in range(200):
            items.append({rnd.randrange(-300, 300): bytes(rnd.randrange(256) for _ in range(rnd.randrange(40)))
                          for _ in range(rnd.randrange(1, 5))})
        n = 0
        for x in items:
            enc = R.cbor_encode(x)
            self.assertEqual(R.cbor_decode(enc), x)                           # positive control: the whole item reads
            for k in range(len(enc)):
                with self.assertRaisesRegex(ValueError, "input ends inside", msg=enc[:k].hex()):
                    R.cbor_decode(enc[:k])
                n += 1
            with self.assertRaisesRegex(ValueError, "trailing bytes"):
                R.cbor_decode(enc + b"\x00")
        self.assertGreater(n, 5000)

    def test_generative_random_bytes_raise_value_error_only(self):
        rnd = random.Random(15112026)
        for _ in range(20000):
            b = bytes(rnd.randrange(256) for _ in range(rnd.randrange(0, 12)))
            try:
                R.cbor_decode(b)
            except ValueError:
                pass
            except Exception as ex:  # noqa: BLE001
                self.fail(f"{b.hex()}: {type(ex).__name__}: {ex}")


@NEEDS_CRYPTO
class MalformedStatement(unittest.TestCase):
    def test_positive_control_valid_statement(self):
        r = CR.verify_statement(VALID, PEM)
        self.assertEqual((r["ok"], r["stage"]), (True, None))
        self.assertTrue(CR.verify_statement(VALID, PEM, profile="rfc9942")["ok"])
        self.assertEqual(positions(b"")["appended"], VALID)            # the builder, with nothing injected, is the valid one
        built = TAG_COSE_SIGN1 + b"\x84" + R.cbor_encode(PB) + b"\xa0" + R.cbor_encode(PAYLOAD) + R.cbor_encode(SIG)
        self.assertEqual(built, VALID)                                  # and the hand-built array equals the encoder's

    def test_every_f1_example_in_five_positions(self):
        self.assertEqual(f1_failures(), [])

    def test_positive_control_a_decoder_that_accepts_is_caught(self):
        real = R.cbor_decode

        def accepting(b):   # what it cannot read becomes a valid protected header or a valid statement
            try:
                return real(b)
            except ValueError:
                return [PB, {}, PAYLOAD, SIG] if b[:1] == b"\x84" else {1: CR.ALG_EDDSA}
        with mock.patch.object(R, "cbor_decode", accepting):
            self.assertGreater(len(f1_failures()), 0)

    def test_other_malformed_shapes(self):
        for data in (b"", b"\xd2", VALID[:-1], VALID[1:], b"\xd2\x80", b"\xd2\x83" + VALID[2:], None, "text",
                     TAG_COSE_SIGN1 + b"\x9f" * 5000, TAG_COSE_SIGN1 + b"\x81" * 5000 + b"\x00",
                     TAG_COSE_SIGN1 + R.cbor_encode([R.cbor_encode([1]), {}, PAYLOAD, SIG]),       # protected is not a map
                     TAG_COSE_SIGN1 + R.cbor_encode([PB, {}, PAYLOAD, SIG, SIG])):
            r = CR.verify_statement(data, PEM)
            self.assertEqual((r["ok"], r["stage"]), (False, "MALFORMED_STATEMENT"), repr(data)[:40])

    def test_well_formed_refusals_keep_their_own_stage(self):
        bad_sig = TAG_COSE_SIGN1 + R.cbor_encode([PB, {}, PAYLOAD, SIG[:-1] + bytes([SIG[-1] ^ 1])])
        self.assertEqual(CR.verify_statement(bad_sig, PEM)["stage"], "BAD_STATEMENT_SIGNATURE")
        pb2 = R.cbor_encode({1: -257})
        self.assertEqual(CR.verify_statement(TAG_COSE_SIGN1 + R.cbor_encode([pb2, {}, PAYLOAD, SIG]), PEM)["stage"],
                         "UNSUPPORTED_ALG")

    def test_generative_truncations_and_byte_flips_of_the_valid_statement(self):
        stages = {"MALFORMED_STATEMENT", "BAD_STATEMENT_SIGNATURE", "UNSUPPORTED_ALG", "PAYLOAD_MISMATCH",
                  "DETACHED_PAYLOAD_MISSING", "HEADER_MUST"}
        for k in range(len(VALID)):                                     # every truncation: too little data
            r = CR.verify_statement(VALID[:k], PEM)
            self.assertEqual((r["ok"], r["stage"]), (False, "MALFORMED_STATEMENT"), k)
        rnd = random.Random(61)
        for _ in range(3000):                                           # one byte changed: a closed stage, never a raise
            b = bytearray(VALID)
            b[rnd.randrange(len(b))] ^= rnd.randrange(1, 256)
            r = CR.verify_statement(bytes(b), PEM)
            self.assertFalse(r["ok"], bytes(b).hex())
            self.assertIn(r["stage"], stages)


@NEEDS_CRYPTO
class CedulonStageOfTruncatedCbor(unittest.TestCase):
    """The same decoder under cryptovalid_cedulon: a record whose COSE bytes end inside a head raised IndexError, which
    the catch-all turned into stage `malformed`; it is the stage that reads the record, `record-header`."""

    def test_truncated_record_is_record_header(self):
        import json
        import cryptovalid_cedulon as C
        for cose_hex in ("18", "8441", "84", "9a01ff00"):
            r = C.verify_ledger(json.dumps({"coseHex": cose_hex}) + "\n", "", "", PEM, PEM, PEM)
            self.assertEqual((r["result"], r["stage"]), ("INVALID", "record-header"), (cose_hex, r))
            self.assertNotIn("IndexError", r["why"])


if __name__ == "__main__":
    unittest.main(verbosity=1)
