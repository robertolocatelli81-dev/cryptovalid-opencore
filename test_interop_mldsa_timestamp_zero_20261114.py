#!/usr/bin/env python3
"""ML-DSA-44 note signatures with timestamp 0 (14/11/2026).

c2sp.org/tlog-cosignature, "ML-DSA-44": the signed CosignedSubtree carries `timestamp`, which is "the input timestamp for
checkpoint cosignatures and zero for subtree cosignatures"; "If `start` is zero, `timestamp` may be zero or the current
time". verify_note refused every ML-DSA-44 line with timestamp 0 (it required 1 <= ts), so a valid checkpoint signed by an
ML-DSA-44 log key - torchwood's litewitness test vector, which that witness accepts - came out NON_VALIDA.

Measured on 14/11/2026 against FiloSottile/torchwood @ 1c05157 (testdata/interop/README.md). The Ed25519 cosignature/v1
branch is not changed: that algorithm signs checkpoints only, with a timestamp.
"""
import base64
import os
import struct
import unittest

import cryptovalid_checkpoint as C

HERE = os.path.dirname(os.path.abspath(__file__))
D = os.path.join(HERE, "testdata", "interop")


def _read(n, mode="r"):
    with open(os.path.join(D, n), mode) as f:
        return f.read()


@unittest.skipIf(C._mldsa() is None, "cryptography without the mldsa module")
class TorchwoodMLDSA44(unittest.TestCase):
    def setUp(self):
        self.vk = _read("torchwood_mldsa44_log.vkey").strip()
        self.note = _read("torchwood_mldsa44_log.note", "rb")

    def test_vector_is_what_the_readme_says(self):
        text, sigs = C.split_note(self.note)
        self.assertEqual(len(sigs), 1)
        name, blob = sigs[0]
        self.assertEqual(name, "example.com/mldsa-log")
        self.assertEqual(struct.unpack(">Q", blob[4:12])[0], 0)            # the timestamp under test
        self.assertEqual(base64.b64decode(self.vk.split("+", 2)[2])[0], C.TYPE_MLDSA44)

    def test_valid_with_timestamp_zero(self):
        r = C.verify_note(self.note, [self.vk])
        self.assertEqual(r["stato"], "OK", r)
        self.assertEqual(r["verified"], [{"name": "example.com/mldsa-log", "type": C.TYPE_MLDSA44, "timestamp": 0}])

    def test_negative_controls(self):
        text, sigs = C.split_note(self.note)
        name, blob = sigs[0]
        def note_with(blob2, text2=text):
            return (text2 + "\n— %s %s\n" % (name, base64.b64encode(blob2).decode())).encode()
        self.assertEqual(C.verify_note(note_with(blob), [self.vk])["stato"], "OK")       # the rebuild is faithful
        bad = bytearray(blob); bad[40] ^= 1
        self.assertEqual(C.verify_note(note_with(bytes(bad)), [self.vk])["stato"], "NON_VALIDA")
        ts1 = blob[:4] + struct.pack(">Q", 1) + blob[12:]                     # the signature does not cover ts = 1
        self.assertEqual(C.verify_note(note_with(ts1), [self.vk])["stato"], "NON_VALIDA")
        cp = C.parse_checkpoint(text)
        other = C.checkpoint_text(cp["origin"], cp["size"] + 1, cp["root"])
        self.assertEqual(C.verify_note(note_with(blob, other.rstrip("\n")), [self.vk])["stato"], "NON_VALIDA")
        top = blob[:4] + struct.pack(">Q", 2 ** 63) + blob[12:]               # still bounded above
        self.assertEqual(C.verify_note(note_with(top), [self.vk])["stato"], "NON_VALIDA")


if __name__ == "__main__":
    unittest.main()
