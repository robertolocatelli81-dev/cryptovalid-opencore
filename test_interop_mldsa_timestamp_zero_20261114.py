#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
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


@unittest.skipIf(C._mldsa() is None, "cryptography without the mldsa module")
class WitnessLineTimestampZero(unittest.TestCase):
    """A witness's ML-DSA-44 line with timestamp 0 is a subtree cosignature over [0, size): tlog-cosignature, "a statement
    that the subtree with the specified hash is consistent with all other historical views ... No statement is made about
    the age". verify_witnessed counts it as a witness (0.23.0: NON_VALIDA), never as a fresh one."""
    def test_counts_without_max_age_never_fresh(self):
        import hashlib
        import cryptovalid_witness as W
        m = C._mldsa()
        seed_log, seed_w = b"\x01" * 32, b"\x02" * 32
        text = C.checkpoint_text("example.com/log", 5, hashlib.sha256(b"r").digest())
        note = C.sign_note(text, "example.com/log", seed_log)
        lvk = C.vkey("example.com/log", C.TYPE_ED25519, C.pubkey_from_seed(seed_log))
        wpub = C.mldsa44_pubkey_from_seed(seed_w)
        wvk = C.vkey("w.example", C.TYPE_MLDSA44, wpub)
        cp = C.parse_checkpoint(text)
        sig = m.MLDSA44PrivateKey.from_seed_bytes(seed_w).sign(
            C.mldsa44_message("w.example", 0, cp["origin"], 0, cp["size"], cp["root"]))
        line = C._sig_line("w.example", C.key_id("w.example", C.TYPE_MLDSA44, wpub), struct.pack(">Q", 0) + sig)
        r = W.verify_witnessed(note + line.encode(), lvk, [wvk], min_witnesses=1)
        self.assertEqual((r["stato"], r["witnesses"]), ("OK", ["w.example"]), r)
        r = W.verify_witnessed(note + line.encode(), lvk, [wvk], min_witnesses=1, max_age_s=3600, now=10 ** 9)
        self.assertEqual((r["stato"], r["fresh_witnesses"]), ("NON_VALIDA", []), r)


if __name__ == "__main__":
    unittest.main()
