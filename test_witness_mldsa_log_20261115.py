#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""A log that signs its checkpoints with ML-DSA-44 (type 0x06), in the witness module (SPEC §16, 15/11/2026).

c2sp.org/tlog-checkpoint (C2SP/C2SP @ 09f3e519fe79), "ML-DSA-44 Checkpoint Cosignatures": "This signature type can be
used either by the log to authenticate itself, or by an arbitrary cosigner role." The Sigstore v2 staging log
(pqc27-a1.us-east4.rekor.sigstage.dev) does so, and torchwood's litewitness accepts an ML-DSA-44 log key
(testdata/interop/torchwood_mldsa44_log.*). cryptovalid_witness took the TYPE of a key for its role: every entry point
refused a 0x06 log key ("a log key must be an Ed25519 (0x01) or ECDSA (0x02) note key"), and verify_witnessed counted
every verified 0x04/0x06 line as a witness, so a 0x06 log line would have counted as one. Now the role is the list the
caller puts the key in; a key in both lists is refused; with only ML-DSA-44 log signatures, extension lines (which no
log signature covers) are refused.

CV_SIGSTAGE_DIR=<dir with `checkpoint` and `vkeys.json` {"log": vkey, "witnesses": [vkeys]}> also checks a live
checkpoint of the Sigstore staging log (not shipped here).
"""
import hashlib
import json
import os
import random
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import cryptovalid_checkpoint as C   # noqa: E402
import cryptovalid_witness as W   # noqa: E402

try:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: F401
    HAVE_CRYPTO = True
except Exception:  # noqa: BLE001
    HAVE_CRYPTO = False
HAVE_MLDSA = HAVE_CRYPTO and C._mldsa() is not None
if os.environ.get("CV_REQUIRE_CRYPTO") == "1" and not HAVE_MLDSA:
    raise SystemExit("CV_REQUIRE_CRYPTO=1 but `cryptography` with `mldsa` did not import: the suite would be skipped")

D = os.path.join(HERE, "testdata", "interop")
ORIGIN = "example.org/mldsa-log"
T0 = 1_794_700_000   # 2026-11-14T...Z, explicit: no wall clock
ROOT = bytes(range(32))


def _seed(tag):
    return bytes([tag]) * 32


def _mldsa_vkey(name, seed):
    return C.vkey(name, C.TYPE_MLDSA44, C.mldsa44_pubkey_from_seed(seed))


def _mldsa_line(text, name, seed, ts):
    """An ML-DSA-44 cosignature/v1 line (the log signing itself may use timestamp 0)."""
    cp = C.parse_checkpoint(text)
    sk = C._mldsa().MLDSA44PrivateKey.from_seed_bytes(seed)
    sig = sk.sign(C.mldsa44_message(name, ts, cp["origin"], 0, cp["size"], cp["root"]))
    return C._sig_line(name, C.key_id(name, C.TYPE_MLDSA44, sk.public_key().public_bytes_raw()), struct.pack(">Q", ts) + sig)


def _ed_log_line(text, name, seed):
    return C.sign_note(text, name, seed)[len(text) + 1:].decode("utf-8")


def _ed_cosig_line(text, name, seed, ts):
    note = C.sign_note(text, "x.example/tmp", _seed(0xEE))
    return C.cosign_v1(note, name, seed, ts)[len(note):].decode("utf-8")


def _ecdsa_key(tag):
    k = ec.derive_private_key(int.from_bytes(bytes([tag]) * 16, "big"), ec.SECP256R1())
    der = k.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return k, der


def _ecdsa_line(text, name, k, der):
    return C._sig_line(name, hashlib.sha256(der).digest()[:4], k.sign(text.encode(), ec.ECDSA(hashes.SHA256())))


def _note(text, lines):
    return (text + "\n" + "".join(lines)).encode("utf-8")


@unittest.skipUnless(HAVE_MLDSA, "cryptography with the mldsa module")
class MLDSALogRelyingParty(unittest.TestCase):
    def setUp(self):
        self.text = C.checkpoint_text(ORIGIN, 5, ROOT)
        self.lv = _mldsa_vkey(ORIGIN, _seed(1))
        self.wv = [_mldsa_vkey(f"w{i}.example/w", _seed(10 + i)) for i in range(3)]
        self.note = _note(self.text, [_mldsa_line(self.text, ORIGIN, _seed(1), 0)]
                          + [_mldsa_line(self.text, f"w{i}.example/w", _seed(10 + i), T0 + i) for i in range(3)])

    def test_mldsa_log_accepted_and_never_a_witness(self):
        r = W.verify_witnessed(self.note, self.lv, self.wv, min_witnesses=3)
        self.assertEqual(r["stato"], "OK", r)
        self.assertEqual(r["witnesses"], ["w0.example/w", "w1.example/w", "w2.example/w"])
        r = W.verify_witnessed(self.note, self.lv, self.wv, min_witnesses=4)   # the log's 0x06 line is not a 4th witness
        self.assertEqual(r["stato"], "NON_VALIDA")
        self.assertIn("3 trusted witness cosignature(s), 4 required", r["motivo"])

    def test_log_line_does_not_count_for_a_witness_of_the_same_name_and_type(self):
        other = _mldsa_vkey(ORIGIN, _seed(2))   # a witness key named as the log, another key: its line is absent
        r = W.verify_witnessed(self.note, self.lv, [other], min_witnesses=1)
        self.assertEqual((r["stato"], r["witnesses"]), ("NON_VALIDA", []), r)
        withit = self.note + _mldsa_line(self.text, ORIGIN, _seed(2), T0).encode()
        r = W.verify_witnessed(withit, self.lv, [other], min_witnesses=1)   # with its own line it counts (caller's list)
        self.assertEqual((r["stato"], r["witnesses"]), ("OK", [ORIGIN]), r)

    def test_witness_line_is_not_the_log_signature(self):
        only_w = _note(self.text, [_mldsa_line(self.text, f"w{i}.example/w", _seed(10 + i), T0) for i in range(3)])
        r = W.verify_witnessed(only_w, self.lv, self.wv, min_witnesses=1)
        self.assertEqual(r["stato"], "NON_VALIDA"); self.assertIn("no log signature", r["motivo"])
        # a witness key given as the log key: the witness's line is then the log's, and the log is no witness
        r = W.verify_witnessed(only_w, self.wv[0], self.wv[1:], 2, expected_origin=ORIGIN)
        self.assertEqual((r["stato"], r["witnesses"]), ("OK", ["w1.example/w", "w2.example/w"]), r)

    def test_same_key_in_both_lists_refused(self):
        for wl in ([self.lv], [self.wv[0], self.lv], [self.lv, self.lv]):
            with self.assertRaises(C.NoteError) as cm:
                W.verify_witnessed(self.note, self.lv, wl, 1)
            self.assertIn("both a log key and a witness key", str(cm.exception))
        with self.assertRaisesRegex(C.NoteError, "both a log key and a witness key"):
            W.verify_witnessed(self.note, [self.lv, self.wv[0]], [self.wv[0]], 1, expected_origin=ORIGIN)
        with self.assertRaisesRegex(C.NoteError, "both a log key and a witness key"):   # before the round trip (port 9)
            W.submit_checkpoint("http://127.0.0.1:9/", self.note, [b"x"], [self.lv], self.lv)

    def test_witness_list_and_log_list_types(self):
        ed_log = C.vkey(ORIGIN, C.TYPE_ED25519, C.pubkey_from_seed(_seed(3)))
        ed_cos = C.vkey("w.example/e", C.TYPE_COSIG_V1, C.pubkey_from_seed(_seed(4)))
        for wl in ([ed_log], [REKOR_VKEY]):   # 0x01 / 0x02 in the witness list: a log key is not a witness
            with self.assertRaises(C.NoteError) as cm:
                W.verify_witnessed(self.note, self.lv, wl, 1)
            self.assertIn("a log key is not a witness", str(cm.exception))
            with self.assertRaisesRegex(C.NoteError, "a log key is not a witness"):
                W.submit_checkpoint("http://127.0.0.1:9/", self.note, [b"x"], wl, self.lv)
        with self.assertRaises(C.NoteError) as cm:   # 0x04 is not a log key (SPEC §16 rule 2)
            W.verify_witnessed(self.note, ed_cos, self.wv, 1, expected_origin=ORIGIN)
        self.assertIn("ML-DSA-44 (0x06)", str(cm.exception))

    def test_extension_lines_need_a_log_signature_that_covers_them(self):
        ext = C.checkpoint_text(ORIGIN, 5, ROOT, ["ext line"])
        lines = [_mldsa_line(ext, f"w{i}.example/w", _seed(10 + i), T0) for i in range(3)]
        n6 = _note(ext, [_mldsa_line(ext, ORIGIN, _seed(1), 0)] + lines)
        r = W.verify_witnessed(n6, self.lv, self.wv, 1)
        self.assertEqual(r["stato"], "NON_VALIDA"); self.assertIn("extension lines", r["motivo"])
        self.assertEqual(W.verify_witnessed(self.note, self.lv, self.wv, 1)["stato"], "OK")   # control: no extension
        ed_lv = C.vkey(ORIGIN, C.TYPE_ED25519, C.pubkey_from_seed(_seed(3)))
        n1 = _note(ext, [_ed_log_line(ext, ORIGIN, _seed(3))] + lines)   # Ed25519 log signs them: as before
        self.assertEqual(W.verify_witnessed(n1, ed_lv, self.wv, 1)["stato"], "OK")
        both = _note(ext, [_ed_log_line(ext, ORIGIN, _seed(3)), _mldsa_line(ext, ORIGIN, _seed(1), 0)] + lines)
        self.assertEqual(W.verify_witnessed(both, [ed_lv, self.lv], self.wv, 1)["stato"], "OK")   # rotation, 0x01 covers

    def test_cli_verify(self):
        d = tempfile.mkdtemp()
        try:
            p = os.path.join(d, "cp.note")
            with open(p, "wb") as f:
                f.write(self.note)
            env = dict(os.environ); env.pop("PYTHONPATH", None)
            r = subprocess.run([sys.executable, os.path.join(HERE, "cryptovalid_witness.py"), "verify", p, "--log-vkey", self.lv]
                               + sum([["--witness-vkey", w] for w in self.wv], []) + ["--min-witnesses", "3"],
                               capture_output=True, text=True, cwd=d, env=env, timeout=120)
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
            self.assertEqual(json.loads(r.stdout)["stato"], "OK")
        finally:
            shutil.rmtree(d)


REKOR_VKEY = ("rekor.sigstore.dev+c0d23d6a+AjBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABNhtmPtrWm3U1eQXBogSMdGvXwBcK5AW5i0hrZLOC96l+"
              "smGNM7nwZ4QvFK/4sueRoVj//QP22Ni4Qt9DPfkWLc=")


@unittest.skipUnless(HAVE_MLDSA, "cryptography with the mldsa module")
class MLDSALogWitnessSide(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.st = os.path.join(self.d, "w.json")

    def tearDown(self):
        shutil.rmtree(self.d)

    def test_torchwood_litewitness_vector_is_cosigned(self):
        with open(os.path.join(D, "torchwood_mldsa44_log.vkey")) as f:
            vk = f.read().strip()
        with open(os.path.join(D, "torchwood_mldsa44_log.note"), "rb") as f:
            note = f.read()
        r = W.witness_cosign(self.st, note, vk, "witness.example/w", _seed(20), None, T0, pq_seed=_seed(21))
        self.assertEqual(r["stato"], W.STATO_OK, r)
        wv = [C.vkey("witness.example/w", C.TYPE_COSIG_V1, C.pubkey_from_seed(_seed(20))), _mldsa_vkey("witness.example/w", _seed(21))]
        v = W.verify_witnessed(r["note"], vk, wv, 1)
        self.assertEqual((v["stato"], v["witnesses"]), ("OK", ["witness.example/w"]), v)

    def test_service_cosigns_an_mldsa_log_and_refuses_own_key_as_log(self):
        text = C.checkpoint_text(ORIGIN, 5, ROOT)
        lv = _mldsa_vkey(ORIGIN, _seed(1))
        note = _note(text, [_mldsa_line(text, ORIGIN, _seed(1), 0)])
        svc = W.WitnessService(self.st, "witness.example/w", _seed(20), [lv], pq_seed=_seed(21))
        status, body, _ = svc.add_checkpoint(W.format_add_checkpoint_body(0, [], note), timestamp=T0)
        self.assertEqual(status, 200, body)
        wv = C.vkey("witness.example/w", C.TYPE_COSIG_V1, C.pubkey_from_seed(_seed(20)))
        self.assertEqual(W.verify_witnessed(note + body, lv, [wv], 1)["stato"], "OK")
        own = _mldsa_vkey("witness.example/w", _seed(21))   # the witness's own ML-DSA key trusted as a log key
        with self.assertRaisesRegex(C.NoteError, "both a log key and a witness key"):
            W.WitnessService(os.path.join(self.d, "o.json"), "witness.example/w", _seed(20), [own], pq_seed=_seed(21))
        t2 = C.checkpoint_text("witness.example/w", 1, ROOT)
        n2 = _note(t2, [_mldsa_line(t2, "witness.example/w", _seed(21), 0)])
        with self.assertRaisesRegex(C.NoteError, "both a log key and a witness key"):   # our line is never the log's
            W.witness_cosign(os.path.join(self.d, "o.json"), n2, own, "witness.example/w", _seed(20), None, T0, pq_seed=_seed(21))
        self.assertFalse(os.path.exists(os.path.join(self.d, "o.json")))

    def test_witness_refuses_extension_lines_only_mldsa_signed(self):
        ext = C.checkpoint_text(ORIGIN, 5, ROOT, ["ext line"])
        lv = _mldsa_vkey(ORIGIN, _seed(1))
        r = W.witness_cosign(self.st, _note(ext, [_mldsa_line(ext, ORIGIN, _seed(1), 0)]), lv, "witness.example/w", _seed(20), None, T0)
        self.assertEqual((r["stato"], r["http_status"]), ("REFUSED", 400), r); self.assertIn("extension lines", r["motivo"])
        self.assertFalse(os.path.exists(self.st))
        ed = C.vkey(ORIGIN, C.TYPE_ED25519, C.pubkey_from_seed(_seed(3)))   # control: an Ed25519 log signs them
        r = W.witness_cosign(self.st, _note(ext, [_ed_log_line(ext, ORIGIN, _seed(3))]), ed, "witness.example/w", _seed(20), None, T0)
        self.assertEqual(r["stato"], W.STATO_OK, r)


@unittest.skipUnless(HAVE_MLDSA, "cryptography with the mldsa module")
class Generative(unittest.TestCase):
    """Keys of every type in both roles, duplicates and orders, against an oracle written from SPEC §16 alone."""

    def test_roles(self):
        rnd = random.Random(20261115)
        text = C.checkpoint_text(ORIGIN, 7, ROOT)
        ek, eder = _ecdsa_key(5)
        keys = {   # id → (vkey, type, line or None when the note carries no line of it)
            "L1": (C.vkey(ORIGIN, C.TYPE_ED25519, C.pubkey_from_seed(_seed(1))), 1, _ed_log_line(text, ORIGIN, _seed(1))),
            "L2": (C.vkey_ecdsa(ORIGIN, eder), 2, _ecdsa_line(text, ORIGIN, ek, eder)),
            "L6": (_mldsa_vkey(ORIGIN, _seed(2)), 6, _mldsa_line(text, ORIGIN, _seed(2), 0)),
            "L6x": (_mldsa_vkey(ORIGIN, _seed(3)), 6, None),
            "C4": (C.vkey(ORIGIN, C.TYPE_COSIG_V1, C.pubkey_from_seed(_seed(1))), 4, _ed_cosig_line(text, ORIGIN, _seed(1), T0)),
            "W4": (C.vkey("w4.example/w", C.TYPE_COSIG_V1, C.pubkey_from_seed(_seed(4))), 4, _ed_cosig_line(text, "w4.example/w", _seed(4), T0)),
            "W6": (_mldsa_vkey("w6.example/w", _seed(6)), 6, _mldsa_line(text, "w6.example/w", _seed(6), T0)),
            "W6b": (_mldsa_vkey("w6b.example/w", _seed(7)), 6, _mldsa_line(text, "w6b.example/w", _seed(7), T0 + 1)),
            "W6x": (_mldsa_vkey("w6x.example/w", _seed(8)), 6, None),
            "S5": (C.vkey_rfc6962(ORIGIN, eder), 5, None),
        }
        ids = sorted(keys)
        checked = {"raise": 0, "OK": 0, "NON_VALIDA": 0}
        log_pool = ["L1", "L2", "L6", "L6x"]
        wit_pool = ["C4", "W4", "W6", "W6b", "W6x"]
        for _ in range(600):   # mostly lists of the right kind, every key now and then, repeats included
            in_note = [k for k in ids if keys[k][2] and rnd.random() < 0.7]
            rnd.shuffle(in_note)
            note = _note(text, [keys[k][2] for k in in_note])
            logl = [rnd.choice(log_pool if rnd.random() < 0.9 else ids) for _ in range(rnd.randint(1, 3))]
            witl = [rnd.choice(wit_pool if rnd.random() < 0.9 else ids) for _ in range(rnd.randint(0, 4))]
            minw = rnd.randint(1, 3)
            # oracle (SPEC §16)
            typ = {k: keys[k][1] for k in ids}
            names = {C.parse_vkey(keys[k][0], strict=False)[0] for k in logl}
            wits = set()
            if any(typ[k] not in (1, 2, 6) for k in logl) or any(typ[k] in (1, 2) for k in witl) \
                    or any(typ[k] in (4, 6) and k in logl for k in witl) or len(names) != 1:
                want = "raise"
            elif names != {ORIGIN}:   # the checkpoint's origin is not the log key's name
                want = "NON_VALIDA"
            else:
                wit_usable = {k for k in witl if typ[k] in (4, 6)}
                known = set(logl) | wit_usable
                has_log = any(k in in_note for k in logl)
                wits = {C.parse_vkey(keys[k][0])[0] for k in wit_usable if k in in_note}
                if not any(k in in_note for k in known) or not has_log or len(wits) < minw:
                    want = "NON_VALIDA"
                else:
                    want = "OK"
            try:
                r = W.verify_witnessed(note, [keys[k][0] for k in logl], [keys[k][0] for k in witl], minw)
                got = r["stato"]
                if want == "OK":
                    self.assertEqual(r["witnesses"], sorted(wits))
            except C.NoteError:
                got = "raise"
            self.assertEqual(got, want, (in_note, logl, witl, minw))
            checked[want] += 1
        self.assertTrue(all(n >= 30 for n in checked.values()), checked)   # every outcome reached


@unittest.skipUnless(HAVE_MLDSA and os.environ.get("CV_SIGSTAGE_DIR"), "CV_SIGSTAGE_DIR not given")
class SigstoreStaging(unittest.TestCase):
    def test_live_checkpoint(self):
        d = os.environ["CV_SIGSTAGE_DIR"]
        with open(os.path.join(d, "checkpoint"), "rb") as f:
            note = f.read()
        with open(os.path.join(d, "vkeys.json")) as f:
            k = json.load(f)
        r = W.verify_witnessed(note, k["log"], k["witnesses"], min_witnesses=3)
        self.assertEqual((r["stato"], len(r["witnesses"])), ("OK", 3), r)
        self.assertEqual(W.verify_witnessed(note, k["log"], k["witnesses"], min_witnesses=4)["stato"], "NON_VALIDA")
        with self.assertRaisesRegex(C.NoteError, "both a log key and a witness key"):
            W.verify_witnessed(note, k["log"], k["witnesses"] + [k["log"]], min_witnesses=1)


if __name__ == "__main__":
    unittest.main()
