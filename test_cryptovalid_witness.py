"""C2SP checkpoints, signed notes, cosignatures and the witness (0.14.0, 2026-09-19).

Every claim of the README section "Witness / split-view" is measured here: the spec vector of c2sp.org/signed-note
verifies; a tampered note, a substituted key and a forged timestamp are refused; the witness refuses a fork (same size,
different root), a rollback and an extension without a valid consistency proof, keeping BOTH log-signed notes as
evidence; a relying party can demand N witnesses and a maximum age. No wall clock: every timestamp is explicit.
When a Go toolchain is on PATH the notes are also opened by the ecosystem's own libraries (golang.org/x/mod/sumdb/note
and github.com/transparency-dev/formats/note, verifiers/note_oracle): CV_REQUIRE_GO_ORACLE=1 makes a missing Go an error.
"""
import base64, hashlib, json, os, shutil, struct, subprocess, sys, tempfile, time, unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import cryptovalid_checkpoint as C
import cryptovalid_merkle as M
import cryptovalid_witness as W
try:
    from cryptography.hazmat.primitives.asymmetric import ed25519 as _ed25519  # noqa: F401 — real presence, not a lazy import
    import signer
    HAVE_CRYPTO = True
except Exception:  # noqa: BLE001
    HAVE_CRYPTO = False

HERE = os.path.dirname(os.path.abspath(__file__))
if os.environ.get("CV_REQUIRE_GO_ORACLE") == "1" and not HAVE_CRYPTO:   # the CI job that requires the oracle must not pass on skips
    raise SystemExit("CV_REQUIRE_GO_ORACLE=1 needs `cryptography` (the oracle tests would be skipped)")
if os.environ.get("CV_REQUIRE_CRYPTO") == "1" and not HAVE_CRYPTO:      # the matrix job with cryptography must not pass on skips
    raise SystemExit("CV_REQUIRE_CRYPTO=1 but `cryptography`/`signer` did not import: the suite would be skipped")
ORACLE_SRC = os.path.join(HERE, "verifiers", "note_oracle")

# c2sp.org/signed-note, section "Verifier keys" (editor's copy downloaded 2026-09-19): the example vkey and the
# example note. Public vector, not ours: if this stops verifying, our parser is wrong, not the spec.
SPEC_VKEY = "example.com/foo+530d903a+AekyeRrm56hApGFkyQR4ZCbV54Id2LKaANYcrnKv3U2k"
SPEC_NOTE = ("This is an example message.\n\n— example.com/foo Uw2QOkn8srV1yJGh2VYRlL1Tnagv1YEq6TfXppzi2ONncAlTgK7Ztg1ER"
             "YNZXsYjOBH3mFXmRKuwHjG1Yu72IneyaQM=\n").encode("utf-8")
LOG = "cryptovalid.example/ledger-A"
# the production vkey of Rekor v1 (ECDSA P-256, verified since round 13), from the transparency-dev omniwitness
# logs.yaml downloaded 2026-09-19: its key id is SHA-256(DER SPKI)[:4], not the Ed25519 formula
REKOR_VKEY = ("rekor.sigstore.dev+c0d23d6a+AjBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABNhtmPtrWm3U1eQXBogSMdGvXwBcK5AW5i0hrZLOC96l+"
              "smGNM7nwZ4QvFK/4sueRoVj//QP22Ni4Qt9DPfkWLc=")
T0 = 1_789_776_000   # 2026-09-19T00:00:00Z (datetime(2026,9,19,tzinfo=utc).timestamp()), explicit


def _canon(e):
    return json.dumps(e, sort_keys=True, separators=(",", ":")).encode()


def _ledger(n, seed="a"):
    out, prev = [], "0" * 64
    for i in range(n):
        e = {"idx": i, "ts": f"2026-09-19T07:00:{i:02d}Z", "data": {"i": i, "s": seed}, "prev_hash": prev}
        e["self_hash"] = hashlib.sha256(_canon(e)).hexdigest(); prev = e["self_hash"]; out.append(e)
    return out


def _wb(path, data):
    with open(path, "wb") as f:
        f.write(data)


def _write(path, entries):
    with open(path, "w") as f:
        for e in entries:
            f.write(json.dumps(e) + "\n")


class TestSpecVectorAndParsing(unittest.TestCase):
    """Runs without `cryptography` too (parsing is stdlib); the signature check needs it."""

    def test_vkey_key_id_matches_spec(self):
        name, kid, typ, pub = C.parse_vkey(SPEC_VKEY)
        self.assertEqual((name, kid.hex(), typ), ("example.com/foo", "530d903a", C.TYPE_ED25519))
        self.assertEqual(C.vkey(name, typ, pub), SPEC_VKEY)

    def test_vkey_with_wrong_id_refused(self):
        bad = SPEC_VKEY.replace("530d903a", "530d903b")
        with self.assertRaises(C.NoteError):
            C.parse_vkey(bad)
        for s in ("", "a+b", "no spaces+530d903a+AQ==", "x+530d903a+AQ==", "example.com/foo+530d903a+" + "!" * 10):
            with self.assertRaises(C.NoteError):
                C.parse_vkey(s)

    @unittest.skipUnless(HAVE_CRYPTO, "cryptography assente")
    def test_spec_note_verifies_and_tampered_does_not(self):
        r = C.verify_note(SPEC_NOTE, [SPEC_VKEY])
        self.assertEqual(r["stato"], "OK", r)
        self.assertEqual(r["verified"], [{"name": "example.com/foo", "type": C.TYPE_ED25519}])
        self.assertEqual(r["text"], "This is an example message.\n")
        # positive control of the bench: one byte of text → NON_VALIDA
        r2 = C.verify_note(SPEC_NOTE.replace(b"example message", b"example massage"), [SPEC_VKEY])
        self.assertEqual(r2["stato"], "NON_VALIDA"); self.assertIn("does not verify", r2["motivo"])
        # the same note with no known key: NON_VALIDA "no signature from a known key", 1 ignored
        r3 = C.verify_note(SPEC_NOTE, [])
        self.assertEqual((r3["stato"], r3["ignored"]), ("NON_VALIDA", 1))

    def test_note_without_crypto_is_non_verificata(self):
        with mock.patch.object(C, "_ed", return_value=(None, None, None)):
            r = C.verify_note(SPEC_NOTE, [SPEC_VKEY])
        self.assertEqual(r["stato"], "NON_VERIFICATA")
        self.assertEqual(r["verified"], [])

    def test_split_note_malformed(self):
        cases = {   # labels are documentation; every case must raise NoteError
            b"": "not ending", b"text\n": "no blank line", b"text\n\n": "empty signature block = one malformed line",
            b"text\n\n\xe2\x80\x94 name notbase64!\n": "not standard base64",
            b"text\n\n- name AAAA\n": "malformed signature line",
            b"text\n\n\xe2\x80\x94 name AAAAAA==\n": "shorter",           # 4 bytes only
            b"text\x01\n\n\xe2\x80\x94 n AAAAAAAAAA==\n": "control", b"\xff\n\n": "UTF-8",
        }
        for raw in cases:
            with self.assertRaises(C.NoteError, msg=repr(raw)):
                C.split_note(raw)
        # 101 signature lines: refused; 100 accepted — the limit of golang.org/x/mod/sumdb/note (signed-note: "verifiers
        # verifiers "MUST accept at least up to 16 signatures"; 100 is the ceiling of golang.org/x/mod/sumdb/note, measured)
        many = b"text\n\n" + b"\xe2\x80\x94 n AAAAAAAAAA==\n" * 101
        with self.assertRaises(C.NoteError):
            C.split_note(many)
        text, sigs = C.split_note(b"text\n\n" + b"\xe2\x80\x94 n AAAAAAAAAA==\n" * 100)
        self.assertEqual((text, len(sigs)), ("text\n", 100))
        # a signature line over 8192 decoded bytes: refused (a stated cap; a padding channel otherwise)
        with self.assertRaises(C.NoteError):
            C.split_note(b"text\n\n\xe2\x80\x94 n " + base64.b64encode(bytes(8193)) + b"\n")
        self.assertEqual(len(C.split_note(b"text\n\n\xe2\x80\x94 n " + base64.b64encode(bytes(8192)) + b"\n")[1]), 1)
        # non-ASCII where base64 is expected: a refusal, never an unhandled exception (round 1, Gemini)
        with self.assertRaises(C.NoteError):
            C.split_note("text\n\n— n ñññññ\n".encode())
        with self.assertRaises(C.NoteError):
            C.parse_checkpoint("o\n1\nñññññññññññññññññññññññññññññññññññññññññññ\n")
        self.assertFalse(C.verify_consistency_b64(1, bytes(32), 2, bytes(32), ["ñ"]))
        with self.assertRaises(C.NoteError):
            C.parse_vkey("n+00000000+ñ")
        # a trailing newline, a control character or a Unicode space in a key name is refused (fullmatch, not match;
        # Go's isValidName: unicode.IsSpace or '+'); 0x7f is allowed, as in Go
        for bad in ("a\n", "a\x01", "a b", "a+b", "a\u00a0b", "a\u2028b", ""):
            with self.assertRaises(C.NoteError):
                C.vkey(bad, C.TYPE_ED25519, bytes(32))
        self.assertTrue(C.vkey("a\x7fb", C.TYPE_ED25519, bytes(32)).startswith("a\x7fb+"))
        # a text made of one empty line is a note (golang.org/x/mod/sumdb/note accepts it; measured 2026-09-19)
        self.assertEqual(C.split_note(b"\n\n\xe2\x80\x94 n AAAAAAAAAA==\n")[0], "\n")
        # the text is separated by the LAST empty line: an internal empty line stays in the text
        text, sigs = C.split_note("line one\n\nline two\n\n— n AAAAAAAAAA==\n".encode())
        self.assertEqual((text, len(sigs)), ("line one\n\nline two\n", 1))
        # the spec's cosignature example line (tlog-cosignature §Example): 4-byte id + 8-byte timestamp + 64-byte sig,
        # timestamp 1679315147 = the "time 1679315147" line the spec shows as the signed message
        _, sigs = C.split_note(("example.com/behind-the-sofa\n20852163\nCsUYapGGPo4dkMgIAUqom/Xajj7h2fB2MPA3j2jxq2I=\n\n"
                                "— example.com/behind-the-sofa Az3grlgtzPICa5OS8npVmf1Myq/5IZniMp+ZJurmRDeOoRDe4URYN7u5/Zhcyv2q1gGzGku9nTo+zyWE+xeMcTOAYQ8=\n"
                                "— witness.example.com/w1 jWbPPwAAAABkGFDLEZMHwSRaJNiIDoe9DYn/zXcrtPHeolMI5OWXEhZCB9dlrDJsX3b2oyin1nPZqhf5nNo0xUe+mbIUBkBIfZ+qnA==\n").encode())
        self.assertEqual((len(sigs[1][1]), struct.unpack(">Q", sigs[1][1][4:12])[0]), (76, 1679315147))
        # vkey ids: exactly 8 hex digits (bytes.fromhex would accept "53 0d 90 3a")
        with self.assertRaises(C.NoteError):
            C.parse_vkey(SPEC_VKEY.replace("530d903a", "53 0d 90 3a"))
        # base64 exactly as Go accepts it (round 8): an extra '=' after a full quantum is malformed there, so here too
        for bad in ("QUJDQUJD=", "QUJDQUJD==", "QUJDQUJD====", "QUJD=QUJD"):
            with self.assertRaises(C.NoteError, msg=bad):
                C.split_note(f"text\n\n— n {bad}\n".encode())
        with self.assertRaises(C.NoteError):
            C.parse_vkey(SPEC_VKEY + "=")
        self.assertEqual(C.split_note(b"text\n\n\xe2\x80\x94 n QUJDQUJDQQ==\n")[1][0][1], b"ABCABCA")
        # vkeys whose base64 contains '+' (found by this suite on 2026-09-19: the first parser split on every '+')
        pub = bytes.fromhex("fb" * 32)
        v = C.vkey("k", C.TYPE_ED25519, pub); self.assertIn("+", v.split("+", 2)[2])
        self.assertEqual(C.parse_vkey(v)[3], pub)

    def test_checkpoint_text_roundtrip_and_strictness(self):
        root = bytes(range(32))
        t = C.checkpoint_text(LOG, 7, root, ["ext 1"])
        self.assertEqual(t, f"{LOG}\n7\n{base64.b64encode(root).decode()}\next 1\n")
        cp = C.parse_checkpoint(t)
        self.assertEqual((cp["origin"], cp["size"], cp["root"], cp["extensions"]), (LOG, 7, root, ["ext 1"]))
        b64 = base64.b64encode(root).decode()
        # non-canonical base64 of 32 bytes: the last character carries 2 unused bits — set one (decodes, but re-encodes differently)
        alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        noncanon = b64[:42] + alphabet[alphabet.index(b64[42]) | 1] + "="
        self.assertEqual(len(base64.b64decode(noncanon)), 32); self.assertNotEqual(noncanon, b64)
        for bad in (f"{LOG}\n07\n{b64}\n", f"{LOG}\n7\n{b64}", f"{LOG}\n7\nAAAA\n", f"{LOG}\n\n{b64}\n",
                    f"{LOG}\n7\n{noncanon}\n",
                    f"{LOG}\n-1\n{b64}\n", f"{LOG}\x01\n7\n{b64}\n", f"{LOG}\n7\n{b64}\n\n"):
            with self.assertRaises(C.NoteError, msg=repr(bad)):
                C.parse_checkpoint(bad)
        for args in ((LOG, -1, root), (LOG, True, root), (LOG, 1, root[:31]), ("", 1, root), ("a\n", 1, root), ("a\x01", 1, root)):
            with self.assertRaises(C.NoteError):
                C.checkpoint_text(*args)
        # emission accepts real-world origins too (Gemini, round 12): the schema-less URL form is only a SHOULD
        self.assertEqual(C.parse_checkpoint(C.checkpoint_text("Armory Drive Prod 2", 1, root))["origin"], "Armory Drive Prod 2")
        # parsing accepts what production logs emit (omniwitness logs.yaml, 2026-09-19): origins with spaces
        for origin in ("go.sum database tree", "rekor.sigstore.dev - 3904496407287907110", "Armory Drive Prod 2"):
            self.assertEqual(C.parse_checkpoint(f"{origin}\n7\n{b64}\n")["origin"], origin)
        # the tree size is a uint64 (the Go reference parses it with ParseUint 64): 2^64-1 parses, 2^64 does not
        self.assertEqual(C.parse_checkpoint(f"{LOG}\n{2**64 - 1}\n{b64}\n")["size"], 2 ** 64 - 1)
        with self.assertRaises(C.NoteError):
            C.parse_checkpoint(f"{LOG}\n{2**64}\n{b64}\n")
        with self.assertRaises(C.NoteError):                   # 6000 digits: refused by the grammar, int() never sees it
            C.parse_checkpoint(f"{LOG}\n{'9' * 6000}\n{b64}\n")
        with self.assertRaises(C.NoteError):
            C.checkpoint_text(LOG, 2 ** 64, root)
        with self.assertRaises(C.NoteError):
            C.checkpoint_text(LOG, 1, root, ["bad\nline"])


@unittest.skipUnless(HAVE_CRYPTO, "cryptography assente")
class TestSignCosign(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.lk = os.path.join(self.tmp, "log.key"); signer.keygen(self.lk); self.ls = C.load_seed_hex(self.lk)
        self.wk = os.path.join(self.tmp, "w.key"); signer.keygen(self.wk); self.ws = C.load_seed_hex(self.wk)
        self.LV = C.vkey(LOG, C.TYPE_ED25519, C.pubkey_from_seed(self.ls))
        self.WV = C.vkey("witness.example/w1", C.TYPE_COSIG_V1, C.pubkey_from_seed(self.ws))
        self.text = C.checkpoint_text(LOG, 3, hashlib.sha256(b"root").digest())

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_sign_verify_and_key_substitution(self):
        note = C.sign_note(self.text, LOG, self.ls)
        self.assertTrue(note.startswith(self.text.encode() + b"\n\xe2\x80\x94 " + LOG.encode() + b" "))
        self.assertEqual(C.verify_note(note, [self.LV])["stato"], "OK")
        # another key under the SAME name: different key id → the line is ignored → no known key → NON_VALIDA
        ok = os.path.join(self.tmp, "other.key"); signer.keygen(ok); other = C.load_seed_hex(ok)
        OV = C.vkey(LOG, C.TYPE_ED25519, C.pubkey_from_seed(other))
        r = C.verify_note(note, [OV])
        self.assertEqual((r["stato"], r["ignored"], r["motivo"]), ("NON_VALIDA", 1, "no signature from a known key"))
        # a forged line that REUSES the trusted key id with another key's signature → known key fails → NON_VALIDA
        _, sigs = C.split_note(note)
        kid = sigs[0][1][:4]
        forged = C.sign_note(self.text, LOG, other)
        _, fs = C.split_note(forged)
        line = f"— {LOG} {base64.b64encode(kid + fs[0][1][4:]).decode()}\n"
        r = C.verify_note((self.text + "\n" + line).encode(), [self.LV])
        self.assertEqual(r["stato"], "NON_VALIDA"); self.assertIn("does not verify", r["motivo"])
        # the log vkey given as a cosigner vkey (type 0x04): different key id → ignored, not accepted
        WRONG = C.vkey(LOG, C.TYPE_COSIG_V1, C.pubkey_from_seed(self.ls))
        self.assertEqual(C.verify_note(note, [WRONG])["stato"], "NON_VALIDA")

    def test_verify_note_parity_with_go(self):
        note = C.sign_note(self.text, LOG, self.ls)
        _, sigs = C.split_note(note)
        line = note[len(self.text) + 1:]
        # the same line twice: counted once; a DIFFERENT line of a known key is verified (signed-note: "MUST verify"),
        # so a bogus repeat after a good one is NON_VALIDA here — Go drops repeats before verifying (declared divergence)
        r = C.verify_note(note + line, [self.LV]); self.assertEqual((r["stato"], len(r["verified"])), ("OK", 1))
        bogus = f"— {LOG} {base64.b64encode(sigs[0][1][:4] + bytes(64)).decode()}\n".encode()
        self.assertEqual(C.verify_note(note + bogus, [self.LV])["stato"], "NON_VALIDA")
        self.assertEqual(C.verify_note(self.text.encode() + b"\n" + bogus + line, [self.LV])["stato"], "NON_VALIDA")
        # the REAL Rekor v1 vkey (ECDSA P-256, 0x02): parsed with the DER-SPKI key id, trusted, and not matching our note
        name, kid, typ, _ = C.parse_vkey(REKOR_VKEY)
        self.assertEqual((name, kid.hex(), typ), ("rekor.sigstore.dev", "c0d23d6a", 0x02))
        r = C.verify_note(note, [REKOR_VKEY, self.LV]); self.assertEqual((r["stato"], r["ignored_vkeys"]), ("OK", 0))
        self.assertEqual(C.verify_note(note, [REKOR_VKEY])["stato"], "NON_VALIDA")
        # a vkey of a type nobody here verifies (RFC 6962 THS, 0x05): ignored, not an exception
        ths = f"ct.example/log+00000000+{base64.b64encode(bytes([5]) + bytes(65)).decode()}"
        r = C.verify_note(note, [ths, self.LV]); self.assertEqual((r["stato"], r["ignored_vkeys"]), ("OK", 1))
        with self.assertRaisesRegex(C.NoteError, "unsupported vkey type 0x05"):
            C.parse_vkey(ths)
        with self.assertRaises(C.NoteError):                   # a cosigner key is never a log key
            W.witness_cosign(os.path.join(self.tmp, "x.json"), note, [self.WV], "w", self.ws, None, T0)
        # a vkey whose declared id does not match its key is refused as a vkey
        _, kid1, _, pub1 = C.parse_vkey(self.LV)
        forged = f"{LOG}+{kid1.hex()}+{base64.b64encode(bytes([1]) + bytes(32)).decode()}"
        with self.assertRaises(C.NoteError):
            C.parse_vkey(forged)
        # two DIFFERENT valid keys under one name with the SAME 4-byte id (a real collision, found by brute force on
        # 2026-09-19 after 55 460 keys: seeds sha256("cryptovalid-collision-search-" || i) for i = 26508 and 55460):
        # both parse, together they are ambiguous → error, as Go's VerifierList ("ambiguous key")
        cname = "collide.example/k"
        seeds = [hashlib.sha256(b"cryptovalid-collision-search-" + i.to_bytes(4, "big")).digest() for i in (26508, 55460)]
        pubs = [C.pubkey_from_seed(sd) for sd in seeds]
        self.assertNotEqual(pubs[0], pubs[1]); self.assertEqual(C.key_id(cname, 1, pubs[0]), C.key_id(cname, 1, pubs[1]))
        v1, v2 = (C.vkey(cname, C.TYPE_ED25519, pb) for pb in pubs)
        cnote = C.sign_note(self.text, cname, seeds[0])
        self.assertEqual(C.verify_note(cnote, [v1])["stato"], "OK")
        with self.assertRaisesRegex(C.NoteError, "ambiguous key"):
            C.verify_note(cnote, [v1, v2])
        # the same vkey twice is fine
        self.assertEqual(C.verify_note(note, [self.LV, self.LV])["stato"], "OK")
        # timestamp 2^63-1 is the spec's maximum; a cosignature carrying 2^63 (validly SIGNED with the high bit set) is
        # refused by us as the spec says ("MUST NOT exceed 2^63 - 1"); Go's library does not check it — a declared divergence
        cs = C.cosign_v1(note, "witness.example/w1", self.ws, 2 ** 63 - 1)
        self.assertEqual(C.verify_note(cs, [self.WV])["verified"][0]["timestamp"], 2 ** 63 - 1)
        with self.assertRaises(C.NoteError):
            C.cosign_v1(note, "w", self.ws, 2 ** 63)
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        big = 2 ** 63
        sig = Ed25519PrivateKey.from_private_bytes(self.ws).sign(f"cosignature/v1\ntime {big}\n".encode() + self.text.encode())
        _, kid, _, _ = C.parse_vkey(self.WV)
        line = f"— witness.example/w1 {base64.b64encode(kid + struct.pack('>Q', big) + sig).decode()}\n".encode()
        self.assertEqual(C.verify_note(note + line, [self.WV])["stato"], "NON_VALIDA")

    def test_emission_refuses_bad_names(self):
        # a signer/cosigner name with a space would produce a line no parser reads: refused at emission (round 2);
        # a name over 255 bytes is refused too (transparency-dev formats refuses such a cosigner vkey, round 11)
        self.assertTrue(C.vkey("n" * 255, C.TYPE_COSIG_V1, bytes(32)))
        with self.assertRaises(C.NoteError):
            C.vkey("n" * 256, C.TYPE_COSIG_V1, bytes(32))
        long_v = f"{'n' * 256}+{C.key_id('n' * 256, C.TYPE_COSIG_V1, bytes(32)).hex()}+{base64.b64encode(bytes([4]) + bytes(32)).decode()}"
        with self.assertRaises(C.NoteError):
            C.parse_vkey(long_v)
        for bad in ("bad name", "a+b", "", "x\n", "n" * 256):
            with self.assertRaises(C.NoteError):
                C.sign_note(self.text, bad, self.ls)
            with self.assertRaises(C.NoteError):
                C.cosign_v1(C.sign_note(self.text, LOG, self.ls), bad, self.ws, T0)

    def test_sign_text_with_blank_line_roundtrips(self):
        # the separator is the LAST empty line (signed-note): a text with empty lines signs and verifies intact
        n = C.sign_note("a\n\nb\n", LOG, self.ls)
        r = C.verify_note(n, [self.LV]); self.assertEqual((r["stato"], r["text"]), ("OK", "a\n\nb\n"))
        with self.assertRaises(C.NoteError):
            C.sign_note("no newline", LOG, self.ls)
        with self.assertRaises(C.NoteError):
            C.sign_note("ctl\x01\n", LOG, self.ls)

    def test_cosign_v1_roundtrip_timestamp_bound(self):
        note = C.sign_note(self.text, LOG, self.ls)
        cs = C.cosign_v1(note, "witness.example/w1", self.ws, T0)
        r = C.verify_note(cs, [self.LV, self.WV])
        self.assertEqual(r["stato"], "OK")
        self.assertEqual(r["verified"][1], {"name": "witness.example/w1", "type": C.TYPE_COSIG_V1, "timestamp": T0})
        # the 8-byte timestamp is inside the signed message: +1 second → NON_VALIDA
        _, sigs = C.split_note(cs)
        raw = sigs[1][1]; kid, ts, sig = raw[:4], struct.unpack(">Q", raw[4:12])[0], raw[12:]
        self.assertEqual(ts, T0)
        bad = f"— witness.example/w1 {base64.b64encode(kid + struct.pack('>Q', T0 + 1) + sig).decode()}\n"
        r2 = C.verify_note(note + bad.encode(), [self.LV, self.WV])
        self.assertEqual(r2["stato"], "NON_VALIDA")
        # positive control: the untouched line still verifies alone
        self.assertEqual(C.verify_note(cs, [self.WV])["stato"], "OK")
        # a cosignature on a non-checkpoint text is refused on the signer side
        with self.assertRaises(C.NoteError):
            C.cosign_v1(C.sign_note("just text\n", LOG, self.ls), "w", self.ws, T0)
        for ts in (-1, 0, 2 ** 63, True, 1.5):     # 0: tlog-witness "MUST NOT be zero"
            with self.assertRaises(C.NoteError):
                C.cosign_v1(note, "w", self.ws, ts)
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        sig0 = Ed25519PrivateKey.from_private_bytes(self.ws).sign(b"cosignature/v1\ntime 0\n" + self.text.encode())
        _, kid, _, _ = C.parse_vkey(self.WV)
        zero = f"— witness.example/w1 {base64.b64encode(kid + struct.pack('>Q', 0) + sig0).decode()}\n".encode()
        self.assertEqual(C.verify_note(note + zero, [self.WV])["stato"], "NON_VALIDA")

    def test_cli(self):
        led = os.path.join(self.tmp, "l.jsonl"); _write(led, _ledger(4))
        out = os.path.join(self.tmp, "cp.note")
        r = subprocess.run([sys.executable, os.path.join(HERE, "cryptovalid_checkpoint.py"), "sign", led, "--origin", LOG,
                            "--key", self.lk, "--out", out], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        v = subprocess.run([sys.executable, os.path.join(HERE, "cryptovalid_checkpoint.py"), "verify", out, "--vkey", self.LV],
                           capture_output=True, text=True)
        self.assertEqual(v.returncode, 0, v.stdout + v.stderr); self.assertEqual(json.loads(v.stdout)["stato"], "OK")
        with open(out, "rb") as f:
            note = f.read()
        with open(out, "wb") as f:
            f.write(note.replace(b"\n4\n", b"\n5\n"))
        v = subprocess.run([sys.executable, os.path.join(HERE, "cryptovalid_checkpoint.py"), "verify", out, "--vkey", self.LV],
                           capture_output=True, text=True)
        self.assertEqual(v.returncode, 1); self.assertEqual(json.loads(v.stdout)["stato"], "NON_VALIDA")
        k = subprocess.run([sys.executable, os.path.join(HERE, "cryptovalid_checkpoint.py"), "vkey", "--key", self.wk,
                            "--name", "witness.example/w1", "--cosigner"], capture_output=True, text=True)
        self.assertEqual(k.stdout.strip(), self.WV)


@unittest.skipUnless(HAVE_CRYPTO, "cryptography assente")
class TestLedgerCheckpoint(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.l5 = os.path.join(self.tmp, "l5.jsonl"); self.e8 = _ledger(8); _write(self.l5, self.e8[:5])
        self.l8 = os.path.join(self.tmp, "l8.jsonl"); _write(self.l8, self.e8)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_root_is_rfc6962_mth_of_canonical_entries(self):
        text, leaves = C.ledger_checkpoint(self.l8, LOG)
        cp = C.parse_checkpoint(text)
        self.assertEqual(cp["size"], 8)
        self.assertEqual(cp["root"], M.mth(M.leaves_from_ledger(self.l8)))
        self.assertEqual(leaves, M.leaves_from_ledger(self.l8))
        # the leaf is the canonical entry WITHOUT self_hash/signature/signer: changing those leaves the root unchanged
        # (a ledger signed with signer.py has the same checkpoint as the bare one); changing a data byte changes it
        e = dict(self.e8[0]); e["self_hash"] = "0" * 64; e["signature"] = "deadbeef"; e["signer"] = "x"
        same = os.path.join(self.tmp, "same.jsonl"); _write(same, [e] + self.e8[1:])
        self.assertEqual(C.parse_checkpoint(C.ledger_checkpoint(same, LOG)[0])["root"], cp["root"])
        e = dict(self.e8[0]); e["data"] = {"i": 0, "s": "b"}
        alt = os.path.join(self.tmp, "alt.jsonl"); _write(alt, [e] + self.e8[1:])
        self.assertNotEqual(C.parse_checkpoint(C.ledger_checkpoint(alt, LOG)[0])["root"], cp["root"])

    def test_consistency_proof_roundtrip_and_refusals(self):
        t5, l5 = C.ledger_checkpoint(self.l5, LOG); t8, l8 = C.ledger_checkpoint(self.l8, LOG)
        r5, r8 = C.parse_checkpoint(t5)["root"], C.parse_checkpoint(t8)["root"]
        proof = C.consistency_proof_b64(l8, 5)
        self.assertTrue(C.verify_consistency_b64(5, r5, 8, r8, proof))
        self.assertTrue(C.verify_consistency_b64(8, r8, 8, r8, []))
        self.assertFalse(C.verify_consistency_b64(8, r8, 8, r5, []))
        self.assertFalse(C.verify_consistency_b64(5, r5, 8, r8, []))                    # no proof
        self.assertFalse(C.verify_consistency_b64(5, r5, 8, r8, proof[:-1]))            # truncated
        self.assertFalse(C.verify_consistency_b64(5, r5, 8, r8, ["!!"] + proof[1:]))   # not base64
        self.assertFalse(C.verify_consistency_b64(5, r5, 8, r8, ["AAAA"] + proof[1:])) # 3-byte hash
        self.assertFalse(C.verify_consistency_b64(8, r8, 5, r5, proof))                # backwards
        self.assertFalse(C.verify_consistency_b64(0, r5, 8, r8, proof))
        # a ledger forked AFTER entry 5 still extends the 5-entry tree (consistent); one forked at entry 4 does not
        fork = os.path.join(self.tmp, "fork.jsonl"); _write(fork, self.e8[:5] + _ledger(8, "z")[5:])
        tf, lf = C.ledger_checkpoint(fork, LOG); rf = C.parse_checkpoint(tf)["root"]
        self.assertTrue(C.verify_consistency_b64(5, r5, 8, rf, C.consistency_proof_b64(lf, 5)))  # fork after 5 IS consistent with 5
        fork2 = os.path.join(self.tmp, "fork2.jsonl"); _write(fork2, self.e8[:4] + _ledger(8, "z")[4:])
        tf2, lf2 = C.ledger_checkpoint(fork2, LOG); rf2 = C.parse_checkpoint(tf2)["root"]
        self.assertFalse(C.verify_consistency_b64(5, r5, 8, rf2, C.consistency_proof_b64(lf2, 5)))  # fork at 4 is NOT
        with self.assertRaises(C.NoteError):
            C.consistency_proof_b64(l8, 0)
        with self.assertRaises(C.NoteError):
            C.consistency_proof_b64(l8, 9)


@unittest.skipUnless(HAVE_CRYPTO, "cryptography assente")
class TestWitness(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.lk = os.path.join(self.tmp, "log.key"); signer.keygen(self.lk); self.ls = C.load_seed_hex(self.lk)
        self.w1k = os.path.join(self.tmp, "w1.key"); signer.keygen(self.w1k); self.w1 = C.load_seed_hex(self.w1k)
        self.w2k = os.path.join(self.tmp, "w2.key"); signer.keygen(self.w2k); self.w2 = C.load_seed_hex(self.w2k)
        self.LV = C.vkey(LOG, C.TYPE_ED25519, C.pubkey_from_seed(self.ls))
        self.W1V = C.vkey("witness.example/w1", C.TYPE_COSIG_V1, C.pubkey_from_seed(self.w1))
        self.W2V = C.vkey("witness.example/w2", C.TYPE_COSIG_V1, C.pubkey_from_seed(self.w2))
        self.e8 = _ledger(8)
        self.l5 = os.path.join(self.tmp, "l5.jsonl"); _write(self.l5, self.e8[:5])
        self.l8 = os.path.join(self.tmp, "l8.jsonl"); _write(self.l8, self.e8)
        self.fork = os.path.join(self.tmp, "fork.jsonl"); _write(self.fork, self.e8[:4] + _ledger(8, "z")[4:])
        self.st1 = os.path.join(self.tmp, "w1.json"); self.st2 = os.path.join(self.tmp, "w2.json")
        self.t5, self.leaves5 = C.ledger_checkpoint(self.l5, LOG); self.n5 = C.sign_note(self.t5, LOG, self.ls)
        self.t8, self.leaves8 = C.ledger_checkpoint(self.l8, LOG); self.n8 = C.sign_note(self.t8, LOG, self.ls)
        self.tf, self.leavesf = C.ledger_checkpoint(self.fork, LOG); self.nf = C.sign_note(self.tf, LOG, self.ls)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _w1(self, note, proof=None, ts=T0):
        return W.witness_cosign(self.st1, note, self.LV, "witness.example/w1", self.w1, proof, ts)

    def test_first_checkpoint_tofu_then_extend_with_proof(self):
        r = self._w1(self.n5)
        self.assertEqual((r["stato"], r["origin"], r["size"], r["evidenza"]), ("COSIGNED", LOG, 5, None))
        v = C.verify_note(r["note"], [self.LV, self.W1V])
        self.assertEqual(v["stato"], "OK"); self.assertEqual(v["verified"][1]["timestamp"], T0)
        with open(self.st1) as f:
            st = json.load(f)
        self.assertEqual(st["origins"][LOG]["size"], 5)
        self.assertFalse(os.path.exists(self.st1 + ".tmp"))
        # the cross-process lock: while another process holds <state>.lock, cosign waits (measured with a timeout)
        if W.fcntl is not None:
            import subprocess as sp
            holder = sp.Popen([sys.executable, "-c", "import fcntl,os,sys,time; fd=os.open(sys.argv[1],os.O_RDWR|os.O_CREAT); "
                               "fcntl.flock(fd,fcntl.LOCK_EX); print('held',flush=True); time.sleep(1.5)", self.st1 + ".lock"], stdout=sp.PIPE)
            self.assertEqual(holder.stdout.readline().strip(), b"held")
            t0 = time.monotonic(); r = self._w1(self.n5, ts=T0 + 20); waited = time.monotonic() - t0
            holder.wait(); holder.stdout.close()
            self.assertEqual(r["stato"], "COSIGNED"); self.assertGreater(waited, 0.5)
        # same checkpoint again (same size, same root, no proof): cosigned again, same size stored, new timestamp;
        # a caller timestamp OLDER than the stored one is refused (the state never moves backwards in time)
        r = self._w1(self.n5, ts=T0 + 30)
        self.assertEqual(r["stato"], "COSIGNED")
        with self.assertRaises(C.NoteError):
            self._w1(self.n5, ts=T0 + 10)
        # …and nothing was written before the refusal: a fork pending, an older timestamp with a valid proof → the
        # proof record is NOT written (round 13: it was written and then re-written on the retry)
        self.assertEqual(self._w1(self.nf, ts=T0 + 31)["evidenza"]["tipo"], "unproven-extension")
        with self.assertRaises(C.NoteError):
            self._w1(self.n8, proof=C.consistency_proof_b64(self.leaves8, 5), ts=T0 + 10)
        self.assertFalse(os.path.exists(self.st1 + ".evidence.jsonl"))
        r = self._w1(self.n8, proof=C.consistency_proof_b64(self.leaves8, 5), ts=T0 + 40); self.assertEqual(r["stato"], "COSIGNED")
        with open(self.st1 + ".evidence.jsonl") as f:
            self.assertEqual(len(f.readlines()), 1)
        os.remove(self.st1 + ".evidence.jsonl"); os.remove(self.st1); os.remove(self.st1 + ".cosigned.jsonl")
        r = self._w1(self.n5); self.assertEqual(r["stato"], "COSIGNED")
        # same size with a non-empty proof is malformed → 422, no evidence (round 1, Opus: a client error is not evidence)
        r = self._w1(self.n5, proof=["AAAA"])
        self.assertEqual((r["stato"], r["http_status"], r["evidenza"]), ("REFUSED", 422, None))
        # extension 5→8 without proof: refused, both checkpoints returned but NOT as proof, state still 5
        r = self._w1(self.n8)
        self.assertEqual((r["stato"], r["evidenza"]["tipo"], r["evidenza"]["prova"]), ("REFUSED", "unproven-extension", False))
        # a wrong (but well-formed) proof for 5→8: the same, 422
        r = self._w1(self.n8, proof=C.consistency_proof_b64(self.leaves8, 5)[:-1])
        self.assertEqual((r["http_status"], r["evidenza"]["tipo"]), (422, "unproven-extension"))
        with open(self.st1) as f:
            self.assertEqual(json.load(f)["origins"][LOG]["size"], 5)
        # with the proof: cosigned, state 8
        r = self._w1(self.n8, proof=C.consistency_proof_b64(self.leaves8, 5), ts=T0 + 60)
        self.assertEqual(r["stato"], "COSIGNED", r["motivo"])
        with open(self.st1) as f:
            self.assertEqual(json.load(f)["origins"][LOG]["size"], 8)

    def test_split_view_and_rollback_produce_evidence(self):
        self.assertEqual(self._w1(self.n8, proof=None)["stato"], "COSIGNED")   # TOFU at 8
        # a fork at 8: same size, different root — both notes are log-signed and both verify: that IS the evidence
        r = self._w1(self.nf, proof=C.consistency_proof_b64(self.leavesf, 8))
        self.assertEqual(r["stato"], "REFUSED"); self.assertEqual(r["motivo"], "equivocation: same size, different root")
        ev = r["evidenza"]
        self.assertEqual((ev["tipo"], ev["prova"]), ("split-view", True))
        a, b = C.verify_note(ev["precedente"].encode(), [self.LV]), C.verify_note(ev["presentato"].encode(), [self.LV])
        self.assertEqual((a["stato"], b["stato"]), ("OK", "OK"))
        ca, cb = C.parse_checkpoint(a["text"]), C.parse_checkpoint(b["text"])
        self.assertEqual((ca["origin"], ca["size"]), (cb["origin"], cb["size"])); self.assertNotEqual(ca["root"], cb["root"])
        # rollback 8 → 5
        r = self._w1(self.n5)
        self.assertEqual(r["stato"], "REFUSED"); self.assertEqual((r["evidenza"]["tipo"], r["evidenza"]["prova"]), ("rollback", False))
        self.assertIn("rollback: size 5 < last cosigned 8", r["motivo"])
        # the same rollback replayed 5 times with padding lines from unknown keys: returned each time (padding
        # stripped from `presentato`), never persisted as notes — refusals that are not proof only bump a counter
        # and a bounded ring in the state (round 4: a client replaying the log's public history must not grow anything)
        pad = self.n5 + "".join(f"— pad{i} AAAAAAAAAA==\n" for i in range(50)).encode()
        for i in range(5):
            r = self._w1(pad, ts=T0 + i); self.assertEqual(r["evidenza"]["tipo"], "rollback"); self.assertNotIn("pad0", r["evidenza"]["presentato"])
        with open(self.st1) as f:
            ring = json.load(f)["refusals"][LOG]
        self.assertEqual((ring["count"], len(ring["last"])), (1, 1)); self.assertNotIn("note", ring["last"][0])   # one distinct rollback
        # a SECOND log-signed root for size 5: this witness never cosigned size 5 (it started at 8) but it remembers
        # the first root in its refusals ring → `split-view-unkept` (the earlier root, not its note), prova False
        alt5 = C.sign_note(C.checkpoint_text(LOG, 5, hashlib.sha256(b"other root").digest()), LOG, self.ls)
        for i in range(3):
            r = self._w1(alt5, ts=T0 + 10 + i); self.assertEqual((r["evidenza"]["tipo"], r["evidenza"]["prova"]), ("split-view-unkept", False))
        # a first checkpoint padded with 99 unknown-key lines, then a fork: the stored `precedente` is text + log line +
        # our line (unknown lines stripped), so both notes of the split-view pair open — here and in Go (TestGoOracle)
        st4 = os.path.join(self.tmp, "w1c.json")
        padded8 = self.n8 + "".join(f"— pad{i} AAAAAAAAAA==\n" for i in range(98)).encode()
        r = W.witness_cosign(st4, padded8, self.LV, "witness.example/w1", self.w1, None, T0)
        self.assertEqual(r["stato"], "COSIGNED"); self.assertEqual(len(C.split_note(r["note"])[1]), 100)
        r = W.witness_cosign(st4, self.nf, self.LV, "witness.example/w1", self.w1, None, T0 + 1)
        self.assertEqual(r["evidenza"]["tipo"], "split-view")
        self.assertEqual(len(C.split_note(r["evidenza"]["precedente"].encode())[1]), 2)
        self.assertEqual(C.verify_note(r["evidenza"]["precedente"].encode(), [self.LV, self.W1V])["stato"], "OK")
        # the evidence file: the fork at 8 (proof, two log-signed notes) and the half record at 5 (root only, once)
        with open(self.st1 + ".evidence.jsonl") as f:
            evs = [json.loads(l) for l in f]
        self.assertEqual([(e["tipo"], e["prova"], e["size_presentato"]) for e in evs], [("split-view", True, 8), ("split-view-unkept", False, 5)])
        evs = evs[:1]
        for e in evs:
            self.assertEqual({C.verify_note(e[k].encode(), [self.LV])["stato"] for k in ("precedente", "presentato")}, {"OK"})
        # the state is untouched by refusals
        with open(self.st1) as f:
            self.assertEqual(json.load(f)["origins"][LOG]["size"], 8)
        # a second, independent witness that saw the fork first refuses the HONEST tree: witnesses are parties
        r2 = W.witness_cosign(self.st2, self.nf, self.LV, "witness.example/w2", self.w2, None, T0)
        self.assertEqual(r2["stato"], "COSIGNED")
        r2 = W.witness_cosign(self.st2, self.n8, self.LV, "witness.example/w2", self.w2, None, T0)
        self.assertEqual((r2["stato"], r2["evidenza"]["tipo"]), ("REFUSED", "split-view"))

    def test_split_view_found_on_every_path(self):
        """Round 4 (Opus): the pair of log-signed roots at one size is proof wherever the witness meets it — a
        refused root later contradicted by a cosigned one, a cosigned root later contradicted by a refused one at a
        size the witness has moved past, and a replay of the refused root against the cosigned one."""
        st = os.path.join(self.tmp, "w4.json"); W_ = lambda note, proof=None, ts=T0: W.witness_cosign(st, note, self.LV, "witness.example/w1", self.w1, proof, ts)
        self.assertEqual(W_(self.n5)["stato"], "COSIGNED")
        # E1: fork-8 without proof (refused, indexed) → honest 8 with proof (COSIGNED): the pair must be recorded now
        self.assertEqual(W_(self.nf)["evidenza"]["tipo"], "unproven-extension")
        self.assertEqual(W_(self.n8, C.consistency_proof_b64(self.leaves8, 5), T0 + 1)["stato"], "COSIGNED")
        with open(st + ".evidence.jsonl") as f:
            evs = [json.loads(l) for l in f]
        self.assertEqual([(e["tipo"], e["prova"], e["size_presentato"]) for e in evs], [("split-view", True, 8)])
        self.assertEqual({C.parse_checkpoint(C.verify_note(evs[0][k].encode(), [self.LV])["text"])["root"] for k in ("precedente", "presentato")},
                         {C.parse_checkpoint(self.tf)["root"], C.parse_checkpoint(self.t8)["root"]})
        with open(st) as f:
            self.assertEqual(json.load(f)["pending"].get(LOG, {}), {})     # the pending root at 8 was consumed
        # a future root presented with the WRONG old size (the discovery request "old 0"): 409 for the client, but the
        # root enters `pending` and a second root at that size with "old 0" is proof (round 6, Opus: the 409 gate came first)
        c70 = C.sign_note(C.checkpoint_text(LOG, 70, hashlib.sha256(b"c70").digest()), LOG, self.ls)
        d70 = C.sign_note(C.checkpoint_text(LOG, 70, hashlib.sha256(b"d70").digest()), LOG, self.ls)
        r = W.witness_cosign(st, c70, self.LV, "witness.example/w1", self.w1, None, T0 + 2, old_size=0)
        self.assertEqual((r["http_status"], r["evidenza"]), (409, None))
        r = W.witness_cosign(st, d70, self.LV, "witness.example/w1", self.w1, None, T0 + 2, old_size=0)
        self.assertEqual((r["http_status"], r["evidenza"]["tipo"], r["evidenza"]["prova"]), (409, "split-view", True))
        # many roots at one pending size: ONE proof per request (a log cannot buy a record and an fsync per pair)
        for i in range(5):
            W.witness_cosign(st, C.sign_note(C.checkpoint_text(LOG, 70, hashlib.sha256(b"x%d" % i).digest()), LOG, self.ls),
                             self.LV, "witness.example/w1", self.w1, None, T0 + 2, old_size=0)
        with open(st + ".evidence.jsonl") as f:
            self.assertEqual(len(f.readlines()), 2 + 5)
        # E9: the fork replayed against the cosigned 8: returned as proof, not recorded twice (7 records so far: the
        # size-8 pair and the size-70 pairs)
        r = W_(self.nf, None, T0 + 2); self.assertEqual((r["evidenza"]["tipo"], r["evidenza"]["prova"]), ("split-view", True))
        with open(st + ".evidence.jsonl") as f:
            self.assertEqual(len(f.readlines()), 7)
        # E2: a second log-signed root at size 5 — a size this witness COSIGNED and moved past: the protocol answer is
        # a rollback, the evidence returned AND recorded is the split-view proof from the cosigned history
        alt5 = C.sign_note(C.checkpoint_text(LOG, 5, hashlib.sha256(b"alt5").digest()), LOG, self.ls)
        r = W_(alt5, None, T0 + 3); self.assertEqual((r["evidenza"]["tipo"], r["evidenza"]["prova"], r["motivo"][:8]), ("split-view", True, "rollback"))
        with open(st + ".evidence.jsonl") as f:
            evs = [json.loads(l) for l in f]
        self.assertEqual([(e["tipo"], e["prova"], e["size_presentato"]) for e in evs][7:], [("split-view", True, 5)])
        self.assertEqual(C.parse_checkpoint(C.verify_note(evs[7]["precedente"].encode(), [self.LV])["text"])["root"], C.parse_checkpoint(self.t5)["root"])
        self.assertEqual(C.verify_note(evs[7]["precedente"].encode(), [self.LV, self.W1V])["stato"], "OK")   # our own cosignature is there
        # a third root at size 5: the FULL cosigned note is preferred over the root-only ring entry → a full pair
        alt5b = C.sign_note(C.checkpoint_text(LOG, 5, hashlib.sha256(b"alt5b").digest()), LOG, self.ls)
        r = W_(alt5b, None, T0 + 3); self.assertEqual((r["evidenza"]["tipo"], r["evidenza"]["prova"]), ("split-view", True))
        self.assertEqual(C.parse_checkpoint(C.verify_note(r["evidenza"]["precedente"].encode(), [self.LV])["text"])["root"],
                         C.parse_checkpoint(self.t5)["root"])   # the cosigned note (full), not the root-only ring entry
        # a fresh root at a size this witness never cosigned nor holds (7): rollback, no proof — declared limit
        alt7 = C.sign_note(C.checkpoint_text(LOG, 7, hashlib.sha256(b"alt7").digest()), LOG, self.ls)
        self.assertEqual(W_(alt7, None, T0 + 3)["evidenza"]["prova"], False)
        with open(st + ".evidence.jsonl") as f:
            self.assertEqual(len(f.readlines()), 9)
        # the history file has exactly the two checkpoints cosigned (a re-cosign of the same one adds nothing)
        self.assertEqual(W_(self.n8, None, T0 + 4)["stato"], "COSIGNED")
        with open(st + ".cosigned.jsonl") as f:
            self.assertEqual([json.loads(l)["size"] for l in f], [5, 8])
        # two log-signed roots at one FUTURE size, both refused without proof: the second one IS the proof (round 5)
        a60 = C.sign_note(C.checkpoint_text(LOG, 60, hashlib.sha256(b"a60").digest()), LOG, self.ls)
        b60 = C.sign_note(C.checkpoint_text(LOG, 60, hashlib.sha256(b"b60").digest()), LOG, self.ls)
        self.assertEqual(W_(a60, None, T0 + 5)["evidenza"]["prova"], False)
        r = W_(b60, None, T0 + 6); self.assertEqual((r["evidenza"]["tipo"], r["evidenza"]["prova"]), ("split-view", True))
        with open(st + ".evidence.jsonl") as f:
            self.assertEqual([json.loads(l)["size_presentato"] for l in f][-1], 60)
        # replaying the log's public FUTURE (sizes 9..300 without proof): the pending ring stays at 100 notes, the
        # state file stops growing (round 5, Opus: the first version kept every note)
        with open(st + ".evidence.jsonl") as f:
            before = len(f.readlines())
        sizes = []
        for sz in range(9, 300):
            W_(C.sign_note(C.checkpoint_text(LOG, sz, hashlib.sha256(str(sz).encode()).digest()), LOG, self.ls), None, T0 + 10)
            if sz in (108, 200, 299):
                with open(st) as f:
                    stt = json.load(f)
                sizes.append((sum(len(r) for r in stt["pending"][LOG].values()), os.path.getsize(st)))
        self.assertEqual([n for n, _ in sizes], [100, 100, 100]); self.assertLess(abs(sizes[2][1] - sizes[1][1]), 2000)
        with open(st) as f:
            self.assertNotIn("9", json.load(f)["pending"][LOG])
        # the evidence file: exactly 2 more records — the third root at size 60 (against one of a60/b60) and at size 70
        # (one pair per request); every other size was fresh → nothing (the README says exactly this)
        with open(st + ".evidence.jsonl") as f:
            self.assertEqual(len(f.readlines()), before + 2)
        # the byte bound: 20 log-signed notes with 115 extension lines of 8 KiB each — none is kept (above 16 KiB); then
        # 60 notes with 5000 four-byte characters (5 000 chars = 20 000 BYTES > 16 KiB: the bound counts bytes, round 7) — none
        # kept either; the state stays small
        big = ["x" * 8000] * 115
        for sz in range(400, 420):
            W_(C.sign_note(C.checkpoint_text(LOG, sz, hashlib.sha256(str(sz).encode()).digest(), big), LOG, self.ls), None, T0 + 11)
        for sz in range(500, 560):
            W_(C.sign_note(C.checkpoint_text(LOG, sz, hashlib.sha256(str(sz).encode()).digest(), ["\U0001F600" * 5000]), LOG, self.ls), None, T0 + 12)
        self.assertLess(os.path.getsize(st), 200_000)
        with open(st) as f:
            self.assertLessEqual(sum(len(n.encode()) for r in json.load(f)["pending"][LOG].values() for n in r.values() if n), 256 * 1024)
        # an oversized first root at a size, then a small conflicting one: not silently lost — a `split-view-unkept`
        # record with the earlier ROOT (the note was not kept), prova False, stated (round 7, Sonnet)
        small559 = C.sign_note(C.checkpoint_text(LOG, 559, hashlib.sha256(b"small").digest()), LOG, self.ls)
        r = W_(small559, None, T0 + 13)
        self.assertEqual((r["evidenza"]["tipo"], r["evidenza"]["prova"], r["evidenza"]["precedente"]), ("split-view-unkept", False, None))
        with open(st + ".evidence.jsonl") as f:
            last = json.loads(f.readlines()[-1])
        self.assertEqual((last["tipo"], last["precedente_root_b64"]), ("split-view-unkept", base64.b64encode(hashlib.sha256(b"559").digest()).decode()))
        # a malformed pending index in the state is a NoteError, not an AttributeError
        with open(st) as f:
            bad = json.load(f)
        bad["pending"] = {LOG: []}
        with open(st, "w") as f:
            json.dump(bad, f)
        with self.assertRaises(C.NoteError):
            W_(self.nf)
        bad["pending"] = []
        with open(st, "w") as f:
            json.dump(bad, f)
        with self.assertRaises(C.NoteError):
            W_(self.nf)

    def test_state_written_once_per_request_and_passed_pending_kept(self):
        # every request writes the state file at most once (round 9: an extension without proof wrote it twice)
        st = os.path.join(self.tmp, "w9b.json"); W_ = lambda note, proof=None, ts=T0, old=None: W.witness_cosign(st, note, self.LV, "witness.example/w1", self.w1, proof, ts, old_size=old)
        counts = []
        real = W._save_state
        def spy(path, state):
            counts.append(1); real(path, state)
        with mock.patch.object(W, "_save_state", spy):
            W_(self.n5); tofu = len(counts); counts.clear()
            W_(self.n8); unproven = len(counts); counts.clear()
            W_(self.n8, C.consistency_proof_b64(self.leaves8, 5)[:-1]); badproof = len(counts); counts.clear()
            W_(self.n5, ts=T0 + 1); recosign = len(counts); counts.clear()
            W_(self.nf, old=0, ts=T0 + 2); disc = len(counts); counts.clear()   # an explicit timestamp never goes backwards
            W_(self.n8, C.consistency_proof_b64(self.leaves8, 5), T0 + 2); cosign = len(counts); counts.clear()
            r = W_(self.n5, ts=T0 + 3); rollback = len(counts); counts.clear(); self.assertEqual(r["evidenza"]["tipo"], "rollback")
            W_(self.n5, ts=T0 + 3); rollback_replay = len(counts); counts.clear()   # already in the ring: nothing changes
            r = W_(self.nf, ts=T0 + 3); known_pair = len(counts); counts.clear(); self.assertEqual(r["evidenza"]["tipo"], "split-view")
            e8 = C.sign_note(C.checkpoint_text(LOG, 8, hashlib.sha256(b"e8").digest()), LOG, self.ls)   # a root never seen: first equivocation
            r = W_(e8, ts=T0 + 3); equiv = len(counts); counts.clear(); self.assertEqual(r["evidenza"]["tipo"], "split-view")
            W_(e8, ts=T0 + 3); equiv_replay = len(counts); counts.clear()
            W_(self.n8, ["AAAA"], T0 + 3); sameproof = len(counts); counts.clear()
            W_(self.n8, old=5, ts=T0 + 3); wrong_old = len(counts); counts.clear()
            W_(self.nf, old=0, ts=T0 + 3); disc_replay = len(counts); counts.clear()   # a discovery 409 on a known root
            self.assertEqual(W_(C.sign_note(C.checkpoint_text(LOG, 8, bytes(32)), "other.example/x", self.ls), ts=T0 + 3)["http_status"], 403)
            untrusted = len(counts); counts.clear()
        self.assertEqual((tofu, unproven, badproof, recosign, disc, cosign), (1, 1, 0, 1, 1, 1))   # bad proof = same refusal: 0
        # ≤ 1 on every path, and 0 when the request adds nothing to the rings or the proofs
        self.assertEqual((rollback, rollback_replay, known_pair, equiv, equiv_replay, sameproof, wrong_old, disc_replay, untrusted),
                         (1, 0, 0, 1, 0, 0, 0, 0, 0))
        # the clock: a stored timestamp from a clock that was once ahead is NOT carried forward (round 10)
        stc = os.path.join(self.tmp, "w10.json")
        W.witness_cosign(stc, self.n5, self.LV, "witness.example/w1", self.w1, None, 4_000_000_000)
        r = W.witness_cosign(stc, self.n5, self.LV, "witness.example/w1", self.w1, None, None)
        self.assertLess(C.verify_note(r["note"], [self.W1V])["verified"][0]["timestamp"], 3_000_000_000)
        # two different log-signed roots at a size below the stored one, never cosigned, never pending: the second
        # pairs with the first through the refusals ring — a `split-view-unkept` record (root only), not "no proof"
        std = os.path.join(self.tmp, "w10b.json")
        W.witness_cosign(std, self.n8, self.LV, "witness.example/w1", self.w1, None, T0)
        a3 = C.sign_note(C.checkpoint_text(LOG, 3, hashlib.sha256(b"a3").digest()), LOG, self.ls)
        b3 = C.sign_note(C.checkpoint_text(LOG, 3, hashlib.sha256(b"b3").digest()), LOG, self.ls)
        self.assertEqual(W.witness_cosign(std, a3, self.LV, "witness.example/w1", self.w1, None, T0 + 1)["evidenza"]["tipo"], "rollback")
        r = W.witness_cosign(std, b3, self.LV, "witness.example/w1", self.w1, None, T0 + 2)
        self.assertEqual((r["evidenza"]["tipo"], r["evidenza"]["precedente_root_b64"]), ("split-view-unkept", base64.b64encode(hashlib.sha256(b"a3").digest()).decode()))
        # a replay of the FIRST root pairs with the second (by root, not by ring position — round 13)
        r = W.witness_cosign(std, a3, self.LV, "witness.example/w1", self.w1, None, T0 + 3)
        self.assertEqual((r["evidenza"]["tipo"], r["evidenza"]["precedente_root_b64"]), ("split-view-unkept", base64.b64encode(hashlib.sha256(b"b3").digest()).decode()))
        # a non-object line in the cosigned history is skipped, not a crash
        with open(std + ".cosigned.jsonl", "a") as f:
            f.write("[]\n")
        self.assertEqual(W.witness_cosign(std, a3, self.LV, "witness.example/w1", self.w1, None, T0 + 3)["stato"], "REFUSED")
        # pending roots at sizes a cosign jumps over are KEPT: root A at 10 refused, honest cosign at 12, then root B
        # at 10 as a rollback → split-view proof from the pending A (round 9: they were dropped unexamined)
        st2 = os.path.join(self.tmp, "w9c.json")
        e12 = _ledger(12); l12 = os.path.join(self.tmp, "l12.jsonl"); _write(l12, e12)
        l5b = os.path.join(self.tmp, "l5b.jsonl"); _write(l5b, e12[:5])
        t5, _ = C.ledger_checkpoint(l5b, LOG); n5 = C.sign_note(t5, LOG, self.ls)
        t12, leaves12 = C.ledger_checkpoint(l12, LOG); n12 = C.sign_note(t12, LOG, self.ls)
        a10 = C.sign_note(C.checkpoint_text(LOG, 10, hashlib.sha256(b"a10").digest()), LOG, self.ls)
        b10 = C.sign_note(C.checkpoint_text(LOG, 10, hashlib.sha256(b"b10").digest()), LOG, self.ls)
        w2 = lambda note, proof=None, ts=T0: W.witness_cosign(st2, note, self.LV, "witness.example/w1", self.w1, proof, ts)
        self.assertEqual(w2(n5)["stato"], "COSIGNED")
        self.assertEqual(w2(a10)["evidenza"]["tipo"], "unproven-extension")
        self.assertEqual(w2(n12, C.consistency_proof_b64(leaves12, 5), T0 + 1)["stato"], "COSIGNED")
        r = w2(b10, None, T0 + 2)
        self.assertEqual((r["evidenza"]["tipo"], r["evidenza"]["prova"]), ("split-view", True))
        # a full pair recorded AFTER a half (unkept) record of the same roots: written as a second, full record
        st3 = os.path.join(self.tmp, "w9d.json"); w3 = lambda note, ts=T0: W.witness_cosign(st3, note, self.LV, "witness.example/w1", self.w1, None, ts)
        self.assertEqual(w3(self.n5)["stato"], "COSIGNED")
        bigx = C.sign_note(C.checkpoint_text(LOG, 9, hashlib.sha256(b"x9").digest(), ["y" * 8000] * 3), LOG, self.ls)
        smallx = C.sign_note(C.checkpoint_text(LOG, 9, hashlib.sha256(b"x9").digest()), LOG, self.ls)   # same root, small
        y9 = C.sign_note(C.checkpoint_text(LOG, 9, hashlib.sha256(b"y9").digest()), LOG, self.ls)
        w3(bigx); self.assertEqual(w3(y9, T0 + 1)["evidenza"]["tipo"], "split-view-unkept")
        self.assertEqual(w3(smallx, T0 + 2)["evidenza"]["tipo"], "split-view")
        with open(st3 + ".evidence.jsonl") as f:
            self.assertEqual([json.loads(l)["tipo"] for l in f], ["split-view-unkept", "split-view"])

    def test_fresh_origin_pending_and_malformed_size0(self):
        # an origin never cosigned: two log-signed roots at one size, both with a wrong old size (409): the second is
        # proof (round 7: "beyond the stored size" includes stored size 0)
        st = os.path.join(self.tmp, "w7.json")
        a9 = C.sign_note(C.checkpoint_text(LOG, 9, hashlib.sha256(b"a9").digest()), LOG, self.ls)
        b9 = C.sign_note(C.checkpoint_text(LOG, 9, hashlib.sha256(b"b9").digest()), LOG, self.ls)
        r = W.witness_cosign(st, a9, self.LV, "witness.example/w1", self.w1, None, T0, old_size=3)
        self.assertEqual((r["http_status"], r["evidenza"]), (409, None))
        r = W.witness_cosign(st, b9, self.LV, "witness.example/w1", self.w1, None, T0, old_size=3)
        self.assertEqual((r["http_status"], r["evidenza"]["tipo"], r["evidenza"]["prova"]), (409, "split-view", True))
        # then a TOFU at 9 with a third root: one more proof (one pair per request), pending consumed
        c9 = C.sign_note(C.checkpoint_text(LOG, 9, hashlib.sha256(b"c9").digest()), LOG, self.ls)
        self.assertEqual(W.witness_cosign(st, c9, self.LV, "witness.example/w1", self.w1, None, T0)["stato"], "COSIGNED")
        with open(st + ".evidence.jsonl") as f:
            self.assertEqual(len(f.readlines()), 2)
        # the same with an OVERSIZED first root (kept as root only) and a small second: the TOFU that follows records
        # exactly one pair, not one full and one half (round 13, Opus)
        st_o = os.path.join(self.tmp, "w7o.json")
        big9 = C.sign_note(C.checkpoint_text(LOG, 9, hashlib.sha256(b"big").digest(), ["y" * 8000] * 3), LOG, self.ls)
        W.witness_cosign(st_o, big9, self.LV, "witness.example/w1", self.w1, None, T0, old_size=3)
        W.witness_cosign(st_o, b9, self.LV, "witness.example/w1", self.w1, None, T0, old_size=3)
        with open(st_o + ".evidence.jsonl") as f:
            before_o = len(f.readlines())
        W.witness_cosign(st_o, c9, self.LV, "witness.example/w1", self.w1, None, T0)
        with open(st_o + ".evidence.jsonl") as f:
            self.assertEqual(len(f.readlines()), before_o + 1)
        with open(st) as f:
            self.assertEqual(json.load(f)["pending"].get(LOG, {}), {})
        # a malformed size-0 checkpoint against a stored size 0: 422, no evidence (the fields must not contradict)
        st0 = os.path.join(self.tmp, "w0.json")
        z = C.sign_note(C.checkpoint_text(LOG, 0, W.EMPTY_ROOT), LOG, self.ls)
        self.assertEqual(W.witness_cosign(st0, z, self.LV, "witness.example/w1", self.w1, None, T0)["stato"], "COSIGNED")
        bad0 = C.sign_note(C.checkpoint_text(LOG, 0, bytes(32)), LOG, self.ls)
        r = W.witness_cosign(st0, bad0, self.LV, "witness.example/w1", self.w1, None, T0)
        self.assertEqual((r["http_status"], r["evidenza"]), (422, None))

    def test_witness_refuses_bad_log_signature_origin_and_state(self):
        ok = os.path.join(self.tmp, "other.key"); signer.keygen(ok); other = C.load_seed_hex(ok)
        # signed by an untrusted key
        r = self._w1(C.sign_note(self.t5, LOG, other))
        self.assertEqual(r["stato"], "REFUSED"); self.assertIn("log signature: NON_VALIDA", r["motivo"])
        # unsigned text: a malformed note is 400, a bad signature 403 (the spec reserves 403 for signatures)
        r = self._w1(self.t5.encode()); self.assertEqual((r["stato"], r["http_status"]), ("REFUSED", 400))
        self.assertEqual(self._w1(C.sign_note(self.t5, LOG, other))["http_status"], 403)
        # origin ≠ key name (signed by the trusted key under another origin)
        r = self._w1(C.sign_note(C.checkpoint_text("other.example/log", 5, bytes(32)), LOG, self.ls))
        self.assertEqual((r["stato"], r["http_status"], r["motivo"]), ("REFUSED", 400, "checkpoint origin is not the origin trusted for this log key"))
        # a production-style log whose origin differs from its key name ("go.sum database tree" / sum.golang.org):
        # accepted only when the operator maps that origin to the key (expected_origin), refused by default
        gs = C.sign_note("go.sum database tree\n5\n" + base64.b64encode(bytes(32)).decode() + "\n", LOG, self.ls)
        self.assertEqual(self._w1(gs)["stato"], "REFUSED")
        r = W.witness_cosign(self.st2, gs, self.LV, "witness.example/w2", self.w2, None, T0, expected_origin="go.sum database tree")
        self.assertEqual((r["stato"], r["origin"]), ("COSIGNED", "go.sum database tree"))
        v = W.verify_witnessed(r["note"], self.LV, [self.W2V], expected_origin="go.sum database tree")
        self.assertEqual((v["stato"], v["checkpoint"]["origin"]), ("OK", "go.sum database tree"))
        # the relying party binds the origin too: by default the log key name, else what it expects
        v = W.verify_witnessed(r["note"], self.LV, [self.W2V]); self.assertEqual(v["stato"], "NON_VALIDA"); self.assertIn("origin", v["motivo"])
        gs_note = r["note"]
        # key rotation: two trusted keys for one origin, either signs; a third does not
        rk = os.path.join(self.tmp, "rot.key"); signer.keygen(rk); rot = C.load_seed_hex(rk)
        RV = C.vkey(LOG, C.TYPE_ED25519, C.pubkey_from_seed(rot))
        r = W.witness_cosign(self.st2, C.sign_note(self.t5, LOG, rot), [self.LV, RV], "witness.example/w2", self.w2, None, T0)
        self.assertEqual(r["stato"], "COSIGNED")
        r = W.witness_cosign(self.st2, self.n5, [self.LV, RV], "witness.example/w2", self.w2, None, T0 + 1)
        self.assertEqual(r["stato"], "COSIGNED")
        r = W.witness_cosign(self.st2, C.sign_note(self.t5, LOG, other), [self.LV, RV], "witness.example/w2", self.w2, None, T0 + 2)
        self.assertEqual((r["stato"], r["http_status"]), ("REFUSED", 403))
        with self.assertRaises(C.NoteError):
            W.witness_cosign(self.st2, self.n5, [], "witness.example/w2", self.w2, None, T0)
        # rotation with DIFFERENT key names for one origin: allowed with an explicit expected_origin, refused without
        rk2 = os.path.join(self.tmp, "rot2.key"); signer.keygen(rk2); rot2 = C.load_seed_hex(rk2)
        R2V = C.vkey("ledger-a.example/2027", C.TYPE_ED25519, C.pubkey_from_seed(rot2))
        with self.assertRaises(C.NoteError):
            W.witness_cosign(self.st2, self.n5, [self.LV, R2V], "witness.example/w2", self.w2, None, T0 + 3)
        r = W.witness_cosign(self.st2, C.sign_note(self.t5, "ledger-a.example/2027", rot2), [self.LV, R2V], "witness.example/w2",
                             self.w2, None, T0 + 3, expected_origin=LOG)
        self.assertEqual(r["stato"], "COSIGNED")
        # the relying party with a rotated key set: same-name keys need no origin, different names do
        self.assertEqual(W.verify_witnessed(gs_note, [self.LV, RV], [self.W2V], expected_origin="go.sum database tree")["stato"], "OK")
        self.assertEqual(W.verify_witnessed(r["note"], [self.LV, R2V], [self.W2V], expected_origin=LOG)["stato"], "OK")
        with self.assertRaises(C.NoteError):
            W.verify_witnessed(r["note"], [self.LV, R2V], [self.W2V])
        # re-cosign of a note that already carries this witness's line: the line is REPLACED (one line, new timestamp)
        st3 = os.path.join(self.tmp, "w1b.json")
        first = W.witness_cosign(st3, self.n5, self.LV, "witness.example/w1", self.w1, None, T0 + 10)["note"]
        again = W.witness_cosign(st3, first, self.LV, "witness.example/w1", self.w1, None, T0 + 100)["note"]
        _, sigs = C.split_note(again)
        self.assertEqual([n for n, _ in sigs], [LOG, "witness.example/w1"])
        self.assertEqual(C.verify_note(again, [self.W1V])["verified"][0]["timestamp"], T0 + 100)
        self.assertEqual(W.verify_witnessed(again, self.LV, [self.W1V], 1, max_age_s=60, now=T0 + 120)["stato"], "OK")
        # a cosignature-only note (no type 0x01 from the log): refused
        cs = C.cosign_v1(self.n5, "witness.example/w2", self.w2, T0)
        _, sigs = C.split_note(cs)
        only = (self.t5 + "\n" + f"— witness.example/w2 {base64.b64encode(sigs[1][1]).decode()}\n").encode()
        r = W.witness_cosign(self.st1, only, self.LV, "witness.example/w1", self.w1, None, T0)
        self.assertEqual(r["stato"], "REFUSED")
        # no cryptography → NON_VERIFICATA is not a green light
        with mock.patch.object(C, "_ed", return_value=(None, None, None)):
            r = self._w1(self.n5)
        self.assertEqual(r["stato"], "REFUSED"); self.assertIn("NON_VERIFICATA", r["motivo"])
        self.assertFalse(os.path.exists(self.st1))
        # malformed state file → error, never silent TOFU
        for bad in ("[]", '{"origins": {"o": {"size": "5"}}}', '{"origins": {"o": {"size": 5, "root_b64": "AAAA", "note": "x"}}}',
                    '{"origins": {"o": {"size": true, "root_b64": "%s", "note": "x"}}}' % base64.b64encode(bytes(32)).decode()):
            with open(self.st1, "w") as f:
                f.write(bad)
            with self.assertRaises(C.NoteError, msg=bad):
                self._w1(self.n5)
        os.remove(self.st1)
        # the timestamp is the caller's: zero/negative/non-int raise, nothing is cosigned or stored — on the first
        # checkpoint AND on a refusal path (round 5: refusals used to store it unvalidated)
        for ts in (0, -1, 1.5, "abc"):
            with self.assertRaises(C.NoteError):
                self._w1(self.n5, ts=ts)
        self.assertFalse(os.path.exists(self.st1))
        st9 = os.path.join(self.tmp, "w9.json")
        W.witness_cosign(st9, self.n8, self.LV, "witness.example/w1", self.w1, None, T0)
        with self.assertRaises(C.NoteError):
            W.witness_cosign(st9, self.n5, self.LV, "witness.example/w1", self.w1, None, 1.5)
        with open(st9) as f:
            self.assertNotIn("refusals", json.load(f))

    def test_verify_witnessed_quorum_and_freshness(self):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        n = self._w1(self.n5)["note"]
        r = W.verify_witnessed(n, self.LV, [self.W1V, self.W2V], min_witnesses=1, max_age_s=60, now=T0 + 30)
        self.assertEqual((r["stato"], r["witnesses"], r["freshness_s"]), ("OK", ["witness.example/w1"], 30))
        self.assertEqual(r["checkpoint"]["size"], 5)
        r = W.verify_witnessed(n, self.LV, [self.W1V, self.W2V], min_witnesses=2, now=T0 + 30)
        self.assertEqual(r["stato"], "NON_VALIDA"); self.assertIn("1 trusted witness cosignature(s), 2 required", r["motivo"])
        n2 = W.witness_cosign(self.st2, n, self.LV, "witness.example/w2", self.w2, None, T0 + 5)["note"]
        r = W.verify_witnessed(n2, self.LV, [self.W1V, self.W2V], min_witnesses=2, max_age_s=60, now=T0 + 30)
        self.assertEqual((r["stato"], r["witnesses"], r["freshness_s"]), ("OK", ["witness.example/w1", "witness.example/w2"], 25))
        # stale
        r = W.verify_witnessed(n2, self.LV, [self.W1V, self.W2V], 2, max_age_s=60, now=T0 + 66)
        self.assertEqual(r["stato"], "NON_VALIDA"); self.assertIn("newest is 61 s old", r["motivo"])
        # N fresh witnesses, not "the newest is fresh": w1 at T0 and w2 at T0+5 with max_age 3 at now=T0+7 → only w2
        r = W.verify_witnessed(n2, self.LV, [self.W1V, self.W2V], 2, max_age_s=3, now=T0 + 7)
        self.assertEqual((r["stato"], r["fresh_witnesses"], r["freshness_s"]), ("NON_VALIDA", ["witness.example/w2"], 2))
        r = W.verify_witnessed(n2, self.LV, [self.W1V, self.W2V], 1, max_age_s=3, now=T0 + 7)
        self.assertEqual((r["stato"], r["witnesses"]), ("OK", ["witness.example/w1", "witness.example/w2"]))
        # a witness whose timestamp is in the future does not count (w2 at T0+5, now T0+4): 1 fresh of 2 required;
        # a declared clock skew tolerates it; the other witness alone still satisfies min_witnesses=1
        r = W.verify_witnessed(n2, self.LV, [self.W1V, self.W2V], 2, max_age_s=60, now=T0 + 4)
        self.assertEqual((r["stato"], r["fresh_witnesses"], r["future_witnesses"]), ("NON_VALIDA", ["witness.example/w1"], ["witness.example/w2"]))
        self.assertIn("in the future: witness.example/w2", r["motivo"])
        r = W.verify_witnessed(n2, self.LV, [self.W1V, self.W2V], 2, max_age_s=60, now=T0 + 4, clock_skew_s=1)
        self.assertEqual((r["stato"], r["freshness_s"]), ("OK", -1))
        r = W.verify_witnessed(n2, self.LV, [self.W1V, self.W2V], 1, max_age_s=60, now=T0 + 4)
        self.assertEqual((r["stato"], r["freshness_s"]), ("OK", 4))
        # min_witnesses < 1 or a negative clock skew is a caller error, not a crash with max_age (round 1, Gemini)
        with self.assertRaises(C.NoteError):
            W.verify_witnessed(n2, self.LV, [], 0, max_age_s=60, now=T0)
        with self.assertRaises(C.NoteError):
            W.verify_witnessed(n2, self.LV, [self.W1V], 1, max_age_s=60, now=T0, clock_skew_s=-1)
        # two lines of one witness key (T0-1000 and T0): every line is verified, the newest counts, whatever the order
        old_line = C.split_note(C.cosign_v1(n, "witness.example/w1", self.w1, T0 - 1000))[1][-1][1]
        appended = n2 + f"— witness.example/w1 {base64.b64encode(old_line).decode()}\n".encode()
        r = W.verify_witnessed(appended, self.LV, [self.W1V, self.W2V], 2, max_age_s=60, now=T0 + 30)
        self.assertEqual((r["stato"], r["freshness_s"]), ("OK", 25))
        older_first = self.n5 + f"— witness.example/w1 {base64.b64encode(old_line).decode()}\n".encode()
        older_first = C.cosign_v1(older_first, "witness.example/w2", self.w2, T0 + 5) + n[len(self.n5):]   # then the fresh w1 line
        r = W.verify_witnessed(older_first, self.LV, [self.W1V, self.W2V], 2, max_age_s=60, now=T0 + 30)
        self.assertEqual((r["stato"], r["freshness_s"], r["fresh_witnesses"]), ("OK", 25, ["witness.example/w1", "witness.example/w2"]))
        # a cosignature over a text that is not a checkpoint (one line): Go's library refuses it (a cosigned note has
        # ≥ 3 lines) and so do we — parity, measured in TestGoOracle
        one = C.sign_note("x\n", LOG, self.ls)
        kid1 = C.parse_vkey(self.W1V)[1]
        sig1 = Ed25519PrivateKey.from_private_bytes(self.w1).sign(f"cosignature/v1\ntime {T0}\n".encode() + b"x\n")
        one_cs = one + f"— witness.example/w1 {base64.b64encode(kid1 + struct.pack('>Q', T0) + sig1).decode()}\n".encode()
        self.assertEqual(C.verify_note(one_cs, [self.LV, self.W1V])["stato"], "NON_VALIDA")
        # a bogus second line of a trusted witness key: NON_VALIDA (the spec's MUST verify), not silently dropped
        bogus = older_first + f"— witness.example/w1 {base64.b64encode(old_line[:4] + bytes(72)).decode()}\n".encode()
        self.assertEqual(W.verify_witnessed(bogus, self.LV, [self.W1V, self.W2V], 2)["stato"], "NON_VALIDA")
        # an untrusted witness does not count; the same witness twice counts once
        r = W.verify_witnessed(n2, self.LV, [self.W1V], min_witnesses=2)
        self.assertEqual(r["stato"], "NON_VALIDA")
        twice = n + C.split_note(C.cosign_v1(n, "witness.example/w1", self.w1, T0 + 1))[1][-1][1]  # raw bytes appended: malformed
        self.assertEqual(W.verify_witnessed(twice, self.LV, [self.W1V], 1)["stato"], "NON_VALIDA")
        twice = C.cosign_v1(n, "witness.example/w1", self.w1, T0 + 1)
        r = W.verify_witnessed(twice, self.LV, [self.W1V], min_witnesses=2)
        self.assertEqual(r["stato"], "NON_VALIDA"); self.assertEqual(r["witnesses"], ["witness.example/w1"])
        # the type byte in the key id keeps the two roles apart: the log's 0x01 line never counts as a witness, and a
        # 0x04 line made with the log's key never counts as the log signature — even when the relying party trusts the
        # log key under both roles
        LOG_AS_WIT = C.vkey(LOG, C.TYPE_COSIG_V1, C.pubkey_from_seed(self.ls))
        r = W.verify_witnessed(self.n5, self.LV, [LOG_AS_WIT], min_witnesses=1)
        self.assertEqual((r["stato"], r["witnesses"]), ("NON_VALIDA", []))
        only04 = (self.t5 + "\n").encode() + C.cosign_v1(self.n5, LOG, self.ls, T0)[len(self.n5):]
        r = W.verify_witnessed(only04, self.LV, [LOG_AS_WIT], min_witnesses=1)
        self.assertEqual(r["stato"], "NON_VALIDA"); self.assertIn("no log signature", r["motivo"])
        r = W.verify_witnessed(C.cosign_v1(self.n5, LOG, self.ls, T0), self.LV, [LOG_AS_WIT], min_witnesses=1)
        self.assertEqual((r["stato"], r["witnesses"]), ("OK", [LOG]))   # trusted as a witness too: it counts, by choice
        with self.assertRaises(C.NoteError):                            # a 0x01 key in the witness list is a caller error
            W.verify_witnessed(self.n5, self.LV, [self.LV], min_witnesses=1)
        # an ML-DSA-44 (0x06) witness key with no line in the note does not disturb the Ed25519 quorum; with a line it
        # counts as the same witness by name (the relying-party checks of 0x06 are in TestRealCheckpoints.test_mldsa44_cosignature)
        mpub = bytes(1312); MV = f"w.mldsa/x+{C.key_id('w.mldsa/x', 0x06, mpub).hex()}+{base64.b64encode(bytes([6]) + mpub).decode()}"
        self.assertEqual(W.verify_witnessed(n, self.LV, [MV, self.W1V], 1)["stato"], "OK")
        # tampered text under two valid-looking cosignatures: NON_VALIDA (the log signature fails)
        r = W.verify_witnessed(n2.replace(b"\n5\n", b"\n6\n"), self.LV, [self.W1V, self.W2V], 2)
        self.assertEqual(r["stato"], "NON_VALIDA")
        # no cryptography → NON_VERIFICATA
        with mock.patch.object(C, "_ed", return_value=(None, None, None)):
            self.assertEqual(W.verify_witnessed(n2, self.LV, [self.W1V], 1)["stato"], "NON_VERIFICATA")

    def test_cli(self):
        n5 = os.path.join(self.tmp, "cp5.note"); _wb(n5, self.n5)
        out = os.path.join(self.tmp, "cp5.c.note")
        cmd = [sys.executable, os.path.join(HERE, "cryptovalid_witness.py")]
        r = subprocess.run(cmd + ["cosign", n5, "--state", self.st1, "--log-vkey", self.LV, "--name", "witness.example/w1",
                                  "--key", self.w1k, "--out", out], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr); self.assertEqual(json.loads(r.stdout)["stato"], "COSIGNED")
        v = subprocess.run(cmd + ["verify", out, "--log-vkey", self.LV, "--witness-vkey", self.W1V], capture_output=True, text=True)
        self.assertEqual(v.returncode, 0, v.stdout); self.assertEqual(json.loads(v.stdout)["stato"], "OK")
        v = subprocess.run(cmd + ["verify", out, "--log-vkey", self.LV, "--witness-vkey", self.W2V], capture_output=True, text=True)
        self.assertEqual(v.returncode, 1)
        n8 = os.path.join(self.tmp, "cp8.note"); _wb(n8, self.n8)
        r = subprocess.run(cmd + ["cosign", n8, "--state", self.st1, "--log-vkey", self.LV, "--name", "witness.example/w1",
                                  "--key", self.w1k, "--out", out + "8"], capture_output=True, text=True)
        self.assertEqual(r.returncode, 1); self.assertEqual(json.loads(r.stdout)["evidenza"]["tipo"], "unproven-extension")
        r = subprocess.run(cmd + ["cosign", n8, "--state", self.st1, "--log-vkey", self.LV, "--name", "witness.example/w1",
                                  "--key", self.w1k, "--out", out + "8", "--proof", json.dumps(C.consistency_proof_b64(self.leaves8, 5))],
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stdout)


@unittest.skipUnless(HAVE_CRYPTO, "cryptography assente")
class TestTlogWitnessHTTP(unittest.TestCase):
    """c2sp.org/tlog-witness add-checkpoint: status codes as the spec states them, our client against our server.
    The same server was driven by the REFERENCE Go client (transparency-dev/witness, 2026-09-19 bench) with identical
    outcomes; that bench is in the release dossier, not in this file (it needs the witness module and its deps)."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        cls.lk = os.path.join(cls.tmp, "log.key"); signer.keygen(cls.lk); cls.ls = C.load_seed_hex(cls.lk)
        cls.wk = os.path.join(cls.tmp, "w.key"); signer.keygen(cls.wk); cls.ws = C.load_seed_hex(cls.wk)
        cls.LV = C.vkey(LOG, C.TYPE_ED25519, C.pubkey_from_seed(cls.ls))
        cls.WV = C.vkey("witness.example/w1", C.TYPE_COSIG_V1, C.pubkey_from_seed(cls.ws))
        cls.svc = W.WitnessService(os.path.join(cls.tmp, "st.json"), "witness.example/w1", cls.ws, [cls.LV])
        cls.httpd = W.serve(cls.svc, "127.0.0.1", 0, "/w")
        cls.url = f"http://127.0.0.1:{cls.httpd.server_address[1]}/w"
        import threading
        cls.th = threading.Thread(target=cls.httpd.serve_forever, daemon=True); cls.th.start()
        cls.e8 = _ledger(8)
        cls.l5 = os.path.join(cls.tmp, "l5.jsonl"); _write(cls.l5, cls.e8[:5])
        cls.l8 = os.path.join(cls.tmp, "l8.jsonl"); _write(cls.l8, cls.e8)
        cls.fork = os.path.join(cls.tmp, "fork.jsonl"); _write(cls.fork, cls.e8[:4] + _ledger(8, "z")[4:])

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown(); cls.httpd.server_close(); shutil.rmtree(cls.tmp, ignore_errors=True)

    def _note(self, ledger):
        text, leaves = C.ledger_checkpoint(ledger, LOG)
        return C.sign_note(text, LOG, self.ls), leaves

    def test_body_parsing(self):
        n5, _ = self._note(self.l5)
        body = W.format_add_checkpoint_body(5, ["AA==", "BB=="], n5)
        self.assertTrue(body.startswith(b"old 5\nAA==\nBB==\n\n" + n5[:10]))
        old, proof, note = W.parse_add_checkpoint_body(W.format_add_checkpoint_body(0, [], n5))
        self.assertEqual((old, proof, note), (0, [], n5))
        h = base64.b64encode(bytes(32)).decode()
        self.assertEqual(W.parse_add_checkpoint_body(f"old 3\n{h}\n\n".encode() + n5)[1], [h])
        for bad in (b"old x\n\n" + n5, b"old 01\n\n" + n5, b"3\n\n" + n5, b"old 3\nAA==\n\n" + n5, b"old 3\n!!\n\n" + n5,
                    b"old 0\n\n\n" + n5, b"old 0\n\n", b"old " + b"9" * 6000 + b"\n\n" + n5,
                    "old 3\nñññññññññññññññññññññññññññññññññññññññññññ\n\n".encode() + n5,
                    b"old 3\n" + n5, f"old 3\n{(h + chr(10)) * 64}\n".encode() + n5, b"\xff\n\n" + n5):
            with self.assertRaises(C.NoteError, msg=repr(bad[:20])):
                W.parse_add_checkpoint_body(bad)

    def test_status_codes_and_client(self):
        n5, l5 = self._note(self.l5); n8, l8 = self._note(self.l8); nf, lf = self._note(self.fork)
        # 400: malformed body / old size > size; 404 unknown origin; 403 untrusted signature
        self.assertEqual(W.add_checkpoint(self.url, n5, 0, ["AA=="])[0], 400)
        self.assertEqual(W.add_checkpoint(self.url, n5, 6, [])[0], 400)
        other = C.sign_note(C.checkpoint_text("other.example/log", 5, bytes(32)), "other.example/log", self.ls)
        self.assertEqual(W.add_checkpoint(self.url, other, 0, [])[0], 404)
        ok = os.path.join(self.tmp, "o.key"); signer.keygen(ok); o = C.load_seed_hex(ok)
        self.assertEqual(W.add_checkpoint(self.url, C.sign_note(C.ledger_checkpoint(self.l5, LOG)[0], LOG, o), 0, [])[0], 403)
        self.assertEqual(W.add_checkpoint(self.url, n5.replace(b"\n5\n", b"\n6\n"), 0, [])[0], 403)
        # 422: size-0 checkpoint with a non-empty root; proof sent with old size 0
        z = C.sign_note(C.checkpoint_text(LOG, 0, bytes(32)), LOG, self.ls)
        self.assertEqual(W.add_checkpoint(self.url, z, 0, [])[0], 422)
        self.assertEqual(W.add_checkpoint(self.url, n5, 0, C.consistency_proof_b64(l8, 5))[0], 422)
        # 200 TOFU: the body is the cosignature line(s) only, and it verifies appended to the note
        st, body = W.add_checkpoint(self.url, n5, 0, [])
        self.assertEqual(st, 200); self.assertTrue(body.startswith("— witness.example/w1 ".encode()) and body.endswith(b"\n"))
        self.assertEqual(W.verify_witnessed(n5 + body, self.LV, [self.WV])["stato"], "OK")
        # a fork presented with the wrong old size (the discovery request "old 0"): 409 for the client, but the pair
        # IS recorded — it is the only kind that is proof (round 3, Opus)
        st, body = W.add_checkpoint(self.url, nf.replace(b"\n8\n", b"\n5\n", 1), 0, [])   # size 5, another root: log-signed? no → 403
        self.assertEqual(st, 403)
        nf5 = C.sign_note(C.checkpoint_text(LOG, 5, hashlib.sha256(b"fork5").digest()), LOG, self.ls)
        self.assertEqual(W.add_checkpoint(self.url, nf5, 0, [])[0], 409)
        with open(self.svc.state_path + ".evidence.jsonl") as f:
            first = [json.loads(l) for l in f]
        self.assertEqual([(e["tipo"], e["prova"], e["size_presentato"]) for e in first], [("split-view", True, 5)])
        self.assertEqual(W.add_checkpoint(self.url, nf5, 0, [])[0], 409)   # replay: nothing new in the file
        with open(self.svc.state_path + ".evidence.jsonl") as f:
            self.assertEqual(len(f.readlines()), 1)
        # 409 with the stored size (text/x.tlog.size body), 422 without proof, 200 with it
        st, body = W.add_checkpoint(self.url, n8, 0, [])
        self.assertEqual((st, body), (409, b"5\n"))
        self.assertEqual(W.add_checkpoint(self.url, n8, 5, [])[0], 422)
        self.assertEqual(W.add_checkpoint(self.url, n8, 5, C.consistency_proof_b64(l8, 5))[0], 200)
        # fork at 8 with an EMPTY proof (old size 8 = size 8): 422 for the root mismatch itself, not for a stray proof
        st, body = W.add_checkpoint(self.url, nf, 8, [])
        self.assertEqual((st, body), (422, b"equivocation: same size, different root\n"))
        # rollback: old size 8 > size 5 → 400; stated old 5 → 409 (stored 8); over HTTP the client sees only the
        # status; the evidence file has the proofs only: the size-5 fork (against the stored 5, then) and the size-8 fork
        self.assertEqual(W.add_checkpoint(self.url, n5, 8, [])[0], 400)
        self.assertEqual(W.add_checkpoint(self.url, n5, 5, [])[0], 409)
        with open(self.svc.state_path + ".evidence.jsonl") as f:
            evs = [json.loads(l) for l in f]
        self.assertEqual([(e["tipo"], e["prova"], e["size_presentato"]) for e in evs], [("split-view", True, 5), ("split-view", True, 8)])
        self.assertEqual(C.verify_note(evs[1]["presentato"].encode(), [self.LV])["text"], C.split_note(nf)[0])
        with open(self.svc.state_path) as f:
            self.assertEqual(json.load(f)["refusals"][LOG]["count"], 2)   # 5→8 without proof, and the rollback (twice = once)
        # re-cosign over HTTP of a note that already carries our line: 200 with exactly ONE fresh line (round 3: the
        # first implementation sliced by length and answered an empty body), and the state moves to the new timestamp
        st, body = W.add_checkpoint(self.url, n8, 8, []); self.assertEqual(st, 200)
        once = n8 + body
        st, body2 = W.add_checkpoint(self.url, once, 8, [])
        self.assertEqual(st, 200); self.assertEqual(body2.count(b"\n"), 1); self.assertTrue(body2.startswith("— witness.example/w1 ".encode()))
        # (within one wall-clock second Ed25519 is deterministic, so the line may be byte-identical: the property is
        # ONE line, verifying, not a different one)
        self.assertEqual(W.verify_witnessed(n8 + body2, self.LV, [self.WV], 1)["stato"], "OK")
        with open(self.svc.state_path) as f:
            self.assertEqual(C.split_note(json.load(f)["origins"][LOG]["note"].encode())[1][1][0], "witness.example/w1")
        # a note with 100 signature lines has no room for ours: 400, not an unopenable 101-line note
        full = n8 + "".join(f"— pad{i} AAAAAAAAAA==\n" for i in range(99)).encode()
        self.assertEqual(C.verify_note(full, [self.LV])["stato"], "OK")
        st, body = W.add_checkpoint(self.url, full, 8, []); self.assertEqual(st, 400); self.assertIn(b"no room", body)
        # the 409 carries the spec's Content-Type; an oversized body is 413
        import http.client
        c = http.client.HTTPConnection("127.0.0.1", self.httpd.server_address[1], timeout=10)
        c.request("POST", "/w/add-checkpoint", body=W.format_add_checkpoint_body(5, [], n8)); resp = c.getresponse()
        self.assertEqual((resp.status, resp.getheader("Content-Type"), resp.read()), (409, "text/x.tlog.size", b"8\n")); c.close()
        c = http.client.HTTPConnection("127.0.0.1", self.httpd.server_address[1], timeout=10)
        c.putrequest("POST", "/w/add-checkpoint"); c.putheader("Content-Length", str((2 << 20) + 1)); c.endheaders()
        resp = c.getresponse(); self.assertEqual((resp.status, resp.getheader("Content-Length"), resp.getheader("Connection")), (413, "0", "close")); c.close()
        # the client helper: 409 → resubmit with the answered size; verifies the cosignature with trusted keys only
        r = W.submit_checkpoint(self.url, n8, l8, [self.WV], self.LV)
        self.assertEqual((r["stato"], r["status"], r["witnesses"]), ("OK", 200, ["witness.example/w1"]))
        self.assertEqual(W.verify_witnessed(r["note"], self.LV, [self.WV])["checkpoint"]["size"], 8)
        # a witness answering with padding lines from unknown keys: the client keeps only its trusted line (round 6)
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
        import threading
        pad_line = "— junk AAAAAAAAAA==\n".encode()

        class Pad(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_POST(self):
                body = self.rfile.read(int(self.headers["Content-Length"]))
                st_, resp, _ = self.server.svc.add_checkpoint(body)
                if st_ == 200:
                    resp = resp + pad_line * 98
                self.send_response(st_); self.send_header("Content-Length", str(len(resp))); self.end_headers(); self.wfile.write(resp)
        padsrv = ThreadingHTTPServer(("127.0.0.1", 0), Pad); padsrv.svc = W.WitnessService(os.path.join(self.tmp, "pad.json"), "witness.example/w1", self.ws, [self.LV])
        threading.Thread(target=padsrv.serve_forever, daemon=True).start()
        try:
            rp = W.submit_checkpoint(f"http://127.0.0.1:{padsrv.server_address[1]}", n8, l8, [self.WV], self.LV)
            self.assertEqual(rp["stato"], "OK"); self.assertEqual([nm for nm, _ in C.split_note(rp["note"])[1]], [LOG, "witness.example/w1"])
            # a 200 with only unknown-key lines, on a note that already carried our old cosignature: NOT accepted as
            # fresh (round 8: the old line used to satisfy the check)
            Pad.only_pad = True
            padsrv.svc2 = padsrv.svc
            def do_POST_pad(self_):
                body = self_.rfile.read(int(self_.headers["Content-Length"]))
                st_, resp, _ = padsrv.svc.add_checkpoint(body)
                if st_ == 200:
                    resp = pad_line
                self_.send_response(st_); self_.send_header("Content-Length", str(len(resp))); self_.end_headers(); self_.wfile.write(resp)
            Pad.do_POST = do_POST_pad
            rp2 = W.submit_checkpoint(f"http://127.0.0.1:{padsrv.server_address[1]}", rp["note"], l8, [self.WV], self.LV)
            self.assertEqual(rp2["stato"], "NON_VALIDA"); self.assertIn("without a cosignature line from a trusted witness key", rp2["motivo"])
        finally:
            padsrv.shutdown(); padsrv.server_close()
        # resubmitting the cosigned note: the fresh line REPLACES ours in the client's note (one line per witness key)
        r2 = W.submit_checkpoint(self.url, r["note"], l8, [self.WV], self.LV)
        self.assertEqual(r2["stato"], "OK"); self.assertEqual([n for n, _ in C.split_note(r2["note"])[1]], [LOG, "witness.example/w1"])
        r = W.submit_checkpoint(self.url, n5, l5, [self.WV], self.LV)
        self.assertEqual((r["stato"], r["status"]), ("NON_VALIDA", 409)); self.assertIn("witness knows size 8", r["motivo"])
        r = W.submit_checkpoint(self.url, nf, lf, [self.WV], self.LV)
        self.assertEqual((r["stato"], r["status"]), ("NON_VALIDA", 422))
        # an untrusted witness key: the 200 is not accepted
        r = W.submit_checkpoint(self.url, n8, l8, [C.vkey("witness.example/w1", C.TYPE_COSIG_V1, C.pubkey_from_seed(o))], self.LV)
        self.assertEqual(r["stato"], "NON_VALIDA"); self.assertIn("without a cosignature line from a trusted witness key", r["motivo"])
        # an empty proof line is 400, not 404 (round 2, Opus)
        self.assertEqual(W.add_checkpoint(self.url, b"\n" + n8, 0, [])[0], 400)
        # a corrupted state file: 500 with a reason on stderr, never a dropped connection (round 2, Opus + Sonnet)
        with open(self.svc.state_path, "w") as f:
            f.write("{")
        self.assertEqual(W.add_checkpoint(self.url, n8, 8, [])[0], 500)
        os.remove(self.svc.state_path)
        with self.assertRaises(C.NoteError):
            W.WitnessService(self.svc.state_path + "x", "w", self.ws, [])
        with self.assertRaises(C.NoteError):                   # a cosigner (0x04) vkey is not a log key
            W.WitnessService(self.svc.state_path + "x", "w", self.ws, [self.WV])
        # two different Content-Length headers, or Transfer-Encoding alongside: 400 and close (RFC 9112 §6.3)
        c = http.client.HTTPConnection("127.0.0.1", self.httpd.server_address[1], timeout=10)
        c.putrequest("POST", "/w/add-checkpoint"); c.putheader("Content-Length", "10"); c.putheader("Content-Length", "5"); c.endheaders()
        self.assertEqual(c.getresponse().status, 400); c.close()
        c = http.client.HTTPConnection("127.0.0.1", self.httpd.server_address[1], timeout=10)
        c.putrequest("POST", "/w/add-checkpoint"); c.putheader("Content-Length", "10"); c.putheader("Transfer-Encoding", "chunked"); c.endheaders()
        self.assertEqual(c.getresponse().status, 400); c.close()
        # hostile Content-Length: a response, not a hung thread or a traceback (round 1, Opus)
        import http.client
        for cl in ("abc", "-1"):
            c = http.client.HTTPConnection("127.0.0.1", self.httpd.server_address[1], timeout=10)
            c.putrequest("POST", "/w/add-checkpoint"); c.putheader("Content-Length", cl); c.endheaders()
            resp = c.getresponse(); self.assertEqual((resp.status, resp.getheader("Content-Length"), resp.getheader("Connection")), (400, "0", "close"), cl); c.close()
        # an unreachable witness: status 0 with the reason, never a traceback (round 5, Sonnet)
        st0, body0 = W.add_checkpoint("http://127.0.0.1:1", n8, 0, [], timeout=2)
        self.assertEqual(st0, 0); self.assertTrue(body0.startswith(b"no response"))
        self.assertEqual(W.submit_checkpoint("http://127.0.0.1:1", n8, l8, [self.WV], self.LV)["status"], 0)
        # wrong path → 404 with Content-Length 0 and the connection closed (keep-alive must not be poisoned, round 7)
        import http.client
        c = http.client.HTTPConnection("127.0.0.1", self.httpd.server_address[1], timeout=10)
        c.request("POST", "/w/nope", body=b"old 0\n\n"); resp = c.getresponse()
        self.assertEqual((resp.status, resp.getheader("Content-Length"), resp.read()), (404, "0", b"")); c.close()
        # keep-alive: two valid requests on one connection
        c = http.client.HTTPConnection("127.0.0.1", self.httpd.server_address[1], timeout=10)
        c.request("POST", "/w/add-checkpoint", body=W.format_add_checkpoint_body(5, [], n8)); r1 = c.getresponse(); r1.read()
        c.request("POST", "/w/add-checkpoint", body=W.format_add_checkpoint_body(5, [], n8)); r2 = c.getresponse(); r2.read()
        self.assertEqual((r1.status, r2.status), (409, 409)); c.close()
        # a log key given as a witness key: refused BEFORE any network round trip (nothing cosigned on the server)
        with open(self.svc.state_path + ".cosigned.jsonl") as f:
            n_before = len(f.readlines())
        with self.assertRaises(C.NoteError):
            W.submit_checkpoint(self.url, n8, l8, [self.LV], self.LV)
        with open(self.svc.state_path + ".cosigned.jsonl") as f:
            self.assertEqual(len(f.readlines()), n_before)
        # wrong path → 404
        import urllib.request, urllib.error
        with self.assertRaises(urllib.error.HTTPError) as cm:
            urllib.request.urlopen(urllib.request.Request(self.url + "/nope", data=b"x", method="POST"))
        self.assertEqual(cm.exception.code, 404)


def _go():
    return shutil.which("go")


@unittest.skipUnless(HAVE_CRYPTO, "cryptography assente")
class TestRealCheckpoints(unittest.TestCase):
    """Three Sigstore Rekor v1 checkpoints downloaded on 2026-09-19 (examples/checkpoints/), signed by the log's ECDSA
    P-256 key: the positive control of signature type 0x02 on data nobody here produced. Each one is refused with
    its size altered, and the witness cosigns the active shard's checkpoint (an ECDSA log key as trusted log key)."""

    def test_rekor_v1_checkpoints_verify(self):
        d = os.path.join(HERE, "examples", "checkpoints")
        vk = open(os.path.join(d, "rekor_v1.vkey")).read().strip()
        notes = sorted(f for f in os.listdir(d) if f.startswith("rekor_v1_") and f.endswith(".note"))
        self.assertEqual(len(notes), 3)
        for f in notes:
            with open(os.path.join(d, f), "rb") as fh:
                n = fh.read()
            r = C.verify_note(n, [vk])
            self.assertEqual((r["stato"], r["verified"]), ("OK", [{"name": "rekor.sigstore.dev", "type": 2}]), f)
            cp = C.parse_checkpoint(r["text"]); self.assertTrue(cp["origin"].startswith("rekor.sigstore.dev - "))
            bad = n.replace(str(cp["size"]).encode(), str(cp["size"] + 1).encode(), 1)
            self.assertEqual(C.verify_note(bad, [vk])["stato"], "NON_VALIDA")
        # the vkey from the PEM the API serves equals the one omniwitness lists
        from cryptography.hazmat.primitives import serialization as ser
        pem = ("-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE2G2Y+2tabdTV5BcGiBIx0a9fAFwr\n"
               "kBbmLSGtks4L3qX6yYY0zufBnhC8Ur/iy55GhWP/9A/bY2LhC30M9+RYtw==\n-----END PUBLIC KEY-----\n")
        der = ser.load_pem_public_key(pem.encode()).public_bytes(ser.Encoding.DER, ser.PublicFormat.SubjectPublicKeyInfo)
        self.assertEqual(C.vkey_ecdsa("rekor.sigstore.dev", der), vk)
        # our witness cosigns the real checkpoint (origin ≠ key name: configured), a relying party verifies it
        wk = os.path.join(tempfile.mkdtemp(), "w.key"); signer.keygen(wk); ws = C.load_seed_hex(wk)
        with open(os.path.join(d, notes[0]), "rb") as fh:
            n = fh.read()
        origin = C.parse_checkpoint(C.split_note(n)[0])["origin"]
        r = W.witness_cosign(wk + ".json", n, vk, "witness.example/w1", ws, None, T0, expected_origin=origin)
        self.assertEqual(r["stato"], "COSIGNED")
        WV = C.vkey("witness.example/w1", C.TYPE_COSIG_V1, C.pubkey_from_seed(ws))
        v = W.verify_witnessed(r["note"], vk, [WV], 1, expected_origin=origin)
        self.assertEqual((v["stato"], v["witnesses"]), ("OK", ["witness.example/w1"]))

    def test_mldsa44_cosignature(self):
        # an ML-DSA-44 cosignature (type 0x06, the type the witness spec recommends) beside the Ed25519 one
        tmp = tempfile.mkdtemp()
        lk = os.path.join(tmp, "l.key"); signer.keygen(lk); ls = C.load_seed_hex(lk)
        wk = os.path.join(tmp, "w.key"); signer.keygen(wk); ws = C.load_seed_hex(wk)
        pk = os.path.join(tmp, "pq.key"); signer.keygen(pk); ps = C.load_seed_hex(pk)   # any 32-byte seed
        LV = C.vkey(LOG, C.TYPE_ED25519, C.pubkey_from_seed(ls))
        WV = C.vkey("witness.example/w1", C.TYPE_COSIG_V1, C.pubkey_from_seed(ws))
        MV = C.vkey("witness.example/w1", C.TYPE_MLDSA44, C.mldsa44_pubkey_from_seed(ps))
        self.assertEqual(len(C.parse_vkey(MV)[3]), 1312)
        text = C.checkpoint_text(LOG, 6, hashlib.sha256(b"r").digest(), ["ext line"])
        note = C.sign_note(text, LOG, ls)
        r = W.witness_cosign(os.path.join(tmp, "s.json"), note, LV, "witness.example/w1", ws, None, T0, pq_seed=ps)
        self.assertEqual(r["stato"], "COSIGNED")
        v = C.verify_note(r["note"], [LV, WV, MV])
        self.assertEqual([(x["name"], x["type"]) for x in v["verified"]], [(LOG, 1), ("witness.example/w1", 4), ("witness.example/w1", 6)])
        self.assertEqual(v["verified"][2]["timestamp"], T0)
        vw = W.verify_witnessed(r["note"], LV, [MV], 1, max_age_s=60, now=T0 + 10)   # the PQ line alone satisfies the quorum
        self.assertEqual((vw["stato"], vw["witnesses"]), ("OK", ["witness.example/w1"]))
        vw = W.verify_witnessed(r["note"], LV, [MV, WV], 2)                             # one witness by name, not two
        self.assertEqual(vw["stato"], "NON_VALIDA")
        # a tampered ML-DSA-44 line → NON_VALIDA; without an ML-DSA implementation → NON_VERIFICATA (not OK)
        lines = r["note"].split(b"\n")
        pq_line = [l for l in lines if l.startswith("— witness".encode()) and len(l) > 200][0]
        bad_pq = r["note"].replace(pq_line, pq_line[:-8] + (b"AAAA" if pq_line[-8:-4] != b"AAAA" else b"BBBB") + pq_line[-4:])
        self.assertEqual(W.verify_witnessed(bad_pq, LV, [MV], 1)["stato"], "NON_VALIDA")
        with mock.patch.object(C, "_mldsa", return_value=None):
            self.assertEqual(W.verify_witnessed(r["note"], LV, [MV], 1)["stato"], "NON_VERIFICATA")
            self.assertEqual(C.verify_note(r["note"], [LV, WV, MV])["stato"], "NON_VERIFICATA")
            self.assertEqual(C.verify_note(bad_pq.replace(b"\n6\n", b"\n7\n", 1), [LV, WV, MV])["stato"], "NON_VALIDA")   # a failing known key still wins
        # tampering the root → NON_VALIDA; tampering an extension line → the ML-DSA-44 line still verifies (the spec's
        # message does not cover extensions — stated), the Ed25519 lines do not
        self.assertEqual(C.verify_note(r["note"].replace(b"\n6\n", b"\n7\n", 1), [MV])["stato"], "NON_VALIDA")
        self.assertEqual(C.verify_note(r["note"].replace(b"ext line", b"ext lin3"), [MV])["stato"], "OK")
        self.assertEqual(C.verify_note(r["note"].replace(b"ext line", b"ext lin3"), [LV])["stato"], "NON_VALIDA")
        # a re-cosign replaces BOTH of our lines
        r2 = W.witness_cosign(os.path.join(tmp, "s.json"), r["note"], LV, "witness.example/w1", ws, None, T0 + 5, pq_seed=ps)
        self.assertEqual([n for n, _ in C.split_note(r2["note"])[1]], [LOG, "witness.example/w1", "witness.example/w1"])
        with self.assertRaises(C.NoteError):
            C.cosign_v1_mldsa44(note, "w", ps, 0)


@unittest.skipUnless(HAVE_CRYPTO, "cryptography assente")
class TestGoOracle(unittest.TestCase):
    """The ecosystem's own libraries open our notes. Skipped without Go unless CV_REQUIRE_GO_ORACLE=1 (CI sets it)."""

    @classmethod
    def setUpClass(cls):
        if not _go():
            if os.environ.get("CV_REQUIRE_GO_ORACLE") == "1":
                raise AssertionError("CV_REQUIRE_GO_ORACLE=1 but no Go toolchain on PATH")
            raise unittest.SkipTest("no Go toolchain")
        cls.tmp = tempfile.mkdtemp(); cls.bin = os.path.join(cls.tmp, "cvnote-oracle")
        r = subprocess.run(["go", "build", "-o", cls.bin, "."], cwd=ORACLE_SRC, capture_output=True, text=True, timeout=600)
        if r.returncode != 0:   # Go present but the oracle does not build: a regression, never a silent skip
            raise AssertionError("note_oracle build failed: " + r.stderr[-800:])

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(getattr(cls, "tmp", ""), ignore_errors=True)

    def _oracle(self, note, *vkeys):
        p = os.path.join(self.tmp, "n.note"); _wb(p, note)
        r = subprocess.run([self.bin, p] + list(vkeys), capture_output=True, text=True, timeout=60)
        return r.returncode, r.stdout

    def test_spec_vector_and_our_notes(self):
        rc, out = self._oracle(SPEC_NOTE, SPEC_VKEY)
        self.assertEqual(rc, 0, out); self.assertIn("VERIFIED sigs=1", out)
        rc, out = self._oracle(SPEC_NOTE.replace(b"message", b"massage"), SPEC_VKEY)
        self.assertEqual(rc, 1, out); self.assertIn("invalid signature", out)
        lk = os.path.join(self.tmp, "log.key"); signer.keygen(lk); ls = C.load_seed_hex(lk)
        w1k = os.path.join(self.tmp, "w1.key"); signer.keygen(w1k); w1 = C.load_seed_hex(w1k)
        w2k = os.path.join(self.tmp, "w2.key"); signer.keygen(w2k); w2 = C.load_seed_hex(w2k)
        LV = C.vkey(LOG, C.TYPE_ED25519, C.pubkey_from_seed(ls))
        W1V = C.vkey("witness.example/w1", C.TYPE_COSIG_V1, C.pubkey_from_seed(w1))
        W2V = C.vkey("witness.example/w2", C.TYPE_COSIG_V1, C.pubkey_from_seed(w2))
        led = os.path.join(self.tmp, "l.jsonl"); _write(led, _ledger(6))
        text, _ = C.ledger_checkpoint(led, LOG)
        note = C.sign_note(text, LOG, ls)
        rc, out = self._oracle(note, LV)
        self.assertEqual(rc, 0, out); self.assertIn("VERIFIED sigs=1 unverified=0", out); self.assertIn("TEXT:\n" + text, out)
        st = os.path.join(self.tmp, "w1.json")
        cs = W.witness_cosign(st, note, LV, "witness.example/w1", w1, None, T0)["note"]
        cs = W.witness_cosign(st + "2", cs, LV, "witness.example/w2", w2, None, T0 + 1)["note"]
        rc, out = self._oracle(cs, LV, W1V, W2V)
        self.assertEqual(rc, 0, out); self.assertIn("VERIFIED sigs=3 unverified=0", out)
        # Python and Go agree on the same bytes
        self.assertEqual(W.verify_witnessed(cs, LV, [W1V, W2V], 2)["stato"], "OK")
        # positive controls: tampered size → both refuse; a cosigner that did not sign → Go refuses (MISSING)
        bad = cs.replace(b"\n6\n", b"\n7\n", 1)
        rc, out = self._oracle(bad, LV, W1V, W2V)
        self.assertEqual(rc, 1, out); self.assertIn("invalid signature", out)
        self.assertEqual(W.verify_witnessed(bad, LV, [W1V, W2V], 2)["stato"], "NON_VALIDA")
        one = W.witness_cosign(st + "3", note, LV, "witness.example/w1", w1, None, T0)["note"]
        rc, out = self._oracle(one, LV, W1V, W2V)
        self.assertEqual(rc, 1, out); self.assertIn("MISSING SIGNATURE from witness.example/w2", out)
        # an origin with spaces signed by a key of another name (sum.golang.org style): Go and we agree
        gs = C.sign_note("go.sum database tree\n5\n" + base64.b64encode(bytes(32)).decode() + "\n", LOG, ls)
        gs = W.witness_cosign(st + "4", gs, LV, "witness.example/w1", w1, None, T0, expected_origin="go.sum database tree")["note"]
        rc, out = self._oracle(gs, LV, W1V)
        self.assertEqual(rc, 0, out); self.assertIn("TEXT:\ngo.sum database tree\n5\n", out)
        self.assertEqual(W.verify_witnessed(gs, LV, [W1V], expected_origin="go.sum database tree")["stato"], "OK")
        # 100 unknown-key lines: both open it; 101: both refuse
        pad = "".join("— x AAAAAAAAAA==\n" for _ in range(99)).encode()
        rc, out = self._oracle(note + pad, LV); self.assertEqual(rc, 0, out)
        self.assertIn("VERIFIED sigs=1 unverified=1", out)                   # Go collapses identical unknown lines to one
        self.assertEqual(C.verify_note(note + pad, [LV])["ignored"], 99)   # we count lines
        # a bogus repeat of the LOG key after its good line: Go opens the note (drops repeats), we refuse (spec MUST verify)
        _, lsigs = C.split_note(note)
        bogus = note + f"— {LOG} {base64.b64encode(lsigs[0][1][:4] + bytes(64)).decode()}\n".encode()
        rc, out = self._oracle(bogus, LV); self.assertEqual(rc, 0, out)
        self.assertEqual(C.verify_note(bogus, [LV])["stato"], "NON_VALIDA")
        rc, out = self._oracle(note + pad + b"\xe2\x80\x94 y AAAAAAAAAA==\n", LV); self.assertEqual(rc, 1, out)
        self.assertEqual(C.verify_note(note + pad + "— y AAAAAAAAAA==\n".encode(), [LV])["stato"], "NON_VALIDA")
        # a padded first checkpoint (99 unknown lines) then a fork: the stored `precedente` of the split-view pair is
        # stripped to text + log line + witness line, and Go opens it (positive control of the "anyone can check" claim)
        fork = os.path.join(self.tmp, "fork.jsonl"); _write(fork, _ledger(6, "z"))
        nfk = C.sign_note(C.ledger_checkpoint(fork, LOG)[0], LOG, ls)
        st5 = os.path.join(self.tmp, "w5.json")
        W.witness_cosign(st5, note + "".join(f"— pad{i} AAAAAAAAAA==\n" for i in range(98)).encode(), LV, "witness.example/w1", w1, None, T0)
        ev = W.witness_cosign(st5, nfk, LV, "witness.example/w1", w1, None, T0 + 1)["evidenza"]
        self.assertEqual(ev["tipo"], "split-view")
        rc, out = self._oracle(ev["precedente"].encode(), LV, W1V); self.assertEqual(rc, 0, out); self.assertIn("sigs=2", out)
        rc, out = self._oracle(ev["presentato"].encode(), LV); self.assertEqual(rc, 0, out)
        # a cosignature over a one-line text: Go refuses (cosigned note format) and so do we
        oneline = C.sign_note("x\n", LOG, ls)
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        sig1 = Ed25519PrivateKey.from_private_bytes(w1).sign(f"cosignature/v1\ntime {T0}\n".encode() + b"x\n")
        one_cs = oneline + f"— witness.example/w1 {base64.b64encode(C.parse_vkey(W1V)[1] + struct.pack('>Q', T0) + sig1).decode()}\n".encode()
        rc, out = self._oracle(one_cs, LV, W1V); self.assertEqual(rc, 1, out)
        self.assertEqual(C.verify_note(one_cs, [LV, W1V])["stato"], "NON_VALIDA")
        # the two timestamp divergences, MEASURED on the oracle: Go verifies ts = 0 and ts = 2^63, we refuse both
        kidw = C.parse_vkey(W1V)[1]
        for tsx in (0, 2 ** 63):
            sgx = Ed25519PrivateKey.from_private_bytes(w1).sign(f"cosignature/v1\ntime {tsx}\n".encode() + text.encode())
            nx = note + f"— witness.example/w1 {base64.b64encode(kidw + struct.pack('>Q', tsx) + sgx).decode()}\n".encode()
            rc, out = self._oracle(nx, LV, W1V); self.assertEqual(rc, 0, out)
            self.assertEqual(C.verify_note(nx, [LV, W1V])["stato"], "NON_VALIDA")
        # extension lines are inside the cosigned bytes for both (tamper one → both refuse)
        ext = C.sign_note(C.checkpoint_text(LOG, 6, hashlib.sha256(b"r").digest(), ["ext one", "ext two"]), LOG, ls)
        ext = W.witness_cosign(st + "5", ext, LV, "witness.example/w1", w1, None, T0)["note"]
        rc, out = self._oracle(ext, LV, W1V); self.assertEqual(rc, 0, out); self.assertIn("sigs=2", out)
        rc, out = self._oracle(ext.replace(b"ext two", b"ext tw0"), LV, W1V); self.assertEqual(rc, 1, out)
        self.assertEqual(C.verify_note(ext.replace(b"ext two", b"ext tw0"), [LV, W1V])["stato"], "NON_VALIDA")
        # REAL Rekor v1 checkpoints (ECDSA log key): opened by formats' NewECDSAVerifier, refused when tampered
        d = os.path.join(HERE, "examples", "checkpoints"); rvk = open(os.path.join(d, "rekor_v1.vkey")).read().strip()
        for f in sorted(x for x in os.listdir(d) if x.endswith(".note")):
            with open(os.path.join(d, f), "rb") as fh:
                rn = fh.read()
            rc, out = self._oracle(rn, rvk); self.assertEqual(rc, 0, out); self.assertIn("VERIFIED sigs=1", out)
            rc, out = self._oracle(rn.replace(b"dev - ", b"dev -  ", 1), rvk)   # origin altered: the log signature fails
            self.assertEqual(rc, 1, out)
        # an ML-DSA-44 cosignature emitted here opens with formats' NewMLDSAVerifier (Go: filippo.io/mldsa)
        pk = os.path.join(self.tmp, "pq.key"); signer.keygen(pk); ps = C.load_seed_hex(pk)
        MV = C.vkey("witness.example/w1", C.TYPE_MLDSA44, C.mldsa44_pubkey_from_seed(ps))
        pqn = W.witness_cosign(st + "6", note, LV, "witness.example/w1", w1, None, T0, pq_seed=ps)["note"]
        rc, out = self._oracle(pqn, LV, W1V, MV); self.assertEqual(rc, 0, out); self.assertIn("VERIFIED sigs=3 unverified=0", out)
        rc, out = self._oracle(pqn.replace(b"\n6\n", b"\n7\n", 1), LV, MV); self.assertEqual(rc, 1, out)
        # a forged cosignature timestamp → Go refuses too
        _, sigs = C.split_note(one)
        raw = sigs[1][1]; forged = raw[:4] + struct.pack(">Q", T0 + 1) + raw[12:]
        forged_note = note + f"— witness.example/w1 {base64.b64encode(forged).decode()}\n".encode()
        rc, out = self._oracle(forged_note, LV, W1V)
        self.assertEqual(rc, 1, out)
        self.assertEqual(C.verify_note(forged_note, [LV, W1V])["stato"], "NON_VALIDA")


if __name__ == "__main__":
    unittest.main(verbosity=1)
