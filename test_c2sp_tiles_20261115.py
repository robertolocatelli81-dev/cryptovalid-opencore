#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Tiles of C2SP tiled logs (SPEC §14, 2026-11-15): cryptovalid_merkle.verify_tiles and `cryptovalid_checkpoint.py tiles`.

Real vectors (testdata/interop/README.md: source, commit, SHA-256): the mirror of sunlight's skylight test (a checkpoint
of size 300 cosigned by the mirror, its three hash tiles, two placeholder entry bundles) and four level-0 tiles, a partial
one and a partial data tile of sunlight's navigli2025h2 static CT test log. Generated trees are written here by a writer
that follows the specifications, independently of the code under test; where Go is installed the same directories go to
golang.org/x/mod/sumdb/tlog, filippo.io/sunlight and filippo.io/torchwood (verifiers/tile_oracle). CV_REQUIRE_GO_ORACLE=1
makes a missing Go an error.
"""
import base64
import contextlib
import gzip
import hashlib
import io
import json
import os
import random
import shutil
import struct
import subprocess
import tempfile
import unittest
import zlib

import cryptovalid_checkpoint as C
import cryptovalid_merkle as M

HERE = os.path.dirname(os.path.abspath(__file__))
D = os.path.join(HERE, "testdata", "interop")
MIRROR = os.path.join(D, "sunlight_mirror")
NAVIGLI = os.path.join(D, "sunlight_navigli2025h2")
ORACLE_SRC = os.path.join(HERE, "verifiers", "tile_oracle")
MIRROR_VKEY = "mirror.example.org+3fb148ef+BAAjjch9GyYz0sJsJx7ALhbdAtz2ov0unbzSl1vMp94O"
SHA = {
    "sunlight_mirror/checkpoint": "d37ad4091828765077feca2d13144ad113fccbbed6c9c07a7c025dd8a22eb499",
    "sunlight_mirror/mirror.v0.json": "833f141b74ac62e7ec2b428ba6f5cf4590bdd566854c418d8f4f26217676debf",
    "sunlight_mirror/tile/0/000": "66a1d43136a854a5776d5bce14bf101c925fc7d4b32f1be23b658f636ebfcddb",
    "sunlight_mirror/tile/0/001.p/44": "699f078d937f13343d71ad39321757de3ecf391e8d7a1b2015ad38bd36f5d60a",
    "sunlight_mirror/tile/1/000.p/1": "dcef9e571841bfe2defd16306f8a7d69f5054092fb8b7f983970c646f7f5fd85",
    "sunlight_mirror/tile/entries/000": "71709ad55def7d1c2fa90f7406780f9661609670c2c60fedfeb9073b4d48fb4a",
    "sunlight_mirror/tile/entries/001.p/44": "87581195f844c6fae65415415f9a890389d876111f2462fa4790ba525eb05348",
    "sunlight_navigli2025h2/tile/0/000": "e5c3ffabecae72a973749908a59f45b80705d04daabf39710c5a3c009bd66c1d",
    "sunlight_navigli2025h2/tile/0/001": "971b3762c5495625fefab0b506c41fed12c05dd5144f054a00dae42dd49ad229",
    "sunlight_navigli2025h2/tile/0/002": "4b3afc555b91ce49f89144cfe36ddf272ce06c5feb7354c4b3a977e3202d4da0",
    "sunlight_navigli2025h2/tile/0/003": "77d22deace823b0c21489d812d32d1463ef666af71df773dc50bbc0471679192",
    "sunlight_navigli2025h2/tile/0/003.p/10": "27274134f3c3dc32dec34a01254a3e40e650b7c96b89a87c7edacc355e43168b",
    "sunlight_navigli2025h2/tile/data/003.p/10": "9c696be7ee1df84ad841a6946bbe6305e4e491060630c528f7a49c4cb67e48e6",
}
try:
    import cryptography  # noqa: F401
    HAVE_CRYPTO = True
except ImportError:
    HAVE_CRYPTO = False
if os.environ.get("CV_REQUIRE_GO_ORACLE") == "1" and not HAVE_CRYPTO:
    raise SystemExit("CV_REQUIRE_GO_ORACLE=1 needs `cryptography` (the checkpoint tests would be skipped)")


def _read(rel):
    with open(os.path.join(D, rel), "rb") as f:
        return f.read()


# ── an independent writer, from the specifications ─────────────────────────────────────────────────────────────────
def lh(data):
    return hashlib.sha256(b"\x00" + data).digest()


def nh(a, b):
    return hashlib.sha256(b"\x01" + a + b).digest()


def mth(hs):                             # RFC 6962 §2.1 over leaf hashes, written again here
    if not hs:
        return hashlib.sha256(b"").digest()
    if len(hs) == 1:
        return hs[0]
    k = 1
    while k * 2 < len(hs):
        k *= 2
    return nh(mth(hs[:k]), mth(hs[k:]))


def index_path(n):
    s = "%d" % n
    s = "0" * (-len(s) % 3) + s
    groups = [s[i:i + 3] for i in range(0, len(s), 3)]
    return "/".join(["x" + g for g in groups[:-1]] + [groups[-1]])


def tile_rel(level, n, w):
    return "tile/%s/%s%s" % (level, index_path(n), "" if w == 256 else ".p/%d" % w)


def ct_entry(index, rnd, ext=None, entry_type=None):
    """(TileLeaf bytes, leaf input): a TimestampedEntry with its leaf_index, as static-ct-api defines it."""
    et = rnd.choice([0, 1]) if entry_type is None else entry_type
    ts = struct.pack(">Q", rnd.randrange(2 ** 63))
    cert = bytes(rnd.randrange(256) for _ in range(rnd.randrange(1, 40)))
    if ext is None:
        ext = b"\x00\x00\x05" + index.to_bytes(5, "big")
    signed = (struct.pack(">H", 0) + len(cert).to_bytes(3, "big") + cert if et == 0 else
              struct.pack(">H", 1) + bytes(32) + len(cert).to_bytes(3, "big") + cert)
    te = ts + signed + struct.pack(">H", len(ext)) + ext
    extra = b""
    if et == 1:
        pre = bytes(rnd.randrange(256) for _ in range(rnd.randrange(1, 30)))
        extra = len(pre).to_bytes(3, "big") + pre
    chain = bytes(rnd.randrange(256) for _ in range(32 * rnd.randrange(0, 3)))
    return te + extra + struct.pack(">H", len(chain)) + chain, b"\x00\x00" + te


def write_tree(root_dir, size, profile, rnd, keep_partials=True, full_size=None, gz=False):
    """Writes the tiles of a log of `full_size` entries (default `size`) and the partial tiles for `size`; returns the
    leaf hashes of the first `size` entries and the bytes of every entry."""
    full_size = size if full_size is None else full_size
    entries, leaves = [], []
    for i in range(full_size):
        if profile == "static-ct-api":
            tl, leaf_input = ct_entry(i, rnd)
            entries.append(tl); leaves.append(lh(leaf_input))
        else:
            e = bytes(rnd.randrange(256) for _ in range(rnd.randrange(0, 60)))
            entries.append(struct.pack(">H", len(e)) + e); leaves.append(lh(e))
    edir = "data" if profile == "static-ct-api" else "entries"

    def put(rel, b):
        p = os.path.join(root_dir, *rel.split("/"))
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "wb") as f:
            f.write(gzip.compress(b, mtime=0) if gz and rel.startswith("tile/" + edir) else b)

    for s in sorted({size, full_size}):
        level_hashes = leaves[:s]; level = 0
        while len(level_hashes) > 0:
            for n in range((len(level_hashes) + 255) // 256):
                chunk = level_hashes[n * 256:(n + 1) * 256]
                if len(chunk) < 256 and not (keep_partials or s == full_size):
                    continue
                put(tile_rel(level, n, len(chunk)), b"".join(chunk))
                if level == 0:
                    put(tile_rel(edir, n, len(chunk)), b"".join(entries[n * 256:n * 256 + len(chunk)]))
            level_hashes = [mth(level_hashes[j * 256:(j + 1) * 256]) for j in range(len(level_hashes) // 256)]
            level += 1
    return leaves[:size], entries


def unbound_spans(data, width):
    """Byte ranges of a data tile that no leaf hash covers: the content of pre_certificate and of certificate_chain
    (static-ct-api: TileLeaf carries them beside the TimestampedEntry, which alone is hashed)."""
    spans, p = [], 0
    for _ in range(width):
        et = struct.unpack(">H", data[p + 8:p + 10])[0]; p += 10
        if et == 1:
            p += 32
        n = int.from_bytes(data[p:p + 3], "big"); p += 3 + n
        n = struct.unpack(">H", data[p:p + 2])[0]; p += 2 + n
        if et == 1:
            n = int.from_bytes(data[p:p + 3], "big"); spans.append(range(p + 3, p + 3 + n)); p += 3 + n
        n = struct.unpack(">H", data[p:p + 2])[0]; spans.append(range(p + 2, p + 2 + n)); p += 2 + n
    return spans


class Vectors(unittest.TestCase):
    def test_bytes_are_the_pinned_ones(self):
        for rel, h in SHA.items():
            self.assertEqual(hashlib.sha256(_read(rel)).hexdigest(), h, rel)

    def test_mirror_root_from_the_tiles(self):
        text = C.split_note(_read("sunlight_mirror/checkpoint"))[0]
        cp = C.parse_checkpoint(text)
        r = M.verify_tiles(MIRROR, cp["size"], cp["root"], "tlog-tiles", entries=False)
        self.assertEqual((r["stato"], r["root"], r["tiles_read"], r["upper_missing"]), ("OK", cp["root"].hex(), 3, 0), r)
        r = M.verify_tiles(MIRROR, cp["size"], cp["root"], "static-ct-api", entries=False)   # same hash tiles
        self.assertEqual(r["stato"], "OK")
        other = bytes([cp["root"][0] ^ 1]) + cp["root"][1:]
        r = M.verify_tiles(MIRROR, cp["size"], other, "tlog-tiles", entries=False)
        self.assertEqual(r["motivo"], "the root computed from the level-0 tiles differs from the checkpoint's")
        for size in (299, 301, 256, 512):
            self.assertEqual(M.verify_tiles(MIRROR, size, cp["root"], "tlog-tiles", entries=False)["stato"], "NON_VALIDA", size)

    def test_mirror_placeholder_entries_are_refused(self):
        cp = C.parse_checkpoint(C.split_note(_read("sunlight_mirror/checkpoint"))[0])
        r = M.verify_tiles(MIRROR, cp["size"], cp["root"], "tlog-tiles")
        self.assertEqual(r["stato"], "NON_VALIDA")
        self.assertIn("entry bundle entry 0", r["motivo"])
        r = M.verify_tiles(MIRROR, cp["size"], cp["root"], "tlog-tiles", encoding="identity")
        self.assertIn("entry bundle entry 0", r["motivo"])

    @unittest.skipUnless(HAVE_CRYPTO, "cryptography")
    def test_mirror_command_line(self):
        def run(*args):
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                rc = C.main(["tiles", MIRROR, "--vkey", MIRROR_VKEY, "--profile", "tlog-tiles", *args])
            return rc, json.loads(out.getvalue())
        rc, out = run("--no-entries")
        self.assertEqual((rc, out["stato"], out["tiles"]["entries"]), (0, "OK", False))
        self.assertEqual(out["checkpoint"]["verified"][0]["name"], "mirror.example.org")
        rc, out = run()
        self.assertEqual((rc, out["stato"], out["tiles"]["stato"]), (1, "NON_VALIDA", "NON_VALIDA"))
        rc, out = run("--no-entries", "--checkpoint", os.path.join(D, "sunlight_rome2026h1.checkpoint"))
        self.assertEqual((rc, out["stato"], out["tiles"]), (1, "NON_VALIDA", None))   # no trusted signature: no tiles read
        self.assertEqual(json.loads(json.dumps(out))["checkpoint"]["motivo"], "no signature from a known key")
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            rc = C.main(["tiles", os.path.join(D, "nowhere"), "--vkey", MIRROR_VKEY, "--profile", "tlog-tiles"])
        self.assertEqual((rc, json.loads(out.getvalue())["stato"]), (2, "ERRORE"))
        tmp = tempfile.mkdtemp()                                       # a checkpoint that is not a regular file of at
        try:                                                           # most 1 MiB: refused before it is read, exit 2
            from test_platforms_20261124 import DEVICE, fifo as make_fifo   # Windows: a named pipe and NUL
            fifo = make_fifo(self, os.path.join(tmp, "fifo"))
            big = os.path.join(tmp, "big")
            with open(big, "wb") as f:
                f.truncate(C.MAX_NOTE_FILE + 1)
            for cp in (fifo, big, tmp, DEVICE):
                for argv in (["tiles", MIRROR, "--vkey", MIRROR_VKEY, "--profile", "tlog-tiles", "--checkpoint", cp],
                             ["verify", cp, "--vkey", MIRROR_VKEY]):
                    if cp == "/dev/zero" and not os.path.exists(cp):
                        continue
                    out = io.StringIO()
                    with contextlib.redirect_stdout(out):
                        rc = C.main(argv)
                    self.assertEqual((rc, json.loads(out.getvalue())["stato"]), (2, "ERRORE"), (cp, argv[0]))
            self.assertEqual(C.read_note_file(os.path.join(MIRROR, "checkpoint")), _read("sunlight_mirror/checkpoint"))
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
        for bad in (["--vkey", MIRROR_VKEY, "--profile", "other"], ["--vkey", MIRROR_VKEY, "--entries-encoding", "zstd",
                    "--profile", "tlog-tiles"], ["--vkey", MIRROR_VKEY], ["--profile", "tlog-tiles"]):
            with self.assertRaises(SystemExit) as cm, contextlib.redirect_stderr(io.StringIO()):
                C.main(["tiles", MIRROR, *bad])
            self.assertEqual(cm.exception.code, 2, bad)

    def test_navigli_level0_and_data(self):
        full = [M.read_hash_tile(_read("sunlight_navigli2025h2/tile/0/%03d" % n), 256) for n in range(4)]
        part = M.read_hash_tile(_read("sunlight_navigli2025h2/tile/0/003.p/10"), 10)
        self.assertEqual(part, full[3][:10])
        data = _read("sunlight_navigli2025h2/tile/data/003.p/10")
        self.assertEqual(M.parse_data_tile(data, 10, 768), part)          # 10 real precertificates
        with self.assertRaises(M.TileError) as cm:
            M.parse_data_tile(data, 10, 0)                               # the entries carry their own index
        self.assertIn("leaf_index 768, the entry is at index 0", str(cm.exception))
        hashes = [h for t in full for h in t]
        for size in (1, 10, 255, 256, 257, 768, 778, 1024):
            r = M.verify_tiles(NAVIGLI, size, mth(hashes[:size]), "static-ct-api", entries=False)
            self.assertEqual(r["stato"], "OK", (size, r))
            self.assertEqual(r["upper_missing"], 0 if size < 256 else 1, size)   # navigli ships no level-1 tile
        r = M.verify_tiles(NAVIGLI, 778, None, "static-ct-api", entries=True)
        self.assertEqual(r["motivo"], "tile/data/000: missing")
        self.assertEqual(M.verify_tiles(NAVIGLI, 1025, None, "static-ct-api", entries=False)["motivo"], "tile/0/004.p/1: missing")

    def test_navigli_data_every_truncation_and_byte(self):
        data = _read("sunlight_navigli2025h2/tile/data/003.p/10")
        want = M.read_hash_tile(_read("sunlight_navigli2025h2/tile/0/003.p/10"), 10)
        for n in range(len(data)):                                     # every truncation: a reason
            with self.assertRaises(M.TileError):
                M.parse_data_tile(data[:n], 10, 768)
        with self.assertRaises(M.TileError) as cm:
            M.parse_data_tile(data + b"\x00", 10, 768)
        self.assertIn("1 bytes after the 10 entries", str(cm.exception))
        rnd = random.Random(1115)
        unbound = unbound_spans(data, 10)
        self.assertGreater(sum(len(r) for r in unbound), 10 * 32)    # precertificates and chains: most of the tile
        same = 0
        for pos in sorted(rnd.sample(range(len(data)), 1500)) + list(range(0, 80)):
            b = bytearray(data); b[pos] ^= 1 << rnd.randrange(8)
            try:
                got = M.parse_data_tile(bytes(b), 10, 768)
            except M.TileError:
                continue
            if any(pos in r for r in unbound):                           # outside every leaf: nothing binds it (SPEC §14)
                self.assertEqual(got, want, pos); same += 1
            else:
                self.assertNotEqual(got, want, pos)                      # parsed, then the leaf hashes decide
        self.assertGreater(same, 0)


class Paths(unittest.TestCase):
    def test_index_path(self):
        self.assertEqual(M.tile_index_path(1234067), "x001/x234/067")
        self.assertEqual(M.tile_path(0, 1234067, 17), "tile/0/x001/x234/067.p/17")
        self.assertEqual(M.tile_path("data", 5), "tile/data/005")
        rnd = random.Random(3)
        for n in [0, 1, 999, 1000, 1001, 999999, 10 ** 6, 2 ** 40] + [rnd.randrange(2 ** 63) for _ in range(500)]:
            self.assertEqual(M.tile_index_path(n), index_path(n), n)
        for bad in (-1, 1.0, "1", True, None):
            with self.assertRaises(M.TileError):
                M.tile_index_path(bad)
        for level, w in ((64, 1), (-1, 1), ("names", 1), (0, 0), (0, 257), (0, True), (True, 3)):
            with self.assertRaises(M.TileError, msg=(level, w)):
                M.tile_path(level, 0, w)

    def test_hash_tile_lengths(self):
        for w in range(1, 257):
            for n in (0, 32 * w - 1, 32 * w + 1, 32 * (w + 1)):
                with self.assertRaises(M.TileError):
                    M.read_hash_tile(bytes(n), w)
            self.assertEqual(len(M.read_hash_tile(bytes(32 * w), w)), w)


class Generated(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def d(self, name):
        p = os.path.join(self.tmp, name); os.makedirs(p, exist_ok=True)
        return p

    def test_sizes_both_profiles(self):
        rnd = random.Random(11)
        sizes = [0, 1, 2, 3, 255, 256, 257, 300, 511, 512, 513, 767, 768, 769, 65535, 65536, 65537]
        for profile in ("tlog-tiles", "static-ct-api"):
            for size in sizes:
                if profile == "static-ct-api" and size > 1100:
                    continue                                           # data tiles: the bound is time, not the rule
                d = self.d("%s-%d" % (profile, size))
                leaves, _ = write_tree(d, size, profile, rnd)
                root = mth(leaves)
                r = M.verify_tiles(d, size, root, profile, entries=size < 1100)
                self.assertEqual((r["stato"], r["root"], r["upper_missing"]), ("OK", root.hex(), 0), (profile, size, r))
                self.assertEqual(r["entries_checked"], size if size < 1100 else 0)
                if size:                                               # one leaf more than the log has: a tile is missing
                    self.assertIn("missing", M.verify_tiles(d, size + 1, None, profile, entries=False)["motivo"])

    def test_partial_from_full_and_both_present(self):
        rnd = random.Random(12)
        for profile in ("tlog-tiles", "static-ct-api"):
            d = self.d(profile)
            leaves, _ = write_tree(d, 300, profile, rnd, keep_partials=False, full_size=600)
            r = M.verify_tiles(d, 300, mth(leaves), profile)
            # level 0 and the entries come from the full tiles of index 1; the level-1 partial of a tree of 300 has no
            # full tile before 65,536 entries, and the writer did not keep it: counted, not passed over
            self.assertEqual((r["stato"], r["partial_from_full"], r["upper_missing"]), ("OK", 2, 1), r)
            d2 = self.d(profile + "-both")
            leaves, _ = write_tree(d2, 300, profile, rnd, keep_partials=True, full_size=600)
            self.assertEqual(M.verify_tiles(d2, 300, mth(leaves), profile)["partial_from_full"], 0)
            p = os.path.join(d2, "tile", "0", "001.p", "44")
            b = bytearray(open(p, "rb").read()); b[0] ^= 1
            open(p, "wb").write(bytes(b))
            r = M.verify_tiles(d2, 300, None, profile, entries=False)
            self.assertEqual(r["motivo"], "tile/0/001.p/44 is not the prefix of tile/0/001")

    def test_upper_tile_missing_or_wrong(self):
        rnd = random.Random(13)
        d = self.d("u")
        leaves, _ = write_tree(d, 70000, "tlog-tiles", rnd)
        root = mth(leaves)
        r = M.verify_tiles(d, 70000, root, "tlog-tiles", entries=False)
        self.assertEqual((r["stato"], r["tiles_read"]), ("OK", 274 + 2 + 1), r)   # the example of the specification
        os.remove(os.path.join(d, "tile", "2", "000.p", "1"))
        r = M.verify_tiles(d, 70000, root, "tlog-tiles", entries=False)
        self.assertEqual((r["stato"], r["upper_missing"]), ("OK", 1))
        p = os.path.join(d, "tile", "1", "000")
        b = bytearray(open(p, "rb").read()); b[32 * 7] ^= 1
        open(p, "wb").write(bytes(b))
        r = M.verify_tiles(d, 70000, root, "tlog-tiles", entries=False)
        self.assertEqual(r["motivo"], "tile/1/000: hash 7 is not the root of the 256 hashes of level 0 below it")
        # a missing upper tile does not end its level: the next one is still read and checked, and counted when absent
        os.replace(p, p + ".bad")
        q = os.path.join(d, "tile", "1", "001.p", "17")
        b = bytearray(open(q, "rb").read()); b[0] ^= 1
        open(q, "wb").write(bytes(b))
        r = M.verify_tiles(d, 70000, root, "tlog-tiles", entries=False)
        self.assertEqual(r["motivo"], "tile/1/001.p/17: hash 0 is not the root of the 256 hashes of level 0 below it")
        os.remove(q)
        r = M.verify_tiles(d, 70000, root, "tlog-tiles", entries=False)
        self.assertEqual((r["stato"], r["upper_missing"]), ("OK", 3))

    def test_every_alteration_of_a_small_tree(self):
        rnd = random.Random(14)
        for profile in ("tlog-tiles", "static-ct-api"):
            d = self.d(profile)
            leaves, _ = write_tree(d, 300, profile, rnd)
            root = mth(leaves)
            r = M.verify_tiles(d, 300, root, profile)
            self.assertEqual((r["stato"], r["tiles_read"], r["entries_checked"]), ("OK", 5, 300))
            files = sorted(os.path.relpath(os.path.join(a, f), d) for a, _, fs in os.walk(d) for f in fs)
            self.assertEqual(len(files), 5)
            for rel in files:
                p = os.path.join(d, rel)
                orig = open(p, "rb").read()
                cuts = sorted(set([0, 1, len(orig) - 1, len(orig) + 1] + rnd.sample(range(len(orig)), min(60, len(orig)))))
                for n in cuts:
                    open(p, "wb").write(orig[:n] if n <= len(orig) else orig + b"\x00")
                    r = M.verify_tiles(d, 300, root, profile)
                    self.assertEqual(r["stato"], "NON_VALIDA", (rel, n)); self.assertTrue(r["motivo"])
                width = 256 if rel.endswith("000") else 44
                unbound = unbound_spans(orig, width) if rel.startswith(os.path.join("tile", "data")) else []
                for pos in rnd.sample(range(len(orig)), min(80, len(orig))):
                    b = bytearray(orig); b[pos] ^= 1 << rnd.randrange(8)
                    open(p, "wb").write(bytes(b))
                    r = M.verify_tiles(d, 300, root, profile)
                    if any(pos in u for u in unbound):
                        continue                                         # pre_certificate / chain content: unbound
                    self.assertEqual(r["stato"], "NON_VALIDA", (rel, pos)); self.assertTrue(r["motivo"])
                os.remove(p)
                r = M.verify_tiles(d, 300, root, profile)
                self.assertIn("missing", r["motivo"], rel) if not rel.startswith(os.path.join("tile", "1")) else \
                    self.assertEqual((r["stato"], r["upper_missing"]), ("OK", 1))
                os.mkdir(p)
                self.assertIn("not a regular file", M.verify_tiles(d, 300, root, profile)["motivo"], rel)
                os.rmdir(p)
                with open(p + ".real", "wb") as f:
                    f.write(orig)
                os.symlink(p + ".real", p)
                self.assertIn("not a regular file", M.verify_tiles(d, 300, root, profile)["motivo"], rel)
                os.remove(p); os.remove(p + ".real")
                with open(p, "wb") as f:
                    f.write(orig)
            self.assertEqual(M.verify_tiles(d, 300, root, profile)["stato"], "OK")

    def test_static_ct_extensions_and_types(self):
        rnd = random.Random(15)
        good = b"\x00\x00\x05" + (0).to_bytes(5, "big")
        cases = {
            "no leaf_index": (b"", "no leaf_index extension"),
            "twice": (good + good, "extension type 0 appears twice"),
            "unknown type": (good + b"\x01\x00\x00", "extension type 1 is not leaf_index"),
            "unknown first": (b"\x07\x00\x01\x00" + good, "extension type 7 is not leaf_index"),
            "short index": (b"\x00\x00\x04" + bytes(4), "leaf_index of 4 bytes"),
            "long index": (b"\x00\x00\x06" + bytes(6), "leaf_index of 6 bytes"),
            "other index": (b"\x00\x00\x05" + (1).to_bytes(5, "big"), "leaf_index 1, the entry is at index 0"),
            "cut header": (b"\x00\x00", "extension data length needs 2 bytes"),
            "cut data": (b"\x00\x00\x05\x00", "extension data needs 5 bytes"),
        }
        for what, (ext, reason) in cases.items():
            tl, _ = ct_entry(0, rnd, ext=ext)
            with self.assertRaises(M.TileError, msg=what) as cm:
                M.parse_data_tile(tl, 1, 0)
            self.assertIn(reason, str(cm.exception), what)
        for et in [2, 3, 255, 256, 65535]:
            tl, _ = ct_entry(0, rnd, entry_type=0)
            tl = tl[:8] + struct.pack(">H", et) + tl[10:]
            with self.assertRaises(M.TileError) as cm:
                M.parse_data_tile(tl, 1, 0)
            self.assertIn("entry_type %d is neither" % et, str(cm.exception))
        tl, _ = ct_entry(0, rnd, entry_type=1)                         # empty pre_certificate
        p = 10 + 32; p += 3 + int.from_bytes(tl[p:p + 3], "big"); p += 2 + struct.unpack(">H", tl[p:p + 2])[0]
        n = int.from_bytes(tl[p:p + 3], "big")
        with self.assertRaises(M.TileError) as cm:
            M.parse_data_tile(tl[:p] + b"\x00\x00\x00" + tl[p + 3 + n:], 1, 0)
        self.assertIn("pre_certificate of 0 bytes, at least 1 required", str(cm.exception))
        two = ct_entry(0, rnd)[0] + ct_entry(1, rnd)[0]
        with self.assertRaises(M.TileError) as cm:
            M.parse_data_tile(two[:-1], 2, 0)
        self.assertTrue(str(cm.exception).startswith("data tile entry 1: "), str(cm.exception))
        for et in (0, 1):                                              # empty certificate, TBS, pre_certificate: <1..2^24-1>
            tl, _ = ct_entry(0, rnd, entry_type=et)
            p = 10 + (32 if et else 0)
            n = int.from_bytes(tl[p:p + 3], "big")
            with self.assertRaises(M.TileError) as cm:
                M.parse_data_tile(tl[:p] + b"\x00\x00\x00" + tl[p + 3 + n:], 1, 0)
            self.assertIn("at least 1 required", str(cm.exception))
        x, _ = ct_entry(0, rnd, entry_type=0)                          # certificate_chain not a list of 32-byte values
        te_end = 10 + 3 + int.from_bytes(x[10:13], "big") + 2 + 8
        n = struct.unpack(">H", x[te_end:te_end + 2])[0]
        for extra in (1, 31, 33):
            mod = x[:te_end] + struct.pack(">H", n + extra) + x[te_end + 2:] + bytes(extra)
            with self.assertRaises(M.TileError) as cm:
                M.parse_data_tile(mod, 1, 0)
            self.assertIn("not a list of 32-byte fingerprints", str(cm.exception))

    def test_entry_bundle_lengths(self):
        rnd = random.Random(16)
        es = [bytes(rnd.randrange(256) for _ in range(rnd.randrange(0, 50))) for _ in range(7)]
        b = b"".join(struct.pack(">H", len(e)) + e for e in es)
        self.assertEqual(M.parse_entry_bundle(b, 7), [lh(e) for e in es])
        for n in range(len(b)):
            with self.assertRaises(M.TileError):
                M.parse_entry_bundle(b[:n], 7)
        with self.assertRaises(M.TileError):
            M.parse_entry_bundle(b, 6)
        with self.assertRaises(M.TileError) as cm:
            M.parse_entry_bundle(b"\x00\x05ab", 1)
        self.assertEqual(str(cm.exception), "entry bundle entry 0: entry needs 5 bytes, 2 left")
        self.assertEqual(M.parse_entry_bundle(b"\x00\x00", 1), [lh(b"")])
        big = bytes(65535)
        self.assertEqual(M.parse_entry_bundle(b"\xff\xff" + big, 1), [lh(big)])

    def test_encodings(self):
        rnd = random.Random(17)
        d = self.d("gz")
        leaves, entries = write_tree(d, 300, "tlog-tiles", rnd, gz=True)
        root = mth(leaves)
        self.assertEqual(M.verify_tiles(d, 300, root, "tlog-tiles")["stato"], "OK")
        self.assertEqual(M.verify_tiles(d, 300, root, "tlog-tiles", encoding="gzip")["stato"], "OK")
        self.assertEqual(M.verify_tiles(d, 300, root, "tlog-tiles", encoding="identity")["stato"], "NON_VALIDA")
        p = os.path.join(d, "tile", "entries", "000")
        raw = b"".join(entries[:256]); z = gzip.compress(raw, mtime=0)
        for content, reason in ((z + z, "bytes after the gzip member"), (z[:-5], "gzip stream truncated"),
                                (z + b"junk", "bytes after the gzip member"), (b"\x1f\x8bxxxxxxxx", "not gzip")):
            open(p, "wb").write(content)
            r = M.verify_tiles(d, 300, root, "tlog-tiles")
            self.assertIn(reason, r["motivo"])
        open(p, "wb").write(gzip.compress(bytes(M.MAX_TILE_FILE + 1), mtime=0))
        self.assertIn("once decompressed", M.verify_tiles(d, 300, root, "tlog-tiles")["motivo"])
        open(p, "wb").write(raw)                                       # identity on disk, read by auto
        self.assertEqual(M.verify_tiles(d, 300, root, "tlog-tiles")["stato"], "OK")
        self.assertIn("not gzip", M.verify_tiles(d, 300, root, "tlog-tiles", encoding="gzip")["motivo"])

    def test_arguments_and_limits(self):
        d = self.d("a")
        r0 = hashlib.sha256(b"").digest()
        self.assertEqual(M.verify_tiles(d, 0, r0, "tlog-tiles")["stato"], "OK")
        cases = [((d, -1), {}, "non-negative"), ((d, 1.0), {}, "non-negative"), ((d, True), {}, "non-negative"),
                 ((d, 1, b"x"), {}, "32 bytes"), ((d, 1), {"profile": "sumdb"}, "unknown profile"),
                 ((d, 1), {"encoding": "br"}, "unknown encoding"),
                 ((d, M.MAX_TREE_SIZE + 1), {}, "more than the"),
                 ((d, 256 ** 6), {"profile": "static-ct-api", "max_size": 2 ** 60}, "needs level 6; static-ct-api allows 0..5"),
                 ((d, 1), {"max_size": 1.5}, "more than the")]
        for args, kw, reason in cases:
            r = M.verify_tiles(*args, **kw)
            self.assertEqual(r["stato"], "NON_VALIDA", (args, kw))
            self.assertIn(reason, r["motivo"], (args, kw))
        self.assertIn("tile/0/000.p/1: missing", M.verify_tiles(d, 1, None, "tlog-tiles")["motivo"])
        self.assertEqual((M.MAX_TREE_SIZE, M.MAX_TILE_FILE), (1 << 24, 64 << 20))   # the limits SPEC §14 states
        self.assertIn("missing", M.verify_tiles(d, 5, None, "tlog-tiles", max_size=5)["motivo"])   # the bound itself passes
        huge = 2 ** 1000
        for size, profile, reason in ((256 ** 5, "static-ct-api", "tile/0/000: missing"),
                                      (256 ** 6 - 1, "static-ct-api", "tile/0/000: missing"),
                                      (256 ** 6, "static-ct-api", "needs level 6; static-ct-api allows 0..5"),
                                      (256 ** 63, "tlog-tiles", "tile/0/000: missing"),
                                      (256 ** 64, "tlog-tiles", "needs level 64; tlog-tiles allows 0..63")):
            self.assertIn(reason, M.verify_tiles(d, size, None, profile, entries=False, max_size=huge)["motivo"], size)
        self.assertEqual(M.tile_path(63, 0), "tile/63/000")

    def test_directories_on_the_path_are_not_links(self):
        """SPEC §14 rule 2: no link is followed, at the file or at any directory under <dir> (tile/, the level, x###, .p);
        <dir> itself may be a link. Before this rule a link at tile/ or tile/0 was followed and the tree was OK."""
        rnd = random.Random(21)
        for profile, size in (("tlog-tiles", 300), ("static-ct-api", 300), ("tlog-tiles", 256 * 1000 + 3)):
            d = self.d("links-%s-%d" % (profile, size))
            leaves, _ = write_tree(d, size, profile, rnd, keep_partials=True) if size == 300 else write_tree(d, size, profile, rnd)
            root = mth(leaves)
            self.assertEqual(M.verify_tiles(d, size, root, profile, entries=(size == 300))["stato"], "OK")
            dirs = sorted({os.path.relpath(a, d) for a, _, fs in os.walk(d)} - {"."})
            self.assertIn(os.path.join("tile", "0"), dirs)
            if size != 300:
                self.assertIn(os.path.join("tile", "0", "x001"), dirs)
            for rel in dirs:
                if size != 300 and rel.startswith(os.path.join("tile", "entries")):
                    continue                                          # entries are not read in this case
                p = os.path.join(d, rel)
                os.rename(p, p + ".real"); os.symlink(os.path.basename(p) + ".real", p)
                r = M.verify_tiles(d, size, root, profile, entries=(size == 300))
                self.assertEqual(r["stato"], "NON_VALIDA", rel)
                self.assertIn("is not a directory (links are not followed)", r["motivo"], rel)
                os.remove(p); os.rename(p + ".real", p)
            link = os.path.join(self.tmp, "link-to-" + os.path.basename(d)); os.symlink(d, link)
            self.assertEqual(M.verify_tiles(link, size, root, profile, entries=(size == 300))["stato"], "OK")

    def test_files_that_cannot_be_read(self):
        d = self.d("f")
        os.makedirs(os.path.join(d, "tile"))
        with open(os.path.join(d, "tile", "0"), "wb") as f:           # a file where a directory should be
            f.write(b"x")
        r = M.verify_tiles(d, 1, None, "tlog-tiles", entries=False)
        self.assertIn("tile/0/000.p/1", r["motivo"]); self.assertNotIn("missing", r["motivo"])
        p = os.path.join(self.tmp, "big")
        with open(p, "wb") as f:
            f.write(bytes(11))
        self.assertEqual(M._read_file(p, limit=11), bytes(11))
        with self.assertRaises(M.TileError) as cm:
            M._read_file(p, limit=10)
        self.assertIn("11 bytes, more than the 10", str(cm.exception))
        if not (hasattr(os, "geteuid") and os.geteuid() == 0):   # root reads any file
            from test_platforms_20261124 import make_unreadable   # Windows: an empty access list
            make_unreadable(self, p)
            with self.assertRaises(M.TileError):
                M._read_file(p)
        with self.assertRaises(M.TileError):
            M._decode(b"x", "br", "p")
        with self.assertRaises(M.TileError):                          # a zlib stream is not gzip
            M._decode(zlib.compress(b"abc"), "gzip", "p")
        rep = bytes(random.Random(9).randrange(256) for _ in range(20000)) * 2   # back-references 20,000 bytes away
        self.assertEqual(M._decode(gzip.compress(rep, mtime=0), "gzip", "p"), rep)       # need gzip's 32 KiB window
        exact = gzip.compress(bytes(M.MAX_TILE_FILE), mtime=0)          # exactly the limit once decompressed: read
        self.assertEqual(len(M._decode(exact, "gzip", "p")), M.MAX_TILE_FILE)


class GoOracle(unittest.TestCase):
    """golang.org/x/mod/sumdb/tlog, filippo.io/sunlight and filippo.io/torchwood read the same directories
    (verifiers/tile_oracle). Skipped without Go unless CV_REQUIRE_GO_ORACLE=1. Asked on directories where every tile is
    present (the oracle reads the tiles it needs; this implementation reads every level-0 tile)."""

    @classmethod
    def setUpClass(cls):
        if shutil.which("go") is None:
            if os.environ.get("CV_REQUIRE_GO_ORACLE") == "1":
                raise AssertionError("CV_REQUIRE_GO_ORACLE=1 but no Go toolchain on PATH")
            raise unittest.SkipTest("no Go toolchain")
        cls.tmp = tempfile.mkdtemp(); cls.bin = os.path.join(cls.tmp, "cvtile-oracle")
        r = subprocess.run(["go", "build", "-o", cls.bin, "."], cwd=ORACLE_SRC, capture_output=True, text=True, encoding="utf-8", timeout=600)
        if r.returncode != 0:
            raise AssertionError("tile_oracle build failed: " + r.stderr[-800:])

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(getattr(cls, "tmp", ""), ignore_errors=True)

    def oracle(self, d, size, root, profile, entries=True):
        args = [self.bin, d, str(size), base64.b64encode(root).decode(), profile] + (["entries"] if entries else [])
        r = subprocess.run(args, capture_output=True, text=True, encoding="utf-8", timeout=120)
        self.assertIn(r.returncode, (0, 1), r.stdout + r.stderr)
        return r.returncode == 0

    def test_mirror(self):
        cp = C.parse_checkpoint(C.split_note(_read("sunlight_mirror/checkpoint"))[0])
        self.assertTrue(self.oracle(MIRROR, 300, cp["root"], "tlog-tiles", entries=False))
        self.assertFalse(self.oracle(MIRROR, 300, cp["root"], "tlog-tiles"))

    def test_generated_and_altered(self):
        rnd = random.Random(21)
        agree = 0
        for profile in ("tlog-tiles", "static-ct-api"):
            for size in (1, 2, 255, 256, 257, 300, 513, 1000):
                d = tempfile.mkdtemp(dir=self.tmp)
                leaves, _ = write_tree(d, size, profile, rnd, gz=size % 2 == 1)
                root = mth(leaves)
                self.assertTrue(self.oracle(d, size, root, profile), (profile, size))
                self.assertEqual(M.verify_tiles(d, size, root, profile)["stato"], "OK")
                files = sorted(os.path.relpath(os.path.join(a, f), d) for a, _, fs in os.walk(d) for f in fs)
                for rel in files:
                    p = os.path.join(d, rel)
                    orig = open(p, "rb").read()
                    for _ in range(6):
                        b = bytearray(orig); b[rnd.randrange(len(b))] ^= 1 << rnd.randrange(8)
                        open(p, "wb").write(bytes(b))
                        ours = M.verify_tiles(d, size, root, profile)["stato"] == "OK"
                        self.assertEqual(ours, self.oracle(d, size, root, profile), (profile, size, rel))
                        agree += 1
                    open(p, "wb").write(orig)
                shutil.rmtree(d)
        self.assertGreater(agree, 300)


if __name__ == "__main__":
    unittest.main(verbosity=1)
