#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Roberto Locatelli
"""RFC 6962 Merkle extension for cryptovalid-opencore: O(log n) inclusion and
consistency (append-only) proofs, third-party-verifiable, QTSP-ready Signed Tree Head.
A leaf is the canonical form of SPEC §3 (the bytes self_hash is computed over: the entry without self_hash and the five
attestation fields). Until 0.20.3 a leaf kept signature_pq, signer_pq and tsa_token, so an ML-DSA signature or a timestamp
token added after a tree head changed the root of entries it already covered. Stdlib-only.

Status: CORE since 2026-11-15 (README, "Core and experimental modules"; SPEC §9, §14). Until that date this module was
experimental, with no new scope; it was moved to the core to read the tiles of C2SP tiled logs (c2sp.org/tlog-tiles,
c2sp.org/static-ct-api): hash tiles, partial tiles, static CT data tiles and tlog-tiles entry bundles, from a directory
laid out as the log serves them, checked against the size and root of a checkpoint (verify_tiles, SPEC §14).
"""
import sys as _sys_0203
if __name__ == "__main__":   # 0.20.3: run as a command, never write the bytecode cache: CPython 3.9 and 3.11 write
    _sys_0203.dont_write_bytecode = True   # a .pyc with one raw write; cut by a file size limit, every later run died (13/10/2026)
    _L0210 = type(__loader__)   # 0.21.0: a .pyc already cut (CPython 3.9/3.11 installed one) is compiled from the source
    if _L0210.__name__ == "SourceFileLoader":   # instead of failing every later run (EOFError: marshal data too short)
        def _get_code_0210(self, fullname, _get_code=_L0210.get_code):
            try:
                return _get_code(self, fullname)
            except (EOFError, ValueError):
                path = self.get_filename(fullname)
                return self.source_to_code(self.get_data(path), path)
        _L0210.get_code = _get_code_0210
import hashlib
import json
import os
import stat
import struct
import zlib
try:   # SPEC §30: one nesting bound for every JSON text, on every Python
    from verifier import json_loads_bounded as json_loads
except ImportError:   # python3 -m opencore.<module> from the parent directory
    from opencore.verifier import json_loads_bounded as json_loads


def leaf_hash(data: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + data).digest()


def node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def _largest_pow2_below(n: int) -> int:
    k = 1
    while k < n:
        k <<= 1
    return k >> 1


def mth(leaves):
    """Merkle Tree Hash over a list of leaf-data (bytes) — RFC 6962 s2.1."""
    n = len(leaves)
    if n == 0:
        return hashlib.sha256(b"").digest()
    if n == 1:
        return leaf_hash(leaves[0])
    k = _largest_pow2_below(n)
    return node_hash(mth(leaves[:k]), mth(leaves[k:]))


def inclusion_proof(m, leaves):
    """Audit path proving leaf m is in the tree — RFC 6962 s2.1.1."""
    n = len(leaves)
    assert 0 <= m < n
    if n == 1:
        return []
    k = _largest_pow2_below(n)
    if m < k:
        return inclusion_proof(m, leaves[:k]) + [mth(leaves[k:])]
    return inclusion_proof(m - k, leaves[k:]) + [mth(leaves[:k])]


def verify_inclusion(m, n, leaf_data, proof, root):
    """Third-party verification, RFC 9162 §2.1.3.2 (Experimental, December 2021; read at rfc-editor.org on 2026-11-20).
    SPEC v0.13 §21 rule 1: step 4a, "If sn is 0, then stop the iteration and fail the proof verification", is applied:
    a proof longer than the path of (m, n) fails. Until 0.27.0 it was not: the inclusion proof of leaf 5 of a tree of 8
    verified as leaf 1 of a tree of 4 against the root of the tree of 8. The caller still binds `n` to `root` (a signed
    tree head): with the root of another size, a proof of the right length can verify, as RFC 9162 writes the
    algorithm. A leaf index or a tree size that is not a non-negative integer fails too."""
    if not all(isinstance(x, int) and not isinstance(x, bool) for x in (m, n)) or not 0 <= m < n:
        return False
    h = leaf_hash(leaf_data)
    fn, sn = m, n - 1
    for p in proof:
        if sn == 0:
            return False
        if fn == sn or (fn & 1):
            h = node_hash(p, h)
            while not (fn & 1) and fn != 0:
                fn >>= 1
                sn >>= 1
        else:
            h = node_hash(h, p)
        fn >>= 1
        sn >>= 1
    return sn == 0 and h == root


def consistency_proof(m, leaves):
    """Append-only proof that D[0:m] is a prefix — RFC 6962 s2.1.2."""
    n = len(leaves)
    assert 0 < m <= n
    if m == n:
        return []
    return _subproof(m, leaves, True)


def _subproof(m, leaves, b):
    n = len(leaves)
    if m == n:
        return [] if b else [mth(leaves)]
    k = _largest_pow2_below(n)
    if m <= k:
        return _subproof(m, leaves[:k], b) + [mth(leaves[k:])]
    return _subproof(m - k, leaves[k:], False) + [mth(leaves[:k])]


def verify_consistency(m, n, proof, old_root, new_root):
    """RFC 6962 consistency verification."""
    if m == 0 or m > n:
        return False
    if m == n:
        return proof == [] and old_root == new_root
    p = list(proof)
    if (m & (m - 1)) == 0:
        p = [old_root] + p
    if not p:
        return False
    fn, sn = m - 1, n - 1
    while fn & 1:
        fn >>= 1
        sn >>= 1
    fr = sr = p[0]
    for c in p[1:]:
        if sn == 0:
            return False
        if (fn & 1) or (fn == sn):
            fr = node_hash(c, fr)
            sr = node_hash(c, sr)
            while not (fn & 1) and fn != 0:
                fn >>= 1
                sn >>= 1
        else:
            sr = node_hash(sr, c)
        fn >>= 1
        sn >>= 1
    return sn == 0 and fr == old_root and sr == new_root


def consistency_verdict(m, n, proof, old_root, new_root) -> str:
    """Three-valued RFC 9162 §2.1.4 check: "could_not_compare" when no consistency proof exists between the two sizes
    (m = 0: nothing to prove; m > n: the "old" tree is larger — a rollback, which a monitor reports apart from a fork),
    else "consistent" / "inconsistent". verify_consistency (bool) is unchanged: both non-consistent states are False."""
    if not (isinstance(m, int) and isinstance(n, int)) or isinstance(m, bool) or isinstance(n, bool) or m <= 0 or m > n:
        return "could_not_compare"
    return "consistent" if verify_consistency(m, n, proof, old_root, new_root) else "inconsistent"


def canonical(entry):
    """The leaf data of an entry: the canonical form of SPEC §3, the one function verifier.canonical_payload (0.21.0)."""
    return canonical_payload(entry)


def leaves_from_ledger(path):
    try:
        from verifier import open_regular
    except ImportError:   # python3 -m opencore.<module> from the parent directory
        from opencore.verifier import open_regular
    # the file is JSON, so UTF-8 whatever the locale; closed deterministically; SPEC §5 step 0: a regular file, opened
    # once without blocking (InputNotRegular / InputTooLarge are OSError)
    with os.fdopen(open_regular(path), encoding="utf-8") as f:
        return [canonical(json_loads(line)) for line in f if line.strip()]


def tree_head(leaves):
    """UNSIGNED tree head (size + root). Until 2026-09-13 this function was called `signed_tree_head` while
    carrying no signature — a misnomer found in the review of that day. The signed one lives in
    cryptovalid_receipt.signed_tree_head (Ed25519 log key)."""
    root = mth(leaves)
    return {
        "tree_size": len(leaves),
        "root_sha256": root.hex(),
        "signed": False,
        "note": "unsigned; sign it with cryptovalid_receipt.signed_tree_head and/or submit root_sha256 to a qualified TSP for a QUALIFIED RFC 3161 timestamp",
    }


def signed_tree_head(leaves):
    """Deprecated alias kept for callers (cryptovalid_ingest): returns the UNSIGNED tree head."""
    return tree_head(leaves)


# ── C2SP tiles (SPEC §14) ─────────────────────────────────────────────────────────────────────────────────────────
TILE_WIDTH = 256                 # tlog-tiles / static-ct-api: "Full tiles MUST be exactly 256 hashes wide, or 8,192 bytes"
HASH_SIZE = 32
PROFILES = {                     # highest level and the directory of the entries, as each specification names them
    "static-ct-api": {"max_level": 5, "entries": "data"},
    "tlog-tiles": {"max_level": 63, "entries": "entries"},
}
MAX_TREE_SIZE = 1 << 24          # a stated limit of this implementation (every leaf hash is held in memory): SPEC §14
MAX_TILE_FILE = 64 << 20         # bytes of a tile file, and of a data tile or entry bundle after gzip decompression
_LEAF_INDEX_EXT = 0              # static-ct-api CtExtensionType leaf_index(0), LeafIndex = uint40


class TileError(ValueError):
    """A tile, a data tile or an entry bundle refused, with the reason (SPEC §14)."""


def tile_index_path(n: int) -> str:
    """tlog-tiles: N "encoded into zero-padded 3-digit path elements. All but the last path element MUST begin with an
    `x`" — 1234067 → x001/x234/067, 5 → 005."""
    if type(n) is not int or n < 0:
        raise TileError("tile index must be a non-negative integer")
    parts = []
    while True:
        parts.append("%03d" % (n % 1000))
        n //= 1000
        if n == 0:
            break
    parts.reverse()
    return "/".join(["x" + p for p in parts[:-1]] + [parts[-1]])


def tile_path(level, n: int, width: int = TILE_WIDTH) -> str:
    """tile/<L>/<N>[.p/<W>]; level is an int, or the entries directory name ("data", "entries")."""
    if not (type(width) is int and 1 <= width <= TILE_WIDTH):
        raise TileError("tile width must be an integer in 1..256")
    if level not in ("data", "entries") and not (type(level) is int and 0 <= level <= 63):
        raise TileError("tile level must be an integer in 0..63, 'data' or 'entries'")
    return "tile/%s/%s%s" % (level, tile_index_path(n), "" if width == TILE_WIDTH else ".p/%d" % width)


def read_hash_tile(b: bytes, width: int) -> list:
    """The hashes of a tile of `width` hashes: exactly 32 × width bytes."""
    if len(b) != HASH_SIZE * width:
        raise TileError(f"a tile of width {width} is {HASH_SIZE * width} bytes, this one is {len(b)}")
    return [b[i:i + HASH_SIZE] for i in range(0, len(b), HASH_SIZE)]


class _Reader:
    __slots__ = ("b", "p", "what")

    def __init__(self, b: bytes, what: str):
        self.b, self.p, self.what = b, 0, what

    def take(self, n: int, field: str) -> bytes:   # every read checks the bytes are there first
        if len(self.b) - self.p < n:
            raise TileError(f"{self.what}: {field} needs {n} bytes, {len(self.b) - self.p} left")
        v = self.b[self.p:self.p + n]; self.p += n
        return v

    def uint(self, n: int, field: str) -> int:
        return int.from_bytes(self.take(n, field), "big")

    def vec(self, len_bytes: int, field: str, minimum: int = 0) -> bytes:
        n = self.uint(len_bytes, field + " length")
        if n < minimum:
            raise TileError(f"{self.what}: {field} of {n} bytes, at least {minimum} required")
        return self.take(n, field)


def _ct_extensions(ext: bytes, index: int, what: str) -> None:
    """static-ct-api §SCT Extension: a list of CtExtension (uint8 type, opaque data<0..2^16-1>), no type twice, exactly
    one leaf_index (5 bytes) equal to the entry's index. A type other than leaf_index is refused (SPEC §14)."""
    r = _Reader(ext, what + " extensions"); seen = set(); leaf_index = None
    while r.p < len(ext):
        t = r.uint(1, "extension type"); data = r.vec(2, "extension data")
        if t in seen:
            raise TileError(f"{what}: extension type {t} appears twice (static-ct-api: MUST NOT)")
        seen.add(t)
        if t != _LEAF_INDEX_EXT:
            raise TileError(f"{what}: extension type {t} is not leaf_index (0), the only one this implementation knows")
        if len(data) != 5:
            raise TileError(f"{what}: leaf_index of {len(data)} bytes, a LeafIndex is 5")
        leaf_index = int.from_bytes(data, "big")
    if leaf_index is None:
        raise TileError(f"{what}: no leaf_index extension (static-ct-api: MUST include)")
    if leaf_index != index:
        raise TileError(f"{what}: leaf_index {leaf_index}, the entry is at index {index}")


def parse_data_tile(b: bytes, width: int, first_index: int) -> list:
    """static-ct-api data tile: `width` TileLeaf structures and nothing after them → their RFC 6962 leaf hashes,
    SHA-256(0x00 || MerkleTreeLeaf), MerkleTreeLeaf = version v1 (0) || leaf_type timestamped_entry (0) ||
    TimestampedEntry. Every length is read before the bytes it covers (SPEC §14)."""
    r = _Reader(b, "data tile"); out = []
    for i in range(width):
        what = f"data tile entry {first_index + i}"
        r.what = what
        start = r.p
        r.take(8, "timestamp")
        entry_type = r.uint(2, "entry_type")
        if entry_type == 0:              # x509_entry: ASN.1Cert<1..2^24-1>
            r.vec(3, "certificate", 1)
        elif entry_type == 1:            # precert_entry: PreCert {issuer_key_hash[32], TBSCertificate<1..2^24-1>}
            r.take(32, "issuer_key_hash"); r.vec(3, "tbs_certificate", 1)
        else:
            raise TileError(f"{what}: entry_type {entry_type} is neither x509_entry (0) nor precert_entry (1)")
        ext = r.vec(2, "extensions")
        timestamped_entry = b[start:r.p]
        _ct_extensions(ext, first_index + i, what)
        if entry_type == 1:
            r.vec(3, "pre_certificate", 1)
        chain = r.vec(2, "certificate_chain")
        if len(chain) % HASH_SIZE:
            raise TileError(f"{what}: certificate_chain of {len(chain)} bytes is not a list of 32-byte fingerprints")
        out.append(leaf_hash(b"\x00\x00" + timestamped_entry))
    if r.p != len(b):
        raise TileError(f"data tile: {len(b) - r.p} bytes after the {width} entries")
    return out


def parse_entry_bundle(b: bytes, width: int, first_index: int = 0) -> list:
    """tlog-tiles entry bundle: `width` big-endian uint16 length-prefixed entries and nothing after them → their RFC 6962
    leaf hashes, SHA-256(0x00 || entry)."""
    r = _Reader(b, "entry bundle"); out = []
    for i in range(width):
        r.what = f"entry bundle entry {first_index + i}"
        out.append(leaf_hash(r.vec(2, "entry")))
    if r.p != len(b):
        raise TileError(f"entry bundle: {len(b) - r.p} bytes after the {width} entries")
    return out


def _read_file(path: str, limit: int = MAX_TILE_FILE):
    """→ bytes, or None when nothing is at the path; TileError for anything that is not a regular file."""
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        return None
    except OSError as e:
        raise TileError(f"{path}: {os.strerror(e.errno) if isinstance(e.errno, int) else e.strerror}") from None
    if not stat.S_ISREG(st.st_mode):
        raise TileError(f"{path}: not a regular file (links are not followed)")
    if st.st_size > limit:
        raise TileError(f"{path}: {st.st_size} bytes, more than the {limit} this implementation reads")
    try:   # opened once without blocking and judged again on the descriptor: a FIFO or a link put there after the lstat
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOCTTY", 0)
                     | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0))
    except OSError as e:
        raise TileError(f"{path}: {os.strerror(e.errno) if isinstance(e.errno, int) else e.strerror}") from None
    try:
        with os.fdopen(fd, "rb") as f:
            if not stat.S_ISREG(os.fstat(f.fileno()).st_mode):
                raise TileError(f"{path}: not a regular file (links are not followed)")
            return f.read(limit + 1)
    except OSError as e:
        raise TileError(f"{path}: {os.strerror(e.errno) if isinstance(e.errno, int) else e.strerror}") from None


def _decode(b: bytes, encoding: str, path: str) -> bytes:
    """identity, gzip (one gzip member, nothing after it, at most MAX_TILE_FILE bytes once decompressed), or auto: gzip
    when the file starts with the gzip magic bytes 1f 8b, identity otherwise (SPEC §14: the leaf hashes then decide)."""
    if encoding == "auto":
        encoding = "gzip" if b[:2] == b"\x1f\x8b" else "identity"
    if encoding == "identity":
        return b
    if encoding != "gzip":
        raise TileError(f"unknown encoding {encoding!r}: auto, gzip or identity")
    d = zlib.decompressobj(16 + zlib.MAX_WBITS)
    try:
        out = d.decompress(b, MAX_TILE_FILE + 1)
    except zlib.error as e:
        raise TileError(f"{path}: not gzip ({e})") from None
    if len(out) > MAX_TILE_FILE:
        raise TileError(f"{path}: more than {MAX_TILE_FILE} bytes once decompressed")
    if not d.eof:
        raise TileError(f"{path}: gzip stream truncated")
    if d.unused_data:
        raise TileError(f"{path}: {len(d.unused_data)} bytes after the gzip member")
    return out


def _perfect_root(hashes: list) -> bytes:
    """Root of a perfect subtree from its 2^k leaf-level hashes (a full tile: 256)."""
    level = list(hashes)
    while len(level) > 1:
        level = [node_hash(level[i], level[i + 1]) for i in range(0, len(level), 2)]
    return level[0]


def mth_from_hashes(hashes: list) -> bytes:
    """RFC 6962 §2.1 Merkle Tree Hash of a tree whose leaf hashes are given (empty tree: SHA-256 of nothing)."""
    n = len(hashes)
    if n == 0:
        return hashlib.sha256(b"").digest()
    if n == 1:
        return hashes[0]
    k = _largest_pow2_below(n)
    return node_hash(mth_from_hashes(hashes[:k]), mth_from_hashes(hashes[k:]))


def verify_tiles(directory: str, size: int, root=None, profile: str = "tlog-tiles", entries: bool = True,
                 encoding: str = "auto", max_size: int = MAX_TREE_SIZE) -> dict:
    """Read the tiles of a tree of `size` leaves from `directory` (laid out as the log serves them: <dir>/tile/...) and
    check them (SPEC §14). → {"stato": "OK" | "NON_VALIDA", "motivo", "size", "root" (hex, computed from the level-0
    tiles), "tiles_read", "partial_from_full", "upper_missing", "entries" (requested or not), "entries_checked"}. With `root` (32 bytes) the computed
    root must equal it. Every check that fails makes the result NON_VALIDA with the reason; nothing is skipped silently:
    a level-0 tile (and, with entries=True, its data tile or entry bundle) that is missing is a failure, an upper-level
    tile that is missing is counted in `upper_missing`."""
    out = {"stato": "NON_VALIDA", "motivo": None, "size": size, "root": None, "tiles_read": 0, "partial_from_full": 0,
           "upper_missing": 0, "entries": bool(entries), "entries_checked": 0}
    try:
        if profile not in PROFILES:
            raise TileError(f"unknown profile {profile!r}: {', '.join(PROFILES)}")
        if type(size) is not int or size < 0:
            raise TileError("tree size must be a non-negative integer")
        if type(max_size) is not int or size > max_size:
            raise TileError(f"tree size {size} is more than the {max_size} leaves this implementation reads")
        if root is not None and (not isinstance(root, (bytes, bytearray)) or len(root) != HASH_SIZE):
            raise TileError("root must be 32 bytes")
        if encoding not in ("auto", "gzip", "identity"):
            raise TileError(f"unknown encoding {encoding!r}: auto, gzip or identity")
        prof = PROFILES[profile]

        def fetch(level, n, width, required):
            """The bytes of tile (level, n) of `width` entries: the partial file, else the prefix of the full one."""
            def at(w):
                parts = tile_path(level, n, w).split("/")
                cur = directory
                for part in parts[:-1]:      # tile/, the level, x### and .p: real directories, never links (SPEC §14)
                    cur = os.path.join(cur, part)
                    try:
                        st = os.lstat(cur)
                    except FileNotFoundError:
                        return None
                    except OSError as e:
                        raise TileError(f"{'/'.join(parts)}: {cur}: {os.strerror(e.errno) if isinstance(e.errno, int) else e.strerror}") from None
                    if not stat.S_ISDIR(st.st_mode):
                        raise TileError(f"{'/'.join(parts)}: {cur} is not a directory (links are not followed)")
                return _read_file(os.path.join(cur, parts[-1]))
            hashes_level = level not in ("data", "entries")
            b = at(width)
            if width < TILE_WIDTH:
                full = at(TILE_WIDTH)
                if b is None and full is not None:
                    out["partial_from_full"] += 1
                    return full, TILE_WIDTH
                if b is not None and full is not None and hashes_level and full[:HASH_SIZE * width] != b:
                    raise TileError(f"{tile_path(level, n, width)} is not the prefix of {tile_path(level, n)}")
            if b is None:
                if required:
                    raise TileError(f"{tile_path(level, n, width)}: missing")
                return None, width
            return b, width

        n_levels = 0                     # levels a tree of `size` leaves has: while floor(size / 256^l) > 0
        while size // TILE_WIDTH ** n_levels > 0:
            n_levels += 1
        if n_levels - 1 > prof["max_level"]:
            raise TileError(f"a tree of {size} leaves needs level {n_levels - 1}; {profile} allows 0..{prof['max_level']}")
        derived = []                     # derived[l]: the level-l hashes computed from the level-0 tiles
        for level in range(n_levels):
            count = size // TILE_WIDTH ** level
            if level:
                below = derived[level - 1]
                derived.append([_perfect_root(below[j * TILE_WIDTH:(j + 1) * TILE_WIDTH]) for j in range(count)])
            else:
                derived.append([])
            for n in range((count + TILE_WIDTH - 1) // TILE_WIDTH):
                width = min(TILE_WIDTH, count - n * TILE_WIDTH)
                b, got = fetch(level, n, width, required=(level == 0))
                if b is None:
                    out["upper_missing"] += 1
                    continue
                out["tiles_read"] += 1
                hashes = read_hash_tile(b, got)[:width]
                if level == 0:
                    derived[0].extend(hashes)
                elif hashes != derived[level][n * TILE_WIDTH:n * TILE_WIDTH + width]:
                    j = next(i for i, h in enumerate(hashes) if h != derived[level][n * TILE_WIDTH + i])
                    raise TileError(f"{tile_path(level, n, width)}: hash {j} is not the root of the 256 hashes of "
                                    f"level {level - 1} below it")
        levels = derived
        leaf_hashes = levels[0] if levels else []
        computed = mth_from_hashes(leaf_hashes)
        out["root"] = computed.hex()
        if root is not None and computed != bytes(root):
            raise TileError("the root computed from the level-0 tiles differs from the checkpoint's")
        if entries:
            for n in range((size + TILE_WIDTH - 1) // TILE_WIDTH):
                width = min(TILE_WIDTH, size - n * TILE_WIDTH)
                b, got = fetch(prof["entries"], n, width, required=True)
                data = _decode(b, encoding, tile_path(prof["entries"], n, got))
                parse = parse_data_tile if profile == "static-ct-api" else parse_entry_bundle
                got_hashes = parse(data, got, n * TILE_WIDTH)[:width]
                for i, h in enumerate(got_hashes):
                    if h != leaf_hashes[n * TILE_WIDTH + i]:
                        raise TileError(f"entry {n * TILE_WIDTH + i} does not hash to its level-0 tile hash")
                out["entries_checked"] += width
                out["tiles_read"] += 1
    except TileError as e:
        out["motivo"] = str(e)
        return out
    out["stato"] = "OK"
    return out


try:   # 0.20.3: the one writer of every command (verifier.py): an outcome is written whole, or exit 74
    from verifier import Parser, canonical_payload, emit, receipt_cli, say
except ImportError:   # python3 -m opencore.<module> from the parent directory
    from opencore.verifier import Parser, canonical_payload, emit, receipt_cli, say


@receipt_cli
def main(argv=None):
    import argparse
    p = Parser(prog="cryptovalid_merkle",
                                description="RFC 6962 Merkle proofs for a cryptovalid ledger.")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("sth").add_argument("ledger")
    pv = sub.add_parser("prove"); pv.add_argument("ledger"); pv.add_argument("index", type=int)
    vf = sub.add_parser("verify"); vf.add_argument("ledger"); vf.add_argument("index", type=int)
    args = p.parse_args(argv)
    lv = leaves_from_ledger(args.ledger)
    if args.cmd == "sth":
        emit(json.dumps(tree_head(lv), indent=2)); return 0
    root = mth(lv)
    if args.cmd == "prove":
        pr = inclusion_proof(args.index, lv)
        emit(json.dumps({"index": args.index, "tree_size": len(lv),
                          "root_sha256": root.hex(), "audit_path": [h.hex() for h in pr]}, indent=2))
        return 0
    pr = inclusion_proof(args.index, lv)
    ok = verify_inclusion(args.index, len(lv), lv[args.index], pr, root)
    emit("INCLUSION VALID" if ok else "INCLUSION INVALID")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
