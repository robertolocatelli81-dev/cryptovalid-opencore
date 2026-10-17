#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Roberto Locatelli
"""RFC 6962 Merkle extension for cryptovalid-opencore: O(log n) inclusion and
consistency (append-only) proofs, third-party-verifiable, QTSP-ready Signed Tree Head.
A leaf is the canonical form of SPEC §3 (the bytes self_hash is computed over: the entry without self_hash and the five
attestation fields). Until 0.20.3 a leaf kept signature_pq, signer_pq and tsa_token, so an ML-DSA signature or a timestamp
token added after a tree head changed the root of entries it already covered. Stdlib-only."""
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
    """Third-party verification (CT client algorithm)."""
    if m >= n:
        return False
    h = leaf_hash(leaf_data)
    fn, sn = m, n - 1
    for p in proof:
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
    with open(path, encoding="utf-8") as f:     # the file is JSON, so UTF-8 whatever the locale; closed deterministically
        return [canonical(json.loads(line)) for line in f if line.strip()]


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
