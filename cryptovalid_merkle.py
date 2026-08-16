#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Roberto Locatelli
"""RFC 6962 Merkle extension for cryptovalid-opencore: O(log n) inclusion and
consistency (append-only) proofs, third-party-verifiable, QTSP-ready Signed Tree Head.
Leaves are the canonical form of each ledger entry (same rule as self_hash). Stdlib-only."""
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


def canonical(entry):
    d = {k: v for k, v in entry.items() if k not in ("self_hash", "signature", "signer")}
    return json.dumps(d, sort_keys=True, separators=(",", ":")).encode()


def leaves_from_ledger(path):
    return [canonical(json.loads(line)) for line in open(path) if line.strip()]


def signed_tree_head(leaves):
    root = mth(leaves)
    return {
        "tree_size": len(leaves),
        "root_sha256": root.hex(),
        "note": "submit root_sha256 to a qualified TSP (eIDAS EU Trusted List) for a QUALIFIED RFC3161 timestamp",
    }


def main(argv=None):
    import argparse
    p = argparse.ArgumentParser(prog="cryptovalid_merkle",
                                description="RFC 6962 Merkle proofs for a cryptovalid ledger.")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("sth").add_argument("ledger")
    pv = sub.add_parser("prove"); pv.add_argument("ledger"); pv.add_argument("index", type=int)
    vf = sub.add_parser("verify"); vf.add_argument("ledger"); vf.add_argument("index", type=int)
    args = p.parse_args(argv)
    lv = leaves_from_ledger(args.ledger)
    if args.cmd == "sth":
        print(json.dumps(signed_tree_head(lv), indent=2)); return 0
    root = mth(lv)
    if args.cmd == "prove":
        pr = inclusion_proof(args.index, lv)
        print(json.dumps({"index": args.index, "tree_size": len(lv),
                          "root_sha256": root.hex(), "audit_path": [h.hex() for h in pr]}, indent=2))
        return 0
    pr = inclusion_proof(args.index, lv)
    ok = verify_inclusion(args.index, len(lv), lv[args.index], pr, root)
    print("INCLUSION VALID" if ok else "INCLUSION INVALID")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
