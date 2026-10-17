#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Roberto Locatelli
"""Signature-profile vectors (SPEC v0.4 §5 step 5, cryptovalid-opencore 0.21.0). Deterministic: running it again writes the
same bytes (RFC 8032 signing with fixed seeds, standard library only, through ../../../ed25519_order.py).

Every vector is a chain that passes steps 1-4 (its `normative` block is the one every verifier reproduces, verifier.py and
the Rust verifier included); its `signature_profile` block is what a verifier that performs step 5 (JS, Go, Java, Swift;
signer.py verify) must return WITHOUT a pinned key: the verdict, and the entries whose signature layer fails with the
reason (the reason names are those of signer.py, JS, Go and Java; Swift reports a boolean only). Its `without_step5`
block is what verifier.py and the Rust verifier, which do not perform step 5, add to the normative receipt fields: how many
entries carry a signature field.

The ed25519_class_N vectors are the 12 classes of novifinancial/ed25519-speccheck (cases.txt at 6551933), as the x402
acceptance checker measured them (b37e471), rebuilt on ledger entries with keys of our own: `data.nonce` is ground until the
class's equations hold on the entry's own message (the UTF-8 bytes of its self_hash). Class 10 keeps R of prime order (with
a neutral key the equation fixes R = S*B). Class 12 (a key of prime order, R the neutral point) and 13 (R of mixed order with
a key of prime order, refused by the cofactorless equation) are ours.

python3 make_vectors.py   (writes the .jsonl and .expected.json files next to it)"""
import base64
import hashlib
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "..", ".."))
import ed25519_order as E  # noqa: E402

p, L, O = E.p, E.L, E.NEUTRAL
B = E.decode((4 * pow(5, p - 2, p)).to_bytes(32, "little"))
enc, add, mul = E.encode, E.add, E.scalar_mul


def eq(P, Q):
    return enc(P) == enc(Q)


def canon(e):
    d = {k: v for k, v in e.items() if k not in ("self_hash", "signature", "signer", "signature_pq", "signer_pq", "tsa_token")}
    return json.dumps(d, sort_keys=True, separators=(",", ":")).encode()


def chain(datas):
    out, prev = [], "0" * 64
    for i, d in enumerate(datas):
        e = {"idx": i, "ts": "2026-10-14T09:%02d:00Z" % i, "data": d, "prev_hash": prev}
        e["self_hash"] = hashlib.sha256(canon(e)).hexdigest()
        prev = e["self_hash"]
        out.append(e)
    return out


def expand(seed):
    h = hashlib.sha512(seed).digest()
    s = int.from_bytes(h[:32], "little")
    s &= ~7
    s &= (1 << 255) - 1
    s |= 1 << 254
    return s, h[32:]


def sign(seed, msg):   # RFC 8032 5.1.6
    s, prefix = expand(seed)
    A = enc(mul(s, B))
    r = int.from_bytes(hashlib.sha512(prefix + msg).digest(), "little") % L
    R = enc(mul(r, B))
    k = int.from_bytes(hashlib.sha512(R + A + msg).digest(), "little") % L
    return A, R + ((r + k * s) % L).to_bytes(32, "little")


def signed(entries, seed, skip=()):
    for i, e in enumerate(entries):
        if i in skip:
            continue
        A, sig = sign(seed, e["self_hash"].encode())
        e["signature"], e["signer"] = base64.b64encode(sig).decode(), A.hex()
    return entries


def torsion8():
    y = 2
    while True:
        P = E.decode(y.to_bytes(32, "little"))
        if P is not None:
            T = mul(L, P)
            if not eq(mul(4, T), O):
                return T
        y += 1


T8 = torsion8()
T2 = E.decode((p - 1).to_bytes(32, "little"))
a, r = 0x1234567 * 977 % L, 0x7654321 * 131 % L
aB, rB = mul(a, B), mul(r, B)
SIGNED_ID = (1 | (1 << 255)).to_bytes(32, "little")          # the neutral point, x = 0 with the sign bit set
SIGNED_M1 = ((p - 1) | (1 << 255)).to_bytes(32, "little")    # (0, -1), x = 0 with the sign bit set


def cls(n):
    """(A octets, R octets, S(k), condition(k)) of class n."""
    if n == 0:
        A, R = T8, mul(3, T8)
        return enc(A), enc(R), lambda k: 0, lambda k: eq(add(R, mul(k, A)), O)
    if n == 1:
        A, T = T8, mul(5, T8)
        return enc(A), enc(add(rB, T)), lambda k: r, lambda k: eq(add(T, mul(k, A)), O)
    if n == 2:
        R = mul(2, T8)
        return enc(add(aB, T8)), enc(R), lambda k: k * a % L, lambda k: eq(add(R, mul(k, T8)), O)
    if n in (3, 4):
        T = mul(6, T8)
        hold = n == 3
        return enc(add(aB, T8)), enc(add(rB, T)), lambda k: (r + k * a) % L, lambda k: eq(add(T, mul(k, T8)), O) == hold
    if n == 5:
        return enc(add(aB, T8)), enc(rB), lambda k: (r + k * a) % L, lambda k: not eq(mul(k, T8), O)
    if n in (6, 7):
        return enc(aB), enc(rB), (lambda k: (r + k * a) % L + (L if n == 6 else 8 * L)), lambda k: True
    if n in (8, 9):
        Rpt, Renc = (O, SIGNED_ID) if n == 8 else (T2, SIGNED_M1)
        return enc(add(aB, T8)), Renc, lambda k: k * a % L, lambda k: eq(add(Rpt, mul(k, T8)), O)
    if n == 10:
        return SIGNED_ID, enc(rB), lambda k: r, lambda k: True
    if n == 11:
        return SIGNED_M1, enc(add(rB, T2)), lambda k: r, lambda k: eq(add(T2, mul(k, T2)), O)
    if n == 12:
        return enc(aB), enc(O), lambda k: k * a % L, lambda k: True
    if n == 13:
        return enc(aB), enc(add(rB, T8)), lambda k: (r + k * a) % L, lambda k: True
    raise ValueError(n)


REASON = {0: "small_order_key", 1: "small_order_key", 2: "mixed_order_key", 3: "mixed_order_key", 4: "mixed_order_key",
          5: "mixed_order_key", 6: "bad_signature", 7: "bad_signature", 8: "mixed_order_key", 9: "mixed_order_key",
          10: "key_not_decodable", 11: "key_not_decodable", 12: "small_order_r", 13: "bad_signature"}


def class_entry(n):
    Aenc, Renc, Sf, cond = cls(n)
    for nonce in range(100000):
        e = chain([{"case": "ed25519_class_%d" % n, "nonce": nonce}])[0]
        k = int.from_bytes(hashlib.sha512(Renc + Aenc + e["self_hash"].encode()).digest(), "little") % L
        if cond(k):
            e["signature"] = base64.b64encode(Renc + Sf(k).to_bytes(32, "little")).decode()
            e["signer"] = Aenc.hex()
            return [e]
    raise SystemExit("class %d: no nonce" % n)


def vectors():
    K1, K2 = b"\x01" * 32, b"\x02" * 32
    three = lambda tag: [{"event": "%s-%d" % (tag, i)} for i in range(3)]   # noqa: E731
    v = {}
    v["signed_valid"] = (signed(chain(three("valid")), K1), "PASS", [])
    b = signed(chain(three("broken")), K1)
    raw = bytearray(base64.b64decode(b[1]["signature"])); raw[40] ^= 1; b[1]["signature"] = base64.b64encode(bytes(raw)).decode()
    v["signed_broken_e1"] = (b, "FAIL", [(1, "bad_signature")])
    v["signed_partial_e1"] = (signed(chain(three("partial")), K1, skip=(1,)), "FAIL", [(1, "missing signature/signer/self_hash")])
    s = signed(chain(three("nosigner")), K1); del s[1]["signer"]
    v["signature_without_signer_e1"] = (s, "FAIL", [(1, "missing signature/signer/self_hash")])
    m = signed(chain(three("malformed")), K1); m[1]["signature"] = m[1]["signature"][:-4] + "!!!="
    v["malformed_signature_e1"] = (m, "FAIL", [(1, "malformed_signature_field")])
    so = signed(chain(three("signeronly")), K1)
    for e in so:
        del e["signature"]
    v["signer_without_signature"] = (so, "FAIL", [(i, "missing signature/signer/self_hash") for i in range(3)])
    v["foreign_signer"] = (signed(chain(three("foreign")), K2), "PASS", [])   # without a key a foreign signer cannot be told
    for n in range(14):
        v["ed25519_class_%d" % n] = (class_entry(n), "FAIL", [(0, REASON[n])])
    return v


def main():
    for name, (entries, verdict, fails) in vectors().items():
        with open(os.path.join(HERE, name + ".jsonl"), "w", encoding="utf-8", newline="\n") as f:
            f.write("".join(json.dumps(e) + "\n" for e in entries))
        exp = {"input": name + ".jsonl",
               "normative": {"algorithm": "sha256", "chain_integrity": True, "entries": len(entries),
                             "hash_failures_idx": [], "link_failures_idx": [], "verdict": "PASS"},
               "signature_profile": {"verdict": verdict, "failures": [{"idx": i, "reason": why} for i, why in fails]},
               "without_step5": {"signatures_not_checked": sum(1 for e in entries if any(
                   k in e for k in ("signature", "signer", "signature_pq", "signer_pq")))}}
        with open(os.path.join(HERE, name + ".expected.json"), "w", encoding="utf-8", newline="\n") as f:
            f.write(json.dumps(exp, indent=1, sort_keys=True) + "\n")
    print(len(vectors()), "vectors")


if __name__ == "__main__":
    main()
