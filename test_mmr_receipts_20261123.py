#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""cryptovalid_cose_receipts, vds 3 (MMR_SHA256) after draft-ietf-scitt-receipts-mmr-profile-00 (2026-11-21, the WG
document, the revision current on datatracker on 2026-11-23); SPEC §28.

External vectors: spec/vectors/forestrie-mmr/checkpoint-receipt-kat39.json (forestrie/protocol e5eb191, MIT), receipts
of CONSISTENCY and the fold under them; every divergence from its expectations is named here with its reason.
No public vector of an inclusion receipt in the form of draft -00 was found on 2026-11-23 (Forestrie's inclusion
receipts carry a {1, 2} map, not a bstr .cbor array, and no vds): the inclusion tests use receipts signed here, over a
tree built with the draft's add_leaf_hash, and check included_root against the 21 accumulators of the KAT-39 tree and
against the 184 unsigned proofs of spec/vectors/aac-cll-mmr (agent-action-capsule f812c44, BSD-3-Clause).

Positive control, measured: on a156b15 (before vds 3) every test here fails or errors except the SHA256SUMS check."""
import hashlib
import json
import os
import random
import sys
import unittest

sys.dont_write_bytecode = True
ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)
import cryptovalid_cose_receipts as C  # noqa: E402
import cryptovalid_receipt as R  # noqa: E402
import test_cose_receipts as TC  # noqa: E402

VEC = os.path.join(ROOT, "spec", "vectors", "forestrie-mmr")
with open(os.path.join(VEC, "checkpoint-receipt-kat39.json"), encoding="utf-8") as _f:
    KAT = json.load(_f)
X = bytes.fromhex
H = lambda b: hashlib.sha256(b).digest()  # noqa: E731

# The 7 of 52 protected_headers rows where draft -00 §7 (RFC 8949 §4.2.1 bytewise key order; "MUST ignore protected
# header labels it does not recognise, whatever the type of their values"; a label is any CBOR int, RFC 9052 §1.4)
# answers otherwise than Forestrie's ADR-0066 D9. The other 45 agree.
DRAFT_NOT_D9 = {
    "skip/two-unread-labels-length-first-order": "reject",    # -1 (20) before 24 (1818): not bytewise
    "reject/mt7-simple-40": "accept", "reject/mt7-undefined": "accept", "reject/array-under-unread-label": "accept",
    "reject/map-under-unread-label": "accept", "reject/tag-under-unread-label": "accept",
    "reject/negative-key-beyond-int64": "accept",
}


def acc_of(size):
    return [X(h) for h in KAT["tree"]["accumulators"][str(size)]["peaks_hex"]] if size else []


def es256_pem():
    from cryptography.hazmat.primitives import serialization as ser
    from cryptography.hazmat.primitives.asymmetric import ec
    k = KAT["keys"]["es256"]
    pub = ec.EllipticCurvePublicNumbers(int(k["public_x_hex"], 16), int(k["public_y_hex"], 16), ec.SECP256R1()).public_key()
    return pub.public_bytes(ser.Encoding.PEM, ser.PublicFormat.SubjectPublicKeyInfo)


def wrapped(receipt_hex):
    """the bare bstr of vdp -2 put in an array, as draft -00 §7 writes it; the unprotected header is not signed"""
    v = R.cbor_decode(X(receipt_hex)[1:])
    if isinstance(v[1][396][-2], bytes):
        v[1][396][-2] = [v[1][396][-2]]
    return b"\xd2" + R.cbor_encode(v)


# ── a tree built from the draft's own algorithms (§8.1 add_leaf_hash, §4.1 inclusion_proof_path) ──
def add_leaf_hash(db, f):
    g, i = 0, None
    db.append(f)
    i = len(db)
    while C._mmr_height(i) > g:
        db.append(C._mmr_pospair(i + 1, db[i - (2 << g)], db[i - 1]))
        i = len(db)
        g += 1
    return i


def inclusion_proof_path(i, c):
    path, g = [], C._mmr_height(i)
    while True:
        off = 2 << g
        if C._mmr_height(i + 1) > g:
            isib, i = i - off + 1, i + 1
        else:
            isib, i = i + off - 1, i + off
        if isib > c:
            return path
        path.append(isib)
        g += 1


class Log:
    def __init__(self, alg=-8, leaves=21):
        from cryptography.hazmat.primitives import serialization as ser
        from cryptography.hazmat.primitives.asymmetric import ec, ed25519
        self.alg = alg
        self.sk = ed25519.Ed25519PrivateKey.generate() if alg == -8 else ec.generate_private_key(
            ec.SECP256R1() if alg == -7 else ec.SECP384R1())
        self.pem = self.sk.public_key().public_bytes(ser.Encoding.PEM, ser.PublicFormat.SubjectPublicKeyInfo)
        self.db = []
        for n in range(leaves):
            add_leaf_hash(self.db, H(b"\x00" + n.to_bytes(8, "big")))

    def sign(self, protected_bytes, payload):
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
        tbs = R.cbor_encode(["Signature1", protected_bytes, b"", payload])
        if self.alg == -8:
            return self.sk.sign(tbs)
        size, hh = (32, hashes.SHA256()) if self.alg == -7 else (48, hashes.SHA384())
        r, s = decode_dss_signature(self.sk.sign(tbs, ec.ECDSA(hh)))
        return r.to_bytes(size, "big") + s.to_bytes(size, "big")

    def inclusion(self, i, size=None, ph=None, uh_extra=None, proofs=None, payload_attached=False, raw_ph=None):
        size = size or len(self.db)
        path = [self.db[j] for j in inclusion_proof_path(i, size - 1)]
        peak = C.mmr_included_root(i, self.db[i], path)
        pb = raw_ph if raw_ph is not None else R.cbor_encode(ph if ph is not None else {1: self.alg, 395: 3})
        uh = {396: {-1: proofs if proofs is not None else [R.cbor_encode([i, path])]}}
        uh.update(uh_extra or {})
        return b"\xd2" + R.cbor_encode([pb, uh, peak if payload_attached else None, self.sign(pb, peak)])


@TC.NEEDS_CRYPTO
class Kat39(unittest.TestCase):
    def test_vendored_bytes_match_their_pins(self):
        with open(os.path.join(VEC, "SHA256SUMS"), encoding="ascii") as f:
            sums = f.read().splitlines()
        for line in sums:
            want, name = line.split()
            with open(os.path.join(VEC, name), "rb") as f:
                self.assertEqual(hashlib.sha256(f.read()).hexdigest(), want, name)

    def test_fold_agrees_on_every_pair_and_negative(self):
        for r in KAT["consistency_pairs"]:
            roots, n = C.mmr_consistent_roots(r["tree_size_1"], r["tree_size_2"], [X(h) for h in r["accumulator_from_hex"]],
                                              [[X(h) for h in p] for p in r["paths_hex"]])
            self.assertEqual(([h.hex() for h in roots], n), (r["roots_hex"], r["right_peak_count"]), r["name"])
            self.assertEqual([h.hex() for h in roots] + r["right_peaks_hex"], r["accumulator_to_hex"], r["name"])
        self.assertEqual(len(KAT["consistency_pairs"]), 231)
        for r in KAT["consistency_negatives"]:
            if r["expect"]["class"] in ("right_peak_count_mismatch", "base_mismatch"):
                continue                     # checks around the fold: test_receipts_* below
            with self.assertRaises(C.MmrShapeError, msg=r["name"]) as cm:
                C.mmr_consistent_roots(r["tree_size_1"], r["tree_size_2"], [X(h) for h in r["accumulator_from_hex"]],
                                       [[X(h) for h in p] for p in r["paths_hex"]])
            self.assertEqual(cm.exception.cls, r["expect"]["class"], r["name"])

    def test_negatives_around_the_fold_in_signed_receipts(self):
        log = Log(alg=-7)
        for r in KAT["consistency_negatives"]:
            if r["expect"]["class"] not in ("right_peak_count_mismatch", "base_mismatch"):
                continue
            proof = R.cbor_encode([r["tree_size_1"], r["tree_size_2"], [[X(h) for h in p] for p in r["paths_hex"]],
                                   [X(h) for h in r["right_peaks_hex"]]])
            pb = R.cbor_encode({1: -7, 395: 3, -65933: r["tree_size_2"]})
            rc = b"\xd2" + R.cbor_encode([pb, {396: {-2: [proof]}}, None, log.sign(pb, b"".join(acc_of(r["tree_size_2"])))])
            trusted = r.get("trusted_tree_size_1", r["tree_size_1"])
            out = C.verify_mmr_consistency(rc, log.pem, trusted, acc_of(trusted))
            self.assertFalse(out["ok"], r["name"])
            if r["expect"]["class"] == "base_mismatch":
                self.assertEqual(out["stage"], "CHAIN_NOT_CONTIGUOUS", r["name"])
            else:
                self.assertEqual(out.get("shape"), "right_peak_count_mismatch", r["name"])

    def test_receipts(self):
        pem = es256_pem()
        for r in KAT["receipts"]:
            s1 = r["tree_size_1"]
            bare = C.verify_mmr_consistency(X(r["receipt_cbor_hex"]), pem, s1, acc_of(s1))
            self.assertFalse(bare["ok"], r["name"])
            if r["alg"] != -7:
                self.assertEqual(bare["stage"], "UNSUPPORTED_ALG", r["name"])    # KS256: not a COSE alg here
                continue
            self.assertEqual(bare["stage"], "MALFORMED_PROOF", r["name"])
            out = C.verify_mmr_consistency(wrapped(r["receipt_cbor_hex"]), pem, s1, acc_of(s1))
            self.assertTrue(out["ok"], (r["name"], out))
            self.assertEqual(out["tree_size_2"], r["tree_size_2"])
            self.assertEqual(out["accumulator"], [h.hex() for h in acc_of(r["tree_size_2"])])
            self.assertEqual(out["accumulator"], [X(r["detached_payload_hex"])[k:k + 32].hex()
                                                  for k in range(0, len(r["detached_payload_hex"]) // 2, 32)])
            other = C.verify_mmr_consistency(wrapped(r["receipt_cbor_hex"]), Log(-7).pem, s1, acc_of(s1))
            self.assertEqual(other["stage"], "CONSISTENCY_SIGNATURE_INVALID")       # control: another key

    def test_receipt_negatives(self):
        pem = es256_pem()
        want = {"signed_size_mismatch": "SIGNED_SIZE_MISMATCH", "signed_size_missing": "SIGNED_SIZE_MISSING",
                "signature_invalid": "CONSISTENCY_SIGNATURE_INVALID"}
        for r in KAT["receipt_negatives"]:
            out = C.verify_mmr_consistency(wrapped(r["receipt_cbor_hex"]), pem, r["tree_size_1"], acc_of(r["tree_size_1"]))
            if r["expect"]["reason"] == "signature_malleable":
                self.assertTrue(out["ok"], out)     # declared divergence: RFC 9053 §2.1 has no low-s rule (SPEC §28)
                continue
            self.assertEqual(out["stage"], want[r["expect"]["reason"]], (r["name"], out))

    def test_receipt_chains(self):
        pem = es256_pem()
        want = {"chain_not_contiguous": "CHAIN_NOT_CONTIGUOUS", "signed_size_mismatch": "SIGNED_SIZE_MISMATCH"}
        for r in KAT["receipt_chains"]:
            t = r["trusted_tree_size_1"]
            out = C.verify_mmr_consistency(X(r["receipt_cbor_hex"]), pem, t, acc_of(t))
            if r["expect"]["result"] == "accept":
                self.assertTrue(out["ok"], out)
                self.assertEqual(out["tree_size_2"], r["expect"]["tree_size_2"])
            else:
                self.assertEqual(out["stage"], want[r["expect"]["reason"]], (r["name"], out))

    def test_protected_header_rows(self):
        agree = 0
        for r in KAT["protected_headers"]:
            try:
                ph, end = C._cbor_read(X(r["hex"]), 0, True)
                assert isinstance(ph, dict) and end == len(r["hex"]) // 2
                ts = ph.get(-65933, "absent")
                got = "absent" if ts == "absent" else "accept" if type(ts) is int and ts >= 0 else "reject"
            except (ValueError, AssertionError):
                got = "reject"
            want = DRAFT_NOT_D9.get(r["name"], r["expect"]["result"])
            self.assertEqual(got, want, r["name"])
            if got == "accept" and r["name"] not in DRAFT_NOT_D9:
                self.assertEqual(ph[-65933], r["expect"]["tree_size_2"])
            agree += r["name"] not in DRAFT_NOT_D9
        self.assertEqual((agree, len(DRAFT_NOT_D9)), (45, 7))

    def test_included_root_reaches_every_peak_of_the_kat_tree(self):
        nodes = [X(h) for h in KAT["tree"]["nodes_hex"]]
        n = 0
        for size in KAT["tree"]["complete_mmr_sizes"]:
            peaks = {h.hex() for h in acc_of(size)}
            for i in range(size):
                path = [nodes[j] for j in inclusion_proof_path(i, size - 1)]
                self.assertIn(C.mmr_included_root(i, nodes[i], path).hex(), peaks, (size, i))
                n += 1
        self.assertEqual(n, sum(KAT["tree"]["complete_mmr_sizes"]))


class AacCllMaterial(unittest.TestCase):
    """spec/vectors/aac-cll-mmr: proofs of action-state-group/agent-action-capsule (f812c44, BSD-3-Clause), written from
    MMR draft-bryce -02; no signature, so they confirm the two algorithms, not a receipt."""
    DIR = os.path.join(ROOT, "spec", "vectors", "aac-cll-mmr")

    def test_pins_and_every_case(self):
        with open(os.path.join(self.DIR, "SHA256SUMS"), encoding="ascii") as f:
            sums = f.read().splitlines()
        for line in sums:
            want, name = line.split()
            with open(os.path.join(self.DIR, name), "rb") as f:
                self.assertEqual(hashlib.sha256(f.read()).hexdigest(), want, name)
        with open(os.path.join(self.DIR, "cases.json"), encoding="utf-8") as f:
            cases = json.load(f)["cases"]
        n = {"inclusion": 0, "consistency": 0, "equal_sizes_refused": 0}
        for c in cases:
            o = R.cbor_decode(X(c["expected"]["octets_hex"]))
            if c["kind"] == "cll-inclusion-proof":
                leaf = c["inputs"]["leaf"]
                self.assertEqual(o, [2 * leaf - bin(leaf).count("1"), [X(h) for h in c["inputs"]["path"]]], c["id"])
                node = H(b"\x00" + X(c["context"]["entry"]))
                self.assertIn(C.mmr_included_root(o[0], node, o[1]).hex(), c["context"]["peaks"], c["id"])
                n["inclusion"] += 1
                continue
            s1, s2, paths, right = o
            old = [X(h) for h in c["inputs"]["old_peaks"]]
            if s1 == s2:                      # draft -00 §7.1.1: "if sizeto <= sizefrom -> ERROR"
                self.assertRaises(C.MmrShapeError, C.mmr_consistent_roots, s1, s2, old, paths)
                n["equal_sizes_refused"] += 1
                continue
            roots, k = C.mmr_consistent_roots(s1, s2, old, paths)
            self.assertEqual(([h.hex() for h in roots + right], k), (c["inputs"]["new_peaks"], len(right)), c["id"])
            n["consistency"] += 1
        self.assertEqual(n, {"inclusion": 92, "consistency": 79, "equal_sizes_refused": 13})

@TC.NEEDS_CRYPTO
class Inclusion(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.logs = {a: Log(a) for a in (-8, -7, -35)}

    def test_every_node_of_every_size_verifies_with_each_alg(self):
        for alg, log in self.logs.items():
            for size in (1, 3, 4, 7, 8, 10, 11, 15, 16, 18, 19, 22, 25, 26, 31, 32, 34, 35, 38, 39):
                for i in range(size):
                    out = C.verify_receipt(log.inclusion(i, size), log.db[i], log.pem)
                    self.assertTrue(out["ok"], (alg, size, i, out))
                    self.assertEqual((out["vds"], out["leaf_index"], out["node_height"]), (3, i, C._mmr_height(i)))
                    self.assertEqual(out["index_bound"], len(inclusion_proof_path(i, size - 1)) > 0)

    def test_wrong_entry_wrong_key_and_flips_refuse(self):
        log, rng = self.logs[-8], random.Random(20261123)
        good = log.inclusion(4, 39)
        self.assertFalse(C.verify_receipt(good, log.db[3], log.pem)["ok"])
        self.assertEqual(C.verify_receipt(good, log.db[4], self.logs[-7].pem)["stage"], "INCLUSION_ROOT_SIGNATURE_INVALID")
        self.assertFalse(C.verify_receipt(good, log.db[4], Log(-8, 1).pem)["ok"])
        for _ in range(400):
            b = bytearray(good)
            b[rng.randrange(len(b))] ^= 1 << rng.randrange(8)
            self.assertFalse(C.verify_receipt(bytes(b), log.db[4], log.pem)["ok"])

    def test_closed_shapes(self):
        log = self.logs[-8]
        i, path = 4, [log.db[j] for j in inclusion_proof_path(4, 38)]
        cases = {
            "payload attached": (dict(payload_attached=True), "PAYLOAD_NOT_DETACHED"),
            "vdp with -2 too": (dict(uh_extra={396: {-1: [R.cbor_encode([i, path])], -2: []}}), "MALFORMED_PROOF"),
            "vdp with another key": (dict(uh_extra={396: {-1: [R.cbor_encode([i, path])], 7: 0}}), "MALFORMED_PROOF"),
            "consistency only": (dict(uh_extra={396: {-2: [b""]}}), "OTHER_RECEIPT_KIND"),
            "proof with a third element": (dict(proofs=[R.cbor_encode([i, path, 0])]), "MALFORMED_PROOF"),
            "index negative": (dict(proofs=[R.cbor_encode([-1, path])]), "MALFORMED_PROOF"),
            "index true": (dict(proofs=[b"\x82\xf5" + R.cbor_encode(path)]), "MALFORMED_PROOF"),
            "index 2^64-1": (dict(proofs=[R.cbor_encode([(1 << 64) - 1, path])]), "MALFORMED_PROOF"),
            "hash of 31 bytes": (dict(proofs=[R.cbor_encode([i, path[:-1] + [path[-1][:31]]])]), "MALFORMED_PROOF"),
            "path of 65": (dict(proofs=[R.cbor_encode([i, [path[0]] * 65])]), "MALFORMED_PROOF"),
            "proof not a bstr": (dict(proofs=[[i, path]]), "MALFORMED_PROOF"),
            "no proof": (dict(proofs=[]), "MALFORMED_PROOF"),
            "another peak beside": (dict(proofs=[R.cbor_encode([i, path]), R.cbor_encode([i, path[:-1]])]), "PROOFS_DISAGREE"),
            "vds as text": (dict(ph={1: -8, 395: "3"}), "UNSUPPORTED_ALG"),
            "alg ES512": (dict(ph={1: -36, 395: 3}), "UNSUPPORTED_ALG"),
            "crit names an unread label": (dict(ph={1: -8, 2: [99], 99: 0, 395: 3}), "MALFORMED_RECEIPT"),
            "crit names tree-size-2": (dict(ph={1: -8, 2: [-65933], 395: 3, -65933: 39}), "MALFORMED_RECEIPT"),
            "keys not in bytewise order": (dict(raw_ph=b"\xa2\x19\x01\x8b\x03\x01\x27"), "PROTECTED_HEADER_ENCODING"),
            "duplicate label": (dict(raw_ph=b"\xa3\x01\x27\x19\x01\x8b\x03\x19\x01\x8b\x03"), "MALFORMED_RECEIPT"),  # vds unreadable
            "non-shortest alg": (dict(raw_ph=b"\xa2\x01\x38\x07\x19\x01\x8b\x03"), "PROTECTED_HEADER_ENCODING"),
            "bytes after the map": (dict(raw_ph=b"\xa2\x01\x27\x19\x01\x8b\x03\x00"), "PROTECTED_HEADER_ENCODING"),
            "double that fits a half": (dict(raw_ph=b"\xa3\x01\x27\x07\xfb\x3f\xf0\x00\x00\x00\x00\x00\x00\x19\x01\x8b\x03"),
                                        "PROTECTED_HEADER_ENCODING"),
        }
        for name, (kw, stage) in cases.items():
            out = C.verify_receipt(log.inclusion(i, 39, **kw), log.db[i], log.pem)
            self.assertFalse(out["ok"], name)
            if name != "vds as text":
                self.assertEqual(out["stage"], stage, (name, out))
        self.assertEqual(C.verify_receipt(log.inclusion(i, 39), log.db[i][:31], log.pem)["stage"], "ENTRY_NOT_A_NODE_VALUE")

    def test_what_the_draft_ignores_is_ignored_and_reported(self):
        log = self.logs[-8]
        for ph_raw, labels in ((b"\xa3\x01\x27\x07\xf9\x3c\x00\x19\x01\x8b\x03", [7]),        # half float 1.0
                               (b"\xa3\x01\x27\x07\xc1\x08\x19\x01\x8b\x03", [7]),            # a tag
                               (b"\xa3\x01\x27\x19\x01\x8b\x03\x61\x61\x80", ["a"]),          # text label, array value
                               (b"\xa3\x01\x27\x19\x01\x8b\x03\x3a\x00\x01\x01\x8c\x05", [])):  # tree-size-2 is read
            out = C.verify_receipt(log.inclusion(0, 39, raw_ph=ph_raw), log.db[0], log.pem)
            self.assertTrue(out["ok"], (ph_raw.hex(), out))
            self.assertEqual(out["ignored_labels"], labels)
        out = C.verify_receipt(log.inclusion(0, 39, uh_extra={4: b"kid", 99: [1, "x"], "t": {}}), log.db[0], log.pem)
        self.assertTrue(out["ok"], out)                     # unprotected: * cose-label => cose-value (-00 §5)

    def test_rfc9943_header_musts(self):
        log = self.logs[-8]
        self.assertEqual(C.verify_receipt(log.inclusion(0, 39), log.db[0], log.pem, profile="rfc9943")["stage"], "HEADER_MUST")
        ph = {1: -8, 4: b"k", 15: {1: "log.example", 2: "mmr"}, 395: 3}
        self.assertTrue(C.verify_receipt(log.inclusion(0, 39, ph=ph), log.db[0], log.pem, profile="rfc9943")["ok"])



@TC.NEEDS_CRYPTO
class Consistency(unittest.TestCase):
    def test_generated_chains_verify_and_tampering_refuses(self):
        log, rng = Log(-7, 40), random.Random(7)
        sizes = [s for s in range(0, len(log.db) + 1) if s == 0 or C._complete(s)]
        def acc(s):                     # peaks, -00 §9.2, as indices
            out, i, rest = [], 0, s
            while rest:
                top = (1 << (rest + 1).bit_length() - 1) - 1
                i += top
                out.append(i - 1)
                rest -= top
            return out

        def proof(s1, s2):
            paths = [[log.db[j] for j in inclusion_proof_path(p, s2 - 1)] for p in acc(s1)]
            roots, n = C.mmr_consistent_roots(s1, s2, [log.db[p] for p in acc(s1)], paths)
            right = [log.db[p] for p in acc(s2)][len(roots):]
            self.assertEqual(len(right), n)
            return R.cbor_encode([s1, s2, paths, right])

        for _ in range(60):
            chain = sorted(rng.sample(sizes, rng.randint(2, 5)))
            pb = R.cbor_encode({1: -7, 395: 3, -65933: chain[-1]})
            proofs = [proof(a, b) for a, b in zip(chain, chain[1:])]
            sig = log.sign(pb, b"".join(log.db[p] for p in acc(chain[-1])))
            rc = b"\xd2" + R.cbor_encode([pb, {396: {-2: proofs}}, None, sig])
            out = C.verify_mmr_consistency(rc, log.pem, chain[0], [log.db[p] for p in acc(chain[0])])
            self.assertTrue(out["ok"], (chain, out))
            self.assertEqual(out["accumulator"], [log.db[p].hex() for p in acc(chain[-1])])
            b = bytearray(rc)
            b[rng.randrange(len(b))] ^= 1 << rng.randrange(8)
            self.assertFalse(C.verify_mmr_consistency(bytes(b), log.pem, chain[0], [log.db[p] for p in acc(chain[0])])["ok"])
            if chain[0]:
                self.assertEqual(C.verify_mmr_consistency(rc, log.pem, 0, [])["stage"], "CHAIN_NOT_CONTIGUOUS")
        inc = Log(-7).inclusion(0, 39)
        out = C.verify_mmr_consistency(inc, log.pem, 0, [])
        self.assertEqual(out["stage"], "OTHER_RECEIPT_KIND")
        self.assertIn("verify_receipt", out["why"])
        out = C.verify_receipt(rc, log.db[0], log.pem)
        self.assertEqual(out["stage"], "OTHER_RECEIPT_KIND")
        self.assertIn("verify_mmr_consistency", out["why"])
        for bad_state in ((2, [b"\x00" * 32]), (3, []), (3, [b"\x00" * 31]), (-1, []), (True, [])):
            self.assertEqual(C.verify_mmr_consistency(rc, log.pem, *bad_state)["stage"], "TRUSTED_STATE_INVALID", bad_state)


def consistency_receipt(log, raw_ph, proofs, payload):
    return b"\xd2" + R.cbor_encode([raw_ph, {396: {-2: proofs}}, None, log.sign(raw_ph, payload)])


@TC.NEEDS_CRYPTO
class Edges(unittest.TestCase):
    """the cases the mutants of 2026-11-23 showed untested"""
    def test_decoder(self):
        rd = lambda h, det=True: C._cbor_read(X(h), 0, det)[0]  # noqa: E731
        self.assertIs(rd("f4"), False)
        self.assertIs(rd("f5"), True)
        self.assertIs(rd("f6"), None)
        self.assertEqual(rd("f7"), 23)
        for h in ("5801", "19", "a1", "", "fb3ff0"):                       # cut short: ValueError, not IndexError
            self.assertRaises(ValueError, C._cbor_read, X(h), 0, True)
        self.assertRaises(ValueError, rd, "fb3ff19999a0000000")      # float32(1.1) written as a double
        self.assertEqual(rd("fa3f8ccccd"), rd("fa3f8ccccd", False))        # 1.1f as single: shortest
        self.assertRaises(ValueError, rd, "fa7fc00000")                    # NaN as single: fits a half
        self.assertRaisesRegex(ValueError, "indefinite", rd, "bf")
        self.assertRaisesRegex(ValueError, "reserved", rd, "1c")
        self.assertEqual(rd("a2182a0001f6", False), {42: 0, 1: None})      # unprotected: no order required
        self.assertRaises(ValueError, rd, "a2182a0001f6")

    def test_structure_and_types(self):
        log = Log(-8)
        good = log.inclusion(0, 39)
        self.assertTrue(C.verify_receipt(good, log.db[0], log.pem)["ok"])
        for bad in (b"\xd1" + good[1:], b"\xd2\x85" + good[2:] + b"\xf6"):
            out = C.verify_receipt(bad, log.db[0], log.pem)
            self.assertEqual(out["stage"], "MALFORMED_RECEIPT", out)
        v = R.cbor_decode(good[1:])
        for k, wrong in ((0, "text"), (1, [1]), (2, 7), (3, "sig")):
            w = list(v)
            w[k] = wrong
            out = C._verify_mmr_inclusion(b"\xd2" + R.cbor_encode(w), log.db[0], log.pem, "rfc9942")
            self.assertIn("COSE_Sign1 must be", out["why"], (k, out))
        # an unprotected header written in another key order is read (it is not signed, -00 §7 binds the protected one)
        raw = b"\xd2\x84" + R.cbor_encode(v[0]) + b"\xa2\x19\x01\x8c" + R.cbor_encode(v[1][396]) + b"\x04\x41k" + b"\xf6" + R.cbor_encode(v[3])
        self.assertTrue(C.verify_receipt(raw, log.db[0], log.pem)["ok"])
        self.assertIs(C.verify_receipt(good, log.db[0], log.pem)["payload_attached"], False)

    def test_consistency_edges(self):
        log = Log(-7, 1)
        pay = log.db[0]
        proof = R.cbor_encode([0, 1, [], [pay]])
        ph = lambda tail: b"\xa3\x01\x26\x19\x01\x8b" + tail  # noqa: E731
        out = C.verify_mmr_consistency(consistency_receipt(log, ph(b"\x03\x3a\x00\x01\x01\x8c\x01"), [proof], pay), log.pem, 0, [])
        self.assertTrue(out["ok"], out)
        self.assertEqual((out["payload_attached"], out["ignored_labels"]), (False, []))
        for tail, stage in ((b"\xf9\x42\x00\x3a\x00\x01\x01\x8c\x01", "UNSUPPORTED_VDS"),   # vds 3.0
                            (b"\x03\x3a\x00\x01\x01\x8c\x20", "SIGNED_SIZE_NOT_UINT")):        # tree-size-2 -1
            out = C.verify_mmr_consistency(consistency_receipt(log, ph(tail), [proof], pay), log.pem, 0, [])
            self.assertEqual(out["stage"], stage, out)
        good_ph = ph(b"\x03\x3a\x00\x01\x01\x8c\x01")
        for name, pr in (("3 elements", [0, 1, []]), ("5 elements", [0, 1, [], [pay], 0]), ("size true", [True, 1, [], [pay]]),
                         ("size -1", [-1, 1, [], [pay]]), ("second size -1", [0, -1, [], [pay]]), ("paths a map", [0, 1, {}, [pay]]),
                         ("65 paths", [0, 1, [[]] * 65, [pay]]), ("second size true", [0, True, [], [pay]])):
            out = C.verify_mmr_consistency(consistency_receipt(log, good_ph, [R.cbor_encode(pr)], pay), log.pem, 0, [])
            self.assertEqual(out["stage"], "MALFORMED_PROOF", (name, out))
        with self.assertRaises(C.MmrShapeError) as cm:
            C.mmr_consistent_roots(1, 3, [], [[pay]])
        self.assertEqual(cm.exception.cls, "peak_count_mismatch")

    def test_review_of_7d87346(self):
        """what no test held: bytes after the receipt, a path on a peak both sizes share, a key on another curve than
        the alg, the index at its bound"""
        logs = {a: Log(a) for a in (-8, -7, -35)}
        log = logs[-8]
        good = log.inclusion(4, 39)
        self.assertTrue(C.verify_receipt(good, log.db[4], log.pem)["ok"])
        for tail in (b"\x00", b"\xf6", good):
            self.assertFalse(C.verify_receipt(good + tail, log.db[4], log.pem)["ok"], tail[:1])
        # 7 -> 8 nodes (4 -> 5 leaves): the peak of 7 is a peak of 8, its path MUST be empty (-00 §7.1.1)
        peak7 = acc_of(7)
        self.assertEqual(C.mmr_consistent_roots(7, 8, peak7, [[]]), (peak7, 1))
        with self.assertRaises(C.MmrShapeError) as cm:
            C.mmr_consistent_roots(7, 8, peak7, [[peak7[0]]])
        self.assertEqual(cm.exception.cls, "path_length_mismatch")
        for alg, other in ((-7, -35), (-35, -7)):
            out = C.verify_receipt(logs[alg].inclusion(4, 39), logs[alg].db[4], logs[other].pem)
            self.assertEqual((out["ok"], out["stage"]), (False, "KEY_CURVE_MISMATCH"), (alg, other, out))
        for alg, other in ((-8, -7), (-7, -8), (-35, -8)):
            self.assertFalse(C.verify_receipt(logs[alg].inclusion(4, 39), logs[alg].db[4], logs[other].pem)["ok"])
        one = Log(-8, 1)
        for index, ok in (((1 << 64) - 2, True), ((1 << 64) - 1, False)):
            out = C.verify_receipt(one.inclusion(0, 1, proofs=[R.cbor_encode([index, []])]), one.db[0], one.pem)
            self.assertEqual(out["ok"], ok, (index, out))
        self.assertEqual(out["stage"], "MALFORMED_PROOF")
        # without cryptography the signature is not evaluated: never ok, for inclusion and for consistency
        from unittest import mock
        blocked = {m: None for m in list(sys.modules) if m == "cryptography" or m.startswith("cryptography.")}
        chain = KAT["receipt_chains"][0]
        t = chain["trusted_tree_size_1"]
        self.assertTrue(C.verify_mmr_consistency(X(chain["receipt_cbor_hex"]), es256_pem(), t, acc_of(t))["ok"])
        with mock.patch.dict(sys.modules, blocked):
            a = C.verify_receipt(good, log.db[4], log.pem)
            b = C.verify_mmr_consistency(X(chain["receipt_cbor_hex"]), log.pem, t, acc_of(t))
        self.assertEqual([(o["ok"], o["stage"]) for o in (a, b)], [(False, "BACKEND_MISSING")] * 2, (a, b))


if __name__ == "__main__":
    unittest.main()
