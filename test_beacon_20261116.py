#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""SPEC v0.10 §18-§19 (16/11/2026): a "not before" bound from the NIST Randomness Beacon 2.0, inside a payment entry.

The data are real: six consecutive pulses of NIST chain 2 and the beacon's certificate, fetched on 2026-11-16
(spec/vectors/beacon/README.md). The payment ledger of the vectors is rebuilt here from the pulse file and compared byte
for byte; its IBANs are published examples, its amounts fictitious. Every refused or invalid input below is derived
from these files by code. When a mutation must reach a check behind the signature, the pulses are re-signed with a
key made here and pinned with its own certificate (certificateId, signature and outputValue recomputed), so that the
mutation, not the signature, is what the check meets.

Positive control: before 0.25.1+beacon there is no cryptovalid_beacon module and no `beacon` command: every test here
fails at the import or with exit 2 from cryptovalid-verify. The draft NIST IR 8213 serialization is run beside the
deployed one on the six pulses: it must verify none of them, or the check of the format would prove nothing."""
import base64
import copy
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from datetime import datetime, timedelta, timezone
from unittest import mock

sys.dont_write_bytecode = True
ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "verifiers"))
import cryptovalid_beacon as B  # noqa: E402
import cryptovalid_tsa as T  # noqa: E402
import evidence_pack as EP  # noqa: E402
import verifier  # noqa: E402

VB = os.path.join(ROOT, "spec", "vectors", "beacon")
VN = os.path.join(VB, "nist")
CERT = os.path.join(VN, "certificate_5b6386e6ac8a993b.pem")
PULSES = list(range(2030298, 2030304))
LEDGER = os.path.join(VB, "payment_ledger.jsonl")
EXAMPLE_IBANS = ("GB82WEST12345698765432", "DE89370400440532013000")   # published examples, never a real account
WIDE = 10 ** 9   # a maximum window width that does not bind (seconds): the tests of the width give their own

try:
    import cryptography  # noqa: F401
    HAVE_CRYPTO = True
except ImportError:
    HAVE_CRYPTO = False
if os.environ.get("CV_REQUIRE_CRYPTO") == "1" and not HAVE_CRYPTO:
    raise RuntimeError("CV_REQUIRE_CRYPTO=1 and cryptography is not importable")
NEEDS_CRYPTO = unittest.skipUnless(HAVE_CRYPTO, "needs cryptography (RSA and X.509)")
NEEDS_OPENSSL = unittest.skipIf(shutil.which("openssl") is None, "needs openssl (the TSA's signature is checked with it)")


def pf(i):
    return os.path.join(VN, f"pulse_{i}.json")


def raw(i):
    with open(pf(i), "rb") as f:
        return f.read()


def pulse(i):
    return json.loads(raw(i))["pulse"]


def doc(p):
    return json.dumps({"pulse": p}, indent=2).encode()


# ───────────────────────────── the payment ledger of the vectors, rebuilt from the pulse file

def chain(datas, ts, algo="sha256"):
    """a ledger (bytes) of these `data`, hashes computed by the format's rule (SPEC §3)"""
    out, prev = [], "0" * 64
    for i, (d, t) in enumerate(zip(datas, ts)):
        e = {"idx": i, "ts": t, "data": d, "prev_hash": prev}
        e["self_hash"] = verifier.hash_with(algo, verifier.canonical_payload(e))
        prev = e["self_hash"]
        out.append(json.dumps(e, ensure_ascii=False, sort_keys=True))
    return ("\n".join(out) + "\n").encode()


# fictitious parties: the salts are derived from a label, so the vector is rebuilt byte for byte
NAMES = {"payer_iban_commitment": EXAMPLE_IBANS[0], "payee_iban_commitment": EXAMPLE_IBANS[1],
         "payer_name_commitment": "Maria Example", "payer_details_commitment": "Via Esempio 1, 00100 Roma, IT",
         "payee_name_commitment": "Example Supplies Ltd", "end_to_end_id_commitment": "INV-2026-0001"}
# random identifiers of SPEC §18 (version 4 UUIDs), fixed so that the vector is rebuilt byte for byte
PIDS = ("0f8b6c2e-4a71-4d3b-9c55-1e2f3a4b5c6d", "7d1e9a40-2b6c-4f8e-a3d2-5c6b7a8e9f01", "c3a9e5d1-8f2b-4e6c-b7a1-0d9e8f7a6b5c")


def salt_of(member, label="v1"):
    return hashlib.sha256(f"test salt {label} {member}".encode()).digest()[:16]   # 128 bits (SPEC §18)


def raw_commitment(member, salt, value):
    """the bytes of SPEC §18 without the normalisation: what a writer that skipped the IBAN rule would commit"""
    return hashlib.sha256(b"cryptovalid-payment/1/" + member.encode() + b"\x00" + salt + value.encode()).hexdigest()


def record_salt_of(i):
    return hashlib.sha256(f"test record salt {i}".encode()).hexdigest()[:32]   # 16 bytes, derived: the vector is rebuilt


def beacon_of(p):
    return {"source": "nist-beacon-2.0", "chain_index": p["chainIndex"], "pulse_index": p["pulseIndex"],
            "output_value": p["outputValue"]}


def payment_datas(p):
    """entry 0: a payment carrying pulse 2030302, with the five commitments of NAMES; entry 1: a payment carrying the
    value of pulse p, with its two IBAN commitments only (payer DE89..., payee GB82..., salts labelled e1); entry 2: not a
    payment"""
    gb, de = EXAMPLE_IBANS
    first = {"profile": B.PAYMENT_PROFILE, "payment_id": PIDS[0], "amount": "1250.00", "currency": "EUR",
             "beacons": [beacon_of(pulse(2030302))], "record_salt": record_salt_of(1)}
    for m, v in NAMES.items():
        first[m] = B.commitment(m, salt_of(m), v)
    return [
        first,
        {"profile": B.PAYMENT_PROFILE, "payment_id": PIDS[1], "amount": "99.95", "currency": "EUR",
         "payer_iban_commitment": B.commitment("payer_iban_commitment", salt_of("payer_iban_commitment", "e1"), de),
         "payee_iban_commitment": B.commitment("payee_iban_commitment", salt_of("payee_iban_commitment", "e1"), gb),
         "beacons": [beacon_of(p)], "record_salt": record_salt_of(2)},
        {"event": "note", "text": "not a payment"},
    ]


def payment_ts(p):
    t = B.pulse_time(p["timeStamp"])
    return [(t + timedelta(seconds=s)).strftime("%Y-%m-%dT%H:%M:%SZ") for s in (-60, 30, 45)]


def build_payment_ledger():
    p = pulse(2030303)
    return chain(payment_datas(p), payment_ts(p))


def write(td, name, b):
    path = os.path.join(td, name)
    with open(path, "wb") as f:
        f.write(b)
    return path


def run(ledger, entry=1, p=2030303, prev=2030302, cert=CERT, **kw):
    return B.verify_beacon_entry(ledger, entry, raw(p) if isinstance(p, int) else p,
                                 raw(prev) if isinstance(prev, int) else prev, cert, **kw)


def draft_message(p):
    """the draft NIST IR 8213 (May 2019) serialization: 8-byte length prefixes, external.statusCode in 8 bytes"""
    h = bytes.fromhex

    def lp(b):
        return len(b).to_bytes(8, "big") + b
    out = lp(p["uri"].encode()) + lp(p["version"].encode()) + p["cipherSuite"].to_bytes(4, "big") + p["period"].to_bytes(4, "big")
    out += lp(h(p["certificateId"])) + p["chainIndex"].to_bytes(8, "big") + p["pulseIndex"].to_bytes(8, "big")
    out += lp(p["timeStamp"].encode()) + lp(h(p["localRandomValue"]))
    e = p["external"]
    out += lp(h(e["sourceId"])) + e["statusCode"].to_bytes(8, "big") + lp(h(e["value"]))
    for x in p["listValues"]:
        out += lp(h(x["value"]))
    return out + lp(h(p["precommitmentValue"])) + p["statusCode"].to_bytes(4, "big")


class OwnBeacon:
    """a key and certificate made here, to re-sign mutated pulses so a mutation reaches the check after the signature"""

    def __init__(self, not_before=None, not_after=None, bits=2048):
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test beacon")])
        nb = not_before or datetime(2026, 1, 1, tzinfo=timezone.utc)
        na = not_after or datetime(2027, 12, 31, tzinfo=timezone.utc)
        cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(self.key.public_key())
                .serial_number(1).not_valid_before(nb).not_valid_after(na).sign(self.key, hashes.SHA256()))
        self.der = cert.public_bytes(serialization.Encoding.DER)
        self.pem = cert.public_bytes(serialization.Encoding.PEM)
        self.cid = hashlib.sha512(self.der).hexdigest()

    def sign(self, p, keep_cid=False, output=True):
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding
        p = copy.deepcopy(p)
        if not keep_cid:
            p["certificateId"] = self.cid
        m = B.signed_message(p)
        s = self.key.sign(m, padding.PKCS1v15(), hashes.SHA512())
        p["signatureValue"] = s.hex().upper()
        if output:
            p["outputValue"] = hashlib.sha512(m + s).hexdigest().upper()
        return p


_OWN = None


def own():
    global _OWN
    if _OWN is None:
        _OWN = OwnBeacon()
    return _OWN


def resigned_pair(mutate_prev=None, mutate_pulse=None, relink=True):
    """(prev, pulse, ledger bytes): the real pair re-signed by OwnBeacon, after the mutations; the pulse's previous
    list value relinked to the new predecessor, the ledger's beacon value set to the new pulse's outputValue"""
    o = own()
    q = pulse(2030302)
    if mutate_prev:
        mutate_prev(q)
    q = o.sign(q)
    p = pulse(2030303)
    if relink:
        p["listValues"][0]["value"] = q["outputValue"]
    if mutate_pulse:
        mutate_pulse(p)
    p = o.sign(p)
    return q, p, chain(payment_datas(p), payment_ts(p))


# ───────────────────────────── tests

class Vectors(unittest.TestCase):
    def test_files_are_the_ones_the_readme_names(self):
        with open(os.path.join(VB, "README.md"), encoding="utf-8") as f:
            readme = f.read()
        for name in [f"nist/pulse_{i}.json" for i in PULSES] + ["nist/certificate_5b6386e6ac8a993b.pem",
                                                                 "payment_ledger.jsonl"]:
            with open(os.path.join(VB, name), "rb") as f:
                self.assertIn(f"{hashlib.sha256(f.read()).hexdigest()}  {name}", readme)

    def test_payment_ledger_is_rebuilt_from_the_pulse(self):
        with open(LEDGER, "rb") as f:
            self.assertEqual(f.read(), build_payment_ledger())

    def test_pulses_are_consecutive_and_served_as_one_object(self):
        for i in PULSES:
            p = B.parse_pulse(pf(i))
            self.assertEqual((p["chainIndex"], p["pulseIndex"]), (2, i))


@NEEDS_CRYPTO
class RealPulses(unittest.TestCase):
    def test_every_consecutive_pair_verifies(self):
        for i in PULSES[1:]:
            p, q = B.parse_pulse(pf(i)), B.parse_pulse(pf(i - 1))
            b = {"source": "nist-beacon-2.0", "chain_index": 2, "pulse_index": i, "output_value": p["outputValue"]}
            r = B.check_pulses(b, p, q, CERT)
            self.assertEqual(r["pulse_index"], i)
            self.assertEqual(r["period_ms"], 60000)

    def test_draft_serialization_verifies_none_deployed_verifies_all(self):
        """the divergence from the draft NIST IR 8213, measured: with the draft's rules 0/6, with the SPEC's 6/6"""
        from cryptography import x509
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding
        with open(CERT, "rb") as f:
            key = x509.load_pem_x509_certificate(f.read()).public_key()
        counts = {"draft_sig": 0, "draft_out": 0, "spec_sig": 0, "spec_out": 0}
        for i in PULSES:
            p = pulse(i)
            s = bytes.fromhex(p["signatureValue"])
            for tag, m, out_in in (("draft", draft_message(p), draft_message(p) + len(s).to_bytes(8, "big") + s),
                                   ("spec", B.signed_message(p), B.signed_message(p) + s)):
                try:
                    key.verify(s, m, padding.PKCS1v15(), hashes.SHA512())
                    counts[tag + "_sig"] += 1
                except InvalidSignature:
                    pass
                counts[tag + "_out"] += hashlib.sha512(out_in).hexdigest().upper() == p["outputValue"].upper()
        self.assertEqual(counts, {"draft_sig": 0, "draft_out": 0, "spec_sig": 6, "spec_out": 6})

    def test_entry_receipt(self):
        r = run(LEDGER)
        self.assertEqual((r["status"], r["valid"], r["reason"]), ("verified", True, None), r)
        self.assertEqual(r["bounds"]["not_before"], "2026-11-16T13:04:00.000Z")
        self.assertEqual(r["bounds"]["not_before_operator_promise"], "2026-11-16T13:03:00.000Z")
        self.assertIsNone(r["bounds"]["against_an_operator_breaking_its_promises"])
        self.assertEqual(r["entry"]["covers"], ["profile", "payment_id", "amount", "currency", "payer_iban_commitment",
                                                "payee_iban_commitment", "beacons", "record_salt"])
        self.assertEqual([list(x)[0] for x in r["scope"]["proves"]], ["composed_after_pulse"])
        self.assertEqual(r["entry"]["payment"], {"payment_id": PIDS[1], "amount": "99.95", "currency": "EUR"})
        self.assertNotIn(EXAMPLE_IBANS[0], json.dumps(r))             # no IBAN in clear, in the ledger or the receipt
        self.assertIs(r["record_complete"], False)                  # no window without the pack's token
        self.assertEqual(r["pulse"]["certificate_sha512"], pulse(2030303)["certificateId"])
        self.assertIsNone(r["window"])

    def test_sha3_ledger_and_upper_case_value(self):
        p = pulse(2030303)
        d = payment_datas(p)
        with tempfile.TemporaryDirectory() as td:
            r = run(write(td, "l.jsonl", chain(d, payment_ts(p), "sha3_256")))
            self.assertEqual(r["status"], "verified", r)
            d[1]["beacons"][0]["output_value"] = p["outputValue"].lower()   # one rule: upper case, as NIST serves it
            r = run(write(td, "l2.jsonl", chain(d, payment_ts(p), "sha3_256")))
            self.assertEqual((r["status"], r["detail"][:26]), ("refused", "beacons[0].output_value: n"))

    def test_without_cryptography_not_evaluated(self):
        real = __import__

        def imp(name, *a, **kw):
            if name.startswith("cryptography"):
                raise ImportError("blocked by the test")
            return real(name, *a, **kw)
        with mock.patch("builtins.__import__", imp):
            r = run(LEDGER)
        self.assertEqual((r["status"], r["reason"], r["valid"]), ("not_evaluated", "backend_missing", False))


class PulseGrammar(unittest.TestCase):
    """generative: every member of every object of the real pulse, removed, doubled, joined by an unknown member,
    given every wrong type; every hex value broken; refused with pulse_malformed, never read"""

    def paths(self, p):
        out = []
        for k in p:
            out.append((k,))
            if k == "external":
                out += [(k, x) for x in p[k]]
            if k == "listValues":
                for i, lv in enumerate(p[k]):
                    out += [(k, i, x) for x in lv]
        return out

    @staticmethod
    def get_parent(p, path):
        o = p
        for x in path[:-1]:
            o = o[x]
        return o

    def assertRefused(self, b, why):
        r = run(LEDGER, p=b)
        self.assertEqual((r["status"], r["reason"]), ("refused", "pulse_malformed"), (why, r))

    def test_generative_members(self):
        base = pulse(2030303)
        n = 0
        wrong = [None, True, False, 0, -1, 1.5, "", "x", [], {}, 2 ** 53, "0" * 128 + "0"]
        for path in self.paths(base):
            p = copy.deepcopy(base)
            del self.get_parent(p, path)[path[-1]]
            self.assertRefused(doc(p), ("delete", path))
            n += 1
            for w in wrong:
                p = copy.deepcopy(base)
                cur = self.get_parent(p, path)[path[-1]]
                if type(w) is type(cur) and w == cur:
                    continue
                if path[-1] == "uri" and isinstance(w, str) and w:   # a uri is any text: checked at step 3, not here
                    continue
                if path[-1] == "version" and isinstance(w, str) and w:
                    continue
                if type(w) is int and type(cur) is int and 0 <= w <= (B.U32 if path[-1] in (
                        "cipherSuite", "period", "statusCode") else verifier._SAFE_INT):
                    continue   # a value of the right type and range is read: the checks of rule 3 judge it (below)
                self.get_parent(p, path)[path[-1]] = w
                self.assertRefused(doc(p), ("type", path, w))
                n += 1
        # an unknown member at every level
        for where in ([], ["pulse"], ["pulse", "external"]) + tuple(["pulse", "listValues", i] for i in range(5)):
            p = {"pulse": copy.deepcopy(base)}
            o = p
            for x in where:
                o = o[x]
            o["zz_unknown"] = 0
            self.assertRefused(json.dumps(p).encode(), ("unknown", where))
            n += 1
        self.assertGreater(n, 200)

    def test_duplicate_keys_at_every_level(self):
        text = raw(2030303).decode()
        n = 0
        for key in ['"uri"', '"external"', '"sourceId"', '"type"', '"pulse"', '"statusCode"']:
            i = text.index(key)
            j = text.index(",", i)
            dup = text[:j + 1] + text[i:j + 1] + text[j + 1:]
            self.assertRefused(dup.encode(), ("dup", key))
            n += 1
        self.assertEqual(n, 6)

    def test_bad_hex_and_lengths(self):
        base = pulse(2030303)
        keys = ["certificateId", "localRandomValue", "precommitmentValue", "outputValue"]
        for k in keys + ["signatureValue"]:
            v = base[k]
            for bad in (v[:-1], v[:-2], v + "00", v[:-1] + "G", " " + v[1:], v[:-1] + "\n", "0x" + v[2:], v[:-1] + "é"):
                p = copy.deepcopy(base)
                p[k] = bad
                if k == "signatureValue" and bad in (v[:-2], v + "00"):
                    continue   # an even hex string of another length is read; the signature check refuses it (below)
                self.assertRefused(doc(p), (k, bad[-3:]))
        for f in ("sourceId", "value"):
            p = copy.deepcopy(base)
            p["external"][f] = p["external"][f][:-2]
            self.assertRefused(doc(p), f)
        for i in range(5):
            p = copy.deepcopy(base)
            p["listValues"][i]["value"] += "00"
            self.assertRefused(doc(p), i)

    def test_list_order_and_count(self):
        base = pulse(2030303)
        for mut in (lambda lv: lv.reverse(), lambda lv: lv.pop(), lambda lv: lv.append(copy.deepcopy(lv[0])),
                    lambda lv: lv.__setitem__(1, copy.deepcopy(lv[0]))):
            p = copy.deepcopy(base)
            mut(p["listValues"])
            self.assertRefused(doc(p), mut)

    def test_bad_documents(self):
        for b in (b"", b"[]", b"null", b'{"pulse": []}', b"\xef\xbb\xbf" + raw(2030303), raw(2030303)[:-5],
                  raw(2030303).replace(b"60000", b"6e4"), raw(2030303).replace(b'"2.0"', b'"2.0\\ud800"'),
                  b"\xff" + raw(2030303), b'{"pulse": ' * 600 + b"{}" + b"}" * 600):
            self.assertRefused(b, b[:20])

    def test_time_stamps(self):
        base = pulse(2030303)
        for t in ("2026-11-16T13:04:00Z", "2026-11-16T13:04:00.000+00:00", "2026-02-30T13:04:00.000Z",
                  "2026-11-16 13:04:00.000Z", "2026-11-16T13:04:00.0000Z", "２026-11-16T13:04:00.000Z",
                  "2026-11-16T24:00:00.000Z", "2026-11-16T13:04:00.000Z\n"):
            p = copy.deepcopy(base)
            p["timeStamp"] = t
            self.assertRefused(doc(p), t)

    def test_integer_ranges(self):
        base = pulse(2030303)
        for k, v in (("period", 2 ** 32), ("statusCode", -1), ("cipherSuite", 2 ** 32), ("pulseIndex", -1),
                     ("chainIndex", 2 ** 53)):
            p = copy.deepcopy(base)
            p[k] = v
            self.assertRefused(doc(p), k)
        p = copy.deepcopy(base)
        p["external"]["statusCode"] = 2 ** 32   # the draft's uint64 does not fit the deployed 4 bytes
        self.assertRefused(doc(p), "external.statusCode")

    def test_texts(self):
        base = pulse(2030303)
        for k in ("uri", "version"):
            for bad in (base[k] + "\n", base[k] + "\x00", "\x85" + base[k], base[k] + "\x7f", "x" * 2049):
                p = copy.deepcopy(base)
                p[k] = bad
                self.assertRefused(doc(p), (k, bad[-2:]))
        p = copy.deepcopy(base)
        p["listValues"][2]["uri"] = "u" * 2049
        self.assertRefused(doc(p), "list uri")
        p = copy.deepcopy(base)
        p["listValues"][2]["uri"] = "u" * 2048                      # the bound itself is read (the list uris are unsigned)
        self.assertEqual(run(LEDGER, p=doc(p))["reason"], None if HAVE_CRYPTO else "backend_missing")

    def test_size_and_file_kind(self):
        r = run(LEDGER, p=raw(2030303) + b" " * B.MAX_PULSE)
        self.assertEqual((r["status"], r["reason"]), ("refused", "input_too_large"))
        with tempfile.TemporaryDirectory() as td:
            big = write(td, "big.json", raw(2030303) + b" " * (B.MAX_PULSE - len(raw(2030303)) + 1))
            r = run(LEDGER, p=big)
            self.assertEqual((r["status"], r["reason"]), ("refused", "input_too_large"))
            edge = write(td, "edge.json", raw(2030303) + b" " * (B.MAX_PULSE - len(raw(2030303))))
            self.assertNotEqual(run(LEDGER, p=edge)["status"], "refused")
            r = run(LEDGER, p=td)
            self.assertEqual((r["status"], r["reason"]), ("refused", "input_unreadable"))
            r = run(LEDGER, p=os.path.join(td, "absent"))
            self.assertEqual((r["status"], r["reason"]), ("refused", "input_unreadable"))
            os.mkfifo(os.path.join(td, "fifo"))
            r = run(LEDGER, p=os.path.join(td, "fifo"))
            self.assertEqual((r["status"], r["reason"]), ("refused", "input_unreadable"))


@NEEDS_CRYPTO
class PulseChecks(unittest.TestCase):
    """each check of SPEC §19 rule 3 reached by a mutation of the real pulses (re-signed where the check is behind
    the signature), and failing with its own reason"""

    def assertInvalid(self, r, reason):
        self.assertEqual((r["status"], r["reason"], r["valid"]), ("invalid", reason, False), r)

    def with_own(self, q, p, led):
        with tempfile.TemporaryDirectory() as td:
            return run(write(td, "l.jsonl", led), p=doc(p), prev=doc(q), cert=own().pem)

    def test_positive_control_resigned_pair_verifies(self):
        q, p, led = resigned_pair()
        self.assertEqual(self.with_own(q, p, led)["status"], "verified")

    def test_version_cipher_status(self):
        for k, v, why in (("version", "2.1", "version_not_supported"), ("cipherSuite", 1, "cipher_suite_not_supported"),
                          ("statusCode", 1, "status_not_supported"), ("statusCode", 2, "status_not_supported"),
                          ("statusCode", 4, "status_not_supported"), ("statusCode", 8, "status_not_supported")):
            for which in ("pulse", "prev"):
                p, q = pulse(2030303), pulse(2030302)
                (p if which == "pulse" else q)[k] = v
                self.assertInvalid(run(LEDGER, p=doc(p), prev=doc(q)), why)

    def test_version_exactly_2_0(self):
        """NEMESIS b26: a pulse re-signed with version "2.0.1" (or "2.00", "2.0 ") is not version 2.0"""
        for v in ("2.0.1", "2.00", "2.0 ", "Version 2.0", "2"):
            q, p, led = resigned_pair(mutate_prev=lambda q: q.__setitem__("version", v),
                                      mutate_pulse=lambda p: p.__setitem__("version", v))
            self.assertInvalid(self.with_own(q, p, led), "version_not_supported")

    def test_pulse_mismatch(self):
        self.assertInvalid(run(LEDGER, p=2030302, prev=2030301), "pulse_mismatch")      # the wrong pulse
        self.assertInvalid(run(LEDGER, p=2030303, prev=2030301), "pulse_mismatch")      # not the predecessor
        self.assertInvalid(run(LEDGER, p=2030303, prev=2030303), "pulse_mismatch")
        p = pulse(2030303)
        p["uri"] = p["uri"].replace("https://", "http://")
        self.assertInvalid(run(LEDGER, p=doc(p)), "pulse_mismatch")
        p = pulse(2030303)
        p["chainIndex"] = 3
        self.assertInvalid(run(LEDGER, p=doc(p)), "pulse_mismatch")
        d = payment_datas(pulse(2030303))
        d[1]["beacons"][0]["chain_index"] = 1                          # only chain 2 is accepted (SPEC §19)
        with tempfile.TemporaryDirectory() as td:
            r = run(write(td, "l", chain(d, payment_ts(pulse(2030303)))))
        self.assertEqual((r["status"], r["reason"], r["detail"][:22]), ("refused", "payment_malformed", "beacons[0].chain_index"))

    def test_wrong_period_and_certificate_change_between_pulses(self):
        q, p, led = resigned_pair(mutate_pulse=lambda p: p.__setitem__("period", 30000))
        self.assertInvalid(self.with_own(q, p, led), "chain_inconsistent")
        q, p, led = resigned_pair(mutate_prev=lambda q: q.__setitem__("period", 30000),
                                  mutate_pulse=lambda p: p.__setitem__("period", 30000))
        self.assertInvalid(self.with_own(q, p, led), "period_mismatch")      # both 30 s, one minute apart
        q, p, led = resigned_pair(mutate_pulse=lambda p: p.__setitem__("timeStamp", "2026-11-16T13:04:00.001Z"))
        self.assertInvalid(self.with_own(q, p, led), "period_mismatch")
        q, p, led = resigned_pair(mutate_pulse=lambda p: p.__setitem__("timeStamp", "2026-11-16T13:03:59.999Z"))
        self.assertInvalid(self.with_own(q, p, led), "period_mismatch")
        o = own()
        q = o.sign(pulse(2030302))
        p = pulse(2030303)
        p["listValues"][0]["value"] = q["outputValue"]
        p = o.sign(p, keep_cid=True)                     # signed by the pinned key, but names NIST's certificate
        self.assertInvalid(self.with_own(q, p, chain(payment_datas(p), payment_ts(p))), "chain_inconsistent")

    def test_wrong_certificate(self):
        self.assertInvalid(run(LEDGER, cert=own().pem), "certificate_mismatch")
        self.assertInvalid(run(LEDGER, cert=own().der), "certificate_mismatch")
        with open(CERT, "rb") as f:
            pem = f.read()
        from cryptography import x509
        from cryptography.hazmat.primitives import serialization
        der = x509.load_pem_x509_certificate(pem).public_bytes(serialization.Encoding.DER)
        self.assertEqual(run(LEDGER, cert=der)["status"], "verified")           # DER of the same certificate
        for bad, why in ((pem + pem, "two certificates"), (pem[:200], "cut"), (b"", "empty"), (b"\x30\x03\x02\x01\x01", "der"),
                         (pem.replace(b"CERTIFICATE", b"PUBLIC KEY"), "another block"),
                         (pem + b"-----BEGIN PRIVATE KEY-----\n", "a second block")):
            r = run(LEDGER, cert=bad)
            self.assertEqual(r["status"], "refused", (why, r))

    def test_certificate_validity_and_key(self):
        for nb, na in ((datetime(2026, 11, 16, 13, 3, 30, tzinfo=timezone.utc), None),
                       (None, datetime(2026, 11, 16, 13, 3, 30, tzinfo=timezone.utc))):
            o = OwnBeacon(nb, na)
            q = o.sign(pulse(2030302))
            p = pulse(2030303)
            p["listValues"][0]["value"] = q["outputValue"]
            p = o.sign(p)
            with tempfile.TemporaryDirectory() as td:
                r = run(write(td, "l", chain(payment_datas(p), payment_ts(p))), p=doc(p), prev=doc(q), cert=o.pem)
            self.assertInvalid(r, "certificate_not_valid_at_pulse_time")
        o = OwnBeacon(bits=1024)
        q = o.sign(pulse(2030302))
        p = pulse(2030303)
        p["listValues"][0]["value"] = q["outputValue"]
        p = o.sign(p)
        with tempfile.TemporaryDirectory() as td:
            r = run(write(td, "l", chain(payment_datas(p), payment_ts(p))), p=doc(p), prev=doc(q), cert=o.pem)
        self.assertInvalid(r, "certificate_key_not_supported")

    def test_signature_from_another_key(self):
        o = own()
        p = o.sign(pulse(2030303), keep_cid=True)        # NIST's certificateId, another key's signature
        self.assertInvalid(run(LEDGER, p=doc(p)), "signature_invalid")
        q = o.sign(pulse(2030302), keep_cid=True)
        self.assertInvalid(run(LEDGER, prev=doc(q)), "signature_invalid")
        for k in ("timeStamp", "localRandomValue", "statusCode"):   # any signed field changed: the real signature fails
            p = pulse(2030303)
            p[k] = {"timeStamp": "2026-11-16T13:04:00.001Z", "localRandomValue": "00" * 64, "statusCode": 0}[k]
            if p[k] == pulse(2030303)[k]:
                p["external"]["statusCode"] = 1
            self.assertInvalid(run(LEDGER, p=doc(p)), "signature_invalid")
        p = pulse(2030303)
        p["signatureValue"] = p["signatureValue"][:-2]
        self.assertInvalid(run(LEDGER, p=doc(p)), "signature_invalid")
        p = pulse(2030303)
        p["listValues"][4]["uri"] = "https://example.invalid/"   # the list uris are not signed and not used
        self.assertEqual(run(LEDGER, p=doc(p))["status"], "verified")

    def test_output_value(self):
        q, p, led = resigned_pair()
        p["outputValue"] = hashlib.sha512(b"other").hexdigest().upper()
        self.assertInvalid(self.with_own(q, p, chain(payment_datas(p), payment_ts(p))), "output_value_mismatch")
        q2 = dict(q, outputValue=hashlib.sha512(b"other").hexdigest().upper())
        self.assertInvalid(self.with_own(q2, p, led), "output_value_mismatch")

    def test_previous_link(self):
        q, p, led = resigned_pair(relink=False)          # the pulse's previous value is NIST's, not the re-signed one
        self.assertInvalid(self.with_own(q, p, led), "previous_mismatch")

    def test_broken_commitment(self):
        q, p, led = resigned_pair(mutate_prev=lambda q: q.__setitem__("precommitmentValue", "AB" * 64))
        self.assertInvalid(self.with_own(q, p, led), "commitment_mismatch")
        q, p, led = resigned_pair(mutate_pulse=lambda p: p.__setitem__("localRandomValue", "CD" * 64))
        self.assertInvalid(self.with_own(q, p, led), "commitment_mismatch")

    def test_beacon_value_mismatch(self):
        p = pulse(2030303)
        for v in (pulse(2030302)["outputValue"], p["localRandomValue"], "00" * 64):
            d = payment_datas(p)
            d[1]["beacons"][0]["output_value"] = v
            with tempfile.TemporaryDirectory() as td:
                self.assertInvalid(run(write(td, "l", chain(d, payment_ts(p)))), "beacon_value_mismatch")


class Payment(unittest.TestCase):
    """SPEC §18: the closed payment profile and the IBAN check, generative"""

    def assertMalformed(self, data, member=None):
        with self.assertRaises(B.Refused) as c:
            B.check_payment(data)
        self.assertEqual(c.exception.reason, "payment_malformed", data)
        if member:
            self.assertTrue(c.exception.detail.startswith(member), (c.exception.detail, member))

    def test_published_examples_pass(self):
        for i in EXAMPLE_IBANS:
            self.assertIsNone(B.iban_problem(i))

    def test_single_character_substitutions(self):
        """measured: MOD 97-10 catches every substitution of a digit by a digit and of a letter by a letter; 7 of the
        1540 substitutions of the two examples, all a digit replaced by a letter, pass it (SPEC §18: the BBAN
        structure of the registry, which would refuse a letter there, is not checked)"""
        alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
        n, passed = 0, []
        for iban in EXAMPLE_IBANS:
            for pos in range(len(iban)):
                for c in alphabet:
                    if c == iban[pos]:
                        continue
                    s = iban[:pos] + c + iban[pos + 1:]
                    n += 1
                    if B.iban_problem(s) is None:
                        passed.append(s)
                        self.assertTrue(iban[pos].isdigit() and c.isalpha(), s)
        self.assertEqual(n, (22 + 22) * 35)
        self.assertEqual(sorted(passed), sorted([
            "GB82WEST1234569D765432", "GB82WEST12345698G65432", "GB82WEST123456987654L2", "DE893S0400440532013000",
            "DE893704T0440532013000", "DE893704004T0532013000", "DE89370400440532I13000"]))

    def test_every_adjacent_transposition_is_caught(self):
        for iban in EXAMPLE_IBANS:
            for pos in range(len(iban) - 1):
                if iban[pos] == iban[pos + 1]:
                    continue
                s = iban[:pos] + iban[pos + 1] + iban[pos] + iban[pos + 2:]
                self.assertIsNotNone(B.iban_problem(s), s)

    def test_forms(self):
        gb = EXAMPLE_IBANS[0]
        cases = {gb.lower(): "iban_charset", gb[:4] + " " + gb[4:]: "iban_charset", gb + "\n": "iban_charset",
                 "GB82": "iban_length", "GB82WEST123456": "iban_length", gb + "0" * 13: "iban_length", "GB82WEST1234569876543Ä": "iban_charset",
                 "1282WEST12345698765432": "iban_charset", "GBX2WEST12345698765432": "iban_charset",
                 "GB00WEST12345698765432": "iban_check_digits", "GB99WEST12345698765432": "iban_check_digits",
                 "GB01WEST12345698765432": "iban_check_digits", "GB83WEST12345698765432": "iban_checksum",
                 "GB82WEST1234569876543２": "iban_charset", 1: "iban_type", None: "iban_type", "": "iban_charset"}
        for v, why in cases.items():
            self.assertEqual(B.iban_problem(v), why, v)
        # 00 / 01 / 99 pass the modulo exactly when 97 / 98 / 02 do: the range rule is what refuses them
        for good in EXAMPLE_IBANS:
            for cd in range(100):
                s = good[:2] + f"{cd:02d}" + good[4:]
                bare = int("".join(str(int(c, 36)) for c in s[4:] + s[:4])) % 97 == 1
                self.assertEqual(B.iban_problem(s) is None, bare and 2 <= cd <= 98, s)

    def test_profile_closed(self):
        """every member removed, given every wrong type, and an unknown member at both levels"""
        base = payment_datas(pulse(2030303))[0]
        n = 0
        for k in list(base):
            d = copy.deepcopy(base)
            del d[k]
            n += 1
            if k in B.NAME_COMMITMENTS:
                self.assertIs(B.check_payment(d), d)        # a name commitment is optional
            elif k == "profile":
                with self.assertRaises(B.Refused) as c:
                    B.check_payment(d)
                self.assertEqual(c.exception.reason, "entry_not_a_payment")
            else:
                self.assertMalformed(d, k)
            for w in (None, True, 0, 1.5, [], {}, "", "x"):
                d = copy.deepcopy(base)
                d[k] = w
                n += 1
                if k == "profile":
                    with self.assertRaises(B.Refused):
                        B.check_payment(d)
                else:
                    self.assertMalformed(d, k)
        for d in (dict(base, zz=1), dict(base, beacons=[dict(base["beacons"][0], zz=1)]), dict(base, Amount="1.00"),
                  dict(base, beacon=base["beacons"][0])):
            self.assertMalformed(d)
        for k in base["beacons"][0]:
            d = copy.deepcopy(base)
            del d["beacons"][0][k]
            self.assertMalformed(d, "beacons[0]")
            for w in (None, True, -1, 1.5, [], {}, "", "0" * 127, 1):
                d = copy.deepcopy(base)
                d["beacons"][0][k] = w
                if k == "source" and isinstance(w, str):
                    with self.assertRaises(B.Refused) as c:
                        B.check_payment(d)
                    self.assertEqual(c.exception.reason, "source_not_supported")
                    continue
                if k == "pulse_index" and type(w) is int and w == 1:
                    self.assertIs(B.check_payment(d), d)
                    continue
                self.assertMalformed(d, "beacons[0]")
        for i, mut in enumerate((lambda d: d["beacons"][0].__setitem__("pulse_index", 0),
                                 lambda d: d["beacons"][0].__setitem__("chain_index", 1),
                                 lambda d: d["beacons"][0].__setitem__("chain_index", 0),
                                 lambda d: d["beacons"][0].__setitem__("output_value", d["beacons"][0]["output_value"].lower()))):
            d = copy.deepcopy(base)
            mut(d)
            self.assertMalformed(d, "beacons[0].")
        for s in ("curby-twine", "drand", "NIST-BEACON-2.0", "nist-beacon-2.0 "):
            d = copy.deepcopy(base)
            d["beacons"][0]["source"] = s
            with self.assertRaises(B.Refused) as c:
                B.check_payment(d)
            self.assertEqual(c.exception.reason, "source_not_supported")
        self.assertEqual(n, 12 * 9)

    def test_beacons_list(self):
        base = payment_datas(pulse(2030303))[1]
        b = base["beacons"][0]
        other = beacon_of(pulse(2030302))
        for v in ([b, other], [other, b], [b] + [dict(b, pulse_index=b["pulse_index"] + i) for i in range(1, 8)]):
            d = dict(base, beacons=v)
            self.assertIs(B.check_payment(d), d)
        for v in ([], [b] * 2, [b] + [dict(b, pulse_index=b["pulse_index"] + i) for i in range(1, 9)], b, "x", None):
            self.assertMalformed(dict(base, beacons=v), "beacons")
        with self.assertRaises(B.Refused) as c:   # a later element of another source: refused at its own place
            B.check_payment(dict(base, beacons=[b, dict(other, source="drand")]))
        self.assertEqual((c.exception.reason, c.exception.detail[:21]), ("source_not_supported", "beacons[1].source 'dr"))

    def test_missing_iban(self):
        base = payment_datas(pulse(2030303))[1]
        for k in ("payer_iban_commitment", "payee_iban_commitment"):
            d = dict(base)
            del d[k]
            self.assertMalformed(d, k)
        for k, v in (("payer_iban", EXAMPLE_IBANS[0]), ("payee_iban", EXAMPLE_IBANS[1])):   # an IBAN in clear is refused
            self.assertMalformed(dict(base, **{k: v}), k)

    def test_amounts_by_currency_minor_units(self):
        """one canonical form: exactly the currency's minor units after the point, no point when there are none"""
        base = payment_datas(pulse(2030303))[1]
        good = [("EUR", "1.00"), ("EUR", "0.01"), ("EUR", "1250.50"), ("EUR", "999999999999999999.99"), ("JPY", "1"),
                ("JPY", "1000"), ("BHD", "0.001"), ("CLF", "0.0001"), ("USD", "10.00")]
        for c, a in good:
            d = dict(base, currency=c, amount=a)
            self.assertIs(B.check_payment(d), d)
        bad = [("EUR", "1", "not_canonical"), ("EUR", "1.5", "not_canonical"), ("EUR", "1.001", "not_canonical"),
               ("JPY", "1.0", "not_canonical"), ("JPY", "1.", "not a decimal"), ("BHD", "0.0001", "not_canonical"),
               ("BHD", "0.01", "not_canonical"), ("CLF", "0.00001", "not_canonical"),
               ("EUR", "0.00", "not greater"), ("JPY", "0", "not greater"), ("BHD", "0.000", "not greater"),
               ("EUR", "-1.00", "not a decimal"), ("EUR", "+1.00", "not a decimal"), ("EUR", "01.00", "not a decimal"),
               ("EUR", ".50", "not a decimal"), ("EUR", "1e3", "not a decimal"), ("EUR", " 1.00", "not a decimal"),
               ("EUR", "1,00", "not a decimal"), ("EUR", "１.00", "not a decimal"), ("EUR", "1.00\n", "not a decimal"),
               ("EUR", "1000000000000000000.00", "not a decimal")]
        for c, a, why in bad:
            d = dict(base, currency=c, amount=a)
            with self.assertRaises(B.Refused) as e:
                B.check_payment(d)
            self.assertTrue(e.exception.detail.startswith("amount: " + why), (c, a, e.exception.detail))
        for a in (1250, 12.5, None, True):
            self.assertMalformed(dict(base, amount=a), "amount")

    def test_currencies(self):
        base = payment_datas(pulse(2030303))[1]
        self.assertEqual(len(B.MINOR_UNITS), 165)
        self.assertEqual({n: sum(1 for v in B.MINOR_UNITS.values() if v == n) for n in (0, 2, 3, 4)},
                         {0: 17, 2: 139, 3: 7, 4: 2})
        for c in ("XAU", "XDR", "XTS", "ABC", "eur", "EU", "EURO", "EUR ", "ÉUR", 978, None, "DEM", "ZWL"):
            self.assertMalformed(dict(base, currency=c), "currency")

    def test_payment_ids(self):
        """a version 4 UUID in lowercase canonical form (SPEC §18): a random identifier, never the payer's reference"""
        import uuid
        base = payment_datas(pulse(2030303))[1]
        for v in [str(uuid.uuid4()) for _ in range(200)] + list(PIDS):
            d = dict(base, payment_id=v)
            self.assertIs(B.check_payment(d), d)
        u = PIDS[0]
        for v in (u.upper(), u.replace("-", ""), "{" + u + "}", "urn:uuid:" + u, u + "\n", u[:-1], u + "0",
                  u[:14] + "1" + u[15:], u[:19] + "c" + u[20:], u[:19] + "7" + u[20:], str(uuid.uuid1()),
                  "NOTPROVIDED", "GB82WEST12345698765432", "PAY-2026-11-16-0001", "", 1, None):
            self.assertMalformed(dict(base, payment_id=v), "payment_id")


class Commitments(unittest.TestCase):
    """SPEC §18: SHA-256("cryptovalid-payment/1/" || member || 0x00 || 16-byte salt || normalised value)"""

    def test_encoding_against_openssl(self):
        """the bytes of the SPEC, hashed by openssl as an independent SHA-256"""
        if shutil.which("openssl") is None:
            self.skipTest("needs openssl as an independent SHA-256")
        for m, v in NAMES.items():
            data = b"cryptovalid-payment/1/" + m.encode() + b"\x00" + salt_of(m) + v.encode("utf-8")
            r = subprocess.run(["openssl", "dgst", "-sha256", "-r"], input=data, capture_output=True, check=True)
            self.assertEqual(B.commitment(m, salt_of(m), v), r.stdout.split()[0].decode())

    def test_member_salt_and_value(self):
        name, iban, s1 = "Maria Example", EXAMPLE_IBANS[0], salt_of("x", "1")
        self.assertNotEqual(B.commitment("payer_name_commitment", s1, name),
                            B.commitment("payee_name_commitment", s1, name))           # same value, another member
        self.assertNotEqual(B.commitment("payer_iban_commitment", s1, iban),
                            B.commitment("payee_iban_commitment", s1, iban))
        self.assertNotEqual(B.commitment("payer_name_commitment", s1, name),
                            B.commitment("payer_name_commitment", salt_of("x", "2"), name))   # another salt
        self.assertNotEqual(B.commitment("payer_name_commitment", s1, name),
                            B.commitment("payer_name_commitment", s1, "Maria Exampl"))
        for nfd, nfc in (("Jose\u0301", "Jos\u00e9"), ("Ma\u0301ria", "M\u00e1ria"), ("\u212b", "\u00c5")):
            for m in B.NAME_COMMITMENTS:
                self.assertEqual(B.commitment(m, s1, nfd), B.commitment(m, s1, nfc))     # NFC and NFD: one commitment
        for form in ("gb82west12345698765432", "GB82 WEST 1234 5698 7654 32", " gb82WEST12345698765432 "):
            self.assertEqual(B.commitment("payer_iban_commitment", s1, form), B.commitment("payer_iban_commitment", s1, iban))
        for bad, why in (("GB83WEST12345698765432", "iban_checksum"), ("GB82WEST1234569876543\u00df", "iban_charset"),
                         ("GB82\tWEST12345698765432", "iban_charset"), ("GB82", "iban_length")):
            with self.assertRaises(ValueError) as c:
                B.commitment("payer_iban_commitment", s1, bad)                   # never committed
            self.assertEqual(str(c.exception), why)
        self.assertEqual(B.commitment("payer_name_commitment", s1, "GB83WEST12345698765432"),
                         B.commitment("payer_name_commitment", s1, "GB83WEST12345698765432"))   # a name is not an IBAN
        for salt in (b"", b"\x00" * 15, b"\x00" * 17, b"\x00" * 32, "00" * 16, None):
            with self.assertRaises(ValueError):
                B.commitment("payer_name_commitment", salt, name)
        for v in ("", "x" * 1025, None, b"Maria"):
            with self.assertRaises(ValueError):
                B.commitment("payer_name_commitment", b"\x00" * 16, v)
        for m in ("payer_iban", "payment_id", "", None):
            with self.assertRaises(ValueError):
                B.commitment(m, b"\x00" * 16, name)
        self.assertEqual(len(B.commitment("payer_name_commitment", b"\x00" * 16, "x" * 1024)), 64)

    def test_commitment_forms_in_the_entry(self):
        base = payment_datas(pulse(2030303))[0]
        for k in B.COMMITMENTS:
            for bad in (base[k].upper(), base[k][:-1], base[k] + "0", "g" * 64, 0, None, ""):
                with self.assertRaises(B.Refused) as c:
                    B.check_payment(dict(base, **{k: bad}))
                self.assertTrue(c.exception.detail.startswith(k), c.exception.detail)

    @staticmethod
    def disclosure(member, value=None, salt=None, **extra):
        d = {"member": member, "salt": (salt or salt_of(member)).hex(), "value": value or NAMES[member]}
        d.update(extra)
        return json.dumps(d).encode()

    @NEEDS_CRYPTO
    def test_disclosures(self):
        run0 = dict(entry=0, p=2030302, prev=2030301)
        r = run(LEDGER, disclosures=[self.disclosure(m) for m in B.COMMITMENTS], **run0)
        self.assertEqual((r["status"], r["disclosed"]), ("verified", list(B.COMMITMENTS)), r)
        self.assertNotIn("Maria", json.dumps(r))                       # the receipt names members, never values
        for d, why in ((self.disclosure("payer_name_commitment", "Maria Exampel"), "another name"),
                       (self.disclosure("payer_name_commitment", salt=salt_of("payer_name_commitment", "v2")), "another salt"),
                       (self.disclosure("payee_name_commitment", NAMES["payer_name_commitment"],
                                        salt_of("payer_name_commitment")), "the payer's pair for the payee")):
            r = run(LEDGER, disclosures=[d], **run0)
            self.assertEqual((r["status"], r["reason"]), ("invalid", "disclosure_mismatch"), why)
        r = run(LEDGER, disclosures=[self.disclosure("payer_name_commitment")])       # entry 1 has no commitment
        self.assertEqual((r["status"], r["reason"]), ("invalid", "disclosure_mismatch"))
        good = json.loads(self.disclosure("payer_name_commitment"))
        for bad in ([self.disclosure("payer_name_commitment")] * 2,
                    [self.disclosure("payer_name_commitment", zz=1)],
                    [json.dumps(dict(good, salt=good["salt"].upper())).encode()],
                    [json.dumps(dict(good, salt=good["salt"][:-2])).encode()],
                    [json.dumps(dict(good, value="")).encode()],
                    [json.dumps(dict(good, member="payment_id")).encode()],
                    [json.dumps({k: v for k, v in good.items() if k != "value"}).encode()],
                    [b'{"member": "payer_name_commitment", "member": "payee_name_commitment", "salt": "%s", "value": "x"}'
                     % good["salt"].encode()],
                    [b"[]"], [b"\xff"]):
            r = run(LEDGER, disclosures=bad, **run0)
            self.assertEqual((r["status"], r["reason"]), ("refused", "disclosure_malformed"), bad)


@NEEDS_CRYPTO
class Binding(unittest.TestCase):
    """the cases Roberto asked for (16/11/2026): the bound covers the payment's value and parties inside one entry"""

    def assertReason(self, r, status, reason):
        self.assertEqual((r["status"], r["reason"]), (status, reason), r)

    def test_both_payments_of_the_vector(self):
        r = run(LEDGER, entry=0, p=2030302, prev=2030301)
        self.assertReason(r, "verified", None)
        self.assertEqual(r["entry"]["covers"], list(B.PAYMENT_KEYS))
        self.assertEqual(r["bounds"]["not_before"], "2026-11-16T13:03:00.000Z")
        self.assertEqual(run(LEDGER, entry=0)["reason"], "pulse_mismatch")     # entry 0 carries pulse 2030302

    def test_entry_without_beacon_and_non_payment(self):
        p = pulse(2030303)
        d = payment_datas(p)
        del d[1]["beacons"]
        with tempfile.TemporaryDirectory() as td:
            r = run(write(td, "l", chain(d, payment_ts(p))))
        self.assertReason(r, "refused", "payment_malformed")
        self.assertEqual(r["detail"], "beacons: member_missing")
        self.assertReason(run(LEDGER, entry=2), "refused", "entry_not_a_payment")
        self.assertReason(run(LEDGER, entry=3), "invalid", "entry_not_found")

    def test_beacon_moved_to_another_entry(self):
        p = pulse(2030303)
        d = payment_datas(p)
        d[0]["beacons"] = d[1].pop("beacons")
        with tempfile.TemporaryDirectory() as td:
            led = write(td, "l", chain(d, payment_ts(p)))
            r = run(led, entry=1)
            self.assertReason(r, "refused", "payment_malformed")
            r = run(led, entry=0)                       # it dates the entry that carries it, and names that one's members
            self.assertReason(r, "verified", None)
            self.assertEqual(r["entry"]["payment"]["amount"], "1250.00")

    def test_payment_id_unique_in_the_ledger(self):
        p = pulse(2030303)
        d = payment_datas(p)
        d[1]["payment_id"] = d[0]["payment_id"]
        with tempfile.TemporaryDirectory() as td:
            led = write(td, "l", chain(d, payment_ts(p)))
            self.assertReason(run(led), "invalid", "payment_id_not_unique")
            self.assertReason(run(led, entry=0, p=2030302, prev=2030301), "invalid", "payment_id_not_unique")
        d = payment_datas(p)
        d[2] = {"event": "note", "payment_id": d[1]["payment_id"]}       # not a payment entry: not counted
        with tempfile.TemporaryDirectory() as td:
            self.assertReason(run(write(td, "l", chain(d, payment_ts(p)))), "verified", None)

    def test_changed_without_recomputing_hashes_is_a_broken_chain(self):
        lines = build_payment_ledger().decode().split("\n")
        for old, new in (('"99.95"', '"99.96"'), (record_salt_of(2), record_salt_of(3)), ('"EUR"', '"USD"')):
            text = "\n".join([lines[0], lines[1].replace(old, new, 1)] + lines[2:])
            with tempfile.TemporaryDirectory() as td:
                self.assertReason(run(write(td, "l", text.encode())), "invalid", "ledger_invalid")

    def test_ledger_not_utf8(self):
        led = build_payment_ledger()
        for bad in (led.replace(b'"note"', b'"n\xe9te"'), led + b"\xff\n", led.replace(b'"note"', b'"n\xed\xa0\x80te"')):
            self.assertReason(run(bad), "invalid", "ledger_invalid")

    def test_bad_checksum_iban_committed(self):
        """an entry that commits to an IBAN with a bad checksum: the ledger cannot show it (only the commitment is
        there); the disclosure does, and is refused"""
        p = pulse(2030303)
        for k in B.IBAN_COMMITMENTS:
            d = payment_datas(p)
            bad = "GB83WEST12345698765432"
            d[1][k] = raw_commitment(k, salt_of(k, "bad"), bad)   # a writer that did not check the IBAN
            with tempfile.TemporaryDirectory() as td:
                led = write(td, "l", chain(d, payment_ts(p)))
                self.assertReason(run(led), "verified", None)
                disc = json.dumps({"member": k, "salt": salt_of(k, "bad").hex(), "value": bad}).encode()
                r = run(led, disclosures=[disc])
            self.assertReason(r, "invalid", "disclosure_iban_invalid")
            self.assertEqual(r["detail"], f"{k}: iban_checksum")

    def test_crypto_shredding(self):
        """the values and salts destroyed outside the ledger: the chain still passes and the commitment cannot be opened,
        not even with the right IBAN and every salt of a guessable kind"""
        r = run(LEDGER, entry=0, p=2030302, prev=2030301)
        self.assertReason(r, "verified", None)
        with open(LEDGER, encoding="utf-8") as f:
            c = json.loads(f.read().split("\n")[0])["data"]["payer_iban_commitment"]
        guesses = [bytes(16), b"\xff" * 16] + [i.to_bytes(16, "big") for i in range(1000)] + \
                  [hashlib.sha256(str(i).encode()).digest()[:16] for i in range(1000)]
        self.assertFalse(any(B.commitment("payer_iban_commitment", g, iban) == c for g in guesses for iban in EXAMPLE_IBANS))
        self.assertEqual(B.commitment("payer_iban_commitment", salt_of("payer_iban_commitment"), EXAMPLE_IBANS[0]), c)   # control: the kept salt opens it


@NEEDS_CRYPTO
@NEEDS_OPENSSL
class Window(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from pack_states_bench import LocalTsa
        cls.td = tempfile.mkdtemp()
        os.makedirs(os.path.join(cls.td, "tsa"))
        cls.tsa = LocalTsa(os.path.join(cls.td, "tsa"))
        cls.pack = os.path.join(cls.td, "pack")
        cls.ledger = os.path.join(cls.td, "payments.jsonl")
        with open(cls.ledger, "wb") as f:
            f.write(build_payment_ledger())
        cls.stamp(cls.pack, cls.ledger)

    @classmethod
    def stamp(cls, pack, ledger):
        import contextlib
        import io
        with contextlib.redirect_stdout(io.StringIO()):
            EP.build_pack([ledger], pack, subject="beacon test")
        with open(os.path.join(pack, "MANIFEST.json")) as f:
            m = json.load(f)
        m["rfc3161_timestamp"] = {"anchored": True, "tsa": "local", "tsr_b64": cls.tsa.token(m["manifest_digest_sha256"])}
        with open(os.path.join(pack, "MANIFEST.json"), "w") as f:
            json.dump(m, f, indent=1, sort_keys=True)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.td)

    def pins(self):
        return [self.tsa.j("ca.crt")]

    def test_window_verified(self):
        r = run(self.ledger, pack_dir=self.pack, tsa_certs=self.pins(), max_window_s=WIDE)
        self.assertEqual(r["status"], "verified", r)
        w = r["window"]
        self.assertEqual(w["not_before"], "2026-11-16T13:04:00.000Z")
        self.assertEqual(w["not_before_operator_promise"], "2026-11-16T13:03:00.000Z")
        self.assertGreaterEqual(B.gen_time_instant(w["not_after"]), B.gen_time_instant("2026-11-16T13:04:00Z"))
        self.assertEqual(w["pack_ledger"], "payments.jsonl")
        self.assertEqual((w["max_window_s"], w["tsa_revocation"]), (WIDE, "not_checked"))
        self.assertIs(r["record_complete"], False)                   # no witnessed checkpoint: not fixed in one history
        self.assertEqual(r["unique"], {"status": "not_established"})
        self.assertEqual([list(x)[0] for x in r["scope"]["proves"]], ["composed_after_pulse", "stamped_before_gen_time"])
        self.assertEqual([list(x)[0] for x in r["scope"]["does_not_prove"]],
                         ["not_execution", "not_unique", "not_ownership", "commitments_not_opened", "not_operator",
                          "not_qualified", "not_legal_beacon"])

    def test_window_with_the_ledger_given_from_outside_the_pack(self):
        r = run(build_payment_ledger(), pack_dir=self.pack, tsa_certs=self.pins(), max_window_s=WIDE)
        self.assertEqual(r["status"], "verified", r)

    def test_changed_after_the_beacon_with_hashes_recomputed(self):
        """a rewrite that keeps the beacon and recomputes every hash is still 'after T' (it was assembled after T):
        the upper bound is what catches it, because the pack's token binds the head of the original ledger"""
        p = pulse(2030303)
        for k, v in (("amount", "99.96"), ("currency", "USD"),
                     ("payee_iban_commitment", B.commitment("payee_iban_commitment", salt_of("payee_iban_commitment", "e9"),
                                                            "FR1420041010050500013M02606"))):
            d = payment_datas(p)
            d[1][k] = v
            led = chain(d, payment_ts(p))
            self.assertEqual(run(led)["status"], "verified")
            self.assertEqual(run(led, pack_dir=self.pack, tsa_certs=self.pins(), max_window_s=WIDE)["reason"], "ledger_not_in_pack")

    def test_entry_after_the_packed_head(self):
        led = build_payment_ledger()
        e = json.loads(led.decode().split("\n")[2])
        d = dict(payment_datas(pulse(2030303))[1], payment_id=PIDS[2])
        nxt = {"idx": 3, "ts": e["ts"], "data": d, "prev_hash": e["self_hash"]}
        nxt["self_hash"] = verifier.hash_with("sha256", verifier.canonical_payload(nxt))
        led2 = led + (json.dumps(nxt, sort_keys=True) + "\n").encode()
        self.assertEqual(run(led2, entry=3)["status"], "verified")
        self.assertEqual(run(led2, entry=3, pack_dir=self.pack, tsa_certs=self.pins(), max_window_s=WIDE)["reason"], "ledger_not_in_pack")

    def test_pack_problems(self):
        with tempfile.TemporaryDirectory() as td:
            pk = os.path.join(td, "p")
            shutil.copytree(self.pack, pk)
            other = os.path.join(td, "other")
            os.makedirs(other)
            from pack_states_bench import LocalTsa
            r = run(self.ledger, pack_dir=pk, tsa_certs=[LocalTsa(other).j("ca.crt")], max_window_s=WIDE)
            self.assertEqual((r["status"], r["reason"]), ("invalid", "time_anchor_not_verified"), r)
            self.assertEqual(r["bounds"]["not_before"], "2026-11-16T13:04:00.000Z")   # the bound stands without a window
            with open(os.path.join(pk, "payments.jsonl"), "ab") as f:
                f.write(b"\n")
            r = run(self.ledger, pack_dir=pk, tsa_certs=self.pins(), max_window_s=WIDE)
            self.assertEqual((r["status"], r["reason"]), ("invalid", "pack_not_valid"), r)
            r = run(self.ledger, pack_dir=pk, tsa_certs=[LocalTsa(other).j("ca.crt")], max_window_s=WIDE)
            self.assertEqual((r["status"], r["reason"]), ("invalid", "pack_not_valid"), r)   # content first, then the token
            pk3 = os.path.join(td, "p3")                            # a broken manifest signature: content and token
            shutil.copytree(self.pack, pk3)                         # still verified, the pack not valid
            with open(os.path.join(pk3, "MANIFEST.json")) as f:
                m3 = json.load(f)
            m3["manifest_signature"], m3["manifest_signer"] = base64.b64encode(b"\x01" * 64).decode(), "ab" * 32
            with open(os.path.join(pk3, "MANIFEST.json"), "w") as f:
                json.dump(m3, f)
            v3 = EP.verify_pack(pk3, tsa_certs=self.pins())
            self.assertEqual((v3["valid"], v3["states"]["sealed_content"]["state"], v3["states"]["time_anchor"]["state"]),
                             (False, "verified", "verified"))
            r = run(self.ledger, pack_dir=pk3, tsa_certs=self.pins(), max_window_s=WIDE)
            self.assertEqual((r["status"], r["reason"]), ("invalid", "pack_not_valid"), r)
            with open(os.path.join(self.pack, "MANIFEST.json")) as f:
                m = json.load(f)
            m["rfc3161_timestamp"] = {"anchored": False, "note": "no TSA provided"}
            pk2 = os.path.join(td, "p2")
            shutil.copytree(self.pack, pk2)
            with open(os.path.join(pk2, "MANIFEST.json"), "w") as f:
                json.dump(m, f)
            r = run(self.ledger, pack_dir=pk2, tsa_certs=self.pins(), max_window_s=WIDE)
            self.assertEqual((r["status"], r["reason"]), ("invalid", "time_anchor_not_verified"), r)

    def test_window_inverted_with_a_real_token(self):
        """the real freetsa.org token of spec/vectors/rfc3161 (requested on 2026-11-13) is before the pulse of 16/11"""
        V = os.path.join(ROOT, "spec", "vectors", "rfc3161")
        with open(os.path.join(V, "manifest.json")) as f:
            man = json.load(f)
        with open(os.path.join(V, "freetsa.tsr"), "rb") as f:
            v = T.verify_token(f.read(), bytes.fromhex(man["digest_sha256"]), "sha256",
                               [os.path.join(V, "freetsa_cacert.pem")])
        self.assertEqual(v["status"], "verified")
        t = B.pulse_time("2026-11-16T13:04:00.000Z")
        with self.assertRaises(B.Invalid) as c:
            B.window(t, 60000, v["tst_info"]["gen_time"], WIDE)
        self.assertEqual(c.exception.reason, "window_inverted")
        self.assertTrue(v["tst_info"]["gen_time"].startswith("2026-11-13"))

    def test_window_edges(self):
        t = B.pulse_time("2026-11-16T13:04:00.000Z")
        self.assertEqual(B.window(t, 60000, "2026-11-16T13:04:00Z", WIDE)["not_after"], "2026-11-16T13:04:00Z")   # one instant
        self.assertEqual(B.window(t, 60000, "2026-11-16T13:04:00.0001Z", WIDE)["not_before"], "2026-11-16T13:04:00.000Z")
        for g in ("2026-11-16T13:03:59.999999999Z", "2026-11-16T13:03:59Z", "2025-11-16T13:04:00Z"):
            with self.assertRaises(B.Invalid):
                B.window(t, 60000, g, WIDE)
        t2 = B.pulse_time("2026-11-16T13:04:00.500Z")
        with self.assertRaises(B.Invalid):
            B.window(t2, 60000, "2026-11-16T13:04:00.4999Z", WIDE)
        self.assertEqual(B.window(t2, 60000, "2026-11-16T13:04:00.5Z", WIDE)["not_before"], "2026-11-16T13:04:00.500Z")
        for bad in (None, "", "2026-11-16T13:04:00", "2026-11-16 13:04:00Z", "2026-11-16T13:04:00.Z"):
            with self.assertRaises(ValueError):
                B.window(t, 60000, bad, WIDE)

    def test_window_inverted_end_to_end(self):
        """the pack's token said genTime before T: the CLI path refuses the window (genTime made earlier by a
        patched §11 outcome, the only part not reproducible on demand: openssl's TSA stamps the present)"""
        real = EP._pinned_time_anchor

        def early(*a, **kw):
            el, chk = real(*a, **kw)
            return el, dict(chk, gen_time="2026-11-16T13:03:59Z")
        with mock.patch.object(EP, "_pinned_time_anchor", early):
            r = run(self.ledger, pack_dir=self.pack, tsa_certs=self.pins(), max_window_s=WIDE)
        self.assertEqual((r["status"], r["reason"]), ("invalid", "window_inverted"), r)


class RecordSalt(unittest.TestCase):
    """SPEC §18: a record salt of at least 128 bits, under the same self_hash"""

    def test_forms(self):
        base = payment_datas(pulse(2030303))[1]
        for v in ("00" * 16, "ab" * 64, "0f" * 33):
            d = dict(base, record_salt=v)
            self.assertIs(B.check_payment(d), d)
        for v in ("00" * 15, "0" * 31, "0" * 33, "ab" * 65, "AB" * 16, "zz" * 16, " " + "00" * 16, "00" * 16 + "\n",
                  "", 0, None, ["00" * 16]):
            with self.assertRaises(B.Refused) as c:
                B.check_payment(dict(base, record_salt=v))
            self.assertTrue(c.exception.detail.startswith("record_salt"), (v, c.exception.detail))
        d = dict(base)
        del d["record_salt"]
        with self.assertRaises(B.Refused) as c:
            B.check_payment(d)
        self.assertEqual(c.exception.detail, "record_salt: member_missing")

    def test_the_salt_changes_the_entry_hash(self):
        p = pulse(2030303)
        a, b = payment_datas(p), payment_datas(p)
        b[1]["record_salt"] = record_salt_of(99)
        ea = json.loads(chain(a, payment_ts(p)).decode().split("\n")[1])
        eb = json.loads(chain(b, payment_ts(p)).decode().split("\n")[1])
        self.assertNotEqual(ea["self_hash"], eb["self_hash"])
        self.assertEqual({k: v for k, v in ea["data"].items() if k != "record_salt"},
                         {k: v for k, v in eb["data"].items() if k != "record_salt"})


class Width(unittest.TestCase):
    def test_edges(self):
        t = B.pulse_time("2026-11-16T13:04:00.000Z")
        self.assertEqual(B.window(t, 60000, "2026-11-16T13:05:00Z", 60)["not_after"], "2026-11-16T13:05:00Z")
        self.assertEqual(B.window(t, 60000, "2026-11-16T13:04:00Z", 0)["not_after"], "2026-11-16T13:04:00Z")
        for g, m in (("2026-11-16T13:05:00.000001Z", 60), ("2026-11-16T13:04:00.1Z", 0), ("2026-11-16T14:04:00Z", 3599)):
            with self.assertRaises(B.Invalid) as c:
                B.window(t, 60000, g, m)
            self.assertEqual(c.exception.reason, "window_too_wide")
        self.assertEqual(B.window(t, 60000, "2026-11-16T14:04:00Z", 3600)["not_after"], "2026-11-16T14:04:00Z")

    def test_clock_tolerance(self):
        """SPEC §19 rule 5: genTime in [T - tolerance, T) is one instant at T; before that, inverted"""
        t = B.pulse_time("2026-11-16T13:04:00.000Z")
        w = B.window(t, 60000, "2026-11-16T13:03:59.5Z", 60, 1)
        self.assertEqual((w["not_before"], w["not_after"], w["gen_time"]),
                         ("2026-11-16T13:04:00.000Z", "2026-11-16T13:04:00.000Z", "2026-11-16T13:03:59.5Z"))
        self.assertEqual(B.window(t, 60000, "2026-11-16T13:03:59Z", 60, 1)["not_after"], "2026-11-16T13:04:00.000Z")
        for g, tol in (("2026-11-16T13:03:58.999999Z", 1), ("2026-11-16T13:03:59.5Z", 0), ("2026-11-16T13:03:00Z", 59)):
            with self.assertRaises(B.Invalid) as c:
                B.window(t, 60000, g, 60, tol)
            self.assertEqual(c.exception.reason, "window_inverted")
        for bad in (-1, 1.5, "1", True):
            with self.assertRaises(ValueError):
                run(LEDGER, pack_dir="/x", tsa_certs=[CERT], max_window_s=60, clock_tolerance_s=bad)
        with self.assertRaises(ValueError):
            run(LEDGER, clock_tolerance_s=0)                       # without a pack

    def test_library_requires_an_explicit_width(self):
        for kw in ({"pack_dir": "/x", "tsa_certs": [CERT]}, {"max_window_s": 60},
                   {"pack_dir": "/x", "tsa_certs": [CERT], "max_window_s": -1},
                   {"pack_dir": "/x", "tsa_certs": [CERT], "max_window_s": True},
                   {"pack_dir": "/x", "tsa_certs": [CERT], "max_window_s": 1.5},
                   {"tsa_crls": ["/x"]}, {"checkpoint": b"x"}, {"checkpoint": b"x", "log_vkeys": ["a"]},
                   {"log_vkeys": ["a"], "witness_vkeys": ["b"]}, {"min_witnesses": 1},
                   {"checkpoint": b"x", "log_vkeys": ["a"], "witness_vkeys": ["b"], "min_witnesses": 0}):
            with self.assertRaises(ValueError, msg=str(kw)):
                run(LEDGER, **kw)


def witness_material(td=None):
    """an Ed25519 log key and two witness keys made here (cryptovalid_checkpoint), as vkeys and seeds"""
    import cryptovalid_checkpoint as C
    keys = {}
    for name, typ in (("example.org/payments", C.TYPE_ED25519), ("witness.example/a", C.TYPE_COSIG_V1),
                      ("witness.example/b", C.TYPE_COSIG_V1)):
        seed = hashlib.sha256(name.encode()).digest()
        keys[name] = (seed, C.vkey(name, typ, C.pubkey_from_seed(seed)))
    return keys


def witnessed_checkpoint(ledger_bytes, keys, size=None, witnesses=("witness.example/a",), origin="example.org/payments",
                         cosigned_at=None, leaves_upto=None):
    """a checkpoint of the ledger, signed by the log key and cosigned by `witnesses` at `cosigned_at` (Unix seconds,
    default: 5 s ago, before any token made afterwards); `leaves_upto` takes the root of fewer entries than `size`"""
    import cryptovalid_checkpoint as C
    import cryptovalid_merkle as M
    leaves = [M.canonical(json.loads(x)) for x in ledger_bytes.decode().split("\n") if x.strip()]
    size = len(leaves) if size is None else size
    root = M.mth(leaves[:size if leaves_upto is None else leaves_upto])
    note = C.sign_note(C.checkpoint_text(origin, size, root), "example.org/payments", keys["example.org/payments"][0])
    for w in witnesses:
        note = C.cosign_v1(note, w, keys[w][0], int(time.time()) - 5 if cosigned_at is None else cosigned_at)
    return note


def make_pack(td, name, ledger_bytes, lab, extra=None):
    """an evidence pack holding the ledger (payments.jsonl) and the `extra` files ({name: bytes}), its manifest stamped
    by the openssl TSA of `lab`: the extra files are under the token too"""
    import contextlib
    import io
    d = os.path.join(td, name)
    src = os.path.join(td, name + ".src")
    os.makedirs(src)
    led = write(src, "payments.jsonl", ledger_bytes)
    with contextlib.redirect_stdout(io.StringIO()):
        EP.build_pack([led], d, subject="beacon test")
    with open(os.path.join(d, "MANIFEST.json")) as f:
        m = json.load(f)
    for n, b in (extra or {}).items():
        write(d, n, b)
        m["file_digests_sha256"][n] = hashlib.sha256(b).hexdigest()
    m2 = {k: v for k, v in m.items() if k not in ("manifest_digest_sha256", "rfc3161_timestamp", "manifest_signature",
                                                 "manifest_signer")}
    m["manifest_digest_sha256"] = hashlib.sha256(EP._canon(m2)).hexdigest()
    tok = lab.token(bytes.fromhex(m["manifest_digest_sha256"]))
    m["rfc3161_timestamp"] = {"anchored": True, "tsa": "local", "tsr_b64": base64.b64encode(tok).decode()}
    with open(os.path.join(d, "MANIFEST.json"), "w") as f:
        json.dump(m, f, indent=1, sort_keys=True)
    return d


@NEEDS_CRYPTO
@NEEDS_OPENSSL
class Uniqueness(unittest.TestCase):
    """SPEC §19 rule 6: one pulse admits many records; an entry is fixed in one history only by a witnessed checkpoint
    INSIDE the pack (under the token), cosigned no later than genTime"""

    @classmethod
    def setUpClass(cls):
        from test_tsa_revocation_20261116 import Lab
        cls.td = tempfile.mkdtemp()
        cls.lab = Lab(cls.td)
        cls.keys = witness_material()
        cls.log = [cls.keys["example.org/payments"][1]]
        cls.wit = [cls.keys["witness.example/a"][1]]
        cls.n = 0

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.td)

    def pack(self, led, extra=None):
        type(self).n += 1
        return make_pack(self.td, f"p{self.n}", led, self.lab, extra)

    def u(self, led, note, pack=None, **kw):
        pk = pack or self.pack(led, {"checkpoint.note": note})
        a = dict(pack_dir=pk, tsa_certs=[self.lab.j("ca.crt")], max_window_s=WIDE, checkpoint=note,
                 log_vkeys=self.log, witness_vkeys=self.wit)
        a.update(kw)
        return run(led, **a)

    def test_many_values_one_witnessed(self):
        """Athena's "many values": 20 variants after one pulse, each in its own pack; the witness cosigned the checkpoint
        of one variant before the token, and it is in that variant's pack: only that one is fixed"""
        p = pulse(2030303)
        variants = []
        for i in range(20):
            d = payment_datas(p)
            d[1]["amount"] = f"{100 + i}.00"
            variants.append(chain(d, payment_ts(p)))
        note = witnessed_checkpoint(variants[7], self.keys)
        results = []
        for i, v in enumerate(variants):
            results.append(self.u(v, note, pack=self.pack(v, {"checkpoint.note": note} if i == 7 else None)))
        self.assertEqual([r["status"] for r in results].count("verified"), 1)
        r = results[7]
        self.assertEqual((r["unique"]["status"], r["unique"]["witnesses"], r["unique"]["checkpoint_size"]),
                         ("witnessed", ["witness.example/a"], 3))
        self.assertIn({"not_unique": B.SCOPE["not_unique"]}, r["scope"]["does_not_prove"])
        self.assertEqual({x["reason"] for i, x in enumerate(results) if i != 7}, {"checkpoint_not_in_pack"})
        r = self.u(variants[3], note, pack=self.pack(variants[3], {"checkpoint.note": note}))   # the note of another variant
        self.assertEqual(r["reason"], "checkpoint_root_mismatch")

    def test_cosigned_400_days_later_is_never_fixed(self):
        """the independent review of 16/11/2026: 20 variants, each with its own pack and token; the witness cosigns, 400
        days later, the variant chosen. v0.10 as reviewed reported all 20 as fixed. Now: the late note is not in any pack
        (checkpoint_not_in_pack), and a pack that carries a note dated after its genTime is refused"""
        p = pulse(2030303)
        later = int(time.time()) + 400 * 86400
        fixed = 0
        for i in range(20):
            d = payment_datas(p)
            d[1]["amount"] = f"{200 + i}.00"
            v = chain(d, payment_ts(p))
            pk = self.pack(v)
            note = witnessed_checkpoint(v, self.keys, cosigned_at=later)
            r = self.u(v, note, pack=pk)
            self.assertEqual((r["status"], r["reason"]), ("invalid", "checkpoint_not_in_pack"))
            fixed += r["unique"]["status"] == "witnessed" or r["record_complete"]
        self.assertEqual(fixed, 0)
        v = build_payment_ledger()
        note = witnessed_checkpoint(v, self.keys, cosigned_at=later)    # a witness clock 400 days ahead, inside the pack
        r = self.u(v, note)
        self.assertEqual((r["status"], r["reason"]), ("invalid", "checkpoint_cosigned_after_gen_time"))
        r = self.u(v, witnessed_checkpoint(v, self.keys, cosigned_at=int(time.time()) + 3600))
        self.assertEqual(r["reason"], "checkpoint_cosigned_after_gen_time")

    def test_same_pulse_twice_in_one_witnessed_history(self):
        """NEMESIS 16/11/2026: a witnessed checkpoint fixes each entry at its position, not that it is the only entry
        after the pulse: two payments of one witnessed history carry the same pulse, both verify, both keep not_unique"""
        p = pulse(2030303)
        d = payment_datas(p)
        twin = dict(d[1], payment_id=PIDS[2], amount="9999.00")
        led = chain(d + [twin], payment_ts(p) + [payment_ts(p)[2]])
        note = witnessed_checkpoint(led, self.keys)
        pk = self.pack(led, {"checkpoint.note": note})
        for idx in (1, 3):
            r = self.u(led, note, pack=pk, entry=idx)
            self.assertEqual((r["status"], r["unique"]["status"]), ("verified", "witnessed"), idx)
            self.assertIn({"not_unique": B.SCOPE["not_unique"]}, r["scope"]["does_not_prove"], idx)

    def test_witness_states_are_three(self):
        """NEMESIS b28 (a branch for a state of verify_witnessed other than OK / NON_VALIDA / NON_VERIFICATA): such a state
        does not exist, shown two more ways than reading: the literals the function assigns, and 300 notes flipped at
        random bytes, valid and broken, whose states fall in the three"""
        import inspect
        import random
        import re
        import cryptovalid_witness as W
        lits = re.findall(r'(?:stato\s*=\s*|"stato":\s*|\["stato"\]\s*=\s*)"([A-Z_]+)"', inspect.getsource(W.verify_witnessed))
        self.assertEqual(set(lits), {"OK", "NON_VALIDA", "NON_VERIFICATA"})
        led = build_payment_ledger()
        note = witnessed_checkpoint(led, self.keys)
        rnd = random.Random(16112026)
        states = {W.verify_witnessed(note, self.log, self.wit)["stato"]}
        for _ in range(300):
            b = bytearray(note)
            for _ in range(rnd.randint(1, 4)):
                b[rnd.randrange(len(b))] = rnd.randrange(256)
            states.add(W.verify_witnessed(bytes(b), self.log, self.wit)["stato"])
        self.assertLessEqual(states, {"OK", "NON_VALIDA", "NON_VERIFICATA"})
        self.assertIn("NON_VALIDA", states)

    def test_checkpoint_failures(self):
        led = build_payment_ledger()
        note = witnessed_checkpoint(led, self.keys)
        r = self.u(led, note)
        self.assertEqual((r["status"], r["unique"]["as_of"]), ("verified", r["window"]["gen_time"]))
        self.assertEqual(self.u(led, witnessed_checkpoint(led, self.keys, size=1))["reason"], "checkpoint_not_covering_entry")
        self.assertEqual(self.u(led, witnessed_checkpoint(led, self.keys, size=2))["status"], "verified")   # a prefix
        self.assertEqual(self.u(led, witnessed_checkpoint(led, self.keys, size=5, leaves_upto=3))["reason"],
                         "checkpoint_root_mismatch")                    # a size beyond the ledger (NEMESIS b07)
        self.assertEqual(self.u(led, witnessed_checkpoint(led, self.keys, witnesses=()))["reason"], "checkpoint_not_witnessed")
        self.assertEqual(self.u(led, witnessed_checkpoint(led, self.keys, witnesses=("witness.example/b",)))["reason"],
                         "checkpoint_not_witnessed")                    # cosigned, but not by the pinned witness
        pk = self.pack(led, {"checkpoint.note": note})
        self.assertEqual(self.u(led, note, pack=pk, min_witnesses=2)["reason"], "checkpoint_not_witnessed")
        both = witnessed_checkpoint(led, self.keys, witnesses=("witness.example/a", "witness.example/b"))
        r = self.u(led, both, witness_vkeys=self.wit + [self.keys["witness.example/b"][1]], min_witnesses=2)
        self.assertEqual(r["unique"]["witnesses"], ["witness.example/a", "witness.example/b"])
        self.assertEqual(self.u(led, witnessed_checkpoint(led, self.keys, origin="other.example"))["reason"],
                         "checkpoint_not_witnessed")                    # another origin than the pinned log's
        self.assertEqual(self.u(led, note.replace(b"example.org/payments\n", b"example.org/paymentz\n", 1))["reason"],
                         "checkpoint_not_witnessed")
        for bad in (b"not a note", note + b"\x00"):
            self.assertEqual(self.u(led, bad)["reason"], "checkpoint_not_witnessed")   # verify_witnessed: NON_VALIDA
        self.assertEqual(self.u(led, note, pack=pk, log_vkeys=self.wit)["reason"], "checkpoint_malformed")
        self.assertEqual(self.u(led, note, pack=pk, witness_vkeys=["nonsense"])["reason"], "checkpoint_malformed")
        self.assertEqual(self.u(led, self.td, pack=pk)["reason"], "checkpoint_malformed")   # a directory
        self.assertEqual(self.u(led, note, pack=self.pack(led))["reason"], "checkpoint_not_in_pack")
        cp = write(self.td, "cp.note", note)
        self.assertEqual(self.u(led, cp, pack=pk)["status"], "verified")   # a path to the same bytes
        with self.assertRaises(ValueError):
            run(led, checkpoint=note, log_vkeys=self.log, witness_vkeys=self.wit)   # without a pack


@NEEDS_CRYPTO
@NEEDS_OPENSSL
class Complete(unittest.TestCase):
    """record_complete = window + revocation checked + witnessed checkpoint in the pack; qualification through a pinned
    Trusted List at genTime (SPEC §19 rules 5-7)"""

    def test_complete_record_and_revocation(self):
        from test_tsa_revocation_20261116 import Lab
        from test_lotl import _QC, _QTST, _svc, _tl
        from cryptography import x509
        from cryptography.hazmat.primitives import serialization
        with tempfile.TemporaryDirectory() as td:
            lab = Lab(td)
            keys = witness_material()
            led = build_payment_ledger()
            note = witnessed_checkpoint(led, keys)
            pack = make_pack(td, "pack", led, lab, {"checkpoint.note": note})
            full = dict(pack_dir=pack, tsa_certs=[lab.j("ca.crt")], max_window_s=WIDE, checkpoint=note,
                        log_vkeys=[keys["example.org/payments"][1]], witness_vkeys=[keys["witness.example/a"][1]])
            crl = lab.crl()   # issued after the token: it can speak for genTime
            r = run(led, tsa_crls=[crl], **full)
            self.assertEqual((r["status"], r["record_complete"], r["window"]["tsa_revocation"]["status"],
                              r["window"]["tsa_qualification"]), ("verified", True, "not_revoked", "not_checked"), r)
            self.assertEqual([list(x)[0] for x in r["scope"]["proves"]],
                             ["composed_after_pulse", "stamped_before_gen_time", "unique_under_pinned_witness"])
            self.assertEqual([list(x)[0] for x in r["scope"]["does_not_prove"]],
                             ["not_execution", "not_unique", "not_ownership", "commitments_not_opened", "not_operator",
                              "not_qualified", "not_legal_beacon"])
            r = run(led, **full)                                            # revocation not checked: not complete
            self.assertEqual((r["status"], r["record_complete"], r["window"]["tsa_revocation"]), ("verified", False, "not_checked"))
            with open(lab.j("tsa.crt"), "rb") as f:
                tsa_b64 = base64.b64encode(x509.load_pem_x509_certificate(f.read()).public_bytes(
                    serialization.Encoding.DER)).decode()
            for tl, want in ((_tl(_svc(_QTST, "granted", "2020-01-01T00:00:00Z", tsa_b64)), "qualified"),
                             (_tl(_svc(_QTST, "withdrawn", "2020-01-01T00:00:00Z", tsa_b64)), "not_qualified"),
                             (_tl(_svc(_QC, "granted", "2020-01-01T00:00:00Z", tsa_b64)), "not_qualified"),
                             (_tl(_svc(_QTST, "granted", "2099-01-01T00:00:00Z", tsa_b64)), "not_qualified")):
                r = run(led, tsa_trusted_list=tl, **full)
                self.assertEqual((r["status"], r["window"]["tsa_qualification"]), ("verified", want), r)
                q = {"stamped_by_qualified_tsa": B.SCOPE["stamped_by_qualified_tsa"]}
                self.assertEqual(q in r["scope"]["proves"], want == "qualified")
                self.assertEqual({"not_qualified": B.SCOPE["not_qualified"]} in r["scope"]["does_not_prove"],
                                 want != "qualified")
            # at genTime, not now (NEMESIS b27): granted until 2 s after the token, withdrawn afterwards
            g = B.gen_time_instant(r["window"]["gen_time"])
            stop = datetime.fromtimestamp(int(g) + 2, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            tl = _tl(_svc(_QTST, "withdrawn", stop, tsa_b64, history=[(_QTST, "granted", "2020-01-01T00:00:00Z", None)]))
            time.sleep(max(0.0, float(int(g) + 3 - time.time())))
            self.assertEqual(run(led, tsa_trusted_list=tl, **full)["window"]["tsa_qualification"], "qualified")
            r = run(led, tsa_trusted_list=b"<not a trusted list", **full)
            self.assertEqual((r["status"], r["reason"]), ("refused", "trusted_list_malformed"))
            with self.assertRaises(ValueError):
                run(led, tsa_trusted_list=b"<x/>")                   # without a pack
            self.assertEqual(run(led, **dict(full, max_window_s=60))["reason"], "window_too_wide")
            time.sleep(1.2)
            lab.revoke("keyCompromise")
            r = run(led, tsa_crls=[lab.crl()], **full)
            self.assertEqual((r["status"], r["reason"], r["record_complete"]), ("invalid", "time_anchor_not_verified", False))
            with self.assertRaises(ValueError):
                run(led, tsa_crls=[b"not a crl"], **full)

    def test_crl_older_than_gen_time_is_unknown(self):
        from test_tsa_revocation_20261116 import Lab
        with tempfile.TemporaryDirectory() as td:
            lab = Lab(td)
            with open(lab.crl(), "rb") as f:
                old = f.read()                                           # issued before the token
            time.sleep(1.2)
            led = build_payment_ledger()
            pack = make_pack(td, "pack", led, lab)
            r = run(led, pack_dir=pack, tsa_certs=[lab.j("ca.crt")], max_window_s=WIDE, tsa_crls=[old])
            self.assertEqual((r["status"], r["reason"]), ("invalid", "time_anchor_not_verified"), r)
            self.assertIn("tsa_revocation_unknown", r["detail"])


@NEEDS_CRYPTO
class MultiBeacon(unittest.TestCase):
    """SPEC §19 rule 1: `beacons` is a list; every value is checked; the lower bound is the latest pulse"""

    def ledger(self, values):
        p = pulse(2030303)
        d = payment_datas(p)
        d[1]["beacons"] = values
        return chain(d, payment_ts(p))

    def test_latest_pulse_is_the_bound(self):
        b2, b3 = beacon_of(pulse(2030302)), beacon_of(pulse(2030303))
        for values, ps, qs in (([b2, b3], [raw(2030302), raw(2030303)], [raw(2030301), raw(2030302)]),
                               ([b3, b2], [raw(2030303), raw(2030302)], [raw(2030302), raw(2030301)])):
            r = run(self.ledger(values), p=ps, prev=qs)
            self.assertEqual((r["status"], r["bounds"]["not_before"]), ("verified", "2026-11-16T13:04:00.000Z"), r)
            self.assertEqual(len(r["pulses"]), 2)
        led = self.ledger([b2, b3])
        r = run(led, p=[raw(2030302), raw(2030303)], prev=[raw(2030301), raw(2030301)])
        self.assertEqual(r["reason"], "pulse_mismatch")                 # the second pair is checked too
        r = run(led, p=[raw(2030303), raw(2030302)], prev=[raw(2030302), raw(2030301)])
        self.assertEqual(r["reason"], "pulse_mismatch")                 # pairs in the order of `beacons`
        for ps, qs in (([raw(2030302)], [raw(2030301)]), ([raw(2030302)] * 3, [raw(2030301)] * 3),
                       ([raw(2030302), raw(2030303)], [raw(2030301)])):
            with self.assertRaises(ValueError):
                run(led, p=ps, prev=qs)


# ───────────────────────── double faults: the code is the one of the earliest step of SPEC §19 rule 8

def _faults():
    """(name, step key, expected code, detail prefix, mutate(state)) — state: datas, extra kw, files; every fault alone
    gives its code, and any two give the code of the earlier step"""
    def data(f):
        def m(st):
            f(st["datas"])
        return m

    def kw(**k):
        def m(st):
            st["kw"].update(k)
        return m
    return [
        ("tampered_chain", "ledger_invalid", None, lambda st: st.__setitem__("tamper", True)),
        ("payment_id", "payment_malformed", "payment_id", data(lambda d: d[1].__setitem__("payment_id", "NOTPROVIDED"))),
        ("currency", "payment_malformed", "currency", data(lambda d: d[1].__setitem__("currency", "XAU"))),
        ("amount", "payment_malformed", "amount", data(lambda d: d[1].__setitem__("amount", "99.9"))),
        ("record_salt", "payment_malformed", "record_salt", data(lambda d: d[1].__setitem__("record_salt", "00" * 15))),
        ("commitment", "payment_malformed", "payer_iban_commitment",
         data(lambda d: d[1].__setitem__("payer_iban_commitment", d[1]["payer_iban_commitment"].upper()))),
        ("source", "source_not_supported", None, data(lambda d: d[1]["beacons"][0].__setitem__("source", "drand"))),
        ("pid_twice", "payment_id_not_unique", None, data(lambda d: d[0].__setitem__("payment_id", PIDS[1]))),
        ("disclosure_bad", "disclosure_malformed", None, lambda st: st["disc"].insert(0, b"[]")),
        ("disclosure_other", "disclosure_mismatch", None, lambda st: st["disc"].append(json.dumps(
            {"member": "payer_iban_commitment", "salt": "00" * 16, "value": EXAMPLE_IBANS[1]}).encode())),
        ("pulse_unknown_key", "pulse_malformed", None, lambda st: st["pobj"]["pulse"].__setitem__("zz", 1)),
        ("status", "status_not_supported", None, lambda st: st["pobj"]["pulse"].__setitem__("statusCode", 1)),
        ("previous_other", "pulse_mismatch", None, lambda st: st.__setitem__("prev_other", True)),
        ("certificate_other", "certificate_mismatch", None, lambda st: st.__setitem__("cert", own().pem)),
        ("window_zero", "window_too_wide", None, kw(max_window_s=0)),
    ]


@NEEDS_CRYPTO
@NEEDS_OPENSSL
class DoubleFaults(unittest.TestCase):
    """SPEC §19 rule 8 is a closed order: every pair of faults gives the code of the earlier one (independent review,
    16/11/2026: the order written before did not match the code)"""

    @classmethod
    def setUpClass(cls):
        from test_tsa_revocation_20261116 import Lab
        cls.td = tempfile.mkdtemp()
        cls.lab = Lab(cls.td)
        cls.n = 0

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.td)

    def outcome(self, faults):
        p = pulse(2030303)
        st = {"datas": payment_datas(p), "kw": {}, "disc": [], "pobj": {"pulse": pulse(2030303)}, "prev": raw(2030302),
              "cert": CERT}
        for f in faults:
            f[3](st)
        st["p"] = json.dumps(st["pobj"]).encode()
        led = chain(st["datas"], payment_ts(p))
        if st.get("tamper"):
            led = led.replace(b'"not a payment"', b'"not a paymenT"', 1)
        if st.get("prev_other"):
            st["prev"] = raw(2030301)
        kw = dict(st["kw"])
        if "max_window_s" in kw:
            type(self).n += 1
            kw.update(pack_dir=make_pack(self.td, f"p{self.n}", led, self.lab), tsa_certs=[self.lab.j("ca.crt")])
        return run(led, p=st["p"], prev=st["prev"], cert=st["cert"], disclosures=st["disc"] or None, **kw)

    def test_every_single_and_every_pair(self):
        fs = _faults()
        n = 0
        for i, f in enumerate(fs):
            r = self.outcome([f])
            self.assertEqual(r["reason"], f[1], f[0])
            if f[2]:
                self.assertTrue(r["detail"].startswith(f[2]), (f[0], r["detail"]))
            for g in fs[i + 1:]:
                r = self.outcome([f, g])
                self.assertEqual(r["reason"], f[1], (f[0], g[0], r["detail"]))
                if f[2]:
                    self.assertTrue(r["detail"].startswith(f[2]), (f[0], g[0], r["detail"]))
                n += 1
        self.assertEqual(n, len(fs) * (len(fs) - 1) // 2)


# every result code of SPEC §19 rule 8 (backend_missing excepted: it is the absence of cryptography, not an input)
CODES = {"input_unreadable", "input_too_large", "ledger_invalid", "entry_not_found", "entry_not_a_payment",
         "payment_malformed", "source_not_supported", "payment_id_not_unique", "disclosure_malformed",
         "disclosure_iban_invalid", "disclosure_mismatch", "pulse_malformed", "version_not_supported",
         "cipher_suite_not_supported", "status_not_supported", "pulse_mismatch", "chain_inconsistent",
         "certificate_malformed", "certificate_mismatch", "certificate_key_not_supported",
         "certificate_not_valid_at_pulse_time", "signature_invalid", "output_value_mismatch", "previous_mismatch",
         "period_mismatch", "commitment_mismatch", "beacon_value_mismatch", "pack_not_valid", "time_anchor_not_verified",
         "ledger_not_in_pack", "window_inverted", "window_too_wide", "trusted_list_malformed", "checkpoint_malformed",
         "checkpoint_not_in_pack", "checkpoint_not_witnessed", "checkpoint_cosigned_after_gen_time",
         "checkpoint_not_covering_entry", "checkpoint_root_mismatch"}
CASE_KEYS = {"name", "ledger", "entry", "pulses", "certificates", "expected", "disclosures", "pack", "tsa_certs",
             "tsa_crls", "tsa_trusted_list", "max_window_s", "clock_tolerance_s", "checkpoint", "log_vkeys",
             "witness_vkeys", "min_witnesses"}


def conformance_run(c):
    """one case of conformance.json through the library, with the case's paths (relative to spec/vectors/beacon/)"""
    j = lambda x: os.path.join(VB, x)   # noqa: E731
    kw = {k: c[k] for k in ("log_vkeys", "witness_vkeys", "min_witnesses", "max_window_s", "clock_tolerance_s") if k in c}
    for k in ("tsa_certs", "tsa_crls", "disclosures"):
        if k in c:
            kw[k] = [j(x) for x in c[k]]
    for k, a in (("pack", "pack_dir"), ("checkpoint", "checkpoint"), ("tsa_trusted_list", "tsa_trusted_list")):
        if k in c:
            kw[a] = j(c[k])
    return B.verify_beacon_entry(j(c["ledger"]), c["entry"], [j(p) for p, _ in c["pulses"]],
                                 [j(q) for _, q in c["pulses"]], [j(x) for x in c["certificates"]], **kw)


class Conformance(unittest.TestCase):
    """spec/vectors/beacon/conformance.json: status, reason and record_complete of every case, for any implementation;
    a complete record and every result code of SPEC §19 rule 8"""

    @classmethod
    def setUpClass(cls):
        with open(os.path.join(VB, "conformance.json"), encoding="utf-8") as f:
            cls.doc = json.load(f)

    def test_format_and_coverage(self):
        self.assertEqual(set(self.doc), {"format", "spec", "paths", "cases", "window_cases"})
        self.assertEqual(self.doc["format"], "cryptovalid-beacon-conformance/2")
        for c in self.doc["cases"]:
            self.assertLessEqual(set(c), CASE_KEYS, c["name"])
            self.assertEqual(set(c["expected"]), {"status", "reason", "record_complete"}, c["name"])
        self.assertEqual({c["expected"]["reason"] for c in self.doc["cases"]} - {None}, CODES)
        self.assertTrue(any(c["expected"]["record_complete"] for c in self.doc["cases"]))
        self.assertEqual(len({c["name"] for c in self.doc["cases"]}), len(self.doc["cases"]))

    def test_cases(self):
        seen = 0
        for c in self.doc["cases"]:
            if not HAVE_CRYPTO and (c["expected"]["status"] != "refused" or c["expected"]["reason"] in (
                    "certificate_malformed", "checkpoint_malformed", "trusted_list_malformed")):
                continue   # these are read after the RSA checks, which need cryptography (SPEC §19 rule 8 step 4)
            if ("pack" in c or c["expected"]["reason"] == "checkpoint_malformed") and shutil.which("openssl") is None:
                continue
            r = conformance_run(c)
            got = {"status": r["status"], "reason": r["reason"], "record_complete": r["record_complete"]}
            self.assertEqual(got, c["expected"], (c["name"], r["detail"]))
            seen += 1
        if HAVE_CRYPTO and shutil.which("openssl"):
            self.assertEqual(seen, len(self.doc["cases"]))

    def test_window_cases(self):
        for w in self.doc["window_cases"]:
            t = B.pulse_time(w["t"])
            if w["expected"] is None:
                self.assertEqual(B.window(t, w["period_ms"], w["gen_time"], w["max_window_s"], w["clock_tolerance_s"])[
                    "gen_time"], w["gen_time"])
            else:
                with self.assertRaises(B.Invalid) as e:
                    B.window(t, w["period_ms"], w["gen_time"], w["max_window_s"], w["clock_tolerance_s"])
                self.assertEqual(e.exception.reason, w["expected"])


class Command(unittest.TestCase):
    """cryptovalid-verify beacon: exit 0 / 1 / 2, usage errors, through the installed entry point's code"""

    def cli(self, *args):
        env = dict(os.environ, HOME=tempfile.mkdtemp())
        env.pop("PYTHONPATH", None)
        r = subprocess.run([sys.executable, os.path.join(ROOT, "verify_evidence.py"), "beacon", *args],
                           capture_output=True, text=True, env=env, cwd=env["HOME"])
        shutil.rmtree(env["HOME"])
        return r

    def base(self, **over):
        a = {"--entry": "1", "--pulse": pf(2030303), "--previous": pf(2030302), "--certificate": CERT}
        a.update(over)
        out = [LEDGER]
        for k, v in a.items():
            if v is not None:
                out += [k, v]
        return out

    @NEEDS_CRYPTO
    def test_exit_codes(self):
        r = self.cli(*self.base())
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(json.loads(r.stdout)["status"], "verified")
        r = self.cli(*self.base(**{"--previous": pf(2030301)}))
        self.assertEqual((r.returncode, json.loads(r.stdout)["reason"]), (1, "pulse_mismatch"))
        r = self.cli(*self.base(**{"--entry": "0"}))
        self.assertEqual((r.returncode, json.loads(r.stdout)["reason"]), (1, "pulse_mismatch"))
        e0 = self.base(**{"--entry": "0", "--pulse": pf(2030302), "--previous": pf(2030301)})
        with tempfile.TemporaryDirectory() as td:
            ok = write(td, "ok.json", Commitments.disclosure("payee_name_commitment"))
            wrong = write(td, "wrong.json", Commitments.disclosure("payee_name_commitment", "Example Supplies Ltd."))
            bad = write(td, "bad.json", Commitments.disclosure("payee_name_commitment", zz=1))
            r = self.cli(*e0, "--disclosure", ok)
            self.assertEqual((r.returncode, json.loads(r.stdout)["disclosed"]), (0, ["payee_name_commitment"]), r.stderr)
            r = self.cli(*e0, "--disclosure", wrong)
            self.assertEqual((r.returncode, json.loads(r.stdout)["reason"]), (1, "disclosure_mismatch"))
            for args in (("--disclosure", bad), ("--disclosure", ok, "--disclosure", ok)):
                r = self.cli(*e0, *args)
                self.assertEqual((r.returncode, json.loads(r.stdout)["reason"]), (2, "disclosure_malformed"))
        r = self.cli(*self.base(**{"--entry": "2"}))
        self.assertEqual((r.returncode, json.loads(r.stdout)["reason"]), (2, "entry_not_a_payment"))
        with tempfile.TemporaryDirectory() as td:
            bad = write(td, "p.json", raw(2030303).replace(b'"version"', b'"zz": 1, "version"'))
            r = self.cli(*self.base(**{"--pulse": bad}))
            self.assertEqual((r.returncode, json.loads(r.stdout)["reason"]), (2, "pulse_malformed"))

    def test_usage_errors(self):
        with tempfile.TemporaryDirectory() as td:
            with open(CERT, "rb") as f:
                pem = write(td, "c.pem", f.read())
            for args in (self.base(**{"--entry": "-1"}), self.base(**{"--entry": "01"}), self.base(**{"--entry": "1.0"}),
                         self.base(**{"--entry": ""}), self.base(**{"--entry": "１"}), self.base(**{"--pulse": ""}),
                         self.base(**{"--certificate": ""}), self.base(**{"--entry": None}),
                         self.base(**{"--pack": td}), self.base(**{"--tsa-cert": pem}), self.base(**{"--pack": ""}),
                         self.base() + ["--entry", "1"], self.base() + ["--pulse", pf(2030302)],
                         self.base() + ["--previous", pf(2030302)],
                         self.base() + ["--pulse", pf(2030303), "--previous", pf(2030302)],   # two pairs, one value
                         self.base() + ["--clock-tolerance", "1"],
                         self.base() + ["--pack", td, "--tsa-cert", pem, "--max-window", "60", "--clock-tolerance", "-1"],
                         self.base() + ["--pack", td, "--pack", td, "--tsa-cert", pem],
                         self.base() + ["--unknown"], self.base() + ["--ent", "1"],
                         self.base(**{"--tsa-cert": os.path.join(td, "absent"), "--pack": td}),
                         self.base() + ["--disclosure", ""],
                         self.base() + ["--pack", td, "--tsa-cert", pem],                      # no --max-window
                         self.base() + ["--max-window", "60"], self.base() + ["--tsa-crl", pem],
                         self.base() + ["--pack", td, "--tsa-cert", pem, "--max-window", "-1"],
                         self.base() + ["--pack", td, "--tsa-cert", pem, "--max-window", "60", "--max-window", "60"],
                         self.base() + ["--checkpoint", pem], self.base() + ["--log-vkey", "a", "--witness-vkey", "b"],
                         self.base() + ["--min-witnesses", "1"],
                         self.base() + ["--checkpoint", pem, "--log-vkey", "a", "--witness-vkey", "b", "--min-witnesses", "0"],
                         self.base() + ["--pack", td, "--tsa-cert", pem, "--max-window", "60", "--checkpoint", pem],
                         self.base() + ["--pack", td, "--tsa-cert", pem, "--max-window", "60", "--tsa-crl", pem]):
                if not HAVE_CRYPTO and "--tsa-crl" in args:
                    continue   # a CRL is read with cryptography: without it the check is not_evaluated (SPEC §11 step 8)
                r = self.cli(*args)
                self.assertEqual((r.returncode, r.stdout), (2, ""), (args, r.stderr))

    @NEEDS_CRYPTO
    def test_two_pinned_certificates(self):
        with tempfile.TemporaryDirectory() as td:
            r = self.cli(*self.base(), "--certificate", write(td, "own.pem", own().pem))
        self.assertEqual((r.returncode, json.loads(r.stdout)["status"]), (0, "verified"), r.stderr)

    def test_help_and_listing(self):
        r = self.cli("--help")
        self.assertEqual(r.returncode, 0)
        self.assertIn("--certificate", r.stdout)
        self.assertIn("cryptovalid-verify beacon", r.stdout)
        env = dict(os.environ)
        env.pop("PYTHONPATH", None)
        r = subprocess.run([sys.executable, os.path.join(ROOT, "verify_evidence.py"), "--help"],
                           capture_output=True, text=True, env=env)
        self.assertIn("beacon", r.stdout)
        r = subprocess.run([sys.executable, os.path.join(ROOT, "verify_evidence.py"), "--", "beacon", LEDGER],
                           capture_output=True, text=True, env=env)
        self.assertEqual(r.returncode, 2)

    def test_library_arguments(self):
        for bad in (-1, True, "1", 1.0, None):
            with self.assertRaises(ValueError):
                run(LEDGER, entry=bad)
        with self.assertRaises(ValueError):
            run(LEDGER, pack_dir="/x")
        with self.assertRaises(ValueError):
            run(LEDGER, tsa_certs=["/x"])


if __name__ == "__main__":
    unittest.main()
