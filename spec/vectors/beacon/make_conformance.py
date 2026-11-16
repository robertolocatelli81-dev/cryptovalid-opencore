#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Roberto Locatelli
"""Builds the conformance cases of SPEC v0.10 §18-§19 under spec/vectors/beacon/conformance/ and their expected results in
spec/vectors/beacon/conformance.json. Every input is derived by this code from the real files of nist/ (six pulses of NIST
chain 2 and the beacon's certificate, 16/11/2026) and from payment_ledger.jsonl; none is written by hand. Run once on
2026-11-16; the outputs are committed. The cases that reach a check behind the beacon's signature are re-signed with an
RSA key made on the spot, whose certificate is committed (other/certificate.pem) and whose private key is not: a new run
gives other bytes for those cases and the same expected results. The witness keys are derived from fixed labels, so the
checkpoint cases are the same at every run. Usage, from the repository root:
    python3 spec/vectors/beacon/make_conformance.py"""
import copy
import datetime
import hashlib
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(HERE)))
sys.path.insert(0, ROOT)
sys.dont_write_bytecode = True
import cryptovalid_beacon as B  # noqa: E402
import verifier  # noqa: E402

OUT = os.path.join(HERE, "conformance")
NIST = os.path.join(HERE, "nist")
CERT = "nist/certificate_5b6386e6ac8a993b.pem"
LOG = "example.org/payments"
WITNESSES = ("witness.example/a", "witness.example/b")
COSIGN_TIME = 1794834000   # 2026-11-16T13:00:00Z, fixed so the cosignatures are reproducible


def pulse(i):
    with open(os.path.join(NIST, f"pulse_{i}.json"), encoding="utf-8") as f:
        return json.load(f)["pulse"]


def ledger_lines():
    with open(os.path.join(HERE, "payment_ledger.jsonl"), encoding="utf-8") as f:
        return [json.loads(x) for x in f if x.strip()]


def chain(datas, tss):
    out, prev = [], "0" * 64
    for i, (d, t) in enumerate(zip(datas, tss)):
        e = {"idx": i, "ts": t, "data": d, "prev_hash": prev}
        e["self_hash"] = verifier.hash_with("sha256", verifier.canonical_payload(e))
        prev = e["self_hash"]
        out.append(json.dumps(e, ensure_ascii=False, sort_keys=True))
    return ("\n".join(out) + "\n").encode()


def put(rel, data):
    p = os.path.join(OUT, rel)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "wb") as f:
        f.write(data if isinstance(data, bytes) else data.encode())
    return "conformance/" + rel


def mutated_ledger(name, fn):
    es = ledger_lines()
    datas, tss = [e["data"] for e in es], [e["ts"] for e in es]
    fn(datas)
    return put(f"ledgers/{name}.jsonl", chain(datas, tss))


def pulse_doc(p):
    return json.dumps({"pulse": p}, indent=2).encode()


class Own:
    def __init__(self):
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        n = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "conformance beacon (not NIST)")])
        c = (x509.CertificateBuilder().subject_name(n).issuer_name(n).public_key(self.key.public_key()).serial_number(1)
             .not_valid_before(datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc))
             .not_valid_after(datetime.datetime(2027, 12, 31, tzinfo=datetime.timezone.utc)).sign(self.key, hashes.SHA256()))
        self.pem = c.public_bytes(serialization.Encoding.PEM)
        self.cid = hashlib.sha512(c.public_bytes(serialization.Encoding.DER)).hexdigest()

    def sign(self, p):
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding
        p = copy.deepcopy(p)
        p["certificateId"] = self.cid
        m = B.signed_message(p)
        s = self.key.sign(m, padding.PKCS1v15(), hashes.SHA512())
        p["signatureValue"], p["outputValue"] = s.hex().upper(), hashlib.sha512(m + s).hexdigest().upper()
        return p


def witness_keys():
    import cryptovalid_checkpoint as C
    out = {}
    for name, typ in ((LOG, C.TYPE_ED25519),) + tuple((w, C.TYPE_COSIG_V1) for w in WITNESSES):
        seed = hashlib.sha256(f"conformance key {name}".encode()).digest()
        out[name] = (seed, C.vkey(name, typ, C.pubkey_from_seed(seed)))
    return out


def checkpoint(ledger_rel, keys, size=None, witnesses=WITNESSES[:1]):
    import cryptovalid_checkpoint as C
    import cryptovalid_merkle as M
    with open(os.path.join(HERE, ledger_rel), encoding="utf-8") as f:
        leaves = [M.canonical(json.loads(x)) for x in f if x.strip()]
    size = len(leaves) if size is None else size
    note = C.sign_note(C.checkpoint_text(LOG, size, M.mth(leaves[:size])), LOG, keys[LOG][0])
    for w in witnesses:
        note = C.cosign_v1(note, w, keys[w][0], COSIGN_TIME)
    return note


def main():
    cases = []

    def case(name, expect, reason, ledger="payment_ledger.jsonl", entry=1, p="nist/pulse_2030303.json",
             prev="nist/pulse_2030302.json", cert=CERT, **extra):
        cases.append(dict({"name": name, "ledger": ledger, "entry": entry, "pulse": p, "previous": prev,
                           "certificate": cert}, **extra, expected={"status": expect, "reason": reason}))

    # positive, real pulses
    case("entry1_pulse_2030303", "verified", None)
    case("entry0_pulse_2030302", "verified", None, entry=0, p="nist/pulse_2030302.json", prev="nist/pulse_2030301.json")
    names = {"payer_iban_commitment": "GB82WEST12345698765432", "payee_iban_commitment": "DE89370400440532013000",
             "payer_name_commitment": "Maria Example", "payer_details_commitment": "Via Esempio 1, 00100 Roma, IT",
             "payee_name_commitment": "Example Supplies Ltd"}

    def salt(m, label="v1"):
        return hashlib.sha256(f"test salt {label} {m}".encode()).digest()[:16]
    discl = []
    for m, v in names.items():
        discl.append(put(f"disclosures/{m}.json", json.dumps({"member": m, "salt": salt(m).hex(), "value": v})))
    e0 = dict(entry=0, p="nist/pulse_2030302.json", prev="nist/pulse_2030301.json")
    case("entry0_five_disclosures", "verified", None, disclosures=discl, **e0)
    case("disclosure_other_name", "invalid", "disclosure_mismatch", disclosures=[put(
        "disclosures/payer_name_wrong.json", json.dumps({"member": "payer_name_commitment", "salt": salt(
            "payer_name_commitment").hex(), "value": "Maria Exampel"}))], **e0)
    case("disclosure_other_salt", "invalid", "disclosure_mismatch", disclosures=[put(
        "disclosures/payer_iban_other_salt.json", json.dumps({"member": "payer_iban_commitment", "salt": salt(
            "payer_iban_commitment", "v2").hex(), "value": names["payer_iban_commitment"]}))], **e0)
    case("disclosure_salt_64_bits", "refused", "disclosure_malformed", disclosures=[put(
        "disclosures/payer_iban_short_salt.json", json.dumps({"member": "payer_iban_commitment", "salt": salt(
            "payer_iban_commitment")[:8].hex(), "value": names["payer_iban_commitment"]}))], **e0)
    bad_iban = "GB83WEST12345698765432"
    bad_led = mutated_ledger("committed_bad_iban", lambda d: d[1].__setitem__(
        "payee_iban_commitment", B.commitment(salt("payee_iban_commitment", "bad"), bad_iban)))
    case("committed_bad_iban_undisclosed", "verified", None, ledger=bad_led)
    case("committed_bad_iban_disclosed", "invalid", "disclosure_iban_invalid", ledger=bad_led, disclosures=[put(
        "disclosures/payee_iban_bad.json", json.dumps({"member": "payee_iban_commitment", "salt": salt(
            "payee_iban_commitment", "bad").hex(), "value": bad_iban}))])
    # pulses: order, grammar, signed fields
    case("previous_not_predecessor", "invalid", "pulse_mismatch", prev="nist/pulse_2030301.json")
    case("pulse_of_another_index", "invalid", "pulse_mismatch", p="nist/pulse_2030302.json", prev="nist/pulse_2030301.json")
    for name, fn, exp, why in (
            ("unknown_member", lambda p: p.__setitem__("zz", 0), "refused", "pulse_malformed"),
            ("unknown_member_external", lambda p: p["external"].__setitem__("zz", 0), "refused", "pulse_malformed"),
            ("external_status_uint64", lambda p: p["external"].__setitem__("statusCode", 2 ** 32), "refused", "pulse_malformed"),
            ("hex_too_short", lambda p: p.__setitem__("localRandomValue", p["localRandomValue"][:-2]), "refused", "pulse_malformed"),
            ("time_without_millis", lambda p: p.__setitem__("timeStamp", "2026-11-16T13:04:00Z"), "refused", "pulse_malformed"),
            ("status_gap", lambda p: p.__setitem__("statusCode", 2), "invalid", "status_not_supported"),
            ("cipher_suite_1", lambda p: p.__setitem__("cipherSuite", 1), "invalid", "cipher_suite_not_supported"),
            ("version_2_1", lambda p: p.__setitem__("version", "2.1"), "invalid", "version_not_supported"),
            ("signed_field_changed", lambda p: p.__setitem__("localRandomValue", "00" * 64), "invalid", "signature_invalid"),
            ("uri_http", lambda p: p.__setitem__("uri", p["uri"].replace("https:", "http:")), "invalid", "pulse_mismatch")):
        p = pulse(2030303)
        fn(p)
        case(f"pulse_{name}", exp, why, p=put(f"pulses/{name}.json", pulse_doc(p)))
    own = Own()
    own_cert = put("other/certificate.pem", own.pem)
    case("certificate_not_the_pulses", "invalid", "certificate_mismatch", cert=own_cert)
    # re-signed by the conformance key: the mutation reaches the check behind the signature
    for name, mp, mq, why in (
            ("commitment_broken", None, lambda q: q.__setitem__("precommitmentValue", "AB" * 64), "commitment_mismatch"),
            ("period_30s", None, lambda q: q.__setitem__("timeStamp", "2026-11-16T13:03:30.000Z"), "period_mismatch"),
            ("previous_value_other", lambda p: p["listValues"][0].__setitem__("value", "CD" * 64), None, "previous_mismatch")):
        q = pulse(2030302)
        if mq:
            mq(q)
        q = own.sign(q)
        p = pulse(2030303)
        p["listValues"][0]["value"] = q["outputValue"]
        if mp:
            mp(p)
        p = own.sign(p)
        es = ledger_lines()
        datas = [e["data"] for e in es]
        datas[1]["beacon"]["output_value"] = p["outputValue"]
        led = put(f"ledgers/resigned_{name}.jsonl", chain(datas, [e["ts"] for e in es]))
        case(f"resigned_{name}", "invalid", why, ledger=led, p=put(f"pulses/resigned_{name}.json", pulse_doc(p)),
             prev=put(f"pulses/resigned_{name}_previous.json", pulse_doc(q)), cert=own_cert)
    # ledgers, hashes recomputed so the change reaches the profile
    for name, fn, exp, why in (
            ("iban_in_clear", lambda d: d[1].__setitem__("payee_iban", "GB82WEST12345698765432"), "refused", "payment_malformed"),
            ("payer_iban_commitment_missing", lambda d: d[1].pop("payer_iban_commitment"), "refused", "payment_malformed"),
            ("commitment_upper_case", lambda d: d[1].__setitem__("payer_iban_commitment", d[1]["payer_iban_commitment"].upper()),
             "refused", "payment_malformed"),
            ("currency_unknown", lambda d: d[1].__setitem__("currency", "XAU"), "refused", "payment_malformed"),
            ("amount_decimals", lambda d: d[1].__setitem__("amount", "99.951"), "refused", "payment_malformed"),
            ("amount_zero", lambda d: d[1].__setitem__("amount", "0.00"), "refused", "payment_malformed"),
            ("amount_negative", lambda d: d[1].__setitem__("amount", "-99.95"), "refused", "payment_malformed"),
            ("unknown_member", lambda d: d[1].__setitem__("note", "x"), "refused", "payment_malformed"),
            ("record_salt_120_bits", lambda d: d[1].__setitem__("record_salt", "00" * 15), "refused", "payment_malformed"),
            ("beacon_missing", lambda d: d[1].pop("beacon"), "refused", "payment_malformed"),
            ("beacon_other_source", lambda d: d[1]["beacon"].__setitem__("source", "curby-twine"), "refused", "source_not_supported"),
            ("beacon_value_other_pulse", lambda d: d[1]["beacon"].__setitem__("output_value", pulse(2030302)["outputValue"]),
             "invalid", "beacon_value_mismatch"),
            ("payment_id_twice", lambda d: d[1].__setitem__("payment_id", d[0]["payment_id"]), "invalid", "payment_id_not_unique")):
        case(f"ledger_{name}", exp, why, ledger=mutated_ledger(name, fn))
    with open(os.path.join(HERE, "payment_ledger.jsonl"), "rb") as f:
        raw = f.read()
    case("ledger_changed_hash_not_recomputed", "invalid", "ledger_invalid",
         ledger=put("ledgers/changed_not_rehashed.jsonl", raw.replace(b'"99.95"', b'"99.96"', 1)))
    case("entry_not_a_payment", "refused", "entry_not_a_payment", entry=2)
    case("entry_not_found", "invalid", "entry_not_found", entry=3)
    # uniqueness: witnessed checkpoints, keys from fixed labels
    keys = witness_keys()
    wk = {"log_vkeys": [keys[LOG][1]], "witness_vkeys": [keys[WITNESSES[0]][1]]}
    cp = put("checkpoints/witnessed.note", checkpoint("payment_ledger.jsonl", keys))
    case("witnessed_unique", "verified", None, checkpoint=cp, **wk)
    case("witnessed_too_small", "invalid", "checkpoint_not_covering_entry",
         checkpoint=put("checkpoints/size1.note", checkpoint("payment_ledger.jsonl", keys, size=1)), **wk)
    case("witnessed_other_ledger", "invalid", "checkpoint_root_mismatch", ledger=mutated_ledger(
        "variant_amount", lambda d: d[1].__setitem__("amount", "199.95")), checkpoint=cp, **wk)
    case("not_witnessed", "invalid", "checkpoint_not_witnessed",
         checkpoint=put("checkpoints/no_witness.note", checkpoint("payment_ledger.jsonl", keys, witnesses=())), **wk)
    case("witnessed_by_unpinned", "invalid", "checkpoint_not_witnessed", checkpoint=put(
        "checkpoints/other_witness.note", checkpoint("payment_ledger.jsonl", keys, witnesses=WITNESSES[1:])), **wk)
    # the window of rule 5 as data: T, period, genTime, maximum width -> expected
    windows = [{"t": "2026-11-16T13:04:00.000Z", "period_ms": 60000, "gen_time": g, "max_window_s": m, "expected": e}
               for g, m, e in (("2026-11-16T13:05:00Z", 60, None), ("2026-11-16T13:05:00.000001Z", 60, "window_too_wide"),
                               ("2026-11-16T13:04:00Z", 0, None), ("2026-11-16T13:03:59.999999Z", 3600, "window_inverted"),
                               ("2026-11-13T09:00:00Z", 10 ** 9, "window_inverted"), ("2026-11-16T14:04:00Z", 3600, None))]
    doc = {"format": "cryptovalid-beacon-conformance/1", "spec": "SPEC_EVIDENCE_FORMAT.md v0.10 §18-§19",
           "paths": "relative to spec/vectors/beacon/", "cases": cases, "window_cases": windows}
    with open(os.path.join(HERE, "conformance.json"), "w", encoding="utf-8") as f:
        f.write(json.dumps(doc, ensure_ascii=False, indent=1) + "\n")
    print(len(cases), "cases,", len(windows), "window cases")


if __name__ == "__main__":
    main()
