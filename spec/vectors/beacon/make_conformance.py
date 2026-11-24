#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Roberto Locatelli
"""Builds the conformance cases of SPEC v0.10 §18-§19 under spec/vectors/beacon/conformance/ and their expected results in
spec/vectors/beacon/conformance.json: a complete record (window, revocation checked, witnessed checkpoint inside the pack,
qualified TSA) and at least one case for every result code of §19 rule 8. Every input is derived by code from the real
files of nist/ (six pulses of NIST chain 2 and the beacon's certificate, 16/11/2026) and from payment_ledger.jsonl; none
is written by hand. The evidence packs are stamped by a TSA made on the spot with openssl (its CA certificate, the TSA
certificate and the CRLs are committed, its private keys are not); the cases that reach a check behind the beacon's
signature are re-signed with an RSA key made on the spot (certificate committed, key not); witness keys are derived from
fixed labels. A new run gives other bytes for the packs and re-signed pulses and the same expected results. Needs
openssl and cryptography. Usage, from the repository root:
    python3 spec/vectors/beacon/make_conformance.py"""
import base64
import datetime
import hashlib
import json
import os
import shutil
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(HERE)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "verifiers"))
sys.dont_write_bytecode = True
import cryptovalid_beacon as B  # noqa: E402
import test_beacon_20261116 as TB  # noqa: E402   (the helpers the tests use: one source of the ledger and the packs)
from test_tsa_revocation_20261116 import Lab  # noqa: E402

OUT = os.path.join(HERE, "conformance")
CERT = "nist/certificate_5b6386e6ac8a993b.pem"
P3, P2, P1 = "nist/pulse_2030303.json", "nist/pulse_2030302.json", "nist/pulse_2030301.json"
LOG = "example.org/payments"


def rel(path):
    return os.path.relpath(path, HERE)


def put(name, data):
    p = os.path.join(OUT, name)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "wb") as f:
        f.write(data if isinstance(data, bytes) else data.encode())
    return rel(p)


def ledger_with(fn=None):
    p = TB.pulse(2030303)
    datas = TB.payment_datas(p)
    if fn:
        fn(datas)
    return TB.chain(datas, TB.payment_ts(p))


def own_cert(nb=None, na=None, bits=2048):
    return TB.OwnBeacon(nb, na, bits)


def resigned(o, mutate_prev=None, mutate_pulse=None, relink=True):
    q = TB.pulse(2030302)
    if mutate_prev:
        mutate_prev(q)
    q = o.sign(q)
    p = TB.pulse(2030303)
    if relink:
        p["listValues"][0]["value"] = q["outputValue"]
    if mutate_pulse:
        mutate_pulse(p)
    p = o.sign(p)
    return q, p


def ledger_for(p):
    pp = TB.pulse(2030303)
    datas = TB.payment_datas(pp)
    datas[1]["beacons"] = [TB.beacon_of(p)]
    return TB.chain(datas, TB.payment_ts(pp))


def main():
    if os.path.isdir(OUT):
        shutil.rmtree(OUT)
    os.makedirs(OUT)
    work = tempfile.mkdtemp()
    cases = []

    def case(name, status, reason, complete=False, ledger="payment_ledger.jsonl", entry=1, pulses=((P3, P2),),
             certificates=(CERT,), **extra):
        c = {"name": name, "ledger": ledger, "entry": entry, "pulses": [list(x) for x in pulses],
             "certificates": list(certificates)}
        if "entry_file" in extra:   # SPEC §19 rule 14: one entry and its proof, no ledger
            del c["ledger"], c["entry"]
        c.update({k: v for k, v in extra.items() if v is not None})
        c["expected"] = {"status": status, "reason": reason, "record_complete": complete}
        cases.append(c)

    try:
        lab = Lab(work, "tsa")
        other = Lab(work, "other")
        revoked = Lab(work, "revoked")
        keys = TB.witness_material()
        wk = {"log_vkeys": [keys[LOG][1]], "witness_vkeys": [keys["witness.example/a"][1]]}
        pins = {"tsa_certs": [put("tsa/ca.crt", open(lab.j("ca.crt"), "rb").read())]}
        led = TB.build_payment_ledger()

        def pack(name, ledger_bytes, extra=None, with_lab=lab):
            d = TB.make_pack(work, name, ledger_bytes, with_lab, extra)
            dst = os.path.join(OUT, "packs", name)
            shutil.copytree(d, dst)
            return rel(dst)

        # the complete record: window, CRL after the token, witnessed checkpoint inside the pack, qualified TSA
        note = TB.witnessed_checkpoint(led, keys)
        full_pack = pack("complete", led, {"checkpoint.note": note})
        # SPEC §19 rule 14: the pack of one entry holds the checkpoint and no payment (stamped before the CRL is issued)
        epack = pack("entry_only", TB.checkpoint_ledger(note), {"checkpoint.note": note})
        note_rel = put("checkpoints/witnessed.note", note)
        crl = put("tsa/crl.pem", open(lab.crl(), "rb").read())
        from cryptography import x509
        from cryptography.hazmat.primitives import serialization
        from test_lotl import _QTST, _svc, _tl
        tsa_b64 = base64.b64encode(x509.load_pem_x509_certificate(open(lab.j("tsa.crt"), "rb").read()).public_bytes(
            serialization.Encoding.DER)).decode()
        tl = put("tsa/trusted_list.xml", _tl(_svc(_QTST, "granted", "2020-01-01T00:00:00Z", tsa_b64)))
        win = dict(pack=full_pack, max_window_s=30 * 86400, **pins)
        case("complete_record", "verified", None, True, tsa_crls=[crl], tsa_trusted_list=tl, checkpoint=note_rel,
             disclosures=None, **win, **wk)
        case("window_without_crl_not_complete", "verified", None, False, checkpoint=note_rel, **win, **wk)
        case("window_without_checkpoint_not_complete", "verified", None, False, tsa_crls=[crl], **win)

        # step 1, the ledger
        case("entry_1", "verified", None)
        case("ledger_unreadable", "refused", "input_unreadable", ledger="nist")
        case("ledger_invalid", "invalid", "ledger_invalid",
             ledger=put("ledgers/changed_not_rehashed.jsonl", led.replace(b'"99.95"', b'"99.96"', 1)))
        case("entry_not_found", "invalid", "entry_not_found", entry=3)
        case("entry_not_a_payment", "refused", "entry_not_a_payment", entry=2)

        # step 2, the profile, one case per check in its order; SPEC §18 "Currencies" (cryptovalid-beacon-conformance/4):
        # the currency cases need a pinned currency table, and without one the same ledgers pass the check of form only
        ctab = put("currency_table.json", json.dumps({'format': 'cryptovalid-iso4217-table/1', 'source': 'the conformance vectors\' own table (SPEC §18 "Currencies"): three codes with their ISO 4217 minor units', 'currencies': {'EUR': 2, 'JPY': 0, 'USD': 2}}, indent=1) + "\n")
        for name, fn, why in (
                ("unknown_member", lambda d: d[1].__setitem__("note", "x"), "payment_malformed"),
                ("no_party_identifier", lambda d: (d[1].pop("payee_iban_commitment"), d[1].pop("payer_iban_commitment")),
                 "payment_malformed"),
                ("payment_id_not_uuid4", lambda d: d[1].__setitem__("payment_id", "NOTPROVIDED"), "payment_malformed"),
                ("currency_unknown", lambda d: d[1].__setitem__("currency", "XAU"), "payment_malformed"),
                ("amount_not_canonical", lambda d: d[1].__setitem__("amount", "99.9"), "payment_malformed"),
                ("amount_zero", lambda d: d[1].__setitem__("amount", "0.00"), "payment_malformed"),
                ("record_salt_120_bits", lambda d: d[1].__setitem__("record_salt", "00" * 15), "payment_malformed"),
                ("commitment_upper_case", lambda d: d[1].__setitem__("payer_iban_commitment",
                                                                    d[1]["payer_iban_commitment"].upper()), "payment_malformed"),
                ("iban_in_clear", lambda d: d[1].__setitem__("payee_iban", "GB82WEST12345698765432"), "payment_malformed"),
                ("beacons_empty", lambda d: d[1].__setitem__("beacons", []), "payment_malformed"),
                ("beacon_chain_1", lambda d: d[1]["beacons"][0].__setitem__("chain_index", 1), "payment_malformed"),
                ("beacon_value_lower_case", lambda d: d[1]["beacons"][0].__setitem__(
                    "output_value", d[1]["beacons"][0]["output_value"].lower()), "payment_malformed"),
                ("beacon_source_drand", lambda d: d[1]["beacons"][0].__setitem__("source", "drand"), "source_not_supported"),
                ("payment_id_twice", lambda d: d[1].__setitem__("payment_id", d[0]["payment_id"]), "payment_id_not_unique"),
                ("double_fault_salt_and_source", lambda d: (d[1].__setitem__("record_salt", "00"),
                                                            d[1]["beacons"][0].__setitem__("source", "drand")),
                 "payment_malformed")):
            status = "invalid" if why == "payment_id_not_unique" else "refused"
            table = ctab if name in ("currency_unknown", "amount_not_canonical") else None
            case(f"profile_{name}", status, why, ledger=put(f"ledgers/{name}.jsonl", ledger_with(fn)), currency_table=table)
        case("currency_table_pinned", "verified", None, currency_table=ctab)
        for name in ("currency_unknown", "amount_not_canonical"):
            case(f"profile_{name}_without_currency_table", "verified", None, ledger=f"conformance/ledgers/{name}.jsonl")

        # step 3, disclosures
        def salt(m, label="v1"):
            return TB.salt_of(m, label)
        e0 = dict(entry=0, pulses=((P2, P1),))
        discl = [put(f"disclosures/{m}.json", json.dumps({"member": m, "salt": salt(m).hex(), "value": v}))
                 for m, v in TB.NAMES.items()]
        case("entry_0_every_disclosure", "verified", None, disclosures=discl, required_disclosures=list(TB.NAMES), **e0)
        case("required_disclosure_missing", "invalid", "required_disclosure_missing",
             required_disclosures=["payer_tax_id_commitment"], disclosures=discl[:1], **e0)
        case("disclosure_malformed", "refused", "disclosure_malformed",
             disclosures=[put("disclosures/short_salt.json", json.dumps({"member": "payer_iban_commitment",
                          "salt": salt("payer_iban_commitment")[:8].hex(), "value": TB.EXAMPLE_IBANS[0]}))], **e0)
        case("disclosure_unreadable", "refused", "input_unreadable", disclosures=["nist"], **e0)
        case("disclosure_mismatch", "invalid", "disclosure_mismatch",
             disclosures=[put("disclosures/other_name.json", json.dumps({"member": "payer_name_commitment",
                          "salt": salt("payer_name_commitment").hex(), "value": "Maria Exampel"}))], **e0)
        bad_iban = "GB83WEST12345698765432"
        bad_led = put("ledgers/committed_bad_iban.jsonl", ledger_with(lambda d: d[1].__setitem__(
            "payee_iban_commitment", TB.raw_commitment("payee_iban_commitment", salt("payee_iban_commitment", "bad"),
                                                       bad_iban))))
        case("disclosure_iban_invalid", "invalid", "disclosure_iban_invalid", ledger=bad_led,
             disclosures=[put("disclosures/bad_iban.json", json.dumps({"member": "payee_iban_commitment",
                          "salt": salt("payee_iban_commitment", "bad").hex(), "value": bad_iban}))])

        # step 4, pulses
        big = TB.raw(2030303) + b" " * (B.MAX_PULSE + 1 - len(TB.raw(2030303)))
        case("pulse_unreadable", "refused", "input_unreadable", pulses=(("nist", P2),))
        case("pulse_too_large", "refused", "input_too_large", pulses=((put("pulses/too_large.json", big), P2),))
        for name, fn, status, why in (
                ("unknown_member", lambda p: p.__setitem__("zz", 0), "refused", "pulse_malformed"),
                ("external_status_uint64", lambda p: p["external"].__setitem__("statusCode", 2 ** 32), "refused", "pulse_malformed"),
                ("version_2_1", lambda p: p.__setitem__("version", "2.1"), "invalid", "version_not_supported"),
                ("cipher_suite_1", lambda p: p.__setitem__("cipherSuite", 1), "invalid", "cipher_suite_not_supported"),
                ("status_gap", lambda p: p.__setitem__("statusCode", 2), "invalid", "status_not_supported"),
                ("uri_http", lambda p: p.__setitem__("uri", p["uri"].replace("https:", "http:")), "invalid", "pulse_mismatch"),
                ("signed_field_changed", lambda p: p.__setitem__("localRandomValue", "00" * 64), "invalid", "signature_invalid")):
            p = TB.pulse(2030303)
            fn(p)
            case(f"pulse_{name}", status, why, pulses=((put(f"pulses/{name}.json", TB.doc(p)), P2),))
        case("previous_not_predecessor", "invalid", "pulse_mismatch", pulses=((P3, P1),))
        case("certificate_malformed", "refused", "certificate_malformed", certificates=[put("other/not_a_certificate.pem",
             b"-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n")])
        o = own_cert()
        own_pem = put("other/certificate.pem", o.pem)
        case("certificate_not_the_pulses", "invalid", "certificate_mismatch", certificates=[own_pem])

        def resigned_case(name, why, o, cert_rel, **kw):
            q, p = resigned(o, **kw)
            case(f"resigned_{name}", "invalid", why, ledger=put(f"ledgers/resigned_{name}.jsonl", ledger_for(p)),
                 pulses=((put(f"pulses/resigned_{name}.json", TB.doc(p)),
                          put(f"pulses/resigned_{name}_previous.json", TB.doc(q))),), certificates=[cert_rel])
            return q, p
        resigned_case("period_in_pulse_only", "chain_inconsistent", o, own_pem, mutate_pulse=lambda p: p.__setitem__("period", 30000))
        resigned_case("commitment_broken", "commitment_mismatch", o, own_pem,
                      mutate_prev=lambda q: q.__setitem__("precommitmentValue", "AB" * 64))
        resigned_case("period_30s", "period_mismatch", o, own_pem,
                      mutate_prev=lambda q: q.__setitem__("timeStamp", "2026-11-16T13:03:30.000Z"))
        resigned_case("previous_value_other", "previous_mismatch", o, own_pem,
                      mutate_pulse=lambda p: p["listValues"][0].__setitem__("value", "CD" * 64))
        weak = own_cert(bits=1024)
        resigned_case("rsa_1024", "certificate_key_not_supported", weak, put("other/rsa_1024.pem", weak.pem))
        expired = own_cert(na=datetime.datetime(2026, 11, 16, 13, 3, 30, tzinfo=datetime.timezone.utc))
        resigned_case("certificate_expired", "certificate_not_valid_at_pulse_time", expired, put("other/expired.pem", expired.pem))
        q, p = resigned(o)
        p["outputValue"] = hashlib.sha512(b"other").hexdigest().upper()
        case("resigned_output_value", "invalid", "output_value_mismatch", ledger=put("ledgers/resigned_output_value.jsonl",
             ledger_for(p)), pulses=((put("pulses/resigned_output_value.json", TB.doc(p)),
                                      put("pulses/resigned_output_value_previous.json", TB.doc(q))),), certificates=[own_pem])
        case("beacon_value_of_other_pulse", "invalid", "beacon_value_mismatch", ledger=put(
            "ledgers/beacon_value_other.jsonl", ledger_with(lambda d: d[1]["beacons"][0].__setitem__(
                "output_value", TB.pulse(2030302)["outputValue"]))))
        two = ledger_with(lambda d: d[1].__setitem__("beacons", [TB.beacon_of(TB.pulse(2030302)), TB.beacon_of(TB.pulse(2030303))]))
        case("two_beacon_values", "verified", None, ledger=put("ledgers/two_beacons.jsonl", two), pulses=((P2, P1), (P3, P2)))

        # step 5, the window
        case("pack_not_valid", "invalid", "pack_not_valid", pack=_tampered(full_pack), max_window_s=30 * 86400, **pins)
        case("time_anchor_other_tsa", "invalid", "time_anchor_not_verified", pack=full_pack, max_window_s=30 * 86400,
             tsa_certs=[put("tsa/other_ca.crt", open(other.j("ca.crt"), "rb").read())])
        rpack = pack("revoked_tsa", led, with_lab=revoked)
        time.sleep(1.2)
        revoked.revoke("keyCompromise")
        case("time_anchor_tsa_revoked", "invalid", "time_anchor_not_verified", pack=rpack, max_window_s=30 * 86400,
             tsa_certs=[put("tsa/revoked_ca.crt", open(revoked.j("ca.crt"), "rb").read())],
             tsa_crls=[put("tsa/revoked_crl.pem", open(revoked.crl(), "rb").read())])
        case("ledger_not_in_pack", "invalid", "ledger_not_in_pack", ledger=put("ledgers/variant_amount.jsonl", ledger_with(
            lambda d: d[1].__setitem__("amount", "199.95"))), pack=full_pack, max_window_s=30 * 86400, **pins)
        case("window_too_wide", "invalid", "window_too_wide", pack=full_pack, max_window_s=0, **pins)
        q, p = resigned(o, mutate_prev=lambda q: q.__setitem__("timeStamp", "2027-01-01T00:00:00.000Z"),
                        mutate_pulse=lambda p: p.__setitem__("timeStamp", "2027-01-01T00:01:00.000Z"))
        future = ledger_for(p)
        case("window_inverted", "invalid", "window_inverted", ledger=put("ledgers/pulse_of_2027.jsonl", future),
             pulses=((put("pulses/pulse_of_2027.json", TB.doc(p)), put("pulses/pulse_of_2027_previous.json", TB.doc(q))),),
             certificates=[own_pem], pack=pack("pulse_of_2027", future), max_window_s=30 * 86400, **pins)
        case("trusted_list_malformed", "refused", "trusted_list_malformed", pack=full_pack, max_window_s=30 * 86400,
             tsa_trusted_list=put("tsa/not_a_trusted_list.xml", b"<not a trusted list"), **pins)

        # step 6, the checkpoint inside the pack
        def cp_case(name, why, note_bytes, status="invalid", in_pack=True, **kw):
            pk = pack(f"cp_{name}", led, {"checkpoint.note": note_bytes} if in_pack else None)
            a = dict(wk)
            a.update(kw)
            case(f"checkpoint_{name}", status, why, pack=pk, max_window_s=30 * 86400,
                 checkpoint=put(f"checkpoints/{name}.note", note_bytes), **pins, **a)
        cp_case("not_in_pack", "checkpoint_not_in_pack", note, in_pack=False)
        cp_case("witness_key_as_log_key", "checkpoint_malformed", note, status="refused",
                log_vkeys=[keys["witness.example/a"][1]])
        cp_case("no_witness", "checkpoint_not_witnessed", TB.witnessed_checkpoint(led, keys, witnesses=()))
        cp_case("cosigned_a_year_later", "checkpoint_cosigned_after_gen_time",
                TB.witnessed_checkpoint(led, keys, cosigned_at=int(time.time()) + 365 * 86400))
        cp_case("size_1", "checkpoint_not_covering_entry", TB.witnessed_checkpoint(led, keys, size=1))
        cp_case("size_beyond_ledger", "checkpoint_root_mismatch", TB.witnessed_checkpoint(led, keys, size=5, leaves_upto=3))
        other_log = dict(keys, **{LOG: (hashlib.sha256(b"another log").digest(), None)})
        cp_case("another_log_key", "checkpoint_log_not_trusted", TB.witnessed_checkpoint(led, other_log))

        # SPEC §19 rule 14: one entry and its inclusion proof, the pack holding the checkpoint and no payment
        line = TB.entry_line(led, 1)
        good_proof = B.inclusion_proof(led, 1, 3)
        ent = dict(pack=epack, max_window_s=30 * 86400, checkpoint=note_rel, tsa_crls=[crl], **pins, **wk)
        e_rel, p_rel = put("entries/entry_1.json", line), put("entries/proof_1.json", json.dumps(good_proof))
        case("entry_alone_complete", "verified", None, True, entry_file=e_rel, proof=p_rel, **ent)
        e = json.loads(line)
        case("entry_unknown_member", "refused", "entry_malformed", entry_file=put("entries/unknown_member.json",
             json.dumps(dict(e, note="x"))), proof=p_rel, **ent)
        case("entry_hash_mismatch", "invalid", "entry_hash_mismatch", entry_file=put("entries/amount_changed.json",
             json.dumps(dict(e, data=dict(e["data"], amount="199.95")))), proof=p_rel, **ent)
        case("proof_malformed", "refused", "proof_malformed", entry_file=e_rel,
             proof=put("entries/proof_unknown_member.json", json.dumps(dict(good_proof, note="x"))), **ent)
        case("proof_other_leaf", "invalid", "proof_mismatch", entry_file=e_rel,
             proof=put("entries/proof_leaf_0.json", json.dumps(B.inclusion_proof(led, 0, 3))), **ent)
        case("proof_wrong_path", "invalid", "inclusion_proof_invalid", entry_file=e_rel,
             proof=put("entries/proof_reversed.json", json.dumps(dict(good_proof, hashes=good_proof["hashes"][::-1]))),
             **ent)

        case("checkpoint_unreadable", "refused", "checkpoint_malformed", pack=full_pack, max_window_s=30 * 86400,
             checkpoint="nist", **pins, **wk)

        windows = [{"t": "2026-11-16T13:04:00.000Z", "period_ms": 60000, "gen_time": g, "max_window_s": m,
                    "clock_tolerance_s": tol, "expected": e}
                   for g, m, tol, e in (("2026-11-16T13:05:00Z", 60, 0, None),
                                        ("2026-11-16T13:05:00.000001Z", 60, 0, "window_too_wide"),
                                        ("2026-11-16T13:04:00Z", 0, 0, None),
                                        ("2026-11-16T13:03:59.999999Z", 3600, 0, "window_inverted"),
                                        ("2026-11-16T13:03:59.5Z", 3600, 1, None),
                                        ("2026-11-16T13:03:58.999999Z", 3600, 1, "window_inverted"),
                                        ("2026-11-13T09:00:00Z", 10 ** 9, 0, "window_inverted"),
                                        ("2026-11-16T14:04:00Z", 3600, 0, None))]
        doc = {"format": "cryptovalid-beacon-conformance/4", "spec": "SPEC_EVIDENCE_FORMAT.md v0.10 §18-§19",
               "paths": "relative to spec/vectors/beacon/", "cases": cases, "window_cases": windows}
        with open(os.path.join(HERE, "conformance.json"), "w", encoding="utf-8", newline="") as f:
            f.write(json.dumps(doc, ensure_ascii=False, indent=1) + "\n")
        print(len(cases), "cases,", len(windows), "window cases")
    finally:
        shutil.rmtree(work)


def _tampered(pack_rel):
    """a copy of the pack whose ledger gained a byte after the token: its content no longer matches the manifest"""
    src = os.path.join(HERE, pack_rel)
    dst = os.path.join(OUT, "packs", "tampered")
    shutil.copytree(src, dst)
    with open(os.path.join(dst, "payments.jsonl"), "ab") as f:
        f.write(b"\n")
    return rel(dst)


if __name__ == "__main__":
    main()
