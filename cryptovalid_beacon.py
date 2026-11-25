#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""A "not before" bound from a public randomness beacon, inside a payment entry (SPEC v0.10 §18-§19, 16/11/2026).

Every time proof cryptovalid verified until v0.9 is an upper bound (an RFC 3161 token, a signed tip, a checkpoint).
Values that the NIST Randomness Beacon 2.0 (chain 2) published, carried inside a ledger entry whose self_hash also
covers the payment (a random identifier, amount, currency, and the parties' IBANs, names and EndToEndId as 128-bit
salted commitments, never in clear), show that the entry's bytes were put together after the latest pulse T, for anyone
but the beacon's operator. The beacon value is technical evidence, not a legal timestamp. With the RFC 3161 token of an
evidence pack that holds the ledger, the entry is dated inside a window [T, genTime]; with a witnessed checkpoint inside
that pack, it is fixed at its position in one history as of genTime.

Status: EXPERIMENTAL (README, "Core and experimental modules").

Checked, offline, from the bytes the caller supplies, in the order of SPEC §19 rule 8: the ledger's chain (verifier.py,
SPEC §5 steps 1-4); the payment entry's closed profile (§18); disclosures against the commitments (a disclosed IBAN by
ISO 7064 MOD 97-10); for each beacon value the named pulse and its predecessor in their closed grammar, against the
certificates the caller pins: signature (RSA PKCS#1 v1.5 SHA-512, 4-byte length prefixes as deployed, not the draft NIST
IR 8213's 8-byte ones), outputValue, link, period, commitment, the entry's value; the window with evidence_pack.verify_pack
(pinned TSA certificates, optional pinned CRLs and Trusted List, a maximum width and a clock tolerance the caller gives);
the checkpoint (cryptovalid_witness.verify_witnessed). The receipt's `scope` names what is proved and what is not, from a
closed list: never that the entry is the only one composed after the pulse.

Not checked: the beacon certificate's chain and revocation (the pin is the trust); the hour/day/month/year list values;
status flags other than 0; chains other than 2; drand and CURBy (not supported yet, SPEC §19). `cryptography` is needed
for RSA, X.509 and Ed25519; without it the outcome is not_evaluated (backend_missing).

Command: cryptovalid-verify beacon <ledger> --entry <idx> --pulse <file> --previous <file> [...] --certificate <file>
         [--pack <dir> --tsa-cert <pem> ... --max-window <s> [--clock-tolerance <s>] [--tsa-crl <crl> ...]
          [--tsa-trusted-list <xml>] [--checkpoint <note> --log-vkey <vkey> --witness-vkey <vkey> ... [--min-witnesses <n>]]]
         [--disclosure <json> ...]
Exit 0 verified, 1 invalid or not_evaluated, 2 usage error or refused input, 74 receipt not written / check not run.
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
import re
import sys
import tempfile
import unicodedata
from datetime import datetime, timedelta, timezone
from fractions import Fraction
from typing import Dict, List, Optional, Tuple, Union

import verifier

PAYMENT_PROFILE = "cryptovalid-payment/1"
SOURCES = ("nist-beacon-2.0",)                     # SPEC §19: a closed list (drand planned, not implemented)
NIST_CHAIN = 2                                      # SPEC §19: only chain 2, version "2.0", is measured and accepted
MAX_BEACONS = 8
# SPEC §18, in the order of its table: required, then the optional commitments
PAYMENT_REQUIRED = ("profile", "payment_id", "amount", "currency", "beacons", "record_salt")
CLEAR_OPTIONAL = ("execution_date", "payee_entity_id", "psp_id")   # SPEC §18: not identifying a natural person
IBAN_COMMITMENTS = ("payer_iban_commitment", "payee_iban_commitment")
COMMITMENTS = ("payer_iban_commitment", "payee_iban_commitment", "payer_name_commitment", "payer_tax_id_commitment",
               "payer_details_commitment", "debtor_name_commitment", "debtor_tax_id_commitment", "payee_name_commitment",
               "end_to_end_id_commitment", "notice_code_commitment", "purpose_commitment", "receipt_id_commitment",
               "rrn_commitment")
NAME_COMMITMENTS = tuple(k for k in COMMITMENTS if k not in IBAN_COMMITMENTS)   # normalised in NFC, not as IBANs
PAYMENT_KEYS = PAYMENT_REQUIRED + CLEAR_OPTIONAL + COMMITMENTS
PARTY_IDENTIFIERS = ("payer_iban_commitment", "payee_iban_commitment", "payer_tax_id_commitment",
                     "debtor_tax_id_commitment", "payee_entity_id")
SALT_BYTES = 16   # SPEC §18: every commitment's salt is exactly 128 bits
BEACON_KEYS = frozenset({"source", "chain_index", "pulse_index", "output_value"})
DISCLOSURE_KEYS = frozenset({"member", "salt", "value"})
# SPEC §19 rule 7: the closed list of the receipt's scope sentences
SCOPE = {
    "composed_after_pulse": "the entry's bytes, with every member of the payment, were put together after the pulse's "
                            "timeStamp, for anyone but the beacon's operator",
    "stamped_before_gen_time": "the same bytes existed at the TSA's genTime",
    "stamped_by_qualified_tsa": "the TSA's certificate was a granted qualified timestamp service, at genTime, in the pinned "
                                "EU Trusted List snapshot, and the token carries the qualified statement of Regulation (EU) "
                                "2025/1929",
    "unique_under_pinned_witness": "the entry is the one at its position in the history the pinned witnesses cosigned "
                                   "before the TSA's genTime",
    "not_execution": "that a payment service provider executed the payment",
    "not_unique": "that this is the only entry composed after that pulse (a witness fixes the entry at its position, "
                  "not the other entries that carry the same pulse)",
    "not_ownership": "that the IBANs belong to the parties",
    "commitments_not_opened": "that a commitment not disclosed here opens to an IBAN, a name or an identifier",
    "payment_id_uniqueness": "that no other entry of the ledger carries the same payment_id",
    "currency_not_checked": "that the currency is an ISO 4217 code and the amount carries exactly its minor units",
    "not_operator": "anything against the beacon's operator beyond its freshness promise",
    "not_qualified": "that the upper bound is a qualified electronic time stamp",
    "not_legal_beacon": "that the beacon value is a legal timestamp: it is technical evidence of not before",
}
# SPEC §18 "Currencies": no currency table is shipped; the caller may pin one in this closed form (tools/iso4217_table.py
# writes it from the caller's own download of ISO 4217 list one)
CURRENCY_TABLE_FORMAT = "cryptovalid-iso4217-table/1"
MAX_CURRENCY_TABLE = 64 * 1024
_CURRENCY = re.compile(r"[A-Z]{3}")
PULSE_KEYS = ("uri", "version", "cipherSuite", "period", "certificateId", "chainIndex", "pulseIndex", "timeStamp",
              "localRandomValue", "external", "listValues", "precommitmentValue", "statusCode", "signatureValue",
              "outputValue")
EXTERNAL_KEYS = ("sourceId", "statusCode", "value")
LIST_KEYS = ("uri", "type", "value")
LIST_TYPES = ("previous", "hour", "day", "month", "year")
NIST_URI = "https://beacon.nist.gov/beacon/2.0/chain/{c}/pulse/{p}"
MAX_PULSE = 64 * 1024
MAX_CERT = 64 * 1024
MAX_LEDGER = 64 * 1024 * 1024
MAX_ENTRY = 1024 * 1024        # SPEC §19 rule 14
MAX_PROOF = 64 * 1024
MAX_PROOF_HASHES = 64
PROOF_FORMAT = "cryptovalid-inclusion-proof/1"
U32 = 2 ** 32 - 1

_HEX128 = re.compile(r"[0-9a-fA-F]{128}")
_HEX128_UPPER = re.compile(r"[0-9A-F]{128}")        # SPEC §19 rule 1: the entry's value as NIST serves it
_SIG = re.compile(r"(?:[0-9a-fA-F]{2}){1,1024}")
_TIME = re.compile(r"([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})\.([0-9]{3})Z")
_GEN_TIME = re.compile(r"([0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2})(?:\.([0-9]+))?Z")
_AMOUNT = re.compile(r"(0|[1-9][0-9]{0,17})(?:\.([0-9]+))?")
# SPEC §18: a version 4 UUID (RFC 9562) in its lowercase canonical form, the form of an ISO 20022 UETR
_PAYMENT_ID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}")
_SHA256_HEX = re.compile(r"[0-9a-f]{64}")
_SALT_HEX = re.compile(r"[0-9a-f]{32}")
_RECORD_SALT = re.compile(r"(?:[0-9a-f]{2}){16,64}")   # SPEC §18: 16 to 64 bytes, at least 128 bits
_IBAN_CHARS = re.compile(r"[A-Z0-9]+")
_CLEAR_ID = re.compile(r"[A-Za-z0-9]{1,35}")   # SPEC §18: payee_entity_id, psp_id
_DATE = re.compile(r"([0-9]{4})-([0-9]{2})-([0-9]{2})")
_IBAN_SHAPE = re.compile(r"[A-Z]{2}[0-9]{2}[A-Z0-9]{11,30}")
_DIGITS = re.compile(r"0|[1-9][0-9]*")


class Refused(ValueError):
    """an input that cannot be read as the format (SPEC §18-§19): status `refused`, exit 2"""

    def __init__(self, reason: str, detail: str = ""):
        super().__init__(f"{reason}: {detail}" if detail else reason)
        self.reason, self.detail = reason, detail


class Invalid(Exception):
    """a check of SPEC §19 that does not hold: status `invalid`, exit 1"""

    def __init__(self, reason: str, detail: str = ""):
        super().__init__(f"{reason}: {detail}" if detail else reason)
        self.reason, self.detail = reason, detail


# ───────────────────────────────────────────── SPEC §18: the payment entry

def iban_problem(value) -> Optional[str]:
    """None for an IBAN of SPEC §18 (ISO 13616-1 electronic format, ISO 7064 MOD 97-10), else the reason"""
    if not isinstance(value, str):
        return "iban_type"
    if not _IBAN_CHARS.fullmatch(value):   # code-point ranges: ASCII only (36 code points, measured)
        return "iban_charset"
    if not 15 <= len(value) <= 34:
        return "iban_length"
    if not _IBAN_SHAPE.fullmatch(value):
        return "iban_charset"
    if not 2 <= int(value[2:4]) <= 98:
        return "iban_check_digits"
    moved = value[4:] + value[:4]
    if int("".join(str(int(c, 36)) for c in moved)) % 97 != 1:
        return "iban_checksum"
    return None


def load_currency_table(src) -> Tuple[Dict[str, int], Dict]:
    """SPEC §18 "Currencies": the caller's pinned table (a path or bytes) -> ({code: minor units}, {"source", "sha256"});
    ValueError for a file outside the closed form (the caller's error, as a pinned CRL that cannot be read)."""
    import hashlib
    try:
        b = _read(src, "currency table", MAX_CURRENCY_TABLE)
        doc = verifier._loads_strict(b.decode("utf-8"))
    except (Refused, UnicodeDecodeError, ValueError, RecursionError) as e:
        raise ValueError(f"currency table: not a readable strict JSON file ({str(e)[:100]})") from None
    if not isinstance(doc, dict) or set(doc) != {"format", "source", "currencies"}:
        raise ValueError("currency table: exactly format, source, currencies")
    if doc["format"] != CURRENCY_TABLE_FORMAT:
        raise ValueError(f"currency table: format is not {CURRENCY_TABLE_FORMAT!r}")
    if not isinstance(doc["source"], str) or not 1 <= len(doc["source"]) <= 200:
        raise ValueError("currency table: source, a string of 1 to 200 characters")
    cur = doc["currencies"]
    if not isinstance(cur, dict) or not cur or not all(
            isinstance(k, str) and _CURRENCY.fullmatch(k) and type(v) is int and 0 <= v <= 4 for k, v in cur.items()):
        raise ValueError("currency table: currencies, at least one {three capital letters: integer 0 to 4}")
    return dict(cur), {"source": doc["source"], "sha256": hashlib.sha256(b).hexdigest()}


def check_payment(data, currencies: Optional[Dict[str, int]] = None) -> Dict:
    """SPEC §18, in the order of "Order of the profile's checks": a payment entry's `data`, closed. Returns it;
    Refused('payment_malformed', '<member>: <reason>') otherwise, Refused('entry_not_a_payment') when `profile` is not
    this profile's, Refused('source_not_supported') for a beacon value of another source (SPEC §19)."""
    def bad(member, why):
        raise Refused("payment_malformed", f"{member}: {why}")
    if not isinstance(data, dict) or data.get("profile") != PAYMENT_PROFILE:              # (1)
        raise Refused("entry_not_a_payment", f"data.profile is not {PAYMENT_PROFILE!r}")
    unknown = sorted(set(data) - set(PAYMENT_KEYS))                                       # (2)
    if unknown:
        bad(",".join(unknown), "member_unknown")
    missing = [k for k in PAYMENT_REQUIRED if k not in data]                              # (3)
    if missing:
        bad(",".join(missing), "member_missing")
    if not (isinstance(data["payment_id"], str) and _PAYMENT_ID.fullmatch(data["payment_id"])):   # (4)
        bad("payment_id", "not a version 4 UUID in lowercase canonical form")
    c = data["currency"]                                                                  # (5)
    if not isinstance(c, str) or not _CURRENCY.fullmatch(c):
        bad("currency", "not three capital letters A-Z")
    if currencies is not None and c not in currencies:
        bad("currency", "currency_unknown (not in the pinned currency table)")
    a = data["amount"]                                                                    # (6)
    m = _AMOUNT.fullmatch(a) if isinstance(a, str) else None
    if m is None:
        bad("amount", "not a decimal string")
    if currencies is None and len(m.group(2) or "") > 4:   # SPEC §18: without a pinned table, at most 4 decimals
        bad("amount", "not_canonical (more than 4 decimals; no currency table pinned)")
    if currencies is not None and len(m.group(2) or "") != currencies[c]:   # "1." is not a decimal string
        bad("amount", f"not_canonical (the minor units of {c} are {currencies[c]} in the pinned table: exactly that many decimals)")
    if int(m.group(1)) == 0 and int(m.group(2) or "0") == 0:
        bad("amount", "not greater than zero")
    if not (isinstance(data["record_salt"], str) and _RECORD_SALT.fullmatch(data["record_salt"])):   # (7)
        bad("record_salt", "not 32 to 128 lowercase hexadecimal characters, an even number (at least 128 bits)")
    if "execution_date" in data:                                                          # (7a)
        dm = _DATE.fullmatch(data["execution_date"]) if isinstance(data["execution_date"], str) else None
        try:
            datetime(*(int(g) for g in dm.groups())) if dm else None
        except ValueError:
            dm = None
        if dm is None:
            bad("execution_date", "not a calendar date YYYY-MM-DD")
    for k in ("payee_entity_id", "psp_id"):
        if k in data and not (isinstance(data[k], str) and _CLEAR_ID.fullmatch(data[k])):
            bad(k, "not 1 to 35 characters A-Z a-z 0-9")
    for k in COMMITMENTS:                                                                 # (8)
        if k in data and not (isinstance(data[k], str) and _SHA256_HEX.fullmatch(data[k])):
            bad(k, "not 64 lowercase hexadecimal characters")
    if not any(k in data for k in PARTY_IDENTIFIERS):                                     # (8a)
        bad("party_identifier_missing", "none of " + ", ".join(PARTY_IDENTIFIERS))
    bs = data["beacons"]                                                                  # (9)
    if not (isinstance(bs, list) and 1 <= len(bs) <= MAX_BEACONS):
        bad("beacons", f"not a list of 1 to {MAX_BEACONS} beacon values")
    for i, b in enumerate(bs):
        w = f"beacons[{i}]"
        if not isinstance(b, dict) or set(b) != BEACON_KEYS:
            bad(w, "not an object of exactly " + ",".join(sorted(BEACON_KEYS)))
        if not isinstance(b["source"], str):
            bad(f"{w}.source", "not a string")
        if b["source"] not in SOURCES:
            raise Refused("source_not_supported", f"{w}.source {b['source'][:80]!r}")
        if not (type(b["chain_index"]) is int and b["chain_index"] == NIST_CHAIN):
            bad(f"{w}.chain_index", f"not {NIST_CHAIN} (the only chain of nist-beacon-2.0 accepted)")
        if not (type(b["pulse_index"]) is int and 1 <= b["pulse_index"] <= verifier._SAFE_INT):
            bad(f"{w}.pulse_index", "not an integer >= 1")
        if not (isinstance(b["output_value"], str) and _HEX128_UPPER.fullmatch(b["output_value"])):
            bad(f"{w}.output_value", "not 128 upper-case hexadecimal characters")
    if len({(b["source"], b["pulse_index"]) for b in bs}) != len(bs):
        bad("beacons", "two values of one source and pulse")
    return data


COMMITMENT_DOMAIN = b"cryptovalid-payment/1/"
# SPEC §18 "Unicode version": the code points assigned in Unicode 13.0.0 (the database of CPython 3.9, the oldest runtime
# supported), as ranges of hex code points. NFC of a string of these code points is the same in every later version
# (Unicode normalization stability policy); a code point assigned later can normalise differently in two runtimes
# (measured 16/11/2026: U+1E08F before U+0316 reorders in Unicode 15.1, not in 13.0; Node 22, Unicode 17, composes
# U+105D2 U+0307 into U+105C9, CPython 3.9-3.13 do not), so the same disclosure would open in one and not the other.
_U13 = ("0-377,37A-37F,384-38A,38C,38E-3A1,3A3-52F,531-556,559-58A,58D-58F,591-5C7,5D0-5EA,5EF-5F4,600-61C,61E-70D,70F-74"
        "A,74D-7B1,7C0-7FA,7FD-82D,830-83E,840-85B,85E,860-86A,8A0-8B4,8B6-8C7,8D3-983,985-98C,98F-990,993-9A8,9AA-9B0,9B"
        "2,9B6-9B9,9BC-9C4,9C7-9C8,9CB-9CE,9D7,9DC-9DD,9DF-9E3,9E6-9FE,A01-A03,A05-A0A,A0F-A10,A13-A28,A2A-A30,A32-A33,A3"
        "5-A36,A38-A39,A3C,A3E-A42,A47-A48,A4B-A4D,A51,A59-A5C,A5E,A66-A76,A81-A83,A85-A8D,A8F-A91,A93-AA8,AAA-AB0,AB2-AB"
        "3,AB5-AB9,ABC-AC5,AC7-AC9,ACB-ACD,AD0,AE0-AE3,AE6-AF1,AF9-AFF,B01-B03,B05-B0C,B0F-B10,B13-B28,B2A-B30,B32-B33,B3"
        "5-B39,B3C-B44,B47-B48,B4B-B4D,B55-B57,B5C-B5D,B5F-B63,B66-B77,B82-B83,B85-B8A,B8E-B90,B92-B95,B99-B9A,B9C,B9E-B9"
        "F,BA3-BA4,BA8-BAA,BAE-BB9,BBE-BC2,BC6-BC8,BCA-BCD,BD0,BD7,BE6-BFA,C00-C0C,C0E-C10,C12-C28,C2A-C39,C3D-C44,C46-C4"
        "8,C4A-C4D,C55-C56,C58-C5A,C60-C63,C66-C6F,C77-C8C,C8E-C90,C92-CA8,CAA-CB3,CB5-CB9,CBC-CC4,CC6-CC8,CCA-CCD,CD5-CD"
        "6,CDE,CE0-CE3,CE6-CEF,CF1-CF2,D00-D0C,D0E-D10,D12-D44,D46-D48,D4A-D4F,D54-D63,D66-D7F,D81-D83,D85-D96,D9A-DB1,DB"
        "3-DBB,DBD,DC0-DC6,DCA,DCF-DD4,DD6,DD8-DDF,DE6-DEF,DF2-DF4,E01-E3A,E3F-E5B,E81-E82,E84,E86-E8A,E8C-EA3,EA5,EA7-EB"
        "D,EC0-EC4,EC6,EC8-ECD,ED0-ED9,EDC-EDF,F00-F47,F49-F6C,F71-F97,F99-FBC,FBE-FCC,FCE-FDA,1000-10C5,10C7,10CD,10D0-1"
        "248,124A-124D,1250-1256,1258,125A-125D,1260-1288,128A-128D,1290-12B0,12B2-12B5,12B8-12BE,12C0,12C2-12C5,12C8-12D"
        "6,12D8-1310,1312-1315,1318-135A,135D-137C,1380-1399,13A0-13F5,13F8-13FD,1400-169C,16A0-16F8,1700-170C,170E-1714,"
        "1720-1736,1740-1753,1760-176C,176E-1770,1772-1773,1780-17DD,17E0-17E9,17F0-17F9,1800-180E,1810-1819,1820-1878,18"
        "80-18AA,18B0-18F5,1900-191E,1920-192B,1930-193B,1940,1944-196D,1970-1974,1980-19AB,19B0-19C9,19D0-19DA,19DE-1A1B"
        ",1A1E-1A5E,1A60-1A7C,1A7F-1A89,1A90-1A99,1AA0-1AAD,1AB0-1AC0,1B00-1B4B,1B50-1B7C,1B80-1BF3,1BFC-1C37,1C3B-1C49,1"
        "C4D-1C88,1C90-1CBA,1CBD-1CC7,1CD0-1CFA,1D00-1DF9,1DFB-1F15,1F18-1F1D,1F20-1F45,1F48-1F4D,1F50-1F57,1F59,1F5B,1F5"
        "D,1F5F-1F7D,1F80-1FB4,1FB6-1FC4,1FC6-1FD3,1FD6-1FDB,1FDD-1FEF,1FF2-1FF4,1FF6-1FFE,2000-2064,2066-2071,2074-208E,"
        "2090-209C,20A0-20BF,20D0-20F0,2100-218B,2190-2426,2440-244A,2460-2B73,2B76-2B95,2B97-2C2E,2C30-2C5E,2C60-2CF3,2C"
        "F9-2D25,2D27,2D2D,2D30-2D67,2D6F-2D70,2D7F-2D96,2DA0-2DA6,2DA8-2DAE,2DB0-2DB6,2DB8-2DBE,2DC0-2DC6,2DC8-2DCE,2DD0"
        "-2DD6,2DD8-2DDE,2DE0-2E52,2E80-2E99,2E9B-2EF3,2F00-2FD5,2FF0-2FFB,3000-303F,3041-3096,3099-30FF,3105-312F,3131-3"
        "18E,3190-31E3,31F0-321E,3220-9FFC,A000-A48C,A490-A4C6,A4D0-A62B,A640-A6F7,A700-A7BF,A7C2-A7CA,A7F5-A82C,A830-A83"
        "9,A840-A877,A880-A8C5,A8CE-A8D9,A8E0-A953,A95F-A97C,A980-A9CD,A9CF-A9D9,A9DE-A9FE,AA00-AA36,AA40-AA4D,AA50-AA59,"
        "AA5C-AAC2,AADB-AAF6,AB01-AB06,AB09-AB0E,AB11-AB16,AB20-AB26,AB28-AB2E,AB30-AB6B,AB70-ABED,ABF0-ABF9,AC00-D7A3,D7"
        "B0-D7C6,D7CB-D7FB,E000-FA6D,FA70-FAD9,FB00-FB06,FB13-FB17,FB1D-FB36,FB38-FB3C,FB3E,FB40-FB41,FB43-FB44,FB46-FBC1"
        ",FBD3-FD3F,FD50-FD8F,FD92-FDC7,FDF0-FDFD,FE00-FE19,FE20-FE52,FE54-FE66,FE68-FE6B,FE70-FE74,FE76-FEFC,FEFF,FF01-F"
        "FBE,FFC2-FFC7,FFCA-FFCF,FFD2-FFD7,FFDA-FFDC,FFE0-FFE6,FFE8-FFEE,FFF9-FFFD,10000-1000B,1000D-10026,10028-1003A,10"
        "03C-1003D,1003F-1004D,10050-1005D,10080-100FA,10100-10102,10107-10133,10137-1018E,10190-1019C,101A0,101D0-101FD,"
        "10280-1029C,102A0-102D0,102E0-102FB,10300-10323,1032D-1034A,10350-1037A,10380-1039D,1039F-103C3,103C8-103D5,1040"
        "0-1049D,104A0-104A9,104B0-104D3,104D8-104FB,10500-10527,10530-10563,1056F,10600-10736,10740-10755,10760-10767,10"
        "800-10805,10808,1080A-10835,10837-10838,1083C,1083F-10855,10857-1089E,108A7-108AF,108E0-108F2,108F4-108F5,108FB-"
        "1091B,1091F-10939,1093F,10980-109B7,109BC-109CF,109D2-10A03,10A05-10A06,10A0C-10A13,10A15-10A17,10A19-10A35,10A3"
        "8-10A3A,10A3F-10A48,10A50-10A58,10A60-10A9F,10AC0-10AE6,10AEB-10AF6,10B00-10B35,10B39-10B55,10B58-10B72,10B78-10"
        "B91,10B99-10B9C,10BA9-10BAF,10C00-10C48,10C80-10CB2,10CC0-10CF2,10CFA-10D27,10D30-10D39,10E60-10E7E,10E80-10EA9,"
        "10EAB-10EAD,10EB0-10EB1,10F00-10F27,10F30-10F59,10FB0-10FCB,10FE0-10FF6,11000-1104D,11052-1106F,1107F-110C1,110C"
        "D,110D0-110E8,110F0-110F9,11100-11134,11136-11147,11150-11176,11180-111DF,111E1-111F4,11200-11211,11213-1123E,11"
        "280-11286,11288,1128A-1128D,1128F-1129D,1129F-112A9,112B0-112EA,112F0-112F9,11300-11303,11305-1130C,1130F-11310,"
        "11313-11328,1132A-11330,11332-11333,11335-11339,1133B-11344,11347-11348,1134B-1134D,11350,11357,1135D-11363,1136"
        "6-1136C,11370-11374,11400-1145B,1145D-11461,11480-114C7,114D0-114D9,11580-115B5,115B8-115DD,11600-11644,11650-11"
        "659,11660-1166C,11680-116B8,116C0-116C9,11700-1171A,1171D-1172B,11730-1173F,11800-1183B,118A0-118F2,118FF-11906,"
        "11909,1190C-11913,11915-11916,11918-11935,11937-11938,1193B-11946,11950-11959,119A0-119A7,119AA-119D7,119DA-119E"
        "4,11A00-11A47,11A50-11AA2,11AC0-11AF8,11C00-11C08,11C0A-11C36,11C38-11C45,11C50-11C6C,11C70-11C8F,11C92-11CA7,11"
        "CA9-11CB6,11D00-11D06,11D08-11D09,11D0B-11D36,11D3A,11D3C-11D3D,11D3F-11D47,11D50-11D59,11D60-11D65,11D67-11D68,"
        "11D6A-11D8E,11D90-11D91,11D93-11D98,11DA0-11DA9,11EE0-11EF8,11FB0,11FC0-11FF1,11FFF-12399,12400-1246E,12470-1247"
        "4,12480-12543,13000-1342E,13430-13438,14400-14646,16800-16A38,16A40-16A5E,16A60-16A69,16A6E-16A6F,16AD0-16AED,16"
        "AF0-16AF5,16B00-16B45,16B50-16B59,16B5B-16B61,16B63-16B77,16B7D-16B8F,16E40-16E9A,16F00-16F4A,16F4F-16F87,16F8F-"
        "16F9F,16FE0-16FE4,16FF0-16FF1,17000-187F7,18800-18CD5,18D00-18D08,1B000-1B11E,1B150-1B152,1B164-1B167,1B170-1B2F"
        "B,1BC00-1BC6A,1BC70-1BC7C,1BC80-1BC88,1BC90-1BC99,1BC9C-1BCA3,1D000-1D0F5,1D100-1D126,1D129-1D1E8,1D200-1D245,1D"
        "2E0-1D2F3,1D300-1D356,1D360-1D378,1D400-1D454,1D456-1D49C,1D49E-1D49F,1D4A2,1D4A5-1D4A6,1D4A9-1D4AC,1D4AE-1D4B9,"
        "1D4BB,1D4BD-1D4C3,1D4C5-1D505,1D507-1D50A,1D50D-1D514,1D516-1D51C,1D51E-1D539,1D53B-1D53E,1D540-1D544,1D546,1D54"
        "A-1D550,1D552-1D6A5,1D6A8-1D7CB,1D7CE-1DA8B,1DA9B-1DA9F,1DAA1-1DAAF,1E000-1E006,1E008-1E018,1E01B-1E021,1E023-1E"
        "024,1E026-1E02A,1E100-1E12C,1E130-1E13D,1E140-1E149,1E14E-1E14F,1E2C0-1E2F9,1E2FF,1E800-1E8C4,1E8C7-1E8D6,1E900-"
        "1E94B,1E950-1E959,1E95E-1E95F,1EC71-1ECB4,1ED01-1ED3D,1EE00-1EE03,1EE05-1EE1F,1EE21-1EE22,1EE24,1EE27,1EE29-1EE3"
        "2,1EE34-1EE37,1EE39,1EE3B,1EE42,1EE47,1EE49,1EE4B,1EE4D-1EE4F,1EE51-1EE52,1EE54,1EE57,1EE59,1EE5B,1EE5D,1EE5F,1E"
        "E61-1EE62,1EE64,1EE67-1EE6A,1EE6C-1EE72,1EE74-1EE77,1EE79-1EE7C,1EE7E,1EE80-1EE89,1EE8B-1EE9B,1EEA1-1EEA3,1EEA5-"
        "1EEA9,1EEAB-1EEBB,1EEF0-1EEF1,1F000-1F02B,1F030-1F093,1F0A0-1F0AE,1F0B1-1F0BF,1F0C1-1F0CF,1F0D1-1F0F5,1F100-1F1A"
        "D,1F1E6-1F202,1F210-1F23B,1F240-1F248,1F250-1F251,1F260-1F265,1F300-1F6D7,1F6E0-1F6EC,1F6F0-1F6FC,1F700-1F773,1F"
        "780-1F7D8,1F7E0-1F7EB,1F800-1F80B,1F810-1F847,1F850-1F859,1F860-1F887,1F890-1F8AD,1F8B0-1F8B1,1F900-1F978,1F97A-"
        "1F9CB,1F9CD-1FA53,1FA60-1FA6D,1FA70-1FA74,1FA78-1FA7A,1FA80-1FA86,1FA90-1FAA8,1FAB0-1FAB6,1FAC0-1FAC2,1FAD0-1FAD"
        "6,1FB00-1FB92,1FB94-1FBCA,1FBF0-1FBF9,20000-2A6DD,2A700-2B734,2B740-2B81D,2B820-2CEA1,2CEB0-2EBE0,2F800-2FA1D,30"
        "000-3134A,E0001,E0020-E007F,E0100-E01EF,F0000-FFFFD,100000-10FFFD")
_U13_LO, _U13_HI = zip(*((int(a, 16), int(b or a, 16)) for a, _, b in (x.partition("-") for x in _U13.split(","))))


def portable(value: str) -> bool:
    """SPEC §18: every code point of `value` is assigned in Unicode 13.0.0 (no lone surrogate: it is not UTF-8)"""
    import bisect
    for ch in value:
        cp = ord(ch)
        i = bisect.bisect_right(_U13_LO, cp) - 1
        if i < 0 or cp > _U13_HI[i] or 0xD800 <= cp <= 0xDFFF:
            return False
    return True


def normalised(member: str, value: str) -> str:
    """SPEC §18: an IBAN without spaces, in upper case, and passing the IBAN rule (ValueError('iban_...') otherwise); a
    name or details string in Unicode NFC"""
    if member not in COMMITMENTS:
        raise ValueError(f"member: one of {', '.join(COMMITMENTS)}")
    if not (isinstance(value, str) and 1 <= len(value) <= 1024):
        raise ValueError("value: a string of 1 to 1024 characters")
    if member in IBAN_COMMITMENTS:
        if not value.isascii():   # "ß".upper() is "SS": upper case only after the value is known to be ASCII
            raise ValueError("iban_charset")
        v = value.replace(" ", "").upper()
        why = iban_problem(v)
        if why:
            raise ValueError(why)
        return v
    if not portable(value):   # SPEC §18: NFC is the same in every runtime only for code points of Unicode 13.0.0
        raise ValueError("value_not_portable: a code point not assigned in Unicode 13.0.0, or a lone surrogate")
    return unicodedata.normalize("NFC", value)


def commitment(member: str, salt: bytes, value: str) -> str:
    """SPEC §18: SHA-256("cryptovalid-payment/1/" || member || 0x00 || salt (16 bytes) || UTF-8(normalised value))"""
    if not (isinstance(salt, (bytes, bytearray)) and len(salt) == SALT_BYTES):
        raise ValueError(f"salt: {SALT_BYTES} bytes")
    v = normalised(member, value)
    return hashlib.sha256(COMMITMENT_DOMAIN + member.encode("ascii") + b"\x00" + bytes(salt) + v.encode("utf-8")).hexdigest()


def parse_disclosure(src) -> Dict:
    """SPEC §18: {"member", "salt" (32 lowercase hex), "value"}, closed; Refused('disclosure_malformed') otherwise"""
    b = _read(src, "disclosure", MAX_PULSE)   # input_unreadable / input_too_large (SPEC §19 rule 8 step 3)
    try:
        d = _json(b, "disclosure")
    except Refused as e:
        raise Refused("disclosure_malformed", e.detail or e.reason) from None
    if not (isinstance(d, dict) and set(d) == DISCLOSURE_KEYS and d["member"] in COMMITMENTS
            and isinstance(d["salt"], str) and _SALT_HEX.fullmatch(d["salt"])
            and isinstance(d["value"], str) and 1 <= len(d["value"]) <= 1024 and portable(d["value"])):
        raise Refused("disclosure_malformed", "not {member: a commitment member, salt: 32 lowercase hex, value: 1 to "
                                              "1024 characters assigned in Unicode 13.0.0}")
    return d


# ───────────────────────────────────────────── SPEC §19 rule 2: a NIST pulse, closed

def _read(src: Union[str, bytes, bytearray], what: str, limit: int) -> bytes:
    if isinstance(src, (bytes, bytearray)):
        b = bytes(src)
    elif isinstance(src, str) and src:
        try:   # opened once without blocking, judged on the open descriptor (SPEC §5 step 0; until 0.26.0 stat then open)
            with os.fdopen(verifier.open_regular(src, sys.maxsize), "rb") as f:
                b = verifier.read_bounded(f, limit)
        except verifier.InputNotRegular:
            raise Refused("input_unreadable", f"{what}: not a regular file") from None
        except OSError as e:
            raise Refused("input_unreadable", f"{what}: {os.strerror(e.errno) if isinstance(e.errno, int) else e}") from None
    else:
        raise Refused("input_unreadable", f"{what}: a path or bytes")
    if len(b) > limit:
        raise Refused("input_too_large", f"{what}: more than {limit} bytes")
    return b


def _json(b: bytes, what: str):
    try:
        text = b.decode("utf-8")
    except UnicodeDecodeError:
        raise Refused("pulse_malformed", f"{what}: not UTF-8") from None
    try:
        return verifier._loads_strict(text)   # a byte order mark is a JSONDecodeError there (3.9 and 3.13 measured)
    except (ValueError, RecursionError) as e:
        raise Refused("pulse_malformed", f"{what}: {str(e)[:120]}") from None


def _keys(obj, keys, where):
    if not isinstance(obj, dict):
        raise Refused("pulse_malformed", f"{where}: not an object")
    if set(obj) != set(keys):
        extra, missing = sorted(set(obj) - set(keys)), sorted(set(keys) - set(obj))
        raise Refused("pulse_malformed", f"{where}: unknown {extra} missing {missing}")


def _text(v, where):
    if not (isinstance(v, str) and 1 <= len(v) <= 2048
            and not any(unicodedata.category(c) == "Cc" for c in v)):
        raise Refused("pulse_malformed", f"{where}: not a string of 1 to 2048 characters without control characters")


def _uint(v, where, top):
    if not (type(v) is int and 0 <= v <= top):
        raise Refused("pulse_malformed", f"{where}: not an integer in [0, {top}]")


def _hex128(v, where):
    if not (isinstance(v, str) and _HEX128.fullmatch(v)):
        raise Refused("pulse_malformed", f"{where}: not 128 hexadecimal characters")


def pulse_time(v: str) -> datetime:
    m = _TIME.fullmatch(v) if isinstance(v, str) else None
    if m is None:
        raise Refused("pulse_malformed", "timeStamp: not YYYY-MM-DDThh:mm:ss.sssZ")
    try:
        return datetime(*(int(g) for g in m.groups()[:6]), int(m.group(7)) * 1000, tzinfo=timezone.utc)
    except ValueError:
        raise Refused("pulse_malformed", "timeStamp: not a calendar time") from None


def parse_pulse(src, what: str = "pulse") -> Dict:
    """SPEC §19 rule 2: the bytes the beacon serves for one pulse, `{"pulse": P}`, closed. Returns P."""
    doc = _json(_read(src, what, MAX_PULSE), what)
    _keys(doc, ("pulse",), what)
    p = doc["pulse"]
    _keys(p, PULSE_KEYS, f"{what}.pulse")
    _text(p["uri"], f"{what}.uri")
    _text(p["version"], f"{what}.version")
    for k in ("cipherSuite", "period", "statusCode"):
        _uint(p[k], f"{what}.{k}", U32)
    for k in ("chainIndex", "pulseIndex"):
        _uint(p[k], f"{what}.{k}", verifier._SAFE_INT)
    pulse_time(p["timeStamp"])
    for k in ("certificateId", "localRandomValue", "precommitmentValue", "outputValue"):
        _hex128(p[k], f"{what}.{k}")
    if not (isinstance(p["signatureValue"], str) and _SIG.fullmatch(p["signatureValue"])):
        raise Refused("pulse_malformed", f"{what}.signatureValue: not hexadecimal of 2 to 2048 characters, even")
    e = p["external"]
    _keys(e, EXTERNAL_KEYS, f"{what}.external")
    _hex128(e["sourceId"], f"{what}.external.sourceId")
    _uint(e["statusCode"], f"{what}.external.statusCode", U32)
    _hex128(e["value"], f"{what}.external.value")
    lv = p["listValues"]
    if not (isinstance(lv, list) and len(lv) == len(LIST_TYPES)):
        raise Refused("pulse_malformed", f"{what}.listValues: not a list of five objects")
    for i, (x, t) in enumerate(zip(lv, LIST_TYPES)):
        _keys(x, LIST_KEYS, f"{what}.listValues[{i}]")
        if x["type"] != t:
            raise Refused("pulse_malformed", f"{what}.listValues[{i}].type: not {t!r}")
        _text(x["uri"], f"{what}.listValues[{i}].uri")
        _hex128(x["value"], f"{what}.listValues[{i}].value")
    return p


def _lp(b: bytes) -> bytes:
    return len(b).to_bytes(4, "big") + b


def signed_message(p: Dict) -> bytes:
    """SPEC §19 step 5: the message the deployed service signs (4-byte big-endian length prefixes)"""
    h = bytes.fromhex
    out = _lp(p["uri"].encode("utf-8")) + _lp(p["version"].encode("utf-8"))
    out += p["cipherSuite"].to_bytes(4, "big") + p["period"].to_bytes(4, "big")
    out += _lp(h(p["certificateId"]))
    out += p["chainIndex"].to_bytes(8, "big") + p["pulseIndex"].to_bytes(8, "big")
    out += _lp(p["timeStamp"].encode("utf-8")) + _lp(h(p["localRandomValue"]))
    e = p["external"]
    out += _lp(h(e["sourceId"])) + e["statusCode"].to_bytes(4, "big") + _lp(h(e["value"]))
    for x in p["listValues"]:
        out += _lp(h(x["value"]))
    out += _lp(h(p["precommitmentValue"])) + p["statusCode"].to_bytes(4, "big")
    return out


def _certificates(srcs) -> List:
    """the pinned beacon certificates (each a PEM holding exactly one, or DER): [(cryptography certificate, DER bytes)]"""
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    out = []
    for src in srcs:
        b = _read(src, "certificate", MAX_CERT)
        try:
            if b.count(b"-----BEGIN") or b.count(b"-----END"):
                if b.count(b"-----BEGIN CERTIFICATE-----") != 1 or b.count(b"-----BEGIN") != 1:
                    raise ValueError("a PEM file holding exactly one certificate")
                cert = x509.load_pem_x509_certificate(b)
            else:
                cert = x509.load_der_x509_certificate(b)
            out.append((cert, cert.public_bytes(serialization.Encoding.DER)))
        except ValueError as e:
            raise Refused("certificate_malformed", str(e)[:120]) from None
    return out


def check_pulses(beacon: Dict, pulse: Dict, prev: Dict, cert_srcs) -> Dict:
    """SPEC §19 rule 3 steps 1-9 for one beacon value, the named pulse and its predecessor (both parsed by parse_pulse);
    `cert_srcs`: the pinned certificates (a path or bytes, or a list of them).
    Returns the pulse summary; Invalid with the reason of the first step that fails. Needs `cryptography`
    (ImportError otherwise)."""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding, rsa
    for p in (pulse, prev):                                                        # step 1
        if p["version"] != "2.0":
            raise Invalid("version_not_supported", f"version {p['version'][:40]!r}")
        if p["cipherSuite"] != 0:
            raise Invalid("cipher_suite_not_supported", f"cipherSuite {p['cipherSuite']}")
    for p in (pulse, prev):                                                        # step 2
        if p["statusCode"] != 0:
            raise Invalid("status_not_supported", f"pulse {p['pulseIndex']}: statusCode {p['statusCode']}")
    want = ((pulse, beacon["pulse_index"]), (prev, beacon["pulse_index"] - 1))     # step 3
    for p, idx in want:
        if p["chainIndex"] != beacon["chain_index"] or p["pulseIndex"] != idx:
            raise Invalid("pulse_mismatch", f"chain {p['chainIndex']} pulse {p['pulseIndex']}, expected chain "
                                            f"{beacon['chain_index']} pulse {idx}")
        if p["uri"] != NIST_URI.format(c=p["chainIndex"], p=p["pulseIndex"]):
            raise Invalid("pulse_mismatch", f"uri {p['uri'][:120]!r}")
    if pulse["period"] != prev["period"] or bytes.fromhex(pulse["certificateId"]) != bytes.fromhex(prev["certificateId"]):
        raise Invalid("chain_inconsistent", "period or certificateId differ between the two pulses")
    pinned = _certificates(cert_srcs if isinstance(cert_srcs, (list, tuple)) else [cert_srcs])   # step 4
    match = [(c, d) for c, d in pinned if hashlib.sha512(d).digest() == bytes.fromhex(pulse["certificateId"])]
    if not match:
        raise Invalid("certificate_mismatch", "no pinned certificate has the SHA-512 certificateId")
    cert, der = match[0]
    key = cert.public_key()
    if not isinstance(key, rsa.RSAPublicKey) or key.key_size < 2048:
        raise Invalid("certificate_key_not_supported", "not an RSA key of at least 2048 bits")
    nb = getattr(cert, "not_valid_before_utc", None) or cert.not_valid_before.replace(tzinfo=timezone.utc)
    na = getattr(cert, "not_valid_after_utc", None) or cert.not_valid_after.replace(tzinfo=timezone.utc)
    for p in (prev, pulse):
        if not nb <= pulse_time(p["timeStamp"]) <= na:
            raise Invalid("certificate_not_valid_at_pulse_time", f"pulse {p['pulseIndex']} at {p['timeStamp']}")
    for p in (prev, pulse):                                                        # steps 5-6
        m, sig = signed_message(p), bytes.fromhex(p["signatureValue"])
        try:
            key.verify(sig, m, padding.PKCS1v15(), hashes.SHA512())
        except InvalidSignature:
            raise Invalid("signature_invalid", f"pulse {p['pulseIndex']}") from None
        if hashlib.sha512(m + sig).digest() != bytes.fromhex(p["outputValue"]):
            raise Invalid("output_value_mismatch", f"pulse {p['pulseIndex']}")
    if bytes.fromhex(pulse["listValues"][0]["value"]) != bytes.fromhex(prev["outputValue"]):   # step 7
        raise Invalid("previous_mismatch", "the previous list value is not the predecessor's outputValue")
    if pulse_time(pulse["timeStamp"]) - pulse_time(prev["timeStamp"]) != timedelta(milliseconds=pulse["period"]):
        raise Invalid("period_mismatch", f"{prev['timeStamp']} + {pulse['period']} ms != {pulse['timeStamp']}")
    if hashlib.sha512(bytes.fromhex(pulse["localRandomValue"])).digest() != bytes.fromhex(prev["precommitmentValue"]):
        raise Invalid("commitment_mismatch", "SHA-512(localRandomValue) is not the predecessor's precommitmentValue")
    if bytes.fromhex(beacon["output_value"]) != bytes.fromhex(pulse["outputValue"]):   # step 9
        raise Invalid("beacon_value_mismatch", "the entry's output_value is not the pulse's outputValue")
    t = pulse_time(pulse["timeStamp"])
    return {"source": beacon["source"], "chain_index": pulse["chainIndex"], "pulse_index": pulse["pulseIndex"],
            "time_stamp": pulse["timeStamp"], "period_ms": pulse["period"], "output_value": pulse["outputValue"].upper(),
            "certificate_sha512": hashlib.sha512(der).hexdigest(),
            "_t": t}


def _iso(t: datetime) -> str:
    return t.strftime("%Y-%m-%dT%H:%M:%S.") + f"{t.microsecond // 1000:03d}Z"


def _instant(t: datetime) -> Fraction:
    return Fraction(int((t - datetime(1970, 1, 1, tzinfo=timezone.utc)) // timedelta(microseconds=1)), 10 ** 6)


def gen_time_instant(gen_time: str) -> Fraction:
    """§11's gen_time (ISO 8601 UTC, any fraction) as an exact instant in seconds since 1970"""
    m = _GEN_TIME.fullmatch(gen_time) if isinstance(gen_time, str) else None
    if m is None:
        raise ValueError(f"gen_time {gen_time!r}")
    base = datetime.strptime(m.group(1), "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc)
    frac = Fraction(int(m.group(2)), 10 ** len(m.group(2))) if m.group(2) else Fraction(0)
    return _instant(base) + frac


def window(t: datetime, period_ms: int, gen_time: str, max_window_s: int, clock_tolerance_s: int = 0) -> Dict:
    """SPEC §19 rule 5: [T, genTime]; Invalid('window_inverted') when genTime < T - tolerance (a genTime in
    [T - tolerance, T) is one instant at T), Invalid('window_too_wide') when genTime - T > max_window_s"""
    g, lo = gen_time_instant(gen_time), _instant(t)
    if g < lo - clock_tolerance_s:
        raise Invalid("window_inverted", f"token genTime {gen_time} is before the pulse's {_iso(t)}")
    if g - lo > max_window_s:
        raise Invalid("window_too_wide", f"genTime {gen_time} is more than {max_window_s} s after the pulse's {_iso(t)}")
    return {"not_before": _iso(t), "not_after": gen_time if g >= lo else _iso(t), "gen_time": gen_time,
            "clock_tolerance_s": clock_tolerance_s,
            "not_before_operator_promise": _iso(t - timedelta(milliseconds=period_ms))}


# ───────────────────────────────────────────── the entry, the ledger, the pack

def _entries(ledger_bytes: bytes) -> List[Dict]:
    """the entries of a ledger that passes SPEC §5 steps 1-4 (Invalid('ledger_invalid') otherwise)"""
    try:   # not mkstemp: its Windows retry loop on an access list that denies (verifier.create_private)
        fd, tmp = verifier.create_private(tempfile.gettempdir(), "cv-beacon-", ".jsonl")
    except OSError as e:
        raise verifier.CheckNotRun(f"cannot write a temporary copy of the ledger: {verifier.os_reason(e)}") from None
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(ledger_bytes)
        r = verifier.verify_ledger(tmp)   # a private copy: no <path>.tip.json beside it
    finally:
        os.unlink(tmp)
    if r.get("verdict") != "PASS":
        raise Invalid("ledger_invalid", f"verdict {r.get('verdict')}")
    return [verifier._loads_strict(line) for line in ledger_bytes.decode("utf-8").split("\n") if line.strip(" \t\r")]


def _qualification(tsr_b64: str, signer_sha256: str, gen_time: str, trusted_list) -> tuple:
    """SPEC §19 rule 5 "Qualified or not": the token's signer in the pinned Trusted List snapshot at genTime"""
    import base64
    import cryptovalid_lotl as L
    try:
        tl = _read(trusted_list, "trusted list", MAX_LEDGER)
        at = datetime.strptime(gen_time[:19], "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc)
        st = L.qtst_status_at(tl, at)
    except Refused:
        raise
    except Exception as e:   # the snapshot is the caller's pin: one it cannot be read is its error
        raise Refused("trusted_list_malformed", f"{type(e).__name__}: {str(e)[:120]}") from None
    return L.qualification(base64.b64decode(tsr_b64), st["granted"], st["errors"], signer_sha256)


def _pack_window(pack_dir: str, tsa_certs, tsa_crls, max_window_s: int, clock_tolerance_s: int, ledger_bytes: bytes,
                 beacon: Dict, trusted_list=None):
    """SPEC §19 rule 5: (window, the manifest's file digests, genTime)"""
    import evidence_pack
    r = evidence_pack.verify_pack(pack_dir, tsa_certs=tsa_certs, tsa_crls=tsa_crls)
    st = r.get("states") or {}
    if (st.get("sealed_content") or {}).get("state") != "verified":   # a refused pack has no states: not verified
        raise Invalid("pack_not_valid", str(r.get("error") or (st.get("sealed_content") or {}).get("reasons"))[:160])
    if (st.get("time_anchor") or {}).get("state") != "verified":
        ta = st.get("time_anchor") or {}
        raise Invalid("time_anchor_not_verified", f"{ta.get('state')} {ta.get('reasons')} {ta.get('detail') or ''}"[:200])
    if r.get("valid") is not True:
        raise Invalid("pack_not_valid", "the pack's verify answers valid: false")
    man = verifier._loads_strict(_read(os.path.join(pack_dir, "MANIFEST.json"), "MANIFEST.json", MAX_LEDGER).decode("utf-8"))
    digests = man["file_digests_sha256"]   # a valid pack: every listed file has its digest (files_ok)
    if ledger_bytes is None:   # SPEC §19 rule 14: one entry, under the checkpoint of the pack (step 6)
        names = [None]
    else:
        digest = hashlib.sha256(ledger_bytes).hexdigest()
        names = sorted(n for n, d in digests.items() if d == digest)
        if not names:
            raise Invalid("ledger_not_in_pack", "no file of the pack has these bytes")
    gt = (r.get("rfc3161") or {}).get("tsa_check", {}).get("gen_time")
    w = window(beacon["_t"], beacon["period_ms"], gt, max_window_s, clock_tolerance_s)
    chk = r["rfc3161"]["tsa_check"]
    w.update({"max_window_s": max_window_s, "pack_ledger": names[0], "tsa_signer_sha256": chk.get("signer_sha256"),
              "tsa_sha1_signature_legacy": chk.get("sha1_signature_legacy"),
              "tsa_revocation": chk["revocation"] if tsa_crls is not None else "not_checked",
              "tsa_qualification": "not_checked", "tsa_qualification_reason": None})
    if trusted_list is not None:   # SPEC §19 "Qualified or not"; v0.10: the qualified statement's reason too
        q, why = _qualification(man["rfc3161_timestamp"]["tsr_b64"], chk.get("signer_sha256"), gt, trusted_list)
        w.update({"tsa_qualification": q, "tsa_qualification_reason": why if q == "not_qualified" else None})
    return w, digests, gt


def _witnessed(checkpoint, log_vkeys: List[str], witness_vkeys: List[str], min_witnesses: int, entries: List[Dict],
               entry_idx: int, pack_digests: Dict, gen_time: str, entry: Optional[Dict] = None,
               proof: Optional[Dict] = None) -> Dict:
    """SPEC §19 rule 6: the entry under a checkpoint inside the pack, signed by a pinned log key and cosigned by pinned
    witnesses no later than the token's genTime"""
    import base64
    import cryptovalid_checkpoint as C
    import cryptovalid_merkle as M
    import cryptovalid_witness as W
    try:
        note = C.read_note_file(checkpoint) if isinstance(checkpoint, str) else bytes(checkpoint)
    except (C.NoteError, OSError, TypeError) as e:
        raise Refused("checkpoint_malformed", verifier.os_error_text(e)[:160]) from None
    if hashlib.sha256(note).hexdigest() not in set(pack_digests.values()):
        raise Invalid("checkpoint_not_in_pack", "the checkpoint is not a file of the pack: it is not under the token")
    now = int(gen_time_instant(gen_time))   # a cosignature timestamp t (whole seconds) is not after genTime iff t <= floor
    try:
        v = W.verify_witnessed(note, log_vkeys, witness_vkeys, min_witnesses)
        vt = W.verify_witnessed(note, log_vkeys, witness_vkeys, min_witnesses, max_age_s=2 ** 62, now=now)
    except (C.NoteError, TypeError) as e:
        raise Refused("checkpoint_malformed", str(e)[:160]) from None
    if v["stato"] == "NON_VERIFICATA":
        raise ImportError(v["motivo"])
    if v["stato"] != "OK":   # SPEC §19 rule 6: the log's signature and origin first, then the witnesses
        lg = C.verify_note(note, log_vkeys)
        names = {C.parse_vkey(k)[0] for k in log_vkeys}
        origin = None
        if lg["stato"] == "OK":
            try:
                origin = C.parse_checkpoint(lg["text"])["origin"]
            except C.NoteError:
                origin = None
        if lg["stato"] != "OK" or origin not in names:
            raise Invalid("checkpoint_log_not_trusted", str(lg.get("motivo") or v["motivo"])[:160])
        raise Invalid("checkpoint_not_witnessed", str(v["motivo"])[:160])
    if vt["stato"] != "OK":
        raise Invalid("checkpoint_cosigned_after_gen_time", f"cosigned after {gen_time}: {vt['future_witnesses']}"[:160])
    size, root = v["checkpoint"]["size"], base64.b64decode(v["checkpoint"]["root"])
    if size <= entry_idx:
        raise Invalid("checkpoint_not_covering_entry", f"checkpoint size {size}, entry {entry_idx}")
    if proof is not None:   # SPEC §19 rule 14 item 4
        if proof["tree_size"] != size:
            raise Invalid("proof_mismatch", f"proof for a tree of {proof['tree_size']}, checkpoint of {size}")
        if not M.verify_inclusion(proof["leaf_index"], size, M.canonical(entry),
                                  [bytes.fromhex(h) for h in proof["hashes"]], root):
            raise Invalid("inclusion_proof_invalid", f"the proof does not lead from entry {entry_idx} to the checkpoint's root")
    else:
        leaves = [M.canonical(e) for e in entries]
        if size > len(leaves) or M.mth(leaves[:size]) != root:
            raise Invalid("checkpoint_root_mismatch",
                          f"the root of the first {size} entries of this ledger is not the checkpoint's")
    return {"status": "witnessed", "witnesses": v["witnesses"], "checkpoint_size": size,
            "origin": v["checkpoint"]["origin"], "as_of": gen_time}


def _doc(b: bytes, what: str, code: str):
    """a UTF-8 JSON document read as a ledger line (SPEC §3): one final line feed allowed"""
    try:
        text = b.decode("utf-8")
    except UnicodeDecodeError:
        raise Refused(code, f"{what}: not UTF-8") from None
    if text.endswith("\n"):
        text = text[:-1]
    if text != text.strip(" \t\r\n"):
        raise Refused(code, f"{what}: white space around the document (one final line feed only)")
    try:
        return verifier._loads_strict(text)
    except (ValueError, RecursionError) as e:
        raise Refused(code, f"{what}: {str(e)[:120]}") from None


def _int(v) -> bool:
    return type(v) is int and v >= 0


def read_entry(src) -> Dict:
    """SPEC §19 rule 14 item 1: one entry of SPEC §2 with the closed members of §2.1, and its self_hash"""
    e = _doc(_read(src, "entry", MAX_ENTRY), "entry", "entry_malformed")
    if not isinstance(e, dict):
        raise Refused("entry_malformed", "not a JSON object")
    unknown = sorted(set(e) - verifier.ENTRY_KEYS)
    if unknown:
        raise Refused("entry_malformed", "unknown_field:" + ",".join(unknown))
    for k in ("idx", "ts", "data", "prev_hash", "self_hash"):
        if k not in e:
            raise Refused("entry_malformed", f"{k}: missing")
    if not _int(e["idx"]):
        raise Refused("entry_malformed", "idx: not an integer >= 0")
    if not isinstance(e["ts"], str) or not isinstance(e["data"], dict):
        raise Refused("entry_malformed", "ts: not a string, or data: not an object")
    for k in ("prev_hash", "self_hash"):
        if not (isinstance(e[k], str) and _SHA256_HEX.fullmatch(e[k])):
            raise Refused("entry_malformed", f"{k}: not 64 lowercase hexadecimal characters")
    payload = verifier.canonical_payload(e)
    if e["self_hash"] not in {verifier.hash_with(a, payload) for a in ("sha256", "sha3_256")}:
        raise Invalid("entry_hash_mismatch", "self_hash is neither the SHA-256 nor the SHA3-256 of the canonical form")
    return e


def read_proof(src) -> Dict:
    """SPEC §19 rule 14 item 2: the closed inclusion proof"""
    p = _doc(_read(src, "proof", MAX_PROOF), "proof", "proof_malformed")
    keys = ("format", "leaf_index", "tree_size", "hashes")
    if not isinstance(p, dict) or set(p) != set(keys):
        raise Refused("proof_malformed", f"not an object of exactly {', '.join(keys)}")
    if p["format"] != PROOF_FORMAT:
        raise Refused("proof_malformed", f"format: not {PROOF_FORMAT}")
    if not _int(p["leaf_index"]) or not _int(p["tree_size"]) or p["tree_size"] < 1 or p["leaf_index"] >= p["tree_size"]:
        raise Refused("proof_malformed", "leaf_index, tree_size: integers with 0 <= leaf_index < tree_size")
    h = p["hashes"]
    if not (isinstance(h, list) and len(h) <= MAX_PROOF_HASHES
            and all(isinstance(x, str) and _SHA256_HEX.fullmatch(x) for x in h)):
        raise Refused("proof_malformed", f"hashes: a list of at most {MAX_PROOF_HASHES} values of 64 lowercase hex")
    return p


def inclusion_proof(ledger, idx: int, tree_size: int) -> Dict:
    """for a provider: the proof of SPEC §19 rule 14 for entry `idx` of `ledger` (path or bytes) in its first
    `tree_size` entries, the size of the checkpoint it will give"""
    import cryptovalid_merkle as M
    entries = _entries(_read(ledger, "ledger", MAX_LEDGER))
    if not (_int(idx) and _int(tree_size) and idx < tree_size <= len(entries)):
        raise ValueError("0 <= idx < tree_size <= the number of entries")
    leaves = [M.canonical(e) for e in entries[:tree_size]]
    return {"format": PROOF_FORMAT, "leaf_index": idx, "tree_size": tree_size,
            "hashes": [h.hex() for h in M.inclusion_proof(idx, leaves)]}


def _scope(window_ok: bool, unique_ok: bool, qualified: bool = False, unopened: bool = True,
           id_checked: bool = True, currency_checked: bool = False) -> Dict:
    proves = ["composed_after_pulse"] + (["stamped_before_gen_time"] if window_ok else []) \
        + (["stamped_by_qualified_tsa"] if qualified else []) + (["unique_under_pinned_witness"] if unique_ok else [])
    not_proved = ["not_execution", "not_unique", "not_ownership"] + (["commitments_not_opened"] if unopened else []) \
        + ([] if id_checked else ["payment_id_uniqueness"]) \
        + ([] if currency_checked else ["currency_not_checked"]) + ["not_operator"] + ([] if qualified else ["not_qualified"]) + ["not_legal_beacon"]
    return {"proves": [{k: SCOPE[k]} for k in proves], "does_not_prove": [{k: SCOPE[k]} for k in not_proved]}


def _bounds(b: Dict) -> Dict:
    t = b["_t"]
    return {"not_before": _iso(t), "holds_against": "anyone but the beacon operator (NIST IR 8213 draft §3.3, promises 1-2)",
            "not_before_operator_promise": _iso(t - timedelta(milliseconds=b["period_ms"])),
            "operator_promise": "only if the operator kept its freshness promise (§3.3, promise 3); not checked",
            "against_an_operator_breaking_its_promises": None}


def _as_list(x):
    return list(x) if isinstance(x, (list, tuple)) else [x]


def verify_beacon_entry(ledger, entry_idx: int, pulse, previous, certificate,
                        pack_dir: Optional[str] = None, tsa_certs: Optional[List] = None,
                        disclosures: Optional[List] = None, max_window_s: Optional[int] = None,
                        tsa_crls: Optional[List] = None, checkpoint=None, log_vkeys: Optional[List[str]] = None,
                        witness_vkeys: Optional[List[str]] = None, min_witnesses: Optional[int] = None,
                        tsa_trusted_list=None, clock_tolerance_s: Optional[int] = None,
                        required_disclosures: Optional[List[str]] = None, currency_table=None) -> Dict:
    """SPEC §19: the receipt for entry `entry_idx` of `ledger` (path or bytes), in the order of SPEC §19 rule 8.
    `pulse`, `previous`: the pulse pair of each element of `beacons`, a path or bytes, or lists of them in the order of
    `beacons`; `certificate`: the pinned beacon certificates (one, or a list). With `pack_dir` (and `tsa_certs`,
    `max_window_s`) the window with the pack's token; `tsa_crls`, `tsa_trusted_list`, `clock_tolerance_s` refine it.
    `checkpoint` (path or bytes, a file of the pack) with `log_vkeys` and `witness_vkeys` (and `min_witnesses`, default
    1): SPEC §19 rule 6. `disclosures`: paths or bytes of SPEC §18 disclosures.
    Never raises on the evidence: status refused / invalid / not_evaluated / verified. Arguments that do not go together
    are a ValueError; a check that cannot run here (openssl, SPEC §10) raises verifier.CheckNotRun.
    `required_disclosures`: commitment members that must be disclosed and match (SPEC §19 rule 15).
    `currency_table`: a pinned ISO 4217 table (path or bytes, SPEC §18 "Currencies"); None: currency checked by form only."""
    if type(entry_idx) is not int or entry_idx < 0:
        raise ValueError("entry_idx: an integer >= 0")
    return _verify(ledger, entry_idx, None, pulse, previous, certificate, pack_dir, tsa_certs, disclosures, max_window_s,
                   tsa_crls, checkpoint, log_vkeys, witness_vkeys, min_witnesses, tsa_trusted_list, clock_tolerance_s,
                   required_disclosures, currency_table)


def verify_beacon_entry_proof(entry, proof, pulse, previous, certificate, pack_dir: str, tsa_certs: List,
                              max_window_s: int, checkpoint, log_vkeys: List[str], witness_vkeys: List[str],
                              disclosures: Optional[List] = None, tsa_crls: Optional[List] = None,
                              min_witnesses: Optional[int] = None, tsa_trusted_list=None,
                              clock_tolerance_s: Optional[int] = None,
                              required_disclosures: Optional[List[str]] = None, currency_table=None) -> Dict:
    """SPEC §19 rule 14: the receipt for one entry (path or bytes) and its inclusion proof under the witnessed
    checkpoint of the pack, without the ledger. The other arguments as in verify_beacon_entry."""
    if pack_dir is None or checkpoint is None:
        raise ValueError("one entry needs pack_dir and checkpoint: the inclusion is under the checkpoint of the pack")
    return _verify(entry, None, proof, pulse, previous, certificate, pack_dir, tsa_certs, disclosures, max_window_s,
                   tsa_crls, checkpoint, log_vkeys, witness_vkeys, min_witnesses, tsa_trusted_list, clock_tolerance_s,
                   required_disclosures, currency_table)


def _verify(ledger, entry_idx, proof, pulse, previous, certificate, pack_dir, tsa_certs, disclosures, max_window_s,
            tsa_crls, checkpoint, log_vkeys, witness_vkeys, min_witnesses, tsa_trusted_list, clock_tolerance_s,
            required_disclosures, currency_table=None) -> Dict:
    if required_disclosures is not None:
        req = list(required_disclosures)
        if not all(isinstance(m, str) and m in COMMITMENTS for m in req) or len(set(req)) != len(req):
            raise ValueError("required_disclosures: distinct commitment members of SPEC §18")
    if (pack_dir is None) != (tsa_certs is None):
        raise ValueError("pack_dir and tsa_certs go together: the window needs a token checked with pinned certificates")
    if (pack_dir is None) != (max_window_s is None):
        raise ValueError("pack_dir and max_window_s go together: the caller says how wide a fresh window may be")
    if max_window_s is not None and (type(max_window_s) is not int or max_window_s < 0):
        raise ValueError("max_window_s: an integer >= 0 (seconds)")
    if clock_tolerance_s is not None and (pack_dir is None or type(clock_tolerance_s) is not int or clock_tolerance_s < 0):
        raise ValueError("clock_tolerance_s: an integer >= 0 (seconds), with pack_dir")
    if tsa_crls is not None and pack_dir is None:
        raise ValueError("tsa_crls need pack_dir")
    if tsa_trusted_list is not None and pack_dir is None:
        raise ValueError("tsa_trusted_list needs pack_dir")
    if tsa_crls is not None:
        import cryptovalid_tsa
        try:
            cryptovalid_tsa._load_crls(tsa_crls)   # a pinned CRL that cannot be read is the caller's error, before any input
        except ImportError:
            pass                                    # read again by verify_token, which reports crl_backend_missing
    if not ((checkpoint is None) == (log_vkeys is None) == (witness_vkeys is None)):
        raise ValueError("checkpoint, log_vkeys and witness_vkeys go together")
    if checkpoint is not None and pack_dir is None:
        raise ValueError("checkpoint needs pack_dir: the checkpoint counts only inside the pack, under its token")
    if min_witnesses is not None and (checkpoint is None or type(min_witnesses) is not int or min_witnesses < 1):
        raise ValueError("min_witnesses: an integer >= 1, with a checkpoint")
    currencies, table_info = load_currency_table(currency_table) if currency_table is not None else (None, None)
    pulses, previouses = _as_list(pulse), _as_list(previous)
    if len(pulses) != len(previouses) or not pulses:
        raise ValueError("one previous pulse for every pulse")
    out = {"kind": "beacon", "status": None, "reason": None, "detail": "", "valid": False, "record_complete": False,
           "entry": None, "pulse": None, "pulses": [], "bounds": None, "window": None,
           "unique": {"status": "not_established"}, "disclosed": [], "currency_table": table_info, "scope": None}
    try:
        if proof is None:
            lb = _read(ledger, "ledger", MAX_LEDGER)                                # step 1
            entries = _entries(lb)   # bytes that are not UTF-8 FAIL verify_ledger (SPEC §3): ledger_invalid
            found = [x for x in entries if x.get("idx") == entry_idx]
            if not found:
                raise Invalid("entry_not_found", f"no entry {entry_idx}")
            e, pr = found[0], None
        else:                                                                       # SPEC §19 rule 14 items 1-2
            lb, entries = None, None
            e = read_entry(ledger)
            pr = read_proof(proof)
            if pr["leaf_index"] != e["idx"]:
                raise Invalid("proof_mismatch", f"proof for leaf {pr['leaf_index']}, entry {e['idx']}")
            entry_idx = e["idx"]
        data = check_payment(e.get("data"), currencies)                             # step 2
        if entries is not None:
            same = [x["idx"] for x in entries if isinstance(x.get("data"), dict)
                    and x["data"].get("profile") == PAYMENT_PROFILE and x["data"].get("payment_id") == data["payment_id"]]
            if len(same) > 1:
                raise Invalid("payment_id_not_unique",
                              f"payment_id also in entries {[i for i in same if i != entry_idx][:10]}")
        if len(pulses) != len(data["beacons"]):
            raise ValueError(f"{len(data['beacons'])} beacon value(s) in the entry, {len(pulses)} pulse pair(s) given")
        ds = [parse_disclosure(d) for d in (disclosures or [])]                    # step 3
        if len({d["member"] for d in ds}) != len(ds):
            raise Refused("disclosure_malformed", "two disclosures for one member")
        out["entry"] = {"idx": entry_idx, "self_hash": e["self_hash"], "covers": [k for k in PAYMENT_KEYS if k in data],
                        "payment": {k: data[k] for k in ("payment_id", "amount", "currency")}}
        for d in ds:
            try:
                c = commitment(d["member"], bytes.fromhex(d["salt"]), d["value"])
            except ValueError as x:   # parse_disclosure checked member, salt and value: only the IBAN rule is left
                raise Invalid("disclosure_iban_invalid", f"{d['member']}: {x}") from None
            if data.get(d["member"]) != c:
                raise Invalid("disclosure_mismatch", f"{d['member']}: the disclosed salt and value do not give the entry's commitment")
            out["disclosed"].append(d["member"])
        missing = [m for m in (required_disclosures or []) if m not in out["disclosed"]]   # SPEC §19 rule 15
        if missing:
            raise Invalid("required_disclosure_missing", "required and not disclosed: " + ", ".join(missing))
        summaries = []
        for i, (bv, ps, qs) in enumerate(zip(data["beacons"], pulses, previouses)):   # step 4
            p = parse_pulse(ps, f"pulse[{i}]")
            q = parse_pulse(qs, f"previous[{i}]")
            try:
                summaries.append(check_pulses(bv, p, q, certificate))
            except ImportError as ie:
                out.update(status="not_evaluated", reason="backend_missing", detail=f"cryptography: {ie}"[:160])
                return out
        b = max(summaries, key=lambda x: x["_t"])   # SPEC §19 rule 4: the latest pulse is the lower bound
        out["pulses"] = [{k: v for k, v in x.items() if not k.startswith("_")} for x in summaries]
        out["pulse"] = {k: v for k, v in b.items() if not k.startswith("_")}
        out["bounds"] = _bounds(b)
        unopened = any(k in data and k not in out["disclosed"] for k in COMMITMENTS)
        out["scope"] = _scope(False, False, False, unopened, proof is None, currencies is not None)
        if pack_dir is not None:                                                    # step 5
            out["window"], digests, gt = _pack_window(pack_dir, tsa_certs, tsa_crls, max_window_s, clock_tolerance_s or 0,
                                                      lb, b, tsa_trusted_list)
            if checkpoint is not None:                                              # step 6
                try:
                    out["unique"] = _witnessed(checkpoint, list(log_vkeys), list(witness_vkeys), min_witnesses or 1,
                                               entries, entry_idx, digests, gt, e, pr)
                except ImportError as ie:
                    out.update(status="not_evaluated", reason="backend_missing", detail=f"checkpoint: {ie}"[:160])
                    return out
        unique = out["unique"]["status"] == "witnessed"
        w = out["window"] or {}
        out["scope"] = _scope(out["window"] is not None, unique, w.get("tsa_qualification") == "qualified", unopened,
                              proof is None, currency_checked=currencies is not None)
        out.update(status="verified", valid=True,
                   record_complete=bool(w) and unique and w.get("tsa_revocation") != "not_checked")
    except Refused as x:
        out.update(status="refused", reason=x.reason, detail=x.detail)
    except Invalid as x:
        out.update(status="invalid", reason=x.reason, detail=x.detail)
    return out


# ───────────────────────────────────────────── command line

def _entry_arg(v: str) -> int:
    import argparse
    if not _DIGITS.fullmatch(v):   # [0-9] are code-point ranges: ASCII digits only
        raise argparse.ArgumentTypeError(f"--entry {v!r}: an integer >= 0 in decimal")
    return int(v)


def _nonempty(v: str) -> str:
    import argparse
    if v == "":
        raise argparse.ArgumentTypeError("an empty value is not a pin (SPEC §17)")
    return v


def main(argv=None, prog=None, cmd_name=None) -> int:
    from verifier import Parser, _Once, emit
    import cryptovalid_tsa as T
    ap = Parser(prog=f"{prog} {cmd_name}" if prog and cmd_name else prog, allow_abbrev=False,
                description="A 'not before' bound from the NIST Randomness Beacon 2.0, inside a payment entry of a "
                            "ledger, and its window with the RFC 3161 token of an evidence pack (SPEC §18-§19).")
    ap.add_argument("ledger", nargs="?", default=None, type=_nonempty,
                    help="the ledger (.jsonl) holding the payment entry (with --entry)")
    ap.add_argument("--entry", action=_Once, type=_entry_arg, help="idx of the payment entry to date (with the ledger)")
    ap.add_argument("--entry-file", action=_Once, type=_nonempty,
                    help="one entry without its ledger (SPEC §19 rule 14; with --proof, --pack and --checkpoint)")
    ap.add_argument("--proof", action=_Once, type=_nonempty,
                    help="the inclusion proof of --entry-file under the checkpoint (cryptovalid-inclusion-proof/1)")
    ap.add_argument("--require-disclosure", action="append", default=None, metavar="MEMBER", type=_nonempty,
                    help="a commitment member that must be disclosed and match (repeatable, SPEC §19 rule 15)")
    ap.add_argument("--pulse", required=True, action="append", type=_nonempty,
                    help="the pulse of a beacon value, as served by /beacon/2.0/chain/2/pulse/<i> (one per value, in order)")
    ap.add_argument("--previous", required=True, action="append", type=_nonempty,
                    help="the pulse before it (commitment), one per --pulse, in the same order")
    ap.add_argument("--certificate", required=True, action="append", type=_nonempty,
                    help="a beacon certificate you pin (PEM with one certificate, or DER; repeatable)")
    ap.add_argument("--pack", action=_Once, type=_nonempty, help="evidence pack holding the ledger: gives the window")
    ap.add_argument("--tsa-cert", action="append", default=None, metavar="PEM", type=T.tsa_cert_arg,
                    help="pin a TSA certificate (or a CA above it) for the pack's token (repeatable; needs --pack)")
    ap.add_argument("--max-window", action=_Once, type=_entry_arg, metavar="SECONDS",
                    help="the widest window you accept between the pulse and the token's genTime (required with --pack)")
    ap.add_argument("--clock-tolerance", action=_Once, type=_entry_arg, metavar="SECONDS",
                    help="how far genTime may be before the pulse and still count as the same instant (default 0; needs --pack)")
    ap.add_argument("--tsa-crl", action="append", default=None, metavar="CRL", type=_nonempty,
                    help="a CRL you pin for the TSA certificate's revocation (repeatable; needs --pack)")
    ap.add_argument("--tsa-trusted-list", action=_Once, type=_nonempty, metavar="XML",
                    help="an EU Trusted List snapshot you pin: the window says 'qualified' only through it (needs --pack)")
    ap.add_argument("--checkpoint", action=_Once, type=_nonempty,
                    help="a checkpoint of this ledger cosigned by witnesses, a file of the pack (needs --pack): fixes the "
                         "entry at its position in the history the witnesses cosigned before genTime")
    ap.add_argument("--log-vkey", action="append", default=None, type=_nonempty,
                    help="the log key you trust for --checkpoint (repeatable)")
    ap.add_argument("--witness-vkey", action="append", default=None, type=_nonempty,
                    help="a witness key you trust for --checkpoint (repeatable)")
    ap.add_argument("--min-witnesses", action=_Once, type=_entry_arg, help="witness cosignatures required (default 1)")
    ap.add_argument("--currency-table", action=_Once, type=_nonempty, metavar="JSON",
                    help="an ISO 4217 table you pin (SPEC §18; tools/iso4217_table.py writes it from your download of list "
                         "one); without it the currency is checked by form only")
    ap.add_argument("--disclosure", action="append", default=None, metavar="JSON", type=_nonempty,
                    help="a disclosure {member, salt, value} to check against the entry's commitment (repeatable)")
    a = ap.parse_args(argv)
    if a.entry_file is None and (a.ledger is None or a.entry is None or a.proof is not None):
        ap.error("give the ledger and --entry, or --entry-file and --proof")
    if a.entry_file is not None and (a.ledger is not None or a.entry is not None or a.proof is None):
        ap.error("--entry-file goes with --proof, without a ledger or --entry")
    try:   # the library refuses options that do not go together, and a pinned CRL it cannot read: a usage error
        if a.entry_file is None:
            r = verify_beacon_entry(a.ledger, a.entry, a.pulse, a.previous, a.certificate, a.pack, a.tsa_cert,
                                    a.disclosure, a.max_window, a.tsa_crl, a.checkpoint, a.log_vkey, a.witness_vkey,
                                    a.min_witnesses, a.tsa_trusted_list, a.clock_tolerance, a.require_disclosure,
                                    a.currency_table)
        else:
            r = verify_beacon_entry_proof(a.entry_file, a.proof, a.pulse, a.previous, a.certificate, a.pack, a.tsa_cert,
                                          a.max_window, a.checkpoint, a.log_vkey, a.witness_vkey, a.disclosure,
                                          a.tsa_crl, a.min_witnesses, a.tsa_trusted_list, a.clock_tolerance,
                                          a.require_disclosure, a.currency_table)
    except ValueError as e:
        ap.error(str(e)[:200])
    emit(json.dumps(r, ensure_ascii=False, indent=1))
    return {"verified": 0, "refused": 2}.get(r["status"], 1)


if __name__ == "__main__":
    from verifier import receipt_cli
    raise SystemExit(receipt_cli(main)())
