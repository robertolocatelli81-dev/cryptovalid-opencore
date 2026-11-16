#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""A "not before" bound from a public randomness beacon, inside a payment entry (SPEC v0.10 §18-§19, 16/11/2026).

Every time proof cryptovalid verified until v0.9 is an upper bound (an RFC 3161 token, a signed tip, a checkpoint).
A value that the NIST Randomness Beacon 2.0 published at T, carried inside a ledger entry whose self_hash also covers
the payment (identifier, amount, currency, and the parties' IBANs and names as 128-bit salted commitments: personal data
are never in clear, so they can be erased by destroying the salts outside the ledger), shows that the entry's bytes were
put together after T, for anyone but the beacon's operator. The beacon value is technical evidence, not a legal
timestamp. With the RFC 3161 token of an evidence pack that holds the ledger, the entry is
dated inside a window [T, genTime].

What is checked, offline, from the bytes the caller supplies: the ledger's chain (verifier.py, SPEC §5 steps 1-4); the
payment entry's closed profile (§18: ISO 4217 currency and its minor units, a payment identifier unique in the ledger,
the commitments' form; disclosures checked against the commitments, a disclosed IBAN by ISO 7064 MOD 97-10); the two NIST pulses (the named one and its
predecessor) in their closed grammar; the certificate the caller pins (SHA-512 of its DER = certificateId); each pulse's
RSA PKCS#1 v1.5 SHA-512 signature over the message the service deploys (4-byte length prefixes, measured on 16/11/2026:
not the draft NIST IR 8213's 8-byte ones); outputValue; the link and the period between the two pulses; the commitment
SHA-512(localRandomValue) = previous precommitmentValue; the entry's value = the pulse's outputValue. The window uses
evidence_pack.verify_pack with pinned TSA certificates (SPEC §10-§11) and optional pinned CRLs (§11 step 8), within a
maximum width the caller gives, reported as from a qualified TSA only through a pinned EU Trusted List snapshot
(cryptovalid_lotl). The entry is "the unique one" only under a checkpoint signed by a pinned log key and
cosigned by pinned witnesses (cryptovalid_witness.verify_witnessed, SPEC §19 rule 6): one pulse admits many records,
and one token can cover them all. The receipt's `scope` names what is proved and what is not, from a closed list.

Not checked: the certificate's chain and revocation (the pin is the trust); the hour/day/month/year list values; the
status flags other than 0 (refused, not evaluated); CURBy (not supported yet, SPEC §19). `cryptography` is needed for
RSA and X.509 only; without it the outcome is not_evaluated (backend_missing).

Command: cryptovalid-verify beacon <ledger> --entry <idx> --pulse <file> --previous <file> --certificate <file>
         [--pack <dir> --tsa-cert <pem> ... --max-window <s> [--tsa-crl <crl> ...] [--tsa-trusted-list <xml>]]
         [--checkpoint <note> --log-vkey <vkey> --witness-vkey <vkey> ... [--min-witnesses <n>]] [--disclosure <json> ...]
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
import stat
import tempfile
import unicodedata
from datetime import datetime, timedelta, timezone
from fractions import Fraction
from typing import Dict, List, Optional, Union

import verifier

PAYMENT_PROFILE = "cryptovalid-payment/1"
SOURCES = ("nist-beacon-2.0",)                     # SPEC §19: a closed list
# SPEC §18, in the order of its table: required, then the optional commitments
PAYMENT_REQUIRED = ("profile", "payment_id", "amount", "currency", "payer_iban_commitment", "payee_iban_commitment",
                    "beacon", "record_salt")
IBAN_COMMITMENTS = ("payer_iban_commitment", "payee_iban_commitment")
NAME_COMMITMENTS = ("payer_name_commitment", "payer_details_commitment", "payee_name_commitment")
COMMITMENTS = IBAN_COMMITMENTS + NAME_COMMITMENTS
PAYMENT_KEYS = PAYMENT_REQUIRED + NAME_COMMITMENTS
SALT_BYTES = 16   # SPEC §18: every commitment's salt is exactly 128 bits
BEACON_KEYS = frozenset({"source", "chain_index", "pulse_index", "output_value"})
DISCLOSURE_KEYS = frozenset({"member", "salt", "value"})
# SPEC §19 rule 7: the closed list of the receipt's scope sentences
SCOPE = {
    "composed_after_pulse": "the entry's bytes, with every member of the payment, were put together after the pulse's "
                            "timeStamp, for anyone but the beacon's operator",
    "stamped_before_gen_time": "the same bytes existed at the TSA's genTime",
    "stamped_by_qualified_tsa": "the TSA's certificate was a granted qualified timestamp service, at genTime, in the pinned "
                                "EU Trusted List snapshot",
    "unique_under_pinned_witness": "the entry is the one at its position in the history the pinned witnesses cosigned",
    "not_execution": "that a payment service provider executed the payment",
    "not_unique": "that this is the only entry composed after that pulse",
    "not_ownership": "that the IBANs belong to the parties",
    "not_operator": "anything against the beacon's operator beyond its freshness promise",
    "not_qualified": "that the upper bound is a qualified electronic time stamp",
    "not_legal_beacon": "that the beacon value is a legal timestamp: it is technical evidence of not before",
}
# ISO 4217 list one, as published by its maintenance agency (SIX) on 2026-09-17, fetched on 2026-11-16 from
# six-group.com (list-one.xml, sha256 33139b438657d1cee116ba737807ea71d19d6de4b90f799a09c56f0cc6a1b0ff): the 165
# alphabetic codes whose minor units are a number, by minor units. The 13 codes with "N.A." are not accepted (SPEC §18).
_ISO4217 = {
    0: "BIF CLP DJF GNF ISK JPY KMF KRW PYG RWF UGX UYI VND VUV XAF XOF XPF",
    2: "AED AFN ALL AMD AOA ARS AUD AWG AZN BAM BBD BDT BMD BND BOB BOV BRL BSD BTN BWP BYN BZD CAD CDF CHE CHF CHW CNY "
       "COP COU CRC CUP CVE CZK DKK DOP DZD EGP ERN ETB EUR FJD FKP GBP GEL GHS GIP GMD GTQ GYD HKD HNL HTG HUF IDR ILS "
       "INR IRR JMD KES KGS KHR KPW KYD KZT LAK LBP LKR LRD LSL MAD MDL MGA MKD MMK MNT MOP MRU MUR MVR MWK MXN MXV MYR "
       "MZN NAD NGN NIO NOK NPR NZD PAB PEN PGK PHP PKR PLN QAR RON RSD RUB SAR SBD SCR SDG SEK SGD SHP SLE SOS SRD SSP "
       "STN SVC SYP SZL THB TJS TMT TOP TRY TTD TWD TZS UAH USD USN UYU UZS VED VES WST XAD XCD XCG YER ZAR ZMW ZWG",
    3: "BHD IQD JOD KWD LYD OMR TND",
    4: "CLF UYW",
}
MINOR_UNITS = {c: n for n, codes in _ISO4217.items() for c in codes.split()}
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
U32 = 2 ** 32 - 1

_HEX128 = re.compile(r"[0-9a-fA-F]{128}")
_SIG = re.compile(r"(?:[0-9a-fA-F]{2}){1,1024}")
_TIME = re.compile(r"([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})\.([0-9]{3})Z")
_GEN_TIME = re.compile(r"([0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2})(?:\.([0-9]+))?Z")
_AMOUNT = re.compile(r"(0|[1-9][0-9]{0,17})(?:\.([0-9]+))?")
# SPEC §18: ISO 20022 Max35Text with the Latin set used for EndToEndId (to be re-read against the EPC guidance)
_PAYMENT_ID = re.compile(r"[A-Za-z0-9/?:().,'+-](?:[A-Za-z0-9/?:().,'+ -]{0,33}[A-Za-z0-9/?:().,'+-])?")
_SHA256_HEX = re.compile(r"[0-9a-f]{64}")
_SALT_HEX = re.compile(r"[0-9a-f]{32}")
_RECORD_SALT = re.compile(r"(?:[0-9a-f]{2}){16,64}")   # SPEC §18: 16 to 64 bytes, at least 128 bits
_IBAN_CHARS = re.compile(r"[A-Z0-9]+")
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


def check_payment(data) -> Dict:
    """SPEC §18: a payment entry's `data`, closed. Returns it; Refused('payment_malformed', '<member>: <reason>')
    otherwise, Refused('entry_not_a_payment') when `profile` is not this profile's, Refused('source_not_supported') for
    a beacon of another source (SPEC §19)."""
    def bad(member, why):
        raise Refused("payment_malformed", f"{member}: {why}")
    if not isinstance(data, dict) or data.get("profile") != PAYMENT_PROFILE:
        raise Refused("entry_not_a_payment", f"data.profile is not {PAYMENT_PROFILE!r}")
    unknown = sorted(set(data) - set(PAYMENT_KEYS))
    if unknown:
        bad(",".join(unknown), "member_unknown")
    missing = [k for k in PAYMENT_REQUIRED if k not in data]
    if missing:
        bad(",".join(missing), "member_missing")
    if not (isinstance(data["payment_id"], str) and _PAYMENT_ID.fullmatch(data["payment_id"])):
        bad("payment_id", "not 1 to 35 characters of the Max35Text Latin set, no leading or trailing space")
    c = data["currency"]
    if not isinstance(c, str) or c not in MINOR_UNITS:
        bad("currency", "currency_unknown")
    a = data["amount"]
    m = _AMOUNT.fullmatch(a) if isinstance(a, str) else None
    if m is None:
        bad("amount", "not a decimal string")
    frac = m.group(2) or ""
    if len(frac) > MINOR_UNITS[c]:   # with 0 minor units "1." is not a decimal string and "1.0" has one digit too many
        bad("amount", f"too_many_decimals (the minor units of {c} are {MINOR_UNITS[c]})")
    if int(m.group(1)) == 0 and int(frac or "0") == 0:
        bad("amount", "not greater than zero")
    if not (isinstance(data["record_salt"], str) and _RECORD_SALT.fullmatch(data["record_salt"])):
        bad("record_salt", "not 32 to 128 lowercase hexadecimal characters, an even number (at least 128 bits)")
    for k in COMMITMENTS:
        if k in data and not (isinstance(data[k], str) and _SHA256_HEX.fullmatch(data[k])):
            bad(k, "not 64 lowercase hexadecimal characters")
    b = data["beacon"]
    if not isinstance(b, dict):
        bad("beacon", "not an object")
    if set(b) != BEACON_KEYS:
        bad("beacon", "members are not exactly " + ",".join(sorted(BEACON_KEYS)))
    if not isinstance(b["source"], str):
        bad("beacon.source", "not a string")
    if b["source"] not in SOURCES:
        raise Refused("source_not_supported", f"beacon.source {b['source'][:80]!r}")
    if not (type(b["chain_index"]) is int and b["chain_index"] >= 0):
        bad("beacon.chain_index", "not an integer >= 0")
    if not (type(b["pulse_index"]) is int and b["pulse_index"] >= 1):
        bad("beacon.pulse_index", "not an integer >= 1")
    if not (isinstance(b["output_value"], str) and _HEX128.fullmatch(b["output_value"])):
        bad("beacon.output_value", "not 128 hexadecimal characters")
    return data


COMMITMENT_DOMAIN = b"cryptovalid-payment/1/"


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
    return unicodedata.normalize("NFC", value)


def commitment(member: str, salt: bytes, value: str) -> str:
    """SPEC §18: SHA-256("cryptovalid-payment/1/" || member || 0x00 || salt (16 bytes) || UTF-8(normalised value))"""
    if not (isinstance(salt, (bytes, bytearray)) and len(salt) == SALT_BYTES):
        raise ValueError(f"salt: {SALT_BYTES} bytes")
    v = normalised(member, value)
    return hashlib.sha256(COMMITMENT_DOMAIN + member.encode("ascii") + b"\x00" + bytes(salt) + v.encode("utf-8")).hexdigest()


def parse_disclosure(src) -> Dict:
    """SPEC §18: {"member", "salt" (32 lowercase hex), "value"}, closed; Refused('disclosure_malformed') otherwise"""
    try:
        d = _json(_read(src, "disclosure", MAX_PULSE), "disclosure")
    except Refused as e:
        raise Refused("disclosure_malformed", e.detail or e.reason) from None
    if not (isinstance(d, dict) and set(d) == DISCLOSURE_KEYS and d["member"] in COMMITMENTS
            and isinstance(d["salt"], str) and _SALT_HEX.fullmatch(d["salt"])
            and isinstance(d["value"], str) and 1 <= len(d["value"]) <= 1024):
        raise Refused("disclosure_malformed", "not {member: a commitment member, salt: 32 lowercase hex, value: 1 to "
                                              "1024 characters}")
    return d


# ───────────────────────────────────────────── SPEC §19 rule 2: a NIST pulse, closed

def _read(src: Union[str, bytes, bytearray], what: str, limit: int) -> bytes:
    if isinstance(src, (bytes, bytearray)):
        b = bytes(src)
    elif isinstance(src, str) and src:
        try:
            st = os.stat(src)
            if not stat.S_ISREG(st.st_mode):
                raise Refused("input_unreadable", f"{what}: not a regular file")
            with open(src, "rb") as f:
                b = f.read(limit + 1)
        except OSError as e:
            raise Refused("input_unreadable", f"{what}: {e.strerror or e}") from None
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


def _certificate(src):
    """the pinned certificate (PEM holding exactly one, or DER): (cryptography certificate, DER bytes)"""
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    b = _read(src, "certificate", MAX_CERT)
    try:
        if b.count(b"-----BEGIN") or b.count(b"-----END"):
            if b.count(b"-----BEGIN CERTIFICATE-----") != 1 or b.count(b"-----BEGIN") != 1:
                raise ValueError("a PEM file holding exactly one certificate")
            cert = x509.load_pem_x509_certificate(b)
        else:
            cert = x509.load_der_x509_certificate(b)
        der = cert.public_bytes(serialization.Encoding.DER)
    except ValueError as e:
        raise Refused("certificate_malformed", str(e)[:120]) from None
    return cert, der


def check_pulses(beacon: Dict, pulse: Dict, prev: Dict, cert_src) -> Dict:
    """SPEC §19 steps 1-9 for the entry's `beacon`, the named pulse and its predecessor (both parsed by parse_pulse).
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
    cert, der = _certificate(cert_src)                                             # step 4
    if hashlib.sha512(der).digest() != bytes.fromhex(pulse["certificateId"]):
        raise Invalid("certificate_mismatch", "SHA-512 of the pinned certificate is not certificateId")
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
        raise Invalid("beacon_value_mismatch", "the entry's beacon.output_value is not the pulse's outputValue")
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


def window(t: datetime, period_ms: int, gen_time: str, max_window_s: int) -> Dict:
    """SPEC §19 rule 5: [T, genTime]; Invalid('window_inverted') when genTime < T, Invalid('window_too_wide') when
    genTime - T > max_window_s (the caller's maximum width, seconds)"""
    if gen_time_instant(gen_time) < _instant(t):
        raise Invalid("window_inverted", f"token genTime {gen_time} is before the pulse's {_iso(t)}")
    if gen_time_instant(gen_time) - _instant(t) > max_window_s:
        raise Invalid("window_too_wide", f"genTime {gen_time} is more than {max_window_s} s after the pulse's {_iso(t)}")
    return {"not_before": _iso(t), "not_after": gen_time,
            "not_before_operator_promise": _iso(t - timedelta(milliseconds=period_ms))}


# ───────────────────────────────────────────── the entry, the ledger, the pack

def _entries(ledger_bytes: bytes) -> List[Dict]:
    """the entries of a ledger that passes SPEC §5 steps 1-4 (Invalid('ledger_invalid') otherwise)"""
    fd, tmp = tempfile.mkstemp(prefix="cv-beacon-", suffix=".jsonl")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(ledger_bytes)
        r = verifier.verify_ledger(tmp)   # a private copy: no <path>.tip.json beside it
    finally:
        os.unlink(tmp)
    if r.get("verdict") != "PASS":
        raise Invalid("ledger_invalid", f"verdict {r.get('verdict')}")
    return [verifier._loads_strict(line) for line in ledger_bytes.decode("utf-8").split("\n") if line.strip(" \t\r")]


def _qualification(tsr_b64: str, signer_sha256: str, gen_time: str, trusted_list) -> str:
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
    return L.qualification(base64.b64decode(tsr_b64), st["granted"], st["errors"], signer_sha256)[0]


def _pack_window(pack_dir: str, tsa_certs, tsa_crls, max_window_s: int, ledger_bytes: bytes, beacon: Dict,
                 trusted_list=None) -> Dict:
    import evidence_pack
    r = evidence_pack.verify_pack(pack_dir, tsa_certs=tsa_certs, tsa_crls=tsa_crls)
    st = r.get("states") or {}
    if not (r.get("admission") == "admitted" and (st.get("sealed_content") or {}).get("state") == "verified"):
        raise Invalid("pack_not_valid", str(r.get("error") or (st.get("sealed_content") or {}).get("reasons"))[:160])
    if (st.get("time_anchor") or {}).get("state") != "verified":
        ta = st.get("time_anchor") or {}
        raise Invalid("time_anchor_not_verified", f"{ta.get('state')} {ta.get('reasons')} {ta.get('detail') or ''}"[:200])
    if r.get("valid") is not True:
        raise Invalid("pack_not_valid", "the pack's verify answers valid: false")
    man = verifier._loads_strict(_read(os.path.join(pack_dir, "MANIFEST.json"), "MANIFEST.json", MAX_LEDGER).decode("utf-8"))
    digest = hashlib.sha256(ledger_bytes).hexdigest()
    leds = [lm for lm in man["ledgers"] if man["file_digests_sha256"].get(lm["file"]) == digest
            and r["file_ok"].get(lm["file"]) is True]
    if not leds:
        raise Invalid("ledger_not_in_pack", "no ledger of the pack has these bytes")
    gt = (r.get("rfc3161") or {}).get("tsa_check", {}).get("gen_time")
    w = window(beacon["_t"], beacon["period_ms"], gt, max_window_s)
    chk = r["rfc3161"]["tsa_check"]
    w.update({"max_window_s": max_window_s, "pack_ledger": leds[0]["file"], "tsa_signer_sha256": chk.get("signer_sha256"),
              "tsa_revocation": chk["revocation"] if tsa_crls is not None else "not_checked",
              "tsa_qualification": "not_checked" if trusted_list is None else
              _qualification(man["rfc3161_timestamp"]["tsr_b64"], chk.get("signer_sha256"), gt, trusted_list)})
    return w


def _witnessed(checkpoint, log_vkeys: List[str], witness_vkeys: List[str], min_witnesses: int, entries: List[Dict],
               entry_idx: int) -> Dict:
    """SPEC §19 rule 6: the entry under a checkpoint signed by a pinned log key and cosigned by pinned witnesses"""
    import base64
    import cryptovalid_checkpoint as C
    import cryptovalid_merkle as M
    import cryptovalid_witness as W
    try:
        note = C.read_note_file(checkpoint) if isinstance(checkpoint, str) else bytes(checkpoint)
        v = W.verify_witnessed(note, log_vkeys, witness_vkeys, min_witnesses)
    except (C.NoteError, OSError, TypeError) as e:
        raise Refused("checkpoint_malformed", str(e)[:160]) from None
    if v["stato"] == "NON_VERIFICATA":
        raise ImportError(v["motivo"])
    if v["stato"] != "OK":
        raise Invalid("checkpoint_not_witnessed", str(v["motivo"])[:160])
    size, root = v["checkpoint"]["size"], base64.b64decode(v["checkpoint"]["root"])
    if size <= entry_idx:
        raise Invalid("checkpoint_not_covering_entry", f"checkpoint size {size}, entry {entry_idx}")
    leaves = [M.canonical(e) for e in entries]
    if size > len(leaves) or M.mth(leaves[:size]) != root:
        raise Invalid("checkpoint_root_mismatch", f"the root of the first {size} entries of this ledger is not the checkpoint's")
    return {"status": "witnessed", "witnesses": v["witnesses"], "checkpoint_size": size,
            "origin": v["checkpoint"]["origin"]}


def _scope(window_ok: bool, unique_ok: bool, qualified: bool = False) -> Dict:
    proves = ["composed_after_pulse"] + (["stamped_before_gen_time"] if window_ok else []) \
        + (["stamped_by_qualified_tsa"] if qualified else []) + (["unique_under_pinned_witness"] if unique_ok else [])
    not_proved = ["not_execution"] + ([] if unique_ok else ["not_unique"]) + ["not_ownership", "not_operator"] \
        + ([] if qualified else ["not_qualified"]) + ["not_legal_beacon"]
    return {"proves": [{k: SCOPE[k]} for k in proves], "does_not_prove": [{k: SCOPE[k]} for k in not_proved]}


def _bounds(b: Dict) -> Dict:
    t = b["_t"]
    return {"not_before": _iso(t), "holds_against": "anyone but the beacon operator (NIST IR 8213 draft §3.3, promises 1-2)",
            "not_before_operator_promise": _iso(t - timedelta(milliseconds=b["period_ms"])),
            "operator_promise": "only if the operator kept its freshness promise (§3.3, promise 3); not checked",
            "against_an_operator_breaking_its_promises": None}


def verify_beacon_entry(ledger, entry_idx: int, pulse, previous, certificate,
                        pack_dir: Optional[str] = None, tsa_certs: Optional[List] = None,
                        disclosures: Optional[List] = None, max_window_s: Optional[int] = None,
                        tsa_crls: Optional[List] = None, checkpoint=None, log_vkeys: Optional[List[str]] = None,
                        witness_vkeys: Optional[List[str]] = None, min_witnesses: Optional[int] = None,
                        tsa_trusted_list=None) -> Dict:
    """SPEC §19: the receipt for entry `entry_idx` of `ledger` (path or bytes). `pulse`, `previous`, `certificate`:
    paths or bytes. With `pack_dir` (and `tsa_certs`, required with it) the window with the pack's token.
    `disclosures`: paths or bytes of SPEC §18 disclosures, each checked against the entry's commitment it names.
    `max_window_s` (required with `pack_dir`): the maximum width of the window, seconds. `tsa_crls`: CRLs pinned for the
    TSA (SPEC §11 step 8). `tsa_trusted_list` (path or bytes): a pinned EU Trusted List snapshot that decides whether the
    TSA is qualified (SPEC §19 rule 5). `checkpoint` (path or bytes) with `log_vkeys` and `witness_vkeys` (and `min_witnesses`,
    default 1): the witnessed checkpoint of SPEC §19 rule 6.
    Never raises on the inputs: status refused / invalid / not_evaluated / verified. A check that cannot run here
    (openssl, SPEC §10) raises verifier.CheckNotRun."""
    if type(entry_idx) is not int or entry_idx < 0:
        raise ValueError("entry_idx: an integer >= 0")
    if (pack_dir is None) != (tsa_certs is None):
        raise ValueError("pack_dir and tsa_certs go together: the window needs a token checked with pinned certificates")
    if (pack_dir is None) != (max_window_s is None):
        raise ValueError("pack_dir and max_window_s go together: the caller says how wide a fresh window may be")
    if max_window_s is not None and (type(max_window_s) is not int or max_window_s < 0):
        raise ValueError("max_window_s: an integer >= 0 (seconds)")
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
    if min_witnesses is not None and (checkpoint is None or type(min_witnesses) is not int or min_witnesses < 1):
        raise ValueError("min_witnesses: an integer >= 1, with a checkpoint")
    out = {"kind": "beacon", "status": None, "reason": None, "detail": "", "valid": False, "record_complete": False,
           "entry": None, "pulse": None, "bounds": None, "window": None, "unique": {"status": "not_established"},
           "disclosed": [], "scope": None}
    try:
        lb = _read(ledger, "ledger", MAX_LEDGER)   # bytes that are not UTF-8 FAIL verify_ledger (SPEC §3): ledger_invalid
        entries = _entries(lb)
        found = [x for x in entries if x.get("idx") == entry_idx]
        if not found:
            raise Invalid("entry_not_found", f"no entry {entry_idx}")
        e = found[0]
        data = check_payment(e.get("data"))
        same = [x["idx"] for x in entries if isinstance(x.get("data"), dict)
                and x["data"].get("profile") == PAYMENT_PROFILE and x["data"].get("payment_id") == data["payment_id"]]
        if len(same) > 1:
            raise Invalid("payment_id_not_unique", f"payment_id also in entries {[i for i in same if i != entry_idx][:10]}")
        ds = [parse_disclosure(d) for d in (disclosures or [])]
        if len({d["member"] for d in ds}) != len(ds):
            raise Refused("disclosure_malformed", "two disclosures for one member")
        out["entry"] = {"idx": entry_idx, "self_hash": e["self_hash"], "covers": [k for k in PAYMENT_KEYS if k in data],
                        "payment": {k: data[k] for k in ("payment_id", "amount", "currency")}}
        for d in ds:
            try:
                c = commitment(d["member"], bytes.fromhex(d["salt"]), d["value"])
            except ValueError as e:   # parse_disclosure checked member, salt and value: only the IBAN rule is left
                raise Invalid("disclosure_iban_invalid", f"{d['member']}: {e}") from None
            if data.get(d["member"]) != c:
                raise Invalid("disclosure_mismatch", f"{d['member']}: the disclosed salt and value do not give the entry's commitment")
            out["disclosed"].append(d["member"])
        p = parse_pulse(pulse, "pulse")
        q = parse_pulse(previous, "previous")
        try:
            b = check_pulses(data["beacon"], p, q, certificate)
        except ImportError as ie:
            out.update(status="not_evaluated", reason="backend_missing", detail=f"cryptography: {ie}"[:160])
            return out
        out["pulse"] = {k: v for k, v in b.items() if not k.startswith("_")}
        out["bounds"] = _bounds(b)
        out["scope"] = _scope(False, False)
        if pack_dir is not None:
            out["window"] = _pack_window(pack_dir, tsa_certs, tsa_crls, max_window_s, lb, b, tsa_trusted_list)
        if checkpoint is not None:
            try:
                out["unique"] = _witnessed(checkpoint, list(log_vkeys), list(witness_vkeys), min_witnesses or 1,
                                           entries, entry_idx)
            except ImportError as ie:
                out.update(status="not_evaluated", reason="backend_missing", detail=f"checkpoint: {ie}"[:160])
                return out
        unique = out["unique"]["status"] == "witnessed"
        out["scope"] = _scope(out["window"] is not None, unique,
                              (out["window"] or {}).get("tsa_qualification") == "qualified")
        out.update(status="verified", valid=True, record_complete=out["window"] is not None and unique)
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
    ap.add_argument("ledger", type=_nonempty, help="the ledger (.jsonl) holding the payment entry")
    ap.add_argument("--entry", required=True, action=_Once, type=_entry_arg, help="idx of the payment entry to date")
    ap.add_argument("--pulse", required=True, action=_Once, type=_nonempty,
                    help="the pulse the entry names, as served by /beacon/2.0/chain/<c>/pulse/<i>")
    ap.add_argument("--previous", required=True, action=_Once, type=_nonempty, help="the pulse before it (commitment)")
    ap.add_argument("--certificate", required=True, action=_Once, type=_nonempty,
                    help="the beacon's certificate you pin (PEM with one certificate, or DER)")
    ap.add_argument("--pack", action=_Once, type=_nonempty, help="evidence pack holding the ledger: gives the window")
    ap.add_argument("--tsa-cert", action="append", default=None, metavar="PEM", type=T.tsa_cert_arg,
                    help="pin a TSA certificate (or a CA above it) for the pack's token (repeatable; needs --pack)")
    ap.add_argument("--max-window", action=_Once, type=_entry_arg, metavar="SECONDS",
                    help="the widest window you accept between the pulse and the token's genTime (required with --pack)")
    ap.add_argument("--tsa-crl", action="append", default=None, metavar="CRL", type=_nonempty,
                    help="a CRL you pin for the TSA certificate's revocation (repeatable; needs --pack)")
    ap.add_argument("--tsa-trusted-list", action=_Once, type=_nonempty, metavar="XML",
                    help="an EU Trusted List snapshot you pin: the window says 'qualified' only through it (needs --pack)")
    ap.add_argument("--checkpoint", action=_Once, type=_nonempty,
                    help="a checkpoint of this ledger cosigned by witnesses: establishes that the entry is the unique one")
    ap.add_argument("--log-vkey", action="append", default=None, type=_nonempty,
                    help="the log key you trust for --checkpoint (repeatable)")
    ap.add_argument("--witness-vkey", action="append", default=None, type=_nonempty,
                    help="a witness key you trust for --checkpoint (repeatable)")
    ap.add_argument("--min-witnesses", action=_Once, type=_entry_arg, help="witness cosignatures required (default 1)")
    ap.add_argument("--disclosure", action="append", default=None, metavar="JSON", type=_nonempty,
                    help="a disclosure {member, salt, value} to check against the entry's commitment (repeatable)")
    a = ap.parse_args(argv)
    try:   # the library refuses options that do not go together, and a pinned CRL it cannot read: a usage error
        r = verify_beacon_entry(a.ledger, a.entry, a.pulse, a.previous, a.certificate, a.pack, a.tsa_cert, a.disclosure,
                                a.max_window, a.tsa_crl, a.checkpoint, a.log_vkey, a.witness_vkey, a.min_witnesses,
                                a.tsa_trusted_list)
    except ValueError as e:
        ap.error(str(e)[:200])
    emit(json.dumps(r, ensure_ascii=False, indent=1))
    return {"verified": 0, "refused": 2}.get(r["status"], 1)


if __name__ == "__main__":
    from verifier import receipt_cli
    raise SystemExit(receipt_cli(main)())
