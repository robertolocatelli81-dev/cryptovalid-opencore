#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Roberto Locatelli
"""
CryptoValid Open Core — self-assessment of a ledger against the eIDAS 2.0 QUALIFIED ELECTRONIC LEDGER rules.

Status: EXPERIMENTAL. Outside the maintained core of cryptovalid-opencore (README, "Core and experimental
modules"): kept, installed and tested, no new scope is added here.

The metre (read on 2026-09-13 from the Official Journal): Regulation (EU) 2024/1183 (eIDAS 2.0) introduces
"electronic ledgers" (Art. 3(52): "a sequence of electronic data records, ensuring the integrity of those
records and the accuracy of the chronological ordering of those records") and, for QUALIFIED ones, Art. 45l;
Commission Implementing Regulation (EU) 2025/2531 of 16 December 2025 (OJ L, 17.12.2025) lists the reference
standards: ETSI EN 319 401 with adaptations, and in particular
  REQ-7.5-04  unique sequential chronological ordering via cryptographic links (hash lists / hash trees) with
              SHA-256 or SHA3-256 or higher — or qualified timestamps when time recording is used;
  REQ-7.5-05  integrity via advanced electronic signatures/seals based on QUALIFIED certificates (SHA-256+),
              and "immediate detectability of any subsequent change";
  REQ-7.5-03  data origin via AdES on qualified certificates created by the USERS (CAdES / XAdES / JAdES,
              JAdES with the `x5c` header present);
  REQ-7.5-06  provider signing keys in a certified secure cryptographic device (CC EAL4+ / EUCC / FIPS 140-3 L3
              until 31.12.2030);
  Annex §2    a "ledger report" (structured presentation of verifiable information) produced automatically;
  REQ-6.1-12  an Electronic Ledger Practice Statement naming the ordering, origin, integrity and link mechanisms.

What this module does: measures, on a real ledger file, which of those requirements are met BY CONSTRUCTION
(hash chain, Merkle tree, SHA-256/SHA3-256, immediate detectability by full recompute), which are met only if
the deployment brings the qualified pieces (qualified certificates, QTSP timestamps, certified devices), and
which are out of a toolkit's reach (being a qualified trust service provider is a legal status, not code).
It then produces the automated LEDGER REPORT and a PRACTICE STATEMENT skeleton filled from what was measured.

Honest scope, stated once and in every output: CryptoValid is a toolkit, not a QTSP. The output is a
self-assessment for a provider preparing a conformity assessment — never a claim of qualification.
"""
from __future__ import annotations
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
import json
import os
import sys
from datetime import datetime, timezone
from typing import Dict, List, Optional

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import cryptovalid_merkle as M  # noqa: E402
import verifier as V  # noqa: E402

FONTI = {
    "eIDAS_2": "Regulation (EU) 2024/1183 (in force 20 May 2024): Art. 3(52) electronic ledger, Art. 45k legal effects, Art. 45l requirements",
    "IR_2025_2531": "Commission Implementing Regulation (EU) 2025/2531 of 16 December 2025 — reference standards and specifications for qualified electronic ledgers (OJ L, 17.12.2025); its Annex §3(a) applies ETSI EN 319 401 V3.1.1 'with adaptations'",
    "REQ_numbering": "the REQ-x.y-NN identifiers are ETSI EN 319 401's, as adapted/added by the Annex of IR 2025/2531 (e.g. REQ-7.5-03..06, REQ-6.1-12): cite 'IR 2025/2531, Annex, REQ-7.5-04' — not an article of the Regulation",
}


def _tsa_outcomes(entries, tsa_certs=None):
    """Counts of the entries' `tsa_token` by SPEC §11 (`cryptovalid_tsa.verify_token`, v0.6): {"present", "verified",
    "signature_only", "not_evaluated", "invalid"}. A token is checked against the entry's own `self_hash` (32 bytes, the
    algorithm the TSA was asked for is not fixed: the ledger's profile may be sha256 or sha3_256); `verified` needs
    `tsa_certs`, the TSA certificates the caller pins. A value that is not strict base64 of a token is `invalid`."""
    import base64
    import binascii
    n = {"present": 0, "verified": 0, "signature_only": 0, "not_evaluated": 0, "invalid": 0}
    try:
        import cryptovalid_tsa as T
    except Exception:  # noqa: BLE001
        T = None
    for e in entries:
        t = e.get("tsa_token")
        if t is None:
            continue
        n["present"] += 1
        sh = e.get("self_hash")
        if T is None:
            n["not_evaluated"] += 1
            continue
        try:
            if not isinstance(t, str) or not isinstance(sh, str):
                raise ValueError("not a string")
            der, digest = base64.b64decode(t, validate=True), bytes.fromhex(sh)
            if len(digest) != 32:
                raise ValueError("self_hash is not 32 bytes")
        except (binascii.Error, ValueError):
            n["invalid"] += 1
            continue
        n[T.verify_token(der, digest, None, tsa_certs)["status"]] += 1
    return n


def _tsa_tokens(entries, tsa_certs=None):
    """(present, bound): entries carrying `tsa_token`, and those whose token is `verified` by SPEC §11 against the pinned
    `tsa_certs` (without them none is: a signature valid with the certificate the token carries does not establish the
    TSA). Since 0.20.2 `tsa_token` is outside the canonical form (SPEC §3): anyone can add one to a signed ledger
    without breaking a hash or a signature, so presence is not a timestamp (until then this check counted presence);
    until 0.22.0 a CMS blob signed with any key, content = the OCTET STRING of `self_hash`, was "bound" (measured
    2026-11-13: SPEC §6, v0.6)."""
    n = _tsa_outcomes(entries, tsa_certs)
    return n["present"], n["verified"]


def _entries(path: str) -> List[Dict]:
    with open(path, encoding="utf-8") as f:
        return [json.loads(l) for l in f if l.strip()]


def assess(ledger_path: str, deployment: Optional[Dict] = None, tsa_certs=None) -> Dict:
    """`deployment` declares what the code cannot see: {"qualified_certificates": bool, "qtsp_timestamps": bool,
    "signing_device": "CC-EAL4"|"EUCC"|"FIPS140-3-L3"|"none"|"unknown", "provider_is_qtsp": bool}."""
    d = {"qualified_certificates": False, "qtsp_timestamps": False, "signing_device": "unknown", "provider_is_qtsp": False}
    d.update(deployment or {})
    snap = V.verify_ledger(ledger_path)
    entries = _entries(ledger_path)
    n = len(entries)
    signed = sum(1 for e in entries if e.get("signature") and e.get("signer"))
    firme_valide = None
    if signed:
        try:
            import signer as SG
            firme_valide = SG.verify_ledger_signatures(entries)
        except Exception as ex:  # noqa: BLE001 — senza cryptography: firme presenti ma NON verificate qui
            firme_valide = {"verified": None, "note": f"not verified: {type(ex).__name__}"}
    tok = _tsa_outcomes(entries, tsa_certs)
    present, stamped = tok["present"], tok["verified"]
    algo = snap.get("algorithm_used")
    # the verifier's VERDICT, not hash+link alone: idx (SPEC §5 step 4) and the closed schema (§2.1) are part of the chain
    # rule (0.20.0 review: a ledger without idx, or with a key nobody defined, was FAIL in verifier.py and SODDISFATTO here)
    chain_ok = snap.get("verdict") == "PASS"
    req = []

    def add(rid, titolo, stato, misura, cosa_manca=None):
        req.append({"req": rid, "titolo": titolo, "stato": stato, "misura": misura, **({"cosa_manca": cosa_manca} if cosa_manca else {})})

    # REQ-7.5-04 chronological ordering via cryptographic links
    add("REQ-7.5-04", "one sequential chronological ordering through cryptographic links (hash list / hash tree, SHA-256/SHA3-256+)",
        "SODDISFATTO_PER_COSTRUZIONE" if chain_ok and algo in ("sha256", "sha3_256") else "NON_SODDISFATTO",
        {"hash_list": "prev_hash -> self_hash on every record", "hash_tree": "RFC 6962/9162 Merkle (cryptovalid_merkle)",
         "algoritmo": algo, "catena_verificata": chain_ok, "idx_sequenziale": snap.get("idx_monotonic"),
         "ts_monotoni": snap.get("ts_monotonic"), "record": n})
    # REQ-7.5-05 integrity + immediate detectability
    if signed == n and n > 0:
        # un booleano dichiarato dal fornitore NON è una verifica (council 13/09): stato «DICHIARATO», mai «SODDISFATTO»
        stato = "DICHIARATO_NON_VERIFICATO" if d["qualified_certificates"] else "PARZIALE"
        manca = ("the qualified certificates are DECLARED by the provider, not inspected here (QcStatements, EUTL): the "
                 "conformity assessment body checks them" if d["qualified_certificates"] else
                 "Ed25519 signatures under the producer's key: NOT on a qualified certificate (AdES/QES needed)")
    else:
        stato, manca = "NON_SODDISFATTO", f"records signed {signed}/{n}: sign every record (signer.py) with a qualified certificate"
    add("REQ-7.5-05", "integrity of the records with advanced signatures/seals on qualified certificates; IMMEDIATE detection of any change",
        stato, {"record_firmati": signed, "totale": n, "firme_verificate": firme_valide,
                "rilevabilita_immediata": ("of the CONTENT: verifier recomputes every self_hash and every link, a change to the content is FAIL at the "
                                           "first check; of the attestation fields (signer/signature, outside the canonical form) only with "
                                           "signer.verify_ledger_signatures, run here when there are signatures"),
                "certificati_qualificati_dichiarati": d["qualified_certificates"]}, manca)
    # REQ-7.5-03 data origin by the users with AdES on qualified certificates
    add("REQ-7.5-03", "data origin: advanced signatures/seals on qualified certificates created by the USERS (CAdES/XAdES/JAdES with x5c)",
        "DICHIARATO_NON_VERIFICATO" if (signed == n and n > 0 and d["qualified_certificates"]) else "PARZIALE" if signed else "NON_SODDISFATTO",
        {"record_firmati_dal_produttore": signed, "formato": "Ed25519 over self_hash (+ JWS EdDSA through cryptovalid_jws, with x5c when given)"},
        None if d["qualified_certificates"] and signed == n else "a per-user signature on a qualified certificate in JAdES form (x5c present): cryptovalid_jws makes the JWS container, the user brings the qualified certificate")
    # REQ-7.5-04 alternative: qualified timestamps if time recording is used
    manca_tsa = None
    if stamped and not d["qtsp_timestamps"]:
        manca_tsa = "the RFC 3161 tokens present come from a TSA not declared qualified"
    elif tok["signature_only"] and not stamped:
        manca_tsa = (f"{tok['signature_only']} tokens whose signature is valid with the certificate in the token, chain not "
                     "established: pin the TSA certificate (--tsa-cert) to count them")
    add("REQ-7.5-04-bis", "when the chronological order relies on the recorded time: QUALIFIED time stamps",
        "DICHIARATO_NON_VERIFICATO" if d["qtsp_timestamps"] and stamped else "PARZIALE" if stamped else "NON_APPLICABILE",
        {"record_con_token_rfc3161": stamped, "record_con_campo_tsa_token": present, "qtsp_dichiarato": d["qtsp_timestamps"],
         "record_con_token_firma_senza_catena": tok["signature_only"], "record_con_token_non_valutato": tok["not_evaluated"],
         "record_con_token_non_valido": tok["invalid"], "certificato_tsa_fissato": bool(tsa_certs),
         "nota": "the order here is given by the cryptographic links (REQ-7.5-04); the time is additional evidence; a token counts "
                 "only when verified under the pinned TSA certificate (--tsa-cert; SPEC §11)"},
        manca_tsa)
    # REQ-7.5-06 device
    dev = d["signing_device"]
    add("REQ-7.5-06", "the provider's private signing keys in a certified secure cryptographic device (CC EAL4+/EUCC; FIPS 140-3 L3 until 31.12.2030)",
        "DICHIARATO_NON_VERIFICATO" if dev in ("CC-EAL4", "EUCC", "FIPS140-3-L3") else "NON_VALUTABILE" if dev == "unknown" else "NON_SODDISFATTO",
        {"dispositivo_dichiarato": dev, "supporto_codice": "cryptovalid_kms: KMS/HSM backend (PKCS#11); the certification is the device's, not the code's"},
        None if dev in ("CC-EAL4", "EUCC", "FIPS140-3-L3") else "declare/adopt a certified HSM; the key in a file (signer.py) does NOT meet the requirement")
    add("Art.45l(a)", "provider = QUALIFIED trust service provider (legal status, supervision, conformity audit)",
        "DICHIARATO_NON_VERIFICATO" if d["provider_is_qtsp"] else "FUORI_PORTATA_DEL_CODICE",
        {"provider_is_qtsp_dichiarato": d["provider_is_qtsp"]}, "a legal status: no software grants it or checks it")
    stati = [r["stato"] for r in req]
    return {"kind": "eidas_ledger_self_assessment/1", "generato_il": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "ledger": os.path.abspath(ledger_path), "fonti": FONTI, "requisiti": req,
            "riepilogo": {"soddisfatti_per_costruzione": stati.count("SODDISFATTO_PER_COSTRUZIONE"),
                          "dichiarati_non_verificati": stati.count("DICHIARATO_NON_VERIFICATO"),
                          "parziali": stati.count("PARZIALE"), "non_soddisfatti": stati.count("NON_SODDISFATTO"),
                          "non_valutabili": stati.count("NON_VALUTABILE") + stati.count("NON_APPLICABILE"),
                          "fuori_portata": stati.count("FUORI_PORTATA_DEL_CODICE")},
            "verdetto": ("qualified electronic ledger: NOT DEMONSTRATED by this tool; a self-assessment for whoever prepares "
                         "conformity: what holds by construction is measured, what the provider declares remains to be checked "
                         "by the conformity assessment body; CryptoValid is a toolkit, not a QTSP"),
            "confine": "never a claim of qualification: the qualified status is given by a QTSP and a conformity assessment body"}


def ledger_report(ledger_path: str, tsa_certs=None) -> Dict:
    """Annex §2: 'ledger report' = structured presentation of VERIFIABLE information, produced automatically."""
    snap = V.verify_ledger(ledger_path)
    entries = _entries(ledger_path)
    leaves = M.leaves_from_ledger(ledger_path)
    ts = [e.get("ts") for e in entries if e.get("ts")]
    return {"kind": "cryptovalid_ledger_report/1", "generato_il": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "ledger": os.path.abspath(ledger_path), "record": len(entries),
            "primo_ts": min(ts) if ts else None, "ultimo_ts": max(ts) if ts else None,
            "algoritmo": snap.get("algorithm_used"), "catena_ok": snap.get("verdict") == "PASS",
            "idx_sequenziale": snap.get("idx_monotonic"), "ts_monotoni": snap.get("ts_monotonic"),
            "record_firmati": sum(1 for e in entries if e.get("signature")), "record_con_marca_rfc3161": _tsa_tokens(entries, tsa_certs)[1],
            "tree_head": M.tree_head(leaves), "verdetto_verifier": snap.get("verdict"),
            "riproducibile": "same file, same report (except generato_il): a third party recomputes it with verifier.py and cryptovalid_merkle"}


def practice_statement(ledger_path: str, provider: str = "<provider>", deployment: Optional[Dict] = None,
                       tsa_certs=None) -> str:
    """REQ-6.1-12 skeleton, filled with the mechanisms actually measured. Markdown."""
    a = assess(ledger_path, deployment, tsa_certs)
    r = ledger_report(ledger_path)
    d = {"qualified_certificates": False, "qtsp_timestamps": False, "signing_device": "unknown"}
    d.update(deployment or {})
    lines = [f"# Electronic Ledger Practice Statement — {provider}",
             f"_Skeleton generated on {a['generato_il']} from `{os.path.basename(ledger_path)}` by CryptoValid; every mechanism below is the one measured, "
             "every «to be provided» is the provider's obligation, not the toolkit's._",
             "", "## Functional and technical capabilities (REQ-6.1-12 a)",
             f"- Append-only JSONL ledger, {r['record']} records, canonical JSON (sort_keys, compact separators), `{r['algoritmo']}` hashes.",
             "- Full re-verification by any third party with `verifier.py` (stdlib only); Merkle tree RFC 6962/9162 with inclusion and consistency proofs; receipts RFC 9942 (`cryptovalid_receipt`).",
             "", "## Data origin authentication mechanisms (REQ-6.1-12 b / REQ-7.5-03)",
             f"- Per-record Ed25519 signature by the producer key (`signer.py`), {r['record_firmati']}/{r['record']} records signed.",
             "- JWS (RFC 7515, EdDSA) container per record with `x5c` when a certificate is supplied (`cryptovalid_jws`).",
             f"- Qualified certificates for users' signatures: {'declared' if d['qualified_certificates'] else '**to be provided** (JAdES on qualified certificates)'}.",
             "", "## Sequential chronological ordering mechanisms (REQ-6.1-12 c / REQ-7.5-04)",
             f"- Hash list: `prev_hash` → `self_hash` on every record, index `idx` sequential ({'verified' if r['idx_sequenziale'] else 'NOT verified'}).",
             f"- Hash tree: Merkle root `{r['tree_head']['root_sha256'][:16]}…` over {r['tree_head']['tree_size']} leaves; consistency proofs prove append-only growth (`cryptovalid_monitor`).",
             f"- Time recording: RFC 3161 tokens on {r['record_con_marca_rfc3161']} records; qualified timestamps: {'declared' if d['qtsp_timestamps'] else '**to be provided** (QTSP on the EU Trusted List)'}.",
             "", "## Cryptographic link ensuring the sequence (REQ-6.1-12 d)",
             "- `prev_hash` = `self_hash` of the previous record (genesis: 64 zeros); Merkle node hashing per RFC 6962 (0x00 leaf / 0x01 node prefixes).",
             "", "## Consensus mechanism and finality (REQ-6.1-12 e)",
             "- Not applicable: single-writer ledger (no distributed consensus); finality = inclusion under a signed tree head and, optionally, an external anchor (RFC 3161 / OpenTimestamps / Solana).",
             "", "## Data integrity mechanisms (REQ-6.1-12 f / REQ-7.5-05)",
             "- Content-bound `self_hash` recomputed by the verifier; per-record signature over `self_hash`; any change is detected at the first verification (immediate detectability).",
             f"- Provider signing keys in a certified device (REQ-7.5-06): `{d['signing_device']}` — {'declared' if d['signing_device'] in ('CC-EAL4', 'EUCC', 'FIPS140-3-L3') else '**to be provided**'} (KMS/HSM backend supported by `cryptovalid_kms`).",
             "", "## Self-assessment summary", "",
             "| Requirement | Status |", "|---|---|"]
    for q in a["requisiti"]:
        lines.append(f"| {q['req']} — {q['titolo'][:70]}… | {q['stato']} |")
    lines += ["", f"**{a['verdetto']}**", "",
              "_Legend: SODDISFATTO_PER_COSTRUZIONE = measured on the ledger; DICHIARATO_NON_VERIFICATO = declared by the provider, "
              "to be verified by the conformity assessment body; PARZIALE / NON_SODDISFATTO / NON_VALUTABILE / FUORI_PORTATA_DEL_CODICE as named._"]
    return "\n".join(lines) + "\n"


try:   # 0.20.3: the one writer of every command (verifier.py): an outcome is written whole, or exit 74
    from verifier import Parser, emit, receipt_cli, say
except ImportError:   # python3 -m opencore.<module> from the parent directory
    from opencore.verifier import Parser, emit, receipt_cli, say


@receipt_cli
def main(argv: Optional[List[str]] = None) -> int:
    import argparse
    try:
        import cryptovalid_tsa as _T_arg
    except ImportError:   # python3 -m opencore.<module>
        from opencore import cryptovalid_tsa as _T_arg
    p = Parser(prog="eidas_ledger_check", description="self-assessment vs eIDAS 2.0 qualified electronic ledger rules (IR 2025/2531)")
    p.add_argument("ledger"); p.add_argument("--report", action="store_true"); p.add_argument("--practice-statement", action="store_true")
    p.add_argument("--provider", default="<provider>"); p.add_argument("--deployment", help="JSON: qualified_certificates, qtsp_timestamps, signing_device, provider_is_qtsp")
    p.add_argument("--tsa-cert", action="append", default=None, metavar="PEM", type=_T_arg.tsa_cert_arg,
                   help="pin the TSA certificate (or a CA above it), repeatable: a tsa_token counts only when verified "
                        "against it (SPEC §11)")
    a = p.parse_args(argv)
    dep = json.loads(a.deployment) if a.deployment else None
    if a.report:
        emit(json.dumps(ledger_report(a.ledger, a.tsa_cert), indent=1)); return 0
    if a.practice_statement:
        emit(practice_statement(a.ledger, a.provider, dep, a.tsa_cert)); return 0
    emit(json.dumps(assess(a.ledger, dep, a.tsa_cert), indent=1, ensure_ascii=False)); return 0


if __name__ == "__main__":
    raise SystemExit(main())
