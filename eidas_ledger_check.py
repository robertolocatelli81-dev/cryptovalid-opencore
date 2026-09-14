#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Roberto Locatelli
"""
CryptoValid Open Core — self-assessment of a ledger against the eIDAS 2.0 QUALIFIED ELECTRONIC LEDGER rules.

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
    "IR_2025_2531": "Commission Implementing Regulation (EU) 2025/2531 of 16 December 2025 — reference standards and specifications for qualified electronic ledgers (OJ L, 17.12.2025)",
    "ETSI_EN_319_401": "ETSI EN 319 401 V3.1.1 (2024-06) with the adaptations of the Annex (REQ-6.1-12, REQ-7.5-03..06)",
}


def _entries(path: str) -> List[Dict]:
    with open(path, encoding="utf-8") as f:
        return [json.loads(l) for l in f if l.strip()]


def assess(ledger_path: str, deployment: Optional[Dict] = None) -> Dict:
    """`deployment` declares what the code cannot see: {"qualified_certificates": bool, "qtsp_timestamps": bool,
    "signing_device": "CC-EAL4"|"EUCC"|"FIPS140-3-L3"|"none"|"unknown", "provider_is_qtsp": bool}."""
    d = {"qualified_certificates": False, "qtsp_timestamps": False, "signing_device": "unknown", "provider_is_qtsp": False}
    d.update(deployment or {})
    snap = V.verify_ledger(ledger_path)
    entries = _entries(ledger_path)
    n = len(entries)
    signed = sum(1 for e in entries if e.get("signature") and e.get("signer"))
    stamped = sum(1 for e in entries if e.get("tsa_token"))
    algo = snap.get("algorithm_used")
    chain_ok = bool(snap.get("hash_recompute_passed") and snap.get("link_passed"))
    req = []

    def add(rid, titolo, stato, misura, cosa_manca=None):
        req.append({"req": rid, "titolo": titolo, "stato": stato, "misura": misura, **({"cosa_manca": cosa_manca} if cosa_manca else {})})

    # REQ-7.5-04 chronological ordering via cryptographic links
    add("REQ-7.5-04", "ordinamento cronologico sequenziale unico via link crittografici (hash list / hash tree, SHA-256/SHA3-256+)",
        "SODDISFATTO_PER_COSTRUZIONE" if chain_ok and algo in ("sha256", "sha3_256") else "NON_SODDISFATTO",
        {"hash_list": "prev_hash → self_hash su ogni record", "hash_tree": "RFC 6962/9162 Merkle (cryptovalid_merkle)",
         "algoritmo": algo, "catena_verificata": chain_ok, "idx_sequenziale": snap.get("idx_monotonic"),
         "ts_monotoni": snap.get("ts_monotonic"), "record": n})
    # REQ-7.5-05 integrity + immediate detectability
    if signed == n and n > 0:
        # un booleano dichiarato dal fornitore NON è una verifica (council 13/09): stato «DICHIARATO», mai «SODDISFATTO»
        stato = "DICHIARATO_NON_VERIFICATO" if d["qualified_certificates"] else "PARZIALE"
        manca = ("i certificati qualificati sono DICHIARATI dal fornitore, non ispezionati qui (QcStatements, EUTL): li verifica "
                 "l'organismo di valutazione" if d["qualified_certificates"] else
                 "firme Ed25519 su chiave del produttore: NON su certificato qualificato (serve AdES/QES)")
    else:
        stato, manca = "NON_SODDISFATTO", f"record firmati {signed}/{n}: firmare ogni record (signer.py) con certificato qualificato"
    add("REQ-7.5-05", "integrità dei record con firme/sigilli avanzati su certificati qualificati; rilevabilità IMMEDIATA di ogni modifica",
        stato, {"record_firmati": signed, "totale": n, "rilevabilita_immediata": "verifier ricalcola ogni self_hash e ogni anello: una modifica è FAIL al primo controllo",
                "certificati_qualificati_dichiarati": d["qualified_certificates"]}, manca)
    # REQ-7.5-03 data origin by the users with AdES on qualified certificates
    add("REQ-7.5-03", "origine dei dati: firme/sigilli avanzati su certificati qualificati creati dagli UTENTI (CAdES/XAdES/JAdES con x5c)",
        "DICHIARATO_NON_VERIFICATO" if (signed == n and n > 0 and d["qualified_certificates"]) else "PARZIALE" if signed else "NON_SODDISFATTO",
        {"record_firmati_dal_produttore": signed, "formato": "Ed25519 su self_hash (+ JWS EdDSA via cryptovalid_jws, con x5c se fornito)"},
        None if d["qualified_certificates"] and signed == n else "firma per-utente su certificato qualificato in formato JAdES (x5c presente): cryptovalid_jws produce il contenitore JWS, il certificato qualificato lo porta l'utente")
    # REQ-7.5-04 alternative: qualified timestamps if time recording is used
    add("REQ-7.5-04-bis", "se l'ordine cronologico si affida al tempo registrato: marche temporali QUALIFICATE",
        "DICHIARATO_NON_VERIFICATO" if d["qtsp_timestamps"] and stamped else "PARZIALE" if stamped else "NON_APPLICABILE",
        {"record_con_token_rfc3161": stamped, "qtsp_dichiarato": d["qtsp_timestamps"],
         "nota": "l'ordine qui è garantito dai link crittografici (REQ-7.5-04); il tempo è evidenza aggiuntiva"},
        None if (d["qtsp_timestamps"] or not stamped) else "i token RFC 3161 presenti provengono da una TSA non dichiarata qualificata")
    # REQ-7.5-06 device
    dev = d["signing_device"]
    add("REQ-7.5-06", "chiavi private di firma del fornitore in dispositivo crittografico sicuro certificato (CC EAL4+/EUCC; FIPS 140-3 L3 fino al 31.12.2030)",
        "DICHIARATO_NON_VERIFICATO" if dev in ("CC-EAL4", "EUCC", "FIPS140-3-L3") else "NON_VALUTABILE" if dev == "unknown" else "NON_SODDISFATTO",
        {"dispositivo_dichiarato": dev, "supporto_codice": "cryptovalid_kms: backend KMS/HSM (PKCS#11) — la certificazione è del dispositivo, non del codice"},
        None if dev in ("CC-EAL4", "EUCC", "FIPS140-3-L3") else "dichiarare/adottare un HSM certificato; la chiave su file (signer.py) NON soddisfa il requisito")
    add("Art.45l(a)", "fornitore = prestatore di servizi fiduciari QUALIFICATO (status legale, vigilanza, audit di conformità)",
        "DICHIARATO_NON_VERIFICATO" if d["provider_is_qtsp"] else "FUORI_PORTATA_DEL_CODICE",
        {"provider_is_qtsp_dichiarato": d["provider_is_qtsp"]}, "uno status giuridico: nessun software lo conferisce né lo verifica")
    stati = [r["stato"] for r in req]
    return {"kind": "eidas_ledger_self_assessment/1", "generato_il": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "ledger": os.path.abspath(ledger_path), "fonti": FONTI, "requisiti": req,
            "riepilogo": {"soddisfatti_per_costruzione": stati.count("SODDISFATTO_PER_COSTRUZIONE"),
                          "dichiarati_non_verificati": stati.count("DICHIARATO_NON_VERIFICATO"),
                          "parziali": stati.count("PARZIALE"), "non_soddisfatti": stati.count("NON_SODDISFATTO"),
                          "non_valutabili": stati.count("NON_VALUTABILE") + stati.count("NON_APPLICABILE"),
                          "fuori_portata": stati.count("FUORI_PORTATA_DEL_CODICE")},
            "verdetto": ("qualified electronic ledger: NON DIMOSTRATO da questo strumento — autovalutazione per chi prepara la "
                         "conformità: ciò che è per costruzione è misurato, ciò che è dichiarato dal fornitore resta da verificare "
                         "dall'organismo di valutazione; CryptoValid è un toolkit, non un QTSP"),
            "confine": "mai un claim di qualificazione: lo stato qualificato lo danno un QTSP e un organismo di valutazione"}


def ledger_report(ledger_path: str) -> Dict:
    """Annex §2: 'ledger report' = structured presentation of VERIFIABLE information, produced automatically."""
    snap = V.verify_ledger(ledger_path)
    entries = _entries(ledger_path)
    leaves = M.leaves_from_ledger(ledger_path)
    ts = [e.get("ts") for e in entries if e.get("ts")]
    return {"kind": "cryptovalid_ledger_report/1", "generato_il": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "ledger": os.path.abspath(ledger_path), "record": len(entries),
            "primo_ts": min(ts) if ts else None, "ultimo_ts": max(ts) if ts else None,
            "algoritmo": snap.get("algorithm_used"), "catena_ok": bool(snap.get("hash_recompute_passed") and snap.get("link_passed")),
            "idx_sequenziale": snap.get("idx_monotonic"), "ts_monotoni": snap.get("ts_monotonic"),
            "record_firmati": sum(1 for e in entries if e.get("signature")), "record_con_marca_rfc3161": sum(1 for e in entries if e.get("tsa_token")),
            "tree_head": M.tree_head(leaves), "verdetto_verifier": snap.get("verdict"),
            "riproducibile": "stesso file → stesso report (tranne generato_il): un terzo lo ricalcola con verifier.py e cryptovalid_merkle"}


def practice_statement(ledger_path: str, provider: str = "<provider>", deployment: Optional[Dict] = None) -> str:
    """REQ-6.1-12 skeleton, filled with the mechanisms actually measured. Markdown."""
    a = assess(ledger_path, deployment)
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


def main(argv: Optional[List[str]] = None) -> int:
    import argparse
    p = argparse.ArgumentParser(prog="eidas_ledger_check", description="self-assessment vs eIDAS 2.0 qualified electronic ledger rules (IR 2025/2531)")
    p.add_argument("ledger"); p.add_argument("--report", action="store_true"); p.add_argument("--practice-statement", action="store_true")
    p.add_argument("--provider", default="<provider>"); p.add_argument("--deployment", help="JSON: qualified_certificates, qtsp_timestamps, signing_device, provider_is_qtsp")
    a = p.parse_args(argv)
    dep = json.loads(a.deployment) if a.deployment else None
    if a.report:
        print(json.dumps(ledger_report(a.ledger), indent=1)); return 0
    if a.practice_statement:
        print(practice_statement(a.ledger, a.provider, dep)); return 0
    print(json.dumps(assess(a.ledger, dep), indent=1, ensure_ascii=False)); return 0


if __name__ == "__main__":
    raise SystemExit(main())
