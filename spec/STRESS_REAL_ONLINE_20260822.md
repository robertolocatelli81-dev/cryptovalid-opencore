<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# Evidenza — Stress test totale ONLINE con dati reali (2026-08-22T11:30Z)

Eseguito **prima** della nomina DPG per dimostrare che OMEGA + CryptoValid funzionano end-to-end con **dati
reali e ancore esterne live**, e che il sistema **sa fallire** (il controllo positivo precede le misure).

## Metodo
- **Prima dimostra di saper FALLIRE** (guardia anti-timbro): un ledger manomesso DEVE dare verdetto FAIL,
  altrimenti tutti i PASS successivi non valgono.
- **SKIP ≠ verde finto**: una risorsa di rete non disponibile è SKIP dichiarato, mai un PASS.
- Scritture in sandbox (`/tmp`), zero modifiche al sistema.

## Risultati (tutti verdi; zero fallimenti reali)

### A. Backbone deterministico
| Prova | Esito |
|---|---|
| **Controllo positivo** — ledger intatto=`0`, manomesso=`FAIL` | **PASS** (sa fallire) |
| Suite `opencore` completa | **PASS 27/27** |
| OMEGA lato-sistema (`tests/stress_total_real_online.py`) | **PASS 8/8** — connettori reali fx/crypto/macro/equities, brain, fintech sotto carico, concorrenza 603 op/s, determinismo bit-identico, resilienza a fonte-giù |
| Moduli sessione 2026-08-22 (longterm_evidence, vdf_timeanchor, longterm_hashbased, pedersen_commit, cldma_confidential, qraft_credit_quadrature) | **PASS 6/6** |

### B. Ancore ESTERNE ONLINE — verificate dal vivo
| Ancora | Esito reale |
|---|---|
| **RFC 3161** — timestamp qualificato via **freeTSA** | **PASS** — `verified=True, granted=True, imprint_ok=True` |
| **OpenTimestamps → Bitcoin** — calendar server reali | **PASS** — **3/3 calendar** committed (stato `pending-bitcoin`) |
| **Solana mainnet-beta** — pin del genesis + controllo negativo | **PASS** — cluster falso **rifiutato**; genesis reale `5eykt4UsFv8P8NJdTREp…` **combacia col pin** |

### C. Finanza — TUTTI i moduli finanziari (richiesta Roberto "fallo per tutto quello che riguarda la finanza")
**17 PASS · 0 FAIL · 1 SKIP onesto.**
| Area | Esito |
|---|---|
| Suite finance deterministiche (fundcert, microfinance, CLDMA, cldma_confidential, pedersen, ap2_evidence, tx_evidence, dora_incident, qeas, qraft_credit, eba_stress, fintech_m1_m2, omega_fintech_platform) | **PASS 13/13** |
| **Controllo positivo** fundcert — vettore `tampered_content` | **PASS** (rifiutato, rc≠0) |
| **Controllo positivo** CLDMA — PAR30 impossibile (200%) | **PASS** (guardia lo rifiuta) |
| tx_evidence — verificatori presenti (`verify_attestation`, `verify_chain`) | **PASS** |
| **SEC EDGAR LIVE** — dati finanziari reali (Apple Total Assets, 146 valori trimestrali, 10-Q 2026-06-27, $383.266B) → integrità CryptoValid | **PASS** — digest riproducibile + **manomissione da 1 USD rilevata** |
| iShares IVV holdings CSV (pull live) | **SKIP** — endpoint dietro bot-wall (HTML invece di CSV); non un difetto di fundcert. Validazione reale documentata su **SEC N-PORT/N-CSR + KIVA + MIX** (`spec/REAL_DATA_VALIDATION_*`, `PREREG_KIVA_20260820.md`) |

## Comandi riproducibili
```bash
# backbone opencore (deterministico)
cd opencore && for t in test_*.py; do python3 "$t"; done
# OMEGA lato-sistema online
python3 tests/stress_total_real_online.py
# gate di manomissione (deve fallire)
cd opencore && python3 verifier.py examples/sample_ledger_tampered.jsonl   # -> exit != 0
# ancora RFC 3161 reale
python3 -c "import sys;sys.path.insert(0,'opencore');import evidence_pack as E,hashlib,time;\
d=hashlib.sha256(str(time.time()).encode()).hexdigest();\
r=E._rfc3161_stamp(d,'https://freetsa.org/tsr',25);print(E._verify_rfc3161(r['tsr_b64'],d,25))"
# ancora Solana mainnet (genesis reale)
python3 -c "import json,urllib.request;print(json.loads(urllib.request.urlopen(\
urllib.request.Request('https://api.mainnet-beta.solana.com',\
data=json.dumps({'jsonrpc':'2.0','id':1,'method':'getGenesisHash'}).encode(),\
headers={'Content-Type':'application/json'}),timeout=15).read())['result'])"
```

## Honest-scope
- Le ancore sono **raggiunte e verificate ora**, ma **network-dipendenti**: offline darebbero **SKIP** onesto.
- OTS è **`pending-bitcoin`**: l'impegno del calendar è immediato, la conferma on-chain piena è **asincrona (~ore)**.
- È **proof-of-integrity** (l'evidenza è inalterata/coerente), **non** proof-of-veracity del contenuto.
- **eIDAS QTSP** (Izenpe qualified) validato separatamente il 2026-08-16 (non ri-eseguito qui).

## Nota di metodo (onestà)
I due FAIL iniziali dello script di stress erano **bug dello strumento di verifica** (chiave `valid` invece di
`verified`; chiamata RPC Solana senza firma), **non** del codice — colti con verifica simmetrica e corretti. Il
codice spedito ha retto; i metri vanno controllati come il codice.
