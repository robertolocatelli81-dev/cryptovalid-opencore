# Audit di DPG-readiness — CryptoValid/OMEGA open-core vs i 9 indicatori del DPG Standard

Fatto 2026-08-20 con la fonte ufficiale ([DPGAlliance/DPG-Standard](https://github.com/DPGAlliance/DPG-Standard)).
Onesto: distinguo MET (evidenza nel repo) da GAP/PARZIALE (cosa manca davvero). Legenda: ✅ MET · ◐ parziale · ⚠️ GAP · N/A.

| # | Indicatore | Stato | Evidenza / cosa manca |
|---|---|---|---|
| **1** | **Rilevanza agli SDG** | ✅ (SDG 16/9 **+ 1/8/10**) | **CHIUSO**: **SDG 16** (istituzioni trasparenti/anti-corruzione) + **SDG 9** (infrastruttura open); **e ora SDG 1/8/10** via il modulo `microfinance.py` — trasparenza del microcredito (portafoglio MFI donor-verificabile, PAR) + protezione del beneficiario (over-indebtedness cross-MFI senza PII). HONEST: il modulo microfinance è validato su dati SINTETICI (le MFI non pubblicano portafogli come i fondi SEC) — capacità reale, validazione-reale in attesa dei dati di un operatore. |
| **2** | **Licenza open approvata** | ✅ | `AGPL-3.0-or-later` (OSI-approved), header SPDX, `NOTICE`, `pyproject.toml`. |
| **3** | **Proprietà chiara** | ✅ | `Copyright (C) 2026 Roberto Locatelli` in `NOTICE`, header SPDX, `authors` in pyproject. |
| **4** | **Indipendenza di piattaforma** | ✅ | `dependencies = []` (solo stdlib Python ≥3.9); `cryptography` è opzionale ed è OSI-open. Nessuna dipendenza chiusa. |
| **5** | **Documentazione** | ✅ | `README.md` (398 righe, setup+use), `SPEC_FUNDCERT_CANONICAL.md`, `spec/CONFORMANCE.md`, `SPEC_EVIDENCE_FORMAT.md`, `REQUIREMENTS_COVERAGE.md`, `GAP_ROADMAP.md`. |
| **6** | **Estrazione dati (non-PII, non-proprietaria)** | ✅ | Formati aperti: JSONL (ledger), JSON (digest/vettori di conformità), CSV/N-PORT XML in ingresso. Import/export non-proprietario. |
| **7** | **Privacy e leggi applicabili** | ✅ | **CHIUSO** con `PRIVACY.md` (no-PII by design, self-hosted, responsabilità operatore, GDPR-aware). |
| **8** | **Standard e best practice** | ✅ | SHA3-256/SHA-256 (FIPS 180-4/202), ISO 6166 (ISIN check-digit), Ed25519 (RFC 8032), RFC 3161 (TSA), RFC 6962 (Merkle/CT), RFC 8410, LOTL. Threat model dichiarato. |
| **9** | **Do no harm by design** | ✅ | **CHIUSO** con `DO_NO_HARM.md`: 9a sicurezza/threat-model + no-PII; 9b/9c dichiarati **N/A** (infrastruttura non-user-facing, niente contenuti/account/minori) con giustificazione; nota dual-use (difensivo, proof-of-integrity non veracity). |

## Verdetto onesto (aggiornato 2026-08-20 — 3 documenti aggiunti)
**9/9 indicatori ora coperti** su SDG 16/9: chiusi (1) sezione SDG nel README, (7) `PRIVACY.md`, (9) `DO_NO_HARM.md`.
Gli altri 6 (2,3,4,5,6,8) erano già MET. **Il repo è DPG-nominabile su SDG 16** (trasparenza istituzionale).
Confine tenuto: l'inclusione finanziaria (SDG 1/8/10) NON è rivendicata — richiede l'adattamento microcredito.

**Il collo è l'indicatore 1.** Due strade oneste:
- **SUBITO, senza pivot:** rivendicare **SDG 16** (trasparenza/accountability/anti-corruzione delle istituzioni via evidenza di compliance tamper-evident). È vero di ciò che il tool È oggi. Con questo + i due statement, la nomination è plausibile.
- **Per SDG 1/8/10 (microcredito/inclusione):** serve l'**adattamento** delle primitive alla trasparenza del microcredito (record prestito/rimborso, audit per donatori). NON rivendicabile onestamente prima di farlo.

## To-do concreto per essere DPG-ready (tutto doc/codice, no call, no entità)
1. **README:** sezione "Relevance to the SDGs" — SDG 16 onesto (+ SDG 9 infrastruttura); NON rivendicare inclusione finché non c'è l'adattamento.
2. **PRIVACY.md** (o sezione README): "no PII by design — il sistema tratta dato di fondo/evidenza, non dati personali".
3. **README/SECURITY:** statement esplicito 9b/9c **N/A** (infrastruttura non-user-facing) + puntare alla policy di sicurezza.
4. (Opzionale, rafforza) nominare al DPG Registry via il form pubblico DOPO gli step 1-3.
