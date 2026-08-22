<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# Dossier di nomina — Digital Public Goods Alliance (DPGA)

Pronto da inviare. La nomina si fa **da umano** (Roberto) sul registro pubblico dei candidati DPGA
(`github.com/DPGAlliance/publicgoods-candidates`) o via il form su digitalpublicgoods.net. Questo file
raccoglie tutti i campi con le **evidenze reali nel repo**. Fonte degli indicatori: [DPG Standard ufficiale](https://github.com/DPGAlliance/DPG-Standard).

## Metadati progetto
- **Nome:** CryptoValid Open Core (OMEGA open-core)
- **Descrizione (1 frase):** libreria open-source, zero-dipendenze, per **verificare offline** l'integrità di
  evidenze finanziarie/di compliance (ledger, attestazioni di metriche derivate, portafogli di microcredito) —
  chiunque ricomputa e controlla senza fidarsi dell'autore.
- **Tipo:** software · **Licenza:** `AGPL-3.0-or-later` (OSI-approved) → [`LICENSE`](LICENSE), header SPDX, [`NOTICE`](NOTICE)
- **Repository pubblico:** https://github.com/robertolocatelli81-dev/cryptovalid-opencore
- **Proprietà:** Copyright (C) 2026 Roberto Locatelli ([`NOTICE`](NOTICE), `pyproject.toml`)
- **Stadio:** funzionante, 27 suite di test, validato su dati reali (SEC N-PORT/N-CSR, KIVA, MIX).

## Rilevanza agli SDG (indicatore 1) — dichiarata ONESTA
- **SDG 16** (istituzioni trasparenti/anti-corruzione) — **PRIMARIO e pieno**: evidenza di compliance
  tamper-evident, verificabile da un terzo qualunque. È ciò che il tool È oggi.
- **SDG 9** (infrastruttura resiliente/open) — infrastruttura di verifica open, zero-dipendenze.
- **SDG 1 / 8 / 10** (inclusione finanziaria) — **supportato** dal modulo microcredito
  ([`microfinance.py`](microfinance.py), [`spec/SPEC_MICROFINANCE.md`](spec/SPEC_MICROFINANCE.md)):
  trasparenza del portafoglio MFI + registro di sovra-indebitamento cross-MFI **senza PII**.
  **HONEST-SCOPE (da NON omettere nella nomina):** capacità **validata su dati sintetici e su dataset pubblici
  (KIVA/MIX)**; la validazione su un portafoglio-MFI **di un operatore reale è in attesa** (le MFI non
  pubblicano portafogli come i fondi SEC). Rivendicare la *capacità*, non un impatto sul campo già dimostrato.

## I 9 indicatori del DPG Standard (con evidenza reale)
| # | Indicatore | Stato | Evidenza nel repo |
|---|---|---|---|
| 1 | Rilevanza SDG | ✅ | SDG 16/9 pieno; 1/8/10 via microfinance (caveat sopra) — [`spec/DPG_AUDIT.md`](spec/DPG_AUDIT.md) |
| 2 | Licenza open approvata | ✅ | `AGPL-3.0-or-later` — [`LICENSE`](LICENSE), SPDX, [`NOTICE`](NOTICE) |
| 3 | Proprietà chiara | ✅ | Copyright Roberto Locatelli — [`NOTICE`](NOTICE), `pyproject.toml` |
| 4 | Indipendenza di piattaforma | ✅ | `dependencies = []` (solo stdlib ≥3.9); `cryptography` opzionale e OSI-open |
| 5 | Documentazione | ✅ | [`README.md`](README.md) (499 righe), `spec/` (CONFORMANCE, SPEC_*, REQUIREMENTS_COVERAGE, GAP_ROADMAP) |
| 6 | Estrazione dati non-PII/non-proprietaria | ✅ | formati aperti JSONL/JSON/CSV/N-PORT XML; import/export non proprietari |
| 7 | Privacy e leggi applicabili | ✅ | [`PRIVACY.md`](PRIVACY.md) — no-PII by design, self-hosted, GDPR-aware |
| 8 | Standard e best practice | ✅ | SHA3/SHA-256 (FIPS 202/180-4), Ed25519 (RFC 8032), RFC 3161 (TSA), RFC 6962 (Merkle), ISO 6166; threat model dichiarato |
| 9 | Do-no-harm by design | ✅ | [`DO_NO_HARM.md`](DO_NO_HARM.md) — sicurezza/threat-model + no-PII; 9b/9c N/A giustificati (infrastruttura non-user-facing); nota dual-use |

## Blocco strutturato (bozza per il file candidato DPGA — YAML)
```yaml
name: CryptoValid Open Core
description: >-
  Zero-dependency open-source library to verify offline the integrity of financial and
  compliance evidence (ledgers, committed-ledger derived-metric attestations, microcredit
  portfolios). Anyone recomputes and checks without trusting the author. Proof-of-integrity,
  not proof-of-veracity; no PII by design.
website: https://github.com/robertolocatelli81-dev/cryptovalid-opencore
license:
  - spdx: AGPL-3.0-or-later
SDGs:
  - SDGNumber: 16   # primary — transparent, accountable institutions
  - SDGNumber: 9    # resilient open infrastructure
  - SDGNumber: 1    # supported via microfinance module (capability; real-operator validation pending)
  - SDGNumber: 8
  - SDGNumber: 10
sectors: [finance, governance]
type: [software]
repositoryURL: https://github.com/robertolocatelli81-dev/cryptovalid-opencore
```

## Confine invalicabile da tenere nella nomina (anti-overclaim)
- **Proof-of-integrity, non proof-of-veracity**: prova che l'evidenza è inalterata/coerente, NON che il
  contenuto sia vero. Dichiararlo.
- **No-PII by design**; nessuna rivendicazione di impatto reale di inclusione finanziaria non ancora misurato.
- **Dual-use dichiarato**: strumento difensivo di integrità, non di sorveglianza.

## Cosa serve da Roberto (azione umana, non automatizzabile)
1. Aprire una PR/nomina sul registro DPGA col blocco YAML sopra (o compilare il form).
2. Confermare l'URL del repo pubblico come canonico.
3. Nessun costo, nessuna entità richiesta per la **nomina** (la valutazione la fa la DPGA).
