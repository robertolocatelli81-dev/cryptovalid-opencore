<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# Dossier di nomina — Digital Public Goods Alliance (DPGA)

Pronto da inviare. La nomina si fa **da umano** (Roberto) sul registro pubblico dei candidati DPGA
(`github.com/DPGAlliance/publicgoods-candidates`) o via il form su digitalpublicgoods.net. Questo file
raccoglie tutti i campi con le **evidenze reali nel repo**. Fonte degli indicatori: [DPG Standard ufficiale](https://github.com/DPGAlliance/DPG-Standard).

## Metadati progetto
- **Nome:** CryptoValid Open Core (OMEGA open-core)
- **Descrizione (1 frase):** libreria open-source, zero-dipendenze, per **verificare localmente** l'integrità di
  evidenze finanziarie/di compliance (ledger, attestazioni di metriche derivate, portafogli di microcredito) —
  chiunque ricomputa e controlla senza fidarsi dell'autore.
- **Tipo:** software · **Licenza:** `AGPL-3.0-or-later` (OSI-approved) → [`LICENSE`](LICENSE), header SPDX, [`NOTICE`](NOTICE)
- **Repository pubblico:** https://github.com/robertolocatelli81-dev/cryptovalid-opencore
- **Proprietà:** Copyright (C) 2026 Roberto Locatelli ([`NOTICE`](NOTICE), `pyproject.toml`)
- **Stadio:** funzionante, 27 suite di test, validato su dati reali (SEC N-PORT/N-CSR, KIVA, MIX).
- **Evidenza di stress ONLINE (2026-08-22):** backbone deterministico 27/27 + OMEGA 8/8 + 6 moduli nuovi, e
  ancore esterne verificate DAL VIVO — RFC 3161 (freeTSA), OpenTimestamps→Bitcoin (3/3 calendar), Solana
  mainnet (pin genesis). Sa fallire (ledger manomesso → FAIL). Vedi [`spec/STRESS_REAL_ONLINE_20260822.md`](spec/STRESS_REAL_ONLINE_20260822.md).

## Rilevanza agli SDG (indicatore 1) — SOLO 16 + 9 (correzione council 4-menti 2026-08-22)
- **SDG 16** (istituzioni trasparenti/anti-corruzione) — **PRIMARIO e pieno**: evidenza di compliance
  tamper-evident, verificabile da un terzo qualunque. È ciò che il tool È oggi.
- **SDG 9** (infrastruttura resiliente/open) — infrastruttura di verifica open, zero-dipendenze.
- **SDG 1 / 8 / 10 RITIRATI.** Il council (Opus + Gemini-Pro, verificato sul codice) ha trovato un
  overclaim + una **contraddizione interna verificata** nel modulo microcredito: il matching cross-MFI del
  sovra-indebitamento (`microfinance.py:148-168`) funziona **solo con salt CONDIVISO** → l'hash del
  beneficiario diventa uno **pseudonimo linkabile fra istituti = dato personale pseudonimizzato** (GDPR
  Recital 26); col salt **per-istituto** (`hash_borrower`, riga 50-53) il matching **non funziona**. In
  entrambi i casi il "no-PII by design" salta proprio nell'uso SDG 1/10, e `DO_NO_HARM.md` non copre il
  rischio "flag di esclusione dei poveri dal credito". → Nomina STRETTA e inattaccabile: **solo 16 + 9**.
  (Il difetto microfinance è un finding reale da correggere PRIMA di rivendicare l'inclusione — vedi
  `spec/SPEC_MICROFINANCE.md`.)

## I 9 indicatori del DPG Standard (con evidenza reale)
| # | Indicatore | Stato | Evidenza nel repo |
|---|---|---|---|
| 1 | Rilevanza SDG | ✅ | **SDG 16 + 9** (1/8/10 ritirati dal council: contraddizione salt/no-PII) — [`spec/DPG_AUDIT.md`](spec/DPG_AUDIT.md) |
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
  Zero-dependency open-source library that lets any third party locally verify the integrity
  of financial and compliance evidence (hash-chained ledgers, committed-ledger derived-metric
  attestations, fund holdings). Anyone recomputes the SHA-256/SHA3-256 hash chains and Merkle
  attestations without trusting the operator. Proof-of-integrity, not proof-of-veracity.
website: https://github.com/robertolocatelli81-dev/cryptovalid-opencore
license:
  - spdx: AGPL-3.0-or-later
SDGs:
  - SDGNumber: 16   # primary — transparent, accountable institutions, anti-corruption
  - SDGNumber: 9    # resilient, zero-dependency open verification infrastructure
# NB: SDG 1/8/10 (financial inclusion) RITIRATI dal council — vedi sezione sopra.
# SDG 1/8/10 RITIRATI dal council. Il JSON finale, schema-valido, e' piu' in basso in questo dossier.
type: [software]
repositoryURL: https://github.com/robertolocatelli81-dev/cryptovalid-opencore
```

## Confine invalicabile da tenere nella nomina (anti-overclaim)
- **Proof-of-integrity, non proof-of-veracity**: prova che l'evidenza è inalterata/coerente, NON che il
  contenuto sia vero. Dichiararlo.
- **Dual-use dichiarato**: strumento difensivo di integrità, non di sorveglianza.
- **Solo SDG 16 + 9** (nessuna rivendicazione di inclusione finanziaria: ritirata dal council).

## PROCESSO CAMBIATO (verificato 2026-08-22): NON è più una PR GitHub
Il repo `DPGAlliance/publicgoods-candidates` è **ARCHIVIATO**. La nomina ora si fa via **web app**:
**https://app.digitalpublicgoods.net** (registrazione + form). Guida eligibilità:
https://digitalpublicgoods.net/submission-guide/ · È il passo umano di Roberto (login proprio).

## JSON FINALE, VERIFICATO DAL COUNCIL E SCHEMA-VALIDO (da usare nel form)
```json
{
  "name": "CryptoValid Open Core",
  "aliases": ["OMEGA open-core", "CryptoValid"],
  "description": "Zero-dependency open-source library that lets any third party locally verify the integrity of financial and compliance evidence: hash-chained ledgers, committed-ledger derived-metric attestations, and fund holdings. Anyone recomputes the SHA-256/SHA3-256 hash chains and Merkle attestations and checks them without trusting the operator. It is proof-of-integrity (the evidence is unaltered and internally consistent), not proof-of-veracity (it does not claim the recorded facts are true).",
  "website": "https://github.com/robertolocatelli81-dev/cryptovalid-opencore",
  "license": [{"spdx": "AGPL-3.0-or-later", "licenseURL": "https://github.com/robertolocatelli81-dev/cryptovalid-opencore/blob/main/LICENSE"}],
  "SDGs": [
    {"SDGNumber": 16, "evidenceText": "Tamper-evident, independently verifiable evidence of compliance and audit decisions: anyone recomputes the SHA-256/SHA3-256 hash chains and Merkle attestations without trusting the operator, supporting transparent, accountable institutions and anti-corruption. The verifier demonstrably fails on tampered evidence, and integrity is anchorable to independent witnesses (RFC 3161 timestamps, OpenTimestamps/Bitcoin)."},
    {"SDGNumber": 9, "evidenceText": "Zero-dependency (Python standard library only), offline-recomputable open infrastructure for verifying financial and regulatory evidence, auditable by any third party without vendor lock-in or proprietary dependencies."}
  ],
  "sectors": ["Economics/Finance", "Anti-corruption", "Governance", "Transparency & Accountability", "Data Security"],
  "type": ["software"],
  "repositories": [{"name": "main", "url": "https://github.com/robertolocatelli81-dev/cryptovalid-opencore"}],
  "organizations": [{"name": "Roberto Locatelli", "website": "https://github.com/robertolocatelli81-dev/cryptovalid-opencore", "org_type": "owner", "contact_name": "Roberto Locatelli", "contact_email": "roberto.locatelli.81@gmail.com"}],
  "stage": "nominee"
}
```
Domanda che la DPGA farà (Gemini): **sostenibilità / bus-factor=1** (owner singolo) — rispondere "cerco stewardship istituzionale".
