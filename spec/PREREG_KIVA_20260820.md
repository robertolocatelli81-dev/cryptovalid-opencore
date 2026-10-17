# Pre-registrazione del metro — microfinance.py su dati REALI Kiva (2026-08-20)

> Nota (2026-10-14, cryptovalid-opencore 0.21.0): i byte pre-registrati — SHA3-256
> `db5671af0156683c646aabbb02814fcb80a0feb0ed6a1f88916691ea1d2a04fe`, il valore citato in
> `REAL_DATA_VALIDATION_KIVA_20260820.md` e `REAL_DATA_VALIDATION_MIX_20260820.md` — sono questo file al commit
> `401e6b2be7134ff94d19ef0d97e662ecb7b2a001` del repository pubblico (2026-08-20), e restano verificabili lì. In questa
> versione sono cambiati soltanto i nomi dei revisori, sostituiti da ruoli, e un rimando a una nota interna non
> pubblica (riga Provenienza); metro, controlli e stop-rule sono invariati.

Scritto e HASHATO **prima** di scaricare/toccare il dato. Gate del council: un primo revisore AI esterno +
un secondo revisore AI (D'ACCORDO-CON-CORREZIONE, 3 correzioni incorporate). Ordine di Roberto: "trova la prima MFI che
usa CryptoValid e procediamo se anche il secondo revisore è d'accordo".

## Stato onesto (Correzione 1 del secondo revisore — lessico)
Un **dataset NON è un utente**. Questo esercizio porta lo stato da *"validato su dati SINTETICI"* a
*"validato su dati REALI pubblici"*. **Adozione: ZERO.** L'ordine "prima MFI che *usa* CryptoValid" resta
**APERTO**; questa è la sua precondizione onesta, non il suo adempimento.

## Mismatch dichiarato (Correzione 3 del secondo revisore)
Kiva è una piattaforma P2P di crowdfunding: lo snapshot è dato **già pubblico**, non il ledger operativo
privato di una MFI. Girarci CryptoValid prova che la pipeline **regge dati reali nella forma giusta**, NON
che risolva il bisogno interno d'integrità di una MFI (quello vive sui loro registri privati).
Confine invariato: **proof-of-integrity, NON veracity** — garbage-in resta garbage.

## METRO (cosa conta come VALORE — pre-registrato, misurabile)
V1. **Determinismo**: stessa porzione Kiva → stesso `portfolio_digest` su 2 run indipendenti (deve coincidere).
V2. **Incoerenze reali rilevate**: `attest_portfolio` con identità contabile
    `disbursed == outstanding + repaid + written_off` (tol dichiarata). Conto quanti record del dato **reale**
    violano l'identità → numero onesto, non aggettivo.
V3. **PAR** (Portfolio-at-Risk) calcolato sul dato reale (dove lo `status` Kiva lo consente) → numero.
V4. **Throughput** di digest/seal su dato vero (record/s) → numero.

## CONTROLLO POSITIVO (il tool DEVE accorgersene, altrimenti è cieco)
P1. Corrompo N record (altero `principal_outstanding` di una quota nota) → `attest_portfolio` DEVE
    segnalare la rottura dell'identità. **Detection attesa: 100% delle corruzioni materiali.**
P2. Permuto i **valori** tra due record (stesso schema, importi scambiati) → il `portfolio_digest` DEVE
    cambiare rispetto all'originale.

## CONTROLLO NULL (il tool NON deve "trovare" nulla dove non c'è)
N1. `reconcile_portfolios(P, P)` — una porzione con SE STESSA → **zero** discrepanze materiali (no falsi positivi).
N2. Permuto l'**ordine** dei record (stessi valori, righe rimescolate) → il `portfolio_digest` DEVE restare
    **IDENTICO** (la canonicalizzazione è invariante all'ordine).

## STOP-RULE (onestà, decisa prima)
- Se P1/P2 NON rilevano le corruzioni → il tool è cieco → **FALLITO**, lo dico netto.
- Se N1 produce falsi positivi o N2 cambia il digest → la canonicalizzazione è rotta → **FALLITO**.
- V2 (incoerenze nel dato reale) è un **fatto osservato**, non un successo/insuccesso: le incoerenze del
  dato pubblico Kiva sono ciò che sono; le riporto come numero, senza spin.

## Provenienza
Fonte: Kiva Data Snapshots (kiva.org/build/data-snapshots) — licenza da LEGGERE al download
(prima di usarlo, come per ogni accordo). Mapping campi dichiarato nel codice del run.
