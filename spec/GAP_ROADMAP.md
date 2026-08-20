# FUNDCERT/OMEGA — roadmap onesta sulle mancanze (vs competitor mondiali, 2026-08-20)

Nata dall'assessment competitivo con cross-check Gemini Pro (verdetto IN DISACCORDO sul differenziatore, accolto).
**Onestà prima di tutto:** alcune mancanze le chiude il codice, altre NO (audit organizzativi, accordi di filing,
track-record). Qui distinguo, e segno lo stato REALE (non "attivo" = "fatto").

Legenda stato: ☐ da fare · ◐ parziale/in corso · ✔ affrontato+misurato · ⛔ NON chiudibile dal codice (organizzativo).

## A. Il core — NAV / valorizzazione
- ◐ **A1 · Attestazione di valorizzazione** (NON calcolo): verificare la coerenza interna di un pack di
  valorizzazione fornito — identità contabile `totAssets − totLiabs = netAssets`, copertura
  `Σ(valore titoli) ≤ totAssets`, cash/crediti ≥ 0 — e fingerprint canonico dell'INTERO pack. Confine: FUNDCERT
  attesta la coerenza dei numeri forniti, **non** prezza né calcola il NAV. → `attest_valuation()` (in corso).
- ⛔ **A2 · Calcolo NAV vero** (pricing feed, fair value, waterfall spese): richiede fonti prezzo e contabilità di
  fondo — fuori dallo scope PoC; è ciò che vendono SS&C/BNY/SimCorp.

## B. Copertura asset-class (oggi regge solo equity domestico semplice)
- ✔ **B1 · MBS/bond per identificatore** — `reconcile(by='auto')` CUSIP→ISIN: collisioni 1514→4 su Total Bond.
- ✔ **B2 · Multi-valuta / FX** — `Position.currency`+`value`, parser legge `<currencyConditional curCd/exchangeRt>`,
  `currency_exposure()`. Validato su VTIAX reale (8878 titoli): 40 valute, EUR 18.5%/JPY 14.6%/GBP 8.4%…
- ◐ **B3 · TIPS / inflation-linked** — `is_inflation_linked()` rileva; per questi face(N-CSR)≠principal-adjusted
  (N-PORT) = accrual, non discrepanza. Resta: riportare il fattore-indice per-bond invece del flag materiale.
- ✔ **B4 · Corporate action** — `corporate_action_flag()`: rapporto ≈ n:m = candidato split/reverse. Validato:
  Wolfspeed 30:1, Republic 1:3 (reverse) → 'split_candidate'; Hydrofarm 5.8% → 'discrepancy'.
- ◐ **B5 · Derivati / asset class** — `Position.asset_class` (da `assetCat` N-PORT) + `asset_class_exposure()`:
  il tool VEDE e separa equity/debt/derivato (`has_derivatives`), non li confonde. Validato su VTIAX reale
  (derivati+DFE forward FX) e Total Bond (77.6% debt/20.9% MBS). Metadata a parte (l'id li distingue nel digest).
  Resta: modellare notional/payoff dei derivati (valutazione), che è ⛔ (pricing).

## C. Stack enterprise
- ✔ **C1 · Ingestion/parser** — oltre a SSGA/N-PORT/N-CSR/CSV, `parse_mapped()`: mapper GENERICO colonna→campo
  (qualsiasi tabella → Holdings senza parser bespoke). Resta ⛔ la parte infra: connettori real-time custodian/SWIFT.
- ✔ **C2 · Matching fuzzy** — `name_similarity()` (Jaccard token ∪ ratio, stdlib) + `fuzzy_bridge()`: recupera i
  nomi quasi-uguali non matchati (validato su Growth reale: 31/38 recuperati, es. "META PLATFORMS"≈"…A"). NON agentic.
- ◐ **C3 · Exception workflow** — `triage()`: da reconcile → worklist prioritizzato (severità high/med/low +
  azione confirm_corporate_action vs investigate_discrepancy + stato 'open'). Scaffold, non ticketing completo.
- ◐ **C4 · Scala** — baseline MISURATO: le operazioni core sono già veloci e LINEARI (digest 220-370K holdings/s,
  100K in 0.35s; reconcile 59K/s). L'unico O(n²) era `fuzzy_bridge` → ottimizzato con BLOCKING (record-linkage):
  500×500 3768ms→11ms (336×), 2000×2000 46ms, ZERO perdita di match (31/31 su Growth reale). Il muro algoritmico
  in Python è tolto. Resta ⛔ (adoption-gated) il vero real-time distribuito/streaming (Go/Rust) — ha senso solo
  CON adozione, non prima.
- ⛔ **C5 · Filing regolamentare reale** (depositare N-PORT/AIFMD): gateway + accordi, non codice.
- ⛔ **C6 · Compliance estesa** (AIFMD 2.0, UCITS, MiFID, EMIR, Solvency II): mappatura enorme, per lo più legale.

## D. Fiducia / moat
- ⛔ **D1 · Certificazioni** SOC 2 / ISO 27001 / pen-test: audit organizzativi.
- ◐ **D2 · Verificabilità come contesto, non solo fingerprint** — la critica Gemini: un digest non dice chi/perché
  E la ri-computabilità serve una spec STABILE, non solo il codice. Affrontato in parte: **vettori di conformità
  pinnati** (`spec/vectors/fundcert_conformance.json` + test) — input canonico → digest atteso, versionati per
  `CANON_VERSION`; se le regole cambiano il test fallisce → bump esplicito. Un terzo ora ricomputa e VERIFICA.
  Inoltre — le 3 deficienze precise di Gemini affrontate col codice: (a) `evidence_record()` lega il digest
  all'INPUT (sha256 byte grezzi + fonte + fetched_at) e al METODO (`canonicalizer_fingerprint`) → la
  ri-computabilità ha una provenienza, non è nuda; (b) `resolve_exception()` porta il CHI/PERCHÉ (resolver,
  reason, decision, timestamp + digest) sulle eccezioni di triage = il contesto operativo che un fingerprint
  non dà. Restano ⛔ il workflow operativo live e l'ambiente d'esecuzione pinnato oltre il fingerprint del metodo.
- ⛔ **D3 · Track-record / brand**: tempo e clienti reali.

## Ordine d'attacco (leva × fattibilità nel confine onesto)
A1 (core, dato in mano) → B2 (multi-valuta) → B4 (corporate action) → B3 (TIPS) → C1/C2 (ingestion/fuzzy) →
C3 (workflow). Le ⛔ restano dichiarate come NON-codice: si riportano a Roberto, non si fingono chiuse.
