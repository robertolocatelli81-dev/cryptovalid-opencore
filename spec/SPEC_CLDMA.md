# CLDMA — Committed-Ledger Derived-Metric Attestation (spec v1, 2026-08-20)

**Il gap fintech che nessuno riempie** (verificato: Gemini Pro + ricerca 2026-08-20): i primitivi esistono
separati — proof-of-reserves Merkle prova una **somma**, ZK-PoR prova con privacy, selective disclosure apre
campi — ma **nessuno prova che un RATIO REGOLATORIO DERIVATO** (PAR30, write-off ratio, risk coverage) **sia
correttamente ricalcolato da un LEDGER PRIVATO IMPEGNATO**, senza rivelare i singoli prestiti, con le
discrepanze localizzabili al record. CLDMA riempie questo, riusando il motore di ricalcolo validato su dato
reale World Bank (`REAL_DATA_VALIDATION_MIX_*`).

> **Nota di novita' (onesta, dopo Gemini Pro):** CLDMA NON e' un nuovo primitivo crittografico. E' un'**applicazione/
> pattern mirato** di un primitivo noto (Merkle Sum Tree, Maxwell PoL) esteso a DUE somme (num, den) + metadati.
> La novita' e' l'**assemblaggio** (nessuno lo fa per ratio regolatori derivati da ledger privati), non la crittografia.

## Costruzione (zero-dipendenze, solo SHA3-256) — algoritmo RIGOROSO (rev. dopo Gemini Pro)
**Merkle Sum Tree** esteso: ogni foglia impegna il record salato e porta due contributi interi (num, den);
ogni nodo porta `(hash, Σnum, Σden)`; la radice porta i totali. La radice pubblicata **lega i metadati**.
Dettagli che una spec riproducibile DEVE fissare (colmati dopo il giudizio di Gemini):
- **Encoding non ambiguo:** ogni input di hash e' `SHA3-256(JSON([tag, campo1, campo2, ...]))` con `sort_keys`
  impliciti nell'ordine e `separators=(',',':')` — **NON** `"a|b|c"` (che collide se un campo contiene `|`).
  Foglia = `H(JSON(["L", commit, num, den]))`, commit = `H(JSON(["commit", salt, canonical_record]))`,
  nodo = `H(JSON(["N", left_hash, right_hash, Σnum, Σden]))`, radice = `H(JSON(["CLDMA", spec, metric, as_of, n, tree_root]))`.
- **Interi a PRECISIONE ARBITRARIA** obbligatori (unita' minori, 2 dp): niente fixed-width -> niente overflow/manipolazione.
- **Nodi dispari: PROMOZIONE** (il nodo dispari sale invariato al livello superiore), **NON duplicazione** —
  evita l'attacco CVE-2012-2459 (Bitcoin merkle). Regola deterministica, riproducibile tra implementazioni.
- **den = 0** (denominatore totale nullo): ratio **INDEFINITO** per convenzione, riportato come `"0"` con
  `denominator_minor: 0`; il verificatore DEVE trattarlo come indefinito, MAI come "0% di rischio".

Modalita':
- **Regolatore** (`verify_full`): apertura completa del ledger → assurance totale, PII vista solo dal regolatore.
- **Pubblica** (`attestation` + `challenge`/`open_leaves`/`verify_open`): radice + totali + ratio + campione
  sfidato via beacon → tamper-evidence deterministica + spot-check probabilistico della classificazione.

## Cosa prova / cosa NO (honest-scope)
- **ROBUSTO:** tamper-evidence deterministica (ogni modifica post-commit rompe la radice); i totali num/den
  sono legati alla radice (non falsificabili senza romperla); l'apertura sfidata verifica inclusione + che la
  classificazione dei record aperti segua la definizione della metrica.
- **PROBABILISTICO:** la classificazione di *tutti* i record (senza aprirli tutti) → detection `1-(1-f)^k`.
- **NON prova:** veracita' (garbage-in resta garbage); completezza (vedi E4); privacy piena (i record sfidati
  vengono aperti — NON zero-knowledge; lo ZK e' un layer successivo, pesante, non implementato).

## Attacco NEMESIS (2026-08-20) — 4 buchi trovati con exploit che girano, tutti gestiti
| # | Buco | Stato |
|---|---|---|
| E1 | metadati (as_of/metric/n) non legati alla radice → forgiabili | **CHIUSO** (`_bind_meta`) |
| E2 | nonce grinding: prover sceglie il nonce ed evita le foglie manipolate | **REQUISITO DI PROTOCOLLO** — il nonce DEVE venire dal verificatore/beacon (documentato) |
| E3 | `verify_open([])` passava vacuamente | **CHIUSO** (apertura vuota → False) |
| E4 | completezza non provata: impegnare un sottoinsieme nasconde i prestiti peggiori | **MITIGATO** (`verify_full(expected_n=...)`); ancoraggio pieno FUORI dallo schema (limite intrinseco di ogni commitment) |
| E5 | second-preimage leaf/internal | difeso: tag di dominio (`"L"`/`"N"`) **+ encoding JSON length-safe** (non piu' `|`) |

## Giudizio di Gemini Pro (2026-08-20) — verdetto avversariale accolto
Gemini ha bocciato la spec v1 come "NON adottabile" per **3 lacune di rigore** (non falle crittografiche):
den=0 non gestito, overflow non specificato, regola nodi-dispari ambigua; + fragilita' dei separatori.
**Tutte affrontate** in questa revisione: encoding JSON, interi arbitrari, promozione esplicita, convenzione den=0.
Gemini ha confermato ROBUSTO: idea/utilita' "estremamente elevata", honest-scope "accurato", E1-E4 gestiti bene;
e ha corretto un mio **overclaim** (novita' del primitivo -> e' applicazione/pattern), accolto sopra.

## Ancora esterna ONLINE (OpenTimestamps / Bitcoin) — `anchor_commitment`
Lo schema interno prova coerenza ma NON che la radice non sia stata **retrodatata/rigenerata**. `anchor_commitment(c)`
sottopone il `root_hash` (32 byte) ai calendar OpenTimestamps pubblici (HTTP stdlib, no account, no costo; riusa
`core/ots_anchor.py`) -> testimone pubblico indipendente su Bitcoin. **Live 2026-08-20:** 3/3 calendar impegnati
(a.pool, b.pool, alice.btc), status `pending-bitcoin`. Honest-scope: subito = impegno del calendar (conferma
on-chain asincrona ~ore, via upgrade della proof); ancora l'**esistenza-nel-tempo** della radice, NON il contenuto
ne' la completezza (E4). Degrada onesto se offline.

## Conformance vector (riproducibile — chiunque implementi lo spec deve ottenere questi valori)
Ledger (3 record), salt `CONFORMANCE-SALT-v1`, metrica PAR30, as_of `2026-08-20`:
```
A1: outstanding 800.00, overdue 0,  active        -> non at-risk
A2: outstanding 500.00, overdue 95, active        -> at-risk (>30gg)
A3: outstanding 1500.00, overdue 0, renegotiated  -> at-risk (rinegoziato)
```
Atteso: PAR30 = (500+1500)/(800+500+1500) = 2000/2800 = **0.714286**
```json
{
  "spec_version": "CLDMA-1", "metric_id": "PAR30", "as_of": "2026-08-20", "n_records": 3,
  "root_hash": "0f03eb1a9d89fbca43cac93f146e5d5df339a5a4674de1bbfbcca35da82a96c7",
  "numerator_minor": 200000, "denominator_minor": 280000, "ratio": "0.714286"
}
```
tree_root interno: `02fe92e8d3acd1d162dc161a8a5766625ce62a4e784115ea553d8e465a0ff050`
(encoding JSON length-safe, rev. dopo Gemini Pro — sostituisce il vettore v0 basato su `|`).

## Confine
Proof-of-integrity / consistenza, NON veracity. No-PII nella radice (solo hash salati). Il valore e'
tecnico/di credibilita', non commerciale: abilita un'istituzione a dimostrare l'integrita' delle proprie
metriche senza esporre i borrower — ma serve un adottante (adozione ancora ZERO). AGPL, zero-dipendenze.
