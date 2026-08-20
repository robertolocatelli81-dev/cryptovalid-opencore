# SPEC · OMEGA-FUNDCERT — canonicalizzazione di basket EQUITY (mono-valuta), v1.0

**Versione:** `fundcert-canon-1.0` · Stato: **PROOF-OF-CONCEPT su equity mono-valuta**, non un canonicalizzatore
del dominio finanziario. Validato su dati reali (SPDR SPY).

## Onestà sullo scope (walk-back supreme-ai 2026-08-20)
Il pass supremo ha dato **CONCORDO** su una diagnosi spietata: *"è un giocattolo su equity, non un
canonicalizzatore robusto per il mercato finanziario reale"*. Accettato. Cosa è **ROBUSTO** vs **APERTO**:
- **ROBUSTO (misurato su SPY reale, 505 posizioni):** digest deterministico su un basket equity mono-valuta —
  ordine irrilevante, notazione normalizzata (bug scientifica risolto), null-control che sa fallire.
- **CHIUSO ora (fix post-supreme):** id-scheme cross-source **US** (CUSIP→ISIN deterministico via check-digit
  ISO 6166 → una fonte CUSIP e una ISIN allineano); **componente cash** del PCF nel digest (gli AP la
  contestano — certificare solo le shares certificava l'oggetto sbagliato).
- **APERTO (il lavoro vero, dichiarato — NON risolto):** **FX multi-orario** e **NAV multi-valuta** (l'oggetto
  ostile, non l'equity basket); **corporate action** con date di efficacia ambigue; **pending settlement**;
  id cross-scheme **non-US** (SEDOL/ISIN non derivabili da CUSIP senza una mappa a pagamento); e — cruciale —
  il **killer-experiment vero NON è stato eseguito**: il cross-source è stato testato solo su una fonte
  SINTETICA (SSGA reformattato + un N-PORT finto della stessa composizione), MAI su due fonti REALI
  indipendenti (sec.gov bloccato, iShares dietro bot-protection dalla sandbox). Va esequito su download reali
  dell'utente prima di qualsiasi claim cross-source.

Certifica artefatti di fund-servicing (**PCF**, holdings, NAV-basket) con l'architettura di CryptoValid —
hash-chain + firma + ancoraggio — ma il digest ha valore SOLO se **lo stesso portafoglio produce sempre lo
stesso digest**. Nei record finanziari questo si rompe; questa spec definisce la forma canonica che lo rende
deterministico e **ri-derivabile da un terzo**.

## Confine (dichiarato, non nascosto)
FUNDCERT prova **cosa è stato ricevuto/trasmesso** (il basket/holdings *come pubblicato*), **NON che il NAV
o i pesi siano corretti**. Se il fund administrator sbaglia il calcolo, FUNDCERT certifica l'errore
fedelmente. È lo stesso confine di CryptoValid: *proof-of-transmission ≠ proof-of-veracity*. La veridicità
del calcolo è responsabilità del fund admin / dell'auditor, non dell'ancora.

## Forma canonica (regole deterministiche)
1. **Contenuto economico only.** Una posizione è ridotta a `{identifier, id_scheme, quantity}`. Nome,
   settore e **peso** sono cosmetici o **derivati** (peso = f(quantity, prezzo, NAV)) → **esclusi dal
   digest-core** (restano disponibili a parte). Si certifica *chi e quanto*, non l'etichetta.
2. **quantity → Decimal normalizzato.** Niente notazione scientifica: un intero espresso come `1.275099E7`
   diventa `12750990` (`format(Decimal, 'f')` — **non** `str(to_integral_value())`, che preserva l'esponente:
   è il bug che rompe il determinismo, trovato su SPY reale). Le quantità frazionarie sono quantizzate a
   `QUANTITY_DP=6` decimali con arrotondamento **BANKERS (ROUND_HALF_EVEN)**, dichiarato.
3. **identifier** normalizzato (upper, trim); **id_scheme** esplicito (CUSIP | SEDOL | ISIN | LEI | TICKER).
4. **Ordine irrilevante.** Le posizioni sono ordinate per `(id_scheme, identifier)` — l'ordine di
   pubblicazione della fonte non entra nel digest.
5. **Digest** = SHA3-256 del canonical JSON (`sort_keys`, `separators=(',',':')`). L'header (`fund_id`,
   `as_of`) si ancora a parte (metadati, non composizione).

## Proprietà ostili gestite / da gestire
- **notazione** (scientifica vs decimale su interi) — GESTITA (regola 2).
- **precisione/arrotondamento** frazionario — GESTITA (BANKERS a 6 dp, dichiarato).
- **ordinamento** — GESTITA (regola 4).
- **id multipli** (CUSIP+SEDOL+ISIN) — la fonte sceglie lo scheme; il cross-source va allineato sullo
  STESSO scheme (o via una mappa id→id) prima di confrontare. **Aperto**: normalizzazione cross-scheme.
- **FX / snapshot a orari diversi**, **corporate action con date ambigue**, **pending settlement** —
  **APERTI**: vanno dichiarati come campi con timestamp/stato e canonicalizzati con regole esplicite; sono
  il prossimo lavoro della spec (v1.1), sull'oggetto più ostile (NAV multi-valuta) non solo l'equity basket.

## Killer-experiment su dati REALI (2026-08-20) — cosa ha trovato
### (a) SSGA SPY vs SSGA SPLG (due file emittente reali, date diverse)
- **id-normalization CUSIP→ISIN VALIDATA su dati reali:** 505/505 CUSIP→ISIN, **480 titoli allineati** tra
  due file indipendenti eterogenei. Il fix #4 funziona fuori dal sintetico.
- **le 25/28 discrepanze NON sono bug:** veri cambi di composizione S&P 500 nei ~10 mesi tra le date (il
  `diff` le isola; il runner AVVERTE se le `as_of` differiscono → test non valido).
- **BUG #1 (parser, dal verdetto contrario):** scartava righe IN SILENZIO (7/file: footer benigni, MA un cert
  tool non droppa in silenzio) → `audit_skips()` separa footer-benigno da **posizione materiale persa**
  (quantità senza id) e ALZA alert; `Holdings.skipped` traccia i drop.

### (b) N-PORT SEC REALE di SPY (scaricato da EDGAR — 503 holdings, periodo 2026-03-31, $653.6B)
Sbloccato l'accesso EDGAR (era solo lo User-Agent che la SEC pretende). Il parser regge sul dato SEC vero
(503 posizioni, CUSIP reali). Il determinismo, che passava sul fixture sintetico, si è **ROTTO sul dato reale**
— ed è QUI il valore del test:
- **BUG #2 (determinismo del digest):** 27 posizioni condividono il CUSIP placeholder `000000000` (futures/cash
  senza CUSIP). L'ordinamento per `(scheme,id)` NON è unico su quei duplicati → l'ordine d'input filtrava nel
  digest. FIX: chiave sul **contenuto pieno** `(scheme,id,qty,cash)` → digest riproducibile, robusto a shuffle
  arbitrario su 503 holdings reali.
- **BUG #3 (diff che collassa in silenzio):** `{(scheme,id):qty}` è un dict → collassava le 27 righe placeholder
  in UNA (perdendo 26 posizioni reali). FIX: `diff` raggruppa in **multiset** e **dichiara** i `duplicate_ids`;
  un cambio su una riga placeholder ora è rilevato (prima veniva perso). Regressione nel banco.

### (c) SPY vs VOO — due N-PORT SEC REALI, STESSA DATA (2026-03-31), emittenti diversi
Scaricati entrambi da EDGAR (SPY=SPDR, 503 hold; VOO=Vanguard series S000002839, 519 hold) allo STESSO
quarter-end. **Controllo positivo prima delle misure:** SPY↔SPY → `same_digest=True`, diff vuoto (il differ SA
riconoscere l'uguaglianza). Poi il cross-source reale:
- `same_digest=False` (atteso: fondi DIVERSI sullo stesso indice, non stesso basket) — il test NON è
  digest-equality (per quello servirebbe lo stesso fondo), ma valida il **differ su 2 fonti SEC reali stessa-data**.
- **overlap composizione 94.3%** (476 titoli comuni / 505 unione) — coerente con due tracker S&P 500.
- **BUG #4 (fabbricazione di id, dal dato reale):** `cusip_to_isin('000000000')` produceva un ISIN FINTO
  (`US0000000002`) da un placeholder «nessun CUSIP». Un cert tool non inventa identificatori. FIX: rifiuto dei
  sentinelli placeholder (all-zero, N/A, …) → il placeholder resta `CUSIP:000000000`, e `only_in_*` ne
  **dichiara il conteggio** (`×27`) invece di collassarlo a una voce.

### (d) N-CSR vs N-PORT — STESSO FONDO, STESSA DATA, due filing SEC indipendenti (il test decisivo)
Scaricati da EDGAR, Vanguard 500 Index Fund (series S000002839), **as-of 31/12/2025**: N-PORT (XML, 518 hold,
CUSIP+shares) e lo **Schedule of Investments dell'N-CSR annuale** (HTML 9.4MB, nome+shares+market value, SENZA
CUSIP → match per nome normalizzato). Controllo positivo prima delle misure (N-PORT↔N-PORT per nome). Reperto,
**misurato**:
- **Due filing autorevoli dello stesso fondo, stessa data, NON coincidono.** Ogni titolo (shares **e** valore)
  differisce per lo **STESSO fattore di scala globale +0.397%** (mediana 1.003969, stdev 8e-5; 367/368 entro
  ±0.05%). Microsoft: 187.420.611→188.164.746 sh; Apple 372.615.534→374.094.479; NVIDIA 612.769.545→615.201.878.
- **Composizione identica al netto della scala:** tolto il fattore, i residui reali crollano (`residual_count=1`
  su 368 a tolleranza 0.05%). **Null control** (nomi permutati, stessa scala) → 0.3%: è segnale vero, non caso.
- Causa esatta della scala (**non fabbricata**): coerente con securities-lending o timing delle unità di
  creazione; le note servirebbero a chiuderla. Robusto: *composizione = identica; quantità = scala globale*.
- **Conseguenza per il prodotto:** «stesse holdings da 2 fonti → stesso digest» è il test SBAGLIATO su dato
  reale (due fonti corrette differiscono per scala). Il valore è la **riconciliazione**: `reconcile()` MISURA la
  scala e isola le differenze reali → *«368 titoli, composizione identica, scala +0.397% (indaga sec-lending),
  1 residuo»* è esattamente il segnale che un fund administrator/auditor vuole. Feature nata dal dato reale.

### (e) Perché il digest-equality byte-identico NON è il test — imparato dal dato reale
L'ipotesi iniziale era: stesso fondo/giorno da 2 fonti → stesso digest. Il giro (d) l'ha **falsificata sul dato
reale**: due filing SEC autorevoli dello stesso fondo/data differiscono per una scala globale a composizione
identica. Quindi «stesso digest tra fonti» pretenderebbe che due viste corrette coincidano byte-a-byte, cosa che
NON accade (sec-lending, timing unità, arrotondamenti dell'N-CSR). **La proprietà vera resta (a)/(b): stesse
holdings, encoding diverso → stesso digest (validata su N-PORT reale).** Il cross-source vero è la
**riconciliazione** (`reconcile()`), non l'uguaglianza. Nota: le share-class (VOO/VFIAX/VFINX = series
S000002839) depositano UNA sola N-PORT → non sono due fonti indipendenti (sarebbe confronto di un file con sé).

## Il test che vale (conformance)
Prendi lo **stesso fondo, stesso giorno, da due fonti** (emittente + N-PORT). Canonicalizza entrambe. Se i
due digest **differiscono**, hai trovato il problema reale prima di scrivere il resto — il `diff()` dice
esattamente quale posizione/quantità diverge. Verificato su SPY reale (SSGA): dopo il fix della notazione,
riordino + riformattazione producono lo **stesso digest** su 505 posizioni; un +1 share cambia il digest e
il differ lo isola. Vettori nel banco `opencore/test_fundcert.py` (fixture: posizioni SPY reali as-of 18/08).

## Fonti dati reali (per costruire e testare, mai dati a distribuzione controllata)
- **SEC N-PORT via EDGAR** — migliore per storico strutturato (XML, holdings mensili con LEI/CUSIP). Bulk
  gratuito, nessun termine restrittivo. (La sandbox OMEGA non raggiunge sec.gov: download lato utente.)
- **Emittenti** che pubblicano holdings quotidiani sul proprio sito (SSGA/SPDR XLSX, iShares CSV, Amundi,
  Xtrackers, Vanguard) — l'**eterogeneità** dei formati è il caso peggiore che la spec deve reggere.
- **NON** si tocca il canale PCF a distribuzione controllata (NSCC → membri/AP): sarebbe accesso non
  autorizzato e contaminerebbe l'asset con dati di provenienza contestabile — l'opposto di ciò che si vende.

Parser di riferimento (stdlib): `parse_nport_xml`, `parse_holdings_csv`, `parse_ssga_xlsx` in
`opencore/fundcert_canonical.py`.
