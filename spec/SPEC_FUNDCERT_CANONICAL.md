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

### (d-bis) 12 fondi Vanguard, N-CSR vs N-PORT (31/12/2025) — meccanismo chiuso (con walk-back)
Esteso a **tutti i 12 fondi** del trust Vanguard Index Funds (parser N-CSR `parse_ncsr_soi` migliorato: gestisce
i **marcatori di nota** '*,1' che spostavano le colonne → coverage 42%→**100-102%**). Controllo positivo + null
passati su tutti e 12. Refutata la scala universale: il +0.397% del 500 Index è fondo-specifico (altri
large-cap ~0.000%).

**WALK-BACK onesto (una prima ipotesi refutata dal dato):** i fondi small-cap/extended mostravano molti residui,
e li avevo attribuiti a **securities-lending**. Andando a prendere le note reali (marcatore N-CSR '1' = "positions
on loan") il nesso è **CROLLATO**: P(residuo|in-prestito) vs P(residuo|no) → lift 1.69× (Small-Cap) e **0.36×**
(Extended, al contrario). Lending NON spiega. Anche l'ipotesi collisioni-di-nome: **0 collisioni**.
**Causa vera, MISURATA:** il residuo è **inversamente proporzionale alla dimensione della posizione** (scarto×shares
≈ costante ~mille azioni in ogni quartile, in TUTTI i fondi) → è **rumore assoluto fisso** (rounding/timing tra i
due snapshot di deposito), grande in % sulle posizioni piccole (small-cap), trascurabile sulle grandi (large-cap).
Non era un'anomalia dei fondi: era la mia **soglia relativa cieca alla dimensione** a fabbricare false anomalie.

**Fix nel prodotto:** `reconcile(material_tol=0.02)` separa la differenza **MATERIALE** (grande in %, discrepanza
reale) dal residuo **MINORE** (piccolo in %, quantizzazione/timing). Riesito: **tutti e 12 i fondi riconciliano
puliti**; su 12 fondi × migliaia di holding restano **~11 item materiali** da rivedere (Wolfspeed +2907% = corporate
action 2025 nota, Republic Airways −67%, Pinnacle −93%, e 2-6% minori). È esattamente il segnale «guarda questi».
HONEST SCOPE: match per **nome** (N-CSR senza CUSIP), 80-90% allineati; l'ID (CUSIP/ISIN) confermerebbe i pochi
materiali che il nome lascia ambigui.

### (d-ter) FONDI OBBLIGAZIONARI — 6 fondi Vanguard Bond Index (N-CSR vs N-PORT, 31/12/2025)
Test su un'asset class diversa (bond = principal/coupon/maturity, non shares). Il nome NON è unico (mille
Treasury/pool) → chiave COMPOSITA **nome|coupon|maturity**; unità diverse (N-CSR face $000 vs N-PORT balance $)
assorbite dalla scala di `reconcile` (=1.00000, conferma). Controllo positivo+null passati su tutti e 6.
`reconcile()` generalizza a QUALSIASI holding con chiave (qui `id_scheme='BONDKEY'`).
- **Treasury/corporate riconciliano bene:** Intermediate 8 materiali/1953, Total Bond II 9/6895 (come l'equity).
- **BUG di parsing trovato con l'auto-audit e riparato:** il face veniva scambiato con un marcatore di nota in
  testa ('2') → 169 falsi materiali su Intermediate → fix (face = primo intero DOPO la maturity) → 8 reali.
- **Due limiti d'asset-class DICHIARATI (dal dato):**
  1. **MBS pool NON matchabili senza CUSIP:** Total Bond ha 1514 collisioni di chiave (1505 sono pool: 5 pool
     "FANNIE MAE POOL|3.000|2042-05-01" diversi, stesso nome/coupon/maturity, CUSIP diversi) → match 41%. È la
     prova che i bond richiedono match a livello di **identificatore** (CUSIP/ISIN), che l'N-CSR non pubblica.
  2. **TIPS non riconciliano sul face:** scala 1.189 = aggiustamento cumulato d'inflazione (N-PORT usa il
     principal inflation-adjusted, N-CSR il face) → 55/57 "materiali" che sono un fatto contabile, non errori.
- **Lezione prodotto:** il name-matching regge sull'equity ma si ROMPE sui bond/MBS → il valore di OMEGA
  (certificare con CUSIP/ISIN quando c'è) è massimo esattamente dove il nome fallisce.

**INTEGRAZIONE CUSIP/ISIN — `reconcile(by='auto')`:** match IDENTIFIER-FIRST — chiave = ISIN (CUSIP→ISIN via
check-digit) quando la posizione lo porta, nome come fallback. **Dimostrato sul dato reale:** sui bond MBS di
Total Bond le collisioni di chiave crollano da **1514 (per nome) a 4 (per CUSIP→ISIN)** — il CUSIP distingue i
pool che nome+coupon+maturity collassava. CONFINE onesto: 'auto' allinea due fonti che portano ENTRAMBE
l'identificatore (custodian/PCF/N-PORT ↔ N-PORT); se una fonte non ha id (N-CSR, solo nome) si usa `by='name'`.
È la ragione strutturale per cui la certificazione a livello di **identificatore** (CUSIP/ISIN) — quando le
fonti lo portano — è la forma giusta del prodotto, non il nome.

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
