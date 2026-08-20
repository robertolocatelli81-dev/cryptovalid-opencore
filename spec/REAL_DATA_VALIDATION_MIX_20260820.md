# CryptoValid su DATO DI MICROFINANZA REALE — MIX Market (World Bank), 2026-08-20

Azione autonoma online (Roberto: "trova qualcosa che puoi fare TU online"), dentro il confine: leggo dato
pubblico, calcolo in locale, nessuna ridistribuzione del grezzo. Chiude il gap lasciato da LendingClub
(che era P2P consumer, non microfinanza). **Contiene un walk-back importante di un mio errore — vedi §Auto-audit.**

## Fonte (reale, no-auth)
**MIX Market Financial Performance Dataset in USD** — il repository storico della microfinanza mondiale,
migrato nel **World Bank Data Catalog** (`dcwb0038647`). Scaricato dal CDN ufficiale
`datacatalogfiles.worldbank.org` (28 MB, 41.258 record MFI-periodo, 276 campi, 1999–2019). Filtrato ad
**annuali (ANN)** e deduplicato per (MFI, anno).

## Il test = l'uso reale di CryptoValid: verifica una cifra dichiarata contro il suo dato sottostante
Il MIX riporta sia i **componenti grezzi** (bucket di morosità, riserva perdite, write-offs) sia i **ratio
derivati** (PAR30/90, write-off ratio, risk coverage). CryptoValid **ricalcola** ogni ratio dai componenti e
lo confronta col valore **dichiarato** nello stesso record. Tolleranza fissata prima: materiale =
|dichiarato − ricalcolato| > 1pp (0,1pp per il write-off, scala piccola — dichiarato) **AND** relativo > 20%.

## Risultato — 4 invarianti indipendenti (definizione MIX corretta: PAR include i rinegoziati)
| Invariante | Ricalcolo | Disclosure | **MATCH** | Residuo | Controllo positivo |
|---|---|---:|---:|---:|---|
| **PAR30** | (portafoglio>30gg **+ rinegoziati**) / GLP | 12.464 | **97,6%** | 2,4% | ✅ |
| **PAR90** | (portafoglio>90gg **+ rinegoziati**) / GLP | 7.215 | **99,9%** | 0,1% | ✅ |
| **Write-off ratio** | write-offs / avg GLP | 13.044 | **99,9%** | 0,09% | 49/50¹ |
| **Risk coverage** | riserva perdite / (portafoglio>30gg + rinegoziati) | 11.446 | **96,9%** | 3,1% | 40/50¹ |

¹ I "non-flag" del controllo positivo sono record con ratio già alto dove la corruzione additiva resta sotto
la soglia **relativa** 20% (regola AND) — comportamento atteso della tolleranza dichiarata, **non cecità del
detector**. Verificato caso per caso (es. write-off 0,39; ~8 record risk-coverage con rc≥1,2).

- **Controllo NULL:** su tutti i MATCH il test **tace** (nessun falso positivo).
- Il MATCH del 96,9–99,9% **valida fortemente il ricalcolo** su dato reale, su 4 formule indipendenti e decine
  di migliaia di istituzioni-anno: la formula ricostruita coincide con quella ufficiale del World Bank/MIX.

## §Auto-audit — le correzioni sono andate nei DUE sensi, e MI HANNO CORRETTO TRE VOLTE
1. **Prima headline ritirata:** il run iniziale (senza filtro ANN/dedup) dava "8,5% incoerenti" — contaminato
   da righe trimestrali/duplicate e sub-campi in scala diversa. Rifatto con ANN + dedup.
2. **Seconda ipotesi ritirata:** avevo supposto il residuo "quasi sempre implausibile"; misurato il contrario.
3. **★ Walk-back principale (il più importante):** avevo riportato **PAR30 = 91,8% MATCH, 7,9% "inconsistenze
   reali scovate"**. FALSO come causa: la definizione MIX di PAR **include i prestiti rinegoziati** nel
   numeratore, che io avevo **escluso**. Col numeratore corretto il MATCH sale a **97,6%** (PAR90: 85,6%→99,9%;
   risk coverage: 88,2%→96,9%). Cioè: **la maggior parte del mio "7,9%" era un mio errore definitorio, non un
   difetto delle MFI.** L'ho scoperto testando il denominatore alternativo (`+rinegoziati`) come controllo.
   Rischio nominato e schivato: stavo per pubblicare un "CryptoValid scova l'8% di misreporting nella
   microfinanza" che era in gran parte il MIO bug — classico self-confirming prior. La correzione onesta
   DEFLAZIONA il risultato, e va bene così.

## Conclusione onesta (rivista)
- **Cosa è ROBUSTO:** CryptoValid ricostruisce 4 ratio regolatori ufficiali della microfinanza dai loro
  componenti grezzi e li riproduce al **96,9–99,9%** su decine di migliaia di disclosure reali del World Bank.
  È un **verificatore di coerenza forte e validato su dato vero**, con controllo positivo (rileva le corruzioni
  iniettate) e null (tace sul pulito) che tengono.
- **Cosa NON è (honest-scope):** NON scova misreporting di massa nella microfinanza. Il residuo è piccolo
  (0,1–3,1%) e include ancora casi **definitori di bordo** (trattamento parziale dei rinegoziati, restatement,
  arrotondamenti) accanto a poche anomalie vere. Il residuo è una **coda di candidati da rivedere**, non un
  tasso d'errore delle istituzioni.
- **Lezione di metodo (vale oltre questo caso):** il potere di un verificatore dipende (a) dall'INDIPENDENZA
  delle fonti della cifra controllata e (b) dall'implementare la definizione ESATTA. Sbagliare la definizione
  fabbrica falsi positivi che sembrano "scoperte". Il valore reale è la riproduzione verificabile, non un
  numero di "errori trovati".
- Confine invariato: **proof-of-integrity / consistenza, NON veracity**. Nessuna PII (dato istituzionale
  pubblico). Adozione: **ancora ZERO** — questo è credibilità tecnica misurata, non un utente.

## Provenienza
Metro coerente con `opencore/spec/PREREG_KIVA_20260820.md` (SHA3 `db5671af`). Fonte MIX: World Bank Data Catalog
(`dcwb0038647`), "Financial Performance in USD", versione 2023-01-19. Analisi in venv usa-e-getta (openpyxl),
python di sistema non toccato.
