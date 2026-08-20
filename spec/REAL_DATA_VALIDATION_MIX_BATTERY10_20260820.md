# CryptoValid su MIX Market reale — batteria di 10 test aggiuntivi (2026-08-20)

Seguito di `REAL_DATA_VALIDATION_MIX_20260820.md` (le prime 4 invarianti). Roberto: "riesegui altri 10 test totali".
Stesso dato reale (MIX Market Financial Performance in USD, World Bank, ANN + dedup ≈ 20.096 righe), stessa
disciplina. Ogni test ricalcola un **ratio ufficiale** dai componenti grezzi e lo confronta col dichiarato.

## Guardie applicate PRIMA (auto-modello `self_errors`)
- **Il banco deve saper fallire:** ogni test ha un **controllo positivo** (corruzione del dichiarato → DEVE
  scattare). Un test il cui positivo non scatta è **INVALIDO** e non viene dichiarato — è successo davvero
  col test 10 (loan loss rate), riparato prima di riportarlo (vedi sotto).
- **Definizione esatta prima di misurare** (lezione dei rinegoziati): dove la formula non combacia, è un mio
  errore di definizione, NON un'inconsistenza reale. Verificato su righe pulite prima di girare a scala.
- **Nessuna scrittura su path di produzione:** solo lettura xlsx + calcolo in venv usa-e-getta.

## Risultato — 10 ratio ufficiali riprodotti dai grezzi
| # | Ratio (ricalcolo) | N | MATCH | residuo | positivo |
|---|---|---:|---:|---:|---:|
| 1 | Deposits / GLP | 8.982 | 100,0% | 0,0% | 46/50 |
| 2 | GLP / total assets | 18.804 | 100,0% | 0,0% | 50/50 |
| 3 | Deposits / total assets | 8.770 | 100,0% | 0,0% | 47/50 |
| 4 | female borrowers / active borrowers | 14.660 | 99,9% | 0,1% | 50/50 |
| 5 | GLP / active borrowers | 18.017 | 99,9% | 0,1% | 50/50 |
| 6 | Deposits / depositors | 7.029 | 99,9% | 0,1% | 50/50 |
| 7 | financial revenue from loans / avg GLP | 12.986 | 99,8% | 0,2% | 50/50 |
| 8 | operating expense / avg GLP | 15.201 | 99,8% | 0,2% | 50/50 |
| 9 | operating expense / avg active borrowers | 14.150 | 99,9% | 0,1% | 50/50 |
| 10 | **(write-offs − recoveries) / avg GLP** | 12.986 | 99,4% | 0,6% | 49/50 |

I positivi <50/50 (46, 47, 49) sono record con ratio piccolo dove la corruzione additiva resta sotto la
soglia **relativa** 20% (regola AND) — comportamento atteso, non cecità. Tutti ≥90% → validi.

## Il test 10 — la guardia ha funzionato (registrato)
Al primo giro il test 10 dava MATCH 98,9% ma **positivo 24/50 → INVALIDO** (banco che non sa fallire: floor
0,005 troppo alto per la scala piccola del loan-loss-rate). NON l'ho dichiarato. Riparato: (a) floor 0,0005 +
corruzione additiva +0,05 → positivo **49/50 valido**; (b) verifica definitoria: `(write-offs − recuperi)/avgGLP`
combacia al **99,4%**, `write-offs/avgGLP` solo 78,3% → confermata la def MIX (sottrae i recuperi). Risultato
onesto: MATCH 99,4%, residuo 0,6%.

## Conclusione (coerente col walk-back del report precedente)
Con **14 invarianti indipendenti** ora validate su dato reale World Bank (le 4 di prima + queste 10), il quadro
è netto e ROBUSTO: **CryptoValid ricostruisce i ratio regolatori ufficiali della microfinanza dai loro
componenti grezzi e li riproduce al 99,4–100%** su decine di migliaia di disclosure reali. Controllo positivo
(rileva le corruzioni) e null (tace sul pulito) tengono su tutti.

Honest-scope invariato: è un **verificatore di coerenza forte**, NON un rilevatore di misreporting di massa —
i residui sono minimi (0–0,6%, coda di arrotondamenti/casi di bordo). Il valore è la **riproduzione
verificabile** delle cifre pubblicate, non "trovare errori". Confine: consistenza, NON veracity; no-PII;
adozione ancora ZERO (credibilità tecnica misurata).
