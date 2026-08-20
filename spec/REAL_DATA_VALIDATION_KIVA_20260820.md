# microfinance.py — validazione su DATI REALI (Kiva) + shortlist prima MFI (2026-08-20)

Ordine di Roberto: *"trova la prima MFI che usa CryptoValid e procediamo se anche Fable 5 è d'accordo."*
Gate: **Gemini Pro** (sviluppo logico via grant) + **Fable 5** (D'ACCORDO-CON-CORREZIONE, 3 correzioni incorporate).
Metro **pre-registrato e hashato PRIMA** del dato: `opencore/spec/PREREG_KIVA_20260820.md`
(SHA3-256 `db5671af0156683c646aabbb02814fcb80a0feb0ed6a1f88916691ea1d2a04fe`, `~/.omega/prereg/prereg_ledger.jsonl`).

## Stato onesto (Correzione 1 di Fable — un dataset NON è un utente)
Questo esercizio porta `microfinance.py` da **"validato su SINTETICO"** a **"validato su DATO REALE pubblico"**
per le proprietà **strutturali/di integrità**. **ADOZIONE: ZERO.** L'ordine "prima MFI che *usa* CryptoValid"
resta **APERTO**; questa ne è la precondizione onesta (una MFI approcciabile con credibilità, non un logo finto).

## Fonte reale
**Kiva GraphQL API viva** (`https://api.kivaws.org/graphql`), 600 prestiti reali (id/importo/stato/settore/paese).
Lo snapshot storico `s3.kiva.org` è **dismesso** (CNAME→footprint.net in NXDOMAIN — verificato via DoH).
Nessuna ridistribuzione del dato grezzo: calcolo locale, riporto solo numeri derivati.

## Risultato del metro pre-registrato (dato reale)
| Controllo | Esito | Numero reale |
|---|---|---|
| **V1 determinismo** | ✅ PASS | stesso digest su 2 run (`fc77fb6e…`) |
| **V2 attestazione contabile** | `identity_ok=True` | 0 violazioni `paid>loan` nel dato reale |
| **V3 mix stati reali** | osservato | 593 fundraising / 7 funded (marketplace corrente) |
| **V4 throughput** | ✅ | ~167.000 record/s su dato vero |
| **P1 controllo POSITIVO** | ✅ PASS | 5 rotture d'identità iniettate → **5/5 rilevate** |
| **P2 permuto valori** | ✅ PASS | digest cambia |
| **N1 controllo NULL** | ✅ PASS | `reconcile(P,P)` = 0 discrepanze materiali |
| **N2 permuto ordine** | ✅ PASS | digest **identico** (canonicalizzazione invariante all'ordine) |

**Verdetto:** tutti i controlli critici PASSANO su dato reale. Il tool è deterministico, la canonicalizzazione
è invariante all'ordine e sensibile ai valori, e il detector d'incoerenza NON è cieco (5/5).

### Nota di auto-audit (le correzioni vanno nei DUE sensi)
Il primo run segnava P1 `FAIL(cieco)`: era un **bug del mio harness** (leggevo chiavi `consistent/ok`
inesistenti; le vere sono `identity_ok`/`loans_inconsistent`), non del tool. Corretto → PASS. Registrato per
onestà: stavo per accusare il tool di cecità per un errore mio.

## LIMITI DICHIARATI (Correzione 3 di Fable + limite dato)
1. **Kiva è P2P crowdfunding**, non il ledger operativo privato di una MFI: lo snapshot è dato **già pubblico**.
   Prova che la pipeline regge dati reali nella forma giusta, NON che risolva il bisogno interno d'integrità
   di una MFI (quello vive sui registri privati).
2. **L'API non popola `paidAmount`** (0.00 ovunque, anche sui prestiti chiusi) → il test di riconciliazione
   sui **rimborsi reali** NON è eseguibile su questo dato. Paradossalmente **conferma la tesi**: lo split
   outstanding/rimborsato/svalutato vive sui ledger privati → è proprio lì che servirebbe CryptoValid.
3. Confine invariato: **proof-of-integrity, NON veracity** — garbage-in resta garbage.

## Chiusura del buco — motore validato su ESITI DI RIMBORSO REALI (LendingClub, 65.841 prestiti)
Il limite Kiva (nessun `paidAmount`) mi ha spinto a cercare **online, da solo**, un loan-book pubblico con lo
split completo. Trovato: **LendingClub `accepted_2007–2018Q4`** (Hugging Face `codesignal/lending-club-loan-accepted`,
resolve pubblico CDN, no-auth; scaricati i primi 45 MB via range = 65.841 righe reali). I campi `funded_amnt`,
`out_prncp` (outstanding), `total_rec_prncp` (rimborsato), `loan_status` sono **indipendenti** → test d'incoerenza
NON circolare, il pezzo che Kiva non consentiva. **Stesso metro pre-registrato**, esito:
| Controllo | Esito reale |
|---|---|
| V1 determinismo | ✅ (`32120a00…`) |
| **V2 incoerenze reali (4 invarianti non-circolari)** | **0 violazioni / 65.841** — dataset curato pulito; il detector NON dà falsi positivi (e P1 prova che *vedrebbe* le rotture) |
| V3 default-rate reale | **20,51%** sui prestiti chiusi (11.861 Charged Off / 57.832) · PAR30/90 **3,73%** |
| V4 throughput | ~100.000 record/s a scala reale |
| P1 positivo | ✅ 5/5 rotture iniettate rilevate |
| N1 / N2 canonicalizzazione | ✅ `reconcile(P,P)`=0 · ordine→digest identico |

**Scope onesto:** LendingClub è **P2P consumer USA, NON microfinanza**. Prova che il *motore* di
riconciliazione/attestazione/PAR regge un loan-book reale con lo split outstanding/rimborsato/svalutato e
produce numeri di rischio veri — **non** che il modulo sia validato *come microfinanza*. Il ponte
microfinanza-su-dato-reale resta aperto (dato che vive sui ledger privati delle MFI — vedi thesi sopra).

**Finding misurato (Kiva a scala):** su 974 prestiti storici Kiva campionati su tutto lo spazio ID, l'API
pubblica espone **solo lo stato lend-side** (funded/expired/refunded) — **0** con esito di rimborso
(in_repayment/paid/defaulted). Cioè: *nessun canale Kiva pubblico espone rimborsi/default* → triplo-conferma
che quel dato è privato per costruzione.

## Shortlist "prima MFI" — candidati REALI, raggiungibili via canali PUBBLICI (no call, no entità)
Non utenti: **candidati da approcciare**, con il fit onesto e il limite dichiarato.

1. **Kiva Field-Partner / community `build-kiva`** — fit più forte: *ogni mese le MFI partner inviano a Kiva un
   report di rimborso su tutti i borrower*. È un workflow ricorrente di riconciliazione MFI→piattaforma dove
   una prova tamper-evident dell'integrità del report ha valore reale. Canale pubblico: gruppo `build-kiva`.
   Credibilità: **ho già validato il tool sul loro dato pubblico reale** (questo report) — l'outreach non è vuoto.
   Limite da dire: Kiva ha già rating di trasparenza alto; il valore è sull'integrità del *dato inviato*, non veracity.
2. **European Microfinance Network (EMN) + Microfinance Centre (MFC)** — reti UE che raccolgono via survey i dati
   della maggioranza delle MFI europee; missione dichiarata = trasparenza/governance. Fit EU/italiano di Roberto,
   raggiungibili via sito. Valore: layer di integrità verificabile sul dato di survey conferito dalle MFI.
3. **Singole MFI UE dalla directory EMN/MFC** — istituzioni piccole dove un tool open-source, zero-dipendenze,
   self-hosted è adottabile senza vendor lock-in. Raggiungibili individualmente.

## Prossimo passo (HUMAN-GATED — non lo faccio senza OK di Roberto)
Inviare messaggi a organizzazioni esterne è un'azione **verso l'esterno**: si fa solo col tuo OK esplicito.
Quando dai il via: bozza onesta (open-source, proof-of-integrity NON veracity, "ho girato il tool sul vostro
dato pubblico, ecco i numeri"), un canale alla volta, nessuna impersonificazione, nessun claim di endorsement.
