<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# Come si colloca CryptoValid/OMEGA open-core — un COMPONENTE di controllo per l'infrastruttura pubblica digitale

Documento di posizionamento **onesto** (no overclaim). Dice cosa questo progetto È, come l'open-source di questo
tipo si diffonde davvero, e — apertamente — cosa **non** è alla portata di un progetto a singolo autore.

## 1. L'identità: un layer di CONTROLLO/verifica, non una piattaforma
opencore è un **carve-out open-source, zero-dipendenze, verificabile offline**: dato un pezzo di evidenza
(ledger, portafoglio MFI, attestazione di una metrica), **un terzo qualunque ricomputa e controlla** senza
fidarsi dell'autore. Non è un core-banking, non è un sistema di pagamento, non custodisce fondi. È il **ponte di
verifica** — la funzione che nell'ecosistema DPI manca più spesso.

## 2. Come l'open-source arriva DAVVERO alle banche centrali (il modello reale)
Non per vendita: per **adozione via fondazione/ecosistema**. Esempi reali:
- **Mojaloop** (pagamenti istantanei interoperabili, open-source) — adottato dalla **Banca Centrale della
  Liberia** nel 2025 (deploy in ~73 giorni), portato dalla **Mojaloop Foundation** + partner (AfricaNenda,
  GLEIF, Visa, MOSIP).
- **MOSIP** (identità open-source a scala nazionale) — adottato da governi/banche centrali.

Lezione: l'open-source raggiunge le autorità monetarie **quando una FONDAZIONE** (governance, staff, supporto,
partner, responsabilità) lo porta. Un repository di un singolo, per quanto corretto, **non** supera procurement,
vetting pluriennale, SLA e responsabilità legale. Questo documento non lo nasconde: è il collo di bottiglia.

## 3. Il bisogno concreto e globale dove questo componente serve: il MICROCREDITO
- I **credit registry** pubblici bridge l'informazione tra prestatori, ma **coprono i prestiti sopra una
  soglia** → il **microcredito resta spesso scoperto**. L'**over-indebtedness** (debt-trap) è una crisi
  documentata a livello mondiale (CGAP: India e oltre).
- opencore offre esattamente il pezzo mancante come **bene pubblico**: un **registro di sovra-indebitamento
  multi-MFI senza PII** (`microfinance.py`, `chain/microfinance_registry.py`) + **certificazione/controllo
  verificabile** del portafoglio (proof-of-integrity, non veracity). Vedi [`spec/SPEC_MICROFINANCE.md`](spec/SPEC_MICROFINANCE.md).
- È **DPG-nominabile** (9/9 indicatori del DPG Standard — [`spec/DPG_AUDIT.md`](spec/DPG_AUDIT.md)), con
  `DO_NO_HARM.md` e `PRIVACY.md`.

## 4. Come si diffonde onestamente (adozione, non vendita)
1. **Componente DPG** integrabile in ecosistemi esistenti (partner program tipo Mojaloop, DPG registry,
   GovStack), non un prodotto stand-alone da vendere.
2. **Settore sviluppo/grant**: è lì che un contributo open-source di un singolo *viene* finanziato e usato
   (fondazioni per l'inclusione finanziaria, NLnet/NGI, istituzioni di sviluppo).
3. **Riferimento/standard**: l'open-source si diffonde per adozione e conformità (spec, vettori, conformance).

## 5. Il confine onesto (cosa NON è)
- **Non** è (ancora) adottato o affiliato ad alcuna delle iniziative citate: le nomina come *modello*, non come
  endorsement.
- **Non** garantisce la veracità dei dati (proof-of-integrity ≠ proof-of-veracity); **non** è un credit bureau
  regolamentato; **non** offre SLA legali.
- La **diffusione globale come "sistema delle banche centrali"** richiede una **fondazione/consorzio** — decisione
  e struttura che un singolo autore non ha. Senza quella leva: si **contribuiscono componenti** come beni
  pubblici; con quella leva: il modello Mojaloop diventa un percorso reale (lungo, ma reale).

## 6. Invito
Contributi, revisioni indipendenti e pilot con operatori reali sono benvenuti — specialmente **dati di un
operatore MFI** per passare dalla validazione sintetica a quella reale (l'unico gap di validazione dichiarato).
