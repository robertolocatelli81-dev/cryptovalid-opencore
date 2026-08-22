<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# SPEC — OMEGA-MICROFINANCE: evidenza verificabile e registro di sovra-indebitamento (no-PII)

**Modulo:** `opencore/microfinance.py` · **Stato:** stabile, 7/7 test · **Canon:** `microfinance-canon-1.0`
**Scopo SDG:** 1 (povertà), 8 (lavoro/crescita), 10 (disuguaglianze) — trasparenza del microcredito + protezione
del beneficiario dal debt-trap. Vedi [`spec/DPG_AUDIT.md`](DPG_AUDIT.md).

## 1. Cosa fa (e cosa NON fa — honest-scope)
Applica le primitive FUNDCERT (canonicalizzazione deterministica, digest, attestazione di coerenza, evidence
record, riconciliazione) al **portafoglio-prestiti di un istituto di microfinanza (MFI)**, e aggiunge un
**registro di sovra-indebitamento multi-MFI senza PII**.
- **PROVA (robusto):** (a) *proof-of-integrity* — il portafoglio dichiarato è tamper-evident e ri-derivabile
  bit-per-bit da un donatore/regolatore (`portfolio_digest`, SHA3-256); (b) il **PAR** (Portfolio at Risk) e i
  totali sono un'attestazione deterministica DATI i dati forniti; (c) la **riconciliazione** vista-MFI vs
  vista-donatore localizza le discrepanze; (d) il **sovra-indebitamento** cross-MFI di uno stesso beneficiario
  (hashato) è rilevabile **senza vedere PII**.
- **NON prova (limite dichiarato):** *proof-of-veracity* — NON verifica che i prestiti esistano davvero né che
  siano ben concessi (garbage-in resta garbage). Non sostituisce un credit bureau regolamentato.

## 2. Modello dati
- `LoanRecord`: `loan_id`, `borrower_ref` (**hash**, mai il nome), `principal_{disbursed,outstanding,repaid,
  written_off}`, `currency`, `days_overdue`, `status`.
- `LoanPortfolio`: `mfi_id`, `as_of`, `source`, `loans[]`, `currency`.

## 3. Privacy by design (DPG indicatore 7 / 9a)
`hash_borrower(borrower_id, salt) = sha256(salt|id)[:32]`. **L'MFI tiene il salt; il donatore vede solo
l'hash** → può contare/riconciliare/rilevare il debt-trap **senza mai vedere identità**. Nessun PII entra nel
digest, nei record o nel registro. Il campo `sector` (microcredit/microdebt) è una categoria, non PII.
Garanzia verificata dai test `test_privacy_no_pii` (payload privo di nome/PII).

## 4. Canonicalizzazione & digest (riproducibilità)
`canonical_form` normalizza gli importi (`F._canon_quantity`, Decimal esatto, niente float), ordina i prestiti
(ordine irrilevante), versiona (`canon_version`). `portfolio_digest` = SHA3-256 del canonico → **stesso
portafoglio, stesso digest**, ri-derivabile indipendentemente. Riusa il fingerprint del canonicalizzatore
FUNDCERT (provenienza del metodo verificabile).

## 5. Metriche & attestazioni
- `portfolio_at_risk(days=30)` → PAR con fail-closed sul singolo record sporco (prudenza: conta a-rischio).
- `attest_portfolio(tol_abs, tol_rel)` → record di attestazione coerenza + digest (tamper-evident).
- `reconcile_portfolios(mfi, donor_view, material_tol)` → material/minor, discrepanze localizzate.
- `borrower_debt_exposure(portfolios)` / `over_indebtedness(portfolios, max_institutions)` → **debt-trap
  cross-MFI**: un beneficiario (hash) esposto a > N istituti è segnalato. `portfolio_evidence` sigilla l'input.

## 6. Registro multi-party (opzionale, oltre il singolo portafoglio)
Per una RETE di MFI senza controllore unico: `chain/microfinance_registry.py` pubblica le esposizioni su un
ledger a consenso (`omega_chain`), aggrega per beneficiario e rileva il debt-trap; una MFI che diverge è colta
come **fork** (nessun oracolo centrale). Honest-scope: una MFI che **non partecipa** non è vista → esposizione
**sottostimata**, dichiarato (non nascosto).

## 7. Validazione (robusto vs in-attesa)
- **Sintetico:** banchi deterministici (debt-trap, no-PII, non-partecipante dichiarato, fork) — verdi.
- **Dati reali:** primitive FUNDCERT validate su **KIVA** e **MIX** (vedi `spec/REAL_DATA_VALIDATION_*`,
  `PREREG_KIVA_20260820.md`). **HONEST:** le MFI non pubblicano portafogli come i fondi SEC → la validazione
  su portafoglio-MFI reale attende i dati di un operatore. Capacità reale, non ancora provata su un operatore vivo.

## 8. Standard riusati
SHA3-256 / SHA-256 (FIPS 202/180-4), Decimal esatto (no float), evidence-record FUNDCERT, RFC 3161/6962 (nel
layer evidence di opencore). Zero dipendenze (stdlib; `cryptography` opzionale). AGPL-3.0-or-later.

## 9. Confine invalicabile
Proof-of-integrity, non veracity. No-PII by design. Non è un credit bureau né consulenza; è **infrastruttura di
verifica** (un donatore/regolatore/rete controlla i numeri senza fidarsi e senza vedere le persone).

## ⚠ LIMITE VERIFICATO (council 4-menti, 2026-08-22): cross-MFI vs no-PII
Contraddizione trovata NEL CODICE (non estrapolata) dal council e confermata alla fonte:
- `hash_borrower(id, salt)` usa un salt che **l'MFI tiene privato** (per-istituto).
- Il matching cross-MFI del sovra-indebitamento (`borrower_debt_exposure`/`over_indebtedness`) funziona **solo
  se le MFI condividono lo stesso schema di hash** → **salt CONDIVISO** → l'hash del beneficiario diventa uno
  **pseudonimo stabile e linkabile fra istituti = dato personale pseudonimizzato** (GDPR Recital 26: resta dato
  personale). Col salt **per-istituto**, lo stesso beneficiario produce hash diversi → il matching **non
  funziona**.
- CONSEGUENZA ONESTA: il "no-PII by design" **regge per il singolo portafoglio** (attestazione/PAR), ma **salta
  nell'uso cross-MFI** che giustificherebbe SDG 1/8/10. Percio' quegli SDG sono stati **RITIRATI dalla nomina DPG**
  (tenuti solo 16 + 9). `DO_NO_HARM.md` inoltre non copre il rischio "flag di esclusione dei poveri dal credito".
- FIX FUTURO (non fatto): per un cross-MFI davvero no-PII servono commitment/PSI (private set intersection) o un
  registro con pseudonimi ciechi + prova ZK, NON un hash con salt condiviso. Da progettare PRIMA di rivendicare
  l'inclusione finanziaria. Vedi [[project_confidential_attestation_20260822]] (Pedersen) come mattone parziale.
