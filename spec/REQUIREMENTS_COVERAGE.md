# CryptoValid — Requirements coverage vs stringent regimes (honest matrix)

**Purpose (supreme-ai 2026-08-19):** the honest answer to "does CryptoValid satisfy the most stringent
global regulations" is **no single tool does** — and claiming so is the "compliance-in-a-box" overclaim.
CryptoValid produces one thing well: **tamper-evident, independently and offline-verifiable audit
EVIDENCE**, optionally anchored on-chain. That is *one cell* of the regulatory matrix, accepted by
stringent regimes **as supporting evidence**, never as compliance itself. This matrix states, per
requirement, what the evidence/anchor layer **covers / partially supports / does not cover** — the
declared out-of-scope is a feature, not a hole.

Legend: **✅ covered** (the evidence layer does this) · **🟡 partial / supporting** (contributes evidence,
does not satisfy alone) · **⬜ out of scope** (structurally not anchor-shaped — needs other controls).

| Regime | Key requirement | CryptoValid | Note |
|---|---|:--:|---|
| **eIDAS** (EU 910/2014) | *Qualified* timestamp with legal presumption (Art. 41-42) — only from a QTSP on an EU Trusted List | 🟡 | Legal weight comes from the **QTSP** in the seal path (e.g. Izenpe), **not** from a Solana anchor. Anchor = extra existence proof, not a qualified timestamp. |
| **eIDAS** | Qualified e-signature / seal | ⬜ | Needs a QTSP-issued certificate + QSCD; out of scope for the anchor layer. |
| **SEC 17a-4 / FINRA / MiFID II** | **WORM retention of the DATA** (immutable, 5–7 yrs, retrievable) | ⬜ | The anchor preserves the **hash**, not the record. WORM storage of the underlying data is a separate control — structurally not anchoring. **Biggest limit.** |
| **CBUAE / VARA record-keeping** | Retention of transaction records (years) | ⬜ | Same: hash ≠ data retention. |
| **MiCA** (EU 2023/1114) | Authorisation, governance, reserve rules, disclosures | 🟡 | Evidence packs *support* reserve-disclosure / whitepaper-input audit; authorisation & governance are organisational, out of scope. |
| **EU AI Act** (full 2026-08-02) | Risk mgmt, logging, human oversight, technical documentation (Art. 11-12) | 🟡 | ADCL/evidence supports **auditable logging & doc integrity**; risk-management system, oversight, conformity assessment are out of scope. |
| **DORA** | ICT risk management, resilience, incident reporting | ⬜ | Organisational/operational regime; evidence integrity is a small input at most. |
| **FATF Recommendation 16 (Travel Rule)** | Transmit originator/beneficiary PII between VASPs | 🟡 | The Travel-Rule *evidence* module proves transmission integrity (HMAC+salt); it does **not** move PII nor replace a Travel-Rule messaging network (e.g. Notabene). |
| **ISO/IEC 27001 · SOC 2** | ISMS controls, audited | 🟡 | Evidence packs are auditable artifacts *within* a control; certification is organisational. |
| **ISO/IEC 42001** | AI management system | 🟡 | Same shape as AI Act: supports documentation integrity, not the management system. |

## What the on-chain anchor DOES and DOES NOT prove
- **Does:** existence + timestamp + signer-identity of a digest at/before a finalized block, verifiable by
  any third party offline, decentralised (no vendor trust). *Proof-of-disclosure.*
- **Does NOT:** prove the underlying facts are true (*not proof-of-veracity*); retain the data; confer any
  qualified/legal-presumption status; guarantee durability (see decay risk below).

## Known limits to test BEFORE production (supreme-ai flagged, highest operational value)
1. **Evidence decay under RPC pruning — one measured data point (2026-08-19; claim narrowed after
   Gemini Pro + Fable 5 review).** The `cryptovalid_pruning_probe` was run once. Of 4 public RPCs probed,
   only **2 were reachable** (onfinality 429, rpcpool 403 — a reachability confound to declare). On the
   reachable pool: fresh anchors (t=0) were held by 2 RPCs; a **73.8-day-old** honest anchor was held by
   only **1** — `publicnode` had **pruned** it (`result=null`) while `mainnet-beta` still had it.
   - **ROBUST (this pool, this date):** pruning is real and *already bites at ~2.5 months on at least one
     major free RPC*; for that old anchor, `min_witnesses=2` STRICT fails **now**.
   - **EXTRAPOLATED (do not overclaim):** the exact "~2.5-month" threshold is **one data point, not a
     curve**; "all free RPCs prune this fast" is **one pruner observed**, not a class law. A scheduled
     cron re-run is needed to build the actual decay curve.
   Direction unchanged: STRICT high-assurance wants **dedicated non-pruning archive RPCs**, or
   **heterogeneous anchors** (OpenTimestamps/Bitcoin + eIDAS QTSP), or **periodic re-anchoring**.

## Bench honesty — mutation testing (hand-written, NOT systematic; claim bounded)
Iteration, walked back twice under Gemini Pro + Fable 5 + supreme-ai review:
- First pass: 6 mutants vs the *live ad-hoc bench* → only **2/6** killed (the bench had no error-tx /
  no RPC-disagreement case, a redundant hex guard, and a **signer code smell**: the verdict recomputed
  `signer == expected` separately from the displayed `signer_ok`).
- Fixes: **unified `signer_ok`** to one decision point (flotta-audited — signer was the ONLY such twin;
  the other guards were already single-variable); added a **strict-N-of-M-insufficient** test and a
  **specific 64-hex-check** assertion. Re-run vs the **unit suite**: **6/6**.
- Then supreme-ai flagged the 6 as cherry-picked (1:1 on covered guards) and named untested classes.
  Measured them with an **extended battery (5 more mutants)**: genesis-pin bypass, `_tx_signer` constant,
  `_extract_memo_digests` permissive, composer `all→any`, hex-regex rename — **all 5 killed** (the
  positive+negative tests constrain the helpers). Total: **11 hand-written mutants across all 7 decision
  guards + 3 extraction helpers + the composer, all killed**, with null control (green baseline) and
  guaranteed file restore.

**Honest bound (do NOT overclaim):** this is **confirmatory hand-written mutation**, NOT systematic tool
coverage. `mutmut`/`cosmic-ray` are **not installable** in this env (PEP 668 externally-managed) → the
systematic pass is **declared blind, not done**. Still unmutated: **higher-order/combined mutants** and
the **network / JSON-RPC parsing / RPC-selection path** (the unit suite mocks `_fetch_one`, so it covers
decision logic end-to-end only up to the mock). Defensible claim: *the suite kills every hand-written
mutant that disables a decision guard, a helper, or the composer — it does not prove a systematically
mutation-tested, network-end-to-end verifier.*
2. **Same-chain "witnesses" are not fault-independent.** N distinct Solana RPCs are read replicas of ONE
   chain (likely one client, possibly shared hosting) — they defeat a single rogue RPC, not client/
   protocol/chain compromise (~1.x witnesses, not N). **True fault-independence needs HETEROGENEOUS
   anchors: Solana + OpenTimestamps/Bitcoin + an eIDAS QTSP.**
3. **Host / key-custody compromise** is out of scope (see repo threat model): an HSM/KMS in the seal path
   is the mitigation, not the anchor.

## The honest positioning
CryptoValid is the **evidence/notarisation cell** — it makes proving things cheaper and vendor-independent
for regulated firms. It is *accepted as supporting evidence* by stringent regimes; it does not *satisfy*
them. Sell the evidence layer; never the compliance. This is the same honest-scope that held in the UAE
review (`NOT_COVERED` manifest) — declared out-of-scope is the asset.

*Provenance: supreme-ai transcript 20260819T081724Z. Regulatory citations (eIDAS Art. 41-42, SEC 17a-4,
FATF R.16, EU AI Act Art. 11-12) are asserted from public sources — verify against primary text before
relying on any single line.*
