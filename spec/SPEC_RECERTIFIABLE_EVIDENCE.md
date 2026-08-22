<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# SPEC — Re-Certifiable Evidence Format (RCE), open & vendor-neutral · v0.1

**Status:** candidate open format (v0.1, 2026-08-22). Not yet a ratified standard — a spec anyone can implement,
with a reference implementation in OMEGA. **Openly licensed (AGPL-3.0-or-later)** so it can be adopted freely.

## 1. Why this exists (the gap it fills)
Regulators now require that a computed decision be **re-verifiable years later** — US interagency SR 26-2
(Apr 2026, superseding SR 11-7) and the EU AI Act (high-risk credit/lending). Existing open standards do **not**
cover this:
- **SLSA / in-toto** standardise *build* provenance (software artifacts), not derived financial metrics or AI
  decisions.
- **eIDAS LTA / RFC 4998 ERS** standardise *document/signature* longevity, not the re-computation of a *derived
  value* with a pinned *method version*.
RCE is the missing, vendor-neutral, **offline-verifiable** format for **re-certifiable derived metrics and AI
decisions**. No lock-in: a plain SHA3-256 + canonical-JSON scheme any third party can implement.

## 2. Common rules
- **Canonicalisation:** JSON with `sort_keys=true`, separators `(",",":")`, UTF-8, no insignificant whitespace.
- **Hash:** SHA3-256 (FIPS 202), lower-case hex.
- **Digest of an object** `X`: `sha3_256(canonical_json(X))`.
- **Tamper-evidence:** every record carries `record_hash = digest(record \ {record_hash})`. Any change breaks it.
- **No PII / no raw payloads in the record:** only digests. The producer keeps the raw input/output.

## 3. Record type A — `ReverificationRecord` (a derived metric over time)
Pins a metric so it can be recomputed and compared in future years.
| Field | Meaning |
|---|---|
| `metric_id` | what is measured (e.g. `PAR30`, `credit_expected_loss`) |
| `method_id` | which method computed it (e.g. `CLDMA`, `qraft_credit_quadrature`) |
| `method_version` | **pins the code**: `spec_version` / `canon_version` / a method lineage string |
| `input_digest` | `digest(input)` — pins the data |
| `numerical_hash` | reproducibility fingerprint of the **result** (salt/time-independent) |
| `value` | human-readable result (for the auditor) |
| `as_of` | ISO date the record was sealed |
| `record_hash` | tamper-evidence (see §2) |

**Verification (re-certify in year N+K):** recompute with the *current* code+data, then classify drift:
`INPUT_DRIFT` (data changed → `input_digest` differs) · `METHOD_DRIFT` (`method_version` changed — result not
directly comparable) · `RESULT_DRIFT` (same input+method but recomputed hash differs → integrity broken) ·
`RECORD_TAMPERED`. A clean re-certification requires **none** of these.

## 4. Record type B — `DecisionRecord` (an AI / model decision)
Certifies the record of a decision even when the model is **not reproducible**.
| Field | Meaning |
|---|---|
| `decision_id` | id of the decision |
| `input_digest` | `digest(input)` (features / prompt) |
| `output_digest` | `digest(output)` (the decision) |
| `context` | `{model_id, model_version, determinism, params}` — `determinism ∈ {deterministic, nondeterministic}`, **declared** |
| `numerical_hash` | `digest(input_digest ‖ output_digest ‖ digest(context))` |
| `output_summary` | human-readable decision (optional) |
| `as_of`, `record_hash` | as §2 |

**Two honest regimes (no faking reproducibility):**
- `determinism = deterministic`: the decision **may be replayed** (re-run with the pinned version) and compared →
  `INPUT_DRIFT` / `DECISION_DRIFT`.
- `determinism = nondeterministic` (LLM/agent): the record is **verifiable and tamper-evident** (accountability:
  *"input X → decision Y, model M v.V, at time T, unaltered"*) but **NOT replayable** — this is stated in the
  record, never disguised as a reproducible result.

## 5. Honest-scope (normative)
- RCE proves **integrity** of the evidence (unaltered, internally consistent) and — for deterministic methods —
  **reproducibility** of the result. It does **NOT** prove the recorded facts are true (proof-of-integrity, not
  proof-of-veracity), nor that a decision was correct/fair, nor make a non-deterministic AI reproducible.
- **Executability over decades is out of scope.** RCE flags `METHOD_DRIFT` but assumes the pinned method is still
  runnable; preserving the runtime for re-execution in future decades (containers/emulation) is a separate,
  infrastructure-level problem RCE does not solve.
- **Anchoring in time** (that the record existed at time T) is delegated to independent witnesses — RFC 3161
  timestamps, OpenTimestamps→Bitcoin — see `SPEC_EVIDENCE_FORMAT.md`. **Long-term crypto-agility** (the hash/
  signature ageing) is delegated to a renewal chain (eIDAS-LTA / RFC 4998 style).

## 6. Relationship to existing standards
RCE **complements**, does not replace: SLSA/in-toto (builds) · eIDAS LTA / RFC 4998 (documents/signatures) ·
RFC 3161 & OpenTimestamps (time anchoring). It occupies the empty slot: **re-certifiable derived metrics and AI
decisions**, offline-verifiable, vendor-neutral.

## 7. Reference implementation (informative)
- `fintech/temporal_reverification.py` — Record type A.
- `fintech/ai_decision_audit.py` — Record type B.
- Digests/canonicalisation reuse the same SHA3-256 + canonical-JSON scheme as `committed_attestation.py` (CLDMA)
  and `fundcert_canonical.py`. Conformance vectors: to be published under `spec/vectors/`.

*RCE is a feature and a format, not a moat: determinism-for-auditability is an active field (DFAH, batch-invariant
architectures). RCE's contribution is being **open, minimal, offline-verifiable and vendor-neutral** — the public
implementation of a pattern regulators now require.*
