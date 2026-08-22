# PUBBLICATA (2026-08-22, approvazione Roberto «1»): https://github.com/google-agentic-commerce/AP2/issues/338
# Reference implementation Apache-2.0: https://github.com/robertolocatelli81-dev/ap2-evidence-pack
# BOZZA issue/discussion per github.com/google-agentic-commerce/AP2 — da approvare e aprire (Roberto)
# Canale consigliato dal loro CONTRIBUTING: issue/discussion PRIMA di sviluppare.
# Nota licenza: il repo AP2 è Apache-2.0; la reference implementation andrà rilicenziata
# Apache-2.0 in un repo standalone prima di linkarla (decisione di Roberto, non ancora presa).

---
Title: Dispute-time evidence: a self-contained storage format for mandates + issuer key material

## Problem

The spec already tells implementers *what* to keep for dispute resolution — "storing the
SD-JWTs, along with their disclosures, for the Mandates in their compact serialization" —
and deliberately leaves retrieval/retention mechanics outside the scope.

There is a time dimension this leaves open. Financial dispute/retention windows run to
5–7 years in several jurisdictions. An ES256 mandate is re-verifiable at dispute time only
if the verifier can still resolve the key material that was valid *at transaction time*.
Years later, JWKS endpoints are gone, keys have rotated, and issuers may no longer exist.
The classic long-term-validation answer (ETSI *AdES-LTA / RFC 4998 evidence records)
exists for AdES signatures, but nothing maps it onto AP2 mandate chains.

## Proposal (format discussion, not a normative change)

A minimal, self-contained **dispute evidence file** that any party (merchant, PSP,
credential provider) can produce at transaction time and any other party can verify
offline years later:

- the mandates in exact compact serialization (disclosures included, KB-JWT included);
- a **snapshot of the key material** used for verification, tagged with an explicit
  provenance class (x5c chain / header jwk / caller-supplied / JWKS fetched over TLS) —
  declared rather than flattened, because these capture classes carry different weight;
- cross-mandate hash bindings recomputed from the compact serializations;
- one canonical digest over the whole file, optionally anchored with an RFC 3161
  timestamp so "this key material existed and verified at time T" is attested by a
  third-party clock;
- an offline, fail-closed verifier.

We built a small working reference implementation (Python, stdlib + `cryptography`;
ES256; SD-JWT disclosure resolution; KB-JWT holder-binding verification via cnf.jwk;
RFC 3161 stamping/verification) and are happy to contribute it, adapt it to whatever
format the maintainers prefer, or simply feed findings into the spec's dispute-resolution
guidance.

Honest scope, stated upfront: such a file proves what verified against which key material
at capture time — it does not by itself prove issuer key authorization (that is what the
provenance classes declare), and it is not a substitute for qualified archiving services
where legal presumption is required (e.g. eIDAS art. 45j in the EU).

Is there interest in specifying (or even just documenting) a recommended dispute-evidence
storage format? If maintainers prefer this live outside the spec, guidance in
implementation-considerations may be enough.
---
