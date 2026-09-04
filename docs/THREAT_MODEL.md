# Threat Model — CryptoValid evidence stack (evidence packs · AP2 · post-quantum)

*Status: 2026-09-03. Scope covers the crypto-relevant surfaces built/hardened over the
last 10 days, in their current state. Honest-scope is a first-class requirement: this
document states what is protected AND, explicitly, what is NOT. Every mechanism below is
implemented in code cited by module; claims a 4-mind review could not verify are marked.*

---

## 1. Assets

| Asset | Meaning |
|---|---|
| **Integrity** | An evidence record / envelope / ledger entry is byte-exactly what was produced. |
| **Authenticity** | A named producer (device / organisation) actually signed it. |
| **Confidentiality** | Payload readable only by the intended recipient device. |
| **Freshness / anti-replay** | A message is recent and accepted at most once. |
| **Long-term validity** | The above survive a 5–7 year retention window, incl. the quantum transition. |
| **Attributability** | Two-party proof of a handover (sender record + receiver receipt). |

## 2. Adversaries

- **A1 — Network / transport attacker**: reads, drops, reorders, replays, or injects bytes on any transport (AirDrop/Quick Share/Huawei Share/BLE/HTTP drop point/QR). No key material.
- **A2 — Malicious sender/device**: a paired-or-unpaired device that crafts hostile envelopes, malformed inputs, or forged claims.
- **A3 — Malicious verifier input**: an attacker who controls the file/pack fed to a verifier (tampered ledger, dup-keys, non-portable numbers, oversized/deeply-nested JSON).
- **A4 — Insider admin**: someone who can enroll devices or issue policy under the organisation root.
- **A5 — Compromised organisation root**: the CA-equivalent key is stolen.
- **A6 — Future quantum adversary (CRQC)**: appears within the retention window and can break classical signatures (Ed25519/ECDSA/RSA) — NIST IR 8547 deprecates classical ~2030, disallows ~2035.
- **A7 — Endpoint compromise**: the OS/app or the enclave host is fully compromised.

## 3. What is protected — mechanism → adversary

| Property | Mechanism (module) | Stops |
|---|---|---|
| Integrity | Canonical SHA3/SHA-256 content-binding — the verifier RECOMPUTES the digest from bytes, never trusts a declared field (`canonical.py`, `verifier.py`, `device.py open_envelope`). Strict **acceptance profile** (no floats, no NaN/∞, ints in ±(2⁵³−1), no duplicate keys incl. escaped) enforced identically by Python/JS/Rust/Swift, machine-checked by `verifiers/differential_oracle.py` → 0 disagreements. | A1, A3 |
| Authenticity | Ed25519 / ECDSA-P256 signature over the canonical body; `device_id = "dev-"+sha256(pubkey)[:16]` so an id cannot be claimed without the key; **key pinning** (`DeviceTrust`, `OrgTrust`). AP2 producer signature is pinnable (`trusted_producer_keys`). `valid` = integrity; **`authenticated`** = a trusted signer — read the latter. | A1, A2 |
| Confidentiality | Ephemeral X25519 → HKDF-SHA3-256 → ChaCha20-Poly1305 (or a stdlib SHAKE256/HMAC suite), AAD binds `{sender, recipient, nonce, inner_type}` (`interop/confidential.py`). | A1 |
| Anti-replay | `ReplayGuard` keyed on `(sender, nonce)`, **age-pruned** (retention ≥ max_age), **fail-closed** under flood (never silently forgets a fresh nonce). | A1 |
| Freshness | UTC `created_utc` + `max_age_s`; an organisation policy can only TIGHTEN it, never loosen. | A1 |
| Zero-touch trust | Organisation root signs device **credentials** carried in every envelope; a device that trusts the root trusts every enrolled device; keys pinned; a stolen credential on a different key is rejected. | A2 |
| Policy enforcement | Signed, versioned policy: which role may send which record kind to whom, `require_encryption`, `require_pq`, allowed algs/keystores — enforced on send AND receipt, fail-closed; downgrade/rollback refused. | A2, A4 |
| Revocation | Signed, **sequenced** CRL (rollback-refused); credential validity windows; revoked devices dropped from cache immediately. | A2, A4 |
| Hardware key custody | `hwkeys.ExternalSigner` brokers signing to Secure Enclave / StrongBox / HUKS / TPM; the private key never enters the toolkit process. | A7 (partial: protects the key, not a signing request from a compromised app) |
| Long-term / quantum | Hybrid **ML-DSA-65** (FIPS 204, validated `cryptography` backend) co-signature over evidence packs (`sigsuite.py`, `ap2_evidence.sign_evidence`); RFC 4998 renewal (`longterm_evidence.py`); crypto-agility via declared `sig_alg`. | A6 (for the PACK signature) |
| Producer-signature soundness | `verify_producer_block` is fail-closed: `ok` requires ≥1 real PASS, 0 FAIL, **0 SKIP** (an unknown alg / missing PQ backend surfaces `incomplete`, never a green). | A2, A3 |
| Timestamp authenticity | `timestamp.verify` runs `openssl ts -verify -CAfile <anchor>` and returns `verified:True` ONLY on a real signature+chain check; **without a supplied TSA trust anchor it returns `verified:None`**, never a green. | A2 |

## 4. What is NOT protected (explicit)

- **Truth of declared facts.** A signature proves who signed and that nothing changed — NOT that a declared GPS fix, timestamp, checklist answer, or mandate content is true. `geo()` is labelled `device-declared`.
- **Confidentiality of low-entropy attested attributes.** `attestation` protects *unlinkability* across records; the per-record salt is disclosed and `matches()` is a public oracle, so an enumerable value (birthdate, over-18, formatted ID) is brute-forceable. It is a linkability primitive, not value hiding.
- **Metadata.** Sender/recipient device ids and record kinds are visible by design (the signature covers them).
- **Compromised organisation root (A5).** The root is a single point of trust; its theft forges any credential. Mitigation is operational (offline / HSM / KMS), not cryptographic.
- **Insider admin abuse (A4).** An admin can enroll a hostile device under a valid role; policy limits blast radius but does not stop a legitimately-issued credential.
- **Endpoint / enclave-host compromise (A7).** A compromised app can request signatures the user did not intend; hardware custody protects the key, not the request.
- **`valid` is not authenticity.** A self-made ledger anchor makes `valid:True` (integrity/time). Integrators MUST read `authenticated` / the authenticity layer, never branch on `valid` alone.
- **No confidentiality in the base envelope.** Only with `encrypt_to`; otherwise integrity/authenticity only.
- **Forward secrecy for the recipient.** The recipient X25519 key is static (no PFS).
- **Timestamp without a trust anchor.** No `ca_file` ⇒ the RFC 3161 token is decoded but UNVERIFIED (`verified:None`).
- **Lone UTF-16 surrogates (residual).** Rust/Swift reject them; Python/JS acceptance is a documented residual to close.

## 5. Unverified / out-of-lab (honest)

- **ArkTS (HarmonyOS) adapter** is corrected (SPKI key wrapping, fail-closed verify) and Node-contract-tested, but **not compiled on a real HarmonyOS device** (no DevEco). Device validation required.
- **Swift Apple/CryptoKit path** is compiled+tested on Linux via swift-crypto; the on-device CryptoKit build is the same source behind a conditional import but not compiled on macOS here.
- **Hardware unhappy paths** (TPM lockout, Secure Enclave biometry timeout) are not yet exercised with tests.

## 6. Trust boundaries

```
[Producer device] --sign(Ed25519/P-256)--> [evidence pack] --any transport (untrusted)--> [Verifier]
       |  key in enclave (ExternalSigner) or software seed (0600)                          |  recomputes digest, checks
       |                                                                                    |  signature+pinned key+policy+freshness+replay
[Organisation root] --sign--> [credential / policy / CRL] --distributed (untrusted)--------/
   (offline / HSM — single point of trust)
```
Everything crossing an untrusted boundary is verified at the receiver; nothing is trusted because it "came from" a channel.
