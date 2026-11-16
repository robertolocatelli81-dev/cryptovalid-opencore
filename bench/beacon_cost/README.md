<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# Cost of one payment check (SPEC v0.10 §18-§19)

`python3 bench/beacon_cost/cost.py [N]` measures, on the vectors of `spec/vectors/beacon/`, the median time of each part
of `cryptovalid_beacon.verify_beacon_entry` and of the whole check. Measured on 2026-11-16, N = 200 (20 for the pack
window), Intel Core i3-N305 (8 cores), one core used, `cryptography` 50.0.2, OpenSSL 3.0.22, with the machine nearly idle (load
average between 0.5 and 1.2): read the figures as an order of magnitude.

| part | Python 3.13.15, ms | Python 3.9.25, ms |
|---|---|---|
| two IBAN checks (MOD 97-10) | 0.008 | 0.012 |
| five commitments (normalisation and SHA-256) | 0.017 | 0.023 |
| payment profile (§18) | 0.007 | 0.010 |
| reading the two pulses (closed grammar) | 0.835 | 1.133 |
| pulse checks: certificate, two RSA-4096 signatures, outputValue, link, period, commitment | 0.468 | 0.493 |
| the commitment alone (SHA-512) | 0.001 | 0.002 |
| window arithmetic | 0.026 | 0.037 |
| whole check of one entry, files read from disk, no window | 2.467 | 2.909 |
| whole check with the evidence pack's window (pack verify and two openssl processes) | 55.178 | 57.843 |
| complete record: window, CRL, witnessed checkpoint in the pack, trusted list | 53.358 | 60.137 |
| one entry alone by its inclusion proof (§19 rule 14), window, CRL, witnessed checkpoint | 56.167 | 64.881 |

The window is dominated by the evidence pack's verify and the openssl processes of the RFC 3161 check (§11), not by the
beacon: a system that checks many payments verifies the pack's token once per pack.
