<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# Cost of one payment check (SPEC v0.10 §18-§19)

`python3 bench/beacon_cost/cost.py [N]` measures, on the vectors of `spec/vectors/beacon/`, the median time of each part
of `cryptovalid_beacon.verify_beacon_entry` and of the whole check. Measured on 2026-11-16, N = 200 (20 for the pack
window), Intel Core i3-N305 (8 cores), one core used, `cryptography` 50.0.2, OpenSSL 3.0.22, while another job ran on
the machine (load average about 1): read the figures as an order of magnitude.

| part | Python 3.13.15, ms | Python 3.9.25, ms |
|---|---|---|
| two IBAN checks (MOD 97-10) | 0.008 | 0.012 |
| five commitments (SHA-256) | 0.004 | 0.007 |
| payment profile (§18) | 0.005 | 0.007 |
| reading the two pulses (closed grammar) | 0.897 | 1.161 |
| pulse checks: certificate, two RSA-4096 signatures, outputValue, link, period, commitment | 0.511 | 0.530 |
| the commitment alone (SHA-512) | 0.001 | 0.002 |
| window arithmetic | 0.040 | 0.060 |
| whole check of one entry, files read from disk, no window | 2.491 | 3.293 |
| whole check with a witnessed checkpoint (Ed25519) | 3.444 | 3.557 |
| whole check with the evidence pack's window (pack verify and two openssl processes) | 54.923 | 58.166 |

The window is dominated by the evidence pack's verify and the openssl processes of the RFC 3161 check (§11), not by the
beacon: a system that checks many payments verifies the pack's token once per pack.
