<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# Beacon vectors (SPEC v0.10 §18-§19)

## `nist/` — NIST Randomness Beacon 2.0, chain 2

Fetched on 2026-11-16 at about 13:06 UTC, each file the bytes the service returned (HTTP 200), unchanged:

- `pulse_<i>.json` for i = 2030298 … 2030303: `https://beacon.nist.gov/beacon/2.0/chain/2/pulse/<i>`
  (timeStamp 2026-11-16T12:59:00.000Z … 13:04:00.000Z, period 60000 ms, statusCode 0). `pulse_2030303.json` was also
  the answer of `https://beacon.nist.gov/beacon/2.0/pulse/last` at about 13:06 UTC (the same bytes).
- `certificate_5b6386e6ac8a993b.pem`: `https://beacon.nist.gov/beacon/2.0/certificate/<certificateId>` for the
  certificateId the six pulses carry (5b6386e6…ec0c18, the SHA-512 of the certificate's DER). Subject
  CN=engine.beacon.nist.gov, O=National Institute of Standards and Technology; issuer DigiCert Global G2 TLS RSA SHA256
  2020 CA1; valid from 2026-10-21 to 2027-03-20; RSA 4096 bits.

Source and terms: NIST is an agency of the U.S. federal government; works of the U.S. government are not subject to
copyright protection in the United States (17 U.S.C. §105). The values are public outputs of the beacon.

## `payment_ledger.jsonl`

Three entries made by `build_payment_ledger()` of `test_beacon_20261116.py` from `nist/pulse_2030302.json` and
`nist/pulse_2030303.json` (the test rebuilds it and compares the bytes), in the profile of SPEC §18: entry 0 a payment
carrying the outputValue of pulse 2030302, with five commitments (payer IBAN GB82WEST12345698765432, payee IBAN
DE89370400440532013000, payer name "Maria Example", payer details "Via Esempio 1, 00100 Roma, IT", payee name "Example
Supplies Ltd"); entry 1 a payment carrying the outputValue of pulse 2030303 with its two IBAN commitments (payer
DE89370400440532013000, payee GB82WEST12345698765432); entry 2 not a payment. Each salt is the first 16 bytes of
SHA-256("test salt <label> <member>") with label `v1` for entry 0 and `e1` for entry 1, and each record salt the first 32
hex characters of SHA-256("test record salt <n>"): derived so that the file is rebuilt byte for byte; a real provider
draws them at random. The IBANs are published examples, the amounts and names fictitious; no real account or person.
No IBAN or name is in clear in the ledger. The `ts` of each entry is derived from the pulse's timeStamp and is a
writer's claim, not used by the check.

## `conformance.json` and `conformance/`

The conformance cases of SPEC §19 rule 8: for each case the inputs (paths relative to this folder) and the expected
`status` and `reason`, positive and negative, plus the window of rule 5 as data (`window_cases`). Built by
`make_conformance.py` from the files above (run once on 2026-11-16; outputs committed): pulses with one member changed
or added; ledgers with one member changed and every hash recomputed; three pairs of pulses re-signed with a key made on
the spot so that the change reaches the check behind the signature (its certificate is `conformance/other/certificate.pem`,
the private key was not kept); checkpoints signed and cosigned with Ed25519 keys derived from fixed labels (log
`example.org/payments`, witnesses `witness.example/a` and `/b`, cosigned at 2026-11-16T13:00:00Z). An implementation
agrees with this format when it gives the expected status and reason for every case.

## SHA-256

```
6d3ed11789b351c1dd11a13ac6d6162bba576a9ea418b628b0a604f951ec63b5  nist/certificate_5b6386e6ac8a993b.pem
1e8ee7e76ff109485d590bb790717f8eb15a3bed3ffcd9d2426384d486bcc6ee  nist/pulse_2030298.json
bbb5f5e66c6623f639baa9a1745fdc416c5466549d5133c242c4ea1f96b76f0d  nist/pulse_2030299.json
81d1f8fc070d0403f98e0c328380c2cc2b9e58e20ea5a19873340ae16b4ae36e  nist/pulse_2030300.json
f3868640bc47ce395b595549dc44c69cb50b0231f3dd971a204834fdd4b1ba0a  nist/pulse_2030301.json
a86820a5b4ebeb8da24147fe2a4df6c490f109e3a615a8625afc754efa659ef3  nist/pulse_2030302.json
88bac288140df522909f46931670183789700d1e2f4b1fd36bd73b066b99f31b  nist/pulse_2030303.json
63147c3296976ad24980a749dac4778bdac3d14d4e993e50362b563cd8c2c1a8  payment_ledger.jsonl
```
