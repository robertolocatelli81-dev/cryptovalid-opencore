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
carrying the outputValue of pulse 2030302 with every optional member of the profile: in clear `execution_date`
2026-11-16, `payee_entity_id` EXAMPLE0001 and `psp_id` EXAMPLEPSPXXX, and the thirteen commitments (payer IBAN
GB82WEST12345698765432, payee IBAN DE89370400440532013000, payer name "Maria Example", payer details "Via Esempio 1, 00100
Roma, IT", payee name "Example Supplies Ltd", EndToEndId "INV-2026-0001", and the fictitious values of `NAMES` in the test
for the tax ids, debtor, notice code, purpose, receipt id and RRN); entry 1 a payment carrying the outputValue of pulse 2030303 with its two IBAN commitments (payer
DE89370400440532013000, payee GB82WEST12345698765432); entry 2 not a payment. Each salt is the first 16 bytes of
SHA-256("test salt <label> <member>") with label `v1` for entry 0 and `e1` for entry 1, and each record salt the first 32
hex characters of SHA-256("test record salt <n>"): derived so that the file is rebuilt byte for byte; a real provider
draws them at random. The IBANs are published examples, the amounts and names fictitious; no real account or person.
No IBAN or name is in clear in the ledger; each commitment is SHA-256("cryptovalid-payment/1/" || member || 0x00 ||
salt || normalised value), SPEC §18. The `ts` of each entry is derived from the pulse's timeStamp and is a
writer's claim, not used by the check.

## `conformance.json` and `conformance/`

The conformance cases of SPEC §19 rule 8, format `cryptovalid-beacon-conformance/4`: for each case the inputs (paths
relative to this folder: ledger and entry, or for rule 14 an `entry_file` and its `proof` without the ledger; one pulse
pair per beacon value, the pinned beacon certificates, and when the case
needs them the evidence pack, the pinned TSA certificates, CRLs and trusted list, the maximum width, the checkpoint with
the pinned log and witness keys, disclosures, `required_disclosures` of rule 15) and the expected `status`, `reason` and `record_complete`. There is a
complete record (window, CRL issued after the token, witnessed checkpoint inside the pack, qualified TSA) and at least one
case for every result code of rule 8; `window_cases` gives the window of rule 5 as data. Built by `make_conformance.py`
(run on 2026-11-16; outputs committed): pulses with one member changed or added; ledgers with one member changed and
every hash recomputed; pulse pairs re-signed with RSA keys made on the spot so that the change reaches the check behind
the signature (their certificates are in `conformance/other/`, the private keys were not kept); evidence packs stamped
by TSAs made on the spot with openssl (CA certificates and CRLs in `conformance/tsa/`, private keys not kept); checkpoints
signed and cosigned with Ed25519 keys derived from fixed labels (log `example.org/payments`, witnesses
`witness.example/a` and `/b`). An implementation agrees with this format when it gives the expected status, reason and
`record_complete` for every case. The cases `profile_currency_unknown` and `profile_amount_not_canonical` pin `conformance/currency_table.json` (format
/4, SPEC §18 "Currencies"); `currency_table_pinned` and the two `..._without_currency_table` cases give the other mode.

## SHA-256

```
6d3ed11789b351c1dd11a13ac6d6162bba576a9ea418b628b0a604f951ec63b5  nist/certificate_5b6386e6ac8a993b.pem
1e8ee7e76ff109485d590bb790717f8eb15a3bed3ffcd9d2426384d486bcc6ee  nist/pulse_2030298.json
bbb5f5e66c6623f639baa9a1745fdc416c5466549d5133c242c4ea1f96b76f0d  nist/pulse_2030299.json
81d1f8fc070d0403f98e0c328380c2cc2b9e58e20ea5a19873340ae16b4ae36e  nist/pulse_2030300.json
f3868640bc47ce395b595549dc44c69cb50b0231f3dd971a204834fdd4b1ba0a  nist/pulse_2030301.json
a86820a5b4ebeb8da24147fe2a4df6c490f109e3a615a8625afc754efa659ef3  nist/pulse_2030302.json
88bac288140df522909f46931670183789700d1e2f4b1fd36bd73b066b99f31b  nist/pulse_2030303.json
af32e472aba5b091feb122eda81f74b0fb3d4f3ee552b6a546f9e767f5d53dc3  payment_ledger.jsonl
```
