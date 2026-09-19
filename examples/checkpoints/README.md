# Real checkpoints, downloaded 2026-09-19 from `https://rekor.sigstore.dev/api/v1/log`

Three Sigstore Rekor v1 checkpoints (the active shard and two inactive ones), signed by the log's **ECDSA P-256** key
(`rekor_v1.vkey`, the key `omniwitness` lists for these origins; its id `c0d23d6a` = SHA-256(DER SPKI)[:4]). They are the
positive control of `cryptovalid_checkpoint.verify_note` for signature type 0x02 and of the Go note oracle
(`verifiers/note_oracle`, transparency-dev/formats `NewECDSAVerifier`); `test_cryptovalid_witness.py` verifies them and
refuses each one with its tree size altered. Sizes at download: [2770974847, 4163431, 117740831].
