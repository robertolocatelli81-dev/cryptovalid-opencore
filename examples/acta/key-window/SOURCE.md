# key-window vectors — vendored, not ours

These eight files are copied verbatim from **ScopeBlind/agent-governance-testvectors**,
`verifier-vectors/key-window/`, as merged into `main` by PR #26 (merge commit `1e24b5687`, 24 September
2026). They are not our work: they are the conformance bench for §5.5 of
draft-farley-acta-signed-receipts-04, and we vendor them so `test_cryptovalid_acta.py` can run them
offline without a network fetch.

`index.json` states three things per case — the expected verdict, the expected `code`, and the
`key_status` the verifier must report. All three are checked; scoring only the verdict would miss a
verifier that reaches the right answer for the wrong reason.

Re-fetch with:

    gh api repos/ScopeBlind/agent-governance-testvectors/contents/verifier-vectors/key-window \
      --ref 1e24b5687
