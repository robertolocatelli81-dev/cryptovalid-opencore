# key-window vectors — vendored, not ours

These eight files are copied verbatim from **ScopeBlind/agent-governance-testvectors**,
`verifier-vectors/key-window/`, as merged into `main` by PR #26 (merge commit `1e24b5687`, 24 September
2026). They are not our work: they are the conformance bench for §5.5 of
draft-farley-acta-signed-receipts-04, and we vendor them so `test_cryptovalid_acta.py` can run them
offline without a network fetch.

`index.json` states three things per case — the expected verdict, the expected `code`, and the
`key_status` the verifier must report. All three are checked; scoring only the verdict would miss a
verifier that reaches the right answer for the wrong reason.

Re-fetch the exact bytes (the raw file at the full commit; each file ends with a newline):

    C=1e24b568747bcc8c9fa379d1201a0beb6f472178
    for f in after-valid-until at-valid-from at-valid-until before-valid-from index inside jwks jwks-no-window; do
      curl -sf -o "$f.json" \
        "https://raw.githubusercontent.com/ScopeBlind/agent-governance-testvectors/$C/verifier-vectors/key-window/$f.json"
    done

Then compare the files with `KW_SHA256` in `test_cryptovalid_acta.py` (`sha256sum *.json`).

Correction, 26/09/2026: the copies vendored on 24/09, shipped in 0.16.0 and 0.16.1, lacked the final newline of each
file (one byte per file), so "copied verbatim" was not true; the JSON content was identical and no verdict changes.
The files now carry the upstream bytes, and `KW_SHA256` pins those bytes. The re-fetch command printed here before
(`gh api … --ref 1e24b5687`) does not run: `gh api` 2.92.0 rejects `--ref` as an unknown flag (exit 1).
