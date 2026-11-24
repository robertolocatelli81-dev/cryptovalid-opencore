#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Roberto Locatelli
"""Select the SLH-DSA verification vectors of spec/vectors/slhdsa/ from the NIST ACVP file (2026-11-23).

Input: gen-val/json-files/SLH-DSA-sigVer-FIPS205/internalProjection.json of usnistgov/ACVP-Server at commit
975de31eb83d87039ec88934fdc47d8c312b892d (the head of master on 2026-11-23), SHA-256 below. The rule: every test group
with signatureInterface "external" and preHash "pure" (FIPS 205 Algorithm 24, slh_verify; the twelve parameter sets),
and in each group the first case, in tcId order, of each distinct `reason` (seven reasons, one of them the valid
signature). Kept per case: tcId, parameterSet, message, context, pk, signature, testPassed, reason; dropped: the secret
key, additionalRandomness, deferred and hashAlg. Output: gzip of JSON lines, the first line the header.

    python3 tools/build_nist_acvp_slhdsa.py internalProjection.json spec/vectors/slhdsa/nist_acvp_slhdsa_sigver.jsonl.gz
"""
import gzip
import hashlib
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import verifier  # noqa: E402

SOURCE_SHA256 = "a013fc2104f4ed4799d96d51141f65b965969b2cf10646626a021b6d456ce792"
COMMIT = "975de31eb83d87039ec88934fdc47d8c312b892d"


def main(src: str, dst: str) -> int:
    raw = verifier.read_regular(src)
    if hashlib.sha256(raw).hexdigest() != SOURCE_SHA256:
        print("source file is not the one this tool selects from", file=sys.stderr)
        return 1
    rows = []
    for g in json.loads(raw)["testGroups"]:
        if g["signatureInterface"] != "external" or g["preHash"] != "pure":
            continue
        seen = set()
        for t in sorted(g["tests"], key=lambda t: t["tcId"]):
            if t["reason"] in seen:
                continue
            seen.add(t["reason"])
            rows.append({"tcId": t["tcId"], "parameterSet": g["parameterSet"], "message": t["message"],
                         "context": t["context"], "pk": t["pk"], "signature": t["signature"],
                         "testPassed": t["testPassed"], "reason": t["reason"]})
    header = {"source": "https://github.com/usnistgov/ACVP-Server", "commit": COMMIT,
              "path": "gen-val/json-files/SLH-DSA-sigVer-FIPS205/internalProjection.json", "sha256": SOURCE_SHA256,
              "selected": "2026-11-23 by tools/build_nist_acvp_slhdsa.py (see its docstring)", "cases": len(rows)}
    body = "".join(json.dumps(x, sort_keys=True, separators=(",", ":")) + "\n" for x in [header] + rows)
    with open(dst, "wb") as f:
        f.write(gzip.compress(body.encode("ascii"), mtime=0))
    print(f"{len(rows)} cases written to {dst}")
    return 0


if __name__ == "__main__":
    if hasattr(sys.stdout, "reconfigure"):   # Windows: a pipe gets the ANSI code page; this tool writes UTF-8 everywhere
        sys.stdout.reconfigure(encoding="utf-8", errors="backslashreplace")
    sys.exit(main(*sys.argv[1:3]))
