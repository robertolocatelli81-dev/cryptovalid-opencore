#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Roberto Locatelli
"""Cost of one payment check of SPEC v0.10 §18-§19, measured on the real vectors (spec/vectors/beacon): the time of each
part and of the whole `verify_beacon_entry`, median of N runs, on this machine. Prints one JSON object. The window and
the complete record are measured on the conformance cases with an evidence pack (`window_without_checkpoint_not_complete`,
`complete_record`), so they include the pack's verify and two openssl processes. Usage, from the repository root:
    python3 bench/beacon_cost/cost.py [N]"""
import json
import os
import platform
import shutil
import statistics
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "verifiers"))   # the test helpers import pack_states_bench from there
sys.dont_write_bytecode = True
import cryptovalid_beacon as B  # noqa: E402

VB = os.path.join(ROOT, "spec", "vectors", "beacon")
N = int(sys.argv[1]) if len(sys.argv) > 1 else 200


def median_ms(fn, n=N):
    fn()
    ts = []
    for _ in range(n):
        t0 = time.perf_counter()
        fn()
        ts.append(time.perf_counter() - t0)
    return round(statistics.median(ts) * 1000, 3)


def main():
    led = os.path.join(VB, "payment_ledger.jsonl")
    p3, p2 = os.path.join(VB, "nist", "pulse_2030303.json"), os.path.join(VB, "nist", "pulse_2030302.json")
    cert = os.path.join(VB, "nist", "certificate_5b6386e6ac8a993b.pem")
    with open(led, encoding="utf-8") as f:
        data = json.loads(f.read().split("\n")[1])["data"]
    P, Q = B.parse_pulse(p3), B.parse_pulse(p2)
    out = {"python": platform.python_version(), "machine": platform.machine(), "runs": N, "median_ms": {}}
    m = out["median_ms"]
    ibans = ("GB82WEST12345698765432", "DE89370400440532013000")
    salt = bytes(16)
    m["iban_check_x2"] = median_ms(lambda: [B.iban_problem(i) for i in ibans])
    m["commitment_x5"] = median_ms(lambda: [B.commitment(k, salt, v) for k, v in zip(
        B.COMMITMENTS, ibans + ("a name", "an address", "a name"))])
    m["payment_profile"] = median_ms(lambda: B.check_payment(data))
    m["parse_two_pulses"] = median_ms(lambda: (B.parse_pulse(p3), B.parse_pulse(p2)))
    m["pulse_checks_two_rsa4096_signatures_commitment"] = median_ms(lambda: B.check_pulses(data["beacons"][0], P, Q, cert))
    m["commitment_sha512_only"] = median_ms(lambda: __import__("hashlib").sha512(bytes.fromhex(P["localRandomValue"])).digest())
    t = B.pulse_time(P["timeStamp"])
    m["window_arithmetic"] = median_ms(lambda: B.window(t, 60000, "2026-11-16T13:05:00Z", 3600))
    m["verify_beacon_entry_whole"] = median_ms(lambda: B.verify_beacon_entry(led, 1, p3, p2, cert))
    with open(os.path.join(VB, "conformance.json"), encoding="utf-8") as f:
        cases = {x["name"]: x for x in json.load(f)["cases"]}
    if shutil.which("openssl"):   # the conformance cases with an evidence pack: the pack's verify runs openssl twice
        from test_beacon_20261116 import conformance_run
        m["verify_with_pack_window_openssl"] = median_ms(
            lambda: conformance_run(cases["window_without_checkpoint_not_complete"]), n=max(5, N // 10))
        m["verify_complete_record_window_crl_checkpoint_trusted_list"] = median_ms(
            lambda: conformance_run(cases["complete_record"]), n=max(5, N // 10))
    print(json.dumps(out, indent=1))


if __name__ == "__main__":
    main()
