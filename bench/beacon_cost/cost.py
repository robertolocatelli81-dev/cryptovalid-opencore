#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Roberto Locatelli
"""Cost of one payment check of SPEC v0.10 §18-§19, measured on the real vectors (spec/vectors/beacon): the time of each
part and of the whole `verify_beacon_entry`, median of N runs, on this machine. Prints one JSON object. The window is
measured with a pack stamped by a TSA made on this machine (openssl), so it includes the evidence pack's verify and two
openssl processes; the uniqueness with the conformance checkpoint. Usage, from the repository root:
    python3 bench/beacon_cost/cost.py [N]"""
import contextlib
import io
import json
import os
import platform
import shutil
import statistics
import sys
import tempfile
import time

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "verifiers"))
sys.dont_write_bytecode = True
import cryptovalid_beacon as B  # noqa: E402
import evidence_pack as EP  # noqa: E402

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
    m["pulse_checks_two_rsa4096_signatures_commitment"] = median_ms(lambda: B.check_pulses(data["beacon"], P, Q, cert))
    m["commitment_sha512_only"] = median_ms(lambda: __import__("hashlib").sha512(bytes.fromhex(P["localRandomValue"])).digest())
    t = B.pulse_time(P["timeStamp"])
    m["window_arithmetic"] = median_ms(lambda: B.window(t, 60000, "2026-11-16T13:05:00Z", 3600))
    m["verify_beacon_entry_whole"] = median_ms(lambda: B.verify_beacon_entry(led, 1, p3, p2, cert))
    with open(os.path.join(VB, "conformance.json"), encoding="utf-8") as f:
        c = next(x for x in json.load(f)["cases"] if x["name"] == "witnessed_unique")
    cp = os.path.join(VB, c["checkpoint"])
    m["verify_with_witnessed_checkpoint"] = median_ms(
        lambda: B.verify_beacon_entry(led, 1, p3, p2, cert, checkpoint=cp, log_vkeys=c["log_vkeys"],
                                      witness_vkeys=c["witness_vkeys"]))
    if shutil.which("openssl"):
        from pack_states_bench import LocalTsa
        td = tempfile.mkdtemp()
        try:
            os.makedirs(os.path.join(td, "tsa"))
            tsa = LocalTsa(os.path.join(td, "tsa"))
            pack = os.path.join(td, "pack")
            with contextlib.redirect_stdout(io.StringIO()):
                EP.build_pack([led], pack, subject="cost")
            with open(os.path.join(pack, "MANIFEST.json")) as f:
                man = json.load(f)
            man["rfc3161_timestamp"] = {"anchored": True, "tsa": "local", "tsr_b64": tsa.token(man["manifest_digest_sha256"])}
            with open(os.path.join(pack, "MANIFEST.json"), "w") as f:
                json.dump(man, f)
            m["verify_with_pack_window_openssl"] = median_ms(
                lambda: B.verify_beacon_entry(led, 1, p3, p2, cert, pack_dir=pack, tsa_certs=[tsa.j("ca.crt")],
                                              max_window_s=10 ** 9), n=max(5, N // 10))
        finally:
            shutil.rmtree(td)
    print(json.dumps(out, indent=1))


if __name__ == "__main__":
    main()
