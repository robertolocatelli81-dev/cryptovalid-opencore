#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Roberto Locatelli
"""Builds the negative tokens of spec/vectors/rfc3161/ (SPEC §11). Run once on 2026-11-13; the outputs are committed, the
throwaway keys are not (a new run gives other bytes and the same outcomes). Needs openssl. Usage, from the repository root:
    python3 spec/vectors/rfc3161/make_negatives.py
- forged_cms_not_tstinfo.der: a CMS SignedData signed with a key made on the spot, eContentType 1.2.3.4, content = the
  digest's OCTET STRING (04 20 <digest>);
- self_tsa.tsr: a well-formed TimeStampResp over the vector digest from an openssl TSA whose key is made on the spot (a real
  TSTInfo, nobody's TSA);
- self_tsa_sha1.tsr: the same TSA, SHA-1 imprint of data.txt;
- freetsa_signature_altered.tsr: freetsa.tsr with the last byte of its signature value flipped.
forged_cms_octet_string.der is the blob of the measurement of 2026-11-13 (eContentType id-data, content 04 20 <digest>)."""
import hashlib
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(HERE))))
sys.dont_write_bytecode = True
import cryptovalid_tsa as T  # noqa: E402

CNF = """[ req ]
distinguished_name = dn
prompt = no
[ dn ]
CN = nobody's TSA
[ ext ]
extendedKeyUsage = critical,timeStamping
basicConstraints = CA:FALSE
[ tsa ]
default_tsa = t1
[ t1 ]
serial = {d}/serial
crypto_device = builtin
signer_cert = {d}/tsa.crt
signer_key = {d}/tsa.key
signer_digest = sha256
default_policy = 1.2.3.4.1
digests = sha1, sha256
ess_cert_id_alg = sha256
"""


def run(*a):
    return subprocess.run(list(a), check=True, capture_output=True)


def main():
    data = os.path.join(HERE, "data.txt")
    digest = hashlib.sha256(open(data, "rb").read()).digest()
    d = tempfile.mkdtemp(prefix="rfc3161-neg-")
    j = lambda n: os.path.join(d, n)  # noqa: E731
    with open(j("tsa.cnf"), "w") as f:
        f.write(CNF.format(d=d))
    with open(j("serial"), "w") as f:
        f.write("01\n")
    run("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", j("tsa.key"), "-out", j("tsa.crt"),
        "-days", "2", "-config", j("tsa.cnf"), "-extensions", "ext")
    with open(j("content.bin"), "wb") as f:
        f.write(T._tlv(0x04, digest))
    run("openssl", "cms", "-sign", "-binary", "-nodetach", "-econtent_type", "1.2.3.4", "-in", j("content.bin"),
        "-signer", j("tsa.crt"), "-inkey", j("tsa.key"), "-outform", "DER", "-out", os.path.join(HERE, "forged_cms_not_tstinfo.der"))
    run("openssl", "ts", "-query", "-digest", digest.hex(), "-sha256", "-cert", "-out", j("q.tsq"))
    run("openssl", "ts", "-reply", "-config", j("tsa.cnf"), "-section", "t1", "-queryfile", j("q.tsq"),
        "-out", os.path.join(HERE, "self_tsa.tsr"))
    run("openssl", "ts", "-query", "-data", data, "-sha1", "-cert", "-out", j("q1.tsq"))
    run("openssl", "ts", "-reply", "-config", j("tsa.cnf"), "-section", "t1", "-queryfile", j("q1.tsq"),
        "-out", os.path.join(HERE, "self_tsa_sha1.tsr"))
    # the signature value: the last OCTET STRING of the one SignerInfo, read with the closed reader of SPEC §11
    raw = open(os.path.join(HERE, "freetsa.tsr"), "rb").read()
    tok = T.parse_token(raw)["token_der"]
    sd = T._der_items(T._der_one(T._der_items(T._der_one(tok, "ci", 0x30), "ci")[1][1], "sd", 0x30), "sd")
    si = T._der_items(T._der_one(sd[-1][1], "sis", 0x30), "si")
    sig = [v for t, v in si if t == 0x04][-1]
    i = raw.rindex(sig) + len(sig) - 1
    bad = bytearray(raw)
    bad[i] ^= 0x01
    with open(os.path.join(HERE, "freetsa_signature_altered.tsr"), "wb") as f:
        f.write(bytes(bad))
    for n in ("tsa.key", "tsa.crt", "tsa.cnf", "serial", "serial.old", "content.bin", "q.tsq", "q1.tsq"):
        if os.path.exists(j(n)):
            os.unlink(j(n))
    os.rmdir(d)


if __name__ == "__main__":
    main()
