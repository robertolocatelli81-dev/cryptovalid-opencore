# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Roberto Locatelli
"""SLH-DSA (FIPS 205) archival anchors, `omega-slhdsa-anchor-v2`: verification only (SPEC v0.15 §24, 2026-11-23).

Status: EXPERIMENTAL (README, "Core and experimental modules").

Ported from pq-scitt, `src/pq_scitt/anchors/slh_dsa.py` `verify_anchor` (commit 9692a74, Apache-2.0, same author; NOTICE):
the format and the signed message are those of pq-scitt; this port keeps the verification of v2 anchors and nothing else
(no key generation, no signing, no `oqs` backend, no v1 anchors), and returns a closed code instead of a bare boolean.

    verify_anchor(anchor, pub=None) -> {"valid": bool, "code": str, "detail": str}

`code` is one of CODES (SPEC §24 rule 5). The signature is checked with the `slh-dsa` package (the optional extra `slh`);
without it, an anchor that passes the format checks raises verifier.CheckNotRun (rule 6): never valid, never refused.
`slh_verify(param, pk, message, sig, ctx=b"")` is the FIPS 205 pure verification (Algorithm 24) the anchor check uses,
exposed for the NIST ACVP vectors of spec/vectors/slhdsa/.
"""
import json
import math
from typing import Any, Dict, Optional, Union

import verifier

SCHEMA = "omega-slhdsa-anchor-v2"
MEMBERS = frozenset({"schema", "backend", "param", "root", "ts", "sig", "pub"})
BACKENDS = ("slhdsa", "oqs")
# FIPS 205 Table 2: (n, signature bytes); the public key is 2n bytes. SHA2 and SHAKE sets have the same sizes.
_SIZES = {"128s": (16, 7856), "128f": (16, 17088), "192s": (24, 16224), "192f": (24, 35664),
          "256s": (32, 29792), "256f": (32, 49856)}
PARAMS = {f"{h}_{k}": v for h in ("sha2", "shake") for k, v in _SIZES.items()}
CODES = ("ok", "not_object", "schema", "members", "type", "encoding", "length", "pin", "signature")
_HEX = frozenset("0123456789abcdef")


def _out(code: str, detail: str) -> Dict[str, Any]:
    return {"valid": code == "ok", "code": code, "detail": detail}


def _is_hex(s: str) -> bool:
    return len(s) % 2 == 0 and len(s) > 0 and set(s) <= _HEX


def signed_message(param: str, root: str, ts: Union[int, float]) -> bytes:
    """SPEC §24 rule 2: the bytes the anchor's signature covers."""
    return json.dumps({"schema": SCHEMA, "param": param, "root": root, "ts": ts},
                      sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def slh_verify(param: str, pk: bytes, message: bytes, sig: bytes, ctx: bytes = b"") -> bool:
    """FIPS 205 slh_verify (Algorithm 24, pure, external interface). Raises verifier.CheckNotRun without slh-dsa."""
    if param not in PARAMS:
        raise ValueError(f"unknown SLH-DSA parameter set: {param!r}")
    try:
        import slhdsa
        import slhdsa.parameters as P
    except ImportError:
        raise verifier.CheckNotRun("SLH-DSA verification needs the slh-dsa package (pip install "
                                   "'cryptovalid-opencore[slh]'): not checked") from None
    try:
        key = slhdsa.PublicKey.from_digest(bytes(pk), getattr(P, param))
        return key.verify_pure(bytes(message), bytes(sig), bytes(ctx)) is True
    except Exception:   # noqa: BLE001 - the library raises on malformed input: that is a signature that does not verify
        return False


def verify_anchor(anchor: Any, pub: Optional[Union[str, bytes]] = None) -> Dict[str, Any]:
    """SPEC §24: verify an `omega-slhdsa-anchor-v2` (a dict, as parsed from JSON). `pub` pins the expected key."""
    if pub is not None:
        if isinstance(pub, (bytes, bytearray)):
            pin = bytes(pub).hex()
        elif isinstance(pub, str):
            pin = bytes.fromhex(pub).hex()      # ValueError when it is not hexadecimal: an error of the caller
        else:
            raise TypeError("pub: a hexadecimal string or bytes")
    if not isinstance(anchor, dict):
        return _out("not_object", "the anchor is not a JSON object")
    if anchor.get("schema") != SCHEMA:
        return _out("schema", f"schema is not {SCHEMA} (omega-slhdsa-anchor-v1 is not FIPS 205 pure: SPEC §24 rule 5)")
    if set(anchor) != MEMBERS:
        extra, missing = sorted(set(anchor) - MEMBERS), sorted(MEMBERS - set(anchor))
        return _out("members", f"unknown members {extra}, missing members {missing}")
    param, root, ts, sig, pk = anchor["param"], anchor["root"], anchor["ts"], anchor["sig"], anchor["pub"]
    if not isinstance(anchor["backend"], str) or anchor["backend"] not in BACKENDS:
        return _out("type", f"backend is not one of {list(BACKENDS)}")
    if not isinstance(param, str) or param not in PARAMS:
        return _out("type", "param is not one of the twelve FIPS 205 parameter sets")
    if not isinstance(root, str) or not root:
        return _out("type", "root is not a non-empty string")
    if isinstance(ts, bool) or not isinstance(ts, (int, float)) or (isinstance(ts, float) and not math.isfinite(ts)):
        return _out("type", "ts is not a finite JSON number")
    if not isinstance(sig, str) or not isinstance(pk, str):
        return _out("type", "sig and pub are not strings")
    if not (_is_hex(sig) and _is_hex(pk)):
        return _out("encoding", "sig and pub must be lowercase hexadecimal of whole bytes")
    n, siglen = PARAMS[param]
    if len(pk) != 4 * n or len(sig) != 2 * siglen:
        return _out("length", f"{param}: pub must be {2 * n} bytes and sig {siglen} bytes")
    if pub is not None and pin != pk:
        return _out("pin", "pub is not the pinned key")
    if not slh_verify(param, bytes.fromhex(pk), signed_message(param, root, ts), bytes.fromhex(sig)):
        return _out("signature", f"the SLH-DSA signature ({param}, pure, empty context) does not verify")
    return _out("ok", "verified with the pinned key" if pub is not None
                else "verified with the key the anchor carries: intact, not who signed it")
