#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
cryptovalid_solana.py — NATIVE verification of a Solana public-chain anchor for CryptoValid.

CryptoValid anchors evidence natively via RFC 3161 timestamps and Merkle STH roots. This
module adds a SECOND, independent anchor: a Solana mainnet transaction whose SPL-memo carries
the evidence digest (`sha3:<hex>`). Given a tx signature and the expected digest, it queries
Solana JSON-RPC (READ-ONLY) and confirms the digest is on a public chain, finalized, immutable.

HONEST SCOPE (read this — it is the whole point):
  A Solana anchor proves ONLY: this exact digest was committed to a public, finalized ledger at
  a specific time and cannot be altered. It does NOT prove the upstream evidence is true, nor
  that the memo author was authorised — the memo is arbitrary text chosen by whoever signs the
  tx. Anyone can anchor any hash. Binding the anchor to an identity requires `expected_signer`
  (the fee-payer pubkey you trust); without it, the anchor is existence+timestamp only. The
  authorised/authentic judgement is CryptoValid's other layers (ESMA register, KMS signature).

Adversarial design review by Gemini Pro (2026-08-18) drove these defences, each a FALSE-POSITIVE
vector it named:
  - fake cluster / rogue RPC → pin the mainnet genesis hash; require N-of-M RPC agreement.
  - fragile log parsing → extract the memo from the PARSED spl-memo instruction, not logMessages.
  - chain reorg → commitment='finalized'.
  - truncated-hash collision → require full 64-hex lowercase match.
  - failed-but-err-null tx → require meta.err is null.

Stdlib only. No keys, no writes, no signing. Fail-closed and honest on every uncertainty.

Author: Roberto Locatelli + Noûs, 2026 — Licence: AGPL-3.0-or-later (opencore).
"""
import json
import re
import urllib.request
import urllib.parse

# The one true Solana mainnet-beta genesis hash. A tx "confirmed" by an RPC that reports any
# other genesis hash is on a different (possibly attacker-run) cluster → reject. (Verified live
# 2026-08-18 from two independent RPCs.)
MAINNET_GENESIS = "5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d"
MEMO_PROGRAM_IDS = {
    "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr",       # spl-memo v2 (current)
    "Memo1UhkJRfHyvLMcVucJwxXeuD728EqVDDwQDxFMNo",       # spl-memo v1 (legacy)
}
DEFAULT_RPCS = (
    "https://api.mainnet-beta.solana.com",
    "https://solana-rpc.publicnode.com",
)
_HEX64 = re.compile(r"^[0-9a-f]{64}$")

_SCOPE = ("A Solana anchor proves existence + timestamp + immutability of the digest on a public "
          "finalized chain — NOT that the upstream evidence is true nor (without expected_signer) "
          "who anchored it. Authorised/authentic is judged by CryptoValid's other layers.")


def _rpc(url, method, params, timeout):
    """One JSON-RPC call. Only http/https (closes CWE-22 / B310). Returns result or raises."""
    if urllib.parse.urlparse(url).scheme not in ("http", "https"):
        raise ValueError(f"scheme not allowed (http/https only): {url!r}")
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    req = urllib.request.Request(url, data=body,
                                 headers={"Content-Type": "application/json",
                                          "User-Agent": "cryptovalid-solana/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as r:  # nosec - scheme validated above
        d = json.loads(r.read().decode())
    if "error" in d:
        raise ValueError(f"rpc error: {str(d['error'])[:120]}")
    return d.get("result")


def _extract_memo_digests(tx):
    """Extract sha3:<hex> digests from the PARSED spl-memo instruction(s) — NOT from logMessages.
    logMessages are debug output and forgeable; the instruction data is the canonical memo.
    Returns the set of lowercase hex digests found in memos issued by the memo program."""
    digests = set()
    msg = (tx or {}).get("transaction", {}).get("message", {})
    instrs = list(msg.get("instructions", []))
    for inner in (tx or {}).get("meta", {}).get("innerInstructions", []) or []:
        instrs.extend(inner.get("instructions", []))
    for ix in instrs:
        if ix.get("programId") not in MEMO_PROGRAM_IDS and ix.get("program") != "spl-memo":
            continue
        # jsonParsed puts the memo string in `parsed` (a str) for spl-memo
        memo = ix.get("parsed")
        if not isinstance(memo, str):
            continue
        for m in re.findall(r"sha3:([0-9a-fA-F]{64})", memo):
            digests.add(m.lower())
    return digests


def _fetch_one(rpc, signature, timeout):
    """Fetch (genesis, tx) from one RPC. Returns dict with what this RPC asserts, or an error."""
    try:
        genesis = _rpc(rpc, "getGenesisHash", [], timeout)
        # maxSupportedTransactionVersion=0 covers legacy + v0 txs (every tx type that exists on
        # Solana today). A future v1+ would need this bumped — documented limit, not silent.
        tx = _rpc(rpc, "getTransaction",
                  [signature, {"encoding": "jsonParsed", "commitment": "finalized",
                               "maxSupportedTransactionVersion": 0}], timeout)
        return {"rpc": rpc, "genesis": genesis, "tx": tx, "reachable": True}
    except Exception as e:  # noqa: BLE001 - one RPC down must not sink the verdict
        return {"rpc": rpc, "reachable": False, "error": f"{type(e).__name__}: {str(e)[:80]}"}


def _tx_signer(tx):
    keys = tx.get("transaction", {}).get("message", {}).get("accountKeys", [])
    if not keys:
        return None
    first = keys[0]
    return first.get("pubkey") if isinstance(first, dict) else first


def verify_solana_anchor(signature, expected_sha3_hex, rpcs=DEFAULT_RPCS, timeout=20,
                         expected_signer=None):
    """Verify that `expected_sha3_hex` is anchored on Solana mainnet by tx `signature`.

    Fail-closed: every hard check must pass. Returns {ok, checks[], onchain, honest_scope}.
    `expected_signer`: if given, the tx fee-payer must equal it (binds anchor→identity).

    Scope of tx support: legacy + v0 transactions (every tx type on Solana today); a future v1+
    would need the RPC's maxSupportedTransactionVersion bumped — a documented limit, not silent.

    On the N-of-M question (Gemini's design review): free public RPCs PRUNE historical txs, so
    "N independent confirmations" is unattainable for months-old anchors. The realistic, honest
    defence is: (1) genesis-pin every reachable RPC to the real mainnet — a fake cluster is
    rejected; (2) require that NO reachable RPC that has the tx CONTRADICTS another (a lying RPC
    is caught the moment a second honest archive disagrees); (3) accept a single archive witness
    but DECLARE it as single-source, never dressing it up as cross-confirmed. For adversarial
    assurance, pass multiple independent ARCHIVE endpoints.
    """
    checks = []

    def add(name, ok, note=""):
        checks.append({"check": name, "ok": ok, "note": note})
        return ok

    exp = (expected_sha3_hex or "").strip().lower()
    if not _HEX64.match(exp):
        add("expected digest is 64-hex sha3-256", False, f"got {expected_sha3_hex!r}")
        return {"ok": False, "checks": checks, "onchain": None, "honest_scope": _SCOPE}
    add("expected digest is 64-hex sha3-256", True)

    results = [_fetch_one(rpc, signature, timeout) for rpc in rpcs]
    reachable = [r for r in results if r.get("reachable")]
    if not reachable:
        add("at least one RPC reachable", None, "; ".join(r.get("error", "") for r in results))
        return {"ok": False, "checks": checks, "onchain": None, "honest_scope": _SCOPE}

    genesis_ok = all(r["genesis"] == MAINNET_GENESIS for r in reachable)
    add("all reachable RPCs on mainnet (genesis pin)", genesis_ok,
        "" if genesis_ok else "an RPC reported a non-mainnet genesis (fake cluster) → reject")

    with_tx = [r for r in reachable if r.get("tx")]
    if not with_tx:
        add("≥1 archive RPC has the tx (finalized)", False,
            f"0/{len(reachable)} reachable RPCs returned the finalized tx (pruned or nonexistent)")
        return {"ok": False, "checks": checks, "onchain": None, "honest_scope": _SCOPE}
    add("≥1 archive RPC has the tx (finalized)", True,
        f"{len(with_tx)}/{len(reachable)} reachable RPCs have it")

    # CONTRADICTION check: every RPC that has the tx must agree on (err, memo digests, signer).
    # A single RPC lying about the content is caught here the moment an honest archive disagrees.
    views = [(r["rpc"], (r["tx"].get("meta") or {}).get("err") is None,
              _extract_memo_digests(r["tx"]), _tx_signer(r["tx"])) for r in with_tx]
    no_contradiction = all(v[1] == views[0][1] and v[2] == views[0][2] and v[3] == views[0][3]
                           for v in views)
    add("witnessing RPCs do not contradict each other", no_contradiction,
        "" if no_contradiction else "reachable RPCs DISAGREE on tx content → an RPC is lying → reject")
    # single-source is declared, never hidden
    add("cross-confirmed by ≥2 archives", (True if len(with_tx) >= 2 else None),
        "" if len(with_tx) >= 2 else "SINGLE archive witness — pass multiple archive RPCs for N-of-M")

    tx = with_tx[0]["tx"]
    meta = tx.get("meta") or {}
    err_ok = meta.get("err") is None
    add("tx executed without error (meta.err is null)", err_ok, str(meta.get("err")))

    digests = _extract_memo_digests(tx)
    digest_ok = exp in digests
    add("expected digest present in canonical spl-memo", digest_ok,
        f"on-chain memo digests: {sorted(d[:12] + '…' for d in digests) or '(none)'}")

    signer = _tx_signer(tx)
    if expected_signer is not None:
        signer_ok = signer == expected_signer
        add("fee-payer == expected signer (anchor→identity)", signer_ok, f"on-chain signer {signer}")
    else:
        add("fee-payer == expected signer (anchor→identity)", None,
            "no expected_signer given → anchor proves existence+timestamp only, NOT authorship")

    hard = [genesis_ok, no_contradiction, err_ok, digest_ok]
    if expected_signer is not None:
        hard.append(signer == expected_signer)
    ok = all(hard)
    return {"ok": ok, "checks": checks,
            "onchain": {"signature": signature, "slot": tx.get("slot"),
                        "block_time": tx.get("blockTime"), "signer": signer,
                        "digests": sorted(digests), "witnesses": len(with_tx)},
            "honest_scope": _SCOPE}


def main(argv=None):
    import argparse
    import sys
    p = argparse.ArgumentParser(prog="cryptovalid_solana",
                                description="Verify a Solana mainnet anchor of a CryptoValid digest.")
    p.add_argument("signature")
    p.add_argument("expected_sha3_hex")
    p.add_argument("--signer", default=None, help="expected fee-payer pubkey (binds anchor→identity)")
    p.add_argument("--rpc", action="append", default=None, help="override RPC(s); repeatable")
    a = p.parse_args(argv)
    out = verify_solana_anchor(a.signature, a.expected_sha3_hex,
                               rpcs=tuple(a.rpc) if a.rpc else DEFAULT_RPCS,
                               expected_signer=a.signer)
    print(json.dumps(out, indent=1, ensure_ascii=False))
    sys.exit(0 if out["ok"] else 1)


if __name__ == "__main__":
    main()
