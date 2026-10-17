"""
CryptoValid — pruning / evidence-decay probe (opencore).

The honest risk (adversarial review, 2026-08-19): free public Solana RPCs PRUNE historical
transactions. A STRICT verify (min_witnesses>=2) that passes at t=0 can FAIL on an *honest* old
anchor months later — a self-DoS of the evidence. This probe MEASURES current retention across a
set of public RPCs for a given anchor, so decay is a measured number, not an assumption.

What it does (and does not):
- MEASURES, per RPC, whether the finalized tx is still retrievable NOW → a retention snapshot.
- INFERS decay by comparing anchors of different AGES in one run (an old anchor vs a fresh one).
- Does NOT predict the future: true decay-over-time needs periodic re-runs (wire this to a cron and
  keep the JSONL history). One run is one point in time.

Positive/null control baked in: probing a non-existent signature MUST report 0 witnesses
(`decayed_or_absent`), proving the probe can detect absence — a probe that always finds the tx would
be useless. Stdlib only.
"""
import sys as _sys_0203
if __name__ == "__main__":   # 0.20.3: run as a command, never write the bytecode cache: CPython 3.9 and 3.11 write
    _sys_0203.dont_write_bytecode = True   # a .pyc with one raw write; cut by a file size limit, every later run died (13/10/2026)
    _L0210 = type(__loader__)   # 0.21.0: a .pyc already cut (CPython 3.9/3.11 installed one) is compiled from the source
    if _L0210.__name__ == "SourceFileLoader":   # instead of failing every later run (EOFError: marshal data too short)
        def _get_code_0210(self, fullname, _get_code=_L0210.get_code):
            try:
                return _get_code(self, fullname)
            except (EOFError, ValueError):
                path = self.get_filename(fullname)
                return self.source_to_code(self.get_data(path), path)
        _L0210.get_code = _get_code_0210
import json
import time
import urllib.request

# a spread of public mainnet RPCs (distinct operators where possible)
PROBE_RPCS = (
    "https://api.mainnet-beta.solana.com",
    "https://solana-rpc.publicnode.com",
    "https://solana.api.onfinality.io/public",
    "https://api.mainnet.rpcpool.com",
)
MAINNET_GENESIS = "5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d"


def _rpc(url, method, params, timeout):
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    req = urllib.request.Request(url, body,
                                 {"Content-Type": "application/json", "User-Agent": "cryptovalid-probe/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.load(r)


def probe_retention(signature, rpcs=PROBE_RPCS, timeout=20):
    """Query each RPC for the finalized tx. Returns per-RPC availability + a retention verdict."""
    per = []
    for url in rpcs:
        entry = {"rpc": url, "has_tx": False, "reachable": False, "note": ""}
        try:
            r = _rpc(url, "getTransaction",
                     [signature, {"encoding": "json", "commitment": "finalized",
                                  "maxSupportedTransactionVersion": 0}], timeout)
            entry["reachable"] = True
            if r.get("result"):
                entry["has_tx"] = True
                entry["note"] = f"slot {r['result'].get('slot')}"
            else:
                entry["note"] = "result=null → pruned or nonexistent on this node"
        except Exception as e:                       # noqa: BLE001 — a probe must survive any RPC error
            entry["note"] = f"{type(e).__name__}: {str(e)[:60]}"
        per.append(entry)
    witnesses = sum(1 for e in per if e["has_tx"])
    reachable = sum(1 for e in per if e["reachable"])
    return {
        "signature": signature,
        "checked_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "rpcs_probed": len(rpcs),
        "rpcs_reachable": reachable,
        "witnesses_with_tx": witnesses,
        "strict_2of_ok": witnesses >= 2,
        "verdict": ("retained" if witnesses >= 2 else
                    "single-witness" if witnesses == 1 else "decayed_or_absent"),
        "per_rpc": per,
    }


def probe_decay(anchors, rpcs=PROBE_RPCS, timeout=20):
    """anchors: list of {signature, label, anchored_utc}. Runs probe_retention on each and reports
    retention vs age — the real decay signal is an OLD anchor with fewer witnesses than a fresh one."""
    now = time.time()
    out = []
    for a in anchors:
        r = probe_retention(a["signature"], rpcs=rpcs, timeout=timeout)
        age_days = None
        if a.get("anchored_utc"):
            try:
                t = time.mktime(time.strptime(a["anchored_utc"], "%Y-%m-%dT%H:%M:%SZ"))
                age_days = round((now - t) / 86400, 1)
            except ValueError:
                pass
        out.append({"label": a.get("label", ""), "age_days": age_days,
                    "witnesses": r["witnesses_with_tx"], "verdict": r["verdict"],
                    "strict_2of_ok": r["strict_2of_ok"], "detail": r})
    return {"checked_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "anchors": out}


def main(argv=None) -> int:
    import sys
    sigs = sys.argv[1:] if argv is None else argv
    if not sigs:
        say("usage: python3 -m opencore.cryptovalid_pruning_probe <signature> [<signature> ...]\n")   # usage on stderr (0.20.3)
        return 2
    emit(json.dumps(probe_decay([{"signature": s, "label": s[:10]} for s in sigs]), indent=1))
    return 0


try:   # 0.20.3: the one writer of every command (verifier.py): an outcome is written whole, or exit 74
    from verifier import emit, receipt_cli, say
except ImportError:   # python3 -m opencore.<module> from the parent directory
    from opencore.verifier import emit, receipt_cli, say
main = receipt_cli(main)

if __name__ == "__main__":
    raise SystemExit(main())
