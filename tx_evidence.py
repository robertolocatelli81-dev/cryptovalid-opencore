#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
tx_evidence — verifiable, reproducible audit trail for digital-asset transactions.

WHY (measured, 2026-08-21): IRS Form 1099-DA requires cost-basis reporting from 2026, but
brokers do NOT report basis for assets acquired before 2026 and do not cover non-custodial/
DeFi activity — the taxpayer must track and, on audit, PROVE their own transactions. Tax
software (CoinTracker, Koinly…) computes the numbers; what it does NOT give is evidence that
survives an audit without trusting the software: a tamper-evident, independently reproducible
record of the source transactions.

WHAT THIS IS (and is NOT — the boundary never moves):
  - It canonicalizes each transaction deterministically (same tx -> same digest), hash-chains
    the set (append-only; any later edit changes the head), and re-derives the cost basis with
    a DECLARED, deterministic lot-matching method (FIFO) so a third party (an auditor, the IRS)
    recomputes the SAME numbers from the same records.
  - It is proof-of-integrity + proof-of-reproducibility, NOT tax advice and NOT proof of
    tax-correctness: it does not choose your accounting method, does not apply wash-sale or
    jurisdiction rules, and does not certify compliance. Those are the taxpayer's / advisor's.
    Garbage in -> garbage attested faithfully (same confine as CryptoValid/FUNDCERT).

Reuses fundcert_canonical._canon_quantity (no divergence). Stdlib + that one import.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from decimal import Decimal
from typing import Dict, List

from fundcert_canonical import _canon_quantity   # riuso: stessa canonicalizzazione, zero divergenza

TX_VERSION = "tx-evidence-1.0"
_ACQUIRE = {"acquire", "buy", "receive", "mining", "reward", "airdrop"}
_DISPOSE = {"dispose", "sell", "send", "spend", "trade_out"}


@dataclass
class Tx:
    """Una transazione. `kind` in _ACQUIRE|_DISPOSE|'transfer'. `qty` = unità dell'asset;
    `unit_price` = prezzo in `currency` per unità (0 per transfer interni). `ts` = ISO8601."""
    txid: str
    kind: str
    asset: str
    qty: str
    unit_price: str
    currency: str
    ts: str
    source: str = ""          # exchange/wallet di provenienza (provenienza, non nel matching)


def canonical_tx(t: Tx) -> Dict:
    """Forma canonica deterministica: quantità/prezzi normalizzati (no notazione scientifica,
    bankers rounding), asset/kind upper-trim. Stesso contenuto economico -> stesso digest."""
    return {
        "txid": t.txid.strip(),
        "kind": t.kind.strip().lower(),
        "asset": t.asset.strip().upper(),
        "qty": _canon_quantity(t.qty),
        "unit_price": _canon_quantity(t.unit_price),
        "currency": t.currency.strip().upper(),
        "ts": t.ts.strip(),
    }


def _canon_bytes(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def tx_digest(t: Tx) -> str:
    return hashlib.sha3_256(_canon_bytes(canonical_tx(t))).hexdigest()


def build_chain(txs: List[Tx]) -> List[Dict]:
    """Hash-chain append-only dei record canonici: ogni entry lega il precedente.
    Una modifica a qualunque tx (o all'ordine) cambia la testa -> tamper-evident."""
    chain, prev = [], "GENESIS"
    for t in txs:
        ct = canonical_tx(t)
        entry = {"canonical": ct, "prev": prev}
        entry["self_hash"] = hashlib.sha3_256(
            _canon_bytes({"canonical": ct, "prev": prev})).hexdigest()
        prev = entry["self_hash"]
        chain.append(entry)
    return chain


def verify_chain(chain: List[Dict]) -> bool:
    prev = "GENESIS"
    for e in chain:
        h = hashlib.sha3_256(_canon_bytes({"canonical": e["canonical"], "prev": prev})).hexdigest()
        if h != e.get("self_hash") or e.get("prev") != prev:
            return False
        prev = h
    return True


def cost_basis_fifo(txs: List[Tx]) -> Dict:
    """Ri-deriva il cost basis per ogni DISPOSE col metodo FIFO DICHIARATO, deterministico e
    riproducibile. Ritorna, per asset, la lista di dispose con {qty, proceeds, basis, gain} e i
    lotti consumati. NON è consulenza: FIFO è UNA scelta esplicita; l'utente può doverne usare
    un'altra. `insufficient_lots` è segnalato, mai silenziato (un dispose senza lotti a monte è
    un buco nei dati, non un gain gratis)."""
    # ordina per timestamp (stabile), poi processa
    ordered = sorted(range(len(txs)), key=lambda i: (txs[i].asset.upper(), txs[i].ts))
    lots: Dict[str, list] = {}          # asset -> [ [qty_rimasta, unit_cost] ]
    out: Dict[str, list] = {}
    for i in ordered:
        t = txs[i]
        asset = t.asset.strip().upper()
        kind = t.kind.strip().lower()
        qty = Decimal(_canon_quantity(t.qty))
        price = Decimal(_canon_quantity(t.unit_price))
        if kind in _ACQUIRE:
            lots.setdefault(asset, []).append([qty, price])
        elif kind in _DISPOSE:
            remaining = qty
            basis = Decimal(0)
            consumed = []
            q = lots.setdefault(asset, [])
            while remaining > 0 and q:
                lot = q[0]
                take = min(remaining, lot[0])
                basis += take * lot[1]
                consumed.append({"qty": _canon_quantity(take), "unit_cost": _canon_quantity(lot[1])})
                lot[0] -= take
                remaining -= take
                if lot[0] == 0:
                    q.pop(0)
            proceeds = qty * price
            out.setdefault(asset, []).append({
                "txid": t.txid, "ts": t.ts, "qty": _canon_quantity(qty),
                "proceeds": _canon_quantity(proceeds), "basis": _canon_quantity(basis),
                "gain": _canon_quantity(proceeds - basis),
                "consumed_lots": consumed,
                "insufficient_lots": remaining > 0,           # dichiarato, mai silenziato
                "unmatched_qty": _canon_quantity(remaining) if remaining > 0 else "0",
            })
        # transfer: non tocca il basis (movimento tra wallet propri)
    return {"method": "FIFO", "by_asset": out}


def attest(txs: List[Tx], as_of: str = "") -> Dict:
    """Attestazione: hash-chain dei record + cost-basis FIFO riproducibile + digest della radice.
    Un terzo ricostruisce tutto dai record e ottiene lo STESSO digest e gli STESSI numeri."""
    chain = build_chain(txs)
    head = chain[-1]["self_hash"] if chain else "EMPTY"
    basis = cost_basis_fifo(txs)
    body = {"tx_version": TX_VERSION, "as_of": as_of, "n": len(txs),
            "chain_head": head, "cost_basis": basis}
    body["attestation_digest_sha3"] = hashlib.sha3_256(_canon_bytes(body)).hexdigest()
    body["honest_scope"] = (
        "Proves the transactions are tamper-evident (hash chain) and that the cost basis is "
        "REPRODUCIBLE under the declared FIFO method — a third party recomputes the same numbers. "
        "NOT tax advice, NOT proof of tax-correctness: it does not pick your accounting method, "
        "apply wash-sale/jurisdiction rules, or certify compliance.")
    return body


def verify_attestation(att: Dict, txs: List[Tx]) -> Dict:
    """Ricostruisce dai record e confronta con l'attestazione: catena intatta, digest e numeri
    riproducibili. Fail-closed: qualunque scostamento -> valid False."""
    chain = build_chain(txs)
    chain_ok = verify_chain(chain)
    head = chain[-1]["self_hash"] if chain else "EMPTY"
    recomputed = {"tx_version": att.get("tx_version"), "as_of": att.get("as_of"),
                  "n": len(txs), "chain_head": head, "cost_basis": cost_basis_fifo(txs)}
    digest = hashlib.sha3_256(_canon_bytes(recomputed)).hexdigest()
    digest_ok = digest == att.get("attestation_digest_sha3")
    head_ok = head == att.get("chain_head")
    return {"chain_ok": chain_ok, "head_match": head_ok, "digest_match": digest_ok,
            "valid": bool(chain_ok and head_ok and digest_ok)}


def _load_txs(path: str) -> List[Tx]:
    with open(path, encoding="utf-8") as f:
        rows = json.load(f)
    return [Tx(txid=str(r.get("txid", i)), kind=r["kind"], asset=r["asset"],
               qty=str(r["qty"]), unit_price=str(r.get("unit_price", "0")),
               currency=r.get("currency", "USD"), ts=r.get("ts", ""),
               source=r.get("source", "")) for i, r in enumerate(rows)]


def main(argv=None) -> int:
    import argparse
    import sys
    p = argparse.ArgumentParser(
        prog="tx-evidence",
        description="Verifiable, reproducible audit trail for digital-asset transactions "
                    "(NOT tax advice).")
    sub = p.add_subparsers(dest="cmd")
    a1 = sub.add_parser("attest")
    a1.add_argument("transactions_json")
    a1.add_argument("--as-of", default="")
    a2 = sub.add_parser("verify")
    a2.add_argument("attestation_json")
    a2.add_argument("transactions_json")
    a = p.parse_args(sys.argv[1:] if argv is None else argv)
    if a.cmd == "attest":
        print(json.dumps(attest(_load_txs(a.transactions_json), as_of=a.as_of),
                         ensure_ascii=False, indent=1))
        return 0
    if a.cmd == "verify":
        with open(a.attestation_json, encoding="utf-8") as f:
            att = json.load(f)
        r = verify_attestation(att, _load_txs(a.transactions_json))
        print(json.dumps(r, ensure_ascii=False, indent=1))
        return 0 if r["valid"] else 1
    p.print_help()
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
