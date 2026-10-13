#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""OMEGA-FUNDCERT · cross-source check ("killer experiment" in the Popperian sense: one fund, one date, TWO real sources)

runner del KILLER-EXPERIMENT VERO — stesso fondo, stesso giorno, DUE fonti reali.

Il test che decide se il cross-source regge su dati reali indipendenti (non sintetici): prendi lo STESSO
fondo, stesso as-of, da due fonti (es. emittente SSGA/iShares + SEC N-PORT), canonicalizza entrambe con
allineamento id (CUSIP→ISIN) e confronta i digest. Se DIVERSI, il `diff` dice ESATTAMENTE cosa diverge —
è lì il problema reale della canonicalizzazione.

USO (la sandbox OMEGA non raggiunge sec.gov: scarica i file TU, poi lancia questo):
  python3 -m opencore.fundcert_crosssource <fileA> <typeA> <fileB> <typeB>
  type ∈ {ssga-xlsx, csv, nport-xml}
Esempio:
  python3 -m opencore.fundcert_crosssource SPY.xlsx ssga-xlsx spy_nport.xml nport-xml

Riporta: digest_A, digest_B, same_digest, la trasparenza dei drop (audit_skips) di ENTRAMBE le fonti (un
cert tool non droppa in silenzio), e — se diversi — only_in_A / only_in_B / changed_quantity dal diff.
"""
import sys as _sys_0203
if __name__ == "__main__":   # 0.20.3: run as a command, never write the bytecode cache: CPython 3.9 and 3.11 write
    _sys_0203.dont_write_bytecode = True   # a .pyc with one raw write; cut by a file size limit, every later run died (13/10/2026)
import json
import sys

from fundcert_canonical import (audit_skips, diff, digest, parse_holdings_csv,  # noqa: E402
                                parse_nport_xml, parse_ssga_xlsx)


def _load(path: str, kind: str):
    if kind == "ssga-xlsx":
        return parse_ssga_xlsx(path)
    if kind == "nport-xml":
        with open(path, encoding="utf-8") as f:
            return parse_nport_xml(f.read())
    if kind == "csv":
        with open(path, encoding="utf-8") as f:
            return parse_holdings_csv(f.read())
    raise SystemExit(f"type sconosciuto: {kind} (usa ssga-xlsx | csv | nport-xml)")


try:   # 0.20.3: the one writer of every command (verifier.py): an outcome is written whole, or exit 74
    from verifier import Parser, emit, receipt_cli, say
except ImportError:   # python3 -m opencore.<module> from the parent directory
    from opencore.verifier import Parser, emit, receipt_cli, say


@receipt_cli
def main(argv=None):
    a = argv if argv is not None else sys.argv[1:]
    if len(a) < 4:
        say(__doc__ + "\n")   # usage on stderr (0.20.3)
        return 2
    A, tA, B, tB = a[0], a[1], a[2], a[3]
    ha, hb = _load(A, tA), _load(B, tB)
    # id_target=ISIN: allinea una fonte CUSIP e una ISIN sullo stesso identificatore (fix cross-source US)
    da, db = digest(ha, "ISIN"), digest(hb, "ISIN")
    out = {
        "source_A": {"file": A, "type": tA, "fund_id": ha.fund_id, "as_of": ha.as_of,
                     "n_positions": len(ha.positions), "digest": da, "audit": audit_skips(ha)},
        "source_B": {"file": B, "type": tB, "fund_id": hb.fund_id, "as_of": hb.as_of,
                     "n_positions": len(hb.positions), "digest": db, "audit": audit_skips(hb)},
        "same_digest": da == db,
    }
    if ha.as_of and hb.as_of and ha.as_of != hb.as_of:
        out["WARNING"] = f"as_of DIVERSI ({ha.as_of} vs {hb.as_of}) — non è lo stesso giorno, il test non è valido"
    if da != db:
        out["diff"] = diff(ha, hb, "ISIN")
    emit(json.dumps(out, indent=1, default=str)[:6000])
    # verdetto onesto
    if out.get("WARNING"):
        emit("\n⚠  " + out["WARNING"])
    elif out["same_digest"]:
        emit("\n✓ STESSO DIGEST: le due fonti concordano sul basket canonico — cross-source REGGE su dati reali.")
    else:
        d = out["diff"]
        emit(f"\n✗ DIGEST DIVERSI: {len(d['only_in_a'])} solo in A, {len(d['only_in_b'])} solo in B, "
              f"{len(d['changed_quantity'])} quantità diverse → è QUI il problema reale della canonicalizzazione.")
    for s in ("source_A", "source_B"):
        au = out[s]["audit"]
        if au["alert"]:
            emit(f"⚠  {s}: {au['material_dropped']} POSIZIONI MATERIALI droppate (basket incompleto) — {au['material']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
