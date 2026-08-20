"""
OMEGA-FUNDCERT · canonicalizzazione deterministica di artefatti di fund-servicing (PCF/holdings/NAV-basket).

Stessa architettura di CryptoValid, oggetto diverso e più OSTILE. L'hash-chain di CryptoValid funziona solo
se lo STESSO portafoglio produce SEMPRE lo stesso digest. Nei record finanziari questo si rompe su:
precisione decimale/arrotondamento, ORDINAMENTO delle posizioni, notazione (scientifica vs decimale),
snapshot FX a orari diversi, corporate action con date ambigue, posizioni in pending settlement. Questa spec
definisce una FORMA CANONICA deterministica → un digest riproducibile da un terzo. È il cuore del modulo.

CONFINE — DA DICHIARARE, NON NASCONDERE: FUNDCERT prova COSA È STATO RICEVUTO/TRASMESSO (il basket/holdings
come pubblicato), NON che il NAV o i pesi siano CORRETTI. Se il fund admin sbaglia il calcolo, FUNDCERT
certifica l'errore fedelmente. È lo stesso confine di CryptoValid (proof-of-transmission ≠ proof-of-veracity).

FORMA CANONICA (regole deterministiche, versionate — `CANON_VERSION`):
  1. La posizione è ridotta al suo CONTENUTO ECONOMICO: {identifier, id_scheme, quantity}. Nome/settore/peso
     sono cosmetici o DERIVATI (peso = f(quantity, prezzo, NAV)) → esclusi dal digest-core (disponibili a
     parte). Certifichi la COMPOSIZIONE (chi e quanto), non l'etichetta.
  2. quantity → Decimal, normalizzato a intero se intero (le shares lo sono), niente notazione scientifica
     ('2.99181969E8' → '299181969'), altrimenti quantizzato a `QUANTITY_DP` decimali, arrotondamento
     BANKERS (ROUND_HALF_EVEN) DICHIARATO.
  3. identifier normalizzato (upper, trim); id_scheme esplicito (CUSIP/SEDOL/ISIN/LEI/TICKER).
  4. posizioni ORDINATE per (id_scheme, identifier) — l'ordine di pubblicazione NON conta.
  5. canonical JSON (sort_keys, separators=(',',':')) → SHA3-256. Header (fund_id, as_of) nel digest a parte.
Stdlib only.
"""
import hashlib
import json
import re
from dataclasses import dataclass, field
from decimal import Decimal, ROUND_HALF_EVEN, InvalidOperation
from typing import Dict, List, Optional

CANON_VERSION = "fundcert-canon-1.0"
QUANTITY_DP = 6                     # decimali per quantità frazionarie (le shares intere restano intere)
# sentinelli placeholder che i fondi usano per "nessun CUSIP/id" (futures, cash, derivati indicizzati):
# NON sono identificatori → non vanno normalizzati a un ISIN finto. '000000000' è gestito a parte (all-zero).
_CUSIP_SENTINELS = {"N/A", "NA", "NONE", "XXXXXXXXX", "999999999"}


@dataclass
class Position:
    identifier: str
    id_scheme: str                  # CUSIP | SEDOL | ISIN | LEI | TICKER
    quantity: str                   # stringa grezza (verrà canonicalizzata)
    name: str = ""                  # cosmetico — NON nel digest-core
    weight: str = ""                # DERIVATO (= f(qty,prezzo,NAV)) — NON nel digest-core
    cash_component: str = ""        # #3: componente cash del PCF per creation unit — SE presente, NEL digest


@dataclass
class Holdings:
    fund_id: str                    # ticker o ISIN del fondo
    as_of: str                      # data di riferimento (come pubblicata)
    source: str                     # 'ssga'|'ishares'|'nport'|... — provenienza
    positions: List[Position] = field(default_factory=list)
    skipped: List[Dict] = field(default_factory=list)   # righe NON incluse — MAI in silenzio (trovato dal
    #                                                     killer-experiment: un cert tool non deve droppare)


def audit_skips(h: "Holdings") -> Dict:
    """Trasparenza dei drop: separa footer/non-holding (benigno) da posizioni MATERIALI perse (quantità
    presente ma senza identifier: cash/futures droppati = basket incompleto). `material>0` è un ALERT."""
    material = [s for s in h.skipped if s.get("has_quantity")]
    benign = [s for s in h.skipped if not s.get("has_quantity")]
    return {"n_positions": len(h.positions), "n_skipped": len(h.skipped),
            "material_dropped": len(material), "benign_skipped": len(benign),
            "alert": len(material) > 0, "material": material[:10]}


def _canon_quantity(raw) -> str:
    """Normalizza una quantità a forma canonica deterministica: niente notazione scientifica, intero se
    intero, altrimenti `QUANTITY_DP` decimali con arrotondamento BANKERS. Solleva su input non numerico."""
    try:
        d = Decimal(str(raw).strip().replace(",", ""))
    except (InvalidOperation, AttributeError):
        raise ValueError(f"quantità non numerica: {raw!r}")
    if d == d.to_integral_value():
        # BUG-FIX (trovato su SPY reale 18/08): str(to_integral_value()) preserva l'esponente su interi in
        # notazione scientifica ('1.275099E7' → '1.275099E+7'), rompendo il determinismo. format(...,'f')
        # lo espande SEMPRE a forma decimale piena ('12750990'). È il cuore ostile della canonicalizzazione.
        return format(d.to_integral_value(), "f")              # '2.99181969E8' → '299181969'
    q = d.quantize(Decimal(1).scaleb(-QUANTITY_DP), rounding=ROUND_HALF_EVEN)
    return format(q.normalize(), "f")                          # niente esponente, decimali fissi


def _isin_check_digit(body11: str) -> str:
    """Check-digit ISIN (Luhn su espansione lettere→numeri, A=10..Z=35). Standard ISO 6166."""
    digits = ""
    for ch in body11:
        digits += str(ord(ch) - 55) if ch.isalpha() else ch      # A=10..Z=35
    total, dbl = 0, True
    for ch in reversed(digits):                                  # Luhn dai meno significativi
        d = int(ch)
        if dbl:
            d *= 2
            if d > 9:
                d -= 9
        total += d
        dbl = not dbl
    return str((10 - (total % 10)) % 10)


def cusip_to_isin(cusip: str) -> Optional[str]:
    """CUSIP (US/CA, 9 char) → ISIN US-prefixed, DETERMINISTICO (ISIN = 'US' + CUSIP + check-digit). È il
    fix del cross-source #4: una fonte in CUSIP e una in ISIN allineano sullo STESSO id → stesso digest.
    Ritorna None se il CUSIP non è 9 alfanumerici (non forzo, non indovino)."""
    c = cusip.strip().upper()
    if len(c) != 9 or not c.isalnum():
        return None
    # placeholder SEC per "nessun CUSIP" (000000000 passa il formato ma NON è un id): non fabbricare un ISIN
    # finto da un non-identificatore — trovato sul dato reale (N-PORT SPY/VOO). Un id inventato > nessun id.
    if set(c) == {"0"} or c in _CUSIP_SENTINELS:
        return None
    body = "US" + c
    return body + _isin_check_digit(body)


# normalizzazione id cross-scheme: schema-target preferito → gli id si allineano tra fonti diverse.
def _normalize_id(identifier: str, scheme: str, target: str) -> tuple:
    """Prova a portare (identifier, scheme) allo scheme `target`. Oggi supporta CUSIP→ISIN (deterministico).
    Se non normalizzabile, lascia (id, scheme) invariati — MAI un'inferenza inventata."""
    ident, scheme = identifier.strip().upper(), scheme.strip().upper()
    if target == "ISIN" and scheme == "CUSIP":
        isin = cusip_to_isin(ident)
        if isin:
            return (isin, "ISIN")
    return (ident, scheme)


def _canon_position(p: Position, id_target: Optional[str] = None) -> Dict:
    ident, scheme = (p.identifier.strip().upper(), p.id_scheme.strip().upper())
    if id_target:
        ident, scheme = _normalize_id(ident, scheme, id_target)
    d = {"id": ident, "scheme": scheme, "qty": _canon_quantity(p.quantity)}
    if p.cash_component not in (None, ""):                        # #3: la componente cash del PCF conta per gli AP
        d["cash"] = _canon_quantity(p.cash_component)
    return d


def canonical_form(h: Holdings, id_target: Optional[str] = None) -> Dict:
    """La forma canonica del basket: posizioni ridotte al contenuto economico, ordinate deterministicamente.
    `id_target` (es. 'ISIN') allinea gli id tra fonti con scheme diversi (CUSIP→ISIN) — il fix cross-source."""
    pos = [_canon_position(p, id_target) for p in h.positions]
    # ordine di pubblicazione irrilevante — chiave sul CONTENUTO PIENO, non solo (scheme,id): i fondi reali
    # riportano N righe con id placeholder '000000000' (futures/cash senza CUSIP). Ordinare solo per (scheme,id)
    # NON è deterministico su quei duplicati (trovato su N-PORT SPY reale: 27 righe '000000000' → l'ordine
    # d'input filtrava nel digest). Aggiungere qty e cash come tiebreaker rende la sequenza riproducibile.
    pos.sort(key=lambda x: (x["scheme"], x["id"], x["qty"], x.get("cash", "")))
    return {"canon_version": CANON_VERSION, "positions": pos, "n": len(pos)}


def canonical_bytes(h: Holdings, id_target: Optional[str] = None) -> bytes:
    return json.dumps(canonical_form(h, id_target), sort_keys=True, separators=(",", ":")).encode()


def digest(h: Holdings, id_target: Optional[str] = None) -> str:
    """SHA3-256 della forma canonica del basket. STESSO portafoglio → STESSO digest (riproducibile da terzi).
    Con `id_target` due fonti su scheme diversi (CUSIP/ISIN) producono lo stesso digest se il basket coincide."""
    return hashlib.sha3_256(canonical_bytes(h, id_target)).hexdigest()


def diff(a: Holdings, b: Holdings, id_target: Optional[str] = None) -> Dict:
    """Diff a livello di posizione tra due basket canonicalizzati: added/removed/changed per (scheme,id).
    Se digest(a)==digest(b) il diff è vuoto — se non lo è, dice ESATTAMENTE cosa è cambiato.
    Gli id NON possono essere assunti unici: i fondi reali riportano più righe con id placeholder
    '000000000' (futures/cash senza CUSIP). Un dict {(scheme,id):qty} le COLLASSEREBBE in silenzio
    (trovato su N-PORT SPY reale: 27 righe → 1). Qui si raggruppa in MULTISET e i duplicati si DICHIARANO."""
    def _multi(h):
        m: Dict = {}
        for p in canonical_form(h, id_target)["positions"]:
            m.setdefault((p["scheme"], p["id"]), []).append((p["qty"], p.get("cash", "")))
        for k in m:
            m[k].sort()
        return m
    ma, mb = _multi(a), _multi(b)
    ka, kb = set(ma), set(mb)
    changed = [{"id": k[1], "scheme": k[0], "a": ma[k], "b": mb[k]} for k in (ka & kb) if ma[k] != mb[k]]
    # id con >1 riga (placeholder/multi-lotto): confronto per multiset, non 1:1 — dichiarati, mai persi
    dup = sorted(f"{s}:{i}(a={len(ma[(s, i)])},b={len(mb.get((s, i), []))})"
                 for s, i in (ka & kb) if len(ma[(s, i)]) > 1 or len(mb.get((s, i), [])) > 1)

    def _label(m, s, i):               # annota il conteggio se l'id copre più righe (placeholder/multi-lotto)
        n = len(m[(s, i)])
        return f"{s}:{i}(×{n})" if n > 1 else f"{s}:{i}"
    return {
        "same_digest": digest(a, id_target) == digest(b, id_target),
        "only_in_a": sorted(_label(ma, s, i) for s, i in ka - kb),   # conteggio esplicito: nulla collassa in silenzio
        "only_in_b": sorted(_label(mb, s, i) for s, i in kb - ka),
        "changed_quantity": changed,
        "duplicate_ids": dup,          # trasparenza: id non unici, confrontati come multiset (non collassati)
    }


def norm_name(name: str) -> str:
    """Normalizza un nome titolo per il match cross-source quando NON c'è un id comune (es. N-CSR senza CUSIP)."""
    n = name.upper()
    n = re.sub(r"[.,/&]", " ", n)
    n = re.sub(r"\b(INC|CORP|CO|LTD|PLC|CLASS|THE|COMPANY|HLDGS|HOLDINGS|GROUP|INTL|INTERNATIONAL|CORPORATION)\b",
               " ", n)
    return re.sub(r"\s+", " ", n).strip()


def reconcile(a: Holdings, b: Holdings, by: str = "id", id_target: Optional[str] = None) -> Dict:
    """Riconciliazione tra due fonti dello STESSO fondo/data — il VERO valore del prodotto (non l'uguaglianza
    del digest). Trovato sul dato SEC reale (N-PORT vs N-CSR del Vanguard 500 Index Fund, 31/12/2025): due
    filing autorevoli NON coincidono — differiscono per un FATTORE DI SCALA globale (+0.397%, sec-lending/units)
    a composizione identica. `reconcile` lo MISURA e separa la scala dalle differenze reali per-titolo.
    by='id' allinea per (scheme,id[,id_target]); by='name' per nome normalizzato (quando manca l'id comune).
    Ritorna: matched, scale_factor/scale_pct, residual_after_scale (mismatch DOPO la scala), only_in_*."""
    import statistics as _st

    def _q(h):
        m: Dict = {}
        if by == "name":
            for p in h.positions:
                if p.name:
                    m.setdefault(norm_name(p.name), []).append(_canon_quantity(p.quantity))
        else:
            for p in canonical_form(h, id_target)["positions"]:
                m.setdefault(f"{p['scheme']}:{p['id']}", []).append(p["qty"])
        return {k: sorted(v) for k, v in m.items()}

    qa, qb = _q(a), _q(b)
    common = set(qa) & set(qb)
    ratios = [float(qb[k][0]) / float(qa[k][0]) for k in common
              if len(qa[k]) == 1 and len(qb[k]) == 1 and float(qa[k][0]) != 0]
    scale = _st.median(ratios) if ratios else 1.0
    residual = []
    for k in sorted(common):                      # differenze REALI = quelle che restano DOPO aver tolto la scala
        if len(qa[k]) == 1 and len(qb[k]) == 1:
            va, vb = float(qa[k][0]), float(qb[k][0])
            if abs(vb / scale - va) > max(2.0, abs(va) * 5e-4):
                residual.append({"key": k, "a": qa[k][0], "b": qb[k][0]})
    return {
        "by": by,
        "matched": len(common),
        "scale_factor": round(scale, 6),
        "scale_pct": round((scale - 1) * 100, 4),
        "residual_after_scale": residual,
        "residual_count": len(residual),
        "only_in_a": len(set(qa) - set(qb)),
        "only_in_b": len(set(qb) - set(qa)),
    }


# ─────────────────────── PARSER (fonti REALI) ───────────────────────

def parse_ssga_xlsx(path: str) -> Holdings:
    """Parser SSGA/SPDR holdings XLSX (stdlib zipfile+xml). Colonne: Name, Ticker, Identifier(CUSIP), SEDOL,
    Weight, Sector, Shares Held. Header con Ticker Symbol + 'Holdings: As of <data>'."""
    import re
    import xml.etree.ElementTree as ET
    import zipfile
    NS = {"a": "http://schemas.openxmlformats.org/spreadsheetml/2006/main"}
    z = zipfile.ZipFile(path)
    ss = []
    if "xl/sharedStrings.xml" in z.namelist():
        for si in ET.fromstring(z.read("xl/sharedStrings.xml")).findall("a:si", NS):
            ss.append("".join(t.text or "" for t in si.iter(
                "{http://schemas.openxmlformats.org/spreadsheetml/2006/main}t")))
    sheet = [n for n in z.namelist() if re.match(r"xl/worksheets/sheet1\.xml", n)][0]
    rows = []
    for row in ET.fromstring(z.read(sheet)).iter(
            "{http://schemas.openxmlformats.org/spreadsheetml/2006/main}row"):
        cells = []
        for c in row.findall("a:c", NS):
            v = c.find("a:v", NS)
            val = v.text if v is not None else None
            if c.get("t") == "s" and val is not None:
                val = ss[int(val)]
            cells.append(val)
        rows.append(cells)
    fund_id, as_of, hdr_idx = "", "", None
    for i, r in enumerate(rows):
        if r and r[0] == "Ticker Symbol:":
            fund_id = (r[1] or "").strip()
        if r and r[0] == "Holdings:":
            as_of = (r[1] or "").replace("As of", "").strip()
        if r and r[0] == "Name" and "Identifier" in r:
            hdr_idx = i
            break
    positions, skipped = [], []
    if hdr_idx is not None:
        hdr = rows[hdr_idx]
        col = {h: hdr.index(h) for h in hdr if h}
        for r in rows[hdr_idx + 1:]:
            if not r or not any(r):
                continue
            ident = (r[col.get("Identifier", -1)] if col.get("Identifier") is not None else "") or ""
            shares = r[col.get("Shares Held", -1)] if col.get("Shares Held") is not None else None
            name = str(r[col.get("Name", 0)] or "")
            if not str(ident).strip() or shares is None:
                # NON silenzioso: registro il drop. has_quantity=True → posizione materiale persa (ALERT),
                # altrimenti riga di footer/disclaimer (benigna).
                skipped.append({"name": name[:60], "identifier": str(ident).strip(),
                                "has_quantity": shares is not None and str(shares).strip() not in ("", "-")})
                continue
            positions.append(Position(
                identifier=str(ident), id_scheme="CUSIP", quantity=str(shares),
                name=name, weight=str(r[col.get("Weight", "")] or "")))
    return Holdings(fund_id=fund_id, as_of=as_of, source="ssga", positions=positions, skipped=skipped)


def parse_holdings_csv(text: str, id_col: str = "ISIN", qty_col: str = "Shares",
                       id_scheme: str = "ISIN", name_col: str = "Name") -> Holdings:
    """Parser CSV generico (iShares/emittente). Colonne configurabili — la SPEC dice quali sono i campi
    economici; il resto è cosmetico. `id_col`/`qty_col` mappano lo schema della fonte alla forma canonica."""
    import csv
    import io
    rdr = csv.DictReader(io.StringIO(text))
    positions = []
    for row in rdr:
        ident = (row.get(id_col) or "").strip()
        qty = row.get(qty_col)
        if not ident or qty in (None, "", "-"):
            continue
        try:
            _canon_quantity(qty)
        except ValueError:
            continue
        positions.append(Position(identifier=ident, id_scheme=id_scheme, quantity=str(qty),
                                  name=(row.get(name_col) or "").strip()))
    return Holdings(fund_id="", as_of="", source="csv", positions=positions)


def parse_nport_xml(text: str, id_scheme: str = "CUSIP") -> Holdings:
    """Parser SEC N-PORT (EDGAR) — la fonte migliore per storico strutturato. Ogni <invstOrSec> ha
    identificatori (cusip/isin/ticker), <balance> (quantità) e valuta. Namespace-agnostico (tag locali)."""
    import xml.etree.ElementTree as ET

    def local(t):
        return t.rsplit("}", 1)[-1]

    root = ET.fromstring(text)
    fund_id = as_of = ""
    for el in root.iter():
        lt = local(el.tag)
        if lt == "seriesId" and el.text and not fund_id:
            fund_id = el.text.strip()
        if lt in ("repPdDate", "reportDate") and el.text and not as_of:
            as_of = el.text.strip()
    positions = []
    for sec in root.iter():
        if local(sec.tag) != "invstOrSec":
            continue
        ident = scheme = qty = None
        name = ""
        for ch in sec:
            lt = local(ch.tag)
            if lt == "cusip" and ch.text:
                ident, scheme = ch.text.strip(), "CUSIP"
            elif lt == "balance" and ch.text:
                qty = ch.text.strip()
            elif lt == "name" and ch.text and not name:
                name = ch.text.strip()
            elif lt == "identifiers":
                for idn in ch:
                    if local(idn.tag) == "isin" and idn.get("value") and not ident:
                        ident, scheme = idn.get("value").strip(), "ISIN"
        if ident and qty is not None:
            try:
                _canon_quantity(qty)
            except ValueError:
                continue
            positions.append(Position(identifier=ident, id_scheme=scheme or id_scheme,
                                      quantity=str(qty), name=name))
    return Holdings(fund_id=fund_id, as_of=as_of, source="nport", positions=positions)
