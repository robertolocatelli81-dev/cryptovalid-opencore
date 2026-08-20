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
import html as _html
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
    currency: str = ""              # B2: valuta locale del titolo (curCd) — per l'esposizione multi-valuta
    value: str = ""                 # B2: valore (in base, es. valUSD) — per esposizione/attestazione, non nel digest-core
    asset_class: str = ""           # B5: categoria (assetCat: EC equity, DBT debt, DE derivato…) — metadata,
    #                                 NON nel digest (l'identificatore già distingue lo strumento); per esposizione


@dataclass
class Holdings:
    fund_id: str                    # ticker o ISIN del fondo
    as_of: str                      # data di riferimento (come pubblicata)
    source: str                     # 'ssga'|'ishares'|'nport'|... — provenienza
    positions: List[Position] = field(default_factory=list)
    skipped: List[Dict] = field(default_factory=list)   # righe NON incluse — MAI in silenzio (trovato dal
    #                                                     killer-experiment: un cert tool non deve droppare)


@dataclass
class Valuation:
    """Pack di valorizzazione di un fondo. FUNDCERT lo ATTESTA (coerenza interna dei numeri forniti + fingerprint),
    NON lo calcola: non prezza titoli, non fa fair value. Il calcolo NAV resta del fund administrator."""
    fund_id: str
    as_of: str
    total_assets: str
    total_liabilities: str
    net_assets: str
    securities_value: str = ""      # Σ dei valori dei titoli (se disponibile: copertura vs total_assets)
    source: str = ""


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


def corporate_action_flag(a: float, b: float, tol: float = 0.02) -> Dict:
    """B4 — annota una differenza di quantità: candidato SPLIT/REVERSE (rapporto ≈ n:m semplice) vs discrepanza.
    Wolfspeed +2907% non è un 'errore' nudo: è un rapporto ~1:30 = azione societaria. Distinguere il segnale
    actionable (split/reverse da confermare) dal vero mismatch rende la lista materiale utile, non rumore."""
    if a <= 0 or b <= 0:
        return {"kind": "discrepancy"}
    hi, lo = (b, a) if b >= a else (a, b)
    r = hi / lo
    for n in range(2, 51):                       # split n:1 / reverse 1:n
        if abs(r - n) / n <= tol:
            return {"kind": "split_candidate", "ratio": f"{n}:1" if b >= a else f"1:{n}"}
    for q in (2, 3, 4, 5):                        # split frazionari comuni (3:2, 4:3, 5:4…)
        for p in range(q + 1, 2 * q + 1):
            if abs(r - p / q) / (p / q) <= tol:
                return {"kind": "split_candidate", "ratio": f"{p}:{q}" if b >= a else f"{q}:{p}"}
    return {"kind": "discrepancy"}               # nessun rapporto semplice → probabile mismatch reale


def norm_name(name: str) -> str:
    """Normalizza un nome titolo per il match cross-source quando NON c'è un id comune (es. N-CSR senza CUSIP)."""
    n = name.upper()
    n = re.sub(r"[.,/&]", " ", n)
    n = re.sub(r"\b(INC|CORP|CO|LTD|PLC|CLASS|THE|COMPANY|HLDGS|HOLDINGS|GROUP|INTL|INTERNATIONAL|CORPORATION)\b",
               " ", n)
    return re.sub(r"\s+", " ", n).strip()


def reconcile(a: Holdings, b: Holdings, by: str = "id", id_target: Optional[str] = None,
              material_tol: float = 0.02, fixed_scale: Optional[float] = None) -> Dict:
    """Riconciliazione tra due fonti dello STESSO fondo/data — il VERO valore del prodotto (non l'uguaglianza
    del digest). Trovato sul dato SEC reale (N-PORT vs N-CSR del Vanguard 500 Index Fund, 31/12/2025): due
    filing autorevoli NON coincidono — differiscono per un FATTORE DI SCALA globale (+0.397%, sec-lending/units)
    a composizione identica. `reconcile` lo MISURA e separa la scala dalle differenze reali per-titolo.
    by='id' allinea per (scheme,id[,id_target]); by='name' per nome normalizzato (quando manca l'id comune);
    by='auto' = IDENTIFIER-FIRST: usa ISIN/CUSIP(→ISIN) quando la posizione lo porta, nome come fallback — è il
    match che i bond/MBS richiedono (nome+coupon+maturity collide tra pool diversi; il CUSIP no). CONFINE: 'auto'
    allinea due fonti che portano ENTRAMBE l'identificatore (custodian/PCF/N-PORT); se una fonte NON ha id (es.
    N-CSR, solo nome) le chiavi id-vs-nome non si allineano → per quel caso usa by='name'.
    Ritorna: matched, scale_factor/scale_pct, residual_after_scale (mismatch DOPO la scala), only_in_*."""
    import statistics as _st

    def _auto_key(p):
        """Chiave IDENTIFIER-FIRST: ISIN se c'è, CUSIP→ISIN normalizzato, altrimenti il nome (fallback).
        Risolve le collisioni che il nome non regge (es. MBS pool: stesso nome/coupon/maturity, CUSIP diverso)
        quando la fonte PORTA l'identificatore — è il match che i bond richiedono."""
        scheme, ident = p.id_scheme.strip().upper(), p.identifier.strip().upper()
        if scheme == "ISIN" and ident:
            return f"ISIN:{ident}"
        if scheme == "CUSIP" and ident:
            isin = cusip_to_isin(ident)
            return f"ISIN:{isin}" if isin else f"CUSIP:{ident}"
        return f"NAME:{norm_name(p.name)}" if p.name else None

    def _q(h):
        m: Dict = {}
        if by == "name":
            for p in h.positions:
                if p.name:
                    m.setdefault(norm_name(p.name), []).append(_canon_quantity(p.quantity))
        elif by == "auto":                          # identificatore quando c'è, nome come fallback
            for p in h.positions:
                k = _auto_key(p)
                if k:
                    m.setdefault(k, []).append(_canon_quantity(p.quantity))
        else:
            for p in canonical_form(h, id_target)["positions"]:
                m.setdefault(f"{p['scheme']}:{p['id']}", []).append(p["qty"])
        return {k: sorted(v) for k, v in m.items()}

    qa, qb = _q(a), _q(b)
    common = set(qa) & set(qb)
    # fixed_scale: quando le due fonti NON hanno un fattore di scala globale (es. stesso portafoglio da due viste,
    # microcredito MFI-vs-donatore), forzare 1.0 evita che la mediana — contaminata dalle discrepanze reali —
    # falsi il confronto. Default None = auto-rileva la scala (caso N-CSR vs N-PORT con differenza di unità).
    if fixed_scale is not None:
        scale = fixed_scale
    else:
        ratios = [float(qb[k][0]) / float(qa[k][0]) for k in common
                  if len(qa[k]) == 1 and len(qb[k]) == 1 and float(qa[k][0]) != 0]
        scale = _st.median(ratios) if ratios else 1.0
    # Un residuo va classificato per la sua ENTITÀ RELATIVA, non con una soglia assoluta cieca alla dimensione.
    # Misurato su 12 fondi Vanguard reali: il rumore di quantizzazione/timing è ~costante in ASSOLUTO (~mille
    # azioni) → appare grande in % sulle posizioni piccole (small-cap) e trascurabile sulle grandi. Usare una
    # soglia relativa fissa fabbricava false "anomalie" sui fondi small-cap. material_tol separa la differenza
    # REALE (grande in %, un holding davvero mis-stated) dal rumore MINORE (piccolo in %, quantizzazione/timing).
    residual, minor = [], 0
    for k in sorted(common):
        if len(qa[k]) == 1 and len(qb[k]) == 1:
            va, vb = float(qa[k][0]), float(qb[k][0])
            if va == 0:
                continue
            rel = abs(vb / scale - va) / abs(va)
            if rel > material_tol:                       # differenza MATERIALE (probabile discrepanza reale)
                residual.append({"key": k, "a": qa[k][0], "b": qb[k][0], "rel_pct": round(rel * 100, 3),
                                 "flag": corporate_action_flag(va, vb)})   # B4: split/reverse candidato vs discrepanza
            elif rel > 5e-4:                             # residuo MINORE (rumore quantizzazione/timing)
                minor += 1
    return {
        "by": by,
        "matched": len(common),
        "scale_factor": round(scale, 6),
        "scale_pct": round((scale - 1) * 100, 4),
        "material_tol_pct": round(material_tol * 100, 3),
        "residual_after_scale": residual,               # SOLO le differenze materiali (> material_tol)
        "residual_count": len(residual),                # = differenze reali; le anomalie small-cap NON entrano
        "minor_residual_count": minor,                  # rumore di quantizzazione/timing (piccolo in %)
        "only_in_a": len(set(qa) - set(qb)),
        "only_in_b": len(set(qb) - set(qa)),
    }


def canonicalizer_fingerprint() -> str:
    """Fingerprint del METODO di canonicalizzazione — lega il digest alle REGOLE esatte, non solo al codice
    pubblico (critica Gemini: la ri-computabilità serve un metodo stabile). Cambia se cambia una regola-core."""
    spec = (f"{CANON_VERSION}|qdp={QUANTITY_DP}|round=ROUND_HALF_EVEN|"
            f"sort=(scheme,id,qty,cash)|hash=sha3_256|content_only")
    return hashlib.sha3_256(spec.encode()).hexdigest()[:16]


def evidence_record(raw_input, source: str, fetched_at: str, holdings_digest: str,
                    fund_id: str = "", as_of: str = "") -> Dict:
    """Lega il digest all'INPUT che l'ha prodotto (provenienza: sha256 dei byte grezzi + fonte + quando) e al
    METODO (fingerprint) → un record di evidenza autoconsistente che prova COSA input, COME, COSA risultato.
    Risponde alla critica Gemini 'un digest non dice da dove viene': senza legare l'input, la ri-computabilità è
    inutile. Va poi hash-chained nel ledger OMEGA per il tamper-evidence (chi/quando lo sigilla). `fetched_at`
    è fornito dal chiamante (tempo reale della fonte) — NON inventato qui."""
    raw = raw_input if isinstance(raw_input, bytes) else str(raw_input).encode()
    rec = {
        "kind": "fundcert_evidence", "fund_id": fund_id, "as_of": as_of,
        "source": source, "fetched_at": fetched_at,
        "input_sha256": hashlib.sha256(raw).hexdigest(),        # PROVENIENZA: quale input esatto
        "canon_version": CANON_VERSION,
        "canonicalizer_fp": canonicalizer_fingerprint(),        # METODO: quali regole
        "holdings_digest": holdings_digest,                     # RISULTATO
    }
    rec["record_digest"] = hashlib.sha3_256(
        json.dumps(rec, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return rec


def resolve_exception(item: Dict, resolver: str, reason: str, decision: str, at: str = "") -> Dict:
    """Il CHI/PERCHÉ che Gemini indicava mancante: registra la RISOLUZIONE di un'eccezione di triage (chi, perché,
    quale decisione, quando). È il contesto operativo che un fingerprint da solo non porta; da hash-chainare per
    la forensics. `at` (timestamp) fornito dal chiamante, non inventato."""
    out = dict(item)
    out["status"] = "resolved"
    out["resolution"] = {"resolver": resolver, "reason": reason, "decision": decision, "at": at}
    out["resolution_digest"] = hashlib.sha3_256(
        json.dumps({"key": item.get("key"), **out["resolution"]}, sort_keys=True,
                   separators=(",", ":")).encode()).hexdigest()
    return out


def valuation_digest(v: Valuation) -> str:
    """SHA3-256 sull'INTERO pack di valorizzazione (totali + Σ titoli), non solo sulle quantità. Ri-derivabile."""
    canon = {
        "canon_version": CANON_VERSION, "kind": "valuation",
        "fund_id": v.fund_id, "as_of": v.as_of,
        "total_assets": _canon_quantity(v.total_assets),
        "total_liabilities": _canon_quantity(v.total_liabilities),
        "net_assets": _canon_quantity(v.net_assets),
        "securities_value": _canon_quantity(v.securities_value) if v.securities_value not in ("", None) else "",
    }
    return hashlib.sha3_256(json.dumps(canon, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def attest_valuation(v: Valuation, tol_abs: str = "1", tol_rel: str = "0") -> Dict:
    """ATTESTAZIONE (non calcolo) della coerenza interna di un pack di valorizzazione:
      (1) identità contabile  total_assets − total_liabilities == net_assets  (esatta sui dati SEC reali);
      (2) copertura           Σ(valore titoli) ≤ total_assets  e  cash/altri = total_assets − Σtitoli ≥ 0.
    Ritorna gli esiti + il digest dell'intero pack. CONFINE: verifica i numeri FORNITI, NON prezza né calcola
    il NAV (quello è del fund administrator). Un NAV sbagliato ma internamente coerente supera l'attestazione:
    è proof-of-consistency, non proof-of-veracity — lo stesso confine di CryptoValid."""
    ta, tl, na = Decimal(str(v.total_assets)), Decimal(str(v.total_liabilities)), Decimal(str(v.net_assets))
    tol = max(Decimal(tol_abs), abs(na) * Decimal(tol_rel))
    identity_gap = (ta - tl) - na
    out = {
        "fund_id": v.fund_id, "as_of": v.as_of,
        "identity_ok": bool(abs(identity_gap) <= tol),      # totAssets − totLiabs == netAssets
        "identity_gap": str(identity_gap),
        "coverage_ok": None, "non_security_assets": None,
        "digest": valuation_digest(v),
        "attests": "coerenza interna dei numeri forniti; NON un calcolo/prezzatura del NAV",
    }
    if v.securities_value not in ("", None):
        sec = Decimal(str(v.securities_value))
        non_sec = ta - sec
        out["coverage_ok"] = bool(sec <= ta + tol and non_sec >= -tol)   # titoli ≤ attivo, cash/crediti ≥ 0
        out["non_security_assets"] = str(non_sec)
    return out


def name_similarity(a: str, b: str) -> float:
    """C2 — similarità nome per il fuzzy fallback (0..1): Jaccard sui token normalizzati ∪ ratio di sequenza.
    Solo stdlib. Serve a recuperare nomi quasi-uguali (abbreviazioni, ordini diversi) quando manca l'id."""
    import difflib
    na, nb = norm_name(a), norm_name(b)
    if not na or not nb:
        return 0.0
    ta, tb = set(na.split()), set(nb.split())
    jacc = len(ta & tb) / len(ta | tb) if (ta | tb) else 0.0
    seq = difflib.SequenceMatcher(None, na, nb).ratio()
    return max(jacc, seq)


def _block_keys(name: str) -> tuple:
    """Chiavi di BLOCKING per il fuzzy: primo token e prefisso — due nomi simili ne condividono almeno una.
    Riduce i confronti da n×m (O(n²)) a soli quelli plausibili (record-linkage standard)."""
    n = norm_name(name)
    if not n:
        return ()
    first = n.split()[0]
    return (f"t:{first}", f"p:{n[:4]}")


def fuzzy_bridge(names_a: List[str], names_b: List[str], threshold: float = 0.85,
                 blocking: bool = True) -> List[Dict]:
    """C2 — accoppia i nomi NON matchati esattamente tra due fonti, sopra `threshold`, greedy sul punteggio più
    alto (1:1). Ogni ponte porta lo score (l'umano lo vede/rifiuta). `blocking=True` (default) confronta solo i
    nomi che condividono una chiave di blocking → sub-quadratico su grandi insiemi; blocking=False = tutte le
    coppie (esatto ma O(n²))."""
    if blocking:
        index: Dict = {}
        for b in names_b:                               # indicizza B per chiave di blocking
            for k in _block_keys(b):
                index.setdefault(k, set()).add(b)
        cand_pairs = set()
        for a in names_a:
            for k in _block_keys(a):
                for b in index.get(k, ()):              # solo i B che condividono un blocco con A
                    cand_pairs.add((a, b))
        scored = ((name_similarity(a, b), a, b) for a, b in cand_pairs)
    else:
        scored = ((name_similarity(a, b), a, b) for a in names_a for b in names_b)
    cand = sorted((t for t in scored if t[0] >= threshold), key=lambda t: -t[0])
    pairs, used_a, used_b = [], set(), set()
    for s, a, b in cand:
        if a in used_a or b in used_b:
            continue
        used_a.add(a); used_b.add(b); pairs.append({"a": a, "b": b, "score": round(s, 3)})
    return pairs


def parse_mapped(rows: List[Dict], mapping: Dict, fund_id: str = "", as_of: str = "", source: str = "mapped") -> Holdings:
    """C1 — ingestion GENERICA: qualsiasi sorgente tabellare (list di dict) diventa Holdings dichiarando una
    mappa campo→colonna, senza un parser bespoke. `mapping` es: {'identifier':'CUSIP','id_scheme':'=CUSIP',
    'quantity':'Shares','name':'Name','currency':'Ccy','value':'MktVal'}. Un valore con prefisso '=' è LETTERALE
    (scheme fisso). Salta le righe senza identifier o quantity, tracciandole in skipped (mai in silenzio)."""
    def get(row, spec):
        if not spec:
            return ""
        return spec[1:] if spec.startswith("=") else str(row.get(spec, "")).strip()
    positions, skipped = [], []
    for row in rows:
        ident, qty = get(row, mapping.get("identifier")), get(row, mapping.get("quantity"))
        if not ident or not qty:
            skipped.append({"name": get(row, mapping.get("name")), "identifier": ident,
                            "has_quantity": bool(qty)})
            continue
        positions.append(Position(identifier=ident, id_scheme=get(row, mapping.get("id_scheme")) or "TICKER",
                                  quantity=qty, name=get(row, mapping.get("name")),
                                  currency=get(row, mapping.get("currency")), value=get(row, mapping.get("value"))))
    return Holdings(fund_id=fund_id, as_of=as_of, source=source, positions=positions, skipped=skipped)


_ASSET_CLASS_LABEL = {"EC": "equity", "DBT": "debt", "DE": "derivative", "RA": "repo",
                      "SN": "short-term-note", "LON": "loan", "ABS": "asset-backed",
                      "COMM": "commodity", "RE": "real-estate", "STIV": "short-term-investment"}


def asset_class_exposure(h: Holdings) -> Dict:
    """B5 — esposizione per CLASSE d'asset (equity/debt/derivato/…), da `assetCat` dell'N-PORT. Risponde alla
    deficienza Gemini 'copertura asset class/derivati': il tool ora VEDE i derivati e li separa, invece di
    confonderli con le azioni. Metadata a parte (l'id li distingue già nel digest). Value in base (es. USD)."""
    exp: Dict = {}
    unknown = 0
    for p in h.positions:
        if p.value in ("", None):
            unknown += 1
            continue
        cls = _ASSET_CLASS_LABEL.get((p.asset_class or "").strip().upper(), (p.asset_class or "unclassified").strip() or "unclassified")
        exp[cls] = exp.get(cls, Decimal(0)) + Decimal(str(p.value))
    total = sum(exp.values()) or Decimal(1)
    return {"by_class": {k: str(v) for k, v in sorted(exp.items(), key=lambda kv: -kv[1])},
            "pct": {k: round(float(v / total) * 100, 3) for k, v in exp.items()},
            "n_classes": len(exp), "positions_without_value": unknown,
            "has_derivatives": exp.get("derivative", Decimal(0)) > 0}


def currency_exposure(h: Holdings) -> Dict:
    """B2 — esposizione multi-valuta: somma il `value` (in base, es. USD) per `currency` locale del titolo.
    La riconciliazione per SHARES è indipendente dalla valuta; questo dà la vista di rischio-valuta che i fondi
    internazionali richiedono. Le posizioni senza value dichiarato finiscono in 'unknown' (mai perse in silenzio)."""
    exp: Dict = {}
    unknown = 0
    for p in h.positions:
        if p.value in ("", None):
            unknown += 1
            continue
        cur = (p.currency or "UNSPECIFIED").strip().upper()
        exp[cur] = exp.get(cur, Decimal(0)) + Decimal(str(p.value))
    total = sum(exp.values()) or Decimal(1)
    return {"by_currency": {k: str(v) for k, v in sorted(exp.items(), key=lambda kv: -kv[1])},
            "pct": {k: round(float(v / total) * 100, 3) for k, v in exp.items()},
            "n_currencies": len(exp), "positions_without_value": unknown}


def is_inflation_linked(name: str) -> bool:
    """B3 — rileva un titolo inflation-linked (TIPS/linker): per questi il face (N-CSR) ≠ principal
    inflation-adjusted (N-PORT), quindi la differenza NON è una discrepanza ma l'accrual d'inflazione.
    Vanno riconciliati sul principal adjusted, non sul face — o si riporta il fattore-indice implicito."""
    n = name.upper()
    return any(t in n for t in ("TIPS", "INFLATION", "INFLATION-INDEXED", "INFLATION INDEXED",
                                "INDEX-LINKED", "INDEXED BOND", "CPI"))


def triage(recon_result: Dict, top: Optional[int] = None) -> Dict:
    """C3 — da un risultato di `reconcile` produce un worklist di eccezioni PRIORITIZZATO (severità + azione),
    lo scaffold minimo di un workflow: non un ticketing completo, ma il residuo materiale diventa lavoro
    ordinato e azionabile invece di un elenco piatto. Ogni voce ha stato 'open' (four-eyes a valle)."""
    items = []
    for r in recon_result.get("residual_after_scale", []):
        rel = r.get("rel_pct", 0)
        sev = "high" if rel >= 50 else "medium" if rel >= 10 else "low"
        flag = r.get("flag", {}) or {}
        action = ("confirm_corporate_action" if flag.get("kind") == "split_candidate"
                  else "investigate_discrepancy")
        items.append({"key": r["key"], "rel_pct": rel, "severity": sev, "action": action,
                      "flag": flag, "status": "open"})
    items.sort(key=lambda x: -x["rel_pct"])
    by_action: Dict = {}
    for it in items:
        by_action[it["action"]] = by_action.get(it["action"], 0) + 1
    return {"open": len(items), "by_action": by_action,
            "worklist": items[:top] if top else items}


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
        cur = val = acat = ""
        for ch in sec:
            lt = local(ch.tag)
            if lt == "cusip" and ch.text:
                ident, scheme = ch.text.strip(), "CUSIP"
            elif lt == "balance" and ch.text:
                qty = ch.text.strip()
            elif lt == "name" and ch.text and not name:
                name = ch.text.strip()
            elif lt == "curCd" and ch.text:              # B2: valuta locale (elemento diretto)
                cur = ch.text.strip()
            elif lt == "currencyConditional":            # B2: valuta estera come attributo (+ tasso di cambio)
                cur = (ch.get("curCd") or cur).strip()
            elif lt == "valUSD" and ch.text:             # B2: valore in USD (base)
                val = ch.text.strip()
            elif lt == "assetCat" and ch.text:           # B5: categoria d'asset (equity/debt/derivato…)
                acat = ch.text.strip()
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
                                      quantity=str(qty), name=name, currency=cur, value=val, asset_class=acat))
    return Holdings(fund_id=fund_id, as_of=as_of, source="nport", positions=positions)


def parse_nport_valuation(text: str) -> Valuation:
    """Estrae il pack di valorizzazione da un N-PORT: totAssets, totLiabs, netAssets (header) + Σ(valUSD) dei
    titoli. Da dare a `attest_valuation()` per verificare l'identità contabile e la copertura sui dati reali."""
    def _first(tag):
        m = re.search(rf"<{tag}>([^<]*)</{tag}>", text)
        return m.group(1).strip() if m else "0"
    sid = re.search(r"<seriesId>([^<]*)</seriesId>", text)
    per = re.search(r"<repPdDate>([^<]*)</repPdDate>", text)
    sec_sum = sum(Decimal(v) for v in re.findall(r"<valUSD>([^<]*)</valUSD>", text)) if "<valUSD>" in text else Decimal(0)
    return Valuation(fund_id=sid.group(1).strip() if sid else "", as_of=per.group(1).strip() if per else "",
                     total_assets=_first("totAssets"), total_liabilities=_first("totLiabs"),
                     net_assets=_first("netAssets"), securities_value=str(sec_sum), source="nport")


def _ncsr_soi_sections(raw: str) -> List[tuple]:
    """[(fund_name, start_offset)] per ogni Schedule of Investments in un documento N-CSR (HTML)."""
    secs = []
    for m in re.finditer(r"Schedule of Investments", raw):
        i = m.start()
        ctx = _html.unescape(re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", raw[max(0, i - 1500):i])))
        mm = list(re.finditer(r"([A-Z][A-Za-z0-9&\-/ ]{3,45}? Fund)\s+Financial Statements", ctx))
        if mm:
            secs.append((mm[-1].group(1).strip(), i))
    return secs


def _ncsr_parse_row(cells: List[str]):
    """Nome = ULTIMA cella con lettere (non header/settore); shares = PRIMO intero DOPO il nome. Robusto ai
    marcatori di nota in testa ('*,1' sposta le colonne) — trovato su N-PORT/N-CSR Vanguard reali."""
    name_idx = None
    for i, cc in enumerate(cells):
        if (re.search(r"[A-Za-z]", cc) and len(cc) > 2 and not cc.endswith("%)")
                and not cc.endswith(":") and cc != "Shares" and "Market" not in cc and "Value" not in cc):
            name_idx = i
    if name_idx is None:
        return None
    for cc in cells[name_idx + 1:]:
        v = cc.replace(",", "")
        if re.fullmatch(r"\d+", v):
            return cells[name_idx], v
    return None


def parse_ncsr_soi(html_text: str, fund_name: str) -> Holdings:
    """Parser dello Schedule of Investments da un report SEC N-CSR (HTML). L'N-CSR NON porta CUSIP →
    id_scheme='NAME' (riconciliazione per nome via `reconcile(by='name')`, non per digest). Isola la sezione
    del fondo (header '<fund_name> ... Schedule of Investments') e la chiude alla successiva 'Statement of
    Assets' o alla sezione SOI seguente; tollera i marcatori di nota che spostano le colonne.
    HONEST SCOPE: tarato su SOI tabellari Nome/Shares/Value (validato su 12 fondi Vanguard reali, 2025-12-31);
    N-CSR di altre famiglie possono richiedere adattamento. È una SECONDA fonte per riconciliare, non un digest."""
    secs = _ncsr_soi_sections(html_text)
    starts = [off for (nm, off) in secs if nm == fund_name]
    if not starts:
        raise ValueError(f"sezione SOI non trovata: {fund_name!r} (disponibili: {sorted({n for n, _ in secs})})")
    start = starts[0]
    later = [off for (_, off) in secs if off > start]
    sa = html_text.find("Statement of Assets", start)
    end = min([x for x in ([sa] + later) if x > start] or [start + 3_000_000])
    seg = html_text[start:end]
    positions, skipped = [], []
    for r in re.findall(r"<tr[^>]*>(.*?)</tr>", seg, re.S):
        cells = [_html.unescape(re.sub(r"<[^>]+>", "", x)).strip().replace("\n", " ")
                 for x in re.findall(r"<t[dh][^>]*>(.*?)</t[dh]>", r, re.S)]
        cells = [y for y in cells if y != ""]
        row = _ncsr_parse_row(cells)
        if row:
            positions.append(Position(identifier="", id_scheme="NAME", quantity=row[1], name=row[0]))
    return Holdings(fund_id=fund_name, as_of="", source="ncsr", positions=positions, skipped=skipped)
