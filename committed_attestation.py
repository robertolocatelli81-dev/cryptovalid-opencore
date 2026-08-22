# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Roberto Locatelli
"""
committed_attestation — Committed-Ledger Derived-Metric Attestation (CLDMA).

Il gap (verificato 2026-08-20, Gemini Pro + ricerca): i primitivi esistono separati
(proof-of-reserves Merkle prova una SOMMA; ZK-PoR prova con privacy; selective disclosure),
ma NESSUNO prova che un RATIO REGOLATORIO DERIVATO (PAR30, write-off ratio, risk coverage)
sia correttamente ricalcolato da un LEDGER PRIVATO IMPEGNATO, senza rivelare i singoli prestiti,
con le discrepanze localizzabili al record.

Costruzione (zero-dipendenze, solo SHA3-256): MERKLE SUM TREE (Maxwell proof-of-liabilities) esteso.
Ogni foglia impegna il record salato e porta due contributi interi (numeratore, denominatore) del
ratio. Ogni nodo porta (hash, somma_num, somma_den). La radice porta i totali -> il ratio pubblicato
= num_total/den_total e' LEGATO crittograficamente al ledger impegnato.

HONEST-SCOPE (dichiarato, non ZK):
- ROBUSTO: (1) tamper-evidence deterministica — qualunque modifica ai dati impegnati dopo il commit
  cambia la radice; (2) i totali num/den sono legati ESPLICITAMENTE alla radice pubblicata
  (`_bind_meta` li hasha, dal 2026-08-21) -> `verify_attestation` verifica che i totali pubblicati
  sono quelli IMPEGNATI (prima si fidava dei campi = falso-verde), e verify_open impone la
  NON-NEGATIVITA' dei contributi del path (prima un sibling negativo sgonfiava il ratio); (3) l'apertura selettiva challenge-based
  (indici da beacon pubblico = hash(root||nonce)) permette al verificatore di controllare l'INCLUSIONE e
  la CLASSIFICAZIONE dei record aperti contro la definizione della metrica.
- ESTRAPOLATO / LIMITE: la correttezza della classificazione di OGNI record (senza aprirli tutti) e'
  garantita solo in modo PROBABILISTICO (detection = 1-(1-f)^k, f = frazione misclassificata, k = sfide).
  La prova a conoscenza-zero della classificazione di tutti i record e' un layer successivo (pesante, ZK)
  qui NON implementato. La privacy e' RIDOTTA (i record sfidati vengono aperti), NON zero-knowledge.
- Non prova la VERACITA' del ledger (garbage-in resta garbage): prova coerenza/integrita', non che i
  prestiti esistano davvero. Modalita' regolatore (verify_full) = apertura completa, assurance totale,
  PII vista solo dal regolatore. Modalita' pubblica = radice + totali + campione sfidato.

LIMITI TROVATI DA NEMESIS (2026-08-20) e loro stato:
- E1 metadati non legati alla radice -> CHIUSO: `_bind_meta` hasha n/metric_id/as_of/spec nella radice pubblicata.
- E3 verify_open([]) vacuo -> CHIUSO: apertura vuota => all_ok False.
- E2 nonce grinding -> REQUISITO DI PROTOCOLLO (documentato in `challenge`): il nonce DEVE venire dal
  verificatore/beacon dopo il commit, altrimenti il prover lo macina per evitare le foglie manipolate.
- E4 COMPLETEZZA non provata (limite intrinseco di OGNI commitment): un prover puo' impegnare un sottoinsieme
  e nascondere i prestiti peggiori. Mitigazione: `verify_full(expected_n=...)` col conteggio da fonte
  indipendente; l'ancoraggio pieno (che NON manchi nessun prestito) e' FUORI dallo schema.
- E5 second-preimage leaf/internal -> difeso dai prefissi di dominio 'L|'/'N|'.
- BUCO A (controllo 3-menti 2026-08-21) -> CHIUSO: `verify_attestation` non legava num/den alla
  radice (solo check aritmetico) -> un prover pubblicava totali falsi con radice reale. Ora i totali
  sono in `_bind_meta` e verify_attestation li verifica (fail-closed senza tree_root). Bump CLDMA-2.
- BUCO B (exploit riprodotto 2026-08-21) -> CHIUSO: `verify_open` sommava i contributi del path senza
  imporne la non-negativita' -> un sibling NEGATIVO (albero costruito a mano) sgonfiava il numeratore
  passando sums_ok. Ora ogni contributo del path e' controllato >= 0, come le foglie al commit.
"""
from __future__ import annotations
import hashlib
import json
from dataclasses import dataclass, field
from decimal import Decimal
from typing import Callable, Dict, List, Optional, Tuple

SPEC_VERSION = "CLDMA-2"   # 2026-08-21: totali legati ESPLICITAMENTE alla radice (buco A)


def _h(s: str) -> str:
    return hashlib.sha3_256(s.encode("utf-8")).hexdigest()


def _enc(*parts) -> str:
    """Encoding NON ambiguo dei campi in un hash (fix field-injection): JSON invece di 'a|b|c'.
    Con 'a|b|c' due tuple diverse ('PAR30','2026') e ('PAR30|2026','') collidono; JSON no (stringhe quotate)."""
    return json.dumps([str(p) for p in parts], separators=(",", ":"), ensure_ascii=False)


def to_minor(x) -> int:
    """Decimale -> unita' minori intere (2 dp, half-even). Aritmetica esatta, niente float."""
    return int((Decimal(str(x)).quantize(Decimal("0.01")) * 100).to_integral_value())


def canonical_record(rec: Dict) -> str:
    """Serializzazione canonica deterministica del record (sort_keys, separatori compatti)."""
    return json.dumps(rec, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


# --------------------------------------------------------------------------- #
#  Definizione di metrica: da un record -> (contributo_numeratore, contributo_denominatore)
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class MetricSpec:
    metric_id: str
    num_of: Callable[[Dict], int]   # contributo intero al numeratore
    den_of: Callable[[Dict], int]   # contributo intero al denominatore


def _outstanding(r: Dict) -> int:
    return to_minor(r.get("principal_outstanding", "0"))


def _is_at_risk_30(r: Dict) -> bool:
    try:
        overdue = int(Decimal(str(r.get("days_overdue", "0"))))
    except Exception:
        overdue = 0
    status = str(r.get("status", "")).strip().lower()
    return overdue > 30 or status in ("renegotiated", "restructured", "rescheduled")


# PAR30 = (outstanding dei prestiti >30gg + rinegoziati) / outstanding totale
SPEC_PAR30 = MetricSpec(
    metric_id="PAR30",
    num_of=lambda r: _outstanding(r) if _is_at_risk_30(r) else 0,
    den_of=_outstanding,
)
# Write-off ratio = write-offs / outstanding (denominatore semplificato al portafoglio impegnato)
SPEC_WRITEOFF = MetricSpec(
    metric_id="WRITEOFF_RATIO",
    num_of=lambda r: to_minor(r.get("principal_written_off", "0")),
    den_of=_outstanding,
)


# --------------------------------------------------------------------------- #
#  Merkle Sum Tree
# --------------------------------------------------------------------------- #
def leaf_salt(master_salt: str, i: int) -> str:
    return _h(f"{master_salt}|leaf|{i}")


def leaf_node(rec: Dict, salt: str, num: int, den: int) -> Dict:
    commit = _h(_enc("commit", salt, canonical_record(rec)))
    # l'hash-foglia lega commit del record + contributi -> la classificazione e' vincolata alla radice
    node_hash = _h(_enc("L", commit, num, den))
    return {"hash": node_hash, "num": num, "den": den, "commit": commit}


def _combine(l: Dict, r: Dict) -> Dict:
    num = l["num"] + r["num"]
    den = l["den"] + r["den"]
    node_hash = _h(_enc("N", l["hash"], r["hash"], num, den))
    return {"hash": node_hash, "num": num, "den": den}


def build_leaves(records: List[Dict], master_salt: str, spec: MetricSpec) -> List[Dict]:
    leaves = []
    for i, rec in enumerate(records):
        num = spec.num_of(rec)
        den = spec.den_of(rec)
        if num < 0 or den < 0:
            raise ValueError(f"contributo negativo al record {i}: num={num} den={den} (Maxwell richiede non-negativi)")
        leaves.append(leaf_node(rec, leaf_salt(master_salt, i), num, den))
    return leaves


def _levels(leaves: List[Dict]) -> List[List[Dict]]:
    if not leaves:
        raise ValueError("ledger vuoto")
    levels = [leaves]
    cur = leaves
    while len(cur) > 1:
        nxt = []
        for j in range(0, len(cur), 2):
            if j + 1 < len(cur):
                nxt.append(_combine(cur[j], cur[j + 1]))
            else:
                nxt.append(cur[j])  # nodo dispari promosso (duplicazione evitata: nessun second-preimage banale)
        levels.append(nxt)
        cur = nxt
    return levels


@dataclass
class Commitment:
    root_hash: str        # radice PUBBLICATA: lega albero + metadati (fix E1 NEMESIS 2026-08-20)
    num_total: int
    den_total: int
    n: int
    metric_id: str
    as_of: str
    tree_root: str = ""   # radice interna del Merkle sum tree (per la verifica dei path)
    spec_version: str = SPEC_VERSION


def _bind_meta(tree_root: str, n: int, metric_id: str, as_of: str,
               num_total: int, den_total: int) -> str:
    # E1: i metadati sono HASHATI nella radice pubblicata (un prover non puo' cambiarli).
    # BUCO A (2026-08-21): num_total/den_total sono legati ESPLICITAMENTE — prima stavano
    # solo dentro tree_root (non ricalcolabile senza l'albero), così verify_attestation
    # non poteva verificarli e un prover pubblicava totali falsi con una radice reale.
    return _h(_enc("CLDMA", SPEC_VERSION, metric_id, as_of, n, tree_root,
                   num_total, den_total))


def commit_ledger(records: List[Dict], master_salt: str, spec: MetricSpec, as_of: str) -> Commitment:
    leaves = build_leaves(records, master_salt, spec)
    root = _levels(leaves)[-1][0]
    n = len(records)
    root_hash = _bind_meta(root["hash"], n, spec.metric_id, as_of, root["num"], root["den"])
    return Commitment(root_hash, root["num"], root["den"], n, spec.metric_id, as_of, tree_root=root["hash"])


def attestation(c: Commitment) -> Dict:
    """Disclosure PUBBLICA: radice + totali + ratio derivato (nessun record).
    den=0 (Gemini): se il denominatore totale e' zero il ratio e' INDEFINITO; per convenzione dichiarata
    lo riportiamo come '0' con `denominator_minor: 0` -> il verificatore DEVE trattarlo come indefinito,
    non come '0% di rischio'. (verify_attestation lo gestisce coerentemente.)"""
    ratio = (Decimal(c.num_total) / Decimal(c.den_total)) if c.den_total else Decimal(0)
    return {
        "spec_version": c.spec_version, "metric_id": c.metric_id, "as_of": c.as_of,
        "n_records": c.n, "root_hash": c.root_hash, "tree_root": c.tree_root,
        "numerator_minor": c.num_total, "denominator_minor": c.den_total,
        "ratio": str(ratio.quantize(Decimal("0.000001"))),
    }


def verify_attestation(att: Dict) -> bool:
    """Chiunque, SENZA il ledger: (1) i totali pubblicati sono LEGATI alla radice ancorata
    (buco A, 2026-08-21) — ricalcola _bind_meta(tree_root, n, id, as_of, num, den) e lo confronta
    con root_hash: un prover non puo' pubblicare totali falsi con una radice reale; (2) il ratio
    dichiarato = num/den. NB: questo prova che i totali sono quelli IMPEGNATI, non la loro
    correttezza rispetto ai record (per quello servono verify_open/verify_full)."""
    den = att["denominator_minor"]
    # binding forte: i totali devono ricostruire la radice pubblicata via tree_root
    tree_root = att.get("tree_root")
    if not tree_root:
        return False   # senza tree_root i totali non sono legati alla radice: rifiuto (fail-closed)
    bind_ok = (_bind_meta(tree_root, att["n_records"], att["metric_id"], att["as_of"],
                          att["numerator_minor"], den) == att["root_hash"])
    if not bind_ok:
        return False
    if den == 0:
        return att["ratio"] in ("0", "0.000000")
    exp = (Decimal(att["numerator_minor"]) / Decimal(den)).quantize(Decimal("0.000001"))
    return str(exp) == str(Decimal(att["ratio"]).quantize(Decimal("0.000001")))


# --------------------------------------------------------------------------- #
#  Sfida (beacon pubblico) + apertura selettiva + verifica
# --------------------------------------------------------------------------- #
def challenge(root_hash: str, nonce: str, k: int, n: int) -> List[int]:
    """k indici DISTINTI, deterministici dalla radice e dal nonce.
    REQUISITO DI PROTOCOLLO (E2, NEMESIS 2026-08-20): il `nonce` DEVE essere fornito dal VERIFICATORE
    (o da un beacon pubblico) DOPO il commit. Se lo sceglie il prover, puo' fare GRINDING del nonce per
    evitare di far sfidare le foglie manipolate (dimostrato: bastano pochi tentativi per 1 foglia su 13).
    Difesa: nonce esterno + k abbastanza grande (detection = 1-(1-f)^k; scegli k per la f che vuoi coprire)."""
    out, ctr = [], 0
    seen = set()
    while len(out) < min(k, n):
        idx = int(_h(f"{root_hash}|{nonce}|{ctr}"), 16) % n
        if idx not in seen:
            seen.add(idx); out.append(idx)
        ctr += 1
    return out


def _inclusion_path(records, master_salt, spec, index) -> List[Dict]:
    leaves = build_leaves(records, master_salt, spec)
    levels = _levels(leaves)
    path, idx = [], index
    for lvl in levels[:-1]:
        if idx % 2 == 0:
            sib = idx + 1
            if sib < len(lvl):
                path.append({"hash": lvl[sib]["hash"], "num": lvl[sib]["num"], "den": lvl[sib]["den"], "side": "right"})
            # else: nodo promosso, nessun sibling
        else:
            sib = idx - 1
            path.append({"hash": lvl[sib]["hash"], "num": lvl[sib]["num"], "den": lvl[sib]["den"], "side": "left"})
        idx //= 2
    return path


def open_leaves(records, master_salt, spec, indices) -> List[Dict]:
    """Il prover apre i record sfidati con salt, contributi e path Merkle."""
    opened = []
    for i in indices:
        rec = records[i]
        opened.append({
            "index": i, "record": rec, "salt": leaf_salt(master_salt, i),
            "num": spec.num_of(rec), "den": spec.den_of(rec),
            "path": _inclusion_path(records, master_salt, spec, i),
        })
    return opened


def verify_open(c: Commitment, spec: MetricSpec, opened: List[Dict]) -> Dict:
    """
    Per ogni record aperto verifica: (a) l'impegno foglia dal record+salt; (b) i contributi num/den
    dichiarati COINCIDONO con la definizione della metrica applicata al record (onesta' della
    classificazione); (c) il path ricostruisce ESATTAMENTE root_hash + i totali della radice.
    """
    results = []
    # E3 (NEMESIS): un insieme di apertura VUOTO non deve dare assurance (passaggio vacuo).
    if not opened:
        return {"all_ok": False, "leaves": [], "error": "nessun record aperto (challenge vuoto) — assurance nulla"}
    ok_all = True
    for o in opened:
        rec, salt = o["record"], o["salt"]
        # (b) classificazione onesta: i contributi devono seguire la spec, non essere scelti dal prover
        spec_num, spec_den = spec.num_of(rec), spec.den_of(rec)
        classif_ok = (spec_num == o["num"] and spec_den == o["den"])
        # BUCO B (2026-08-21): non-negativita' IMPOSTA in verifica, non solo al commit.
        # Un prover malevolo costruisce l'albero a mano con un sibling NEGATIVO che
        # sgonfia il numeratore (attacco Maxwell classico): la somma finale combacia col
        # num_total (anch'esso scelto dal prover) e sums_ok passava. Ogni contributo del
        # path DEVE essere non-negativo, esattamente come build_leaves impone alle foglie.
        neg_ok = (o["num"] >= 0 and o["den"] >= 0
                  and all(s["num"] >= 0 and s["den"] >= 0 for s in o["path"]))
        # (a)+(c) inclusione: ricostruisci la foglia e risali
        leaf = leaf_node(rec, salt, o["num"], o["den"])
        h, num, den = leaf["hash"], o["num"], o["den"]
        for step in o["path"]:
            if step["side"] == "right":
                num2, den2 = num + step["num"], den + step["den"]
                h = _h(_enc("N", h, step["hash"], num2, den2))
                num, den = num2, den2
            else:
                num2, den2 = step["num"] + num, step["den"] + den
                h = _h(_enc("N", step["hash"], h, num2, den2))
                num, den = num2, den2
        # ricostruito h = radice INTERNA dell'albero; la lego ai metadati + TOTALI e confronto
        # con la radice pubblicata (E1 + buco A: i totali sono ora nel bind)
        incl_ok = (_bind_meta(h, c.n, c.metric_id, c.as_of, c.num_total, c.den_total)
                   == c.root_hash)
        # la ricostruzione foglia+path arriva alla RADICE coi totali ESATTI -> lega i totali dichiarati
        # (uguaglianza, non <=): un prover non puo' gonfiare/sgonfiare num_total/den_total senza rompere la radice
        sums_ok = (num == c.num_total and den == c.den_total)
        leaf_ok = classif_ok and incl_ok and sums_ok and neg_ok
        ok_all = ok_all and leaf_ok
        results.append({"index": o["index"], "classif_ok": classif_ok, "inclusion_ok": incl_ok,
                        "sums_ok": sums_ok, "non_negative_ok": neg_ok, "ok": leaf_ok})
    return {"all_ok": ok_all, "leaves": results}


def verify_full(records, master_salt, spec: MetricSpec, c: Commitment, expected_n: Optional[int] = None) -> Dict:
    """Modalita' REGOLATORE: ricostruisci l'intero albero dal ledger completo e confronta con l'impegno.
    E4 (NEMESIS): questo schema — come OGNI schema a commitment — NON prova la COMPLETEZZA: un prover puo'
    impegnare un SOTTOINSIEME (nascondere i prestiti peggiori) e tutto verifica coerente. La completezza va
    ancorata FUORI dallo schema. Passa `expected_n` (conteggio atteso da un registro/fonte indipendente) per
    far fallire il commit di un sottoinsieme di dimensione diversa da quella nota al regolatore."""
    try:
        c2 = commit_ledger(records, master_salt, spec, c.as_of)
    except Exception as e:
        return {"ok": False, "error": str(e)}
    ok = (c2.root_hash == c.root_hash and c2.num_total == c.num_total and c2.den_total == c.den_total and c2.n == c.n)
    completeness_ok = (expected_n is None) or (c.n == expected_n)
    return {"ok": ok and completeness_ok, "integrity_ok": ok, "completeness_ok": completeness_ok,
            "recomputed_root": c2.root_hash, "recomputed_num": c2.num_total,
            "recomputed_den": c2.den_total, "committed_root": c.root_hash, "n": c.n, "expected_n": expected_n}


def detection_probability(fraction_bad: float, k: int) -> float:
    """P(almeno una sfida colpisce un record manipolato) = 1-(1-f)^k. Honest-scope della modalita' pubblica."""
    return 1.0 - (1.0 - fraction_bad) ** k


# --------------------------------------------------------------------------- #
#  ANCORA ESTERNA ONLINE — timestamp pubblico indipendente della radice (OpenTimestamps/Bitcoin)
# --------------------------------------------------------------------------- #
def anchor_commitment(c: Commitment, timeout: int = 20) -> Dict:
    """Ancora ONLINE il root_hash a un testimone pubblico indipendente (OpenTimestamps -> Bitcoin), via i
    calendar server HTTP (stdlib, no account, no costo). Chiude un buco che lo schema interno NON copre:
    prova che l'attestazione ESISTEVA a un certo tempo e non e' stata RETRODATATA/rigenerata a posteriori.
    Riusa `core.ots_anchor.submit`. HONEST-SCOPE: subito = IMPEGNO del calendar (pending Bitcoin); la conferma
    on-chain e' asincrona (~ore) e si fa con l'upgrade della proof. Ancora l'ESISTENZA-NEL-TEMPO della radice,
    NON il contenuto ne' la completezza (E4). Degrada onesto: se offline -> {ok: False, error}."""
    digest = bytes.fromhex(c.root_hash)  # 32 byte
    try:
        import sys as _sys, os as _os
        _root = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
        if _root not in _sys.path:
            _sys.path.insert(0, _root)
        from core import ots_anchor  # riuso dell'infra esistente
    except Exception as e:
        return {"ok": False, "error": f"ots_anchor non disponibile: {e}", "root_hash": c.root_hash}
    try:
        res = ots_anchor.submit(digest, timeout=timeout)
    except Exception as e:
        return {"ok": False, "error": f"submit fallita (offline?): {e}", "root_hash": c.root_hash}
    committed = [k for k, v in res.items() if isinstance(v, dict) and v.get("ok")]
    return {
        "ok": len(committed) > 0, "root_hash": c.root_hash, "digest_hex": c.root_hash,
        "witness": "opentimestamps", "calendars_committed": committed,
        "calendars_total": len(res), "status": "pending-bitcoin" if committed else "failed",
        "proofs": {k: v.get("proof_b64") for k, v in res.items() if isinstance(v, dict) and v.get("ok")},
        "raw": {k: (v.get("ok") if isinstance(v, dict) else v) for k, v in res.items()},
    }
