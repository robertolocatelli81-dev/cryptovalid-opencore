# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Roberto Locatelli
"""
cldma_confidential — PROPOSTA FUTURA additiva: attestazione CLDMA con contributi CONFIDENZIALI.

ADDITIVO PER COSTRUZIONE (ordine Roberto 2026-08-22): NON modifica `committed_attestation` ne'
`pedersen_commit` — li IMPORTA e li COMPONE. Il sistema CLDMA esistente resta identico e funzionante;
questo e' un layer opt-in, una proposta seria per il post-2030 (auditabilita' privacy-preserving CBDC/RWA),
non un cambio del prodotto attuale.

IDEA: invece dei totali in chiaro di CLDMA, ogni contributo per-record (num_i, den_i della metrica) e'
impegnato con Pedersen (hiding). La radice Merkle (hash, PQ-safe) lega TUTTI gli impegni -> tamper-evidence;
la somma OMOMORFICA degli impegni da' i totali impegnati -> il ratio si prova sui totali senza rivelare i
singoli record. Apertura selettiva del solo TOTALE al regolatore.

DIVISIONE ONESTA DEL LAVORO (honest-scope):
- CONFIDENZIALITA' dei valori per-record: Pedersen hiding = INFO-TEORICO (quantum-safe).
- TAMPER-EVIDENCE / integrita' di QUALI impegni sono attestati: hash-Merkle = PQ-safe (come CLDMA).
- BINDING valore<->impegno: DL, NON quantum-safe (un quantistico riapre un impegno). Percio' la garanzia
  forte di integrita' resta hash-based; Pedersen aggiunge PRIVACY. Per l'integrita' PQ a lungo termine si
  compone con longterm_evidence (rinnovo hash-based). NON e' ZK completa.
- ⚠ LIMITE DI SOUNDNESS DIMOSTRATO (2026-08-22): senza prova di RANGE lo schema NON e' sound contro un
  prover MALEVOLO. Attacco (verificato nel banco): impegnare num_i = q-k ("-k" mod q) SGONFIA il numeratore
  netto (es. reale 100000 + fake (q-100000) => somma = 0 mod q), e l'apertura del solo TOTALE non lo coglie
  (il netto sembra valido). Ogni c_num_i e' un impegno valido, la radice regge => verify_confidential PASSA.
  E' esattamente il motivo per cui esistono le prove di RANGE (Bulletproofs). CONSEGUENZA ONESTA: questo modulo
  e' una PROPOSTA/DIMOSTRAZIONE di PRIVACY, sound solo contro prover ONESTO-ma-curioso; per la sound-ness contro
  prover malevolo serve il layer di range proof (Bulletproofs, pesante, NON arrangiato a mano) O l'apertura
  completa al regolatore (che pero' annulla la privacy). NON spacciarlo per attestazione confidenziale sicura.
- prova di RANGE in ZK (num_i<=den_i, e non-negativita', senza rivelarli) = layer Bulletproofs -> NON incluso.
- COMPLETEZZA/TRONCAMENTO (review council 2026-08-22): la radice e' AUTO-REFERENZIALE (verify la ricomputa
  dalle stesse foglie di `att`) -> un prover che tronca/riordina puo' ricomputare la radice e passare. Percio'
  la radice DEVE essere ANCORATA ESTERNAMENTE al momento dell'attestazione (ledger CLDMA / RFC3161 TSA /
  Solana) perche' completezza e non-troncamento contino. Mitigato in parte: indice nella foglia (anti-riordino)
  + n legato alla radice (cattura n incoerente). La completezza piena resta fuori schema (come CLDMA E4).
- MITIGAZIONE del range SENZA Bulletproofs (council) -- IMPLEMENTATA: SPOT-CHECK a campione
  (`challenge_indices`/`open_challenged`/`verify_challenged`): il regolatore sfida k foglie (indici da beacon
  = hash(root||nonce) DOPO l'attestazione), il prover le apre, si controlla 0<=num<=den<=MAX_SANE. Coglie il
  -k (q-k >> den) e l'overflow con detection PROBABILISTICA 1-(1-f)^k. Alza la soundness da ZERO a
  probabilistica restando STDLIB e senza ZK. Rivela solo le foglie campionate (privacy ridotta sul campione).
  NB: verifica il RANGE dei contributi; la CLASSIFICAZIONE onesta (che num/den seguano la definizione della
  metrica sul record) richiederebbe di aprire anche il RECORD sfidato (come la challenge piena di CLDMA) = piu'
  privacy spesa -> layer ulteriore, qui non incluso. Le prove di RANGE in ZK (Bulletproofs) restano l'alternativa
  pesante e a zero-privacy-cost, ma NON stdlib e MAI a mano.
- La guardia `if num<0 raise` in build e' solo HONEST-PATH: un prover malevolo pubblica il dict `att`
  direttamente, non passa da build -> NON e' una difesa (lo dice il council). verify_total_opening ora e'
  SELF-CONTAINED (ricomputa i totali dalle foglie e verifica la radice: non si fida del campo pubblicato).

Stdlib puro (riusa gli helper di committed_attestation + pedersen_commit).
"""
from __future__ import annotations

from typing import Dict, List, Tuple

try:
    import committed_attestation as _C
    import pedersen_commit as _P
except ImportError:  # importato come opencore.*
    from opencore import committed_attestation as _C
    from opencore import pedersen_commit as _P


def _merkle_root(leaf_hashes: List[str]) -> str:
    """Radice Merkle hash-only (PQ-safe) sui leaf_hash. Nodo dispari promosso (come CLDMA)."""
    if not leaf_hashes:
        raise ValueError("nessuna foglia")
    cur = list(leaf_hashes)
    while len(cur) > 1:
        nxt = []
        for j in range(0, len(cur), 2):
            if j + 1 < len(cur):
                nxt.append(_C._h(_C._enc("N", cur[j], cur[j + 1])))
            else:
                nxt.append(cur[j])
        cur = nxt
    return cur[0]


def _leaf_hash(index: int, record_commit: str, c_num: int, c_den: int) -> str:
    # lega INDICE (anti-riordino, council 2026-08-22) + impegno del record ai suoi impegni di valore -> radice
    return _C._h(_C._enc("CL", index, record_commit, str(c_num), str(c_den)))


def _bound_root(inner_root: str, metric_id: str, as_of: str, n: int) -> str:
    # lega metadati + n alla radice pubblicata (come CLDMA _bind_meta). NB: NON prova la COMPLETEZZA da
    # sola (un prover che tronca ricomputa anche n e la radice) -> la radice VA ANCORATA ESTERNAMENTE.
    return _C._h(_C._enc("CLDMA-CONF-1", metric_id, as_of, n, inner_root))


def build_confidential(records: List[Dict], master_salt: str, spec: "_C.MetricSpec",
                       as_of: str) -> Tuple[Dict, Dict]:
    """Costruisce l'attestazione confidenziale. Ritorna (attestation_pubblica, secret_per_il_prover).
    - attestation: radice + per-foglia {record_commit, c_num, c_den} + totali impegnati (nessun valore/record).
    - secret: i randomizer e i valori, che il prover custodisce per aprire il TOTALE al regolatore."""
    leaves_pub, leaf_hashes = [], []
    c_nums, c_dens = [], []
    r_nums, r_dens, nums, dens = [], [], [], []
    for i, rec in enumerate(records):
        num, den = spec.num_of(rec), spec.den_of(rec)
        if num < 0 or den < 0:
            raise ValueError(f"contributo negativo al record {i}")
        salt = _C.leaf_salt(master_salt, i)
        record_commit = _C._h(_C._enc("commit", salt, _C.canonical_record(rec)))
        c_num, r_num = _P.commit(num)
        c_den, r_den = _P.commit(den)
        leaves_pub.append({"record_commit": record_commit, "c_num": c_num, "c_den": c_den})
        leaf_hashes.append(_leaf_hash(i, record_commit, c_num, c_den))
        c_nums.append(c_num); c_dens.append(c_den)
        r_nums.append(r_num); r_dens.append(r_den); nums.append(num); dens.append(den)
    root = _bound_root(_merkle_root(leaf_hashes), spec.metric_id, as_of, len(records))
    C_num_total = _P.add(*c_nums)
    C_den_total = _P.add(*c_dens)
    att = {
        "scheme": "CLDMA-CONFIDENTIAL-1", "metric_id": spec.metric_id, "as_of": as_of,
        "n_records": len(records), "root": root, "leaves": leaves_pub,
        "C_num_total": C_num_total, "C_den_total": C_den_total,
        "num_le_den": getattr(spec, "num_le_den", True),
    }
    secret = {"nums": nums, "dens": dens, "r_nums": r_nums, "r_dens": r_dens}
    return att, secret


def verify_confidential(att: Dict) -> Dict:
    """Chiunque, SENZA i record: (1) la radice Merkle si ricostruisce dalle foglie pubblicate
    (tamper-evidence); (2) la somma OMOMORFICA degli impegni per-foglia == totali impegnati pubblicati.
    Prova che i totali impegnati derivano ESATTAMENTE dagli impegni legati alla radice, senza aprirli."""
    reasons: List[str] = []
    leaves = att.get("leaves", [])
    if not leaves:
        return {"ok": False, "reasons": ["nessuna foglia"]}
    if len(leaves) != att.get("n_records"):
        reasons.append(f"n_records dichiarato ({att.get('n_records')}) != foglie ({len(leaves)})")
    lh = [_leaf_hash(i, l["record_commit"], l["c_num"], l["c_den"]) for i, l in enumerate(leaves)]
    root = _bound_root(_merkle_root(lh), att["metric_id"], att["as_of"], len(leaves))
    if root != att["root"]:
        reasons.append("radice non combacia (foglie/impegni/ordine/metadati manomessi). NB: la radice va "
                       "ANCORATA ESTERNAMENTE per contare la completezza/troncamento")
    if _P.add(*[l["c_num"] for l in leaves]) != att["C_num_total"]:
        reasons.append("somma omomorfica numeratore != C_num_total")
    if _P.add(*[l["c_den"] for l in leaves]) != att["C_den_total"]:
        reasons.append("somma omomorfica denominatore != C_den_total")
    return {"ok": not reasons, "reasons": reasons, "n": len(leaves)}


def open_totals(att: Dict, secret: Dict) -> Dict:
    """Il prover apre SOLO i totali (per il regolatore): num_total, den_total e i randomizer sommati.
    Non rivela i singoli record ne' i singoli contributi."""
    num_total = sum(secret["nums"]) % _P.Q
    den_total = sum(secret["dens"]) % _P.Q
    r_num_total = sum(secret["r_nums"]) % _P.Q
    r_den_total = sum(secret["r_dens"]) % _P.Q
    return {"num_total": num_total, "den_total": den_total,
            "r_num_total": r_num_total, "r_den_total": r_den_total}


def verify_total_opening(att: Dict, opening: Dict) -> Dict:
    """Il regolatore: i totali impegnati aprono ai totali dichiarati, e il ratio e' calcolabile.
    SELF-CONTAINED (fix council 2026-08-22): ricomputa C_num_total/C_den_total DALLE FOGLIE (non si fida del
    campo pubblicato) e prima verifica la coerenza foglie<->radice, cosi' non dipende dall'ordine di chiamata.
    num<=den controllato SUI TOTALI aperti se la metrica e' limitata (guardia che sa fallire)."""
    reasons: List[str] = []
    vc = verify_confidential(att)
    if not vc["ok"]:
        return {"ok": False, "reasons": ["attestazione non coerente: " + "; ".join(vc["reasons"])]}
    C_num = _P.add(*[l["c_num"] for l in att["leaves"]])   # ricomputato dalle foglie legate alla radice
    C_den = _P.add(*[l["c_den"] for l in att["leaves"]])
    if not _P.open_commit(C_num, opening["num_total"], opening["r_num_total"]):
        reasons.append("C_num_total (ricomputato dalle foglie) non apre al num_total dichiarato")
    if not _P.open_commit(C_den, opening["den_total"], opening["r_den_total"]):
        reasons.append("C_den_total (ricomputato dalle foglie) non apre al den_total dichiarato")
    if att.get("num_le_den") and not reasons and opening["num_total"] > opening["den_total"]:
        reasons.append(f"ratio IMPOSSIBILE: num_total {opening['num_total']} > den_total {opening['den_total']}")
    ratio = None
    if not reasons and opening["den_total"]:
        ratio = opening["num_total"] / opening["den_total"]
    return {"ok": not reasons, "reasons": reasons, "ratio": ratio}


# --------------------------------------------------------------------------- #
#  MITIGAZIONE onesta del range SENZA Bulletproofs: SPOT-CHECK a campione (council 2026-08-22)
#  Alza la soundness da ZERO a PROBABILISTICA (detection = 1-(1-f)^k) restando stdlib e senza ZK.
#  Riusa la challenge di CLDMA (indici da beacon pubblico = hash(root||nonce)). NON e' zero-knowledge:
#  rivela i contributi delle SOLE foglie campionate (privacy ridotta sul campione, non azzerata).
# --------------------------------------------------------------------------- #
MAX_SANE = 10 ** 18  # limite di sanita' dichiarato (unita' minori): oltre = fuori range (coglie q-k e overflow)


def challenge_indices(att: Dict, nonce: str, k: int) -> List[int]:
    """k indici da sfidare, deterministici da (radice, nonce). REQUISITO (CLDMA E2): il `nonce` DEVE venire
    dal VERIFICATORE/beacon DOPO l'attestazione, altrimenti il prover lo macina per evitare le foglie barate."""
    return _C.challenge(att["root"], nonce, k, att["n_records"])


def open_challenged(att: Dict, secret: Dict, indices: List[int]) -> List[Dict]:
    """Il prover apre SOLO le foglie sfidate (valore + randomizer), non tutte."""
    return [{"index": i, "num": secret["nums"][i], "r_num": secret["r_nums"][i],
             "den": secret["dens"][i], "r_den": secret["r_dens"][i]} for i in indices]


def verify_challenged(att: Dict, opened: List[Dict]) -> Dict:
    """Per ogni foglia sfidata: (a) l'apertura combacia con l'impegno pubblicato; (b) RANGE:
    0 <= num <= den <= MAX_SANE (non-negativita' + bound + sanita') -> coglie il -k (q-k e' enorme > den) e
    l'overflow. Se una foglia barata e' campionata, FALLISCE. Honest-scope: detection PROBABILISTICA."""
    reasons: List[str] = []
    if not opened:
        return {"ok": False, "reasons": ["nessuna foglia aperta (challenge vuoto) = assurance nulla"]}
    for o in opened:
        i = o["index"]
        leaf = att["leaves"][i]
        if not _P.open_commit(leaf["c_num"], o["num"], o["r_num"]):
            reasons.append(f"foglia {i}: c_num non apre al valore dichiarato")
        if not _P.open_commit(leaf["c_den"], o["den"], o["r_den"]):
            reasons.append(f"foglia {i}: c_den non apre al valore dichiarato")
        if not (0 <= o["num"] <= o["den"] <= MAX_SANE):
            reasons.append(f"foglia {i}: FUORI RANGE (num={o['num']}, den={o['den']}) -> contributo "
                           f"negativo/overflow (attacco -k) o valore assurdo")
    return {"ok": not reasons, "reasons": reasons, "n_checked": len(opened)}


def detection_probability(fraction_bad: float, k: int) -> float:
    """P(almeno una sfida colpisce una foglia barata) = 1-(1-f)^k. Honest-scope dello spot-check."""
    return _C.detection_probability(fraction_bad, k)


if __name__ == "__main__":
    led = [{"principal_outstanding": "1000.00", "days_overdue": "0", "status": "active"},
           {"principal_outstanding": "500.00", "days_overdue": "45", "status": "active"}]
    att, secret = build_confidential(led, "salt", _C.SPEC_PAR30, "2026-08-22")
    print("verify_confidential:", verify_confidential(att)["ok"])
    op = open_totals(att, secret)
    print("verify_total_opening:", verify_total_opening(att, op))
