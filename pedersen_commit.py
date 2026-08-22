# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Roberto Locatelli
"""
pedersen_commit — impegni di Pedersen (Pedersen 1991) per l'auditabilita' CONFIDENZIALE di CLDMA.

BISOGNO (post-2030 salvato): auditabilita' privacy-preserving per CBDC/RWA — provare una metrica derivata
(ratio, riserva) senza rivelare i singoli record. CLDMA oggi pubblica i TOTALI in chiaro e apre i record
sfidati; questo modulo aggiunge un layer CONFIDENZIALE reale.

PERCHE' Pedersen e non "zkp_enterprise" (verificato 2026-08-22): `core/zkp_enterprise.py` NON e' una ZK vera —
`verify_proof` ricomputa hash dai campi del proof e confronta, non usa mai il segreto, zero soundness (e' un
wrapper di lifecycle/integrita' travestito). Pedersen e' invece un primitivo STANDARD, additivamente
omomorfico, con hiding e binding dimostrabili. NON e' crypto nuova: e' del 1991.

HONEST-SCOPE (dichiarato, non ZK completa):
- HIDING = INFO-TEORICO (r uniforme): la privacy dei valori sopravvive anche a un avversario quantistico.
- BINDING = COMPUTAZIONALE (logaritmo discreto): un computer QUANTISTICO rompe il binding (puo' riaprire un
  impegno su un valore diverso). Quindi per l'INTEGRITA' a lungo termine NON ci si affida a Pedersen: resta
  alla hash-chain/Merkle di CLDMA (binding hash-based). L'impegno aggiunge PRIVACY, non integrita' PQ.
- OMOMORFICO: C(v1,r1)*C(v2,r2) = C(v1+v2, r1+r2) -> si prova che il TOTALE impegnato = somma dei contributi
  per-record, senza rivelarli. Apertura selettiva del solo TOTALE al regolatore.
- NON incluso: la PROVA DI RANGE in zero-knowledge (num<=den senza rivelarli) = layer Bulletproofs, pesante,
  NON implementato (e non lo si arrangia a mano). Qui: hiding + omomorfismo + apertura verificabile.
- Gruppo: RFC 3526 MODP-2048 (group 14), sottogruppo dei residui quadratici (ordine primo q=(p-1)/2). g e h
  sono QR con log discreto reciproco IGNOTO (h derivato "nothing-up-my-sleeve" da un seed pubblico).

Stdlib puro (big-int). Deterministico dove serve; r da os.urandom (segreto).
"""
from __future__ import annotations

import hashlib
import os
from typing import List, Optional, Tuple

# RFC 3526 MODP group 14 (2048-bit safe prime). p = 2q+1, q primo.
P = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74"
    "020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437"
    "4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05"
    "98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB"
    "9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718"
    "3995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF", 16
)
Q = (P - 1) // 2  # ordine del sottogruppo dei residui quadratici (primo)
G = 4             # = 2^2: residuo quadratico che genera il sottogruppo di ordine q


def _hash_to_subgroup(seed: bytes) -> int:
    """Deriva un elemento del sottogruppo QR da un seed pubblico (nothing-up-my-sleeve):
    x = H(seed) mod p, poi x^2 mod p -> QR. Il log discreto di h base g e' IGNOTO (nessuno lo sceglie)."""
    x = int.from_bytes(hashlib.sha3_512(seed).digest(), "big") % P
    h = pow(x, 2, P)
    return h if h not in (0, 1) else pow(3, 2, P)


# h: generatore indipendente, log_g(h) ignoto. Seed pubblico fisso -> riproducibile e verificabile.
H = _hash_to_subgroup(b"OMEGA-CLDMA-Pedersen-h/RFC3526-group14/v1")


def _rand_scalar() -> int:
    return 1 + int.from_bytes(os.urandom(32), "big") % (Q - 1)


def commit(value: int, r: Optional[int] = None) -> Tuple[int, int]:
    """C = g^value * h^r mod p. Ritorna (C, r). value in [0,q). r casuale se non fornito (hiding)."""
    if not (0 <= value < Q):
        raise ValueError("value fuori range [0,q)")
    if r is None:
        r = _rand_scalar()
    C = (pow(G, value % Q, P) * pow(H, r % Q, P)) % P
    return C, r


def open_commit(C: int, value: int, r: int) -> bool:
    """Verifica che C impegna (value, r). Binding: senza conoscere log_g(h) non si apre su un value diverso."""
    return C == (pow(G, value % Q, P) * pow(H, r % Q, P)) % P


def add(*commitments: int) -> int:
    """Somma omomorfica: prod(C_i) mod p impegna (sum v_i mod q, sum r_i mod q)."""
    acc = 1
    for C in commitments:
        acc = (acc * C) % P
    return acc


# --------------------------------------------------------------------------- #
#  Attestazione CONFIDENZIALE di una somma (contributi per-record nascosti)
# --------------------------------------------------------------------------- #
def commit_contributions(values: List[int]) -> Tuple[List[int], List[int]]:
    """Impegna ogni contributo (es. num_i o den_i di CLDMA). Ritorna (commitments, randomizers).
    I commitments sono pubblicabili/legabili alla radice Merkle SENZA rivelare i valori."""
    Cs, rs = [], []
    for v in values:
        C, r = commit(v)
        Cs.append(C)
        rs.append(r)
    return Cs, rs


def sum_opening(values: List[int], randomizers: List[int]) -> Tuple[int, int]:
    """Apertura del solo TOTALE (sum value, sum r): il regolatore verifica che la somma degli impegni
    apre al totale dichiarato, SENZA vedere i singoli contributi."""
    return sum(values) % Q, sum(randomizers) % Q


def verify_confidential_sum(commitments: List[int], total_value: int, total_r: int) -> bool:
    """Chiunque: la somma omomorfica degli impegni per-record apre al TOTALE dichiarato.
    Prova il totale impegnato senza aprire i record. (Il range num<=den in ZK e' il layer non incluso.)"""
    return open_commit(add(*commitments), total_value, total_r)


def h_provenance() -> dict:
    """Provenienza dei parametri (verificabile da terzi): come e' derivato h (no trapdoor nascosta)."""
    return {"group": "RFC3526-MODP-2048-group14", "g": G,
            "h_seed": "OMEGA-CLDMA-Pedersen-h/RFC3526-group14/v1",
            "h": hex(H), "note": "h = (H(seed))^2 mod p; log_g(h) ignoto per costruzione (NUMS)"}


if __name__ == "__main__":
    C, r = commit(1500)
    print("open:", open_commit(C, 1500, r), " open-wrong:", open_commit(C, 1501, r))
    vs = [100, 250, 175]
    Cs, rs = commit_contributions(vs)
    tv, tr = sum_opening(vs, rs)
    print("confidential sum:", verify_confidential_sum(Cs, tv, tr))
