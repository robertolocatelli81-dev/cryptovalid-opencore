"""
CryptoValid · ancoraggio ETEROGENEO — fault-independence VERA, non repliche same-chain.

Annichila la criticità W3 (Fable 5 + Gemini Pro, 2026-08-19): N RPC di UNA chain sono repliche di una
sola fonte (~1.x testimoni) e NON proteggono da monocultura client / bug di protocollo / attacco alla
chain. La difesa reale è ancorare lo stesso digest su DOMINI DI GUASTO DISTINTI — sistemi di consenso/
fiducia indipendenti, dove la compromissione di uno NON tocca l'altro:

  · dominio "solana"   → consenso di una chain pubblica (verifica nativa, genesis-pin, N-of-M same-chain)
  · dominio "rfc3161"  → PKI di una TSA qualificata (eIDAS/QTSP, es. Izenpe) — fiducia ORTOGONALE alla chain
  · dominio "opentimestamps"/"bitcoin" → (estensione) un terzo dominio, ancora indipendente

Regola: si contano i DOMINI DISTINTI che attestano il digest; due attestazioni dello STESSO dominio contano
UNA (repliche, non testimoni). `min_domains>=2` rende l'indipendenza-di-guasto un requisito IMPONIBILE.

HONEST-SCOPE: prova che il digest è attestato da ≥N sistemi di fiducia INDIPENDENTI (un 51%/bug Solana non
tocca l'attestazione RFC3161, e viceversa). NON prova la veridicità del contenuto (resta W1, confine). I
verificatori di dominio sono iniettabili (`verifiers=`) per test ermetici. Stdlib only.
"""
import json
from typing import Callable, Dict, List, Optional


def _verify_solana(att: Dict, digest_hex: str) -> bool:
    from cryptovalid_solana import verify_solana_anchor, DEFAULT_RPCS
    r = verify_solana_anchor(att["signature"], digest_hex,
                             rpcs=att.get("rpcs", DEFAULT_RPCS),
                             timeout=att.get("timeout", 20),
                             expected_signer=att.get("expected_signer"),
                             min_witnesses=att.get("min_witnesses", 1))
    return bool(r.get("ok"))


def _verify_rfc3161(att: Dict, digest_hex: str) -> bool:
    from cryptovalid_tsa import token_contains_digest, verify_with_openssl
    token = att["token_der"]                       # bytes (DER del token RFC3161)
    digest = bytes.fromhex(digest_hex)
    if not token_contains_digest(token, digest):   # il token deve impegnare QUESTO digest
        return False
    res = verify_with_openssl(token, att.get("digest_data", digest))
    return bool(res.get("verified") or res.get("ok"))


# registro dei domini noti → verificatore nativo. Iniettabile nei test.
DOMAIN_VERIFIERS: Dict[str, Callable[[Dict, str], bool]] = {
    "solana": _verify_solana,
    "rfc3161": _verify_rfc3161,
}


def verify_heterogeneous_anchor(expected_sha3_hex: str, attestations: List[Dict],
                                min_domains: int = 2,
                                verifiers: Optional[Dict[str, Callable]] = None) -> Dict:
    """Verifica che `expected_sha3_hex` sia ancorato su ≥`min_domains` DOMINI DI GUASTO DISTINTI.
    Fail-closed. `attestations`: lista di dict, ognuno con 'domain' + i campi del dominio. Ritorna
    {ok, domains_verified, domains_required, distinct_domains, per_domain, honest_scope}."""
    vmap = verifiers or DOMAIN_VERIFIERS
    per_domain = []
    verified_domains = set()          # DOMINI distinti che hanno attestato (repliche stesso dominio = 1)
    seen_domains = set()
    for att in attestations:
        dom = att.get("domain", "")
        seen_domains.add(dom)
        vfn = vmap.get(dom)
        if vfn is None:
            per_domain.append({"domain": dom, "ok": False, "note": "dominio sconosciuto"})
            continue
        try:
            ok = bool(vfn(att, expected_sha3_hex))
        except Exception as e:        # noqa: BLE001 — un dominio che erra non deve rompere gli altri
            per_domain.append({"domain": dom, "ok": False, "note": f"errore: {str(e).splitlines()[0][:80]}"})
            continue
        per_domain.append({"domain": dom, "ok": ok, "note": ""})
        if ok:
            verified_domains.add(dom)   # set → due 'solana' validi contano UNA volta
    distinct = len(verified_domains)
    ok = distinct >= min_domains
    return {
        "ok": ok,
        "digest": expected_sha3_hex,
        "domains_required": min_domains,
        "domains_verified": distinct,
        "verified_domains": sorted(verified_domains),
        "distinct_domains_attempted": len(seen_domains),
        "per_domain": per_domain,
        "honest_scope": ("prova l'attestazione su ≥N sistemi di fiducia INDIPENDENTI (un attacco a un "
                         "dominio non tocca l'altro); repliche dello stesso dominio contano UNA. NON prova "
                         "la veridicità del contenuto (confine W1)."),
    }


def main(argv=None):
    import argparse
    import sys
    p = argparse.ArgumentParser(prog="cryptovalid-heterogeneous",
                                description="Verifica un'ancora ETEROGENEA (>=N domini di fiducia indipendenti).")
    p.add_argument("digest_sha3_hex")
    p.add_argument("attestations_json", help="file JSON: lista di attestazioni [{\"domain\": ...}, ...]")
    p.add_argument("--min-domains", type=int, default=2)
    a = p.parse_args(sys.argv[1:] if argv is None else argv)
    with open(a.attestations_json, encoding="utf-8") as f:
        atts = json.load(f)
    r = verify_heterogeneous_anchor(a.digest_sha3_hex, atts, min_domains=a.min_domains)
    print(json.dumps(r, ensure_ascii=False, indent=1))
    return 0 if r.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
