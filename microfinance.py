#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""OMEGA-MICROFINANCE — evidenza verificabile per la trasparenza del MICROCREDITO (adattamento SDG 1/8/10).

Applica le primitive di FUNDCERT (canonicalizzazione deterministica, attestazione di coerenza, evidence-record,
hash-chain) a un oggetto diverso: il **portafoglio-prestiti** di un istituto di microfinanza (MFI). Permette a un
DONATORE o REGOLATORE di verificare che il portafoglio dichiarato è quello reale — SENZA fidarsi dell'MFI e SENZA
vedere dati personali.

CONFINE (onesto, uguale a CryptoValid): è **proof-of-integrity**, NON proof-of-veracity. Attesta la COERENZA dei
numeri forniti e li rende tamper-evident; NON verifica che i prestiti esistano davvero né che siano ben concessi.
PRIVACY (DPG indicator 7/9a) — HONEST-SCOPE, corretto 2026-08-22 (council + GDPR Recital 26):
- Su un SINGOLO portafoglio l'MFI usa un salt **per-istituto** che NON condivide → il `borrower_ref` non è
  linkabile fra istituti (pseudonimo locale).
- Il **cross-MFI** (`borrower_debt_exposure`/`over_indebtedness`, microdebito) funziona SOLO se gli istituti
  **condividono lo schema di hash** (salt condiviso): allora il `borrower_ref` diventa uno pseudonimo
  **stabile e linkabile fra istituti** che, sotto GDPR **Recital 26**, **È dato personale pseudonimizzato**
  (la pseudonimizzazione NON è anonimizzazione). In quel caso il titolare del trattamento è l'operatore.
Nessun nome/PII in chiaro entra mai nel digest o nei record; ma il "no-PII by design" vale per il singolo
portafoglio, NON per il matching cross-MFI. Vedi DO_NO_HARM.md e spec/SPEC_MICROFINANCE.md (fix: PSI/ZK).

Riuso reale del motore FUNDCERT: `_canon_quantity`, `evidence_record`, `canonicalizer_fingerprint`, `reconcile`.
"""
import hashlib
import json
from dataclasses import dataclass, field
from decimal import Decimal
from typing import Dict, List, Optional

import fundcert_canonical as F

CANON_VERSION = "microfinance-canon-1.0"


@dataclass
class LoanRecord:
    loan_id: str                    # id del prestito (non del beneficiario)
    borrower_ref: str               # HASH del beneficiario (mai il nome/PII) — vedi hash_borrower()
    principal_disbursed: str        # capitale erogato
    principal_outstanding: str      # capitale ancora in essere
    principal_repaid: str = "0"     # capitale rimborsato
    principal_written_off: str = "0"  # capitale svalutato (perdita)
    currency: str = ""              # valuta locale
    days_overdue: str = "0"         # giorni di ritardo (per il PAR)
    status: str = ""                # 'active'|'closed'|'default'… (cosmetico)


@dataclass
class LoanPortfolio:
    mfi_id: str                     # id dell'istituto
    as_of: str                      # data di riferimento
    source: str                     # provenienza (core-banking MFI, export donatore…)
    loans: List[LoanRecord] = field(default_factory=list)
    currency: str = ""


def hash_borrower(borrower_id: str, salt: str) -> str:
    """PRIVACY: trasforma l'identità del beneficiario in un riferimento non reversibile (sha256(salt|id)).
    L'MFI tiene il salt; il donatore vede solo l'hash → può riconciliare/contare senza mai vedere PII."""
    return hashlib.sha256(f"{salt}|{borrower_id}".encode()).hexdigest()[:32]


def _canon_loan(loan: LoanRecord) -> Dict:
    """Contenuto economico del prestito, ridotto e normalizzato (le stringhe grezze → Decimal canonico)."""
    return {
        "loan_id": loan.loan_id.strip(),
        "borrower_ref": loan.borrower_ref.strip(),
        "disbursed": F._canon_quantity(loan.principal_disbursed),
        "outstanding": F._canon_quantity(loan.principal_outstanding),
        "repaid": F._canon_quantity(loan.principal_repaid or "0"),
        "written_off": F._canon_quantity(loan.principal_written_off or "0"),
    }


def canonical_form(p: LoanPortfolio) -> Dict:
    loans = [_canon_loan(x) for x in p.loans]
    loans.sort(key=lambda x: (x["loan_id"], x["borrower_ref"], x["disbursed"]))  # ordine irrilevante
    return {"canon_version": CANON_VERSION, "loans": loans, "n": len(loans)}


def portfolio_digest(p: LoanPortfolio) -> str:
    """SHA3-256 del portafoglio canonico. STESSO portafoglio → STESSO digest (ri-derivabile dal donatore)."""
    return hashlib.sha3_256(
        json.dumps(canonical_form(p), sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def portfolio_at_risk(p: LoanPortfolio, days: int = 30) -> Dict:
    """PAR (Portfolio at Risk) — la metrica-chiave che donatori/regolatori guardano: quota di capitale in essere
    su prestiti in ritardo > `days` giorni. È un'ATTESTAZIONE del numero DATI i dati forniti, non una verifica
    indipendente del rimborso."""
    outstanding = Decimal(0)
    at_risk = Decimal(0)
    for loan in p.loans:
        o = Decimal(F._canon_quantity(loan.principal_outstanding))
        outstanding += o
        # un valore days_overdue sporco ("n/a", "30+") NON deve abbattere l'intero
        # portafoglio: fail-closed sul singolo record (conta come a-rischio, segnala)
        try:
            overdue = int(float(loan.days_overdue or "0"))
        except (ValueError, TypeError):
            overdue = days + 1        # non-parsabile → prudenza: a rischio
        if overdue > days:
            at_risk += o
    par = (at_risk / outstanding) if outstanding > 0 else Decimal(0)
    return {"days": days, "outstanding": str(outstanding), "at_risk": str(at_risk),
            "par_pct": round(float(par) * 100, 4)}


def attest_portfolio(p: LoanPortfolio, tol_abs: str = "1", tol_rel: str = "0") -> Dict:
    """ATTESTA la coerenza interna del portafoglio (non lo verifica veritiero):
      identità per portafoglio  Σdisbursed == Σoutstanding + Σrepaid + Σwritten_off  (i conti tornano);
      copertura                 outstanding ≥ 0, nessun capitale > disbursed.
    Ritorna gli esiti + PAR30/PAR90 + il digest del portafoglio. Da hash-chainare per il donatore."""
    dis = out = rep = wo = Decimal(0)
    bad = []
    for loan in p.loans:
        d = Decimal(F._canon_quantity(loan.principal_disbursed))
        o = Decimal(F._canon_quantity(loan.principal_outstanding))
        r = Decimal(F._canon_quantity(loan.principal_repaid or "0"))
        w = Decimal(F._canon_quantity(loan.principal_written_off or "0"))
        dis += d; out += o; rep += r; wo += w
        if abs(d - (o + r + w)) > Decimal("1") or o < 0 or o > d + Decimal("1"):
            bad.append(loan.loan_id)          # prestito i cui conti non tornano
    tol = max(Decimal(tol_abs), abs(dis) * Decimal(tol_rel))
    gap = dis - (out + rep + wo)
    return {
        "mfi_id": p.mfi_id, "as_of": p.as_of, "n_loans": len(p.loans),
        "identity_ok": bool(abs(gap) <= tol),        # Σerogato == Σin-essere + Σrimborsato + Σsvalutato
        "identity_gap": str(gap),
        "loans_inconsistent": bad,                   # dichiarati, mai nascosti
        "total_disbursed": str(dis), "total_outstanding": str(out),
        "par30": portfolio_at_risk(p, 30), "par90": portfolio_at_risk(p, 90),
        "digest": portfolio_digest(p),
        "attests": "coerenza interna del portafoglio + no-PII; NON che i prestiti esistano o siano ben concessi",
    }


def _to_holdings(p: LoanPortfolio) -> "F.Holdings":
    """Adatta il portafoglio al reconcile di FUNDCERT: ogni prestito = una 'posizione' con id=loan_id,
    quantità=outstanding → il donatore riconcilia la sua vista vs quella dell'MFI riusando il motore esistente."""
    return F.Holdings(fund_id=p.mfi_id, as_of=p.as_of, source=p.source,
                      positions=[F.Position(identifier=x.loan_id, id_scheme="LOANID",
                                            quantity=F._canon_quantity(x.principal_outstanding),
                                            name=x.borrower_ref) for x in p.loans])


def reconcile_portfolios(mfi: LoanPortfolio, donor_view: LoanPortfolio, material_tol: float = 0.02) -> Dict:
    """Riconcilia la vista dell'MFI con quella del donatore/regolatore per loan_id (riusa `F.reconcile`).
    Materiale = differenze reali (capitale mis-stated); minore = quantizzazione/timing. Nessuna scala globale tra
    MFI e donatore (stesso portafoglio, stessa valuta) → `fixed_scale=1.0`: gli importi devono coincidere."""
    return F.reconcile(_to_holdings(mfi), _to_holdings(donor_view), by="id",
                       material_tol=material_tol, fixed_scale=1.0)


def borrower_debt_exposure(portfolios: List[LoanPortfolio]) -> Dict:
    """MICRO-DEBITO (protezione del beneficiario, SDG 1/10): aggrega il debito in-essere per beneficiario
    ATTRAVERSO più portafogli/istituti, riconoscendo chi ha prestiti in PIÙ MFI — segnale di sovra-indebitamento.
    Usa il `borrower_ref` HASHATO → nessun PII: due MFI che condividono lo stesso schema di hash possono vedere
    l'esposizione totale senza mai vedere il nome. Confine: attesta il debito nei dati FORNITI, non prova che
    siano tutti i prestiti del beneficiario (una fonte mancante resta invisibile — dichiarato)."""
    agg: Dict = {}
    for p in portfolios:
        for loan in p.loans:
            ref = loan.borrower_ref.strip()
            e = agg.setdefault(ref, {"outstanding": Decimal(0), "n_loans": 0, "institutions": set()})
            e["outstanding"] += Decimal(F._canon_quantity(loan.principal_outstanding))
            e["n_loans"] += 1
            e["institutions"].add(p.mfi_id)
    out = {ref: {"outstanding": str(v["outstanding"]), "n_loans": v["n_loans"],
                 "n_institutions": len(v["institutions"]), "institutions": sorted(v["institutions"])}
           for ref, v in agg.items()}
    return {"n_borrowers": len(out), "by_borrower": out}


def over_indebtedness(portfolios: List[LoanPortfolio], max_institutions: int = 1,
                      max_total_outstanding: Optional[str] = None) -> Dict:
    """Segnala i beneficiari a rischio sovra-indebitamento: prestiti in > `max_institutions` istituti (cross-MFI),
    e/o debito totale in-essere oltre `max_total_outstanding`. Lista dichiarata, ordinata per esposizione — è un
    ALLERTA per la protezione del beneficiario, non una decisione automatica (four-eyes a valle)."""
    exp = borrower_debt_exposure(portfolios)["by_borrower"]
    cap = Decimal(max_total_outstanding) if max_total_outstanding is not None else None
    flags = []
    for ref, v in exp.items():
        cross = v["n_institutions"] > max_institutions
        over = cap is not None and Decimal(v["outstanding"]) > cap
        if cross or over:
            flags.append({"borrower_ref": ref, "outstanding": v["outstanding"],
                          "n_institutions": v["n_institutions"], "institutions": v["institutions"],
                          "reasons": ([f">{max_institutions} istituti"] if cross else []) +
                                     (["oltre soglia debito"] if over else [])})
    flags.sort(key=lambda f: -Decimal(f["outstanding"]))
    return {"n_flagged": len(flags), "max_institutions": max_institutions, "flags": flags}


def portfolio_evidence(p: LoanPortfolio, raw_input, source: str, fetched_at: str) -> Dict:
    """Record di evidenza donor-verificabile: lega l'INPUT (byte grezzi) → METODO → digest del portafoglio
    (riusa `F.evidence_record`). Da ancorare nella hash-chain OMEGA per il tamper-evidence (chi/quando sigilla)."""
    rec = F.evidence_record(raw_input, source=source, fetched_at=fetched_at,
                            holdings_digest=portfolio_digest(p), fund_id=p.mfi_id, as_of=p.as_of)
    rec["kind"] = "microfinance_evidence"
    rec["canon_version"] = CANON_VERSION
    return rec
