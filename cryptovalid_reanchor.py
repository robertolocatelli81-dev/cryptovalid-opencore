"""
CryptoValid · re-ancoraggio schedulato + ALERT di decadimento — annichila W4.

W4 (misurato 2026-08-19): su RPC pubblici gratuiti un anchor onesto perde testimoni col tempo (publicnode
aveva PRUNATO un anchor di 73.8 giorni; strict min_witnesses>=2 fallisce già a ~2.5 mesi). L'evidenza non
sparisce dalla chain, ma diventa INACCESSIBILE via RPC pubblici → l'auto-DoS dell'evidenza.

Fix (chiusura ingegneristica, Fable+Gemini): ri-ancorare lo stesso digest PRIMA della finestra di pruning
misurata, e ALLERTARE quando un anchor è già sotto soglia. Questo modulo DECIDE e ALLERTA; NON spende: il
re-ancoraggio è una nuova tx on-chain = HUMAN-GATED (confine sulla spesa irreversibile). La finestra di
default (75 giorni) è ancorata alla MISURA (pruning osservato ~74gg), non a un'ipotesi — ri-misurabile con
cryptovalid_pruning_probe e da aggiornare quando la sonda-cron accumula la curva.

HONEST-SCOPE: pianifica il rinnovo dell'ACCESSIBILITÀ dell'evidenza; non prova né la veridicità (W1) né
sostituisce un archive dedicato (l'alternativa forte resta un nodo full-archive / servizio a pagamento).
Stdlib only. La sonda è iniettabile (`probe_fn=`) per test ermetici.
"""
from typing import Callable, Dict, List, Optional


def assess(retention: Dict, age_days: Optional[float], min_witnesses: int = 2,
           pruning_window_days: float = 75.0, warn_margin_days: float = 15.0) -> Dict:
    """Da una retention (output di pruning_probe.probe_retention) + età, decide status e needs_reanchor.
      - 'decayed'  : testimoni < min_witnesses ORA → l'evidenza è GIÀ sotto soglia (ALERT critico).
      - 'decaying' : ancora abbastanza testimoni ma l'età è entro `warn_margin` dalla finestra di pruning
                     → ri-ancorare PROATTIVAMENTE prima che diventi inaccessibile.
      - 'healthy'  : giovane e con testimoni sufficienti."""
    witnesses = retention.get("witnesses_with_tx", 0)
    if witnesses < min_witnesses:
        return {"status": "decayed", "needs_reanchor": True, "witnesses": witnesses,
                "reason": f"{witnesses} testimoni < {min_witnesses} richiesti: evidenza già sotto soglia"}
    if age_days is not None and age_days >= (pruning_window_days - warn_margin_days):
        return {"status": "decaying", "needs_reanchor": True, "witnesses": witnesses,
                "reason": f"età {age_days:.0f}gg entro {warn_margin_days:.0f}gg dalla finestra di pruning "
                          f"(~{pruning_window_days:.0f}gg): ri-ancorare prima dell'inaccessibilità"}
    return {"status": "healthy", "needs_reanchor": False, "witnesses": witnesses,
            "reason": "testimoni sufficienti e lontano dalla finestra di pruning"}


def plan(anchors: List[Dict], probe_fn: Callable[[str], Dict], now_ts: float,
         min_witnesses: int = 2, pruning_window_days: float = 75.0,
         warn_margin_days: float = 15.0) -> Dict:
    """anchors: [{signature, anchored_ts?}]. probe_fn(signature)->retention. now_ts: epoch (passato da
    fuori: niente clock qui, per determinismo/riproducibilità). Ritorna il piano + il conteggio per stato."""
    items = []
    for a in anchors:
        ret = probe_fn(a["signature"])
        age = None
        if a.get("anchored_ts") is not None:
            age = round((now_ts - a["anchored_ts"]) / 86400.0, 1)
        v = assess(ret, age, min_witnesses, pruning_window_days, warn_margin_days)
        items.append({"signature": a["signature"], "age_days": age, **v})
    summary = {"decayed": 0, "decaying": 0, "healthy": 0}
    for it in items:
        summary[it["status"]] += 1
    return {
        "items": items,
        "summary": summary,
        "to_reanchor": [it["signature"] for it in items if it["needs_reanchor"]],
        "alert": summary["decayed"] > 0,      # almeno un anchor già sotto soglia → ALERT
        "honest_scope": ("pianifica il rinnovo dell'ACCESSIBILITÀ dell'evidenza (il re-ancoraggio è una tx "
                         "on-chain HUMAN-GATED, non automatica); non prova veridicità (W1) né sostituisce "
                         "un archive dedicato. Finestra ancorata alla MISURA, non a un'ipotesi."),
    }
