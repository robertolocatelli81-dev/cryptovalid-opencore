#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
cryptovalid_qeas — adapter verso un Qualified Electronic Archiving Service (eIDAS art. 45j).

IL VALORE LEGALE (2026-08-21, ricerca reale): l'evidenza a prova di manomissione, da sola, non
ha presunzione legale — un tribunale può sempre chiedere "chi garantisce che non l'hai riscritta
tu?". eIDAS risponde con i TRUST SERVICE QUALIFICATI accreditati:
  - Qualified TIMESTAMP (art. 41/42) — presunzione legale di data + integrità in quell'istante;
    l'onere della prova si sposta sulla controparte. → CryptoValid lo HA GIÀ: `cryptovalid_tsa`
    punta a qualsiasi QTSP (Izenpe/Signicat/GlobalSign/Evidency…) e `cryptovalid_lotl` verifica
    che il token sia eIDAS-QUALIFIED contro le EU Trusted Lists.
  - Qualified ARCHIVING (art. 45j, CIR 2025/2532 + CEN/TS 18170:2025) — presunzione legale di
    INTEGRITÀ e ORIGINE per TUTTO il periodo di conservazione: un documento estratto da un QEAS
    è "legalmente presunto autentico e intatto dal deposito". Questo modulo è l'anello mancante.

COSA FA QUESTO ADAPTER (e cosa NON fa — honest-scope inviolabile):
  Deposita un evidence-pack (o il suo manifest digest) presso un QEAS accreditato e conserva la
  RICEVUTA di deposito, che è ciò che porta la presunzione legale. Il valore legale viene dal
  QEATSP accreditato, NON da questo codice: noi produciamo l'evidenza verificabile e il ponte
  standard. Un solo dev non può ESSERE un QEATSP (serve accreditamento/ente — fuori dai vincoli);
  può integrarne uno. Backend:
    - HttpQeasBackend  → un QEAS reale via REST (deposit/retrieve/verify); URL+auth dell'utente.
    - LocalQeasStub    → banco di prova LOCALE, DICHIARATO non-qualificato: NON dà valore legale,
                         serve solo a testare il contratto (mai spacciato per un QEAS reale).

Stdlib only. Il deposito è HUMAN-GATED per costruzione (richiede le credenziali del QEAS dell'utente).
"""
from __future__ import annotations

import hashlib
import json
import os
import time
import urllib.request
from typing import Dict, Optional

QEAS_FORMAT = "cryptovalid-qeas-receipt/1.0"

HONEST_SCOPE = (
    "The legal presumption of integrity+origin comes from the ACCREDITED qualified archiving "
    "service (eIDAS art. 45j), NOT from this code. This adapter deposits the evidence and keeps "
    "the provider's receipt; it does not itself confer legal value, and a LocalQeasStub receipt "
    "has NO legal value (test only). Verify the provider is on an EU Trusted List with qualified "
    "archiving status before relying on it.")


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def pack_digest(pack_dir: str) -> str:
    """Il digest da depositare: il manifest_digest del pack (già impegna tutto il pack)."""
    with open(os.path.join(pack_dir, "MANIFEST.json"), encoding="utf-8") as f:
        man = json.load(f)
    d = man.get("manifest_digest_sha256")
    if not d:
        raise ValueError("MANIFEST.json senza manifest_digest_sha256")
    return d


class LocalQeasStub:
    """Banco di prova LOCALE del contratto QEAS. NON è un QEAS: nessun valore legale.
    Persiste le ricevute in un file JSON per testare deposit→verify end-to-end."""

    name = "local-stub(NO-LEGAL-VALUE)"

    def __init__(self, store_path: str):
        self._path = store_path
        self._db: Dict[str, Dict] = {}
        if os.path.exists(store_path):
            with open(store_path, encoding="utf-8") as f:
                self._db = json.load(f)

    def deposit(self, digest_hex: str, subject: str, now: float) -> Dict:
        rid = _sha256(f"{digest_hex}|{subject}|{now}".encode())[:32]
        rec = {"receipt_format": QEAS_FORMAT, "receipt_id": rid, "digest_sha256": digest_hex,
               "subject": subject, "deposited_at": now, "provider": self.name,
               "qualified": False, "note": "LOCAL STUB — no legal value, test only"}
        self._db[rid] = rec
        with open(self._path, "w", encoding="utf-8") as f:
            json.dump(self._db, f)
        return rec

    def verify(self, receipt: Dict) -> Dict:
        rid = receipt.get("receipt_id")
        stored = self._db.get(rid)
        ok = bool(stored) and stored.get("digest_sha256") == receipt.get("digest_sha256")
        return {"present": bool(stored), "digest_match": ok, "qualified": False,
                "legal_value": False, "note": "local stub: integrity of the receipt only, NOT eIDAS"}


class HttpQeasBackend:
    """QEAS reale via REST (contratto generico: POST deposit, GET verify). L'URL e l'auth sono
    dell'utente (il suo QEATSP accreditato). Il token di auth arriva da env, mai literal."""

    name = "http-qeas"

    def __init__(self, base_url: str, token_env: str = "QEAS_TOKEN", timeout: int = 30):
        if not base_url.startswith("https://"):
            raise ValueError("QEAS base_url must be https:// (legal evidence in transit)")
        self._url = base_url.rstrip("/")
        self._token = os.environ.get(token_env, "")
        if not self._token:
            raise RuntimeError(f"QEAS auth token env {token_env!r} is empty/unset")
        self._timeout = timeout

    def _req(self, method: str, path: str, body: Optional[Dict] = None) -> Dict:
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(f"{self._url}/{path}", data=data, method=method,
                                     headers={"Authorization": f"Bearer {self._token}",
                                              "Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=self._timeout) as r:  # nosec B310 - https enforced
            return json.loads(r.read().decode())

    def deposit(self, digest_hex: str, subject: str, now: float) -> Dict:
        r = self._req("POST", "deposit", {"digest_sha256": digest_hex, "subject": subject})
        r.setdefault("receipt_format", QEAS_FORMAT)
        r.setdefault("provider", self._url)
        return r

    def verify(self, receipt: Dict) -> Dict:
        return self._req("GET", f"verify/{receipt.get('receipt_id')}")


def archive_pack(pack_dir: str, backend, subject: str = "", now: Optional[float] = None) -> Dict:
    """Deposita il manifest digest del pack nel QEAS e salva la ricevuta accanto al pack
    (QEAS_RECEIPT.json). Ritorna la ricevuta + l'honest-scope. Il deposito è l'atto che porta
    (via il QEAS accreditato) la presunzione legale — questo adapter lo esegue e lo registra."""
    digest = pack_digest(pack_dir)
    ts = now if now is not None else time.time()
    receipt = backend.deposit(digest, subject or os.path.basename(pack_dir.rstrip("/")), ts)
    out = {"receipt": receipt, "pack_digest": digest, "backend": backend.name,
           "honest_scope": HONEST_SCOPE}
    with open(os.path.join(pack_dir, "QEAS_RECEIPT.json"), "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, indent=1)
    return out


def verify_pack_archive(pack_dir: str, backend) -> Dict:
    """Verifica che il digest ATTUALE del pack combaci con quello nella ricevuta QEAS, e che il
    QEAS confermi il deposito. Fail-closed: se il pack è cambiato dopo il deposito, digest_match=False."""
    rp = os.path.join(pack_dir, "QEAS_RECEIPT.json")
    if not os.path.exists(rp):
        return {"present": False, "note": "no QEAS_RECEIPT.json (pack not archived)"}
    with open(rp, encoding="utf-8") as f:
        saved = json.load(f)
    current = pack_digest(pack_dir)
    local_match = current == saved.get("pack_digest")
    remote = backend.verify(saved["receipt"])
    return {"present": True, "local_digest_match": local_match, "remote": remote,
            "legal_value": bool(remote.get("qualified")) and local_match,
            "honest_scope": HONEST_SCOPE}
