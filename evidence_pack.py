#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CryptoValid Open Core — auditor-ready evidence pack (build + vendor-free verify).

SPDX-License-Identifier: AGPL-3.0-or-later
Copyright (C) 2026 Roberto Locatelli

The regtech time-sink is assembling evidence for an auditor. This turns one or more
hash-chained (and optionally Ed25519-signed) ledgers into a self-verifying BUNDLE:
  - MANIFEST.json  — subject, SHA-256 of every file, per-ledger hash/signature verdicts,
                     signer public keys, a manifest digest, and an OPTIONAL RFC 3161 stamp;
  - SUMMARY.md     — human-readable receipt + the exact command to re-verify;
  - the ledgers    — copied verbatim.

`verify_pack()` re-checks EVERYTHING with nothing but this repo (verifier.py + signer.py):
file digests == manifest, manifest self-consistent, and every ledger passes hash + signature.
No server, no account, no vendor — "trust replaced by verification". Closed GRC tools do not
give you this: their evidence lives in a vendor database and dies with the subscription.

Honest scope: proves what was recorded, when, in which order, and who signed — plus that it was
not altered afterwards. NOT the truth of the recorded facts. RFC 3161 is optional (needs openssl
+ a TSA); its absence never invalidates the pack (signatures + hash chain already stand).

Usage:
  python3 evidence_pack.py build  out_dir/  ledger1.jsonl [ledger2.jsonl ...] [--subject "..."] [--tsa URL]
  python3 evidence_pack.py verify out_dir/
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import shutil
import sys
from datetime import datetime, timezone
from typing import Dict, List, Optional

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
import signer  # noqa: E402
import verifier  # noqa: E402


def _sha256_file(p: str) -> str:
    with open(p, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def _canon(obj: Dict) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


def _first_entry(path: str) -> Dict:
    try:
        with open(path, encoding="utf-8") as f:
            return json.loads(f.readline() or "{}")
    except Exception:  # noqa: BLE001
        return {}


def _rfc3161_stamp(digest_hex: str, tsa_url: str, timeout: int = 20) -> Dict:
    """Timestamp RFC 3161 OPZIONALE via openssl (graceful se assente). Non invalida mai il pack."""
    from urllib.parse import urlparse
    if urlparse(tsa_url).scheme not in ("http", "https"):
        return {"anchored": False, "note": "TSA URL scheme not allowed (http/https only)"}   # no file:// etc.
    exe = shutil.which("openssl")
    if not exe:
        return {"anchored": False, "note": "openssl absent (RFC 3161 optional)"}
    import subprocess
    import tempfile
    import urllib.request
    d = tempfile.mkdtemp()
    try:
        tsq = os.path.join(d, "q.tsq")
        r = subprocess.run(  # nosec B603 - exe da shutil.which('openssl'), argomenti list FISSI, no shell
            [exe, "ts", "-query", "-digest", digest_hex, "-sha256", "-cert", "-out", tsq],
            capture_output=True, timeout=timeout)
        if r.returncode != 0 or not os.path.exists(tsq):
            return {"anchored": False, "note": "openssl ts-query failed"}
        with open(tsq, "rb") as f:
            req = f.read()
        http = urllib.request.Request(tsa_url, data=req, method="POST",
                                      headers={"Content-Type": "application/timestamp-query"})
        resp = urllib.request.urlopen(http, timeout=timeout).read()  # nosec B310 - schema validato http/https sopra
        return {"anchored": True, "tsa": tsa_url, "tsr_b64": base64.b64encode(resp).decode()}
    except Exception as e:  # noqa: BLE001
        return {"anchored": False, "note": f"{type(e).__name__}: {str(e)[:80]}"}
    finally:
        shutil.rmtree(d, ignore_errors=True)


def _summary_md(m: Dict) -> str:
    lines = "\n".join(
        f"- `{l['file']}` — {l['entries']} entries · hash **{l['hash_verdict']}**"
        + (f" · signatures **{'OK' if l.get('signatures_ok') else 'FAIL'}**" if "signatures_ok" in l else "")
        for l in m.get("ledgers", []))
    ts = m.get("rfc3161_timestamp", {})
    return (
        f"# Evidence pack — {m.get('subject')}\n\n"
        f"- Format: `{m.get('pack_format')}` · created {m.get('created_utc')}\n"
        f"- Signers: {len(m.get('signer_pubkeys', []))}\n"
        f"- RFC 3161: {'anchored (' + str(ts.get('tsa')) + ')' if ts.get('anchored') else 'not anchored'}\n\n"
        f"## Ledgers\n{lines}\n\n"
        "## Verify it yourself (vendor-free)\n```\npython3 evidence_pack.py verify <this-folder>\n```\n"
        "`valid: true` = every file digest matches the manifest, the manifest is self-consistent, and "
        "every ledger passes its hash chain and (if signed) its signatures — checked with nothing but "
        "this repository.\n\n"
        "**Honest scope:** proves what/when/order/who-signed + non-alteration — not the truth of the facts.\n")


def build_pack(ledger_paths: List[str], out_dir: str, subject: str = "compliance evidence",
               tsa_url: Optional[str] = None) -> Dict:
    os.makedirs(out_dir, exist_ok=True)
    ledgers_meta: List[Dict] = []
    file_digests: Dict[str, str] = {}
    signers = set()
    for lp in ledger_paths:
        name = os.path.basename(lp)
        dst = os.path.join(out_dir, name)
        shutil.copyfile(lp, dst)
        file_digests[name] = _sha256_file(dst)
        rec = verifier.verify_ledger(dst)
        entry = {"file": name, "entries": rec.get("entries_count"),
                 "hash_verdict": rec.get("verdict"), "chain_integrity": rec.get("chain_integrity")}
        if _first_entry(dst).get("signature"):
            sv = signer.verify_file(dst)
            entry["signatures_ok"] = sv["ok"]
            entry["signers"] = sv["signers"]
            signers.update(sv["signers"])
        ledgers_meta.append(entry)
    manifest = {
        "pack_format": "cryptovalid-evidence-pack/1.0", "subject": subject,
        "created_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "ledgers": ledgers_meta, "file_digests_sha256": file_digests,
        "signer_pubkeys": sorted(signers),
        "honest_scope": "Proves what/when/order/who-signed + non-alteration. Not the truth of the facts.",
    }
    manifest["manifest_digest_sha256"] = hashlib.sha256(_canon(manifest)).hexdigest()
    manifest["rfc3161_timestamp"] = (_rfc3161_stamp(manifest["manifest_digest_sha256"], tsa_url)
                                     if tsa_url else {"anchored": False, "note": "no TSA provided"})
    with open(os.path.join(out_dir, "MANIFEST.json"), "w", encoding="utf-8") as f:
        json.dump(manifest, f, ensure_ascii=False, indent=1, sort_keys=True)
    with open(os.path.join(out_dir, "SUMMARY.md"), "w", encoding="utf-8") as f:
        f.write(_summary_md(manifest))
    return {"pack_dir": out_dir, "manifest_digest": manifest["manifest_digest_sha256"],
            "ledgers": len(ledgers_meta), "signers": len(signers)}


def verify_pack(pack_dir: str) -> Dict:
    """Verifica INDIPENDENTE dell'intero pack (l'auditor non usa alcun vendor): digest dei file ==
    manifest, manifest auto-consistente, ogni ledger passa hash + firme. Fail-closed."""
    with open(os.path.join(pack_dir, "MANIFEST.json"), encoding="utf-8") as f:
        man = json.load(f)
    file_ok = {}
    for name, dig in man.get("file_digests_sha256", {}).items():
        p = os.path.join(pack_dir, name)
        file_ok[name] = os.path.exists(p) and _sha256_file(p) == dig
    m2 = {k: v for k, v in man.items() if k not in ("manifest_digest_sha256", "rfc3161_timestamp")}
    manifest_ok = hashlib.sha256(_canon(m2)).hexdigest() == man.get("manifest_digest_sha256")
    ledger_results, ledgers_ok = [], True
    for lm in man.get("ledgers", []):
        p = os.path.join(pack_dir, lm["file"])
        hp = os.path.exists(p) and verifier.verify_ledger(p).get("verdict") == "PASS"
        sp = True
        if _first_entry(p).get("signature"):
            sp = signer.verify_file(p)["ok"]
        ledger_results.append({"file": lm["file"], "hash_pass": hp, "sig_pass": sp})
        ledgers_ok = ledgers_ok and hp and sp
    files_ok = all(file_ok.values()) if file_ok else False
    ts = man.get("rfc3161_timestamp", {})
    return {"files_ok": files_ok, "file_ok": file_ok, "manifest_ok": manifest_ok,
            "ledgers_ok": ledgers_ok, "ledgers": ledger_results,
            "rfc3161_anchored": ts.get("anchored", False),
            "valid": bool(files_ok and manifest_ok and ledgers_ok)}


def main(argv: Optional[List[str]] = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    p = argparse.ArgumentParser(prog="cryptovalid-evidence-pack")
    sub = p.add_subparsers(dest="cmd")
    b = sub.add_parser("build")
    b.add_argument("out_dir"); b.add_argument("ledgers", nargs="+")
    b.add_argument("--subject", default="compliance evidence"); b.add_argument("--tsa")
    v = sub.add_parser("verify"); v.add_argument("dir")
    a = p.parse_args(argv)
    if a.cmd == "build":
        print(json.dumps(build_pack(a.ledgers, a.out_dir, subject=a.subject, tsa_url=a.tsa), indent=1))
        return 0
    if a.cmd == "verify":
        r = verify_pack(a.dir)
        print(json.dumps(r, indent=1))
        return 0 if r["valid"] else 1
    p.print_help(); return 2


if __name__ == "__main__":
    raise SystemExit(main())
