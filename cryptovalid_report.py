#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CryptoValid Open Core — auditor-facing report (HTML always, PDF when WeasyPrint exists).

SPDX-License-Identifier: AGPL-3.0-or-later
Copyright (C) 2026 Roberto Locatelli

An ISO inspector or an EU regulator expects a formal document, not JSON on a terminal.
This module renders an evidence pack (built by evidence_pack.py) into a typographic
report: front page, global verification status, per-ledger detail, signer keys,
RFC 3161 / eIDAS anchoring, honest scope, and the exact vendor-free re-verify command.

Design rules (they ARE the security model of this layer):
  - READ-ONLY: the report never recomputes a verdict. Every light comes verbatim from
    `evidence_pack.verify_pack()` — the same independent, fail-closed checker an auditor
    runs by hand. If verify says invalid, the report is RED. No renderer-side "green".
  - The report is a RENDERING, not evidence. The authoritative artifacts remain
    MANIFEST.json + the ledgers; the report says so on its face and prints the
    re-verify command. Its own SHA-256 is returned for provenance, nothing more.
  - Zero new hard dependencies: HTML is pure stdlib. PDF uses WeasyPrint ONLY if it is
    already importable; otherwise the module degrades honestly (html_only note).
  - eIDAS/LOTL is a NETWORK check and therefore opt-in (--lotl). Three honest states:
    not checked (default) / qualified True / qualified False — never a fabricated green.

Usage:
  python3 cryptovalid_report.py <pack_dir> [--out report.pdf] [--html-only]
                                [--lotl] [--lotl-ms ES,IT] [--title "..."]
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import html
import json
import os
import sys
from datetime import datetime, timezone
from typing import Dict, List, Optional

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
import evidence_pack  # noqa: E402

REPORT_FORMAT = "cryptovalid-audit-report/1.0"

# ---------------------------------------------------------------- LOTL (opt-in)

def lotl_status(manifest: Dict, member_states: Optional[List[str]] = None,
                cache_path: Optional[str] = None) -> Dict:
    """Opt-in eIDAS check: is the pack's RFC 3161 token issued by a QUALIFIED TSP
    (EU Trusted Lists via LOTL)? Fail-honest: any problem -> checked with a note,
    never an invented verdict."""
    ts = manifest.get("rfc3161_timestamp", {})
    if not (ts.get("anchored") and ts.get("tsr_b64")):
        return {"checked": False, "qualified": None, "note": "no RFC 3161 token in pack"}
    try:
        import cryptovalid_lotl as lotl
        import cryptovalid_tsa as tsa
        fps, _coverage = lotl.load_qualified_fingerprints(member_states=member_states,
                                                          cache_path=cache_path)
        raw = base64.b64decode(ts["tsr_b64"])
        # il pack conserva la RISPOSTA TimeStampResp; il token CMS è il suo 2° figlio
        try:
            kids = tsa._parse_seq_children(tsa._parse_seq_children(raw)[0][1])
            token = kids[1][2] if len(kids) > 1 else raw
        except Exception:  # noqa: BLE001 - già un token nudo, o forma inattesa
            token = raw
        got = lotl.token_cert_fingerprints(token)
        if not got:
            return {"checked": True, "qualified": None,
                    "note": "no certificate extractable from token (inconclusive)"}
        q = lotl.is_qualified(token, fps)
        return {"checked": True, "qualified": bool(q), "tsa": ts.get("tsa"),
                "trusted_fingerprints": len(fps)}
    except Exception as e:  # noqa: BLE001
        return {"checked": True, "qualified": None,
                "note": f"LOTL check failed: {type(e).__name__}: {str(e)[:80]}"}


# ---------------------------------------------------------------- rendering

def _e(x) -> str:
    return html.escape(str(x if x is not None else "—"), quote=True)


def _short(h: Optional[str], n: int = 16) -> str:
    return f"{h[:n]}…" if isinstance(h, str) and len(h) > n else (h or "—")


_LIGHT = {True: ("PASS", "ok"), False: ("FAIL", "bad"), None: ("N/A", "na")}


def _badge(v, yes: str = "PASS", no: str = "FAIL", na: str = "N/A") -> str:
    # identità stretta: un futuro 1/0 non deve MAI dipingersi PASS/FAIL (review F2)
    txt, cls = _LIGHT[v if (v is True or v is False) else None]
    label = {("PASS", "ok"): yes, ("FAIL", "bad"): no, ("N/A", "na"): na}[(txt, cls)]
    return f'<span class="badge {cls}">{_e(label)}</span>'


_CSS = """
@page { size: A4; margin: 22mm 18mm 24mm 18mm;
  @bottom-center { content: "Page " counter(page) " of " counter(pages);
                   font: 8pt sans-serif; color: #6b7280; }
  @bottom-left { content: string(rid); font: 7pt monospace; color: #9ca3af; } }
* { box-sizing: border-box; }
body { font: 10.5pt/1.55 "DejaVu Sans", "Helvetica Neue", Arial, sans-serif;
       color: #111827; margin: 0; }
h1 { font-size: 21pt; margin: 0 0 2mm; letter-spacing: -.02em; }
h2 { font-size: 12.5pt; margin: 9mm 0 2.5mm; border-bottom: 1.5pt solid #111827;
     padding-bottom: 1.2mm; }
.mono { font-family: "DejaVu Sans Mono", Consolas, monospace; font-size: 8.4pt; }
.front { border-bottom: 3pt double #111827; padding-bottom: 5mm; margin-bottom: 6mm;
         string-set: rid attr(data-rid); }
.front .sub { color: #374151; font-size: 11pt; }
.kv { width: 100%; border-collapse: collapse; margin-top: 4mm; }
.kv td { padding: 1.2mm 2mm; vertical-align: top; border-bottom: .4pt solid #e5e7eb; }
.kv td:first-child { width: 34%; color: #6b7280; font-size: 9pt;
                     text-transform: uppercase; letter-spacing: .04em; }
.status { border: 1.6pt solid; border-radius: 2mm; padding: 4mm 5mm; margin: 4mm 0; }
.status.ok  { border-color: #1a7f37; background: #f0fdf4; }
.status.bad { border-color: #b91c1c; background: #fef2f2; }
.status .verdict { font-size: 15pt; font-weight: 700; }
.status.ok  .verdict { color: #1a7f37; }
.status.bad .verdict { color: #b91c1c; }
.badge { display: inline-block; padding: .4mm 2.2mm; border-radius: 1mm;
         font-size: 8.2pt; font-weight: 700; letter-spacing: .03em; white-space: nowrap; }
.badge.ok  { background: #dcfce7; color: #14532d; }
.badge.bad { background: #fee2e2; color: #7f1d1d; }
.badge.na  { background: #f3f4f6; color: #4b5563; }
table.grid { width: 100%; border-collapse: collapse; margin-top: 2mm; }
table.grid th { text-align: left; font-size: 8.6pt; text-transform: uppercase;
  letter-spacing: .05em; color: #374151; border-bottom: 1.2pt solid #111827;
  padding: 1.6mm 2mm; }
table.grid td { padding: 1.6mm 2mm; border-bottom: .4pt solid #e5e7eb;
                vertical-align: top; }
.note { background: #f9fafb; border-left: 2.5pt solid #9ca3af; padding: 2.5mm 4mm;
        color: #374151; font-size: 9.3pt; }
.cmd { background: #111827; color: #e5e7eb; padding: 3mm 4mm; border-radius: 1.5mm;
       font-family: "DejaVu Sans Mono", monospace; font-size: 8.6pt;
       white-space: pre-wrap; }
.small { font-size: 8.6pt; color: #6b7280; }
"""


def render_html(manifest: Dict, verification: Dict, lotl: Dict,
                title: str = "Compliance Evidence — Audit Report",
                pack_dir: str = "") -> str:
    """Pure-stdlib rendering of verify_pack()'s verdict. Every status shown comes
    from `verification`/`lotl` — this function must stay verdict-free."""
    valid = bool(verification.get("valid"))
    rid = manifest.get("manifest_digest_sha256", "")
    rows = []
    for lr in verification.get("ledgers", []):
        meta = next((m for m in manifest.get("ledgers", [])
                     if m.get("file") == lr.get("file")), {})
        rows.append(
            "<tr><td class='mono'>{f}</td><td>{n}</td><td class='mono'>{h}</td>"
            "<td>{hp}</td><td>{sp}</td><td>{tr}</td></tr>".format(
                f=_e(lr.get("file")), n=_e(meta.get("entries")),
                h=_e(_short(meta.get("head_self_hash"))),
                hp=_badge(lr.get("hash_pass")),
                sp=_badge(lr.get("sig_pass")),
                tr=_badge(lr.get("untruncated"), yes="INTACT", no="TRUNCATED")))
    signers = manifest.get("signer_pubkeys", [])
    signer_rows = "".join(f"<tr><td>{i+1}</td><td class='mono'>{_e(k)}</td></tr>"
                          for i, k in enumerate(signers)) or \
                  "<tr><td colspan='2' class='small'>none — unsigned ledgers</td></tr>"

    rfc = verification.get("rfc3161", {})
    ts = manifest.get("rfc3161_timestamp", {})
    if not rfc.get("claimed"):
        rfc_badge, rfc_note = _badge(None, na="NOT ANCHORED"), \
            "No RFC 3161 timestamp in this pack (optional; chain + signatures stand on their own)."
    elif rfc.get("verified") is True:
        rfc_badge, rfc_note = _badge(True, yes="VERIFIED"), \
            f"Token cryptographically verified (Granted + digest imprint match). TSA: {ts.get('tsa')}"
    elif rfc.get("verified") is None:
        rfc_badge, rfc_note = _badge(None, na="RECORDED, NOT VERIFIED"), \
            "Token recorded but not verifiable here (openssl absent)."
    else:
        rfc_badge, rfc_note = _badge(False, no="VERIFICATION FAILED"), \
            "Recorded token FAILED cryptographic verification."

    if not lotl.get("checked"):
        eidas_badge = _badge(None, na="NOT CHECKED")
        eidas_note = ("eIDAS qualification not checked (network check, opt-in via --lotl). "
                      "Absence of a check is not a verdict.")
    elif lotl.get("qualified") is True:
        eidas_badge = _badge(True, yes="QUALIFIED TSP")
        eidas_note = (f"TSA certificate matches the EU Trusted Lists (LOTL) — "
                      f"{lotl.get('trusted_fingerprints')} qualified fingerprints loaded.")
    elif lotl.get("qualified") is False:
        eidas_badge = _badge(False, no="NOT QUALIFIED")
        eidas_note = ("TSA certificate NOT found in the EU Trusted Lists: timestamp is "
                      "standard RFC 3161, not an eIDAS qualified timestamp.")
    else:
        eidas_badge = _badge(None, na="INCONCLUSIVE")
        eidas_note = lotl.get("note", "inconclusive")

    comp = [
        ("File digests match the manifest", verification.get("files_ok")),
        ("Manifest self-consistent (digest)", verification.get("manifest_ok")),
        ("Manifest authenticated (Ed25519)", verification.get("manifest_authenticated")
         if (manifest.get("manifest_signature") or verification.get("manifest_authenticated"))
         else None),
        ("All ledgers: hash chain + signatures + no truncation",
         verification.get("ledgers_ok")),
    ]
    comp_rows = "".join(f"<tr><td>{_e(k)}</td><td>{_badge(v, na='NOT PRESENT')}</td></tr>"
                        for k, v in comp)

    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<title>{_e(title)}</title><style>{_CSS}</style></head><body>

<div class="front" data-rid="report {_e(_short(rid, 24))}">
  <h1>{_e(title)}</h1>
  <div class="sub">{_e(manifest.get("subject"))}</div>
  <table class="kv">
    <tr><td>Report ID (manifest digest, SHA-256)</td><td class="mono">{_e(rid)}</td></tr>
    <tr><td>Evidence pack created (UTC)</td><td>{_e(manifest.get("created_utc"))}</td></tr>
    <tr><td>Report generated (UTC)</td><td>{_e(datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))}</td></tr>
    <tr><td>Pack format / report format</td>
        <td class="mono">{_e(manifest.get("pack_format"))} · {_e(REPORT_FORMAT)}</td></tr>
    <tr><td>Pack location at generation time</td><td class="mono">{_e(pack_dir)}</td></tr>
  </table>
</div>

<div class="status {'ok' if valid else 'bad'}">
  <div class="verdict">{'VALID — evidence verified' if valid else 'INVALID — verification FAILED'}</div>
  <div class="small">Verdict produced by the independent fail-closed checker
  (<span class="mono">evidence_pack.verify_pack</span>); this document only renders it.</div>
</div>

<h2>1 · Verification components</h2>
<table class="grid"><tr><th>Check</th><th>Result</th></tr>{comp_rows}</table>

<h2>2 · Ledger detail</h2>
<table class="grid">
<tr><th>File</th><th>Entries</th><th>Head hash</th><th>Hash chain</th>
<th>Signatures</th><th>Truncation</th></tr>
{''.join(rows) or "<tr><td colspan='6' class='small'>no ledgers listed</td></tr>"}
</table>

<h2>3 · Signer public keys (Ed25519)</h2>
<table class="grid"><tr><th>#</th><th>Public key (hex)</th></tr>{signer_rows}</table>

<h2>4 · Time anchoring</h2>
<table class="grid">
<tr><th>Anchor</th><th>Status</th><th>Detail</th></tr>
<tr><td>RFC 3161 timestamp</td><td>{rfc_badge}</td><td>{_e(rfc_note)}</td></tr>
<tr><td>eIDAS qualification (LOTL)</td><td>{eidas_badge}</td><td>{_e(eidas_note)}</td></tr>
</table>

<h2>5 · Honest scope</h2>
<div class="note">{_e(manifest.get("honest_scope", ""))}</div>

<h2>6 · Verify it yourself (vendor-free)</h2>
<p class="small">This report is a <b>rendering</b>, not the evidence. The authoritative
artifacts are <span class="mono">MANIFEST.json</span> and the ledger files. Any party can
re-verify with nothing but the open-source repository:</p>
<div class="cmd">python3 evidence_pack.py verify {_e(pack_dir or "&lt;pack-dir&gt;")}</div>
<p class="small">CryptoValid Open Core · AGPL-3.0 · trust replaced by verification.</p>

</body></html>"""


# ---------------------------------------------------------------- generation

def generate_report(pack_dir: str, out: Optional[str] = None, html_only: bool = False,
                    lotl: bool = False, lotl_ms: Optional[List[str]] = None,
                    title: str = "Compliance Evidence — Audit Report") -> Dict:
    """Verify the pack independently, render HTML (always), then PDF if WeasyPrint
    is importable and not html_only. Returns paths + the UNMODIFIED verdict."""
    try:
        with open(os.path.join(pack_dir, "MANIFEST.json"), encoding="utf-8") as f:
            manifest = json.load(f)
    except (OSError, ValueError) as e:
        # fail-closed E pulito: un auditor merita un errore leggibile, mai un traceback
        return {"valid": False, "html": None, "pdf": None,
                "error": f"MANIFEST.json unreadable: {type(e).__name__}: {str(e)[:120]}"}
    verification = evidence_pack.verify_pack(pack_dir)           # the ONLY verdict source
    lres = lotl_status(manifest, member_states=lotl_ms) if lotl else \
        {"checked": False, "qualified": None}

    doc = render_html(manifest, verification, lres, title=title,
                      pack_dir=os.path.abspath(pack_dir))
    base = out or os.path.join(pack_dir, "report.pdf")
    html_path = os.path.splitext(base)[0] + ".html"
    with open(html_path, "w", encoding="utf-8") as f:
        f.write(doc)
    result = {"valid": verification["valid"], "html": html_path, "pdf": None,
              "report_sha256": hashlib.sha256(doc.encode()).hexdigest(),
              "eidas": lres}
    if not html_only:
        try:
            from weasyprint import HTML  # optional, never a hard dependency
            HTML(string=doc, base_url=pack_dir).write_pdf(base)
            result["pdf"] = base
        except ImportError:
            result["note"] = ("WeasyPrint not installed — HTML report generated; "
                              "print it to PDF with any browser (pip install weasyprint)")
        except Exception as e:  # noqa: BLE001
            result["note"] = f"PDF rendering failed: {type(e).__name__}: {str(e)[:80]}"
    return result


def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(prog="cryptovalid-report",
                                description="Render an evidence pack as an auditor-facing report")
    p.add_argument("pack_dir")
    p.add_argument("--out", help="output PDF path (default: <pack>/report.pdf)")
    p.add_argument("--html-only", action="store_true")
    p.add_argument("--lotl", action="store_true",
                   help="opt-in NETWORK check: is the TSA eIDAS-qualified (EU LOTL)?")
    p.add_argument("--lotl-ms", help="comma-separated member states (e.g. ES,IT)")
    p.add_argument("--title", default="Compliance Evidence — Audit Report")
    a = p.parse_args(sys.argv[1:] if argv is None else argv)
    r = generate_report(a.pack_dir, out=a.out, html_only=a.html_only, lotl=a.lotl,
                        lotl_ms=[s.strip() for s in a.lotl_ms.split(",")] if a.lotl_ms else None,
                        title=a.title)
    print(json.dumps(r, indent=1))
    return 0 if r["valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
