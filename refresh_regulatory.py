#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Roberto Locatelli
"""
CryptoValid — self-updating regulatory profiles.

Keeps `spec/regulatory_profiles.json` HONEST over time. It:
  1. re-checks each regulation's source URL is reachable (provenance still lives);
  2. stamps `last_checked_utc`;
  3. FLAGS any entry whose `as_of` is older than the staleness window as `needs_review`.

HONEST SCOPE (the important part): this does NOT auto-interpret legal text — laws change in ways a
scraper cannot safely read. A stale or unreachable entry is FLAGGED for a human to re-verify against
the PRIMARY source, never silently trusted. That is the disciplined meaning of "self-updating": the
mapping keeps itself fresh and provenance-honest and refuses to hide staleness — it does not pretend
to practise law. Exit code 1 if anything needs review (so CI surfaces stale regulatory mappings).

  python3 refresh_regulatory.py                 # check + flag (no network HEAD unless --check-urls)
  python3 refresh_regulatory.py --check-urls     # also verify each source URL is reachable
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from typing import Dict
from urllib.parse import urlparse

_HERE = os.path.dirname(os.path.abspath(__file__))
PROFILES = os.path.join(_HERE, "spec", "regulatory_profiles.json")
STALE_DAYS = 90   # after this, an entry MUST be re-verified against its primary source by a human


def _days_since(iso_date: str, now: datetime) -> int:
    d = datetime.fromisoformat(iso_date + "T00:00:00+00:00")
    return (now - d).days


def _reachable(url: str, timeout: int = 15) -> bool:
    if urlparse(url).scheme not in ("http", "https"):   # no file:// etc.
        return False
    import urllib.request
    try:
        req = urllib.request.Request(url, method="HEAD", headers={"User-Agent": "cryptovalid-reg/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as r:  # nosec B310 - scheme validated http/https
            return 200 <= r.status < 400
    except Exception:  # noqa: BLE001
        return False


def refresh(profiles_path: str = PROFILES, check_urls: bool = False) -> Dict:
    with open(profiles_path, encoding="utf-8") as f:
        prof = json.load(f)
    now = datetime.now(timezone.utc)
    needs_review = []
    for r in prof.get("regulations", []):
        stale = _days_since(r.get("as_of", "1970-01-01"), now) > STALE_DAYS
        r["needs_review"] = bool(stale)
        if check_urls and r.get("source_url"):
            r["source_reachable"] = _reachable(r["source_url"])
            if not r["source_reachable"]:
                r["needs_review"] = True
        if r["needs_review"]:
            needs_review.append(r["id"])
    prof["last_checked_utc"] = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    prof["needs_review"] = sorted(needs_review)
    with open(profiles_path, "w", encoding="utf-8") as f:
        json.dump(prof, f, ensure_ascii=False, indent=1, sort_keys=True)
    return {"last_checked_utc": prof["last_checked_utc"], "total": len(prof.get("regulations", [])),
            "needs_review": prof["needs_review"], "stale_window_days": STALE_DAYS}


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    p = argparse.ArgumentParser(prog="cryptovalid-refresh-regulatory")
    p.add_argument("--check-urls", action="store_true", help="also HEAD each source URL")
    p.add_argument("--profiles", default=PROFILES)
    a = p.parse_args(argv)
    r = refresh(a.profiles, check_urls=a.check_urls)
    print(json.dumps(r, ensure_ascii=False, indent=1))
    return 1 if r["needs_review"] else 0   # CI red if any regulatory mapping is stale/unreachable


if __name__ == "__main__":
    raise SystemExit(main())
