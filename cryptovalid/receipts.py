# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
"""The declared shape of the receipts (API.md, surface 3).

0.25.0 declares the top-level keys of the receipt of `verify_ledger`. The other receipts (pack, note, tiles, token,
signatures) are `Dict[str, Any]` until their shape is declared here too: each is a later, separate step, because it
means reading every branch that builds one.

Rules (API.md): a key may be ADDED in a minor release; a key is never removed and never changes meaning without the
deprecation period. Three keys are always present; the others are absent when the file could not be read at all
(`verdict` FILE_NOT_FOUND, or FAIL with `parse_errors` naming `input_too_large` / `unreadable`).
"""
from typing import Any, Dict, List, Optional, TypedDict


class _LedgerReceiptAlways(TypedDict):
    verdict: str                 # "PASS" | "FAIL" | "FILE_NOT_FOUND"
    path: str
    verified_utc: str            # when the check started, UTC, seconds; not covered by receipt_sha256


class LedgerReceipt(_LedgerReceiptAlways, total=False):
    verifier: str
    algorithm_used: str          # "sha256" | "sha3_256"
    algorithm_supported: List[str]
    entries_count: int
    hash_recomputed_ok: int
    hash_recomputed_total: int
    hash_recompute_passed: bool
    hash_failures: List[Dict[str, Any]]
    link_ok: int
    link_total: int
    link_passed: bool
    link_failures: List[Dict[str, Any]]
    idx_monotonic: bool
    ts_monotonic: bool
    ts_backwards: List[Dict[str, Any]]
    parse_errors: List[Dict[str, Any]]
    schema_failures: List[Dict[str, Any]]
    chain_integrity: bool
    tip: Optional[Dict[str, Any]]     # None: no signed chain tip was checked
    scope: Dict[str, Any]             # what the verdict proves and does not prove
    signatures_not_checked: int       # present only when entries carry a signature layer
    failure_classes: Dict[str, Any]   # 0.27.0, on a FAIL of a file that was read (zero entries too): SPEC §5 "Failure classes"
    receipt_sha256: str
    receipt_sha3_256: str


__all__ = ["LedgerReceipt"]
