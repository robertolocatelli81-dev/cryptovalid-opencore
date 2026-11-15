# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
"""cryptovalid — the declared Python API of cryptovalid-opencore (see API.md).

This package is the only import name the project promises to keep stable. It re-exports, unchanged, a small set of
functions of the core modules (`verifier`, `evidence_pack`, `signer`, `cryptovalid_checkpoint`, `cryptovalid_merkle`,
`cryptovalid_tsa`): `cryptovalid.verify_ledger is verifier.verify_ledger`. The types are declared in `__init__.pyi`
and `receipts.py`; `py.typed` marks the package for type checkers (PEP 561: a module-only distribution cannot carry
type information, a package can).

Importing it needs the standard library only. The functions that check signatures need `cryptography`
(the `sign` extra) when they are called, as they do in the flat modules.
"""
from verifier import CheckNotRun, canonical_payload, hash_with, verify_ledger
from evidence_pack import verify_pack
from signer import verify_ledger_signatures
from cryptovalid_checkpoint import NoteError, parse_checkpoint, verify_note
from cryptovalid_merkle import TileError, verify_consistency, verify_inclusion, verify_tiles
from cryptovalid_tsa import TokenError, verify_token

from .receipts import LedgerReceipt

try:
    from importlib.metadata import PackageNotFoundError as _PackageNotFoundError, version as _version
    try:
        __version__ = _version("cryptovalid-opencore")
    except _PackageNotFoundError:      # run from a clone that is not installed
        __version__ = "0+unknown"
except ImportError:                    # pragma: no cover  (importlib.metadata: Python >= 3.8)
    __version__ = "0+unknown"


class CryptovalidDeprecationWarning(UserWarning):
    """Raised (as a warning) by a declared name that will be removed. A subclass of UserWarning, not of
    DeprecationWarning, so that it is shown without -W options (the choice of pyca/cryptography). API.md states for
    how long a name warns before it goes."""


__all__ = [
    "CheckNotRun",
    "CryptovalidDeprecationWarning",
    "LedgerReceipt",
    "NoteError",
    "TileError",
    "TokenError",
    "__version__",
    "canonical_payload",
    "hash_with",
    "parse_checkpoint",
    "verify_consistency",
    "verify_inclusion",
    "verify_ledger",
    "verify_ledger_signatures",
    "verify_note",
    "verify_pack",
    "verify_tiles",
    "verify_token",
]
