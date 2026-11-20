# SPDX-License-Identifier: AGPL-3.0-or-later
# Declared types of the `cryptovalid` package (PEP 561 stub next to the runtime file). A type checker reads this file
# and never follows the imports of __init__.py into the flat modules, which carry no marker.
# proposte_governo/strumenti/check_stub.py compares every signature here with the runtime object.
from typing import Any, Dict, List, Optional, Sequence, Union

from .receipts import LedgerReceipt as LedgerReceipt

__version__: str

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

class CryptovalidDeprecationWarning(UserWarning): ...

class CheckNotRun(OSError):
    receipt: Optional[Dict[str, Any]]
    def __init__(self, *args: Any, receipt: Optional[Dict[str, Any]] = None) -> None: ...

class NoteError(ValueError): ...
class TileError(ValueError): ...
class TokenError(ValueError):
    reason: str
    detail: str
    def __init__(self, reason: str, detail: str) -> None: ...

def verify_ledger(
    path: str,
    algo: Optional[str] = None,
    tip: Optional[str] = None,
    trusted_pubkey_hex: Optional[str] = None,
    require_tip: bool = False,
    tip_not_before: Optional[str] = None,
    expect_ledger_id: Optional[str] = None,
    trusted_pq_pubkey_b64: Optional[str] = None,
) -> LedgerReceipt: ...
def canonical_payload(entry: Dict[str, Any]) -> bytes: ...
def hash_with(algo: str, payload: bytes) -> str: ...
def verify_pack(
    pack_dir: str,
    pq_pubkey_b64: Optional[str] = None,
    signer_pubkey_hex: Optional[str] = None,
    manifest_signer_hex: Optional[str] = None,
    tsa_certs: Optional[Sequence[Union[str, bytes]]] = None,
    tsa_crls: Optional[Sequence[Union[str, bytes]]] = None,
    require_signature_domain: bool = False,
) -> Dict[str, Any]: ...
def verify_ledger_signatures(
    entries: List[Dict[str, Any]],
    expected_pubkey_hex: Optional[str] = None,
    expected_pq_pubkey_b64: Optional[str] = None,
    require_pq: bool = False,
) -> Dict[str, Any]: ...
def parse_checkpoint(text: str) -> Dict[str, Any]: ...
def verify_note(note: bytes, vkeys: List[str]) -> Dict[str, Any]: ...
def verify_inclusion(m: int, n: int, leaf_data: bytes, proof: Sequence[bytes], root: bytes) -> bool: ...
def verify_consistency(m: int, n: int, proof: Sequence[bytes], old_root: bytes, new_root: bytes) -> bool: ...
def verify_tiles(
    directory: str,
    size: int,
    root: Optional[bytes] = None,
    profile: str = "tlog-tiles",
    entries: bool = True,
    encoding: str = "auto",
    max_size: int = ...,
) -> Dict[str, Any]: ...
def verify_token(
    token_der: bytes,
    digest: bytes,
    hash_alg: Optional[str] = None,
    tsa_certs: Optional[Sequence[Union[str, bytes]]] = None,
    crls: Optional[Sequence[Union[str, bytes]]] = None,
) -> Dict[str, Any]: ...
