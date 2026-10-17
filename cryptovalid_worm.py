"""
CryptoValid · WORM escrow adapter — annichila W2 (tiene l'HASH, non il DATO).

W2 (adversarial review, 2026-08-19): l'ancora conserva l'hash, non il record → i requisiti WORM del
DATO (SEC 17a-4, MiFID: ritenzione 5-7 anni immutabile) non erano soddisfatti PER COSTRUZIONE. Fix (chiusura
ingegneristica): un adapter OPZIONALE che mette il RECORD (cifrato) su storage write-once, con
l'ancora esistente che ne attesta l'integrità. La cancellazione GDPR («diritto all'oblio») avviene via
CRYPTO-SHREDDING della chiave — si distrugge la chiave, non l'oggetto WORM: il ciphertext resta immutabile
(WORM rispettato) ma diventa indecifrabile (dato effettivamente cancellato). I due obblighi, apparentemente
in conflitto (immutabilità WORM vs cancellabilità GDPR), coesistono.

HONEST-SCOPE:
  - Storage: `LocalWormStore` è un RIFERIMENTO write-once a livello applicativo (rifiuta l'overwrite). WORM
    conforme VERO richiede S3 Object Lock in compliance-mode o hardware WORM — un backend che neanche root
    può alterare. Dichiarato: il locale enforce write-once nell'app, non contro un attaccante root.
  - Chiavi: il keyring di riferimento è in-process/file; in produzione le chiavi vivono in KMS/HSM (il
    crypto-shredding = distruzione della chiave nel KMS). Il bridge KMS di CryptoValid è il posto giusto.
  - Non prova la VERIDICITÀ del contenuto (resta W1, confine). Prova integrità + retention + cancellabilità.
Richiede `cryptography` (AES-256-GCM); degrada onesto se assente.
"""
import sys as _sys_0203
if __name__ == "__main__":   # 0.20.3: run as a command, never write the bytecode cache: CPython 3.9 and 3.11 write
    _sys_0203.dont_write_bytecode = True   # a .pyc with one raw write; cut by a file size limit, every later run died (13/10/2026)
    _L0210 = type(__loader__)   # 0.21.0: a .pyc already cut (CPython 3.9/3.11 installed one) is compiled from the source
    if _L0210.__name__ == "SourceFileLoader":   # instead of failing every later run (EOFError: marshal data too short)
        def _get_code_0210(self, fullname, _get_code=_L0210.get_code):
            try:
                return _get_code(self, fullname)
            except (EOFError, ValueError):
                path = self.get_filename(fullname)
                return self.source_to_code(self.get_data(path), path)
        _L0210.get_code = _get_code_0210
import hashlib
import json
import os
from typing import Dict, Optional

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    _HAVE_CRYPTO = True
except Exception:  # noqa: BLE001
    _HAVE_CRYPTO = False


class WormError(Exception):
    pass


class LocalWormStore:
    """Store write-once di riferimento su filesystem: rifiuta l'overwrite di una chiave già scritta.
    Honest-scope: WORM a livello applicativo (un root può ancora cancellare i file); il WORM conforme vero
    è S3 Object Lock compliance-mode / hardware."""

    def __init__(self, root: str):
        self.root = root
        os.makedirs(root, exist_ok=True)

    def _path(self, key: str) -> str:
        safe = hashlib.sha256(key.encode()).hexdigest()      # nome-file deterministico, no path-injection
        return os.path.join(self.root, safe + ".worm")

    def put(self, key: str, blob: bytes) -> Dict:
        p = self._path(key)
        if os.path.exists(p):
            raise WormError(f"WORM: '{key}' già scritto, overwrite RIFIUTATO (write-once)")
        write_new(p, blob, mode=0o400)   # 0400; 0.20.3: whole or absent (temporary + link, never over an existing object)
        return {"key": key, "bytes": len(blob), "sha256": hashlib.sha256(blob).hexdigest()}

    def get(self, key: str) -> bytes:
        p = self._path(key)
        if not os.path.exists(p):
            raise WormError(f"WORM: '{key}' assente")
        with open(p, "rb") as f:
            return f.read()

    def exists(self, key: str) -> bool:
        return os.path.exists(self._path(key))


class KeyRing:
    """Keyring di riferimento (in-process). In produzione: KMS/HSM. crypto_shred() distrugge la chiave →
    GDPR erasure senza toccare l'oggetto WORM."""

    def __init__(self):
        self._keys: Dict[str, bytes] = {}

    def new_key(self, key_id: str) -> bytes:
        k = AESGCM.generate_key(bit_length=256)
        self._keys[key_id] = k
        return k

    def get(self, key_id: str) -> Optional[bytes]:
        return self._keys.get(key_id)

    def crypto_shred(self, key_id: str) -> bool:
        """Distrugge la chiave: il ciphertext WORM resta ma diventa indecifrabile (cancellazione effettiva)."""
        return self._keys.pop(key_id, None) is not None


def store_record_escrow(record: bytes, worm: LocalWormStore, keyring: KeyRing, record_id: str) -> Dict:
    """Cifra il record (AES-256-GCM), lo mette in WORM write-once, e ritorna la ricevuta con il DIGEST del
    ciphertext (ANCORABILE con l'ancora esistente → integrità attestata) + il key_id."""
    if not _HAVE_CRYPTO:
        raise WormError("cryptography assente: AES-256-GCM non disponibile per l'escrow WORM")
    key_id = "k-" + hashlib.sha256((record_id + ":key").encode()).hexdigest()[:24]
    key = keyring.new_key(key_id)
    nonce = os.urandom(12)
    ct = AESGCM(key).encrypt(nonce, record, record_id.encode())   # record_id come AAD (lega il ciphertext)
    blob = nonce + ct
    receipt = worm.put(record_id, blob)
    digest = hashlib.sha3_256(blob).hexdigest()
    return {
        "record_id": record_id,
        "key_id": key_id,
        "worm_sha256": receipt["sha256"],
        "ciphertext_sha3_256": digest,           # QUESTO va ancorato (integrità del dato retained, non solo l'hash)
        "bytes": receipt["bytes"],
        "honest_scope": ("il DATO cifrato è in WORM write-once; il suo digest è ancorabile per integrità; "
                         "GDPR erasure via crypto_shred (la chiave, non l'oggetto WORM). Non prova veridicità."),
    }


def retrieve_record(record_id: str, key_id: str, worm: LocalWormStore, keyring: KeyRing) -> bytes:
    """Recupera e decifra. Se la chiave è stata crypto-shreddata → fallisce (dato cancellato per GDPR)."""
    if not _HAVE_CRYPTO:
        raise WormError("cryptography assente")
    key = keyring.get(key_id)
    if key is None:
        raise WormError("chiave assente (crypto-shredded?) → record cancellato per GDPR, ciphertext immutato in WORM")
    blob = worm.get(record_id)
    nonce, ct = blob[:12], blob[12:]
    return AESGCM(key).decrypt(nonce, ct, record_id.encode())     # AES-GCM: manomissione → InvalidTag


try:   # 0.20.3: the one writer of every command (verifier.py): an outcome is written whole, or exit 74
    from verifier import Parser, emit, receipt_cli, say, write_all_bytes, write_new
except ImportError:   # python3 -m opencore.<module> from the parent directory
    from opencore.verifier import Parser, emit, receipt_cli, say, write_all_bytes, write_new


@receipt_cli
def main(argv=None):
    import argparse
    import sys
    p = Parser(prog="cryptovalid-worm",
                                description="WORM escrow store — retention immutabile del dato (SEC 17a-4).")
    sub = p.add_subparsers(dest="cmd")
    pp = sub.add_parser("put")
    pp.add_argument("store"); pp.add_argument("key"); pp.add_argument("file")
    pg = sub.add_parser("get")
    pg.add_argument("store"); pg.add_argument("key")
    a = p.parse_args(sys.argv[1:] if argv is None else argv)
    if a.cmd == "put":
        with open(a.file, "rb") as f:
            emit(json.dumps(LocalWormStore(a.store).put(a.key, f.read())))
        return 0
    if a.cmd == "get":
        write_all_bytes(LocalWormStore(a.store).get(a.key))   # 0.20.3: every byte, or exit 74
        return 0
    p.print_help(); return 2


if __name__ == "__main__":
    raise SystemExit(main())
