"""
CryptoValid · WORM escrow adapter — annichila W2 (tiene l'HASH, non il DATO).

W2 (Fable 5 vs Gemini Pro, 2026-08-19): l'ancora conserva l'hash, non il record → i requisiti WORM del
DATO (SEC 17a-4, MiFID: ritenzione 5-7 anni immutabile) non erano soddisfatti PER COSTRUZIONE. Fix (Fable,
chiusura ingegneristica): un adapter OPZIONALE che mette il RECORD (cifrato) su storage write-once, con
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
        fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o400)  # 0400: read-only dopo la scrittura
        with os.fdopen(fd, "wb") as f:
            f.write(blob)
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


def main(argv=None):
    import argparse
    import sys
    p = argparse.ArgumentParser(prog="cryptovalid-worm",
                                description="WORM escrow store — retention immutabile del dato (SEC 17a-4).")
    sub = p.add_subparsers(dest="cmd")
    pp = sub.add_parser("put")
    pp.add_argument("store"); pp.add_argument("key"); pp.add_argument("file")
    pg = sub.add_parser("get")
    pg.add_argument("store"); pg.add_argument("key")
    a = p.parse_args(sys.argv[1:] if argv is None else argv)
    if a.cmd == "put":
        with open(a.file, "rb") as f:
            print(json.dumps(LocalWormStore(a.store).put(a.key, f.read())))
        return 0
    if a.cmd == "get":
        sys.stdout.buffer.write(LocalWormStore(a.store).get(a.key))
        return 0
    p.print_help(); return 2


if __name__ == "__main__":
    raise SystemExit(main())
