#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""A verifier whose `cryptography` backend is not installed says that the check did not run (0.27.0, 18/11/2026).

Measured on 2026-11-18 on the wheel 0.26.0 installed without the `[sign]` extra: cryptovalid_cose_receipts answered a
valid Signed Statement `MALFORMED_STATEMENT | ModuleNotFoundError: No module named 'cryptography'` (a missing dependency
reported as a malformed input). The same class, found by a static reading of every module that imports `cryptography`
inside a function under a broad `except` and measured with it made unimportable: cryptovalid_cedulon (`INVALID` /
`malformed`) and cryptovalid_vaara_receipt (`signature_ok: false`). The rules are in each module's docstring
("Backend"). The checks run in a child process where `cryptography` cannot be imported (a meta-path finder raises
ModuleNotFoundError for it), so this file says the same on an interpreter with or without `cryptography`; the inputs that
need it to be made are skipped without it. Positive control: on 0.26.0 every assertion on a valid input here fails."""
import json
import os
import subprocess
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True
ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)
try:
    import cryptography  # noqa: F401
    HAVE_CRYPTO = True
except ImportError:
    HAVE_CRYPTO = False
NEEDS_CRYPTO = unittest.skipUnless(HAVE_CRYPTO, "needs cryptography to make the inputs")
TV = os.path.join(ROOT, "spec", "vectors", "scitt-cose", "test-vectors", "v1")

BLOCK = r"""
import importlib.abc, json, sys
sys.dont_write_bytecode = True
for m in [m for m in sys.modules if m == "cryptography" or m.startswith("cryptography.")]:
    del sys.modules[m]
class Block(importlib.abc.MetaPathFinder):
    def find_spec(self, name, path, target=None):
        if name == "cryptography" or name.startswith("cryptography."):
            raise ModuleNotFoundError("No module named %r" % name)
sys.meta_path.insert(0, Block())
sys.path.insert(0, sys.argv[1])
"""


def without_backend(code: str, arg: str = "") -> dict:
    """run `code` in a child where cryptography cannot be imported; it prints one JSON object"""
    p = subprocess.run([sys.executable, "-I", "-c", BLOCK + code, ROOT, arg], capture_output=True, text=True, timeout=120,
                       env={k: v for k, v in os.environ.items() if k != "PYTHONPATH"})
    if p.returncode != 0:
        raise AssertionError(p.stderr[-800:])
    return json.loads(p.stdout)


COSE = r"""
import os, cryptovalid_cose_receipts as C
d = os.path.join(sys.argv[1], "spec", "vectors", "scitt-cose", "test-vectors", "v1", sys.argv[2])
rd = lambda n: open(os.path.join(d, n), "rb").read()
e = json.loads(rd("expected.json"))
st = C.verify_statement(rd("statement.cose"), rd("issuer-key.pub"), payload=rd("payload.bin"))
rc = C.verify_receipt(rd("receipt.cose"), bytes.fromhex(e["leaf_entry"]), rd("log-key.pub"))
o = C.verify_statement_with_receipt(rd("statement.cose"), rd("receipt.cose"), rd("issuer-key.pub"), rd("log-key.pub"),
                                    bytes.fromhex(e["leaf_entry"]), payload=rd("payload.bin"))
print(json.dumps({"st": [st["ok"], st["stage"]], "rc": [rc["ok"], rc["stage"]], "o": [o["ok"], o["result"], o["stage"]],
                  "why": st["why"]}))
"""


class CoseWithoutBackend(unittest.TestCase):
    def test_valid_vectors_are_not_evaluated(self):
        for name in ("valid-eddsa", "valid-es256", "valid-eddsa-multi-proof"):
            r = without_backend(COSE, name)
            self.assertEqual(r["st"], [False, "BACKEND_MISSING"], (name, r))
            self.assertEqual(r["rc"], [False, "BACKEND_MISSING"], (name, r))
            self.assertEqual(r["o"], [False, "NOT_EVALUATED", "BACKEND_MISSING"], (name, r))
            self.assertIn("cryptovalid-opencore[sign]", r["why"])

    def test_a_refusal_for_another_stage_stays_invalid(self):
        """a receipt refused before any key is read (receipt-v1/fail-unsupported-alg) keeps its stage, and with a valid
        statement whose signature could not be checked the result is INVALID: a missing backend never hides a refusal"""
        code = r"""
import os, cryptovalid_cose_receipts as C
tv = os.path.join(sys.argv[1], "spec", "vectors", "scitt-cose", "test-vectors")
rd = lambda *p: open(os.path.join(tv, *p), "rb").read()
r = "receipt-v1/fail-unsupported-alg"; v = "v1/valid-eddsa"
e = json.loads(rd(r, "expected.json"))
rc = C.verify_receipt(rd(r, "receipt.cose"), bytes.fromhex(e["leaf_entry_hex"]), rd(r, "log-key.pub"))
o = C.verify_statement_with_receipt(rd(v, "statement.cose"), rd(r, "receipt.cose"), rd(v, "issuer-key.pub"),
                                    rd(r, "log-key.pub"), bytes.fromhex(e["leaf_entry_hex"]), payload=rd(v, "payload.bin"))
print(json.dumps({"rc": [rc["ok"], rc["stage"]], "o": [o["ok"], o["result"], o["stage"], o["statement"]["stage"]]}))
"""
        r = without_backend(code)
        self.assertEqual(r["rc"], [False, "UNSUPPORTED_ALG"], r)
        self.assertEqual(r["o"], [False, "INVALID", "UNSUPPORTED_ALG", "BACKEND_MISSING"], r)

    @unittest.skipUnless(HAVE_CRYPTO, "control: needs cryptography")
    def test_control_with_the_backend(self):
        import cryptovalid_cose_receipts as C
        d = os.path.join(TV, "valid-eddsa")
        rd = lambda n: open(os.path.join(d, n), "rb").read()  # noqa: E731
        e = json.loads(rd("expected.json"))
        o = C.verify_statement_with_receipt(rd("statement.cose"), rd("receipt.cose"), rd("issuer-key.pub"),
                                            rd("log-key.pub"), bytes.fromhex(e["leaf_entry"]), payload=rd("payload.bin"))
        self.assertEqual((o["ok"], o["result"]), (True, "VALID"))


@NEEDS_CRYPTO
class CedulonAndVaaraWithoutBackend(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import test_cedulon as TC
        import test_vaara_receipt as TVR
        cls.td = tempfile.mkdtemp()
        L = TC.Ledger()
        cls.cedulon = os.path.join(cls.td, "cedulon.json")
        with open(cls.cedulon, "w") as f:
            json.dump([*L.render(), *(TC._pem(k).decode() if isinstance(TC._pem(k), bytes) else TC._pem(k)
                                      for k in (L.rk, L.xk, L.ck))], f)
        sign, key = TVR.keys()
        cls.vaara = os.path.join(cls.td, "vaara.json")
        k = key["ES256"]
        with open(cls.vaara, "w") as f:
            json.dump({"r": TVR.execution(sign, "ES256"), "key": k.decode() if isinstance(k, bytes) else k}, f)

    @classmethod
    def tearDownClass(cls):
        import shutil
        shutil.rmtree(cls.td)

    def test_cedulon(self):
        import cryptovalid_cedulon as CE
        with open(self.cedulon) as f:
            a = json.load(f)
        self.assertEqual(CE.verify_ledger(*a)["result"], "VALID")                      # control
        r = without_backend("import cryptovalid_cedulon as CE\na = json.load(open(sys.argv[2]))\n"
                            "r = CE.verify_ledger(*a)\nprint(json.dumps([r['result'], r['stage'], r['why']]))", self.cedulon)
        self.assertEqual(r[:2], ["NOT_EVALUATED", "backend_missing"], r)

    def test_vaara(self):
        import cryptovalid_vaara_receipt as VA
        with open(self.vaara) as f:
            a = json.load(f)
        self.assertTrue(VA.verify_receipt(a["r"], a["key"], alg="ES256")["ok"])         # control
        r = without_backend("import cryptovalid_vaara_receipt as VA\na = json.load(open(sys.argv[2]))\n"
                            "o = VA.verify_receipt(a['r'], a['key'], alg='ES256')\n"
                            "print(json.dumps([o['ok'], o['signature_ok'], o['why']]))", self.vaara)
        self.assertEqual(r[:2], [False, None], r)
        self.assertTrue(r[2].startswith("backend_missing:"), r)


if __name__ == "__main__":
    unittest.main()
