#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Test MIRATI per uccidere i mutanti sopravvissuti del mutation runner su cryptovalid_solana:
frontiera di rete (_rpc/_fetch_one, urlopen mockato), estrazione memo (inner/filtro programId), e i
check di verify (64-hex su valido, nessun RPC reachable, display signer, contraddizione su err). Offline.

Mutation score portato da 0.679 (18 sopravvissuti) a 0.946 (53/56). I 3 RESIDUI sono MUTANTI EQUIVALENTI
(non uccidibili senza teatro, dichiarati onestamente — NON gap di copertura):
  · L175 `is None`→`is not None`: la flag err è usata SOLO relazionalmente (confronto tra viste per la
    contraddizione); invertirla su ENTRAMBI i lati preserva le uguaglianze → comportamento invariato.
  · L183 `>=`→`<`: seleziona il TESTO di una nota (display); il valore del check è calcolato a parte.
  · L244 `False`→`True`: `ensure_ascii=` nel print della CLI main() — solo formattazione stdout, nessun
    effetto osservabile senza testare i byte esatti di stdout (fuori scopo del verificatore).
Effettivo: 53/53 dei mutanti NON-equivalenti uccisi.
"""
import io
import json
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import cryptovalid_solana as CS  # noqa: E402

GEN = CS.MAINNET_GENESIS
SIG = "0" * 88
HASH = "ab" * 32
SIGNER = "0" * 44
MEMO_PID = "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr"


def _memo_ix(digest, program="spl-memo", program_id=MEMO_PID):
    return {"program": program, "programId": program_id, "parsed": f"x sha3:{digest} y"}


def _tx(digest=HASH, err=None, signer=SIGNER, inner=False):
    ixs = [] if inner else [_memo_ix(digest)]
    meta = {"err": err, "innerInstructions": ([{"instructions": [_memo_ix(digest)]}] if inner else [])}
    return {"slot": 1, "blockTime": 1, "meta": meta,
            "transaction": {"message": {"accountKeys": [{"pubkey": signer}], "instructions": ixs}}}


def _urlopen_returning(payload: dict):
    class _R(io.BytesIO):
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    return mock.patch.object(CS.urllib.request, "urlopen",
                             return_value=_R(json.dumps(payload).encode()))


class TestRpcBoundary(unittest.TestCase):
    def test_rpc_rifiuta_scheme_non_http(self):          # kills L59 (not in→in)
        with self.assertRaises(ValueError):
            CS._rpc("ftp://evil/x", "m", [], 2)

    def test_rpc_accetta_https_e_ritorna_result(self):   # kills L59 dall'altro lato
        with _urlopen_returning({"result": 42}):
            self.assertEqual(CS._rpc("https://ok.example", "m", [], 2), 42)

    def test_rpc_error_solleva(self):                    # kills L67 (in→not in)
        with _urlopen_returning({"error": "boom"}):
            with self.assertRaises(ValueError):
                CS._rpc("https://ok.example", "m", [], 2)


class TestFetchOne(unittest.TestCase):
    def test_reachable_true_su_successo(self):           # kills L102 (True→False)
        with mock.patch.object(CS, "_rpc", side_effect=[GEN, _tx()]):
            r = CS._fetch_one("https://ok", SIG, 2)
        self.assertTrue(r["reachable"])
        self.assertEqual(r["genesis"], GEN)

    def test_reachable_false_su_eccezione(self):         # kills L104 (False→True)
        with mock.patch.object(CS, "_rpc", side_effect=RuntimeError("down")):
            r = CS._fetch_one("https://ko", SIG, 2)
        self.assertFalse(r["reachable"])
        self.assertIn("error", r)


class TestExtractMemo(unittest.TestCase):
    def test_estrae_da_inner_instructions(self):         # kills L79 (or→and su innerInstructions)
        digs = CS._extract_memo_digests(_tx(inner=True))
        self.assertIn(HASH.lower(), digs)

    def test_ignora_istruzione_non_memo(self):           # kills L82 (not in→in / !=→==)
        # istruzione con sha3 nel parsed MA non-memo (programId estraneo, program != spl-memo) → SCARTATA
        tx = {"meta": {"err": None, "innerInstructions": []},
              "transaction": {"message": {"accountKeys": [{"pubkey": SIGNER}],
                              "instructions": [_memo_ix(HASH, program="other", program_id="OtherProg111")]}}}
        self.assertEqual(CS._extract_memo_digests(tx), set())

    def test_memo_per_programId_con_program_field_diverso(self):  # kills L82 (and→or)
        # caso MISTO: programId È del memo (not_in=False) ma il campo program è diverso (!=spl-memo=True).
        # con 'and' → False and True = False → NON scartata → estratta. con 'or' → scartata (mutante ucciso).
        tx = {"meta": {"err": None, "innerInstructions": []},
              "transaction": {"message": {"accountKeys": [{"pubkey": SIGNER}],
                              "instructions": [_memo_ix(HASH, program="x", program_id=MEMO_PID)]}}}
        self.assertIn(HASH.lower(), CS._extract_memo_digests(tx))


class TestVerifyChecks(unittest.TestCase):
    def setUp(self):
        self._orig = CS._fetch_one

    def tearDown(self):
        CS._fetch_one = self._orig

    def _patch(self, fetch_map):
        def _f(rpc, signature, timeout):
            return fetch_map.get(rpc, {"rpc": rpc, "reachable": False, "error": "unreachable"})
        CS._fetch_one = _f

    def test_check_64hex_true_su_digest_valido(self):    # kills L153 (True→False)
        self._patch({"r1": {"rpc": "r1", "reachable": True, "genesis": GEN, "tx": _tx()}})
        out = CS.verify_solana_anchor(SIG, HASH, rpcs=("r1",))
        hexc = next(c for c in out["checks"] if "64-hex" in c["check"])
        self.assertTrue(hexc["ok"])                      # su digest valido il check DEVE essere True

    def test_nessun_rpc_reachable_ok_false(self):        # kills L159 (False→True nel ramo no-reachable)
        self._patch({})                                  # tutti unreachable
        out = CS.verify_solana_anchor(SIG, HASH, rpcs=("x", "y"))
        self.assertFalse(out["ok"])

    def test_signer_check_presente_quando_atteso(self):  # kills L209 (is not None→is None display)
        self._patch({"r1": {"rpc": "r1", "reachable": True, "genesis": GEN, "tx": _tx()}})
        out = CS.verify_solana_anchor(SIG, HASH, rpcs=("r1",), expected_signer="WrongSigner")
        signer_checks = [c for c in out["checks"] if "expected signer" in c["check"]]
        self.assertTrue(signer_checks)                   # il check signer DEVE comparire quando atteso
        self.assertIs(signer_checks[0]["ok"], False)     # ok è ESATTAMENTE False (non None) su signer errato

    def test_archive_has_tx_check_valori(self):          # kills L167 (False→True) e L170 (True→False)
        # con tx presente → il check "≥1 archive RPC has the tx" è True
        self._patch({"r1": {"rpc": "r1", "reachable": True, "genesis": GEN, "tx": _tx()}})
        out = CS.verify_solana_anchor(SIG, HASH, rpcs=("r1",))
        arch = next(c for c in out["checks"] if "archive RPC has the tx" in c["check"])
        self.assertTrue(arch["ok"])
        # reachable MA nessun tx → il check è False
        self._patch({"r1": {"rpc": "r1", "reachable": True, "genesis": GEN, "tx": None}})
        out2 = CS.verify_solana_anchor(SIG, HASH, rpcs=("r1",))
        arch2 = next(c for c in out2["checks"] if "archive RPC has the tx" in c["check"])
        self.assertFalse(arch2["ok"])

    def test_contraddizione_su_err(self):                # kills L175 (is None→is not None nel view su err)
        self._patch({
            "ok": {"rpc": "ok", "reachable": True, "genesis": GEN, "tx": _tx(err=None)},
            "bad": {"rpc": "bad", "reachable": True, "genesis": GEN,
                    "tx": _tx(err={"InstructionError": [0, "X"]})},
        })
        out = CS.verify_solana_anchor(SIG, HASH, rpcs=("ok", "bad"))
        self.assertFalse(out["ok"])                      # RPC in disaccordo su err → contraddizione → reject
        contra = next(c for c in out["checks"] if "contradict" in c["check"])
        self.assertFalse(contra["ok"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
