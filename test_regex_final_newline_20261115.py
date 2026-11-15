#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""`$` before a final newline (15/11/2026): in Python `re`, `$` also matches just before a newline that ends the string,
so `re.match(r"^...$", s)` accepts `s + "\\n"`. An audit of every pattern with `$` in the modules of this repository
(test files aside) found two used with `.match`: cryptovalid_solana._HEX64 (the expected digest of an anchor) and
cryptovalid_kms.VaultTransitBackend._SIG_RE (the signature Vault returns). Both now use `fullmatch` without `$`.

Measured before the change: VaultTransitBackend.sign accepted "vault:v1:<base64>\\n" and returned the signature; the
Solana digest is stripped of whitespace before the pattern, so a final newline never reached its check (the pattern is
tested directly). The other patterns with `$` already used `fullmatch` (cryptovalid_kms._AWS_REGION_RE) or are messages
(cryptovalid_aps). The verifiers in other languages: JS (no `m` flag) and Go (RE2 without `(?m)`) match `$` at the end
only; the Java timestamp pattern is applied with `matches()`, which needs the whole input.
"""
import base64
import os
import unittest

import cryptovalid_kms as K
import cryptovalid_solana as S


class Solana(unittest.TestCase):
    def test_hex64_whole_string(self):
        h = "a" * 64
        self.assertTrue(S._HEX64.fullmatch(h))
        for bad in (h + "\n", h + "\r\n", "\n" + h, h[:-1], h + "a", h.upper()):
            self.assertIsNone(S._HEX64.fullmatch(bad), repr(bad))
            self.assertIsNone(S._HEX64.match(bad), repr(bad))   # the pattern itself carries the whole-string rule

    def test_digest_with_final_newline_still_stripped(self):
        S_fetch = S._fetch_one
        try:
            S._fetch_one = lambda rpc, sig, t: {"rpc": rpc, "reachable": False, "error": "offline test"}
            out = S.verify_solana_anchor("sig", "a" * 64 + "\n", rpcs=("x",))
            self.assertTrue(out["checks"][0]["ok"])   # strip() as before: the digest check passes, the RPC is what fails
            out = S.verify_solana_anchor("sig", "a" * 63 + "\nb", rpcs=("x",))
            self.assertFalse(out["checks"][0]["ok"])
        finally:
            S._fetch_one = S_fetch


class Vault(unittest.TestCase):
    def _backend(self, answer):
        os.environ["CV_TEST_VAULT_TOKEN"] = "t"
        b = K.VaultTransitBackend(url="http://127.0.0.1:1", key="cv", token_env="CV_TEST_VAULT_TOKEN")
        b._version = 1
        b._req = lambda method, path, body=None: {"data": {"signature": answer}}
        return b

    def test_signature_answer_whole_string(self):
        sig = bytes(range(64))
        good = "vault:v1:" + base64.b64encode(sig).decode()
        self.assertEqual(self._backend(good).sign(b"m"), sig)
        for bad in (good + "\n", good + "\r\n", good + "\n\n", "\n" + good, good.replace("vault:", "vault:\n")):
            with self.assertRaises(RuntimeError, msg=repr(bad)):
                self._backend(bad).sign(b"m")
            self.assertIsNone(K.VaultTransitBackend._SIG_RE.match(bad), repr(bad))   # the pattern carries the rule too


if __name__ == "__main__":
    unittest.main(verbosity=1)
