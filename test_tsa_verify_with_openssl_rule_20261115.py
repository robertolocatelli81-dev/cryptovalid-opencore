# SPDX-License-Identifier: AGPL-3.0-or-later
"""`cryptovalid_tsa.verify_with_openssl` does what its docstring now says (registry item 21, 15/11/2026): it reads a
TimeStampResp, hashes the data it is given, and validates against the system CA store at the time of the call (no
-attime, no pinned TSA). The command line is pinned, and a bare token taken out of a real reply is False."""
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import cryptovalid_tsa as T  # noqa: E402

VEC = os.path.join(HERE, "spec", "vectors", "rfc3161")


class TestVerifyWithOpensslRule(unittest.TestCase):
    def test_docstring_states_the_rule(self):
        doc = T.verify_with_openssl.__doc__
        for phrase in ("TimeStampResp", "time of the call, not at the token's genTime", "-attime", "/etc/ssl/certs",
                       "not a digest", "not a pinned TSA"):
            self.assertIn(phrase, doc)

    def test_command_line(self):
        seen = []

        def fake(cmd, **kw):
            seen.append(cmd)
            return subprocess.CompletedProcess(cmd, 0, "Verification: OK\n", "")
        with mock.patch.object(T, "_run_openssl", fake), mock.patch.object(shutil, "which", lambda n: "/usr/bin/openssl"):
            self.assertIs(T.verify_with_openssl(b"reply", b"data"), True)
        self.assertEqual(len(seen), 1)
        cmd = seen[0]
        self.assertEqual(cmd[:3], ["openssl", "ts", "-verify"])
        self.assertEqual(cmd[cmd.index("-CApath") + 1], "/etc/ssl/certs")
        self.assertIn("-data", cmd)
        for absent in ("-attime", "-token_in", "-digest", "-CAfile", "-untrusted"):
            self.assertNotIn(absent, cmd)

    @unittest.skipUnless(shutil.which("openssl"), "openssl absent")
    def test_bare_token_is_false(self):
        with open(os.path.join(VEC, "data.txt"), "rb") as fh:
            data = fh.read()
        d = tempfile.mkdtemp()
        for name in ("digicert", "sectigo", "globalsign", "freetsa"):
            tok = os.path.join(d, name + ".tok")
            subprocess.run(["openssl", "ts", "-reply", "-in", os.path.join(VEC, name + ".tsr"), "-token_out", "-out", tok],
                           check=True, capture_output=True)
            with open(tok, "rb") as fh:
                self.assertIs(T.verify_with_openssl(fh.read(), data), False, name)


if __name__ == "__main__":
    unittest.main()
