#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""SPEC v0.12 §20 rules 1 and 12, completed after a second review on 2026-11-20 (each case fails on c7b84dd, measured):

- rule 1: urllib decodes %XX in the host of a URL before it connects (`urllib.request.Request.host` is unquoted), while
  the rule judged the host as `urlsplit` gives it, still encoded: a redirect from a remote host to
  `http://%31%32%37.0.0.1/` reached 127.0.0.1. A host with a percent sign is now refused (the "%25" zone of an IPv6
  literal too: RFC 9844 obsoleted RFC 6874, which had put it in the URI syntax);
- rule 12: a line with a lone surrogate in its `id` or `method` ("\\ud800" in the JSON text) made the reply
  unwritable as UTF-8 (exit 74), a line that is not UTF-8 ended the read loop (exit 1), and an id `NaN` was echoed as
  `NaN`, which is not JSON. Each is now one answer, and the server reads the next line.

Nothing here uses the network: servers listen on 127.0.0.1.
"""
import http.server
import json
import os
import random
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest
import urllib.parse
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
SEED = 20261120


def _serve(answer):
    class H(http.server.BaseHTTPRequestHandler):
        def _any(self):
            self.rfile.read(int(self.headers.get("Content-Length") or 0))   # a close with it unread can reset the connection
            code, headers = answer(self.path)
            self.server.seen.append(self.path)
            self.send_response(code)
            for k, v in headers:
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(b"ok")
        do_GET = do_POST = _any

        def log_message(self, *a):
            pass
    s = http.server.HTTPServer(("127.0.0.1", 0), H)
    s.seen = []
    threading.Thread(target=s.serve_forever, daemon=True).start()
    return s


def _stop(s):
    s.shutdown()
    s.server_close()


def _pct(host: str, rng) -> str:
    """`host` with at least one of its characters written as %XX (upper or lower case hex)."""
    chars = list(host)
    at = [i for i, c in enumerate(chars) if c not in "[]"]
    pick = set(rng.sample(at, rng.randint(1, len(at))))
    return "".join(("%%%02x" if rng.random() < 0.5 else "%%%02X") % ord(c) if i in pick else c for i, c in enumerate(chars))


class TestPercentEncodedHost(unittest.TestCase):
    def setUp(self):
        import cryptovalid_net
        self.N = cryptovalid_net

    def test_urllib_decodes_the_host(self):
        # the control of the premise: urllib connects to the decoded host
        self.assertEqual(urllib.request.Request("http://%31%32%37.0.0.1/x").host, "127.0.0.1")

    def test_refused_under_every_policy(self):
        N, rng = self.N, random.Random(SEED)
        hosts = ["127.0.0.1", "localhost", "0.0.0.0", "169.254.169.254", "example.org", "8.8.8.8", "2130706433", "127.1"]
        n = 0
        for _ in range(100):
            for h in hosts:
                enc = _pct(h, rng)
                for scheme in ("http", "https"):
                    for policy in (N.ALLOW_HTTPS, N.ALLOW_HTTPS_OR_LOOPBACK_HTTP, N.ALLOW_HTTP_OR_HTTPS):
                        with self.subTest(url=f"{scheme}://{enc}/"):
                            with self.assertRaises(ValueError) as cm:
                                N.check_url(f"{scheme}://{enc}:8200/x", policy)
                            self.assertTrue(str(cm.exception).startswith("url_not_allowed: "))
                        n += 1
        self.assertEqual(n, 100 * len(hosts) * 2 * 3)

    def test_no_ipv6_zone_either(self):
        # RFC 9844 (August 2025) obsoletes RFC 6874: a zone identifier is no longer part of the URI syntax of RFC 3986
        N = self.N
        for bad in ("http://[fe80::1%25eth0]:8080/x", "http://[fe80::1%eth0]/", "http://[%3a%3a1]/", "http://x%25lo/",
                    "https://[::1%25lo]/"):
            with self.subTest(url=bad):
                with self.assertRaises(ValueError):
                    N.check_url(bad, N.ALLOW_HTTP_OR_HTTPS)
        N.check_url("http://[fe80::1]:8080/x", N.ALLOW_HTTP_OR_HTTPS)     # the control: the literal without a zone

    def test_end_to_end_on_this_host(self):
        N = self.N
        secret = _serve(lambda path: (200, []))
        self.addCleanup(_stop, secret)
        port = secret.server_address[1]
        for host in ("%31%32%37.0.0.1", "127%2e0%2e0%2e1", "%6c%6f%63%61%6c%68%6f%73%74", "%30%2e%30%2e%30%2e%30"):
            redirector = _serve(lambda path, host=host: (302, [("Location", f"http://{host}:{port}/v1/secret")]))
            self.addCleanup(_stop, redirector)
            req = urllib.request.Request("http://127.0.0.1:%d/tsr" % redirector.server_address[1], data=b"x", method="POST")
            with self.subTest(host=host):
                with self.assertRaises(ValueError) as cm:     # loopback=False: the redirector stands for a remote host
                    N._open(req, 5, False, N.ALLOW_HTTP_OR_HTTPS)
                self.assertIn("a percent sign in the host", str(cm.exception))
        self.assertEqual(secret.seen, [])


class TestMcpUnwritableAndUndecodable(unittest.TestCase):
    """Each line is followed by a ping that the same process must answer; every line written back is strict JSON."""

    def setUp(self):
        home = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, home, True)
        self.p = subprocess.Popen([sys.executable, os.path.join(HERE, "cryptovalid_mcp.py")], stdin=subprocess.PIPE,
                                  stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env={**os.environ, "HOME": home, "USERPROFILE": home})
        self.addCleanup(self._stop)
        self.n = 5000

    def _stop(self):
        for f in (self.p.stdin, self.p.stdout):
            try:
                f.close()
            except OSError:
                pass
        self.p.wait(timeout=20)

    @staticmethod
    def strict(line: bytes):
        def no(c):
            raise ValueError(c)
        return json.loads(line.decode("utf-8"), parse_constant=no)

    def send(self, raw: bytes):
        self.n += 1
        try:
            self.p.stdin.write(raw + b"\n" + json.dumps({"jsonrpc": "2.0", "id": self.n, "method": "ping"}).encode() + b"\n")
            self.p.stdin.flush()
        except OSError as e:
            self.fail(f"the server is gone ({type(e).__name__}) before {raw[:60]!r}")
        got = []
        while True:
            out = self.p.stdout.readline()
            if not out:
                self.fail(f"the server ended (exit {self.p.wait(timeout=20)}) on {raw[:60]!r}")
            reply = self.strict(out)
            if reply.get("id") == self.n:
                return got
            got.append(reply)

    def test_cases(self):
        cases = [
            (b'{"jsonrpc":"2.0","id":"\\ud800","method":"ping"}', ("result", "\ud800")),
            (b'{"jsonrpc":"2.0","id":7,"method":"\\udfff"}', (-32601, 7)),
            (b'{"jsonrpc":"2.0","id":8,"method":"ping"}\xff', (-32700, None)),
            (b'\xc3\x28', (-32700, None)),
            (b'{"jsonrpc":"2.0","id":"\xff","method":"ping"}', (-32700, None)),   # not UTF-8 inside a string: not JSON
            (b'{"jsonrpc":"2.0","id":NaN,"method":"ping"}', (-32700, None)),
            (b'{"jsonrpc":"2.0","id":9,"method":"ping","params":{"x":Infinity}}', (-32700, None)),
            (b'{"jsonrpc":"2.0","id":10,"method":"tools/call","params":{"name":"verify_ledger","arguments":{"path":"\\ud800x"}}}',
             ("result", 10)),
            (b'{"jsonrpc":"2.0","id":null,"method":"no/such"}', (-32601, None)),   # id null is a Request: answered
        ]
        for raw, (code, id_) in cases:
            with self.subTest(raw=raw):
                got = self.send(raw)
                self.assertEqual(len(got), 1, got)
                self.assertEqual(got[0].get("id"), id_)
                if code == "result":
                    self.assertIn("result", got[0])
                else:
                    self.assertEqual(got[0]["error"]["code"], code)

    def test_generated(self):
        rng = random.Random(SEED)
        pieces = [b"\\ud800", b"\\udc00", b"\\ud83d\\ude00", b"\xff", b"\xc0\xaf", b"\xed\xa0\x80", b"NaN", b"-Infinity", b"x"]
        for k in range(300):
            where = rng.choice(["id", "method", "param", "raw"])
            p = rng.choice(pieces)
            if where == "raw":
                raw = b'{"jsonrpc":"2.0","id":%d,"method":"ping"}' % k + p
            elif p in (b"NaN", b"-Infinity"):
                raw = (b'{"jsonrpc":"2.0","id":%s,"method":"ping"}' % p if where == "id"
                       else b'{"jsonrpc":"2.0","id":%d,"method":"ping","params":{"a":%s}}' % (k, p))
            elif where == "id":
                raw = b'{"jsonrpc":"2.0","id":"' + p + b'","method":"ping"}'
            elif where == "method":
                raw = b'{"jsonrpc":"2.0","id":%d,"method":"' % k + p + b'"}'
            else:
                raw = b'{"jsonrpc":"2.0","id":%d,"method":"tools/call","params":{"name":"verify_ledger","arguments":{"path":"' % k + p + b'"}}}'
            with self.subTest(raw=raw):
                self.assertLessEqual(len(self.send(raw)), 1)


if __name__ == "__main__":
    unittest.main()
