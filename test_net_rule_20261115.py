#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""cryptovalid_net (15/11/2026): every module that opens a URL goes through one closed rule.

1. Schemes: generated URLs (schemes in every case, white space and control characters, hosts that look like loopback
   and are not, userinfo and fragment tricks, non-strings) against the three policies, with the expected answer computed
   here from the rule's text, not from the module; then every call site refuses `file:`, `ftp:`, `data:` BEFORE any I/O.
2. Proxy: a fresh interpreter, started with HTTP_PROXY / HTTPS_PROXY pointing at a recording proxy, asks a stub on
   127.0.0.1 through every call site. The loopback stub must be reached directly (the proxy sees none of those
   requests), while a request to a remote host still goes to the proxy. A fresh interpreter, because
   `urllib.request.urlopen` builds its opener once per process: a proxy set in the middle of a process is not read.
   Positive control inside the bench: in the same child, plain `urllib.request.urlopen` to the same stub DOES go to the
   proxy (the bench can see the defect). On the tree of 0.24.0 the proxy test fails: the TSA client, the witness client,
   Vault, NetHSM, AWS KMS, the trusted lists and both Solana clients went through the proxy (measured 15/11/2026).
3. Redirects: followed only to a URL the rule accepts.
"""
import http.server
import json
import os
import random
import subprocess
import sys
import tempfile
import threading
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

LOOPBACK_HOSTS = ["127.0.0.1", "127.9.8.7", "localhost", "LOCALHOST", "localhost.", "[::1]"]
REMOTE_HOSTS = ["example.org", "localhost.example.org", "127.0.0.1.nip.io", "10.0.0.1", "[::2]", "0.0.0.0"]


def expected(url, policy):
    """The rule of cryptovalid_net written out again here, independently of its code: True = accepted."""
    if not isinstance(url, str) or any(c.isspace() or ord(c) < 0x20 or ord(c) == 0x7F for c in url):
        return False
    scheme, sep, rest = url.partition(":")
    if not sep or not rest.startswith("//"):
        return False
    authority = rest[2:].split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
    host = authority.rsplit("@", 1)[-1]
    if host.startswith("["):
        host, _, port = host.partition("]")
        host += "]"
        if port and not (port.startswith(":") and (port[1:].isdigit() or port == ":")):
            return False
    elif ":" in host:
        host, port = host.rsplit(":", 1)
        if port and not port.isdigit():
            return False
    if not host:
        return False
    s = scheme.lower()
    if s == "https":
        return True
    if s != "http":
        return False
    return policy == "http|https" or (policy == "https|loopback-http" and _loopback(host))


def _loopback(host):
    h = host.strip("[]").rstrip(".").lower()
    parts = h.split(".")
    return h in ("localhost", "::1") or (len(parts) == 4 and parts[0] == "127"
                                         and all(p.isdigit() and int(p) < 256 for p in parts))


class TestSchemeRule(unittest.TestCase):
    def setUp(self):
        import cryptovalid_net
        self.N = cryptovalid_net

    def _accepted(self, url, policy):
        try:
            self.N.check_url(url, policy)
            return True
        except ValueError as e:
            self.assertTrue(str(e).startswith("url_not_allowed: "), str(e))
            return False

    def test_named_cases(self):
        N = self.N
        for policy in (N.ALLOW_HTTPS, N.ALLOW_HTTPS_OR_LOOPBACK_HTTP, N.ALLOW_HTTP_OR_HTTPS):
            for url in ("file:///etc/passwd", "file://localhost/etc/passwd", "FILE:///etc/passwd", "ftp://127.0.0.1/x",
                        "Ftp://example.org/x", "data:text/plain,hello", "javascript:alert(1)", "gopher://localhost/",
                        "x-custom://localhost/", "//example.org/x", "example.org/x", "", "https:", "https:///x",
                        " https://example.org/", "https://example.org/ ", "https://exa mple.org/", "https://example.org/\n",
                        "https://example.org/\x00", "https://example.org/\x7f", "https://example.org:port/",
                        b"https://example.org/", None, 443):
                with self.subTest(policy=policy, url=url):
                    self.assertFalse(self._accepted(url, policy))
            for url in ("https://example.org/", "HTTPS://example.org/", "hTTpS://127.0.0.1:8443/x"):
                with self.subTest(policy=policy, url=url):
                    self.assertTrue(self._accepted(url, policy))
        self.assertFalse(self._accepted("http://example.org/", N.ALLOW_HTTPS))
        self.assertFalse(self._accepted("http://127.0.0.1/", N.ALLOW_HTTPS))
        self.assertTrue(self._accepted("http://127.0.0.1:8200/", N.ALLOW_HTTPS_OR_LOOPBACK_HTTP))
        self.assertTrue(self._accepted("HTTP://[::1]:8200/", N.ALLOW_HTTPS_OR_LOOPBACK_HTTP))
        for trick in ("http://127.0.0.1@example.org/", "http://example.org#@127.0.0.1/", "http://localhost.example.org/",
                      "http://127.0.0.1.nip.io/", "http://0.0.0.0/"):
            with self.subTest(trick=trick):
                self.assertFalse(self._accepted(trick, N.ALLOW_HTTPS_OR_LOOPBACK_HTTP))
        self.assertTrue(self._accepted("http://example.org/", N.ALLOW_HTTP_OR_HTTPS))
        with self.assertRaises(ValueError):
            N.check_url("https://example.org/", "anything")          # an unknown policy is a refusal too

    def test_generated_urls_follow_the_rule(self):
        rng = random.Random(20261115)
        N = self.N
        schemes = ["http", "https", "file", "ftp", "data", "ws", "wss", "httpx", "https2", "h", "", "ht tp", "-x"]
        n = 0
        for _ in range(4000):
            s = rng.choice(schemes)
            s = "".join(c.upper() if rng.random() < 0.4 else c for c in s)
            host = rng.choice(LOOPBACK_HOSTS + REMOTE_HOSTS + ["", "a b", "x\tx"])
            port = rng.choice(["", ":8080", ":0", ":x", ":"])
            pre = rng.choice(["", "", "", " ", "\t", "\n"])
            post = rng.choice(["", "/p", "/p?q=1", "/p#f", "/ space", "/\r"])
            url = f"{pre}{s}://{host}{port}{post}"
            for policy in (N.ALLOW_HTTPS, N.ALLOW_HTTPS_OR_LOOPBACK_HTTP, N.ALLOW_HTTP_OR_HTTPS):
                with self.subTest(url=url, policy=policy):
                    self.assertEqual(self._accepted(url, policy), expected(url, policy))
                n += 1
        self.assertEqual(n, 12000)

    def test_loopback_names(self):
        N = self.N
        for h in ("localhost", "LocalHost", "localhost.", "127.0.0.1", "127.255.255.254", "::1", "[::1]"):
            self.assertTrue(N.is_loopback(h), h)
        for h in ("", None, 5, "localhost.example.org", "127.0.0.1.nip.io", "0.0.0.0", "::", "10.0.0.1", "::ffff:8.8.8.8"):
            self.assertFalse(N.is_loopback(h), h)


class TestCallSitesRefuseBeforeIO(unittest.TestCase):
    """Every module that opens a URL refuses file:, ftp:, data: (and a scheme in capitals) without calling the network."""
    BAD = ("file:///etc/passwd", "FILE:///etc/hostname", "ftp://127.0.0.1/x", "data:text/plain,x", "gopher://localhost/")

    def setUp(self):
        import cryptovalid_net
        self.N = cryptovalid_net
        self.calls = []
        self._orig = cryptovalid_net._open
        cryptovalid_net._open = lambda *a, **k: self.calls.append(a) or (_ for _ in ()).throw(AssertionError("I/O"))
        self.env = dict(os.environ)
        os.environ.update(VAULT_TOKEN="t", NETHSM_PASS="p", AWS_ACCESS_KEY_ID="AKIDEXAMPLE", AWS_SECRET_ACCESS_KEY="s",
                          QEAS_TOKEN="t")

    def tearDown(self):
        self.N._open = self._orig
        os.environ.clear()
        os.environ.update(self.env)

    def test_every_site(self):
        import cryptovalid_tsa, cryptovalid_lotl, cryptovalid_pruning_probe, cryptovalid_solana, cryptovalid_witness
        import cryptovalid_kms, cryptovalid_qeas, refresh_regulatory, evidence_pack
        for url in self.BAD:
            with self.subTest(url=url):
                for name, call in (
                        ("tsa", lambda: cryptovalid_tsa.request_timestamp(b"\0" * 32, url, 1)),
                        ("lotl", lambda: cryptovalid_lotl._get(url, 1)),
                        ("pruning", lambda: cryptovalid_pruning_probe._rpc(url, "m", [], 1)),
                        ("solana", lambda: cryptovalid_solana._rpc(url, "m", [], 1)),
                        ("aws", lambda: cryptovalid_kms.AwsKmsHttpBackend("k", "eu-south-1", endpoint=url)),
                        ("vault", lambda: cryptovalid_kms.VaultTransitBackend(url, "k")),
                        ("nethsm", lambda: cryptovalid_kms.NetHsmBackend(url, "k", "u")),
                        ("qeas", lambda: cryptovalid_qeas.HttpQeasBackend(url))):
                    with self.assertRaises(ValueError, msg=name):
                        call()
                status, body = cryptovalid_witness.add_checkpoint(url, b"note\n", 0, [])
                self.assertEqual(status, 0)
                self.assertIn(b"url_not_allowed", body)
                self.assertFalse(refresh_regulatory._reachable(url, 1))
                self.assertFalse(evidence_pack._rfc3161_stamp("00" * 32, url, 1)["anchored"])
        self.assertEqual(self.calls, [])
        # positive control of this bench: an accepted URL does reach the (replaced) I/O point
        with self.assertRaises(AssertionError):
            cryptovalid_lotl._get("https://example.org/tl.xml", 1)
        self.assertEqual(len(self.calls), 1)


class _Recorder(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _any(self):
        self.server.seen.append((self.command, self.path))
        n = int(self.headers.get("Content-Length") or 0)
        if n:
            self.rfile.read(n)
        code, body, extra = self.server.answer(self.path)
        self.send_response(code)
        for k, v in extra:
            self.send_header(k, v)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    do_GET = do_POST = do_HEAD = do_PUT = do_CONNECT = _any


def _serve(answer):
    s = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Recorder)
    s.seen, s.answer = [], answer
    threading.Thread(target=s.serve_forever, daemon=True).start()
    return s


CHILD = r'''
import json, os, sys, urllib.request
sys.path.insert(0, sys.argv[1]); base = sys.argv[2]; out = {}
def run(name, f):
    try:
        f(); out[name] = "ok"
    except BaseException as e:
        out[name] = type(e).__name__ + ": " + str(e)[:160]
import cryptovalid_tsa, cryptovalid_lotl, cryptovalid_pruning_probe, cryptovalid_solana, cryptovalid_witness
import cryptovalid_kms, refresh_regulatory
run("control-urlopen", lambda: urllib.request.urlopen(base + "/control", timeout=5).read())
run("tsa", lambda: cryptovalid_tsa.request_timestamp(b"\0" * 32, base + "/tsa", 5))
run("lotl", lambda: cryptovalid_lotl._get(base + "/lotl", 5))
run("pruning", lambda: cryptovalid_pruning_probe._rpc(base + "/pruning", "m", [], 5))
run("solana", lambda: cryptovalid_solana._rpc(base + "/solana", "m", [], 5))
run("witness", lambda: cryptovalid_witness.add_checkpoint(base + "/witness", b"n\n", 0, [], 5))
run("vault", lambda: cryptovalid_kms.VaultTransitBackend(base + "/vault", "k")._req("GET", "transit/keys/k"))
run("nethsm", lambda: cryptovalid_kms.NetHsmBackend(base + "/nethsm", "k", "u")._req("GET", "keys/k"))
run("aws", lambda: cryptovalid_kms.AwsKmsHttpBackend("k", "eu-south-1", endpoint=base + "/aws")._call("TrentService.GetPublicKey", {}))
run("refresh", lambda: refresh_regulatory._reachable(base + "/refresh", 5))
try:
    import cryptovalid_net as N
    run("open_url-loopback", lambda: N.open_url(base + "/open_url", 5, N.ALLOW_HTTP_OR_HTTPS).read())
    run("open_url-remote", lambda: N.open_url("http://cv-remote.invalid/remote", 5, N.ALLOW_HTTP_OR_HTTPS).read())
except ImportError:
    pass
print(json.dumps(out))
'''
# "lotl" is not among them since SPEC §22 rule 6: it fetches over https only, so a plain-http loopback stub is refused before
# any request (asserted below)
SITES = ("tsa", "pruning", "solana", "witness", "vault", "nethsm", "aws", "refresh")


class TestLoopbackNeverThroughTheProxy(unittest.TestCase):
    def test_fresh_interpreter_with_a_proxy_from_the_start(self):
        stub = _serve(lambda path: (200, b"{}", []))
        proxy = _serve(lambda path: (403, b"{}", []))
        self.addCleanup(stub.shutdown)
        self.addCleanup(proxy.shutdown)
        base = "http://127.0.0.1:%d" % stub.server_address[1]
        purl = "http://127.0.0.1:%d" % proxy.server_address[1]
        env = {k: v for k, v in os.environ.items() if k.lower() not in ("no_proxy", "http_proxy", "https_proxy",
                                                                          "all_proxy", "pythonpath")}
        env.update(HTTP_PROXY=purl, HTTPS_PROXY=purl, http_proxy=purl, https_proxy=purl, VAULT_TOKEN="t",
                   NETHSM_PASS="p", AWS_ACCESS_KEY_ID="AKIDEXAMPLE", AWS_SECRET_ACCESS_KEY="s")
        with tempfile.TemporaryDirectory() as d:
            env["HOME"] = env["USERPROFILE"] = d   # USERPROFILE: Windows reads ~ there
            r = subprocess.run([sys.executable, "-c", CHILD, HERE, base], env=env, capture_output=True, text=True, encoding="utf-8",
                               timeout=120)
        self.assertEqual(r.returncode, 0, r.stderr[-800:])
        out = json.loads(r.stdout)
        via_proxy = [p for _, p in proxy.seen]
        direct = [p for _, p in stub.seen]
        # positive control: plain urlopen to the same loopback stub goes to the proxy, so the bench sees the defect
        self.assertTrue(any(p.endswith("/control") for p in via_proxy), (via_proxy, out))
        for site in SITES:
            with self.subTest(site=site):
                self.assertFalse([p for p in via_proxy if "/" + site in p], (site, via_proxy, out[site]))
                self.assertTrue([p for p in direct if p.startswith("/" + site)], (site, direct, out[site]))
        self.assertEqual(out["open_url-loopback"], "ok")
        self.assertTrue(out["lotl"].startswith("ValueError"), out["lotl"])          # §22 rule 6: http refused, even loopback
        self.assertFalse([p for p in via_proxy + direct if "/lotl" in p], (via_proxy, direct))
        # a remote host still goes through the environment's proxy (which answered 403 here)
        self.assertTrue(any("cv-remote.invalid" in p for p in via_proxy), via_proxy)
        self.assertIn("403", out["open_url-remote"])


class TestRedirects(unittest.TestCase):
    def test_redirect_only_where_the_rule_allows(self):
        import cryptovalid_net as N
        import urllib.error

        def answer(path):
            if path.startswith("/to-ftp"):
                return 302, b"", [("Location", "ftp://127.0.0.1/x")]
            if path.startswith("/to-file"):
                return 302, b"", [("Location", "file:///etc/passwd")]
            if path.startswith("/to-ok"):
                return 302, b"", [("Location", "/final")]
            return 200, b'{"ok":1}', []
        stub = _serve(answer)
        self.addCleanup(stub.shutdown)
        base = "http://127.0.0.1:%d" % stub.server_address[1]
        self.assertEqual(N.open_url(base + "/to-ok", 5, N.ALLOW_HTTP_OR_HTTPS).read(), b'{"ok":1}')
        # ftp: urllib alone follows it; the rule refuses it. file: urllib itself already refuses (HTTPError 302)
        for p, why in (("/to-ftp", "url_not_allowed"), ("/to-file", "is not allowed")):
            with self.subTest(p=p):
                with self.assertRaises((ValueError, urllib.error.URLError)) as cm:
                    N.open_url(base + p, 5, N.ALLOW_HTTP_OR_HTTPS)
                self.assertIn(why, str(cm.exception))
        self.assertNotIn("/x", [q for _, q in stub.seen])


if __name__ == "__main__":
    unittest.main()
