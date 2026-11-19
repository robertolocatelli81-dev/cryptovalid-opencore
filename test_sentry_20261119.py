#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""The rules of SPEC v0.12 §20, written after a security review of 0.26.0 on 2026-11-19: each class holds one rule to
generated inputs, with the expected answer computed here and not taken from the module. Every test of this file that
names a defect fails on 22d342c, the commit before these rules (measured; the CHANGELOG gives the counts).

Nothing here uses the network: servers listen on 127.0.0.1, names are answered by a resolver replaced in the test.
"""
import http.server
import ipaddress
import os
import random
import socket
import sys
import threading
import unittest
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

SEED = 20261119


# ---------------------------------------------------------------- §20 rules 1 and 2: cryptovalid_net

def _v4_forms(n: int, rng) -> list:
    """Spellings of one IPv4 address that inet_aton reads: 1 to 4 parts, each decimal, octal or hexadecimal."""
    b = n.to_bytes(4, "big")

    def num(v):
        return rng.choice([str(v), "0x%x" % v, "0X%X" % v, "0%o" % v if v else "0", "0x%08x" % v])
    return [".".join(str(x) for x in b),
            num(n),
            f"{num(b[0])}.{num(int.from_bytes(b[1:], 'big'))}",
            f"{num(b[0])}.{num(b[1])}.{num(int.from_bytes(b[2:], 'big'))}",
            ".".join(num(x) for x in b),
            "[::ffff:%s]" % ".".join(str(x) for x in b),
            "[::ffff:%x:%x]" % (n >> 16, n & 0xFFFF),
            "[0:0:0:0:0:ffff:%x:%x]" % (n >> 16, n & 0xFFFF),
            "[::FFFF:%X:%X]" % (n >> 16, n & 0xFFFF)]


def _os_kinds(host: str):
    """What THIS system would connect to for `host`, classified with ipaddress on the resolver's own answer (the
    oracle: the module is not asked). None when the system does not resolve it."""
    try:
        infos = socket.getaddrinfo(host.strip("[]"), 80, proto=socket.IPPROTO_TCP)
    except (OSError, UnicodeError):
        return None
    kinds = set()
    for info in infos:
        a = ipaddress.ip_address(info[4][0].split("%", 1)[0])
        if a.version == 6 and a.ipv4_mapped is not None:
            a = a.ipv4_mapped
        kinds.add("loopback" if a.is_loopback else "unspecified" if a.is_unspecified
                  else "link-local" if a.is_link_local else "other")
    return kinds


class _Quiet(http.server.BaseHTTPRequestHandler):
    def _any(self):
        self.server.seen.append((self.command, self.path, {k.lower(): v for k, v in self.headers.items()}))
        code, headers = self.server.answer(self.path)
        self.send_response(code)
        for k, v in headers:
            self.send_header(k, v)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")

    do_GET = do_POST = _any

    def log_message(self, *a):
        pass


def _serve(answer):
    s = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Quiet)
    s.seen, s.answer = [], answer
    threading.Thread(target=s.serve_forever, daemon=True).start()
    return s


def _stop(s):
    s.shutdown()
    s.server_close()


class TestNetAddressAsNumber(unittest.TestCase):
    """Rule 1: a redirect from a host that is not loopback never reaches a loopback, unspecified or link-local
    address, in whatever form the address is written."""

    def setUp(self):
        import cryptovalid_net
        self.N = cryptovalid_net

    def _redirect(self, target, origin="http://tsa.example.org/tsr", loopback=False, headers=None):
        h = self.N._Redirects(self.N.ALLOW_HTTP_OR_HTTPS, loopback=loopback)
        req = urllib.request.Request(origin, data=b"x", method="POST", headers=headers or {})
        return h.redirect_request(req, None, 302, "Found", {}, target)

    def test_named_bypasses(self):
        # the seven spellings of the review, each one resolved by this system to an address the rule refuses
        for host in ("127.1", "0.0.0.0", "2130706433", "0x7f000001", "0177.0.0.1", "[::ffff:127.0.0.1]", "[::]"):
            with self.subTest(host=host):
                self.assertTrue(_os_kinds(host) & {"loopback", "unspecified"}, "the control: the system resolves it there")
                with self.assertRaises(ValueError) as cm:
                    self._redirect(f"http://{host}:8200/v1/secret")
                self.assertTrue(str(cm.exception).startswith("url_not_allowed: a redirect from a remote host"))

    def test_generated_literals(self):
        rng = random.Random(SEED)
        refused = followed = 0
        nets = [(0x7F000000, 24, "loopback"), (0xA9FE0000, 16, "link-local"), (0, 0, "unspecified")]
        for _ in range(300):
            base, bits, kind = rng.choice(nets)
            n = base | rng.getrandbits(bits) if bits else 0
            for host in _v4_forms(n, rng):
                with self.subTest(host=host):
                    self.assertEqual(_os_kinds(host), {kind}, "the control: the system reads the same address")
                    with self.assertRaises(ValueError) as cm:
                        self._redirect(f"http://{host}/x")
                    self.assertIn(f"to a {kind} ", str(cm.exception))
                    refused += 1
        for host in ("[::1]", "[0::1]", "[::0001]", "[0:0:0:0:0:0:0:1]", "[fe80::1]", "[FE80::abcd]", "[fe80::1%25lo]",
                     "[::ffff:0.0.0.0]", "[::ffff:0:0]", "0", "0x0", "00.0", "１２７.0.0.1", "127。0。0。1", "localhost",
                     "LOCALHOST."):
            with self.subTest(host=host):
                with self.assertRaises(ValueError):
                    self._redirect(f"http://{host}/x")
                refused += 1
        for _ in range(300):                        # the other side: an address that is none of the three is followed
            n = rng.choice([0x08080808, 0x5DB8D822, 0x0A000001, 0xC0A80001, 0x7E000001, 0x80000001, 0xA9FD0001, 0xA9FF0001])
            for host in _v4_forms(n, rng):
                with self.subTest(host=host):
                    self.assertEqual(_os_kinds(host), {"other"})
                    self.assertIsNotNone(self._redirect(f"http://{host}/x"))
                    followed += 1
        self.assertEqual((refused, followed), (300 * 9 + 16, 300 * 9))

    def test_names_are_resolved(self):
        N = self.N
        answers = {"to-loopback.example": ["127.0.0.1"], "to-v6-loopback.example": ["::1"],
                   "to-mapped.example": ["::ffff:127.0.0.1"], "to-any.example": ["0.0.0.0"],
                   "to-link-local.example": ["169.254.169.254"], "one-of-two.example": ["93.184.216.34", "127.0.0.2"],
                   "first-of-two.example": ["127.0.0.2", "93.184.216.34"],
                   "public.example": ["93.184.216.34", "2606:2800:220:1:248:1893:25c8:1946"]}
        asked = []

        def fake(host, port, *a, **kw):
            asked.append(host)
            if host not in answers:
                raise socket.gaierror(socket.EAI_NONAME, "Name or service not known")
            return [(socket.AF_INET6 if ":" in x else socket.AF_INET, socket.SOCK_STREAM, 6, "", (x, 0)) for x in answers[host]]
        real = socket.getaddrinfo
        N.socket.getaddrinfo = fake
        try:
            for name in answers:
                with self.subTest(name=name):
                    if name == "public.example":
                        self.assertIsNotNone(self._redirect(f"https://{name}/x"))
                    else:
                        with self.assertRaises(ValueError) as cm:
                            self._redirect(f"https://{name}/x")
                        self.assertIn("a redirect from a remote host to a ", str(cm.exception))
            self.assertIsNotNone(self._redirect("https://does-not-resolve.example/x"))   # left to urllib (module docstring)
            self.assertEqual(asked, list(answers) + ["does-not-resolve.example"])
        finally:
            N.socket.getaddrinfo = real

    def test_every_hop_is_judged(self):
        # the first URL was loopback, the request being redirected is not: remote -> loopback is still refused
        with self.assertRaises(ValueError):
            self._redirect("http://127.0.0.1:8200/x", origin="http://remote.example/y", loopback=True)
        # loopback -> loopback stays allowed (a local Vault that redirects to itself)
        self.assertIsNotNone(self._redirect("http://127.0.0.1:8200/x", origin="http://127.0.0.1:8200/y", loopback=True))
        self.assertIsNotNone(self._redirect("http://127.1:8200/x", origin="http://localhost:8200/y", loopback=True))

    def test_loopback_in_every_form_is_loopback(self):
        N, rng = self.N, random.Random(SEED)
        for _ in range(200):
            n = 0x7F000000 | rng.getrandbits(24)
            for host in _v4_forms(n, rng):
                with self.subTest(host=host):
                    self.assertTrue(N.is_loopback(host))
                    N.check_url(f"http://{host}:8200/v1/x", N.ALLOW_HTTPS_OR_LOOPBACK_HTTP)   # plain http allowed: it IS loopback
        for host in ("１２７.0.0.1", "127。0。0。1", "１２７.１"):      # the resolver is given the IDNA form: ASCII digits and dots
            with self.subTest(host=host):
                self.assertEqual(_os_kinds(host), {"loopback"}, "the control: the system connects to loopback")
                self.assertTrue(N.is_loopback(host))
        for host in ("126.255.255.255", "128.0.0.1", "0x7e000001", "2130706432.example", "127.0.0.1 x", "127.0.0.1\tx", "0.0.0.0",
                     "0", "::", "::ffff:8.8.8.8", "169.254.1.1", "fe80::1", "1.2.3.4.5", "0x", "", None, 5, b"127.0.0.1"):
            with self.subTest(host=host):
                self.assertFalse(N.is_loopback(host))

    def test_end_to_end_on_this_host(self):
        N = self.N
        secret = _serve(lambda path: (200, []))
        self.addCleanup(_stop, secret)
        port = secret.server_address[1]
        for host in ("127.1", "0.0.0.0", "2130706433", "0x7f000001", "0177.0.0.1", "[::ffff:127.0.0.1]"):
            redirector = _serve(lambda path, host=host: (302, [("Location", f"http://{host}:{port}/v1/secret")]))
            self.addCleanup(_stop, redirector)
            req = urllib.request.Request("http://127.0.0.1:%d/tsr" % redirector.server_address[1], data=b"x", method="POST")
            with self.subTest(host=host):
                # loopback=False: what open_url passes when the first URL is not loopback (the redirector stands for it)
                with self.assertRaises(ValueError):
                    N._open(req, 5, False, N.ALLOW_HTTP_OR_HTTPS)
        self.assertEqual(secret.seen, [])
        # the control of the bench: the same server IS reached when the first URL is loopback
        redirector = _serve(lambda path: (302, [("Location", f"http://127.1:{port}/v1/secret")]))
        self.addCleanup(_stop, redirector)
        r = N.open_url("http://127.0.0.1:%d/x" % redirector.server_address[1], 5, N.ALLOW_HTTP_OR_HTTPS)
        self.assertEqual(r.read(), b"ok")
        self.assertEqual([p for _, p, _ in secret.seen], ["/v1/secret"])


class TestNetCredentialsStayWithTheirOrigin(unittest.TestCase):
    """Rule 2: a redirect to another origin is refused when the request carries a header outside the closed list."""

    CREDENTIALS = ["Authorization", "Proxy-Authorization", "X-Vault-Token", "Cookie", "X-Amz-Security-Token", "X-Amz-Date",
                   "X-Amz-Target", "X-Amz-Content-Sha256", "X-Api-Key", "X-Auth-Token"]

    def setUp(self):
        import cryptovalid_net
        self.N = cryptovalid_net

    def _redirect(self, origin, target, headers):
        h = self.N._Redirects(self.N.ALLOW_HTTP_OR_HTTPS, loopback=False)
        req = urllib.request.Request(origin, data=b"{}", method="POST", headers=headers)
        return h.redirect_request(req, None, 302, "Found", {}, target)

    def test_headers_of_the_callers(self):
        # the headers cryptovalid_kms and cryptovalid_qeas put on a request (read in their code on 2026-11-19)
        for headers in ({"X-Vault-Token": "s.SECRET", "Content-Type": "application/json"},
                        {"Authorization": "Basic dTpw", "Content-Type": "application/json"},
                        {"Authorization": "Bearer t", "Content-Type": "application/json", "Accept": "application/json"},
                        {"Content-Type": "application/x-amz-json-1.1", "X-Amz-Date": "20261119T000000Z",
                         "X-Amz-Target": "TrentService.Sign", "Authorization": "AWS4-HMAC-SHA256 Credential=..."},
                        {"X-Amz-Security-Token": "t"}):
            with self.subTest(headers=sorted(headers)):
                with self.assertRaises(ValueError) as cm:
                    self._redirect("https://vault.example:8200/v1/transit/sign/k", "https://other.example/x", headers)
                self.assertIn("a redirect to another origin", str(cm.exception))
                self.assertNotIn("SECRET", str(cm.exception))

    def test_generated(self):
        rng, N = random.Random(SEED), self.N
        safe = ["Content-Type", "User-Agent", "Accept", "Accept-Encoding", "Accept-Language", "content-length"]
        origins = ["https://a.example", "https://a.example:443", "https://A.EXAMPLE", "https://a.example.", "http://a.example",
                   "https://a.example:8443", "https://b.example", "https://a.example.org", "http://a.example:80",
                   "https://93.184.216.34", "https://1572395042", "http://a.example:443", "https://a.example:80"]

        def canon(o):                                   # the origin written out here: scheme, host, port
            scheme, rest = o.split("://")
            host, _, port = rest.partition(":")
            host = host.rstrip(".").lower()
            if host == "1572395042":
                host = "93.184.216.34"
            return scheme, host, int(port) if port else {"http": 80, "https": 443}[scheme]
        counts = {"refused": 0, "followed": 0}
        for _ in range(4000):
            a, b = rng.choice(origins), rng.choice(origins)
            headers = {}
            for name in rng.sample(safe, rng.randint(0, 3)):
                headers["".join(c.upper() if rng.random() < 0.5 else c.lower() for c in name)] = "v"
            carried = []
            for _ in range(rng.choice([0, 0, 1, 2])):
                name = rng.choice(self.CREDENTIALS + ["X-" + "".join(rng.choice("abcdefghij-") for _ in range(6)) + "z"])
                name = "".join(c.upper() if rng.random() < 0.5 else c.lower() for c in name)
                headers[name] = "secret"
                carried.append(name)
            want_refused = canon(a) != canon(b) and bool(carried)
            with self.subTest(a=a, b=b, headers=sorted(headers)):
                try:
                    new = self._redirect(a + "/p", b + "/q", headers)
                    got_refused = False
                except ValueError as e:
                    got_refused = True
                    self.assertTrue(str(e).startswith("url_not_allowed: a redirect to another origin"), str(e))
                self.assertEqual(got_refused, want_refused)
                if not got_refused:
                    self.assertEqual({k.lower() for k in new.headers} | {"content-type", "content-length"},
                                     {k.lower() for k in headers} | {"content-type", "content-length"})   # same origin: kept
            counts["refused" if want_refused else "followed"] += 1
        self.assertGreater(counts["refused"], 1000)
        self.assertGreater(counts["followed"], 1000)
        self.assertEqual(N.FORWARDED_ACROSS_ORIGINS, frozenset(x.lower() for x in safe))   # the closed list, as written here

    def test_end_to_end_on_this_host(self):
        N = self.N
        other = _serve(lambda path: (200, []))
        self.addCleanup(_stop, other)
        first = _serve(lambda path: (302, [("Location", "http://127.0.0.1:%d/elsewhere" % other.server_address[1])])
                       if path == "/away" else (302, [("Location", "/same")]) if path == "/stay" else (200, []))
        self.addCleanup(_stop, first)
        base = "http://127.0.0.1:%d" % first.server_address[1]
        for name in ("X-Vault-Token", "Authorization", "Cookie", "X-Amz-Security-Token"):
            req = urllib.request.Request(base + "/away", headers={name: "s.SECRET"})
            with self.subTest(header=name):
                with self.assertRaises(ValueError):
                    N.open_url(req, 5, N.ALLOW_HTTP_OR_HTTPS)
        self.assertEqual(other.seen, [])               # another port is another origin: nothing arrived there
        req = urllib.request.Request(base + "/stay", headers={"X-Vault-Token": "s.SECRET"})
        self.assertEqual(N.open_url(req, 5, N.ALLOW_HTTP_OR_HTTPS).read(), b"ok")
        self.assertEqual(first.seen[-1][2].get("x-vault-token"), "s.SECRET")           # the same origin keeps it
        req = urllib.request.Request(base + "/away", headers={"User-Agent": "cv-test"})
        self.assertEqual(N.open_url(req, 5, N.ALLOW_HTTP_OR_HTTPS).read(), b"ok")      # no credential: followed
        self.assertEqual([p for _, p, _ in other.seen], ["/elsewhere"])


if __name__ == "__main__":
    unittest.main()
