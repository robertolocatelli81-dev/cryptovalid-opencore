#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""The rules of SPEC v0.12 §20, written after a security review of 0.26.0 on 2026-11-19: each class holds one rule to
generated inputs, with the expected answer computed here and not taken from the module. Every test of this file that
names a defect fails on 22d342c, the commit before these rules (measured; the CHANGELOG gives the counts).

Nothing here uses the network: servers listen on 127.0.0.1, names are answered by a resolver replaced in the test.
"""
import base64
import hashlib
import http.server
import ipaddress
import json
import os
import random
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

try:   # the `sign` extra; without it the cases that need it are skipped with this reason, never an import error
    from cryptography.hazmat.primitives import hashes, serialization as ser
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
    HAVE_CRYPTO = True
except ImportError:
    HAVE_CRYPTO = False
if os.environ.get("CV_REQUIRE_CRYPTO") == "1" and not HAVE_CRYPTO:   # the job with cryptography must not pass on skips
    raise SystemExit("CV_REQUIRE_CRYPTO=1 but `cryptography` is missing: the cases that need it would be skipped")
NEEDS_CRYPTO = unittest.skipUnless(HAVE_CRYPTO, "needs `cryptography` (the `sign` extra)")

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


# ---------------------------------------------------------------- §20 rule 3: JCS and integers that are not doubles

def _is_double(x: int) -> bool:
    """Is the integer exactly an IEEE 754 binary64 value? Integer arithmetic only: at most 53 significant bits and an
    exponent the format has (the oracle: float() is not asked)."""
    m = abs(x)
    if m == 0:
        return True
    low = (m & -m).bit_length() - 1                      # trailing zero bits
    return m.bit_length() - low <= 53 and m.bit_length() <= 1024


_NODE = r"""
const out = [];
for (const t of JSON.parse(require('fs').readFileSync(0, 'utf8'))) {
  const n = JSON.parse(t);
  out.push([JSON.stringify(n), Number.isFinite(n) && BigInt(n) === BigInt(t)]);   // what ECMAScript writes; did it keep the value
}
process.stdout.write(JSON.stringify(out));
"""


class TestJcsIntegersAreDoubles(unittest.TestCase):
    """Rule 3: jcs() refuses an integer that is not exactly a double; two integers never give the same bytes."""

    def setUp(self):
        import cryptovalid_acta
        self.jcs = cryptovalid_acta.jcs

    def _integers(self):
        rng = random.Random(SEED)
        xs = set()
        for k in range(-70, 71):                          # around 2^53 and around 2^63, 2^64, both signs
            for base in (2 ** 53, 2 ** 63, 2 ** 64):
                xs.update((base + k, -(base + k)))
        for _ in range(3000):                             # any size up to past the double range
            bits = rng.randint(50, 1100)
            x = rng.getrandbits(bits) | (1 << (bits - 1))
            if rng.random() < 0.5:                        # half of them made doubles: 53 significant bits, zeros below
                x = (x >> max(0, bits - 53)) << max(0, bits - 53)
            xs.add(x if rng.random() < 0.5 else -x)
        xs.update((10 ** 20, 10 ** 21, 10 ** 22, 10 ** 23, 2 ** 1023, 2 ** 1024, -(2 ** 1024), 2 ** 1024 - 2 ** 970))
        return sorted(xs)

    def test_refused_exactly_when_not_a_double(self):
        seen, refused, accepted = {}, 0, 0
        for x in self._integers():
            with self.subTest(x=x if abs(x) < 10 ** 30 else f"{x.bit_length()} bits"):
                if _is_double(x):
                    b = self.jcs({"n": [x]})
                    self.assertNotIn(b, seen, "two integers, the same bytes")
                    seen[b] = x
                    self.assertEqual(int(float(json.loads(b)["n"][0])), x)          # the bytes still name this integer
                    accepted += 1
                else:
                    with self.assertRaises(ValueError) as cm:
                        self.jcs({"n": [x]})
                    self.assertIn("JCS: ", str(cm.exception))
                    refused += 1
        self.assertGreater(refused, 1500)
        self.assertGreater(accepted, 1500)
        for x in (2 ** 53 + 1, -(2 ** 53 + 1), 2 ** 53 + 3, 2 ** 60 + 7, 2 ** 63 - 1, 2 ** 64 - 1):   # named in the review
            self.assertFalse(_is_double(x))
            with self.assertRaises(ValueError) as cm:
                self.jcs(x)
            self.assertIn("is not exactly an IEEE 754 double (RFC 8785 §3.1", str(cm.exception))
        for x in (2 ** 53, -(2 ** 53), 2 ** 53 + 2, 2 ** 53 - 1, -(2 ** 53 - 1), 0, 1, -1):
            self.assertEqual(self.jcs(x), str(x).encode())
        self.assertEqual(self.jcs([1e21, 2.0 ** 53, True, False]), b"[1e+21,9007199254740992,true,false]")   # floats, booleans: as before

    def test_against_ecmascript(self):
        if not shutil.which("node"):
            self.skipTest("node not installed")
        xs = self._integers()                                         # past the double range JSON.parse gives Infinity
        p = subprocess.run(["node", "-e", _NODE], input=json.dumps([str(x) for x in xs]).encode(), capture_output=True, timeout=120)
        self.assertEqual(p.returncode, 0, p.stderr.decode()[:300])
        got = json.loads(p.stdout)
        self.assertEqual(len(got), len(xs))
        kept = lost = 0
        for x, (text, same) in zip(xs, got):
            with self.subTest(x=x if abs(x) < 10 ** 30 else f"{x.bit_length()} bits"):
                self.assertEqual(same, _is_double(x), "the control: the oracle here and ECMAScript agree on which are doubles")
                if same:
                    self.assertEqual(self.jcs(x), text.encode())
                    kept += 1
                else:
                    with self.assertRaises(ValueError):
                        self.jcs(x)
                    lost += 1
        self.assertGreater(kept, 1500)
        self.assertGreater(lost, 1500)

    def test_other_call_sites(self):
        import cryptovalid_aps as A
        import cryptovalid_vaara_receipt as V
        self.assertNotEqual(A.payload_ref_v2({"amount": 1}), A.payload_ref_v2({"amount": 2}))
        self.assertNotEqual(A.payload_ref_v2({"amount": 2 ** 53}), A.payload_ref_v2({"amount": 2 ** 53 + 2}))
        for f, doc in ((A.payload_ref_v2, {"amount": 2 ** 53 + 1}), (V.sha256_jcs, {"x": 2 ** 60 + 7}),
                       (V.sha256_jcs, {"deep": [{"x": [-(2 ** 53) - 1]}]})):
            with self.subTest(f=f.__name__):
                with self.assertRaises(ValueError):
                    f(doc)

    @NEEDS_CRYPTO
    def test_signed_receipt_does_not_verify_with_another_number(self):
        import cryptovalid_vaara_receipt as V
        sk = ec.generate_private_key(ec.SECP256R1())
        pem = sk.public_key().public_bytes(ser.Encoding.PEM, ser.PublicFormat.SubjectPublicKeyInfo)
        rng = random.Random(SEED)
        changed = 0
        for amount in (2 ** 53, -(2 ** 53), 2 ** 60, 2 ** 64, 10 ** 20, 2 ** 53 - 1, 12345):
            r = {"version": 1, "alg": "ES256", "backLink": {"attestationDigest": "sha256:" + "0" * 64},
                 "decisionDerived": {"amount_wei": amount}, "issuerAsserted": {"nonce": "n1"}}
            rr, ss = decode_dss_signature(sk.sign(V.signed_payload(r), ec.ECDSA(hashes.SHA256())))
            r["signature"] = (rr.to_bytes(32, "big") + ss.to_bytes(32, "big")).hex()
            wire = json.dumps(r)
            self.assertTrue(V.verify_receipt(json.loads(wire), pem, alg="ES256")["ok"], amount)     # the control
            for _ in range(60):
                other = amount + rng.choice([1, -1, 2, -2, 3, 255, -255, 256, 1024, -1024, rng.randint(-5000, 5000) or 1])
                forged = json.loads(wire.replace(f'"amount_wei": {amount}', f'"amount_wei": {other}'))
                self.assertEqual(forged["decisionDerived"]["amount_wei"], other)
                with self.subTest(amount=amount, other=other):
                    res = V.verify_receipt(forged, pem, alg="ES256")
                    self.assertFalse(res["ok"])
                    if not _is_double(other):
                        self.assertIn("is not exactly an IEEE 754 double", res["why"])
                changed += 1
        self.assertEqual(changed, 420)


# ---------------------------------------------------------------- §20 rules 4 to 6: cryptovalid_cedulon

class _CedulonLedger:
    """A Decider's ledger made here with fresh keys from a plan: one dict per record with decision, ref, effectHash,
    effectClass and `signed` (the context its inputsHash commits to, or None for a null inputsHash)."""

    def __init__(self):
        self.rk, self.xk, self.ck = (Ed25519PrivateKey.generate() for _ in range(3))
        self.t0 = 1_790_000_000_000

    @staticmethod
    def _pem(sk):
        return sk.public_key().public_bytes(ser.Encoding.PEM, ser.PublicFormat.SubjectPublicKeyInfo)

    def _record(self, claims):
        import cryptovalid_cedulon as C
        import cryptovalid_receipt as R
        der = self.rk.public_key().public_bytes(ser.Encoding.DER, ser.PublicFormat.SubjectPublicKeyInfo)
        ph = R.cbor_encode({1: -19, 3: C.CT_RECORD, 4: hashlib.sha256(der).digest()[:8]})
        payload = R.cbor_encode({label: claims[name] for label, name in C.RECORD_LABELS.items()})
        return R.cbor_encode([ph, {}, payload, self.rk.sign(R.cbor_encode(["Signature1", ph, b"", payload]))])

    def decisions(self, plan):
        from cryptovalid_acta import jcs
        lines, prev, hashes = [], None, []
        for i, p in enumerate(plan):
            allow = p["decision"] == "allow"
            c = {"decider": "d", "subject": "s", "requestHash": "a" * 64, "policyHash": "b" * 64,
                 "inputsHash": None if p.get("signed") is None else hashlib.sha256(jcs(p["signed"])).hexdigest(),
                 "decision": p["decision"], "reasonCode": "r", "ref": p["ref"], "effectHash": p["effectHash"] if allow else None,
                 "timestampMs": self.t0 + i, "nonce": f"n{i}", "prevRecordHash": prev,
                 "effectClass": p.get("effectClass", "act") if allow else None}
            octets = self._record(c)
            prev = hashlib.sha256(octets).hexdigest()
            hashes.append(prev)
            lines.append(json.dumps({"coseHex": octets.hex(), "claims": c}))
        return "\n".join(lines) + "\n", hashes

    def effects(self, rows):
        from cryptovalid_acta import jcs
        body = {"deciderId": "d", "channelId": "c", "windowStartMs": self.t0, "windowEndMs": self.t0 + 10_000,
                "effects": [{"ref": ref, "effectHash": h, "effectClass": cls, "timestampMs": self.t0 + 100 + k}
                            for k, (ref, h, cls) in enumerate(rows)]}
        return json.dumps({"receipt": {"body": body, "signature": base64.b64encode(self.xk.sign(jcs(body))).decode()}}) + "\n"

    def verify(self, plan, rows=None, inputs=None, **kw):
        import cryptovalid_cedulon as C
        dec, _ = self.decisions(plan)
        if rows is None:                                # every allow has its row
            rows = [(p["ref"], p["effectHash"], p.get("effectClass", "act")) for p in plan if p["decision"] == "allow"]
        inputs_text = None if inputs is None else "".join(json.dumps({"ref": r, "inputs": v}) + "\n" for r, v in inputs)
        kw.setdefault("clock_skew_ms", 0)
        return C.verify_ledger(dec, self.effects(rows), "", self._pem(self.rk), self._pem(self.xk), self._pem(self.ck),
                               inputs_text=inputs_text, **kw)


def _h(s) -> str:
    return hashlib.sha256(str(s).encode()).hexdigest()


@NEEDS_CRYPTO
class TestCedulonControlReadsSignedInputs(unittest.TestCase):
    """Rule 4: control reads a record's context only when its signed inputsHash binds it."""

    def _plan(self, rng):
        plan = []
        for i in range(rng.randint(3, 9)):
            kind = rng.choice(["halt", "resume", "plain-signed", "plain-null", "plain-null", "deny"])
            signed = {"halt": {"control": {"action": "halt"}}, "resume": {"control": {"action": "resume"}},
                      "plain-signed": {"principal": {"brain": f"agent-{i}"}, "inputs": []}}.get(kind)
            plan.append({"decision": "deny" if kind == "deny" else "allow", "ref": f"ref-{i}", "effectHash": _h(f"e{i}"),
                         "signed": signed if kind != "deny" or rng.random() < 0.5 else None})
            if kind == "deny" and plan[-1]["signed"] is None and rng.random() < 0.5:
                plan[-1]["signed"] = {"p": i}
        return plan

    @staticmethod
    def _oracle(plan):
        """The stage's rule on what the Decider SIGNED: the index of the first allow inside a halt window, or None."""
        halted = False
        for i, p in enumerate(plan):
            action = ((p.get("signed") or {}).get("control") or {}).get("action")
            if p["decision"] != "allow":
                continue
            if action == "halt":
                halted = True
            elif action == "resume":
                halted = False
            elif halted:
                return i
        return None

    def test_the_review_case(self):
        L = _CedulonLedger()
        plan = [{"decision": "allow", "ref": "a", "effectHash": _h(1), "signed": {"control": {"action": "halt"}}},
                {"decision": "allow", "ref": "b", "effectHash": _h(2), "signed": None}]
        bound = [("a", plan[0]["signed"])]
        r = L.verify(plan, inputs=bound)
        self.assertEqual((r["result"], r["stage"]), ("INVALID", "control"), r)                    # the control
        for added in ({"control": {"action": "resume"}}, {"control": {"action": "halt"}}, {}, None, [], "resume",
                      {"control": {"action": "resume"}, "new-key": 1}):
            for rows in (bound + [("b", added)], [("b", added)] + bound):
                with self.subTest(added=added, first=rows[0][0]):
                    r = L.verify(plan, inputs=rows)
                    self.assertEqual((r["result"], r["stage"]), ("INVALID", "inputs-binding"), r)
                    self.assertIn("no record's signed inputsHash binds it", r["why"])

    def test_a_context_signed_for_another_record_of_the_same_ref(self):
        # a deny whose SIGNED context says "resume" shares its ref with a later allow that has no signed context and
        # (inside the boundary allowance) no row yet: the allow has no context of its own, so the window stays open
        L = _CedulonLedger()
        plan = [{"decision": "allow", "ref": "h", "effectHash": _h(1), "signed": {"control": {"action": "halt"}}},
                {"decision": "deny", "ref": "X", "effectHash": None, "signed": {"control": {"action": "resume"}}},
                {"decision": "allow", "ref": "X", "effectHash": _h(2), "signed": None},
                {"decision": "allow", "ref": "y", "effectHash": _h(3), "signed": None}]
        bound = [("h", plan[0]["signed"]), ("X", plan[1]["signed"])]
        rows = [("h", _h(1), "act"), ("y", _h(3), "act")]
        r = L.verify(plan, rows=rows, inputs=bound, clock_skew_ms=300000)
        self.assertEqual((r["result"], r["stage"]), ("INVALID", "control"), r)
        self.assertIn("record 2:", r["why"])
        plan[2]["signed"] = {"control": {"action": "resume"}}        # the control: the allow's OWN signed context resumes
        r = L.verify(plan, rows=rows, inputs=bound, clock_skew_ms=300000)
        self.assertEqual(r["result"], "VALID", r)

    def test_generated(self):
        rng = random.Random(SEED)
        L = _CedulonLedger()
        seen = {"valid": 0, "control": 0, "attacks": 0}
        for _ in range(250):
            plan = self._plan(rng)
            bound = [(p["ref"], p["signed"]) for p in plan if p.get("signed") is not None]
            unbound = [p["ref"] for p in plan if p.get("signed") is None]
            first = self._oracle(plan)
            r = L.verify(plan, inputs=bound)
            with self.subTest(plan=[(p["decision"], p.get("signed")) for p in plan]):
                if first is None:
                    self.assertEqual(r["result"], "VALID", r)
                    self.assertNotIn("control", r["not_verified"])
                    seen["valid"] += 1
                else:
                    self.assertEqual((r["result"], r["stage"]), ("INVALID", "control"), r)
                    self.assertIn(f"record {first}:", r["why"])
                    seen["control"] += 1
                # rows nobody signed, for the records that have no signed context and for refs no record has:
                # whatever they say and wherever they stand, the verdict never becomes VALID where the signed
                # ledger is not, and the added row is the refusal
                for _ in range(4):
                    extra = [(rng.choice(unbound + ["nobody", "ref-99"]),
                              rng.choice([{"control": {"action": rng.choice(["resume", "halt", "x"])}},
                                          {"control": {"action": "resume"}, "k" + str(rng.randint(0, 9)): 1},
                                          {"approver": {"id": "op", "resolves": "ref-0", "signature": {}}}, {}, None, 0, []]))]
                    rows = list(bound)
                    rows.insert(rng.randint(0, len(rows)), extra[0])
                    r2 = L.verify(plan, inputs=rows)
                    self.assertEqual((r2["result"], r2["stage"]), ("INVALID", "inputs-binding"), r2)
                    seen["attacks"] += 1
        self.assertGreater(seen["valid"], 40)
        self.assertGreater(seen["control"], 40)
        self.assertEqual(seen["attacks"], 1000)


@NEEDS_CRYPTO
class TestCedulonDuplicateRef(unittest.TestCase):
    """Rule 5: a ref on more than one allow, or on more than one effect row, is duplicate-ref."""

    def test_the_review_case(self):
        L = _CedulonLedger()
        h1, h2, h3 = "1" * 64, "2" * 64, "3" * 64
        two = [{"decision": "allow", "ref": "X", "effectHash": h1}, {"decision": "allow", "ref": "X", "effectHash": h2}]
        for name, plan, rows in (("H1 never happened, H2 twice", [dict(two[0], effectHash=h3), two[1]], [("X", h2, "act")] * 2),
                                 ("both happened", two, [("X", h1, "act"), ("X", h2, "act")]),
                                 ("both happened, rows swapped", two, [("X", h2, "act"), ("X", h1, "act")]),
                                 ("one row", two, [("X", h2, "act")]), ("no row", two, [])):
            with self.subTest(name):
                r = L.verify(plan, rows=rows)
                self.assertEqual((r["result"], r["stage"]), ("INVALID", "effect-binding"), r)
                self.assertIn("duplicate-ref: ref X is on more than one allow", r["why"])
        one = [{"decision": "allow", "ref": "X", "effectHash": h1}]
        self.assertEqual(L.verify(one)["result"], "VALID")                                         # the control
        # found by test_generated below, not by the review: a ref on a refusal AND on an allow, with its row
        for plan in ([{"decision": "deny", "ref": "X", "effectHash": None}, one[0]], [one[0], {"decision": "defer", "ref": "X", "effectHash": None}]):
            r = L.verify(plan, rows=[("X", h1, "act")])
            self.assertEqual((r["result"], r["stage"]), ("INVALID", "effect-binding"), r)
            self.assertIn("effect-against-refusal under ref X", r["why"])
        r = L.verify(one, rows=[("X", h1, "act")] * 2)
        self.assertIn("duplicate-ref: ref X is on more than one effect row", r["why"])

    def test_generated(self):
        rng = random.Random(SEED)
        L = _CedulonLedger()
        seen = {"VALID": 0, "duplicate allow": 0, "duplicate row": 0, "other finding": 0}
        for _ in range(400):
            refs = [f"r{rng.randint(0, 5)}" for _ in range(rng.randint(1, 6))]
            if rng.random() < 0.4:
                refs = list(dict.fromkeys(refs))                                 # a ledger without a repeated ref
            plan = [{"decision": rng.choice(["allow", "allow", "allow", "deny"]), "ref": ref,
                     "effectHash": _h(rng.randint(0, 3)), "effectClass": rng.choice(["act", "act", "pay"])} for ref in refs]
            allows = [p for p in plan if p["decision"] == "allow"]
            rows = [(p["ref"], p["effectHash"], p["effectClass"]) for p in allows]
            bend = rng.choice(["none", "none", "shuffle", "repeat", "drop", "last-wins", "other-hash"])
            if bend == "shuffle":
                rng.shuffle(rows)
            elif bend == "repeat" and rows:
                rows.insert(rng.randint(0, len(rows)), rng.choice(rows))
            elif bend == "drop" and rows:
                rows.pop(rng.randrange(len(rows)))
            elif bend == "last-wins":                        # every row carries what the LAST allow under its ref named
                last = {p["ref"]: p for p in allows}
                rows = [(p["ref"], last[p["ref"]]["effectHash"], last[p["ref"]]["effectClass"]) for p in allows]
            elif bend == "other-hash" and rows:
                k = rng.randrange(len(rows))
                rows[k] = (rows[k][0], _h("other"), rows[k][2])
            allow_refs, row_refs = [p["ref"] for p in allows], [r[0] for r in rows]
            refused = {p["ref"] for p in plan if p["decision"] != "allow"}
            if len(set(allow_refs)) != len(allow_refs):                          # the rule, written out here
                want = "duplicate allow"
            elif len(set(row_refs)) != len(row_refs):
                want = "duplicate row"
            elif sorted(rows) == sorted((p["ref"], p["effectHash"], p["effectClass"]) for p in allows) \
                    and not (set(row_refs) & refused):
                want = "VALID"
            else:
                want = "other finding"
            with self.subTest(plan=[(p["decision"], p["ref"], p["effectHash"][:4]) for p in plan], rows=[(a, b[:4], c) for a, b, c in rows]):
                r = L.verify(plan, rows=rows)
                if want == "VALID":
                    self.assertEqual(r["result"], "VALID", r)
                else:
                    self.assertEqual((r["result"], r["stage"]), ("INVALID", "effect-binding"), r)
                    self.assertEqual("duplicate-ref" in r["why"], want.startswith("duplicate"), r)
                    if want == "duplicate allow":
                        self.assertIn("more than one allow", r["why"])
                    elif want == "duplicate row":
                        self.assertIn("more than one effect row", r["why"])
            seen[want] += 1
        for k, n in seen.items():
            self.assertGreater(n, 25, k)


@NEEDS_CRYPTO
class TestCedulonApprovalRelyingParty(unittest.TestCase):
    """Rule 6: the assertion's RP ID and origin are the ones the relying party expects, or not_verified says so."""

    def setUp(self):
        import test_cedulon
        self.TC = test_cedulon
        self.L = test_cedulon.VeraxLedger()

    def _verify(self, rp, origin, rp_member="same", **kw):
        TC, L = self.TC, self.L

        def assertion(sig, ad, cdj, pk):                   # the operator's passkey signs for another relying party
            ad2 = hashlib.sha256(rp.encode()).digest() + ad[32:]
            cdj2 = json.dumps({"type": "webauthn.get", "challenge": "c", "origin": origin}).encode()
            out = {**sig, "authenticatorData": TC._b64u(ad2), "clientDataJSON": TC._b64u(cdj2),
                   "signature": TC._b64u(pk.sign(ad2 + hashlib.sha256(cdj2).digest()))}
            if rp_member == "same":
                out["rpId"] = rp
            elif rp_member == "absent":
                out.pop("rpId")
            else:
                out["rpId"] = rp_member
            return out
        import cryptovalid_cedulon as C
        dec, eff, cps, inp, idx, creds = L.render(bend_assertion=assertion)
        return C.verify_ledger(dec, eff, cps, TC._pem(L.rk), TC._pem(L.xk), TC._pem(L.ck), inputs_text=inp, index_text=idx,
                               operator_credentials=creds, **kw)

    def test_assertion_for_another_relying_party(self):
        r = self._verify("evil.example", "https://evil.example")
        self.assertEqual(r["result"], "VALID", r)          # nothing expected was given: as 0.26.0, and now it says so
        self.assertEqual(r["not_verified"], ["approval-challenge-binding", "approval-rp-id", "approval-origin"])
        r = self._verify("evil.example", "https://evil.example", expected_rp_ids="localhost")
        self.assertEqual((r["result"], r["stage"]), ("INVALID", "approval-signature"), r)
        self.assertEqual(r["not_verified"], ["approval-challenge-binding", "approval-origin"])
        r = self._verify("localhost", "https://evil.example", expected_rp_ids="localhost", expected_origins="http://localhost")
        self.assertEqual((r["result"], r["stage"]), ("INVALID", "approval-signature"), r)
        r = self._verify("localhost", "http://localhost", expected_rp_ids="localhost", expected_origins="http://localhost")
        self.assertEqual(r["result"], "VALID", r)          # the control
        self.assertEqual(r["not_verified"], ["approval-challenge-binding"])

    def test_generated(self):
        rng = random.Random(SEED)
        rps = ["localhost", "evil.example", "example.org", "LOCALHOST", "localhost.", "sub.localhost", ""]
        origins = ["http://localhost", "https://localhost", "http://localhost:4173", "https://evil.example", "http://LOCALHOST", ""]
        counts = {"VALID": 0, "INVALID": 0}
        for _ in range(300):
            rp, origin = rng.choice(rps), rng.choice(origins)
            member = rng.choice(["same", "same", "absent", rng.choice(rps)])
            want_rps = rng.sample([x for x in rps if x], rng.randint(1, 3))
            want_origins = rng.sample([x for x in origins if x], rng.randint(1, 3))
            give_rp, give_origin = rng.random() < 0.8, rng.random() < 0.8
            kw = {}
            if give_rp:
                kw["expected_rp_ids"] = want_rps[0] if len(want_rps) == 1 and rng.random() < 0.5 else want_rps
            if give_origin:
                kw["expected_origins"] = want_origins
            stated = rp if member == "same" else None if member == "absent" else member
            if give_rp:
                ok = rp in want_rps and (stated is None or stated in want_rps)
            else:
                ok = stated == rp                           # the check of 0.26.0: against the assertion's own member
            ok = ok and (not give_origin or origin in want_origins)
            with self.subTest(rp=rp, origin=origin, member=member, kw=kw):
                r = self._verify(rp, origin, member, **kw)
                self.assertEqual(r["result"], "VALID" if ok else "INVALID", r)
                if not ok:
                    self.assertEqual(r["stage"], "approval-signature")
                self.assertEqual("approval-rp-id" in r["not_verified"], not give_rp)
                self.assertEqual("approval-origin" in r["not_verified"], not give_origin)
            counts[r["result"]] += 1
        self.assertGreater(counts["VALID"], 30)
        self.assertGreater(counts["INVALID"], 150)

    def test_an_empty_pin_pins_nothing(self):
        for name in ("expected_rp_ids", "expected_origins"):
            for bad in ("", [], [""], ["localhost", ""], 5, ["localhost", 5], {"localhost"}, b"localhost", True):
                with self.subTest(name=name, bad=bad), self.assertRaises(ValueError):
                    self._verify("localhost", "http://localhost", **{name: bad})


if __name__ == "__main__":
    unittest.main()
