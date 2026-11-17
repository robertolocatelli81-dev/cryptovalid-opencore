#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""cryptovalid_httpdigest (0.26.0, 2026-11-17): Digest (RFC 3230) and Content-Digest / Repr-Digest (RFC 9530).

Positive control from a real document, the Italian ModI guidelines, pattern INTEGRITY_REST_01 (lg-modellointeroperabilita-
docs 9790b6a, `02_integrity_rest.rst` lines 180 and 183, from the file saved on 16/11/2026): `Digest: SHA-256=cFfTOCes…96E=`
is the SHA-256 of `{"testo": "ciao mondo"}` and not of the body shown, `{"testo": "Ciao mondo"}`. The examples of RFC 9530
(its appendix table for `{"hello": "world"}` and the §2 example, the same body with a final line feed) verify. Generated fields: dictionaries serialized here by RFC 9651 §4.1 (code apart from the
parser) and then parsed. The module did not exist in 0.25.1 (this file fails at its import there)."""
import base64
import hashlib
import os
import random
import sys
import unittest

sys.dont_write_bytecode = True
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import cryptovalid_httpdigest as D  # noqa: E402

MODI_DIGEST = "SHA-256=cFfTOCesrWTLVzxn8fmHl4AcrUs40Lv5D275FmAZ96E="
HELLO = b'{"hello": "world"}'
# RFC 9530 Appendix (rfc9530.txt lines 1585-1588): the digests of {"hello": "world"}; §2: the same body with a final LF
SECTION2 = ("sha-512=:YMAam51Jz/jOATT6/zvHrLVgOYTGFy1d6GJiOHTohq4yP+pgk4vf2aCsyRZOtw8MjkM7iw7yZ/WkppmM44T3qg==:")
RFC9530_256 = "sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:"
RFC9530_512 = ("sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:")


def b64(data):
    return base64.b64encode(data).decode()


class Real(unittest.TestCase):
    def test_modi_example(self):
        r = D.check_digest(MODI_DIGEST, b'{"testo": "Ciao mondo"}', "rfc3230")
        self.assertEqual((r["ok"], r["why"], r["algs_checked"]), (False, "mismatch", ["SHA-256"]))
        r = D.check_digest(MODI_DIGEST, b'{"testo": "ciao mondo"}', "rfc3230")
        self.assertEqual((r["ok"], r["why"]), (True, None))

    def test_rfc9530_examples(self):
        for f in (RFC9530_256, RFC9530_512, RFC9530_256 + ", " + RFC9530_512, RFC9530_512 + ",\t" + RFC9530_256):
            self.assertTrue(D.check_digest(f, HELLO, "rfc9530")["ok"], f)
        self.assertEqual(D.check_digest(RFC9530_256, HELLO + b" ", "rfc9530")["why"], "mismatch")
        self.assertTrue(D.check_digest(SECTION2, HELLO + b"\n", "rfc9530")["ok"])
        self.assertEqual(D.check_digest(SECTION2, HELLO, "rfc9530")["why"], "mismatch")

    def test_the_same_digest_in_both_syntaxes(self):
        d = b64(hashlib.sha256(HELLO).digest())
        self.assertTrue(D.check_digest("SHA-256=" + d, HELLO, "rfc3230")["ok"])
        self.assertTrue(D.check_digest("sha-256=:" + d + ":", HELLO, "rfc9530")["ok"])
        self.assertEqual(D.check_digest("sha-256=:" + d + ":", HELLO, "rfc3230")["why"], "grammar")
        self.assertEqual(D.check_digest("SHA-256=" + d, HELLO, "rfc9530")["why"], "grammar")


class Rules(unittest.TestCase):
    def test_unknown_and_deprecated_are_ignored_not_refused(self):
        d = b64(hashlib.sha256(HELLO).digest())
        r = D.check_digest("md5=HUXZLQLMuI/KZ5KDcJPcOA==, SHA-256=" + d + ", UNIXsum=30637, foo=bar", HELLO, "rfc3230")
        self.assertEqual((r["ok"], r["ignored"], r["algs_checked"]), (True, ["md5", "UNIXsum", "foo"], ["SHA-256"]))
        r = D.check_digest("md5=:HUXZLQLMuI/KZ5KDcJPcOA==:, sha=:AAAA:, sha-256=:" + d + ":", HELLO, "rfc9530")
        self.assertEqual((r["ok"], r["ignored"]), (True, ["md5", "sha"]))
        for f, s in (("md5=:HUXZLQLMuI/KZ5KDcJPcOA==:", "rfc9530"), ("sha=AAAA", "rfc3230")):
            r = D.check_digest(f, HELLO, s)
            self.assertEqual((r["ok"], r["why"], len(r["ignored"])), (False, "no_supported_alg", 1))

    def test_every_supported_digest_must_match(self):
        good, bad = b64(hashlib.sha256(HELLO).digest()), b64(hashlib.sha512(b"other").digest())
        self.assertEqual(D.check_digest("sha-256=:" + good + ":, sha-512=:" + bad + ":", HELLO, "rfc9530")["why"], "mismatch")
        self.assertEqual(D.check_digest("SHA-256=" + good + ", sha-256=" + b64(bytes(32)), HELLO, "rfc3230")["why"],
                         "mismatch")                                    # a repeated algorithm is checked too

    def test_base64_and_lengths(self):
        d = b64(hashlib.sha256(HELLO).digest())                        # 44 characters, one "="
        self.assertEqual(D.check_digest("SHA-256=" + d.rstrip("="), HELLO, "rfc3230")["why"], "grammar")
        r = D.check_digest("sha-256=:" + d.rstrip("=") + ":", HELLO, "rfc9530")
        self.assertEqual((r["ok"], r["noncanonical"]), (True, ["sha-256"]))   # RFC 9651 §4.2.7: SHOULD NOT fail
        pad = d[:-2] + chr(ord(d[-2]) + 1) + "="                           # non-zero pad bits
        r = D.check_digest("sha-256=:" + pad + ":", HELLO, "rfc9530")
        self.assertEqual((r["ok"], r["noncanonical"]), (True, ["sha-256"]))
        self.assertEqual(D.check_digest("SHA-256=" + pad, HELLO, "rfc3230")["why"], "grammar")
        for f, s in (("SHA-256=" + b64(bytes(31)), "rfc3230"), ("sha-512=:" + d + ":", "rfc9530")):
            self.assertEqual(D.check_digest(f, HELLO, s)["why"], "digest_length", f)

    def test_dictionary_rules(self):
        d = b64(hashlib.sha256(HELLO).digest())
        r = D.check_digest("sha-256=:" + b64(bytes(32)) + ":, sha-256=:" + d + ":", HELLO, "rfc9530")
        self.assertEqual((r["ok"], r["duplicate_keys"]), (True, ["sha-256"]))   # RFC 9651 §4.2.2: the last value
        r = D.check_digest("sha-256=:" + d + ":;q=1;x", HELLO, "rfc9530")
        self.assertEqual((r["ok"], r["parameters"]), (True, {"sha-256": ["q", "x"]}))
        for f in ("sha-256=" + d, 'sha-256="' + d + '"', "sha-256", "sha-256=(:" + d + ":)", "SHA-256=:" + d + ":",
                  "sha-256=:" + d + ":,", "sha-256=:" + d + ": sha-512=:x:", "sha-256=:" + d, "sha-256=:" + d + "!:",
                  "", " "):
            self.assertEqual(D.check_digest(f, HELLO, "rfc9530")["why"], "grammar" if f.strip() else "no_supported_alg", f)

    def test_tokens_keys_and_byte_characters(self):
        d = b64(hashlib.sha256(HELLO).digest())
        for f in ("SHA@256=" + d, "SHA 256=" + d, "=" + d, "SHA-256=", "SHA-256=" + d + ",,md5=x"):
            self.assertEqual(D.check_digest(f, HELLO, "rfc3230")["why"], "grammar", f)
        for f in ("Sha-256=:" + d + ":", "sha-256=:" + d[:10] + "!" + d[11:] + ":", "sha-256=:" + d[:10] + "-" + d[11:] + ":"):
            self.assertEqual(D.check_digest(f, HELLO, "rfc9530")["why"], "grammar", f)

    def test_arguments(self):
        self.assertEqual(D.check_digest(b"SHA-256=x", HELLO, "rfc3230")["why"], "not_text")
        for s in (None, "", "RFC9530", "content-digest"):
            with self.assertRaises(ValueError):
                D.check_digest(MODI_DIGEST, HELLO, s)


def _ser_bare(rnd, kind, data):
    if kind == "bytes":
        return ":" + b64(data) + ":"
    return rnd.choice(["42", "-7", "3.14", '"a \\"q\\""', "tok/en", "?1", "?0", "@1700000000", '%"caf%c3%a9"'])


class Generated(unittest.TestCase):
    def test_serialized_dictionaries(self):
        rnd = random.Random(20261117)
        body = os.urandom(64)
        algs = ["sha-256", "sha-512", "md5", "sha", "x-new", "*k", "a.b_c-d"]
        seen = {}
        for _ in range(3000):
            members, expect = [], {}
            for _ in range(rnd.randint(1, 4)):
                k = rnd.choice(algs)
                kind = "bytes" if rnd.random() < 0.85 else "other"
                if k in D.SUPPORTED and kind == "bytes":
                    name = D.SUPPORTED[k][0]
                    data = hashlib.new(name, body if rnd.random() < 0.8 else b"x").digest()
                    if rnd.random() < 0.1:
                        data = data[:-1]
                else:
                    data = os.urandom(rnd.randint(0, 20))
                params = "".join(";" + rnd.choice(["q=1", "x", "y=?0"]) for _ in range(rnd.randint(0, 1)))
                members.append(k + "=" + _ser_bare(rnd, kind, data) + params)
                expect[k] = (kind, data)                               # the last value of a key counts
            field = rnd.choice([", ", ",", ",\t", " ,  "]).join(members)
            r = D.check_digest(field, body, "rfc9530")
            if any(kind != "bytes" for kind, _ in expect.values()):
                want = "grammar"
            else:
                sup = [(k, d) for k, (_, d) in expect.items() if k in D.SUPPORTED]
                want = None
                if not sup:
                    want = "no_supported_alg"
                for k, d in sup:
                    name, size = D.SUPPORTED[k]
                    if len(d) != size:
                        want = "digest_length"
                        break
                    if hashlib.new(name, body).digest() != d:
                        want = "mismatch"
                        break
            self.assertEqual(r["why"], want, field)
            seen[want] = seen.get(want, 0) + 1
        for code in (None, "grammar", "digest_length", "mismatch", "no_supported_alg"):
            self.assertGreaterEqual(seen.get(code, 0), 30, seen)

    def test_mutated_fields_never_raise(self):
        rnd = random.Random(7)
        base = [MODI_DIGEST, RFC9530_256 + ", " + RFC9530_512]
        alphabet = list(":=,;\"()?@% \t-_.*/+aAz09") + ["é", "\x00", "\n"]
        for _ in range(3000):
            s = list(rnd.choice(base))
            for _ in range(rnd.randint(1, 4)):
                op = rnd.randrange(3)
                pos = rnd.randrange(len(s) + 1)
                if op == 0:
                    s.insert(pos, rnd.choice(alphabet))
                elif s:
                    if op == 1:
                        del s[min(pos, len(s) - 1)]
                    else:
                        s[min(pos, len(s) - 1)] = rnd.choice(alphabet)
            for syntax in D.SYNTAXES:
                r = D.check_digest("".join(s), HELLO, syntax)
                self.assertIn(r["why"], (None,) + D.CODES)


if __name__ == "__main__":
    unittest.main()
