#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Roberto Locatelli
"""SPEC v0.13 §21: the rules written after the re-measurement of 2026-11-20 (findings of the review of 0.26.0, each
re-run on 0.26.0 and on the released 0.27.0 before the change). Generative where the class asks for it; the rule each
test holds is in its name. Positive control: every test below fails on 0.27.0 (ec56b3c) except the controls named
`*_control`, which hold what did not change and pass there too."""
import ast
import base64
import glob
import hashlib
import io
import json
import os
import random
import sys
import tempfile
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
import cryptovalid_merkle as M  # noqa: E402
import cryptovalid_net as N  # noqa: E402
import verifier  # noqa: E402

try:   # the `sign` extra; without it the cases that need it are skipped with this reason, never an error
    import cryptography  # noqa: F401
    HAVE_CRYPTO = True
except ImportError:
    HAVE_CRYPTO = False
if os.environ.get("CV_REQUIRE_CRYPTO") == "1" and not HAVE_CRYPTO:
    raise SystemExit("CV_REQUIRE_CRYPTO=1 but `cryptography` is missing: the cases that need it would be skipped")
NEEDS_CRYPTO = unittest.skipUnless(HAVE_CRYPTO, "needs `cryptography` (the `sign` extra)")
SEED = 20261120


def _ledger(path, n=3, tag="e"):
    prev = "0" * 64
    with open(path, "w") as f:
        for i in range(n):
            e = {"idx": i, "ts": "2026-11-20T10:%02d:00Z" % i, "data": {"event": "%s%d" % (tag, i)}, "prev_hash": prev}
            e["self_hash"] = hashlib.sha256(json.dumps(e, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
            prev = e["self_hash"]
            f.write(json.dumps(e) + "\n")


class Rule1MerkleInclusion(unittest.TestCase):
    """RFC 9162 §2.1.3.2 step 4a: "If sn is 0, then stop the iteration and fail the proof verification"."""

    def test_every_proof_against_an_exact_oracle_control(self):
        # oracle, the root always of n leaves: in a tree of n leaves, the one proof that verifies leaf m against the root is inclusion_proof(m, leaves)
        rnd = random.Random(SEED)
        checked = accepted = 0
        trees = {n: [b"leaf %d of %d" % (i, n) for i in range(n)] for n in range(1, 41)}
        roots = {n: M.mth(lv) for n, lv in trees.items()}
        for n, lv in trees.items():
            for m in range(n):
                true = M.inclusion_proof(m, lv)
                cands = [true, true + [rnd.randbytes(32)], true + [roots[n]], true[:-1], true[1:]]
                for n2, lv2 in trees.items():   # the proof of another tree, given with this (m, n)
                    for m2 in rnd.sample(range(n2), min(n2, 2)):
                        cands.append(M.inclusion_proof(m2, lv2))
                for pr in cands:
                    for root in (roots[n], rnd.choice(list(roots.values()))):
                        for leaf in (lv[m], lv[rnd.randrange(n)]):
                            want = pr == true and root == roots[n] and leaf == lv[m]
                            got = M.verify_inclusion(m, n, leaf, pr, root)
                            checked += 1
                            accepted += got
                            self.assertEqual(got, want, (m, n, len(pr), len(true)))
        self.assertGreater(checked, 30000)
        self.assertGreater(accepted, 800)   # the control: the true proofs verify

    def test_a_proof_longer_than_the_path_of_m_n_never_verifies(self):
        # the leaf, the proof and the root of a tree of N leaves (N <= 33), given with every (m, n), n <= N, whose path is
        # SHORTER than the proof: step 4a fails each one (0.27.0 accepted 1,416 of these 81,927). The other pairs are
        # outside what the algorithm can tell: a root says nothing of its tree size, which a signed head binds to it
        lv = [b"leaf %d" % i for i in range(33)]
        plen, longer, accepted = {}, 0, 0
        for N in range(1, 34):
            root = M.mth(lv[:N])
            for Mi in range(N):
                pr = M.inclusion_proof(Mi, lv[:N])
                for n in range(1, N + 1):
                    for m in range(n):
                        if (m, n) not in plen:
                            plen[(m, n)] = len(M.inclusion_proof(m, lv[:n]))
                        if len(pr) > plen[(m, n)]:
                            longer += 1
                            accepted += M.verify_inclusion(m, n, lv[Mi], pr, root)
        self.assertEqual((longer, accepted), (81927, 0))

    def test_the_measured_case(self):
        leaves = [b"leaf%d" % i for i in range(8)]
        proof = M.inclusion_proof(5, leaves)
        self.assertTrue(M.verify_inclusion(5, 8, leaves[5], proof, M.mth(leaves)))           # control
        self.assertFalse(M.verify_inclusion(1, 4, leaves[5], proof, M.mth(leaves)))          # 0.27.0: True

    def test_index_and_size_are_non_negative_integers(self):
        lv = [b"a", b"b", b"c"]
        root, pr = M.mth(lv), M.inclusion_proof(1, lv)
        for m, n in ((-2, 3), (1.0, 3), (1, 3.0), (True, 3), (1, "3"), (3, 3), (0, 0)):
            self.assertFalse(M.verify_inclusion(m, n, lv[1], pr, root), (m, n))
        self.assertTrue(M.verify_inclusion(0, 1, b"a", [], M.mth([b"a"])))           # control
        self.assertFalse(M.verify_inclusion(1, 1, b"a", [], M.mth([b"a"])))          # an index past the last leaf


def _dup_variants(line_obj, rnd):
    """(text with one key written twice, path) for a key at the top level and inside `data`, first or last value kept"""
    out = []
    for where in ("top", "data"):
        obj = line_obj if where == "top" else line_obj["data"]
        keys = list(obj)
        k = rnd.choice(keys)
        other = json.dumps({"x": rnd.randrange(10 ** 6)})
        body = ", ".join("%s: %s" % (json.dumps(kk), json.dumps(vv)) for kk, vv in obj.items())
        dup = "%s: %s" % (json.dumps(k), other)
        text_obj = "{" + (dup + ", " + body if rnd.random() < 0.5 else body + ", " + dup) + "}"
        if where == "top":
            out.append(text_obj)
        else:
            top = dict(line_obj)
            top["data"] = "@@DATA@@"
            out.append(json.dumps(top).replace('"@@DATA@@"', text_obj))
    return out


@NEEDS_CRYPTO
class Rule2DuplicateKeys(unittest.TestCase):
    """SPEC §3: "duplicate object keys — a strict parser MUST reject them"; RFC 7515 §10.12 for the JOSE header."""

    def setUp(self):
        import signer
        self.signer = signer
        self.d = tempfile.mkdtemp()
        led = os.path.join(self.d, "l.jsonl")
        _ledger(led, 4)
        self.key = os.path.join(self.d, "k.key")
        self.pub = signer.keygen(self.key)["public_key_hex"]
        self.signed = os.path.join(self.d, "s.jsonl")
        signer.sign_ledger(led, self.signed, self.key)
        self.lines = open(self.signed).read().splitlines()

    def test_signed_ledger_control(self):
        self.assertTrue(self.signer.verify_file(self.signed, self.pub)["ok"])

    def test_signer_refuses_a_key_twice_at_every_entry_and_depth(self):
        rnd = random.Random(SEED)
        n = 0
        for i, ln in enumerate(self.lines):
            for text in _dup_variants(json.loads(ln), rnd):
                p = os.path.join(self.d, "dup%d.jsonl" % n)
                with open(p, "w") as f:
                    f.write("\n".join(self.lines[:i] + [text] + self.lines[i + 1:]) + "\n")
                r = self.signer.verify_file(p, self.pub)
                self.assertFalse(r["ok"], text)
                self.assertIn({"idx": i, "reason": "duplicate_key"}, r["failures"], r["failures"])
                self.assertEqual(verifier.verify_ledger(p)["verdict"], "FAIL")   # the two readers agree
                n += 1
        self.assertEqual(n, 2 * len(self.lines))

    def _jws(self, header_text, payload_bytes):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        sk = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(open(self.key).read().strip()))
        b = lambda x: base64.urlsafe_b64encode(x).rstrip(b"=").decode()  # noqa: E731
        h, p = b(header_text.encode()), b(payload_bytes)
        return "%s.%s.%s" % (h, p, b(sk.sign(("%s.%s" % (h, p)).encode())))

    def test_jws_refuses_a_key_twice_in_header_or_payload(self):
        import cryptovalid_jws as J
        rnd = random.Random(SEED)
        rec = json.loads(self.lines[0])
        rec = {k: v for k, v in rec.items() if k not in ("signature", "signer")}
        head = {"alg": "EdDSA", "kid": self.pub}
        ok = J.verify(self._jws(json.dumps(head), json.dumps(rec).encode()), self.pub)
        self.assertTrue(ok["ok"], ok)                                                     # control
        for _ in range(40):
            for text in _dup_variants(rec, rnd):
                r = J.verify(self._jws(json.dumps(head), text.encode()), self.pub)
                self.assertFalse(r["ok"], text)
                self.assertTrue(r["why"].startswith("payload_duplicate_key: "), r)
                self.assertTrue(r["signature_valid"])
            k = rnd.choice(["alg", "kid"])
            v = json.dumps(head[k]) if rnd.random() < 0.5 else json.dumps("other")
            body = json.dumps(head)[1:-1]
            text = "{" + (body + ', "%s": %s' % (k, v)) + "}"
            r = J.verify(self._jws(text, json.dumps(rec).encode()), self.pub)
            self.assertFalse(r["ok"], text)
            self.assertTrue(r["why"].startswith("header_duplicate_key: "), r)


class Rule3XmlDoctype(unittest.TestCase):
    """A document type declaration is refused by the XML parser, wherever it stands and in whatever encoding."""

    def setUp(self):
        import fundcert_canonical as F
        self.F = F
        self.saved = {k: sys.modules.get(k) for k in ("defusedxml", "defusedxml.ElementTree")}
        sys.modules["defusedxml"] = None              # the stdlib branch (defusedxml absent)
        sys.modules["defusedxml.ElementTree"] = None

    def tearDown(self):
        for k, v in self.saved.items():
            if v is None:
                sys.modules.pop(k, None)
            else:
                sys.modules[k] = v

    def test_doctype_anywhere_in_the_prolog_any_encoding(self):
        rnd = random.Random(SEED)
        n = 0
        for _ in range(300):
            pad = rnd.choice(["", "<!--%s-->" % ("x" * rnd.randrange(0, 12000)), "<?pi %s?>" % ("y" * rnd.randrange(0, 12000)),
                              "\n" * rnd.randrange(0, 5000)])
            ent = rnd.choice(['<!DOCTYPE r [<!ENTITY a "EXPANDED">]>', "<!DOCTYPE r>", '<!DOCTYPE r SYSTEM "x.dtd">'])
            enc = rnd.choice(["utf-8", "utf-16", "utf-16-le", "utf-16-be", "str"])
            decl = '<?xml version="1.0"%s?>' % ("" if enc in ("utf-8", "str") else ' encoding="%s"' % enc.upper()[:6])
            doc = decl + pad + ent + "<r>%s</r>" % ("&a;" if "ENTITY" in ent else "t")
            data = doc if enc == "str" else doc.encode(enc)
            with self.assertRaises(ValueError, msg=(enc, len(pad), ent)) as cm:
                self.F._safe_fromstring(data)
            self.assertIn("DOCTYPE/ENTITY refused", str(cm.exception))
            n += 1
        self.assertEqual(n, 300)

    def test_documents_without_doctype_parse_as_before_control(self):
        import xml.etree.ElementTree as ET
        rnd = random.Random(SEED)
        for _ in range(100):
            pad = "<!--%s-->" % ("z" * rnd.randrange(0, 6000))
            doc = '<?xml version="1.0"?>' + pad + '<r a="1"><c>%d</c></r>' % rnd.randrange(10 ** 9)
            for data in (doc, doc.encode("utf-8")):
                self.assertEqual(ET.tostring(self.F._safe_fromstring(data)), ET.tostring(ET.fromstring(data)))
        with self.assertRaises(ET.ParseError):        # not well-formed: the ParseError of ElementTree, as before
            self.F._safe_fromstring(b"<r><c></r>")


@NEEDS_CRYPTO
class Rule4Vaara(unittest.TestCase):
    """ES256 is P-256 (RFC 7518 §3.1); an evidence record given to a receipt that binds none is not bound."""

    def make(self, sk, ref=False):
        import cryptovalid_vaara_receipt as V
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
        dd = {"decision": "allow"}
        if ref:
            dd["evidenceRef"] = {"canonicalization": "JCS", "digest": V.sha256_jcs({"e": 1})}
        r = {"version": 1, "alg": "ES256", "backLink": {"attestationDigest": "sha256:" + "0" * 64}, "decisionDerived": dd,
             "issuerAsserted": {"nonce": "n"}}
        rr, ss = decode_dss_signature(sk.sign(V.signed_payload(r), ec.ECDSA(hashes.SHA256())))
        r["signature"] = (rr.to_bytes(32, "big") + ss.to_bytes(32, "big")).hex() if max(rr, ss) < 2 ** 256 else "00" * 64
        return r

    def pem(self, sk):
        from cryptography.hazmat.primitives import serialization as ser
        return sk.public_key().public_bytes(ser.Encoding.PEM, ser.PublicFormat.SubjectPublicKeyInfo)

    def test_es256_only_on_p256_every_curve(self):
        import cryptovalid_vaara_receipt as V
        from cryptography.hazmat.primitives.asymmetric import ec
        curves = [c for c in (ec.SECP192R1, ec.SECP224R1, ec.SECP256R1, ec.SECP256K1, ec.SECP384R1, ec.SECP521R1,
                              ec.BrainpoolP256R1, ec.BrainpoolP384R1)]
        seen = 0
        for C in curves:
            try:
                sk = ec.generate_private_key(C())
            except Exception:  # noqa: BLE001 - a curve this backend lacks
                continue
            seen += 1
            out = V.verify_receipt(self.make(sk), self.pem(sk), alg="ES256")
            if C is ec.SECP256R1:
                self.assertTrue(out["ok"], out)                                         # control
            else:
                self.assertFalse(out["ok"], C.name)
                self.assertIn("ES256 needs a P-256 key", out["why"], out)
        self.assertGreaterEqual(seen, 6)

    def test_evidence_binding_matrix(self):
        import cryptovalid_vaara_receipt as V
        from cryptography.hazmat.primitives.asymmetric import ec
        sk = ec.generate_private_key(ec.SECP256R1())
        for ref in (False, True):
            r = self.make(sk, ref)
            for ev, want_ok, want_ev in ((None, True, None), ({"e": 1}, ref, ref), ({"e": 2}, False, False)):
                out = V.verify_receipt(r, self.pem(sk), alg="ES256", evidence=ev)
                self.assertEqual((out["ok"], out["evidence_ok"]), (want_ok, want_ev), (ref, ev, out))


class Rule5McpArgumentTypes(unittest.TestCase):
    """An MCP argument is of the JSON type its tool's input schema declares; refused before the tool runs."""

    VALUES = {"string": ["", "x", "ledger"], "boolean": [True, False], "object": [{}, {"a": 1}],
              "array": [[], ["a"], ["a", "b"]], "number": [0, 1.5, -3], "null": [None]}

    def test_every_tool_every_property_every_type(self):
        import cryptovalid_mcp as MCP
        ran = []
        saved = {n: t["fn"] for n, t in MCP._TOOLS.items()}
        try:
            for n in MCP._TOOLS:
                MCP._TOOLS[n]["fn"] = lambda a, n=n: (ran.append(n), {"result": "stub"})[1]
            checked = 0
            for name, tool in MCP._TOOLS.items():
                props = tool["schema"]["properties"]
                for prop, sch in props.items():
                    for typ, vals in self.VALUES.items():
                        for v in vals + ([[1], [None], [["a"]]] if typ == "array" else []):
                            args = {k: ("x" if s.get("type") == "string" else {} if s.get("type") == "object" else
                                        ["a"] if s.get("type") == "array" else False) for k, s in props.items()}
                            args[prop] = v
                            ok_type = sch["type"] == typ and (typ != "array" or all(isinstance(x, str) for x in v))
                            del ran[:]
                            r = MCP.handle({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                                            "params": {"name": name, "arguments": args}})
                            if ok_type:
                                self.assertIn("result", r, (name, prop, v, r))
                            else:
                                self.assertEqual(r["error"]["code"], -32602, (name, prop, v, r))
                                self.assertIn(repr(prop), r["error"]["message"])
                                self.assertEqual(ran, [], (name, prop, v))
                            checked += 1
            self.assertEqual(checked, 221)   # 6 tools, 13 properties, 17 values each (14 of six types, 3 more arrays)
        finally:
            for n, fn in saved.items():
                MCP._TOOLS[n]["fn"] = fn

    def test_verify_ledger_description_does_not_claim_signatures(self):
        import cryptovalid_mcp as MCP
        d = MCP._TOOLS["verify_ledger"]["description"]
        self.assertIn("Signatures are NOT checked", d)
        self.assertNotIn("and its Ed25519 signatures", d)


class _Endless:
    def __init__(self, size, rnd):
        self.left, self.rnd, self.asked, self.given = size, rnd, [], 0

    def read(self, n=-1):
        self.asked.append(n)
        if n is None or n < 0:
            raise AssertionError("read() without a bound")
        if n == 0:                       # as http.client.HTTPResponse.read(0)
            return b""
        k = min(n, self.left, self.rnd.randrange(1, n + 1))
        self.left -= k
        self.given += k
        return b"a" * k


class Rule6NetworkBodies(unittest.TestCase):
    def test_read_body_against_its_bound(self):
        rnd = random.Random(SEED)
        for _ in range(400):
            limit = rnd.choice([0, 1, 7, 1000, 1 << 20, (1 << 20) + 3])
            size = max(0, limit + rnd.randrange(-5, 6))
            r = _Endless(size, rnd)
            if size <= limit:
                self.assertEqual(len(N.read_body(r, limit)), size)
            else:
                with self.assertRaises(ValueError):
                    N.read_body(r, limit)
            self.assertLessEqual(r.given, limit + 1)   # never more than one byte past the bound is read

    def test_no_module_reads_a_response_without_read_body(self):
        # every name bound by `with _net.open_url(...) as X:` (and an HTTPError `e` read in _http_error_text) is read
        # only through cryptovalid_net.read_body: no X.read() without a size, no json.load(X)
        bad = []
        for path in sorted(glob.glob(os.path.join(_HERE, "*.py"))):
            if os.path.basename(path).startswith("test_") or os.path.basename(path) == "cryptovalid_net.py":
                continue
            tree = ast.parse(open(path, encoding="utf-8").read())
            for node in ast.walk(tree):
                if not isinstance(node, ast.With):
                    continue
                for item in node.items:
                    call = item.context_expr
                    if not (isinstance(call, ast.Call) and isinstance(call.func, ast.Attribute)
                            and call.func.attr == "open_url" and isinstance(item.optional_vars, ast.Name)):
                        continue
                    var = item.optional_vars.id
                    for sub in ast.walk(node):
                        if isinstance(sub, ast.Call):
                            f = sub.func
                            if isinstance(f, ast.Attribute) and f.attr == "read" and isinstance(f.value, ast.Name) \
                                    and f.value.id == var and not sub.args:
                                bad.append("%s:%d %s.read()" % (os.path.basename(path), sub.lineno, var))
                            if isinstance(f, ast.Attribute) and f.attr == "load" and isinstance(f.value, ast.Name) \
                                    and f.value.id == "json" and sub.args and isinstance(sub.args[0], ast.Name) \
                                    and sub.args[0].id == var:
                                bad.append("%s:%d json.load(%s)" % (os.path.basename(path), sub.lineno, var))
        self.assertEqual(bad, [])

    def test_the_trusted_list_reader_is_bounded(self):
        import cryptovalid_lotl as L
        rnd = random.Random(SEED)
        saved = L._net.open_url

        class Ctx(_Endless):
            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False
        try:
            L._net.open_url = lambda *a, **k: Ctx(N.MAX_RESPONSE_BYTES + 10, rnd)
            with self.assertRaises(ValueError):
                L._get("https://example.org/tl.xml")
            L._net.open_url = lambda *a, **k: Ctx(5367120, rnd)   # the largest list measured on 2026-11-20
            self.assertEqual(len(L._get("https://example.org/tl.xml")), 5367120)
        finally:
            L._net.open_url = saved


def _write(path, data):
    with open(path, "wb") as f:
        f.write(data)


class Rule7PackReadsALedgerOnce(unittest.TestCase):
    """The digest, the chain, the signatures, the count and the head of a ledger are checked on the same bytes."""

    def build(self, d, broken):
        import evidence_pack as E
        led = os.path.join(d, "l.jsonl")
        _ledger(led, 3)
        with open(led, "rb") as f:
            good = f.read()
        ls = good.splitlines(keepends=True)
        bad = ls[0] + ls[1].replace(b'"e1"', b'"XX"') + ls[2]   # same length, entry 1 changed, self_hash not
        _write(led, bad if broken else good)
        pack = os.path.join(d, "pack")
        E.build_pack([led], pack)
        return pack, os.path.join(pack, "l.jsonl"), good, bad

    def test_a_file_exchanged_between_the_reads_changes_nothing(self):
        import evidence_pack as E
        import signer
        reads = [("verifier", "verify_ledger"), ("signer", "verify_file"), ("E", "_entries_and_head"),
                 ("E", "_has_signature_field")]
        for broken in (True, False):
            for mod_name, fn_name in reads:
                d = tempfile.mkdtemp()
                pack, lp, good, bad = self.build(d, broken)
                committed, other = (bad, good) if broken else (good, bad)
                want = E.verify_pack(pack)["valid"]
                self.assertEqual(want, not broken)                                       # control
                mod = {"verifier": E.verifier, "signer": signer, "E": E}[mod_name]
                real = getattr(mod, fn_name)

                def swapped(*a, _real=real, **k):
                    _write(lp, other)                 # another file at the path while this read happens
                    try:
                        return _real(*a, **k)
                    finally:
                        _write(lp, committed)
                setattr(mod, fn_name, swapped)
                try:
                    got = E.verify_pack(pack)
                finally:
                    setattr(mod, fn_name, real)
                self.assertEqual(got["valid"], want, (broken, fn_name, got["ledgers"]))

    @NEEDS_CRYPTO
    def test_a_signed_ledger_exchanged_at_every_read(self):
        # committed: a signed ledger of 3 entries; at the path while one reader runs: the same with a signature broken and
        # the last entry gone. Every reader of the path (0.27.0: five) must not change the verdict
        import evidence_pack as E
        import signer
        d = tempfile.mkdtemp()
        led, key = os.path.join(d, "u.jsonl"), os.path.join(d, "k.key")
        _ledger(led, 3)
        signer.keygen(key)
        sl = os.path.join(d, "l.jsonl")
        signer.sign_ledger(led, sl, key)
        pack = os.path.join(d, "pack")
        E.build_pack([sl], pack)
        lp = os.path.join(pack, "l.jsonl")
        with open(lp, "rb") as f:
            committed = f.read()
        ls = [json.loads(x) for x in committed.splitlines()]
        sig = bytearray(base64.b64decode(ls[0]["signature"]))
        sig[0] ^= 1
        ls[0]["signature"] = base64.b64encode(bytes(sig)).decode()
        other = "".join(json.dumps(x) + "\n" for x in ls[:2]).encode()
        self.assertTrue(E.verify_pack(pack)["valid"])                                    # control
        for mod, fn in ((E.verifier, "verify_ledger"), (E.verifier, "_verify_ledger_data"), (signer, "verify_file"),
                        (signer, "verify_ledger_signatures"), (E, "_entries_and_head"), (E, "_entries_and_head_data"),
                        (E, "_has_signature_field"), (E, "_has_signature_field_data")):
            if not hasattr(mod, fn):
                continue
            real = getattr(mod, fn)

            def swapped(*a, _real=real, **k):
                _write(lp, other)
                try:
                    return _real(*a, **k)
                finally:
                    _write(lp, committed)
            setattr(mod, fn, swapped)
            try:
                got = E.verify_pack(pack)
            finally:
                setattr(mod, fn, real)
            self.assertTrue(got["valid"], (fn, got["ledgers"]))

    def test_the_digest_is_taken_from_the_bytes_checked(self):
        # another file at the path from just after the first read to the end: the digest and the checks see one file
        import evidence_pack as E
        for broken in (True, False):
            d = tempfile.mkdtemp()
            pack, lp, good, bad = self.build(d, broken)
            committed, other = (bad, good) if broken else (good, bad)
            want = E.verify_pack(pack)["valid"]
            V = E.verifier                 # the first read of the ledger, whole: its digest (0.27.0) or its bytes (now)
            saved = {n: getattr(V, n) for n in ("read_regular", "sha256_regular")}
            done = []

            def first_then_swap(*a, _n=None, **k):
                r = saved[_n](*a, **k)
                if not done and a and os.path.basename(str(a[0])) == "l.jsonl":
                    done.append(1)
                    _write(lp, other)
                return r
            for n in saved:
                setattr(V, n, lambda *a, _n=n, **k: first_then_swap(*a, _n=_n, **k))
            try:
                got = E.verify_pack(pack)
            finally:
                for n, f in saved.items():
                    setattr(V, n, f)
                _write(lp, committed)
            self.assertEqual(done, [1])
            self.assertEqual(got["valid"], want, (broken, got["ledgers"]))
            self.assertEqual(got["file_ok"]["l.jsonl"], True)

    def test_a_ledger_not_in_the_digests_is_still_checked_control(self):
        import evidence_pack as E
        d = tempfile.mkdtemp()
        pack, _lp, _g, _b = self.build(d, False)
        mp = os.path.join(pack, "MANIFEST.json")
        with open(mp) as f:
            man = json.load(f)
        man["file_digests_sha256"] = {}
        body = {k: v for k, v in man.items() if k not in ("manifest_digest_sha256", "rfc3161_timestamp",
                                                         "manifest_signature", "manifest_signer")}
        man["manifest_digest_sha256"] = hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        with open(mp, "w") as f:
            json.dump(man, f)
        r = E.verify_pack(pack)
        self.assertFalse(r["valid"])                                   # no file listed: digest_mismatch, as before
        self.assertEqual((r["ledgers"][0]["hash_pass"], r["ledgers"][0]["untruncated"]), (True, True), r["ledgers"])


@NEEDS_CRYPTO
class Rule8SignerSignsEntriesOnly(unittest.TestCase):
    """signer.sign_ledger signs the self_hash of an entry it recomputed, never a hash as written."""

    def setUp(self):
        import signer
        self.signer = signer
        self.d = tempfile.mkdtemp()
        self.key = os.path.join(self.d, "k.key")
        self.pub = signer.keygen(self.key)["public_key_hex"]

    def test_a_tree_head_hash_is_not_signed(self):
        import cryptovalid_ingest as I
        arc = os.path.join(self.d, "arc")
        w = I.Ingestor(arc, batch_size=1)
        w.append({"x": 1})
        w.seal()
        w.close(seal=False)
        with open(glob.glob(os.path.join(arc, "*.sth.json"))[0]) as f:
            h = I._sth_canonical_hash(json.load(f))
        led = os.path.join(self.d, "forged.jsonl")
        with open(led, "w") as f:
            f.write(json.dumps({"idx": 0, "ts": "2026-11-20T00:00:00Z", "data": {}, "prev_hash": "0" * 64, "self_hash": h}) + "\n")
        with self.assertRaises(ValueError) as cm:
            self.signer.sign_ledger(led, os.path.join(self.d, "out.jsonl"), self.key)
        self.assertIn("is not the hash of its content", str(cm.exception))

    def test_generated_lines(self):
        rnd = random.Random(SEED)
        for i in range(120):
            led = os.path.join(self.d, "g%d.jsonl" % i)
            _ledger(led, rnd.randrange(1, 5), tag="t%d-" % i)
            with open(led) as f:
                lines = f.read().splitlines()
            j = rnd.randrange(len(lines))
            e = json.loads(lines[j])
            kind = i % 4
            if kind == 0:     # a valid ledger: signed, and its signatures verify (control)
                out = os.path.join(self.d, "o%d.jsonl" % i)
                self.assertEqual(self.signer.sign_ledger(led, out, self.key)["signed"], len(lines))
                self.assertTrue(self.signer.verify_file(out, self.pub)["ok"])
                continue
            if kind == 1:     # a self_hash that is not the hash of the content
                e["self_hash"] = hashlib.sha256(rnd.randbytes(16)).hexdigest()
                lines[j] = json.dumps(e)
                want = "is not the hash of its content"
            elif kind == 2:   # a member outside the entry schema, the self_hash recomputed with it
                e.pop("self_hash")
                e[rnd.choice(["root_sha256", "tree_size", "segments_sealed", "zz"])] = rnd.randrange(100)
                e["self_hash"] = hashlib.sha256(json.dumps(e, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
                lines[j] = json.dumps(e)
                want = "outside the entry schema"
            else:             # a key written twice, or a line that is not an object
                lines[j] = rnd.choice(['{"idx": 0, "idx": 0}', "[1]", "7"])
                want = "not a JSON object with distinct keys"
            with open(led, "w") as f:
                f.write("\n".join(lines) + "\n")
            out = os.path.join(self.d, "o%d.jsonl" % i)
            with self.assertRaises(ValueError) as cm:
                self.signer.sign_ledger(led, out, self.key)
            self.assertIn(want, str(cm.exception))
            self.assertFalse(os.path.exists(out))


if __name__ == "__main__":
    unittest.main()
