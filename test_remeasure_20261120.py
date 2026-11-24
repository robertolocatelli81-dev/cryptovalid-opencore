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
    with open(path, "w", encoding="utf-8", newline="") as f:
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
        self.lines = open(self.signed, encoding="utf-8").read().splitlines()

    def test_signed_ledger_control(self):
        self.assertTrue(self.signer.verify_file(self.signed, self.pub)["ok"])

    def test_signer_refuses_a_key_twice_at_every_entry_and_depth(self):
        rnd = random.Random(SEED)
        n = 0
        for i, ln in enumerate(self.lines):
            for text in _dup_variants(json.loads(ln), rnd):
                p = os.path.join(self.d, "dup%d.jsonl" % n)
                with open(p, "w", encoding="utf-8", newline="") as f:
                    f.write("\n".join(self.lines[:i] + [text] + self.lines[i + 1:]) + "\n")
                r = self.signer.verify_file(p, self.pub)
                self.assertFalse(r["ok"], text)
                self.assertIn({"idx": i, "reason": "duplicate_key"}, r["failures"], r["failures"])
                self.assertEqual(verifier.verify_ledger(p)["verdict"], "FAIL")   # the two readers agree
                n += 1
        self.assertEqual(n, 2 * len(self.lines))

    def _jws(self, header_text, payload_bytes):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        sk = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(open(self.key, encoding="utf-8").read().strip()))
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
            # 6 tools, 14 properties (13 until SPEC §22 rule 5 gave verify_ledger expected_pubkey_hex), 17 values each
            self.assertEqual(checked, 238)
        finally:
            for n, fn in saved.items():
                MCP._TOOLS[n]["fn"] = fn

    def test_verify_ledger_description_does_not_claim_signatures(self):
        import cryptovalid_mcp as MCP
        d = MCP._TOOLS["verify_ledger"]["description"]
        self.assertIn("without it the signatures are NOT checked", d)   # SPEC §22 rule 5: checked with expected_pubkey_hex
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
        with open(mp, encoding="utf-8") as f:
            man = json.load(f)
        man["file_digests_sha256"] = {}
        body = {k: v for k, v in man.items() if k not in ("manifest_digest_sha256", "rfc3161_timestamp",
                                                         "manifest_signature", "manifest_signer")}
        man["manifest_digest_sha256"] = hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        with open(mp, "w", encoding="utf-8", newline="") as f:
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
        with open(glob.glob(os.path.join(arc, "*.sth.json"))[0], encoding="utf-8") as f:
            h = I._sth_canonical_hash(json.load(f))
        led = os.path.join(self.d, "forged.jsonl")
        with open(led, "w", encoding="utf-8", newline="") as f:
            f.write(json.dumps({"idx": 0, "ts": "2026-11-20T00:00:00Z", "data": {}, "prev_hash": "0" * 64, "self_hash": h}) + "\n")
        with self.assertRaises(ValueError) as cm:
            self.signer.sign_ledger(led, os.path.join(self.d, "out.jsonl"), self.key)
        self.assertIn("is not the hash of its content", str(cm.exception))

    def test_generated_lines(self):
        rnd = random.Random(SEED)
        for i in range(120):
            led = os.path.join(self.d, "g%d.jsonl" % i)
            _ledger(led, rnd.randrange(1, 5), tag="t%d-" % i)
            with open(led, encoding="utf-8") as f:
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
            with open(led, "w", encoding="utf-8", newline="") as f:
                f.write("\n".join(lines) + "\n")
            out = os.path.join(self.d, "o%d.jsonl" % i)
            with self.assertRaises(ValueError) as cm:
                self.signer.sign_ledger(led, out, self.key)
            self.assertIn(want, str(cm.exception))
            self.assertFalse(os.path.exists(out))


def _canon(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


def _redigest(manifest_path, man):
    body = {k: v for k, v in man.items() if k not in ("manifest_digest_sha256", "rfc3161_timestamp",
                                                      "manifest_signature", "manifest_signer")}
    man["manifest_digest_sha256"] = hashlib.sha256(_canon(body)).hexdigest()
    with open(manifest_path, "w", encoding="utf-8", newline="") as f:
        json.dump(man, f)


class Rule7OneReadHoweverTheNameIsSpelled(unittest.TestCase):
    """The review of the branch (2026-11-20): one file is read once whatever name the manifest gives it, and a ledger
    that stops being UTF-8 past the first block read is a named failure of its signature layer."""

    def pack(self, broken, spelling):
        import evidence_pack as E
        d = tempfile.mkdtemp()
        pack, lp, good, bad = Rule7PackReadsALedgerOnce.build(self, d, broken)
        mp = os.path.join(pack, "MANIFEST.json")
        with open(mp, encoding="utf-8") as f:
            man = json.load(f)
        if spelling == "dot":        # file_digests_sha256 names "./l.jsonl", ledgers names "l.jsonl"
            man["file_digests_sha256"] = {("./" + k if k == "l.jsonl" else k): v
                                          for k, v in man["file_digests_sha256"].items()}
        elif spelling == "both":     # file_digests_sha256 names the file twice, "l.jsonl" and "./l.jsonl"
            man["file_digests_sha256"]["./l.jsonl"] = man["file_digests_sha256"]["l.jsonl"]
        elif spelling == "link":     # ledgers names a link, inside the pack, to the file the digests name
            os.symlink("l.jsonl", os.path.join(pack, "ln.jsonl"))
            man["ledgers"][0]["file"] = "ln.jsonl"
        _redigest(mp, man)
        return E, pack, lp, good, bad

    def test_one_read_and_one_verdict_for_every_spelling(self):
        for spelling in ("same", "dot", "both", "link"):
            for broken in (True, False):
                E, pack, lp, good, bad = self.pack(broken, spelling)
                committed, other = (bad, good) if broken else (good, bad)
                want = E.verify_pack(pack)["valid"]
                self.assertEqual(want, not broken, spelling)                             # control
                V = E.verifier
                saved = {n: getattr(V, n) for n in ("read_regular", "sha256_regular")}
                reads = []

                def first_then_swap(*a, _n=None, **k):
                    r = saved[_n](*a, **k)
                    if a and os.path.basename(str(a[0])) in ("l.jsonl", "ln.jsonl"):
                        if not reads:
                            _write(lp, other)         # another file at the path after the first read, to the end
                        reads.append(str(a[0]))
                    return r
                for n in saved:
                    setattr(V, n, lambda *a, _n=n, **k: first_then_swap(*a, _n=_n, **k))
                try:
                    got = E.verify_pack(pack)
                finally:
                    for n, f in saved.items():
                        setattr(V, n, f)
                    _write(lp, committed)
                self.assertEqual(len(reads), 1, (spelling, broken, reads))
                self.assertEqual(got["valid"], want, (spelling, broken, got["ledgers"]))

    def test_a_name_the_system_does_not_open_is_not_another_spelling_control(self):
        # "l.jsonl/" and "l.jsonl/." resolve to the file and are not opened as it. Since 0.29.0 (SPEC §31) both are refused
        # as names by every system (Windows opened "l.jsonl/." as the file; CI run 45356889667): malformed, with the reason
        for name in ("l.jsonl/", "l.jsonl/."):
            for where in ("ledgers", "digests"):
                E, pack, _lp, _good, _bad = self.pack(False, "same")
                mp = os.path.join(pack, "MANIFEST.json")
                with open(mp, encoding="utf-8") as f:
                    man = json.load(f)
                if where == "ledgers":
                    man["ledgers"][0]["file"] = name
                else:
                    man["file_digests_sha256"][name] = man["file_digests_sha256"]["l.jsonl"]
                _redigest(mp, man)
                r = E.verify_pack(pack)
                self.assertFalse(r["valid"], (name, where))
                self.assertEqual(r.get("refusal_class"), "malformed", r)
                self.assertIn("a trailing '/' or '/.'", r["error"])

    def test_a_link_out_of_the_pack_is_not_read_control(self):
        E, pack, lp, good, _bad = self.pack(False, "same")
        outside = os.path.join(os.path.dirname(pack), "outside.jsonl")
        _write(outside, good)
        os.remove(lp)
        os.symlink(outside, lp)
        V = E.verifier
        saved = {n: getattr(V, n) for n in ("read_regular", "sha256_regular")}
        seen = []

        def spy(*a, _n=None, **k):
            seen.append(os.path.realpath(str(a[0])))
            return saved[_n](*a, **k)
        for n in saved:
            setattr(V, n, lambda *a, _n=n, **k: spy(*a, _n=_n, **k))
        try:
            got = E.verify_pack(pack)
        finally:
            for n, f in saved.items():
                setattr(V, n, f)
        self.assertGreater(len(seen), 0)                                # the spy saw the reads of the pack
        self.assertNotIn(os.path.realpath(outside), seen)
        self.assertFalse(got["valid"])
        self.assertEqual(got["ledgers"][0].get("pq_reason"), "not_a_file_inside_the_pack", got["ledgers"])

    @NEEDS_CRYPTO
    def test_a_signed_ledger_not_utf8_past_the_first_block_is_a_named_failure(self):
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
        self.assertTrue(E.verify_pack(pack)["valid"])                                    # control
        lp, mp = os.path.join(pack, "l.jsonl"), os.path.join(pack, "MANIFEST.json")
        for pad in (0, 5000, 20000, 70000):
            with open(lp, "rb") as f:
                data = f.read()
            _write(lp, data + b" " * pad + b"\xff\xfe\n")
            with open(mp, encoding="utf-8") as f:
                man = json.load(f)
            with open(lp, "rb") as f:
                man["file_digests_sha256"]["l.jsonl"] = hashlib.sha256(f.read()).hexdigest()
            _redigest(mp, man)
            r = E.verify_pack(pack)                    # 0.27.0 and the branch before this test: UnicodeDecodeError
            self.assertFalse(r["valid"], pad)
            self.assertFalse(r["ledgers"][0]["hash_pass"], (pad, r["ledgers"]))
            if pad >= 20000:   # the signature field is found before the bytes that are not UTF-8: the layer is read, and fails
                self.assertFalse(r["ledgers"][0]["sig_pass"], (pad, r["ledgers"]))
                self.assertEqual(r["states"]["producer_signature"]["state"], "contradicted", r["states"])
            _write(lp, data)


@NEEDS_CRYPTO
class Rule8OtherSignedDocumentsAreNotEntries(unittest.TestCase):
    """A tree head, a HEAD and a pack manifest are signed over the same kind of message as an entry: none of them is
    signed by the signer, and none of them verifies as a signed entry."""

    def setUp(self):
        import signer
        self.signer = signer
        self.d = tempfile.mkdtemp()
        self.key = os.path.join(self.d, "k.key")
        self.pub = signer.keygen(self.key)["public_key_hex"]
        self.led = os.path.join(self.d, "l.jsonl")
        _ledger(self.led, 2)

    def test_a_manifest_digest_is_not_signed(self):
        import evidence_pack as E
        pack = os.path.join(self.d, "pack")
        E.build_pack([self.led], pack, subject="made by someone else")
        mp = os.path.join(pack, "MANIFEST.json")
        with open(mp, encoding="utf-8") as f:
            man = json.load(f)
        forged = os.path.join(self.d, "forged.jsonl")
        with open(forged, "w", encoding="utf-8", newline="") as f:
            f.write(json.dumps({"idx": 0, "ts": "2026-11-20T00:00:00Z", "data": {}, "prev_hash": "0" * 64,
                                "self_hash": man["manifest_digest_sha256"]}) + "\n")
        out = os.path.join(self.d, "out.jsonl")
        with self.assertRaises(ValueError) as cm:      # 0.27.0: signed, and the pack verified with the key pinned
            self.signer.sign_ledger(forged, out, self.key)
        self.assertIn("is not the hash of its content", str(cm.exception))
        self.assertFalse(os.path.exists(out))
        r = E.verify_pack(pack, manifest_signer_hex=self.pub)
        self.assertEqual(r["states"]["producer_signature"]["state"], "not_evaluated")    # control: nothing signed it

    def test_a_signed_tree_head_head_or_manifest_is_not_a_signed_entry(self):
        import cryptovalid_ingest as I
        import evidence_pack as E
        from cryptovalid_kms import FileKeyBackend
        arc = os.path.join(self.d, "arc")
        w = I.Ingestor(arc, batch_size=1, backend=FileKeyBackend(self.key))
        w.append({"x": 1})
        w.seal()
        w.close(seal=False)
        self.assertTrue(I.verify_archive(arc, expected_pubkey_hex=[self.pub])["ok"])     # control
        pack = os.path.join(self.d, "pack")
        E.build_pack([self.led], pack, sign_key=self.key)
        docs = []
        for p in (glob.glob(os.path.join(arc, "*.sth.json"))[0], os.path.join(arc, "ledger.head.json")):
            with open(p, encoding="utf-8") as f:
                doc = json.load(f)
            docs.append((dict(doc, self_hash=I._sth_canonical_hash(doc)), doc["signature"]))
        with open(os.path.join(pack, "MANIFEST.json"), encoding="utf-8") as f:
            man = json.load(f)
        body = {k: v for k, v in man.items() if k not in ("manifest_digest_sha256", "rfc3161_timestamp",
                                                          "manifest_signature", "manifest_signer")}
        docs.append((dict(body, self_hash=man["manifest_digest_sha256"], signer=self.pub), man["manifest_signature"]))
        for i, (line, sig) in enumerate(docs):
            line["signature"] = sig
            p = os.path.join(self.d, "as_entry%d.jsonl" % i)
            with open(p, "w", encoding="utf-8", newline="") as f:
                f.write(json.dumps(line) + "\n")
            r = self.signer.verify_file(p, self.pub)   # until this rule: ok, verified 1, under the pinned key
            self.assertFalse(r["ok"], (i, r))
            self.assertEqual(r["verified"], 0)
            self.assertTrue(r["failures"][0]["reason"].startswith("unknown_field:"), r["failures"])
            self.assertEqual(verifier.verify_ledger(p)["verdict"], "FAIL")               # the two readers agree
        signed = os.path.join(self.d, "s.jsonl")
        self.signer.sign_ledger(self.led, signed, self.key)
        self.assertTrue(self.signer.verify_file(signed, self.pub)["ok"])                 # control


class _Body:
    """An HTTP body of `data`; records the size asked for at every read."""

    def __init__(self, data):
        self.data, self.asked = data, []

    def read(self, n=-1):
        self.asked.append(n)
        if n is None or n < 0:
            n = len(self.data)
        out, self.data = self.data[:n], self.data[n:]
        return out


class ReviewOfTheBranch(unittest.TestCase):
    """What the mutants of the review of the branch (2026-11-20) left alive, each held here."""

    def test_a_negative_index_is_not_the_last_leaf(self):
        # rule 1: until 0.27.0 the index -1 walked the path of the last leaf of a tree of 2^k leaves, and verified
        for n in (1, 2, 4, 8, 16):
            lv = [b"leaf %d" % i for i in range(n)]
            root, pr = M.mth(lv), M.inclusion_proof(n - 1, lv)
            self.assertTrue(M.verify_inclusion(n - 1, n, lv[n - 1], pr, root))           # control
            self.assertFalse(M.verify_inclusion(-1, n, lv[n - 1], pr, root), n)

    def test_bytes_already_read_verify_at_any_caller_depth(self):
        # rule 7: the bytes the pack hands to the ledger verifier are decoded under the same headroom as a path (SPEC §5:
        # a line at the bound is PASS however deep the caller's stack is)
        data = cur = {}
        for _ in range(verifier.MAX_JSON_DEPTH - 2):
            cur["x"] = {}
            cur = cur["x"]
        e = {"idx": 0, "ts": "t", "data": data, "prev_hash": "0" * 64}
        e["self_hash"] = hashlib.sha256(verifier.canonical_payload(e)).hexdigest()
        line = (json.dumps(e, separators=(",", ":")) + "\n").encode()
        p = os.path.join(tempfile.mkdtemp(), "l.jsonl")
        _write(p, line)

        def deep(n, f):
            return f() if n == 0 else deep(n - 1, f)
        self.assertEqual(deep(700, lambda: verifier.verify_ledger(p))["verdict"], "PASS")                # control
        self.assertEqual(deep(700, lambda: verifier._verify_ledger_data(p, line))["verdict"], "PASS")

    def test_the_error_body_of_a_kms_answer_is_bounded(self):
        # rule 6, the tenth read (cryptovalid_kms._http_error_text): never read() without a size, at most 1 MiB + 1 byte
        import cryptovalid_kms as K
        small = _Body(json.dumps({"errors": ["permission denied"]}).encode())
        self.assertEqual(K._http_error_text(small), "permission denied")                  # control
        self.assertTrue(small.asked and all(isinstance(n, int) and n >= 0 for n in small.asked), small.asked)
        big = _Body(json.dumps({"errors": ["x"], "pad": "p" * (2 << 20)}).encode())      # valid JSON of more than 2 MiB
        self.assertEqual(K._http_error_text(big), "")                                     # past the bound: only the status
        self.assertTrue(all(isinstance(n, int) and n >= 0 for n in big.asked), big.asked[:3])
        self.assertLessEqual(sum(big.asked), (1 << 20) + 1)

    def test_a_schema_type_this_server_does_not_check_is_refused(self):
        # rule 5: a property whose schema type is outside the four checked is refused, never passed unchecked
        import cryptovalid_mcp as MCP
        ran = []
        MCP._TOOLS["zz_review"] = {"fn": lambda a: (ran.append(1), {"result": "stub"})[1], "readonly": True,
                                   "description": "test", "schema": {"type": "object", "additionalProperties": False,
                                                                     "properties": {"n": {"type": "integer"}}}}
        try:
            r = MCP.handle({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                            "params": {"name": "zz_review", "arguments": {"n": 1}}})
        finally:
            del MCP._TOOLS["zz_review"]
        self.assertEqual(r["error"]["code"], -32602, r)
        self.assertIn("is not checked by this server", r["error"]["message"])
        self.assertEqual(ran, [])

    @NEEDS_CRYPTO
    def test_the_name_of_a_key_written_twice_is_reported_in_ascii(self):
        # rule 2: the name comes from anyone; a lone surrogate or a non-ASCII letter in it never reaches the receipt raw
        import cryptovalid_jws as J
        t = Rule2DuplicateKeys("test_signed_ledger_control")
        t.setUp()
        rec = {k: v for k, v in json.loads(t.lines[0]).items() if k not in ("signature", "signer")}
        head = json.dumps({"alg": "EdDSA", "kid": t.pub})
        name = '"\\ud800\u00e9"'                       # JSON text: an escaped lone surrogate, then U+00E9
        dup_head = head[:-1] + ', %s: 1, %s: 2}' % (name, name)
        dup_rec = json.dumps(rec)[:-1] + ', %s: 1, %s: 2}' % (name, name)
        for jws, why in ((t._jws(dup_head, json.dumps(rec).encode()), "header_duplicate_key: "),
                         (t._jws(head, dup_rec.encode("utf-8")), "payload_duplicate_key: ")):
            r = J.verify(jws, t.pub)
            self.assertFalse(r["ok"], r)
            self.assertTrue(r["why"].startswith(why), r)
            r["why"].encode("ascii")                   # raises if the name was copied as it came
            self.assertIn("\\ud800", r["why"])


@NEEDS_CRYPTO
class Rule2TreeHeadsAndReceipts(unittest.TestCase):
    """A key written twice in a tree head, a HEAD or a receipt file is refused."""

    def setUp(self):
        import signer
        self.d = tempfile.mkdtemp()
        self.key = os.path.join(self.d, "k.key")
        self.pub = signer.keygen(self.key)["public_key_hex"]

    def test_tree_head_and_head_with_a_key_twice(self):
        import cryptovalid_ingest as I
        from cryptovalid_kms import FileKeyBackend
        arc = os.path.join(self.d, "arc")
        w = I.Ingestor(arc, batch_size=1, backend=FileKeyBackend(self.key))
        w.append({"x": 1})
        w.seal()
        w.close(seal=False)
        self.assertTrue(I.verify_archive(arc, expected_pubkey_hex=[self.pub])["ok"])     # control
        for p, member, reason in ((glob.glob(os.path.join(arc, "*.sth.json"))[0], "tree_size", "sth_unreadable: duplicate_key"),
                                  (os.path.join(arc, "ledger.head.json"), "segments_sealed", "head_unreadable: duplicate_key")):
            with open(p, encoding="utf-8") as f:
                text = f.read()
            for first in (True, False):   # the other value first (the signed one is read last) or last
                body = json.dumps(json.loads(text))[1:-1]
                dup = '"%s": 999999' % member
                with open(p, "w", encoding="utf-8", newline="") as f:
                    f.write("{" + (dup + ", " + body if first else body + ", " + dup) + "}")
                r = I.verify_archive(arc, expected_pubkey_hex=[self.pub])
                self.assertFalse(r["ok"], (member, first))
                self.assertIn(reason, [x["reason"] for x in r["failures"]])
            with open(p, "w", encoding="utf-8", newline="") as f:
                f.write(text)
        self.assertTrue(I.verify_archive(arc, expected_pubkey_hex=[self.pub])["ok"])     # control: restored

    def test_receipt_file_and_entry_file_with_a_key_twice(self):
        import subprocess
        import cryptovalid_receipt as R
        led = os.path.join(self.d, "l.jsonl")
        _ledger(led, 3)
        rc = R.inclusion_receipt(led, 1, self.key)
        with open(led, encoding="utf-8") as f:
            entry = json.loads(f.read().splitlines()[1])
        rp, ep = os.path.join(self.d, "r.json"), os.path.join(self.d, "e.json")

        def run(receipt_text, entry_text):
            with open(rp, "w", encoding="utf-8", newline="") as f:
                f.write(receipt_text)
            with open(ep, "w", encoding="utf-8", newline="") as f:
                f.write(entry_text)
            cp = subprocess.run([sys.executable, os.path.join(_HERE, "cryptovalid_receipt.py"), "verify", rp, self.pub,
                                 "--entry-json", ep], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            return cp.returncode, json.loads(cp.stdout.decode("utf-8"))
        code, out = run(json.dumps(rc), json.dumps(entry))
        self.assertEqual((code, out["ok"]), (0, True))                                    # control
        code, out = run('{"tree_size": 999, ' + json.dumps(rc)[1:], json.dumps(entry))
        self.assertEqual((code, out), (1, {"ok": False, "why": "receipt unreadable: duplicate_key"}))
        code, out = run(json.dumps(rc), '{"data": {"other": 1}, ' + json.dumps(entry)[1:])
        self.assertEqual((code, out), (1, {"ok": False, "why": "entry unreadable: duplicate_key"}))


if __name__ == "__main__":
    unittest.main()
