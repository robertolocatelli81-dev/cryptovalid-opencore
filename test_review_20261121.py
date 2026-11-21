# SPDX-License-Identifier: AGPL-3.0-or-later
"""SPEC §22 (Unreleased), after the review of the branch on 2026-11-21: the cases that mutants of the lines added by the
rules showed missing in `test_decisions_20261120.py`, and the sentences of the specification the review re-measured.

Rule 6 says the signature of a trusted list is read closed, "anything else refused with its reason": each refusal held
here is one a mutant that dropped its check survived. So are the cut of the names of rule 2, the command-line option of
rule 3 and three answers of the MCP tool of rule 5. TestSentencesOfSection22 also holds sentences of §22 as measured
(the pivot chain of rule 6, rule 4 with rule 7) and the sequence number of rule 6; the last class, the empty pin of
rule 4."""
import base64
import hashlib
import os
import re
import shutil
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

try:
    import cryptography  # noqa: F401
    HAVE_CRYPTO = True
except ImportError:
    HAVE_CRYPTO = False
if os.environ.get("CV_REQUIRE_CRYPTO") == "1" and not HAVE_CRYPTO:
    raise SystemExit("CV_REQUIRE_CRYPTO=1 but `cryptography` is missing: the cases that need it would be skipped")

import cryptovalid_lotl as L  # noqa: E402

_DS, _XADES = "http://www.w3.org/2000/09/xmldsig#", "http://uri.etsi.org/01903/v1.3.2#"
_TSL = "http://uri.etsi.org/02231/v2#"
_SHA256 = "http://www.w3.org/2001/04/xmlenc#sha256"
_EXC = "http://www.w3.org/2001/10/xml-exc-c14n#"
_LIST = (f'<TrustServiceStatusList xmlns="{_TSL}"><SchemeInformation><TSLSequenceNumber>SEQ</TSLSequenceNumber>'
         "<NextUpdate><dateTime>2099-01-01T00:00:00Z</dateTime></NextUpdate></SchemeInformation></TrustServiceStatusList>")


def _b64(b):
    return base64.b64encode(b).decode()


class TestUnknownMembersOfATreeHeadAndAHeadAreCut(unittest.TestCase):
    """§22 rule 2: the keys outside the list of a tree head or of a HEAD are named in code-point order, joined by `,` and
    cut to 120 code points, as those of a tip (a cut at 119 survived as a mutant: the tests named short keys only)."""

    def test_the_names_are_sorted_joined_and_cut_to_120_code_points(self):
        import json
        import cryptovalid_ingest as I
        tmp = tempfile.mkdtemp()
        try:
            w = I.Ingestor(tmp, batch_size=1)
            for i in range(3):
                w.append({"i": i})
            w.seal()
            w.append({"i": 3})
            w.close()
            extra = {"z" * 130: 1, "\U0001f600" * 3: 2, "a": 3}
            want = ",".join(sorted(extra))[:120]
            self.assertEqual((len(want), want[:3]), (120, "a,z"))
            for name, reason in (("ledger-000000.jsonl.sth.json", "sth_unknown_member:"), ("ledger.head.json", "head_unknown_member:")):
                path = os.path.join(tmp, name)
                with open(path, encoding="utf-8") as f:
                    doc = json.load(f)
                doc.update(extra)
                with open(path, "w", encoding="utf-8") as f:
                    json.dump(doc, f)
            reasons = [f["reason"] for f in I.verify_archive(tmp)["failures"]]
            self.assertIn("sth_unknown_member:" + want, reasons)
            self.assertIn("head_unknown_member:" + want, reasons)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


class TestMcpVerifyLedgerWithoutCryptography(unittest.TestCase):
    """§22 rule 5: "Without `cryptography` the signatures cannot be checked: `checked: false`, `ok: false`, `valid:
    false`". The tests of the rule need `cryptography` to sign and are skipped without it, and with it that branch is
    not reached: an answer `checked: true, ok: true` there survived as a mutant. Here the branch runs in both: without
    `cryptography` as it is, with it by making the signature layer answer as it does when the package is missing."""

    def test_checked_false_and_not_valid(self):
        import json
        from unittest import mock
        import cryptovalid_mcp as M
        import signer
        pk = "00" * 32
        req = {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
               "params": {"name": "verify_ledger", "arguments": {"path": os.path.join(HERE, "examples", "sample_ledger.jsonl"),
                                                                 "expected_pubkey_hex": pk}}}
        if HAVE_CRYPTO:
            missing = RuntimeError("the signature layer requires 'cryptography' (pip install cryptography)")
            with mock.patch.object(signer, "verify_ledger_signatures", side_effect=missing):
                r = M.handle(req)
        else:
            r = M.handle(req)
        out = json.loads(r["result"]["content"][0]["text"])
        self.assertEqual(out["result"]["verdict"], "PASS")   # the chain of the sample holds: only the signatures are unknown
        self.assertEqual((out["signatures"]["checked"], out["signatures"]["ok"], out["signatures"]["pinned_key"]), (False, False, pk))
        self.assertTrue(out["signatures"]["error"].startswith("backend_missing: "), out["signatures"])
        self.assertIs(out["valid"], False)


class TestCanonicalFormOfAnAttribute(unittest.TestCase):
    """Canonical XML §2.3 (Processing Model), which Exclusive C14N 1.0 keeps: in an attribute value TAB, LF and CR are
    written as character references (a TAB written as itself survived as a mutant: the forms copied from libxml2 had
    none); a processing instruction after the document element is preceded by a line feed."""

    def test_tab_lf_cr_in_an_attribute_value(self):
        root = L._xml_tree(b'<a x="&#9;&#10;&#13;" y="&lt;&amp;&quot;>"/>')[0]
        self.assertEqual(L.exc_c14n(root), b'<a x="&#x9;&#xA;&#xD;" y="&lt;&amp;&quot;>"></a>')

    def test_cr_in_text_and_gt(self):
        root = L._xml_tree(b"<a>&#13;&gt;&lt;&amp;\"</a>")[0]
        self.assertEqual(L.exc_c14n(root), b'<a>&#xD;&gt;&lt;&amp;"</a>')

    def test_processing_instructions_outside_the_document_element(self):
        root, before, after = L._xml_tree(b"<?a b?><r/><?c d?><?e?>")
        self.assertEqual(L.exc_c14n(root, before=before, after=after), b"<?a b?>\n<r></r>\n<?c d?>\n<?e?>")

    def test_two_attributes_with_one_expanded_name(self):
        with self.assertRaises(ValueError) as c:
            L._xml_tree(b'<a xmlns:p="urn:u" xmlns:q="urn:u" p:x="1" q:x="2"/>')
        self.assertIn("two attributes with one expanded name", str(c.exception))

    def test_the_depth_bound(self):
        L._xml_tree(b"<a>" * L._MAX_DEPTH + b"</a>" * L._MAX_DEPTH)
        with self.assertRaises(ValueError) as c:
            L._xml_tree(b"<a>" * (L._MAX_DEPTH + 1) + b"</a>" * (L._MAX_DEPTH + 1))
        self.assertIn(f"deeper than {L._MAX_DEPTH} elements", str(c.exception))


@unittest.skipUnless(HAVE_CRYPTO, "needs `cryptography` (the `sign` extra)")
class TestSignatureShapeIsClosed(unittest.TestCase):
    """§22 rule 6, "the signature read is closed": every list below carries a signature that VERIFIES cryptographically
    (made by the trusted key over its own SignedInfo) in a shape outside the one of the rule; each is `xmldsig_shape`."""

    @classmethod
    def setUpClass(cls):
        from test_lotl import make_signer, sign_list
        cls.sign = staticmethod(sign_list)
        cls.key, cls.der, cls.fp = make_signer(name="tl")
        cls.xml = _LIST.replace("SEQ", "7").encode()
        cls.good = sign_list(cls.xml, cls.key, cls.der)

    def _why(self, doc, at=None):
        try:
            L.verify_list_signature(doc, {self.fp}, at=at)
        except ValueError as e:
            return str(e)
        return "ok"

    def _ecdsa(self, signed):
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec, utils
        r, s = utils.decode_dss_signature(self.key.sign(signed, ec.ECDSA(hashes.SHA256())))
        return r.to_bytes(32, "big") + s.to_bytes(32, "big")

    def _resign(self, doc, fn, value=None):
        """`doc` with its SignedInfo rewritten by `fn` and the SignatureValue made again over the new SignedInfo (by
        `value(signed bytes)`, default ECDSA r || s with the list's key): a signature the signer could have made, in
        another shape."""
        m = re.search(rb"<ds:SignedInfo>.*?</ds:SignedInfo>", doc, re.S)
        si = fn(m.group(0))
        signed = L.exc_c14n(L._xml_tree(b'<w xmlns:ds="' + _DS.encode() + b'">' + si + b"</w>")[0].elements()[0])
        doc = doc[:m.start()] + si + doc[m.end():]
        v = re.search(rb"<ds:SignatureValue>[^<]*</ds:SignatureValue>", doc)
        return (doc[:v.start()] + b"<ds:SignatureValue>" + base64.b64encode((value or self._ecdsa)(signed))
                + b"</ds:SignatureValue>" + doc[v.end():])

    def test_the_shape_of_the_rule_verifies_control(self):
        self.assertEqual(self._why(self.good), "ok")
        self.assertEqual(self._why(self._resign(self.good, lambda si: si)), "ok")   # the helper signs as the signer does

    def test_children_of_the_signature_in_another_order(self):
        ki = re.search(rb"<ds:KeyInfo>.*?</ds:KeyInfo>", self.good, re.S)
        doc = self.good[:ki.start()] + self.good[ki.end():]
        v = doc.index(b"<ds:SignatureValue>")
        self.assertTrue(self._why(doc[:v] + ki.group(0) + doc[v:]).startswith("xmldsig_shape: ds:Signature must be"))

    def test_a_child_of_the_signature_that_is_not_an_object(self):
        doc = self.sign(self.xml, self.key, self.der, edit=lambda p: p.update(objects='<x:Other xmlns:x="urn:x"/>'))
        self.assertTrue(self._why(doc).startswith("xmldsig_shape: ds:Signature must be"), self._why(doc))

    def test_an_algorithm_with_parameters(self):
        for tag in (b"ds:SignatureMethod", b"ds:CanonicalizationMethod"):
            def fn(si, tag=tag):
                m = re.search(b"<" + tag + rb' Algorithm="[^"]*"/>', si)
                return si[:m.end() - 2] + b"><ds:HMACOutputLength>8</ds:HMACOutputLength></" + tag + b">" + si[m.end():]
            why = self._why(self._resign(self.good, fn))
            self.assertTrue(why.startswith("xmldsig_shape:") and "carries parameters" in why, (tag, why))

    def test_a_reference_with_another_attribute(self):
        doc = self._resign(self.good, lambda si: si.replace(b'<ds:Reference Id="r-doc" URI="">',
                                                            b'<ds:Reference Id="r-doc" URI="" Other="x">'))
        self.assertTrue(self._why(doc).startswith("xmldsig_shape: a Reference carries the attribute"), self._why(doc))

    def test_a_reference_with_two_digest_values(self):
        def fn(si):
            m = re.search(rb"<ds:DigestValue>[^<]*</ds:DigestValue>", si)
            return si[:m.end()] + m.group(0) + si[m.end():]
        why = self._why(self._resign(self.good, fn))
        self.assertTrue(why.startswith("xmldsig_shape: a Reference must be Transforms, DigestMethod, DigestValue"), why)

    def test_the_reference_to_the_list_with_a_type(self):
        doc = self._resign(self.good, lambda si: si.replace(
            b'<ds:Reference Id="r-doc" URI="">', b'<ds:Reference Id="r-doc" URI="" Type="' + _DS.encode() + b'Object">'))
        self.assertTrue(self._why(doc).startswith("xmldsig_shape: the reference to the list carries a Type"), self._why(doc))

    def test_the_reference_to_the_list_without_the_canonicalization_transform(self):
        # only the enveloped transform: the default would be inclusive C14N, which this verifier does not write
        doc = self.sign(self.xml, self.key, self.der, edit=lambda p: p.update(
            doc_transforms='<ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>'))
        self.assertTrue(self._why(doc).startswith("xmldsig_shape: the reference to the list must be"), self._why(doc))

    def test_the_signed_properties_reference_names_another_element_of_the_signature(self):
        # a ds:Object of this signature that holds a SignedSignatureProperties with the right certificate digest, signed
        # and digested correctly: everything holds but the name of the element the reference points to
        inner = (f'<xades:SignedSignatureProperties xmlns:xades="{_XADES}"><xades:SigningCertificateV2><xades:Cert>'
                 f'<xades:CertDigest><ds:DigestMethod Algorithm="{_SHA256}"/><ds:DigestValue>'
                 f"{_b64(hashlib.sha256(self.der).digest())}</ds:DigestValue></xades:CertDigest></xades:Cert>"
                 "</xades:SigningCertificateV2></xades:SignedSignatureProperties>")
        obj = f'<ds:Object Id="o-2">{inner}</ds:Object>'
        canon = L.exc_c14n(L._xml_tree(f'<w xmlns:ds="{_DS}">{obj}</w>'.encode())[0].elements()[0])
        doc = self.sign(self.xml, self.key, self.der, edit=lambda p: p.update(
            objects=obj, sp_uri="#o-2", sp_digest=_b64(hashlib.sha256(canon).digest())))
        why = self._why(doc)
        self.assertTrue(why.startswith("xmldsig_shape: the SignedProperties reference does not name"), why)

    def test_signed_info_with_another_first_element(self):
        doc = self._resign(self.good, lambda si: si.replace(b"ds:CanonicalizationMethod", b"ds:C14nMethod"))
        self.assertTrue(self._why(doc).startswith("xmldsig_shape: SignedInfo must be"), self._why(doc))

    def test_the_reference_to_the_list_names_a_fragment(self):
        # same digest (the whole list), another URI: the reference no longer says it covers the document
        doc = self._resign(self.good, lambda si: si.replace(b'<ds:Reference Id="r-doc" URI="">', b'<ds:Reference Id="r-doc" URI="#sig-1">'))
        self.assertTrue(self._why(doc).startswith("xmldsig_shape: two References expected"), self._why(doc))

    def test_a_sha1_digest_of_the_list_is_not_read(self):
        root, before, after = L._xml_tree(self.xml)
        sha1 = _b64(hashlib.sha1(L.exc_c14n(root, before=before, after=after)).digest())

        def fn(si):
            m = re.search(rb'<ds:DigestMethod Algorithm="[^"]*"/><ds:DigestValue>[^<]*</ds:DigestValue>', si)
            return (si[:m.start()] + b'<ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/><ds:DigestValue>'
                    + sha1.encode() + b"</ds:DigestValue>" + si[m.end():])
        why = self._why(self._resign(self.good, fn))
        self.assertTrue(why.startswith("xmldsig_algorithm: DigestMethod"), why)

    def test_key_info_with_a_key_value_next_to_the_certificate(self):
        doc = self.sign(self.xml, self.key, self.der, edit=lambda p: p.update(keyinfo=p["keyinfo"] + "<ds:KeyValue/>"))
        self.assertTrue(self._why(doc).startswith("xmldsig_shape: KeyInfo must hold"), self._why(doc))

    def test_a_signature_value_that_is_not_base64(self):
        # the SignatureValue is outside what is signed: a character outside the alphabet must not be skipped
        doc = self.good.replace(b"<ds:SignatureValue>", b"<ds:SignatureValue>!")
        self.assertEqual(self._why(doc), "xmldsig_malformed: SignatureValue is not base64")

    def test_an_ecdsa_value_longer_than_r_and_s(self):
        # r || 00 || s reads as the same two integers: only r || s, each of the size of the curve, is the XML form
        def value(signed):
            rs = self._ecdsa(signed)
            return rs[:32] + b"\x00" + rs[32:]
        self.assertEqual(self._why(self._resign(self.good, lambda si: si, value)),
                         "xmldsig_signature_invalid: the signature value does not verify")

    def test_rsa_pss_with_another_salt_length(self):
        # RFC 6931 §2.3.10: the salt is of the length of the hash; a signature with a salt of 20 bytes is not that method
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding
        from test_lotl import make_signer
        key, der, fp = make_signer("rsa", name="tl rsa")
        good = self.sign(self.xml, key, der, alg="rsa-pss-sha256")
        self.assertEqual(L.verify_list_signature(good, {fp})["signer_sha256"], fp)
        other = self._resign(good, lambda si: si, lambda signed: key.sign(
            signed, padding.PSS(padding.MGF1(hashes.SHA256()), 20), hashes.SHA256()))
        with self.assertRaises(ValueError) as c:
            L.verify_list_signature(other, {fp})
        self.assertTrue(str(c.exception).startswith("xmldsig_signature_invalid"), str(c.exception))

    def test_a_certificate_not_yet_valid(self):
        why = self._why(self.good, at=datetime(2020, 1, 1, tzinfo=timezone.utc))
        self.assertTrue(why.startswith("xmldsig_certificate_not_valid"), why)

    def test_next_update_at_the_instant_itself_and_one_second_later(self):
        when = (datetime.now(timezone.utc) + timedelta(hours=1)).replace(microsecond=0)
        doc = self.sign(self.xml.replace(b"2099-01-01T00:00:00Z", when.strftime("%Y-%m-%dT%H:%M:%SZ").encode()), self.key, self.der)
        self.assertEqual(self._why(doc, at=when), "ok")
        self.assertTrue(self._why(doc, at=when + timedelta(seconds=1)).startswith("tl_next_update_passed"))

    def test_a_next_update_that_is_not_one_date_time_of_the_form(self):
        for bad in (b"<dateTime>2099-01-01T00:00:00+01:00</dateTime>", b"<dateTime>2099-01-01</dateTime>", b"<dateTime></dateTime>",
                    b"<dateTime>2099-01-01T00:00:00Z</dateTime><dateTime>2099-01-01T00:00:00Z</dateTime>"):
            doc = self.sign(self.xml.replace(b"<dateTime>2099-01-01T00:00:00Z</dateTime>", bad), self.key, self.der)
            self.assertTrue(self._why(doc).startswith("xmldsig_malformed: NextUpdate is not one dateTime"), (bad, self._why(doc)))

    def test_an_instant_without_a_time_zone_is_refused_by_name(self):
        with self.assertRaises(ValueError) as c:
            L.verify_list_signature(self.good, {self.fp}, at=datetime(2026, 11, 21))
        self.assertIn("timezone-aware", str(c.exception))
        self.assertEqual(self._why(self.good, at=datetime(2026, 11, 21, tzinfo=timezone.utc)), "ok")


@unittest.skipUnless(HAVE_CRYPTO, "needs `cryptography` (the `sign` extra)")
class TestSentencesOfSection22(unittest.TestCase):
    """Sentences of §22 as the review measured them."""

    def test_an_earlier_list_verifies_unless_a_minimum_sequence_is_given(self):
        # rule 6: no state is kept between two calls; the sequence number is reported, and a minimum refuses an earlier list
        from test_lotl import make_signer, sign_list
        key, der, fp = make_signer(name="tl")
        nine, eight = (sign_list(_LIST.replace("SEQ", s).encode(), key, der) for s in ("9", "8"))
        self.assertEqual(L.verify_list_signature(nine, {fp})["sequence_number"], 9)
        self.assertEqual(L.verify_list_signature(eight, {fp})["sequence_number"], 8)   # earlier: verifies without a minimum
        self.assertEqual(L.verify_list_signature(nine, {fp}, min_sequence=9)["sequence_number"], 9)
        with self.assertRaises(ValueError) as c:
            L.verify_list_signature(eight, {fp}, min_sequence=9)
        self.assertTrue(str(c.exception).startswith("tl_sequence_rolled_back: TSLSequenceNumber 8"), str(c.exception))
        for bad in (0, -1, True, "9", 9.0):
            with self.assertRaises(ValueError):
                L.verify_list_signature(nine, {fp}, min_sequence=bad)

    def test_a_sequence_number_is_required_and_well_formed(self):
        from test_lotl import make_signer, sign_list
        key, der, fp = make_signer(name="tl")
        for seq in ("0", "-1", "", "x", "1.0", "\u0661", "1 2"):
            x = sign_list(_LIST.replace("SEQ", seq).encode(), key, der)
            with self.assertRaises(ValueError) as c:
                L.verify_list_signature(x, {fp})
            self.assertTrue(str(c.exception).startswith("tl_sequence_malformed"), (seq, str(c.exception)))
        for xml in (_LIST.replace("<TSLSequenceNumber>SEQ</TSLSequenceNumber>", ""),
                    _LIST.replace("<TSLSequenceNumber>SEQ</TSLSequenceNumber>", "<TSLSequenceNumber>1</TSLSequenceNumber>" * 2)):
            with self.assertRaises(ValueError) as c:
                L.verify_list_signature(sign_list(xml.encode(), key, der), {fp})
            self.assertTrue(str(c.exception).startswith("tl_sequence_malformed"), str(c.exception))
        self.assertEqual(L.verify_list_signature(sign_list(_LIST.replace("SEQ", " 12\n").encode(), key, der), {fp})
                         ["sequence_number"], 12)   # white space around the number, as the lists write it

    def test_the_loader_reports_and_enforces_sequences(self):
        import json
        from test_decisions_20261120 import _lotl, _pointer, _QTST_SVC, _b64 as b64
        from test_lotl import make_signer, sign_list
        lk, lder, lfp = make_signer(name="lotl")
        tk, tder, _tfp = make_signer(name="tl")
        url = "https://tl.example/a.xml"
        lotl = sign_list(_lotl([L.OJ_LOTL_URL], [_pointer(url, tder)]).replace(b"<TSLSequenceNumber>1<", b"<TSLSequenceNumber>7<"), lk, lder)
        tl = sign_list((f'<TrustServiceStatusList xmlns="{_TSL}"><SchemeInformation><TSLSequenceNumber>4</TSLSequenceNumber>'
                        "</SchemeInformation>" + _QTST_SVC.format(c=b64(b"Q")) + "</TrustServiceStatusList>").encode(), tk, tder)
        orig = L._get
        L._get = lambda u, timeout=45: lotl if u == L.LOTL_URL else tl
        tmp = tempfile.mkdtemp()
        try:
            seqs, log = {}, []
            cache = os.path.join(tmp, "c.json")
            fprs, cov, _e = L.load_qualified_status(cache_path=cache, trusted_lotl_signers={lfp}, sequences_out=seqs, log=log.append)
            self.assertEqual((seqs, cov), ({L.LOTL_URL: 7, url: 4}, [url]))
            with open(cache, encoding="utf-8") as f:
                self.assertEqual(json.load(f)["sequences"], {L.LOTL_URL: 7, url: 4})
            again = {}
            L.load_qualified_status(cache_path=cache, trusted_lotl_signers={lfp}, sequences_out=again)   # from the cache
            self.assertEqual(again, seqs)
            # with a minimum the fresh cache (built above, sequence 4) is not read: the list is fetched and refused
            fprs2, cov2, _e = L.load_qualified_status(cache_path=cache, trusted_lotl_signers={lfp}, min_sequences={url: 5},
                                                      log=log.append)
            self.assertEqual((fprs2, cov2), (set(), []))
            self.assertTrue(any("tl_sequence_rolled_back" in m for m in log), log)
            with self.assertRaises(ValueError) as c:
                L.load_qualified_status(trusted_lotl_signers={lfp}, min_sequences={L.LOTL_URL: 8})
            self.assertTrue(str(c.exception).startswith("tl_sequence_rolled_back"))
            for bad in ({url: 0}, {url: "5"}, {1: 5}, [url]):
                with self.assertRaises(ValueError):
                    L.load_qualified_status(trusted_lotl_signers={lfp}, min_sequences=bad)
        finally:
            L._get = orig
            shutil.rmtree(tmp, ignore_errors=True)

    def test_two_pivots_are_followed_oldest_first_and_a_pivot_without_certificates_is_named(self):
        # rule 6, the pivot mechanism: OJ certificate A -> pivot 1 (signed by A, announces B) -> pivot 2 (signed by B,
        # announces C) -> the LOTL, signed by C. The tests of test_decisions_20261120.py have one pivot: no order to get wrong
        from test_decisions_20261120 import _lotl, _pointer
        from test_lotl import make_signer, sign_list
        a, b, c = (make_signer(name=n) for n in "abc")
        own = lambda who: [_pointer("https://lotl.example/lotl.xml", who[1], lotl=True)]   # noqa: E731
        p1 = sign_list(_lotl([L.OJ_LOTL_URL], own(b)), a[0], a[1])
        p2 = sign_list(_lotl(["https://p.example/1", L.OJ_LOTL_URL], own(c)), b[0], b[1])
        cur = sign_list(_lotl(["https://p.example/2", "https://p.example/1", L.OJ_LOTL_URL], own(c)), c[0], c[1])
        store = {"https://p.example/1": p1, "https://p.example/2": p2}
        signers = L.lotl_signers(cur, get=lambda u, t: store[u], anchors={a[2]})
        self.assertEqual(signers, {c[2]})
        self.assertEqual(L.verify_list_signature(cur, signers)["signer_sha256"], c[2])
        empty = sign_list(_lotl([L.OJ_LOTL_URL], []), a[0], a[1])
        with self.assertRaises(ValueError) as e:
            L.lotl_signers(sign_list(_lotl(["https://p.example/1", L.OJ_LOTL_URL], own(a)), a[0], a[1]),
                           get=lambda u, t: empty, anchors={a[2]})
        self.assertEqual(str(e.exception), "lotl_pivot_without_certificates: https://p.example/1")

    def test_the_command_line_option_require_signature_domain(self):
        # rule 3: `cryptovalid_ingest.py verify --require-signature-domain` (an option that did nothing survived as a mutant)
        import base64
        import json
        import subprocess
        import cryptovalid_ingest as I
        import signer
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptovalid_kms import FileKeyBackend
        tmp = tempfile.mkdtemp()
        try:
            key = os.path.join(tmp, "k.key")
            pk = signer.keygen(key)["public_key_hex"]
            arch = os.path.join(tmp, "arch")
            w = I.Ingestor(arch, batch_size=1, backend=FileKeyBackend(key))
            for i in range(3):
                w.append({"i": i})
            w.close()
            env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
            cmd = [sys.executable, os.path.join(HERE, "cryptovalid_ingest.py"), "verify", arch, "--pubkey", pk]

            def run(*more):
                cp = subprocess.run(cmd + list(more), capture_output=True, text=True, env=env)
                return cp.returncode, json.loads(cp.stdout)
            self.assertEqual(run("--require-signature-domain")[0], 0)   # written now: tagged
            with open(key, encoding="utf-8") as f:   # the same archive as 0.27.0 signed it: no sig_domain, the bare hex
                sk = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(f.read().strip()))
            last = None
            for name in ("ledger-000000.jsonl.sth.json", "ledger.head.json"):
                path = os.path.join(arch, name)
                with open(path, encoding="utf-8") as f:
                    doc = json.load(f)
                doc.pop("sig_domain")
                if name.endswith("head.json"):
                    doc["last_sth_sha256"] = last
                doc["signature"] = base64.b64encode(sk.sign(I._sth_canonical_hash(doc).encode())).decode()
                last = I._sth_canonical_hash(doc)
                with open(path, "w", encoding="utf-8") as f:
                    json.dump(doc, f)
            rc, r = run()
            self.assertEqual((rc, r["ok"]), (0, True), r["failures"])
            self.assertTrue(any(x.startswith("untagged_signatures: ledger-000000.jsonl, HEAD") for x in r["warnings"]), r["warnings"])
            rc, r = run("--require-signature-domain")
            self.assertEqual((rc, r["ok"]), (1, False))
            self.assertEqual({f["reason"] for f in r["failures"]}, {"sth_signature_domain_untagged", "head_signature_domain_untagged"})
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_the_mcp_tool_is_not_valid_when_every_signature_holds_and_the_chain_is_broken(self):
        # rule 5: `valid` is the chain AND the signatures (a `valid` made of the signatures alone survived as a mutant:
        # the tests broke the signatures, never the chain under good signatures)
        import json
        import cryptovalid_mcp as M
        import signer
        tmp = tempfile.mkdtemp()
        try:
            key = os.path.join(tmp, "k.key")
            pk = signer.keygen(key)["public_key_hex"]
            signed = os.path.join(tmp, "signed.jsonl")
            signer.sign_ledger(os.path.join(HERE, "examples", "sample_ledger.jsonl"), signed, key)
            with open(signed, encoding="utf-8") as f:
                lines = f.read().splitlines()
            cut = os.path.join(tmp, "cut.jsonl")
            with open(cut, "w", encoding="utf-8") as f:   # an entry of the middle removed: each remaining entry is signed
                f.write("\n".join(lines[:1] + lines[2:]) + "\n")

            def call(path):
                r = M.handle({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                              "params": {"name": "verify_ledger", "arguments": {"path": path, "expected_pubkey_hex": pk}}})
                return json.loads(r["result"]["content"][0]["text"])
            out = call(signed)
            self.assertEqual((out["valid"], out["result"]["verdict"], out["signatures"]["ok"]), (True, "PASS", True))
            out = call(cut)
            self.assertEqual((out["result"]["verdict"], out["signatures"]["ok"]), ("FAIL", True), out["signatures"])
            self.assertIs(out["valid"], False)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_the_mcp_tool_names_a_ledger_that_is_not_utf8(self):
        # rule 5: the signatures are checked on the bytes the chain was checked on; bytes that are not UTF-8 are one
        # failure `not_utf8`, not "no entry" (an empty list there survived as a mutant)
        import json
        import cryptovalid_mcp as M
        tmp = tempfile.mkdtemp()
        try:
            path = os.path.join(tmp, "x.jsonl")
            with open(path, "wb") as f:
                f.write(b'{"a": "\xff"}\n')
            r = M.handle({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                          "params": {"name": "verify_ledger", "arguments": {"path": path, "expected_pubkey_hex": "00" * 32}}})
            out = json.loads(r["result"]["content"][0]["text"])
            self.assertEqual((out["valid"], out["result"]["verdict"], out["signatures"]["checked"], out["signatures"]["ok"]),
                             (False, "FAIL", True, False))
            self.assertEqual((out["signatures"]["total"], out["signatures"]["failures"]), (1, [{"idx": 0, "reason": "not_utf8"}]))
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_under_a_tsa_pin_a_pack_signed_by_the_pinned_keys_is_not_valid_without_a_token(self):
        # rule 4 with rule 7: admitted, not valid, nothing contradicted, producer_signature verified
        import evidence_pack as EP
        import signer
        from cryptography import x509
        from cryptography.hazmat.primitives import serialization
        from test_lotl import make_signer
        tmp = tempfile.mkdtemp()
        try:
            key = os.path.join(tmp, "k.key")
            pk = signer.keygen(key)["public_key_hex"]
            led = os.path.join(tmp, "s.jsonl")
            signer.sign_ledger(os.path.join(HERE, "examples", "sample_ledger.jsonl"), led, key)
            pack = os.path.join(tmp, "pack")
            EP.build_pack([led], pack, sign_key=key)
            pem = os.path.join(tmp, "tsa.pem")
            with open(pem, "wb") as f:
                f.write(x509.load_der_x509_certificate(make_signer(name="a tsa")[1]).public_bytes(serialization.Encoding.PEM))
            r = EP.verify_pack(pack, manifest_signer_hex=pk, signer_pubkey_hex=pk)
            self.assertEqual((r["valid"], r["states"]["producer_signature"]["state"]), (True, "verified"))
            r = EP.verify_pack(pack, manifest_signer_hex=pk, signer_pubkey_hex=pk, tsa_certs=[pem])
            states = r["states"]
            self.assertEqual((r["valid"], r["admission"]), (False, "admitted"))
            self.assertEqual([s for s in states if states[s]["state"] == "contradicted"], [])
            self.assertEqual((states["producer_signature"]["state"], states["producer_signature"]["reasons"]), ("verified", []))
            self.assertEqual((states["time_anchor"]["state"], states["time_anchor"]["reasons"]), ("not_evaluated", ["not_present"]))
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


class TestAnEmptyPinOfThePackVerifier(unittest.TestCase):
    """§22 rule 4: a pin given to verify_pack decides `valid`; an empty one is not "no pin" (as §17 rule 4)."""

    def setUp(self):
        import evidence_pack as EP
        self.EP = EP
        self.tmp = tempfile.mkdtemp()
        self.pack = os.path.join(self.tmp, "pack")
        EP.build_pack([os.path.join(HERE, "examples", "sample_ledger.jsonl")], self.pack)   # unsigned

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_no_pin_control(self):
        self.assertIs(self.EP.verify_pack(self.pack)["valid"], True)
        self.assertIs(self.EP.verify_pack(self.pack, signer_pubkey_hex=None, manifest_signer_hex=None, pq_pubkey_b64=None)["valid"], True)

    def test_an_empty_pin_is_refused_before_the_pack_is_read(self):
        for name in ("signer_pubkey_hex", "manifest_signer_hex", "pq_pubkey_b64"):
            for empty in ("", b"", 0, [], False):
                for where in (self.pack, os.path.join(self.tmp, "no such pack")):
                    with self.assertRaises(ValueError) as c:
                        self.EP.verify_pack(where, **{name: empty})
                    self.assertEqual(str(c.exception), f"{name}: a pin is a key, a non-empty string; None for no pin (an empty pin pins nothing)")

    def test_a_pin_of_another_type_is_refused(self):
        for bad in (b"00" * 32, 5, ["00" * 32], {"k": 1}):
            with self.assertRaises(ValueError):
                self.EP.verify_pack(self.pack, signer_pubkey_hex=bad)

    def test_a_real_pin_on_the_unsigned_pack_is_not_valid(self):
        self.assertIs(self.EP.verify_pack(self.pack, signer_pubkey_hex="00" * 32)["valid"], False)


if __name__ == "__main__":
    unittest.main()
