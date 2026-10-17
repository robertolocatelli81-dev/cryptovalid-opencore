#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Roberto Locatelli
"""Standalone test of the eIDAS LOTL validation (offline-deterministic; live test opt-in)."""
import base64
import hashlib
import os
import sys
import unittest
_HERE = os.path.dirname(os.path.abspath(__file__)); sys.path.insert(0, _HERE)
import cryptovalid_lotl as L  # noqa: E402

_CERT_A = base64.b64encode(b"QUALIFIED-QTST-CERT").decode()      # stand-in DER bytes
_CERT_B = base64.b64encode(b"SOME-OTHER-SERVICE").decode()
_TL = f"""<TrustServiceStatusList xmlns="http://uri.etsi.org/02231/v2#">
 <TSPService><ServiceInformation>
   <ServiceTypeIdentifier>http://uri.etsi.org/TrstSvc/Svctype/TSA/QTST</ServiceTypeIdentifier>
   <ServiceStatus>http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted</ServiceStatus>
   <StatusStartingTime>2016-07-01T00:00:00Z</StatusStartingTime>
   <ServiceDigitalIdentity><DigitalId><X509Certificate>{_CERT_A}</X509Certificate></DigitalId></ServiceDigitalIdentity>
 </ServiceInformation></TSPService>
 <TSPService><ServiceInformation>
   <ServiceTypeIdentifier>http://uri.etsi.org/TrstSvc/Svctype/CA/QC</ServiceTypeIdentifier>
   <ServiceStatus>http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted</ServiceStatus>
   <ServiceDigitalIdentity><DigitalId><X509Certificate>{_CERT_B}</X509Certificate></DigitalId></ServiceDigitalIdentity>
 </ServiceInformation></TSPService>
</TrustServiceStatusList>""".encode()

class TestLOTL(unittest.TestCase):
    def test_extract_only_qualified_qtst(self):
        fprs = L.qtst_fingerprints(_TL)
        fpr_a = hashlib.sha256(b"QUALIFIED-QTST-CERT").hexdigest()
        fpr_b = hashlib.sha256(b"SOME-OTHER-SERVICE").hexdigest()
        self.assertIn(fpr_a, fprs)          # QTST + granted -> extracted
        self.assertNotIn(fpr_b, fprs)       # CA/QC service -> excluded
        self.assertEqual(len(fprs), 1)
    def test_matching_logic(self):
        fpr = hashlib.sha256(b"QUALIFIED-QTST-CERT").hexdigest()
        self.assertTrue(bool({fpr} & {fpr}))
        self.assertFalse(bool({fpr} & set()))
    def test_member_state_filter_uses_tld_not_substring(self):
        # bug trovato 2026-08-16 nella validazione QTSP live: 'ES' matchava
        # 'fil-ES-' dentro qualunque URL (crc.bg/filES, messervicES.cyber.gouv.fr…)
        self.assertEqual(L._ms_of_url("https://crc.bg/files/_en/TSL_BG.xml"), "BG")
        self.assertEqual(L._ms_of_url("https://messervices.cyber.gouv.fr/visas/tl.xml"), "FR")
        self.assertEqual(L._ms_of_url("https://tsl.digital.gob.es/TSL.xml"), "ES")
        self.assertNotIn(L._ms_of_url("https://crc.bg/files/_en/TSL_BG.xml"), {"ES", "NL"})

    def test_lotl_pointers_skip_self(self):
        def ptr(loc, mime, typ="EUgeneric"):
            return (f"<OtherTSLPointer><TSLLocation>{loc}</TSLLocation><AdditionalInformation>"
                    f"<OtherInformation><TSLType>http://uri.etsi.org/TrustedList/TSLType/{typ}</TSLType></OtherInformation>"
                    f"<OtherInformation><a:MimeType>{mime}</a:MimeType></OtherInformation>"
                    "</AdditionalInformation></OtherTSLPointer>").replace("TrustedList/TSLType", "TrstSvc/TrustedList/TSLType")
        x, pdf = "application/vnd.etsi.tsl+xml", "application/pdf"
        lotl = ('<TrustServiceStatusList xmlns="http://uri.etsi.org/02231/v2#" xmlns:a="http://uri.etsi.org/02231/v2/'
                'additionaltypes#"><SchemeInformation><PointersToOtherTSL>'
                + ptr("https://ec.europa.eu/tools/lotl/eu-lotl.xml", x, "EUlistofthelists")
                + ptr("https://mirror.example/eu-lotl-copy.xml", x, "EUlistofthelists")
                + ptr("https://tsl.belgium.be/tsl-be-v6.xml", x) + ptr("https://tsl.belgium.be/tsl-be-v6.xml", x)
                + ptr("https://tsl.gov.cz/publ/TSL_CZ.pdf", pdf) + ptr("https://tsl.gov.cz/publ/TSL_CZ.xtsl", x)
                + ptr("https://www.digst.dk/TSLDK_v6xml", x)
                + "</PointersToOtherTSL></SchemeInformation></TrustServiceStatusList>").encode()
        # the XML lists, whatever their file name ends with (0.20.1: a regex on ".xml" dropped CZ and DK); not the PDFs,
        # not the LOTL itself
        self.assertEqual(L.lotl_pointers(lotl), ["https://tsl.belgium.be/tsl-be-v6.xml",
                                                 "https://tsl.gov.cz/publ/TSL_CZ.xtsl", "https://www.digst.dk/TSLDK_v6xml"])
        with self.assertRaises(ValueError):
            L.lotl_pointers(b"<x><TSLLocation>https://tsl.belgium.be/tsl-be-v6.xml</TSLLocation></x>")   # not a TSL
    @unittest.skipUnless(os.environ.get("CRYPTOVALID_LIVE_TSA"), "set CRYPTOVALID_LIVE_TSA=1 for live LOTL/TSA test")
    def test_live_freetsa_not_qualified(self):
        import cryptovalid_tsa as T
        import urllib.request
        d = hashlib.sha256(b"live").digest()
        _, token, _ = T.request_timestamp(d, "https://freetsa.org/tsr", timeout=25)
        qual = L.qtst_fingerprints(urllib.request.urlopen("https://tsl.belgium.be/tsl-be-v6.xml", timeout=40).read())
        self.assertFalse(L.is_qualified(token, qual))   # freetsa is NOT eIDAS-qualified

_C1 = base64.b64encode(b"SERVICE-1-CERT").decode()
_C2 = base64.b64encode(b"SERVICE-2-CERT").decode()
_C3 = base64.b64encode(b"HISTORY-ONLY-CERT").decode()
_QTST = "http://uri.etsi.org/TrstSvc/Svctype/TSA/QTST"
_QC = "http://uri.etsi.org/TrstSvc/Svctype/CA/QC"
_ST = "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/"


def _svc(typ, status, start, cert, history=()):
    hist = "".join(f"""<ServiceHistoryInstance><ServiceTypeIdentifier>{t}</ServiceTypeIdentifier>
      <ServiceStatus>{_ST}{st}</ServiceStatus><StatusStartingTime>{sst}</StatusStartingTime>
      <ServiceDigitalIdentity><DigitalId>{f"<X509Certificate>{hc}</X509Certificate>" if hc else "<X509SKI>AAAA</X509SKI>"}</DigitalId></ServiceDigitalIdentity>
      </ServiceHistoryInstance>""" for t, st, sst, hc in history)
    return f"""<TSPService><ServiceInformation><ServiceTypeIdentifier>{typ}</ServiceTypeIdentifier>
      <ServiceStatus>{_ST}{status}</ServiceStatus><StatusStartingTime>{start}</StatusStartingTime>
      <ServiceDigitalIdentity><DigitalId><X509Certificate>{cert}</X509Certificate></DigitalId></ServiceDigitalIdentity>
      </ServiceInformation>{f"<ServiceHistory>{hist}</ServiceHistory>" if hist else ""}</TSPService>"""


def _tl(*svcs):
    return ('<TrustServiceStatusList xmlns="http://uri.etsi.org/02231/v2#"><TrustServiceProviderList><TrustServiceProvider>'
            "<TSPServices>" + "".join(svcs) + "</TSPServices></TrustServiceProvider></TrustServiceProviderList>"
            "</TrustServiceStatusList>").encode()


def _fp(b):
    return hashlib.sha256(b).hexdigest()


class TestCurrentStatusAndHistory(unittest.TestCase):
    """ETSI TS 119 612 (12/10/2026, 0.20.2): the status is ServiceInformation/ServiceStatus (current); ServiceHistory holds the
    earlier ones, each with its StatusStartingTime. Until 0.20.1 the text "Svcstatus/granted" anywhere in the TSPService
    made it qualified, its history included; on the 0.20.1 code test_withdrawn_today_granted_in_history fails."""
    WITHDRAWN = _svc(_QTST, "withdrawn", "2024-05-01T00:00:00Z", _C2,
                     history=[(_QTST, "granted", "2017-03-01T00:00:00Z", None)])

    def test_granted_today_is_qualified(self):                       # positive control
        self.assertEqual(L.qtst_fingerprints(_tl(_svc(_QTST, "granted", "2017-03-01T00:00:00Z", _C1))), {_fp(b"SERVICE-1-CERT")})

    def test_withdrawn_today_granted_in_history_is_not_qualified_today(self):
        self.assertEqual(L.qtst_fingerprints(_tl(self.WITHDRAWN)), set())

    def test_a_status_published_for_the_future_applies_from_its_start(self):
        # one real list (12/10/2026) publishes withdrawals starting in 2027-2029: granted until then
        from datetime import datetime, timezone
        sched = _tl(_svc(_QTST, "withdrawn", "2999-01-01T00:00:00Z", _C1, history=[(_QTST, "granted", "2020-01-01T00:00:00Z", None)]))
        self.assertEqual(L.qtst_fingerprints(sched, now=datetime(2026, 10, 12, tzinfo=timezone.utc)), {_fp(b"SERVICE-1-CERT")})
        self.assertEqual(L.qtst_fingerprints(sched, now=datetime(2999, 1, 1, tzinfo=timezone.utc)), set())

    def test_type_and_certs_come_from_their_own_block(self):
        # QTST only in the history, CA/QC today: not a qualified timestamp service today
        qc_now = _svc(_QC, "granted", "2020-01-01T00:00:00Z", _C1, history=[(_QTST, "granted", "2017-01-01T00:00:00Z", _C3)])
        self.assertEqual(L.qtst_fingerprints(_tl(qc_now)), set())
        # a certificate that appears only in a history instance is not the current identity
        granted = _svc(_QTST, "granted", "2020-01-01T00:00:00Z", _C1, history=[(_QTST, "granted", "2017-01-01T00:00:00Z", _C3)])
        self.assertEqual(L.qtst_fingerprints(_tl(granted)), {_fp(b"SERVICE-1-CERT")})

    def test_status_at_the_token_time(self):
        from datetime import datetime, timezone
        tl = _tl(self.WITHDRAWN)
        at = lambda s: datetime.fromisoformat(s).replace(tzinfo=timezone.utc)   # noqa: E731
        self.assertEqual(L.qtst_fingerprints_at(tl, at("2020-06-01T00:00:00")), {_fp(b"SERVICE-2-CERT")})   # granted then
        self.assertEqual(L.qtst_fingerprints_at(tl, at("2024-05-01T00:00:00")), set())     # withdrawn from that instant
        self.assertEqual(L.qtst_fingerprints_at(tl, at("2024-04-30T23:59:59")), {_fp(b"SERVICE-2-CERT")})
        self.assertEqual(L.qtst_fingerprints_at(tl, at("2017-03-01T00:00:00")), {_fp(b"SERVICE-2-CERT")})   # start inclusive
        self.assertEqual(L.qtst_fingerprints_at(tl, at("2017-02-28T23:59:59")), set())     # before any entry
        with self.assertRaises(ValueError):
            L.qtst_fingerprints_at(tl, datetime(2020, 1, 1))                              # naive datetime refused
        bad = _tl(_svc(_QTST, "granted", "not-a-date", _C1))
        self.assertEqual(L.qtst_fingerprints_at(bad, at("2020-01-01T00:00:00")), set())    # unordered timeline: never
        self.assertEqual(L.qtst_fingerprints(bad), set())       # StatusStartingTime is mandatory (TS 119 612): missing = not counted

    def test_closed_input(self):
        with self.assertRaises(ValueError):
            L.qtst_fingerprints(b'<!DOCTYPE x [<!ENTITY a "b">]><TrustServiceStatusList xmlns="http://uri.etsi.org/02231/v2#"/>')
        with self.assertRaises(ValueError):   # a document type declaration with no entity
            L.qtst_fingerprints(b'<!DOCTYPE TrustServiceStatusList><TrustServiceStatusList xmlns="http://uri.etsi.org/02231/v2#"/>')
        with self.assertRaises(ValueError):   # a byte that is not UTF-8, no declaration
            L.qtst_fingerprints(_tl(_svc(_QTST, "granted", "2017-03-01T00:00:00Z", _C1)).replace(b"<TSPServices>", b"<!-- \xe9 --><TSPServices>"))
        with self.assertRaises(ValueError):
            L.qtst_fingerprints(b"<TrustServiceStatusList/>")                # no ETSI namespace
        with self.assertRaises(ValueError):
            L.qtst_fingerprints(b"<TrustServiceStatusList")                  # not well-formed
        other_ns = _tl(_svc(_QTST, "granted", "2017-03-01T00:00:00Z", _C1)).replace(b"02231/v2#", b"02231/v9#")
        with self.assertRaises(ValueError):
            L.qtst_fingerprints(other_ns)
        # the same DTD in a list encoded as UTF-16 (a byte search for "<!DOCTYPE" does not see it): refused, and a UTF-16
        # list without a DTD too (TS 119 612: XML trusted lists are UTF-8)
        doc = _tl(_svc(_QTST, "&g;", "2017-03-01T00:00:00Z", _C1)).decode()
        dtd16 = ('<?xml version="1.0" encoding="UTF-16"?><!DOCTYPE TrustServiceStatusList [<!ENTITY g "granted">]>'
                 + doc).encode("utf-16")
        with self.assertRaises(ValueError):
            L.qtst_fingerprints(dtd16)
        plain16 = ('<?xml version="1.0" encoding="UTF-16"?>' + _tl(_svc(_QTST, "granted", "2017-03-01T00:00:00Z", _C1)).decode()).encode("utf-16")
        with self.assertRaises(ValueError):
            L.qtst_fingerprints(plain16)
        with self.assertRaises(ValueError):
            L.qtst_fingerprints(_tl(_svc(_QTST, "granted", "2017-03-01T00:00:00Z", _C1)).decode().encode("utf-16-le"))   # no BOM
        latin = b'<?xml version="1.0" encoding="ISO-8859-1"?>' + _tl(_svc(_QTST, "granted", "2017-03-01T00:00:00Z", _C1))
        with self.assertRaises(ValueError):
            L.qtst_fingerprints(latin)
        # positive control: the same list in UTF-8, with a declaration and a BOM, is read
        ok = b"\xef\xbb\xbf" + b'<?xml version="1.0" encoding="UTF-8"?>' + _tl(_svc(_QTST, "granted", "2017-03-01T00:00:00Z", _C1))
        self.assertEqual(L.qtst_fingerprints(ok), {_fp(b"SERVICE-1-CERT")})

    def test_closed_rows(self):
        from datetime import datetime, timezone
        at = datetime(2026, 10, 12, tzinfo=timezone.utc)
        # StatusStartingTime only as TS 119 612 5.1.3 writes it (YYYY-MM-DDThh:mm:ssZ): any other form is not ordered, so
        # the service is not counted, on every Python version (fromisoformat took some of these on 3.11+ only)
        self.assertEqual(L.qtst_fingerprints_at(_tl(_svc(_QTST, "granted", "2017-03-01T00:00:00Z", _C1)), at), {_fp(b"SERVICE-1-CERT")})
        for bad in ("2017-03-01T00:00:00", "2017-03-01T00:00:00+01:00", "2017-03-01T00:00:00.5Z", "20170301T000000Z",
                    "2017-03-01", "2017-03-01 00:00:00Z", "2017-W09-3T00:00:00Z", "2017-13-01T00:00:00Z",
                    "\uff12\uff10\uff11\uff17-03-01T00:00:00Z", "2017-03-01T00:00:00Z\n2017"):
            self.assertEqual(L.qtst_fingerprints_at(_tl(_svc(_QTST, "granted", bad, _C1)), at), set(), bad)
        # the identity is the ServiceInformation's (TS 119 615 PRO-4.3.4-03): a certificate of the history entry in force
        # is not added
        sched = _tl(_svc(_QTST, "withdrawn", "2999-01-01T00:00:00Z", _C1, history=[(_QTST, "granted", "2017-01-01T00:00:00Z", _C3)]))
        self.assertEqual(L.qtst_fingerprints_at(sched, at), {_fp(b"SERVICE-1-CERT")})
        # whitespace: a base64 certificate folded on lines, URIs and times padded, are read as the lists write them
        folded = _C1[:4] + "\n  " + _C1[4:]
        padded = _tl(_svc(_QTST, "granted", "2017-03-01T00:00:00Z", folded)).replace(
            b"<ServiceStatus>", b"<ServiceStatus>\n ").replace(b"<StatusStartingTime>", b"<StatusStartingTime> ")
        self.assertEqual(L.qtst_fingerprints_at(padded, at), {_fp(b"SERVICE-1-CERT")})
        # a TSPService without ServiceInformation is not read from its other children
        no_si = _tl(_svc(_QTST, "granted", "2017-03-01T00:00:00Z", _C1)).replace(b"<ServiceInformation>", b"<Other>").replace(
            b"</ServiceInformation>", b"</Other>")
        self.assertEqual(L.qtst_fingerprints_at(no_si, at), set())
        flat = _tl(_svc(_QTST, "granted", "2017-03-01T00:00:00Z", _C1)).replace(b"<ServiceInformation>", b"").replace(
            b"</ServiceInformation>", b"")   # the fields straight under TSPService, no ServiceInformation
        self.assertEqual(L.qtst_fingerprints_at(flat, at), set())

    def test_cache_of_another_rule_is_not_read(self):
        import json
        import tempfile
        d = tempfile.mkdtemp(); self.addCleanup(__import__("shutil").rmtree, d, True)
        cache = os.path.join(d, "c.json")
        json.dump({"fingerprints": ["ab" * 32], "coverage": ["x"]}, open(cache, "w"))   # 0.20.1 format, no rule
        other = os.path.join(d, "o.json")   # fresh, but another rule
        with open(other, "w") as f:
            json.dump({"rule": "x/0", "built_at": __import__("datetime").datetime.now(__import__("datetime").timezone.utc)
                       .strftime("%Y-%m-%dT%H:%M:%SZ"), "fingerprints": ["cd" * 32], "coverage": ["x"]}, f)
        calls = []
        orig = L._get
        L._get = lambda url, timeout=45: (calls.append(url), b'<TrustServiceStatusList xmlns="http://uri.etsi.org/02231/v2#"/>')[1]
        try:
            fprs, cov = L.load_qualified_fingerprints(cache_path=cache)
            fprs2, _ = L.load_qualified_fingerprints(cache_path=other)
        finally:
            L._get = orig
        self.assertEqual(calls, [L.LOTL_URL, L.LOTL_URL]); self.assertEqual(fprs, set()); self.assertEqual(fprs2, set())

    def test_cache_older_than_its_max_age_is_not_read(self):
        # the set is the status in force when the cache was built: the ingest keeps it in ~/.cache/cryptovalid, so without an
        # age a cache built in 2026 would still call a service qualified after its withdrawal took effect
        import json
        import tempfile
        from datetime import datetime, timedelta, timezone
        d = tempfile.mkdtemp(); self.addCleanup(__import__("shutil").rmtree, d, True)
        cache = os.path.join(d, "c.json")
        empty = b'<TrustServiceStatusList xmlns="http://uri.etsi.org/02231/v2#"/>'
        orig = L._get
        try:
            for built, used in ((timedelta(hours=1), True), (timedelta(days=2), False), (timedelta(days=-1), False), (None, False)):
                rec = {"rule": L.RULE, "fingerprints": ["ab" * 32], "coverage": ["x"]}
                if built is not None:
                    rec["built_at"] = (datetime.now(timezone.utc) - built).strftime("%Y-%m-%dT%H:%M:%SZ")
                with open(cache, "w") as f:
                    json.dump(rec, f)
                calls = []
                L._get = lambda url, timeout=45: (calls.append(url), empty)[1]
                fprs, _cov = L.load_qualified_fingerprints(cache_path=cache)
                self.assertEqual(fprs == {"ab" * 32}, used, built)
                self.assertEqual(calls == [], used, built)
                if not used:
                    with open(cache) as f:
                        self.assertEqual(json.load(f)["fingerprints"], [])   # rebuilt and rewritten, with its built_at
        finally:
            L._get = orig
        self.assertEqual(json.load(open(cache))["rule"], L.RULE)
        self.assertEqual(L.load_qualified_fingerprints(cache_path=cache)[0], set())   # now read from the cache


class TestHistoryOrder(unittest.TestCase):
    """ETSI TS 119 615 PRO-4.3.4-03A (0.21.0): for a QTST service, ServiceHistoryInstance entries not in descending order
    of StatusStartingTime (TS 119 612 5.5.10), or two with the same StatusStartingTime, are an error: the service is not
    counted and its certificates are named. Until 0.20.3 the first entry of a tie was taken (counted)."""
    AT = __import__("datetime").datetime(2026, 10, 14, tzinfo=__import__("datetime").timezone.utc)
    F1 = _fp(b"SERVICE-1-CERT")

    def test_duplicate_history_start_is_an_error(self):
        for order in ((("granted",) * 1 + ("withdrawn",)), ("withdrawn", "granted")):
            tl = _tl(_svc(_QTST, "granted", "2026-01-01T00:00:00Z", _C1,
                          history=[(_QTST, order[0], "2020-01-01T00:00:00Z", None), (_QTST, order[1], "2020-01-01T00:00:00Z", None)]))
            self.assertEqual(L.qtst_fingerprints(tl, now=self.AT), set(), order)   # 0.20.3: {F1} (the old API fails first)
            st = L.qtst_status_at(tl, self.AT)
            self.assertEqual(st, {"granted": set(), "errors": {self.F1: L.HISTORY_DUPLICATE_START}}, order)

    def test_history_in_ascending_order_is_an_error(self):
        tl = _tl(_svc(_QTST, "granted", "2026-01-01T00:00:00Z", _C1,
                      history=[(_QTST, "withdrawn", "2018-01-01T00:00:00Z", None), (_QTST, "granted", "2020-01-01T00:00:00Z", None)]))
        self.assertEqual(L.qtst_fingerprints_at(tl, self.AT), set())   # 0.20.3: {F1}
        self.assertEqual(L.qtst_status_at(tl, self.AT)["errors"], {self.F1: L.HISTORY_NOT_ORDERED})

    def test_controls(self):
        # descending history: no error, counted (positive control)
        ok = _tl(_svc(_QTST, "granted", "2026-01-01T00:00:00Z", _C1,
                      history=[(_QTST, "withdrawn", "2020-01-01T00:00:00Z", None), (_QTST, "granted", "2018-01-01T00:00:00Z", None)]))
        self.assertEqual(L.qtst_status_at(ok, self.AT), {"granted": {self.F1}, "errors": {}})
        # ServiceInformation and one history entry with the same start: not 03A; the ServiceInformation applies (03 b)
        tie = _tl(_svc(_QTST, "granted", "2020-01-01T00:00:00Z", _C1, history=[(_QTST, "withdrawn", "2020-01-01T00:00:00Z", None)]))
        self.assertEqual(L.qtst_status_at(tie, self.AT), {"granted": {self.F1}, "errors": {}})
        tie_w = _tl(_svc(_QTST, "withdrawn", "2020-01-01T00:00:00Z", _C1, history=[(_QTST, "granted", "2020-01-01T00:00:00Z", None)]))
        self.assertEqual(L.qtst_status_at(tie_w, self.AT), {"granted": set(), "errors": {}})
        # a service that is not QTST is outside the procedure (its certificate is never a QTST match)
        qc = _tl(_svc(_QC, "granted", "2026-01-01T00:00:00Z", _C1,
                      history=[(_QC, "granted", "2020-01-01T00:00:00Z", None), (_QC, "withdrawn", "2020-01-01T00:00:00Z", None)]))
        self.assertEqual(L.qtst_status_at(qc, self.AT), {"granted": set(), "errors": {}})
        # one error does not hide another service of the same list
        both = _tl(_svc(_QTST, "granted", "2026-01-01T00:00:00Z", _C1,
                        history=[(_QTST, "granted", "2020-01-01T00:00:00Z", None), (_QTST, "granted", "2020-01-01T00:00:00Z", None)]),
                   _svc(_QTST, "granted", "2017-03-01T00:00:00Z", _C2))
        self.assertEqual(L.qtst_status_at(both, self.AT), {"granted": {_fp(b"SERVICE-2-CERT")},
                                                             "errors": {self.F1: L.HISTORY_DUPLICATE_START}})
        # the same certificate in a service in error and in a good one: the error wins (03A stops the procedure for it)
        shared = _tl(_svc(_QTST, "granted", "2026-01-01T00:00:00Z", _C1,
                          history=[(_QTST, "granted", "2020-01-01T00:00:00Z", None), (_QTST, "granted", "2020-01-01T00:00:00Z", None)]),
                     _svc(_QTST, "granted", "2017-03-01T00:00:00Z", _C1))
        self.assertEqual(L.qtst_status_at(shared, self.AT), {"granted": set(), "errors": {self.F1: L.HISTORY_DUPLICATE_START}})
        with self.assertRaises(ValueError):
            L.qtst_status_at(ok, __import__("datetime").datetime(2020, 1, 1))

    def test_qualification_is_three_valued(self):
        orig = L.token_cert_fingerprints
        L.token_cert_fingerprints = lambda tok: {"ab" * 32}
        try:
            self.assertEqual(L.qualification(b"t", {"ab" * 32}, {}), ("qualified", None))
            self.assertEqual(L.qualification(b"t", set(), {}), ("not_qualified", None))
            self.assertEqual(L.qualification(b"t", set(), None), ("not_qualified", None))
            self.assertEqual(L.qualification(b"t", set(), {"ab" * 32: "history_not_ordered u"}), ("indeterminate", "history_not_ordered u"))
            self.assertEqual(L.qualification(b"t", set(), {"cd" * 32: "x"}), ("not_qualified", None))
        finally:
            L.token_cert_fingerprints = orig

    def test_loader_names_the_errors_and_caches_them(self):
        import json
        import tempfile
        d = tempfile.mkdtemp(); self.addCleanup(__import__("shutil").rmtree, d, True)
        cache = os.path.join(d, "c.json")
        lotl = (b'<TrustServiceStatusList xmlns="http://uri.etsi.org/02231/v2#" xmlns:a="http://uri.etsi.org/02231/v2/additionaltypes#">'
                b'<SchemeInformation><PointersToOtherTSL><OtherTSLPointer><TSLLocation>https://tl.example/x.xml</TSLLocation>'
                b'<AdditionalInformation><OtherInformation><TSLType>http://uri.etsi.org/TrstSvc/TrustedList/TSLType/EUgeneric</TSLType>'
                b'</OtherInformation><OtherInformation><a:MimeType>application/vnd.etsi.tsl+xml</a:MimeType></OtherInformation>'
                b'</AdditionalInformation></OtherTSLPointer></PointersToOtherTSL></SchemeInformation></TrustServiceStatusList>')
        tl = _tl(_svc(_QTST, "granted", "2026-01-01T00:00:00Z", _C1,
                      history=[(_QTST, "granted", "2020-01-01T00:00:00Z", None), (_QTST, "granted", "2020-01-01T00:00:00Z", None)]),
                 _svc(_QTST, "granted", "2017-03-01T00:00:00Z", _C2))
        orig = L._get
        L._get = lambda url, timeout=45: lotl if url == L.LOTL_URL else tl
        try:
            fprs, cov, errs = L.load_qualified_status(cache_path=cache)
            # the certificate in error is granted by another list: the error still wins
            two = lotl.replace(b"</PointersToOtherTSL>", lotl[lotl.index(b"<OtherTSLPointer>"):lotl.index(b"</PointersToOtherTSL>")]
                               .replace(b"tl.example/x.xml", b"tl.example/y.xml") + b"</PointersToOtherTSL>")
            good = _tl(_svc(_QTST, "granted", "2017-03-01T00:00:00Z", _C1))
            L._get = lambda url, timeout=45: two if url == L.LOTL_URL else (tl if url.endswith("x.xml") else good)
            f2, c2, e2 = L.load_qualified_status(cache_path=os.path.join(d, "c2.json"))
            self.assertEqual((f2, len(c2), e2), ({_fp(b"SERVICE-2-CERT")}, 2, errs))
        finally:
            L._get = orig
        self.assertEqual(fprs, {_fp(b"SERVICE-2-CERT")}); self.assertEqual(cov, ["https://tl.example/x.xml"])
        self.assertEqual(errs, {self.F1: "history_duplicate_start https://tl.example/x.xml"})
        rec = json.load(open(cache))
        self.assertEqual(rec["rule"], L.RULE); self.assertEqual(rec["history_errors"], errs)
        self.assertEqual(L.load_qualified_status(cache_path=cache), (fprs, cov, errs))   # read back from the cache
        self.assertEqual(L.load_qualified_fingerprints(cache_path=cache), (fprs, cov))
        self.assertTrue(L.RULE.endswith("/2"))   # a cache of rule /1 (0.20.2-0.20.3) is rebuilt


if __name__ == "__main__":
    unittest.main(verbosity=2)
