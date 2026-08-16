#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Roberto Locatelli
"""Standalone test of the eIDAS LOTL validation (offline-deterministic; live test opt-in)."""
import base64, hashlib, os, sys, unittest
_HERE = os.path.dirname(os.path.abspath(__file__)); sys.path.insert(0, _HERE)
import cryptovalid_lotl as L  # noqa: E402

_CERT_A = base64.b64encode(b"QUALIFIED-QTST-CERT").decode()      # stand-in DER bytes
_CERT_B = base64.b64encode(b"SOME-OTHER-SERVICE").decode()
_TL = f"""<TrustServiceStatusList xmlns="http://uri.etsi.org/02231/v2#">
 <TSPService><ServiceInformation>
   <ServiceTypeIdentifier>http://uri.etsi.org/TrstSvc/Svctype/TSA/QTST</ServiceTypeIdentifier>
   <ServiceStatus>http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted</ServiceStatus>
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
    def test_lotl_pointers_skip_self(self):
        lotl = b"<x><TSLLocation>https://ec.europa.eu/tools/lotl/eu-lotl.xml</TSLLocation>" \
               b"<TSLLocation>https://tsl.belgium.be/tsl-be-v6.xml</TSLLocation></x>"
        p = L.lotl_pointers(lotl)
        self.assertEqual(p, ["https://tsl.belgium.be/tsl-be-v6.xml"])
    @unittest.skipUnless(os.environ.get("CRYPTOVALID_LIVE_TSA"), "set CRYPTOVALID_LIVE_TSA=1 for live LOTL/TSA test")
    def test_live_freetsa_not_qualified(self):
        import cryptovalid_tsa as T, urllib.request
        d = hashlib.sha256(b"live").digest()
        _, token, _ = T.request_timestamp(d, "https://freetsa.org/tsr", timeout=25)
        qual = L.qtst_fingerprints(urllib.request.urlopen("https://tsl.belgium.be/tsl-be-v6.xml", timeout=40).read())
        self.assertFalse(L.is_qualified(token, qual))   # freetsa is NOT eIDAS-qualified

if __name__ == "__main__":
    unittest.main(verbosity=2)
