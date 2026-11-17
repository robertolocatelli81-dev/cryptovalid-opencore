#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Roberto Locatelli
"""Write the currency table a caller pins for SPEC §18 ("Currencies") from the caller's OWN download of ISO 4217 list
one, the XML file its maintenance agency publishes. This repository ships no currency table: whoever downloads list
one accepts its publisher's terms of use; this script only turns that file into the closed JSON form.

    python3 tools/iso4217_table.py list-one.xml > iso4217.json

Rule: every `CcyNtry` whose `Ccy` is three capital letters and whose `CcyMnrUnts` is an integer 0 to 4 (entries with
"N.A." are left out); a code listed twice with two different minor units is an error. Output:
{"format": "cryptovalid-iso4217-table/1", "source": "ISO 4217 list one, published <Pblshd>, sha256 <of the file>",
 "currencies": {code: minor units}}, codes sorted."""
import hashlib
import json
import re
import sys
import xml.etree.ElementTree as ET


def table(data: bytes) -> dict:
    root = ET.fromstring(data)
    if root.tag != "ISO_4217" or not root.get("Pblshd"):
        raise ValueError("not ISO 4217 list one (root ISO_4217 with Pblshd)")
    cur = {}
    for e in root.iter("CcyNtry"):
        code, units = (e.findtext("Ccy") or "").strip(), (e.findtext("CcyMnrUnts") or "").strip()
        if not code:
            continue                                   # an entry without a currency (e.g. Antarctica)
        if not re.fullmatch(r"[A-Z]{3}", code):
            raise ValueError(f"Ccy {code!r} is not three capital letters")
        if not re.fullmatch(r"[0-4]", units):
            continue                                   # "N.A." (precious metals, SDR, test code...)
        if cur.get(code, int(units)) != int(units):
            raise ValueError(f"{code}: two different minor units ({cur[code]}, {units})")
        cur[code] = int(units)
    if not cur:
        raise ValueError("no currency with numeric minor units")
    return {"format": "cryptovalid-iso4217-table/1",
            "source": f"ISO 4217 list one, published {root.get('Pblshd')}, sha256 {hashlib.sha256(data).hexdigest()}",
            "currencies": dict(sorted(cur.items()))}


if __name__ == "__main__":
    with open(sys.argv[1], "rb") as f:
        sys.stdout.write(json.dumps(table(f.read()), indent=1) + "\n")
