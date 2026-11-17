#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Roberto Locatelli
"""The currency table of the payment profile, generated from Unicode CLDR (Unicode License v3), never typed by hand.

    python3 currency_table_from_cldr.py <supplementalData.xml> <currency.xml>

Inputs: CLDR release 49 (tag release-49, commit 96e54b273d2da4ec6fbad350ba19ff23fa24a588, 2026-10-21), the files
common/supplemental/supplementalData.xml and common/validity/currency.xml; their SHA-256 is checked (a file that
differs stops the script). Rule (written in the SPEC first): the codes whose idStatus is "regular" in currency.xml, each
with the `digits` of supplementalData.xml currencyData/fractions (the DEFAULT entry when the code has none). Output: the
Python literal `{digits: "CODE CODE ..."}`, codes sorted, lines of at most 120 characters, to paste with the citation."""
import hashlib
import sys
import xml.etree.ElementTree as ET

PINS = {"supplementalData.xml": "745150ec1408d50e1a272b65654a5dd645f3e60f5cc2898b576f725b28538d1a",
        "currency.xml": "b046c1fa146666f2176275f28202196136267d50ee8d595f396655b0a8887ec7"}


def read(path, name):
    with open(path, "rb") as f:
        data = f.read()
    got = hashlib.sha256(data).hexdigest()
    if got != PINS[name]:
        sys.exit(f"{path}: sha256 {got}, CLDR 49 {name} is {PINS[name]}")
    return ET.fromstring(data)


def table(supplemental, validity):
    regular = []
    for idl in validity.iter("id"):
        if idl.get("type") == "currency" and idl.get("idStatus") == "regular":
            for tok in idl.text.split():
                if "~" in tok:   # a range such as ARL~M: ARL ARM
                    a, b = tok.split("~")
                    regular += [a[:-1] + chr(c) for c in range(ord(a[-1]), ord(b) + 1)]
                else:
                    regular.append(tok)
    fractions = {i.get("iso4217"): int(i.get("digits")) for i in supplemental.find("currencyData").find("fractions")}
    out = {}
    for code in sorted(set(regular)):
        out.setdefault(fractions.get(code, fractions["DEFAULT"]), []).append(code)
    return out


def literal(t):
    lines = ["{"]
    for d in sorted(t):
        chunks, cur = [], []
        for c in t[d]:
            if len(cur) == 26:
                chunks.append(cur)
                cur = []
            cur.append(c)
        chunks.append(cur)
        text = [" ".join(ch) + (" " if k < len(chunks) - 1 else "") for k, ch in enumerate(chunks)]
        lines.append(f"    {d}: " + "\n       ".join(f'"{x}"' for x in text) + ",")
    lines.append("}")
    return "\n".join(lines)


if __name__ == "__main__":
    t = table(read(sys.argv[1], "supplementalData.xml"), read(sys.argv[2], "currency.xml"))
    print(literal(t))
    print(f"# {sum(len(v) for v in t.values())} codes", file=sys.stderr)
