#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
"""The wheel must contain EVERY product module: pyproject lists them by hand (lesson from omega-health-companion
0.4.0 on 2026-09-13, whose wheel shipped without four modules). Red whenever a module is missing from the list."""
import os, re, unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
EXCLUDE = {"demo", "setup"}


class TestPackaging(unittest.TestCase):
    def test_every_product_module_is_packaged(self):
        with open(os.path.join(_HERE, "pyproject.toml"), encoding="utf-8") as f:
            m = re.search(r"py-modules\s*=\s*\[(.*?)\]", f.read(), re.S)
        listed = set(re.findall(r"'([A-Za-z0-9_]+)'", m.group(1)))
        on_disk = {n[:-3] for n in os.listdir(_HERE) if n.endswith(".py") and not n.startswith("test_") and n[:-3] not in EXCLUDE}
        self.assertEqual(on_disk - listed, set(), f"modules not packaged: {sorted(on_disk - listed)}")
        self.assertEqual(listed - on_disk, set(), f"listed but absent: {sorted(listed - on_disk)}")


if __name__ == "__main__":
    unittest.main()
