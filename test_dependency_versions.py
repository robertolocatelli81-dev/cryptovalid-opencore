"""The versions of the projects this one links to are written once, in pyproject.toml, and every other copy must say the
same (2026-10-05). The `ap2` extra names ap2-evidence-pack with a range; the CI installs it twice (the range in the main
job, the exact minimum in the floor job, so each run proves the minimum exists on the index and works); the README
states the range in words. The `sign` extra names the cryptography floor, which the floor job pins and the README
states. A copy that drifts from pyproject.toml turns this test red; on a copy of this tree with any one of them edited,
it fails (checked when it was written).
Run: python3 test_dependency_versions.py
"""
import glob
import os
import re
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))


def _read(rel):
    with open(os.path.join(HERE, rel), encoding="utf-8") as f:
        return f.read()


def extra(name):
    """The single requirement string of an extra in pyproject.toml (no tomllib: this runs on 3.9 too)."""
    m = re.search(r"^%s\s*=\s*\[\s*\"([^\"]+)\"\s*\]" % re.escape(name), _read("pyproject.toml"), re.M)
    if not m:
        raise AssertionError(f"extra {name!r} not found in pyproject.toml")
    return m.group(1)


def bounds(req, package):
    m = re.fullmatch(re.escape(package) + r">=([0-9][0-9.]*)(?:,<([0-9][0-9.]*))?", req)
    if not m:
        raise AssertionError(f"{req!r} is not of the form {package}>=X[,<Y]")
    return m.group(1), m.group(2)


def ci_mentions(package):
    out = []
    for path in sorted(glob.glob(os.path.join(HERE, ".github", "workflows", "*.yml"))):
        with open(path, encoding="utf-8") as f:
            for n, line in enumerate(f, 1):
                if "pip install" in line:
                    out += [(os.path.basename(path), n, m.group(0))
                            for m in re.finditer(re.escape(package) + r"[=<>!~][^'\" ]*", line)]
    return out


class TestDependencyVersions(unittest.TestCase):
    def test_ap2_extra_is_a_bounded_range(self):
        lo, hi = bounds(extra("ap2"), "ap2-evidence-pack")
        self.assertTrue(lo and hi, "the ap2 extra needs a minimum and an upper bound")

    def test_ci_installs_the_declared_range_or_the_exact_minimum(self):
        req = extra("ap2")
        lo, _ = bounds(req, "ap2-evidence-pack")
        seen = ci_mentions("ap2-evidence-pack")
        self.assertTrue(seen, "no CI step installs ap2-evidence-pack")
        for where, line, spec in seen:
            with self.subTest(where=where, line=line):
                self.assertIn(spec, (req, f"ap2-evidence-pack=={lo}"))
        self.assertIn(f"ap2-evidence-pack=={lo}", [s for _, _, s in seen], "no CI job runs the declared minimum")

    def test_readme_states_the_same_range(self):
        lo, hi = bounds(extra("ap2"), "ap2-evidence-pack")
        text = " ".join(_read("README.md").split())
        self.assertIn(f"installs ap2-evidence-pack >= {lo}, < {hi} from the same index", text)

    def test_cryptography_floor_is_the_same_everywhere(self):
        lo, _ = bounds(extra("sign"), "cryptography")
        floors = [s for _, _, s in ci_mentions("cryptography") if "==" in s]
        self.assertTrue(floors, "no CI job pins the cryptography floor")
        for s in floors:
            self.assertEqual(s, f"cryptography=={lo}.0.0" if lo.count(".") == 0 else f"cryptography=={lo}")
        self.assertIn(f"≥ {lo}: the floor where ML-DSA-65 works", _read("README.md"))


if __name__ == "__main__":
    unittest.main()
