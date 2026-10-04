"""verify_evidence on a structurally malformed evidence file: a fail-closed receipt (valid False), never a traceback.
Found 2026-10-03 by a structural fuzz (remove / null / wrong type on every path): 29 of 222 variants raised
TypeError/AttributeError out of verify_evidence; ap2-evidence-pack 1.1.0 already checked these shapes."""
import json
import os
import unittest

import ap2_evidence as ap2
import test_ap2_evidence as T


def _set(obj, path, value):
    for k in path[:-1]:
        obj = obj[k]
    obj[path[-1]] = value


class TestMalformedShapeIsARefusal(unittest.TestCase):
    CASES = [
        ((), []),                                           # top level not an object
        (("artifacts",), None),
        (("artifacts",), {"a": 1}),
        (("artifacts", 0), None),
        (("artifacts", 0), ["x"]),
        (("artifacts", 0, "key"), None),
        (("artifacts", 0, "key", "jwk"), None),
        (("artifacts", 0, "key", "jwk", "x"), 7),
        (("artifacts", 0, "sd_jwt_compact"), 7),
        (("artifacts", 0, "key", "provenance_class"), 7),
        (("bindings",), {"a": 1}),
        (("rfc3161_timestamp",), ["x"]),
        (("rfc3161_timestamp", "anchored"), "yes"),
        (("rfc3161_timestamp", "anchored"), None),
        (("producer_signatures",), ["x"]),
    ]

    def setUp(self):
        b = T._Base(); b.setUp()
        ap2.build_evidence(b.arts, b.out)
        self.out = b.out
        with open(b.out) as f:
            self.ev = json.load(f)

    def test_genuine_file_is_valid(self):                   # positive control: the bench can say "valid"
        self.assertTrue(ap2.verify_evidence(self.out)["valid"])

    def test_each_malformed_shape_is_a_refusal(self):
        normal_keys = set(ap2.verify_evidence(self.out))
        for path, value in self.CASES:
            with self.subTest(path=path, value=value):
                ev = json.loads(json.dumps(self.ev))
                if path:
                    _set(ev, path, value)
                else:
                    ev = value
                with open(self.out, "w") as f:
                    json.dump(ev, f)
                r = ap2.verify_evidence(self.out)           # must not raise
                self.assertIs(r["valid"], False)
                self.assertLessEqual(normal_keys, set(r))   # same receipt shape as a normal verdict


if __name__ == "__main__":
    unittest.main()
