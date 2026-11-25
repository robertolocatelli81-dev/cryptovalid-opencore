# SPDX-License-Identifier: AGPL-3.0-or-later
"""`cryptovalid-verify auto` recognises a path by the closed list of SPEC §12, or refuses it with the reason.

Measured on 0.23.0 on 2026-11-14: `auto` on the cra_pack.json of omega-cra-evol 0.10.0 (a pretty-printed JSON object)
verified it as a ledger and answered with three json_decode errors per line, kind "ledger". The release files of that
version are in testdata/interop/ (AGPL-3.0-or-later, SHA-256 pinned below). The generative part builds inputs of every
shape (JSON values, objects with random members, JSONL, pretty-printed documents, binary, empty, blank, byte order mark,
deep nesting, long lines) and compares `verify_auto` with an oracle written here from the text of SPEC §12."""
import hashlib
import json
import os
import random
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import verify_evidence as VE  # noqa: E402

INTEROP = os.path.join(HERE, "testdata", "interop")
CRA = {   # file -> SHA-256 in the SHA256SUMS of the omega-cra-evol v0.10.0 release
    "omega-cra-evol-0.10.0-cra_pack.json": "d396c761bdb556f7e0fbb161e20af4140d59c123c9ecfa4c4fdbda1b57a4cfa1",
    "omega-cra-evol-0.10.0-sbom.cdx.json": "ab6fee49ed288b6b58e6ad5dcbc68c162672930a8b3fee3c8aa4b76713525f89",
    "omega-cra-evol-0.10.0-cra.ledger.jsonl": "16bcbf69265f74869c8ebc307cc96bbdb51ad0f1ad7b7c0fb862b0a8dfb6f96e",
}
PREFIX = "format not recognised: "


def oracle(raw: bytes) -> str:
    """SPEC §12 for a regular file of at most 64 MiB: 'ap2' | 'cldma' | 'ledger' | 'refused' | 'ambiguous'"""
    rows = []
    try:
        if raw.startswith(b"\xef\xbb\xbf"):
            raise ValueError("bom")
        whole = json.loads(raw.decode("utf-8"))
    except (ValueError, RecursionError):
        whole = None
    if isinstance(whole, dict):
        if isinstance(whole.get("evidence_format"), str) and whole["evidence_format"].startswith("ap2-evidence"):
            rows.append("ap2")
        if "root_hash" in whole and "metric_id" in whole:
            rows.append("cldma")
    for line in raw.split(b"\n"):
        if line.startswith(b"\xef\xbb\xbf"):
            break
        try:
            text = line.decode("utf-8")
        except UnicodeDecodeError:
            break
        if text.strip(" \t\r") == "":
            continue
        try:
            first = json.loads(text)
        except (ValueError, RecursionError):
            break
        if isinstance(first, dict) and "prev_hash" in first and "self_hash" in first:
            rows.append("ledger")
        break
    if len(rows) > 1:
        return "ambiguous"
    return rows[0] if rows else "refused"


def _scalar(rnd):
    return rnd.choice([None, True, False, 0, -1, 2 ** 70, 1.5, "", "x", "é", " ", "ap2-evidence/1",
                       "0" * 64, rnd.random(), rnd.randint(-10 ** 6, 10 ** 6)])


def _value(rnd, depth=0):
    k = rnd.random()
    if depth > 3 or k < 0.4:
        return _scalar(rnd)
    if k < 0.7:
        return [_value(rnd, depth + 1) for _ in range(rnd.randint(0, 4))]
    return _obj(rnd, depth + 1)


KEYS = ["prev_hash", "self_hash", "idx", "ts", "data", "evidence_format", "root_hash", "metric_id", "artifacts",
        "pack_format", "kind", "bomFormat", "", "é", "PREV_HASH", "self_hash ", "spec_version"]


def _obj(rnd, depth=0):
    d = {}
    for _ in range(rnd.randint(0, 6)):
        key = rnd.choice(KEYS) if rnd.random() < 0.7 else "k%d" % rnd.randint(0, 99)
        d[key] = _value(rnd, depth)
    if rnd.random() < 0.25:
        d["evidence_format"] = rnd.choice(["ap2-evidence/1", "ap2-evidence", "AP2-evidence", "x-ap2-evidence", 1])
    return d


def _case(rnd) -> bytes:
    kind = rnd.randrange(14)
    if kind == 0:   # one JSON value, compact
        return json.dumps(_value(rnd), ensure_ascii=rnd.random() < 0.5).encode()
    if kind == 1:   # one object, pretty-printed
        return json.dumps(_obj(rnd), indent=rnd.choice([1, 2, "\t"])).encode()
    if kind == 2:   # JSONL of objects
        return b"\n".join(json.dumps(_obj(rnd)).encode() for _ in range(rnd.randint(1, 5))) + b"\n"
    if kind == 3:   # ledger-like first line, then anything
        first = dict(_obj(rnd), prev_hash="0" * 64, self_hash=rnd.choice(["a" * 64, 1, None]))
        return json.dumps(first).encode() + b"\n" + json.dumps(_value(rnd)).encode()
    if kind == 4:   # binary
        return bytes(rnd.randrange(256) for _ in range(rnd.randint(1, 300)))
    if kind == 5:   # empty or blank
        return rnd.choice([b"", b"\n", b" \t\r\n\n", b"\r\n", b"   "])
    if kind == 6:   # byte order mark before something recognised
        return b"\xef\xbb\xbf" + json.dumps({"prev_hash": "0" * 64, "self_hash": "a" * 64}).encode()
    if kind == 7:   # blank lines before a ledger-like line
        return b"\n \t\r\n" + json.dumps({"idx": 0, "prev_hash": "0" * 64, "self_hash": "b" * 64}).encode() + b"\n"
    if kind == 8:   # deep nesting
        n = rnd.choice([10, 5000, 200000])
        return b"[" * n + b"]" * n
    if kind == 9:   # CLDMA-like and AP2-like objects, sometimes on one line with ledger members too
        d = _obj(rnd)
        d.update(rnd.choice([{"root_hash": "aa", "metric_id": "m"}, {"evidence_format": "ap2-evidence/1"},
                             {"root_hash": "aa", "metric_id": "m", "evidence_format": "ap2-evidence/1"}]))
        if rnd.random() < 0.4:
            d.update(prev_hash="0" * 64, self_hash="c" * 64)
        return json.dumps(d, indent=None if rnd.random() < 0.5 else 1).encode()
    if kind == 10:   # invalid UTF-8 after a valid first line, or on the first line
        good = json.dumps({"prev_hash": "0" * 64, "self_hash": "d" * 64}).encode()
        return rnd.choice([good + b"\n\xff\xfe", b"\xff" + good, good[:10] + b"\xc3\x28" + good[10:]])
    if kind == 11:   # JSON texts that Python's parser reads but are not documents of the list
        return rnd.choice([b"NaN", b"-Infinity", b"\"ap2-evidence\"", b"[{\"prev_hash\":1,\"self_hash\":2}]", b"null"])
    if kind == 12:   # mutate a real ledger line
        with open(os.path.join(HERE, "examples", "sample_ledger.jsonl"), "rb") as fh:
            raw = bytearray(fh.read())
        for _ in range(rnd.randint(1, 4)):
            raw[rnd.randrange(len(raw))] = rnd.randrange(256)
        return bytes(raw)
    return ("{" * rnd.randint(1, 3) + "\"prev_hash\": \"0\"").encode()   # truncated document


def _kind(r: dict) -> str:
    if r["kind"] != "auto":
        return r["kind"]
    detail = r["layers"][0]["detail"]
    return "ambiguous" if detail.startswith(PREFIX + "ambiguous") else "refused"


class TestAutoReal(unittest.TestCase):
    def test_release_files_are_the_released_bytes(self):
        for name, want in CRA.items():
            with open(os.path.join(INTEROP, name), "rb") as fh:
                self.assertEqual(hashlib.sha256(fh.read()).hexdigest(), want, name)

    def test_cra_pack_and_sbom_are_not_recognised(self):
        for name in ("omega-cra-evol-0.10.0-cra_pack.json", "omega-cra-evol-0.10.0-sbom.cdx.json"):
            r = VE.verify_auto(os.path.join(INTEROP, name))
            self.assertEqual((r["kind"], r["valid"], len(r["layers"])), ("auto", False, 1), name)
            d = r["layers"][0]["detail"]
            self.assertTrue(d.startswith(PREFIX + "the file is a JSON object of another kind (members: "), d)
            self.assertNotIn("json_decode", d)
        d = VE.verify_auto(os.path.join(INTEROP, "omega-cra-evol-0.10.0-cra_pack.json"))["layers"][0]["detail"]
        self.assertIn('"kind"', d)

    def test_cra_ledger_is_a_ledger_and_passes(self):
        r = VE.verify_auto(os.path.join(INTEROP, "omega-cra-evol-0.10.0-cra.ledger.jsonl"))
        self.assertEqual((r["kind"], r["valid"]), ("ledger", True))

    def test_sample_ledgers(self):
        r = VE.verify_auto(os.path.join(HERE, "examples", "sample_ledger.jsonl"))
        self.assertEqual((r["kind"], r["valid"]), ("ledger", True))
        r = VE.verify_auto(os.path.join(HERE, "examples", "sample_ledger_tampered.jsonl"))
        self.assertEqual((r["kind"], r["valid"]), ("ledger", False))

    def test_command_exit_and_output(self):
        import subprocess
        env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
        p = subprocess.run([sys.executable, os.path.join(HERE, "verify_evidence.py"), "auto",
                            os.path.join(INTEROP, "omega-cra-evol-0.10.0-cra_pack.json")],
                           capture_output=True, text=True, encoding="utf-8", env=env, timeout=120)
        self.assertEqual(p.returncode, 1, p.stderr)
        self.assertEqual(json.loads(p.stdout)["kind"], "auto")
        self.assertNotIn("Traceback", p.stderr)


class TestAutoPaths(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp(prefix="auto_")

    def _refused(self, path, why):
        r = VE.verify_auto(path)
        self.assertEqual((r["kind"], r["valid"]), ("auto", False))
        self.assertIn(why, r["layers"][0]["detail"])
        self.assertTrue(r["layers"][0]["detail"].startswith(PREFIX))

    def _write(self, raw: bytes) -> str:
        p = os.path.join(self.d, "f%d" % len(os.listdir(self.d)))
        with open(p, "wb") as fh:
            fh.write(raw)
        return p

    def test_reasons(self):
        nine = {"k%d" % i: 1 for i in range(9)}
        cases = [
            (b"", "the file is empty or blank"),
            (b" \t\r\n\n", "the file is empty or blank"),
            (b"\xef\xbb\xbf{}", "line 1 starts with a UTF-8 byte order mark"),
            (b"\xff{}", "line 1 is not UTF-8 text (byte 0: ff)"),
            (b"\n\n\xc3\x28", "line 3 is not UTF-8 text (byte 0: c3)"),
            (b"[1, 2]", "the file is a JSON array"),
            (b'"x"', "the file is a JSON string"),
            (b"null", "the file is JSON null"),
            (b"[" * 200000 + b"]" * 200000, "the first non-blank line: JSON nested deeper than the parser allows"),
            (b"{\n\"a\": 1\n", "the first non-blank line is not JSON ("),
            (b'{"a": 1}\n{"b": 2}\n', "the first non-blank line is a JSON object without prev_hash and self_hash"),
            (b'{"prev_hash": "0"}\nx', "the first non-blank line is a JSON object without self_hash"),
            (b'[{"prev_hash": 1, "self_hash": 2}]\n[1]', "the first non-blank line is a JSON array"),
            (json.dumps({"root_hash": "a", "metric_id": "m", "prev_hash": "0", "self_hash": "1"}).encode(),
             "ambiguous: the file matches cldma and ledger; name the verifier"),
            (json.dumps({"evidence_format": "ap2-evidence/1", "root_hash": "a", "metric_id": "m"}).encode(),
             "ambiguous: the file matches ap2 and cldma; name the verifier"),
            (json.dumps(nine).encode(), '(members: "k0", "k1", "k2", "k3", "k4", "k5", "k6", "k7", ...)'),
            (json.dumps({"k%d" % i: 1 for i in range(8)}).encode(), '"k6", "k7")'),
            (json.dumps({}).encode(), "(members: none)"),
            (json.dumps({"\u00e9": 1}, ensure_ascii=False).encode(), '(members: "\\u00e9")'),
        ]
        for raw, why in cases:
            self._refused(self._write(raw), why)

    def test_unreadable_file(self):
        from test_platforms_20261124 import make_unreadable   # Windows: an empty access list
        p = self._write(b"{}")
        make_unreadable(self, p)
        self._refused(p, "cannot read the file (PermissionError: Permission denied);")

    def test_missing_path(self):
        self._refused(os.path.join(self.d, "nope.jsonl"), "cannot read the path (FileNotFoundError: No such file or directory);")

    def test_the_recognised_list_is_named(self):
        d = VE.verify_auto(os.path.join(self.d, "nope"))["layers"][0]["detail"]
        self.assertTrue(d.endswith(
            "; recognised: evidence pack directory (MANIFEST.json), ingest archive directory (*.head.json or *-*.jsonl), "
            "AP2 evidence (one JSON object, evidence_format ap2-evidence*), CLDMA attestation (one JSON object with "
            "root_hash and metric_id), ledger (JSONL whose first line is an object with prev_hash and self_hash), "
            "C2SP checkpoint (a signed note of at most 1 MiB whose text is a checkpoint), C2SP tiled log directory "
            "(a directory tile)"), d)

    def test_empty_directory(self):
        self._refused(self.d, "a directory with neither MANIFEST.json")

    def test_pipe(self):
        from test_platforms_20261124 import fifo   # Windows: a named pipe given by name
        p = fifo(self, os.path.join(self.d, "fifo"))
        self._refused(p, "neither a directory nor a regular file")

    def test_directory_with_glob_characters(self):
        d = os.path.join(self.d, "a[1]")
        os.mkdir(d)
        with open(os.path.join(d, "ledger-000.jsonl"), "w", encoding="utf-8", newline="") as fh:
            fh.write("")
        self.assertEqual(VE.verify_auto(d)["kind"], "archive")

    def test_unreadable_directory(self):
        from test_platforms_20261124 import make_unreadable   # Windows: an empty access list
        d = os.path.join(self.d, "pack")
        os.mkdir(d)
        with open(os.path.join(d, "MANIFEST.json"), "w", encoding="utf-8", newline="") as fh:
            fh.write("{}")
        make_unreadable(self, d)
        self._refused(d, "cannot read the directory (PermissionError: Permission denied);")

    def test_non_utf8_after_the_first_line_is_the_ledger_verifiers(self):
        # SPEC §12: only the lines up to the first non-blank one decide; a later line of a ledger is judged by `ledger`
        with open(os.path.join(HERE, "examples", "sample_ledger.jsonl"), "rb") as fh:
            raw = fh.read()
        r = VE.verify_auto(self._write(raw + b"\xe9\n"))
        self.assertEqual((r["kind"], r["valid"]), ("ledger", False))
        self.assertIn("not_utf8", r["layers"][0]["detail"])

    def test_a_one_line_document_is_parsed_once(self):
        from unittest import mock
        calls = []
        real = VE._json_value
        def counting(text, what):
            calls.append(what)
            return real(text, what)
        p = self._write(b"\n" + json.dumps({"prev_hash": "0" * 64, "self_hash": "a" * 64}).encode() + b"\r\n \n")
        with mock.patch.object(VE, "_json_value", counting):
            self.assertEqual(VE._file_format(p), "ledger")
        self.assertEqual(calls, ["the file"])
        calls.clear()
        p = self._write(b'{"prev_hash": "0", "self_hash": "1"}\n{"x": 1}\n')   # two lines: the first is parsed alone
        with mock.patch.object(VE, "_json_value", counting):
            self.assertEqual(VE._file_format(p), "ledger")
        self.assertEqual(calls, ["the file", "the first non-blank line"])

    def test_the_limit_is_the_specs(self):   # SPEC §12 names 64 MiB; the test below swaps the limit for 500
        self.assertEqual(VE._AUTO_JSON_LIMIT, 64 * 1024 * 1024)

    def test_larger_than_the_limit(self):
        old = VE._AUTO_JSON_LIMIT
        VE._AUTO_JSON_LIMIT = 500
        try:
            led = os.path.join(HERE, "examples", "sample_ledger.jsonl")
            self.assertEqual(VE.verify_auto(led)["kind"], "ledger")
            p = os.path.join(self.d, "long")
            with open(p, "w", encoding="utf-8", newline="") as fh:
                fh.write(json.dumps({"x": "y" * 1000}))
            self._refused(p, "format not recognised: the file is larger than 64 MiB and its first line longer than 64 MiB;")
            with open(p, "w", encoding="utf-8", newline="") as fh:
                fh.write("\n" * 1000)
            self._refused(p, "no non-blank line in the first")
            with open(p, "w", encoding="utf-8", newline="") as fh:
                fh.write(json.dumps({"evidence_format": "ap2-evidence/1"}) + "\n" + " " * 1000)   # AP2 only when read whole
            self._refused(p, "the first non-blank line is a JSON object without prev_hash and self_hash")
            with open(p, "w", encoding="utf-8", newline="") as fh:   # blank lines, then a line cut by the limit: the cut piece is not read as a line
                fh.write("\n" * 490 + json.dumps({"prev_hash": "0" * 64, "self_hash": "a" * 64}))
            self._refused(p, "no non-blank line in the first")
            for size, kind in ((500, "ap2"), (501, "auto")):   # read whole up to the limit, not beyond
                with open(p, "w", encoding="utf-8", newline="") as fh:
                    head = '{"evidence_format": "ap2-evidence/1", "pad": "'
                    fh.write(head + "z" * (size - len(head) - 2) + '"}')
                self.assertEqual(os.path.getsize(p), size)
                self.assertEqual(VE.verify_auto(p)["kind"], kind, size)
        finally:
            VE._AUTO_JSON_LIMIT = old


class TestAutoGenerative(unittest.TestCase):
    N = 1500

    def test_matches_the_oracle(self):
        rnd = random.Random(20261115)
        d = tempfile.mkdtemp(prefix="autogen_")
        p = os.path.join(d, "x")
        seen, wrong = {}, []
        for i in range(self.N):
            raw = _case(rnd)
            with open(p, "wb") as fh:
                fh.write(raw)
            want = oracle(raw)
            r = VE.verify_auto(p)
            got = _kind(r)
            seen[want] = seen.get(want, 0) + 1
            if got != want:
                wrong.append((i, want, got, raw[:80]))
            if r["kind"] == "auto":
                self.assertFalse(r["valid"])
                self.assertTrue(r["layers"][0]["detail"].startswith(PREFIX))
                self.assertNotIn("json_decode", r["layers"][0]["detail"])
        self.assertEqual(wrong, [])
        for k in ("ap2", "cldma", "ledger", "refused", "ambiguous"):   # every row of the table was exercised
            self.assertGreater(seen.get(k, 0), 10, seen)


if __name__ == "__main__":
    unittest.main()
