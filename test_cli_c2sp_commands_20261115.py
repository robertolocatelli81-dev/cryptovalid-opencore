#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""The commands of SPEC §13-§14 from the installed command, and `auto` on what they verify (SPEC §12, v0.7).

Measured on 2026-11-15, before this file: `checkpoint`, `tiles` and `vkey-rfc6962` existed only in
cryptovalid_checkpoint.py, which has no installed command, and `cryptovalid-verify auto` answered "format not
recognised" on a checkpoint file and on a directory of tiles. Now `cryptovalid-verify checkpoint|tiles|vkey-rfc6962` run
the code of cryptovalid_checkpoint.py (`checkpoint` is its `verify`), and `auto` recognises the two by the closed rows of
SPEC §12 and names the command to run, which needs a trusted key `auto` has not got.

The differential part runs the same arguments through both commands (stdout and exit status must be equal); the
generative part alters real notes and compares `auto` with an oracle written here from the text of SPEC §12."""
import base64
import json
import os
import random
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import verify_evidence as VE  # noqa: E402
from test_auto_closed_20261115 import oracle as json_rows_oracle  # noqa: E402  (the rows of SPEC §12 before v0.7)

D = os.path.join(HERE, "testdata", "interop")
ROME = os.path.join(D, "sunlight_rome2026h1.checkpoint")
ROME_LOG = os.path.join(D, "sunlight_rome2026h1.log.v3.json")
MIRROR = os.path.join(D, "sunlight_mirror")
NAVIGLI = os.path.join(D, "sunlight_navigli2025h2")
TORCHWOOD = os.path.join(D, "torchwood_mldsa44_log.note")
MIRROR_VKEY = "mirror.example.org+3fb148ef+BAAjjch9GyYz0sJsJx7ALhbdAtz2ov0unbzSl1vMp94O"
ROME_VKEY = ("rome2026h1.example.org+91507526+BTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABDyHHq+0Qd9o7eG0xG4YFCiyrznLRQ/iNoaAyLRc"
             "VAZSYhhb37QbkZN3zu3tU+4AtnpMny+16DtqDfzm3GcnOBA=")
try:
    import cryptography  # noqa: F401
    HAVE_CRYPTO = True
except ImportError:
    HAVE_CRYPTO = False
if os.environ.get("CV_REQUIRE_CRYPTO") == "1" and not HAVE_CRYPTO:
    raise SystemExit("CV_REQUIRE_CRYPTO=1 and `cryptography` is missing")


def _child_flags() -> list:
    """Flags of a child interpreter that sees the packages this one sees (15/11/2026): `-E` / `-s` only when this process
    runs with them. Until 0.24.0 the children ran with `-E -s` whatever the parent did: with `cryptography` installed by
    `pip install --user`, the parent found it and the children did not (3 failures in test_cli_c2sp_commands_20261115.py)."""
    return (["-E"] if sys.flags.ignore_environment else []) + (["-s"] if sys.flags.no_user_site else [])


def _child_env(env: dict) -> dict:
    """`env` plus this interpreter's user base, so that a child given another HOME looks for user packages where this
    interpreter found them."""
    import site
    if site.ENABLE_USER_SITE and not sys.flags.ignore_environment:
        env = dict(env, PYTHONUSERBASE=site.getuserbase())
    return env


def _run(script, args, cwd=HERE):
    env = {k: v for k, v in os.environ.items() if k not in ("PYTHONPATH", "PYTHONHOME", "PYTHONSTARTUP")}
    env.update(LC_ALL="C.UTF-8", PYTHONIOENCODING="utf-8")
    r = subprocess.run([sys.executable, *_child_flags(), os.path.join(HERE, script), *args], cwd=cwd, env=_child_env(env),
                       capture_output=True, text=True, encoding="utf-8", timeout=300)
    return r.returncode, r.stdout, r.stderr


# ── the oracle of the checkpoint row, from the text of SPEC §12 (independent of cryptovalid_checkpoint) ────────────
_B64 = re.compile(r"(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?")


def _b64(s):
    if not _B64.fullmatch(s):
        return None
    return base64.b64decode(s)


def note_is_checkpoint(raw: bytes) -> bool:
    if len(raw) > 1 << 20 or raw.startswith(b"\xef\xbb\xbf"):
        return False
    try:
        s = raw.decode("utf-8")
    except UnicodeDecodeError:
        return False
    if any(ord(c) < 0x20 and c != "\n" for c in s) or not s.endswith("\n") or "\n\n" not in s:
        return False
    i = s.rindex("\n\n")
    text, block = s[:i + 1], s[i + 2:]
    lines = block[:-1].split("\n")
    if len(lines) > 100:
        return False
    for line in lines:
        m = re.fullmatch(r"— ([^\s+]+) (\S+)", line)
        if not m:
            return False
        sig = _b64(m.group(2))
        if sig is None or not 5 <= len(sig) <= 8192:
            return False
    tl = text[:-1].split("\n")
    if len(tl) < 3 or "" in tl:
        return False
    if not re.fullmatch(r"0|[1-9][0-9]*", tl[1]) or int(tl[1]) >= 2 ** 64:
        return False
    root = _b64(tl[2])
    return root is not None and len(root) == 32 and base64.b64encode(root).decode() == tl[2]


def oracle(raw: bytes) -> str:
    rows = json_rows_oracle(raw)
    if note_is_checkpoint(raw):
        return "checkpoint" if rows == "refused" else "ambiguous"
    return rows


def _kind(r: dict) -> str:
    if r["kind"] != "auto":
        return r["kind"]
    return "ambiguous" if r["layers"][0]["detail"].startswith("format not recognised: ambiguous") else "refused"


class TestChildrenSeeTheParentsPackages(unittest.TestCase):
    """The children of this suite import what the parent imports (15/11/2026): `cryptography` found by one and not by the
    other turned verdicts into failures. Checked here for `cryptography` and for the module directory itself."""
    def test_same_packages(self):
        code = "import importlib.util as u; print(u.find_spec('cryptography') is not None)"
        with tempfile.TemporaryDirectory() as home:
            env = _child_env(dict(os.environ, HOME=home))
            r = subprocess.run([sys.executable, *_child_flags(), "-c", code], cwd=home, env=env, capture_output=True,
                               text=True, encoding="utf-8", timeout=120)
        self.assertEqual((r.returncode, r.stdout.strip()), (0, str(HAVE_CRYPTO)), r.stderr[-400:])


class TestInstalledCommands(unittest.TestCase):
    def test_help_lists_and_opens_them(self):
        rc, out, _ = _run("verify_evidence.py", ["--help"])
        self.assertEqual(rc, 0)
        for cmd in ("checkpoint", "tiles", "vkey-rfc6962"):
            self.assertRegex(out, rf"(?m)^  {cmd} +\S")
            rc, sub, err = _run("verify_evidence.py", [cmd, "--help"])
            self.assertEqual((rc, err), (0, ""))
            self.assertTrue(sub.startswith(f"usage: cryptovalid-verify {cmd} [-h]"), sub[:200])
            self.assertNotEqual(sub, out)
        self.assertIn("--vkey VKEY", _run("verify_evidence.py", ["checkpoint", "--help"])[1])
        self.assertIn("--profile {static-ct-api,tlog-tiles}", _run("verify_evidence.py", ["tiles", "--help"])[1])

    def test_command_descriptions_in_one_column(self):
        cols = {m.start(2) - m.start(0) for m in re.finditer(r"(?m)^  ([a-z0-9-]+) +(\S)", VE._COMMANDS_HELP)}
        self.assertEqual(len(cols), 1, VE._COMMANDS_HELP)
        more = {len(m.group(1)) for m in re.finditer(r"(?m)^( {3,})\S", VE._COMMANDS_HELP)}   # continuation lines
        self.assertEqual(more, cols, VE._COMMANDS_HELP)
        self.assertEqual(len(re.findall(r"(?m)^  ([a-z0-9-]+) +\S", VE._COMMANDS_HELP)), len(VE._COMMANDS))

    def test_usage_errors_name_the_command(self):
        rc, out, err = _run("verify_evidence.py", ["tiles"])
        self.assertEqual((rc, out), (2, ""))
        self.assertIn("cryptovalid-verify tiles: error: the following arguments are required: directory, --vkey, --profile",
                      err)
        rc, out, err = _run("verify_evidence.py", ["checkpoint", ROME])
        self.assertEqual((rc, out), (2, ""))
        self.assertIn("cryptovalid-verify checkpoint: error: the following arguments are required: --vkey", err)

    def test_a_c2sp_command_after_double_dash_is_a_usage_error(self):   # was a KeyError traceback, exit 1
        for cmd in ("checkpoint", "tiles", "vkey-rfc6962"):
            rc, out, err = _run("verify_evidence.py", ["--", cmd, ROME])
            self.assertEqual((rc, out), (2, ""), err)
            self.assertIn(f"{cmd} takes its own options and must come first", err)
            self.assertNotIn("Traceback", err)

    def test_the_vkey_of_the_log_list_entry(self):
        with open(ROME_LOG, encoding="utf-8") as fh:
            key = json.load(fh)["key"]
        rc, out, _ = _run("verify_evidence.py", ["vkey-rfc6962", "--name", "rome2026h1.example.org", "--key-b64", key])
        self.assertEqual((rc, out), (0, ROME_VKEY + "\n"))

    @unittest.skipUnless(HAVE_CRYPTO, "signatures need cryptography")
    def test_same_outcome_as_the_module(self):
        d = tempfile.mkdtemp(prefix="c2spcli_")
        with open(ROME, "rb") as fh:
            note = fh.read()
        bad = os.path.join(d, "bad")
        with open(bad, "wb") as fh:
            fh.write(note.replace(b"\n300\n", b"\n301\n"))
        fifo = os.path.join(d, "fifo")
        if hasattr(os, "mkfifo"):
            os.mkfifo(fifo)
        mirror_cp = os.path.join(MIRROR, "checkpoint")
        cases = [
            ("checkpoint", [ROME, "--vkey", ROME_VKEY], 0),
            ("checkpoint", [mirror_cp, "--vkey", MIRROR_VKEY], 0),
            ("checkpoint", [bad, "--vkey", ROME_VKEY], 1),
            ("checkpoint", [ROME, "--vkey", MIRROR_VKEY], 1),
            ("checkpoint", [ROME, "--vkey", "x+1+2"], 2),
            ("checkpoint", [os.path.join(d, "nope"), "--vkey", ROME_VKEY], 2),
            ("checkpoint", [d, "--vkey", ROME_VKEY], 2),
            ("tiles", [MIRROR, "--vkey", MIRROR_VKEY, "--profile", "tlog-tiles", "--no-entries"], 0),
            ("tiles", [MIRROR, "--vkey", MIRROR_VKEY, "--profile", "tlog-tiles"], 1),
            ("tiles", [MIRROR, "--vkey", ROME_VKEY, "--profile", "static-ct-api", "--no-entries"], 1),
            ("tiles", [NAVIGLI, "--vkey", ROME_VKEY, "--profile", "static-ct-api"], 2),
            ("tiles", [MIRROR, "--vkey", MIRROR_VKEY, "--profile", "nope"], 2),
            ("vkey-rfc6962", ["--name", "a+b", "--key-b64", "AAAA"], 2),
            ("vkey-rfc6962", ["--name", "x", "--key-b64", "=AAA"], 2),
        ]
        if hasattr(os, "mkfifo"):
            cases.append(("checkpoint", [fifo, "--vkey", ROME_VKEY], 2))
            cases.append(("tiles", [MIRROR, "--vkey", MIRROR_VKEY, "--profile", "tlog-tiles", "--checkpoint", fifo], 2))
        mapped = {"checkpoint": "verify", "tiles": "tiles", "vkey-rfc6962": "vkey-rfc6962"}
        for cmd, args, want in cases:
            a = _run("verify_evidence.py", [cmd, *args])
            b = _run("cryptovalid_checkpoint.py", [mapped[cmd], *args])
            self.assertEqual(a[0], want, (cmd, args, a))
            self.assertEqual(a[:2], b[:2], (cmd, args))
            self.assertNotIn("Traceback", a[2])
        shutil.rmtree(d)


class TestAutoNamesTheCommand(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp(prefix="autoc2sp_")

    def tearDown(self):
        shutil.rmtree(self.d, ignore_errors=True)

    def _write(self, name, raw):
        p = os.path.join(self.d, name)
        with open(p, "wb") as fh:
            fh.write(raw)
        return p

    def _skip(self, r, kind):
        self.assertEqual((r["kind"], r["valid"], len(r["layers"])), (kind, False, 1))
        self.assertEqual((r["layers"][0]["layer"], r["layers"][0]["status"]), (kind, "SKIP"))
        return r["layers"][0]["detail"]

    def test_real_checkpoints(self):
        for path, origin, size in ((ROME, "rome2026h1.example.org", 300),
                                   (os.path.join(MIRROR, "checkpoint"), "rome2026h1.example.org", 300),
                                   (TORCHWOOD, "example.com/mldsa-log", 1)):
            detail = self._skip(VE.verify_auto(path), "checkpoint")
            self.assertEqual(detail, f'C2SP checkpoint (origin "{origin}", size {size}): auto holds no trusted key and '
                                     f"verifies nothing; run: cryptovalid-verify checkpoint {path} --vkey <vkey of the log>")

    @unittest.skipUnless(HAVE_CRYPTO, "signatures need cryptography")
    def test_the_named_command_verifies(self):
        for path, vkey in ((ROME, ROME_VKEY), (os.path.join(MIRROR, "checkpoint"), MIRROR_VKEY)):
            detail = self._skip(VE.verify_auto(path), "checkpoint")
            argv = detail.split("; run: cryptovalid-verify ", 1)[1].replace("<vkey of the log>", vkey).split(" ")
            rc, out, _ = _run("verify_evidence.py", argv)
            self.assertEqual((rc, json.loads(out)["stato"]), (0, "OK"))
        detail = self._skip(VE.verify_auto(MIRROR), "tiles")
        self.assertTrue(detail.endswith(f"run: cryptovalid-verify tiles {MIRROR} --vkey <vkey of the log> --profile "
                                        "<static-ct-api or tlog-tiles>"), detail)
        argv = (detail.split("; run: cryptovalid-verify ", 1)[1].replace("<vkey of the log>", MIRROR_VKEY)
                .replace("<static-ct-api or tlog-tiles>", "tlog-tiles").split(" ") + ["--no-entries"])
        rc, out, _ = _run("verify_evidence.py", argv)
        self.assertEqual((rc, json.loads(out)["stato"]), (0, "OK"))

    def test_command_line_exit(self):
        rc, out, err = _run("verify_evidence.py", ["auto", ROME])
        self.assertEqual(rc, 1, err)
        self.assertEqual(json.loads(out)["kind"], "checkpoint")

    def test_origin_is_named_as_written(self):   # a non-ASCII origin is named as it is, not \u-escaped
        with open(ROME, "rb") as fh:
            note = fh.read()
        p = self._write("e", "\u00e9.example".encode() + note[note.index(b"\n"):])
        self.assertIn('C2SP checkpoint (origin "\u00e9.example", size 300)', self._skip(VE.verify_auto(p), "checkpoint"))

    def test_control_characters_are_those_below_u0020(self):   # SPEC §12 as c2sp.org/signed-note defines them
        with open(ROME, "rb") as fh:
            note = fh.read()
        for ch in ("\x7f", "\x85", "\u202e"):   # DEL, a C1 control, a format character: a checkpoint (origin as written)
            p = self._write("c", ("a" + ch + "b").encode() + note[note.index(b"\n"):])
            self.assertIn('origin "a' + ch + 'b"', self._skip(VE.verify_auto(p), "checkpoint"))
        for ch in ("\x00", "\x1f", "\t", "\r"):
            p = self._write("c", ("a" + ch + "b").encode() + note[note.index(b"\n"):])
            self.assertEqual(VE.verify_auto(p)["kind"], "auto", repr(ch))

    def test_paths_are_quoted(self):
        with open(ROME, "rb") as fh:
            p = self._write("a b'c", fh.read())
        detail = self._skip(VE.verify_auto(p), "checkpoint")
        self.assertIn("run: cryptovalid-verify checkpoint '" + self.d + "/a b'\"'\"'c' --vkey", detail)

    def test_a_path_starting_with_a_dash(self):   # the command named in the receipt must run as written
        with open(ROME, "rb") as fh:
            self._write("-cp", fh.read())
        os.makedirs(os.path.join(self.d, "-log", "tile"))
        old = os.getcwd()
        os.chdir(self.d)
        try:
            detail = self._skip(VE.verify_auto("-cp"), "checkpoint")
            tiles = self._skip(VE.verify_auto("-log"), "tiles")
        finally:
            os.chdir(old)
        self.assertIn("run: cryptovalid-verify checkpoint ./-cp --vkey", detail)
        self.assertIn("run: cryptovalid-verify tiles ./-log --vkey", tiles)
        with open(ROME_LOG, encoding="utf-8") as fh:
            key = json.load(fh)["key"]
        _, vkey, _ = _run("verify_evidence.py", ["vkey-rfc6962", "--name", "rome2026h1.example.org", "--key-b64", key])
        rc, out, err = _run("verify_evidence.py", ["checkpoint", "./-cp", "--vkey", vkey.strip()], cwd=self.d)
        # the path is read as the note, not as an option (exit 2 "required: note" before the fix), with or without
        # cryptography; the signature itself verifies only where cryptography is installed
        self.assertNotEqual(rc, 2, err)
        self.assertNotIn("required", err)
        if HAVE_CRYPTO:
            self.assertEqual(rc, 0, err)
        else:     # the note was read and only the signature is left unchecked, for the reason that cryptography is missing
            self.assertEqual(rc, 1, err)
            self.assertIn("`cryptography` missing", json.loads(out)["motivo"])

    def test_a_library_call_from_the_parent_directory(self):   # `from opencore import verify_evidence` (namespace package):
        os.symlink(HERE, os.path.join(self.d, "opencore"))           # verify_auto itself puts the module directory on the path
        code = ("from opencore import verify_evidence as V; r = V.verify_auto(%r); print(r['kind'], r['layers'][0]['status'])"
                % ROME)
        r = subprocess.run([sys.executable, *_child_flags(), "-c", code], cwd=self.d, env=_child_env(dict(os.environ)),
                           capture_output=True, text=True, encoding="utf-8", timeout=120)
        self.assertEqual((r.returncode, r.stdout), (0, "checkpoint SKIP\n"), r.stderr[-400:])

    def test_tile_directories(self):
        detail = self._skip(VE.verify_auto(NAVIGLI), "tiles")
        self.assertTrue(detail.endswith("--profile <static-ct-api or tlog-tiles> --checkpoint <checkpoint file>"), detail)
        t = os.path.join(self.d, "log")
        os.makedirs(os.path.join(t, "tile"))
        self.assertTrue(self._skip(VE.verify_auto(t), "tiles").endswith("--checkpoint <checkpoint file>"))
        os.mkdir(os.path.join(t, "checkpoint"))           # not a regular file
        self.assertTrue(self._skip(VE.verify_auto(t), "tiles").endswith("--checkpoint <checkpoint file>"))
        os.rmdir(os.path.join(t, "checkpoint"))
        shutil.copy(ROME, os.path.join(t, "checkpoint"))
        self.assertTrue(self._skip(VE.verify_auto(t), "tiles").endswith("<static-ct-api or tlog-tiles>"))
        with open(os.path.join(t, "MANIFEST.json"), "w", encoding="utf-8", newline="") as fh:   # the rows of a directory in the order of the table
            fh.write("{}")
        self.assertEqual(VE.verify_auto(t)["kind"], "pack")
        os.remove(os.path.join(t, "MANIFEST.json"))
        with open(os.path.join(t, "ledger-000.jsonl"), "w", encoding="utf-8", newline="") as fh:
            fh.write("")
        self.assertEqual(VE.verify_auto(t)["kind"], "archive")

    def test_not_a_tile_directory(self):
        for make in ("file", "link", "none", "link_to_file"):
            t = os.path.join(self.d, make)
            os.mkdir(t)
            if make == "file":
                open(os.path.join(t, "tile"), "w", encoding="utf-8", newline="").close()
            elif make == "link":
                os.symlink(os.path.join(NAVIGLI, "tile"), os.path.join(t, "tile"))
            elif make == "link_to_file":
                os.symlink(ROME, os.path.join(t, "tile"))
            r = VE.verify_auto(t)
            self.assertEqual((r["kind"], r["valid"]), ("auto", False), make)
            self.assertIn("nor a directory tile (C2SP tiled log)", r["layers"][0]["detail"])

    def test_note_limits(self):
        with open(ROME, "rb") as fh:
            note = fh.read()
        text, sigs = note.split(b"\n\n", 1)
        line = sigs.rstrip(b"\n")
        for n, kind in ((100, "checkpoint"), (101, "auto")):
            many = b"\n".join(line.replace(b"rome2026h1", b"r%04d" % i) for i in range(n)) + b"\n"
            self.assertEqual(VE.verify_auto(self._write("m%d" % n, text + b"\n\n" + many))["kind"], kind, n)
        pad = (1 << 20) - len(note) - 1
        for extra, kind in ((0, "checkpoint"), (1, "auto")):   # extension lines up to 1 MiB, then one byte more
            raw = text + b"\n" + b"e" * (pad + extra) + b"\n\n" + sigs
            self.assertEqual(len(raw), (1 << 20) + extra)
            self.assertEqual(VE.verify_auto(self._write("big%d" % extra, raw))["kind"], kind, extra)
        r = VE.verify_auto(self._write("bom", b"\xef\xbb\xbf" + note))
        self.assertEqual(r["kind"], "auto")
        self.assertIn("byte order mark", r["layers"][0]["detail"])

    def test_ambiguous_with_a_ledger(self):
        origin = json.dumps({"prev_hash": "0" * 64, "self_hash": "a" * 64}).encode()
        with open(ROME, "rb") as fh:
            note = fh.read()
        r = VE.verify_auto(self._write("amb", origin + note[note.index(b"\n"):]))
        self.assertEqual(r["kind"], "auto")
        self.assertIn("ambiguous: the file matches ledger and checkpoint; name the verifier", r["layers"][0]["detail"])

    def test_the_recognised_list_names_the_rows(self):
        d = VE.verify_auto(os.path.join(self.d, "nope"))["layers"][0]["detail"]
        self.assertTrue(d.endswith("C2SP checkpoint (a signed note of at most 1 MiB whose text is a checkpoint), "
                                   "C2SP tiled log directory (a directory tile)"), d)


def _rbytes(rnd, n):
    return bytes(rnd.randrange(256) for _ in range(n))


def _alter(rnd, raw: bytes) -> bytes:
    k = rnd.randrange(12)
    b = bytearray(raw)
    if not b or (k in (7, 8, 9) and raw.count(b"\n") < 3) or (k == 4 and b"\n\n" not in raw):
        return raw + b"\n"
    if k == 0:
        b[rnd.randrange(len(b))] ^= 1 << rnd.randrange(8)
    elif k == 1:
        del b[rnd.randrange(len(b))]
    elif k == 2:
        lines = raw.split(b"\n")
        del lines[rnd.randrange(len(lines))]
        return b"\n".join(lines)
    elif k == 3:
        return raw.replace(b"\n", b"\r\n", rnd.randint(1, 3))
    elif k == 4:
        i = raw.index(b"\n\n")
        return raw[:i + 1] + rnd.choice([b"ext line\n", b"\n", b" \n", b"0\n"]) + raw[i + 1:]
    elif k == 5:
        return raw + rnd.choice([b"\n", b"x", b"\xe2\x80\x94 a AAAAAAA=\n", b"\xe2\x80\x94 a AAAAAA==\n"])
    elif k == 6:
        return raw[:rnd.randrange(len(raw))]
    elif k == 7:
        lines = raw.split(b"\n")
        lines[1] = rnd.choice([b"0300", b"+300", b"-1", b"18446744073709551615", b"18446744073709551616", b"0", b""])
        return b"\n".join(lines)
    elif k == 8:
        lines = raw.split(b"\n")
        lines[2] = rnd.choice([lines[2].rstrip(b"="), lines[2] + b"=", base64.b64encode(_rbytes(rnd, 31)),
                               base64.b64encode(_rbytes(rnd, 33)), lines[2][:-2] + b"A="])
        return b"\n".join(lines)
    elif k == 9:
        lines = raw.split(b"\n")
        lines[0] = rnd.choice([b"a b", b"a+b", b"\xc3\xa9", b"{}", b"\t", b"x\x01"])
        return b"\n".join(lines)
    elif k == 10:
        return raw.replace(b"\xe2\x80\x94 ", rnd.choice([b"- ", b"\xe2\x80\x94  ", b"\xe2\x80\x94"]), 1)
    else:
        return bytes(rnd.randrange(256) for _ in range(rnd.randint(1, 200)))
    return bytes(b)


class TestAutoGenerative(unittest.TestCase):
    N = 2000

    def test_matches_the_oracle(self):
        notes = []
        for p in (ROME, os.path.join(MIRROR, "checkpoint"), TORCHWOOD):
            with open(p, "rb") as fh:
                notes.append(fh.read())
        rnd = random.Random(20261115)
        d = tempfile.mkdtemp(prefix="autoc2spgen_")
        p = os.path.join(d, "x")
        seen, wrong = {}, []
        for i in range(self.N):
            raw = rnd.choice(notes)
            for _ in range(rnd.choice([0, 1, 1, 2, 3])):
                raw = _alter(rnd, raw)
            with open(p, "wb") as fh:
                fh.write(raw)
            want = oracle(raw)
            got = _kind(VE.verify_auto(p))
            seen[want] = seen.get(want, 0) + 1
            if got != want:
                wrong.append((i, want, got, raw[:120]))
        shutil.rmtree(d)
        self.assertEqual(wrong, [])
        for k in ("checkpoint", "refused"):
            self.assertGreater(seen.get(k, 0), 100, seen)

    def test_oracle_against_known_texts(self):   # positive control of the oracle itself
        with open(ROME, "rb") as fh:
            note = fh.read()
        self.assertTrue(note_is_checkpoint(note))
        for bad in (note.replace(b"\n300\n", b"\n0300\n"), note[:-1], note.replace(b"\n\n", b"\n"),
                    note.replace(b"\xe2\x80\x94", b"-"), b"\xef\xbb\xbf" + note):
            self.assertFalse(note_is_checkpoint(bad), bad[:60])


if __name__ == "__main__":
    unittest.main()
