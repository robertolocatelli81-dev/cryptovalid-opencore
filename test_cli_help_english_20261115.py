# SPDX-License-Identifier: AGPL-3.0-or-later
"""The --help of every command line in this package is English, like the rest of the public package. On 15/11/2026
`cryptovalid-verify --help` (and the --help of each of its commands) said "Un verificatore per TUTTA l'evidenza
CryptoValid, offline", and verifier.py, cryptovalid_heterogeneous.py, cryptovalid_reanchor.py and cryptovalid_worm.py
had Italian descriptions or option help.

Every tracked top-level module that builds a parser is run with --help, and again with --help after each command its
usage lists between braces; the output must hold no Italian accented letter and none of the Italian words below. The
detector is checked first on the texts the help held before (positive control)."""
import os
import re
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))

ITALIAN_WORDS = (
    "il", "lo", "gli", "della", "delle", "dello", "degli", "alla", "nel", "sul", "del", "una", "uno", "di", "da", "ed",
    "che", "se", "anche", "oppure", "ogni", "senza", "solo", "tutta", "tutto", "tutti", "questo", "questa", "sono",
    "nessun", "nessuna", "firma", "verifica", "verificatore", "stampa", "scrivi", "valuta", "segnala", "forza",
    "algoritmo", "lista", "percorso", "chiave", "uscita", "ancora", "dato", "fiducia", "indipendente", "indipendenti",
    "immutabile", "evidenza", "file JSON con",
)
_WORDS = re.compile(r"\b(" + "|".join(re.escape(w) for w in ITALIAN_WORDS) + r")\b", re.I)
_ACCENTED = re.compile("[àèéìòùÀÈÉÌÒÙ]")

# what the help held before 15/11/2026: each must be caught
OLD_TEXTS = (
    "Un verificatore per TUTTA l'evidenza CryptoValid, offline",
    "Stampa solo il verdetto sintetico (PASS/FAIL + exit code)",
    "Scrivi receipt JSON anche su file",
    "Path del file .jsonl da verificare",
    "Forza algoritmo (default: auto-detect)",
    "Verifica indipendente di un OMEGA ledger .jsonl (auditor-grade, stdlib-only).",
    "Verifica un'ancora ETEROGENEA (>=N domini di fiducia indipendenti).",
    'file JSON: lista di attestazioni [{"domain": ...}, ...]',
    "Valuta il decadimento di un'ancora e segnala se ri-ancorare.",
    'file JSON con almeno {"witnesses_with_tx": N}',
    "WORM escrow store — retention immutabile del dato (SEC 17a-4).",
)


def italian(text: str) -> list:
    return sorted(set(_ACCENTED.findall(text)) | {m.lower() for m in _WORDS.findall(text)})


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


def _tracked_py() -> list:
    """The repository's Python files: `git ls-files` in a checkout; in an unpacked sdist (PKG-INFO at the top, no git
    metadata), every .py it holds, since the sdist is the released file list (15/11/2026: the sdist carries the suite).
    Anywhere else: a failure that says so, never an empty list."""
    try:
        r = subprocess.run(["git", "-C", HERE, "ls-files", "*.py"], capture_output=True, text=True)
        if r.returncode == 0:
            return r.stdout.split()
        why = r.stderr.strip()
    except OSError as e:
        why = repr(e)
    if os.path.isfile(os.path.join(HERE, "PKG-INFO")):
        return sorted(os.path.relpath(os.path.join(d, f), HERE) for d, _, fs in os.walk(HERE)
                      if "__pycache__" not in d.split(os.sep) for f in fs if f.endswith(".py"))
    raise AssertionError(f"neither a git checkout nor an unpacked sdist: {why}")


def _modules() -> list:
    files = _tracked_py()
    out = []
    for f in files:
        if "/" in f or f.startswith("test_"):
            continue
        with open(os.path.join(HERE, f), encoding="utf-8") as fh:
            src = fh.read()
        if "add_argument(" in src and "__main__" in src:
            out.append(f)
    return out


class TestCliHelpEnglish(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.home = tempfile.mkdtemp()
        cls.env = {k: v for k, v in os.environ.items() if k not in ("PYTHONPATH", "PYTHONHOME", "PYTHONSTARTUP")}
        cls.env = _child_env(dict(cls.env, HOME=cls.home, LC_ALL="C.UTF-8", PYTHONIOENCODING="utf-8"))

    def _help(self, argv):
        r = subprocess.run([sys.executable, *_child_flags(), *argv, "--help"], cwd=HERE, env=self.env,
                           capture_output=True, text=True, timeout=120)
        return r.returncode, r.stdout + r.stderr

    def test_detector_catches_the_old_texts(self):
        for t in OLD_TEXTS:
            self.assertTrue(italian(t), t)
        self.assertEqual(italian("print only the verdict (PASS/FAIL, and the exit code); policy_digest per §6.8; "
                                 "append-only / non-equivocation monitor"), [])

    def test_every_help_is_english(self):
        mods = _modules()
        self.assertIn("verify_evidence.py", mods)
        self.assertGreater(len(mods), 20)
        found, ran = {}, 0
        for m in mods:
            rc, out = self._help([m])
            ran += 1
            self.assertEqual(rc, 0, f"{m} --help: exit {rc}\n{out[-800:]}")
            if italian(out):
                found[m] = italian(out)
            u = re.search(r"^usage:.*?\{([^}]+)\}", out, re.M | re.S)
            for cmd in (u.group(1).split(",") if u else []):
                rc, sout = self._help([m, cmd])
                ran += 1
                self.assertEqual(rc, 0, f"{m} {cmd} --help: exit {rc}\n{sout[-800:]}")
                if italian(sout):
                    found[f"{m} {cmd}"] = italian(sout)
        self.assertEqual(found, {})
        self.assertGreater(ran, len(mods))

    def test_cryptovalid_verify_lists_its_commands(self):
        rc, out = self._help(["verify_evidence.py"])
        self.assertEqual(rc, 0)
        for cmd in ("auto", "pack", "archive", "ledger", "ap2", "cldma"):
            self.assertRegex(out, rf"(?m)^  {cmd} +\S")
            rc, sub = self._help(["verify_evidence.py", cmd])
            self.assertEqual((rc, sub), (0, out))


if __name__ == "__main__":
    unittest.main()
