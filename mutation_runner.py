"""
CryptoValid · mutation runner SISTEMATICO (stdlib) — annichila W7.

W7 (supreme-ai + Fable + Gemini): finora solo mutanti SCELTI A MANO → "il banco becca un verifier corrotto"
era estrapolato da pochi mutanti su guardie già coperte. mutmut/cosmic-ray NON sono installabili qui
(PEP 668, env gestito). Questo runner colma il gap SENZA dipendenze: genera mutanti da REGOLE (operatori
di confronto, booleani, letterali, appartenenza) su TUTTO un file — generazione sistematica, non cherry-pick
— esegue la test-suite per ognuno e calcola il MUTATION SCORE reale (uccisi/totale) elencando i sopravvissuti.

HONEST-SCOPE: è un runner LEGGERO (mutazioni a livello di token su classi comuni), un gradino REALE sopra i
mutanti a mano ma NON un mutation-testing completo (mutmut/cosmic-ray fanno AST, più operatori, incrementale).
Caveat dichiarato: le mutazioni che cadono dentro stringhe/commenti sono "mutanti equivalenti" (non uccidibili)
→ i commenti a riga piena sono saltati, ma una mutazione dentro una stringa può gonfiare i sopravvissuti: si
leggano i sopravvissuti col contesto. Da eseguire in CI; una passata mutmut in un venv resta il gradino sopra.
Stdlib only.
"""
import glob
import os
import shutil
import subprocess
from typing import Dict, Iterator, List, Tuple

# regole di mutazione: (token, sostituto). Ordine: i più lunghi prima (match non ambiguo).
_RULES: List[Tuple[str, str]] = [
    (" is not None", " is None"),
    (" is None", " is not None"),
    (" not in ", " in "),
    (" in ", " not in "),
    (" and ", " or "),
    (" or ", " and "),
    (">=", "<"),
    ("<=", ">"),
    ("==", "!="),
    ("!=", "=="),
    (">", "<="),
    ("<", ">="),
    ("True", "False"),
    ("False", "True"),
]


def _forbidden_spans(src: str) -> Dict[int, List[Tuple[int, int]]]:
    """Per ogni riga (1-based), gli intervalli [col_start,col_end) che stanno DENTRO stringhe o commenti:
    lì una mutazione è un 'mutante equivalente' (non cambia il comportamento) → va saltata. Usa tokenize
    (stdlib), che gestisce correttamente docstring, stringhe multi-riga e commenti."""
    import io
    import token as _tok
    import tokenize
    spans: Dict[int, List[Tuple[int, int]]] = {}
    try:
        for t in tokenize.generate_tokens(io.StringIO(src).readline):
            if t.type in (_tok.STRING, _tok.COMMENT) or getattr(_tok, "FSTRING_START", -1) == t.type:
                (r1, c1), (r2, c2) = t.start, t.end
                for r in range(r1, r2 + 1):
                    lo = c1 if r == r1 else 0
                    hi = c2 if r == r2 else 10 ** 9
                    spans.setdefault(r, []).append((lo, hi))
    except (tokenize.TokenError, IndentationError):
        pass                               # sorgente non tokenizzabile: nessuna esclusione (conservativo)
    return spans


def generate_mutants(src: str) -> Iterator[Tuple[str, str]]:
    """Genera (descrizione, sorgente_mutato) — UNA mutazione per occorrenza di ogni regola, SOLO nel codice
    eseguibile (stringhe e commenti esclusi via tokenize → niente mutanti equivalenti da docstring).
    Sistematico: copre tutte le occorrenze reali."""
    lines = src.splitlines(keepends=True)
    forbidden = _forbidden_spans(src)

    def _in_string(lineno: int, col: int) -> bool:
        return any(lo <= col < hi for lo, hi in forbidden.get(lineno, ()))

    for li, line in enumerate(lines):
        if line.lstrip().startswith("#"):
            continue
        for tok, rep in _RULES:
            start = 0
            while True:
                idx = line.find(tok, start)
                if idx == -1:
                    break
                start = idx + len(tok)
                if _in_string(li + 1, idx):      # dentro stringa/commento → mutante equivalente, salta
                    continue
                mutated_line = line[:idx] + rep + line[idx + len(tok):]
                new_lines = lines[:li] + [mutated_line] + lines[li + 1:]
                yield (f"L{li+1}: '{tok.strip()}'→'{rep.strip()}' @col{idx}", "".join(new_lines))


def run_mutation(target_path: str, test_cmd: List[str], limit: int = 0) -> Dict:
    """Muta `target_path` una volta per mutante, esegue `test_cmd` (lista argv), UCCIDE il mutante se la
    suite fallisce. Restore GARANTITO del file. limit>0 tronca (e lo DICHIARA). Ritorna il report."""
    bak = target_path + ".mutbak"
    shutil.copy(target_path, bak)
    base_src = open(target_path, encoding="utf-8").read()
    tgt_dir = os.path.dirname(os.path.abspath(target_path))

    def _clear_pyc():
        # la cache bytecode cross-contamina i mutanti (un .pyc stantio riusato tra scritture nello stesso
        # secondo → falsi 'uccisi'). Pulisco il __pycache__ del target prima di ogni esecuzione.
        for p in glob.glob(os.path.join(tgt_dir, "__pycache__", "*.pyc")):
            try:
                os.remove(p)
            except OSError:
                pass

    # env con bytecode-write DISABILITATO: nessun .pyc scritto → ogni mutante ricompila dal sorgente.
    _env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")

    def _suite_green() -> bool:
        _clear_pyc()
        return subprocess.run(test_cmd, capture_output=True, env=_env).returncode == 0

    result = {"target": target_path, "killed": 0, "survived": [], "total": 0,
              "baseline_green": None, "truncated": False}
    try:
        result["baseline_green"] = _suite_green()      # NULL CONTROL: senza mutazioni la suite DEVE passare
        if not result["baseline_green"]:
            return result                              # baseline rossa → il runner non può misurare
        mutants = list(generate_mutants(base_src))
        if limit and len(mutants) > limit:
            mutants = mutants[:limit]
            result["truncated"] = True                 # troncamento DICHIARATO, mai silenzioso
        result["total"] = len(mutants)
        for desc, msrc in mutants:
            with open(target_path, "w", encoding="utf-8") as f:
                f.write(msrc)
            killed = not _suite_green()
            if killed:
                result["killed"] += 1
            else:
                result["survived"].append(desc)
            shutil.copy(bak, target_path)              # restore dopo OGNI mutante
    finally:
        shutil.copy(bak, target_path)                  # restore garantito
        os.remove(bak)
    result["score"] = round(result["killed"] / result["total"], 3) if result["total"] else None
    return result


def main(argv=None):
    import sys
    a = argv if argv is not None else sys.argv[1:]
    if len(a) < 2:
        print("usage: python3 -m opencore.mutation_runner <target.py> <test_cmd...> [--limit N]")
        return 2
    limit = 0
    if "--limit" in a:
        i = a.index("--limit")
        limit = int(a[i + 1])
        a = a[:i] + a[i + 2:]
    target, test_cmd = a[0], a[1:]
    r = run_mutation(target, test_cmd, limit=limit)
    import json
    print(json.dumps({k: v for k, v in r.items() if k != "survived"}, indent=1))
    if r["survived"]:
        print(f"SOPRAVVISSUTI ({len(r['survived'])}):")
        for s in r["survived"][:50]:
            print("  -", s)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
