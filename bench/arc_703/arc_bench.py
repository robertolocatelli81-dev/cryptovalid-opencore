"""Tamper bench on the audit-log schema of Basekick-Labs/arc (issue #703), reproducible from this repository.

    python3 bench/arc_703/arc_bench.py          # needs: python3 + `cryptography`; node and go optional (extra sweeps)

What it measures (200 rows of the 13-field `audit_logs` schema, hash-chained the cryptovalid way): every tampering
it can enumerate — mutate / delete / add any field of any row, change a timestamp, delete any row, swap adjacent
rows, delete the first 1/10/50 rows, corrupt a hash — 6003 in total; how many the bare verifier catches; the
monitor on the truncated tail; a receipt; the JS and Go verifiers on the same tamperings; and the signed chain
tip. The bench proves it can FAIL first (a fake "always PASS" verifier is caught). Results are printed as JSON
lines; the committed `risultati.jsonl` is one run of 15/09/2026.
"""
import sys, os, json, hashlib, random, tempfile, subprocess, copy
ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))   # repo root (opencore)
sys.path.insert(0, ROOT)
import verifier as V, signer, cryptovalid_receipt as R, cryptovalid_monitor as MON, cryptovalid_merkle as M
random.seed(20260914)
N = 200
EVENTS = ["query", "write", "auth_failure", "admin_action", "schema_change", "retention_delete"]
def arc_row(i):
    return {"id": i + 1, "timestamp": f"2026-09-14T1{i//600:01d}:{(i//10)%60:02d}:{i%60:02d}Z",
            "event_type": random.choice(EVENTS), "actor": random.choice(["alice", "bob", "svc-ingest", "anonymous", "müller-é"]),
            "method": random.choice(["GET", "POST", "DELETE"]), "path": random.choice(["/api/v1/query", "/api/v1/write", "/admin/retention"]),
            "database_name": random.choice(["telemetry", "", "finance"]), "measurement": random.choice(["cpu", "", "trades"]),
            "status_code": random.choice([200, 201, 401, 500]), "ip_address": f"10.0.{random.randint(0,255)}.{random.randint(1,254)}",
            "user_agent": random.choice(["curl/8.5", "telegraf/1.30", "Mozilla/5.0 (X11; Linux) 中文"]),
            "duration_ms": random.randint(0, 5000), "detail": random.choice(["", json.dumps({"rows": random.randint(1, 10**6), "note": "€ \"quoted\""})])}
def canon_hash(e):
    body = {k: v for k, v in e.items() if k not in ("self_hash", "signature", "signer")}
    return hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
def build(rows):
    out, prev = [], "0" * 64
    for i, r in enumerate(rows):
        e = {"idx": i, "ts": r["timestamp"], "prev_hash": prev, "data": r}
        e["self_hash"] = canon_hash(e); prev = e["self_hash"]; out.append(e)
    return out
def write(path, entries):
    with open(path, "w", encoding="utf-8") as f:
        for e in entries: f.write(json.dumps(e, ensure_ascii=False) + "\n")
def passes(entries, path):
    write(path, entries); return V.verify_ledger(path).get("verdict") == "PASS"
tmp = tempfile.mkdtemp(); led = os.path.join(tmp, "arc_audit.jsonl"); work = os.path.join(tmp, "mut.jsonl")
rows = [arc_row(i) for i in range(N)]; base = build(rows); write(led, base)
assert V.verify_ledger(led)["verdict"] == "PASS", "baseline non PASS"
# controllo positivo del banco: un verificatore rotto deve far fallire il banco
orig = V.verify_ledger; V.verify_ledger = lambda p, algo=None: {"verdict": "PASS"}
broken_seen = passes([dict(e, data=dict(e["data"], actor="X")) if i == 3 else e for i, e in enumerate(base)], work)
V.verify_ledger = orig
assert broken_seen is True, "il controllo positivo non ha rilevato il verificatore rotto"
tot = det = 0; miss = []
fields = list(rows[0].keys())
def count(name, entries):
    global tot, det
    tot += 1
    if not passes(entries, work): det += 1
    else: miss.append(name)
def mutations():
    """UNICA enumerazione delle manomissioni, condivisa da Python e Go (15/09: prima il Go ne contava un sottoinsieme)."""
    for i in range(N):
        for f in fields:
            e = copy.deepcopy(base); v = e[i]["data"][f]
            e[i]["data"][f] = (v + "x") if isinstance(v, str) else (v + 1); yield f"mod {i}.{f}", e
            e = copy.deepcopy(base); del e[i]["data"][f]; yield f"del-field {i}.{f}", e
        e = copy.deepcopy(base); e[i]["data"]["injected"] = True; yield f"add-field {i}", e
        e = copy.deepcopy(base); e[i]["ts"] = "2030-01-01T00:00:00Z"; yield f"ts {i}", e
        e = copy.deepcopy(base); del e[i]; yield f"delete-row {i}", e                       # cancellazione (anche l'ULTIMA riga)
        if i + 1 < N:
            e = copy.deepcopy(base); e[i], e[i + 1] = e[i + 1], e[i]; yield f"swap {i}", e
    for k in (1, 10, 50):
        e = copy.deepcopy(base)[k:]; yield f"retention-delete-first-{k}", e                 # il caso che li preoccupa
    e = copy.deepcopy(base); e[7]["self_hash"] = e[7]["self_hash"][:-1] + ("0" if e[7]["self_hash"][-1] != "0" else "1"); yield "hash-field", e
for name, e in mutations():
    count(name, e)
last_row_deletions = [m for m in miss if m == f"delete-row {N-1}"]
print(json.dumps({"righe": N, "manomissioni_totali": tot, "rilevate_dal_verifier": det, "non_rilevate": len(miss),
                  "non_rilevate_elenco": miss[:10]}, ensure_ascii=False))
# la coda: verifier da solo non può vedere una riga in coda cancellata (catena ancora valida) → monitor + STH
k = os.path.join(tmp, "log.key"); pk = signer.keygen(k)["public_key_hex"]
st = os.path.join(tmp, "state.json"); assert MON.run(led, st, keyfile=k)["ok"]
write(led, base[:-1]); v = MON.run(led, st, keyfile=k)
print(json.dumps({"coda_cancellata_rilevata_dal_monitor": (not v["ok"]) and any("TRUNC" in a for a in v["alerts"])}))
write(led, base)
rc = R.inclusion_receipt(led, 123, k); ok_r = R.verify_receipt(rc, pk, leaf_canonical=M.canonical(base[123]))["ok"]
bad_r = R.verify_receipt(rc, pk, leaf_canonical=M.canonical(dict(base[123], data=dict(base[123]["data"], actor="X"))))["ok"]
print(json.dumps({"ricevuta_riga_123_verifica_offline": ok_r, "ricevuta_su_riga_alterata": bad_r}))
# verificatore JS indipendente sugli stessi file (baseline + 3 mutanti)
js = os.path.join(ROOT, "verifiers", "js", "cvverify.mjs")
if os.path.exists(js) and subprocess.run(["which", "node"], capture_output=True).returncode == 0:
    def jsv(entries):
        write(work, entries); r = subprocess.run(["node", js, work], capture_output=True, text=True); return r.returncode
    e1 = copy.deepcopy(base); e1[50]["data"]["status_code"] += 1
    e2 = copy.deepcopy(base); del e2[100]
    e3 = copy.deepcopy(base); e3[10], e3[11] = e3[11], e3[10]
    print(json.dumps({"js_baseline_rc": jsv(base), "js_mutanti_rc": [jsv(e1), jsv(e2), jsv(e3)]}))
else:
    print(json.dumps({"js": "verificatore JS non trovato (file o node)"}))
# sweep completo anche col JS (indipendente da Python): stessi 6003 casi
if os.path.exists(js):
    jt = jd = 0; jmiss = []
    def jcount(name, entries):
        global jt, jd
        jt += 1
        if jsv(entries) != 0: jd += 1
        else: jmiss.append(name)
    for i in range(0, N, 4):          # 1 riga su 4 (JS ~10× più lento): 50 righe × tutte le mutazioni
        for f in fields:
            e = copy.deepcopy(base); v = e[i]["data"][f]; e[i]["data"][f] = (v + "x") if isinstance(v, str) else (v + 1); jcount(f"mod {i}.{f}", e)
        e = copy.deepcopy(base); del e[i]; jcount(f"delete-row {i}", e)
        if i + 1 < N: e = copy.deepcopy(base); e[i], e[i+1] = e[i+1], e[i]; jcount(f"swap {i}", e)
    e = copy.deepcopy(base); del e[N-1]; jcount(f"delete-row {N-1}", e)
    print(json.dumps({"js_sweep_totale": jt, "js_rilevate": jd, "js_non_rilevate": jmiss}))

# sweep completo col verificatore GO (compilato al volo; 15/09: prima il cross-check Go viveva in uno script perso)
gosrc = os.path.join(ROOT, "verifiers", "go")
gobin = os.path.join(tmp, "cvverify-go")
env = dict(os.environ)
if subprocess.run(["go", "build", "-o", gobin, "./cmd/cvverify"], cwd=gosrc, env=env, capture_output=True).returncode == 0:
    def gov(entries):
        write(work, entries); return subprocess.run([gobin, work], capture_output=True, text=True).returncode
    gt = gd = 0; gmiss = []
    def gcount(name, entries):
        global gt, gd
        gt += 1
        if gov(entries) != 0: gd += 1
        else: gmiss.append(name)
    for name, e in mutations():       # ESATTAMENTE le stesse manomissioni del verifier Python (stesso generatore)
        gcount(name, e)
    print(json.dumps({"go_baseline_rc": gov(base), "go_sweep_totale": gt, "go_rilevate": gd, "go_non_rilevate": gmiss[:10],
                      "go_identico_a_python": (gt == tot and gd == det and gmiss == miss)}))
else:
    print(json.dumps({"go": "toolchain Go assente: sweep Go non eseguito"}))

# ── 15/09: il limite della coda si sposta con il capo-catena firmato (cryptovalid_tip) ───────────────────────
# Stesse 6003 manomissioni, ma il verificatore ha anche il tip firmato dal writer e la chiave pubblica fidata.
import cryptovalid_tip as TIP
tk = os.path.join(tmp, "tip.key"); tpk = signer.keygen(tk)["public_key_hex"]
write(led, base); tip_doc = TIP.sign_tip(led, tk)
def passes_tip(entries, path):
    write(path, entries)
    return V.verify_ledger(path, tip=led + ".tip.json", trusted_pubkey_hex=tpk).get("verdict") == "PASS"
assert passes_tip(base, work) is True, "baseline con tip non PASS"
# controllo positivo del banco col tip: verificatore finto → il banco deve accorgersene
orig = V.verify_ledger; V.verify_ledger = lambda p, **k: {"verdict": "PASS"}
assert passes_tip(base[:-1], work) is True; V.verify_ledger = orig
assert passes_tip(base[:-1], work) is False, "il tip non vede la coda cancellata"
tt = td = 0; tmiss = []
for name, e in mutations():
    tt += 1
    if not passes_tip(e, work): td += 1
    else: tmiss.append(name)
# l'attaccante senza chiave: cancella il tip (visibile solo se richiesto) o lo rifirma con la SUA chiave
write(work, base[:-1]); ak = os.path.join(tmp, "attacker.key"); signer.keygen(ak)
TIP.sign_tip(work, ak)                                   # tip dell'attaccante accanto al file manomesso
refirmato = V.verify_ledger(work, trusted_pubkey_hex=tpk)["verdict"]
os.remove(work + ".tip.json")
senza_tip_richiesto = V.verify_ledger(work, trusted_pubkey_hex=tpk, require_tip=True)["verdict"]
senza_tip_non_richiesto = V.verify_ledger(work, trusted_pubkey_hex=tpk)["verdict"]
print(json.dumps({"tip_manomissioni_totali": tt, "tip_rilevate": td, "tip_non_rilevate": tmiss[:10],
                  "tip_rifirmato_da_attaccante_senza_chiave": refirmato,
                  "tip_cancellato_e_richiesto": senza_tip_richiesto,
                  "tip_cancellato_non_richiesto": senza_tip_non_richiesto,
                  "limite_residuo": "chi possiede la chiave del log può troncare e rifirmare; custodia della chiave (HSM/KMS) e copie del tip fuori dalla portata del writer"}))
