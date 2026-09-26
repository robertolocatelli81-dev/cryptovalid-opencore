# SPDX-License-Identifier: AGPL-3.0-or-later
"""Banco CLDMA: controlli POSITIVI (attacchi che DEVONO essere colti) + null onesto + conformance vector.
Il banco deve PRIMA dimostrare di saper fallire. Eseguibile: python3 -m opencore.test_committed_attestation
o direttamente da opencore/: python3 test_committed_attestation.py"""
import copy
try:
    import committed_attestation as C
except ImportError:
    from opencore import committed_attestation as C

SALT, AS_OF = "master-salt-demo", "2026-08-20"


def _ledger(n=13):
    out = []
    for i in range(n):
        out.append({"loan_id": f"L{i}", "borrower_ref": C._h(f"b{i}"),
                    "principal_disbursed": "1000.00", "principal_outstanding": f"{1000 - i*10}.00",
                    "principal_repaid": f"{i*10}.00", "principal_written_off": "0", "currency": "USD",
                    "days_overdue": "90" if i % 4 == 0 else "0",
                    "status": "renegotiated" if i == 1 else "active"})
    return out


def test_property_leaf_path_reconstructs_root():
    for n in range(1, 18):
        L = _ledger(n)
        c = C.commit_ledger(L, SALT, C.SPEC_PAR30, AS_OF)
        for i in range(n):
            op = C.open_leaves(L, SALT, C.SPEC_PAR30, [i])
            assert C.verify_open(c, C.SPEC_PAR30, op)["all_ok"], (n, i)


def test_null_honest_passes():
    L = _ledger(13); c = C.commit_ledger(L, SALT, C.SPEC_PAR30, AS_OF)
    assert C.verify_attestation(C.attestation(c))
    assert C.verify_full(L, SALT, C.SPEC_PAR30, c)["ok"]
    idx = C.challenge(c.root_hash, "verifier-nonce", 5, c.n)
    assert C.verify_open(c, C.SPEC_PAR30, C.open_leaves(L, SALT, C.SPEC_PAR30, idx))["all_ok"]


def test_positive_controls_catch_attacks():
    L = _ledger(13); c = C.commit_ledger(L, SALT, C.SPEC_PAR30, AS_OF)
    # tamper post-commit
    L2 = copy.deepcopy(L); L2[3]["principal_outstanding"] = "1.00"
    assert not C.verify_full(L2, SALT, C.SPEC_PAR30, c)["ok"]
    # ratio incoerente
    att = dict(C.attestation(c)); att["ratio"] = "0.010000"
    assert not C.verify_attestation(att)
    # forgia num_total ma radice vera
    c_fake = C.Commitment(c.root_hash, 0, c.den_total, c.n, "PAR30", AS_OF, tree_root=c.tree_root)
    assert not C.verify_open(c_fake, C.SPEC_PAR30, C.open_leaves(L, SALT, C.SPEC_PAR30, [0]))["all_ok"]
    # misclassificazione su record aperto
    ob = C.open_leaves(L, SALT, C.SPEC_PAR30, [0]); ob[0]["num"] = 0
    assert not C.verify_open(c, C.SPEC_PAR30, ob)["all_ok"]
    # contributo negativo rifiutato
    Ln = copy.deepcopy(L); Ln[2]["principal_outstanding"] = "-5.00"
    try:
        C.commit_ledger(Ln, SALT, C.SPEC_PAR30, AS_OF); assert False
    except ValueError:
        pass


def test_nemesis_holes_closed():
    L = _ledger(13); c = C.commit_ledger(L, SALT, C.SPEC_PAR30, AS_OF)
    # E1 metadati legati alla radice
    c_meta = C.Commitment(c.root_hash, c.num_total, c.den_total, c.n, "PAR30", "1999-01-01", tree_root=c.tree_root)
    assert not C.verify_open(c_meta, C.SPEC_PAR30, C.open_leaves(L, SALT, C.SPEC_PAR30, [1]))["all_ok"]
    # E3 open vuoto
    assert not C.verify_open(c, C.SPEC_PAR30, [])["all_ok"]
    # E4 completezza via expected_n
    sub = [r for r in _ledger(13) if r["days_overdue"] == "0"]
    cs = C.commit_ledger(sub, SALT, C.SPEC_PAR30, AS_OF)
    assert not C.verify_full(sub, SALT, C.SPEC_PAR30, cs, expected_n=13)["ok"]


def test_conformance_vector():
    led = [
        {"loan_id": "A1", "borrower_ref": "h_alice", "principal_disbursed": "1000.00", "principal_outstanding": "800.00", "principal_repaid": "200.00", "principal_written_off": "0", "currency": "USD", "days_overdue": "0", "status": "active"},
        {"loan_id": "A2", "borrower_ref": "h_bob", "principal_disbursed": "500.00", "principal_outstanding": "500.00", "principal_repaid": "0", "principal_written_off": "0", "currency": "USD", "days_overdue": "95", "status": "active"},
        {"loan_id": "A3", "borrower_ref": "h_carol", "principal_disbursed": "2000.00", "principal_outstanding": "1500.00", "principal_repaid": "500.00", "principal_written_off": "0", "currency": "USD", "days_overdue": "0", "status": "renegotiated"},
    ]
    c = C.commit_ledger(led, "CONFORMANCE-SALT-v1", C.SPEC_PAR30, "2026-08-20")
    att = C.attestation(c)
    assert att["root_hash"] == "e433e1588183683887a9b5db63e3b880ac9f1fd79d00fec8ff5cde83987e3315", att["root_hash"]
    assert att["ratio"] == "0.714286" and att["numerator_minor"] == 200000 and att["denominator_minor"] == 280000


def test_den_zero_defined():
    led = [{"loan_id": "Z", "borrower_ref": "h", "principal_disbursed": "0", "principal_outstanding": "0",
            "principal_repaid": "0", "principal_written_off": "0", "currency": "USD", "days_overdue": "0", "status": "active"}]
    c = C.commit_ledger(led, "s", C.SPEC_PAR30, "2026-08-20")
    att = C.attestation(c)
    assert att["denominator_minor"] == 0 and att["ratio"] == "0.000000"  # indefinito per convenzione, non 0% rischio
    assert C.verify_attestation(att)


def test_buco_A_totali_falsi_con_radice_reale():
    # controllo 3-menti 21/08: un prover pubblica totali FALSI tenendo una radice reale.
    # verify_attestation prima si fidava dei campi (falso-verde), ora lega i totali alla radice.
    led = [{"loan_id": "L", "principal_outstanding": "100.00", "days_overdue": "40", "status": "active"}]
    c = C.commit_ledger(led, "s", C.SPEC_PAR30, "2026-08-20")
    att = C.attestation(c)
    assert C.verify_attestation(att)                    # onesto: verde
    forged = dict(att); forged["numerator_minor"] = 0; forged["ratio"] = "0.000000"
    assert not C.verify_attestation(forged)             # sgonfiato: rosso
    # anche togliere il tree_root (per aggirare il binding) = fail-closed
    no_root = dict(att); no_root.pop("tree_root")
    assert not C.verify_attestation(no_root)


def test_buco_B_sibling_negativo_in_verify_open():
    # exploit riprodotto: albero costruito a mano con un sibling NEGATIVO che sgonfia il
    # numeratore. verify_open ora impone la non-negativita' di ogni contributo del path.
    spec, master = C.SPEC_PAR30, "m"
    rec0 = {"loan_id": "L0", "principal_outstanding": "100.00", "days_overdue": "40", "status": "active"}
    salt0 = C.leaf_salt(master, 0)
    n0, d0 = spec.num_of(rec0), spec.den_of(rec0)
    leaf0 = C.leaf_node(rec0, salt0, n0, d0)
    evil_num, evil_hash = -n0, C._h("evil")
    root_num, root_den = n0 + evil_num, d0
    root_int = C._h(C._enc("N", leaf0["hash"], evil_hash, root_num, root_den))
    root_pub = C._bind_meta(root_int, 2, spec.metric_id, "2026-08-20", root_num, root_den)
    cc = C.Commitment(root_pub, root_num, root_den, 2, spec.metric_id, "2026-08-20", tree_root=root_int)
    opened = [{"index": 0, "record": rec0, "salt": salt0, "num": n0, "den": d0,
               "path": [{"side": "right", "num": evil_num, "den": 0, "hash": evil_hash}]}]
    assert not C.verify_open(cc, spec, opened)["all_ok"]


# --- disciplina dual-hash travasata in CLDMA (2026-08-22): dual-hash + guardia che sa fallire ---
def test_cldma_guard_catches_impossible_ratio():
    # PRIMA dimostra di saper FALLIRE: un PAR30 > 100% e' impossibile (piu' a-rischio del totale).
    # verify_attestation da solo lo ACCETTA se la radice lega i totali falsi; verify_metric_consistency NO.
    led = [{"loan_id": "L", "principal_outstanding": "100.00", "days_overdue": "40", "status": "active"}]
    c = C.commit_ledger(led, "s", C.SPEC_PAR30, "2026-08-22")
    att = C.attestation(c)
    assert C.verify_metric_consistency(att)["ok"]                 # onesto: passa entrambe
    from decimal import Decimal as D
    bad = dict(att); bad["numerator_minor"] = 2000; bad["denominator_minor"] = 1000
    bad["ratio"] = str((D(2000) / D(1000)).quantize(D("0.000001")))
    bad["root_hash"] = C._bind_meta(att["tree_root"], att["n_records"], att["metric_id"], att["as_of"], 2000, 1000)
    bad["numerical_hash"] = C.metric_numerical_hash(att["spec_version"], att["metric_id"], att["as_of"], 2000, 1000)
    assert C.verify_attestation(bad)                              # buco: verify_attestation da solo accetta
    assert not C.verify_metric_consistency(bad)["ok"]            # la guardia FALLISCE (come deve)


def test_cldma_numerical_hash_is_salt_independent():
    # dual-hash: stesso ledger, salt diversi -> root_hash diverso (emissione) ma numerical_hash uguale (calcolo)
    led = [{"loan_id": "L", "principal_outstanding": "500.00", "days_overdue": "10", "status": "active"},
           {"loan_id": "M", "principal_outstanding": "500.00", "days_overdue": "60", "status": "active"}]
    a1 = C.attestation(C.commit_ledger(led, "salt-1", C.SPEC_PAR30, "2026-08-22"))
    a2 = C.attestation(C.commit_ledger(led, "salt-2", C.SPEC_PAR30, "2026-08-22"))
    assert a1["root_hash"] != a2["root_hash"]                    # emissione diversa
    assert a1["numerical_hash"] == a2["numerical_hash"]          # calcolo derivato riprodotto


def test_cldma_verifier_ignores_declared_num_le_den():
    # un prover malevolo mette num_le_den=False per schivare il check: il verificatore usa KNOWN_BOUNDED
    led = [{"loan_id": "L", "principal_outstanding": "100.00", "days_overdue": "40", "status": "active"}]
    att = C.attestation(C.commit_ledger(led, "s", C.SPEC_PAR30, "2026-08-22"))
    from decimal import Decimal as D
    bad = dict(att); bad["numerator_minor"] = 500; bad["denominator_minor"] = 100
    bad["ratio"] = str((D(500) / D(100)).quantize(D("0.000001")))
    bad["numerical_hash"] = C.metric_numerical_hash(att["spec_version"], att["metric_id"], att["as_of"], 500, 100)
    bad["num_le_den"] = False                                    # il prover mente sulla proprieta'
    assert not C.verify_metric_consistency(bad)["ok"]           # KNOWN_BOUNDED[PAR30]=True vince -> FAIL


def _with_fake_ots(calendars):
    """Inject a minimal stand-in for the `opentimestamps` package (no network, no dependency): each url maps to a
    callable digest -> message the fake calendar claims to commit, or to an exception to raise."""
    import sys
    import types

    class _Ts:
        def __init__(self, msg):
            self.msg = msg

        def serialize(self, ctx):
            ctx.buf += b"TS" + self.msg

    class _Ctx:
        def __init__(self):
            self.buf = b""

        def getbytes(self):
            return self.buf

    class _Remote:
        def __init__(self, url):
            self.url = url

        def submit(self, digest, timeout=None):
            behaviour = calendars[self.url]
            if isinstance(behaviour, Exception):
                raise behaviour
            return _Ts(behaviour(digest))

    cal = types.ModuleType("opentimestamps.calendar")
    cal.RemoteCalendar, cal.DEFAULT_AGGREGATORS = _Remote, tuple(calendars)
    ser = types.ModuleType("opentimestamps.core.serialize")
    ser.BytesSerializationContext = _Ctx
    names = ("opentimestamps", "opentimestamps.calendar", "opentimestamps.core", "opentimestamps.core.serialize")
    saved = {n: sys.modules.get(n) for n in names}
    sys.modules.update({"opentimestamps": types.ModuleType("opentimestamps"), "opentimestamps.calendar": cal,
                        "opentimestamps.core": types.ModuleType("opentimestamps.core"),
                        "opentimestamps.core.serialize": ser})
    return saved


def _restore(saved):
    import sys
    for n, m in saved.items():
        if m is None:
            sys.modules.pop(n, None)
        else:
            sys.modules[n] = m


def test_anchor_without_the_library_says_so():
    """26/09/2026: up to 0.16.0 this imported a module outside the repository and always answered "not available"
    in a public install. Without the optional library the answer must still be an honest ok=False, never a raise."""
    import sys
    c = C.commit_ledger(_ledger(5), SALT, C.SPEC_PAR30, AS_OF)
    names = ("opentimestamps", "opentimestamps.calendar", "opentimestamps.core", "opentimestamps.core.serialize")
    saved = {n: sys.modules.get(n) for n in names}
    sys.modules.update({n: None for n in names})     # None in sys.modules makes the import fail
    try:
        r = C.anchor_commitment(c)
    finally:
        _restore(saved)
    assert r["ok"] is False and "opentimestamps not installed" in r["error"], r


def test_anchor_counts_each_calendar_and_guards_the_message():
    """One calendar committed, one unreachable, one returning a timestamp for another message: only the first counts.
    The third case tests the defensive invariant msg == root; python-opentimestamps 0.4.5 builds the Timestamp from the
    digest WE pass, so with the real library that guard cannot trip — it is kept for other client implementations."""
    c = C.commit_ledger(_ledger(5), SALT, C.SPEC_PAR30, AS_OF)
    saved = _with_fake_ots({"https://good": lambda d: d, "https://down": OSError("unreachable"),
                            "https://liar": lambda d: bytes(32)})
    try:
        r = C.anchor_commitment(c)
    finally:
        _restore(saved)
    assert r["ok"] is True and r["calendars_committed"] == ["https://good"], r
    assert r["calendars_total"] == 3 and r["status"] == "pending-bitcoin"
    assert r["raw"] == {"https://good": True, "https://down": False, "https://liar": False}, r["raw"]
    assert set(r["errors"]) == {"https://down", "https://liar"} and "another message" in r["errors"]["https://liar"]
    import base64
    assert base64.b64decode(r["proofs"]["https://good"]) == b"TS" + bytes.fromhex(c.root_hash)
    saved = _with_fake_ots({"https://down": OSError("unreachable")})
    try:
        r = C.anchor_commitment(c)
    finally:
        _restore(saved)
    assert r["ok"] is False and r["status"] == "failed" and r["calendars_committed"] == [], r
    saved = _with_fake_ots({"https://good": lambda d: d})
    try:
        r = C.anchor_commitment(c, calendars=[])          # an empty list replaces the defaults: no calendar at all
    finally:
        _restore(saved)
    assert r["ok"] is False and r["calendars_total"] == 0, r


def test_anchor_live_opt_in():
    """Real calendars, only with CV_ONLINE_OTS=1 and the library installed: the returned proof must decode to an
    OpenTimestamps Timestamp whose message is our root."""
    import os
    import sys
    if os.environ.get("CV_ONLINE_OTS") != "1":
        print("[SKIP] test_anchor_live_opt_in: set CV_ONLINE_OTS=1 (and install the [ots] extra) to run it", file=sys.stderr)
        return "skip"
    import base64
    from opentimestamps.core.notary import PendingAttestation
    from opentimestamps.core.serialize import BytesDeserializationContext
    from opentimestamps.core.timestamp import Timestamp
    c = C.commit_ledger(_ledger(5), SALT, C.SPEC_PAR30, AS_OF)
    r = C.anchor_commitment(c, timeout=30)
    assert r["ok"] is True, r
    for url, b64 in r["proofs"].items():
        ts = Timestamp.deserialize(BytesDeserializationContext(base64.b64decode(b64)), bytes.fromhex(c.root_hash))
        atts = [att for _, att in ts.all_attestations()]
        assert ts.msg == bytes.fromhex(c.root_hash) and atts, url
        assert all(isinstance(att, PendingAttestation) for att in atts), (url, atts)   # pending, measured not labelled


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    skipped = 0
    for fn in fns:
        if fn() == "skip":
            skipped += 1
        else:
            print(f"[OK] {fn.__name__}")
    ran = len(fns) - skipped
    print(f">>> CLDMA: {ran}/{ran} test verdi, {skipped} saltati (positivi colgono, null passa, conformance congelato)")
