#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""cryptovalid_cedulon on ledgers built HERE with fresh Ed25519 keys: a valid ledger first (positive control), then one
change per stage, each refused at that stage. No third-party bytes."""
import base64
import hashlib
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import cryptovalid_cedulon as V  # noqa: E402
import cryptovalid_receipt as R  # noqa: E402
from cryptovalid_acta import jcs  # noqa: E402

from cryptography.hazmat.primitives import serialization as ser  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

H = lambda s: hashlib.sha256(s.encode()).hexdigest()  # noqa: E731


def _pem(sk):
    return sk.public_key().public_bytes(ser.Encoding.PEM, ser.PublicFormat.SubjectPublicKeyInfo)


def _kid(sk):
    return hashlib.sha256(sk.public_key().public_bytes(ser.Encoding.DER, ser.PublicFormat.SubjectPublicKeyInfo)).digest()[:8]


def _cose(sk, ct, payload_map, protected=None, unprotected=None):
    pb = R.cbor_encode(protected if protected is not None else {1: -19, 3: ct, 4: _kid(sk)})
    pl = R.cbor_encode(payload_map)
    sig = sk.sign(R.cbor_encode(["Signature1", pb, b"", pl]))
    return R.cbor_encode([pb, unprotected if unprotected is not None else {}, pl, sig])


def _claims(i, decision, prev, ts):
    allow = decision == "allow"
    return {"decider": "d", "subject": "s", "requestHash": H(f"req{i}"), "policyHash": H("pol"), "inputsHash": None,
            "decision": decision, "reasonCode": "r", "ref": f"ref-{i}", "effectHash": H(f"eff{i}") if allow else None,
            "timestampMs": ts, "nonce": f"n{i}", "prevRecordHash": prev, "effectClass": "reply" if allow else None}


class Ledger:
    """decisions / effects / checkpoints text for a small valid ledger; every part can be bent before rendering."""
    def __init__(self):
        self.rk, self.xk, self.ck = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
        self.kinds = ["allow", "deny", "allow", "defer"]
        self.t0 = 1_790_000_000_000

    def records(self, bend=None):
        out, prev = [], None
        for i, d in enumerate(self.kinds):
            c = _claims(i, d, prev, self.t0 + i)
            payload = {k: c[n] for k, n in V.RECORD_LABELS.items()}
            presented = dict(c)
            kw = {}
            if bend:
                payload, presented, kw = bend(i, payload, presented)
            octets = _cose(self.rk, V.CT_RECORD, payload, **kw)
            out.append((octets, presented))
            prev = hashlib.sha256(octets).hexdigest()
        return out

    def render(self, bend_record=None, bend_rows=None, bend_cp=None, sign_body=None, bend_body=None, presented_cp=None,
               presented_row=None):
        recs = self.records(bend_record)
        dec = "".join(json.dumps({"coseHex": o.hex(), "claims": c}) + "\n" for o, c in recs)
        rows = [{"ref": f"ref-{i}", "effectHash": H(f"eff{i}"), "effectClass": "reply", "timestampMs": self.t0 + i, "actor": "a"}
                for i, d in enumerate(self.kinds) if d == "allow"]
        if bend_rows:
            rows = bend_rows(rows)
        effects = ""
        for r in rows:
            body = {"deciderId": "d", "channelId": "c", "windowStartMs": self.t0, "windowEndMs": self.t0 + 100, "effects": [r]}
            if bend_body:
                body = bend_body(body)
            sig = (sign_body or self.xk).sign(jcs(body))
            line = {"receipt": {"body": body, "signature": base64.b64encode(sig).decode()}}
            if presented_row:                             # the copy of the row a ledger shows beside its extract
                line["row"] = presented_row(r)
            effects += json.dumps(line) + "\n"
        hashes = [hashlib.sha256(o).hexdigest() for o, _ in recs]
        cp = {"epoch": 0, "startMs": self.t0, "endMs": self.t0 + 100, "receiptCount": len(recs), "chainHeadHash": hashes[-1],
              "totals": {d: str(self.kinds.count(d)) for d in V.DECISIONS}, "prevCheckpointHash": None}
        kw = {}
        if bend_cp:
            cp, kw = bend_cp(cp)
        cpm = {k: cp[n] for k, n in V.CHECKPOINT_LABELS.items()}
        if "labels" in kw:
            cpm = kw.pop("labels")(cpm)
        cps = json.dumps({"coseHex": _cose(kw.pop("key", self.ck), V.CT_CHECKPOINT, cpm, **kw).hex(),
                          "claims": presented_cp(cp) if presented_cp else cp}) + "\n"
        return dec, effects, cps

    def verify(self, clock_skew_ms=V.DEFAULT_CLOCK_SKEW_MS, **kw):
        return V.verify_ledger(*self.render(**kw), _pem(self.rk), _pem(self.xk), _pem(self.ck), clock_skew_ms=clock_skew_ms)


class TestCedulon(unittest.TestCase):
    def setUp(self):
        self.L = Ledger()

    def stage(self, r):
        self.assertEqual(r["result"], "INVALID", r)
        return r["stage"]

    def test_valid_ledger_verifies_and_names_what_it_does_not_verify(self):
        r = self.L.verify()
        self.assertEqual(r["result"], "VALID", r)
        self.assertEqual(r["not_verified"], ["inputs-binding", "index", "approval-signature", "control"])

    def bent(self, n, f):
        return lambda i, p, c: f(p, c) if i == n else (p, c, {})

    def test_record_header(self):
        rk = self.L.rk
        cases = {
            "alg -8": lambda p, c: (p, c, {"protected": {1: -8, 3: V.CT_RECORD, 4: _kid(rk)}}),
            "content type": lambda p, c: (p, c, {"protected": {1: -19, 3: "application/cedulon-decision+cbor", 4: _kid(rk)}}),
            "kid": lambda p, c: (p, c, {"protected": {1: -19, 3: V.CT_RECORD, 4: b"\x00" * 8}}),
            "unprotected": lambda p, c: (p, c, {"unprotected": {"x": 1}}),
        }
        for name, f in cases.items():
            with self.subTest(name):
                self.assertEqual(self.stage(self.L.verify(bend_record=self.bent(1, f))), "record-header")

    def test_non_deterministic_protected_header(self):
        rk = self.L.rk
        pb = bytes([0xa3, 0x03]) + R.cbor_encode(V.CT_RECORD) + bytes([0x01, 0x32, 0x04]) + R.cbor_encode(_kid(rk))   # 3 before 1
        self.assertNotEqual(R.cbor_encode(R.cbor_decode(pb)), pb)
        dec, eff, cps = self.L.render()
        first = json.loads(dec.splitlines()[0]); arr = R.cbor_decode(bytes.fromhex(first["coseHex"]))
        sig = rk.sign(R.cbor_encode(["Signature1", pb, b"", arr[2]]))
        first["coseHex"] = R.cbor_encode([pb, {}, arr[2], sig]).hex()
        dec = json.dumps(first) + "\n" + "\n".join(dec.splitlines()[1:]) + "\n"
        r = V.verify_ledger(dec, eff, cps, _pem(rk), _pem(self.L.xk), _pem(self.L.ck))
        self.assertEqual(self.stage(r), "record-header")
        self.assertIn("deterministic", r["why"])

    def test_cose_array_must_have_exactly_four_members(self):
        dec, eff, cps = self.L.render()
        lines = dec.splitlines(); x = json.loads(lines[0]); arr = R.cbor_decode(bytes.fromhex(x["coseHex"]))
        x["coseHex"] = R.cbor_encode(arr + [b"extra"]).hex(); lines[0] = json.dumps(x)
        # relink record 1 to the new octets is not even needed: the header stage refuses first
        r = V.verify_ledger("\n".join(lines) + "\n", eff, cps, _pem(self.L.rk), _pem(self.L.xk), _pem(self.L.ck))
        self.assertEqual(self.stage(r), "record-header")

    def test_record_signature(self):
        dec, eff, cps = self.L.render()
        lines = dec.splitlines(); x = json.loads(lines[2]); h = x["coseHex"]
        x["coseHex"] = h[:-2] + format(int(h[-2:], 16) ^ 1, "02x"); lines[2] = json.dumps(x)
        r = V.verify_ledger("\n".join(lines) + "\n", eff, cps, _pem(self.L.rk), _pem(self.L.xk), _pem(self.L.ck))
        self.assertEqual(self.stage(r), "record-signature")

    def test_record_claims(self):
        lab = {n: k for k, n in V.RECORD_LABELS.items()}
        def setp(name, v):
            return lambda p, c: ({**p, lab[name]: v}, {**c, name: v}, {})
        cases = {
            "decision": setp("decision", "maybe"),
            "hash grammar": setp("policyHash", "AB" * 32),
            "timestamp": setp("timestampMs", 2 ** 53),
            "timestamp bool": setp("timestampMs", True),
            "refusal with effectHash": lambda p, c: ({**p, lab["effectHash"]: H("x")}, {**c, "effectHash": H("x")}, {}),
            "nonce null": setp("nonce", None),
            "twelve labels": lambda p, c: ({k: v for k, v in p.items() if k != -70513}, {k: v for k, v in c.items() if k != "effectClass"}, {}),
            "fourteen labels": lambda p, c: ({**p, -70514: "x"}, c, {}),
            "presented differs": lambda p, c: (p, {**c, "reasonCode": "other"}, {}),
        }
        for name, f in cases.items():
            with self.subTest(name):
                self.assertEqual(self.stage(self.L.verify(bend_record=self.bent(1, f))), "record-claims")
        allow = {"allow no ref": setp("ref", None), "allow empty ref": setp("ref", ""), "allow no effectHash": setp("effectHash", None),
                 "allow no class": setp("effectClass", None)}
        for name, f in allow.items():
            with self.subTest(name):
                self.assertEqual(self.stage(self.L.verify(bend_record=self.bent(0, f))), "record-claims")

    def test_chain(self):
        r = self.L.verify(bend_record=self.bent(2, lambda p, c: ({**p, -70512: H("other")}, {**c, "prevRecordHash": H("other")}, {})))
        self.assertEqual(self.stage(r), "chain")
        r = self.L.verify(bend_record=self.bent(0, lambda p, c: ({**p, -70512: H("x")}, {**c, "prevRecordHash": H("x")}, {})))
        self.assertEqual(self.stage(r), "chain")

    def test_effect_binding(self):
        cases = {
            "effect-mismatch": lambda rows: [{**rows[0], "effectHash": H("zzz")}] + rows[1:],
            "effect-class-mismatch": lambda rows: [{**rows[0], "effectClass": "post"}] + rows[1:],
            "effect-against-refusal": lambda rows: rows + [{**rows[0], "ref": "ref-1"}],
            "effect-without-decision": lambda rows: rows + [{**rows[0], "ref": "nobody"}],
            "duplicate row": lambda rows: rows + [rows[0]],
            "decision-without-effect": lambda rows: rows[1:],
            "outside window": lambda rows: [{**rows[0], "timestampMs": self.L.t0 + 100}] + rows[1:],
            "extra member": lambda rows: [{**rows[0], "x": 1}] + rows[1:],
            "missing member": lambda rows: [{k: v for k, v in rows[0].items() if k != "effectClass"}] + rows[1:],
            "hash grammar": lambda rows: [{**rows[0], "effectHash": "AB" * 32}] + rows[1:],
            "actor type": lambda rows: [{**rows[0], "actor": 3}] + rows[1:],
            "timestamp not an integer": lambda rows: [{**rows[0], "timestampMs": float(rows[0]["timestampMs"])}] + rows[1:],
        }
        for name, f in cases.items():
            with self.subTest(name):
                # the findings themselves, with no boundary allowance (this ledger spans 3 ms: inside any allowance)
                r = self.L.verify(bend_rows=f, clock_skew_ms=0)
                self.assertEqual(self.stage(r), "effect-binding")
                if name.startswith(("effect-", "decision-")):
                    self.assertIn(name, r["why"])
                if name == "hash grammar":                     # §5.1: refused BY NAME, not as a later mismatch
                    self.assertIn("grammar", r["why"])
        self.assertEqual(self.stage(self.L.verify(sign_body=Ed25519PrivateKey.generate())), "effect-binding")
        self.assertEqual(self.stage(self.L.verify(bend_body=lambda b: {**b, "extra": 1})), "effect-binding")

    def test_boundary_allowance(self):
        # Mutations of the rule this test turns red (measured 2026-10-05, each one alone): <= read as < on either edge;
        # the 0 guard dropped on either edge; the opening edge measured from the newest record; the closing deferral
        # without its continue; a deferral for any count shortfall instead of for no row; the conditional note dropped;
        # a row under a refusal deferred. Nine.
        # closing edge: ref-0's allow (t0) has no row; the newest record is t0 + 3, so the distance is 3 ms
        drop = lambda rows: rows[1:]                            # noqa: E731
        r = self.L.verify(bend_rows=drop)                       # default allowance: deferred, VALID, guarantee conditional
        self.assertEqual(r["result"], "VALID")
        self.assertEqual(r["boundary_deferred"], [{"ref": "ref-0", "unmatched": "allow", "edge": "closing", "distance_ms": 3}])
        self.assertIn("conditional", r["why"])
        self.assertEqual(self.L.verify(bend_rows=drop, clock_skew_ms=3)["result"], "VALID")      # within: ≤ the allowance
        r = self.L.verify(bend_rows=drop, clock_skew_ms=2)                                       # 3 ms > 2: the finding
        self.assertEqual(self.stage(r), "effect-binding")
        self.assertIn("decision-without-effect under ref ref-0", r["why"])
        # opening edge: a row no record names, 5 ms after the oldest record (t0)
        extra = lambda rows: rows + [{**rows[0], "ref": "nobody", "timestampMs": self.L.t0 + 5}]  # noqa: E731
        r = self.L.verify(bend_rows=extra, clock_skew_ms=5)
        self.assertEqual(r["result"], "VALID")
        self.assertEqual(r["boundary_deferred"], [{"ref": "nobody", "unmatched": "row", "edge": "opening", "distance_ms": 5}])
        r = self.L.verify(bend_rows=extra, clock_skew_ms=4)
        self.assertIn("effect-without-decision under ref nobody", r["why"])
        # a row under a REFUSAL is never deferred: it has a record (effect-against-refusal), whatever the allowance
        r = self.L.verify(bend_rows=lambda rows: rows + [{**rows[0], "ref": "ref-1"}])
        self.assertIn("effect-against-refusal", r["why"])
        # a count shortfall under a ref that HAS a row stays a finding: record 2 re-signed under ref-0 (two allows, one
        # row, bound to the second), the last allow 1 ms from the newest record; nothing is deferred
        def dup(i, payload, presented):
            if i == 2:
                payload = {k: ("ref-0" if n == "ref" else payload[k]) for k, n in V.RECORD_LABELS.items()}
                presented = {**presented, "ref": "ref-0"}
            return payload, presented, {}
        r = self.L.verify(bend_record=dup, bend_rows=lambda rows: [{**rows[0], "effectHash": H("eff2")}])
        self.assertIn("decision-without-effect under ref ref-0", r["why"])
        self.assertEqual(r["boundary_deferred"], [])
        self.assertEqual(self.L.verify()["boundary_deferred"], [])                               # a whole ledger: none
        # 0 applies no allowance, also for an item exactly on the edge (distance 0)
        r = self.L.verify(bend_rows=lambda rows: rows + [{**rows[0], "ref": "nobody"}], clock_skew_ms=0)
        self.assertIn("effect-without-decision under ref nobody", r["why"])
        self.L.kinds = ["deny", "allow"]                                      # the newest record is an allow with no row
        r = self.L.verify(bend_rows=lambda rows: [], clock_skew_ms=0)
        self.assertIn("decision-without-effect under ref ref-1", r["why"])
        self.assertEqual(self.L.verify(bend_rows=lambda rows: [])["boundary_deferred"][0]["distance_ms"], 0)
        for bad in (-1, True, 1.5, "300000"):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                self.L.verify(clock_skew_ms=bad)

    def test_presented_row_is_one_the_extract_signs(self):
        self.assertEqual(self.L.verify(presented_row=dict)["result"], "VALID")            # the signed row, shown again
        for name, f in {"another effectHash": lambda r: {**r, "effectHash": H("zzz")},      # signed body untouched
                        "another member": lambda r: {**r, "x": 1},
                        "a member missing": lambda r: {k: v for k, v in r.items() if k != "actor"},
                        "not an object": lambda r: [r], "null": lambda r: None}.items():
            with self.subTest(name):
                r = self.L.verify(presented_row=f)
                self.assertEqual(self.stage(r), "effect-binding")
                self.assertIn("presented beside the extract", r["why"])

    def test_checkpoints(self):
        other = Ed25519PrivateKey.generate()
        self.assertEqual(self.stage(self.L.verify(bend_cp=lambda cp: (cp, {"key": other}))), "checkpoint-signature")
        self.assertEqual(self.stage(self.L.verify(bend_cp=lambda cp: ({**cp, "receiptCount": 3}, {}))), "checkpoint-coverage")
        self.assertEqual(self.stage(self.L.verify(bend_cp=lambda cp: ({**cp, "chainHeadHash": H("h")}, {}))), "checkpoint-coverage")
        self.assertEqual(self.stage(self.L.verify(bend_cp=lambda cp: ({**cp, "prevCheckpointHash": H("p")}, {}))), "checkpoint-coverage")
        self.assertEqual(self.stage(self.L.verify(bend_cp=lambda cp: ({**cp, "totals": {"allow": "1", "deny": "1", "defer": "1"}}, {}))),
                         "checkpoint-totals")
        self.assertEqual(self.L.verify(bend_cp=lambda cp: ({**cp, "totals": None}, {}))["result"], "VALID")   # signed redaction
        self.assertEqual(self.stage(self.L.verify(bend_cp=lambda cp: ({**cp, "epoch": -1}, {}))), "checkpoint-signature")
        no_prev = lambda m: {k: v for k, v in m.items() if k != -70107}  # noqa: E731
        r = self.L.verify(bend_cp=lambda cp: (cp, {"labels": no_prev}), presented_cp=lambda cp: {k: v for k, v in cp.items() if k != "prevCheckpointHash"})
        self.assertEqual(self.stage(r), "checkpoint-signature")
        r = self.L.verify(presented_cp=lambda cp: {**cp, "receiptCount": 99})
        self.assertEqual(self.stage(r), "checkpoint-signature")
        self.assertIn("presented", r["why"])

    def test_hostile_input_is_a_verdict(self):
        for dec in ("{", '{"coseHex": "zz"}\n', '{"coseHex": "00"}\n', "[1]\n", '{"a": 1, "a": 2}\n', '{"x": NaN}\n'):
            with self.subTest(dec=dec):
                r = V.verify_ledger(dec, "", "", _pem(self.L.rk), _pem(self.L.xk), _pem(self.L.ck))
                self.assertEqual(r["result"], "INVALID")


def _b64u(b):
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


class VeraxLedger:
    """Records with inputsHash, an approval (real WebAuthn assertion, fresh Ed25519 passkey), a halt/resume window, the
    index; every part can be bent. Stage order checked: inputs-binding, effect-binding, index, approval-signature, control."""
    def __init__(self):
        self.rk, self.xk, self.ck, self.pk = (Ed25519PrivateKey.generate() for _ in range(4))
        self.t0 = 1_790_000_000_000
        # (decision, effectClass, inputs) — 0 defer held, 1 approved allow, 2 halt, 3 deny while halted, 4 resume, 5 allow
        self.plan = [("defer", "memory.put", {"p": 0}), ("allow", "memory.put", None), ("allow", "verax.control", {"control": {"action": "halt"}}),
                     ("deny", None, {"p": 3}), ("allow", "verax.control", {"control": {"action": "resume"}}), ("allow", "memory.get", {"p": 5})]

    def render(self, bend_inputs=None, bend_index=None, bend_assertion=None, bend_plan=None, drop_rows=()):
        plan = [list(x) for x in self.plan]
        if bend_plan:
            plan = bend_plan(plan)
        recs, prev, inputs = [], None, {}
        held_hash = None
        for i, (d, cls, inp) in enumerate(plan):
            ref = f"ref-{i}"
            if inp is None:                                   # the approval: a WebAuthn assertion on the held defer
                ad = hashlib.sha256(b"localhost").digest() + bytes([0x05]) + (1).to_bytes(4, "big")
                cdj = json.dumps({"type": "webauthn.get", "challenge": "c", "origin": "http://localhost"}).encode()
                sig = {"credentialId": "cred-1", "sub": "operator-1", "rpId": "localhost", "deferRecordHash": held_hash,
                       "authenticatorData": _b64u(ad), "clientDataJSON": _b64u(cdj), "signature": _b64u(self.pk.sign(ad + hashlib.sha256(cdj).digest()))}
                if bend_assertion:
                    sig = bend_assertion(sig, ad, cdj, self.pk)
                inp = {"approver": {"id": "operator-1", "resolves": "ref-0", "signature": sig}}
            signed_inputs = inp                               # what the record's inputsHash commits to
            inputs[ref] = bend_inputs(i, inp) if bend_inputs else inp      # what the inputs row presents
            c = _claims(i, d, prev, self.t0 + i)
            c.update(ref=ref, effectClass=cls if d == "allow" else None, inputsHash=hashlib.sha256(jcs(signed_inputs)).hexdigest())
            octets = _cose(self.rk, V.CT_RECORD, {k: c[n] for k, n in V.RECORD_LABELS.items()})
            recs.append((octets, c)); prev = hashlib.sha256(octets).hexdigest()
            if d == "defer" and held_hash is None:
                held_hash = prev
        dec = "".join(json.dumps({"coseHex": o.hex(), "claims": c}) + "\n" for o, c in recs)
        rows = [{"ref": c["ref"], "effectHash": c["effectHash"], "effectClass": c["effectClass"], "timestampMs": c["timestampMs"]}
                for _, c in recs if c["decision"] == "allow" and c["ref"] not in drop_rows]
        eff = ""
        for r in rows:
            body = {"deciderId": "d", "channelId": "c", "windowStartMs": self.t0, "windowEndMs": self.t0 + 100, "effects": [r]}
            eff += json.dumps({"receipt": {"body": body, "signature": base64.b64encode(self.xk.sign(jcs(body))).decode()}}) + "\n"
        hashes = [hashlib.sha256(o).hexdigest() for o, _ in recs]
        kinds = [c["decision"] for _, c in recs]
        cp = {"epoch": 0, "startMs": self.t0, "endMs": self.t0 + 100, "receiptCount": len(recs), "chainHeadHash": hashes[-1],
              "totals": {d: str(kinds.count(d)) for d in V.DECISIONS}, "prevCheckpointHash": None}
        cps = json.dumps({"coseHex": _cose(self.ck, V.CT_CHECKPOINT, {k: cp[n] for k, n in V.CHECKPOINT_LABELS.items()}).hex(), "claims": cp}) + "\n"
        index = [{"kind": c["decision"], "ref": c["ref"]} for _, c in recs] + [{"kind": "effect", "ref": r["ref"]} for r in rows]
        if bend_index:
            index = bend_index(index)
        idx = "".join(json.dumps(x) + "\n" for x in index)
        inp_text = "".join(json.dumps({"ref": k, "inputs": v}) + "\n" for k, v in inputs.items())
        cose_key = R.cbor_encode({1: 1, 3: -8, -1: 6, -2: self.pk.public_key().public_bytes(ser.Encoding.Raw, ser.PublicFormat.Raw)})
        creds = {"credentials": [{"id": "cred-1", "publicKey": _b64u(cose_key), "sub": "operator-1"}]}
        return dec, eff, cps, inp_text, idx, creds

    def verify(self, **kw):
        dec, eff, cps, inp, idx, creds = self.render(**kw)
        return V.verify_ledger(dec, eff, cps, _pem(self.rk), _pem(self.xk), _pem(self.ck),
                               inputs_text=inp, index_text=idx, operator_credentials=creds)


class TestVeraxStages(unittest.TestCase):
    def setUp(self):
        self.L = VeraxLedger()

    def stage(self, r):
        self.assertEqual(r["result"], "INVALID", r)
        return r["stage"]

    def test_valid_and_what_stays_unverified(self):
        r = self.L.verify()
        self.assertEqual(r["result"], "VALID", r)
        self.assertEqual(r["not_verified"], ["approval-challenge-binding"])

    def test_inputs_binding(self):
        self.assertEqual(self.stage(self.L.verify(bend_inputs=lambda i, inp: {**inp, "x": 1} if i == 3 else inp)), "inputs-binding")
        dec, eff, cps, inp, idx, creds = self.L.render()
        missing = "".join(l + "\n" for l in inp.splitlines() if '"ref-3"' not in l)
        r = V.verify_ledger(dec, eff, cps, _pem(self.L.rk), _pem(self.L.xk), _pem(self.L.ck), inputs_text=missing)
        self.assertEqual(self.stage(r), "inputs-binding")
        for bad_row in ('{"ref": 5, "inputs": {}}', '{"ref": "ref-9"}', '[1]'):
            r = V.verify_ledger(dec, eff, cps, _pem(self.L.rk), _pem(self.L.xk), _pem(self.L.ck), inputs_text=inp + bad_row + "\n")
            self.assertEqual(self.stage(r), "inputs-binding")
        dup = inp + inp.splitlines()[0] + "\n"
        r = V.verify_ledger(dec, eff, cps, _pem(self.L.rk), _pem(self.L.xk), _pem(self.L.ck), inputs_text=dup)
        self.assertEqual(self.stage(r), "inputs-binding")

    def test_index(self):
        for bend in (lambda ix: ix + [{"kind": "allow", "ref": "nobody"}], lambda ix: ix + [{"kind": "effect", "ref": "ref-3"}],
                     lambda ix: ix + [{"kind": "deny", "ref": "ref-1"}], lambda ix: ix + [{"kind": "other", "ref": "ref-1"}]):
            self.assertEqual(self.stage(self.L.verify(bend_index=bend)), "index")

    def test_approval_signature(self):
        other = Ed25519PrivateKey.generate()
        cases = {
            "signed by another key": lambda s, ad, cdj, pk: {**s, "signature": _b64u(other.sign(ad + hashlib.sha256(cdj).digest()))},
            "wrong rpId": lambda s, ad, cdj, pk: {**s, "rpId": "evil.example"},
            "not webauthn.get": lambda s, ad, cdj, pk: {**s, "clientDataJSON": _b64u(json.dumps({"type": "webauthn.create"}).encode()),
                                                        "signature": _b64u(pk.sign(ad + hashlib.sha256(json.dumps({"type": "webauthn.create"}).encode()).digest()))},
            "user not present": lambda s, ad, cdj, pk: {**s, "authenticatorData": _b64u(ad[:32] + bytes([0x04]) + ad[33:]),
                                                        "signature": _b64u(pk.sign(ad[:32] + bytes([0x04]) + ad[33:] + hashlib.sha256(cdj).digest()))},
            "deferRecordHash elsewhere": lambda s, ad, cdj, pk: {**s, "deferRecordHash": "0" * 64},
            "unknown credential": lambda s, ad, cdj, pk: {**s, "credentialId": "cred-9"},
            "sub mismatch": lambda s, ad, cdj, pk: {**s, "sub": "operator-2"},
        }
        for name, f in cases.items():
            with self.subTest(name):
                self.assertEqual(self.stage(self.L.verify(bend_assertion=f)), "approval-signature")

    def test_control(self):
        # the deny while halted becomes an allow WITH its effect row: only the control stage can catch it
        def allow_in_window(plan):
            plan[3] = ["allow", "memory.get", {"p": 3}]; return plan
        self.assertEqual(self.stage(self.L.verify(bend_plan=allow_in_window)), "control")
        def no_resume(plan):        # without the resume, the last allow is inside the window too
            plan[4] = ["deny", None, {"p": 4}]; return plan
        self.assertEqual(self.stage(self.L.verify(bend_plan=no_resume)), "control")


if __name__ == "__main__":
    unittest.main()
