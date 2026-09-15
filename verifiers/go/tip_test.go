package cryptovalid

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func newKey(t *testing.T, dir string) (ed25519.PrivateKey, string, string) {
	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		t.Fatal(err)
	}
	p := dir + "/log.key"
	if err := os.WriteFile(p, []byte(hex.EncodeToString(seed)), 0o600); err != nil {
		t.Fatal(err)
	}
	k := ed25519.NewKeyFromSeed(seed)
	return k, p, hex.EncodeToString(k.Public().(ed25519.PublicKey))
}

func TestTipMovesTheTailLimit(t *testing.T) {
	dir := t.TempDir()
	p := dir + "/l.jsonl"
	key, _, pk := newKey(t, dir)
	ts := time.Date(2026, 9, 15, 7, 0, 0, 0, time.UTC)
	for i := 0; i < 5; i++ {
		if _, err := AppendSigned(p, ts, map[string]any{"i": i}, "sha256", key); err != nil {
			t.Fatal(err)
		}
	}
	v := VerifyLedgerWithTip(p, "", pk, true, "", "")
	if v.Verdict != "PASS" || v.Tip == nil || !v.Tip.OK || !v.Tip.Trusted {
		t.Fatalf("intact with tip: %+v", v)
	}
	full, _ := os.ReadFile(p)
	lines := strings.SplitAfter(string(full), "\n")
	// positive control: the bare verifier cannot see the deleted last row
	os.WriteFile(p, []byte(strings.Join(lines[:4], "")), 0o600)
	if bare := VerifyLedgerWithTip(p, "/nonexistent-so-no-tip", pk, false, "", ""); bare.Verdict != "FAIL" || !strings.Contains(strings.Join(bare.Failures, " "), "tip_unreadable") {
		// an explicit but missing tip path is an error, never a silent "no tip"
		t.Fatalf("explicit missing tip must be a failure: %+v", bare)
	}
	f, _ := os.Open(p)
	if bare := VerifyLedger(f); bare.Verdict != "PASS" {
		t.Fatalf("positive control failed: bare chain must PASS on a truncated file: %+v", bare)
	}
	f.Close()
	if v := VerifyLedgerWithTip(p, "", pk, true, "", ""); v.Verdict != "FAIL" || !strings.Contains(v.Tip.Why, "tail_truncated") {
		t.Fatalf("truncation not named: %+v", v)
	}
	// unsealed append (no key): more entries than the tip
	os.WriteFile(p, full, 0o600)
	if _, err := Append(p, ts, map[string]any{"i": 5}, "sha256"); err != nil {
		t.Fatal(err)
	}
	if v := VerifyLedgerWithTip(p, "", pk, true, "", ""); v.Verdict != "FAIL" || !strings.Contains(v.Tip.Why, "unsealed_tail") {
		t.Fatalf("unsealed append not named: %+v", v)
	}
	// attacker re-signs with another key: refused against the trusted key
	os.WriteFile(p, []byte(strings.Join(lines[:4], "")), 0o600)
	other, _, _ := newKey(t, t.TempDir())
	if _, err := SignTip(p, other, ts); err != nil {
		t.Fatal(err)
	}
	if v := VerifyLedgerWithTip(p, "", pk, true, "", ""); v.Verdict != "FAIL" || !strings.Contains(v.Tip.Why, "tip_invalid") {
		t.Fatalf("foreign key accepted: %+v", v)
	}
	// no trusted key: the tip is NOT checked (the attacker's own key inside proves nothing) → required = FAIL
	if v := VerifyLedgerWithTip(p, "", "", true, "", ""); v.Verdict != "FAIL" || v.Tip.Checked || !strings.Contains(v.Tip.Why, "tip_untrusted") {
		t.Fatalf("no trusted key + required must FAIL, never fail-open: %+v", v)
	}
	if v := VerifyLedgerWithTip(p, "", "", false, "", ""); v.Verdict != "PASS" || v.Tip.Checked {
		t.Fatalf("no trusted key, not required: bare chain verdict, tip unchecked: %+v", v)
	}
	// instants, not strings: 'Z', '+00:00', '+02:00' of the same moment all pass; one second later fails
	os.WriteFile(p, full, 0o600)
	if _, err := SignTip(p, key, time.Date(2026, 9, 15, 10, 0, 0, 0, time.UTC)); err != nil {
		t.Fatal(err)
	}
	for _, same := range []string{"2026-09-15T10:00:00Z", "2026-09-15T10:00:00+00:00", "2026-09-15T12:00:00+02:00", "2026-09-15T10:00:00"} { // notBefore may be naive (UTC); the TIP's ts must carry a zone
		if v := VerifyLedgerWithTip(p, "", pk, true, same, ""); v.Verdict != "PASS" {
			t.Fatalf("same instant %q refused: %+v", same, v)
		}
	}
	if v := VerifyLedgerWithTip(p, "", pk, true, "2026-09-15T10:00:01Z", ""); v.Verdict != "FAIL" {
		t.Fatalf("later not-before accepted: %+v", v)
	}
	os.WriteFile(p, []byte(strings.Join(lines[:4], "")), 0o600)
	if _, err := SignTip(p, other, ts); err != nil {
		t.Fatal(err)
	}
	// ROLLBACK: truncate and restore an OLDER genuine tip → passes (declared), refused with notBefore
	os.WriteFile(p, full, 0o600)
	if _, err := SignTip(p, key, ts); err != nil {
		t.Fatal(err)
	}
	oldTip, _ := os.ReadFile(TipPath(p))
	if _, err := AppendSigned(p, ts.Add(time.Hour), map[string]any{"i": 9}, "sha256", key); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(p, full, 0o600)
	os.WriteFile(TipPath(p), oldTip, 0o600)
	if v := VerifyLedgerWithTip(p, "", pk, true, "", ""); v.Verdict != "PASS" {
		t.Fatalf("rollback must pass without notBefore (declared limit): %+v", v)
	}
	if v := VerifyLedgerWithTip(p, "", pk, true, ts.Add(time.Hour).UTC().Format("2006-01-02T15:04:05+00:00"), ""); v.Verdict != "FAIL" || !strings.Contains(v.Tip.Why, "tip_rolled_back") {
		t.Fatalf("rollback not refused with notBefore: %+v", v)
	}
	os.WriteFile(p, []byte(strings.Join(lines[:4], "")), 0o600)
	if _, err := SignTip(p, other, ts); err != nil {
		t.Fatal(err)
	}
	// another ledger signed by the SAME key: its tip on this file is named; the whole pair only with expectLedgerID
	q := dir + "/other.jsonl"
	for i := 0; i < 5; i++ {
		if _, err := AppendSigned(q, ts, map[string]any{"other": i}, "sha256", key); err != nil {
			t.Fatal(err)
		}
	}
	os.WriteFile(p, full, 0o600)
	qt, _ := os.ReadFile(TipPath(q))
	os.WriteFile(TipPath(p), qt, 0o600)
	if v := VerifyLedgerWithTip(p, "", pk, true, "", ""); v.Verdict != "FAIL" || !strings.Contains(v.Tip.Why, "tip_of_another_ledger") {
		t.Fatalf("other ledger's tip not named: %+v", v)
	}
	if vq := VerifyLedgerWithTip(q, "", pk, true, "", ""); vq.Verdict != "PASS" {
		t.Fatalf("other ledger intact: %+v", vq)
	}
	os.Remove(TipPath(p))
	vp := VerifyLedgerWithTip(p, "", pk, false, "", "")
	if v := VerifyLedgerWithTip(q, "", pk, true, "", vp.FirstSelfHash); v.Verdict != "FAIL" || !strings.Contains(v.Tip.Why, "ledger_id_mismatch") {
		t.Fatalf("whole-pair substitution not caught with expectLedgerID: %+v", v)
	}
	if _, err := SignTip(p, key, ts); err != nil {
		t.Fatal(err)
	}
	// tip removed: fine unless required
	os.Remove(TipPath(p))
	if v := VerifyLedgerWithTip(p, "", pk, false, "", ""); v.Verdict != "PASS" || v.Tip != nil {
		t.Fatalf("no tip, not required: %+v", v)
	}
	if v := VerifyLedgerWithTip(p, "", pk, true, "", ""); v.Verdict != "FAIL" || !strings.Contains(strings.Join(v.Failures, " "), "tip_missing") {
		t.Fatalf("required tip missing not named: %+v", v)
	}
}

func TestTipCrossLanguageWithPython(t *testing.T) {
	// the Python reference is the oracle of the signed bytes: a tip signed by Python must verify in Go and
	// a tip signed by Go must verify in Python (same key, same document)
	py, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 not on PATH")
	}
	if out, err := exec.Command(py, "-c", "import cryptography").CombinedOutput(); err != nil {
		t.Skip("python cryptography absent: " + string(out))
	}
	dir := t.TempDir()
	p := dir + "/l.jsonl"
	key, keyfile, pk := newKey(t, dir)
	ts := time.Date(2026, 9, 15, 7, 0, 0, 0, time.UTC)
	for i := 0; i < 3; i++ {
		if _, err := Append(p, ts, map[string]any{"i": i}, "sha256"); err != nil {
			t.Fatal(err)
		}
	}
	root := "../.."
	if out, err := exec.Command(py, root+"/cryptovalid_tip.py", "sign", p, keyfile).CombinedOutput(); err != nil {
		t.Fatalf("python sign: %v %s", err, out)
	}
	if v := VerifyLedgerWithTip(p, "", pk, true, "", ""); v.Verdict != "PASS" || !v.Tip.Trusted {
		t.Fatalf("Python-signed tip refused by Go: %+v", v)
	}
	if _, err := SignTip(p, key, ts); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(py, root+"/verifier.py", p, "--trusted-pubkey", pk, "--require-tip", "--quiet")
	if out, err := cmd.CombinedOutput(); err != nil || strings.TrimSpace(string(out)) != "PASS" {
		t.Fatalf("Go-signed tip refused by Python: %v %s", err, out)
	}
	// and Python must still see the truncation against the Go-signed tip
	full, _ := os.ReadFile(p)
	lines := strings.SplitAfter(string(full), "\n")
	os.WriteFile(p, []byte(strings.Join(lines[:2], "")), 0o600)
	cmd = exec.Command(py, root+"/verifier.py", p, "--trusted-pubkey", pk, "--quiet")
	if out, _ := cmd.CombinedOutput(); strings.TrimSpace(string(out)) != "FAIL" {
		t.Fatalf("Python did not see the truncation against the Go tip: %s", out)
	}
}
