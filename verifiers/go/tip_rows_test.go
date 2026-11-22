// SPDX-License-Identifier: AGPL-3.0-or-later
package cryptovalid

import (
	"strings"
	"testing"
)

// SPEC §22 rule 2: a Tip built by a caller without LoadTip gets the rows of the table on its fields, with the same
// words (CheckTip). NEMESIS 2026-11-22: dropping the row of a negative entries count there lived with the tests.
func TestCheckTipRowsOnATipBuiltByTheCaller(t *testing.T) {
	base := Tip{Kind: TipKind, Entries: 1, LedgerID: strings.Repeat("a", 64), TipSHA256: strings.Repeat("b", 64),
		TS: "2026-11-22T00:00:00Z", SignatureHex: strings.Repeat("c", 128)}
	trusted := strings.Repeat("d", 64)
	cases := []struct {
		name string
		mod  func(*Tip)
		want string
	}{
		{"kind", func(p *Tip) { p.Kind = "cryptovalid_tip/2" }, "tip_invalid: not a cryptovalid_tip/1 document"},
		{"entries", func(p *Tip) { p.Entries = -1 }, "tip_invalid: tip entries must be a non-negative integer"},
		{"ledger_id", func(p *Tip) { p.LedgerID = strings.Repeat("A", 64) }, "tip_invalid: ledger_id / tip_sha256 must be 64 lowercase hex characters"},
		{"tip_sha256", func(p *Tip) { p.TipSHA256 = "b" }, "tip_invalid: ledger_id / tip_sha256 must be 64 lowercase hex characters"},
		{"signature_hex", func(p *Tip) { p.SignatureHex = "c" }, "tip_invalid: signature_hex must be 128 lowercase hex characters"},
		{"pq present, signature empty", func(p *Tip) { p.PQFieldsPresent = true }, "tip_invalid: signature_pq_hex must be 6618 lowercase hex characters (ML-DSA-65)"},
		{"pq key malformed", func(p *Tip) { p.SignaturePQHex = strings.Repeat("e", 6618); p.LogPQPubkeyB64 = "x" }, "tip_invalid: log_pq_pubkey_b64 must be strict base64 of a 1952-byte ML-DSA-65 public key"},
		{"ts", func(p *Tip) { p.TS = "2026-11-22" }, "tip_invalid: ts outside the profile YYYY-MM-DDThh:mm:ss[.fraction](Z|±hh:mm)"},
	}
	for _, c := range cases {
		tp := base
		c.mod(&tp)
		if _, why, _ := CheckTip(1, base.LedgerID, base.TipSHA256, &tp, trusted, "", ""); why != c.want {
			t.Errorf("%s: got %q, want %q", c.name, why, c.want)
		}
	}
	// control: the well-formed tip passes every row and reaches the signature (an unsigned one fails there)
	tp := base
	if _, why, _ := CheckTip(1, base.LedgerID, base.TipSHA256, &tp, trusted, "", ""); !strings.HasPrefix(why, "tip_invalid: tip signature invalid") {
		t.Errorf("control: got %q", why)
	}
}
