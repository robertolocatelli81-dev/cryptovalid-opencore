// SPDX-License-Identifier: AGPL-3.0-or-later
package cryptovalid

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
)

const Genesis = "0000000000000000000000000000000000000000000000000000000000000000"

// Verdict mirrors verifier.py's receipt for the fields any auditor reads.
type Verdict struct {
	Verdict             string    `json:"verdict"` // PASS | FAIL
	Algo                string    `json:"algo,omitempty"`
	Entries             int       `json:"entries_count"`
	HashRecomputePassed bool      `json:"hash_recompute_passed"`
	LinkPassed          bool      `json:"link_passed"`
	Failures            []string  `json:"failures"`
	FirstSelfHash       string    `json:"first_self_hash,omitempty"` // the chain's identity (ledger_id of its tip)
	LastSelfHash        string    `json:"last_self_hash,omitempty"`
	Tip                 *TipCheck `json:"tip,omitempty"` // nil = no signed tip checked (the tail limit applies in full)
	Scope               string    `json:"scope"`
}

// TipCheck is the outcome of comparing the snapshot with a signed chain tip (tip.go).
type TipCheck struct {
	OK      bool   `json:"ok"`
	Checked bool   `json:"checked"` // false = a tip was there but could not be checked (no trusted key)
	Why     string `json:"why"`
	Trusted bool   `json:"trusted"`
	Path    string `json:"tip_path,omitempty"`
	// post-quantum layer: true only when the ML-DSA-65 signature verified against the trusted PQ key;
	// false when absent/invalid/unchecked (never a silent green), with the reason in PQWhy
	PQProtected *bool  `json:"pq_protected"` // nil = present but unchecked (no trusted PQ key): the Python tri-state
	PQWhy       string `json:"pq_why,omitempty"`
}

const scope = "single-snapshot check of the cryptovalid profile (SPEC_EVIDENCE_FORMAT §3-4): self_hash recompute, " +
	"prev_hash linkage, sequential idx, genesis. Does NOT see a truncated tail (chain still valid) unless a " +
	"signed chain tip is checked (tip.go / cvverify -tip): then only a holder of the log key can truncate " +
	"and re-sign. Entry signatures are not verified here."

// MaxLineBytes bounds one JSONL line (a longer line is a failure, not a crash, and never silently truncated).
const MaxLineBytes = 64 << 20

// VerifyLedger reads JSONL in STREAMING (one entry in memory at a time — council 14/09: a multi-GB ledger must
// not be loaded whole) and recomputes the chain. Fail-closed: any unparsable line is a failure; a scanner
// error (line too long, I/O) is a failure, not a silent stop.
func VerifyLedger(r io.Reader) Verdict {
	v := Verdict{Failures: []string{}, Scope: scope}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 1<<20), MaxLineBytes)
	hashOK, linkOK := true, true
	prev := Genesis
	line, i := 0, 0
	for sc.Scan() {
		line++
		raw := sc.Bytes()
		if len(strings.TrimSpace(string(raw))) == 0 {
			continue
		}
		val, err := Parse(raw)
		if err != nil {
			v.Failures = append(v.Failures, fmt.Sprintf("line %d: %v", line, err))
			hashOK = false
			i++
			continue
		}
		e, ok := val.(*Object)
		if !ok {
			v.Failures = append(v.Failures, fmt.Sprintf("line %d: entry is not an object", line))
			hashOK = false
			i++
			continue
		}
		if v.Algo == "" { // profile auto-detection on the first PARSABLE entry (a garbage first line must not desynchronise it)
			if s0, ok := e.Vals["self_hash"].(string); !ok || len(s0) != 64 {
				v.Failures = append(v.Failures, fmt.Sprintf("entry %d: self_hash missing or not a 64-hex string", i))
				v.Entries = i + 1
				v.Verdict = "FAIL"
				return v
			}
			if p0, err := Payload(e); err == nil {
				for _, a := range Algos {
					h, _ := Hash(a, p0)
					if s, _ := e.Vals["self_hash"].(string); s == h {
						v.Algo = a
					}
				}
			}
			if v.Algo == "" {
				v.Failures = append(v.Failures, fmt.Sprintf("entry %d: self_hash matches no supported profile", i))
				v.Entries = i + 1
				v.Verdict = "FAIL"
				return v
			}
		}
		idx, _ := e.Vals["idx"].(json.Number)
		if idx.String() != fmt.Sprint(i) {
			linkOK = false
			v.Failures = append(v.Failures, fmt.Sprintf("entry %d: idx %q not sequential", i, idx.String()))
		}
		self, isStr := e.Vals["self_hash"].(string)
		if !isStr || len(self) != 64 { // reported HERE, not as a link failure on the next entry (Gemini, round 1)
			hashOK = false
			v.Failures = append(v.Failures, fmt.Sprintf("entry %d: self_hash missing or not a 64-hex string", i))
		}
		payload, err := Payload(e)
		if err != nil {
			hashOK = false
			v.Failures = append(v.Failures, fmt.Sprintf("entry %d: %v", i, err))
		} else if h, _ := Hash(v.Algo, payload); isStr && self != h {
			hashOK = false
			v.Failures = append(v.Failures, fmt.Sprintf("entry %d: self_hash mismatch", i))
		}
		if p, _ := e.Vals["prev_hash"].(string); p != prev {
			linkOK = false
			v.Failures = append(v.Failures, fmt.Sprintf("entry %d: prev_hash does not link", i))
		}
		if i == 0 {
			v.FirstSelfHash = self
		}
		prev = self
		i++
	}
	if err := sc.Err(); err != nil {
		v.Failures = append(v.Failures, "read: "+err.Error())
		hashOK = false
	}
	v.Entries = i
	v.LastSelfHash = prev
	if i == 0 {
		// zero entries = nothing verified = FAIL, same rule and message as Python/JS (2026-09-11); the Go
		// reference said "EMPTY" until 15/09/2026 — an undeclared divergence caught by adding Go to the oracle
		v.Failures = append(v.Failures, "line 0: empty_ledger: zero entries, nothing to verify")
		hashOK = false
	}
	v.HashRecomputePassed, v.LinkPassed = hashOK, linkOK
	if hashOK && linkOK && len(v.Failures) == 0 {
		v.Verdict = "PASS"
	} else {
		v.Verdict = "FAIL"
	}
	return v
}

// VerifyLedgerWithTip verifies the file and, when a tip is given (path "" = `<ledger>.tip.json` if present),
// compares the snapshot with the signed chain tip: truncation, suffix rewrite and unsealed appends become named
// failures. requireTip: a missing tip is a failure.
func VerifyLedgerWithTip(ledgerPath, tipPath, trustedPubkeyHex string, requireTip bool, tipNotBefore, expectLedgerID string) Verdict {
	return VerifyLedgerWithTipPQ(ledgerPath, tipPath, trustedPubkeyHex, "", requireTip, tipNotBefore, expectLedgerID)
}

// VerifyLedgerWithTipPQ is VerifyLedgerWithTip plus the trusted ML-DSA-65 key: when given, a tip without a valid
// post-quantum signature is a FAIL (pq_missing / invalid); when empty, the PQ layer is reported as not protected.
func VerifyLedgerWithTipPQ(ledgerPath, tipPath, trustedPubkeyHex, trustedPQPubkeyB64 string, requireTip bool, tipNotBefore, expectLedgerID string) Verdict {
	f, err := os.Open(ledgerPath)
	if err != nil {
		return Verdict{Verdict: "FAIL", Failures: []string{"open: " + err.Error()}, Scope: scope}
	}
	defer f.Close()
	v := VerifyLedger(f)
	if tipPath == "" {
		if _, err := os.Stat(TipPath(ledgerPath)); err == nil {
			tipPath = TipPath(ledgerPath)
		}
	}
	if trustedPQPubkeyB64 != "" {
		// a trusted post-quantum key is a REQUIREMENT: it implies a required tip and needs the trusted log key
		// (council 15/09, Fable: PQ key alone returned before CheckTipPQ → PASS, a fail-open)
		requireTip = true
		if trustedPubkeyHex == "" {
			v.Verdict = "FAIL"
			v.Failures = append(v.Failures, "pq_key_without_log_key: -trusted-pq-pubkey needs -trusted-pubkey (the post-quantum layer sits on top of the Ed25519 tip, never instead of it)")
			return v
		}
	}
	if tipPath == "" {
		if requireTip {
			v.Verdict = "FAIL"
			v.Failures = append(v.Failures, "tip_missing: a signed chain tip is required and none was found")
		}
		return v
	}
	tc := &TipCheck{Path: tipPath}
	if trustedPubkeyHex == "" {
		// a tip is there but no trusted key: NOT checked; the verdict is the bare chain's, FAIL if required
		tc.Why = "tip_untrusted: a signed tip is present but no trusted log key was given (-trusted-pubkey); the tail limit applies in full"
		v.Tip = tc
		if requireTip {
			v.Verdict = "FAIL"
			v.Failures = append(v.Failures, fmt.Sprintf("entry %d: %s", v.Entries, tc.Why))
		}
		return v
	}
	t, err := LoadTip(tipPath)
	if err != nil {
		tc.Why = err.Error()
		f := false // unreadable tip: not protected (the Python reference says false here too)
		tc.PQProtected = &f
	} else {
		first := v.FirstSelfHash
		if v.Entries == 0 {
			first = Genesis
		}
		tc.OK, tc.Why, tc.Trusted = CheckTip(v.Entries, first, v.LastSelfHash, t, trustedPubkeyHex, tipNotBefore, expectLedgerID)
		tc.Checked = true
		if tc.OK {
			tc.PQProtected, tc.PQWhy = CheckTipPQ(t, trustedPQPubkeyB64)
		} else {
			f := false // hybrid = BOTH hold: a broken classical tip is never "post-quantum protected"
			tc.PQProtected, tc.PQWhy = &f, "classical tip check failed first"
		}
		if trustedPQPubkeyB64 != "" && (tc.PQProtected == nil || !*tc.PQProtected) {
			tc.OK = false
			tc.Why = tc.Why + "; " + tc.PQWhy
		}
	}
	v.Tip = tc
	if !tc.OK {
		v.Verdict = "FAIL"
		v.Failures = append(v.Failures, fmt.Sprintf("entry %d: %s", v.Entries, tc.Why))
	}
	return v
}
