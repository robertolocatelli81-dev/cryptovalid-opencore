// SPDX-License-Identifier: AGPL-3.0-or-later
package cryptovalid

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

// Signed chain tip (15/09/2026): the tail limit of a snapshot chain moves. Same document, same signed bytes as
// the Python reference (cryptovalid_tip.py): {"entries":N,"kind":"cryptovalid_tip/1","ledger_id":"…","tip_sha256":"…","ts":"…"}
// (ledger_id = self_hash of entry 0: the chain's identity, so a log key shared by two ledgers cannot lend B's tip to A).
// With a tip and the TRUSTED log key, truncation / suffix rewrite / an unsealed append become named failures.
// What it does not prove: a holder of the log key can truncate and re-sign (key custody is the limit).
const TipKind = "cryptovalid_tip/1"

type Tip struct {
	Kind         string `json:"kind"`
	Entries      int    `json:"entries"`
	LedgerID     string `json:"ledger_id"`
	TipSHA256    string `json:"tip_sha256"`
	TS           string `json:"ts"`
	LogPubkeyHex string `json:"log_pubkey_hex"`
	SignatureHex string `json:"signature_hex"`
}

// TipPath is the sidecar next to the ledger.
func TipPath(ledger string) string { return ledger + ".tip.json" }

// TipPayload returns the exact bytes that are signed (canonical JSON, keys sorted — Python is the oracle).
func TipPayload(entries int, ledgerID, tipSHA256, ts string) []byte {
	return []byte(fmt.Sprintf(`{"entries":%d,"kind":"%s","ledger_id":"%s","tip_sha256":"%s","ts":"%s"}`, entries, TipKind, ledgerID, tipSHA256, ts))
}

// the payload is built by Sprintf (no JSON escaping): only hex and a plain ISO-8601 timestamp are admitted,
// anything else would not be the reference bytes (council 15/09, Sonnet)
func isHex64(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

// plainTS = the ONE timestamp profile of the three checkers: RFC 3339 with seconds and a zone (Z or ±hh:mm).
func plainTS(s string) bool {
	if s == "" || len(s) > 40 || strings.ContainsAny(s, "\"\\") {
		return false
	}
	_, err := time.Parse(time.RFC3339Nano, s)
	return err == nil && len(s) >= len("2006-01-02T15:04:05Z") && s[10] == 'T' && s[13] == ':' && s[16] == ':'
}

// LoadTipKey reads the 32-byte Ed25519 seed (hex) used by signer.py / cryptovalid_tip.py.
func LoadTipKey(keyfile string) (ed25519.PrivateKey, error) {
	raw, err := os.ReadFile(keyfile)
	if err != nil {
		return nil, err
	}
	seed, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, errors.New("tip key: expected a 32-byte hex seed")
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

// SignTip signs the CURRENT tail of the ledger (entries = last idx + 1, tip = last self_hash) and writes the
// sidecar atomically. Call it under the same lock as Append (AppendSigned does).
func SignTip(ledger string, key ed25519.PrivateKey, ts time.Time) (*Tip, error) {
	f, err := os.Open(ledger)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	idx, last, err := tail(f)
	if err != nil {
		return nil, err
	}
	first, err := firstSelfHash(f)
	if err != nil {
		return nil, err
	}
	return writeTip(ledger, key, idx, first, last, ts)
}

// firstSelfHash reads ONLY the first line (the chain's identity); Genesis when the file is empty.
func firstSelfHash(f *os.File) (string, error) {
	buf := make([]byte, 64<<10)
	n, err := f.ReadAt(buf, 0)
	if err != nil && err != io.EOF {
		return "", err
	}
	buf = buf[:n]
	if k := bytes.IndexByte(buf, '\n'); k >= 0 {
		buf = buf[:k]
	} else if int64(n) == int64(len(buf)) {
		return "", errors.New("first line exceeds 64 KiB: cannot read the ledger identity")
	}
	if len(bytes.TrimSpace(buf)) == 0 {
		return Genesis, nil
	}
	v, err := Parse(bytes.TrimSpace(buf))
	if err != nil {
		return "", fmt.Errorf("first line unreadable: %w", err)
	}
	obj, ok := v.(*Object)
	if !ok {
		return "", errors.New("first line is not an object")
	}
	h, _ := obj.Vals["self_hash"].(string)
	if !isHex64(h) {
		return "", errors.New("first line has no self_hash")
	}
	return h, nil
}

func writeTip(ledger string, key ed25519.PrivateKey, entries int, first, last string, ts time.Time) (*Tip, error) {
	t := &Tip{Kind: TipKind, Entries: entries, LedgerID: first, TipSHA256: last, TS: ts.UTC().Format("2006-01-02T15:04:05+00:00"),
		LogPubkeyHex: hex.EncodeToString(key.Public().(ed25519.PublicKey))}
	t.SignatureHex = hex.EncodeToString(ed25519.Sign(key, TipPayload(t.Entries, t.LedgerID, t.TipSHA256, t.TS)))
	doc, _ := json.Marshal(t)
	tmp := TipPath(ledger) + ".tmp"
	if err := os.WriteFile(tmp, doc, 0o600); err != nil {
		return nil, err
	}
	if err := os.Rename(tmp, TipPath(ledger)); err != nil {
		return nil, err
	}
	return t, nil
}

// AppendSigned = Append + SignTip under ONE lock: the tip always describes the file as left by this append.
func AppendSigned(path string, ts time.Time, data any, algo string, key ed25519.PrivateKey) (selfHash string, err error) {
	return appendLocked(path, ts, data, algo, func(f *os.File, entries int, last string) error {
		first, e := firstSelfHash(f)
		if e != nil {
			return e
		}
		_, e = writeTip(path, key, entries, first, last, ts)
		return e
	})
}

// CheckTip compares a verified snapshot (entries, last self_hash) with a tip. trustedPubkeyHex="" means the
// key inside the tip is used and the result says so (NOT trusted).
// notBefore ("" = no check): refuse a tip dated before that instant — ROLLBACK (declared): an older genuine tip
// restored after a truncation passes otherwise (the tip proves "a signed state", not "the latest").
// first = this file's first self_hash (Genesis for an empty file); expectLedgerID ("" = no check) = the chain the
// relying party expects, out of band — the only defence against a whole pair file+tip of another ledger.
func CheckTip(entries int, first, last string, t *Tip, trustedPubkeyHex, notBefore, expectLedgerID string) (ok bool, why string, trusted bool) {
	if t == nil || t.Kind != TipKind || t.SignatureHex == "" || !isHex64(t.TipSHA256) || !isHex64(t.LedgerID) || !plainTS(t.TS) || t.Entries < 0 {
		return false, "tip_invalid: not a cryptovalid_tip/1 document", false
	}

	// the key inside the tip proves nothing: without the trusted log key there is NO verification (never a
	// "PASS but untrusted" that an automation reads as exit 0 — council 15/09, Gemini)
	if trustedPubkeyHex == "" {
		return false, "tip_untrusted: no trusted log key given (-trusted-pubkey); the key inside the tip cannot be trusted", false
	}
	if t.LogPubkeyHex != "" && t.LogPubkeyHex != trustedPubkeyHex {
		return false, "tip_invalid: tip log key differs from the trusted log key", false
	}
	pk, err1 := hex.DecodeString(trustedPubkeyHex)
	sig, err2 := hex.DecodeString(t.SignatureHex)
	if err1 != nil || err2 != nil || len(pk) != ed25519.PublicKeySize ||
		!ed25519.Verify(ed25519.PublicKey(pk), TipPayload(t.Entries, t.LedgerID, t.TipSHA256, t.TS), sig) {
		return false, "tip_invalid: tip signature invalid", false
	}
	trusted = trustedPubkeyHex != ""
	if expectLedgerID != "" && t.LedgerID != expectLedgerID {
		return false, "ledger_id_mismatch: the tip belongs to a different ledger than the one you expect", trusted
	}
	if entries > 0 && t.LedgerID != first {
		return false, "tip_of_another_ledger: the tip's ledger_id is not this file's first self_hash", trusted
	}
	if notBefore != "" {
		// instants, not strings (council 15/09, Opus: "…Z" vs "…+00:00" compared as bytes was a false rollback);
		// a malformed notBefore is the VERIFIER's error, never the tip's
		nbT, e2 := parseInstant(notBefore)
		if e2 != nil {
			return false, "bad_not_before: -tip-not-before is not ISO-8601", trusted
		}
		tipT, _ := time.Parse(time.RFC3339Nano, t.TS)
		if tipT.Before(nbT) {
			return false, fmt.Sprintf("tip_rolled_back: the tip is dated %s, before the required %s", t.TS, notBefore), trusted
		}
	}
	switch {
	case entries < t.Entries:
		return false, fmt.Sprintf("tail_truncated: file has %d entries, the signed tip commits to %d", entries, t.Entries), trusted
	case entries > t.Entries:
		return false, fmt.Sprintf("unsealed_tail: file has %d entries, the signed tip commits to %d (appended after the last signed head)", entries, t.Entries), trusted
	case last != t.TipSHA256:
		return false, "tail_rewritten: same entry count but the last self_hash differs from the signed tip", trusted
	}
	return true, "tip matches the verified chain", trusted
}

// LoadTip reads a sidecar; any malformation is an error (never a silent "no tip").
func LoadTip(path string) (*Tip, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("tip_unreadable: %w", err)
	}
	var t Tip
	if err := json.Unmarshal(raw, &t); err != nil {
		return nil, fmt.Errorf("tip_unreadable: %w", err)
	}
	return &t, nil
}

// parseInstant accepts RFC 3339 with 'Z' or an offset, or a naive "YYYY-MM-DDTHH:MM:SS" taken as UTC.
func parseInstant(s string) (time.Time, error) {
	s = strings.TrimSpace(s)
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t, nil
	}
	return time.Parse("2006-01-02T15:04:05", s)
}
