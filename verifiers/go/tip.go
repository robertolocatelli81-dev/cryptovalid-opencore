// SPDX-License-Identifier: AGPL-3.0-or-later
package cryptovalid

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
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
	// hybrid tip (0.12.0): the SAME payload bytes signed with ML-DSA-65 (FIPS 204) — checked with the trusted
	// post-quantum key (crypto/mldsa, Go standard library); absent or unchecked = not post-quantum protected
	SignaturePQHex string `json:"signature_pq_hex,omitempty"`
	LogPQPubkeyB64 string `json:"log_pq_pubkey_b64,omitempty"`
	// PQFieldsPresent: one of the two optional fields exists in the document (even as null / "" / a wrong type):
	// then both must be well-formed, as in Python/JS. json.Unmarshal into string maps null to "" (council 16/09).
	PQFieldsPresent bool `json:"-"`
	// Shape: the reason of the first row 4-13 of the table of SPEC §22 rule 2 the document fails, "" if none
	Shape string `json:"-"`
}

// TipMembers is the closed member list of a tip (SPEC §22 rule 2, Unreleased; as cryptovalid_tip.TIP_MEMBERS): a member
// outside it is tip_invalid naming it (until 0.27.0 ignored, PASS).
var TipMembers = map[string]bool{"kind": true, "entries": true, "ledger_id": true, "tip_sha256": true, "ts": true,
	"log_pubkey_hex": true, "signature_hex": true, "signature_pq_hex": true, "log_pq_pubkey_b64": true}

// TipPath is the sidecar next to the ledger.
func TipPath(ledger string) string { return ledger + ".tip.json" }

// TipPayload returns the exact bytes that are signed (canonical JSON, keys sorted — Python is the oracle).
func TipPayload(entries int, ledgerID, tipSHA256, ts string) []byte {
	return []byte(fmt.Sprintf(`{"entries":%d,"kind":"%s","ledger_id":"%s","tip_sha256":"%s","ts":"%s"}`, entries, TipKind, ledgerID, tipSHA256, ts))
}

// the payload is built by Sprintf (no JSON escaping): only hex and a plain ISO-8601 timestamp are admitted,
// anything else would not be the reference bytes (council 15/09)
func isHex64(s string) bool { return isHexN(s, 64) }

// ValidLedgerID: the form of an expected ledger identity, 64 lowercase hex characters like every self_hash (SPEC v0.9
// §17 rule 1); any other value can match no ledger and is the caller's error (cvverify: usage, exit 2).
func ValidLedgerID(s string) bool { return isHex64(s) }

// isHexN: exactly n LOWERCASE hex digits (no whitespace, no uppercase — hex.DecodeString would take "AB")
func isHexN(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

// tsProfile is the ONE timestamp profile of the three checkers, validated by HAND (independent review,
// 15/09/2026: time.Parse accepted a comma fraction, a 10-digit fraction, offset +24:00 and year 0000 that Python
// refused). YYYY-MM-DDThh:mm:ss[.f{1,9}](Z|±hh:mm); year 0001-9999; real calendar day; hour 0-23; minute and
// second 0-59 (no leap second); offset hour 0-23, minute 0-59.
var tsProfile = regexp.MustCompile(`^([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})(?:\.([0-9]{1,9}))?(Z|[+-][0-9]{2}:[0-9]{2})$`) // [0-9] literally, as in Python/JS (RE2's \d is ASCII anyway)

func plainTS(s string) bool {
	_, err := parseInstant(s)
	return err == nil
}

// parseInstant applies the profile above and returns the instant; every other form is an error.
func parseInstant(s string) (time.Time, error) {
	m := tsProfile.FindStringSubmatch(s)
	if m == nil {
		return time.Time{}, errors.New("timestamp outside the profile YYYY-MM-DDThh:mm:ss[.fraction](Z|±hh:mm)")
	}
	y, _ := strconv.Atoi(m[1])
	mo, _ := strconv.Atoi(m[2])
	d, _ := strconv.Atoi(m[3])
	h, _ := strconv.Atoi(m[4])
	mi, _ := strconv.Atoi(m[5])
	sec, _ := strconv.Atoi(m[6])
	if y < 1 || y > 9999 || mo < 1 || mo > 12 || h > 23 || mi > 59 || sec > 59 {
		return time.Time{}, errors.New("timestamp field out of range")
	}
	leap := (y%4 == 0 && y%100 != 0) || y%400 == 0
	dim := []int{31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31}[mo-1]
	if mo == 2 && leap {
		dim = 29
	}
	if d < 1 || d > dim {
		return time.Time{}, errors.New("timestamp day does not exist in that month")
	}
	offSec := 0
	if m[8] != "Z" {
		oh, _ := strconv.Atoi(m[8][1:3])
		om, _ := strconv.Atoi(m[8][4:6])
		if oh > 23 || om > 59 {
			return time.Time{}, errors.New("timestamp offset out of range")
		}
		offSec = oh*3600 + om*60
		if m[8][0] == '-' {
			offSec = -offSec
		}
	}
	nanos := 0
	if m[7] != "" {
		n, _ := strconv.Atoi((m[7] + "000000000")[:9])
		nanos = n
	}
	return time.Date(y, time.Month(mo), d, h, mi, sec, nanos, time.FixedZone("", offSec)), nil
}

// LoadTipKey reads the 32-byte Ed25519 seed (hex) used by signer.py / cryptovalid_tip.py.
func LoadTipKey(keyfile string) (ed25519.PrivateKey, error) {
	raw, err := readInput(keyfile, keyMaxBytes) // SPEC §22 rule 8: a regular file or a FIFO of at most 1 MiB, never a wait without end
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
	f, err := openRegularLedger(ledger, os.O_RDONLY)
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
	t := &Tip{Kind: TipKind, Entries: entries, LedgerID: first, TipSHA256: last, TS: formatTS(ts),
		LogPubkeyHex: hex.EncodeToString(key.Public().(ed25519.PublicKey))}
	t.SignatureHex = hex.EncodeToString(ed25519.Sign(key, TipPayload(t.Entries, t.LedgerID, t.TipSHA256, t.TS)))
	doc, _ := json.Marshal(t)
	// 0.20.3: a temporary of a name nobody can predict (O_EXCL; it was <tip>.tmp, where a planted symlink or FIFO was
	// followed or blocked the run), written, fsynced and closed, then renamed; on failure removed, the old tip intact
	dir, base := filepath.Split(TipPath(ledger))
	if dir == "" {
		dir = "."
	}
	tf, err := os.CreateTemp(dir, base+".*.tmp")
	if err != nil {
		return nil, err
	}
	tmp := tf.Name()
	_, err = tf.Write(doc)
	if err == nil {
		err = tf.Chmod(0o600)
	}
	if err == nil {
		err = tf.Sync()
	}
	if cerr := tf.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmp, TipPath(ledger))
	}
	if err != nil {
		_ = os.Remove(tmp)
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
	if t == nil {
		return false, "tip_invalid: not a cryptovalid_tip/1 document", false
	}
	if t.Shape != "" { // SPEC §22 rule 2, rows 4-13, read by LoadTip from the document
		return false, "tip_invalid: " + t.Shape, false
	}
	// a Tip built by a caller without LoadTip: the same rows on its fields, the same words
	pq := t.PQFieldsPresent || t.SignaturePQHex != "" || t.LogPQPubkeyB64 != ""
	switch {
	case t.Kind != TipKind:
		return false, "tip_invalid: not a cryptovalid_tip/1 document", false
	case t.Entries < 0:
		return false, "tip_invalid: tip entries must be a non-negative integer", false
	case !isHex64(t.LedgerID) || !isHex64(t.TipSHA256):
		return false, "tip_invalid: ledger_id / tip_sha256 must be 64 lowercase hex characters", false
	case !isHexN(t.SignatureHex, 128):
		return false, "tip_invalid: signature_hex must be 128 lowercase hex characters", false
	case pq && !isHexN(t.SignaturePQHex, 6618):
		return false, "tip_invalid: signature_pq_hex must be 6618 lowercase hex characters (ML-DSA-65)", false
	case pq && decodeB64Strict(t.LogPQPubkeyB64, 1952) == nil:
		return false, "tip_invalid: log_pq_pubkey_b64 must be strict base64 of a 1952-byte ML-DSA-65 public key", false
	case !plainTS(t.TS):
		return false, "tip_invalid: ts outside the profile YYYY-MM-DDThh:mm:ss[.fraction](Z|±hh:mm)", false
	}

	// the key inside the tip proves nothing: without the trusted log key there is NO verification (never a
	// "PASS but untrusted" that an automation reads as exit 0 — council 15/09)
	if trustedPubkeyHex == "" {
		return false, "tip_untrusted: no trusted log key given (-trusted-pubkey); the key inside the tip cannot be trusted", false
	}
	if t.LogPubkeyHex != "" && t.LogPubkeyHex != trustedPubkeyHex {
		return false, "tip_invalid: tip log key differs from the trusted log key", false
	}
	pk, err1 := hex.DecodeString(trustedPubkeyHex)
	sig, err2 := hex.DecodeString(t.SignatureHex)
	if err1 != nil || err2 != nil || len(pk) != ed25519.PublicKeySize {
		return false, "tip_invalid: tip signature invalid", false
	}
	if ok, why := ed25519Strict(pk, TipPayload(t.Entries, t.LedgerID, t.TipSHA256, t.TS), sig, nil); !ok {
		if why == "bad_signature" {
			return false, "tip_invalid: tip signature invalid", false
		}
		return false, "tip_invalid: tip signature invalid (" + why + ")", false // 0.21.0: small/mixed order, named
	}
	trusted = trustedPubkeyHex != ""
	if expectLedgerID != "" && t.LedgerID != expectLedgerID {
		return false, "ledger_id_mismatch: the tip belongs to a different ledger than the one you expect", trusted
	}
	if entries > 0 && t.LedgerID != first {
		return false, "tip_of_another_ledger: the tip's ledger_id is not this file's first self_hash", trusted
	}
	if notBefore != "" {
		// instants, not strings (council 15/09: "…Z" vs "…+00:00" compared as bytes was a false rollback);
		// a malformed notBefore is the VERIFIER's error, never the tip's
		nbT, e2 := parseInstant(notBefore)
		if e2 != nil {
			return false, "bad_not_before: --tip-not-before must be YYYY-MM-DDThh:mm:ss[.f](Z|±hh:mm)", trusted
		}
		tipT, _ := parseInstant(t.TS)
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

// The texts of SPEC §22 rule 2, rows 1-3 (the same in the four verifiers).
const (
	TipUnreadableFile   = "tip_unreadable: the tip file cannot be read"
	TipUnreadableJSON   = "tip_unreadable: not a JSON text of the profile of SPEC §3"
	TipUnreadableObject = "tip_unreadable: not a JSON object"
)

// tipShape applies rows 4-13 of the table of SPEC §22 rule 2 to the decoded object, in that order, before any typed
// decode, and returns the first reason (without "tip_invalid: ") or "" when every row holds.
func tipShape(o *Object) string {
	if kind, isStr := o.Vals["kind"].(string); !isStr || kind != TipKind {
		return "not a cryptovalid_tip/1 document"
	}
	var unknown []string
	for _, k := range o.Keys {
		if !TipMembers[k] {
			unknown = append(unknown, k)
		}
	}
	if len(unknown) > 0 {
		sort.Strings(unknown) // UTF-8 byte order = code-point order, as Python's sorted()
		return "unknown_member:" + truncRunes(strings.Join(unknown, ","), 120)
	}
	for _, k := range []string{"entries", "ledger_id", "tip_sha256", "ts", "signature_hex"} {
		if _, ok := o.Vals[k]; !ok {
			return "tip missing field " + k
		}
	}
	num, isNum := o.Vals["entries"].(json.Number)
	if n, err := strconv.ParseInt(string(num), 10, 64); !isNum || err != nil || n < 0 {
		return "tip entries must be a non-negative integer"
	}
	str := func(k string) (string, bool) { v, ok := o.Vals[k].(string); return v, ok }
	lid, a := str("ledger_id")
	tsh, b := str("tip_sha256")
	ts, c := str("ts")
	sig, d := str("signature_hex")
	lpk, present := o.Vals["log_pubkey_hex"]
	_, lpkStr := lpk.(string)
	if !(a && b && c && d) || (present && lpk != nil && !lpkStr) {
		return "tip fields must be strings"
	}
	if !isHex64(lid) || !isHex64(tsh) {
		return "ledger_id / tip_sha256 must be 64 lowercase hex characters"
	}
	if !isHexN(sig, 128) {
		return "signature_hex must be 128 lowercase hex characters"
	}
	_, hasSpq := o.Vals["signature_pq_hex"]
	_, hasKpq := o.Vals["log_pq_pubkey_b64"]
	if hasSpq || hasKpq {
		if spq, ok := str("signature_pq_hex"); !ok || !isHexN(spq, 6618) {
			return "signature_pq_hex must be 6618 lowercase hex characters (ML-DSA-65)"
		}
		if kpq, ok := str("log_pq_pubkey_b64"); !ok || decodeB64Strict(kpq, 1952) == nil {
			return "log_pq_pubkey_b64 must be strict base64 of a 1952-byte ML-DSA-65 public key"
		}
	}
	if !plainTS(ts) {
		return "ts outside the profile YYYY-MM-DDThh:mm:ss[.fraction](Z|±hh:mm)"
	}
	return ""
}

// MaxTipBytes: a tip file larger than this is row 1 of the table of SPEC §22 rule 2 (verifier.py MAX_INPUT_BYTES).
const MaxTipBytes = 256 << 20

// readTipFile: the bytes of a regular file of at most MaxTipBytes, opened once without waiting (a FIFO, a device, a
// directory or a larger file is an error: row 1 of the table of SPEC §22 rule 2, as Python's read_regular).
func readTipFile(path string) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|oNonblock, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() || st.Size() > MaxTipBytes {
		return nil, errors.New("not a regular file of at most MaxTipBytes")
	}
	raw, err := io.ReadAll(io.LimitReader(f, MaxTipBytes+1))
	if err != nil || len(raw) > MaxTipBytes {
		return nil, errors.New("not a regular file of at most MaxTipBytes")
	}
	return raw, nil
}

// LoadTip reads a sidecar; any malformation is an error (never a silent "no tip"). SPEC §22 rule 2: a file that cannot
// be read, is not a JSON text of the profile, or is not an object is an error carrying one of the three texts above; a
// tip that fails a row 4-13 of the table is returned with Shape set, and CheckTip names it.
func LoadTip(path string) (*Tip, error) {
	raw, err := readTipFile(path)
	if err != nil {
		return nil, errors.New(TipUnreadableFile)
	}
	// the tip is a SIGNED document: same strict acceptance profile as the entries (dup keys, floats, bounds,
	// depth, surrogates) before the typed decode — one rule in Python, JS, Go and Java (r5); only JSON white space
	// around it (bytes.TrimSpace also took a form feed, a vertical tab, U+0085 and U+00A0)
	if countTokens(raw) > MaxJSONTokens { // SPEC §22 rule 9: counted before it is parsed
		return nil, errors.New(TipUnreadableJSON)
	}
	doc, err := Parse(bytes.Trim(raw, " \t\r\n"))
	if err != nil {
		return nil, errors.New(TipUnreadableJSON)
	}
	o, isObj := doc.(*Object)
	if !isObj {
		return nil, errors.New(TipUnreadableObject)
	}
	var t Tip
	if why := tipShape(o); why != "" {
		t.Shape = why
		return &t, nil
	}
	// every member was checked above, by its exact name: the fields are taken from the object, never from a
	// case-insensitive typed decode
	n, _ := strconv.ParseInt(string(o.Vals["entries"].(json.Number)), 10, 64)
	t.Kind, t.Entries = TipKind, int(n)
	t.LedgerID, _ = o.Vals["ledger_id"].(string)
	t.TipSHA256, _ = o.Vals["tip_sha256"].(string)
	t.TS, _ = o.Vals["ts"].(string)
	t.SignatureHex, _ = o.Vals["signature_hex"].(string)
	t.LogPubkeyHex, _ = o.Vals["log_pubkey_hex"].(string)
	_, a := o.Vals["signature_pq_hex"]
	_, b := o.Vals["log_pq_pubkey_b64"]
	t.PQFieldsPresent = a || b
	t.SignaturePQHex, _ = o.Vals["signature_pq_hex"].(string)
	t.LogPQPubkeyB64, _ = o.Vals["log_pq_pubkey_b64"].(string)
	return &t, nil
}

// formatTS writes the profile form in UTC; the fraction is kept only when non-zero (Python writes none).
func formatTS(ts time.Time) string {
	u := ts.UTC()
	if u.Nanosecond() == 0 {
		return u.Format("2006-01-02T15:04:05+00:00")
	}
	return u.Format("2006-01-02T15:04:05.999999999+00:00")
}

func decodeB64Strict(s string, n int) []byte {
	if len(s) != ((n+2)/3)*4 {
		return nil
	}
	raw, err := base64.StdEncoding.Strict().DecodeString(s)
	if err != nil || len(raw) != n || base64.StdEncoding.EncodeToString(raw) != s {
		return nil
	}
	return raw
}
