// SPDX-License-Identifier: AGPL-3.0-or-later
package cryptovalid

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strconv"
	"time"
)

// Append adds one entry {idx, ts, prev_hash, data, self_hash} to a JSONL ledger (created if absent).
// `data` is any JSON-encodable value WITHOUT floats (ints, strings, bools, nested objects/arrays).
// This is what a writer such as a database's audit log needs at insert time.
//
// Concurrency: the ledger file is held under an exclusive BLOCKING advisory lock (flock LOCK_EX on Unix) from
// the read of the tail to the fsync of the new line. Every call opens its own descriptor, and flock is per open
// file description, so callers are serialised both across processes and across goroutines of one process
// (test: 40 concurrent Append → one chain of 40). On non-Unix builds there is no lock: serialise callers yourself.
// Torn write (declared): a crash between Write and Sync can leave a partial last line without '\n'; the next
// Append refuses to continue from it ("torn last line") and never guesses — recovery is a human decision:
// verify the file, truncate the torn bytes, keep the incident in the ledger's report.
// Cost: O(1) per append — the tail is read backwards from the end (last line only), idx = last idx + 1.
// Note on Go's json.Marshal: a whole-number float64 marshals as an integer (accepted); a non-UTF-8 Go string
// is replaced with U+FFFD by Marshal before this function sees it — validate strings at the source.
func Append(path string, ts time.Time, data any, algo string) (selfHash string, err error) {
	return appendLocked(path, ts, data, algo, nil)
}

// appendLocked is Append with an optional hook run under the same lock after the fsync, receiving the new
// entry count and self_hash (used by AppendSigned to write the signed tip atomically with the append).
func appendLocked(path string, ts time.Time, data any, algo string, after func(f *os.File, entries int, last string) error) (selfHash string, err error) {
	if algo == "" {
		algo = "sha256"
	}
	raw, err := json.Marshal(data)
	if err != nil {
		return "", err
	}
	dv, err := Parse(raw) // enforces: no floats, no duplicate keys, valid UTF-8, bounds
	if err != nil {
		return "", fmt.Errorf("data not admissible: %w", err)
	}
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return "", err
	}
	defer f.Close()
	if err := lockFile(f); err != nil {
		return "", err
	}
	defer unlockFile(f)
	idx, prev, err := tail(f)
	if err != nil {
		return "", err
	}
	entry := &Object{Keys: []string{"idx", "ts", "prev_hash", "data"}, Vals: map[string]any{
		"idx": json.Number(strconv.Itoa(idx)), "ts": ts.UTC().Format("2006-01-02T15:04:05Z"),
		"prev_hash": prev, "data": dv}}
	payload, err := Canonical(entry)
	if err != nil {
		return "", err
	}
	selfHash, err = Hash(algo, payload)
	if err != nil {
		return "", err
	}
	entry.Keys = append(entry.Keys, "self_hash")
	entry.Vals["self_hash"] = selfHash
	line, err := Canonical(entry) // the stored line is canonical too (any JSON encoding would verify)
	if err != nil {
		return "", err
	}
	if _, err := f.Seek(0, io.SeekEnd); err != nil {
		return "", err
	}
	if _, err := f.Write(append(line, '\n')); err != nil {
		return "", err
	}
	if err := f.Sync(); err != nil {
		return "", err
	}
	if after != nil {
		if err := after(f, idx+1, selfHash); err != nil {
			return "", fmt.Errorf("entry written, tip NOT signed: %w", err)
		}
	}
	return selfHash, nil
}

// tail returns (next idx, last self_hash) reading ONLY the last line (backwards from EOF); genesis if empty.
// Any read error or an unreadable last line is an error: the chain is never continued from a guessed state.
func tail(f *os.File) (int, string, error) {
	st, err := f.Stat()
	if err != nil {
		return 0, "", err
	}
	size := st.Size()
	if size == 0 {
		return 0, Genesis, nil
	}
	const chunk = 64 << 10
	var buf []byte
	pos := size
	for pos > 0 {
		n := int64(chunk)
		if n > pos {
			n = pos
		}
		pos -= n
		part := make([]byte, n)
		if _, err := f.ReadAt(part, pos); err != nil && err != io.EOF {
			return 0, "", err
		}
		buf = append(part, buf...)
		trimmed := bytes.TrimRight(buf, "\r\n \t")
		if k := bytes.LastIndexByte(trimmed, '\n'); k >= 0 {
			buf = trimmed[k+1:]
			break
		}
		if pos == 0 {
			buf = trimmed
		}
		if int64(len(buf)) > MaxLineBytes {
			return 0, "", fmt.Errorf("last line exceeds %d bytes", MaxLineBytes)
		}
	}
	if len(bytes.TrimSpace(buf)) == 0 {
		return 0, Genesis, nil
	}
	// The last byte ON DISK must be '\n' — checked ALWAYS, not only when the line fails to parse (council
	// round 3, 14/09/2026): a complete line that lost only its newline (crash between '}' and '\n', or a file
	// truncated by one byte) parses fine, and Append would then write the next entry on the SAME line and
	// corrupt the chain itself. Refuse instead of guessing; recovery is a human decision.
	tailRaw := make([]byte, 1)
	if _, err := f.ReadAt(tailRaw, size-1); err != nil {
		return 0, "", err
	}
	if tailRaw[0] != '\n' {
		// say exactly what is on disk (council round 4): bytes after the last '\n' that are only
		// whitespace are NOT a missing newline — the line is terminated, something was appended after it
		if tailWhitespaceOnly(f, size) {
			return 0, "", fmt.Errorf("trailing whitespace after the last newline: refusing to continue the chain; recovery = verify the file, truncate the trailing bytes, record the incident")
		}
		if _, perr := Parse(buf); perr != nil {
			return 0, "", fmt.Errorf("torn last line (no trailing newline, unparsable): refusing to continue the chain; recovery = verify, truncate the torn bytes, record the incident: %w", perr)
		}
		return 0, "", fmt.Errorf("torn last line (complete entry, no trailing newline): refusing to continue the chain; recovery = verify the file, append the missing newline, record the incident")
	}
	v, err := Parse(buf)
	if err != nil {
		return 0, "", fmt.Errorf("last line unreadable: %w", err)
	}
	obj, ok := v.(*Object)
	if !ok {
		return 0, "", fmt.Errorf("last line is not an object")
	}
	h, _ := obj.Vals["self_hash"].(string)
	if len(h) != 64 {
		return 0, "", fmt.Errorf("last line has no self_hash")
	}
	idx, ok := obj.Vals["idx"].(json.Number)
	if !ok {
		return 0, "", fmt.Errorf("last line has no idx")
	}
	n, err := strconv.Atoi(idx.String())
	if err != nil || n < 0 {
		return 0, "", fmt.Errorf("last line idx %q invalid", idx.String())
	}
	return n + 1, h, nil
}

// tailWhitespaceOnly reports whether every byte after the last '\n' of the file is whitespace (and a '\n' exists
// in the window it inspects). It reads at most 64 KiB from the end: a longer whitespace tail is treated as "no".
func tailWhitespaceOnly(f *os.File, size int64) bool {
	n := int64(64 << 10)
	if n > size {
		n = size
	}
	raw := make([]byte, n)
	if _, err := f.ReadAt(raw, size-n); err != nil && err != io.EOF {
		return false
	}
	k := bytes.LastIndexByte(raw, '\n')
	if k < 0 {
		return false
	}
	return len(bytes.TrimRight(raw[k+1:], " \t\r")) == 0
}
