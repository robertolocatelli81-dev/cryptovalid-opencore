// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build unix

package cryptovalid

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// SPEC §22 rule 8: the reader of the ledger and of the key file (openInput, readInput, openRegularLedger)

func TestInputNotRegular(t *testing.T) {
	dir := t.TempDir()
	for _, p := range []string{dir, "/dev/null"} {
		if _, err := openInput(p, 1<<20, true); !errors.Is(err, errNotRegular) {
			t.Fatalf("%s: %v", p, err)
		}
	}
	fifo := filepath.Join(dir, "f")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := openInput(fifo, 1<<20, false); !errors.Is(err, errNotRegular) { // a FIFO where only a file is taken
		t.Fatalf("fifo without fifoOK: %v", err)
	}
	if _, err := openRegularLedger(fifo, os.O_RDWR|os.O_CREATE); !errors.Is(err, errNotRegular) {
		t.Fatalf("writer on a fifo: %v", err)
	}
	key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	done := make(chan error, 1)
	go func() { _, err := SignTip(fifo, key, time.Now()); done <- err }() // waited for a writer until 2026-11-22
	select {
	case err := <-done:
		if !errors.Is(err, errNotRegular) {
			t.Fatalf("SignTip on a fifo: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("SignTip on a fifo waits")
	}
}

func TestInputBound(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "l")
	if err := os.WriteFile(p, []byte("0123456789"), 0o600); err != nil {
		t.Fatal(err)
	}
	var tl *inputTooLarge
	if _, err := openInput(p, 9, true); !errors.As(err, &tl) || err.Error() != "input_too_large: file exceeds 9 bytes" {
		t.Fatalf("larger than the bound: %v", err)
	}
	if b, err := readInput(p, 10); err != nil || string(b) != "0123456789" { // at the bound: read
		t.Fatalf("at the bound: %q %v", b, err)
	}
	r, err := openInput(p, 10, true) // a file that grows past the bound after the fstat
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if err := os.WriteFile(p, []byte("0123456789AB"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadAll(r); !errors.As(err, &tl) || !errors.As(r.reason, &tl) {
		t.Fatalf("grown past the bound: %v %v", err, r.reason)
	}
	if r.n != 11 { // never more than one byte past the bound is read
		t.Fatalf("read %d bytes past a bound of 10", r.n)
	}
}

func TestInputFIFO(t *testing.T) {
	dir := t.TempDir()
	fifo := filepath.Join(dir, "f")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	// a writer that comes after the open (on Linux the FIFO reads as its end until one comes)
	go func() {
		time.Sleep(300 * time.Millisecond)
		os.WriteFile(fifo, []byte("abc"), 0o600)
	}()
	if b, err := readInput(fifo, 10); err != nil || string(b) != "abc" {
		t.Fatalf("late writer: %q %v", b, err)
	}
	// a writer that comes after the open and leaves without a byte: the end at once, not an idle FIFO (the first read
	// of nothing waits for the poller once, not at each read)
	go func() {
		time.Sleep(300 * time.Millisecond)
		if w, err := os.OpenFile(fifo, os.O_WRONLY, 0); err == nil {
			w.Close()
		}
	}()
	t0 := time.Now()
	if b, err := readInput(fifo, 10); err != nil || len(b) != 0 || time.Since(t0) > 5*time.Second {
		t.Fatalf("late writer that leaves without a byte: %q %v after %v", b, err, time.Since(t0))
	}
	// an empty buffer reads nothing and is not the end (io.Reader), whatever the FIFO holds
	go func() {
		time.Sleep(300 * time.Millisecond)
		os.WriteFile(fifo, []byte("xyz"), 0o600)
	}()
	r, err := openInput(fifo, 10, true)
	if err != nil {
		t.Fatal(err)
	}
	if n, err := r.Read(nil); n != 0 || err != nil {
		t.Fatalf("empty read: %d %v", n, err)
	}
	if b, err := io.ReadAll(r); err != nil || string(b) != "xyz" {
		t.Fatalf("after an empty read: %q %v", b, err)
	}
	r.Close()
	// more than the bound through a FIFO
	go func() {
		os.WriteFile(fifo, []byte("0123456789AB"), 0o600)
	}()
	var tl *inputTooLarge
	if _, err := readInput(fifo, 10); !errors.As(err, &tl) {
		t.Fatalf("fifo past the bound: %v", err)
	}
}

func TestInputFIFOIdle(t *testing.T) {
	if testing.Short() {
		t.Skip("waits 10 s")
	}
	dir := t.TempDir()
	fifo := filepath.Join(dir, "f")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	t0 := time.Now()
	_, err := readInput(fifo, 10)
	if !errors.Is(err, errFIFOIdle) || err.Error() != "unreadable: FIFO idle for 10 s" {
		t.Fatalf("no writer: %v", err)
	}
	if d := time.Since(t0); d < 9*time.Second || d > 30*time.Second {
		t.Fatalf("idle after %v", d)
	}
	v := VerifyLedgerFull(fifo, "", "", "", "", "", false, false, "", "")
	if v.Verdict != "FAIL" || len(v.Failures) != 1 || v.Failures[0] != "unreadable: FIFO idle for 10 s" {
		t.Fatalf("VerifyLedgerFull on a FIFO with no writer: %+v", v)
	}
}

// a ledger the writer creates is private to its owner whatever the umask (0600, as before rule 8 moved the open here)
func TestTheLedgerIsCreatedPrivate(t *testing.T) {
	old := syscall.Umask(0)
	defer syscall.Umask(old)
	p := filepath.Join(t.TempDir(), "new.jsonl")
	f, err := openRegularLedger(p, os.O_RDWR|os.O_CREATE)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("mode of a new ledger: %v %v", st.Mode().Perm(), err)
	}
}

// SPEC §22 rule 9: lines first, then tokens ({ [ , : inside strings too), counted over the whole input; the reason alone
func TestRule9TheBudgetOfALedger(t *testing.T) {
	lines := fmt.Sprintf("input_too_large: more than %d lines", MaxInputLines)
	tokens := fmt.Sprintf("input_too_large: more than %d JSON tokens", MaxJSONTokens)
	T := `"` + strings.Repeat(",", MaxJSONTokens) + `"`
	for _, c := range []struct {
		in, want string
	}{
		{strings.Repeat("0\n", MaxInputLines), ""},
		{strings.Repeat("0\n", MaxInputLines) + "0", lines},
		{T + "\n", ""},
		{T + ",\n", tokens},
		{strings.Repeat(",\n", MaxInputLines+1), lines},
	} {
		v := VerifyLedger(strings.NewReader(c.in))
		if v.Verdict != "FAIL" {
			t.Fatalf("%d bytes: %s", len(c.in), v.Verdict)
		}
		budget := len(v.Failures) == 1 && (v.Failures[0] == lines || v.Failures[0] == tokens)
		if (c.want == "" && budget) || (c.want != "" && (!budget || v.Failures[0] != c.want)) {
			t.Fatalf("%d bytes: want %q, got %v", len(c.in), c.want, v.Failures[:min(len(v.Failures), 2)])
		}
	}
	// the reason is alone whatever the caller asks (until NEMESIS 22/11/2026 the id and the tip asked for added theirs)
	p := filepath.Join(t.TempDir(), "l.jsonl")
	if err := os.WriteFile(p, []byte(strings.Repeat("\n", MaxInputLines+1)), 0o600); err != nil {
		t.Fatal(err)
	}
	v := VerifyLedgerFull(p, "", strings.Repeat("a", 64), "", strings.Repeat("a", 64), "", false, true, "2026-01-01T00:00:00Z", strings.Repeat("a", 64))
	if v.Verdict != "FAIL" || len(v.Failures) != 1 || v.Failures[0] != lines {
		t.Fatalf("with every option: %v", v.Failures)
	}
}
