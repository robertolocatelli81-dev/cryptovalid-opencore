// SPDX-License-Identifier: AGPL-3.0-or-later

package cryptovalid

import (
	"bufio"
	"bytes"
	"io"
	"math/rand"
	"sync/atomic"
	"testing"
	"testing/iotest"
)

func lines(r io.Reader, split bufio.SplitFunc) []string {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 16), 1<<20)
	sc.Split(split)
	var out []string
	for sc.Scan() {
		out = append(out, sc.Text())
	}
	return out
}

// scanLinesOnce gives the lines bufio.ScanLines gives, whatever the input and however it arrives
func TestScanLinesOnceIsScanLines(t *testing.T) {
	rng := rand.New(rand.NewSource(20261124))
	alphabet := []byte("ab\n\r\n ")
	for k := 0; k < 2000; k++ {
		b := make([]byte, rng.Intn(300))
		for i := range b {
			b[i] = alphabet[rng.Intn(len(alphabet))]
		}
		want := lines(bytes.NewReader(b), bufio.ScanLines)
		for _, r := range []io.Reader{bytes.NewReader(b), iotest.OneByteReader(bytes.NewReader(b)), iotest.HalfReader(bytes.NewReader(b))} {
			if got := lines(r, scanLinesOnce()); !equal(got, want) {
				t.Fatalf("input %q: %q, want %q", b, got, want)
			}
		}
	}
}

func equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// a long line arriving in small reads is searched once. Counted, not timed (a shared CI runner's noise): the bytes each
// split searches. bufio.ScanLines searches all the pending bytes at every call; scanLinesOnce only those it has not
// searched (it is called with the same token start until it returns a line). On 32 MiB in 64 KiB reads: scanLinesOnce
// at most twice the input, ScanLines (the control) at least 100 times it (64 MiB of a FIFO took 3.9 s against 0.39 s
// for 16 MiB before, 2026-11-24).
func TestScanLinesOnceIsLinear(t *testing.T) {
	const size = 32 << 20
	long := bytes.Repeat([]byte{'x'}, size)
	scan := func(split bufio.SplitFunc) {
		sc := bufio.NewScanner(&chunks{b: long, n: 64 << 10})
		sc.Buffer(make([]byte, 1<<20), 64<<20)
		sc.Split(split)
		for sc.Scan() {
		}
	}
	before := atomic.LoadInt64(&scanSearchedBytes)
	scan(scanLinesOnce())
	once := atomic.LoadInt64(&scanSearchedBytes) - before
	var old int64 // the control: ScanLines searches the whole pending line at every call
	scan(func(data []byte, atEOF bool) (int, []byte, error) {
		old += int64(len(data))
		return bufio.ScanLines(data, atEOF)
	})
	if once > 2*size || old < 100*size {
		t.Fatalf("bytes searched: scanLinesOnce %d, bufio.ScanLines %d, input %d", once, old, size)
	}
}

type chunks struct {
	b []byte
	n int
}

func (c *chunks) Read(p []byte) (int, error) {
	if len(c.b) == 0 {
		return 0, io.EOF
	}
	if len(p) > c.n {
		p = p[:c.n]
	}
	k := copy(p, c.b)
	c.b = c.b[k:]
	return k, nil
}
