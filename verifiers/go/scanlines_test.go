// SPDX-License-Identifier: AGPL-3.0-or-later

package cryptovalid

import (
	"bufio"
	"bytes"
	"io"
	"math/rand"
	"testing"
	"testing/iotest"
	"time"
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

// a long line arriving in small reads is searched once: linear, where bufio.ScanLines searches the pending line again at
// every read (64 MiB of a FIFO took 3.9 s against 0.39 s for 16 MiB, 2026-11-24). Measured against ScanLines on the same
// input (the control): at least 4 times faster on 32 MiB in 64 KiB reads.
func TestScanLinesOnceIsLinear(t *testing.T) {
	long := bytes.Repeat([]byte{'x'}, 32<<20)
	run := func(split bufio.SplitFunc) time.Duration {
		t0 := time.Now()
		sc := bufio.NewScanner(&chunks{b: long, n: 64 << 10})
		sc.Buffer(make([]byte, 1<<20), 64<<20)
		sc.Split(split)
		for sc.Scan() {
		}
		return time.Since(t0)
	}
	once, old := run(scanLinesOnce()), run(bufio.ScanLines)
	if once*4 > old {
		t.Fatalf("scanLinesOnce %v, bufio.ScanLines %v: not linear", once, old)
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
