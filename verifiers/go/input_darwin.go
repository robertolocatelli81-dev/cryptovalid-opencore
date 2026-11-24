// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build darwin

package cryptovalid

import (
	"io"
	"os"
	"syscall"
	"time"
)

// fifoReader on macOS: the descriptor opened with O_NONBLOCK, read directly and polled (pauses from 0.1 ms
// doubling to 10 ms while nothing comes), as the JS verifier does: a byte is data; EAGAIN is a writer there with nothing yet; 0 is the end once a writer was seen (a byte
// or an EAGAIN) and no writer yet before that, the distinction verifier.py's select makes. The idle time counts from
// the last byte. Until 0.29.0 the runtime poller was used: on macOS (kqueue) a FIFO with no writer yet was reported
// readable and read as its end (a writer 2 s late found an empty ledger, CI run 45377477990); a select(2) loop tried
// next never saw the writer there (CI run 45460009605: idle with a writer present).
type fifoReader struct {
	f    *os.File
	rc   syscall.RawConn
	seen bool
}

func newFIFOReader(f *os.File) (*fifoReader, error) {
	rc, err := f.SyscallConn()
	if err != nil {
		return nil, err
	}
	return &fifoReader{f: f, rc: rc}, nil
}

func (r *fifoReader) read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	deadline := time.Now().Add(fifoIdle)
	pause := 100 * time.Microsecond // doubled up to 10 ms while nothing comes, back to 0.1 ms after a byte
	for {
		var n int
		var rerr error
		if err := r.rc.Control(func(fd uintptr) { n, rerr = syscall.Read(int(fd), p) }); err != nil {
			return 0, err
		}
		switch {
		case rerr == nil && n > 0:
			r.seen = true
			return n, nil
		case rerr == nil && n == 0 && r.seen:
			return 0, io.EOF
		case rerr == syscall.EAGAIN:
			r.seen = true
		case rerr == syscall.EINTR, rerr == nil:
			// interrupted, or no writer yet: wait
		default:
			return 0, rerr
		}
		if time.Now().After(deadline) {
			return 0, errFIFOIdle
		}
		time.Sleep(pause)
		if pause < 10*time.Millisecond {
			pause *= 2
		}
	}
}
