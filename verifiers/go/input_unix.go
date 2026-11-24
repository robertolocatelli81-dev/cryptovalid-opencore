// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build unix && !darwin

package cryptovalid

import (
	"errors"
	"io"
	"os"
	"syscall"
	"time"
)

// fifoReader reads a FIFO opened with O_NONBLOCK. Where the runtime poller takes it (Linux, the BSDs) a read waits for
// the poller with a deadline of fifoIdle; on Linux a FIFO no writer has opened yet reads as its end, so a first read of
// nothing waits once for the poller (a writer that comes and writes, or comes and goes), as verifier.py's select does.
// Where the poller does not take a FIFO (macOS) it is read with a pause of 10 ms between tries (not measured).
type fifoReader struct {
	f       *os.File
	rc      syscall.RawConn
	polled  bool
	started bool // a byte came, or the read would block: a writer is there, so nothing read is the end
	waited  bool // the first read of nothing has waited once for the poller
}

func newFIFOReader(f *os.File) (*fifoReader, error) {
	rc, err := f.SyscallConn()
	if err != nil {
		return nil, err
	}
	return &fifoReader{f: f, rc: rc, polled: f.SetReadDeadline(time.Now().Add(fifoIdle)) == nil}, nil
}

func (r *fifoReader) read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	var n int
	var rerr error
	if r.polled {
		if err := r.f.SetReadDeadline(time.Now().Add(fifoIdle)); err != nil {
			return 0, err
		}
		err := r.rc.Read(func(fd uintptr) bool {
			n, rerr = syscall.Read(int(fd), p) // non-blocking: no EINTR; n is read only when rerr is nil
			if rerr == syscall.EAGAIN {
				r.started = true
				return false // wait for the poller
			}
			if rerr == nil && n == 0 && !r.started && !r.waited {
				r.waited = true
				return false
			}
			return true
		})
		if errors.Is(err, os.ErrDeadlineExceeded) {
			return 0, errFIFOIdle
		}
		if err != nil {
			return 0, err
		}
	} else {
		deadline := time.Now().Add(fifoIdle)
		for {
			if err := r.rc.Control(func(fd uintptr) { n, rerr = syscall.Read(int(fd), p) }); err != nil {
				return 0, err
			}
			if rerr != syscall.EAGAIN {
				break
			}
			if time.Now().After(deadline) {
				return 0, errFIFOIdle
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	if rerr != nil {
		return 0, rerr
	}
	if n == 0 {
		return 0, io.EOF
	}
	r.started = true
	return n, nil
}
