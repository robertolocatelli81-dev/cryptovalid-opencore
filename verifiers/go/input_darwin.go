// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build darwin

package cryptovalid

import (
	"io"
	"os"
	"syscall"
	"time"
)

// fifoReader on macOS: select(2) on the descriptor opened with O_NONBLOCK, as verifier.py does. select tells the cases
// apart that a read cannot: a FIFO no writer has opened yet is not readable (it is waited for, up to fifoIdle), a byte
// or a writer gone is. Until 0.29.0 the runtime poller was used: on macOS (kqueue) a FIFO with no writer yet was
// reported readable at once and read as its end, so a writer 2 s late found an empty ledger (CI run 45377477990).
type fifoReader struct {
	f  *os.File
	rc syscall.RawConn
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
	var n int
	var rerr error
	for {
		left := time.Until(deadline)
		if left <= 0 {
			return 0, errFIFOIdle
		}
		ready := false
		var serr error
		if err := r.rc.Control(func(fd uintptr) {
			var set syscall.FdSet
			set.Bits[int(fd)/32] |= 1 << (uint(fd) % 32)
			tv := syscall.NsecToTimeval(int64(left))
			serr = syscall.Select(int(fd)+1, &set, nil, nil, &tv)
			ready = serr == nil && set.Bits[int(fd)/32]&(1<<(uint(fd)%32)) != 0
		}); err != nil {
			return 0, err
		}
		if serr == syscall.EINTR {
			continue
		}
		if serr != nil {
			return 0, serr
		}
		if !ready {
			continue // the time left is checked above
		}
		if err := r.rc.Control(func(fd uintptr) { n, rerr = syscall.Read(int(fd), p) }); err != nil {
			return 0, err
		}
		if rerr == syscall.EAGAIN || rerr == syscall.EINTR {
			continue
		}
		break
	}
	if rerr != nil {
		return 0, rerr
	}
	if n == 0 {
		return 0, io.EOF
	}
	return n, nil
}
