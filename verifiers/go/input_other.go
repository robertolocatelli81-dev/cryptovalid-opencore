// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build !unix

package cryptovalid

import (
	"os"
	"time"
)

// fifoReader: a named pipe on Windows (os.File.Stat says ModeNamedPipe), where a read has no deadline: each read runs in
// a goroutine and this one waits for it at most fifoIdle, so a pipe that gives no byte and no end for that long is
// errFIFOIdle, as on POSIX (until 0.29.0 it was read the plain way, bounded in size only: a pipe with a silent writer
// waited without end). The writer gone is the end (os.File.Read gives io.EOF for ERROR_BROKEN_PIPE). A read still
// waiting after errFIFOIdle is left to the process's end.
type fifoReader struct {
	f       *os.File
	pending chan fifoRead // a read in flight, nil when none
}

type fifoRead struct {
	b   []byte
	err error
}

func newFIFOReader(f *os.File) (*fifoReader, error) { return &fifoReader{f: f}, nil }

func (r *fifoReader) read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if r.pending == nil {
		ch := make(chan fifoRead, 1)
		buf := make([]byte, len(p))
		go func() {
			n, err := r.f.Read(buf)
			ch <- fifoRead{buf[:n], err}
		}()
		r.pending = ch
	}
	t := time.NewTimer(fifoIdle)
	defer t.Stop()
	select {
	case got := <-r.pending:
		r.pending = nil
		n := copy(p, got.b)
		return n, got.err
	case <-t.C:
		return 0, errFIFOIdle
	}
}
