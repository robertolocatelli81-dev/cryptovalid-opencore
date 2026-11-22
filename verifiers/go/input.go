// SPDX-License-Identifier: AGPL-3.0-or-later
package cryptovalid

import (
	"errors"
	"fmt"
	"io"
	"os"
	"time"
)

// SPEC §22 rule 8 (§5 step 0 of the Python reference: verifier.open_ledger_input, read_input): the path is opened once
// without waiting for a writer (oNonblock) and judged on what was opened. A regular file of at most the bound is read;
// a FIFO (when the caller takes one) is read to its end, at most the bound, and a FIFO that gives no byte and no end of
// file for fifoIdle is errFIFOIdle; anything else that opens (a directory, a device) is errNotRegular, no byte read
// (a Unix socket does not open: the system's ENXIO).

const (
	maxInputBytes   = 256 << 20 // verifier.py MAX_INPUT_BYTES
	keyMaxBytes     = 1 << 20   // verifier.py KEY_MAX_BYTES
	fifoIdleSeconds = 10        // verifier.py FIFO_IDLE_SECONDS
	fifoIdle        = fifoIdleSeconds * time.Second
)

var (
	errNotRegular = errors.New("unreadable: not a regular file")
	errFIFOIdle   = fmt.Errorf("unreadable: FIFO idle for %d s", fifoIdleSeconds)
)

// inputTooLarge: the file, or the bytes of the FIFO, past the bound (the text of verifier.py)
type inputTooLarge struct{ limit int64 }

func (e *inputTooLarge) Error() string {
	return fmt.Sprintf("input_too_large: file exceeds %d bytes", e.limit)
}

// inputReader reads what openInput opened, never past limit; a reason of rule 8 met while reading is kept (reason)
type inputReader struct {
	f      *os.File
	fifo   *fifoReader // nil: a regular file
	n      int64
	limit  int64
	reason error
}

// openInput opens path once without waiting and judges the open descriptor (SPEC §22 rule 8)
func openInput(path string, limit int64, fifoOK bool) (*inputReader, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|oNonblock, 0)
	if err != nil {
		return nil, err
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	switch m := st.Mode(); {
	case m.IsRegular():
		if st.Size() > limit {
			f.Close()
			return nil, &inputTooLarge{limit}
		}
		return &inputReader{f: f, limit: limit}, nil
	case fifoOK && m&os.ModeNamedPipe != 0:
		fr, err := newFIFOReader(f)
		if err != nil {
			f.Close()
			return nil, err
		}
		return &inputReader{f: f, fifo: fr, limit: limit}, nil
	}
	f.Close()
	return nil, errNotRegular
}

func (r *inputReader) Read(p []byte) (int, error) {
	if r.reason != nil {
		return 0, r.reason
	}
	if room := r.limit + 1 - r.n; int64(len(p)) > room {
		p = p[:room] // never more than one byte past the bound
	}
	var n int
	var err error
	if r.fifo != nil {
		n, err = r.fifo.read(p)
	} else {
		n, err = r.f.Read(p)
	}
	r.n += int64(n)
	if r.n > r.limit {
		r.reason = &inputTooLarge{r.limit}
		return 0, r.reason
	}
	if errors.Is(err, errFIFOIdle) {
		r.reason = err
	}
	return n, err
}

func (r *inputReader) Close() error { return r.f.Close() }

// openRegularLedger opens the ledger a writer appends to or signs (SPEC §5 step 0 (a), §22 rule 8): once, without
// waiting, and only a regular file (a FIFO there waited, and a link to /dev/zero was written to, until 2026-11-22)
func openRegularLedger(path string, flag int) (*os.File, error) {
	f, err := os.OpenFile(path, flag|oNonblock, 0o600)
	if err != nil {
		return nil, err
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	if !st.Mode().IsRegular() {
		f.Close()
		return nil, fmt.Errorf("%s: %w", path, errNotRegular)
	}
	return f, nil
}

// readInput: the bytes of path read by rule 8 (a regular file or a FIFO of at most limit bytes)
func readInput(path string, limit int64) ([]byte, error) {
	r, err := openInput(path, limit, true)
	if err != nil {
		return nil, err
	}
	defer r.Close()
	return io.ReadAll(r)
}
