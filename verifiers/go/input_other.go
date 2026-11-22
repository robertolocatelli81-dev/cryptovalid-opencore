// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build !unix

package cryptovalid

import "os"

// fifoReader: no non-blocking open on this platform (declared, SPEC §22 rules 2 and 8): a named pipe is read the plain
// way, bounded in size by inputReader, not in idle time
type fifoReader struct{ f *os.File }

func newFIFOReader(f *os.File) (*fifoReader, error) { return &fifoReader{f: f}, nil }

func (r *fifoReader) read(p []byte) (int, error) { return r.f.Read(p) }
