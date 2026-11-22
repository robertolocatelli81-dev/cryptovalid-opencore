//go:build !unix

package cryptovalid

import "os"

// oNonblock: no non-blocking open on this platform (declared limit: a FIFO given as a path waits for a writer)
const oNonblock = 0

// No advisory lock on this platform: callers MUST serialise writers themselves (declared limit).
func lockFile(f *os.File) error   { return nil }
func unlockFile(f *os.File) error { return nil }
