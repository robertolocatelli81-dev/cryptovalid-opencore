//go:build !unix

package cryptovalid

import "os"

// No advisory lock on this platform: callers MUST serialise writers themselves (declared limit).
func lockFile(f *os.File) error   { return nil }
func unlockFile(f *os.File) error { return nil }
