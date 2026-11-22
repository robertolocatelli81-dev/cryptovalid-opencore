//go:build unix

package cryptovalid

import (
	"os"
	"syscall"
)

// oNonblock: a FIFO given as a path is opened without waiting for a writer (SPEC §22 rule 2, row 1)
const oNonblock = syscall.O_NONBLOCK

func lockFile(f *os.File) error   { return syscall.Flock(int(f.Fd()), syscall.LOCK_EX) }
func unlockFile(f *os.File) error { return syscall.Flock(int(f.Fd()), syscall.LOCK_UN) }
