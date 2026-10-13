//go:build linux && (amd64 || arm64)

package main

// 0.20.3 (review of 0.20.3, 13/10): an fsync that FAILS is a line (or a tip) not written: the ledger is truncated back / the tip
// stays as it was, exit 74. The child installs a seccomp filter that makes fsync and fdatasync fail with EIO on one
// descriptor (or on all, -1) before running main(): the only way to fail an fsync from Go without a crash.

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"unsafe"
)

func installFsyncFilter(fd int) error {
	nrSeccomp := map[string]uintptr{"amd64": 317, "arm64": 277}[runtime.GOARCH]
	const (
		ld   = 0x00 | 0x00 | 0x20 // BPF_LD|BPF_W|BPF_ABS
		jeq  = 0x05 | 0x10 | 0x00 // BPF_JMP|BPF_JEQ|BPF_K
		ret  = 0x06               // BPF_RET|BPF_K
		allw = 0x7fff0000         // SECCOMP_RET_ALLOW
		eio  = 0x00050000 | 5     // SECCOMP_RET_ERRNO|EIO
	)
	miss := uint32(allw)
	if fd < 0 {
		miss = eio
	}
	prog := []syscall.SockFilter{
		{Code: ld, K: 0}, // seccomp_data.nr
		{Code: jeq, Jt: 2, K: uint32(syscall.SYS_FSYNC)},
		{Code: jeq, Jt: 1, K: uint32(syscall.SYS_FDATASYNC)},
		{Code: ret, K: allw},
		{Code: ld, K: 16}, // seccomp_data.args[0] (low 32 bits, little endian)
		{Code: jeq, Jt: 1, K: uint32(fd)},
		{Code: ret, K: miss},
		{Code: ret, K: eio},
	}
	fp := syscall.SockFprog{Len: uint16(len(prog)), Filter: &prog[0]}
	if _, _, e := syscall.RawSyscall6(syscall.SYS_PRCTL, 38 /*PR_SET_NO_NEW_PRIVS*/, 1, 0, 0, 0, 0); e != 0 {
		return e
	}
	if _, _, e := syscall.RawSyscall(nrSeccomp, 1 /*SET_MODE_FILTER*/, 1 /*FLAG_TSYNC*/, uintptr(unsafe.Pointer(&fp))); e != 0 {
		return e
	}
	return nil
}

func init() { failFsyncHook = installFsyncFilter }

func runFsync(t *testing.T, ledger, fd string, extra ...string) (int, string) {
	t.Setenv("CVAPPEND_FAIL_FSYNC_FD", fd)
	defer os.Unsetenv("CVAPPEND_FAIL_FSYNC_FD")
	return runLimited(t, ledger, 1<<20, extra...)
}

// a failed fsync of the LEDGER line: 74, ledger byte for byte as before (fsync fails on every descriptor)
func TestLedgerFsyncFailureIsTruncatedBack(t *testing.T) {
	ledger := filepath.Join(t.TempDir(), "l.jsonl")
	if code, e := run(t, ledger, nil); code != 0 {
		t.Fatalf("seed: %d %q", code, e)
	}
	before, _ := os.ReadFile(ledger)
	code, stderr := runFsync(t, ledger, "-1")
	if code != 74 || !strings.Contains(stderr, "nothing was recorded, the ledger is left as it was") {
		t.Errorf("fsync EIO: exit %d stderr %q", code, stderr)
	}
	if after, _ := os.ReadFile(ledger); !bytes.Equal(before, after) {
		t.Errorf("the ledger changed after a failed fsync: %d -> %d bytes", len(before), len(after))
	}
}

// a failed fsync of the TIP's temporary only: 74 with the tip line, the old tip intact, no temporary left. The tip's
// descriptor is found by trying each small descriptor number in turn.
func TestTipFsyncFailureIs74(t *testing.T) {
	seen := false
	for fd := 3; fd < 16 && !seen; fd++ {
		d := t.TempDir()
		ledger := filepath.Join(d, "l.jsonl")
		seed := filepath.Join(d, "k.hex")
		_ = os.WriteFile(seed, []byte(strings.Repeat("ab", 32)), 0o600)
		if code, e := runLimited(t, ledger, 1<<20, "-tipkey", seed); code != 0 {
			t.Fatalf("seed: %d %q", code, e)
		}
		tip0, _ := os.ReadFile(ledger + ".tip.json")
		code, stderr := runFsync(t, ledger, strconv.Itoa(fd), "-tipkey", seed)
		if !strings.Contains(stderr, ".tmp: input/output error") {
			continue
		}
		seen = true
		if code != 74 || !strings.Contains(stderr, "is in the ledger") {
			t.Errorf("tip fsync EIO (fd %d): exit %d %q", fd, code, stderr)
		}
		if tip1, _ := os.ReadFile(ledger + ".tip.json"); !bytes.Equal(tip0, tip1) {
			t.Errorf("the tip changed although its fsync failed")
		}
		if left, _ := filepath.Glob(filepath.Join(d, "*.tmp")); len(left) != 0 {
			t.Errorf("temporary left: %v", left)
		}
	}
	if !seen {
		t.Errorf("no descriptor made the tip's fsync fail: the tip is not fsynced")
	}
}
