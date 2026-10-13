package main

// 0.20.3: cvappend prints the new entry's self_hash; when that line cannot be written (/dev/full, a reader gone) the exit
// is 74 with a stderr line, and the entry is appended all the same. On 0.20.2: exit 0 and nothing said (/dev/full), or a
// SIGPIPE death (reader gone).

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// failFsyncHook installs the fsync fault (fsync_linux_test.go); nil elsewhere
var failFsyncHook func(fd int) error

func TestMain(m *testing.M) {
	if os.Getenv("CVAPPEND_AS_CLI") == "1" {
		if v := os.Getenv("CVAPPEND_FAIL_FSYNC_FD"); v != "" && failFsyncHook != nil {
			n, _ := strconv.Atoi(v)
			if err := failFsyncHook(n); err != nil {
				os.Exit(125)
			}
		}
		os.Args = append([]string{"cvappend"}, strings.Split(os.Getenv("CVAPPEND_ARGS"), "\n")...)
		main()
		return
	}
	os.Exit(m.Run())
}

func run(t *testing.T, ledger string, stdout *os.File) (int, string) {
	cmd := exec.Command(os.Args[0], "-test.run=^$")
	cmd.Env = append(os.Environ(), "CVAPPEND_AS_CLI=1", "CVAPPEND_ARGS="+ledger+"\n2026-10-12T00:00:00Z")
	cmd.Stdin = strings.NewReader(`{"actor":"alice"}`)
	var errb, outb bytes.Buffer
	cmd.Stderr = &errb
	if stdout != nil {
		cmd.Stdout = stdout
	} else {
		cmd.Stdout = &outb
	}
	err := cmd.Run()
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode(), errb.String()
	} else if err != nil {
		t.Fatal(err)
	}
	if stdout == nil && len(strings.TrimSpace(outb.String())) != 64 {
		t.Errorf("control: printed %q, want a 64-hex self_hash", outb.String())
	}
	return 0, errb.String()
}

func lines(t *testing.T, p string) int {
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return bytes.Count(b, []byte("\n"))
}

func TestSelfHashNotWrittenIsExit74(t *testing.T) {
	ledger := filepath.Join(t.TempDir(), "l.jsonl")
	if code, stderr := run(t, ledger, nil); code != 0 || stderr != "" {
		t.Fatalf("control: exit %d stderr %q", code, stderr)
	}
	full, err := os.OpenFile("/dev/full", os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	code, stderr := run(t, ledger, full)
	full.Close()
	if code != 74 || !strings.HasPrefix(stderr, "receipt not written: ") {
		t.Errorf("/dev/full: exit %d stderr %q (want 74 + a line)", code, stderr)
	}
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	r.Close()
	code, stderr = run(t, ledger, w)
	w.Close()
	if code != 74 || !strings.HasPrefix(stderr, "receipt not written: ") {
		t.Errorf("reader gone: exit %d stderr %q (want 74 + a line)", code, stderr)
	}
	if n := lines(t, ledger); n != 3 {
		t.Errorf("ledger has %d entries, want 3 (the append happens before the print)", n)
	}
}

// runLimited runs cvappend under `ulimit -f <blocks>` (1 024-byte blocks in bash), stdout to a buffer.
func runLimited(t *testing.T, ledger string, blocks int, extra ...string) (int, string) {
	args := strings.Join(append(extra, ledger, "2026-10-12T00:00:00Z"), "\n")
	cmd := exec.Command("bash", "-c", "ulimit -f "+strconv.Itoa(blocks)+`; exec "$0" -test.run=^$`, os.Args[0])
	cmd.Env = append(os.Environ(), "CVAPPEND_AS_CLI=1", "CVAPPEND_ARGS="+args)
	cmd.Stdin = strings.NewReader(`{"actor":"alice"}`)
	var errb bytes.Buffer
	cmd.Stderr = &errb
	err := cmd.Run()
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode(), errb.String()
	} else if err != nil {
		t.Fatal(err)
	}
	return 0, errb.String()
}

// 0.20.3: a line that cannot be written whole (a file size limit) is truncated back under the lock: the ledger is byte
// for byte what it was, the exit is 74 with a line that says nothing was recorded. On 0.20.2: exit 1 and the ledger
// ended in part of a line, which the next append refused as a torn tail.
func TestLineNotWrittenWholeIsTruncatedBack(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash needed for ulimit")
	}
	ledger := filepath.Join(t.TempDir(), "l.jsonl")
	for i := 0; ; i++ {
		if code, stderr := run(t, ledger, nil); code != 0 {
			t.Fatalf("fill: exit %d %q", code, stderr)
		}
		st, _ := os.Stat(ledger)
		if r := st.Size() % 1024; r > 900 && r < 1000 || i > 200 {
			break
		}
	}
	before, _ := os.ReadFile(ledger)
	code, stderr := runLimited(t, ledger, int(len(before)/1024)+1)
	if code != 74 || !strings.Contains(stderr, "nothing was recorded, the ledger is left as it was") {
		t.Errorf("limited: exit %d stderr %q (want 74 + nothing was recorded)", code, stderr)
	}
	after, _ := os.ReadFile(ledger)
	if !bytes.Equal(before, after) {
		t.Errorf("the ledger changed: %d bytes before, %d after", len(before), len(after))
	}
	if code, stderr := run(t, ledger, nil); code != 0 { // the chain continues: no torn tail left
		t.Errorf("append after the failure: exit %d %q", code, stderr)
	}
}

// 0.20.3: with -tipkey, a tip that cannot be written (here its path is a directory) is 74, the entry is appended and
// the line says so. On 0.20.2: exit 1.
func TestTipNotWrittenIs74(t *testing.T) {
	d := t.TempDir()
	ledger := filepath.Join(d, "l.jsonl")
	seed := filepath.Join(d, "k.hex")
	if err := os.WriteFile(seed, []byte(strings.Repeat("ab", 32)), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(ledger+".tip.json", 0o700); err != nil {
		t.Fatal(err)
	}
	code, stderr := runLimited(t, ledger, 1<<20, "-tipkey", seed)
	if code != 74 || !strings.Contains(stderr, "is in the ledger, the tip (if there is one) still names the previous entry") {
		t.Errorf("tip: exit %d stderr %q", code, stderr)
	}
	if n := lines(t, ledger); n != 1 {
		t.Errorf("ledger has %d entries, want 1", n)
	}
	left, _ := filepath.Glob(filepath.Join(d, "*.tmp"))
	if len(left) != 0 {
		t.Errorf("temporary left: %v", left)
	}
}

// 0.20.3: the tip goes through a temporary of an unpredictable name; a symlink planted at the old predictable
// <tip>.tmp is never followed (0.20.2 truncated and rewrote its target).
func TestTipNeverFollowsPlantedTmp(t *testing.T) {
	d := t.TempDir()
	ledger := filepath.Join(d, "l.jsonl")
	seed := filepath.Join(d, "k.hex")
	if err := os.WriteFile(seed, []byte(strings.Repeat("ab", 32)), 0o600); err != nil {
		t.Fatal(err)
	}
	victim := filepath.Join(d, "victim")
	if err := os.WriteFile(victim, []byte("untouched"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, ledger+".tip.json.tmp"); err != nil {
		t.Fatal(err)
	}
	if code, stderr := runLimited(t, ledger, 1<<20, "-tipkey", seed); code != 0 {
		t.Fatalf("exit %d %q", code, stderr)
	}
	if b, _ := os.ReadFile(victim); string(b) != "untouched" {
		t.Errorf("the planted symlink was followed: victim now %q", b)
	}
}

// review of 0.20.3, 13/10: a ledger named without a folder (cvappend l.jsonl) gets its tip's temporary next to it, never in
// $TMPDIR (another file system there makes the rename fail: EXDEV, exit 74 with the entry appended and no tip).
func TestTipTemporaryNextToARelativeLedger(t *testing.T) {
	d := t.TempDir()
	if err := os.WriteFile(filepath.Join(d, "k.hex"), []byte(strings.Repeat("ab", 32)), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^$")
	cmd.Dir = d
	cmd.Env = append(os.Environ(), "CVAPPEND_AS_CLI=1", "CVAPPEND_ARGS=-tipkey\nk.hex\nl.jsonl\n2026-10-12T00:00:00Z",
		"TMPDIR="+filepath.Join(d, "no-such-dir"))
	cmd.Stdin = strings.NewReader(`{"actor":"alice"}`)
	var errb bytes.Buffer
	cmd.Stderr = &errb
	if err := cmd.Run(); err != nil {
		t.Fatalf("relative ledger with TMPDIR elsewhere: %v %q", err, errb.String())
	}
	if _, err := os.Stat(filepath.Join(d, "l.jsonl.tip.json")); err != nil {
		t.Errorf("no tip next to the ledger: %v", err)
	}
}
