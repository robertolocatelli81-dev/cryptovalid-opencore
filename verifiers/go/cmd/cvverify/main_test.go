package main

// 0.20.3: a receipt that is not written whole is exit 74 (EX_IOERR) with one stderr line, whatever the verdict. The test
// binary re-runs itself as the CLI (CVVERIFY_AS_CLI=1), so the real main() writes to a real fd: /dev/full (ENOSPC) and a
// pipe whose read end is closed before the start (EPIPE; on 0.20.2 the process died of SIGPIPE, on /dev/full it exited
// with the verdict's code and no receipt). `>&-` is not tested: Go reopens fd 1 on /dev/null, the program cannot see it.

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestMain(m *testing.M) {
	if os.Getenv("CVVERIFY_AS_CLI") == "1" {
		os.Args = append([]string{"cvverify"}, strings.Split(os.Getenv("CVVERIFY_ARGS"), "\n")...)
		main()
		return
	}
	os.Exit(m.Run())
}

func repoFile(t *testing.T, rel string) string {
	_, here, _, _ := runtime.Caller(0)
	p := filepath.Join(filepath.Dir(here), "..", "..", "..", "..", rel)
	if _, err := os.Stat(p); err != nil {
		t.Fatalf("missing %s: %v", p, err)
	}
	return p
}

func cli(args []string, stdout *os.File) (int, string, []byte) {
	cmd := exec.Command(os.Args[0], "-test.run=^$")
	cmd.Env = append(os.Environ(), "CVVERIFY_AS_CLI=1", "CVVERIFY_ARGS="+strings.Join(args, "\n"))
	var errb, outb bytes.Buffer
	cmd.Stderr = &errb
	if stdout != nil {
		cmd.Stdout = stdout
	} else {
		cmd.Stdout = &outb
	}
	err := cmd.Run()
	code := 0
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		code = ee.ExitCode() // -1 when killed by a signal (SIGPIPE on 0.20.2)
	} else if err != nil {
		code = -2
	}
	return code, errb.String(), outb.Bytes()
}

func TestReceiptNotWrittenIsExit74(t *testing.T) {
	cases := []struct {
		name string
		args []string
		code int
	}{
		{"valid", []string{repoFile(t, "examples/sample_ledger.jsonl")}, 0},
		{"invalid", []string{repoFile(t, "examples/sample_ledger_tampered.jsonl")}, 1},
	}
	for _, c := range cases {
		code, stderr, out := cli(c.args, nil)
		var r map[string]any
		if code != c.code || json.Unmarshal(out, &r) != nil || strings.Contains(stderr, "receipt not written") {
			t.Errorf("%s control: exit %d (want %d), receipt %q, stderr %q", c.name, code, c.code, out, stderr)
		}
		full, err := os.OpenFile("/dev/full", os.O_WRONLY, 0)
		if err != nil {
			t.Fatal(err)
		}
		code, stderr, _ = cli(c.args, full)
		full.Close()
		if code != 74 || !strings.HasPrefix(stderr, "receipt not written: ") {
			t.Errorf("%s on /dev/full: exit %d, stderr %q (want 74 + a line)", c.name, code, stderr)
		}
		r2, w2, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		r2.Close()
		code, stderr, _ = cli(c.args, w2)
		w2.Close()
		if code != 74 || !strings.HasPrefix(stderr, "receipt not written: ") {
			t.Errorf("%s with the reader gone: exit %d, stderr %q (want 74 + a line)", c.name, code, stderr)
		}
	}
}
