// cvappend — append one JSON object (stdin) to a cryptovalid ledger; prints the self_hash. Exit 0 done, 1 append refused
// (data not admissible, a torn last line, a lock or read error), 2 usage or data, 74 (0.20.3) = the line could not be
// written whole (truncated back: nothing recorded), or the -tipkey tip could not be written (the entry is appended), or
// the entry is appended but its self_hash could not be printed (stdout full or a reader gone).
// -tipkey <seed.hex>: also sign the chain tip (<ledger>.tip.json) under the same lock (tip.go).
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	cv "github.com/robertolocatelli81-dev/cryptovalid-opencore/verifiers/go"
)

func main() {
	signal.Ignore(syscall.SIGPIPE) // a reader that is gone is an EPIPE error, not a silent SIGPIPE death
	tipkey := flag.String("tipkey", "", "Ed25519 seed (hex file): sign the chain tip after the append")
	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: cvappend [-tipkey seed.hex] <ledger.jsonl> [RFC3339-ts] < data.json")
	}
	flag.Parse()
	if flag.NArg() < 1 {
		flag.Usage()
		os.Exit(2)
	}
	ts := time.Now()
	if flag.NArg() > 1 {
		t, err := time.Parse(time.RFC3339, flag.Arg(1))
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		ts = t
	}
	raw, _ := io.ReadAll(os.Stdin)
	var data any
	dec := json.NewDecoder(bytesReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&data); err != nil {
		fmt.Fprintln(os.Stderr, "data:", err)
		os.Exit(2)
	}
	var h string
	var err error
	if *tipkey != "" {
		key, kerr := cv.LoadTipKey(*tipkey)
		if kerr != nil {
			fmt.Fprintln(os.Stderr, kerr)
			os.Exit(2)
		}
		h, err = cv.AppendSigned(flag.Arg(0), ts, data, "sha256", key)
	} else {
		h, err = cv.Append(flag.Arg(0), ts, data, "sha256")
	}
	var nw *cv.NotWrittenError
	if errors.As(err, &nw) { // 0.20.3: the line (truncated back) or the signed tip was not written whole: 74
		fmt.Fprintf(os.Stderr, "receipt not written: %v\n", err)
		os.Exit(74) // sysexits EX_IOERR
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if _, err := fmt.Fprintln(os.Stdout, h); err != nil {
		fmt.Fprintf(os.Stderr, "receipt not written: %v (the entry is appended)\n", err)
		os.Exit(74) // sysexits EX_IOERR
	}
}
