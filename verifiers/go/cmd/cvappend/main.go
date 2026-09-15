// cvappend — append one JSON object (stdin) to a cryptovalid ledger; prints the self_hash.
// -tipkey <seed.hex>: also sign the chain tip (<ledger>.tip.json) under the same lock (tip.go).
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	cv "github.com/robertolocatelli81-dev/cryptovalid-opencore/verifiers/go"
)

func main() {
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
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Println(h)
}
