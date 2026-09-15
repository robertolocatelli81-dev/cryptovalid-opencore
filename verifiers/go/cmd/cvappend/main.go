// cvappend — append one JSON object (stdin) to a cryptovalid ledger; prints the self_hash.
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"

	cv "github.com/robertolocatelli81-dev/cryptovalid-opencore/verifiers/go"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: cvappend <ledger.jsonl> [RFC3339-ts] < data.json")
		os.Exit(2)
	}
	ts := time.Now()
	if len(os.Args) > 2 {
		t, err := time.Parse(time.RFC3339, os.Args[2])
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
	h, err := cv.Append(os.Args[1], ts, data, "sha256")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Println(h)
}
