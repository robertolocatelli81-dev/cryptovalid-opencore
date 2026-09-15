// cvverify — Go verifier for cryptovalid ledgers. Exit 0 = PASS, 1 = FAIL (an empty ledger is FAIL too), 2 = usage.
package main

import (
	"encoding/json"
	"fmt"
	"os"

	cv "github.com/robertolocatelli81-dev/cryptovalid-opencore/verifiers/go"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: cvverify <ledger.jsonl>")
		os.Exit(2)
	}
	f, err := os.Open(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	defer f.Close()
	v := cv.VerifyLedger(f)
	out, _ := json.MarshalIndent(v, "", " ")
	fmt.Println(string(out))
	if v.Verdict == "PASS" {
		os.Exit(0)
	}
	os.Exit(1)
}
