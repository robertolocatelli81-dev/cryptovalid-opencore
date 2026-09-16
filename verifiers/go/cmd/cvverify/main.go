// cvverify — Go verifier for cryptovalid ledgers. Exit 0 = PASS, 1 = FAIL (an empty ledger is FAIL too), 2 = usage.
// With a signed chain tip (-tip, or <ledger>.tip.json next to the file) truncation / suffix rewrite / unsealed
// appends are named failures; -trusted-pubkey <hex> is the log key the relying party trusts; -require-tip makes
// a missing tip a failure.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	cv "github.com/robertolocatelli81-dev/cryptovalid-opencore/verifiers/go"
)

func main() {
	tip := flag.String("tip", "", "signed chain tip to check (default: <ledger>.tip.json if present)")
	pk := flag.String("trusted-pubkey", "", "log key (hex) the tip must be signed with")
	req := flag.Bool("require-tip", false, "FAIL when no signed tip is available")
	nb := flag.String("tip-not-before", "", "refuse a tip dated before this ISO-8601 instant (rollback)")
	lid := flag.String("expect-ledger-id", "", "the chain identity (self_hash of entry 0) you expect")
	pq := flag.String("trusted-pq-pubkey", "", "ML-DSA-65 log key (base64) a hybrid tip must also be signed with (FAIL if missing/invalid)")
	epk := flag.String("pubkey", "", "Ed25519 key (hex) every ENTRY signature must be by (signed ledgers)")
	epq := flag.String("pq-pubkey", "", "ML-DSA-65 key (base64) every ENTRY must also be signed with: requires the layer (needs -pubkey)")
	rpq := flag.Bool("require-pq", false, "FAIL unless every entry carries a valid ML-DSA-65 signature by -pq-pubkey")
	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: cvverify [-tip f] [-trusted-pubkey hex] [-require-tip] [-tip-not-before iso] [-expect-ledger-id hex] <ledger.jsonl>")
	}
	flag.Parse()
	if flag.NArg() != 1 {
		flag.Usage()
		os.Exit(2)
	}
	if _, err := os.Stat(flag.Arg(0)); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	v := cv.VerifyLedgerFull(flag.Arg(0), *tip, *pk, *pq, *epk, *epq, *rpq, *req, *nb, *lid)
	out, _ := json.MarshalIndent(v, "", " ")
	fmt.Println(string(out))
	if v.Verdict == "PASS" {
		os.Exit(0)
	}
	os.Exit(1)
}
