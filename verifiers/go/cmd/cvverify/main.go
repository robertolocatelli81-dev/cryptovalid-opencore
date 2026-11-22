// cvverify — Go verifier for cryptovalid ledgers. Exit 0 = PASS, 1 = FAIL (an empty ledger is FAIL too), 2 = usage,
// 74 = the receipt was not written whole (stdout full or a reader gone; 0.20.3), whatever the verdict.
// With a signed chain tip (-tip, or <ledger>.tip.json next to the file) truncation / suffix rewrite / unsealed
// appends are named failures; -trusted-pubkey <hex> is the log key the relying party trusts and makes the tip required
// (SPEC §22 rule 1); -require-tip makes a missing tip a failure.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	cv "github.com/robertolocatelli81-dev/cryptovalid-opencore/verifiers/go"
)

// onceString: a value flag given twice is a usage error, exit 2 (flag keeps the last value, so the first expectation would be
// accepted and dropped: SPEC v0.9 §17, NEMESIS 16/11/2026)
type once struct {
	v   string
	set bool
}

func (o *once) String() string { return o.v }
func (o *once) Set(s string) error {
	if o.set {
		return fmt.Errorf("given twice (a second value would silently replace the first)")
	}
	o.v, o.set = s, true
	return nil
}

func onceString(name, usage string) *string {
	o := &once{}
	flag.Var(o, name, usage)
	return &o.v
}

func main() {
	// a reader that is gone must be an EPIPE error the program sees, not a SIGPIPE death (exit 141, no message: 0.20.2)
	signal.Ignore(syscall.SIGPIPE)
	tip := onceString("tip", "signed chain tip to check (default: <ledger>.tip.json if present)")
	pk := onceString("trusted-pubkey", "log key (hex) the tip must be signed with; makes the tip required (SPEC §22 rule 1)")
	req := flag.Bool("require-tip", false, "FAIL when no signed tip is available")
	nb := onceString("tip-not-before", "refuse a tip dated before this ISO-8601 instant (rollback)")
	lid := onceString("expect-ledger-id", "the chain identity (self_hash of entry 0) you expect")
	pq := onceString("trusted-pq-pubkey", "ML-DSA-65 log key (base64) a hybrid tip must also be signed with (FAIL if missing/invalid)")
	epk := onceString("pubkey", "Ed25519 key (hex) every ENTRY signature must be by (signed ledgers)")
	epq := onceString("pq-pubkey", "ML-DSA-65 key (base64) every ENTRY must also be signed with: requires the layer (needs -pubkey)")
	rpq := flag.Bool("require-pq", false, "FAIL unless every entry carries a valid ML-DSA-65 signature by -pq-pubkey")
	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: cvverify [-tip f] [-trusted-pubkey hex] [-require-tip] [-tip-not-before iso] [-expect-ledger-id hex] <ledger.jsonl>")
	}
	flag.Parse()
	if flag.NArg() != 1 {
		flag.Usage()
		os.Exit(2)
	}
	flag.Visit(func(f *flag.Flag) { // a value flag given with "" (or a flag as its value) would silently mean "not given": usage error (21/09/2026, one grammar in the four)
		if v := f.Value.String(); v == "" || strings.HasPrefix(v, "-") { // boolean flags print "true": never caught here
			fmt.Fprintf(os.Stderr, "usage: -%s needs a value (got %q)\n", f.Name, v)
			os.Exit(2)
		}
	})
	if *lid != "" && !cv.ValidLedgerID(*lid) { // SPEC v0.9 §17: a value that can match no ledger is a usage error
		fmt.Fprintf(os.Stderr, "usage: -expect-ledger-id needs 64 lowercase hex characters, the self_hash of entry 0 (got %q)\n", *lid)
		os.Exit(2)
	}
	if _, err := os.Stat(flag.Arg(0)); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	v := cv.VerifyLedgerFull(flag.Arg(0), *tip, *pk, *pq, *epk, *epq, *rpq, *req, *nb, *lid)
	out, _ := json.MarshalIndent(v, "", " ")
	// 0.20.3: fmt.Println's error was dropped, so a full disk exited with the verdict's code and no receipt. os.Stdout is
	// unbuffered: Write returning nil means every byte was taken.
	if _, err := os.Stdout.Write(append(out, '\n')); err != nil {
		fmt.Fprintf(os.Stderr, "receipt not written: %v\n", err)
		os.Exit(74) // sysexits EX_IOERR
	}
	if v.Verdict == "PASS" {
		os.Exit(0)
	}
	os.Exit(1)
}
