package cryptovalid

// 0.21.0 (SPEC v0.4 §5 step 5): the signature-profile vectors of spec/vectors/signatures — without a key, a signature layer
// that does not verify is a FAIL with the failing entries named; the Ed25519 checks refuse keys and R values of small or
// mixed order (ed25519order.go). Every vector passes steps 1-4.

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

type sigVector struct {
	Input     string `json:"input"`
	Normative struct {
		ChainIntegrity bool `json:"chain_integrity"`
	} `json:"normative"`
	Profile struct {
		Verdict  string `json:"verdict"`
		Failures []struct {
			Idx    int    `json:"idx"`
			Reason string `json:"reason"`
		} `json:"failures"`
	} `json:"signature_profile"`
}

func TestSignatureProfileVectors(t *testing.T) {
	dir := filepath.Join("..", "..", "spec", "vectors", "signatures")
	files, _ := filepath.Glob(filepath.Join(dir, "*.expected.json"))
	if len(files) < 21 {
		t.Fatalf("signature vectors: %d files", len(files))
	}
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		var v sigVector
		if err := json.Unmarshal(raw, &v); err != nil {
			t.Fatal(err)
		}
		got := VerifyLedgerFull(filepath.Join(dir, v.Input), "", "", "", "", "", false, false, "", "")
		want := []string{}
		for _, x := range v.Profile.Failures {
			want = append(want, fmt.Sprintf("idx %d: %s", x.Idx, x.Reason))
		}
		have := []string{}
		if got.Signatures != nil {
			have = append(have, got.Signatures.Failures...)
		}
		sort.Strings(want)
		sort.Strings(have)
		if got.Verdict != v.Profile.Verdict || (got.HashRecomputePassed && got.LinkPassed) != v.Normative.ChainIntegrity || strings.Join(want, "|") != strings.Join(have, "|") {
			t.Errorf("%s: verdict %s chain %v failures %v, want %s %v", v.Input, got.Verdict, got.HashRecomputePassed && got.LinkPassed, have, v.Profile.Verdict, want)
		}
	}
}

func TestEd25519OrderPositiveControl(t *testing.T) {
	// 64 keys made by crypto/ed25519 are of prime order, and their signatures pass the R check
	for i := 0; i < 64; i++ {
		seed := make([]byte, 32)
		seed[0], seed[1] = byte(i), 0x5a
		sk := ed25519.NewKeyFromSeed(seed)
		pk := sk.Public().(ed25519.PublicKey)
		sig := ed25519.Sign(sk, []byte("m"))
		if p := Ed25519KeyProblem(pk); p != "" {
			t.Fatalf("key %d (%s): %s", i, hex.EncodeToString(pk), p)
		}
		if p := Ed25519RProblem(sig); p != "" {
			t.Fatalf("sig %d: %s", i, p)
		}
		if ok, why := ed25519Strict(pk, []byte("m"), sig, nil); !ok {
			t.Fatalf("sig %d: %s", i, why)
		}
	}
	// the eight points of small order (their canonical encodings, enumerated from an order-8 point on 14/10/2026) are refused
	small := []string{
		"0100000000000000000000000000000000000000000000000000000000000000",
		"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
		"0000000000000000000000000000000000000000000000000000000000000000",
		"0000000000000000000000000000000000000000000000000000000000000080",
		"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
		"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
		"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
		"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
	}
	for _, h := range small {
		b, _ := hex.DecodeString(h)
		p := Ed25519KeyProblem(b)
		if p != "small_order_key" {
			t.Errorf("%s as key: %q", h, p)
		}
		r := Ed25519RProblem(append(b, make([]byte, 32)...))
		if r != "small_order_r" {
			t.Errorf("%s as R: %q", h, r)
		}
	}
}
