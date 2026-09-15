//go:build go1.27

package cryptovalid

// ML-DSA-65 (FIPS 204) tip verification with the Go standard library (crypto/mldsa, Go >= 1.27).
// A verifier built with an older toolchain uses tip_pq_compat.go and reports pq_unverifiable, never a silent green.

import (
	"crypto/mldsa"
	"encoding/hex"
)

const PQSupported = true

// PQContextTip is the FIPS 204 pure-mode context of tip signatures (entries use "cryptovalid/entry/1").
const PQContextTip = "cryptovalid/tip/1"

// CheckTipPQ verifies the ML-DSA-65 signature of a hybrid tip against the TRUSTED post-quantum key.
// protected: true = verified against the trusted key; false = absent, invalid, foreign or missing-when-required;
// nil = present but not checked (no trusted PQ key given) — the same tri-state as the Python reference.
func CheckTipPQ(t *Tip, trustedPQPubkeyB64 string) (protected *bool, why string) {
	f, tr := false, true
	if trustedPQPubkeyB64 == "" {
		if t.SignaturePQHex != "" {
			return nil, "pq_unchecked: the tip carries an ML-DSA-65 signature but no trusted post-quantum key was given"
		}
		return &f, "pq_absent: Ed25519-only tip (not quantum-resistant)"
	}
	if t.SignaturePQHex == "" {
		return &f, "pq_missing: a trusted ML-DSA-65 key was given but the tip carries no post-quantum signature"
	}
	if t.LogPQPubkeyB64 != "" && t.LogPQPubkeyB64 != trustedPQPubkeyB64 {
		return &f, "tip post-quantum key differs from the trusted one"
	}
	pk := decodeB64Strict(trustedPQPubkeyB64, 1952)
	if pk == nil {
		return &f, "bad_trusted_pq_key: -trusted-pq-pubkey must be strict base64 of 1952 bytes"
	}
	pub, err := mldsa.NewPublicKey(mldsa.MLDSA65(), pk)
	if err != nil {
		return &f, "trusted post-quantum key is not an ML-DSA-65 public key"
	}
	sig, err := hex.DecodeString(t.SignaturePQHex)
	if err != nil {
		return &f, "tip post-quantum signature is not hex"
	}
	if err := mldsa.Verify(pub, TipPayload(t.Entries, t.LedgerID, t.TipSHA256, t.TS), sig, &mldsa.Options{Context: PQContextTip}); err != nil {
		return &f, "tip post-quantum signature invalid"
	}
	return &tr, "ML-DSA-65 signature verified against the trusted post-quantum key"
}
