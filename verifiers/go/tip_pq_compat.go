//go:build !go1.27

package cryptovalid

// Older toolchains have no crypto/mldsa: the post-quantum layer is declared unverifiable (protected=false when a
// trusted ML-DSA-65 key was given — a required layer that cannot be checked is not a pass; nil when unchecked).

const PQSupported = false

const PQContextTip = "cryptovalid/tip/1"

func CheckTipPQ(t *Tip, trustedPQPubkeyB64 string) (protected *bool, why string) {
	f := false
	if trustedPQPubkeyB64 == "" {
		if t.SignaturePQHex != "" {
			return nil, "pq_unchecked: the tip carries an ML-DSA-65 signature but no trusted post-quantum key was given"
		}
		return &f, "pq_absent: Ed25519-only tip (not quantum-resistant)"
	}
	return &f, "pq_unverifiable: this verifier was built with Go < 1.27 (no crypto/mldsa); rebuild with Go >= 1.27 to check the post-quantum layer"
}
