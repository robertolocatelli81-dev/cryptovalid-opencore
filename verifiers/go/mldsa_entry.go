//go:build go1.27

package cryptovalid

import "crypto/mldsa"

// mldsaVerifyRaw: pure ML-DSA-65 with the empty context over msg (Go >= 1.27, standard library).
func mldsaVerifyRaw(pkRaw, msg, sig []byte) bool {
	pub, err := mldsa.NewPublicKey(mldsa.MLDSA65(), pkRaw)
	if err != nil {
		return false
	}
	return mldsa.Verify(pub, msg, sig, nil) == nil
}
