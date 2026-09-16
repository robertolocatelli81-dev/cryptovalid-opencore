//go:build !go1.27

package cryptovalid

// No crypto/mldsa before Go 1.27: never called (PQSupported is false), kept so the package builds.
func mldsaVerifyRaw(pkRaw, msg, sig []byte) bool { return false }
