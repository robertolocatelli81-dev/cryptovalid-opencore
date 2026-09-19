// cvnote-oracle — INDEPENDENT verifier of cryptovalid checkpoint notes (added 2026-09-19, release 0.14.0).
//
// It contains no cryptovalid code: the note is opened with golang.org/x/mod/sumdb/note (the Go module
// checksum database / Sigstore implementation of c2sp.org/signed-note, Ed25519 type 0x01) and the witness
// cosignatures with github.com/transparency-dev/formats/note (c2sp.org/tlog-cosignature, Ed25519 cosignature/v1).
// Log keys may be Ed25519 (x/mod) or ECDSA (formats, the type Rekor v1 uses); cosigners Ed25519 or ML-DSA-44 (formats).
// If this program says VERIFIED, the note produced by cryptovalid_checkpoint.py / cryptovalid_witness.py is a
// standard checkpoint that the transparency ecosystem's own libraries accept — that is the whole point of it.
//
//	usage: cvnote-oracle <note-file> <log-vkey> [cosigner-vkey...]
//	exit 0 = every listed key verified (unverified signatures from unknown keys are counted, not accepted);
//	exit 1 = the note does not open (bad signature from a known key, or no known key signed it).
package main

import (
	"encoding/base64"
	"fmt"
	"os"
	"strings"

	tdnote "github.com/transparency-dev/formats/note"
	"golang.org/x/mod/sumdb/note"
)

// keyType reads the signature-type byte of a vkey (the first byte of its base64 material).
func keyType(vkey string) byte {
	parts := strings.SplitN(vkey, "+", 3)
	if len(parts) != 3 {
		return 0
	}
	b, err := base64.StdEncoding.DecodeString(parts[2])
	if err != nil || len(b) == 0 {
		return 0
	}
	return b[0]
}

// logVerifier: Ed25519 (0x01) through golang.org/x/mod/sumdb/note, ECDSA (0x02, Rekor v1) through transparency-dev/formats.
func logVerifier(vkey string) (note.Verifier, error) {
	if keyType(vkey) == 0x02 {
		return tdnote.NewECDSAVerifier(vkey)
	}
	return note.NewVerifier(vkey)
}

// cosignerVerifier: Ed25519 cosignature/v1 (0x04) or ML-DSA-44 cosignature/v1 (0x06), both from transparency-dev/formats.
func cosignerVerifier(vkey string) (note.Verifier, error) {
	if keyType(vkey) == 0x06 {
		return tdnote.NewMLDSAVerifier(vkey)
	}
	return tdnote.NewVerifierForCosignatureV1(vkey)
}

func main() {
	if len(os.Args) < 3 {
		fmt.Println("usage: cvnote-oracle <note-file> <log-vkey> [cosigner-vkey...]")
		os.Exit(2)
	}
	msg, err := os.ReadFile(os.Args[1])
	if err != nil {
		fmt.Println("READ ERROR:", err)
		os.Exit(2)
	}
	var verifiers []note.Verifier
	v, err := logVerifier(os.Args[2])
	if err != nil {
		fmt.Println("LOG VKEY ERROR:", err)
		os.Exit(2)
	}
	verifiers = append(verifiers, v)
	for _, cv := range os.Args[3:] {
		w, err := cosignerVerifier(cv)
		if err != nil {
			fmt.Println("COSIGNER VKEY ERROR:", err)
			os.Exit(2)
		}
		verifiers = append(verifiers, w)
	}
	n, err := note.Open(msg, note.VerifierList(verifiers...))
	if err != nil {
		fmt.Println("OPEN ERROR:", err)
		os.Exit(1)
	}
	// every key the caller listed must have signed: a missing cosigner is a failure, not a partial success
	for _, ver := range verifiers {
		found := false
		for _, s := range n.Sigs {
			if s.Name == ver.Name() && s.Hash == ver.KeyHash() {
				found = true
			}
		}
		if !found {
			fmt.Printf("MISSING SIGNATURE from %s\n", ver.Name())
			os.Exit(1)
		}
	}
	fmt.Printf("VERIFIED sigs=%d unverified=%d\n", len(n.Sigs), len(n.UnverifiedSigs))
	for _, s := range n.Sigs {
		fmt.Printf("  sig by %s hash=%08x\n", s.Name, s.Hash)
	}
	fmt.Print("TEXT:\n", n.Text)
}
