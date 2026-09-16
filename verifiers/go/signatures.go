package cryptovalid

// Per-entry signature verification (0.13.0): Ed25519 over the UTF-8 bytes of `self_hash` and, for hybrid ledgers,
// ML-DSA-65 over the same bytes (pure ML-DSA, EMPTY context — crypto/mldsa, Go >= 1.27; older toolchains report
// pq_unverifiable). The semantics mirror signer.py (the Python reference) exactly:
//   - the Ed25519 layer is verified against the key INSIDE the entry, and against `expectedPubkeyHex` when given;
//   - pq_protected is TRUE only when every entry carries a valid ML-DSA-65 signature by `expectedPQPubkeyB64`
//     AND the Ed25519 layer holds; NULL when present but unpinned / unverifiable; FALSE when absent, invalid,
//     foreign, malformed or partial. A pinned PQ key REQUIRES the layer (pq_missing); a PQ key needs the Ed25519
//     key (the caller must refuse the combination before calling, as the CLI does).
// The content hash is re-derived by VerifyLedger (content → self_hash → signature), so the chain verdict already
// binds the signed bytes to the content.

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"sort"
)

// SignatureCheck is the per-entry signature outcome, the same fields as signer.verify_ledger_signatures.
type SignatureCheck struct {
	OK          bool     `json:"ok"`
	Verified    int      `json:"verified"`
	Total       int      `json:"total"`
	Failures    []string `json:"failures"`
	Signers     []string `json:"signers"`
	PQProtected *bool    `json:"pq_protected"`
	PQStatus    string   `json:"pq_status"`
	PQVerified  int      `json:"pq_verified"`
	PQFailures  []string `json:"pq_failures"`
	PQSigners   []string `json:"pq_signers"`
	PQNote      string   `json:"pq_note"`
}

func isHexN64(s string) bool { return isHexN(s, 64) }

// VerifySignatures checks the attestation fields of every parsed entry. `entries` are the objects VerifyLedger
// parsed (in order); an entry that failed to parse is counted as a missing signature.
func VerifySignatures(entries []*Object, expectedPubkeyHex, expectedPQPubkeyB64 string, requirePQ bool) SignatureCheck {
	sc := SignatureCheck{Failures: []string{}, PQFailures: []string{}, Signers: []string{}, PQSigners: []string{}, Total: len(entries)}
	require := requirePQ || expectedPQPubkeyB64 != ""
	signers, pqSigners := map[string]bool{}, map[string]bool{}
	pqPresent, pqUnverifiable := 0, 0
	for i, e := range entries {
		if e == nil {
			sc.Failures = append(sc.Failures, fmt.Sprintf("idx %d: missing signature/signer/self_hash", i))
			continue
		}
		sig, _ := e.Vals["signature"].(string)
		signer, _ := e.Vals["signer"].(string)
		sh, _ := e.Vals["self_hash"].(string)
		if sig == "" || signer == "" || sh == "" {
			sc.Failures = append(sc.Failures, fmt.Sprintf("idx %d: missing signature/signer/self_hash", i))
			continue
		}
		if expectedPubkeyHex != "" && signer != expectedPubkeyHex {
			sc.Failures = append(sc.Failures, fmt.Sprintf("idx %d: signer_mismatch", i))
			continue
		}
		rawSig := decodeB64Strict(sig, 64)
		if rawSig == nil || !isHexN64(signer) {
			sc.Failures = append(sc.Failures, fmt.Sprintf("idx %d: malformed_signature_field", i))
			continue
		}
		pk, _ := hex.DecodeString(signer) // already validated: 64 lowercase hex
		if ed25519.Verify(ed25519.PublicKey(pk), []byte(sh), rawSig) {
			sc.Verified++
			signers[signer] = true
		} else {
			sc.Failures = append(sc.Failures, fmt.Sprintf("idx %d: bad_signature", i))
		}
		pqSigV, hasSig := e.Vals["signature_pq"]
		pqSignerV, hasSigner := e.Vals["signer_pq"]
		if !hasSig && !hasSigner {
			if require {
				sc.PQFailures = append(sc.PQFailures, fmt.Sprintf("idx %d: pq_missing", i))
			}
			continue
		}
		pqPresent++
		pqSig, ok1 := pqSigV.(string)
		pqSigner, ok2 := pqSignerV.(string)
		if !ok1 || !ok2 || pqSig == "" || pqSigner == "" {
			sc.PQFailures = append(sc.PQFailures, fmt.Sprintf("idx %d: missing signature_pq/signer_pq", i))
			continue
		}
		if expectedPQPubkeyB64 != "" && pqSigner != expectedPQPubkeyB64 {
			sc.PQFailures = append(sc.PQFailures, fmt.Sprintf("idx %d: pq_signer_mismatch", i))
			continue
		}
		rawPQSig, rawPQPk := decodeB64Strict(pqSig, 3309), decodeB64Strict(pqSigner, 1952)
		if rawPQSig == nil || rawPQPk == nil {
			sc.PQFailures = append(sc.PQFailures, fmt.Sprintf("idx %d: malformed_pq_field", i))
			continue
		}
		if !PQSupported {
			pqUnverifiable++
			if require {
				sc.PQFailures = append(sc.PQFailures, fmt.Sprintf("idx %d: pq_unverifiable", i))
			}
			continue
		}
		if mldsaVerifyRaw(rawPQPk, []byte(sh), rawPQSig) {
			sc.PQVerified++
			pqSigners[pqSigner] = true
		} else {
			sc.PQFailures = append(sc.PQFailures, fmt.Sprintf("idx %d: bad_pq_signature", i))
		}
	}
	for k := range signers {
		sc.Signers = append(sc.Signers, k)
	}
	for k := range pqSigners {
		sc.PQSigners = append(sc.PQSigners, k)
	}
	sort.Strings(sc.Signers) // deterministic output, as Python's sorted()
	sort.Strings(sc.PQSigners)
	f, t := false, true
	allUnverifiable := len(sc.PQFailures) > 0
	for _, x := range sc.PQFailures {
		if len(x) < 15 || x[len(x)-15:] != "pq_unverifiable" {
			allUnverifiable = false
		}
	}
	switch {
	case len(sc.PQFailures) > 0 && allUnverifiable:
		sc.PQProtected, sc.PQStatus = nil, "unverifiable"
		sc.PQNote = "post-quantum layer required but ML-DSA-65 cannot be verified here (Go < 1.27): not a pass"
	case len(sc.PQFailures) > 0:
		sc.PQProtected, sc.PQStatus = &f, "invalid"
		allMissing := true
		for _, x := range sc.PQFailures {
			if len(x) < 10 || x[len(x)-10:] != "pq_missing" {
				allMissing = false
			}
		}
		if allMissing {
			sc.PQStatus = "missing"
			sc.PQNote = "post-quantum layer required but absent on some entries (stripped or never signed)"
		} else {
			sc.PQNote = "post-quantum layer invalid, foreign or malformed on some entries"
		}
	case pqPresent == 0:
		sc.PQProtected, sc.PQStatus = &f, "absent"
		sc.PQNote = "no post-quantum signatures (Ed25519 only: not quantum-resistant, NIST IR 8547 draft)"
	case pqUnverifiable > 0:
		sc.PQProtected, sc.PQStatus = nil, "unverifiable"
		sc.PQNote = "ML-DSA-65 signatures present but NOT verified (this verifier was built with Go < 1.27)"
	case sc.PQVerified != len(entries) || len(entries) == 0:
		sc.PQProtected, sc.PQStatus = &f, "partial"
		sc.PQNote = "post-quantum signatures on some entries only: not a protected ledger"
	case len(sc.Failures) > 0:
		sc.PQProtected, sc.PQStatus = &f, "classical_broken"
		sc.PQNote = "ML-DSA-65 signatures valid but an Ed25519 signature is not: hybrid means BOTH hold"
	case expectedPQPubkeyB64 == "":
		sc.PQProtected, sc.PQStatus = nil, "unpinned"
		sc.PQNote = "ML-DSA-65 signatures verified against the EMBEDDED key only (anyone can add their own): pass -pq-pubkey to pin"
	default:
		sc.PQProtected, sc.PQStatus = &t, "protected"
		sc.PQNote = "hybrid: every entry carries a valid ML-DSA-65 (FIPS 204) signature by the expected key, besides Ed25519"
	}
	sc.OK = len(sc.Failures) == 0 && sc.Verified == len(entries) && len(entries) > 0 && len(sc.PQFailures) == 0
	return sc
}
