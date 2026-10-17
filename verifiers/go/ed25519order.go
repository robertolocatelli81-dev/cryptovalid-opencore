package cryptovalid

// Ed25519 points of small and mixed order (0.21.0). crypto/ed25519 implements RFC 8032 5.1.7 with the cofactorless
// equation and accepts a public key or an R of small order, a public key of mixed order, and a public key whose x is 0
// with the sign bit set: measured 14/10/2026 on the 12 classes of novifinancial/ed25519-speccheck rebuilt on ledger
// entries (classes 0-3, 10, 11 verified). The x402 acceptance checker refuses all 12 (b37e471, sentences 4 and 9);
// these checks align the verifiers with it:
//   - the public key decodes as RFC 8032 5.1.3 says (y < p; x = 0 with the sign bit set refused), is not of small
//     order ([8]A is not the neutral point) and lies in the subgroup of order L ([L]A is the neutral point);
//   - R decodes the same way and is not of small order. R of mixed order needs no check here: with A in the subgroup,
//     S*B = R + k*A puts R in it too, so the cofactorless equation the library checks refuses such an R.
// The key check is one scalar multiplication per distinct key (cached by the caller); the R check is three doublings.
// math/big: not constant time (public values only).

import (
	"crypto/ed25519"
	"math/big"
)

func ed25519Verify(pk, msg, sig []byte) bool { return ed25519.Verify(ed25519.PublicKey(pk), msg, sig) }

var (
	edP = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 255), big.NewInt(19))
	edL = func() *big.Int {
		l, _ := new(big.Int).SetString("27742317777372353535851937790883648493", 10)
		return l.Add(l, new(big.Int).Lsh(big.NewInt(1), 252))
	}()
	edD = func() *big.Int {
		d := new(big.Int).ModInverse(big.NewInt(121666), edP)
		d.Mul(d, big.NewInt(-121665))
		return d.Mod(d, edP)
	}()
	edI  = new(big.Int).Exp(big.NewInt(2), new(big.Int).Rsh(new(big.Int).Sub(edP, big.NewInt(1)), 2), edP)
	edE1 = new(big.Int).Rsh(new(big.Int).Sub(edP, big.NewInt(5)), 3)
)

type edPoint struct{ x, y, z, t *big.Int }

func edMod(a *big.Int) *big.Int    { return a.Mod(a, edP) }
func edMul(a, b *big.Int) *big.Int { return edMod(new(big.Int).Mul(a, b)) }

// edDecode: RFC 8032 5.1.3; nil when the 32 octets are not a point.
func edDecode(b []byte) *edPoint {
	if len(b) != 32 {
		return nil
	}
	le := make([]byte, 32)
	for i := range b {
		le[31-i] = b[i]
	}
	n := new(big.Int).SetBytes(le)
	x0 := n.Bit(255)
	y := new(big.Int).SetBit(n, 255, 0)
	if y.Cmp(edP) >= 0 {
		return nil
	}
	yy := edMul(y, y)
	u := edMod(new(big.Int).Sub(yy, big.NewInt(1)))
	v := edMod(new(big.Int).Add(edMul(edD, yy), big.NewInt(1)))
	v3 := edMul(edMul(v, v), v)
	v7 := edMul(edMul(v3, v3), v)
	x := edMul(edMul(u, v3), new(big.Int).Exp(edMul(u, v7), edE1, edP))
	vxx := edMul(v, edMul(x, x))
	switch {
	case vxx.Cmp(u) == 0:
	case vxx.Cmp(edMod(new(big.Int).Neg(u))) == 0:
		x = edMul(x, edI)
	default:
		return nil
	}
	if x.Sign() == 0 && x0 == 1 {
		return nil
	}
	if x.Bit(0) != x0 {
		x = new(big.Int).Sub(edP, x)
	}
	return &edPoint{x, y, big.NewInt(1), edMul(x, y)}
}

func edAdd(p, q *edPoint) *edPoint { // RFC 8032 5.1.4
	a := edMul(edMod(new(big.Int).Sub(p.y, p.x)), edMod(new(big.Int).Sub(q.y, q.x)))
	b := edMul(new(big.Int).Add(p.y, p.x), new(big.Int).Add(q.y, q.x))
	c := edMul(edMul(edMul(p.t, big.NewInt(2)), edD), q.t)
	d := edMul(edMul(p.z, big.NewInt(2)), q.z)
	e, f := edMod(new(big.Int).Sub(b, a)), edMod(new(big.Int).Sub(d, c))
	g, h := edMod(new(big.Int).Add(d, c)), edMod(new(big.Int).Add(b, a))
	return &edPoint{edMul(e, f), edMul(g, h), edMul(f, g), edMul(e, h)}
}

func edScalar(k *big.Int, p *edPoint) *edPoint {
	r := &edPoint{big.NewInt(0), big.NewInt(1), big.NewInt(1), big.NewInt(0)}
	for i := k.BitLen() - 1; i >= 0; i-- {
		r = edAdd(r, r)
		if k.Bit(i) == 1 {
			r = edAdd(r, p)
		}
	}
	return r
}

// edNeutral: X = 0 and Y = Z in projective coordinates.
func edNeutral(p *edPoint) bool { return p.x.Sign() == 0 && p.y.Cmp(p.z) == 0 }

// Ed25519KeyProblem: "" when the 32-octet key is usable; else not_decodable, small_order or mixed_order.
func Ed25519KeyProblem(pk []byte) string {
	a := edDecode(pk)
	if a == nil {
		return "key_not_decodable"
	}
	if edNeutral(edScalar(big.NewInt(8), a)) {
		return "small_order_key"
	}
	if !edNeutral(edScalar(edL, a)) {
		return "mixed_order_key"
	}
	return ""
}

// Ed25519RProblem: "" when R (the first 32 octets of a signature) decodes and is not of small order.
func Ed25519RProblem(sig []byte) string {
	if len(sig) != 64 {
		return "r_not_decodable"
	}
	r := edDecode(sig[:32])
	if r == nil {
		return "r_not_decodable"
	}
	if edNeutral(edScalar(big.NewInt(8), r)) {
		return "small_order_r"
	}
	return ""
}

// ed25519Strict is crypto/ed25519.Verify behind the two checks above; keyCache memoises Ed25519KeyProblem by key.
func ed25519Strict(pk, msg, sig []byte, keyCache map[string]string) (bool, string) {
	kp, seen := keyCache[string(pk)]
	if !seen {
		kp = Ed25519KeyProblem(pk)
		if keyCache != nil {
			keyCache[string(pk)] = kp
		}
	}
	if kp != "" {
		return false, kp
	}
	if rp := Ed25519RProblem(sig); rp != "" {
		return false, rp
	}
	if !ed25519Verify(pk, msg, sig) {
		return false, "bad_signature"
	}
	return true, ""
}
