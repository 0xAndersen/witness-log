package witnesslog

import (
	"crypto/ed25519"
	"math/big"
)

// SPEC.md §6 requires strict Ed25519 verification: canonical scalars per
// RFC 8032 and rejection of signatures whose R or public key A is a
// small-order point (the profile of ed25519-dalek's verify_strict, which
// does not refuse mixed-order points, so neither does this).
//
// crypto/ed25519 already rejects a non-canonical S and an undecodable A,
// and compares the recomputed R against the signature's R bytes (so a
// non-canonical or undecodable R never verifies, as in the reference,
// which compares encodings too). What it does not do is reject small-order
// points. A point is small-order exactly when its y-coordinate, after
// reduction modulo p, is one of five values: 0, 1, p-1 and the two
// y-coordinates of the order-8 points. Both decoders accept y in [p, 2^255)
// as y-p and x = 0 with the sign bit set, so the reduction here mirrors what
// the point decoder would do. corpus/16_ed25519_strict.json holds all
// fourteen encodings of small-order points, as A and as R, with the
// reference's answers. Honestly generated signatures never have
// small-order components.

var (
	fieldP          = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 255), big.NewInt(19))
	smallOrderYVals []*big.Int
)

func init() {
	y8 := leBytesToInt(mustHex("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a"))
	pMinus1 := new(big.Int).Sub(fieldP, big.NewInt(1))
	pMinusY8 := new(big.Int).Sub(fieldP, y8)
	smallOrderYVals = []*big.Int{big.NewInt(0), big.NewInt(1), pMinus1, y8, pMinusY8}
}

func leBytesToInt(b []byte) *big.Int {
	be := make([]byte, len(b))
	for i := range b {
		be[len(b)-1-i] = b[i]
	}
	return new(big.Int).SetBytes(be)
}

// isSmallOrderEncoding reports whether a 32-byte compressed Edwards point
// encoding, if it decodes at all, decodes to a point of order 1, 2, 4 or 8.
func isSmallOrderEncoding(enc []byte) bool {
	if len(enc) != 32 {
		return false
	}
	y := make([]byte, 32)
	copy(y, enc)
	y[31] &= 0x7f
	v := leBytesToInt(y)
	if v.Cmp(fieldP) >= 0 {
		v.Sub(v, fieldP)
	}
	for _, s := range smallOrderYVals {
		if v.Cmp(s) == 0 {
			return true
		}
	}
	return false
}

// curveD is edwards25519's d = -121665/121666 mod p.
var curveD = func() *big.Int {
	inv := new(big.Int).ModInverse(big.NewInt(121666), fieldP)
	d := new(big.Int).Sub(fieldP, big.NewInt(121665))
	return d.Mul(d, inv).Mod(d, fieldP)
}()

// decodesAsPoint reports whether 32 bytes decode as an edwards25519 point
// the way ed25519-dalek's VerifyingKey::from_bytes (and crypto/ed25519)
// decode one: y is the low 255 bits read mod p, and a point exists when
// x^2 = (y^2 - 1)/(d*y^2 + 1) has a square root (the sign bit, x = 0
// included, is accepted). The reference refuses a key binding whose session
// key does not decode, though the session key signs nothing in it
// (corpus/16_ed25519_strict.json).
func decodesAsPoint(enc []byte) bool {
	if len(enc) != 32 {
		return false
	}
	b := make([]byte, 32)
	copy(b, enc)
	b[31] &= 0x7f
	y := leBytesToInt(b)
	y.Mod(y, fieldP)
	y2 := new(big.Int).Mul(y, y)
	y2.Mod(y2, fieldP)
	u := new(big.Int).Sub(y2, big.NewInt(1))
	u.Mod(u, fieldP)
	v := new(big.Int).Mul(curveD, y2)
	v.Add(v, big.NewInt(1)).Mod(v, fieldP)
	w := new(big.Int).ModInverse(v, fieldP)
	if w == nil {
		return false
	}
	w.Mul(w, u).Mod(w, fieldP)
	return w.Sign() == 0 || big.Jacobi(w, fieldP) == 1
}

// VerifyStrict verifies an Ed25519 signature under SPEC.md §6's strict
// profile. pub must be 32 bytes and sig 64 bytes.
func VerifyStrict(pub, msg, sig []byte) bool {
	if len(pub) != ed25519.PublicKeySize || len(sig) != ed25519.SignatureSize {
		return false
	}
	if isSmallOrderEncoding(pub) || isSmallOrderEncoding(sig[:32]) {
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(pub), msg, sig)
}
