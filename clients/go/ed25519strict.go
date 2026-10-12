package witnesslog

import (
	"crypto/ed25519"
	"math/big"
)

// SPEC.md §6 requires strict Ed25519 verification: canonical scalars per
// RFC 8032 and rejection of signatures whose R or public key A is a
// small-order point (the profile of ed25519-dalek's verify_strict).
//
// crypto/ed25519 already rejects a non-canonical S and an undecodable A or
// R, and compares the recomputed R against the signature's R bytes (so a
// non-canonical encoding of R is also rejected, which is at least as
// strict as the reference). What it does not do is reject small-order
// points. A point is small-order exactly when its y-coordinate, after
// reduction modulo p, is one of five values: 0, 1, p-1 and the two
// y-coordinates of the order-8 points. Both decoders accept y in [p, 2^255)
// as y-p, so the reduction here mirrors what the point decoder would do.
// Honestly generated signatures never have small-order components.

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
