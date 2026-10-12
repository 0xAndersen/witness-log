package witnesslog

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
)

// bucketSize is the padding bucket of SPEC.md §8.
const bucketSize = 256

// BucketPad is SPEC.md §8: len(payload) as u64 BE || payload || zero
// padding to (floor(len/256)+1)*256 bytes, so the output is 264, 520, 776
// ... bytes long.
func BucketPad(payload []byte) []byte {
	target := (len(payload)/bucketSize + 1) * bucketSize
	out := make([]byte, 0, target+8)
	out = putU64(out, uint64(len(payload)))
	out = append(out, payload...)
	for len(out) < target+8 {
		out = append(out, 0)
	}
	return out
}

// PayloadHash is SPEC.md §8: SHA256(bucket_pad(payload) || salt || leaf_index as u64 BE).
func PayloadHash(payload []byte, salt [32]byte, leafIndex uint64) Hash {
	h := sha256.New()
	h.Write(BucketPad(payload))
	h.Write(salt[:])
	h.Write(putU64(nil, leafIndex))
	var out Hash
	copy(out[:], h.Sum(nil))
	return out
}

// ErrDisclosureMismatch is returned when a disclosed payload and salt do
// not reproduce the leaf's committed payload_hash.
var ErrDisclosureMismatch = errors.New("disclosed payload and salt do not reproduce the leaf's payload_hash")

// VerifyDisclosure checks a selective disclosure: given a leaf from a
// verified dossier, the raw payload the log's operator claims it recorded,
// and the per-leaf salt, it recomputes SPEC.md §8's payload_hash with the
// leaf's own index and compares it to the committed value. A match proves
// this payload is what the leaf committed to; the leaf's place in the
// signed tree is what VerifyDossier establishes.
func VerifyDisclosure(leaf *Leaf, payload []byte, salt []byte) error {
	if len(salt) != 32 {
		return fmt.Errorf("salt must be 32 bytes, got %d", len(salt))
	}
	var s [32]byte
	copy(s[:], salt)
	got := PayloadHash(payload, s, leaf.Index)
	if hex.EncodeToString(got[:]) != leaf.PayloadHash {
		return fmt.Errorf("%w (leaf %d: committed %s, recomputed %s)", ErrDisclosureMismatch, leaf.Index, leaf.PayloadHash, hex.EncodeToString(got[:]))
	}
	return nil
}
