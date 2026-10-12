package witnesslog

import (
	"crypto/sha256"
	"math/bits"
)

// Hash is a SHA-256 digest.
type Hash = [32]byte

// LeafHash is RFC 6962 §2.1: SHA256(0x00 || data).
func LeafHash(data []byte) Hash {
	h := sha256.New()
	h.Write([]byte{0x00})
	h.Write(data)
	var out Hash
	copy(out[:], h.Sum(nil))
	return out
}

// NodeHash is RFC 6962 §2.1: SHA256(0x01 || left || right).
func NodeHash(left, right Hash) Hash {
	h := sha256.New()
	h.Write([]byte{0x01})
	h.Write(left[:])
	h.Write(right[:])
	var out Hash
	copy(out[:], h.Sum(nil))
	return out
}

// EmptyRoot is the root of the empty tree, SHA256("").
func EmptyRoot() Hash {
	return sha256.Sum256(nil)
}

// largestPowerOfTwoLT returns the largest power of two strictly less than n
// (n >= 2).
func largestPowerOfTwoLT(n uint64) uint64 {
	return uint64(1) << (bits.Len64(n-1) - 1)
}

// MerkleRoot computes the RFC 6962 root of a slice of leaf hashes.
func MerkleRoot(leaves []Hash) Hash {
	switch len(leaves) {
	case 0:
		return EmptyRoot()
	case 1:
		return leaves[0]
	}
	k := largestPowerOfTwoLT(uint64(len(leaves)))
	return NodeHash(MerkleRoot(leaves[:k]), MerkleRoot(leaves[k:]))
}

// InclusionProof is RFC 6962 §2.1.1 PATH(m, D[n]) for leaf m of the tree
// over leaves, ordered innermost sibling first (the order the corpus and
// the reference implementation use). It returns nil when m >= n.
func InclusionProof(leaves []Hash, m uint64) []Hash {
	n := uint64(len(leaves))
	if m >= n {
		return nil
	}
	return path(leaves, m)
}

func path(leaves []Hash, m uint64) []Hash {
	n := uint64(len(leaves))
	if n <= 1 {
		return []Hash{}
	}
	k := largestPowerOfTwoLT(n)
	if m < k {
		return append(path(leaves[:k], m), MerkleRoot(leaves[k:]))
	}
	return append(path(leaves[k:], m-k), MerkleRoot(leaves[:k]))
}

// VerifyInclusion checks an RFC 6962 inclusion proof for leaf at
// leafIndex in a tree of treeSize leaves with the given root. The proof is
// innermost sibling first and must be consumed exactly.
func VerifyInclusion(leaf Hash, leafIndex, treeSize uint64, proof []Hash, root Hash) bool {
	if leafIndex >= treeSize {
		return false
	}
	got, rest, ok := verifyPath(leaf, leafIndex, treeSize, proof)
	return ok && len(rest) == 0 && got == root
}

// verifyPath peels the outermost sibling off the END of proof at each
// level, mirroring the construction in path.
func verifyPath(h Hash, index, size uint64, proof []Hash) (Hash, []Hash, bool) {
	if size <= 1 {
		return h, proof, true
	}
	if len(proof) == 0 {
		return h, nil, false
	}
	k := largestPowerOfTwoLT(size)
	sibling := proof[len(proof)-1]
	rest := proof[:len(proof)-1]
	if index < k {
		sub, remaining, ok := verifyPath(h, index, k, rest)
		if !ok {
			return h, nil, false
		}
		return NodeHash(sub, sibling), remaining, true
	}
	sub, remaining, ok := verifyPath(h, index-k, size-k, rest)
	if !ok {
		return h, nil, false
	}
	return NodeHash(sibling, sub), remaining, true
}

// ConsistencyProof is RFC 6962 §2.1.2 PROOF(m, D[n]) between the tree of
// the first m leaves and the tree over all leaves. It returns nil when
// m > n; the proof for m == 0 or m == n is empty.
func ConsistencyProof(leaves []Hash, m uint64) []Hash {
	n := uint64(len(leaves))
	if m > n {
		return nil
	}
	if m == 0 || m == n {
		return []Hash{}
	}
	return subproof(leaves, m, true)
}

func subproof(leaves []Hash, m uint64, isComplete bool) []Hash {
	n := uint64(len(leaves))
	if m == n {
		if isComplete {
			return []Hash{}
		}
		return []Hash{MerkleRoot(leaves)}
	}
	k := largestPowerOfTwoLT(n)
	if m <= k {
		return append(subproof(leaves[:k], m, isComplete), MerkleRoot(leaves[k:]))
	}
	return append(subproof(leaves[k:], m-k, false), MerkleRoot(leaves[:k]))
}

// VerifyConsistency is the RFC 9162 §2.1.4.2 algorithm: it reconstructs
// BOTH roots from the proof and requires both to match and the proof to be
// fully consumed. Reconstructing only the second root accepts forks.
func VerifyConsistency(first uint64, firstRoot Hash, second uint64, secondRoot Hash, proof []Hash) bool {
	if first > second {
		return false
	}
	if first == 0 {
		return len(proof) == 0
	}
	if first == second {
		return len(proof) == 0 && firstRoot == secondRoot
	}
	var start Hash
	rest := proof
	if first&(first-1) == 0 {
		start = firstRoot
	} else {
		if len(rest) == 0 {
			return false
		}
		start = rest[0]
		rest = rest[1:]
	}
	fnode := first - 1
	snode := second - 1
	for fnode&1 == 1 {
		fnode >>= 1
		snode >>= 1
	}
	fr, sr := start, start
	for _, c := range rest {
		if snode == 0 {
			return false
		}
		if fnode&1 == 1 || fnode == snode {
			fr = NodeHash(c, fr)
			sr = NodeHash(c, sr)
			if fnode&1 == 0 {
				for fnode&1 == 0 && fnode != 0 {
					fnode >>= 1
					snode >>= 1
				}
			}
		} else {
			sr = NodeHash(sr, c)
		}
		fnode >>= 1
		snode >>= 1
	}
	return snode == 0 && fr == firstRoot && sr == secondRoot
}
