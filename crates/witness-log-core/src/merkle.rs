//! Append-only Merkle tree following the RFC 6962 (Certificate Transparency)
//! construction: domain-separated leaf/interior-node hashing prevents the
//! classic second-preimage attack where an interior node hash is replayed
//! as a leaf hash. This is deliberately the same construction CT logs use —
//! see SPEC.md for why we borrow it rather than inventing a new one.

use sha2::{Digest, Sha256};

const LEAF_PREFIX: u8 = 0x00;
const NODE_PREFIX: u8 = 0x01;

pub type Hash = [u8; 32];

pub fn leaf_hash(leaf_bytes: &[u8]) -> Hash {
    let mut hasher = Sha256::new();
    hasher.update([LEAF_PREFIX]);
    hasher.update(leaf_bytes);
    hasher.finalize().into()
}

fn node_hash(left: &Hash, right: &Hash) -> Hash {
    let mut hasher = Sha256::new();
    hasher.update([NODE_PREFIX]);
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

/// An append-only log of leaf hashes with RFC 6962 root computation and
/// inclusion-proof generation/verification.
/// An append-only RFC 6962 Merkle tree.
///
/// Maintains an incremental "right spine": the perfect-subtree roots
/// covering all appended leaves, largest first. Appending folds the new
/// leaf into that spine in O(1) amortized time, and `root()` combines the
/// spine in O(log n).
///
/// The previous implementation stored only leaf hashes and recomputed the
/// entire tree on every `root()` call — O(n) hashes per checkpoint, so a
/// log that checkpoints once per leaf did O(n²) total work. At a million
/// leaves that is roughly a million SHA-256 operations per checkpoint,
/// blocking, inside whatever process embedded this library. For
/// infrastructure whose core promise is not to affect the system it's
/// integrated into, that was disqualifying.
///
/// Leaf hashes are still retained because inclusion and consistency
/// proofs need them; the spine is an additional index, not a replacement.
/// See `spine` for the invariant it maintains.
#[derive(Debug, Default, Clone)]
pub struct MerkleTree {
    leaves: Vec<Hash>,
    /// Perfect-subtree roots covering `leaves`, ordered largest subtree
    /// first. For a tree of size n, this holds exactly one entry per set
    /// bit in n's binary representation — so at most log2(n)+1 entries,
    /// and its shape is determined entirely by n.
    ///
    /// Example at n = 11 (binary 1011): subtrees of size 8, 2, and 1.
    spine: Vec<Hash>,
}

impl MerkleTree {
    pub fn new() -> Self {
        Self {
            leaves: Vec::new(),
            spine: Vec::new(),
        }
    }

    pub fn size(&self) -> u64 {
        self.leaves.len() as u64
    }

    /// Append a leaf hash. Returns its index. O(1) amortized.
    ///
    /// Cannot panic: the spine-merge loop breaks rather than unwrapping
    /// if the spine were ever shorter than the carry chain expects. That
    /// case is unreachable given the invariant, but "unreachable" and
    /// "cannot crash the host process" are different guarantees, and
    /// this crate promises the second one — see the crate-level docs on
    /// the no-panic contract.
    pub fn append(&mut self, hash: Hash) -> u64 {
        self.leaves.push(hash);
        let n = self.leaves.len();

        // Fold the new leaf into the spine. A new leaf starts as a
        // size-1 perfect subtree; it merges with the trailing spine
        // entry whenever that entry covers an equal-sized subtree. The
        // number of merges equals the number of trailing 1-bits in
        // (n - 1), which averages under 1 across appends -- hence O(1)
        // amortized, matching the classic binary-counter argument.
        let mut carry = hash;
        let mut merged_size = 1usize;
        let already_present = n - 1;
        while already_present % (merged_size * 2) >= merged_size {
            let Some(left) = self.spine.pop() else {
                // Unreachable while the invariant holds. If it somehow
                // doesn't, stop merging and keep what we have rather
                // than aborting the caller's process.
                break;
            };
            carry = node_hash(&left, &carry);
            merged_size *= 2;
        }
        self.spine.push(carry);
        (n - 1) as u64
    }

    /// RFC 6962 §2.1 root computation (MTH). The empty tree's root is
    /// SHA-256 of the empty string. O(log n) via the maintained spine.
    ///
    /// Cannot panic.
    pub fn root(&self) -> Hash {
        // Combine right-to-left: the spine holds perfect subtrees
        // largest-first, and RFC 6962 splits at the largest power of
        // two, so the smallest subtrees nest deepest on the right.
        let mut iter = self.spine.iter().rev();
        match iter.next() {
            None => Sha256::new().finalize().into(),
            Some(&smallest) => {
                let mut acc = smallest;
                for left in iter {
                    acc = node_hash(left, &acc);
                }
                acc
            }
        }
    }

    fn subtree_hash(leaves: &[Hash]) -> Hash {
        // Match on the slice shape rather than on its length and then
        // indexing: the single-leaf case binds the leaf directly, so
        // there is no index to get wrong and no panic path.
        match leaves {
            [] => {
                let hasher = Sha256::new();
                hasher.finalize().into()
            }
            [only] => *only,
            _ => {
                // Split at the largest power of two strictly less than n.
                let n = leaves.len();
                let k = largest_power_of_two_lt(n);
                let (left, right) = leaves.split_at(k);
                node_hash(&Self::subtree_hash(left), &Self::subtree_hash(right))
            }
        }
    }

    /// RFC 6962 §2.1.1 inclusion proof: the audit path from `leaf_index` up
    /// to the root of the first `tree_size` leaves.
    pub fn inclusion_proof(&self, leaf_index: u64, tree_size: u64) -> Option<Vec<Hash>> {
        let tree_size_usize = usize::try_from(tree_size).ok()?;
        let leaves = self.leaves.get(0..tree_size_usize)?;
        if leaf_index >= tree_size {
            return None;
        }
        let leaf_index_usize = usize::try_from(leaf_index).ok()?;
        Some(Self::path(leaves, leaf_index_usize))
    }

    fn path(leaves: &[Hash], index: usize) -> Vec<Hash> {
        if leaves.len() <= 1 {
            return Vec::new();
        }
        let k = largest_power_of_two_lt(leaves.len());
        let (left, right) = leaves.split_at(k);
        if index < k {
            let mut proof = Self::path(left, index);
            proof.push(Self::subtree_hash(right));
            proof
        } else {
            let mut proof = Self::path(right, index - k);
            proof.push(Self::subtree_hash(left));
            proof
        }
    }

    /// RFC 6962 §2.1.2 consistency proof: demonstrates that the tree of
    /// `second` leaves is a pure append-only extension of the tree of
    /// `first` leaves — nothing before position `first` was altered,
    /// reordered, or removed. This is the check an automated witness
    /// (human-operated or agent-operated) runs on *every* new checkpoint
    /// against the last one it signed, so it never has to take "this is a
    /// valid continuation" on faith.
    pub fn consistency_proof(&self, first: u64, second: u64) -> Option<Vec<Hash>> {
        if first > second || second > self.size() {
            return None;
        }
        if first == 0 || first == second {
            return Some(Vec::new());
        }
        let second_usize = usize::try_from(second).ok()?;
        let leaves = self.leaves.get(0..second_usize)?;
        let first_usize = usize::try_from(first).ok()?;
        Some(Self::subproof(leaves, first_usize, true))
    }

    /// Mirrors `path()`'s recursive shape. `b` tracks whether the current
    /// subtree, if it turns out to exactly equal the old tree (`m == n`),
    /// is *the* old tree (`b == true`, needs no commitment — the verifier
    /// already has old_root) or an unrelated same-sized subtree elsewhere
    /// in the new tree (`b == false`, needs its hash committed explicitly).
    fn subproof(leaves: &[Hash], m: usize, b: bool) -> Vec<Hash> {
        let n = leaves.len();
        if m == n {
            if b {
                Vec::new()
            } else {
                vec![Self::subtree_hash(leaves)]
            }
        } else {
            let k = largest_power_of_two_lt(n);
            if m <= k {
                let (left, right) = leaves.split_at(k);
                let mut proof = Self::subproof(left, m, b);
                proof.push(Self::subtree_hash(right));
                proof
            } else {
                let (left, right) = leaves.split_at(k);
                let mut proof = Self::subproof(right, m - k, false);
                proof.push(Self::subtree_hash(left));
                proof
            }
        }
    }
}

/// Verify an inclusion proof against a known root, without needing the
/// full tree. This is what a third party runs offline.
pub fn verify_inclusion(
    leaf: &Hash,
    leaf_index: u64,
    tree_size: u64,
    proof: &[Hash],
    root: &Hash,
) -> bool {
    // RFC 9162 §2.1.3.2 step 1: an index outside the tree never verifies.
    // Without this, the proof for the last leaf also "verified" for any
    // larger index, since the path only looks at the index's bits below
    // the tree size (found by the final pre-publish review).
    if leaf_index >= tree_size {
        return false;
    }
    verify_path(leaf, leaf_index, tree_size, proof) == Some(*root)
}

fn verify_path(leaf: &Hash, index: u64, size: u64, proof: &[Hash]) -> Option<Hash> {
    // `proof` is built leaf-ward-first (see `path()`): index 0 is the
    // deepest/innermost sibling, the last element is the outermost
    // (root-level) sibling. Each recursive step here peels the *last*
    // element off first, since the top-level call corresponds to the
    // root-level split, which needs the outermost sibling.
    fn go(hash: Hash, index: u64, size: u64, proof: &[Hash]) -> Option<(Hash, &[Hash])> {
        if size <= 1 {
            return Some((hash, proof));
        }
        let k = largest_power_of_two_lt_u64(size);
        let (sibling, rest) = proof.split_last()?;
        if index < k {
            let (sub, remaining) = go(hash, index, k, rest)?;
            Some((node_hash(&sub, sibling), remaining))
        } else {
            let (sub, remaining) = go(hash, index - k, size - k, rest)?;
            Some((node_hash(sibling, &sub), remaining))
        }
    }
    let (root, remaining) = go(*leaf, index, size, proof)?;
    // Require the proof slice to be fully consumed. Elements are peeled
    // off the END of the slice each recursive step, so unconsumed extra
    // elements PREPENDED to a valid proof were never read -- `go`
    // returned as soon as `size <= 1` regardless of whether `proof` still
    // had leftover elements at the front. That made inclusion proofs
    // malleable: infinitely many distinct proofs verified for the same
    // statement, breaking proof canonicity. The equivalent trailing-
    // element case already had a test and already failed correctly (the
    // recursion's own out-of-elements case handles that direction); this
    // is the direction that didn't. See the pre-launch review, finding 13.
    if remaining.is_empty() {
        Some(root)
    } else {
        None
    }
}

fn largest_power_of_two_lt(n: usize) -> usize {
    debug_assert!(n > 1);
    let mut k = 1;
    while k * 2 < n {
        k *= 2;
    }
    k
}

/// Same computation as `largest_power_of_two_lt`, but entirely in `u64`.
/// Used ONLY by the offline proof verifiers (`verify_path`,
/// `verify_subproof`), which take a caller-supplied, potentially
/// attacker-controlled `size`/`n: u64` with no real slice backing it to
/// naturally bound the value. Casting that value through `as usize`
/// truncates on any 32-bit target (wasm32, armv7, embedded witnesses):
/// a claimed tree_size of 2^32+8 becomes 8, silently changing the proof
/// geometry the recursion checks against and forging both inclusion and
/// consistency proofs at negligible cost. CI here only builds 64-bit
/// hosts, so this was never caught by CI itself. See the pre-launch
/// review, finding 16.
fn largest_power_of_two_lt_u64(n: u64) -> u64 {
    debug_assert!(n > 1);
    let mut k: u64 = 1;
    while k * 2 < n {
        k *= 2;
    }
    k
}

/// Verify a consistency proof between two checkpoints, fully offline: no
/// access to the tree, only the two roots and the proof. This is the exact
/// call an automated witness makes before signing a new receipt — refusing
/// to sign if this returns `false` is what makes witnessing meaningful
/// rather than decorative.
///
/// Implements RFC 9162 §2.1.4.2, which reconstructs BOTH the old and the
/// new root from the proof and requires both to match. Proofs are RFC 6962
/// `PROOF(m, D[n])`, the format `MerkleTree::consistency_proof` emits and
/// C2SP `tlog-witness` carries.
///
/// **Security history (0.3.1).** The previous implementation rebuilt only
/// the NEW root. When the old size was not a power of two, the trusted
/// old root was never consulted at all, so any self-consistent fork that
/// grew past a non-power-of-two size verified -- witnesses cosigned forks
/// and `compare_checkpoints` reported them as extensions. Unit tests only
/// ever fed it honest proofs; a live ten-witness run caught it. The
/// exhaustive fork test below (every m < n <= 64) now guards it.
pub fn verify_consistency(
    first: u64,
    first_root: &Hash,
    second: u64,
    second_root: &Hash,
    proof: &[Hash],
) -> bool {
    if first > second {
        return false;
    }
    if first == 0 {
        // Nothing to be consistent with; RFC 9162 requires an empty proof.
        return proof.is_empty();
    }
    if first == second {
        return proof.is_empty() && first_root == second_root;
    }
    // Step 1: a non-trivial proof is never empty.
    let mut path = proof.iter();
    // Step 2: if `first` is an exact power of two, the old root is itself
    // the first node of the path.
    let start: Hash = if first.is_power_of_two() {
        *first_root
    } else {
        match path.next() {
            Some(h) => *h,
            None => return false,
        }
    };
    // Steps 3-4.
    let mut fnode = first - 1;
    let mut snode = second - 1;
    while fnode & 1 == 1 {
        fnode >>= 1;
        snode >>= 1;
    }
    // Step 5.
    let mut fr = start;
    let mut sr = start;
    // Step 6.
    for c in path {
        if snode == 0 {
            return false;
        }
        if fnode & 1 == 1 || fnode == snode {
            fr = node_hash(c, &fr);
            sr = node_hash(c, &sr);
            if fnode & 1 == 0 {
                while fnode & 1 == 0 && fnode != 0 {
                    fnode >>= 1;
                    snode >>= 1;
                }
            }
        } else {
            sr = node_hash(&sr, c);
        }
        fnode >>= 1;
        snode >>= 1;
    }
    // Step 7.
    snode == 0 && fr == *first_root && sr == *second_root
}

#[cfg(test)]
mod inclusion_range_tests {
    use super::*;

    #[test]
    fn inclusion_rejects_indices_outside_the_tree() {
        let mut t = MerkleTree::new();
        for i in 0..3u8 {
            t.append(leaf_hash(&[i]));
        }
        let leaf = leaf_hash(&[2]);
        let proof = t.inclusion_proof(2, 3).unwrap();
        assert!(verify_inclusion(&leaf, 2, 3, &proof, &t.root()));
        for bad in [3u64, 5, 6, u64::MAX] {
            assert!(
                !verify_inclusion(&leaf, bad, 3, &proof, &t.root()),
                "index {bad} is outside a 3-leaf tree"
            );
        }
    }
}

#[cfg(test)]
mod consistency_fork_tests {
    use super::*;

    fn tree(leaves: &[Hash]) -> MerkleTree {
        let mut t = MerkleTree::new();
        for l in leaves {
            t.append(*l);
        }
        t
    }

    /// Every (m, n) with 1 <= m < n <= 64: honest proofs verify; a proof
    /// produced by a forked tree (any of the first m leaves changed) never
    /// verifies against the honest old root; tampered proofs never verify.
    /// The pre-0.3.1 verifier failed the fork case for every non-power-of-
    /// two m.
    #[test]
    fn exhaustive_honest_and_forked_consistency() {
        let honest: Vec<Hash> = (0..64u32).map(|i| leaf_hash(&i.to_be_bytes())).collect();
        for n in 2..=64usize {
            let t_n = tree(&honest[..n]);
            for m in 1..n {
                let old_root = tree(&honest[..m]).root();
                let proof = t_n.consistency_proof(m as u64, n as u64).expect("proof");
                assert!(
                    verify_consistency(m as u64, &old_root, n as u64, &t_n.root(), &proof),
                    "honest proof rejected m={m} n={n}"
                );
                // Tampering with the proof or either root must fail.
                for i in 0..proof.len() {
                    let mut bad = proof.clone();
                    bad[i][0] ^= 1;
                    assert!(!verify_consistency(
                        m as u64,
                        &old_root,
                        n as u64,
                        &t_n.root(),
                        &bad
                    ));
                }
                let mut short = proof.clone();
                short.pop();
                assert!(!verify_consistency(
                    m as u64,
                    &old_root,
                    n as u64,
                    &t_n.root(),
                    &short
                ));
                let mut long = proof.clone();
                long.push([7u8; 32]);
                assert!(!verify_consistency(
                    m as u64,
                    &old_root,
                    n as u64,
                    &t_n.root(),
                    &long
                ));
                // Forks: rewrite one of the first m leaves, keep growing.
                for j in [0, m / 2, m - 1] {
                    let mut forked = honest[..n].to_vec();
                    forked[j] = leaf_hash(b"rewritten history");
                    let f = tree(&forked);
                    let fproof = f.consistency_proof(m as u64, n as u64).expect("proof");
                    assert!(
                        !verify_consistency(m as u64, &old_root, n as u64, &f.root(), &fproof),
                        "FORK ACCEPTED: m={m} n={n} rewritten leaf {j}"
                    );
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(b: u8) -> Hash {
        leaf_hash(&[b])
    }

    #[test]
    fn empty_tree_root_is_sha256_empty() {
        let t = MerkleTree::new();
        let expected: Hash = Sha256::new().finalize().into();
        assert_eq!(t.root(), expected);
    }

    #[test]
    fn single_leaf_root_is_leaf_hash() {
        let mut t = MerkleTree::new();
        t.append(h(1));
        assert_eq!(t.root(), h(1));
    }

    #[test]
    fn inclusion_proof_roundtrip_various_sizes() {
        for n in [1u8, 2, 3, 4, 5, 7, 8, 13, 32, 33] {
            let mut t = MerkleTree::new();
            for i in 0..n {
                t.append(h(i));
            }
            let root = t.root();
            for i in 0..n {
                let proof = t.inclusion_proof(i as u64, n as u64).unwrap();
                assert!(
                    verify_inclusion(&h(i), i as u64, n as u64, &proof, &root),
                    "inclusion failed for n={n}, i={i}"
                );
            }
        }
    }

    #[test]
    fn tampered_leaf_fails_inclusion() {
        let mut t = MerkleTree::new();
        for i in 0..8u8 {
            t.append(h(i));
        }
        let root = t.root();
        let proof = t.inclusion_proof(3, 8).unwrap();
        let wrong_leaf = h(99);
        assert!(!verify_inclusion(&wrong_leaf, 3, 8, &proof, &root));
    }

    #[test]
    fn consistency_proof_roundtrip_various_sizes() {
        for n in 1u8..=40 {
            let mut full = Vec::new();
            let mut tree = MerkleTree::new();
            for i in 0..n {
                let lh = h(i);
                full.push(lh);
                tree.append(lh);
            }
            let new_root = tree.root();
            for m in 0..=n {
                let mut old_tree = MerkleTree::new();
                for &lh in &full[0..m as usize] {
                    old_tree.append(lh);
                }
                let old_root = old_tree.root();
                let proof = tree.consistency_proof(m as u64, n as u64).unwrap();
                assert!(
                    verify_consistency(m as u64, &old_root, n as u64, &new_root, &proof),
                    "consistency failed for n={n}, m={m}"
                );
            }
        }
    }

    #[test]
    fn tampered_consistency_proof_fails() {
        let mut tree = MerkleTree::new();
        for i in 0..10u8 {
            tree.append(h(i));
        }
        let new_root = tree.root();
        let mut old_tree = MerkleTree::new();
        for i in 0..4u8 {
            old_tree.append(h(i));
        }
        let old_root = old_tree.root();
        let mut proof = tree.consistency_proof(4, 10).unwrap();
        assert!(verify_consistency(4, &old_root, 10, &new_root, &proof));
        assert!(
            !proof.is_empty(),
            "this case should produce a non-trivial proof"
        );
        proof[0] = h(200); // tamper with a committed subtree hash
        assert!(!verify_consistency(4, &old_root, 10, &new_root, &proof));
    }

    #[test]
    fn consistency_proof_rejects_wrong_old_root() {
        let mut tree = MerkleTree::new();
        for i in 0..10u8 {
            tree.append(h(i));
        }
        let new_root = tree.root();
        let proof = tree.consistency_proof(4, 10).unwrap();
        let wrong_old_root = h(222);
        assert!(!verify_consistency(
            4,
            &wrong_old_root,
            10,
            &new_root,
            &proof
        ));
    }

    #[test]
    fn consistency_proof_rejects_shrunk_or_forked_history() {
        // Simulates exactly the attack witnessing exists to catch: an
        // operator presents a "new" tree that does NOT actually contain
        // the old tree as a prefix (e.g. a leaf was swapped).
        let mut honest_tree = MerkleTree::new();
        for i in 0..5u8 {
            honest_tree.append(h(i));
        }
        let old_root = honest_tree.root();

        let mut forked_tree = MerkleTree::new();
        for i in 0..5u8 {
            forked_tree.append(h(i));
        }
        // Continue the fork with different content than the honest chain would.
        forked_tree.append(h(250));
        forked_tree.append(h(251));
        let forked_root = forked_tree.root();

        // Rewrite leaf 2 in the "forked" history — this tree no longer
        // has the honest 5-leaf tree as a genuine prefix.
        let mut rewritten = MerkleTree::new();
        for i in 0..5u8 {
            if i == 2 {
                rewritten.append(h(199));
            } else {
                rewritten.append(h(i));
            }
        }
        rewritten.append(h(250));
        rewritten.append(h(251));
        let rewritten_root = rewritten.root();
        assert_ne!(
            forked_root, rewritten_root,
            "sanity: rewriting did change the root"
        );

        // A witness holding old_root (from the honest 5-leaf checkpoint)
        // must reject a "consistency proof" claiming rewritten_root is a
        // valid extension, because no genuine proof exists for a tree
        // that isn't actually consistent.
        let proof = forked_tree.consistency_proof(5, 7).unwrap();
        assert!(verify_consistency(5, &old_root, 7, &forked_root, &proof));
        assert!(
            !verify_consistency(5, &old_root, 7, &rewritten_root, &proof),
            "a proof generated for the honest tree must not validate against a rewritten root"
        );
    }

    #[test]
    fn consistency_proof_trivial_cases() {
        let mut tree = MerkleTree::new();
        for i in 0..6u8 {
            tree.append(h(i));
        }
        let root = tree.root();
        // first == second: proof is empty, roots must match.
        let proof = tree.consistency_proof(6, 6).unwrap();
        assert!(proof.is_empty());
        assert!(verify_consistency(6, &root, 6, &root, &proof));
        // first == 0: vacuously consistent with any new tree.
        let proof0 = tree.consistency_proof(0, 6).unwrap();
        assert!(proof0.is_empty());
        assert!(verify_consistency(0, &h(0), 6, &root, &proof0));
    }

    // --- Adversarial red-team additions ---
    // Each test below targets one named attack shape, not just "does the
    // happy path work." These correspond directly to THREAT_MODEL.md's
    // claims about what tamper-evidence covers.

    #[test]
    fn rollback_attempt_rejected_by_consistency_check() {
        // An operator presents an OLDER, smaller tree as though it were an
        // update relative to a checkpoint a verifier already trusts —
        // i.e. tries to make history appear to have shrunk. first > second
        // is rejected outright, before any proof content is even examined.
        let mut tree = MerkleTree::new();
        for i in 0..10u8 {
            tree.append(h(i));
        }
        let big_root = tree.root();
        let mut smaller_tree = MerkleTree::new();
        for i in 0..5u8 {
            smaller_tree.append(h(i));
        }
        let small_root = smaller_tree.root();
        // Claiming "first=10, second=5" (a rollback) must fail regardless
        // of what's in the proof.
        assert!(!verify_consistency(10, &big_root, 5, &small_root, &[]));
        assert!(!verify_consistency(
            10,
            &big_root,
            5,
            &small_root,
            &[h(0), h(1)]
        ));
    }

    #[test]
    fn reordered_inclusion_proof_elements_fail() {
        let mut t = MerkleTree::new();
        for i in 0..8u8 {
            t.append(h(i));
        }
        let root = t.root();
        let mut proof = t.inclusion_proof(3, 8).unwrap();
        assert!(
            proof.len() >= 2,
            "test needs a proof with at least 2 elements to meaningfully reorder"
        );
        proof.swap(0, 1);
        assert!(
            !verify_inclusion(&h(3), 3, 8, &proof, &root),
            "reordering proof elements must not still verify — position carries meaning, this isn't a bag of hashes"
        );
    }

    #[test]
    fn reordered_consistency_proof_elements_fail() {
        let mut tree = MerkleTree::new();
        for i in 0..9u8 {
            tree.append(h(i));
        }
        let new_root = tree.root();
        let mut old_tree = MerkleTree::new();
        for i in 0..4u8 {
            old_tree.append(h(i));
        }
        let old_root = old_tree.root();
        let mut proof = tree.consistency_proof(4, 9).unwrap();
        assert!(
            proof.len() >= 2,
            "test needs a proof with at least 2 elements to meaningfully reorder"
        );
        proof.swap(0, 1);
        assert!(
            !verify_consistency(4, &old_root, 9, &new_root, &proof),
            "reordering consistency-proof elements must not still verify"
        );
    }

    #[test]
    fn inclusion_proof_with_extra_trailing_elements_fails() {
        // Adversarial strictness: a proof that contains MORE elements than
        // the tree structure requires must be rejected outright, not
        // verified against a prefix with the excess silently ignored. A
        // lenient verifier here would accept infinitely many "valid"
        // proofs for one statement, which breaks proof canonicity and
        // opens the door to implementations disagreeing about validity.
        let mut t = MerkleTree::new();
        for i in 0..8u8 {
            t.append(h(i));
        }
        let root = t.root();
        let mut proof = t.inclusion_proof(3, 8).unwrap();
        assert!(
            verify_inclusion(&h(3), 3, 8, &proof, &root),
            "sanity: valid proof verifies"
        );
        proof.push(h(0xEE));
        assert!(
            !verify_inclusion(&h(3), 3, 8, &proof, &root),
            "a proof with extra trailing elements must be rejected"
        );
    }

    #[test]
    fn consistency_proof_with_extra_trailing_elements_fails() {
        let mut tree = MerkleTree::new();
        for i in 0..8u8 {
            tree.append(h(i));
        }
        let new_root = tree.root();
        let mut old_tree = MerkleTree::new();
        for i in 0..4u8 {
            old_tree.append(h(i));
        }
        let old_root = old_tree.root();
        let mut proof = tree.consistency_proof(4, 8).unwrap();
        assert!(
            verify_consistency(4, &old_root, 8, &new_root, &proof),
            "sanity: valid proof verifies"
        );
        proof.push(h(0xDD));
        assert!(
            !verify_consistency(4, &old_root, 8, &new_root, &proof),
            "a consistency proof with extra trailing elements must be rejected"
        );
    }

    #[test]
    fn power_of_two_helper_does_not_collide_across_32_bit_truncation() {
        // On a 32-bit target, the OLD code's `size as usize` truncated a
        // u64 to its low 32 bits before computing the split point. This
        // confirms the u64-native helper no longer produces the same
        // split point for a huge size and the small size sharing its low
        // 32 bits -- i.e. a claimed tree_size of 2^32+8 is no longer
        // treated identically to tree_size=8. See finding 16.
        let huge = (1u64 << 32) + 8;
        let small = 8u64;
        assert_ne!(
            largest_power_of_two_lt_u64(huge),
            largest_power_of_two_lt_u64(small),
            "a tree_size differing only above the 32nd bit must not collide with its truncated equivalent"
        );
        // And the value is still mathematically correct: the largest
        // power of two strictly less than 2^32+8 is 2^32.
        assert_eq!(largest_power_of_two_lt_u64(huge), 1u64 << 32);
    }

    #[test]
    fn inclusion_proof_rejects_tree_size_that_does_not_fit_the_real_leaf_count() {
        let mut t = MerkleTree::new();
        for i in 0..8u8 {
            t.append(h(i));
        }
        // A tree_size wildly larger than the real leaf count must fail
        // cleanly (None), not silently truncate to something in range.
        assert!(t.inclusion_proof(3, u64::MAX).is_none());
    }
}

#[cfg(test)]
mod spine_tests {
    use super::*;

    fn h(i: u64) -> Hash {
        leaf_hash(&i.to_be_bytes())
    }

    /// Reference implementation: the original O(n) recursive computation.
    /// Kept ONLY as a test oracle. If the incremental spine ever diverges
    /// from this, the spine is wrong — this is the definition.
    fn reference_root(leaves: &[Hash]) -> Hash {
        match leaves.len() {
            0 => Sha256::new().finalize().into(),
            1 => leaves[0],
            n => {
                let k = largest_power_of_two_lt(n);
                let (left, right) = leaves.split_at(k);
                node_hash(&reference_root(left), &reference_root(right))
            }
        }
    }

    #[test]
    fn incremental_root_matches_the_reference_at_every_size() {
        // Exhaustive across every size where the spine's shape changes
        // meaningfully — powers of two, their neighbours, and everything
        // below 200. A shape bug would show up as a mismatch at exactly
        // one size, which a spot check would miss.
        let mut tree = MerkleTree::new();
        let mut leaves = Vec::new();
        for i in 0..200u64 {
            tree.append(h(i));
            leaves.push(h(i));
            assert_eq!(
                tree.root(),
                reference_root(&leaves),
                "incremental root diverged from the reference at size {}",
                i + 1
            );
        }
    }

    #[test]
    fn incremental_root_matches_the_reference_across_power_of_two_boundaries() {
        // Boundaries are where carry chains are longest and most likely
        // to be wrong.
        for target in [255usize, 256, 257, 511, 512, 513, 1023, 1024, 1025] {
            let mut tree = MerkleTree::new();
            let mut leaves = Vec::new();
            for i in 0..target as u64 {
                tree.append(h(i));
                leaves.push(h(i));
            }
            assert_eq!(
                tree.root(),
                reference_root(&leaves),
                "mismatch at size {target}"
            );
        }
    }

    #[test]
    fn spine_stays_logarithmic() {
        // The performance guarantee, asserted rather than assumed: the
        // spine holds one entry per set bit in the size, so it must never
        // exceed log2(n)+1. If this regresses, root() silently becomes
        // linear again and checkpointing goes quadratic.
        let mut tree = MerkleTree::new();
        for i in 0..4096u64 {
            tree.append(h(i));
            let n = tree.size();
            let max = (64 - n.leading_zeros()) as usize;
            assert!(
                tree.spine.len() <= max,
                "spine grew to {} entries at size {n} (bound {max})",
                tree.spine.len()
            );
            assert_eq!(
                tree.spine.len(),
                n.count_ones() as usize,
                "spine must hold exactly one entry per set bit in the size"
            );
        }
    }

    #[test]
    fn root_is_stable_across_repeated_calls() {
        // root() must be a pure read of the spine, never mutate it.
        let mut tree = MerkleTree::new();
        for i in 0..37u64 {
            tree.append(h(i));
        }
        let first = tree.root();
        for _ in 0..100 {
            assert_eq!(tree.root(), first, "root() must not mutate tree state");
        }
    }
}
