//! Property tests for the two proofs everything else rests on: RFC 6962
//! inclusion and RFC 9162 consistency. Random tree sizes up to 3,000
//! leaves, random positions. For every case:
//!
//! - the honest proof verifies;
//! - flipping any single bit of the leaf, either root, or any proof
//!   element makes it fail;
//! - a consistency proof must reconstruct BOTH roots: a proof from a
//!   different history (a fork that rewrote one leaf below the old size)
//!   never verifies against the honest old root, and the honest proof
//!   never verifies against a forked new root. (Rebuilding only the new
//!   root was the 0.3.0 bug.)
//!
//! `PROPTEST_CASES=1000 cargo test -p witness-log-core --test merkle_properties --release`
//! runs a longer search.

use proptest::prelude::*;
use witness_log_core::merkle::{leaf_hash, verify_consistency, verify_inclusion, Hash, MerkleTree};

const MAX_LEAVES: u64 = 3_000;

fn tree(seed: u64, n: u64, rewrite: Option<u64>) -> MerkleTree {
    let mut t = MerkleTree::new();
    for i in 0..n {
        let tag = if Some(i) == rewrite { 0xff } else { 0x00 };
        let mut b = Vec::with_capacity(17);
        b.extend_from_slice(&seed.to_le_bytes());
        b.extend_from_slice(&i.to_le_bytes());
        b.push(tag);
        t.append(leaf_hash(&b));
    }
    t
}

fn leaf(seed: u64, i: u64) -> Hash {
    let mut b = Vec::with_capacity(17);
    b.extend_from_slice(&seed.to_le_bytes());
    b.extend_from_slice(&i.to_le_bytes());
    b.push(0x00);
    leaf_hash(&b)
}

fn flip(h: &Hash, bit: usize) -> Hash {
    let mut out = *h;
    out[(bit / 8) % 32] ^= 1 << (bit % 8);
    out
}

fn config() -> ProptestConfig {
    // Each case builds a tree of up to 3,000 leaves and checks every
    // single-bit mutation of a proof: keep the default run under a few
    // seconds in debug; raise with PROPTEST_CASES for a longer search.
    ProptestConfig {
        cases: std::env::var("PROPTEST_CASES")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(48),
        ..ProptestConfig::default()
    }
}

proptest! {
    #![proptest_config(config())]

    #[test]
    fn inclusion_honest_verifies_and_any_bit_flip_fails(
        seed in any::<u64>(),
        n in 1..=MAX_LEAVES,
        pos in any::<u64>(),
        bit in 0usize..256,
    ) {
        let t = tree(seed, n, None);
        let i = pos % n;
        let root = t.root();
        let l = leaf(seed, i);
        let proof = t.inclusion_proof(i, n).expect("index in range");
        prop_assert!(verify_inclusion(&l, i, n, &proof, &root));

        prop_assert!(!verify_inclusion(&flip(&l, bit), i, n, &proof, &root), "leaf bit {bit}");
        prop_assert!(!verify_inclusion(&l, i, n, &proof, &flip(&root, bit)), "root bit {bit}");
        for k in 0..proof.len() {
            let mut p = proof.clone();
            p[k] = flip(&p[k], bit);
            prop_assert!(!verify_inclusion(&l, i, n, &p, &root), "proof[{k}] bit {bit}");
        }
        // A truncated or extended proof never verifies either.
        if !proof.is_empty() {
            prop_assert!(!verify_inclusion(&l, i, n, &proof[..proof.len() - 1], &root));
        }
        let mut longer = proof.clone();
        longer.push(root);
        prop_assert!(!verify_inclusion(&l, i, n, &longer, &root));
    }

    #[test]
    fn consistency_honest_verifies_and_any_bit_flip_fails(
        seed in any::<u64>(),
        n in 2..=MAX_LEAVES,
        m_raw in any::<u64>(),
        bit in 0usize..256,
    ) {
        let m = 1 + m_raw % (n - 1); // 1 <= m < n
        let t = tree(seed, n, None);
        let old = t.root_at(m).expect("m <= n");
        let new = t.root();
        let proof = t.consistency_proof(m, n).expect("m <= n");
        prop_assert!(verify_consistency(m, &old, n, &new, &proof));

        prop_assert!(!verify_consistency(m, &flip(&old, bit), n, &new, &proof), "old root bit {bit}");
        prop_assert!(!verify_consistency(m, &old, n, &flip(&new, bit), &proof), "new root bit {bit}");
        for k in 0..proof.len() {
            let mut p = proof.clone();
            p[k] = flip(&p[k], bit);
            prop_assert!(!verify_consistency(m, &old, n, &new, &p), "proof[{k}] bit {bit}");
        }
        if !proof.is_empty() {
            prop_assert!(!verify_consistency(m, &old, n, &new, &proof[..proof.len() - 1]));
        }
    }

    #[test]
    fn consistency_reconstructs_both_roots(
        seed in any::<u64>(),
        n in 2..=MAX_LEAVES,
        m_raw in any::<u64>(),
        r_raw in any::<u64>(),
    ) {
        let m = 1 + m_raw % (n - 1);
        let rewritten = r_raw % m; // a leaf the witness already cosigned
        let honest = tree(seed, n, None);
        let fork = tree(seed, n, Some(rewritten));
        let old = honest.root_at(m).expect("m <= n");
        // The fork is internally consistent: its own proof links its own heads.
        let fork_proof = fork.consistency_proof(m, n).expect("m <= n");
        prop_assert!(verify_consistency(m, &fork.root_at(m).expect("m"), n, &fork.root(), &fork_proof));
        // ...but it never extends the head the witness holds.
        prop_assert!(!verify_consistency(m, &old, n, &fork.root(), &fork_proof));
        // And the honest proof does not carry the honest old head to the fork.
        let honest_proof = honest.consistency_proof(m, n).expect("m <= n");
        prop_assert!(!verify_consistency(m, &old, n, &fork.root(), &honest_proof));
    }
}
