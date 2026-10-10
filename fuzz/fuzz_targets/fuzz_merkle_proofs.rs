//! The core cryptographic surface: `verify_inclusion` and
//! `verify_consistency` take fully attacker-controlled leaf/root hashes,
//! sizes, indices, and proof vectors. This is exactly the surface where
//! the pre-launch review found two real defects (finding 13: proof
//! malleability at the front of the proof slice; finding 16: u64->usize
//! truncation on 32-bit targets) -- and it was, at the time, completely
//! unfuzzed. Nothing here may panic, and no malformed or adversarial
//! input should ever produce `true` for a proof that wasn't legitimately
//! generated.
#![no_main]
use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

#[derive(Debug, Arbitrary)]
struct InclusionInput {
    leaf: [u8; 32],
    leaf_index: u64,
    tree_size: u64,
    proof: Vec<[u8; 32]>,
    root: [u8; 32],
}

#[derive(Debug, Arbitrary)]
struct ConsistencyInput {
    first: u64,
    first_root: [u8; 32],
    second: u64,
    second_root: [u8; 32],
    proof: Vec<[u8; 32]>,
}

#[derive(Debug, Arbitrary)]
enum FuzzInput {
    Inclusion(InclusionInput),
    Consistency(ConsistencyInput),
}

fuzz_target!(|input: FuzzInput| {
    match input {
        FuzzInput::Inclusion(i) => {
            let _ = witness_log_core::merkle::verify_inclusion(
                &i.leaf,
                i.leaf_index,
                i.tree_size,
                &i.proof,
                &i.root,
            );
        }
        FuzzInput::Consistency(c) => {
            let _ = witness_log_core::merkle::verify_consistency(
                c.first,
                &c.first_root,
                c.second,
                &c.second_root,
                &c.proof,
            );
        }
    }
});
