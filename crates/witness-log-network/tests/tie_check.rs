//! Regressions for compare_checkpoints. A rollback verdict is an
//! accusation; it must never depend on argument order.
use ed25519_dalek::SigningKey;
use witness_log_core::sth::SignedTreeHead;
use witness_log_network::*;

fn k() -> SigningKey {
    SigningKey::from_bytes(&[7u8; 32])
}

#[test]
fn same_millisecond_checkpoints_are_never_a_rollback() {
    let small = SignedTreeHead::sign(&k(), 5, &[1u8; 32], 1_700_000_000_000);
    let big = SignedTreeHead::sign(&k(), 10, &[2u8; 32], 1_700_000_000_000);
    let ab = compare_checkpoints(&small, &big, None);
    let ba = compare_checkpoints(&big, &small, None);
    assert_eq!(ab, ba, "argument order must not change the verdict");
    assert_ne!(
        ab,
        CheckpointRelation::Rollback,
        "a same-ms growth is not a rollback"
    );
}

#[test]
fn a_genuine_rollback_is_still_caught_in_either_order() {
    let big_early = SignedTreeHead::sign(&k(), 10, &[2u8; 32], 1_700_000_000_000);
    let small_late = SignedTreeHead::sign(&k(), 3, &[3u8; 32], 1_700_000_005_000);
    assert_eq!(
        compare_checkpoints(&big_early, &small_late, None),
        CheckpointRelation::Rollback
    );
    assert_eq!(
        compare_checkpoints(&small_late, &big_early, None),
        CheckpointRelation::Rollback
    );
}

#[test]
fn every_relation_is_symmetric() {
    let cases = [
        (
            SignedTreeHead::sign(&k(), 5, &[1u8; 32], 100),
            SignedTreeHead::sign(&k(), 5, &[1u8; 32], 100),
        ),
        (
            SignedTreeHead::sign(&k(), 5, &[1u8; 32], 100),
            SignedTreeHead::sign(&k(), 5, &[9u8; 32], 200),
        ),
        (
            SignedTreeHead::sign(&k(), 5, &[1u8; 32], 100),
            SignedTreeHead::sign(&k(), 8, &[2u8; 32], 100),
        ),
        (
            SignedTreeHead::sign(&k(), 9, &[1u8; 32], 100),
            SignedTreeHead::sign(&k(), 4, &[2u8; 32], 300),
        ),
    ];
    for (a, b) in &cases {
        assert_eq!(
            compare_checkpoints(a, b, None),
            compare_checkpoints(b, a, None),
            "asymmetric verdict for sizes {}/{} at ts {}/{}",
            a.tree_size,
            b.tree_size,
            a.timestamp_ms,
            b.timestamp_ms
        );
    }
}
