//! New 0.3.6 API used by the fresh-eyes fixes: a fallible anchor append
//! for the in-memory log, and sized-head helpers (root and consistency
//! proof for an earlier head) that let a background witnesser pin one
//! head while the agent keeps appending.

use witness_log_core::leaf::LeafValidationError;
use witness_log_core::log::WitnessLog;
use witness_log_core::merkle::verify_consistency;
use witness_log_network::{Dossier, Verdict, VerifyContext};

fn verdict_of(log: &WitnessLog) -> Verdict {
    let d = Dossier::from_log(log, log.checkpoint_self());
    let id = log.identity_pubkey_hex();
    let ctx = VerifyContext {
        expected_identity_pubkey: Some(&id),
        ..Default::default()
    };
    d.verify(0.66, &ctx).verdict
}

#[test]
fn in_memory_try_append_external_anchor_refuses_bad_urls() {
    let mut log = WitnessLog::new();
    assert!(matches!(
        log.try_append_external_anchor("ftp://x", "{}"),
        Err(LeafValidationError::MalformedUrl { .. })
    ));
    assert_eq!(log.tree_size(), 0);
    log.try_append_external_anchor("https://x.example/a", "{}")
        .unwrap();
    assert_eq!(verdict_of(&log), Verdict::Unanchored);
}

/// The sized helpers the Python background witnesser pins a head with.
#[test]
fn root_at_and_consistency_between_agree_with_the_live_tree() {
    let mut log = WitnessLog::new();
    let mut roots = vec![log.root_at(0).unwrap()];
    for i in 0..37u32 {
        log.append_intent(&i.to_le_bytes());
        roots.push(log.root_at(log.tree_size()).unwrap());
        assert_eq!(hex::encode(roots[roots.len() - 1]), log.root_hex());
    }
    assert!(log.root_at(38).is_none());
    for first in 1..=37u64 {
        for second in first..=37u64 {
            let p = log.consistency_proof_between(first, second).unwrap();
            assert!(verify_consistency(
                first,
                &roots[first as usize],
                second,
                &roots[second as usize],
                &p
            ));
        }
    }
}
