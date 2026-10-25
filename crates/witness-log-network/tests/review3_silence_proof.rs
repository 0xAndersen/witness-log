//! Review III, H1 and M1: a censorship accusation must be bound to the
//! log's witnessed history, and held to the same independence bar as a
//! WITNESSED verdict.
//!
//! H1: 0.6.0 counted witnessed checkpoints and looked for the event in a
//! caller-supplied leaf list without joining the two, so an accuser
//! holding a genuine write receipt and the log's real witnessed
//! checkpoints could drop the event from the list (or pass no list) and
//! get `Censored` against an honest log.
//! M1: a checkpoint counted as witnessed on one trusted receipt, while
//! `Verdict::Witnessed` needs two independent operators.

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use witness_log_core::identity::IdentityKeypair;
use witness_log_core::log::WitnessLog;
use witness_log_core::sth::{SignedTreeHead, WriteReceipt};
use witness_log_network::*;

fn now() -> u64 {
    1_800_000_000_000
}

struct Witness {
    key: SigningKey,
}

/// A directory of witnesses, one per (org, project_operated) given.
fn network(orgs: &[(&str, bool)]) -> (WitnessDirectory, Vec<Witness>) {
    let mut dir = WitnessDirectory::default();
    let mut ws = Vec::new();
    for (i, (org, project)) in orgs.iter().enumerate() {
        let key = SigningKey::generate(&mut OsRng);
        dir.witnesses.push(WitnessEntry {
            name: format!("w{i}"),
            operator_org: org.to_string(),
            url: format!("https://w{i}.example"),
            pubkey: hex::encode(key.verifying_key().to_bytes()),
            runtime: WitnessRuntime::Human,
            compute_provider: None,
            is_project_operated: *project,
        });
        ws.push(Witness { key });
    }
    (dir, ws)
}

/// The log's checkpoint at its current size, cosigned by every witness.
fn witnessed(log: &WitnessLog, key: &SigningKey, ws: &[Witness]) -> ObservedCheckpoint {
    let root: [u8; 32] = hex::decode(log.root_hex()).unwrap().try_into().unwrap();
    let cp = SignedTreeHead::sign(key, log.tree_size(), &root, now() + log.tree_size());
    let receipts = ws
        .iter()
        .map(|w| WitnessReceipt::sign(&w.key, &cp, now() + log.tree_size()))
        .collect();
    ObservedCheckpoint {
        checkpoint: cp,
        receipts,
    }
}

/// A log under `seed`, its write receipt for an event at size 0, and its
/// leaves grown to 5 and 9 entries with a witnessed checkpoint at each.
/// `include` puts the event in the log (at index 3), as an honest log would.
fn scenario(
    include: bool,
    ws: &[Witness],
) -> (
    WriteReceipt,
    WitnessLog,
    Vec<ObservedCheckpoint>,
    SigningKey,
) {
    let seed = [7u8; 32];
    let key = SigningKey::from_bytes(&seed);
    let mut log = WitnessLog::resume(IdentityKeypair::from_bytes(&seed), 0);
    let mut later = Vec::new();
    let mut receipt = None;
    for i in 0..9u64 {
        if include && i == 3 {
            let idx = log.append_intent(b"the event");
            receipt = log.write_receipt(idx);
        } else {
            log.append_intent(format!("other {i}").as_bytes());
        }
        if log.tree_size() == 5 || log.tree_size() == 9 {
            later.push(witnessed(&log, &key, ws));
        }
    }
    // Excluded: the log signed a receipt for an event it never appended.
    let receipt = receipt.unwrap_or_else(|| WriteReceipt::sign(&key, &"ab".repeat(32), 0, now()));
    (receipt, log, later, key)
}

fn report(
    receipt: &WriteReceipt,
    leaves: &[witness_log_core::leaf::Leaf],
    later: &[ObservedCheckpoint],
    dir: &WitnessDirectory,
    subject_org: Option<&str>,
) -> SilenceProofReport {
    silence_proof_for_subject(receipt, leaves, later, dir, 2, subject_org)
}

#[test]
fn an_event_left_out_of_the_witnessed_history_is_censored_and_bound_to_its_root() {
    let (dir, ws) = network(&[("Org A", false), ("Org B", false)]);
    let (receipt, log, later, _) = scenario(false, &ws);
    let r = report(&receipt, log.leaves(), &later, &dir, None);
    assert!(
        matches!(
            r.result,
            SilenceProofResult::Censored {
                receipt_tree_size: 0,
                witnessed_checkpoints_after: 2
            }
        ),
        "{r:?}"
    );
    assert_eq!(r.bound_tree_size, Some(9));
    assert_eq!(r.bound_root_hash.as_deref(), Some(log.root_hex().as_str()));
    // The kept signature: same answer.
    assert!(matches!(
        silence_proof(&receipt, log.leaves(), &later, &dir, 2),
        SilenceProofResult::Censored { .. }
    ));
}

#[test]
fn an_accuser_cannot_drop_the_event_from_an_honest_logs_leaves() {
    let (dir, ws) = network(&[("Org A", false), ("Org B", false)]);
    let (receipt, log, later, _) = scenario(true, &ws);
    // The honest view: present.
    assert!(matches!(
        report(&receipt, log.leaves(), &later, &dir, None).result,
        SilenceProofResult::Present { leaf_index: 3 }
    ));
    // The event removed from the list: the leaves no longer reproduce the
    // witnessed roots, so nothing is proven.
    let mut doctored: Vec<_> = log.leaves().to_vec();
    doctored.remove(3);
    let r = report(&receipt, &doctored, &later, &dir, None);
    assert!(
        matches!(r.result, SilenceProofResult::Inconclusive { .. }),
        "{r:?}"
    );
    assert!(
        r.reason.as_deref().unwrap().contains("cover")
            || r.reason.as_deref().unwrap().contains("reproduce")
    );
    // The event's leaf replaced by another (same length): still caught.
    let mut swapped: Vec<_> = log.leaves().to_vec();
    swapped[3].payload_hash = "cd".repeat(32);
    let r = report(&receipt, &swapped, &later, &dir, None);
    assert!(
        matches!(r.result, SilenceProofResult::Inconclusive { .. }),
        "{r:?}"
    );
    assert!(r.reason.as_deref().unwrap().contains("reproduce"), "{r:?}");
    // No leaves at all: 0.6.0 called this Censored.
    let r = report(&receipt, &[], &later, &dir, None);
    assert!(
        matches!(r.result, SilenceProofResult::Inconclusive { .. }),
        "{r:?}"
    );
    assert!(matches!(
        silence_proof(&receipt, &[], &later, &dir, 2),
        SilenceProofResult::Inconclusive { .. }
    ));
}

#[test]
fn leaves_behind_the_largest_witnessed_checkpoint_prove_nothing() {
    let (dir, ws) = network(&[("Org A", false), ("Org B", false)]);
    let (receipt, log, later, _) = scenario(false, &ws);
    // Only the first 5 leaves: the event could be in 5..9.
    let r = report(&receipt, &log.leaves()[..5], &later, &dir, None);
    assert!(
        matches!(
            r.result,
            SilenceProofResult::Inconclusive {
                witnessed_checkpoints_seen: 2,
                ..
            }
        ),
        "{r:?}"
    );
    assert!(r.reason.as_deref().unwrap().contains("cover 5"), "{r:?}");
}

#[test]
fn a_checkpoint_counts_only_with_two_independent_operators() {
    // Two witnesses, one organisation (spelled differently): one operator.
    let (dir, ws) = network(&[("Org A", false), ("  org a ", false)]);
    let (receipt, log, later, _) = scenario(false, &ws);
    let r = report(&receipt, log.leaves(), &later, &dir, None);
    assert!(
        matches!(
            r.result,
            SilenceProofResult::Inconclusive {
                witnessed_checkpoints_seen: 0,
                ..
            }
        ),
        "{r:?}"
    );

    // One independent operator plus project-operated witnesses: one.
    let (dir, ws) = network(&[("Org A", false), ("Project", true), ("Project 2", true)]);
    let (receipt, log, later, _) = scenario(false, &ws);
    let r = report(&receipt, log.leaves(), &later, &dir, None);
    assert!(
        matches!(
            r.result,
            SilenceProofResult::Inconclusive {
                witnessed_checkpoints_seen: 0,
                ..
            }
        ),
        "{r:?}"
    );

    // Two operators, but one of them runs the accused log.
    let (dir, ws) = network(&[("Org A", false), ("Registry Inc", false)]);
    let (receipt, log, later, _) = scenario(false, &ws);
    assert!(matches!(
        report(&receipt, log.leaves(), &later, &dir, None).result,
        SilenceProofResult::Censored { .. }
    ));
    let r = report(&receipt, log.leaves(), &later, &dir, Some("registry inc"));
    assert!(
        matches!(
            r.result,
            SilenceProofResult::Inconclusive {
                witnessed_checkpoints_seen: 0,
                ..
            }
        ),
        "{r:?}"
    );
}

#[test]
fn two_witnessed_roots_for_one_size_are_equivocation_not_a_silence_proof() {
    let (dir, ws) = network(&[("Org A", false), ("Org B", false)]);
    let (receipt, log, mut later, key) = scenario(false, &ws);
    let forked = SignedTreeHead::sign(&key, 9, &[0xee; 32], now() + 99);
    later.push(ObservedCheckpoint {
        receipts: ws
            .iter()
            .map(|w| WitnessReceipt::sign(&w.key, &forked, now() + 99))
            .collect(),
        checkpoint: forked,
    });
    let r = report(&receipt, log.leaves(), &later, &dir, None);
    assert!(
        matches!(r.result, SilenceProofResult::Inconclusive { .. }),
        "{r:?}"
    );
    assert!(
        r.reason.as_deref().unwrap().contains("equivocation"),
        "{r:?}"
    );
}

#[test]
fn a_smaller_witnessed_checkpoint_from_another_history_is_caught() {
    let (dir, ws) = network(&[("Org A", false), ("Org B", false)]);
    let (receipt, log, mut later, key) = scenario(false, &ws);
    // Replace the size-5 checkpoint with one over a different root.
    let other = SignedTreeHead::sign(&key, 5, &[0x11; 32], now() + 5);
    later[0] = ObservedCheckpoint {
        receipts: ws
            .iter()
            .map(|w| WitnessReceipt::sign(&w.key, &other, now() + 5))
            .collect(),
        checkpoint: other,
    };
    let r = report(&receipt, log.leaves(), &later, &dir, None);
    assert!(
        matches!(r.result, SilenceProofResult::Inconclusive { .. }),
        "{r:?}"
    );
    assert!(r.reason.as_deref().unwrap().contains("size 5"), "{r:?}");
}
