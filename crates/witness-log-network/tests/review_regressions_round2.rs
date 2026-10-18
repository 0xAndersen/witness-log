//! Regression tests for the second-round review (9 findings against
//! v0.2.0, 4 with executable PoCs, all reproduced and confirmed real).
//! This file is the inverse of the original `review_poc_2.rs`: same four
//! constructions, now asserting each is fixed. If any of these tests
//! goes red, one of the four findings below has regressed.

use ed25519_dalek::SigningKey;
use witness_log_core::identity::IdentityKeypair;
use witness_log_core::journal::JournaledLog;
use witness_log_core::leaf::{validate_sequence, Leaf, LeafType};
use witness_log_core::merkle::{leaf_hash, MerkleTree};
use witness_log_core::sth::{SignedTreeHead, WriteReceipt};
use witness_log_network::*;

fn hex64(byte: u8) -> String {
    hex::encode([byte; 32])
}

fn leaf_at(index: u64, ts: u64, session: &str) -> Leaf {
    Leaf {
        index,
        leaf_type: LeafType::ActiveIntent.tag(),
        timestamp_ms: ts,
        session_pubkey: session.to_string(),
        payload_hash: hex64(0xAB),
        redacted_index: None,
        revoked_identity: None,
        handoff_direction: None,
        counterparty_pubkey: None,
        handoff_state_hash: None,
        authorization_event_kind: None,
        authorization_scope_hash: None,
        anchor_url: None,
        anchor_proof_json: None,
        anchor_proof_hash: None,
    }
}

/// Finding 02 (HIGH): a backward clock step no longer diverges an honest
/// log. Two protections now apply: WitnessLog::append clamps timestamps
/// to be non-decreasing at write time (the common case), AND
/// validate_sequence no longer treats a non-monotonic timestamp as a
/// hard verification failure at all (the general case — covers replayed
/// old data, a second implementation, or any leaf source this crate
/// doesn't control). This test exercises the general case directly, by
/// hand-constructing a leaf sequence with a backward step exactly as the
/// original PoC did.
#[test]
fn finding02_backward_clock_step_no_longer_diverges_an_honest_log() {
    let identity = IdentityKeypair::generate();
    let signer = identity.public_hex();
    let leaves = vec![
        leaf_at(0, 1_000_000, &signer),
        leaf_at(1, 1_000_050, &signer),
        leaf_at(2, 1_000_045, &signer), // clock stepped back 5ms
        leaf_at(3, 1_000_060, &signer),
    ];
    assert!(
        validate_sequence(&leaves).is_ok(),
        "a backward timestamp step must no longer fail structural validation"
    );

    let mut tree = MerkleTree::new();
    for l in &leaves {
        tree.append(leaf_hash(&l.canonical_bytes()));
    }
    let key = SigningKey::from_bytes(&identity.to_bytes());
    let sth = SignedTreeHead::sign(&key, tree.size(), &tree.root(), 1_000_060);
    let dossier = Dossier {
        identity_pubkey: signer,
        leaves,
        checkpoint: sth,
        witness_receipts: vec![],
        witness_directory: WitnessDirectory::default(),
        key_bindings: vec![],
        revocations: vec![],
        fleet_anchor: None,
    };
    let report = dossier.verify(0.66, &VerifyContext::default());
    assert_ne!(
        report.verdict,
        Verdict::Invalid,
        "an honest log with one backward clock step must not be classified as tampered"
    );
    assert!(report.leaves_structurally_valid);
}

/// Finding 02, other half: WitnessLog::append itself now clamps, so a
/// real log built through the normal API never even produces a backward
/// step in the first place (the append()-side fix, on top of the
/// verifier-side fix above).
#[test]
fn finding02_append_clamps_timestamps_at_write_time() {
    let identity = IdentityKeypair::generate();
    let mut log = witness_log_core::log::WitnessLog::resume(identity, 0);
    log.append_intent(b"first");
    let ts1 = log.leaves()[0].timestamp_ms;
    log.append_intent(b"second");
    let ts2 = log.leaves()[1].timestamp_ms;
    assert!(ts2 >= ts1, "append() must never produce a decreasing timestamp, even if the wall clock stepped backward between calls");
}

/// Finding 04 (MEDIUM): journal replay now rejects an unrecognized leaf
/// type instead of replaying it into a live log. Mirrors load_snapshot's
/// matching fix.
#[test]
fn finding04_journal_replay_rejects_unrecognized_leaf_type() {
    let bad = Leaf {
        leaf_type: 0xFE,
        ..leaf_at(0, 1, &hex64(0x01))
    };
    assert!(bad.validate(0).is_err());

    let path = std::env::temp_dir().join(format!("finding04-journal-{}.jsonl", std::process::id()));
    let p = path.to_str().unwrap();
    let _ = std::fs::remove_file(p);
    drop(JournaledLog::create_ephemeral(p).unwrap());
    let header = std::fs::read_to_string(p).unwrap();
    let header_line = header.lines().next().unwrap().to_string();
    let bad_line = serde_json::to_string(&bad).unwrap();
    std::fs::write(p, format!("{header_line}\n{bad_line}\n")).unwrap();

    let result = JournaledLog::resume(p);
    assert!(
        result.is_err(),
        "an unrecognized leaf_type must be rejected on replay, not silently loaded into a live tree"
    );
    std::fs::remove_file(p).ok();
}

/// Finding 04, load_snapshot's matching path: same validation gap,
/// same fix, checked directly against the ingest point.
#[test]
fn finding04_load_snapshot_rejects_unrecognized_leaf_type() {
    let bad = Leaf {
        leaf_type: 0xFE,
        ..leaf_at(0, 1, &hex64(0x01))
    };
    let identity = IdentityKeypair::generate();
    let snapshot_json = serde_json::json!({
        "format_version": 1,
        "identity_bytes_hex": hex::encode(identity.to_bytes()),
        "session_number": 0,
        "leaves": [bad],
    });
    let path = std::env::temp_dir().join(format!("finding04-snapshot-{}.json", std::process::id()));
    std::fs::write(&path, serde_json::to_string(&snapshot_json).unwrap()).unwrap();

    let result = witness_log_core::log::WitnessLog::load_snapshot(path.to_str().unwrap());
    assert!(
        result.is_err(),
        "an unrecognized leaf_type must be rejected on snapshot load, not silently loaded into a live tree"
    );
    std::fs::remove_file(&path).ok();
}

fn mk_witness_entry(pubkey: String) -> WitnessEntry {
    WitnessEntry {
        name: "w".into(),
        operator_org: "org".into(),
        url: "https://w.example".into(),
        pubkey,
        runtime: WitnessRuntime::Human,
        compute_provider: None,
        is_project_operated: false,
    }
}

/// Finding 07 (POLISH), part 1: silence_proof no longer counts the same
/// witnessed checkpoint twice when it appears more than once in the
/// caller's observed-checkpoints list (e.g. from polling and
/// accumulating snapshots).
#[test]
fn finding07_silence_proof_deduplicates_observed_checkpoints() {
    let id = IdentityKeypair::generate();
    let key = SigningKey::from_bytes(&id.to_bytes());
    let write_receipt = WriteReceipt::sign(&key, &"ab".repeat(32), 1, 1000);
    let later = SignedTreeHead::sign(&key, 5, &[2u8; 32], 2000);
    // Two independent operators: since review III (M1) a checkpoint counts
    // only with the bar a WITNESSED verdict needs.
    let mut dir = WitnessDirectory::default();
    let mut receipts = vec![];
    for org in ["org a", "org b"] {
        let w = SigningKey::generate(&mut rand::rngs::OsRng);
        let mut e = mk_witness_entry(hex::encode(w.verifying_key().to_bytes()));
        e.operator_org = org.into();
        dir.witnesses.push(e);
        receipts.push(WitnessReceipt::sign(&w, &later, 2000));
    }
    let oc = ObservedCheckpoint {
        checkpoint: later,
        receipts,
    };
    // Same checkpoint passed in twice -- must count once, not twice.
    let result = silence_proof(&write_receipt, &[], &[oc.clone(), oc], &dir, 2);
    assert!(
        matches!(result, SilenceProofResult::Inconclusive { witnessed_checkpoints_seen: 1, .. }),
        "the same checkpoint observed twice must count as ONE distinct witnessed checkpoint: {result:?}"
    );
}

/// Finding 07 (POLISH), part 2: silence_proof no longer counts a
/// checkpoint from an unrelated log toward this log's censorship
/// accusation.
#[test]
fn finding07_silence_proof_rejects_foreign_log_checkpoints() {
    let a = IdentityKeypair::generate();
    let write_receipt = WriteReceipt::sign(
        &SigningKey::from_bytes(&a.to_bytes()),
        &"ab".repeat(32),
        1,
        1000,
    );
    let b = IdentityKeypair::generate();
    let foreign = SignedTreeHead::sign(&SigningKey::from_bytes(&b.to_bytes()), 9, &[7u8; 32], 3000);
    let w = SigningKey::generate(&mut rand::rngs::OsRng);
    let mut dir = WitnessDirectory::default();
    dir.witnesses
        .push(mk_witness_entry(hex::encode(w.verifying_key().to_bytes())));
    let r = WitnessReceipt::sign(&w, &foreign, 3000);
    let later = vec![ObservedCheckpoint {
        checkpoint: foreign.clone(),
        receipts: vec![r.clone()],
    }];
    let result = silence_proof(&write_receipt, &[], &later, &dir, 1);
    assert!(
        matches!(result, SilenceProofResult::Inconclusive { witnessed_checkpoints_seen: 0, .. }),
        "a checkpoint signed by a DIFFERENT log identity must never count toward this log's censorship accusation: {result:?}"
    );
}

/// Final pre-publish review: a silence proof must be bound to the event.
/// With a plain checkpoint as the "receipt", any payload hash could be
/// "proven" censored against any witnessed log. Now the receipt is a
/// signed commitment to one payload hash, and the whole chain holds up.
#[test]
fn silence_proof_requires_a_signed_commitment_to_the_event() {
    use witness_log_core::identity::IdentityKeypair;
    use witness_log_core::log::WitnessLog;
    let id = IdentityKeypair::generate();
    let key = SigningKey::from_bytes(&id.to_bytes());
    let mut log = WitnessLog::resume(id, 0);
    let idx = log.append_intent(b"the event");
    let receipt = log.write_receipt(idx).expect("leaf exists");
    assert!(receipt.verify().is_ok());
    assert!(log.write_receipt(99).is_none());

    // Two later checkpoints from this log, each cosigned by two
    // independent operators.
    let ws: Vec<SigningKey> = (0..2)
        .map(|_| SigningKey::generate(&mut rand::rngs::OsRng))
        .collect();
    let mut dir = WitnessDirectory::default();
    for (i, w) in ws.iter().enumerate() {
        let mut e = mk_witness_entry(hex::encode(w.verifying_key().to_bytes()));
        e.operator_org = format!("org {i}");
        dir.witnesses.push(e);
    }
    let mut later = vec![];
    for (size, b) in [(5u64, 2u8), (9, 3)] {
        let cp = SignedTreeHead::sign(&key, size, &[b; 32], 5000 + size);
        later.push(ObservedCheckpoint {
            receipts: ws
                .iter()
                .map(|w| WitnessReceipt::sign(w, &cp, 5000 + size))
                .collect(),
            checkpoint: cp,
        });
    }

    // Present in the caller's view: not censored, whatever the witnesses say.
    assert!(matches!(
        silence_proof(&receipt, log.leaves(), &later, &dir, 2),
        SilenceProofResult::Present { leaf_index: 0 }
    ));
    // Absent from an empty view: since review III (H1) that proves
    // nothing, because no leaves reproduce the witnessed roots. (The full
    // Censored path is in tests/review3_silence_proof.rs.)
    assert!(matches!(
        silence_proof(&receipt, &[], &later, &dir, 2),
        SilenceProofResult::Inconclusive {
            witnessed_checkpoints_seen: 2,
            ..
        }
    ));
    // A receipt whose payload hash was swapped after signing proves nothing.
    let mut forged = receipt.clone();
    forged.payload_hash = "ff".repeat(32);
    assert!(matches!(
        silence_proof(&forged, &[], &later, &dir, 2),
        SilenceProofResult::Inconclusive {
            witnessed_checkpoints_seen: 0,
            ..
        }
    ));
    // A receipt signed by someone other than the log proves nothing about it.
    let other = SigningKey::generate(&mut rand::rngs::OsRng);
    let foreign = WriteReceipt::sign(&other, &receipt.payload_hash, 0, 1);
    assert!(matches!(
        silence_proof(&foreign, &[], &later, &dir, 2),
        SilenceProofResult::Inconclusive {
            witnessed_checkpoints_seen: 0,
            ..
        }
    ));
}
