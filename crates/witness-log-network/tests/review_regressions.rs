//! Regression tests for the pre-launch security review (28 findings, 8
//! executable PoCs, all reproduced and confirmed real against v0.1.0 as
//! shipped). This file is the inverse of the original `review_poc.rs`:
//! same eight attack constructions, now asserting that each one is
//! BLOCKED. If any of these tests goes red, one of the eight findings
//! below has regressed.

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use witness_log_core::identity::IdentityKeypair;
use witness_log_core::leaf::{Leaf, LeafType};
use witness_log_core::log::WitnessLog;
use witness_log_core::merkle::{leaf_hash, verify_inclusion, MerkleTree};
use witness_log_core::sth::{SignedTreeHead, WriteReceipt};
use witness_log_network::*;

fn now() -> u64 {
    1_700_000_000_000
}

/// Finding 01 (CRITICAL): a dossier attributing a fabricated log to a
/// victim's identity is now caught by the identity-binding check and
/// reaches Invalid (Diverged before 0.5.0), whether or not the verifier pins an expected identity.
#[test]
fn finding01_mismatched_identity_claim_is_caught_even_unpinned() {
    let victim = IdentityKeypair::generate();
    let victim_pubkey = victim.public_hex();

    let attacker = IdentityKeypair::generate();
    let attacker_bytes = attacker.to_bytes();
    let mut fake = WitnessLog::resume(attacker, 0);
    fake.append_intent(br#"{"tool":"transfer_funds","args":{"amount_usd":10000000}}"#);
    let sth = fake.checkpoint(&SigningKey::from_bytes(&attacker_bytes));

    let dossier = Dossier {
        identity_pubkey: victim_pubkey.clone(), // the lie
        leaves: fake.leaves().to_vec(),
        checkpoint: sth.clone(),
        witness_receipts: vec![],
        witness_directory: WitnessDirectory::default(),
        key_bindings: vec![],
        revocations: vec![],
    };

    // Even with NO out-of-band pin at all, self-consistency alone catches
    // this: the dossier's own identity_pubkey doesn't match the key that
    // signed its own checkpoint.
    let report = dossier.verify(0.66, &VerifyContext::default());
    assert!(
        !report.identity_bound,
        "mismatched identity claim must not be reported as bound"
    );
    assert_eq!(
        report.verdict,
        Verdict::Invalid,
        "identity mismatch must produce Invalid"
    );
    assert!(!report.is_internally_consistent());

    // And if a verifier DOES pin the victim's real identity, expecting to
    // confirm it's really them, that's also rejected.
    let ctx = VerifyContext {
        expected_identity_pubkey: Some(&victim_pubkey),
        trusted_directory: None,
        min_receipts: None,
        revocations: &[],
        known_heads: &[],
        evidence: &[],
    };
    let pinned_report = dossier.verify(0.66, &ctx);
    assert_eq!(pinned_report.verdict, Verdict::Invalid);
}

/// Finding 02 (CRITICAL): a fabricated dossier can no longer reach
/// Witnessed by shipping its own "independent" witnesses and directory —
/// evaluate_quorum/verify only trust a directory the CALLER supplies.
/// With no trusted_directory at all, the verdict is capped at Unanchored,
/// and WitnessPolicy::production() correctly rejects it.
#[test]
fn finding02_fabricated_dossier_capped_at_unanchored_not_witnessed() {
    let attacker = IdentityKeypair::generate();
    let attacker_bytes = attacker.to_bytes();
    let mut fake = WitnessLog::resume(attacker, 0);
    fake.append_intent(b"entirely invented history");
    let sth = fake.checkpoint(&SigningKey::from_bytes(&attacker_bytes));

    // Attacker generates its own "independent" witnesses AND its own
    // directory -- exactly as before. The difference is what verify()
    // does with them now.
    let mut receipts = Vec::new();
    let mut directory = WitnessDirectory::default();
    for org in [
        "totally-real-auditors-llc",
        "definitely-independent-gmbh",
        "third-party-labs",
    ] {
        let k = SigningKey::generate(&mut OsRng);
        directory.witnesses.push(WitnessEntry {
            name: org.into(),
            operator_org: org.into(),
            url: format!("https://{org}.example"),
            pubkey: hex::encode(k.verifying_key().to_bytes()),
            runtime: WitnessRuntime::Human,
            compute_provider: Some(format!("{org}-infra")),
            is_project_operated: false,
        });
        receipts.push(WitnessReceipt::sign(&k, &sth, now()));
    }

    let dossier = Dossier {
        identity_pubkey: fake.identity_pubkey_hex(),
        leaves: fake.leaves().to_vec(),
        checkpoint: sth.clone(),
        witness_receipts: receipts,
        witness_directory: directory, // still shipped -- but display-only now
        key_bindings: vec![],
        revocations: vec![],
    };

    // No trusted_directory supplied -> the dossier's own directory is
    // never consulted for trust purposes, regardless of what it contains.
    let report = dossier.verify(0.66, &VerifyContext::default());
    assert_eq!(
        report.verdict,
        Verdict::Unanchored,
        "a fabricated dossier with a self-authored directory must cap at Unanchored, not reach {:?}",
        report.verdict
    );
    assert!(
        report.quorum.is_none(),
        "quorum must not even be computed without a trusted directory"
    );
    assert!(
        WitnessPolicy::production()
            .evaluate(&report, sth.timestamp_ms, sth.timestamp_ms)
            .is_err(),
        "an unanchored fabricated dossier must fail the production policy"
    );
}

/// Finding 03 (CRITICAL): one witness key resigning the same checkpoint at
/// different timestamps now counts once, not once per receipt — and only
/// if that key is present in the (caller-supplied, trusted) directory.
#[test]
fn finding03_one_witness_cannot_forge_a_multi_receipt_quorum() {
    let identity = IdentityKeypair::generate();
    let key = SigningKey::from_bytes(&identity.to_bytes());
    let sth = SignedTreeHead::sign(&key, 5, &[9u8; 32], now());

    let w = SigningKey::generate(&mut OsRng);
    let mut directory = WitnessDirectory::default();
    directory.witnesses.push(WitnessEntry {
        name: "lonely-witness".into(),
        operator_org: "one-org".into(),
        url: "https://one.example".into(),
        pubkey: hex::encode(w.verifying_key().to_bytes()),
        runtime: WitnessRuntime::Human,
        compute_provider: Some("one-infra".into()),
        is_project_operated: false,
    });

    // Same witness, same checkpoint, three different witnessed_at_ms
    // values -- three distinct, individually valid signed receipts.
    let receipts: Vec<_> = (0..3)
        .map(|i| WitnessReceipt::sign(&w, &sth, now() + i))
        .collect();

    let q = evaluate_quorum(&sth, &receipts, &directory, 0.66);
    assert_eq!(
        q.valid_receipts, 1,
        "one distinct key must count once, regardless of how many times it resigned"
    );
    assert!(
        q.quorum_fraction <= 1.0,
        "quorum_fraction must never exceed 1.0: got {}",
        q.quorum_fraction
    );

    // And a receipt from a key absent from the directory must not count
    // at all, even if the signature itself is perfectly valid.
    let outsider = SigningKey::generate(&mut OsRng);
    let outsider_receipt = WitnessReceipt::sign(&outsider, &sth, now());
    let q2 = evaluate_quorum(&sth, &[outsider_receipt], &directory, 0.66);
    assert_eq!(
        q2.valid_receipts, 0,
        "a valid signature from a key absent from the trusted directory must not count"
    );
}

/// Finding 13 (HIGH): inclusion proofs are no longer malleable at the
/// front. Prepending junk to a valid proof must fail, matching the
/// existing (correct) behavior for junk appended at the end.
#[test]
fn finding13_inclusion_proof_rejects_extra_leading_elements() {
    let mut t = MerkleTree::new();
    for i in 0..8u8 {
        t.append(leaf_hash(&[i]));
    }
    let root = t.root();
    let proof = t.inclusion_proof(3, 8).unwrap();
    assert!(
        verify_inclusion(&leaf_hash(&[3]), 3, 8, &proof, &root),
        "the real proof must still verify"
    );

    let mut malleable = vec![[0xAB; 32]]; // junk prepended
    malleable.extend_from_slice(&proof);
    assert!(
        !verify_inclusion(&leaf_hash(&[3]), 3, 8, &malleable, &root),
        "a proof with extra leading elements must be rejected, not silently accepted"
    );
}

/// Finding 04 (CRITICAL): two structurally different leaves that
/// previously collided to the same canonical bytes (and therefore the
/// same Merkle leaf hash) now produce distinct encodings, because every
/// variable-length field is length-prefixed.
#[test]
fn finding04_canonical_bytes_no_longer_ambiguous() {
    let mk = |session: &str, payload: &str| Leaf {
        index: 0,
        leaf_type: LeafType::ActiveIntent.tag(),
        timestamp_ms: 1,
        session_pubkey: session.into(),
        payload_hash: payload.into(),
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
    };
    let a = mk("aaaabbbb", "cccc");
    let b = mk("aaaa", "bbbbcccc");
    assert_ne!(
        a.canonical_bytes(),
        b.canonical_bytes(),
        "two distinct leaves must no longer share one canonical encoding"
    );
    assert_ne!(
        leaf_hash(&a.canonical_bytes()),
        leaf_hash(&b.canonical_bytes())
    );
}

/// Finding 11 (HIGH): silence_proof now counts distinct WITNESSED
/// checkpoints, not receipts. Two witnesses countersigning the SAME
/// checkpoint must not manufacture a censorship accusation.
#[test]
fn finding11_silence_proof_no_longer_confuses_receipts_with_checkpoints() {
    let identity = IdentityKeypair::generate();
    let key = SigningKey::from_bytes(&identity.to_bytes());
    let mut log = WitnessLog::resume(IdentityKeypair::generate(), 0);
    log.append_intent(b"some event that IS in the log");
    let later_checkpoint = SignedTreeHead::sign(&key, log.tree_size(), &[3u8; 32], now());

    let mut directory = WitnessDirectory::default();
    let mut receipts = Vec::new();
    for i in 0..2u64 {
        let w = SigningKey::generate(&mut OsRng);
        directory.witnesses.push(WitnessEntry {
            name: format!("w{i}"),
            operator_org: format!("org{i}"),
            url: format!("https://w{i}.example"),
            pubkey: hex::encode(w.verifying_key().to_bytes()),
            runtime: WitnessRuntime::Human,
            compute_provider: None,
            is_project_operated: false,
        });
        receipts.push(WitnessReceipt::sign(&w, &later_checkpoint, now()));
    }

    // ONE checkpoint, corroborated by TWO receipts.
    let observed = vec![ObservedCheckpoint {
        checkpoint: later_checkpoint,
        receipts,
    }];

    let receipt = WriteReceipt::sign(&key, &"ab".repeat(32), 0, now() - 1000);
    let result = silence_proof(
        &receipt,
        log.leaves(),
        &observed,
        &directory,
        2, // requires 2 DISTINCT witnessed checkpoints
    );
    assert!(
        matches!(result, SilenceProofResult::Inconclusive { .. }),
        "one checkpoint corroborated by two receipts must not count as two witnessed checkpoints: {result:?}"
    );
}

/// Finding 14 (HIGH): structurally invalid leaves (duplicate indices,
/// timestamps running backwards, an undefined leaf type tag) are now
/// rejected by validate_sequence and produce Invalid.
#[test]
fn finding14_structurally_invalid_leaves_no_longer_verify() {
    let identity = IdentityKeypair::generate();
    let bytes = identity.to_bytes();
    let key = SigningKey::from_bytes(&bytes);

    let mk = |index: u64, leaf_type: u8, ts: u64| Leaf {
        index,
        leaf_type,
        timestamp_ms: ts,
        session_pubkey: "00".repeat(32),
        payload_hash: "11".repeat(32),
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
    };
    let leaves = vec![
        mk(0, 0x01, 2_000),
        mk(0, 0xFE, 1_000), // duplicate index, undefined leaf type, time goes backwards
        mk(99, 0x01, 500),  // index unrelated to position
    ];

    let mut tree = MerkleTree::new();
    for l in &leaves {
        tree.append(leaf_hash(&l.canonical_bytes()));
    }
    let sth = SignedTreeHead::sign(&key, tree.size(), &tree.root(), now());
    let identity_pubkey = identity.public_hex();
    let dossier = Dossier {
        identity_pubkey,
        leaves,
        checkpoint: sth,
        witness_receipts: vec![],
        witness_directory: WitnessDirectory::default(),
        key_bindings: vec![],
        revocations: vec![],
    };
    let report = dossier.verify(0.66, &VerifyContext::default());
    assert!(
        !report.leaves_structurally_valid,
        "malformed leaf sequence must fail structural validation"
    );
    assert_eq!(report.verdict, Verdict::Invalid);
    assert!(
        !report.is_internally_consistent(),
        "duplicate indices, reversed timestamps, and an undefined leaf tag must not verify"
    );
}

/// Finding 12 (HIGH): sig_alg and signer_pubkey are now covered by the STH
/// signature. Mutating sig_alg after signing must invalidate the
/// signature itself, not rely solely on the algorithm allow-list check.
#[test]
fn finding12_sig_alg_now_covered_by_the_signature() {
    let identity = IdentityKeypair::generate();
    let key = SigningKey::from_bytes(&identity.to_bytes());
    let sth = SignedTreeHead::sign(&key, 1, &[1u8; 32], now());
    let mut mutated = sth.clone();
    mutated.sig_alg = "ml-dsa-65".into();
    // The signature itself is unchanged (same bytes)...
    assert_eq!(
        hex::decode(&sth.signature).unwrap(),
        hex::decode(&mutated.signature).unwrap()
    );
    // ...but it verifies over a message that now includes sig_alg, so a
    // mutated sig_alg makes the signature invalid on its own terms, not
    // just rejected by the allow-list.
    assert!(mutated.verify().is_err());
    // The original allow-list defense-in-depth still applies independently.
    let mut still_ed25519_but_wrong_alg_string = sth.clone();
    still_ed25519_but_wrong_alg_string.sig_alg = "dilithium3".into();
    assert!(still_ed25519_but_wrong_alg_string.verify().is_err());
}

/// Finding 06 (HIGH): key bindings and revocations can now reach a
/// verifier at all — Dossier previously had no field for either, so
/// SPEC.md §5's normative "leaves signed by a revoked identity's sessions
/// after as_of_ms MUST be treated as untrusted" was unimplementable.
mod finding06_key_bindings_and_revocations {
    use super::*;

    fn build_dossier(
        identity: &IdentityKeypair,
        leaves: Vec<Leaf>,
        key_bindings: Vec<witness_log_core::identity::KeyBindingStatement>,
        revocations: Vec<witness_log_core::identity::RevocationStatement>,
    ) -> Dossier {
        let key = SigningKey::from_bytes(&identity.to_bytes());
        let mut tree = MerkleTree::new();
        for l in &leaves {
            tree.append(leaf_hash(&l.canonical_bytes()));
        }
        let sth = SignedTreeHead::sign(&key, tree.size(), &tree.root(), now());
        Dossier {
            identity_pubkey: identity.public_hex(),
            leaves,
            checkpoint: sth,
            witness_receipts: vec![],
            witness_directory: WitnessDirectory::default(),
            key_bindings,
            revocations,
        }
    }

    fn mk_leaf(index: u64, session_pubkey: &str, ts: u64) -> Leaf {
        Leaf {
            index,
            leaf_type: LeafType::ActiveIntent.tag(),
            timestamp_ms: ts,
            session_pubkey: session_pubkey.to_string(),
            payload_hash: "11".repeat(32),
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

    #[test]
    fn no_bindings_supplied_is_not_a_failure() {
        // The common, pre-existing case: a dossier with leaves but no
        // binding/revocation data at all must NOT be treated as a
        // failure -- it means provenance wasn't asserted, not that it
        // failed. Every dossier built before this field existed must
        // keep verifying.
        let identity = IdentityKeypair::generate();
        let leaves = vec![mk_leaf(0, &"aa".repeat(32), 1000)];
        let dossier = build_dossier(&identity, leaves, vec![], vec![]);
        let report = dossier.verify(0.66, &VerifyContext::default());
        assert!(
            report.bindings_valid,
            "no bindings supplied must default to valid, not invalid"
        );
    }

    #[test]
    fn leaf_from_unbound_session_is_rejected_once_any_binding_is_supplied() {
        let identity = IdentityKeypair::generate();
        let session_a = witness_log_core::identity::SessionKeypair::generate();
        let binding_a = identity.bind_session(&session_a.verifying_key(), 0, 500, None);
        // Two leaves: one from the bound session, one from a DIFFERENT,
        // unbound session key. Supplying binding_a opts into full
        // coverage -- the second leaf must now be caught.
        let leaves = vec![
            mk_leaf(0, &session_a.public_hex(), 600),
            mk_leaf(1, &"ff".repeat(32), 700), // no covering binding
        ];
        let dossier = build_dossier(&identity, leaves, vec![binding_a], vec![]);
        let report = dossier.verify(0.66, &VerifyContext::default());
        assert!(
            !report.bindings_valid,
            "a leaf from a session with no covering binding must be rejected"
        );
        assert_eq!(report.verdict, Verdict::Invalid);
    }

    #[test]
    fn leaf_after_binding_expiry_is_rejected() {
        let identity = IdentityKeypair::generate();
        let session = witness_log_core::identity::SessionKeypair::generate();
        let binding = identity.bind_session(&session.verifying_key(), 0, 500, Some(1000));
        let leaves = vec![mk_leaf(0, &session.public_hex(), 1001)]; // 1ms past not_after_ms
        let dossier = build_dossier(&identity, leaves, vec![binding], vec![]);
        let report = dossier.verify(0.66, &VerifyContext::default());
        assert!(
            !report.bindings_valid,
            "a leaf timestamped after its binding's not_after_ms must be rejected"
        );
    }

    #[test]
    fn leaf_at_or_after_revocation_is_rejected() {
        let identity = IdentityKeypair::generate();
        let session = witness_log_core::identity::SessionKeypair::generate();
        let binding = identity.bind_session(&session.verifying_key(), 0, 500, None);
        let revocation = identity.revoke(2000, "suspected compromise");
        let leaves = vec![mk_leaf(0, &session.public_hex(), 2000)]; // exactly at as_of_ms
        let dossier = build_dossier(&identity, leaves, vec![binding], vec![revocation]);
        let report = dossier.verify(0.66, &VerifyContext::default());
        assert!(
            !report.bindings_valid,
            "a leaf timestamped at or after the revocation must be rejected"
        );
    }

    #[test]
    fn fully_covered_and_unexpired_leaves_verify_clean() {
        let identity = IdentityKeypair::generate();
        let session = witness_log_core::identity::SessionKeypair::generate();
        let binding = identity.bind_session(&session.verifying_key(), 0, 500, Some(5000));
        let leaves = vec![
            mk_leaf(0, &session.public_hex(), 600),
            mk_leaf(1, &session.public_hex(), 700),
        ];
        let dossier = build_dossier(&identity, leaves, vec![binding], vec![]);
        let report = dossier.verify(0.66, &VerifyContext::default());
        assert!(
            report.bindings_valid,
            "leaves within a valid, unexpired binding's window must verify"
        );
        assert!(report.is_internally_consistent());
    }
}
