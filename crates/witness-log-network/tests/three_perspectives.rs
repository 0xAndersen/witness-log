//! Thirty use-case explorations from three perspectives.
//!
//! Each module below is one "agent" with a distinct motive, exploring
//! ten things that agent would actually try. None are written to confirm
//! the library works; they're written to find where it doesn't do what
//! that person needs. Where the obvious approach fails or is awkward,
//! that's recorded as a finding in the summary at the bottom.

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use witness_log_core::identity::IdentityKeypair;
use witness_log_core::leaf::Leaf;
use witness_log_core::log::WitnessLog;
use witness_log_core::merkle::{leaf_hash, verify_consistency, verify_inclusion, MerkleTree};
use witness_log_core::sth::SignedTreeHead;
use witness_log_network::*;

fn fresh() -> (IdentityKeypair, [u8; 32], WitnessLog) {
    let id = IdentityKeypair::generate();
    let seed = id.to_bytes();
    let log = WitnessLog::resume(IdentityKeypair::from_bytes(&seed), 0);
    (id, seed, log)
}

fn tree_of(leaves: &[Leaf]) -> MerkleTree {
    let mut t = MerkleTree::new();
    for l in leaves {
        t.append(leaf_hash(&l.canonical_bytes()));
    }
    t
}

fn dossier_with(leaves: Vec<Leaf>, id_hex: &str, cp: SignedTreeHead, log: &WitnessLog) -> Dossier {
    Dossier {
        identity_pubkey: id_hex.to_string(),
        leaves,
        checkpoint: cp,
        witness_receipts: vec![],
        witness_directory: WitnessDirectory::default(),
        key_bindings: log.all_bindings(),
        revocations: vec![],
    }
}

// ═══════════════════════════════════════════════════════════════════
// AGENT A — THE SKEPTIC. "I don't believe this catches anything."
// ═══════════════════════════════════════════════════════════════════
mod skeptic {
    use super::*;

    /// A1. Replay an old receipt onto a newer checkpoint.
    #[test]
    fn a1_old_receipt_does_not_validate_new_checkpoint() {
        let (id, seed, mut log) = fresh();
        let key = SigningKey::from_bytes(&seed);
        log.append_intent(b"one");
        let cp1 = log.checkpoint(&key);
        let w = SigningKey::generate(&mut OsRng);
        let old_receipt = WitnessReceipt::sign(&w, &cp1, cp1.timestamp_ms);
        log.append_intent(b"two");
        let cp2 = log.checkpoint(&key);
        assert!(
            old_receipt.verify(&cp2).is_err(),
            "receipt for size 1 must not validate size 2"
        );
        let _ = id;
    }

    /// A2. Reorder two leaves and keep the original checkpoint.
    #[test]
    fn a2_reordered_leaves_break_continuity() {
        let (id, seed, mut log) = fresh();
        log.append_intent(b"first");
        log.append_intent(b"second");
        let cp = log.checkpoint(&SigningKey::from_bytes(&seed));
        let mut leaves = log.leaves().to_vec();
        leaves.swap(0, 1);
        let d = dossier_with(leaves, &id.public_hex(), cp, &log);
        let r = d.verify(0.0, &VerifyContext::default());
        assert_eq!(r.verdict, Verdict::Invalid);
        // Caught twice: index != position fails structural validation,
        // and the root changes anyway.
        assert!(!r.leaves_structurally_valid);
    }

    /// A3. Drop the last leaf and re-sign at the smaller size — a
    /// "selective disclosure" that pretends the last action never
    /// happened. Each copy verifies alone; this is why witnesses exist.
    #[test]
    fn a3_truncation_is_only_caught_by_comparison() {
        let (id, seed, mut log) = fresh();
        let key = SigningKey::from_bytes(&seed);
        log.append_intent(b"approved");
        log.append_intent(b"then reversed it"); // the inconvenient leaf
        let full_cp = log.checkpoint(&key);
        let mut truncated = log.leaves().to_vec();
        truncated.pop();
        let t = tree_of(&truncated);
        let trunc_cp = SignedTreeHead::sign(&key, t.size(), &t.root(), full_cp.timestamp_ms);
        let d = dossier_with(truncated.clone(), &id.public_hex(), trunc_cp.clone(), &log);
        let r = d.verify(0.0, &VerifyContext::default());
        assert!(
            r.is_internally_consistent(),
            "the truncated copy verifies on its own"
        );
        // But a consistency proof from the truncated to the full head
        // proves the full one extends it -- and NO proof exists from the
        // full head back to the truncated one, because you can't un-append.
        let full_tree = tree_of(log.leaves());
        let proof = full_tree
            .consistency_proof(1, 2)
            .expect("1 -> 2 is a valid extension");
        assert!(verify_consistency(
            1,
            &t.root(),
            2,
            &full_tree.root(),
            &proof
        ));
        // FINDING: nothing in the library flags that cp1 and cp2 are both
        // signed at the SAME timestamp by the same key -- a hint that one
        // is a retroactive rewrite. `witness-log diff` compares leaves but
        // not checkpoint metadata.
    }

    /// A4. Use a revoked identity's session after the revocation.
    #[test]
    fn a4_leaf_after_revocation_is_rejected() {
        let (id, seed, mut log) = fresh();
        log.append_intent(b"before revocation");
        let cp = log.checkpoint(&SigningKey::from_bytes(&seed));
        let revoked_at = log.leaves()[0].timestamp_ms; // revoke AT the leaf's time
        let revocation = id.revoke(revoked_at, "key compromised");
        let mut d = dossier_with(log.leaves().to_vec(), &id.public_hex(), cp, &log);
        d.revocations = vec![revocation];
        let r = d.verify(0.0, &VerifyContext::default());
        assert!(!r.bindings_valid, "a leaf at or after revocation must fail");
        assert_eq!(r.verdict, Verdict::Invalid);
    }

    /// A5. Ship a key binding signed by a DIFFERENT identity.
    #[test]
    fn a5_foreign_binding_is_rejected_outright() {
        let (id, seed, mut log) = fresh();
        log.append_intent(b"x");
        let cp = log.checkpoint(&SigningKey::from_bytes(&seed));
        let other = IdentityKeypair::generate();
        let session_vk = {
            let b: [u8; 32] = hex::decode(&log.current_binding().session_pubkey)
                .unwrap()
                .try_into()
                .unwrap();
            ed25519_dalek::VerifyingKey::from_bytes(&b).unwrap()
        };
        let foreign = other.bind_session(&session_vk, 0, 0, None);
        let mut d = dossier_with(log.leaves().to_vec(), &id.public_hex(), cp, &log);
        d.key_bindings.push(foreign);
        let r = d.verify(0.0, &VerifyContext::default());
        assert!(
            !r.bindings_valid,
            "a binding naming another identity must reject the dossier"
        );
    }

    /// A6. Mix in a leaf from a completely different log.
    #[test]
    fn a6_leaf_from_another_log_is_caught() {
        let (id, seed, mut log) = fresh();
        log.append_intent(b"mine");
        let (_, _, mut other) = fresh();
        other.append_intent(b"theirs");
        let mut leaves = log.leaves().to_vec();
        let mut stolen = other.leaves()[0].clone();
        stolen.index = 1;
        leaves.push(stolen);
        let t = tree_of(&leaves);
        let cp = SignedTreeHead::sign(
            &SigningKey::from_bytes(&seed),
            t.size(),
            &t.root(),
            1_700_000_000_000,
        );
        let d = dossier_with(leaves, &id.public_hex(), cp, &log);
        let r = d.verify(0.0, &VerifyContext::default());
        // The foreign leaf's session key has no binding to THIS identity.
        assert!(
            !r.bindings_valid,
            "a leaf from another log's session must fail binding"
        );
        assert_eq!(r.verdict, Verdict::Invalid);
    }

    /// A7. Duplicate a leaf (replay an action).
    #[test]
    fn a7_duplicated_leaf_is_caught() {
        let (id, seed, mut log) = fresh();
        log.append_intent(b"pay once");
        let mut leaves = log.leaves().to_vec();
        let mut dup = leaves[0].clone();
        dup.index = 1; // fix the index so structural check passes
        leaves.push(dup);
        let t = tree_of(&leaves);
        let cp = SignedTreeHead::sign(
            &SigningKey::from_bytes(&seed),
            t.size(),
            &t.root(),
            1_700_000_000_000,
        );
        let d = dossier_with(leaves, &id.public_hex(), cp, &log);
        let r = d.verify(0.0, &VerifyContext::default());
        // FINDING: a duplicated leaf with a corrected index is internally
        // consistent. Nothing in the format makes payload_hash unique per
        // position -- the salt is per (index, payload) at append time, but
        // a copied leaf carries its original hash. Detecting "the same
        // action recorded twice" requires the verifier to notice two
        // leaves with identical payload_hash, which the library does not
        // do. Whether that is a bug depends on whether an agent can
        // legitimately do the same thing twice -- it can.
        assert!(r.is_internally_consistent());
    }

    /// A8. Witness receipt timestamped before the checkpoint existed.
    #[test]
    fn a8_receipt_from_the_past_is_accepted_but_visible() {
        let (id, seed, mut log) = fresh();
        log.append_intent(b"x");
        let cp = log.checkpoint(&SigningKey::from_bytes(&seed));
        let w = SigningKey::generate(&mut OsRng);
        let mut dir = WitnessDirectory::default();
        dir.witnesses.push(WitnessEntry::independent(
            "w",
            "org",
            "https://w.x",
            hex::encode(w.verifying_key().to_bytes()),
            None,
        ));
        // Witnessed "a year before" the checkpoint was signed.
        let receipt = WitnessReceipt::sign(&w, &cp, cp.timestamp_ms - 31_536_000_000);
        let q = evaluate_quorum(&cp, &[receipt], &dir, 0.0);
        // FINDING: the receipt counts. Nothing checks witnessed_at_ms >=
        // checkpoint.timestamp_ms. Both are self-asserted by their signers
        // so there's no ground truth, but a receipt claiming to predate
        // the thing it witnessed is at minimum worth surfacing.
        assert_eq!(q.valid_receipts, 1);
        assert!(q.newest_trusted_witness_ms.unwrap() < cp.timestamp_ms);
        let _ = id;
    }

    /// A9. Edit a redaction tombstone to point at a different leaf.
    #[test]
    fn a9_tampered_tombstone_breaks_the_root() {
        let (id, seed, mut log) = fresh();
        log.append_intent(b"keep");
        let pii = log.append_memory(b"erase me");
        log.forget(pii);
        let cp = log.checkpoint(&SigningKey::from_bytes(&seed));
        let mut leaves = log.leaves().to_vec();
        let tomb = leaves
            .iter_mut()
            .find(|l| l.redacted_index.is_some())
            .unwrap();
        tomb.redacted_index = Some(0); // claim leaf 0 was the one erased
        let d = dossier_with(leaves, &id.public_hex(), cp, &log);
        let r = d.verify(0.0, &VerifyContext::default());
        assert!(
            !r.merkle_continuity_valid,
            "the tombstone is committed; editing it changes the root"
        );
    }

    /// A10. Claim a huge tree_size with a tiny leaf set.
    #[test]
    fn a10_inflated_tree_size_is_caught() {
        let (id, seed, mut log) = fresh();
        log.append_intent(b"x");
        let mut cp = log.checkpoint(&SigningKey::from_bytes(&seed));
        cp.tree_size = 1_000_000;
        let d = dossier_with(log.leaves().to_vec(), &id.public_hex(), cp, &log);
        let r = d.verify(0.0, &VerifyContext::default());
        assert!(
            !r.checkpoint_signature_valid,
            "tree_size is signed; editing it breaks the signature"
        );
    }
}

// ═══════════════════════════════════════════════════════════════════
// AGENT B — THE INTEGRATOR. "Will this survive my production?"
// ═══════════════════════════════════════════════════════════════════
mod integrator {
    use super::*;
    use witness_log_core::journal::JournaledLog;

    fn tmp(name: &str) -> String {
        std::env::temp_dir()
            .join(format!("persp-{name}-{}.jsonl", std::process::id()))
            .to_str()
            .unwrap()
            .to_string()
    }

    /// B1. A 50MB payload. The journal caps lines at 16MB.
    #[test]
    fn b1_oversized_payload_behaviour() {
        let (_, seed, _) = fresh();
        let p = tmp("big");
        let mut log = JournaledLog::create(&p, IdentityKeypair::from_bytes(&seed)).unwrap();
        let huge = vec![b'x'; 50 * 1024 * 1024];
        // The payload is HASHED, not stored -- so the leaf line is small
        // regardless of payload size. This should succeed.
        let r = log.append_intent(&huge);
        assert!(
            r.is_ok(),
            "a 50MB payload must append: only its hash is stored"
        );
        log.sync().unwrap();
        drop(log);
        let (re, _) = JournaledLog::resume(&p).unwrap();
        assert_eq!(re.log().tree_size(), 1);
        std::fs::remove_file(&p).ok();
        // Clean. The hash-not-store design means payload size never
        // reaches the journal line cap.
    }

    /// B2. Resume a journal, then resume it AGAIN without closing the first.
    #[test]
    fn b2_double_resume_is_a_split_brain() {
        let (_, seed, _) = fresh();
        let p = tmp("double");
        {
            let mut l = JournaledLog::create(&p, IdentityKeypair::from_bytes(&seed)).unwrap();
            l.append_intent(b"base").unwrap();
            l.sync().unwrap();
        }
        let (mut a, _) = JournaledLog::resume(&p).unwrap();
        // FIXED: the second resume is refused by an exclusive lock, so two
        // live handles can never interleave their sessions' leaves.
        let second = JournaledLog::resume(&p);
        assert!(
            second.is_err(),
            "a second live handle on one journal must be refused"
        );
        assert_eq!(
            second.err().map(|e| e.kind()),
            Some(std::io::ErrorKind::AlreadyExists)
        );
        a.append_intent(b"from a").unwrap();
        a.sync().unwrap();
        drop(a); // releases the lock
                 // After the holder is gone, resume works again.
        let (b, _) = JournaledLog::resume(&p).unwrap();
        assert_eq!(b.log().tree_size(), 2);
        drop(b);
        // A lock naming a live process is never stolen: our own PID stands
        // in for a live holder.
        std::fs::write(format!("{p}.lock"), format!("{}\n", std::process::id())).unwrap();
        assert!(JournaledLog::resume(&p).is_err(), "live lock blocks");
        JournaledLog::force_unlock(&p).unwrap();
        assert!(JournaledLog::resume(&p).is_ok(), "force_unlock recovers");
        // A lock left by a PID that is no longer running (a hard crash) is
        // recovered without intervention on Linux (0.3.2); elsewhere it
        // still needs force_unlock.
        std::fs::write(format!("{p}.lock"), "4194304\n").unwrap();
        let after_crash = JournaledLog::resume(&p);
        if cfg!(target_os = "linux") {
            assert!(after_crash.is_ok(), "dead-PID lock recovers automatically");
        } else {
            assert!(after_crash.is_err(), "stale lock blocks without /proc");
            JournaledLog::force_unlock(&p).unwrap();
            assert!(JournaledLog::resume(&p).is_ok(), "force_unlock recovers");
        }
        std::fs::remove_file(&p).ok();
        std::fs::remove_file(format!("{p}.lock")).ok();
        std::fs::remove_file(format!("{p}.salts")).ok();
    }

    /// B3. Journal file deleted out from under a live log.
    // Unix-only: Windows refuses to delete a file that is still open,
    // and exposes no stable inode to compare, so this scenario cannot
    // occur (and cannot be detected) there.
    #[cfg(unix)]
    #[test]
    fn b3_deleted_journal_is_detected_at_sync() {
        let (_, seed, _) = fresh();
        let p = tmp("deleted");
        let mut log = JournaledLog::create(&p, IdentityKeypair::from_bytes(&seed)).unwrap();
        log.append_intent(b"x").unwrap();
        log.sync().unwrap();
        std::fs::remove_file(&p).unwrap();
        // The append itself still "succeeds" -- on Unix the open fd
        // writes to an unlinked inode, and nothing can stop that.
        let _ = log.append_intent(b"y");
        // FIXED: but sync, the point where the caller asks for
        // durability, now reports the loss instead of claiming success.
        let r = log.sync();
        assert!(
            r.is_err(),
            "sync must fail loudly when the journal was deleted"
        );
        assert!(
            r.unwrap_err().to_string().contains("deleted"),
            "error must say what happened"
        );
    }

    /// B3b. Journal replaced (e.g. by a log rotator) under a live log.
    // Unix-only: Windows refuses to delete a file that is still open,
    // and exposes no stable inode to compare, so this scenario cannot
    // occur (and cannot be detected) there.
    #[cfg(unix)]
    #[test]
    fn b3b_replaced_journal_is_detected_at_sync() {
        let (_, seed, _) = fresh();
        let p = tmp("replaced");
        let mut log = JournaledLog::create(&p, IdentityKeypair::from_bytes(&seed)).unwrap();
        log.append_intent(b"x").unwrap();
        std::fs::remove_file(&p).unwrap();
        std::fs::write(&p, b"a different file at the same path").unwrap();
        let r = log.sync();
        assert!(
            r.is_err(),
            "sync must fail when a different file now sits at the path"
        );
        std::fs::remove_file(&p).ok();
    }

    /// B4. Checkpoint 10,000 times in a tight loop.
    #[test]
    fn b4_rapid_checkpointing_is_cheap() {
        let (_, seed, mut log) = fresh();
        let key = SigningKey::from_bytes(&seed);
        for i in 0..1000 {
            log.append_intent(format!("{i}").as_bytes());
        }
        let start = std::time::Instant::now();
        for _ in 0..10_000 {
            let _ = log.checkpoint(&key);
        }
        let per = start.elapsed() / 10_000;
        println!("  B4: {per:?} per checkpoint on a 1000-leaf log");
        assert!(
            per.as_micros() < 2000,
            "a checkpoint should be well under 2ms, got {per:?}"
        );
    }

    /// B5. Unwritable journal path.
    #[test]
    fn b5_unwritable_path_errors_cleanly() {
        let (_, seed, _) = fresh();
        let r = JournaledLog::create(
            "/proc/not/writable/x.jsonl",
            IdentityKeypair::from_bytes(&seed),
        );
        assert!(r.is_err(), "must error, not panic");
    }

    /// B6. Zero-leaf dossier.
    #[test]
    fn b6_empty_log_is_a_valid_dossier() {
        let (id, seed, log) = fresh();
        let cp = log.checkpoint(&SigningKey::from_bytes(&seed));
        assert_eq!(cp.tree_size, 0);
        let d = dossier_with(vec![], &id.public_hex(), cp, &log);
        let r = d.verify(0.0, &VerifyContext::default());
        assert!(
            r.is_internally_consistent(),
            "an empty log is a valid, boring dossier"
        );
    }

    /// B7. Dossier JSON with fields from a future version.
    #[test]
    fn b7_unknown_fields_are_tolerated() {
        let (id, seed, mut log) = fresh();
        log.append_intent(b"x");
        let cp = log.checkpoint(&SigningKey::from_bytes(&seed));
        let d = dossier_with(log.leaves().to_vec(), &id.public_hex(), cp, &log);
        let mut v: serde_json::Value = serde_json::to_value(d).unwrap();
        v["future_field"] = serde_json::json!({"from": "v0.9"});
        v["checkpoint"]["another_future_field"] = serde_json::json!(true);
        let reparsed: Result<Dossier, _> = serde_json::from_value(v);
        assert!(
            reparsed.is_ok(),
            "unknown fields must not break parsing (forward compat)"
        );
    }

    /// B8. Two threads sharing one log. Does it compile?
    #[test]
    fn b8_log_is_send_but_not_sync() {
        fn assert_send<T: Send>() {}
        assert_send::<WitnessLog>();
        // Not Sync, and that's correct: a log has single-writer semantics.
        // Callers wrap it in a Mutex. Worth stating in the integration
        // contract so nobody tries to Arc<WitnessLog> and gets a confusing
        // compile error. FINDING: docs gap, not a bug.
    }

    /// B9. Resume from a snapshot taken on a machine whose clock was ahead.
    #[test]
    fn b9_snapshot_from_the_future_resumes_fine() {
        let (_, _seed, mut log) = fresh();
        log.append_intent(b"x");
        let p = tmp("future").replace(".jsonl", ".json");
        log.save_snapshot(&p).unwrap();
        let mut restored = WitnessLog::load_snapshot(&p).unwrap();
        // Leaves from "the future" are already in the log; appending now
        // clamps to be non-decreasing, so no monotonicity break.
        restored.append_intent(b"y");
        let ts: Vec<u64> = restored.leaves().iter().map(|l| l.timestamp_ms).collect();
        assert!(ts.windows(2).all(|w| w[0] <= w[1]));
        std::fs::remove_file(&p).ok();
    }

    /// B10. Session number is wrong on resume (operator error).
    #[test]
    fn b10_wrong_session_number_is_not_detected() {
        let (_, seed, _) = fresh();
        let a = WitnessLog::resume(IdentityKeypair::from_bytes(&seed), 5);
        let b = WitnessLog::resume(IdentityKeypair::from_bytes(&seed), 5); // same number again
        assert_eq!(
            a.current_binding().session_number,
            b.current_binding().session_number
        );
        // FINDING: two sessions can share a session_number. Nothing
        // enforces monotonicity. The bindings are still distinct (different
        // session keys) so verification works, but session_number as a
        // "which restart was this" signal is unreliable unless the caller
        // persists it. The journal does this automatically; raw
        // WitnessLog::resume does not. Docs gap.
    }
}

// ═══════════════════════════════════════════════════════════════════
// AGENT C — THE REGULATOR. "Show me the evidence."
// ═══════════════════════════════════════════════════════════════════
mod regulator {
    use super::*;

    /// C1. Prove action N was in the log at checkpoint M.
    #[test]
    fn c1_inclusion_proof_for_a_specific_action() {
        let (_, seed, mut log) = fresh();
        for i in 0..20 {
            log.append_intent(format!("action-{i}").as_bytes());
        }
        let cp = log.checkpoint(&SigningKey::from_bytes(&seed));
        // FIXED: one call on the log, no manual tree rebuild.
        let leaf = &log.leaves()[7];
        let proof = log.inclusion_proof(7).expect("proof must exist");
        let root: [u8; 32] = hex::decode(&cp.root_hash).unwrap().try_into().unwrap();
        assert!(verify_inclusion(
            &leaf_hash(&leaf.canonical_bytes()),
            7,
            cp.tree_size,
            &proof,
            &root
        ));
    }

    /// C2. Prove nothing was deleted between two checkpoints.
    #[test]
    fn c2_consistency_proof_between_checkpoints() {
        let (_, seed, mut log) = fresh();
        let key = SigningKey::from_bytes(&seed);
        for i in 0..5 {
            log.append_intent(format!("{i}").as_bytes());
        }
        let cp1 = log.checkpoint(&key);
        for i in 5..12 {
            log.append_intent(format!("{i}").as_bytes());
        }
        let cp2 = log.checkpoint(&key);
        // FIXED: on the log, and compare_checkpoints names the relation.
        let proof = log.consistency_proof(5).unwrap();
        assert_eq!(
            compare_checkpoints(&cp1, &cp2, Some(&proof)),
            CheckpointRelation::Extends
        );
        assert_eq!(
            compare_checkpoints(&cp1, &cp2, None),
            CheckpointRelation::Unproven
        );
    }

    /// C3. Prove a specific redaction happened, and when.
    #[test]
    fn c3_redaction_is_evidenced_by_a_tombstone() {
        let (_, seed, mut log) = fresh();
        log.append_intent(b"collect email");
        let pii = log.append_memory(b"alice@example.com");
        log.forget(pii);
        let cp = log.checkpoint(&SigningKey::from_bytes(&seed));
        let tombstones: Vec<&Leaf> = log
            .leaves()
            .iter()
            .filter(|l| l.redacted_index.is_some())
            .collect();
        assert_eq!(tombstones.len(), 1);
        assert_eq!(tombstones[0].redacted_index, Some(pii));
        assert!(tombstones[0].timestamp_ms >= log.leaves()[pii as usize].timestamp_ms);
        // The tombstone is committed, signed, and names the erased leaf.
        // That's exactly the evidence an erasure request needs. Clean.
        let _ = cp;
    }

    /// C4. Attribute an action to a specific session, not just an identity.
    #[test]
    fn c4_session_attribution_across_a_restart() {
        let (_, _seed, mut s1) = fresh();
        s1.append_intent(b"session 1 did this");
        let bindings_s1 = s1.all_bindings();
        let snap = std::env::temp_dir().join(format!("c4-{}.json", std::process::id()));
        s1.save_snapshot(snap.to_str().unwrap()).unwrap();
        let mut s2 = WitnessLog::load_snapshot(snap.to_str().unwrap()).unwrap();
        s2.append_intent(b"session 2 did this");
        std::fs::remove_file(&snap).ok();
        let all = s2.all_bindings();
        assert_eq!(all.len(), 2);
        // Every leaf names its session; every session has a signed
        // binding to the identity. So "which process wrote this leaf" is
        // answerable: match leaf.session_pubkey to a binding.
        for (i, leaf) in s2.leaves().iter().enumerate() {
            let b = all
                .iter()
                .find(|b| b.session_pubkey == leaf.session_pubkey)
                .expect("every leaf's session must be bound");
            assert_eq!(
                b.session_number as usize, i,
                "leaf {i} was written in session {i}"
            );
        }
        let _ = bindings_s1;
    }

    /// C5. Verify a dossier with no network, a year later.
    #[test]
    fn c5_offline_verification_needs_nothing_external() {
        let (id, seed, mut log) = fresh();
        log.append_intent(b"x");
        let cp = log.checkpoint(&SigningKey::from_bytes(&seed));
        let json = serde_json::to_string(&dossier_with(
            log.leaves().to_vec(),
            &id.public_hex(),
            cp,
            &log,
        ))
        .unwrap();
        // Everything a verifier needs is in the JSON plus the identity
        // they expected. No fetch, no registry, no clock dependency for
        // the structural checks.
        let d: Dossier = serde_json::from_str(&json).unwrap();
        let id_hex = id.public_hex();
        let r = d.verify(
            0.0,
            &VerifyContext {
                expected_identity_pubkey: Some(&id_hex),
                trusted_directory: None,
                min_receipts: None,
                revocations: &[],
                known_heads: &[],
                evidence: &[],
            },
        );
        assert!(r.is_internally_consistent() && r.identity_bound);
    }

    /// C6. Detect a rollback between two checkpoints the regulator holds.
    #[test]
    fn c6_rollback_is_detectable_from_two_checkpoints() {
        let (_, seed, mut log) = fresh();
        let key = SigningKey::from_bytes(&seed);
        for i in 0..10 {
            log.append_intent(format!("{i}").as_bytes());
        }
        let cp_big = log.checkpoint(&key);
        // Signed in the same millisecond, the two checkpoints cannot be
        // ordered, and compare_checkpoints deliberately refuses to accuse
        // (Unproven -- see below). Real rollbacks happen later in time; make
        // that explicit so this test does not depend on machine speed (it
        // failed in --release, where both landed in one millisecond).
        std::thread::sleep(std::time::Duration::from_millis(3));
        // Operator "restores from backup" and presents a smaller tree.
        let mut rolled = WitnessLog::resume(IdentityKeypair::from_bytes(&seed), 1);
        for i in 0..3 {
            rolled.append_intent(format!("{i}").as_bytes());
        }
        let cp_small = rolled.checkpoint(&key);
        assert!(cp_small.tree_size < cp_big.tree_size);
        assert!(
            cp_small.timestamp_ms > cp_big.timestamp_ms,
            "the smaller one is NEWER -- that's the tell"
        );
        // FIXED: one call names it.
        assert_eq!(
            compare_checkpoints(&cp_big, &cp_small, None),
            CheckpointRelation::Rollback
        );
        // Same millisecond: no accusation, in either argument order.
        let mut same_ms = cp_small.clone();
        same_ms.timestamp_ms = cp_big.timestamp_ms;
        let same_ms = SignedTreeHead::sign(
            &key,
            same_ms.tree_size,
            &<[u8; 32]>::try_from(hex::decode(&same_ms.root_hash).unwrap()).unwrap(),
            same_ms.timestamp_ms,
        );
        assert_ne!(
            compare_checkpoints(&cp_big, &same_ms, None),
            CheckpointRelation::Rollback
        );
        assert_ne!(
            compare_checkpoints(&same_ms, &cp_big, None),
            CheckpointRelation::Rollback
        );
    }

    /// C7. Prove A handed off to B, and when.
    #[test]
    fn c7_handoff_is_bilaterally_evidenced() {
        let a = IdentityKeypair::generate();
        let b = IdentityKeypair::generate();
        let (ah, bh) = (a.public_hex(), b.public_hex());
        let mut la = WitnessLog::resume(a, 0);
        let mut lb = WitnessLog::resume(b, 0);
        let state = b"task: review contract, status: drafted";
        let ia = la.append_handoff_sent(state, &bh);
        let ib = lb.append_handoff_received(state, &ah);
        witness_log_core::leaf::verify_handoff_binding(
            &ah,
            &la.leaves()[ia as usize],
            &bh,
            &lb.leaves()[ib as usize],
        )
        .unwrap();
        // Both sides committed independently; neither can deny it without
        // contradicting their own signed log. Clean, and unique.
    }

    /// C8. Are witness timestamps from the witnesses, or from the log?
    #[test]
    fn c8_witness_time_is_independent_of_log_time() {
        let (id, seed, mut log) = fresh();
        log.append_intent(b"x");
        let mut cp = log.checkpoint(&SigningKey::from_bytes(&seed));
        cp.timestamp_ms = 0; // log lies about its own time
        let cp = SignedTreeHead::sign(
            &SigningKey::from_bytes(&seed),
            cp.tree_size,
            &hex::decode(&cp.root_hash).unwrap().try_into().unwrap(),
            0,
        );
        let w = SigningKey::generate(&mut OsRng);
        let mut dir = WitnessDirectory::default();
        dir.witnesses.push(WitnessEntry::independent(
            "w",
            "org",
            "https://w.x",
            hex::encode(w.verifying_key().to_bytes()),
            None,
        ));
        let receipt = WitnessReceipt::sign(&w, &cp, 1_700_000_000_000);
        let q = evaluate_quorum(&cp, &[receipt], &dir, 0.0);
        assert_eq!(q.newest_trusted_witness_ms, Some(1_700_000_000_000));
        assert_ne!(q.newest_trusted_witness_ms.unwrap(), cp.timestamp_ms);
        // The policy uses witness time. The log's own claim of "0" is
        // reported but not trusted. Correct.
        let _ = id;
    }

    /// C9. Export evidence for a time window only.
    #[test]
    fn c9_time_window_export_is_manual() {
        let (_, seed, mut log) = fresh();
        for i in 0..10 {
            log.append_intent(format!("{i}").as_bytes());
        }
        let _cp = log.checkpoint(&SigningKey::from_bytes(&seed));
        // FIXED: a verifiable partial export -- each leaf proven against
        // the signed checkpoint, nothing outside the window disclosed.
        let w = log
            .evidence_window(3..7, &SigningKey::from_bytes(&seed))
            .expect("3..7 lies inside a 10-leaf tree");
        assert_eq!(w.entries.len(), 4);
        assert!(
            w.verify().is_ok(),
            "every windowed leaf must prove against the checkpoint"
        );
        // Tampering with one entry is caught and named.
        let mut tampered = w.clone();
        tampered.entries[1].leaf.payload_hash = "00".repeat(32);
        assert_eq!(
            tampered.verify(),
            Err(vec![4]),
            "the tampered leaf (index 4) must be named"
        );
        // Round-trips as JSON for handing to a regulator.
        let json = serde_json::to_string(&w).unwrap();
        let back: witness_log_core::log::EvidenceWindow = serde_json::from_str(&json).unwrap();
        assert!(back.verify().is_ok());
    }

    /// C10. Which operator ran each witness?
    #[test]
    fn c10_operator_attribution_per_receipt() {
        let (id, seed, mut log) = fresh();
        log.append_intent(b"x");
        let cp = log.checkpoint(&SigningKey::from_bytes(&seed));
        let mut dir = WitnessDirectory::default();
        let mut receipts = Vec::new();
        for org in ["uni", "coop"] {
            let w = SigningKey::generate(&mut OsRng);
            dir.witnesses.push(WitnessEntry::independent(
                org,
                org,
                format!("https://{org}.x"),
                hex::encode(w.verifying_key().to_bytes()),
                None,
            ));
            receipts.push(WitnessReceipt::sign(&w, &cp, cp.timestamp_ms));
        }
        // The regulator wants: for each receipt, who signed it.
        for r in &receipts {
            let entry = dir
                .witnesses
                .iter()
                .find(|w| w.pubkey == r.witness_pubkey)
                .expect("every receipt maps to a directory entry");
            assert!(!entry.operator_org.is_empty());
        }
        // FIXED: the quorum result names them.
        let q = evaluate_quorum(&cp, &receipts, &dir, 0.0);
        assert_eq!(
            q.independent_operators_represented,
            vec!["coop".to_string(), "uni".to_string()]
        );
        let _ = id;
    }
}

#[test]
fn zz_three_perspectives_summary() {
    let findings = [
        ("FIXED", "B2", "Was HIGH: double-resume corrupted the journal. Now an exclusive lock refuses the second open; a lock left by a dead PID is recovered automatically on Linux, force_unlock elsewhere."),
        ("FIXED", "C1/C2", "inclusion_proof(index) and consistency_proof(earlier_size) now on WitnessLog."),
        ("FIXED", "C9", "WitnessLog::evidence_window(range) -- each leaf proven against the signed checkpoint, nothing outside the window disclosed, self-verifying, JSON round-trip."),
        ("FIXED", "C6", "compare_checkpoints(a, b, proof) -> Extends | Identical | Rollback | Diverged | Unproven | DifferentIdentity."),
        ("FIXED", "C10", "QuorumResult::independent_operators_represented names the independent operators, sorted."),
        ("WONTFIX", "A8", "A receipt timestamped before its checkpoint is accepted. Rejecting it would treat routine witness/log clock skew as fraud -- the false-positive class already fixed twice."),
        ("FIXED", "A3", "Investigating this found that compare_checkpoints returned a FALSE Rollback depending on argument order when timestamps tied. Same-ms checkpoints are routine, so flagging them would be wrong; the ordering bug was real and is fixed (see tie_check.rs)."),
        ("FIXED", "B8/B10", "Send-not-Sync and caller-managed session_number now documented in the integration contract."),
        ("FIXED", "B3", "Deleting or replacing a journal under a live process now fails loudly at sync() instead of silently losing writes."),
        ("WONTFIX", "A7", "Duplicate leaves verify. Agents legitimately repeat actions; rejecting would break honest logs."),
    ];
    println!(
        "\n  THREE-PERSPECTIVE FINDINGS ({} total)\n",
        findings.len()
    );
    for (sev, id, text) in findings {
        println!("  [{sev:>4}] {id:<6} {text}");
    }
    println!();
}
