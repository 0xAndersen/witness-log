//! Second independent review: demonstrating tests for the network crate.
//!
//! `defect_*` tests assert the behaviour as it stands today (a fix flips
//! them); `sound_*` tests pin checks that were examined and found correct.

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use witness_log_core::c2sp::{
    canonical_origin, identity_from_canonical_origin, Checkpoint, Cosignature, SignedNote,
    VerifierKey,
};
use witness_log_core::identity::{IdentityKeypair, SessionKeypair};
use witness_log_core::leaf::{Leaf, LeafType};
use witness_log_core::merkle::{leaf_hash, MerkleTree};
use witness_log_core::sth::SignedTreeHead;
use witness_log_network::tlog_witness::*;
use witness_log_network::*;

fn hex64(b: u8) -> String {
    hex::encode([b; 32])
}

fn leaf(index: u64, ts: u64, session: &str) -> Leaf {
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

fn sign_head(id: &IdentityKeypair, leaves: &[Leaf], ts: u64) -> SignedTreeHead {
    let mut t = MerkleTree::new();
    for l in leaves {
        t.append(leaf_hash(&l.canonical_bytes()));
    }
    let key = SigningKey::from_bytes(&id.to_bytes());
    SignedTreeHead::sign(&key, t.size(), &t.root(), ts)
}

fn entry(org: &str, key: &SigningKey) -> WitnessEntry {
    WitnessEntry::independent(
        format!("{org}-w"),
        org,
        format!("https://{org}.example"),
        hex::encode(key.verifying_key().to_bytes()),
        None,
    )
}

// ---------------------------------------------------------------------------
// Finding W1 (MEDIUM): `EquivocationProof::verify` trusts the vkey embedded in
// the proof. Anyone can mint two conflicting notes under a key they own, label
// them with a victim's canonical origin, and the proof "verifies". The CLI's
// `witness check-evidence` prints PROVEN / "This identity showed two
// histories" and exits 0 on such a file.
// ---------------------------------------------------------------------------
#[test]
fn fixed_w1_equivocation_proof_is_bound_to_the_origin_key() {
    let victim = IdentityKeypair::generate();
    let victim_vk = ed25519_dalek::VerifyingKey::from_bytes(
        &hex::decode(victim.public_hex())
            .unwrap()
            .try_into()
            .unwrap(),
    )
    .unwrap();
    let origin = canonical_origin(&victim_vk);

    let attacker = SigningKey::generate(&mut OsRng);
    let vkey = VerifierKey::for_ed25519(&origin, &attacker.verifying_key());
    let mk = |root: u8| {
        Checkpoint {
            origin: origin.clone(),
            tree_size: 7,
            root_hash: [root; 32],
            extensions: vec![],
        }
        .sign(&attacker)
        .unwrap()
        .encode()
        .unwrap()
    };
    let proof = EquivocationProof {
        origin: origin.clone(),
        log_vkey: vkey.encode(),
        earlier_note: mk(1),
        conflicting_note: mk(2),
    };
    assert_ne!(
        identity_from_canonical_origin(&origin).unwrap().to_bytes(),
        attacker.verifying_key().to_bytes(),
        "the origin names the victim, the vkey is the attacker's"
    );
    assert!(
        !proof.verify(),
        "fixed in 0.4.2: a proof signed by a stranger's key under the victim's origin is NOT PROVEN"
    );
    // The same two notes under the victim's own key are proof.
    let victim_sk = SigningKey::from_bytes(&victim.to_bytes());
    let mk_real = |root: u8| {
        Checkpoint {
            origin: origin.clone(),
            tree_size: 7,
            root_hash: [root; 32],
            extensions: vec![],
        }
        .sign(&victim_sk)
        .unwrap()
        .encode()
        .unwrap()
    };
    let real = EquivocationProof {
        origin: origin.clone(),
        log_vkey: VerifierKey::for_ed25519(&origin, &victim_vk).encode(),
        earlier_note: mk_real(1),
        conflicting_note: mk_real(2),
    };
    assert!(real.verify());
    // A non-canonical origin only verifies with a caller-supplied key.
    let other = EquivocationProof {
        origin: "example.org/log".into(),
        ..real.clone()
    };
    assert!(!other.verify());
}

// ---------------------------------------------------------------------------
// Finding W2 (MEDIUM, design): the revocation cut-off is enforced only on
// `leaf.timestamp_ms`, which the holder of the (compromised) identity key sets
// freely. Post-revocation leaves with backdated timestamps, under a
// checkpoint signed after the revocation, verify. The verifier has no
// out-of-band input for revocations, so omitting the statement altogether
// is equally undetectable.
// ---------------------------------------------------------------------------
/// Fixed in 0.4.2 (partially; the index cut-off is RFC-0005): a checkpoint
/// signed at or after the revocation is invalid whatever the leaves say,
/// and a verifier can supply revocations it knows about so a dossier that
/// omits the statement is judged the same way.
#[test]
fn fixed_w2_revocation_applies_to_the_checkpoint_and_from_the_verifier() {
    let id = IdentityKeypair::generate();
    let session = SessionKeypair::generate();
    let binding = id.bind_session(&session.verifying_key(), 1, 1_000, None);
    let revocation = id.revoke(5_000, "key compromised");

    let leaves: Vec<Leaf> = (0..4)
        .map(|i| leaf(i, 4_999, &session.public_hex()))
        .collect();
    let checkpoint = sign_head(&id, &leaves, 9_000); // signed after revocation
    let dossier = Dossier {
        identity_pubkey: id.public_hex(),
        leaves: leaves.clone(),
        checkpoint: checkpoint.clone(),
        witness_receipts: vec![],
        witness_directory: WitnessDirectory::default(),
        key_bindings: vec![binding.clone()],
        revocations: vec![revocation.clone()],
    };
    let ident = id.public_hex();
    let ctx = VerifyContext {
        expected_identity_pubkey: Some(&ident),
        trusted_directory: None,
        min_receipts: None,
        revocations: &[],
    };
    let report = dossier.verify(0.66, &ctx);
    assert!(report.bindings_asserted);
    assert!(
        !report.bindings_valid,
        "a checkpoint signed after the revocation is not evidence"
    );
    assert_eq!(report.verdict, Verdict::Diverged);

    // Stripping the revocation no longer helps when the verifier knows it.
    let mut d3 = dossier.clone();
    d3.revocations.clear();
    let known = vec![revocation.clone()];
    let ctx_known = VerifyContext {
        expected_identity_pubkey: Some(&ident),
        trusted_directory: None,
        min_receipts: None,
        revocations: &known,
    };
    assert_eq!(
        d3.verify(0.66, &ctx).verdict,
        Verdict::Unanchored,
        "unknown to this verifier"
    );
    let r3 = d3.verify(0.66, &ctx_known);
    assert!(r3.bindings_asserted && !r3.bindings_valid);
    assert_eq!(r3.verdict, Verdict::Diverged);

    // A head signed before the revocation, with leaves before it, still verifies.
    let pre = sign_head(&id, &leaves, 4_999);
    let mut d4 = dossier.clone();
    d4.checkpoint = pre;
    assert_eq!(d4.verify(0.66, &ctx_known).verdict, Verdict::Unanchored);
    // A revocation for another identity in the verifier's list is ignored.
    let stranger = IdentityKeypair::generate().revoke(1, "x");
    let others = vec![stranger];
    let ctx_other = VerifyContext {
        expected_identity_pubkey: Some(&ident),
        trusted_directory: None,
        min_receipts: None,
        revocations: &others,
    };
    assert_eq!(d4.verify(0.66, &ctx_other).verdict, Verdict::Unanchored);
}

// ---------------------------------------------------------------------------
// Finding W3 (LOW): `AddCheckpointRequest::parse` accepts non-canonical
// `old` lines (`+5`, `005`) because it uses `u64::from_str`. The spec's
// checkpoint-size parser in `Checkpoint::from_note` is strict; the request
// parser is not. No security consequence found; recorded for consistency.
// ---------------------------------------------------------------------------
#[test]
fn fixed_w3_old_size_line_requires_a_canonical_integer() {
    let key = SigningKey::generate(&mut OsRng);
    let cp = Checkpoint {
        origin: "example.org/log".into(),
        tree_size: 5,
        root_hash: [3u8; 32],
        extensions: vec![],
    };
    let note = cp.sign(&key).unwrap().encode().unwrap();
    for old in ["+5", "005", "+0", "-1", ""] {
        let body = format!("old {old}\n\n{note}");
        assert!(
            AddCheckpointRequest::parse(&body).is_err(),
            "`old {old}` must be refused"
        );
    }
    for old in ["0", "5"] {
        let body = format!("old {old}\n\n{note}");
        assert!(
            AddCheckpointRequest::parse(&body).is_ok(),
            "`old {old}` is canonical"
        );
    }
}

// ---------------------------------------------------------------------------
// Sound: the verify path.
// ---------------------------------------------------------------------------

/// Receipts are counted only for the exact head in the checkpoint, from
/// keys in the verifier's directory, once per key, and the dossier's own
/// directory never reaches a trust decision.
#[test]
fn sound_receipts_counted_against_exact_head_and_trusted_directory_only() {
    let id = IdentityKeypair::generate();
    let session = SessionKeypair::generate();
    let leaves: Vec<Leaf> = (0..3)
        .map(|i| leaf(i, 10 + i, &session.public_hex()))
        .collect();
    let sth = sign_head(&id, &leaves, 100);
    let other_sth = sign_head(&id, &leaves[..2], 90);

    let w1 = SigningKey::generate(&mut OsRng);
    let w2 = SigningKey::generate(&mut OsRng);
    let w3 = SigningKey::generate(&mut OsRng); // not in the trusted directory
    let trusted = WitnessDirectory {
        witnesses: vec![entry("acme", &w1), entry("acme", &w2), entry("zed", &w3)],
    };
    // w3 is replaced by an impostor key in the dossier's own directory.
    let impostor = SigningKey::generate(&mut OsRng);
    let shipped = WitnessDirectory {
        witnesses: vec![
            entry("acme", &w1),
            entry("zed", &impostor),
            entry("other", &w2),
        ],
    };
    let receipts = vec![
        WitnessReceipt::sign(&w1, &sth, 1_000),
        WitnessReceipt::sign(&w1, &sth, 2_000), // same key, resigned: counts once
        WitnessReceipt::sign(&w2, &other_sth, 1_000), // wrong head: ignored
        WitnessReceipt::sign(&impostor, &sth, 1_000), // not in trusted dir
    ];
    let dossier = Dossier {
        identity_pubkey: id.public_hex(),
        leaves,
        checkpoint: sth,
        witness_receipts: receipts,
        witness_directory: shipped,
        key_bindings: vec![id.bind_session(&session.verifying_key(), 1, 1, None)],
        revocations: vec![],
    };
    let ident = id.public_hex();
    let r = dossier.verify(
        0.0,
        &VerifyContext {
            expected_identity_pubkey: Some(&ident),
            trusted_directory: Some(&trusted),
            min_receipts: Some(1),
            revocations: &[],
        },
    );
    let q = r.quorum.as_ref().unwrap();
    assert_eq!(q.valid_receipts, 1);
    assert_eq!(q.distinct_independent_operators, 1);
    assert_eq!(r.verdict, Verdict::ConsistentUnwitnessed);
    // No directory at all: capped at Unanchored whatever the receipts say.
    assert_eq!(
        dossier.verify(0.0, &VerifyContext::default()).verdict,
        Verdict::Unanchored
    );
    // Pinned to a different identity: Diverged.
    let other = IdentityKeypair::generate().public_hex();
    assert_eq!(
        dossier
            .verify(
                0.0,
                &VerifyContext {
                    expected_identity_pubkey: Some(&other),
                    trusted_directory: Some(&trusted),
                    min_receipts: Some(1),
                    revocations: &[],
                }
            )
            .verdict,
        Verdict::Diverged
    );
}

/// Operator label variants and project-operated witnesses cannot inflate
/// the independent-operator count; two real operators are needed.
#[test]
fn sound_operator_normalisation_and_project_bucket() {
    let id = IdentityKeypair::generate();
    let leaves = vec![leaf(0, 1, &hex64(1))];
    let sth = sign_head(&id, &leaves, 5);
    let keys: Vec<SigningKey> = (0..5).map(|_| SigningKey::generate(&mut OsRng)).collect();
    let mut dir = WitnessDirectory {
        witnesses: vec![
            entry("Acme Corp", &keys[0]),
            entry("acme  corp ", &keys[1]),
            entry("\tACME CORP", &keys[2]),
        ],
    };
    dir.witnesses.push(WitnessEntry::project_operated(
        "p1",
        "https://p1",
        hex::encode(keys[3].verifying_key().to_bytes()),
        Some("x".into()),
    ));
    dir.witnesses.push(WitnessEntry::project_operated(
        "p2",
        "https://p2",
        hex::encode(keys[4].verifying_key().to_bytes()),
        Some("y".into()),
    ));
    let receipts: Vec<WitnessReceipt> = keys
        .iter()
        .map(|k| WitnessReceipt::sign(k, &sth, 7))
        .collect();
    let q = evaluate_quorum(&sth, &receipts, &dir, 0.5);
    assert_eq!(q.valid_receipts, 5);
    assert_eq!(q.distinct_independent_operators, 1);
    assert_eq!(q.project_operated_receipts, 2);
    assert!(q.meets_count_threshold);
    let d = Dossier {
        identity_pubkey: id.public_hex(),
        leaves,
        checkpoint: sth,
        witness_receipts: receipts,
        witness_directory: WitnessDirectory::default(),
        key_bindings: vec![],
        revocations: vec![],
    };
    let r = d.verify(
        0.5,
        &VerifyContext {
            expected_identity_pubkey: None,
            trusted_directory: Some(&dir),
            min_receipts: None,
            revocations: &[],
        },
    );
    assert_eq!(
        r.verdict,
        Verdict::ConsistentUnwitnessed,
        "5/5 but one operator"
    );
}

/// C2SP receipts: bound to the canonical origin of the checkpoint signer,
/// to whole seconds, and to the exact (size, root). Native and C2SP
/// receipts from one key count once.
#[test]
fn sound_c2sp_receipts_bind_origin_time_and_head() {
    let id = IdentityKeypair::generate();
    let leaves = vec![leaf(0, 1, &hex64(1)), leaf(1, 2, &hex64(1))];
    let sth = sign_head(&id, &leaves, 5);
    let id_vk = ed25519_dalek::VerifyingKey::from_bytes(
        &hex::decode(id.public_hex()).unwrap().try_into().unwrap(),
    )
    .unwrap();
    let origin = canonical_origin(&id_vk);
    let cp = Checkpoint {
        origin: origin.clone(),
        tree_size: sth.tree_size,
        root_hash: hex::decode(&sth.root_hash).unwrap().try_into().unwrap(),
        extensions: vec![],
    };
    let w = SigningKey::generate(&mut OsRng);
    let wv = VerifierKey::for_cosignature("w.example/1", &w.verifying_key());
    let cosig = Cosignature::sign("w.example/1", &w, 1_700_000_000, &cp.note_text().unwrap());
    let rc = cosignature_to_receipt(&cosig, &wv, &cp, &sth).expect("converts");
    assert!(rc.receipt.verify(&sth).is_ok());

    // Same cosignature under a non-canonical origin: not convertible, and
    // a hand-built receipt claiming it does not verify.
    let mut other_cp = cp.clone();
    other_cp.origin = "agents.example/42".into();
    let cosig2 = Cosignature::sign(
        "w.example/1",
        &w,
        1_700_000_000,
        &other_cp.note_text().unwrap(),
    );
    let rc2 = cosignature_to_receipt(&cosig2, &wv, &other_cp, &sth).expect("valid C2SP");
    assert!(
        rc2.receipt.verify(&sth).is_err(),
        "non-canonical origin never counts"
    );

    // Sub-second witnessed_at_ms is unsigned precision: refused.
    let mut r3 = rc.receipt.clone();
    r3.witnessed_at_ms += 1;
    assert!(r3.verify(&sth).is_err());
    // Cosignature over a different head does not convert.
    let mut other_head = cp.clone();
    other_head.tree_size = 3;
    let cosig4 = Cosignature::sign("w.example/1", &w, 1, &other_head.note_text().unwrap());
    assert!(cosignature_to_receipt(&cosig4, &wv, &other_head, &sth).is_none());
    // The log's own 0x01 note signature cannot be re-labelled as a cosignature.
    let note = cp.sign(&SigningKey::from_bytes(&id.to_bytes())).unwrap();
    let fake = WitnessReceipt {
        witness_pubkey: id.public_hex(),
        tree_size: sth.tree_size,
        root_hash: sth.root_hash.clone(),
        witnessed_at_ms: 0,
        signature: hex::encode(&note.signatures[0].signature),
        c2sp_origin: Some(origin.clone()),
        witness_name: None,
    };
    assert!(fake.verify(&sth).is_err());
    // Dedup across formats.
    let native = WitnessReceipt::sign(&w, &sth, 1_000);
    let dir = WitnessDirectory {
        witnesses: vec![entry("org", &w)],
    };
    let q = evaluate_quorum(&sth, &[native, rc.receipt], &dir, 0.0);
    assert_eq!(q.valid_receipts, 1);
}

/// The witness state machine: no cosignature for a head that does not
/// extend the held one; equivocation evidence only for two log-signed
/// roots at the held size; re-adding a known log does not reset it;
/// restored state bound to a key is refused next to another key.
#[test]
fn sound_witness_refuses_forks_and_records_only_real_equivocation() {
    let log_key = SigningKey::generate(&mut OsRng);
    let origin = canonical_origin(&log_key.verifying_key());
    let wkey = SigningKey::generate(&mut OsRng);
    let mut svc = WitnessService::new();

    let mut honest = MerkleTree::new();
    for i in 0..5u8 {
        honest.append(leaf_hash(&[i]));
    }
    let head = |t: &MerkleTree| Checkpoint {
        origin: origin.clone(),
        tree_size: t.size(),
        root_hash: t.root(),
        extensions: vec![],
    };
    let req = |cp: &Checkpoint, old: u64, proof: Vec<[u8; 32]>| AddCheckpointRequest {
        old_size: old,
        consistency_proof: proof,
        checkpoint_note: cp.sign(&log_key).unwrap(),
    };
    let first = req(&head(&honest), 0, vec![]);
    assert!(svc.enroll_canonical(&first));
    assert!(
        !svc.enroll_canonical(&first),
        "known log is never re-enrolled"
    );
    assert!(!svc.add_log(
        &origin,
        VerifierKey::for_ed25519(&origin, &log_key.verifying_key())
    ));
    assert!(matches!(
        svc.handle_add_checkpoint(&first, "w", &wkey, 1),
        AddCheckpointOutcome::Cosigned { new_size: 5, .. }
    ));

    // A fork: rewrite leaf 1, grow to 7 (a non-power-of-two old size).
    let mut fork = MerkleTree::new();
    for i in 0..7u8 {
        fork.append(leaf_hash(&[if i == 1 { 99 } else { i }]));
    }
    let fp = fork.consistency_proof(5, 7).unwrap();
    let out = svc.handle_add_checkpoint(&req(&head(&fork), 5, fp), "w", &wkey, 2);
    assert!(
        matches!(
            out,
            AddCheckpointOutcome::ConsistencyFailed {
                equivocation: None,
                ..
            }
        ),
        "{out:?}"
    );
    assert_eq!(
        svc.known_log(&origin).unwrap().tree_size,
        5,
        "state unchanged"
    );

    // Same size, different root, log-signed: evidence.
    let mut fork5 = MerkleTree::new();
    for i in 0..5u8 {
        fork5.append(leaf_hash(&[if i == 1 { 99 } else { i }]));
    }
    let out = svc.handle_add_checkpoint(&req(&head(&fork5), 5, vec![]), "w", &wkey, 3);
    match out {
        AddCheckpointOutcome::ConsistencyFailed {
            equivocation: Some(p),
            ..
        } => {
            assert!(p.verify());
            assert!(AddCheckpointOutcome::ConsistencyFailed {
                witness_size: 5,
                witness_root: honest.root(),
                submitted_size: 5,
                submitted_root: fork5.root(),
                equivocation: Some(p)
            }
            .is_misbehaviour_evidence());
        }
        o => panic!("expected evidence, got {o:?}"),
    }

    // Honest growth with a correct proof is cosigned; a stale honest head is 400.
    honest.append(leaf_hash(&[5]));
    let p = honest.consistency_proof(5, 6).unwrap();
    assert!(matches!(
        svc.handle_add_checkpoint(&req(&head(&honest), 5, p), "w", &wkey, 4),
        AddCheckpointOutcome::Cosigned { new_size: 6, .. }
    ));
    let mut small = MerkleTree::new();
    for i in 0..3u8 {
        small.append(leaf_hash(&[i]));
    }
    assert!(matches!(
        svc.handle_add_checkpoint(&req(&head(&small), 6, vec![]), "w", &wkey, 5),
        AddCheckpointOutcome::StaleCheckpoint { .. }
    ));
    assert!(matches!(
        svc.handle_add_checkpoint(&req(&head(&honest), 2, vec![]), "w", &wkey, 5),
        AddCheckpointOutcome::SizeMismatch {
            witness_size: 6,
            ..
        }
    ));
    // Unsigned/forged note: 403, and never enrolled.
    let stranger = SigningKey::generate(&mut OsRng);
    let forged = AddCheckpointRequest {
        old_size: 6,
        consistency_proof: vec![],
        checkpoint_note: head(&honest).sign(&stranger).unwrap(),
    };
    assert!(matches!(
        svc.handle_add_checkpoint(&forged, "w", &wkey, 6),
        AddCheckpointOutcome::UnknownOrBadSignature
    ));
    let mut fresh = WitnessService::new();
    assert!(!fresh.enroll_canonical(&forged));
    assert_eq!(fresh.log_count(), 0);

    // State binding.
    let state = svc
        .export_state()
        .bind(&hex::encode(wkey.verifying_key().to_bytes()));
    assert!(state
        .check_bound_to(&hex::encode(stranger.verifying_key().to_bytes()))
        .is_err());
    let restored = WitnessService::from_state(&state).unwrap();
    assert_eq!(restored.known_log(&origin).unwrap().tree_size, 6);
}

/// Request parsing bounds: 64 proof lines refused, oversized checkpoint
/// body refused, non-32-byte hashes refused, and a hostile body does not
/// panic.
#[test]
fn sound_request_parser_bounds() {
    use base64ct::Encoding;
    let key = SigningKey::generate(&mut OsRng);
    let cp = Checkpoint {
        origin: "example.org/log".into(),
        tree_size: 5,
        root_hash: [3u8; 32],
        extensions: vec![],
    };
    let note = cp.sign(&key).unwrap().encode().unwrap();
    let h = base64ct::Base64::encode_string(&[1u8; 32]);
    let many: String = format!("{h}\n").repeat(64);
    assert!(AddCheckpointRequest::parse(&format!("old 1\n{many}\n{note}")).is_err());
    let ok: String = format!("{h}\n").repeat(63);
    assert!(AddCheckpointRequest::parse(&format!("old 1\n{ok}\n{note}")).is_ok());
    let short = base64ct::Base64::encode_string(&[1u8; 31]);
    assert!(AddCheckpointRequest::parse(&format!("old 1\n{short}\n\n{note}")).is_err());
    let big = Checkpoint {
        origin: "example.org/log".into(),
        tree_size: 5,
        root_hash: [3u8; 32],
        extensions: vec!["x".repeat(2000)],
    };
    let big_note = big.sign(&key).unwrap().encode().unwrap();
    assert!(AddCheckpointRequest::parse(&format!("old 0\n\n{big_note}")).is_err());
    for hostile in [
        "",
        "\n\n",
        "old\n\n",
        "old 1",
        "old 1\n\n\n\n",
        "old 18446744073709551616\n\nx\n\n\u{2014} a AAAAAAAA\n",
    ] {
        let _ = AddCheckpointRequest::parse(hostile);
    }
    for hostile in [
        "",
        "\n",
        "\u{2014}",
        "a\n\n\u{2014} ",
        "a\n\n\u{2014} k",
        "a\n\n\u{2014} k !!!!",
    ] {
        let _ = SignedNote::parse(hostile);
    }
}

/// Hostile dossier JSON is handled without panics and lands on Diverged
/// (or fails to parse), never on a higher verdict.
#[test]
fn sound_hostile_dossier_json_does_not_panic_or_upgrade() {
    let id = IdentityKeypair::generate();
    let leaves = vec![leaf(0, 1, &hex64(1))];
    let sth = sign_head(&id, &leaves, 5);
    let base = Dossier {
        identity_pubkey: id.public_hex(),
        leaves,
        checkpoint: sth,
        witness_receipts: vec![],
        witness_directory: WitnessDirectory::default(),
        key_bindings: vec![],
        revocations: vec![],
    };
    let mut v = serde_json::to_value(&base).unwrap();
    let dir = WitnessDirectory::default();
    let mutate = |v: &mut serde_json::Value, path: &[&str], new: serde_json::Value| {
        let mut cur = v;
        for p in &path[..path.len() - 1] {
            cur = match p.parse::<usize>() {
                Ok(i) => cur.get_mut(i).unwrap(),
                Err(_) => cur.get_mut(*p).unwrap(),
            };
        }
        cur[path[path.len() - 1]] = new;
    };
    let cases: Vec<(&[&str], serde_json::Value)> = vec![
        (&["checkpoint", "tree_size"], serde_json::json!(u64::MAX)),
        (&["checkpoint", "tree_size"], serde_json::json!(1u64 << 63)),
        (&["checkpoint", "root_hash"], serde_json::json!("")),
        (&["checkpoint", "root_hash"], serde_json::json!("zz")),
        (&["checkpoint", "signer_pubkey"], serde_json::json!("00")),
        (&["checkpoint", "signature"], serde_json::json!("ab")),
        (&["checkpoint", "sig_alg"], serde_json::json!("ED25519")),
        (&["identity_pubkey"], serde_json::json!("")),
        (
            &["leaves", "0", "session_pubkey"],
            serde_json::json!("AB".repeat(32)),
        ),
        (&["leaves", "0", "payload_hash"], serde_json::json!("")),
        (&["leaves", "0", "index"], serde_json::json!(u64::MAX)),
        (&["leaves", "0", "leaf_type"], serde_json::json!(8)),
    ];
    for (path, new) in cases {
        let mut m = v.clone();
        mutate(&mut m, path, new);
        if let Ok(d) = serde_json::from_value::<Dossier>(m) {
            let r = d.verify(
                0.66,
                &VerifyContext {
                    expected_identity_pubkey: Some(&base.identity_pubkey),
                    trusted_directory: Some(&dir),
                    min_receipts: None,
                    revocations: &[],
                },
            );
            assert_eq!(r.verdict, Verdict::Diverged, "{path:?}");
        }
    }
    // Baseline is sound.
    let d: Dossier = serde_json::from_value(v.take()).unwrap();
    assert_eq!(
        d.verify(
            0.66,
            &VerifyContext {
                expected_identity_pubkey: Some(&base.identity_pubkey),
                trusted_directory: Some(&dir),
                min_receipts: None,
                revocations: &[],
            }
        )
        .verdict,
        Verdict::ConsistentUnwitnessed
    );
}

/// compare_checkpoints never accuses on unverified input and requires a
/// both-roots consistency proof to claim Extends.
#[test]
fn sound_compare_checkpoints() {
    let id = IdentityKeypair::generate();
    let s = hex64(1);
    let a: Vec<Leaf> = (0..3).map(|i| leaf(i, 1, &s)).collect();
    let b: Vec<Leaf> = (0..5).map(|i| leaf(i, 1, &s)).collect();
    let mut forked = b.clone();
    forked[1].payload_hash = hex64(0xCC);
    let sa = sign_head(&id, &a, 10);
    let sb = sign_head(&id, &b, 20);
    let sf = sign_head(&id, &forked, 20);
    let mut t = MerkleTree::new();
    for l in &b {
        t.append(leaf_hash(&l.canonical_bytes()));
    }
    let p = t.consistency_proof(3, 5).unwrap();
    assert_eq!(
        compare_checkpoints(&sa, &sb, Some(&p)),
        CheckpointRelation::Extends
    );
    assert_eq!(
        compare_checkpoints(&sb, &sa, Some(&p)),
        CheckpointRelation::Extends
    );
    assert_eq!(
        compare_checkpoints(&sa, &sb, None),
        CheckpointRelation::Unproven
    );
    let mut ft = MerkleTree::new();
    for l in &forked {
        ft.append(leaf_hash(&l.canonical_bytes()));
    }
    let fp = ft.consistency_proof(3, 5).unwrap();
    assert_eq!(
        compare_checkpoints(&sa, &sf, Some(&fp)),
        CheckpointRelation::Unproven
    );
    assert_eq!(
        compare_checkpoints(&sb, &sf, None),
        CheckpointRelation::Diverged
    );
    let mut bad = sb.clone();
    bad.tree_size = 2;
    assert_eq!(
        compare_checkpoints(&sa, &bad, None),
        CheckpointRelation::InvalidSignature
    );
}
