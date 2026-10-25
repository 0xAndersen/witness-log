//! Silence proofs, as `witness-log prove-silence` runs them (SPEC §9.4):
//! presence and absence are decided only over leaves bound to every
//! counted witnessed checkpoint, at the index the receipt promised, with
//! the receipt's key not revoked; and over dossiers, only dossiers that
//! verify, are witnessed and reproduce their own checkpoint are used for
//! anything.
//!
//! Each test names the review finding it pins (the outside review of the
//! CLI commit), or the mutation of the library that it catches.

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use witness_log_core::identity::{IdentityKeypair, RevocationStatement};
use witness_log_core::leaf::Leaf;
use witness_log_core::log::WitnessLog;
use witness_log_core::merkle::{leaf_hash, MerkleTree};
use witness_log_core::sth::{SignedTreeHead, WriteReceipt};
use witness_log_network::*;

const NOW: u64 = 1_800_000_000_000;
const SEED: [u8; 32] = [7u8; 32];

fn key() -> SigningKey {
    SigningKey::from_bytes(&SEED)
}

fn new_log() -> WitnessLog {
    WitnessLog::resume(IdentityKeypair::from_bytes(&SEED), 0)
}

/// Witnesses of four organisations; `ws[0..2]` are orgs A and B,
/// `ws[2..4]` orgs C and D.
fn network() -> (WitnessDirectory, Vec<SigningKey>) {
    let mut dir = WitnessDirectory::default();
    let mut ws = Vec::new();
    for (i, org) in ["Org A", "Org B", "Org C", "Org D"].iter().enumerate() {
        let key = SigningKey::generate(&mut OsRng);
        dir.witnesses.push(WitnessEntry {
            name: format!("w{i}"),
            operator_org: org.to_string(),
            url: format!("https://w{i}.example"),
            pubkey: hex::encode(key.verifying_key().to_bytes()),
            runtime: WitnessRuntime::Human,
            compute_provider: None,
            is_project_operated: false,
        });
        ws.push(key);
    }
    (dir, ws)
}

fn root_of(leaves: &[Leaf]) -> [u8; 32] {
    let mut tree = MerkleTree::new();
    for l in leaves {
        tree.append(leaf_hash(&l.canonical_bytes()));
    }
    tree.root()
}

fn cosigned(cp: SignedTreeHead, ws: &[SigningKey]) -> ObservedCheckpoint {
    ObservedCheckpoint {
        receipts: ws
            .iter()
            .map(|w| WitnessReceipt::sign(w, &cp, NOW + cp.tree_size))
            .collect(),
        checkpoint: cp,
    }
}

/// A checkpoint of `leaves` signed by the log's key, cosigned by `ws`.
fn witnessed(leaves: &[Leaf], ws: &[SigningKey]) -> ObservedCheckpoint {
    let n = leaves.len() as u64;
    cosigned(
        SignedTreeHead::sign(&key(), n, &root_of(leaves), NOW + n),
        ws,
    )
}

fn dossier(leaves: &[Leaf], oc: &ObservedCheckpoint) -> Dossier {
    Dossier {
        identity_pubkey: oc.checkpoint.signer_pubkey.clone(),
        leaves: leaves.to_vec(),
        checkpoint: oc.checkpoint.clone(),
        witness_receipts: oc.receipts.clone(),
        witness_directory: WitnessDirectory::default(),
        key_bindings: vec![],
        revocations: vec![],
        fleet_anchor: None,
    }
}

fn ctx<'a>(
    dir: &'a WitnessDirectory,
    min: usize,
    revocations: &'a [RevocationStatement],
) -> SilenceContext<'a> {
    SilenceContext {
        trusted_directory: dir,
        min_witnessed_checkpoints: min,
        subject_org: None,
        revocations,
    }
}

fn check(
    receipt: &WriteReceipt,
    leaves: &[Leaf],
    later: &[ObservedCheckpoint],
    dir: &WitnessDirectory,
) -> SilenceProofReport {
    silence_proof_in_context(receipt, leaves, later, &ctx(dir, 2, &[]))
}

fn is_censored(r: &SilenceProofReport) -> bool {
    matches!(r.result, SilenceProofResult::Censored { .. })
}

fn is_inconclusive(r: &SilenceProofReport) -> bool {
    matches!(r.result, SilenceProofResult::Inconclusive { .. })
}

/// A log that signed a receipt for an event at size 0 and never appended
/// it: nine other entries, checkpoints at 5 and 9 cosigned by orgs A and B.
struct Censoring {
    receipt: WriteReceipt,
    leaves: Vec<Leaf>,
    d5: Dossier,
    d9: Dossier,
}

fn censoring(ws: &[SigningKey]) -> Censoring {
    let receipt = WriteReceipt::sign(&key(), &"ab".repeat(32), 0, NOW);
    let mut log = new_log();
    for i in 0..9 {
        log.append_intent(format!("other {i}").as_bytes());
    }
    let leaves = log.leaves().to_vec();
    let d5 = dossier(&leaves[..5], &witnessed(&leaves[..5], &ws[..2]));
    let d9 = dossier(&leaves, &witnessed(&leaves, &ws[..2]));
    Censoring {
        receipt,
        leaves,
        d5,
        d9,
    }
}

/// An honest log: the event appended at index 3 with its receipt, then
/// grown to 9, checkpoints at 5 and 9 cosigned by orgs A and B.
fn honest(ws: &[SigningKey]) -> (WriteReceipt, Vec<Leaf>, Vec<ObservedCheckpoint>) {
    let mut log = new_log();
    let mut receipt = None;
    for i in 0..9 {
        if i == 3 {
            let idx = log.append_intent(b"the event");
            receipt = log.write_receipt(idx);
        } else {
            log.append_intent(format!("other {i}").as_bytes());
        }
    }
    let leaves = log.leaves().to_vec();
    let later = vec![
        witnessed(&leaves[..5], &ws[..2]),
        witnessed(&leaves, &ws[..2]),
    ];
    (receipt.unwrap(), leaves, later)
}

#[test]
fn present_is_the_event_at_the_promised_index_in_leaves_bound_to_every_witnessed_checkpoint() {
    let (dir, ws) = network();
    let (receipt, leaves, later) = honest(&ws);
    assert_eq!(
        receipt.tree_size, 3,
        "a receipt names the index of its leaf"
    );

    let r = check(&receipt, &leaves, &later, &dir);
    assert!(
        matches!(r.result, SilenceProofResult::Present { leaf_index: 3 }),
        "{r:?}"
    );
    assert_eq!(r.bound_tree_size, Some(9));
    assert_eq!(
        r.bound_root_hash.as_deref(),
        Some(hex::encode(root_of(&leaves)).as_str())
    );
    assert!(r.reason.is_none());

    // One witnessed checkpoint covering the event is enough to be present.
    let r = check(&receipt, &leaves, &later[..1], &dir);
    assert!(matches!(r.result, SilenceProofResult::Present { .. }));
    assert_eq!(r.bound_tree_size, Some(5));

    // No witnessed checkpoint: the leaves are a copy nobody cosigned.
    let r = check(&receipt, &leaves, &[], &dir);
    assert!(is_inconclusive(&r), "{r:?}");

    // Cosigned by one operator only: not witnessed.
    let one: Vec<_> = later
        .iter()
        .map(|oc| cosigned(oc.checkpoint.clone(), &ws[..1]))
        .collect();
    assert!(is_inconclusive(&check(&receipt, &leaves, &one, &dir)));

    // A leaf after the event edited: the leaves no longer reproduce the
    // largest checkpoint, so they are not the log's history (before the
    // review the event was bound to the size-5 checkpoint alone). That is
    // the leaves' fault, not the log's: the reason must not call it a fork.
    let mut tail_edited = leaves.clone();
    tail_edited[7].payload_hash = "cd".repeat(32);
    let r = check(&receipt, &tail_edited, &later, &dir);
    assert!(is_inconclusive(&r), "{r:?}");
    let why = r.reason.unwrap();
    assert!(why.contains("not the log's history"), "{why}");
    assert!(
        !why.contains("fork") && !why.contains("equivocation"),
        "{why}"
    );
}

/// Finding 2: a log that shows witnesses of orgs A and B a history without
/// the event (checkpoints 7 and 10) and witnesses of orgs C and D one with
/// it (checkpoint 12) forked; the event is not PRESENT in "the" witnessed
/// history, and the fork is named.
#[test]
fn a_fork_across_sizes_is_equivocation_not_presence() {
    let (dir, ws) = network();
    let mut a = new_log();
    for i in 0..10 {
        a.append_intent(format!("a {i}").as_bytes());
    }
    let a_leaves = a.leaves().to_vec();
    let a7 = witnessed(&a_leaves[..7], &ws[..2]);
    let a10 = witnessed(&a_leaves, &ws[..2]);
    let mut b = new_log();
    let mut receipt = None;
    for i in 0..12 {
        let idx = b.append_intent(format!("b {i}").as_bytes());
        if i == 5 {
            receipt = b.write_receipt(idx);
        }
    }
    let receipt = receipt.unwrap();
    let b_leaves = b.leaves().to_vec();
    let b12 = witnessed(&b_leaves, &ws[2..]);

    // Branch A alone, with its own leaves: the event was left out.
    let r = check(&receipt, &a_leaves, &[a7.clone(), a10.clone()], &dir);
    assert!(is_censored(&r), "{r:?}");
    // Both branches, with branch B's leaves (the largest): a fork.
    let r = check(
        &receipt,
        &b_leaves,
        &[a7.clone(), a10.clone(), b12.clone()],
        &dir,
    );
    assert!(is_inconclusive(&r), "{r:?}");
    assert!(r.reason.as_deref().unwrap().contains("fork"), "{r:?}");
    // The same over dossiers: before the review, exit 0 PRESENT bound to 12.
    let dossiers = [
        dossier(&a_leaves[..7], &a7),
        dossier(&a_leaves, &a10),
        dossier(&b_leaves, &b12),
    ];
    let p = silence_proof_over_dossiers(&receipt, &dossiers, &ctx(&dir, 2, &[]));
    assert_eq!(p.leaves_from, Some(2));
    assert!(is_inconclusive(&p.report), "{p:?}");
    assert!(p.report.reason.as_deref().unwrap().contains("fork"));
}

/// Finding 3 (first review) and 2 (second): the receipt promises index
/// `tree_size`. An event the log left out of witnessed checkpoints 5 and 9
/// and then appended at index 9 is in its history, but not where it was
/// promised: MISPLACED, a broken signed promise, neither PRESENT nor
/// CENSORED (it was not left out).
#[test]
fn the_event_at_another_index_than_promised_is_misplaced() {
    let (dir, ws) = network();
    let mut log = new_log();
    for i in 0..9 {
        log.append_intent(format!("other {i}").as_bytes());
    }
    let late = log.append_intent(b"the event, late");
    let leaves = log.leaves().to_vec();
    // The receipt the log signed when it accepted the event, at size 0.
    let receipt = WriteReceipt::sign(&key(), &leaves[late as usize].payload_hash, 0, NOW);
    let later = vec![
        witnessed(&leaves[..5], &ws[..2]),
        witnessed(&leaves[..9], &ws[..2]),
        witnessed(&leaves, &ws[..2]),
    ];
    let r = check(&receipt, &leaves, &later, &dir);
    assert!(
        matches!(
            r.result,
            SilenceProofResult::Misplaced {
                promised_index: 0,
                leaf_index: 9,
                witnessed_checkpoints_without: 2
            }
        ),
        "{r:?}"
    );
    assert_eq!(r.bound_tree_size, Some(10));
    let why = r.reason.unwrap();
    assert!(why.contains("leaf 9, not leaf 0"), "{why}");
    assert!(why.contains("2 witnessed checkpoint(s)"), "{why}");
    // No minimum applies: the size-10 checkpoint alone fixes leaf 0.
    let r = silence_proof_in_context(&receipt, &leaves, &later[2..], &ctx(&dir, 5, &[]));
    assert!(
        matches!(
            r.result,
            SilenceProofResult::Misplaced {
                witnessed_checkpoints_without: 0,
                ..
            }
        ),
        "{r:?}"
    );

    // Mutation guard: the event is looked for only among the leaves the
    // witnessed checkpoints cover. With checkpoints 5 and 9 alone, the
    // event at index 9 is beyond them: it was left out of both.
    let r = check(&receipt, &leaves, &later[..2], &dir);
    assert!(is_censored(&r), "{r:?}");
    assert_eq!(r.bound_tree_size, Some(9));

    // An event before the promised index is misplaced too.
    let early = WriteReceipt::sign(&key(), &leaves[3].payload_hash, 5, NOW);
    let r = check(&early, &leaves, &later[1..], &dir);
    assert!(
        matches!(
            r.result,
            SilenceProofResult::Misplaced {
                promised_index: 5,
                leaf_index: 3,
                witnessed_checkpoints_without: 0
            }
        ),
        "{r:?}"
    );
}

/// Finding 4 (first review) and 1 (second): a receipt signed by a key whose
/// revocation has taken effect proves nothing, whatever it claims about
/// when it was issued, since whoever stole the key can sign one for any
/// hash. But a revocation that has not taken effect on the witnessed
/// history is not applied: otherwise the accused log escapes for free by
/// signing one that never cuts anything off.
#[test]
fn only_a_revocation_in_effect_neutralises_a_receipt() {
    let (dir, ws) = network();
    let c = censoring(&ws);
    let later = [
        cosigned(c.d5.checkpoint.clone(), &ws[..2]),
        cosigned(c.d9.checkpoint.clone(), &ws[..2]),
    ];
    let with = |rs: &[RevocationStatement]| {
        silence_proof_in_context(&c.receipt, &c.leaves, &later, &ctx(&dir, 2, rs))
    };
    assert!(is_censored(&with(&[])));

    // Not in effect, so not applied: v1 statements, whatever their time
    // (the log dates its own checkpoints), and v2 statements whose index
    // no witnessed checkpoint has reached. Before the second review each
    // of these made the result Inconclusive.
    let log = new_log();
    for r in [
        log.revoke(Some(u64::MAX), None, "noop"),
        log.revoke(Some(0), None, "everything, by time"),
        log.revoke(Some(NOW), None, "now"),
        log.revoke(Some(u64::MAX), Some(u64::MAX), "noop"),
        log.revoke(Some(0), Some(10), "one past the witnessed history"),
    ] {
        let rep = with(std::slice::from_ref(&r));
        assert!(is_censored(&rep), "{r:?}: {rep:?}");
        assert_eq!(rep.revocations_not_in_effect, 1, "{r:?}");
    }

    // In effect: a v2 index at or below a counted checkpoint. Every
    // verifier holding it rejects every checkpoint of this log past that
    // index, so the identity ends there.
    for index in [9, 5, 0] {
        let r = log.revoke(Some(u64::MAX), Some(index), "key stolen");
        let rep = with(&[r]);
        assert!(is_inconclusive(&rep), "{index}: {rep:?}");
        assert!(
            rep.reason.as_deref().unwrap().contains("revoked"),
            "{rep:?}"
        );
        assert_eq!(rep.revocations_not_in_effect, 0);
    }
    // One in effect among others: inconclusive; the rest are counted as
    // not in effect.
    let rep = with(&[
        log.revoke(Some(u64::MAX), None, "noop"),
        log.revoke(None, Some(9), "key stolen"),
    ]);
    assert!(is_inconclusive(&rep));
    assert_eq!(rep.revocations_not_in_effect, 1);

    // A revocation of another key, or one that does not verify, changes
    // nothing and is not counted.
    let other =
        WitnessLog::resume(IdentityKeypair::from_bytes(&[9u8; 32]), 0).revoke(None, Some(0), "x");
    let mut forged = log.revoke(None, Some(9), "key stolen");
    forged.reason = "edited".into();
    for rs in [vec![other], vec![forged]] {
        let rep = with(&rs);
        assert!(is_censored(&rep), "{rep:?}");
        assert_eq!(rep.revocations_not_in_effect, 0);
    }
}

/// The case revocations exist for: someone holding a stolen key signs a
/// backdated receipt for a hash the honest log never saw, and "proves" its
/// public witnessed dossiers omit it. Once the operator's v2 revocation at
/// its witnessed size is known, the receipt proves nothing.
#[test]
fn a_receipt_forged_with_a_stolen_key_proves_nothing_once_the_key_is_revoked() {
    let (dir, ws) = network();
    let (_, leaves, later) = honest(&ws);
    let forged = WriteReceipt::sign(&key(), &"ef".repeat(32), 0, NOW - 1);
    assert!(is_censored(&check(&forged, &leaves, &later, &dir)));
    let revocation = new_log().revoke(None, Some(9), "key stolen");
    let r = silence_proof_in_context(
        &forged,
        &leaves,
        &later,
        &ctx(&dir, 2, std::slice::from_ref(&revocation)),
    );
    assert!(is_inconclusive(&r), "{r:?}");
}

/// Second review, finding 1: revocations a dossier carries apply only when
/// that dossier counts. The reviewer's repro: a junk dossier (broken
/// signature) carrying a no-op revocation turned 30 into 20.
#[test]
fn a_set_aside_dossier_cannot_bring_a_revocation() {
    let (dir, ws) = network();
    let c = censoring(&ws);
    let log = new_log();
    let in_effect = log.revoke(None, Some(9), "key stolen");
    for r in [log.revoke(Some(u64::MAX), None, "noop"), in_effect.clone()] {
        let mut junk = c.d9.clone();
        junk.checkpoint.tree_size = 10;
        junk.revocations.push(r.clone());
        let p = silence_proof_over_dossiers(
            &c.receipt,
            &[c.d5.clone(), c.d9.clone(), junk],
            &ctx(&dir, 2, &[]),
        );
        assert_eq!(p.dossiers[2], SilenceCheckpointUse::BadSignature);
        assert!(is_censored(&p.report), "{r:?}: {p:?}");
    }
    // Carried by a counted dossier, a revocation in effect applies.
    let mut d9 = c.d9.clone();
    d9.revocations.push(in_effect.clone());
    let p = silence_proof_over_dossiers(&c.receipt, &[c.d5.clone(), d9], &ctx(&dir, 2, &[]));
    assert!(is_inconclusive(&p.report), "{p:?}");
    // And so does one passed in directly, whatever carries the dossiers.
    let p = silence_proof_over_dossiers(
        &c.receipt,
        &[c.d5.clone(), c.d9.clone()],
        &ctx(&dir, 2, std::slice::from_ref(&in_effect)),
    );
    assert!(is_inconclusive(&p.report), "{p:?}");
}

/// Finding 1: a dossier that is forged, edited, unwitnessed or of another
/// log is used for nothing: it never picks the leaves and never turns a
/// CENSORED into anything else.
#[test]
fn a_forged_edited_unwitnessed_or_foreign_dossier_never_changes_a_censored() {
    let (dir, ws) = network();
    let c = censoring(&ws);
    let genuine = vec![c.d5.clone(), c.d9.clone()];
    let base = silence_proof_over_dossiers(&c.receipt, &genuine, &ctx(&dir, 2, &[]));
    assert!(is_censored(&base.report), "{base:?}");
    assert_eq!(base.leaves_from, Some(1));

    // A checkpoint of size 10 whose signature fails, with the event
    // appended to its leaves (before the review: PRESENT-unbound, exit 20).
    let mut forged = c.d9.clone();
    forged.checkpoint.tree_size = 10;
    let mut extra = forged.leaves[8].clone();
    extra.index = 9;
    extra.payload_hash = c.receipt.payload_hash.clone();
    forged.leaves.push(extra);
    // An edited copy of the size-9 dossier: genuine checkpoint and
    // cosignatures, leaf 0 changed.
    let mut edited = c.d9.clone();
    edited.leaves[0].payload_hash = "cd".repeat(32);
    // Signed by the log, never witnessed: another history with the event
    // at the promised index, larger than anything witnessed.
    let mut fork_leaves = c.leaves.clone();
    fork_leaves[0].payload_hash = c.receipt.payload_hash.clone();
    let mut extra = fork_leaves[8].clone();
    extra.index = 9;
    fork_leaves.push(extra);
    let unwitnessed = dossier(&fork_leaves, &witnessed(&fork_leaves, &[]));
    // The same, cosigned by one organisation only.
    let one_operator = dossier(&fork_leaves, &witnessed(&fork_leaves, &ws[..1]));
    // Another log, larger, witnessed by everyone.
    let other_key = SigningKey::from_bytes(&[9u8; 32]);
    let mut other = WitnessLog::resume(IdentityKeypair::from_bytes(&[9u8; 32]), 0);
    for i in 0..12 {
        other.append_intent(format!("unrelated {i}").as_bytes());
    }
    let ocp = SignedTreeHead::sign(&other_key, 12, &root_of(other.leaves()), NOW);
    let foreign = dossier(other.leaves(), &cosigned(ocp, &ws));

    let extras = [
        (forged, SilenceCheckpointUse::BadSignature),
        (edited, SilenceCheckpointUse::LeavesDoNotReproduce),
        (unwitnessed, SilenceCheckpointUse::NotWitnessed),
        (one_operator, SilenceCheckpointUse::NotWitnessed),
        (foreign, SilenceCheckpointUse::OtherLog),
    ];
    for (extra, why) in &extras {
        // First or last, alone or with the others.
        for front in [true, false] {
            let mut ds = genuine.clone();
            if front {
                ds.insert(0, extra.clone());
            } else {
                ds.push(extra.clone());
            }
            let p = silence_proof_over_dossiers(&c.receipt, &ds, &ctx(&dir, 2, &[]));
            assert!(is_censored(&p.report), "{why:?} front={front}: {p:?}");
            assert_eq!(p.report.bound_tree_size, Some(9));
            let at = if front { 0 } else { 2 };
            assert_eq!(p.dossiers[at], *why);
            assert_eq!(p.leaves_from, Some(if front { 2 } else { 1 }));
        }
    }
    let mut all: Vec<Dossier> = extras.iter().map(|(d, _)| d.clone()).collect();
    all.extend(genuine.iter().cloned());
    let p = silence_proof_over_dossiers(&c.receipt, &all, &ctx(&dir, 2, &[]));
    assert!(is_censored(&p.report), "{p:?}");

    // Only invalid dossiers: nothing counts.
    let p = silence_proof_over_dossiers(&c.receipt, &all[..extras.len()], &ctx(&dir, 2, &[]));
    assert!(is_inconclusive(&p.report));
    assert_eq!(p.leaves_from, None);
}

/// An edited copy of a witnessed dossier cannot hide an honest log's
/// event either: it is set aside, and the genuine dossiers decide.
#[test]
fn an_edited_dossier_cannot_hide_an_honest_logs_event() {
    let (dir, ws) = network();
    let (receipt, leaves, later) = honest(&ws);
    let d5 = dossier(&leaves[..5], &later[0]);
    let d9 = dossier(&leaves, &later[1]);
    let mut dropped = d9.clone();
    dropped.leaves.remove(3);
    let p =
        silence_proof_over_dossiers(&receipt, &[dropped.clone(), d5.clone()], &ctx(&dir, 2, &[]));
    assert_eq!(p.dossiers[0], SilenceCheckpointUse::LeavesDoNotReproduce);
    assert!(
        matches!(
            p.report.result,
            SilenceProofResult::Present { leaf_index: 3 }
        ),
        "{p:?}"
    );
    assert_eq!(p.report.bound_tree_size, Some(5));
    let p = silence_proof_over_dossiers(&receipt, &[d5, dropped, d9], &ctx(&dir, 2, &[]));
    assert_eq!(p.report.bound_tree_size, Some(9));
    assert_eq!(p.leaves_from, Some(2));
}

/// Mutation guard: a checkpoint no larger than the receipt's size is from
/// before the event was due and never counts.
#[test]
fn checkpoints_no_larger_than_the_receipt_do_not_count() {
    let (dir, ws) = network();
    let mut log = new_log();
    for i in 0..9 {
        log.append_intent(format!("other {i}").as_bytes());
    }
    let leaves = log.leaves().to_vec();
    // The event was due at index 5.
    let receipt = WriteReceipt::sign(&key(), &"ab".repeat(32), 5, NOW);
    let later = vec![
        witnessed(&leaves[..3], &ws[..2]),
        witnessed(&leaves[..5], &ws[..2]),
        witnessed(&leaves, &ws[..2]),
    ];
    let r = check(&receipt, &leaves, &later, &dir);
    assert!(
        matches!(
            r.result,
            SilenceProofResult::Inconclusive {
                witnessed_checkpoints_seen: 1,
                ..
            }
        ),
        "{r:?}"
    );
    let r = silence_proof_in_context(&receipt, &leaves, &later, &ctx(&dir, 1, &[]));
    assert!(
        matches!(
            r.result,
            SilenceProofResult::Censored {
                witnessed_checkpoints_after: 1,
                ..
            }
        ),
        "{r:?}"
    );
    let ds: Vec<Dossier> = later
        .iter()
        .map(|oc| dossier(&leaves[..oc.checkpoint.tree_size as usize], oc))
        .collect();
    let p = silence_proof_over_dossiers(&receipt, &ds, &ctx(&dir, 2, &[]));
    assert_eq!(
        p.dossiers,
        [
            SilenceCheckpointUse::NotAfterReceipt,
            SilenceCheckpointUse::NotAfterReceipt,
            SilenceCheckpointUse::Counted
        ]
    );
}

/// Mutation guard: a checkpoint counts only if the log's signature on it
/// verifies, even when witnesses cosigned exactly those bytes.
#[test]
fn a_checkpoint_whose_signature_fails_does_not_count() {
    let (dir, ws) = network();
    let c = censoring(&ws);
    // The size-9 checkpoint with its time changed after signing: same size
    // and root, so the leaves still reproduce it, but the log never signed
    // it. Witnesses cosign the altered bytes.
    let mut altered = c.d9.checkpoint.clone();
    altered.timestamp_ms += 1;
    assert!(altered.verify().is_err());
    let later = [
        cosigned(c.d5.checkpoint.clone(), &ws[..2]),
        cosigned(altered, &ws[..2]),
    ];
    let r = check(&c.receipt, &c.leaves, &later, &dir);
    assert!(
        matches!(
            r.result,
            SilenceProofResult::Inconclusive {
                witnessed_checkpoints_seen: 1,
                ..
            }
        ),
        "{r:?}"
    );
}
