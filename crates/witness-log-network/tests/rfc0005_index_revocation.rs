//! RFC-0005: an index-based revocation cut-off that does not depend on
//! timestamps the key holder writes.

use ed25519_dalek::SigningKey;
use witness_log_core::identity::{IdentityKeypair, SessionKeypair};
use witness_log_core::leaf::{Leaf, LeafType};
use witness_log_core::merkle::{leaf_hash, MerkleTree};
use witness_log_core::sth::SignedTreeHead;
use witness_log_network::*;

fn leaf(index: u64, ts: u64, session: &str) -> Leaf {
    Leaf {
        index,
        leaf_type: LeafType::ActiveIntent.tag(),
        timestamp_ms: ts,
        session_pubkey: session.to_string(),
        payload_hash: hex::encode([0xABu8; 32]),
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

fn head(id: &IdentityKeypair, leaves: &[Leaf], ts: u64) -> SignedTreeHead {
    let mut t = MerkleTree::new();
    for l in leaves {
        t.append(leaf_hash(&l.canonical_bytes()));
    }
    SignedTreeHead::sign(
        &SigningKey::from_bytes(&id.to_bytes()),
        t.size(),
        &t.root(),
        ts,
    )
}

fn ctx<'a>(
    ident: &'a str,
    revs: &'a [witness_log_core::identity::RevocationStatement],
) -> VerifyContext<'a> {
    VerifyContext {
        expected_identity_pubkey: Some(ident),
        trusted_directory: None,
        min_receipts: None,
        revocations: revs,
        known_heads: &[],
        evidence: &[],
        subject_org: None,
        accept_fleet_anchor: false,
    }
}

/// Backdating defeats the timestamp rule but not the index rule: a holder
/// of the compromised key who writes leaves 4..8 with timestamps before the
/// revocation and signs a head of size 8 "before" it still fails, because
/// the operator revoked as of index 4.
#[test]
fn backdated_history_past_the_cut_off_is_rejected() {
    let id = IdentityKeypair::generate();
    let session = SessionKeypair::generate();
    let binding = id.bind_session(&session.verifying_key(), 1, 1_000, None);
    let revocation = id.revoke_at_index(5_000, 4, "key compromised");
    let leaves: Vec<Leaf> = (0..8)
        .map(|i| leaf(i, 2_000, &session.public_hex()))
        .collect();
    let dossier = Dossier {
        identity_pubkey: id.public_hex(),
        leaves: leaves.clone(),
        checkpoint: head(&id, &leaves, 4_000), // backdated before as_of_ms
        witness_receipts: vec![],
        witness_directory: WitnessDirectory::default(),
        key_bindings: vec![binding.clone()],
        revocations: vec![],
        fleet_anchor: None,
    };
    let ident = id.public_hex();
    // The verifier knows the revocation out of band; the dossier omits it.
    let known = vec![revocation.clone()];
    let r = dossier.verify(0.66, &ctx(&ident, &known));
    assert!(r.bindings_asserted && !r.bindings_valid, "{r:?}");
    assert_ne!(r.verdict, Verdict::Unanchored);
    // The same with a v1 revocation passes the backdated history: that
    // is exactly the gap the index closes.
    let v1 = vec![id.revoke(5_000, "key compromised")];
    assert_eq!(
        dossier.verify(0.66, &ctx(&ident, &v1)).verdict,
        Verdict::Unanchored
    );
}

/// The honest history up to the cut-off keeps verifying after revocation.
#[test]
fn history_up_to_the_cut_off_still_verifies() {
    let id = IdentityKeypair::generate();
    let session = SessionKeypair::generate();
    let binding = id.bind_session(&session.verifying_key(), 1, 1_000, None);
    let leaves: Vec<Leaf> = (0..4)
        .map(|i| leaf(i, 2_000, &session.public_hex()))
        .collect();
    let revocation = id.revoke_at_index(5_000, 4, "rotated");
    let dossier = Dossier {
        identity_pubkey: id.public_hex(),
        leaves: leaves.clone(),
        checkpoint: head(&id, &leaves, 3_000),
        witness_receipts: vec![],
        witness_directory: WitnessDirectory::default(),
        key_bindings: vec![binding],
        revocations: vec![revocation.clone()],
        fleet_anchor: None,
    };
    let ident = id.public_hex();
    let r = dossier.verify(0.66, &ctx(&ident, &[]));
    assert!(r.bindings_valid, "{r:?}");
    assert_eq!(r.verdict, Verdict::Unanchored);
    // A head one larger than the cut-off is not.
    let mut longer = leaves.clone();
    longer.push(leaf(4, 2_000, &session.public_hex()));
    let mut d2 = dossier.clone();
    d2.leaves = longer.clone();
    d2.checkpoint = head(&id, &longer, 3_000);
    assert!(!d2.verify(0.66, &ctx(&ident, &[])).bindings_valid);
}

/// The smallest cut-off wins when several revocations are known, and a
/// tampered index fails the signature.
#[test]
fn smallest_cut_off_wins_and_the_index_is_signed() {
    let id = IdentityKeypair::generate();
    let session = SessionKeypair::generate();
    let binding = id.bind_session(&session.verifying_key(), 1, 1_000, None);
    let leaves: Vec<Leaf> = (0..6)
        .map(|i| leaf(i, 2_000, &session.public_hex()))
        .collect();
    let dossier = Dossier {
        identity_pubkey: id.public_hex(),
        leaves: leaves.clone(),
        checkpoint: head(&id, &leaves, 3_000),
        witness_receipts: vec![],
        witness_directory: WitnessDirectory::default(),
        key_bindings: vec![binding],
        revocations: vec![],
        fleet_anchor: None,
    };
    let ident = id.public_hex();
    let both = vec![
        id.revoke_at_index(9_000, 10, "a"),
        id.revoke_at_index(9_000, 5, "b"),
    ];
    assert!(!dossier.verify(0.66, &ctx(&ident, &both)).bindings_valid);
    let mut forged = id.revoke_at_index(9_000, 3, "c");
    forged.as_of_index = Some(100);
    let mut d2 = dossier.clone();
    d2.revocations = vec![forged];
    assert!(
        !d2.verify(0.66, &ctx(&ident, &[])).bindings_valid,
        "a forged statement invalidates"
    );
}

/// Corpus vector 12: messages, signatures and cut-off cases.
#[test]
fn corpus_vector_12() {
    use witness_log_core::identity::{revocation_message, RevocationStatement};
    let root =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../corpus/12_revocation.json");
    let v: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(root).unwrap()).unwrap();
    let pk: [u8; 32] = hex::decode(v["identity_pubkey"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let stmt = |k: &str| -> RevocationStatement {
        serde_json::from_value(v[k]["statement"].clone()).unwrap()
    };
    for k in ["v1", "v2"] {
        let r = stmt(k);
        let msg = revocation_message(&pk, r.as_of_ms, r.as_of_index, &r.reason);
        assert_eq!(
            hex::encode(msg),
            v[k]["message_hex"].as_str().unwrap(),
            "{k}"
        );
        assert!(r.verify().is_ok(), "{k}");
    }
    let mut stripped = stmt("v2");
    stripped.as_of_index = None;
    assert!(stripped.verify().is_err());
    for c in v["cut_off_cases"].as_array().unwrap() {
        let r = stmt(c["revocation"].as_str().unwrap());
        let max = c["max_leaf_index"].as_u64().unwrap();
        let res = revocation_cut_off(
            &[r],
            (0..=max).map(|i| (i, 0u64)),
            c["checkpoint_timestamp_ms"].as_u64().unwrap(),
            c["checkpoint_tree_size"].as_u64().unwrap(),
        );
        assert_eq!(res.is_ok(), c["valid"].as_bool().unwrap(), "{c}: {res:?}");
    }
}
