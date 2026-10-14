//! Generates `/corpus/*.json` — the frozen test vectors independent
//! implementations are expected to reproduce exactly. Uses fixed seeds
//! throughout so every value here is deterministic and reproducible by
//! anyone re-running this generator: no randomness in the corpus itself.
//!
//! Ed25519 signing (RFC 8032) is deterministic given a fixed key and
//! message — no nonce randomness — so signature vectors below are exact,
//! not just "shape-compatible."
//!
//! Run with: cargo run -p witness-log-core --example generate_corpus

use ed25519_dalek::SigningKey;
use serde_json::json;
use std::fs;
use witness_log_core::c2sp::{bridge, Checkpoint, Cosignature, SignedNote, VerifierKey};
use witness_log_core::identity::IdentityKeypair;
use witness_log_core::leaf::{Leaf, LeafType};
use witness_log_core::merkle::{leaf_hash, verify_consistency, verify_inclusion, MerkleTree};
use witness_log_core::sth::SignedTreeHead;

/// A fixed, published seed. This key is PUBLIC and for conformance testing
/// only — never use it for anything real.
const FIXED_SEED: [u8; 32] = [
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
];

fn fixed_leaf(
    index: u64,
    leaf_type: LeafType,
    session_pubkey: &str,
    payload_hash_byte: u8,
) -> Leaf {
    Leaf {
        index,
        leaf_type: leaf_type.tag(),
        // Fixed, not wall-clock time, so the corpus is reproducible.
        timestamp_ms: 1_700_000_000_000 + index * 1000,
        session_pubkey: session_pubkey.to_string(),
        payload_hash: hex::encode([payload_hash_byte; 32]),
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

fn main() {
    // CARGO_MANIFEST_DIR is this crate's own directory
    // (crates/witness-log-core), set by cargo regardless of the working
    // directory the example is invoked from. The corpus lives at
    // <repo-root>/corpus, i.e. two levels up from here. Resolving via CWD
    // (the previous approach) silently wrote outside the checkout when run
    // from the repo root, which is exactly how CI invokes it -- the
    // conformance-drift check was comparing an untouched directory against
    // itself on every run. See review finding 05.
    let manifest_dir = std::path::PathBuf::from(
        std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR must be set by cargo"),
    );
    let repo_root = manifest_dir
        .parent() // crates/
        .and_then(|p| p.parent()) // repo root
        .expect("witness-log-core must be at <repo-root>/crates/witness-log-core");
    let dir = repo_root.join("corpus");
    fs::create_dir_all(&dir).expect("failed to create corpus output directory");
    let dir = dir
        .to_str()
        .expect("corpus path must be valid UTF-8")
        .to_string();
    let dir = dir.as_str();

    let identity = IdentityKeypair::from_bytes(&FIXED_SEED);
    let signing_key = SigningKey::from_bytes(&FIXED_SEED);
    let session_pubkey = identity.public_hex(); // reuse for determinism in vectors; real usage differs

    // --- Vector set 1: leaf canonical encoding + leaf hash ---
    let leaves: Vec<Leaf> = (0..5)
        .map(|i| fixed_leaf(i, LeafType::ActiveIntent, &session_pubkey, i as u8 + 1))
        .collect();
    let leaf_vectors: Vec<_> = leaves
        .iter()
        .map(|l| {
            let canon = l.canonical_bytes();
            let h = leaf_hash(&canon);
            json!({
                "leaf": l,
                "canonical_bytes_hex": hex::encode(&canon),
                "leaf_hash_hex": hex::encode(h),
            })
        })
        .collect();
    write_json(
        dir,
        "01_leaf_encoding.json",
        &json!({
            "description": "Canonical byte encoding and RFC6962 leaf-hash (SHA256(0x00 || canonical_bytes)) for five fixed leaves. Any conformant implementation MUST reproduce these hashes exactly given identical input fields.",
            "vectors": leaf_vectors,
        }),
    );

    // --- Vector set 2: Merkle roots for n = 1..=8 fixed leaves ---
    let mut root_vectors = Vec::new();
    for n in 1..=8u64 {
        let mut tree = MerkleTree::new();
        for i in 0..n {
            let l = fixed_leaf(i, LeafType::ActiveIntent, &session_pubkey, i as u8 + 1);
            tree.append(leaf_hash(&l.canonical_bytes()));
        }
        root_vectors.push(json!({
            "tree_size": n,
            "root_hex": hex::encode(tree.root()),
        }));
    }
    write_json(
        dir,
        "02_merkle_roots.json",
        &json!({
            "description": "RFC6962 Merkle root for tree sizes 1 through 8, built from fixed_leaf(0..n). Domain-separated hashing: leaf=SHA256(0x00||data), node=SHA256(0x01||left||right).",
            "vectors": root_vectors,
        }),
    );

    // --- Vector set 3: inclusion proof for n=7, every index ---
    let n = 7u64;
    let mut tree = MerkleTree::new();
    for i in 0..n {
        let l = fixed_leaf(i, LeafType::ActiveIntent, &session_pubkey, i as u8 + 1);
        tree.append(leaf_hash(&l.canonical_bytes()));
    }
    let root = tree.root();
    let mut proof_vectors = Vec::new();
    for i in 0..n {
        let l = fixed_leaf(i, LeafType::ActiveIntent, &session_pubkey, i as u8 + 1);
        let lh = leaf_hash(&l.canonical_bytes());
        let proof = tree.inclusion_proof(i, n).unwrap();
        assert!(
            verify_inclusion(&lh, i, n, &proof, &root),
            "self-check failed for i={i}"
        );
        proof_vectors.push(json!({
            "leaf_index": i,
            "tree_size": n,
            "leaf_hash_hex": hex::encode(lh),
            "proof_hex": proof.iter().map(hex::encode).collect::<Vec<_>>(),
        }));
    }
    write_json(
        dir,
        "03_inclusion_proofs.json",
        &json!({
            "description": "Inclusion proofs for every leaf index in a 7-leaf tree built from fixed_leaf(0..7). proof_hex is ordered innermost-sibling-first (see merkle.rs `path()` docs). root_hex is the tree's root; verifying any (leaf_hash, leaf_index, tree_size, proof) against root_hex MUST succeed.",
            "root_hex": hex::encode(root),
            "vectors": proof_vectors,
        }),
    );

    // --- Vector set 4: STH signing with the fixed key ---
    let fixed_root = [0xabu8; 32];
    let sth = SignedTreeHead::sign(&signing_key, 42, &fixed_root, 1_700_000_000_000);
    write_json(
        dir,
        "04_signed_tree_head.json",
        &json!({
            "description": "Ed25519 (RFC 8032, deterministic) signature over a fixed tree_size/root/timestamp using the published fixed test seed. Signer pubkey and signature MUST match exactly — Ed25519 signing has no randomness given a fixed key and message.",
            "seed_hex": hex::encode(FIXED_SEED),
            "sth": sth,
        }),
    );

    // --- Vector set 5: redaction continuity ---
    // Demonstrates that forgetting a leaf's salt does not change any leaf
    // hash or the tree root — see witness-log-core::redaction module docs.
    let mut log_tree = MerkleTree::new();
    let mut redaction_leaves = Vec::new();
    for i in 0..4u64 {
        let l = fixed_leaf(i, LeafType::ActiveIntent, &session_pubkey, i as u8 + 1);
        log_tree.append(leaf_hash(&l.canonical_bytes()));
        redaction_leaves.push(l);
    }
    let root_before = log_tree.root();
    // A redaction leaf appended for index 1 — payload_hash is the zero hash
    // per witness-log-core::log::WitnessLog::forget's convention for marker leaves.
    let redaction_marker = Leaf {
        index: 4,
        leaf_type: LeafType::Redaction.tag(),
        timestamp_ms: 1_700_000_004_000,
        session_pubkey: session_pubkey.clone(),
        payload_hash: hex::encode([0u8; 32]),
        redacted_index: Some(1),
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
    log_tree.append(leaf_hash(&redaction_marker.canonical_bytes()));
    let root_after = log_tree.root();
    write_json(
        dir,
        "05_redaction_continuity.json",
        &json!({
            "description": "The leaf hashes for indices 0-3 are unchanged before and after a 0x03 Redaction marker is appended for index 1. Root changes only because a NEW leaf (the marker) was appended, not because any prior leaf hash changed. A conformant implementation forgetting a salt MUST NOT alter any previously-committed leaf hash.",
            "leaves_before_redaction": redaction_leaves,
            "root_before_hex": hex::encode(root_before),
            "redaction_marker_leaf": redaction_marker,
            "root_after_hex": hex::encode(root_after),
        }),
    );

    // --- Vector set 6: consistency proof between two checkpoints ---
    // Demonstrates the append-only extension property an automated witness
    // (human- or agent-operated) checks before signing every new receipt.
    let old_size = 4u64;
    let new_size = 9u64;
    let mut full_tree = MerkleTree::new();
    let mut all_leaves = Vec::new();
    for i in 0..new_size {
        let l = fixed_leaf(i, LeafType::ActiveIntent, &session_pubkey, i as u8 + 1);
        full_tree.append(leaf_hash(&l.canonical_bytes()));
        all_leaves.push(l);
    }
    let new_root = full_tree.root();
    let mut old_tree = MerkleTree::new();
    for l in &all_leaves[0..old_size as usize] {
        old_tree.append(leaf_hash(&l.canonical_bytes()));
    }
    let old_root = old_tree.root();
    let consistency = full_tree.consistency_proof(old_size, new_size).unwrap();
    assert!(
        verify_consistency(old_size, &old_root, new_size, &new_root, &consistency),
        "self-check failed for consistency proof"
    );
    write_json(
        dir,
        "06_consistency_proof.json",
        &json!({
            "description": "Consistency proof (RFC 6962 §2.1.2) that the 9-leaf tree built from fixed_leaf(0..9) is an append-only extension of the 4-leaf tree built from fixed_leaf(0..4). proof_hex entries are consumed front-to-back by the verifier; old_root MUST be substituted (not looked up) at exactly one point in the recursive reconstruction — see merkle.rs verify_subproof doc comment. A conformant implementation MUST accept this proof and MUST reject it if any single proof element, old_root, or new_root is altered.",
            "old_tree_size": old_size,
            "old_root_hex": hex::encode(old_root),
            "new_tree_size": new_size,
            "new_root_hex": hex::encode(new_root),
            "proof_hex": consistency.iter().map(hex::encode).collect::<Vec<_>>(),
        }),
    );

    // --- Vector set 7: HandoffAttestation encoding + cross-log binding ---
    // Two fixed leaves representing the sender's and receiver's
    // independent attestations of the SAME handoff, plus one deliberately
    // mismatched pair to show what a failed binding check looks like.
    let sender_identity = "aa".repeat(32);
    let receiver_identity = "bb".repeat(32);
    let state_hash = hex::encode([0x77u8; 32]);
    let sent_leaf = Leaf {
        index: 0,
        leaf_type: LeafType::HandoffAttestation.tag(),
        timestamp_ms: 1_700_000_010_000,
        session_pubkey: session_pubkey.clone(),
        payload_hash: hex::encode([0x01u8; 32]),
        redacted_index: None,
        revoked_identity: None,
        handoff_direction: Some(witness_log_core::leaf::HandoffDirection::Sent),
        counterparty_pubkey: Some(receiver_identity.clone()),
        handoff_state_hash: Some(state_hash.clone()),
        authorization_event_kind: None,
        authorization_scope_hash: None,
        anchor_url: None,
        anchor_proof_json: None,
        anchor_proof_hash: None,
    };
    let received_leaf = Leaf {
        index: 0,
        leaf_type: LeafType::HandoffAttestation.tag(),
        timestamp_ms: 1_700_000_011_000,
        // A distinct, VALID session key (hex): a leaf must be well-formed on its
        // own, and the schema test checks every corpus leaf against SPEC §3.
        session_pubkey: hex::encode([0xB2u8; 32]),
        payload_hash: hex::encode([0x02u8; 32]), // different salt -> different payload_hash, by design
        redacted_index: None,
        revoked_identity: None,
        handoff_direction: Some(witness_log_core::leaf::HandoffDirection::Received),
        counterparty_pubkey: Some(sender_identity.clone()),
        handoff_state_hash: Some(state_hash.clone()),
        authorization_event_kind: None,
        authorization_scope_hash: None,
        anchor_url: None,
        anchor_proof_json: None,
        anchor_proof_hash: None,
    };
    let binding_ok = witness_log_core::leaf::verify_handoff_binding(
        &sender_identity,
        &sent_leaf,
        &receiver_identity,
        &received_leaf,
    );
    assert!(
        binding_ok.is_ok(),
        "self-check: matching handoff attestations must bind"
    );

    let mismatched_received = Leaf {
        handoff_state_hash: Some(hex::encode([0x99u8; 32])), // wrong content
        ..received_leaf.clone()
    };
    let binding_fails = witness_log_core::leaf::verify_handoff_binding(
        &sender_identity,
        &sent_leaf,
        &receiver_identity,
        &mismatched_received,
    );
    assert!(
        binding_fails.is_err(),
        "self-check: mismatched state hash must fail binding"
    );

    write_json(
        dir,
        "07_handoff_attestation.json",
        &json!({
            "description": "0x05 HandoffAttestation leaf encoding, and the cross-log binding check (verify_handoff_binding). handoff_* fields are appended to canonical_bytes ONLY for leaf_type 0x05 -- see vector set 1, where fixed_leaf's leaves (types 0x00-0x04) are unaffected by this leaf type's addition. sent_leaf and received_leaf are two INDEPENDENTLY constructed leaves (different session_pubkey, different salted payload_hash) that nonetheless bind because their handoff_state_hash (unsalted) and mutual counterparty_pubkey references match. mismatched_case shows what a failed binding looks like when the state hash differs.",
            "sender_identity_pubkey": sender_identity,
            "receiver_identity_pubkey": receiver_identity,
            "sent_leaf": {
                "leaf": sent_leaf,
                "canonical_bytes_hex": hex::encode(sent_leaf.canonical_bytes()),
                "leaf_hash_hex": hex::encode(leaf_hash(&sent_leaf.canonical_bytes())),
            },
            "received_leaf": {
                "leaf": received_leaf,
                "canonical_bytes_hex": hex::encode(received_leaf.canonical_bytes()),
                "leaf_hash_hex": hex::encode(leaf_hash(&received_leaf.canonical_bytes())),
            },
            "binding_result": "ok",
            "mismatched_case": {
                "description": "Same sent_leaf, but received_leaf's handoff_state_hash altered -- verify_handoff_binding MUST return an error.",
                "expected_result": "error",
            },
        }),
    );

    // --- Vector set 8: AuthorizationEvent encoding + cross-log binding ---
    let granter_identity = "cc".repeat(32);
    let grantee_identity = "dd".repeat(32);
    let scope_hash = hex::encode([0x88u8; 32]);
    let granted_leaf = Leaf {
        index: 0,
        leaf_type: LeafType::AuthorizationEvent.tag(),
        timestamp_ms: 1_700_000_020_000,
        session_pubkey: session_pubkey.clone(),
        payload_hash: hex::encode([0x03u8; 32]),
        redacted_index: None,
        revoked_identity: None,
        handoff_direction: None,
        counterparty_pubkey: Some(grantee_identity.clone()),
        handoff_state_hash: None,
        authorization_event_kind: Some(witness_log_core::leaf::AuthorizationEventKind::GrantedByMe),
        authorization_scope_hash: Some(scope_hash.clone()),
        anchor_url: None,
        anchor_proof_json: None,
        anchor_proof_hash: None,
    };
    let received_grant_leaf = Leaf {
        index: 0,
        leaf_type: LeafType::AuthorizationEvent.tag(),
        timestamp_ms: 1_700_000_021_000,
        session_pubkey: hex::encode([0xB3u8; 32]),
        payload_hash: hex::encode([0x04u8; 32]),
        redacted_index: None,
        revoked_identity: None,
        handoff_direction: None,
        counterparty_pubkey: Some(granter_identity.clone()),
        handoff_state_hash: None,
        authorization_event_kind: Some(witness_log_core::leaf::AuthorizationEventKind::GrantedToMe),
        authorization_scope_hash: Some(scope_hash.clone()),
        anchor_url: None,
        anchor_proof_json: None,
        anchor_proof_hash: None,
    };
    let auth_binding_ok = witness_log_core::leaf::verify_authorization_binding(
        &granter_identity,
        &granted_leaf,
        &grantee_identity,
        &received_grant_leaf,
    );
    assert!(
        auth_binding_ok.is_ok(),
        "self-check: matching authorization events must bind"
    );

    let mismatched_grant = Leaf {
        authorization_scope_hash: Some(hex::encode([0x99u8; 32])), // wider/different scope claimed
        anchor_url: None,
        anchor_proof_json: None,
        anchor_proof_hash: None,
        ..received_grant_leaf.clone()
    };
    let auth_binding_fails = witness_log_core::leaf::verify_authorization_binding(
        &granter_identity,
        &granted_leaf,
        &grantee_identity,
        &mismatched_grant,
    );
    assert!(
        auth_binding_fails.is_err(),
        "self-check: mismatched scope hash must fail binding"
    );

    write_json(
        dir,
        "08_authorization_event.json",
        &json!({
            "description": "0x06 AuthorizationEvent leaf encoding, and the cross-log binding check (verify_authorization_binding). Logging-only: WitnessLog records that a delegation/authorization event happened and lets two independently-salted logs agree on the scope via an unsalted authorization_scope_hash, exactly mirroring HandoffAttestation's pattern -- it never mints, evaluates, or enforces the authorization. authorization_* fields are appended to canonical_bytes ONLY for leaf_type 0x06; vectors 01-07 are unaffected by this leaf type's addition (verified by diffing the full corpus before/after in the implementation's commit history).",
            "granter_identity_pubkey": granter_identity,
            "grantee_identity_pubkey": grantee_identity,
            "granted_leaf": {
                "leaf": granted_leaf,
                "canonical_bytes_hex": hex::encode(granted_leaf.canonical_bytes()),
                "leaf_hash_hex": hex::encode(leaf_hash(&granted_leaf.canonical_bytes())),
            },
            "received_grant_leaf": {
                "leaf": received_grant_leaf,
                "canonical_bytes_hex": hex::encode(received_grant_leaf.canonical_bytes()),
                "leaf_hash_hex": hex::encode(leaf_hash(&received_grant_leaf.canonical_bytes())),
            },
            "binding_result": "ok",
            "mismatched_case": {
                "description": "Same granted_leaf, but received_grant_leaf's authorization_scope_hash altered -- verify_authorization_binding MUST return an error.",
                "expected_result": "error",
            },
        }),
    );

    // --- Vector set 9: ExternalAnchor encoding + proof-content commitment ---
    let anchor_url = "https://rekor.sigstore.dev/api/v1/log/entries/example-entry-id".to_string();
    let anchor_proof_json = r#"{"logIndex":12345,"logID":"c0d23d6a...","integratedTime":1700000030,"body":"eyJhcGlWZXJzaW9uIjoi..."}"#.to_string();
    let anchor_proof_hash = {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(anchor_proof_json.as_bytes());
        hex::encode(h.finalize())
    };
    let anchor_leaf = Leaf {
        index: 0,
        leaf_type: LeafType::ExternalAnchor.tag(),
        timestamp_ms: 1_700_000_030_000,
        session_pubkey: session_pubkey.clone(),
        payload_hash: hex::encode([0x05u8; 32]),
        redacted_index: None,
        revoked_identity: None,
        handoff_direction: None,
        counterparty_pubkey: None,
        handoff_state_hash: None,
        authorization_event_kind: None,
        authorization_scope_hash: None,
        anchor_url: Some(anchor_url.clone()),
        anchor_proof_json: Some(anchor_proof_json.clone()),
        anchor_proof_hash: Some(anchor_proof_hash.clone()),
    };

    // Self-check: swapping the proof content (same URL, different JSON)
    // must change canonical_bytes -- this is the exact property finding
    // 17 fixed. Only anchor_proof_hash is committed, so recomputing it
    // from a different anchor_proof_json and confirming the LEAF HASH
    // changes demonstrates the commitment actually binds the content.
    let swapped_proof_json =
        r#"{"logIndex":99999,"logID":"DIFFERENT...","integratedTime":1700000099,"body":"swapped"}"#
            .to_string();
    let swapped_hash = {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(swapped_proof_json.as_bytes());
        hex::encode(h.finalize())
    };
    let swapped_leaf = Leaf {
        anchor_proof_json: Some(swapped_proof_json.clone()),
        anchor_proof_hash: Some(swapped_hash.clone()),
        ..anchor_leaf.clone()
    };
    assert_ne!(
        leaf_hash(&anchor_leaf.canonical_bytes()),
        leaf_hash(&swapped_leaf.canonical_bytes()),
        "self-check: swapping anchor_proof_json (and its hash) MUST change the leaf hash -- this is the commitment finding 17 added"
    );

    write_json(
        dir,
        "09_external_anchor.json",
        &json!({
            "description": "0x07 ExternalAnchor leaf encoding. anchor_proof_hash = SHA256(anchor_proof_json) is what's actually committed into canonical_bytes, not the raw JSON (which can be arbitrarily large) and not anchor_url alone (an earlier revision committed only the URL, leaving the proof content itself freely swappable -- see SPEC.md §3.3 and the pre-launch review, finding 17). The swapped-proof case demonstrates the commitment: same anchor_url, different anchor_proof_json/anchor_proof_hash, different leaf hash. Vectors 01-08 are unaffected by this leaf type's fields (verified by diffing the full corpus before/after in the implementation's commit history).",
            "anchor_leaf": {
                "leaf": anchor_leaf,
                "canonical_bytes_hex": hex::encode(anchor_leaf.canonical_bytes()),
                "leaf_hash_hex": hex::encode(leaf_hash(&anchor_leaf.canonical_bytes())),
            },
            "swapped_proof_case": {
                "description": "Same anchor_url as anchor_leaf, but a completely different anchor_proof_json (and correspondingly different anchor_proof_hash). A verifier recomputing SHA256(anchor_proof_json) and comparing against the committed anchor_proof_hash detects this swap; the leaf hash itself also differs from anchor_leaf's.",
                "leaf": swapped_leaf,
                "canonical_bytes_hex": hex::encode(swapped_leaf.canonical_bytes()),
                "leaf_hash_hex": hex::encode(leaf_hash(&swapped_leaf.canonical_bytes())),
            },
        }),
    );

    // --- Vector set 10: C2SP transparency-log interoperability ---
    // Deterministic from FIXED_SEED, so any implementation claiming C2SP
    // conformance must reproduce these exact bytes. This is the vector
    // that proves a WitnessLog checkpoint can be consumed by the
    // existing CT witness ecosystem -- see SPEC.md §9.3.
    let c2sp_origin = "corpus.witnesslog.example/vector-10";
    let c2sp_sth = SignedTreeHead::sign(&signing_key, 6, &[0x6Au8; 32], 1_700_000_000_000);
    let c2sp_checkpoint = bridge::checkpoint_from_sth(&c2sp_sth, c2sp_origin)
        .expect("bridge conversion must succeed for a well-formed STH");
    let c2sp_note = c2sp_checkpoint
        .sign(&signing_key)
        .expect("signing a well-formed checkpoint must succeed");
    let c2sp_encoded = c2sp_note.encode().expect("encoding must succeed");
    let log_vkey = bridge::log_vkey(c2sp_origin, &signing_key.verifying_key());

    // A witness cosignature over that checkpoint body, from a second
    // fixed key, at a fixed time.
    let witness_seed: [u8; 32] = [0x5Cu8; 32];
    let witness_key = SigningKey::from_bytes(&witness_seed);
    let witness_name = "corpus-witness.example/w1";
    let body = c2sp_checkpoint.note_text().expect("note text must render");
    let cosig = Cosignature::sign(witness_name, &witness_key, 1_700_000_030, &body);
    let witness_vkey = VerifierKey::for_cosignature(witness_name, &witness_key.verifying_key());
    let mut cosigned = c2sp_note.clone();
    cosigned.signatures.push(cosig.to_note_signature());
    let cosigned_encoded = cosigned.encode().expect("encoding must succeed");

    // Self-checks: everything written below must actually verify, so a
    // broken generator can never emit a corpus that only looks right.
    SignedNote::parse(&c2sp_encoded)
        .expect("emitted note must reparse")
        .verify(std::slice::from_ref(&log_vkey))
        .expect("emitted note must verify against the log vkey");
    let reparsed = SignedNote::parse(&cosigned_encoded).expect("cosigned note must reparse");
    reparsed
        .verify(std::slice::from_ref(&log_vkey))
        .expect("cosignatures must not break the log's own verification");
    Cosignature::from_note_signature(
        reparsed
            .signatures
            .last()
            .expect("cosigned note has at least two signatures"),
    )
    .expect("cosignature must decode")
    .verify(&witness_vkey, &body)
    .expect("cosignature must verify against the checkpoint body");
    assert_eq!(
        Checkpoint::from_note(&reparsed).expect("checkpoint must parse"),
        c2sp_checkpoint,
        "checkpoint must survive a full encode/parse roundtrip"
    );

    write_json(
        dir,
        "10_c2sp_checkpoint.json",
        &json!({
            "description": "C2SP transparency-log interoperability (SPEC.md §9.3). A WitnessLog checkpoint expressed as a c2sp.org/tlog-checkpoint signed note, plus a c2sp.org/tlog-cosignature v1 witness cosignature over it. An implementation claiming C2SP conformance MUST reproduce note_text and both verifier keys byte-for-byte, and MUST verify both signatures. Note that the checkpoint body carries NO timestamp: in C2SP, time is asserted only by cosigners, never by the log itself.",
            "origin": c2sp_origin,
            "tree_size": c2sp_checkpoint.tree_size,
            "root_hash_hex": hex::encode(c2sp_checkpoint.root_hash),
            "note_text": body,
            "log_vkey": log_vkey.encode(),
            "signed_note": c2sp_encoded,
            "cosignature": {
                "witness_vkey": witness_vkey.encode(),
                "timestamp": cosig.timestamp,
                "signed_message": Cosignature::message(cosig.timestamp, &body),
                "cosigned_note": cosigned_encoded,
            },
        }),
    );

    // 11. payload_hash (SPEC §8). Fixed salts, so the exact bucket_pad
    // function is pinned: 0-byte, 1-byte, 255-byte, 256-byte and 257-byte
    // payloads straddle the first bucket boundary both ways.
    let salt_a = [0x5au8; 32];
    let salt_b = [0xa5u8; 32];
    let cases: Vec<serde_json::Value> = [
        ("empty", vec![], salt_a, 0u64),
        ("one_byte", vec![0x41u8], salt_a, 1),
        ("bucket_minus_one", vec![0x42u8; 255], salt_a, 2),
        ("exactly_one_bucket", vec![0x43u8; 256], salt_b, 3),
        ("bucket_plus_one", vec![0x44u8; 257], salt_b, 4),
        ("same_payload_other_index", vec![0x41u8], salt_a, 9),
    ]
    .into_iter()
    .map(|(name, payload, salt, index)| {
        json!({
            "name": name,
            "payload_hex": hex::encode(&payload),
            "salt_hex": hex::encode(salt),
            "leaf_index": index,
            "payload_hash": hex::encode(
                witness_log_core::redaction::payload_hash_with_salt(&payload, &salt, index)
            ),
        })
    })
    .collect();
    write_json(
        dir,
        "11_payload_hash.json",
        &json!({
            "description": "payload_hash = SHA256(bucket_pad(payload) || salt || leaf_index as u64 BE) with bucket_pad = len as u64 BE || payload || zero padding to (len/256+1)*256 bytes (SPEC.md §8). Fixed salts so the padding function itself is pinned: an implementation that pads len||payload together, or omits the length prefix, or uses a different bucket rule, produces different hashes here and nowhere else in this corpus. same_payload_other_index shows the leaf index is part of the commitment.",
            "cases": cases,
        }),
    );

    // 12. Revocation statements (SPEC §5, RFC-0005). v1 is the timestamp
    // statement every release has signed; v2 adds the tree size at which
    // the revocation takes effect under its own message prefix, so a v2
    // signature cannot be replayed as a v1 one with the index stripped.
    let rev_identity = IdentityKeypair::from_bytes(&FIXED_SEED);
    let rev_pk: [u8; 32] = hex::decode(rev_identity.public_hex())
        .unwrap()
        .try_into()
        .unwrap();
    let v1 = rev_identity.revoke(1_700_000_500_000, "key compromised");
    let v2 = rev_identity.revoke_at_index(1_700_000_500_000, 4, "key compromised");
    let msg_v1 =
        witness_log_core::identity::revocation_message(&rev_pk, v1.as_of_ms, None, &v1.reason);
    let msg_v2 = witness_log_core::identity::revocation_message(
        &rev_pk,
        v2.as_of_ms,
        v2.as_of_index,
        &v2.reason,
    );
    write_json(
        dir,
        "12_revocation.json",
        &json!({
            "description": "RevocationStatement signatures (SPEC.md §5) under the published fixed seed. v1: \"witness-log-revoke-v1\" || identity (32B) || as_of_ms (u64 BE) || reason. v2 (RFC-0005): \"witness-log-revoke-v2\" || identity || as_of_ms || 0x01 || as_of_index (u64 BE) || reason. An implementation MUST reproduce message_hex and verify signature for both, MUST reject the v2 statement with as_of_index removed or changed, and MUST apply the cut-off rules in cut_off_cases: with a v2 revocation at index n, a checkpoint of tree_size > n, or any leaf with index >= n, is not evidence; with any revocation, a checkpoint whose timestamp_ms >= as_of_ms is not evidence.",
            "seed_hex": hex::encode(FIXED_SEED),
            "identity_pubkey": hex::encode(rev_pk),
            "v1": {
                "statement": serde_json::to_value(&v1).unwrap(),
                "message_hex": hex::encode(&msg_v1),
            },
            "v2": {
                "statement": serde_json::to_value(&v2).unwrap(),
                "message_hex": hex::encode(&msg_v2),
            },
            "cut_off_cases": [
                {"revocation": "v2", "checkpoint_tree_size": 3, "checkpoint_timestamp_ms": 1_700_000_400_000u64, "max_leaf_index": 2, "valid": true},
                {"revocation": "v2", "checkpoint_tree_size": 4, "checkpoint_timestamp_ms": 1_700_000_400_000u64, "max_leaf_index": 3, "valid": true},
                {"revocation": "v2", "checkpoint_tree_size": 5, "checkpoint_timestamp_ms": 1_700_000_400_000u64, "max_leaf_index": 4, "valid": false},
                {"revocation": "v2", "checkpoint_tree_size": 4, "checkpoint_timestamp_ms": 1_700_000_500_000u64, "max_leaf_index": 3, "valid": false},
                {"revocation": "v1", "checkpoint_tree_size": 9, "checkpoint_timestamp_ms": 1_700_000_400_000u64, "max_leaf_index": 8, "valid": true},
                {"revocation": "v1", "checkpoint_tree_size": 9, "checkpoint_timestamp_ms": 1_700_000_500_000u64, "max_leaf_index": 8, "valid": false},
            ],
        }),
    );

    println!("wrote conformance corpus to {dir}/");
}

fn write_json(dir: &str, name: &str, value: &serde_json::Value) {
    let path = format!("{dir}/{name}");
    fs::write(&path, serde_json::to_string_pretty(value).unwrap()).unwrap();
    println!("  {path}");
}
