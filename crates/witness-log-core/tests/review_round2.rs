//! Second independent review: demonstrating tests for the core crate.
//!
//! Every test here asserts the behaviour AS IT STANDS TODAY, so that a
//! fix flips the test and the reviewer's claim is checkable. Tests whose
//! name starts with `defect_` document a finding; tests whose name starts
//! with `sound_` document a check that passed and is kept as coverage.

use witness_log_core::identity::IdentityKeypair;
use witness_log_core::journal::JournaledLog;
use witness_log_core::leaf::{Leaf, LeafType};
use witness_log_core::merkle::{leaf_hash, verify_consistency};

fn tmp(tag: &str) -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir()
        .join(format!(
            "wl-review2-{tag}-{}-{nanos}.jsonl",
            std::process::id()
        ))
        .to_string_lossy()
        .into_owned()
}

fn cleanup(path: &str) {
    let _ = std::fs::remove_file(path);
    let _ = std::fs::remove_file(JournaledLog::salts_path(path));
    let _ = std::fs::remove_file(format!("{path}.lock"));
}

/// Drop the final byte of a file if it is `\n`. This is exactly the state
/// a crash between the two `write(2)` calls that `writeln!` issues on an
/// unbuffered `File` leaves behind (the formatted line, then the literal
/// newline are separate pieces of the `format_args!`).
fn strip_trailing_newline(path: &str) {
    let mut bytes = std::fs::read(path).unwrap();
    assert_eq!(
        bytes.last(),
        Some(&b'\n'),
        "fixture expects a trailing newline"
    );
    bytes.pop();
    std::fs::write(path, bytes).unwrap();
}

// ---------------------------------------------------------------------------
// Finding J1 (HIGH): a final journal line that lacks its trailing newline is
// accepted by replay as a good line, `open_for_append` does not re-terminate
// it, and the very next record (the resume binding) is written directly after
// the closing brace. The merged line is unparsable on the following replay.
// ---------------------------------------------------------------------------

/// Fixed in 0.4.2: a complete final record without its newline is kept
/// (it may have been witnessed), `open_for_append` terminates it before
/// anything else lands, and every record is one `write_all`. Both
/// variants below now resume with every leaf intact.
#[test]
fn fixed_j1a_torn_newline_then_resume_keeps_every_leaf() {
    let p = tmp("j1a");
    cleanup(&p);
    {
        let mut jl = JournaledLog::create_ephemeral(&p).unwrap();
        jl.append_intent(b"a").unwrap();
        jl.append_intent(b"b").unwrap();
        jl.append_intent(b"c").unwrap();
        jl.sync().unwrap();
    }
    strip_trailing_newline(&p);
    {
        let (jl, report) = JournaledLog::resume(&p).unwrap();
        assert_eq!(report.dropped_trailing_lines, 0);
        assert_eq!(jl.log().tree_size(), 3, "session 2 sees all three leaves");
    }
    let on_disk = std::fs::read_to_string(&p).unwrap();
    for l in on_disk.lines().filter(|l| !l.trim().is_empty()) {
        assert!(
            serde_json::from_str::<serde_json::Value>(l).is_ok(),
            "a record was written onto another:\n{on_disk}"
        );
    }
    let (jl, report) = JournaledLog::resume(&p).unwrap();
    assert_eq!(report.dropped_trailing_lines, 0);
    assert_eq!(jl.log().tree_size(), 3, "leaf 2 survives two resumes");
    drop(jl);
    cleanup(&p);
}

#[test]
fn fixed_j1b_torn_newline_then_one_append_still_resumes() {
    let p = tmp("j1b");
    cleanup(&p);
    {
        let mut jl = JournaledLog::create_ephemeral(&p).unwrap();
        jl.append_intent(b"a").unwrap();
        jl.append_intent(b"b").unwrap();
        jl.sync().unwrap();
    }
    strip_trailing_newline(&p);
    {
        let (mut jl, _) = JournaledLog::resume(&p).unwrap();
        jl.append_intent(b"c").unwrap();
        jl.sync().unwrap();
    }
    let (jl, report) = JournaledLog::resume(&p).unwrap();
    assert_eq!(report.dropped_trailing_lines, 0);
    assert_eq!(jl.log().tree_size(), 3);
    drop(jl);
    cleanup(&p);
}

/// Fixed in 0.4.2: the salt sidecar gets the same treatment, so every
/// leaf stays forgettable across the torn write.
#[test]
fn fixed_j2_salt_sidecar_torn_newline_then_two_appends_resumes() {
    let p = tmp("j2");
    cleanup(&p);
    {
        let mut jl = JournaledLog::create_ephemeral(&p).unwrap();
        jl.append_intent(b"a").unwrap();
        jl.append_intent(b"b").unwrap();
        jl.sync().unwrap();
    }
    strip_trailing_newline(&JournaledLog::salts_path(&p));
    {
        let (mut jl, _) = JournaledLog::resume(&p).unwrap();
        jl.append_intent(b"c").unwrap();
        jl.append_intent(b"d").unwrap();
        jl.sync().unwrap();
    }
    let (mut jl, _) = JournaledLog::resume(&p).unwrap();
    for i in 0..4 {
        assert!(jl.can_forget(i), "leaf {i} must still be forgettable");
    }
    assert!(jl.forget(1).unwrap());
    drop(jl);
    cleanup(&p);
}

/// Fixed in 0.4.2: a tear inside a multi-byte character is a torn tail
/// like any other and is healed, not refused.
#[test]
fn fixed_j3_tear_inside_multibyte_char_is_healed() {
    let p = tmp("j3");
    cleanup(&p);
    {
        let mut jl = JournaledLog::create_ephemeral(&p).unwrap();
        jl.append_intent(b"a").unwrap();
        jl.append_external_anchor("https://example.com/\u{e9}/entry", "{}")
            .unwrap();
        jl.sync().unwrap();
    }
    let mut bytes = std::fs::read(&p).unwrap();
    let pos = bytes
        .windows(2)
        .rposition(|w| w == [0xC3, 0xA9])
        .expect("fixture contains the two-byte character");
    bytes.truncate(pos + 1);
    std::fs::write(&p, &bytes).unwrap();
    let (jl, report) = JournaledLog::resume(&p).unwrap();
    assert_eq!(report.dropped_trailing_lines, 1);
    assert_eq!(jl.log().tree_size(), 1);
    drop(jl);
    cleanup(&p);
}

// ---------------------------------------------------------------------------
// Finding R1 (LOW): `forget` reports success on an ExternalAnchor leaf, but
// the only payload that leaf has (the URL) and the anchor proof remain in
// cleartext in the leaf itself; only the salt behind a hash of the URL goes.
// ---------------------------------------------------------------------------
#[test]
fn fixed_r1_forget_refuses_an_anchor_leaf_whose_content_stays_visible() {
    let p = tmp("r1");
    cleanup(&p);
    let mut jl = JournaledLog::create_ephemeral(&p).unwrap();
    let url = "https://rekor.example/api/v1/log/entries/secret-correlator";
    let proof = r#"{"logIndex":42}"#;
    let idx = jl.append_external_anchor(url, proof).unwrap();
    assert!(
        !jl.can_forget(idx),
        "0.4.2: the URL and proof live in the leaf; nothing to erase"
    );
    assert!(!jl.forget(idx).unwrap());
    assert_eq!(jl.log().tree_size(), 1, "no tombstone for a refused forget");
    // Handoff leaves stay forgettable; the unsalted comparison hash that
    // remains is the documented `bind` commitment, not the payload.
    let cp = hex::encode([7u8; 32]);
    let h = jl.append_handoff_sent(b"approve", &cp).unwrap();
    assert!(jl.forget(h).unwrap());
    let leaf = &jl.log().leaves()[h as usize];
    use sha2::Digest;
    assert_eq!(
        leaf.handoff_state_hash.as_deref(),
        Some(hex::encode(sha2::Sha256::digest(b"approve")).as_str()),
        "unsalted SHA-256 of the forgotten payload remains committed"
    );
    drop(jl);
    cleanup(&p);
}

// ---------------------------------------------------------------------------
// Finding L1 (LOW): fields that do not belong to a leaf's type are neither
// committed by `canonical_bytes` nor rejected by `validate`, so a dossier
// editor can add or alter them freely under an unchanged, signed root.
// ---------------------------------------------------------------------------
fn hex64(b: u8) -> String {
    hex::encode([b; 32])
}

fn plain(index: u64) -> Leaf {
    Leaf {
        index,
        leaf_type: LeafType::ActiveIntent.tag(),
        timestamp_ms: 1,
        session_pubkey: hex64(1),
        payload_hash: hex64(2),
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
fn fixed_l1_uncommitted_fields_are_refused() {
    let a = plain(0);
    let mut b = plain(0);
    b.counterparty_pubkey = Some(hex64(0xEE));
    b.handoff_state_hash = Some(hex64(0xDD));
    b.authorization_scope_hash = Some("anything".into());
    b.anchor_url = Some("javascript:alert(1)".into());
    b.anchor_proof_json = Some("not the committed proof".into());
    b.anchor_proof_hash = Some("zz".into());
    assert!(a.validate(0).is_ok());
    assert_eq!(
        leaf_hash(&a.canonical_bytes()),
        leaf_hash(&b.canonical_bytes()),
        "stray fields are invisible to the Merkle root, which is why validate must refuse them"
    );
    let err = b
        .validate(0)
        .expect_err("0.4.2: stray type-specific fields are refused");
    assert!(err.to_string().contains("must not carry field"), "{err}");
    // Each stray field alone is refused too.
    let mut c = plain(0);
    c.redacted_index = Some(0);
    assert!(c.validate(0).is_err());
    let mut d = plain(0);
    d.revoked_identity = Some(hex64(9));
    assert!(d.validate(0).is_err());
}

/// Related: a Redaction leaf may name an index that does not exist, or its
/// own index, and a marker leaf may carry a non-zero payload_hash; none of
/// that is structurally rejected.
#[test]
fn fixed_l2_redaction_target_and_marker_hash_are_checked() {
    let mut r = plain(3);
    r.leaf_type = LeafType::Redaction.tag();
    r.redacted_index = Some(u64::MAX);
    r.payload_hash = hex64(0x55);
    assert!(r.validate(3).is_err(), "non-zero marker hash is refused");
    r.payload_hash = hex64(0);
    assert!(r.validate(3).is_err(), "a non-existent target is refused");
    r.redacted_index = Some(3);
    assert!(r.validate(3).is_err(), "a leaf may not redact itself");
    r.redacted_index = Some(1);
    assert!(r.validate(3).is_ok());
}

// ---------------------------------------------------------------------------
// Finding I1 (INFO, documented in SPEC §5): `custody` is outside the signed
// binding message, so any party relaying a dossier can rewrite it.
// ---------------------------------------------------------------------------
#[test]
fn info_i1_binding_custody_is_not_signed() {
    use witness_log_core::identity::{KeyCustody, SessionKeypair};
    let id = IdentityKeypair::generate();
    let s = SessionKeypair::generate();
    let mut b = id.bind_session(&s.verifying_key(), 1, 1000, None);
    assert_eq!(b.custody, KeyCustody::Undisclosed);
    b.custody = KeyCustody::Hsm;
    assert!(
        b.verify().is_ok(),
        "custody upgraded to Hsm, signature still valid"
    );
}

// ---------------------------------------------------------------------------
// Finding M1 (INFO): `verify_consistency(0, x, 0, y, [])` is true for x != y.
// Harmless in every caller found (the witness checks the empty root
// separately), recorded so the edge is explicit.
// ---------------------------------------------------------------------------
#[test]
fn info_m1_consistency_zero_to_zero_ignores_roots() {
    assert!(verify_consistency(0, &[1u8; 32], 0, &[2u8; 32], &[]));
}

// ---------------------------------------------------------------------------
// Sound: things checked and found correct, kept as regression coverage.
// ---------------------------------------------------------------------------

/// Consistency proofs: the single-element proof for first=1 of a size-2
/// tree, the size-1 -> size-1 case, and proofs with one trailing or one
/// leading extra element all behave per RFC 9162.
#[test]
fn sound_consistency_edges() {
    use witness_log_core::merkle::MerkleTree;
    let mut t = MerkleTree::new();
    let l0 = leaf_hash(b"0");
    let l1 = leaf_hash(b"1");
    t.append(l0);
    let r1 = t.root();
    t.append(l1);
    let r2 = t.root();
    let p = t.consistency_proof(1, 2).unwrap();
    assert_eq!(p, vec![l1]);
    assert!(verify_consistency(1, &r1, 2, &r2, &p));
    assert!(!verify_consistency(1, &r1, 2, &r2, &[]));
    assert!(!verify_consistency(1, &r1, 2, &r2, &[l1, l1]));
    assert!(!verify_consistency(1, &r1, 2, &r2, &[l0]));
    // same size, same root, must have empty proof
    assert!(verify_consistency(2, &r2, 2, &r2, &[]));
    assert!(!verify_consistency(2, &r2, 2, &r2, &[l1]));
    assert!(!verify_consistency(2, &r2, 2, &r1, &[]));
    // first > second
    assert!(!verify_consistency(2, &r2, 1, &r1, &[]));
    // huge sizes never hang or panic
    assert!(!verify_consistency(u64::MAX - 1, &r1, u64::MAX, &r2, &p));
    assert!(!verify_consistency(1 << 63, &r1, u64::MAX, &r2, &[l1; 3]));
}

/// Inclusion: huge tree sizes, index == size, oversized proofs.
#[test]
fn sound_inclusion_edges() {
    use witness_log_core::merkle::verify_inclusion;
    let l = leaf_hash(b"x");
    assert!(!verify_inclusion(&l, 0, 0, &[], &l));
    assert!(verify_inclusion(&l, 0, 1, &[], &l));
    assert!(!verify_inclusion(&l, 0, 1, &[l], &l));
    assert!(!verify_inclusion(&l, u64::MAX - 1, u64::MAX, &[l; 64], &l));
    assert!(!verify_inclusion(&l, u64::MAX - 1, u64::MAX, &[l; 63], &l));
}

/// Leaf encoding: the two length-prefixed strings cannot be re-split, and
/// a presence byte distinguishes `Some(0)` from `None`.
#[test]
fn sound_leaf_encoding_injective_on_committed_fields() {
    let mut a = plain(0);
    let mut b = plain(0);
    a.session_pubkey = "a".repeat(64);
    a.payload_hash = "b".repeat(64);
    b.session_pubkey = "a".repeat(60);
    b.payload_hash = "a".repeat(4) + &"b".repeat(64); // same concatenation
    assert_eq!(
        format!("{}{}", a.session_pubkey, a.payload_hash),
        format!("{}{}", b.session_pubkey, b.payload_hash)
    );
    assert_ne!(a.canonical_bytes(), b.canonical_bytes());
    let mut c = plain(0);
    c.redacted_index = Some(0);
    assert_ne!(plain(0).canonical_bytes(), c.canonical_bytes());
    let mut d = plain(0);
    d.revoked_identity = Some(String::new());
    assert_ne!(plain(0).canonical_bytes(), d.canonical_bytes());
}

/// C2SP parsing: tree size canonical form, root length, origin rules, vkey
/// parsing with '+' in base64, signature line shape, signature cap.
#[test]
fn sound_c2sp_parsers_reject_malformed_input() {
    use base64ct::Encoding;
    use witness_log_core::c2sp::*;
    let mk = |body: &str| {
        let text = format!(
            "{body}\n\n\u{2014} k {}\n",
            base64ct::Base64::encode_string(&[0u8; 68])
        );
        SignedNote::parse(&text).map(|n| Checkpoint::from_note(&n))
    };
    let root = base64ct::Base64::encode_string(&[0u8; 32]);
    assert!(mk(&format!("o\n007\n{root}")).unwrap().is_err());
    assert!(mk(&format!("o\n+7\n{root}")).unwrap().is_err());
    assert!(mk(&format!("o\n18446744073709551616\n{root}"))
        .unwrap()
        .is_err());
    assert!(mk(&format!(
        "o\n7\n{}",
        base64ct::Base64::encode_string(&[0u8; 31])
    ))
    .unwrap()
    .is_err());
    assert!(mk(&format!("o o\n7\n{root}")).unwrap().is_err());
    assert!(mk(&format!("o+p\n7\n{root}")).unwrap().is_err());
    // INFO C1: a note whose text ends in a blank line ("o\n7\nroot\n\n") is
    // accepted; `from_note` trims every trailing newline, so this
    // non-canonical text parses as the canonical checkpoint. A witness
    // then cosigns `note_text()` (canonical) while the log signed the
    // non-canonical bytes. Not exploitable without the log key; recorded.
    assert!(
        mk(&format!("o\n7\n{root}\n")).unwrap().is_ok(),
        "trailing blank line in note text is tolerated (see report, C1)"
    );
    assert!(mk(&format!("o\n7\n{root}")).unwrap().is_ok());
    assert!(SignedNote::parse("o\n7\nx\n\n").is_err(), "no signatures");
    assert!(
        SignedNote::parse("o\n7\nx\n\n- k AAAA\n").is_err(),
        "hyphen is not an em dash"
    );
    // C2 (fixed in 0.4.2): a 4-byte payload is a key ID with no
    // signature bytes and is refused at parse time.
    assert!(
        SignedNote::parse("o\n7\nx\n\n\u{2014} k AAAAAA==\n").is_err(),
        "a key ID with no signature bytes is malformed"
    );
    assert!(
        SignedNote::parse("o\n7\nx\n\n\u{2014} k AAAA\n").is_err(),
        "3 bytes: too short"
    );
    assert!(
        SignedNote::parse("o\r\n7\nx\n\n\u{2014} k AAAAAAAA\n").is_err(),
        "CR rejected"
    );
    let many: String = "\u{2014} k AAAAAAAA\n".repeat(65);
    assert!(
        SignedNote::parse(&format!("o\n7\nx\n\n{many}")).is_err(),
        "signature cap"
    );
    assert!(VerifierKey::parse("name+zz+AAAA").is_err());
    assert!(VerifierKey::parse("+00000000+AQ==").is_err());
    assert!(VerifierKey::parse("name+00000000+").is_err());
    assert!(identity_from_canonical_origin(&format!("witness-log/{}", "AB".repeat(32))).is_none());
    assert!(identity_from_canonical_origin("witness-log/").is_none());
}

/// Signed messages: algorithm, signer, and every field are under the
/// signature; strict verification rejects a non-canonical signature.
#[test]
fn sound_signed_messages_bind_all_fields() {
    use ed25519_dalek::SigningKey;
    use witness_log_core::sth::SignedTreeHead;
    let id = IdentityKeypair::generate();
    let key = SigningKey::from_bytes(&id.to_bytes());
    let sth = SignedTreeHead::sign(&key, 3, &[1u8; 32], 5);
    let mut t = sth.clone();
    t.signer_pubkey = t.signer_pubkey.to_ascii_uppercase();
    assert!(
        t.verify().is_err(),
        "the hex spelling of the signer is signed"
    );
    let mut t = sth.clone();
    t.root_hash = t.root_hash.to_ascii_uppercase();
    assert!(
        t.verify().is_ok(),
        "root is signed as bytes; case-variant hex still verifies"
    );
    let mut t = sth.clone();
    t.timestamp_ms += 1;
    assert!(t.verify().is_err());
    let rev = id.revoke(10, "r");
    let mut r2 = rev.clone();
    r2.as_of_ms = 9;
    assert!(r2.verify().is_err());
    let mut r3 = rev;
    r3.identity_pubkey = hex64(9);
    assert!(r3.verify().is_err());
}
