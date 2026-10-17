//! End-to-end `tlog-witness` protocol tests.
//!
//! The headline case is `witness_refuses_to_cosign_an_equivocating_log`:
//! it is the reason the whole project exists, and until this protocol
//! existed there was no path by which a real third-party witness could
//! ever reach that conclusion about a WitnessLog.

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use witness_log_core::c2sp::{bridge, Checkpoint, VerifierKey};
use witness_log_core::identity::IdentityKeypair;
use witness_log_core::log::WitnessLog;
use witness_log_core::merkle::MerkleTree;
use witness_log_network::tlog_witness::*;

const ORIGIN: &str = "agents.example.com/agent-42";

struct Log {
    seed: [u8; 32],
    log: WitnessLog,
}

impl Log {
    fn new() -> Self {
        let id = IdentityKeypair::generate();
        let seed = id.to_bytes();
        Self {
            log: WitnessLog::resume(IdentityKeypair::from_bytes(&seed), 0),
            seed,
        }
    }
    fn key(&self) -> SigningKey {
        SigningKey::from_bytes(&self.seed)
    }
    fn append(&mut self, n: usize) {
        for i in 0..n {
            self.log.append_intent(format!("event-{i}").as_bytes());
        }
    }
    fn tree(&self) -> MerkleTree {
        let mut t = MerkleTree::new();
        for l in self.log.leaves() {
            t.append(witness_log_core::merkle::leaf_hash(&l.canonical_bytes()));
        }
        t
    }
    fn checkpoint(&self) -> Checkpoint {
        let t = self.tree();
        Checkpoint {
            origin: ORIGIN.to_string(),
            tree_size: t.size(),
            root_hash: t.root(),
            extensions: vec![],
        }
    }
    fn vkey(&self) -> VerifierKey {
        bridge::log_vkey(ORIGIN, &self.key().verifying_key())
    }
    fn request(&self, old_size: u64, witness_root: Option<[u8; 32]>) -> AddCheckpointRequest {
        let cp = self.checkpoint();
        let proof = if old_size == 0 || old_size == cp.tree_size {
            vec![]
        } else {
            self.tree()
                .consistency_proof(old_size, cp.tree_size)
                .unwrap_or_default()
        };
        let _ = witness_root;
        AddCheckpointRequest {
            old_size,
            consistency_proof: proof,
            checkpoint_note: cp.sign(&self.key()).expect("checkpoint must sign"),
        }
    }
}

fn witness() -> (WitnessService, SigningKey, VerifierKey) {
    let k = SigningKey::generate(&mut OsRng);
    let vkey = VerifierKey::for_cosignature("witness.example/w1", &k.verifying_key());
    (WitnessService::new(), k, vkey)
}

#[test]
fn full_happy_path_log_gets_cosigned_and_advances() {
    let mut log = Log::new();
    log.append(4);
    let (mut svc, wkey, wvkey) = witness();
    svc.add_log(ORIGIN, log.vkey());

    // First submission: witness has nothing, so no proof is needed.
    let out = svc.handle_add_checkpoint(
        &log.request(0, None),
        "witness.example/w1",
        &wkey,
        1_700_000_000,
    );
    let AddCheckpointOutcome::Cosigned {
        cosignature,
        new_size,
    } = out
    else {
        panic!("expected Cosigned, got {out:?}");
    };
    assert_eq!(new_size, 4);
    assert_eq!(
        out_status(&AddCheckpointOutcome::Cosigned {
            cosignature: cosignature.clone(),
            new_size
        }),
        200
    );
    assert!(
        verify_cosignature_response(&cosignature, &wvkey, &log.checkpoint()),
        "cosignature must verify against the exact checkpoint submitted"
    );
    assert_eq!(svc.known_log(ORIGIN).map(|l| l.tree_size), Some(4));

    // The log grows; the witness advances on a valid consistency proof.
    log.append(6);
    let out2 = svc.handle_add_checkpoint(
        &log.request(4, None),
        "witness.example/w1",
        &wkey,
        1_700_000_060,
    );
    assert!(
        matches!(out2, AddCheckpointOutcome::Cosigned { new_size: 10, .. }),
        "expected advance to 10, got {out2:?}"
    );
    assert_eq!(svc.known_log(ORIGIN).map(|l| l.tree_size), Some(10));
}

fn out_status(o: &AddCheckpointOutcome) -> u16 {
    o.http_status()
}

#[test]
fn witness_refuses_to_cosign_an_equivocating_log() {
    // THE test. A log cosigned at size 5, then forks and presents a
    // different history at the same size to a party who doesn't hold the
    // first copy. The witness holds the first copy, so it can tell.
    let mut log = Log::new();
    log.append(5);
    let (mut svc, wkey, _) = witness();
    svc.add_log(ORIGIN, log.vkey());
    let first = svc.handle_add_checkpoint(
        &log.request(0, None),
        "witness.example/w1",
        &wkey,
        1_700_000_000,
    );
    assert!(matches!(first, AddCheckpointOutcome::Cosigned { .. }));

    // Fork: same identity, same origin, same size, different content.
    let mut forked = WitnessLog::resume(IdentityKeypair::from_bytes(&log.seed), 0);
    for i in 0..5 {
        forked.append_intent(format!("DIFFERENT-{i}").as_bytes());
    }
    let mut t = MerkleTree::new();
    for l in forked.leaves() {
        t.append(witness_log_core::merkle::leaf_hash(&l.canonical_bytes()));
    }
    let forked_cp = Checkpoint {
        origin: ORIGIN.to_string(),
        tree_size: t.size(),
        root_hash: t.root(),
        extensions: vec![],
    };
    assert_ne!(
        forked_cp.root_hash,
        log.checkpoint().root_hash,
        "fixture must actually diverge"
    );

    let req = AddCheckpointRequest {
        old_size: 5,
        consistency_proof: vec![],
        checkpoint_note: forked_cp.sign(&log.key()).unwrap(),
    };
    let out = svc.handle_add_checkpoint(&req, "witness.example/w1", &wkey, 1_700_000_060);

    assert!(
        matches!(out, AddCheckpointOutcome::ConsistencyFailed { .. }),
        "an equivocating log MUST be refused, got {out:?}"
    );
    assert_eq!(out.http_status(), 422);
    assert!(
        out.is_misbehaviour_evidence(),
        "a consistency failure is publishable evidence, not a generic error"
    );
    // And the witness must NOT have advanced its record.
    assert_eq!(
        svc.known_log(ORIGIN).map(|l| l.tree_size),
        Some(5),
        "a refused checkpoint must not move the witness's record"
    );
}

#[test]
fn witness_refuses_a_rollback() {
    let mut log = Log::new();
    log.append(10);
    let (mut svc, wkey, _) = witness();
    svc.add_log(ORIGIN, log.vkey());
    svc.handle_add_checkpoint(
        &log.request(0, None),
        "witness.example/w1",
        &wkey,
        1_700_000_000,
    );

    // Present a SMALLER tree. A log cannot un-append.
    let mut shrunk = WitnessLog::resume(IdentityKeypair::from_bytes(&log.seed), 0);
    for i in 0..3 {
        shrunk.append_intent(format!("event-{i}").as_bytes());
    }
    let mut t = MerkleTree::new();
    for l in shrunk.leaves() {
        t.append(witness_log_core::merkle::leaf_hash(&l.canonical_bytes()));
    }
    let cp = Checkpoint {
        origin: ORIGIN.to_string(),
        tree_size: t.size(),
        root_hash: t.root(),
        extensions: vec![],
    };
    let req = AddCheckpointRequest {
        old_size: 10,
        consistency_proof: vec![],
        checkpoint_note: cp.sign(&log.key()).unwrap(),
    };
    let out = svc.handle_add_checkpoint(&req, "witness.example/w1", &wkey, 1_700_000_060);
    // Refused with 400 per c2sp.org/tlog-witness -- but NOT flagged as
    // equivocation evidence: an honest log's old checkpoint arriving late
    // is indistinguishable from this, so accusing would be a false
    // positive (the pre-0.3.1 behaviour this test used to assert).
    assert!(
        matches!(out, AddCheckpointOutcome::StaleCheckpoint { .. }),
        "a rollback must be refused, got {out:?}"
    );
    assert_eq!(out.http_status(), 400);
    assert!(!out.is_misbehaviour_evidence());
    // And the witness's record did not move.
    assert_eq!(svc.known_log(ORIGIN).unwrap().tree_size, 10);
}

#[test]
fn size_mismatch_tells_the_client_where_the_witness_actually_is() {
    let mut log = Log::new();
    log.append(8);
    let (mut svc, wkey, _) = witness();
    svc.add_log(ORIGIN, log.vkey());
    svc.handle_add_checkpoint(
        &log.request(0, None),
        "witness.example/w1",
        &wkey,
        1_700_000_000,
    );

    log.append(4);
    // Claim the witness is at 3 when it is actually at 8.
    let out = svc.handle_add_checkpoint(
        &log.request(3, None),
        "witness.example/w1",
        &wkey,
        1_700_000_060,
    );
    match out {
        AddCheckpointOutcome::SizeMismatch { witness_size, .. } => {
            assert_eq!(
                witness_size, 8,
                "must report the witness's real size so the client can retry"
            );
        }
        other => panic!("expected SizeMismatch, got {other:?}"),
    }
    assert_eq!(
        AddCheckpointOutcome::SizeMismatch {
            witness_size: 8,
            witness_root: [0; 32]
        }
        .http_status(),
        409
    );
}

#[test]
fn witness_rejects_a_checkpoint_signed_by_the_wrong_key() {
    let mut log = Log::new();
    log.append(3);
    let (mut svc, wkey, _) = witness();
    // The witness holds the RIGHT key for this origin...
    svc.add_log(ORIGIN, log.vkey());

    // ...but an impostor signs a checkpoint for the same origin.
    let impostor = SigningKey::generate(&mut OsRng);
    let cp = log.checkpoint();
    let req = AddCheckpointRequest {
        old_size: 0,
        consistency_proof: vec![],
        checkpoint_note: cp.sign(&impostor).unwrap(),
    };
    let out = svc.handle_add_checkpoint(&req, "witness.example/w1", &wkey, 1_700_000_000);
    assert!(
        matches!(out, AddCheckpointOutcome::UnknownOrBadSignature),
        "a checkpoint signed by an unknown key must be refused, got {out:?}"
    );
    assert_eq!(out.http_status(), 403);
}

#[test]
fn witness_refuses_a_log_it_was_never_told_about() {
    let mut log = Log::new();
    log.append(2);
    let (mut svc, wkey, _) = witness();
    // Deliberately NOT calling add_log: a witness must not learn a log's
    // key from the log's own submission.
    let out = svc.handle_add_checkpoint(
        &log.request(0, None),
        "witness.example/w1",
        &wkey,
        1_700_000_000,
    );
    assert!(
        matches!(out, AddCheckpointOutcome::UnknownLog { .. }),
        "got {out:?}"
    );
    assert_eq!(out.http_status(), 404);
}

#[test]
fn request_roundtrips_through_the_wire_format() {
    let mut log = Log::new();
    log.append(7);
    let req = log.request(0, None);
    let body = req.to_http_body().expect("must serialize");
    assert!(body.starts_with("old 0\n"), "body: {body}");
    let parsed = AddCheckpointRequest::parse(&body).expect("must reparse");
    assert_eq!(parsed.old_size, req.old_size);
    assert_eq!(parsed.consistency_proof, req.consistency_proof);
    assert_eq!(parsed.checkpoint_note, req.checkpoint_note);

    // And a request carrying a real proof.
    log.append(5);
    let req2 = log.request(7, None);
    assert!(
        !req2.consistency_proof.is_empty(),
        "fixture must carry a proof"
    );
    let parsed2 = AddCheckpointRequest::parse(&req2.to_http_body().unwrap()).unwrap();
    assert_eq!(parsed2.consistency_proof, req2.consistency_proof);
}

#[test]
fn malformed_requests_never_panic() {
    let hostile = [
        "",
        "old",
        "old notanumber\n\nx",
        "old 5",
        "old 5\n\n",
        "old 5\n!!!notbase64!!!\n\ntext\n\n— a AAAAAAAA\n",
        "old 5\nAAAA\n\nnope",
        "\n\n",
        &"old 0\n".repeat(10_000),
    ];
    for h in hostile {
        let _ = AddCheckpointRequest::parse(h);
    }
}

#[test]
fn a_cosignature_over_a_different_checkpoint_does_not_verify() {
    // Guards the client side: a witness returning 200 with a signature
    // over something else must not be trusted because the status was green.
    let mut log = Log::new();
    log.append(4);
    let (mut svc, wkey, wvkey) = witness();
    svc.add_log(ORIGIN, log.vkey());
    let out = svc.handle_add_checkpoint(
        &log.request(0, None),
        "witness.example/w1",
        &wkey,
        1_700_000_000,
    );
    let AddCheckpointOutcome::Cosigned { cosignature, .. } = out else {
        panic!("expected Cosigned");
    };

    let mut other = log.checkpoint();
    other.tree_size += 1;
    assert!(
        !verify_cosignature_response(&cosignature, &wvkey, &other),
        "a cosignature must not verify against a checkpoint it didn't sign"
    );
}

// ---- c2sp.org/tlog-witness conformance details (0.3.1) ----

#[test]
fn spec_409_body_is_just_the_size() {
    let out = AddCheckpointOutcome::SizeMismatch {
        witness_size: 42,
        witness_root: [7u8; 32],
    };
    assert_eq!(out.http_body(), ("42\n".to_string(), "text/x.tlog.size"));
}

#[test]
fn spec_rejects_more_than_63_proof_lines() {
    use base64ct::{Base64, Encoding};
    let line = Base64::encode_string(&[0u8; 32]);
    let mut body = "old 1\n".to_string();
    for _ in 0..64 {
        body.push_str(&line);
        body.push('\n');
    }
    body.push_str("\nx\n1\nAAAA\n\n\u{2014} k AAAA\n");
    assert!(AddCheckpointRequest::parse(&body).is_err());
}

#[test]
fn spec_422_for_proof_from_size_zero_and_bad_empty_root() {
    let mut log = Log::new();
    log.append(3);
    let (mut svc, wkey, _) = witness();
    svc.add_log(ORIGIN, log.vkey());
    let mut req = log.request(0, None);
    req.consistency_proof = vec![[1u8; 32]];
    let out = svc.handle_add_checkpoint(&req, "witness.example/w1", &wkey, 1);
    assert_eq!(out.http_status(), 422, "{out:?}");

    let cp = Checkpoint {
        origin: ORIGIN.to_string(),
        tree_size: 0,
        root_hash: [9u8; 32],
        extensions: vec![],
    };
    let req = AddCheckpointRequest {
        old_size: 0,
        consistency_proof: vec![],
        checkpoint_note: cp.sign(&log.key()).unwrap(),
    };
    let out = svc.handle_add_checkpoint(&req, "witness.example/w1", &wkey, 1);
    assert_eq!(out.http_status(), 422, "{out:?}");
}

#[test]
fn witness_state_round_trips_and_rejects_corruption() {
    let mut log = Log::new();
    log.append(5);
    let (mut svc, wkey, _) = witness();
    svc.add_log(ORIGIN, log.vkey());
    svc.handle_add_checkpoint(&log.request(0, None), "witness.example/w1", &wkey, 1);
    let st = svc.export_state();
    let json = serde_json::to_string(&st).unwrap();
    let back = WitnessService::from_state(&serde_json::from_str(&json).unwrap()).unwrap();
    assert_eq!(back.known_log(ORIGIN), svc.known_log(ORIGIN));

    let mut dup = st.clone();
    dup.logs.push(dup.logs[0].clone());
    assert!(WitnessService::from_state(&dup).is_err(), "duplicate log");
    let mut bad = st.clone();
    bad.logs[0].root_hash = "zz".into();
    assert!(WitnessService::from_state(&bad).is_err(), "bad root");
    let mut ver = st;
    ver.format_version = 99;
    assert!(WitnessService::from_state(&ver).is_err(), "unknown version");
}

#[test]
fn open_enrollment_only_for_canonical_validly_signed_logs() {
    use witness_log_core::c2sp::canonical_origin;
    let id = IdentityKeypair::generate();
    let key = SigningKey::from_bytes(&id.to_bytes());
    let mut wl = WitnessLog::resume(id, 0);
    wl.append_intent(b"x");
    let origin = canonical_origin(&key.verifying_key());
    let good = AddCheckpointRequest {
        old_size: 0,
        consistency_proof: vec![],
        checkpoint_note: wl.c2sp_checkpoint(&origin).sign(&key).unwrap(),
    };
    let mut svc = WitnessService::new();
    // Signed by the wrong key: not enrolled.
    let other = SigningKey::generate(&mut OsRng);
    let forged = AddCheckpointRequest {
        old_size: 0,
        consistency_proof: vec![],
        checkpoint_note: wl.c2sp_checkpoint(&origin).sign(&other).unwrap(),
    };
    assert!(!svc.enroll_canonical(&forged));
    assert_eq!(svc.log_count(), 0);
    // Non-canonical origin: not enrolled.
    let custom = AddCheckpointRequest {
        old_size: 0,
        consistency_proof: vec![],
        checkpoint_note: wl.c2sp_checkpoint("example.com/x").sign(&key).unwrap(),
    };
    assert!(!svc.enroll_canonical(&custom));
    // Canonical and validly signed: enrolled once, never re-enrolled.
    assert!(svc.enroll_canonical(&good));
    assert!(!svc.enroll_canonical(&good));
    assert_eq!(svc.log_count(), 1);
    let wkey = SigningKey::generate(&mut OsRng);
    let out = svc.handle_add_checkpoint(&good, "w.example/1", &wkey, 1);
    assert_eq!(out.http_status(), 200, "{out:?}");
}

// ---- independent review findings (0.3.1) ----

#[test]
fn junk_proof_on_an_honest_checkpoint_is_refused_but_not_evidence() {
    // Anyone can relay an honest log's public checkpoint with a garbage
    // proof. That must be refused, and must NOT be "misbehaviour evidence".
    let mut log = Log::new();
    log.append(5);
    let (mut svc, wkey, _) = witness();
    svc.add_log(ORIGIN, log.vkey());
    svc.handle_add_checkpoint(&log.request(0, None), "witness.example/w1", &wkey, 1);
    log.append(3);
    let mut req = log.request(5, None);
    req.consistency_proof = vec![[0xAB; 32]; 3];
    let out = svc.handle_add_checkpoint(&req, "witness.example/w1", &wkey, 2);
    assert_eq!(out.http_status(), 422, "{out:?}");
    assert!(
        !out.is_misbehaviour_evidence(),
        "a junk proof is not proof of a fork"
    );
}

#[test]
fn same_size_different_root_is_provable_equivocation() {
    let mut log = Log::new();
    log.append(6);
    let (mut svc, wkey, _) = witness();
    svc.add_log(ORIGIN, log.vkey());
    svc.handle_add_checkpoint(&log.request(0, None), "witness.example/w1", &wkey, 1);
    let other = Checkpoint {
        origin: ORIGIN.to_string(),
        tree_size: 6,
        root_hash: [0x42; 32],
        extensions: vec![],
    };
    let req = AddCheckpointRequest {
        old_size: 6,
        consistency_proof: vec![],
        checkpoint_note: other.sign(&log.key()).unwrap(),
    };
    let out = svc.handle_add_checkpoint(&req, "witness.example/w1", &wkey, 2);
    assert!(out.is_misbehaviour_evidence(), "{out:?}");
    let AddCheckpointOutcome::ConsistencyFailed {
        equivocation: Some(proof),
        ..
    } = out
    else {
        panic!()
    };
    // A non-canonical origin does not name its key: the proof needs the
    // key the checker holds for this log (0.4.2, review round 2 W1).
    assert!(
        !proof.verify(),
        "no key can be taken from a non-canonical origin"
    );
    assert!(
        proof.verify_with_key(&log.vkey()),
        "proof must check out under the log's key"
    );
    // A tampered proof must not.
    let mut bad = proof.clone();
    bad.conflicting_note = bad.earlier_note.clone();
    assert!(
        !bad.verify_with_key(&log.vkey()),
        "two identical notes prove nothing"
    );
}

#[test]
fn re_adding_a_known_log_never_resets_it() {
    let mut log = Log::new();
    log.append(5);
    let (mut svc, wkey, _) = witness();
    assert!(svc.add_log(ORIGIN, log.vkey()));
    svc.handle_add_checkpoint(&log.request(0, None), "witness.example/w1", &wkey, 1);
    assert!(
        !svc.add_log(ORIGIN, log.vkey()),
        "second add must be refused"
    );
    assert_eq!(
        svc.known_log(ORIGIN).unwrap().tree_size,
        5,
        "state not reset"
    );
}

#[test]
fn oversized_checkpoint_bodies_are_refused() {
    // Extension lines are legal C2SP, but a witness stores the last note
    // per log: an uncapped body let one log make a witness keep 64 KiB.
    let log = Log::new();
    let cp = Checkpoint {
        origin: ORIGIN.to_string(),
        tree_size: 0,
        root_hash: MerkleTree::new().root(),
        extensions: (0..40)
            .map(|i| format!("ext-{i}-{}", "x".repeat(30)))
            .collect(),
    };
    let body = AddCheckpointRequest {
        old_size: 0,
        consistency_proof: vec![],
        checkpoint_note: cp.sign(&log.key()).unwrap(),
    }
    .to_http_body()
    .unwrap();
    assert!(AddCheckpointRequest::parse(&body).is_err());
}

/// A server that keeps each log's record in storage and reads one per
/// request (`witness serve` since it stopped loading every record at
/// startup) runs the protocol on a single `KnownLog`. Persisted and
/// reloaded after every request, that record must decide exactly as the
/// in-memory service does, and hold exactly what the service holds.
#[test]
fn a_record_kept_in_storage_decides_exactly_like_the_service() {
    let mut log = Log::new();
    log.append(5);
    let (mut svc, wkey, _) = witness();
    svc.add_log(ORIGIN, log.vkey());
    let mut stored: KnownLogRecord = KnownLog::new(ORIGIN, log.vkey()).to_record();

    let first = log.request(0, None);
    let fork_same_size = AddCheckpointRequest {
        old_size: 5,
        consistency_proof: vec![],
        checkpoint_note: Checkpoint {
            origin: ORIGIN.to_string(),
            tree_size: 5,
            root_hash: [0x42; 32],
            extensions: vec![],
        }
        .sign(&log.key())
        .unwrap(),
    };
    let wrong_key = AddCheckpointRequest {
        old_size: 5,
        consistency_proof: vec![],
        checkpoint_note: log
            .checkpoint()
            .sign(&SigningKey::generate(&mut OsRng))
            .unwrap(),
    };
    let behind = log.request(3, None);
    let mut requests = vec![
        first.clone(),
        log.request(5, None),
        fork_same_size,
        wrong_key,
        behind,
    ];
    log.append(3);
    requests.push(log.request(5, None));
    log.append(3);
    let mut junk = log.request(8, None);
    junk.consistency_proof = vec![[0xAB; 32]; 3];
    requests.push(junk);
    requests.push(AddCheckpointRequest {
        old_size: 8,
        ..first
    });

    let mut statuses = Vec::new();
    for (i, req) in requests.iter().enumerate() {
        let now = 1_700_000_000 + i as u64;
        let a = svc.handle_add_checkpoint(req, "witness.example/w1", &wkey, now);
        let mut k = KnownLog::from_record(&stored).expect("stored record decodes");
        let b = k.handle_add_checkpoint(req, "witness.example/w1", &wkey, now);
        assert_eq!(a, b, "request {i}");
        statuses.push(b.http_status());
        stored = k.to_record();
        assert_eq!(svc.export_state().logs, vec![stored.clone()], "request {i}");
    }
    assert_eq!(statuses, [200, 200, 422, 403, 409, 200, 422, 400]);
    assert_eq!(stored.tree_size, 8);

    // A request naming another log is not this record's business.
    let mut k = KnownLog::from_record(&stored).unwrap();
    let other = AddCheckpointRequest {
        old_size: 0,
        consistency_proof: vec![],
        checkpoint_note: Checkpoint {
            origin: "other.example/log".to_string(),
            ..log.checkpoint()
        }
        .sign(&log.key())
        .unwrap(),
    };
    let out = k.handle_add_checkpoint(&other, "witness.example/w1", &wkey, 1);
    assert_eq!(out.http_status(), 404, "{out:?}");
    assert_eq!(k.to_record(), stored, "unchanged");

    // A malformed stored record is an error, never a log at size 0.
    let mut bad = stored.clone();
    bad.log_vkey = "not a vkey".into();
    assert!(KnownLog::from_record(&bad).is_err());
    let mut bad = stored;
    bad.root_hash = "zz".into();
    assert!(KnownLog::from_record(&bad).is_err());
}

#[test]
fn canonical_enrollment_of_a_single_record() {
    use witness_log_core::c2sp::canonical_origin;
    let id = IdentityKeypair::generate();
    let key = SigningKey::from_bytes(&id.to_bytes());
    let mut wl = WitnessLog::resume(id, 0);
    wl.append_intent(b"x");
    let origin = canonical_origin(&key.verifying_key());
    let request = |origin: &str, signer: &SigningKey| AddCheckpointRequest {
        old_size: 0,
        consistency_proof: vec![],
        checkpoint_note: wl.c2sp_checkpoint(origin).sign(signer).unwrap(),
    };
    let k = KnownLog::from_canonical_request(&request(&origin, &key)).expect("enrolls");
    assert_eq!(
        k,
        KnownLog::new(
            &origin,
            VerifierKey::for_ed25519(&origin, &key.verifying_key())
        )
    );
    let other = SigningKey::generate(&mut OsRng);
    assert!(KnownLog::from_canonical_request(&request(&origin, &other)).is_none());
    assert!(KnownLog::from_canonical_request(&request("example.com/x", &key)).is_none());
}
