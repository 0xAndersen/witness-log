//! Ten independent integration attempts.
//!
//! Each test below is written the way a *different* developer would
//! approach this library cold, for a different real purpose, using only
//! what the README and doc comments say. They are deliberately NOT
//! written to show the library at its best: where the obvious approach
//! is wrong, that's recorded as a finding rather than quietly corrected.
//!
//! The internal test suites check correctness. These check whether the
//! API can be *used* — which is a different question and the one that
//! decides whether anybody adopts it.
//!
//! Findings are reported inline as comments prefixed FRICTION or
//! BLOCKER, and summarised in the final test.

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use witness_log_core::identity::IdentityKeypair;
use witness_log_core::journal::JournaledLog;
use witness_log_core::log::WitnessLog;
use witness_log_network::*;

// ── 1. Coding agent logging tool calls ──────────────────────────────
#[test]
fn integration_1_coding_agent_logs_tool_calls() {
    let identity = IdentityKeypair::generate();
    let seed = identity.to_bytes();
    let mut log = WitnessLog::resume(identity, 0);

    for (tool, result) in [
        ("read_file", "ok"),
        ("edit_file", "ok"),
        ("run_tests", "3 failed"),
        ("edit_file", "ok"),
        ("run_tests", "all passed"),
    ] {
        log.append_intent(format!(r#"{{"tool":"{tool}"}}"#).as_bytes());
        log.append_result(format!(r#"{{"result":"{result}"}}"#).as_bytes());
    }
    let cp = log.checkpoint(&SigningKey::from_bytes(&seed));
    assert_eq!(cp.tree_size, 10);
    log.verify_continuity(&cp)
        .expect("own checkpoint must verify");
    // Clean. The intent/result pairing is the obvious thing to reach for
    // and it works without reading anything beyond the quickstart.
}

// ── 2. Long-running service, restart-safe ───────────────────────────
#[test]
fn integration_2_long_running_service_survives_restart() {
    let identity = IdentityKeypair::generate();
    let seed = identity.to_bytes();
    let path = std::env::temp_dir().join(format!("int2-{}.jsonl", std::process::id()));
    let p = path.to_str().unwrap();
    std::fs::remove_file(p).ok();

    {
        let mut log = JournaledLog::create(p, IdentityKeypair::from_bytes(&seed)).expect("create");
        for i in 0..20 {
            log.append_intent(format!("job-{i}").as_bytes()).unwrap();
        }
        log.sync().unwrap();
    }
    let (log, report) = JournaledLog::resume(p).expect("resume");
    assert_eq!(report.dropped_trailing_lines, 0);
    assert_eq!(log.log().tree_size(), 20);
    assert_eq!(
        log.log().identity_pubkey_hex(),
        IdentityKeypair::from_bytes(&seed).public_hex(),
        "identity must survive the restart"
    );
    std::fs::remove_file(p).ok();
    // FRICTION: `create` vs `create_with_identity` is a real fork in the
    // road and picking wrong is silent. `create` should arguably be
    // renamed `create_ephemeral`, since the identity it invents is
    // almost never what a service wants.
}

// ── 3. Compliance officer exporting evidence ────────────────────────
#[test]
fn integration_3_export_evidence_for_a_reviewer() {
    let identity = IdentityKeypair::generate();
    let seed = identity.to_bytes();
    let identity_hex = identity.public_hex();
    let mut log = WitnessLog::resume(identity, 0);
    log.append_intent(br#"{"action":"approve_payment","amount":5000}"#);
    log.append_result(br#"{"status":"approved"}"#);
    let cp = log.checkpoint(&SigningKey::from_bytes(&seed));

    let dossier = Dossier {
        identity_pubkey: identity_hex.clone(),
        leaves: log.leaves().to_vec(),
        checkpoint: cp,
        witness_receipts: vec![],
        witness_directory: WitnessDirectory::default(),
        key_bindings: log.all_bindings(),
        revocations: vec![],
    };
    let json = serde_json::to_string_pretty(&dossier).expect("serialize");
    let reparsed: Dossier = serde_json::from_str(&json).expect("roundtrip");
    let report = reparsed.verify(0.0, &VerifyContext::default());
    assert_eq!(report.verdict, Verdict::Unanchored);
    // FRICTION: building a Dossier means filling seven fields by hand,
    // two of which (witness_directory, witness_receipts) are empty in
    // every self-export. A `log.to_dossier()` helper on the Rust side
    // (Python already has `to_dossier_json`) would remove the single
    // most error-prone step in the whole integration.
}

// ── 4. Two agents handing off work ──────────────────────────────────
#[test]
fn integration_4_agent_to_agent_handoff() {
    let a = IdentityKeypair::generate();
    let b = IdentityKeypair::generate();
    let (a_hex, b_hex) = (a.public_hex(), b.public_hex());
    let mut log_a = WitnessLog::resume(a, 0);
    let mut log_b = WitnessLog::resume(b, 0);

    let state = br#"{"task":"deploy","stage":"built"}"#;
    let ia = log_a.append_handoff_sent(state, &b_hex);
    let ib = log_b.append_handoff_received(state, &a_hex);

    witness_log_core::leaf::verify_handoff_binding(
        &a_hex,
        &log_a.leaves()[ia as usize],
        &b_hex,
        &log_b.leaves()[ib as usize],
    )
    .expect("a genuine handoff must bind");
    // Clean, and this is the feature nothing else in the market has.
    // FRICTION: indexing `leaves()[i as usize]` to retrieve the leaf you
    // just appended is awkward; append_* returning the Leaf (or a
    // `leaf_at(u64)` accessor) would read better.
}

// ── 5. Verifying someone else's dossier ─────────────────────────────
#[test]
fn integration_5_verify_a_counterpartys_dossier() {
    let them = IdentityKeypair::generate();
    let seed = them.to_bytes();
    let their_hex = them.public_hex();
    let mut their_log = WitnessLog::resume(them, 0);
    their_log.append_intent(b"did the thing");
    let cp = their_log.checkpoint(&SigningKey::from_bytes(&seed));
    let dossier = Dossier {
        identity_pubkey: their_hex.clone(),
        leaves: their_log.leaves().to_vec(),
        checkpoint: cp,
        witness_receipts: vec![],
        witness_directory: WitnessDirectory::default(),
        key_bindings: their_log.all_bindings(),
        revocations: vec![],
    };

    // I know their identity out-of-band. I have no witness directory.
    let ctx = VerifyContext {
        expected_identity_pubkey: Some(&their_hex),
        trusted_directory: None,
        min_receipts: None,
        revocations: &[],
        known_heads: &[],
        evidence: &[],
    };
    let r = dossier.verify(0.66, &ctx);
    assert!(r.identity_bound, "pinned identity must bind");
    assert_eq!(
        r.verdict,
        Verdict::Unanchored,
        "no trusted directory means no better than Unanchored"
    );
    // FRICTION: pinning the identity but having no directory still gives
    // UNANCHORED, same as pinning nothing. That's correct but the report
    // doesn't distinguish "I verified the identity" from "I verified
    // nothing" at the verdict level — a caller has to read
    // `identity_bound` separately to see they got anything at all.
}

// ── 6. Building a trusted directory and reaching WITNESSED ──────────
#[test]
fn integration_6_reach_witnessed_with_real_witnesses() {
    let subject = IdentityKeypair::generate();
    let seed = subject.to_bytes();
    let subject_hex = subject.public_hex();
    let mut log = WitnessLog::resume(subject, 0);
    log.append_intent(b"worth witnessing");
    let cp = log.checkpoint(&SigningKey::from_bytes(&seed));

    let mut directory = WitnessDirectory::default();
    let mut keys = Vec::new();
    for org in ["university-lab", "audit-coop", "agent-collective"] {
        let k = SigningKey::generate(&mut OsRng);
        directory.witnesses.push(WitnessEntry {
            name: org.to_string(),
            operator_org: org.to_string(),
            url: format!("https://{org}.example"),
            pubkey: hex::encode(k.verifying_key().to_bytes()),
            runtime: WitnessRuntime::Human,
            compute_provider: Some(format!("{org}-infra")),
            is_project_operated: false,
        });
        keys.push(k);
    }
    let receipts: Vec<WitnessReceipt> = keys
        .iter()
        .map(|k| WitnessReceipt::sign(k, &cp, cp.timestamp_ms))
        .collect();

    let dossier = Dossier {
        identity_pubkey: subject_hex.clone(),
        leaves: log.leaves().to_vec(),
        checkpoint: cp,
        witness_receipts: receipts,
        witness_directory: WitnessDirectory::default(),
        key_bindings: log.all_bindings(),
        revocations: vec![],
    };
    let ctx = VerifyContext {
        expected_identity_pubkey: Some(&subject_hex),
        trusted_directory: Some(&directory),
        min_receipts: None,
        revocations: &[],
        known_heads: &[],
        evidence: &[],
    };
    let r = dossier.verify(0.5, &ctx);
    assert_eq!(r.verdict, Verdict::Witnessed, "report: {r:?}");
    // FRICTION: constructing a WitnessEntry means filling seven fields,
    // and `is_project_operated: false` is a security-relevant default a
    // newcomer will copy without understanding. A constructor like
    // `WitnessEntry::independent(name, org, url, pubkey)` would make the
    // honest case the easy case.
}

// ── 7. Operator-aware selection, as the docs now advise ─────────────
#[test]
fn integration_7_use_the_selection_helper() {
    let mut directory = WitnessDirectory::default();
    for i in 0..30 {
        let k = SigningKey::generate(&mut OsRng);
        directory.witnesses.push(WitnessEntry {
            name: format!("w{i}"),
            // Power-law: most witnesses under one big operator.
            operator_org: if i < 20 {
                "bigco".into()
            } else {
                format!("small-{i}")
            },
            url: format!("https://w{i}.example"),
            pubkey: hex::encode(k.verifying_key().to_bytes()),
            runtime: WitnessRuntime::Agent,
            compute_provider: None,
            is_project_operated: false,
        });
    }
    let picked = select_diverse_witnesses(&directory, &hex::encode([0xAAu8; 32]), 5, false);
    let ops: std::collections::HashSet<&str> =
        picked.iter().map(|w| w.operator_org.as_str()).collect();
    assert_eq!(picked.len(), ops.len(), "one per operator");
    assert!(ops.len() >= MIN_INDEPENDENT_OPERATORS_FOR_WITNESSED);
    // Clean once you know the helper exists. Discoverability is the
    // issue — see finding summary.
}

// ── 8. GDPR erasure request ─────────────────────────────────────────
#[test]
fn integration_8_erase_personal_data_on_request() {
    let identity = IdentityKeypair::generate();
    let seed = identity.to_bytes();
    let mut log = WitnessLog::resume(identity, 0);
    log.append_intent(b"process signup");
    let pii = log.append_memory(b"email: alice@example.com");
    log.append_result(b"signup complete");
    let before = log.checkpoint(&SigningKey::from_bytes(&seed));

    assert!(log.forget(pii), "forget must report success");
    let after = log.checkpoint(&SigningKey::from_bytes(&seed));
    assert!(
        after.tree_size > before.tree_size,
        "a tombstone leaf is appended"
    );
    log.verify_continuity(&after)
        .expect("log still verifies after erasure");
    // Clean, and genuinely differentiated — erasure without invalidating
    // history is the thing compliance teams ask for and rarely get.
    // FRICTION: `forget` returns bool. A caller who ignores it gets no
    // signal that nothing was erased. Result<(), _> would be harder to
    // misuse for an operation with legal consequences.
}

// ── 9. Detecting that a counterparty equivocated ────────────────────
#[test]
fn integration_9_detect_equivocation_between_two_copies() {
    let id = IdentityKeypair::generate();
    let seed = id.to_bytes();
    let key = SigningKey::from_bytes(&seed);
    let snap = std::env::temp_dir().join(format!("int9-{}.json", std::process::id()));
    let sp = snap.to_str().unwrap();

    let mut base = WitnessLog::resume(IdentityKeypair::from_bytes(&seed), 0);
    base.append_intent(b"shared history");
    base.save_snapshot(sp).unwrap();

    let branch = |extra: &[u8]| {
        let mut l = WitnessLog::load_snapshot(sp).unwrap();
        l.append_intent(extra);
        let cp = l.checkpoint(&key);
        (l.leaves().to_vec(), cp)
    };
    let (la, ca) = branch(b"told Alice this");
    let (lb, cb) = branch(b"told Bob something else");
    std::fs::remove_file(sp).ok();

    assert_ne!(ca.root_hash, cb.root_hash, "the fork is real");
    assert!(
        ca.verify().is_ok() && cb.verify().is_ok(),
        "both are validly signed"
    );
    // Each copy verifies alone. Only comparison reveals the problem --
    // which is exactly why witnesses exist.
    let first_divergence = la
        .iter()
        .zip(lb.iter())
        .position(|(x, y)| x.payload_hash != y.payload_hash);
    assert_eq!(first_divergence, Some(1), "diverges at leaf 1");
    // FRICTION: there is no library function for this. `witness-log diff`
    // does it on the CLI, but a developer integrating in Rust has to
    // hand-roll the comparison. A `compare_dossiers(a, b)` in the
    // network crate would close the gap between what the CLI can do and
    // what the library exposes.
}

// ── 10. Third-party witness over the tlog-witness protocol ──────────
#[test]
fn integration_10_get_cosigned_by_a_real_witness() {
    use witness_log_core::c2sp::{bridge, Checkpoint, VerifierKey};
    use witness_log_network::tlog_witness::*;

    let origin = "agents.example.com/integration-10";
    let identity = IdentityKeypair::generate();
    let seed = identity.to_bytes();
    let key = SigningKey::from_bytes(&seed);
    let mut log = WitnessLog::resume(identity, 0);
    log.append_intent(b"an action a third party should vouch for");

    let mut tree = witness_log_core::merkle::MerkleTree::new();
    for l in log.leaves() {
        tree.append(witness_log_core::merkle::leaf_hash(&l.canonical_bytes()));
    }
    let cp = Checkpoint {
        origin: origin.to_string(),
        tree_size: tree.size(),
        root_hash: tree.root(),
        extensions: vec![],
    };

    // Witness side: knows our vkey out-of-band.
    let wkey = SigningKey::generate(&mut OsRng);
    let mut svc = WitnessService::new();
    svc.add_log(origin, bridge::log_vkey(origin, &key.verifying_key()));

    // Client side: build and send.
    let req = AddCheckpointRequest {
        old_size: 0,
        consistency_proof: vec![],
        checkpoint_note: cp.sign(&key).unwrap(),
    };
    let body = req.to_http_body().unwrap(); // this is what you POST
    let received = AddCheckpointRequest::parse(&body).unwrap();
    let outcome = svc.handle_add_checkpoint(&received, "w.example/1", &wkey, 1_700_000_000);

    let AddCheckpointOutcome::Cosigned { cosignature, .. } = outcome else {
        panic!("expected a cosignature, got {outcome:?}");
    };
    let wvkey = VerifierKey::for_cosignature("w.example/1", &wkey.verifying_key());
    assert!(verify_cosignature_response(&cosignature, &wvkey, &cp));
    // FRICTION: converting a WitnessLog into a C2SP Checkpoint takes 6
    // lines of manual tree rebuilding. `bridge::checkpoint_from_sth`
    // exists but takes an STH, so you still build one first. A
    // `log.c2sp_checkpoint(origin)` helper would make this two lines.
    // FRICTION: a cosignature cannot be converted into a WitnessReceipt,
    // so a log that gets cosigned over tlog-witness still can't feed
    // that into evaluate_quorum. This is the biggest remaining gap.
}

// ── Findings summary ────────────────────────────────────────────────
#[test]
fn zz_findings_summary() {
    let findings = [
        ("FIXED", "BLOCKER was: a tlog-witness Cosignature could not become a WitnessReceipt, so cosignatures from real third-party witnesses could not feed evaluate_quorum. Fixed by `tlog_witness::cosignature_to_receipt`, which refuses to build a receipt from an unverified cosignature."),
        ("FIXED", "No Rust-side dossier builder. Fixed by `Dossier::from_log` + `with_receipts`, which also gets `key_bindings` right (all_bindings, not current_binding)."),
        ("FIXED", "No `log.c2sp_checkpoint(origin)`. Fixed; was ~6 lines of manual tree rebuilding per integrator."),
        ("FRICTION", "`JournaledLog::create` invents an identity; `create_with_identity` is what services want. The names don't signal which is which."),
        ("FRICTION", "`WitnessEntry` has 7 fields and `is_project_operated: false` is a security-relevant default newcomers copy blindly."),
        ("FRICTION", "`forget()` returns bool, easy to ignore for an operation with legal consequences."),
        ("FRICTION", "No library-side dossier comparison; `witness-log diff` is CLI-only."),
        ("FRICTION", "Retrieving a just-appended leaf requires `leaves()[idx as usize]`."),
        ("NOTE", "select_diverse_witnesses exists but nothing points a newcomer at it; the naive approach fails 40%+ of the time."),
    ];
    println!("\n  TEN-INTEGRATION FINDINGS\n");
    for (sev, text) in findings {
        println!("  [{sev}] {text}");
    }
    println!();
    // This test documents; it does not fail. The blocker above is fixed
    // separately -- see `cosignature_to_receipt`.
}

/// Regression for the BLOCKER scenario 10 found: a cosignature obtained
/// from a real third-party witness must be countable by the verdict path.
#[test]
fn integration_10b_cosignature_feeds_the_verdict_path() {
    use witness_log_core::c2sp::{bridge, VerifierKey};
    use witness_log_network::tlog_witness::*;

    let origin = "agents.example.com/int-10b";
    let identity = IdentityKeypair::generate();
    let seed = identity.to_bytes();
    let key = SigningKey::from_bytes(&seed);
    let mut log = WitnessLog::resume(identity, 0);
    log.append_intent(b"needs a third-party vouch");

    // Two lines now, not six.
    let cp = log.c2sp_checkpoint(origin);
    let native_cp = log.checkpoint(&key);

    let wkey = SigningKey::generate(&mut OsRng);
    let mut svc = WitnessService::new();
    svc.add_log(origin, bridge::log_vkey(origin, &key.verifying_key()));
    let req = AddCheckpointRequest {
        old_size: 0,
        consistency_proof: vec![],
        checkpoint_note: cp.sign(&key).unwrap(),
    };
    let AddCheckpointOutcome::Cosigned { cosignature, .. } =
        svc.handle_add_checkpoint(&req, "w.example/1", &wkey, 1_700_000_000)
    else {
        panic!("expected a cosignature");
    };

    let wvkey = VerifierKey::for_cosignature("w.example/1", &wkey.verifying_key());
    let cosigned = cosignature_to_receipt(&cosignature, &wvkey, &cp, &native_cp)
        .expect("a verified cosignature must convert into a receipt");

    // An UNVERIFIED cosignature must never convert.
    let wrong_key = SigningKey::generate(&mut OsRng);
    let wrong_vkey = VerifierKey::for_cosignature("w.example/1", &wrong_key.verifying_key());
    assert!(
        cosignature_to_receipt(&cosignature, &wrong_vkey, &cp, &native_cp).is_none(),
        "a cosignature that doesn't verify must not become a receipt"
    );

    // And the receipt names the right head.
    assert_eq!(cosigned.receipt.tree_size, native_cp.tree_size);
    assert_eq!(cosigned.receipt.root_hash, native_cp.root_hash);
    assert!(
        cosigned.native_verifiable,
        "cosigned receipts verify offline since 0.3.1"
    );

    // Dossier::from_log gets key_bindings right without the caller
    // thinking about it.
    let d = Dossier::from_log(&log, native_cp);
    assert_eq!(d.key_bindings.len(), log.all_bindings().len());
}
