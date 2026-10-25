//! `witness-log bind`: cross-log handoff / authorization binding from the
//! command line. Until 0.3.4 this existed only as a Rust function, so a
//! Python or MCP agent that recorded a handoff had no way to prove the
//! binding without writing Rust (outside evaluation of 0.3.3).

mod common;

use common::TmpJson;
use std::process::Command;
use witness_log_core::identity::IdentityKeypair;
use witness_log_core::leaf::AuthorizationEventKind;
use witness_log_core::log::WitnessLog;
use witness_log_network::Dossier;

fn dossier(log: &WitnessLog) -> TmpJson {
    let d = Dossier::from_log(log, log.checkpoint_self());
    TmpJson::write(&serde_json::to_string(&d).unwrap())
}

fn bind(a: &str, b: &str, extra: &[&str]) -> (i32, String, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_witness-log"))
        .args(["bind", a, b])
        .args(extra)
        .output()
        .unwrap();
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).to_string(),
        String::from_utf8_lossy(&out.stderr).to_string(),
    )
}

#[test]
fn bind_matches_handoffs_and_authorizations_and_reports_mismatch() {
    let mut a = WitnessLog::resume(IdentityKeypair::generate(), 0);
    let mut b = WitnessLog::resume(IdentityKeypair::generate(), 0);
    let (ia, ib) = (a.identity_pubkey_hex(), b.identity_pubkey_hex());

    // Nothing to bind yet: exit 10.
    let (code, out, _) = bind(dossier(&a).path(), dossier(&b).path(), &[]);
    assert_eq!(code, 10, "{out}");

    a.append_handoff_sent(b"task:reconcile", &ib);
    b.append_handoff_received(b"task:reconcile", &ia);
    a.append_authorization_event(AuthorizationEventKind::GrantedByMe, b"max_usd=500", &ib);
    b.append_authorization_event(AuthorizationEventKind::GrantedToMe, b"max_usd=500", &ia);
    let (da, db) = (dossier(&a), dossier(&b));
    let (code, out, err) = bind(da.path(), db.path(), &[]);
    assert_eq!(code, 0, "{out}{err}");
    assert!(
        out.contains("handoff bound") && out.contains("authorization bound"),
        "{out}"
    );
    // Event kinds print as the names the other surfaces accept, not Debug.
    assert!(
        out.contains("granted_by_me") && out.contains("granted_to_me"),
        "{out}"
    );
    assert!(!out.contains("Some("), "{out}");

    let (code, out, _) = bind(da.path(), db.path(), &["--json"]);
    assert_eq!(code, 0);
    let v: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(v["bound"].as_array().unwrap().len(), 2);
    assert_eq!(v["failed"].as_array().unwrap().len(), 0);
    let auth = v["bound"]
        .as_array()
        .unwrap()
        .iter()
        .find(|x| x["kind"] == "authorization")
        .unwrap();
    assert_eq!(auth["a_event"], "granted_by_me");
    assert_eq!(auth["b_event"], "granted_to_me");

    // B claims a wider scope than A granted: mismatch, exit 30.
    b.append_authorization_event(AuthorizationEventKind::GrantedToMe, b"max_usd=5000", &ia);
    a.append_authorization_event(AuthorizationEventKind::GrantedByMe, b"max_usd=50", &ib);
    let (code, out, _) = bind(dossier(&a).path(), dossier(&b).path(), &[]);
    assert_eq!(code, 30, "{out}");
    assert!(out.contains("NOT bound"), "{out}");

    // Same identity twice is a usage error, not a binding.
    let (code, _, err) = bind(da.path(), da.path(), &[]);
    assert_eq!(code, 2);
    assert!(err.contains("same identity"), "{err}");
}

/// Regression: an AuthorizationEvent only B recorded (B claims a grant A
/// never made) was invisible to `bind a b`, which exited 0 BOUND, while
/// `bind b a` exited 30. Found with the agent-payments example: a seller
/// that adds a wider grant next to the real one. The result must not
/// depend on argument order.
#[test]
fn a_grant_only_one_side_recorded_is_a_mismatch_in_either_order() {
    let mut buyer = WitnessLog::resume(IdentityKeypair::generate(), 0);
    let mut seller = WitnessLog::resume(IdentityKeypair::generate(), 0);
    let (ib, is) = (buyer.identity_pubkey_hex(), seller.identity_pubkey_hex());
    buyer.append_authorization_event(AuthorizationEventKind::GrantedByMe, b"amount=0.01", &is);
    seller.append_authorization_event(AuthorizationEventKind::GrantedToMe, b"amount=0.01", &ib);
    let honest = dossier(&seller);
    seller.append_authorization_event(AuthorizationEventKind::GrantedToMe, b"amount=10.00", &ib);
    let (db, ds) = (dossier(&buyer), dossier(&seller));

    // The two honest halves still bind, in either order.
    for (x, y) in [(db.path(), honest.path()), (honest.path(), db.path())] {
        let (code, out, err) = bind(x, y, &[]);
        assert_eq!(code, 0, "{out}{err}");
    }
    for (x, y, side) in [
        (db.path(), ds.path(), "b_leaf"),
        (ds.path(), db.path(), "a_leaf"),
    ] {
        let (code, out, _) = bind(x, y, &["--json"]);
        assert_eq!(code, 30, "{out}");
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["bound"].as_array().unwrap().len(), 1, "{out}");
        let failed = v["failed"].as_array().unwrap();
        assert_eq!(failed.len(), 1, "{out}");
        assert_eq!(failed[0]["kind"], "authorization");
        assert_eq!(
            failed[0][side], 1,
            "the seller's extra grant is leaf 1: {out}"
        );
        assert!(
            failed[0]["reason"]
                .as_str()
                .unwrap()
                .contains("scope hashes do not match"),
            "{out}"
        );
    }
    let (code, out, _) = bind(db.path(), ds.path(), &[]);
    assert_eq!(code, 30);
    assert!(out.contains("authorization NOT bound (B leaf 1)"), "{out}");

    // A grant only B recorded, with nothing at all on A's side, is a
    // mismatch too, not "nothing to bind".
    let quiet = WitnessLog::resume(IdentityKeypair::generate(), 0);
    let empty = dossier(&quiet);
    let mut lone = WitnessLog::resume(IdentityKeypair::generate(), 0);
    lone.append_authorization_event(
        AuthorizationEventKind::GrantedToMe,
        b"amount=10.00",
        &quiet.identity_pubkey_hex(),
    );
    let dl = dossier(&lone);
    for (x, y) in [(empty.path(), dl.path()), (dl.path(), empty.path())] {
        let (code, out, _) = bind(x, y, &[]);
        assert_eq!(code, 30, "{out}");
        assert!(
            out.contains("no AuthorizationEvent naming this agent"),
            "{out}"
        );
    }
}
