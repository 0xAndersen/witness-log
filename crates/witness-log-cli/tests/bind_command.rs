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

    let (code, out, _) = bind(da.path(), db.path(), &["--json"]);
    assert_eq!(code, 0);
    let v: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(v["bound"].as_array().unwrap().len(), 2);
    assert_eq!(v["failed"].as_array().unwrap().len(), 0);

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
