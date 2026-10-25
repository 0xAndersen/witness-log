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

/// `bind x y --json` as (exit, bound pairs, failures), each failure named by
/// the identity whose dossier holds the leaf, so both argument orders can be
/// compared directly.
type Outcome = (i32, Vec<(String, u64, u64)>, Vec<(String, String, u64)>);

fn outcome(x: &str, y: &str, first_id: &str) -> Outcome {
    let (code, out, err) = bind(x, y, &["--json"]);
    let v: serde_json::Value =
        serde_json::from_str(&out).unwrap_or_else(|e| panic!("{e}: {out}{err}"));
    let s = |v: &serde_json::Value| v.as_str().unwrap().to_string();
    let n = |v: &serde_json::Value| v.as_u64().unwrap();
    let mut bound: Vec<(String, u64, u64)> = v["bound"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| match p["kind"].as_str() {
            // (kind, leaf in the first-named identity's dossier, leaf in the other)
            Some("handoff") if p["sender"] == first_id => (
                "handoff".into(),
                n(&p["sender_leaf"]),
                n(&p["receiver_leaf"]),
            ),
            Some("handoff") => (
                "handoff".into(),
                n(&p["receiver_leaf"]),
                n(&p["sender_leaf"]),
            ),
            _ if p["a"] == first_id => ("authorization".into(), n(&p["a_leaf"]), n(&p["b_leaf"])),
            _ => ("authorization".into(), n(&p["b_leaf"]), n(&p["a_leaf"])),
        })
        .collect();
    let mut failed: Vec<(String, String, u64)> = v["failed"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| {
            let (owner, leaf) = if f.get("sender_leaf").is_some() {
                (s(&f["sender"]), n(&f["sender_leaf"]))
            } else if f.get("receiver_leaf").is_some() {
                (s(&f["receiver"]), n(&f["receiver_leaf"]))
            } else if f.get("a_leaf").is_some() {
                (s(&f["a"]), n(&f["a_leaf"]))
            } else {
                (s(&f["b"]), n(&f["b_leaf"]))
            };
            (s(&f["kind"]), owner, leaf)
        })
        .collect();
    bound.sort();
    failed.sort();
    (code, bound, failed)
}

/// Both orders, normalised to (x's identity first); asserts they agree.
fn outcome_both_orders(x: &WitnessLog, y: &WitnessLog) -> Outcome {
    let (dx, dy) = (dossier(x), dossier(y));
    let ix = x.identity_pubkey_hex();
    let xy = outcome(dx.path(), dy.path(), &ix);
    let yx = outcome(dy.path(), dx.path(), &ix);
    assert_eq!(xy, yx, "bind must not depend on argument order");
    xy
}

/// Regression (review of the agent-payments change): matching was "first
/// match", so several leaves on one side could bind the same leaf on the
/// other. A re-grant after a revocation that only the grantee logged, or a
/// grant logged twice by one side, was BOUND (exit 0) in both orders.
/// Matching is one to one now: each leaf binds at most once.
#[test]
fn a_repeated_authorization_event_binds_once() {
    let mut a = WitnessLog::resume(IdentityKeypair::generate(), 0);
    let mut b = WitnessLog::resume(IdentityKeypair::generate(), 0);
    let (ia, ib) = (a.identity_pubkey_hex(), b.identity_pubkey_hex());
    use AuthorizationEventKind as K;
    a.append_authorization_event(K::GrantedByMe, b"scope", &ib);
    a.append_authorization_event(K::RevokedByMe, b"scope", &ib);
    b.append_authorization_event(K::GrantedToMe, b"scope", &ia);
    b.append_authorization_event(K::RevokedToMe, b"scope", &ia);
    // Both sides agree so far.
    let (code, bound, failed) = outcome_both_orders(&a, &b);
    assert_eq!((code, bound.len(), failed.len()), (0, 2, 0));
    // B alone records a re-grant after the revocation.
    b.append_authorization_event(K::GrantedToMe, b"scope", &ia);
    let (code, bound, failed) = outcome_both_orders(&a, &b);
    assert_eq!(code, 30);
    assert_eq!(bound.len(), 2);
    assert_eq!(failed, vec![("authorization".to_string(), ib.clone(), 2)]);
    // A logs the re-grant too: everything binds again, one to one.
    a.append_authorization_event(K::GrantedByMe, b"scope", &ib);
    assert_eq!(outcome_both_orders(&a, &b).0, 0);

    // Two identical grants on one side, one on the other: one is left over.
    let mut c = WitnessLog::resume(IdentityKeypair::generate(), 0);
    let mut d = WitnessLog::resume(IdentityKeypair::generate(), 0);
    let (ic, id) = (c.identity_pubkey_hex(), d.identity_pubkey_hex());
    c.append_authorization_event(K::GrantedByMe, b"scope", &id);
    c.append_authorization_event(K::GrantedByMe, b"scope", &id);
    d.append_authorization_event(K::GrantedToMe, b"scope", &ic);
    let (code, bound, failed) = outcome_both_orders(&c, &d);
    assert_eq!((code, bound.len()), (30, 1));
    assert_eq!(failed, vec![("authorization".to_string(), ic.clone(), 1)]);
    let (_, out, _) = bind(dossier(&c).path(), dossier(&d).path(), &[]);
    assert!(
        out.contains("authorization NOT bound (A leaf 1): b leaf 0: already bound to a leaf 0"),
        "{out}"
    );
}

/// Regression (same review): a Received handoff that no Sent leaf binds to
/// was ignored in both orders: alone it gave exit 10 with "neither dossier
/// carries a HandoffAttestation ... naming the other identity", which was
/// false, and next to a bound pair it gave 0.
#[test]
fn a_received_handoff_nobody_sent_is_a_mismatch() {
    let mut a = WitnessLog::resume(IdentityKeypair::generate(), 0);
    let mut b = WitnessLog::resume(IdentityKeypair::generate(), 0);
    let (ia, ib) = (a.identity_pubkey_hex(), b.identity_pubkey_hex());
    b.append_handoff_received(b"H1", &ia);
    let (code, bound, failed) = outcome_both_orders(&a, &b);
    assert_eq!((code, bound.len()), (30, 0));
    assert_eq!(failed, vec![("handoff".to_string(), ib.clone(), 0)]);
    let (_, out, _) = bind(dossier(&a).path(), dossier(&b).path(), &[]);
    assert!(
        out.contains("handoff NOT bound (B leaf 0): sender logged no HandoffAttestation (Sent) naming this receiver"),
        "{out}"
    );

    // A sends H1 once; B logs receiving it twice: one Received is left over.
    a.append_handoff_sent(b"H1", &ib);
    b.append_handoff_received(b"H1", &ia);
    let (code, bound, failed) = outcome_both_orders(&a, &b);
    assert_eq!((code, bound.len()), (30, 1));
    assert_eq!(failed, vec![("handoff".to_string(), ib.clone(), 1)]);

    // A bound grant pair plus a lone Received is still a mismatch.
    let mut c = WitnessLog::resume(IdentityKeypair::generate(), 0);
    let mut d = WitnessLog::resume(IdentityKeypair::generate(), 0);
    let (ic, id) = (c.identity_pubkey_hex(), d.identity_pubkey_hex());
    c.append_authorization_event(AuthorizationEventKind::GrantedByMe, b"s", &id);
    d.append_authorization_event(AuthorizationEventKind::GrantedToMe, b"s", &ic);
    d.append_handoff_received(b"H2", &ic);
    let (code, bound, failed) = outcome_both_orders(&c, &d);
    assert_eq!((code, bound.len()), (30, 1));
    assert_eq!(failed, vec![("handoff".to_string(), id.clone(), 1)]);
}

/// A one-to-one mismatch reports both leaves, in either order (the
/// failure list is the same set whichever dossier comes first).
#[test]
fn a_mismatched_pair_reports_both_leaves() {
    let mut a = WitnessLog::resume(IdentityKeypair::generate(), 0);
    let mut b = WitnessLog::resume(IdentityKeypair::generate(), 0);
    let (ia, ib) = (a.identity_pubkey_hex(), b.identity_pubkey_hex());
    a.append_authorization_event(AuthorizationEventKind::GrantedByMe, b"max_usd=120", &ib);
    b.append_authorization_event(AuthorizationEventKind::GrantedToMe, b"max_usd=1200", &ia);
    a.append_handoff_sent(b"report v1", &ib);
    b.append_handoff_received(b"report v2", &ia);
    let (code, bound, failed) = outcome_both_orders(&a, &b);
    assert_eq!((code, bound.len()), (30, 0));
    assert_eq!(failed, {
        let mut f = vec![
            ("authorization".to_string(), ia.clone(), 0),
            ("authorization".to_string(), ib.clone(), 0),
            ("handoff".to_string(), ia.clone(), 1),
            ("handoff".to_string(), ib.clone(), 1),
        ];
        f.sort();
        f
    });
}
