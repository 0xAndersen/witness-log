//! Regressions for defects found by the 0.3.5 fresh-eyes evaluation
//! (integrator, adversary and hostile-input personas working from the
//! README and the published packages). Each test fails on 0.3.5.

use witness_log_core::identity::IdentityKeypair;
use witness_log_core::journal::JournaledLog;
use witness_log_core::leaf::verify_handoff_binding;
use witness_log_core::log::WitnessLog;
use witness_log_network::{Dossier, Verdict, VerifyContext};

fn tmp(name: &str) -> String {
    let dir = std::env::temp_dir().join(format!(
        "wl-fresh-eyes-{}-{}-{}",
        name,
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir.join("agent.jsonl").to_string_lossy().into_owned()
}

fn verdict_of(log: &WitnessLog) -> Verdict {
    let d = Dossier::from_log(log, log.checkpoint_self());
    let id = log.identity_pubkey_hex();
    let ctx = VerifyContext {
        expected_identity_pubkey: Some(&id),
        ..Default::default()
    };
    d.verify(0.66, &ctx).verdict
}

/// Hostile input: `append_external_anchor("javascript:alert(1)", ..)` was
/// committed, every later dossier was DIVERGED, and `resume` refused the
/// journal. Now refused before the leaf exists.
#[test]
fn journal_refuses_a_non_http_anchor_url_and_stays_resumable() {
    let path = tmp("anchor");
    let mut j = JournaledLog::create_ephemeral(&path).unwrap();
    j.append_intent(b"before").unwrap();
    let err = j
        .append_external_anchor("javascript:alert(1)", "{}")
        .unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    assert!(err.to_string().contains("http:// or https://"), "{err}");
    assert_eq!(j.log().tree_size(), 1, "no leaf may be committed");
    j.append_external_anchor("https://rekor.example/entry/1", "{}")
        .unwrap();
    assert_eq!(verdict_of(j.log()), Verdict::Unanchored);
    drop(j);
    let (resumed, _) = JournaledLog::resume(&path).expect("journal must stay resumable");
    assert_eq!(resumed.log().tree_size(), 2);
}

/// Hostile input: any string was accepted as a handoff/authorization
/// counterparty ("zz", ""), producing a leaf that verifies but can never
/// bind.
#[test]
fn journal_refuses_a_counterparty_that_is_not_a_key() {
    let path = tmp("counterparty");
    let mut j = JournaledLog::create_ephemeral(&path).unwrap();
    for bad in ["zz", "", "not-a-key", &"g".repeat(64)] {
        assert!(j.append_handoff_sent(b"s", bad).is_err(), "{bad:?}");
        assert!(j.append_handoff_received(b"s", bad).is_err(), "{bad:?}");
        assert!(
            j.append_authorization_event(
                witness_log_core::leaf::AuthorizationEventKind::GrantedByMe,
                b"scope",
                bad
            )
            .is_err(),
            "{bad:?}"
        );
    }
    assert_eq!(j.log().tree_size(), 0);
}

/// Integrator: a counterparty key pasted in uppercase was committed
/// verbatim and the two sides could never bind. Now lowercased.
#[test]
fn uppercase_counterparty_key_still_binds() {
    let mut a = WitnessLog::new();
    let mut b = WitnessLog::new();
    let (ia, ib) = (a.identity_pubkey_hex(), b.identity_pubkey_hex());
    let sa = a.append_handoff_sent(b"task", &ib.to_ascii_uppercase());
    let sb = b.append_handoff_received(b"task", &ia.to_ascii_uppercase());
    let la = &a.leaves()[sa as usize];
    let lb = &b.leaves()[sb as usize];
    assert_eq!(la.counterparty_pubkey.as_deref(), Some(ib.as_str()));
    verify_handoff_binding(&ia, la, &ib, lb).expect("must bind");
}

/// Hostile input: after a TTL session binding expired the log kept
/// writing under it, so an honest log turned DIVERGED (`ttl_ms = 0`:
/// on the very first append).
#[test]
fn expired_ttl_session_rotates_instead_of_diverging() {
    let mut log = WitnessLog::resume_with_ttl(IdentityKeypair::generate(), 1, 0);
    std::thread::sleep(std::time::Duration::from_millis(3));
    log.append_intent(b"a");
    std::thread::sleep(std::time::Duration::from_millis(3));
    log.append_result(b"b");
    assert_eq!(verdict_of(&log), Verdict::Unanchored);
    assert!(log.all_bindings().len() >= 2, "rotation keeps old bindings");

    let mut log = WitnessLog::resume_with_ttl(IdentityKeypair::generate(), 1, 5);
    for _ in 0..4 {
        log.append_intent(b"x");
        std::thread::sleep(std::time::Duration::from_millis(4));
    }
    assert_eq!(verdict_of(&log), Verdict::Unanchored);
}
