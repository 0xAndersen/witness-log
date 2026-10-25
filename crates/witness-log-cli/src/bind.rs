//! `witness-log bind <a.json> <b.json>`: cross-log binding of handoff
//! attestations (SPEC §3.1) and authorization events (§3.2) between two
//! dossiers, from the command line. Each side committed independently
//! in its own log; this is the after-the-fact match that proves both
//! parties committed to the same content (or scope) changing hands
//! between the same two identities.
//!
//! Exit 0 when at least one pair binds and no candidate pair fails; 30
//! when a candidate pair exists but fails to bind (the two sides disagree
//! on what was handed over, or on who the other party was); 10 when
//! neither dossier carries a cross-log leaf naming the other; 2 for
//! unreadable input. The verdict of each dossier on its own is `verify`'s
//! job; run that first.

use std::process::ExitCode;
use witness_log_core::leaf::{
    verify_authorization_binding, verify_handoff_binding, AuthorizationEventKind, HandoffDirection,
    Leaf, LeafType,
};
use witness_log_network::Dossier;

use crate::exit;

fn load(path: &str) -> Result<Dossier, String> {
    let text = crate::read_input(path).map_err(|e| format!("{path}: {e}"))?;
    Dossier::from_json(&text).map_err(|e| format!("{path}: not a dossier: {e}"))
}

/// The same snake_case names the Python and MCP surfaces accept
/// (`granted_by_me`, ...), never Rust's Debug form (`Some(GrantedByMe)`).
fn event_name(kind: Option<AuthorizationEventKind>) -> &'static str {
    use AuthorizationEventKind as K;
    match kind {
        Some(K::GrantedByMe) => "granted_by_me",
        Some(K::GrantedToMe) => "granted_to_me",
        Some(K::RevokedByMe) => "revoked_by_me",
        Some(K::RevokedToMe) => "revoked_to_me",
        Some(K::ScopeChangedByMe) => "scope_changed_by_me",
        Some(K::ScopeChangedToMe) => "scope_changed_to_me",
        None => "unknown",
    }
}

fn names_other<'a>(leaves: &'a [Leaf], other_identity: &str, tag: u8) -> Vec<&'a Leaf> {
    leaves
        .iter()
        .filter(|l| l.leaf_type == tag)
        .filter(|l| l.counterparty_pubkey.as_deref() == Some(other_identity))
        .collect()
}

pub fn run_bind(path_a: &str, path_b: &str, json: bool) -> ExitCode {
    let (a, b) = match (load(path_a), load(path_b)) {
        (Ok(a), Ok(b)) => (a, b),
        (Err(e), _) | (_, Err(e)) => {
            eprintln!("{e}");
            return ExitCode::from(exit::USAGE);
        }
    };
    let (ia, ib) = (a.identity_pubkey.as_str(), b.identity_pubkey.as_str());
    // What the output names an identity by: each dossier's claim, cut when
    // it is longer than a key (`reported_identity`).
    let (ra, rb) = (crate::reported_identity(ia), crate::reported_identity(ib));
    if ia == ib {
        eprintln!("both dossiers claim the same identity {ra}; `bind` is for two different agents (use `diff` for two copies of one log)");
        return ExitCode::from(exit::USAGE);
    }

    let mut bound: Vec<serde_json::Value> = Vec::new();
    let mut failed: Vec<serde_json::Value> = Vec::new();

    // Handoffs: A→B (A Sent, B Received) and B→A.
    let h = LeafType::HandoffAttestation.tag();
    for (sender, sender_id, sender_name, receiver, receiver_id, receiver_name) in
        [(&a, ia, &ra, &b, ib, &rb), (&b, ib, &rb, &a, ia, &ra)]
    {
        let sent: Vec<&Leaf> = names_other(&sender.leaves, receiver_id, h)
            .into_iter()
            .filter(|l| l.handoff_direction == Some(HandoffDirection::Sent))
            .collect();
        let recv: Vec<&Leaf> = names_other(&receiver.leaves, sender_id, h)
            .into_iter()
            .filter(|l| l.handoff_direction == Some(HandoffDirection::Received))
            .collect();
        for s in &sent {
            // A Sent leaf binds to the first Received leaf with the same
            // state hash; if none matches, every candidate is a failure
            // worth reporting (the receiver logged *something* from this
            // sender, but not these bytes).
            let hit = recv
                .iter()
                .find(|r| verify_handoff_binding(sender_id, s, receiver_id, r).is_ok());
            match hit {
                Some(r) => bound.push(serde_json::json!({
                    "kind": "handoff", "sender": sender_name, "sender_leaf": s.index,
                    "receiver": receiver_name, "receiver_leaf": r.index,
                    "state_hash": s.handoff_state_hash,
                })),
                None => {
                    let reasons: Vec<String> = recv
                        .iter()
                        .map(|r| {
                            format!(
                                "receiver leaf {}: {}",
                                r.index,
                                verify_handoff_binding(sender_id, s, receiver_id, r)
                                    .err()
                                    .unwrap_or_default()
                            )
                        })
                        .collect();
                    failed.push(serde_json::json!({
                        "kind": "handoff", "sender": sender_name, "sender_leaf": s.index,
                        "receiver": receiver_name,
                        "reason": if reasons.is_empty() { "receiver logged no HandoffAttestation naming this sender".to_string() } else { reasons.join("; ") },
                    }));
                }
            }
        }
    }

    // Authorization events: any A leaf naming B against any B leaf naming A.
    let t = LeafType::AuthorizationEvent.tag();
    let auth_a = names_other(&a.leaves, ib, t);
    let auth_b = names_other(&b.leaves, ia, t);
    for la in &auth_a {
        match auth_b
            .iter()
            .find(|lb| verify_authorization_binding(ia, la, ib, lb).is_ok())
        {
            Some(lb) => bound.push(serde_json::json!({
                "kind": "authorization", "a": ra, "a_leaf": la.index, "a_event": event_name(la.authorization_event_kind),
                "b": rb, "b_leaf": lb.index, "b_event": event_name(lb.authorization_event_kind),
                "scope_hash": la.authorization_scope_hash,
            })),
            None => failed.push(serde_json::json!({
                "kind": "authorization", "a": ra, "a_leaf": la.index, "b": rb,
                "reason": if auth_b.is_empty() { "the other log has no AuthorizationEvent naming this agent".to_string() }
                          else { auth_b.iter().map(|lb| format!("b leaf {}: {}", lb.index, verify_authorization_binding(ia, la, ib, lb).err().unwrap_or_default())).collect::<Vec<_>>().join("; ") },
            })),
        }
    }

    let code = if !failed.is_empty() {
        exit::DIVERGED
    } else if bound.is_empty() {
        exit::CONSISTENT_UNWITNESSED
    } else {
        0
    };
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "a": {"path": path_a, "identity": ra}, "b": {"path": path_b, "identity": rb},
                "bound": bound, "failed": failed, "exit": code,
            }))
            .unwrap_or_default()
        );
    } else {
        println!("witness-log bind\n  A: {ra}\n  B: {rb}\n");
        for v in &bound {
            match v["kind"].as_str() {
                Some("handoff") => println!(
                    "\u{2713} handoff bound: {}#{} → {}#{}  state {}",
                    crate::short(v["sender"].as_str().unwrap_or("")),
                    v["sender_leaf"],
                    crate::short(v["receiver"].as_str().unwrap_or("")),
                    v["receiver_leaf"],
                    crate::short(v["state_hash"].as_str().unwrap_or(""))
                ),
                _ => println!(
                    "\u{2713} authorization bound: {}#{} {} ↔ {}#{} {}  scope {}",
                    crate::short(v["a"].as_str().unwrap_or("")),
                    v["a_leaf"],
                    v["a_event"].as_str().unwrap_or(""),
                    crate::short(v["b"].as_str().unwrap_or("")),
                    v["b_leaf"],
                    v["b_event"].as_str().unwrap_or(""),
                    crate::short(v["scope_hash"].as_str().unwrap_or(""))
                ),
            }
        }
        for v in &failed {
            println!(
                "\u{2717} {} NOT bound (leaf {}): {}",
                v["kind"].as_str().unwrap_or(""),
                v.get("sender_leaf")
                    .or(v.get("a_leaf"))
                    .cloned()
                    .unwrap_or_default(),
                v["reason"].as_str().unwrap_or("")
            );
        }
        println!();
        match code {
            0 => println!("Result: BOUND — both parties committed, in their own logs, to the same content between the same two identities ({} binding(s)).", bound.len()),
            exit::DIVERGED => println!("Result: MISMATCH — the two logs disagree about what was handed over or to whom. Neither copy is 'the wrong one'; the disagreement is the finding."),
            _ => println!("Result: NO CROSS-LOG LEAVES — neither dossier carries a HandoffAttestation or AuthorizationEvent naming the other identity."),
        }
        println!("\nThis checks the two logs against each other only. Run `witness-log verify` on each dossier first; a binding between two unverified logs proves nothing.");
    }
    ExitCode::from(code)
}
