//! `witness-log bind <a.json> <b.json>`: cross-log binding of handoff
//! attestations (SPEC §3.1) and authorization events (§3.2) between two
//! dossiers, from the command line. Each side committed independently
//! in its own log; this is the after-the-fact match that proves both
//! parties committed to the same content (or scope) changing hands
//! between the same two identities.
//!
//! Leaves are matched one to one: a leaf binds at most one leaf on the
//! other side, so every HandoffAttestation and AuthorizationEvent naming
//! the other identity is either bound or reported. Exit 0 when at least
//! one pair binds and nothing is left over; 30 when any such leaf, on
//! either side, binds to nothing (the two sides disagree on what was
//! handed over or granted, on who the other party was, or on how many
//! times it happened); 10 when neither dossier carries a cross-log leaf
//! naming the other; 2 for unreadable input. Bound pairs and failures are
//! the same in either argument order. The verdict of each dossier on its
//! own is `verify`'s job; run that first.

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

type Check<'c> = dyn Fn(&Leaf, &Leaf) -> Result<(), String> + 'c;

/// A one-to-one matching of two leaf lists (each in index order): each left
/// leaf binds the first right leaf `check` accepts that no earlier left leaf
/// took. A leaf binds at most once, so an event one side recorded twice and
/// the other once leaves one over. Leaves that can bind each other form
/// groups (same kind pair and hash), and each group pairs its i-th left leaf
/// with its i-th right leaf, so what is bound and what is left over do not
/// depend on which side is left. The wasm crate's `bind_value`, Python's
/// `bind_dossiers` and Go's `Bind` use the same rule.
struct Matching {
    /// For each left leaf, the position of the right leaf it bound to.
    left_partner: Vec<Option<usize>>,
    /// For each right leaf, the position of the left leaf it bound to.
    right_partner: Vec<Option<usize>>,
}

fn match_one_to_one(left: &[&Leaf], right: &[&Leaf], check: &Check) -> Matching {
    let mut right_partner: Vec<Option<usize>> = vec![None; right.len()];
    let mut left_partner = Vec::with_capacity(left.len());
    for (i, l) in left.iter().enumerate() {
        let free = right
            .iter()
            .zip(right_partner.iter_mut())
            .enumerate()
            .find(|(_, (r, p))| p.is_none() && check(l, r).is_ok());
        match free {
            Some((j, (_, p))) => {
                *p = Some(i);
                left_partner.push(Some(j));
            }
            None => left_partner.push(None),
        }
    }
    Matching {
        left_partner,
        right_partner,
    }
}

/// The leaves of `leaves` whose entry in `partners` is `None`.
fn unbound<'a>(leaves: &[&'a Leaf], partners: &[Option<usize>]) -> Vec<&'a Leaf> {
    leaves
        .iter()
        .zip(partners)
        .filter(|(_, p)| p.is_none())
        .map(|(l, _)| *l)
        .collect()
}

impl Matching {
    /// The bound pairs, in left index order.
    fn pairs<'a>(&self, left: &[&'a Leaf], right: &[&'a Leaf]) -> Vec<(&'a Leaf, &'a Leaf)> {
        left.iter()
            .zip(&self.left_partner)
            .filter_map(|(l, p)| p.and_then(|j| right.get(j)).map(|r| (*l, *r)))
            .collect()
    }

    /// Why `leaf` (from the left list, or with `right_side` the right one)
    /// bound to nothing: one clause per leaf on the other side, naming each
    /// side as `names` does ("a"/"b", "sender"/"receiver"), or `none` when
    /// the other side has no candidate at all.
    #[allow(clippy::too_many_arguments)]
    fn why(
        &self,
        leaf: &Leaf,
        right_side: bool,
        left: &[&Leaf],
        right: &[&Leaf],
        check: &Check,
        names: (&str, &str),
        none: &str,
    ) -> String {
        let (others, other_partner, other_name, own_name, own) = if right_side {
            (left, &self.left_partner, names.0, names.1, right)
        } else {
            (right, &self.right_partner, names.1, names.0, left)
        };
        if others.is_empty() {
            return none.to_string();
        }
        others
            .iter()
            .zip(other_partner)
            .map(|(other, partner)| {
                let res = if right_side {
                    check(other, leaf)
                } else {
                    check(leaf, other)
                };
                match (res, partner.and_then(|p| own.get(p))) {
                    (Ok(()), Some(p)) => format!(
                        "{other_name} leaf {}: already bound to {own_name} leaf {}",
                        other.index, p.index
                    ),
                    (Ok(()), None) => format!("{other_name} leaf {}: unbound", other.index),
                    (Err(e), _) => format!("{other_name} leaf {}: {e}", other.index),
                }
            })
            .collect::<Vec<_>>()
            .join("; ")
    }
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

    // Handoffs: A→B (A Sent, B Received) and B→A. A Sent leaf nothing on the
    // receiver's side binds to is a failure, and so is a Received leaf no
    // Sent leaf binds to: the receiver logged bytes the sender never logged
    // sending.
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
        let check = |s: &Leaf, r: &Leaf| verify_handoff_binding(sender_id, s, receiver_id, r);
        let m = match_one_to_one(&sent, &recv, &check);
        for (s, r) in m.pairs(&sent, &recv) {
            bound.push(serde_json::json!({
                "kind": "handoff", "sender": sender_name, "sender_leaf": s.index,
                "receiver": receiver_name, "receiver_leaf": r.index,
                "state_hash": s.handoff_state_hash,
            }));
        }
        let names = ("sender", "receiver");
        for s in unbound(&sent, &m.left_partner) {
            failed.push(serde_json::json!({
                "kind": "handoff", "sender": sender_name, "sender_leaf": s.index,
                "receiver": receiver_name,
                "reason": m.why(s, false, &sent, &recv, &check, names,
                                "receiver logged no HandoffAttestation naming this sender"),
            }));
        }
        for r in unbound(&recv, &m.right_partner) {
            failed.push(serde_json::json!({
                "kind": "handoff", "sender": sender_name, "receiver": receiver_name,
                "receiver_leaf": r.index,
                "reason": m.why(r, true, &sent, &recv, &check, names,
                                "sender logged no HandoffAttestation (Sent) naming this receiver"),
            }));
        }
    }

    // Authorization events: A's leaves naming B against B's naming A, one
    // to one. A leaf either side holds that the other never recorded (a
    // grant, a re-grant, a revocation or a scope change) is a failure.
    let t = LeafType::AuthorizationEvent.tag();
    let auth_a = names_other(&a.leaves, ib, t);
    let auth_b = names_other(&b.leaves, ia, t);
    let check = |la: &Leaf, lb: &Leaf| verify_authorization_binding(ia, la, ib, lb);
    let m = match_one_to_one(&auth_a, &auth_b, &check);
    for (la, lb) in m.pairs(&auth_a, &auth_b) {
        bound.push(serde_json::json!({
            "kind": "authorization", "a": ra, "a_leaf": la.index, "a_event": event_name(la.authorization_event_kind),
            "b": rb, "b_leaf": lb.index, "b_event": event_name(lb.authorization_event_kind),
            "scope_hash": la.authorization_scope_hash,
        }));
    }
    const NO_AUTH: &str = "the other log has no AuthorizationEvent naming this agent";
    for la in unbound(&auth_a, &m.left_partner) {
        failed.push(serde_json::json!({
            "kind": "authorization", "a": ra, "a_leaf": la.index, "b": rb,
            "reason": m.why(la, false, &auth_a, &auth_b, &check, ("a", "b"), NO_AUTH),
        }));
    }
    for lb in unbound(&auth_b, &m.right_partner) {
        failed.push(serde_json::json!({
            "kind": "authorization", "a": ra, "b": rb, "b_leaf": lb.index,
            "reason": m.why(lb, true, &auth_a, &auth_b, &check, ("a", "b"), NO_AUTH),
        }));
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
            // Name the dossier the unmatched leaf is in: A (first argument) or B.
            // The entries carry the reported (possibly cut) identity.
            let side = |id: &serde_json::Value| {
                if id.as_str() == Some(ra.as_str()) {
                    "A"
                } else {
                    "B"
                }
            };
            let leaf = if let Some(i) = v.get("sender_leaf") {
                format!("{} leaf {i}", side(&v["sender"]))
            } else if let Some(i) = v.get("receiver_leaf") {
                format!("{} leaf {i}", side(&v["receiver"]))
            } else if let Some(i) = v.get("a_leaf") {
                format!("A leaf {i}")
            } else if let Some(i) = v.get("b_leaf") {
                format!("B leaf {i}")
            } else {
                "leaf ?".to_string()
            };
            println!(
                "\u{2717} {} NOT bound ({leaf}): {}",
                v["kind"].as_str().unwrap_or(""),
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
