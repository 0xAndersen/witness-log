//! WebAssembly bindings for witness-log dossier verification.
//!
//! This crate is a thin layer over `witness-log-network::Dossier::verify`
//! (the single canonical verifier) and `witness-log-core`'s leaf, binding
//! and redaction primitives, shaped for a browser: strings and plain JSON
//! in, a JSON report out, no I/O, no network, no clock. The static page in
//! `web/` loads the `wasm-bindgen` output from `web/pkg/` and calls three
//! functions:
//!
//! - [`verify_dossier`] / [`verify_dossier_with_options`]: verdict + the
//!   same report `witness-log verify --json` prints, plus a display
//!   summary (leaf table, checkpoint, receipt-by-receipt status).
//! - [`verify_disclosure`]: SPEC.md §8, does a payload and salt reproduce a
//!   leaf's `payload_hash`.
//! - [`bind`]: SPEC.md §3.1–§3.2 cross-log binding of two dossiers, the
//!   same matching `witness-log bind` performs.
//!
//! Every JS-facing function has a pure-Rust twin returning
//! `serde_json::Value` (`verify_dossier_value`, `verify_disclosure_value`,
//! `bind_value`), which is what the host-side tests and the corpus
//! conformance tests exercise. The wasm functions only convert.
//!
//! The verdict semantics are the reference implementation's, unchanged:
//! `WITNESSED` needs a trusted directory the *caller* supplies, never the
//! dossier's own `witness_directory` (SPEC.md §9.1).

#![cfg_attr(not(test), deny(clippy::unwrap_used))]
#![cfg_attr(not(test), deny(clippy::expect_used))]
#![cfg_attr(not(test), deny(clippy::panic))]
#![cfg_attr(not(test), deny(clippy::indexing_slicing))]

use serde::Deserialize;
use serde_json::value::RawValue;
use serde_json::{json, Value};
use wasm_bindgen::prelude::*;
use witness_log_core::leaf::{
    verify_authorization_binding, verify_handoff_binding, AuthorizationEventKind, HandoffDirection,
    Leaf, LeafType,
};
use witness_log_core::redaction::payload_hash_with_salt;
use witness_log_network::{Dossier, DossierReport, Verdict, VerifyContext, WitnessDirectory};

/// Default quorum threshold, the same as `witness-log verify`.
pub const DEFAULT_QUORUM_THRESHOLD: f64 = 0.66;

/// Caller-controlled verification inputs (SPEC.md §9.1), as JSON:
/// `{"expected_identity_pubkey": "<hex>", "threshold": 0.66, "min_receipts": 2,
///   "allow_sub_majority": false, "revocations": [...],
///   "known_heads": ["<size>:<root hex>"], "evidence": [{...}]}`.
/// Every field is optional. `revocations` and each evidence item are kept
/// as their JSON text and read as the CLI reads its `--revocations` and
/// `--evidence` files, SPEC.md §9's nesting limit included, counted from
/// the input itself.
#[derive(Debug, Default, Deserialize)]
pub struct VerifyOptions {
    /// The identity the caller expects, obtained out-of-band.
    #[serde(default)]
    pub expected_identity_pubkey: Option<String>,
    /// Quorum gate as a fraction of the trusted directory.
    #[serde(default)]
    pub threshold: Option<f64>,
    /// Absolute receipt-count gate; overrides the fraction when set.
    #[serde(default)]
    pub min_receipts: Option<usize>,
    /// Accept WITNESSED from fewer than a strict majority of the directory
    /// as exit 0 (the CLI's `--allow-sub-majority`). Default false: such a
    /// verdict's `exit_code` is 11, as `witness-log verify` returns.
    #[serde(default)]
    pub allow_sub_majority: bool,
    /// Revocation statements the caller knows of out of band (SPEC.md §5),
    /// one or a JSON array of them (`witness_log_network::revocations_from_json`);
    /// applied even when the dossier omits them.
    #[serde(default)]
    pub revocations: Option<Box<RawValue>>,
    /// Heads the caller already trusts for this identity, as
    /// `"<size>:<root hex>"`; one the dossier does not reproduce makes the
    /// verdict DIVERGED (RFC-0002).
    #[serde(default)]
    pub known_heads: Vec<String>,
    /// Witness equivocation proofs, bare or as `witness serve` writes them
    /// (`{"kind": "equivocation", "proof": {...}}`); one that verifies for
    /// this identity makes the verdict DIVERGED. Each is read as an
    /// evidence file (`EquivocationProof::from_evidence_json`).
    #[serde(default)]
    pub evidence: Vec<Box<RawValue>>,
    /// The organisation that operates this log; witnesses with that
    /// `operator_org` never count as independent operators.
    #[serde(default)]
    pub subject_org: Option<String>,
    /// RFC-0001, EXPERIMENTAL: count the cosigners of a fleet checkpoint
    /// that includes this dossier's checkpoint (`verify
    /// --accept-fleet-anchor`; needs `subject_org`). Default false.
    #[serde(default)]
    pub accept_fleet_anchor: bool,
}

impl VerifyOptions {
    /// The options JSON as [`verify_dossier_with_options`] reads it: a JSON
    /// object, never an array of the field values, whose keys serde matches
    /// exactly and at most once (other keys are ignored), with `null` only
    /// for the optional fields; the whole text nested at most two levels
    /// above `MAX_DOSSIER_DEPTH` (the options object and the evidence list
    /// around an evidence item), each input in it then keeping its own
    /// limit. Go's wasm build reads its options the same way.
    pub fn from_json(text: &str) -> Result<Self, String> {
        witness_log_network::check_json_depth_within(
            text,
            witness_log_network::MAX_DOSSIER_DEPTH + 2,
        )
        .map_err(|e| format!("options: {e}"))?;
        if !text.trim_start().starts_with('{') {
            return Err("options: expected a JSON object".to_string());
        }
        serde_json::from_str(text).map_err(|e| {
            format!(
                "options: {}",
                witness_log_core::echo::bounded(&e.to_string())
            )
        })
    }
}

/// Exit code `witness-log verify` (strict, the default) returns for this
/// report: the verdict's code, or 11 for a WITNESSED verdict whose
/// cosigners are not a strict majority of the directory.
pub fn report_exit_code(report: &DossierReport, allow_sub_majority: bool) -> u8 {
    if report.split_view_unsafe && !allow_sub_majority {
        return 11;
    }
    exit_code(&report.verdict)
}

/// Exit code for a verdict on its own (0/10/20/30/40).
pub fn exit_code(verdict: &Verdict) -> u8 {
    match verdict {
        Verdict::Witnessed => 0,
        Verdict::ConsistentUnwitnessed => 10,
        Verdict::Unanchored => 20,
        Verdict::Diverged => 30,
        Verdict::Invalid => 40,
    }
}

fn leaf_type_name(tag: u8) -> &'static str {
    match LeafType::from_tag(tag) {
        Some(LeafType::PassiveMemory) => "PassiveMemory",
        Some(LeafType::ActiveIntent) => "ActiveIntent",
        Some(LeafType::ActiveResult) => "ActiveResult",
        Some(LeafType::Redaction) => "Redaction",
        Some(LeafType::KeyRevocation) => "KeyRevocation",
        Some(LeafType::HandoffAttestation) => "HandoffAttestation",
        Some(LeafType::AuthorizationEvent) => "AuthorizationEvent",
        Some(LeafType::ExternalAnchor) => "ExternalAnchor",
        None => "unrecognized",
    }
}

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

/// Parse a directory the way `witness-log verify --directory` does:
/// `{"witnesses": [...]}` or a bare array of entries, nested at most 1000
/// deep (`WitnessDirectory::from_json`).
pub fn parse_directory(raw: &str) -> Result<WitnessDirectory, String> {
    WitnessDirectory::from_json(raw).map_err(|e| match e {
        witness_log_network::InputParseError::Json(_) => {
            format!("directory: {e} (expected {{\"witnesses\": [...]}} or a bare array of entries)")
        }
        other => format!("directory: {other}"),
    })
}

/// Per-leaf display rows for the browser's leaf table. Structural
/// validity is reported per leaf so a DIVERGED dossier points at the
/// offending row.
fn leaf_rows(leaves: &[Leaf]) -> Vec<Value> {
    leaves
        .iter()
        .enumerate()
        .map(|(i, l)| {
            let structural = l.validate(i as u64).map_err(|e| e.to_string());
            json!({
                "index": l.index,
                "leaf_type": l.leaf_type,
                "leaf_type_name": leaf_type_name(l.leaf_type),
                "timestamp_ms": l.timestamp_ms,
                "session_pubkey": l.session_pubkey,
                "payload_hash": l.payload_hash,
                "leaf_hash": hex::encode(witness_log_core::merkle::leaf_hash(&l.canonical_bytes())),
                "redacted_index": l.redacted_index,
                "revoked_identity": l.revoked_identity,
                "handoff_direction": l.handoff_direction.map(|d| match d {
                    HandoffDirection::Sent => "Sent",
                    HandoffDirection::Received => "Received",
                }),
                "counterparty_pubkey": l.counterparty_pubkey,
                "handoff_state_hash": l.handoff_state_hash,
                "authorization_event_kind": l.authorization_event_kind.map(|k| event_name(Some(k))),
                "authorization_scope_hash": l.authorization_scope_hash,
                "anchor_url": l.anchor_url,
                "anchor_proof_hash": l.anchor_proof_hash,
                "has_anchor_proof_json": l.anchor_proof_json.is_some(),
                "structurally_valid": structural.is_ok(),
                "structural_error": structural.err(),
            })
        })
        .collect()
}

/// Per-receipt display rows: does the signature verify against the
/// checkpoint, is the witness in the caller's directory (and under which
/// operator), is it a native receipt or a C2SP cosignature.
fn receipt_rows(dossier: &Dossier, trusted: Option<&WitnessDirectory>) -> Vec<Value> {
    dossier
        .witness_receipts
        .iter()
        .map(|r| {
            let valid = r.verify(&dossier.checkpoint).map_err(|e| e.to_string());
            let key = r.witness_pubkey.to_ascii_lowercase();
            let entry = trusted.and_then(|d| {
                d.witnesses
                    .iter()
                    .find(|w| w.pubkey.to_ascii_lowercase() == key)
            });
            let claimed = dossier
                .witness_directory
                .witnesses
                .iter()
                .find(|w| w.pubkey.to_ascii_lowercase() == key);
            json!({
                "witness_pubkey": r.witness_pubkey,
                "tree_size": r.tree_size,
                "root_hash": r.root_hash,
                "witnessed_at_ms": r.witnessed_at_ms,
                "kind": if r.c2sp_origin.is_some() { "c2sp-cosignature" } else { "native" },
                "c2sp_origin": r.c2sp_origin,
                "signature_valid": valid.is_ok(),
                "signature_error": valid.err(),
                "in_trusted_directory": entry.is_some(),
                "trusted_operator_org": entry.map(|e| e.operator_org.clone()),
                "trusted_is_project_operated": entry.map(|e| e.is_project_operated),
                "trusted_name": entry.map(|e| e.name.clone()),
                "claimed_name": claimed.map(|e| e.name.clone()),
                "claimed_operator_org": claimed.map(|e| e.operator_org.clone()),
            })
        })
        .collect()
}

fn binding_rows(dossier: &Dossier) -> Vec<Value> {
    dossier
        .key_bindings
        .iter()
        .map(|b| {
            json!({
                "session_pubkey": b.session_pubkey,
                "session_number": b.session_number,
                "timestamp_ms": b.timestamp_ms,
                "not_after_ms": b.not_after_ms,
                "custody": b.custody,
                "signature_valid": b.verify().is_ok(),
                "names_this_identity": b.identity_pubkey.eq_ignore_ascii_case(&dossier.identity_pubkey),
            })
        })
        .collect()
}

/// Verify a dossier. `directory_json` is the directory the CALLER trusts
/// (`None` caps the verdict at UNANCHORED). Returns
/// `{verdict, exit_code, report, summary}` where `report` is byte-for-byte
/// the `DossierReport` of `witness-log verify --json`.
pub fn verify_dossier_value(
    dossier_json: &str,
    directory_json: Option<&str>,
    options: &VerifyOptions,
) -> Result<Value, String> {
    let dossier = Dossier::from_json(dossier_json).map_err(|e| format!("not a dossier: {e}"))?;
    let trusted = match directory_json {
        Some(raw) => Some(parse_directory(raw)?),
        None => None,
    };
    let known_heads = options
        .known_heads
        .iter()
        .map(|h| {
            h.parse::<witness_log_network::KnownHead>()
                .map_err(|e| format!("known head {h:?}: {e}"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let revocations = match &options.revocations {
        Some(raw) => witness_log_network::revocations_from_json(raw.get())
            .map_err(|e| format!("revocations: {e}"))?,
        None => Vec::new(),
    };
    let evidence = options
        .evidence
        .iter()
        .map(|raw| {
            witness_log_network::tlog_witness::EquivocationProof::from_evidence_json(raw.get())
                .map_err(|e| e.to_string())
        })
        .collect::<Result<Vec<_>, _>>()?;
    let ctx = VerifyContext {
        expected_identity_pubkey: options.expected_identity_pubkey.as_deref(),
        trusted_directory: trusted.as_ref(),
        min_receipts: options.min_receipts,
        revocations: &revocations,
        known_heads: &known_heads,
        evidence: &evidence,
        subject_org: options.subject_org.as_deref(),
        accept_fleet_anchor: options.accept_fleet_anchor,
    };
    let threshold = options.threshold.unwrap_or(DEFAULT_QUORUM_THRESHOLD);
    let report: DossierReport = dossier.verify(threshold, &ctx);
    let report_value = serde_json::to_value(&report).map_err(|e| e.to_string())?;
    Ok(json!({
        "verdict": report.verdict.to_string(),
        "exit_code": report_exit_code(&report, options.allow_sub_majority),
        "threshold_used": threshold,
        "min_receipts_used": options.min_receipts,
        "identity_pinned": options.expected_identity_pubkey.is_some(),
        "directory_pinned": trusted.is_some(),
        "report": report_value,
        "summary": {
            "identity_pubkey": dossier.identity_pubkey,
            "checkpoint": dossier.checkpoint,
            "canonical_origin": hex::decode(&dossier.checkpoint.signer_pubkey)
                .ok()
                .and_then(|b| <[u8; 32]>::try_from(b).ok())
                .and_then(|b| ed25519_dalek::VerifyingKey::from_bytes(&b).ok())
                .map(|k| witness_log_core::c2sp::canonical_origin(&k)),
            "leaves": leaf_rows(&dossier.leaves),
            "receipts": receipt_rows(&dossier, trusted.as_ref()),
            "key_bindings": binding_rows(&dossier),
            "revocations": dossier.revocations.len(),
            "claimed_directory_size": dossier.witness_directory.witnesses.len(),
        }
    }))
}

/// SPEC.md §8: does `payload` under `salt` reproduce `leaf.payload_hash`
/// at the leaf's own index. Returns `{matches, leaf_index, committed,
/// recomputed}`.
pub fn verify_disclosure_value(
    leaf_json: &str,
    payload: &[u8],
    salt_hex: &str,
) -> Result<Value, String> {
    let leaf: Leaf = serde_json::from_str(leaf_json).map_err(|e| format!("not a leaf: {e}"))?;
    let salt: [u8; 32] = hex::decode(salt_hex)
        .map_err(|_| "salt must be hex".to_string())?
        .try_into()
        .map_err(|_| "salt must be 32 bytes".to_string())?;
    let recomputed = hex::encode(payload_hash_with_salt(payload, &salt, leaf.index));
    Ok(json!({
        "matches": recomputed == leaf.payload_hash,
        "leaf_index": leaf.index,
        "committed": leaf.payload_hash,
        "recomputed": recomputed,
    }))
}

fn names_other<'a>(leaves: &'a [Leaf], other: &str, tag: u8) -> Vec<&'a Leaf> {
    leaves
        .iter()
        .filter(|l| l.leaf_type == tag && l.counterparty_pubkey.as_deref() == Some(other))
        .collect()
}

type Check<'c> = dyn Fn(&Leaf, &Leaf) -> Result<(), String> + 'c;

/// A one-to-one matching of two leaf lists (each in index order): each
/// left leaf binds the first right leaf `check` accepts that no earlier
/// left leaf took. Same rule as `witness-log bind`: a leaf binds at most
/// once, and what is bound or left over does not depend on which side is
/// left.
/// (Written without indexing: this crate denies `clippy::indexing_slicing`.)
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
    /// bound to nothing: one clause per leaf on the other side, in the
    /// CLI's wording.
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

/// Cross-log binding of two different agents' dossiers, matching exactly
/// what `witness-log bind` does, one to one: Sent handoffs against the
/// Received handoffs naming them (both directions), AuthorizationEvents of
/// A naming B against those of B naming A. Every such leaf on either side
/// that binds to nothing is in `failed`. Returns `{a, b, bound, failed,
/// exit}` with the CLI's exit codes (0 bound, 30 mismatch, 10 nothing).
pub fn bind_value(a_json: &str, b_json: &str) -> Result<Value, String> {
    let a = Dossier::from_json(a_json).map_err(|e| format!("a: not a dossier: {e}"))?;
    let b = Dossier::from_json(b_json).map_err(|e| format!("b: not a dossier: {e}"))?;
    let (ia, ib) = (a.identity_pubkey.as_str(), b.identity_pubkey.as_str());
    if ia == ib {
        return Err(format!(
            "both dossiers claim the same identity {ia}; bind is for two different agents"
        ));
    }
    let mut bound = Vec::new();
    let mut failed = Vec::new();

    let h = LeafType::HandoffAttestation.tag();
    for (sender, sender_id, receiver, receiver_id) in [(&a, ia, &b, ib), (&b, ib, &a, ia)] {
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
            bound.push(json!({
                "kind": "handoff", "sender": sender_id, "sender_leaf": s.index,
                "receiver": receiver_id, "receiver_leaf": r.index,
                "state_hash": s.handoff_state_hash,
            }));
        }
        let names = ("sender", "receiver");
        for s in unbound(&sent, &m.left_partner) {
            failed.push(json!({
                "kind": "handoff", "sender": sender_id, "sender_leaf": s.index,
                "receiver": receiver_id,
                "reason": m.why(s, false, &sent, &recv, &check, names,
                    "receiver logged no HandoffAttestation naming this sender"),
            }));
        }
        for r in unbound(&recv, &m.right_partner) {
            failed.push(json!({
                "kind": "handoff", "sender": sender_id, "receiver": receiver_id,
                "receiver_leaf": r.index,
                "reason": m.why(r, true, &sent, &recv, &check, names,
                    "sender logged no HandoffAttestation (Sent) naming this receiver"),
            }));
        }
    }

    let t = LeafType::AuthorizationEvent.tag();
    let auth_a = names_other(&a.leaves, ib, t);
    let auth_b = names_other(&b.leaves, ia, t);
    let check = |la: &Leaf, lb: &Leaf| verify_authorization_binding(ia, la, ib, lb);
    let m = match_one_to_one(&auth_a, &auth_b, &check);
    for (la, lb) in m.pairs(&auth_a, &auth_b) {
        bound.push(json!({
            "kind": "authorization", "a": ia, "a_leaf": la.index,
            "a_event": event_name(la.authorization_event_kind),
            "b": ib, "b_leaf": lb.index, "b_event": event_name(lb.authorization_event_kind),
            "scope_hash": la.authorization_scope_hash,
        }));
    }
    const NO_AUTH: &str = "the other log has no AuthorizationEvent naming this agent";
    for la in unbound(&auth_a, &m.left_partner) {
        failed.push(json!({
            "kind": "authorization", "a": ia, "a_leaf": la.index, "b": ib,
            "reason": m.why(la, false, &auth_a, &auth_b, &check, ("a", "b"), NO_AUTH),
        }));
    }
    for lb in unbound(&auth_b, &m.right_partner) {
        failed.push(json!({
            "kind": "authorization", "a": ia, "b": ib, "b_leaf": lb.index,
            "reason": m.why(lb, true, &auth_a, &auth_b, &check, ("a", "b"), NO_AUTH),
        }));
    }

    let exit = if !failed.is_empty() {
        30
    } else if bound.is_empty() {
        10
    } else {
        0
    };
    Ok(json!({
        "a": {"identity": ia}, "b": {"identity": ib},
        "bound": bound, "failed": failed, "exit": exit,
    }))
}

fn to_js(v: Value) -> Result<JsValue, JsValue> {
    // json_compatible(): objects become plain JS objects, not `Map`s, so
    // the page reads `result.verdict` the same way for both engines.
    use serde::Serialize;
    v.serialize(&serde_wasm_bindgen::Serializer::json_compatible())
        .map_err(|e| JsValue::from_str(&e.to_string()))
}

/// Verify a dossier in the browser. `directory_json` is the directory the
/// caller trusts; omit it and the verdict is capped at UNANCHORED.
/// Resolves to `{verdict, exit_code, report, summary}`; rejects with a
/// string when the input is not a dossier or directory.
#[wasm_bindgen]
pub fn verify_dossier(json: &str, directory_json: Option<String>) -> Result<JsValue, JsValue> {
    verify_dossier_value(json, directory_json.as_deref(), &VerifyOptions::default())
        .map_err(|e| JsValue::from_str(&e))
        .and_then(to_js)
}

/// [`verify_dossier`] with caller options as JSON:
/// `{"expected_identity_pubkey": "<hex>", "threshold": 0.66, "min_receipts": 2}`.
#[wasm_bindgen]
pub fn verify_dossier_with_options(
    json: &str,
    directory_json: Option<String>,
    options_json: &str,
) -> Result<JsValue, JsValue> {
    let options = VerifyOptions::from_json(options_json).map_err(|e| JsValue::from_str(&e))?;
    verify_dossier_value(json, directory_json.as_deref(), &options)
        .map_err(|e| JsValue::from_str(&e))
        .and_then(to_js)
}

/// SPEC.md §8 selective disclosure check. `leaf_json` is one leaf object
/// from a verified dossier; `payload` the raw bytes the operator discloses;
/// `salt_hex` the 32-byte per-leaf salt. Resolves to `{matches, leaf_index,
/// committed, recomputed}`.
#[wasm_bindgen]
pub fn verify_disclosure(
    leaf_json: &str,
    payload: &[u8],
    salt_hex: &str,
) -> Result<JsValue, JsValue> {
    verify_disclosure_value(leaf_json, payload, salt_hex)
        .map_err(|e| JsValue::from_str(&e))
        .and_then(to_js)
}

/// Cross-log binding of two dossiers (SPEC.md §3.1–§3.2), as `witness-log
/// bind`. Resolves to `{a, b, bound, failed, exit}`.
#[wasm_bindgen]
pub fn bind(a_json: &str, b_json: &str) -> Result<JsValue, JsValue> {
    bind_value(a_json, b_json)
        .map_err(|e| JsValue::from_str(&e))
        .and_then(to_js)
}

/// The crate version, for the page footer.
#[wasm_bindgen]
pub fn version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}
