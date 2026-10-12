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
/// `{"expected_identity_pubkey": "<hex>", "threshold": 0.66, "min_receipts": 2}`.
/// Every field is optional.
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
}

/// Exit code the CLI would return for this verdict (0/10/20/30).
pub fn exit_code(verdict: &Verdict) -> u8 {
    match verdict {
        Verdict::Witnessed => 0,
        Verdict::ConsistentUnwitnessed => 10,
        Verdict::Unanchored => 20,
        Verdict::Diverged => 30,
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
/// `{"witnesses": [...]}` or a bare array of entries.
pub fn parse_directory(raw: &str) -> Result<WitnessDirectory, String> {
    match serde_json::from_str::<WitnessDirectory>(raw) {
        Ok(d) => Ok(d),
        Err(as_object) => {
            match serde_json::from_str::<Vec<witness_log_network::WitnessEntry>>(raw) {
                Ok(witnesses) => Ok(WitnessDirectory { witnesses }),
                Err(_) => Err(format!(
                    "directory: {as_object} (expected {{\"witnesses\": [...]}} or a bare array of entries)"
                )),
            }
        }
    }
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
    let dossier: Dossier =
        serde_json::from_str(dossier_json).map_err(|e| format!("not a dossier: {e}"))?;
    let trusted = match directory_json {
        Some(raw) => Some(parse_directory(raw)?),
        None => None,
    };
    let ctx = VerifyContext {
        expected_identity_pubkey: options.expected_identity_pubkey.as_deref(),
        trusted_directory: trusted.as_ref(),
        min_receipts: options.min_receipts,
        revocations: &[],
    };
    let threshold = options.threshold.unwrap_or(DEFAULT_QUORUM_THRESHOLD);
    let report: DossierReport = dossier.verify(threshold, &ctx);
    let report_value = serde_json::to_value(&report).map_err(|e| e.to_string())?;
    Ok(json!({
        "verdict": report.verdict.to_string(),
        "exit_code": exit_code(&report.verdict),
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

/// Cross-log binding of two different agents' dossiers, matching exactly
/// what `witness-log bind` does: each Sent handoff against the Received
/// handoffs naming it (both directions), each AuthorizationEvent of A
/// naming B against those of B naming A. Returns `{a, b, bound, failed,
/// exit}` with the CLI's exit codes (0 bound, 30 mismatch, 10 nothing).
pub fn bind_value(a_json: &str, b_json: &str) -> Result<Value, String> {
    let a: Dossier = serde_json::from_str(a_json).map_err(|e| format!("a: not a dossier: {e}"))?;
    let b: Dossier = serde_json::from_str(b_json).map_err(|e| format!("b: not a dossier: {e}"))?;
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
        for s in &sent {
            let hit = recv
                .iter()
                .find(|r| verify_handoff_binding(sender_id, s, receiver_id, r).is_ok());
            match hit {
                Some(r) => bound.push(json!({
                    "kind": "handoff", "sender": sender_id, "sender_leaf": s.index,
                    "receiver": receiver_id, "receiver_leaf": r.index,
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
                    failed.push(json!({
                        "kind": "handoff", "sender": sender_id, "sender_leaf": s.index,
                        "receiver": receiver_id,
                        "reason": if reasons.is_empty() {
                            "receiver logged no HandoffAttestation naming this sender".to_string()
                        } else { reasons.join("; ") },
                    }));
                }
            }
        }
    }

    let t = LeafType::AuthorizationEvent.tag();
    let auth_a = names_other(&a.leaves, ib, t);
    let auth_b = names_other(&b.leaves, ia, t);
    for la in &auth_a {
        match auth_b
            .iter()
            .find(|lb| verify_authorization_binding(ia, la, ib, lb).is_ok())
        {
            Some(lb) => bound.push(json!({
                "kind": "authorization", "a": ia, "a_leaf": la.index,
                "a_event": event_name(la.authorization_event_kind),
                "b": ib, "b_leaf": lb.index, "b_event": event_name(lb.authorization_event_kind),
                "scope_hash": la.authorization_scope_hash,
            })),
            None => failed.push(json!({
                "kind": "authorization", "a": ia, "a_leaf": la.index, "b": ib,
                "reason": if auth_b.is_empty() {
                    "the other log has no AuthorizationEvent naming this agent".to_string()
                } else {
                    auth_b.iter().map(|lb| format!(
                        "b leaf {}: {}", lb.index,
                        verify_authorization_binding(ia, la, ib, lb).err().unwrap_or_default()
                    )).collect::<Vec<_>>().join("; ")
                },
            })),
        }
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
    let options: VerifyOptions = serde_json::from_str(options_json)
        .map_err(|e| JsValue::from_str(&format!("options: {e}")))?;
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
