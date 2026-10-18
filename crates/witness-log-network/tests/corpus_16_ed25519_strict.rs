//! Corpus vector 16 (`corpus/16_ed25519_strict.json`): strict Ed25519
//! (SPEC.md §6) at the edges where implementations disagree, for the raw
//! check and inside dossiers. The Go and TypeScript verifiers, the wasm
//! build, Node and Python run the same file (outside review of 0.6.0,
//! H3/M3). `examples/generate_ed25519_corpus.rs` writes it; CI fails if the
//! committed copy drifts from what the generator produces.

use ed25519_dalek::{Signature, VerifyingKey};
use serde_json::{json, Value};
use witness_log_core::sth::SignedTreeHead;
use witness_log_network::tlog_witness::EquivocationProof;
use witness_log_network::{Dossier, Verdict, VerifyContext, WitnessDirectory};

fn corpus() -> Value {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../corpus/16_ed25519_strict.json");
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn bytes<const N: usize>(hex_str: &str) -> [u8; N] {
    hex::decode(hex_str).unwrap().try_into().unwrap()
}

/// The check every signature in a dossier goes through in this crate and
/// in witness-log-core (checkpoints, key bindings, revocations, native and
/// C2SP receipts, signed notes): decode the key, then `verify_strict`.
fn reference_check(public_key: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> bool {
    VerifyingKey::from_bytes(public_key)
        .map(|k| {
            k.verify_strict(message, &Signature::from_bytes(signature))
                .is_ok()
        })
        .unwrap_or(false)
}

#[test]
fn corpus_vector_16_signatures() {
    let v = corpus();
    let sigs = v["signatures"].as_array().unwrap();
    assert!(sigs.len() >= 45);
    let mut small_order_a = 0;
    for s in sigs {
        let name = s["name"].as_str().unwrap();
        let a: [u8; 32] = bytes(s["public_key"].as_str().unwrap());
        let m = hex::decode(s["message"].as_str().unwrap()).unwrap();
        let sig: [u8; 64] = bytes(s["signature"].as_str().unwrap());
        assert_eq!(
            reference_check(&a, &m, &sig),
            s["valid"].as_bool().unwrap(),
            "{name}"
        );
        if name.starts_with("small-order A") {
            small_order_a += 1;
            assert!(
                s["cofactorless_non_strict"].as_bool().unwrap(),
                "{name}: built to pass a non-strict check"
            );
        }
    }
    assert!(small_order_a >= 14, "every small-order encoding as A");
}

/// The checkpoint path itself refuses the degenerate checkpoints, not
/// only the dossier verdict built on it.
#[test]
fn corpus_vector_16_checkpoints_through_signed_tree_head_verify() {
    let v = corpus();
    for (name, ok) in [
        ("honest", true),
        ("identity_point_checkpoint", false),
        ("small_order_key_checkpoint", false),
        ("small_order_r_checkpoint", false),
        ("mixed_order_key_checkpoint", true),
    ] {
        let sth: SignedTreeHead =
            serde_json::from_value(v["dossiers"][name]["checkpoint"].clone()).unwrap();
        assert_eq!(sth.verify().is_ok(), ok, "{name}");
    }
}

#[test]
fn corpus_vector_16_cases() {
    let v = corpus();
    let mut seen = std::collections::BTreeSet::new();
    for c in v["cases"].as_array().unwrap() {
        let name = c["name"].as_str().unwrap();
        let e = &c["expect"];
        seen.insert(e["exit_code"].as_u64().unwrap());
        let evidence: Vec<EquivocationProof> = c["evidence"]
            .as_array()
            .unwrap()
            .iter()
            .map(|k| EquivocationProof::from_evidence(&v["evidence"][k.as_str().unwrap()]).unwrap())
            .collect();
        let directory: Option<WitnessDirectory> = c["directory"]
            .as_str()
            .map(|d| serde_json::from_value(v["directories"][d].clone()).unwrap());
        let dossier: Dossier =
            serde_json::from_value(v["dossiers"][c["dossier"].as_str().unwrap()].clone()).unwrap();
        let ctx = VerifyContext {
            expected_identity_pubkey: c["expected_identity"].as_str(),
            trusted_directory: directory.as_ref(),
            min_receipts: c["min_witnesses"].as_u64().map(|n| n as usize),
            revocations: &[],
            known_heads: &[],
            evidence: &evidence,
            subject_org: c["subject_org"].as_str(),
            accept_fleet_anchor: false,
        };
        let r = dossier.verify(c["threshold"].as_f64().unwrap(), &ctx);
        let exit = if r.split_view_unsafe && !c["allow_sub_majority"].as_bool().unwrap() {
            11
        } else {
            match r.verdict {
                Verdict::Witnessed => 0,
                Verdict::ConsistentUnwitnessed => 10,
                Verdict::Unanchored => 20,
                Verdict::Diverged => 30,
                Verdict::Invalid => 40,
            }
        };
        assert_eq!(
            serde_json::to_value(&r.verdict).unwrap(),
            e["verdict"],
            "{name}"
        );
        assert_eq!(exit, e["exit_code"].as_u64().unwrap(), "{name}");
        assert_eq!(json!(r.split_view_unsafe), e["split_view_unsafe"], "{name}");
        assert_eq!(
            json!(r.internally_consistent),
            e["internally_consistent"],
            "{name}"
        );
        assert_eq!(json!(!r.failures.is_empty()), e["has_failures"], "{name}");
        assert_eq!(json!(r.contradictions.len()), e["contradictions"], "{name}");
        assert_eq!(
            json!(r.quorum.as_ref().map(|q| q.valid_receipts)),
            e["valid_receipts"],
            "{name}"
        );
        assert_eq!(
            json!(r.quorum.as_ref().map(|q| q.distinct_independent_operators)),
            e["independent_operators"],
            "{name}"
        );
    }
    assert_eq!(seen.into_iter().collect::<Vec<_>>(), vec![10, 20, 40]);
}
