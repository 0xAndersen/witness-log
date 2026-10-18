//! Corpus vector 15 (`corpus/15_evidence_and_args.json`): the inputs a
//! verifier brings (evidence items, known heads, directory labels and
//! subject_org) read the same way by the reference as by the Go and
//! TypeScript verifiers, the wasm build, Node and Python, which run the
//! same file (security review of 0.5.0: F1, F5, F10, F12).
//! `examples/generate_evidence_corpus.rs` writes it; CI fails if the
//! committed copy drifts from what the generator produces.

use serde_json::{json, Value};
use witness_log_network::tlog_witness::EquivocationProof;
use witness_log_network::{Dossier, KnownHead, Verdict, VerifyContext, WitnessDirectory};

fn exit_code(verdict: &Verdict, split_view_unsafe: bool, allow_sub_majority: bool) -> u64 {
    if split_view_unsafe && !allow_sub_majority {
        return 11;
    }
    match verdict {
        Verdict::Witnessed => 0,
        Verdict::ConsistentUnwitnessed => 10,
        Verdict::Unanchored => 20,
        Verdict::Diverged => 30,
        Verdict::Invalid => 40,
    }
}

#[test]
fn corpus_vector_15_evidence_and_args() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../corpus/15_evidence_and_args.json");
    let v: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let mut seen = std::collections::BTreeSet::new();
    for c in v["cases"].as_array().unwrap() {
        let name = c["name"].as_str().unwrap();
        let e = &c["expect"];
        let known_heads: Result<Vec<KnownHead>, String> = c["known_heads"]
            .as_array()
            .unwrap()
            .iter()
            .map(|h| h.as_str().unwrap().parse())
            .collect();
        let evidence: Result<Vec<EquivocationProof>, String> = c["evidence"]
            .as_array()
            .unwrap()
            .iter()
            .map(|k| EquivocationProof::from_evidence(&v["evidence"][k.as_str().unwrap()]))
            .collect();
        seen.insert(e["exit_code"].as_u64().unwrap());
        let (known_heads, evidence) = match (known_heads, evidence) {
            (Ok(h), Ok(p)) => (h, p),
            (h, p) => {
                assert_eq!(e["exit_code"], json!(2), "{name}: refused ({h:?}, {p:?})");
                continue;
            }
        };
        assert_ne!(e["exit_code"], json!(2), "{name}: inputs accepted");
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
            known_heads: &known_heads,
            evidence: &evidence,
            subject_org: c["subject_org"].as_str(),
            accept_fleet_anchor: false,
        };
        let r = dossier.verify(c["threshold"].as_f64().unwrap(), &ctx);
        assert_eq!(
            serde_json::to_value(&r.verdict).unwrap(),
            e["verdict"],
            "{name}"
        );
        assert_eq!(
            exit_code(
                &r.verdict,
                r.split_view_unsafe,
                c["allow_sub_majority"].as_bool().unwrap()
            ),
            e["exit_code"].as_u64().unwrap(),
            "{name}"
        );
        assert_eq!(json!(r.split_view_unsafe), e["split_view_unsafe"], "{name}");
        assert_eq!(
            json!(r.internally_consistent),
            e["internally_consistent"],
            "{name}"
        );
        assert_eq!(json!(!r.failures.is_empty()), e["has_failures"], "{name}");
        assert_eq!(json!(r.contradictions.len()), e["contradictions"], "{name}");
        assert_eq!(
            json!(r.known_heads_unchecked.len()),
            e["known_heads_unchecked"],
            "{name}"
        );
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
    assert_eq!(
        seen.into_iter().collect::<Vec<_>>(),
        vec![2, 10, 11, 20, 30, 40]
    );
}

/// `EquivocationProof` deserializes only from an object: serde's derived
/// impl took a four-element array as a proof (security review of 0.5.0,
/// F5), which the Go and TypeScript verifiers never did.
#[test]
fn an_equivocation_proof_is_never_read_from_an_array() {
    let v: Value = serde_json::from_str(
        &std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../corpus/15_evidence_and_args.json"),
        )
        .unwrap(),
    )
    .unwrap();
    let array = v["evidence"]["array"].clone();
    assert!(serde_json::from_value::<EquivocationProof>(array.clone()).is_err());
    assert!(serde_json::from_str::<EquivocationProof>(&array.to_string()).is_err());
    let bare: EquivocationProof = serde_json::from_value(v["evidence"]["bare"].clone()).unwrap();
    assert!(bare.verify());
    // The wrapped form is an evidence item, not a proof.
    assert!(serde_json::from_value::<EquivocationProof>(v["evidence"]["wrapped"].clone()).is_err());
    assert_eq!(
        EquivocationProof::from_evidence(&v["evidence"]["wrapped"]).unwrap(),
        bare
    );
    // Duplicate keys: the last wins, as in encoding/json and JSON.parse.
    let dup = format!(
        "{{\"origin\": \"x\", {}",
        &v["evidence"]["bare"].to_string()[1..]
    );
    assert_eq!(
        serde_json::from_str::<EquivocationProof>(&dup).unwrap(),
        bare
    );
}
