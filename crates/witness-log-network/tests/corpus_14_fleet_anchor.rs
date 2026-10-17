//! Corpus vector 14 (`corpus/14_fleet_anchor.json`, RFC-0001, experimental):
//! the reference verifier reproduces every case, and the fleet log's own
//! values (leaf hashes, root, inclusion proof) recompute.
//! `examples/generate_fleet_corpus.rs` writes it; CI fails if the committed
//! copy drifts. The Go and TypeScript verifiers, the wasm build, the Node
//! and Python bindings run the same file.

use base64ct::{Base64, Encoding};
use serde_json::Value;
use witness_log_core::merkle::{leaf_hash, verify_inclusion, MerkleTree};
use witness_log_network::{Dossier, Verdict, VerifyContext, WitnessDirectory};

fn corpus() -> Value {
    let path =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../corpus/14_fleet_anchor.json");
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

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
fn corpus_vector_14_fleet_log_values_recompute() {
    let v = corpus();
    let f = &v["fleet_log"];
    let mut tree = MerkleTree::new();
    for (e, h) in f["entries_b64"]
        .as_array()
        .unwrap()
        .iter()
        .zip(f["leaf_hashes_hex"].as_array().unwrap())
    {
        let bytes = Base64::decode_vec(e.as_str().unwrap()).unwrap();
        assert_eq!(hex::encode(leaf_hash(&bytes)), h.as_str().unwrap());
        tree.append(leaf_hash(&bytes));
    }
    assert_eq!(tree.size(), f["tree_size"].as_u64().unwrap());
    assert_eq!(hex::encode(tree.root()), f["root_hex"].as_str().unwrap());
    let proof: Vec<[u8; 32]> = f["entry_2_inclusion_proof_hex"]
        .as_array()
        .unwrap()
        .iter()
        .map(|h| {
            hex::decode(h.as_str().unwrap())
                .unwrap()
                .try_into()
                .unwrap()
        })
        .collect();
    assert_eq!(proof, tree.inclusion_proof(2, 4).unwrap());
    let entry_2 = Base64::decode_vec(f["entries_b64"][2].as_str().unwrap()).unwrap();
    assert!(verify_inclusion(
        &leaf_hash(&entry_2),
        2,
        4,
        &proof,
        &tree.root()
    ));
    // The fleet checkpoint note verifies under the published fleet vkey.
    let vkey =
        witness_log_core::c2sp::VerifierKey::parse(f["fleet_vkey"].as_str().unwrap()).unwrap();
    let note =
        witness_log_core::c2sp::SignedNote::parse(f["checkpoint_note"].as_str().unwrap()).unwrap();
    note.verify(&[vkey]).unwrap();
    assert_eq!(note.text, f["checkpoint_note_text"].as_str().unwrap());
}

#[test]
fn corpus_vector_14_fleet_anchor_cases() {
    let v = corpus();
    let directory: WitnessDirectory =
        serde_json::from_value(v["trusted_directory"].clone()).unwrap();
    let mut seen_exit = std::collections::BTreeSet::new();
    let mut seen_via = std::collections::BTreeSet::new();
    for c in v["cases"].as_array().unwrap() {
        let name = c["name"].as_str().unwrap();
        let dossier: Dossier =
            serde_json::from_value(v["dossiers"][c["dossier"].as_str().unwrap()].clone()).unwrap();
        let accept = c["accept_fleet_anchor"].as_bool().unwrap();
        let ctx = VerifyContext {
            trusted_directory: c["trusted_directory"]
                .as_bool()
                .unwrap()
                .then_some(&directory),
            min_receipts: c["min_witnesses"].as_u64().map(|n| n as usize),
            subject_org: c["subject_org"].as_str(),
            accept_fleet_anchor: accept,
            ..Default::default()
        };
        let r = dossier.verify(c["threshold"].as_f64().unwrap(), &ctx);
        let e = &c["expect"];
        let report = serde_json::to_value(&r).unwrap();
        assert_eq!(report["verdict"], e["verdict"], "{name}");
        let code = exit_code(
            &r.verdict,
            r.split_view_unsafe,
            c["allow_sub_majority"].as_bool().unwrap(),
        );
        assert_eq!(code, e["exit_code"].as_u64().unwrap(), "{name}");
        assert_eq!(
            report["split_view_unsafe"], e["split_view_unsafe"],
            "{name}"
        );
        assert_eq!(
            report["quorum"]
                .get("valid_receipts")
                .cloned()
                .unwrap_or(Value::Null),
            e["valid_receipts"],
            "{name}"
        );
        assert_eq!(
            report["quorum"]
                .get("distinct_independent_operators")
                .cloned()
                .unwrap_or(Value::Null),
            e["independent_operators"],
            "{name}"
        );
        assert_eq!(
            report
                .get("fleet_anchor")
                .map(|f| f["status"].clone())
                .unwrap_or(Value::Null),
            e["fleet_anchor_status"],
            "{name}"
        );
        assert_eq!(
            report
                .get("fleet_anchor")
                .map(|f| f["fleet_tree_size"].clone())
                .unwrap_or(Value::Null),
            e["fleet_tree_size"],
            "{name}"
        );
        if accept {
            assert_eq!(
                report.get("witnessed_via"),
                Some(&e["witnessed_via"]),
                "{name}"
            );
            assert_eq!(
                report.get("witness_paths"),
                Some(&e["witness_paths"]),
                "{name}"
            );
        } else {
            assert!(report.get("witnessed_via").is_none(), "{name}");
            assert!(report.get("witness_paths").is_none(), "{name}");
        }
        seen_exit.insert(e["exit_code"].as_u64().unwrap());
        seen_via.insert(e["witnessed_via"].to_string());
    }
    assert_eq!(
        seen_exit.into_iter().collect::<Vec<_>>(),
        vec![0, 10, 11, 20]
    );
    assert_eq!(
        seen_via.into_iter().collect::<Vec<_>>(),
        vec!["\"both\"", "\"direct\"", "\"fleet\"", "null"]
    );
}
