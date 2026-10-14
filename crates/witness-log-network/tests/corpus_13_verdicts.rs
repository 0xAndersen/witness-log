//! Corpus vector 13 (`corpus/13_verdicts.json`): the reference verifier
//! reproduces every case's verdict, exit code and report fields. The Go
//! and TypeScript verifiers and the wasm build run the same file.
//! `examples/generate_verdict_corpus.rs` writes it; CI fails if the
//! committed copy drifts from what the generator produces.

use serde_json::Value;
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
fn corpus_vector_13_verdicts() {
    let path =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../corpus/13_verdicts.json");
    let v: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let directory: WitnessDirectory =
        serde_json::from_value(v["trusted_directory"].clone()).unwrap();
    let mut seen = std::collections::BTreeSet::new();
    for c in v["cases"].as_array().unwrap() {
        let name = c["name"].as_str().unwrap();
        let dossier: Dossier =
            serde_json::from_value(v["dossiers"][c["dossier"].as_str().unwrap()].clone()).unwrap();
        let known_heads: Vec<KnownHead> = c["known_heads"]
            .as_array()
            .unwrap()
            .iter()
            .map(|h| h.as_str().unwrap().parse().unwrap())
            .collect();
        let evidence: Vec<EquivocationProof> = c["evidence"]
            .as_array()
            .unwrap()
            .iter()
            .map(|k| serde_json::from_value(v["evidence"][k.as_str().unwrap()].clone()).unwrap())
            .collect();
        let ctx = VerifyContext {
            expected_identity_pubkey: c["expected_identity"].as_str(),
            trusted_directory: c["trusted_directory"]
                .as_bool()
                .unwrap()
                .then_some(&directory),
            min_receipts: c["min_witnesses"].as_u64().map(|n| n as usize),
            revocations: &[],
            known_heads: &known_heads,
            evidence: &evidence,
        };
        let r = dossier.verify(c["threshold"].as_f64().unwrap(), &ctx);
        let e = &c["expect"];
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
        assert_eq!(
            r.split_view_unsafe,
            e["split_view_unsafe"].as_bool().unwrap(),
            "{name}"
        );
        assert_eq!(
            r.internally_consistent,
            e["internally_consistent"].as_bool().unwrap(),
            "{name}"
        );
        assert_eq!(
            !r.failures.is_empty(),
            e["has_failures"].as_bool().unwrap(),
            "{name}"
        );
        assert_eq!(
            r.contradictions.len() as u64,
            e["contradictions"].as_u64().unwrap(),
            "{name}"
        );
        assert_eq!(
            r.known_heads_unchecked.len() as u64,
            e["known_heads_unchecked"].as_u64().unwrap(),
            "{name}"
        );
        assert_eq!(
            r.quorum.as_ref().map(|q| q.valid_receipts as u64),
            e["valid_receipts"].as_u64(),
            "{name}"
        );
        seen.insert(e["exit_code"].as_u64().unwrap());
    }
    // Every exit status a verdict can produce is exercised.
    assert_eq!(
        seen.into_iter().collect::<Vec<_>>(),
        vec![0, 10, 11, 20, 30, 40]
    );
}
