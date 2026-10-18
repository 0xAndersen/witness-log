//! Corpus vector 17 (`corpus/17_dossier_parsing.json`): which texts are
//! dossiers and what they verify to, at the edges where the Go and
//! TypeScript verifiers once read JSON differently from serde (outside
//! review of 0.6.0, H2 and P3). The Go and TypeScript verifiers, the wasm
//! build, Node and Python run the same file.
//! `examples/generate_parsing_corpus.rs` writes it; CI fails if the
//! committed copy drifts from what the generator produces.

use serde_json::{json, Value};
use witness_log_network::{Dossier, KnownHead, Verdict, VerifyContext, WitnessDirectory};

fn corpus() -> Value {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../corpus/17_dossier_parsing.json");
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

#[test]
fn corpus_vector_17_dossier_parsing() {
    let v = corpus();
    let cases = v["cases"].as_array().unwrap();
    assert!(cases.len() >= 100);
    let (mut refused, mut read) = (0, 0);
    for c in cases {
        let name = c["name"].as_str().unwrap();
        let e = &c["expect"];
        let text = c["dossier_json"].as_str().unwrap();
        let dossier = match serde_json::from_str::<Dossier>(text) {
            Err(err) => {
                assert_eq!(e["not_a_dossier"], json!(true), "{name}: refused: {err}");
                refused += 1;
                continue;
            }
            Ok(d) => d,
        };
        assert_eq!(e["not_a_dossier"], json!(false), "{name}: read");
        read += 1;
        let directory: Option<WitnessDirectory> = c["directory"]
            .as_str()
            .map(|d| serde_json::from_value(v["directories"][d].clone()).unwrap());
        let known_heads: Vec<KnownHead> = c["known_heads"]
            .as_array()
            .unwrap()
            .iter()
            .map(|h| h.as_str().unwrap().parse().unwrap())
            .collect();
        let ctx = VerifyContext {
            expected_identity_pubkey: c["expected_identity"].as_str(),
            trusted_directory: directory.as_ref(),
            min_receipts: c["min_witnesses"].as_u64().map(|n| n as usize),
            revocations: &[],
            known_heads: &known_heads,
            evidence: &[],
            subject_org: c["subject_org"].as_str(),
            accept_fleet_anchor: false,
        };
        let r = dossier.verify(c["threshold"].as_f64().unwrap(), &ctx);
        let exit = if r.split_view_unsafe {
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
    }
    assert!(
        refused >= 50 && read >= 40,
        "{refused} refused, {read} read"
    );
}

/// A struct written as an array of its field values was a dossier to
/// serde's derived impl and to nothing else; it is refused now, from text
/// and from a parsed value alike.
#[test]
fn a_struct_written_as_an_array_is_not_a_dossier() {
    let v = corpus();
    for c in v["cases"].as_array().unwrap() {
        let name = c["name"].as_str().unwrap();
        if !name.contains("as an array") {
            continue;
        }
        let text = c["dossier_json"].as_str().unwrap();
        assert!(serde_json::from_str::<Dossier>(text).is_err(), "{name}");
        let value: Value = serde_json::from_str(text).unwrap();
        assert!(serde_json::from_value::<Dossier>(value).is_err(), "{name}");
    }
}
