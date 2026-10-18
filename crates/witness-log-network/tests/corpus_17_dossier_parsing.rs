//! Corpus vector 17 (`corpus/17_dossier_parsing.json`): which texts are
//! dossiers and what they verify to, at the edges where the Go and
//! TypeScript verifiers once read JSON differently from serde (outside
//! review III, H2 and P3). The Go and TypeScript verifiers, the wasm
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
        let dossier = match Dossier::from_json(text) {
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

/// `T::deserialize(..)` called by path, as a `deserialize_with` helper in
/// another crate calls it. While the wire types derived with
/// `#[serde(remote = "Self")]` that path named serde's public inherent
/// function, which skips the object-only rule, and the array forms read.
#[test]
fn calling_deserialize_by_path_cannot_skip_the_object_rule() {
    use serde::Deserialize;
    use witness_log_network::fleet::FleetAnchor;
    use witness_log_network::{WitnessEntry, WitnessReceipt};
    macro_rules! reads {
        ($ty:ident, $json:expr) => {
            $ty::deserialize(&mut serde_json::Deserializer::from_str($json)).is_ok()
        };
    }
    let v = corpus();
    let case = |n: &str| {
        v["cases"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["name"] == n)
            .unwrap()["dossier_json"]
            .as_str()
            .unwrap()
            .to_string()
    };
    assert!(!reads!(
        Dossier,
        &case("the dossier written as an array of its field values")
    ));
    assert!(reads!(Dossier, &case("valid")));
    assert!(!reads!(WitnessDirectory, r#"[[]]"#));
    assert!(!reads!(
        WitnessEntry,
        r#"["n","o","https://n.example","00","human",null,false]"#
    ));
    assert!(!reads!(WitnessReceipt, r#"["00",1,"11",2,"22",null,null]"#));
    assert!(!reads!(FleetAnchor, r#"["o.example/fleet",0,"",[],""]"#));
    assert!(reads!(
        FleetAnchor,
        r#"{"origin":"o.example/fleet","entry_index":0,"entry_bytes_b64":"","inclusion_proof":[],"fleet_checkpoint_note":""}"#
    ));
}

fn minimal_dossier() -> String {
    let v = corpus();
    v["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == "whitespace around the object")
        .unwrap()["dossier_json"]
        .as_str()
        .unwrap()
        .trim()
        .to_string()
}

/// Before the closing brace of the top-level object.
fn with_field(text: &str, field: &str) -> String {
    format!("{},{field}}}", &text[..text.len() - 1])
}

/// SPEC.md §9: a dossier text nests at most MAX_DOSSIER_DEPTH (1000)
/// arrays and objects deep, the dossier object being depth 1, wherever the
/// nesting is. Before the limit an ignored key of any depth was read here,
/// and Go refused 10,000 levels.
#[test]
fn a_dossier_text_nests_at_most_1000_deep() {
    use witness_log_network::{DossierParseError, MAX_DOSSIER_DEPTH};
    assert_eq!(MAX_DOSSIER_DEPTH, 1000);
    let min = minimal_dossier();
    let nested = |n: usize| format!("{}{}", "[".repeat(n), "]".repeat(n));
    let objects = |n: usize| format!("{}1{}", "{\"a\":".repeat(n), "}".repeat(n));
    assert!(Dossier::from_json(&with_field(&min, &format!("\"zz\":{}", nested(999)))).is_ok());
    assert!(Dossier::from_json(&with_field(&min, &format!("\"zz\":{}", objects(999)))).is_ok());
    for too_deep in [nested(1000), objects(1000), nested(10_000), nested(100_000)] {
        let text = with_field(&min, &format!("\"zz\":{too_deep}"));
        // serde_json alone skips an ignored key of any depth.
        assert!(serde_json::from_str::<Dossier>(&text).is_ok());
        let started = std::time::Instant::now();
        match Dossier::from_json(&text) {
            Err(e @ DossierParseError::TooDeep { .. }) => {
                assert!(e.to_string().contains("nested deeper than 1000"), "{e}")
            }
            other => panic!("{other:?}"),
        }
        assert!(started.elapsed() < std::time::Duration::from_secs(1));
    }
    // Brackets in strings, escaped quotes included, do not count.
    let in_string = format!("\"zz\":\"\\\"{}\"", "[".repeat(5000));
    assert!(Dossier::from_json(&with_field(&min, &in_string)).is_ok());
}

/// Numbers in `fleet_anchor` are read correctly rounded (serde_json's
/// `float_roundtrip`), as Go and JavaScript read them: a literal is
/// refused only when it rounds to infinity. Without the feature,
/// 1.7976931348623158e308 and the 309-digit integers below, all finite as
/// binary64, were "number out of range" here and read by Go and TypeScript.
#[test]
fn fleet_anchor_numbers_are_refused_only_when_they_round_to_infinity() {
    let min = minimal_dossier();
    let with = |x: &str| with_field(&min, &format!("\"fleet_anchor\":{{\"x\":{x}}}"));
    let max_digits = format!("17976931348623157{}", "0".repeat(292));
    for finite in [
        "1.7976931348623158e308",
        "-1.7976931348623158e308",
        "1.7976931348623157e308",
        max_digits.as_str(),
        "4.9e-324",
        "1e-400",
    ] {
        assert!(Dossier::from_json(&with(finite)).is_ok(), "{finite}");
    }
    for infinite in ["1.7976931348623159e308", "-1.7976931348623159e308", "1e309"] {
        assert!(Dossier::from_json(&with(infinite)).is_err(), "{infinite}");
    }
}

/// A refusal quotes a bounded part of the text, not the whole of it.
#[test]
fn a_refusal_does_not_echo_a_huge_input() {
    let min = minimal_dossier();
    let huge = "S".repeat(10_000_000);
    for text in [
        min.replacen("\"sig_alg\":\"ed25519\"", &format!("\"sig_alg\":{}", "1".repeat(10_000_000)), 1),
        min.replacen("\"tree_size\":0", &format!("\"tree_size\":\"{huge}\""), 1),
        min.replacen(
            "\"witness_directory\":{\"witnesses\":[]}",
            &format!("\"witness_directory\":{{\"witnesses\":[{{\"name\":\"n\",\"operator_org\":\"o\",\"url\":\"u\",\"pubkey\":\"p\",\"runtime\":\"{huge}\"}}]}}"),
            1,
        ),
    ] {
        let started = std::time::Instant::now();
        let e = Dossier::from_json(&text).unwrap_err().to_string();
        assert!(e.len() < 400, "{} bytes: {}", e.len(), &e[..200]);
        assert!(e.contains("line 1 column"), "{e}");
        assert!(started.elapsed() < std::time::Duration::from_secs(5));
    }
}
