//! Host-side tests of the pure-Rust functions behind the wasm exports:
//! the corpus vectors they can be checked against, the golden dossiers the
//! Rust CLI produced for the Go client (clients/go/testdata), and the
//! README's sample dossier.

use serde_json::{json, Value};
use std::fs;
use std::path::PathBuf;
use witness_log_wasm::{bind_value, verify_disclosure_value, verify_dossier_value, VerifyOptions};

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap()
}

fn read(rel: &str) -> String {
    let path = repo_root().join(rel);
    fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

fn read_json(rel: &str) -> Value {
    serde_json::from_str(&read(rel)).unwrap()
}

/// An option value (an evidence item) as the options JSON carries it.
fn raw(v: &Value) -> Box<serde_json::value::RawValue> {
    serde_json::value::to_raw_value(v).unwrap()
}

/// A minimal dossier wrapper around a list of leaves, for `bind`, which
/// only reads identity_pubkey and leaves. Not verifiable; not meant to be.
fn dossier_with(identity: &str, leaves: Vec<Value>) -> String {
    json!({
        "identity_pubkey": identity,
        "leaves": leaves,
        "checkpoint": {
            "tree_size": leaves.len(), "root_hash": "00".repeat(32), "timestamp_ms": 0,
            "sig_alg": "ed25519", "signer_pubkey": identity, "signature": "00".repeat(64)
        }
    })
    .to_string()
}

#[test]
fn corpus_11_payload_hash_via_verify_disclosure() {
    let v = read_json("corpus/11_payload_hash.json");
    let cases = v["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 6);
    for c in cases {
        let payload = hex::decode(c["payload_hex"].as_str().unwrap()).unwrap();
        let leaf = json!({
            "index": c["leaf_index"], "leaf_type": 1, "timestamp_ms": 0,
            "session_pubkey": "00".repeat(32), "payload_hash": c["payload_hash"],
        })
        .to_string();
        let out =
            verify_disclosure_value(&leaf, &payload, c["salt_hex"].as_str().unwrap()).unwrap();
        assert_eq!(out["matches"], json!(true), "{}", c["name"]);
        assert_eq!(out["recomputed"], c["payload_hash"]);
        let wrong = verify_disclosure_value(
            &leaf,
            &[payload.as_slice(), b"x"].concat(),
            c["salt_hex"].as_str().unwrap(),
        )
        .unwrap();
        assert_eq!(wrong["matches"], json!(false));
    }
    assert!(verify_disclosure_value("{}", b"", "00").is_err());
    let leaf = json!({"index": 0, "leaf_type": 1, "timestamp_ms": 0, "session_pubkey": "00".repeat(32), "payload_hash": "00".repeat(32)}).to_string();
    assert!(verify_disclosure_value(&leaf, b"", "zz").is_err());
    assert!(
        verify_disclosure_value(&leaf, b"", "00").is_err(),
        "a 1-byte salt is rejected"
    );
}

#[test]
fn corpus_01_07_08_09_leaf_hashes_via_summary() {
    // The summary's per-leaf `leaf_hash` must equal the corpus leaf hash,
    // and every corpus leaf is structurally valid at its own index. The
    // dummy checkpoint signs nothing, so each dossier is DIVERGED (exit 30)
    // with structural validity still reported true.
    let check = |leaves: Vec<Value>, want: Vec<String>| {
        let d = dossier_with(&"aa".repeat(32), leaves.clone());
        let out = verify_dossier_value(&d, None, &VerifyOptions::default()).unwrap();
        let rows = out["summary"]["leaves"].as_array().unwrap();
        assert_eq!(rows.len(), want.len());
        for (row, want) in rows.iter().zip(&want) {
            assert_eq!(row["leaf_hash"].as_str().unwrap(), want, "{row}");
            assert_eq!(row["structurally_valid"], json!(true), "{row}");
        }
        assert_eq!(out["verdict"], json!("INVALID"));
        assert_eq!(out["exit_code"], json!(40));
        assert_eq!(out["report"]["checkpoint_signature_valid"], json!(false));
        assert_eq!(out["report"]["leaves_structurally_valid"], json!(true));
    };
    let v01 = read_json("corpus/01_leaf_encoding.json");
    let vectors = v01["vectors"].as_array().unwrap();
    assert_eq!(vectors.len(), 5);
    check(
        vectors.iter().map(|v| v["leaf"].clone()).collect(),
        vectors
            .iter()
            .map(|v| v["leaf_hash_hex"].as_str().unwrap().to_string())
            .collect(),
    );
    let mut n = 0;
    for (file, keys) in [
        (
            "corpus/07_handoff_attestation.json",
            vec!["sent_leaf", "received_leaf"],
        ),
        (
            "corpus/08_authorization_event.json",
            vec!["granted_leaf", "received_grant_leaf"],
        ),
        ("corpus/09_external_anchor.json", vec!["anchor_leaf"]),
    ] {
        let v = read_json(file);
        for k in keys {
            check(
                vec![v[k]["leaf"].clone()],
                vec![v[k]["leaf_hash_hex"].as_str().unwrap().to_string()],
            );
            n += 1;
        }
    }
    assert_eq!(n, 5);
}

#[test]
fn corpus_07_08_binding_via_bind() {
    let h = read_json("corpus/07_handoff_attestation.json");
    let sender = h["sender_identity_pubkey"].as_str().unwrap();
    let receiver = h["receiver_identity_pubkey"].as_str().unwrap();
    let a = dossier_with(sender, vec![h["sent_leaf"]["leaf"].clone()]);
    let b = dossier_with(receiver, vec![h["received_leaf"]["leaf"].clone()]);
    let out = bind_value(&a, &b).unwrap();
    assert_eq!(out["exit"], json!(0), "{out}");
    assert_eq!(out["bound"].as_array().unwrap().len(), 1);
    assert_eq!(out["bound"][0]["kind"], json!("handoff"));
    // Called the other way round, the same pair binds.
    let rev = bind_value(&b, &a).unwrap();
    assert_eq!(rev["exit"], json!(0));
    // The worked mismatch.
    let mut bad = h["received_leaf"]["leaf"].clone();
    bad["handoff_state_hash"] = json!("99".repeat(32));
    let out = bind_value(&a, &dossier_with(receiver, vec![bad])).unwrap();
    assert_eq!(out["exit"], json!(30));
    assert_eq!(out["failed"].as_array().unwrap().len(), 1);

    let g = read_json("corpus/08_authorization_event.json");
    let granter = g["granter_identity_pubkey"].as_str().unwrap();
    let grantee = g["grantee_identity_pubkey"].as_str().unwrap();
    let a = dossier_with(granter, vec![g["granted_leaf"]["leaf"].clone()]);
    let b = dossier_with(grantee, vec![g["received_grant_leaf"]["leaf"].clone()]);
    let out = bind_value(&a, &b).unwrap();
    assert_eq!(out["exit"], json!(0), "{out}");
    assert_eq!(out["bound"][0]["kind"], json!("authorization"));
    assert_eq!(out["bound"][0]["a_event"], json!("granted_by_me"));
    assert_eq!(out["bound"][0]["b_event"], json!("granted_to_me"));
    let mut bad = g["received_grant_leaf"]["leaf"].clone();
    bad["authorization_scope_hash"] = json!("99".repeat(32));
    let out = bind_value(&a, &dossier_with(grantee, vec![bad])).unwrap();
    assert_eq!(out["exit"], json!(30));
    // Nothing naming the other: exit 10. Same identity: error.
    let out = bind_value(&a, &dossier_with(&"ee".repeat(32), vec![])).unwrap();
    assert_eq!(out["exit"], json!(10));
    assert!(bind_value(&a, &a).is_err());
}

#[test]
fn golden_dossiers_reach_every_verdict() {
    let td = "clients/go/testdata/";
    let native = read(&format!("{td}native/dossier.json"));
    let native_dir = read(&format!("{td}native/trusted.json"));
    let a = read(&format!("{td}c2sp/a.json"));
    let b = read(&format!("{td}c2sp/b.json"));
    let c2sp_dir = read(&format!("{td}c2sp/trusted.json"));
    let no_opts = VerifyOptions::default();

    let out = verify_dossier_value(&native, None, &no_opts).unwrap();
    assert_eq!(out["verdict"], json!("UNANCHORED"));
    assert_eq!(out["exit_code"], json!(20));
    assert_eq!(out["report"]["internally_consistent"], json!(true));
    assert_eq!(out["report"]["quorum"], Value::Null);

    let out = verify_dossier_value(&native, Some(&native_dir), &no_opts).unwrap();
    assert_eq!(out["verdict"], json!("WITNESSED"));
    assert_eq!(out["exit_code"], json!(0));
    assert_eq!(
        out["report"]["quorum"]["distinct_independent_operators"],
        json!(2)
    );
    assert_eq!(
        out["report"]["quorum"]["project_operated_receipts"],
        json!(1)
    );
    assert_eq!(out["summary"]["receipts"].as_array().unwrap().len(), 3);
    assert!(out["summary"]["receipts"]
        .as_array()
        .unwrap()
        .iter()
        .all(|r| r["signature_valid"] == json!(true) && r["kind"] == json!("native")));

    let out = verify_dossier_value(&native, Some(&c2sp_dir), &no_opts).unwrap();
    assert_eq!(out["verdict"], json!("CONSISTENT-UNWITNESSED"));
    assert_eq!(out["exit_code"], json!(10));

    let out = verify_dossier_value(&a, Some(&c2sp_dir), &no_opts).unwrap();
    assert_eq!(out["verdict"], json!("WITNESSED"), "{}", out["report"]);
    let receipts = out["summary"]["receipts"].as_array().unwrap();
    assert_eq!(receipts.len(), 2);
    assert!(receipts.iter().all(
        |r| r["kind"] == json!("c2sp-cosignature") && r["in_trusted_directory"] == json!(true)
    ));
    assert_eq!(out["summary"]["leaves"].as_array().unwrap().len(), 7);
    let types: Vec<u64> = out["summary"]["leaves"]
        .as_array()
        .unwrap()
        .iter()
        .map(|l| l["leaf_type"].as_u64().unwrap())
        .collect();
    assert_eq!(types, vec![1, 2, 0, 5, 6, 7, 3]);
    assert_eq!(
        out["summary"]["canonical_origin"],
        json!(receipts[0]["c2sp_origin"])
    );

    let pinned = VerifyOptions {
        expected_identity_pubkey: Some("ab".repeat(32)),
        ..Default::default()
    };
    let out = verify_dossier_value(&a, Some(&c2sp_dir), &pinned).unwrap();
    assert_eq!(out["verdict"], json!("INVALID"));
    assert_eq!(out["exit_code"], json!(40));
    assert_eq!(out["report"]["identity_bound"], json!(false));
    assert_eq!(out["identity_pinned"], json!(true));

    let min3 = VerifyOptions {
        min_receipts: Some(3),
        ..Default::default()
    };
    let out = verify_dossier_value(&a, Some(&c2sp_dir), &min3).unwrap();
    assert_eq!(out["verdict"], json!("CONSISTENT-UNWITNESSED"));
    assert_eq!(out["report"]["quorum"]["count_gate"], json!("count >= 3"));

    // Tampering: edit one leaf timestamp.
    let mut tampered: Value = serde_json::from_str(&a).unwrap();
    tampered["leaves"][1]["timestamp_ms"] =
        json!(tampered["leaves"][1]["timestamp_ms"].as_u64().unwrap() + 1);
    let out = verify_dossier_value(&tampered.to_string(), Some(&c2sp_dir), &no_opts).unwrap();
    assert_eq!(out["verdict"], json!("INVALID"));
    assert_eq!(out["report"]["merkle_continuity_valid"], json!(false));

    // Bind the two goldens as `witness-log bind` did.
    let expected: Value = read_json(&format!("{td}c2sp/bind.expected.json"));
    let out = bind_value(&a, &b).unwrap();
    assert_eq!(out["exit"], expected["exit"]);
    assert_eq!(out["bound"], expected["bound"]);
    assert_eq!(out["failed"], expected["failed"]);

    // Disclosure fixture.
    let fx = read_json(&format!("{td}c2sp/disclosure.json"));
    let dossier: Value = serde_json::from_str(&a).unwrap();
    let leaf = dossier["leaves"][fx["leaf_index"].as_u64().unwrap() as usize].to_string();
    let payload = hex::decode(fx["payload_hex"].as_str().unwrap()).unwrap();
    let out = verify_disclosure_value(&leaf, &payload, fx["salt_hex"].as_str().unwrap()).unwrap();
    assert_eq!(out["matches"], json!(true));

    // Bad inputs are errors, not verdicts.
    assert!(verify_dossier_value("{}", None, &no_opts).is_err());
    assert!(verify_dossier_value(&a, Some("not json"), &no_opts).is_err());
    // A bare array of directory entries is accepted, as the CLI does.
    let bare = serde_json::from_str::<Value>(&c2sp_dir).unwrap()["witnesses"].to_string();
    let out = verify_dossier_value(&a, Some(&bare), &no_opts).unwrap();
    assert_eq!(out["verdict"], json!("WITNESSED"));
}

#[test]
fn golden_reports_equal_the_rust_cli_reports() {
    // The Go testdata keeps `witness-log verify --json` output for every
    // golden; the wasm crate shares the verifier, so its report must be
    // identical, which also guards the JSON shape the page relies on.
    let td = repo_root().join("clients/go/testdata");
    let cases = [
        ("native.unanchored", "native/dossier.json", None, None, None),
        (
            "native.directory",
            "native/dossier.json",
            Some("native/trusted.json"),
            None,
            None,
        ),
        (
            "native.min-witnesses-4",
            "native/dossier.json",
            Some("native/trusted.json"),
            None,
            Some(4),
        ),
        (
            "native.threshold-1",
            "native/dossier.json",
            Some("native/trusted.json"),
            Some(1.0),
            None,
        ),
        (
            "c2sp-a.directory",
            "c2sp/a.json",
            Some("c2sp/trusted.json"),
            None,
            None,
        ),
        (
            "c2sp-a.min-witnesses-3",
            "c2sp/a.json",
            Some("c2sp/trusted.json"),
            None,
            Some(3),
        ),
        (
            "c2sp-b.native-directory",
            "c2sp/b.json",
            Some("native/trusted.json"),
            None,
            None,
        ),
    ];
    for (name, dossier, dir, threshold, min) in cases {
        let expected: Value = serde_json::from_str(
            &fs::read_to_string(td.join(format!("expect/{name}.json"))).unwrap(),
        )
        .unwrap();
        let dossier = fs::read_to_string(td.join(dossier)).unwrap();
        let dir = dir.map(|d| fs::read_to_string(td.join(d)).unwrap());
        let opts = VerifyOptions {
            threshold,
            min_receipts: min,
            ..Default::default()
        };
        let out = verify_dossier_value(&dossier, dir.as_deref(), &opts).unwrap();
        assert_eq!(out["report"], expected["report"], "{name}");
        assert_eq!(out["verdict"], expected["verdict"], "{name}");
        let exit: u64 = fs::read_to_string(td.join(format!("expect/{name}.exit")))
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        assert_eq!(out["exit_code"], json!(exit), "{name}");
    }
}

#[test]
fn sample_dossier_from_the_readme() {
    let d = read("examples/sample-dossier.json");
    let dir = read("examples/trusted-directory.json");
    let out = verify_dossier_value(&d, Some(&dir), &VerifyOptions::default()).unwrap();
    assert_eq!(out["verdict"], json!("WITNESSED"));
    let out = verify_dossier_value(&d, None, &VerifyOptions::default()).unwrap();
    assert_eq!(out["verdict"], json!("UNANCHORED"));
}

/// Corpus vector 13: every verdict case, through the wasm verifier's
/// options (known heads and evidence included).
#[test]
fn corpus_13_verdicts() {
    let v = read_json("corpus/13_verdicts.json");
    let directory = v["trusted_directory"].to_string();
    let cases = v["cases"].as_array().unwrap();
    assert!(cases.len() >= 20);
    for c in cases {
        let name = c["name"].as_str().unwrap();
        let dossier = v["dossiers"][c["dossier"].as_str().unwrap()].to_string();
        let opts = VerifyOptions {
            expected_identity_pubkey: c["expected_identity"].as_str().map(str::to_string),
            threshold: c["threshold"].as_f64(),
            min_receipts: c["min_witnesses"].as_u64().map(|n| n as usize),
            allow_sub_majority: c["allow_sub_majority"].as_bool().unwrap(),
            known_heads: serde_json::from_value(c["known_heads"].clone()).unwrap(),
            evidence: c["evidence"]
                .as_array()
                .unwrap()
                .iter()
                .map(|k| raw(&v["evidence"][k.as_str().unwrap()]))
                .collect(),
            subject_org: c["subject_org"].as_str().map(str::to_string),
            ..Default::default()
        };
        let dir = c["trusted_directory"]
            .as_bool()
            .unwrap()
            .then_some(directory.as_str());
        let out = verify_dossier_value(&dossier, dir, &opts).unwrap();
        let e = &c["expect"];
        let verdict = out["report"]["verdict"].clone();
        assert_eq!(verdict, e["verdict"], "{name}");
        assert_eq!(out["exit_code"], e["exit_code"], "{name}");
        let r = &out["report"];
        assert_eq!(r["split_view_unsafe"], e["split_view_unsafe"], "{name}");
        assert_eq!(
            r["internally_consistent"], e["internally_consistent"],
            "{name}"
        );
        assert_eq!(
            !r["failures"].as_array().unwrap().is_empty(),
            e["has_failures"].as_bool().unwrap(),
            "{name}"
        );
        assert_eq!(
            json!(r["contradictions"].as_array().unwrap().len()),
            e["contradictions"],
            "{name}"
        );
        assert_eq!(
            json!(r["known_heads_unchecked"].as_array().unwrap().len()),
            e["known_heads_unchecked"],
            "{name}"
        );
        assert_eq!(r["quorum"]["valid_receipts"], e["valid_receipts"], "{name}");
        assert_eq!(
            r["quorum"]["distinct_independent_operators"], e["independent_operators"],
            "{name}"
        );
    }
}

/// Corpus vector 14 (RFC-0001, experimental): fleet anchors through the
/// wasm verifier's `accept_fleet_anchor` option.
#[test]
fn corpus_14_fleet_anchor() {
    let v = read_json("corpus/14_fleet_anchor.json");
    let directory = v["trusted_directory"].to_string();
    for c in v["cases"].as_array().unwrap() {
        let name = c["name"].as_str().unwrap();
        let dossier = v["dossiers"][c["dossier"].as_str().unwrap()].to_string();
        let accept = c["accept_fleet_anchor"].as_bool().unwrap();
        let opts = VerifyOptions {
            threshold: c["threshold"].as_f64(),
            min_receipts: c["min_witnesses"].as_u64().map(|n| n as usize),
            allow_sub_majority: c["allow_sub_majority"].as_bool().unwrap(),
            subject_org: c["subject_org"].as_str().map(str::to_string),
            accept_fleet_anchor: accept,
            ..Default::default()
        };
        let dir = c["trusted_directory"]
            .as_bool()
            .unwrap()
            .then_some(directory.as_str());
        let out = verify_dossier_value(&dossier, dir, &opts).unwrap();
        let e = &c["expect"];
        let r = &out["report"];
        assert_eq!(r["verdict"], e["verdict"], "{name}");
        assert_eq!(out["exit_code"], e["exit_code"], "{name}");
        assert_eq!(r["split_view_unsafe"], e["split_view_unsafe"], "{name}");
        assert_eq!(r["quorum"]["valid_receipts"], e["valid_receipts"], "{name}");
        assert_eq!(
            r["quorum"]["distinct_independent_operators"], e["independent_operators"],
            "{name}"
        );
        assert_eq!(
            r["fleet_anchor"]["status"], e["fleet_anchor_status"],
            "{name}"
        );
        assert_eq!(
            r["fleet_anchor"]["fleet_tree_size"], e["fleet_tree_size"],
            "{name}"
        );
        if accept {
            assert_eq!(r.get("witnessed_via"), Some(&e["witnessed_via"]), "{name}");
            assert_eq!(r.get("witness_paths"), Some(&e["witness_paths"]), "{name}");
        } else {
            assert!(r.get("witnessed_via").is_none(), "{name}");
            assert!(r.get("witness_paths").is_none(), "{name}");
        }
    }
}

/// Corpus vector 15: evidence items, known heads and directory labels,
/// read through the wasm verifier's options. A case whose inputs must be
/// refused (exit_code 2) is an `Err`, never a verdict.
#[test]
fn corpus_15_evidence_and_args() {
    let v = read_json("corpus/15_evidence_and_args.json");
    let cases = v["cases"].as_array().unwrap();
    assert!(cases.len() >= 40);
    for c in cases {
        let name = c["name"].as_str().unwrap();
        let dossier = v["dossiers"][c["dossier"].as_str().unwrap()].to_string();
        let opts = VerifyOptions {
            expected_identity_pubkey: c["expected_identity"].as_str().map(str::to_string),
            threshold: c["threshold"].as_f64(),
            min_receipts: c["min_witnesses"].as_u64().map(|n| n as usize),
            allow_sub_majority: c["allow_sub_majority"].as_bool().unwrap(),
            known_heads: serde_json::from_value(c["known_heads"].clone()).unwrap(),
            evidence: c["evidence"]
                .as_array()
                .unwrap()
                .iter()
                .map(|k| raw(&v["evidence"][k.as_str().unwrap()]))
                .collect(),
            subject_org: c["subject_org"].as_str().map(str::to_string),
            ..Default::default()
        };
        let dir = c["directory"]
            .as_str()
            .map(|d| v["directories"][d].to_string());
        let e = &c["expect"];
        let out = match verify_dossier_value(&dossier, dir.as_deref(), &opts) {
            Ok(out) => out,
            Err(err) => {
                assert_eq!(e["exit_code"], json!(2), "{name}: refused: {err}");
                continue;
            }
        };
        assert_ne!(e["exit_code"], json!(2), "{name}: inputs accepted");
        let r = &out["report"];
        assert_eq!(r["verdict"], e["verdict"], "{name}");
        assert_eq!(out["exit_code"], e["exit_code"], "{name}");
        assert_eq!(r["split_view_unsafe"], e["split_view_unsafe"], "{name}");
        assert_eq!(
            r["internally_consistent"], e["internally_consistent"],
            "{name}"
        );
        assert_eq!(
            json!(!r["failures"].as_array().unwrap().is_empty()),
            e["has_failures"],
            "{name}"
        );
        assert_eq!(
            json!(r["contradictions"].as_array().unwrap().len()),
            e["contradictions"],
            "{name}"
        );
        assert_eq!(
            json!(r["known_heads_unchecked"].as_array().unwrap().len()),
            e["known_heads_unchecked"],
            "{name}"
        );
        assert_eq!(r["quorum"]["valid_receipts"], e["valid_receipts"], "{name}");
        assert_eq!(
            r["quorum"]["distinct_independent_operators"], e["independent_operators"],
            "{name}"
        );
    }
}

/// Corpus 16 and 17 cases through the wasm entry point: a dossier the
/// reference cannot read is an error (the page shows it), anything else
/// the corpus verdict, exit code and report fields.
fn run_verdict_case(v: &Value, c: &Value, dossier: &str) {
    let name = c["name"].as_str().unwrap();
    let opts = VerifyOptions {
        expected_identity_pubkey: c["expected_identity"].as_str().map(str::to_string),
        threshold: c["threshold"].as_f64(),
        min_receipts: c["min_witnesses"].as_u64().map(|n| n as usize),
        allow_sub_majority: c["allow_sub_majority"].as_bool().unwrap(),
        known_heads: serde_json::from_value(c["known_heads"].clone()).unwrap(),
        evidence: c["evidence"]
            .as_array()
            .unwrap()
            .iter()
            .map(|k| raw(&v["evidence"][k.as_str().unwrap()]))
            .collect(),
        subject_org: c["subject_org"].as_str().map(str::to_string),
        ..Default::default()
    };
    let dir = c["directory"]
        .as_str()
        .map(|d| v["directories"][d].to_string());
    let e = &c["expect"];
    let out = match verify_dossier_value(dossier, dir.as_deref(), &opts) {
        Ok(out) => out,
        Err(err) => {
            assert_eq!(e["not_a_dossier"], json!(true), "{name}: refused: {err}");
            return;
        }
    };
    assert_ne!(e["not_a_dossier"], json!(true), "{name}: read");
    let r = &out["report"];
    assert_eq!(r["verdict"], e["verdict"], "{name}");
    assert_eq!(out["exit_code"], e["exit_code"], "{name}");
    assert_eq!(r["split_view_unsafe"], e["split_view_unsafe"], "{name}");
    assert_eq!(
        r["internally_consistent"], e["internally_consistent"],
        "{name}"
    );
    assert_eq!(
        json!(!r["failures"].as_array().unwrap().is_empty()),
        e["has_failures"],
        "{name}"
    );
    assert_eq!(
        json!(r["contradictions"].as_array().unwrap().len()),
        e["contradictions"],
        "{name}"
    );
    assert_eq!(r["quorum"]["valid_receipts"], e["valid_receipts"], "{name}");
    assert_eq!(
        r["quorum"]["distinct_independent_operators"], e["independent_operators"],
        "{name}"
    );
}

#[test]
fn corpus_16_ed25519_strict() {
    let v = read_json("corpus/16_ed25519_strict.json");
    let cases = v["cases"].as_array().unwrap();
    assert!(cases.len() >= 10);
    for c in cases {
        let dossier = v["dossiers"][c["dossier"].as_str().unwrap()].to_string();
        run_verdict_case(&v, c, &dossier);
    }
}

/// Corpus 17's `inputs`, given as the page gives them: the directory as its
/// own text, revocations and an evidence item inside the options JSON. Each
/// is read from its own text, so the nesting limit counts from the input
/// as for the CLI's files. Before, the directory and revocations were read
/// at any depth, and an evidence item (a `serde_json::Value` in the
/// options) only to serde_json's 128 levels, the options object included.
#[test]
fn corpus_17_inputs() {
    let v = read_json("corpus/17_dossier_parsing.json");
    let inputs = v["inputs"].as_array().unwrap();
    assert!(inputs.len() >= 18);
    for c in inputs {
        let name = c["name"].as_str().unwrap();
        let text = c["text"].as_str().unwrap();
        let dossier = v["cases"]
            .as_array()
            .unwrap()
            .iter()
            .find(|d| d["name"] == c["dossier"])
            .unwrap()["dossier_json"]
            .as_str()
            .unwrap();
        let (directory, options) = match c["input"].as_str().unwrap() {
            "directory" => (
                Some(text),
                format!(r#"{{"min_receipts":{}}}"#, c["min_witnesses"]),
            ),
            "revocations" => (None, format!(r#"{{"revocations":{text}}}"#)),
            "evidence" => (None, format!(r#"{{"evidence":[{text}]}}"#)),
            other => panic!("{name}: {other}"),
        };
        let opts: VerifyOptions = serde_json::from_str(&options).unwrap();
        let e = &c["expect"];
        match verify_dossier_value(dossier, directory, &opts) {
            Err(err) => {
                assert_eq!(e["refused"], json!(true), "{name}: refused: {err}");
                assert!(err.contains("nested deeper than 1000"), "{name}: {err}");
            }
            Ok(out) => {
                assert_eq!(e["refused"], json!(false), "{name}: read");
                assert_eq!(out["report"]["verdict"], e["verdict"], "{name}");
                assert_eq!(out["exit_code"], e["exit_code"], "{name}");
                assert_eq!(
                    json!(!out["report"]["failures"].as_array().unwrap().is_empty()),
                    e["has_failures"],
                    "{name}"
                );
                assert_eq!(
                    out["report"]["quorum"]["valid_receipts"], e["valid_receipts"],
                    "{name}"
                );
            }
        }
    }
}

/// Revocations in the options are one statement or an array of them, as
/// `--revocations` reads them (and Go's wasm build); `null` is none.
#[test]
fn options_revocations_are_one_statement_or_an_array() {
    let v = read_json("corpus/17_dossier_parsing.json");
    let find = |list: &str, n: &str| -> Value {
        v[list]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["name"] == n)
            .unwrap()
            .clone()
    };
    let dossier = find("cases", "valid")["dossier_json"]
        .as_str()
        .unwrap()
        .to_string();
    let statement = find(
        "inputs",
        "a revocation statement with 1001 brackets in a string after an escaped quote",
    )["text"]
        .as_str()
        .unwrap()
        .to_string();
    for (options, verdict) in [
        ("{}".to_string(), "unanchored"),
        (r#"{"revocations":null}"#.to_string(), "unanchored"),
        (format!(r#"{{"revocations":{statement}}}"#), "invalid"),
        (format!(r#"{{"revocations":[{statement}]}}"#), "invalid"),
    ] {
        let opts: VerifyOptions = serde_json::from_str(&options).unwrap();
        let out = verify_dossier_value(&dossier, None, &opts).unwrap();
        assert_eq!(
            out["report"]["verdict"],
            verdict,
            "{}",
            &options[..20.min(options.len())]
        );
    }
    let opts: VerifyOptions = serde_json::from_str(r#"{"revocations":"x"}"#).unwrap();
    assert!(verify_dossier_value(&dossier, None, &opts).is_err());
}

#[test]
fn corpus_17_dossier_parsing() {
    let v = read_json("corpus/17_dossier_parsing.json");
    let cases = v["cases"].as_array().unwrap();
    assert!(cases.len() >= 100);
    for c in cases {
        run_verdict_case(&v, c, c["dossier_json"].as_str().unwrap());
    }
}
