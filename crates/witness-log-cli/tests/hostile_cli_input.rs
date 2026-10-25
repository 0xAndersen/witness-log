//! Drives `witness-log verify` end-to-end against hostile dossier files —
//! not just the library's `Dossier::verify`, but the actual binary,
//! including its render path (`short()`, text/`--explain` formatting).
//! The library-level `malformed_input_robustness` suite in
//! witness-log-network never touched the CLI, which is the surface an
//! attacker actually gets to hit. See the pre-launch review, finding 10.

use std::io::Write;
use std::process::Command;

const HOSTILE_INPUTS: &[&str] = &[
    "",
    "null",
    "not json at all",
    "{}",
    // The exact case that panicked: a multibyte UTF-8 character sitting on
    // the byte offset `short()` used to slice at.
    r#"{"identity_pubkey": "語aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa語", "leaves": [], "checkpoint": {"sig_alg": "ed25519", "tree_size": 0, "root_hash": "", "timestamp_ms": 0, "signer_pubkey": "", "signature": ""}}"#,
    r#"{"identity_pubkey": "\ud800\ud800", "leaves": [], "checkpoint": {"sig_alg": "ed25519", "tree_size": 0, "root_hash": "", "timestamp_ms": 0, "signer_pubkey": "", "signature": ""}}"#,
];

fn run_verify_on(content: &str) -> std::process::Output {
    let f = tempfile_write(content);
    let bin = env!("CARGO_BIN_EXE_witness-log");
    let out = Command::new(bin)
        .args(["verify", f.path_str()])
        .output()
        .expect("failed to run witness-log binary");
    f.close();
    out
}

// Minimal manual tempfile so this test has no extra dependency.
struct TmpFile {
    path: std::path::PathBuf,
}
impl TmpFile {
    fn path_str(&self) -> &str {
        self.path.to_str().unwrap()
    }
    fn close(self) {
        let _ = std::fs::remove_file(self.path.as_path());
    }
}
fn tempfile_write(content: &str) -> TmpFile {
    let path = std::env::temp_dir().join(format!(
        "witness-log-cli-hostile-{}-{}.json",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let mut f = std::fs::File::create(&path).unwrap();
    f.write_all(content.as_bytes()).unwrap();
    TmpFile { path }
}

#[test]
fn cli_never_panics_on_hostile_dossier_files() {
    for (i, input) in HOSTILE_INPUTS.iter().enumerate() {
        let out = run_verify_on(input);
        // A panic in a Rust binary run without RUST_BACKTRACE set through
        // this harness exits with a distinctive non-zero code and prints
        // "panicked at" to stderr; a clean error exit does neither.
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            !stderr.contains("panicked at"),
            "hostile input {i} panicked the CLI: {stderr}"
        );
    }
}

#[test]
fn cli_rejects_unrecognized_flags_instead_of_silently_ignoring_them() {
    let f = tempfile_write(
        r#"{"identity_pubkey":"aa","leaves":[],"checkpoint":{"sig_alg":"ed25519","tree_size":0,"root_hash":"","timestamp_ms":0,"signer_pubkey":"","signature":""}}"#,
    );
    let bin = env!("CARGO_BIN_EXE_witness-log");
    let out = Command::new(bin)
        .args(["verify", f.path_str(), "--jsom"]) // deliberate typo of --json
        .output()
        .expect("failed to run witness-log binary");
    f.close();
    assert!(
        !out.status.success(),
        "a typo'd flag must be rejected, not silently run with defaults"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("unrecognized flag"),
        "expected an unrecognized-flag error, got: {stderr}"
    );
}

fn run_verify_json_on(content: &str) -> std::process::Output {
    let f = tempfile_write(content);
    let out = Command::new(env!("CARGO_BIN_EXE_witness-log"))
        .args(["verify", f.path_str(), "--json"])
        .output()
        .expect("failed to run witness-log binary");
    f.close();
    out
}

fn hostile_dossier(leaf_extra: &str, payload_hash: &str, extra: &str) -> String {
    let key = "aa".repeat(32);
    format!(
        r#"{{"identity_pubkey":"{key}","leaves":[{{"index":0,"leaf_type":1,"timestamp_ms":1,"session_pubkey":"{key}","payload_hash":"{payload_hash}"{leaf_extra}}}],"checkpoint":{{"sig_alg":"ed25519","tree_size":1,"root_hash":"","timestamp_ms":0,"signer_pubkey":"{key}","signature":""}}{extra}}}"#
    )
}

/// An outside audit of 0.6.1: a refusal or a failure quoted the hostile
/// input whole (a 10-million-character variant name on stderr, a
/// 10-million-character field in `failures`). Messages now quote a bounded
/// part of it.
#[test]
fn cli_messages_quote_a_bounded_part_of_a_huge_input() {
    let huge = "S".repeat(10_000_000);
    let hash = "bb".repeat(32);
    // Not a dossier: serde_json's error names the variant it refused.
    let out = run_verify_json_on(&hostile_dossier(
        &format!(r#","handoff_direction":"{huge}""#),
        &hash,
        "",
    ));
    assert_eq!(out.status.code(), Some(2));
    assert!(
        out.stderr.len() < 1000,
        "{} bytes on stderr",
        out.stderr.len()
    );
    // A dossier, INVALID: the leaf check names the field it refused.
    let out = run_verify_json_on(&hostile_dossier("", &huge, ""));
    assert_eq!(out.status.code(), Some(40));
    assert!(
        out.stdout.len() < 10_000,
        "{} bytes on stdout",
        out.stdout.len()
    );
    let report: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let failures = report["report"]["failures"].as_array().unwrap();
    assert!(
        failures
            .iter()
            .any(|f| f.as_str().unwrap().contains("payload_hash")),
        "{failures:?}"
    );
}

/// Corpus 17's `inputs` through the binary: a --directory, --revocations
/// or --evidence file nested deeper than 1000 is a usage error (exit 2), as
/// a malformed one is; at 1000 it is read and used. Before, the directory
/// and revocations were read at any depth and evidence refused beyond
/// serde_json's 128 levels, while Go refused all three at 10,000.
#[test]
fn cli_refuses_directory_revocations_and_evidence_nested_deeper_than_1000() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../corpus/17_dossier_parsing.json");
    let v: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let valid = v["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == "valid")
        .unwrap()["dossier_json"]
        .as_str()
        .unwrap();
    let dossier = tempfile_write(valid);
    let inputs = v["inputs"].as_array().unwrap();
    assert!(inputs.len() >= 18);
    for c in inputs {
        let name = c["name"].as_str().unwrap();
        assert_eq!(c["dossier"], "valid", "{name}");
        let input = tempfile_write(c["text"].as_str().unwrap());
        let flag = format!("--{}", c["input"].as_str().unwrap());
        let mut args = vec![
            "verify",
            dossier.path_str(),
            &flag,
            input.path_str(),
            "--json",
        ];
        let min = c["min_witnesses"].as_u64().map(|n| n.to_string());
        if let Some(n) = &min {
            args.extend(["--min-witnesses", n.as_str()]);
        }
        let out = Command::new(env!("CARGO_BIN_EXE_witness-log"))
            .args(&args)
            .output()
            .unwrap();
        input.close();
        let e = &c["expect"];
        assert_eq!(
            out.status.code().map(i64::from),
            e["exit_code"].as_i64(),
            "{name}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        if e["refused"] == true {
            let stderr = String::from_utf8_lossy(&out.stderr);
            assert!(
                !name.contains("nested") || stderr.contains("nested deeper than 1000"),
                "{name}: {stderr}"
            );
            assert!(out.stdout.is_empty(), "{name}");
        } else {
            let report: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
            assert_eq!(report["report"]["verdict"], e["verdict"], "{name}");
        }
    }
    dossier.close();
}

/// `verify --json` reports the dossier's own identity_pubkey whole up to 64
/// bytes (a key in hex) and cut to 64 characters and "…" beyond: a longer
/// one is never a key. Through 0.6.1 a hostile file's megabytes came back
/// whole on stdout. The Go CLI reports it the same way.
#[test]
fn cli_json_reports_a_bounded_identity() {
    let key = "aa".repeat(32);
    let dossier = |identity: &str| {
        format!(
            r#"{{"identity_pubkey":"{identity}","leaves":[],"checkpoint":{{"sig_alg":"ed25519","tree_size":0,"root_hash":"","timestamp_ms":0,"signer_pubkey":"{key}","signature":""}}}}"#
        )
    };
    for (claimed, reported) in [
        (key.clone(), key.clone()),
        ("zz".to_string(), "zz".to_string()),
        ("é".repeat(40), format!("{}\u{2026}", "é".repeat(40))),
        (
            "ab".repeat(5_000_000),
            format!("{}\u{2026}", "ab".repeat(32)),
        ),
    ] {
        let out = run_verify_json_on(&dossier(&claimed));
        assert_eq!(out.status.code(), Some(40));
        assert!(out.stdout.len() < 10_000, "{} bytes", out.stdout.len());
        let report: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
        assert_eq!(report["identity_pubkey"], reported.as_str());
    }
}

/// `bind` names each dossier's identity as `verify --json` does: cut to 64
/// characters and "…" when longer than a key, in the JSON, the text and the
/// refusal of two equal claims. Through 0.6.1 it printed them whole, and
/// both dossiers are input the caller does not control.
#[test]
fn cli_bind_reports_bounded_identities() {
    let key = "aa".repeat(32);
    let huge = "ab".repeat(5_000_000);
    let dossier = |identity: &str| {
        tempfile_write(&format!(
            r#"{{"identity_pubkey":"{identity}","leaves":[],"checkpoint":{{"sig_alg":"ed25519","tree_size":0,"root_hash":"","timestamp_ms":0,"signer_pubkey":"{key}","signature":""}}}}"#
        ))
    };
    let (a, b) = (dossier(&huge), dossier(&key));
    let cut = format!("{}\u{2026}", "ab".repeat(32));
    let bind = |args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_witness-log"))
            .arg("bind")
            .args(args)
            .output()
            .unwrap()
    };
    let out = bind(&[a.path_str(), b.path_str(), "--json"]);
    assert_eq!(out.status.code(), Some(10));
    assert!(out.stdout.len() < 10_000, "{} bytes", out.stdout.len());
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["a"]["identity"], cut.as_str());
    assert_eq!(v["b"]["identity"], key.as_str());
    let out = bind(&[a.path_str(), b.path_str()]);
    assert!(out.stdout.len() < 10_000, "{} bytes", out.stdout.len());
    assert!(String::from_utf8_lossy(&out.stdout).contains(&cut));
    let out = bind(&[a.path_str(), a.path_str()]);
    assert_eq!(out.status.code(), Some(2));
    assert!(out.stderr.len() < 1_000, "{} bytes", out.stderr.len());
    a.close();
    b.close();
}

/// SPEC.md §9: a dossier text nests at most 1000 arrays and objects deep
/// (the dossier object is depth 1). Before, an ignored key of any depth was
/// read here while Go refused 10,000 levels and more.
#[test]
fn cli_refuses_a_dossier_nested_deeper_than_1000() {
    let hash = "bb".repeat(32);
    let nested = |n: usize| format!("{}{}", "[".repeat(n), "]".repeat(n));
    let at_limit = run_verify_json_on(&hostile_dossier(
        "",
        &hash,
        &format!(r#","zz":{}"#, nested(999)),
    ));
    // Read, and INVALID: the checkpoint is not signed.
    assert_eq!(at_limit.status.code(), Some(40));
    for n in [1000, 100_000] {
        let started = std::time::Instant::now();
        let out = run_verify_json_on(&hostile_dossier(
            "",
            &hash,
            &format!(r#","zz":{}"#, nested(n)),
        ));
        assert_eq!(out.status.code(), Some(2), "an ignored key {n} deep");
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(stderr.contains("nested deeper than 1000"), "{stderr}");
        assert!(started.elapsed() < std::time::Duration::from_secs(10));
    }
}
