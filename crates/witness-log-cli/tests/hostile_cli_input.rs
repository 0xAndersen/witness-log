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
