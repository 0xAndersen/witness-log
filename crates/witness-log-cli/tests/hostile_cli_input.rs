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
