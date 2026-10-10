//! Integration tests for `witness-log diff` — the equivocation check.
//!
//! These drive the real binary end-to-end (parse → compare → render →
//! exit code) rather than testing a library function, because the thing
//! being verified is the whole user-facing behavior: what a person sees
//! and what a script gets back. Each test builds its own fixtures, so
//! nothing here depends on generated files being left lying around.

use std::process::Command;

mod common;
use common::{write_dossier_pair, TmpJson};

/// Exit codes are the public contract — see `exit` in main.rs.
const EXIT_MATCH: i32 = 0;
const EXIT_DIVERGED: i32 = 30;
const EXIT_USAGE: i32 = 2;

fn run_diff(a: &str, b: &str) -> (i32, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_witness-log"))
        .args(["diff", a, b])
        .output()
        .expect("failed to run witness-log");
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    (out.status.code().unwrap_or(-1), combined)
}

#[test]
fn real_equivocation_is_detected_and_reported() {
    // One log, forked after a shared prefix, both branches signed by the
    // same identity. This is what equivocation actually looks like.
    let (a, b) = write_dossier_pair(
        2,
        Some(br#"{"tool":"transfer_funds","args":{"amount_usd":250}}"#),
        Some(br#"{"tool":"transfer_funds","args":{"amount_usd":9999999}}"#),
    );
    let (code, out) = run_diff(a.path(), b.path());
    assert_eq!(code, EXIT_DIVERGED, "equivocation must exit 30\n{out}");
    assert!(out.contains("EQUIVOCATION DETECTED"), "{out}");
    assert!(
        out.contains("Leaves 0–1: identical"),
        "shared prefix must be reported: {out}"
    );
    assert!(
        out.contains("Leaf 2: DIVERGENT"),
        "divergence point must be named: {out}"
    );
}

#[test]
fn identical_copies_report_no_divergence() {
    // Genuinely identical copies means the SAME FILE copied — not two
    // branches that re-append the same content. Salts are per-instance
    // and excluded from snapshots by design, so re-appending identical
    // content after a restore produces a different payload_hash, a
    // different root, and therefore a real fork. See
    // `restoring_and_reappending_is_a_genuine_fork` below.
    let (a, _b) = write_dossier_pair(2, Some(b"an event"), Some(b"an event"));
    let copy = TmpJson::write(&std::fs::read_to_string(a.path()).unwrap());
    let (code, out) = run_diff(a.path(), copy.path());
    assert_eq!(
        code, EXIT_MATCH,
        "a file compared against its own copy must exit 0\n{out}"
    );
    assert!(out.contains("No divergence"), "{out}");
    assert!(
        !out.contains("EQUIVOCATION"),
        "must not accuse on identical copies: {out}"
    );
}

#[test]
fn restoring_and_reappending_is_a_genuine_fork() {
    // Two branches restored from one snapshot, each appending the SAME
    // content. Human-readably "the same thing happened twice" — but
    // cryptographically the log signed two different roots at the same
    // tree size, which is exactly what equivocation is. Reporting it is
    // correct, and this test pins that behavior so it can't silently
    // change: an agent that crashes, restores, and redoes work really
    // has produced a fork a witness would flag.
    let (a, b) = write_dossier_pair(2, Some(b"an event"), Some(b"an event"));
    let (code, out) = run_diff(a.path(), b.path());
    assert_eq!(
        code, EXIT_DIVERGED,
        "a restore-and-redo fork must be reported\n{out}"
    );
    assert!(out.contains("EQUIVOCATION DETECTED"), "{out}");
}

#[test]
fn strict_prefix_is_not_reported_as_equivocation() {
    // B has everything A has, plus more — two views taken at different
    // times, which is normal and must NOT be called equivocation.
    let (a, b) = write_dossier_pair(2, None, Some(b"a later event only B saw"));
    let (code, out) = run_diff(a.path(), b.path());
    assert_eq!(
        code, EXIT_MATCH,
        "a strict prefix must not be a failure\n{out}"
    );
    assert!(out.contains("strict prefix"), "{out}");
    assert!(
        !out.contains("EQUIVOCATION DETECTED"),
        "a longer log is not evidence of equivocation: {out}"
    );
}

#[test]
fn divergence_at_leaf_zero_explains_salting_instead_of_accusing() {
    // Two logs sharing ONE identity but built independently from leaf 0.
    // Payload hashes are salted per log instance, so these diverge
    // immediately even with identical content. The tool must explain
    // that rather than reporting equivocation — a false accusation here
    // would be a serious defect.
    let (a, b) = common::write_same_identity_separate_logs(b"identical content");
    let (code, out) = run_diff(a.path(), b.path());
    assert_eq!(
        code, EXIT_DIVERGED,
        "still a failure, but for a different reason\n{out}"
    );
    assert!(
        out.contains("SEPARATE logs"),
        "must explain these are separate logs, not an equivocating one: {out}"
    );
    assert!(
        out.contains("salted per log instance"),
        "must explain WHY: {out}"
    );
    assert!(
        !out.contains("EQUIVOCATION DETECTED"),
        "must NOT accuse two unrelated logs of equivocating: {out}"
    );
}

#[test]
fn different_identities_are_refused_rather_than_compared() {
    let a = common::write_standalone_dossier(b"log one");
    let b = common::write_standalone_dossier(b"log two");
    // write_standalone_dossier generates a fresh identity each time, so
    // these name different identities.
    let (code, out) = run_diff(a.path(), b.path());
    // Either refused as incomparable (2) or explained as separate logs
    // (30) — both are correct, neither may claim equivocation.
    assert!(
        code == EXIT_USAGE || code == EXIT_DIVERGED,
        "got {code}\n{out}"
    );
    assert!(!out.contains("EQUIVOCATION DETECTED"), "{out}");
}

#[test]
fn unreadable_input_is_a_usage_error_not_a_verdict() {
    let bad = TmpJson::write("not json at all");
    let good = common::write_standalone_dossier(b"fine");
    let (code, out) = run_diff(bad.path(), good.path());
    assert_eq!(
        code, EXIT_USAGE,
        "a parse failure is a usage error, not a verdict\n{out}"
    );
}

#[test]
fn missing_arguments_print_usage() {
    let out = Command::new(env!("CARGO_BIN_EXE_witness-log"))
        .args(["diff", "only-one-file.json"])
        .output()
        .expect("failed to run witness-log");
    assert_eq!(out.status.code(), Some(EXIT_USAGE));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("usage:"), "{stderr}");
}

/// Final pre-publish review: a copy whose leaves no longer reproduce its
/// own signed root is a TAMPERED file, not a second history the log
/// signed. `diff` must say so instead of accusing the log of
/// equivocation -- otherwise anyone holding one honest copy could edit a
/// leaf and frame the log.
#[test]
fn a_tampered_copy_is_not_reported_as_equivocation() {
    let (a, b) = write_dossier_pair(3, None, None);
    // Same file twice is "identical"; now corrupt one leaf in B without
    // touching its checkpoint.
    let mut v: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(b.path()).unwrap()).unwrap();
    v["leaves"][1]["payload_hash"] = serde_json::Value::String("00".repeat(32));
    std::fs::write(b.path(), serde_json::to_string(&v).unwrap()).unwrap();

    let (code, out) = run_diff(a.path(), b.path());
    assert_eq!(code, EXIT_DIVERGED, "{out}");
    assert!(
        !out.contains("EQUIVOCATION DETECTED"),
        "a tampered copy must not be called equivocation:\n{out}"
    );
    assert!(out.contains("Copy B"), "{out}");
    assert!(out.contains("tampered file"), "{out}");
}
