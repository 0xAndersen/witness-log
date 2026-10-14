//! `witness-log c2sp verify` is used as a gate (`… && proceed`), so its
//! exit code must reflect EVERY key the caller supplied. The final
//! pre-publish review found a forged cosignature from a supplied witness
//! key printed "FAILED" while the process still exited 0.

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use std::process::Command;
use witness_log_core::c2sp::{Checkpoint, Cosignature, VerifierKey};

fn run(args: &[&str]) -> (i32, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_witness-log"))
        .args(args)
        .output()
        .unwrap();
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).to_string(),
    )
}

fn tmp(tag: &str, contents: &str) -> String {
    let p = std::env::temp_dir().join(format!(
        "wl-c2sp-{tag}-{}-{}",
        std::process::id(),
        rand::random::<u32>()
    ));
    std::fs::write(&p, contents).unwrap();
    p.to_string_lossy().into_owned()
}

#[test]
fn forged_cosignature_from_a_supplied_key_fails_the_gate() {
    let origin = "example.test/log";
    let log_key = SigningKey::generate(&mut OsRng);
    let witness_key = SigningKey::generate(&mut OsRng);
    let cp = Checkpoint {
        origin: origin.into(),
        tree_size: 4,
        root_hash: [7u8; 32],
        extensions: vec![],
    };
    let mut note = cp.sign(&log_key).unwrap();
    let log_vkey = VerifierKey::for_ed25519(origin, &log_key.verifying_key()).encode();
    let witness_vkey =
        VerifierKey::for_cosignature("w.test/1", &witness_key.verifying_key()).encode();

    // Genuine cosignature: gate passes.
    let good = Cosignature::sign(
        "w.test/1",
        &witness_key,
        1_700_000_000,
        &cp.note_text().unwrap(),
    );
    note.signatures.push(good.to_note_signature());
    let good_path = tmp("good", &note.encode().unwrap());
    let (code, out) = run(&[
        "c2sp",
        "verify",
        &good_path,
        "--vkey",
        &log_vkey,
        "--vkey",
        &witness_vkey,
    ]);
    assert_eq!(code, 0, "{out}");
    assert!(
        !out.contains("IGNORED"),
        "a supplied cosignature key is not 'unknown':\n{out}"
    );

    // Cosignature over a DIFFERENT head, attached to this note: gate fails.
    let other = Checkpoint {
        root_hash: [9u8; 32],
        ..cp.clone()
    };
    let forged = Cosignature::sign(
        "w.test/1",
        &witness_key,
        1_700_000_000,
        &other.note_text().unwrap(),
    );
    note.signatures.pop();
    note.signatures.push(forged.to_note_signature());
    let bad_path = tmp("bad", &note.encode().unwrap());
    let (code, out) = run(&[
        "c2sp",
        "verify",
        &bad_path,
        "--vkey",
        &log_vkey,
        "--vkey",
        &witness_vkey,
    ]);
    assert_ne!(
        code, 0,
        "a forged cosignature from a supplied key must fail:\n{out}"
    );
    assert!(out.contains("FAILED"), "{out}");

    // Without the witness key supplied, the same line is an unknown
    // signature and is ignored per signed-note: the log's own check passes.
    let (code, _) = run(&["c2sp", "verify", &bad_path, "--vkey", &log_vkey]);
    assert_eq!(code, 0);
    let _ = std::fs::remove_file(good_path);
    let _ = std::fs::remove_file(bad_path);
}

/// The exit status is about the keys the caller supplied, both kinds.
/// Until 0.3.6 it was the log-key check alone: a note whose cosignatures
/// all verified exited 30 when only witness keys were given (the shape
/// `c2sp export` writes without `--sign-with`), and a run in which none
/// of the supplied keys matched any signature line was not itself a
/// rejection.
#[test]
fn verdict_covers_cosignature_keys_and_rejects_when_nothing_verified() {
    let origin = "example.test/log";
    let log_key = SigningKey::generate(&mut OsRng);
    let witness_key = SigningKey::generate(&mut OsRng);
    let stranger = SigningKey::generate(&mut OsRng);
    let cp = Checkpoint {
        origin: origin.into(),
        tree_size: 9,
        root_hash: [3u8; 32],
        extensions: vec![],
    };
    let body = cp.note_text().unwrap();
    // A cosignature-only note, as `c2sp export` writes it without the log key.
    let note = witness_log_core::c2sp::SignedNote {
        text: body.clone(),
        signatures: vec![
            Cosignature::sign("w.test/1", &witness_key, 1_700_000_000, &body).to_note_signature(),
        ],
    };
    let path = tmp("cosig-only", &note.encode().unwrap());
    let witness_vkey =
        VerifierKey::for_cosignature("w.test/1", &witness_key.verifying_key()).encode();
    let (code, out) = run(&["c2sp", "verify", &path, "--vkey", &witness_vkey]);
    assert_eq!(
        code, 0,
        "a verifying cosignature from a supplied key is a pass:\n{out}"
    );

    // A supplied witness key that matches no line: nothing verified.
    let stranger_vkey =
        VerifierKey::for_cosignature("w.test/9", &stranger.verifying_key()).encode();
    let (code, out) = run(&["c2sp", "verify", &path, "--vkey", &stranger_vkey]);
    assert_eq!(
        code, 40,
        "no supplied key verified anything (INVALID since 0.5.0):\n{out}"
    );
    assert!(
        out.contains("None of the 1 supplied key(s) verified"),
        "{out}"
    );

    // Same for a log-signed note checked with the wrong log key.
    let signed = cp.sign(&log_key).unwrap();
    let signed_path = tmp("log-signed", &signed.encode().unwrap());
    let wrong_log_vkey = VerifierKey::for_ed25519(origin, &stranger.verifying_key()).encode();
    let (code, _) = run(&["c2sp", "verify", &signed_path, "--vkey", &wrong_log_vkey]);
    assert_eq!(code, 40);
    let right_log_vkey = VerifierKey::for_ed25519(origin, &log_key.verifying_key()).encode();
    let (code, _) = run(&["c2sp", "verify", &signed_path, "--vkey", &right_log_vkey]);
    assert_eq!(code, 0);
    let _ = std::fs::remove_file(path);
    let _ = std::fs::remove_file(signed_path);
}

#[test]
fn unreadable_input_is_a_usage_error_not_a_verdict() {
    let (code, _) = run(&["verify", "/definitely/not/a/file.json"]);
    assert_eq!(code, 2, "docs promise exit 2 for unreadable input");
    let p = tmp("garbage", "{not json");
    let (code, _) = run(&["verify", &p]);
    assert_eq!(code, 2);
    let _ = std::fs::remove_file(p);
}
