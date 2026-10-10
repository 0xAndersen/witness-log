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

#[test]
fn unreadable_input_is_a_usage_error_not_a_verdict() {
    let (code, _) = run(&["verify", "/definitely/not/a/file.json"]);
    assert_eq!(code, 2, "docs promise exit 2 for unreadable input");
    let p = tmp("garbage", "{not json");
    let (code, _) = run(&["verify", &p]);
    assert_eq!(code, 2);
    let _ = std::fs::remove_file(p);
}
