//! Adversarial input robustness: every parsing path that accepts
//! attacker-controlled bytes must return an error, never panic. A
//! malformed dossier is the EXPECTED input to `witness-log verify`, not an
//! edge case. This suite runs on stable Rust in every CI run; the
//! fuzz/ directory holds cargo-fuzz targets covering the same surfaces
//! with coverage-guided generation on nightly (see fuzz/README.md).

use witness_log_network::{Dossier, VerifyContext};

const HOSTILE_INPUTS: &[&str] = &[
    "",
    "null",
    "0",
    "[]",
    "{}",
    "\"a string\"",
    "{\"identity_pubkey\": null}",
    "{\"identity_pubkey\": 42, \"leaves\": \"not an array\", \"checkpoint\": []}",
    "{\"leaves\": [[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]}",
    "{\"identity_pubkey\": \"aa\", \"leaves\": [{\"index\": 99999999999999999999999999, \"leaf_type\": -1, \"timestamp_ms\": 1.5e308, \"session_pubkey\": \"x\", \"payload_hash\": \"y\", \"redacted_index\": null, \"revoked_identity\": null}], \"checkpoint\": {\"sig_alg\": \"ed25519\", \"tree_size\": 0, \"root_hash\": \"\", \"timestamp_ms\": 0, \"signer_pubkey\": \"\", \"signature\": \"\"}}",
    "{\"identity_pubkey\": \"zz-not-hex\", \"leaves\": [], \"checkpoint\": {\"sig_alg\": \"ed25519\", \"tree_size\": 0, \"root_hash\": \"zz\", \"timestamp_ms\": 0, \"signer_pubkey\": \"zz\", \"signature\": \"zz\"}}",
    "{\"identity_pubkey\": \"aa\", \"leaves\": [], \"checkpoint\": {\"sig_alg\": \"quantum-magic-9000\", \"tree_size\": 0, \"root_hash\": \"\", \"timestamp_ms\": 0, \"signer_pubkey\": \"\", \"signature\": \"\"}}",
    // signer_pubkey (not identity_pubkey) is the real field name on
    // SignedTreeHead. Earlier versions of this fixture named the wrong
    // field, so several "hostile" cases silently failed to deserialize
    // and tested nothing -- see the pre-launch review, finding 10.
    "{\"identity_pubkey\": \"\\u0000\\uFFFDevil\", \"leaves\": [], \"checkpoint\": {\"sig_alg\": \"ed25519\", \"tree_size\": 18446744073709551615, \"root_hash\": \"fire\", \"timestamp_ms\": 0, \"signer_pubkey\": \"dots\", \"signature\": \"sig\"}}",
    "{\"identity_pubkey\": \"aa\", \"lea",
];

#[test]
fn hostile_dossier_inputs_never_panic() {
    for (i, input) in HOSTILE_INPUTS.iter().enumerate() {
        let parsed: Result<Dossier, _> = serde_json::from_str(input);
        if let Ok(dossier) = parsed {
            let report = dossier.verify(0.66, &VerifyContext::default());
            assert!(
                !report.is_internally_consistent() || dossier.leaves.is_empty(),
                "hostile input {i} must never verify as consistent unless trivially empty"
            );
        }
    }
}

#[test]
fn hostile_checkpoint_inputs_never_panic() {
    use witness_log_core::sth::SignedTreeHead;
    for input in HOSTILE_INPUTS {
        if let Ok(sth) = serde_json::from_str::<SignedTreeHead>(input) {
            let _ = sth.verify();
        }
    }
}

#[test]
fn hostile_snapshot_files_never_panic() {
    use witness_log_core::WitnessLog;
    let dir = std::env::temp_dir();
    for (i, input) in HOSTILE_INPUTS.iter().enumerate() {
        let path = dir.join(format!(
            "witness-log-hostile-snap-{}-{i}.json",
            std::process::id()
        ));
        std::fs::write(&path, input).unwrap();
        let _ = WitnessLog::load_snapshot(path.to_str().unwrap());
        std::fs::remove_file(&path).ok();
    }
}

#[test]
fn hostile_journal_files_never_panic() {
    use witness_log_core::journal::LeafJournal;
    let dir = std::env::temp_dir();
    for (i, input) in HOSTILE_INPUTS.iter().enumerate() {
        let path = dir.join(format!(
            "witness-log-hostile-journal-{}-{i}.jsonl",
            std::process::id()
        ));
        std::fs::write(&path, input).unwrap();
        let _ = LeafJournal::replay(path.to_str().unwrap());
        std::fs::remove_file(&path).ok();
    }
}
