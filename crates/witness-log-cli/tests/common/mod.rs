//! Shared fixtures for CLI integration tests.
//!
//! Everything here builds its own temporary files and cleans up after
//! itself, so the tests have no dependency on generated artifacts being
//! present in the tree and leave nothing behind.

#![allow(dead_code)] // each test file uses a different subset

use ed25519_dalek::SigningKey;
use witness_log_core::identity::IdentityKeypair;
use witness_log_core::log::WitnessLog;
use witness_log_network::{Dossier, WitnessDirectory};

/// A temp file that deletes itself when dropped.
pub struct TmpJson {
    path: std::path::PathBuf,
}

impl TmpJson {
    pub fn write(contents: &str) -> Self {
        // Nanosecond timestamp plus a counter: two fixtures created in the
        // same test can otherwise collide on a fast machine.
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "witness-log-test-{}-{}-{}.json",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            COUNTER.fetch_add(1, Ordering::Relaxed),
        ));
        std::fs::write(&path, contents).expect("failed to write temp fixture");
        Self { path }
    }

    pub fn path(&self) -> &str {
        self.path.to_str().expect("temp path must be valid UTF-8")
    }
}

impl Drop for TmpJson {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

fn dossier_json(log: &WitnessLog, signing_key: &SigningKey, identity_hex: &str) -> String {
    let sth = log.checkpoint(signing_key);
    let d = Dossier {
        identity_pubkey: identity_hex.to_string(),
        leaves: log.leaves().to_vec(),
        checkpoint: sth,
        witness_receipts: vec![],
        witness_directory: WitnessDirectory::default(),
        key_bindings: vec![],
        revocations: vec![],
        fleet_anchor: None,
    };
    serde_json::to_string_pretty(&d).expect("dossier must serialize")
}

/// A dossier from a freshly-created log with its own identity. Two calls
/// produce two genuinely SEPARATE logs — useful for testing that the tool
/// distinguishes "two different logs" from "one log that equivocated."
pub fn write_standalone_dossier(payload: &[u8]) -> TmpJson {
    let identity = IdentityKeypair::generate();
    let bytes = identity.to_bytes();
    let identity_hex = identity.public_hex();
    let mut log = WitnessLog::resume(identity, 0);
    log.append_intent(payload);
    let key = SigningKey::from_bytes(&bytes);
    TmpJson::write(&dossier_json(&log, &key, &identity_hex))
}

/// Two logs that share ONE identity but were built independently from
/// leaf 0 — no shared history at all. Because payload hashes are salted
/// per log instance, these diverge immediately even with byte-identical
/// content. Distinct from `write_dossier_pair`, which shares a real
/// prefix, and from two `write_standalone_dossier` calls, which don't
/// even share an identity.
pub fn write_same_identity_separate_logs(payload: &[u8]) -> (TmpJson, TmpJson) {
    let identity = IdentityKeypair::generate();
    let bytes = identity.to_bytes();
    let identity_hex = identity.public_hex();
    let key = SigningKey::from_bytes(&bytes);

    let build = || {
        let mut log = WitnessLog::resume(IdentityKeypair::from_bytes(&bytes), 0);
        log.append_intent(payload);
        TmpJson::write(&dossier_json(&log, &key, &identity_hex))
    };
    let a = build();
    let b = build();
    (a, b)
}

/// Two dossiers from ONE log: a shared prefix of `prefix_len` leaves,
/// then each branch optionally appends its own continuation. This is the
/// construction real equivocation requires — a shared history followed by
/// a fork, both branches signed by the same identity. Passing `None` for
/// a branch leaves it at the prefix, producing a strict-prefix pair
/// rather than a divergent one.
pub fn write_dossier_pair(
    prefix_len: usize,
    a_extra: Option<&[u8]>,
    b_extra: Option<&[u8]>,
) -> (TmpJson, TmpJson) {
    let identity = IdentityKeypair::generate();
    let bytes = identity.to_bytes();
    let identity_hex = identity.public_hex();
    let key = SigningKey::from_bytes(&bytes);

    // Build the shared prefix once, then snapshot it so both branches
    // resume from byte-identical state.
    let mut base = WitnessLog::resume(IdentityKeypair::from_bytes(&bytes), 0);
    for i in 0..prefix_len {
        base.append_intent(format!("shared prefix event {i}").as_bytes());
    }
    let snapshot = TmpJson::write("{}");
    base.save_snapshot(snapshot.path())
        .expect("snapshot must write");

    let branch = |extra: Option<&[u8]>| -> TmpJson {
        let mut log = WitnessLog::load_snapshot(snapshot.path()).expect("snapshot must load");
        if let Some(e) = extra {
            log.append_intent(e);
        }
        TmpJson::write(&dossier_json(&log, &key, &identity_hex))
    };

    let a = branch(a_extra);
    let b = branch(b_extra);
    (a, b)
}
