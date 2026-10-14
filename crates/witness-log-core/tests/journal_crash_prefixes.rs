//! The torn-write family, exhaustively: a crash can leave any byte prefix
//! of the journal and, independently, any byte prefix of the salt sidecar.
//! For every such prefix of a journal that exercises every record shape
//! (header, bindings, every leaf type, a non-ASCII anchor URL, a
//! tombstone), resume must:
//!
//! 1. never panic and never refuse the journal;
//! 2. keep exactly the leaf records whose JSON is complete in the prefix,
//!    with or without the trailing newline (review round 2, J1);
//! 3. heal a tear anywhere, including inside a multi-byte character (J3);
//! 4. leave a file the next append extends cleanly: after one append and
//!    another resume the tree has one more leaf and the same root the live
//!    process had (no merged lines, no lost leaves).
//!
//! The sidecar half checks that no prefix of `<journal>.salts` blocks
//! resume (J2) and that every complete salt record is still usable.
//!
//! `fuzz/fuzz_targets/fuzz_journal_damage.rs` runs the same invariants on
//! fuzzer-chosen journals and damage; this test is the deterministic floor
//! that runs on every push.

use witness_log_core::identity::IdentityKeypair;
use witness_log_core::journal::JournaledLog;

fn scratch(tag: &str) -> std::path::PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let d = std::env::temp_dir().join(format!("wl-prefix-{tag}-{}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// A journal with every record shape. Returns its path.
fn build(dir: &std::path::Path) -> String {
    let p = dir.join("j.jsonl").to_string_lossy().into_owned();
    let mut jl = JournaledLog::create(&p, IdentityKeypair::from_bytes(&[7u8; 32])).unwrap();
    jl.append_intent(br#"{"tool":"pay","amount":5}"#).unwrap();
    jl.append_result(br#"{"ok":true}"#).unwrap();
    let mem = jl.append_memory("caf\u{e9} \u{1F600}".as_bytes()).unwrap();
    jl.append_handoff_sent(b"state", &hex::encode([9u8; 32]))
        .unwrap();
    jl.append_external_anchor(
        "https://example.com/\u{e9}t\u{e9}/entry/1",
        r#"{"logIndex":42}"#,
    )
    .unwrap();
    jl.forget(mem).unwrap();
    jl.append_intent(b"last").unwrap();
    jl.sync().unwrap();
    drop(jl);
    // A second session, so the file holds two binding records.
    let (mut jl, _) = JournaledLog::resume(&p).unwrap();
    jl.append_result(b"after restart").unwrap();
    jl.sync().unwrap();
    p
}

/// (end offset of the record's JSON, excluding its newline; is it a leaf)
fn record_ends(bytes: &[u8]) -> Vec<(usize, bool)> {
    let mut out = Vec::new();
    let mut start = 0usize;
    for (i, b) in bytes.iter().enumerate() {
        if *b == b'\n' {
            let line = &bytes[start..i];
            let is_leaf = std::str::from_utf8(line)
                .ok()
                .and_then(|t| serde_json::from_str::<serde_json::Value>(t).ok())
                .map(|v| {
                    v.get("leaf_type").is_some()
                        || v.get("Leaf").is_some()
                        || v.get("leaf").is_some()
                })
                .unwrap_or(false);
            out.push((i, is_leaf));
            start = i + 1;
        }
    }
    out
}

#[test]
fn every_journal_prefix_resumes_and_keeps_every_complete_record() {
    let dir = scratch("journal");
    let original_path = build(&dir);
    let original = std::fs::read(&original_path).unwrap();
    let salts = std::fs::read(JournaledLog::salts_path(&original_path)).unwrap();
    let ends = record_ends(&original);
    let header_end = ends[0].0;
    let total_leaves = ends.iter().filter(|(_, l)| *l).count();
    assert!(
        total_leaves >= 7,
        "fixture must hold every leaf shape, got {total_leaves}"
    );

    let work = dir.join("w.jsonl").to_string_lossy().into_owned();
    let mut checked = 0usize;
    for k in 0..=original.len() {
        std::fs::write(&work, &original[..k]).unwrap();
        std::fs::write(JournaledLog::salts_path(&work), &salts).unwrap();
        let _ = std::fs::remove_file(format!("{work}.lock"));
        let resumed = std::panic::catch_unwind(|| JournaledLog::resume(&work));
        let resumed = resumed.unwrap_or_else(|_| panic!("resume panicked on a {k}-byte prefix"));
        if k < header_end {
            // Not even a complete header: a crash during `create`. Refusing
            // is correct; panicking or inventing an identity is not.
            assert!(resumed.is_err(), "a {k}-byte prefix has no complete header");
            continue;
        }
        let (mut jl, _) = resumed.unwrap_or_else(|e| panic!("prefix {k}: resume refused: {e}"));
        let expected = ends.iter().filter(|(end, leaf)| *leaf && *end <= k).count() as u64;
        assert_eq!(
            jl.log().tree_size(),
            expected,
            "prefix {k}: every leaf whose JSON is complete must survive"
        );
        jl.append_intent(b"post-crash").unwrap();
        jl.sync().unwrap();
        let live = jl.log().root_hex();
        drop(jl);
        let (again, report) = JournaledLog::resume(&work)
            .unwrap_or_else(|e| panic!("prefix {k}: second resume refused: {e}"));
        assert_eq!(
            report.dropped_trailing_lines, 0,
            "prefix {k}: the append left a torn line"
        );
        assert_eq!(again.log().tree_size(), expected + 1, "prefix {k}");
        assert_eq!(
            again.log().root_hex(),
            live,
            "prefix {k}: restart reproduces the live root"
        );
        drop(again);
        checked += 1;
    }
    assert!(checked > 500, "checked {checked} prefixes");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn every_salt_sidecar_prefix_resumes() {
    let dir = scratch("salts");
    let original_path = build(&dir);
    let journal = std::fs::read(&original_path).unwrap();
    let salts = std::fs::read(JournaledLog::salts_path(&original_path)).unwrap();
    // Salt records are `{"i":N,"s":"<64 hex>"}`; collect complete ones.
    let mut complete: Vec<(usize, u64)> = Vec::new();
    let mut start = 0usize;
    for (i, b) in salts.iter().enumerate() {
        if *b == b'\n' {
            let v: serde_json::Value = serde_json::from_slice(&salts[start..i]).unwrap();
            complete.push((i, v["i"].as_u64().unwrap()));
            start = i + 1;
        }
    }
    let work = dir.join("w.jsonl").to_string_lossy().into_owned();
    for k in 0..=salts.len() {
        std::fs::write(&work, &journal).unwrap();
        std::fs::write(JournaledLog::salts_path(&work), &salts[..k]).unwrap();
        let _ = std::fs::remove_file(format!("{work}.lock"));
        let (mut jl, _) = JournaledLog::resume(&work)
            .unwrap_or_else(|e| panic!("salt prefix {k}: resume refused: {e}"));
        for (end, index) in &complete {
            if *end <= k {
                // The record is complete; unless the leaf was forgotten or
                // is a kind forget refuses, its salt must still be usable.
                let leaf = &jl.log().leaves()[*index as usize];
                let forgettable = leaf.leaf_type != 7;
                let tombstoned = jl
                    .log()
                    .leaves()
                    .iter()
                    .any(|l| l.redacted_index == Some(*index));
                if forgettable && !tombstoned {
                    assert!(
                        jl.can_forget(*index),
                        "salt prefix {k}: salt for leaf {index} lost"
                    );
                }
            }
        }
        // And the sidecar takes the next record cleanly.
        let next = jl.append_memory(b"x").unwrap();
        jl.sync().unwrap();
        drop(jl);
        let (again, _) = JournaledLog::resume(&work).unwrap();
        assert!(
            again.can_forget(next),
            "salt prefix {k}: the next salt record was not usable"
        );
        drop(again);
    }
    let _ = std::fs::remove_dir_all(&dir);
}
