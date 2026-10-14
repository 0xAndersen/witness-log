//! Structured crash damage on real journals (the torn-write family).
//!
//! The fuzzer chooses a history (appends of every kind with arbitrary
//! payloads, anchors with arbitrary URLs, forgets) and a crash: a byte
//! prefix of the journal, optionally with the final newline removed, and a
//! byte prefix of the salt sidecar. Invariants, the same ones
//! `crates/witness-log-core/tests/journal_crash_prefixes.rs` checks
//! exhaustively on a fixed journal:
//!
//! - resume never panics; with a complete header it never refuses;
//! - every leaf record whose JSON is complete in the prefix survives;
//! - after one append and another resume the tree grew by exactly one and
//!   the root equals the live process's root (nothing merged, nothing lost).
#![no_main]
use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use witness_log_core::identity::IdentityKeypair;
use witness_log_core::journal::JournaledLog;

#[derive(Arbitrary, Debug)]
enum Op {
    Intent(Vec<u8>),
    Result(Vec<u8>),
    Memory(Vec<u8>),
    Handoff(Vec<u8>),
    Anchor(String),
    Forget(u8),
}

#[derive(Arbitrary, Debug)]
struct Case {
    ops: Vec<Op>,
    journal_cut: u16,
    strip_newline: bool,
    salt_cut: u16,
}

fn record_ends(bytes: &[u8]) -> Vec<(usize, bool)> {
    let mut out = Vec::new();
    let mut start = 0usize;
    for (i, b) in bytes.iter().enumerate() {
        if *b == b'\n' {
            let is_leaf = std::str::from_utf8(&bytes[start..i])
                .ok()
                .and_then(|t| serde_json::from_str::<serde_json::Value>(t).ok())
                .map(|v| v.get("leaf_type").is_some())
                .unwrap_or(false);
            out.push((i, is_leaf));
            start = i + 1;
        }
    }
    out
}

fuzz_target!(|case: Case| {
    if case.ops.len() > 24 {
        return;
    }
    let dir = std::env::temp_dir().join(format!("wl-fuzz-damage-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("j.jsonl").to_string_lossy().into_owned();

    let mut jl = JournaledLog::create(&path, IdentityKeypair::from_bytes(&[3u8; 32])).unwrap();
    for op in &case.ops {
        let _ = match op {
            Op::Intent(p) => jl.append_intent(p).map(|_| ()),
            Op::Result(p) => jl.append_result(p).map(|_| ()),
            Op::Memory(p) => jl.append_memory(p).map(|_| ()),
            Op::Handoff(p) => jl.append_handoff_sent(p, &"ab".repeat(32)).map(|_| ()),
            Op::Anchor(u) => jl
                .append_external_anchor(&format!("https://example.com/{u}"), "{}")
                .map(|_| ()),
            Op::Forget(i) => jl.forget(u64::from(*i)).map(|_| ()),
        };
    }
    jl.sync().unwrap();
    drop(jl);

    let journal = std::fs::read(&path).unwrap();
    let salts = std::fs::read(JournaledLog::salts_path(&path)).unwrap_or_default();
    let ends = record_ends(&journal);
    let header_end = ends.first().map_or(0, |e| e.0);
    let k = usize::from(case.journal_cut) % (journal.len() + 1);
    let mut damaged = journal[..k].to_vec();
    if case.strip_newline && damaged.last() == Some(&b'\n') {
        damaged.pop();
    }
    let sk = usize::from(case.salt_cut) % (salts.len() + 1);
    std::fs::write(&path, &damaged).unwrap();
    std::fs::write(JournaledLog::salts_path(&path), &salts[..sk]).unwrap();
    let _ = std::fs::remove_file(format!("{path}.lock"));

    let resumed = JournaledLog::resume(&path);
    if damaged.len() < header_end {
        assert!(resumed.is_err());
        let _ = std::fs::remove_dir_all(&dir);
        return;
    }
    let (mut jl, _) = resumed.expect("a journal with a complete header always resumes");
    let expected = ends
        .iter()
        .filter(|(end, leaf)| *leaf && *end <= damaged.len())
        .count() as u64;
    assert_eq!(jl.log().tree_size(), expected, "every complete leaf record survives");
    jl.append_intent(b"post-crash").unwrap();
    jl.sync().unwrap();
    let live = jl.log().root_hex();
    drop(jl);
    let (again, report) = JournaledLog::resume(&path).expect("second resume");
    assert_eq!(report.dropped_trailing_lines, 0);
    assert_eq!(again.log().tree_size(), expected + 1);
    assert_eq!(again.log().root_hex(), live);
    drop(again);
    let _ = std::fs::remove_dir_all(&dir);
});
