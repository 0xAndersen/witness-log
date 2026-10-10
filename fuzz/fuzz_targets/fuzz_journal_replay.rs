//! Journal files are read back after crashes — arbitrary tail damage is
//! the expected case, so replay must be total over arbitrary bytes.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let path =
        std::env::temp_dir().join(format!("witness-log-fuzz-journal-{}", std::process::id()));
    if std::fs::write(&path, data).is_ok() {
        let _ = witness_log_core::journal::LeafJournal::replay(path.to_str().unwrap());
        let _ = std::fs::remove_file(&path);
    }
});
