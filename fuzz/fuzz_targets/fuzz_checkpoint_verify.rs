#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        if let Ok(sth) = serde_json::from_str::<witness_log_core::sth::SignedTreeHead>(s) {
            let _ = sth.verify();
        }
    }
});
