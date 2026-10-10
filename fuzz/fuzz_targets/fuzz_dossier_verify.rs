//! The primary attacker-controlled surface: `witness-log verify <file>` parses
//! and fully verifies arbitrary bytes. Nothing here may panic.
#![no_main]
use libfuzzer_sys::fuzz_target;
use witness_log_network::VerifyContext;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        if let Ok(dossier) = serde_json::from_str::<witness_log_network::Dossier>(s) {
            let _ = dossier.verify(0.66, &VerifyContext::default());
        }
    }
});
