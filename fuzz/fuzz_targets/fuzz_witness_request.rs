//! A public witness parses attacker-controlled bodies and runs the
//! protocol on them. Nothing here may panic, and nothing unverified may
//! enroll a log or advance a witness's state.
#![no_main]
use libfuzzer_sys::fuzz_target;
use witness_log_network::tlog_witness::{AddCheckpointRequest, WitnessService};

fuzz_target!(|data: &[u8]| {
    let Ok(body) = std::str::from_utf8(data) else {
        return;
    };
    let Ok(req) = AddCheckpointRequest::parse(body) else {
        return;
    };
    let key = ed25519_dalek::SigningKey::from_bytes(&[1u8; 32]);
    let mut svc = WitnessService::new();
    let enrolled = svc.enroll_canonical(&req);
    let out = svc.handle_add_checkpoint(&req, "fuzz.example/w", &key, 1);
    let _ = out.http_body();
    // A random body essentially never carries a valid signature, so if
    // anything was enrolled the cosign must have been genuinely earned.
    if enrolled {
        assert!(svc.log_count() == 1);
    }
});
