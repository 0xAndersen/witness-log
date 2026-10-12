//! Per-call overhead budget: what an agent pays for each recorded step,
//! and what a verifier pays for a 10,000-leaf dossier.
//!
//! A plain timed harness (no criterion: no extra dependencies to audit).
//! Every repetition times a calibration loop (SHA-256 over 1 KiB, the
//! operation appends are dominated by) immediately before the metric, and
//! records `metric / calibration`. The median of those ratios is what
//! `benches/check_budget.py` compares with the committed baseline: a
//! shared runner that is slow for a few seconds slows both halves of a
//! repetition, so the ratio moves far less than the raw time does.
//!
//! ```sh
//! cargo bench -p witness-log-network --bench overhead      # writes <workspace>/target/bench-rust.json
//! python3 benches/check_budget.py target/bench-rust.json
//! ```

use sha2::{Digest, Sha256};
use std::hint::black_box;
use std::time::{Duration, Instant};
use witness_log_core::identity::IdentityKeypair;
use witness_log_core::journal::JournaledLog;
use witness_log_core::log::WitnessLog;
use witness_log_network::{Dossier, VerifyContext};

const REPS: usize = 21;
const APPENDS: usize = 2_000;
const CALIBRATION_ITERS: usize = 2_000;
const VERIFY_LEAVES: usize = 10_000;

fn median(mut v: Vec<f64>) -> f64 {
    v.sort_by(|a, b| a.total_cmp(b));
    v[v.len() / 2]
}

fn calibration_ns() -> f64 {
    let buf = [7u8; 1024];
    let t = Instant::now();
    for _ in 0..CALIBRATION_ITERS {
        black_box(Sha256::digest(black_box(&buf)));
    }
    t.elapsed().as_nanos() as f64 / CALIBRATION_ITERS as f64
}

struct Metric {
    ns: f64,
    normalized: f64,
}

/// `run(n)` returns the time for `n` iterations; reported per iteration.
fn measure(n: usize, mut run: impl FnMut(usize) -> Duration) -> Metric {
    let mut raw = Vec::with_capacity(REPS);
    let mut ratio = Vec::with_capacity(REPS);
    for _ in 0..REPS {
        let cal = calibration_ns();
        let ns = run(n).as_nanos() as f64 / n as f64;
        raw.push(ns);
        ratio.push(ns / cal);
    }
    Metric {
        ns: median(raw),
        normalized: median(ratio),
    }
}

fn payload(i: usize) -> Vec<u8> {
    format!(r#"{{"tool":"transfer_funds","args":[{i}],"kwargs":{{}},"t":1700000000.0}}"#)
        .into_bytes()
}

fn main() {
    let out_path = std::env::args()
        .skip_while(|a| a != "--out")
        .nth(1)
        // cargo runs benches from the package directory; default to the
        // workspace target/ so the file lands where check_budget.py looks.
        .unwrap_or_else(|| {
            concat!(env!("CARGO_MANIFEST_DIR"), "/../../target/bench-rust.json").into()
        });

    // In-memory append. One recorded step (intent + result) is two.
    let append_inmem = measure(APPENDS, |n| {
        let mut log = WitnessLog::resume(IdentityKeypair::generate(), 0);
        let payloads: Vec<Vec<u8>> = (0..n).map(payload).collect();
        let t = Instant::now();
        for p in &payloads {
            black_box(log.append_intent(p));
        }
        t.elapsed()
    });

    // Journaled append, no fsync (the default: the OS batches writes).
    let dir = std::env::temp_dir().join(format!("wl-bench-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("temp dir");
    let mut run = 0usize;
    let append_journaled = measure(APPENDS, |n| {
        run += 1;
        let path = dir.join(format!("j{run}.jsonl"));
        let path = path.to_str().expect("utf-8 temp path");
        let mut j = JournaledLog::create_ephemeral(path).expect("create journal");
        let payloads: Vec<Vec<u8>> = (0..n).map(payload).collect();
        let t = Instant::now();
        for p in &payloads {
            black_box(j.append_intent(p).expect("append"));
        }
        t.elapsed()
    });
    let _ = std::fs::remove_dir_all(&dir);

    // Verify a 10k-leaf dossier, identity pinned (no directory, no quorum).
    let mut log = WitnessLog::resume(IdentityKeypair::generate(), 0);
    for i in 0..VERIFY_LEAVES {
        if i % 2 == 0 {
            log.append_intent(&payload(i));
        } else {
            log.append_result(&payload(i));
        }
    }
    let dossier = Dossier::from_log(&log, log.checkpoint_self());
    let id = log.identity_pubkey_hex();
    let ctx = VerifyContext {
        expected_identity_pubkey: Some(&id),
        ..Default::default()
    };
    assert!(dossier.verify(0.66, &ctx).internally_consistent);
    let verify_10k = measure(1, |_| {
        let t = Instant::now();
        black_box(dossier.verify(0.66, &ctx));
        t.elapsed()
    });

    let m = |name: &str, x: &Metric| {
        format!(
            "    \"{name}\": {{\"ns\": {:.1}, \"normalized\": {:.4}}}",
            x.ns, x.normalized
        )
    };
    let json = format!(
        "{{\n  \"suite\": \"rust\",\n  \"calibration\": \"sha256 of 1 KiB\",\n  \"metrics\": {{\n{},\n{},\n{}\n  }}\n}}\n",
        m("rust_append_inmem", &append_inmem),
        m("rust_append_journaled_nosync", &append_journaled),
        m("rust_verify_10k_leaves", &verify_10k),
    );
    print!("{json}");
    if let Some(parent) = std::path::Path::new(&out_path).parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    std::fs::write(&out_path, json).expect("write bench output");
    eprintln!("wrote {out_path}");
}
