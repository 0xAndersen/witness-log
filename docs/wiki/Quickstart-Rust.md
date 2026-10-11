# Quickstart: Rust

MSRV 1.75. Two crates: `witness-log-core` (log, Merkle, identity, redaction,
journal, C2SP encoding) and `witness-log-network` (witnesses, quorum,
dossiers, verification).

```toml
[dependencies]
witness-log-core = "0.3"
witness-log-network = "0.3"
# or: { git = "https://github.com/0xAndersen/witness-log", tag = "v0.3.3" }
```

```rust
use witness_log_core::identity::IdentityKeypair;
use witness_log_core::journal::JournaledLog;
use witness_log_network::{Dossier, VerifyContext};

fn main() -> std::io::Result<()> {
    // First run: a new identity. Every later run: JournaledLog::resume("agent.jsonl").
    let identity = IdentityKeypair::generate();
    let mut log = JournaledLog::create("agent.jsonl", identity)?;

    log.append_intent(br#"{"tool":"transfer_funds","args":{"amount_usd":250}}"#)?;
    log.append_result(br#"{"status":"ok","tx_id":"tx_7ac31"}"#)?;
    log.sync()?;

    let sth = log.log().checkpoint_self();                 // signed by the identity key
    let dossier = Dossier::from_log(log.log(), sth);       // the portable proof
    let report = dossier.verify(0.66, &VerifyContext::default());
    assert!(report.internally_consistent);
    println!("{}", serde_json::to_string_pretty(&dossier).unwrap());
    Ok(())
}
```

## Resume

```rust
let (mut log, report) = JournaledLog::resume("agent.jsonl")?;
if report.dropped_trailing_lines > 0 { /* a crash tore the last line; it was healed */ }
```

## Redaction

```rust
let i = log.append_memory(b"contact: alice@example.com")?;
assert!(log.forget(i)?);          // salt gone from agent.jsonl.salts, marker leaf appended
assert!(!log.can_forget(i));
```

## Proofs for a regulator

```rust
let key = ed25519_dalek::SigningKey::from_bytes(&log.log().identity_bytes());
let window = log.log().evidence_window(100..200, &key);  // leaves 100..199, each with an inclusion proof
assert!(window.verify().is_ok());
let proof = log.log().inclusion_proof(42);
let consistency = log.log().consistency_proof(1_000);     // from size 1000 to now
```

## Verify someone else's dossier

```rust
let dossier: Dossier = serde_json::from_str(&json)?;
let directory: WitnessDirectory = serde_json::from_str(&dir_json)?;
let report = dossier.verify(0.66, &VerifyContext {
    expected_identity_pubkey: Some(&expected_hex),
    trusted_directory: Some(&directory),
    min_receipts: Some(3),            // absolute gate; use it with large directories
});
match report.verdict {
    Verdict::Witnessed => {}
    other => return Err(format!("{other}").into()),
}
```

## Run a witness in your own server

`witness_log_network::tlog_witness::WitnessService` is the protocol state
machine with no I/O: feed it the body of each `POST /add-checkpoint`, persist
`export_state()` **before** returning the cosignature, and reply with what it
returns. `crates/witness-log-cli/src/witness_cmd.rs` is the reference
embedding. See [Running a witness](Running-a-Witness).

`cargo doc --open -p witness-log-core -p witness-log-network` for the full API.
