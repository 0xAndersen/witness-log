//! Writes the two agent journals that `clients/go/testdata/regen.sh` feeds
//! to `witness-log witness submit` to produce the golden dossiers the Go
//! and wasm verifiers are tested against.
//!
//!     cargo run -p witness-log-wasm --example golden_journals -- <out-dir>
//!
//! Agent A hands state to agent B and grants B a scope; B records the
//! matching Received / GrantedToMe leaves; A also records an ExternalAnchor
//! and redacts one leaf, so every leaf type a verifier must parse appears
//! in at least one of the two journals (0x00–0x03, 0x05–0x07; 0x04
//! KeyRevocation is exercised by the corpus and unit tests). Payloads are
//! fixed strings, so the salts are the only randomness; the salt sidecar
//! of A is read by the script to produce the disclosure fixture.

use std::fs;
use std::path::PathBuf;
use witness_log_core::identity::IdentityKeypair;
use witness_log_core::journal::JournaledLog;
use witness_log_core::leaf::AuthorizationEventKind;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let out = PathBuf::from(
        std::env::args()
            .nth(1)
            .ok_or("usage: golden_journals <out-dir>")?,
    );
    fs::create_dir_all(&out)?;
    let a_path = out.join("agent-a.jsonl");
    let b_path = out.join("agent-b.jsonl");
    let a_path = a_path.to_str().ok_or("non-UTF-8 path")?;
    let b_path = b_path.to_str().ok_or("non-UTF-8 path")?;

    let a_identity = IdentityKeypair::generate();
    let b_identity = IdentityKeypair::generate();
    let a_hex = a_identity.public_hex();
    let b_hex = b_identity.public_hex();

    let handoff_state = br#"{"task":"reconcile-invoices","cursor":"INV-0042","open_items":3}"#;
    let scope = br#"{"allow":["read:invoices","write:payments"],"ceiling_usd":500}"#;

    let mut a = JournaledLog::create(a_path, a_identity)?;
    a.append_intent(br#"{"tool":"read_invoice","args":{"invoice":"INV-0042"}}"#)?;
    a.append_result(br#"{"supplier":"acct_supplier_17","amount_due_usd":250}"#)?;
    let pii = a.append_memory(b"contact: ops@example.invalid")?;
    a.append_handoff_sent(handoff_state, &b_hex)?;
    a.append_authorization_event(AuthorizationEventKind::GrantedByMe, scope, &b_hex)?;
    a.append_external_anchor(
        "https://rekor.sigstore.dev/api/v1/log/entries/golden-fixture",
        r#"{"logIndex":1,"integratedTime":1700000000,"body":"golden fixture, not a real entry"}"#,
    )?;
    a.forget(pii)?;
    a.sync()?;

    let mut b = JournaledLog::create(b_path, b_identity)?;
    b.append_handoff_received(handoff_state, &a_hex)?;
    b.append_authorization_event(AuthorizationEventKind::GrantedToMe, scope, &a_hex)?;
    b.append_intent(
        br#"{"tool":"transfer_funds","args":{"to":"acct_supplier_17","amount_usd":250}}"#,
    )?;
    b.append_result(br#"{"status":"ok","tx_id":"tx_7ac31"}"#)?;
    b.sync()?;

    println!("{a_hex}");
    println!("{b_hex}");
    Ok(())
}
