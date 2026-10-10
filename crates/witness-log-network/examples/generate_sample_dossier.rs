//! Generates `examples/sample-dossier.json`, used as the worked example in
//! README.md and as a smoke-test fixture. Run with:
//!   cargo run -p witness-log-network --example generate_sample_dossier

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};
use witness_log_core::identity::IdentityKeypair;
use witness_log_core::log::WitnessLog;
use witness_log_network::{WitnessDirectory, WitnessEntry, WitnessReceipt, WitnessRuntime};

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

fn main() {
    // 1. An agent's persistent identity, and a fresh session for this run.
    let identity = IdentityKeypair::generate();
    let identity_bytes = identity.to_bytes();
    let mut log = WitnessLog::resume(identity, 0);

    // 2. A realistic sequence: an intent, its result, a memory note
    //    containing something that will later need to be forgotten.
    log.append_intent(br#"{"tool":"transfer_funds","args":{"to":"acct_9f2","amount_usd":250}}"#);
    log.append_result(br#"{"status":"ok","tx_id":"tx_7ac31"}"#);
    let pii_index = log.append_memory(b"contact: alice@example.com, +1-555-0100");
    log.append_intent(br#"{"tool":"send_email","args":{"template":"receipt"}}"#);
    log.append_result(br#"{"status":"sent"}"#);

    // 3. Right-to-be-forgotten on the PII leaf. Tree continuity is
    //    unaffected — this is the property demonstrated in
    //    log::tests::forget_preserves_continuity_for_other_leaves.
    log.forget(pii_index);

    // 4. Checkpoint, signed by the identity key.
    let identity_signing_key = SigningKey::from_bytes(&identity_bytes);
    let sth = log.checkpoint(&identity_signing_key);

    // 5. Witnessing. Two receipts from genuinely distinct operators, plus a
    //    third witness present in the directory that never signed —
    //    deliberately included so the sample demonstrates a realistic,
    //    partial-diversity outcome rather than a too-clean 100% case. One
    //    witness is agent-operated (continuous polling + consistency-proof
    //    checking, see examples/agent_witness.rs) and one is human-operated,
    //    to show both runtime kinds coexisting in the same directory.
    let mut directory = WitnessDirectory::default();
    let mut receipts = Vec::new();

    let witness_a_key = SigningKey::generate(&mut OsRng);
    directory.witnesses.push(WitnessEntry {
        name: "example-university-security-lab".into(),
        operator_org: "example-university".into(),
        url: "https://witness.example-university.edu".into(),
        pubkey: hex::encode(witness_a_key.verifying_key().to_bytes()),
        runtime: WitnessRuntime::Human,
        compute_provider: None,
        is_project_operated: false,
    });
    receipts.push(WitnessReceipt::sign(&witness_a_key, &sth, now_ms()));

    let witness_b_key = SigningKey::generate(&mut OsRng);
    directory.witnesses.push(WitnessEntry {
        name: "example-infra-co-agent-witness".into(),
        operator_org: "example-infra-co".into(),
        url: "https://witness.example-infra.co".into(),
        pubkey: hex::encode(witness_b_key.verifying_key().to_bytes()),
        runtime: WitnessRuntime::Agent,
        compute_provider: Some("example-inference-provider-a".into()),
        is_project_operated: false,
    });
    receipts.push(WitnessReceipt::sign(&witness_b_key, &sth, now_ms()));

    // Listed in the directory, but did not sign — shows up as reduced
    // diversity/quorum in `witness-log verify`, honestly.
    let witness_c_key = SigningKey::generate(&mut OsRng);
    directory.witnesses.push(WitnessEntry {
        name: "example-nonresponsive-witness".into(),
        operator_org: "example-third-org".into(),
        url: "https://witness.example-third.org".into(),
        pubkey: hex::encode(witness_c_key.verifying_key().to_bytes()),
        runtime: WitnessRuntime::Agent,
        compute_provider: Some("example-inference-provider-b".into()),
        is_project_operated: false,
    });

    // A bootstrap witness run by the WitnessLog project itself, honestly
    // disclosed as such (see WitnessEntry::is_project_operated's doc
    // comment). This is what network bootstrapping is supposed to look
    // like: present, functioning, and impossible to mistake for an
    // independent third party in `witness-log verify`'s output.
    let bootstrap_key = SigningKey::generate(&mut OsRng);
    directory.witnesses.push(WitnessEntry {
        name: "witness-log-project-bootstrap-witness-01".into(),
        operator_org: "witness-log-project".into(),
        url: "https://witness-01.witness-log.dev".into(),
        pubkey: hex::encode(bootstrap_key.verifying_key().to_bytes()),
        runtime: WitnessRuntime::Agent,
        compute_provider: Some("witness-log-project-infra".into()),
        is_project_operated: true,
    });
    receipts.push(WitnessReceipt::sign(&bootstrap_key, &sth, now_ms()));

    let dossier = witness_log_network::Dossier {
        identity_pubkey: log.identity_pubkey_hex(),
        leaves: log.leaves().to_vec(),
        checkpoint: sth.clone(),
        witness_receipts: receipts,
        witness_directory: directory.clone(),
        key_bindings: log.all_bindings(),
        revocations: vec![],
    };

    let out_path = "examples/sample-dossier.json";
    fs::create_dir_all("examples").unwrap();
    fs::write(out_path, serde_json::to_string_pretty(&dossier).unwrap()).unwrap();
    println!("wrote {out_path}");

    // A separate trusted-directory file: what a REAL verifier would hold
    // out-of-band, never read from the dossier under test. This is what
    // README.md's quickstart passes via --directory to actually reach
    // WITNESSED, rather than silently capping at UNANCHORED. See the
    // pre-launch review, finding 02 and finding 26.
    let trusted_directory_path = "examples/trusted-directory.json";
    fs::write(
        trusted_directory_path,
        serde_json::to_string_pretty(&directory).unwrap(),
    )
    .unwrap();
    println!("wrote {trusted_directory_path}");

    println!("identity (for --identity): {}", log.identity_pubkey_hex());
    println!("tree size: {}", log.tree_size());
    println!("root: {}", log.root_hex());
}
