//! `witness-log demo` — a self-contained, zero-argument worked example,
//! and `witness-log demo --tamper`, which builds a genuinely convincing
//! forgery and watches verification catch it.
//!
//! Everything here happens in memory. No files are written, no network
//! calls are made, and every keypair generated is thrown away when the
//! process exits — this is a teaching aid, not a key-management tool.

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use std::process::ExitCode;
use witness_log_core::identity::IdentityKeypair;
use witness_log_core::log::WitnessLog;
use witness_log_network::{
    Dossier, Verdict, VerifyContext, WitnessDirectory, WitnessEntry, WitnessReceipt, WitnessRuntime,
};

/// A fixed timestamp so demo output is stable across runs — makes the
/// output diffable and screenshot-comparable. Real logs use wall-clock time.
const DEMO_NOW_MS: u64 = 1_700_000_000_000;

fn rule() {
    println!("  {}", "─".repeat(66));
}

fn short(hexstr: &str) -> String {
    let chars: Vec<char> = hexstr.chars().collect();
    if chars.len() > 16 {
        let head: String = chars[..8].iter().collect();
        let tail: String = chars[chars.len() - 8..].iter().collect();
        format!("{head}…{tail}")
    } else {
        hexstr.to_string()
    }
}

/// Build a witness directory with `n` independent operators plus one
/// project-operated witness, and countersign `sth` with each. Returns the
/// directory and the receipts separately, because keeping them separate is
/// the entire point — see `VerifyContext`.
fn build_witnesses(
    sth: &witness_log_core::sth::SignedTreeHead,
) -> (WitnessDirectory, Vec<WitnessReceipt>) {
    let mut directory = WitnessDirectory::default();
    let mut receipts = Vec::new();
    let independents = [
        ("university-security-lab", "example-university", "on-prem"),
        ("northwind-audit-coop", "northwind-cooperative", "hetzner"),
        ("agent-collective-witness", "agent-collective", "aws"),
    ];
    for (name, org, provider) in independents {
        let k = SigningKey::generate(&mut OsRng);
        directory.witnesses.push(WitnessEntry {
            name: name.into(),
            operator_org: org.into(),
            url: format!("https://{name}.example"),
            pubkey: hex::encode(k.verifying_key().to_bytes()),
            runtime: WitnessRuntime::Human,
            compute_provider: Some(provider.into()),
            is_project_operated: false,
        });
        receipts.push(WitnessReceipt::sign(&k, sth, DEMO_NOW_MS + 1000));
    }
    // One project-operated bootstrap witness, disclosed honestly. It
    // countersigns like any other, but collapses into a single diversity
    // bucket regardless of how it's labeled — see GOVERNANCE.md.
    let k = SigningKey::generate(&mut OsRng);
    directory.witnesses.push(WitnessEntry {
        name: "witnesslog-bootstrap-1".into(),
        operator_org: "witnesslog-project".into(),
        url: "https://bootstrap-1.witnesslog.example".into(),
        pubkey: hex::encode(k.verifying_key().to_bytes()),
        runtime: WitnessRuntime::Agent,
        compute_provider: Some("fly.io".into()),
        is_project_operated: true,
    });
    receipts.push(WitnessReceipt::sign(&k, sth, DEMO_NOW_MS + 1000));
    (directory, receipts)
}

pub fn run_demo() -> ExitCode {
    println!();
    println!("  witness-log demo — everything below runs in memory, writes nothing,");
    println!("  and talks to no network. Throwaway keys, generated fresh each run.");
    println!();
    rule();
    println!();

    // 1. Identity
    let identity = IdentityKeypair::generate();
    let identity_bytes = identity.to_bytes();
    let identity_hex = identity.public_hex();
    let mut log = WitnessLog::resume(identity, 0);
    println!("  1. Created an agent identity");
    println!("     {}", short(&identity_hex));
    println!("     Long-lived. A short-lived session key signs individual leaves and is");
    println!("     cryptographically bound to this identity — so a checkpoint stays");
    println!("     verifiable after the process that made it is long gone.");
    println!();

    // 2. Log some agent activity
    log.append_intent(br#"{"tool":"transfer_funds","args":{"amount_usd":250,"to":"acct_88f2"}}"#);
    log.append_result(br#"{"status":"ok","tx_id":"tx_7ac31"}"#);
    let pii_index = log.append_memory(b"user contact on file: alice@example.com");
    println!("  2. Logged three events");
    println!("     [0] INTENT  transfer_funds($250)      what the agent decided to do");
    println!("     [1] RESULT  ok, tx_7ac31              what actually happened");
    println!("     [2] MEMORY  (contains an email address)");
    println!("     Tree size: {}", log.tree_size());
    println!();

    // 3. Redaction — the surprising part
    let root_before = log.root_hex();
    log.forget(pii_index);
    println!("  3. Right-to-be-forgotten on leaf [2]");
    println!("     The payload's salt is deleted, making the content permanently");
    println!("     unrecoverable. A tombstone leaf records that the redaction happened.");
    println!("     Root before redaction:  {}", short(&root_before));
    println!("     Every previously-issued proof over leaves [0] and [1] still verifies:");
    println!("     erasing data did NOT invalidate the history around it.");
    println!();

    // 4. Checkpoint
    let signing_key = SigningKey::from_bytes(&identity_bytes);
    let sth = log.checkpoint(&signing_key);
    println!("  4. Signed a checkpoint");
    println!(
        "     tree_size {}  root {}",
        sth.tree_size,
        short(&sth.root_hash)
    );
    println!("     Signed by the identity key, not the session key.");
    println!();

    // 5. Witnesses
    let (directory, receipts) = build_witnesses(&sth);
    println!("  5. Four witnesses countersigned that checkpoint");
    for w in &directory.witnesses {
        let tag = if w.is_project_operated {
            "  (project-operated, disclosed)"
        } else {
            ""
        };
        println!("     · {:<26} {}{}", w.name, w.operator_org, tag);
    }
    println!();
    rule();
    println!();

    let dossier = Dossier {
        identity_pubkey: identity_hex.clone(),
        leaves: log.leaves().to_vec(),
        checkpoint: sth,
        witness_receipts: receipts,
        witness_directory: directory.clone(),
        key_bindings: log.all_bindings(),
        revocations: vec![],
        fleet_anchor: None,
    };

    // 6. The point: same bytes, two different questions.
    println!("  Now verify it — twice, over the exact same bytes.");
    println!();

    let unanchored = dossier.verify(0.66, &VerifyContext::default());
    println!("  A. With nothing supplied from outside the dossier:");
    println!();
    println!("       Verdict: {}", unanchored.verdict);
    println!();
    println!("     Every signature checked out. The Merkle root rebuilt correctly.");
    println!("     But every input came from the file itself — including the list of");
    println!("     witnesses it wants you to trust. This proves the file doesn't");
    println!("     contradict itself. It proves nothing about who wrote it.");
    println!();

    let ctx = VerifyContext {
        expected_identity_pubkey: Some(&identity_hex),
        trusted_directory: Some(&directory),
        min_receipts: None,
        revocations: &[],
        known_heads: &[],
        evidence: &[],
        subject_org: None,
        accept_fleet_anchor: false,
    };
    let anchored = dossier.verify(0.66, &ctx);
    println!("  B. With an identity you expected and a witness directory YOU trust,");
    println!("     both obtained out-of-band:");
    println!();
    println!("       Verdict: {}", anchored.verdict);
    if let Some(q) = &anchored.quorum {
        println!();
        println!(
            "       {}/{} witness signatures valid",
            q.valid_receipts, q.total_directory_witnesses
        );
        println!(
            "       operator diversity          {:.0}%  ({} of {} distinct operator buckets)",
            q.diversity_fraction * 100.0,
            q.distinct_operators_represented,
            q.distinct_operators_in_directory
        );
        println!(
            "       compute-provider diversity  {:.0}%  ({} of {} distinct providers)",
            q.compute_diversity_fraction * 100.0,
            q.distinct_compute_providers_represented,
            q.distinct_compute_providers_in_directory
        );
        if q.project_operated_receipts > 0 {
            println!();
            println!(
                "       Note: {} of those {} signatures is project-operated. Every",
                q.project_operated_receipts, q.valid_receipts
            );
            println!("       project-operated witness collapses into ONE shared bucket on both");
            println!("       diversity axes, however differently they're labeled — so ten");
            println!("       project-run witnesses would score exactly like one. The counts");
            println!(
                "       above already reflect that collapse; they are not raw witness counts."
            );
        }
    }
    println!();
    rule();
    println!();
    println!("  Same bytes. Different question asked.");
    println!();
    println!("  That gap is the whole idea: a log can be perfectly self-consistent and");
    println!("  still tell you nothing, until you anchor verification to something its");
    println!("  author doesn't control.");
    println!();
    println!("  Next:");
    println!("    witness-log demo --tamper     watch a convincing forgery get caught");
    println!("    witness-log explain unanchored    what each verdict does and doesn't mean");
    println!("    witness-log verify examples/sample-dossier.json --explain");
    println!();
    exit_for(&anchored.verdict)
}

pub fn run_demo_tamper() -> ExitCode {
    println!();
    println!("  witness-log demo --tamper");
    println!();
    println!("  Building a forgery the way an attacker actually would — not a broken");
    println!("  file, a convincing one. Every signature in it will be valid.");
    println!();
    rule();
    println!();

    // The victim: a real identity the attacker wants to frame.
    let victim = IdentityKeypair::generate();
    let victim_hex = victim.public_hex();
    println!("  The victim's real, publicly-known identity:");
    println!("    {}", short(&victim_hex));
    println!();

    // The attacker builds an entirely invented history under their OWN key.
    let attacker = IdentityKeypair::generate();
    let attacker_bytes = attacker.to_bytes();
    let attacker_hex = attacker.public_hex();
    let mut forged = WitnessLog::resume(attacker, 0);
    forged.append_intent(br#"{"tool":"transfer_funds","args":{"amount_usd":10000000}}"#);
    forged.append_result(br#"{"status":"ok","tx_id":"tx_forged"}"#);
    let attacker_signing = SigningKey::from_bytes(&attacker_bytes);
    let forged_sth = forged.checkpoint(&attacker_signing);

    println!("  Step 1 — generate our own keypair (not the victim's)");
    println!("           {}", short(&attacker_hex));
    println!("  Step 2 — invent a history: transfer_funds($10,000,000)");
    println!("  Step 3 — sign a checkpoint over it with our own key");
    println!("           This signature is genuinely, cryptographically valid.");
    println!("  Step 4 — label the dossier with the VICTIM's public key");
    println!("  Step 5 — generate three 'independent auditors'. Also ours.");
    println!("  Step 6 — ship our own witness directory alongside the dossier,");
    println!("           listing those three under convincing-sounding org names.");
    println!();

    let mut fake_directory = WitnessDirectory::default();
    let mut fake_receipts = Vec::new();
    for org in [
        "global-audit-partners",
        "verified-systems-gmbh",
        "trustchain-labs",
    ] {
        let k = SigningKey::generate(&mut OsRng);
        fake_directory.witnesses.push(WitnessEntry {
            name: org.into(),
            operator_org: org.into(),
            url: format!("https://{org}.example"),
            pubkey: hex::encode(k.verifying_key().to_bytes()),
            runtime: WitnessRuntime::Human,
            compute_provider: Some(format!("{org}-infra")),
            is_project_operated: false, // the attacker sets this field, of course
        });
        fake_receipts.push(WitnessReceipt::sign(&k, &forged_sth, DEMO_NOW_MS));
    }

    let forgery = Dossier {
        identity_pubkey: victim_hex.clone(), // the lie
        leaves: forged.leaves().to_vec(),
        checkpoint: forged_sth,
        witness_receipts: fake_receipts,
        witness_directory: fake_directory,
        key_bindings: vec![],
        revocations: vec![],
        fleet_anchor: None,
    };

    rule();
    println!();
    println!("  Every signature in this file is valid. Verifying it:");
    println!();

    let report = forgery.verify(0.66, &VerifyContext::default());
    let mark = |ok: bool| if ok { "\u{2713}" } else { "\u{2717}" };
    println!(
        "    {} Checkpoint signature valid",
        mark(report.checkpoint_signature_valid)
    );
    println!(
        "    {} Leaf structure valid",
        mark(report.leaves_structurally_valid)
    );
    println!(
        "    {} Merkle continuity verified",
        mark(report.merkle_continuity_valid)
    );
    println!("    {} Identity bound", mark(report.identity_bound));
    if !report.identity_bound {
        println!("        dossier claims:  {}", short(&victim_hex));
        println!("        actually signed by: {}", short(&attacker_hex));
    }
    println!();
    println!("    Verdict: {}", report.verdict);
    println!();
    rule();
    println!();
    println!("  The forgery had flawless cryptography. It failed on a question");
    println!("  cryptography doesn't answer by itself: whose log is this?");
    println!();
    println!("  Two independent things caught it:");
    println!();
    println!("   1. The dossier's claimed identity didn't match the key that actually");
    println!("      signed its checkpoint. Nothing else in the file could hide that.");
    println!();
    println!("   2. Even with a matching identity, the three 'independent auditors'");
    println!("      came from a directory the attacker shipped. Receipts are only ever");
    println!("      scored against a directory the VERIFIER supplies — so a fabricated");
    println!("      dossier tops out at UNANCHORED no matter how well-witnessed it");
    println!("      claims to be. Try it: the attacker cannot reach WITNESSED.");
    println!();
    exit_for(&report.verdict)
}

fn exit_for(verdict: &Verdict) -> ExitCode {
    ExitCode::from(match verdict {
        Verdict::Witnessed => 0u8,
        Verdict::ConsistentUnwitnessed => 10,
        Verdict::Unanchored => 20,
        Verdict::Diverged => 30,
        Verdict::Invalid => 40,
    })
}
