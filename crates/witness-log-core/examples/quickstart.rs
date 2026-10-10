//! The whole integration, in one runnable file.
//!
//!     cargo run -p witness-log-core --example quickstart
//!
//! Copy this file, change the payloads, ship it. Every line is real —
//! nothing here is pseudocode and nothing is elided. It writes a journal
//! and a dossier to a temp directory and cleans up after itself.
//!
//! Read top to bottom it answers, in order: how do I create an agent
//! identity, how do I log what my agent did, how do I survive a restart,
//! how do I prove any of it to someone else, and what does that proof
//! actually mean.

use ed25519_dalek::SigningKey;
use witness_log_core::identity::IdentityKeypair;
use witness_log_core::journal::JournaledLog;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let dir = std::env::temp_dir().join(format!("witnesslog-quickstart-{}", std::process::id()));
    std::fs::create_dir_all(&dir)?;
    let journal_path = dir.join("agent.jsonl");
    let journal_path = journal_path.to_str().ok_or("non-UTF-8 temp path")?;

    // ── 1. Identity ────────────────────────────────────────────────
    // Generate once, persist the 32-byte seed somewhere safe, reuse it
    // forever. This is your agent's long-lived identity. A short-lived
    // session key signs individual leaves and is cryptographically bound
    // to this identity, so a checkpoint stays verifiable long after the
    // process that produced it has exited.
    let identity = IdentityKeypair::generate();
    let identity_seed = identity.to_bytes(); // persist this; treat as a private key
    let identity_hex = identity.public_hex(); // publish this; it's your agent's name
    println!("1. identity: {}", &identity_hex[..16]);

    // ── 2. Log what the agent does ─────────────────────────────────
    // JournaledLog streams every append to disk, so a crash loses at
    // most the last unsynced write. Use this for anything long-lived;
    // plain WitnessLog keeps everything in memory only.
    // `create` takes the identity. A journal with no stable identity
    // produces dossiers nobody can attribute, so it's a required argument
    // rather than something generated silently.
    let mut log = JournaledLog::create(journal_path, IdentityKeypair::from_bytes(&identity_seed))?;

    // Log the decision BEFORE acting, and the outcome after. The pair is
    // what makes "the agent intended X and Y happened" checkable later.
    log.append_intent(br#"{"tool":"transfer_funds","args":{"usd":250,"to":"acct_88f2"}}"#)?;
    // ... your agent actually does the thing here ...
    log.append_result(br#"{"status":"ok","tx_id":"tx_7ac31"}"#)?;

    // Payloads are hashed with a per-leaf salt, never stored in the
    // clear. Logging an email address is safe; it can be erased later
    // without invalidating any proof over the surrounding history.
    let pii_leaf = log.append_memory(b"user contact: alice@example.com")?;

    // append never touches the disk or the network and never blocks.
    // You choose when durability happens:
    log.sync()?; // fsync — call from spawn_blocking if you're async
    println!("2. logged {} events", log.log().tree_size());

    // ── 3. Right to be forgotten ───────────────────────────────────
    // Deletes the salt, making the payload permanently unrecoverable,
    // and appends a tombstone recording that the redaction happened.
    // Every previously-issued proof still verifies: erasing the data did
    // not rewrite the history around it.
    let root_before = log.log().root_hex();
    log.forget(pii_leaf)?;
    log.sync()?;
    println!(
        "3. redacted leaf {pii_leaf}; prior root {} still provable",
        &root_before[..16]
    );

    // ── 4. Survive a restart ───────────────────────────────────────
    drop(log);
    let (restored, report) = JournaledLog::resume(journal_path)?;
    if report.dropped_trailing_lines > 0 {
        // A torn final line means the process died mid-write. It's
        // dropped and the file is truncated so the next append lands
        // cleanly. Surfaced rather than silent, so you can alert on it.
        eprintln!(
            "   note: recovered from an unclean shutdown ({} torn line)",
            report.dropped_trailing_lines
        );
    }
    println!(
        "4. resumed from disk: {} leaves",
        restored.log().tree_size()
    );

    // ── 5. Checkpoint and export ───────────────────────────────────
    // A checkpoint is a signed commitment to the whole history so far.
    // It's O(log n) — cheap enough to call often, even on a large log.
    let signing_key = SigningKey::from_bytes(&identity_seed);
    let checkpoint = restored.log().checkpoint(&signing_key);
    println!(
        "5. checkpoint: size {} root {}",
        checkpoint.tree_size,
        &checkpoint.root_hash[..16]
    );

    // A dossier is the portable, offline-verifiable bundle you hand to
    // someone else. It needs no server and no network to check.
    let dossier = serde_json::json!({
        "identity_pubkey": identity_hex,
        "leaves": restored.log().leaves(),
        "checkpoint": checkpoint,
        "witness_receipts": [],
        "witness_directory": { "witnesses": [] },
        "key_bindings": restored.log().all_bindings(),
        "revocations": [],
    });
    let dossier_path = dir.join("dossier.json");
    std::fs::write(&dossier_path, serde_json::to_string_pretty(&dossier)?)?;
    println!("6. wrote {}", dossier_path.display());

    // ── 6. What this proves, and what it doesn't ───────────────────
    println!();
    println!("   Verify it:");
    println!("     witness-log verify {}", dossier_path.display());
    println!();
    println!("   That run returns UNANCHORED — it proves the dossier doesn't");
    println!("   contradict itself, and nothing more, because every input came");
    println!("   from the file itself. To prove something to a party that");
    println!("   doesn't already trust you, the verifier supplies an identity");
    println!("   they expected and a witness directory THEY trust:");
    println!();
    println!("     witness-log verify {} \\", dossier_path.display());
    println!("       --identity {identity_hex} \\");
    println!("       --directory <a-directory-you-trust.json>");
    println!();
    println!("   See `witness-log explain` for what each verdict does and");
    println!("   does NOT establish, and THREAT_MODEL.md before relying on it.");

    // Clean up. Delete this block if you want to inspect the artifacts.
    std::fs::remove_dir_all(&dir).ok();
    Ok(())
}
