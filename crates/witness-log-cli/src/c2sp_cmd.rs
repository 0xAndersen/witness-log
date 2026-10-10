//! `witness-log c2sp` — transparency-log interoperability commands.
//!
//! These exist so an operator can produce and check C2SP artifacts
//! without writing any Rust: render a dossier's checkpoint in C2SP form
//! to hand to an existing transparency-log witness, and verify the
//! signed notes and cosignatures that come back.
//!
//! See `spec/SPEC.md` §9.3 and `witness_log_core::c2sp`.

use std::process::ExitCode;
use witness_log_core::c2sp::{bridge, Checkpoint, Cosignature, SignedNote, VerifierKey};
use witness_log_network::Dossier;

const EXIT_OK: u8 = 0;
const EXIT_USAGE: u8 = 2;
const EXIT_DIVERGED: u8 = 30;

fn rule() {
    println!("  {}", "─".repeat(66));
}

/// `witness-log c2sp show <dossier.json> --origin <name>`
///
/// Render this dossier's checkpoint as a C2SP checkpoint body. Does NOT
/// sign — signing requires the log's private key, which this tool never
/// handles. Use `witness_log_core::c2sp::bridge::sign_as_c2sp` from the
/// process that holds the key.
pub fn run_show(dossier_path: &str, origin: &str) -> ExitCode {
    let raw = match std::fs::read_to_string(dossier_path) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("could not read {dossier_path}: {e}");
            return ExitCode::from(EXIT_USAGE);
        }
    };
    let dossier: Dossier = match serde_json::from_str(&raw) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("could not parse dossier: {e}");
            return ExitCode::from(EXIT_USAGE);
        }
    };
    let checkpoint = match bridge::checkpoint_from_sth(&dossier.checkpoint, origin) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("could not convert checkpoint: {e}");
            return ExitCode::from(EXIT_USAGE);
        }
    };
    let body = match checkpoint.note_text() {
        Ok(b) => b,
        Err(e) => {
            eprintln!("could not render note text: {e}");
            return ExitCode::from(EXIT_USAGE);
        }
    };

    println!();
    println!("  C2SP checkpoint body (c2sp.org/tlog-checkpoint)");
    rule();
    print!("{body}");
    rule();
    println!();
    println!("  This body is what a witness cosigns. It carries origin, tree size,");
    println!("  and root hash — and deliberately no timestamp: in C2SP, time is");
    println!("  asserted only by cosigners, never by the log itself.");
    println!();
    println!("  The log's verifier key, derived from the checkpoint's signing key:");
    println!();
    match hex::decode(&dossier.checkpoint.signer_pubkey)
        .ok()
        .and_then(|b| <[u8; 32]>::try_from(b).ok())
        .and_then(|b| ed25519_dalek::VerifyingKey::from_bytes(&b).ok())
    {
        Some(vk) => {
            println!("    {}", bridge::log_vkey(origin, &vk).encode());
            println!();
            println!("  Publish that vkey alongside the origin so witnesses and verifiers");
            println!("  can check this log's checkpoints. Note the base64 field may contain");
            println!("  '+' characters — parsers must split at the FIRST two separators.");
        }
        None => println!("    (checkpoint signer_pubkey is not a valid Ed25519 key)"),
    }
    println!();
    println!("  To sign this as a C2SP note, call bridge::sign_as_c2sp from the");
    println!("  process holding the identity key. This tool never touches private keys.");
    println!();
    ExitCode::from(EXIT_OK)
}

/// `witness-log c2sp verify <note.txt> --vkey <vkey> [--vkey <vkey>...]`
///
/// Verify a C2SP signed note against one or more verifier keys, and
/// report any cosignatures found.
pub fn run_verify(note_path: &str, vkey_strings: &[String]) -> ExitCode {
    let raw = match std::fs::read_to_string(note_path) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("could not read {note_path}: {e}");
            return ExitCode::from(EXIT_USAGE);
        }
    };
    let mut vkeys = Vec::new();
    for s in vkey_strings {
        match VerifierKey::parse(s) {
            Ok(k) => vkeys.push(k),
            Err(e) => {
                eprintln!("could not parse vkey {s:?}: {e}");
                return ExitCode::from(EXIT_USAGE);
            }
        }
    }
    if vkeys.is_empty() {
        eprintln!("at least one --vkey is required");
        eprintln!("  a note verified against no keys proves nothing — see SPEC.md §9.1");
        return ExitCode::from(EXIT_USAGE);
    }

    let note = match SignedNote::parse(&raw) {
        Ok(n) => n,
        Err(e) => {
            eprintln!("could not parse signed note: {e}");
            return ExitCode::from(EXIT_USAGE);
        }
    };

    println!();
    println!("  C2SP signed note verification");
    println!("    {note_path}");
    println!(
        "    {} signature line(s), {} trusted key(s) supplied",
        note.signatures.len(),
        vkeys.len()
    );
    println!();

    // Checkpoint body, if this note is a checkpoint.
    match Checkpoint::from_note(&note) {
        Ok(cp) => {
            println!("  ✓ Parses as a tlog-checkpoint");
            println!("      origin     {}", cp.origin);
            println!("      tree size  {}", cp.tree_size);
            println!("      root       {}", hex::encode(cp.root_hash));
            if !cp.extensions.is_empty() {
                println!(
                    "      {} extension line(s) — NOT RECOMMENDED by the spec,",
                    cp.extensions.len()
                );
                println!("      as monitors cannot audit them");
            }
        }
        Err(e) => {
            println!("  ⚠ Not a tlog-checkpoint body ({e})");
            println!("      Still verifiable as a plain signed note.");
        }
    }
    println!();

    // Cosignature keys (type 0x04) are checked separately below, against
    // the cosignature/v1 message; only plain note keys count here.
    let cosig_keys: Vec<&VerifierKey> = vkeys
        .iter()
        .filter(|k| k.sig_type == witness_log_core::c2sp::SIG_TYPE_COSIGNATURE_V1)
        .collect();
    let mut verdict = match note.verify(&vkeys) {
        Ok(names) => {
            println!("  ✓ Verified by {} known key(s):", names.len());
            for n in &names {
                println!("      {n}");
            }
            // Signatures that match none of the supplied keys of either
            // type are ignored per signed-note §Signatures. Cosignature
            // lines for supplied 0x04 keys are NOT ignored: see below.
            let known_cosigs = note
                .signatures
                .iter()
                .filter(|s| {
                    cosig_keys
                        .iter()
                        .any(|k| k.name == s.key_name && k.id == s.key_id)
                })
                .count();
            let ignored = note.signatures.len() - names.len() - known_cosigs;
            if ignored > 0 {
                println!();
                println!("  {ignored} signature(s) from unknown keys were IGNORED, per");
                println!("  signed-note §Signatures. That is what lets witness cosignatures");
                println!("  accumulate on a checkpoint without breaking the log's verifiers.");
            }
            EXIT_OK
        }
        Err(e) => {
            println!("  ✗ Verification FAILED: {e}");
            EXIT_DIVERGED
        }
    };

    // Cosignatures from keys the caller supplied are part of the verdict:
    // a known witness key whose signature does not verify is a forgery or
    // a cosignature over a different head, and SPEC §9.3 says a known-key
    // failure rejects the note. Before 0.3.1 these were printed as FAILED
    // but the exit code stayed 0, so `c2sp verify … && proceed` proceeded.
    let body = note.text.clone();
    if !cosig_keys.is_empty() {
        println!();
        println!("  Cosignatures (c2sp.org/tlog-cosignature v1):");
        let mut found = 0usize;
        for sig in &note.signatures {
            let Ok(cosig) = Cosignature::from_note_signature(sig) else {
                continue;
            };
            for k in &cosig_keys {
                if k.name != cosig.key_name || k.id != cosig.key_id {
                    continue;
                }
                found += 1;
                match cosig.verify(k, &body) {
                    Ok(()) => println!(
                        "    ✓ {} at unix {} — attests this is the largest consistent tree head it has seen",
                        cosig.key_name, cosig.timestamp
                    ),
                    Err(e) => {
                        println!("    ✗ {} FAILED: {e}", cosig.key_name);
                        verdict = EXIT_DIVERGED;
                    }
                }
            }
        }
        if found == 0 {
            println!("    (none matching the supplied cosignature keys)");
        }
    }

    println!();
    ExitCode::from(verdict)
}
