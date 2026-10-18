//! `witness-log c2sp` — transparency-log interoperability commands.
//!
//! These exist so an operator can produce and check C2SP artifacts
//! without writing any Rust: render a dossier's checkpoint in C2SP form
//! to hand to an existing transparency-log witness, and verify the
//! signed notes and cosignatures that come back.
//!
//! See `spec/SPEC.md` §9.3 and `witness_log_core::c2sp`.

use std::process::ExitCode;
use witness_log_core::c2sp::{
    bridge, canonical_origin, Checkpoint, Cosignature, SignedNote, VerifierKey,
};
use witness_log_network::Dossier;

const EXIT_OK: u8 = 0;
const EXIT_USAGE: u8 = 2;
/// A note that does not verify, or nothing to export: a failed check, not
/// a contradiction (RFC-0002), so INVALID.
const EXIT_INVALID: u8 = crate::exit::INVALID;

fn rule() {
    println!("  {}", "─".repeat(66));
}

/// Options for `c2sp show`.
pub struct ShowOptions {
    /// Print only the checkpoint body (or the signed note with
    /// `sign_with`), nothing else, for piping.
    pub raw: bool,
    /// Path of the log's journal. Its header holds the identity key, so
    /// the body can be signed into a verifiable note here instead of in
    /// the agent's process.
    pub sign_with: Option<String>,
    /// The identity seed, when `sign_with` names a sealed journal (from
    /// `--identity-seed-env` / `--identity-seed-file`).
    pub seed: Option<zeroize::Zeroizing<[u8; 32]>>,
}

/// `witness-log c2sp show <dossier.json> --origin <name> [--raw] [--sign-with <journal>]`
///
/// Render this dossier's checkpoint as a C2SP checkpoint body. Without
/// `--sign-with` nothing is signed: the body is what a witness cosigns,
/// and the signed note is what `witness submit` produces for you. With
/// `--sign-with <journal>` the journal's identity key signs the body, so
/// the output is a note `c2sp verify` accepts.
pub fn run_show(dossier_path: &str, origin: &str, opts: &ShowOptions) -> ExitCode {
    let raw = match crate::read_input(dossier_path) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("could not read {dossier_path}: {e}");
            return ExitCode::from(EXIT_USAGE);
        }
    };
    let dossier = match Dossier::from_json(&raw) {
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

    // Optional signing with the identity key held in a journal header.
    let signed: Option<String> = match &opts.sign_with {
        None => None,
        Some(journal) => {
            let (log, _) = match crate::replay_journal(journal, opts.seed.as_deref()) {
                Ok(x) => x,
                Err(e) => {
                    eprintln!("{journal}: {e}");
                    return ExitCode::from(EXIT_USAGE);
                }
            };
            if !log
                .identity_pubkey_hex()
                .eq_ignore_ascii_case(&dossier.checkpoint.signer_pubkey)
            {
                eprintln!(
                    "{journal} holds identity {}, but the dossier's checkpoint was signed by {}: refusing to sign another log's head",
                    log.identity_pubkey_hex(),
                    dossier.checkpoint.signer_pubkey
                );
                return ExitCode::from(EXIT_USAGE);
            }
            let key = ed25519_dalek::SigningKey::from_bytes(&log.identity_bytes());
            match bridge::sign_as_c2sp(&dossier.checkpoint, origin, &key).and_then(|n| n.encode()) {
                Ok(text) => Some(text),
                Err(e) => {
                    eprintln!("could not sign note: {e}");
                    return ExitCode::from(EXIT_USAGE);
                }
            }
        }
    };

    if opts.raw {
        print!("{}", signed.as_deref().unwrap_or(&body));
        return ExitCode::from(EXIT_OK);
    }

    println!();
    match &signed {
        Some(note) => {
            println!(
                "  C2SP signed note (c2sp.org/signed-note), signed by the journal's identity key"
            );
            rule();
            print!("{note}");
            rule();
        }
        None => {
            println!("  C2SP checkpoint body (c2sp.org/tlog-checkpoint)");
            rule();
            print!("{body}");
            rule();
        }
    }
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
    if signed.is_none() {
        println!("  To get a signed note: `witness-log witness submit <journal> --directory ...`");
        println!("  submits and cosigns it for you, or add `--sign-with <journal>` here to sign");
        println!("  the body with the identity key in that journal. `--raw` prints only the");
        println!("  body (or note) for piping into `c2sp verify`.");
        println!();
    }
    let canonical = format!(
        "{}{}",
        witness_log_core::c2sp::CANONICAL_ORIGIN_PREFIX,
        dossier.checkpoint.signer_pubkey.to_ascii_lowercase()
    );
    if origin != canonical {
        println!("  Note: this origin is not the canonical `witness-log/<identity hex>`.");
        println!("  Witnesses with open enrollment accept only the canonical origin, and only");
        println!("  cosignatures under it count toward a WITNESSED verdict (SPEC.md §9.3).");
        println!();
    }
    ExitCode::from(EXIT_OK)
}

/// `witness-log c2sp verify <note.txt> --vkey <vkey> [--vkey <vkey>...]`
///
/// Verify a C2SP signed note against one or more verifier keys, and
/// report any cosignatures found.
pub fn run_verify(note_path: &str, vkey_strings: &[String]) -> ExitCode {
    let raw = match crate::read_input(note_path) {
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
    let has_log_key = vkeys
        .iter()
        .any(|k| k.sig_type != witness_log_core::c2sp::SIG_TYPE_COSIGNATURE_V1);
    if !has_log_key {
        println!("  ⚠ Only cosignature (witness) keys were supplied. The note's own signature");
        println!("    cannot be checked without the log's vkey (printed by `c2sp show`);");
        println!("    the cosignatures below are checked, but the note itself is unverified.");
        println!();
    }
    // The verdict is over the keys the caller supplied, both kinds:
    //   * a supplied key whose signature line does not verify -> rejected;
    //   * no supplied key verifies anything -> rejected (signed-note:
    //     "if no known key verifies, the note MUST be rejected");
    //   * otherwise accepted, with a warning when the log's own key was
    //     not supplied (the note text is then vouched for only by the
    //     cosigners).
    // Until 0.3.6 the exit status was the log-key check alone: a note whose
    // cosignatures all verified exited 30 when only witness keys were
    // supplied, and a run where none of the supplied keys matched any line
    // could exit 0 if the log check happened to pass on another key.
    let mut verified_keys = 0usize;
    let mut failed_keys = 0usize;
    match note.verify(&vkeys) {
        Ok(names) => {
            verified_keys += names.len();
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
            let ignored = note
                .signatures
                .len()
                .saturating_sub(names.len())
                .saturating_sub(known_cosigs);
            if ignored > 0 {
                println!();
                println!("  {ignored} signature(s) from unknown keys were IGNORED, per");
                println!("  signed-note §Signatures. That is what lets witness cosignatures");
                println!("  accumulate on a checkpoint without breaking the log's verifiers.");
            }
        }
        Err(e) => {
            if has_log_key {
                println!("  ✗ Verification FAILED: {e}");
                failed_keys += 1;
            } else {
                println!("  – Note text not checked: no log vkey supplied ({e})");
            }
        }
    }

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
                    Ok(()) => {
                        verified_keys += 1;
                        println!(
                            "    ✓ {} at unix {} — attests this is the largest consistent tree head it has seen",
                            cosig.key_name, cosig.timestamp
                        );
                    }
                    Err(e) => {
                        failed_keys += 1;
                        println!("    ✗ {} FAILED: {e}", cosig.key_name);
                    }
                }
            }
        }
        if found == 0 {
            println!("    (none matching the supplied cosignature keys)");
        }
    }

    let verdict = if failed_keys > 0 {
        println!();
        println!("  ✗ {failed_keys} supplied key(s) did not verify: REJECTED (exit 40)");
        EXIT_INVALID
    } else if verified_keys == 0 {
        println!();
        println!("  ✗ None of the {} supplied key(s) verified any signature on this note: REJECTED (exit 40)", vkeys.len());
        EXIT_INVALID
    } else {
        EXIT_OK
    };
    println!();
    ExitCode::from(verdict)
}

/// `witness-log c2sp export <dossier.json> [--directory trusted.json] [--sign-with <journal>] --out note.txt`
///
/// Write the dossier's checkpoint as a C2SP signed note under the log's
/// canonical origin, with every C2SP cosignature the dossier carries
/// attached as a signature line. A cosignature line needs the witness's
/// key name; it is taken from `--directory` (matched by public key) or,
/// failing that, from the receipt's own `witness_name`. Receipts whose
/// name cannot be determined, and native (non-C2SP) receipts, are left
/// out and listed on stderr.
///
/// The note's own log signature is over the C2SP body, which the native
/// checkpoint signature is not, so it can only be added when the identity
/// key is at hand: `--sign-with <journal>` (plus `--identity-seed-env` or
/// `--identity-seed-file` for a sealed journal). Without it the note
/// holds cosignatures only, which `c2sp verify --vkey <witness vkey>`
/// checks; with it, `--vkey <log vkey>` checks the note itself too.
pub fn run_export(args: &[String]) -> ExitCode {
    const USAGE: &str = "usage: witness-log c2sp export <dossier.json> [--directory trusted.json] [--sign-with <journal>] --out note.txt\n  [--identity-seed-env NAME | --identity-seed-file F]  seed for a sealed --sign-with journal";
    let mut i = 0;
    let mut positional: Vec<&String> = Vec::new();
    while i < args.len() {
        match args[i].as_str() {
            "--directory"
            | "--out"
            | "--sign-with"
            | "--identity-seed-env"
            | "--identity-seed-file" => i += 2,
            a if a.starts_with("--") => {
                eprintln!("unrecognized flag for `c2sp export`: {a}\n{USAGE}");
                return ExitCode::from(EXIT_USAGE);
            }
            _ => {
                positional.push(&args[i]);
                i += 1;
            }
        }
    }
    let (Some(dossier_path), Some(out_path)) =
        (positional.first(), crate::flag_value(args, "--out"))
    else {
        eprintln!("{USAGE}");
        return ExitCode::from(EXIT_USAGE);
    };
    if positional.len() != 1 {
        eprintln!("{USAGE}");
        return ExitCode::from(EXIT_USAGE);
    }
    let seed = match crate::identity_seed_from_args(args) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(EXIT_USAGE);
        }
    };
    let dossier: Dossier = match crate::read_input(dossier_path)
        .map_err(|e| e.to_string())
        .and_then(|raw| Dossier::from_json(&raw).map_err(|e| e.to_string()))
    {
        Ok(d) => d,
        Err(e) => {
            eprintln!("could not read {dossier_path}: {e}");
            return ExitCode::from(EXIT_USAGE);
        }
    };
    let directory = match crate::flag_value(args, "--directory") {
        None => None,
        Some(p) => match crate::read_input(&p)
            .map_err(|e| e.to_string())
            .and_then(|raw| crate::parse_directory(&raw))
        {
            Ok(d) => Some(d),
            Err(e) => {
                eprintln!("could not read directory {p}: {e}");
                return ExitCode::from(EXIT_USAGE);
            }
        },
    };
    let Some(signer) = hex::decode(&dossier.checkpoint.signer_pubkey)
        .ok()
        .and_then(|b| <[u8; 32]>::try_from(b).ok())
        .and_then(|b| ed25519_dalek::VerifyingKey::from_bytes(&b).ok())
    else {
        eprintln!("checkpoint signer_pubkey is not a valid Ed25519 key");
        return ExitCode::from(EXIT_USAGE);
    };
    let origin = canonical_origin(&signer);
    let checkpoint = match bridge::checkpoint_from_sth(&dossier.checkpoint, &origin) {
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
    let mut note = SignedNote {
        text: body.clone(),
        signatures: Vec::new(),
    };
    if let Some(journal) = crate::flag_value(args, "--sign-with") {
        let (log, _) = match crate::replay_journal(&journal, seed.as_deref()) {
            Ok(x) => x,
            Err(e) => {
                eprintln!("{journal}: {e}");
                return ExitCode::from(EXIT_USAGE);
            }
        };
        if !log
            .identity_pubkey_hex()
            .eq_ignore_ascii_case(&dossier.checkpoint.signer_pubkey)
        {
            eprintln!(
                "{journal} holds identity {}, but the dossier's checkpoint was signed by {}: refusing to sign another log's head",
                log.identity_pubkey_hex(),
                dossier.checkpoint.signer_pubkey
            );
            return ExitCode::from(EXIT_USAGE);
        }
        let key = ed25519_dalek::SigningKey::from_bytes(&log.identity_bytes());
        note.sign(&origin, &key);
    }
    let mut attached = 0usize;
    let mut skipped: Vec<String> = Vec::new();
    for r in &dossier.witness_receipts {
        if r.verify(&dossier.checkpoint).is_err() {
            skipped.push(format!(
                "{}: receipt does not verify",
                short_key(&r.witness_pubkey)
            ));
            continue;
        }
        if r.c2sp_origin.as_deref() != Some(origin.as_str()) {
            skipped.push(format!(
                "{}: native receipt, not a C2SP cosignature",
                short_key(&r.witness_pubkey)
            ));
            continue;
        }
        let name = directory
            .as_ref()
            .and_then(|d| {
                d.witnesses
                    .iter()
                    .find(|w| w.pubkey.eq_ignore_ascii_case(&r.witness_pubkey))
                    .map(|w| w.name.clone())
            })
            .or_else(|| r.witness_name.clone());
        let Some(name) = name else {
            skipped.push(format!(
                "{}: key name unknown (pass --directory, or submit with 0.4.0+ so receipts carry it)",
                short_key(&r.witness_pubkey)
            ));
            continue;
        };
        let (Some(pk), Some(sig)) = (
            hex::decode(&r.witness_pubkey).ok(),
            hex::decode(&r.signature).ok(),
        ) else {
            skipped.push(format!("{}: malformed hex", short_key(&r.witness_pubkey)));
            continue;
        };
        let cosig = Cosignature {
            key_name: name.clone(),
            key_id: witness_log_core::c2sp::key_id(
                &name,
                witness_log_core::c2sp::SIG_TYPE_COSIGNATURE_V1,
                &pk,
            ),
            timestamp: r.witnessed_at_ms / 1000,
            signature: sig,
        };
        note.signatures.push(cosig.to_note_signature());
        attached += 1;
    }
    if note.signatures.is_empty() {
        eprintln!(
            "nothing to write: the dossier carries no usable cosignature and --sign-with was not given, \
             and a signed note needs at least one signature line"
        );
        for s in &skipped {
            eprintln!("  skipped {s}");
        }
        return ExitCode::from(EXIT_INVALID);
    }
    let text = match note.encode() {
        Ok(t) => t,
        Err(e) => {
            eprintln!("could not encode note: {e}");
            return ExitCode::from(EXIT_USAGE);
        }
    };
    if let Err(e) =
        crate::witness_cmd::atomic_write_shared(std::path::Path::new(&out_path), text.as_bytes())
    {
        eprintln!("{out_path}: {e}");
        return ExitCode::from(1);
    }
    eprintln!(
        "wrote {out_path}: {origin} size {} with {attached} cosignature(s){}",
        checkpoint.tree_size,
        if note.signatures.len() > attached {
            " and the log's own signature"
        } else {
            " (no log signature: pass --sign-with <journal> to add one)"
        }
    );
    for s in &skipped {
        eprintln!("  skipped {s}");
    }
    ExitCode::from(EXIT_OK)
}

fn short_key(hex: &str) -> String {
    crate::short(hex)
}
