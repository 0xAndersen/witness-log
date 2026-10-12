//! `witness-log diff` — compare two dossiers that claim to be the same log.
//!
//! This is the equivocation check, and it is the single thing this whole
//! project exists to make possible. A dishonest log operator's most
//! powerful move is not tampering with one history — that's caught by any
//! Merkle log — it's presenting history A to you and history B to someone
//! else, each internally perfect and each validly signed. Neither copy
//! looks wrong on its own. The divergence is only visible when two
//! parties compare.
//!
//! Witnesses exist to make that comparison happen automatically and
//! continuously. This command is what it looks like when you do it by
//! hand, with two copies in front of you — during an incident, a dispute,
//! or an audit.

use std::process::ExitCode;
use witness_log_core::merkle::leaf_hash;
use witness_log_network::{Dossier, VerifyContext};

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

fn load(path: &str) -> Result<Dossier, String> {
    let raw = crate::read_input(path).map_err(|e| format!("could not read {path}: {e}"))?;
    serde_json::from_str(&raw).map_err(|e| format!("could not parse {path}: {e}"))
}

pub fn run_diff(path_a: &str, path_b: &str) -> ExitCode {
    let (a, b) = match (load(path_a), load(path_b)) {
        (Ok(a), Ok(b)) => (a, b),
        (Err(e), _) | (_, Err(e)) => {
            eprintln!("{e}");
            return ExitCode::from(2);
        }
    };

    println!();
    println!("  Comparing two dossiers that claim to be the same log");
    println!("    A: {path_a}");
    println!("    B: {path_b}");
    println!();

    // Are these even claiming to be the same log? Comparing two unrelated
    // logs and reporting "they differ" would be noise, not a finding.
    let same_identity = a.identity_pubkey.eq_ignore_ascii_case(&b.identity_pubkey);
    let same_signer = a
        .checkpoint
        .signer_pubkey
        .eq_ignore_ascii_case(&b.checkpoint.signer_pubkey);
    if !same_identity || !same_signer {
        println!("  These are not two views of one log — they name different identities:");
        println!("    A identity: {}", short(&a.identity_pubkey));
        println!("    B identity: {}", short(&b.identity_pubkey));
        println!();
        println!("  Nothing to compare. Equivocation means ONE log telling two stories;");
        println!("  two different logs telling different stories is just two logs.");
        println!();
        return ExitCode::from(2);
    }

    println!("  Both claim identity {}", short(&a.identity_pubkey));

    // Both signatures must be valid for a divergence to be damning. If one
    // is invalid it's simply a bad file, not evidence of equivocation.
    let a_sig_ok = a.checkpoint.verify().is_ok();
    let b_sig_ok = b.checkpoint.verify().is_ok();
    println!(
        "  A checkpoint signature: {}   B checkpoint signature: {}",
        if a_sig_ok { "valid" } else { "INVALID" },
        if b_sig_ok { "valid" } else { "INVALID" }
    );
    println!();

    if !a_sig_ok || !b_sig_ok {
        println!("  At least one checkpoint signature does not verify, so any difference");
        println!("  below is explained by a corrupt or forged file — not by equivocation.");
        println!("  Fix or discard the invalid copy, then compare again.");
        println!();
        return ExitCode::from(30);
    }

    // Each copy's leaves must reproduce ITS OWN signed root. A copy whose
    // leaves were edited after signing is a tampered file: the log never
    // signed that history, so it is not evidence the log said two things.
    // Without this check, anyone holding one honest copy could edit a
    // leaf and "prove" equivocation -- a false accusation the final
    // pre-publish review reproduced against the sample dossier.
    let ctx = VerifyContext::default();
    let a_cont = a.verify(0.0, &ctx).merkle_continuity_valid;
    let b_cont = b.verify(0.0, &ctx).merkle_continuity_valid;
    println!(
        "  A leaves match root: {}   B leaves match root: {}",
        if a_cont { "yes" } else { "NO" },
        if b_cont { "yes" } else { "NO" }
    );
    println!();
    if !a_cont || !b_cont {
        let bad = match (a_cont, b_cont) {
            (false, false) => "Both copies contain",
            (false, true) => "Copy A contains",
            _ => "Copy B contains",
        };
        println!("  {bad} leaves that do not reproduce the signed root: the");
        println!("  leaves were altered after the checkpoint was signed. That is a");
        println!("  tampered file, not a second history the log signed. Any difference");
        println!("  between the copies is explained by the tampering — not by");
        println!("  equivocation. Run `witness-log verify` on the bad copy for details.");
        println!();
        return ExitCode::from(30);
    }

    // Compare leaf-by-leaf on committed hashes, not on displayed fields:
    // the leaf hash is what the tree actually commits to.
    let n = a.leaves.len().max(b.leaves.len());
    let mut first_divergence: Option<usize> = None;
    let mut common_prefix = 0usize;
    for i in 0..n {
        match (a.leaves.get(i), b.leaves.get(i)) {
            (Some(la), Some(lb)) => {
                let ha = leaf_hash(&la.canonical_bytes());
                let hb = leaf_hash(&lb.canonical_bytes());
                if ha == hb {
                    common_prefix = i + 1;
                } else {
                    first_divergence = Some(i);
                    break;
                }
            }
            // One log is a strict prefix of the other: not equivocation on
            // its own, just different points in time (or a truncation).
            _ => break,
        }
    }

    println!(
        "  A: {} leaves, checkpoint at size {}, root {}",
        a.leaves.len(),
        a.checkpoint.tree_size,
        short(&a.checkpoint.root_hash)
    );
    println!(
        "  B: {} leaves, checkpoint at size {}, root {}",
        b.leaves.len(),
        b.checkpoint.tree_size,
        short(&b.checkpoint.root_hash)
    );
    println!();

    match first_divergence {
        Some(i) => {
            let la = &a.leaves[i];
            let lb = &b.leaves[i];
            if i == 0 {
                println!("  Leaf 0: DIVERGENT (no common prefix at all)");
            } else {
                println!("  Leaves 0–{}: identical", i - 1);
                println!("  Leaf {i}: DIVERGENT");
            }
            println!();
            println!(
                "    A  type 0x{:02x}  ts {}  payload_hash {}",
                la.leaf_type,
                la.timestamp_ms,
                short(&la.payload_hash)
            );
            println!(
                "    B  type 0x{:02x}  ts {}  payload_hash {}",
                lb.leaf_type,
                lb.timestamp_ms,
                short(&lb.payload_hash)
            );
            println!();
            // Divergence at leaf 0 used to be explained away as "probably two
            // separate logs". Under the canonical-origin rule
            // (`witness-log/<identity hex>`, SPEC §9.3) the identity key IS
            // the log's name: two histories signed by one key are two
            // histories of one log, whether the operator rewrote it from the
            // start or ran a second journal from the same seed. Witnesses
            // treat both identically (422 + evidence), so diff must too. The
            // hedge also hid the most important case: a whole-history rewrite.
            let from = if i == 0 {
                "the very first leaf".to_string()
            } else {
                format!("leaf {i} onward")
            };
            println!("  \u{26A0} EQUIVOCATION DETECTED");
            println!();
            println!("  Both dossiers are validly signed by the same identity. Both are");
            println!("  internally consistent. They commit to different histories from");
            println!("  {from}.");
            println!();
            println!("  Neither copy is \"the wrong one\" — that is precisely the finding.");
            println!("  A log that signs two different histories has equivocated, and no");
            println!("  amount of checking either copy in isolation would ever reveal it.");
            println!();
            println!("  This is what a witness network prevents: witnesses countersign");
            println!("  checkpoints continuously, so a second history cannot be presented");
            println!("  without contradicting a receipt someone already holds.");
            if i == 0 {
                println!();
                println!("  A divergence from the very first leaf is either a whole-history");
                println!("  rewrite or two journals run from one identity seed (for example the");
                println!("  same seed deployed twice). The key names the log (SPEC §9.3), so");
                println!("  witnesses refuse either one the same way; use one identity per log.");
            }
            println!();
            ExitCode::from(30)
        }
        None if a.leaves.len() == b.leaves.len() => {
            println!("  All {} leaves identical. No divergence.", a.leaves.len());
            println!();
            if a.checkpoint
                .root_hash
                .eq_ignore_ascii_case(&b.checkpoint.root_hash)
            {
                println!("  Same root, same size: these are two copies of the same history.");
            } else {
                println!("  \u{26A0} Leaves match but checkpoint roots differ — the checkpoints");
                println!("  were taken at different tree sizes, or one root does not match its");
                println!("  own leaves. Run `witness-log verify` on each copy separately.");
            }
            println!();
            ExitCode::SUCCESS
        }
        None => {
            let (shorter, longer) = if a.leaves.len() < b.leaves.len() {
                ("A", "B")
            } else {
                ("B", "A")
            };
            println!("  First {common_prefix} leaves identical; {shorter} is a strict prefix of {longer}.");
            println!();
            println!("  This is NOT equivocation. It's consistent with two views taken at");
            println!("  different times — {longer} simply has more history than {shorter}.");
            println!();
            println!("  Worth confirming separately: a consistency proof between the two");
            println!("  checkpoint sizes proves {longer} only ever appended to {shorter}, rather");
            println!("  than rewriting anything before it.");
            println!();
            ExitCode::SUCCESS
        }
    }
}
