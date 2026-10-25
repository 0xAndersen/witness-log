//! `witness-log prove-silence`: the counterparty's check of a write receipt
//! against a log's witnessed dossiers (SPEC §9.4).
//!
//! The log operator signs a write receipt when it accepts an entry
//! (`witness-log log receipt`) and hands it to whoever submitted the entry.
//! Later, holding the log's dossiers (each a checkpoint with its witness
//! receipts, plus the leaves), that party, or anyone they hand the bundle
//! to, checks whether the entry is in the history the witnesses cosigned
//! at the index the receipt promised, or provably left out of it. Offline,
//! and a thin renderer over
//! `witness_log_network::silence_proof_over_dossiers`, which decides.

use std::process::ExitCode;
use witness_log_core::identity::RevocationStatement;
use witness_log_core::sth::WriteReceipt;
use witness_log_network::{
    silence_proof_over_dossiers, Dossier, SilenceCheckpointUse, SilenceContext, SilenceProofReport,
    SilenceProofResult, MIN_INDEPENDENT_OPERATORS_FOR_WITNESSED,
};

/// The result is the exit status, spaced like `verify`'s: 0 is the only
/// "proceed", 20 is "not enough to say", 30 is a finding against the log.
mod code {
    /// The event is in the log's witnessed history.
    pub const PRESENT: u8 = 0;
    /// Not enough witnessed evidence either way. Never an accusation.
    pub const INCONCLUSIVE: u8 = 20;
    /// The log signed a receipt for an event its witnessed history
    /// provably omits.
    pub const CENSORED: u8 = 30;
}

/// The library's "conservative minimum" of witnessed checkpoints after the
/// receipt before an omission counts as censorship.
const DEFAULT_MIN_CHECKPOINTS: usize = 2;

/// A write receipt is six short fields, a few hundred bytes. Anything much
/// larger is not one, and is refused before it is read into memory.
const MAX_RECEIPT_BYTES: u64 = 64 * 1024;

pub(crate) const USAGE: &str =
    "usage: witness-log prove-silence <receipt.json> --dossier <d.json> [--dossier <d2.json> ...]
                                 --directory <trusted.json> [--identity <hex>] [--min-checkpoints N]
                                 [--subject-org ORG] [--revocations <path>] [--json]
  Check a write receipt (what `witness-log log receipt` prints) against the log's
  witnessed dossiers: is the event it names in the history the witnesses cosigned, at
  the index the receipt promised, or provably left out of it? Offline.
  <receipt.json>       the write receipt the log signed when it accepted the event
  --dossier <path>     a dossier of the log (repeatable). One counts only if its checkpoint is
                       signed by the receipt's key and verifies, is larger than the receipt's
                       tree_size, was cosigned by two independent operators from --directory,
                       and its leaves reproduce it; any other is used for nothing. The leaves
                       come from the largest counted dossier and must reproduce every counted
                       checkpoint
  --directory <path>   a witness directory YOU trust, never one a dossier carries
  --identity <hex>     the log's identity key, obtained out of band; the receipt must be signed
                       by it (exit 2 otherwise). Without it the result is about whatever key
                       signed the receipt
  --min-checkpoints N  counted checkpoints after the receipt that CENSORED needs (default 2)
  --subject-org ORG    the organisation that operates the log; its witnesses never count
  --revocations <path> revocations you know of (one statement or a JSON array), applied with
                       those the dossiers carry: a receipt whose key was revoked proves nothing
  --json               one JSON object instead of the verdict line
  Exit: 0 PRESENT: the event is in the log's witnessed history, at the promised index
        20 INCONCLUSIVE: not enough witnessed evidence either way (never an accusation)
        30 CENSORED: the log signed a receipt for an event its witnessed history omits
        2 usage, unreadable or malformed input, a receipt that does not verify, or a
          receipt not signed by --identity";

struct Options {
    receipt_path: String,
    dossier_paths: Vec<String>,
    directory_path: String,
    identity: Option<String>,
    min_checkpoints: usize,
    subject_org: Option<String>,
    revocations_path: Option<String>,
    json: bool,
}

fn parse(args: &[String]) -> Result<Options, String> {
    let mut receipt_path: Option<String> = None;
    let mut dossier_paths = Vec::new();
    let mut directory_path: Option<String> = None;
    let mut identity: Option<String> = None;
    let mut min_checkpoints: Option<usize> = None;
    let mut subject_org: Option<String> = None;
    let mut revocations_path: Option<String> = None;
    let mut json = false;
    // A flag's value; a value that looks like a flag is refused, so
    // `--dossier --json` does not read a file named "--json".
    let value = |i: usize, what: &str| -> Result<String, String> {
        match args.get(i + 1) {
            Some(v) if !v.starts_with("--") && !v.trim().is_empty() => Ok(v.clone()),
            _ => Err(format!("{} requires {what}", args[i])),
        }
    };
    let once = |given: bool, flag: &str| -> Result<(), String> {
        if given {
            Err(format!("{flag} given twice"))
        } else {
            Ok(())
        }
    };
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--dossier" => {
                dossier_paths.push(value(i, "a path to a dossier")?);
                i += 2;
            }
            "--directory" => {
                once(directory_path.is_some(), "--directory")?;
                directory_path = Some(value(i, "a path to a trusted witness directory")?);
                i += 2;
            }
            "--revocations" => {
                once(revocations_path.is_some(), "--revocations")?;
                revocations_path = Some(value(i, "a path to revocation statements")?);
                i += 2;
            }
            "--identity" => {
                once(identity.is_some(), "--identity")?;
                let v = value(i, "the log's identity key as 64 hex characters")?;
                if !crate::is_hex32(&v) {
                    return Err(format!(
                        "--identity must be a 32-byte Ed25519 public key as 64 hex characters, got {}",
                        witness_log_core::echo::quoted(&v)
                    ));
                }
                identity = Some(v);
                i += 2;
            }
            "--min-checkpoints" => {
                once(min_checkpoints.is_some(), "--min-checkpoints")?;
                let v = value(i, "a positive integer")?;
                match v.parse::<usize>() {
                    Ok(n) if n >= 1 => min_checkpoints = Some(n),
                    _ => {
                        return Err(format!(
                            "--min-checkpoints must be a positive integer, got {}",
                            witness_log_core::echo::quoted(&v)
                        ))
                    }
                }
                i += 2;
            }
            "--subject-org" => {
                once(subject_org.is_some(), "--subject-org")?;
                subject_org = Some(value(i, "the organisation that operates the log")?);
                i += 2;
            }
            "--json" => {
                json = true;
                i += 1;
            }
            other if other.starts_with("--") => {
                return Err(format!("unrecognized flag: {other}"));
            }
            other => {
                if receipt_path.is_some() {
                    return Err(format!(
                        "unexpected extra argument {} (the receipt is already {})",
                        witness_log_core::echo::quoted(other),
                        witness_log_core::echo::quoted(receipt_path.as_deref().unwrap_or(""))
                    ));
                }
                receipt_path = Some(other.to_string());
                i += 1;
            }
        }
    }
    let receipt_path = receipt_path.ok_or("expected the path of a write receipt")?;
    if dossier_paths.is_empty() {
        return Err("at least one --dossier <path> is required: the log's witnessed history to check the receipt against".into());
    }
    let directory_path = directory_path.ok_or(
        "--directory <trusted.json> is required: only witnesses in a directory you trust count",
    )?;
    Ok(Options {
        receipt_path,
        dossier_paths,
        directory_path,
        identity,
        min_checkpoints: min_checkpoints.unwrap_or(DEFAULT_MIN_CHECKPOINTS),
        subject_org,
        revocations_path,
        json,
    })
}

fn usage(msg: impl std::fmt::Display) -> ExitCode {
    eprintln!("prove-silence: {msg}");
    ExitCode::from(crate::exit::USAGE)
}

/// A write receipt file: the object `log receipt` prints, at most
/// [`MAX_RECEIPT_BYTES`], read from an object only.
fn read_receipt(path: &str) -> Result<WriteReceipt, String> {
    use std::io::Read;
    let mut raw = String::new();
    std::fs::File::open(path)
        .and_then(|f| f.take(MAX_RECEIPT_BYTES + 1).read_to_string(&mut raw))
        .map_err(|e| format!("could not read receipt {path}: {e}"))?;
    if raw.len() as u64 > MAX_RECEIPT_BYTES {
        return Err(format!(
            "{path} is larger than {} KiB: not a write receipt",
            MAX_RECEIPT_BYTES >> 10
        ));
    }
    serde_json::from_str::<WriteReceipt>(&raw).map_err(|e| {
        format!(
            "could not parse write receipt {path}: {} (expected the JSON object `witness-log log receipt` prints)",
            witness_log_core::echo::bounded(&e.to_string())
        )
    })
}

/// What a note says about a dossier that was not counted.
fn why_not_counted(u: SilenceCheckpointUse) -> Option<&'static str> {
    match u {
        SilenceCheckpointUse::Counted => None,
        SilenceCheckpointUse::OtherLog => Some("signed by another log's key"),
        SilenceCheckpointUse::BadSignature => Some("its checkpoint signature does not verify"),
        SilenceCheckpointUse::NotAfterReceipt => Some("not larger than the receipt's tree size"),
        SilenceCheckpointUse::NotWitnessed => {
            Some("not cosigned by two independent operators from your directory")
        }
        SilenceCheckpointUse::LeavesDoNotReproduce => {
            Some("its leaves do not reproduce its checkpoint")
        }
    }
}

pub(crate) fn run(args: &[String]) -> ExitCode {
    if args.iter().any(|a| a == "--help" || a == "-h") {
        println!("{USAGE}");
        return ExitCode::SUCCESS;
    }
    let opts = match parse(args) {
        Ok(o) => o,
        Err(e) => {
            return usage(format!(
                "{e}\n  run `witness-log prove-silence --help` for usage"
            ))
        }
    };

    let receipt = match read_receipt(&opts.receipt_path) {
        Ok(r) => r,
        Err(e) => return usage(e),
    };
    // An unverifiable receipt is no commitment by anyone: refuse it rather
    // than report on it.
    if let Err(e) = receipt.verify() {
        return usage(format!(
            "the write receipt in {} does not verify ({e}): it was altered after signing, or is not a write receipt",
            opts.receipt_path
        ));
    }
    if let Some(id) = &opts.identity {
        if !id.eq_ignore_ascii_case(receipt.signer_pubkey.trim()) {
            return usage(format!(
                "the receipt is signed by {}, not by --identity {id}: it is not from the log you named",
                receipt.signer_pubkey
            ));
        }
    }
    let mut dossiers = Vec::with_capacity(opts.dossier_paths.len());
    for p in &opts.dossier_paths {
        let raw = match crate::read_input(p) {
            Ok(r) => r,
            Err(e) => return usage(format!("could not read dossier {p}: {e}")),
        };
        match Dossier::from_json(&raw) {
            Ok(d) => dossiers.push(d),
            Err(e) => return usage(format!("could not parse dossier {p}: {e}")),
        }
    }
    // The trusted directory comes from the caller, never from a dossier.
    let directory = match crate::read_input(&opts.directory_path) {
        Ok(raw) => match crate::parse_directory(&raw) {
            Ok(d) => d,
            Err(e) => {
                return usage(format!(
                    "could not parse trusted directory {}: {e}",
                    opts.directory_path
                ))
            }
        },
        Err(e) => {
            return usage(format!(
                "could not read trusted directory {}: {e}",
                opts.directory_path
            ))
        }
    };
    let revocations: Vec<RevocationStatement> = match &opts.revocations_path {
        Some(p) => match crate::read_input(p)
            .map_err(|e| e.to_string())
            .and_then(|t| crate::parse_revocations(&t))
        {
            Ok(v) => v,
            Err(e) => {
                return usage(format!(
                    "could not read revocations {p}: {e} (expected one statement as `log revoke` prints it, or a JSON array of them)"
                ))
            }
        },
        None => Vec::new(),
    };

    let proof = silence_proof_over_dossiers(
        &receipt,
        &dossiers,
        &SilenceContext {
            trusted_directory: &directory,
            min_witnessed_checkpoints: opts.min_checkpoints,
            subject_org: opts.subject_org.as_deref(),
            revocations: &revocations,
        },
    );
    let report = &proof.report;
    let (result, exit) = match &report.result {
        SilenceProofResult::Censored { .. } => ("censored", code::CENSORED),
        SilenceProofResult::Present { .. } => ("present", code::PRESENT),
        SilenceProofResult::Inconclusive { .. } => ("inconclusive", code::INCONCLUSIVE),
    };

    if opts.json {
        let (leaf_index, after, seen) = match &report.result {
            SilenceProofResult::Present { leaf_index } => (Some(*leaf_index), None, None),
            SilenceProofResult::Censored {
                witnessed_checkpoints_after,
                ..
            } => (None, Some(*witnessed_checkpoints_after), None),
            SilenceProofResult::Inconclusive {
                witnessed_checkpoints_seen,
                ..
            } => (report.misplaced_at, None, Some(*witnessed_checkpoints_seen)),
        };
        let inputs: Vec<serde_json::Value> = opts
            .dossier_paths
            .iter()
            .zip(&dossiers)
            .zip(&proof.dossiers)
            .map(|((p, d), u)| {
                serde_json::json!({
                    "path": p,
                    "tree_size": d.checkpoint.tree_size,
                    "root_hash": d.checkpoint.root_hash,
                    "leaves": d.leaves.len(),
                    "witness_receipts": d.witness_receipts.len(),
                    "status": u,
                })
            })
            .collect();
        let doc = serde_json::json!({
            "result": result,
            "exit_code": exit,
            "leaf_index": leaf_index,
            "promised_index": receipt.tree_size,
            "receipt_tree_size": receipt.tree_size,
            "witnessed_checkpoints_after": after,
            "witnessed_checkpoints_seen": seen,
            "min_checkpoints": opts.min_checkpoints,
            "bound_tree_size": report.bound_tree_size,
            "bound_root_hash": report.bound_root_hash,
            "reason": report.reason,
            "subject_org": opts.subject_org,
            "identity": receipt.signer_pubkey,
            "identity_pinned": opts.identity.is_some(),
            "receipt": {
                "path": opts.receipt_path,
                "payload_hash": receipt.payload_hash,
                "tree_size": receipt.tree_size,
                "issued_at_ms": receipt.issued_at_ms,
                "signer_pubkey": receipt.signer_pubkey,
            },
            "directory": opts.directory_path,
            "revocations": opts.revocations_path,
            "dossiers": inputs,
            "leaves_from": proof.leaves_from.map(|i| opts.dossier_paths[i].clone()),
        });
        println!("{}", serde_json::to_string_pretty(&doc).unwrap_or_default());
        return ExitCode::from(exit);
    }

    println!("{}", verdict_line(&receipt, report));
    let not_counted: Vec<String> = opts
        .dossier_paths
        .iter()
        .zip(&proof.dossiers)
        .filter_map(|(p, u)| why_not_counted(*u).map(|why| format!("{p} ({why})")))
        .collect();
    if !not_counted.is_empty() {
        println!("  note: not counted: {}", not_counted.join("; "));
    }
    if opts.identity.is_none() && result != "inconclusive" {
        println!(
            "\u{26A0} --identity was not supplied: this is about the log whose key signed the receipt, {}. Pass --identity <the log's key, obtained out of band> to tie it to the log you dealt with.",
            receipt.signer_pubkey
        );
    }
    ExitCode::from(exit)
}

/// The one line a person reads: the result, what it is bound to, and what
/// it means.
fn verdict_line(receipt: &WriteReceipt, report: &SilenceProofReport) -> String {
    let min = MIN_INDEPENDENT_OPERATORS_FOR_WITNESSED;
    let bound = match (report.bound_tree_size, report.bound_root_hash.as_deref()) {
        (Some(n), Some(root)) => format!("checkpoint {n} (root {root})"),
        _ => "no witnessed checkpoint".to_string(),
    };
    match &report.result {
        SilenceProofResult::Present { leaf_index } => format!(
            "PRESENT: the event (payload_hash {}) is leaf {leaf_index} of the log's witnessed history, where the receipt promised it: the leaves reproduce every witnessed checkpoint supplied, up to {bound}, each cosigned by at least {min} independent operators from your directory. It was not left out.",
            receipt.payload_hash
        ),
        SilenceProofResult::Censored {
            witnessed_checkpoints_after,
            ..
        } => format!(
            "CENSORED: the log signed a write receipt for this event (payload_hash {}) at tree size {}, and {witnessed_checkpoints_after} later checkpoints of the same log, each cosigned by at least {min} independent operators from your directory, do not contain it, up to {bound}. The receipt, these dossiers and your directory are the evidence: anyone who checks them reaches this result.",
            receipt.payload_hash, receipt.tree_size
        ),
        SilenceProofResult::Inconclusive { .. } => {
            let reason = report
                .reason
                .as_deref()
                .unwrap_or("not enough witnessed evidence either way");
            let bound = match report.bound_tree_size {
                Some(_) => format!(" (leaves bound to {bound})"),
                None => String::new(),
            };
            format!(
                "INCONCLUSIVE: {reason}{bound}. Not an accusation, and not proof the event was kept where promised."
            )
        }
    }
}
