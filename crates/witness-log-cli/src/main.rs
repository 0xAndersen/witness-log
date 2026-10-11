//! `witness-log verify <dossier.json>` — the entire point of this tool.
//!
//! Runs fully offline via `witness_log_network::Dossier::verify`, which is the
//! single canonical implementation of what "verify a dossier" means — this
//! binary is a thin renderer over that shared logic, not a second copy of
//! it. See README.md for the dossier format and a worked example, and
//! THREAT_MODEL.md for what each check does and doesn't prove.

use std::env;
use std::fs;
use std::process::ExitCode;
use witness_log_network::{Dossier, DossierReport, VerifyContext, WitnessDirectory};

/// Default quorum threshold: 2-of-3-style supermajority. This is a
/// starting point, not a universal answer — a $10 API call and a $10M
/// settlement shouldn't necessarily use the same bar. Override with
/// `--threshold <fraction>` when the stakes call for something else.
pub const DEFAULT_QUORUM_THRESHOLD: f64 = 0.66;

/// Semantic exit codes: the verdict IS the exit status. An agent or a
/// shell script gates on verification in one line, with no JSON parsing
/// and no dependency on this tool's output format:
///
/// ```sh
/// witness-log verify d.json --identity $ID --directory $DIR || handle_failure
/// ```
///
/// Codes are spaced by 10 so intermediate states can be added later
/// without renumbering anything a caller already depends on. 0 is
/// reserved for the strongest verdict specifically so the common
/// `cmd && next` shell idiom means "proceed only if genuinely witnessed"
/// — the safe default for anyone who doesn't read the docs.
mod exit {
    pub const WITNESSED: u8 = 0;
    pub const CONSISTENT_UNWITNESSED: u8 = 10;
    pub const UNANCHORED: u8 = 20;
    pub const DIVERGED: u8 = 30;
    /// Usage error, unreadable file, unparseable input — a problem with
    /// the invocation, distinct from any verdict about a dossier.
    pub const USAGE: u8 = 2;
}

fn exit_code_for(verdict: &witness_log_network::Verdict) -> ExitCode {
    ExitCode::from(match verdict {
        witness_log_network::Verdict::Witnessed => exit::WITNESSED,
        witness_log_network::Verdict::ConsistentUnwitnessed => exit::CONSISTENT_UNWITNESSED,
        witness_log_network::Verdict::Unanchored => exit::UNANCHORED,
        witness_log_network::Verdict::Diverged => exit::DIVERGED,
    })
}

struct Options {
    path: String,
    threshold: f64,
    /// Absolute receipt-count gate (`--min-witnesses`); overrides the
    /// fraction when set. The right gate for a registry-sized directory.
    min_witnesses: Option<usize>,
    json: bool,
    explain: bool,
    /// Out-of-band identity pin — NEVER read from the dossier itself.
    /// Without this, the verdict is capped at UNANCHORED (or, for the
    /// identity check specifically, self-consistency between the
    /// dossier's identity_pubkey and its checkpoint signer is still
    /// checked, but there's no external confirmation this is the
    /// specific party the caller expected). See VerifyContext.
    identity: Option<String>,
    /// Path to a JSON file containing the witness directory this CALLER
    /// trusts — NEVER the dossier's own embedded directory. Without this,
    /// witness receipts (even if present) cannot be scored and the
    /// verdict is capped at UNANCHORED.
    directory_path: Option<String>,
}

mod c2sp_cmd;
mod demo;
mod diff;
mod explain;
mod http;
mod witness_cmd;

const HELP: &str = "witness-log — verifiable audit trails for autonomous agents

  New here? Run `witness-log demo` — zero arguments, nothing written to disk.

USAGE:
  witness-log demo [--tamper]
      A self-contained worked example: build a log, redact a leaf, sign a
      checkpoint, gather witnesses, then verify it twice to show what
      changes when you anchor verification to something outside the file.
      --tamper   build a convincing forgery instead, and watch it get caught.

  witness-log verify <dossier.json> [--threshold 0.0-1.0 | --min-witnesses N] [--json] [--explain]
                      [--identity <hex-pubkey>] [--directory <path.json>]
      Verify a dossier fully offline: checkpoint signature, identity
      binding, leaf structural validity, key-binding validity, Merkle
      continuity rebuilt from the leaves, and (when a --directory is
      supplied) quorum + operator diversity + compute-provider diversity
      against THAT directory.
      --threshold  quorum bar as a fraction of the directory (default 0.66)
      --min-witnesses N  quorum bar as an absolute count (use for large directories)
      --json       machine-readable structured report
      --explain    one line under each check: what it does and doesn't prove
      --identity   the identity pubkey you expect, obtained out-of-band
      --directory  path to a witness directory YOU trust, obtained out-of-band
      Omitting --identity and --directory is a legal, meaningful run, but
      the strongest reachable verdict is UNANCHORED — see `explain` below.

  witness-log diff <a.json> <b.json>
      Compare two dossiers claiming to be the same log. This is the
      equivocation check: a log that showed one history to you and a
      different one to someone else is exactly what witnessing exists to
      catch, and this is how you catch it with two copies in hand.

  witness-log explain [verdict|<name>]
      What each verdict means, what it does NOT mean, and how to reach the
      next level. Machine-readable with --json, so an agent that hits an
      unexpected verdict can ask why without a human in the loop.

  witness-log c2sp show <dossier.json> --origin <name>
  witness-log c2sp verify <note.txt> --vkey <vkey> [--vkey <vkey>...]
      Transparency-log interoperability (c2sp.org). `show` renders a
      dossier's checkpoint as a C2SP checkpoint body — the artifact an
      existing CT-ecosystem witness cosigns. `verify` checks a signed
      note and any cosignatures against verifier keys you supply.
      See SPEC.md §9.3.

  witness-log witness init <dir> --name <key-name> [--org <operator>] [--url <url>]
  witness-log witness serve <dir> [--listen 127.0.0.1:7380] [--open-enrollment]
  witness-log witness add-log <dir> <origin> <log-vkey>
  witness-log witness info <http://witness-url>
  witness-log witness submit <journal> --directory <witnesses.json> [--out dossier.json]
      Run a c2sp.org/tlog-witness witness, or get an agent's journal
      cosigned by the witnesses in a directory. `serve` persists every
      cosigned head (fsync) before replying and refuses forks with 422,
      recording provable equivocation under evidence/. With --open-enrollment it accepts
      any agent whose origin is witness-log/<its identity key> -- the
      origin names the key, so no key exchange is needed. `submit`
      writes a dossier whose receipts verify offline.

  witness-log conform <candidate-corpus-dir>
      Compare another implementation's generated conformance vectors
      against this implementation's committed /corpus. This is how a
      from-scratch reimplementation proves wire-format agreement — see
      CONTRIBUTING.md.

  witness-log --help | -h | help
      This text.

  witness-log --version

EXIT CODES — the verdict IS the exit status, so gating needs no JSON parsing:
   0  WITNESSED               30  DIVERGED
  10  CONSISTENT-UNWITNESSED   2  usage / unreadable input
  20  UNANCHORED
";

/// First value following `flag`, if present. Values that look like
/// flags are rejected so `--origin --vkey x` fails loudly instead of
/// silently taking "--vkey" as the origin.
fn flag_value(args: &[String], flag: &str) -> Option<String> {
    let idx = args.iter().position(|a| a == flag)?;
    let v = args.get(idx + 1)?;
    if v.starts_with("--") {
        return None;
    }
    Some(v.clone())
}

/// Every value following each occurrence of `flag`. Repeatable flags
/// (`--vkey a --vkey b`) are how a verifier supplies more than one
/// trusted key.
fn all_flag_values(args: &[String], flag: &str) -> Vec<String> {
    let mut out = Vec::new();
    for (i, a) in args.iter().enumerate() {
        if a == flag {
            if let Some(v) = args.get(i + 1) {
                if !v.starts_with("--") {
                    out.push(v.clone());
                }
            }
        }
    }
    out
}

fn main() -> ExitCode {
    // Rust ignores SIGPIPE at startup, which turns a closed pipe (`| head`)
    // into a panic with a backtrace on the next print. A CLI should just
    // stop, like every other Unix tool.
    #[cfg(unix)]
    // SAFETY: resetting a signal disposition to its default, before any
    // thread exists, has no preconditions.
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_DFL);
    }
    let args: Vec<String> = env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("demo") => {
            // Reject unrecognized flags rather than silently ignoring
            // them — a typo'd `--tampr` should say so, not quietly run
            // the non-tamper demo and leave the user confused about why
            // nothing was forged.
            let unknown: Vec<&String> = args[2..]
                .iter()
                .filter(|a| a.as_str() != "--tamper")
                .collect();
            if let Some(bad) = unknown.first() {
                eprintln!("unrecognized argument for `demo`: {bad}");
                eprintln!("  usage: witness-log demo [--tamper]");
                return ExitCode::from(exit::USAGE);
            }
            if args.iter().any(|a| a == "--tamper") {
                demo::run_demo_tamper()
            } else {
                demo::run_demo()
            }
        }
        Some("verify") => {
            if args[2..].iter().any(|a| a == "--help" || a == "-h") {
                println!("{VERIFY_USAGE}");
                return ExitCode::SUCCESS;
            }
            match parse_options(&args[2..]) {
                Ok(opts) => run_verify(&opts),
                Err(msg) => {
                    eprintln!("{msg}");
                    ExitCode::from(exit::USAGE)
                }
            }
        }
        Some("diff") => {
            let positional: Vec<&String> =
                args[2..].iter().filter(|a| !a.starts_with("--")).collect();
            if let Some(flag) = args[2..].iter().find(|a| a.starts_with("--")) {
                eprintln!("unrecognized flag for `diff`: {flag}");
                eprintln!("  usage: witness-log diff <a.json> <b.json>");
                ExitCode::from(exit::USAGE)
            } else if positional.len() == 2 {
                diff::run_diff(positional[0], positional[1])
            } else {
                eprintln!("usage: witness-log diff <a.json> <b.json>");
                if positional.len() > 2 {
                    eprintln!(
                        "  (got {} paths; diff compares exactly two)",
                        positional.len()
                    );
                }
                ExitCode::from(exit::USAGE)
            }
        }
        Some("witness") => witness_cmd::run(args.get(2..).unwrap_or(&[])),
        Some("explain") => {
            let json = args.iter().any(|a| a == "--json");
            // Skip flags when looking for the topic. Without this,
            // `explain --json` treats "--json" as the topic name, finds no
            // matching verdict, and exits 2 with an empty result — the same
            // class of bug as flags being silently swallowed as positional
            // arguments, which the first review caught in `verify`.
            let topic = args
                .get(2..)
                .unwrap_or(&[])
                .iter()
                .find(|a| !a.starts_with("--"))
                .map(String::as_str);
            explain::run_explain(topic, json)
        }
        Some("c2sp") => match args.get(2).map(String::as_str) {
            Some("show") => {
                let rest = &args[3..];
                let origin = flag_value(rest, "--origin");
                let sign_with = flag_value(rest, "--sign-with");
                let raw = rest.iter().any(|a| a == "--raw");
                // Positional = the dossier path: everything that is neither a
                // flag nor the value of a value-taking flag.
                let positional: Vec<&String> = rest
                    .iter()
                    .enumerate()
                    .filter(|(i, a)| {
                        !a.starts_with("--")
                            && !matches!(
                                i.checked_sub(1)
                                    .and_then(|p| rest.get(p))
                                    .map(String::as_str),
                                Some("--origin") | Some("--sign-with")
                            )
                    })
                    .map(|(_, a)| a)
                    .collect();
                if let Some(bad) = rest.iter().find(|a| {
                    a.starts_with("--")
                        && !matches!(a.as_str(), "--origin" | "--sign-with" | "--raw")
                }) {
                    eprintln!("unrecognized flag for `c2sp show`: {bad}");
                    eprintln!("usage: witness-log c2sp show <dossier.json> --origin <name> [--raw] [--sign-with <journal>]");
                    return ExitCode::from(exit::USAGE);
                }
                match (positional.first(), origin) {
                    (Some(path), Some(origin)) if positional.len() == 1 => {
                        c2sp_cmd::run_show(path, &origin, &c2sp_cmd::ShowOptions { raw, sign_with })
                    }
                    _ => {
                        eprintln!("usage: witness-log c2sp show <dossier.json> --origin <name> [--raw] [--sign-with <journal>]");
                        eprintln!("  --origin     a stable log identifier; use the canonical `witness-log/<identity hex>`");
                        eprintln!("               (printed by `witness submit`) for anything a witness should cosign");
                        eprintln!("  --raw        print only the body or signed note, for piping");
                        eprintln!("  --sign-with  sign the body with the identity key held in this journal");
                        ExitCode::from(exit::USAGE)
                    }
                }
            }
            Some("verify") => {
                let rest = &args[3..];
                if let Some(bad) = rest
                    .iter()
                    .find(|a| a.starts_with("--") && a.as_str() != "--vkey")
                {
                    eprintln!("unrecognized flag for `c2sp verify`: {bad}");
                    eprintln!("usage: witness-log c2sp verify <note.txt> --vkey <vkey> [--vkey <vkey>...]");
                    return ExitCode::from(exit::USAGE);
                }
                let vkeys = all_flag_values(rest, "--vkey");
                let positional: Vec<&String> = rest
                    .iter()
                    .enumerate()
                    .filter(|(i, a)| {
                        !a.starts_with("--")
                            && i.checked_sub(1)
                                .and_then(|p| rest.get(p))
                                .map(String::as_str)
                                != Some("--vkey")
                    })
                    .map(|(_, a)| a)
                    .collect();
                match positional.first() {
                    Some(path) if positional.len() == 1 => c2sp_cmd::run_verify(path, &vkeys),
                    _ => {
                        eprintln!("usage: witness-log c2sp verify <note.txt> --vkey <vkey> [--vkey <vkey>...]");
                        ExitCode::from(exit::USAGE)
                    }
                }
            }
            _ => {
                eprintln!("usage: witness-log c2sp <show|verify> ...");
                eprintln!("  run `witness-log --help` for details");
                ExitCode::from(exit::USAGE)
            }
        },
        Some("conform") => match args.get(2) {
            Some(dir) => run_conform(dir),
            None => {
                eprintln!("usage: witness-log conform <candidate-corpus-dir>");
                ExitCode::from(exit::USAGE)
            }
        },
        Some("--help") | Some("-h") | Some("help") => {
            print!("{HELP}");
            ExitCode::SUCCESS
        }
        Some("--version") | Some("-V") | Some("version") => {
            println!("witness-log {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        None => {
            // Bare `witness-log` with no arguments: point at the demo
            // rather than dumping usage. Someone who just installed this
            // and typed the binary name is asking "what is this?", and
            // the fastest honest answer is one runnable command.
            println!("witness-log — verifiable audit trails for autonomous agents");
            println!();
            println!("  Try:  witness-log demo        (zero arguments, writes nothing)");
            println!("        witness-log --help      (all commands)");
            ExitCode::SUCCESS
        }
        Some(other) => {
            eprintln!("unknown command: {other}");
            eprintln!("  run `witness-log --help`, or `witness-log demo` to see it work");
            ExitCode::from(exit::USAGE)
        }
    }
}

/// Field-by-field comparison of a candidate corpus directory against the
/// reference corpus committed in this repository. The comparison is over
/// parsed JSON values, so formatting/key-order differences don't matter —
/// only actual values do, which is exactly the property a wire-format
/// conformance check should have.
fn run_conform(candidate_dir: &str) -> ExitCode {
    let reference_dir = "corpus";
    let files = [
        "01_leaf_encoding.json",
        "02_merkle_roots.json",
        "03_inclusion_proofs.json",
        "04_signed_tree_head.json",
        "05_redaction_continuity.json",
        "06_consistency_proof.json",
        "07_handoff_attestation.json",
        "08_authorization_event.json",
        "09_external_anchor.json",
        "10_c2sp_checkpoint.json",
        "11_payload_hash.json",
    ];
    let mut mismatches = 0usize;
    let mut missing = 0usize;
    for f in files {
        let ref_path = format!("{reference_dir}/{f}");
        let cand_path = format!("{}/{f}", candidate_dir.trim_end_matches('/'));
        let reference: serde_json::Value = match fs::read_to_string(&ref_path)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
        {
            Some(v) => v,
            None => {
                eprintln!("✗ cannot read reference {ref_path} — run this from the repository root");
                return ExitCode::from(2);
            }
        };
        let candidate: Option<serde_json::Value> = fs::read_to_string(&cand_path)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok());
        match candidate {
            None => {
                println!("✗ {f}: missing or unparsable in candidate dir");
                missing += 1;
            }
            Some(cand) => {
                let mut diffs = Vec::new();
                diff_json("", &reference, &cand, &mut diffs);
                if diffs.is_empty() {
                    println!("✓ {f}: all values agree");
                } else {
                    println!("✗ {f}: {} differing value(s):", diffs.len());
                    for d in diffs.iter().take(5) {
                        println!("    {d}");
                    }
                    if diffs.len() > 5 {
                        println!("    ... and {} more", diffs.len() - 5);
                    }
                    mismatches += diffs.len();
                }
            }
        }
    }
    println!();
    if mismatches == 0 && missing == 0 {
        println!("Result: CONFORMANT — candidate agrees with the reference corpus on every value");
        ExitCode::SUCCESS
    } else {
        println!("Result: NOT CONFORMANT ({mismatches} value mismatches, {missing} missing files)");
        ExitCode::FAILURE
    }
}

fn diff_json(path: &str, a: &serde_json::Value, b: &serde_json::Value, out: &mut Vec<String>) {
    use serde_json::Value;
    match (a, b) {
        (Value::Object(ma), Value::Object(mb)) => {
            for (k, va) in ma {
                let sub = if path.is_empty() {
                    k.clone()
                } else {
                    format!("{path}.{k}")
                };
                match mb.get(k) {
                    Some(vb) => diff_json(&sub, va, vb, out),
                    None => out.push(format!("{sub}: missing in candidate")),
                }
            }
            for k in mb.keys() {
                if !ma.contains_key(k) {
                    let sub = if path.is_empty() {
                        k.clone()
                    } else {
                        format!("{path}.{k}")
                    };
                    out.push(format!("{sub}: present in candidate but not reference"));
                }
            }
        }
        (Value::Array(aa), Value::Array(ab)) => {
            if aa.len() != ab.len() {
                out.push(format!("{path}: array length {} vs {}", aa.len(), ab.len()));
            }
            for (i, (va, vb)) in aa.iter().zip(ab.iter()).enumerate() {
                diff_json(&format!("{path}[{i}]"), va, vb, out);
            }
        }
        _ => {
            if a != b {
                out.push(format!("{path}: {a} vs {b}"));
            }
        }
    }
}

const VERIFY_USAGE: &str = "usage: witness-log verify <dossier.json> [--threshold 0.0-1.0] [--json] [--explain] [--identity <hex>] [--directory <path>]
  --identity   the identity pubkey you expect (64 hex), obtained out-of-band
  --directory  a witness directory YOU trust: {\"witnesses\": [...]} or a bare [...] of entries
  --threshold  receipt-count bar as a fraction of the directory (default 0.66)
  --min-witnesses N  receipt-count bar as an absolute number of distinct witnesses; use this
               instead of --threshold when the directory is large (a registry)
  Exit: 0 WITNESSED, 10 CONSISTENT-UNWITNESSED, 20 UNANCHORED, 30 DIVERGED, 2 usage";

/// 64 hex characters: a 32-byte key.
pub(crate) fn is_hex32(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// A trusted directory file is `{"witnesses": [...]}`; a bare JSON array
/// of entries (what `witness init` prints, collected) is accepted too.
pub(crate) fn parse_directory(raw: &str) -> Result<WitnessDirectory, String> {
    match serde_json::from_str::<WitnessDirectory>(raw) {
        Ok(d) => Ok(d),
        Err(as_object) => match serde_json::from_str::<Vec<witness_log_network::WitnessEntry>>(raw) {
            Ok(witnesses) => Ok(WitnessDirectory { witnesses }),
            Err(_) => Err(format!(
                "{as_object}\n  expected {{\"witnesses\": [ <entry>, ... ]}} or a bare JSON array of the entries `witness init` prints"
            )),
        },
    }
}

fn parse_options(args: &[String]) -> Result<Options, String> {
    let mut path = None;
    let mut threshold = DEFAULT_QUORUM_THRESHOLD;
    let mut min_witnesses = None;
    let mut json = false;
    let mut explain = false;
    let mut identity = None;
    let mut directory_path = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--threshold" => {
                let v = args
                    .get(i + 1)
                    .ok_or("--threshold requires a value between 0.0 and 1.0")?;
                threshold = v
                    .parse::<f64>()
                    .map_err(|_| format!("--threshold value '{v}' is not a valid number"))?;
                if !(0.0..=1.0).contains(&threshold) {
                    return Err(format!(
                        "--threshold must be between 0.0 and 1.0, got {threshold}"
                    ));
                }
                i += 2;
            }
            "--min-witnesses" => {
                let v = args
                    .get(i + 1)
                    .ok_or("--min-witnesses requires a positive integer")?;
                let n: usize = v.parse().map_err(|_| {
                    format!("--min-witnesses value '{v}' is not a positive integer")
                })?;
                if n == 0 {
                    return Err("--min-witnesses must be at least 1".to_string());
                }
                min_witnesses = Some(n);
                i += 2;
            }
            "--json" => {
                json = true;
                i += 1;
            }
            "--explain" => {
                explain = true;
                i += 1;
            }
            "--identity" => {
                let v = args
                    .get(i + 1)
                    .ok_or("--identity requires a hex-encoded public key")?;
                if !is_hex32(v) {
                    return Err(format!(
                        "--identity must be a 32-byte Ed25519 public key as 64 hex characters, got '{v}'"
                    ));
                }
                identity = Some(v.clone());
                i += 2;
            }
            "--directory" => {
                let v = args.get(i + 1).ok_or(
                    "--directory requires a path to a trusted witness directory JSON file",
                )?;
                directory_path = Some(v.clone());
                i += 2;
            }
            other if other.starts_with("--") => {
                // Previously any unrecognized token fell through to the
                // positional-argument branch below and was silently
                // ignored if a path was already set (e.g. `--jsom` or
                // `--treshold 0.9` ran with defaults, no complaint). A
                // typo'd flag in a security tool should never run
                // silently under different settings than the caller
                // intended. See the pre-launch review, finding 22.
                return Err(format!(
                    "unrecognized flag: {other}\n  run `witness-log --help` for usage"
                ));
            }
            other => {
                if path.is_some() {
                    return Err(format!(
                        "unexpected extra argument: '{other}' (path already set)\n  run `witness-log --help` for usage"
                    ));
                }
                path = Some(other.to_string());
                i += 1;
            }
        }
    }
    Ok(Options {
        path: path.ok_or(VERIFY_USAGE)?,
        threshold,
        min_witnesses,
        json,
        explain,
        identity,
        directory_path,
    })
}

fn run_verify(opts: &Options) -> ExitCode {
    let raw = match fs::read_to_string(&opts.path) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("could not read {}: {e}", opts.path);
            return ExitCode::from(exit::USAGE);
        }
    };
    let dossier: Dossier = match serde_json::from_str(&raw) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("could not parse dossier: {e}");
            return ExitCode::from(exit::USAGE);
        }
    };

    // The trusted directory comes from the CALLER's filesystem, never from
    // the dossier under test. See VerifyContext and finding 02.
    let trusted_directory: Option<WitnessDirectory> = match &opts.directory_path {
        Some(p) => {
            let raw = match fs::read_to_string(p) {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("could not read trusted directory {p}: {e}");
                    return ExitCode::from(exit::USAGE);
                }
            };
            match parse_directory(&raw) {
                Ok(d) => Some(d),
                Err(e) => {
                    eprintln!("could not parse trusted directory {p}: {e}");
                    return ExitCode::from(exit::USAGE);
                }
            }
        }
        None => None,
    };

    let ctx = VerifyContext {
        expected_identity_pubkey: opts.identity.as_deref(),
        trusted_directory: trusted_directory.as_ref(),
        min_receipts: opts.min_witnesses,
    };

    let report = dossier.verify(opts.threshold, &ctx);
    let overall_ok = report.is_internally_consistent();

    if opts.json {
        let output = serde_json::json!({
            "path": opts.path,
            "identity_pubkey": dossier.identity_pubkey,
            "threshold_used": opts.threshold,
            "min_witnesses_used": opts.min_witnesses,
            "identity_pinned": opts.identity.is_some(),
            "directory_pinned": opts.directory_path.is_some(),
            "verdict": report.verdict.to_string(),
            "report": report,
        });
        println!("{}", serde_json::to_string_pretty(&output).unwrap());
        return exit_code_for(&report.verdict);
    }

    render_text(&dossier, &report, opts);

    println!();
    // Four-valued verdict is THE result — see Verdict's doc comment.
    // "VERIFIED/FAILED" undersells what the anchor rule distinguishes.
    print!("Verdict: {}", report.verdict);
    match report.verdict {
        witness_log_network::Verdict::Witnessed => {
            print!(" \u{2014} proofs verify and at least {} independent operators from your trusted directory cosigned this checkpoint", witness_log_network::MIN_INDEPENDENT_OPERATORS_FOR_WITNESSED);
        }
        witness_log_network::Verdict::ConsistentUnwitnessed => {
            print!(
                " \u{2014} cryptography is sound; {}; do NOT treat as fully verified",
                unwitnessed_reason(&report)
            );
        }
        witness_log_network::Verdict::Unanchored => {
            print!(" \u{2014} internally consistent only: no --directory was supplied, so receipts cannot be scored against anything you trust");
            if opts.identity.is_none() {
                print!(" (and no --identity, so nothing ties this file to a party you expected)");
            }
        }
        witness_log_network::Verdict::Diverged => {
            print!(" \u{2014} a check marked \u{2717} above FAILED: the file was altered after signing, was fabricated, or is not the log named by --identity");
        }
    }
    println!();
    if !report.identity_pinned
        && matches!(
            report.verdict,
            witness_log_network::Verdict::Witnessed
                | witness_log_network::Verdict::ConsistentUnwitnessed
        )
    {
        println!(
            "\u{26A0} --identity was not supplied: this verdict is about the log's history, not about whose log it is. A gate should pass --identity {}",
            dossier.checkpoint.signer_pubkey
        );
    }

    // Progressive disclosure: rather than explaining the concept and
    // leaving the reader to assemble the command themselves, hand them
    // the literal next command with the real values already filled in.
    // Nobody reads docs to get from state A to state B when the tool
    // itself tells them, and this turns the CLI into its own tutorial.
    if report.verdict == witness_log_network::Verdict::Unanchored {
        println!();
        println!("To anchor this run to something the dossier's author doesn't control:");
        println!();
        if opts.identity.is_none() {
            println!("  witness-log verify {} \\", opts.path);
            println!("    --identity {} \\", dossier.checkpoint.signer_pubkey);
            println!("    --directory <a-witness-directory-you-trust.json>");
            println!();
            println!("  (the --identity value above is read from this dossier, which is fine for");
            println!(
                "   trying it out -- but in real use it MUST come from somewhere the dossier's"
            );
            println!(
                "   author doesn't control, or you've proven nothing. That's the whole point.)"
            );
        } else {
            println!("  witness-log verify {} \\", opts.path);
            println!(
                "    --identity {} \\",
                opts.identity.as_deref().unwrap_or("")
            );
            println!("    --directory <a-witness-directory-you-trust.json>");
        }
    }

    println!();
    println!(
        "Run with --explain for what each check does and doesn't prove, or see THREAT_MODEL.md"
    );
    let _ = overall_ok;
    exit_code_for(&report.verdict)
}

/// The gate that actually failed for a CONSISTENT-UNWITNESSED verdict,
/// so the reason is printed instead of implied by a row of check marks.
fn unwitnessed_reason(report: &DossierReport) -> String {
    let min = witness_log_network::MIN_INDEPENDENT_OPERATORS_FOR_WITNESSED;
    match &report.quorum {
        None => "no receipt in this dossier is from a witness in your trusted directory".to_string(),
        Some(q) if !q.meets_count_threshold => format!(
            "{}/{} directory witnesses cosigned, below the count gate ({})",
            q.valid_receipts,
            q.total_directory_witnesses,
            q.count_gate
        ),
        Some(q) => format!(
            "only {} independent operator{} cosigned; WITNESSED needs at least {min} (project-operated witnesses count as one bucket, the log's own operator as none)",
            q.distinct_independent_operators,
            if q.distinct_independent_operators == 1 { "" } else { "s" }
        ),
    }
}

fn render_text(dossier: &Dossier, report: &DossierReport, opts: &Options) {
    println!("WitnessLog dossier verification");
    println!("  identity: {}", short(&dossier.identity_pubkey));
    println!("  claimed tree size: {}", report.claimed_tree_size);
    println!();

    if report.checkpoint_signature_valid {
        println!("\u{2713} Checkpoint signature valid");
    } else {
        println!("\u{2717} Checkpoint signature INVALID");
    }
    if opts.explain {
        println!("    Confirms the checkpoint bytes were signed by WHATEVER key checkpoint.signer_pubkey names. On its own this says nothing about whose identity that is -- see the identity binding check below for that.");
    }

    match (report.identity_bound, report.identity_pinned) {
        (true, true) => println!("\u{2713} Identity bound to --identity {}", short(&dossier.checkpoint.signer_pubkey)),
        (true, false) => println!("\u{2713} Identity self-consistent (not pinned: no --identity supplied)"),
        (false, true) => println!("\u{2717} Identity NOT bound: the checkpoint was signed by {}, not the --identity you expected", short(&dossier.checkpoint.signer_pubkey)),
        (false, false) => println!("\u{2717} Identity NOT bound: the dossier's identity_pubkey is not the key that signed its checkpoint"),
    }
    if opts.explain {
        if opts.identity.is_some() {
            println!("    Confirms the dossier's claimed identity_pubkey matches the key that actually signed the checkpoint, AND matches the --identity you supplied. This is the check that stops a fabricated log from being attributed to someone else's key.");
        } else {
            println!("    Confirms the dossier's claimed identity_pubkey matches the key that actually signed the checkpoint (self-consistency only -- you didn't supply --identity, so there's no external confirmation this is the specific party you expected).");
        }
    }

    if report.leaves_structurally_valid {
        println!("\u{2713} Leaf structure valid");
    } else {
        println!("\u{2717} Leaf structure INVALID");
    }
    if opts.explain {
        println!("    Confirms every leaf has a recognized type, well-formed hex fields, all mandatory fields for its type, correct index/position, and that every binding/revocation referenced is well-formed. Timestamps are self-asserted metadata and are NOT checked for order (see THREAT_MODEL.md). Does not confirm the CONTENT is truthful -- only that the structure isn't malformed or internally contradictory.");
    }

    if !report.bindings_asserted {
        println!(
            "\u{2013} Key bindings not asserted (dossier carries no key_bindings or revocations)"
        );
    } else if report.bindings_valid {
        println!(
            "\u{2713} Key bindings valid ({} binding{}, {} revocation{})",
            dossier.key_bindings.len(),
            if dossier.key_bindings.len() == 1 {
                ""
            } else {
                "s"
            },
            dossier.revocations.len(),
            if dossier.revocations.len() == 1 {
                ""
            } else {
                "s"
            }
        );
    } else {
        println!("\u{2717} Key bindings INVALID: a leaf's session key has no valid binding from this identity, falls outside its binding's validity window, or postdates a revocation");
    }
    if opts.explain {
        println!("    Every leaf is signed under a session key; a binding is the identity key's statement that the session key was authorised. Without bindings the dossier is still checked for consistency, but session provenance is simply not asserted.");
    }

    if report.merkle_continuity_valid {
        println!(
            "\u{2713} Merkle continuity verified ({} leaves)",
            report.leaf_count
        );
    } else if report.leaf_count != report.claimed_tree_size {
        println!(
            "\u{2717} Leaf count ({}) does not match checkpoint tree_size ({})",
            report.leaf_count, report.claimed_tree_size
        );
    } else {
        println!("\u{2717} Merkle continuity BROKEN — recomputed root does not match checkpoint");
        println!("    This means the leaves have been altered, reordered, or removed since the checkpoint was signed.");
    }
    if opts.explain {
        println!("    Rebuilds the Merkle root from every leaf in this file and compares it to the signed checkpoint. See THREAT_MODEL.md's 'Log truncation / selective omission' row — this only catches tampering WITHIN the leaves shown to you, not leaves quietly withheld.");
    }

    match &report.quorum {
        Some(result) => {
            let quorum_symbol = if result.meets_count_threshold {
                "\u{2713}"
            } else {
                "\u{2717}"
            };
            println!(
                "{quorum_symbol} {}/{} witness signatures valid (gate: {}{})",
                result.valid_receipts,
                result.total_directory_witnesses,
                match opts.min_witnesses {
                    Some(n) => format!("at least {n} witnesses"),
                    None => format!("{:.0}% of the directory", opts.threshold * 100.0),
                },
                if result.meets_count_threshold {
                    ""
                } else {
                    ", NOT MET"
                }
            );
            if opts.min_witnesses.is_none() && result.total_directory_witnesses >= 16 {
                println!(
                    "    Large directory: {:.0}% of {} is {} cosignatures per checkpoint. \
                     For a registry-sized directory, gate on an absolute count with --min-witnesses N.",
                    opts.threshold * 100.0,
                    result.total_directory_witnesses,
                    (opts.threshold * result.total_directory_witnesses as f64).ceil() as usize
                );
            }
            if result.project_operated_receipts > 0 {
                println!(
                    "\u{26A0} {} of those {} signatures are from project-operated witnesses, not independent third parties.",
                    result.project_operated_receipts, result.valid_receipts
                );
                println!("    Project-operated witnesses prove the mechanism works; they don't provide equivocation-resistance on their own — see GOVERNANCE.md.");
            }

            let diversity_pct = (result.diversity_fraction * 100.0).round();
            let min = witness_log_network::MIN_INDEPENDENT_OPERATORS_FOR_WITNESSED;
            if result.distinct_independent_operators >= min {
                println!(
                    "\u{2713} Independent operators: {} cosigned ({}); {} of {} known operators represented ({diversity_pct}%)",
                    result.distinct_independent_operators,
                    result.independent_operators_represented.join(", "),
                    result.distinct_operators_represented,
                    result.distinct_operators_in_directory
                );
            } else {
                println!(
                    "\u{2717} Independent operators: {} cosigned, WITNESSED needs at least {min}; {} of {} known operators represented ({diversity_pct}%)",
                    result.distinct_independent_operators,
                    result.distinct_operators_represented,
                    result.distinct_operators_in_directory
                );
            }
            if opts.explain {
                println!("    The gate is the absolute number of distinct independent operators, not a fraction: a single operator cannot contradict itself, so equivocation is detectable only once two parties who share no operator have both committed to the same head. See THREAT_MODEL.md's 'Witness independence' section.");
            }

            let compute_pct = (result.compute_diversity_fraction * 100.0).round();
            if result.compute_diversity_fraction < 0.5 {
                println!(
                    "\u{26A0} Compute-provider diversity: LOW ({} of {} known providers represented, {compute_pct}%)",
                    result.distinct_compute_providers_represented, result.distinct_compute_providers_in_directory
                );
            } else {
                println!(
                    "\u{2713} Compute-provider diversity: {} of {} known providers represented ({compute_pct}%)",
                    result.distinct_compute_providers_represented, result.distinct_compute_providers_in_directory
                );
            }
            if opts.explain {
                println!("    Witnesses sharing an underlying model/infra provider can fail identically. Undisclosed providers count as their own low-diversity bucket, not as neutral.");
            }
        }
        None => {
            if opts.directory_path.is_none() {
                println!("\u{26A0} No --directory supplied — witness receipts cannot be scored against anything you trust.");
                if opts.explain {
                    println!("    Even if this dossier ships receipts, they're evaluated only against a directory YOU supply with --directory, never against the dossier's own embedded directory. Without one, this proves tamper-evidence but NOT equivocation-resistance.");
                }
            } else {
                println!("\u{26A0} No witness receipts present — this dossier proves tamper-evidence but NOT equivocation-resistance.");
                if opts.explain {
                    println!("    A single-node log can still show a different history to different verifiers. See THREAT_MODEL.md.");
                }
            }
        }
    }
}

fn short(hexstr: &str) -> String {
    // Previously sliced at byte offsets 8 and len()-8. identity_pubkey is
    // an arbitrary JSON string from an untrusted file -- multibyte UTF-8
    // (e.g. a CJK character) landing on one of those byte offsets panics
    // the whole process rather than returning an error. Operating on
    // chars is always safe regardless of what's in the string. See the
    // pre-launch review, finding 10.
    let chars: Vec<char> = hexstr.chars().collect();
    if chars.len() > 16 {
        let head: String = chars[..8].iter().collect();
        let tail: String = chars[chars.len() - 8..].iter().collect();
        format!("{head}...{tail}")
    } else {
        hexstr.to_string()
    }
}
