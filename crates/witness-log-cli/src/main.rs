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
pub(crate) mod exit {
    pub const WITNESSED: u8 = 0;
    pub const CONSISTENT_UNWITNESSED: u8 = 10;
    /// `verify --strict` only: the verdict was not WITNESSED, or it was
    /// but by fewer than a majority of the directory. Opt-in; the default
    /// run still exits by the verdict codes above.
    pub const STRICT_FAILED: u8 = 11;
    pub const UNANCHORED: u8 = 20;
    /// `submit`: a witness refused the history (422), or fewer than
    /// `--min` cosigned. Same number as UNANCHORED on purpose: both mean
    /// "do not treat this as witnessed", and a script that gates on 0 or
    /// on `< 20` reads either correctly.
    pub const SUBMIT_REFUSED: u8 = 20;
    pub const DIVERGED: u8 = 30;
    /// Usage error, unreadable file, unparseable input — a problem with
    /// the invocation, distinct from any verdict about a dossier.
    pub const USAGE: u8 = 2;
}

pub(crate) fn exit_code_for(verdict: &witness_log_network::Verdict) -> ExitCode {
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
    /// Path to a JSON file of revocation statements the caller knows
    /// about out of band (`--revocations`); applied whether or not the
    /// dossier carries them.
    revocations_path: Option<String>,
    /// Exit 11 unless the verdict is WITNESSED by a majority of the
    /// directory. For gates that must never pass on anything weaker.
    strict: bool,
}

mod bind;
mod c2sp_cmd;
mod demo;
mod diff;
mod directory_cmd;
mod explain;
mod http;
mod journal_serve;
mod log_cmd;
mod testnet;
mod witness_cmd;

const HELP: &str = "witness-log — verifiable audit trails for autonomous agents

  New here? Run `witness-log demo` — zero arguments, nothing written to disk.

USAGE:
  witness-log demo [--tamper]
      A self-contained worked example: build a log, redact a leaf, sign a
      checkpoint, gather witnesses, then verify it twice to show what
      changes when you anchor verification to something outside the file.
      --tamper   build a convincing forgery instead, and watch it get caught.

  witness-log verify <dossier.json> [--threshold 0.0-1.0 | --min-witnesses N] [--json] [--explain] [--revocations <path>]
                      [--identity <hex-pubkey>] [--directory <path.json>] [--strict]
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
      --strict     exit 11 unless WITNESSED by a majority of the directory
      Omitting --identity and --directory is a legal, meaningful run, but
      the strongest reachable verdict is UNANCHORED — see `explain` below.

  witness-log testnet up [--witnesses 3] [--dir ./.witness-testnet] [--out trusted.json]
  witness-log testnet status [--dir DIR]
  witness-log testnet down [--dir DIR]
      Three local witnesses under distinct operator names, as child
      processes of this binary on loopback ports, plus the directory file
      that lists them. Enough to reach WITNESSED on one machine with no
      code: up, `log append`, `submit`, `verify`, down.

  witness-log log init <journal> [--sealed] [--identity-seed-env NAME | --identity-seed-file F]
  witness-log log append <journal> --intent|--result|--memory <payload|@file|-> [--outcome ok|error]
  witness-log log forget <journal> <index>
  witness-log log export <journal> --out dossier.json
  witness-log log disclose <journal> <index>
  witness-log log info <journal>
      An agent's journal from the shell. `append` takes the payload as an
      argument, from @file, or from stdin (-). `disclose` prints the leaf,
      its payload hash and its salt so a verifier can recompute
      SHA256(bucket_pad(payload) || salt || index) for that one entry.
      A sealed journal (--sealed) never stores its seed; every command then
      needs --identity-seed-env NAME or --identity-seed-file F.

  witness-log submit <journal> --directory <trusted.json> [--out dossier.json] [--min N] [--allow-partial]
      Same as `witness submit`: get the journal's head cosigned and write
      a dossier. Fail-closed: --min defaults to a majority of the directory
      (never below 2) and a 422 refusal exits 20.

  witness-log journal serve <journal> [--listen 127.0.0.1:7390] [--directory trusted.json] [--allow-remote]
      A small HTTP front for one journal, for agents in any language:
      POST /append {kind,payload,outcome?}, POST /forget {index},
      POST /submit {directory_path?,want?,min?}, GET /dossier, GET /info.
      Loopback only unless --allow-remote.

  witness-log directory build [--registry DIR | --url URL] [--include-project] --out trusted.json
  witness-log directory add <trusted.json> --vkey <c2sp vkey> --org ORG --url URL [--compute P]
      Build a directory file from registry/witnesses/*.json (the schema
      registry/build_directory.py produces), or add one witness by its
      C2SP verifier key.

  witness-log diff <a.json> <b.json>
      Compare two dossiers claiming to be the same log. This is the
      equivocation check: a log that showed one history to you and a
      different one to someone else is exactly what witnessing exists to
      catch, and this is how you catch it with two copies in hand.

  witness-log bind <a.json> <b.json> [--json]
      Two DIFFERENT agents' dossiers: match their HandoffAttestation and
      AuthorizationEvent leaves (SPEC §3.1–§3.2) and prove both sides
      committed, in their own logs, to the same bytes or scope between the
      same two identities. Exit 0 bound, 30 mismatch, 10 nothing to bind.

  witness-log explain [verdict|<name>]
      What each verdict means, what it does NOT mean, and how to reach the
      next level. Machine-readable with --json, so an agent that hits an
      unexpected verdict can ask why without a human in the loop.

  witness-log c2sp show <dossier.json> --origin <name> [--raw] [--sign-with <journal>]
  witness-log c2sp export <dossier.json> [--directory trusted.json] --out note.txt
  witness-log c2sp verify <note.txt> --vkey <vkey> [--vkey <vkey>...]
      Transparency-log interoperability (c2sp.org). `show` renders a
      dossier's checkpoint as a C2SP checkpoint body — the artifact an
      existing CT-ecosystem witness cosigns. `export` writes the signed
      note with the dossier's cosignatures attached, for any C2SP tool.
      `verify` checks a signed note and any cosignatures against verifier
      keys you supply; exit 30 when a supplied key does not verify.
      See SPEC.md §9.3.

  witness-log witness init <dir> --name <key-name> [--org <operator>] [--url <url>]
  witness-log witness serve <dir> [--listen 127.0.0.1:7380] [--open-enrollment]
  witness-log witness add-log <dir> <origin> <log-vkey>
  witness-log witness info <http://witness-url>
  witness-log witness submit <journal> --directory <witnesses.json> [--out dossier.json]
  witness-log witness verify-evidence <evidence.json>
      Run a c2sp.org/tlog-witness witness, or get an agent's journal
      cosigned by the witnesses in a directory. `serve` persists every
      cosigned head (fsync) before replying and refuses forks with 422,
      recording provable equivocation under evidence/. With --open-enrollment it accepts
      any agent whose origin is witness-log/<its identity key> -- the
      origin names the key, so no key exchange is needed. `submit`
      writes a dossier whose receipts verify offline. `verify-evidence`
      checks an equivocation proof a witness recorded (exit 0 proven,
      30 not).

  witness-log conform <candidate-corpus-dir>
      Compare another implementation's generated conformance vectors
      against this implementation's committed /corpus. This is how a
      from-scratch reimplementation proves wire-format agreement — see
      CONTRIBUTING.md.

  witness-log --help | -h | help
      This text.

  witness-log --version

EXIT CODES — the verdict IS the exit status, so gating needs no JSON parsing:
   0  WITNESSED                        20  UNANCHORED; submit: refused (422) or below --min
  10  CONSISTENT-UNWITNESSED           30  DIVERGED
  11  verify --strict: not WITNESSED    2  usage / unreadable input
      by a directory majority
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
        Some("bind") => {
            let json = args[2..].iter().any(|a| a == "--json");
            let positional: Vec<&String> =
                args[2..].iter().filter(|a| !a.starts_with("--")).collect();
            if let Some(flag) = args[2..]
                .iter()
                .find(|a| a.starts_with("--") && *a != "--json")
            {
                eprintln!("unrecognized flag for `bind`: {flag}");
                eprintln!("  usage: witness-log bind <a.json> <b.json> [--json]");
                ExitCode::from(exit::USAGE)
            } else if positional.len() == 2 {
                bind::run_bind(positional[0], positional[1], json)
            } else {
                eprintln!("usage: witness-log bind <a.json> <b.json> [--json]");
                ExitCode::from(exit::USAGE)
            }
        }
        Some("witness") => witness_cmd::run(args.get(2..).unwrap_or(&[])),
        // `submit` at the top level is the same command as `witness submit`:
        // the newcomer path is init, append, submit, verify, and the
        // `witness` prefix read as "run a witness" to people who only wanted
        // to use one.
        Some("submit") => {
            let mut rest = vec!["submit".to_string()];
            rest.extend(args.get(2..).unwrap_or(&[]).iter().cloned());
            witness_cmd::run(&rest)
        }
        Some("log") => log_cmd::run(args.get(2..).unwrap_or(&[])),
        Some("journal") => journal_serve::run(args.get(2..).unwrap_or(&[])),
        Some("directory") => directory_cmd::run(args.get(2..).unwrap_or(&[])),
        Some("testnet") => testnet::run(args.get(2..).unwrap_or(&[])),
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
            Some("export") => c2sp_cmd::run_export(&args[3..]),
            Some("show") => {
                let rest = &args[3..];
                let origin = flag_value(rest, "--origin");
                let sign_with = flag_value(rest, "--sign-with");
                let raw = rest.iter().any(|a| a == "--raw");
                let seed = match identity_seed_from_args(rest) {
                    Ok(s) => s,
                    Err(e) => {
                        eprintln!("{e}");
                        return ExitCode::from(exit::USAGE);
                    }
                };
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
                                Some("--origin")
                                    | Some("--sign-with")
                                    | Some("--identity-seed-env")
                                    | Some("--identity-seed-file")
                            )
                    })
                    .map(|(_, a)| a)
                    .collect();
                if let Some(bad) = rest.iter().find(|a| {
                    a.starts_with("--")
                        && !matches!(
                            a.as_str(),
                            "--origin"
                                | "--sign-with"
                                | "--raw"
                                | "--identity-seed-env"
                                | "--identity-seed-file"
                        )
                }) {
                    eprintln!("unrecognized flag for `c2sp show`: {bad}");
                    eprintln!("usage: witness-log c2sp show <dossier.json> --origin <name> [--raw] [--sign-with <journal>] [--identity-seed-env NAME | --identity-seed-file F]");
                    return ExitCode::from(exit::USAGE);
                }
                match (positional.first(), origin) {
                    (Some(path), Some(origin)) if positional.len() == 1 => c2sp_cmd::run_show(
                        path,
                        &origin,
                        &c2sp_cmd::ShowOptions {
                            raw,
                            sign_with,
                            seed,
                        },
                    ),
                    _ => {
                        eprintln!("usage: witness-log c2sp show <dossier.json> --origin <name> [--raw] [--sign-with <journal>] [--identity-seed-env NAME | --identity-seed-file F]");
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
                eprintln!("usage: witness-log c2sp <show|export|verify> ...");
                eprintln!("  run `witness-log --help` for details");
                ExitCode::from(exit::USAGE)
            }
        },
        Some("conform") => {
            // `--reference <dir>`: the corpus to compare against. Defaults
            // to ./corpus, which only exists in a checkout; a `cargo
            // install` user points this at a downloaded corpus/.
            let rest = &args[2..];
            let reference = flag_value(rest, "--reference");
            let positional: Vec<&String> = rest
                .iter()
                .enumerate()
                .filter(|(i, a)| {
                    !a.starts_with("--")
                        && i.checked_sub(1)
                            .and_then(|p| rest.get(p))
                            .map(String::as_str)
                            != Some("--reference")
                })
                .map(|(_, a)| a)
                .collect();
            let bad_flag = rest
                .iter()
                .find(|a| a.starts_with("--") && a.as_str() != "--reference");
            match (positional.as_slice(), bad_flag) {
                ([dir], None) => run_conform(dir, reference.as_deref().unwrap_or("corpus")),
                _ => {
                    eprintln!("usage: witness-log conform <candidate-corpus-dir> [--reference <corpus-dir>]");
                    ExitCode::from(exit::USAGE)
                }
            }
        }
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
fn run_conform(candidate_dir: &str, reference_dir: &str) -> ExitCode {
    let reference_dir = reference_dir.trim_end_matches('/');
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
                eprintln!(
                    "✗ cannot read reference {ref_path} — run this from the repository root, \
                     or pass --reference <path to the repository's corpus/ directory>"
                );
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

const VERIFY_USAGE: &str = "usage: witness-log verify <dossier.json> [--threshold 0.0-1.0 | --min-witnesses N] [--json] [--explain] [--identity <hex>] [--directory <path>] [--strict]
  --identity   the identity pubkey you expect (64 hex), obtained out-of-band
  --directory  a witness directory YOU trust: {\"witnesses\": [...]} or a bare [...] of entries
  --revocations <path>  revocation statements you know of (JSON array); applied even if the
               dossier omits them: leaves and checkpoints the revoked key signed after
               as_of_ms do not verify
  --threshold  receipt-count bar as a fraction of the directory (default 0.66)
  --min-witnesses N  receipt-count bar as an absolute number of distinct witnesses; use this
               instead of --threshold when the directory is large (a registry)
  --strict     exit 11 unless the verdict is WITNESSED and the cosigning witnesses are a
               strict majority of the directory (split-view resistant)
  Exit: 0 WITNESSED, 10 CONSISTENT-UNWITNESSED, 20 UNANCHORED, 30 DIVERGED, 2 usage
        11 (--strict only) anything weaker than WITNESSED by a directory majority";

/// `--identity-seed-env NAME` / `--identity-seed-file F`: the identity
/// seed for a sealed journal, 32 bytes as 64 hex characters, from the
/// named environment variable or file (a file may also hold the raw 32
/// bytes). Never from the command line itself, where it would land in
/// shell history and process listings. `Ok(None)` when neither flag is
/// given.
pub(crate) fn identity_seed_from_args(
    args: &[String],
) -> Result<Option<zeroize::Zeroizing<[u8; 32]>>, String> {
    let from_env = flag_value(args, "--identity-seed-env");
    let from_file = flag_value(args, "--identity-seed-file");
    if args.iter().any(|a| a == "--identity-seed-env") && from_env.is_none() {
        return Err("--identity-seed-env requires the name of an environment variable".into());
    }
    if args.iter().any(|a| a == "--identity-seed-file") && from_file.is_none() {
        return Err("--identity-seed-file requires a path".into());
    }
    if from_env.is_some() && from_file.is_some() {
        return Err("give either --identity-seed-env or --identity-seed-file, not both".into());
    }
    let raw: zeroize::Zeroizing<Vec<u8>> = match (from_env, from_file) {
        (Some(name), _) => {
            let v = env::var(&name)
                .map_err(|_| format!("environment variable {name} is not set (or is not UTF-8)"))?;
            zeroize::Zeroizing::new(v.into_bytes())
        }
        (None, Some(path)) => {
            zeroize::Zeroizing::new(fs::read(&path).map_err(|e| format!("{path}: {e}"))?)
        }
        (None, None) => return Ok(None),
    };
    parse_seed(&raw).map(Some)
}

/// A seed as 64 hex characters (surrounding whitespace ignored) or as the
/// raw 32 bytes.
pub(crate) fn parse_seed(raw: &[u8]) -> Result<zeroize::Zeroizing<[u8; 32]>, String> {
    if raw.len() == 32 {
        let mut out = zeroize::Zeroizing::new([0u8; 32]);
        out.copy_from_slice(raw);
        return Ok(out);
    }
    let text = std::str::from_utf8(raw).map_err(|_| "seed is neither 32 raw bytes nor hex")?;
    let decoded = hex::decode(text.trim())
        .map_err(|_| "seed must be 64 hex characters (32 bytes)".to_string())?;
    let bytes: [u8; 32] = decoded
        .try_into()
        .map_err(|_| "seed must be exactly 32 bytes".to_string())?;
    Ok(zeroize::Zeroizing::new(bytes))
}

/// Replay a journal read-only, with the seed when the caller supplied
/// one (required for a sealed journal; checked against an unsealed one).
pub(crate) fn replay_journal(
    path: &str,
    seed: Option<&[u8; 32]>,
) -> std::io::Result<(
    witness_log_core::log::WitnessLog,
    witness_log_core::journal::ReplayReport,
)> {
    match seed {
        Some(s) => witness_log_core::journal::LeafJournal::replay_with_identity(path, s),
        None => witness_log_core::journal::LeafJournal::replay(path).map_err(sealed_hint),
    }
}

/// The core crate's "sealed journal" error names the library call; the
/// CLI user needs the flag.
fn sealed_hint(e: std::io::Error) -> std::io::Error {
    if e.to_string().contains("sealed") {
        std::io::Error::new(
            e.kind(),
            format!(
                "{e}\n  this journal is sealed: pass --identity-seed-env NAME or --identity-seed-file F"
            ),
        )
    } else {
        e
    }
}

/// Open a journal for appends, with the seed when supplied.
pub(crate) fn resume_journal(
    path: &str,
    seed: Option<&[u8; 32]>,
) -> std::io::Result<(
    witness_log_core::journal::JournaledLog,
    witness_log_core::journal::ReplayReport,
)> {
    match seed {
        Some(s) => witness_log_core::journal::JournaledLog::resume_with_identity(path, s),
        None => witness_log_core::journal::JournaledLog::resume(path).map_err(sealed_hint),
    }
}

/// 64 hex characters: a 32-byte key.
/// Largest input file (dossier, directory, note, evidence) the CLI reads.
/// A dossier of a million leaves is a few hundred MiB; anything larger is
/// refused with a message instead of being read until memory runs out.
pub(crate) const MAX_INPUT_BYTES: u64 = 512 * 1024 * 1024;

/// `fs::read_to_string` with a size cap. 0.3.5 read inputs unbounded, so
/// `witness-log verify /dev/zero` (or a FIFO) grew until the OOM killer
/// ended it, with no message (found by the hostile-input evaluation).
pub(crate) fn read_input(path: &str) -> std::io::Result<String> {
    use std::io::Read;
    let mut out = String::new();
    fs::File::open(path)?
        .take(MAX_INPUT_BYTES + 1)
        .read_to_string(&mut out)?;
    if out.len() as u64 > MAX_INPUT_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("input is larger than {} MiB", MAX_INPUT_BYTES >> 20),
        ));
    }
    Ok(out)
}

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
    let mut revocations_path = None;
    let mut strict = false;
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
            "--revocations" => {
                revocations_path = Some(
                    args.get(i + 1)
                        .ok_or("--revocations requires a path")?
                        .clone(),
                );
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
            "--strict" => {
                strict = true;
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
        revocations_path,
        strict,
    })
}

/// `--strict`: the one exit code a gate that must never pass on anything
/// weaker can rely on. WITNESSED alone is not enough: a WITNESSED dossier
/// cosigned by fewer than half the directory can coexist with a
/// conflicting one (see `QuorumResult::split_view_resistant`).
/// The `--strict` exit status as a plain code (`ExitCode` is not
/// comparable on the MSRV toolchain).
fn strict_exit_code(report: &DossierReport) -> u8 {
    let majority = report
        .quorum
        .as_ref()
        .is_some_and(|q| q.split_view_resistant);
    if report.verdict == witness_log_network::Verdict::Witnessed && majority {
        exit::WITNESSED
    } else {
        exit::STRICT_FAILED
    }
}

fn run_verify(opts: &Options) -> ExitCode {
    let raw = match read_input(&opts.path) {
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
            let raw = match read_input(p) {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("could not read trusted directory {p}: {e}");
                    return ExitCode::from(exit::USAGE);
                }
            };
            match parse_directory(&raw) {
                Ok(d) => {
                    // An entry whose key is not a key can never match a
                    // receipt; say so instead of silently scoring it as a
                    // witness that did not cosign.
                    for w in &d.witnesses {
                        if !is_hex32(w.pubkey.trim()) {
                            eprintln!(
                                "warning: trusted directory entry {:?} has a malformed pubkey {:?}; \
                                 it can never count toward the quorum",
                                w.name, w.pubkey
                            );
                        }
                    }
                    Some(d)
                }
                Err(e) => {
                    eprintln!("could not parse trusted directory {p}: {e}");
                    return ExitCode::from(exit::USAGE);
                }
            }
        }
        None => None,
    };

    let revocations: Vec<witness_log_core::identity::RevocationStatement> = match &opts
        .revocations_path
    {
        Some(p) => match std::fs::read_to_string(p)
            .map_err(|e| e.to_string())
            .and_then(|t| serde_json::from_str(&t).map_err(|e| e.to_string()))
        {
            Ok(v) => v,
            Err(e) => {
                eprintln!("could not read revocations {p}: {e} (expected a JSON array of revocation statements)");
                return ExitCode::from(exit::USAGE);
            }
        },
        None => Vec::new(),
    };
    let ctx = VerifyContext {
        expected_identity_pubkey: opts.identity.as_deref(),
        trusted_directory: trusted_directory.as_ref(),
        min_receipts: opts.min_witnesses,
        revocations: &revocations,
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
            "strict": opts.strict,
            "verdict": report.verdict.to_string(),
            "report": report,
        });
        println!("{}", serde_json::to_string_pretty(&output).unwrap());
        return if opts.strict {
            ExitCode::from(strict_exit_code(&report))
        } else {
            exit_code_for(&report.verdict)
        };
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
    if opts.strict {
        let code = strict_exit_code(&report);
        if code != exit::WITNESSED {
            println!(
                "--strict: not WITNESSED by a majority of the directory ({}); exit 11",
                match &report.quorum {
                    Some(q) => format!(
                        "verdict {}, {}/{} directory witnesses cosigned",
                        report.verdict, q.valid_receipts, q.total_directory_witnesses
                    ),
                    None => format!("verdict {}", report.verdict),
                }
            );
        }
        return ExitCode::from(code);
    }
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

    let anchors = dossier
        .leaves
        .iter()
        .filter(|l| l.leaf_type == witness_log_core::leaf::LeafType::ExternalAnchor.tag())
        .count();
    if anchors > 0 {
        println!(
            "\u{2139} External anchors: {anchors} recorded (proof hashes bound to the leaves; the anchors themselves are NOT fetched or verified against their providers by this tool)"
        );
        if opts.explain {
            println!("    An ExternalAnchor leaf commits to SHA-256 of a provider response (Rekor, an RFC 3161 TSA) and its URL. The leaf proves what the log claimed to have anchored, not that the provider agrees; confirm that by fetching the URL and checking the response hash against anchor_proof_hash.");
        }
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
            let gate_count = match opts.min_witnesses {
                Some(n) => n,
                None => (opts.threshold * result.total_directory_witnesses as f64).ceil() as usize,
            };
            if result.meets_count_threshold
                && result.split_view_resistant
                && gate_count * 2 <= result.total_directory_witnesses
            {
                println!(
                    "\u{26A0} This dossier was cosigned by a majority ({}/{}), but the gate you set ({}) is not one: a different dossier passing it could coexist with a conflicting one. Use --min-witnesses {} or the default --threshold 0.66 to make the gate itself split-view resistant.",
                    result.valid_receipts,
                    result.total_directory_witnesses,
                    result.count_gate,
                    result.total_directory_witnesses / 2 + 1
                );
            }
            if result.meets_count_threshold && !result.split_view_resistant {
                println!(
                    "\u{26A0} Split view possible: {} of {} directory witnesses cosigned, not a majority. A conflicting history cosigned by a disjoint set of the other {} would also pass this gate, and no witness would see both.",
                    result.valid_receipts,
                    result.total_directory_witnesses,
                    result.total_directory_witnesses - result.valid_receipts
                );
                println!(
                    "    Raise the gate above half the directory (--min-witnesses {} here, or the default --threshold 0.66), or compare copies with `witness-log diff`.",
                    result.total_directory_witnesses / 2 + 1
                );
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

pub(crate) fn short(hexstr: &str) -> String {
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
