//! `witness-log log ...` -- an agent's journal from the shell.
//!
//! The library API (`JournaledLog`) is what a Rust or Python agent uses.
//! These subcommands expose the same operations to a shell script, a CI
//! step, or an agent written in a language without bindings, so the path
//! from install to a WITNESSED dossier needs no code at all:
//!
//! ```sh
//! witness-log log init agent.jsonl
//! witness-log log append agent.jsonl --intent '{"tool":"pay","amount":5}'
//! witness-log log append agent.jsonl --result '{"tx":"ok"}' --outcome ok
//! witness-log submit agent.jsonl --directory trusted.json --out dossier.json
//! ```
//!
//! Every command takes `--identity-seed-env NAME` or
//! `--identity-seed-file F` for a sealed journal (one whose header holds
//! only the public key). The seed is never accepted on the command line
//! itself.

use std::io::Read;
use std::path::Path;
use std::process::ExitCode;
use witness_log_core::identity::IdentityKeypair;
use witness_log_core::journal::JournaledLog;
use witness_log_core::leaf::LeafType;
use witness_log_core::redaction::{FileSaltStore, SaltStore};
use witness_log_network::Dossier;

const USAGE: &str = "usage:
  witness-log log init <journal> [--sealed] [--identity-seed-env NAME | --identity-seed-file F]
      Create a journal. Without flags a fresh identity is generated and its seed
      is stored in the journal header (mode 0600). With --sealed the seed is never
      written to the journal: supply it from an environment variable or a file.
      --identity-seed-file F with a file that does not exist yet generates a seed
      into F (mode 0600) and uses it.
  witness-log log append <journal> (--intent | --result | --memory) <payload | @file | ->
                                   [--outcome ok|error] [--json]
      Append one leaf. The payload is the argument's bytes, the contents of @file,
      or stdin when `-`. --outcome (results only) commits the canonical JSON
      {\"outcome\":\"ok|error\",\"value\":\"<payload>\"} instead of the raw payload;
      the exact bytes committed are printed so they can be disclosed later.
  witness-log log forget <journal> <index>
      Right to be forgotten: erase the salt for leaf <index> and append a
      Redaction leaf. Every proof over the log stays valid.
  witness-log log export <journal> --out dossier.json
      Write an unwitnessed dossier (leaves, signed checkpoint, key bindings).
  witness-log log disclose <journal> <index>
      Print the leaf, its payload hash and its salt, so a verifier holding the
      payload can recompute SHA256(bucket_pad(payload) || salt || index) and
      compare it with the leaf's payload_hash.
  witness-log log info <journal>
      Identity, size, root, leaf counts, whether the journal is sealed.
  witness-log log receipt <journal> <index> [--out receipt.json]
      Sign a write receipt for leaf <index> (SPEC §9.4): this log's statement
      that it accepted that entry (its payload_hash) at tree size <index>.
      Hand it to whoever submitted the entry. With it and the log's later
      witnessed dossiers they can check the entry was kept, or prove it was
      left out: `witness-log prove-silence`. Exit 2 for an index the journal
      does not hold.
  witness-log log revoke <journal> --reason TEXT [--as-of-ms MS] [--out revocation.json]
                         [--experimental --as-of-index N | --experimental --at-current-size]
      Sign a revocation of this journal's identity key (SPEC §5) and print it.
      Verifiers apply it with `verify --revocations revocation.json` even when a
      dossier omits it: leaves and checkpoints signed at or after as_of_ms (default
      now) stop counting. --as-of-index N (RFC-0005, experimental, requires
      --experimental) also cuts off by position: nothing at index N or later and
      no head larger than N, whatever its timestamps; --at-current-size uses the
      journal's size now. Pair it with a witnessed checkpoint of that size.
  Every command accepts --identity-seed-env NAME or --identity-seed-file F for a
  sealed journal.";

fn usage_err(msg: &str) -> ExitCode {
    eprintln!("{msg}\n\n{USAGE}");
    ExitCode::from(2)
}

fn fail(msg: impl std::fmt::Display) -> ExitCode {
    eprintln!("{msg}");
    ExitCode::from(1)
}

/// Flags every `log` subcommand accepts, so a typo is caught before any
/// file is opened.
const COMMON_VALUE_FLAGS: &[&str] = &["--identity-seed-env", "--identity-seed-file"];

/// Positional arguments and a check that every flag is known.
/// `value_flags` take one value; `bool_flags` take none.
fn split_args<'a>(
    args: &'a [String],
    value_flags: &[&str],
    bool_flags: &[&str],
) -> Result<Vec<&'a String>, String> {
    let mut positional = Vec::new();
    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        if value_flags.contains(&a) || COMMON_VALUE_FLAGS.contains(&a) {
            if args.get(i + 1).is_none() {
                return Err(format!("{a} requires a value"));
            }
            i += 2;
        } else if bool_flags.contains(&a) {
            i += 1;
        } else if a.starts_with("--") && a.len() > 2 {
            return Err(format!("unrecognized flag: {a}"));
        } else {
            positional.push(&args[i]);
            i += 1;
        }
    }
    Ok(positional)
}

pub fn run(args: &[String]) -> ExitCode {
    let sub = args.first().map(String::as_str);
    let rest = args.get(1..).unwrap_or(&[]);
    if matches!(sub, Some("--help") | Some("-h") | Some("help"))
        || rest.iter().any(|a| a == "--help" || a == "-h")
    {
        println!("{USAGE}");
        return ExitCode::SUCCESS;
    }
    match sub {
        Some("init") => cmd_init(rest),
        Some("append") => cmd_append(rest),
        Some("forget") => cmd_forget(rest),
        Some("export") => cmd_export(rest),
        Some("disclose") => cmd_disclose(rest),
        Some("info") => cmd_info(rest),
        Some("receipt") => cmd_receipt(rest),
        Some("revoke") => cmd_revoke(rest),
        _ => usage_err(
            "log: expected a subcommand (init, append, forget, export, disclose, info, receipt, revoke)",
        ),
    }
}

// --------------------------------------------------------------- receipt

/// What the log operator hands the party whose entry it accepted: a
/// signed `WriteReceipt` for one leaf. The counterparty keeps it and later
/// runs `witness-log prove-silence` against the log's witnessed dossiers.
fn cmd_receipt(args: &[String]) -> ExitCode {
    let positional = match split_args(args, &["--out"], &[]) {
        Ok(p) => p,
        Err(e) => return usage_err(&format!("log receipt: {e}")),
    };
    let [journal, index] = positional.as_slice() else {
        return usage_err("log receipt: expected <journal> <index>");
    };
    let index = match parse_index(index) {
        Ok(i) => i,
        Err(e) => return usage_err(&format!("log receipt: {e}")),
    };
    let out = crate::flag_value(args, "--out");
    if args.iter().any(|a| a == "--out") && out.is_none() {
        return usage_err("log receipt: --out requires a path");
    }
    let seed = match crate::identity_seed_from_args(args) {
        Ok(s) => s,
        Err(e) => return usage_err(&format!("log receipt: {e}")),
    };
    let (log, report) = match crate::replay_journal(journal, seed.as_deref()) {
        Ok(x) => x,
        Err(e) => return fail(format!("{journal}: {e}")),
    };
    if report.dropped_trailing_lines > 0 {
        eprintln!(
            "note: {journal} has a partially written last line; only its {} complete leaves count",
            log.tree_size()
        );
    }
    // A receipt for an entry the log does not hold would be a promise about
    // nothing; the library refuses it, and so does this command.
    let Some(receipt) = log.write_receipt(index) else {
        eprintln!(
            "log receipt: {journal} has no leaf {index} (tree size {}); a write receipt is issued \
             only for an entry the log holds",
            log.tree_size()
        );
        return ExitCode::from(2);
    };
    let text = match serde_json::to_string_pretty(&receipt) {
        Ok(t) => t,
        Err(e) => return fail(e),
    };
    match out {
        Some(out) => {
            if let Err(e) = crate::witness_cmd::atomic_write_shared(
                Path::new(&out),
                format!("{text}\n").as_bytes(),
            ) {
                return fail(format!("{out}: {e}"));
            }
            eprintln!(
                "write receipt for leaf {index} (payload_hash {}) written to {out}. Hand it to whoever \
                 submitted that entry; they check it later with `witness-log prove-silence {out} \
                 --dossier <dossier.json> --directory <trusted.json> --identity {}`",
                receipt.payload_hash, receipt.signer_pubkey
            );
        }
        None => println!("{text}"),
    }
    ExitCode::SUCCESS
}

// ---------------------------------------------------------------- revoke

fn cmd_revoke(args: &[String]) -> ExitCode {
    let positional = match split_args(
        args,
        &["--reason", "--as-of-ms", "--as-of-index", "--out"],
        &["--experimental", "--at-current-size"],
    ) {
        Ok(p) => p,
        Err(e) => return usage_err(&format!("log revoke: {e}")),
    };
    let [journal] = positional.as_slice() else {
        return usage_err("log revoke: expected exactly one <journal> path");
    };
    let Some(reason) = crate::flag_value(args, "--reason") else {
        return usage_err(
            "log revoke: --reason TEXT is required (it is signed into the statement)",
        );
    };
    let as_of_ms = match crate::flag_value(args, "--as-of-ms").map(|v| v.parse::<u64>()) {
        None => None,
        Some(Ok(v)) => Some(v),
        Some(Err(_)) => {
            return usage_err("log revoke: --as-of-ms must be milliseconds since the epoch")
        }
    };
    let experimental = args.iter().any(|a| a == "--experimental");
    let at_current = args.iter().any(|a| a == "--at-current-size");
    let explicit_index = match crate::flag_value(args, "--as-of-index").map(|v| parse_index(&v)) {
        None => None,
        Some(Ok(v)) => Some(v),
        Some(Err(e)) => return usage_err(&format!("log revoke: --as-of-index: {e}")),
    };
    if (explicit_index.is_some() || at_current) && !experimental {
        return usage_err(
            "log revoke: index-based revocation is RFC-0005 and experimental; add --experimental to sign a v2 statement (verifiers older than 0.4.3 reject it, which fails closed)",
        );
    }
    if explicit_index.is_some() && at_current {
        return usage_err("log revoke: pass either --as-of-index N or --at-current-size, not both");
    }
    let seed = match crate::identity_seed_from_args(args) {
        Ok(s) => s,
        Err(e) => return usage_err(&format!("log revoke: {e}")),
    };
    let (log, _) = match crate::replay_journal(journal, seed.as_deref()) {
        Ok(x) => x,
        Err(e) => return fail(format!("{journal}: {e}")),
    };
    let as_of_index = if at_current {
        Some(log.tree_size())
    } else {
        explicit_index
    };
    let statement = log.revoke(as_of_ms, as_of_index, &reason);
    let text = match serde_json::to_string_pretty(&statement) {
        Ok(t) => t,
        Err(e) => return fail(e),
    };
    if let Some(out) = crate::flag_value(args, "--out") {
        if let Err(e) =
            crate::witness_cmd::atomic_write_shared(Path::new(&out), format!("{text}\n").as_bytes())
        {
            return fail(format!("{out}: {e}"));
        }
        eprintln!(
            "revocation for {} written to {out}; verifiers apply it with `witness-log verify ... --revocations {out}`",
            statement.identity_pubkey
        );
    }
    println!("{text}");
    ExitCode::SUCCESS
}

// ------------------------------------------------------------------ init

fn cmd_init(args: &[String]) -> ExitCode {
    let positional = match split_args(args, &[], &["--sealed"]) {
        Ok(p) => p,
        Err(e) => return usage_err(&format!("log init: {e}")),
    };
    let [journal] = positional.as_slice() else {
        return usage_err("log init: expected exactly one <journal> path");
    };
    let journal = journal.as_str();
    if Path::new(journal).exists() {
        return fail(format!(
            "{journal}: already exists; `log append` adds to it, and a second header would corrupt it"
        ));
    }
    let sealed = args.iter().any(|a| a == "--sealed");
    // A sealed journal needs a seed the caller keeps. The one convenience:
    // `--identity-seed-file F` naming a file that does not exist yet has
    // the seed generated into it, so the no-code path stays one command.
    let seed_file = crate::flag_value(args, "--identity-seed-file");
    let mut generated_seed_file: Option<String> = None;
    if let Some(f) = &seed_file {
        if !Path::new(f).exists() {
            let key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
            let hex_seed = zeroize::Zeroizing::new(hex::encode(key.to_bytes()));
            if let Err(e) = crate::witness_cmd::atomic_write(
                Path::new(f),
                format!("{}\n", *hex_seed).as_bytes(),
            ) {
                return fail(format!("{f}: {e}"));
            }
            generated_seed_file = Some(f.clone());
        }
    }
    let seed = match crate::identity_seed_from_args(args) {
        Ok(s) => s,
        Err(e) => return usage_err(&format!("log init: {e}")),
    };
    if sealed && seed.is_none() {
        return usage_err(
            "log init --sealed: the seed must come from --identity-seed-env NAME or \
             --identity-seed-file F (a file that does not exist yet is created with a new seed)",
        );
    }
    let identity = match &seed {
        Some(s) => IdentityKeypair::from_bytes(s),
        None => IdentityKeypair::generate(),
    };
    let created = if sealed {
        JournaledLog::create_sealed(journal, identity)
    } else {
        JournaledLog::create(journal, identity)
    };
    let mut log = match created {
        Ok(l) => l,
        Err(e) => return fail(format!("{journal}: {e}")),
    };
    if let Err(e) = log.sync() {
        return fail(format!("{journal}: {e}"));
    }
    let identity_hex = log.log().identity_pubkey_hex();
    drop(log);
    let doc = serde_json::json!({
        "journal": journal,
        "identity": identity_hex,
        "sealed": sealed,
        "salts": JournaledLog::salts_path(journal),
        "seed_file": generated_seed_file,
    });
    println!("{}", serde_json::to_string(&doc).unwrap_or_default());
    if let Some(f) = &generated_seed_file {
        eprintln!("generated a new identity seed into {f} (mode 0600). Back it up: without it this journal cannot be continued.");
    }
    if sealed {
        eprintln!(
            "sealed journal: the seed is not in {journal}. Pass the same --identity-seed-* flag to every later command."
        );
    } else {
        eprintln!(
            "{journal} holds the identity seed in its header (mode 0600); protect it like a private key, or use --sealed."
        );
    }
    eprintln!("next: witness-log log append {journal} --intent '<payload>'");
    ExitCode::SUCCESS
}

// ---------------------------------------------------------------- append

/// Read a payload argument: `-` is stdin, `@path` is a file, anything
/// else is the literal bytes.
fn read_payload(arg: &str) -> Result<Vec<u8>, String> {
    if arg == "-" {
        let mut buf = Vec::new();
        std::io::stdin()
            .lock()
            .take(crate::MAX_INPUT_BYTES + 1)
            .read_to_end(&mut buf)
            .map_err(|e| format!("stdin: {e}"))?;
        if buf.len() as u64 > crate::MAX_INPUT_BYTES {
            return Err(format!(
                "stdin payload is larger than {} MiB",
                crate::MAX_INPUT_BYTES >> 20
            ));
        }
        return Ok(buf);
    }
    if let Some(path) = arg.strip_prefix('@') {
        let meta = std::fs::metadata(path).map_err(|e| format!("{path}: {e}"))?;
        if meta.len() > crate::MAX_INPUT_BYTES {
            return Err(format!(
                "{path} is larger than {} MiB",
                crate::MAX_INPUT_BYTES >> 20
            ));
        }
        return std::fs::read(path).map_err(|e| format!("{path}: {e}"));
    }
    Ok(arg.as_bytes().to_vec())
}

fn cmd_append(args: &[String]) -> ExitCode {
    let positional = match split_args(
        args,
        &["--outcome"],
        &["--intent", "--result", "--memory", "--json"],
    ) {
        Ok(p) => p,
        Err(e) => return usage_err(&format!("log append: {e}")),
    };
    let kinds: Vec<&str> = args
        .iter()
        .map(String::as_str)
        .filter(|a| matches!(*a, "--intent" | "--result" | "--memory"))
        .collect();
    let [kind] = kinds.as_slice() else {
        return usage_err("log append: give exactly one of --intent, --result, --memory");
    };
    let kind = *kind;
    // `log append j --intent -` : the payload may legitimately be "-", which
    // split_args treats as positional (it is not "--something").
    let (journal, payload_arg) = match positional.as_slice() {
        [j, p] => (j.as_str(), p.as_str()),
        _ => {
            return usage_err(
                "log append: expected <journal> and one payload (text, @file, or - for stdin)",
            )
        }
    };
    let outcome = crate::flag_value(args, "--outcome");
    if args.iter().any(|a| a == "--outcome") && outcome.is_none() {
        return usage_err("log append: --outcome requires ok or error");
    }
    if let Some(o) = &outcome {
        if kind != "--result" {
            return usage_err("log append: --outcome applies to --result only");
        }
        if o != "ok" && o != "error" {
            return usage_err(&format!(
                "log append: --outcome must be ok or error, got {o:?}"
            ));
        }
    }
    let seed = match crate::identity_seed_from_args(args) {
        Ok(s) => s,
        Err(e) => return usage_err(&format!("log append: {e}")),
    };
    let raw = match read_payload(payload_arg) {
        Ok(p) => p,
        Err(e) => return fail(e),
    };
    // With --outcome the committed bytes are a small canonical JSON object
    // (keys sorted, no whitespace), the shape the Python `step` decorator
    // and the MCP server write. Printed back so the caller can disclose
    // exactly what was committed.
    let committed: Vec<u8> = match &outcome {
        Some(o) => {
            let value = String::from_utf8_lossy(&raw).into_owned();
            serde_json::to_vec(&serde_json::json!({ "outcome": o, "value": value }))
                .unwrap_or_default()
        }
        None => raw,
    };
    let (mut log, report) = match crate::resume_journal(journal, seed.as_deref()) {
        Ok(x) => x,
        Err(e) => return fail(format!("{journal}: {e}")),
    };
    if report.dropped_trailing_lines > 0 {
        eprintln!(
            "note: {journal} had a partially written last line; it was dropped before appending"
        );
    }
    let appended = match kind {
        "--intent" => log.append_intent(&committed),
        "--result" => log.append_result(&committed),
        _ => log.append_memory(&committed),
    };
    let index = match appended.and_then(|i| log.sync().map(|_| i)) {
        Ok(i) => i,
        Err(e) => return fail(format!("{journal}: {e}")),
    };
    let leaf = log
        .log()
        .leaves()
        .get(usize::try_from(index).unwrap_or(usize::MAX))
        .cloned();
    let doc = serde_json::json!({
        "index": index,
        "leaf_type": kind.trim_start_matches("--"),
        "payload_hash": leaf.as_ref().map(|l| l.payload_hash.clone()),
        "payload_bytes": committed.len(),
        "committed_payload": outcome.as_ref().map(|_| String::from_utf8_lossy(&committed).into_owned()),
        "tree_size": log.log().tree_size(),
        "root": log.log().root_hex(),
    });
    println!("{}", serde_json::to_string(&doc).unwrap_or_default());
    ExitCode::SUCCESS
}

// ---------------------------------------------------------------- forget

fn parse_index(s: &str) -> Result<u64, String> {
    s.parse::<u64>()
        .map_err(|_| format!("<index> must be a non-negative integer, got {s:?}"))
}

fn cmd_forget(args: &[String]) -> ExitCode {
    let positional = match split_args(args, &[], &[]) {
        Ok(p) => p,
        Err(e) => return usage_err(&format!("log forget: {e}")),
    };
    let [journal, index] = positional.as_slice() else {
        return usage_err("log forget: expected <journal> <index>");
    };
    let index = match parse_index(index) {
        Ok(i) => i,
        Err(e) => return usage_err(&format!("log forget: {e}")),
    };
    let seed = match crate::identity_seed_from_args(args) {
        Ok(s) => s,
        Err(e) => return usage_err(&format!("log forget: {e}")),
    };
    let (mut log, _) = match crate::resume_journal(journal, seed.as_deref()) {
        Ok(x) => x,
        Err(e) => return fail(format!("{journal}: {e}")),
    };
    let size = log.log().tree_size();
    if index >= size {
        return fail(format!(
            "{journal}: leaf {index} does not exist (tree size {size})"
        ));
    }
    match log.forget(index).and_then(|f| log.sync().map(|_| f)) {
        Ok(true) => {
            let doc = serde_json::json!({
                "forgotten": index,
                "tombstone_index": size,
                "tree_size": log.log().tree_size(),
                "root": log.log().root_hex(),
            });
            println!("{}", serde_json::to_string(&doc).unwrap_or_default());
            ExitCode::SUCCESS
        }
        Ok(false) => fail(format!(
            "{journal}: leaf {index} has no salt to erase (already forgotten, a marker leaf, or \
             appended before the salt sidecar existed)"
        )),
        Err(e) => fail(format!("{journal}: {e}")),
    }
}

// ---------------------------------------------------------------- export

fn cmd_export(args: &[String]) -> ExitCode {
    let positional = match split_args(args, &["--out"], &[]) {
        Ok(p) => p,
        Err(e) => return usage_err(&format!("log export: {e}")),
    };
    let ([journal], Some(out)) = (positional.as_slice(), crate::flag_value(args, "--out")) else {
        return usage_err("log export: expected <journal> --out <dossier.json>");
    };
    let seed = match crate::identity_seed_from_args(args) {
        Ok(s) => s,
        Err(e) => return usage_err(&format!("log export: {e}")),
    };
    let (log, report) = match crate::replay_journal(journal, seed.as_deref()) {
        Ok(x) => x,
        Err(e) => return fail(format!("{journal}: {e}")),
    };
    if report.dropped_trailing_lines > 0 {
        eprintln!(
            "note: {journal} has a partially written last line; exporting the {} complete leaves",
            log.tree_size()
        );
    }
    let dossier = Dossier::from_log(&log, log.checkpoint_self());
    let json = match serde_json::to_vec_pretty(&dossier) {
        Ok(j) => j,
        Err(e) => return fail(e),
    };
    if let Err(e) = crate::witness_cmd::atomic_write_shared(Path::new(&out), &json) {
        return fail(format!("{out}: {e}"));
    }
    eprintln!(
        "wrote {out}: {} leaves, identity {}. This dossier is unwitnessed; `witness-log submit {journal} --directory <trusted.json>` gets it cosigned.",
        dossier.leaves.len(),
        dossier.identity_pubkey
    );
    ExitCode::SUCCESS
}

// -------------------------------------------------------------- disclose

fn cmd_disclose(args: &[String]) -> ExitCode {
    let positional = match split_args(args, &[], &[]) {
        Ok(p) => p,
        Err(e) => return usage_err(&format!("log disclose: {e}")),
    };
    let [journal, index] = positional.as_slice() else {
        return usage_err("log disclose: expected <journal> <index>");
    };
    let index = match parse_index(index) {
        Ok(i) => i,
        Err(e) => return usage_err(&format!("log disclose: {e}")),
    };
    let seed = match crate::identity_seed_from_args(args) {
        Ok(s) => s,
        Err(e) => return usage_err(&format!("log disclose: {e}")),
    };
    let (log, _) = match crate::replay_journal(journal, seed.as_deref()) {
        Ok(x) => x,
        Err(e) => return fail(format!("{journal}: {e}")),
    };
    let Some(leaf) = usize::try_from(index)
        .ok()
        .and_then(|i| log.leaves().get(i))
    else {
        return fail(format!(
            "{journal}: leaf {index} does not exist (tree size {})",
            log.tree_size()
        ));
    };
    if matches!(
        LeafType::from_tag(leaf.leaf_type),
        Some(LeafType::Redaction) | Some(LeafType::KeyRevocation)
    ) {
        return fail(format!(
            "{journal}: leaf {index} is a marker leaf (type 0x{:02x}) and carries no payload",
            leaf.leaf_type
        ));
    }
    // The salts live in the sidecar, which a read-only replay does not
    // load; open it directly rather than taking the journal lock.
    let salts_path = JournaledLog::salts_path(journal);
    let store = match FileSaltStore::open(&salts_path) {
        Ok(s) => s,
        Err(e) => return fail(format!("{salts_path}: {e}")),
    };
    let Some(salt) = store.salt_for(index) else {
        return fail(format!(
            "{journal}: no salt held for leaf {index}: it was forgotten, or appended before the salt sidecar existed. Nothing can be disclosed."
        ));
    };
    let doc = serde_json::json!({
        "index": index,
        "leaf": leaf,
        "payload_hash": leaf.payload_hash,
        "salt": hex::encode(salt),
        "identity": log.identity_pubkey_hex(),
        "check": "payload_hash == SHA256(len(payload) as u64 BE || payload || zero padding to (len/256+1)*256 bytes || salt || index as u64 BE); see spec/SPEC.md section 8",
    });
    println!("{}", serde_json::to_string_pretty(&doc).unwrap_or_default());
    eprintln!(
        "hand the verifier this output and the payload; only leaf {index}'s salt is disclosed"
    );
    ExitCode::SUCCESS
}

// ------------------------------------------------------------------ info

/// The header line's public facts, readable without the seed.
fn header_facts(journal: &str) -> Option<(bool, Option<String>)> {
    let f = std::fs::File::open(journal).ok()?;
    let mut first = String::new();
    std::io::BufRead::read_line(
        &mut std::io::BufReader::new(f.take(crate::MAX_INPUT_BYTES)),
        &mut first,
    )
    .ok()?;
    let v: serde_json::Value = serde_json::from_str(first.trim()).ok()?;
    let sealed = v
        .get("identity_bytes_hex")
        .and_then(|x| x.as_str())
        .is_some_and(str::is_empty);
    let pubkey = v
        .get("identity_pubkey_hex")
        .and_then(|x| x.as_str())
        .map(str::to_string);
    Some((sealed, pubkey))
}

fn cmd_info(args: &[String]) -> ExitCode {
    let positional = match split_args(args, &[], &[]) {
        Ok(p) => p,
        Err(e) => return usage_err(&format!("log info: {e}")),
    };
    let [journal] = positional.as_slice() else {
        return usage_err("log info: expected <journal>");
    };
    let seed = match crate::identity_seed_from_args(args) {
        Ok(s) => s,
        Err(e) => return usage_err(&format!("log info: {e}")),
    };
    let (sealed, header_pubkey) = header_facts(journal).unwrap_or((false, None));
    let (log, report) = match crate::replay_journal(journal, seed.as_deref()) {
        Ok(x) => x,
        Err(e) if sealed && seed.is_none() => {
            // The seed is needed to replay, but the header says enough
            // for a status check.
            let doc = serde_json::json!({
                "journal": journal,
                "sealed": true,
                "identity": header_pubkey,
                "note": format!("{e}"),
            });
            println!("{}", serde_json::to_string_pretty(&doc).unwrap_or_default());
            return ExitCode::SUCCESS;
        }
        Err(e) => return fail(format!("{journal}: {e}")),
    };
    let count = |t: LeafType| {
        log.leaves()
            .iter()
            .filter(|l| l.leaf_type == t.tag())
            .count()
    };
    let salts_path = JournaledLog::salts_path(journal);
    let salts_held = FileSaltStore::open(&salts_path).map(|s| s.len()).ok();
    let doc = serde_json::json!({
        "journal": journal,
        "sealed": sealed,
        "identity": log.identity_pubkey_hex(),
        "origin": witness_log_core::c2sp::canonical_origin(
            &ed25519_dalek::SigningKey::from_bytes(&log.identity_bytes()).verifying_key()
        ),
        "tree_size": log.tree_size(),
        "root": log.root_hex(),
        "leaves": {
            "intent": count(LeafType::ActiveIntent),
            "result": count(LeafType::ActiveResult),
            "memory": count(LeafType::PassiveMemory),
            "redaction": count(LeafType::Redaction),
            "handoff": count(LeafType::HandoffAttestation),
            "authorization": count(LeafType::AuthorizationEvent),
            "external_anchor": count(LeafType::ExternalAnchor),
        },
        "key_bindings": log.all_bindings().len(),
        "salts_held": salts_held,
        "salts": salts_path,
        "dropped_trailing_lines": report.dropped_trailing_lines,
    });
    println!("{}", serde_json::to_string_pretty(&doc).unwrap_or_default());
    ExitCode::SUCCESS
}
