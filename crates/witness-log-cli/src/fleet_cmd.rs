//! `witness-log fleet ...`: an EXPERIMENTAL prototype of RFC-0001, one
//! append-only log per organisation whose entries are its agents' signed
//! checkpoint notes. Ordinary `c2sp.org/tlog-witness` witnesses cosign the
//! fleet log's checkpoint (one enrollment per organisation, with `witness
//! add-log`), and an agent's dossier carries a `fleet_anchor` that a
//! verifier counts only with `verify --accept-fleet-anchor`.
//!
//! What the server enforces:
//!
//! 1. **Only agent checkpoints.** An entry is a `c2sp.org/tlog-checkpoint`
//!    note whose origin is `witness-log/<identity hex>`, signed by the key
//!    that origin names, with no extension lines. Anything else is refused.
//! 2. **Per-agent fork refusal.** The fleet log keeps, for every agent
//!    origin, the latest checkpoint it appended, and runs the exact
//!    `tlog-witness` state machine against it (`KnownLog`): the agent sends
//!    the size it believes the fleet holds and a consistency proof; a
//!    checkpoint that does not extend the held one is refused with 422,
//!    and two signed roots for one size are kept as an `EquivocationProof`
//!    under `evidence/`, the file a witness writes. Re-sending the held
//!    checkpoint appends nothing and returns its entry.
//! 3. **Persist before acknowledging.** An entry is appended to `entries`
//!    and fsynced before the response; a failed write is rolled back or the
//!    process exits. `entries` is the only authority: the tree and the
//!    per-agent memory are rebuilt from it at start.
//! 4. **One process per state directory** (`fleet.lock`), loopback only
//!    unless `--allow-remote` (there is no authentication: whoever can reach
//!    it can append any validly signed agent checkpoint), bounded requests
//!    (`http.rs`) and a cap on agent origins (`--max-origins`).
//!
//! Not implemented in the prototype: `c2sp.org/tlog-tiles` serving (an
//! auditor walks entries with `GET /proof/<index>`), batching or rate
//! limits per agent, and retention. The server holds every entry and leaf
//! hash in memory (a few hundred bytes per entry) and rebuilds them from
//! `entries` at start.
//!
//! State layout (`<dir>`):
//!   fleet.key       32-byte Ed25519 seed, hex, mode 0600
//!   fleet.json      origin, operator org, public URL, public key
//!   entries         one entry per line, standard base64 of the note bytes
//!   cosigned.note   the largest fleet checkpoint witnesses cosigned, with
//!                   their cosignature lines
//!   witnesses.json  `fleet witness`'s memory of each witness's size
//!   evidence/<sha256(agent origin)>.json  proven agent equivocation
//!   fleet.lock      held while serving

use crate::http::{self, Request, Response};
use crate::witness_cmd::{
    acquire_lock_at, atomic_write, atomic_write_shared, cosign_one, default_min,
    post_add_checkpoint, record_evidence, submit_log, Lock, SubmitError,
};
use base64ct::{Base64, Encoding};
use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use witness_log_core::c2sp::{
    canonical_origin, identity_from_canonical_origin, Checkpoint, NoteSignature, SignedNote,
    VerifierKey,
};
use witness_log_core::merkle::{leaf_hash, MerkleTree};
use witness_log_network::fleet::{decode_canonical_base64, valid_fleet_origin, FleetAnchor};
use witness_log_network::tlog_witness::{AddCheckpointOutcome, AddCheckpointRequest, KnownLog};
use witness_log_network::{Dossier, WitnessDirectory};

const USAGE: &str = "usage (EXPERIMENTAL, RFC-0001; not part of the specification):
  witness-log fleet init <dir> --origin <org-domain>/witness-log/fleet --org ORG [--url <public-url>] [--json]
      Create a fleet checkpoint log: one append-only log whose entries are your
      agents' signed checkpoints. Prints the vkey witnesses enroll it with:
        witness-log witness add-log <witness-dir> <origin> <vkey>
  witness-log fleet serve <dir> [--listen 127.0.0.1:7480] [--allow-remote] [--max-origins 100000]
                                [--directory trusted.json --witness-every SECS [--min N]]
      POST /add-entry   a c2sp.org/tlog-witness add-checkpoint body (old size, consistency
                        proof, the agent's checkpoint note); 200 with JSON {entry_index,
                        entry_bytes_b64, inclusion_proof, fleet_checkpoint_note, ...}, 409 with
                        the size held for that agent, 422 for a fork (proof under evidence/)
      GET /proof/<index>   the same JSON for an existing entry
      GET /latest/<agent origin>   the latest entry for one agent
      GET /    GET /health
      With --directory and --witness-every, submits the fleet checkpoint to the
      directory's witnesses every SECS seconds when it has grown.
  witness-log fleet witness <dir> --directory trusted.json [--min N]
      Submit the fleet checkpoint to every witness in the directory once (each must
      have enrolled the fleet origin), and keep their cosignatures in cosigned.note.
      Exit 0 when at least --min cosigned (default max(2, N/2+1)), 20 otherwise or
      when any witness refused (422).
  witness-log submit <journal> --fleet <url> [--fleet-wait SECS] [--directory trusted.json ...]
      Append the journal's checkpoint to a fleet log and write a dossier with a
      fleet_anchor. Verify it with --accept-fleet-anchor --subject-org ORG.";

const ENTRIES: &str = "entries";
const COSIGNED: &str = "cosigned.note";
const FORMAT: &str = "witness-log fleet log, RFC-0001 experimental prototype v0";

fn usage_err(msg: &str) -> ExitCode {
    eprintln!("{msg}\n\n{USAGE}");
    ExitCode::from(crate::exit::USAGE)
}

fn flag(args: &[String], name: &str) -> Option<String> {
    crate::flag_value(args, name)
}

fn now_s() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
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
        Some("serve") => cmd_serve(rest),
        Some("witness") => cmd_witness(rest),
        _ => usage_err("fleet: expected init, serve or witness"),
    }
}

/// Every argument after the positional one is a known flag, followed by a
/// value unless it is in `switches`.
fn check_flags(
    cmd: &str,
    args: &[String],
    valued: &[&str],
    switches: &[&str],
) -> Result<(), String> {
    let mut i = 1;
    while i < args.len() {
        let a = args[i].as_str();
        if valued.contains(&a) {
            match args.get(i + 1) {
                Some(v) if !v.starts_with("--") => i += 2,
                _ => return Err(format!("{cmd}: {a} requires a value")),
            }
        } else if switches.contains(&a) {
            i += 1;
        } else {
            return Err(format!("{cmd}: unexpected argument {a:?}"));
        }
    }
    Ok(())
}

#[derive(Serialize, Deserialize, Clone)]
struct FleetConfig {
    format: String,
    origin: String,
    operator_org: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    public_url: Option<String>,
    pubkey_hex: String,
}

fn load_config_and_key(dir: &Path) -> Result<(FleetConfig, SigningKey), String> {
    let p = dir.join("fleet.json");
    let raw = fs::read_to_string(&p).map_err(|e| format!("{}: {e}", p.display()))?;
    let cfg: FleetConfig =
        serde_json::from_str(&raw).map_err(|e| format!("{}: {e}", p.display()))?;
    if !valid_fleet_origin(&cfg.origin) {
        return Err(format!("{}: invalid origin {:?}", p.display(), cfg.origin));
    }
    let kp = dir.join("fleet.key");
    let s = fs::read_to_string(&kp).map_err(|e| format!("{}: {e}", kp.display()))?;
    let seed = zeroize::Zeroizing::new(
        hex::decode(s.trim())
            .ok()
            .and_then(|b| <[u8; 32]>::try_from(b).ok())
            .ok_or_else(|| format!("{}: not a 32-byte hex seed", kp.display()))?,
    );
    let key = SigningKey::from_bytes(&seed);
    if !cfg
        .pubkey_hex
        .eq_ignore_ascii_case(&hex::encode(key.verifying_key().to_bytes()))
    {
        return Err(format!(
            "{}: fleet.key is not the key fleet.json was initialised with; refusing to sign \
             (witnesses hold the vkey from init)",
            dir.display()
        ));
    }
    Ok((cfg, key))
}

fn vkey_of(cfg: &FleetConfig, key: &SigningKey) -> String {
    VerifierKey::for_ed25519(&cfg.origin, &key.verifying_key()).encode()
}

// ------------------------------------------------------------------ init

fn cmd_init(args: &[String]) -> ExitCode {
    let Some(dir) = args.first().filter(|a| !a.starts_with("--")) else {
        return usage_err("fleet init: missing <dir>");
    };
    if let Err(e) = check_flags(
        "fleet init",
        args,
        &["--origin", "--org", "--url"],
        &["--json"],
    ) {
        return usage_err(&e);
    }
    let Some(origin) = flag(args, "--origin") else {
        return usage_err("fleet init: --origin <org-domain>/witness-log/fleet is required");
    };
    if !valid_fleet_origin(&origin) {
        return usage_err(
            "fleet init: --origin must be a C2SP origin (no spaces or '+') that does not start \
             with witness-log/ (that prefix names one agent's own log)",
        );
    }
    let Some(org) = flag(args, "--org").filter(|o| !o.trim().is_empty()) else {
        return usage_err(
            "fleet init: --org ORG is required: the organisation that runs this fleet log and \
             its agents (verifiers pass it as --subject-org)",
        );
    };
    let url = flag(args, "--url");
    if let Some(u) = &url {
        if !(u.starts_with("http://") || u.starts_with("https://")) {
            return usage_err("fleet init: --url must start with http:// or https://");
        }
    }
    let dir = PathBuf::from(dir);
    if dir.join("fleet.key").exists() {
        eprintln!(
            "{}: already initialised (fleet.key exists); refusing to overwrite a key",
            dir.display()
        );
        return ExitCode::from(1);
    }
    if let Err(e) = fs::create_dir_all(&dir) {
        eprintln!("{}: {e}", dir.display());
        return ExitCode::from(1);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&dir, fs::Permissions::from_mode(0o700));
    }
    let key = SigningKey::generate(&mut rand::rngs::OsRng);
    let cfg = FleetConfig {
        format: FORMAT.into(),
        origin: origin.clone(),
        operator_org: org,
        public_url: url,
        pubkey_hex: hex::encode(key.verifying_key().to_bytes()),
    };
    let seed_hex = zeroize::Zeroizing::new(hex::encode(key.to_bytes()));
    let wrote = atomic_write(&dir.join("fleet.key"), seed_hex.as_bytes())
        .and_then(|_| {
            let json = serde_json::to_vec_pretty(&cfg).map_err(std::io::Error::other)?;
            atomic_write(&dir.join("fleet.json"), &json)
        })
        .and_then(|_| atomic_write(&dir.join(ENTRIES), b""));
    if let Err(e) = wrote {
        eprintln!("{}: {e}", dir.display());
        return ExitCode::from(1);
    }
    let vkey = vkey_of(&cfg, &key);
    if args.iter().any(|a| a == "--json") {
        let doc = serde_json::json!({
            "origin": cfg.origin,
            "vkey": vkey,
            "org": cfg.operator_org,
            "pubkey_hex": cfg.pubkey_hex,
            "data_dir": dir.display().to_string(),
            "experimental": "RFC-0001",
        });
        println!("{}", serde_json::to_string(&doc).unwrap_or_default());
        return ExitCode::SUCCESS;
    }
    println!("{vkey}");
    eprintln!(
        "fleet log initialised in {} (EXPERIMENTAL, RFC-0001)\n  origin: {}\n  vkey:   {vkey}\n  Each witness operator enrolls it once:\n    witness-log witness add-log <witness-dir> {} {vkey}",
        dir.display(),
        cfg.origin,
        cfg.origin
    );
    ExitCode::SUCCESS
}

// --------------------------------------------------------------- entries

/// The fleet log as `entries` holds it.
struct Entries {
    /// Base64 of each entry, as stored and served.
    lines: Vec<String>,
    tree: MerkleTree,
    /// Agent origin -> (the latest checkpoint appended for it, as the
    /// witness state machine holds it; that entry's index).
    agents: HashMap<String, (KnownLog, u64)>,
    /// Bytes of `entries` up to the end of the last complete line.
    complete_len: u64,
    /// Bytes of `entries` on disk (more than `complete_len` after a write
    /// torn by a crash; such a line was never acknowledged).
    file_len: u64,
}

/// Read `entries`. Every complete line must decode to an agent checkpoint
/// note: the file is this log's own fsynced state, so anything else means
/// it was damaged, and serving from it could contradict what witnesses
/// cosigned. Signatures are not re-verified (each was before it was
/// appended).
fn load_entries(dir: &Path) -> Result<Entries, String> {
    let p = dir.join(ENTRIES);
    let raw = fs::read(&p).map_err(|e| format!("{}: {e}", p.display()))?;
    let complete_len = raw.iter().rposition(|&b| b == b'\n').map_or(0, |i| i + 1);
    let text = std::str::from_utf8(raw.get(..complete_len).unwrap_or(&[]))
        .map_err(|_| format!("{}: not UTF-8", p.display()))?;
    let mut e = Entries {
        lines: Vec::new(),
        tree: MerkleTree::new(),
        agents: HashMap::new(),
        complete_len: complete_len as u64,
        file_len: raw.len() as u64,
    };
    for (i, line) in text.lines().enumerate() {
        let bad = |why: &str| format!("{} line {}: {why}; refusing to use it", p.display(), i + 1);
        let bytes = decode_canonical_base64(line).ok_or_else(|| bad("not base64"))?;
        let note_text = std::str::from_utf8(&bytes).map_err(|_| bad("not UTF-8"))?;
        let note = SignedNote::parse(note_text).map_err(|_| bad("not a signed note"))?;
        let cp = Checkpoint::from_note(&note).map_err(|_| bad("not a checkpoint"))?;
        let identity =
            identity_from_canonical_origin(&cp.origin).ok_or_else(|| bad("not an agent origin"))?;
        let index = e.tree.append(leaf_hash(&bytes));
        let newer = e
            .agents
            .get(&cp.origin)
            .map_or(true, |(k, _)| cp.tree_size >= k.tree_size);
        if newer {
            let k = KnownLog {
                origin: cp.origin.clone(),
                log_vkey: VerifierKey::for_ed25519(&cp.origin, &identity),
                tree_size: cp.tree_size,
                root_hash: cp.root_hash,
                checkpoint_note: Some(note_text.to_string()),
            };
            e.agents.insert(cp.origin, (k, index));
        }
        e.lines.push(line.to_string());
    }
    Ok(e)
}

/// The cosigned fleet checkpoint `fleet witness` keeps: (size, note).
fn read_cosigned(dir: &Path) -> Option<(u64, String)> {
    let raw = fs::read_to_string(dir.join(COSIGNED)).ok()?;
    let note = SignedNote::parse(&raw).ok()?;
    Some((Checkpoint::from_note(&note).ok()?.tree_size, raw))
}

/// A cosigned checkpoint must be one of this log's own heads: a fleet log
/// restored from a backup older than what witnesses cosigned would serve,
/// and append to, a history that contradicts their cosignatures.
fn check_cosigned_against(dir: &Path, cfg: &FleetConfig, tree: &MerkleTree) -> Result<(), String> {
    let Some((size, raw)) = read_cosigned(dir) else {
        return Ok(());
    };
    let cp = SignedNote::parse(&raw)
        .ok()
        .and_then(|n| Checkpoint::from_note(&n).ok())
        .ok_or("cosigned.note does not parse")?;
    if cp.origin != cfg.origin || tree.root_at(size) != Some(cp.root_hash) {
        return Err(format!(
            "{}: witnesses cosigned this fleet log at size {size}, and `entries` ({} entries) \
             does not reproduce that head. Restore `entries` from the same backup; serving or \
             appending now would contradict the cosigned history.",
            dir.join(COSIGNED).display(),
            tree.size()
        ));
    }
    Ok(())
}

/// The fleet checkpoint note at the tree's current size, signed now.
fn signed_head(
    cfg: &FleetConfig,
    key: &SigningKey,
    tree: &MerkleTree,
) -> Result<SignedNote, String> {
    Checkpoint {
        origin: cfg.origin.clone(),
        tree_size: tree.size(),
        root_hash: tree.root(),
        extensions: vec![],
    }
    .sign(key)
    .map_err(|e| e.to_string())
}

/// Signature lines on a fleet note other than the fleet log's own.
fn cosignature_lines(note: &SignedNote, origin: &str) -> usize {
    note.signatures
        .iter()
        .filter(|s| s.key_name != origin)
        .count()
}

/// The anchor for entry `index`: proven against the largest cosigned
/// checkpoint that includes it, or, before one exists, against the current
/// head (signed by the fleet key only).
fn anchor_json(
    dir: &Path,
    cfg: &FleetConfig,
    key: &SigningKey,
    e: &Entries,
    index: u64,
    appended: Option<bool>,
) -> Result<serde_json::Value, String> {
    let (note, size, cosigned) = match read_cosigned(dir) {
        Some((size, raw)) if index < size && size <= e.tree.size() => (raw, size, true),
        _ => {
            let n = signed_head(cfg, key, &e.tree)?;
            (n.encode().map_err(|e| e.to_string())?, e.tree.size(), false)
        }
    };
    let proof = e
        .tree
        .inclusion_proof(index, size)
        .ok_or("entry outside the tree")?;
    let parsed = SignedNote::parse(&note).map_err(|e| e.to_string())?;
    let mut v = serde_json::json!({
        "origin": cfg.origin,
        "entry_index": index,
        "entry_bytes_b64": e.lines.get(index as usize).ok_or("no such entry")?,
        "inclusion_proof": proof.iter().map(hex::encode).collect::<Vec<_>>(),
        "fleet_checkpoint_note": note,
        "fleet_tree_size": size,
        "cosigned": cosigned,
        "cosignature_lines": cosignature_lines(&parsed, &cfg.origin),
    });
    if let Some(a) = appended {
        v["appended"] = serde_json::Value::Bool(a);
    }
    Ok(v)
}

// ----------------------------------------------------------------- serve

struct FleetServer {
    lock: Lock,
    dir: PathBuf,
    cfg: FleetConfig,
    key: SigningKey,
    entries: Entries,
    file: fs::File,
    max_origins: usize,
    appended: u64,
    refused_forks: u64,
    started: u64,
}

impl FleetServer {
    /// Append one entry durably (write, fsync) and only then to the tree.
    /// A failed write is truncated away; if that fails too the process
    /// exits rather than append after a partial line.
    fn append(&mut self, entry: &[u8]) -> Result<u64, String> {
        let line = format!("{}\n", Base64::encode_string(entry));
        let before = self.entries.file_len;
        let res = self
            .file
            .write_all(line.as_bytes())
            .and_then(|_| self.file.sync_data());
        if let Err(e) = res {
            if self
                .file
                .set_len(before)
                .and_then(|_| self.file.sync_data())
                .is_err()
            {
                eprintln!(
                    "FATAL: could not append to or roll back {}: {e}. Exiting without \
                     acknowledging; check the file before restarting.",
                    self.dir.join(ENTRIES).display()
                );
                std::process::exit(3);
            }
            return Err(format!("could not persist the entry: {e}"));
        }
        self.entries.file_len += line.len() as u64;
        self.entries.complete_len = self.entries.file_len;
        self.entries.lines.push(line.trim_end().to_string());
        self.appended += 1;
        Ok(self.entries.tree.append(leaf_hash(entry)))
    }
}

fn cmd_serve(args: &[String]) -> ExitCode {
    let Some(dir) = args.first().filter(|a| !a.starts_with("--")) else {
        return usage_err("fleet serve: missing <dir>");
    };
    if let Err(e) = check_flags(
        "fleet serve",
        args,
        &[
            "--listen",
            "--max-origins",
            "--directory",
            "--witness-every",
            "--min",
        ],
        &["--allow-remote"],
    ) {
        return usage_err(&e);
    }
    let dir = PathBuf::from(dir);
    let listen = flag(args, "--listen").unwrap_or_else(|| "127.0.0.1:7480".into());
    let allow_remote = args.iter().any(|a| a == "--allow-remote");
    let max_origins = match flag(args, "--max-origins").map(|v| v.parse::<usize>()) {
        None => 100_000,
        Some(Ok(n)) if n > 0 => n,
        _ => return usage_err("fleet serve: --max-origins expects a positive integer"),
    };
    let witnessing = match (flag(args, "--directory"), flag(args, "--witness-every")) {
        (None, None) => None,
        (Some(d), Some(s)) => match (read_directory(&d), s.parse::<u64>()) {
            (Ok(trusted), Ok(secs)) if secs > 0 => Some((trusted, Duration::from_secs(secs))),
            (Err(e), _) => return usage_err(&format!("fleet serve: {d}: {e}")),
            _ => {
                return usage_err(
                    "fleet serve: --witness-every expects a positive number of seconds",
                )
            }
        },
        _ => return usage_err("fleet serve: --directory and --witness-every go together"),
    };
    let min = match flag(args, "--min").map(|v| v.parse::<usize>()) {
        None => None,
        Some(Ok(n)) => Some(n),
        Some(Err(_)) => return usage_err("fleet serve: --min expects an integer"),
    };
    let (cfg, key) = match load_config_and_key(&dir) {
        Ok(x) => x,
        Err(e) => {
            eprintln!(
                "{e}\n(run `witness-log fleet init {} --origin ... --org ...` first)",
                dir.display()
            );
            return ExitCode::from(1);
        }
    };
    let lock = match acquire_lock_at(
        &dir.join("fleet.lock"),
        "fleet log",
        "Two fleet log processes on one state directory could append two different histories.",
    ) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(1);
        }
    };
    let mut entries = match load_entries(&dir) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("refusing to start: {e}");
            return ExitCode::from(1);
        }
    };
    if let Err(e) = check_cosigned_against(&dir, &cfg, &entries.tree) {
        eprintln!("refusing to start: {e}");
        return ExitCode::from(1);
    }
    let file = match fs::OpenOptions::new().append(true).open(dir.join(ENTRIES)) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("{}: {e}", dir.join(ENTRIES).display());
            return ExitCode::from(1);
        }
    };
    if entries.file_len > entries.complete_len {
        // A line torn by a crash mid-write: it was never fsynced, so never
        // acknowledged, and never seen by `fleet witness` (complete lines
        // only). Drop it so the next entry starts on a line of its own.
        eprintln!(
            "dropping {} bytes of an incomplete last line in {} (a write interrupted by a crash; never acknowledged)",
            entries.file_len - entries.complete_len,
            dir.join(ENTRIES).display()
        );
        if let Err(e) = file
            .set_len(entries.complete_len)
            .and_then(|_| file.sync_data())
        {
            eprintln!("refusing to start: could not truncate the incomplete line: {e}");
            return ExitCode::from(1);
        }
        entries.file_len = entries.complete_len;
    }
    let listener = match std::net::TcpListener::bind(&listen) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("bind {listen}: {e}");
            return ExitCode::from(1);
        }
    };
    let bound = match listener.local_addr() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("bind {listen}: {e}");
            return ExitCode::from(1);
        }
    };
    if !bound.ip().is_loopback() && !allow_remote {
        eprintln!(
            "refusing to listen on {bound}: the fleet log has no authentication (anyone who can \
             reach it can append any validly signed agent checkpoint). Bind 127.0.0.1 or pass \
             --allow-remote and put it behind something that does."
        );
        return ExitCode::from(2);
    }
    eprintln!(
        "fleet log {} (EXPERIMENTAL, RFC-0001) listening on http://{bound} ({} entries, {} agents)",
        cfg.origin,
        entries.tree.size(),
        entries.agents.len()
    );
    let server = Arc::new(Mutex::new(FleetServer {
        lock,
        dir: dir.clone(),
        cfg: cfg.clone(),
        key: key.clone(),
        entries,
        file,
        max_origins,
        appended: 0,
        refused_forks: 0,
        started: now_s(),
    }));
    #[cfg(unix)]
    {
        let s = server.clone();
        crate::witness_cmd::on_stop_signal(move |sig| {
            let s = s.lock().unwrap_or_else(|e| e.into_inner());
            eprintln!(
                "fleet log stopping on signal {sig}: {} entries appended since start",
                s.appended
            );
            s.lock.release();
        });
    }
    if let Some((directory, every)) = witnessing {
        let s = server.clone();
        let min = min.unwrap_or_else(|| default_min(directory.witnesses.len()));
        std::thread::spawn(move || {
            let mut last = 0u64;
            loop {
                std::thread::sleep(every);
                let tree = s
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .entries
                    .tree
                    .clone();
                if tree.size() == 0 || tree.size() <= last {
                    continue;
                }
                match witness_round(&dir, &cfg, &key, &tree, &directory) {
                    Ok(r) => {
                        eprintln!(
                            "fleet checkpoint size {}: {}/{} witnesses cosigned{}",
                            tree.size(),
                            r.cosigned,
                            directory.witnesses.len(),
                            if r.cosigned < min {
                                " (below --min)"
                            } else {
                                ""
                            }
                        );
                        for l in &r.lines {
                            eprintln!("{l}");
                        }
                        if r.cosigned > 0 {
                            last = tree.size();
                        }
                    }
                    Err(e) => eprintln!("fleet witnessing: {e}"),
                }
            }
        });
    }
    let handler = Arc::new(move |req: &Request| route(&server, req, allow_remote));
    http::serve(listener, 256, 16, handler);
    ExitCode::SUCCESS
}

fn read_directory(path: &str) -> Result<WitnessDirectory, String> {
    crate::read_input(path)
        .map_err(|e| e.to_string())
        .and_then(|s| crate::parse_directory(&s))
}

fn route(server: &Arc<Mutex<FleetServer>>, req: &Request, allow_remote: bool) -> Response {
    if !allow_remote && !req.peer.ip().is_loopback() {
        return Response::text(
            403,
            "loopback clients only (start with --allow-remote to change)\n",
        );
    }
    match (req.method.as_str(), req.path.as_str()) {
        ("POST", "/add-entry") => add_entry(server, req),
        ("GET", "/") => info(server),
        ("GET", "/health") => Response::text(200, "ok\n"),
        ("GET", p) if p.starts_with("/proof/") => {
            let Some(index) = p
                .strip_prefix("/proof/")
                .and_then(witness_log_core::c2sp::parse_canonical_u64)
            else {
                return Response::text(400, "expected /proof/<entry index>\n");
            };
            let s = server.lock().unwrap_or_else(|e| e.into_inner());
            if index >= s.entries.tree.size() {
                return Response::text(404, "no such entry\n");
            }
            match anchor_json(&s.dir, &s.cfg, &s.key, &s.entries, index, None) {
                Ok(v) => Response::json(200, v.to_string()),
                Err(e) => Response::text(500, format!("{e}\n")),
            }
        }
        ("GET", p) if p.starts_with("/latest/") => {
            let origin = p.trim_start_matches("/latest/");
            let s = server.lock().unwrap_or_else(|e| e.into_inner());
            match s.entries.agents.get(origin) {
                Some((k, index)) => Response::json(
                    200,
                    serde_json::json!({
                        "origin": origin,
                        "entry_index": index,
                        "tree_size": k.tree_size,
                        "root_hash": hex::encode(k.root_hash),
                    })
                    .to_string(),
                ),
                None => Response::text(404, "no entry for this agent origin\n"),
            }
        }
        (_, "/add-entry") | (_, "/") | (_, "/health") => {
            Response::text(405, "method not allowed\n")
        }
        _ => Response::text(404, "not found\n"),
    }
}

fn info(server: &Arc<Mutex<FleetServer>>) -> Response {
    let s = server.lock().unwrap_or_else(|e| e.into_inner());
    let head = signed_head(&s.cfg, &s.key, &s.entries.tree)
        .ok()
        .and_then(|n| n.encode().ok());
    let body = serde_json::json!({
        "software": format!("witness-log {}", env!("CARGO_PKG_VERSION")),
        "protocol": "witness-log fleet checkpoint log (RFC-0001, EXPERIMENTAL)",
        "origin": s.cfg.origin,
        "operator_org": s.cfg.operator_org,
        "vkey": vkey_of(&s.cfg, &s.key),
        "entries": s.entries.tree.size(),
        "agents": s.entries.agents.len(),
        "cosigned_size": read_cosigned(&s.dir).map(|(n, _)| n),
        "checkpoint": head,
        "appended_since_start": s.appended,
        "proven_equivocations_since_start": s.refused_forks,
        "started_unix": s.started,
    });
    Response::json(200, serde_json::to_string_pretty(&body).unwrap_or_default())
}

fn add_entry(server: &Arc<Mutex<FleetServer>>, req: &Request) -> Response {
    let Ok(body) = std::str::from_utf8(&req.body) else {
        return Response::text(400, "body is not UTF-8\n");
    };
    let request = match AddCheckpointRequest::parse(body) {
        Ok(r) => r,
        Err(e) => return Response::text(400, format!("{e}\n")),
    };
    let cp = match Checkpoint::from_note(&request.checkpoint_note) {
        Ok(c) => c,
        Err(e) => return Response::text(400, format!("not a checkpoint note: {e}\n")),
    };
    if identity_from_canonical_origin(&cp.origin).is_none() {
        return Response::text(
            400,
            "a fleet log entry is a witness-log agent checkpoint: its origin must be \
             witness-log/<identity hex>\n",
        );
    }
    if !cp.extensions.is_empty() {
        return Response::text(400, "a fleet log entry carries no extension lines\n");
    }

    let mut guard = server.lock().unwrap_or_else(|e| e.into_inner());
    let s = &mut *guard;
    if !s.lock.still_ours() {
        eprintln!(
            "FATAL: {}/fleet.lock no longer names this process -- another process took over \
             this state directory. Exiting without appending anything further.",
            s.dir.display()
        );
        std::process::exit(3);
    }
    let (mut record, held_index) = match s.entries.agents.get(&cp.origin) {
        Some((k, index)) => (k.clone(), Some(*index)),
        None => {
            if s.entries.agents.len() >= s.max_origins {
                return Response::text(503, "fleet log is at its --max-origins capacity\n");
            }
            // The origin names the only key that can sign under it.
            match KnownLog::from_canonical_request(&request) {
                Some(k) => (k, None),
                None => return Response::text(403, "checkpoint signature not verified\n"),
            }
        }
    };
    let held = (record.tree_size, record.root_hash);
    // The witness state machine decides; its cosignature (by the fleet key,
    // over the agent's checkpoint) is discarded and never leaves here.
    let outcome = record.handle_add_checkpoint(&request, &s.cfg.origin, &s.key, now_s());
    match outcome {
        AddCheckpointOutcome::Cosigned { .. } => {
            if let Some(index) = held_index {
                if held == (cp.tree_size, cp.root_hash) {
                    // The checkpoint this log already holds: nothing new.
                    return anchor_response(s, index, false);
                }
            }
            let Some(entry) = record.checkpoint_note.clone() else {
                return Response::text(500, "no log-signed note to append\n");
            };
            match s.append(entry.as_bytes()) {
                Ok(index) => {
                    s.entries.agents.insert(cp.origin, (record, index));
                    anchor_response(s, index, true)
                }
                Err(e) => {
                    eprintln!("{e}; not acknowledged");
                    Response::text(500, "could not persist the entry; not appended\n")
                }
            }
        }
        AddCheckpointOutcome::ConsistencyFailed {
            witness_size,
            equivocation,
            ..
        } => {
            let proven = equivocation.is_some();
            if let Some(proof) = equivocation {
                s.refused_forks += 1;
                record_evidence(&s.dir, &proof);
            }
            Response::text(
                422,
                format!(
                    "refused: this checkpoint does not extend the one this fleet log holds for \
                     {} (size {witness_size}){}\n",
                    cp.origin,
                    if proven {
                        "; the two signed roots for one size are kept as evidence"
                    } else {
                        ""
                    }
                ),
            )
        }
        other => {
            let (text, ctype) = other.http_body();
            Response::typed(other.http_status(), ctype, text)
        }
    }
}

fn anchor_response(s: &FleetServer, index: u64, appended: bool) -> Response {
    match anchor_json(&s.dir, &s.cfg, &s.key, &s.entries, index, Some(appended)) {
        Ok(v) => Response::json(200, v.to_string()),
        Err(e) => Response::text(500, format!("{e}\n")),
    }
}

// --------------------------------------------------------------- witness

struct Round {
    cosigned: usize,
    refused_422: usize,
    lines: Vec<String>,
}

/// Submit the fleet checkpoint at `tree`'s size to every witness in
/// `directory` (the `tlog-witness` protocol, consistency proofs from each
/// witness's last size), and keep the cosignatures that verify under the
/// directory's keys in `cosigned.note`.
fn witness_round(
    dir: &Path,
    cfg: &FleetConfig,
    key: &SigningKey,
    tree: &MerkleTree,
    directory: &WitnessDirectory,
) -> Result<Round, String> {
    let checkpoint = Checkpoint {
        origin: cfg.origin.clone(),
        tree_size: tree.size(),
        root_hash: tree.root(),
        extensions: vec![],
    };
    let note = checkpoint.sign(key).map_err(|e| e.to_string())?;
    let state_path = dir.join("witnesses.json");
    let mut sizes: BTreeMap<String, u64> = fs::read_to_string(&state_path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default();
    let results: Vec<_> = std::thread::scope(|sc| {
        let handles: Vec<_> = directory
            .witnesses
            .iter()
            .map(|w| {
                let known = sizes
                    .get(&w.pubkey.to_ascii_lowercase())
                    .copied()
                    .unwrap_or(0);
                let (checkpoint, note) = (&checkpoint, &note);
                sc.spawn(move || (w, cosign_one(w, tree, checkpoint, note, known, "fleet log")))
            })
            .collect();
        handles.into_iter().filter_map(|h| h.join().ok()).collect()
    });
    let mut cosignatures: Vec<NoteSignature> = Vec::new();
    let mut lines = Vec::new();
    let mut refused_422 = 0;
    for (w, r) in results {
        match r {
            Ok((cos, _)) => {
                lines.push(format!(
                    "  ✓ {:<32} cosigned fleet size {}",
                    w.name,
                    tree.size()
                ));
                sizes.insert(w.pubkey.to_ascii_lowercase(), tree.size());
                cosignatures.push(cos.to_note_signature());
            }
            Err(e) => {
                if matches!(e, SubmitError::Refused(_)) {
                    refused_422 += 1;
                }
                let hint = if e.to_string().contains("HTTP 404") {
                    format!(
                        " (the witness has not enrolled this fleet log: witness-log witness add-log <its dir> {} {})",
                        cfg.origin,
                        vkey_of(cfg, key)
                    )
                } else {
                    String::new()
                };
                lines.push(format!("  ✗ {:<32} {e}{hint}", w.name));
            }
        }
    }
    if let Ok(json) = serde_json::to_vec_pretty(&sizes) {
        if let Err(e) = atomic_write(&state_path, &json) {
            lines.push(format!(
                "warning: could not save {}: {e}",
                state_path.display()
            ));
        }
    }
    let cosigned = cosignatures.len();
    if cosigned > 0 {
        store_cosigned(dir, note, cosignatures)?;
    }
    Ok(Round {
        cosigned,
        refused_422,
        lines,
    })
}

/// Keep the largest cosigned fleet checkpoint. Cosignatures on the same
/// size are merged (one line per key name and ID); a smaller size never
/// replaces a larger one.
fn store_cosigned(
    dir: &Path,
    mut note: SignedNote,
    cosignatures: Vec<NoteSignature>,
) -> Result<(), String> {
    let size = Checkpoint::from_note(&note)
        .map_err(|e| e.to_string())?
        .tree_size;
    if let Some((held, raw)) = read_cosigned(dir) {
        if held > size {
            return Ok(());
        }
        if held == size {
            if let Ok(old) = SignedNote::parse(&raw) {
                if old.text == note.text {
                    note = old;
                }
            }
        }
    }
    for c in cosignatures {
        if !note
            .signatures
            .iter()
            .any(|s| s.key_name == c.key_name && s.key_id == c.key_id)
        {
            note.signatures.push(c);
        }
    }
    let encoded = note.encode().map_err(|e| e.to_string())?;
    atomic_write_shared(&dir.join(COSIGNED), encoded.as_bytes()).map_err(|e| e.to_string())
}

fn cmd_witness(args: &[String]) -> ExitCode {
    let Some(dir) = args.first().filter(|a| !a.starts_with("--")) else {
        return usage_err("fleet witness: missing <dir>");
    };
    if let Err(e) = check_flags("fleet witness", args, &["--directory", "--min"], &[]) {
        return usage_err(&e);
    }
    let Some(dir_path) = flag(args, "--directory") else {
        return usage_err("fleet witness: --directory <trusted.json> is required");
    };
    let dir = PathBuf::from(dir);
    let directory = match read_directory(&dir_path) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("{dir_path}: {e}");
            return ExitCode::from(crate::exit::USAGE);
        }
    };
    let min = match flag(args, "--min").map(|v| v.parse::<usize>()) {
        None => default_min(directory.witnesses.len()),
        Some(Ok(n)) => n,
        Some(Err(_)) => return usage_err("fleet witness: --min expects an integer"),
    };
    let (cfg, key) = match load_config_and_key(&dir) {
        Ok(x) => x,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(1);
        }
    };
    // Complete lines only: a running `fleet serve` may be mid-append. Each
    // complete line was written before this read; fsync makes them durable
    // before any witness is asked to cosign a head that includes them.
    let entries = match load_entries(&dir) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(1);
        }
    };
    if let Err(e) = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(dir.join(ENTRIES))
        .and_then(|f| f.sync_all())
    {
        eprintln!("{}: {e}", dir.join(ENTRIES).display());
        return ExitCode::from(1);
    }
    if let Err(e) = check_cosigned_against(&dir, &cfg, &entries.tree) {
        eprintln!("{e}");
        return ExitCode::from(1);
    }
    if entries.tree.size() == 0 {
        eprintln!("the fleet log is empty; nothing to witness");
        return ExitCode::SUCCESS;
    }
    let round = match witness_round(&dir, &cfg, &key, &entries.tree, &directory) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(1);
        }
    };
    for l in &round.lines {
        eprintln!("{l}");
    }
    eprintln!(
        "{}/{} witnesses cosigned fleet checkpoint size {} of {}",
        round.cosigned,
        directory.witnesses.len(),
        entries.tree.size(),
        cfg.origin
    );
    if round.refused_422 > 0 {
        eprintln!(
            "{} witness(es) REFUSED this fleet log's checkpoint (422): it does not extend what \
             they cosigned before. Exit 20.",
            round.refused_422
        );
        return ExitCode::from(crate::exit::SUBMIT_REFUSED);
    }
    if round.cosigned < min {
        eprintln!("{} is below --min {min}; exit 20.", round.cosigned);
        return ExitCode::from(crate::exit::SUBMIT_REFUSED);
    }
    ExitCode::SUCCESS
}

// --------------------------------------------------- submit --fleet (agent)

#[derive(Deserialize)]
struct AnchorResponse {
    origin: String,
    entry_index: u64,
    entry_bytes_b64: String,
    inclusion_proof: Vec<String>,
    fleet_checkpoint_note: String,
    fleet_tree_size: u64,
    cosigned: bool,
    #[serde(default)]
    appended: bool,
}

impl AnchorResponse {
    fn anchor(&self) -> FleetAnchor {
        FleetAnchor {
            origin: self.origin.clone(),
            entry_index: self.entry_index,
            entry_bytes_b64: self.entry_bytes_b64.clone(),
            inclusion_proof: self.inclusion_proof.clone(),
            fleet_checkpoint_note: self.fleet_checkpoint_note.clone(),
        }
    }
}

/// Append `log`'s checkpoint to the fleet log at `url` and return the
/// anchor, checked against `native` (RFC-0001 steps 2 and 3): a fleet log
/// that answers with something else is an error, not an anchor. With
/// `wait`, poll until a cosigned fleet checkpoint covers the entry.
fn anchor_in_fleet(
    log: &witness_log_core::log::WitnessLog,
    native: &witness_log_core::sth::SignedTreeHead,
    url: &str,
    wait: Duration,
) -> Result<AnchorResponse, SubmitError> {
    let fleet = http::parse_url(url)?;
    let key = SigningKey::from_bytes(&log.identity_bytes());
    let checkpoint = log.c2sp_checkpoint(&canonical_origin(&key.verifying_key()));
    let note = checkpoint
        .sign(&key)
        .map_err(|e| format!("could not sign checkpoint: {e}"))?;
    let mut tree = MerkleTree::new();
    for l in log.leaves() {
        tree.append(leaf_hash(&l.canonical_bytes()));
    }
    let body = post_add_checkpoint(
        &fleet,
        "/add-entry",
        &tree,
        &note,
        checkpoint.tree_size,
        0,
        "the fleet log already holds",
        "journal",
    )?;
    let check = |body: &str| -> Result<AnchorResponse, SubmitError> {
        let r: AnchorResponse = serde_json::from_str(body)
            .map_err(|e| format!("fleet log answered with something other than an anchor: {e}"))?;
        witness_log_network::fleet::verify_fleet_anchor(&r.anchor(), native, None).map_err(
            |f| {
                format!(
                    "the fleet log's anchor does not check out: {}",
                    f.join("; ")
                )
            },
        )?;
        Ok(r)
    };
    let mut r = check(&body)?;
    let deadline = Instant::now() + wait;
    while !r.cosigned && Instant::now() < deadline {
        std::thread::sleep(Duration::from_secs(1));
        let (status, resp, _) = http::request(
            &fleet,
            "GET",
            &format!("/proof/{}", r.entry_index),
            b"",
            Duration::from_secs(10),
        )?;
        if status != 200 {
            return Err(format!(
                "fleet log GET /proof/{}: HTTP {status}: {}",
                r.entry_index,
                String::from_utf8_lossy(&resp).trim()
            )
            .into());
        }
        let appended = r.appended;
        r = check(&String::from_utf8_lossy(&resp))?;
        r.appended = appended;
    }
    Ok(r)
}

/// `submit <journal> --fleet <url> [--fleet-wait SECS] [--directory ...]`.
/// `args` are `submit`'s, the journal first. With `--directory` the direct
/// submission runs exactly as without `--fleet` and its exit rules apply;
/// the fleet anchor is added to the dossier. Without it the exit status is
/// 0 when a cosigned fleet checkpoint covers the entry, 20 otherwise.
pub(crate) fn cmd_submit_fleet(journal: &str, args: &[String]) -> ExitCode {
    let Some(fleet_url) = flag(args, "--fleet") else {
        return usage_err("submit: --fleet requires the fleet log's URL");
    };
    let wait = match flag(args, "--fleet-wait").map(|v| v.parse::<u64>()) {
        None => Duration::ZERO,
        Some(Ok(n)) => Duration::from_secs(n),
        Some(Err(_)) => return usage_err("submit: --fleet-wait expects seconds"),
    };
    if flag(args, "--directory").is_none() && args.iter().any(|a| a == "--min" || a == "--state") {
        return usage_err("submit: --min and --state apply to --directory, which was not given");
    }
    let out_path = flag(args, "--out").unwrap_or_else(|| "dossier.json".into());
    let seed = match crate::identity_seed_from_args(args) {
        Ok(s) => s,
        Err(e) => return usage_err(&e),
    };
    let (log, _) = match crate::replay_journal(journal, seed.as_deref()) {
        Ok(x) => x,
        Err(e) => {
            eprintln!("{journal}: {e}");
            return ExitCode::from(crate::exit::USAGE);
        }
    };

    // The direct path first, unchanged, when a directory was given.
    let mut direct_exit: Option<ExitCode> = None;
    let mut dossier = match flag(args, "--directory") {
        Some(dir_path) => {
            let directory = match read_directory(&dir_path) {
                Ok(d) => d,
                Err(e) => {
                    eprintln!("{dir_path}: {e}");
                    return ExitCode::from(crate::exit::USAGE);
                }
            };
            let n_dir = directory.witnesses.len();
            let min: usize = match flag(args, "--min").map(|v| v.parse()) {
                None => default_min(n_dir),
                Some(Ok(n)) => n,
                Some(Err(_)) => return usage_err("--min: expected an integer"),
            };
            let state_path =
                flag(args, "--state").unwrap_or_else(|| format!("{journal}.witnesses.json"));
            let result = match submit_log(&log, &directory, &directory.witnesses, &state_path) {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("{e}");
                    return ExitCode::from(1);
                }
            };
            for l in &result.lines {
                eprintln!("{l}");
            }
            eprintln!("{}/{n_dir} witnesses cosigned directly", result.cosigned);
            if result.refused_422 > 0 || result.cosigned < min {
                direct_exit = Some(ExitCode::from(crate::exit::SUBMIT_REFUSED));
            }
            result.dossier
        }
        None => {
            let key = SigningKey::from_bytes(&log.identity_bytes());
            Dossier::from_log(&log, log.checkpoint(&key))
        }
    };

    let r = match anchor_in_fleet(&log, &dossier.checkpoint, &fleet_url, wait) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("fleet log {fleet_url}: {e}");
            return ExitCode::from(match e {
                SubmitError::Refused(_) => crate::exit::SUBMIT_REFUSED,
                SubmitError::Other(_) => 1,
            });
        }
    };
    let lines = SignedNote::parse(&r.fleet_checkpoint_note)
        .map(|n| cosignature_lines(&n, &r.origin))
        .unwrap_or(0);
    dossier = dossier.with_fleet_anchor(r.anchor());
    let json = match serde_json::to_vec_pretty(&dossier) {
        Ok(j) => j,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(1);
        }
    };
    if let Err(e) = atomic_write_shared(Path::new(&out_path), &json) {
        eprintln!("{out_path}: {e}");
        return ExitCode::from(1);
    }
    eprintln!(
        "fleet log {}: entry {} ({}), proven against fleet checkpoint size {} with {lines} cosignature line(s)\nwrote {out_path} (EXPERIMENTAL fleet anchor). Verify with:\n  witness-log verify {out_path} --identity {} --directory <directory YOU trust> --accept-fleet-anchor --subject-org <the organisation that runs this fleet log>",
        r.origin,
        r.entry_index,
        if r.appended { "appended" } else { "already held" },
        r.fleet_tree_size,
        dossier.identity_pubkey
    );
    if let Some(code) = direct_exit {
        return code;
    }
    if flag(args, "--directory").is_some() {
        return ExitCode::SUCCESS;
    }
    if !r.cosigned {
        eprintln!(
            "No cosigned fleet checkpoint covers entry {} yet: the dossier anchors it to the \
             fleet log's current head only. Run submit again after the fleet operator's next \
             `fleet witness` (or pass --fleet-wait SECS). Exit 20.",
            r.entry_index
        );
        return ExitCode::from(crate::exit::SUBMIT_REFUSED);
    }
    ExitCode::SUCCESS
}

/// The server's request path and its state on disk, in process.
#[cfg(test)]
mod tests {
    use super::*;
    use witness_log_core::c2sp::Cosignature;

    fn tmp(tag: &str) -> PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static N: AtomicU64 = AtomicU64::new(0);
        let d = std::env::temp_dir().join(format!(
            "wl-fleet-unit-{tag}-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    /// An initialised fleet directory and a server over it.
    fn server(dir: &Path, max_origins: usize) -> Arc<Mutex<FleetServer>> {
        let key = SigningKey::from_bytes(&[3; 32]);
        let cfg = FleetConfig {
            format: FORMAT.into(),
            origin: "fleet.test/witness-log/fleet".into(),
            operator_org: "Test".into(),
            public_url: None,
            pubkey_hex: hex::encode(key.verifying_key().to_bytes()),
        };
        if !dir.join(ENTRIES).exists() {
            fs::write(dir.join(ENTRIES), b"").unwrap();
        }
        let entries = load_entries(dir).unwrap();
        let file = fs::OpenOptions::new()
            .append(true)
            .open(dir.join(ENTRIES))
            .unwrap();
        Arc::new(Mutex::new(FleetServer {
            lock: acquire_lock_at(&dir.join("fleet.lock"), "fleet log", "test").unwrap(),
            dir: dir.to_path_buf(),
            cfg,
            key,
            entries,
            file,
            max_origins,
            appended: 0,
            refused_forks: 0,
            started: 0,
        }))
    }

    /// An agent history: its key and leaf hashes.
    fn agent(seed: u8, leaves: &[&str]) -> (SigningKey, MerkleTree) {
        let mut t = MerkleTree::new();
        for l in leaves {
            t.append(leaf_hash(l.as_bytes()));
        }
        (SigningKey::from_bytes(&[seed; 32]), t)
    }

    fn body(key: &SigningKey, tree: &MerkleTree, old: u64) -> Vec<u8> {
        let cp = Checkpoint {
            origin: canonical_origin(&key.verifying_key()),
            tree_size: tree.size(),
            root_hash: tree.root(),
            extensions: vec![],
        };
        AddCheckpointRequest {
            old_size: old,
            consistency_proof: if old == 0 || old == tree.size() {
                vec![]
            } else {
                tree.consistency_proof(old, tree.size()).unwrap()
            },
            checkpoint_note: cp.sign(key).unwrap(),
        }
        .to_http_body()
        .unwrap()
        .into_bytes()
    }

    fn post(s: &Arc<Mutex<FleetServer>>, body: Vec<u8>) -> (u16, String) {
        let r = add_entry(
            s,
            &Request {
                method: "POST".into(),
                path: "/add-entry".into(),
                body,
                peer: "127.0.0.1:9".parse().unwrap(),
            },
        );
        (r.status, String::from_utf8_lossy(&r.body).into_owned())
    }

    #[test]
    fn entries_survive_a_restart_and_a_resubmission_appends_nothing() {
        let dir = tmp("restart");
        let s = server(&dir, 10);
        let (a, ta) = agent(1, &["a0", "a1"]);
        let (b, tb) = agent(2, &["b0"]);
        let (st, j) = post(&s, body(&a, &ta, 0));
        assert_eq!(st, 200, "{j}");
        let v: serde_json::Value = serde_json::from_str(&j).unwrap();
        assert_eq!(
            (v["entry_index"].as_u64(), v["appended"].as_bool()),
            (Some(0), Some(true))
        );
        assert_eq!(post(&s, body(&b, &tb, 0)).0, 200);
        // The held head again: old size must be what the fleet holds.
        assert_eq!(post(&s, body(&a, &ta, 0)).0, 409);
        let (st, j) = post(&s, body(&a, &ta, 2));
        assert_eq!(st, 200);
        let v: serde_json::Value = serde_json::from_str(&j).unwrap();
        assert_eq!(
            (v["entry_index"].as_u64(), v["appended"].as_bool()),
            (Some(0), Some(false))
        );
        let root = s.lock().unwrap().entries.tree.root();
        drop(s);

        // A restart rebuilds the same tree and per-agent memory.
        let s = server(&dir, 10);
        assert_eq!(s.lock().unwrap().entries.tree.root(), root);
        let (a2, ta2) = agent(1, &["a0", "a1", "a2"]);
        let (st, j) = post(&s, body(&a2, &ta2, 2));
        assert_eq!(st, 200, "{j}");
        // A same-size fork after the restart is refused with evidence.
        let (fa, tfa) = agent(1, &["a0", "X", "a2"]);
        let (st, _) = post(&s, body(&fa, &tfa, 3));
        assert_eq!(st, 422);
        assert_eq!(fs::read_dir(dir.join("evidence")).unwrap().count(), 1);
        assert_eq!(s.lock().unwrap().entries.tree.size(), 3);
        drop(s);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn only_agent_checkpoints_without_extensions_and_at_most_max_origins() {
        let dir = tmp("refuse");
        let s = server(&dir, 1);
        let k = SigningKey::from_bytes(&[4; 32]);
        let plain = |origin: String, ext: Vec<String>| {
            AddCheckpointRequest {
                old_size: 0,
                consistency_proof: vec![],
                checkpoint_note: Checkpoint {
                    origin,
                    tree_size: 1,
                    root_hash: [1; 32],
                    extensions: ext,
                }
                .sign(&k)
                .unwrap(),
            }
            .to_http_body()
            .unwrap()
            .into_bytes()
        };
        assert_eq!(post(&s, plain("example.com/log".into(), vec![])).0, 400);
        let own = canonical_origin(&k.verifying_key());
        assert_eq!(post(&s, plain(own.clone(), vec!["ext".into()])).0, 400);
        assert_eq!(post(&s, plain(own, vec![])).0, 200);
        let (b, tb) = agent(5, &["b0"]);
        assert_eq!(post(&s, body(&b, &tb, 0)).0, 503, "--max-origins 1");
        assert_eq!(s.lock().unwrap().entries.tree.size(), 1);
        drop(s);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_torn_last_line_is_ignored_and_a_damaged_one_refused() {
        let dir = tmp("torn");
        let s = server(&dir, 10);
        let (a, ta) = agent(1, &["a0"]);
        assert_eq!(post(&s, body(&a, &ta, 0)).0, 200);
        drop(s);
        let mut f = fs::OpenOptions::new()
            .append(true)
            .open(dir.join(ENTRIES))
            .unwrap();
        f.write_all(b"d2l0bmVzcy1sb2cv").unwrap();
        let e = load_entries(&dir).unwrap();
        assert_eq!(e.tree.size(), 1);
        assert!(e.file_len > e.complete_len);
        f.write_all(b"\n").unwrap();
        let err = load_entries(&dir).err().unwrap();
        assert!(err.contains("line 2"), "{err}");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn cosignatures_merge_per_size_and_never_go_backwards() {
        let dir = tmp("cosigned");
        let s = server(&dir, 10);
        let (a, ta) = agent(1, &["a0"]);
        let (b, tb) = agent(2, &["b0"]);
        assert_eq!(post(&s, body(&a, &ta, 0)).0, 200);
        let (cfg, key, tree1) = {
            let g = s.lock().unwrap();
            (g.cfg.clone(), g.key.clone(), g.entries.tree.clone())
        };
        assert_eq!(post(&s, body(&b, &tb, 0)).0, 200);
        let tree2 = s.lock().unwrap().entries.tree.clone();
        let cos = |tree: &MerkleTree, w: u8| {
            let note = signed_head(&cfg, &key, tree).unwrap();
            let c = Cosignature::sign(
                &format!("w{w}"),
                &SigningKey::from_bytes(&[w; 32]),
                1,
                &note.text,
            );
            (note, c.to_note_signature())
        };
        let (n1, c1) = cos(&tree1, 10);
        store_cosigned(&dir, n1, vec![c1]).unwrap();
        let (n2, c2) = cos(&tree2, 11);
        store_cosigned(&dir, n2.clone(), vec![c2]).unwrap();
        let (_, c3) = cos(&tree2, 12);
        store_cosigned(&dir, n2, vec![c3]).unwrap();
        let (n1b, c4) = cos(&tree1, 13);
        store_cosigned(&dir, n1b, vec![c4]).unwrap();
        let (size, raw) = read_cosigned(&dir).unwrap();
        assert_eq!(size, 2, "a smaller size never replaces a larger one");
        let note = SignedNote::parse(&raw).unwrap();
        assert_eq!(
            cosignature_lines(&note, &cfg.origin),
            2,
            "w11 and w12 merged"
        );
        // Entry 0 is now proven against the cosigned size 2.
        let v = {
            let g = s.lock().unwrap();
            anchor_json(&dir, &g.cfg, &g.key, &g.entries, 0, None).unwrap()
        };
        assert_eq!(
            (v["fleet_tree_size"].as_u64(), v["cosigned"].as_bool()),
            (Some(2), Some(true))
        );
        drop(s);

        // Restored from a backup older than what witnesses cosigned: refuse.
        let full = fs::read(dir.join(ENTRIES)).unwrap();
        let first = full.iter().position(|&b| b == b'\n').unwrap() + 1;
        fs::write(dir.join(ENTRIES), &full[..first]).unwrap();
        let e = load_entries(&dir).unwrap();
        let err = check_cosigned_against(&dir, &cfg, &e.tree).unwrap_err();
        assert!(err.contains("does not reproduce"), "{err}");
        let _ = fs::remove_dir_all(&dir);
    }
}
