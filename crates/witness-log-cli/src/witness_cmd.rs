//! `witness-log witness ...` -- run a `c2sp.org/tlog-witness` witness, and
//! submit an agent's checkpoints to witnesses to get a WITNESSED dossier.
//!
//! Safety properties the server enforces, in priority order:
//!
//! 1. **Persist before cosigning.** A log's new size/root is written and
//!    fsynced (atomic rename, then directory fsync) BEFORE the cosignature
//!    leaves the process. If persisting fails, the in-memory record is
//!    rolled back and the client gets a 500, never a cosignature. A
//!    witness that cosigns, crashes and restarts with older state can be
//!    walked onto a fork -- this is the one bug a witness must not have.
//! 2. **One process per state directory.** A lock file stops two
//!    witnesses sharing state (each would hold its own in-memory view
//!    and could cosign two forks between them).
//! 3. **Serialized decisions.** All add-checkpoint handling runs under one
//!    mutex, so the size check and the persist are atomic (spec: "to
//!    prevent a rollback race").
//! 4. **Bounded everything.** See `http.rs` for request limits; open
//!    enrollment is capped in total logs and per-client rate.
//!
//! State layout (`<dir>`):
//!   witness.key    32-byte Ed25519 seed, hex, mode 0600
//!   witness.json   key name, operator org, public URL, compute provider
//!   logs/<sha256(origin)>.json   one record per witnessed log
//!   evidence/<sha256(origin)>.json  proven equivocation (two log-signed
//!                  roots for one size) -- self-contained, publishable
//!   witness.lock   held while serving

use crate::http::{self, Request, Response};
use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use witness_log_core::c2sp::{
    canonical_origin, Checkpoint, Cosignature, NoteSignature, VerifierKey,
};
use witness_log_network::tlog_witness::{
    cosignature_to_receipt, AddCheckpointOutcome, AddCheckpointRequest, KnownLog, KnownLogRecord,
    WitnessService,
};
use witness_log_network::{Dossier, WitnessDirectory, WitnessEntry, WitnessReceipt};

const USAGE: &str = "usage:
  witness-log witness init <dir> --name <key-name> [--org <operator>] [--url <public-url>] [--compute <provider>]
  witness-log witness serve <dir> [--listen 127.0.0.1:7380] [--open-enrollment]
                                  [--max-logs 100000] [--max-conns 256] [--max-conns-per-ip 16]
                                  [--enroll-rate 600]
      Behind a reverse proxy every client shares the proxy's address:
      raise --max-conns-per-ip and --enroll-rate to match.
  witness-log witness add-log <dir> <origin> <log-vkey>
  witness-log witness info <http://witness-url>
  witness-log witness submit <journal> --directory <witnesses.json> [--out dossier.json]
                                  [--state <client-state.json>] [--min <n>]
  witness-log witness verify-evidence <evidence.json>
      Check an equivocation proof a witness recorded under evidence/:
      exit 0 if it proves two signed roots for one size, 30 if not.";

#[derive(Serialize, Deserialize, Clone)]
struct WitnessConfig {
    key_name: String,
    operator_org: String,
    public_url: String,
    #[serde(default)]
    compute_provider: Option<String>,
    /// Hex public key of `witness.key` at init. `serve` refuses to start
    /// if the key on disk is a different one: a state directory restored
    /// next to the wrong key would cosign heads that key never saw.
    /// Absent in directories initialised before 0.3.2.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pubkey_hex: Option<String>,
}

fn usage_err(msg: &str) -> ExitCode {
    eprintln!("{msg}\n\n{USAGE}");
    ExitCode::from(2)
}

fn flag(args: &[String], name: &str) -> Option<String> {
    crate::flag_value(args, name)
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
        Some("add-log") => cmd_add_log(rest),
        Some("info") => cmd_info(rest),
        Some("submit") => cmd_submit(rest),
        Some("verify-evidence") => cmd_verify_evidence(rest),
        _ => usage_err("witness: expected a subcommand"),
    }
}

// ------------------------------------------------------- verify-evidence

/// Independently check a proof written by `serve` under `evidence/`.
/// Anyone holding the file can run this; no witness state is needed.
fn cmd_verify_evidence(args: &[String]) -> ExitCode {
    let Some(path) = args.first().filter(|a| !a.starts_with("--")) else {
        return usage_err("witness verify-evidence: missing <evidence.json>");
    };
    let raw = match crate::read_input(path) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("{path}: {e}");
            return ExitCode::from(2);
        }
    };
    let doc: serde_json::Value = match serde_json::from_str(&raw) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("{path}: not JSON: {e}");
            return ExitCode::from(2);
        }
    };
    // Accept the file as `serve` writes it ({"proof": {...}}) or a bare proof.
    let proof_value = doc.get("proof").cloned().unwrap_or(doc);
    let proof: witness_log_network::tlog_witness::EquivocationProof =
        match serde_json::from_value(proof_value) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("{path}: not an equivocation proof: {e}");
                return ExitCode::from(2);
            }
        };
    let describe = |n: &str| -> String {
        witness_log_core::c2sp::SignedNote::parse(n)
            .ok()
            .and_then(|note| Checkpoint::from_note(&note).ok())
            .map(|c| format!("size {} root {}", c.tree_size, hex::encode(c.root_hash)))
            .unwrap_or_else(|| "unparsable note".to_string())
    };
    println!("origin:  {}", proof.origin);
    println!("log key: {}", proof.log_vkey);
    println!("note A:  {}", describe(&proof.earlier_note));
    println!("note B:  {}", describe(&proof.conflicting_note));
    if proof.verify() {
        println!("PROVEN: both notes are signed by the log's key, name the same origin and size, and commit different roots. This identity showed two histories.");
        ExitCode::SUCCESS
    } else {
        println!("NOT PROVEN: the notes do not both verify under the log key with one origin, one size and two roots. This file is not evidence of equivocation.");
        ExitCode::from(30)
    }
}

fn now_s() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// C2SP key names: non-empty, no whitespace, no '+' (field separator).
fn valid_key_name(n: &str) -> bool {
    !n.is_empty()
        && n.len() <= 128
        && n.chars()
            .all(|c| !c.is_whitespace() && !c.is_control() && c != '+')
}

/// Write `data` to `path` atomically and durably: temp file, fsync,
/// rename, fsync the directory. Mode 0600 on Unix.
fn atomic_write(path: &Path, data: &[u8]) -> std::io::Result<()> {
    // `Path::new("dossier.json").parent()` is `Some("")`, not `None`;
    // opening "" to fsync it fails with ENOENT after the rename already
    // succeeded, which made `submit --out dossier.json` in the current
    // directory report failure for a file it had written.
    let dir = path
        .parent()
        .filter(|d| !d.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let tmp = dir.join(format!(
        ".{}.tmp-{}",
        path.file_name().and_then(|n| n.to_str()).unwrap_or("f"),
        std::process::id()
    ));
    {
        let mut opts = fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts.open(&tmp)?;
        f.write_all(data)?;
        f.sync_all()?;
    }
    fs::rename(&tmp, path)?;
    #[cfg(unix)]
    {
        fs::File::open(dir)?.sync_all()?;
    }
    Ok(())
}

fn record_path(dir: &Path, origin: &str) -> PathBuf {
    dir.join("logs").join(format!(
        "{}.json",
        hex::encode(Sha256::digest(origin.as_bytes()))
    ))
}

fn load_key(dir: &Path) -> Result<SigningKey, String> {
    let p = dir.join("witness.key");
    let s = fs::read_to_string(&p).map_err(|e| format!("{}: {e}", p.display()))?;
    let seed: [u8; 32] = hex::decode(s.trim())
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| format!("{}: not a 32-byte hex seed", p.display()))?;
    Ok(SigningKey::from_bytes(&seed))
}

fn load_config(dir: &Path) -> Result<WitnessConfig, String> {
    let p = dir.join("witness.json");
    let s = fs::read_to_string(&p).map_err(|e| format!("{}: {e}", p.display()))?;
    let c: WitnessConfig = serde_json::from_str(&s).map_err(|e| format!("{}: {e}", p.display()))?;
    if !valid_key_name(&c.key_name) {
        return Err(format!("{}: invalid key_name", p.display()));
    }
    Ok(c)
}

/// Load every log record. Any unreadable or inconsistent record aborts
/// startup: silently skipping one would reset that log to size 0 and let
/// it be walked onto a fork.
fn load_service(dir: &Path) -> Result<WitnessService, String> {
    let logs_dir = dir.join("logs");
    if !logs_dir.is_dir() {
        // `init` creates it. Missing state with a key present means the
        // witness's memory was deleted; starting empty would let every
        // log it ever cosigned be walked onto a fork.
        return Err(format!(
            "{} is missing. This witness has a key but no record of what it cosigned; \
             starting empty would allow forks. Restore it from backup, or run `init` \
             in a fresh directory to start a new witness with a new key.",
            logs_dir.display()
        ));
    }
    let mut records = Vec::new();
    for entry in fs::read_dir(&logs_dir).map_err(|e| e.to_string())? {
        let entry = entry.map_err(|e| e.to_string())?;
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().to_string();
        if name.starts_with('.') {
            // Leftover temp file from a crash mid-write; the rename never
            // happened, so the previous record is still authoritative.
            let _ = fs::remove_file(&path);
            continue;
        }
        let s = fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))?;
        let r: KnownLogRecord =
            serde_json::from_str(&s).map_err(|e| format!("{}: {e}", path.display()))?;
        if record_path(dir, &r.origin) != path {
            return Err(format!(
                "{}: record origin does not match its file name (tampered state?)",
                path.display()
            ));
        }
        records.push(r);
    }
    let state = witness_log_network::tlog_witness::WitnessState {
        format_version: witness_log_network::tlog_witness::WitnessState::FORMAT_VERSION,
        witness_pubkey: None, // bound through witness.json's pubkey_hex instead
        logs: records,
    };
    WitnessService::from_state(&state).map_err(|e| e.to_string())
}

fn to_record(k: &KnownLog) -> KnownLogRecord {
    KnownLogRecord {
        origin: k.origin.clone(),
        log_vkey: k.log_vkey.encode(),
        tree_size: k.tree_size,
        root_hash: hex::encode(k.root_hash),
        checkpoint_note: k.checkpoint_note.clone(),
    }
}

fn persist_record(dir: &Path, k: &KnownLog) -> std::io::Result<()> {
    let json = serde_json::to_vec_pretty(&to_record(k)).map_err(std::io::Error::other)?;
    atomic_write(&record_path(dir, &k.origin), &json)
}

// ------------------------------------------------------------------ init

fn cmd_init(args: &[String]) -> ExitCode {
    let Some(dir) = args.first().filter(|a| !a.starts_with("--")) else {
        return usage_err("witness init: missing <dir>");
    };
    let Some(name) = flag(args, "--name") else {
        return usage_err(
            "witness init: --name <key-name> is required (e.g. witness.example.org/w1)",
        );
    };
    if !valid_key_name(&name) {
        return usage_err("witness init: key name must be non-empty, without spaces or '+'");
    }
    // An empty --org was scored by verifiers as an operator of its own,
    // and a non-http --url produced an entry no client can submit to;
    // both were accepted before 0.3.6.
    if flag(args, "--org").is_some_and(|o| o.trim().is_empty()) {
        return usage_err(
            "witness init: --org must be non-empty (verifiers count operators by it)",
        );
    }
    if let Some(u) = flag(args, "--url") {
        if !(u.starts_with("http://") || u.starts_with("https://")) {
            return usage_err(&format!(
                "witness init: --url must start with http:// or https://, got {u:?}"
            ));
        }
    }
    let dir = PathBuf::from(dir);
    if dir.join("witness.key").exists() {
        eprintln!(
            "{}: already initialised (witness.key exists); refusing to overwrite a key",
            dir.display()
        );
        return ExitCode::from(1);
    }
    if let Err(e) = fs::create_dir_all(dir.join("logs")) {
        eprintln!("{}: {e}", dir.display());
        return ExitCode::from(1);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&dir, fs::Permissions::from_mode(0o700));
    }
    let key = SigningKey::generate(&mut rand::rngs::OsRng);
    let operator_org = flag(args, "--org").unwrap_or_else(|| "unspecified".into());
    if operator_org == "unspecified" {
        eprintln!(
            "warning: no --org given. Verifiers score operator diversity by this label; every \
             witness left 'unspecified' shares one bucket and can never count as independent \
             of the others. Set --org to the organisation that runs this witness."
        );
    }
    let cfg = WitnessConfig {
        key_name: name,
        operator_org,
        public_url: flag(args, "--url").unwrap_or_else(|| "http://127.0.0.1:7380".into()),
        compute_provider: flag(args, "--compute"),
        pubkey_hex: Some(hex::encode(key.verifying_key().to_bytes())),
    };
    let key_hex = zeroize::Zeroizing::new(hex::encode(key.to_bytes()));
    let wrote = atomic_write(&dir.join("witness.key"), key_hex.as_bytes()).and_then(|_| {
        let json = serde_json::to_vec_pretty(&cfg).map_err(std::io::Error::other)?;
        atomic_write(&dir.join("witness.json"), &json)
    });
    if let Err(e) = wrote {
        eprintln!("{}: {e}", dir.display());
        return ExitCode::from(1);
    }
    let entry = directory_entry(&cfg, &key);
    println!(
        "{}",
        serde_json::to_string_pretty(&entry).unwrap_or_default()
    );
    eprintln!(
        "\nwitness initialised in {}\n  vkey: {}\n  The JSON above is this witness's directory entry. Publish it;\n  verifiers add it to the directory they trust.",
        dir.display(),
        VerifierKey::for_cosignature(&cfg.key_name, &key.verifying_key()).encode()
    );
    ExitCode::SUCCESS
}

fn directory_entry(cfg: &WitnessConfig, key: &SigningKey) -> WitnessEntry {
    WitnessEntry::independent(
        &cfg.key_name,
        &cfg.operator_org,
        &cfg.public_url,
        hex::encode(key.verifying_key().to_bytes()),
        cfg.compute_provider.clone(),
    )
}

// --------------------------------------------------------------- add-log

fn cmd_add_log(args: &[String]) -> ExitCode {
    let pos: Vec<&String> = args.iter().filter(|a| !a.starts_with("--")).collect();
    let (Some(dir), Some(origin), Some(vkey)) = (pos.first(), pos.get(1), pos.get(2)) else {
        return usage_err("witness add-log: need <dir> <origin> <log-vkey>");
    };
    let dir = PathBuf::from(dir);
    let vk = match VerifierKey::parse(vkey) {
        Ok(v) => v,
        Err(e) => return usage_err(&format!("witness add-log: bad vkey: {e}")),
    };
    if vk.name != **origin {
        return usage_err("witness add-log: vkey name must equal the origin");
    }
    let path = record_path(&dir, origin);
    if path.exists() {
        eprintln!("{origin}: already witnessed; refusing to reset its state (that would allow a rollback)");
        return ExitCode::from(1);
    }
    if let Err(e) = fs::create_dir_all(dir.join("logs")) {
        eprintln!("{e}");
        return ExitCode::from(1);
    }
    let k = KnownLog {
        origin: origin.to_string(),
        log_vkey: vk,
        tree_size: 0,
        root_hash: [0u8; 32],
        checkpoint_note: None,
    };
    if !dir.join("witness.key").exists() {
        return usage_err("witness add-log: <dir> is not an initialised witness");
    }
    match persist_record(&dir, &k) {
        Ok(()) => {
            eprintln!("added {origin}; restart the witness for it to take effect");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("{e}");
            ExitCode::from(1)
        }
    }
}

// ----------------------------------------------------------------- serve

struct Lock(PathBuf);
impl Lock {
    /// True while the lock file still names this process. Checked before
    /// every cosignature: if a racing process removed and replaced our
    /// lock (two restarts after a crash), we find out before signing
    /// anything, not after two witnesses diverged.
    fn still_ours(&self) -> bool {
        fs::read_to_string(&self.0)
            .map(|s| s.trim() == std::process::id().to_string())
            .unwrap_or(false)
    }
}
impl Lock {
    /// Remove the lock file if it is still ours. Idempotent.
    fn release(&self) {
        if self.still_ours() {
            let _ = fs::remove_file(&self.0);
        }
    }
}
impl Drop for Lock {
    fn drop(&mut self) {
        self.release();
    }
}

/// Stop cleanly on SIGTERM/SIGINT: wait for any in-flight decision to
/// finish (the server mutex), release the lock, exit 0. Without this a
/// normal `systemctl stop` left `witness.lock` behind and every restart
/// reported a crash. Signals are blocked in this thread before the
/// accept loop spawns workers, so they inherit the mask and only the
/// waiter thread receives them.
#[cfg(unix)]
fn stop_cleanly_on_signal(server: Arc<Mutex<Server>>) {
    // SAFETY: plain libc signal-mask calls on a zeroed, then initialised,
    // sigset; the spawned thread only ever calls sigwait on that set.
    unsafe {
        let mut set: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut set);
        libc::sigaddset(&mut set, libc::SIGTERM);
        libc::sigaddset(&mut set, libc::SIGINT);
        libc::pthread_sigmask(libc::SIG_BLOCK, &set, std::ptr::null_mut());
        std::thread::spawn(move || {
            let mut sig: libc::c_int = 0;
            if libc::sigwait(&set, &mut sig) == 0 {
                let s = server.lock().unwrap_or_else(|e| e.into_inner());
                eprintln!(
                    "witness stopping on signal {sig}: {} cosigned since start",
                    s.cosigned
                );
                s.lock.release();
                std::process::exit(0);
            }
        });
    }
}

/// Whether `pid` names a running process: `Some(false)` only when we are
/// sure it does not. PID reuse can make a dead holder look alive, which
/// fails safe (the operator removes the lock); the reverse cannot happen.
fn process_alive(pid: &str) -> Option<bool> {
    if pid.is_empty() || !pid.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    #[cfg(target_os = "linux")]
    {
        Some(Path::new(&format!("/proc/{pid}")).exists())
    }
    #[cfg(all(unix, not(target_os = "linux")))]
    {
        let out = std::process::Command::new("kill")
            .args(["-0", pid])
            .output()
            .ok()?;
        if out.status.success() {
            return Some(true);
        }
        let err = String::from_utf8_lossy(&out.stderr).to_ascii_lowercase();
        // EPERM means it exists but belongs to someone else: alive.
        if err.contains("no such process") {
            Some(false)
        } else {
            Some(true)
        }
    }
    #[cfg(not(unix))]
    {
        None
    }
}

fn acquire_lock(dir: &Path) -> Result<Lock, String> {
    let p = dir.join("witness.lock");
    for _ in 0..2 {
        match fs::OpenOptions::new().write(true).create_new(true).open(&p) {
            Ok(mut f) => {
                let _ = writeln!(f, "{}", std::process::id());
                let _ = f.sync_all();
                let lock = Lock(p);
                // Two processes restarting over the same stale lock can
                // both "take it over" within microseconds. Settle, then
                // confirm we still hold it, BEFORE loading state or serving:
                // the loser exits having signed nothing.
                std::thread::sleep(Duration::from_millis(250));
                if !lock.still_ours() {
                    std::mem::forget(lock);
                    return Err(format!(
                        "{}: lost a race for the lock to another witness process",
                        dir.join("witness.lock").display()
                    ));
                }
                return Ok(lock);
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                let pid = fs::read_to_string(&p).unwrap_or_default();
                let pid = pid.trim();
                // Tell a crashed holder from a live one where the OS lets
                // us; anywhere else, fail safe and ask the operator.
                //
                // A lock naming OUR OWN pid cannot be held by a live
                // witness: we have not taken it yet. It was left by an
                // earlier process that had the same pid -- always the case
                // in a container (the witness is pid 1 on every start, so
                // `docker kill` + `start` refused forever) and possible on
                // a host after a reboot.
                let own = pid == std::process::id().to_string();
                if own || process_alive(pid) == Some(false) {
                    // Narrow the race with another restarting process: only
                    // remove the file if it still names the dead pid.
                    let again = fs::read_to_string(&p).unwrap_or_default();
                    if again.trim() == pid {
                        if own {
                            eprintln!(
                                "removing stale witness.lock naming pid {pid}, this process's own pid \
                                 (left by an earlier run with the same pid, e.g. pid 1 in a container)"
                            );
                        } else {
                            eprintln!(
                                "removing stale witness.lock left by pid {pid}, which is no longer running"
                            );
                        }
                        let _ = fs::remove_file(&p);
                    }
                    continue;
                }
                return Err(format!(
                    "{} is held by pid {pid}. Two witnesses on one state directory could \
                     cosign two forks. If that process is gone, delete the lock file.",
                    p.display()
                ));
            }
            Err(e) => return Err(format!("{}: {e}", p.display())),
        }
    }
    Err(format!("{}: could not acquire lock", p.display()))
}

struct Server {
    lock: Lock,
    /// Origins whose equivocation is already recorded this run; one proof
    /// per log is all anyone needs.
    evidence_recorded: std::collections::HashSet<String>,
    refused_unproven: u64,
    dir: PathBuf,
    cfg: WitnessConfig,
    key: SigningKey,
    svc: WitnessService,
    open_enrollment: bool,
    max_logs: usize,
    /// Per-client enrollment rate limit: (window start, count).
    enroll_rate: HashMap<IpAddr, (Instant, usize)>,
    enroll_per_minute: usize,
    started: u64,
    cosigned: u64,
    refused_forks: u64,
}

/// Default new-log enrollments per client IP per minute. Generous on
/// purpose: a fleet of agents behind one NAT or CI runner must be able to
/// enroll together (the live 50-agent run hit a 30/min limit). Storage is
/// bounded by `--max-logs`, not by this.
const DEFAULT_ENROLL_PER_MINUTE: usize = 600;

fn cmd_serve(args: &[String]) -> ExitCode {
    let Some(dir) = args.first().filter(|a| !a.starts_with("--")) else {
        return usage_err("witness serve: missing <dir>");
    };
    let dir = PathBuf::from(dir);
    let listen = flag(args, "--listen").unwrap_or_else(|| "127.0.0.1:7380".into());
    let parse_n = |f: &str, d: usize| -> Result<usize, ExitCode> {
        match flag(args, f) {
            None => Ok(d),
            Some(v) => v
                .parse()
                .ok()
                .filter(|n| *n > 0)
                .ok_or_else(|| usage_err(&format!("{f}: expected a positive integer"))),
        }
    };
    let max_logs = match parse_n("--max-logs", 100_000) {
        Ok(n) => n,
        Err(c) => return c,
    };
    let max_conns = match parse_n("--max-conns", 256) {
        Ok(n) => n,
        Err(c) => return c,
    };
    let max_per_ip = match parse_n("--max-conns-per-ip", 16) {
        Ok(n) => n,
        Err(c) => return c,
    };
    let enroll_per_minute = match parse_n("--enroll-rate", DEFAULT_ENROLL_PER_MINUTE) {
        Ok(n) => n,
        Err(c) => return c,
    };
    let (cfg, key) = match (load_config(&dir), load_key(&dir)) {
        (Ok(c), Ok(k)) => (c, k),
        (Err(e), _) | (_, Err(e)) => {
            eprintln!(
                "{e}\n(run `witness-log witness init {} --name <key-name>` first)",
                dir.display()
            );
            return ExitCode::from(1);
        }
    };
    if let Some(expected) = &cfg.pubkey_hex {
        let actual = hex::encode(key.verifying_key().to_bytes());
        if !expected.eq_ignore_ascii_case(&actual) {
            eprintln!(
                "{}: witness.key ({actual}) is not the key witness.json was initialised with \
                 ({expected}). Refusing to serve: logs/ is that key's memory, and another key \
                 using it would cosign heads it never saw. Restore witness.key, witness.json \
                 and logs/ from the same backup.",
                dir.display()
            );
            return ExitCode::from(1);
        }
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(m) = fs::metadata(dir.join("witness.key")) {
            if m.permissions().mode() & 0o077 != 0 {
                eprintln!(
                    "WARNING: {}/witness.key is readable by other users. Anyone who reads \
                     it can forge this witness's cosignatures. Run: chmod 600 {}/witness.key",
                    dir.display(),
                    dir.display()
                );
            }
        }
    }
    let lock = match acquire_lock(&dir) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(1);
        }
    };
    let svc = match load_service(&dir) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("refusing to start: {e}");
            return ExitCode::from(1);
        }
    };
    let listener = match std::net::TcpListener::bind(&listen) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("bind {listen}: {e}");
            return ExitCode::from(1);
        }
    };
    let bound = listener
        .local_addr()
        .map(|a| a.to_string())
        .unwrap_or(listen);
    eprintln!(
        "witness {} listening on http://{bound} ({} logs, open enrollment: {})",
        cfg.key_name,
        svc.log_count(),
        if args.iter().any(|a| a == "--open-enrollment") {
            "on"
        } else {
            "off"
        }
    );
    let server = Arc::new(Mutex::new(Server {
        lock,
        evidence_recorded: std::collections::HashSet::new(),
        refused_unproven: 0,
        dir,
        cfg,
        key,
        svc,
        open_enrollment: args.iter().any(|a| a == "--open-enrollment"),
        max_logs,
        enroll_rate: HashMap::new(),
        enroll_per_minute,
        started: now_s(),
        cosigned: 0,
        refused_forks: 0,
    }));
    #[cfg(unix)]
    stop_cleanly_on_signal(server.clone());
    let handler = Arc::new(move |req: &Request| route(&server, req));
    http::serve(listener, max_conns, max_per_ip, handler);
    ExitCode::SUCCESS
}

fn route(server: &Arc<Mutex<Server>>, req: &Request) -> Response {
    match (req.method.as_str(), req.path.as_str()) {
        ("POST", "/add-checkpoint") => add_checkpoint(server, req),
        ("GET", "/") => info(server),
        ("GET", "/health") => Response::text(200, "ok\n"),
        (_, "/add-checkpoint") | (_, "/") | (_, "/health") => {
            Response::text(405, "method not allowed\n")
        }
        _ => Response::text(404, "not found\n"),
    }
}

fn info(server: &Arc<Mutex<Server>>) -> Response {
    let s = server.lock().unwrap_or_else(|e| e.into_inner());
    let entry = directory_entry(&s.cfg, &s.key);
    let body = serde_json::json!({
        "software": format!("witness-log {}", env!("CARGO_PKG_VERSION")),
        "protocol": "c2sp.org/tlog-witness",
        "key_name": s.cfg.key_name,
        "pubkey_hex": hex::encode(s.key.verifying_key().to_bytes()),
        "vkey": VerifierKey::for_cosignature(&s.cfg.key_name, &s.key.verifying_key()).encode(),
        "open_enrollment": s.open_enrollment,
        "logs": s.svc.log_count(),
        "cosigned_since_start": s.cosigned,
        "proven_equivocations_since_start": s.refused_forks,
        "refused_unproven_since_start": s.refused_unproven,
        "started_unix": s.started,
        "directory_entry": entry,
    });
    Response::json(200, serde_json::to_string_pretty(&body).unwrap_or_default())
}

fn add_checkpoint(server: &Arc<Mutex<Server>>, req: &Request) -> Response {
    let Ok(body) = std::str::from_utf8(&req.body) else {
        return Response::text(400, "body is not UTF-8\n");
    };
    let request = match AddCheckpointRequest::parse(body) {
        Ok(r) => r,
        Err(e) => return Response::text(400, format!("{e}\n")),
    };
    let origin = match Checkpoint::from_note(&request.checkpoint_note) {
        Ok(c) => c.origin,
        Err(_) => return Response::text(403, "checkpoint signature not verified\n"),
    };

    let mut guard = server.lock().unwrap_or_else(|e| e.into_inner());
    let s = &mut *guard;
    if !s.lock.still_ours() {
        eprintln!(
            "FATAL: {}/witness.lock no longer names this process -- another witness took \
             over this state directory. Exiting without cosigning anything further.",
            s.dir.display()
        );
        std::process::exit(3);
    }
    let mut newly_enrolled = false;
    if s.svc.known_log(&origin).is_none() && s.open_enrollment {
        if s.svc.log_count() >= s.max_logs {
            return Response::text(503, "witness is at its log capacity\n").retry_after(3600);
        }
        let ip = http::client_key(req.peer.ip());
        let now = Instant::now();
        let slot = s.enroll_rate.entry(ip).or_insert((now, 0));
        if now.duration_since(slot.0) > Duration::from_secs(60) {
            *slot = (now, 0);
        }
        if slot.1 >= s.enroll_per_minute {
            let wait = 60u64
                .saturating_sub(now.duration_since(slot.0).as_secs())
                .max(1);
            return Response::text(429, "enrollment rate limit\n").retry_after(wait);
        }
        newly_enrolled = s.svc.enroll_canonical(&request);
        if newly_enrolled {
            slot.1 += 1;
        } else if witness_log_core::c2sp::identity_from_canonical_origin(&origin).is_some() {
            // The origin names its own key, so this witness DOES know which
            // key must have signed: a failure here is a bad signature (403),
            // not an unknown log (404).
            return Response::text(403, "checkpoint signature not verified\n");
        }
        // Keep the rate table bounded.
        if s.enroll_rate.len() > 10_000 {
            s.enroll_rate
                .retain(|_, (t, _)| now.duration_since(*t) <= Duration::from_secs(60));
        }
    }

    let previous = s.svc.known_log(&origin).cloned();
    let outcome = s
        .svc
        .handle_add_checkpoint(&request, &s.cfg.key_name, &s.key, now_s());

    match &outcome {
        AddCheckpointOutcome::Cosigned { .. } => {
            let persisted = match s.svc.known_log(&origin) {
                Some(k) => persist_record(&s.dir, k),
                None => Err(std::io::Error::other("record vanished")),
            };
            if let Err(e) = persisted {
                // Roll back and DO NOT release the cosignature.
                match previous {
                    Some(p) if !newly_enrolled => s.svc.set_known_log(p),
                    _ => {
                        s.svc.remove_log(&origin);
                    }
                }
                eprintln!("persist failed for {origin}: {e}; cosignature withheld");
                return Response::text(500, "could not persist state; not cosigning\n");
            }
            s.cosigned += 1;
        }
        AddCheckpointOutcome::ConsistencyFailed {
            equivocation: Some(proof),
            ..
        } => {
            s.refused_forks += 1;
            if s.evidence_recorded.insert(origin.clone()) {
                record_evidence(&s.dir, proof);
            }
        }
        AddCheckpointOutcome::ConsistencyFailed { .. } => {
            // Refused, but a failing proof is not proof of a fork: anyone
            // can attach a junk proof to an honest log's checkpoint.
            s.refused_unproven += 1;
        }
        _ => {}
    }
    // Enrollment is kept only once a cosignature has been persisted. Every
    // other outcome -- including a 422 on first contact, which the final
    // review found left a phantom in-memory log counting toward
    // --max-logs -- drops it again. (A first-contact request can never be
    // provable equivocation: the witness holds nothing to contradict.)
    if newly_enrolled && !matches!(outcome, AddCheckpointOutcome::Cosigned { .. }) {
        s.svc.remove_log(&origin);
    }
    let (text, ctype) = outcome.http_body();
    Response::typed(outcome.http_status(), ctype, text)
}

/// Write a proven equivocation to `evidence/<sha256(origin)>.json`. One
/// file per log, first proof wins: one proof is all anyone needs, storage
/// is bounded by `--max-logs` (each proof is a few KiB since checkpoint
/// bodies are capped), and no log's evidence can crowd out another's.
fn record_evidence(dir: &Path, proof: &witness_log_network::tlog_witness::EquivocationProof) {
    let ev_dir = dir.join("evidence");
    let path = ev_dir.join(format!(
        "{}.json",
        hex::encode(Sha256::digest(proof.origin.as_bytes()))
    ));
    if path.exists() {
        return;
    }
    let doc = serde_json::json!({
        "observed_unix": now_s(),
        "kind": "equivocation",
        "proof": proof,
    });
    let res = fs::create_dir_all(&ev_dir).and_then(|_| {
        let bytes = serde_json::to_vec_pretty(&doc).map_err(std::io::Error::other)?;
        atomic_write(&path, &bytes)
    });
    match res {
        Ok(()) => eprintln!(
            "EQUIVOCATION by {}: two signed roots for one size; proof in {}",
            proof.origin,
            path.display()
        ),
        Err(e) => eprintln!(
            "could not record equivocation proof for {}: {e}",
            proof.origin
        ),
    }
}

// ------------------------------------------------------------------ info

fn cmd_info(args: &[String]) -> ExitCode {
    let Some(url) = args.first() else {
        return usage_err("witness info: missing <url>");
    };
    let u = match http::parse_url(url) {
        Ok(u) => u,
        Err(e) => return usage_err(&e),
    };
    match http::request(&u, "GET", "/", b"", Duration::from_secs(5)) {
        Ok((200, body, _)) => {
            println!("{}", String::from_utf8_lossy(&body));
            ExitCode::SUCCESS
        }
        Ok((st, body, _)) => {
            eprintln!(
                "{url}: HTTP {st}: {}",
                String::from_utf8_lossy(&body).trim()
            );
            ExitCode::from(1)
        }
        Err(e) => {
            eprintln!("{url}: {e}");
            ExitCode::from(1)
        }
    }
}

// ---------------------------------------------------------------- submit

/// Client-side memory of how far each witness has cosigned this log, so
/// the next submission carries the right `old` size and proof without a
/// 409 round-trip. Losing it is harmless (the 409 tells us).
#[derive(Serialize, Deserialize, Default)]
struct ClientState {
    /// witness pubkey hex -> last cosigned size
    sizes: std::collections::BTreeMap<String, u64>,
    /// Largest head any witness has cosigned for this log (size, root hex).
    /// Used to refuse submitting a history that contradicts it: witnesses
    /// would record that as proof this identity equivocated.
    #[serde(default)]
    cosigned_size: u64,
    #[serde(default)]
    cosigned_root: String,
}

struct Outcome {
    name: String,
    result: Result<(WitnessReceipt, u64), String>,
}

fn cmd_submit(args: &[String]) -> ExitCode {
    let Some(journal) = args.first().filter(|a| !a.starts_with("--")) else {
        return usage_err("witness submit: missing <journal>");
    };
    // Every other argument is a known flag followed by its value. 0.3.5
    // ignored anything else, so `--mni 2` silently meant `--min 1`.
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--directory" | "--out" | "--state" | "--min" => i += 2,
            other => {
                return usage_err(&format!(
                    "witness submit: unexpected argument {other:?} \
                     (flags: --directory, --out, --state, --min)"
                ))
            }
        }
    }
    let Some(dir_path) = flag(args, "--directory") else {
        return usage_err("witness submit: --directory <witnesses.json> is required");
    };
    let out_path = flag(args, "--out").unwrap_or_else(|| "dossier.json".into());
    let state_path = flag(args, "--state").unwrap_or_else(|| format!("{journal}.witnesses.json"));
    let min: usize = match flag(args, "--min").map(|v| v.parse()) {
        None => 1,
        Some(Ok(n)) => n,
        Some(Err(_)) => return usage_err("--min: expected an integer"),
    };

    let (log, report) = match witness_log_core::journal::LeafJournal::replay(journal) {
        Ok(x) => x,
        Err(e) => {
            eprintln!("{journal}: {e}");
            return ExitCode::from(2);
        }
    };
    if report.dropped_trailing_lines > 0 {
        eprintln!(
            "note: {journal} has a partially written last line (agent mid-write?); \
             submitting the {} complete leaves",
            log.tree_size()
        );
    }
    let directory: WitnessDirectory = match crate::read_input(&dir_path)
        .map_err(|e| e.to_string())
        .and_then(|s| crate::parse_directory(&s))
    {
        Ok(d) => d,
        Err(e) => {
            eprintln!("{dir_path}: {e}");
            return ExitCode::from(2);
        }
    };
    let mut state: ClientState = fs::read_to_string(&state_path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default();

    let key = SigningKey::from_bytes(&log.identity_bytes());
    let origin = canonical_origin(&key.verifying_key());
    let checkpoint = log.c2sp_checkpoint(&origin);

    // Safety guard: never publish a history that contradicts one witnesses
    // already cosigned for this identity (e.g. a journal restored from an
    // old backup and then appended to). Witnesses would refuse it, and a
    // same-size conflict is recorded as proof that this identity
    // equivocated -- permanently.
    if state.cosigned_size > 0 {
        let prior_root: Option<[u8; 32]> = hex::decode(&state.cosigned_root)
            .ok()
            .and_then(|b| b.try_into().ok());
        let consistent = match prior_root {
            None => false,
            Some(_) if checkpoint.tree_size < state.cosigned_size => false,
            Some(r) => log
                .consistency_proof(state.cosigned_size)
                .map(|p| {
                    witness_log_core::merkle::verify_consistency(
                        state.cosigned_size,
                        &r,
                        checkpoint.tree_size,
                        &checkpoint.root_hash,
                        &p,
                    )
                })
                .unwrap_or(false),
        };
        if !consistent {
            eprintln!(
                "REFUSING TO SUBMIT: witnesses already cosigned size {} for this identity, and \
                 {journal} (size {}) does not extend it. Submitting would get this identity \
                 recorded as equivocating. Restore the journal that was witnessed. \
                 (State: {state_path})",
                state.cosigned_size, checkpoint.tree_size
            );
            return ExitCode::from(1);
        }
    }
    let note = match checkpoint.sign(&key) {
        Ok(n) => n,
        Err(e) => {
            eprintln!("could not sign checkpoint: {e}");
            return ExitCode::from(1);
        }
    };
    let native = log.checkpoint(&key);
    // WitnessLog is Send but not Sync; proofs are cheap, so share it
    // behind a mutex rather than precomputing every possible proof.
    let log = Arc::new(Mutex::new(log));

    // Ask every witness in parallel.
    let handles: Vec<_> = directory
        .witnesses
        .iter()
        .map(|w| {
            let w = w.clone();
            let log = log.clone();
            let checkpoint = checkpoint.clone();
            let note = note.clone();
            let native = native.clone();
            let known = state
                .sizes
                .get(&w.pubkey.to_ascii_lowercase())
                .copied()
                .unwrap_or(0);
            std::thread::spawn(move || Outcome {
                name: w.name.clone(),
                result: submit_one(&w, &log, &checkpoint, &note, &native, known),
            })
        })
        .collect();

    let mut receipts = Vec::new();
    for h in handles {
        let Ok(o) = h.join() else { continue };
        match o.result {
            Ok((receipt, size)) => {
                eprintln!("  ✓ {:<32} cosigned size {size}", o.name);
                state
                    .sizes
                    .insert(receipt.witness_pubkey.to_ascii_lowercase(), size);
                receipts.push(receipt);
            }
            Err(e) => eprintln!("  ✗ {:<32} {e}", o.name),
        }
    }
    if !receipts.is_empty() && checkpoint.tree_size >= state.cosigned_size {
        state.cosigned_size = checkpoint.tree_size;
        state.cosigned_root = hex::encode(checkpoint.root_hash);
    }
    if let Ok(json) = serde_json::to_vec_pretty(&state) {
        if let Err(e) = atomic_write(Path::new(&state_path), &json) {
            eprintln!("warning: could not save {state_path}: {e}");
        }
    }

    let n = receipts.len();
    let log = log.lock().unwrap_or_else(|e| e.into_inner());
    let mut dossier = Dossier::from_log(&log, native).with_receipts(receipts);
    dossier.witness_directory = directory;
    let json = match serde_json::to_vec_pretty(&dossier) {
        Ok(j) => j,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(1);
        }
    };
    if let Err(e) = atomic_write(Path::new(&out_path), &json) {
        eprintln!("{out_path}: {e}");
        return ExitCode::from(1);
    }
    eprintln!(
        "{n}/{} witnesses cosigned size {} for {origin}\nwrote {out_path}. Verify with:\n  witness-log verify {out_path} --identity {} --directory <directory YOU trust>",
        dossier.witness_directory.witnesses.len(),
        dossier.checkpoint.tree_size,
        dossier.identity_pubkey
    );
    if n >= min {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    }
}

/// Submit to one witness, following at most two 409 corrections.
fn submit_one(
    w: &WitnessEntry,
    log: &Mutex<witness_log_core::log::WitnessLog>,
    checkpoint: &Checkpoint,
    note: &witness_log_core::c2sp::SignedNote,
    native: &witness_log_core::sth::SignedTreeHead,
    known: u64,
) -> Result<(WitnessReceipt, u64), String> {
    let url = http::parse_url(&w.url)?;
    let size = checkpoint.tree_size;
    let wpk: [u8; 32] = hex::decode(w.pubkey.trim())
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or("directory entry has a malformed pubkey")?;
    let wvk = ed25519_dalek::VerifyingKey::from_bytes(&wpk)
        .map_err(|_| "directory entry pubkey is not a valid key")?;
    let mut old = if known > size { 0 } else { known };
    for _ in 0..5 {
        let proof = if old == 0 || old == size {
            vec![]
        } else {
            log.lock()
                .unwrap_or_else(|e| e.into_inner())
                .consistency_proof(old)
                .ok_or_else(|| format!("cannot prove consistency from size {old}"))?
        };
        let body = AddCheckpointRequest {
            old_size: old,
            consistency_proof: proof,
            checkpoint_note: note.clone(),
        }
        .to_http_body()
        .map_err(|e| e.to_string())?;
        let (status, resp, retry_after) = http::request(
            &url,
            "POST",
            "/add-checkpoint",
            body.as_bytes(),
            Duration::from_secs(10),
        )?;
        let text = String::from_utf8_lossy(&resp).to_string();
        match status {
            200 => {
                // Accept only a cosignature from THIS directory entry's key,
                // over THIS checkpoint. A green status code proves nothing.
                for line in text.lines().filter(|l| !l.is_empty()) {
                    let Ok(sig) = NoteSignature::parse(line) else {
                        continue;
                    };
                    let Ok(cos) = Cosignature::from_note_signature(&sig) else {
                        continue;
                    };
                    let vkey = VerifierKey::for_cosignature(&sig.key_name, &wvk);
                    if let Some(c) = cosignature_to_receipt(&cos, &vkey, checkpoint, native) {
                        return Ok((c.receipt, size));
                    }
                }
                return Err("HTTP 200 but no valid cosignature from the expected key".into());
            }
            409 => {
                let theirs: u64 = text
                    .trim()
                    .parse()
                    .map_err(|_| format!("HTTP 409 with unparseable size {:?}", text.trim()))?;
                if theirs > size {
                    return Err(format!(
                        "witness already cosigned size {theirs} but this journal has only {size} \
                         leaves -- truncated journal, or this log was forked"
                    ));
                }
                old = theirs;
            }
            // Enrollment rate limit or a busy witness: honour Retry-After
            // (the server's windows are at most a minute). Found by the
            // 1,000-agent swarm: fleets of agents behind one address hit
            // the per-address enrollment limit together.
            429 | 503 if retry_after.is_some_and(|s| s <= 60) => {
                std::thread::sleep(Duration::from_secs(retry_after.unwrap_or(1)));
            }
            422 => {
                return Err(format!(
                    "REFUSED (422): not consistent with what this witness already cosigned for \
                     this identity -- a forked history or a corrupted journal. {}",
                    text.trim()
                ))
            }
            other => return Err(format!("HTTP {other}: {}", text.trim())),
        }
    }
    Err("no cosignature after 5 attempts (size changes or rate limiting)".into())
}

#[cfg(test)]
mod lock_tests {
    use super::*;

    /// `docker kill` then `docker start`: the witness is pid 1 both times,
    /// so the lock left behind names the new process's own pid. Before
    /// 0.3.6 `process_alive` saw itself and the witness refused to start
    /// forever (found by the operator-kit work).
    #[test]
    fn a_lock_naming_our_own_pid_is_stale() {
        let dir = std::env::temp_dir().join(format!(
            "wl-lock-own-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&dir).unwrap();
        fs::write(
            dir.join("witness.lock"),
            format!("{}\n", std::process::id()),
        )
        .unwrap();
        let lock = acquire_lock(&dir).expect("a lock naming our own pid must be taken over");
        assert!(lock.still_ours());
        drop(lock);
        assert!(!dir.join("witness.lock").exists());
        let _ = fs::remove_dir_all(&dir);
    }
}
