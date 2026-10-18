//! `witness-log witness ...` -- run a `c2sp.org/tlog-witness` witness, and
//! submit an agent's checkpoints to witnesses to get a WITNESSED dossier.
//!
//! Safety properties the server enforces, in priority order:
//!
//! 1. **Persist before cosigning.** A log's new size/root is written and
//!    fsynced (atomic rename, then directory fsync) BEFORE the cosignature
//!    leaves the process. The decision is made on a copy of the record;
//!    if persisting fails, the cached copy is dropped (the file stays the
//!    authority) and the client gets a 500, never a cosignature. A
//!    witness that cosigns, crashes and restarts with older state can be
//!    walked onto a fork -- this is the one bug a witness must not have.
//! 2. **One process per state directory.** A lock file stops two
//!    witnesses sharing state (each would hold its own in-memory view
//!    and could cosign two forks between them).
//! 3. **Serialized decisions.** All add-checkpoint handling runs under one
//!    mutex, so reading a log's record, the size check and the persist are
//!    atomic (spec: "to prevent a rollback race").
//! 4. **Bounded everything.** See `http.rs` for request limits; open
//!    enrollment is capped in total logs and per-client rate. Records are
//!    read on demand with a bounded cache (`witness_store.rs`), so startup
//!    time and memory do not grow with the number of logs witnessed.
//!
//! State layout (`<dir>`):
//!   witness.key    32-byte Ed25519 seed, hex, mode 0600
//!   witness.json   key name, operator org, public URL, compute provider
//!   logs/<sha256(origin)>.json   one record per witnessed log, read when a
//!                  request for that origin arrives
//!   evidence/<sha256(origin)>.json  proven equivocation (two log-signed
//!                  roots for one size) -- self-contained, publishable
//!   witness.lock   held while serving

use crate::http::{self, Request, Response};
use crate::witness_store::{persist_record, record_path, LogStore, DEFAULT_CACHE_CAPACITY};
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
    cosignature_to_receipt, AddCheckpointOutcome, AddCheckpointRequest, KnownLog,
};
use witness_log_network::{Dossier, WitnessDirectory, WitnessEntry, WitnessReceipt};

const USAGE: &str = "usage:
  witness-log witness init <dir> --name <key-name> [--org <operator>] [--url <public-url>] [--compute <provider>] [--json]
      --json  print one JSON object (identity hex, c2sp vkey, org, data dir) and nothing else on stdout
  witness-log witness serve <dir> [--listen 127.0.0.1:7380] [--open-enrollment]
                                  [--max-logs 100000] [--max-conns 256] [--max-conns-per-ip 16]
                                  [--enroll-rate 600]
      Behind a reverse proxy every client shares the proxy's address:
      raise --max-conns-per-ip and --enroll-rate to match.
  witness-log witness add-log <dir> <origin> <log-vkey>
  witness-log witness info <http://witness-url>
  witness-log witness submit <journal> --directory <witnesses.json> [--out dossier.json]
                                  [--state <client-state.json>] [--min <n>] [--allow-partial]
                                  [--identity-seed-env NAME | --identity-seed-file F]
      Fail-closed: --min defaults to max(2, N/2+1) for a directory of N witnesses, and
      any witness answering 422 (your history contradicts what it cosigned) makes the
      exit status 20. --allow-partial instead verifies the dossier it wrote against the
      directory and exits by verdict (0 WITNESSED, 10 CONSISTENT-UNWITNESSED, ...).
      A sealed journal needs its seed: --identity-seed-env NAME or --identity-seed-file F.
  witness-log witness submit <journal> --fleet <url> [--fleet-wait SECS] [--directory ...] [--out ...]
      EXPERIMENTAL (RFC-0001): append the checkpoint to an organisation's fleet log
      and add a fleet_anchor to the dossier; --directory is then optional. See
      `witness-log fleet --help`.
  witness-log witness verify-evidence <evidence.json> [--vkey <log vkey>]
      Check an equivocation proof a witness recorded under evidence/:
      exit 0 if it proves two signed roots for one size, 40 if not, 2 unreadable.";

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
    // Accept the file as `serve` writes it ({"proof": {...}}) or a bare
    // proof, by the same rule as `verify --evidence`.
    let proof = match crate::read_evidence(path) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("{path}: {e}");
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
    // The key the notes are checked under is never the one inside the
    // file: a canonical origin names its own key; any other origin needs
    // `--vkey` from the log's directory entry (review round 2, W1).
    let supplied = flag(args, "--vkey");
    let proven = match &supplied {
        Some(v) => match witness_log_core::c2sp::VerifierKey::parse(v) {
            Ok(k) => proof.verify_with_key(&k),
            Err(e) => {
                eprintln!("--vkey: {e}");
                return ExitCode::from(2);
            }
        },
        None => proof.verify(),
    };
    if proven {
        println!("PROVEN: both notes are signed by the log's key (taken from its canonical origin or --vkey, not from this file), name the same origin and size, and commit different roots. This identity showed two histories.");
        ExitCode::SUCCESS
    } else if supplied.is_none()
        && witness_log_core::c2sp::identity_from_canonical_origin(&proof.origin).is_none()
    {
        println!("NOT PROVEN: the origin is not canonical, so the log's key cannot be taken from it; pass --vkey <the log's key as you know it>. The key inside the file is not trusted.");
        ExitCode::from(crate::exit::INVALID)
    } else {
        println!("NOT PROVEN: the notes do not both verify under the log's key with one origin, one size and two roots. This file is not evidence of equivocation.");
        ExitCode::from(crate::exit::INVALID)
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
/// rename, fsync the directory. Mode 0600 on Unix: for keys, state and
/// anything else only this user should read.
pub(crate) fn atomic_write(path: &Path, data: &[u8]) -> std::io::Result<()> {
    atomic_write_mode(path, data, 0o600)
}

/// `atomic_write` for files meant to be handed on: dossiers, directories,
/// notes. Mode 0644 on Unix. Until 0.3.6 dossiers were written 0600, so a
/// dossier produced under one account could not be read by the service
/// account or CI step meant to verify it.
pub(crate) fn atomic_write_shared(path: &Path, data: &[u8]) -> std::io::Result<()> {
    atomic_write_mode(path, data, 0o644)
}

fn atomic_write_mode(path: &Path, data: &[u8], mode: u32) -> std::io::Result<()> {
    #[cfg(not(unix))]
    let _ = mode;
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
            opts.mode(mode);
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
    let vkey = VerifierKey::for_cosignature(&cfg.key_name, &key.verifying_key()).encode();
    if args.iter().any(|a| a == "--json") {
        // One object, nothing else on stdout: a script reads it with one
        // JSON parse. `entry` is the directory entry other tools accept.
        let doc = serde_json::json!({
            "identity": hex::encode(key.verifying_key().to_bytes()),
            "vkey": vkey,
            "org": cfg.operator_org,
            "name": cfg.key_name,
            "url": cfg.public_url,
            "data_dir": dir.display().to_string(),
            "entry": entry,
        });
        println!("{}", serde_json::to_string(&doc).unwrap_or_default());
        return ExitCode::SUCCESS;
    }
    println!(
        "{}",
        serde_json::to_string_pretty(&entry).unwrap_or_default()
    );
    eprintln!(
        "\nwitness initialised in {}\n  vkey: {vkey}\n  The JSON above is this witness's directory entry. Publish it;\n  verifiers add it to the directory they trust.",
        dir.display(),
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
    let k = KnownLog::new(origin, vk);
    if !dir.join("witness.key").exists() {
        return usage_err("witness add-log: <dir> is not an initialised witness");
    }
    match persist_record(&dir, &k) {
        Ok(()) => {
            // `serve` reads records on demand, so a running witness picks
            // this up on the first request for the origin. Its `GET /` log
            // count includes it from the next start.
            eprintln!(
                "added {origin}; a running witness reads it on the next request for this log"
            );
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("{e}");
            ExitCode::from(1)
        }
    }
}

// ----------------------------------------------------------------- serve

pub(crate) struct Lock(PathBuf);
impl Lock {
    /// True while the lock file still names this process. Checked before
    /// every cosignature: if a racing process removed and replaced our
    /// lock (two restarts after a crash), we find out before signing
    /// anything, not after two witnesses diverged.
    pub(crate) fn still_ours(&self) -> bool {
        fs::read_to_string(&self.0)
            .map(|s| s.trim() == std::process::id().to_string())
            .unwrap_or(false)
    }
}
impl Lock {
    /// Remove the lock file if it is still ours. Idempotent.
    pub(crate) fn release(&self) {
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
    on_stop_signal(move |sig| {
        let s = server.lock().unwrap_or_else(|e| e.into_inner());
        eprintln!(
            "witness stopping on signal {sig}: {} cosigned since start",
            s.cosigned
        );
        s.lock.release();
    });
}

/// Run `stop` on the first SIGTERM/SIGINT, then exit 0. Call before
/// spawning any thread that should not receive the signals (see
/// `stop_cleanly_on_signal`).
#[cfg(unix)]
pub(crate) fn on_stop_signal(stop: impl FnOnce(i32) + Send + 'static) {
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
                stop(sig);
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
    acquire_lock_at(
        &dir.join("witness.lock"),
        "witness",
        "Two witnesses on one state directory could cosign two forks.",
    )
}

/// Take the lock file `p` for this process. `what` names the process kind
/// ("witness") and `why` says what two holders could do, for the messages.
pub(crate) fn acquire_lock_at(p: &Path, what: &str, why: &str) -> Result<Lock, String> {
    let p = p.to_path_buf();
    let file_name = p
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    for _ in 0..2 {
        match fs::OpenOptions::new().write(true).create_new(true).open(&p) {
            Ok(mut f) => {
                let _ = writeln!(f, "{}", std::process::id());
                let _ = f.sync_all();
                let lock = Lock(p.clone());
                // Two processes restarting over the same stale lock can
                // both "take it over" within microseconds. Settle, then
                // confirm we still hold it, BEFORE loading state or serving:
                // the loser exits having signed nothing.
                std::thread::sleep(Duration::from_millis(250));
                if !lock.still_ours() {
                    std::mem::forget(lock);
                    return Err(format!(
                        "{}: lost a race for the lock to another {what} process",
                        p.display()
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
                                "removing stale {file_name} naming pid {pid}, this process's own pid \
                                 (left by an earlier run with the same pid, e.g. pid 1 in a container)"
                            );
                        } else {
                            eprintln!(
                                "removing stale {file_name} left by pid {pid}, which is no longer running"
                            );
                        }
                        let _ = fs::remove_file(&p);
                    }
                    continue;
                }
                return Err(format!(
                    "{} is held by pid {pid}. {why} If that process is gone, delete the lock file.",
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
    refused_unproven: u64,
    dir: PathBuf,
    cfg: WitnessConfig,
    key: SigningKey,
    /// Per-log records, read on demand (bounded cache, never a full scan).
    logs: LogStore,
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
    // Lists logs/ by name only. Records are read when a request for their
    // origin arrives; an unreadable one fails that request closed.
    let logs = match LogStore::open(&dir, DEFAULT_CACHE_CAPACITY) {
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
        logs.count(),
        if args.iter().any(|a| a == "--open-enrollment") {
            "on"
        } else {
            "off"
        }
    );
    let server = Arc::new(Mutex::new(Server {
        lock,
        refused_unproven: 0,
        dir,
        cfg,
        key,
        logs,
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
        "logs": s.logs.count(),
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
    // What this witness already cosigned for the origin: its record file,
    // read now unless it is cached. A record that exists but cannot be
    // read or trusted is NOT an unknown log -- enrolling it afresh at size
    // 0 would cosign a fork -- so the request is refused until the
    // operator restores the file.
    let held = match s.logs.get(&origin) {
        Ok(held) => held,
        Err(e) => {
            eprintln!(
                "refusing {origin}: unreadable record ({e}). Not cosigning for this log until \
                 the file is restored; do not delete it (the log would be enrolled afresh at \
                 size 0)."
            );
            return Response::text(
                500,
                "witness state for this log is unreadable; not cosigning\n",
            );
        }
    };
    let (mut record, newly_enrolled) = match held {
        Some(k) => (k, false),
        None => {
            let unknown = AddCheckpointOutcome::UnknownLog {
                origin: origin.clone(),
            };
            if !s.open_enrollment {
                let (text, ctype) = unknown.http_body();
                return Response::typed(unknown.http_status(), ctype, text);
            }
            if s.logs.count() >= s.max_logs {
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
            let enrolled = KnownLog::from_canonical_request(&request);
            if enrolled.is_some() {
                slot.1 += 1;
            }
            // Keep the rate table bounded.
            if s.enroll_rate.len() > 10_000 {
                s.enroll_rate
                    .retain(|_, (t, _)| now.duration_since(*t) <= Duration::from_secs(60));
            }
            match enrolled {
                Some(k) => (k, true),
                // The origin names its own key, so this witness DOES know
                // which key must have signed: a failure here is a bad
                // signature (403), not an unknown log (404).
                None if witness_log_core::c2sp::identity_from_canonical_origin(&origin)
                    .is_some() =>
                {
                    return Response::text(403, "checkpoint signature not verified\n");
                }
                None => {
                    let (text, ctype) = unknown.http_body();
                    return Response::typed(unknown.http_status(), ctype, text);
                }
            }
        }
    };

    // `record` is a copy: the store changes only once the advanced record
    // is on disk, so a refusal or a failed persist leaves nothing to undo.
    // A log enrolled by this request therefore exists only once its first
    // cosignature is persisted; every other outcome -- including a 422 on
    // first contact, which the final review found left a phantom log
    // counting toward --max-logs -- leaves no trace. (A first-contact
    // request can never be provable equivocation: the witness holds
    // nothing to contradict.)
    let outcome = record.handle_add_checkpoint(&request, &s.cfg.key_name, &s.key, now_s());

    match &outcome {
        AddCheckpointOutcome::Cosigned { .. } => {
            if let Err(e) = s.logs.put(record, newly_enrolled) {
                // DO NOT release the cosignature.
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
            record_evidence(&s.dir, proof);
        }
        AddCheckpointOutcome::ConsistencyFailed { .. } => {
            // Refused, but a failing proof is not proof of a fork: anyone
            // can attach a junk proof to an honest log's checkpoint.
            s.refused_unproven += 1;
        }
        _ => {}
    }
    let (text, ctype) = outcome.http_body();
    Response::typed(outcome.http_status(), ctype, text)
}

/// Write a proven equivocation to `evidence/<sha256(origin)>.json`. One
/// file per log, first proof wins: one proof is all anyone needs, storage
/// is bounded by `--max-logs` (each proof is a few KiB since checkpoint
/// bodies are capped), and no log's evidence can crowd out another's. The
/// file's existence is the record that a log's proof is already kept, so
/// nothing about it is held in memory.
pub(crate) fn record_evidence(
    dir: &Path,
    proof: &witness_log_network::tlog_witness::EquivocationProof,
) {
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
    result: Result<(WitnessReceipt, u64), SubmitError>,
}

/// Why one witness did not cosign.
#[derive(Debug, Clone)]
pub(crate) enum SubmitError {
    /// HTTP 422: the witness holds a cosigned head this history does not
    /// extend. Either a fork or a corrupted journal; never safe to ignore.
    Refused(String),
    Other(String),
}

impl std::fmt::Display for SubmitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Refused(t) => write!(
                f,
                "REFUSED (422): not consistent with what this witness already cosigned for \
                 this identity -- a forked history or a corrupted journal. {t}"
            ),
            Self::Other(t) => f.write_str(t),
        }
    }
}

impl From<String> for SubmitError {
    fn from(s: String) -> Self {
        Self::Other(s)
    }
}

/// The default `--min`: a strict majority of the directory, and never
/// fewer than the two independent operators WITNESSED needs. A directory
/// of one witness therefore cannot pass without an explicit `--min 1`.
pub(crate) fn default_min(directory_size: usize) -> usize {
    (directory_size / 2 + 1).max(2)
}

/// What one submission round produced.
pub(crate) struct SubmitReport {
    pub dossier: Dossier,
    pub cosigned: usize,
    pub refused_422: usize,
    /// One line per witness, as printed to stderr: `✓ name cosigned size N`
    /// or `✗ name <reason>`.
    pub lines: Vec<String>,
    pub origin: String,
}

/// Submit `log`'s head to `contact` (a subset of `directory`, or all of
/// it), persist client state to `state_path`, and return the dossier.
/// Shared by `witness submit` and `journal serve`'s POST /submit.
///
/// `Err` is a problem with the inputs or a refusal to proceed (the
/// journal contradicts a head witnesses already cosigned); a witness that
/// declined is reported in the `SubmitReport`, not as `Err`.
pub(crate) fn submit_log(
    log: &witness_log_core::log::WitnessLog,
    directory: &WitnessDirectory,
    contact: &[WitnessEntry],
    state_path: &str,
) -> Result<SubmitReport, String> {
    let mut state: ClientState = fs::read_to_string(state_path)
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
            return Err(format!(
                "REFUSING TO SUBMIT: witnesses already cosigned size {} for this identity, and \
                 this journal (size {}) does not extend it. Submitting would get this identity \
                 recorded as equivocating. Restore the journal that was witnessed. \
                 (State: {state_path})",
                state.cosigned_size, checkpoint.tree_size
            ));
        }
    }
    let note = checkpoint
        .sign(&key)
        .map_err(|e| format!("could not sign checkpoint: {e}"))?;
    let native = log.checkpoint(&key);
    // Each worker needs consistency proofs for whatever `old` size its
    // witness reports. The leaf hashes are enough for that, and a
    // MerkleTree is Sync, so rebuild one and share it rather than locking
    // the log (which `journal serve` holds under its own mutex).
    let mut tree = witness_log_core::merkle::MerkleTree::new();
    for l in log.leaves() {
        tree.append(witness_log_core::merkle::leaf_hash(&l.canonical_bytes()));
    }
    let tree = Arc::new(tree);

    // Ask every witness in parallel.
    let handles: Vec<_> = contact
        .iter()
        .map(|w| {
            let w = w.clone();
            let tree = tree.clone();
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
                result: submit_one(&w, &tree, &checkpoint, &note, &native, known),
            })
        })
        .collect();

    let mut receipts = Vec::new();
    let mut lines = Vec::new();
    let mut refused_422 = 0usize;
    for h in handles {
        let Ok(o) = h.join() else { continue };
        match o.result {
            Ok((receipt, size)) => {
                lines.push(format!("  ✓ {:<32} cosigned size {size}", o.name));
                state
                    .sizes
                    .insert(receipt.witness_pubkey.to_ascii_lowercase(), size);
                receipts.push(receipt.with_witness_name(o.name));
            }
            Err(e) => {
                if matches!(e, SubmitError::Refused(_)) {
                    refused_422 += 1;
                }
                lines.push(format!("  ✗ {:<32} {e}", o.name));
            }
        }
    }
    if !receipts.is_empty() && checkpoint.tree_size >= state.cosigned_size {
        state.cosigned_size = checkpoint.tree_size;
        state.cosigned_root = hex::encode(checkpoint.root_hash);
    }
    if let Ok(json) = serde_json::to_vec_pretty(&state) {
        if let Err(e) = atomic_write(Path::new(state_path), &json) {
            lines.push(format!("warning: could not save {state_path}: {e}"));
        }
    }

    let cosigned = receipts.len();
    let mut dossier = Dossier::from_log(log, native).with_receipts(receipts);
    dossier.witness_directory = directory.clone();
    Ok(SubmitReport {
        dossier,
        cosigned,
        refused_422,
        lines,
        origin,
    })
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
            "--directory"
            | "--out"
            | "--state"
            | "--min"
            | "--identity-seed-env"
            | "--identity-seed-file"
            | "--fleet"
            | "--fleet-wait" => i += 2,
            "--allow-partial" => i += 1,
            other => {
                return usage_err(&format!(
                    "witness submit: unexpected argument {other:?} \
                     (flags: --directory, --out, --state, --min, --allow-partial, \
                     --identity-seed-env, --identity-seed-file, --fleet, --fleet-wait)"
                ))
            }
        }
    }
    // RFC-0001 (experimental): append to a fleet log, with or without the
    // direct path. Without --fleet nothing below changes.
    if args.iter().any(|a| a == "--fleet") {
        if args.iter().any(|a| a == "--allow-partial") {
            return usage_err("witness submit: --allow-partial is not supported with --fleet");
        }
        return crate::fleet_cmd::cmd_submit_fleet(journal, args);
    }
    if args.iter().any(|a| a == "--fleet-wait") {
        return usage_err("witness submit: --fleet-wait needs --fleet <url>");
    }
    let Some(dir_path) = flag(args, "--directory") else {
        return usage_err("witness submit: --directory <witnesses.json> is required");
    };
    let out_path = flag(args, "--out").unwrap_or_else(|| "dossier.json".into());
    let state_path = flag(args, "--state").unwrap_or_else(|| format!("{journal}.witnesses.json"));
    let allow_partial = args.iter().any(|a| a == "--allow-partial");
    let seed = match crate::identity_seed_from_args(args) {
        Ok(s) => s,
        Err(e) => return usage_err(&e),
    };

    let (log, report) = match crate::replay_journal(journal, seed.as_deref()) {
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
    let n_dir = directory.witnesses.len();
    let min: usize = match flag(args, "--min").map(|v| v.parse()) {
        None => default_min(n_dir),
        Some(Ok(n)) => n,
        Some(Err(_)) => return usage_err("--min: expected an integer"),
    };
    if min > n_dir {
        eprintln!(
            "note: --min {min} cannot be met by a directory of {n_dir} witness{} \
             (the default is max(2, N/2+1); pass --min explicitly to lower it)",
            if n_dir == 1 { "" } else { "es" }
        );
    }

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
    let json = match serde_json::to_vec_pretty(&result.dossier) {
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
    let n = result.cosigned;
    eprintln!(
        "{n}/{} witnesses cosigned size {} for {}\nwrote {out_path}. Verify with:\n  witness-log verify {out_path} --identity {} --directory <directory YOU trust>",
        n_dir,
        result.dossier.checkpoint.tree_size,
        result.origin,
        result.dossier.identity_pubkey
    );
    // The verdict this dossier reaches against the directory it was
    // submitted to, with the count gate at --min. Printed either way;
    // with --allow-partial it is also the exit status.
    let ctx = witness_log_network::VerifyContext {
        expected_identity_pubkey: Some(&result.dossier.identity_pubkey),
        trusted_directory: Some(&directory),
        min_receipts: Some(min),
        revocations: &[],
        known_heads: &[],
        evidence: &[],
        subject_org: None,
        accept_fleet_anchor: false,
    };
    let verdict = result
        .dossier
        .verify(crate::DEFAULT_QUORUM_THRESHOLD, &ctx)
        .verdict;
    eprintln!("verdict against {dir_path} with --min {min}: {verdict}");
    if allow_partial {
        return crate::exit_code_for(&verdict);
    }
    if result.refused_422 > 0 {
        eprintln!(
            "{} witness{} REFUSED this history (422). Nothing about this is partial: a \
             refusal means the journal does not extend a head that witness already cosigned. \
             Exit 20. (--allow-partial exits by verdict instead.)",
            result.refused_422,
            if result.refused_422 == 1 { "" } else { "es" }
        );
        return ExitCode::from(crate::exit::SUBMIT_REFUSED);
    }
    if n < min {
        eprintln!(
            "{n} cosignature{} is below --min {min}; exit 20. (--allow-partial exits by verdict instead.)",
            if n == 1 { "" } else { "s" }
        );
        return ExitCode::from(crate::exit::SUBMIT_REFUSED);
    }
    ExitCode::SUCCESS
}

/// Submit to one witness, following at most two 409 corrections.
fn submit_one(
    w: &WitnessEntry,
    tree: &witness_log_core::merkle::MerkleTree,
    checkpoint: &Checkpoint,
    note: &witness_log_core::c2sp::SignedNote,
    native: &witness_log_core::sth::SignedTreeHead,
    known: u64,
) -> Result<(WitnessReceipt, u64), SubmitError> {
    let (cos, vkey) = cosign_one(w, tree, checkpoint, note, known, "journal")?;
    match cosignature_to_receipt(&cos, &vkey, checkpoint, native) {
        Some(c) => Ok((c.receipt, checkpoint.tree_size)),
        None => Err("HTTP 200 but no valid cosignature from the expected key"
            .to_string()
            .into()),
    }
}

/// Ask one witness to cosign `checkpoint` (signed as `note`) and return its
/// cosignature with the verifier key it verified under: only a cosignature
/// from THIS directory entry's key, over THIS checkpoint, is accepted. A
/// green status code proves nothing. Used for an agent's own checkpoint
/// (`submit`) and a fleet log's (`fleet witness`); `history` names what
/// `tree` is in error messages ("journal", "fleet log").
pub(crate) fn cosign_one(
    w: &WitnessEntry,
    tree: &witness_log_core::merkle::MerkleTree,
    checkpoint: &Checkpoint,
    note: &witness_log_core::c2sp::SignedNote,
    known: u64,
    history: &str,
) -> Result<(Cosignature, VerifierKey), SubmitError> {
    let url = http::parse_url(&w.url)?;
    let wpk: [u8; 32] = hex::decode(w.pubkey.trim())
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| "directory entry has a malformed pubkey".to_string())?;
    let wvk = ed25519_dalek::VerifyingKey::from_bytes(&wpk)
        .map_err(|_| "directory entry pubkey is not a valid key".to_string())?;
    let text = post_add_checkpoint(
        &url,
        "/add-checkpoint",
        tree,
        note,
        checkpoint.tree_size,
        known,
        "witness already cosigned",
        history,
    )?;
    for line in text.lines().filter(|l| !l.is_empty()) {
        let Ok(sig) = NoteSignature::parse(line) else {
            continue;
        };
        let Ok(cos) = Cosignature::from_note_signature(&sig) else {
            continue;
        };
        let vkey = VerifierKey::for_cosignature(&sig.key_name, &wvk);
        if witness_log_network::tlog_witness::verify_cosignature_response(&cos, &vkey, checkpoint) {
            return Ok((cos, vkey));
        }
    }
    Err("HTTP 200 but no valid cosignature from the expected key"
        .to_string()
        .into())
}

/// The `c2sp.org/tlog-witness` exchange: POST an add-checkpoint body for
/// `note` (a checkpoint of `tree` at `size`) to `path`, starting from
/// `known` as the old size and following the server's 409 corrections and
/// Retry-After, at most five attempts. Returns the 200 body. A 422 is
/// [`SubmitError::Refused`]. `held` and `history` word the error when the
/// server holds more than `tree` has ("witness already cosigned",
/// "journal").
#[allow(clippy::too_many_arguments)]
pub(crate) fn post_add_checkpoint(
    url: &http::Url,
    path: &str,
    tree: &witness_log_core::merkle::MerkleTree,
    note: &witness_log_core::c2sp::SignedNote,
    size: u64,
    known: u64,
    held: &str,
    history: &str,
) -> Result<String, SubmitError> {
    let mut old = if known > size { 0 } else { known };
    for _ in 0..5 {
        let proof = if old == 0 || old == size {
            vec![]
        } else {
            tree.consistency_proof(old, size)
                .ok_or_else(|| format!("cannot prove consistency from size {old}"))?
        };
        let body = AddCheckpointRequest {
            old_size: old,
            consistency_proof: proof,
            checkpoint_note: note.clone(),
        }
        .to_http_body()
        .map_err(|e| e.to_string())?;
        let (status, resp, retry_after) =
            http::request(url, "POST", path, body.as_bytes(), Duration::from_secs(10))?;
        let text = String::from_utf8_lossy(&resp).to_string();
        match status {
            200 => return Ok(text),
            409 => {
                let theirs: u64 = text
                    .trim()
                    .parse()
                    .map_err(|_| format!("HTTP 409 with unparseable size {:?}", text.trim()))?;
                if theirs > size {
                    return Err(format!(
                        "{held} size {theirs} but this {history} has only {size} \
                         leaves -- truncated {history}, or this log was forked"
                    )
                    .into());
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
            422 => return Err(SubmitError::Refused(text.trim().to_string())),
            other => return Err(format!("HTTP {other}: {}", text.trim()).into()),
        }
    }
    Err(
        "no cosignature after 5 attempts (size changes or rate limiting)"
            .to_string()
            .into(),
    )
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

/// The request path of `serve`, in process: records read on demand, a
/// bounded cache, and the one mutex that makes each decision atomic.
#[cfg(test)]
mod serve_tests {
    use super::*;
    use witness_log_core::merkle::{leaf_hash, MerkleTree};
    use witness_log_network::tlog_witness::EquivocationProof;

    /// A log identity and the leaves of one history it signs.
    struct TestLog {
        key: SigningKey,
        leaves: Vec<String>,
    }

    impl TestLog {
        fn new(seed: u8, leaves: &[&str]) -> Self {
            Self {
                key: SigningKey::from_bytes(&[seed; 32]),
                leaves: leaves.iter().map(|l| l.to_string()).collect(),
            }
        }
        fn origin(&self) -> String {
            canonical_origin(&self.key.verifying_key())
        }
        fn tree(&self) -> MerkleTree {
            let mut t = MerkleTree::new();
            for l in &self.leaves {
                t.append(leaf_hash(l.as_bytes()));
            }
            t
        }
        /// The add-checkpoint body for this history's head, from `old`.
        fn body(&self, old: u64) -> Vec<u8> {
            let t = self.tree();
            let size = t.size();
            let proof = if old == 0 || old == size {
                vec![]
            } else {
                t.consistency_proof(old, size).unwrap()
            };
            self.request(old, proof)
        }
        fn request(&self, old: u64, proof: Vec<[u8; 32]>) -> Vec<u8> {
            let t = self.tree();
            let cp = Checkpoint {
                origin: self.origin(),
                tree_size: t.size(),
                root_hash: t.root(),
                extensions: vec![],
            };
            AddCheckpointRequest {
                old_size: old,
                consistency_proof: proof,
                checkpoint_note: cp.sign(&self.key).unwrap(),
            }
            .to_http_body()
            .unwrap()
            .into_bytes()
        }
    }

    fn witness_dir(tag: &str) -> PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static N: AtomicU64 = AtomicU64::new(0);
        let d = std::env::temp_dir().join(format!(
            "wl-serve-{tag}-{}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(d.join("logs")).unwrap();
        d
    }

    /// A `serve` over `dir` as `cmd_serve` builds it, with a record cache
    /// of `cache` entries and `--max-logs max_logs`.
    fn server(dir: &Path, cache: usize, max_logs: usize) -> Arc<Mutex<Server>> {
        fs::write(
            dir.join("witness.lock"),
            format!("{}\n", std::process::id()),
        )
        .unwrap();
        Arc::new(Mutex::new(Server {
            lock: Lock(dir.join("witness.lock")),
            refused_unproven: 0,
            dir: dir.to_path_buf(),
            cfg: WitnessConfig {
                key_name: "w.test/witness".into(),
                operator_org: "Test".into(),
                public_url: "http://127.0.0.1:7380".into(),
                compute_provider: None,
                pubkey_hex: None,
            },
            key: SigningKey::from_bytes(&[42; 32]),
            logs: LogStore::open(dir, cache).unwrap(),
            open_enrollment: true,
            max_logs,
            enroll_rate: HashMap::new(),
            enroll_per_minute: usize::MAX,
            started: 0,
            cosigned: 0,
            refused_forks: 0,
        }))
    }

    fn post(server: &Arc<Mutex<Server>>, body: Vec<u8>) -> (u16, String) {
        let r = add_checkpoint(
            server,
            &Request {
                method: "POST".into(),
                path: "/add-checkpoint".into(),
                body,
                peer: "127.0.0.1:9".parse().unwrap(),
            },
        );
        (r.status, String::from_utf8_lossy(&r.body).into_owned())
    }

    /// `logs` as `GET /` reports it.
    fn info_logs(server: &Arc<Mutex<Server>>) -> u64 {
        let r = info(server);
        let v: serde_json::Value = serde_json::from_slice(&r.body).unwrap();
        v["logs"].as_u64().unwrap()
    }

    fn evidence_path(dir: &Path, origin: &str) -> PathBuf {
        dir.join("evidence").join(format!(
            "{}.json",
            hex::encode(Sha256::digest(origin.as_bytes()))
        ))
    }

    #[test]
    fn a_log_evicted_from_the_cache_still_refuses_forks() {
        let dir = witness_dir("evict");
        let srv = server(&dir, 1, 100);
        let a = TestLog::new(1, &["a0", "a1", "a2"]);
        let (b, c) = (TestLog::new(2, &["b0"]), TestLog::new(3, &["c0"]));
        assert_eq!(post(&srv, a.body(0)).0, 200);
        assert_eq!(post(&srv, b.body(0)).0, 200, "evicts a");
        assert_eq!(srv.lock().unwrap().logs.cached(), 1);

        // Same size, different root: refused from the record on disk, and
        // the two log-signed notes are kept as proof.
        let same = TestLog::new(1, &["a0", "rewritten", "a2"]);
        let (st, body) = post(&srv, same.body(3));
        assert_eq!(st, 422, "{body}");
        let doc: serde_json::Value =
            serde_json::from_slice(&fs::read(evidence_path(&dir, &a.origin())).unwrap()).unwrap();
        let proof: EquivocationProof = serde_json::from_value(doc["proof"].clone()).unwrap();
        assert!(proof.verify(), "evidence must verify independently");

        // Evict a again; a growing fork is refused too (not provable, so
        // no new evidence), and the honest history still advances.
        assert_eq!(post(&srv, c.body(0)).0, 200, "evicts a");
        let grow = TestLog::new(1, &["a0", "rewritten", "a2", "a3"]);
        assert_eq!(post(&srv, grow.body(3)).0, 422);
        assert_eq!(post(&srv, c.body(1)).0, 200, "evicts a");
        let honest = TestLog::new(1, &["a0", "a1", "a2", "a3"]);
        assert_eq!(post(&srv, honest.body(3)).0, 200);
        {
            let s = srv.lock().unwrap();
            assert_eq!((s.refused_forks, s.refused_unproven), (1, 1));
            assert_eq!(s.logs.count(), 3);
            assert!(s.logs.cached() <= 1);
        }
        let rec: serde_json::Value =
            serde_json::from_slice(&fs::read(record_path(&dir, &a.origin())).unwrap()).unwrap();
        assert_eq!(rec["tree_size"], 4);
        drop(srv);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn concurrent_requests_for_one_origin_are_serialized() {
        let dir = witness_dir("race");
        // No cache: every request reads the record from disk, so the read,
        // the decision and the persist must all sit under the one mutex.
        let srv = server(&dir, 0, 100);
        let race = |logs: &[TestLog], old: u64| -> Vec<u16> {
            std::thread::scope(|sc| {
                let hs: Vec<_> = logs
                    .iter()
                    .map(|l| {
                        let srv = &srv;
                        sc.spawn(move || post(srv, l.body(old)).0)
                    })
                    .collect();
                hs.into_iter().map(|h| h.join().unwrap()).collect()
            })
        };
        // Sixteen different first histories for one identity.
        let firsts: Vec<TestLog> = (0..16)
            .map(|i| TestLog::new(7, &["shared", &format!("v{i}")]))
            .collect();
        let st = race(&firsts, 0);
        assert_eq!(st.iter().filter(|&&s| s == 200).count(), 1, "{st:?}");
        assert!(st.iter().all(|&s| s == 200 || s == 409), "{st:?}");
        let winner = st.iter().position(|&s| s == 200).unwrap();

        // Sixteen different extensions of the cosigned head.
        let nexts: Vec<TestLog> = (0..16)
            .map(|i| TestLog::new(7, &["shared", &format!("v{winner}"), &format!("n{i}")]))
            .collect();
        let st = race(&nexts, 2);
        assert_eq!(st.iter().filter(|&&s| s == 200).count(), 1, "{st:?}");
        assert!(st.iter().all(|&s| s == 200 || s == 409), "{st:?}");
        let won = st.iter().position(|&s| s == 200).unwrap();
        let rec: serde_json::Value =
            serde_json::from_slice(&fs::read(record_path(&dir, &firsts[0].origin())).unwrap())
                .unwrap();
        assert_eq!(rec["root_hash"], hex::encode(nexts[won].tree().root()));
        assert_eq!(srv.lock().unwrap().logs.count(), 1);
        drop(srv);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn log_count_and_max_logs_come_from_names_not_contents() {
        let dir = witness_dir("count");
        // Fifty records `serve` must not read at startup: unparsable on
        // purpose, so reading any of them would refuse to start.
        for i in 0..50 {
            let name = hex::encode(Sha256::digest(format!("filler-{i}").as_bytes()));
            fs::write(dir.join("logs").join(format!("{name}.json")), b"not json").unwrap();
        }
        let srv = server(&dir, 8, 52);
        assert_eq!(info_logs(&srv), 50);
        assert_eq!(srv.lock().unwrap().logs.cached(), 0);

        // A 422 on first contact enrolls nothing.
        let junk = TestLog::new(3, &["x"]).request(0, vec![[0u8; 32]]);
        assert_eq!(post(&srv, junk).0, 422);
        assert_eq!(info_logs(&srv), 50);

        assert_eq!(post(&srv, TestLog::new(4, &["y"]).body(0)).0, 200);
        assert_eq!(post(&srv, TestLog::new(5, &["z"]).body(0)).0, 200);
        assert_eq!(info_logs(&srv), 52);
        // At --max-logs: no new log, but known logs are still served.
        assert_eq!(post(&srv, TestLog::new(6, &["w"]).body(0)).0, 503);
        assert_eq!(post(&srv, TestLog::new(4, &["y", "y1"]).body(1)).0, 200);
        assert_eq!(info_logs(&srv), 52);

        // A restart counts the same, again without reading a record.
        drop(srv);
        let srv = server(&dir, 8, 52);
        assert_eq!(info_logs(&srv), 52);
        drop(srv);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_unreadable_record_is_refused_not_enrolled_afresh() {
        let dir = witness_dir("garbage");
        let a = TestLog::new(9, &["a0", "a1"]);
        let path = record_path(&dir, &a.origin());
        for broken in [&b"{ \"origin\": \"trunc"[..], b""] {
            fs::write(&path, broken).unwrap();
            let srv = server(&dir, 8, 100);
            assert_eq!(info_logs(&srv), 1);
            for old in [0, 2] {
                let (st, body) = post(&srv, a.body(old));
                assert_eq!(st, 500, "{body}");
                assert!(body.contains("unreadable"), "{body}");
            }
            assert_eq!(fs::read(&path).unwrap(), broken, "left as it was");
            let s = srv.lock().unwrap();
            assert_eq!((s.cosigned, s.logs.count()), (0, 1));
            drop(s);
            drop(srv);
        }
        let _ = fs::remove_dir_all(&dir);
    }
}
