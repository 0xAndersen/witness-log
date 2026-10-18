//! `witness-log testnet up|status|down` -- a local witness network on one
//! machine, for trying the whole path to WITNESSED without any code and
//! without anyone else's witness.
//!
//! `up` starts N `witness serve` processes (children of this binary, each
//! with its own key, state directory, operator name and loopback port)
//! and writes the directory file that lists them. The witnesses are real:
//! they persist what they cosign, refuse forks with 422, and record
//! equivocation evidence. What they are not is independent of you, which
//! is why the operator names say `testnet-`: a verifier who adds this
//! directory to the one they trust is trusting you three times.
//!
//! Layout under `--dir` (default `./.witness-testnet`):
//!
//! ```text
//! testnet.json        which processes are up: pid, url, dir, log
//! trusted.json        the directory file (also written to --out)
//! testnet-a/          witness state (witness.key, witness.json, logs/)
//! testnet-a.pid       the serving process's pid
//! testnet-a.log       its stderr
//! ```

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};
use std::time::{Duration, Instant};
use witness_log_network::{WitnessDirectory, WitnessEntry};

const USAGE: &str = "usage:
  witness-log testnet up [--witnesses 3] [--dir ./.witness-testnet] [--out trusted.json]
      Start N local witnesses (child processes of this binary, distinct keys and
      operator names testnet-a, testnet-b, ...) and write the directory file.
      --out defaults to <dir>/trusted.json.
  witness-log testnet status [--dir ./.witness-testnet]
      Which witnesses answer, and how many logs each has cosigned. Exit 1 if any is down.
  witness-log testnet down [--dir ./.witness-testnet]
      Stop them (SIGTERM, then SIGKILL; taskkill on Windows) and remove the pid files.
      State directories and keys are kept, so `up` again continues with the same keys.";

fn usage_err(msg: &str) -> ExitCode {
    eprintln!("{msg}\n\n{USAGE}");
    ExitCode::from(2)
}

fn fail(msg: impl std::fmt::Display) -> ExitCode {
    eprintln!("{msg}");
    ExitCode::from(1)
}

#[derive(Serialize, Deserialize, Clone)]
struct Member {
    name: String,
    org: String,
    dir: String,
    pid: u32,
    url: String,
    log: String,
}

#[derive(Serialize, Deserialize, Default)]
struct Testnet {
    witnesses: Vec<Member>,
    directory: String,
}

fn state_path(dir: &Path) -> PathBuf {
    dir.join("testnet.json")
}

fn load(dir: &Path) -> Option<Testnet> {
    let raw = std::fs::read_to_string(state_path(dir)).ok()?;
    serde_json::from_str(&raw).ok()
}

/// `a`, `b`, ... `z`, then `a1`, `b1`, ...: distinct operator names the
/// verifier sees as distinct organisations.
fn suffix(i: usize) -> String {
    let letter = (b'a' + (i % 26) as u8) as char;
    if i < 26 {
        letter.to_string()
    } else {
        format!("{letter}{}", i / 26)
    }
}

fn health(url: &str, timeout: Duration) -> bool {
    crate::http::parse_url(url)
        .ok()
        .and_then(|u| crate::http::request(&u, "GET", "/health", b"", timeout).ok())
        .is_some_and(|(status, _, _)| status == 200)
}

fn info(url: &str) -> Option<serde_json::Value> {
    let u = crate::http::parse_url(url).ok()?;
    let (status, body, _) =
        crate::http::request(&u, "GET", "/", b"", Duration::from_secs(3)).ok()?;
    if status != 200 {
        return None;
    }
    serde_json::from_slice(&body).ok()
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
    // Flag check shared by the three subcommands.
    let mut i = 0;
    while i < rest.len() {
        match rest[i].as_str() {
            "--witnesses" | "--dir" | "--out" => {
                if rest.get(i + 1).is_none() {
                    return usage_err(&format!("testnet: {} requires a value", rest[i]));
                }
                i += 2;
            }
            other => return usage_err(&format!("testnet: unexpected argument {other:?}")),
        }
    }
    let dir = PathBuf::from(
        crate::flag_value(rest, "--dir").unwrap_or_else(|| ".witness-testnet".into()),
    );
    match sub {
        Some("up") => cmd_up(rest, &dir),
        Some("status") => cmd_status(&dir),
        Some("down") => cmd_down(&dir),
        _ => usage_err("testnet: expected up, status or down"),
    }
}

/// On Windows every inheritable handle in this process is copied into
/// each child, not only the three stdio handles the child is given.
/// When `testnet up` runs under a parent that reads its stdout through a
/// pipe (a test, a script), that pipe handle is inheritable, the
/// long-lived `witness serve` children inherit it, and the parent never
/// sees EOF (issue #12). Clearing the inherit flag on this process's own
/// stdio before spawning keeps the pipe with this process alone.
#[cfg(windows)]
fn detach_inherited_stdio() {
    #[link(name = "kernel32")]
    extern "system" {
        fn GetStdHandle(n_std_handle: u32) -> isize;
        fn SetHandleInformation(h: isize, mask: u32, flags: u32) -> i32;
    }
    const HANDLE_FLAG_INHERIT: u32 = 0x1;
    for n in [-10i32, -11, -12] {
        // STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, STD_ERROR_HANDLE
        // SAFETY: both calls take a handle value and flags; an invalid or
        // closed handle makes SetHandleInformation fail, which is ignored.
        unsafe {
            let h = GetStdHandle(n as u32);
            if h != 0 && h != -1 {
                let _ = SetHandleInformation(h, HANDLE_FLAG_INHERIT, 0);
            }
        }
    }
}

#[cfg(not(windows))]
fn detach_inherited_stdio() {}

fn cmd_up(args: &[String], dir: &Path) -> ExitCode {
    detach_inherited_stdio();
    let n: usize = match crate::flag_value(args, "--witnesses").map(|v| v.parse()) {
        None => 3,
        Some(Ok(n)) if (1..=64).contains(&n) => n,
        Some(_) => return usage_err("testnet up: --witnesses must be between 1 and 64"),
    };
    if n < 2 {
        eprintln!(
            "note: WITNESSED needs two distinct operators; with --witnesses 1 the best verdict is CONSISTENT-UNWITNESSED"
        );
    }
    if let Some(existing) = load(dir) {
        let alive: Vec<&Member> = existing
            .witnesses
            .iter()
            .filter(|m| health(&m.url, Duration::from_millis(500)))
            .collect();
        if !alive.is_empty() {
            return fail(format!(
                "testnet in {} is already up ({} of {} witnesses answering). Run `witness-log testnet down --dir {}` first.",
                dir.display(),
                alive.len(),
                existing.witnesses.len(),
                dir.display()
            ));
        }
        // All dead (crash, reboot): clean up what `down` would have.
        for m in &existing.witnesses {
            let _ = std::fs::remove_file(Path::new(&m.dir).join("witness.lock"));
            let _ = std::fs::remove_file(format!("{}.pid", m.dir));
        }
    }
    if let Err(e) = std::fs::create_dir_all(dir) {
        return fail(format!("{}: {e}", dir.display()));
    }
    let exe = match std::env::current_exe() {
        Ok(e) => e,
        Err(e) => return fail(format!("cannot locate this binary: {e}")),
    };
    let out = crate::flag_value(args, "--out")
        .unwrap_or_else(|| dir.join("trusted.json").display().to_string());

    let mut members = Vec::new();
    let mut entries: Vec<WitnessEntry> = Vec::new();
    for i in 0..n {
        let org = format!("testnet-{}", suffix(i));
        let wdir = dir.join(&org);
        let wdir_s = wdir.display().to_string();
        if !wdir.join("witness.key").exists() {
            let init = Command::new(&exe)
                .args(["witness", "init"])
                .arg(&wdir)
                .args([
                    "--name",
                    &format!("{org}/w"),
                    "--org",
                    &org,
                    "--compute",
                    &format!("{org}-host"),
                    "--json",
                ])
                .output();
            match init {
                Ok(o) if o.status.success() => {}
                Ok(o) => {
                    return fail(format!(
                        "witness init {wdir_s} failed: {}",
                        String::from_utf8_lossy(&o.stderr).trim()
                    ))
                }
                Err(e) => return fail(format!("witness init {wdir_s}: {e}")),
            }
        }
        let log_path = dir.join(format!("{org}.log"));
        let log_file = match std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_path)
        {
            Ok(f) => f,
            Err(e) => return fail(format!("{}: {e}", log_path.display())),
        };
        let child = Command::new(&exe)
            .args(["witness", "serve"])
            .arg(&wdir)
            .args(["--listen", "127.0.0.1:0", "--open-enrollment"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::from(log_file))
            .spawn();
        let child = match child {
            Ok(c) => c,
            Err(e) => {
                stop_all(&members);
                return fail(format!("could not start witness {org}: {e}"));
            }
        };
        let pid = child.id();
        // The URL is on the first "listening on http://..." line of the
        // log, written once the socket is bound.
        let started = Instant::now();
        let url = loop {
            if let Ok(text) = std::fs::read_to_string(&log_path) {
                if let Some(line) = text
                    .lines()
                    .rev()
                    .find(|l| l.contains("listening on http://"))
                {
                    if let Some(idx) = line.find("http://") {
                        break Some(
                            line[idx..]
                                .split_whitespace()
                                .next()
                                .unwrap_or("")
                                .to_string(),
                        );
                    }
                }
            }
            if started.elapsed() > Duration::from_secs(15) {
                break None;
            }
            std::thread::sleep(Duration::from_millis(50));
        };
        let Some(url) = url else {
            stop_all(&members);
            kill(pid);
            return fail(format!(
                "witness {org} did not start within 15s; see {}",
                log_path.display()
            ));
        };
        let started = Instant::now();
        while !health(&url, Duration::from_millis(500)) {
            if started.elapsed() > Duration::from_secs(15) {
                stop_all(&members);
                kill(pid);
                return fail(format!("witness {org} at {url} does not answer /health"));
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        let Some(entry) = info(&url).and_then(|v| {
            serde_json::from_value::<WitnessEntry>(v.get("directory_entry")?.clone()).ok()
        }) else {
            stop_all(&members);
            kill(pid);
            return fail(format!(
                "witness {org} at {url} did not serve its directory entry"
            ));
        };
        let mut entry = entry;
        entry.url = url.clone();
        let _ = std::fs::write(dir.join(format!("{org}.pid")), format!("{pid}\n"));
        eprintln!("  {org:<12} pid {pid:<7} {url}");
        members.push(Member {
            name: entry.name.clone(),
            org,
            dir: wdir_s,
            pid,
            url,
            log: log_path.display().to_string(),
        });
        entries.push(entry);
    }

    let directory = WitnessDirectory { witnesses: entries };
    let dir_json = match serde_json::to_vec_pretty(&directory) {
        Ok(j) => j,
        Err(e) => return fail(e),
    };
    if let Err(e) = crate::witness_cmd::atomic_write_shared(Path::new(&out), &dir_json) {
        stop_all(&members);
        return fail(format!("{out}: {e}"));
    }
    let local_copy = dir.join("trusted.json");
    if Path::new(&out) != local_copy {
        let _ = crate::witness_cmd::atomic_write_shared(&local_copy, &dir_json);
    }
    let net = Testnet {
        witnesses: members,
        directory: out.clone(),
    };
    if let Err(e) = serde_json::to_vec_pretty(&net)
        .map_err(std::io::Error::other)
        .and_then(|j| crate::witness_cmd::atomic_write_shared(&state_path(dir), &j))
    {
        stop_all(&net.witnesses);
        return fail(format!("{}: {e}", state_path(dir).display()));
    }
    println!(
        "testnet up: {n} witness{} in {}; directory written to {out}",
        if n == 1 { "" } else { "es" },
        dir.display()
    );
    println!();
    println!("  witness-log log init agent.jsonl");
    println!("  witness-log log append agent.jsonl --intent '{{\"tool\":\"example\"}}'");
    println!("  witness-log submit agent.jsonl --directory {out} --out dossier.json");
    println!(
        "  witness-log verify dossier.json --identity <identity from log init> --directory {out}"
    );
    println!("  witness-log testnet down{}", dir_flag(dir));
    ExitCode::SUCCESS
}

fn dir_flag(dir: &Path) -> String {
    if dir == Path::new(".witness-testnet") {
        String::new()
    } else {
        format!(" --dir {}", dir.display())
    }
}

fn cmd_status(dir: &Path) -> ExitCode {
    let Some(net) = load(dir) else {
        println!("no testnet in {} (nothing is up)", dir.display());
        return ExitCode::from(1);
    };
    let mut down = 0usize;
    for m in &net.witnesses {
        match info(&m.url) {
            Some(v) => println!(
                "  {:<12} up    pid {:<7} {}  logs {}  cosigned {}",
                m.org,
                m.pid,
                m.url,
                v.get("logs").and_then(|x| x.as_u64()).unwrap_or(0),
                v.get("cosigned_since_start")
                    .and_then(|x| x.as_u64())
                    .unwrap_or(0)
            ),
            None => {
                down += 1;
                println!(
                    "  {:<12} DOWN  pid {:<7} {}  (see {})",
                    m.org, m.pid, m.url, m.log
                );
            }
        }
    }
    println!("directory: {}", net.directory);
    if down == 0 {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    }
}

fn cmd_down(dir: &Path) -> ExitCode {
    let Some(net) = load(dir) else {
        println!("no testnet in {} (nothing to stop)", dir.display());
        return ExitCode::SUCCESS;
    };
    stop_all(&net.witnesses);
    for m in &net.witnesses {
        let _ = std::fs::remove_file(format!("{}.pid", m.dir));
        // A witness stopped by SIGTERM releases its lock itself; one that
        // had to be killed (or any on Windows) leaves it, and the next
        // `up` must not be refused by a lock nobody holds.
        let _ = std::fs::remove_file(Path::new(&m.dir).join("witness.lock"));
        println!("  {:<12} stopped (pid {})", m.org, m.pid);
    }
    let _ = std::fs::remove_file(state_path(dir));
    println!(
        "testnet down; keys and state kept in {} (`up` again reuses them)",
        dir.display()
    );
    ExitCode::SUCCESS
}

/// Whether `pid`, read from testnet.json, may be signalled: a real
/// process id (never 0, 1 or a value that becomes negative as pid_t, which
/// would signal a process group or every process the user owns) and still a
/// witness-log witness, not an unrelated process that reused the id after
/// a reboot (security sweep of 0.6.0, F12): on Linux and other Unix
/// systems, the `witness-log witness serve <dir>` this testnet started for
/// that member's state directory (Linux reads /proc, others ask `ps`); on
/// Windows, which shows no arguments, a `witness-log` image (`tasklist`).
fn signalable(pid: u32, dir: &str) -> bool {
    if pid < 2 || pid > i32::MAX as u32 {
        return false;
    }
    #[cfg(target_os = "linux")]
    {
        match std::fs::read(format!("/proc/{pid}/cmdline")) {
            Ok(c) => {
                let args: Vec<&[u8]> = c.split(|b| *b == 0).collect();
                args.first()
                    .is_some_and(|a| String::from_utf8_lossy(a).contains("witness-log"))
                    && args
                        .windows(3)
                        .any(|w| w[0] == b"witness" && w[1] == b"serve" && w[2] == dir.as_bytes())
            }
            Err(_) => false,
        }
    }
    #[cfg(all(unix, not(target_os = "linux")))]
    {
        match Command::new("ps")
            .args(["-p", &pid.to_string(), "-o", "command="])
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .output()
        {
            Ok(o) if o.status.success() => {
                let c = String::from_utf8_lossy(&o.stdout);
                c.contains("witness-log") && c.contains(&format!(" witness serve {dir} "))
            }
            _ => false,
        }
    }
    #[cfg(not(unix))]
    {
        let _ = dir; // tasklist shows no arguments to match it against
        match Command::new("tasklist")
            .args(["/FI", &format!("PID eq {pid}"), "/FO", "CSV", "/NH"])
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .output()
        {
            Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout)
                .lines()
                .any(|l| l.to_ascii_lowercase().starts_with("\"witness-log")),
            _ => false,
        }
    }
}

/// Stop every member: terminate, wait up to 5s for /health to stop
/// answering, then kill.
fn stop_all(members: &[Member]) {
    let members: Vec<&Member> = members
        .iter()
        .filter(|m| signalable(m.pid, &m.dir))
        .collect();
    for m in &members {
        terminate(m.pid);
    }
    let started = Instant::now();
    loop {
        let alive: Vec<&&Member> = members
            .iter()
            .filter(|m| health(&m.url, Duration::from_millis(300)))
            .collect();
        if alive.is_empty() {
            break;
        }
        if started.elapsed() > Duration::from_secs(5) {
            for m in alive {
                kill(m.pid);
            }
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

#[cfg(unix)]
fn terminate(pid: u32) {
    // SAFETY: sending a signal has no memory-safety preconditions; a stale
    // pid is a harmless ESRCH.
    unsafe {
        libc::kill(pid as libc::pid_t, libc::SIGTERM);
    }
}

#[cfg(unix)]
fn kill(pid: u32) {
    // SAFETY: as above.
    unsafe {
        libc::kill(pid as libc::pid_t, libc::SIGKILL);
    }
}

#[cfg(not(unix))]
fn terminate(pid: u32) {
    kill(pid);
}

#[cfg(not(unix))]
fn kill(pid: u32) {
    let _ = Command::new("taskkill")
        .args(["/PID", &pid.to_string(), "/T", "/F"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

#[cfg(test)]
mod pid_tests {
    use super::signalable;

    /// testnet.json is a file anyone with write access to the directory can
    /// edit: 0 would signal the process group, 2^32-1 becomes -1 (every
    /// process the user owns), and a recycled pid belongs to someone else.
    #[test]
    fn only_a_running_witness_is_signalled() {
        for pid in [0, 1, u32::MAX, i32::MAX as u32 + 1] {
            assert!(!signalable(pid, "tn/testnet-a"), "{pid}");
        }
        // This test process is not a `witness-log witness serve`, on any
        // system (its path may well contain "witness-log").
        assert!(!signalable(std::process::id(), "tn/testnet-a"));
    }

    // That a real witness IS recognised, on Linux, macOS and Windows, is
    // tests/no_code_path.rs: `testnet down` must leave no witness answering.
}
