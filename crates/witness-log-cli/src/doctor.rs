//! `witness-log doctor`: check a setup end to end and say what to fix.
//!
//! Every check prints one line (✓ fine, ! worth fixing, ✗ will not work,
//! · for information) and, when something is off, the command that fixes
//! it. Nothing is changed on disk. Exit 0 when nothing is ✗, 1 when
//! something is, 2 on a usage error.
//!
//! What it looks at, each only when given:
//! - this binary: version, whether it can reach `https://` witnesses, and
//!   whether `WITNESS_LOG_CA_FILE` loads;
//! - a journal: it replays, its files are private, its lock is not stale,
//!   and how it stands against the head witnesses last cosigned for it
//!   (`<journal>.witnesses.json`): up to date, behind, or contradicting it;
//! - a trusted directory: whether WITNESSED is reachable with it at all
//!   (two independent operators besides the log's own), what `submit`
//!   will ask for, and whether each witness answers with the key the
//!   directory lists (skipped with `--offline`);
//! - a witness state directory (`--witness DIR`): key and config present
//!   and private, `logs/` writable, and any equivocation proofs recorded.

use std::path::Path;
use std::process::ExitCode;
use std::time::Duration;

use crate::http;

const USAGE: &str = "\
usage: witness-log doctor [<journal>] [--directory <trusted.json>] [--subject-org ORG]
                          [--witness <witness dir>] [--offline] [--json]
                          [--identity-seed-env NAME | --identity-seed-file F]

Checks what you give it and says what to fix; changes nothing.
  <journal>         an agent journal: replays, file modes, lock, witnessing state
  --directory P     a directory you trust: is WITNESSED reachable, do the witnesses answer
  --subject-org O   the organisation that operates the journal's log (as for `verify`)
  --witness DIR     a witness state directory (`witness init` / `witness serve`)
  --offline         do not contact any witness
  --json            one JSON object: {ok, problems, warnings, findings: [...]}
Exit: 0 nothing broken (warnings allowed), 1 something will not work, 2 usage.";

#[derive(Clone, Copy, PartialEq, Eq)]
enum Level {
    Ok,
    Info,
    Warn,
    Fail,
}

impl Level {
    fn mark(self) -> &'static str {
        match self {
            Level::Ok => "✓",
            Level::Info => "·",
            Level::Warn => "!",
            Level::Fail => "✗",
        }
    }
    fn name(self) -> &'static str {
        match self {
            Level::Ok => "ok",
            Level::Info => "info",
            Level::Warn => "warn",
            Level::Fail => "fail",
        }
    }
}

struct Finding {
    section: String,
    level: Level,
    what: String,
    fix: Option<String>,
}

#[derive(Default)]
struct Report {
    findings: Vec<Finding>,
    section: String,
}

impl Report {
    fn section(&mut self, name: impl Into<String>) {
        self.section = name.into();
    }
    fn push(&mut self, level: Level, what: impl Into<String>, fix: Option<String>) {
        self.findings.push(Finding {
            section: self.section.clone(),
            level,
            what: what.into(),
            fix,
        });
    }
    fn ok(&mut self, what: impl Into<String>) {
        self.push(Level::Ok, what, None);
    }
    fn info(&mut self, what: impl Into<String>) {
        self.push(Level::Info, what, None);
    }
    fn warn(&mut self, what: impl Into<String>, fix: impl Into<String>) {
        self.push(Level::Warn, what, Some(fix.into()));
    }
    fn fail(&mut self, what: impl Into<String>, fix: impl Into<String>) {
        self.push(Level::Fail, what, Some(fix.into()));
    }
    fn count(&self, level: Level) -> usize {
        self.findings.iter().filter(|f| f.level == level).count()
    }
}

struct Args {
    journal: Option<String>,
    directory: Option<String>,
    subject_org: Option<String>,
    witness: Option<String>,
    offline: bool,
    json: bool,
}

fn parse(args: &[String]) -> Result<Args, String> {
    let mut a = Args {
        journal: None,
        directory: None,
        subject_org: None,
        witness: None,
        offline: false,
        json: false,
    };
    let mut i = 0;
    while i < args.len() {
        let arg = args[i].as_str();
        let value = |i: usize| -> Result<String, String> {
            match args.get(i + 1) {
                Some(v) if !v.starts_with("--") && !v.trim().is_empty() => Ok(v.clone()),
                _ => Err(format!("doctor: {arg} needs a value")),
            }
        };
        match arg {
            "--directory" => {
                a.directory = Some(value(i)?);
                i += 1;
            }
            "--subject-org" => {
                a.subject_org = Some(value(i)?);
                i += 1;
            }
            "--witness" => {
                a.witness = Some(value(i)?);
                i += 1;
            }
            // Read by identity_seed_from_args; skip the value here.
            "--identity-seed-env" | "--identity-seed-file" => {
                value(i)?;
                i += 1;
            }
            "--offline" => a.offline = true,
            "--json" => a.json = true,
            s if s.starts_with("--") => return Err(format!("doctor: unknown flag {s}")),
            s => {
                if a.journal.is_some() {
                    return Err(format!("doctor: one journal at a time (got {s:?} as well)"));
                }
                a.journal = Some(s.to_string());
            }
        }
        i += 1;
    }
    Ok(a)
}

pub fn run(args: &[String]) -> ExitCode {
    if args.iter().any(|a| a == "--help" || a == "-h") {
        println!("{USAGE}");
        return ExitCode::SUCCESS;
    }
    let a = match parse(args) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("{e}\n\n{USAGE}");
            return ExitCode::from(crate::exit::USAGE);
        }
    };
    let seed = match crate::identity_seed_from_args(args) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("doctor: {e}");
            return ExitCode::from(crate::exit::USAGE);
        }
    };

    let mut r = Report::default();
    check_binary(&mut r);
    let identity = a
        .journal
        .as_deref()
        .and_then(|j| check_journal(&mut r, j, seed.as_deref(), a.directory.as_deref()));
    if let Some(d) = a.directory.as_deref() {
        check_directory(
            &mut r,
            d,
            identity.as_deref(),
            a.subject_org.as_deref(),
            a.offline,
        );
    }
    if let Some(w) = a.witness.as_deref() {
        check_witness_dir(&mut r, Path::new(w), a.offline);
    }
    if a.journal.is_none() && a.directory.is_none() && a.witness.is_none() {
        r.section("next");
        r.info("nothing else to check: pass a journal, --directory and/or --witness");
    }

    let (problems, warnings) = (r.count(Level::Fail), r.count(Level::Warn));
    if a.json {
        let findings: Vec<serde_json::Value> = r
            .findings
            .iter()
            .map(|f| {
                serde_json::json!({
                    "section": f.section,
                    "level": f.level.name(),
                    "what": f.what,
                    "fix": f.fix,
                })
            })
            .collect();
        let doc = serde_json::json!({
            "version": env!("CARGO_PKG_VERSION"),
            "ok": problems == 0,
            "problems": problems,
            "warnings": warnings,
            "findings": findings,
        });
        println!("{}", serde_json::to_string_pretty(&doc).unwrap_or_default());
    } else {
        println!("witness-log doctor ({})", env!("CARGO_PKG_VERSION"));
        let mut last = String::new();
        for f in &r.findings {
            if f.section != last {
                println!();
                println!("{}", f.section);
                last.clone_from(&f.section);
            }
            println!("  {} {}", f.level.mark(), f.what);
            if let Some(fix) = &f.fix {
                println!("      fix: {fix}");
            }
        }
        println!();
        println!(
            "{problems} problem{}, {warnings} warning{}.",
            if problems == 1 { "" } else { "s" },
            if warnings == 1 { "" } else { "s" }
        );
    }
    if problems == 0 {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    }
}

// ------------------------------------------------------------------ binary

fn check_binary(r: &mut Report) {
    r.section("this binary");
    r.info(format!(
        "witness-log {} ({})",
        env!("CARGO_PKG_VERSION"),
        std::env::current_exe()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|_| "path unknown".into())
    ));
    match http::https_ready() {
        Ok(roots) => r.ok(format!("reaches https:// witnesses; certificates checked against {roots}")),
        Err(e) if std::env::var_os("WITNESS_LOG_CA_FILE").is_some() => r.fail(
            e,
            "point WITNESS_LOG_CA_FILE at a PEM file of CA certificates, or unset it to use the built-in roots",
        ),
        Err(e) => r.warn(
            format!("{e}: https:// witnesses (every registry witness) are unreachable"),
            "cargo install witness-log-cli (default features), or a release binary",
        ),
    }
}

// ----------------------------------------------------------------- journal

/// Returns the journal's identity (hex) when it could be read.
fn check_journal(
    r: &mut Report,
    journal: &str,
    seed: Option<&[u8; 32]>,
    directory: Option<&str>,
) -> Option<String> {
    r.section(format!("journal {journal}"));
    let meta = match std::fs::metadata(journal) {
        Ok(m) => m,
        Err(e) => {
            r.fail(
                format!("cannot read it: {e}"),
                format!("witness-log log init {journal}   (to start a new one)"),
            );
            return None;
        }
    };
    let header = header(journal);
    let sealed = header.as_ref().is_some_and(|h| h.0);
    let header_identity = header.and_then(|h| h.1);

    let (log, report) = match crate::replay_journal(journal, seed) {
        Ok(x) => x,
        Err(e) if sealed && seed.is_none() => {
            r.info(format!(
                "sealed (the identity seed is kept outside the file): {}",
                header_identity.as_deref().unwrap_or("identity unknown")
            ));
            r.warn(
                format!("not replayed without the seed ({e})"),
                format!("witness-log doctor {journal} --identity-seed-env NAME (or --identity-seed-file F)"),
            );
            return header_identity;
        }
        Err(e) => {
            r.fail(
                format!("does not replay: {e}"),
                "restore it from a backup; `witness-log log info` on the backup should succeed",
            );
            return header_identity;
        }
    };
    let identity = log.identity_pubkey_hex();
    r.ok(format!(
        "replays: {}, identity {identity}{}",
        leaves(log.tree_size()),
        if sealed { " (sealed)" } else { "" }
    ));
    if report.dropped_trailing_lines > 0 {
        r.warn(
            format!(
                "{} incomplete line(s) at the end were ignored (a write cut off by a crash or a full disk)",
                report.dropped_trailing_lines
            ),
            "nothing is lost that was acknowledged; check free disk space if it recurs",
        );
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let private = |m: &std::fs::Metadata| m.permissions().mode() & 0o077 == 0;
        if !sealed && !private(&meta) {
            r.warn(
                "the journal (it holds the identity seed) is readable by other users",
                format!("chmod 600 {journal}"),
            );
        }
        let salts = witness_log_core::journal::JournaledLog::salts_path(journal);
        match std::fs::metadata(&salts) {
            Ok(m) if !private(&m) => r.warn(
                format!("{salts} (the payload salts) is readable by other users"),
                format!("chmod 600 {salts}"),
            ),
            Ok(_) => {}
            Err(_) if log.tree_size() > 0 => r.warn(
                format!("{salts} is missing: payloads can no longer be disclosed or proven"),
                "restore it from the same backup as the journal (they belong together)",
            ),
            Err(_) => {}
        }
    }
    #[cfg(not(unix))]
    let _ = meta;

    check_lock(r, journal);

    let state_path = format!("{journal}.witnesses.json");
    let submit = format!(
        "witness-log submit {journal} --directory {}",
        directory.unwrap_or("trusted.json")
    );
    match crate::read_input(&state_path) {
        Err(_) => r.warn("never submitted to witnesses (no .witnesses.json)", submit),
        Ok(raw) => {
            let state: serde_json::Value = serde_json::from_str(&raw).unwrap_or_default();
            let size = state
                .get("cosigned_size")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            let root = state
                .get("cosigned_root")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_ascii_lowercase();
            let witnesses = state
                .get("sizes")
                .and_then(|v| v.as_object())
                .map_or(0, |m| m.len());
            if size == 0 || root.is_empty() {
                r.warn("no head has been cosigned yet", submit);
            } else if size > log.tree_size() {
                r.fail(
                    format!(
                        "witnesses cosigned a head at size {size}, but the journal now has {}: it was truncated or replaced",
                        leaves(log.tree_size())
                    ),
                    "do not submit this journal (witnesses would record it as equivocation); restore the full journal from a backup",
                );
            } else if log.root_at(size).map(hex::encode).as_deref() != Some(root.as_str()) {
                r.fail(
                    format!("the journal contradicts the head witnesses cosigned at size {size}: a forked or edited history"),
                    "do not submit it: each witness that cosigned would refuse (422) and keep proof; restore the journal from a backup",
                );
            } else if size < log.tree_size() {
                r.warn(
                    format!(
                        "{} since the last witnessed head (size {size}, cosigned by {witnesses} witness{})",
                        leaves(log.tree_size() - size),
                        if witnesses == 1 { "" } else { "es" }
                    ),
                    submit,
                );
            } else {
                r.ok(format!(
                    "witnessed up to the current head (size {size}, {witnesses} witness{})",
                    if witnesses == 1 { "" } else { "es" }
                ));
            }
        }
    }
    Some(identity)
}

fn leaves(n: u64) -> String {
    format!("{n} lea{}", if n == 1 { "f" } else { "ves" })
}

/// (sealed, identity hex) from the journal's first line.
fn header(journal: &str) -> Option<(bool, Option<String>)> {
    use std::io::{BufRead, Read};
    let f = std::fs::File::open(journal).ok()?;
    let mut first = String::new();
    std::io::BufReader::new(f.take(1 << 20))
        .read_line(&mut first)
        .ok()?;
    let v: serde_json::Value = serde_json::from_str(first.trim()).ok()?;
    let sealed = v
        .get("identity_bytes_hex")
        .and_then(|x| x.as_str())
        .is_some_and(str::is_empty);
    let identity = v
        .get("identity_pubkey_hex")
        .and_then(|x| x.as_str())
        .map(str::to_string);
    Some((sealed, identity))
}

fn check_lock(r: &mut Report, journal: &str) {
    let lock = format!("{journal}.lock");
    let Ok(holder) = std::fs::read_to_string(&lock) else {
        return;
    };
    let pid = holder.trim().to_string();
    #[cfg(target_os = "linux")]
    {
        if !pid.is_empty() && Path::new(&format!("/proc/{pid}")).exists() {
            r.info(format!("open in process {pid} (it holds {lock})"));
        } else {
            r.warn(
                format!("{lock} is left from process {pid}, which is no longer running"),
                "nothing: the next open takes a dead process's lock over on Linux",
            );
        }
    }
    #[cfg(not(target_os = "linux"))]
    r.warn(
        format!("{lock} exists (process {pid}): the journal is open elsewhere, or a crash left it"),
        format!("if no process has the journal open, delete {lock}"),
    );
}

// --------------------------------------------------------------- directory

fn label(s: &str) -> String {
    // The verifier's normalisation of operator names (trim, collapse
    // whitespace, lowercase), so the counts here match what `verify` does.
    s.split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_lowercase()
}

fn check_directory(
    r: &mut Report,
    path: &str,
    identity: Option<&str>,
    subject_org: Option<&str>,
    offline: bool,
) {
    r.section(format!("directory {path}"));
    let dir = match crate::read_input(path)
        .map_err(|e| e.to_string())
        .and_then(|raw| crate::parse_directory(&raw))
    {
        Ok(d) => d,
        Err(e) => {
            r.fail(
                format!("cannot use it: {e}"),
                "witness-log directory add <file> --vkey <vkey> --org <org> --url <url>, or witness-log directory build --out <file>",
            );
            return;
        }
    };
    let n = dir.witnesses.len();
    if n == 0 {
        r.fail(
            "lists no witnesses: submit has nobody to ask and the best verdict is CONSISTENT-UNWITNESSED",
            "add witnesses: witness-log directory add, or see docs/wiki/Pilot-Three-Organisations.md",
        );
        return;
    }

    let mut seen = std::collections::HashSet::new();
    for w in &dir.witnesses {
        if !seen.insert(w.pubkey.to_ascii_lowercase()) {
            r.fail(
                format!("{} is listed twice (same key)", w.name),
                "remove the duplicate entry",
            );
        }
    }

    let mut operators: Vec<String> = Vec::new();
    let mut display: std::collections::BTreeMap<String, String> = Default::default();
    let mut project = 0usize;
    for w in &dir.witnesses {
        if w.is_project_operated {
            project += 1;
            continue;
        }
        let k = label(&w.operator_org);
        if !operators.contains(&k) {
            operators.push(k.clone());
            display.insert(k, w.operator_org.trim().to_string());
        }
    }
    let names: Vec<&str> = operators
        .iter()
        .filter_map(|k| display.get(k).map(String::as_str))
        .collect();
    r.ok(format!(
        "{n} witness{}: {} independent operator{}{}{}",
        if n == 1 { "" } else { "es" },
        operators.len(),
        if operators.len() == 1 { "" } else { "s" },
        if names.is_empty() {
            String::new()
        } else {
            format!(" ({})", names.join(", "))
        },
        if project > 0 {
            format!(", and {project} project-operated (never counted as independent)")
        } else {
            String::new()
        }
    ));

    // Who operates the log being checked: the verifier's two sources.
    let mut excluded: Vec<String> = Vec::new();
    if let Some(id) = identity {
        if let Some(w) = dir
            .witnesses
            .iter()
            .find(|w| w.pubkey.eq_ignore_ascii_case(id) && !w.is_project_operated)
        {
            excluded.push(label(&w.operator_org));
        }
    }
    match subject_org {
        Some(org) => {
            let k = label(org);
            if operators.contains(&k) {
                r.info(format!(
                    "{org:?} operates this log: its own witnesses count as receipts, not as independent operators"
                ));
                excluded.push(k);
            } else {
                r.info(format!("no witness in the directory belongs to {org:?}"));
            }
        }
        None if identity.is_some() && operators.len() >= 2 => r.warn(
            "who operates this log was not given, so a witness of its own operator would count as independent",
            "pass --subject-org <your organisation> here and to `witness-log verify`",
        ),
        None => {}
    }
    let independent = operators.iter().filter(|o| !excluded.contains(o)).count();
    if independent >= 2 {
        r.ok(format!(
            "WITNESSED is reachable: {independent} operators other than the log's own can cosign (it needs 2)"
        ));
    } else {
        r.fail(
            format!(
                "WITNESSED is unreachable with this directory: {independent} operator{} other than the log's own (it needs 2); the best verdict is CONSISTENT-UNWITNESSED",
                if independent == 1 { "" } else { "s" }
            ),
            "add a witness run by another organisation (docs/wiki/Pilot-Three-Organisations.md: three organisations, one witness each)",
        );
    }
    let need = crate::witness_cmd::default_min(n);
    r.info(format!(
        "`submit` asks for {need} cosignature{} by default (a strict majority of {n}, never below 2); `verify` exits 11 below a majority",
        if need == 1 { "" } else { "s" }
    ));

    if offline {
        r.info("witnesses not contacted (--offline)");
        return;
    }
    // Ask every witness at once, at most 16 in flight.
    let entries: Vec<(String, String, String)> = dir
        .witnesses
        .iter()
        .map(|w| (w.name.clone(), w.url.clone(), w.pubkey.to_ascii_lowercase()))
        .collect();
    let mut results: Vec<(usize, Result<serde_json::Value, String>)> = Vec::new();
    for chunk in entries.chunks(16).enumerate() {
        let (c, batch) = chunk;
        let handles: Vec<_> = batch
            .iter()
            .enumerate()
            .map(|(i, (_, url, _))| {
                let url = url.clone();
                let idx = c * 16 + i;
                std::thread::spawn(move || (idx, probe(&url)))
            })
            .collect();
        for h in handles {
            if let Ok(r) = h.join() {
                results.push(r);
            }
        }
    }
    results.sort_by_key(|(i, _)| *i);
    for (i, res) in results {
        let Some((name, url, key)) = entries.get(i) else {
            continue;
        };
        match res {
            Err(e) => r.fail(
                format!("{name} at {url}: {e}"),
                format!("check the URL and that it is up: curl {url}/health"),
            ),
            Ok(info) => {
                let served = info
                    .get("pubkey_hex")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_ascii_lowercase();
                if served.is_empty() {
                    r.warn(
                        format!("{name} at {url} answers, but not as a witness-log witness (no pubkey_hex)"),
                        "if it is another tlog-witness implementation, check its key by other means",
                    );
                } else if &served != key {
                    r.fail(
                        format!("{name} at {url} serves a different key ({}…) than the directory lists ({}…)", short(&served), short(key)),
                        "the entry is stale or the URL points at another witness: re-add it from the witness's own `witness info`",
                    );
                } else {
                    let open = info
                        .get("open_enrollment")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false);
                    let version = info.get("software").and_then(|v| v.as_str()).unwrap_or("?");
                    if open {
                        r.ok(format!(
                            "{name}: up, key matches, open enrollment ({version})"
                        ));
                    } else {
                        r.warn(
                            format!("{name}: up and key matches, but not open enrollment: it cosigns only logs its operator added ({version})"),
                            "ask its operator to enroll your log's origin, or to run with --open-enrollment",
                        );
                    }
                }
            }
        }
    }
}

fn short(hex: &str) -> &str {
    hex.get(..12).unwrap_or(hex)
}

/// `GET /` on a witness: its self-description as JSON.
fn probe(url: &str) -> Result<serde_json::Value, String> {
    let u = http::parse_url(url)?;
    match http::request(&u, "GET", "/", b"", Duration::from_secs(5)) {
        Ok((200, body, _)) => {
            serde_json::from_slice(&body).map_err(|_| "answers GET / but not with JSON".to_string())
        }
        Ok((status, _, _)) => Err(format!("HTTP {status} for GET /")),
        Err(e) => Err(format!("unreachable: {e}")),
    }
}

// ----------------------------------------------------------------- witness

fn check_witness_dir(r: &mut Report, dir: &Path, offline: bool) {
    r.section(format!("witness {}", dir.display()));
    let cfg_path = dir.join("witness.json");
    let cfg: serde_json::Value = match std::fs::read_to_string(&cfg_path)
        .map_err(|e| e.to_string())
        .and_then(|s| serde_json::from_str(&s).map_err(|e| e.to_string()))
    {
        Ok(v) => v,
        Err(e) => {
            r.fail(
                format!("{}: {e}", cfg_path.display()),
                format!(
                    "witness-log witness init {} --name <host/name> --org <org> --url <public url>",
                    dir.display()
                ),
            );
            return;
        }
    };
    let get = |k: &str| {
        cfg.get(k)
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string()
    };
    let (name, org, url) = (get("key_name"), get("operator_org"), get("public_url"));
    r.ok(format!("{name}, operated by {org:?}, public URL {url}"));
    if org.trim().is_empty() {
        r.fail(
            "no operator organisation: verifiers cannot count it as independent of anyone",
            "set operator_org in witness.json to the organisation that controls this machine and key",
        );
    }

    let key = dir.join("witness.key");
    match std::fs::metadata(&key) {
        Err(_) => r.fail(
            "witness.key is missing: this witness cannot sign",
            "restore witness.key, witness.json and logs/ together from the same backup",
        ),
        Ok(_m) => {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if _m.permissions().mode() & 0o077 != 0 {
                    r.warn(
                        "witness.key is readable by other users",
                        format!("chmod 600 {}", key.display()),
                    );
                } else {
                    r.ok("witness.key present and private");
                }
            }
            #[cfg(not(unix))]
            r.ok("witness.key present");
        }
    }

    let logs = dir.join("logs");
    let probe_file = logs.join(".doctor-write-test");
    match std::fs::write(&probe_file, b"") {
        Ok(()) => {
            let _ = std::fs::remove_file(&probe_file);
            let count = std::fs::read_dir(&logs)
                .map(|it| {
                    it.filter_map(Result::ok)
                        .filter(|e| e.file_name().to_string_lossy().ends_with(".json"))
                        .count()
                })
                .unwrap_or(0);
            r.ok(format!(
                "logs/ writable; {count} log{} witnessed so far",
                if count == 1 { "" } else { "s" }
            ));
        }
        Err(e) => r.fail(
            format!("logs/ is not writable ({e}): every cosignature would fail"),
            format!("fix ownership/permissions of {}", logs.display()),
        ),
    }

    let evidence = std::fs::read_dir(dir.join("evidence"))
        .map(|it| it.filter_map(Result::ok).count())
        .unwrap_or(0);
    if evidence > 0 {
        r.warn(
            format!("{evidence} equivocation proof(s) in evidence/: a log signed two histories and this witness kept the proof"),
            "share them with the parties relying on those logs; `witness-log verify --evidence <file>` turns one into DIVERGED",
        );
    }

    if !offline && (url.starts_with("http://") || url.starts_with("https://")) {
        let own = cfg
            .get("pubkey_hex")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_ascii_lowercase();
        match probe(&url) {
            Ok(info) => {
                let served = info
                    .get("pubkey_hex")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_ascii_lowercase();
                if !own.is_empty() && served != own {
                    r.fail(
                        format!("{url} serves a different key than this directory's"),
                        "public_url points at another witness, or a different state directory is being served",
                    );
                } else {
                    r.ok(format!("{url} answers with this witness's key"));
                }
            }
            Err(e) => r.warn(
                format!("{url}: {e}"),
                "start it (witness-log witness serve <dir> --open-enrollment) and check the proxy in front of it",
            ),
        }
    }
}
