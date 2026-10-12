//! `witness-log journal serve <journal>` -- a small HTTP front for one
//! journal, so an agent written in any language appends, redacts and gets
//! witnessed with plain HTTP calls and no bindings.
//!
//! Endpoints (JSON in, JSON out):
//!
//! | method | path       | body                                  |
//! |--------|------------|---------------------------------------|
//! | POST   | /append    | `{"kind":"intent|result|memory","payload":<string or JSON>,"outcome":"ok|error"?}` |
//! | POST   | /forget    | `{"index":N}`                         |
//! | POST   | /submit    | `{"directory_path":"..."?,"want":N?,"min":N?}` |
//! | GET    | /dossier   | the current dossier (witnessed if the head is unchanged since the last submit) |
//! | GET    | /info      | identity, origin, size, root, witnessed size |
//! | GET    | /health    | `ok`                                  |
//!
//! The process holds the journal's lock for as long as it runs, exactly
//! as an agent embedding the library would; `log append` on the same file
//! is refused meanwhile. Loopback only unless `--allow-remote`: the
//! front has no authentication, and whoever can reach it can write to
//! the agent's history.

use crate::http::{self, Request, Response};
use std::process::ExitCode;
use std::sync::{Arc, Mutex};
use witness_log_core::journal::JournaledLog;
use witness_log_network::{Dossier, WitnessDirectory};

const USAGE: &str = "usage:
  witness-log journal serve <journal> [--listen 127.0.0.1:7390] [--directory trusted.json]
                                      [--state <client-state.json>] [--allow-remote]
                                      [--identity-seed-env NAME | --identity-seed-file F]
      POST /append  {\"kind\":\"intent|result|memory\",\"payload\":\"...\",\"outcome\":\"ok|error\"?}
      POST /forget  {\"index\":N}
      POST /submit  {\"directory_path\":\"...\"?,\"want\":N?,\"min\":N?}   (directory_path defaults to --directory)
      GET  /dossier    GET /info    GET /health
      Binds loopback only unless --allow-remote (there is no authentication).";

fn usage_err(msg: &str) -> ExitCode {
    eprintln!("{msg}\n\n{USAGE}");
    ExitCode::from(2)
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
        Some("serve") => cmd_serve(rest),
        _ => usage_err("journal: expected `serve`"),
    }
}

struct State {
    /// `None` only while shutting down on a signal, so the lock file is
    /// released before the process exits.
    log: Option<JournaledLog>,
    journal: String,
    directory_path: Option<String>,
    state_path: String,
    /// The dossier the last successful submit produced, served by GET
    /// /dossier while the head has not moved.
    witnessed: Option<Dossier>,
    allow_remote: bool,
}

fn cmd_serve(args: &[String]) -> ExitCode {
    let mut positional = Vec::new();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--listen"
            | "--directory"
            | "--state"
            | "--identity-seed-env"
            | "--identity-seed-file" => {
                if args.get(i + 1).is_none() {
                    return usage_err(&format!("journal serve: {} requires a value", args[i]));
                }
                i += 2;
            }
            "--allow-remote" => i += 1,
            a if a.starts_with("--") => {
                return usage_err(&format!("journal serve: unrecognized flag {a}"))
            }
            _ => {
                positional.push(args[i].clone());
                i += 1;
            }
        }
    }
    let [journal] = positional.as_slice() else {
        return usage_err("journal serve: expected exactly one <journal>");
    };
    let listen = crate::flag_value(args, "--listen").unwrap_or_else(|| "127.0.0.1:7390".into());
    let allow_remote = args.iter().any(|a| a == "--allow-remote");
    let seed = match crate::identity_seed_from_args(args) {
        Ok(s) => s,
        Err(e) => return usage_err(&format!("journal serve: {e}")),
    };
    let directory_path = crate::flag_value(args, "--directory");
    if let Some(d) = &directory_path {
        // Fail now, not on the first /submit.
        if let Err(e) = crate::read_input(d)
            .map_err(|e| e.to_string())
            .and_then(|s| crate::parse_directory(&s))
        {
            eprintln!("{d}: {e}");
            return ExitCode::from(2);
        }
    }
    let state_path =
        crate::flag_value(args, "--state").unwrap_or_else(|| format!("{journal}.witnesses.json"));

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
            "refusing to listen on {bound}: this front has no authentication. Bind 127.0.0.1 or pass --allow-remote and put it behind something that does."
        );
        return ExitCode::from(2);
    }
    let (log, report) = match crate::resume_journal(journal, seed.as_deref()) {
        Ok(x) => x,
        Err(e) => {
            eprintln!("{journal}: {e}");
            return ExitCode::from(1);
        }
    };
    if report.dropped_trailing_lines > 0 {
        eprintln!("note: {journal} had a partially written last line; it was dropped");
    }
    eprintln!(
        "journal {journal} ({} leaves, identity {}) listening on http://{bound}",
        log.log().tree_size(),
        log.log().identity_pubkey_hex()
    );
    let state = Arc::new(Mutex::new(State {
        log: Some(log),
        journal: journal.clone(),
        directory_path,
        state_path,
        witnessed: None,
        allow_remote,
    }));
    #[cfg(unix)]
    stop_cleanly_on_signal(state.clone());
    let handler = Arc::new(move |req: &Request| route(&state, req));
    http::serve(listener, 64, 16, handler);
    ExitCode::SUCCESS
}

/// Drop the journal (releasing its lock file) on SIGTERM/SIGINT, then
/// exit 0. Same arrangement as `witness serve`.
#[cfg(unix)]
fn stop_cleanly_on_signal(state: Arc<Mutex<State>>) {
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
                let mut s = state.lock().unwrap_or_else(|e| e.into_inner());
                if let Some(mut log) = s.log.take() {
                    let _ = log.sync();
                }
                eprintln!("journal serve stopping on signal {sig}");
                std::process::exit(0);
            }
        });
    }
}

fn json_err(status: u16, msg: impl std::fmt::Display) -> Response {
    Response::json(
        status,
        serde_json::json!({ "error": msg.to_string() }).to_string(),
    )
}

fn route(state: &Arc<Mutex<State>>, req: &Request) -> Response {
    {
        let s = state.lock().unwrap_or_else(|e| e.into_inner());
        if !s.allow_remote && !req.peer.ip().is_loopback() {
            return json_err(
                403,
                "loopback clients only (start with --allow-remote to change)",
            );
        }
    }
    match (req.method.as_str(), req.path.as_str()) {
        ("GET", "/health") => Response::text(200, "ok\n"),
        ("GET", "/info") => info(state),
        ("GET", "/dossier") => dossier(state),
        ("POST", "/append") => append(state, req),
        ("POST", "/forget") => forget(state, req),
        ("POST", "/submit") => submit(state, req),
        (_, "/health")
        | (_, "/info")
        | (_, "/dossier")
        | (_, "/append")
        | (_, "/forget")
        | (_, "/submit") => json_err(405, "method not allowed"),
        _ => json_err(404, "not found"),
    }
}

fn parse_body(req: &Request) -> Result<serde_json::Value, Response> {
    if req.body.is_empty() {
        return Ok(serde_json::Value::Object(Default::default()));
    }
    serde_json::from_slice(&req.body).map_err(|e| json_err(400, format!("body is not JSON: {e}")))
}

fn with_log<T>(s: &mut State, f: impl FnOnce(&mut JournaledLog) -> T) -> Result<T, Response> {
    match s.log.as_mut() {
        Some(log) => Ok(f(log)),
        None => Err(json_err(503, "shutting down")),
    }
}

fn info(state: &Arc<Mutex<State>>) -> Response {
    let mut s = state.lock().unwrap_or_else(|e| e.into_inner());
    let journal = s.journal.clone();
    let directory_path = s.directory_path.clone();
    let witnessed = s
        .witnessed
        .as_ref()
        .map(|d| (d.checkpoint.tree_size, d.witness_receipts.len()));
    let body = with_log(&mut s, |log| {
        let l = log.log();
        let key = ed25519_dalek::SigningKey::from_bytes(&l.identity_bytes());
        serde_json::json!({
            "software": format!("witness-log {}", env!("CARGO_PKG_VERSION")),
            "journal": journal,
            "identity": l.identity_pubkey_hex(),
            "origin": witness_log_core::c2sp::canonical_origin(&key.verifying_key()),
            "tree_size": l.tree_size(),
            "root": l.root_hex(),
            "directory": directory_path,
            "witnessed_size": witnessed.map(|w| w.0),
            "witnessed_cosignatures": witnessed.map(|w| w.1),
        })
    });
    match body {
        Ok(b) => Response::json(200, serde_json::to_string_pretty(&b).unwrap_or_default()),
        Err(r) => r,
    }
}

fn dossier(state: &Arc<Mutex<State>>) -> Response {
    let mut s = state.lock().unwrap_or_else(|e| e.into_inner());
    let cached = s.witnessed.clone();
    let doc = with_log(&mut s, |log| {
        let size = log.log().tree_size();
        match cached {
            Some(d) if d.checkpoint.tree_size == size => d,
            _ => Dossier::from_log(log.log(), log.log().checkpoint_self()),
        }
    });
    match doc {
        Ok(d) => Response::json(200, serde_json::to_string_pretty(&d).unwrap_or_default()),
        Err(r) => r,
    }
}

fn append(state: &Arc<Mutex<State>>, req: &Request) -> Response {
    let body = match parse_body(req) {
        Ok(b) => b,
        Err(r) => return r,
    };
    let kind = body.get("kind").and_then(|k| k.as_str()).unwrap_or("");
    if !matches!(kind, "intent" | "result" | "memory") {
        return json_err(400, "kind must be intent, result or memory");
    }
    let Some(payload) = body.get("payload") else {
        return json_err(
            400,
            "payload is required (a string, or a JSON value committed as compact JSON)",
        );
    };
    let raw: Vec<u8> = match payload {
        serde_json::Value::String(s) => s.as_bytes().to_vec(),
        other => serde_json::to_vec(other).unwrap_or_default(),
    };
    let outcome = match body.get("outcome") {
        None | Some(serde_json::Value::Null) => None,
        Some(serde_json::Value::String(o)) if o == "ok" || o == "error" => Some(o.clone()),
        Some(_) => return json_err(400, "outcome must be \"ok\" or \"error\""),
    };
    if outcome.is_some() && kind != "result" {
        return json_err(400, "outcome applies to kind \"result\" only");
    }
    let committed = match &outcome {
        Some(o) => serde_json::to_vec(&serde_json::json!({
            "outcome": o,
            "value": String::from_utf8_lossy(&raw).into_owned(),
        }))
        .unwrap_or_default(),
        None => raw,
    };
    let mut s = state.lock().unwrap_or_else(|e| e.into_inner());
    let res = with_log(&mut s, |log| {
        let r = match kind {
            "intent" => log.append_intent(&committed),
            "result" => log.append_result(&committed),
            _ => log.append_memory(&committed),
        };
        r.and_then(|i| log.sync().map(|_| i)).map(|i| {
            let l = log.log();
            serde_json::json!({
                "index": i,
                "leaf_type": kind,
                "payload_hash": l.leaves().get(usize::try_from(i).unwrap_or(usize::MAX)).map(|x| x.payload_hash.clone()),
                "committed_payload": outcome.as_ref().map(|_| String::from_utf8_lossy(&committed).into_owned()),
                "tree_size": l.tree_size(),
                "root": l.root_hex(),
            })
        })
    });
    match res {
        Ok(Ok(doc)) => Response::json(200, doc.to_string()),
        Ok(Err(e)) => json_err(500, format!("append failed: {e}")),
        Err(r) => r,
    }
}

fn forget(state: &Arc<Mutex<State>>, req: &Request) -> Response {
    let body = match parse_body(req) {
        Ok(b) => b,
        Err(r) => return r,
    };
    let Some(index) = body.get("index").and_then(|i| i.as_u64()) else {
        return json_err(400, "index must be a non-negative integer");
    };
    let mut s = state.lock().unwrap_or_else(|e| e.into_inner());
    let res = with_log(&mut s, |log| {
        let size = log.log().tree_size();
        if index >= size {
            return Err(json_err(
                404,
                format!("leaf {index} does not exist (tree size {size})"),
            ));
        }
        match log.forget(index).and_then(|f| log.sync().map(|_| f)) {
            Ok(true) => Ok(serde_json::json!({
                "forgotten": index,
                "tombstone_index": size,
                "tree_size": log.log().tree_size(),
                "root": log.log().root_hex(),
            })),
            Ok(false) => Err(json_err(
                409,
                format!("leaf {index} has no salt to erase (already forgotten or a marker leaf)"),
            )),
            Err(e) => Err(json_err(500, format!("forget failed: {e}"))),
        }
    });
    match res {
        Ok(Ok(doc)) => Response::json(200, doc.to_string()),
        Ok(Err(r)) | Err(r) => r,
    }
}

fn submit(state: &Arc<Mutex<State>>, req: &Request) -> Response {
    let body = match parse_body(req) {
        Ok(b) => b,
        Err(r) => return r,
    };
    let mut s = state.lock().unwrap_or_else(|e| e.into_inner());
    let requested_path = body.get("directory_path").and_then(|p| p.as_str());
    // A remote caller must not be able to point this process at arbitrary
    // files; it gets the directory the operator configured.
    if requested_path.is_some() && !req.peer.ip().is_loopback() {
        return json_err(403, "directory_path may only be set by a loopback client");
    }
    let Some(dir_path) = requested_path
        .map(str::to_string)
        .or_else(|| s.directory_path.clone())
    else {
        return json_err(
            400,
            "no directory: pass directory_path or start with --directory",
        );
    };
    let directory: WitnessDirectory = match crate::read_input(&dir_path)
        .map_err(|e| e.to_string())
        .and_then(|raw| crate::parse_directory(&raw))
    {
        Ok(d) => d,
        Err(e) => return json_err(400, format!("{dir_path}: {e}")),
    };
    let want = body.get("want").and_then(|w| w.as_u64());
    let contact: Vec<witness_log_network::WitnessEntry> = match want {
        Some(w) => {
            let identity = match s.log.as_ref() {
                Some(l) => l.log().identity_pubkey_hex(),
                None => return json_err(503, "shutting down"),
            };
            let picked = witness_log_network::select_diverse_witnesses(
                &directory,
                &identity,
                usize::try_from(w).unwrap_or(usize::MAX),
                true,
            );
            picked.into_iter().cloned().collect()
        }
        None => directory.witnesses.clone(),
    };
    let min = match body.get("min") {
        None | Some(serde_json::Value::Null) => crate::witness_cmd::default_min(contact.len()),
        Some(m) => match m.as_u64() {
            Some(n) => usize::try_from(n).unwrap_or(usize::MAX),
            None => return json_err(400, "min must be a non-negative integer"),
        },
    };
    let state_path = s.state_path.clone();
    let result = with_log(&mut s, |log| {
        crate::witness_cmd::submit_log(log.log(), &directory, &contact, &state_path)
    });
    let report = match result {
        Ok(Ok(r)) => r,
        Ok(Err(e)) => return json_err(409, e),
        Err(r) => return r,
    };
    let ctx = witness_log_network::VerifyContext {
        expected_identity_pubkey: Some(&report.dossier.identity_pubkey),
        trusted_directory: Some(&directory),
        min_receipts: Some(min),
        revocations: &[],
    };
    let verdict = report
        .dossier
        .verify(crate::DEFAULT_QUORUM_THRESHOLD, &ctx)
        .verdict;
    let ok = report.refused_422 == 0 && report.cosigned >= min;
    if report.cosigned > 0 {
        s.witnessed = Some(report.dossier.clone());
    }
    let doc = serde_json::json!({
        "ok": ok,
        "cosigned": report.cosigned,
        "contacted": contact.len(),
        "refused_422": report.refused_422,
        "min": min,
        "tree_size": report.dossier.checkpoint.tree_size,
        "verdict": verdict.to_string(),
        "witnesses": report.lines.iter().map(|l| l.trim()).collect::<Vec<_>>(),
        "origin": report.origin,
    });
    let status = if ok {
        200
    } else if report.refused_422 > 0 {
        422
    } else {
        503
    };
    Response::json(
        status,
        serde_json::to_string_pretty(&doc).unwrap_or_default(),
    )
}
