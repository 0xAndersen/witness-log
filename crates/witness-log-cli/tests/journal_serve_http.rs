//! `witness-log journal serve`: a real socket, JSON in and out, and a
//! submit round against a local testnet. The front is what an agent in a
//! language without bindings talks to, so the contract is the HTTP
//! surface itself.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

const BIN: &str = env!("CARGO_BIN_EXE_witness-log");

fn tmpdir(tag: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!(
        "wl-jserve-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&p).unwrap();
    p
}

fn wl(cwd: &Path, args: &[&str]) -> std::process::Output {
    Command::new(BIN)
        .current_dir(cwd)
        .args(args)
        .output()
        .unwrap()
}

struct Front {
    child: Child,
    addr: String,
    /// Read on Windows only, to remove the lock a killed front leaves.
    #[allow(dead_code)]
    journal: PathBuf,
}

impl Front {
    fn start(root: &Path, journal: &Path, extra: &[&str]) -> Self {
        let mut child = Command::new(BIN)
            .current_dir(root)
            .args(["journal", "serve"])
            .arg(journal)
            .args(["--listen", "127.0.0.1:0"])
            .args(extra)
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let stderr = child.stderr.take().unwrap();
        let mut lines = BufReader::new(stderr).lines();
        let addr = loop {
            let line = lines
                .next()
                .expect("journal serve exited before listening")
                .unwrap();
            if let Some(i) = line.find("http://") {
                break line[i + 7..].split_whitespace().next().unwrap().to_string();
            }
        };
        std::thread::spawn(move || for _ in lines {});
        Self {
            child,
            addr,
            journal: journal.to_path_buf(),
        }
    }

    /// (status, body)
    fn call(&self, method: &str, path: &str, body: &str) -> (u16, serde_json::Value) {
        let (status, text) = self.raw(method, path, body);
        let v = serde_json::from_str(&text).unwrap_or(serde_json::Value::String(text));
        (status, v)
    }

    fn raw(&self, method: &str, path: &str, body: &str) -> (u16, String) {
        let mut s = TcpStream::connect(&self.addr).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(60))).unwrap();
        let req = format!(
            "{method} {path} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            self.addr,
            body.len()
        );
        s.write_all(req.as_bytes()).unwrap();
        let mut out = String::new();
        s.read_to_string(&mut out).unwrap();
        let status: u16 = out.split(' ').nth(1).unwrap().parse().unwrap();
        let body = out.split("\r\n\r\n").nth(1).unwrap_or("").to_string();
        (status, body)
    }

    fn stop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        #[cfg(not(unix))]
        let _ = std::fs::remove_file(format!("{}.lock", self.journal.display()));
    }
}

impl Drop for Front {
    fn drop(&mut self) {
        self.stop();
    }
}

#[test]
fn append_forget_info_dossier_over_http() {
    let root = tmpdir("basic");
    let journal = root.join("agent.jsonl");
    let init = wl(&root, &["log", "init", journal.to_str().unwrap()]);
    assert!(
        init.status.success(),
        "{}",
        String::from_utf8_lossy(&init.stderr)
    );
    let f = Front::start(&root, &journal, &[]);

    let (st, v) = f.call("GET", "/info", "");
    assert_eq!(st, 200, "{v}");
    assert_eq!(v["tree_size"], 0);
    let identity = v["identity"].as_str().unwrap().to_string();
    assert_eq!(v["origin"], format!("witness-log/{identity}"));

    let (st, v) = f.call(
        "POST",
        "/append",
        r#"{"kind":"intent","payload":"{\"tool\":\"pay\"}"}"#,
    );
    assert_eq!(st, 200, "{v}");
    assert_eq!(v["index"], 0);
    assert_eq!(v["payload_hash"].as_str().unwrap().len(), 64);
    // A JSON value as payload is committed as compact JSON; a result may
    // carry an outcome.
    let (st, v) = f.call(
        "POST",
        "/append",
        r#"{"kind":"result","payload":{"tx":"ok"},"outcome":"ok"}"#,
    );
    assert_eq!(st, 200, "{v}");
    assert_eq!(v["index"], 1);
    assert_eq!(
        v["committed_payload"],
        r#"{"outcome":"ok","value":"{\"tx\":\"ok\"}"}"#
    );
    let (st, _) = f.call("POST", "/append", r#"{"kind":"memory","payload":"note"}"#);
    assert_eq!(st, 200);

    // Bad input is 400 with a reason, not a crash and not a leaf.
    for body in [
        r#"{"kind":"nope","payload":"x"}"#,
        r#"{"kind":"intent"}"#,
        r#"{"kind":"intent","payload":"x","outcome":"ok"}"#,
        r#"{"kind":"result","payload":"x","outcome":"maybe"}"#,
        "not json",
    ] {
        let (st, v) = f.call("POST", "/append", body);
        assert_eq!(st, 400, "{body}: {v}");
        assert!(v["error"].is_string(), "{v}");
    }
    let (st, _) = f.call("GET", "/append", "");
    assert_eq!(st, 405);
    let (st, _) = f.call("GET", "/nope", "");
    assert_eq!(st, 404);
    let (st, v) = f.call("GET", "/info", "");
    assert_eq!(st, 200);
    assert_eq!(v["tree_size"], 3, "rejected requests appended nothing");

    // forget: tombstone appended; twice is 409; out of range is 404.
    let (st, v) = f.call("POST", "/forget", r#"{"index":1}"#);
    assert_eq!(st, 200, "{v}");
    assert_eq!(v["tombstone_index"], 3);
    assert_eq!(v["tree_size"], 4);
    let (st, _) = f.call("POST", "/forget", r#"{"index":1}"#);
    assert_eq!(st, 409);
    let (st, _) = f.call("POST", "/forget", r#"{"index":40}"#);
    assert_eq!(st, 404);
    let (st, _) = f.call("POST", "/forget", r#"{"index":"one"}"#);
    assert_eq!(st, 400);

    // The dossier verifies offline (UNANCHORED without a directory).
    let (st, d) = f.call("GET", "/dossier", "");
    assert_eq!(st, 200);
    assert_eq!(d["leaves"].as_array().unwrap().len(), 4);
    std::fs::write(root.join("d.json"), d.to_string()).unwrap();
    let v = wl(&root, &["verify", "d.json", "--identity", &identity]);
    assert_eq!(
        v.status.code(),
        Some(20),
        "{}",
        String::from_utf8_lossy(&v.stdout)
    );

    // No submit without a directory configured or given.
    let (st, v) = f.call("POST", "/submit", "{}");
    assert_eq!(st, 400, "{v}");

    // The journal is locked while served: `log append` is refused, and
    // the on-disk journal replays to the same head once the front stops.
    let a = wl(
        &root,
        &["log", "append", journal.to_str().unwrap(), "--intent", "x"],
    );
    assert_eq!(
        a.status.code(),
        Some(1),
        "{}",
        String::from_utf8_lossy(&a.stderr)
    );
    drop(f);
    let info = wl(&root, &["log", "info", journal.to_str().unwrap()]);
    assert!(
        info.status.success(),
        "{}",
        String::from_utf8_lossy(&info.stderr)
    );
    let info: serde_json::Value = serde_json::from_slice(&info.stdout).unwrap();
    assert_eq!(info["tree_size"], 4);
    assert_eq!(info["leaves"]["redaction"], 1);
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn submit_over_http_reaches_witnessed() {
    let root = tmpdir("submit");
    let tn = root.join("tn").display().to_string();
    let trusted = root.join("trusted.json").display().to_string();
    let up = wl(
        &root,
        &[
            "testnet",
            "up",
            "--witnesses",
            "3",
            "--dir",
            &tn,
            "--out",
            &trusted,
        ],
    );
    assert!(
        up.status.success(),
        "{}",
        String::from_utf8_lossy(&up.stderr)
    );
    // Stops the testnet and removes the directory, in that order, on every
    // exit path (`testnet down` runs with `root` as its cwd).
    struct Down(PathBuf, String);
    impl Drop for Down {
        fn drop(&mut self) {
            let _ = wl(&self.0, &["testnet", "down", "--dir", &self.1]);
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    let _down = Down(root.clone(), tn.clone());

    let journal = root.join("agent.jsonl");
    assert!(wl(&root, &["log", "init", journal.to_str().unwrap()])
        .status
        .success());
    let f = Front::start(&root, &journal, &["--directory", &trusted]);
    for i in 0..3 {
        let (st, _) = f.call(
            "POST",
            "/append",
            &format!(r#"{{"kind":"intent","payload":"step {i}"}}"#),
        );
        assert_eq!(st, 200);
    }
    let (st, v) = f.call("POST", "/submit", "{}");
    assert_eq!(st, 200, "{v}");
    assert_eq!(v["ok"], true);
    assert_eq!(v["cosigned"], 3);
    assert_eq!(v["min"], 2, "fail-closed default: majority of 3");
    assert_eq!(v["verdict"], "WITNESSED");
    assert_eq!(v["tree_size"], 3);

    // GET /dossier now carries the receipts, and verifies WITNESSED.
    let (st, d) = f.call("GET", "/dossier", "");
    assert_eq!(st, 200);
    assert_eq!(d["witness_receipts"].as_array().unwrap().len(), 3);
    std::fs::write(root.join("w.json"), d.to_string()).unwrap();
    let (_, info) = f.call("GET", "/info", "");
    let identity = info["identity"].as_str().unwrap().to_string();
    assert_eq!(info["witnessed_size"], 3);
    let v = wl(
        &root,
        &[
            "verify",
            "w.json",
            "--identity",
            &identity,
            "--directory",
            &trusted,
            "--strict",
        ],
    );
    assert_eq!(
        v.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&v.stdout)
    );

    // The head moves on: /dossier is the unwitnessed current head again.
    let (st, _) = f.call("POST", "/append", r#"{"kind":"memory","payload":"later"}"#);
    assert_eq!(st, 200);
    let (_, d) = f.call("GET", "/dossier", "");
    assert_eq!(d["leaves"].as_array().unwrap().len(), 4);
    assert_eq!(d["witness_receipts"].as_array().unwrap().len(), 0);

    // `want` picks a subset through diversity-aware selection; `min` is
    // honoured; an unmeetable min is 503, not 200.
    let (st, v) = f.call("POST", "/submit", r#"{"want":2}"#);
    assert_eq!(st, 200, "{v}");
    assert_eq!(v["contacted"], 2);
    assert_eq!(v["cosigned"], 2);
    let (st, _) = f.call("POST", "/append", r#"{"kind":"memory","payload":"again"}"#);
    assert_eq!(st, 200);
    let (st, v) = f.call("POST", "/submit", r#"{"want":1,"min":2}"#);
    assert_eq!(st, 503, "{v}");
    assert_eq!(v["ok"], false);
    let (st, v) = f.call(
        "POST",
        "/submit",
        r#"{"directory_path":"/nonexistent.json"}"#,
    );
    assert_eq!(st, 400, "{v}");
    drop(f);
}

#[test]
fn refuses_a_non_loopback_bind_without_allow_remote() {
    let root = tmpdir("bind");
    let journal = root.join("a.jsonl");
    assert!(wl(&root, &["log", "init", journal.to_str().unwrap()])
        .status
        .success());
    let out = wl(
        &root,
        &[
            "journal",
            "serve",
            journal.to_str().unwrap(),
            "--listen",
            "0.0.0.0:0",
        ],
    );
    assert_eq!(
        out.status.code(),
        Some(2),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(String::from_utf8_lossy(&out.stderr).contains("--allow-remote"));
    let out = wl(
        &root,
        &[
            "journal",
            "serve",
            journal.to_str().unwrap(),
            "--listn",
            "x",
        ],
    );
    assert_eq!(out.status.code(), Some(2));
    let _ = std::fs::remove_dir_all(&root);
}

/// Security sweep of 0.6.0, F1: a web page in the user's browser is a
/// loopback peer too. Its `fetch(..., {mode: "no-cors", method: "POST"})`
/// carries an `Origin` header and a DNS-rebinding page sends a `Host` that
/// is not a loopback name; both are refused, while ordinary local clients
/// (no Origin, a loopback Host, or no Host at all) are served as before.
#[test]
fn requests_a_browser_could_send_are_refused() {
    let root = tmpdir("browser");
    let journal = root.join("agent.jsonl");
    assert!(wl(&root, &["log", "init", journal.to_str().unwrap()])
        .status
        .success());
    let front = Front::start(&root, &journal, &[]);
    let port = front.addr.rsplit_once(':').unwrap().1.to_string();
    let send = |head: &str, body: &str| -> (u16, String) {
        let mut s = TcpStream::connect(&front.addr).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(30))).unwrap();
        let req = format!(
            "POST /append HTTP/1.1\r\n{head}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        s.write_all(req.as_bytes()).unwrap();
        let mut out = String::new();
        s.read_to_string(&mut out).unwrap();
        let status: u16 = out.split(' ').nth(1).unwrap().parse().unwrap();
        (status, out)
    };
    let leaf = r#"{"kind":"result","payload":"forged by a web page"}"#;
    // A cross-site "simple request" from a page.
    let (st, out) = send(
        &format!("Host: 127.0.0.1:{port}\r\nOrigin: https://evil.example\r\nContent-Type: text/plain\r\n"),
        leaf,
    );
    assert_eq!(st, 403, "{out}");
    // DNS rebinding: the page's own host name now resolves to 127.0.0.1.
    let (st, out) = send(&format!("Host: rebind.evil.example:{port}\r\n"), leaf);
    assert_eq!(st, 403, "{out}");
    // A loopback name on another port is not this server either.
    let (st, _) = send("Host: localhost:1\r\n", leaf);
    assert_eq!(st, 403);
    // Nothing was appended.
    let (_, info) = front.call("GET", "/info", "");
    assert_eq!(info["tree_size"], 0, "{info}");
    // Local programs: loopback Host spellings, or none at all.
    for host in [
        format!("Host: 127.0.0.1:{port}\r\n"),
        format!("Host: localhost:{port}\r\n"),
        format!("Host: LOCALHOST:{port}\r\n"),
        String::new(),
    ] {
        let (st, out) = send(&host, r#"{"kind":"intent","payload":"ok"}"#);
        assert_eq!(st, 200, "{host:?}: {out}");
    }
    let (_, info) = front.call("GET", "/info", "");
    assert_eq!(info["tree_size"], 4, "{info}");
}
