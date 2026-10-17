//! `submit` and `verify` against witnesses reached over `https://`, the way
//! the cloud-init deployment publishes them (TLS terminated by a proxy in
//! front of `witness serve`). Before 0.6.0 the built-in client refused any
//! `https://` URL, so a directory built from deployed witnesses could not
//! be submitted to from the CLI at all.
//!
//! A throwaway CA signs a certificate for `localhost` and `127.0.0.1`; a
//! small rustls proxy terminates TLS in front of each real witness process.
//! `WITNESS_LOG_CA_FILE` makes the client trust that CA; without it the
//! compiled-in Mozilla roots reject the certificate.
#![cfg(feature = "https")]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::Arc;
use std::time::Duration;

const BIN: &str = env!("CARGO_BIN_EXE_witness-log");

fn tmpdir() -> PathBuf {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let p = std::env::temp_dir().join(format!("wl-https-{}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&p).unwrap();
    p
}

struct Witness {
    child: Child,
    dir: PathBuf,
    backend: String,
    entry: serde_json::Value,
}

impl Witness {
    fn start(root: &Path, i: usize) -> Self {
        let dir = root.join(format!("w{i}"));
        let out = Command::new(BIN)
            .args(["witness", "init"])
            .arg(&dir)
            .args([
                "--name",
                &format!("w{i}.test/witness"),
                "--org",
                &format!("TLS Org {i}"),
            ])
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let entry: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
        let mut child = Command::new(BIN)
            .args(["witness", "serve"])
            .arg(&dir)
            .args(["--listen", "127.0.0.1:0", "--open-enrollment"])
            .stderr(Stdio::piped())
            .stdout(Stdio::null())
            .spawn()
            .unwrap();
        let mut lines = BufReader::new(child.stderr.take().unwrap()).lines();
        let url = loop {
            let line = lines.next().expect("witness exited").unwrap();
            if let Some(i) = line.find("http://") {
                break line[i..].split_whitespace().next().unwrap().to_string();
            }
        };
        std::thread::spawn(move || for _ in lines {});
        let backend = url
            .trim_start_matches("http://")
            .trim_end_matches('/')
            .to_string();
        Self {
            child,
            dir,
            backend,
            entry,
        }
    }
}

impl Drop for Witness {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        #[cfg(not(unix))]
        let _ = std::fs::remove_file(self.dir.join("witness.lock"));
        let _ = &self.dir;
    }
}

/// A CA, and a server config whose certificate it signed for
/// `localhost` and `127.0.0.1`. Returns (CA PEM, server config).
fn pki() -> (String, Arc<rustls::ServerConfig>) {
    let ca_key = rcgen::KeyPair::generate().unwrap();
    let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "witness-log test CA");
    let ca = rcgen::CertifiedIssuer::self_signed(ca_params, ca_key).unwrap();

    let leaf_key = rcgen::KeyPair::generate().unwrap();
    let leaf_params =
        rcgen::CertificateParams::new(vec!["localhost".to_string(), "127.0.0.1".to_string()])
            .unwrap();
    let leaf = leaf_params.signed_by(&leaf_key, &ca).unwrap();

    let key = rustls::pki_types::PrivateKeyDer::Pkcs8(rustls::pki_types::PrivatePkcs8KeyDer::from(
        leaf_key.serialize_der(),
    ));
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![leaf.der().clone()], key)
        .unwrap();
    (ca.pem(), Arc::new(config))
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

/// Terminate TLS for one connection and relay the request to `backend`.
fn relay(sock: TcpStream, backend: &str, config: Arc<rustls::ServerConfig>) -> std::io::Result<()> {
    sock.set_read_timeout(Some(Duration::from_secs(10)))?;
    let conn = rustls::ServerConnection::new(config).map_err(std::io::Error::other)?;
    let mut tls = rustls::StreamOwned::new(conn, sock);
    let mut req = Vec::new();
    let mut buf = [0u8; 4096];
    let head_end = loop {
        let n = tls.read(&mut buf)?;
        if n == 0 {
            return Ok(());
        }
        req.extend_from_slice(&buf[..n]);
        if let Some(i) = find(&req, b"\r\n\r\n") {
            break i + 4;
        }
    };
    let head = String::from_utf8_lossy(&req[..head_end]).to_string();
    let len = head
        .lines()
        .filter_map(|l| l.split_once(':'))
        .find(|(n, _)| n.eq_ignore_ascii_case("content-length"))
        .and_then(|(_, v)| v.trim().parse::<usize>().ok())
        .unwrap_or(0);
    while req.len() < head_end + len {
        let n = tls.read(&mut buf)?;
        if n == 0 {
            break;
        }
        req.extend_from_slice(&buf[..n]);
    }
    let mut up = TcpStream::connect(backend)?;
    up.write_all(&req)?;
    let mut resp = Vec::new();
    up.read_to_end(&mut resp)?;
    tls.write_all(&resp)?;
    tls.conn.send_close_notify();
    tls.flush()
}

/// A TLS-terminating proxy in front of `backend`; returns its port.
fn tls_proxy(backend: String, config: Arc<rustls::ServerConfig>) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for sock in listener.incoming().flatten() {
            let (backend, config) = (backend.clone(), config.clone());
            std::thread::spawn(move || {
                let _ = relay(sock, &backend, config);
            });
        }
    });
    port
}

fn cli(args: &[&str], cwd: &Path, ca_file: Option<&Path>) -> Output {
    let mut c = Command::new(BIN);
    c.args(args)
        .current_dir(cwd)
        .env_remove("WITNESS_LOG_CA_FILE");
    if let Some(ca) = ca_file {
        c.env("WITNESS_LOG_CA_FILE", ca);
    }
    c.output().unwrap()
}

fn journal(dir: &Path, name: &str) -> String {
    let out = cli(&["log", "init", name], dir, None);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    for payload in [r#"{"tool":"settle"}"#, r#"{"ok":true}"#] {
        let out = cli(&["log", "append", name, "--intent", payload], dir, None);
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    let out = cli(&["log", "info", name], dir, None);
    let info: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    info["identity"].as_str().unwrap().to_string()
}

#[test]
fn submit_and_verify_over_https() {
    let root = tmpdir();
    let (ca_pem, server_config) = pki();
    let ca_file = root.join("ca.pem");
    std::fs::write(&ca_file, ca_pem).unwrap();

    // One witness by DNS name, one by IP address: both SAN kinds.
    let witnesses: Vec<Witness> = (0..2).map(|i| Witness::start(&root, i)).collect();
    let mut entries = Vec::new();
    for (i, w) in witnesses.iter().enumerate() {
        let port = tls_proxy(w.backend.clone(), server_config.clone());
        let host = if i == 0 { "localhost" } else { "127.0.0.1" };
        let mut e = w.entry.clone();
        e["url"] = serde_json::Value::String(format!("https://{host}:{port}"));
        entries.push(e);
    }
    std::fs::write(
        root.join("dir.json"),
        serde_json::json!({ "witnesses": entries }).to_string(),
    )
    .unwrap();

    let identity = journal(&root, "agent.jsonl");
    let out = cli(
        &[
            "submit",
            "agent.jsonl",
            "--directory",
            "dir.json",
            "--out",
            "d.json",
            "--min",
            "2",
        ],
        &root,
        Some(&ca_file),
    );
    assert!(
        out.status.success(),
        "submit over https failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let out = cli(
        &[
            "verify",
            "d.json",
            "--identity",
            &identity,
            "--directory",
            "dir.json",
            "--json",
        ],
        &root,
        None,
    );
    let rep: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(rep["verdict"], "WITNESSED", "{rep}");
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(rep["report"]["quorum"]["distinct_independent_operators"], 2);

    // Without the test CA the compiled-in roots reject the certificate,
    // and the failure names the reason instead of hanging or cosigning.
    journal(&root, "other.jsonl");
    let out = cli(
        &[
            "submit",
            "other.jsonl",
            "--directory",
            "dir.json",
            "--out",
            "o.json",
            "--min",
            "2",
        ],
        &root,
        None,
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !out.status.success(),
        "an untrusted certificate was accepted: {stderr}"
    );
    assert!(
        stderr.contains("certificate") || stderr.contains("UnknownIssuer"),
        "TLS failure not explained: {stderr}"
    );
    drop(witnesses);
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn unreadable_ca_file_is_reported() {
    let root = tmpdir();
    let out = Command::new(BIN)
        .args(["witness", "init"])
        .arg(root.join("w"))
        .args(["--name", "w.test/witness", "--org", "TLS Org"])
        .output()
        .unwrap();
    let mut entry: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    entry["url"] = serde_json::Value::String("https://127.0.0.1:9".into());
    std::fs::write(
        root.join("dir.json"),
        serde_json::json!({ "witnesses": [entry] }).to_string(),
    )
    .unwrap();
    journal(&root, "agent.jsonl");
    let out = cli(
        &[
            "submit",
            "agent.jsonl",
            "--directory",
            "dir.json",
            "--min",
            "1",
        ],
        &root,
        Some(&root.join("missing.pem")),
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success());
    assert!(stderr.contains("WITNESS_LOG_CA_FILE"), "{stderr}");
    let _ = std::fs::remove_dir_all(&root);
}
