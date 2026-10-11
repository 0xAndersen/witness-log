//! Real witness processes over real sockets, on every CI platform:
//! `witness init` / `serve` / `submit` / `verify`, fork refusal, and
//! state durability across a hard kill. This is the path that a live
//! ten-witness run found two security bugs in (fork acceptance at
//! non-power-of-two sizes; cosigned receipts never counting), so it is
//! exercised end to end here rather than only through library calls.

use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use witness_log_core::identity::IdentityKeypair;
use witness_log_core::journal::JournaledLog;

const BIN: &str = env!("CARGO_BIN_EXE_witness-log");

fn tmpdir(tag: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!(
        "wl-live-{tag}-{}-{}",
        std::process::id(),
        rand_suffix()
    ));
    std::fs::create_dir_all(&p).unwrap();
    p
}

fn rand_suffix() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64
        % 1_000_000_007
}

struct Witness {
    dir: PathBuf,
    child: Option<Child>,
    url: String,
    entry: serde_json::Value,
}

impl Witness {
    fn init(root: &Path, i: usize) -> Self {
        let dir = root.join(format!("w{i}"));
        let out = Command::new(BIN)
            .args(["witness", "init"])
            .arg(&dir)
            .args([
                "--name",
                &format!("w{i}.test/witness"),
                "--org",
                &format!("Org {i}"),
                "--compute",
                &format!("cloud-{i}"),
            ])
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let entry: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
        let mut w = Self {
            dir,
            child: None,
            url: String::new(),
            entry,
        };
        w.start();
        w
    }

    fn start(&mut self) {
        let mut child = Command::new(BIN)
            .args(["witness", "serve"])
            .arg(&self.dir)
            .args(["--listen", "127.0.0.1:0", "--open-enrollment"])
            .stderr(Stdio::piped())
            .stdout(Stdio::null())
            .spawn()
            .unwrap();
        let stderr = child.stderr.take().unwrap();
        let mut lines = BufReader::new(stderr).lines();
        let url = loop {
            let line = lines
                .next()
                .expect("witness exited before listening")
                .unwrap();
            if let Some(i) = line.find("http://") {
                break line[i..].split_whitespace().next().unwrap().to_string();
            }
        };
        // Keep draining stderr so the child never blocks on a full pipe.
        std::thread::spawn(move || for _ in lines {});
        self.entry["url"] = serde_json::Value::String(url.clone());
        self.url = url;
        self.child = Some(child);
    }

    fn kill(&mut self) {
        if let Some(mut c) = self.child.take() {
            let _ = c.kill();
            let _ = c.wait();
        }
        // Windows has no way for the restarting witness to tell that the
        // lock holder died; the operator removes the lock (documented).
        #[cfg(not(unix))]
        let _ = std::fs::remove_file(self.dir.join("witness.lock"));
    }
}

impl Drop for Witness {
    fn drop(&mut self) {
        self.kill();
    }
}

fn journal(path: &Path, seed: &[u8; 32], leaves: &[&[u8]]) {
    let mut j =
        JournaledLog::create(path.to_str().unwrap(), IdentityKeypair::from_bytes(seed)).unwrap();
    for l in leaves {
        j.append_intent(l).unwrap();
    }
    j.sync().unwrap();
}

fn run(args: &[&str]) -> (i32, String) {
    let out = Command::new(BIN).args(args).output().unwrap();
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stderr).to_string(),
    )
}

#[test]
fn live_witnesses_cosign_refuse_forks_and_survive_a_crash() {
    let root = tmpdir("net");
    let mut ws: Vec<Witness> = (0..3).map(|i| Witness::init(&root, i)).collect();
    let dir_path = root.join("directory.json");
    let write_dir = |ws: &[Witness]| {
        let d = serde_json::json!({ "witnesses": ws.iter().map(|w| w.entry.clone()).collect::<Vec<_>>() });
        std::fs::write(&dir_path, serde_json::to_vec(&d).unwrap()).unwrap();
    };
    write_dir(&ws);
    let dir_s = dir_path.to_str().unwrap().to_string();

    let seed = [7u8; 32];
    let identity = hex::encode(
        ed25519_dalek::SigningKey::from_bytes(&seed)
            .verifying_key()
            .to_bytes(),
    );
    // Honest history: 7 leaves (a non-power-of-two size on purpose).
    let honest = root.join("honest.jsonl");
    let leaves: Vec<Vec<u8>> = (0..7).map(|i| format!("event-{i}").into_bytes()).collect();
    let refs: Vec<&[u8]> = leaves.iter().map(|v| v.as_slice()).collect();
    journal(&honest, &seed, &refs);
    let honest_s = honest.to_str().unwrap();
    let dossier = root.join("d.json");
    let (code, err) = run(&[
        "witness",
        "submit",
        honest_s,
        "--directory",
        &dir_s,
        "--out",
        dossier.to_str().unwrap(),
        "--min",
        "3",
    ]);
    assert_eq!(code, 0, "{err}");
    let (code, err) = run(&[
        "verify",
        dossier.to_str().unwrap(),
        "--identity",
        &identity,
        "--directory",
        &dir_s,
    ]);
    assert_eq!(code, 0, "cosigned dossier must be WITNESSED: {err}");

    // Bare relative paths (`submit agent.jsonl --out dossier.json` from the
    // journal's own directory): `Path::parent()` is `Some("")` here and
    // the directory fsync used to fail with ENOENT after the file was
    // already written, turning a successful submit into exit 1.
    let out = Command::new(BIN)
        .current_dir(&root)
        .args([
            "witness",
            "submit",
            "honest.jsonl",
            "--directory",
            "directory.json",
            "--out",
            "relative.json",
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "submit with bare relative paths: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(root.join("relative.json").is_file());
    assert!(!String::from_utf8_lossy(&out.stderr).contains("could not save"));

    // An honest agent whose journal was restored from an old backup and
    // then appended to must be stopped by the client BEFORE it publishes
    // a contradicting history (which witnesses would record as
    // equivocation against its own identity).
    let restored = root.join("restored.jsonl");
    let mut rleaves: Vec<Vec<u8>> = leaves[..4].to_vec();
    rleaves.extend([b"new-a".to_vec(), b"new-b".to_vec(), b"new-c".to_vec()]);
    let rrefs: Vec<&[u8]> = rleaves.iter().map(|v| v.as_slice()).collect();
    journal(&restored, &seed, &rrefs);
    let restored_s = restored.to_str().unwrap().to_string();
    std::fs::copy(
        format!("{honest_s}.witnesses.json"),
        format!("{restored_s}.witnesses.json"),
    )
    .unwrap();
    let (code, err) = run(&[
        "witness",
        "submit",
        &restored_s,
        "--directory",
        &dir_s,
        "--out",
        root.join("r.json").to_str().unwrap(),
    ]);
    assert_ne!(code, 0);
    assert!(err.contains("REFUSING TO SUBMIT"), "{err}");
    for w in &ws {
        assert!(!w.dir.join("evidence").exists(), "nothing was sent");
    }

    // A forking agent (no honest client memory): same identity, rewrite
    // leaf 3, grow to 9.
    let fork = root.join("fork.jsonl");
    let mut fleaves = leaves.clone();
    fleaves[3] = b"rewritten".to_vec();
    fleaves.push(b"x".to_vec());
    fleaves.push(b"y".to_vec());
    let frefs: Vec<&[u8]> = fleaves.iter().map(|v| v.as_slice()).collect();
    journal(&fork, &seed, &frefs);
    let fork_s = fork.to_str().unwrap().to_string();
    let (code, err) = run(&[
        "witness",
        "submit",
        &fork_s,
        "--directory",
        &dir_s,
        "--out",
        root.join("f.json").to_str().unwrap(),
    ]);
    assert_ne!(code, 0);
    assert_eq!(err.matches("REFUSED (422)").count(), 3, "{err}");
    // A growing fork is refused but is not PROVABLE by a witness alone
    // (a junk proof looks the same), so it is not recorded as evidence.
    for w in &ws {
        assert!(!w.dir.join("evidence").exists());
    }

    // Same-size fork: the log signed two roots for size 7. That IS proof,
    // and every witness records it self-contained.
    let same = root.join("same.jsonl");
    let mut sleaves = leaves.clone();
    sleaves[1] = b"other".to_vec();
    let srefs: Vec<&[u8]> = sleaves.iter().map(|v| v.as_slice()).collect();
    journal(&same, &seed, &srefs);
    let same_s = same.to_str().unwrap().to_string();
    let (code, err) = run(&[
        "witness",
        "submit",
        &same_s,
        "--directory",
        &dir_s,
        "--out",
        root.join("s.json").to_str().unwrap(),
    ]);
    assert_ne!(code, 0);
    assert_eq!(err.matches("REFUSED (422)").count(), 3, "{err}");
    for w in &ws {
        let files: Vec<_> = std::fs::read_dir(w.dir.join("evidence"))
            .expect("evidence dir")
            .collect();
        assert_eq!(files.len(), 1, "one proof per log");
        let ev = std::fs::read_to_string(files[0].as_ref().unwrap().path()).unwrap();
        let line: serde_json::Value = serde_json::from_str(&ev).unwrap();
        let proof: witness_log_network::tlog_witness::EquivocationProof =
            serde_json::from_value(line["proof"].clone()).unwrap();
        assert!(proof.verify(), "evidence must verify independently");
    }

    // Hard-kill one witness and restart it: its state must survive.
    ws[0].kill();
    ws[0].start();
    write_dir(&ws);
    let (code, err) = run(&[
        "witness",
        "submit",
        &fork_s,
        "--directory",
        &dir_s,
        "--out",
        root.join("f2.json").to_str().unwrap(),
    ]);
    assert_ne!(code, 0);
    assert_eq!(
        err.matches("REFUSED (422)").count(),
        3,
        "after restart: {err}"
    );

    // The honest log keeps advancing through all three.
    let mut j = JournaledLog::resume(honest_s).unwrap().0;
    j.append_intent(b"later").unwrap();
    j.sync().unwrap();
    drop(j);
    let (code, err) = run(&[
        "witness",
        "submit",
        honest_s,
        "--directory",
        &dir_s,
        "--out",
        dossier.to_str().unwrap(),
        "--min",
        "3",
    ]);
    assert_eq!(code, 0, "{err}");
    drop(ws);
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn witness_rejects_hostile_http() {
    use std::io::{Read, Write};
    let root = tmpdir("http");
    let w = Witness::init(&root, 0);
    let addr = w.url.trim_start_matches("http://").to_string();
    let send = |raw: &[u8]| -> u16 {
        let mut s = std::net::TcpStream::connect(&addr).unwrap();
        s.set_read_timeout(Some(std::time::Duration::from_secs(15)))
            .unwrap();
        let _ = s.write_all(raw);
        let mut out = Vec::new();
        let _ = s.read_to_end(&mut out);
        String::from_utf8_lossy(&out)
            .split(' ')
            .nth(1)
            .and_then(|c| c.parse().ok())
            .unwrap_or(0)
    };
    assert_eq!(send(b"GET /health HTTP/1.1\r\n\r\n"), 200);
    assert_eq!(send(b"GET /nope HTTP/1.1\r\n\r\n"), 404);
    assert_eq!(send(b"PUT /add-checkpoint HTTP/1.1\r\n\r\n"), 405);
    assert_eq!(send(b"POST /add-checkpoint HTTP/1.1\r\n\r\n"), 411);
    assert_eq!(
        send(b"POST /add-checkpoint HTTP/1.1\r\nContent-Length: 99999999\r\n\r\n"),
        413
    );
    assert_eq!(
        send(b"POST /add-checkpoint HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n"),
        501
    );
    assert_eq!(
        send(b"POST /add-checkpoint HTTP/1.1\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\nx"),
        400
    );
    assert_eq!(
        send(b"POST /add-checkpoint HTTP/1.1\r\nContent-Length: 3\r\n\r\nabc"),
        400
    );
    let mut big = b"GET / HTTP/1.1\r\nX: ".to_vec();
    big.extend(std::iter::repeat(b'a').take(20_000));
    big.extend_from_slice(b"\r\n\r\n");
    assert_eq!(send(&big), 431);
    // Still healthy after all of that.
    assert_eq!(send(b"GET /health HTTP/1.1\r\n\r\n"), 200);
    drop(w);
    let _ = std::fs::remove_dir_all(&root);
}
