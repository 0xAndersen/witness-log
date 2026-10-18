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
    // already written, turning a successful submit into exit 1. No --min:
    // the fail-closed default is max(2, 3/2+1) = 2, met by three cosigners.
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
    // Fail-closed: a 422 from any witness is exit 20 (0.3.6 exited 1 only
    // when fewer than `--min`, default 1, cosigned).
    assert_eq!(code, 20, "{err}");
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
    assert_eq!(code, 20, "{err}");
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
    assert_eq!(code, 20, "after restart: {err}");
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

/// `logs` as the witness's `GET /` reports it.
fn logs_reported(w: &Witness) -> u64 {
    let out = Command::new(BIN)
        .args(["witness", "info", &w.url])
        .output()
        .unwrap();
    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    v["logs"].as_u64().unwrap()
}

fn record_name(seed: &[u8; 32]) -> String {
    use sha2::Digest;
    let origin = witness_log_core::c2sp::canonical_origin(
        &ed25519_dalek::SigningKey::from_bytes(seed).verifying_key(),
    );
    format!(
        "{}.json",
        hex::encode(sha2::Sha256::digest(origin.as_bytes()))
    )
}

/// Through 0.5.0 `serve` parsed every record in `logs/` before listening, so
/// start-up time and memory grew with every log the witness had ever
/// cosigned (minutes for ~25,000 logs on a cold disk: the 100,000-agent
/// load test). Records are now read when a request for their origin
/// arrives. A record that cannot be read must still fail closed for its
/// log, never be taken for a log the witness has not seen.
#[test]
fn a_witness_starts_without_reading_its_records_and_refuses_an_unreadable_one() {
    let root = tmpdir("lazy");
    let mut w = Witness::init(&root, 0);
    w.kill();
    // 2,000 records under valid names, every one unparsable: a start that
    // read any of them would refuse to serve.
    let logs = w.dir.join("logs");
    for i in 0..2000 {
        use sha2::Digest;
        let name = hex::encode(sha2::Sha256::digest(format!("filler-{i}").as_bytes()));
        std::fs::write(logs.join(format!("{name}.json")), b"{ not json").unwrap();
    }
    // And one for a real identity, truncated as if by a bad restore.
    let seed = [11u8; 32];
    let broken = logs.join(record_name(&seed));
    std::fs::write(&broken, b"{\"origin\": \"witness-log/").unwrap();
    w.start();
    assert_eq!(logs_reported(&w), 2001, "counted by name, none read");

    let dir_path = root.join("directory.json");
    let d = serde_json::json!({ "witnesses": [w.entry.clone()] });
    std::fs::write(&dir_path, serde_json::to_vec(&d).unwrap()).unwrap();
    let dir_s = dir_path.to_str().unwrap();
    let submit = |journal_path: &Path, out: &str| {
        run(&[
            "witness",
            "submit",
            journal_path.to_str().unwrap(),
            "--directory",
            dir_s,
            "--out",
            root.join(out).to_str().unwrap(),
            "--min",
            "1",
        ])
    };

    // The log whose record is unreadable is refused, not enrolled afresh at
    // size 0 (which would let it be walked onto a fork).
    let j = root.join("broken.jsonl");
    journal(&j, &seed, &[b"a", b"b"]);
    let (code, err) = submit(&j, "broken.json");
    assert_eq!(code, 20, "{err}");
    assert!(
        err.contains("HTTP 500") && err.contains("unreadable"),
        "{err}"
    );
    assert_eq!(
        std::fs::read(&broken).unwrap(),
        b"{\"origin\": \"witness-log/",
        "the record is left for the operator to restore"
    );
    assert_eq!(logs_reported(&w), 2001);

    // Any other log is served as usual and counted.
    let j2 = root.join("fresh.jsonl");
    journal(&j2, &[12u8; 32], &[b"c"]);
    let (code, err) = submit(&j2, "fresh.json");
    assert_eq!(code, 0, "{err}");
    assert_eq!(logs_reported(&w), 2002);
    drop(w);
    let _ = std::fs::remove_dir_all(&root);
}

/// A restarted witness has nothing cached, so its refusal must come from
/// the record file read on demand: a same-size fork after a hard kill and
/// restart is still refused with 422, and recorded as verifiable proof.
#[test]
fn a_same_size_fork_after_restart_is_refused_with_evidence() {
    let root = tmpdir("restart-fork");
    let mut w = Witness::init(&root, 0);
    let dir_path = root.join("directory.json");
    let write_dir = |w: &Witness| {
        let d = serde_json::json!({ "witnesses": [w.entry.clone()] });
        std::fs::write(&dir_path, serde_json::to_vec(&d).unwrap()).unwrap();
    };
    write_dir(&w);
    let dir_s = dir_path.to_str().unwrap().to_string();
    let submit = |journal_path: &Path, out: &str| {
        run(&[
            "witness",
            "submit",
            journal_path.to_str().unwrap(),
            "--directory",
            &dir_s,
            "--out",
            root.join(out).to_str().unwrap(),
            "--min",
            "1",
        ])
    };
    let seed = [13u8; 32];
    let honest = root.join("honest.jsonl");
    journal(&honest, &seed, &[b"e0", b"e1", b"e2", b"e3", b"e4"]);
    let (code, err) = submit(&honest, "h.json");
    assert_eq!(code, 0, "{err}");

    w.kill();
    w.start();
    write_dir(&w);

    let fork = root.join("fork.jsonl");
    journal(&fork, &seed, &[b"e0", b"e1", b"rewritten", b"e3", b"e4"]);
    let (code, err) = submit(&fork, "f.json");
    assert_eq!(code, 20, "{err}");
    assert!(err.contains("REFUSED (422)"), "{err}");
    let ev: Vec<_> = std::fs::read_dir(w.dir.join("evidence"))
        .expect("evidence dir")
        .map(|e| e.unwrap().path())
        .collect();
    assert_eq!(ev.len(), 1, "one proof for the log");
    assert_eq!(
        ev[0].file_name().unwrap().to_str().unwrap(),
        record_name(&seed)
    );
    let doc: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&ev[0]).unwrap()).unwrap();
    let proof: witness_log_network::tlog_witness::EquivocationProof =
        serde_json::from_value(doc["proof"].clone()).unwrap();
    assert!(proof.verify(), "evidence must verify independently");
    let (code, out) = run(&["witness", "verify-evidence", ev[0].to_str().unwrap()]);
    assert_eq!(code, 0, "{out}");

    // The honest history still advances on the restarted witness.
    let mut j = JournaledLog::resume(honest.to_str().unwrap()).unwrap().0;
    j.append_intent(b"e5").unwrap();
    j.sync().unwrap();
    drop(j);
    let (code, err) = submit(&honest, "h2.json");
    assert_eq!(code, 0, "{err}");
    drop(w);
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

/// Witnessing detects equivocation only where two histories meet the same
/// witness. With a gate below a majority of the directory, a log can send
/// history A to one half and history B to the other, and both dossiers
/// reach WITNESSED. The verifier cannot stop that (it never sees the
/// other dossier); what it can do is say so, loudly, whenever the gate or
/// the cosigning set is not a majority. Found by an outside evaluation.
#[test]
fn split_view_below_a_majority_is_reported_not_hidden() {
    let root = tmpdir("split");
    let ws: Vec<Witness> = (0..4).map(|i| Witness::init(&root, i)).collect();
    let dir_path = root.join("directory.json");
    let d =
        serde_json::json!({ "witnesses": ws.iter().map(|w| w.entry.clone()).collect::<Vec<_>>() });
    std::fs::write(&dir_path, serde_json::to_vec(&d).unwrap()).unwrap();
    let dir_s = dir_path.to_str().unwrap().to_string();
    // Two half-directories, disjoint.
    let half = |idx: &[usize], name: &str| {
        let p = root.join(name);
        let d = serde_json::json!({ "witnesses": idx.iter().map(|&i| ws[i].entry.clone()).collect::<Vec<_>>() });
        std::fs::write(&p, serde_json::to_vec(&d).unwrap()).unwrap();
        p.to_str().unwrap().to_string()
    };
    let left = half(&[0, 1], "left.json");
    let right = half(&[2, 3], "right.json");

    let seed = [9u8; 32];
    let identity = hex::encode(
        ed25519_dalek::SigningKey::from_bytes(&seed)
            .verifying_key()
            .to_bytes(),
    );
    let a = root.join("a.jsonl");
    journal(&a, &seed, &[b"shared-0", b"shared-1", b"history-A"]);
    let b = root.join("b.jsonl");
    journal(&b, &seed, &[b"shared-0", b"shared-1", b"history-B"]);
    let (da, db) = (root.join("a.json"), root.join("b.json"));
    for (j, d, half) in [(&a, &da, &left), (&b, &db, &right)] {
        let (code, err) = run(&[
            "witness",
            "submit",
            j.to_str().unwrap(),
            "--directory",
            half,
            "--out",
            d.to_str().unwrap(),
            "--min",
            "2",
        ]);
        assert_eq!(code, 0, "{err}");
    }
    // Against the full directory, each half-cosigned dossier passes a
    // count-2 gate ... and the verifier says a split view is possible.
    for d in [&da, &db] {
        let out = Command::new(BIN)
            .args([
                "verify",
                d.to_str().unwrap(),
                "--identity",
                &identity,
                "--directory",
                &dir_s,
                "--min-witnesses",
                "2",
            ])
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&out.stdout);
        // Strict, the default since 0.5.0: WITNESSED by 2 of 4 is a
        // possible split view, exit 11 (RFC-0002).
        assert_eq!(out.status.code(), Some(11), "{stdout}");
        assert!(stdout.contains("Split view possible: 2 of 4"), "{stdout}");
        let ok = Command::new(BIN)
            .args([
                "verify",
                d.to_str().unwrap(),
                "--identity",
                &identity,
                "--directory",
                &dir_s,
                "--min-witnesses",
                "2",
                "--allow-sub-majority",
            ])
            .output()
            .unwrap();
        assert_eq!(ok.status.code(), Some(0));
        let json = Command::new(BIN)
            .args([
                "verify",
                d.to_str().unwrap(),
                "--directory",
                &dir_s,
                "--min-witnesses",
                "2",
                "--json",
            ])
            .output()
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&json.stdout).unwrap();
        assert_eq!(v["report"]["quorum"]["split_view_resistant"], false);
        assert_eq!(v["report"]["split_view_unsafe"], true);
        assert_eq!(v["exit_code"], 11);
    }
    // Two valid, conflicting copies: each one names the other's head as
    // a contradiction once the verifier brings it (--known-head), and the
    // verdict is DIVERGED, exit 30 (RFC-0002).
    let head_of = |p: &std::path::Path| -> String {
        let v: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap();
        format!(
            "{}:{}",
            v["checkpoint"]["tree_size"].as_u64().unwrap(),
            v["checkpoint"]["root_hash"].as_str().unwrap()
        )
    };
    let (code, out) = run(&[
        "verify",
        da.to_str().unwrap(),
        "--identity",
        &identity,
        "--known-head",
        &head_of(&db),
    ]);
    assert_eq!(code, 30, "{out}");
    let (code, _) = run(&[
        "verify",
        da.to_str().unwrap(),
        "--identity",
        &identity,
        "--known-head",
        &head_of(&da),
    ]);
    assert_eq!(code, 20, "its own head is not a contradiction");
    // With the default gate (0.66 of 4 = 3), neither half passes, and the
    // two copies side by side are an equivocation finding.
    let (code, _) = run(&[
        "verify",
        da.to_str().unwrap(),
        "--identity",
        &identity,
        "--directory",
        &dir_s,
    ]);
    assert_eq!(
        code, 10,
        "a half-cosigned dossier must not be WITNESSED at the default gate"
    );
    let (code, _) = run(&["diff", da.to_str().unwrap(), db.to_str().unwrap()]);
    assert_ne!(code, 0, "diff must flag two histories under one identity");
}
