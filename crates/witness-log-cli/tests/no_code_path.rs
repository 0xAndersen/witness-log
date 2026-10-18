//! The path an outside evaluation found missing: from `cargo install` to a
//! WITNESSED dossier with the CLI alone. `testnet up` starts three local
//! witnesses as child processes, `log init`/`log append` build a journal,
//! `submit` gets it cosigned, `verify --strict` gates on it, `testnet
//! down` stops everything. Real processes, real sockets, every CI platform.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const BIN: &str = env!("CARGO_BIN_EXE_witness-log");

fn tmpdir(tag: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!(
        "wl-nocode-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&p).unwrap();
    p
}

fn wl(cwd: &Path, args: &[&str]) -> Output {
    Command::new(BIN)
        .current_dir(cwd)
        .args(args)
        .output()
        .unwrap()
}

fn code(o: &Output) -> i32 {
    o.status.code().unwrap_or(-1)
}

fn stdout(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).to_string()
}

fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).to_string()
}

fn json(o: &Output) -> serde_json::Value {
    serde_json::from_slice(&o.stdout).unwrap_or_else(|e| {
        panic!(
            "stdout is not one JSON object: {e}\n{}\n{}",
            stdout(o),
            stderr(o)
        )
    })
}

/// A running testnet; `testnet down` on drop so a failing assertion does
/// not leave witness processes behind.
struct Testnet {
    root: PathBuf,
    dir: String,
    trusted: String,
}

impl Testnet {
    fn up(root: &Path, n: usize) -> Self {
        let dir = root.join("tn").display().to_string();
        let trusted = root.join("trusted.json").display().to_string();
        let out = wl(
            root,
            &[
                "testnet",
                "up",
                "--witnesses",
                &n.to_string(),
                "--dir",
                &dir,
                "--out",
                &trusted,
            ],
        );
        assert_eq!(code(&out), 0, "testnet up: {}", stderr(&out));
        assert!(stdout(&out).contains("testnet up"), "{}", stdout(&out));
        Self {
            root: root.to_path_buf(),
            dir,
            trusted,
        }
    }
}

impl Drop for Testnet {
    fn drop(&mut self) {
        let _ = wl(&self.root, &["testnet", "down", "--dir", &self.dir]);
    }
}

fn directory(path: &str) -> witness_log_network::WitnessDirectory {
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

#[test]
fn install_to_witnessed_with_the_cli_alone() {
    let root = tmpdir("flow");
    let net = Testnet::up(&root, 3);
    let dir = directory(&net.trusted);
    assert_eq!(dir.witnesses.len(), 3);
    assert_eq!(
        dir.distinct_operator_count(),
        3,
        "three distinct operator names"
    );
    for w in &dir.witnesses {
        assert!(w.url.starts_with("http://127.0.0.1:"), "{}", w.url);
        assert!(!w.is_project_operated);
    }

    let status = wl(&root, &["testnet", "status", "--dir", &net.dir]);
    assert_eq!(code(&status), 0, "{}", stdout(&status));
    assert_eq!(
        stdout(&status).matches(" up ").count(),
        3,
        "{}",
        stdout(&status)
    );

    // init -> append (argument, @file, stdin) -> info
    let init = wl(&root, &["log", "init", "agent.jsonl"]);
    assert_eq!(code(&init), 0, "{}", stderr(&init));
    let init = json(&init);
    let identity = init["identity"].as_str().unwrap().to_string();
    assert_eq!(identity.len(), 64);
    assert_eq!(init["sealed"], false);

    let a = wl(
        &root,
        &[
            "log",
            "append",
            "agent.jsonl",
            "--intent",
            r#"{"tool":"pay","amount":5}"#,
        ],
    );
    assert_eq!(code(&a), 0, "{}", stderr(&a));
    let a = json(&a);
    assert_eq!(a["index"], 0);
    assert_eq!(a["tree_size"], 1);
    std::fs::write(root.join("payload.bin"), b"file payload").unwrap();
    let b = wl(
        &root,
        &[
            "log",
            "append",
            "agent.jsonl",
            "--result",
            "@payload.bin",
            "--outcome",
            "ok",
        ],
    );
    assert_eq!(code(&b), 0, "{}", stderr(&b));
    let b = json(&b);
    assert_eq!(b["index"], 1);
    assert_eq!(
        b["committed_payload"], r#"{"outcome":"ok","value":"file payload"}"#,
        "--outcome wraps the payload in the canonical result shape"
    );
    let mut child = Command::new(BIN)
        .current_dir(&root)
        .args(["log", "append", "agent.jsonl", "--memory", "-"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    std::io::Write::write_all(child.stdin.as_mut().unwrap(), b"from stdin").unwrap();
    drop(child.stdin.take());
    let c = child.wait_with_output().unwrap();
    assert_eq!(code(&c), 0, "{}", stderr(&c));
    assert_eq!(json(&c)["index"], 2);
    // --outcome is for results only; two kinds at once is an error.
    let bad = wl(
        &root,
        &[
            "log",
            "append",
            "agent.jsonl",
            "--intent",
            "x",
            "--outcome",
            "ok",
        ],
    );
    assert_eq!(code(&bad), 2);
    let bad = wl(
        &root,
        &["log", "append", "agent.jsonl", "--intent", "--memory", "x"],
    );
    assert_eq!(code(&bad), 2);
    let bad = wl(&root, &["log", "append", "agent.jsonl", "--intnet", "x"]);
    assert_eq!(code(&bad), 2, "a typo'd flag must not run");

    let info = wl(&root, &["log", "info", "agent.jsonl"]);
    assert_eq!(code(&info), 0, "{}", stderr(&info));
    let info = json(&info);
    assert_eq!(info["tree_size"], 3);
    assert_eq!(info["identity"], identity);
    assert_eq!(info["leaves"]["intent"], 1);
    assert_eq!(info["leaves"]["result"], 1);
    assert_eq!(info["leaves"]["memory"], 1);

    // submit with the fail-closed default (--min 2 of 3), then verify.
    let s = wl(
        &root,
        &[
            "submit",
            "agent.jsonl",
            "--directory",
            &net.trusted,
            "--out",
            "dossier.json",
        ],
    );
    assert_eq!(code(&s), 0, "{}", stderr(&s));
    assert!(
        stderr(&s).contains("3/3 witnesses cosigned size 3"),
        "{}",
        stderr(&s)
    );
    assert!(stderr(&s).contains("--min 2: WITNESSED"), "{}", stderr(&s));
    let dossier: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(root.join("dossier.json")).unwrap()).unwrap();
    let names: Vec<&str> = dossier["witness_receipts"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["witness_name"].as_str().unwrap())
        .collect();
    assert_eq!(names.len(), 3);
    assert!(names.contains(&"testnet-a/w"), "{names:?}");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(root.join("dossier.json"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o644, "a dossier is meant to be handed on");
        let mode = std::fs::metadata(&net.trusted)
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o644);
        let mode = std::fs::metadata(root.join("agent.jsonl"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "the journal holds the seed");
    }

    let v = wl(
        &root,
        &[
            "verify",
            "dossier.json",
            "--identity",
            &identity,
            "--directory",
            &net.trusted,
            "--strict",
        ],
    );
    assert_eq!(
        code(&v),
        0,
        "WITNESSED by 3 of 3 passes --strict: {}",
        stdout(&v)
    );
    let v = wl(
        &root,
        &[
            "verify",
            "dossier.json",
            "--directory",
            &net.trusted,
            "--json",
        ],
    );
    assert_eq!(code(&v), 0);
    assert_eq!(json(&v)["verdict"], "WITNESSED");

    // Strict (the default since 0.5.0) only refines WITNESSED: without a
    // directory the verdict is UNANCHORED and the exit code is 20 either way.
    let v = wl(&root, &["verify", "dossier.json", "--strict"]);
    assert_eq!(code(&v), 20, "{}", stdout(&v));
    // --no-strict was kept for one release (0.5.x) and is gone in 0.6.0: a
    // usage error that names the replacement.
    let v = wl(&root, &["verify", "dossier.json", "--no-strict"]);
    assert_eq!(code(&v), 2);
    assert!(String::from_utf8_lossy(&v.stderr).contains("--allow-sub-majority"));

    // C2SP export: the cosignatures travel as a signed note that `c2sp
    // verify` accepts against the witnesses' keys alone.
    let e = wl(
        &root,
        &[
            "c2sp",
            "export",
            "dossier.json",
            "--directory",
            &net.trusted,
            "--out",
            "note.txt",
        ],
    );
    assert_eq!(code(&e), 0, "{}", stderr(&e));
    assert!(stderr(&e).contains("3 cosignature(s)"), "{}", stderr(&e));
    let mut args = vec!["c2sp", "verify", "note.txt"];
    let vkeys: Vec<String> = dir
        .witnesses
        .iter()
        .map(|w| {
            let pk: [u8; 32] = hex::decode(&w.pubkey).unwrap().try_into().unwrap();
            witness_log_core::c2sp::VerifierKey::for_cosignature(
                &w.name,
                &ed25519_dalek::VerifyingKey::from_bytes(&pk).unwrap(),
            )
            .encode()
        })
        .collect();
    for k in &vkeys {
        args.push("--vkey");
        args.push(k);
    }
    let cv = wl(&root, &args);
    assert_eq!(code(&cv), 0, "{}", stdout(&cv));
    assert_eq!(
        stdout(&cv).matches("attests this is the largest").count(),
        3
    );
    // With the log's own key too (signed from the journal).
    let e = wl(
        &root,
        &[
            "c2sp",
            "export",
            "dossier.json",
            "--directory",
            &net.trusted,
            "--sign-with",
            "agent.jsonl",
            "--out",
            "signed.txt",
        ],
    );
    assert_eq!(code(&e), 0, "{}", stderr(&e));
    let pk: [u8; 32] = hex::decode(&identity).unwrap().try_into().unwrap();
    let log_vkey = witness_log_core::c2sp::VerifierKey::for_ed25519(
        &format!("witness-log/{identity}"),
        &ed25519_dalek::VerifyingKey::from_bytes(&pk).unwrap(),
    )
    .encode();
    let cv = wl(
        &root,
        &["c2sp", "verify", "signed.txt", "--vkey", &log_vkey],
    );
    assert_eq!(code(&cv), 0, "{}", stdout(&cv));

    // disclose one leaf: the salt verifies exactly that payload.
    let d = wl(&root, &["log", "disclose", "agent.jsonl", "1"]);
    assert_eq!(code(&d), 0, "{}", stderr(&d));
    let d = json(&d);
    let salt: [u8; 32] = hex::decode(d["salt"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let leaf: witness_log_core::leaf::Leaf = serde_json::from_value(d["leaf"].clone()).unwrap();
    assert!(witness_log_core::redaction::verify_disclosure(
        &leaf,
        br#"{"outcome":"ok","value":"file payload"}"#,
        &salt
    ));
    assert!(!witness_log_core::redaction::verify_disclosure(
        &leaf,
        b"file payload",
        &salt
    ));

    // forget it: a tombstone is appended, the salt is gone, proofs hold.
    let f = wl(&root, &["log", "forget", "agent.jsonl", "1"]);
    assert_eq!(code(&f), 0, "{}", stderr(&f));
    assert_eq!(json(&f)["tombstone_index"], 3);
    let d = wl(&root, &["log", "disclose", "agent.jsonl", "1"]);
    assert_eq!(code(&d), 1, "nothing to disclose after forget");
    let f = wl(&root, &["log", "forget", "agent.jsonl", "1"]);
    assert_eq!(code(&f), 1, "forgetting twice is reported, not silently ok");
    let f = wl(&root, &["log", "forget", "agent.jsonl", "99"]);
    assert_eq!(code(&f), 1);

    // export (unwitnessed) still verifies internally and the redaction is in it.
    let x = wl(
        &root,
        &["log", "export", "agent.jsonl", "--out", "self.json"],
    );
    assert_eq!(code(&x), 0, "{}", stderr(&x));
    let v = wl(&root, &["verify", "self.json", "--identity", &identity]);
    assert_eq!(
        code(&v),
        20,
        "self export is UNANCHORED, not DIVERGED: {}",
        stdout(&v)
    );
    let self_dossier: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(root.join("self.json")).unwrap()).unwrap();
    assert_eq!(self_dossier["leaves"].as_array().unwrap().len(), 4);

    // The head moved (tombstone): submit again, all three cosign size 4.
    let s = wl(
        &root,
        &[
            "submit",
            "agent.jsonl",
            "--directory",
            &net.trusted,
            "--out",
            "dossier2.json",
        ],
    );
    assert_eq!(code(&s), 0, "{}", stderr(&s));
    assert!(stderr(&s).contains("cosigned size 4"), "{}", stderr(&s));

    // down: processes stop, state stays, a second down is a no-op.
    let down = wl(&root, &["testnet", "down", "--dir", &net.dir]);
    assert_eq!(code(&down), 0, "{}", stderr(&down));
    let status = wl(&root, &["testnet", "status", "--dir", &net.dir]);
    assert_eq!(code(&status), 1, "{}", stdout(&status));
    for w in &dir.witnesses {
        assert!(
            std::net::TcpStream::connect(w.url.trim_start_matches("http://")).is_err(),
            "{} still answers after down",
            w.url
        );
    }
    assert!(Path::new(&net.dir)
        .join("testnet-a")
        .join("witness.key")
        .exists());
    let down = wl(&root, &["testnet", "down", "--dir", &net.dir]);
    assert_eq!(code(&down), 0);
    drop(net);
    let _ = std::fs::remove_dir_all(&root);
}

/// Fail-closed submit. A directory of one witness cannot meet the default
/// `--min` (max(2, N/2+1) = 2): exit 20. `--allow-partial` exits by the
/// verdict instead (10: cosigned by one operator). `--min 1` is the
/// explicit opt-out. A 422 refusal is exit 20 whatever `--min` says.
#[test]
fn submit_fails_closed_by_default() {
    let root = tmpdir("closed");
    let net = Testnet::up(&root, 2);
    let full = directory(&net.trusted);
    let one = witness_log_network::WitnessDirectory {
        witnesses: vec![full.witnesses[0].clone()],
    };
    let one_path = root.join("one.json");
    std::fs::write(&one_path, serde_json::to_vec(&one).unwrap()).unwrap();
    let one_s = one_path.display().to_string();

    let init = json(&wl(&root, &["log", "init", "a.jsonl"]));
    let identity = init["identity"].as_str().unwrap().to_string();
    assert_eq!(
        code(&wl(&root, &["log", "append", "a.jsonl", "--intent", "one"])),
        0
    );

    let s = wl(
        &root,
        &[
            "submit",
            "a.jsonl",
            "--directory",
            &one_s,
            "--out",
            "d.json",
        ],
    );
    assert_eq!(code(&s), 20, "{}", stderr(&s));
    assert!(stderr(&s).contains("below --min 2"), "{}", stderr(&s));
    assert!(
        root.join("d.json").is_file(),
        "the dossier is still written"
    );

    let s = wl(
        &root,
        &[
            "submit",
            "a.jsonl",
            "--directory",
            &one_s,
            "--out",
            "d.json",
            "--allow-partial",
        ],
    );
    assert_eq!(
        code(&s),
        10,
        "exit by verdict: one operator is CONSISTENT-UNWITNESSED: {}",
        stderr(&s)
    );

    let s = wl(
        &root,
        &[
            "submit",
            "a.jsonl",
            "--directory",
            &one_s,
            "--out",
            "d.json",
            "--min",
            "1",
        ],
    );
    assert_eq!(code(&s), 0, "{}", stderr(&s));
    // That dossier is not WITNESSED by a majority of the full directory.
    let v = wl(
        &root,
        &[
            "verify",
            "d.json",
            "--identity",
            &identity,
            "--directory",
            &net.trusted,
            "--strict",
        ],
    );
    // Below the default gate the verdict is CONSISTENT-UNWITNESSED, and
    // the exit code is the verdict's (10) with or without strict.
    assert_eq!(code(&v), 10, "{}", stdout(&v));
    let v = wl(
        &root,
        &[
            "verify",
            "d.json",
            "--identity",
            &identity,
            "--directory",
            &net.trusted,
            "--allow-sub-majority",
        ],
    );
    assert_eq!(code(&v), 10);

    // A fork of the same identity: the witness that cosigned refuses (422).
    let seed_hex = {
        let header: serde_json::Value = serde_json::from_str(
            std::fs::read_to_string(root.join("a.jsonl"))
                .unwrap()
                .lines()
                .next()
                .unwrap(),
        )
        .unwrap();
        header["identity_bytes_hex"].as_str().unwrap().to_string()
    };
    std::fs::write(root.join("seed.hex"), &seed_hex).unwrap();
    let f = wl(
        &root,
        &[
            "log",
            "init",
            "fork.jsonl",
            "--identity-seed-file",
            "seed.hex",
        ],
    );
    assert_eq!(code(&f), 0, "{}", stderr(&f));
    assert_eq!(
        code(&wl(
            &root,
            &["log", "append", "fork.jsonl", "--intent", "other"]
        )),
        0
    );
    let s = wl(
        &root,
        &[
            "submit",
            "fork.jsonl",
            "--directory",
            &one_s,
            "--out",
            "f.json",
            "--min",
            "1",
        ],
    );
    assert_eq!(
        code(&s),
        20,
        "a 422 is exit 20 even with --min 1: {}",
        stderr(&s)
    );
    assert!(stderr(&s).contains("REFUSED (422)"), "{}", stderr(&s));
    let s = wl(
        &root,
        &[
            "submit",
            "fork.jsonl",
            "--directory",
            &one_s,
            "--out",
            "f.json",
            "--allow-partial",
        ],
    );
    assert_ne!(
        code(&s),
        0,
        "--allow-partial exits by verdict; nothing cosigned this head"
    );
    drop(net);
    let _ = std::fs::remove_dir_all(&root);
}

/// `witness init --json`: one object on stdout, nothing else.
#[test]
fn witness_init_json_is_one_object() {
    let root = tmpdir("initjson");
    let out = wl(
        &root,
        &[
            "witness",
            "init",
            "w",
            "--name",
            "w.test/x",
            "--org",
            "Test Org",
            "--url",
            "http://127.0.0.1:1",
            "--json",
        ],
    );
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    let text = stdout(&out);
    assert_eq!(text.trim().lines().count(), 1, "exactly one line:\n{text}");
    let v: serde_json::Value = serde_json::from_str(text.trim()).unwrap();
    assert_eq!(v["identity"].as_str().unwrap().len(), 64);
    assert!(v["vkey"].as_str().unwrap().starts_with("w.test/x+"));
    assert_eq!(v["org"], "Test Org");
    assert!(v["data_dir"].as_str().unwrap().ends_with('w'));
    assert_eq!(v["entry"]["pubkey"], v["identity"]);
    let _ = std::fs::remove_dir_all(&root);
}

/// `testnet up` twice is refused while the first is running.
#[test]
fn testnet_up_refuses_a_second_start() {
    let root = tmpdir("twice");
    let net = Testnet::up(&root, 2);
    let again = wl(
        &root,
        &["testnet", "up", "--dir", &net.dir, "--out", &net.trusted],
    );
    assert_eq!(code(&again), 1, "{}", stderr(&again));
    assert!(stderr(&again).contains("already up"), "{}", stderr(&again));
    let bad = wl(
        &root,
        &["testnet", "up", "--dir", &net.dir, "--witnesess", "2"],
    );
    assert_eq!(code(&bad), 2);
    drop(net);
    let _ = std::fs::remove_dir_all(&root);
}
