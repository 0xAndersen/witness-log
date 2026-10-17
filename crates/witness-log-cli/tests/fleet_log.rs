//! RFC-0001 (fleet checkpoint log, EXPERIMENTAL) end to end with real
//! processes: two ordinary `witness serve` witnesses from two organisations
//! enroll the fleet origin once with `witness add-log`; an agent appends
//! its checkpoint with `submit --fleet`; `fleet witness` gets the fleet
//! checkpoint cosigned; `verify --accept-fleet-anchor` reaches WITNESSED
//! via the fleet, and without the opt-in the same dossier is
//! CONSISTENT-UNWITNESSED. The fleet log refuses a same-size fork with 422
//! and keeps the evidence, also after a restart.

use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use witness_log_core::identity::IdentityKeypair;
use witness_log_core::journal::JournaledLog;

const BIN: &str = env!("CARGO_BIN_EXE_witness-log");
const FLEET_ORIGIN: &str = "acme.example/witness-log/fleet";
const FLEET_ORG: &str = "Acme Fleet";

fn tmpdir(tag: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!(
        "wl-fleet-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&p).unwrap();
    p
}

/// A child process that prints `... http://<addr> ...` on stderr once it
/// listens; killed on drop.
struct Server {
    child: Option<Child>,
    url: String,
    /// Removed after a kill where the restarting process cannot tell that
    /// the holder died (not on Unix; see `witness serve`'s lock).
    #[cfg_attr(unix, allow(dead_code))]
    lock: PathBuf,
}

impl Server {
    fn start(args: &[&str], lock: PathBuf) -> Self {
        let mut child = Command::new(BIN)
            .args(args)
            .stderr(Stdio::piped())
            .stdout(Stdio::null())
            .spawn()
            .unwrap();
        let stderr = child.stderr.take().unwrap();
        let mut lines = BufReader::new(stderr).lines();
        let url = loop {
            let line = lines
                .next()
                .expect("server exited before listening")
                .unwrap();
            if let Some(i) = line.find("http://") {
                break line[i..].split_whitespace().next().unwrap().to_string();
            }
        };
        std::thread::spawn(move || for _ in lines {});
        Self {
            child: Some(child),
            url,
            lock,
        }
    }

    fn kill(&mut self) {
        if let Some(mut c) = self.child.take() {
            let _ = c.kill();
            let _ = c.wait();
        }
        #[cfg(not(unix))]
        let _ = std::fs::remove_file(&self.lock);
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.kill();
    }
}

fn run(args: &[&str]) -> (i32, String, String) {
    let out = Command::new(BIN).args(args).output().unwrap();
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).to_string(),
        String::from_utf8_lossy(&out.stderr).to_string(),
    )
}

fn journal(path: &Path, seed: &[u8; 32], leaves: &[&str]) {
    let mut j =
        JournaledLog::create(path.to_str().unwrap(), IdentityKeypair::from_bytes(seed)).unwrap();
    for l in leaves {
        j.append_intent(l.as_bytes()).unwrap();
    }
    j.sync().unwrap();
}

/// POST `body` to `url` + `path` over a plain socket; (status, body).
fn post(url: &str, path: &str, body: &str) -> (u16, String) {
    let addr = url.trim_start_matches("http://").trim_end_matches('/');
    let mut s = std::net::TcpStream::connect(addr).unwrap();
    write!(
        s,
        "POST {path} HTTP/1.1\r\nHost: {addr}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
    .unwrap();
    let mut resp = String::new();
    s.read_to_string(&mut resp).unwrap();
    let status = resp
        .split(' ')
        .nth(1)
        .and_then(|c| c.parse().ok())
        .unwrap_or(0);
    let body = resp.split_once("\r\n\r\n").map(|(_, b)| b).unwrap_or("");
    (status, body.to_string())
}

fn verify_json(
    dossier: &Path,
    extra: &[&str],
    dir: &str,
    identity: &str,
) -> (i32, serde_json::Value) {
    let mut args = vec![
        "verify",
        dossier.to_str().unwrap(),
        "--identity",
        identity,
        "--directory",
        dir,
        "--json",
    ];
    args.extend_from_slice(extra);
    let (code, out, err) = run(&args);
    let v: serde_json::Value =
        serde_json::from_str(&out).unwrap_or_else(|e| panic!("{e}: {out} {err}"));
    (code, v)
}

#[test]
fn fleet_log_end_to_end_with_real_witnesses() {
    let root = tmpdir("e2e");
    let fleet_dir = root.join("fleet");
    let fleet_s = fleet_dir.to_str().unwrap().to_string();

    // The organisation's fleet log.
    let (code, out, err) = run(&[
        "fleet",
        "init",
        &fleet_s,
        "--origin",
        FLEET_ORIGIN,
        "--org",
        FLEET_ORG,
        "--json",
    ]);
    assert_eq!(code, 0, "{err}");
    let init: serde_json::Value = serde_json::from_str(&out).unwrap();
    let vkey = init["vkey"].as_str().unwrap().to_string();
    // A second init must not overwrite the key.
    assert_eq!(
        run(&[
            "fleet",
            "init",
            &fleet_s,
            "--origin",
            FLEET_ORIGIN,
            "--org",
            FLEET_ORG
        ])
        .0,
        1
    );
    // An agent origin is not a fleet origin.
    let agent_origin = format!("witness-log/{}", "ab".repeat(32));
    assert_eq!(
        run(&[
            "fleet",
            "init",
            root.join("x").to_str().unwrap(),
            "--origin",
            &agent_origin,
            "--org",
            "X"
        ])
        .0,
        2
    );

    // Two ordinary witnesses from two organisations; each enrolls the
    // fleet origin once, exactly as it would any non-canonical log.
    let mut entries = Vec::new();
    let mut witnesses = Vec::new();
    for (i, org) in ["Org North", "Org South"].iter().enumerate() {
        let wdir = root.join(format!("w{i}"));
        let (code, out, err) = run(&[
            "witness",
            "init",
            wdir.to_str().unwrap(),
            "--name",
            &format!("w{i}.test/witness"),
            "--org",
            org,
        ]);
        assert_eq!(code, 0, "{err}");
        let (code, _, err) = run(&[
            "witness",
            "add-log",
            wdir.to_str().unwrap(),
            FLEET_ORIGIN,
            &vkey,
        ]);
        assert_eq!(code, 0, "{err}");
        let w = Server::start(
            &[
                "witness",
                "serve",
                wdir.to_str().unwrap(),
                "--listen",
                "127.0.0.1:0",
                "--open-enrollment",
            ],
            wdir.join("witness.lock"),
        );
        let mut entry: serde_json::Value = serde_json::from_str(&out).unwrap();
        entry["url"] = serde_json::Value::String(w.url.clone());
        entries.push(entry);
        witnesses.push(w);
    }
    let dir_path = root.join("trusted.json");
    std::fs::write(
        &dir_path,
        serde_json::to_vec(&serde_json::json!({ "witnesses": entries })).unwrap(),
    )
    .unwrap();
    let dir_s = dir_path.to_str().unwrap().to_string();

    let fleet_args = ["fleet", "serve", &fleet_s, "--listen", "127.0.0.1:0"];
    let mut fleet = Server::start(&fleet_args, fleet_dir.join("fleet.lock"));

    // The agent.
    let seed = [21u8; 32];
    let identity = hex::encode(
        ed25519_dalek::SigningKey::from_bytes(&seed)
            .verifying_key()
            .to_bytes(),
    );
    let honest = root.join("agent.jsonl");
    journal(&honest, &seed, &["e0", "e1", "e2", "e3", "e4"]);
    let honest_s = honest.to_str().unwrap().to_string();
    let dossier = root.join("d.json");
    let dossier_s = dossier.to_str().unwrap().to_string();

    // Before the fleet log is witnessed: appended, dossier written, exit 20.
    let (code, _, err) = run(&[
        "submit", &honest_s, "--fleet", &fleet.url, "--out", &dossier_s,
    ]);
    assert_eq!(code, 20, "{err}");
    assert!(err.contains("entry 0 (appended)"), "{err}");
    let (code, v) = verify_json(
        &dossier,
        &["--accept-fleet-anchor", "--subject-org", FLEET_ORG],
        &dir_s,
        &identity,
    );
    assert_eq!(code, 10, "uncosigned fleet checkpoint: {v}");
    assert_eq!(v["report"]["fleet_anchor"]["status"], "verified");

    // The fleet operator gets its checkpoint cosigned.
    let (code, _, err) = run(&["fleet", "witness", &fleet_s, "--directory", &dir_s]);
    assert_eq!(code, 0, "{err}");
    assert!(
        err.contains("2/2 witnesses cosigned fleet checkpoint size 1"),
        "{err}"
    );

    // Submitting the same head again appends nothing and anchors it to the
    // cosigned fleet checkpoint.
    let (code, _, err) = run(&[
        "submit", &honest_s, "--fleet", &fleet.url, "--out", &dossier_s,
    ]);
    assert_eq!(code, 0, "{err}");
    assert!(err.contains("entry 0 (already held)"), "{err}");
    assert!(err.contains("2 cosignature line(s)"), "{err}");

    // With the opt-in: WITNESSED via the fleet; exit 11 because no witness
    // cosigned this log itself (fleet cosigners never make it split-view
    // resistant), 0 with --allow-sub-majority.
    let opt_in = ["--accept-fleet-anchor", "--subject-org", FLEET_ORG];
    let (code, v) = verify_json(&dossier, &opt_in, &dir_s, &identity);
    assert_eq!(code, 11, "{v}");
    assert_eq!(v["verdict"], "WITNESSED");
    assert_eq!(v["accept_fleet_anchor"], true);
    let r = &v["report"];
    assert_eq!(r["witnessed_via"], "fleet");
    assert_eq!(r["witness_paths"]["fleet"]["witnesses"], 2);
    assert_eq!(r["witness_paths"]["fleet"]["independent_operators"], 2);
    assert_eq!(r["witness_paths"]["direct"]["witnesses"], 0);
    assert_eq!(r["quorum"]["distinct_independent_operators"], 2);
    assert_eq!(r["split_view_unsafe"], true);
    let mut allow = opt_in.to_vec();
    allow.push("--allow-sub-majority");
    assert_eq!(verify_json(&dossier, &allow, &dir_s, &identity).0, 0);

    // Without the opt-in the anchor is ignored: CONSISTENT-UNWITNESSED,
    // and the JSON has no fleet path fields.
    let (code, v) = verify_json(&dossier, &[], &dir_s, &identity);
    assert_eq!(code, 10, "{v}");
    assert_eq!(v["report"]["fleet_anchor"]["status"], "ignored");
    assert!(v["report"].get("witnessed_via").is_none());
    assert!(v.get("accept_fleet_anchor").is_none());
    // The opt-in needs the fleet operator's organisation.
    let (code, _, err) = run(&[
        "verify",
        &dossier_s,
        "--directory",
        &dir_s,
        "--accept-fleet-anchor",
    ]);
    assert_eq!(code, 2, "{err}");
    assert!(err.contains("--subject-org"), "{err}");
    // If the fleet operator also runs one of the two witnesses, only one
    // independent operator is left.
    let (code, v) = verify_json(
        &dossier,
        &["--accept-fleet-anchor", "--subject-org", "org north"],
        &dir_s,
        &identity,
    );
    assert_eq!(code, 10, "{v}");
    assert_eq!(v["report"]["quorum"]["distinct_independent_operators"], 1);

    // A forking agent: same identity, same size, a different root. The
    // fleet log refuses it (422) and keeps both signed notes as evidence.
    let fork = root.join("fork.jsonl");
    journal(&fork, &seed, &["e0", "e1", "REWRITTEN", "e3", "e4"]);
    let fork_s = fork.to_str().unwrap().to_string();
    let (code, _, err) = run(&[
        "submit",
        &fork_s,
        "--fleet",
        &fleet.url,
        "--out",
        root.join("f.json").to_str().unwrap(),
    ]);
    assert_eq!(code, 20, "{err}");
    assert!(err.contains("REFUSED (422)"), "{err}");
    let evidence: Vec<_> = std::fs::read_dir(fleet_dir.join("evidence"))
        .expect("evidence dir")
        .collect();
    assert_eq!(evidence.len(), 1);
    let ev: serde_json::Value =
        serde_json::from_slice(&std::fs::read(evidence[0].as_ref().unwrap().path()).unwrap())
            .unwrap();
    assert_eq!(ev["kind"], "equivocation");
    let proof: witness_log_network::tlog_witness::EquivocationProof =
        serde_json::from_value(ev["proof"].clone()).unwrap();
    assert!(
        proof.verify(),
        "the fleet log's evidence verifies on its own"
    );
    let (code, out, err) = run(&[
        "witness",
        "verify-evidence",
        evidence[0].as_ref().unwrap().path().to_str().unwrap(),
    ]);
    assert_eq!(code, 0, "{out}{err}");
    // A verifier holding that evidence sees the honest dossier DIVERGED.
    let (code, _, _) = run(&[
        "verify",
        &dossier_s,
        "--directory",
        &dir_s,
        "--evidence",
        evidence[0].as_ref().unwrap().path().to_str().unwrap(),
    ]);
    assert_eq!(code, 30);

    // A growing fork is refused too (not provable, so no new evidence).
    let grow = root.join("grow.jsonl");
    journal(&grow, &seed, &["e0", "e1", "REWRITTEN", "e3", "e4", "e5"]);
    let (code, _, err) = run(&[
        "submit",
        grow.to_str().unwrap(),
        "--fleet",
        &fleet.url,
        "--out",
        root.join("g.json").to_str().unwrap(),
    ]);
    assert_eq!(code, 20, "{err}");

    // Only agent checkpoints are entries.
    let other_key = ed25519_dalek::SigningKey::from_bytes(&[5u8; 32]);
    let not_agent = witness_log_core::c2sp::Checkpoint {
        origin: "example.com/some-log".into(),
        tree_size: 1,
        root_hash: [1; 32],
        extensions: vec![],
    }
    .sign(&other_key)
    .unwrap()
    .encode()
    .unwrap();
    let (status, body) = post(&fleet.url, "/add-entry", &format!("old 0\n\n{not_agent}"));
    assert_eq!(status, 400, "{body}");
    let agent_key = ed25519_dalek::SigningKey::from_bytes(&[6u8; 32]);
    let mut forged = witness_log_core::c2sp::Checkpoint {
        origin: witness_log_core::c2sp::canonical_origin(&agent_key.verifying_key()),
        tree_size: 1,
        root_hash: [1; 32],
        extensions: vec![],
    }
    .sign(&other_key)
    .unwrap();
    forged.signatures[0].key_name =
        witness_log_core::c2sp::canonical_origin(&agent_key.verifying_key());
    let (status, body) = post(
        &fleet.url,
        "/add-entry",
        &format!("old 0\n\n{}", forged.encode().unwrap()),
    );
    assert_eq!(status, 403, "{body}");

    // A restart of the fleet log keeps its state: the fork is still
    // refused, and the honest agent's next head extends entry 0.
    fleet.kill();
    let fleet = Server::start(&fleet_args, fleet_dir.join("fleet.lock"));
    let (code, _, err) = run(&[
        "submit",
        &fork_s,
        "--fleet",
        &fleet.url,
        "--out",
        root.join("f2.json").to_str().unwrap(),
    ]);
    assert_eq!(code, 20, "{err}");
    for payload in ["e5", "e6"] {
        let (code, _, err) = run(&["log", "append", &honest_s, "--intent", payload]);
        assert_eq!(code, 0, "{err}");
    }
    let d2 = root.join("d2.json");
    let d2_s = d2.to_str().unwrap().to_string();
    let (code, _, err) = run(&["submit", &honest_s, "--fleet", &fleet.url, "--out", &d2_s]);
    assert_eq!(code, 20, "appended, not yet cosigned: {err}");
    assert!(err.contains("entry 1 (appended)"), "{err}");
    // Witnesses cosign the grown fleet log (consistency from size 1).
    let (code, _, err) = run(&["fleet", "witness", &fleet_s, "--directory", &dir_s]);
    assert_eq!(code, 0, "{err}");
    assert!(err.contains("size 2"), "{err}");
    let (code, _, err) = run(&["submit", &honest_s, "--fleet", &fleet.url, "--out", &d2_s]);
    assert_eq!(code, 0, "{err}");
    let (code, v) = verify_json(&d2, &allow, &dir_s, &identity);
    assert_eq!(code, 0, "{v}");
    assert_eq!(v["report"]["fleet_anchor"]["fleet_tree_size"], 2);
    assert_eq!(v["report"]["fleet_anchor"]["entry_index"], 1);

    // Direct and fleet together: one witness key counts once.
    let (code, _, err) = run(&[
        "submit",
        &honest_s,
        "--fleet",
        &fleet.url,
        "--directory",
        &dir_s,
        "--out",
        root.join("both.json").to_str().unwrap(),
    ]);
    assert_eq!(code, 0, "{err}");
    let (code, v) = verify_json(&root.join("both.json"), &opt_in, &dir_s, &identity);
    assert_eq!(code, 0, "a direct majority: {v}");
    let r = &v["report"];
    assert_eq!(r["witnessed_via"], "direct");
    assert_eq!(r["quorum"]["valid_receipts"], 2);
    assert_eq!(r["witness_paths"]["on_both"], 2);

    drop(witnesses);
    drop(fleet);
    let _ = std::fs::remove_dir_all(&root);
}
