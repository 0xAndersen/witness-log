//! `witness-log doctor`: each check reports what a newcomer would
//! otherwise find out from a failed submit or a weaker verdict, and the
//! exit status separates "will not work" (1) from "worth fixing" (0).

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const BIN: &str = env!("CARGO_BIN_EXE_witness-log");

fn tmpdir(tag: &str) -> PathBuf {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let p = std::env::temp_dir().join(format!("wl-doctor-{tag}-{}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&p).unwrap();
    p
}

fn run(dir: &Path, args: &[&str]) -> Output {
    Command::new(BIN)
        .arg("doctor")
        .args(args)
        .current_dir(dir)
        .env_remove("WITNESS_LOG_CA_FILE")
        .output()
        .unwrap()
}

fn json(out: &Output) -> serde_json::Value {
    serde_json::from_slice(&out.stdout)
        .unwrap_or_else(|e| panic!("not JSON ({e}): {}", String::from_utf8_lossy(&out.stdout)))
}

fn findings(doc: &serde_json::Value, level: &str) -> Vec<String> {
    doc["findings"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|f| f["level"] == level)
        .map(|f| f["what"].as_str().unwrap().to_string())
        .collect()
}

fn cli(dir: &Path, args: &[&str]) {
    let out = Command::new(BIN)
        .args(args)
        .current_dir(dir)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// A directory of `orgs.len()` witnesses (not running), one per org.
fn directory(dir: &Path, orgs: &[&str]) {
    let mut entries = Vec::new();
    for (i, org) in orgs.iter().enumerate() {
        let out = Command::new(BIN)
            .args(["witness", "init"])
            .arg(dir.join(format!("w{i}")))
            .args(["--name", &format!("w{i}.test/w"), "--org", org])
            .output()
            .unwrap();
        assert!(out.status.success());
        entries.push(serde_json::from_slice::<serde_json::Value>(&out.stdout).unwrap());
    }
    std::fs::write(
        dir.join("trusted.json"),
        serde_json::json!({ "witnesses": entries }).to_string(),
    )
    .unwrap();
}

#[test]
fn no_arguments_checks_the_binary_and_succeeds() {
    let dir = tmpdir("bare");
    let out = run(&dir, &[]);
    assert_eq!(out.status.code(), Some(0));
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("this binary"), "{text}");
    #[cfg(feature = "https")]
    assert!(text.contains("reaches https:// witnesses"), "{text}");
}

#[test]
fn usage_errors_exit_2() {
    let dir = tmpdir("usage");
    assert_eq!(run(&dir, &["--bogus"]).status.code(), Some(2));
    assert_eq!(run(&dir, &["--directory"]).status.code(), Some(2));
    assert_eq!(run(&dir, &["a.jsonl", "b.jsonl"]).status.code(), Some(2));
    assert_eq!(run(&dir, &["--help"]).status.code(), Some(0));
}

#[test]
fn an_unsubmitted_journal_is_a_warning_with_the_command_to_run() {
    let dir = tmpdir("journal");
    cli(&dir, &["log", "init", "agent.jsonl"]);
    cli(
        &dir,
        &["log", "append", "agent.jsonl", "--intent", "{\"a\":1}"],
    );
    let out = run(&dir, &["agent.jsonl", "--offline", "--json"]);
    assert_eq!(out.status.code(), Some(0));
    let doc = json(&out);
    assert_eq!(doc["ok"], true);
    assert!(findings(&doc, "ok")
        .iter()
        .any(|w| w.contains("replays: 1 leaf,")));
    let warn = &doc["findings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["level"] == "warn")
        .expect("a warning")
        .clone();
    assert!(warn["what"].as_str().unwrap().contains("never submitted"));
    assert!(warn["fix"]
        .as_str()
        .unwrap()
        .contains("witness-log submit agent.jsonl"));
}

#[test]
fn a_journal_that_contradicts_its_cosigned_head_is_a_problem() {
    let dir = tmpdir("fork");
    cli(&dir, &["log", "init", "agent.jsonl"]);
    cli(
        &dir,
        &["log", "append", "agent.jsonl", "--intent", "{\"a\":1}"],
    );
    // What `submit` records after witnesses cosign size 1, with a root
    // this journal does not have.
    std::fs::write(
        dir.join("agent.jsonl.witnesses.json"),
        serde_json::json!({"sizes": {"aa": 1}, "cosigned_size": 1, "cosigned_root": "ab".repeat(32)})
            .to_string(),
    )
    .unwrap();
    let out = run(&dir, &["agent.jsonl", "--offline", "--json"]);
    assert_eq!(out.status.code(), Some(1));
    let fails = findings(&json(&out), "fail");
    assert!(
        fails
            .iter()
            .any(|f| f.contains("contradicts the head witnesses cosigned at size 1")),
        "{fails:?}"
    );

    // A head larger than the journal: truncated or replaced.
    std::fs::write(
        dir.join("agent.jsonl.witnesses.json"),
        serde_json::json!({"sizes": {"aa": 5}, "cosigned_size": 5, "cosigned_root": "ab".repeat(32)})
            .to_string(),
    )
    .unwrap();
    let out = run(&dir, &["agent.jsonl", "--offline", "--json"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(findings(&json(&out), "fail")
        .iter()
        .any(|f| f.contains("truncated or replaced")));
}

#[test]
fn a_directory_that_cannot_reach_witnessed_is_a_problem() {
    let dir = tmpdir("dir1");
    directory(&dir, &["Only Org", "only org "]); // one operator, spelled twice
    let out = run(
        &dir,
        &["--directory", "trusted.json", "--offline", "--json"],
    );
    assert_eq!(out.status.code(), Some(1));
    let doc = json(&out);
    assert!(findings(&doc, "ok")
        .iter()
        .any(|f| f.contains("1 independent operator")));
    assert!(findings(&doc, "fail")
        .iter()
        .any(|f| f.contains("WITNESSED is unreachable")));
}

#[test]
fn subject_org_removes_the_logs_own_operator_from_the_count() {
    let dir = tmpdir("dir2");
    directory(&dir, &["Alpha Payments", "Bravo Logistics"]);
    let out = run(
        &dir,
        &["--directory", "trusted.json", "--offline", "--json"],
    );
    assert_eq!(out.status.code(), Some(0), "two operators reach WITNESSED");
    let out = run(
        &dir,
        &[
            "--directory",
            "trusted.json",
            "--offline",
            "--json",
            "--subject-org",
            " alpha  PAYMENTS",
        ],
    );
    assert_eq!(
        out.status.code(),
        Some(1),
        "only Bravo is independent of Alpha"
    );
    let doc = json(&out);
    assert!(findings(&doc, "fail")
        .iter()
        .any(|f| f.contains("1 operator other than the log's own")));
}

#[test]
fn an_unreachable_witness_is_named() {
    let dir = tmpdir("down");
    directory(&dir, &["A", "B"]);
    // witness init's default URL is http://127.0.0.1:7380; point both at a
    // port nothing listens on.
    let mut d: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(dir.join("trusted.json")).unwrap()).unwrap();
    for w in d["witnesses"].as_array_mut().unwrap() {
        w["url"] = serde_json::Value::String("http://127.0.0.1:9".into());
    }
    std::fs::write(dir.join("trusted.json"), d.to_string()).unwrap();
    let out = run(&dir, &["--directory", "trusted.json", "--json"]);
    assert_eq!(out.status.code(), Some(1));
    let fails = findings(&json(&out), "fail");
    assert_eq!(
        fails.iter().filter(|f| f.contains("unreachable")).count(),
        2,
        "{fails:?}"
    );
}

#[test]
fn a_witness_state_directory_is_checked() {
    let dir = tmpdir("wdir");
    directory(&dir, &["A"]);
    let out = run(&dir, &["--witness", "w0", "--offline", "--json"]);
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stdout)
    );
    let oks = findings(&json(&out), "ok");
    assert!(oks.iter().any(|f| f.contains("logs/ writable")), "{oks:?}");
    std::fs::remove_file(dir.join("w0").join("witness.key")).unwrap();
    let out = run(&dir, &["--witness", "w0", "--offline", "--json"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(findings(&json(&out), "fail")
        .iter()
        .any(|f| f.contains("witness.key is missing")));
}
