//! `witness-network log-list` / `request` from the binary, and `directory
//! add` with the full add-checkpoint URL a witness's about page gives.
//! The networked half (omniwitness polling the list, cosigning, refusing a
//! fork) is tests/interop/omniwitness.sh, run by .github/workflows/interop.yml.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const BIN: &str = env!("CARGO_BIN_EXE_witness-log");

struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        let p = std::env::temp_dir().join(format!(
            "wl-wnet-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&p).unwrap();
        Self(p)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn wl(cwd: &Path, args: &[&str]) -> Output {
    Command::new(BIN)
        .current_dir(cwd)
        .args(args)
        .output()
        .unwrap()
}

fn text(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

fn fleet(dir: &Path) -> serde_json::Value {
    let out = wl(
        dir,
        &[
            "fleet",
            "init",
            "fleet",
            "--origin",
            "acme.example/witness-log/fleet",
            "--org",
            "Acme Corp",
            "--json",
        ],
    );
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    serde_json::from_slice(&out.stdout).unwrap()
}

/// The `logs/v0` entries of a list: (vkey, qpd, contact) per log, checked
/// in the order the format requires.
fn entries(list: &str) -> Vec<(String, String, String)> {
    let mut lines = list
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'));
    assert_eq!(lines.next(), Some("logs/v0"), "{list}");
    let mut out = Vec::new();
    while let Some(v) = lines.next() {
        let vkey = v.strip_prefix("vkey ").expect(v).to_string();
        let qpd = lines
            .next()
            .unwrap()
            .strip_prefix("qpd ")
            .unwrap()
            .to_string();
        let contact = lines
            .next()
            .unwrap()
            .strip_prefix("contact ")
            .unwrap()
            .to_string();
        out.push((vkey, qpd, contact));
    }
    out
}

#[test]
fn a_fleet_and_an_agent_in_one_list() {
    let tmp = TempDir::new("list");
    let f = fleet(&tmp.0);
    let init = wl(&tmp.0, &["log", "init", "agent.wlog"]);
    let init: serde_json::Value = serde_json::from_slice(&init.stdout).unwrap();
    let id = init["identity"].as_str().unwrap().to_string();
    let out = wl(
        &tmp.0,
        &[
            "witness-network",
            "log-list",
            "--fleet",
            "fleet",
            "--identity",
            &id,
            "--every",
            "60",
            "--contact",
            "ops (at) acme.example",
        ],
    );
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    let list = text(&out.stdout);
    let e = entries(&list);
    assert_eq!(e.len(), 2, "{list}");
    // The vkey `fleet init` printed, verbatim.
    assert_eq!(e[0].0, f["vkey"].as_str().unwrap());
    assert!(e[1].0.starts_with(&format!("witness-log/{id}+")), "{list}");
    assert!(e
        .iter()
        .all(|(_, q, c)| q == "1440" && c == "ops (at) acme.example"));
}

#[test]
fn the_request_is_printed_not_sent() {
    let tmp = TempDir::new("request");
    let f = fleet(&tmp.0);
    let out = wl(
        &tmp.0,
        &[
            "witness-network",
            "request",
            "--fleet",
            "fleet",
            "--qpd",
            "24",
            "--contact",
            "https://acme.example/about",
            "--list",
            "staging",
        ],
    );
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    let r = text(&out.stdout);
    assert!(
        r.starts_with("To: participate (at) lists.witness-network.org\n"),
        "{r}"
    );
    assert!(
        r.contains("Origin line:         acme.example/witness-log/fleet"),
        "{r}"
    );
    assert!(r.contains(f["vkey"].as_str().unwrap()), "{r}");
    assert!(
        r.contains("at most 24 add-checkpoint requests per day"),
        "{r}"
    );
    assert!(
        r.contains("Log list: staging") && r.contains("run by Acme Corp"),
        "{r}"
    );
    assert!(text(&out.stderr).contains("nothing was sent"));
}

#[test]
fn what_cannot_go_on_a_list_is_a_usage_error() {
    let tmp = TempDir::new("usage");
    fleet(&tmp.0);
    // A fleet log made before `fleet init` refused Unicode whitespace.
    std::fs::create_dir_all(tmp.0.join("nbsp")).unwrap();
    let cfg = std::fs::read_to_string(tmp.0.join("fleet/fleet.json"))
        .unwrap()
        .replace(
            "acme.example/witness-log/fleet",
            "acme.example/fleet\u{a0}x",
        );
    std::fs::write(tmp.0.join("nbsp/fleet.json"), cfg).unwrap();
    let refused = wl(
        &tmp.0,
        &[
            "fleet",
            "init",
            "f2",
            "--origin",
            "acme.example/fleet\u{a0}x",
            "--org",
            "A",
        ],
    );
    assert_eq!(refused.status.code(), Some(2), "{}", text(&refused.stderr));
    let witness = wl(
        &tmp.0,
        &[
            "witness",
            "init",
            "w",
            "--name",
            "w.example/witness",
            "--json",
        ],
    );
    let wvkey: serde_json::Value = serde_json::from_slice(&witness.stdout).unwrap();
    let base = ["witness-network", "log-list"];
    for (args, why) in [
        (
            vec!["--every", "60", "--contact", "x"],
            "name at least one log",
        ),
        (vec!["--fleet", "fleet", "--contact", "x"], "--every SECS"),
        (
            vec!["--fleet", "fleet", "--qpd", "0", "--contact", "x"],
            "--qpd must be",
        ),
        (
            vec!["--fleet", "fleet", "--qpd", "24"],
            "--contact is required",
        ),
        (
            vec![
                "--fleet",
                "fleet",
                "--fleet",
                "fleet",
                "--qpd",
                "1",
                "--contact",
                "x",
            ],
            "named twice",
        ),
        (
            vec![
                "--vkey",
                wvkey["vkey"].as_str().unwrap(),
                "--qpd",
                "1",
                "--contact",
                "x",
            ],
            "cosignature key",
        ),
        (
            vec!["--identity", "XYZ", "--qpd", "1", "--contact", "x"],
            "64 lowercase hex",
        ),
        (
            vec!["--fleet", "nowhere", "--qpd", "1", "--contact", "x"],
            "fleet.json",
        ),
        (
            vec!["--fleet", "nbsp", "--qpd", "1", "--contact", "x"],
            "has whitespace",
        ),
        (
            vec![
                "--fleet",
                "fleet",
                "--qpd",
                "1",
                "--contact",
                "x",
                "--list",
                "testing",
            ],
            "unexpected argument",
        ),
    ] {
        let out = wl(&tmp.0, &[&base[..], &args[..]].concat());
        let e = text(&out.stderr);
        assert_eq!(out.status.code(), Some(2), "{args:?}: {e}");
        assert!(e.contains(why), "{args:?}: want {why:?} in {e}");
        assert!(out.stdout.is_empty(), "{args:?}");
    }
}

#[test]
fn directory_add_takes_the_full_add_checkpoint_url() {
    let tmp = TempDir::new("dir");
    let w = wl(
        &tmp.0,
        &[
            "witness",
            "init",
            "w",
            "--name",
            "w.example/witness",
            "--json",
        ],
    );
    let vkey: serde_json::Value = serde_json::from_slice(&w.stdout).unwrap();
    let out = wl(
        &tmp.0,
        &[
            "directory",
            "add",
            "trusted.json",
            "--vkey",
            vkey["vkey"].as_str().unwrap(),
            "--org",
            "W Org",
            "--url",
            "https://w.example/witness/add-checkpoint",
        ],
    );
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert!(text(&out.stderr).contains("appends /add-checkpoint itself"));
    let d: serde_json::Value =
        serde_json::from_slice(&std::fs::read(tmp.0.join("trusted.json")).unwrap()).unwrap();
    assert_eq!(d["witnesses"][0]["url"], "https://w.example/witness");
}
