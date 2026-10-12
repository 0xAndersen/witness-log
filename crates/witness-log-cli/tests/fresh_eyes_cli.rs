//! Regressions for CLI defects the 0.3.5 fresh-eyes evaluation found
//! (hostile-input and integrator personas). Each fails on 0.3.5.

mod common;

use std::process::{Command, Output};

fn wl(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_witness-log"))
        .args(args)
        .output()
        .expect("run witness-log")
}

fn tmpdir(tag: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!(
        "wl-cli-fresh-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// `verify /dev/zero` read until the OOM killer ended the process.
#[cfg(unix)]
#[test]
fn verify_refuses_an_unbounded_input_instead_of_exhausting_memory() {
    let out = wl(&["verify", "/dev/zero"]);
    assert_eq!(out.status.code(), Some(2), "{out:?}");
    assert!(String::from_utf8_lossy(&out.stderr).contains("larger than"));
}

/// `witness submit --mni 2` was silently ignored.
#[test]
fn submit_rejects_unknown_flags() {
    let d = tmpdir("submit");
    let j = d.join("a.jsonl");
    let out = wl(&[
        "witness",
        "submit",
        j.to_str().unwrap(),
        "--directory",
        "x.json",
        "--mni",
        "2",
    ]);
    assert_eq!(out.status.code(), Some(2), "{out:?}");
    assert!(String::from_utf8_lossy(&out.stderr).contains("--mni"));
}

/// `witness init --org ""` and `--url ftp://x` produced entries that were
/// scored as an operator named "" / could not be submitted to.
#[test]
fn init_rejects_an_empty_org_and_a_non_http_url() {
    let d = tmpdir("init");
    for (i, extra) in [["--org", ""], ["--url", "ftp://x"], ["--url", "not a url"]]
        .iter()
        .enumerate()
    {
        let dir = d.join(format!("w{i}"));
        let mut args = vec![
            "witness",
            "init",
            dir.to_str().unwrap(),
            "--name",
            "w.test/x",
        ];
        args.extend_from_slice(extra);
        let out = wl(&args);
        assert_eq!(out.status.code(), Some(2), "{extra:?}: {out:?}");
        assert!(
            !dir.join("witness.key").exists(),
            "no key on a refused init"
        );
    }
    let ok = d.join("ok");
    let out = wl(&[
        "witness",
        "init",
        ok.to_str().unwrap(),
        "--name",
        "w.test/x",
        "--org",
        "Org",
        "--url",
        "https://w.example",
    ]);
    assert!(out.status.success(), "{out:?}");
}

/// A trusted directory entry with a malformed key was silently ignored.
#[test]
fn verify_warns_about_malformed_directory_entries() {
    let dossier = common::write_standalone_dossier(b"x");
    let dir = common::TmpJson::write(
        r#"{"witnesses":[{"name":"bad","operator_org":"o","url":"http://x","pubkey":"zz"}]}"#,
    );
    let out = wl(&["verify", dossier.path(), "--directory", dir.path()]);
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("malformed pubkey"), "{err}");
}

/// `conform` only worked from the repository root.
#[test]
fn conform_takes_a_reference_corpus_path() {
    let corpus = concat!(env!("CARGO_MANIFEST_DIR"), "/../../corpus");
    let elsewhere = tmpdir("conform");
    let out = Command::new(env!("CARGO_BIN_EXE_witness-log"))
        .args(["conform", corpus, "--reference", corpus])
        .current_dir(&elsewhere)
        .output()
        .unwrap();
    assert!(out.status.success(), "{out:?}");
    assert!(String::from_utf8_lossy(&out.stdout).contains("CONFORMANT"));
    let out = wl(&["conform", corpus, "--bogus"]);
    assert_eq!(out.status.code(), Some(2));
}
