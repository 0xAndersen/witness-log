//! `testnet up` again after `testnet down`, and a witness that cannot
//! start. Both were found by the audit of the 0.6.1 dependency update:
//! `up` read the previous run's port from the witness log it appends to
//! (so the second `up` on a directory always waited for a dead port, then
//! failed), and a witness that exited at once was reported only when the
//! start timeout ran out.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{Duration, Instant};

const BIN: &str = env!("CARGO_BIN_EXE_witness-log");

struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        let p = std::env::temp_dir().join(format!(
            "wl-testnet-{tag}-{}-{}",
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
        let _ = Command::new(BIN)
            .args(["testnet", "down", "--dir"])
            .arg(self.0.join("tn"))
            .output();
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

fn up(root: &Path) -> (Output, Duration) {
    let t = Instant::now();
    let out = wl(
        root,
        &[
            "testnet",
            "up",
            "--witnesses",
            "1",
            "--dir",
            "tn",
            "--out",
            "trusted.json",
        ],
    );
    (out, t.elapsed())
}

fn err(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

#[test]
fn up_down_up_on_the_same_directory_starts_again() {
    let tmp = TempDir::new("again");
    for round in 0..3 {
        let (out, took) = up(&tmp.0);
        assert_eq!(out.status.code(), Some(0), "round {round}: {}", err(&out));
        // A fresh port each time, found at once: not the previous run's.
        assert!(
            took < Duration::from_secs(20),
            "round {round} took {took:?}"
        );
        let down = wl(&tmp.0, &["testnet", "down", "--dir", "tn"]);
        assert_eq!(down.status.code(), Some(0), "{}", err(&down));
    }
}

#[test]
fn a_witness_that_cannot_start_is_reported_at_once_with_its_log() {
    let tmp = TempDir::new("badkey");
    // A first `up` creates the witness's state; then break its key.
    let (out, _) = up(&tmp.0);
    assert_eq!(out.status.code(), Some(0), "{}", err(&out));
    let down = wl(&tmp.0, &["testnet", "down", "--dir", "tn"]);
    assert_eq!(down.status.code(), Some(0), "{}", err(&down));
    std::fs::write(tmp.0.join("tn/testnet-a/witness.key"), "not a key\n").unwrap();
    let (out, took) = up(&tmp.0);
    let e = err(&out);
    assert_ne!(out.status.code(), Some(0), "{e}");
    assert!(
        took < Duration::from_secs(20),
        "reported after {took:?}: {e}"
    );
    assert!(e.contains("exited") && e.contains("its log ends:"), "{e}");
}
