//! Integration tests for `witness-log demo` and `witness-log explain`.
//!
//! These are the two commands a new user hits first, so they carry more
//! weight than their line count suggests: if `demo` breaks, the project's
//! entire first impression breaks with it, and a broken first impression
//! is invisible to every other test in this repo.

use std::process::Command;

const EXIT_WITNESSED: i32 = 0;
const EXIT_INVALID: i32 = 40;
const EXIT_USAGE: i32 = 2;

fn run(args: &[&str]) -> (i32, String, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_witness-log"))
        .args(args)
        .output()
        .expect("failed to run witness-log");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).to_string(),
        String::from_utf8_lossy(&out.stderr).to_string(),
    )
}

#[test]
fn demo_runs_clean_and_ends_witnessed() {
    let (code, stdout, stderr) = run(&["demo"]);
    assert_eq!(
        code, EXIT_WITNESSED,
        "demo must end WITNESSED\nstderr: {stderr}"
    );
    assert!(!stderr.contains("panicked"), "{stderr}");
    // The whole point of the demo is the contrast between the two runs.
    assert!(
        stdout.contains("UNANCHORED"),
        "must show the unanchored run: {stdout}"
    );
    assert!(
        stdout.contains("WITNESSED"),
        "must show the anchored run: {stdout}"
    );
    assert!(
        stdout.contains("Same bytes"),
        "must make the contrast explicit rather than leaving it implied"
    );
}

#[test]
fn demo_writes_nothing_to_disk() {
    // The demo generates real keypairs. It must never persist them, or
    // leave anything behind in the user's working directory — a security
    // property, not a tidiness one.
    let scratch = std::env::temp_dir().join(format!("witness-log-demo-cwd-{}", std::process::id()));
    std::fs::create_dir_all(&scratch).unwrap();
    let before: Vec<_> = std::fs::read_dir(&scratch).unwrap().collect();
    assert!(before.is_empty(), "scratch dir should start empty");

    let out = Command::new(env!("CARGO_BIN_EXE_witness-log"))
        .arg("demo")
        .current_dir(&scratch)
        .output()
        .expect("failed to run witness-log");
    assert!(out.status.success());

    let after: Vec<_> = std::fs::read_dir(&scratch)
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    assert!(
        after.is_empty(),
        "demo must not write anything to the working directory, found: {after:?}"
    );
    std::fs::remove_dir_all(&scratch).ok();
}

#[test]
fn demo_output_is_stable_across_runs_except_for_keys() {
    // Two runs should produce the same narrative structure. Keys and
    // roots differ (fresh keypairs each run, by design), but if the
    // step-by-step scaffolding changes between runs something is
    // non-deterministic that shouldn't be.
    let (_, a, _) = run(&["demo"]);
    let (_, b, _) = run(&["demo"]);
    let strip_hex = |s: &str| -> Vec<String> {
        s.lines()
            .filter(|l| !l.contains('…')) // lines carrying shortened hex
            .map(|l| l.to_string())
            .collect()
    };
    assert_eq!(
        strip_hex(&a),
        strip_hex(&b),
        "demo narrative must be identical across runs once key material is stripped"
    );
}

#[test]
fn tamper_demo_ends_invalid_and_names_the_failing_check() {
    // Since 0.5.0 (RFC-0002) a file that fails a check is INVALID (40);
    // DIVERGED is reserved for a valid file that contradicts other evidence.
    let (code, stdout, stderr) = run(&["demo", "--tamper"]);
    assert_eq!(
        code, EXIT_INVALID,
        "a caught forgery must exit 40\nstderr: {stderr}"
    );
    assert!(!stderr.contains("panicked"), "{stderr}");
    assert!(stdout.contains("INVALID"), "{stdout}");
    // The teaching point: crypto passed, identity binding didn't.
    assert!(
        stdout.contains("Checkpoint signature valid"),
        "must show that the forgery's crypto was genuinely valid: {stdout}"
    );
    assert!(
        stdout.contains("Identity bound"),
        "must name identity binding as the check that caught it: {stdout}"
    );
}

#[test]
fn bare_invocation_points_at_the_demo() {
    // Someone who just installed this and typed the binary name is asking
    // "what is this?" — the answer should be a runnable command, not a
    // usage dump.
    let (code, stdout, _) = run(&[]);
    assert_eq!(code, 0, "bare invocation is not an error");
    assert!(stdout.contains("witness-log demo"), "{stdout}");
}

#[test]
fn explain_covers_every_verdict() {
    let (code, stdout, _) = run(&["explain"]);
    assert_eq!(code, 0);
    for verdict in [
        "WITNESSED",
        "CONSISTENT-UNWITNESSED",
        "UNANCHORED",
        "DIVERGED",
    ] {
        assert!(
            stdout.contains(verdict),
            "explain must cover {verdict}: {stdout}"
        );
    }
}

#[test]
fn explain_states_what_each_verdict_does_not_prove() {
    // The negative space is the part that matters — a verdict's limits are
    // what stop someone over-trusting it.
    let (_, stdout, _) = run(&["explain", "witnessed"]);
    assert!(stdout.contains("does NOT prove"), "{stdout}");
    assert!(
        stdout.contains("TRUE") || stdout.contains("true"),
        "WITNESSED must state it doesn't prove the content is true: {stdout}"
    );
}

#[test]
fn explain_json_is_parseable_and_complete() {
    // An agent hitting an unexpected verdict calls this. It must parse.
    let (code, stdout, _) = run(&["explain", "unanchored", "--json"]);
    assert_eq!(code, 0);
    let parsed: serde_json::Value =
        serde_json::from_str(&stdout).expect("explain --json must emit valid JSON");
    let arr = parsed.as_array().expect("expected an array");
    assert_eq!(arr.len(), 1);
    let entry = &arr[0];
    for field in [
        "verdict",
        "exit_code",
        "summary",
        "proves",
        "does_not_prove",
        "next_step",
    ] {
        assert!(
            entry.get(field).is_some(),
            "missing field `{field}` in {entry}"
        );
    }
    assert_eq!(entry["verdict"], "UNANCHORED");
    assert_eq!(entry["exit_code"], 20);
}

#[test]
fn explain_documented_exit_codes_match_the_real_ones() {
    // If `explain` says UNANCHORED is 20 but the binary returns something
    // else, an agent gating on the documented code silently does the wrong
    // thing. Cross-check the documentation against reality.
    let (_, stdout, _) = run(&["explain", "--json"]);
    let parsed: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let expected: Vec<(String, u64)> = parsed
        .as_array()
        .unwrap()
        .iter()
        .map(|e| {
            (
                e["verdict"].as_str().unwrap().to_string(),
                e["exit_code"].as_u64().unwrap(),
            )
        })
        .collect();

    // demo ends WITNESSED; demo --tamper ends INVALID. Verify those two
    // against what explain claims.
    let witnessed_code = expected.iter().find(|(v, _)| v == "WITNESSED").unwrap().1;
    let diverged_code = expected.iter().find(|(v, _)| v == "INVALID").unwrap().1;
    let (demo_code, _, _) = run(&["demo"]);
    let (tamper_code, _, _) = run(&["demo", "--tamper"]);
    assert_eq!(
        demo_code as u64, witnessed_code,
        "explain's WITNESSED code disagrees with reality"
    );
    assert_eq!(
        tamper_code as u64, diverged_code,
        "explain's INVALID code disagrees with reality"
    );
}

#[test]
fn explain_rejects_an_unknown_topic() {
    let (code, _, stderr) = run(&["explain", "nonsense-verdict"]);
    assert_eq!(code, EXIT_USAGE);
    assert!(stderr.contains("unknown topic"), "{stderr}");
}

#[test]
fn explain_json_without_a_topic_lists_everything() {
    // Regression: `--json` was previously consumed as the topic name, so
    // this returned nothing at all. Flags must never be read as
    // positional arguments — the same bug class the first review caught
    // in `verify`, which reappeared here in new code.
    let (code, stdout, _) = run(&["explain", "--json"]);
    assert_eq!(code, 0, "explain --json with no topic must succeed");
    let parsed: serde_json::Value = serde_json::from_str(&stdout).expect("must be valid JSON");
    assert_eq!(
        parsed.as_array().unwrap().len(),
        6,
        "all five verdicts plus the split-view exit: {stdout}"
    );
}

#[test]
fn demo_rejects_an_unrecognized_flag() {
    // A typo'd `--tampr` must not silently run the non-tamper demo.
    let (code, _, stderr) = run(&["demo", "--tampr"]);
    assert_eq!(code, EXIT_USAGE, "a typo'd flag must be rejected");
    assert!(stderr.contains("unrecognized"), "{stderr}");
}

#[test]
fn diff_rejects_extra_paths_and_stray_flags() {
    let (code, _, stderr) = run(&["diff", "a.json", "b.json", "c.json"]);
    assert_eq!(code, EXIT_USAGE, "diff compares exactly two files");
    assert!(stderr.contains("usage:"), "{stderr}");

    let (code, _, stderr) = run(&["diff", "a.json", "b.json", "--verbose"]);
    assert_eq!(code, EXIT_USAGE, "an unrecognized flag must be rejected");
    assert!(stderr.contains("unrecognized flag"), "{stderr}");
}

/// The CLI quickstart says "Every subcommand has `--help`". Through 0.6.1
/// `demo`, `diff`, `bind`, `c2sp` and `conform` answered it with
/// "unrecognized flag" and exit 2. Every command and subcommand the main
/// help lists answers `--help` and `-h` with usage that names it.
#[test]
fn every_subcommand_in_help_answers_help() {
    let (_, help, _) = run(&["--help"]);
    let mut cmds: Vec<Vec<&str>> = Vec::new();
    for line in help.lines() {
        let Some(rest) = line.strip_prefix("  witness-log ") else {
            continue;
        };
        let words: Vec<&str> = rest.split_whitespace().take(2).collect();
        if words[0].starts_with('-') {
            continue;
        }
        cmds.push(vec![words[0]]);
        if let Some(sub) = words
            .get(1)
            .filter(|w| w.chars().all(|c| c.is_ascii_lowercase() || c == '-'))
        {
            cmds.push(vec![words[0], sub]);
        }
    }
    cmds.dedup();
    assert!(cmds.len() >= 30, "{cmds:?}");
    for cmd in &cmds {
        for flag in ["--help", "-h"] {
            let mut args = cmd.clone();
            args.push(flag);
            let (code, stdout, stderr) = run(&args);
            let name = cmd.last().unwrap();
            assert_eq!(code, 0, "`{args:?}`\nstdout: {stdout}\nstderr: {stderr}");
            assert!(
                stdout.contains("witness-log ") && stdout.contains(&format!(" {name} ")),
                "`{args:?}` must show its usage: {stdout}"
            );
        }
    }
    let (_, stdout, _) = run(&["conform", "--help"]);
    assert!(stdout.contains("--reference"), "{stdout}");
    let (_, stdout, _) = run(&["c2sp", "export", "--help"]);
    for flag in ["--sign-with", "--identity-seed-env", "--identity-seed-file"] {
        assert!(stdout.contains(flag), "{flag}: {stdout}");
    }
}

/// `--help` or `-h` is a help request only on its own after the command.
/// Anywhere else it is an ordinary argument: through 0.6.1 most commands
/// answered it anywhere, so `verify d.json --identity --help` exited 0, the
/// code a gate reads as "verified".
#[test]
fn help_anywhere_else_is_an_argument_not_a_success() {
    for args in [
        &["verify", "d.json", "--identity", "--help"][..],
        &["verify", "d.json", "-h"],
        &["verify", "--help", "d.json"],
        &["c2sp", "verify", "note.txt", "--vkey", "-h"],
        &["c2sp", "show", "d.json", "--origin", "--help"],
        &["diff", "-h", "b.json"],
        &["bind", "a.json", "--help"],
        &["demo", "--tamper", "--help"],
        &["conform", "dir", "--help"],
        &["witness", "verify-evidence", "x.json", "-h"],
        &["witness", "--help", "info"],
        &["submit", "j.jsonl", "--directory", "--help"],
        &["log", "info", "j.jsonl", "--help"],
        &["doctor", "--offline", "--help"],
        &["directory", "build", "--out", "--help"],
        &["journal", "serve", "j.jsonl", "-h"],
        &["fleet", "init", "x", "--help"],
    ] {
        let (code, stdout, stderr) = run(args);
        assert_ne!(
            code, 0,
            "`{args:?}` must not succeed\nstdout: {stdout}\nstderr: {stderr}"
        );
        assert!(
            !stdout.contains("usage"),
            "`{args:?}` printed help: {stdout}"
        );
    }
}

#[test]
fn help_lists_every_subcommand_and_the_exit_codes() {
    let (code, stdout, _) = run(&["--help"]);
    assert_eq!(code, 0);
    for cmd in ["demo", "verify", "diff", "explain", "conform"] {
        assert!(stdout.contains(cmd), "help must mention `{cmd}`: {stdout}");
    }
    assert!(
        stdout.contains("EXIT CODES"),
        "help must document exit codes: {stdout}"
    );
}
