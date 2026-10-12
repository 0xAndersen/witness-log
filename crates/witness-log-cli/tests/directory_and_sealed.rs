//! `directory build` / `directory add`, sealed journals from the CLI, and
//! the promise that dossiers written before `witness_name` existed still
//! verify.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const BIN: &str = env!("CARGO_BIN_EXE_witness-log");

fn tmpdir(tag: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!(
        "wl-dirsealed-{tag}-{}-{}",
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

fn wl_env(cwd: &Path, args: &[&str], env: &[(&str, &str)]) -> Output {
    Command::new(BIN)
        .current_dir(cwd)
        .args(args)
        .envs(env.iter().copied())
        .output()
        .unwrap()
}

fn code(o: &Output) -> i32 {
    o.status.code().unwrap_or(-1)
}

fn err(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).to_string()
}

fn entry(name: &str, org: &str, project: bool) -> (String, serde_json::Value) {
    let key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
    let pubkey = hex::encode(key.verifying_key().to_bytes());
    let vkey =
        witness_log_core::c2sp::VerifierKey::for_cosignature(name, &key.verifying_key()).encode();
    (
        vkey,
        serde_json::json!({
            "name": name,
            "operator_org": org,
            "url": format!("https://{}", name.split('/').next().unwrap()),
            "pubkey": pubkey,
            "runtime": "human",
            "compute_provider": "some-cloud",
            "is_project_operated": project,
        }),
    )
}

/// `directory build` reads one entry per file and writes exactly the
/// `{"witnesses": [...]}` document `registry/build_directory.py` prints:
/// same entries, same fields, file-name order.
#[test]
fn directory_build_matches_the_registry_script_schema() {
    let root = tmpdir("build");
    let reg = root.join("witnesses");
    std::fs::create_dir_all(&reg).unwrap();
    let (_, a) = entry("a.example/w", "Org A", false);
    let (_, b) = entry("b.example/w", "Org B", false);
    let (_, p) = entry("p.example/w", "project-operated", true);
    for (file, e) in [("org-a.json", &a), ("org-b.json", &b), ("project.json", &p)] {
        std::fs::write(reg.join(file), serde_json::to_vec_pretty(e).unwrap()).unwrap();
    }
    let reg_s = reg.display().to_string();

    // Independents only, by default.
    let out = wl(
        &root,
        &[
            "directory",
            "build",
            "--registry",
            &reg_s,
            "--out",
            "t.json",
        ],
    );
    assert_eq!(code(&out), 0, "{}", err(&out));
    let t: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(root.join("t.json")).unwrap()).unwrap();
    assert_eq!(
        t,
        serde_json::json!({ "witnesses": [a.clone(), b.clone()] })
    );

    // --include-project keeps the project-operated entry, in file order.
    let out = wl(
        &root,
        &[
            "directory",
            "build",
            "--registry",
            &reg_s,
            "--include-project",
            "--out",
            "all.json",
        ],
    );
    assert_eq!(code(&out), 0, "{}", err(&out));
    let all: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(root.join("all.json")).unwrap()).unwrap();
    assert_eq!(
        all,
        serde_json::json!({ "witnesses": [a.clone(), b.clone(), p.clone()] })
    );
    // ... and `verify` accepts the file as a directory.
    let d: witness_log_network::WitnessDirectory = serde_json::from_value(all).unwrap();
    assert_eq!(d.witnesses.len(), 3);
    assert_eq!(d.distinct_operator_count(), 3);

    // A malformed entry fails the build, naming the file.
    let mut bad = a.clone();
    bad["pubkey"] = serde_json::Value::String("zz".into());
    std::fs::write(reg.join("zz-bad.json"), serde_json::to_vec(&bad).unwrap()).unwrap();
    let out = wl(
        &root,
        &[
            "directory",
            "build",
            "--registry",
            &reg_s,
            "--out",
            "x.json",
        ],
    );
    assert_eq!(code(&out), 1);
    assert!(err(&out).contains("zz-bad.json"), "{}", err(&out));
    std::fs::remove_file(reg.join("zz-bad.json")).unwrap();
    // A duplicate key fails too (the same rule registry/validate.py applies).
    std::fs::write(reg.join("dup.json"), serde_json::to_vec(&a).unwrap()).unwrap();
    let out = wl(
        &root,
        &[
            "directory",
            "build",
            "--registry",
            &reg_s,
            "--out",
            "x.json",
        ],
    );
    assert_eq!(code(&out), 1);
    assert!(err(&out).contains("duplicate pubkey"), "{}", err(&out));
    let out = wl(&root, &["directory", "build", "--registry", &reg_s]);
    assert_eq!(code(&out), 2, "--out is required");
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn directory_add_by_vkey() {
    let root = tmpdir("add");
    let (vkey_a, a) = entry("a.example/w", "Org A", false);
    let (vkey_b, _) = entry("b.example/w", "Org B", false);
    // Creates the file.
    let out = wl(
        &root,
        &[
            "directory",
            "add",
            "t.json",
            "--vkey",
            &vkey_a,
            "--org",
            "Org A",
            "--url",
            "https://a.example",
            "--compute",
            "some-cloud",
        ],
    );
    assert_eq!(code(&out), 0, "{}", err(&out));
    let t: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(root.join("t.json")).unwrap()).unwrap();
    assert_eq!(t["witnesses"].as_array().unwrap().len(), 1);
    assert_eq!(t["witnesses"][0]["pubkey"], a["pubkey"]);
    assert_eq!(t["witnesses"][0]["name"], "a.example/w");
    assert_eq!(t["witnesses"][0]["is_project_operated"], false);
    // Appends to it.
    let out = wl(
        &root,
        &[
            "directory",
            "add",
            "t.json",
            "--vkey",
            &vkey_b,
            "--org",
            "Org B",
            "--url",
            "http://b.example",
        ],
    );
    assert_eq!(code(&out), 0, "{}", err(&out));
    // Refuses the same key twice, a log key, a bad URL, and an empty org.
    let out = wl(
        &root,
        &[
            "directory",
            "add",
            "t.json",
            "--vkey",
            &vkey_a,
            "--org",
            "Org A",
            "--url",
            "https://a.example",
        ],
    );
    assert_eq!(code(&out), 1, "{}", err(&out));
    assert!(err(&out).contains("already listed"));
    let log_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
    let log_vkey =
        witness_log_core::c2sp::VerifierKey::for_ed25519("c.example/log", &log_key.verifying_key())
            .encode();
    let out = wl(
        &root,
        &[
            "directory",
            "add",
            "t.json",
            "--vkey",
            &log_vkey,
            "--org",
            "Org C",
            "--url",
            "https://c.example",
        ],
    );
    assert_eq!(code(&out), 2, "{}", err(&out));
    let out = wl(
        &root,
        &[
            "directory",
            "add",
            "t.json",
            "--vkey",
            &vkey_b,
            "--org",
            "Org D",
            "--url",
            "ftp://d",
        ],
    );
    assert_eq!(code(&out), 2);
    let out = wl(
        &root,
        &[
            "directory",
            "add",
            "t.json",
            "--vkey",
            &vkey_b,
            "--org",
            "  ",
            "--url",
            "https://d.example",
        ],
    );
    assert_eq!(code(&out), 2);
    let t: witness_log_network::WitnessDirectory =
        serde_json::from_str(&std::fs::read_to_string(root.join("t.json")).unwrap()).unwrap();
    assert_eq!(t.witnesses.len(), 2);
    assert_eq!(t.distinct_operator_count(), 2);
    let _ = std::fs::remove_dir_all(&root);
}

/// A sealed journal never holds its seed. Every command takes the seed
/// from an environment variable or a file, never the command line, and a
/// sealed journal without it is refused with a message that says so.
#[test]
fn sealed_journal_from_the_cli() {
    let root = tmpdir("sealed");
    // --sealed with no seed source: refused before anything is written.
    let out = wl(&root, &["log", "init", "s.jsonl", "--sealed"]);
    assert_eq!(code(&out), 2, "{}", err(&out));
    assert!(!root.join("s.jsonl").exists());

    // A seed file that does not exist yet is generated (0600) and used.
    let out = wl(
        &root,
        &[
            "log",
            "init",
            "s.jsonl",
            "--sealed",
            "--identity-seed-file",
            "seed.hex",
        ],
    );
    assert_eq!(code(&out), 0, "{}", err(&out));
    let init: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(init["sealed"], true);
    assert_eq!(init["seed_file"], "seed.hex");
    let identity = init["identity"].as_str().unwrap().to_string();
    let seed_hex = std::fs::read_to_string(root.join("seed.hex"))
        .unwrap()
        .trim()
        .to_string();
    assert_eq!(seed_hex.len(), 64);
    let header = std::fs::read_to_string(root.join("s.jsonl")).unwrap();
    assert!(
        !header.contains(&seed_hex),
        "the seed must not be in the journal"
    );
    assert!(header.lines().next().unwrap().contains(&identity));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(root.join("seed.hex"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
    }

    // Without the seed: refused, with the reason. With it, from the file
    // or from the environment: works.
    let out = wl(&root, &["log", "append", "s.jsonl", "--intent", "x"]);
    assert_eq!(code(&out), 1, "{}", err(&out));
    assert!(err(&out).contains("sealed"), "{}", err(&out));
    let out = wl(
        &root,
        &[
            "log",
            "append",
            "s.jsonl",
            "--intent",
            "x",
            "--identity-seed-file",
            "seed.hex",
        ],
    );
    assert_eq!(code(&out), 0, "{}", err(&out));
    let out = wl_env(
        &root,
        &[
            "log",
            "append",
            "s.jsonl",
            "--intent",
            "y",
            "--identity-seed-env",
            "WL_SEED",
        ],
        &[("WL_SEED", &seed_hex)],
    );
    assert_eq!(code(&out), 0, "{}", err(&out));
    let out = wl(
        &root,
        &[
            "log",
            "append",
            "s.jsonl",
            "--intent",
            "y",
            "--identity-seed-env",
            "WL_UNSET_VAR",
        ],
    );
    assert_eq!(code(&out), 2, "{}", err(&out));
    // The wrong seed is refused: a stranger cannot continue this history.
    std::fs::write(root.join("wrong.hex"), "11".repeat(32)).unwrap();
    let out = wl(
        &root,
        &[
            "log",
            "append",
            "s.jsonl",
            "--intent",
            "z",
            "--identity-seed-file",
            "wrong.hex",
        ],
    );
    assert_eq!(code(&out), 1, "{}", err(&out));
    assert!(err(&out).contains("does not match"), "{}", err(&out));

    // info without the seed still reports the public facts.
    let out = wl(&root, &["log", "info", "s.jsonl"]);
    assert_eq!(code(&out), 0, "{}", err(&out));
    let info: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(info["sealed"], true);
    assert_eq!(info["identity"], identity);
    let out = wl(
        &root,
        &["log", "info", "s.jsonl", "--identity-seed-file", "seed.hex"],
    );
    let info: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(info["tree_size"], 2);

    // disclose, forget, export with the seed.
    let out = wl(
        &root,
        &[
            "log",
            "disclose",
            "s.jsonl",
            "0",
            "--identity-seed-file",
            "seed.hex",
        ],
    );
    assert_eq!(code(&out), 0, "{}", err(&out));
    let out = wl(
        &root,
        &[
            "log",
            "forget",
            "s.jsonl",
            "0",
            "--identity-seed-file",
            "seed.hex",
        ],
    );
    assert_eq!(code(&out), 0, "{}", err(&out));
    let out = wl(
        &root,
        &[
            "log",
            "export",
            "s.jsonl",
            "--out",
            "d.json",
            "--identity-seed-file",
            "seed.hex",
        ],
    );
    assert_eq!(code(&out), 0, "{}", err(&out));
    let out = wl(&root, &["log", "export", "s.jsonl", "--out", "d2.json"]);
    assert_eq!(code(&out), 1, "export needs the key to sign the checkpoint");
    let v = wl(&root, &["verify", "d.json", "--identity", &identity]);
    assert_eq!(code(&v), 20, "{}", String::from_utf8_lossy(&v.stdout));

    // c2sp show --sign-with on the sealed journal, seed from the environment.
    let out = wl_env(
        &root,
        &[
            "c2sp",
            "show",
            "d.json",
            "--origin",
            &format!("witness-log/{identity}"),
            "--sign-with",
            "s.jsonl",
            "--raw",
            "--identity-seed-env",
            "WL_SEED",
        ],
        &[("WL_SEED", &seed_hex)],
    );
    assert_eq!(code(&out), 0, "{}", err(&out));
    std::fs::write(root.join("note.txt"), &out.stdout).unwrap();
    let pk: [u8; 32] = hex::decode(&identity).unwrap().try_into().unwrap();
    let vkey = witness_log_core::c2sp::VerifierKey::for_ed25519(
        &format!("witness-log/{identity}"),
        &ed25519_dalek::VerifyingKey::from_bytes(&pk).unwrap(),
    )
    .encode();
    let out = wl(&root, &["c2sp", "verify", "note.txt", "--vkey", &vkey]);
    assert_eq!(code(&out), 0, "{}", String::from_utf8_lossy(&out.stdout));
    let out = wl(
        &root,
        &[
            "c2sp",
            "show",
            "d.json",
            "--origin",
            "x",
            "--sign-with",
            "s.jsonl",
        ],
    );
    assert_eq!(code(&out), 2, "sealed, no seed: {}", err(&out));

    // submit on a sealed journal takes the same flags (no witnesses here,
    // so the directory is empty and nothing is contacted; the point is
    // that the journal opens). Both flags at once is a usage error.
    std::fs::write(root.join("empty.json"), r#"{"witnesses":[]}"#).unwrap();
    let out = wl(
        &root,
        &[
            "submit",
            "s.jsonl",
            "--directory",
            "empty.json",
            "--out",
            "o.json",
            "--min",
            "0",
            "--identity-seed-file",
            "seed.hex",
        ],
    );
    assert_eq!(code(&out), 0, "{}", err(&out));
    let out = wl(
        &root,
        &[
            "submit",
            "s.jsonl",
            "--directory",
            "empty.json",
            "--out",
            "o.json",
        ],
    );
    assert_eq!(code(&out), 2, "{}", err(&out));
    let out = wl(
        &root,
        &[
            "submit",
            "s.jsonl",
            "--directory",
            "empty.json",
            "--identity-seed-file",
            "seed.hex",
            "--identity-seed-env",
            "X",
        ],
    );
    assert_eq!(code(&out), 2);

    // An unsealed journal created from a seed file gets that identity.
    let out = wl(
        &root,
        &["log", "init", "u.jsonl", "--identity-seed-file", "seed.hex"],
    );
    assert_eq!(code(&out), 0, "{}", err(&out));
    let init: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(init["identity"], identity);
    assert_eq!(init["sealed"], false);
    let _ = std::fs::remove_dir_all(&root);
}

/// The committed sample dossier predates `witness_name` on receipts (and
/// the C2SP receipt form). It must keep verifying WITNESSED against its
/// directory, and `verify --strict` must agree (3 of 4 is a majority).
#[test]
fn old_fixture_dossier_still_verifies() {
    let repo = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let dossier = repo.join("examples/sample-dossier.json");
    let directory = repo.join("examples/trusted-directory.json");
    let raw = std::fs::read_to_string(&dossier).unwrap();
    assert!(
        !raw.contains("witness_name"),
        "fixture must stay a pre-0.4.0 dossier for this test to mean anything"
    );
    let parsed: witness_log_network::Dossier = serde_json::from_str(&raw).unwrap();
    assert!(parsed
        .witness_receipts
        .iter()
        .all(|r| r.witness_name.is_none()));
    let out = wl(
        &repo,
        &[
            "verify",
            dossier.to_str().unwrap(),
            "--directory",
            directory.to_str().unwrap(),
            "--strict",
        ],
    );
    assert_eq!(code(&out), 0, "{}", String::from_utf8_lossy(&out.stdout));
    let out = wl(
        &repo,
        &[
            "verify",
            dossier.to_str().unwrap(),
            "--directory",
            directory.to_str().unwrap(),
            "--json",
        ],
    );
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["verdict"], "WITNESSED");
    assert_eq!(v["strict"], false);
}

/// `verify-evidence` is documented in the top-level help, as are the new
/// commands and exit code 11.
#[test]
fn help_lists_every_command_and_exit_code() {
    let out = wl(Path::new("."), &["--help"]);
    assert_eq!(code(&out), 0);
    let help = String::from_utf8_lossy(&out.stdout);
    for needle in [
        "verify-evidence",
        "testnet up",
        "testnet down",
        "log init",
        "log append",
        "log forget",
        "log export",
        "log disclose",
        "log info",
        "journal serve",
        "directory build",
        "directory add",
        "c2sp export",
        "--strict",
        "11  verify --strict",
        "20  UNANCHORED; submit",
    ] {
        assert!(help.contains(needle), "help is missing {needle:?}");
    }
}
