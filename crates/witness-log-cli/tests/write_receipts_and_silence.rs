//! `log receipt` and `prove-silence`: a log signs a write receipt when it
//! accepts an event, and the party holding it later checks the log's
//! witnessed dossiers for that event (SPEC §9.4).
//!
//! The journal, its events and the receipt go through the CLI. The
//! witnessed dossiers are built here with the library (each checkpoint
//! cosigned by witnesses of two organisations), the way
//! `crates/witness-log-network/tests/review3_silence_proof.rs` builds them,
//! instead of through `submit` and a network.

use ed25519_dalek::SigningKey;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use witness_log_core::identity::IdentityKeypair;
use witness_log_core::log::WitnessLog;
use witness_log_core::sth::WriteReceipt;
use witness_log_network::{
    Dossier, WitnessDirectory, WitnessEntry, WitnessReceipt, WitnessRuntime,
};

const BIN: &str = env!("CARGO_BIN_EXE_witness-log");

/// The log's identity seed: fixed, so the "censoring" history below can be
/// signed by the same key as the journal.
const SEED: [u8; 32] = [7u8; 32];

/// A temporary directory that removes itself.
struct Tmp(PathBuf);

impl Tmp {
    fn new(tag: &str) -> Self {
        let p = std::env::temp_dir().join(format!(
            "wl-silence-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&p).unwrap();
        Tmp(p)
    }
    fn path(&self, name: &str) -> String {
        self.0.join(name).to_str().unwrap().to_string()
    }
    fn write(&self, name: &str, contents: &str) -> String {
        let p = self.path(name);
        std::fs::write(&p, contents).unwrap();
        p
    }
}

impl Drop for Tmp {
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

fn code(o: &Output) -> i32 {
    o.status.code().unwrap_or(-1)
}

fn out(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).to_string()
}

fn err(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).to_string()
}

fn json(o: &Output) -> serde_json::Value {
    serde_json::from_slice(&o.stdout)
        .unwrap_or_else(|e| panic!("not JSON ({e}): {}\nstderr: {}", out(o), err(o)))
}

/// Two witnesses, one per organisation: the least that makes a checkpoint
/// witnessed (two independent operators).
fn witnesses() -> (WitnessDirectory, Vec<SigningKey>) {
    let mut dir = WitnessDirectory::default();
    let mut keys = Vec::new();
    for (i, org) in ["Org A", "Org B"].iter().enumerate() {
        let key = SigningKey::generate(&mut rand::rngs::OsRng);
        dir.witnesses.push(WitnessEntry {
            name: format!("w{i}.example/w"),
            operator_org: org.to_string(),
            url: format!("https://w{i}.example"),
            pubkey: hex::encode(key.verifying_key().to_bytes()),
            runtime: WitnessRuntime::Human,
            compute_provider: None,
            is_project_operated: false,
        });
        keys.push(key);
    }
    (dir, keys)
}

/// The log's checkpoint at its current size, cosigned by `witnesses`, as a
/// dossier.
fn witnessed_dossier(log: &WitnessLog, witnesses: &[SigningKey]) -> Dossier {
    let cp = log.checkpoint(&SigningKey::from_bytes(&SEED));
    let mut d = Dossier::from_log(log, cp.clone());
    d.witness_receipts = witnesses
        .iter()
        .map(|w| WitnessReceipt::sign(w, &cp, cp.timestamp_ms + 1))
        .collect();
    d
}

fn write_dossier(t: &Tmp, name: &str, d: &Dossier) -> String {
    t.write(name, &serde_json::to_string_pretty(d).unwrap())
}

/// A journal (through the CLI) holding `e0 e1 e2 <the event> e4`, its
/// write receipt for the event at index 3, and the trusted directory.
struct Setup {
    t: Tmp,
    journal: String,
    receipt: String,
    directory: String,
    witnesses: Vec<SigningKey>,
    identity: String,
}

impl Setup {
    fn new(tag: &str) -> Self {
        let t = Tmp::new(tag);
        let seed_file = t.write("seed.hex", &hex::encode(SEED));
        let journal = t.path("agent.jsonl");
        let init = wl(
            &t.0,
            &["log", "init", &journal, "--identity-seed-file", &seed_file],
        );
        assert_eq!(code(&init), 0, "{}", err(&init));
        let identity = json(&init)["identity"].as_str().unwrap().to_string();
        for p in ["e0", "e1", "e2", "the event", "e4"] {
            let a = wl(&t.0, &["log", "append", &journal, "--intent", p]);
            assert_eq!(code(&a), 0, "{}", err(&a));
        }
        let receipt = t.path("receipt.json");
        let r = wl(&t.0, &["log", "receipt", &journal, "3", "--out", &receipt]);
        assert_eq!(code(&r), 0, "{}", err(&r));
        let (dir, witnesses) = witnesses();
        let directory = t.write("trusted.json", &serde_json::to_string(&dir).unwrap());
        Setup {
            t,
            journal,
            receipt,
            directory,
            witnesses,
            identity,
        }
    }

    fn append(&self, payload: &str) {
        let a = wl(
            &self.t.0,
            &["log", "append", &self.journal, "--intent", payload],
        );
        assert_eq!(code(&a), 0, "{}", err(&a));
    }

    /// The journal as it stands, cosigned by both witnesses.
    fn witness_journal(&self, name: &str) -> (String, WitnessLog) {
        let (log, _) = witness_log_core::journal::LeafJournal::replay(&self.journal).unwrap();
        let p = write_dossier(&self.t, name, &witnessed_dossier(&log, &self.witnesses));
        (p, log)
    }

    /// An honest log: the event stays. Witnessed at sizes 5 and 9.
    fn honest(&self) -> (String, String, WitnessLog) {
        let (d5, _) = self.witness_journal("d5.json");
        for p in ["e5", "e6", "e7", "e8"] {
            self.append(p);
        }
        let (d9, log9) = self.witness_journal("d9.json");
        (d5, d9, log9)
    }

    /// The same identity publishes histories without the event, witnessed
    /// at sizes 5 and 9, after signing the receipt for it.
    fn censoring(&self) -> (String, String, WitnessLog) {
        let mut log = WitnessLog::resume(IdentityKeypair::from_bytes(&SEED), 0);
        let mut d5 = None;
        for i in 0..9 {
            log.append_intent(format!("other {i}").as_bytes());
            if log.tree_size() == 5 {
                d5 = Some(write_dossier(
                    &self.t,
                    "c5.json",
                    &witnessed_dossier(&log, &self.witnesses),
                ));
            }
        }
        let d9 = write_dossier(
            &self.t,
            "c9.json",
            &witnessed_dossier(&log, &self.witnesses),
        );
        (d5.unwrap(), d9, log)
    }

    fn prove(&self, extra: &[&str]) -> Output {
        let mut args = vec![
            "prove-silence",
            self.receipt.as_str(),
            "--directory",
            self.directory.as_str(),
        ];
        args.extend_from_slice(extra);
        wl(&self.t.0, &args)
    }
}

#[test]
fn log_receipt_signs_a_verifiable_receipt_for_the_entry_and_refuses_one_it_does_not_hold() {
    let s = Setup::new("receipt");
    let printed = wl(&s.t.0, &["log", "receipt", &s.journal, "3"]);
    assert_eq!(code(&printed), 0, "{}", err(&printed));
    let receipt: WriteReceipt = serde_json::from_str(&out(&printed)).unwrap();
    assert!(receipt.verify().is_ok());
    assert_eq!(receipt.signer_pubkey, s.identity);
    assert_eq!(
        receipt.tree_size, 3,
        "issued at the size the entry was appended at"
    );
    let (log, _) = witness_log_core::journal::LeafJournal::replay(&s.journal).unwrap();
    assert_eq!(receipt.payload_hash, log.leaves()[3].payload_hash);

    // --out: the same receipt, in the file only.
    let written: WriteReceipt =
        serde_json::from_str(&std::fs::read_to_string(&s.receipt).unwrap()).unwrap();
    assert!(written.verify().is_ok());
    assert_eq!(written.payload_hash, receipt.payload_hash);
    let again = wl(
        &s.t.0,
        &[
            "log",
            "receipt",
            &s.journal,
            "0",
            "--out",
            &s.t.path("r0.json"),
        ],
    );
    assert_eq!(code(&again), 0);
    assert!(out(&again).is_empty(), "{}", out(&again));
    assert!(err(&again).contains("prove-silence"), "{}", err(&again));

    // An index the journal does not hold: no receipt, exit 2.
    let missing = wl(&s.t.0, &["log", "receipt", &s.journal, "5"]);
    assert_eq!(code(&missing), 2);
    assert!(out(&missing).is_empty());
    assert!(
        err(&missing).contains("no leaf 5 (tree size 5)"),
        "{}",
        err(&missing)
    );
    for bad in [
        vec!["log", "receipt", &s.journal, "-1"],
        vec!["log", "receipt", &s.journal, "three"],
        vec!["log", "receipt", &s.journal],
        vec!["log", "receipt", &s.journal, "3", "--bogus"],
        vec!["log", "receipt", &s.journal, "3", "--out"],
    ] {
        let o = wl(&s.t.0, &bad);
        assert_eq!(code(&o), 2, "{bad:?}: {}", err(&o));
    }
}

#[test]
fn log_receipt_on_a_sealed_journal_needs_its_seed() {
    let t = Tmp::new("sealed");
    let journal = t.path("sealed.jsonl");
    let seed_file = t.path("seed.hex");
    let init = wl(
        &t.0,
        &[
            "log",
            "init",
            &journal,
            "--sealed",
            "--identity-seed-file",
            &seed_file,
        ],
    );
    assert_eq!(code(&init), 0, "{}", err(&init));
    let a = wl(
        &t.0,
        &[
            "log",
            "append",
            &journal,
            "--intent",
            "x",
            "--identity-seed-file",
            &seed_file,
        ],
    );
    assert_eq!(code(&a), 0, "{}", err(&a));
    let without = wl(&t.0, &["log", "receipt", &journal, "0"]);
    assert_eq!(code(&without), 1);
    assert!(
        err(&without).contains("--identity-seed"),
        "{}",
        err(&without)
    );
    let with = wl(
        &t.0,
        &[
            "log",
            "receipt",
            &journal,
            "0",
            "--identity-seed-file",
            &seed_file,
        ],
    );
    assert_eq!(code(&with), 0, "{}", err(&with));
    let r: WriteReceipt = serde_json::from_str(&out(&with)).unwrap();
    assert!(r.verify().is_ok());
    assert_eq!(r.signer_pubkey, json(&init)["identity"].as_str().unwrap());
}

#[test]
fn an_honest_log_that_kept_the_event_is_present_with_its_index() {
    let s = Setup::new("honest");
    let (d5, d9, log9) = s.honest();
    let o = s.prove(&[
        "--dossier",
        &d5,
        "--dossier",
        &d9,
        "--identity",
        &s.identity,
        "--json",
    ]);
    assert_eq!(code(&o), 0, "{}{}", out(&o), err(&o));
    let v = json(&o);
    assert_eq!(v["result"], "present");
    assert_eq!(v["exit_code"], 0);
    assert_eq!(v["leaf_index"], 3);
    assert_eq!(v["receipt_tree_size"], 3);
    assert_eq!(v["bound_tree_size"], 9);
    assert_eq!(v["bound_root_hash"], log9.root_hex());
    assert_eq!(v["reason"], serde_json::Value::Null);
    assert_eq!(v["identity"], s.identity.as_str());
    assert_eq!(v["identity_pinned"], true);
    assert_eq!(v["leaves_from"], d9.as_str());
    assert_eq!(v["min_checkpoints"], 2);
    assert_eq!(v["dossiers"].as_array().unwrap().len(), 2);

    // The human line says the same, bound to the same root.
    let o = s.prove(&[
        "--dossier",
        &d9,
        "--dossier",
        &d5,
        "--identity",
        &s.identity,
    ]);
    assert_eq!(code(&o), 0);
    let text = out(&o);
    assert!(text.starts_with("PRESENT:"), "{text}");
    assert!(text.contains("leaf 3"), "{text}");
    assert!(
        text.contains(&format!("checkpoint 9 (root {})", log9.root_hex())),
        "{text}"
    );
    assert!(!text.contains("--identity was not supplied"), "{text}");

    // One witnessed checkpoint covering the event is enough to be present.
    let o = s.prove(&["--dossier", &d5]);
    assert_eq!(code(&o), 0, "{}", out(&o));
    assert!(
        out(&o).contains("--identity was not supplied"),
        "{}",
        out(&o)
    );
}

#[test]
fn the_event_in_an_unwitnessed_copy_is_not_present() {
    // The log's own export holds the event, but no witness cosigned it:
    // present in that copy, not shown to be in the witnessed history.
    let s = Setup::new("unwitnessed");
    let exported = s.t.path("export.json");
    let e = wl(&s.t.0, &["log", "export", &s.journal, "--out", &exported]);
    assert_eq!(code(&e), 0, "{}", err(&e));
    let o = s.prove(&["--dossier", &exported, "--json"]);
    assert_eq!(code(&o), 20, "{}", out(&o));
    let v = json(&o);
    assert_eq!(v["result"], "inconclusive");
    assert_eq!(v["leaf_index"], 3);
    assert_eq!(v["bound_tree_size"], serde_json::Value::Null);
    assert!(v["reason"].as_str().unwrap().contains("not shown"), "{v}");
}

#[test]
fn a_log_that_signed_a_receipt_and_published_witnessed_histories_without_the_event_is_censored() {
    let s = Setup::new("censored");
    let (c5, c9, log) = s.censoring();
    let o = s.prove(&[
        "--dossier",
        &c5,
        "--dossier",
        &c9,
        "--identity",
        &s.identity,
        "--json",
    ]);
    assert_eq!(code(&o), 30, "{}{}", out(&o), err(&o));
    let v = json(&o);
    assert_eq!(v["result"], "censored");
    assert_eq!(v["exit_code"], 30);
    assert_eq!(v["receipt_tree_size"], 3);
    assert_eq!(v["witnessed_checkpoints_after"], 2);
    assert_eq!(v["leaf_index"], serde_json::Value::Null);
    assert_eq!(v["bound_tree_size"], 9);
    assert_eq!(v["bound_root_hash"], log.root_hex());
    assert_eq!(v["leaves_from"], c9.as_str());
    assert_eq!(v["receipt"]["payload_hash"].as_str().unwrap().len(), 64);

    let o = s.prove(&[
        "--dossier",
        &c5,
        "--dossier",
        &c9,
        "--identity",
        &s.identity,
    ]);
    assert_eq!(code(&o), 30);
    let text = out(&o);
    assert!(text.starts_with("CENSORED:"), "{text}");
    assert!(
        text.contains(&format!("checkpoint 9 (root {})", log.root_hex())),
        "{text}"
    );

    // --min-checkpoints 1 accepts one witnessed checkpoint.
    let o = s.prove(&["--dossier", &c9, "--min-checkpoints", "1"]);
    assert_eq!(code(&o), 30, "{}", out(&o));
}

#[test]
fn one_witnessed_checkpoint_is_inconclusive_under_the_default_minimum_of_two() {
    let s = Setup::new("one");
    let (_, c9, log) = s.censoring();
    for extra in [vec![], vec!["--min-checkpoints", "2"]] {
        let mut args = vec!["--dossier", c9.as_str(), "--json"];
        args.extend(extra);
        let o = s.prove(&args);
        assert_eq!(code(&o), 20, "{}", out(&o));
        let v = json(&o);
        assert_eq!(v["result"], "inconclusive");
        assert_eq!(v["witnessed_checkpoints_seen"], 1);
        // Only the count fell short: the absence is still bound.
        assert_eq!(v["bound_tree_size"], 9);
        assert_eq!(v["bound_root_hash"], log.root_hex());
        assert!(v["reason"].as_str().unwrap().contains("2 required"), "{v}");
    }
    let o = s.prove(&["--dossier", &c9]);
    assert!(out(&o).starts_with("INCONCLUSIVE:"), "{}", out(&o));
    assert!(out(&o).contains("Not an accusation"), "{}", out(&o));
}

#[test]
fn an_accuser_who_drops_the_event_from_the_leaves_proves_nothing() {
    let s = Setup::new("doctored");
    let (d5, d9, _) = s.honest();
    let original: Dossier = Dossier::from_json(&std::fs::read_to_string(&d9).unwrap()).unwrap();

    // The event removed from the largest dossier's leaves.
    let mut dropped = original.clone();
    dropped.leaves.remove(3);
    let dropped = write_dossier(&s.t, "dropped.json", &dropped);
    // The event's leaf replaced, so the count still matches.
    let mut replaced = original.clone();
    replaced.leaves[3].payload_hash = "cd".repeat(32);
    let replaced = write_dossier(&s.t, "replaced.json", &replaced);

    for (doctored, why) in [(&dropped, "cover"), (&replaced, "reproduce")] {
        let o = s.prove(&["--dossier", &d5, "--dossier", doctored, "--json"]);
        assert_eq!(code(&o), 20, "{}", out(&o));
        let v = json(&o);
        assert_eq!(v["result"], "inconclusive");
        assert!(v["reason"].as_str().unwrap().contains(why), "{v}");
    }
}

#[test]
fn witnesses_of_the_logs_own_operator_do_not_count() {
    let s = Setup::new("subject");
    let (c5, c9, _) = s.censoring();
    for org in ["Org B", "  org b "] {
        let o = s.prove(&[
            "--dossier",
            &c5,
            "--dossier",
            &c9,
            "--subject-org",
            org,
            "--json",
        ]);
        assert_eq!(code(&o), 20, "{}", out(&o));
        let v = json(&o);
        assert_eq!(v["result"], "inconclusive");
        assert_eq!(v["witnessed_checkpoints_seen"], 0);
        assert_eq!(v["subject_org"], org);
    }
    // An organisation not in the directory changes nothing.
    let o = s.prove(&["--dossier", &c5, "--dossier", &c9, "--subject-org", "Org C"]);
    assert_eq!(code(&o), 30, "{}", out(&o));
}

#[test]
fn a_receipt_from_another_log_than_identity_is_a_usage_error() {
    let s = Setup::new("identity");
    let (c5, c9, _) = s.censoring();
    let other = hex::encode(
        SigningKey::generate(&mut rand::rngs::OsRng)
            .verifying_key()
            .to_bytes(),
    );
    let o = s.prove(&["--dossier", &c5, "--dossier", &c9, "--identity", &other]);
    assert_eq!(code(&o), 2, "{}", out(&o));
    assert!(out(&o).is_empty());
    assert!(
        err(&o).contains("not from the log you named"),
        "{}",
        err(&o)
    );
    // Upper-case hex for the right key is the same key.
    let o = s.prove(&[
        "--dossier",
        &c5,
        "--dossier",
        &c9,
        "--identity",
        &s.identity.to_uppercase(),
    ]);
    assert_eq!(code(&o), 30, "{}", err(&o));
}

#[test]
fn malformed_inputs_are_usage_errors() {
    let s = Setup::new("malformed");
    let (c5, c9, _) = s.censoring();
    let receipt: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&s.receipt).unwrap()).unwrap();

    let not_json = s.t.write("not-json.json", "this is not json");
    let as_array = s.t.write(
        "array.json",
        &serde_json::json!([
            receipt["payload_hash"],
            receipt["tree_size"],
            receipt["issued_at_ms"],
            receipt["sig_alg"],
            receipt["signer_pubkey"],
            receipt["signature"]
        ])
        .to_string(),
    );
    let mut altered = receipt.clone();
    altered["payload_hash"] = serde_json::json!("ab".repeat(32));
    let altered = s.t.write("altered.json", &altered.to_string());
    let missing = s.t.path("missing.json");
    let deep = s.t.write(
        "deep.json",
        &format!("{}{}", "[".repeat(1001), "]".repeat(1001)),
    );
    let bad_dir = s.t.write("bad-dir.json", "{\"witnesses\": 3}");
    let dir = s.directory.as_str();

    let cases: Vec<(&str, Vec<&str>)> = vec![
        (
            "receipt not JSON",
            vec![&not_json, "--dossier", &c9, "--directory", dir],
        ),
        (
            "receipt as an array",
            vec![&as_array, "--dossier", &c9, "--directory", dir],
        ),
        (
            "receipt altered",
            vec![&altered, "--dossier", &c9, "--directory", dir],
        ),
        (
            "receipt missing",
            vec![&missing, "--dossier", &c9, "--directory", dir],
        ),
        (
            "dossier not a dossier",
            vec![&s.receipt, "--dossier", &s.receipt, "--directory", dir],
        ),
        (
            "dossier too deep",
            vec![&s.receipt, "--dossier", &deep, "--directory", dir],
        ),
        (
            "dossier missing",
            vec![&s.receipt, "--dossier", &missing, "--directory", dir],
        ),
        (
            "directory malformed",
            vec![&s.receipt, "--dossier", &c9, "--directory", &bad_dir],
        ),
        (
            "directory missing",
            vec![&s.receipt, "--dossier", &c9, "--directory", &missing],
        ),
        ("no --directory", vec![&s.receipt, "--dossier", &c9]),
        ("no --dossier", vec![&s.receipt, "--directory", dir]),
        ("no receipt", vec!["--dossier", &c9, "--directory", dir]),
        (
            "two receipts",
            vec![&s.receipt, &s.receipt, "--dossier", &c9, "--directory", dir],
        ),
        (
            "flag as a value",
            vec![&s.receipt, "--dossier", "--json", "--directory", dir],
        ),
        (
            "unknown flag",
            vec![&s.receipt, "--dossier", &c9, "--directory", dir, "--jsno"],
        ),
        (
            "--min-checkpoints 0",
            vec![
                &s.receipt,
                "--dossier",
                &c9,
                "--directory",
                dir,
                "--min-checkpoints",
                "0",
            ],
        ),
        (
            "--min-checkpoints abc",
            vec![
                &s.receipt,
                "--dossier",
                &c9,
                "--directory",
                dir,
                "--min-checkpoints",
                "abc",
            ],
        ),
        (
            "--identity not hex",
            vec![
                &s.receipt,
                "--dossier",
                &c9,
                "--directory",
                dir,
                "--identity",
                "zz",
            ],
        ),
        (
            "--directory twice",
            vec![
                &s.receipt,
                "--dossier",
                &c9,
                "--directory",
                dir,
                "--directory",
                dir,
            ],
        ),
        (
            "empty --subject-org",
            vec![
                &s.receipt,
                "--dossier",
                &c9,
                "--directory",
                dir,
                "--subject-org",
                " ",
            ],
        ),
    ];
    for (what, args) in cases {
        let mut full = vec!["prove-silence"];
        full.extend(args);
        let o = wl(&s.t.0, &full);
        assert_eq!(code(&o), 2, "{what}: {}{}", out(&o), err(&o));
        assert!(out(&o).is_empty(), "{what}: {}", out(&o));
        assert!(
            err(&o).starts_with("prove-silence: "),
            "{what}: {}",
            err(&o)
        );
    }
    // The inputs themselves were fine.
    let o = s.prove(&["--dossier", &c5, "--dossier", &c9]);
    assert_eq!(code(&o), 30, "{}", err(&o));
}

#[test]
fn dossiers_of_another_log_or_from_before_the_receipt_do_not_count() {
    let s = Setup::new("ignored");
    let (c5, c9, _) = s.censoring();
    // Witnessed, but of another identity.
    let mut other = WitnessLog::resume(IdentityKeypair::from_bytes(&[9u8; 32]), 0);
    for i in 0..12 {
        other.append_intent(format!("unrelated {i}").as_bytes());
    }
    let cp = other.checkpoint(&SigningKey::from_bytes(&[9u8; 32]));
    let mut foreign = Dossier::from_log(&other, cp.clone());
    foreign.witness_receipts = s
        .witnesses
        .iter()
        .map(|w| WitnessReceipt::sign(w, &cp, cp.timestamp_ms + 1))
        .collect();
    let foreign = write_dossier(&s.t, "foreign.json", &foreign);
    // Witnessed, of this log, but no larger than the receipt's size.
    let mut early = WitnessLog::resume(IdentityKeypair::from_bytes(&SEED), 0);
    for i in 0..3 {
        early.append_intent(format!("early {i}").as_bytes());
    }
    let early = write_dossier(&s.t, "early.json", &witnessed_dossier(&early, &s.witnesses));

    let o = s.prove(&["--dossier", &foreign, "--dossier", &early, "--dossier", &c9]);
    assert_eq!(code(&o), 20, "{}", out(&o));
    let text = out(&o);
    assert!(
        text.contains("signed by another log's key: ") && text.contains("foreign.json"),
        "{text}"
    );
    assert!(
        text.contains("not after the receipt") && text.contains("early.json"),
        "{text}"
    );

    // The larger foreign dossier is never where the leaves come from.
    let o = s.prove(&[
        "--dossier",
        &foreign,
        "--dossier",
        &c5,
        "--dossier",
        &c9,
        "--json",
    ]);
    assert_eq!(code(&o), 30, "{}", out(&o));
    let v = json(&o);
    assert_eq!(v["leaves_from"], c9.as_str());
    let same: Vec<bool> = v["dossiers"]
        .as_array()
        .unwrap()
        .iter()
        .map(|d| d["same_log"].as_bool().unwrap())
        .collect();
    assert_eq!(same, [false, true, true]);
}

#[test]
fn help_names_both_commands_and_the_exit_codes() {
    let t = Tmp::new("help");
    let top = wl(&t.0, &["--help"]);
    assert!(out(&top).contains("witness-log log receipt <journal> <index>"));
    assert!(out(&top).contains("witness-log prove-silence <receipt.json>"));
    assert!(out(&top).contains("prove-silence: 0 PRESENT, 20 INCONCLUSIVE, 30 CENSORED"));
    let help = wl(&t.0, &["prove-silence", "--help"]);
    assert_eq!(code(&help), 0);
    for needle in [
        "0 PRESENT",
        "20 INCONCLUSIVE",
        "30 CENSORED",
        "2 usage",
        "--min-checkpoints",
    ] {
        assert!(out(&help).contains(needle), "{needle}: {}", out(&help));
    }
    let log_help = wl(&t.0, &["log", "--help"]);
    assert!(out(&log_help).contains("log receipt <journal> <index>"));
}
