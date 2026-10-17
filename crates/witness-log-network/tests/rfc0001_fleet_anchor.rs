//! RFC-0001 (fleet checkpoint log, experimental): what must NOT change for
//! a caller who does not opt in, and what an anchor can never do when one
//! does. Corpus vector 14 pins the cases; these check the properties over
//! every dossier and context of corpus vector 13 as well.

use serde_json::Value;
use witness_log_network::fleet::{FleetAnchorField, FleetAnchorStatus};
use witness_log_network::tlog_witness::EquivocationProof;
use witness_log_network::{Dossier, KnownHead, Verdict, VerifyContext, WitnessDirectory};

fn read(name: &str) -> Value {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../corpus")
        .join(name);
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

/// Every (dossier, context) of corpus 13, with the verdict-relevant inputs.
struct Case13 {
    dossier: Dossier,
    expected_identity: Option<String>,
    use_dir: bool,
    min: Option<usize>,
    heads: Vec<KnownHead>,
    evidence: Vec<EquivocationProof>,
    subject_org: Option<String>,
}

fn corpus_13() -> (WitnessDirectory, Vec<Case13>) {
    let v = read("13_verdicts.json");
    let dir: WitnessDirectory = serde_json::from_value(v["trusted_directory"].clone()).unwrap();
    let cases = v["cases"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| Case13 {
            dossier: serde_json::from_value(v["dossiers"][c["dossier"].as_str().unwrap()].clone())
                .unwrap(),
            expected_identity: c["expected_identity"].as_str().map(str::to_string),
            use_dir: c["trusted_directory"].as_bool().unwrap(),
            min: c["min_witnesses"].as_u64().map(|n| n as usize),
            heads: c["known_heads"]
                .as_array()
                .unwrap()
                .iter()
                .map(|h| h.as_str().unwrap().parse().unwrap())
                .collect(),
            evidence: c["evidence"]
                .as_array()
                .unwrap()
                .iter()
                .map(|k| {
                    serde_json::from_value(v["evidence"][k.as_str().unwrap()].clone()).unwrap()
                })
                .collect(),
            subject_org: c["subject_org"].as_str().map(str::to_string),
        })
        .collect();
    (dir, cases)
}

impl Case13 {
    fn ctx<'a>(&'a self, dir: &'a WitnessDirectory, accept: bool) -> VerifyContext<'a> {
        VerifyContext {
            expected_identity_pubkey: self.expected_identity.as_deref(),
            trusted_directory: self.use_dir.then_some(dir),
            min_receipts: self.min,
            revocations: &[],
            known_heads: &self.heads,
            evidence: &self.evidence,
            subject_org: self.subject_org.as_deref(),
            accept_fleet_anchor: accept,
        }
    }
}

/// A fleet anchor from corpus 14: well-formed, but for another identity,
/// so it fails step 2 for any corpus 13 dossier.
fn foreign_anchor() -> FleetAnchorField {
    let v = read("14_fleet_anchor.json");
    serde_json::from_value(v["dossiers"]["fleet_only"]["fleet_anchor"].clone()).unwrap()
}

fn without(mut v: Value, keys: &[&str]) -> Value {
    for k in keys {
        v.as_object_mut().unwrap().remove(*k);
    }
    v
}

#[test]
fn a_dossier_without_the_field_serialises_byte_identically() {
    let v = read("13_verdicts.json");
    for (name, d) in v["dossiers"].as_object().unwrap() {
        let parsed: Dossier = serde_json::from_value(d.clone()).unwrap();
        assert!(parsed.fleet_anchor.is_none(), "{name}");
        // The field is the last one declared and skipped when absent, so
        // the serialiser writes exactly the 0.5.0 bytes.
        let back = serde_json::to_string(&parsed).unwrap();
        assert!(!back.contains("fleet_anchor"), "{name}");
        assert_eq!(
            serde_json::from_str::<Value>(&back).unwrap(),
            *d,
            "{name}: the field must be invisible when absent"
        );
    }
    // `"fleet_anchor": null` reads as absent.
    let mut d = v["dossiers"]["full"].clone();
    d["fleet_anchor"] = Value::Null;
    let parsed: Dossier = serde_json::from_value(d).unwrap();
    assert!(parsed.fleet_anchor.is_none());
}

#[test]
fn a_verifier_predating_the_field_reads_an_anchored_dossier() {
    // The 0.5.0 `Dossier` shape: serde's default ignores unknown fields
    // (the struct never had deny_unknown_fields), so an anchored dossier
    // verifies on an old verifier as if the field were absent.
    #[derive(serde::Deserialize)]
    #[allow(dead_code)]
    struct Dossier050 {
        identity_pubkey: String,
        leaves: Vec<witness_log_core::leaf::Leaf>,
        checkpoint: witness_log_core::sth::SignedTreeHead,
        #[serde(default)]
        witness_receipts: Vec<witness_log_network::WitnessReceipt>,
        #[serde(default)]
        witness_directory: WitnessDirectory,
        #[serde(default)]
        key_bindings: Vec<witness_log_core::identity::KeyBindingStatement>,
        #[serde(default)]
        revocations: Vec<witness_log_core::identity::RevocationStatement>,
    }
    let v = read("14_fleet_anchor.json");
    for (name, d) in v["dossiers"].as_object().unwrap() {
        assert!(d.get("fleet_anchor").is_some(), "{name}");
        serde_json::from_value::<Dossier050>(d.clone()).unwrap();
    }
}

#[test]
fn without_the_opt_in_an_anchor_changes_nothing_but_its_own_report_line() {
    let (dir, cases) = corpus_13();
    for (i, c) in cases.iter().enumerate() {
        let plain = serde_json::to_value(c.dossier.verify(0.66, &c.ctx(&dir, false))).unwrap();
        for anchor in [
            foreign_anchor(),
            FleetAnchorField::Malformed(serde_json::json!({"origin": []})),
        ] {
            let mut anchored = c.dossier.clone();
            anchored.fleet_anchor = Some(anchor);
            let r = anchored.verify(0.66, &c.ctx(&dir, false));
            assert_eq!(
                r.fleet_anchor.as_ref().unwrap().status,
                FleetAnchorStatus::Ignored
            );
            assert_eq!(
                without(serde_json::to_value(&r).unwrap(), &["fleet_anchor"]),
                plain,
                "case {i}"
            );
        }
    }
}

#[test]
fn opting_in_without_an_anchor_adds_only_the_path_fields() {
    let (dir, cases) = corpus_13();
    for (i, c) in cases.iter().enumerate() {
        let plain = serde_json::to_value(c.dossier.verify(0.66, &c.ctx(&dir, false))).unwrap();
        let opted = serde_json::to_value(c.dossier.verify(0.66, &c.ctx(&dir, true))).unwrap();
        assert!(opted.get("witnessed_via").is_some(), "case {i}");
        assert!(opted.get("witness_paths").is_some(), "case {i}");
        assert_eq!(opted["witness_paths"]["fleet"]["witnesses"], 0, "case {i}");
        let via = &opted["witnessed_via"];
        if opted["verdict"] == "witnessed" {
            assert_eq!(via, "direct", "case {i}");
        } else {
            assert!(via.is_null(), "case {i}");
        }
        assert_eq!(
            without(opted, &["witnessed_via", "witness_paths"]),
            plain,
            "case {i}"
        );
    }
}

#[test]
fn a_failed_anchor_never_lowers_or_raises_a_verdict() {
    let (dir, cases) = corpus_13();
    for (i, c) in cases.iter().enumerate() {
        let plain = c.dossier.verify(0.66, &c.ctx(&dir, true));
        for anchor in [
            foreign_anchor(),
            FleetAnchorField::Malformed(serde_json::json!("x")),
        ] {
            let mut anchored = c.dossier.clone();
            anchored.fleet_anchor = Some(anchor);
            let r = anchored.verify(0.66, &c.ctx(&dir, true));
            assert_eq!(
                r.fleet_anchor.as_ref().unwrap().status,
                FleetAnchorStatus::Failed
            );
            assert!(!r.fleet_anchor.as_ref().unwrap().failures.is_empty());
            assert_eq!(r.verdict, plain.verdict, "case {i}");
            assert_eq!(
                serde_json::to_value(&r.quorum).unwrap(),
                serde_json::to_value(&plain.quorum).unwrap(),
                "case {i}"
            );
            assert_eq!(r.split_view_unsafe, plain.split_view_unsafe, "case {i}");
        }
    }
}

#[test]
fn project_operated_fleet_cosigners_are_never_independent() {
    let v = read("14_fleet_anchor.json");
    let mut dir: WitnessDirectory = serde_json::from_value(v["trusted_directory"].clone()).unwrap();
    for w in &mut dir.witnesses {
        w.is_project_operated = true;
    }
    let d: Dossier = serde_json::from_value(v["dossiers"]["fleet_only_three"].clone()).unwrap();
    let r = d.verify(
        0.66,
        &VerifyContext {
            trusted_directory: Some(&dir),
            subject_org: Some("corpus-fleet-org"),
            accept_fleet_anchor: true,
            ..Default::default()
        },
    );
    let q = r.quorum.unwrap();
    assert_eq!(q.valid_receipts, 3);
    assert_eq!(q.project_operated_receipts, 3);
    assert_eq!(q.distinct_independent_operators, 0);
    assert_eq!(r.verdict, Verdict::ConsistentUnwitnessed);
    assert_eq!(r.witness_paths.unwrap().fleet.independent_operators, 0);
}

#[test]
fn a_fleet_cosigner_never_makes_a_dossier_split_view_resistant() {
    // Four witnesses, all four cosign the fleet: still not resistant,
    // because none of them would refuse a conflicting checkpoint of this
    // agent. One direct receipt plus three fleet-only does not change it.
    let v = read("14_fleet_anchor.json");
    let dir: WitnessDirectory = serde_json::from_value(v["trusted_directory"].clone()).unwrap();
    let d: Dossier = serde_json::from_value(v["dossiers"]["fleet_only_three"].clone()).unwrap();
    let ctx = VerifyContext {
        trusted_directory: Some(&dir),
        subject_org: Some("someone else"),
        accept_fleet_anchor: true,
        ..Default::default()
    };
    let r = d.verify(0.66, &ctx);
    assert_eq!(r.verdict, Verdict::Witnessed);
    assert!(r.split_view_unsafe);
    assert!(!r.quorum.as_ref().unwrap().split_view_resistant);
    assert_eq!(
        r.witnessed_via,
        Some(Some(witness_log_network::fleet::WitnessedVia::Fleet))
    );
}
