//! Generates `corpus/14_fleet_anchor.json`: RFC-0001 (fleet checkpoint log,
//! EXPERIMENTAL) verification vector. A four-entry fleet log, its cosigned
//! checkpoints, dossiers carrying fleet anchors, and for each case the
//! verdict, exit code and report fields every verifier must produce with
//! and without `accept_fleet_anchor`. Deterministic: fixed keys, fixed
//! timestamps, Ed25519's deterministic signatures. Run with:
//!
//!   cargo run -p witness-log-network --example generate_fleet_corpus
//!
//! CI regenerates it and fails if the committed file differs. Every key
//! here is PUBLIC and for conformance testing only.
//!
//! RFC-0001 is a draft; this vector pins the 0.6.0 prototype's behaviour
//! so that the verifiers that implement the opt-in agree. It is not part
//! of the specification's conformance set.

use base64ct::{Base64, Encoding};
use ed25519_dalek::SigningKey;
use serde_json::{json, Value};
use witness_log_core::c2sp::{canonical_origin, Checkpoint, Cosignature, SignedNote, VerifierKey};
use witness_log_core::leaf::{Leaf, LeafType};
use witness_log_core::merkle::{leaf_hash, MerkleTree};
use witness_log_core::sth::SignedTreeHead;
use witness_log_network::fleet::{FleetAnchor, FleetAnchorField};
use witness_log_network::{
    Dossier, Verdict, VerifyContext, WitnessDirectory, WitnessEntry, WitnessReceipt, WitnessRuntime,
};

const IDENTITY_SEED: [u8; 32] = [0x41; 32];
const FLEET_SEED: [u8; 32] = [0x4f; 32];
const FLEET_ORIGIN: &str = "fleet.example/witness-log/fleet";
const FLEET_ORG: &str = "corpus-fleet-org";
const T0: u64 = 1_700_000_000_000;
/// Cosignature time (Unix seconds) of witness `i`: COSIGNED_AT + i.
const COSIGNED_AT: u64 = 1_700_000_100;

fn leaf(index: u64, session: &str) -> Leaf {
    Leaf {
        index,
        leaf_type: if index % 2 == 0 {
            LeafType::ActiveIntent.tag()
        } else {
            LeafType::ActiveResult.tag()
        },
        timestamp_ms: T0 + index * 1000,
        session_pubkey: session.to_string(),
        payload_hash: hex::encode([0x60 + index as u8; 32]),
        redacted_index: None,
        revoked_identity: None,
        handoff_direction: None,
        counterparty_pubkey: None,
        handoff_state_hash: None,
        authorization_event_kind: None,
        authorization_scope_hash: None,
        anchor_url: None,
        anchor_proof_json: None,
        anchor_proof_hash: None,
    }
}

/// An agent's checkpoint note, as a fleet log stores it.
fn agent_note(key: &SigningKey, size: u64, root: [u8; 32]) -> String {
    Checkpoint {
        origin: canonical_origin(&key.verifying_key()),
        tree_size: size,
        root_hash: root,
        extensions: vec![],
    }
    .sign(key)
    .unwrap()
    .encode()
    .unwrap()
}

struct FleetLog {
    entries: Vec<String>,
    tree: MerkleTree,
}

impl FleetLog {
    fn new(entries: Vec<String>) -> Self {
        let mut tree = MerkleTree::new();
        for e in &entries {
            tree.append(leaf_hash(e.as_bytes()));
        }
        Self { entries, tree }
    }

    /// The fleet checkpoint at the full size, signed by the fleet key and
    /// cosigned by the witnesses at `cosigners` (indices into `keys`).
    fn checkpoint_note(
        &self,
        keys: &[SigningKey],
        names: &[String],
        cosigners: &[usize],
    ) -> String {
        let mut note = Checkpoint {
            origin: FLEET_ORIGIN.into(),
            tree_size: self.tree.size(),
            root_hash: self.tree.root(),
            extensions: vec![],
        }
        .sign(&SigningKey::from_bytes(&FLEET_SEED))
        .unwrap();
        for &i in cosigners {
            let c = Cosignature::sign(&names[i], &keys[i], COSIGNED_AT + i as u64, &note.text);
            note.signatures.push(c.to_note_signature());
        }
        note.encode().unwrap()
    }

    fn anchor(&self, index: u64, note: String) -> FleetAnchor {
        FleetAnchor {
            origin: FLEET_ORIGIN.into(),
            entry_index: index,
            entry_bytes_b64: Base64::encode_string(self.entries[index as usize].as_bytes()),
            inclusion_proof: self
                .tree
                .inclusion_proof(index, self.tree.size())
                .unwrap()
                .iter()
                .map(hex::encode)
                .collect(),
            fleet_checkpoint_note: note,
        }
    }
}

fn main() {
    let identity = SigningKey::from_bytes(&IDENTITY_SEED);
    let identity_hex = hex::encode(identity.verifying_key().to_bytes());
    let fleet_key = SigningKey::from_bytes(&FLEET_SEED);

    // Four witnesses: three independent operators and the fleet operator's
    // own (its operator_org differs from FLEET_ORG only in case and
    // spacing, which normalisation removes).
    let orgs = [
        "corpus-operator-a",
        "corpus-operator-b",
        "corpus-operator-c",
        " Corpus-Fleet-Org",
    ];
    let keys: Vec<SigningKey> = (0..4u8)
        .map(|i| SigningKey::from_bytes(&[0x50 + i; 32]))
        .collect();
    let names: Vec<String> = (0..4).map(|i| format!("corpus-witness-{i}")).collect();
    let directory = WitnessDirectory {
        witnesses: keys
            .iter()
            .enumerate()
            .map(|(i, k)| WitnessEntry {
                name: names[i].clone(),
                operator_org: orgs[i].to_string(),
                url: format!("https://witness-{i}.example"),
                pubkey: hex::encode(k.verifying_key().to_bytes()),
                runtime: WitnessRuntime::Human,
                compute_provider: Some(format!("corpus-provider-{i}")),
                is_project_operated: false,
            })
            .collect(),
    };

    // The agent's log and checkpoint.
    let leaves: Vec<Leaf> = (0..4).map(|i| leaf(i, &identity_hex)).collect();
    let mut agent_tree = MerkleTree::new();
    for l in &leaves {
        agent_tree.append(leaf_hash(&l.canonical_bytes()));
    }
    let root = agent_tree.root();
    let sth = SignedTreeHead::sign(&identity, 4, &root, T0 + 10_000);
    let entry = agent_note(&identity, 4, root);

    // The fleet log: three other agents' checkpoints around this one, at
    // index 2.
    let others: Vec<String> = (0..3u8)
        .map(|i| {
            agent_note(
                &SigningKey::from_bytes(&[0x44 + i; 32]),
                1 + i as u64,
                [0x70 + i; 32],
            )
        })
        .collect();
    let fleet = FleetLog::new(vec![
        others[0].clone(),
        others[1].clone(),
        entry.clone(),
        others[2].clone(),
    ]);
    // A fleet log holding a checkpoint of this identity at the same size
    // with a different root (validly signed): RFC-0001 step 2 must fail.
    let forked_entry = agent_note(&identity, 4, [0xee; 32]);
    let forked_fleet = FleetLog::new(vec![
        others[0].clone(),
        others[1].clone(),
        forked_entry.clone(),
        others[2].clone(),
    ]);

    let dossier = |receipts: &[usize], anchor: Option<FleetAnchorField>| Dossier {
        identity_pubkey: identity_hex.clone(),
        leaves: leaves.clone(),
        checkpoint: sth.clone(),
        witness_receipts: receipts
            .iter()
            .map(|&i| WitnessReceipt::sign(&keys[i], &sth, T0 + 11_000 + i as u64))
            .collect(),
        witness_directory: WitnessDirectory::default(),
        key_bindings: vec![],
        revocations: vec![],
        fleet_anchor: anchor,
    };
    let anchored = |cosigners: &[usize]| -> Option<FleetAnchorField> {
        Some(
            fleet
                .anchor(2, fleet.checkpoint_note(&keys, &names, cosigners))
                .into(),
        )
    };
    let mut tampered = fleet.anchor(2, fleet.checkpoint_note(&keys, &names, &[0, 1]));
    tampered.inclusion_proof[0] = hex::encode([0u8; 32]);

    let dossiers = json!({
        "fleet_only": dossier(&[], anchored(&[0, 1])),
        "fleet_only_three": dossier(&[], anchored(&[0, 1, 2])),
        "fleet_wrong_root": dossier(&[], Some(forked_fleet
            .anchor(2, forked_fleet.checkpoint_note(&keys, &names, &[0, 1]))
            .into())),
        "fleet_operator_cosigner": dossier(&[], anchored(&[0, 3])),
        "both_paths": dossier(&[0, 1], anchored(&[1, 2])),
        "direct_majority_plus_fleet": dossier(&[0, 1, 2], anchored(&[2])),
        "fleet_tampered_proof": dossier(&[], Some(tampered.into())),
        "direct_majority_malformed_anchor": dossier(
            &[0, 1, 2],
            Some(FleetAnchorField::Malformed(json!({"origin": 5, "entry_index": "two"}))),
        ),
    });
    let by_name = |n: &str| -> Dossier { serde_json::from_value(dossiers[n].clone()).unwrap() };

    // (name, dossier, trusted directory, accept_fleet_anchor, subject_org,
    //  min_witnesses, allow_sub_majority). Two of four witnesses do not meet
    //  the default 0.66 count gate, so those cases gate on a count of 2, as
    //  corpus 13 does: what they test is the independence rule.
    let fleet_org = Some(FLEET_ORG);
    type Case<'a> = (
        &'a str,
        &'a str,
        bool,
        bool,
        Option<&'a str>,
        Option<usize>,
        bool,
    );
    let cases: Vec<Case> = vec![
        (
            "positive: two independent operators cosigned the fleet checkpoint",
            "fleet_only",
            true,
            true,
            fleet_org,
            Some(2),
            false,
        ),
        (
            "positive, sub-majority accepted",
            "fleet_only",
            true,
            true,
            fleet_org,
            Some(2),
            true,
        ),
        (
            "three fleet cosigners are still not split-view resistant",
            "fleet_only_three",
            true,
            true,
            fleet_org,
            None,
            false,
        ),
        (
            "without the opt-in the anchor is ignored",
            "fleet_only",
            true,
            false,
            fleet_org,
            Some(2),
            false,
        ),
        (
            "an entry for a different root fails step 2",
            "fleet_wrong_root",
            true,
            true,
            fleet_org,
            Some(2),
            false,
        ),
        (
            "a cosigner from the fleet operator's organisation counts as none",
            "fleet_operator_cosigner",
            true,
            true,
            fleet_org,
            Some(2),
            false,
        ),
        (
            "one witness on both paths is counted once",
            "both_paths",
            true,
            true,
            fleet_org,
            None,
            false,
        ),
        (
            "both paths, without the opt-in: direct receipts only",
            "both_paths",
            true,
            false,
            fleet_org,
            Some(2),
            false,
        ),
        (
            "a direct majority plus a fleet cosigner already counted",
            "direct_majority_plus_fleet",
            true,
            true,
            fleet_org,
            None,
            false,
        ),
        (
            "opted in without subject_org: the anchor is not used",
            "fleet_only",
            true,
            true,
            None,
            Some(2),
            false,
        ),
        (
            "a tampered inclusion proof fails step 3",
            "fleet_tampered_proof",
            true,
            true,
            fleet_org,
            Some(2),
            false,
        ),
        (
            "a malformed fleet_anchor is ignored without the opt-in",
            "direct_majority_malformed_anchor",
            true,
            false,
            fleet_org,
            None,
            false,
        ),
        (
            "a malformed fleet_anchor fails with the opt-in and lowers nothing",
            "direct_majority_malformed_anchor",
            true,
            true,
            fleet_org,
            None,
            false,
        ),
        (
            "no trusted directory: unanchored, the anchor still checked",
            "fleet_only",
            false,
            true,
            fleet_org,
            None,
            false,
        ),
    ];

    let mut out_cases = Vec::new();
    for (name, d, use_dir, accept, subject_org, min, allow) in cases {
        let ctx = VerifyContext {
            trusted_directory: use_dir.then_some(&directory),
            min_receipts: min,
            subject_org,
            accept_fleet_anchor: accept,
            ..Default::default()
        };
        let r = by_name(d).verify(0.66, &ctx);
        let exit_code = if r.split_view_unsafe && !allow {
            11
        } else {
            match r.verdict {
                Verdict::Witnessed => 0,
                Verdict::ConsistentUnwitnessed => 10,
                Verdict::Unanchored => 20,
                Verdict::Diverged => 30,
                Verdict::Invalid => 40,
            }
        };
        let report = serde_json::to_value(&r).unwrap();
        out_cases.push(json!({
            "name": name,
            "dossier": d,
            "trusted_directory": use_dir,
            "accept_fleet_anchor": accept,
            "subject_org": subject_org,
            "threshold": 0.66,
            "min_witnesses": min,
            "allow_sub_majority": allow,
            "expect": {
                "verdict": r.verdict,
                "exit_code": exit_code,
                "split_view_unsafe": r.split_view_unsafe,
                "valid_receipts": r.quorum.as_ref().map(|q| q.valid_receipts),
                "independent_operators": r.quorum.as_ref().map(|q| q.distinct_independent_operators),
                "fleet_anchor_status": r.fleet_anchor.as_ref().map(|f| f.status),
                "fleet_tree_size": r.fleet_anchor.as_ref().and_then(|f| f.fleet_tree_size),
                "witnessed_via": report.get("witnessed_via").cloned().unwrap_or(Value::Null),
                "witness_paths": report.get("witness_paths").cloned().unwrap_or(Value::Null),
            },
        }));
    }

    let fleet_note_uncosigned = fleet.checkpoint_note(&keys, &names, &[]);
    let doc = json!({
        "description": "RFC-0001 fleet checkpoint log, EXPERIMENTAL (0.6.0 prototype; not part of the \
            specification's conformance set). fleet_log: four agent checkpoint notes as a fleet log \
            appends them (entries_b64), their RFC 6962 leaf hashes SHA256(0x00 || entry bytes), the \
            fleet root, the inclusion proof for entry 2 (hex, innermost first) and the fleet \
            checkpoint note signed by the fleet key (fleet_vkey). Cases: run each named dossier \
            through your verifier with the trusted directory when trusted_directory is true, \
            subject_org, threshold, min_witnesses (when not null it replaces the threshold gate) \
            and the fleet-anchor opt-in when accept_fleet_anchor is true. \
            The verdict, exit code (11 when split_view_unsafe and allow_sub_majority is false), \
            quorum valid_receipts and distinct_independent_operators (null when there is no \
            quorum), fleet_anchor.status and fleet_anchor.fleet_tree_size (null when the report \
            has no fleet_anchor) must equal expect. With the opt-in the report must carry \
            witnessed_via (\"direct\" | \"fleet\" | \"both\", null unless the verdict is \
            witnessed) and witness_paths equal to expect; without it the report must carry \
            neither key. The fleet operator's organisation is subject_org; witnesses of it never \
            count as independent, and with the opt-in but no subject_org the anchor fails. Each \
            witness key counts once across both paths; only keys with a direct receipt count \
            toward split-view resistance. Every key here is public and for testing only.",
        "identity_pubkey": identity_hex,
        "fleet_origin": FLEET_ORIGIN,
        "fleet_operator_org": FLEET_ORG,
        "trusted_directory": directory,
        "fleet_log": {
            "origin": FLEET_ORIGIN,
            "fleet_vkey": VerifierKey::for_ed25519(FLEET_ORIGIN, &fleet_key.verifying_key()).encode(),
            "entries_b64": fleet.entries.iter().map(|e| Base64::encode_string(e.as_bytes())).collect::<Vec<_>>(),
            "leaf_hashes_hex": fleet.entries.iter().map(|e| hex::encode(leaf_hash(e.as_bytes()))).collect::<Vec<_>>(),
            "tree_size": fleet.tree.size(),
            "root_hex": hex::encode(fleet.tree.root()),
            "entry_2_inclusion_proof_hex": fleet.tree.inclusion_proof(2, 4).unwrap().iter().map(hex::encode).collect::<Vec<_>>(),
            "checkpoint_note": fleet_note_uncosigned,
            "checkpoint_note_text": SignedNote::parse(&fleet_note_uncosigned).unwrap().text,
        },
        "dossiers": dossiers,
        "cases": out_cases,
    });

    let path =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../corpus/14_fleet_anchor.json");
    std::fs::write(&path, serde_json::to_string_pretty(&doc).unwrap() + "\n").unwrap();
    println!("wrote {}", path.display());
}
