//! Generates `corpus/13_verdicts.json`: whole dossiers, a trusted
//! directory, witness evidence, and the verdict, exit code and report
//! booleans every conformant verifier must produce for each case
//! (SPEC.md §9.2, RFC-0002). Deterministic: fixed keys, fixed timestamps,
//! Ed25519's deterministic signatures. Run with:
//!
//!   cargo run -p witness-log-network --example generate_verdict_corpus
//!
//! CI regenerates it and fails if the committed file differs. Every key
//! here is PUBLIC and for conformance testing only.
//!
//! Unlike vectors 01–12 this is a verification vector, not an encoding
//! vector: an implementation runs every case through its verifier and
//! compares the outcome, rather than producing the file itself.

use ed25519_dalek::SigningKey;
use serde_json::{json, Value};
use witness_log_core::c2sp::{canonical_origin, Checkpoint, VerifierKey};
use witness_log_core::leaf::{Leaf, LeafType};
use witness_log_core::merkle::{leaf_hash, MerkleTree};
use witness_log_core::sth::SignedTreeHead;
use witness_log_network::tlog_witness::EquivocationProof;
use witness_log_network::{
    Dossier, KnownHead, VerifyContext, WitnessDirectory, WitnessEntry, WitnessReceipt,
    WitnessRuntime,
};

const IDENTITY_SEED: [u8; 32] = [0x13; 32];
const OTHER_IDENTITY_SEED: [u8; 32] = [0x14; 32];
const STRANGER_SEED: [u8; 32] = [0x15; 32];
const T0: u64 = 1_700_000_000_000;

fn leaf(index: u64, session: &str) -> Leaf {
    let leaf_type = if index % 2 == 0 {
        LeafType::ActiveIntent
    } else {
        LeafType::ActiveResult
    };
    Leaf {
        index,
        leaf_type: leaf_type.tag(),
        timestamp_ms: T0 + index * 1000,
        session_pubkey: session.to_string(),
        payload_hash: hex::encode([0x40 + index as u8; 32]),
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

fn root_of(leaves: &[Leaf]) -> [u8; 32] {
    let mut t = MerkleTree::new();
    for l in leaves {
        t.append(leaf_hash(&l.canonical_bytes()));
    }
    t.root()
}

fn equivocation(signer: &SigningKey, origin_key: &SigningKey) -> EquivocationProof {
    let origin = canonical_origin(&origin_key.verifying_key());
    let note = |root: u8| {
        Checkpoint {
            origin: origin.clone(),
            tree_size: 2,
            root_hash: [root; 32],
            extensions: vec![],
        }
        .sign(signer)
        .unwrap()
        .encode()
        .unwrap()
    };
    EquivocationProof {
        origin: origin.clone(),
        log_vkey: VerifierKey::for_ed25519(&origin, &signer.verifying_key()).encode(),
        earlier_note: note(0xa1),
        conflicting_note: note(0xa2),
    }
}

fn main() {
    let identity = SigningKey::from_bytes(&IDENTITY_SEED);
    let identity_hex = hex::encode(identity.verifying_key().to_bytes());
    let other = SigningKey::from_bytes(&OTHER_IDENTITY_SEED);
    let stranger = SigningKey::from_bytes(&STRANGER_SEED);

    // Four witnesses, four independent operators, none project-operated.
    let witness_keys: Vec<SigningKey> = (0..4u8)
        .map(|i| SigningKey::from_bytes(&[0x20 + i; 32]))
        .collect();
    let directory = WitnessDirectory {
        witnesses: witness_keys
            .iter()
            .enumerate()
            .map(|(i, k)| WitnessEntry {
                name: format!("corpus-witness-{i}"),
                operator_org: format!("corpus-operator-{i}"),
                url: format!("https://witness-{i}.example"),
                pubkey: hex::encode(k.verifying_key().to_bytes()),
                runtime: WitnessRuntime::Human,
                compute_provider: Some(format!("corpus-provider-{i}")),
                is_project_operated: false,
            })
            .collect(),
    };

    let leaves: Vec<Leaf> = (0..4).map(|i| leaf(i, &identity_hex)).collect();
    let root = root_of(&leaves);
    let sth = SignedTreeHead::sign(&identity, 4, &root, T0 + 10_000);
    let receipts = |n: usize| -> Vec<WitnessReceipt> {
        witness_keys
            .iter()
            .take(n)
            .enumerate()
            .map(|(i, k)| WitnessReceipt::sign(k, &sth, T0 + 11_000 + i as u64))
            .collect()
    };
    let dossier = |n: usize| Dossier {
        identity_pubkey: identity_hex.clone(),
        leaves: leaves.clone(),
        checkpoint: sth.clone(),
        witness_receipts: receipts(n),
        witness_directory: WitnessDirectory::default(),
        key_bindings: vec![],
        revocations: vec![],
    };
    let full = dossier(4);
    let two_of_four = dossier(2);
    let mut tampered = dossier(4);
    tampered.leaves[1].payload_hash = hex::encode([0xee; 32]);
    let mut truncated = dossier(4);
    truncated.leaves.pop();

    let prefix_root_2 = hex::encode(root_of(&leaves[..2]));
    let empty_root = hex::encode(root_of(&[]));
    let full_root = hex::encode(root);
    let wrong_root = hex::encode([0xab; 32]);

    let evidence = json!({
        "equivocation": equivocation(&identity, &identity),
        "stranger_key": equivocation(&stranger, &identity),
        "other_identity": equivocation(&other, &other),
    });

    // (name, dossier, directory, identity, min_witnesses, known_heads,
    //  evidence, allow_sub_majority)
    type Case<'a> = (
        &'a str,
        &'a str,
        bool,
        Option<&'a str>,
        Option<usize>,
        Vec<String>,
        Vec<&'a str>,
        bool,
    );
    let wrong_identity = hex::encode([0xcd; 32]);
    let cases: Vec<Case> = vec![
        (
            "no trusted inputs",
            "full",
            false,
            None,
            None,
            vec![],
            vec![],
            false,
        ),
        (
            "trusted directory, 4 of 4",
            "full",
            true,
            None,
            None,
            vec![],
            vec![],
            false,
        ),
        (
            "pinned identity, 4 of 4",
            "full",
            true,
            Some("pinned"),
            None,
            vec![],
            vec![],
            false,
        ),
        (
            "wrong identity",
            "full",
            true,
            Some("wrong"),
            None,
            vec![],
            vec![],
            false,
        ),
        (
            "gate not met",
            "full",
            true,
            None,
            Some(5),
            vec![],
            vec![],
            false,
        ),
        (
            "2 of 4 under --min-witnesses 2",
            "two_of_four",
            true,
            None,
            Some(2),
            vec![],
            vec![],
            false,
        ),
        (
            "2 of 4, allow sub-majority",
            "two_of_four",
            true,
            None,
            Some(2),
            vec![],
            vec![],
            true,
        ),
        (
            "2 of 4, default threshold",
            "two_of_four",
            true,
            None,
            None,
            vec![],
            vec![],
            false,
        ),
        (
            "tampered leaf",
            "full_tampered",
            true,
            None,
            None,
            vec![],
            vec![],
            false,
        ),
        (
            "leaf removed",
            "full_truncated",
            false,
            None,
            None,
            vec![],
            vec![],
            false,
        ),
        (
            "tampered, contradicted known head is not checked",
            "full_tampered",
            false,
            None,
            None,
            vec![format!("2:{wrong_root}")],
            vec![],
            false,
        ),
        (
            "known head reproduced",
            "full",
            false,
            None,
            None,
            vec![format!("2:{prefix_root_2}")],
            vec![],
            false,
        ),
        (
            "known head at full size reproduced",
            "full",
            true,
            None,
            None,
            vec![format!("4:{full_root}")],
            vec![],
            false,
        ),
        (
            "empty known head reproduced",
            "full",
            false,
            None,
            None,
            vec![format!("0:{empty_root}")],
            vec![],
            false,
        ),
        (
            "known head contradicted",
            "full",
            false,
            None,
            None,
            vec![format!("2:{wrong_root}")],
            vec![],
            false,
        ),
        (
            "known head contradicted beats WITNESSED",
            "full",
            true,
            Some("pinned"),
            None,
            vec![format!("3:{prefix_root_2}")],
            vec![],
            false,
        ),
        (
            "known head larger than the dossier",
            "full",
            false,
            None,
            None,
            vec![format!("9:{wrong_root}")],
            vec![],
            false,
        ),
        (
            "equivocation evidence",
            "full",
            true,
            None,
            None,
            vec![],
            vec!["equivocation"],
            false,
        ),
        (
            "evidence signed by a stranger is ignored",
            "full",
            false,
            None,
            None,
            vec![],
            vec!["stranger_key"],
            false,
        ),
        (
            "evidence about another identity is ignored",
            "full",
            false,
            None,
            None,
            vec![],
            vec!["other_identity"],
            false,
        ),
    ];

    let dossiers = json!({
        "full": full,
        "two_of_four": two_of_four,
        "full_tampered": tampered,
        "full_truncated": truncated,
    });
    let by_name = |n: &str| -> Dossier { serde_json::from_value(dossiers[n].clone()).unwrap() };

    // The organisation that operates the log, as the verifier knows it
    // (`--subject-org`): its own witnesses never count as independent.
    let subject_cases: Vec<(Case, &str)> = vec![
        (
            (
                "subject org named, 4 of 4: three others remain",
                "full",
                true,
                None,
                None,
                vec![],
                vec![],
                false,
            ),
            "corpus-operator-0",
        ),
        (
            (
                "subject org named, 2 of 4: one other is not enough",
                "two_of_four",
                true,
                None,
                Some(2),
                vec![],
                vec![],
                false,
            ),
            "corpus-operator-0",
        ),
        (
            (
                "subject org matched after case and space normalization",
                "two_of_four",
                true,
                None,
                Some(2),
                vec![],
                vec![],
                false,
            ),
            "  Corpus-Operator-0 ",
        ),
        (
            (
                "subject org not in the directory changes nothing",
                "two_of_four",
                true,
                None,
                Some(2),
                vec![],
                vec![],
                true,
            ),
            "some other org",
        ),
    ];
    let all_cases: Vec<(Case, Option<&str>)> = cases
        .into_iter()
        .map(|c| (c, None))
        .chain(subject_cases.into_iter().map(|(c, o)| (c, Some(o))))
        .collect();

    let mut out_cases = Vec::new();
    for ((name, d, use_dir, id, min, heads, ev, allow), subject_org) in all_cases {
        let expected_identity = match id {
            Some("pinned") => Some(identity_hex.clone()),
            Some("wrong") => Some(wrong_identity.clone()),
            _ => None,
        };
        let known_heads: Vec<KnownHead> = heads.iter().map(|h| h.parse().unwrap()).collect();
        let proofs: Vec<EquivocationProof> = ev
            .iter()
            .map(|k| serde_json::from_value(evidence[*k].clone()).unwrap())
            .collect();
        let ctx = VerifyContext {
            expected_identity_pubkey: expected_identity.as_deref(),
            trusted_directory: if use_dir { Some(&directory) } else { None },
            min_receipts: min,
            revocations: &[],
            known_heads: &known_heads,
            evidence: &proofs,
            subject_org,
        };
        let r = by_name(d).verify(0.66, &ctx);
        let exit_code = if r.split_view_unsafe && !allow {
            11
        } else {
            match r.verdict {
                witness_log_network::Verdict::Witnessed => 0,
                witness_log_network::Verdict::ConsistentUnwitnessed => 10,
                witness_log_network::Verdict::Unanchored => 20,
                witness_log_network::Verdict::Diverged => 30,
                witness_log_network::Verdict::Invalid => 40,
            }
        };
        out_cases.push(json!({
            "name": name,
            "dossier": d,
            "trusted_directory": use_dir,
            "expected_identity": expected_identity,
            "threshold": 0.66,
            "min_witnesses": min,
            "known_heads": heads,
            "evidence": ev,
            "allow_sub_majority": allow,
            "subject_org": subject_org,
            "expect": {
                "verdict": r.verdict,
                "exit_code": exit_code,
                "split_view_unsafe": r.split_view_unsafe,
                "internally_consistent": r.internally_consistent,
                "has_failures": !r.failures.is_empty(),
                "contradictions": r.contradictions.len(),
                "known_heads_unchecked": r.known_heads_unchecked.len(),
                "valid_receipts": r.quorum.as_ref().map(|q| q.valid_receipts),
                "independent_operators": r.quorum.as_ref().map(|q| q.distinct_independent_operators),
            },
        }));
    }

    let doc = json!({
        "description": "Verification vector (SPEC.md §9.2, RFC-0002): run every case through \
            your verifier with the named dossier, the trusted directory when trusted_directory \
            is true, expected_identity, threshold, min_witnesses (when not null, it replaces \
            the threshold gate), known_heads (\"<size>:<root hex>\") and the named evidence \
            proofs; the verdict, exit code and report fields must equal expect. exit_code is \
            the CLI's: 11 when split_view_unsafe and allow_sub_majority is false. \
            subject_org, when not null, is the organisation that operates the log \
            (`verify --subject-org`): witnesses with that operator_org, normalized like \
            every operator label, never count as independent operators. \
            has_failures is whether report.failures is non-empty; failure wording is not \
            normative. Every key here is public and for testing only.",
        "identity_pubkey": identity_hex,
        "trusted_directory": directory,
        "dossiers": dossiers,
        "evidence": evidence,
        "cases": out_cases,
    });

    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../corpus");
    let path = dir.join("13_verdicts.json");
    std::fs::write(&path, serde_json::to_string_pretty(&doc).unwrap() + "\n").unwrap();
    println!("wrote {}", path.display());
    let _: Value = doc;
}
