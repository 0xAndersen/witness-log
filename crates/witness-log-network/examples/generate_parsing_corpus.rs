//! Generates `corpus/17_dossier_parsing.json`: dossiers as JSON text, at
//! the edges where the three verifiers once read the same file
//! differently (outside review III, H2 and P3). Each case is either
//! a text the reference cannot read as a dossier (`Dossier::from_json`;
//! `not_a_dossier`) or one it can, with the verdict, exit code and report
//! fields:
//!
//! - not JSON, not an object, wrong types, `null` where a list or struct
//!   belongs, missing fields, a struct written as an array, duplicate
//!   fields, unpaired surrogates, enum forms;
//! - integers: fractions, exponents, `-0`, negatives, beyond 2^64 - 1, and
//!   u64 values above 2^53 signed exactly (JavaScript's `JSON.parse`
//!   rounds them; the reference and Go read them exactly);
//! - keys that differ from a field name only by case (Go's encoding/json
//!   matched them case-insensitively);
//! - hex case in each field the verdict compares;
//! - nesting depth, at most `MAX_DOSSIER_DEPTH` (1000) wherever it is
//!   (outside audit of 0.6.1: the reference and TypeScript read an ignored
//!   key of any depth, Go refused 10,000 levels and more);
//! - `fleet_anchor` numbers at the edge of binary64 (the same audit: the
//!   reference's serde_json, without `float_roundtrip`, refused finite
//!   literals near f64::MAX that Go and TypeScript read).
//!
//! `inputs` applies the nesting limit to the other JSON inputs a verifier
//! reads: a trusted directory, revocations and an evidence item, each at
//! depth 1000, 1001 and 100,000 and with brackets in a string. The audit of
//! 0.6.1 found the limit covered dossier text only: Go refused those inputs
//! 10,000 deep and more, the reference read a directory or revocations of
//! any depth and an evidence item only up to serde_json's recursion limit
//! (128), and TypeScript read options of any depth.
//!
//! The text is the input, byte for byte, so it is stored as a string.
//!
//!   cargo run -p witness-log-network --example generate_parsing_corpus
//!
//! CI regenerates it and fails if the committed file differs. Each case
//! states the outcome it is built to have, and this generator panics if
//! the reference disagrees. Deterministic: fixed keys, Ed25519's
//! deterministic signatures. Every key here is PUBLIC and for conformance
//! testing only.

use ed25519_dalek::{Signer, SigningKey};
use serde_json::json;
use witness_log_core::c2sp::{canonical_origin, Checkpoint, Cosignature, VerifierKey};
use witness_log_core::identity::{
    revocation_message, KeyBindingStatement, KeyCustody, RevocationStatement,
};
use witness_log_core::leaf::{AuthorizationEventKind, HandoffDirection, Leaf, LeafType};
use witness_log_core::merkle::{leaf_hash, MerkleTree};
use witness_log_core::sth::SignedTreeHead;
use witness_log_network::tlog_witness::EquivocationProof;
use witness_log_network::{
    revocations_from_json, Dossier, DossierReport, InputParseError, KnownHead, Verdict,
    VerifyContext, WitnessDirectory, WitnessEntry, WitnessReceipt, WitnessRuntime,
};

const IDENTITY_SEED: [u8; 32] = [0x19; 32];
const COUNTERPARTY_SEED: [u8; 32] = [0x1a; 32];
const WITNESS_SEEDS: [[u8; 32]; 2] = [[0x29; 32], [0x2a; 32]];
const T0: u64 = 1_700_000_000_000;
const ABOVE_2_53: u64 = (1 << 53) + 1;

fn leaf(index: u64, session: &str, counterparty: &str) -> Leaf {
    let mut l = Leaf {
        index,
        leaf_type: LeafType::ActiveIntent.tag(),
        timestamp_ms: T0 + index * 1000,
        session_pubkey: session.to_string(),
        payload_hash: hex::encode([0x70 + index as u8; 32]),
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
    };
    match index {
        1 => {
            l.leaf_type = LeafType::HandoffAttestation.tag();
            l.handoff_direction = Some(HandoffDirection::Sent);
            l.counterparty_pubkey = Some(counterparty.to_string());
            l.handoff_state_hash = Some(hex::encode([0x7a; 32]));
        }
        2 => {
            l.leaf_type = LeafType::AuthorizationEvent.tag();
            l.authorization_event_kind = Some(AuthorizationEventKind::GrantedByMe);
            l.counterparty_pubkey = Some(counterparty.to_string());
            l.authorization_scope_hash = Some(hex::encode([0x7b; 32]));
        }
        _ => {}
    }
    l
}

fn root_of(leaves: &[Leaf]) -> [u8; 32] {
    let mut t = MerkleTree::new();
    for l in leaves {
        t.append(leaf_hash(&l.canonical_bytes()));
    }
    t.root()
}

fn lp(buf: &mut Vec<u8>, b: &[u8]) {
    buf.extend_from_slice(&(b.len() as u32).to_be_bytes());
    buf.extend_from_slice(b);
}

/// SPEC.md §6's checkpoint message, over the signer string as written.
fn sth_message(signer: &str, tree_size: u64, root: &[u8; 32], ts: u64) -> Vec<u8> {
    let mut m = b"witness-log-sth-v2".to_vec();
    lp(&mut m, b"ed25519");
    lp(&mut m, signer.as_bytes());
    m.extend_from_slice(&tree_size.to_be_bytes());
    m.extend_from_slice(root);
    m.extend_from_slice(&ts.to_be_bytes());
    m
}

/// SPEC.md §7's native receipt message, over the strings as written.
fn receipt_message(witness: &str, signer: &str, size: u64, root: &str, at: u64) -> Vec<u8> {
    let mut m = b"witness-log-witness-receipt-v2".to_vec();
    lp(&mut m, witness.as_bytes());
    lp(&mut m, signer.as_bytes());
    m.extend_from_slice(&size.to_be_bytes());
    lp(&mut m, root.as_bytes());
    m.extend_from_slice(&at.to_be_bytes());
    m
}

/// SPEC.md §5's key binding message.
fn binding_message(
    identity: &[u8; 32],
    session: &[u8; 32],
    n: u64,
    ts: u64,
    not_after: Option<u64>,
) -> Vec<u8> {
    let mut m = b"witness-log-key-bind-v1".to_vec();
    m.extend_from_slice(identity);
    m.extend_from_slice(session);
    m.extend_from_slice(&n.to_be_bytes());
    m.extend_from_slice(&ts.to_be_bytes());
    match not_after {
        Some(t) => {
            m.push(1);
            m.extend_from_slice(&t.to_be_bytes());
        }
        None => m.push(0),
    }
    m
}

struct Keys {
    identity: SigningKey,
    identity_hex: String,
    witnesses: Vec<SigningKey>,
}

impl Keys {
    fn witness_hex(&self, i: usize) -> String {
        hex::encode(self.witnesses[i].verifying_key().to_bytes())
    }

    fn sth(&self, signer: &str, leaves: &[Leaf], ts: u64) -> SignedTreeHead {
        let root = root_of(leaves);
        let m = sth_message(signer, leaves.len() as u64, &root, ts);
        SignedTreeHead {
            tree_size: leaves.len() as u64,
            root_hash: hex::encode(root),
            timestamp_ms: ts,
            sig_alg: "ed25519".into(),
            signer_pubkey: signer.into(),
            signature: hex::encode(self.identity.sign(&m).to_bytes()),
        }
    }

    /// A native receipt by witness `i`, signed over the strings as given.
    fn receipt(
        &self,
        i: usize,
        witness: &str,
        sth: &SignedTreeHead,
        root: &str,
        at: u64,
    ) -> WitnessReceipt {
        let m = receipt_message(witness, &sth.signer_pubkey, sth.tree_size, root, at);
        WitnessReceipt {
            witness_pubkey: witness.into(),
            tree_size: sth.tree_size,
            root_hash: root.into(),
            witnessed_at_ms: at,
            signature: hex::encode(self.witnesses[i].sign(&m).to_bytes()),
            c2sp_origin: None,
            witness_name: None,
        }
    }

    /// A C2SP cosignature receipt by witness `i` at `at` (whole seconds).
    fn c2sp_receipt(&self, i: usize, sth: &SignedTreeHead, at: u64) -> WitnessReceipt {
        let origin = canonical_origin(&self.identity.verifying_key());
        let root: [u8; 32] = hex::decode(&sth.root_hash).unwrap().try_into().unwrap();
        let body = Checkpoint {
            origin: origin.clone(),
            tree_size: sth.tree_size,
            root_hash: root,
            extensions: vec![],
        }
        .note_text()
        .unwrap();
        let m = Cosignature::message(at / 1000, &body);
        WitnessReceipt {
            witness_pubkey: self.witness_hex(i),
            tree_size: sth.tree_size,
            root_hash: sth.root_hash.clone(),
            witnessed_at_ms: at,
            signature: hex::encode(self.witnesses[i].sign(m.as_bytes()).to_bytes()),
            c2sp_origin: Some(origin),
            witness_name: None,
        }
    }

    fn binding(
        &self,
        identity: &str,
        session: &str,
        n: u64,
        ts: u64,
        not_after: Option<u64>,
        custody: KeyCustody,
    ) -> KeyBindingStatement {
        let id: [u8; 32] = hex::decode(identity).unwrap().try_into().unwrap();
        let s: [u8; 32] = hex::decode(session).unwrap().try_into().unwrap();
        let b = KeyBindingStatement {
            identity_pubkey: identity.into(),
            session_pubkey: session.into(),
            session_number: n,
            timestamp_ms: ts,
            custody,
            not_after_ms: not_after,
            signature: hex::encode(
                self.identity
                    .sign(&binding_message(&id, &s, n, ts, not_after))
                    .to_bytes(),
            ),
        };
        assert!(b.verify().is_ok());
        b
    }
}

fn dossier(identity: &str, leaves: Vec<Leaf>, checkpoint: SignedTreeHead) -> Dossier {
    Dossier {
        identity_pubkey: identity.into(),
        leaves,
        checkpoint,
        witness_receipts: vec![],
        witness_directory: WitnessDirectory::default(),
        key_bindings: vec![],
        revocations: vec![],
        fleet_anchor: None,
    }
}

fn text(d: &Dossier) -> String {
    serde_json::to_string(d).unwrap()
}

/// `s` with the first occurrence of `from` replaced; `from` must occur.
fn sub(s: &str, from: &str, to: &str) -> String {
    assert!(s.contains(from), "{from:?} not in the text");
    s.replacen(from, to, 1)
}

/// Before the closing brace of the top-level object.
fn add_field(s: &str, field: &str) -> String {
    let end = s.rfind('}').unwrap();
    format!("{},{field}}}", &s[..end])
}

/// `m * 2^e` in decimal.
fn decimal_times_pow2(m: u64, e: u32) -> String {
    let mut digits: Vec<u8> = m.to_string().bytes().rev().map(|b| b - b'0').collect();
    for _ in 0..e {
        let mut carry = 0;
        for d in digits.iter_mut() {
            let x = *d * 2 + carry;
            *d = x % 10;
            carry = x / 10;
        }
        if carry > 0 {
            digits.push(carry);
        }
    }
    digits.iter().rev().map(|d| char::from(b'0' + d)).collect()
}

/// A positive decimal integer minus one.
fn decimal_minus_one(s: &str) -> String {
    let mut digits: Vec<u8> = s.bytes().map(|b| b - b'0').collect();
    for d in digits.iter_mut().rev() {
        if *d > 0 {
            *d -= 1;
            break;
        }
        *d = 9;
    }
    let s: String = digits.iter().map(|d| char::from(b'0' + d)).collect();
    s.trim_start_matches('0').to_string()
}

#[derive(Clone, Copy, PartialEq, Debug)]
enum Outcome {
    NotADossier,
    Exit(u8),
}

struct Case {
    name: String,
    text: String,
    directory: Option<&'static str>,
    min_witnesses: Option<usize>,
    expected_identity: Option<String>,
    known_heads: Vec<String>,
    intended: Outcome,
}

fn case(name: &str, text: String, intended: Outcome) -> Case {
    Case {
        name: name.into(),
        text,
        directory: None,
        min_witnesses: None,
        expected_identity: None,
        known_heads: vec![],
        intended,
    }
}

impl Case {
    fn dir(mut self, d: &'static str, min: usize) -> Self {
        self.directory = Some(d);
        self.min_witnesses = Some(min);
        self
    }
}

/// Which input of `verify` an `inputs` case gives as text.
#[derive(Clone, Copy, PartialEq, Debug)]
enum Input {
    /// `--directory`: `{"witnesses": [...]}` or a bare array of entries.
    Directory,
    /// `--revocations`: one statement or an array of them.
    Revocations,
    /// `--evidence`: one evidence item.
    Evidence,
}

impl Input {
    fn name(self) -> &'static str {
        match self {
            Input::Directory => "directory",
            Input::Revocations => "revocations",
            Input::Evidence => "evidence",
        }
    }
}

/// A case of `inputs`: the dossier of the case named "valid", verified with
/// `text` as the input `input` names. `NotADossier` here means the verifier
/// refuses the input.
struct InputCase {
    name: &'static str,
    input: Input,
    text: String,
    intended: Outcome,
}

fn input(name: &'static str, input: Input, text: String, intended: Outcome) -> InputCase {
    InputCase {
        name,
        input,
        text,
        intended,
    }
}

/// The CLI's exit code for a report (strict, without --allow-sub-majority).
fn exit_code(r: &DossierReport) -> u8 {
    if r.split_view_unsafe {
        11
    } else {
        match r.verdict {
            Verdict::Witnessed => 0,
            Verdict::ConsistentUnwitnessed => 10,
            Verdict::Unanchored => 20,
            Verdict::Diverged => 30,
            Verdict::Invalid => 40,
        }
    }
}

/// Two checkpoints the identity signed for one size with different roots.
fn equivocation(identity: &SigningKey) -> EquivocationProof {
    let origin = canonical_origin(&identity.verifying_key());
    let note = |root: u8| {
        Checkpoint {
            origin: origin.clone(),
            tree_size: 2,
            root_hash: [root; 32],
            extensions: vec![],
        }
        .sign(identity)
        .unwrap()
        .encode()
        .unwrap()
    };
    let proof = EquivocationProof {
        origin: origin.clone(),
        log_vkey: VerifierKey::for_ed25519(&origin, &identity.verifying_key()).encode(),
        earlier_note: note(0xa1),
        conflicting_note: note(0xa2),
    };
    assert!(proof.verify());
    proof
}

use Outcome::{Exit, NotADossier as Refused};

fn main() {
    let identity = SigningKey::from_bytes(&IDENTITY_SEED);
    let k = Keys {
        identity_hex: hex::encode(identity.verifying_key().to_bytes()),
        identity,
        witnesses: WITNESS_SEEDS.iter().map(SigningKey::from_bytes).collect(),
    };
    let id = k.identity_hex.clone();
    let counterparty = hex::encode(
        SigningKey::from_bytes(&COUNTERPARTY_SEED)
            .verifying_key()
            .to_bytes(),
    );

    // ---- dossiers
    let leaves: Vec<Leaf> = (0..3).map(|i| leaf(i, &id, &counterparty)).collect();
    let sth = k.sth(&id, &leaves, T0 + 10_000);
    let mut base = dossier(&id, leaves.clone(), sth.clone());
    base.witness_receipts = (0..2)
        .map(|i| {
            k.receipt(
                i,
                &k.witness_hex(i),
                &sth,
                &sth.root_hash,
                T0 + 11_000 + i as u64,
            )
        })
        .collect();
    let base_t = text(&base);
    let minimal = dossier(&id, vec![], k.sth(&id, &[], T0 + 10_000));
    let min_t = text(&minimal);
    let entry = |i: usize, pubkey: String| WitnessEntry {
        name: format!("corpus-17-witness-{i}"),
        operator_org: format!("corpus-17-operator-{i}"),
        url: format!("https://corpus-17-witness-{i}.example"),
        pubkey,
        runtime: WitnessRuntime::Human,
        compute_provider: None,
        is_project_operated: false,
    };
    let directories = json!({
        "corpus": WitnessDirectory { witnesses: vec![entry(0, k.witness_hex(0)), entry(1, k.witness_hex(1))] },
        "upper": WitnessDirectory { witnesses: vec![entry(0, k.witness_hex(0)), entry(1, k.witness_hex(1).to_uppercase())] },
    });

    // u64 values above 2^53, each signed or committed exactly.
    let big_checkpoint = |ts: u64| text(&dossier(&id, leaves.clone(), k.sth(&id, &leaves, ts)));
    let mut big_leaves = leaves.clone();
    big_leaves[0].timestamp_ms = ABOVE_2_53;
    let big_leaf_t = text(&dossier(
        &id,
        big_leaves.clone(),
        k.sth(&id, &big_leaves, T0 + 10_000),
    ));
    let mut big_statements = dossier(&id, leaves.clone(), sth.clone());
    big_statements.key_bindings = vec![k.binding(
        &id,
        &id,
        u64::MAX,
        ABOVE_2_53,
        Some(u64::MAX),
        KeyCustody::SelfHeld,
    )];
    let rm = revocation_message(
        &k.identity.verifying_key().to_bytes(),
        u64::MAX,
        Some(ABOVE_2_53),
        "corpus 17",
    );
    big_statements.revocations = vec![RevocationStatement {
        identity_pubkey: id.clone(),
        as_of_ms: u64::MAX,
        as_of_index: Some(ABOVE_2_53),
        reason: "corpus 17".into(),
        signature: hex::encode(k.identity.sign(&rm).to_bytes()),
    }];
    assert!(big_statements.revocations[0].verify().is_ok());
    let mut big_receipt = base.clone();
    big_receipt.witness_receipts[0] =
        k.receipt(0, &k.witness_hex(0), &sth, &sth.root_hash, ABOVE_2_53);
    let c2sp_at = u64::MAX - u64::MAX % 1000;
    let mut big_c2sp = base.clone();
    big_c2sp.witness_receipts[1] = k.c2sp_receipt(1, &sth, c2sp_at);

    // Hex case (P3), field by field.
    let mut upper_root = dossier(&id, leaves.clone(), sth.clone());
    upper_root.checkpoint.root_hash = sth.root_hash.to_uppercase(); // the signature is over the bytes
    let mut upper_receipt_root = base.clone();
    upper_receipt_root.witness_receipts[1] = k.receipt(
        1,
        &k.witness_hex(1),
        &sth,
        &sth.root_hash.to_uppercase(),
        T0 + 11_001,
    );
    let mut upper_receipt_witness = base.clone();
    upper_receipt_witness.witness_receipts[1] = k.receipt(
        1,
        &k.witness_hex(1).to_uppercase(),
        &sth,
        &sth.root_hash,
        T0 + 11_001,
    );
    let upper_id = id.to_uppercase();
    let upper_sth = k.sth(&upper_id, &leaves, T0 + 10_000);
    let mut upper_signer = dossier(&upper_id, leaves.clone(), upper_sth.clone());
    upper_signer.witness_receipts = vec![
        k.receipt(
            0,
            &k.witness_hex(0),
            &upper_sth,
            &upper_sth.root_hash,
            T0 + 11_000,
        ),
        k.c2sp_receipt(1, &upper_sth, T0 + 12_000),
    ];
    let mut upper_binding = dossier(&id, leaves.clone(), sth.clone());
    upper_binding.key_bindings =
        vec![k.binding(&upper_id, &id, 1, T0 - 1000, None, KeyCustody::Hsm)];
    let mut custody_map = dossier(&id, leaves.clone(), sth.clone());
    custody_map.key_bindings = vec![k.binding(&id, &id, 1, T0 - 1000, None, KeyCustody::Hsm)];
    let custody_t = text(&custody_map);
    let mut threshold = custody_map.clone();
    threshold.key_bindings[0].custody = KeyCustody::Threshold {
        k: "2".into(),
        n: "3".into(),
    };
    let threshold_t = text(&threshold);

    let ck = |s: &str| format!("\"checkpoint\":{{\"tree_size\":{s}");
    let ck_base = ck("3");
    let ck_min = ck("0");
    let nested = |n: usize| format!("{}{}", "[".repeat(n), "]".repeat(n));
    let objects = |n: usize| format!("{}1{}", "{\"a\":".repeat(n), "}".repeat(n));
    // The edge of binary64. Literals round to nearest, ties to even: f64::MAX
    // is (2^53 - 1) * 2^971, and the point halfway to 2^1024,
    // (2^54 - 1) * 2^970, rounds up, to infinity. Checked here against
    // Rust's own correctly rounded parser.
    let halfway = decimal_times_pow2((1 << 54) - 1, 970);
    let below_halfway = decimal_minus_one(&halfway);
    let max_digits = format!("17976931348623157{}", "0".repeat(292));
    assert_eq!(halfway.len(), 309);
    assert_eq!(halfway.parse::<f64>().unwrap(), f64::INFINITY);
    for finite in [
        below_halfway.as_str(),
        max_digits.as_str(),
        "1.7976931348623158e308",
    ] {
        assert_eq!(finite.parse::<f64>().unwrap(), f64::MAX, "{finite}");
    }
    assert_eq!(
        "1.7976931348623159e308".parse::<f64>().unwrap(),
        f64::INFINITY
    );
    let fleet_x = |x: &str| add_field(&min_t, &format!("\"fleet_anchor\":{{\"x\":{x}}}"));
    let leaf_zz = |n: usize| {
        sub(
            &base_t,
            "{\"index\":0,",
            &format!("{{\"zz\":{},\"index\":0,", nested(n)),
        )
    };

    let mut cases = vec![
        // ---- JSON text and the top-level value
        case("valid", base_t.clone(), Exit(20)),
        case("valid, trusted directory", base_t.clone(), Exit(0)).dir("corpus", 2),
        case("not JSON", "{not json".into(), Refused),
        case("empty text", String::new(), Refused),
        case("null", "null".into(), Refused),
        case("an empty array", "[]".into(), Refused),
        case("a number", "42".into(), Refused),
        case("a string", "\"dossier\"".into(), Refused),
        case("true", "true".into(), Refused),
        case("a byte order mark before the object", format!("\u{feff}{min_t}"), Refused),
        case("trailing characters after the object", format!("{min_t} x"), Refused),
        case("a trailing comma", format!("{},}}", &min_t[..min_t.len() - 1]), Refused),
        case("whitespace around the object", format!(" \n\t{min_t}\r\n "), Exit(20)),
        case(
            "the dossier written as an array of its field values",
            serde_json::to_string(&json!([id, [], minimal.checkpoint])).unwrap(),
            Refused,
        ),
        // ---- fields: presence, null, type
        case("identity_pubkey missing", sub(&min_t, &format!("\"identity_pubkey\":\"{id}\","), ""), Refused),
        case("identity_pubkey null", sub(&min_t, &format!("\"{id}\""), "null"), Refused),
        case("identity_pubkey a number", sub(&min_t, &format!("\"{id}\""), "5"), Refused),
        case("leaves null", sub(&min_t, "\"leaves\":[]", "\"leaves\":null"), Refused),
        case("leaves an object", sub(&min_t, "\"leaves\":[]", "\"leaves\":{}"), Refused),
        case("checkpoint null", serde_json::to_string(&json!({"identity_pubkey": id, "leaves": [], "checkpoint": null})).unwrap(), Refused),
        case(
            "checkpoint written as an array",
            serde_json::to_string(&json!({"identity_pubkey": id, "leaves": [], "checkpoint": [
                0, minimal.checkpoint.root_hash, minimal.checkpoint.timestamp_ms, "ed25519", id, minimal.checkpoint.signature]})).unwrap(),
            Refused,
        ),
        case("checkpoint signature missing", sub(&min_t, &format!(",\"signature\":\"{}\"", minimal.checkpoint.signature), ""), Refused),
        case("witness_receipts an object", sub(&min_t, "\"witness_receipts\":[]", "\"witness_receipts\":{}"), Refused),
        case("witness_receipts null", sub(&min_t, "\"witness_receipts\":[]", "\"witness_receipts\":null"), Refused),
        case("witness_receipts [null]", sub(&min_t, "\"witness_receipts\":[]", "\"witness_receipts\":[null]"), Refused),
        case("a receipt with no fields", sub(&min_t, "\"witness_receipts\":[]", "\"witness_receipts\":[{}]"), Refused),
        case("witness_receipts absent", sub(&min_t, "\"witness_receipts\":[],", ""), Exit(20)),
        case("key_bindings null", sub(&min_t, "\"key_bindings\":[]", "\"key_bindings\":null"), Refused),
        case("revocations null", sub(&min_t, "\"revocations\":[]", "\"revocations\":null"), Refused),
        case("witness_directory null", sub(&min_t, "\"witness_directory\":{\"witnesses\":[]}", "\"witness_directory\":null"), Refused),
        case("witness_directory written as an array", sub(&min_t, "\"witness_directory\":{\"witnesses\":[]}", "\"witness_directory\":[[]]"), Refused),
        case("witness_directory without witnesses", sub(&min_t, "\"witness_directory\":{\"witnesses\":[]}", "\"witness_directory\":{}"), Refused),
        case("witness_directory absent", sub(&min_t, "\"witness_directory\":{\"witnesses\":[]},", ""), Exit(20)),
    ];
    let dir_entry = |extra: &str| {
        sub(
            &min_t,
            "\"witness_directory\":{\"witnesses\":[]}",
            &format!("\"witness_directory\":{{\"witnesses\":[{{\"name\":\"n\",\"operator_org\":\"o\",\"url\":\"https://n.example\",\"pubkey\":\"{id}\"{extra}}}]}}"),
        )
    };
    cases.extend([
        case("a dossier directory entry with only its required fields", dir_entry(""), Exit(20)),
        case("is_project_operated null", dir_entry(",\"is_project_operated\":null"), Refused),
        case("runtime null", dir_entry(",\"runtime\":null"), Refused),
        case("runtime not human or agent", dir_entry(",\"runtime\":\"robot\""), Refused),
        case("runtime as {\"agent\": null}", dir_entry(",\"runtime\":{\"agent\":null}"), Exit(20)),
        case("compute_provider null", dir_entry(",\"compute_provider\":null"), Exit(20)),
        case("witness_name a number", sub(&base_t, "\"witness_receipts\":[{", "\"witness_receipts\":[{\"witness_name\":5,"), Refused),
        case("witness_name a string", sub(&base_t, "\"witness_receipts\":[{", "\"witness_receipts\":[{\"witness_name\":\"w0\","), Exit(20)),
        case("c2sp_origin null", sub(&base_t, "\"witness_receipts\":[{", "\"witness_receipts\":[{\"c2sp_origin\":null,"), Exit(20)),
        // ---- enums
        case("custody as a string", custody_t.clone(), Exit(20)),
        case("custody as {\"hsm\": null}", sub(&custody_t, "\"custody\":\"hsm\"", "\"custody\":{\"hsm\":null}"), Exit(20)),
        case("custody not a variant", sub(&custody_t, "\"custody\":\"hsm\"", "\"custody\":\"bogus\""), Refused),
        case("custody null", sub(&custody_t, "\"custody\":\"hsm\"", "\"custody\":null"), Refused),
        case("custody with two variants", sub(&custody_t, "\"custody\":\"hsm\"", "\"custody\":{\"hsm\":null,\"kms\":null}"), Refused),
        case("custody threshold", threshold_t.clone(), Exit(20)),
        case("custody threshold written as an array", sub(&threshold_t, "{\"k\":\"2\",\"n\":\"3\"}", "[\"2\",\"3\"]"), Refused),
        case("custody threshold with k twice", sub(&threshold_t, "{\"k\":\"2\",", "{\"k\":\"2\",\"k\":\"2\","), Refused),
        case("custody absent", sub(&custody_t, ",\"custody\":\"hsm\"", ""), Exit(20)),
        case("handoff_direction as {\"Sent\": null}", sub(&base_t, "\"handoff_direction\":\"Sent\"", "\"handoff_direction\":{\"Sent\":null}"), Exit(20)),
        case("handoff_direction not a variant", sub(&base_t, "\"handoff_direction\":\"Sent\"", "\"handoff_direction\":\"Sideways\""), Refused),
        case("handoff_direction as {\"Sent\": 1}", sub(&base_t, "\"handoff_direction\":\"Sent\"", "\"handoff_direction\":{\"Sent\":1}"), Refused),
        case(
            "authorization_event_kind as {\"GrantedByMe\": null}",
            sub(&base_t, "\"authorization_event_kind\":\"GrantedByMe\"", "\"authorization_event_kind\":{\"GrantedByMe\":null}"),
            Exit(20),
        ),
        case("authorization_event_kind lowercase", sub(&base_t, "\"authorization_event_kind\":\"GrantedByMe\"", "\"authorization_event_kind\":\"grantedbyme\""), Refused),
        // ---- integers
        case("tree_size 3.5", sub(&base_t, &ck_base, &ck("3.5")), Refused),
        case("tree_size -1", sub(&base_t, &ck_base, &ck("-1")), Refused),
        case("tree_size 1e30", sub(&base_t, &ck_base, &ck("1e30")), Refused),
        case("tree_size a string", sub(&base_t, &ck_base, &ck("\"3\"")), Refused),
        case("tree_size 3.0", sub(&base_t, &ck_base, &ck("3.0")), Refused),
        case("tree_size 3e0", sub(&base_t, &ck_base, &ck("3e0")), Refused),
        case("tree_size 30e-1", sub(&base_t, &ck_base, &ck("30e-1")), Refused),
        case("tree_size -0", sub(&min_t, &ck_min, &ck("-0")), Refused),
        case("tree_size 0.0", sub(&min_t, &ck_min, &ck("0.0")), Refused),
        case("tree_size 2^64", sub(&base_t, &ck_base, &ck("18446744073709551616")), Refused),
        case("tree_size 2^64 - 1", sub(&base_t, &ck_base, &ck("18446744073709551615")), Exit(40)),
        case("tree_size null", sub(&base_t, &ck_base, &ck("null")), Refused),
        case("tree_size true", sub(&base_t, &ck_base, &ck("true")), Refused),
        case("tree_size with a leading zero", sub(&base_t, &ck_base, &ck("03")), Refused),
        case("checkpoint timestamp_ms 1.5", sub(&base_t, &format!("\"timestamp_ms\":{}", T0 + 10_000), "\"timestamp_ms\":1.5"), Refused),
        case("leaf index 0.5", sub(&base_t, "\"index\":0,", "\"index\":0.5,"), Refused),
        case("leaf index 0.0", sub(&base_t, "\"index\":0,", "\"index\":0.0,"), Refused),
        case("leaf_type 256", sub(&base_t, "\"leaf_type\":1,", "\"leaf_type\":256,"), Refused),
        case("leaf_type -1", sub(&base_t, "\"leaf_type\":1,", "\"leaf_type\":-1,"), Refused),
        case("leaf_type 8", sub(&base_t, "\"leaf_type\":1,", "\"leaf_type\":8,"), Exit(40)),
        case("redacted_index 1.5", sub(&base_t, "\"redacted_index\":null", "\"redacted_index\":1.5"), Refused),
        case("receipt witnessed_at_ms 1.5", sub(&base_t, &format!("\"witnessed_at_ms\":{}", T0 + 11_000), "\"witnessed_at_ms\":1.5"), Refused),
        // u64 above 2^53, exactly
        case("checkpoint timestamp_ms 2^53 + 1, signed exactly", big_checkpoint(ABOVE_2_53), Exit(20)),
        case("checkpoint timestamp_ms 2^64 - 1, signed exactly", big_checkpoint(u64::MAX), Exit(20)),
        case("checkpoint timestamp_ms one more than signed (2^53 + 2)", sub(&big_checkpoint(ABOVE_2_53), &ABOVE_2_53.to_string(), &(ABOVE_2_53 + 1).to_string()), Exit(40)),
        case("leaf timestamp_ms 2^53 + 1, committed exactly", big_leaf_t, Exit(20)),
        case(
            "key binding and revocation with u64 values above 2^53, signed exactly",
            text(&big_statements),
            Exit(20),
        ),
        case("native receipt witnessed_at_ms 2^53 + 1, signed exactly", text(&big_receipt), Exit(0)).dir("corpus", 2),
        case("C2SP receipt witnessed_at_ms near 2^64, signed exactly", text(&big_c2sp), Exit(0)).dir("corpus", 2),
        // ---- keys
        case("checkpoint twice", add_field(&min_t, &format!("\"checkpoint\":{}", serde_json::to_string(&minimal.checkpoint).unwrap())), Refused),
        case("identity_pubkey twice", add_field(&min_t, &format!("\"identity_pubkey\":\"{id}\"")), Refused),
        case("tree_size twice", sub(&base_t, &ck_base, &format!("{ck_base},\"tree_size\":3")), Refused),
        case("an unknown field twice", add_field(&min_t, "\"zz\":1,\"zz\":2"), Exit(20)),
        case("TREE_SIZE beside tree_size is an unknown field", sub(&base_t, &ck_base, &format!("{ck_base},\"TREE_SIZE\":99")), Exit(20)),
        case("Tree_Size instead of tree_size", sub(&base_t, &ck_base, "\"checkpoint\":{\"Tree_Size\":3"), Refused),
        case("SIGNATURE beside signature is an unknown field", sub(&base_t, &format!("\"signature\":\"{}\"", sth.signature), &format!("\"signature\":\"{}\",\"SIGNATURE\":\"{}\"", sth.signature, "00".repeat(64))), Exit(20)),
        case("PAYLOAD_HASH beside payload_hash is an unknown field", sub(&base_t, "\"payload_hash\":", &format!("\"PAYLOAD_HASH\":\"{}\",\"payload_hash\":", "ee".repeat(32))), Exit(20)),
        case("Identity_Pubkey beside identity_pubkey is an unknown field", add_field(&base_t, &format!("\"Identity_Pubkey\":\"{}\"", "ab".repeat(32))), Exit(20)),
        case("a field name written with an escape", sub(&base_t, &ck_base, "\"checkpoint\":{\"\\u0074ree_size\":3"), Exit(20)),
        case("an unknown field", add_field(&min_t, "\"zz\":{\"a\":[1,2,{}]}"), Exit(20)),
        // ---- strings
        case("an unpaired surrogate in sig_alg", sub(&min_t, "\"sig_alg\":\"ed25519\"", "\"sig_alg\":\"ed25519\\ud800\""), Refused),
        case("an unpaired low surrogate in a leaf field", sub(&base_t, "\"anchor_url\":null", "\"anchor_url\":\"\\udc00\""), Refused),
        case("an unpaired surrogate in an unknown field's value", add_field(&min_t, "\"zz\":\"\\udc00\""), Exit(20)),
        case("an unpaired surrogate in an unknown key of the checkpoint", sub(&min_t, &ck_min, "\"checkpoint\":{\"\\udc00\":1,\"tree_size\":0"), Refused),
        case("a surrogate pair in an unknown field", add_field(&min_t, "\"zz\":\"\\ud83d\\ude00\""), Exit(20)),
        case("a raw control character in a string", sub(&min_t, "\"sig_alg\":\"ed25519\"", "\"sig_alg\":\"ed\t25519\""), Refused),
        case("an unknown field holding 1e400", add_field(&min_t, "\"zz\":1e400"), Exit(20)),
        case("an unknown field holding a 400-digit integer", add_field(&min_t, &format!("\"zz\":1{}", "0".repeat(400))), Exit(20)),
        case("an unknown field nested 200 deep", add_field(&min_t, &format!("\"zz\":{}", nested(200))), Exit(20)),
        // ---- nesting depth: at most 1000, counted outside strings, the dossier object being depth 1
        case("an unknown field nested to depth 1000, the limit", add_field(&min_t, &format!("\"zz\":{}", nested(999))), Exit(20)),
        case("an unknown field nested to depth 1001", add_field(&min_t, &format!("\"zz\":{}", nested(1000))), Refused),
        case("an unknown field of objects nested to depth 1000", add_field(&min_t, &format!("\"zz\":{}", objects(999))), Exit(20)),
        case("an unknown field of objects nested to depth 1001", add_field(&min_t, &format!("\"zz\":{}", objects(1000))), Refused),
        case("an unknown field of a leaf nested to depth 1000", leaf_zz(997), Exit(20)),
        case("an unknown field of a leaf nested to depth 1001", leaf_zz(998), Refused),
        case("an unknown field nested 100000 deep", add_field(&min_t, &format!("\"zz\":{}", nested(100_000))), Refused),
        case(
            "1001 brackets in a string after an escaped quote do not nest",
            add_field(&min_t, &format!("\"zz\":\"\\\"{}\"", "[".repeat(1001))),
            Exit(20),
        ),
        case("tree_size a 100000-digit integer", sub(&base_t, &ck_base, &ck(&format!("1{}", "0".repeat(100_000)))), Refused),
        // ---- fleet_anchor (RFC-0001, experimental): any value, read as a JSON value
        case("fleet_anchor null", add_field(&min_t, "\"fleet_anchor\":null"), Exit(20)),
        case("fleet_anchor an array (malformed, ignored)", add_field(&min_t, "\"fleet_anchor\":[1,2]"), Exit(20)),
        case("fleet_anchor with an unpaired surrogate", add_field(&min_t, "\"fleet_anchor\":{\"origin\":\"\\udc00\"}"), Refused),
        case("fleet_anchor holding 1e400", add_field(&min_t, "\"fleet_anchor\":{\"x\":1e400}"), Refused),
        case("fleet_anchor holding a 400-digit integer", add_field(&min_t, &format!("\"fleet_anchor\":{{\"x\":1{}}}", "0".repeat(400))), Refused),
        case("fleet_anchor nested 126 deep", add_field(&min_t, &format!("\"fleet_anchor\":{}", nested(126))), Exit(20)),
        case("fleet_anchor nested 127 deep", add_field(&min_t, &format!("\"fleet_anchor\":{}", nested(127))), Refused),
        // binary64's edge: refused only when the literal rounds to infinity
        case("fleet_anchor holding 1.7976931348623158e308, which rounds to f64::MAX", fleet_x("1.7976931348623158e308"), Exit(20)),
        case("fleet_anchor holding -1.7976931348623158e308", fleet_x("-1.7976931348623158e308"), Exit(20)),
        case("fleet_anchor holding 17976931348623157 and 292 zeros, which rounds to f64::MAX", fleet_x(&max_digits), Exit(20)),
        case("fleet_anchor holding 2^1024 - 2^970 - 1, the largest integer that rounds to f64::MAX", fleet_x(&below_halfway), Exit(20)),
        case("fleet_anchor holding 2^1024 - 2^970, halfway to 2^1024, which rounds to infinity", fleet_x(&halfway), Refused),
        case("fleet_anchor holding 1.7976931348623159e308, which rounds to infinity", fleet_x("1.7976931348623159e308"), Refused),
        case("fleet_anchor holding 1e309", fleet_x("1e309"), Refused),
        // More than 800 digits before the point: Go's strconv.ParseFloat
        // keeps 800 and once read 1 + 800 zeros + e-491 (1e309) as 1e308.
        case("fleet_anchor holding 1, 800 zeros, e-491 (1e309)", fleet_x(&format!("1{}e-491", "0".repeat(800))), Refused),
        case("fleet_anchor holding 1, 900 zeros, .0e-591 (1e309)", fleet_x(&format!("1{}.0e-591", "0".repeat(900))), Refused),
        case("fleet_anchor holding 1, 800 zeros, e-493 (1e307)", fleet_x(&format!("1{}e-493", "0".repeat(800))), Exit(20)),
        // ---- hex case (P3)
        case("checkpoint root_hash in uppercase, signed over its bytes", text(&upper_root), Exit(40)),
        case("receipt root_hash in uppercase, signed as written, does not count", text(&upper_receipt_root), Exit(10)).dir("corpus", 2),
        case("receipt witness_pubkey in uppercase, signed as written, counts", text(&upper_receipt_witness), Exit(0)).dir("corpus", 2),
        case("trusted directory pubkey in uppercase", base_t.clone(), Exit(0)).dir("upper", 2),
        case("identity and signer_pubkey in uppercase, signed as written; native and C2SP receipts count", text(&upper_signer), Exit(0)).dir("corpus", 2),
        case("key binding identity_pubkey in uppercase", text(&upper_binding), Exit(20)),
    ]);
    let mut pinned = case(
        "identity in uppercase, pinned in lowercase",
        text(&upper_signer),
        Exit(20),
    );
    pinned.expected_identity = Some(id.clone());
    cases.push(pinned);
    let mut head = case("known head root in uppercase", base_t.clone(), Exit(20));
    head.known_heads = vec![format!(
        "2:{}",
        hex::encode(root_of(&leaves[..2])).to_uppercase()
    )];
    cases.push(head);

    // ---- the other inputs a verifier reads: at most 1000 deep, each
    // counted from its own top-level value, wherever the nesting is
    let corpus_directory = WitnessDirectory {
        witnesses: vec![entry(0, k.witness_hex(0)), entry(1, k.witness_hex(1))],
    };
    let dir_t = serde_json::to_string(&corpus_directory).unwrap();
    let entries_t = serde_json::to_string(&corpus_directory.witnesses).unwrap();
    // Revoked between leaf 0 and leaf 1 of "valid": leaves 1 and 2 no
    // longer verify, so a verifier that read the statement says INVALID.
    let revoked_at = T0 + 500;
    let reason = "corpus 17 inputs";
    let revocation = RevocationStatement {
        identity_pubkey: id.clone(),
        as_of_ms: revoked_at,
        as_of_index: None,
        reason: reason.into(),
        signature: hex::encode(
            k.identity
                .sign(&revocation_message(
                    &k.identity.verifying_key().to_bytes(),
                    revoked_at,
                    None,
                    reason,
                ))
                .to_bytes(),
        ),
    };
    assert!(revocation.verify().is_ok());
    let rev_t = serde_json::to_string(&revocation).unwrap();
    let proof_t = serde_json::to_string(&equivocation(&k.identity)).unwrap();
    let wrapped = |proof: &str| {
        format!("{{\"observed_unix\":1700000100,\"kind\":\"equivocation\",\"proof\":{proof}}}")
    };
    let wrapped_t = wrapped(&proof_t);
    let deep = |n: usize| format!("\"zz\":{}", nested(n));
    let in_string = format!("\"zz\":\"\\\"{}\"", "[".repeat(1001));
    // [entry 0, entry 1 with the member]
    let bare_entries = |m: &str| format!("{},{m}}}]", &entries_t[..entries_t.len() - 2]);
    let rev_array = |m: &str| format!("[{}]", add_field(&rev_t, m));
    use Input::{Directory, Evidence, Revocations};
    let inputs = vec![
        input("a trusted directory with an unknown member nested to depth 1000, the limit", Directory, add_field(&dir_t, &deep(999)), Exit(0)),
        input("a trusted directory with an unknown member nested to depth 1001", Directory, add_field(&dir_t, &deep(1000)), Refused),
        input("a trusted directory with an unknown member of objects nested to depth 1001", Directory, add_field(&dir_t, &format!("\"zz\":{}", objects(1000))), Refused),
        input("a trusted directory as a bare array, an entry's unknown member nested to depth 1000", Directory, bare_entries(&deep(998)), Exit(0)),
        input("a trusted directory as a bare array, an entry's unknown member nested to depth 1001", Directory, bare_entries(&deep(999)), Refused),
        input("a trusted directory nested 100000 deep", Directory, add_field(&dir_t, &deep(100_000)), Refused),
        input("a trusted directory with 1001 brackets in a string after an escaped quote", Directory, add_field(&dir_t, &in_string), Exit(0)),
        input("a revocation statement with an unknown member nested to depth 1000, the limit", Revocations, add_field(&rev_t, &deep(999)), Exit(40)),
        input("a revocation statement with an unknown member nested to depth 1001", Revocations, add_field(&rev_t, &deep(1000)), Refused),
        input("an array of revocation statements, one with an unknown member nested to depth 1000", Revocations, rev_array(&deep(998)), Exit(40)),
        input("an array of revocation statements, one with an unknown member nested to depth 1001", Revocations, rev_array(&deep(999)), Refused),
        input("a revocation statement nested 100000 deep", Revocations, add_field(&rev_t, &deep(100_000)), Refused),
        input("a revocation statement with 1001 brackets in a string after an escaped quote", Revocations, add_field(&rev_t, &in_string), Exit(40)),
        input("an evidence item as witness serve writes it, an unknown member nested to depth 1000, the limit", Evidence, add_field(&wrapped_t, &deep(999)), Exit(30)),
        input("an evidence item as witness serve writes it, an unknown member nested to depth 1001", Evidence, add_field(&wrapped_t, &deep(1000)), Refused),
        input("an evidence item whose proof has an unknown member nested to depth 1000", Evidence, wrapped(&add_field(&proof_t, &deep(998))), Exit(30)),
        input("an evidence item whose proof has an unknown member nested to depth 1001", Evidence, wrapped(&add_field(&proof_t, &deep(999))), Refused),
        input("a bare equivocation proof with an unknown member nested to depth 1000", Evidence, add_field(&proof_t, &deep(999)), Exit(30)),
        input("a bare equivocation proof with an unknown member nested to depth 1001", Evidence, add_field(&proof_t, &deep(1000)), Refused),
        input("an evidence item nested 100000 deep", Evidence, add_field(&wrapped_t, &deep(100_000)), Refused),
        input("an evidence item with 1001 brackets in a string after an escaped quote", Evidence, add_field(&wrapped_t, &in_string), Exit(30)),
    ];
    // ---- reading an evidence item (SPEC.md §9): of a repeated key the last
    // counts and only it is read; every other member is checked as JSON
    // syntax only; keys and the four fields have no unpaired surrogate. An
    // audit of the depth rule found the reference refusing items Go and
    // TypeScript counted, and Go and TypeScript reading null directories,
    // null revocations and the keys below differently.
    let origin_member = format!(
        "\"origin\":\"{}\"",
        canonical_origin(&k.identity.verifying_key())
    );
    let proof_rest = &proof_t[1..]; // the proof's members and its closing brace
    let item_with =
        |members: &str| format!("{{{members},\"kind\":\"equivocation\",\"proof\":{proof_t}}}");
    let mut inputs_more = vec![
        input("an evidence item with an origin beside its proof holding 1e400, ignored", Evidence, item_with("\"origin\":1e400"), Exit(30)),
        input("an evidence item with an origin beside its proof holding an unpaired surrogate escape, ignored", Evidence, item_with("\"origin\":\"\\ud800\""), Exit(30)),
        input("an evidence item with an ignored member holding 1e400", Evidence, item_with("\"x\":1e400"), Exit(30)),
        input("an evidence item with an ignored member holding an unpaired surrogate escape", Evidence, item_with("\"x\":\"\\ud800\""), Exit(30)),
        input("a bare equivocation proof whose origin is given twice, the first holding 1e400", Evidence, format!("{{\"origin\":1e400,{proof_rest}"), Exit(30)),
        input("a bare equivocation proof whose origin is given twice, the first with an unpaired surrogate escape", Evidence, format!("{{\"origin\":\"\\ud800\",{proof_rest}"), Exit(30)),
        input("an evidence item whose proof is given twice, the first an array", Evidence, format!("{{\"kind\":\"equivocation\",\"proof\":[1],\"proof\":{proof_t}}}"), Exit(30)),
        input("an evidence item whose proof is given twice, the last null", Evidence, format!("{{\"kind\":\"equivocation\",\"proof\":{proof_t},\"proof\":null}}"), Refused),
        input("a bare equivocation proof whose origin has an unpaired surrogate escape", Evidence, sub(&proof_t, &origin_member, "\"origin\":\"\\ud800\""), Refused),
        input("a bare equivocation proof with an ignored key that has an unpaired surrogate escape", Evidence, format!("{{\"\\ud800\":1,{proof_rest}"), Refused),
        input("an evidence item with a key beside its proof that has an unpaired surrogate escape", Evidence, item_with("\"\\ud800\":1"), Refused),
        input("an evidence item whose proof has a key with an unpaired surrogate escape", Evidence, wrapped(&format!("{{\"\\ud800\":1,{proof_rest}")), Refused),
        // ---- null and repeated keys in a directory or revocations file
        input("a trusted directory that is null", Directory, "null".into(), Refused),
        input("revocations that are null", Revocations, "null".into(), Refused),
        input(
            "a trusted directory with an ignored key given twice, the first copy nested to depth 1001",
            Directory,
            add_field(&add_field(&dir_t, &deep(1000)), "\"zz\":0"),
            Refused,
        ),
    ];
    let mut inputs = inputs;
    inputs.append(&mut inputs_more);

    // ---- expectations from the reference
    let mut out = Vec::new();
    let mut names = std::collections::BTreeSet::new();
    for c in &cases {
        assert!(
            names.insert(c.name.clone()),
            "duplicate case name {}",
            c.name
        );
        let expect = match Dossier::from_json(&c.text) {
            Err(_) => {
                assert_eq!(c.intended, Refused, "{}: the reference reads it", c.name);
                json!({
                    "not_a_dossier": true, "verdict": null, "exit_code": 2,
                    "split_view_unsafe": null, "internally_consistent": null, "has_failures": null,
                    "contradictions": null, "known_heads_unchecked": null,
                    "valid_receipts": null, "independent_operators": null,
                })
            }
            Ok(d) => {
                let trusted: Option<WitnessDirectory> = c
                    .directory
                    .map(|n| serde_json::from_value(directories[n].clone()).unwrap());
                let heads: Vec<KnownHead> =
                    c.known_heads.iter().map(|h| h.parse().unwrap()).collect();
                let ctx = VerifyContext {
                    expected_identity_pubkey: c.expected_identity.as_deref(),
                    trusted_directory: trusted.as_ref(),
                    min_receipts: c.min_witnesses,
                    revocations: &[],
                    known_heads: &heads,
                    evidence: &[],
                    subject_org: None,
                    accept_fleet_anchor: false,
                };
                let r = d.verify(0.66, &ctx);
                let exit_code = exit_code(&r);
                assert_eq!(
                    Exit(exit_code),
                    c.intended,
                    "{}: the reference gives exit {exit_code} ({:?})",
                    c.name,
                    r.failures
                );
                json!({
                    "not_a_dossier": false,
                    "verdict": r.verdict,
                    "exit_code": exit_code,
                    "split_view_unsafe": r.split_view_unsafe,
                    "internally_consistent": r.internally_consistent,
                    "has_failures": !r.failures.is_empty(),
                    "contradictions": r.contradictions.len(),
                    "known_heads_unchecked": r.known_heads_unchecked.len(),
                    "valid_receipts": r.quorum.as_ref().map(|q| q.valid_receipts),
                    "independent_operators": r.quorum.as_ref().map(|q| q.distinct_independent_operators),
                })
            }
        };
        out.push(json!({
            "name": c.name,
            "dossier_json": c.text,
            "directory": c.directory,
            "expected_identity": c.expected_identity,
            "threshold": 0.66,
            "min_witnesses": c.min_witnesses,
            "known_heads": c.known_heads,
            "evidence": [],
            "allow_sub_majority": false,
            "subject_org": null,
            "expect": expect,
        }));
    }

    let valid = Dossier::from_json(&base_t).unwrap();
    let mut inputs_out = Vec::new();
    for c in &inputs {
        assert!(
            names.insert(c.name.to_string()),
            "duplicate case name {}",
            c.name
        );
        let min_witnesses = (c.input == Directory).then_some(2);
        let read = match c.input {
            Directory => WitnessDirectory::from_json(&c.text).map(|d| (Some(d), vec![], vec![])),
            Revocations => revocations_from_json(&c.text).map(|r| (None, r, vec![])),
            Evidence => {
                EquivocationProof::from_evidence_json(&c.text).map(|p| (None, vec![], vec![p]))
            }
        };
        let expect = match read {
            Err(e) => {
                assert_eq!(
                    c.intended, Refused,
                    "{}: the reference refuses it: {e}",
                    c.name
                );
                // A case about nesting is refused for its depth, not for
                // something else wrong with the text.
                assert_eq!(
                    matches!(e, InputParseError::TooDeep(_)),
                    c.name.contains("nested"),
                    "{}: {e}",
                    c.name
                );
                json!({
                    "refused": true, "verdict": null, "exit_code": 2,
                    "has_failures": null, "contradictions": null, "valid_receipts": null,
                })
            }
            Ok((directory, revocations, evidence)) => {
                let ctx = VerifyContext {
                    trusted_directory: directory.as_ref(),
                    min_receipts: min_witnesses,
                    revocations: &revocations,
                    evidence: &evidence,
                    ..VerifyContext::default()
                };
                let r = valid.verify(0.66, &ctx);
                let exit_code = exit_code(&r);
                assert_eq!(
                    Exit(exit_code),
                    c.intended,
                    "{}: the reference gives exit {exit_code} ({:?})",
                    c.name,
                    r.failures
                );
                json!({
                    "refused": false,
                    "verdict": r.verdict,
                    "exit_code": exit_code,
                    "has_failures": !r.failures.is_empty(),
                    "contradictions": r.contradictions.len(),
                    "valid_receipts": r.quorum.as_ref().map(|q| q.valid_receipts),
                })
            }
        };
        inputs_out.push(json!({
            "name": c.name,
            "input": c.input.name(),
            "text": c.text,
            "dossier": "valid",
            "min_witnesses": min_witnesses,
            "expect": expect,
        }));
    }

    let doc = json!({
        "description": "Reading a dossier (outside review III, H2 and P3). Each case's \
            `dossier_json` is the input text, byte for byte; give it to your verifier as text. \
            The rule is the reference's (SPEC.md §9, \"Reading a dossier\"): the text is RFC 8259 \
            JSON (no byte order mark, no trailing characters) and nests at most 1000 arrays and \
            objects deep, counted outside strings with the dossier object at depth 1, wherever \
            the nesting is (an ignored key's value included); a deeper text is not a dossier, and \
            a verifier stops reading at the 1001st level; the dossier and every struct in it (checkpoint, leaf, receipt, \
            directory and entry, key binding, revocation, custody threshold) is an object, never \
            an array; a key that names a field appears once, is matched exactly (case-sensitive, \
            after unescaping) and any other key is ignored, its value only checked as JSON \
            syntax; a u64 is an integer literal with no sign, fraction or exponent, at most \
            2^64 - 1 (leaf_type at most 255), read exactly, including above 2^53; a string, \
            bool or list field has that JSON type; optional fields may be absent or null, \
            defaulted ones (witness_receipts, witness_directory, key_bindings, revocations, \
            runtime, is_project_operated, custody) absent but not null; a unit enum variant is \
            its name or {\"name\": null}; a field's string and every key of a struct have no \
            unpaired surrogate escape; fleet_anchor is any JSON value whose strings have no \
            unpaired surrogate, whose numbers are finite as binary64 once rounded to nearest, \
            ties to even (1.7976931348623158e308 and 2^1024 - 2^970 - 1 are; \
            1.7976931348623159e308 and 2^1024 - 2^970 are not) and which nests at most 126 deep \
            below the dossier object. `not_a_dossier` true: the reference cannot deserialise the text; a CLI \
            exits 2, a library refuses it (Rust's Dossier::from_json fails; wasm, Node and Python \
            raise; Go's VerifyDossier returns Invalid with the error and no report; \
            TypeScript's verifyDossier returns INVALID, exit 40, with the reason in failures) \
            and no verifier returns any other verdict. Otherwise run the case as in \
            15_evidence_and_args.json, with the named trusted directory from `directories` \
            (none when null), expected_identity, threshold, min_witnesses and known_heads; the \
            verdict, exit code and report fields must equal expect. Hex: identity and witness \
            keys compare case-insensitively; the checkpoint's root_hash is compared, as written, \
            with the lowercase hex of the rebuilt root and a receipt's root_hash with the \
            checkpoint's, both case-sensitively; every signed message covers the strings as \
            written. `inputs` holds the other JSON inputs a verifier reads, as text, under the \
            same nesting rule: a trusted directory (`input` \"directory\": {\"witnesses\": [...]} \
            or a bare array of entries, as --directory), revocations (\"revocations\": one \
            statement or an array of them, as --revocations) and an evidence item (\"evidence\": \
            a bare proof or one as `witness serve` writes it, as --evidence), each nesting at \
            most 1000 arrays and objects deep, counted outside strings from its own top-level \
            value at depth 1, wherever the nesting is. Verify the dossier of the case named by \
            `dossier` with that one input, min_witnesses and threshold 0.66. `refused` true: the \
            verifier refuses the input as it refuses a malformed one, and gives no verdict (a CLI \
            exits 2; Rust's WitnessDirectory::from_json, revocations_from_json and \
            EquivocationProof::from_evidence_json fail; wasm, Node and Python raise; Go's \
            ParseDirectory, ParseRevocations and ParseEvidence return an error; TypeScript's \
            verifyDossier throws a TypeError for the option); otherwise the verdict, exit code \
            and report fields must equal expect. Where one JSON text carries several inputs (an \
            array of evidence items, wasm's options object), the limit applies to each input in \
            it. An evidence item is valid UTF-8 JSON and an object: the proof, or one carrying the \
            proof under \"proof\"; of a key given twice the last counts and only it is read; every \
            other member (an earlier copy, and beside \"proof\" every member of the item) is \
            ignored, its value only checked as JSON syntax; the keys of the item and of the proof, \
            and the proof's four string fields, have no unpaired surrogate escape. A directory or \
            revocations input that is null is refused. Give each input as text: a value already \
            parsed has lost an earlier copy of a repeated key and whatever was nested under it. \
            Every key here is public and for testing only.",
        "directories": directories,
        "cases": out,
        "inputs": inputs_out,
    });
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../corpus")
        .join("17_dossier_parsing.json");
    std::fs::write(&path, serde_json::to_string_pretty(&doc).unwrap() + "\n").unwrap();
    println!("wrote {}", path.display());
}
