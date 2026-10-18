//! Generates `corpus/15_evidence_and_args.json`: verdict cases for the
//! inputs a verifier brings rather than the dossier it checks, where the
//! three verifiers (this reference, Go, TypeScript) once parsed differently
//! (security review of 0.5.0): evidence items as `witness serve` writes
//! them and malformed ones (F1, F5), equivocation proofs at the edges of
//! the signed-note format (F5), known heads beyond 2^53 or wrapped in
//! Unicode White_Space or a BOM (F10), and operator_org / subject_org
//! labels that differ only by Unicode whitespace or case mapping (F12).
//! Deterministic: fixed keys and Ed25519's deterministic signatures.
//!
//!   cargo run -p witness-log-network --example generate_evidence_corpus
//!
//! CI regenerates it and fails if the committed file differs. Each case
//! states the exit status it is meant to have, and this generator panics
//! if the reference disagrees, so a change of behaviour cannot slip into
//! the corpus as a regenerated expectation. Every key here is PUBLIC and
//! for conformance testing only.

use base64ct::{Base64, Encoding};
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use witness_log_core::c2sp::{canonical_origin, key_id, SIG_TYPE_ED25519};
use witness_log_core::leaf::{Leaf, LeafType};
use witness_log_core::merkle::{leaf_hash, MerkleTree};
use witness_log_core::sth::SignedTreeHead;
use witness_log_network::tlog_witness::EquivocationProof;
use witness_log_network::{
    Dossier, KnownHead, Verdict, VerifyContext, WitnessDirectory, WitnessEntry, WitnessReceipt,
    WitnessRuntime,
};

// The same identity, witnesses and dossiers as corpus 13.
const IDENTITY_SEED: [u8; 32] = [0x13; 32];
const OTHER_IDENTITY_SEED: [u8; 32] = [0x14; 32];
const T0: u64 = 1_700_000_000_000;
const EM_DASH: char = '\u{2014}';

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

fn b64(b: &[u8]) -> String {
    Base64::encode_string(b)
}

/// `n` deterministic bytes named by `label`.
fn det(label: &str, n: usize) -> Vec<u8> {
    let mut out = Vec::new();
    let mut i = 0u32;
    while out.len() < n {
        out.extend_from_slice(&Sha256::digest(format!("{label}/{i}").as_bytes()));
        i += 1;
    }
    out.truncate(n);
    out
}

/// A base64 string that decodes (leniently) to the same bytes as the
/// canonical encoding of `bytes` but sets a padding bit, so a strict
/// decoder refuses it. `bytes.len() % 3` must not be 0.
fn non_canonical_b64(bytes: &[u8]) -> String {
    const ALPHABET: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let canonical = b64(bytes);
    let data = canonical.trim_end_matches('=');
    let last = data.chars().last().unwrap();
    let flipped = ALPHABET
        .chars()
        .nth(ALPHABET.find(last).unwrap() ^ 1)
        .unwrap();
    format!(
        "{}{flipped}{}",
        &data[..data.len() - 1],
        &canonical[data.len()..]
    )
}

/// Signs C2SP checkpoint notes and builds equivocation proofs for one log
/// key under one origin, with the edits the cases need.
struct Notes {
    key: SigningKey,
    origin: String,
    id: [u8; 4],
}

impl Notes {
    fn new(key: SigningKey) -> Self {
        let origin = canonical_origin(&key.verifying_key());
        let id = key_id(&origin, SIG_TYPE_ED25519, &key.verifying_key().to_bytes());
        Self { key, origin, id }
    }

    fn vkey_with(&self, id_hex: &str, material_tail: &[u8]) -> String {
        let mut material = vec![SIG_TYPE_ED25519];
        material.extend_from_slice(&self.key.verifying_key().to_bytes());
        material.extend_from_slice(material_tail);
        format!("{}+{id_hex}+{}", self.origin, b64(&material))
    }

    fn vkey(&self) -> String {
        self.vkey_with(&hex::encode(self.id), &[])
    }

    /// A checkpoint note for (size, root) signed by the log under key ID
    /// `id`, followed by `extra` signature lines.
    fn note_with(&self, size: u64, root_b64: &str, id: [u8; 4], extra: &[String]) -> String {
        let text = format!("{}\n{size}\n{root_b64}\n", self.origin);
        let mut payload = id.to_vec();
        payload.extend_from_slice(&self.key.sign(text.as_bytes()).to_bytes());
        let mut lines = vec![format!("{EM_DASH} {} {}", self.origin, b64(&payload))];
        lines.extend(extra.iter().cloned());
        format!("{text}\n{}\n", lines.join("\n"))
    }

    fn note(&self, root: &[u8; 32], extra: &[String]) -> String {
        self.note_with(3, &b64(root), self.id, extra)
    }

    fn proof(&self, earlier: String, conflicting: String, vkey: String) -> Value {
        json!({
            "origin": self.origin,
            "log_vkey": vkey,
            "earlier_note": earlier,
            "conflicting_note": conflicting,
        })
    }
}

/// A signature line from a key nobody knows, with a well-formed payload.
fn unknown_line(name: &str, label: &str) -> String {
    format!("{EM_DASH} {name} {}", b64(&det(label, 68)))
}

struct Case {
    name: &'static str,
    dossier: &'static str,
    directory: Option<&'static str>,
    min_witnesses: Option<usize>,
    known_heads: Vec<String>,
    evidence: Vec<&'static str>,
    subject_org: Option<String>,
    /// The exit status this case is meant to have; 2 means the verifier
    /// must refuse the inputs (a usage error, or an exception from a
    /// library) rather than return a verdict.
    intended_exit: u8,
}

fn case(name: &'static str, dossier: &'static str, intended_exit: u8) -> Case {
    Case {
        name,
        dossier,
        directory: None,
        min_witnesses: None,
        known_heads: vec![],
        evidence: vec![],
        subject_org: None,
        intended_exit,
    }
}

impl Case {
    fn dir(mut self, d: &'static str) -> Self {
        self.directory = Some(d);
        self
    }
    fn min(mut self, n: usize) -> Self {
        self.min_witnesses = Some(n);
        self
    }
    fn heads(mut self, h: Vec<String>) -> Self {
        self.known_heads = h;
        self
    }
    fn ev(mut self, e: &[&'static str]) -> Self {
        self.evidence = e.to_vec();
        self
    }
    fn subject(mut self, s: &str) -> Self {
        self.subject_org = Some(s.to_string());
        self
    }
}

fn main() {
    let identity = SigningKey::from_bytes(&IDENTITY_SEED);
    let identity_hex = hex::encode(identity.verifying_key().to_bytes());

    // ---- dossiers and the trusted directory (as corpus 13)
    let witness_keys: Vec<SigningKey> = (0..4u8)
        .map(|i| SigningKey::from_bytes(&[0x20 + i; 32]))
        .collect();
    let directory_with = |orgs: [&str; 4]| WitnessDirectory {
        witnesses: witness_keys
            .iter()
            .zip(orgs)
            .enumerate()
            .map(|(i, (k, org))| WitnessEntry {
                name: format!("corpus-witness-{i}"),
                operator_org: org.to_string(),
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
        fleet_anchor: None,
    };
    let mut tampered = dossier(4);
    tampered.leaves[1].payload_hash = hex::encode([0xee; 32]);
    let dossiers = json!({
        "full": dossier(4),
        "two_of_four": dossier(2),
        "full_tampered": tampered,
    });

    // ---- trusted directories: corpus 13's, and label variants (F12) in
    // which the two cosigners of `two_of_four` (witnesses 0 and 1) carry
    // operator_org labels that differ only by Unicode whitespace or case.
    let others = ["corpus-operator-2", "corpus-operator-3"];
    let pair = |a: &str, b: &str| directory_with([a, b, others[0], others[1]]);
    let directories = json!({
        "corpus": directory_with(["corpus-operator-0", "corpus-operator-1", others[0], others[1]]),
        // Full lowercasing maps a word-final capital sigma to ς: two operators.
        "final_sigma_vs_medial": pair("\u{39f}\u{394}\u{39f}\u{3a3}", "\u{3bf}\u{3b4}\u{3bf}\u{3c3}"),
        // ... and to the same label as a lowercase final ς: one operator.
        "final_sigma_vs_final": pair("\u{39f}\u{394}\u{39f}\u{3a3}", "\u{3bf}\u{3b4}\u{3bf}\u{3c2}"),
        // U+0130 lowercases to "i" + U+0307 (SpecialCasing): one operator.
        "dotted_capital_i": pair("\u{130}NC", "i\u{307}nc"),
        // U+0085 (NEL) is White_Space: collapsed like a space. One operator.
        "nel_is_whitespace": pair("Acme\u{85}Labs", "acme labs"),
        // U+FEFF (BOM) is not White_Space: kept. Two operators.
        "bom_is_not_whitespace": pair("\u{feff}acme", "acme"),
        // U+3000 (ideographic space) is White_Space. One operator.
        "ideographic_space": pair("acme\u{3000}labs", "  ACME   LABS "),
        // For subject_org matching: witness 0 is the log's own operator.
        "subject_sigma": pair("\u{39f}\u{394}\u{39f}\u{3a3}", "independent-1"),
        "subject_spaces": pair("acme labs", "independent-1"),
    });
    let directory = |name: &str| -> WitnessDirectory {
        serde_json::from_value(directories[name].clone()).unwrap()
    };

    // ---- evidence items (F1, F5)
    let log = Notes::new(identity.clone());
    let other = Notes::new(SigningKey::from_bytes(&OTHER_IDENTITY_SEED));
    let r1: [u8; 32] = Sha256::digest(b"history A").into();
    let r2: [u8; 32] = Sha256::digest(b"history B").into();
    let bare = log.proof(log.note(&r1, &[]), log.note(&r2, &[]), log.vkey());
    let lines = |n: usize| -> Vec<String> {
        (0..n)
            .map(|i| unknown_line(&format!("other.example/w{i}"), &format!("u{i}")))
            .collect()
    };
    let with = |edit: &dyn Fn(&mut Value)| {
        let mut p = bare.clone();
        edit(&mut p);
        p
    };
    let zero_id = [0u8; 4];
    let id_hex = hex::encode(log.id);
    let evidence = json!({
        // F1: the forms an evidence file comes in.
        "bare": bare,
        "wrapped": {"observed_unix": 1_700_000_100u64, "kind": "equivocation", "proof": bare},
        "wrapped_other_identity": {"observed_unix": 1_700_000_100u64, "kind": "equivocation",
            "proof": other.proof(other.note(&r1, &[]), other.note(&r2, &[]), other.vkey())},
        "wrapped_proof_null": {"kind": "equivocation", "proof": null},
        "array": [log.origin, log.vkey(), log.note(&r1, &[]), log.note(&r2, &[])],
        "wrapped_array": {"kind": "equivocation",
            "proof": [log.origin, log.vkey(), log.note(&r1, &[]), log.note(&r2, &[])]},
        "missing_log_vkey": with(&|p| { p.as_object_mut().unwrap().remove("log_vkey"); }),
        "number_origin": with(&|p| p["origin"] = json!(5)),
        "null_note": with(&|p| p["earlier_note"] = Value::Null),
        "string_item": "not a proof",
        "null_item": null,
        // F5: signed-note edges. Signature-line limit is 64.
        "lines_64": with(&|p| p["earlier_note"] = json!(log.note(&r1, &lines(63)))),
        "lines_65": with(&|p| p["earlier_note"] = json!(log.note(&r1, &lines(64)))),
        "lines_70_both": with(&|p| {
            p["earlier_note"] = json!(log.note(&r1, &lines(69)));
            p["conflicting_note"] = json!(log.note(&r2, &lines(69)));
        }),
        // The key ID is computed from the origin and key, never read from the file.
        "vkey_wrong_key_id": with(&|p| p["log_vkey"] = json!(log.vkey_with("00000000", &[]))),
        "vkey_and_lines_bogus_key_id": with(&|p| {
            p["log_vkey"] = json!(log.vkey_with("00000000", &[]));
            p["earlier_note"] = json!(log.note_with(3, &b64(&r1), zero_id, &[]));
            p["conflicting_note"] = json!(log.note_with(3, &b64(&r2), zero_id, &[]));
        }),
        "vkey_key_id_not_hex": with(&|p| p["log_vkey"] = json!(log.vkey_with(&format!("g{}", &id_hex[1..]), &[]))),
        "vkey_key_id_uppercase": with(&|p| p["log_vkey"] = json!(log.vkey_with(&id_hex.to_uppercase(), &[]))),
        "vkey_trailing_byte": with(&|p| p["log_vkey"] = json!(log.vkey_with(&id_hex, &[0]))),
        "vkey_empty": with(&|p| p["log_vkey"] = json!("")),
        // A key name with '+' or a Unicode space makes the note malformed,
        // known key or not; U+FEFF and U+007F are not spaces.
        "unknown_name_plus": with(&|p| p["earlier_note"] = json!(log.note(&r1, &[unknown_line("a+b", "p")]))),
        "unknown_name_nbsp": with(&|p| p["earlier_note"] = json!(log.note(&r1, &[unknown_line("a\u{a0}b", "n")]))),
        "unknown_name_ideographic_space": with(&|p| p["earlier_note"] = json!(log.note(&r1, &[unknown_line("a\u{3000}b", "i")]))),
        "unknown_name_bom": with(&|p| p["earlier_note"] = json!(log.note(&r1, &[unknown_line("a\u{feff}b", "b")]))),
        "unknown_name_del": with(&|p| p["earlier_note"] = json!(log.note(&r1, &[unknown_line("a\u{7f}b", "d")]))),
        // Base64 is strict: one value, one encoding.
        "unknown_line_non_canonical_base64": with(&|p| p["earlier_note"] = json!(log.note(&r1,
            &[format!("{EM_DASH} other.example/x {}", non_canonical_b64(&det("nc", 70)))]))),
        "root_non_canonical_base64": with(&|p| p["conflicting_note"] = json!(log.note_with(3, &non_canonical_b64(&r2), log.id, &[]))),
        "duplicate_log_signature": with(&|p| {
            let n = log.note(&r1, &[]);
            let sig_line = n.split("\n\n").nth(1).unwrap().trim_end().to_string();
            p["earlier_note"] = json!(log.note(&r1, &[sig_line]));
        }),
    });

    // ---- known heads (F10)
    let prefix_root_2 = hex::encode(root_of(&leaves[..2]));
    let wrong = hex::encode([0xab; 32]);
    let heads = [
        format!("9007199254740993:{wrong}"),
        format!("18446744073709551615:{wrong}"),
        format!("18446744073709551616:{wrong}"),
        format!("\u{feff}2:{prefix_root_2}"),
        format!("2:{prefix_root_2}\u{feff}"),
        format!("\u{85}2\u{3000}:\u{a0}{wrong}\u{85}"),
        format!("+2:{prefix_root_2}"),
        format!("2:{wrong}"),
        format!("\u{2028}2:{prefix_root_2}\u{2029}"),
    ];
    let hs = |i: &[usize]| -> Vec<String> { i.iter().map(|&k| heads[k].clone()).collect() };

    let cases: Vec<Case> = vec![
        // F1
        case("bare proof", "full", 30).ev(&["bare"]),
        case("proof as witness serve writes it", "full", 30).ev(&["wrapped"]),
        case("wrapped proof beats WITNESSED", "full", 30)
            .dir("corpus")
            .ev(&["wrapped"]),
        case(
            "wrapped proof about another identity is ignored",
            "full",
            20,
        )
        .ev(&["wrapped_other_identity"]),
        case(
            "wrapped proof is not checked for an invalid dossier",
            "full_tampered",
            40,
        )
        .ev(&["wrapped"]),
        case("wrapped proof that is null is refused", "full", 2).ev(&["wrapped_proof_null"]),
        case("evidence item that is an array is refused", "full", 2).ev(&["array"]),
        case("wrapped proof that is an array is refused", "full", 2).ev(&["wrapped_array"]),
        case("proof without log_vkey is refused", "full", 2).ev(&["missing_log_vkey"]),
        case("proof with a numeric origin is refused", "full", 2).ev(&["number_origin"]),
        case("proof with a null note is refused", "full", 2).ev(&["null_note"]),
        case("evidence item that is a string is refused", "full", 2).ev(&["string_item"]),
        case("evidence item that is null is refused", "full", 2).ev(&["null_item"]),
        case(
            "a refused item refuses the run even beside a good one",
            "full",
            2,
        )
        .ev(&["wrapped", "array"]),
        // F5
        case("64 signature lines (the limit)", "full", 30).ev(&["lines_64"]),
        case("65 signature lines", "full", 20).ev(&["lines_65"]),
        case("70 signature lines in both notes", "full", 20).ev(&["lines_70_both"]),
        case("log_vkey key ID wrong, signature lines right", "full", 20).ev(&["vkey_wrong_key_id"]),
        case(
            "log_vkey and signature lines share a bogus key ID",
            "full",
            20,
        )
        .ev(&["vkey_and_lines_bogus_key_id"]),
        case("log_vkey key ID not hex", "full", 20).ev(&["vkey_key_id_not_hex"]),
        case("log_vkey key ID in uppercase hex", "full", 30).ev(&["vkey_key_id_uppercase"]),
        case("log_vkey with a trailing key byte", "full", 20).ev(&["vkey_trailing_byte"]),
        case("empty log_vkey", "full", 20).ev(&["vkey_empty"]),
        case("unknown signature line, '+' in its name", "full", 20).ev(&["unknown_name_plus"]),
        case("unknown signature line, U+00A0 in its name", "full", 20).ev(&["unknown_name_nbsp"]),
        case("unknown signature line, U+3000 in its name", "full", 20)
            .ev(&["unknown_name_ideographic_space"]),
        case("unknown signature line, U+FEFF in its name", "full", 30).ev(&["unknown_name_bom"]),
        case("unknown signature line, U+007F in its name", "full", 30).ev(&["unknown_name_del"]),
        case(
            "unknown signature line with non-canonical base64",
            "full",
            20,
        )
        .ev(&["unknown_line_non_canonical_base64"]),
        case("root hash in non-canonical base64", "full", 20).ev(&["root_non_canonical_base64"]),
        case("the log's signature line twice", "full", 30).ev(&["duplicate_log_signature"]),
        // F10
        case("known head above 2^53 is unchecked", "full", 20).heads(hs(&[0])),
        case("known head at 2^64-1 is unchecked", "full", 20).heads(hs(&[1])),
        case("known head above 2^64-1 is refused", "full", 2).heads(hs(&[2])),
        case("known head with a BOM before it is refused", "full", 2).heads(hs(&[3])),
        case("known head with a BOM after it is refused", "full", 2).heads(hs(&[4])),
        case(
            "known head in U+0085, U+3000 and U+00A0 is read",
            "full",
            30,
        )
        .heads(hs(&[5])),
        case("known head in U+2028 and U+2029 is read", "full", 20).heads(hs(&[8])),
        case("known head with a '+' sign is refused", "full", 2).heads(hs(&[6])),
        case("unchecked huge head beside a contradicted one", "full", 30).heads(hs(&[0, 7])),
        // F12: operator counting
        case(
            "final sigma: ΟΔΟΣ and οδοσ are two operators",
            "two_of_four",
            11,
        )
        .dir("final_sigma_vs_medial")
        .min(2),
        case(
            "final sigma: ΟΔΟΣ and οδος are one operator",
            "two_of_four",
            10,
        )
        .dir("final_sigma_vs_final")
        .min(2),
        case("U+0130 lowercases to i + U+0307", "two_of_four", 10)
            .dir("dotted_capital_i")
            .min(2),
        case("U+0085 is whitespace in a label", "two_of_four", 10)
            .dir("nel_is_whitespace")
            .min(2),
        case("U+FEFF is not whitespace in a label", "two_of_four", 11)
            .dir("bom_is_not_whitespace")
            .min(2),
        case("U+3000 is whitespace in a label", "two_of_four", 10)
            .dir("ideographic_space")
            .min(2),
        // F12: subject_org matching
        case("subject_org οδος names ΟΔΟΣ", "two_of_four", 10)
            .dir("subject_sigma")
            .min(2)
            .subject("\u{3bf}\u{3b4}\u{3bf}\u{3c2}"),
        case("subject_org οδοσ does not name ΟΔΟΣ", "two_of_four", 11)
            .dir("subject_sigma")
            .min(2)
            .subject("\u{3bf}\u{3b4}\u{3bf}\u{3c3}"),
        case("subject_org with U+0085 names it", "two_of_four", 10)
            .dir("subject_spaces")
            .min(2)
            .subject("ACME\u{85}LABS"),
        case("subject_org with U+3000 names it", "two_of_four", 10)
            .dir("subject_spaces")
            .min(2)
            .subject("\u{3000}Acme\u{3000}Labs"),
        case(
            "subject_org with U+FEFF does not name it",
            "two_of_four",
            11,
        )
        .dir("subject_spaces")
        .min(2)
        .subject("\u{feff}acme labs"),
    ];

    let by_name = |n: &str| -> Dossier { serde_json::from_value(dossiers[n].clone()).unwrap() };
    let mut out_cases = Vec::new();
    for c in &cases {
        let known: Result<Vec<KnownHead>, String> =
            c.known_heads.iter().map(|h| h.parse()).collect();
        let proofs: Result<Vec<EquivocationProof>, String> = c
            .evidence
            .iter()
            .map(|k| EquivocationProof::from_evidence(&evidence[*k]))
            .collect();
        let expect = match (known, proofs) {
            (Ok(known), Ok(proofs)) => {
                let trusted = c.directory.map(directory);
                let ctx = VerifyContext {
                    expected_identity_pubkey: None,
                    trusted_directory: trusted.as_ref(),
                    min_receipts: c.min_witnesses,
                    revocations: &[],
                    known_heads: &known,
                    evidence: &proofs,
                    subject_org: c.subject_org.as_deref(),
                    accept_fleet_anchor: false,
                };
                let r = by_name(c.dossier).verify(0.66, &ctx);
                let exit_code = if r.split_view_unsafe {
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
                json!({
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
            _ => json!({
                "verdict": null,
                "exit_code": 2,
                "split_view_unsafe": null,
                "internally_consistent": null,
                "has_failures": null,
                "contradictions": null,
                "known_heads_unchecked": null,
                "valid_receipts": null,
                "independent_operators": null,
            }),
        };
        assert_eq!(
            expect["exit_code"],
            json!(c.intended_exit),
            "{}: the reference no longer gives the intended exit",
            c.name
        );
        out_cases.push(json!({
            "name": c.name,
            "dossier": c.dossier,
            "directory": c.directory,
            "expected_identity": null,
            "threshold": 0.66,
            "min_witnesses": c.min_witnesses,
            "known_heads": c.known_heads,
            "evidence": c.evidence,
            "allow_sub_majority": false,
            "subject_org": c.subject_org,
            "expect": expect,
        }));
    }

    let doc = json!({
        "description": "Verification vector for the inputs a verifier brings (security review \
            of 0.5.0: F1, F5, F10, F12). Run every case through your verifier as for \
            13_verdicts.json, with the named dossier, the named trusted directory from \
            `directories` (none when null), threshold, min_witnesses, known_heads, subject_org \
            and the named evidence items, passed as the raw JSON values under `evidence`. An \
            evidence item is a JSON object: the proof itself, or the proof under \"proof\" as \
            `witness serve` writes it; the proof is an object whose origin, log_vkey, \
            earlier_note and conflicting_note are strings. An equivocation proof verifies only \
            under the verifier key built from its canonical origin (key ID included); its notes \
            are c2sp.org/signed-note with at most 64 signature lines, strict base64, and key \
            names that are non-empty with no '+' and no Unicode White_Space (a line breaking \
            this makes the note malformed, known key or not). A known head's size is any u64 \
            and surrounding Unicode White_Space is ignored (U+FEFF is not White_Space). Labels \
            (operator_org, subject_org) are compared after splitting on Unicode White_Space, \
            joining with one space and Unicode full default lowercasing (SpecialCasing, \
            Final_Sigma included). exit_code 2 means the verifier must refuse the inputs (the \
            CLI's usage error, an exception from a library) instead of returning a verdict; \
            the other expect fields are then null. Otherwise the verdict, exit code and report \
            fields must equal expect, as in 13_verdicts.json. Every key here is public and for \
            testing only.",
        "identity_pubkey": identity_hex,
        "directories": directories,
        "dossiers": dossiers,
        "evidence": evidence,
        "cases": out_cases,
    });

    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../corpus")
        .join("15_evidence_and_args.json");
    std::fs::write(&path, serde_json::to_string_pretty(&doc).unwrap() + "\n").unwrap();
    println!("wrote {}", path.display());
}
