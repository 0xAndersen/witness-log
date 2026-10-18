//! RFC-0001, **experimental**: fleet checkpoint log anchors.
//!
//! An organisation runs one append-only log (origin such as
//! `example.com/witness-log/fleet`) whose entries are the signed C2SP
//! checkpoint notes of its agents' logs. Ordinary `c2sp.org/tlog-witness`
//! witnesses cosign that one log instead of every agent's. A dossier then
//! carries a [`FleetAnchor`]: the agent's checkpoint note as appended, an
//! RFC 6962 inclusion proof, and the fleet log's checkpoint note with its
//! cosignature lines.
//!
//! Nothing here is read unless the verifier opts in
//! ([`crate::VerifyContext::accept_fleet_anchor`]); without the opt-in a
//! dossier verifies exactly as it would without the field. With it, the
//! anchor can only *add* cosigners: a fleet anchor that fails any check is
//! reported in [`FleetAnchorReport::failures`] and contributes nothing. It
//! never makes a verdict INVALID, since anyone holding the dossier could
//! strip the field and get the same result without it.
//!
//! What the fleet path proves less well than direct witnessing: a witness
//! that cosigns the fleet log commits to the fleet log's head, not to the
//! agent's. It refuses a fork of the fleet log, but it does not look inside
//! entries, so two conflicting checkpoints of one agent can both be
//! appended (the fleet log refuses that itself, but the fleet log is run by
//! the agent's own organisation). Equivocation is then recorded and
//! findable, not refused by an independent party. That is why fleet
//! cosigners never count toward `split_view_resistant`, and why the report
//! says `witnessed_via`.
//!
//! The fleet log's own signature on its checkpoint is not checked here,
//! because no key for it is a trust input: a trusted witness's cosignature
//! signs the exact checkpoint body (origin, size, root), and a conforming
//! witness cosigns a body only after verifying it under the key it was
//! configured with for that origin and only if it extends what it cosigned
//! before. See RFC-0001's "Decisions in the 0.6.0 prototype".

use base64ct::{Base64, Encoding};
use serde::{Deserialize, Serialize};
use witness_log_core::c2sp::{
    canonical_origin, key_id, Checkpoint, Cosignature, SignedNote, VerifierKey,
    CANONICAL_ORIGIN_PREFIX, SIG_TYPE_COSIGNATURE_V1,
};
use witness_log_core::merkle::{leaf_hash, verify_inclusion, Hash};
use witness_log_core::sth::SignedTreeHead;

use crate::{normalize_hex, WitnessDirectory};

/// Largest `entry_bytes` (the agent's checkpoint note) accepted. A
/// witness-log checkpoint note with its one signature is under 300 bytes.
pub const MAX_FLEET_ENTRY_BYTES: usize = 4096;

/// Largest checkpoint body (text before the signatures) accepted for the
/// agent's note and the fleet checkpoint: the same bound a witness applies
/// ([`crate::tlog_witness::MAX_CHECKPOINT_TEXT_BYTES`]).
pub const MAX_FLEET_NOTE_TEXT_BYTES: usize = crate::tlog_witness::MAX_CHECKPOINT_TEXT_BYTES;

/// Largest `fleet_checkpoint_note` accepted, signature lines included.
pub const MAX_FLEET_NOTE_BYTES: usize = 64 * 1024;

/// Most signature lines accepted on the fleet checkpoint note.
pub const MAX_FLEET_NOTE_SIGNATURES: usize = 64;

/// Most inclusion-proof hashes accepted (a tree of 2^64 leaves needs 64).
pub const MAX_INCLUSION_PROOF_HASHES: usize = 64;

/// The dossier field (RFC-0001): where this dossier's checkpoint sits in a
/// fleet checkpoint log, and that log's cosigned checkpoint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(remote = "Self")]
pub struct FleetAnchor {
    /// The fleet log's C2SP origin, e.g. `example.com/witness-log/fleet`.
    pub origin: String,
    /// Index of the agent's entry in the fleet log.
    pub entry_index: u64,
    /// The agent's checkpoint note, exactly as appended, standard base64.
    pub entry_bytes_b64: String,
    /// RFC 6962 inclusion proof of `SHA256(0x00 || entry_bytes)` at
    /// `entry_index` under the root in `fleet_checkpoint_note`; hex hashes,
    /// innermost first (the order `MerkleTree::inclusion_proof` produces).
    pub inclusion_proof: Vec<String>,
    /// The fleet log's checkpoint note (`c2sp.org/tlog-checkpoint`) with
    /// the witnesses' `cosignature/v1` lines.
    pub fleet_checkpoint_note: String,
}

witness_log_core::object_only_serde!(FleetAnchor);

/// `Dossier::fleet_anchor` as read from JSON: the field parsed, or, when it
/// does not have the [`FleetAnchor`] shape, the raw value kept as it was.
///
/// A malformed field must not stop a dossier from parsing: a verifier that
/// has not opted in ignores the field entirely, exactly as a verifier
/// predating it does. With the opt-in, a malformed field is a failed
/// anchor, reported and not counted.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum FleetAnchorField {
    Parsed(FleetAnchor),
    Malformed(serde_json::Value),
}

impl FleetAnchorField {
    /// The anchor, if the field has the expected shape.
    pub fn parsed(&self) -> Option<&FleetAnchor> {
        match self {
            Self::Parsed(a) => Some(a),
            Self::Malformed(_) => None,
        }
    }
}

impl From<FleetAnchor> for FleetAnchorField {
    fn from(a: FleetAnchor) -> Self {
        Self::Parsed(a)
    }
}

/// What the verifier did with a dossier's fleet anchor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FleetAnchorStatus {
    /// The caller did not opt in (`accept_fleet_anchor` false): the field
    /// was not read beyond its origin and index.
    Ignored,
    /// The entry is this checkpoint and is included in the fleet
    /// checkpoint; cosignatures on it from the trusted directory count.
    Verified,
    /// A check failed (see `failures`); the anchor contributes nothing.
    Failed,
}

/// Report on a dossier's fleet anchor. Present in `DossierReport` only
/// when the dossier carries one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FleetAnchorReport {
    pub status: FleetAnchorStatus,
    /// The fleet origin the anchor names (absent if the field is malformed).
    pub origin: Option<String>,
    pub entry_index: Option<u64>,
    /// Size of the fleet checkpoint the entry was proven against; only for
    /// a verified anchor.
    pub fleet_tree_size: Option<u64>,
    /// Why the anchor failed, one entry per failed check; empty otherwise.
    /// The wording is not normative.
    pub failures: Vec<String>,
}

/// Which path the counted witness keys of a WITNESSED verdict came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WitnessedVia {
    /// Every counted witness key has a valid direct receipt.
    Direct,
    /// No counted witness key has a direct receipt: all came from
    /// cosignatures on the fleet checkpoint.
    Fleet,
    /// Some counted keys only cosigned the fleet checkpoint, others
    /// cosigned this log directly.
    Both,
}

/// Distinct trusted witness keys, and the distinct independent operators
/// among them, on one path.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct PathCount {
    pub witnesses: usize,
    pub independent_operators: usize,
}

/// Per-path counts, present in `DossierReport` only when the caller opted
/// in. `quorum` counts the union with each witness key once.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct WitnessPaths {
    /// Direct receipts (the only path that counts toward
    /// `split_view_resistant`).
    pub direct: PathCount,
    /// Cosignatures on the fleet checkpoint.
    pub fleet: PathCount,
    /// Witness keys that are on both paths (counted once).
    pub on_both: usize,
}

/// What a fleet anchor that passed every check contributes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedFleetAnchor {
    pub fleet_tree_size: u64,
    /// `(witness key, lowercase hex; witnessed_at_ms)` for every cosignature
    /// line on the fleet checkpoint that verified under a key in the
    /// trusted directory, in note order. Empty without a directory.
    pub cosigners: Vec<(String, u64)>,
}

/// The leaf hash a fleet log appends for an entry: `SHA256(0x00 || entry)`.
pub fn fleet_entry_leaf_hash(entry_bytes: &[u8]) -> Hash {
    leaf_hash(entry_bytes)
}

/// A fleet origin is a C2SP origin (non-empty; no space, `+` or control
/// character) that is not a witness-log agent origin: cosignatures under
/// an agent's own canonical origin are direct receipts, not a fleet path.
pub fn valid_fleet_origin(origin: &str) -> bool {
    !origin.is_empty()
        && origin.len() <= 255
        && !origin.starts_with(CANONICAL_ORIGIN_PREFIX)
        && origin
            .chars()
            .all(|c| c != ' ' && c != '+' && !c.is_control())
}

/// Standard base64 with padding, in its one canonical spelling.
pub fn decode_canonical_base64(s: &str) -> Option<Vec<u8>> {
    let bytes = Base64::decode_vec(s).ok()?;
    (Base64::encode_string(&bytes) == s).then_some(bytes)
}

/// The agent's checkpoint, as an entry of a fleet log must carry it: a
/// signed note with no extension lines, whose origin is the canonical
/// origin of `identity` and which verifies under that key. Shared by the
/// verifier (step 2) and `witness-log fleet serve`, which refuses any
/// other entry.
pub fn agent_checkpoint_from_entry(
    entry_bytes: &[u8],
    identity: &ed25519_dalek::VerifyingKey,
) -> Result<Checkpoint, String> {
    if entry_bytes.len() > MAX_FLEET_ENTRY_BYTES {
        return Err(format!(
            "entry is larger than {MAX_FLEET_ENTRY_BYTES} bytes"
        ));
    }
    let text = std::str::from_utf8(entry_bytes).map_err(|_| "entry is not UTF-8".to_string())?;
    let note = SignedNote::parse(text).map_err(|e| format!("entry is not a signed note: {e}"))?;
    if note.text.len() > MAX_FLEET_NOTE_TEXT_BYTES {
        return Err(format!(
            "entry checkpoint body is larger than {MAX_FLEET_NOTE_TEXT_BYTES} bytes"
        ));
    }
    let cp =
        Checkpoint::from_note(&note).map_err(|e| format!("entry is not a checkpoint note: {e}"))?;
    if !cp.extensions.is_empty() {
        return Err("entry checkpoint has extension lines".to_string());
    }
    let origin = canonical_origin(identity);
    if cp.origin != origin {
        return Err(format!(
            "entry is a checkpoint of {}, not of this identity ({origin})",
            cp.origin
        ));
    }
    note.verify(&[VerifierKey::for_ed25519(&origin, identity)])
        .map_err(|e| format!("entry is not signed by this identity: {e}"))?;
    Ok(cp)
}

/// RFC-0001 steps 2–4 for one anchor against the dossier's own checkpoint
/// (step 1, everything a dossier is checked for without the anchor, is
/// `Dossier::verify`'s). `Err` lists why the anchor does not count.
///
/// 2. `entry_bytes` is a checkpoint note for the identity that signed
///    `checkpoint`, at its tree size and root, signed by that identity.
/// 3. The inclusion proof of `SHA256(0x00 || entry_bytes)` at
///    `entry_index` verifies under the fleet checkpoint's root.
/// 4. Each cosignature line on the fleet checkpoint whose key name and key
///    ID match a key in `directory` and which verifies (`cosignature/v1`
///    over the fleet checkpoint body) is a cosigner. Other lines, including
///    the fleet log's own signature, are ignored.
pub fn verify_fleet_anchor(
    anchor: &FleetAnchor,
    checkpoint: &SignedTreeHead,
    directory: Option<&WitnessDirectory>,
) -> Result<VerifiedFleetAnchor, Vec<String>> {
    let fail = |m: String| Err(vec![m]);
    if !valid_fleet_origin(&anchor.origin) {
        return fail(format!(
            "fleet origin {:?} is not a fleet log origin (a C2SP origin that is not witness-log/...)",
            anchor.origin
        ));
    }

    // Step 2: the entry is this checkpoint.
    let Some(identity) = hex::decode(&checkpoint.signer_pubkey)
        .ok()
        .and_then(|b| <[u8; 32]>::try_from(b).ok())
        .and_then(|b| ed25519_dalek::VerifyingKey::from_bytes(&b).ok())
    else {
        return fail("the checkpoint's signer_pubkey is not an Ed25519 key".to_string());
    };
    let Some(entry_bytes) = decode_canonical_base64(&anchor.entry_bytes_b64) else {
        return fail("entry_bytes_b64 is not canonical standard base64".to_string());
    };
    let entry = match agent_checkpoint_from_entry(&entry_bytes, &identity) {
        Ok(cp) => cp,
        Err(e) => return fail(e),
    };
    let root: Option<[u8; 32]> = hex::decode(&checkpoint.root_hash)
        .ok()
        .and_then(|b| b.try_into().ok());
    if entry.tree_size != checkpoint.tree_size || Some(entry.root_hash) != root {
        return fail(format!(
            "the entry commits to size {} root {}, not this checkpoint (size {} root {}){}",
            entry.tree_size,
            hex::encode(entry.root_hash),
            checkpoint.tree_size,
            checkpoint.root_hash,
            if entry.tree_size == checkpoint.tree_size {
                ": this identity signed two different roots for one size"
            } else {
                ""
            }
        ));
    }

    // Step 3: the entry is in the fleet checkpoint.
    if anchor.fleet_checkpoint_note.len() > MAX_FLEET_NOTE_BYTES {
        return fail(format!(
            "fleet_checkpoint_note is larger than {MAX_FLEET_NOTE_BYTES} bytes"
        ));
    }
    let note = match SignedNote::parse(&anchor.fleet_checkpoint_note) {
        Ok(n) => n,
        Err(e) => return fail(format!("fleet_checkpoint_note is not a signed note: {e}")),
    };
    if note.text.len() > MAX_FLEET_NOTE_TEXT_BYTES
        || note.signatures.len() > MAX_FLEET_NOTE_SIGNATURES
    {
        return fail("fleet_checkpoint_note is larger than a witness accepts".to_string());
    }
    let fleet = match Checkpoint::from_note(&note) {
        Ok(c) => c,
        Err(e) => return fail(format!("fleet_checkpoint_note is not a checkpoint: {e}")),
    };
    if fleet.origin != anchor.origin {
        return fail(format!(
            "the fleet checkpoint is for origin {:?}, not {:?}",
            fleet.origin, anchor.origin
        ));
    }
    if anchor.inclusion_proof.len() > MAX_INCLUSION_PROOF_HASHES {
        return fail("inclusion_proof is longer than any tree needs".to_string());
    }
    let mut proof: Vec<Hash> = Vec::with_capacity(anchor.inclusion_proof.len());
    for h in &anchor.inclusion_proof {
        match hex::decode(h)
            .ok()
            .and_then(|b| <[u8; 32]>::try_from(b).ok())
        {
            Some(b) => proof.push(b),
            None => {
                return fail("inclusion_proof holds a value that is not 32 bytes of hex".into())
            }
        }
    }
    if anchor.entry_index >= fleet.tree_size {
        return fail(format!(
            "entry_index {} is not inside the fleet checkpoint (size {})",
            anchor.entry_index, fleet.tree_size
        ));
    }
    if !verify_inclusion(
        &fleet_entry_leaf_hash(&entry_bytes),
        anchor.entry_index,
        fleet.tree_size,
        &proof,
        &fleet.root_hash,
    ) {
        return fail(format!(
            "the inclusion proof for entry {} does not verify under the fleet checkpoint's root",
            anchor.entry_index
        ));
    }

    // Step 4: cosignatures from the trusted directory.
    let mut cosigners = Vec::new();
    if let Some(dir) = directory {
        for sig in &note.signatures {
            for w in &dir.witnesses {
                let Some(pk) = hex::decode(&w.pubkey)
                    .ok()
                    .and_then(|b| <[u8; 32]>::try_from(b).ok())
                    .and_then(|b| ed25519_dalek::VerifyingKey::from_bytes(&b).ok())
                else {
                    continue;
                };
                if key_id(&sig.key_name, SIG_TYPE_COSIGNATURE_V1, &pk.to_bytes()) != sig.key_id {
                    continue;
                }
                let Ok(cos) = Cosignature::from_note_signature(sig) else {
                    continue;
                };
                let vkey = VerifierKey::for_cosignature(&sig.key_name, &pk);
                if cos.verify(&vkey, &note.text).is_ok() {
                    cosigners.push((normalize_hex(&w.pubkey), cos.timestamp.saturating_mul(1000)));
                }
            }
        }
    }
    Ok(VerifiedFleetAnchor {
        fleet_tree_size: fleet.tree_size,
        cosigners,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{WitnessEntry, WitnessRuntime};
    use ed25519_dalek::SigningKey;
    use witness_log_core::c2sp::NoteSignature;
    use witness_log_core::merkle::MerkleTree;

    struct Fixture {
        identity: SigningKey,
        checkpoint: SignedTreeHead,
        entry: String,
        fleet_key: SigningKey,
        tree: MerkleTree,
        witnesses: Vec<SigningKey>,
        directory: WitnessDirectory,
    }

    const FLEET: &str = "fleet.example/witness-log/fleet";

    fn agent_note(identity: &SigningKey, size: u64, root: [u8; 32]) -> String {
        Checkpoint {
            origin: canonical_origin(&identity.verifying_key()),
            tree_size: size,
            root_hash: root,
            extensions: vec![],
        }
        .sign(identity)
        .unwrap()
        .encode()
        .unwrap()
    }

    fn fixture() -> Fixture {
        let identity = SigningKey::from_bytes(&[1; 32]);
        let root = [7u8; 32];
        let checkpoint = SignedTreeHead::sign(&identity, 5, &root, 1_000);
        let entry = agent_note(&identity, 5, root);
        let mut tree = MerkleTree::new();
        for i in 0..5u8 {
            if i == 2 {
                tree.append(fleet_entry_leaf_hash(entry.as_bytes()));
            } else {
                let other = SigningKey::from_bytes(&[100 + i; 32]);
                tree.append(fleet_entry_leaf_hash(
                    agent_note(&other, 1, [i; 32]).as_bytes(),
                ));
            }
        }
        let witnesses: Vec<SigningKey> = (0..3u8)
            .map(|i| SigningKey::from_bytes(&[50 + i; 32]))
            .collect();
        let directory = WitnessDirectory {
            witnesses: witnesses
                .iter()
                .enumerate()
                .map(|(i, k)| WitnessEntry {
                    name: format!("w{i}"),
                    operator_org: format!("org {i}"),
                    url: "https://w.example".into(),
                    pubkey: hex::encode(k.verifying_key().to_bytes()).to_uppercase(),
                    runtime: WitnessRuntime::Human,
                    compute_provider: None,
                    is_project_operated: false,
                })
                .collect(),
        };
        Fixture {
            identity,
            checkpoint,
            entry,
            fleet_key: SigningKey::from_bytes(&[9; 32]),
            tree,
            witnesses,
            directory,
        }
    }

    impl Fixture {
        fn anchor(&self, cosigners: &[usize]) -> FleetAnchor {
            let cp = Checkpoint {
                origin: FLEET.into(),
                tree_size: self.tree.size(),
                root_hash: self.tree.root(),
                extensions: vec![],
            };
            let mut note = cp.sign(&self.fleet_key).unwrap();
            for &i in cosigners {
                let c = Cosignature::sign(
                    &format!("w{i}.example/witness"),
                    &self.witnesses[i],
                    1_700_000_000 + i as u64,
                    &note.text,
                );
                note.signatures.push(c.to_note_signature());
            }
            FleetAnchor {
                origin: FLEET.into(),
                entry_index: 2,
                entry_bytes_b64: Base64::encode_string(self.entry.as_bytes()),
                inclusion_proof: self
                    .tree
                    .inclusion_proof(2, self.tree.size())
                    .unwrap()
                    .iter()
                    .map(hex::encode)
                    .collect(),
                fleet_checkpoint_note: note.encode().unwrap(),
            }
        }
    }

    #[test]
    fn a_cosigned_anchor_verifies_and_names_its_cosigners() {
        let f = fixture();
        let v = verify_fleet_anchor(&f.anchor(&[0, 2]), &f.checkpoint, Some(&f.directory)).unwrap();
        assert_eq!(v.fleet_tree_size, 5);
        let keys: Vec<String> = v.cosigners.iter().map(|(k, _)| k.clone()).collect();
        assert_eq!(
            keys,
            vec![
                hex::encode(f.witnesses[0].verifying_key().to_bytes()),
                hex::encode(f.witnesses[2].verifying_key().to_bytes())
            ]
        );
        assert_eq!(v.cosigners[1].1, 1_700_000_002_000);
        // Without a directory the entry and proof still check; nothing counts.
        let v = verify_fleet_anchor(&f.anchor(&[0, 2]), &f.checkpoint, None).unwrap();
        assert!(v.cosigners.is_empty());
    }

    #[test]
    fn a_cosigner_outside_the_directory_and_a_bad_line_do_not_count() {
        let f = fixture();
        let mut a = f.anchor(&[0]);
        let mut note = SignedNote::parse(&a.fleet_checkpoint_note).unwrap();
        // A stranger's valid cosignature.
        let stranger = SigningKey::from_bytes(&[77; 32]);
        note.signatures
            .push(Cosignature::sign("stranger", &stranger, 1, &note.text).to_note_signature());
        // Witness 1's cosignature over a different body.
        note.signatures.push(
            Cosignature::sign("w1.example/witness", &f.witnesses[1], 1, "other\n")
                .to_note_signature(),
        );
        // Witness 2's line with a corrupted signature.
        let mut bad = Cosignature::sign("w2.example/witness", &f.witnesses[2], 1, &note.text)
            .to_note_signature();
        bad.signature[20] ^= 1;
        note.signatures.push(bad);
        a.fleet_checkpoint_note = note.encode().unwrap();
        let v = verify_fleet_anchor(&a, &f.checkpoint, Some(&f.directory)).unwrap();
        assert_eq!(v.cosigners.len(), 1);
    }

    #[test]
    fn every_broken_part_fails_the_anchor() {
        let f = fixture();
        let good = f.anchor(&[0, 1]);
        let check = |a: &FleetAnchor, cp: &SignedTreeHead, want: &str| {
            let e = verify_fleet_anchor(a, cp, Some(&f.directory)).unwrap_err();
            assert!(e[0].contains(want), "{e:?} should mention {want:?}");
        };
        // Step 2: a different root at the same size (validly signed).
        let mut a = good.clone();
        a.entry_bytes_b64 = Base64::encode_string(agent_note(&f.identity, 5, [8; 32]).as_bytes());
        check(&a, &f.checkpoint, "two different roots");
        // Step 2: another identity's checkpoint.
        let mut a = good.clone();
        a.entry_bytes_b64 = Base64::encode_string(
            agent_note(&SigningKey::from_bytes(&[2; 32]), 5, [7; 32]).as_bytes(),
        );
        check(&a, &f.checkpoint, "not of this identity");
        // Step 2: this identity's origin, signed by someone else.
        let mut a = good.clone();
        let mut forged = SignedNote::parse(&f.entry).unwrap();
        forged.signatures = vec![NoteSignature {
            key_name: canonical_origin(&f.identity.verifying_key()),
            key_id: forged.signatures[0].key_id,
            signature: vec![0; 64],
        }];
        a.entry_bytes_b64 = Base64::encode_string(forged.encode().unwrap().as_bytes());
        check(&a, &f.checkpoint, "not signed by this identity");
        // Step 2: non-canonical base64.
        let mut a = good.clone();
        a.entry_bytes_b64.push('\n');
        check(&a, &f.checkpoint, "base64");
        // Step 3: wrong index, tampered proof, wrong origin.
        let mut a = good.clone();
        a.entry_index = 3;
        check(&a, &f.checkpoint, "does not verify");
        let mut a = good.clone();
        a.entry_index = 5;
        check(&a, &f.checkpoint, "not inside");
        let mut a = good.clone();
        a.inclusion_proof[0] = hex::encode([0u8; 32]);
        check(&a, &f.checkpoint, "does not verify");
        let mut a = good.clone();
        a.origin = "other.example/witness-log/fleet".into();
        check(&a, &f.checkpoint, "not \"other.example");
        let mut a = good.clone();
        a.origin = canonical_origin(&f.identity.verifying_key());
        check(&a, &f.checkpoint, "not a fleet log origin");
        // A checkpoint the entry does not match (size).
        let other = SignedTreeHead::sign(&f.identity, 6, &[7; 32], 1_000);
        check(&good, &other, "not this checkpoint");
    }

    #[test]
    fn the_field_parses_leniently_and_round_trips() {
        let f = fixture();
        let a = f.anchor(&[0]);
        let v = serde_json::to_value(FleetAnchorField::from(a.clone())).unwrap();
        let back: FleetAnchorField = serde_json::from_value(v.clone()).unwrap();
        assert_eq!(back.parsed(), Some(&a));
        assert_eq!(serde_json::to_value(&back).unwrap(), v);
        for raw in [
            serde_json::json!({"origin": 5}),
            serde_json::json!("not an object"),
            serde_json::json!([1, 2]),
        ] {
            let m: FleetAnchorField = serde_json::from_value(raw.clone()).unwrap();
            assert_eq!(m, FleetAnchorField::Malformed(raw.clone()));
            assert_eq!(serde_json::to_value(&m).unwrap(), raw);
        }
    }
}
