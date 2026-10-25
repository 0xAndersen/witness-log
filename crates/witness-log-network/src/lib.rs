//! Witness protocol.
//!
//! A witness is an outsider that periodically fetches an agent's current
//! checkpoint (Signed Tree Head), signs "I saw this," and publishes that
//! receipt somewhere the log operator cannot reach or rewrite. Once an
//! independent party has recorded yesterday's root, a rewritten history
//! can't retroactively match it.
//!
//! **The honest limitation, stated up front:** this only works if the
//! witnesses are actually independent of the thing they're witnessing. A
//! quorum of witnesses all operated by the same party is not a quorum, it's
//! the same party signing twice. This module refuses to hide that behind a
//! bare pass/fail — `evaluate_quorum` always returns an operator-diversity
//! breakdown alongside the count, and callers should treat a low-diversity
//! quorum as weak evidence, not as "verified."
//!
//! See GOVERNANCE.md for how the witness directory itself is meant to be
//! curated by a body independent of any single implementation, not by this
//! project.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use thiserror::Error;
pub mod fleet;
pub mod tlog_witness;

use witness_log_core::identity::{KeyBindingStatement, RevocationStatement};
use witness_log_core::leaf::Leaf;
use witness_log_core::merkle::{leaf_hash, MerkleTree};
use witness_log_core::sth::{SignedTreeHead, WriteReceipt};

#[derive(Debug, Error)]
pub enum WitnessError {
    #[error("invalid witness signature")]
    InvalidSignature,
    #[error("malformed key or signature bytes")]
    Malformed,
    #[error("receipt does not match the checkpoint it claims to witness")]
    Mismatch,
}

/// An entry in a witness directory: who is running this witness, and what
/// their public key is. `operator_org` is the primary field diversity
/// scoring keys off of — two witnesses with the same `operator_org` count
/// as one for diversity purposes, regardless of how many keys that
/// operator holds.
///
/// `runtime` and `compute_provider` capture a *second* independence axis,
/// specific to automated witnesses: an org running three witness agents
/// all on the same model/inference provider is not as independent as three
/// witnesses spread across distinct providers, even if the org itself is
/// the same or different in each case. Both axes are scored separately in
/// `evaluate_quorum` — see its doc comment for why they aren't collapsed
/// into one number.
///
/// Serialized as a JSON object with these fields in this order, and read
/// only from an object, never from an array of the field values. `runtime`,
/// `compute_provider` and `is_project_operated` may be absent (their
/// defaults: human, none, false).
#[derive(Debug, Clone)]
pub struct WitnessEntry {
    pub name: String,
    pub operator_org: String,
    pub url: String,
    pub pubkey: String, // hex
    pub runtime: WitnessRuntime,
    /// Free-text identifier of the underlying compute/model stack this
    /// witness runs on (e.g. "anthropic-api", "openai-api",
    /// "self-hosted-llama-3", "human-manual"). `None` when not disclosed.
    /// Used only for the runtime-diversity axis, never required.
    pub compute_provider: Option<String>,
    /// True if this witness is operated by the same party that maintains
    /// the WitnessLog project itself, rather than a genuinely third-party
    /// operator. This exists specifically for network bootstrapping: a
    /// brand-new witness network has no independent operators yet, and
    /// refusing to start until some appear is how protocols never launch.
    /// Project-run witnesses are a legitimate way to prove the mechanism
    /// works and give real third parties something functioning to join —
    /// see GOVERNANCE.md's bootstrap section.
    ///
    /// The one non-negotiable rule: this flag must be set honestly, and
    /// `evaluate_quorum` treats every witness sharing it as `true` as ONE
    /// combined entity for diversity purposes, regardless of how many
    /// individually-keyed witnesses exist under it or how their
    /// `operator_org` values are labeled. Ten project-run witnesses must
    /// score identically to one, on both diversity axes. A dossier or
    /// dashboard MUST surface this flag directly wherever quorum results
    /// are shown, not just leave it discoverable in the raw directory —
    /// see `QuorumResult::project_operated_receipts`.
    pub is_project_operated: bool,
}

/// The serde shape of [`WitnessEntry`]; see `witness_log_core::object_only`
/// for why it is a separate, private type.
#[derive(Serialize, Deserialize)]
#[serde(remote = "WitnessEntry", rename = "WitnessEntry")]
struct WitnessEntryDef {
    name: String,
    operator_org: String,
    url: String,
    pubkey: String,
    #[serde(default)]
    runtime: WitnessRuntime,
    #[serde(default)]
    compute_provider: Option<String>,
    #[serde(default)]
    is_project_operated: bool,
}

witness_log_core::object_only_serde!(WitnessEntry, WitnessEntryDef);

/// Whether a witness is operated by a human process (a person or team
/// manually or semi-manually running the check) or an autonomous agent
/// polling and signing on a loop. Neither is inherently more trustworthy —
/// see THREAT_MODEL.md — but they fail differently (humans fail slowly and
/// visibly; agent loops can fail silently and identically across many
/// instances if they share a common bug or provider outage), so directories
/// and verifiers may reasonably want to see the mix, not just the count.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum WitnessRuntime {
    #[default]
    Human,
    Agent,
}

/// A witness directory: `{"witnesses": [...]}`, read only from an object.
#[derive(Debug, Clone, Default)]
pub struct WitnessDirectory {
    pub witnesses: Vec<WitnessEntry>,
}

/// The serde shape of [`WitnessDirectory`]; see `witness_log_core::object_only`.
#[derive(Serialize, Deserialize)]
#[serde(remote = "WitnessDirectory", rename = "WitnessDirectory")]
struct WitnessDirectoryDef {
    witnesses: Vec<WitnessEntry>,
}

witness_log_core::object_only_serde!(WitnessDirectory, WitnessDirectoryDef);

/// Internal sentinel used to collapse every project-operated witness into
/// a single bucket for diversity purposes, regardless of what individual
/// `operator_org` or `compute_provider` values they're labeled with. This
/// is what makes `is_project_operated`'s guarantee real rather than
/// aspirational — see that field's doc comment.
/// Minimum distinct independent (non-project-operated) operators required
/// for `Verdict::Witnessed`.
///
/// Two is the floor at which equivocation becomes detectable at all: a
/// single operator cannot contradict itself, so a divergence is only
/// visible once two parties who do not share an operator have each
/// committed to a head. This is deliberately a floor and not a
/// recommendation — set `WitnessPolicy::min_independent_operators`
/// higher for anything consequential.
pub const MIN_INDEPENDENT_OPERATORS_FOR_WITNESSED: usize = 2;

impl WitnessEntry {
    /// A witness run by a genuinely independent third party.
    ///
    /// Prefer this and [`project_operated`](Self::project_operated) over
    /// building the struct by hand. The struct form puts
    /// `is_project_operated: false` in every copied example, and that
    /// flag is the one field whose honesty the entire diversity model
    /// depends on — a newcomer should never be typing it, they should be
    /// choosing a constructor whose name says what they are declaring.
    ///
    /// `pubkey` is the witness's hex-encoded Ed25519 public key.
    /// `compute_provider` is optional but strongly encouraged — leaving
    /// it `None` is scored as its own low-diversity bucket, never as
    /// neutral, so disclosing honestly is always at least as good as
    /// not disclosing.
    pub fn independent(
        name: impl Into<String>,
        operator_org: impl Into<String>,
        url: impl Into<String>,
        pubkey: impl Into<String>,
        compute_provider: Option<String>,
    ) -> Self {
        Self {
            name: name.into(),
            operator_org: operator_org.into(),
            url: url.into(),
            pubkey: pubkey.into(),
            runtime: WitnessRuntime::Human,
            compute_provider,
            is_project_operated: false,
        }
    }

    /// A witness run by the party that maintains this project, declared
    /// honestly as such.
    ///
    /// Every witness created this way collapses into ONE diversity bucket
    /// on both axes, regardless of how `operator_org` or
    /// `compute_provider` are labeled. That is the point: project-run
    /// witnesses prove the mechanism works and give real third parties
    /// something functioning to join, but ten of them must never score
    /// like ten independent operators. See GOVERNANCE.md.
    pub fn project_operated(
        name: impl Into<String>,
        url: impl Into<String>,
        pubkey: impl Into<String>,
        compute_provider: Option<String>,
    ) -> Self {
        Self {
            name: name.into(),
            operator_org: "project-operated".into(),
            url: url.into(),
            pubkey: pubkey.into(),
            runtime: WitnessRuntime::Agent,
            compute_provider,
            is_project_operated: true,
        }
    }

    /// Mark this witness as an autonomous agent rather than a human-run
    /// service. Informational; affects no trust decision.
    pub fn as_agent(mut self) -> Self {
        self.runtime = WitnessRuntime::Agent;
        self
    }
}

const PROJECT_OPERATED_BUCKET: &str = "\0witness-log-project-operated\0";

/// Case-insensitive hex comparison. Pubkey/hash comparisons throughout this
/// crate previously used a raw `String` `==`, so a directory entry with
/// uppercase hex silently scored zero diversity against lowercase receipt
/// keys (or vice versa) despite being the same key. See the pre-launch
/// review, finding 03's sidenote.
fn normalize_hex(s: &str) -> String {
    s.to_ascii_lowercase()
}

/// Normalize an operator or compute-provider label for bucketing.
///
/// Diversity scoring groups witnesses by these labels, and
/// `distinct_independent_operators` gates `Verdict::Witnessed`. That
/// makes the label the cheapest attack surface in the whole system: an
/// operator who runs many witnesses can inflate apparent independence
/// with nothing but the shift key, no extra infrastructure and no
/// forged signatures.
///
/// Measured before this existed: 100 witnesses under a single operator,
/// labeled with case and whitespace variants of one name, scored as
/// SEVEN independent operators — a 7x inflation of the security
/// parameter. See `tests/sybil_and_soak.rs`.
///
/// Normalization is deliberately conservative: trim, lowercase, and
/// collapse internal whitespace runs. Over-collapsing would be worse
/// than the bug, because it would silently merge genuinely independent
/// operators and suppress real diversity.
///
/// **Known limitation, not solved here:** Unicode homoglyphs. A Cyrillic
/// "а" (U+0430) in "аcme" is a different codepoint from Latin "a" and
/// will still bucket separately. Defending that properly needs a
/// confusables table (UTS #39), which is a dependency and a maintenance
/// commitment this crate hasn't taken on. Directory curators should
/// treat visually-identical operator names from different parties as a
/// review item — see GOVERNANCE.md on who curates directories.
/// Public so that every surface that compares or cleans an operator label
/// (the MCP server, the proxy, the CLI's notes) uses this exact rule rather
/// than its own language's idea of whitespace and case: Python's
/// `str.split` also splits on U+001C..U+001F and JavaScript's `\s` also
/// matches U+FEFF, and either difference let an operator's own witnesses
/// count as independent again (audit of the subject_org surfaces, 0.6.2).
pub fn normalize_label(s: &str) -> String {
    s.split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_lowercase()
}

fn operator_key(w: &WitnessEntry) -> String {
    if w.is_project_operated {
        PROJECT_OPERATED_BUCKET.to_string()
    } else {
        normalize_label(&w.operator_org)
    }
}

fn compute_provider_key(w: &WitnessEntry) -> Option<String> {
    if w.is_project_operated {
        Some(PROJECT_OPERATED_BUCKET.to_string())
    } else {
        // Same normalization as operator labels: four spellings of one
        // cloud provider must not look like provider diversity, or a
        // single-provider outage reads as a diverse quorum.
        w.compute_provider.as_deref().map(normalize_label)
    }
}

impl WitnessDirectory {
    pub fn distinct_operator_count(&self) -> usize {
        self.witnesses
            .iter()
            .map(operator_key)
            .collect::<HashSet<_>>()
            .len()
    }

    /// Distinct compute providers, including an "undisclosed" bucket for
    /// witnesses that didn't say — non-disclosure is scored as its own
    /// low-diversity bucket rather than being invisible, so it can never
    /// look better than it is by simply omitting the field.
    pub fn distinct_compute_provider_count(&self) -> usize {
        self.witnesses
            .iter()
            .map(|w| compute_provider_key(w).unwrap_or_else(|| "undisclosed".to_string()))
            .collect::<HashSet<_>>()
            .len()
    }
}

/// A witness's signed attestation that it observed a specific checkpoint at
/// a specific time. Serialized as a JSON object with these fields in this
/// order (`c2sp_origin` and `witness_name` only when set), and read only
/// from an object, never from an array of the field values.
#[derive(Debug, Clone)]
pub struct WitnessReceipt {
    pub witness_pubkey: String, // hex
    pub tree_size: u64,
    pub root_hash: String, // hex, copied from the STH being witnessed
    pub witnessed_at_ms: u64,
    pub signature: String, // hex
    /// Present when this receipt is a `c2sp.org/tlog-cosignature` from a
    /// `tlog-witness` witness rather than a native receipt. Then
    /// `signature` is over `cosignature/v1\ntime <witnessed_at_ms/1000>\n`
    /// followed by the C2SP checkpoint `<origin>\n<size>\n<base64 root>\n`,
    /// and `origin` must be the log identity's
    /// [`canonical_origin`](witness_log_core::c2sp::canonical_origin).
    /// Absent (and not serialized) for native receipts, so pre-existing
    /// dossiers are byte-identical.
    pub c2sp_origin: Option<String>,
    /// The directory `name` of the witness that issued this receipt, as
    /// the submitting client knew it (`witness.example/w1`). Display
    /// only: a reader of the dossier sees who cosigned without joining
    /// against a directory by key. Never part of any signature and never
    /// consulted by `verify` or `evaluate_quorum`, which match receipts to
    /// a trusted directory by `witness_pubkey` alone. Absent (and not
    /// serialized) when unknown, so dossiers from before 0.4.0 and
    /// receipts without a name are byte-identical to what they were.
    pub witness_name: Option<String>,
}

/// The serde shape of [`WitnessReceipt`]; see `witness_log_core::object_only`.
#[derive(Serialize, Deserialize)]
#[serde(remote = "WitnessReceipt", rename = "WitnessReceipt")]
struct WitnessReceiptDef {
    witness_pubkey: String,
    tree_size: u64,
    root_hash: String,
    witnessed_at_ms: u64,
    signature: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    c2sp_origin: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    witness_name: Option<String>,
}

witness_log_core::object_only_serde!(WitnessReceipt, WitnessReceiptDef);

impl WitnessReceipt {
    pub fn sign(witness_key: &SigningKey, sth: &SignedTreeHead, witnessed_at_ms: u64) -> Self {
        let witness_pubkey = hex::encode(witness_key.verifying_key().to_bytes());
        let msg = receipt_message(
            &witness_pubkey,
            &sth.signer_pubkey,
            sth.tree_size,
            &sth.root_hash,
            witnessed_at_ms,
        );
        let signature = witness_key.sign(&msg);
        Self {
            witness_pubkey,
            tree_size: sth.tree_size,
            root_hash: sth.root_hash.clone(),
            witnessed_at_ms,
            signature: hex::encode(signature.to_bytes()),
            c2sp_origin: None,
            witness_name: None,
        }
    }

    /// Attach the witness's directory name (display only; see
    /// [`witness_name`](Self::witness_name)).
    pub fn with_witness_name(mut self, name: impl Into<String>) -> Self {
        self.witness_name = Some(name.into());
        self
    }

    pub fn verify(&self, against: &SignedTreeHead) -> Result<(), WitnessError> {
        if self.tree_size != against.tree_size || self.root_hash != against.root_hash {
            return Err(WitnessError::Mismatch);
        }
        if let Some(origin) = &self.c2sp_origin {
            return self.verify_c2sp(origin, against);
        }
        let pk_bytes: [u8; 32] = hex::decode(&self.witness_pubkey)
            .map_err(|_| WitnessError::Malformed)?
            .try_into()
            .map_err(|_| WitnessError::Malformed)?;
        let pk = VerifyingKey::from_bytes(&pk_bytes).map_err(|_| WitnessError::Malformed)?;
        let sig_bytes: [u8; 64] = hex::decode(&self.signature)
            .map_err(|_| WitnessError::Malformed)?
            .try_into()
            .map_err(|_| WitnessError::Malformed)?;
        let signature = Signature::from_bytes(&sig_bytes);
        // witness_pubkey and the log's own signer_pubkey are now covered by
        // the signature -- previously a receipt attested only to a
        // (size, root) pair with no statement about whose key witnessed it
        // or whose log it was, both attacker-mutable with no cryptographic
        // consequence. See the pre-launch review, finding 12.
        let msg = receipt_message(
            &self.witness_pubkey,
            &against.signer_pubkey,
            self.tree_size,
            &self.root_hash,
            self.witnessed_at_ms,
        );
        pk.verify_strict(&msg, &signature)
            .map_err(|_| WitnessError::InvalidSignature)
    }

    /// Verify a receipt that carries a C2SP cosignature. Every field the
    /// verdict relies on is either covered by the witness's signature or
    /// checked against the signed checkpoint: size and root (above),
    /// origin (must be the signer's canonical origin), and time (must be
    /// whole seconds, since the cosignature signs seconds -- a sub-second
    /// `witnessed_at_ms` would be unsigned precision a verifier could be
    /// fooled by when judging freshness).
    fn verify_c2sp(&self, origin: &str, against: &SignedTreeHead) -> Result<(), WitnessError> {
        use witness_log_core::c2sp::{canonical_origin, Checkpoint, Cosignature};
        let signer: [u8; 32] = hex::decode(&against.signer_pubkey)
            .map_err(|_| WitnessError::Malformed)?
            .try_into()
            .map_err(|_| WitnessError::Malformed)?;
        let signer = VerifyingKey::from_bytes(&signer).map_err(|_| WitnessError::Malformed)?;
        if origin != canonical_origin(&signer) {
            return Err(WitnessError::Mismatch);
        }
        if self.witnessed_at_ms % 1000 != 0 {
            return Err(WitnessError::Malformed);
        }
        let root: [u8; 32] = hex::decode(&self.root_hash)
            .map_err(|_| WitnessError::Malformed)?
            .try_into()
            .map_err(|_| WitnessError::Malformed)?;
        let body = Checkpoint {
            origin: origin.to_string(),
            tree_size: self.tree_size,
            root_hash: root,
            extensions: vec![],
        }
        .note_text()
        .map_err(|_| WitnessError::Malformed)?;
        let msg = Cosignature::message(self.witnessed_at_ms / 1000, &body);
        let pk_bytes: [u8; 32] = hex::decode(&self.witness_pubkey)
            .map_err(|_| WitnessError::Malformed)?
            .try_into()
            .map_err(|_| WitnessError::Malformed)?;
        let pk = VerifyingKey::from_bytes(&pk_bytes).map_err(|_| WitnessError::Malformed)?;
        let sig: [u8; 64] = hex::decode(&self.signature)
            .map_err(|_| WitnessError::Malformed)?
            .try_into()
            .map_err(|_| WitnessError::Malformed)?;
        pk.verify_strict(msg.as_bytes(), &Signature::from_bytes(&sig))
            .map_err(|_| WitnessError::InvalidSignature)
    }
}

fn push_lp(buf: &mut Vec<u8>, bytes: &[u8]) {
    buf.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    buf.extend_from_slice(bytes);
}

fn receipt_message(
    witness_pubkey_hex: &str,
    log_signer_pubkey_hex: &str,
    tree_size: u64,
    root_hash: &str,
    witnessed_at_ms: u64,
) -> Vec<u8> {
    let mut msg = Vec::new();
    msg.extend_from_slice(b"witness-log-witness-receipt-v2");
    push_lp(&mut msg, witness_pubkey_hex.as_bytes());
    push_lp(&mut msg, log_signer_pubkey_hex.as_bytes());
    msg.extend_from_slice(&tree_size.to_be_bytes());
    push_lp(&mut msg, root_hash.as_bytes());
    msg.extend_from_slice(&witnessed_at_ms.to_be_bytes());
    msg
}

/// Outcome of evaluating a set of receipts against a checkpoint and a
/// directory. Deliberately not a bool: a caller (human or agent) should be
/// able to see *why* a quorum is or isn't trustworthy, not just whether it
/// nominally hit a threshold.
///
/// Two diversity numbers are reported, not one, and they are NOT averaged
/// or combined into a single score. Operator diversity and compute-provider
/// diversity are different failure modes — a quorum can be strong on one
/// and weak on the other — and collapsing them would let a bad result on
/// one axis hide behind a good result on the other. Callers who want a
/// single conservative number should take the minimum of the two
/// themselves, deliberately, rather than have this function decide for them.
///
/// Non-disclosure of a compute provider is scored as its own low-diversity
/// bucket, not excluded — omitting the field must never score better than
/// honestly disclosing a shared provider.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuorumResult {
    pub tree_size: u64,
    pub valid_receipts: usize,
    pub total_directory_witnesses: usize,
    pub distinct_operators_represented: usize,
    pub distinct_operators_in_directory: usize,
    /// valid_receipts / total_directory_witnesses
    pub quorum_fraction: f64,
    /// distinct_operators_represented / distinct_operators_in_directory
    pub diversity_fraction: f64,
    pub distinct_compute_providers_represented: usize,
    pub distinct_compute_providers_in_directory: usize,
    /// distinct_compute_providers_represented / distinct_compute_providers_in_directory
    pub compute_diversity_fraction: f64,
    /// How many of the VALID, signing receipts came from a witness with
    /// `is_project_operated == true`. Always populated, always shown —
    /// this is the number that keeps the bootstrap-witness case honest.
    /// A quorum that's 10/10 valid but 10/10 project-operated must be
    /// impossible to mistake for a healthy, independent quorum.
    pub project_operated_receipts: usize,
    /// Distinct operator buckets represented by counted receipts,
    /// EXCLUDING the project-operated bucket. This is the number that
    /// actually delivers equivocation resistance: a checkpoint cosigned
    /// by N genuinely independent operators is evidence against
    /// collusion among N parties, and that meaning does not change
    /// based on how many other operators happen to exist elsewhere.
    ///
    /// Prefer this over `diversity_fraction` for any trust decision.
    /// `diversity_fraction` divides by the number of distinct operators
    /// in the whole directory, so it measures *coverage of a known set*
    /// — useful to report, but it falls as the network grows. Gating a
    /// verdict on it means a larger, healthier witness network makes
    /// verification harder: at 1,000 known operators a 0.5 threshold
    /// would demand 500 cosignatures for a single checkpoint. Found by
    /// the 100-agent fleet simulation, where 5 genuinely independent
    /// operators scored 5/12 = 0.42 and could not reach `Witnessed`.
    pub distinct_independent_operators: usize,
    /// WHICH independent operators cosigned, normalized, sorted. The
    /// counts above answer "how many"; a regulator asks "who". Excludes
    /// project-operated and the subject's own operator, so its length is
    /// `distinct_independent_operators` (not `distinct_operators_represented`,
    /// which also counts the project bucket). Named `operators_represented`
    /// in 0.3.1 JSON; still accepted on input.
    #[serde(alias = "operators_represented")]
    pub independent_operators_represented: Vec<String>,
    pub meets_count_threshold: bool,
    /// Which count gate `meets_count_threshold` applied: `"fraction >= 0.66"`
    /// or `"count >= 4"`.
    #[serde(default)]
    pub count_gate: String,
    /// True when the counted receipts are a strict majority of the
    /// directory's witnesses (`2 * valid_receipts > total_directory_witnesses`).
    ///
    /// Witnessing detects equivocation only where two histories meet the
    /// same witness: a witness that has cosigned size N for one history
    /// refuses the other (422). A log that can collect a gate-satisfying
    /// set of receipts from one half of the directory and a second,
    /// disjoint set from the other half can therefore present two
    /// WITNESSED dossiers with different pasts and no witness ever sees
    /// both. A strict majority makes any two gate-satisfying sets
    /// overlap, so no such split exists among honest witnesses. The
    /// default `--threshold 0.66` has this property; a low fraction or
    /// a small `--min-witnesses` against a larger directory does not,
    /// and this flag says so. Found by an outside evaluation of 0.3.3.
    ///
    /// Only direct receipts count here. With an accepted fleet anchor
    /// (RFC-0001, experimental) `valid_receipts` includes the fleet
    /// cosigners, but a witness that cosigned the fleet log's head would
    /// not refuse a conflicting checkpoint of this log, so they do not.
    #[serde(default)]
    pub split_view_resistant: bool,
    /// The newest `witnessed_at_ms` among counted (deduplicated,
    /// trusted-directory) receipts. `None` when no receipts counted.
    ///
    /// This, not the checkpoint's own `timestamp_ms`, is the timestamp a
    /// staleness check should actually use. `checkpoint.timestamp_ms` is
    /// set and signed by the party being verified — a dishonest operator
    /// backdates or forward-dates it freely, and a staleness check
    /// against it is only as honest as that operator. Witness receipts
    /// carry `witnessed_at_ms` from independent parties (once scored
    /// against a trusted directory), which actually carries evidentiary
    /// weight. See the pre-launch review, finding 23.
    pub newest_trusted_witness_ms: Option<u64>,
}

/// Evaluate a batch of receipts against a checkpoint. `threshold_fraction`
/// is applied to *receipt count* (e.g. 2/3 = 0.667); both diversity axes
/// are reported separately and are NOT folded into the pass/fail so
/// neither can be silently hidden by a caller who only checks
/// `.meets_count_threshold`.
///
/// `directory` here MUST be a directory the caller actually trusts,
/// obtained out-of-band — never a directory read from the artifact under
/// test. See `VerifyContext` and the pre-launch review, finding 02.
pub fn evaluate_quorum(
    sth: &SignedTreeHead,
    receipts: &[WitnessReceipt],
    directory: &WitnessDirectory,
    threshold_fraction: f64,
) -> QuorumResult {
    evaluate_quorum_for_subject(sth, receipts, directory, threshold_fraction, None)
}

/// [`evaluate_quorum`] when the verifier knows which organisation operates
/// the log (`VerifyContext::subject_org`, `verify --subject-org`).
/// Witnesses with that `operator_org` count toward the receipt total but
/// never as independent: an organisation's own witness attesting to its
/// own agent's history is self-attestation. Without it the subject's
/// operator is known only when the log's key is itself listed in the
/// directory, which an ordinary agent's key is not, so an organisation
/// that runs both an agent and a witness would otherwise count as
/// independent of itself.
pub fn evaluate_quorum_for_subject(
    sth: &SignedTreeHead,
    receipts: &[WitnessReceipt],
    directory: &WitnessDirectory,
    threshold_fraction: f64,
    subject_org: Option<&str>,
) -> QuorumResult {
    score_attestations(
        sth,
        direct_attestations(sth, receipts),
        directory,
        threshold_fraction,
        subject_org,
    )
    .0
}

/// Which path a verified attestation came by: a direct receipt on this
/// log's checkpoint, or a cosignature on a fleet checkpoint that includes
/// it (RFC-0001, experimental).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AttestationPath {
    Direct,
    Fleet,
}

/// One witness key's verified statement: (lowercase key hex, witnessed_at_ms, path).
type Attestation = (String, u64, AttestationPath);

/// The receipts that verify against `sth`, in order.
fn direct_attestations<'a>(
    sth: &'a SignedTreeHead,
    receipts: &'a [WitnessReceipt],
) -> impl Iterator<Item = Attestation> + 'a {
    receipts.iter().filter(|r| r.verify(sth).is_ok()).map(|r| {
        (
            normalize_hex(&r.witness_pubkey),
            r.witnessed_at_ms,
            AttestationPath::Direct,
        )
    })
}

/// The quorum over already-verified attestations, plus the per-path
/// counts (`fleet::WitnessPaths`). With direct attestations only this is
/// exactly what `evaluate_quorum_for_subject` has always computed.
///
/// Each witness key counts once whichever paths it is on; the first
/// attestation for a key (direct ones come first) sets its time for
/// `newest_trusted_witness_ms`. `split_view_resistant` counts only keys
/// with a direct receipt: a fleet cosignature commits the witness to the
/// fleet log's head, so it would not refuse a conflicting checkpoint of
/// this log, and the majority argument behind the flag does not hold for it.
fn score_attestations(
    sth: &SignedTreeHead,
    attestations: impl IntoIterator<Item = Attestation>,
    directory: &WitnessDirectory,
    threshold_fraction: f64,
    subject_org: Option<&str>,
) -> (QuorumResult, fleet::WitnessPaths) {
    let declared_subject = subject_org.map(normalize_label).filter(|s| !s.is_empty());
    // A witness run by the same operator as the log being witnessed
    // provides zero independence: that operator is attesting to its own
    // agent's history. If the log's own signing key appears in the
    // directory, exclude its operator from the independence count.
    //
    // Found by the 1,000-agent cohort simulation: a hyperscale operator
    // running 250 agents could cosign one of its own with 200 of the
    // others and score a nonzero independent-operator count. It did not
    // reach Witnessed only because the floor is 2 — an operator with two
    // sub-brands would have cleared it.
    let subject_operator: Option<String> = directory
        .witnesses
        .iter()
        .find(|w| normalize_hex(&w.pubkey) == normalize_hex(&sth.signer_pubkey))
        .map(operator_key);
    let mut operators = HashSet::new();
    let mut compute_providers = HashSet::new();
    // Distinct witness keys actually counted. A HashSet, not a counter:
    // Ed25519 signing is deterministic per message, but witnessed_at_ms is
    // part of the signed message, so a single witness key can trivially
    // produce many distinct, individually valid receipts for one
    // checkpoint by resigning at different timestamps. Counting receipts
    // rather than distinct keys let one witness forge an N-receipt
    // quorum. See the pre-launch review, finding 03.
    let mut counted_keys: HashSet<String> = HashSet::new();
    let mut project_operated_receipts = 0usize;
    // Distinct operators excluding the project-operated bucket. Kept
    // separately from `operators` because this is the figure trust
    // decisions use -- see QuorumResult::distinct_independent_operators.
    let mut independent_operators: HashSet<String> = HashSet::new();
    let mut newest_trusted_witness_ms: Option<u64> = None;
    // Per path: trusted keys seen on it, and the independent operators
    // among them (the same rule as `independent_operators`).
    let mut direct_keys: HashSet<String> = HashSet::new();
    let mut fleet_keys: HashSet<String> = HashSet::new();
    let mut direct_independent: HashSet<String> = HashSet::new();
    let mut fleet_independent: HashSet<String> = HashSet::new();

    for (key, witnessed_at_ms, path) in attestations {
        // Only a receipt from a key actually present in the TRUSTED
        // directory counts. Previously a receipt from a key absent from
        // the directory still incremented the valid count, which is how
        // `quorum_fraction` could exceed 1.0 -- the denominator was the
        // directory size, the numerator wasn't bounded by it.
        let Some(entry) = directory
            .witnesses
            .iter()
            .find(|w| normalize_hex(&w.pubkey) == key)
        else {
            continue;
        };
        // Normalized, because this is the set that gates the verdict.
        // Excludes the subject's own operator -- self-attestation is not
        // independence, however many keys it holds.
        let independent_op = (!entry.is_project_operated)
            .then(|| normalize_label(&entry.operator_org))
            .filter(|op| {
                subject_operator.as_deref() != Some(op.as_str())
                    && declared_subject.as_deref() != Some(op.as_str())
            });
        let (path_keys, path_independent) = match path {
            AttestationPath::Direct => (&mut direct_keys, &mut direct_independent),
            AttestationPath::Fleet => (&mut fleet_keys, &mut fleet_independent),
        };
        path_keys.insert(key.clone());
        if let Some(op) = &independent_op {
            path_independent.insert(op.clone());
        }
        if !counted_keys.insert(key) {
            continue; // already counted this witness key once
        }
        operators.insert(operator_key(entry));
        if let Some(op) = independent_op {
            independent_operators.insert(op);
        }
        compute_providers
            .insert(compute_provider_key(entry).unwrap_or_else(|| "undisclosed".to_string()));
        if entry.is_project_operated {
            project_operated_receipts += 1;
        }
        newest_trusted_witness_ms = Some(match newest_trusted_witness_ms {
            Some(existing) => existing.max(witnessed_at_ms),
            None => witnessed_at_ms,
        });
    }

    let valid = counted_keys.len();
    let total = directory.witnesses.len().max(1);
    let quorum_fraction = valid as f64 / total as f64;
    let distinct_operators_in_directory = directory.distinct_operator_count().max(1);
    let distinct_providers_in_directory = directory.distinct_compute_provider_count().max(1);
    let paths = fleet::WitnessPaths {
        direct: fleet::PathCount {
            witnesses: direct_keys.len(),
            independent_operators: direct_independent.len(),
        },
        fleet: fleet::PathCount {
            witnesses: fleet_keys.len(),
            independent_operators: fleet_independent.len(),
        },
        on_both: direct_keys.intersection(&fleet_keys).count(),
    };

    let quorum = QuorumResult {
        tree_size: sth.tree_size,
        valid_receipts: valid,
        total_directory_witnesses: directory.witnesses.len(),
        distinct_operators_represented: operators.len(),
        distinct_operators_in_directory,
        quorum_fraction,
        diversity_fraction: operators.len() as f64 / distinct_operators_in_directory as f64,
        distinct_compute_providers_represented: compute_providers.len(),
        distinct_compute_providers_in_directory: distinct_providers_in_directory,
        compute_diversity_fraction: compute_providers.len() as f64
            / distinct_providers_in_directory as f64,
        project_operated_receipts,
        distinct_independent_operators: independent_operators.len(),
        independent_operators_represented: {
            let mut v: Vec<String> = independent_operators.iter().cloned().collect();
            v.sort();
            v
        },
        meets_count_threshold: quorum_fraction >= threshold_fraction,
        count_gate: format!("fraction >= {threshold_fraction}"),
        // Direct keys only; with no fleet attestations this is `valid`.
        split_view_resistant: 2 * direct_keys.len() > directory.witnesses.len(),
        newest_trusted_witness_ms,
    };
    (quorum, paths)
}

/// The canonical offline-verifiable bundle (SPEC.md §9): leaves, a signed
/// checkpoint, and optionally witness receipts + the directory needed to
/// score them. This is the ONE definition of the dossier shape — the CLI,
/// the Python bindings, and the example generator all serialize/deserialize
/// through this type rather than each independently constructing the same
/// JSON shape by hand, which is exactly how those three would eventually
/// drift out of sync with each other and with SPEC.md.
///
/// Read a dossier from JSON text with [`Dossier::from_json`], which applies
/// all of SPEC.md §9's "Reading a dossier" rule. The `Deserialize` impl
/// applies all of it but the nesting limit: the dossier and every struct in
/// it are read only from objects, never from arrays of the field values;
/// `witness_receipts`, `witness_directory`, `key_bindings` and
/// `revocations` may be absent but not `null`; other keys are ignored.
#[derive(Debug, Clone)]
pub struct Dossier {
    pub identity_pubkey: String,
    pub leaves: Vec<Leaf>,
    pub checkpoint: SignedTreeHead,
    pub witness_receipts: Vec<WitnessReceipt>,
    pub witness_directory: WitnessDirectory,
    /// Every session-key binding covering the session keys that actually
    /// authored `leaves`. Required for a verifier to check SPEC.md §5's
    /// normative rule that leaves signed by a revoked identity's sessions
    /// after `as_of_ms` MUST be treated as untrusted — that rule was
    /// previously unimplementable: the wire format had no field to carry
    /// bindings into a dossier at all, so no verifier could ever apply
    /// it. See the pre-launch review, finding 06.
    ///
    /// Use `WitnessLog::all_bindings()` to populate this, NOT
    /// `current_binding()`. A log that has restarted holds leaves
    /// authored by session keys that no longer exist, and supplying only
    /// the current session's binding leaves those leaves uncovered —
    /// verification then reports `Invalid` (`Diverged` before 0.5.0)
    /// for an agent that merely rebooted. Binding history is persisted
    /// across snapshots and journal replays for exactly this reason.
    pub key_bindings: Vec<KeyBindingStatement>,
    /// Every revocation the identity has issued for itself.
    pub revocations: Vec<RevocationStatement>,
    /// RFC-0001, **experimental**: this checkpoint's entry in an
    /// organisation's fleet checkpoint log, with that log's cosigned
    /// checkpoint. Read only when the verifier opts in
    /// (`VerifyContext::accept_fleet_anchor`); see [`fleet`]. Absent and
    /// not serialized unless set, so dossiers without it are byte-identical
    /// to before. A field that does not have the expected shape still
    /// parses (as [`fleet::FleetAnchorField::Malformed`]), so it cannot
    /// make a dossier unreadable to a verifier that ignores it.
    pub fleet_anchor: Option<fleet::FleetAnchorField>,
}

/// The serde shape of [`Dossier`]; see `witness_log_core::object_only` for
/// why it is a separate, private type.
#[derive(Serialize, Deserialize)]
#[serde(remote = "Dossier", rename = "Dossier")]
struct DossierDef {
    identity_pubkey: String,
    leaves: Vec<Leaf>,
    checkpoint: SignedTreeHead,
    #[serde(default)]
    witness_receipts: Vec<WitnessReceipt>,
    #[serde(default)]
    witness_directory: WitnessDirectory,
    #[serde(default)]
    key_bindings: Vec<KeyBindingStatement>,
    #[serde(default)]
    revocations: Vec<RevocationStatement>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    fleet_anchor: Option<fleet::FleetAnchorField>,
}

witness_log_core::object_only_serde!(Dossier, DossierDef);

/// The deepest a dossier text may nest (SPEC.md §9, "Reading a dossier"):
/// arrays and objects, counted outside strings, the dossier object itself
/// being depth 1. A deeper text is not a dossier.
///
/// Why 1000: a dossier written by any implementation nests at most 5 deep
/// (a key binding's threshold custody), and the deepest value the reference
/// reads at all is a `fleet_anchor` 126 levels below the dossier object
/// (serde_json's recursion limit), 127 in all; corpus 17 has an ignored
/// key 201 deep. Below 1000 nothing changes. Before the limit, serde_json
/// skipped ignored keys of any depth, Go's encoding/json refused 10,000
/// levels and more, and the TypeScript parser held a frame per level until
/// it ran out of memory (outside audit of 0.6.1). 1000 is an order of
/// magnitude below Go's limit, so that limit never decides, and bounds what
/// any verifier holds while reading.
pub const MAX_DOSSIER_DEPTH: usize = 1000;

/// Why a text is not a dossier (SPEC.md §9, "Reading a dossier"). The
/// message quotes at most a bounded part of the text
/// (`witness_log_core::echo`).
#[derive(Debug, Error)]
pub enum DossierParseError {
    /// The text nests deeper than [`MAX_DOSSIER_DEPTH`]; `offset` is the
    /// byte offset of the first bracket past the limit.
    #[error("nested deeper than {MAX_DOSSIER_DEPTH} arrays and objects (at byte {offset})")]
    TooDeep { offset: usize },
    /// Not RFC 8259 JSON, or JSON without the dossier's shape.
    #[error("{}", witness_log_core::echo::bounded(&.0.to_string()))]
    Json(#[source] serde_json::Error),
}

/// The byte offset of the first `[` or `{` outside a string at which `text`
/// is nested deeper than `max`, if any. Exact for JSON; for a text that is
/// not JSON the answer does not matter, since it is refused either way.
/// One pass, no allocation, so a hostile text costs no more than its
/// length to measure.
fn json_nesting_exceeds(text: &[u8], max: usize) -> Option<usize> {
    let mut depth = 0usize;
    let mut in_string = false;
    let mut escaped = false;
    for (i, &b) in text.iter().enumerate() {
        if in_string {
            if escaped {
                escaped = false;
            } else if b == b'\\' {
                escaped = true;
            } else if b == b'"' {
                in_string = false;
            }
            continue;
        }
        match b {
            b'"' => in_string = true,
            b'[' | b'{' => {
                depth += 1;
                if depth > max {
                    return Some(i);
                }
            }
            b']' | b'}' => depth = depth.saturating_sub(1),
            _ => {}
        }
    }
    None
}

impl Dossier {
    /// Read a dossier from its JSON text as SPEC.md §9 ("Reading a
    /// dossier") says, which is how the Go and TypeScript verifiers read it
    /// too (`/corpus/17_dossier_parsing.json`): the text nests at most
    /// [`MAX_DOSSIER_DEPTH`] deep, then everything the `Deserialize` impl
    /// checks. `serde_json::from_str::<Dossier>` alone skips the depth
    /// limit; read a dossier from anywhere else with this.
    pub fn from_json(text: &str) -> Result<Self, DossierParseError> {
        if let Some(offset) = json_nesting_exceeds(text.as_bytes(), MAX_DOSSIER_DEPTH) {
            return Err(DossierParseError::TooDeep { offset });
        }
        serde_json::from_str(text).map_err(DossierParseError::Json)
    }
}

/// Five-valued verification verdict (the four of the 1F916 Agent Record
/// draft §3.6 "Anchor Rule", with DIVERGED split per RFC-0002). These are
/// not a spectrum — `unanchored` is not "almost verified." They answer
/// fundamentally different questions:
///
/// - `Witnessed`: strongest. Requires a `VerifyContext` with BOTH
///   `trusted_directory` supplied (never the dossier's own embedded
///   directory) AND, if `expected_identity_pubkey` was supplied, that it
///   matches. Valid receipts from witnesses in that trusted directory
///   come from at least `MIN_INDEPENDENT_OPERATORS_FOR_WITNESSED` (2)
///   distinct independent operators -- project-operated witnesses all
///   collapse to one bucket and the subject's own operator counts as none
///   -- and the count meets the caller's threshold.
/// - `ConsistentUnwitnessed`: crypto is solid but witness coverage is
///   absent, below threshold, or from fewer than two independent
///   operators. Depends on registry-asserted timing. Honest result; not
///   proof against a colluding operator.
/// - `Unanchored`: proofs are internally consistent but no external trust
///   input was supplied at all — no `trusted_directory`, so witness
///   receipts (even if present and individually valid) cannot be scored
///   against anything the verifier actually trusts. This proves the
///   artifact doesn't contradict itself — nothing more. A fabricated
///   dossier, complete with self-generated "witnesses" and a
///   self-authored directory, reaches this verdict and NO FURTHER: an
///   unanchored run is capped here regardless of what the dossier itself
///   claims about its own witness coverage. This is the fix for the
///   defect where a wholly fabricated dossier previously reached
///   `Witnessed` by shipping its own directory alongside its own receipts
///   — see the pre-launch review, finding 02.
/// - `Diverged` (since 0.5.0, narrowed): the dossier is internally valid
///   AND contradicts other evidence the verifier was given about the same
///   identity: a head the verifier already trusted
///   (`VerifyContext::known_heads`) that this dossier's leaves do not
///   reproduce, or a witness's equivocation proof for this identity
///   (`VerifyContext::evidence`). Divergence is a relation between two
///   histories; one file on its own cannot be DIVERGED.
/// - `Invalid` (since 0.5.0): any proof fails, any signature check fails,
///   the leaf sequence fails structural validation, a key binding or
///   revocation fails, or the dossier's claimed identity doesn't match
///   the key that actually signed the checkpoint (either the dossier's own
///   internal claim, or the caller's pinned expectation — see finding 01).
///   The file establishes nothing about the identity. Before 0.5.0 this
///   was reported as `Diverged`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    Witnessed,
    ConsistentUnwitnessed,
    Unanchored,
    Diverged,
    Invalid,
}

impl std::fmt::Display for Verdict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Witnessed => write!(f, "WITNESSED"),
            Self::ConsistentUnwitnessed => write!(f, "CONSISTENT-UNWITNESSED"),
            Self::Unanchored => write!(f, "UNANCHORED"),
            Self::Diverged => write!(f, "DIVERGED"),
            Self::Invalid => write!(f, "INVALID"),
        }
    }
}

/// External inputs a verifier controls, as distinct from anything read
/// from the dossier under test. A dossier's own `identity_pubkey` and
/// `witness_directory` fields are supplied by the party being verified —
/// trusting either of them for a verdict above `Unanchored` means the
/// artifact is grading its own homework. See the pre-launch review,
/// findings 01 and 02.
///
/// `Default` (both fields `None`) is the fully-unpinned case: the
/// resulting verdict is capped at `Unanchored`. The two fields answer
/// different questions. `trusted_directory` is what anchors a run: without
/// it no verdict above `Unanchored` is reachable, whatever receipts the
/// dossier carries. `expected_identity_pubkey` authenticates: it ties the
/// verdict to a specific party. A run with a directory but no identity
/// pin can reach `Witnessed` and proves that *some* log was cosigned by
/// independent operators, not *whose*; `DossierReport::identity_pinned`
/// records which kind of run produced a report, and any gate should pass
/// both.
#[derive(Debug, Clone, Default)]
pub struct VerifyContext<'a> {
    /// The identity this run is actually trying to confirm, obtained
    /// out-of-band (a CLI `--identity` flag, a pinned config, a prior
    /// conversation) — never read from the dossier itself. If `Some`, it
    /// MUST equal `checkpoint.signer_pubkey` (case-insensitive) or the
    /// verdict is `Diverged`.
    ///
    /// Independent of this field, `dossier.identity_pubkey` is ALWAYS
    /// checked against `checkpoint.signer_pubkey` for self-consistency —
    /// a dossier that contradicts its own identity claim is `Diverged`
    /// even with no external pin supplied. What an external pin adds is
    /// actual authentication: confirming this dossier is about the
    /// specific party the verifier expected, not merely that the dossier
    /// is honest about itself.
    pub expected_identity_pubkey: Option<&'a str>,
    /// The witness directory this verifier actually trusts, obtained
    /// out-of-band. Receipts are scored against THIS directory, never
    /// against `dossier.witness_directory` — the dossier's own directory
    /// field is retained purely for display (names/URLs to show a human
    /// alongside the report) and MUST NOT be used to compute quorum or
    /// diversity. If `None`, the verdict is capped at `Unanchored`
    /// regardless of how many receipts the dossier ships.
    pub trusted_directory: Option<&'a WitnessDirectory>,
    /// Absolute receipt-count gate. When `Some(n)`, the count gate is
    /// "at least `n` valid receipts from distinct witnesses in the trusted
    /// directory" and `threshold_fraction` is reported but not enforced.
    /// A fraction of the directory is the wrong gate once a directory is a
    /// registry of hundreds of witnesses (0.66 of 100 is 66 cosignatures
    /// per checkpoint); an absolute count plus the two-independent-operator
    /// rule is what a verifier actually means. Found by the 1,000-agent
    /// swarm against a 100-witness network.
    pub min_receipts: Option<usize>,
    /// Revocations the verifier knows about out of band (a revocation
    /// the identity's operator published, a registry entry). They are
    /// applied whether or not the dossier carries them: a dossier that
    /// omits a known revocation cannot thereby verify leaves or a
    /// checkpoint the revoked key signed after `as_of_ms`. Statements
    /// for other identities are ignored. Review round 2, W2.
    pub revocations: &'a [RevocationStatement],
    /// Heads the verifier already trusts for this identity (a receipt it
    /// kept, a cosignature it saw): `(tree_size, root)`. A dossier whose
    /// leaves do not reproduce one of these roots at that size is
    /// `Diverged`. A head larger than the dossier cannot be checked
    /// against it and is listed in `DossierReport::known_heads_unchecked`.
    /// RFC-0002.
    pub known_heads: &'a [KnownHead],
    /// Witness equivocation proofs the verifier holds. One that names this
    /// identity's canonical origin and verifies under the key that origin
    /// names makes the verdict `Diverged`, whatever the dossier says.
    /// RFC-0002.
    pub evidence: &'a [tlog_witness::EquivocationProof],
    /// The organisation that operates this log, as the verifier knows it
    /// (from the same out-of-band source as the identity). Witnesses whose
    /// `operator_org` matches it (normalized like every operator label)
    /// never count as independent operators for this dossier. `None`
    /// keeps the older rule, which can only exclude the subject's operator
    /// when the log's own key is listed in the directory.
    pub subject_org: Option<&'a str>,
    /// RFC-0001, **experimental**: score the dossier's `fleet_anchor`.
    /// `false` (the default) ignores the field entirely: the verdict and
    /// every report field are what they are without it, apart from
    /// `DossierReport::fleet_anchor` saying it was ignored.
    ///
    /// With `true`, after every other check, a fleet anchor that fully
    /// verifies ([`fleet::verify_fleet_anchor`]) adds its cosigners from
    /// `trusted_directory` to the quorum, each witness key counted once
    /// across both paths and under the same operator rules. A fleet log is
    /// run by the organisation whose agents it records, so the fleet
    /// operator's organisation is taken to be `subject_org`, and the anchor
    /// is not used without one (its own witnesses could otherwise count as
    /// independent). An anchor that fails a check is reported and adds
    /// nothing; it never lowers a verdict. Fleet cosigners never count
    /// toward `split_view_resistant`. The report then also carries
    /// `witnessed_via` and `witness_paths`.
    ///
    /// Leaving this `false` is how a verifier requires direct witnessing.
    pub accept_fleet_anchor: bool,
}

/// A head a verifier already trusts for an identity: `--known-head
/// <size>:<root hex>`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KnownHead {
    pub tree_size: u64,
    pub root_hash: [u8; 32],
}

impl std::str::FromStr for KnownHead {
    type Err = String;
    /// `<size>:<64 hex>`.
    fn from_str(s: &str) -> Result<Self, String> {
        use witness_log_core::echo::quoted;
        let (size, root) = s
            .split_once(':')
            .ok_or_else(|| format!("expected <size>:<root hex>, got {}", quoted(s)))?;
        let tree_size = witness_log_core::c2sp::parse_canonical_u64(size.trim())
            .ok_or_else(|| format!("size {} is not a canonical decimal integer", quoted(size)))?;
        let root_hash: [u8; 32] = hex::decode(root.trim())
            .ok()
            .and_then(|v| v.try_into().ok())
            .ok_or_else(|| format!("root {} is not 32 bytes of hex", quoted(root)))?;
        Ok(Self {
            tree_size,
            root_hash,
        })
    }
}

/// Everything `witness-log verify` reports, structured rather than printed —
/// callers (the CLI's text mode, its `--json` mode, or any other consumer
/// entirely, including another agent deciding whether to trust this
/// dossier) all derive their output from one shared computation instead of
/// duplicating the logic that decides what "verified" means.
#[derive(Debug, Clone, Serialize)]
pub struct DossierReport {
    pub checkpoint_signature_valid: bool,
    pub identity_bound: bool,
    pub leaves_structurally_valid: bool,
    /// Every distinct session key among `leaves` is covered by a valid,
    /// verified `KeyBindingStatement` for this identity, no leaf falls
    /// outside its binding's `not_after_ms` window, and no leaf postdates
    /// a verified revocation for this identity. Vacuously true when
    /// `leaves` is empty, and true when the dossier carries no bindings
    /// or revocations at all ("not asserted"); `bindings_asserted` tells
    /// the two apart.
    pub bindings_valid: bool,
    /// Whether the dossier carried any key bindings or revocations to
    /// check. False means `bindings_valid` is vacuous.
    pub bindings_asserted: bool,
    pub leaf_count: u64,
    pub claimed_tree_size: u64,
    pub merkle_continuity_valid: bool,
    /// True when a `trusted_directory` was supplied to `verify` at all —
    /// independent of whether any receipts actually cleared quorum.
    /// `Unanchored` is exactly the case where this is false. (This is
    /// about the verifier's inputs, not about 0x07 ExternalAnchor leaves.)
    pub externally_anchored: bool,
    /// True when `VerifyContext::expected_identity_pubkey` was supplied.
    /// Without it, `identity_bound` means only that the dossier is
    /// self-consistent about its own identity.
    pub identity_pinned: bool,
    /// `is_internally_consistent()`, serialised so `--json` consumers see
    /// it next to the verdict (SPEC.md §9.2).
    pub internally_consistent: bool,
    pub quorum: Option<QuorumResult>,
    /// True when the verdict is `Witnessed` but the cosigning witnesses
    /// are not a strict majority of the trusted directory, so a second,
    /// conflicting history could have been cosigned by the rest
    /// (RFC-0002). `witness-log verify` exits 11 for this by default.
    pub split_view_unsafe: bool,
    /// Why the verdict is `Invalid`, one entry per failed check; empty
    /// otherwise.
    pub failures: Vec<String>,
    /// Why the verdict is `Diverged`: each known head or evidence file
    /// this dossier contradicts. Empty otherwise.
    pub contradictions: Vec<String>,
    /// Known heads larger than this dossier, which it cannot be checked
    /// against (`"<size>:<root>"`).
    pub known_heads_unchecked: Vec<String>,
    /// Five-valued verdict. See `Verdict` for what each value means and
    /// doesn't mean. Callers MUST use this field, not try to reconstruct
    /// a verdict from the individual boolean fields.
    pub verdict: Verdict,
    /// RFC-0001, experimental. Present only when the dossier carries a
    /// `fleet_anchor`: whether it was ignored (no opt-in), verified, or
    /// failed, and why.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fleet_anchor: Option<fleet::FleetAnchorReport>,
    /// RFC-0001, experimental. Present only when the caller opted in
    /// (`VerifyContext::accept_fleet_anchor`): `"direct"`, `"fleet"` or
    /// `"both"` for a `Witnessed` verdict (see [`fleet::WitnessedVia`]),
    /// `null` for any other verdict. Absent otherwise, so reports of
    /// callers who did not opt in are unchanged.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub witnessed_via: Option<Option<fleet::WitnessedVia>>,
    /// RFC-0001, experimental. Present only when the caller opted in:
    /// trusted witness keys and independent operators per path.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub witness_paths: Option<fleet::WitnessPaths>,
}

impl DossierReport {
    /// True exactly when the dossier is internally consistent: signature
    /// valid, identity bound, leaves structurally valid, bindings valid,
    /// and leaves reproduce the signed root. Deliberately independent of
    /// `quorum.meets_count_threshold` — whether a witness quorum clears
    /// some caller-chosen bar is a separate question from whether the
    /// dossier itself is honest about its own contents.
    pub fn is_internally_consistent(&self) -> bool {
        self.checkpoint_signature_valid
            && self.identity_bound
            && self.leaves_structurally_valid
            && self.bindings_valid
            && self.merkle_continuity_valid
    }

    /// True when the verdict is `Witnessed` — the strongest guarantee.
    /// Use this for programmatic gating; use `verdict` for display.
    pub fn is_witnessed(&self) -> bool {
        self.verdict == Verdict::Witnessed
    }
}

/// Every distinct session key among `leaves` must be covered by a valid,
/// verified `KeyBindingStatement` naming `identity_pubkey`; no leaf may
/// fall outside its binding's `not_after_ms` window; no leaf may postdate
/// a verified revocation for this identity. Vacuously true for an empty
/// leaf slice. See the pre-launch review, finding 06, and SPEC.md §5.
fn bindings_and_revocations_valid(
    leaves: &[Leaf],
    identity_pubkey: &str,
    key_bindings: &[KeyBindingStatement],
    revocations: &[RevocationStatement],
    checkpoint_timestamp_ms: u64,
    checkpoint_tree_size: u64,
) -> bool {
    // No binding or revocation data supplied at all. This is the common
    // case today (see `Dossier::key_bindings`'s doc comment on the
    // single-session-history limitation) and MUST NOT be treated as a
    // failure -- it means session-key provenance wasn't asserted for
    // this dossier, not that provenance failed to verify. Treating it as
    // a failure would make every dossier that predates this field
    // Diverged, which is a much larger breaking change than the review
    // asked for. The moment a caller supplies ANY binding or revocation,
    // though, they've opted into the stronger guarantee below, and full
    // coverage is then required -- a partial set that conveniently omits
    // an inconvenient leaf's session key must not look the same as "not
    // asserted."
    if key_bindings.is_empty() && revocations.is_empty() {
        return true;
    }

    let mut binding_by_session: std::collections::HashMap<String, &KeyBindingStatement> =
        std::collections::HashMap::new();
    for b in key_bindings {
        // A binding in this dossier claiming a DIFFERENT identity is
        // rejected outright rather than merely ignored -- shipping it at
        // all is either a caller bug or an attempt to pad the dossier
        // with a plausible-looking but irrelevant statement.
        if normalize_hex(&b.identity_pubkey) != normalize_hex(identity_pubkey) {
            return false;
        }
        if b.verify().is_err() {
            return false;
        }
        binding_by_session.insert(normalize_hex(&b.session_pubkey), b);
    }

    for r in revocations {
        if normalize_hex(&r.identity_pubkey) != normalize_hex(identity_pubkey) {
            return false;
        }
        if r.verify().is_err() {
            return false;
        }
    }
    for l in leaves {
        let session_key = normalize_hex(&l.session_pubkey);
        let binding = match binding_by_session.get(&session_key) {
            Some(b) => b,
            // A leaf authored by a session key with no covering binding
            // in this dossier cannot be confirmed as authorized by the
            // identity at all.
            None => return false,
        };
        if let Some(not_after) = binding.not_after_ms {
            if l.timestamp_ms > not_after {
                return false;
            }
        }
    }
    revocation_cut_off(
        revocations,
        leaves.iter().map(|l| (l.index, l.timestamp_ms)),
        checkpoint_timestamp_ms,
        checkpoint_tree_size,
    )
    .is_ok()
}

/// SPEC §5's cut-off over revocations whose signatures are already
/// verified. With any revocation: no leaf and no checkpoint at or after
/// the earliest `as_of_ms` (a checkpoint the revoked key signed after the
/// revocation is not evidence: whoever holds the key now signed it). With
/// an RFC-0005 index: no leaf at or past the smallest `as_of_index` and no
/// head larger than it, whatever the timestamps say, because timestamps
/// are written by the same key holder the revocation defends against.
/// `leaves` yields `(index, timestamp_ms)`. Corpus vector 12 pins the
/// cases.
pub fn revocation_cut_off(
    revocations: &[RevocationStatement],
    leaves: impl IntoIterator<Item = (u64, u64)>,
    checkpoint_timestamp_ms: u64,
    checkpoint_tree_size: u64,
) -> Result<(), String> {
    let as_of = revocations.iter().map(|r| r.as_of_ms).min();
    let at_index = revocations.iter().filter_map(|r| r.as_of_index).min();
    if let Some(t) = as_of {
        if checkpoint_timestamp_ms >= t {
            return Err("the checkpoint is signed at or after the identity's revocation".into());
        }
    }
    if let Some(n) = at_index {
        if checkpoint_tree_size > n {
            return Err(format!(
                "checkpoint tree_size {checkpoint_tree_size} is past the revocation index {n}"
            ));
        }
    }
    for (index, ts) in leaves {
        if let Some(t) = as_of {
            if ts >= t {
                return Err(format!("leaf {index} postdates the identity's revocation"));
            }
        }
        if let Some(n) = at_index {
            if index >= n {
                return Err(format!(
                    "leaf {index} is at or past the revocation index {n}"
                ));
            }
        }
    }
    Ok(())
}

impl Dossier {
    /// Rebuild the Merkle root from `self.leaves`, check it against
    /// `self.checkpoint`, check the checkpoint's own signature, validate
    /// every leaf structurally, confirm the claimed identity is
    /// self-consistent (and matches `ctx.expected_identity_pubkey` if
    /// supplied), and — only if `ctx.trusted_directory` is supplied —
    /// evaluate witness receipts against that trusted directory. Fully
    /// offline given `ctx`: no network access, no trust in this process
    /// beyond the arithmetic and whatever `ctx` the caller supplied.
    ///
    /// Passing `VerifyContext::default()` (no external inputs at all) is
    /// legal and caps the reachable verdict at `Unanchored` — see
    /// `VerifyContext` and `Verdict`.
    pub fn verify(&self, threshold_fraction: f64, ctx: &VerifyContext) -> DossierReport {
        let checkpoint_signature_valid = self.checkpoint.verify().is_ok();

        // Identity binding (finding 01). Always checked: the dossier's own
        // claimed identity must match the key that actually signed the
        // checkpoint, regardless of whether an external pin was supplied.
        // Previously nothing compared these two fields at all -- a dossier
        // could attribute a fabricated log to any victim's public key and
        // this check simply didn't exist.
        let self_consistent_identity =
            normalize_hex(&self.identity_pubkey) == normalize_hex(&self.checkpoint.signer_pubkey);
        let identity_bound = self_consistent_identity
            && match ctx.expected_identity_pubkey {
                Some(expected) => {
                    normalize_hex(expected) == normalize_hex(&self.checkpoint.signer_pubkey)
                }
                None => true,
            };

        // Structural leaf validation (finding 14): recognized types,
        // well-formed hex fields, mandatory fields present, indices
        // matching position, non-decreasing timestamps.
        // Once: it walks every leaf, and its error feeds `failures` below.
        let leaf_structure = witness_log_core::leaf::validate_sequence(&self.leaves);
        let leaves_structurally_valid = leaf_structure.is_ok();

        // Session-key binding and revocation validation (finding 06):
        // every leaf's authoring session key must be covered by a valid
        // binding to this identity, within its validity window, and not
        // postdating a revocation.
        let trusted_revocations: Vec<RevocationStatement> = ctx
            .revocations
            .iter()
            .filter(|r| normalize_hex(&r.identity_pubkey) == normalize_hex(&self.identity_pubkey))
            .filter(|r| !self.revocations.iter().any(|d| d.signature == r.signature))
            .cloned()
            .collect();
        let all_revocations: Vec<RevocationStatement> = self
            .revocations
            .iter()
            .cloned()
            .chain(trusted_revocations)
            .collect();
        let bindings_valid = bindings_and_revocations_valid(
            &self.leaves,
            &self.identity_pubkey,
            &self.key_bindings,
            &all_revocations,
            self.checkpoint.timestamp_ms,
            self.checkpoint.tree_size,
        );
        let bindings_asserted = !self.key_bindings.is_empty() || !all_revocations.is_empty();

        let mut tree = MerkleTree::new();
        for l in &self.leaves {
            tree.append(leaf_hash(&l.canonical_bytes()));
        }
        let rebuilt_root = hex::encode(tree.root());
        let size_matches = tree.size() == self.checkpoint.tree_size;
        let merkle_continuity_valid = size_matches && rebuilt_root == self.checkpoint.root_hash;

        // Witness quorum, evaluated ONLY against the caller's trusted
        // directory -- NEVER against self.witness_directory, which is
        // attacker-controlled exactly like every other field on this
        // struct. self.witness_directory exists purely for display
        // (showing a human the names/URLs the dossier claims for its
        // receipts); it must never reach a trust decision. See finding 02.
        let externally_anchored = ctx.trusted_directory.is_some();
        // RFC-0001 (experimental): read only with the opt-in. Without it
        // the attestations below are the direct receipts alone, exactly as
        // before the field existed.
        let (fleet_report, fleet_verified) = self.evaluate_fleet_anchor(ctx);
        let fleet_cosigners: &[(String, u64)] = fleet_verified
            .as_ref()
            .map(|v| v.cosigners.as_slice())
            .unwrap_or(&[]);
        let mut paths = fleet::WitnessPaths::default();
        let quorum = match ctx.trusted_directory {
            Some(trusted) if !self.witness_receipts.is_empty() || fleet_verified.is_some() => {
                let attestations = direct_attestations(&self.checkpoint, &self.witness_receipts)
                    .chain(
                        fleet_cosigners
                            .iter()
                            .map(|(k, ms)| (k.clone(), *ms, AttestationPath::Fleet)),
                    );
                let (mut q, p) = score_attestations(
                    &self.checkpoint,
                    attestations,
                    trusted,
                    threshold_fraction,
                    ctx.subject_org,
                );
                paths = p;
                if let Some(n) = ctx.min_receipts {
                    q.meets_count_threshold = q.valid_receipts >= n;
                    q.count_gate = format!("count >= {n}");
                }
                Some(q)
            }
            _ => None,
        };

        // Why the file is not valid evidence, one entry per failed check.
        let mut failures = Vec::new();
        if !checkpoint_signature_valid {
            failures.push("checkpoint signature does not verify".to_string());
        }
        if !self_consistent_identity {
            failures.push(
                "identity_pubkey does not match the key that signed the checkpoint".to_string(),
            );
        } else if !identity_bound {
            failures.push("the checkpoint is not signed by the identity you expected".to_string());
        }
        if let Err(e) = &leaf_structure {
            failures.push(format!("leaf structure: {e}"));
        }
        if !bindings_valid {
            failures.push(
                "key bindings or revocations: a leaf's session key has no valid binding from \
                 this identity, falls outside its binding's window, or the leaf or checkpoint is \
                 past a revocation"
                    .to_string(),
            );
        }
        if !size_matches {
            failures.push(format!(
                "{} leaves but the checkpoint claims tree_size {}",
                tree.size(),
                self.checkpoint.tree_size
            ));
        } else if !merkle_continuity_valid {
            failures.push("the leaves do not reproduce the signed root".to_string());
        }

        // Contradictions with evidence the verifier brought (RFC-0002).
        // Only meaningful for a valid file: an invalid one is INVALID
        // whatever else is true.
        let mut contradictions = Vec::new();
        let mut known_heads_unchecked = Vec::new();
        if failures.is_empty() {
            for kh in ctx.known_heads {
                if kh.tree_size > tree.size() {
                    known_heads_unchecked.push(format!(
                        "{}:{}",
                        kh.tree_size,
                        hex::encode(kh.root_hash)
                    ));
                    continue;
                }
                let mut prefix = MerkleTree::new();
                for l in self.leaves.iter().take(kh.tree_size as usize) {
                    prefix.append(leaf_hash(&l.canonical_bytes()));
                }
                if prefix.root() != kh.root_hash {
                    contradictions.push(format!(
                        "known head {}:{} is not what this dossier's first {} leaves produce ({})",
                        kh.tree_size,
                        hex::encode(kh.root_hash),
                        kh.tree_size,
                        hex::encode(prefix.root())
                    ));
                }
            }
            let origin = hex::decode(&self.identity_pubkey)
                .ok()
                .and_then(|b| <[u8; 32]>::try_from(b).ok())
                .and_then(|b| ed25519_dalek::VerifyingKey::from_bytes(&b).ok())
                .map(|k| witness_log_core::c2sp::canonical_origin(&k));
            for proof in ctx.evidence {
                if Some(&proof.origin) == origin.as_ref() && proof.verify() {
                    contradictions.push(format!(
                        "witness evidence: this identity signed two different roots for one tree \
                         size ({})",
                        proof.origin
                    ));
                }
            }
        }

        // Compute the five-valued verdict. See Verdict's doc comment.
        let verdict = if !failures.is_empty() {
            // Any cryptographic, identity, structural, or binding failure.
            Verdict::Invalid
        } else if !contradictions.is_empty() {
            Verdict::Diverged
        } else if !externally_anchored {
            // No external trust input supplied at all. Everything checks
            // out internally, but that's exactly what a fabricated dossier
            // with a freshly generated keypair -- and, previously, its own
            // fabricated witness directory -- could also produce. Capped
            // here regardless of what witness_receipts or witness_directory
            // claim about themselves.
            Verdict::Unanchored
        } else {
            match &quorum {
                None => Verdict::ConsistentUnwitnessed,
                Some(q) if !q.meets_count_threshold => Verdict::ConsistentUnwitnessed,
                Some(q) => {
                    // Gate on the ABSOLUTE number of distinct
                    // independent operators, not on what fraction of the
                    // known directory they represent.
                    //
                    // The previous rule required `diversity_fraction >=
                    // 0.5`, where the denominator is every distinct
                    // operator in the trusted directory. That made a
                    // larger witness network *harder* to verify against:
                    // at 1,000 known operators it demanded 500
                    // cosignatures on one checkpoint. The 100-agent
                    // fleet simulation surfaced this -- 5 genuinely
                    // independent operators scored 5/12 = 0.42 and could
                    // not reach Witnessed, while the existing 3-4 witness
                    // unit tests passed trivially at 75%.
                    //
                    // Two independent operators is the minimum that means
                    // anything: a single operator cannot contradict
                    // itself, so equivocation only becomes detectable
                    // once two parties who do not share an operator have
                    // both committed to the same head. Callers wanting a
                    // higher bar set `WitnessPolicy::min_independent_operators`;
                    // this is the floor for the verdict itself, not a
                    // recommendation.
                    if q.distinct_independent_operators >= MIN_INDEPENDENT_OPERATORS_FOR_WITNESSED
                        && q.meets_count_threshold
                    {
                        Verdict::Witnessed
                    } else {
                        Verdict::ConsistentUnwitnessed
                    }
                }
            }
        };

        let internally_consistent = checkpoint_signature_valid
            && identity_bound
            && leaves_structurally_valid
            && bindings_valid
            && merkle_continuity_valid;
        let split_view_unsafe = verdict == Verdict::Witnessed
            && !quorum.as_ref().is_some_and(|q| q.split_view_resistant);
        // Which path the counted keys came by (opt-in only). A key on both
        // paths counts as direct.
        let witnessed_via = ctx.accept_fleet_anchor.then(|| {
            (verdict == Verdict::Witnessed).then(|| {
                let fleet_only = paths.fleet.witnesses - paths.on_both;
                if fleet_only == 0 {
                    fleet::WitnessedVia::Direct
                } else if paths.direct.witnesses == 0 {
                    fleet::WitnessedVia::Fleet
                } else {
                    fleet::WitnessedVia::Both
                }
            })
        });
        DossierReport {
            checkpoint_signature_valid,
            identity_bound,
            leaves_structurally_valid,
            bindings_valid,
            bindings_asserted,
            leaf_count: tree.size(),
            claimed_tree_size: self.checkpoint.tree_size,
            merkle_continuity_valid,
            externally_anchored,
            identity_pinned: ctx.expected_identity_pubkey.is_some(),
            internally_consistent,
            quorum,
            split_view_unsafe,
            failures,
            contradictions,
            known_heads_unchecked,
            verdict,
            fleet_anchor: fleet_report,
            witnessed_via,
            witness_paths: ctx.accept_fleet_anchor.then_some(paths),
        }
    }

    /// RFC-0001: the report on `self.fleet_anchor`, and what it contributes
    /// when it fully verifies. `(None, None)` when the dossier has none.
    fn evaluate_fleet_anchor(
        &self,
        ctx: &VerifyContext,
    ) -> (
        Option<fleet::FleetAnchorReport>,
        Option<fleet::VerifiedFleetAnchor>,
    ) {
        use fleet::{FleetAnchorField, FleetAnchorReport, FleetAnchorStatus};
        let Some(field) = &self.fleet_anchor else {
            return (None, None);
        };
        let parsed = field.parsed();
        let mut report = FleetAnchorReport {
            status: FleetAnchorStatus::Ignored,
            origin: parsed.map(|a| a.origin.clone()),
            entry_index: parsed.map(|a| a.entry_index),
            fleet_tree_size: None,
            failures: Vec::new(),
        };
        if !ctx.accept_fleet_anchor {
            return (Some(report), None);
        }
        report.status = FleetAnchorStatus::Failed;
        let anchor = match field {
            FleetAnchorField::Parsed(a) => a,
            FleetAnchorField::Malformed(v) => {
                let why = serde_json::from_value::<fleet::FleetAnchor>(v.clone())
                    .err()
                    .map(|e| witness_log_core::echo::bounded(&e.to_string()))
                    .unwrap_or_default();
                report
                    .failures
                    .push(format!("fleet_anchor is not well-formed: {why}"));
                return (Some(report), None);
            }
        };
        if ctx
            .subject_org
            .map(normalize_label)
            .unwrap_or_default()
            .is_empty()
        {
            report.failures.push(
                "no subject_org: a fleet log is run by its agents' own organisation, and \
                 without knowing which one its own witnesses could count as independent"
                    .to_string(),
            );
            return (Some(report), None);
        }
        match fleet::verify_fleet_anchor(anchor, &self.checkpoint, ctx.trusted_directory) {
            Ok(v) => {
                report.status = FleetAnchorStatus::Verified;
                report.fleet_tree_size = Some(v.fleet_tree_size);
                (Some(report), Some(v))
            }
            Err(failures) => {
                report.failures = failures;
                (Some(report), None)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;
    use witness_log_core::identity::IdentityKeypair;

    fn make_sth() -> SignedTreeHead {
        let identity = IdentityKeypair::generate();
        let key = SigningKey::from_bytes(&identity.to_bytes());
        SignedTreeHead::sign(&key, 5, &[9u8; 32], 1000)
    }

    #[test]
    fn receipt_roundtrip() {
        let sth = make_sth();
        let witness_key = SigningKey::generate(&mut OsRng);
        let receipt = WitnessReceipt::sign(&witness_key, &sth, 1050);
        assert!(receipt.verify(&sth).is_ok());
    }

    /// `witness_name` is display metadata: it serializes only when set,
    /// a receipt without it (every dossier before 0.4.0) still parses,
    /// and no value of it changes whether the receipt verifies.
    #[test]
    fn witness_name_is_optional_additive_and_not_signed() {
        let sth = make_sth();
        let witness_key = SigningKey::generate(&mut OsRng);
        let bare = WitnessReceipt::sign(&witness_key, &sth, 1050);
        let bare_json = serde_json::to_string(&bare).unwrap();
        assert!(!bare_json.contains("witness_name"));
        let old: WitnessReceipt = serde_json::from_str(&bare_json).unwrap();
        assert_eq!(old.witness_name, None);
        assert!(old.verify(&sth).is_ok());

        let named = bare.clone().with_witness_name("w.example/1");
        let named_json = serde_json::to_string(&named).unwrap();
        assert!(named_json.contains("\"witness_name\":\"w.example/1\""));
        let back: WitnessReceipt = serde_json::from_str(&named_json).unwrap();
        assert!(back.verify(&sth).is_ok());
        let mut relabelled = back;
        relabelled.witness_name = Some("someone-else".into());
        assert!(
            relabelled.verify(&sth).is_ok(),
            "the name is not part of the signed message"
        );
    }

    #[test]
    fn quorum_flags_low_diversity_even_when_count_passes() {
        let sth = make_sth();
        // Three witness keys, but all three registered under the same
        // operator_org in the directory — this should score high on count,
        // low on diversity.
        let mut receipts = Vec::new();
        let mut directory = WitnessDirectory::default();
        for i in 0..3 {
            let k = SigningKey::generate(&mut OsRng);
            directory.witnesses.push(WitnessEntry {
                name: format!("witness-{i}"),
                operator_org: "same-operator-inc".to_string(),
                url: format!("https://witness{i}.example.com"),
                pubkey: hex::encode(k.verifying_key().to_bytes()),
                runtime: WitnessRuntime::Human,
                compute_provider: None,
                is_project_operated: false,
            });
            receipts.push(WitnessReceipt::sign(&k, &sth, 1050 + i));
        }
        // The wider directory also lists witnesses from other operators —
        // none of whom actually signed a receipt here. This is the
        // realistic shape of the problem: plenty of known-independent
        // witnesses exist, but this particular quorum didn't draw on them.
        for other_op in ["security-lab-a", "security-lab-b", "unrelated-org-c"] {
            let k = SigningKey::generate(&mut OsRng);
            directory.witnesses.push(WitnessEntry {
                name: format!("{other_op}-witness"),
                operator_org: other_op.to_string(),
                url: format!("https://{other_op}.example.com"),
                pubkey: hex::encode(k.verifying_key().to_bytes()),
                runtime: WitnessRuntime::Human,
                compute_provider: None,
                is_project_operated: false,
            });
        }

        let result = evaluate_quorum(&sth, &receipts, &directory, 0.4);
        assert!(
            result.meets_count_threshold,
            "3/7 at a 0.4 threshold should still pass count threshold"
        );
        assert_eq!(result.distinct_operators_represented, 1);
        assert!(
            result.diversity_fraction < 0.5,
            "single-operator quorum must score low on diversity regardless of count"
        );
    }

    #[test]
    fn tampered_receipt_fails_verification() {
        let sth = make_sth();
        let witness_key = SigningKey::generate(&mut OsRng);
        let mut receipt = WitnessReceipt::sign(&witness_key, &sth, 1050);
        receipt.tree_size += 1; // tamper
        assert!(receipt.verify(&sth).is_err());
    }

    #[test]
    fn compute_provider_diversity_is_scored_independently_of_operator_diversity() {
        let sth = make_sth();
        // Three DIFFERENT operators (good operator diversity), but all
        // three run their witness agent on the same underlying provider
        // (bad compute-provider diversity). The two axes should disagree,
        // on purpose — that disagreement is the point of scoring them
        // separately rather than averaging them into one number.
        let mut receipts = Vec::new();
        let mut directory = WitnessDirectory::default();
        for (i, org) in ["org-a", "org-b", "org-c"].iter().enumerate() {
            let k = SigningKey::generate(&mut OsRng);
            directory.witnesses.push(WitnessEntry {
                name: format!("{org}-agent-witness"),
                operator_org: org.to_string(),
                url: format!("https://{org}.example.com/witness"),
                pubkey: hex::encode(k.verifying_key().to_bytes()),
                runtime: WitnessRuntime::Agent,
                compute_provider: Some("same-inference-provider".to_string()),
                is_project_operated: false,
            });
            receipts.push(WitnessReceipt::sign(&k, &sth, 1050 + i as u64));
        }
        // A fourth directory entry on a distinct provider that did not sign.
        let unused_key = SigningKey::generate(&mut OsRng);
        directory.witnesses.push(WitnessEntry {
            name: "org-d-agent-witness".into(),
            operator_org: "org-d".into(),
            url: "https://org-d.example.com/witness".into(),
            pubkey: hex::encode(unused_key.verifying_key().to_bytes()),
            runtime: WitnessRuntime::Agent,
            compute_provider: Some("different-inference-provider".to_string()),
            is_project_operated: false,
        });

        let result = evaluate_quorum(&sth, &receipts, &directory, 0.5);
        assert_eq!(
            result.distinct_operators_represented, 3,
            "operator diversity should reflect 3 distinct orgs"
        );
        assert_eq!(
            result.distinct_compute_providers_represented, 1,
            "compute-provider diversity must independently reflect only 1 distinct provider"
        );
        assert!(
            result.diversity_fraction > result.compute_diversity_fraction,
            "operator diversity looking healthy must not mask weak compute-provider diversity"
        );
    }

    #[test]
    fn project_operated_witnesses_never_count_as_diverse_regardless_of_labels() {
        // The adversarial case this exists to prevent: ten witnesses, all
        // run by us, each given a DIFFERENT-looking operator_org and
        // compute_provider to make them superficially resemble ten
        // independent parties. is_project_operated must collapse all of
        // them into a single bucket on BOTH axes regardless.
        let sth = make_sth();
        let mut receipts = Vec::new();
        let mut directory = WitnessDirectory::default();
        for i in 0..10 {
            let k = SigningKey::generate(&mut OsRng);
            directory.witnesses.push(WitnessEntry {
                name: format!("bootstrap-witness-{i}"),
                operator_org: format!("totally-independent-org-{i}"), // misleading on purpose
                url: format!("https://witness{i}.example.com"),
                pubkey: hex::encode(k.verifying_key().to_bytes()),
                runtime: WitnessRuntime::Agent,
                compute_provider: Some(format!("provider-{i}")), // also misleading
                is_project_operated: true,
            });
            receipts.push(WitnessReceipt::sign(&k, &sth, 1000 + i));
        }

        let result = evaluate_quorum(&sth, &receipts, &directory, 0.9);
        assert!(
            result.meets_count_threshold,
            "10/10 should trivially pass a count threshold"
        );
        assert_eq!(result.valid_receipts, 10);
        assert_eq!(
            result.project_operated_receipts, 10,
            "all ten signing receipts must be flagged as project-operated"
        );
        assert_eq!(
            result.distinct_operators_represented, 1,
            "ten project-operated witnesses must collapse to ONE operator regardless of their labels"
        );
        assert_eq!(
            result.distinct_compute_providers_represented, 1,
            "ten project-operated witnesses must collapse to ONE compute provider regardless of their labels"
        );
    }

    #[test]
    fn genuine_third_party_witness_alongside_bootstrap_witnesses_is_counted_separately() {
        let sth = make_sth();
        let mut receipts = Vec::new();
        let mut directory = WitnessDirectory::default();
        for i in 0..3 {
            let k = SigningKey::generate(&mut OsRng);
            directory.witnesses.push(WitnessEntry {
                name: format!("bootstrap-{i}"),
                operator_org: "witness-log-project".into(),
                url: "https://witness.witness-log.dev".into(),
                pubkey: hex::encode(k.verifying_key().to_bytes()),
                runtime: WitnessRuntime::Agent,
                compute_provider: Some("witness-log-infra".into()),
                is_project_operated: true,
            });
            receipts.push(WitnessReceipt::sign(&k, &sth, 2000 + i));
        }
        let real_key = SigningKey::generate(&mut OsRng);
        directory.witnesses.push(WitnessEntry {
            name: "real-third-party-witness".into(),
            operator_org: "genuinely-independent-university".into(),
            url: "https://witness.example-university.edu".into(),
            pubkey: hex::encode(real_key.verifying_key().to_bytes()),
            runtime: WitnessRuntime::Human,
            compute_provider: None,
            is_project_operated: false,
        });
        receipts.push(WitnessReceipt::sign(&real_key, &sth, 2003));

        let result = evaluate_quorum(&sth, &receipts, &directory, 0.5);
        assert_eq!(result.project_operated_receipts, 3);
        assert_eq!(
            result.distinct_operators_represented, 2,
            "3 bootstrap witnesses (1 bucket) + 1 genuine third party = 2 distinct operators"
        );
    }
}

/// A machine-readable, executable pre-action policy an agent embeds to
/// gate execution on verifiable witness quality. Not a dashboard metric —
/// an agent MUST evaluate this before acting on a dossier's claims.
///
/// Design intent: enforcement of "I will not execute until I have
/// sufficient independent evidence" belongs in agent logic, not in a
/// human-readable audit trail reviewed after the fact. This struct makes
/// that intent a computable, auditable, version-controlled artifact
/// rather than an informally documented intent.
#[derive(Debug, Clone, Serialize, serde::Deserialize)]
pub struct WitnessPolicy {
    /// Minimum number of valid receipt signatures required.
    pub min_valid_receipts: usize,
    /// Minimum number of DISTINCT INDEPENDENT operators (excluding the
    /// project-operated bucket) represented among valid receipts.
    ///
    /// This, not `min_operator_diversity`, is the field to set for a
    /// meaningful trust decision. It is an absolute count, so it keeps
    /// the same meaning as the witness network grows: "at least N
    /// parties who don't share an operator each committed to this head."
    #[serde(default = "default_min_independent_operators")]
    pub min_independent_operators: usize,
    /// Minimum operator diversity *fraction* (0.0–1.0): what share of
    /// all distinct operators in the trusted directory are represented.
    ///
    /// Use with care, and prefer `min_independent_operators`. Because
    /// the denominator is the whole directory, this value becomes
    /// harder to satisfy as the network grows — on a 1,000-operator
    /// directory, 0.66 demands 660 cosignatures on one checkpoint.
    /// Useful as a coverage floor on a small, fixed, known witness set;
    /// actively misleading as a general trust gate. Defaults to 0.0 in
    /// both presets for that reason.
    pub min_operator_diversity: f64,
    /// Minimum compute-provider diversity fraction (0.0–1.0).
    pub min_compute_diversity: f64,
    /// Maximum age of the newest checkpoint, in milliseconds. An agent
    /// that insists on recent witnessing catches a dossier that's been
    /// sitting unupdated while the world's state changed.
    pub max_checkpoint_age_ms: Option<u64>,
    /// If true, reject any dossier where ALL valid receipts come from
    /// project-operated witnesses (i.e. `project_operated_receipts ==
    /// valid_receipts`). Set to true for anything that matters.
    pub reject_if_only_project_operated: bool,
    /// The minimum verdict required. A policy that demands `Witnessed`
    /// rejects anything that only reaches `ConsistentUnwitnessed`.
    pub min_verdict: Verdict,
}

fn default_min_independent_operators() -> usize {
    // Policies deserialized from older JSON that predates this field
    // get the verdict floor, not zero -- silently weakening an existing
    // deployed policy would be the wrong default.
    MIN_INDEPENDENT_OPERATORS_FOR_WITNESSED
}

impl WitnessPolicy {
    /// A permissive bootstrap default: accepts any valid dossier with at
    /// least one receipt. Appropriate while you're setting up witnesses.
    /// Do not use for production transactions.
    pub fn bootstrap() -> Self {
        Self {
            min_valid_receipts: 1,
            min_independent_operators: 0,
            min_operator_diversity: 0.0,
            min_compute_diversity: 0.0,
            max_checkpoint_age_ms: None,
            reject_if_only_project_operated: false,
            min_verdict: Verdict::ConsistentUnwitnessed,
        }
    }

    /// Production default: 3 receipts from at least 3 distinct
    /// independent operators, a checkpoint no older than 10 minutes,
    /// rejects all-project-operated quorums, and requires `Witnessed`.
    ///
    /// Note `min_operator_diversity` is 0.0 here, deliberately. An
    /// earlier version set it to 0.66, which is unreachable on any
    /// network of meaningful size — the fraction's denominator is every
    /// operator in the directory, so a growing witness network made this
    /// preset progressively impossible to satisfy. The absolute
    /// `min_independent_operators` count expresses the same intent
    /// ("enough genuinely separate parties agree") without degrading as
    /// the network grows.
    pub fn production() -> Self {
        Self {
            min_valid_receipts: 3,
            min_independent_operators: 3,
            min_operator_diversity: 0.0,
            min_compute_diversity: 0.0,
            max_checkpoint_age_ms: Some(600_000),
            reject_if_only_project_operated: true,
            min_verdict: Verdict::Witnessed,
        }
    }

    /// Evaluate a dossier report against this policy. Returns Ok(()) when
    /// the dossier satisfies every constraint, or Err with a plain-English
    /// explanation of the first constraint that failed. Agents gate
    /// execution on this result; it is the enforcement point.
    ///
    /// `self_asserted_checkpoint_timestamp_ms` is `checkpoint.timestamp_ms`
    /// — set and signed by the party being verified, and named
    /// accordingly. When the report has a quorum with at least one
    /// witness-corroborated timestamp, staleness is evaluated against
    /// THAT instead, since it carries actual evidentiary weight; a
    /// dishonest operator cannot backdate or forward-date a timestamp
    /// countersigned by an independent third party. The self-asserted
    /// checkpoint timestamp is used only as a fallback when no such
    /// corroboration exists, and the resulting error message says so.
    /// See the pre-launch review, finding 23.
    pub fn evaluate(
        &self,
        report: &DossierReport,
        self_asserted_checkpoint_timestamp_ms: u64,
        now_ms: u64,
    ) -> Result<(), String> {
        // Verdict gate first — most discriminating, cheapest check.
        let verdict_order = |v: &Verdict| match v {
            Verdict::Invalid | Verdict::Diverged => 0,
            Verdict::Unanchored => 1,
            Verdict::ConsistentUnwitnessed => 2,
            Verdict::Witnessed => 3,
        };
        if verdict_order(&report.verdict) < verdict_order(&self.min_verdict) {
            return Err(format!(
                "verdict {} is below policy minimum {} — will not proceed",
                report.verdict, self.min_verdict
            ));
        }
        if let Some(max_age) = self.max_checkpoint_age_ms {
            let witness_corroborated_ms = report
                .quorum
                .as_ref()
                .and_then(|q| q.newest_trusted_witness_ms);
            let (reference_ms, basis) = match witness_corroborated_ms {
                Some(ts) => (ts, "witness-corroborated"),
                None => (
                    self_asserted_checkpoint_timestamp_ms,
                    "self-asserted (no witness-corroborated timestamp available)",
                ),
            };
            let age = now_ms.saturating_sub(reference_ms);
            if age > max_age {
                return Err(format!(
                    "{basis} timestamp is {age}ms old, policy maximum is {max_age}ms — dossier may be stale"
                ));
            }
        }
        let quorum = match &report.quorum {
            Some(q) => q,
            None => {
                if self.min_valid_receipts > 0 {
                    return Err(format!(
                        "no witness receipts present, policy requires at least {}",
                        self.min_valid_receipts
                    ));
                }
                return Ok(());
            }
        };
        if quorum.valid_receipts < self.min_valid_receipts {
            return Err(format!(
                "{} valid receipts, policy requires at least {}",
                quorum.valid_receipts, self.min_valid_receipts
            ));
        }
        if quorum.distinct_independent_operators < self.min_independent_operators {
            return Err(format!(
                "{} distinct independent operator(s) cosigned, policy requires at least {} \u{2014} \
                 receipts from parties sharing an operator do not add independence",
                quorum.distinct_independent_operators, self.min_independent_operators
            ));
        }
        if quorum.diversity_fraction < self.min_operator_diversity {
            return Err(format!(
                "operator diversity {:.2} is below policy minimum {:.2} (note: this fraction's \
                 denominator is the whole directory, so it falls as the network grows \u{2014} \
                 prefer min_independent_operators)",
                quorum.diversity_fraction, self.min_operator_diversity
            ));
        }
        if quorum.compute_diversity_fraction < self.min_compute_diversity {
            return Err(format!(
                "compute-provider diversity {:.2} is below policy minimum {:.2}",
                quorum.compute_diversity_fraction, self.min_compute_diversity
            ));
        }
        if self.reject_if_only_project_operated
            && quorum.project_operated_receipts > 0
            && quorum.project_operated_receipts == quorum.valid_receipts
        {
            return Err(format!(
                "all {} valid receipts are from project-operated witnesses — policy requires at least one independent receipt",
                quorum.valid_receipts
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod policy_tests {
    use super::*;

    fn mock_report(
        verdict: Verdict,
        valid: usize,
        op_div: f64,
        comp_div: f64,
        proj: usize,
    ) -> DossierReport {
        let quorum = if valid == 0 {
            None
        } else {
            Some(QuorumResult {
                tree_size: 10,
                valid_receipts: valid,
                total_directory_witnesses: valid,
                distinct_operators_represented: 2,
                distinct_operators_in_directory: 3,
                quorum_fraction: valid as f64 / 3.0,
                diversity_fraction: op_div,
                distinct_compute_providers_represented: 2,
                distinct_compute_providers_in_directory: 3,
                compute_diversity_fraction: comp_div,
                project_operated_receipts: proj,
                // Mock: independent operators = valid receipts minus the
                // project-operated ones, which is the common real shape.
                distinct_independent_operators: valid.saturating_sub(proj),
                independent_operators_represented: (0..valid.saturating_sub(proj))
                    .map(|i| format!("op-{i}"))
                    .collect(),
                meets_count_threshold: true,
                count_gate: String::new(),
                split_view_resistant: false,
                newest_trusted_witness_ms: if valid == 0 { None } else { Some(0) },
            })
        };
        DossierReport {
            checkpoint_signature_valid: true,
            identity_bound: true,
            leaves_structurally_valid: true,
            bindings_valid: true,
            bindings_asserted: false,
            leaf_count: 10,
            claimed_tree_size: 10,
            merkle_continuity_valid: true,
            externally_anchored: valid > 0,
            identity_pinned: true,
            internally_consistent: true,
            quorum,
            split_view_unsafe: false,
            failures: Vec::new(),
            contradictions: Vec::new(),
            known_heads_unchecked: Vec::new(),
            verdict,
            fleet_anchor: None,
            witnessed_via: None,
            witness_paths: None,
        }
    }

    #[test]
    fn production_policy_passes_healthy_dossier() {
        let policy = WitnessPolicy::production();
        let report = mock_report(Verdict::Witnessed, 3, 0.75, 0.67, 0);
        assert!(policy.evaluate(&report, 0, 300_000).is_ok());
    }

    #[test]
    fn production_policy_rejects_stale_checkpoint() {
        let policy = WitnessPolicy::production();
        let report = mock_report(Verdict::Witnessed, 3, 0.75, 0.67, 0);
        let err = policy.evaluate(&report, 0, 700_000).unwrap_err();
        assert!(err.contains("stale"), "expected stale message: {err}");
    }

    #[test]
    fn staleness_prefers_witness_corroborated_time_over_self_asserted_claim() {
        // Finding 23: a dishonest operator can set checkpoint.timestamp_ms
        // to anything -- it's self-signed by the party being verified.
        // This confirms that when a witness-corroborated timestamp IS
        // available, staleness is judged against THAT, not the operator's
        // claim, even when the operator's claim says "just now."
        let policy = WitnessPolicy::production();
        let mut report = mock_report(Verdict::Witnessed, 3, 0.75, 0.67, 0);
        // The witness timestamp (buried in mock_report's quorum) is 0ms --
        // ancient. The operator's self-asserted checkpoint timestamp claims
        // to be very recent (699_999ms, 1ms before now).
        report.quorum.as_mut().unwrap().newest_trusted_witness_ms = Some(0);
        let now = 700_000;
        let self_asserted_but_lying = 699_999; // operator claims "just now"
        let err = policy
            .evaluate(&report, self_asserted_but_lying, now)
            .unwrap_err();
        assert!(
            err.contains("witness-corroborated") && err.contains("stale"),
            "must reject based on the OLD witness-corroborated time, not the operator's fresh self-asserted claim: {err}"
        );
    }

    #[test]
    fn staleness_falls_back_to_self_asserted_time_when_no_witness_corroboration() {
        // A quorum IS present (so the verdict/receipt/diversity gates all
        // pass) but its newest_trusted_witness_ms is None -- simulating a
        // policy relaxed enough to reach Witnessed without any witness
        // supplying a countersigned timestamp (e.g. a receipt format that
        // predates witnessed_at_ms tracking). Staleness must still be
        // checked, falling back to the self-asserted checkpoint time, and
        // the resulting message must say so rather than silently passing.
        let policy = WitnessPolicy::production();
        let mut report = mock_report(Verdict::Witnessed, 3, 0.75, 0.67, 0);
        report.quorum.as_mut().unwrap().newest_trusted_witness_ms = None;
        let stale_self_asserted = 0; // ancient
        let now = 700_000;
        let err = policy
            .evaluate(&report, stale_self_asserted, now)
            .unwrap_err();
        assert!(
            err.contains("self-asserted") && err.contains("stale"),
            "must fall back to the self-asserted timestamp and say so when no witness corroboration exists: {err}"
        );
    }

    #[test]
    fn production_policy_rejects_all_project_operated() {
        let policy = WitnessPolicy::production();
        // Verdict passed as Witnessed so the verdict gate doesn't fire first —
        // this test isolates the project-operated gate specifically. (In a real
        // report, all-project-operated receipts can never reach Witnessed; the
        // verdict computation itself enforces that, tested separately.)
        let report = mock_report(Verdict::Witnessed, 3, 0.75, 0.67, 3);
        let err = policy.evaluate(&report, 0, 0).unwrap_err();
        // Either rejection reason is correct and both are desirable. The
        // independent-operator check fires first because it is the more
        // fundamental objection: an all-project-operated quorum has ZERO
        // independent operators, so there is no equivocation resistance
        // regardless of how the receipts are labeled.
        assert!(
            err.contains("project-operated") || err.contains("distinct independent operator"),
            "expected a project-operated or independence rejection: {err}"
        );
    }

    #[test]
    fn production_policy_rejects_weak_verdict() {
        let policy = WitnessPolicy::production();
        let report = mock_report(Verdict::Unanchored, 0, 0.0, 0.0, 0);
        let err = policy.evaluate(&report, 0, 0).unwrap_err();
        assert!(err.contains("below policy minimum"), "{err}");
    }

    #[test]
    fn bootstrap_policy_accepts_minimal_dossier() {
        let policy = WitnessPolicy::bootstrap();
        let report = mock_report(Verdict::ConsistentUnwitnessed, 1, 0.0, 0.0, 1);
        assert!(policy.evaluate(&report, 0, 0).is_ok());
    }
}

/// Outcome of a silence-proof check: did an event the log acknowledged
/// (a signed write receipt) make it into the log's witnessed history?
/// See [`silence_proof_for_subject`] for what each outcome rests on.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SilenceProofResult {
    /// The event is in the caller's leaf view. Not an accusation; before
    /// relying on it as proof of inclusion, check an inclusion proof
    /// against a witnessed checkpoint.
    Present {
        /// The leaf index where the event appears.
        leaf_index: u64,
    },
    /// The log signed a receipt for the event, at least
    /// `min_witnessed_checkpoints` distinct later checkpoints of the same
    /// log were cosigned by two or more independent operators from the
    /// caller's directory, the caller's leaves reproduce the root of every
    /// one of them (so they are exactly the log's leaves up to the largest),
    /// and the event is not among them. Anyone holding the same receipt,
    /// checkpoints with their receipts, and leaves reaches this result
    /// again, which is what makes the bundle evidence rather than a claim.
    Censored {
        /// The tree_size in the write receipt — the registry claimed to
        /// have accepted the event at this size.
        receipt_tree_size: u64,
        /// Number of witnessed checkpoints observed after receipt_tree_size
        /// without the event appearing.
        witnessed_checkpoints_after: usize,
    },
    /// Not enough to conclude either way: too few witnessed checkpoints
    /// since the receipt, a receipt that does not verify, leaves that do
    /// not reproduce the witnessed checkpoints, or witnessed checkpoints
    /// that contradict each other. [`SilenceProofReport::reason`] says
    /// which.
    Inconclusive {
        receipt_tree_size: u64,
        witnessed_checkpoints_seen: usize,
        min_required: usize,
    },
}

/// [`SilenceProofResult`] plus what it was bound to and, when
/// inconclusive, why.
#[derive(Debug, Clone, Serialize)]
pub struct SilenceProofReport {
    pub result: SilenceProofResult,
    /// The largest witnessed checkpoint `(tree_size, root_hash)` that the
    /// caller's leaves reproduced, in whose leaves the event's absence was
    /// checked. Set for `Censored`, and for `Inconclusive` when only the
    /// count fell short.
    pub bound_tree_size: Option<u64>,
    pub bound_root_hash: Option<String>,
    /// Why the result is `Inconclusive`; `None` otherwise.
    pub reason: Option<String>,
}

/// One later checkpoint observed after a write receipt, paired with
/// whatever witness receipts corroborate it. `silence_proof` counts
/// DISTINCT checkpoints meeting this bar, not receipts — see its doc
/// comment and the pre-launch review, finding 11.
#[derive(Debug, Clone)]
pub struct ObservedCheckpoint {
    pub checkpoint: SignedTreeHead,
    pub receipts: Vec<WitnessReceipt>,
}

/// [`silence_proof_for_subject`] without naming the log's operator; the
/// result only. Kept for 0.6 callers: since 0.6.1 its `Censored` requires
/// the same binding and independence as the full function.
pub fn silence_proof(
    write_receipt: &WriteReceipt,
    latest_leaves: &[Leaf],
    later_checkpoints: &[ObservedCheckpoint],
    trusted_directory: &WitnessDirectory,
    min_witnessed_checkpoints: usize,
) -> SilenceProofResult {
    silence_proof_for_subject(
        write_receipt,
        latest_leaves,
        later_checkpoints,
        trusted_directory,
        min_witnessed_checkpoints,
        None,
    )
    .result
}

/// Check whether an event the log acknowledged (`write_receipt`) is in its
/// witnessed history, or has been provably left out of it.
///
/// `write_receipt`: a [`WriteReceipt`] the log signed when it accepted the
/// event. It commits the log to a specific `payload_hash` at a specific
/// `tree_size`. Its signature is verified first; an unverifiable receipt
/// proves nothing. (Before 0.3.1 this took a plain checkpoint, which
/// commits to no event.)
///
/// `latest_leaves`: the log's leaves as the caller holds them, from index
/// 0. They are trusted for nothing: `Censored` requires that they
/// reproduce the root of every counted checkpoint, so a caller cannot
/// drop the event from the list and accuse an honest log. (0.6.0 and
/// earlier counted the checkpoints and looked for the event in this list
/// without joining the two, so an accuser could pass a list with the event
/// removed, or no list at all, and get `Censored` against an honest log.
/// Found by the third outside review, H1.)
///
/// `later_checkpoints`: checkpoints the caller observed with
/// `tree_size > write_receipt.tree_size`, each with its witness receipts.
/// One counts only if its own signature verifies, it was signed by the
/// same identity as the receipt, and its valid receipts from witnesses in
/// `trusted_directory` come from at least
/// [`MIN_INDEPENDENT_OPERATORS_FOR_WITNESSED`] distinct independent
/// operators, the bar `Verdict::Witnessed` uses (project-operated
/// witnesses never count; witnesses of the log's own operator never
/// count, the operator being the directory entry with the log's key or
/// `subject_org`). One trusted receipt used to be enough, which made an
/// accusation easier to reach than an affirmation (review III, M1). The
/// same `(tree_size, root_hash)` observed twice counts once.
///
/// `min_witnessed_checkpoints`: how many distinct counted checkpoints must
/// pass before calling it censorship. 2 is a conservative minimum; 5 is
/// robust.
///
/// `subject_org`: the organisation that operates the log being checked,
/// as for [`VerifyContext::subject_org`]; its witnesses never count.
pub fn silence_proof_for_subject(
    write_receipt: &WriteReceipt,
    latest_leaves: &[Leaf],
    later_checkpoints: &[ObservedCheckpoint],
    trusted_directory: &WitnessDirectory,
    min_witnessed_checkpoints: usize,
    subject_org: Option<&str>,
) -> SilenceProofReport {
    let inconclusive = |seen: usize, bound: Option<(u64, String)>, reason: String| {
        let (bound_tree_size, bound_root_hash) = match bound {
            Some((n, r)) => (Some(n), Some(r)),
            None => (None, None),
        };
        SilenceProofReport {
            result: SilenceProofResult::Inconclusive {
                receipt_tree_size: write_receipt.tree_size,
                witnessed_checkpoints_seen: seen,
                min_required: min_witnessed_checkpoints,
            },
            bound_tree_size,
            bound_root_hash,
            reason: Some(reason),
        }
    };
    // An unverifiable write receipt proves nothing about acceptance.
    if write_receipt.verify().is_err() {
        return inconclusive(0, None, "the write receipt does not verify".into());
    }
    let event_payload_hash = normalize_hex(&write_receipt.payload_hash);

    // 1. In the caller's view: not an accusation, whatever else holds.
    if let Some(idx) = latest_leaves
        .iter()
        .position(|l| normalize_hex(&l.payload_hash) == event_payload_hash)
    {
        return SilenceProofReport {
            result: SilenceProofResult::Present {
                leaf_index: idx as u64,
            },
            bound_tree_size: None,
            bound_root_hash: None,
            reason: None,
        };
    }

    // 2. Distinct checkpoints after the receipt, of this log, cosigned by
    // at least two independent operators from the caller's directory.
    let mut counted: std::collections::BTreeSet<(u64, String)> = Default::default();
    for oc in later_checkpoints {
        if oc.checkpoint.tree_size <= write_receipt.tree_size
            || oc.checkpoint.verify().is_err()
            || normalize_hex(&oc.checkpoint.signer_pubkey)
                != normalize_hex(&write_receipt.signer_pubkey)
        {
            continue;
        }
        let q = evaluate_quorum_for_subject(
            &oc.checkpoint,
            &oc.receipts,
            trusted_directory,
            0.0,
            subject_org,
        );
        if q.distinct_independent_operators < MIN_INDEPENDENT_OPERATORS_FOR_WITNESSED {
            continue;
        }
        counted.insert((
            oc.checkpoint.tree_size,
            normalize_hex(&oc.checkpoint.root_hash),
        ));
    }
    let seen = counted.len();

    // Two witnessed roots for one size: the log equivocated, and absence
    // from one history says nothing about the other.
    let mut sizes = HashSet::new();
    if let Some((n, _)) = counted.iter().find(|(n, _)| !sizes.insert(*n)) {
        return inconclusive(
            seen,
            None,
            format!(
                "two witnessed checkpoints of size {n} commit to different roots:                  the log showed two histories (equivocation evidence, not a silence proof)"
            ),
        );
    }
    let Some((largest, largest_root)) = counted.iter().next_back().cloned() else {
        return inconclusive(
            0,
            None,
            "no checkpoint after the receipt was cosigned by two independent operators              from the trusted directory"
                .into(),
        );
    };

    // 3. Bind the absence: the leaves must be the log's leaves up to the
    // largest witnessed checkpoint, and agree with every smaller one.
    if (latest_leaves.len() as u64) < largest {
        return inconclusive(
            seen,
            None,
            format!(
                "the leaves cover {} entries but the largest witnessed checkpoint has {largest}:                  fetch the log up to that size",
                latest_leaves.len()
            ),
        );
    }
    let mut tree = MerkleTree::new();
    for l in latest_leaves.iter().take(largest as usize) {
        tree.append(leaf_hash(&l.canonical_bytes()));
    }
    for (n, root) in &counted {
        if tree.root_at(*n).map(hex::encode).as_deref() != Some(root.as_str()) {
            return inconclusive(
                seen,
                None,
                format!(
                    "the leaves do not reproduce the witnessed root at size {n}: they are not                      the log's history, so the event's absence from them proves nothing"
                ),
            );
        }
    }
    let bound = Some((largest, largest_root));

    if seen >= min_witnessed_checkpoints {
        let (bound_tree_size, bound_root_hash) = bound.unzip();
        SilenceProofReport {
            result: SilenceProofResult::Censored {
                receipt_tree_size: write_receipt.tree_size,
                witnessed_checkpoints_after: seen,
            },
            bound_tree_size,
            bound_root_hash,
            reason: None,
        }
    } else {
        inconclusive(
            seen,
            bound,
            format!(
                "{seen} witnessed checkpoint(s) after the receipt; {min_witnessed_checkpoints} required"
            ),
        )
    }
}

/// Choose witnesses that maximize operator independence.
///
/// **Use this instead of picking witnesses yourself.** The 1,000-agent
/// cohort simulation measured the difference: naive selection (nearest
/// peers, round-robin, random) reached the independence floor only
/// 53–62% of the time, while operator-aware selection reached 100%.
///
/// The reason is that real operator distributions follow a power law —
/// a few large operators run most agents, so any selection that doesn't
/// look at `operator_org` keeps picking witnesses that share one. Those
/// receipts are individually valid and add nothing: `Verdict::Witnessed`
/// counts distinct *independent operators*, not signatures.
///
/// Returns at most one witness per operator, skipping:
/// - witnesses sharing `subject_operator` (self-attestation is not
///   independence — see `evaluate_quorum`)
/// - project-operated witnesses, which all collapse to one bucket
///
/// Project-operated witnesses are returned *after* independent ones when
/// `include_project_operated` is set, so they top up a thin quorum
/// without ever displacing a genuinely independent signature.
///
/// Within an operator, the witness chosen is a function of the subject's
/// identity key, so one agent keeps using the same witnesses run after
/// run (no 409 resync churn) while a thousand agents spread across all of
/// an operator's witnesses instead of all choosing its first one. Found
/// by the 1,000-agent swarm: deterministic first-entry selection sent
/// every agent to the same eight witnesses and tripped their enrollment
/// rate limits while ninety-two sat idle.
pub fn select_diverse_witnesses<'a>(
    directory: &'a WitnessDirectory,
    subject_identity_pubkey: &str,
    want: usize,
    include_project_operated: bool,
) -> Vec<&'a WitnessEntry> {
    let subject_operator: Option<String> = directory
        .witnesses
        .iter()
        .find(|w| normalize_hex(&w.pubkey) == normalize_hex(subject_identity_pubkey))
        .map(operator_key);

    // Group independent witnesses by operator, in directory order.
    let mut order: Vec<String> = Vec::new();
    let mut buckets: std::collections::HashMap<String, Vec<&WitnessEntry>> =
        std::collections::HashMap::new();
    for w in directory
        .witnesses
        .iter()
        .filter(|w| !w.is_project_operated)
    {
        let op = normalize_label(&w.operator_org);
        if subject_operator.as_deref() == Some(op.as_str()) {
            continue; // the subject's own operator adds no independence
        }
        if !buckets.contains_key(&op) {
            order.push(op.clone());
        }
        buckets.entry(op).or_default().push(w);
    }
    let spread = subject_spread(subject_identity_pubkey);
    let mut chosen: Vec<&WitnessEntry> = Vec::new();
    for op in &order {
        if chosen.len() >= want {
            break;
        }
        if let Some(bucket) = buckets.get(op) {
            if let Some(w) = bucket.get(spread % bucket.len()) {
                chosen.push(w);
            }
        }
    }

    if include_project_operated {
        // At most one: they all collapse into a single diversity bucket,
        // so a second adds nothing a verifier will count.
        if chosen.len() < want {
            if let Some(w) = directory.witnesses.iter().find(|w| w.is_project_operated) {
                chosen.push(w);
            }
        }
    }
    chosen
}

/// Diversity first, then capacity. Starts from [`select_diverse_witnesses`]
/// (one witness per independent operator) and, if `want` is not yet met,
/// fills the remaining slots round-robin across operators, so a submitter
/// asking for eight witnesses from a four-operator directory gets two per
/// operator rather than four. Use this to choose whom to *submit* to when
/// availability matters; the verifier's independence count is unchanged
/// either way. Found by the 1,000-agent swarm against a 100-witness
/// network, where one-per-operator left most of the capacity idle.
pub fn select_witnesses<'a>(
    directory: &'a WitnessDirectory,
    subject_identity_pubkey: &str,
    want: usize,
    include_project_operated: bool,
) -> Vec<&'a WitnessEntry> {
    let mut chosen = select_diverse_witnesses(
        directory,
        subject_identity_pubkey,
        want,
        include_project_operated,
    );
    let subject_operator: Option<String> = directory
        .witnesses
        .iter()
        .find(|w| normalize_hex(&w.pubkey) == normalize_hex(subject_identity_pubkey))
        .map(operator_key);
    if chosen.len() < want {
        let mut by_op: Vec<Vec<&WitnessEntry>> = Vec::new();
        let mut index: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
        for w in directory
            .witnesses
            .iter()
            .filter(|w| !w.is_project_operated)
        {
            let op = normalize_label(&w.operator_org);
            if subject_operator.as_deref() == Some(op.as_str())
                || chosen.iter().any(|c| c.pubkey == w.pubkey)
            {
                continue;
            }
            let i = *index.entry(op).or_insert_with(|| {
                by_op.push(Vec::new());
                by_op.len() - 1
            });
            by_op[i].push(w);
        }
        let spread = subject_spread(subject_identity_pubkey);
        let mut round = 0;
        while chosen.len() < want {
            let mut added = false;
            for bucket in &by_op {
                if chosen.len() >= want {
                    break;
                }
                if bucket.is_empty() || round >= bucket.len() {
                    continue;
                }
                if let Some(w) = bucket.get((spread + round) % bucket.len()) {
                    chosen.push(w);
                    added = true;
                }
            }
            if !added {
                break;
            }
            round += 1;
        }
    }
    chosen
}

/// A stable per-subject offset for spreading load across an operator's
/// witnesses: the first eight bytes of SHA-256(identity key).
fn subject_spread(subject_identity_pubkey: &str) -> usize {
    // leaf_hash is SHA-256 with a domain prefix; any stable hash works here.
    let h = leaf_hash(normalize_hex(subject_identity_pubkey).as_bytes());
    let mut b = [0u8; 8];
    b.copy_from_slice(&h[..8]);
    (u64::from_be_bytes(b) % (usize::MAX as u64)) as usize
}

#[cfg(test)]
mod selection_tests {
    use super::*;

    fn dir_with(entries: &[(&str, &str, bool)]) -> WitnessDirectory {
        let mut d = WitnessDirectory::default();
        for (i, (name, org, project)) in entries.iter().enumerate() {
            d.witnesses.push(WitnessEntry {
                name: (*name).to_string(),
                operator_org: (*org).to_string(),
                url: format!("https://{name}.example"),
                pubkey: hex::encode([i as u8; 32]),
                runtime: WitnessRuntime::Human,
                compute_provider: None,
                is_project_operated: *project,
            });
        }
        d
    }

    #[test]
    fn never_returns_two_witnesses_from_one_operator() {
        // The exact failure the cohort measured: a power-law directory
        // where naive selection keeps picking the same big operator.
        let d = dir_with(&[
            ("a1", "hyperscale", false),
            ("a2", "hyperscale", false),
            ("a3", "hyperscale", false),
            ("a4", "hyperscale", false),
            ("b1", "midsize", false),
            ("c1", "smallco", false),
        ]);
        let picked = select_diverse_witnesses(&d, &hex::encode([99u8; 32]), 4, false);
        let ops: HashSet<&str> = picked.iter().map(|w| w.operator_org.as_str()).collect();
        assert_eq!(picked.len(), ops.len(), "one witness per operator");
        assert_eq!(ops.len(), 3, "only three distinct operators exist");
    }

    #[test]
    fn excludes_the_subjects_own_operator() {
        let d = dir_with(&[("self", "my-org", false), ("other", "their-org", false)]);
        let subject = d.witnesses[0].pubkey.clone();
        let picked = select_diverse_witnesses(&d, &subject, 5, false);
        assert_eq!(picked.len(), 1);
        assert_eq!(picked[0].operator_org, "their-org");
    }

    #[test]
    fn case_variants_do_not_slip_through_as_separate_operators() {
        let d = dir_with(&[
            ("a", "Acme", false),
            ("b", "acme", false),
            ("c", " ACME ", false),
            ("d", "real-other", false),
        ]);
        let picked = select_diverse_witnesses(&d, &hex::encode([99u8; 32]), 4, false);
        assert_eq!(
            picked.len(),
            2,
            "Acme/acme/ACME are one operator, plus one other"
        );
    }

    #[test]
    fn project_operated_tops_up_but_never_displaces() {
        let d = dir_with(&[
            ("boot", "project", true),
            ("ind1", "org-a", false),
            ("ind2", "org-b", false),
        ]);
        let picked = select_diverse_witnesses(&d, &hex::encode([99u8; 32]), 3, true);
        assert_eq!(picked.len(), 3);
        assert!(
            !picked[0].is_project_operated && !picked[1].is_project_operated,
            "independent witnesses must come first"
        );
        assert!(picked[2].is_project_operated);
    }

    #[test]
    fn selection_actually_reaches_the_independence_floor() {
        // End-to-end: the selection must produce a quorum that clears
        // MIN_INDEPENDENT_OPERATORS_FOR_WITNESSED, which is the whole
        // point of the helper existing.
        let d = dir_with(&[
            ("a1", "big", false),
            ("a2", "big", false),
            ("a3", "big", false),
            ("b1", "mid", false),
            ("c1", "small", false),
        ]);
        let picked = select_diverse_witnesses(&d, &hex::encode([99u8; 32]), 3, false);
        let distinct: HashSet<String> = picked
            .iter()
            .map(|w| normalize_label(&w.operator_org))
            .collect();
        assert!(
            distinct.len() >= MIN_INDEPENDENT_OPERATORS_FOR_WITNESSED,
            "selection must clear the independence floor; got {} operators",
            distinct.len()
        );
    }
}

impl Dossier {
    /// Build a self-export dossier from a log: the common case, where
    /// you are exporting your own history and have no witness receipts
    /// yet.
    ///
    /// Hand-building a `Dossier` means filling seven fields, two of
    /// which are empty in every self-export and one of which
    /// (`key_bindings`) is easy to get wrong in a way that makes a
    /// restarted agent verify as `Diverged`. This gets it right.
    ///
    /// Add witness receipts with [`Dossier::with_receipts`] once you
    /// have them.
    pub fn from_log(log: &witness_log_core::log::WitnessLog, checkpoint: SignedTreeHead) -> Self {
        Self {
            identity_pubkey: log.identity_pubkey_hex(),
            leaves: log.leaves().to_vec(),
            checkpoint,
            witness_receipts: Vec::new(),
            witness_directory: WitnessDirectory::default(),
            // all_bindings, NOT current_binding: a log that has restarted
            // holds leaves signed by session keys that no longer exist,
            // and omitting their bindings makes verification report
            // tampering for an agent that merely rebooted.
            key_bindings: log.all_bindings(),
            revocations: Vec::new(),
            fleet_anchor: None,
        }
    }

    /// Attach witness receipts to a dossier.
    pub fn with_receipts(mut self, receipts: Vec<WitnessReceipt>) -> Self {
        self.witness_receipts = receipts;
        self
    }

    /// Attach a fleet anchor (RFC-0001, experimental).
    pub fn with_fleet_anchor(mut self, anchor: fleet::FleetAnchor) -> Self {
        self.fleet_anchor = Some(anchor.into());
        self
    }
}

/// How two checkpoints from the same identity relate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CheckpointRelation {
    /// `later` is a strict extension of `earlier`, proven by consistency
    /// proof. Nothing was removed or altered.
    Extends,
    /// Same size, same root: two copies of one checkpoint.
    Identical,
    /// The newer checkpoint (by timestamp) has a SMALLER tree. A log
    /// cannot un-append, so this is evidence of a restore-from-backup or
    /// deliberate rollback.
    Rollback,
    /// Same size, different root — two incompatible histories at the
    /// same length. Equivocation.
    Diverged,
    /// A consistency proof was needed and either wasn't supplied or
    /// didn't verify. Could be equivocation; could be a missing proof.
    Unproven,
    /// The two checkpoints are not from the same signing key.
    DifferentIdentity,
    /// At least one checkpoint's signature does not verify. Nothing can be
    /// concluded about the log from a checkpoint it never signed -- a
    /// corrupt or forged file is not evidence of a rollback or a fork.
    /// Before 0.3.1 this function compared unverified checkpoints and
    /// could report `Diverged` for an honest head plus a tampered copy.
    InvalidSignature,
}

/// Relate two checkpoints from one identity. A regulator holding two
/// dossiers previously had to compare `tree_size` and `timestamp_ms` by
/// hand to spot a rollback; this does it, and distinguishes the cases
/// that matter. `proof` is a consistency proof from the smaller tree to
/// the larger, if the caller has one (e.g. from
/// `WitnessLog::consistency_proof`); without it, `Extends` cannot be
/// claimed and the result is `Unproven`.
pub fn compare_checkpoints(
    a: &SignedTreeHead,
    b: &SignedTreeHead,
    proof: Option<&[witness_log_core::merkle::Hash]>,
) -> CheckpointRelation {
    if normalize_hex(&a.signer_pubkey) != normalize_hex(&b.signer_pubkey) {
        return CheckpointRelation::DifferentIdentity;
    }
    // Every relation below is a statement about what the log signed, so
    // both signatures are checked first (strict Ed25519, as everywhere).
    if a.verify().is_err() || b.verify().is_err() {
        return CheckpointRelation::InvalidSignature;
    }
    // Order by (timestamp, tree_size), not timestamp alone. Two
    // checkpoints in the same millisecond are routine for an agent that
    // appends and checkpoints quickly, and ordering by timestamp alone
    // made the verdict depend on argument order: compare(small, big)
    // returned Unproven while compare(big, small) returned Rollback -- a
    // false accusation of the most serious kind. Logs only grow, so on a
    // tie the smaller tree is the earlier one. Rollback now fires only
    // when a STRICTLY later timestamp carries a strictly smaller tree.
    let (earlier, later) = if (a.timestamp_ms, a.tree_size) <= (b.timestamp_ms, b.tree_size) {
        (a, b)
    } else {
        (b, a)
    };
    if earlier.tree_size == later.tree_size {
        return if normalize_hex(&earlier.root_hash) == normalize_hex(&later.root_hash) {
            CheckpointRelation::Identical
        } else {
            CheckpointRelation::Diverged
        };
    }
    if later.tree_size < earlier.tree_size {
        return CheckpointRelation::Rollback;
    }
    // later is larger: must prove it extends earlier.
    let Some(p) = proof else {
        return CheckpointRelation::Unproven;
    };
    let (Ok(r1), Ok(r2)) = (
        hex::decode(&earlier.root_hash),
        hex::decode(&later.root_hash),
    ) else {
        return CheckpointRelation::Unproven;
    };
    let (Ok(r1), Ok(r2)) = (<[u8; 32]>::try_from(r1), <[u8; 32]>::try_from(r2)) else {
        return CheckpointRelation::Unproven;
    };
    if witness_log_core::merkle::verify_consistency(earlier.tree_size, &r1, later.tree_size, &r2, p)
    {
        CheckpointRelation::Extends
    } else {
        CheckpointRelation::Unproven
    }
}

#[cfg(test)]
mod registry_scale_tests {
    //! Found by the 1,000-agent swarm against a 100-witness network: a
    //! fraction of the directory is the wrong count gate once the
    //! directory is a registry, and one-per-operator selection left most
    //! of the network idle.
    use super::*;
    use rand::rngs::OsRng;
    use witness_log_core::identity::IdentityKeypair;

    fn big_directory(ops: usize, per_op: usize) -> (WitnessDirectory, Vec<SigningKey>) {
        let mut d = WitnessDirectory::default();
        let mut keys = Vec::new();
        for o in 0..ops {
            for w in 0..per_op {
                let k = SigningKey::generate(&mut OsRng);
                d.witnesses.push(WitnessEntry {
                    name: format!("op{o}/w{w}"),
                    operator_org: format!("Operator {o}"),
                    url: format!("https://op{o}.example/w{w}"),
                    pubkey: hex::encode(k.verifying_key().to_bytes()),
                    runtime: WitnessRuntime::Agent,
                    compute_provider: Some(format!("cloud-{o}")),
                    is_project_operated: false,
                });
                keys.push(k);
            }
        }
        (d, keys)
    }

    #[test]
    fn select_witnesses_fills_round_robin_after_one_per_operator() {
        let (d, _) = big_directory(4, 25);
        let diverse = select_diverse_witnesses(&d, &hex::encode([7u8; 32]), 8, false);
        assert_eq!(diverse.len(), 4, "one per operator");
        let picked = select_witnesses(&d, &hex::encode([7u8; 32]), 8, false);
        assert_eq!(picked.len(), 8);
        let mut per_op = std::collections::HashMap::new();
        for w in &picked {
            *per_op.entry(w.operator_org.clone()).or_insert(0) += 1;
        }
        assert!(
            per_op.values().all(|&n| n == 2),
            "two per operator: {per_op:?}"
        );
        let distinct: HashSet<_> = picked.iter().map(|w| &w.pubkey).collect();
        assert_eq!(distinct.len(), 8, "no witness twice");
        assert_eq!(
            select_witnesses(&d, &hex::encode([7u8; 32]), 500, false).len(),
            100
        );
    }

    #[test]
    fn selection_spreads_subjects_across_each_operators_witnesses() {
        let (d, _) = big_directory(4, 25);
        let mut used: HashSet<String> = HashSet::new();
        let mut first: Option<Vec<String>> = None;
        for i in 0..400u32 {
            let subject = hex::encode(leaf_hash(&i.to_be_bytes()));
            let picked: Vec<String> = select_witnesses(&d, &subject, 8, false)
                .iter()
                .map(|w| w.pubkey.clone())
                .collect();
            if i == 0 {
                first = Some(picked.clone());
            }
            used.extend(picked);
        }
        assert_eq!(
            used.len(),
            100,
            "400 subjects must reach every witness, not the same eight"
        );
        // Deterministic per subject: the same agent picks the same witnesses every run.
        let subject = hex::encode(leaf_hash(&0u32.to_be_bytes()));
        let again: Vec<String> = select_witnesses(&d, &subject, 8, false)
            .iter()
            .map(|w| w.pubkey.clone())
            .collect();
        assert_eq!(first.unwrap(), again);
    }

    #[test]
    fn min_receipts_gate_reaches_witnessed_where_the_fraction_cannot() {
        let (d, keys) = big_directory(4, 25);
        let id = IdentityKeypair::generate();
        let key = SigningKey::from_bytes(&id.to_bytes());
        let mut log = witness_log_core::log::WitnessLog::resume(id, 0);
        log.append_intent(b"x");
        let sth = log.checkpoint(&key);
        // Eight cosignatures, two per operator, as select_witnesses would arrange.
        let picked = select_witnesses(&d, &log.identity_pubkey_hex(), 8, false);
        let receipts: Vec<WitnessReceipt> = picked
            .iter()
            .map(|w| {
                let k = keys
                    .iter()
                    .find(|k| hex::encode(k.verifying_key().to_bytes()) == w.pubkey)
                    .unwrap();
                WitnessReceipt::sign(k, &sth, 1_000)
            })
            .collect();
        let mut dossier = Dossier::from_log(&log, sth);
        dossier.witness_receipts = receipts;
        let ident = log.identity_pubkey_hex();
        let fraction = dossier.verify(
            0.66,
            &VerifyContext {
                expected_identity_pubkey: Some(&ident),
                trusted_directory: Some(&d),
                min_receipts: None,
                revocations: &[],
                known_heads: &[],
                evidence: &[],
                subject_org: None,
                accept_fleet_anchor: false,
            },
        );
        assert_eq!(
            fraction.verdict,
            Verdict::ConsistentUnwitnessed,
            "8/100 < 66%"
        );
        assert_eq!(
            fraction.quorum.as_ref().unwrap().count_gate,
            "fraction >= 0.66"
        );
        let absolute = dossier.verify(
            0.66,
            &VerifyContext {
                expected_identity_pubkey: Some(&ident),
                trusted_directory: Some(&d),
                min_receipts: Some(4),
                revocations: &[],
                known_heads: &[],
                evidence: &[],
                subject_org: None,
                accept_fleet_anchor: false,
            },
        );
        assert_eq!(absolute.verdict, Verdict::Witnessed);
        assert_eq!(absolute.quorum.as_ref().unwrap().count_gate, "count >= 4");
        let too_few = dossier.verify(
            0.0,
            &VerifyContext {
                expected_identity_pubkey: Some(&ident),
                trusted_directory: Some(&d),
                min_receipts: Some(9),
                revocations: &[],
                known_heads: &[],
                evidence: &[],
                subject_org: None,
                accept_fleet_anchor: false,
            },
        );
        assert_eq!(
            too_few.verdict,
            Verdict::ConsistentUnwitnessed,
            "absolute gate still binds"
        );
    }
}
