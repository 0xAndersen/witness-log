//! The developer-facing entry point. `WitnessLog` wires together identity,
//! the Merkle tree, redaction, and checkpointing behind a small API surface
//! — see README.md for the three-line quickstart this is designed around.

use crate::identity::{IdentityKeypair, KeyBindingStatement, SessionKeypair};
use crate::leaf::{AuthorizationEventKind, HandoffDirection, Leaf, LeafType};
use crate::merkle::{leaf_hash, MerkleTree};
use crate::redaction::{SaltManager, SaltStore};
use crate::sth::{SignedTreeHead, SthError};
use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

/// Typed reasons `verify_continuity` can fail, so callers (including
/// language bindings) can distinguish "the signature itself is bad" from
/// "the signature is fine but doesn't match this log's actual state" —
/// these call for different responses in most integrations.
#[derive(Debug, Error)]
pub enum VerifyError {
    #[error("checkpoint signature invalid: {0}")]
    BadSignature(#[from] SthError),
    #[error("checkpoint tree_size {checkpoint} does not match log size {actual}")]
    SizeMismatch { checkpoint: u64, actual: u64 },
    #[error("checkpoint root does not match recomputed root — log may have been tampered with")]
    RootMismatch,
}

pub struct WitnessLog {
    identity: IdentityKeypair,
    session: SessionKeypair,
    session_number: u64,
    binding: KeyBindingStatement,
    /// Bindings from EARLIER sessions of this same log, oldest first.
    ///
    /// Session keys are ephemeral and never persisted, so after a
    /// restart the old session key is gone forever — but leaves it
    /// signed are still in the log, and a verifier checking that every
    /// leaf traces to an authorized session needs the binding that
    /// authorized it. Without this, any log that has ever restarted
    /// produces a dossier whose pre-restart leaves have no covering
    /// binding, and verification returns `Diverged` — "evidence of
    /// tampering" — for an agent that merely rebooted.
    ///
    /// Found by the 1,000-agent cohort simulation, where 10% of agents
    /// followed a crash-restart profile and every one of them was
    /// flagged as forged.
    prior_bindings: Vec<KeyBindingStatement>,
    tree: MerkleTree,
    leaves: Vec<Leaf>,
    salts: Box<dyn SaltStore>,
}

/// On-disk snapshot format for `save_snapshot` / `load_snapshot`. Not
/// exported — callers interact with it only through those two methods, so
/// the shape can evolve without being part of the crate's public API.
#[derive(Serialize, Deserialize)]
struct LogSnapshot {
    format_version: u8,
    identity_bytes_hex: String,
    session_number: u64,
    leaves: Vec<Leaf>,
    /// All bindings this log knows about, oldest first, including the
    /// one for the session that wrote the snapshot. `serde(default)` so
    /// snapshots written before this field existed still load — they
    /// simply carry no history, which is the honest representation of
    /// what they recorded.
    #[serde(default)]
    key_bindings: Vec<KeyBindingStatement>,
}

/// Internal grouping for `WitnessLog::append`'s parameters. Not exported —
/// this exists purely so adding a field to support a new leaf type (as
/// AuthorizationEvent just did) means adding one struct field instead of
/// inserting a new positional parameter into every call site and hoping
/// none get shuffled. Each public `append_*` method builds one of these
/// and fills in only the fields its leaf type actually uses.
struct AppendArgs<'a> {
    leaf_type: LeafType,
    payload: &'a [u8],
    redacted_index: Option<u64>,
    revoked_identity: Option<String>,
    handoff_direction: Option<HandoffDirection>,
    counterparty_pubkey: Option<String>,
    handoff_state_hash: Option<String>,
    authorization_event_kind: Option<AuthorizationEventKind>,
    authorization_scope_hash: Option<String>,
    anchor_url: Option<String>,
    anchor_proof_json: Option<String>,
    anchor_proof_hash: Option<String>,
}

impl<'a> AppendArgs<'a> {
    fn simple(leaf_type: LeafType, payload: &'a [u8]) -> Self {
        Self {
            leaf_type,
            payload,
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
}

fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let out: [u8; 32] = hasher.finalize().into();
    hex::encode(out)
}

/// One leaf with its proof of inclusion in a specific checkpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProvenLeaf {
    pub leaf: Leaf,
    pub inclusion_proof: Vec<crate::merkle::Hash>,
}

/// A partial, verifiable export: see `WitnessLog::evidence_window`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceWindow {
    pub identity_pubkey: String,
    pub checkpoint: SignedTreeHead,
    pub entries: Vec<ProvenLeaf>,
    pub key_bindings: Vec<KeyBindingStatement>,
}

impl EvidenceWindow {
    /// Verify every entry against the checkpoint. Returns the indices of
    /// any entries whose proof fails; empty means the window is sound.
    pub fn verify(&self) -> Result<(), Vec<u64>> {
        if self.checkpoint.verify().is_err() {
            return Err(self.entries.iter().map(|e| e.leaf.index).collect());
        }
        let Ok(root_vec) = hex::decode(&self.checkpoint.root_hash) else {
            return Err(self.entries.iter().map(|e| e.leaf.index).collect());
        };
        let Ok(root) = <[u8; 32]>::try_from(root_vec) else {
            return Err(self.entries.iter().map(|e| e.leaf.index).collect());
        };
        let bad: Vec<u64> = self
            .entries
            .iter()
            .filter(|e| {
                !crate::merkle::verify_inclusion(
                    &leaf_hash(&e.leaf.canonical_bytes()),
                    e.leaf.index,
                    self.checkpoint.tree_size,
                    &e.inclusion_proof,
                    &root,
                )
            })
            .map(|e| e.leaf.index)
            .collect();
        if bad.is_empty() {
            Ok(())
        } else {
            Err(bad)
        }
    }
}

impl WitnessLog {
    /// Start a new log for a freshly generated identity. Most callers want
    /// `resume` instead, so an identity persists across process restarts.
    pub fn new() -> Self {
        let identity = IdentityKeypair::generate();
        Self::resume(identity, 0)
    }

    /// Resume logging under a persistent identity key, generating a fresh
    /// ephemeral session key for this process lifecycle and signing a
    /// binding statement linking the two. `session_number` should be
    /// incremented by the caller each time a process restarts under the
    /// same identity (e.g. persisted alongside the identity key bytes, or
    /// use `save_snapshot`/`load_snapshot` which do this for you).
    pub fn resume(identity: IdentityKeypair, session_number: u64) -> Self {
        Self::resume_inner(identity, session_number, None, Box::new(SaltManager::new()))
    }

    /// Like `resume`, but the session binding expires `ttl_ms` milliseconds
    /// from now — see `KeyBindingStatement::verify_valid_at`. Useful when a
    /// verifier should be able to tell a stale, long-abandoned session
    /// apart from a live one without you having to issue an explicit
    /// revocation for routine session turnover.
    pub fn resume_with_ttl(identity: IdentityKeypair, session_number: u64, ttl_ms: u64) -> Self {
        // Saturate: a "never expires" caller passing u64::MAX must not
        // panic (no-panic contract) or wrap to the past.
        let not_after = now_ms().saturating_add(ttl_ms);
        Self::resume_inner(
            identity,
            session_number,
            Some(not_after),
            Box::new(SaltManager::new()),
        )
    }

    /// Like `resume`, but with a custom `SaltStore` instead of the default
    /// in-memory one. See `SaltStore`'s doc comment for when this matters —
    /// most callers should just use `resume`.
    pub fn resume_with_salt_store(
        identity: IdentityKeypair,
        session_number: u64,
        salts: Box<dyn SaltStore>,
    ) -> Self {
        Self::resume_inner(identity, session_number, None, salts)
    }

    fn resume_inner(
        identity: IdentityKeypair,
        session_number: u64,
        not_after_ms: Option<u64>,
        salts: Box<dyn SaltStore>,
    ) -> Self {
        let session = SessionKeypair::generate();
        let now = now_ms();
        let binding =
            identity.bind_session(&session.verifying_key(), session_number, now, not_after_ms);
        Self {
            prior_bindings: Vec::new(),
            identity,
            session,
            session_number,
            binding,
            tree: MerkleTree::new(),
            leaves: Vec::new(),
            salts,
        }
    }

    pub fn identity_pubkey_hex(&self) -> String {
        self.identity.public_hex()
    }

    /// Whether `forget(index)` would do anything: the leaf exists, carries
    /// a payload, and its salt is still held by this log's salt store.
    pub fn can_forget(&self, index: u64) -> bool {
        self.salts.has_salt(index)
    }

    /// Replace the salt store. Used by `JournaledLog::resume` to attach the
    /// persisted salts after replay; the store must already hold exactly
    /// the salts of the live, unredacted leaves.
    pub(crate) fn set_salt_store(&mut self, salts: Box<dyn SaltStore>) {
        self.salts = salts;
    }

    pub(crate) fn sync_salts(&mut self) -> std::io::Result<()> {
        self.salts.sync()
    }

    pub(crate) fn take_salt_error(&mut self) -> Option<std::io::Error> {
        self.salts.take_error()
    }

    /// Raw identity key bytes, for persistence across process restarts by
    /// the embedding application (e.g. language bindings). Treat this like
    /// any other private key material — the caller is responsible for
    /// storing it safely (OS keystore, encrypted file, HSM, etc.).
    pub fn identity_bytes(&self) -> [u8; 32] {
        self.identity.to_bytes()
    }

    /// Every key binding this log knows about, oldest first, ending with
    /// the current session's.
    ///
    /// **This, not `current_binding`, is what a dossier should carry.** A
    /// log that has restarted holds leaves authored by session keys that
    /// no longer exist; supplying only the current binding leaves those
    /// leaves uncovered and verification reports `Diverged`. See
    /// `prior_bindings`.
    pub fn all_bindings(&self) -> Vec<KeyBindingStatement> {
        let mut out = self.prior_bindings.clone();
        out.push(self.binding.clone());
        out
    }

    pub fn current_binding(&self) -> &KeyBindingStatement {
        &self.binding
    }

    pub fn append_intent(&mut self, payload: &[u8]) -> u64 {
        self.append(AppendArgs::simple(LeafType::ActiveIntent, payload))
    }

    pub fn append_result(&mut self, payload: &[u8]) -> u64 {
        self.append(AppendArgs::simple(LeafType::ActiveResult, payload))
    }

    pub fn append_memory(&mut self, payload: &[u8]) -> u64 {
        self.append(AppendArgs::simple(LeafType::PassiveMemory, payload))
    }

    /// Commit this agent's side of a context/state handoff: "I sent
    /// `state_payload` to the agent identified by
    /// `counterparty_identity_pubkey`." The receiving agent should
    /// independently call `append_handoff_received` with the same payload
    /// in its own log — neither side needs access to the other's log, or
    /// any shared mutable state, at write time. The binding is checked
    /// later via `verify_handoff_binding`, by comparing the two
    /// independently-made commitments. See SPEC.md §3.1.
    pub fn append_handoff_sent(
        &mut self,
        state_payload: &[u8],
        counterparty_identity_pubkey: &str,
    ) -> u64 {
        self.append_handoff(
            HandoffDirection::Sent,
            state_payload,
            counterparty_identity_pubkey,
        )
    }

    /// The receiving side of a handoff — see `append_handoff_sent`.
    pub fn append_handoff_received(
        &mut self,
        state_payload: &[u8],
        counterparty_identity_pubkey: &str,
    ) -> u64 {
        self.append_handoff(
            HandoffDirection::Received,
            state_payload,
            counterparty_identity_pubkey,
        )
    }

    fn append_handoff(
        &mut self,
        direction: HandoffDirection,
        state_payload: &[u8],
        counterparty_identity_pubkey: &str,
    ) -> u64 {
        // Deliberately unsalted, unlike payload_hash: this is a permanent
        // cross-log comparison key, not a redactable secret. See
        // `Leaf::handoff_state_hash`'s doc comment.
        let state_hash = sha256_hex(state_payload);
        self.append(AppendArgs {
            leaf_type: LeafType::HandoffAttestation,
            payload: state_payload,
            redacted_index: None,
            revoked_identity: None,
            handoff_direction: Some(direction),
            counterparty_pubkey: Some(counterparty_identity_pubkey.to_string()),
            handoff_state_hash: Some(state_hash),
            authorization_event_kind: None,
            authorization_scope_hash: None,
            anchor_url: None,
            anchor_proof_json: None,
            anchor_proof_hash: None,
        })
    }

    /// Commit this agent's side of a delegation/authorization change: e.g.
    /// "I granted `scope_description` to the agent identified by
    /// `counterparty_identity_pubkey`." Logging-only — this records that
    /// the event happened and lets both sides' logs later agree on what
    /// was granted; it does not mint, evaluate, or enforce anything. The
    /// counterparty should independently log the paired kind (see
    /// `AuthorizationEventKind::expected_counterparty_kind`) in its own
    /// log. See SPEC.md §3.2 and `verify_authorization_binding`.
    pub fn append_authorization_event(
        &mut self,
        kind: AuthorizationEventKind,
        scope_description: &[u8],
        counterparty_identity_pubkey: &str,
    ) -> u64 {
        let scope_hash = sha256_hex(scope_description);
        self.append(AppendArgs {
            leaf_type: LeafType::AuthorizationEvent,
            payload: scope_description,
            redacted_index: None,
            revoked_identity: None,
            handoff_direction: None,
            counterparty_pubkey: Some(counterparty_identity_pubkey.to_string()),
            handoff_state_hash: None,
            authorization_event_kind: Some(kind),
            authorization_scope_hash: Some(scope_hash),
            anchor_url: None,
            anchor_proof_json: None,
            anchor_proof_hash: None,
        })
    }

    /// Record an external anchor for the current checkpoint. `anchor_url`
    /// is where the anchor proof can be fetched (e.g. a Rekor entry URL
    /// or RFC 3161 TSA endpoint). `anchor_proof_json` is the full response
    /// from that external service, stored verbatim. The URL alone is what
    /// goes into `canonical_bytes`; the proof is separately verifiable.
    ///
    /// Call this after submitting the current checkpoint to Rekor (or any
    /// compatible external timestamp service) and receiving its inclusion
    /// proof. The leaf commits "at this point in the log, checkpoint
    /// existence was independently anchored at this URL."
    pub fn append_external_anchor(&mut self, anchor_url: &str, anchor_proof_json: &str) -> u64 {
        // The URL alone was previously the only committed field; the
        // proof content itself (anchor_proof_json) was freely swappable
        // after the fact -- a verifier fetching the URL later could be
        // shown different content than what was originally anchored,
        // with no way to detect it. See the pre-launch review, finding
        // 17, and SPEC.md §3.3.
        let anchor_proof_hash = sha256_hex(anchor_proof_json.as_bytes());
        self.append(AppendArgs {
            leaf_type: LeafType::ExternalAnchor,
            payload: anchor_url.as_bytes(), // salted for GDPR consistency
            redacted_index: None,
            revoked_identity: None,
            handoff_direction: None,
            counterparty_pubkey: None,
            handoff_state_hash: None,
            authorization_event_kind: None,
            authorization_scope_hash: None,
            anchor_url: Some(anchor_url.to_string()),
            anchor_proof_json: Some(anchor_proof_json.to_string()),
            anchor_proof_hash: Some(anchor_proof_hash),
        })
    }

    /// GDPR/CCPA right-to-be-forgotten. Appends a 0x03 Redaction leaf and
    /// deletes the salt for `target_index`, permanently, from this log's
    /// salt store. Tree continuity for every other leaf is untouched.
    pub fn forget(&mut self, target_index: u64) -> bool {
        if !self.salts.has_salt(target_index) {
            return false;
        }
        self.salts.forget(target_index);
        self.append(AppendArgs {
            leaf_type: LeafType::Redaction,
            payload: b"",
            redacted_index: Some(target_index),
            revoked_identity: None,
            handoff_direction: None,
            counterparty_pubkey: None,
            handoff_state_hash: None,
            authorization_event_kind: None,
            authorization_scope_hash: None,
            anchor_url: None,
            anchor_proof_json: None,
            anchor_proof_hash: None,
        });
        true
    }

    fn append(&mut self, args: AppendArgs<'_>) -> u64 {
        let index = self.tree.size();
        // Markers (0x03 Redaction, 0x04 KeyRevocation) carry no payload and
        // commit the all-zero hash. Every other leaf is salted, including
        // one whose payload happens to be empty: §8 defines payload_hash
        // for the empty payload (corpus vector 11, case "empty"), and a
        // constant hash would otherwise reveal which entries were empty
        // and leave them with nothing to forget.
        let is_marker = matches!(
            args.leaf_type,
            LeafType::Redaction | LeafType::KeyRevocation
        );
        let payload_hash = if is_marker {
            [0u8; 32]
        } else {
            self.salts.commit(index, args.payload)
        };
        // Clamp against the previous leaf's timestamp rather than trusting
        // the wall clock to be monotone. It isn't, reliably: an NTP step
        // correction, a VM live-migration, a laptop suspend/resume, or a
        // container on an overcommitted host can all step the clock
        // backwards by anywhere from microseconds to seconds. Without
        // this clamp, a single such step during otherwise honest
        // operation would produce a leaf sequence that fails
        // validate_sequence's non-decreasing-timestamp check -- which
        // Dossier::verify reports as Diverged, the same verdict a
        // genuinely fabricated dossier gets, with no way to distinguish
        // "this log was tampered with" from "this host's clock hiccuped
        // once." Clamping here means validate_sequence's invariant is
        // true by construction for any log built through this API: the
        // check still catches genuine post-hoc timestamp tampering (an
        // attacker editing a leaf's timestamp after the fact, disjoint
        // from anything this process ever wrote), while never firing on
        // an honest clock. See the second-round review, finding 02 (POC A).
        let observed_now = now_ms();
        let previous_timestamp = self.leaves.last().map(|l| l.timestamp_ms).unwrap_or(0);
        let timestamp_ms = observed_now.max(previous_timestamp);
        let leaf = Leaf {
            index,
            leaf_type: args.leaf_type.tag(),
            timestamp_ms,
            session_pubkey: self.session.public_hex(),
            payload_hash: hex::encode(payload_hash),
            redacted_index: args.redacted_index,
            revoked_identity: args.revoked_identity,
            handoff_direction: args.handoff_direction,
            counterparty_pubkey: args.counterparty_pubkey,
            handoff_state_hash: args.handoff_state_hash,
            authorization_event_kind: args.authorization_event_kind,
            authorization_scope_hash: args.authorization_scope_hash,
            anchor_url: args.anchor_url,
            anchor_proof_json: args.anchor_proof_json,
            anchor_proof_hash: args.anchor_proof_hash,
        };
        let h = leaf_hash(&leaf.canonical_bytes());
        self.tree.append(h);
        self.leaves.push(leaf);
        index
    }

    /// Produce a checkpoint (Signed Tree Head) over the current root,
    /// signed by the *identity* key — not the session key — so the
    /// checkpoint remains verifiable even after this process's session
    /// ends. This is the artifact witnesses countersign.
    pub fn checkpoint(&self, identity_signing_key: &SigningKey) -> SignedTreeHead {
        SignedTreeHead::sign(
            identity_signing_key,
            self.tree.size(),
            &self.tree.root(),
            now_ms(),
        )
    }

    /// This log's current head as a C2SP checkpoint, ready to sign and
    /// submit to a third-party witness (see `c2sp` and the
    /// `tlog-witness` protocol).
    ///
    /// `origin` is a stable log identifier, RECOMMENDED to be a
    /// schema-less URL such as `agents.example.com/agent-42`. Publish
    /// the mapping from that origin to this log's identity key so
    /// witnesses and verifiers can check it.
    ///
    /// Without this, obtaining a C2SP checkpoint meant rebuilding the
    /// Merkle tree by hand — six lines that every integrator wrote
    /// identically and could get subtly wrong.
    pub fn c2sp_checkpoint(&self, origin: &str) -> crate::c2sp::Checkpoint {
        crate::c2sp::Checkpoint {
            origin: origin.to_string(),
            tree_size: self.tree.size(),
            root_hash: self.tree.root(),
            extensions: Vec::new(),
        }
    }

    /// Inclusion proof that leaf `index` is in this log's current tree.
    /// Pair with `checkpoint()` to answer "prove this specific action was
    /// logged" — the single most common regulator request. Previously
    /// required rebuilding the Merkle tree by hand.
    ///
    /// Returns `None` if `index` is out of range.
    pub fn inclusion_proof(&self, index: u64) -> Option<Vec<crate::merkle::Hash>> {
        self.tree.inclusion_proof(index, self.tree.size())
    }

    /// Consistency proof from an earlier size of this log to its current
    /// size: evidence that nothing before `earlier_size` was altered or
    /// removed. Pair with the two checkpoints to answer "prove nothing was
    /// deleted between these two points in time."
    pub fn consistency_proof(&self, earlier_size: u64) -> Option<Vec<crate::merkle::Hash>> {
        self.tree.consistency_proof(earlier_size, self.tree.size())
    }

    /// A windowed evidence export: the full checkpoint, only the leaves
    /// in `range`, and an inclusion proof for each.
    ///
    /// A regulator asking "show me Q3 only" cannot be given a slice of
    /// leaves — a subset doesn't reproduce the root and so isn't
    /// verifiable. Nor should they be given everything, which is
    /// over-disclosure. This is the artifact that is both: each leaf is
    /// individually proven against the signed checkpoint, and nothing
    /// outside the window is revealed.
    pub fn evidence_window(
        &self,
        range: std::ops::Range<u64>,
        identity_signing_key: &SigningKey,
    ) -> EvidenceWindow {
        let checkpoint = self.checkpoint(identity_signing_key);
        let size = self.tree.size();
        // Clamp to the tree before iterating: `0..u64::MAX` must cost one
        // pass over the leaves, not 2^64 filter calls.
        let start = range.start.min(size);
        let end = range.end.min(size);
        let entries = (start..end)
            .filter_map(|i| {
                let leaf = self.leaves.get(usize::try_from(i).ok()?)?.clone();
                let proof = self.tree.inclusion_proof(i, size)?;
                Some(ProvenLeaf {
                    leaf,
                    inclusion_proof: proof,
                })
            })
            .collect();
        EvidenceWindow {
            identity_pubkey: self.identity_pubkey_hex(),
            checkpoint,
            entries,
            key_bindings: self.all_bindings(),
        }
    }

    /// `checkpoint` signed with this log's own stored identity key, so
    /// callers (language bindings, the journal) need not carry the key
    /// bytes separately just to produce a checkpoint.
    pub fn checkpoint_self(&self) -> SignedTreeHead {
        let key = SigningKey::from_bytes(&self.identity.to_bytes());
        self.checkpoint(&key)
    }

    /// Issue a signed write receipt for the leaf at `leaf_index`: the
    /// log's commitment that this event is part of its history. Hand it
    /// to the party who submitted the event; with it, they can later
    /// prove censorship (`witness_log_network::silence_proof`) if the
    /// event vanishes from witnessed checkpoints. `None` if the index
    /// does not exist.
    pub fn write_receipt(&self, leaf_index: u64) -> Option<crate::sth::WriteReceipt> {
        let leaf = self.leaves.get(usize::try_from(leaf_index).ok()?)?;
        let key = SigningKey::from_bytes(&self.identity.to_bytes());
        // Issued at the size the leaf was appended at: the event is due in
        // every checkpoint of size > leaf_index.
        Some(crate::sth::WriteReceipt::sign(
            &key,
            &leaf.payload_hash,
            leaf_index,
            now_ms(),
        ))
    }

    pub fn tree_size(&self) -> u64 {
        self.tree.size()
    }

    pub fn root_hex(&self) -> String {
        hex::encode(self.tree.root())
    }

    pub fn leaves(&self) -> &[Leaf] {
        &self.leaves
    }

    /// Recompute the root from stored leaves and confirm it matches a given
    /// checkpoint. This is the core of `witness-log verify` — anyone holding the
    /// leaves and a checkpoint can run this without trusting this process.
    ///
    /// Recomputes from `self.leaves` on every call rather than comparing
    /// against `self.tree` (the incrementally-maintained cache). The cost
    /// is the same order as the checkpoint operation this validates.
    /// Comparing against the cache instead would mean mutating
    /// `self.leaves` directly (bypassing `append`) silently escapes
    /// detection — this method's entire purpose is to catch exactly that.
    /// See the pre-launch review, finding 15.
    pub fn verify_continuity(&self, sth: &SignedTreeHead) -> Result<(), VerifyError> {
        sth.verify()?;
        let mut rebuilt = MerkleTree::new();
        for l in &self.leaves {
            rebuilt.append(leaf_hash(&l.canonical_bytes()));
        }
        if sth.tree_size != rebuilt.size() {
            return Err(VerifyError::SizeMismatch {
                checkpoint: sth.tree_size,
                actual: rebuilt.size(),
            });
        }
        if sth.root_hash != hex::encode(rebuilt.root()) {
            return Err(VerifyError::RootMismatch);
        }
        Ok(())
    }

    /// Write identity key material + leaves to `path` as JSON, so a process
    /// restart can pick up where this log left off via `load_snapshot`.
    ///
    /// **Crash safety**: this writes to a temporary file in the same
    /// directory as `path`, fsyncs it so the bytes are durably on disk,
    /// then atomically renames it over `path`. A crash at any point before
    /// the rename leaves whatever was previously at `path` untouched — a
    /// reader can never observe a truncated or half-written snapshot file.
    /// The rename must land on the same filesystem as `path` for atomicity
    /// to hold, which is why the temp file is created as a sibling of the
    /// target rather than in a system temp directory.
    ///
    /// **Security note**: this file contains the raw identity *private*
    /// key in plain hex. Treat it exactly like any other private key file
    /// — filesystem permissions at minimum, encryption at rest if your
    /// threat model calls for it. This method does not encrypt it for you.
    ///
    /// **Salts are not included.** Leaves committed before a
    /// snapshot/restore cycle can no longer be redacted afterward, unless
    /// you supply a persistent `SaltStore` of your own through
    /// `resume_with_salt_store`. This fails safe (toward "can no longer be
    /// redacted"), never open. The journal (`JournaledLog`) persists salts
    /// in a sidecar and is the path for anything long-lived.
    pub fn save_snapshot(&self, path: &str) -> std::io::Result<()> {
        let snapshot = LogSnapshot {
            format_version: 1,
            identity_bytes_hex: hex::encode(self.identity.to_bytes()),
            session_number: self.session_number,
            leaves: self.leaves.clone(),
            key_bindings: self.all_bindings(),
        };
        // Zeroizing: this string embeds identity_bytes_hex, the raw
        // Ed25519 seed, in plaintext. Without this, the buffer is freed
        // normally at scope end -- the bytes remain in the process's
        // heap until some later allocation happens to overwrite them,
        // recoverable by a heap scan or core dump in the meantime. See
        // the pre-launch review, finding 21.
        let json: zeroize::Zeroizing<String> = zeroize::Zeroizing::new(
            serde_json::to_string_pretty(&snapshot).map_err(std::io::Error::other)?,
        );

        let target = std::path::Path::new(path);
        let dir = target.parent().filter(|p| !p.as_os_str().is_empty());
        let dir = dir.unwrap_or_else(|| std::path::Path::new("."));
        let file_name = target
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("witness-log-snapshot");
        // PID plus a random suffix: PID alone collides if two threads (or
        // two processes racing after a fork) target the same path at the
        // same moment. See the pre-launch review, finding 09.
        let rand_suffix: u64 = {
            use rand::RngCore;
            rand::rngs::OsRng.next_u64()
        };
        let tmp_path = dir.join(format!(
            ".{file_name}.tmp-{}-{rand_suffix:016x}",
            std::process::id()
        ));

        // Write + fsync the temp file BEFORE the rename. If the process
        // dies here, `path` itself is never touched — only an ignorable
        // stray `.tmp-<pid>-<rand>` file is left behind. On any error in
        // this block, clean up the partial temp file rather than leaving
        // it behind (it contains the raw identity seed).
        let write_result = (|| -> std::io::Result<()> {
            use std::io::Write;
            let mut f = std::fs::File::create(&tmp_path)?;
            // 0600: this file contains identity_bytes_hex, the raw Ed25519
            // seed. Default create() permissions are 0644 on Unix -- world-
            // readable. Any local user could read the seed and sign
            // checkpoints as this agent indefinitely. Set BEFORE writing
            // any content, closing the window where the file briefly
            // exists with default permissions. See finding 09.
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                f.set_permissions(std::fs::Permissions::from_mode(0o600))?;
            }
            f.write_all(json.as_bytes())?;
            f.sync_all()?;
            Ok(())
        })();
        if let Err(e) = write_result {
            let _ = std::fs::remove_file(&tmp_path);
            return Err(e);
        }

        // Atomic on the same filesystem: readers see either the old file
        // or the new one in full, never a partial write.
        std::fs::rename(&tmp_path, target)?;

        // fsync the parent directory too. Without this, the rename itself
        // is not guaranteed durable across a power loss: a crash right
        // after rename() can leave the directory entry pointing at the
        // OLD file (or no file at all) even though rename() returned Ok.
        // See finding 09.
        #[cfg(unix)]
        {
            if let Ok(dir_file) = std::fs::File::open(dir) {
                let _ = dir_file.sync_all();
            }
        }
        Ok(())
    }

    /// Rebuild a log from leaves replayed out of a journal (see
    /// `crate::journal`), advancing the session number like any restart.
    /// Crate-public rather than fully public: only persistence code
    /// should construct logs this way.
    ///
    /// Validates the leaf sequence before constructing anything — see
    /// `load_snapshot`'s matching fix and the second-round review,
    /// finding 04 (POC B). A journal file (which, like a snapshot,
    /// carries the raw identity seed in its header and is exactly what
    /// an operator persists and may transport) could otherwise replay a
    /// leaf with an unrecognized `leaf_type` straight into a live tree.
    pub(crate) fn from_replayed_leaves(
        identity: IdentityKeypair,
        session_number: u64,
        leaves: Vec<Leaf>,
        prior_bindings: Vec<KeyBindingStatement>,
    ) -> Result<Self, crate::leaf::LeafValidationError> {
        crate::leaf::validate_sequence(&leaves)?;
        let mut log = Self::resume(identity, session_number);
        log.prior_bindings = prior_bindings;
        let mut tree = MerkleTree::new();
        for l in &leaves {
            tree.append(leaf_hash(&l.canonical_bytes()));
        }
        log.tree = tree;
        log.leaves = leaves;
        Ok(log)
    }

    /// Current on-disk snapshot format. Bump this and add a match arm in
    /// `load_snapshot` — never silently reinterpret an old or future
    /// format under the current field layout.
    pub const SNAPSHOT_FORMAT_VERSION: u8 = 1;

    /// Restore from a snapshot written by `save_snapshot`. Increments the
    /// session number and issues a fresh session key + binding — exactly
    /// what a real process restart should do. The Merkle tree is rebuilt
    /// from the saved leaves; since leaf hashing is a pure function of leaf
    /// content (SPEC.md §3), this reproduces the exact prior root.
    pub fn load_snapshot(path: &str) -> std::io::Result<Self> {
        let json = std::fs::read_to_string(path)?;
        let snapshot: LogSnapshot = serde_json::from_str(&json)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        // format_version was carried on disk but never actually checked:
        // a future format-2 file would parse as far as serde manages
        // under format-1's field layout and then be silently
        // misinterpreted, rather than rejected. See the pre-launch
        // review, finding 20.
        if snapshot.format_version != Self::SNAPSHOT_FORMAT_VERSION {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "unsupported snapshot format_version {} (this build supports {})",
                    snapshot.format_version,
                    Self::SNAPSHOT_FORMAT_VERSION
                ),
            ));
        }
        let identity_bytes: [u8; 32] = hex::decode(&snapshot.identity_bytes_hex)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?
            .try_into()
            .map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "identity key must be 32 bytes",
                )
            })?;
        // validate_sequence's own doc comment says it MUST be called from
        // every path that ingests a full leaf sequence: dossier
        // verification, snapshot loading, journal replay. Only dossier
        // verification did. A snapshot -- exactly the kind of file an
        // operator persists and may transport between hosts -- could
        // carry an unrecognized leaf_type (violating SPEC.md §2's
        // normative MUST-reject), a duplicate index, or a non-monotonic
        // timestamp straight into a live WitnessLog with no complaint.
        // See the second-round review, finding 04 (POC B).
        crate::leaf::validate_sequence(&snapshot.leaves)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;
        let identity = IdentityKeypair::from_bytes(&identity_bytes);
        let mut log = Self::resume(identity, snapshot.session_number.saturating_add(1));
        let mut tree = MerkleTree::new();
        for l in &snapshot.leaves {
            tree.append(leaf_hash(&l.canonical_bytes()));
        }
        log.tree = tree;
        log.leaves = snapshot.leaves;
        // Carry forward every binding the snapshot recorded. Resuming
        // mints a NEW session key, so without this the leaves written by
        // the previous session have no covering binding and a verifier
        // correctly -- but uselessly -- reports Diverged.
        log.prior_bindings = snapshot.key_bindings;
        Ok(log)
    }
}

impl Default for WitnessLog {
    fn default() -> Self {
        Self::new()
    }
}

fn now_ms() -> u64 {
    // .unwrap() here would panic if the host clock is set before the Unix
    // epoch -- a panic inside a library embedded in someone's agent,
    // which is the exact failure mode the PyO3 binding converts panics
    // to exceptions specifically to avoid (and a Rust panic in library
    // code bypasses that conversion boundary entirely, since it isn't a
    // Result the caller can catch). Saturating to 0 is the honest answer
    // for a clock that predates the epoch, not a crash. See the
    // second-round review, finding 08.
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::IdentityKeypair;

    #[test]
    fn evidence_window_is_clamped_to_the_tree() {
        let identity = IdentityKeypair::generate();
        let key = SigningKey::from_bytes(&identity.to_bytes());
        let mut log = WitnessLog::resume(identity, 0);
        for i in 0..5u8 {
            log.append_intent(&[i]);
        }
        // Found by the release test: `0..u64::MAX` iterated 2^64 times.
        let all = log.evidence_window(0..u64::MAX, &key);
        assert_eq!(all.entries.len(), 5);
        assert!(all.verify().is_ok());
        let tail = log.evidence_window(3..u64::MAX, &key);
        assert_eq!(
            tail.entries
                .iter()
                .map(|e| e.leaf.index)
                .collect::<Vec<_>>(),
            vec![3, 4]
        );
        assert!(log.evidence_window(9..12, &key).entries.is_empty());
        let (hi, lo) = (4u64, 2u64);
        assert!(log.evidence_window(hi..lo, &key).entries.is_empty());
    }

    #[test]
    fn append_and_verify_continuity_succeeds() {
        let identity = IdentityKeypair::generate();
        let identity_bytes = identity.to_bytes();
        let mut log = WitnessLog::resume(identity, 0);
        log.append_intent(b"call payment_api(amount=100)");
        log.append_result(b"200 OK");

        let signing_key = SigningKey::from_bytes(&identity_bytes);
        let sth = log.checkpoint(&signing_key);
        assert!(log.verify_continuity(&sth).is_ok());
    }

    #[test]
    fn tampered_leaf_breaks_continuity() {
        let identity = IdentityKeypair::generate();
        let identity_bytes = identity.to_bytes();
        let mut log = WitnessLog::resume(identity, 0);
        log.append_intent(b"call payment_api(amount=100)");
        let signing_key = SigningKey::from_bytes(&identity_bytes);
        let sth = log.checkpoint(&signing_key);

        // Simulate tampering: mutate a stored leaf's payload hash after the
        // checkpoint was issued.
        log.leaves[0].payload_hash = hex::encode([0xffu8; 32]);

        // verify_continuity now recomputes from self.leaves on every call
        // (see finding 15), so it directly catches this rather than
        // requiring a hand-rebuilt tree to demonstrate the mismatch.
        assert!(
            matches!(log.verify_continuity(&sth), Err(VerifyError::RootMismatch)),
            "verify_continuity must itself detect tampering with self.leaves, not merely be demonstrable via a separately hand-rebuilt tree"
        );
    }

    #[test]
    fn forget_preserves_continuity_for_other_leaves() {
        let identity = IdentityKeypair::generate();
        let identity_bytes = identity.to_bytes();
        let mut log = WitnessLog::resume(identity, 0);
        log.append_intent(b"user email: alice@example.com");
        log.append_result(b"stored");
        assert!(log.forget(0));

        let signing_key = SigningKey::from_bytes(&identity_bytes);
        let sth = log.checkpoint(&signing_key);
        // Tree continuity holds — the leaf hash for index 0 is untouched;
        // only the salt needed to reconstruct its payload is gone.
        assert!(log.verify_continuity(&sth).is_ok());
    }

    #[test]
    fn verify_continuity_distinguishes_bad_signature_from_state_mismatch() {
        let identity = IdentityKeypair::generate();
        let identity_bytes = identity.to_bytes();
        let mut log = WitnessLog::resume(identity, 0);
        log.append_intent(b"a");
        let signing_key = SigningKey::from_bytes(&identity_bytes);
        let mut sth = log.checkpoint(&signing_key);

        // Case 1: tamper with the signature itself.
        let mut bad_sig = sth.clone();
        bad_sig.signature = hex::encode([0u8; 64]);
        assert!(matches!(
            log.verify_continuity(&bad_sig),
            Err(VerifyError::BadSignature(_))
        ));

        // Case 2: valid signature, but log has since grown — size mismatch.
        log.append_result(b"b");
        assert!(matches!(
            log.verify_continuity(&sth),
            Err(VerifyError::SizeMismatch { .. })
        ));

        // Case 3: re-checkpoint at the new size, then mutate a leaf's
        // content afterward. verify_continuity now recomputes from
        // self.leaves on every call, so it directly catches this.
        sth = log.checkpoint(&signing_key);
        log.leaves[0].payload_hash = hex::encode([0xaa; 32]);
        assert!(
            matches!(log.verify_continuity(&sth), Err(VerifyError::RootMismatch)),
            "verify_continuity must itself detect the mismatch, not merely be demonstrable via a separately hand-rebuilt tree"
        );
    }

    #[test]
    fn resume_with_ttl_binding_expires() {
        let identity = IdentityKeypair::generate();
        let log = WitnessLog::resume_with_ttl(identity, 0, 1); // 1ms TTL
        std::thread::sleep(std::time::Duration::from_millis(10));
        let now = now_ms();
        assert!(
            log.current_binding().verify_valid_at(now).is_err(),
            "binding should be expired well past its 1ms TTL"
        );
    }

    #[test]
    fn resume_without_ttl_binding_never_expires() {
        let identity = IdentityKeypair::generate();
        let log = WitnessLog::resume(identity, 0);
        assert!(log.current_binding().verify_valid_at(u64::MAX).is_ok());
    }

    #[test]
    fn snapshot_roundtrip_preserves_leaves_and_continuity() {
        let identity = IdentityKeypair::generate();
        let identity_bytes = identity.to_bytes();
        let mut log = WitnessLog::resume(identity, 0);
        log.append_intent(b"before restart: intent");
        log.append_result(b"before restart: result");
        let signing_key = SigningKey::from_bytes(&identity_bytes);
        let sth_before = log.checkpoint(&signing_key);

        let path = std::env::temp_dir().join(format!(
            "witness-log-snapshot-test-{}-{}.json",
            std::process::id(),
            now_ms()
        ));
        let path_str = path.to_str().unwrap();
        log.save_snapshot(path_str)
            .expect("save_snapshot should succeed");

        let restored = WitnessLog::load_snapshot(path_str).expect("load_snapshot should succeed");
        assert_eq!(restored.tree_size(), log.tree_size());
        assert_eq!(restored.root_hex(), log.root_hex());
        assert!(restored.verify_continuity(&sth_before).is_ok());
        assert_eq!(restored.identity_pubkey_hex(), log.identity_pubkey_hex());
        // Session number must have advanced, consistent with a real restart.
        assert_eq!(restored.session_number, log.session_number + 1);

        std::fs::remove_file(path_str).ok();
    }

    #[test]
    fn load_snapshot_rejects_malformed_file() {
        let path = std::env::temp_dir().join(format!("witness-log-bad-snapshot-{}.json", now_ms()));
        std::fs::write(&path, b"not valid json at all").unwrap();
        let result = WitnessLog::load_snapshot(path.to_str().unwrap());
        assert!(result.is_err());
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn snapshot_write_is_crash_safe_stray_temp_file_never_observed() {
        // Simulates "process died between writing the temp file and the
        // rename." The property under test: a reader of `path` must NEVER
        // see anything other than the last successfully-completed write —
        // a half-written or stray temp file must be invisible to
        // load_snapshot, which only ever reads the exact target path.
        let identity = IdentityKeypair::generate();
        let mut log = WitnessLog::resume(identity, 0);
        log.append_intent(b"good, committed state");

        let dir = std::env::temp_dir();
        let path = dir.join(format!("witness-log-crash-safety-test-{}.json", now_ms()));
        let path_str = path.to_str().unwrap();

        // 1. A real, successful save — this is the "old, good" state.
        log.save_snapshot(path_str)
            .expect("initial save should succeed");
        let good_root = log.root_hex();

        // 2. Simulate a crash mid-write: manually drop a stray temp file
        // with GARBAGE content next to the target, mimicking exactly what
        // save_snapshot's own temp-file step would leave behind if the
        // process died before the rename. Note we do NOT rename it.
        let stray_tmp = dir.join(format!(
            ".witness-log-crash-safety-test-{}.json.tmp-999999",
            now_ms()
        ));
        std::fs::write(
            &stray_tmp,
            b"GARBAGE: this must never be read as real state",
        )
        .unwrap();

        // 3. load_snapshot on the real path must still return the last
        // genuinely completed write, completely unaffected by the stray
        // temp file sitting next to it.
        let restored = WitnessLog::load_snapshot(path_str)
            .expect("load must succeed and ignore the stray temp file");
        assert_eq!(restored.root_hex(), good_root);

        std::fs::remove_file(&path).ok();
        std::fs::remove_file(&stray_tmp).ok();
    }

    #[test]
    fn snapshot_save_overwrite_leaves_no_stray_temp_files() {
        let identity = IdentityKeypair::generate();
        let mut log = WitnessLog::resume(identity, 0);
        log.append_intent(b"v1");
        let dir = std::env::temp_dir();
        let path = dir.join(format!("witness-log-overwrite-test-{}.json", now_ms()));
        let path_str = path.to_str().unwrap();

        log.save_snapshot(path_str).unwrap();
        log.append_intent(b"v2");
        log.save_snapshot(path_str).unwrap(); // overwrite

        let restored = WitnessLog::load_snapshot(path_str).unwrap();
        assert_eq!(
            restored.tree_size(),
            2,
            "second save must fully replace the first"
        );

        // No leftover .tmp-<pid> siblings after a successful save cycle.
        let file_name = path.file_name().unwrap().to_str().unwrap();
        let stray_count = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| {
                e.file_name()
                    .to_str()
                    .map(|n| n.starts_with(&format!(".{file_name}.tmp-")))
                    .unwrap_or(false)
            })
            .count();
        assert_eq!(
            stray_count, 0,
            "successful saves must not leave temp files behind"
        );

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn stale_root_injected_at_current_tree_size_is_rejected() {
        // A checkpoint that claims the CURRENT tree_size but carries a root
        // from an earlier point in the log's history (e.g. an operator
        // trying to pass off a stale root as current, or a corrupted/
        // truncated log that still reports the right leaf count). The
        // signature is genuinely valid — it really was signed by the
        // identity key — but it doesn't match this log's actual content.
        let identity = IdentityKeypair::generate();
        let identity_bytes = identity.to_bytes();
        let mut log = WitnessLog::resume(identity, 0);
        log.append_intent(b"leaf 0");
        log.append_intent(b"leaf 1");
        log.append_intent(b"leaf 2");
        let signing_key = SigningKey::from_bytes(&identity_bytes);
        let current_size = log.tree_size();

        // Take a stale root from an earlier point (size 1) but sign a
        // checkpoint that claims the CURRENT size (3) with that stale root
        // — this is exactly the "stale root injection" attack shape.
        let mut stale_tree = MerkleTree::new();
        stale_tree.append(leaf_hash(&log.leaves()[0].canonical_bytes()));
        let stale_root = stale_tree.root();
        let forged_sth = SignedTreeHead::sign(&signing_key, current_size, &stale_root, now_ms());

        assert!(
            matches!(log.verify_continuity(&forged_sth), Err(VerifyError::RootMismatch)),
            "a validly-signed checkpoint with a stale root at the current tree_size must be rejected"
        );
    }

    #[test]
    fn handoff_end_to_end_across_two_independent_logs() {
        // Two genuinely separate WitnessLog instances, standing in for two
        // separate agents that never share memory, a process, or any
        // synchronization primitive — exactly the "no shared mutable
        // state" constraint the design needs to satisfy.
        let mut agent_a = WitnessLog::resume(IdentityKeypair::generate(), 0);
        let mut agent_b = WitnessLog::resume(IdentityKeypair::generate(), 0);
        let a_identity = agent_a.identity_pubkey_hex();
        let b_identity = agent_b.identity_pubkey_hex();

        let handoff_payload = br#"{"conversation_state":"...","step":42}"#;

        // Each agent independently commits its own side. Neither call
        // knows anything about the other agent's log.
        let a_index = agent_a.append_handoff_sent(handoff_payload, &b_identity);
        let b_index = agent_b.append_handoff_received(handoff_payload, &a_identity);

        let a_leaf = &agent_a.leaves()[a_index as usize];
        let b_leaf = &agent_b.leaves()[b_index as usize];

        // The salted payload_hash values are expected to differ -- each
        // log salts independently. The binding must still hold via the
        // unsalted handoff_state_hash.
        assert_ne!(
            a_leaf.payload_hash, b_leaf.payload_hash,
            "sanity: independently-salted payload_hash values should not coincidentally match"
        );
        assert!(
            crate::leaf::verify_handoff_binding(&a_identity, a_leaf, &b_identity, b_leaf).is_ok()
        );
    }

    #[test]
    fn handoff_binding_fails_when_receiver_got_different_content() {
        let mut agent_a = WitnessLog::resume(IdentityKeypair::generate(), 0);
        let mut agent_b = WitnessLog::resume(IdentityKeypair::generate(), 0);
        let a_identity = agent_a.identity_pubkey_hex();
        let b_identity = agent_b.identity_pubkey_hex();

        let a_index = agent_a.append_handoff_sent(b"original state", &b_identity);
        // Simulates a tampered transport: B actually received something else.
        let b_index = agent_b.append_handoff_received(b"tampered state", &a_identity);

        let a_leaf = &agent_a.leaves()[a_index as usize];
        let b_leaf = &agent_b.leaves()[b_index as usize];
        assert!(
            crate::leaf::verify_handoff_binding(&a_identity, a_leaf, &b_identity, b_leaf).is_err(),
            "differing handoff content must fail the binding check even though both sides logged honestly"
        );
    }

    #[test]
    fn handoff_leaves_are_redactable_like_any_other_leaf() {
        // forget() is leaf_type-agnostic by design -- confirm that holds
        // for the newest leaf type too, not just the original four.
        let mut log = WitnessLog::resume(IdentityKeypair::generate(), 0);
        let index =
            log.append_handoff_sent(b"sensitive handoff content", "counterparty-pubkey-hex");
        assert!(log.forget(index));
        let identity_bytes = log.identity_bytes();
        let signing_key = SigningKey::from_bytes(&identity_bytes);
        let sth = log.checkpoint(&signing_key);
        assert!(log.verify_continuity(&sth).is_ok());
    }

    #[test]
    fn authorization_event_end_to_end_across_two_independent_logs() {
        let mut granter = WitnessLog::resume(IdentityKeypair::generate(), 0);
        let mut grantee = WitnessLog::resume(IdentityKeypair::generate(), 0);
        let granter_id = granter.identity_pubkey_hex();
        let grantee_id = grantee.identity_pubkey_hex();

        let scope = br#"{"tool":"calendar","access":"read"}"#;
        let g_index = granter.append_authorization_event(
            crate::leaf::AuthorizationEventKind::GrantedByMe,
            scope,
            &grantee_id,
        );
        let e_index = grantee.append_authorization_event(
            crate::leaf::AuthorizationEventKind::GrantedToMe,
            scope,
            &granter_id,
        );

        let g_leaf = &granter.leaves()[g_index as usize];
        let e_leaf = &grantee.leaves()[e_index as usize];
        assert!(crate::leaf::verify_authorization_binding(
            &granter_id,
            g_leaf,
            &grantee_id,
            e_leaf
        )
        .is_ok());
    }

    #[test]
    fn authorization_event_binding_fails_on_scope_mismatch() {
        let mut granter = WitnessLog::resume(IdentityKeypair::generate(), 0);
        let mut grantee = WitnessLog::resume(IdentityKeypair::generate(), 0);
        let granter_id = granter.identity_pubkey_hex();
        let grantee_id = grantee.identity_pubkey_hex();

        let g_index = granter.append_authorization_event(
            crate::leaf::AuthorizationEventKind::GrantedByMe,
            b"calendar.read",
            &grantee_id,
        );
        // Grantee's log claims a WIDER scope than the granter actually granted.
        let e_index = grantee.append_authorization_event(
            crate::leaf::AuthorizationEventKind::GrantedToMe,
            b"calendar.read+write",
            &granter_id,
        );

        let g_leaf = &granter.leaves()[g_index as usize];
        let e_leaf = &grantee.leaves()[e_index as usize];
        assert!(
            crate::leaf::verify_authorization_binding(&granter_id, g_leaf, &grantee_id, e_leaf)
                .is_err(),
            "a claimed scope wider than what was actually granted must fail the binding check"
        );
    }
}

#[cfg(all(test, unix))]
mod perm_regression_tests {
    use super::*;
    use crate::identity::IdentityKeypair;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn save_snapshot_is_not_world_or_group_readable() {
        let identity = IdentityKeypair::generate();
        let mut log = WitnessLog::resume(identity, 0);
        log.append_intent(b"perm check");
        let path = std::env::temp_dir()
            .join(format!(
                "witness-log-permcheck-snap-{}.json",
                std::process::id()
            ))
            .to_str()
            .unwrap()
            .to_string();
        log.save_snapshot(&path).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "snapshot containing the raw identity seed must be 0600, got {mode:o}"
        );
        std::fs::remove_file(&path).ok();
    }
}
