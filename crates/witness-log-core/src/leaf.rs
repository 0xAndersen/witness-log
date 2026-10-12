//! Leaf schema. Every event appended to an WitnessLog log is one of these seven
//! kinds. The numeric tag is part of the wire format (see /spec/SPEC.md) and
//! MUST NOT change once published — it is hashed into every leaf.

use serde::{Deserialize, Serialize};

/// The `payload_hash` of a marker leaf (0x03, 0x04): 32 zero bytes, hex.
pub const ZERO_HASH_HEX: &str = "0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum LeafType {
    /// General contextual memory inserts (non-actionable context an agent stored).
    PassiveMemory = 0x00,
    /// Intercepted tool-call inputs / LLM action prompts — what the agent *intended* to do.
    ActiveIntent = 0x01,
    /// Tool execution results / API response payloads — what actually happened.
    ActiveResult = 0x02,
    /// GDPR/CCPA tombstone marker: the salt for `redacted_index` has been
    /// permanently deleted. The leaf hash at that index remains in the tree;
    /// the payload behind it is no longer reconstructable.
    Redaction = 0x03,
    /// Marks an identity key as revoked as of this leaf. Leaves signed by
    /// that key prior to this point remain valid; none after do.
    KeyRevocation = 0x04,
    /// One side's independent commitment to a context/state handoff between
    /// two agents — see `HandoffDirection` and SPEC.md §3.1 for how two
    /// independently-logged attestations (sender's and receiver's) bind to
    /// each other without either agent needing access to the other's log
    /// or any shared mutable state at write time.
    HandoffAttestation = 0x05,
    /// One side's independent commitment to a delegation/authorization
    /// change between two agents — see `AuthorizationEventKind` and
    /// SPEC.md §3.2. Deliberately logging-only: WitnessLog records that an
    /// authorization event happened and lets both sides' logs agree on
    /// what was granted; it never mints, evaluates, or enforces the
    /// authorization itself. That remains the job of whatever
    /// authorization system (OAuth, UCAN, Macaroons, or otherwise) an
    /// integration already uses — see SPEC.md §1.1 on layering.
    AuthorizationEvent = 0x06,
    /// Records an external anchor for a checkpoint — a cryptographic
    /// commitment from a party entirely outside this log (a Sigstore
    /// Rekor entry, an RFC 3161 timestamp authority response, or any
    /// equivalent) that proves this checkpoint existed at a moment in
    /// time, verifiable offline via the URL in `anchor_url`. See
    /// SPEC.md §3.3. This is how independence on day one works without
    /// witness recruitment: anchor to infrastructure nobody in this
    /// project operates.
    ExternalAnchor = 0x07,
}

impl LeafType {
    pub fn tag(self) -> u8 {
        self as u8
    }

    pub fn from_tag(tag: u8) -> Option<Self> {
        match tag {
            0x00 => Some(Self::PassiveMemory),
            0x01 => Some(Self::ActiveIntent),
            0x02 => Some(Self::ActiveResult),
            0x03 => Some(Self::Redaction),
            0x04 => Some(Self::KeyRevocation),
            0x05 => Some(Self::HandoffAttestation),
            0x06 => Some(Self::AuthorizationEvent),
            0x07 => Some(Self::ExternalAnchor),
            _ => None,
        }
    }
}

/// Which side of a handoff this attestation represents. The SAME leaf type
/// (0x05) is used by both the sending and receiving agent, each appending
/// independently to their own log — there's no coordination protocol, no
/// shared state, and no requirement that both sides even use WitnessLog. The
/// binding comes entirely from comparing two independently-made
/// commitments after the fact: if agent A's `Sent` attestation and agent
/// B's `Received` attestation name each other as counterparty and carry
/// the same `payload_hash`... except payload_hash alone isn't quite
/// enough, since each side salts independently (see `redaction.rs`) — see
/// SPEC.md §3.1 for the actual comparison procedure, which compares a
/// separate, unsalted `handoff_state_hash` instead.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum HandoffDirection {
    /// This log's agent was the sender: it handed state to `counterparty_pubkey`.
    Sent = 0x00,
    /// This log's agent was the receiver: it received state from `counterparty_pubkey`.
    Received = 0x01,
}

impl HandoffDirection {
    pub fn tag(self) -> u8 {
        self as u8
    }

    pub fn from_tag(tag: u8) -> Option<Self> {
        match tag {
            0x00 => Some(Self::Sent),
            0x01 => Some(Self::Received),
            _ => None,
        }
    }
}

/// Both "which side" and "what happened," combined into one field — the
/// same simplification `HandoffDirection` makes, extended to cover three
/// kinds of event instead of one. Logging-only: none of these variants
/// imply WitnessLog evaluated, minted, or enforced anything. See
/// `LeafType::AuthorizationEvent`'s doc comment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum AuthorizationEventKind {
    /// This log's agent granted scope to `counterparty_pubkey`.
    GrantedByMe = 0x00,
    /// This log's agent received a scope grant from `counterparty_pubkey`.
    GrantedToMe = 0x01,
    /// This log's agent revoked `counterparty_pubkey`'s scope.
    RevokedByMe = 0x02,
    /// This log's agent had its scope revoked by `counterparty_pubkey`.
    RevokedToMe = 0x03,
    /// This log's agent changed `counterparty_pubkey`'s scope without a
    /// full grant or revoke (e.g. narrowing or widening an existing grant).
    ScopeChangedByMe = 0x04,
    /// This log's agent's scope was changed by `counterparty_pubkey`.
    ScopeChangedToMe = 0x05,
}

impl AuthorizationEventKind {
    pub fn tag(self) -> u8 {
        self as u8
    }

    pub fn from_tag(tag: u8) -> Option<Self> {
        match tag {
            0x00 => Some(Self::GrantedByMe),
            0x01 => Some(Self::GrantedToMe),
            0x02 => Some(Self::RevokedByMe),
            0x03 => Some(Self::RevokedToMe),
            0x04 => Some(Self::ScopeChangedByMe),
            0x05 => Some(Self::ScopeChangedToMe),
            _ => None,
        }
    }

    /// The kind an honest counterparty's own leaf should carry, for
    /// binding verification — e.g. my `GrantedByMe` should be matched by
    /// their `GrantedToMe`. Used by `verify_authorization_binding`.
    pub fn expected_counterparty_kind(self) -> Self {
        match self {
            Self::GrantedByMe => Self::GrantedToMe,
            Self::GrantedToMe => Self::GrantedByMe,
            Self::RevokedByMe => Self::RevokedToMe,
            Self::RevokedToMe => Self::RevokedByMe,
            Self::ScopeChangedByMe => Self::ScopeChangedToMe,
            Self::ScopeChangedToMe => Self::ScopeChangedByMe,
        }
    }
}

/// A single committed leaf in the log. `payload_hash` is `H(payload || salt)`
/// (see `redaction.rs`) — the raw payload itself is never stored in the tree.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Leaf {
    pub index: u64,
    pub leaf_type: u8,
    /// Unix millis, set by the local process at append time. Not
    /// independently attested — see THREAT_MODEL.md on clock trust.
    pub timestamp_ms: u64,
    /// hex-encoded Ed25519 public key of the session that authored this leaf.
    pub session_pubkey: String,
    /// SHA-256(payload || salt), hex-encoded. 32 bytes.
    pub payload_hash: String,
    /// For 0x03 Redaction leaves only: which prior leaf index is being forgotten.
    pub redacted_index: Option<u64>,
    /// For 0x04 KeyRevocation leaves only: the identity pubkey being revoked.
    pub revoked_identity: Option<String>,
    /// For 0x05 HandoffAttestation leaves only: which side of the handoff
    /// this is.
    pub handoff_direction: Option<HandoffDirection>,
    /// For 0x05 HandoffAttestation or 0x06 AuthorizationEvent leaves:
    /// hex-encoded identity pubkey of the OTHER agent involved.
    pub counterparty_pubkey: Option<String>,
    /// For 0x05 HandoffAttestation leaves only: SHA-256 of the raw
    /// state/context payload, WITHOUT a salt. This is deliberately separate
    /// from `payload_hash` (which each side salts independently and so
    /// will never match across two logs even for identical content) — this
    /// field is what a cross-log comparison actually checks. See
    /// SPEC.md §3.1. Not redactable on its own; forgetting this leaf via
    /// `WitnessLog::forget` still only removes the *salt* behind
    /// `payload_hash`, per the normal redaction mechanism — this field's
    /// value remains, by design, since the whole point of a handoff
    /// attestation is a comparable commitment, not a redactable secret.
    pub handoff_state_hash: Option<String>,
    /// For 0x06 AuthorizationEvent leaves only: which kind of event, and
    /// from which side. See `AuthorizationEventKind`.
    pub authorization_event_kind: Option<AuthorizationEventKind>,
    /// For 0x06 AuthorizationEvent leaves only: SHA-256 of the raw scope/
    /// capability description, WITHOUT a salt — same rationale as
    /// `handoff_state_hash`: this is what `verify_authorization_binding`
    /// compares across two independently-salted logs.
    pub authorization_scope_hash: Option<String>,
    /// For 0x07 ExternalAnchor leaves only: the URL where the anchor
    /// proof can be fetched and re-verified (e.g. a Rekor entry URL or
    /// an RFC 3161 TSA endpoint).
    pub anchor_url: Option<String>,
    /// For 0x07 ExternalAnchor leaves only: the anchor provider's
    /// response stored as a JSON string — self-describing and
    /// version-tolerant across providers. NOT included in
    /// `canonical_bytes` directly (it can be arbitrarily large); its
    /// SHA-256, `anchor_proof_hash`, is what's actually committed. See
    /// `anchor_proof_hash`'s doc comment.
    pub anchor_proof_json: Option<String>,
    /// SHA-256(anchor_proof_json), hex-encoded, WITHOUT a salt — same
    /// pattern as `handoff_state_hash` and `authorization_scope_hash`.
    /// This, not `anchor_url` alone, is the actual commitment: earlier
    /// revisions committed only the URL, leaving `anchor_proof_json`
    /// freely swappable after the fact — a verifier fetching the URL
    /// later could be shown different content than what the log
    /// originally anchored, with no way to detect it. See the pre-launch
    /// review, finding 17, and SPEC.md §3.3.
    pub anchor_proof_hash: Option<String>,
}

impl Leaf {
    /// Length-prefix a variable-length field: 4-byte BE length, then the
    /// bytes. Every variable-length field in this encoding goes through
    /// this helper — concatenating raw strings with no length information
    /// let two semantically different leaves hash identically (e.g.
    /// session_pubkey="aaaabbbb"+payload_hash="cccc" collided with
    /// session_pubkey="aaaa"+payload_hash="bbbbcccc"). See the pre-launch
    /// review, finding 04.
    fn push_lp(buf: &mut Vec<u8>, bytes: &[u8]) {
        buf.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
        buf.extend_from_slice(bytes);
    }

    /// Canonical bytes hashed into the Merkle tree for this leaf. Uses a
    /// fixed field order so serialization is deterministic across
    /// implementations — see SPEC.md §3.
    ///
    /// Every variable-length field is length-prefixed (`push_lp`), and
    /// every optional field — including the handoff/authorization/anchor
    /// fields that only apply to specific leaf types — is preceded by an
    /// explicit 0/1 presence byte. Earlier versions omitted both: a
    /// missing optional field contributed zero bytes rather than a
    /// presence marker, and adjacent strings were concatenated with no
    /// length information, so distinct leaves could produce identical
    /// canonical bytes and therefore identical Merkle leaf hashes. This
    /// encoding is a breaking wire-format change from the one that
    /// shipped in the earlier draft; corpus vectors were regenerated
    /// against it before this crate's first publication.
    ///
    /// The `handoff_*` and `authorization_*` fields are still only
    /// encoded when `leaf_type` matches their respective leaf type — for
    /// every other leaf type they contribute no bytes at all, preserving
    /// the property that adding a new leaf type doesn't change the
    /// encoding of leaf types that existed before it.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.push(self.leaf_type);
        buf.extend_from_slice(&self.index.to_be_bytes());
        buf.extend_from_slice(&self.timestamp_ms.to_be_bytes());
        Self::push_lp(&mut buf, self.session_pubkey.as_bytes());
        Self::push_lp(&mut buf, self.payload_hash.as_bytes());
        if let Some(r) = self.redacted_index {
            buf.push(1);
            buf.extend_from_slice(&r.to_be_bytes());
        } else {
            buf.push(0);
        }
        if let Some(ref rid) = self.revoked_identity {
            buf.push(1);
            Self::push_lp(&mut buf, rid.as_bytes());
        } else {
            buf.push(0);
        }
        if self.leaf_type == LeafType::HandoffAttestation.tag() {
            if let Some(dir) = self.handoff_direction {
                buf.push(1);
                buf.push(dir.tag());
            } else {
                buf.push(0);
            }
            if let Some(ref cp) = self.counterparty_pubkey {
                buf.push(1);
                Self::push_lp(&mut buf, cp.as_bytes());
            } else {
                buf.push(0);
            }
            if let Some(ref hsh) = self.handoff_state_hash {
                buf.push(1);
                Self::push_lp(&mut buf, hsh.as_bytes());
            } else {
                buf.push(0);
            }
        }
        if self.leaf_type == LeafType::AuthorizationEvent.tag() {
            if let Some(kind) = self.authorization_event_kind {
                buf.push(1);
                buf.push(kind.tag());
            } else {
                buf.push(0);
            }
            if let Some(ref cp) = self.counterparty_pubkey {
                buf.push(1);
                Self::push_lp(&mut buf, cp.as_bytes());
            } else {
                buf.push(0);
            }
            if let Some(ref sh) = self.authorization_scope_hash {
                buf.push(1);
                Self::push_lp(&mut buf, sh.as_bytes());
            } else {
                buf.push(0);
            }
        }
        if self.leaf_type == LeafType::ExternalAnchor.tag() {
            if let Some(ref url) = self.anchor_url {
                buf.push(1);
                Self::push_lp(&mut buf, url.as_bytes());
            } else {
                buf.push(0);
            }
            if let Some(ref h) = self.anchor_proof_hash {
                buf.push(1);
                Self::push_lp(&mut buf, h.as_bytes());
            } else {
                buf.push(0);
            }
        }
        buf
    }

    /// Structural validation independent of cryptography: is this leaf
    /// well-formed on its own terms? Does NOT check signatures, Merkle
    /// membership, or cross-leaf ordering (see `validate_sequence` for
    /// ordering). Every path that ingests leaves from outside this
    /// process — dossier verification, snapshot loading, journal replay —
    /// MUST call this (via `validate_sequence`) before trusting a leaf's
    /// contents. Previously nothing did: a leaf with a duplicate index,
    /// an unrecognized `leaf_type` tag, or a malformed `session_pubkey`
    /// verified cleanly. See the pre-launch review, finding 14, and
    /// SPEC.md §2's normative "MUST reject leaves with an unrecognized
    /// tag."
    pub fn validate(&self, expected_index: u64) -> Result<(), LeafValidationError> {
        if self.index != expected_index {
            return Err(LeafValidationError::IndexMismatch {
                expected: expected_index,
                actual: self.index,
            });
        }
        if LeafType::from_tag(self.leaf_type).is_none() {
            return Err(LeafValidationError::UnrecognizedType(self.leaf_type));
        }
        if !is_valid_hex64(&self.session_pubkey) {
            return Err(LeafValidationError::MalformedField {
                field: "session_pubkey",
                value: self.session_pubkey.clone(),
            });
        }
        if !is_valid_hex64(&self.payload_hash) {
            return Err(LeafValidationError::MalformedField {
                field: "payload_hash",
                value: self.payload_hash.clone(),
            });
        }
        let require = |present: bool, field: &'static str| -> Result<(), LeafValidationError> {
            if present {
                Ok(())
            } else {
                Err(LeafValidationError::MissingMandatoryField {
                    leaf_type: self.leaf_type,
                    field,
                })
            }
        };
        // Fields that belong to another leaf type are not committed by
        // `canonical_bytes`, so under an unchanged signed root a dossier
        // editor could add or alter them freely and anything that renders
        // them (explain, bind, the Python package) would show the edit as
        // if it were on the record. They are refused (0.4.2, review
        // round 2 L1). Markers commit the all-zero payload hash and a
        // redaction names an earlier leaf, never itself (L2).
        let forbid = |present: bool, field: &'static str| -> Result<(), LeafValidationError> {
            if present {
                Err(LeafValidationError::FieldNotApplicable {
                    leaf_type: self.leaf_type,
                    field,
                })
            } else {
                Ok(())
            }
        };
        let t = self.leaf_type;
        if t != LeafType::Redaction.tag() {
            forbid(self.redacted_index.is_some(), "redacted_index")?;
        }
        if t != LeafType::KeyRevocation.tag() {
            forbid(self.revoked_identity.is_some(), "revoked_identity")?;
        }
        if t != LeafType::HandoffAttestation.tag() {
            forbid(self.handoff_direction.is_some(), "handoff_direction")?;
            forbid(self.handoff_state_hash.is_some(), "handoff_state_hash")?;
        }
        if t != LeafType::AuthorizationEvent.tag() {
            forbid(
                self.authorization_event_kind.is_some(),
                "authorization_event_kind",
            )?;
            forbid(
                self.authorization_scope_hash.is_some(),
                "authorization_scope_hash",
            )?;
        }
        if t != LeafType::HandoffAttestation.tag() && t != LeafType::AuthorizationEvent.tag() {
            forbid(self.counterparty_pubkey.is_some(), "counterparty_pubkey")?;
        }
        if t != LeafType::ExternalAnchor.tag() {
            forbid(self.anchor_url.is_some(), "anchor_url")?;
            forbid(self.anchor_proof_json.is_some(), "anchor_proof_json")?;
            forbid(self.anchor_proof_hash.is_some(), "anchor_proof_hash")?;
        }
        if (t == LeafType::Redaction.tag() || t == LeafType::KeyRevocation.tag())
            && self.payload_hash != ZERO_HASH_HEX
        {
            return Err(LeafValidationError::InvalidField {
                field: "payload_hash (markers commit the all-zero hash)",
                value: self.payload_hash.clone(),
            });
        }
        if self.leaf_type == LeafType::Redaction.tag() {
            require(self.redacted_index.is_some(), "redacted_index")?;
            if let Some(target) = self.redacted_index {
                if target >= expected_index {
                    return Err(LeafValidationError::InvalidField {
                        field: "redacted_index (must name an earlier leaf)",
                        value: target.to_string(),
                    });
                }
            }
        }
        if self.leaf_type == LeafType::KeyRevocation.tag() {
            require(self.revoked_identity.is_some(), "revoked_identity")?;
        }
        if self.leaf_type == LeafType::HandoffAttestation.tag() {
            require(self.handoff_direction.is_some(), "handoff_direction")?;
            require(self.counterparty_pubkey.is_some(), "counterparty_pubkey")?;
            require(self.handoff_state_hash.is_some(), "handoff_state_hash")?;
        }
        if self.leaf_type == LeafType::AuthorizationEvent.tag() {
            require(
                self.authorization_event_kind.is_some(),
                "authorization_event_kind",
            )?;
            require(self.counterparty_pubkey.is_some(), "counterparty_pubkey")?;
            require(
                self.authorization_scope_hash.is_some(),
                "authorization_scope_hash",
            )?;
        }
        if self.leaf_type == LeafType::ExternalAnchor.tag() {
            require(self.anchor_url.is_some(), "anchor_url")?;
            require(self.anchor_proof_hash.is_some(), "anchor_proof_hash")?;
            // The committed value is SHA-256(anchor_proof_json). When the
            // JSON travels with the leaf it MUST be the preimage of the
            // committed hash, or a dossier could carry an anchor proof
            // the log never committed to (a swapped Rekor entry, say) and
            // every structural check would still pass. Found by an
            // outside evaluation of 0.3.3.
            if let (Some(json), Some(h)) = (&self.anchor_proof_json, &self.anchor_proof_hash) {
                use sha2::{Digest, Sha256};
                let actual = hex::encode(Sha256::digest(json.as_bytes()));
                if &actual != h {
                    return Err(LeafValidationError::AnchorProofMismatch {
                        committed: h.clone(),
                        actual,
                    });
                }
            }
            if let Some(url) = &self.anchor_url {
                if !is_valid_anchor_url(url) {
                    return Err(LeafValidationError::MalformedUrl {
                        field: "anchor_url",
                        value: url.clone(),
                    });
                }
            }
        }
        Ok(())
    }
}

/// The rule [`Leaf::validate`] applies to an ExternalAnchor's
/// `anchor_url`: an `http://` or `https://` URL. Public so writers can
/// refuse a bad URL *before* the leaf is committed: a committed leaf that
/// fails this check makes every later dossier of that log `DIVERGED`, and
/// journal replay refuses it, permanently.
pub fn is_valid_anchor_url(url: &str) -> bool {
    url.starts_with("https://") || url.starts_with("http://")
}

/// A 32-byte public key as 64 hex characters, either case. Writers
/// lowercase counterparty keys before committing them, because `bind`
/// compares the committed strings byte for byte.
pub fn is_hex_pubkey(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

fn is_valid_hex64(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum LeafValidationError {
    #[error("leaf index {actual} does not match its position {expected}")]
    IndexMismatch { expected: u64, actual: u64 },
    #[error("unrecognized leaf_type tag: 0x{0:02x}")]
    UnrecognizedType(u8),
    #[error("field `{field}` must be exactly 64 lowercase hex characters, got {value:?}")]
    MalformedField { field: &'static str, value: String },
    #[error("field `{field}` must be an http:// or https:// URL, got {value:?}")]
    MalformedUrl { field: &'static str, value: String },
    #[error("leaf_type 0x{leaf_type:02x} requires field `{field}` to be present")]
    MissingMandatoryField { leaf_type: u8, field: &'static str },
    /// A field that belongs to another leaf type is set; it would not be
    /// committed by the root, so it is refused rather than displayed.
    #[error("leaf_type 0x{leaf_type:02x} must not carry field `{field}` (it is not committed by the root)")]
    FieldNotApplicable { leaf_type: u8, field: &'static str },
    #[error("field `{field}` is invalid: {value:?}")]
    InvalidField { field: &'static str, value: String },
    #[error("anchor_proof_json does not hash to the committed anchor_proof_hash (committed {committed}, actual {actual}); the anchor proof was swapped after the leaf was committed")]
    AnchorProofMismatch { committed: String, actual: String },
}

/// Validate every leaf in sequence: each leaf structurally (`Leaf::validate`,
/// against its own position as the expected index). Call this — not
/// `Leaf::validate` leaf-by-leaf — from any path that ingests a full leaf
/// sequence: dossier verification, snapshot loading, journal replay.
///
/// Deliberately does NOT check `timestamp_ms` for monotonicity. An
/// earlier version did, and treated a decreasing timestamp as a hard
/// verification failure (`Verdict::Diverged`) — which is wrong on two
/// counts. First, `timestamp_ms` is explicitly documented elsewhere in
/// this crate (see `Leaf::timestamp_ms`'s own doc comment and
/// THREAT_MODEL.md) as self-asserted, "not independently attested" —
/// treating it as a hard structural invariant contradicts what the
/// project itself says the field is worth. Second, and more seriously:
/// wall clocks step backwards routinely in real deployments — an NTP
/// step correction, a VM live-migration, a laptop suspend/resume, a
/// container on an overcommitted host — so an entirely honest,
/// unmodified log could fail this check with zero adversary involved,
/// and once the offending timestamps are committed into leaf hashes the
/// failure is permanent and unfixable after the fact. `WitnessLog::append`
/// clamps `timestamp_ms` to be non-decreasing at write time (see
/// `log.rs`), which keeps this property true in the common case for logs
/// built through this crate's own API — but a verifier's job is to check
/// dossiers it receives, which may come from replayed old data, a second
/// implementation, or any other producer this crate cannot control. A
/// verification check this crate cannot guarantee every honest producer
/// satisfies must not be allowed to fail verification. See the
/// second-round review, finding 02 (POC A).
pub fn validate_sequence(leaves: &[Leaf]) -> Result<(), LeafValidationError> {
    for (i, l) in leaves.iter().enumerate() {
        l.validate(i as u64)?;
    }
    Ok(())
}

/// Compare two independently-made handoff attestations and confirm they
/// genuinely bind to each other. This is the entire "cryptographic
/// binding" mechanism for handoffs — there is no coordination protocol
/// and no shared state between the two agents at write time; the binding
/// is established here, after the fact, by an auditor (or either agent
/// itself) holding both leaves. See SPEC.md §3.1.
pub fn verify_handoff_binding(
    sender_identity_pubkey: &str,
    sender_leaf: &Leaf,
    receiver_identity_pubkey: &str,
    receiver_leaf: &Leaf,
) -> Result<(), String> {
    if sender_leaf.leaf_type != LeafType::HandoffAttestation.tag() {
        return Err("sender_leaf is not a HandoffAttestation leaf".into());
    }
    if receiver_leaf.leaf_type != LeafType::HandoffAttestation.tag() {
        return Err("receiver_leaf is not a HandoffAttestation leaf".into());
    }
    if sender_leaf.handoff_direction != Some(HandoffDirection::Sent) {
        return Err("sender_leaf is not marked as the Sent side".into());
    }
    if receiver_leaf.handoff_direction != Some(HandoffDirection::Received) {
        return Err("receiver_leaf is not marked as the Received side".into());
    }
    if sender_leaf.counterparty_pubkey.as_deref() != Some(receiver_identity_pubkey) {
        return Err(
            "sender's named counterparty does not match the receiver's claimed identity".into(),
        );
    }
    if receiver_leaf.counterparty_pubkey.as_deref() != Some(sender_identity_pubkey) {
        return Err(
            "receiver's named counterparty does not match the sender's claimed identity".into(),
        );
    }
    match (
        &sender_leaf.handoff_state_hash,
        &receiver_leaf.handoff_state_hash,
    ) {
        (Some(s), Some(r)) if s == r => Ok(()),
        (Some(_), Some(_)) => Err(
            "state hashes do not match — sender and receiver committed to different content".into(),
        ),
        _ => Err("one or both leaves is missing a handoff_state_hash".into()),
    }
}

/// Compare two independently-made AuthorizationEvent attestations, the
/// same way `verify_handoff_binding` does for handoffs. Logging-only, as
/// with the leaf type itself: this confirms both sides' logs agree on
/// what happened, not that either agent is actually authorized to act.
pub fn verify_authorization_binding(
    party_a_identity_pubkey: &str,
    party_a_leaf: &Leaf,
    party_b_identity_pubkey: &str,
    party_b_leaf: &Leaf,
) -> Result<(), String> {
    if party_a_leaf.leaf_type != LeafType::AuthorizationEvent.tag() {
        return Err("party_a_leaf is not an AuthorizationEvent leaf".into());
    }
    if party_b_leaf.leaf_type != LeafType::AuthorizationEvent.tag() {
        return Err("party_b_leaf is not an AuthorizationEvent leaf".into());
    }
    let (a_kind, b_kind) = match (
        party_a_leaf.authorization_event_kind,
        party_b_leaf.authorization_event_kind,
    ) {
        (Some(a), Some(b)) => (a, b),
        _ => return Err("one or both leaves is missing an authorization_event_kind".into()),
    };
    if b_kind != a_kind.expected_counterparty_kind() {
        return Err(format!(
            "mismatched event kinds: party_a is {a_kind:?}, party_b is {b_kind:?}, expected {:?}",
            a_kind.expected_counterparty_kind()
        ));
    }
    if party_a_leaf.counterparty_pubkey.as_deref() != Some(party_b_identity_pubkey) {
        return Err(
            "party_a's named counterparty does not match party_b's claimed identity".into(),
        );
    }
    if party_b_leaf.counterparty_pubkey.as_deref() != Some(party_a_identity_pubkey) {
        return Err(
            "party_b's named counterparty does not match party_a's claimed identity".into(),
        );
    }
    match (
        &party_a_leaf.authorization_scope_hash,
        &party_b_leaf.authorization_scope_hash,
    ) {
        (Some(s), Some(r)) if s == r => Ok(()),
        (Some(_), Some(_)) => Err(
            "scope hashes do not match — the two sides committed to different scope descriptions"
                .into(),
        ),
        _ => Err("one or both leaves is missing an authorization_scope_hash".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_leaf(leaf_type: LeafType) -> Leaf {
        Leaf {
            index: 0,
            leaf_type: leaf_type.tag(),
            timestamp_ms: 1000,
            session_pubkey: "session".into(),
            payload_hash: "deadbeef".into(),
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

    #[test]
    fn external_anchor_proof_json_must_be_the_committed_preimage() {
        use sha2::{Digest, Sha256};
        let hex64 = "ab".repeat(32);
        let mut l = base_leaf(LeafType::ExternalAnchor);
        l.session_pubkey = hex64.clone();
        l.payload_hash = hex64.clone();
        let proof = r#"{"logIndex":42,"integratedTime":1700000000}"#.to_string();
        l.anchor_url = Some("https://rekor.sigstore.dev/api/v1/log/entries/abc".into());
        l.anchor_proof_hash = Some(hex::encode(Sha256::digest(proof.as_bytes())));
        l.anchor_proof_json = Some(proof.clone());
        assert!(l.validate(0).is_ok());
        // Swap the proof after commitment: structurally complete, but not
        // what the log committed to.
        l.anchor_proof_json = Some(r#"{"logIndex":43,"integratedTime":1700000000}"#.into());
        assert!(matches!(
            l.validate(0),
            Err(LeafValidationError::AnchorProofMismatch { .. })
        ));
        // No JSON carried at all is still valid: the hash is the commitment.
        l.anchor_proof_json = None;
        assert!(l.validate(0).is_ok());
        // A URL that is not a URL is not an anchor.
        l.anchor_url = Some("etherscan tx 0x1234".into());
        assert!(matches!(
            l.validate(0),
            Err(LeafValidationError::MalformedUrl {
                field: "anchor_url",
                ..
            })
        ));
        // ...and the message says what is wrong, rather than demanding 64
        // hex characters of a URL (the 0.3.5 message did).
        let msg = l.validate(0).unwrap_err().to_string();
        assert!(msg.contains("http:// or https:// URL"), "{msg}");
    }

    fn matching_pair() -> (String, Leaf, String, Leaf) {
        let sender_id = "sender-identity-hex".to_string();
        let receiver_id = "receiver-identity-hex".to_string();
        let mut sent = base_leaf(LeafType::HandoffAttestation);
        sent.handoff_direction = Some(HandoffDirection::Sent);
        sent.counterparty_pubkey = Some(receiver_id.clone());
        sent.handoff_state_hash = Some("shared-state-hash".into());

        let mut received = base_leaf(LeafType::HandoffAttestation);
        received.handoff_direction = Some(HandoffDirection::Received);
        received.counterparty_pubkey = Some(sender_id.clone());
        received.handoff_state_hash = Some("shared-state-hash".into());

        (sender_id, sent, receiver_id, received)
    }

    #[test]
    fn matching_handoff_attestations_bind_successfully() {
        let (sender_id, sent, receiver_id, received) = matching_pair();
        assert!(verify_handoff_binding(&sender_id, &sent, &receiver_id, &received).is_ok());
    }

    #[test]
    fn mismatched_state_hash_fails_binding() {
        let (sender_id, sent, receiver_id, mut received) = matching_pair();
        received.handoff_state_hash = Some("a-different-state-entirely".into());
        assert!(verify_handoff_binding(&sender_id, &sent, &receiver_id, &received).is_err());
    }

    #[test]
    fn wrong_counterparty_fails_binding() {
        // Sender says it sent to receiver_id, but the leaf we're checking
        // against claims a different receiver identity than the one
        // actually passed in — simulates an attempt to misattribute a
        // handoff to the wrong counterparty.
        let (sender_id, sent, _receiver_id, received) = matching_pair();
        let impostor_receiver_id = "some-other-agent-entirely".to_string();
        assert!(
            verify_handoff_binding(&sender_id, &sent, &impostor_receiver_id, &received).is_err()
        );
    }

    #[test]
    fn wrong_direction_fails_binding() {
        // Both leaves claim to be "Sent" — not a valid sender/receiver pair.
        let (sender_id, sent, receiver_id, mut received) = matching_pair();
        received.handoff_direction = Some(HandoffDirection::Sent);
        assert!(verify_handoff_binding(&sender_id, &sent, &receiver_id, &received).is_err());
    }

    #[test]
    fn non_handoff_leaf_type_rejected() {
        let (sender_id, _sent, receiver_id, received) = matching_pair();
        let not_a_handoff = base_leaf(LeafType::ActiveIntent);
        assert!(
            verify_handoff_binding(&sender_id, &not_a_handoff, &receiver_id, &received).is_err()
        );
    }

    #[test]
    fn handoff_fields_only_affect_canonical_bytes_for_handoff_leaf_type() {
        // The core backward-compatibility guarantee: giving a NON-handoff
        // leaf handoff_* field values (which should never happen in
        // practice, since WitnessLog only sets them for 0x05 leaves) must
        // NOT change that leaf's canonical encoding. This is what keeps
        // corpus vectors 01-06 stable — see canonical_bytes' doc comment.
        let mut intent_leaf = base_leaf(LeafType::ActiveIntent);
        let bytes_without_handoff_fields = intent_leaf.canonical_bytes();

        intent_leaf.handoff_direction = Some(HandoffDirection::Sent);
        intent_leaf.counterparty_pubkey = Some("should-be-ignored".into());
        intent_leaf.handoff_state_hash = Some("should-also-be-ignored".into());
        let bytes_with_handoff_fields_but_wrong_type = intent_leaf.canonical_bytes();

        assert_eq!(
            bytes_without_handoff_fields, bytes_with_handoff_fields_but_wrong_type,
            "handoff_* fields must be ignored in canonical_bytes for any leaf_type other than HandoffAttestation"
        );
    }

    #[test]
    fn handoff_leaf_type_canonical_bytes_change_when_handoff_fields_change() {
        let mut h1 = base_leaf(LeafType::HandoffAttestation);
        h1.handoff_direction = Some(HandoffDirection::Sent);
        h1.counterparty_pubkey = Some("party-a".into());
        h1.handoff_state_hash = Some("hash-1".into());

        let mut h2 = h1.clone();
        h2.handoff_state_hash = Some("hash-2".into());

        assert_ne!(
            h1.canonical_bytes(),
            h2.canonical_bytes(),
            "for HandoffAttestation leaves, handoff_state_hash MUST be part of canonical_bytes"
        );
    }

    fn matching_authorization_pair() -> (String, Leaf, String, Leaf) {
        let granter_id = "granter-identity-hex".to_string();
        let grantee_id = "grantee-identity-hex".to_string();
        let mut granted = base_leaf(LeafType::AuthorizationEvent);
        granted.authorization_event_kind = Some(AuthorizationEventKind::GrantedByMe);
        granted.counterparty_pubkey = Some(grantee_id.clone());
        granted.authorization_scope_hash = Some("shared-scope-hash".into());

        let mut received = base_leaf(LeafType::AuthorizationEvent);
        received.authorization_event_kind = Some(AuthorizationEventKind::GrantedToMe);
        received.counterparty_pubkey = Some(granter_id.clone());
        received.authorization_scope_hash = Some("shared-scope-hash".into());

        (granter_id, granted, grantee_id, received)
    }

    #[test]
    fn matching_authorization_events_bind_successfully() {
        let (granter_id, granted, grantee_id, received) = matching_authorization_pair();
        assert!(
            verify_authorization_binding(&granter_id, &granted, &grantee_id, &received).is_ok()
        );
    }

    #[test]
    fn mismatched_scope_hash_fails_authorization_binding() {
        let (granter_id, granted, grantee_id, mut received) = matching_authorization_pair();
        received.authorization_scope_hash = Some("a-different-scope-entirely".into());
        assert!(
            verify_authorization_binding(&granter_id, &granted, &grantee_id, &received).is_err()
        );
    }

    #[test]
    fn mismatched_event_kind_fails_authorization_binding() {
        // Granter says GrantedByMe, but the other side ALSO claims
        // GrantedByMe instead of the expected GrantedToMe -- e.g. both
        // logs think they were the one doing the granting.
        let (granter_id, granted, grantee_id, mut received) = matching_authorization_pair();
        received.authorization_event_kind = Some(AuthorizationEventKind::GrantedByMe);
        assert!(
            verify_authorization_binding(&granter_id, &granted, &grantee_id, &received).is_err()
        );
    }

    #[test]
    fn revoke_and_scope_change_kinds_pair_correctly() {
        assert_eq!(
            AuthorizationEventKind::RevokedByMe.expected_counterparty_kind(),
            AuthorizationEventKind::RevokedToMe
        );
        assert_eq!(
            AuthorizationEventKind::ScopeChangedByMe.expected_counterparty_kind(),
            AuthorizationEventKind::ScopeChangedToMe
        );
        // Symmetric: applying the mapping twice returns the original.
        for kind in [
            AuthorizationEventKind::GrantedByMe,
            AuthorizationEventKind::RevokedByMe,
            AuthorizationEventKind::ScopeChangedByMe,
        ] {
            assert_eq!(
                kind.expected_counterparty_kind()
                    .expected_counterparty_kind(),
                kind
            );
        }
    }

    #[test]
    fn authorization_fields_only_affect_canonical_bytes_for_authorization_leaf_type() {
        let mut intent_leaf = base_leaf(LeafType::ActiveIntent);
        let bytes_before = intent_leaf.canonical_bytes();
        intent_leaf.authorization_event_kind = Some(AuthorizationEventKind::GrantedByMe);
        intent_leaf.counterparty_pubkey = Some("should-be-ignored".into());
        intent_leaf.authorization_scope_hash = Some("should-also-be-ignored".into());
        assert_eq!(
            bytes_before,
            intent_leaf.canonical_bytes(),
            "authorization_* fields must be ignored in canonical_bytes for any leaf_type other than AuthorizationEvent"
        );
    }

    #[test]
    fn handoff_and_authorization_fields_do_not_interfere_with_each_other() {
        // Both leaf types share the counterparty_pubkey field. Confirm a
        // HandoffAttestation leaf's bytes are unaffected by
        // authorization_* fields being set (which should never happen in
        // practice, but the encoding must be robust to it), and vice versa.
        let mut handoff = base_leaf(LeafType::HandoffAttestation);
        handoff.handoff_direction = Some(HandoffDirection::Sent);
        handoff.counterparty_pubkey = Some("party-x".into());
        handoff.handoff_state_hash = Some("hash-x".into());
        let handoff_bytes_clean = handoff.canonical_bytes();

        handoff.authorization_event_kind = Some(AuthorizationEventKind::GrantedByMe);
        handoff.authorization_scope_hash = Some("irrelevant".into());
        assert_eq!(
            handoff_bytes_clean,
            handoff.canonical_bytes(),
            "authorization_* fields must not affect a HandoffAttestation leaf's canonical_bytes"
        );
    }
}
