//! `c2sp.org/tlog-witness` — the protocol a log speaks to obtain
//! cosignatures from third-party witnesses.
//!
//! **Why this is the unlock.** C2SP conformance made WitnessLog
//! checkpoints *expressible* in a format existing Certificate
//! Transparency witnesses understand. It did not make them *reachable*:
//! without the transport, a witness has no way to receive a checkpoint
//! or return a cosignature, so `Verdict::Witnessed` stays theoretical
//! for anyone not running their own witnesses. This closes that gap.
//!
//! **No network dependency, deliberately.** This module implements the
//! protocol — request parsing, the witness state machine, response
//! formatting — and nothing else. Binding it to a specific HTTP server
//! would force an async runtime and a web framework onto every consumer
//! of a crate whose integration contract promises neither. Instead,
//! callers wire [`WitnessService::handle_add_checkpoint`] into whatever
//! server they already run (ten lines in axum, hyper, actix, or a
//! cloud function), and [`AddCheckpointRequest::to_http_body`] produces
//! the bytes a client POSTs. See `examples/witness_service.rs`.
//!
//! **The core safety property.** A witness MUST refuse to cosign a tree
//! head that is not consistent with the largest one it has already
//! cosigned for that log. Refusing is not an error path — a refusal is
//! evidence of log misbehaviour, which is the entire reason witnesses
//! exist. [`AddCheckpointOutcome::ConsistencyFailed`] carries that
//! evidence rather than discarding it.

use crate::normalize_hex;
use std::collections::HashMap;
use witness_log_core::c2sp::{Checkpoint, Cosignature, SignedNote, VerifierKey};
use witness_log_core::merkle::verify_consistency;

/// Maximum consistency proof lines in a request (c2sp.org/tlog-witness).
pub const MAX_PROOF_LINES: usize = 63;

/// Largest checkpoint body (origin, size, root and any extension lines) a
/// witness accepts. A WitnessLog checkpoint is ~140 bytes. Witnesses keep
/// the last log-signed note per log, so without a cap a log could make a
/// witness store ~64 KiB per log (gigabytes at 100k logs) and inflate
/// equivocation evidence the same way. Found by independent review.
pub const MAX_CHECKPOINT_TEXT_BYTES: usize = 1024;

/// What the witness knows about one log it has cosigned before.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KnownLog {
    /// The C2SP origin line identifying this log.
    pub origin: String,
    /// The verifier key the witness trusts for this log's own signature.
    /// Obtained out-of-band when the log was first added — a witness
    /// that accepts a key from the request it is verifying is not a
    /// witness, it is a rubber stamp.
    pub log_vkey: VerifierKey,
    /// Size of the largest consistent tree head cosigned so far. Zero
    /// means the witness has never cosigned this log.
    pub tree_size: u64,
    /// Root hash at `tree_size`.
    pub root_hash: [u8; 32],
    /// The log-signed checkpoint note (text plus only the log's own
    /// signature) this witness last cosigned. Kept so that if the log
    /// later signs a different root at the same size, the witness holds
    /// two conflicting log signatures: self-contained, publishable proof
    /// of equivocation. `None` before the first cosignature.
    pub checkpoint_note: Option<String>,
}

/// A `tlog-witness` add-checkpoint request: a signed checkpoint note,
/// plus a consistency proof from the witness's last known size to the
/// new one.
#[derive(Debug, Clone)]
pub struct AddCheckpointRequest {
    /// `old <size>` — the size the submitter believes the witness holds.
    pub old_size: u64,
    /// Consistency proof hashes from `old_size` to the checkpoint's size.
    /// Empty when `old_size` is 0 or equals the new size.
    pub consistency_proof: Vec<[u8; 32]>,
    /// The signed checkpoint note being submitted.
    pub checkpoint_note: SignedNote,
}

impl AddCheckpointRequest {
    /// Serialize to the wire body a client POSTs:
    ///
    /// ```text
    /// old <size>\n
    /// <base64 proof hash>\n   (zero or more)
    /// \n
    /// <signed checkpoint note>
    /// ```
    pub fn to_http_body(&self) -> Result<String, WitnessError> {
        use base64ct::{Base64, Encoding};
        let mut out = format!("old {}\n", self.old_size);
        for h in &self.consistency_proof {
            out.push_str(&Base64::encode_string(h));
            out.push('\n');
        }
        out.push('\n');
        out.push_str(
            &self
                .checkpoint_note
                .encode()
                .map_err(|e| WitnessError::Malformed(e.to_string()))?,
        );
        Ok(out)
    }

    /// Parse a request body received by a witness.
    pub fn parse(body: &str) -> Result<Self, WitnessError> {
        use base64ct::{Base64, Encoding};
        // The blank line separates the preamble (old size + proof) from
        // the note. The note itself contains blank lines, so split only
        // on the FIRST one.
        let (preamble, note_text) = body
            .split_once("\n\n")
            .ok_or_else(|| WitnessError::Malformed("no blank line after the proof".into()))?;

        let mut lines = preamble.lines();
        let old_line = lines
            .next()
            .ok_or_else(|| WitnessError::Malformed("empty request".into()))?;
        let old_size: u64 = old_line
            .strip_prefix("old ")
            .and_then(witness_log_core::c2sp::parse_canonical_u64)
            .ok_or_else(|| {
                WitnessError::Malformed(
                    "first line must be `old <size>` with a canonical decimal size".into(),
                )
            })?;

        let mut consistency_proof = Vec::new();
        for l in lines.filter(|l| !l.is_empty()) {
            // c2sp.org/tlog-witness: "The client MUST NOT send more than
            // 63 consistency proof lines." Also bounds witness work.
            if consistency_proof.len() == MAX_PROOF_LINES {
                return Err(WitnessError::Malformed(format!(
                    "more than {MAX_PROOF_LINES} consistency proof lines"
                )));
            }
            let bytes = Base64::decode_vec(l)
                .map_err(|_| WitnessError::Malformed("proof hash is not valid base64".into()))?;
            let h: [u8; 32] = bytes
                .try_into()
                .map_err(|_| WitnessError::Malformed("proof hash is not 32 bytes".into()))?;
            consistency_proof.push(h);
        }

        let checkpoint_note = SignedNote::parse(note_text)
            .map_err(|e| WitnessError::Malformed(format!("checkpoint note: {e}")))?;
        if checkpoint_note.text.len() > MAX_CHECKPOINT_TEXT_BYTES {
            return Err(WitnessError::Malformed(format!(
                "checkpoint body larger than {MAX_CHECKPOINT_TEXT_BYTES} bytes"
            )));
        }
        Ok(Self {
            old_size,
            consistency_proof,
            checkpoint_note,
        })
    }
}

/// The result of asking a witness to cosign.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum AddCheckpointOutcome {
    /// Cosigned. The witness's record is now at this checkpoint.
    Cosigned {
        cosignature: Cosignature,
        /// HTTP 200.
        new_size: u64,
    },
    /// The submitter's `old_size` doesn't match what the witness holds.
    /// Not a failure — the client should re-request with a proof from
    /// the size the witness actually has. HTTP 409 with this body.
    SizeMismatch {
        witness_size: u64,
        witness_root: [u8; 32],
    },
    /// The checkpoint is validly signed but could not be shown to extend
    /// the head this witness already cosigned. HTTP 422; never cosigned.
    ///
    /// On its own this is NOT proof the log misbehaved: anyone can relay
    /// an honest log's public checkpoint with a junk proof attached. It is
    /// proof only when `equivocation` is set -- the log signed two
    /// different roots for the same size, and both signed notes are here.
    ConsistencyFailed {
        witness_size: u64,
        witness_root: [u8; 32],
        submitted_size: u64,
        submitted_root: [u8; 32],
        /// Present only when the failure is provable equivocation.
        equivocation: Option<EquivocationProof>,
    },
    /// The log's own signature on the checkpoint didn't verify under the
    /// key the witness holds for it. HTTP 403.
    UnknownOrBadSignature,
    /// The witness doesn't know this origin. HTTP 404.
    UnknownLog { origin: String },
    /// The checkpoint is smaller than the size the request claims the
    /// witness holds (`old_size`). HTTP 400. **Not misbehaviour evidence:**
    /// an older, genuine checkpoint arriving late -- a client retry, a
    /// queued request -- looks exactly like this, and a witness has no
    /// consistency proof to tell it apart from a rollback. Before 0.3.1
    /// this was reported as `ConsistencyFailed`, i.e. a false accusation
    /// of equivocation against an honest log.
    StaleCheckpoint {
        witness_size: u64,
        submitted_size: u64,
    },
}

impl AddCheckpointOutcome {
    /// The HTTP status a conforming witness returns for this outcome.
    pub fn http_status(&self) -> u16 {
        match self {
            Self::Cosigned { .. } => 200,
            Self::UnknownOrBadSignature => 403,
            Self::UnknownLog { .. } => 404,
            Self::SizeMismatch { .. } => 409,
            Self::ConsistencyFailed { .. } => 422,
            Self::StaleCheckpoint { .. } => 400,
        }
    }

    /// The response body a conforming witness sends with
    /// [`http_status`](Self::http_status), and its `Content-Type`.
    ///
    /// Per `c2sp.org/tlog-witness`, 200 carries the cosignature as note
    /// signature line(s) and 409 carries ONLY the witness's current size
    /// as a decimal followed by a newline (`text/x.tlog.size`), which is
    /// what clients parse to resubmit with the right proof.
    pub fn http_body(&self) -> (String, &'static str) {
        const TEXT: &str = "text/plain; charset=utf-8";
        match self {
            // Each note signature line MUST end with a newline.
            Self::Cosigned { cosignature, .. } => (
                format!("{}\n", cosignature.to_note_signature().encode()),
                TEXT,
            ),
            Self::SizeMismatch { witness_size, .. } => {
                (format!("{witness_size}\n"), "text/x.tlog.size")
            }
            Self::ConsistencyFailed {
                witness_size,
                submitted_size,
                ..
            } => (
                format!(
                    "consistency proof failed: witness holds size {witness_size}, \
                     submitted {submitted_size}\n"
                ),
                TEXT,
            ),
            Self::UnknownOrBadSignature => ("checkpoint signature not verified\n".into(), TEXT),
            Self::UnknownLog { origin } => (format!("unknown log: {origin}\n"), TEXT),
            Self::StaleCheckpoint {
                witness_size,
                submitted_size,
            } => (
                format!(
                    "checkpoint size {submitted_size} is smaller than old size {witness_size}\n"
                ),
                TEXT,
            ),
        }
    }

    /// True when this outcome is publishable evidence that a log
    /// equivocated. A caller that treats this like any other error is
    /// discarding the most valuable output the protocol can produce.
    ///
    /// Since 0.3.1 this is true only for provable equivocation (two
    /// log-signed checkpoints, same size, different roots). A failed
    /// consistency proof alone is not evidence: a third party can attach
    /// a junk proof to an honest log's checkpoint, and treating that as
    /// misbehaviour would let anyone smear any log (and fill the
    /// witness's evidence store so real evidence is dropped).
    pub fn is_misbehaviour_evidence(&self) -> bool {
        matches!(
            self,
            Self::ConsistencyFailed {
                equivocation: Some(_),
                ..
            }
        )
    }
}

/// Two checkpoints the same log signed for the same tree size with
/// different roots. Each note carries only the log's own signature, so
/// anyone holding the log's verifier key can check both and see the
/// conflict without trusting the witness that reported it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct EquivocationProof {
    pub origin: String,
    /// C2SP vkey the notes verify under.
    pub log_vkey: String,
    pub earlier_note: String,
    pub conflicting_note: String,
}

impl EquivocationProof {
    /// Check the proof independently: both notes verify under the log's
    /// key, name `origin`, have the same size, and differ in root.
    ///
    /// The key is taken from `origin`, never from the proof: a canonical
    /// origin (`witness-log/<identity hex>`) names its own key, and the
    /// embedded `log_vkey` must be that key with the origin as its name.
    /// Before 0.4.2 the embedded vkey was trusted as given, so a proof
    /// signed with a stranger's key under a victim's origin verified
    /// (review round 2, W1). A proof for a non-canonical origin needs the
    /// trusted key supplied out of band: `verify_with_key`.
    pub fn verify(&self) -> bool {
        let Some(identity) = witness_log_core::c2sp::identity_from_canonical_origin(&self.origin)
        else {
            return false;
        };
        let Ok(vkey) = VerifierKey::parse(&self.log_vkey) else {
            return false;
        };
        if vkey.name != self.origin
            || vkey.sig_type != witness_log_core::c2sp::SIG_TYPE_ED25519
            || vkey.public_key != identity.to_bytes()
        {
            return false;
        }
        self.verify_with_key(&vkey)
    }

    /// `verify` for a log whose origin is not canonical: `vkey` is the
    /// log's key as the caller knows it (from the log's directory entry,
    /// not from this proof). The proof's own `log_vkey` is ignored.
    pub fn verify_with_key(&self, vkey: &VerifierKey) -> bool {
        if vkey.name != self.origin {
            return false;
        }
        let parse = |n: &str| -> Option<Checkpoint> {
            let note = SignedNote::parse(n).ok()?;
            note.verify(std::slice::from_ref(vkey)).ok()?;
            Checkpoint::from_note(&note).ok()
        };
        match (parse(&self.earlier_note), parse(&self.conflicting_note)) {
            (Some(a), Some(b)) => {
                a.origin == self.origin
                    && b.origin == self.origin
                    && a.tree_size == b.tree_size
                    && a.root_hash != b.root_hash
            }
            _ => false,
        }
    }
}

/// The note re-encoded with only the signatures made by `vkey` -- small,
/// and all a third party needs to check it.
fn log_signed_only(note: &SignedNote, vkey: &VerifierKey) -> Option<String> {
    SignedNote {
        text: note.text.clone(),
        // One signature is all a third party needs; keep at most one so
        // the stored note stays small whatever the request carried.
        signatures: note
            .signatures
            .iter()
            .filter(|s| s.key_name == vkey.name && s.key_id == vkey.id)
            .take(1)
            .cloned()
            .collect(),
    }
    .encode()
    .ok()
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum WitnessError {
    #[error("malformed request: {0}")]
    Malformed(String),
}

/// Durable witness state: one record per log. See
/// [`WitnessService::export_state`].
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct WitnessState {
    pub format_version: u32,
    /// Hex public key of the witness this state belongs to. A state file
    /// restored next to a different key would let that key cosign heads
    /// it never saw; see [`WitnessState::bind`]. Absent in states written
    /// before 0.3.2, which load unchecked.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub witness_pubkey: Option<String>,
    pub logs: Vec<KnownLogRecord>,
}

impl WitnessState {
    pub const FORMAT_VERSION: u32 = 1;

    /// Record which witness key this state belongs to.
    pub fn bind(mut self, witness_pubkey_hex: &str) -> Self {
        self.witness_pubkey = Some(witness_pubkey_hex.to_ascii_lowercase());
        self
    }

    /// `Err` if this state is bound to a key other than `witness_pubkey_hex`.
    /// Unbound (pre-0.3.2) states pass.
    pub fn check_bound_to(&self, witness_pubkey_hex: &str) -> Result<(), WitnessError> {
        match &self.witness_pubkey {
            Some(k) if !k.eq_ignore_ascii_case(witness_pubkey_hex) => {
                Err(WitnessError::Malformed(format!(
                    "witness state belongs to key {k}, not {witness_pubkey_hex}: a state file \
                     restored next to the wrong key would cosign heads this key never saw"
                )))
            }
            _ => Ok(()),
        }
    }
}

/// One log in a [`WitnessState`].
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct KnownLogRecord {
    pub origin: String,
    /// C2SP vkey string.
    pub log_vkey: String,
    pub tree_size: u64,
    /// Hex.
    pub root_hash: String,
    /// See [`KnownLog::checkpoint_note`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checkpoint_note: Option<String>,
}

/// A witness. Holds one record per log it has agreed to witness, and
/// updates that record only on a verified, consistent advance.
#[derive(Debug, Default)]
pub struct WitnessService {
    logs: HashMap<String, KnownLog>,
}

impl WitnessService {
    pub fn new() -> Self {
        Self::default()
    }

    /// Begin witnessing a log. `log_vkey` MUST be obtained out-of-band;
    /// a witness that learns a log's key from the log's own submissions
    /// verifies nothing.
    ///
    /// Returns false, changing nothing, if the origin is already known.
    /// Re-adding must never reset a log to size 0: that would let it be
    /// walked onto a fork (found by independent review of 0.3.1 -- a
    /// startup script that reloads state and then re-adds its logs did
    /// exactly that).
    pub fn add_log(&mut self, origin: &str, log_vkey: VerifierKey) -> bool {
        if self.logs.contains_key(origin) {
            return false;
        }
        self.logs.insert(
            origin.to_string(),
            KnownLog {
                origin: origin.to_string(),
                log_vkey,
                tree_size: 0,
                root_hash: [0u8; 32],
                checkpoint_note: None,
            },
        );
        true
    }

    pub fn known_log(&self, origin: &str) -> Option<&KnownLog> {
        self.logs.get(origin)
    }

    /// Overwrite one log's record. For an embedding server restoring the
    /// previous record after it failed to persist a new one -- the
    /// cosignature must then not be released (c2sp.org/tlog-witness:
    /// "The witness MUST persist the new checkpoint before responding").
    pub fn set_known_log(&mut self, record: KnownLog) {
        self.logs.insert(record.origin.clone(), record);
    }

    /// Stop tracking a log. Returns the removed record. Used to undo an
    /// enrollment whose first cosignature could not be persisted.
    pub fn remove_log(&mut self, origin: &str) -> Option<KnownLog> {
        self.logs.remove(origin)
    }

    /// Number of logs this witness tracks.
    pub fn log_count(&self) -> usize {
        self.logs.len()
    }

    /// Enroll the request's log if, and only if, its origin is a
    /// [`canonical_origin`](witness_log_core::c2sp::canonical_origin) and
    /// the checkpoint is validly signed by the key that origin names.
    /// Returns true if a new log was enrolled.
    ///
    /// This is what lets a public witness serve any WitnessLog agent with
    /// no out-of-band key exchange: the origin *is* the key, so there is
    /// nothing to trust on first use. Logs already known are never
    /// re-enrolled (that would reset their state and enable a rollback),
    /// and nothing is enrolled from an unverified request, so junk
    /// requests cannot grow the witness's state.
    pub fn enroll_canonical(&mut self, request: &AddCheckpointRequest) -> bool {
        use witness_log_core::c2sp::{identity_from_canonical_origin, VerifierKey};
        let Ok(checkpoint) = Checkpoint::from_note(&request.checkpoint_note) else {
            return false;
        };
        if self.logs.contains_key(&checkpoint.origin) {
            return false;
        }
        let Some(identity) = identity_from_canonical_origin(&checkpoint.origin) else {
            return false;
        };
        let vkey = VerifierKey::for_ed25519(&checkpoint.origin, &identity);
        if request
            .checkpoint_note
            .verify(std::slice::from_ref(&vkey))
            .is_err()
        {
            return false;
        }
        self.add_log(&checkpoint.origin, vkey);
        true
    }

    /// Snapshot of everything this witness must remember. Persist it
    /// durably BEFORE releasing a cosignature: a witness that cosigns,
    /// crashes and restarts with older state can be walked onto a fork.
    pub fn export_state(&self) -> WitnessState {
        let mut logs: Vec<KnownLogRecord> = self
            .logs
            .values()
            .map(|k| KnownLogRecord {
                origin: k.origin.clone(),
                log_vkey: k.log_vkey.encode(),
                tree_size: k.tree_size,
                root_hash: hex::encode(k.root_hash),
                checkpoint_note: k.checkpoint_note.clone(),
            })
            .collect();
        logs.sort_by(|a, b| a.origin.cmp(&b.origin));
        WitnessState {
            format_version: WitnessState::FORMAT_VERSION,
            witness_pubkey: None,
            logs,
        }
    }

    /// Restore from [`export_state`](Self::export_state). Rejects the
    /// whole state on any malformed record rather than silently dropping
    /// a log, which would reset it to size 0 and accept a fork.
    pub fn from_state(state: &WitnessState) -> Result<Self, WitnessError> {
        if state.format_version != WitnessState::FORMAT_VERSION {
            return Err(WitnessError::Malformed(format!(
                "unsupported witness state format_version {}",
                state.format_version
            )));
        }
        let mut logs = HashMap::new();
        for r in &state.logs {
            let log_vkey = VerifierKey::parse(&r.log_vkey)
                .map_err(|e| WitnessError::Malformed(format!("{}: vkey: {e}", r.origin)))?;
            let root_hash: [u8; 32] = hex::decode(&r.root_hash)
                .ok()
                .and_then(|b| b.try_into().ok())
                .ok_or_else(|| WitnessError::Malformed(format!("{}: root_hash", r.origin)))?;
            if logs
                .insert(
                    r.origin.clone(),
                    KnownLog {
                        origin: r.origin.clone(),
                        log_vkey,
                        tree_size: r.tree_size,
                        root_hash,
                        checkpoint_note: r.checkpoint_note.clone(),
                    },
                )
                .is_some()
            {
                return Err(WitnessError::Malformed(format!(
                    "duplicate log {} in witness state",
                    r.origin
                )));
            }
        }
        Ok(Self { logs })
    }

    /// Handle an add-checkpoint request. This is the whole protocol.
    ///
    /// `witness_key_name` and `signing_key` are this witness's own
    /// cosigning identity; `now_unix_seconds` is the time asserted in
    /// the cosignature.
    pub fn handle_add_checkpoint(
        &mut self,
        request: &AddCheckpointRequest,
        witness_key_name: &str,
        signing_key: &ed25519_dalek::SigningKey,
        now_unix_seconds: u64,
    ) -> AddCheckpointOutcome {
        // 1. Which log is this? The origin comes from the checkpoint
        //    body, which is covered by the log's signature — so a
        //    mismatched origin fails at step 2, not here.
        let Ok(checkpoint) = Checkpoint::from_note(&request.checkpoint_note) else {
            return AddCheckpointOutcome::UnknownOrBadSignature;
        };
        let Some(known) = self.logs.get(&checkpoint.origin).cloned() else {
            return AddCheckpointOutcome::UnknownLog {
                origin: checkpoint.origin,
            };
        };

        // 2. Verify the LOG's signature under the key held out-of-band.
        //    Everything after this is about a checkpoint we know is
        //    genuinely from this log.
        if request
            .checkpoint_note
            .verify(std::slice::from_ref(&known.log_vkey))
            .is_err()
        {
            return AddCheckpointOutcome::UnknownOrBadSignature;
        }

        // 3a. Request-level sanity (c2sp.org/tlog-witness, in spec order).
        //     old size larger than the checkpoint: 400, never evidence.
        if request.old_size > checkpoint.tree_size {
            return AddCheckpointOutcome::StaleCheckpoint {
                witness_size: request.old_size,
                submitted_size: checkpoint.tree_size,
            };
        }

        // 3. Does the submitter agree with us about where we are? If
        //    not, tell them where we actually are so they can resubmit
        //    with the right proof. This is a normal, expected response.
        if request.old_size != known.tree_size {
            return AddCheckpointOutcome::SizeMismatch {
                witness_size: known.tree_size,
                witness_root: known.root_hash,
            };
        }

        // 3b. 422 cases the spec names that don't need prior state: a
        //     proof sent from size 0 (there is nothing to prove from), and
        //     an empty tree whose root is not SHA-256 of the empty string.
        let malformed_claim = (request.old_size == 0 && !request.consistency_proof.is_empty())
            || (checkpoint.tree_size == 0 && checkpoint.root_hash != empty_tree_root());
        if malformed_claim {
            return AddCheckpointOutcome::ConsistencyFailed {
                witness_size: known.tree_size,
                witness_root: known.root_hash,
                submitted_size: checkpoint.tree_size,
                submitted_root: checkpoint.root_hash,
                equivocation: None,
            };
        }

        // 4. Consistency. The new head must extend the one we hold.
        //    A first checkpoint (witness_size 0) has nothing to extend,
        //    so it is accepted on signature alone — the witness simply
        //    has no prior claim to contradict.
        if known.tree_size > 0 {
            if checkpoint.tree_size < known.tree_size {
                // Smaller than what we hold. Refuse, but do NOT call it
                // equivocation: a stale genuine checkpoint looks identical
                // and there is no proof here that could distinguish them.
                return AddCheckpointOutcome::StaleCheckpoint {
                    witness_size: known.tree_size,
                    submitted_size: checkpoint.tree_size,
                };
            }
            let consistent = verify_consistency(
                known.tree_size,
                &known.root_hash,
                checkpoint.tree_size,
                &checkpoint.root_hash,
                &request.consistency_proof,
            );
            if !consistent {
                // Refuse. Provable equivocation only when the log signed a
                // different root at the very size we cosigned: then we hold
                // two conflicting log signatures. A different size with a
                // failing proof may be a fork or just a junk proof relayed
                // by anyone -- refused, but not evidence.
                let equivocation = if checkpoint.tree_size == known.tree_size
                    && checkpoint.root_hash != known.root_hash
                {
                    match (
                        &known.checkpoint_note,
                        log_signed_only(&request.checkpoint_note, &known.log_vkey),
                    ) {
                        (Some(earlier), Some(conflicting)) => Some(EquivocationProof {
                            origin: known.origin.clone(),
                            log_vkey: known.log_vkey.encode(),
                            earlier_note: earlier.clone(),
                            conflicting_note: conflicting,
                        }),
                        _ => None,
                    }
                } else {
                    None
                };
                return AddCheckpointOutcome::ConsistencyFailed {
                    witness_size: known.tree_size,
                    witness_root: known.root_hash,
                    submitted_size: checkpoint.tree_size,
                    submitted_root: checkpoint.root_hash,
                    equivocation,
                };
            }
        }

        // 5. Cosign, then advance our record — atomically from the
        //    caller's perspective, since nothing between these two
        //    lines can fail.
        let note_text = match checkpoint.note_text() {
            Ok(t) => t,
            Err(_) => return AddCheckpointOutcome::UnknownOrBadSignature,
        };
        let cosignature =
            Cosignature::sign(witness_key_name, signing_key, now_unix_seconds, &note_text);
        let note = log_signed_only(&request.checkpoint_note, &known.log_vkey);
        if let Some(entry) = self.logs.get_mut(&checkpoint.origin) {
            entry.tree_size = checkpoint.tree_size;
            entry.root_hash = checkpoint.root_hash;
            entry.checkpoint_note = note;
        }
        AddCheckpointOutcome::Cosigned {
            cosignature,
            new_size: checkpoint.tree_size,
        }
    }
}

/// RFC 6962 root of the empty tree: SHA-256 of the empty string.
fn empty_tree_root() -> [u8; 32] {
    witness_log_core::merkle::MerkleTree::new().root()
}

/// Client side: does this cosignature actually attest to the checkpoint
/// we submitted? Call this before counting a cosignature as a receipt —
/// a witness that returns 200 with a signature over something else must
/// not be trusted just because the status code was green.
pub fn verify_cosignature_response(
    cosignature: &Cosignature,
    witness_vkey: &VerifierKey,
    submitted: &Checkpoint,
) -> bool {
    let Ok(text) = submitted.note_text() else {
        return false;
    };
    cosignature.verify(witness_vkey, &text).is_ok()
}

/// Is `pubkey_hex` the key this witness entry names? Convenience for
/// matching a returned cosignature back to a directory entry.
pub fn matches_witness_entry(entry: &crate::WitnessEntry, pubkey_hex: &str) -> bool {
    normalize_hex(&entry.pubkey) == normalize_hex(pubkey_hex)
}

/// Convert a `tlog-witness` cosignature into a [`crate::WitnessReceipt`] that
/// [`crate::evaluate_quorum`] counts.
///
/// The receipt carries the cosignature bytes and `c2sp_origin`, and
/// [`crate::WitnessReceipt::verify`] re-checks it against the C2SP
/// `cosignature/v1` message offline -- so a dossier built from live
/// third-party witnesses verifies anywhere, with no access to the
/// witnesses. Only cosignatures under the log identity's
/// [`canonical_origin`](witness_log_core::c2sp::canonical_origin) count
/// toward a verdict.
///
/// History: before 0.3.1 these receipts were flagged non-verifiable and
/// quorum evaluation silently dropped every one of them, so no real
/// witness could ever produce `Witnessed`. The earlier test checked the
/// conversion but never ran the result through `Dossier::verify`; the
/// live-witness run did.
#[derive(Debug, Clone)]
pub struct CosignedReceipt {
    /// The receipt, verifiable by [`crate::WitnessReceipt::verify`].
    pub receipt: crate::WitnessReceipt,
    /// Always true since 0.3.1. Kept so 0.3.0 callers still compile.
    pub native_verifiable: bool,
}

/// Build a quorum-countable receipt from a verified cosignature.
///
/// Returns `None` unless the cosignature verifies against
/// `checkpoint`, so an unverified cosignature can never become a
/// receipt by accident.
pub fn cosignature_to_receipt(
    cosignature: &Cosignature,
    witness_vkey: &VerifierKey,
    checkpoint: &Checkpoint,
    native_checkpoint: &witness_log_core::sth::SignedTreeHead,
) -> Option<CosignedReceipt> {
    if !verify_cosignature_response(cosignature, witness_vkey, checkpoint) {
        return None;
    }
    // The receipt must name the same (tree_size, root) the native
    // checkpoint does, or quorum evaluation will correctly reject it as
    // being about a different head.
    if native_checkpoint.tree_size != checkpoint.tree_size
        || normalize_hex(&native_checkpoint.root_hash) != hex::encode(checkpoint.root_hash)
    {
        return None;
    }
    Some(CosignedReceipt {
        receipt: crate::WitnessReceipt {
            witness_pubkey: hex::encode(&witness_vkey.public_key),
            tree_size: checkpoint.tree_size,
            root_hash: native_checkpoint.root_hash.clone(),
            witnessed_at_ms: cosignature.timestamp.saturating_mul(1000),
            signature: hex::encode(&cosignature.signature),
            c2sp_origin: Some(checkpoint.origin.clone()),
            witness_name: None,
        },
        native_verifiable: true,
    })
}
