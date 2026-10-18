//! Two-tier identity: a long-lived *identity key* the agent keeps across
//! process restarts, and short-lived *session keys* generated fresh each
//! process lifecycle for zero-disk-leakage signing. A `KeyBindingStatement`,
//! signed by the identity key, links a session key to that identity for a
//! specific window — so log continuity can be verified across restarts
//! without the identity key ever touching disk unencrypted more than once.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum IdentityError {
    #[error("invalid signature on key-binding statement")]
    InvalidBindingSignature,
    #[error("malformed public key bytes")]
    MalformedKey,
    #[error("key binding expired at {not_after_ms}ms (checked at {checked_at_ms}ms)")]
    BindingExpired {
        not_after_ms: u64,
        checked_at_ms: u64,
    },
}

pub struct IdentityKeypair {
    signing_key: SigningKey,
}

impl IdentityKeypair {
    pub fn generate() -> Self {
        Self {
            signing_key: SigningKey::generate(&mut OsRng),
        }
    }

    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        Self {
            signing_key: SigningKey::from_bytes(bytes),
        }
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        self.signing_key.to_bytes()
    }

    pub fn public_hex(&self) -> String {
        hex::encode(self.signing_key.verifying_key().to_bytes())
    }

    /// Sign a fresh session key into existence. This is the statement that
    /// makes cross-restart continuity provable: anyone with the identity's
    /// public key can confirm this session key really was authorized by
    /// that identity, at this session number, at this time.
    ///
    /// `not_after_ms` is optional session-expiry: `None` means the binding
    /// never expires on its own (the old, still-supported default — most
    /// callers don't need epoching). When set, it's folded into the signed
    /// message, so a verifier can't be tricked by an operator who strips
    /// the field to pretend a binding is still live past its expiry.
    pub fn bind_session(
        &self,
        session_pubkey: &VerifyingKey,
        session_number: u64,
        timestamp_ms: u64,
        not_after_ms: Option<u64>,
    ) -> KeyBindingStatement {
        let msg = binding_message(
            &self.signing_key.verifying_key(),
            session_pubkey,
            session_number,
            timestamp_ms,
            not_after_ms,
        );
        let signature = self.signing_key.sign(&msg);
        KeyBindingStatement {
            identity_pubkey: hex::encode(self.signing_key.verifying_key().to_bytes()),
            session_pubkey: hex::encode(session_pubkey.to_bytes()),
            session_number,
            timestamp_ms,
            not_after_ms,
            custody: KeyCustody::default(),
            signature: hex::encode(signature.to_bytes()),
        }
    }

    /// Produce a signed revocation for this identity's own key, e.g. after
    /// suspected compromise. Leaves after `as_of_ms` under this identity
    /// should be treated as untrusted by verifiers.
    pub fn revoke(&self, as_of_ms: u64, reason: &str) -> RevocationStatement {
        self.sign_revocation(as_of_ms, None, reason)
    }

    /// RFC-0005 (experimental): a revocation that also names the tree size
    /// at which it takes effect. Verifiers reject every leaf at index
    /// `as_of_index` or later and every checkpoint larger than
    /// `as_of_index`, whatever their timestamps say. Pair it with a
    /// witnessed checkpoint of size `as_of_index`: witnesses refuse to
    /// cosign a different root at that size, so whoever holds the
    /// compromised key can neither rewrite the history below the cut-off
    /// nor extend it. Signed under the `witness-log-revoke-v2` message,
    /// which a verifier that only knows v1 rejects (fail-closed).
    pub fn revoke_at_index(
        &self,
        as_of_ms: u64,
        as_of_index: u64,
        reason: &str,
    ) -> RevocationStatement {
        self.sign_revocation(as_of_ms, Some(as_of_index), reason)
    }

    fn sign_revocation(
        &self,
        as_of_ms: u64,
        as_of_index: Option<u64>,
        reason: &str,
    ) -> RevocationStatement {
        let pk = self.signing_key.verifying_key().to_bytes();
        let msg = revocation_message(&pk, as_of_ms, as_of_index, reason);
        let signature = self.signing_key.sign(&msg);
        RevocationStatement {
            identity_pubkey: hex::encode(pk),
            as_of_ms,
            as_of_index,
            reason: reason.to_string(),
            signature: hex::encode(signature.to_bytes()),
        }
    }
}

/// SPEC §5. v1 (no index): `"witness-log-revoke-v1" || identity (32B) ||
/// as_of_ms (8B BE) || reason`. v2 (RFC-0005, with an index):
/// `"witness-log-revoke-v2" || identity || as_of_ms || 0x01 || as_of_index
/// (8B BE) || reason`. The prefix names the version, so a v2 signature can
/// never be read as a v1 one with the index stripped.
pub fn revocation_message(
    identity_pubkey: &[u8; 32],
    as_of_ms: u64,
    as_of_index: Option<u64>,
    reason: &str,
) -> Vec<u8> {
    let mut msg = Vec::new();
    match as_of_index {
        None => {
            msg.extend_from_slice(b"witness-log-revoke-v1");
            msg.extend_from_slice(identity_pubkey);
            msg.extend_from_slice(&as_of_ms.to_be_bytes());
        }
        Some(index) => {
            msg.extend_from_slice(b"witness-log-revoke-v2");
            msg.extend_from_slice(identity_pubkey);
            msg.extend_from_slice(&as_of_ms.to_be_bytes());
            msg.push(0x01);
            msg.extend_from_slice(&index.to_be_bytes());
        }
    }
    msg.extend_from_slice(reason.as_bytes());
    msg
}

pub struct SessionKeypair {
    signing_key: SigningKey,
}

impl SessionKeypair {
    pub fn generate() -> Self {
        Self {
            signing_key: SigningKey::generate(&mut OsRng),
        }
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }

    pub fn public_hex(&self) -> String {
        hex::encode(self.signing_key.verifying_key().to_bytes())
    }

    pub fn sign(&self, msg: &[u8]) -> Signature {
        self.signing_key.sign(msg)
    }
}

fn binding_message(
    identity_pk: &VerifyingKey,
    session_pk: &VerifyingKey,
    session_number: u64,
    timestamp_ms: u64,
    not_after_ms: Option<u64>,
) -> Vec<u8> {
    let mut msg = Vec::new();
    msg.extend_from_slice(b"witness-log-key-bind-v1");
    msg.extend_from_slice(&identity_pk.to_bytes());
    msg.extend_from_slice(&session_pk.to_bytes());
    msg.extend_from_slice(&session_number.to_be_bytes());
    msg.extend_from_slice(&timestamp_ms.to_be_bytes());
    // Presence flag before the value, same pattern as leaf.rs's optional
    // fields, so "no expiry" and "expiry = 0" are never ambiguous on the wire.
    match not_after_ms {
        Some(t) => {
            msg.push(1);
            msg.extend_from_slice(&t.to_be_bytes());
        }
        None => msg.push(0),
    }
    msg
}

/// How the private key behind a `KeyBindingStatement` is held.
/// Copied from the 1F916 Agent Record draft §3.1 — this field answers
/// "what does a signature over this key actually prove?" which is a
/// different question from "is the signature cryptographically valid?"
/// Verifiers MUST surface custody alongside any signature-verification
/// result; they are not the same thing.
///
/// Serialized in snake_case (`"self_held"`, `{"threshold": {"k": "2", "n":
/// "3"}}`); the threshold variant's content is read only from an object,
/// never from an array of `k` and `n`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum KeyCustody {
    /// Agent process holds the key in memory. Any runtime compromise exposes it.
    SelfHeld,
    /// An operator's platform holds the key on the agent's behalf. A signature
    /// proves the operator authorized this, not the agent alone.
    PlatformHeld,
    /// A hardware security module holds the key.
    Hsm,
    /// A cloud KMS (AWS KMS, GCP KMS, HashiCorp Vault, etc.).
    Kms,
    /// k-of-n threshold scheme. k and n embedded as strings.
    Threshold { k: String, n: String },
    /// A parent agent delegated this session key.
    SessionDelegated,
    /// Custody not disclosed — treat as the weakest tier, never as neutral.
    #[default]
    Undisclosed,
}

/// The serde shape of [`KeyCustody`]; see `object_only` for why it is a
/// separate, private type.
#[derive(Serialize, Deserialize)]
#[serde(
    remote = "KeyCustody",
    rename = "KeyCustody",
    rename_all = "snake_case"
)]
enum KeyCustodyDef {
    SelfHeld,
    PlatformHeld,
    Hsm,
    Kms,
    Threshold { k: String, n: String },
    SessionDelegated,
    Undisclosed,
}

crate::object_only_serde!(KeyCustody, KeyCustodyDef);

/// A session key binding (SPEC.md §5). Serialized as a JSON object with
/// these fields in this order, and read only from an object, never from an
/// array of the field values.
#[derive(Debug, Clone)]
pub struct KeyBindingStatement {
    pub identity_pubkey: String,
    pub session_pubkey: String,
    pub session_number: u64,
    pub timestamp_ms: u64,
    /// How the session key is held. Surfaced by verifiers alongside the
    /// signature result -- a cryptographically valid signature means
    /// different things depending on custody. Default (absent from the
    /// JSON): Undisclosed.
    pub custody: KeyCustody,
    /// Unix millis after which this binding should be treated as expired.
    /// `None` (also when absent from the JSON, for backward compatibility
    /// with bindings issued before this field existed) means no expiry.
    pub not_after_ms: Option<u64>,
    pub signature: String,
}

/// The serde shape of [`KeyBindingStatement`]; see `object_only`.
#[derive(Serialize, Deserialize)]
#[serde(remote = "KeyBindingStatement", rename = "KeyBindingStatement")]
struct KeyBindingStatementDef {
    identity_pubkey: String,
    session_pubkey: String,
    session_number: u64,
    timestamp_ms: u64,
    #[serde(default)]
    custody: KeyCustody,
    #[serde(default)]
    not_after_ms: Option<u64>,
    signature: String,
}

crate::object_only_serde!(KeyBindingStatement, KeyBindingStatementDef);

impl KeyBindingStatement {
    /// Signature validity only — does NOT check expiry. Use `verify_valid_at`
    /// if expiry matters for your use case (it usually should).
    pub fn verify(&self) -> Result<(), IdentityError> {
        let identity_bytes: [u8; 32] = hex::decode(&self.identity_pubkey)
            .map_err(|_| IdentityError::MalformedKey)?
            .try_into()
            .map_err(|_| IdentityError::MalformedKey)?;
        let session_bytes: [u8; 32] = hex::decode(&self.session_pubkey)
            .map_err(|_| IdentityError::MalformedKey)?
            .try_into()
            .map_err(|_| IdentityError::MalformedKey)?;
        let identity_pk =
            VerifyingKey::from_bytes(&identity_bytes).map_err(|_| IdentityError::MalformedKey)?;
        let session_pk =
            VerifyingKey::from_bytes(&session_bytes).map_err(|_| IdentityError::MalformedKey)?;
        let sig_bytes: [u8; 64] = hex::decode(&self.signature)
            .map_err(|_| IdentityError::InvalidBindingSignature)?
            .try_into()
            .map_err(|_| IdentityError::InvalidBindingSignature)?;
        let signature = Signature::from_bytes(&sig_bytes);
        let msg = binding_message(
            &identity_pk,
            &session_pk,
            self.session_number,
            self.timestamp_ms,
            self.not_after_ms,
        );
        identity_pk
            .verify_strict(&msg, &signature)
            .map_err(|_| IdentityError::InvalidBindingSignature)
    }

    /// Signature validity AND not-expired-as-of `now_ms`. This is what most
    /// callers should actually use — a cryptographically valid but expired
    /// binding is not a binding a verifier should currently trust.
    pub fn verify_valid_at(&self, now_ms: u64) -> Result<(), IdentityError> {
        self.verify()?;
        if let Some(not_after) = self.not_after_ms {
            if now_ms > not_after {
                return Err(IdentityError::BindingExpired {
                    not_after_ms: not_after,
                    checked_at_ms: now_ms,
                });
            }
        }
        Ok(())
    }
}

/// A revocation statement (SPEC.md §5). Serialized as a JSON object with
/// these fields in this order, and read only from an object, never from an
/// array of the field values.
#[derive(Debug, Clone)]
pub struct RevocationStatement {
    pub identity_pubkey: String,
    pub as_of_ms: u64,
    /// RFC-0005 (experimental): the tree size at which the revocation
    /// takes effect. Absent in v1 statements, which keep the timestamp
    /// rule alone; not serialized when `None`.
    pub as_of_index: Option<u64>,
    pub reason: String,
    pub signature: String,
}

/// The serde shape of [`RevocationStatement`]; see `object_only`.
#[derive(Serialize, Deserialize)]
#[serde(remote = "RevocationStatement", rename = "RevocationStatement")]
struct RevocationStatementDef {
    identity_pubkey: String,
    as_of_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    as_of_index: Option<u64>,
    reason: String,
    signature: String,
}

crate::object_only_serde!(RevocationStatement, RevocationStatementDef);

impl RevocationStatement {
    pub fn verify(&self) -> Result<(), IdentityError> {
        let identity_bytes: [u8; 32] = hex::decode(&self.identity_pubkey)
            .map_err(|_| IdentityError::MalformedKey)?
            .try_into()
            .map_err(|_| IdentityError::MalformedKey)?;
        let identity_pk =
            VerifyingKey::from_bytes(&identity_bytes).map_err(|_| IdentityError::MalformedKey)?;
        let sig_bytes: [u8; 64] = hex::decode(&self.signature)
            .map_err(|_| IdentityError::InvalidBindingSignature)?
            .try_into()
            .map_err(|_| IdentityError::InvalidBindingSignature)?;
        let signature = Signature::from_bytes(&sig_bytes);
        let msg = revocation_message(
            &identity_pk.to_bytes(),
            self.as_of_ms,
            self.as_of_index,
            &self.reason,
        );
        identity_pk
            .verify_strict(&msg, &signature)
            .map_err(|_| IdentityError::InvalidBindingSignature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn index_revocation_is_bound_to_its_index_and_version() {
        let id = IdentityKeypair::generate();
        let r = id.revoke_at_index(5_000, 7, "compromised");
        assert!(r.verify().is_ok());
        let mut moved = r.clone();
        moved.as_of_index = Some(8);
        assert!(moved.verify().is_err(), "the index is signed");
        let mut stripped = r.clone();
        stripped.as_of_index = None;
        assert!(stripped.verify().is_err(), "a v2 signature is not a v1 one");
        let v1 = id.revoke(5_000, "compromised");
        let mut upgraded = v1.clone();
        upgraded.as_of_index = Some(7);
        assert!(upgraded.verify().is_err(), "a v1 signature is not a v2 one");
        let json = serde_json::to_string(&v1).unwrap();
        assert!(
            !json.contains("as_of_index"),
            "v1 serialises exactly as before: {json}"
        );
    }

    #[test]
    fn binding_verifies_and_tamper_fails() {
        let identity = IdentityKeypair::generate();
        let session = SessionKeypair::generate();
        let mut binding = identity.bind_session(&session.verifying_key(), 1, 1_000, None);
        assert!(binding.verify().is_ok());
        binding.session_number = 2; // tamper
        assert!(binding.verify().is_err());
    }

    #[test]
    fn binding_without_expiry_is_valid_at_any_future_time() {
        let identity = IdentityKeypair::generate();
        let session = SessionKeypair::generate();
        let binding = identity.bind_session(&session.verifying_key(), 1, 1_000, None);
        assert!(binding.verify_valid_at(1_000).is_ok());
        assert!(binding.verify_valid_at(u64::MAX).is_ok());
    }

    #[test]
    fn binding_with_expiry_rejected_after_not_after_ms() {
        let identity = IdentityKeypair::generate();
        let session = SessionKeypair::generate();
        let binding = identity.bind_session(&session.verifying_key(), 1, 1_000, Some(5_000));
        assert!(binding.verify_valid_at(1_000).is_ok(), "well before expiry");
        assert!(
            binding.verify_valid_at(5_000).is_ok(),
            "exactly at expiry boundary is still valid"
        );
        let err = binding.verify_valid_at(5_001).unwrap_err();
        assert!(
            matches!(err, IdentityError::BindingExpired { .. }),
            "must reject just past expiry"
        );
    }

    #[test]
    fn stripping_expiry_from_a_signed_binding_invalidates_the_signature() {
        // An operator can't quietly remove not_after_ms to make an expired
        // binding look permanent — the field is folded into the signed
        // message, so stripping it breaks the signature instead.
        let identity = IdentityKeypair::generate();
        let session = SessionKeypair::generate();
        let mut binding = identity.bind_session(&session.verifying_key(), 1, 1_000, Some(2_000));
        binding.not_after_ms = None;
        assert!(
            binding.verify().is_err(),
            "removing not_after_ms must invalidate the signature"
        );
    }

    #[test]
    fn revocation_verifies_and_tamper_fails() {
        let identity = IdentityKeypair::generate();
        let mut rev = identity.revoke(1_000, "suspected key compromise");
        assert!(rev.verify().is_ok());
        rev.reason = "different reason".into();
        assert!(rev.verify().is_err());
    }
}
