//! Signed Tree Heads (checkpoints). An STH is the thing witnesses
//! countersign and the thing verifiers ultimately trust: "at tree size N,
//! the root was X, and I (this signer) attest to that at time T."
//!
//! `sig_alg` is included on every STH from v1 onward even though Ed25519 is
//! the only algorithm implemented today. This is a deliberate crypto-agility
//! decision: rotating signature schemes later (e.g. for post-quantum
//! migration) must not require a breaking format change or invalidate
//! historical STHs signed under the old algorithm.

use crate::merkle::Hash;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const SIG_ALG_ED25519: &str = "ed25519";

#[derive(Debug, Error)]
pub enum SthError {
    #[error("signature invalid for this tree head")]
    InvalidSignature,
    #[error("unsupported signature algorithm: {0}")]
    UnsupportedAlgorithm(String),
    #[error("malformed key or signature bytes")]
    Malformed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedTreeHead {
    pub tree_size: u64,
    pub root_hash: String, // hex
    pub timestamp_ms: u64,
    pub sig_alg: String,
    pub signer_pubkey: String, // hex
    pub signature: String,     // hex
}

impl SignedTreeHead {
    pub fn sign(
        signing_key: &SigningKey,
        tree_size: u64,
        root_hash: &Hash,
        timestamp_ms: u64,
    ) -> Self {
        let sig_alg = SIG_ALG_ED25519.to_string();
        let signer_pubkey = hex::encode(signing_key.verifying_key().to_bytes());
        let msg = sth_message(&sig_alg, &signer_pubkey, tree_size, root_hash, timestamp_ms);
        let signature = signing_key.sign(&msg);
        Self {
            tree_size,
            root_hash: hex::encode(root_hash),
            timestamp_ms,
            sig_alg,
            signer_pubkey,
            signature: hex::encode(signature.to_bytes()),
        }
    }

    pub fn verify(&self) -> Result<(), SthError> {
        if self.sig_alg != SIG_ALG_ED25519 {
            return Err(SthError::UnsupportedAlgorithm(self.sig_alg.clone()));
        }
        let root: [u8; 32] = hex::decode(&self.root_hash)
            .map_err(|_| SthError::Malformed)?
            .try_into()
            .map_err(|_| SthError::Malformed)?;
        let pk_bytes: [u8; 32] = hex::decode(&self.signer_pubkey)
            .map_err(|_| SthError::Malformed)?
            .try_into()
            .map_err(|_| SthError::Malformed)?;
        let pk = VerifyingKey::from_bytes(&pk_bytes).map_err(|_| SthError::Malformed)?;
        let sig_bytes: [u8; 64] = hex::decode(&self.signature)
            .map_err(|_| SthError::Malformed)?
            .try_into()
            .map_err(|_| SthError::Malformed)?;
        let signature = Signature::from_bytes(&sig_bytes);
        // sig_alg and signer_pubkey are now covered by the signature (see
        // sth_message) -- previously only tree_size/root/timestamp were
        // signed, leaving the crypto-agility selector field itself
        // attacker-mutable with no cryptographic consequence (the classic
        // algorithm-downgrade setup: today it's caught only by the
        // hardcoded equality check above, not by the signature). See the
        // pre-launch review, finding 12.
        let msg = sth_message(
            &self.sig_alg,
            &self.signer_pubkey,
            self.tree_size,
            &root,
            self.timestamp_ms,
        );
        // verify_strict rather than verify: additionally rejects degenerate
        // small-order/mixed-order edge cases so that all conformant verifiers
        // agree on validity -- see SPEC.md SS6. Honestly-generated signatures
        // are unaffected.
        pk.verify_strict(&msg, &signature)
            .map_err(|_| SthError::InvalidSignature)
    }
}

/// A signed acknowledgement that the log accepted an event for inclusion:
/// "I, `signer_pubkey`, accepted the leaf with `payload_hash` while my tree
/// had `tree_size` leaves, at `issued_at_ms`." The log identity signs it
/// at submission time, BEFORE the event is in any checkpoint.
///
/// This is what makes censorship provable: the receipt commits the log to
/// a specific event, so if witnessed checkpoints later pass `tree_size`
/// without that event ever appearing, the receipt and those checkpoints
/// together are evidence a third party can check. A plain checkpoint
/// cannot serve as a write receipt -- it says nothing about any
/// particular event -- which is exactly the hole the pre-publish review
/// found in the earlier `silence_proof` (any payload hash could be
/// "proven" censored against any witnessed log).
///
/// Message: `"witness-log-write-receipt-v1" || lp(sig_alg) ||
/// lp(signer_pubkey_hex) || lp(payload_hash_hex) || tree_size (8B BE) ||
/// issued_at_ms (8B BE)`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WriteReceipt {
    /// Hex payload_hash of the accepted leaf (SPEC §8).
    pub payload_hash: String,
    /// The log's tree size when the event was accepted. The event is due
    /// in a checkpoint of size > this.
    pub tree_size: u64,
    pub issued_at_ms: u64,
    pub sig_alg: String,
    pub signer_pubkey: String,
    pub signature: String,
}

impl WriteReceipt {
    pub fn sign(
        signing_key: &SigningKey,
        payload_hash_hex: &str,
        tree_size: u64,
        issued_at_ms: u64,
    ) -> Self {
        let sig_alg = SIG_ALG_ED25519.to_string();
        let signer_pubkey = hex::encode(signing_key.verifying_key().to_bytes());
        let payload_hash = payload_hash_hex.to_ascii_lowercase();
        let msg = write_receipt_message(
            &sig_alg,
            &signer_pubkey,
            &payload_hash,
            tree_size,
            issued_at_ms,
        );
        let signature = signing_key.sign(&msg);
        Self {
            payload_hash,
            tree_size,
            issued_at_ms,
            sig_alg,
            signer_pubkey,
            signature: hex::encode(signature.to_bytes()),
        }
    }

    pub fn verify(&self) -> Result<(), SthError> {
        if self.sig_alg != SIG_ALG_ED25519 {
            return Err(SthError::UnsupportedAlgorithm(self.sig_alg.clone()));
        }
        let pk_bytes: [u8; 32] = hex::decode(&self.signer_pubkey)
            .map_err(|_| SthError::Malformed)?
            .try_into()
            .map_err(|_| SthError::Malformed)?;
        let pk = VerifyingKey::from_bytes(&pk_bytes).map_err(|_| SthError::Malformed)?;
        let sig_bytes: [u8; 64] = hex::decode(&self.signature)
            .map_err(|_| SthError::Malformed)?
            .try_into()
            .map_err(|_| SthError::Malformed)?;
        let msg = write_receipt_message(
            &self.sig_alg,
            &self.signer_pubkey,
            &self.payload_hash,
            self.tree_size,
            self.issued_at_ms,
        );
        pk.verify_strict(&msg, &Signature::from_bytes(&sig_bytes))
            .map_err(|_| SthError::InvalidSignature)
    }
}

fn write_receipt_message(
    sig_alg: &str,
    signer_pubkey_hex: &str,
    payload_hash_hex: &str,
    tree_size: u64,
    issued_at_ms: u64,
) -> Vec<u8> {
    let mut msg = Vec::new();
    msg.extend_from_slice(b"witness-log-write-receipt-v1");
    push_lp(&mut msg, sig_alg.as_bytes());
    push_lp(&mut msg, signer_pubkey_hex.as_bytes());
    push_lp(&mut msg, payload_hash_hex.as_bytes());
    msg.extend_from_slice(&tree_size.to_be_bytes());
    msg.extend_from_slice(&issued_at_ms.to_be_bytes());
    msg
}

fn push_lp(buf: &mut Vec<u8>, bytes: &[u8]) {
    buf.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    buf.extend_from_slice(bytes);
}

fn sth_message(
    sig_alg: &str,
    signer_pubkey_hex: &str,
    tree_size: u64,
    root_hash: &Hash,
    timestamp_ms: u64,
) -> Vec<u8> {
    let mut msg = Vec::new();
    msg.extend_from_slice(b"witness-log-sth-v2");
    push_lp(&mut msg, sig_alg.as_bytes());
    push_lp(&mut msg, signer_pubkey_hex.as_bytes());
    msg.extend_from_slice(&tree_size.to_be_bytes());
    msg.extend_from_slice(root_hash);
    msg.extend_from_slice(&timestamp_ms.to_be_bytes());
    msg
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn sth_roundtrip_and_tamper_detection() {
        let key = SigningKey::generate(&mut OsRng);
        let root = [7u8; 32];
        let mut sth = SignedTreeHead::sign(&key, 10, &root, 123_456);
        assert!(sth.verify().is_ok());
        sth.tree_size = 11; // tamper
        assert!(sth.verify().is_err());
    }

    #[test]
    fn unsupported_algorithm_rejected() {
        let key = SigningKey::generate(&mut OsRng);
        let mut sth = SignedTreeHead::sign(&key, 1, &[0u8; 32], 0);
        sth.sig_alg = "dilithium3".to_string();
        assert!(matches!(
            sth.verify(),
            Err(SthError::UnsupportedAlgorithm(_))
        ));
    }

    #[test]
    fn write_receipt_binds_event_and_signer() {
        let key = SigningKey::generate(&mut OsRng);
        let r = WriteReceipt::sign(&key, "AB".repeat(32).as_str(), 7, 1_700_000_000_000);
        assert!(r.verify().is_ok());
        assert_eq!(r.payload_hash, "ab".repeat(32), "normalised to lowercase");
        let mut t = r.clone();
        t.payload_hash = "cd".repeat(32);
        assert!(t.verify().is_err(), "payload hash is signed");
        let mut t = r.clone();
        t.tree_size += 1;
        assert!(t.verify().is_err(), "tree size is signed");
        let mut t = r.clone();
        t.issued_at_ms += 1;
        assert!(t.verify().is_err(), "time is signed");
        let other = SigningKey::generate(&mut OsRng);
        let mut t = r;
        t.signer_pubkey = hex::encode(other.verifying_key().to_bytes());
        assert!(t.verify().is_err(), "signer is signed");
    }
}
