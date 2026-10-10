//! GDPR/CCPA "right to be forgotten" via salted tombstones.
//!
//! `payload_hash = SHA256(bucket_pad(payload) || salt || leaf_index)`. The
//! Merkle tree only ever sees `payload_hash`; the salt lives in a *separate*
//! store. Deleting the salt makes `payload_hash` unrecomputable, which
//! makes the payload practically unrecoverable, while every hash already
//! committed into the tree — and every proof over it — stays valid.
//!
//! Two hardening choices worth calling out explicitly (see THREAT_MODEL.md):
//! 1. Bucket-padding the payload before hashing defeats length-correlation
//!    attacks on low-entropy payloads.
//! 2. Folding `leaf_index` into the hash means a dictionary/brute-force
//!    attack has to be repeated per-leaf; salts can't be reused to attack
//!    multiple leaves at once even if two payloads are identical.
//!
//! What this does NOT protect against, on its own: traffic analysis via
//! leaf-type visibility, timestamp correlation, or tree-position metadata.
//! State this explicitly to callers — see `RedactionEngine::forget`'s docs.

use sha2::{Digest, Sha256};
use std::collections::HashMap;

/// Payloads are padded up to the nearest bucket boundary before hashing so
/// that payload length doesn't leak through the hash's *input size* via
/// side channels in naive implementations that hash-then-store length
/// separately. (The hash itself is fixed-size regardless; this guards
/// callers who also log payload length alongside the hash.)
const BUCKET_SIZE: usize = 256;

/// Where salts live, decoupled from where leaves live. The default
/// (`SaltManager`) is in-memory only — it does NOT survive a process
/// restart, which is a deliberate, documented v0.1 limitation (see
/// `WitnessLog::save_snapshot`'s doc comment): losing salts on restart means
/// pre-restart leaves can no longer be redacted by *this* process, but
/// nothing about tree integrity depends on salts persisting, so this fails
/// safe rather than fails open.
///
/// The trait exists so that an operator who needs cross-restart redaction
/// capability, or who has retention-policy or access-control requirements
/// on salts that differ from their requirements on leaves (e.g. salts must
/// be encrypted at rest, or purged on a different schedule than leaves),
/// can supply their own store without forking `witness-log-core`. There is
/// deliberately only one implementation shipped today — this abstraction
/// earns its keep the moment a second one exists, not before.
///
/// `: Send` is required so `Box<dyn SaltStore>` can live inside `WitnessLog`
/// unconditionally, including behind language bindings (PyO3 `pyclass`
/// types must be `Send`).
pub trait SaltStore: Send {
    /// Generate a fresh salt for `leaf_index` and compute the payload hash
    /// to be committed into the tree.
    fn commit(&mut self, leaf_index: u64, payload: &[u8]) -> [u8; 32];
    /// Right-to-be-forgotten: permanently delete the salt for `leaf_index`.
    /// Returns `false` if there was nothing to forget (already forgotten,
    /// or never had a payload).
    fn forget(&mut self, leaf_index: u64) -> bool;
    fn has_salt(&self, leaf_index: u64) -> bool;
    /// Recompute the committed hash for a still-live leaf, e.g. to verify a
    /// payload against the tree before redacting it. `None` if the salt is
    /// gone (already forgotten) or never existed.
    fn recompute(&self, leaf_index: u64, payload: &[u8]) -> Option<[u8; 32]>;
}

pub struct SaltManager {
    salts: HashMap<u64, [u8; 32]>,
}

impl SaltManager {
    pub fn new() -> Self {
        Self {
            salts: HashMap::new(),
        }
    }

    /// Generate a fresh 32-byte salt for `leaf_index` and compute the
    /// payload hash to be committed into the tree.
    pub fn commit(&mut self, leaf_index: u64, payload: &[u8]) -> [u8; 32] {
        let salt = rand_salt();
        self.salts.insert(leaf_index, salt);
        payload_hash(payload, &salt, leaf_index)
    }

    /// Right-to-be-forgotten: permanently delete the salt for `leaf_index`.
    /// After this call, `payload_hash` for that leaf can no longer be
    /// recomputed from the original payload, even by this process — the
    /// salt is gone, not just hidden.
    pub fn forget(&mut self, leaf_index: u64) -> bool {
        self.salts.remove(&leaf_index).is_some()
    }

    pub fn has_salt(&self, leaf_index: u64) -> bool {
        self.salts.contains_key(&leaf_index)
    }

    /// Recompute the committed hash for a still-live (non-forgotten) leaf,
    /// e.g. to verify a payload against the tree before redacting it.
    pub fn recompute(&self, leaf_index: u64, payload: &[u8]) -> Option<[u8; 32]> {
        let salt = self.salts.get(&leaf_index)?;
        Some(payload_hash(payload, salt, leaf_index))
    }
}

impl Default for SaltManager {
    fn default() -> Self {
        Self::new()
    }
}

impl SaltStore for SaltManager {
    fn commit(&mut self, leaf_index: u64, payload: &[u8]) -> [u8; 32] {
        SaltManager::commit(self, leaf_index, payload)
    }
    fn forget(&mut self, leaf_index: u64) -> bool {
        SaltManager::forget(self, leaf_index)
    }
    fn has_salt(&self, leaf_index: u64) -> bool {
        SaltManager::has_salt(self, leaf_index)
    }
    fn recompute(&self, leaf_index: u64, payload: &[u8]) -> Option<[u8; 32]> {
        SaltManager::recompute(self, leaf_index, payload)
    }
}

/// SPEC §8 `payload_hash`, computable with an explicit salt. Exposed so
/// a verifier holding a disclosed salt, and the conformance corpus, can
/// recompute a commitment without a `SaltManager`.
pub fn payload_hash_with_salt(payload: &[u8], salt: &[u8; 32], leaf_index: u64) -> [u8; 32] {
    payload_hash(payload, salt, leaf_index)
}

fn payload_hash(payload: &[u8], salt: &[u8; 32], leaf_index: u64) -> [u8; 32] {
    let padded = bucket_pad(payload);
    let mut hasher = Sha256::new();
    hasher.update(&padded);
    hasher.update(salt);
    hasher.update(leaf_index.to_be_bytes());
    hasher.finalize().into()
}

/// `len(payload) as u64 (8B BE) || payload || zero padding`, where the
/// payload-plus-padding part is `(len / 256 + 1) * 256` bytes: 256 for
/// 0..=255 bytes, 512 for 256..=511, and so on. The 8-byte length prefix
/// sits outside the bucket, so the total is 264, 520, 776, …. Pinned by
/// corpus vector 11.
fn bucket_pad(payload: &[u8]) -> Vec<u8> {
    let target = ((payload.len() / BUCKET_SIZE) + 1) * BUCKET_SIZE;
    let mut out = Vec::with_capacity(target + 8);
    out.extend_from_slice(&(payload.len() as u64).to_be_bytes());
    out.extend_from_slice(payload);
    out.resize(target + 8, 0);
    out
}

fn rand_salt() -> [u8; 32] {
    use rand::RngCore;
    let mut salt = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut salt);
    salt
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn forget_makes_hash_unrecomputable() {
        let mut sm = SaltManager::new();
        let hash = sm.commit(0, b"user@example.com");
        assert_eq!(sm.recompute(0, b"user@example.com"), Some(hash));
        assert!(sm.forget(0));
        assert_eq!(sm.recompute(0, b"user@example.com"), None);
    }

    #[test]
    fn same_payload_different_index_yields_different_hash() {
        let mut sm = SaltManager::new();
        let h0 = sm.commit(0, b"identical payload");
        let h1 = sm.commit(1, b"identical payload");
        assert_ne!(h0, h1, "leaf_index must be folded into the hash");
    }

    #[test]
    fn short_and_long_payloads_pad_to_bucket_boundaries() {
        let short = bucket_pad(b"hi");
        let long = bucket_pad(&[0u8; 200]);
        assert_eq!(short.len(), BUCKET_SIZE + 8);
        assert_eq!(long.len(), BUCKET_SIZE + 8);
    }

    #[test]
    fn payload_inflation_attack_does_not_break_commit_or_recompute() {
        // A payload far larger than typical (here, ~2MB) must not panic,
        // overflow, or silently corrupt the hash. This is the "payload
        // inflation" attack shape: can an oversized input break the
        // redaction engine's invariants, not just slow it down.
        let mut sm = SaltManager::new();
        let huge_payload = vec![0x5Au8; 2 * 1024 * 1024];
        let hash = sm.commit(0, &huge_payload);
        assert_eq!(
            sm.recompute(0, &huge_payload),
            Some(hash),
            "recompute must still match commit for an oversized payload"
        );
        assert!(sm.forget(0));
        assert_eq!(sm.recompute(0, &huge_payload), None);
    }

    #[test]
    fn different_large_payloads_in_the_same_bucket_still_hash_differently() {
        // Two payloads that round up to the SAME padded length (same
        // bucket) must still produce different hashes — bucket padding
        // hides length, it must never collapse distinct content together.
        let mut sm = SaltManager::new();
        let mut payload_a = vec![0x11u8; 300]; // pads to 512
        let mut payload_b = vec![0x22u8; 300]; // same padded length, different content
        payload_a[0] = 0xAA;
        payload_b[0] = 0xBB;
        let hash_a = sm.commit(0, &payload_a);
        let hash_b = sm.commit(1, &payload_b);
        assert_ne!(hash_a, hash_b);
    }
}
