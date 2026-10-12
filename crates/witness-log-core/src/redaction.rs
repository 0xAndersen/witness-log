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
//! See THREAT_MODEL.md and `WitnessLog::forget`.

use sha2::{Digest, Sha256};
use std::collections::HashMap;

/// Payloads are padded up to the nearest bucket boundary before hashing so
/// that payload length doesn't leak through the hash's *input size* via
/// side channels in naive implementations that hash-then-store length
/// separately. (The hash itself is fixed-size regardless; this guards
/// callers who also log payload length alongside the hash.)
const BUCKET_SIZE: usize = 256;

/// Where salts live, decoupled from where leaves live.
///
/// Two implementations ship:
///
/// * [`SaltManager`] — in memory. Used by `WitnessLog::new`/`resume` and by
///   the snapshot path. Salts do not survive the process, so leaves
///   committed before a restart can no longer be redacted by the next
///   process. Nothing about tree integrity depends on salts persisting, so
///   this fails safe (toward "can no longer be redacted"), never open.
/// * [`FileSaltStore`] — a `<journal>.salts` sidecar, used automatically by
///   `JournaledLog`. Salts survive restarts, so `forget` works on any
///   leaf in the journal's history; a forgotten salt is physically
///   removed from the file.
///
/// The trait exists so an operator with retention or access-control
/// requirements on salts that differ from those on leaves (encrypted at
/// rest, an HSM, a different purge schedule) can supply their own store
/// through `WitnessLog::resume_with_salt_store` without forking the crate.
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
    /// Persistent stores: make everything committed so far durable. The
    /// in-memory store has nothing to do.
    fn sync(&mut self) -> std::io::Result<()> {
        Ok(())
    }
    /// Persistent stores: the first I/O error since the last call, if any.
    /// `commit` and `forget` have no error channel of their own, so a
    /// store that failed to persist reports it here and `JournaledLog`
    /// turns it into the error its caller sees.
    fn take_error(&mut self) -> Option<std::io::Error> {
        None
    }
    /// The salt held for `leaf_index`, for selective disclosure: handing
    /// a verifier the payload, this salt and the leaf lets them recompute
    /// `payload_hash` without access to the store (see
    /// [`verify_disclosure`]). `None` once the salt has been forgotten or
    /// if the leaf never had one. Stores that cannot release salts (an
    /// HSM) keep the default and simply cannot disclose.
    fn salt_for(&self, leaf_index: u64) -> Option<[u8; 32]> {
        let _ = leaf_index;
        None
    }
}

/// Salts persisted as one JSON line each in a sidecar file, 0600 on Unix.
///
/// Appends are O(1): one line per committed leaf. `forget` removes the
/// salt from memory and rewrites the file without it (temp file, fsync,
/// atomic rename), so the salt is gone from the live file, not merely
/// marked. The rewrite is O(salts); redaction requests are rare enough
/// that this is the right trade against an append-only tombstone format,
/// which could never erase anything.
///
/// Treat the sidecar like the journal header: it is what makes committed
/// payload hashes checkable against guessed payloads, and it must be
/// backed up together with the journal or redaction after a restore is
/// impossible. On an ordinary filesystem the blocks of a rewritten file
/// can linger until reused; put the sidecar on encrypted storage if a
/// forgotten salt must be unrecoverable at the block level.
pub struct FileSaltStore {
    path: std::path::PathBuf,
    file: std::fs::File,
    salts: HashMap<u64, [u8; 32]>,
    error: Option<std::io::Error>,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct SaltRecord {
    i: u64,
    s: String,
}

/// A salt record is ~90 bytes. Anything near this cap is not a record.
const MAX_SALT_LINE_BYTES: usize = 4096;

impl FileSaltStore {
    /// Open `path`, creating it if absent. Existing records are loaded; a
    /// torn final line (crash mid-write) is dropped and truncated away. An
    /// unparsable line followed by more content is corruption, not a torn
    /// tail, and is an error: delete the sidecar to proceed without the
    /// ability to redact earlier leaves.
    pub fn open(path: &str) -> std::io::Result<Self> {
        use std::io::{BufReader, Seek, SeekFrom};
        let mut open_opts = std::fs::OpenOptions::new();
        open_opts
            .read(true)
            .write(true)
            .create(true)
            .truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            open_opts.mode(0o600);
        }
        let mut file = open_opts.open(path)?;
        let mut salts = HashMap::new();
        let mut good_len: u64 = 0;
        let mut torn = false;
        {
            let mut reader = BufReader::new(&file);
            while let Some(line) =
                crate::journal::read_bounded_line(&mut reader, MAX_SALT_LINE_BYTES)?
            {
                if torn {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!(
                            "{path}: unparsable salt record followed by further content; \
                             the file is corrupted beyond a torn tail. Remove it to resume \
                             without the ability to redact earlier leaves."
                        ),
                    ));
                }
                let trimmed = line.trim();
                if trimmed.is_empty() {
                    good_len = good_len.saturating_add(line.len() as u64);
                    continue;
                }
                match serde_json::from_str::<SaltRecord>(trimmed) {
                    Ok(rec) => {
                        let salt = hex::decode(&rec.s)
                            .ok()
                            .and_then(|v| <[u8; 32]>::try_from(v).ok());
                        match salt {
                            Some(salt) => {
                                salts.insert(rec.i, salt);
                                good_len = good_len.saturating_add(line.len() as u64);
                            }
                            None => torn = true,
                        }
                    }
                    Err(_) => torn = true,
                }
            }
        }
        if file.metadata()?.len() != good_len {
            file.set_len(good_len)?;
        }
        file.seek(SeekFrom::End(0))?;
        Ok(Self {
            path: std::path::PathBuf::from(path),
            file,
            salts,
            error: None,
        })
    }

    pub fn len(&self) -> usize {
        self.salts.len()
    }

    pub fn is_empty(&self) -> bool {
        self.salts.is_empty()
    }

    /// Bring the store in line with a replayed log: drop salts for
    /// indices at or beyond `tree_size` (their leaf line was torn away)
    /// and for every index in `forgotten` (a redaction whose compaction
    /// did not complete). Rewrites the file only if something changed.
    pub fn reconcile(
        &mut self,
        tree_size: u64,
        forgotten: impl IntoIterator<Item = u64>,
    ) -> std::io::Result<()> {
        let before = self.salts.len();
        self.salts.retain(|i, _| *i < tree_size);
        for i in forgotten {
            self.salts.remove(&i);
        }
        if self.salts.len() != before {
            self.compact()?;
        }
        Ok(())
    }

    fn record_line(index: u64, salt: &[u8; 32]) -> std::io::Result<String> {
        serde_json::to_string(&SaltRecord {
            i: index,
            s: hex::encode(salt),
        })
        .map_err(std::io::Error::other)
    }

    /// Rewrite the whole file from memory: temp sibling (0600), fsync,
    /// rename over the original, fsync the directory, then continue
    /// appending to the new file.
    fn compact(&mut self) -> std::io::Result<()> {
        use std::io::{Seek, SeekFrom, Write};
        let dir = self
            .path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .map(std::path::Path::to_path_buf)
            .unwrap_or_else(|| std::path::PathBuf::from("."));
        let file_name = self
            .path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("salts");
        let rand_suffix: u64 = {
            use rand::RngCore;
            rand::rngs::OsRng.next_u64()
        };
        let tmp = dir.join(format!(
            ".{file_name}.tmp-{}-{rand_suffix:016x}",
            std::process::id()
        ));
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let written = (|| -> std::io::Result<std::fs::File> {
            let mut f = opts.open(&tmp)?;
            let mut indices: Vec<&u64> = self.salts.keys().collect();
            indices.sort_unstable();
            for i in indices {
                if let Some(salt) = self.salts.get(i) {
                    writeln!(f, "{}", Self::record_line(*i, salt)?)?;
                }
            }
            f.sync_all()?;
            Ok(f)
        })();
        let mut f = match written {
            Ok(f) => f,
            Err(e) => {
                let _ = std::fs::remove_file(&tmp);
                return Err(e);
            }
        };
        std::fs::rename(&tmp, &self.path)?;
        #[cfg(unix)]
        {
            if let Ok(d) = std::fs::File::open(&dir) {
                let _ = d.sync_all();
            }
        }
        f.seek(SeekFrom::End(0))?;
        self.file = f;
        Ok(())
    }

    fn note(&mut self, r: std::io::Result<()>) {
        if let Err(e) = r {
            if self.error.is_none() {
                self.error = Some(e);
            }
        }
    }
}

impl SaltStore for FileSaltStore {
    fn commit(&mut self, leaf_index: u64, payload: &[u8]) -> [u8; 32] {
        use std::io::Write;
        let salt = rand_salt();
        self.salts.insert(leaf_index, salt);
        let r = Self::record_line(leaf_index, &salt).and_then(|line| writeln!(self.file, "{line}"));
        self.note(r);
        payload_hash(payload, &salt, leaf_index)
    }
    fn forget(&mut self, leaf_index: u64) -> bool {
        if self.salts.remove(&leaf_index).is_none() {
            return false;
        }
        let r = self.compact();
        self.note(r);
        true
    }
    fn has_salt(&self, leaf_index: u64) -> bool {
        self.salts.contains_key(&leaf_index)
    }
    fn recompute(&self, leaf_index: u64, payload: &[u8]) -> Option<[u8; 32]> {
        let salt = self.salts.get(&leaf_index)?;
        Some(payload_hash(payload, salt, leaf_index))
    }
    fn sync(&mut self) -> std::io::Result<()> {
        use std::io::Write;
        self.file.flush()?;
        self.file.sync_all()
    }
    fn take_error(&mut self) -> Option<std::io::Error> {
        self.error.take()
    }
    fn salt_for(&self, leaf_index: u64) -> Option<[u8; 32]> {
        self.salts.get(&leaf_index).copied()
    }
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

    /// The salt for `leaf_index`, if still held. See [`SaltStore::salt_for`].
    pub fn salt_for(&self, leaf_index: u64) -> Option<[u8; 32]> {
        self.salts.get(&leaf_index).copied()
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
    fn salt_for(&self, leaf_index: u64) -> Option<[u8; 32]> {
        SaltManager::salt_for(self, leaf_index)
    }
}

/// SPEC §8 `payload_hash`, computable with an explicit salt. Exposed so
/// a verifier holding a disclosed salt, and the conformance corpus, can
/// recompute a commitment without a `SaltManager`.
pub fn payload_hash_with_salt(payload: &[u8], salt: &[u8; 32], leaf_index: u64) -> [u8; 32] {
    payload_hash(payload, salt, leaf_index)
}

/// Check a selective disclosure: that `payload` and `salt` are what `leaf`
/// committed to. Recomputes `SHA256(bucket_pad(payload) || salt ||
/// leaf.index)` and compares it with `leaf.payload_hash`. The leaf itself
/// should separately be proven against a checkpoint (an inclusion proof,
/// or the whole dossier); this answers only "is this the payload behind
/// that leaf". Marker leaves (0x03, 0x04) carry no payload and never
/// verify.
pub fn verify_disclosure(leaf: &crate::leaf::Leaf, payload: &[u8], salt: &[u8; 32]) -> bool {
    if matches!(
        crate::leaf::LeafType::from_tag(leaf.leaf_type),
        Some(crate::leaf::LeafType::Redaction) | Some(crate::leaf::LeafType::KeyRevocation)
    ) {
        return false;
    }
    let expected = payload_hash(payload, salt, leaf.index);
    hex::decode(&leaf.payload_hash)
        .map(|committed| committed == expected)
        .unwrap_or(false)
}

/// SPEC §8 `payload_hash`: `SHA256(bucket_pad(payload) || salt ||
/// leaf_index as u64 big-endian)`. Same function as
/// [`payload_hash_with_salt`], under the name the spec uses.
pub fn payload_hash(payload: &[u8], salt: &[u8; 32], leaf_index: u64) -> [u8; 32] {
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

    fn tmp(tag: &str) -> String {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir()
            .join(format!("wl-saltfile-{tag}-{}-{nanos}", std::process::id()))
            .to_string_lossy()
            .into_owned()
    }

    #[test]
    fn file_store_round_trips_and_forget_rewrites_the_file() {
        let p = tmp("rt");
        let (h0, h1);
        {
            let mut s = FileSaltStore::open(&p).unwrap();
            h0 = s.commit(0, b"zero");
            h1 = s.commit(1, b"one");
            s.sync().unwrap();
            assert!(s.take_error().is_none());
        }
        let mut s = FileSaltStore::open(&p).unwrap();
        assert_eq!(s.len(), 2);
        assert_eq!(s.recompute(0, b"zero"), Some(h0));
        assert_eq!(s.recompute(1, b"one"), Some(h1));
        assert!(s.forget(0));
        assert!(s.take_error().is_none());
        let on_disk = std::fs::read_to_string(&p).unwrap();
        assert_eq!(on_disk.lines().count(), 1);
        assert!(on_disk.contains("\"i\":1,"));
        // Appends keep working on the rewritten file.
        let h2 = s.commit(2, b"two");
        drop(s);
        let s = FileSaltStore::open(&p).unwrap();
        assert_eq!(s.recompute(0, b"zero"), None);
        assert_eq!(s.recompute(2, b"two"), Some(h2));
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    #[cfg(unix)]
    fn file_store_is_private_to_the_owner() {
        use std::os::unix::fs::PermissionsExt;
        let p = tmp("perm");
        let mut s = FileSaltStore::open(&p).unwrap();
        s.commit(0, b"x");
        assert!(s.forget(0));
        let mode = std::fs::metadata(&p).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "sidecar must stay 0600 across a rewrite, got {mode:o}"
        );
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn file_store_rejects_corruption_in_the_middle() {
        let p = tmp("corrupt");
        std::fs::write(
            &p,
            format!("not a record\n{{\"i\":1,\"s\":\"{}\"}}\n", "ab".repeat(32)),
        )
        .unwrap();
        assert!(FileSaltStore::open(&p).is_err());
        let _ = std::fs::remove_file(&p);
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
