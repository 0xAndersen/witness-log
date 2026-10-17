//! `logs/`, the witness's memory of what it cosigned, read on demand.
//!
//! A witness keeps one record per log: `logs/<sha256(origin)>.json`,
//! written atomically and fsynced before a cosignature leaves the process.
//! Through 0.5.0 `serve` parsed every record at startup and held them all
//! in memory, so a witness that had cosigned ~25,000 logs took minutes to
//! start on a cold disk and its memory grew with every log it ever saw
//! (found by the 100,000-agent load test).
//!
//! [`LogStore`] reads an origin's record when a request for that origin
//! arrives and keeps a bounded LRU cache of recently used records. Startup
//! lists `logs/` once, by name only (that count is what `--max-logs` and
//! `GET /` report), and opens no record. What must not change:
//!
//! - **The record file is the authority.** A lookup tells "no file" (a log
//!   this witness never cosigned) apart from "a file it cannot read or
//!   trust". The second fails closed and is never treated as a new log:
//!   that would enroll the log afresh at size 0 and cosign a fork.
//! - **The cache holds only what is on disk.** A record enters it after it
//!   was read, or after a new version was persisted. A failed persist drops
//!   the entry, so the next request reads the file again.
//! - **Callers serialize.** `serve` holds one mutex across the lookup, the
//!   decision and the persist, so the compare-and-update for one origin is
//!   atomic.
//! - **The format is unchanged.** Records are read and written exactly as
//!   before, including the check that a record's origin matches its name.

use crate::witness_cmd::atomic_write;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use witness_log_network::tlog_witness::{KnownLog, KnownLogRecord};

/// Records `serve` keeps in memory. A record is at most a few KiB (the
/// checkpoint body is capped at 1 KiB), so this bounds the cache at a few
/// MiB however many logs the witness has cosigned. A miss costs one small
/// file read, against the two fsyncs every cosignature already pays.
pub(crate) const DEFAULT_CACHE_CAPACITY: usize = 4096;

/// Where `origin`'s record lives under the witness directory `dir`.
pub(crate) fn record_path(dir: &Path, origin: &str) -> PathBuf {
    dir.join("logs").join(format!(
        "{}.json",
        hex::encode(Sha256::digest(origin.as_bytes()))
    ))
}

/// Write `k` as its origin's record: atomic and durable.
pub(crate) fn persist_record(dir: &Path, k: &KnownLog) -> io::Result<()> {
    let json = serde_json::to_vec_pretty(&k.to_record()).map_err(io::Error::other)?;
    atomic_write(&record_path(dir, &k.origin), &json)
}

/// `<64 lowercase hex>.json`: the only names `record_path` produces.
fn is_record_file_name(name: &str) -> bool {
    name.strip_suffix(".json")
        .is_some_and(|h| h.len() == 64 && h.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')))
}

/// Decode the record read from `path`, which must be `origin`'s.
fn parse_record(path: &Path, origin: &str, raw: &[u8]) -> Result<KnownLog, String> {
    let r: KnownLogRecord =
        serde_json::from_slice(raw).map_err(|e| format!("{}: {e}", path.display()))?;
    // `path` is `record_path(origin)`: a record naming another origin was
    // moved or edited, and must not stand in for this log's history.
    if r.origin != origin {
        return Err(format!(
            "{}: record origin does not match its file name (tampered state?)",
            path.display()
        ));
    }
    KnownLog::from_record(&r).map_err(|e| format!("{}: {e}", path.display()))
}

/// The witness's per-log records, read on demand. See the module docs.
pub(crate) struct LogStore {
    /// The witness directory (records live in `dir/logs`).
    dir: PathBuf,
    /// Record files in `logs/`: counted by name at open, plus logs this
    /// process enrolled since.
    count: usize,
    cache: RecordCache,
}

impl LogStore {
    /// Open the records under `dir/logs` without reading any of them.
    ///
    /// Refuses a missing `logs/` (the witness's memory was deleted:
    /// starting empty would let every log it ever cosigned be walked onto
    /// a fork) and any entry whose name `record_path` could not have
    /// produced (rather than guess what it is). Leftover temp files from a
    /// write interrupted by a crash are removed: the rename never happened,
    /// so the previous record is still the authority.
    pub(crate) fn open(dir: &Path, cache_capacity: usize) -> Result<Self, String> {
        let logs_dir = dir.join("logs");
        if !logs_dir.is_dir() {
            // `init` creates it. Missing state with a key present means the
            // witness's memory was deleted; starting empty would let every
            // log it ever cosigned be walked onto a fork.
            return Err(format!(
                "{} is missing. This witness has a key but no record of what it cosigned; \
                 starting empty would allow forks. Restore it from backup, or run `init` \
                 in a fresh directory to start a new witness with a new key.",
                logs_dir.display()
            ));
        }
        let mut count = 0usize;
        let entries =
            fs::read_dir(&logs_dir).map_err(|e| format!("{}: {e}", logs_dir.display()))?;
        for entry in entries {
            let entry = entry.map_err(|e| format!("{}: {e}", logs_dir.display()))?;
            let path = entry.path();
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name.starts_with('.') {
                let _ = fs::remove_file(&path);
                continue;
            }
            if !is_record_file_name(&name) {
                return Err(format!(
                    "{}: not a log record (logs/ holds only <sha256(origin)>.json files); \
                     move it out of logs/ (tampered or misplaced state?)",
                    path.display()
                ));
            }
            count += 1;
        }
        Ok(Self {
            dir: dir.to_path_buf(),
            count,
            cache: RecordCache::new(cache_capacity),
        })
    }

    /// Logs this witness holds a record for.
    pub(crate) fn count(&self) -> usize {
        self.count
    }

    /// What this witness holds for `origin`. `Ok(None)` only when it has no
    /// record file for it; a file that exists but cannot be read, parsed or
    /// matched to `origin` is an `Err`, which the caller must treat as
    /// "refuse", never as "new log".
    pub(crate) fn get(&mut self, origin: &str) -> Result<Option<KnownLog>, String> {
        if let Some(k) = self.cache.get(origin) {
            return Ok(Some(k));
        }
        let path = record_path(&self.dir, origin);
        let raw = match fs::read(&path) {
            Ok(raw) => raw,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                // No record, or no `logs/` at all (deleted while serving).
                // Only the first means "never cosigned".
                let logs_dir = self.dir.join("logs");
                if !logs_dir.is_dir() {
                    return Err(format!(
                        "{} is missing: this witness no longer has a record of what it cosigned",
                        logs_dir.display()
                    ));
                }
                return Ok(None);
            }
            Err(e) => return Err(format!("{}: {e}", path.display())),
        };
        let k = parse_record(&path, origin, &raw)?;
        self.cache.insert(k.clone());
        Ok(Some(k))
    }

    /// Persist `k`, the advanced record for its origin, durably; only then
    /// cache it. `new` says the origin had no record before (an
    /// enrollment), which grows the count once the file exists.
    ///
    /// On `Err` the caller must not release the cosignature. The cached copy
    /// is dropped either way: the rename may or may not have happened, and
    /// the file is the authority. Both possible states are safe, because
    /// the witness never released a cosignature for the head it failed to
    /// persist.
    pub(crate) fn put(&mut self, k: KnownLog, new: bool) -> io::Result<()> {
        match persist_record(&self.dir, &k) {
            Ok(()) => {
                if new {
                    self.count += 1;
                }
                self.cache.insert(k);
                Ok(())
            }
            Err(e) => {
                self.cache.remove(&k.origin);
                if new && record_path(&self.dir, &k.origin).exists() {
                    self.count += 1;
                }
                Err(e)
            }
        }
    }

    /// Records currently held in memory.
    #[cfg(test)]
    pub(crate) fn cached(&self) -> usize {
        self.cache.len()
    }
}

/// A bounded least-recently-used map from origin to record. Every
/// operation is O(log n) in the capacity.
struct RecordCache {
    capacity: usize,
    tick: u64,
    entries: HashMap<String, (u64, KnownLog)>,
    /// Last-use tick -> origin; the first entry is evicted first.
    by_age: BTreeMap<u64, String>,
}

impl RecordCache {
    /// `capacity` 0 caches nothing: every lookup reads the file.
    fn new(capacity: usize) -> Self {
        Self {
            capacity,
            tick: 0,
            entries: HashMap::new(),
            by_age: BTreeMap::new(),
        }
    }

    fn next_tick(&mut self) -> u64 {
        self.tick += 1;
        self.tick
    }

    fn get(&mut self, origin: &str) -> Option<KnownLog> {
        let tick = self.next_tick();
        let (used, k) = self.entries.get_mut(origin)?;
        self.by_age.remove(used);
        *used = tick;
        self.by_age.insert(tick, origin.to_string());
        Some(k.clone())
    }

    fn insert(&mut self, k: KnownLog) {
        if self.capacity == 0 {
            return;
        }
        let tick = self.next_tick();
        let origin = k.origin.clone();
        if let Some((old, _)) = self.entries.insert(origin.clone(), (tick, k)) {
            self.by_age.remove(&old);
        }
        self.by_age.insert(tick, origin);
        while self.entries.len() > self.capacity {
            let Some((_, oldest)) = self.by_age.pop_first() else {
                break;
            };
            self.entries.remove(&oldest);
        }
    }

    fn remove(&mut self, origin: &str) {
        if let Some((used, _)) = self.entries.remove(origin) {
            self.by_age.remove(&used);
        }
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        debug_assert_eq!(self.entries.len(), self.by_age.len());
        self.entries.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use witness_log_core::c2sp::{canonical_origin, VerifierKey};

    fn tmpdir(tag: &str) -> PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static N: AtomicU64 = AtomicU64::new(0);
        let d = std::env::temp_dir().join(format!(
            "wl-store-{tag}-{}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(d.join("logs")).unwrap();
        d
    }

    fn log(i: u8, size: u64) -> KnownLog {
        let key = SigningKey::from_bytes(&[i; 32]);
        let origin = canonical_origin(&key.verifying_key());
        let mut k = KnownLog::new(
            &origin,
            VerifierKey::for_ed25519(&origin, &key.verifying_key()),
        );
        k.tree_size = size;
        k.root_hash = [i; 32];
        k
    }

    #[test]
    fn cache_is_bounded_and_evicts_the_least_recently_used() {
        let mut c = RecordCache::new(2);
        let (a, b, d) = (log(1, 1), log(2, 1), log(3, 1));
        c.insert(a.clone());
        c.insert(b.clone());
        assert!(c.get(&a.origin).is_some()); // a is now the most recent
        c.insert(d.clone());
        assert_eq!(c.len(), 2);
        assert!(c.get(&b.origin).is_none(), "b was least recently used");
        assert!(c.get(&a.origin).is_some());
        assert!(c.get(&d.origin).is_some());
        // Replacing an entry does not grow the cache.
        let mut a2 = a.clone();
        a2.tree_size = 9;
        c.insert(a2);
        assert_eq!(c.len(), 2);
        assert_eq!(c.get(&a.origin).unwrap().tree_size, 9);
        c.remove(&a.origin);
        assert_eq!(c.len(), 1);
        let mut none = RecordCache::new(0);
        none.insert(a);
        assert_eq!(none.len(), 0);
    }

    #[test]
    fn open_counts_names_and_reads_no_record() {
        let dir = tmpdir("open");
        let a = log(1, 3);
        persist_record(&dir, &a).unwrap();
        // Garbage under a record name: open must not read it, and a lookup
        // of that origin must fail closed, not report "no record".
        let garbage = log(2, 0);
        fs::write(record_path(&dir, &garbage.origin), b"{ not json").unwrap();
        // A leftover temp file from a crash mid-write is swept.
        fs::write(dir.join("logs").join(".x.json.tmp-1"), b"partial").unwrap();
        let mut s = LogStore::open(&dir, 8).unwrap();
        assert_eq!(s.count(), 2);
        assert_eq!(s.cached(), 0, "nothing is read at open");
        assert!(!dir.join("logs").join(".x.json.tmp-1").exists());
        assert_eq!(s.get(&a.origin).unwrap(), Some(a.clone()));
        assert!(s.get(&garbage.origin).is_err());
        assert_eq!(s.get(&log(3, 0).origin).unwrap(), None);
        assert_eq!(s.cached(), 1, "only the readable record is cached");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn open_refuses_a_missing_logs_dir_and_foreign_names() {
        let dir = tmpdir("refuse");
        fs::write(dir.join("logs").join("notes.txt"), b"hi").unwrap();
        let e = LogStore::open(&dir, 8).err().unwrap();
        assert!(e.contains("not a log record"), "{e}");
        fs::remove_file(dir.join("logs").join("notes.txt")).unwrap();
        let upper = format!("{}.json", "A".repeat(64));
        fs::write(dir.join("logs").join(&upper), b"{}").unwrap();
        assert!(
            LogStore::open(&dir, 8).is_err(),
            "record names are lowercase"
        );
        fs::remove_dir_all(dir.join("logs")).unwrap();
        let e = LogStore::open(&dir, 8).err().unwrap();
        assert!(e.contains("is missing"), "{e}");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_record_under_another_origins_name_fails_closed() {
        let dir = tmpdir("moved");
        let (a, b) = (log(1, 5), log(2, 0));
        // a's record, moved to b's file name.
        let json = serde_json::to_vec_pretty(&a.to_record()).unwrap();
        fs::write(record_path(&dir, &b.origin), json).unwrap();
        let mut s = LogStore::open(&dir, 8).unwrap();
        let e = s.get(&b.origin).err().unwrap();
        assert!(e.contains("does not match its file name"), "{e}");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn put_persists_before_caching_and_eviction_rereads_the_file() {
        let dir = tmpdir("put");
        let mut s = LogStore::open(&dir, 1).unwrap();
        let (a, b) = (log(1, 4), log(2, 6));
        s.put(a.clone(), true).unwrap();
        s.put(b.clone(), true).unwrap();
        assert_eq!(s.count(), 2);
        assert_eq!(s.cached(), 1, "capacity 1");
        // a was evicted; it comes back from disk, byte-for-byte the record.
        assert_eq!(s.get(&a.origin).unwrap(), Some(a.clone()));
        let on_disk = fs::read(record_path(&dir, &a.origin)).unwrap();
        assert_eq!(on_disk, serde_json::to_vec_pretty(&a.to_record()).unwrap());
        // Advancing an existing log does not change the count.
        let mut a2 = a.clone();
        a2.tree_size = 8;
        s.put(a2.clone(), false).unwrap();
        assert_eq!(s.count(), 2);
        assert_eq!(s.get(&a.origin).unwrap(), Some(a2));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_failed_persist_leaves_the_file_as_the_authority() {
        let dir = tmpdir("fail");
        let mut s = LogStore::open(&dir, 8).unwrap();
        let a = log(1, 4);
        s.put(a.clone(), true).unwrap();
        // Make the next write fail: logs/ replaced by a file.
        fs::remove_dir_all(dir.join("logs")).unwrap();
        fs::write(dir.join("logs"), b"").unwrap();
        let mut a2 = a.clone();
        a2.tree_size = 9;
        assert!(s.put(a2, false).is_err());
        // The cached copy was dropped; the lookup now fails closed instead
        // of answering from memory or calling the log new.
        assert!(s.get(&a.origin).is_err());
        assert!(s.get(&log(3, 0).origin).is_err());
        let _ = fs::remove_dir_all(&dir);
    }
}
