//! Append-only leaf journal: the scale-path for persistence.
//!
//! `save_snapshot` rewrites the entire log as one JSON file per save —
//! fine for thousands of leaves, an obvious O(n)-per-save wall for
//! millions. The journal writes each leaf exactly once, as one JSON line
//! appended to a file, never rewritten. Restart = replay the lines.
//!
//! Deliberately NOT a StorageEngine trait, a database, or an async
//! pipeline (all previously declined — see project history): it's a file
//! you can inspect with `less`, repair with a text editor, and replay
//! with twenty lines of any language. The header line carries identity
//! key material and MUST be protected like any private key file — same
//! caveat as `save_snapshot`, documented there.

use crate::identity::{IdentityKeypair, KeyBindingStatement};
use crate::leaf::{AuthorizationEventKind, Leaf};
use crate::log::WitnessLog;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Seek, SeekFrom, Write};

/// One record in the journal. `untagged` deliberately: a leaf line keeps
/// exactly the shape it always had, so journals written before binding
/// records existed replay unchanged. The two variants are structurally
/// unambiguous — a `Leaf` requires `index` and `leaf_type`, a
/// `KeyBindingStatement` requires `identity_pubkey` and `signature` —
/// so serde can tell them apart without a discriminator field.
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
enum JournalRecord {
    Leaf(Box<Leaf>),
    Binding(Box<KeyBindingStatement>),
}

/// Hard cap on a single journal line, in bytes. `replay` previously used
/// `BufRead::lines()`, which allocates without bound for however long a
/// single line runs — relevant for a crate whose pitch is million-leaf
/// logs, where a corrupted or hostile journal file with one absurdly
/// long line could exhaust memory before any content check runs. 16MiB
/// is generous for any real leaf (which carries fixed-width hex fields,
/// not arbitrary payloads — payloads are hashed, not stored) while still
/// bounding the worst case. See the pre-launch review, finding 20.
const MAX_JOURNAL_LINE_BYTES: usize = 16 * 1024 * 1024;

/// Generous bound on everything in an external-anchor leaf line other
/// than the two caller-supplied strings: field names, hex keys and
/// hashes, the newline. A full leaf with 64-hex fields is under 1 KiB.
const ANCHOR_LEAF_FIXED_OVERHEAD: usize = 4096;

/// Read one line (including its trailing `\n` if present) from `reader`,
/// bailing with an error the moment the accumulated length exceeds
/// `max_len` rather than continuing to grow an unbounded buffer. Returns
/// `Ok(None)` on clean EOF with nothing read, `Ok(Some(line))` otherwise
/// (mirroring `BufRead::read_line`'s contract, but bounded and returning
/// the line rather than a byte count).
pub(crate) fn read_bounded_line<R: BufRead>(
    reader: &mut R,
    max_len: usize,
) -> std::io::Result<Option<String>> {
    let mut buf: Vec<u8> = Vec::new();
    loop {
        let available = reader.fill_buf()?;
        if available.is_empty() {
            if buf.is_empty() {
                return Ok(None);
            }
            break; // EOF without a trailing newline -- return what we have
        }
        match available.iter().position(|&b| b == b'\n') {
            Some(pos) => {
                // `get` rather than slicing: journal files are untrusted
                // on replay (they may be corrupt or hostile), and a
                // panicking reader would take the host process with it.
                let through_newline = available
                    .get(..=pos)
                    .ok_or_else(|| std::io::Error::other("internal: newline index out of range"))?;
                buf.extend_from_slice(through_newline);
                reader.consume(pos.saturating_add(1));
                break;
            }
            None => {
                buf.extend_from_slice(available);
                let n = available.len();
                reader.consume(n);
            }
        }
        if buf.len() > max_len {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("journal line exceeds {max_len} byte cap"),
            ));
        }
    }
    if buf.len() > max_len {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("journal line exceeds {max_len} byte cap"),
        ));
    }
    String::from_utf8(buf)
        .map(Some)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
}

#[derive(serde::Serialize, serde::Deserialize)]
struct JournalHeader {
    format_version: u8,
    /// The raw Ed25519 identity seed, hex. Empty when the journal is
    /// *sealed*: the seed is then supplied by the caller on every resume
    /// (`JournaledLog::resume_with_identity`) and `identity_pubkey_hex`
    /// pins which seed is acceptable.
    identity_bytes_hex: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    identity_pubkey_hex: Option<String>,
    session_number: u64,
}

/// Appends each leaf as one JSON line. Owned separately from `WitnessLog`
/// so journaling stays opt-in and the core stays storage-free: callers
/// wire the two together (see `JournaledLog` for the batteries-included
/// pairing).
pub struct LeafJournal {
    file: File,
    /// Held for the journal's lifetime. Dropping it releases the lock.
    _lock: JournalLock,
    /// The path we opened, and the identity of the file behind it at
    /// open time. `sync` re-checks both: on Unix, deleting or replacing a
    /// journal under a live process leaves the open handle writing to an
    /// unlinked inode, and every subsequent append is silently lost when
    /// the process exits. For an audit log, silent loss is the worst
    /// available failure.
    path: std::path::PathBuf,
    file_id: Option<FileId>,
}

/// (device, inode) on Unix; `None` elsewhere, where only existence is
/// checked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileId(u64, u64);

fn file_id_of(meta: &std::fs::Metadata) -> Option<FileId> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        Some(FileId(meta.dev(), meta.ino()))
    }
    #[cfg(not(unix))]
    {
        let _ = meta;
        None
    }
}

/// An exclusive advisory lock on a journal, via an `O_EXCL`-created
/// sidecar file. Two live handles on one journal interleave their
/// sessions' leaves with conflicting indices and corrupt it silently;
/// found by the three-perspective review (B2). A supervisor that
/// restarts a crashed-but-not-dead process hits this. With the lock, the
/// second open fails cleanly with `AlreadyExists` instead.
///
/// Sidecar rather than `flock`: `flock` is Unix-only and silently
/// absent on some filesystems (NFS, some containers). An `O_EXCL`
/// create is atomic everywhere `std` supports. The cost is a stale
/// lock after a hard crash, which `force_unlock` handles explicitly —
/// a visible decision rather than a silent one.
struct JournalLock {
    path: std::path::PathBuf,
    /// What this process wrote into the lock file. `Drop` removes the
    /// file only while it still says this, so a lock taken over by another
    /// process after a stale-lock recovery is never deleted from under it.
    token: String,
}

impl JournalLock {
    fn acquire(journal_path: &str) -> std::io::Result<Self> {
        let path = std::path::PathBuf::from(format!("{journal_path}.lock"));
        let token = format!("{}", std::process::id());
        match Self::try_create(&path, &token) {
            Ok(lock) => Ok(lock),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                if Self::take_over_if_stale(&path)? {
                    if let Ok(lock) = Self::try_create(&path, &token) {
                        // Another recoverer may have raced us through the
                        // same stale lock. Give it a moment, then confirm
                        // the file still carries our token.
                        std::thread::sleep(std::time::Duration::from_millis(100));
                        if std::fs::read_to_string(&path)
                            .map(|s| s.trim() == token)
                            .unwrap_or(false)
                        {
                            return Ok(lock);
                        }
                        // Lost the race: `lock` drops without deleting
                        // the winner's file (token mismatch).
                    }
                }
                Err(std::io::Error::new(
                    std::io::ErrorKind::AlreadyExists,
                    format!(
                        "journal is already open: lock file {} is held by a live process. \
                         If you are certain no other process has this journal open, call \
                         JournaledLog::force_unlock first.",
                        path.display()
                    ),
                ))
            }
            Err(e) => Err(e),
        }
    }

    fn try_create(path: &std::path::Path, token: &str) -> std::io::Result<Self> {
        let mut f = OpenOptions::new().write(true).create_new(true).open(path)?;
        // Record who holds it: the PID, for diagnostics and for stale
        // detection after a crash.
        let _ = writeln!(f, "{token}");
        let _ = f.sync_all();
        Ok(Self {
            path: path.to_path_buf(),
            token: token.to_string(),
        })
    }

    /// A lock whose recorded PID is no longer running is stale: the
    /// holder died without dropping it (SIGKILL, OOM, power loss). A
    /// supervisor restarting that agent must be able to resume without a
    /// human running `force_unlock`, so the stale file is moved aside and
    /// `Ok(true)` is returned. Liveness is checked through `/proc` on
    /// Linux; elsewhere there is no portable check without `libc`, so
    /// the lock is left alone and the caller gets the explicit error.
    ///
    /// The file is renamed, not deleted, and only after re-checking that
    /// the path still names the inode whose PID was read, so a lock that
    /// a concurrent recoverer has already replaced is not touched.
    fn take_over_if_stale(path: &std::path::Path) -> std::io::Result<bool> {
        #[cfg(target_os = "linux")]
        {
            let f = match File::open(path) {
                Ok(f) => f,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(true),
                Err(e) => return Err(e),
            };
            let opened = f.metadata().ok().as_ref().and_then(file_id_of);
            let mut content = String::new();
            {
                use std::io::Read;
                let _ = (&f).take(64).read_to_string(&mut content);
            }
            let Ok(pid) = content.trim().parse::<u32>() else {
                return Ok(false); // not our format: never steal it
            };
            if pid == std::process::id() || std::path::Path::new(&format!("/proc/{pid}")).exists() {
                return Ok(false);
            }
            let now = std::fs::metadata(path).ok().as_ref().and_then(file_id_of);
            if opened.is_none() || opened != now {
                return Ok(false);
            }
            let aside = path.with_extension(format!(
                "lock.stale-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_nanos())
                    .unwrap_or(0)
            ));
            std::fs::rename(path, &aside)?;
            let _ = std::fs::remove_file(&aside);
            Ok(true)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = path;
            Ok(false)
        }
    }
}

impl Drop for JournalLock {
    fn drop(&mut self) {
        let still_ours = std::fs::read_to_string(&self.path)
            .map(|s| s.trim() == self.token)
            .unwrap_or(false);
        if still_ours {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

impl LeafJournal {
    /// Create a NEW journal at `path`, writing the header line. Fails if
    /// the file already exists — replaying an existing journal is
    /// `LeafJournal::replay`'s job, and silently appending a second
    /// header into an existing journal would corrupt it.
    pub fn create(
        path: &str,
        identity_bytes: &[u8; 32],
        session_number: u64,
    ) -> std::io::Result<Self> {
        Self::create_inner(path, Some(identity_bytes), None, session_number)
    }

    /// Create a journal whose header holds only the identity's PUBLIC
    /// key. The seed never touches this file; `replay_with_identity`
    /// must be given it (from a KMS, an environment variable, a secrets
    /// manager) and checks that it matches the pinned public key.
    pub fn create_sealed(
        path: &str,
        identity_pubkey_hex: &str,
        session_number: u64,
    ) -> std::io::Result<Self> {
        Self::create_inner(path, None, Some(identity_pubkey_hex), session_number)
    }

    fn create_inner(
        path: &str,
        identity_bytes: Option<&[u8; 32]>,
        identity_pubkey_hex: Option<&str>,
        session_number: u64,
    ) -> std::io::Result<Self> {
        let mut open_opts = OpenOptions::new();
        open_opts.write(true).create_new(true);
        // 0600 from the moment of creation: the journal header contains
        // identity_bytes_hex, the raw Ed25519 seed, in plaintext, same as
        // the snapshot format. Default create() permissions are world-
        // readable on Unix. See the pre-launch review, finding 09.
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            open_opts.mode(0o600);
        }
        let lock = JournalLock::acquire(path)?;
        let mut file = open_opts.open(path)?;
        let header = JournalHeader {
            format_version: Self::JOURNAL_FORMAT_VERSION,
            identity_bytes_hex: identity_bytes.map(hex::encode).unwrap_or_default(),
            identity_pubkey_hex: identity_pubkey_hex.map(str::to_string),
            session_number,
        };
        // Zeroizing: same rationale as save_snapshot's -- this string
        // embeds identity_bytes_hex, the raw Ed25519 seed, in plaintext.
        // See the pre-launch review, finding 21.
        let line: zeroize::Zeroizing<String> =
            zeroize::Zeroizing::new(serde_json::to_string(&header).map_err(std::io::Error::other)?);
        writeln!(file, "{}", line.as_str())?;
        file.sync_all()?;
        let file_id = file.metadata().ok().as_ref().and_then(file_id_of);
        Ok(Self {
            file,
            _lock: lock,
            path: std::path::PathBuf::from(path),
            file_id,
        })
    }

    /// Open an EXISTING journal for further appends. `truncate_to` MUST
    /// be `ReplayReport::good_byte_length` from a prior `replay` call on
    /// this same path — there is deliberately no zero-argument overload,
    /// so it's structurally impossible to open a journal for append
    /// without first replaying it and learning where the last good line
    /// ends.
    ///
    /// Truncates the file to `truncate_to` BEFORE returning. Without
    /// this, a torn tail line (the only thing a crash can damage in an
    /// append-only file) was left in place and the next `append` wrote
    /// directly on top of it: exactly one append after recovery silently
    /// ATE the next leaf (it became indistinguishable from a new torn
    /// tail on the following restart); two or more appends left content
    /// after the torn line, which `replay` correctly refuses to treat as
    /// a torn tail and instead reports as unrecoverable corruption —
    /// permanently bricking the journal. See the pre-launch review,
    /// finding 07.
    pub fn open_for_append(path: &str, truncate_to: u64) -> std::io::Result<Self> {
        let lock = JournalLock::acquire(path)?;
        // Opened for write, not append: on Windows an append-only handle
        // has no permission to truncate, so healing a torn tail with
        // `set_len` failed with "Access is denied" on EVERY resume (the
        // first CI run on Windows). The lock guarantees a single writer,
        // so seeking to the end gives the same append behaviour.
        let mut file = OpenOptions::new().write(true).open(path)?;
        if file.metadata()?.len() != truncate_to {
            file.set_len(truncate_to)?;
        }
        file.seek(SeekFrom::End(0))?;
        let file_id = file.metadata().ok().as_ref().and_then(file_id_of);
        Ok(Self {
            file,
            _lock: lock,
            path: std::path::PathBuf::from(path),
            file_id,
        })
    }

    /// Remove a stale lock left by a process that died without dropping
    /// its journal. Deliberately explicit: silently stealing a lock is
    /// how two processes end up writing one file.
    pub fn force_unlock(path: &str) -> std::io::Result<()> {
        match std::fs::remove_file(format!("{path}.lock")) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e),
        }
    }

    /// Append one leaf as one line. O(leaf), not O(log) — this is the
    /// entire point versus `save_snapshot`.
    ///
    /// A line longer than `replay` will read back is refused here, so the
    /// journal can never hold a leaf that bricks its own resume. The only
    /// leaf whose size a caller controls is the external anchor;
    /// `JournaledLog::append_external_anchor` checks the budget before the
    /// leaf enters the in-memory tree.
    pub fn append(&mut self, leaf: &Leaf) -> std::io::Result<()> {
        let line = serde_json::to_string(leaf).map_err(std::io::Error::other)?;
        if line.len().saturating_add(1) > MAX_JOURNAL_LINE_BYTES {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "leaf serialises to {} bytes; the journal line cap is {MAX_JOURNAL_LINE_BYTES}",
                    line.len()
                ),
            ));
        }
        writeln!(self.file, "{line}")?;
        Ok(())
    }

    /// Whether an external-anchor leaf with these fields fits in one
    /// journal line, measured on the JSON-escaped strings with headroom
    /// for the leaf's fixed-width fields.
    pub fn anchor_fits(anchor_url: &str, anchor_proof_json: &str) -> bool {
        let escaped = |s: &str| {
            serde_json::to_string(s)
                .map(|j| j.len())
                .unwrap_or(usize::MAX)
        };
        escaped(anchor_url)
            .saturating_add(escaped(anchor_proof_json))
            .saturating_add(ANCHOR_LEAF_FIXED_OVERHEAD)
            <= MAX_JOURNAL_LINE_BYTES
    }

    /// Append a key-binding record. Not part of the Merkle tree — this
    /// records which session key was authorized to write the leaves that
    /// follow it, which a verifier needs in order to accept leaves
    /// written by a session that no longer exists.
    pub fn append_binding(&mut self, binding: &KeyBindingStatement) -> std::io::Result<()> {
        let record = JournalRecord::Binding(Box::new(binding.clone()));
        let line = serde_json::to_string(&record).map_err(std::io::Error::other)?;
        writeln!(self.file, "{line}")
    }

    /// Flush + fsync. Callers choose their own durability cadence (every
    /// leaf, every checkpoint, ...) rather than the library imposing one.
    ///
    /// After syncing, confirms the journal is still the file at the path
    /// it was opened from. If it was deleted or replaced, returns an
    /// error rather than reporting success for data that will be lost:
    /// the fsync succeeded, but on an inode nobody can reach. Detection,
    /// not prevention -- appends between the deletion and this call are
    /// already gone -- but it turns silent loss into a loud failure at
    /// exactly the point the caller asked for durability.
    pub fn sync(&mut self) -> std::io::Result<()> {
        self.file.flush()?;
        self.file.sync_all()?;
        let current = match std::fs::metadata(&self.path) {
            Ok(m) => m,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    format!(
                        "journal {} was deleted while open; appends since then are lost",
                        self.path.display()
                    ),
                ));
            }
            Err(e) => return Err(e),
        };
        if let (Some(opened), Some(now)) = (self.file_id, file_id_of(&current)) {
            if opened != now {
                return Err(std::io::Error::other(format!(
                    "journal {} was replaced by a different file while open; \
                     appends since then went to the old, now-unreachable file",
                    self.path.display()
                )));
            }
        }
        Ok(())
    }

    /// Current on-disk journal format. Bump this and add handling in
    /// `replay` — never silently reinterpret an old or future format
    /// under the current header layout.
    pub const JOURNAL_FORMAT_VERSION: u8 = 1;

    /// Replay a journal into a fresh `WitnessLog`, advancing the session
    /// number — the journal equivalent of `load_snapshot`. A truncated
    /// final line (crash mid-append) is tolerated and dropped with its
    /// count reported, because an append-only journal's last line is the
    /// only line a crash can ever damage; every earlier line was complete
    /// when written.
    pub fn replay(path: &str) -> std::io::Result<(WitnessLog, ReplayReport)> {
        Self::replay_inner(path, None)
    }

    /// Replay a sealed journal (see `create_sealed`), supplying the
    /// identity seed the header does not hold. Also accepted for an
    /// unsealed journal, in which case the seed must equal the stored one.
    pub fn replay_with_identity(
        path: &str,
        identity_bytes: &[u8; 32],
    ) -> std::io::Result<(WitnessLog, ReplayReport)> {
        Self::replay_inner(path, Some(identity_bytes))
    }

    fn replay_inner(
        path: &str,
        supplied: Option<&[u8; 32]>,
    ) -> std::io::Result<(WitnessLog, ReplayReport)> {
        let file = File::open(path)?;
        let mut reader = BufReader::new(file);
        let mut offset: u64 = 0;

        let header_line = match read_bounded_line(&mut reader, MAX_JOURNAL_LINE_BYTES)? {
            None => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "empty journal",
                ))
            }
            Some(l) => l,
        };
        offset += header_line.len() as u64;
        let header: JournalHeader = serde_json::from_str(header_line.trim_end())
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        // format_version was carried on disk but never actually checked
        // (same gap as load_snapshot's — see finding 20).
        if header.format_version != Self::JOURNAL_FORMAT_VERSION {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "unsupported journal format_version {} (this build supports {})",
                    header.format_version,
                    Self::JOURNAL_FORMAT_VERSION
                ),
            ));
        }
        let invalid = |m: &str| std::io::Error::new(std::io::ErrorKind::InvalidData, m.to_string());
        let identity_bytes: [u8; 32] = if header.identity_bytes_hex.is_empty() {
            // Sealed journal: the seed must come from the caller and must
            // be the one the header pinned, or a stranger's key could
            // continue this history under a new identity.
            let Some(seed) = supplied else {
                return Err(invalid(
                    "this journal is sealed (header holds only identity_pubkey_hex); \
                     resume it with the identity seed (JournaledLog::resume_with_identity)",
                ));
            };
            let expected = header
                .identity_pubkey_hex
                .as_deref()
                .ok_or_else(|| invalid("sealed journal header has no identity_pubkey_hex"))?;
            let actual = hex::encode(
                ed25519_dalek::SigningKey::from_bytes(seed)
                    .verifying_key()
                    .to_bytes(),
            );
            if actual != expected.to_ascii_lowercase() {
                return Err(invalid(
                    "supplied identity seed does not match the public key this sealed journal was created with",
                ));
            }
            *seed
        } else {
            let stored: [u8; 32] = hex::decode(&header.identity_bytes_hex)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?
                .try_into()
                .map_err(|_| invalid("identity key must be 32 bytes"))?;
            if let Some(seed) = supplied {
                if seed != &stored {
                    return Err(invalid(
                        "supplied identity seed does not match the identity stored in this journal",
                    ));
                }
            }
            stored
        };

        let mut leaves = Vec::new();
        let mut replayed_bindings: Vec<KeyBindingStatement> = Vec::new();
        let mut dropped_trailing = 0usize;
        let mut saw_unparsable = false;
        // The safe truncation point: initially right after the header,
        // advanced to the end of each successfully-parsed leaf line as
        // replay proceeds. A torn or unparsable trailing line is never
        // included, so truncating here always discards exactly the torn
        // write and nothing else.
        let mut good_byte_length = offset;

        loop {
            let line = match read_bounded_line(&mut reader, MAX_JOURNAL_LINE_BYTES)? {
                None => break, // EOF
                Some(l) => l,
            };
            offset += line.len() as u64;
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            if saw_unparsable {
                // ANY content after an unparsable line — parsable or not —
                // means the damage wasn't a torn tail write. A crash can
                // only ever damage the final line of an append-only file;
                // damage followed by more content is real corruption and
                // must fail loudly, never be skipped over. No truncation
                // point is offered in this case — resume must not proceed.
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "unparsable line followed by further content — journal is corrupted beyond a single torn tail write",
                ));
            }
            match serde_json::from_str::<JournalRecord>(trimmed) {
                Ok(JournalRecord::Leaf(leaf)) => {
                    leaves.push(*leaf);
                    good_byte_length = offset;
                }
                Ok(JournalRecord::Binding(b)) => {
                    // A binding record marks the start of a session. It
                    // is not part of the Merkle tree -- it is the proof
                    // that the session key which signed the leaves after
                    // it was authorized by the identity.
                    replayed_bindings.push(*b);
                    good_byte_length = offset;
                }
                Err(_) => {
                    saw_unparsable = true;
                    dropped_trailing += 1;
                    // good_byte_length stays at the end of the previous
                    // good line -- truncating here removes exactly this
                    // torn line and nothing that came before it.
                }
            }
        }
        let identity = IdentityKeypair::from_bytes(&identity_bytes);
        // The next session number is one past the highest this journal has
        // ever bound, not one past the header: the header is written once
        // at create time, so `header + 1` gave every resume the same
        // number (found by the final pre-publish review). Saturating, per
        // the no-panic contract.
        let highest = replayed_bindings
            .iter()
            .map(|b| b.session_number)
            .fold(header.session_number, u64::max);
        let log = WitnessLog::from_replayed_leaves(
            identity,
            highest.saturating_add(1),
            leaves,
            replayed_bindings,
        )
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;
        Ok((
            log,
            ReplayReport {
                dropped_trailing_lines: dropped_trailing,
                good_byte_length,
            },
        ))
    }
}

/// What `replay` found — surfaced rather than silent, so an embedding
/// application can log or alert on a torn tail write instead of never
/// knowing it happened.
#[derive(Debug, Clone, Copy)]
pub struct ReplayReport {
    pub dropped_trailing_lines: usize,
    /// Byte offset of the end of the last successfully-parsed line
    /// (header or leaf). Pass this to `LeafJournal::open_for_append` to
    /// truncate away a torn trailing write before further appends land.
    pub good_byte_length: u64,
}

/// The batteries-included pairing: an `WitnessLog` whose every append also
/// lands in the journal. Thin by design — it forwards to the inner log
/// and journals the resulting leaf, nothing more.
pub struct JournaledLog {
    log: WitnessLog,
    journal: LeafJournal,
}

impl JournaledLog {
    /// Create a journaled log for an identity you already hold.
    ///
    /// This is the constructor nearly every real agent needs. An agent's
    /// identity is its name: generated once, persisted as a 32-byte
    /// seed, reused for its whole lifetime. The identity goes in here
    /// because a journal without a stable identity produces dossiers
    /// attributed to a key the caller never chose and cannot reproduce.
    ///
    /// This used to be `create_with_identity`, with a bare `create(path)`
    /// that invented an identity internally. That was a silent
    /// correctness trap: nothing failed, the dossier just belonged to
    /// nobody. The 1,000-agent cohort hit it — every crash-restart agent
    /// failed identity binding because the journal's identity differed
    /// from the agent's own. The bare form is now `create_ephemeral`,
    /// named for what it does.
    pub fn create(path: &str, identity: crate::identity::IdentityKeypair) -> std::io::Result<Self> {
        let salts_path = Self::salts_path(path);
        if std::path::Path::new(&salts_path).exists() {
            // A sidecar with no journal is left over from a deleted log.
            // Its salts belong to leaves that no longer exist; attaching
            // them to a new log would make `recompute` answer for the
            // wrong payloads. Refuse, like `create` refuses an existing
            // journal, rather than silently reuse or silently discard.
            return Err(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                format!(
                    "{salts_path} exists but {path} does not: remove the stale salt sidecar \
                     before creating a new journal here"
                ),
            ));
        }
        let mut log = WitnessLog::resume(identity, 0);
        let mut journal = LeafJournal::create(path, &log.identity_bytes(), 0)?;
        let salts = crate::redaction::FileSaltStore::open(&salts_path)?;
        log.set_salt_store(Box::new(salts));
        // Record this session's binding before any leaf it signs. On
        // replay this is what proves the session key that authored the
        // following leaves was authorized by the identity -- without it,
        // a restarted log's earlier leaves verify as Diverged.
        journal.append_binding(log.current_binding())?;
        Ok(Self { log, journal })
    }

    /// Like [`create`](Self::create), but the identity SEED is never
    /// written to disk: the journal header holds only the public key.
    /// Every later start must be [`resume_with_identity`](Self::resume_with_identity)
    /// with the same seed, which is then your KMS's, secrets manager's or
    /// environment's job to keep. Choose this for anything where the
    /// journal file might be readable by more parties than the key should
    /// be; disclose custody accordingly.
    pub fn create_sealed(
        path: &str,
        identity: crate::identity::IdentityKeypair,
    ) -> std::io::Result<Self> {
        let salts_path = Self::salts_path(path);
        if std::path::Path::new(&salts_path).exists() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                format!(
                    "{salts_path} exists but {path} does not: remove the stale salt sidecar \
                     before creating a new journal here"
                ),
            ));
        }
        let mut log = WitnessLog::resume(identity, 0);
        let pubkey_hex = log.identity_pubkey_hex();
        let mut journal = LeafJournal::create_sealed(path, &pubkey_hex, 0)?;
        let salts = crate::redaction::FileSaltStore::open(&salts_path)?;
        log.set_salt_store(Box::new(salts));
        journal.append_binding(log.current_binding())?;
        Ok(Self { log, journal })
    }

    /// Resume a journal created with [`create_sealed`](Self::create_sealed),
    /// supplying the identity seed. Works for unsealed journals too (the
    /// seed must then match the stored one).
    pub fn resume_with_identity(
        path: &str,
        identity_bytes: &[u8; 32],
    ) -> std::io::Result<(Self, ReplayReport)> {
        let (log, report) = LeafJournal::replay_with_identity(path, identity_bytes)?;
        Self::finish_resume(path, log, report)
    }

    /// The salt sidecar that travels with a journal: `<path>.salts`.
    /// Back it up together with the journal; see `FileSaltStore`.
    pub fn salts_path(journal_path: &str) -> String {
        format!("{journal_path}.salts")
    }

    /// Create a journaled log with a NEW, randomly generated identity
    /// that will be discarded when this process ends.
    ///
    /// Named for what it does so it cannot be mistaken for the
    /// constructor a service wants. Use this for tests, demos, and
    /// throwaway work. Use [`create`](Self::create) for anything whose
    /// dossiers need to be attributable to a known party.
    pub fn create_ephemeral(path: &str) -> std::io::Result<Self> {
        Self::create(path, crate::identity::IdentityKeypair::generate())
    }

    /// Kept for one release so existing callers get a clear signal
    /// rather than a mysterious compile error. Delegates to `create`.
    #[deprecated(
        since = "0.3.0",
        note = "renamed to `create`, which now takes the identity"
    )]
    pub fn create_with_identity(
        path: &str,
        identity: crate::identity::IdentityKeypair,
    ) -> std::io::Result<Self> {
        Self::create(path, identity)
    }

    /// Remove a stale lock after a hard crash. See `LeafJournal::force_unlock`.
    pub fn force_unlock(path: &str) -> std::io::Result<()> {
        LeafJournal::force_unlock(path)
    }

    /// Resume from an existing journal and its salt sidecar. Journals
    /// written before the sidecar existed resume normally; their earlier
    /// leaves simply have no salt to forget, exactly as before.
    pub fn resume(path: &str) -> std::io::Result<(Self, ReplayReport)> {
        let (log, report) = LeafJournal::replay(path)?;
        Self::finish_resume(path, log, report)
    }

    fn finish_resume(
        path: &str,
        mut log: WitnessLog,
        report: ReplayReport,
    ) -> std::io::Result<(Self, ReplayReport)> {
        let mut journal = LeafJournal::open_for_append(path, report.good_byte_length)?;
        let mut salts = crate::redaction::FileSaltStore::open(&Self::salts_path(path))?;
        // Salts for leaves that were torn away, or for leaves whose
        // redaction marker is in the journal but whose salt-file rewrite
        // did not complete, are dropped now so the store matches the tree.
        let forgotten: Vec<u64> = log
            .leaves()
            .iter()
            .filter(|l| l.leaf_type == crate::leaf::LeafType::Redaction.tag())
            .filter_map(|l| l.redacted_index)
            .collect();
        salts.reconcile(log.tree_size(), forgotten)?;
        log.set_salt_store(Box::new(salts));
        // Resuming mints a new session key. Record its binding so leaves
        // written after this point are covered too.
        journal.append_binding(log.current_binding())?;
        Ok((Self { log, journal }, report))
    }

    pub fn append_intent(&mut self, payload: &[u8]) -> std::io::Result<u64> {
        let idx = self.log.append_intent(payload);
        self.journal_leaf_at(idx)?;
        Ok(idx)
    }

    pub fn append_result(&mut self, payload: &[u8]) -> std::io::Result<u64> {
        let idx = self.log.append_result(payload);
        self.journal_leaf_at(idx)?;
        Ok(idx)
    }

    pub fn append_memory(&mut self, payload: &[u8]) -> std::io::Result<u64> {
        let idx = self.log.append_memory(payload);
        self.journal_leaf_at(idx)?;
        Ok(idx)
    }

    /// Whether `forget(index)` would erase anything. True for a live,
    /// payload-carrying leaf whose salt is in the sidecar.
    pub fn can_forget(&self, index: u64) -> bool {
        self.log.can_forget(index)
    }

    /// See `WitnessLog::append_handoff_sent`. Previously reachable only
    /// through `log_mut()`, which meant it silently mutated the tree
    /// without touching the journal -- a restart would replay a
    /// different, shorter history with a different root. See the
    /// pre-launch review, finding 08.
    pub fn append_handoff_sent(
        &mut self,
        state_payload: &[u8],
        counterparty_identity_pubkey: &str,
    ) -> std::io::Result<u64> {
        let idx = self
            .log
            .append_handoff_sent(state_payload, counterparty_identity_pubkey);
        self.journal_leaf_at(idx)?;
        Ok(idx)
    }

    /// See `WitnessLog::append_handoff_received`.
    pub fn append_handoff_received(
        &mut self,
        state_payload: &[u8],
        counterparty_identity_pubkey: &str,
    ) -> std::io::Result<u64> {
        let idx = self
            .log
            .append_handoff_received(state_payload, counterparty_identity_pubkey);
        self.journal_leaf_at(idx)?;
        Ok(idx)
    }

    /// See `WitnessLog::append_authorization_event`.
    pub fn append_authorization_event(
        &mut self,
        kind: AuthorizationEventKind,
        scope_description: &[u8],
        counterparty_identity_pubkey: &str,
    ) -> std::io::Result<u64> {
        let idx = self.log.append_authorization_event(
            kind,
            scope_description,
            counterparty_identity_pubkey,
        );
        self.journal_leaf_at(idx)?;
        Ok(idx)
    }

    /// See `WitnessLog::append_external_anchor`.
    pub fn append_external_anchor(
        &mut self,
        anchor_url: &str,
        anchor_proof_json: &str,
    ) -> std::io::Result<u64> {
        // Checked before the leaf enters the tree: a leaf the journal
        // cannot hold must not exist in memory either, or the replayed
        // history would differ from the live one.
        if !LeafJournal::anchor_fits(anchor_url, anchor_proof_json) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "anchor proof too large for one journal line (cap {MAX_JOURNAL_LINE_BYTES} \
                     bytes); store the proof elsewhere and anchor its URL"
                ),
            ));
        }
        let idx = self
            .log
            .append_external_anchor(anchor_url, anchor_proof_json);
        self.journal_leaf_at(idx)?;
        Ok(idx)
    }

    /// See `WitnessLog::forget`. `forget` appends a new Redaction leaf,
    /// same as every other append here — mirroring it is what makes a
    /// GDPR redaction survive a restart instead of the tombstone leaf and
    /// the redaction itself both silently vanishing from the replayed
    /// history while surviving in the live, unpersisted tree.
    ///
    /// The salt is removed from the sidecar file before the tombstone is
    /// journaled. If that rewrite fails, this returns the error and the
    /// tombstone is not written; on the next resume the salt is restored
    /// from the unchanged sidecar and the request can be retried.
    pub fn forget(&mut self, target_index: u64) -> std::io::Result<bool> {
        let size_before = self.log.leaves().len();
        let did_forget = self.log.forget(target_index);
        if let Some(e) = self.log.take_salt_error() {
            return Err(e);
        }
        // `get` rather than indexing: the length comparison makes the
        // index safe today, but a checked lookup keeps the no-panic
        // guarantee structural. If the tombstone leaf somehow isn't
        // there, the redaction still happened in memory -- report that
        // truthfully rather than aborting the caller's process.
        if did_forget {
            if let Some(tombstone) = self.log.leaves().get(size_before) {
                self.journal.append(tombstone)?;
            }
        }
        Ok(did_forget)
    }

    /// Journal the leaf at `idx`, looked up rather than indexed.
    ///
    /// Every append method routes through here so the checked lookup
    /// exists in exactly one place. `idx` always comes from the append
    /// that just happened, so the leaf is present; using `get` anyway is
    /// what keeps `clippy::indexing_slicing` enabled crate-wide and the
    /// no-panic guarantee structural rather than argued.
    ///
    /// Also surfaces a salt-sidecar write failure from the append that
    /// just happened: a leaf whose salt did not reach disk could not be
    /// forgotten after a restart, and the caller must hear about it now.
    fn journal_leaf_at(&mut self, idx: u64) -> std::io::Result<()> {
        if let Some(e) = self.log.take_salt_error() {
            return Err(e);
        }
        let leaf = usize::try_from(idx)
            .ok()
            .and_then(|i| self.log.leaves().get(i))
            .ok_or_else(|| {
                std::io::Error::other("internal: leaf missing immediately after append")
            })?
            .clone();
        self.journal.append(&leaf)
    }

    /// Flush and fsync the journal and the salt sidecar.
    pub fn sync(&mut self) -> std::io::Result<()> {
        self.journal.sync()?;
        self.log.sync_salts()
    }

    pub fn log(&self) -> &WitnessLog {
        &self.log
    }

    // log_mut() has been removed. It was the only way to reach an append
    // method (or `forget`) without it being journaled -- every mutation
    // path that exists on WitnessLog now has a mirrored, journaled
    // equivalent on JournaledLog above. If a future WitnessLog method is
    // added and NOT mirrored here, that's a compile-time-invisible gap
    // again; the fix under consideration is inverting ownership (giving
    // WitnessLog itself an optional sink so `append()` can't be extended
    // without the journal seeing it) — tracked, not yet done. See the
    // pre-launch review, finding 08.
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    fn tmp_path(tag: &str) -> String {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir()
            .join(format!(
                "witness-log-journal-{tag}-{}-{nanos}.jsonl",
                std::process::id()
            ))
            .to_str()
            .unwrap()
            .to_string()
    }

    #[test]
    fn journal_roundtrip_reproduces_exact_root() {
        let path = tmp_path("roundtrip");
        let mut jl = JournaledLog::create_ephemeral(&path).unwrap();
        jl.append_intent(b"intent one").unwrap();
        jl.append_result(b"result one").unwrap();
        jl.append_memory(b"a memory").unwrap();
        jl.sync().unwrap();
        let root_before = jl.log().root_hex();
        let identity_bytes = jl.log().identity_bytes();
        drop(jl);

        let (restored, report) = JournaledLog::resume(&path).unwrap();
        assert_eq!(report.dropped_trailing_lines, 0);
        assert_eq!(restored.log().root_hex(), root_before);
        assert_eq!(restored.log().tree_size(), 3);

        // A checkpoint signed by the SAME identity over the pre-restart
        // state must verify against the replayed log — proof the replay
        // reproduced the exact tree, not merely the same leaf count.
        let key = SigningKey::from_bytes(&identity_bytes);
        let sth = restored.log().checkpoint(&key);
        assert!(restored.log().verify_continuity(&sth).is_ok());
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn torn_tail_is_healed_on_resume_not_just_reported() {
        let path = tmp_path("torn");
        let mut jl = JournaledLog::create_ephemeral(&path).unwrap();
        jl.append_intent(b"complete leaf").unwrap();
        jl.sync().unwrap();
        drop(jl);
        // Simulate crash mid-append: half a JSON line at the tail.
        use std::io::Write as _;
        let mut f = OpenOptions::new().append(true).open(&path).unwrap();
        write!(f, "{{\"index\":1,\"leaf_ty").unwrap();
        drop(f);

        let (restored, report) = JournaledLog::resume(&path).unwrap();
        assert_eq!(
            report.dropped_trailing_lines, 1,
            "torn tail must be reported, not silent"
        );
        assert_eq!(
            restored.log().tree_size(),
            1,
            "only the complete leaf survives"
        );
        drop(restored);

        // The actual regression check for finding 07: resume() must have
        // physically TRUNCATED the torn bytes out of the file, not merely
        // skipped them in memory. Resuming a SECOND time must report zero
        // dropped lines -- if the torn bytes were still on disk, this
        // would report dropped_trailing_lines == 1 again.
        let (mut healed, report2) = JournaledLog::resume(&path).unwrap();
        assert_eq!(
            report2.dropped_trailing_lines, 0,
            "the torn line must be physically gone from the file after one resume, not merely skipped again"
        );

        // And a fresh append after recovery must land cleanly -- not on
        // top of torn bytes (which silently ate the appended leaf in the
        // old behavior) and not misread as a second torn tail.
        healed.append_intent(b"second complete leaf").unwrap();
        healed.sync().unwrap();
        drop(healed);

        let (restored2, report3) = JournaledLog::resume(&path).unwrap();
        assert_eq!(report3.dropped_trailing_lines, 0);
        assert_eq!(
            restored2.log().tree_size(),
            2,
            "the append after recovery must not have been silently eaten"
        );
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn corruption_in_the_middle_of_the_journal_still_fails_loudly() {
        // With the truncate-on-resume fix, a torn tail can no longer
        // evolve into mid-file corruption through a normal resume+append
        // cycle -- resume() now heals a torn tail immediately, before any
        // new append can land on top of it. To exercise the genuine
        // "corruption surrounded by good lines on both sides" path, this
        // constructs that file layout directly instead.
        let path = tmp_path("midcorrupt");
        let mut jl = JournaledLog::create_ephemeral(&path).unwrap();
        jl.append_intent(b"leaf a").unwrap();
        jl.sync().unwrap();
        drop(jl);
        use std::io::Write as _;
        let mut f = OpenOptions::new().append(true).open(&path).unwrap();
        writeln!(f, "not json at all").unwrap();
        writeln!(
            f,
            "{{\"index\":1,\"leaf_type\":1,\"timestamp_ms\":1,\"session_pubkey\":\"{}\",\"payload_hash\":\"{}\",\"redacted_index\":null,\"revoked_identity\":null,\"handoff_direction\":null,\"counterparty_pubkey\":null,\"handoff_state_hash\":null,\"authorization_event_kind\":null,\"authorization_scope_hash\":null,\"anchor_url\":null,\"anchor_proof_json\":null}}",
            "11".repeat(32),
            "22".repeat(32)
        )
        .unwrap();
        drop(f);

        let result = JournaledLog::resume(&path);
        assert!(
            result.is_err(),
            "unparsable line followed by a valid line means real corruption -> must error, never silently skip"
        );
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn create_refuses_to_overwrite_existing_journal() {
        let path = tmp_path("norewrite");
        let _jl = JournaledLog::create_ephemeral(&path).unwrap();
        assert!(
            JournaledLog::create_ephemeral(&path).is_err(),
            "create_new must refuse an existing file"
        );
        std::fs::remove_file(&path).ok();
    }

    #[test]
    #[cfg(unix)]
    fn journal_header_is_not_world_or_group_readable() {
        use std::os::unix::fs::PermissionsExt;
        let path = tmp_path("permcheck");
        let identity = IdentityKeypair::generate();
        let _jl = LeafJournal::create(&path, &identity.to_bytes(), 0).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "journal containing the raw identity seed in its header must be 0600, got {mode:o}"
        );
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn replay_rejects_unrecognized_format_version() {
        let path = tmp_path("badversion");
        let identity = IdentityKeypair::generate();
        let _jl = LeafJournal::create(&path, &identity.to_bytes(), 0).unwrap();
        // Rewrite the header line with an unrecognized format_version,
        // simulating a future format this build predates.
        let content = std::fs::read_to_string(&path).unwrap();
        let mut header: serde_json::Value =
            serde_json::from_str(content.lines().next().unwrap()).unwrap();
        header["format_version"] = serde_json::json!(99);
        let rest: String = content.lines().skip(1).collect::<Vec<_>>().join("\n");
        std::fs::write(&path, format!("{}\n{}", header, rest)).unwrap();

        let result = LeafJournal::replay(&path);
        assert!(
            result.is_err(),
            "an unrecognized format_version must be rejected, not silently misinterpreted"
        );
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn replay_rejects_a_line_exceeding_the_byte_cap_instead_of_growing_unbounded() {
        let path = tmp_path("hugeline");
        let identity = IdentityKeypair::generate();
        let mut jl = LeafJournal::create(&path, &identity.to_bytes(), 0).unwrap();
        // A syntactically-plausible-looking but absurdly long single line
        // with no newline -- what an unbounded read_line would have to
        // buffer in full before any content check could reject it.
        use std::io::Write as _;
        write!(jl.file, "{}", "a".repeat(MAX_JOURNAL_LINE_BYTES + 1024)).unwrap();
        jl.sync().unwrap();
        drop(jl);

        let result = LeafJournal::replay(&path);
        assert!(
            result.is_err(),
            "a line exceeding the byte cap must be rejected, not buffered without bound"
        );
        std::fs::remove_file(&path).ok();
    }
}

#[cfg(test)]
mod salt_persistence_tests {
    use super::*;
    use crate::identity::IdentityKeypair;

    fn tmp(tag: &str) -> String {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir()
            .join(format!(
                "wl-salt-{tag}-{}-{nanos}.jsonl",
                std::process::id()
            ))
            .to_string_lossy()
            .into_owned()
    }

    fn cleanup(p: &str) {
        let _ = std::fs::remove_file(p);
        let _ = std::fs::remove_file(JournaledLog::salts_path(p));
    }

    /// The HIGH finding from the release test: before 0.3.2 `forget` on a
    /// resumed journal returned false for every pre-restart leaf.
    #[test]
    fn forget_works_after_resume_and_the_salt_leaves_the_sidecar() {
        let p = tmp("resume-forget");
        let mut log = JournaledLog::create(&p, IdentityKeypair::generate()).unwrap();
        log.append_intent(b"alice@example.com").unwrap();
        log.append_result(b"ok").unwrap();
        log.sync().unwrap();
        let before = std::fs::read_to_string(JournaledLog::salts_path(&p)).unwrap();
        assert_eq!(
            before.lines().count(),
            2,
            "one salt record per payload leaf"
        );
        drop(log);

        let (mut log, _) = JournaledLog::resume(&p).unwrap();
        assert!(log.can_forget(0));
        assert!(
            log.forget(0).unwrap(),
            "pre-restart leaf must be forgettable"
        );
        assert!(!log.can_forget(0));
        assert!(!log.forget(0).unwrap(), "second forget is a no-op");
        let after = std::fs::read_to_string(JournaledLog::salts_path(&p)).unwrap();
        assert_eq!(
            after.lines().count(),
            1,
            "the forgotten salt is gone from disk"
        );
        assert!(!after.contains("\"i\":0,"));
        assert_eq!(log.log().tree_size(), 3, "tombstone appended");
        drop(log);

        // And it stays forgotten across another restart.
        let (log, _) = JournaledLog::resume(&p).unwrap();
        assert!(!log.can_forget(0));
        assert!(log.can_forget(1));
        cleanup(&p);
    }

    #[test]
    fn empty_payload_leaves_are_salted_and_forgettable() {
        let p = tmp("empty");
        let mut log = JournaledLog::create(&p, IdentityKeypair::generate()).unwrap();
        let i = log.append_result(b"").unwrap();
        assert_ne!(
            log.log().leaves()[0].payload_hash,
            "0".repeat(64),
            "an empty user payload must not commit the marker hash"
        );
        assert!(log.forget(i).unwrap());
        cleanup(&p);
    }

    #[test]
    fn redaction_markers_carry_the_zero_hash_and_no_salt() {
        let p = tmp("marker");
        let mut log = JournaledLog::create(&p, IdentityKeypair::generate()).unwrap();
        log.append_intent(b"x").unwrap();
        assert!(log.forget(0).unwrap());
        let marker = &log.log().leaves()[1];
        assert_eq!(marker.payload_hash, "0".repeat(64));
        assert!(!log.can_forget(1));
        cleanup(&p);
    }

    #[test]
    fn journals_without_a_sidecar_still_resume() {
        let p = tmp("legacy");
        let mut log = JournaledLog::create(&p, IdentityKeypair::generate()).unwrap();
        log.append_intent(b"old").unwrap();
        log.sync().unwrap();
        drop(log);
        std::fs::remove_file(JournaledLog::salts_path(&p)).unwrap();
        let (mut log, _) = JournaledLog::resume(&p).unwrap();
        assert!(!log.can_forget(0), "no salt survived: nothing to forget");
        let i = log.append_intent(b"new").unwrap();
        assert!(log.can_forget(i), "new leaves are persisted again");
        cleanup(&p);
    }

    #[test]
    fn torn_sidecar_tail_is_healed_and_orphan_salts_dropped() {
        let p = tmp("torn-salts");
        let mut log = JournaledLog::create(&p, IdentityKeypair::generate()).unwrap();
        log.append_intent(b"a").unwrap();
        log.sync().unwrap();
        drop(log);
        let sp = JournaledLog::salts_path(&p);
        {
            use std::io::Write as _;
            let mut f = OpenOptions::new().append(true).open(&sp).unwrap();
            // A salt for a leaf whose journal line never landed, then a torn record.
            writeln!(f, "{{\"i\":7,\"s\":\"{}\"}}", "ab".repeat(32)).unwrap();
            write!(f, "{{\"i\":8,\"s\":\"ab").unwrap();
        }
        let (log, _) = JournaledLog::resume(&p).unwrap();
        assert!(log.can_forget(0));
        assert!(!log.can_forget(7));
        let content = std::fs::read_to_string(&sp).unwrap();
        assert_eq!(content.lines().count(), 1);
        cleanup(&p);
    }

    #[test]
    fn create_refuses_a_stale_sidecar() {
        let p = tmp("stale-sidecar");
        std::fs::write(JournaledLog::salts_path(&p), "{\"i\":0,\"s\":\"00\"}\n").unwrap();
        let err = match JournaledLog::create(&p, IdentityKeypair::generate()) {
            Err(e) => e,
            Ok(_) => panic!("create must refuse a stale sidecar"),
        };
        assert_eq!(err.kind(), std::io::ErrorKind::AlreadyExists);
        cleanup(&p);
    }

    #[test]
    fn oversized_anchor_is_refused_before_it_enters_the_tree() {
        let p = tmp("bigshot");
        let mut log = JournaledLog::create(&p, IdentityKeypair::generate()).unwrap();
        let huge = "x".repeat(MAX_JOURNAL_LINE_BYTES);
        let err = log
            .append_external_anchor("https://anchor.example/1", &huge)
            .unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
        assert_eq!(log.log().tree_size(), 0, "nothing was appended in memory");
        drop(log);
        let (log, r) = JournaledLog::resume(&p).unwrap();
        assert_eq!(r.dropped_trailing_lines, 0);
        assert_eq!(log.log().tree_size(), 0);
        cleanup(&p);
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn stale_lock_from_a_dead_pid_is_recovered_automatically() {
        let p = tmp("stale-lock");
        let mut log = JournaledLog::create(&p, IdentityKeypair::generate()).unwrap();
        log.append_intent(b"before crash").unwrap();
        log.sync().unwrap();
        // Simulate SIGKILL: forget the lock without dropping it.
        std::mem::forget(log);
        let lock_path = format!("{p}.lock");
        assert!(std::path::Path::new(&lock_path).exists());
        // Rewrite the lock with a PID that cannot be running.
        std::fs::write(&lock_path, "4194304\n").unwrap();
        let (log, _) = JournaledLog::resume(&p).unwrap();
        assert_eq!(log.log().tree_size(), 1);
        let holder = std::fs::read_to_string(&lock_path).unwrap();
        assert_eq!(holder.trim(), std::process::id().to_string());
        drop(log);
        assert!(!std::path::Path::new(&lock_path).exists());
        cleanup(&p);
    }

    #[test]
    fn live_lock_is_never_stolen() {
        let p = tmp("live-lock");
        let _held = JournaledLog::create(&p, IdentityKeypair::generate()).unwrap();
        let err = match JournaledLog::resume(&p) {
            Err(e) => e,
            Ok(_) => panic!("a live lock must not be stolen"),
        };
        assert_eq!(err.kind(), std::io::ErrorKind::AlreadyExists);
        drop(_held);
        cleanup(&p);
    }
}

#[cfg(test)]
mod session_number_tests {
    use super::*;
    use crate::identity::IdentityKeypair;

    fn tmp(tag: &str) -> String {
        std::env::temp_dir()
            .join(format!("wl-sess-{tag}-{}", std::process::id()))
            .to_string_lossy()
            .into_owned()
    }

    /// Each resume must get a NEW session number, and every binding the
    /// journal ever made must still be present after replay. Before 0.3.1
    /// every resume computed `header + 1`, so the second and later
    /// sessions all shared number 1.
    #[test]
    fn every_resume_advances_the_session_number() {
        let p = tmp("advance");
        let _ = std::fs::remove_file(&p);
        let mut log = JournaledLog::create(&p, IdentityKeypair::generate()).unwrap();
        log.append_intent(b"s0").unwrap();
        drop(log);
        let mut seen = vec![0u64];
        for _ in 0..3 {
            let (mut log, _) = JournaledLog::resume(&p).unwrap();
            let current = log.log().all_bindings().last().unwrap().session_number;
            assert_eq!(
                current,
                seen.len() as u64,
                "session numbers must be 0,1,2,3"
            );
            seen.push(current);
            log.append_intent(b"x").unwrap();
            drop(log);
        }
        let (log, _) = JournaledLog::resume(&p).unwrap();
        let numbers: Vec<u64> = log
            .log()
            .all_bindings()
            .iter()
            .map(|b| b.session_number)
            .collect();
        assert_eq!(numbers, vec![0, 1, 2, 3, 4]);
        let _ = std::fs::remove_file(&p);
    }
}

#[cfg(test)]
mod sealed_identity_tests {
    use super::*;
    use crate::identity::IdentityKeypair;

    fn tmp(tag: &str) -> String {
        let p = std::env::temp_dir().join(format!(
            "wl-sealed-{tag}-{}-{}.jsonl",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        p.to_str().unwrap().to_string()
    }

    #[test]
    fn sealed_journal_never_stores_the_seed_and_resumes_only_with_it() {
        let p = tmp("a");
        let identity = IdentityKeypair::generate();
        let seed = identity.to_bytes();
        let pubkey = {
            let mut j = JournaledLog::create_sealed(&p, identity).unwrap();
            j.append_intent(b"one").unwrap();
            j.sync().unwrap();
            j.log().identity_pubkey_hex()
        };
        let text = std::fs::read_to_string(&p).unwrap();
        assert!(
            !text.contains(&hex::encode(seed)),
            "the seed must not appear anywhere in a sealed journal"
        );
        assert!(text.contains(&pubkey), "the public key pins the identity");

        // Plain resume is refused with a message that names the fix.
        let err = match JournaledLog::resume(&p) {
            Ok(_) => panic!("plain resume of a sealed journal must fail"),
            Err(e) => e,
        };
        assert!(err.to_string().contains("sealed"), "{err}");

        // The wrong seed is refused: a stranger cannot continue this log.
        let wrong = IdentityKeypair::generate().to_bytes();
        assert!(
            JournaledLog::resume_with_identity(&p, &wrong).is_err(),
            "wrong seed accepted"
        );

        // The right seed resumes with the same identity and a new session.
        let (mut j, report) = JournaledLog::resume_with_identity(&p, &seed).unwrap();
        assert_eq!(report.dropped_trailing_lines, 0);
        assert_eq!(j.log().identity_pubkey_hex(), pubkey);
        j.append_result(b"two").unwrap();
        assert_eq!(j.log().tree_size(), 2);
        let _ = std::fs::remove_file(&p);
        let _ = std::fs::remove_file(JournaledLog::salts_path(&p));
    }

    #[test]
    fn unsealed_journal_accepts_a_matching_seed_and_refuses_another() {
        let p = tmp("b");
        let identity = IdentityKeypair::generate();
        let seed = identity.to_bytes();
        let created = JournaledLog::create(&p, identity).unwrap();
        drop(created);
        let (j, _) = JournaledLog::resume_with_identity(&p, &seed).unwrap();
        drop(j);
        let other = IdentityKeypair::generate().to_bytes();
        assert!(
            JournaledLog::resume_with_identity(&p, &other).is_err(),
            "wrong seed accepted"
        );
        let _ = std::fs::remove_file(&p);
        let _ = std::fs::remove_file(JournaledLog::salts_path(&p));
    }
}
