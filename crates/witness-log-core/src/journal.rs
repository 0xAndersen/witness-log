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

/// Read one line (including its trailing `\n` if present) from `reader`,
/// bailing with an error the moment the accumulated length exceeds
/// `max_len` rather than continuing to grow an unbounded buffer. Returns
/// `Ok(None)` on clean EOF with nothing read, `Ok(Some(line))` otherwise
/// (mirroring `BufRead::read_line`'s contract, but bounded and returning
/// the line rather than a byte count).
fn read_bounded_line<R: BufRead>(
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
    identity_bytes_hex: String,
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
}

impl JournalLock {
    fn acquire(journal_path: &str) -> std::io::Result<Self> {
        let path = std::path::PathBuf::from(format!("{journal_path}.lock"));
        match OpenOptions::new().write(true).create_new(true).open(&path) {
            Ok(mut f) => {
                // Record who holds it, for diagnostics after a crash.
                let _ = writeln!(f, "{}", std::process::id());
                Ok(Self { path })
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Err(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                format!(
                    "journal is already open: lock file {} exists. If the previous process \
                     crashed, call JournaledLog::force_unlock first.",
                    path.display()
                ),
            )),
            Err(e) => Err(e),
        }
    }
}

impl Drop for JournalLock {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
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
            identity_bytes_hex: hex::encode(identity_bytes),
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
    pub fn append(&mut self, leaf: &Leaf) -> std::io::Result<()> {
        let line = serde_json::to_string(leaf).map_err(std::io::Error::other)?;
        writeln!(self.file, "{line}")?;
        Ok(())
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

    /// Replay a journal into a fresh `WitnessLog`, advancing the session
    /// number — the journal equivalent of `load_snapshot`. A truncated
    /// final line (crash mid-append) is tolerated and dropped with its
    /// count reported, because an append-only journal's last line is the
    /// only line a crash can ever damage; every earlier line was complete
    /// when written.
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
        let identity_bytes: [u8; 32] = hex::decode(&header.identity_bytes_hex)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?
            .try_into()
            .map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "identity key must be 32 bytes",
                )
            })?;

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
        let log = WitnessLog::resume(identity, 0);
        let mut journal = LeafJournal::create(path, &log.identity_bytes(), 0)?;
        // Record this session's binding before any leaf it signs. On
        // replay this is what proves the session key that authored the
        // following leaves was authorized by the identity -- without it,
        // a restarted log's earlier leaves verify as Diverged.
        journal.append_binding(log.current_binding())?;
        Ok(Self { log, journal })
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

    pub fn resume(path: &str) -> std::io::Result<(Self, ReplayReport)> {
        let (log, report) = LeafJournal::replay(path)?;
        let mut journal = LeafJournal::open_for_append(path, report.good_byte_length)?;
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
    pub fn forget(&mut self, target_index: u64) -> std::io::Result<bool> {
        let size_before = self.log.leaves().len();
        let did_forget = self.log.forget(target_index);
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
    fn journal_leaf_at(&mut self, idx: u64) -> std::io::Result<()> {
        let leaf = usize::try_from(idx)
            .ok()
            .and_then(|i| self.log.leaves().get(i))
            .ok_or_else(|| {
                std::io::Error::other("internal: leaf missing immediately after append")
            })?
            .clone();
        self.journal.append(&leaf)
    }

    pub fn sync(&mut self) -> std::io::Result<()> {
        self.journal.sync()
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
