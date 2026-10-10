//! Python bindings. Deliberately thin: this module's only job is to expose
//! `witness_log_core::log::WitnessLog` with a Pythonic surface and JSON in/out at
//! the boundary, so serialization stays governed by `witness-log-core`'s own
//! `serde` derives (and therefore SPEC.md) rather than being reimplemented
//! here.
//!
//! Exceptions are a small hierarchy, not one generic ValueError, so callers
//! can catch what they actually care about: `SignatureError` (a signature
//! didn't check out — usually means "someone tampered with this"),
//! `ContinuityError` (the signature is fine but doesn't match this log's
//! state — usually means "this checkpoint isn't for the log you think it
//! is"), and `MalformedError` (input wasn't even shaped right). All three
//! inherit from `WitnessLogError`, so `except witness_log.WitnessLogError` catches
//! anything from this module.

use pyo3::exceptions::{PyException, PyIOError};
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use std::sync::{Mutex, MutexGuard};
use witness_log_core::identity::IdentityKeypair;
use witness_log_core::log::{VerifyError, WitnessLog as CoreLog};
use witness_log_core::sth::SignedTreeHead;

/// Lock a binding's inner state. A poisoned mutex only means an earlier
/// call panicked mid-borrow; the core has a no-panic contract, so recover
/// the guard rather than turning every later call into an error.
fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

pyo3::create_exception!(
    witness_log,
    WitnessLogError,
    PyException,
    "Base class for all WitnessLog-specific errors."
);
pyo3::create_exception!(
    witness_log,
    SignatureError,
    WitnessLogError,
    "A cryptographic signature failed to verify."
);
pyo3::create_exception!(
    witness_log,
    ContinuityError,
    WitnessLogError,
    "A checkpoint's signature is valid but doesn't match this log's actual state."
);
pyo3::create_exception!(
    witness_log,
    MalformedError,
    WitnessLogError,
    "Input was malformed (wrong size, bad hex, unparsable)."
);

#[pyclass(name = "WitnessLog")]
struct PyWitnessLog {
    inner: Mutex<CoreLog>,
}

#[pymethods]
impl PyWitnessLog {
    /// Start a brand-new log under a freshly generated identity.
    /// `agent.identity_bytes()` must be persisted by the caller if the
    /// identity should survive a process restart — see `resume`, or use
    /// `save_snapshot`/`load_snapshot` to handle that automatically.
    #[staticmethod]
    fn generate() -> Self {
        Self {
            inner: Mutex::new(CoreLog::new()),
        }
    }

    /// Resume logging under a previously-generated identity.
    /// `identity_seed` is the 32 raw bytes from a prior `identity_bytes()`
    /// call. `session_number` should be incremented by the caller each
    /// time a process restarts under the same identity.
    #[staticmethod]
    fn resume(identity_seed: &[u8], session_number: u64) -> PyResult<Self> {
        let identity = parse_identity_seed(identity_seed)?;
        Ok(Self {
            inner: Mutex::new(CoreLog::resume(identity, session_number)),
        })
    }

    /// Like `resume`, but the session binding expires `ttl_ms`
    /// milliseconds from now. A verifier calling `current_binding` (not
    /// yet exposed here — see `witness-log-core::identity::KeyBindingStatement`)
    /// can then tell a stale, abandoned session apart from a live one
    /// without you needing to issue an explicit revocation.
    #[staticmethod]
    fn resume_with_ttl(identity_seed: &[u8], session_number: u64, ttl_ms: u64) -> PyResult<Self> {
        let identity = parse_identity_seed(identity_seed)?;
        Ok(Self {
            inner: Mutex::new(CoreLog::resume_with_ttl(identity, session_number, ttl_ms)),
        })
    }

    /// Raw identity key bytes (32 bytes). Persist this somewhere safe if
    /// you want the same identity across process restarts.
    fn identity_bytes<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &lock(&self.inner).identity_bytes())
    }

    fn identity_pubkey_hex(&self) -> String {
        lock(&self.inner).identity_pubkey_hex()
    }

    fn append_intent(&self, payload: &[u8]) -> u64 {
        lock(&self.inner).append_intent(payload)
    }

    fn append_result(&self, payload: &[u8]) -> u64 {
        lock(&self.inner).append_result(payload)
    }

    fn append_memory(&self, payload: &[u8]) -> u64 {
        lock(&self.inner).append_memory(payload)
    }

    /// Right-to-be-forgotten for `leaf_index`. Returns False if that index
    /// has no live salt (already forgotten, or never had a payload).
    fn forget(&self, leaf_index: u64) -> bool {
        lock(&self.inner).forget(leaf_index)
    }

    fn tree_size(&self) -> u64 {
        lock(&self.inner).tree_size()
    }

    fn root_hex(&self) -> String {
        lock(&self.inner).root_hex()
    }

    /// JSON array of every leaf currently in the log, in `witness-log-core`
    /// canonical serde form — matches the `leaves` field of a dossier
    /// (SPEC.md §9).
    fn leaves_json(&self) -> PyResult<String> {
        serde_json::to_string(lock(&self.inner).leaves()).map_err(malformed_err)
    }

    /// Produce a checkpoint (Signed Tree Head), signed by this log's own
    /// identity key, as a JSON string matching SPEC.md §6.
    fn checkpoint(&self) -> PyResult<String> {
        let sth = lock(&self.inner).checkpoint_self();
        serde_json::to_string(&sth).map_err(malformed_err)
    }

    /// Verify that a checkpoint (as produced by `checkpoint()`) matches
    /// this log's current state exactly — signature valid, tree size
    /// matches, root matches. Raises `SignatureError` if the signature
    /// itself is bad, `ContinuityError` if it's validly signed but doesn't
    /// match this log's state — see this module's docstring.
    fn verify_continuity(&self, checkpoint_json: &str) -> PyResult<()> {
        let sth: SignedTreeHead = serde_json::from_str(checkpoint_json).map_err(malformed_err)?;
        lock(&self.inner)
            .verify_continuity(&sth)
            .map_err(verify_error_to_py)
    }

    /// This log's head as a C2SP checkpoint body (the text a third-party
    /// witness cosigns), as a string. Sign it with `sign_c2sp_checkpoint`.
    fn c2sp_checkpoint_text(&self, origin: &str) -> PyResult<String> {
        lock(&self.inner)
            .c2sp_checkpoint(origin)
            .note_text()
            .map_err(|e| MalformedError::new_err(e.to_string()))
    }

    /// Sign this log's current head as a C2SP signed note, ready to POST
    /// to a `tlog-witness` endpoint. Returns the note as a string.
    fn sign_c2sp_checkpoint(&self, origin: &str) -> PyResult<String> {
        let key = ed25519_dalek::SigningKey::from_bytes(&lock(&self.inner).identity_bytes());
        lock(&self.inner)
            .c2sp_checkpoint(origin)
            .sign(&key)
            .and_then(|n| n.encode())
            .map_err(|e| MalformedError::new_err(e.to_string()))
    }

    /// The verifier key (vkey) a witness needs to check this log's C2SP
    /// checkpoints. Publish it alongside the origin.
    fn c2sp_vkey(&self, origin: &str) -> String {
        let key = ed25519_dalek::SigningKey::from_bytes(&lock(&self.inner).identity_bytes());
        witness_log_core::c2sp::bridge::log_vkey(origin, &key.verifying_key()).encode()
    }

    /// Every key binding this log knows about, as JSON. Use this -- not
    /// just the current binding -- when building a dossier, or a log that
    /// has restarted will verify as Diverged.
    fn all_bindings_json(&self) -> PyResult<String> {
        serde_json::to_string(&lock(&self.inner).all_bindings()).map_err(malformed_err)
    }

    /// This log's canonical C2SP origin, `witness-log/<identity key hex>`.
    /// Witnesses with open enrollment accept it with no key exchange, and
    /// only cosignatures under it count toward a verdict.
    fn canonical_origin(&self) -> String {
        let key = ed25519_dalek::SigningKey::from_bytes(&lock(&self.inner).identity_bytes());
        witness_log_core::c2sp::canonical_origin(&key.verifying_key())
    }

    /// POST body for `<witness>/add-checkpoint`. `old_size` is the size
    /// the witness last cosigned for this log (0 the first time; a 409
    /// reply's body tells you the right value).
    #[pyo3(signature = (old_size=0))]
    fn add_checkpoint_body(&self, old_size: u64) -> PyResult<String> {
        add_checkpoint_body(&lock(&self.inner), old_size)
    }

    /// Dossier JSON for the current head from witness 200 responses:
    /// a list of `(witness_pubkey_hex, response_body)`. Returns
    /// `(dossier_json, receipts_accepted)`; forged or mismatched
    /// cosignatures are dropped, never counted.
    fn dossier_from_responses(
        &self,
        responses: Vec<(String, String)>,
    ) -> PyResult<(String, usize)> {
        dossier_from_responses(&lock(&self.inner), responses)
    }

    /// Assemble a full dossier (leaves + checkpoint) as a JSON string,
    /// matching SPEC.md §9 minus witness fields — attach those separately
    /// if/when this log has been witnessed.
    fn to_dossier_json(&self) -> PyResult<String> {
        // One shared constructor (Dossier::from_log) rather than a
        // hand-built struct, so bindings, CLI and examples cannot drift --
        // finding 18 of the pre-launch review. It carries every key
        // binding, so restarted logs verify cleanly.
        let inner = lock(&self.inner);
        let dossier = witness_log_network::Dossier::from_log(&inner, inner.checkpoint_self());
        serde_json::to_string_pretty(&dossier).map_err(malformed_err)
    }

    /// Write identity key material + leaves to `path` as JSON so a process
    /// restart can pick up where this log left off via `load_snapshot`.
    ///
    /// SECURITY: this file contains the raw identity private key in plain
    /// hex. Treat it like any other private key file — this method does
    /// not encrypt it for you. Salts are NOT included; leaves committed
    /// before a save/load cycle can no longer be redacted afterward. See
    /// `witness_log_core::log::WitnessLog::save_snapshot`'s doc comment for why.
    fn save_snapshot(&self, path: &str) -> PyResult<()> {
        lock(&self.inner)
            .save_snapshot(path)
            .map_err(|e| PyIOError::new_err(e.to_string()))
    }

    /// Restore from a snapshot written by `save_snapshot`. Advances the
    /// session number and issues a fresh session key, exactly like a real
    /// process restart should.
    #[staticmethod]
    fn load_snapshot(path: &str) -> PyResult<Self> {
        CoreLog::load_snapshot(path)
            .map(|inner| Self {
                inner: Mutex::new(inner),
            })
            .map_err(|e| PyIOError::new_err(e.to_string()))
    }
}

fn parse_identity_seed(identity_seed: &[u8]) -> PyResult<IdentityKeypair> {
    let seed: [u8; 32] = identity_seed
        .try_into()
        .map_err(|_| MalformedError::new_err("identity_seed must be exactly 32 bytes"))?;
    Ok(IdentityKeypair::from_bytes(&seed))
}

fn malformed_err<E: std::fmt::Display>(e: E) -> PyErr {
    MalformedError::new_err(e.to_string())
}

/// Verify a full dossier (SPEC.md SS9) offline: checkpoint signature,
/// identity binding, leaf structural validity, key-binding/revocation
/// validity, Merkle continuity rebuilt from the leaves, and — when a
/// trusted directory is supplied — quorum and both diversity axes against
/// `threshold`. Returns the structured report as a JSON string (same
/// shape as `witness-log verify --json`'s `report` field). This is THE
/// product: the same single verification implementation the CLI uses,
/// reachable from Python. Raises MalformedError if the dossier or
/// trusted-directory JSON doesn't parse.
///
/// `expected_identity_pubkey` and `trusted_directory_json` are the
/// out-of-band anchors — see `VerifyContext` in witness-log-network.
/// Omitting both is legal (the run checks only self-consistency) but
/// caps the reachable verdict at "unanchored". `trusted_directory_json`
/// must be a JSON `WitnessDirectory` object, never the dossier's own
/// embedded directory.
#[pyfunction]
#[pyo3(signature = (dossier_json, threshold, expected_identity_pubkey=None, trusted_directory_json=None))]
fn verify_dossier_json(
    dossier_json: &str,
    threshold: f64,
    expected_identity_pubkey: Option<String>,
    trusted_directory_json: Option<String>,
) -> PyResult<String> {
    let dossier: witness_log_network::Dossier =
        serde_json::from_str(dossier_json).map_err(malformed_err)?;
    let trusted_directory: Option<witness_log_network::WitnessDirectory> =
        match &trusted_directory_json {
            Some(s) => Some(serde_json::from_str(s).map_err(malformed_err)?),
            None => None,
        };
    let ctx = witness_log_network::VerifyContext {
        expected_identity_pubkey: expected_identity_pubkey.as_deref(),
        trusted_directory: trusted_directory.as_ref(),
    };
    let report = dossier.verify(threshold, &ctx);
    serde_json::to_string_pretty(&report).map_err(malformed_err)
}

/// The add-checkpoint request body for this log's current head, signed
/// under its canonical origin, with a consistency proof from `old_size`.
fn add_checkpoint_body(log: &CoreLog, old_size: u64) -> PyResult<String> {
    let key = ed25519_dalek::SigningKey::from_bytes(&log.identity_bytes());
    let origin = witness_log_core::c2sp::canonical_origin(&key.verifying_key());
    let size = log.tree_size();
    if old_size > size {
        return Err(MalformedError::new_err(format!(
            "old_size {old_size} exceeds this log's size {size}"
        )));
    }
    let proof = if old_size == 0 || old_size == size {
        vec![]
    } else {
        log.consistency_proof(old_size)
            .ok_or_else(|| MalformedError::new_err("no consistency proof for that size"))?
    };
    let note = log
        .c2sp_checkpoint(&origin)
        .sign(&key)
        .map_err(|e| MalformedError::new_err(e.to_string()))?;
    witness_log_network::tlog_witness::AddCheckpointRequest {
        old_size,
        consistency_proof: proof,
        checkpoint_note: note,
    }
    .to_http_body()
    .map_err(malformed_err)
}

/// Build a dossier for this log's current head from witness responses.
/// `responses` is a list of `(witness_pubkey_hex, response_body)` from
/// HTTP 200 replies. Only cosignatures that verify under that key over
/// this exact head become receipts; everything else is ignored.
/// Returns `(dossier_json, receipts_accepted)`.
fn dossier_from_responses(
    log: &CoreLog,
    responses: Vec<(String, String)>,
) -> PyResult<(String, usize)> {
    use witness_log_core::c2sp::{Cosignature, NoteSignature, VerifierKey};
    let key = ed25519_dalek::SigningKey::from_bytes(&log.identity_bytes());
    let origin = witness_log_core::c2sp::canonical_origin(&key.verifying_key());
    let cp = log.c2sp_checkpoint(&origin);
    let native = log.checkpoint(&key);
    let mut receipts = Vec::new();
    for (pk_hex, body) in responses {
        let Some(wvk) = hex::decode(pk_hex.trim())
            .ok()
            .and_then(|b| <[u8; 32]>::try_from(b).ok())
            .and_then(|b| ed25519_dalek::VerifyingKey::from_bytes(&b).ok())
        else {
            continue;
        };
        for line in body.lines().filter(|l| !l.is_empty()) {
            let Ok(sig) = NoteSignature::parse(line) else {
                continue;
            };
            let Ok(cos) = Cosignature::from_note_signature(&sig) else {
                continue;
            };
            let vkey = VerifierKey::for_cosignature(&sig.key_name, &wvk);
            if let Some(c) =
                witness_log_network::tlog_witness::cosignature_to_receipt(&cos, &vkey, &cp, &native)
            {
                receipts.push(c.receipt);
                break;
            }
        }
    }
    let n = receipts.len();
    let dossier = witness_log_network::Dossier::from_log(log, native).with_receipts(receipts);
    Ok((
        serde_json::to_string_pretty(&dossier).map_err(malformed_err)?,
        n,
    ))
}

fn verify_error_to_py(e: VerifyError) -> PyErr {
    match e {
        VerifyError::BadSignature(_) => SignatureError::new_err(e.to_string()),
        VerifyError::SizeMismatch { .. } | VerifyError::RootMismatch => {
            ContinuityError::new_err(e.to_string())
        }
    }
}

/// A `WitnessLog` whose every append also lands in an append-only
/// on-disk journal. Use this for anything long-lived: a crash loses at
/// most the last unsynced write, and `resume` recovers from a torn tail
/// automatically.
#[pyclass(name = "JournaledLog")]
struct PyJournaledLog {
    inner: Mutex<witness_log_core::journal::JournaledLog>,
}

#[pymethods]
impl PyJournaledLog {
    /// Create a journaled log for an identity you already hold.
    /// `identity_seed` is the 32 raw bytes from `WitnessLog.identity_bytes()`.
    #[staticmethod]
    fn create(path: &str, identity_seed: &[u8]) -> PyResult<Self> {
        let identity = parse_identity_seed(identity_seed)?;
        witness_log_core::journal::JournaledLog::create(path, identity)
            .map(|inner| Self {
                inner: Mutex::new(inner),
            })
            .map_err(|e| PyIOError::new_err(e.to_string()))
    }

    /// Create a journaled log with a throwaway identity. For tests and
    /// demos. Dossiers from this log belong to a key you cannot reproduce.
    #[staticmethod]
    fn create_ephemeral(path: &str) -> PyResult<Self> {
        witness_log_core::journal::JournaledLog::create_ephemeral(path)
            .map(|inner| Self {
                inner: Mutex::new(inner),
            })
            .map_err(|e| PyIOError::new_err(e.to_string()))
    }

    /// Resume from an existing journal. Returns `(log, dropped_trailing_lines)`;
    /// a nonzero count means the previous process died mid-write and the
    /// torn line was discarded and physically truncated.
    #[staticmethod]
    fn resume(path: &str) -> PyResult<(Self, usize)> {
        witness_log_core::journal::JournaledLog::resume(path)
            .map(|(inner, report)| {
                (
                    Self {
                        inner: Mutex::new(inner),
                    },
                    report.dropped_trailing_lines,
                )
            })
            .map_err(|e| PyIOError::new_err(e.to_string()))
    }

    fn append_intent(&self, payload: &[u8]) -> PyResult<u64> {
        lock(&self.inner)
            .append_intent(payload)
            .map_err(|e| PyIOError::new_err(e.to_string()))
    }
    fn append_result(&self, payload: &[u8]) -> PyResult<u64> {
        lock(&self.inner)
            .append_result(payload)
            .map_err(|e| PyIOError::new_err(e.to_string()))
    }
    fn append_memory(&self, payload: &[u8]) -> PyResult<u64> {
        lock(&self.inner)
            .append_memory(payload)
            .map_err(|e| PyIOError::new_err(e.to_string()))
    }
    fn append_handoff_sent(&self, state: &[u8], counterparty_pubkey_hex: &str) -> PyResult<u64> {
        lock(&self.inner)
            .append_handoff_sent(state, counterparty_pubkey_hex)
            .map_err(|e| PyIOError::new_err(e.to_string()))
    }
    fn append_handoff_received(
        &self,
        state: &[u8],
        counterparty_pubkey_hex: &str,
    ) -> PyResult<u64> {
        lock(&self.inner)
            .append_handoff_received(state, counterparty_pubkey_hex)
            .map_err(|e| PyIOError::new_err(e.to_string()))
    }

    /// Right-to-be-forgotten. Returns True if a leaf was actually erased.
    /// Raises on I/O failure, so a journaling failure during a legally
    /// consequential operation cannot go unnoticed.
    fn forget(&self, index: u64) -> PyResult<bool> {
        lock(&self.inner)
            .forget(index)
            .map_err(|e| PyIOError::new_err(e.to_string()))
    }

    /// fsync. Blocks; call from a thread if you are async.
    fn sync(&self) -> PyResult<()> {
        lock(&self.inner)
            .sync()
            .map_err(|e| PyIOError::new_err(e.to_string()))
    }

    fn tree_size(&self) -> u64 {
        lock(&self.inner).log().tree_size()
    }
    fn root_hex(&self) -> String {
        lock(&self.inner).log().root_hex()
    }
    fn identity_pubkey_hex(&self) -> String {
        lock(&self.inner).log().identity_pubkey_hex()
    }
    fn identity_bytes<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &lock(&self.inner).log().identity_bytes())
    }

    /// Sign a checkpoint over the current head. Returns JSON.
    fn checkpoint(&self) -> PyResult<String> {
        serde_json::to_string(&lock(&self.inner).log().checkpoint_self()).map_err(malformed_err)
    }

    /// Export a dossier of this log's own history, with key bindings
    /// populated correctly across restarts. Returns JSON.
    fn to_dossier_json(&self) -> PyResult<String> {
        let sth = lock(&self.inner).log().checkpoint_self();
        let dossier = witness_log_network::Dossier::from_log(lock(&self.inner).log(), sth);
        serde_json::to_string_pretty(&dossier).map_err(malformed_err)
    }

    /// This log's canonical C2SP origin, `witness-log/<identity key hex>`.
    /// Witnesses with open enrollment accept it with no key exchange, and
    /// only cosignatures under it count toward a verdict.
    fn canonical_origin(&self) -> String {
        let key = ed25519_dalek::SigningKey::from_bytes(&lock(&self.inner).log().identity_bytes());
        witness_log_core::c2sp::canonical_origin(&key.verifying_key())
    }

    /// POST body for `<witness>/add-checkpoint`. `old_size` is the size
    /// the witness last cosigned for this log (0 the first time; a 409
    /// reply's body tells you the right value).
    #[pyo3(signature = (old_size=0))]
    fn add_checkpoint_body(&self, old_size: u64) -> PyResult<String> {
        add_checkpoint_body(&lock(&self.inner).log(), old_size)
    }

    /// Dossier JSON for the current head from witness 200 responses:
    /// a list of `(witness_pubkey_hex, response_body)`. Returns
    /// `(dossier_json, receipts_accepted)`; forged or mismatched
    /// cosignatures are dropped, never counted.
    fn dossier_from_responses(
        &self,
        responses: Vec<(String, String)>,
    ) -> PyResult<(String, usize)> {
        dossier_from_responses(&lock(&self.inner).log(), responses)
    }

    fn c2sp_checkpoint_text(&self, origin: &str) -> PyResult<String> {
        lock(&self.inner)
            .log()
            .c2sp_checkpoint(origin)
            .note_text()
            .map_err(|e| MalformedError::new_err(e.to_string()))
    }

    fn sign_c2sp_checkpoint(&self, origin: &str) -> PyResult<String> {
        let key = ed25519_dalek::SigningKey::from_bytes(&lock(&self.inner).log().identity_bytes());
        lock(&self.inner)
            .log()
            .c2sp_checkpoint(origin)
            .sign(&key)
            .and_then(|n| n.encode())
            .map_err(|e| MalformedError::new_err(e.to_string()))
    }

    fn c2sp_vkey(&self, origin: &str) -> String {
        let key = ed25519_dalek::SigningKey::from_bytes(&lock(&self.inner).log().identity_bytes());
        witness_log_core::c2sp::bridge::log_vkey(origin, &key.verifying_key()).encode()
    }
}

/// A `tlog-witness` witness. Holds one record per log it witnesses and
/// cosigns only verified, consistent advances. Wire
/// `handle_add_checkpoint_http` into any HTTP server: it takes the POST
/// body and returns `(status, content_type, body)` exactly as
/// c2sp.org/tlog-witness requires.
///
/// Pass `state_path` for anything real. Then every cosigned head is
/// written durably (temp file, fsync, rename) BEFORE the cosignature is
/// returned, and if that write fails no cosignature is returned at all.
/// Without `state_path` the witness forgets everything on restart and
/// can be walked onto a fork -- fine for tests, wrong for production.
#[pyclass(name = "WitnessService")]
struct PyWitnessService {
    inner: Mutex<witness_log_network::tlog_witness::WitnessService>,
    key_name: String,
    signing_key: ed25519_dalek::SigningKey,
    state_path: Option<String>,
    open_enrollment: bool,
    max_logs: usize,
    /// Held while this object lives when `state_path` is set: one writer
    /// per state file, or two processes (e.g. gunicorn workers) could each
    /// cosign a different fork from their own in-memory view.
    lock: Option<StateLock>,
    evidence_recorded: Mutex<std::collections::HashSet<String>>,
}

struct StateLock(std::path::PathBuf);
impl StateLock {
    fn acquire(state_path: &str) -> std::io::Result<Self> {
        use std::io::Write;
        let p = std::path::PathBuf::from(format!("{state_path}.lock"));
        for _ in 0..2 {
            match std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&p)
            {
                Ok(mut f) => {
                    writeln!(f, "{}", std::process::id())?;
                    f.sync_all()?;
                    let lock = Self(p);
                    // Settle, then confirm we still hold it (two processes
                    // racing over one stale lock).
                    std::thread::sleep(std::time::Duration::from_millis(250));
                    if !lock.still_ours() {
                        std::mem::forget(lock);
                        return Err(std::io::Error::other("lost a race for the state lock"));
                    }
                    return Ok(lock);
                }
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                    let pid = std::fs::read_to_string(&p).unwrap_or_default();
                    let pid = pid.trim().to_string();
                    #[cfg(target_os = "linux")]
                    {
                        if !pid.is_empty()
                            && pid.bytes().all(|b| b.is_ascii_digit())
                            && !std::path::Path::new(&format!("/proc/{pid}")).exists()
                            && std::fs::read_to_string(&p).unwrap_or_default().trim() == pid
                        {
                            let _ = std::fs::remove_file(&p);
                            continue;
                        }
                    }
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::AlreadyExists,
                        format!(
                            "{} is held by pid {pid}: another witness process is using this \
                             state. Run ONE witness process per state file (two could cosign \
                             two forks). If that process is gone, delete the lock file.",
                            p.display()
                        ),
                    ));
                }
                Err(e) => return Err(e),
            }
        }
        Err(std::io::Error::other("could not acquire state lock"))
    }
    fn still_ours(&self) -> bool {
        std::fs::read_to_string(&self.0)
            .map(|s| s.trim() == std::process::id().to_string())
            .unwrap_or(false)
    }
}
impl Drop for StateLock {
    fn drop(&mut self) {
        if self.still_ours() {
            let _ = std::fs::remove_file(&self.0);
        }
    }
}

fn valid_key_name(n: &str) -> bool {
    !n.is_empty()
        && n.len() <= 128
        && n.chars()
            .all(|c| !c.is_whitespace() && !c.is_control() && c != '+')
}

fn persist_witness_state(
    path: &str,
    svc: &witness_log_network::tlog_witness::WitnessService,
) -> std::io::Result<()> {
    use std::io::Write;
    let json = serde_json::to_vec_pretty(&svc.export_state())
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
    let p = std::path::Path::new(path);
    let dir = p
        .parent()
        .filter(|d| !d.as_os_str().is_empty())
        .unwrap_or(std::path::Path::new("."));
    let tmp = dir.join(format!(".witness-state.tmp-{}", std::process::id()));
    {
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts.open(&tmp)?;
        f.write_all(&json)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, p)?;
    #[cfg(unix)]
    std::fs::File::open(dir)?.sync_all()?;
    Ok(())
}

/// Append a proven equivocation to `<state_path>.evidence.jsonl` (capped
/// at 64 MiB). Best effort: failing to record never changes the refusal.
fn record_equivocation(
    path: &str,
    proof: &witness_log_network::tlog_witness::EquivocationProof,
    now: u64,
) {
    use std::io::Write;
    if std::fs::metadata(path).is_ok_and(|m| m.len() > 64 * 1024 * 1024) {
        return;
    }
    let line = serde_json::json!({ "observed_unix": now, "kind": "equivocation", "proof": proof });
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
    {
        let _ = writeln!(f, "{line}");
        let _ = f.sync_all();
    }
}

impl PyWitnessService {
    fn handle(&self, body: &str, now: u64) -> (u16, &'static str, String) {
        use witness_log_network::tlog_witness::{AddCheckpointOutcome, AddCheckpointRequest};
        let req = match AddCheckpointRequest::parse(body) {
            Ok(r) => r,
            Err(e) => return (400, "text/plain; charset=utf-8", format!("{e}\n")),
        };
        let mut svc = lock(&self.inner);
        if let Some(l) = &self.lock {
            if !l.still_ours() {
                return (
                    503,
                    "text/plain; charset=utf-8",
                    "state lock lost to another process; not cosigning\n".into(),
                );
            }
        }
        let origin = witness_log_core::c2sp::Checkpoint::from_note(&req.checkpoint_note)
            .map(|c| c.origin)
            .unwrap_or_default();
        let unknown = svc.known_log(&origin).is_none();
        if self.open_enrollment && unknown && svc.log_count() >= self.max_logs {
            return (
                503,
                "text/plain; charset=utf-8",
                "witness is at its log capacity\n".into(),
            );
        }
        let enrolled = self.open_enrollment && svc.enroll_canonical(&req);
        if self.open_enrollment
            && unknown
            && !enrolled
            && witness_log_core::c2sp::identity_from_canonical_origin(&origin).is_some()
        {
            // The origin names its key: a failure is a bad signature, not
            // an unknown log.
            return (
                403,
                "text/plain; charset=utf-8",
                "checkpoint signature not verified\n".into(),
            );
        }
        let previous = svc.known_log(&origin).cloned();
        let out = svc.handle_add_checkpoint(&req, &self.key_name, &self.signing_key, now);
        let cosigned = matches!(out, AddCheckpointOutcome::Cosigned { .. });
        if cosigned {
            if let Some(path) = &self.state_path {
                if persist_witness_state(path, &svc).is_err() {
                    match previous {
                        Some(p) if !enrolled => svc.set_known_log(p),
                        _ => {
                            svc.remove_log(&origin);
                        }
                    }
                    return (
                        500,
                        "text/plain; charset=utf-8",
                        "could not persist state; not cosigning\n".into(),
                    );
                }
            }
        } else if enrolled {
            svc.remove_log(&origin);
        }
        if let AddCheckpointOutcome::ConsistencyFailed {
            equivocation: Some(proof),
            ..
        } = &out
        {
            if let Some(path) = &self.state_path {
                if lock(&self.evidence_recorded).insert(origin.clone()) {
                    record_equivocation(&format!("{path}.evidence.jsonl"), proof, now);
                }
            }
        }
        let (text, ctype) = out.http_body();
        (out.http_status(), ctype, text)
    }
}

fn now_unix_s() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[pymethods]
impl PyWitnessService {
    /// `key_name` is this witness's C2SP key name (e.g. "witness.example/w1").
    /// `signing_seed` is 32 bytes; generate once and persist.
    /// `state_path`: JSON file holding what this witness has cosigned;
    /// loaded if it exists. `open_enrollment`: accept any agent whose
    /// origin is `witness-log/<its identity key>` without `add_log`.
    #[staticmethod]
    /// `max_logs` caps how many logs open enrollment will accept.
    #[pyo3(signature = (key_name, signing_seed, state_path=None, open_enrollment=false, max_logs=100_000))]
    fn new(
        key_name: &str,
        signing_seed: &[u8],
        state_path: Option<String>,
        open_enrollment: bool,
        max_logs: usize,
    ) -> PyResult<Self> {
        let seed: [u8; 32] = signing_seed
            .try_into()
            .map_err(|_| MalformedError::new_err("signing seed must be exactly 32 bytes"))?;
        if !valid_key_name(key_name) {
            return Err(MalformedError::new_err(
                "key_name must be non-empty, at most 128 chars, without whitespace or '+'",
            ));
        }
        if let Some(p) = &state_path {
            if !std::path::Path::new(p).exists() {
                return Err(PyIOError::new_err(format!(
                    "{p} does not exist. A witness that starts with no memory of what it \
                     cosigned can be walked onto a fork, so a missing state file is an error. \
                     Create it once with WitnessService.create_state(path)."
                )));
            }
        }
        let state_lock = match &state_path {
            Some(p) => Some(StateLock::acquire(p).map_err(|e| PyIOError::new_err(e.to_string()))?),
            None => None,
        };
        let svc = match &state_path {
            Some(p) if std::path::Path::new(p).exists() => {
                let s =
                    std::fs::read_to_string(p).map_err(|e| PyIOError::new_err(e.to_string()))?;
                let st: witness_log_network::tlog_witness::WitnessState =
                    serde_json::from_str(&s).map_err(malformed_err)?;
                witness_log_network::tlog_witness::WitnessService::from_state(&st)
                    .map_err(malformed_err)?
            }
            _ => witness_log_network::tlog_witness::WitnessService::new(),
        };
        Ok(Self {
            inner: Mutex::new(svc),
            key_name: key_name.to_string(),
            signing_key: ed25519_dalek::SigningKey::from_bytes(&seed),
            state_path,
            open_enrollment,
            max_logs,
            lock: state_lock,
            evidence_recorded: Mutex::new(std::collections::HashSet::new()),
        })
    }

    /// Create an empty state file for a NEW witness. Fails if it exists:
    /// overwriting a witness's memory would allow forks.
    #[staticmethod]
    fn create_state(path: &str) -> PyResult<()> {
        if std::path::Path::new(path).exists() {
            return Err(PyIOError::new_err(format!(
                "{path} already exists; refusing to overwrite"
            )));
        }
        persist_witness_state(
            path,
            &witness_log_network::tlog_witness::WitnessService::new(),
        )
        .map_err(|e| PyIOError::new_err(e.to_string()))
    }

    /// The vkey verifiers use to check this witness's cosignatures.
    fn vkey(&self) -> String {
        witness_log_core::c2sp::VerifierKey::for_cosignature(
            &self.key_name,
            &self.signing_key.verifying_key(),
        )
        .encode()
    }

    /// This witness's public key, hex -- what goes in a directory entry.
    fn pubkey_hex(&self) -> String {
        hex::encode(self.signing_key.verifying_key().to_bytes())
    }

    /// Agree to witness a log. `log_vkey` MUST come from somewhere the log
    /// itself does not control.
    /// Returns False, changing nothing, if the log is already known --
    /// re-adding never resets a log (that would allow a fork). Persisted
    /// immediately when `state_path` is set.
    fn add_log(&self, origin: &str, log_vkey: &str) -> PyResult<bool> {
        let vk = witness_log_core::c2sp::VerifierKey::parse(log_vkey)
            .map_err(|e| MalformedError::new_err(e.to_string()))?;
        let mut svc = lock(&self.inner);
        if !svc.add_log(origin, vk) {
            return Ok(false);
        }
        if let Some(p) = &self.state_path {
            if let Err(e) = persist_witness_state(p, &svc) {
                svc.remove_log(origin);
                return Err(PyIOError::new_err(e.to_string()));
            }
        }
        Ok(true)
    }

    /// Handle an add-checkpoint POST body. Returns `(status, body)`:
    /// 200 cosignature line; 400 malformed/stale; 403 bad signature;
    /// 404 unknown log; 409 the witness's size (send it with
    /// Content-Type `text/x.tlog.size`); 422 refused fork. Prefer
    /// `handle_add_checkpoint_http`, which also gives the content type.
    #[pyo3(signature = (body, now_unix_seconds=None))]
    fn handle_add_checkpoint(&self, body: &str, now_unix_seconds: Option<u64>) -> (u16, String) {
        let (st, _, b) = self.handle(body, now_unix_seconds.unwrap_or_else(now_unix_s));
        (st, b)
    }

    /// Like `handle_add_checkpoint`, returning `(status, content_type, body)`.
    #[pyo3(signature = (body, now_unix_seconds=None))]
    fn handle_add_checkpoint_http(
        &self,
        body: &str,
        now_unix_seconds: Option<u64>,
    ) -> (u16, &'static str, String) {
        self.handle(body, now_unix_seconds.unwrap_or_else(now_unix_s))
    }

    /// Number of logs this witness tracks.
    fn log_count(&self) -> usize {
        lock(&self.inner).log_count()
    }
}

/// Choose witnesses that maximise operator independence. Takes a
/// `WitnessDirectory` as JSON, returns the chosen entries as JSON.
/// Naive selection reaches the independence floor only ~55% of the time
/// under realistic operator distributions; this reaches 100%.
#[pyfunction]
#[pyo3(signature = (directory_json, subject_pubkey_hex, want, include_project_operated=false))]
fn select_diverse_witnesses(
    directory_json: &str,
    subject_pubkey_hex: &str,
    want: usize,
    include_project_operated: bool,
) -> PyResult<String> {
    let dir: witness_log_network::WitnessDirectory =
        serde_json::from_str(directory_json).map_err(malformed_err)?;
    let picked: Vec<&witness_log_network::WitnessEntry> =
        witness_log_network::select_diverse_witnesses(
            &dir,
            subject_pubkey_hex,
            want,
            include_project_operated,
        );
    serde_json::to_string(&picked).map_err(malformed_err)
}

/// Build an independent witness directory entry. Returns JSON. Prefer
/// this over hand-writing the struct: it makes the honest case the easy
/// case.
#[pyfunction]
#[pyo3(signature = (name, operator_org, url, pubkey_hex, compute_provider=None))]
fn witness_entry_independent(
    name: &str,
    operator_org: &str,
    url: &str,
    pubkey_hex: &str,
    compute_provider: Option<String>,
) -> PyResult<String> {
    let e = witness_log_network::WitnessEntry::independent(
        name,
        operator_org,
        url,
        pubkey_hex,
        compute_provider,
    );
    serde_json::to_string(&e).map_err(malformed_err)
}

/// Build a project-operated witness directory entry, declared honestly.
#[pyfunction]
#[pyo3(signature = (name, url, pubkey_hex, compute_provider=None))]
fn witness_entry_project_operated(
    name: &str,
    url: &str,
    pubkey_hex: &str,
    compute_provider: Option<String>,
) -> PyResult<String> {
    let e = witness_log_network::WitnessEntry::project_operated(
        name,
        url,
        pubkey_hex,
        compute_provider,
    );
    serde_json::to_string(&e).map_err(malformed_err)
}

#[pymodule]
fn witness_log(m: &Bound<'_, PyModule>) -> PyResult<()> {
    let py = m.py();
    m.add_class::<PyWitnessLog>()?;
    m.add_class::<PyJournaledLog>()?;
    m.add_class::<PyWitnessService>()?;
    m.add_function(pyo3::wrap_pyfunction!(verify_dossier_json, m)?)?;
    m.add_function(pyo3::wrap_pyfunction!(select_diverse_witnesses, m)?)?;
    m.add_function(pyo3::wrap_pyfunction!(witness_entry_independent, m)?)?;
    m.add_function(pyo3::wrap_pyfunction!(witness_entry_project_operated, m)?)?;
    m.add("WitnessLogError", py.get_type::<WitnessLogError>())?;
    m.add("SignatureError", py.get_type::<SignatureError>())?;
    m.add("ContinuityError", py.get_type::<ContinuityError>())?;
    m.add("MalformedError", py.get_type::<MalformedError>())?;
    m.add(
        "__doc__",
        "WitnessLog: witnessed, not trusted. See spec/SPEC.md for the wire format this implements.",
    )?;
    Ok(())
}
