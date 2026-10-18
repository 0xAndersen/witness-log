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

/// The guard if `m` is free now, `None` if another thread holds it.
fn try_lock<T>(m: &Mutex<T>) -> Option<MutexGuard<'_, T>> {
    match m.try_lock() {
        Ok(g) => Some(g),
        Err(std::sync::TryLockError::Poisoned(e)) => Some(e.into_inner()),
        Err(std::sync::TryLockError::WouldBlock) => None,
    }
}

/// Run `f` on `m`'s value from a thread that holds the GIL.
///
/// Another thread may hold `m` across work done with the GIL released (an
/// fsync, a dossier over a long log). Two rules keep the GIL and `m` from
/// ever waiting on each other: never block on `m` while holding the GIL,
/// and never hold `m` while taking the GIL back. So `m` is taken without
/// waiting when it is free (the common case: no GIL round trip, and `f`
/// cannot release the GIL since it is plain Rust); otherwise the GIL is
/// released, `m` is waited for, `f` runs, and `m` is dropped before the
/// GIL is retaken. 0.5.0 kept the guard across that retake, which with a
/// GIL holder blocking on the same lock froze the process (security
/// review 3, F3).
///
/// Callers that do I/O under `m` (fsync, a file rewrite) use `py.detach`
/// with `lock` instead, so they never hold the GIL across it at all.
fn with_lock_py<T: Send, R: Send>(
    py: Python<'_>,
    m: &Mutex<T>,
    f: impl FnOnce(&mut T) -> R + Send,
) -> R {
    if let Some(mut g) = try_lock(m) {
        return f(&mut g);
    }
    py.detach(|| {
        let mut g = lock(m);
        let r = f(&mut g);
        drop(g);
        r
    })
}

const CLOSED_JOURNAL: &str =
    "this JournaledLog is closed; open it again with witness_log.open(path)";

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
    /// Only ever locked by a thread holding the GIL, and never held across
    /// a GIL release or a call into Python, so no thread can be waiting on
    /// it: plain `lock` cannot block here. Keep it that way, or switch to
    /// `with_lock_py` like `PyJournaledLog`.
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
        // Copy out first: allocating a Python object can run arbitrary
        // Python (a GC pass), which must not happen with the lock held.
        let seed = lock(&self.inner).identity_bytes();
        PyBytes::new(py, &seed)
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

    /// `add_checkpoint_body` for the earlier head of `size` leaves.
    #[pyo3(signature = (size, old_size=0))]
    fn add_checkpoint_body_at(&self, size: u64, old_size: u64) -> PyResult<String> {
        add_checkpoint_body_at(&lock(&self.inner), size, old_size)
    }

    /// `dossier_from_responses` for the earlier head of `size` leaves.
    fn dossier_from_responses_at(
        &self,
        size: u64,
        responses: Vec<(String, String)>,
    ) -> PyResult<(String, usize)> {
        dossier_from_responses_at(&lock(&self.inner), size, responses)
    }

    /// Root of the first `size` leaves, hex, or `None` if the log is
    /// shorter. `root_hex_at(n) == r` is how a client checks the log
    /// still extends a head `(n, r)` that witnesses cosigned.
    fn root_hex_at(&self, size: u64) -> Option<String> {
        lock(&self.inner).root_at(size).map(hex::encode)
    }

    /// `(tree_size, root_hex, proof)` proving the leaf at `index` is in the
    /// current tree. Verify offline with `witness_log.verify_inclusion`.
    fn inclusion_proof(&self, index: u64) -> Option<(u64, String, Vec<String>)> {
        inclusion_proof_of(&lock(&self.inner), index)
    }

    /// RFC 6962 leaf hash of the leaf at `index`, hex.
    fn leaf_hash_hex(&self, index: u64) -> Option<String> {
        leaf_hash_of(&lock(&self.inner), index)
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
/// embedded directory. `min_witnesses`, when given, replaces the
/// fraction with an absolute receipt count: the right gate when the
/// directory is a registry of many witnesses.
///
/// `known_heads` (`"<size>:<root hex>"` strings) are heads the caller
/// already trusts for this identity, and `evidence_json` is a JSON array
/// of witness equivocation proofs (bare, or as `witness serve` writes
/// them); a dossier that contradicts either is "diverged" (RFC-0002).
/// A dossier that fails a check is "invalid".
///
/// `accept_fleet_anchor` (RFC-0001, EXPERIMENTAL) counts the cosigners of
/// a fleet checkpoint that includes the dossier's checkpoint, when its
/// `fleet_anchor` fully verifies; it needs `subject_org` (the organisation
/// that runs the fleet log). Default False: the field is ignored.
#[pyfunction]
#[pyo3(signature = (dossier_json, threshold, expected_identity_pubkey=None, trusted_directory_json=None, min_witnesses=None, revocations_json=None, known_heads=None, evidence_json=None, subject_org=None, accept_fleet_anchor=false))]
#[allow(clippy::too_many_arguments)]
fn verify_dossier_json(
    py: Python<'_>,
    dossier_json: &str,
    threshold: f64,
    expected_identity_pubkey: Option<String>,
    trusted_directory_json: Option<String>,
    min_witnesses: Option<usize>,
    revocations_json: Option<String>,
    known_heads: Option<Vec<String>>,
    evidence_json: Option<String>,
    subject_org: Option<String>,
    accept_fleet_anchor: bool,
) -> PyResult<String> {
    // Parsing and verifying a long dossier is real CPU work: release the
    // GIL so other Python threads (an agent's event loop, its witnesser)
    // keep running meanwhile.
    py.detach(|| {
        verify_dossier_json_detached(
            dossier_json,
            threshold,
            expected_identity_pubkey,
            trusted_directory_json,
            min_witnesses,
            revocations_json,
            known_heads,
            evidence_json,
            subject_org,
            accept_fleet_anchor,
        )
    })
}

#[allow(clippy::too_many_arguments)]
fn verify_dossier_json_detached(
    dossier_json: &str,
    threshold: f64,
    expected_identity_pubkey: Option<String>,
    trusted_directory_json: Option<String>,
    min_witnesses: Option<usize>,
    revocations_json: Option<String>,
    known_heads: Option<Vec<String>>,
    evidence_json: Option<String>,
    subject_org: Option<String>,
    accept_fleet_anchor: bool,
) -> PyResult<String> {
    if min_witnesses == Some(0) {
        return Err(pyo3::exceptions::PyValueError::new_err(
            "min_witnesses must be at least 1",
        ));
    }
    if !(0.0..=1.0).contains(&threshold) {
        return Err(pyo3::exceptions::PyValueError::new_err(format!(
            "threshold must be between 0.0 and 1.0, got {threshold}"
        )));
    }
    if let Some(id) = &expected_identity_pubkey {
        if id.len() != 64 || !id.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(pyo3::exceptions::PyValueError::new_err(
                "expected_identity_pubkey must be a 32-byte Ed25519 public key as 64 hex characters",
            ));
        }
    }
    let dossier: witness_log_network::Dossier =
        serde_json::from_str(dossier_json).map_err(malformed_err)?;
    let trusted_directory: Option<witness_log_network::WitnessDirectory> =
        match &trusted_directory_json {
            // `{"witnesses": [...]}` or a bare array of entries.
            Some(s) => Some(
                serde_json::from_str::<witness_log_network::WitnessDirectory>(s)
                    .or_else(|first| {
                        serde_json::from_str::<Vec<witness_log_network::WitnessEntry>>(s)
                            .map(|witnesses| witness_log_network::WitnessDirectory { witnesses })
                            .map_err(|_| first)
                    })
                    .map_err(malformed_err)?,
            ),
            None => None,
        };
    // Revocations the caller knows about out of band: one statement (as
    // `revoke_json` returns it) or an array of them.
    let revocations: Vec<witness_log_core::identity::RevocationStatement> = match &revocations_json
    {
        None => Vec::new(),
        Some(s) if s.trim_start().starts_with('{') => {
            vec![serde_json::from_str(s).map_err(malformed_err)?]
        }
        Some(s) => serde_json::from_str(s).map_err(malformed_err)?,
    };
    let known_heads = known_heads
        .iter()
        .flatten()
        .map(|h| {
            h.parse::<witness_log_network::KnownHead>().map_err(|e| {
                pyo3::exceptions::PyValueError::new_err(format!("known head {h:?}: {e}"))
            })
        })
        .collect::<PyResult<Vec<_>>>()?;
    let evidence = match &evidence_json {
        None => Vec::new(),
        Some(s) => {
            let v: serde_json::Value = serde_json::from_str(s).map_err(malformed_err)?;
            let items = match v {
                serde_json::Value::Array(a) => a,
                one => vec![one],
            };
            items
                .into_iter()
                .map(|v| {
                    witness_log_network::tlog_witness::EquivocationProof::from_evidence(&v)
                        .map_err(|e| malformed_err(format!("not an equivocation proof: {e}")))
                })
                .collect::<PyResult<Vec<_>>>()?
        }
    };
    let ctx = witness_log_network::VerifyContext {
        expected_identity_pubkey: expected_identity_pubkey.as_deref(),
        trusted_directory: trusted_directory.as_ref(),
        min_receipts: min_witnesses,
        revocations: &revocations,
        known_heads: &known_heads,
        evidence: &evidence,
        subject_org: subject_org.as_deref(),
        accept_fleet_anchor,
    };
    let report = dossier.verify(threshold, &ctx);
    serde_json::to_string_pretty(&report).map_err(malformed_err)
}

/// The add-checkpoint request body for this log's current head, signed
/// under its canonical origin, with a consistency proof from `old_size`.
fn add_checkpoint_body(log: &CoreLog, old_size: u64) -> PyResult<String> {
    add_checkpoint_body_at(log, log.tree_size(), old_size)
}

/// `add_checkpoint_body` for an earlier head of `size` leaves, so a
/// background submitter can pin one head while the agent keeps appending.
fn add_checkpoint_body_at(log: &CoreLog, size: u64, old_size: u64) -> PyResult<String> {
    let key = ed25519_dalek::SigningKey::from_bytes(&log.identity_bytes());
    let origin = witness_log_core::c2sp::canonical_origin(&key.verifying_key());
    let current = log.tree_size();
    if size > current {
        return Err(MalformedError::new_err(format!(
            "size {size} exceeds this log's size {current}"
        )));
    }
    if old_size > size {
        return Err(MalformedError::new_err(format!(
            "old_size {old_size} exceeds this log's size {size}"
        )));
    }
    let proof = if old_size == 0 || old_size == size {
        vec![]
    } else {
        log.consistency_proof_between(old_size, size)
            .ok_or_else(|| MalformedError::new_err("no consistency proof for that size"))?
    };
    let note = log
        .c2sp_checkpoint_at(&origin, size)
        .ok_or_else(|| MalformedError::new_err("no head at that size"))?
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
    dossier_from_responses_at(log, log.tree_size(), responses)
}

/// `dossier_from_responses` for an earlier head of `size` leaves: the
/// dossier holds exactly the first `size` leaves and a checkpoint over
/// them, so cosignatures gathered for that head verify even if the agent
/// has appended since.
fn dossier_from_responses_at(
    log: &CoreLog,
    size: u64,
    responses: Vec<(String, String)>,
) -> PyResult<(String, usize)> {
    use witness_log_core::c2sp::{Cosignature, NoteSignature, VerifierKey};
    let key = ed25519_dalek::SigningKey::from_bytes(&log.identity_bytes());
    let origin = witness_log_core::c2sp::canonical_origin(&key.verifying_key());
    let cp = log
        .c2sp_checkpoint_at(&origin, size)
        .ok_or_else(|| MalformedError::new_err(format!("no head at size {size}")))?;
    let native = log
        .checkpoint_at(&key, size)
        .ok_or_else(|| MalformedError::new_err(format!("no head at size {size}")))?;
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
    let mut dossier = witness_log_network::Dossier::from_log(log, native).with_receipts(receipts);
    // `size <= tree_size`, checked by `checkpoint_at` above.
    dossier
        .leaves
        .truncate(usize::try_from(size).unwrap_or(usize::MAX));
    Ok((
        serde_json::to_string_pretty(&dossier).map_err(malformed_err)?,
        n,
    ))
}

/// `(tree_size, root_hex, proof_hexes)` for the leaf at `index` in the
/// CURRENT tree, or `None` if the index does not exist.
fn inclusion_proof_of(log: &CoreLog, index: u64) -> Option<(u64, String, Vec<String>)> {
    let proof = log.inclusion_proof(index)?;
    Some((
        log.tree_size(),
        log.root_hex(),
        proof.iter().map(hex::encode).collect(),
    ))
}

/// RFC 6962 leaf hash (`SHA256(0x00 || canonical_bytes)`) of the leaf at
/// `index`, hex, or `None` if it does not exist.
fn leaf_hash_of(log: &CoreLog, index: u64) -> Option<String> {
    let leaf = log.leaves().get(usize::try_from(index).ok()?)?;
    Some(hex::encode(witness_log_core::merkle::leaf_hash(
        &leaf.canonical_bytes(),
    )))
}

/// SPEC §8: `SHA256(bucket_pad(payload) || salt || index)` as 64 hex
/// characters, where `bucket_pad(payload) = len(payload) as u64 (8 bytes
/// big-endian) || payload || zeros` up to `(len/256 + 1) * 256` payload
/// bytes, `salt` is 32 bytes and `index` is the leaf index as 8 bytes
/// big-endian. The function a verifier runs over a disclosed payload and
/// salt; pinned by corpus vector 11.
#[pyfunction]
fn payload_hash(payload: &[u8], salt: &[u8], index: u64) -> PyResult<String> {
    let salt: [u8; 32] = salt
        .try_into()
        .map_err(|_| MalformedError::new_err("salt must be exactly 32 bytes"))?;
    Ok(hex::encode(
        witness_log_core::redaction::payload_hash_with_salt(payload, &salt, index),
    ))
}

/// Verify an inclusion proof offline. All hashes hex. False on any
/// malformed input rather than raising, so a verifier loop never stops
/// on a hostile dossier.
#[pyfunction]
fn verify_inclusion(
    leaf_hash_hex: &str,
    leaf_index: u64,
    tree_size: u64,
    proof_hexes: Vec<String>,
    root_hex: &str,
) -> bool {
    let to32 = |h: &str| -> Option<[u8; 32]> { hex::decode(h.trim()).ok()?.try_into().ok() };
    let (Some(leaf), Some(root)) = (to32(leaf_hash_hex), to32(root_hex)) else {
        return false;
    };
    let mut proof = Vec::with_capacity(proof_hexes.len());
    for h in &proof_hexes {
        match to32(h) {
            Some(x) => proof.push(x),
            None => return false,
        }
    }
    witness_log_core::merkle::verify_inclusion(&leaf, leaf_index, tree_size, &proof, &root)
}

fn parse_auth_kind(kind: &str) -> PyResult<witness_log_core::leaf::AuthorizationEventKind> {
    use witness_log_core::leaf::AuthorizationEventKind as K;
    Ok(match kind {
        "granted_by_me" => K::GrantedByMe,
        "granted_to_me" => K::GrantedToMe,
        "revoked_by_me" => K::RevokedByMe,
        "revoked_to_me" => K::RevokedToMe,
        "scope_changed_by_me" => K::ScopeChangedByMe,
        "scope_changed_to_me" => K::ScopeChangedToMe,
        other => {
            return Err(pyo3::exceptions::PyValueError::new_err(format!(
                "unknown authorization event kind {other:?}; expected granted_by_me, granted_to_me, revoked_by_me, revoked_to_me, scope_changed_by_me or scope_changed_to_me"
            )))
        }
    })
}

/// Match a HandoffAttestation pair across two logs (SPEC §3.1): the
/// sender's `Sent` leaf and the receiver's `Received` leaf, as JSON
/// objects from `leaves_json()` or a dossier's `leaves`. Returns None when
/// they bind, else the reason they do not.
#[pyfunction]
fn handoff_binding_error(
    sender_identity_hex: &str,
    sender_leaf_json: &str,
    receiver_identity_hex: &str,
    receiver_leaf_json: &str,
) -> PyResult<Option<String>> {
    let a: witness_log_core::leaf::Leaf = serde_json::from_str(sender_leaf_json)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("sender_leaf_json: {e}")))?;
    let b: witness_log_core::leaf::Leaf = serde_json::from_str(receiver_leaf_json)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("receiver_leaf_json: {e}")))?;
    Ok(witness_log_core::leaf::verify_handoff_binding(
        sender_identity_hex,
        &a,
        receiver_identity_hex,
        &b,
    )
    .err())
}

/// Match an AuthorizationEvent pair across two logs (SPEC §3.2). Returns
/// None when they bind, else the reason.
#[pyfunction]
fn authorization_binding_error(
    party_a_identity_hex: &str,
    party_a_leaf_json: &str,
    party_b_identity_hex: &str,
    party_b_leaf_json: &str,
) -> PyResult<Option<String>> {
    let a: witness_log_core::leaf::Leaf = serde_json::from_str(party_a_leaf_json)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("party_a_leaf_json: {e}")))?;
    let b: witness_log_core::leaf::Leaf = serde_json::from_str(party_b_leaf_json)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("party_b_leaf_json: {e}")))?;
    Ok(witness_log_core::leaf::verify_authorization_binding(
        party_a_identity_hex,
        &a,
        party_b_identity_hex,
        &b,
    )
    .err())
}

/// True when a HandoffAttestation pair binds (SPEC §3.1). Until 0.4.0 this
/// returned `None` for success and the reason for failure, which read as
/// false in an `if`; the reason is now `handoff_binding_error`.
#[pyfunction]
fn verify_handoff_binding(
    sender_identity_hex: &str,
    sender_leaf_json: &str,
    receiver_identity_hex: &str,
    receiver_leaf_json: &str,
) -> PyResult<bool> {
    Ok(handoff_binding_error(
        sender_identity_hex,
        sender_leaf_json,
        receiver_identity_hex,
        receiver_leaf_json,
    )?
    .is_none())
}

/// True when an AuthorizationEvent pair binds (SPEC §3.2); the reason for a
/// failure is `authorization_binding_error`.
#[pyfunction]
fn verify_authorization_binding(
    party_a_identity_hex: &str,
    party_a_leaf_json: &str,
    party_b_identity_hex: &str,
    party_b_leaf_json: &str,
) -> PyResult<bool> {
    Ok(authorization_binding_error(
        party_a_identity_hex,
        party_a_leaf_json,
        party_b_identity_hex,
        party_b_leaf_json,
    )?
    .is_none())
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
#[pyclass(name = "JournaledLog", weakref)]
struct PyJournaledLog {
    /// `None` after `close()`: the journal and its lock are released.
    inner: Mutex<Option<witness_log_core::journal::JournaledLog>>,
    /// The journal path this log was opened with; `<path>.salts` is the
    /// salt sidecar `disclose` reads.
    path: String,
    /// Optional erasable payload sidecar (`witness_log.open(...,
    /// store_payloads=True)`), so `disclose` can hand out the payload
    /// along with its salt. `None` unless enabled.
    ///
    /// Lock order: `payloads` before `inner`, always. An append holds
    /// `payloads` from before its leaf exists until its record is written,
    /// and `forget` holds it from before the salt is erased until the
    /// record is gone, so neither can run inside the other.
    payloads: Mutex<Option<PayloadStore>>,
}

impl PyJournaledLog {
    fn wrap(path: &str, inner: witness_log_core::journal::JournaledLog) -> Self {
        Self {
            inner: Mutex::new(Some(inner)),
            path: path.to_string(),
            payloads: Mutex::new(None),
        }
    }

    /// Run `f` with the payload sidecar and the journal (`None` once
    /// closed) both locked, in the one order every caller uses
    /// (`payloads`, then `inner`). Like `with_lock_py`: both are taken
    /// without waiting when free; otherwise the wait, `f` and the release
    /// all happen with the GIL released.
    fn with_store_and_journal<R: Send>(
        &self,
        py: Python<'_>,
        f: impl FnOnce(
                &mut Option<PayloadStore>,
                &mut Option<witness_log_core::journal::JournaledLog>,
            ) -> R
            + Send,
    ) -> R {
        if let Some(mut store) = try_lock(&self.payloads) {
            if let Some(mut g) = try_lock(&self.inner) {
                return f(&mut store, &mut g);
            }
        }
        py.detach(|| {
            let mut store = lock(&self.payloads);
            let mut g = lock(&self.inner);
            let r = f(&mut store, &mut g);
            drop(g);
            drop(store);
            r
        })
    }

    /// Append a payload-carrying leaf and, if a sidecar is enabled, its
    /// payload record, as one step under both locks: a concurrent
    /// `forget(i)` runs before leaf `i` exists or after its record does.
    /// 0.5.0 appended the leaf, then took the sidecar lock separately,
    /// releasing the GIL in between when it was busy; a `forget(i)` there
    /// found no record, returned True, and the record was written after
    /// it (security review 3, F7). A sidecar failure still never loses
    /// the leaf; it surfaces as an error on this call.
    fn append_with_payload(
        &self,
        py: Python<'_>,
        payload: &[u8],
        append: fn(&mut witness_log_core::journal::JournaledLog, &[u8]) -> std::io::Result<u64>,
    ) -> PyResult<u64> {
        self.with_store_and_journal(py, |store, g| {
            let j = g
                .as_mut()
                .ok_or_else(|| PyIOError::new_err(CLOSED_JOURNAL))?;
            let idx = append(j, payload).map_err(io_err)?;
            if let Some(s) = store.as_mut() {
                s.record(idx, payload)
                    .map_err(|e| PyIOError::new_err(format!("payload sidecar: {e}")))?;
            }
            Ok(idx)
        })
    }
}

fn redaction_targets(log: &CoreLog) -> impl Iterator<Item = u64> + '_ {
    log.leaves()
        .iter()
        .filter(|l| l.leaf_type == witness_log_core::leaf::LeafType::Redaction.tag())
        .filter_map(|l| l.redacted_index)
}

/// Every index a Redaction leaf in `log` names.
fn redacted_indices(log: &CoreLog) -> Vec<u64> {
    redaction_targets(log).collect()
}

/// Whether a Redaction leaf in `log` names `index`.
fn is_redacted(log: &CoreLog, index: u64) -> bool {
    redaction_targets(log).any(|i| i == index)
}

/// `<journal>.payloads`: one JSON line per leaf, `{"i": index, "p": hex}`,
/// created 0600. Opt-in, because it holds exactly what the tree was
/// designed not to hold. `forget` zero-overwrites the old file's bytes,
/// then replaces it with a copy that lacks the record, so the payload is
/// gone from the live file, not merely marked.
struct PayloadStore {
    path: std::path::PathBuf,
    file: std::fs::File,
    /// Leaves the journal has redacted (or `forget` was called for).
    /// `record` refuses them: defence in depth behind the lock order,
    /// which already keeps a record from following its `forget`.
    redacted: std::collections::HashSet<u64>,
}

impl PayloadStore {
    fn open(path: &str) -> std::io::Result<Self> {
        let mut opts = std::fs::OpenOptions::new();
        opts.append(true).create(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let file = opts.open(path)?;
        Ok(Self {
            path: std::path::PathBuf::from(path),
            file,
            redacted: std::collections::HashSet::new(),
        })
    }

    fn record(&mut self, index: u64, payload: &[u8]) -> std::io::Result<()> {
        use std::io::Write;
        if self.redacted.contains(&index) {
            return Ok(());
        }
        let line = serde_json::json!({"i": index, "p": hex::encode(payload)});
        writeln!(self.file, "{line}")
    }

    /// Every record in the file, in order, skipping lines that do not
    /// parse (a torn tail from a crash).
    fn records(&self) -> std::io::Result<Vec<(u64, Vec<u8>)>> {
        use std::io::BufRead;
        let f = std::fs::File::open(&self.path)?;
        let mut out = Vec::new();
        for line in std::io::BufReader::new(f).lines() {
            let line = line?;
            let v: serde_json::Value = match serde_json::from_str(line.trim()) {
                Ok(v) => v,
                Err(_) => continue,
            };
            let i = v.get("i").and_then(serde_json::Value::as_u64);
            let p = v
                .get("p")
                .and_then(serde_json::Value::as_str)
                .and_then(|h| hex::decode(h).ok());
            if let (Some(i), Some(p)) = (i, p) {
                out.push((i, p));
            }
        }
        Ok(out)
    }

    fn get(&self, index: u64) -> std::io::Result<Option<Vec<u8>>> {
        if self.redacted.contains(&index) {
            return Ok(None);
        }
        Ok(self
            .records()?
            .into_iter()
            .rfind(|(i, _)| *i == index)
            .map(|(_, p)| p))
    }

    fn mark_redacted(&mut self, indices: &[u64]) {
        self.redacted.extend(indices.iter().copied());
    }

    /// Drop every record for an index in `indices`. Returns whether any
    /// record was removed. Writes the surviving records to a temp sibling
    /// (0600), fsyncs it, overwrites the old file's bytes with zeros,
    /// then renames the temp file over it.
    fn forget(&mut self, indices: &[u64]) -> std::io::Result<bool> {
        use std::io::{Seek, SeekFrom, Write};
        let all = self.records()?;
        let keep: Vec<&(u64, Vec<u8>)> = all.iter().filter(|(i, _)| !indices.contains(i)).collect();
        if keep.len() == all.len() {
            return Ok(false);
        }
        let dir = self
            .path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .map(std::path::Path::to_path_buf)
            .unwrap_or_else(|| std::path::PathBuf::from("."));
        let name = self
            .path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("payloads");
        let tmp = dir.join(format!(".{name}.tmp-{}", std::process::id()));
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let written = (|| -> std::io::Result<()> {
            let mut f = opts.open(&tmp)?;
            for (i, p) in keep {
                writeln!(f, "{}", serde_json::json!({"i": i, "p": hex::encode(p)}))?;
            }
            f.sync_all()
        })();
        if let Err(e) = written {
            let _ = std::fs::remove_file(&tmp);
            return Err(e);
        }
        // Zero the old bytes before the rename unlinks them.
        {
            let len = self.file.metadata()?.len();
            let mut old = std::fs::OpenOptions::new().write(true).open(&self.path)?;
            old.seek(SeekFrom::Start(0))?;
            let zeros = vec![0u8; 1 << 16];
            let mut left = len;
            while left > 0 {
                let n = std::cmp::min(left, zeros.len() as u64) as usize;
                old.write_all(&zeros[..n])?;
                left -= n as u64;
            }
            old.sync_all()?;
        }
        std::fs::rename(&tmp, &self.path)?;
        #[cfg(unix)]
        {
            if let Ok(d) = std::fs::File::open(&dir) {
                let _ = d.sync_all();
            }
        }
        let mut opts = std::fs::OpenOptions::new();
        opts.append(true);
        self.file = opts.open(&self.path)?;
        Ok(true)
    }

    fn sync(&mut self) -> std::io::Result<()> {
        use std::io::Write;
        self.file.flush()?;
        self.file.sync_all()
    }
}

/// The salt for leaf `index` from the `<journal>.salts` sidecar (SPEC §8
/// says where salts live is an implementation matter; this is where the
/// reference implementation keeps them). `None` when the salt was
/// forgotten or the leaf never had one. Read from the file each time:
/// the core appends every salt synchronously, and `disclose` is rare.
fn salt_from_sidecar(journal_path: &str, index: u64) -> std::io::Result<Option<String>> {
    use std::io::BufRead;
    let p = witness_log_core::journal::JournaledLog::salts_path(journal_path);
    let f = match std::fs::File::open(&p) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    let mut found = None;
    for line in std::io::BufReader::new(f).lines() {
        let line = line?;
        let v: serde_json::Value = match serde_json::from_str(line.trim()) {
            Ok(v) => v,
            Err(_) => continue,
        };
        if v.get("i").and_then(serde_json::Value::as_u64) == Some(index) {
            if let Some(s) = v.get("s").and_then(serde_json::Value::as_str) {
                if s.len() == 64 && hex::decode(s).is_ok() {
                    found = Some(s.to_ascii_lowercase());
                }
            }
        }
    }
    Ok(found)
}

fn io_err(e: std::io::Error) -> PyErr {
    PyIOError::new_err(e.to_string())
}

impl PyJournaledLog {
    /// Run `f` on the open journal with the GIL released, for calls that
    /// do real work (dossiers, proofs, request bodies over a long log), so
    /// other Python threads keep running meanwhile.
    fn detached<R: Send>(
        &self,
        py: Python<'_>,
        f: impl FnOnce(&mut witness_log_core::journal::JournaledLog) -> PyResult<R> + Send,
    ) -> PyResult<R> {
        py.detach(|| {
            let mut g = lock(&self.inner);
            match g.as_mut() {
                None => Err(PyIOError::new_err(CLOSED_JOURNAL)),
                Some(j) => f(j),
            }
        })
    }

    /// Run `f` on the open journal for a quick call (a size, a root, one
    /// leaf, one append), without a GIL round trip when nothing else holds
    /// the journal. See `with_lock_py` for why this never deadlocks.
    fn with_j<R: Send>(
        &self,
        py: Python<'_>,
        f: impl FnOnce(&mut witness_log_core::journal::JournaledLog) -> PyResult<R> + Send,
    ) -> PyResult<R> {
        with_lock_py(py, &self.inner, |g| match g.as_mut() {
            None => Err(PyIOError::new_err(CLOSED_JOURNAL)),
            Some(j) => f(j),
        })
    }

    fn signing_key(&self, py: Python<'_>) -> PyResult<ed25519_dalek::SigningKey> {
        let seed = self.with_j(py, |j| Ok(j.log().identity_bytes()))?;
        Ok(ed25519_dalek::SigningKey::from_bytes(&seed))
    }
}

#[pymethods]
impl PyJournaledLog {
    /// Create a journaled log for an identity you already hold.
    /// `identity_seed` is 32 raw bytes: `os.urandom(32)` the first time,
    /// then the same bytes forever (or `WitnessLog.identity_bytes()`).
    ///
    /// The journal's first line stores this seed, the identity PRIVATE
    /// key, in plain hex, and `<path>.salts` holds the redaction salts.
    /// Both files are created 0600; protect and back them up together,
    /// like any key file.
    #[staticmethod]
    fn create(py: Python<'_>, path: &str, identity_seed: &[u8]) -> PyResult<Self> {
        let identity = parse_identity_seed(identity_seed)?;
        py.detach(|| witness_log_core::journal::JournaledLog::create(path, identity))
            .map(|inner| Self::wrap(path, inner))
            .map_err(|e| PyIOError::new_err(e.to_string()))
    }

    /// Like `create`, but the seed is never written to the journal: the
    /// header holds only the public key, and every later start must be
    /// `resume_with_identity(path, seed)` with the same seed (from a KMS,
    /// a secrets manager, an environment variable).
    #[staticmethod]
    fn create_sealed(py: Python<'_>, path: &str, identity_seed: &[u8]) -> PyResult<Self> {
        let identity = parse_identity_seed(identity_seed)?;
        py.detach(|| witness_log_core::journal::JournaledLog::create_sealed(path, identity))
            .map(|inner| Self::wrap(path, inner))
            .map_err(|e| PyIOError::new_err(e.to_string()))
    }

    /// Resume a sealed journal (or an unsealed one; the seed must then
    /// match). Returns `(log, dropped_trailing_lines)` like `resume`.
    #[staticmethod]
    fn resume_with_identity(
        py: Python<'_>,
        path: &str,
        identity_seed: &[u8],
    ) -> PyResult<(Self, usize)> {
        let seed: [u8; 32] = identity_seed.try_into().map_err(|_| {
            pyo3::exceptions::PyValueError::new_err("identity_seed must be exactly 32 bytes")
        })?;
        py.detach(|| witness_log_core::journal::JournaledLog::resume_with_identity(path, &seed))
            .map(|(inner, report)| (Self::wrap(path, inner), report.dropped_trailing_lines))
            .map_err(|e| PyIOError::new_err(e.to_string()))
    }

    /// Create a journaled log with a throwaway identity. For tests and
    /// demos. Dossiers from this log belong to a key you cannot reproduce.
    #[staticmethod]
    fn create_ephemeral(py: Python<'_>, path: &str) -> PyResult<Self> {
        py.detach(|| witness_log_core::journal::JournaledLog::create_ephemeral(path))
            .map(|inner| Self::wrap(path, inner))
            .map_err(|e| PyIOError::new_err(e.to_string()))
    }

    /// Resume from an existing journal. Returns `(log, dropped_trailing_lines)`;
    /// a nonzero count means the previous process died mid-write and the
    /// torn line was discarded and physically truncated.
    #[staticmethod]
    fn resume(py: Python<'_>, path: &str) -> PyResult<(Self, usize)> {
        py.detach(|| witness_log_core::journal::JournaledLog::resume(path))
            .map(|(inner, report)| (Self::wrap(path, inner), report.dropped_trailing_lines))
            .map_err(|e| PyIOError::new_err(e.to_string()))
    }

    fn append_intent(&self, py: Python<'_>, payload: &[u8]) -> PyResult<u64> {
        self.append_with_payload(
            py,
            payload,
            witness_log_core::journal::JournaledLog::append_intent,
        )
    }
    fn append_result(&self, py: Python<'_>, payload: &[u8]) -> PyResult<u64> {
        self.append_with_payload(
            py,
            payload,
            witness_log_core::journal::JournaledLog::append_result,
        )
    }
    fn append_memory(&self, py: Python<'_>, payload: &[u8]) -> PyResult<u64> {
        self.append_with_payload(
            py,
            payload,
            witness_log_core::journal::JournaledLog::append_memory,
        )
    }
    fn append_handoff_sent(
        &self,
        py: Python<'_>,
        state: &[u8],
        counterparty_pubkey_hex: &str,
    ) -> PyResult<u64> {
        self.with_j(py, |j| {
            j.append_handoff_sent(state, counterparty_pubkey_hex)
                .map_err(io_err)
        })
    }
    fn append_handoff_received(
        &self,
        py: Python<'_>,
        state: &[u8],
        counterparty_pubkey_hex: &str,
    ) -> PyResult<u64> {
        self.with_j(py, |j| {
            j.append_handoff_received(state, counterparty_pubkey_hex)
                .map_err(io_err)
        })
    }
    /// Record that a delegation/authorization change happened between this
    /// agent and `counterparty_pubkey_hex` (SPEC §3.2). `kind` is one of
    /// "granted_by_me", "granted_to_me", "revoked_by_me", "revoked_to_me",
    /// "scope_changed_by_me", "scope_changed_to_me". `scope` is the raw
    /// scope description (an AP2 mandate, a UCAN, a JSON policy: any bytes);
    /// its unsalted SHA-256 is what the two sides later match on.
    fn append_authorization_event(
        &self,
        py: Python<'_>,
        kind: &str,
        scope: &[u8],
        counterparty_pubkey_hex: &str,
    ) -> PyResult<u64> {
        let kind = parse_auth_kind(kind)?;
        self.with_j(py, |j| {
            j.append_authorization_event(kind, scope, counterparty_pubkey_hex)
                .map_err(io_err)
        })
    }
    /// Record an external anchor (Rekor entry, RFC 3161 token, ...) for
    /// the current head (SPEC §3.3). The proof JSON is hashed into the
    /// leaf; verifiers check the carried JSON against that hash.
    fn append_external_anchor(
        &self,
        py: Python<'_>,
        anchor_url: &str,
        anchor_proof_json: &str,
    ) -> PyResult<u64> {
        self.with_j(py, |j| {
            j.append_external_anchor(anchor_url, anchor_proof_json)
                .map_err(io_err)
        })
    }

    /// Right-to-be-forgotten. Returns True if a leaf was actually erased.
    /// Raises on I/O failure, so a journaling failure during a legally
    /// consequential operation cannot go unnoticed. Works for leaves from
    /// earlier sessions too: salts live in `<path>.salts` next to the
    /// journal and the forgotten salt is removed from that file.
    fn forget(&self, py: Python<'_>, index: u64) -> PyResult<bool> {
        // Rewrites and fsyncs the salt sidecar: done with the GIL released.
        // `payloads` is taken first (the lock order) and held until the
        // payload record is gone, so no append's record for `index` can
        // land after this looked for it (security review 3, F7).
        py.detach(|| {
            let mut store = lock(&self.payloads);
            let (erased, exists) = {
                let mut g = lock(&self.inner);
                let j = g.as_mut().ok_or_else(|| CLOSED_JOURNAL.to_string())?;
                let exists = index < j.log().tree_size();
                (j.forget(index).map_err(|e| e.to_string())?, exists)
            };
            // The payload record goes whether or not a salt was left to
            // forget: a payload with no salt is still a payload.
            if let Some(s) = store.as_mut() {
                if exists {
                    s.mark_redacted(&[index]);
                }
                s.forget(&[index])
                    .map_err(|e| format!("payload sidecar: {e}"))?;
            }
            drop(store);
            Ok(erased)
        })
        .map_err(PyIOError::new_err::<String>)
    }

    /// True if `forget(index)` would erase something: the leaf exists,
    /// carries a payload, and its salt is still held. Distinguishes "never
    /// had a payload / already forgotten" from a pending redaction.
    fn can_forget(&self, py: Python<'_>, index: u64) -> PyResult<bool> {
        self.with_j(py, |j| Ok(j.can_forget(index)))
    }

    /// Remove a stale `<path>.lock` left by a process that died holding
    /// the journal. On Linux `resume` does this itself when the recorded
    /// PID is no longer running; elsewhere, or when a live PID was
    /// reused, call this only if you are certain nothing else has the
    /// journal open: two writers corrupt it.
    #[staticmethod]
    fn force_unlock(path: &str) -> PyResult<()> {
        witness_log_core::journal::JournaledLog::force_unlock(path)
            .map_err(|e| PyIOError::new_err(e.to_string()))
    }

    /// fsync. Blocks the calling thread (call it from a worker thread if
    /// you are async); since 0.5.0 other Python threads keep running while
    /// it waits, because the GIL is released for the fsync.
    fn sync(&self, py: Python<'_>) -> PyResult<()> {
        py.detach(|| {
            {
                let mut g = lock(&self.inner);
                let j = g.as_mut().ok_or_else(|| CLOSED_JOURNAL.to_string())?;
                j.sync().map_err(|e| e.to_string())?;
            }
            if let Some(store) = lock(&self.payloads).as_mut() {
                store.sync().map_err(|e| format!("payload sidecar: {e}"))?;
            }
            Ok(())
        })
        .map_err(PyIOError::new_err::<String>)
    }

    fn tree_size(&self, py: Python<'_>) -> PyResult<u64> {
        self.with_j(py, |j| Ok(j.log().tree_size()))
    }

    /// The journal path this log was opened with.
    fn path(&self) -> String {
        self.path.clone()
    }

    /// One leaf as JSON (the same object `leaves_json()` lists at that
    /// position), or `None` past the end.
    fn leaf_json(&self, py: Python<'_>, index: u64) -> PyResult<Option<String>> {
        self.with_j(py, |j| {
            match j
                .log()
                .leaves()
                .get(usize::try_from(index).unwrap_or(usize::MAX))
            {
                Some(leaf) => serde_json::to_string(leaf).map(Some).map_err(malformed_err),
                None => Ok(None),
            }
        })
    }

    /// The redaction salt for leaf `index` as 64 hex characters, read
    /// from `<path>.salts`, or `None` if it was forgotten or the leaf
    /// never carried a payload. Handing this out together with the
    /// payload lets a third party recompute `payload_hash` (SPEC §8) and
    /// check it against the leaf; see `witness_log.verify_disclosure`.
    fn salt_hex(&self, py: Python<'_>, index: u64) -> PyResult<Option<String>> {
        if !self.with_j(py, |j| Ok(j.can_forget(index)))? {
            return Ok(None);
        }
        salt_from_sidecar(&self.path, index).map_err(io_err)
    }

    /// Keep every payload appended from now on in `<path>.payloads`
    /// (`path` defaults to that) so `payload(index)` and `disclose` can
    /// return it. `forget(index)` removes and zero-overwrites its record.
    /// Records for leaves this journal has already redacted are dropped
    /// on enable (a crash between `forget` and the sidecar rewrite).
    #[pyo3(signature = (path = None))]
    fn enable_payload_store(&self, py: Python<'_>, path: Option<&str>) -> PyResult<()> {
        let p = path
            .map(str::to_string)
            .unwrap_or_else(|| format!("{}.payloads", self.path));
        // Both locks, in order, from reading the journal's redactions to
        // installing the store: a `forget` cannot fall between the two
        // (it would erase from no store and leave its record in this one).
        // Rewriting the sidecar fsyncs, so the GIL is released throughout.
        py.detach(|| {
            let mut slot = lock(&self.payloads);
            let forgotten = {
                let g = lock(&self.inner);
                let j = g
                    .as_ref()
                    .ok_or_else(|| PyIOError::new_err(CLOSED_JOURNAL))?;
                redacted_indices(j.log())
            };
            let mut store = PayloadStore::open(&p).map_err(io_err)?;
            if !forgotten.is_empty() {
                store
                    .forget(&forgotten)
                    .map_err(|e| PyIOError::new_err(format!("payload sidecar: {e}")))?;
            }
            store.mark_redacted(&forgotten);
            *slot = Some(store);
            drop(slot);
            Ok(())
        })
    }

    /// The payload sidecar's path, or `None` when none is enabled.
    fn payload_store_path(&self, py: Python<'_>) -> Option<String> {
        with_lock_py(py, &self.payloads, |s| {
            s.as_ref().map(|s| s.path.to_string_lossy().into_owned())
        })
    }

    /// The payload stored for leaf `index`, or `None` when no sidecar is
    /// enabled, the leaf was appended without one, or it was forgotten.
    /// A redacted leaf gets `None` even if a record for it is somehow in
    /// the file (0.5.0 could leave one there: security review 3, F7).
    fn payload<'py>(&self, py: Python<'py>, index: u64) -> PyResult<Option<Bound<'py, PyBytes>>> {
        let got = self.with_store_and_journal(py, |s, g| match s.as_ref() {
            Some(_) if g.as_ref().is_some_and(|j| is_redacted(j.log(), index)) => Ok(None),
            Some(store) => store
                .get(index)
                .map_err(|e| PyIOError::new_err(format!("payload sidecar: {e}"))),
            None => Ok(None),
        })?;
        Ok(got.map(|p| PyBytes::new(py, &p)))
    }
    fn root_hex(&self, py: Python<'_>) -> PyResult<String> {
        self.with_j(py, |j| Ok(j.log().root_hex()))
    }
    fn identity_pubkey_hex(&self, py: Python<'_>) -> PyResult<String> {
        self.with_j(py, |j| Ok(j.log().identity_pubkey_hex()))
    }
    fn identity_bytes<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyBytes>> {
        let seed = self.with_j(py, |j| Ok(j.log().identity_bytes()))?;
        Ok(PyBytes::new(py, &seed))
    }

    /// Sign a checkpoint over the current head. Returns JSON.
    fn checkpoint(&self, py: Python<'_>) -> PyResult<String> {
        self.with_j(py, |j| {
            serde_json::to_string(&j.log().checkpoint_self()).map_err(malformed_err)
        })
    }

    /// Sign a revocation of this log's identity key (SPEC §5) and return
    /// it as JSON. `as_of_ms` defaults to now. `as_of_index` (RFC-0005,
    /// experimental) also cuts off by position and needs
    /// `experimental=True`; `-1` means "this log's size now". Publish the
    /// result; verifiers apply it with `verify_dossier_json(...,
    /// revocations_json=...)` or `witness-log verify --revocations`.
    #[pyo3(signature = (reason, as_of_ms=None, as_of_index=None, experimental=false))]
    fn revoke_json(
        &self,
        py: Python<'_>,
        reason: &str,
        as_of_ms: Option<u64>,
        as_of_index: Option<i64>,
        experimental: bool,
    ) -> PyResult<String> {
        let as_of_index = match as_of_index {
            None => None,
            Some(_) if !experimental => {
                return Err(pyo3::exceptions::PyValueError::new_err(
                    "as_of_index is RFC-0005 and experimental; pass experimental=True to sign a v2 statement",
                ))
            }
            Some(n) if n >= -1 => Some(n),
            Some(n) => {
                return Err(pyo3::exceptions::PyValueError::new_err(format!(
                    "as_of_index must be a tree size (>= 0) or -1 for the current size, got {n}"
                )))
            }
        };
        self.with_j(py, |j| {
            // -1 is "this log's size now", read under the same lock.
            let index = as_of_index.map(|n| {
                if n == -1 {
                    j.log().tree_size()
                } else {
                    n as u64
                }
            });
            serde_json::to_string(&j.log().revoke(as_of_ms, index, reason)).map_err(malformed_err)
        })
    }

    /// Export a dossier of this log's own history, with key bindings
    /// populated correctly across restarts. Returns JSON.
    fn to_dossier_json(&self, py: Python<'_>) -> PyResult<String> {
        self.detached(py, |j| {
            let sth = j.log().checkpoint_self();
            let dossier = witness_log_network::Dossier::from_log(j.log(), sth);
            serde_json::to_string_pretty(&dossier).map_err(malformed_err)
        })
    }

    /// This log's canonical C2SP origin, `witness-log/<identity key hex>`.
    /// Witnesses with open enrollment accept it with no key exchange, and
    /// only cosignatures under it count toward a verdict.
    fn canonical_origin(&self, py: Python<'_>) -> PyResult<String> {
        let key = self.signing_key(py)?;
        Ok(witness_log_core::c2sp::canonical_origin(
            &key.verifying_key(),
        ))
    }

    /// POST body for `<witness>/add-checkpoint`. `old_size` is the size
    /// the witness last cosigned for this log (0 the first time; a 409
    /// reply's body tells you the right value).
    #[pyo3(signature = (old_size=0))]
    fn add_checkpoint_body(&self, py: Python<'_>, old_size: u64) -> PyResult<String> {
        self.detached(py, |j| add_checkpoint_body(j.log(), old_size))
    }

    /// Dossier JSON for the current head from witness 200 responses:
    /// a list of `(witness_pubkey_hex, response_body)`. Returns
    /// `(dossier_json, receipts_accepted)`; forged or mismatched
    /// cosignatures are dropped, never counted.
    fn dossier_from_responses(
        &self,
        py: Python<'_>,
        responses: Vec<(String, String)>,
    ) -> PyResult<(String, usize)> {
        self.detached(py, |j| dossier_from_responses(j.log(), responses))
    }

    /// `add_checkpoint_body` for the earlier head of `size` leaves.
    #[pyo3(signature = (size, old_size=0))]
    fn add_checkpoint_body_at(&self, py: Python<'_>, size: u64, old_size: u64) -> PyResult<String> {
        self.detached(py, |j| add_checkpoint_body_at(j.log(), size, old_size))
    }

    /// `dossier_from_responses` for the earlier head of `size` leaves.
    fn dossier_from_responses_at(
        &self,
        py: Python<'_>,
        size: u64,
        responses: Vec<(String, String)>,
    ) -> PyResult<(String, usize)> {
        self.detached(py, |j| dossier_from_responses_at(j.log(), size, responses))
    }

    /// Root of the first `size` leaves, hex, or `None` if the log is
    /// shorter.
    fn root_hex_at(&self, py: Python<'_>, size: u64) -> PyResult<Option<String>> {
        self.with_j(py, |j| Ok(j.log().root_at(size).map(hex::encode)))
    }

    /// `(tree_size, root_hex, proof)` proving the leaf at `index` is in the
    /// current tree. Verify offline with `witness_log.verify_inclusion`.
    fn inclusion_proof(
        &self,
        py: Python<'_>,
        index: u64,
    ) -> PyResult<Option<(u64, String, Vec<String>)>> {
        self.detached(py, |j| Ok(inclusion_proof_of(j.log(), index)))
    }

    /// RFC 6962 leaf hash of the leaf at `index`, hex.
    fn leaf_hash_hex(&self, py: Python<'_>, index: u64) -> PyResult<Option<String>> {
        self.with_j(py, |j| Ok(leaf_hash_of(j.log(), index)))
    }

    /// JSON array of every leaf, in SPEC.md canonical serde form (same
    /// as a dossier's `leaves`).
    fn leaves_json(&self, py: Python<'_>) -> PyResult<String> {
        self.detached(py, |j| {
            serde_json::to_string(j.log().leaves()).map_err(malformed_err)
        })
    }

    fn c2sp_checkpoint_text(&self, py: Python<'_>, origin: &str) -> PyResult<String> {
        self.with_j(py, |j| {
            j.log()
                .c2sp_checkpoint(origin)
                .note_text()
                .map_err(|e| MalformedError::new_err(e.to_string()))
        })
    }

    fn sign_c2sp_checkpoint(&self, py: Python<'_>, origin: &str) -> PyResult<String> {
        self.with_j(py, |j| {
            let key = ed25519_dalek::SigningKey::from_bytes(&j.log().identity_bytes());
            j.log()
                .c2sp_checkpoint(origin)
                .sign(&key)
                .and_then(|n| n.encode())
                .map_err(|e| MalformedError::new_err(e.to_string()))
        })
    }

    fn c2sp_vkey(&self, py: Python<'_>, origin: &str) -> PyResult<String> {
        let key = self.signing_key(py)?;
        Ok(witness_log_core::c2sp::bridge::log_vkey(origin, &key.verifying_key()).encode())
    }
    /// Sync and release the journal and its lock. After this every other
    /// method raises; reopen with `witness_log.open(path)`. Needed when
    /// something else (a decorated function's closure, a REPL variable)
    /// still references this object, since the lock is held until the
    /// object is dropped.
    fn close(&self, py: Python<'_>) -> PyResult<()> {
        py.detach(|| {
            let mut g = lock(&self.inner);
            if let Some(j) = g.as_mut() {
                j.sync().map_err(|e| e.to_string())?;
            }
            *g = None;
            Ok(())
        })
        .map_err(PyIOError::new_err::<String>)
    }

    /// True once `close()` has been called.
    fn is_closed(&self, py: Python<'_>) -> bool {
        with_lock_py(py, &self.inner, |g| g.is_none())
    }

    fn __enter__(slf: pyo3::PyRef<'_, Self>) -> pyo3::PyRef<'_, Self> {
        slf
    }

    fn __exit__(
        &self,
        _t: Option<Bound<'_, pyo3::PyAny>>,
        _v: Option<Bound<'_, pyo3::PyAny>>,
        _tb: Option<Bound<'_, pyo3::PyAny>>,
    ) -> PyResult<bool> {
        Python::attach(|py| self.close(py))?;
        Ok(false)
    }
}

#[pyclass(name = "WitnessService")]
struct PyWitnessService {
    /// Taken only inside `py.detach`, with the GIL released, and dropped
    /// before the GIL is retaken (see `with_lock_py`): `handle` holds it
    /// across an fsync, so a thread waiting for it must not hold the GIL.
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
    witness_pubkey_hex: Option<&str>,
) -> std::io::Result<()> {
    use std::io::Write;
    let mut state = svc.export_state();
    if let Some(k) = witness_pubkey_hex {
        state = state.bind(k);
    }
    let json = serde_json::to_vec_pretty(&state).map_err(std::io::Error::other)?;
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
                let me = hex::encode(self.signing_key.verifying_key().to_bytes());
                if persist_witness_state(path, &svc, Some(&me)).is_err() {
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
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
        let our_pubkey = hex::encode(signing_key.verifying_key().to_bytes());
        let svc = match &state_path {
            Some(p) if std::path::Path::new(p).exists() => {
                let s =
                    std::fs::read_to_string(p).map_err(|e| PyIOError::new_err(e.to_string()))?;
                let st: witness_log_network::tlog_witness::WitnessState =
                    serde_json::from_str(&s).map_err(malformed_err)?;
                // A state file is this key's memory; another key must not
                // inherit it (found by the 0.3.1 release test).
                st.check_bound_to(&our_pubkey).map_err(malformed_err)?;
                witness_log_network::tlog_witness::WitnessService::from_state(&st)
                    .map_err(malformed_err)?
            }
            _ => witness_log_network::tlog_witness::WitnessService::new(),
        };
        Ok(Self {
            inner: Mutex::new(svc),
            key_name: key_name.to_string(),
            signing_key,
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
            None,
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
    fn add_log(&self, py: Python<'_>, origin: &str, log_vkey: &str) -> PyResult<bool> {
        let vk = witness_log_core::c2sp::VerifierKey::parse(log_vkey)
            .map_err(|e| MalformedError::new_err(e.to_string()))?;
        // `handle` holds `inner` across an fsync with the GIL released, and
        // persisting here fsyncs too: wait for `inner`, and hold it, only
        // with the GIL released. 0.5.0 waited for it holding the GIL, which
        // deadlocked against `log_count` (security review 3, F3).
        py.detach(|| {
            let mut svc = lock(&self.inner);
            if !svc.add_log(origin, vk) {
                return Ok(false);
            }
            if let Some(p) = &self.state_path {
                let me = hex::encode(self.signing_key.verifying_key().to_bytes());
                if let Err(e) = persist_witness_state(p, &svc, Some(&me)) {
                    svc.remove_log(origin);
                    return Err(io_err(e));
                }
            }
            Ok(true)
        })
    }

    /// Handle an add-checkpoint POST body. Returns `(status, body)`:
    /// 200 cosignature line; 400 malformed/stale; 403 bad signature;
    /// 404 unknown log; 409 the witness's size (send it with
    /// Content-Type `text/x.tlog.size`); 422 refused fork. Prefer
    /// `handle_add_checkpoint_http`, which also gives the content type.
    #[pyo3(signature = (body, now_unix_seconds=None))]
    fn handle_add_checkpoint(
        &self,
        py: Python<'_>,
        body: &str,
        now_unix_seconds: Option<u64>,
    ) -> (u16, String) {
        let now = now_unix_seconds.unwrap_or_else(now_unix_s);
        let (st, _, b) = py.detach(|| self.handle(body, now));
        (st, b)
    }

    /// Like `handle_add_checkpoint`, returning `(status, content_type, body)`.
    #[pyo3(signature = (body, now_unix_seconds=None))]
    fn handle_add_checkpoint_http(
        &self,
        py: Python<'_>,
        body: &str,
        now_unix_seconds: Option<u64>,
    ) -> (u16, &'static str, String) {
        // Persisting the cosigned head fsyncs: release the GIL so an
        // agent-run witness keeps serving its other threads meanwhile.
        // `handle` takes `inner` (and `evidence_recorded`) only in here.
        let now = now_unix_seconds.unwrap_or_else(now_unix_s);
        py.detach(|| self.handle(body, now))
    }

    /// Number of logs this witness tracks.
    fn log_count(&self, py: Python<'_>) -> usize {
        // Every holder of `inner` holds it with the GIL released; wait for
        // it the same way, and drop it before the GIL is retaken.
        py.detach(|| lock(&self.inner).log_count())
    }
}

/// `{"witnesses": [...]}` or a bare array of entries, the two shapes
/// `verify_dossier_json` and the CLI accept. The selection functions
/// accepted only the object form before 0.3.6.
fn parse_directory_json(s: &str) -> PyResult<witness_log_network::WitnessDirectory> {
    serde_json::from_str::<witness_log_network::WitnessDirectory>(s)
        .or_else(|first| {
            serde_json::from_str::<Vec<witness_log_network::WitnessEntry>>(s)
                .map(|witnesses| witness_log_network::WitnessDirectory { witnesses })
                .map_err(|_| first)
        })
        .map_err(malformed_err)
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
    let dir = parse_directory_json(directory_json)?;
    let picked: Vec<&witness_log_network::WitnessEntry> =
        witness_log_network::select_diverse_witnesses(
            &dir,
            subject_pubkey_hex,
            want,
            include_project_operated,
        );
    serde_json::to_string(&picked).map_err(malformed_err)
}

/// Like `select_diverse_witnesses`, then fill up to `want` round-robin
/// across operators: the set to *submit* to when availability matters.
/// Returns a JSON array of directory entries.
#[pyfunction]
#[pyo3(signature = (directory_json, subject_pubkey_hex, want, include_project_operated=false))]
fn select_witnesses(
    directory_json: &str,
    subject_pubkey_hex: &str,
    want: usize,
    include_project_operated: bool,
) -> PyResult<String> {
    let dir = parse_directory_json(directory_json)?;
    let picked = witness_log_network::select_witnesses(
        &dir,
        subject_pubkey_hex,
        want,
        include_project_operated,
    );
    serde_json::to_string(&picked).map_err(malformed_err)
}

/// Entries are the verifier's trust input. 0.3.5 built one from any
/// strings: a pubkey of "zz" (an entry that silently never matches a
/// receipt) and an empty `operator_org` (scored as an operator of its
/// own) both went through. Refused here; the verifier is unchanged.
fn check_entry_fields(
    name: &str,
    operator_org: Option<&str>,
    url: &str,
    pubkey_hex: &str,
) -> PyResult<()> {
    let bad = |m: String| Err(MalformedError::new_err(m));
    if name.trim().is_empty() {
        return bad("name must be non-empty".into());
    }
    if let Some(org) = operator_org {
        if org.trim().is_empty() {
            return bad(
                "operator_org must be non-empty: verifiers count independent operators by it"
                    .into(),
            );
        }
    }
    if !(url.starts_with("http://") || url.starts_with("https://")) {
        return bad(format!(
            "url must start with http:// or https://, got {url:?}"
        ));
    }
    if pubkey_hex.len() != 64 || !pubkey_hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return bad(format!(
            "pubkey_hex must be a 32-byte Ed25519 key as 64 hex characters, got {pubkey_hex:?}"
        ));
    }
    Ok(())
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
    check_entry_fields(name, Some(operator_org), url, pubkey_hex)?;
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
    check_entry_fields(name, None, url, pubkey_hex)?;
    let e = witness_log_network::WitnessEntry::project_operated(
        name,
        url,
        pubkey_hex,
        compute_provider,
    );
    serde_json::to_string(&e).map_err(malformed_err)
}

#[pymodule]
fn _core(m: &Bound<'_, PyModule>) -> PyResult<()> {
    let py = m.py();
    m.add_class::<PyWitnessLog>()?;
    m.add_class::<PyJournaledLog>()?;
    m.add_class::<PyWitnessService>()?;
    m.add_function(pyo3::wrap_pyfunction!(verify_dossier_json, m)?)?;
    m.add_function(pyo3::wrap_pyfunction!(verify_inclusion, m)?)?;
    m.add_function(pyo3::wrap_pyfunction!(payload_hash, m)?)?;
    m.add_function(pyo3::wrap_pyfunction!(verify_handoff_binding, m)?)?;
    m.add_function(pyo3::wrap_pyfunction!(handoff_binding_error, m)?)?;
    m.add_function(pyo3::wrap_pyfunction!(authorization_binding_error, m)?)?;
    m.add_function(pyo3::wrap_pyfunction!(verify_authorization_binding, m)?)?;
    m.add_function(pyo3::wrap_pyfunction!(select_diverse_witnesses, m)?)?;
    m.add_function(pyo3::wrap_pyfunction!(select_witnesses, m)?)?;
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
