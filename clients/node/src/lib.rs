//! Node.js bindings for witness-log, via napi-rs. Published to npm as
//! `@witness-log/node`.
//!
//! Deliberately thin, like the Python binding: this crate exposes
//! `witness_log_core::journal::JournaledLog` and the network crate's
//! verifier with JSON at the boundary, so serialization stays governed by
//! the core's `serde` derives (and therefore spec/SPEC.md) and nothing is
//! reimplemented here. The TypeScript layer in `src/index.ts` adds the
//! conveniences (string payloads, options objects, `submit` over `fetch`).
//!
//! Two things live here that the core does not offer as public API, both
//! implemented against the files the core already writes:
//!
//! * `salt_hex(index)` reads the `<journal>.salts` sidecar the core keeps
//!   (one JSON record per leaf), so a holder of the journal can disclose
//!   one leaf's salt and let anyone check a payload against the committed
//!   `payload_hash` (SPEC §8).
//! * An optional `<journal>.payloads` sidecar (0600, one JSON record per
//!   leaf) that keeps the plaintext payloads next to the journal when the
//!   caller asks for it, so `disclose(index)` can return payload and salt
//!   together. `forget(index)` removes the payload record as well as the
//!   salt.

#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]

use napi::bindgen_prelude::*;
use napi_derive::napi;
use std::collections::HashMap;
use std::io::Write;
use std::sync::{Mutex, MutexGuard};
use witness_log_core::identity::IdentityKeypair;
use witness_log_core::journal::JournaledLog as CoreJournal;
use witness_log_core::log::WitnessLog as CoreLog;

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

fn fail<E: std::fmt::Display>(e: E) -> Error {
    Error::new(Status::GenericFailure, e.to_string())
}

fn invalid<E: std::fmt::Display>(e: E) -> Error {
    Error::new(Status::InvalidArg, e.to_string())
}

fn parse_seed(seed: &[u8]) -> Result<IdentityKeypair> {
    let seed: [u8; 32] = seed
        .try_into()
        .map_err(|_| invalid("identitySeed must be exactly 32 bytes"))?;
    Ok(IdentityKeypair::from_bytes(&seed))
}

fn to_index(i: i64) -> Result<u64> {
    u64::try_from(i).map_err(|_| invalid(format!("index must be non-negative, got {i}")))
}

fn to_i64(n: u64) -> i64 {
    i64::try_from(n).unwrap_or(i64::MAX)
}

/// One stored plaintext payload: `{"i": <index>, "p": "<hex>"}`.
#[derive(serde::Serialize, serde::Deserialize)]
struct PayloadRecord {
    i: u64,
    p: String,
}

/// `{"i": <index>, "s": "<hex>"}`, the core's salt sidecar record.
#[derive(serde::Deserialize)]
struct SaltRecord {
    i: u64,
    s: String,
}

fn open_0600(path: &str, append: bool) -> std::io::Result<std::fs::File> {
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true);
    if append {
        opts.append(true);
    } else {
        opts.truncate(true);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    opts.open(path)
}

/// Plaintext payloads next to the journal, when the caller opted in.
struct PayloadStore {
    path: String,
    payloads: HashMap<u64, Vec<u8>>,
}

impl PayloadStore {
    fn open(path: String) -> std::io::Result<Self> {
        let mut payloads = HashMap::new();
        match std::fs::read_to_string(&path) {
            Ok(text) => {
                for line in text.lines() {
                    let line = line.trim();
                    if line.is_empty() {
                        continue;
                    }
                    // A torn last line (crash mid-write) is dropped; the
                    // leaf itself is still in the journal, only its copy
                    // of the plaintext is lost.
                    if let Ok(r) = serde_json::from_str::<PayloadRecord>(line) {
                        if let Ok(p) = hex::decode(&r.p) {
                            payloads.insert(r.i, p);
                        }
                    }
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
        Ok(Self { path, payloads })
    }

    fn put(&mut self, index: u64, payload: &[u8]) -> std::io::Result<()> {
        let line = serde_json::to_string(&PayloadRecord {
            i: index,
            p: hex::encode(payload),
        })
        .map_err(std::io::Error::other)?;
        let mut f = open_0600(&self.path, true)?;
        writeln!(f, "{line}")?;
        self.payloads.insert(index, payload.to_vec());
        Ok(())
    }

    /// Remove one payload and rewrite the file without it (temp file,
    /// fsync, rename), so the plaintext is gone from the live file.
    fn remove(&mut self, index: u64) -> std::io::Result<()> {
        if self.payloads.remove(&index).is_none() {
            return Ok(());
        }
        let tmp = format!("{}.tmp-{}", self.path, std::process::id());
        {
            let mut f = open_0600(&tmp, false)?;
            let mut keys: Vec<&u64> = self.payloads.keys().collect();
            keys.sort();
            for k in keys {
                if let Some(p) = self.payloads.get(k) {
                    let line = serde_json::to_string(&PayloadRecord {
                        i: *k,
                        p: hex::encode(p),
                    })
                    .map_err(std::io::Error::other)?;
                    writeln!(f, "{line}")?;
                }
            }
            f.sync_all()?;
        }
        std::fs::rename(&tmp, &self.path)
    }

    fn get(&self, index: u64) -> Option<&Vec<u8>> {
        self.payloads.get(&index)
    }
}

/// Read one salt from the core's `<journal>.salts` sidecar. `None` when
/// the leaf has no live salt (forgotten, never had a payload, or the
/// sidecar is absent).
fn read_salt(journal_path: &str, index: u64) -> Result<Option<String>> {
    let path = CoreJournal::salts_path(journal_path);
    let text = match std::fs::read_to_string(&path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(fail(e)),
    };
    let mut found = None;
    for line in text.lines() {
        if let Ok(r) = serde_json::from_str::<SaltRecord>(line.trim()) {
            if r.i == index {
                found = Some(r.s);
            }
        }
    }
    Ok(found)
}

/// Result of `inclusionProof(index)`.
#[napi(object)]
pub struct InclusionProof {
    pub tree_size: i64,
    pub root_hex: String,
    pub proof: Vec<String>,
}

/// One witness's HTTP 200 body, keyed by the witness public key you
/// expected it from (hex).
#[napi(object)]
pub struct WitnessResponse {
    pub witness_pubkey: String,
    pub body: String,
}

/// Result of `dossierFromResponsesAt`.
#[napi(object)]
pub struct DossierFromResponses {
    pub dossier_json: String,
    pub receipts_accepted: u32,
}

/// What `disclose(index)` returns: the committed hash, the salt the log
/// held for it, and the payload when this journal stores payloads.
#[napi(object)]
pub struct Disclosure {
    pub index: i64,
    pub payload_hash: String,
    pub salt_hex: Option<String>,
    pub payload: Option<Buffer>,
}

/// A `JournaledLog` from witness-log-core: every append lands in an
/// append-only journal at `path`, salts in `<path>.salts`.
#[napi]
pub struct NativeLog {
    inner: Mutex<Option<CoreJournal>>,
    path: String,
    payloads: Mutex<Option<PayloadStore>>,
    dropped_trailing_lines: u32,
}

struct Open<'a>(MutexGuard<'a, Option<CoreJournal>>);
impl std::ops::Deref for Open<'_> {
    type Target = CoreJournal;
    fn deref(&self) -> &Self::Target {
        // `NativeLog::j` only constructs this after the `None` check.
        match self.0.as_ref() {
            Some(j) => j,
            None => unreachable!("checked open before constructing"),
        }
    }
}
impl std::ops::DerefMut for Open<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        match self.0.as_mut() {
            Some(j) => j,
            None => unreachable!("checked open before constructing"),
        }
    }
}

impl NativeLog {
    fn wrap(inner: CoreJournal, path: &str, dropped: usize, store_payloads: bool) -> Result<Self> {
        let payloads = if store_payloads {
            Some(PayloadStore::open(format!("{path}.payloads")).map_err(fail)?)
        } else {
            None
        };
        Ok(Self {
            inner: Mutex::new(Some(inner)),
            path: path.to_string(),
            payloads: Mutex::new(payloads),
            dropped_trailing_lines: u32::try_from(dropped).unwrap_or(u32::MAX),
        })
    }

    fn j(&self) -> Result<Open<'_>> {
        let g = lock(&self.inner);
        if g.is_none() {
            return Err(fail("this log is closed; open it again with openLog(path)"));
        }
        Ok(Open(g))
    }

    fn with_log<T>(&self, f: impl FnOnce(&CoreLog) -> T) -> Result<T> {
        Ok(f(self.j()?.log()))
    }

    fn record_payload(&self, index: u64, payload: &[u8]) -> Result<()> {
        if let Some(store) = lock(&self.payloads).as_mut() {
            store.put(index, payload).map_err(fail)?;
        }
        Ok(())
    }
}

#[napi]
impl NativeLog {
    /// Create a journal for an identity you hold (32-byte seed). The seed
    /// is stored in the journal header (0600).
    #[napi(factory)]
    pub fn create(path: String, identity_seed: &[u8], store_payloads: bool) -> Result<Self> {
        let identity = parse_seed(identity_seed)?;
        let inner = CoreJournal::create(&path, identity).map_err(fail)?;
        Self::wrap(inner, &path, 0, store_payloads)
    }

    /// Like `create`, but the seed is never written: the header holds
    /// only the public key and every later open needs the seed.
    #[napi(factory)]
    pub fn create_sealed(path: String, identity_seed: &[u8], store_payloads: bool) -> Result<Self> {
        let identity = parse_seed(identity_seed)?;
        let inner = CoreJournal::create_sealed(&path, identity).map_err(fail)?;
        Self::wrap(inner, &path, 0, store_payloads)
    }

    /// Create a journal with a fresh identity stored in its header.
    #[napi(factory)]
    pub fn create_ephemeral(path: String, store_payloads: bool) -> Result<Self> {
        let inner = CoreJournal::create_ephemeral(&path).map_err(fail)?;
        Self::wrap(inner, &path, 0, store_payloads)
    }

    /// Resume an existing journal. `droppedTrailingLines` reports a torn
    /// last line healed on the way in.
    #[napi(factory)]
    pub fn resume(path: String, store_payloads: bool) -> Result<Self> {
        let (inner, report) = CoreJournal::resume(&path).map_err(fail)?;
        Self::wrap(inner, &path, report.dropped_trailing_lines, store_payloads)
    }

    /// Resume a sealed journal (or an unsealed one; the seed must match).
    #[napi(factory)]
    pub fn resume_with_identity(
        path: String,
        identity_seed: &[u8],
        store_payloads: bool,
    ) -> Result<Self> {
        let seed: [u8; 32] = identity_seed
            .try_into()
            .map_err(|_| invalid("identitySeed must be exactly 32 bytes"))?;
        let (inner, report) = CoreJournal::resume_with_identity(&path, &seed).map_err(fail)?;
        Self::wrap(inner, &path, report.dropped_trailing_lines, store_payloads)
    }

    #[napi(getter)]
    pub fn path(&self) -> String {
        self.path.clone()
    }

    #[napi(getter)]
    pub fn dropped_trailing_lines(&self) -> u32 {
        self.dropped_trailing_lines
    }

    #[napi(getter)]
    pub fn stores_payloads(&self) -> bool {
        lock(&self.payloads).is_some()
    }

    #[napi]
    pub fn append_intent(&self, payload: &[u8]) -> Result<i64> {
        let i = self.j()?.append_intent(payload).map_err(fail)?;
        self.record_payload(i, payload)?;
        Ok(to_i64(i))
    }

    #[napi]
    pub fn append_result(&self, payload: &[u8]) -> Result<i64> {
        let i = self.j()?.append_result(payload).map_err(fail)?;
        self.record_payload(i, payload)?;
        Ok(to_i64(i))
    }

    #[napi]
    pub fn append_memory(&self, payload: &[u8]) -> Result<i64> {
        let i = self.j()?.append_memory(payload).map_err(fail)?;
        self.record_payload(i, payload)?;
        Ok(to_i64(i))
    }

    /// SPEC §3.1, the sending side. `counterpartyPubkey` is the other
    /// agent's identity key (64 hex).
    #[napi]
    pub fn append_handoff_sent(&self, state: &[u8], counterparty_pubkey: String) -> Result<i64> {
        let i = self
            .j()?
            .append_handoff_sent(state, &counterparty_pubkey)
            .map_err(fail)?;
        self.record_payload(i, state)?;
        Ok(to_i64(i))
    }

    /// SPEC §3.1, the receiving side.
    #[napi]
    pub fn append_handoff_received(
        &self,
        state: &[u8],
        counterparty_pubkey: String,
    ) -> Result<i64> {
        let i = self
            .j()?
            .append_handoff_received(state, &counterparty_pubkey)
            .map_err(fail)?;
        self.record_payload(i, state)?;
        Ok(to_i64(i))
    }

    /// SPEC §3.2. `kind` is one of granted_by_me, granted_to_me,
    /// revoked_by_me, revoked_to_me, scope_changed_by_me, scope_changed_to_me.
    #[napi]
    pub fn append_authorization_event(
        &self,
        kind: String,
        scope: &[u8],
        counterparty_pubkey: String,
    ) -> Result<i64> {
        use witness_log_core::leaf::AuthorizationEventKind as K;
        let kind = match kind.as_str() {
            "granted_by_me" => K::GrantedByMe,
            "granted_to_me" => K::GrantedToMe,
            "revoked_by_me" => K::RevokedByMe,
            "revoked_to_me" => K::RevokedToMe,
            "scope_changed_by_me" => K::ScopeChangedByMe,
            "scope_changed_to_me" => K::ScopeChangedToMe,
            other => {
                return Err(invalid(format!(
                    "unknown authorization event kind {other:?}; expected granted_by_me, granted_to_me, revoked_by_me, revoked_to_me, scope_changed_by_me or scope_changed_to_me"
                )))
            }
        };
        let i = self
            .j()?
            .append_authorization_event(kind, scope, &counterparty_pubkey)
            .map_err(fail)?;
        self.record_payload(i, scope)?;
        Ok(to_i64(i))
    }

    /// SPEC §3.3. The proof JSON is hashed into the leaf.
    #[napi]
    pub fn append_external_anchor(
        &self,
        anchor_url: String,
        anchor_proof_json: String,
    ) -> Result<i64> {
        let i = self
            .j()?
            .append_external_anchor(&anchor_url, &anchor_proof_json)
            .map_err(fail)?;
        Ok(to_i64(i))
    }

    /// Right to be forgotten: erase the salt (and the stored payload, if
    /// any) of leaf `index`. True if something was erased.
    #[napi]
    pub fn forget(&self, index: i64) -> Result<bool> {
        let index = to_index(index)?;
        let erased = self.j()?.forget(index).map_err(fail)?;
        if let Some(store) = lock(&self.payloads).as_mut() {
            store.remove(index).map_err(fail)?;
        }
        Ok(erased)
    }

    #[napi]
    pub fn can_forget(&self, index: i64) -> Result<bool> {
        let index = to_index(index)?;
        Ok(self.j()?.can_forget(index))
    }

    /// The salt the log holds for leaf `index` (hex), or null if it has
    /// been forgotten or the leaf never had a payload.
    #[napi]
    pub fn salt_hex(&self, index: i64) -> Result<Option<String>> {
        let index = to_index(index)?;
        if !self.j()?.can_forget(index) {
            return Ok(None);
        }
        read_salt(&self.path, index)
    }

    /// The stored plaintext payload of leaf `index`, when this journal
    /// stores payloads and the leaf has not been forgotten.
    #[napi]
    pub fn payload(&self, index: i64) -> Result<Option<Buffer>> {
        let index = to_index(index)?;
        Ok(lock(&self.payloads)
            .as_ref()
            .and_then(|s| s.get(index))
            .map(|p| Buffer::from(p.clone())))
    }

    /// Everything needed to prove what leaf `index` said: the committed
    /// hash, the salt, and the payload when stored. Null if there is no
    /// leaf at `index`.
    #[napi]
    pub fn disclose(&self, index: i64) -> Result<Option<Disclosure>> {
        let idx = to_index(index)?;
        let payload_hash = match self.with_log(|l| {
            l.leaves()
                .get(usize::try_from(idx).unwrap_or(usize::MAX))
                .map(|leaf| leaf.payload_hash.clone())
        })? {
            Some(h) => h,
            None => return Ok(None),
        };
        let salt_hex = self.salt_hex(index)?;
        let payload = self.payload(index)?;
        Ok(Some(Disclosure {
            index,
            payload_hash,
            salt_hex,
            payload,
        }))
    }

    #[napi]
    pub fn sync(&self) -> Result<()> {
        self.j()?.sync().map_err(fail)
    }

    #[napi]
    pub fn tree_size(&self) -> Result<i64> {
        self.with_log(|l| to_i64(l.tree_size()))
    }

    #[napi]
    pub fn root_hex(&self) -> Result<String> {
        self.with_log(|l| l.root_hex())
    }

    #[napi]
    pub fn identity_pubkey_hex(&self) -> Result<String> {
        self.with_log(|l| l.identity_pubkey_hex())
    }

    /// The 32-byte identity seed. Private key material.
    #[napi]
    pub fn identity_bytes(&self) -> Result<Buffer> {
        self.with_log(|l| Buffer::from(l.identity_bytes().to_vec()))
    }

    /// `witness-log/<identity hex>` (SPEC §9.3).
    #[napi]
    pub fn canonical_origin(&self) -> Result<String> {
        self.with_log(|l| {
            let key = ed25519_dalek::SigningKey::from_bytes(&l.identity_bytes());
            witness_log_core::c2sp::canonical_origin(&key.verifying_key())
        })
    }

    /// Signed checkpoint over the current head, as JSON (SPEC §6).
    #[napi]
    pub fn checkpoint_json(&self) -> Result<String> {
        self.with_log(|l| serde_json::to_string(&l.checkpoint_self()))?
            .map_err(fail)
    }

    /// The dossier for the current head (SPEC §9), with every key
    /// binding, as JSON. No receipts: get those with `submit`.
    #[napi]
    pub fn to_dossier_json(&self) -> Result<String> {
        self.with_log(|l| {
            let d = witness_log_network::Dossier::from_log(l, l.checkpoint_self());
            serde_json::to_string_pretty(&d)
        })?
        .map_err(fail)
    }

    /// Every leaf as JSON (the dossier's `leaves`).
    #[napi]
    pub fn leaves_json(&self) -> Result<String> {
        self.with_log(|l| serde_json::to_string(l.leaves()))?
            .map_err(fail)
    }

    /// Root of the first `size` leaves (hex), or null if the log is shorter.
    #[napi]
    pub fn root_hex_at(&self, size: i64) -> Result<Option<String>> {
        let size = to_index(size)?;
        self.with_log(|l| l.root_at(size).map(hex::encode))
    }

    /// Proof that leaf `index` is in the current tree.
    #[napi]
    pub fn inclusion_proof(&self, index: i64) -> Result<Option<InclusionProof>> {
        let index = to_index(index)?;
        self.with_log(|l| {
            l.inclusion_proof(index).map(|proof| InclusionProof {
                tree_size: to_i64(l.tree_size()),
                root_hex: l.root_hex(),
                proof: proof.iter().map(hex::encode).collect(),
            })
        })
    }

    /// RFC 6962 leaf hash of leaf `index`, hex.
    #[napi]
    pub fn leaf_hash_hex(&self, index: i64) -> Result<Option<String>> {
        let index = to_index(index)?;
        self.with_log(|l| {
            l.leaves()
                .get(usize::try_from(index).unwrap_or(usize::MAX))
                .map(|leaf| {
                    hex::encode(witness_log_core::merkle::leaf_hash(&leaf.canonical_bytes()))
                })
        })
    }

    /// POST body for `<witness>/add-checkpoint` for the head of `size`
    /// leaves, with a consistency proof from `oldSize` (0 the first time;
    /// a 409 body tells you the witness's size).
    #[napi]
    pub fn add_checkpoint_body_at(&self, size: i64, old_size: i64) -> Result<String> {
        let size = to_index(size)?;
        let old_size = to_index(old_size)?;
        let log = self.j()?;
        add_checkpoint_body_at(log.log(), size, old_size)
    }

    /// Dossier for the head of `size` leaves from witness 200 bodies. Only
    /// cosignatures that verify under the named key over that head become
    /// receipts; the rest are dropped, never counted.
    #[napi]
    pub fn dossier_from_responses_at(
        &self,
        size: i64,
        responses: Vec<WitnessResponse>,
    ) -> Result<DossierFromResponses> {
        let size = to_index(size)?;
        let log = self.j()?;
        dossier_from_responses_at(log.log(), size, responses)
    }

    /// Sync and release the journal and its lock.
    #[napi]
    pub fn close(&self) -> Result<()> {
        let mut g = lock(&self.inner);
        if let Some(j) = g.as_mut() {
            j.sync().map_err(fail)?;
        }
        *g = None;
        Ok(())
    }

    #[napi]
    pub fn is_closed(&self) -> bool {
        lock(&self.inner).is_none()
    }
}

fn add_checkpoint_body_at(log: &CoreLog, size: u64, old_size: u64) -> Result<String> {
    let key = ed25519_dalek::SigningKey::from_bytes(&log.identity_bytes());
    let origin = witness_log_core::c2sp::canonical_origin(&key.verifying_key());
    let current = log.tree_size();
    if size > current {
        return Err(invalid(format!(
            "size {size} exceeds this log's size {current}"
        )));
    }
    if old_size > size {
        return Err(invalid(format!("oldSize {old_size} exceeds size {size}")));
    }
    let proof = if old_size == 0 || old_size == size {
        vec![]
    } else {
        log.consistency_proof_between(old_size, size)
            .ok_or_else(|| fail("no consistency proof for that size"))?
    };
    let note = log
        .c2sp_checkpoint_at(&origin, size)
        .ok_or_else(|| fail("no head at that size"))?
        .sign(&key)
        .map_err(fail)?;
    witness_log_network::tlog_witness::AddCheckpointRequest {
        old_size,
        consistency_proof: proof,
        checkpoint_note: note,
    }
    .to_http_body()
    .map_err(fail)
}

fn dossier_from_responses_at(
    log: &CoreLog,
    size: u64,
    responses: Vec<WitnessResponse>,
) -> Result<DossierFromResponses> {
    use witness_log_core::c2sp::{Cosignature, NoteSignature, VerifierKey};
    let key = ed25519_dalek::SigningKey::from_bytes(&log.identity_bytes());
    let origin = witness_log_core::c2sp::canonical_origin(&key.verifying_key());
    let cp = log
        .c2sp_checkpoint_at(&origin, size)
        .ok_or_else(|| invalid(format!("no head at size {size}")))?;
    let native = log
        .checkpoint_at(&key, size)
        .ok_or_else(|| invalid(format!("no head at size {size}")))?;
    let mut receipts = Vec::new();
    for r in responses {
        let Some(wvk) = hex::decode(r.witness_pubkey.trim())
            .ok()
            .and_then(|b| <[u8; 32]>::try_from(b).ok())
            .and_then(|b| ed25519_dalek::VerifyingKey::from_bytes(&b).ok())
        else {
            continue;
        };
        for line in r.body.lines().filter(|l| !l.is_empty()) {
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
    dossier
        .leaves
        .truncate(usize::try_from(size).unwrap_or(usize::MAX));
    Ok(DossierFromResponses {
        dossier_json: serde_json::to_string_pretty(&dossier).map_err(fail)?,
        receipts_accepted: u32::try_from(n).unwrap_or(u32::MAX),
    })
}

/// Options for `verifyDossierJson`.
#[napi(object)]
#[derive(Default)]
pub struct VerifyOptions {
    /// The identity you expect (64 hex), obtained out of band.
    pub identity: Option<String>,
    /// A witness directory YOU trust, as JSON (`{"witnesses": [...]}` or a bare array).
    pub directory_json: Option<String>,
    /// Receipt-count gate as a fraction of the directory. Default 0.66.
    pub threshold: Option<f64>,
    /// Receipt-count gate as an absolute count; replaces `threshold`.
    pub min_witnesses: Option<u32>,
    /// Revocations known out of band: one statement or a JSON array (SPEC §5).
    pub revocations_json: Option<String>,
    /// Heads already trusted for this identity, as `"<size>:<root hex>"`;
    /// one the dossier does not reproduce makes the verdict DIVERGED
    /// (RFC-0002).
    pub known_heads: Option<Vec<String>>,
    /// Witness equivocation proofs as a JSON array (bare proofs or
    /// `{"kind": "equivocation", "proof": {...}}`); one that verifies for
    /// this identity makes the verdict DIVERGED.
    pub evidence_json: Option<String>,
    /// The organisation that operates this log; witnesses with that
    /// `operator_org` never count as independent operators.
    pub subject_org: Option<String>,
    /// RFC-0001, EXPERIMENTAL: count the cosigners of a fleet checkpoint
    /// that includes this dossier's checkpoint (needs `subject_org`).
    /// Default false.
    pub accept_fleet_anchor: Option<bool>,
}

fn parse_directory(s: &str) -> Result<witness_log_network::WitnessDirectory> {
    serde_json::from_str::<witness_log_network::WitnessDirectory>(s)
        .or_else(|first| {
            serde_json::from_str::<Vec<witness_log_network::WitnessEntry>>(s)
                .map(|witnesses| witness_log_network::WitnessDirectory { witnesses })
                .map_err(|_| first)
        })
        .map_err(invalid)
}

/// The reference verifier (witness-log-network `Dossier::verify`) over a
/// dossier JSON string. Returns the report as JSON: the same object
/// `witness-log verify --json` prints under `report`, with `verdict` one
/// of witnessed, consistent_unwitnessed, unanchored, diverged, invalid.
#[napi]
pub fn verify_dossier_json(dossier_json: String, options: Option<VerifyOptions>) -> Result<String> {
    let o = options.unwrap_or_default();
    let threshold = o.threshold.unwrap_or(0.66);
    if !(0.0..=1.0).contains(&threshold) {
        return Err(invalid(format!(
            "threshold must be between 0 and 1, got {threshold}"
        )));
    }
    if o.min_witnesses == Some(0) {
        return Err(invalid("minWitnesses must be at least 1"));
    }
    if let Some(id) = &o.identity {
        if id.len() != 64 || !id.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(invalid(
                "identity must be a 32-byte Ed25519 public key as 64 hex characters",
            ));
        }
    }
    let dossier: witness_log_network::Dossier =
        serde_json::from_str(&dossier_json).map_err(invalid)?;
    let trusted = match &o.directory_json {
        Some(s) => Some(parse_directory(s)?),
        None => None,
    };
    let revocations: Vec<witness_log_core::identity::RevocationStatement> =
        match &o.revocations_json {
            None => Vec::new(),
            Some(s) if s.trim_start().starts_with('{') => {
                vec![serde_json::from_str(s).map_err(invalid)?]
            }
            Some(s) => serde_json::from_str(s).map_err(invalid)?,
        };
    let known_heads = o
        .known_heads
        .iter()
        .flatten()
        .map(|h| {
            h.parse::<witness_log_network::KnownHead>()
                .map_err(|e| invalid(format!("known head {h:?}: {e}")))
        })
        .collect::<Result<Vec<_>>>()?;
    let evidence = match &o.evidence_json {
        None => Vec::new(),
        Some(s) => serde_json::from_str::<Vec<serde_json::Value>>(s)
            .map_err(invalid)?
            .into_iter()
            .map(|v| {
                let proof = v.get("proof").cloned().unwrap_or(v);
                serde_json::from_value::<witness_log_network::tlog_witness::EquivocationProof>(
                    proof,
                )
                .map_err(|e| invalid(format!("not an equivocation proof: {e}")))
            })
            .collect::<Result<Vec<_>>>()?,
    };
    let ctx = witness_log_network::VerifyContext {
        expected_identity_pubkey: o.identity.as_deref(),
        trusted_directory: trusted.as_ref(),
        min_receipts: o.min_witnesses.map(|n| n as usize),
        revocations: &revocations,
        known_heads: &known_heads,
        evidence: &evidence,
        subject_org: o.subject_org.as_deref(),
        accept_fleet_anchor: o.accept_fleet_anchor.unwrap_or(false),
    };
    let report = dossier.verify(threshold, &ctx);
    serde_json::to_string(&report).map_err(fail)
}

/// RFC 6962 inclusion proof check. All hashes hex. False on malformed input.
#[napi]
pub fn verify_inclusion(
    leaf_hash_hex: String,
    leaf_index: i64,
    tree_size: i64,
    proof_hexes: Vec<String>,
    root_hex: String,
) -> bool {
    let to32 = |h: &str| -> Option<[u8; 32]> { hex::decode(h.trim()).ok()?.try_into().ok() };
    let (Some(leaf), Some(root), Ok(index), Ok(size)) = (
        to32(&leaf_hash_hex),
        to32(&root_hex),
        u64::try_from(leaf_index),
        u64::try_from(tree_size),
    ) else {
        return false;
    };
    let mut proof = Vec::with_capacity(proof_hexes.len());
    for h in &proof_hexes {
        match to32(h) {
            Some(x) => proof.push(x),
            None => return false,
        }
    }
    witness_log_core::merkle::verify_inclusion(&leaf, index, size, &proof, &root)
}

/// SPEC §8 `payload_hash` for a disclosed salt, hex.
#[napi]
pub fn payload_hash_hex(payload: &[u8], salt_hex: String, leaf_index: i64) -> Result<String> {
    let salt: [u8; 32] = hex::decode(salt_hex.trim())
        .map_err(|_| invalid("salt must be hex"))?
        .try_into()
        .map_err(|_| invalid("salt must be 32 bytes"))?;
    let index = to_index(leaf_index)?;
    Ok(hex::encode(
        witness_log_core::redaction::payload_hash_with_salt(payload, &salt, index),
    ))
}

/// SPEC §3.1 binding check between two agents' leaves (JSON objects).
/// Null when they bind, else the reason.
#[napi]
pub fn verify_handoff_binding(
    sender_identity_hex: String,
    sender_leaf_json: String,
    receiver_identity_hex: String,
    receiver_leaf_json: String,
) -> Result<Option<String>> {
    let a: witness_log_core::leaf::Leaf =
        serde_json::from_str(&sender_leaf_json).map_err(invalid)?;
    let b: witness_log_core::leaf::Leaf =
        serde_json::from_str(&receiver_leaf_json).map_err(invalid)?;
    Ok(witness_log_core::leaf::verify_handoff_binding(
        &sender_identity_hex,
        &a,
        &receiver_identity_hex,
        &b,
    )
    .err())
}

/// SPEC §3.2 binding check. Null when they bind, else the reason.
#[napi]
pub fn verify_authorization_binding(
    party_a_identity_hex: String,
    party_a_leaf_json: String,
    party_b_identity_hex: String,
    party_b_leaf_json: String,
) -> Result<Option<String>> {
    let a: witness_log_core::leaf::Leaf =
        serde_json::from_str(&party_a_leaf_json).map_err(invalid)?;
    let b: witness_log_core::leaf::Leaf =
        serde_json::from_str(&party_b_leaf_json).map_err(invalid)?;
    Ok(witness_log_core::leaf::verify_authorization_binding(
        &party_a_identity_hex,
        &a,
        &party_b_identity_hex,
        &b,
    )
    .err())
}

/// Diversity-first witness selection, then round-robin fill up to `want`
/// (the set to submit to). Returns the chosen entries as a JSON array.
#[napi]
pub fn select_witnesses(
    directory_json: String,
    subject_pubkey_hex: String,
    want: u32,
    include_project_operated: Option<bool>,
) -> Result<String> {
    let dir = parse_directory(&directory_json)?;
    let picked = witness_log_network::select_witnesses(
        &dir,
        &subject_pubkey_hex,
        want as usize,
        include_project_operated.unwrap_or(false),
    );
    serde_json::to_string(&picked).map_err(fail)
}

/// Remove a stale `<path>.lock` left by a process that died holding the
/// journal. Only when nothing else has the journal open.
#[napi]
pub fn force_unlock(path: String) -> Result<()> {
    CoreJournal::force_unlock(&path).map_err(fail)
}

/// Version of this addon crate.
#[napi]
pub fn native_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}
