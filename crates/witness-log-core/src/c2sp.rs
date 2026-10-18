//! C2SP transparency-log interoperability.
//!
//! Implements three Community Cryptography Specification Project formats
//! so that WitnessLog checkpoints can be cosigned by the *existing*
//! transparency-log witness ecosystem rather than requiring a bespoke
//! witness network to be recruited from zero:
//!
//! - `c2sp.org/signed-note` — the underlying signed message format
//! - `c2sp.org/tlog-checkpoint` — checkpoint body layout
//! - `c2sp.org/tlog-cosignature` — timestamped witness cosignatures (v1)
//!
//! **Why this exists.** The hardest problem this project faces is not
//! cryptographic, it's social: a witness network is worthless until
//! independent operators actually run witnesses, and nobody wants to be
//! the first. Certificate Transparency solved that over a decade, and
//! the operators, the tooling (`github.com/transparency-dev/witness`),
//! and the protocols already exist. Speaking their protocol means those
//! witnesses can cosign a WitnessLog checkpoint without writing a line
//! of new code — inheriting an installed base instead of building one.
//!
//! **What C2SP does and does not cover.** These specs define checkpoints
//! and cosignatures. They say nothing about leaf schemas, dossiers,
//! redaction, key binding, or operator/compute-provider diversity
//! scoring — those remain WitnessLog's own (see `spec/SPEC.md`). This
//! module is the interop boundary, not a replacement for the native
//! format.
//!
//! **One consequence worth calling out.** A C2SP checkpoint body carries
//! origin, tree size, and root hash — and no timestamp. Time is supplied
//! only by cosigners, via `cosignature/v1`'s `time` line. That is
//! strictly better than the native `SignedTreeHead`'s self-asserted
//! `timestamp_ms`, which a dishonest operator can set freely (see
//! THREAT_MODEL.md and `WitnessPolicy`'s staleness handling). In the
//! C2SP encoding the log structurally *cannot* assert its own time.

use base64ct::{Base64, Encoding};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};
use thiserror::Error;

/// Signature type identifier for Ed25519 signed-note signatures
/// (signed-note §Signature types).
pub const SIG_TYPE_ED25519: u8 = 0x01;

/// Signature type identifier for timestamped Ed25519 checkpoint
/// cosignatures (`c2sp.org/tlog-cosignature`).
pub const SIG_TYPE_COSIGNATURE_V1: u8 = 0x04;

/// A tree size as the C2SP formats spell it: ASCII digits only, no sign,
/// no leading zero unless the value is 0, within `u64`. The only accepted
/// spelling of a number, so two encodings can never name one checkpoint.
pub fn parse_canonical_u64(s: &str) -> Option<u64> {
    if s.is_empty() || (s.len() > 1 && s.starts_with('0')) || !s.bytes().all(|b| b.is_ascii_digit())
    {
        return None;
    }
    s.parse().ok()
}

/// Em dash (U+2014) — the first character of every signed-note signature
/// line. Spelled out because a literal em dash in source is easy to
/// mistake for a hyphen during review, and getting it wrong produces
/// notes that no other implementation will accept.
const EM_DASH: char = '\u{2014}';

#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum C2spError {
    #[error("note is not valid UTF-8 or contains a disallowed ASCII control character")]
    InvalidCharacters,
    #[error("note has no blank line separating text from signatures")]
    MissingSeparator,
    #[error("note has no signature lines")]
    NoSignatures,
    #[error("malformed signature line: {0}")]
    MalformedSignature(String),
    #[error("checkpoint note text must have at least 3 lines (origin, size, root hash)")]
    CheckpointTooShort,
    #[error("checkpoint tree size is not a valid decimal integer without leading zeroes")]
    MalformedTreeSize,
    #[error("checkpoint root hash is not a base64-encoded 32-byte value")]
    MalformedRootHash,
    #[error("origin line must be non-empty and contain no spaces or '+'")]
    MalformedOrigin,
    #[error("no signature from a known key verified")]
    NoTrustedSignature,
    #[error("signature from a known key failed to verify")]
    BadSignature,
    #[error("malformed verifier key (vkey)")]
    MalformedVkey,
    #[error("malformed cosignature: {0}")]
    MalformedCosignature(String),
}

/// Compute a signed-note key ID:
/// `SHA-256(key_name || 0x0A || signature_type || public_key)[:4]`
/// (signed-note §Signatures).
pub fn key_id(key_name: &str, sig_type: u8, public_key: &[u8]) -> [u8; 4] {
    let mut h = Sha256::new();
    h.update(key_name.as_bytes());
    h.update([0x0A]);
    h.update([sig_type]);
    h.update(public_key);
    let digest = h.finalize();
    // Take the first four bytes without indexing. SHA-256 output is
    // always 32 bytes so this cannot fail, but expressing it as a
    // checked conversion keeps `clippy::indexing_slicing` enabled
    // crate-wide rather than carving out an exception.
    let mut id = [0u8; 4];
    for (slot, byte) in id.iter_mut().zip(digest.iter()) {
        *slot = *byte;
    }
    id
}

/// A signed-note verifier key, encoded as
/// `<key name>+hex(key ID)+base64(signature type || public key)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifierKey {
    pub name: String,
    pub id: [u8; 4],
    pub sig_type: u8,
    pub public_key: Vec<u8>,
}

impl VerifierKey {
    /// Build a vkey for an Ed25519 signing key used for plain note
    /// signatures (signature type 0x01).
    pub fn for_ed25519(name: &str, public_key: &VerifyingKey) -> Self {
        let pk = public_key.to_bytes().to_vec();
        Self {
            id: key_id(name, SIG_TYPE_ED25519, &pk),
            name: name.to_string(),
            sig_type: SIG_TYPE_ED25519,
            public_key: pk,
        }
    }

    /// Build a vkey for an Ed25519 key used for timestamped checkpoint
    /// cosignatures (signature type 0x04). A key used for both plain
    /// notes and cosignatures gets a *different* key ID for each, which
    /// is exactly the domain separation signed-note intends.
    pub fn for_cosignature(name: &str, public_key: &VerifyingKey) -> Self {
        let pk = public_key.to_bytes().to_vec();
        Self {
            id: key_id(name, SIG_TYPE_COSIGNATURE_V1, &pk),
            name: name.to_string(),
            sig_type: SIG_TYPE_COSIGNATURE_V1,
            public_key: pk,
        }
    }

    pub fn encode(&self) -> String {
        let mut material = Vec::with_capacity(1 + self.public_key.len());
        material.push(self.sig_type);
        material.extend_from_slice(&self.public_key);
        format!(
            "{}+{}+{}",
            self.name,
            hex::encode(self.id),
            Base64::encode_string(&material)
        )
    }

    pub fn parse(s: &str) -> Result<Self, C2spError> {
        // Split from the LEFT, not the right. The base64 alphabet
        // (RFC 4648 §4) includes '+', which is also this format's field
        // separator — so the trailing base64 field frequently contains
        // '+' characters of its own (empirically, in a majority of
        // random keys). Splitting from the right therefore cut into the
        // base64 payload rather than at the real separators.
        //
        // Splitting from the left is unambiguous because the spec
        // guarantees the two leading fields are separator-free: key
        // names "MUST NOT contain any Unicode spaces or plus (U+002B)
        // characters" (signed-note §Format), and the key ID is fixed
        // 8-character hex. Everything after the second '+' is the base64
        // payload, '+' characters included.
        let mut parts = s.splitn(3, '+');
        let name = parts.next().ok_or(C2spError::MalformedVkey)?;
        let id_hex = parts.next().ok_or(C2spError::MalformedVkey)?;
        let b64 = parts.next().ok_or(C2spError::MalformedVkey)?;
        if name.is_empty() {
            return Err(C2spError::MalformedVkey);
        }
        let id_bytes = hex::decode(id_hex).map_err(|_| C2spError::MalformedVkey)?;
        let id: [u8; 4] = id_bytes.try_into().map_err(|_| C2spError::MalformedVkey)?;
        let material = Base64::decode_vec(b64).map_err(|_| C2spError::MalformedVkey)?;
        let (&sig_type, public_key) = material.split_first().ok_or(C2spError::MalformedVkey)?;
        Ok(Self {
            name: name.to_string(),
            id,
            sig_type,
            public_key: public_key.to_vec(),
        })
    }

    fn verifying_key(&self) -> Result<VerifyingKey, C2spError> {
        let bytes: [u8; 32] = self
            .public_key
            .clone()
            .try_into()
            .map_err(|_| C2spError::MalformedVkey)?;
        VerifyingKey::from_bytes(&bytes).map_err(|_| C2spError::MalformedVkey)
    }
}

/// A signed-note key name: non-empty, no Unicode space (White_Space) and
/// no '+' (signed-note §Format).
pub fn is_valid_key_name(name: &str) -> bool {
    !name.is_empty() && !name.chars().any(|c| c == '+' || c.is_whitespace())
}

/// One signature line from a signed note.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NoteSignature {
    pub key_name: String,
    pub key_id: [u8; 4],
    /// Raw signature bytes (the base64 payload minus the 4-byte key ID).
    pub signature: Vec<u8>,
}

impl NoteSignature {
    pub fn encode(&self) -> String {
        let mut payload = Vec::with_capacity(4 + self.signature.len());
        payload.extend_from_slice(&self.key_id);
        payload.extend_from_slice(&self.signature);
        format!(
            "{EM_DASH} {} {}",
            self.key_name,
            Base64::encode_string(&payload)
        )
    }

    /// Parse one signature line (`— <name> <base64>`, without the
    /// trailing newline) -- e.g. a line of a `tlog-witness` 200 response.
    pub fn parse(line: &str) -> Result<Self, C2spError> {
        let mut chars = line.chars();
        if chars.next() != Some(EM_DASH) || chars.next() != Some(' ') {
            return Err(C2spError::MalformedSignature(
                "must begin with an em dash and a space".into(),
            ));
        }
        let rest: String = chars.collect();
        let mut parts = rest.splitn(2, ' ');
        let key_name = parts
            .next()
            .filter(|n| !n.is_empty())
            .ok_or_else(|| C2spError::MalformedSignature("missing key name".into()))?;
        let b64 = parts
            .next()
            .ok_or_else(|| C2spError::MalformedSignature("missing signature".into()))?;
        // signed-note §Format: key names contain no Unicode spaces and no
        // '+'. A line that breaks this is malformed whether or not the key
        // is known, so the whole note is rejected, as the reference parser
        // (golang.org/x/mod/sumdb/note) rejects it; it is not an "unknown
        // key" to skip. The Go and TypeScript verifiers apply the same rule.
        if !is_valid_key_name(key_name) {
            return Err(C2spError::MalformedSignature(
                "key name contains '+' or a Unicode space".into(),
            ));
        }
        let payload = Base64::decode_vec(b64)
            .map_err(|_| C2spError::MalformedSignature("signature is not valid base64".into()))?;
        // Bind the 4-byte key ID and the remaining signature bytes by
        // pattern rather than by length-check-then-index. `sig @ ..`
        // matches an empty tail, so the one-byte minimum is checked
        // explicitly (review round 2, C2).
        let [a, b, c, d, sig @ ..] = payload.as_slice() else {
            return Err(C2spError::MalformedSignature(
                "signature payload shorter than a key ID plus one byte".into(),
            ));
        };
        if sig.is_empty() {
            return Err(C2spError::MalformedSignature(
                "signature payload holds a key ID and no signature bytes".into(),
            ));
        }
        Ok(Self {
            key_name: key_name.to_string(),
            key_id: [*a, *b, *c, *d],
            signature: sig.to_vec(),
        })
    }
}

/// A signed note: text plus one or more signature lines
/// (`c2sp.org/signed-note`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedNote {
    /// The note text, INCLUDING its final newline and EXCLUDING the
    /// blank separator line. This is exactly the byte sequence
    /// signatures are computed over.
    pub text: String,
    pub signatures: Vec<NoteSignature>,
}

/// Verifiers SHOULD limit the number of signatures but MUST accept at
/// least 16 (signed-note §Format). 64 is a generous ceiling that still
/// bounds work on hostile input; post-quantum signatures can approach
/// 5kB each, so an unbounded count is a real memory concern.
const MAX_SIGNATURES: usize = 64;

impl SignedNote {
    /// Reject ASCII control characters other than newline, per
    /// signed-note §Format. Called on both serialization and parsing so
    /// a malformed note can never be produced OR accepted.
    fn check_characters(s: &str) -> Result<(), C2spError> {
        if s.chars().any(|c| (c as u32) < 0x20 && c != '\n') {
            return Err(C2spError::InvalidCharacters);
        }
        Ok(())
    }

    pub fn encode(&self) -> Result<String, C2spError> {
        Self::check_characters(&self.text)?;
        let mut out = self.text.clone();
        if !out.ends_with('\n') {
            out.push('\n');
        }
        out.push('\n'); // the blank separator line
        for sig in &self.signatures {
            out.push_str(&sig.encode());
            out.push('\n');
        }
        Ok(out)
    }

    pub fn parse(raw: &str) -> Result<Self, C2spError> {
        Self::check_characters(raw)?;
        // "the text is separated from the signatures by the LAST empty
        // line in the note" -- note text may itself contain empty lines,
        // so scanning for the first blank line would truncate it.
        let lines: Vec<&str> = raw.split('\n').collect();
        let mut separator: Option<usize> = None;
        for (i, line) in lines.iter().enumerate() {
            if !line.is_empty() {
                continue;
            }
            // A trailing empty element from the final newline isn't a
            // separator; only a blank line with content after it is.
            // `get` rather than slicing: `raw` is untrusted input and a
            // parser that can panic on it is a denial-of-service hole,
            // not just a bug.
            let has_content_after = lines
                .get(i.saturating_add(1)..)
                .map(|rest| rest.iter().any(|l| !l.is_empty()))
                .unwrap_or(false);
            if has_content_after {
                separator = Some(i);
            }
        }
        let sep = separator.ok_or(C2spError::MissingSeparator)?;
        let mut text = lines
            .get(..sep)
            .ok_or(C2spError::MissingSeparator)?
            .join("\n");
        text.push('\n');

        let mut signatures = Vec::new();
        let signature_lines = lines
            .get(sep.saturating_add(1)..)
            .ok_or(C2spError::NoSignatures)?;
        for line in signature_lines.iter().filter(|l| !l.is_empty()) {
            if signatures.len() >= MAX_SIGNATURES {
                return Err(C2spError::MalformedSignature(format!(
                    "more than {MAX_SIGNATURES} signature lines"
                )));
            }
            signatures.push(NoteSignature::parse(line)?);
        }
        if signatures.is_empty() {
            return Err(C2spError::NoSignatures);
        }
        Ok(Self { text, signatures })
    }

    /// Sign this note's text with an Ed25519 key (signature type 0x01),
    /// appending a signature line.
    pub fn sign(&mut self, key_name: &str, signing_key: &SigningKey) {
        let pk = signing_key.verifying_key().to_bytes();
        let id = key_id(key_name, SIG_TYPE_ED25519, &pk);
        let sig = signing_key.sign(self.text.as_bytes());
        self.signatures.push(NoteSignature {
            key_name: key_name.to_string(),
            key_id: id,
            signature: sig.to_bytes().to_vec(),
        });
    }

    /// Verify against a set of trusted verifier keys.
    ///
    /// Per signed-note §Signatures: signatures from unknown keys MUST be
    /// ignored (this is what allows witness cosignatures to ride along
    /// on a log's checkpoint without breaking the log's own verifiers);
    /// a signature from a KNOWN key that fails to verify SHOULD cause
    /// the whole note to be rejected; and if no known key verifies, the
    /// note MUST be rejected.
    ///
    /// Returns the names of the keys that verified.
    pub fn verify(&self, trusted: &[VerifierKey]) -> Result<Vec<String>, C2spError> {
        let mut verified = Vec::new();
        for sig in &self.signatures {
            // A key is "known" only when name AND id both match.
            let Some(vk) = trusted
                .iter()
                .find(|k| k.name == sig.key_name && k.id == sig.key_id)
            else {
                continue; // unknown key: MUST ignore
            };
            if vk.sig_type != SIG_TYPE_ED25519 {
                // Cosignatures sign a different message; they're verified
                // by `Cosignature::verify`, not here.
                continue;
            }
            let key = vk.verifying_key()?;
            let bytes: [u8; 64] = sig
                .signature
                .clone()
                .try_into()
                .map_err(|_| C2spError::BadSignature)?;
            // verify_strict, consistent with SPEC.md §6's normative
            // requirement: two conformant verifiers must never disagree
            // about the validity of the same artifact.
            key.verify_strict(self.text.as_bytes(), &Signature::from_bytes(&bytes))
                .map_err(|_| C2spError::BadSignature)?;
            verified.push(vk.name.clone());
        }
        if verified.is_empty() {
            return Err(C2spError::NoTrustedSignature);
        }
        Ok(verified)
    }
}

/// A transparency-log checkpoint (`c2sp.org/tlog-checkpoint`): a signed
/// note whose text is origin, tree size, and base64 root hash, plus
/// optional extension lines.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Checkpoint {
    /// Unique identifier for the log identity. SHOULD be a schema-less
    /// URL with no Unicode spaces and no '+', e.g. `example.com/log42`.
    /// Clients MUST NOT assume it is reachable.
    pub origin: String,
    pub tree_size: u64,
    pub root_hash: [u8; 32],
    /// Opaque, optional, NOT RECOMMENDED by the spec (monitors can't
    /// audit them). Present for round-trip fidelity when consuming
    /// checkpoints produced elsewhere.
    pub extensions: Vec<String>,
}

impl Checkpoint {
    fn validate_origin(origin: &str) -> Result<(), C2spError> {
        if origin.is_empty()
            || origin.contains(' ')
            || origin.contains('+')
            || origin.contains('\n')
        {
            return Err(C2spError::MalformedOrigin);
        }
        Ok(())
    }

    /// The note text: origin, tree size, base64 root hash, then any
    /// extension lines — each newline-terminated.
    pub fn note_text(&self) -> Result<String, C2spError> {
        Self::validate_origin(&self.origin)?;
        let mut text = String::new();
        text.push_str(&self.origin);
        text.push('\n');
        text.push_str(&self.tree_size.to_string());
        text.push('\n');
        text.push_str(&Base64::encode_string(&self.root_hash));
        text.push('\n');
        for ext in &self.extensions {
            if ext.is_empty() {
                return Err(C2spError::MalformedOrigin);
            }
            text.push_str(ext);
            text.push('\n');
        }
        Ok(text)
    }

    /// Produce a signed checkpoint note. The log's key name SHOULD match
    /// the origin line (tlog-checkpoint §Signatures), so that's the
    /// default here.
    pub fn sign(&self, signing_key: &SigningKey) -> Result<SignedNote, C2spError> {
        let mut note = SignedNote {
            text: self.note_text()?,
            signatures: Vec::new(),
        };
        note.sign(&self.origin, signing_key);
        Ok(note)
    }

    /// Parse a checkpoint out of a signed note's text.
    pub fn from_note(note: &SignedNote) -> Result<Self, C2spError> {
        let lines: Vec<&str> = note.text.trim_end_matches('\n').split('\n').collect();
        // Destructure rather than index. The length check below would
        // make indexing safe today, but a slice pattern makes safety
        // structural instead of dependent on a guard staying correct as
        // the function changes — and it's what lets
        // `clippy::indexing_slicing` be enabled crate-wide.
        let [origin_line, size_str, root_line, extension_lines @ ..] = lines.as_slice() else {
            return Err(C2spError::CheckpointTooShort);
        };
        let origin = (*origin_line).to_string();
        Self::validate_origin(&origin)?;

        // "no leading zeroes (unless the tree is empty, in which case the
        // tree size is 0)" -- accepting "007" would let two distinct
        // encodings represent one checkpoint, which breaks the property
        // that a checkpoint's bytes are canonical.
        let tree_size = parse_canonical_u64(size_str).ok_or(C2spError::MalformedTreeSize)?;

        let root_bytes = Base64::decode_vec(root_line).map_err(|_| C2spError::MalformedRootHash)?;
        let root_hash: [u8; 32] = root_bytes
            .try_into()
            .map_err(|_| C2spError::MalformedRootHash)?;

        let extensions = extension_lines
            .iter()
            .map(|s| (*s).to_string())
            .collect::<Vec<_>>();
        if extensions.iter().any(|e| e.is_empty()) {
            return Err(C2spError::CheckpointTooShort);
        }
        Ok(Self {
            origin,
            tree_size,
            root_hash,
            extensions,
        })
    }
}

/// A timestamped checkpoint cosignature (`c2sp.org/tlog-cosignature`, v1).
///
/// Semantically a v1 cosignature states: *as of this time, the consistent
/// tree head with the largest size the cosigner has observed for the log
/// identified by the origin line has this root hash.* That is the same
/// claim a native `WitnessReceipt` makes, which is what makes this a real
/// interop path rather than a lossy bridge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cosignature {
    pub key_name: String,
    pub key_id: [u8; 4],
    /// Unix seconds.
    pub timestamp: u64,
    pub signature: Vec<u8>,
}

impl Cosignature {
    /// The signed message: a `cosignature/v1` header line, a `time` line,
    /// then the whole note body of the cosigned checkpoint (including its
    /// final newline, excluding signature lines).
    pub fn message(timestamp: u64, checkpoint_note_text: &str) -> String {
        format!("cosignature/v1\ntime {timestamp}\n{checkpoint_note_text}")
    }

    pub fn sign(
        key_name: &str,
        signing_key: &SigningKey,
        timestamp: u64,
        checkpoint_note_text: &str,
    ) -> Self {
        let msg = Self::message(timestamp, checkpoint_note_text);
        let pk = signing_key.verifying_key().to_bytes();
        Self {
            key_name: key_name.to_string(),
            key_id: key_id(key_name, SIG_TYPE_COSIGNATURE_V1, &pk),
            timestamp,
            signature: signing_key.sign(msg.as_bytes()).to_bytes().to_vec(),
        }
    }

    pub fn verify(&self, vkey: &VerifierKey, checkpoint_note_text: &str) -> Result<(), C2spError> {
        if vkey.sig_type != SIG_TYPE_COSIGNATURE_V1
            || vkey.id != self.key_id
            || vkey.name != self.key_name
        {
            return Err(C2spError::NoTrustedSignature);
        }
        let key = vkey.verifying_key()?;
        let bytes: [u8; 64] = self
            .signature
            .clone()
            .try_into()
            .map_err(|_| C2spError::BadSignature)?;
        let msg = Self::message(self.timestamp, checkpoint_note_text);
        key.verify_strict(msg.as_bytes(), &Signature::from_bytes(&bytes))
            .map_err(|_| C2spError::BadSignature)
    }

    /// Render as a signed-note signature line. The signature payload for
    /// a cosignature is `key ID || timestamp (8B BE) || signature`, so a
    /// verifier that doesn't know the cosignature format still sees a
    /// well-formed, ignorable signature line.
    pub fn to_note_signature(&self) -> NoteSignature {
        let mut payload = Vec::with_capacity(8 + self.signature.len());
        payload.extend_from_slice(&self.timestamp.to_be_bytes());
        payload.extend_from_slice(&self.signature);
        NoteSignature {
            key_name: self.key_name.clone(),
            key_id: self.key_id,
            signature: payload,
        }
    }

    pub fn from_note_signature(sig: &NoteSignature) -> Result<Self, C2spError> {
        if sig.signature.len() < 9 {
            return Err(C2spError::MalformedCosignature(
                "payload shorter than a timestamp plus a signature".into(),
            ));
        }
        let (ts_bytes, sig_bytes) = sig.signature.split_at(8);
        let mut ts = [0u8; 8];
        ts.copy_from_slice(ts_bytes);
        Ok(Self {
            key_name: sig.key_name.clone(),
            key_id: sig.key_id,
            timestamp: u64::from_be_bytes(ts),
            signature: sig_bytes.to_vec(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    fn test_key() -> SigningKey {
        SigningKey::generate(&mut OsRng)
    }

    #[test]
    fn vkey_roundtrips() {
        let k = test_key();
        let vkey = VerifierKey::for_ed25519("example.com/log42", &k.verifying_key());
        let encoded = vkey.encode();
        let parsed = VerifierKey::parse(&encoded).expect("vkey must parse");
        assert_eq!(vkey, parsed);
        // Format sanity. Note we must NOT assert on the total number of
        // '+'-separated parts: the trailing base64 field routinely
        // contains '+' characters of its own. Only the first two fields
        // are guaranteed separator-free, so only they can be checked
        // positionally.
        let mut parts = encoded.splitn(3, '+');
        assert_eq!(
            parts.next(),
            Some("example.com/log42"),
            "field 1 is the key name"
        );
        assert_eq!(
            parts.next().map(str::len),
            Some(8),
            "field 2 is a 4-byte key ID = 8 hex chars"
        );
        assert!(parts.next().is_some(), "field 3 is the base64 key material");
    }

    #[test]
    fn vkey_roundtrips_when_the_base64_payload_contains_plus_characters() {
        // Regression, deterministic. '+' is both this format's field
        // separator AND a member of the standard base64 alphabet, so a
        // vkey whose encoded key material contains '+' must still parse.
        // The original implementation split from the right and broke on
        // roughly 60% of random keys -- the flakiness was the bug's
        // disguise, so this test pins specific key bytes rather than
        // generating them.
        //
        // These 32 bytes were chosen so the base64 of (0x01 || key)
        // contains at least one '+'.
        let key_bytes: [u8; 32] = [
            0xfb, 0xef, 0xbe, 0xff, 0xbe, 0xfb, 0xef, 0xbe, 0xff, 0xbe, 0xfb, 0xef, 0xbe, 0xff,
            0xbe, 0xfb, 0xef, 0xbe, 0xff, 0xbe, 0xfb, 0xef, 0xbe, 0xff, 0xbe, 0xfb, 0xef, 0xbe,
            0xff, 0xbe, 0xfb, 0xef,
        ];
        let mut material = vec![SIG_TYPE_ED25519];
        material.extend_from_slice(&key_bytes);
        let encoded_material = Base64::encode_string(&material);
        assert!(
            encoded_material.contains('+'),
            "fixture must actually exercise the bug; got {encoded_material}"
        );

        let vkey = VerifierKey {
            name: "example.com/plus-test".into(),
            id: [0xDE, 0xAD, 0xBE, 0xEF],
            sig_type: SIG_TYPE_ED25519,
            public_key: key_bytes.to_vec(),
        };
        let encoded = vkey.encode();
        let parsed = VerifierKey::parse(&encoded).expect("vkey with '+' in base64 must parse");
        assert_eq!(vkey, parsed);
    }

    #[test]
    fn vkey_roundtrips_across_many_random_keys() {
        // The original bug appeared in ~60% of random keys, so a single
        // random sample would have caught it only by luck. 200 samples
        // makes a recurrence effectively certain to be caught.
        for _ in 0..200 {
            let k = test_key();
            let vkey = VerifierKey::for_ed25519("example.com/log42", &k.verifying_key());
            let parsed = VerifierKey::parse(&vkey.encode()).expect("every vkey must roundtrip");
            assert_eq!(vkey, parsed);
            let cosign = VerifierKey::for_cosignature("example.com/log42", &k.verifying_key());
            assert_eq!(
                VerifierKey::parse(&cosign.encode()).expect("cosignature vkey must roundtrip"),
                cosign
            );
        }
    }

    #[test]
    fn key_id_domain_separates_signature_types() {
        // The same key used for plain notes and for cosignatures MUST get
        // different key IDs — that separation is the whole reason the
        // signature type byte is in the key ID preimage.
        let k = test_key();
        let plain = VerifierKey::for_ed25519("example.com/log", &k.verifying_key());
        let cosign = VerifierKey::for_cosignature("example.com/log", &k.verifying_key());
        assert_ne!(plain.id, cosign.id);
    }

    #[test]
    fn checkpoint_note_text_matches_spec_layout() {
        let cp = Checkpoint {
            origin: "example.com/behind-the-sofa".into(),
            tree_size: 20852163,
            root_hash: [0x42; 32],
            extensions: vec![],
        };
        let text = cp.note_text().unwrap();
        let lines: Vec<&str> = text.trim_end_matches('\n').split('\n').collect();
        assert_eq!(lines.len(), 3);
        assert_eq!(lines[0], "example.com/behind-the-sofa");
        assert_eq!(lines[1], "20852163");
        assert_eq!(lines[2], Base64::encode_string(&[0x42u8; 32]));
        assert!(text.ends_with('\n'), "note text includes its final newline");
    }

    #[test]
    fn signed_checkpoint_roundtrips_and_verifies() {
        let k = test_key();
        let cp = Checkpoint {
            origin: "example.com/log42".into(),
            tree_size: 7,
            root_hash: [0xAB; 32],
            extensions: vec![],
        };
        let note = cp.sign(&k).unwrap();
        let encoded = note.encode().unwrap();
        let parsed = SignedNote::parse(&encoded).unwrap();
        assert_eq!(note, parsed);

        let vkey = VerifierKey::for_ed25519("example.com/log42", &k.verifying_key());
        let verified = parsed.verify(&[vkey]).expect("must verify");
        assert_eq!(verified, vec!["example.com/log42".to_string()]);

        let recovered = Checkpoint::from_note(&parsed).unwrap();
        assert_eq!(cp, recovered);
    }

    #[test]
    fn unknown_signatures_are_ignored_not_rejected() {
        // This is what lets witness cosignatures ride along on a log's
        // own checkpoint without breaking the log's verifiers.
        let log_key = test_key();
        let stranger = test_key();
        let cp = Checkpoint {
            origin: "example.com/log42".into(),
            tree_size: 1,
            root_hash: [1u8; 32],
            extensions: vec![],
        };
        let mut note = cp.sign(&log_key).unwrap();
        note.sign("someone.example/unknown", &stranger);

        let vkey = VerifierKey::for_ed25519("example.com/log42", &log_key.verifying_key());
        let verified = note.verify(&[vkey]).expect("must still verify");
        assert_eq!(verified.len(), 1, "only the known key counts");
    }

    #[test]
    fn a_signature_line_with_an_invalid_key_name_makes_the_note_malformed() {
        // signed-note §Format: no '+' and no Unicode space in a key name.
        // Such a line is malformed, not a signature from an unknown key,
        // so the note is rejected even though the line's key is unknown
        // (as golang.org/x/mod/sumdb/note rejects it). The Go and
        // TypeScript verifiers apply the same rule (corpus 15).
        let k = test_key();
        let cp = Checkpoint {
            origin: "example.com/log42".into(),
            tree_size: 1,
            root_hash: [1u8; 32],
            extensions: vec![],
        };
        let good = cp.sign(&k).unwrap().encode().unwrap();
        let payload = Base64::encode_string(&[7u8; 68]);
        for name in ["a+b", "a\u{a0}b", "a\u{3000}b", "a\u{85}b", "a\u{2028}b"] {
            let raw = format!("{good}{EM_DASH} {name} {payload}\n");
            assert!(
                matches!(
                    SignedNote::parse(&raw),
                    Err(C2spError::MalformedSignature(_))
                ),
                "{name:?}"
            );
        }
        // U+FEFF and U+007F are not White_Space: such a name is merely
        // unknown, and the note still verifies under its own key.
        for name in ["a\u{feff}b", "a\u{7f}b"] {
            let raw = format!("{good}{EM_DASH} {name} {payload}\n");
            let note = SignedNote::parse(&raw).expect(name);
            let vkey = VerifierKey::for_ed25519("example.com/log42", &k.verifying_key());
            assert!(note.verify(&[vkey]).is_ok(), "{name:?}");
        }
        assert!(is_valid_key_name("example.com/log42"));
        assert!(!is_valid_key_name(""));
    }

    #[test]
    fn a_known_key_with_a_bad_signature_rejects_the_whole_note() {
        let k = test_key();
        let cp = Checkpoint {
            origin: "example.com/log42".into(),
            tree_size: 1,
            root_hash: [1u8; 32],
            extensions: vec![],
        };
        let mut note = cp.sign(&k).unwrap();
        note.signatures[0].signature[0] ^= 0xFF; // corrupt it
        let vkey = VerifierKey::for_ed25519("example.com/log42", &k.verifying_key());
        assert_eq!(note.verify(&[vkey]), Err(C2spError::BadSignature));
    }

    #[test]
    fn note_with_no_trusted_signature_is_rejected() {
        let k = test_key();
        let other = test_key();
        let cp = Checkpoint {
            origin: "example.com/log42".into(),
            tree_size: 1,
            root_hash: [1u8; 32],
            extensions: vec![],
        };
        let note = cp.sign(&k).unwrap();
        let wrong = VerifierKey::for_ed25519("example.com/other", &other.verifying_key());
        assert_eq!(note.verify(&[wrong]), Err(C2spError::NoTrustedSignature));
    }

    #[test]
    fn note_text_may_contain_empty_lines() {
        // The separator is the LAST empty line, not the first — a note
        // whose text contains blank lines must round-trip intact.
        let k = test_key();
        let mut note = SignedNote {
            text: "line one\n\nline three\n".into(),
            signatures: Vec::new(),
        };
        note.sign("example.com/x", &k);
        let encoded = note.encode().unwrap();
        let parsed = SignedNote::parse(&encoded).unwrap();
        assert_eq!(parsed.text, "line one\n\nline three\n");
        let vkey = VerifierKey::for_ed25519("example.com/x", &k.verifying_key());
        parsed.verify(&[vkey]).expect("must verify after roundtrip");
    }

    #[test]
    fn tree_size_with_leading_zeroes_is_rejected() {
        // Two encodings of one checkpoint would break canonicity.
        let k = test_key();
        let mut note = SignedNote {
            text: "example.com/log\n007\n".to_string() + &Base64::encode_string(&[0u8; 32]) + "\n",
            signatures: Vec::new(),
        };
        note.sign("example.com/log", &k);
        let parsed = SignedNote::parse(&note.encode().unwrap()).unwrap();
        assert_eq!(
            Checkpoint::from_note(&parsed),
            Err(C2spError::MalformedTreeSize)
        );
    }

    #[test]
    fn cosignature_signs_the_specified_message_and_verifies() {
        let _log_key = test_key();
        let witness_key = test_key();
        let cp = Checkpoint {
            origin: "example.com/log42".into(),
            tree_size: 42,
            root_hash: [9u8; 32],
            extensions: vec![],
        };
        let text = cp.note_text().unwrap();
        let cosig = Cosignature::sign("witness.example/w1", &witness_key, 1679315147, &text);

        // Message layout is normative — a mismatch here means no other
        // implementation's witness will interoperate.
        let msg = Cosignature::message(1679315147, &text);
        assert!(msg.starts_with("cosignature/v1\ntime 1679315147\n"));
        assert!(msg.ends_with(&text));

        let vkey = VerifierKey::for_cosignature("witness.example/w1", &witness_key.verifying_key());
        cosig.verify(&vkey, &text).expect("cosignature must verify");

        // A cosignature over a DIFFERENT checkpoint must not verify.
        let other = Checkpoint {
            tree_size: 43,
            ..cp.clone()
        };
        assert!(cosig.verify(&vkey, &other.note_text().unwrap()).is_err());
    }

    #[test]
    fn cosignature_roundtrips_through_a_note_signature_line() {
        let witness_key = test_key();
        let cosig = Cosignature::sign("witness.example/w1", &witness_key, 1700000000, "x\n");
        let line = cosig.to_note_signature();
        let recovered = Cosignature::from_note_signature(&line).unwrap();
        assert_eq!(cosig, recovered);
    }

    #[test]
    fn hostile_notes_never_panic() {
        let hostile = [
            "",
            "\n",
            "\n\n",
            "no separator at all",
            "text\n\n",
            "text\n\n— ",
            "text\n\n— name",
            "text\n\n— name !!!not-base64!!!",
            "text\n\n— name AA==",       // payload shorter than a key ID
            "text\n\n\u{0001}control\n", // disallowed control character
            &format!("text\n\n{}", "— n AAAAAAAA\n".repeat(200)), // signature flood
        ];
        for input in hostile {
            let _ = SignedNote::parse(input);
        }
    }

    #[test]
    fn control_characters_are_rejected_on_both_encode_and_parse() {
        let note = SignedNote {
            text: "bad\u{0007}bell\n".into(),
            signatures: vec![NoteSignature {
                key_name: "x".into(),
                key_id: [0; 4],
                signature: vec![0; 64],
            }],
        };
        assert_eq!(note.encode(), Err(C2spError::InvalidCharacters));
        assert_eq!(
            SignedNote::parse("bad\u{0007}bell\n\n— x AAAAAA==\n"),
            Err(C2spError::InvalidCharacters)
        );
    }
}

/// Conformance tests against the example vectors published IN the specs
/// themselves. These are the only tests in this module that prove
/// interoperability rather than mere self-consistency: a round-trip test
/// passes just as happily against a wrong-but-consistent implementation.
#[cfg(test)]
mod spec_vectors {
    use super::*;

    /// signed-note §Verifier keys publishes this exact vkey/note pair.
    const SPEC_VKEY: &str = "example.com/foo+530d903a+AekyeRrm56hApGFkyQR4ZCbV54Id2LKaANYcrnKv3U2k";
    const SPEC_NOTE: &str = "This is an example message.\n\n\u{2014} example.com/foo Uw2QOkn8srV1yJGh2VYRlL1Tnagv1YEq6TfXppzi2ONncAlTgK7Ztg1ERYNZXsYjOBH3mFXmRKuwHjG1Yu72IneyaQM=\n";

    #[test]
    fn parses_the_specs_own_verifier_key() {
        let vkey = VerifierKey::parse(SPEC_VKEY).expect("spec vkey must parse");
        assert_eq!(vkey.name, "example.com/foo");
        assert_eq!(hex::encode(vkey.id), "530d903a");
        assert_eq!(vkey.sig_type, SIG_TYPE_ED25519);
        assert_eq!(vkey.public_key.len(), 32);
        // Re-encoding must reproduce the spec's string byte for byte.
        assert_eq!(vkey.encode(), SPEC_VKEY);
    }

    #[test]
    fn recomputes_the_specs_key_id_from_the_public_key() {
        // If our key-ID derivation is wrong, every signature line we
        // produce is addressed to a key nobody recognizes.
        let vkey = VerifierKey::parse(SPEC_VKEY).unwrap();
        let recomputed = key_id(&vkey.name, SIG_TYPE_ED25519, &vkey.public_key);
        assert_eq!(
            recomputed, vkey.id,
            "key ID derivation disagrees with the spec's published key"
        );
    }

    #[test]
    fn verifies_the_specs_own_signed_note() {
        // The end-to-end conformance check: parse the spec's note, verify
        // it against the spec's key. This exercises note framing, the
        // text/signature split, base64 handling, key-ID matching, and the
        // Ed25519 verification path all at once, against bytes we did not
        // produce.
        let vkey = VerifierKey::parse(SPEC_VKEY).unwrap();
        let note = SignedNote::parse(SPEC_NOTE).expect("spec note must parse");
        assert_eq!(note.text, "This is an example message.\n");
        assert_eq!(note.signatures.len(), 1);
        assert_eq!(note.signatures[0].key_name, "example.com/foo");
        assert_eq!(hex::encode(note.signatures[0].key_id), "530d903a");
        let verified = note.verify(&[vkey]).expect("spec note must verify");
        assert_eq!(verified, vec!["example.com/foo".to_string()]);
    }

    #[test]
    fn reencodes_the_specs_note_byte_for_byte() {
        let note = SignedNote::parse(SPEC_NOTE).unwrap();
        assert_eq!(
            note.encode().unwrap(),
            SPEC_NOTE,
            "re-encoding the spec's note must reproduce it exactly"
        );
    }

    #[test]
    fn parses_the_checkpoint_example_from_tlog_checkpoint() {
        // tlog-checkpoint §Note text publishes this body.
        let text =
            "example.com/behind-the-sofa\n20852163\nCsUYapGGPo4dkMgIAUqom/Xajj7h2fB2MPA3j2jxq2I=\n";
        let note = SignedNote {
            text: text.to_string(),
            signatures: vec![NoteSignature {
                key_name: "example.com/behind-the-sofa".into(),
                key_id: [0; 4],
                signature: vec![0; 64],
            }],
        };
        let cp = Checkpoint::from_note(&note).expect("spec checkpoint must parse");
        assert_eq!(cp.origin, "example.com/behind-the-sofa");
        assert_eq!(cp.tree_size, 20852163);
        assert_eq!(
            Base64::encode_string(&cp.root_hash),
            "CsUYapGGPo4dkMgIAUqom/Xajj7h2fB2MPA3j2jxq2I="
        );
        // And regenerating the body reproduces the spec's bytes.
        assert_eq!(cp.note_text().unwrap(), text);
    }

    #[test]
    fn cosignature_message_matches_the_specs_example_layout() {
        // tlog-cosignature publishes this message shape.
        let body =
            "example.com/behind-the-sofa\n20852163\nCsUYapGGPo4dkMgIAUqom/Xajj7h2fB2MPA3j2jxq2I=\n";
        let msg = Cosignature::message(1679315147, body);
        assert_eq!(
            msg,
            "cosignature/v1\ntime 1679315147\nexample.com/behind-the-sofa\n20852163\nCsUYapGGPo4dkMgIAUqom/Xajj7h2fB2MPA3j2jxq2I=\n"
        );
    }
}

/// Prefix of a [`canonical_origin`].
pub const CANONICAL_ORIGIN_PREFIX: &str = "witness-log/";

/// The canonical C2SP origin for a WitnessLog identity:
/// `witness-log/<64 lowercase hex chars of the identity public key>`.
///
/// **Why the name is the key.** A cosignature counts toward a verdict
/// only when it was made under this origin (SPEC.md §9.3). Two things
/// follow. First, a witness can enroll a log it has never heard of
/// without any out-of-band key exchange: the origin names the only key
/// that can sign under it, so there is nothing to trust on first use.
/// Second, one identity has exactly one origin, so an agent cannot show
/// one history to some witnesses and a fork to others under a different
/// name. Logs may still use other origins with witnesses; those
/// cosignatures are valid C2SP but do not count toward a WitnessLog
/// verdict.
pub fn canonical_origin(identity: &VerifyingKey) -> String {
    format!(
        "{CANONICAL_ORIGIN_PREFIX}{}",
        hex::encode(identity.to_bytes())
    )
}

/// Inverse of [`canonical_origin`]: the identity key a canonical origin
/// names, or `None` if `origin` is not exactly canonical (uppercase hex,
/// extra characters and non-curve points are all rejected, so each key
/// has exactly one accepted spelling).
pub fn identity_from_canonical_origin(origin: &str) -> Option<VerifyingKey> {
    let hex_part = origin.strip_prefix(CANONICAL_ORIGIN_PREFIX)?;
    if hex_part.len() != 64
        || !hex_part
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return None;
    }
    let bytes: [u8; 32] = hex::decode(hex_part).ok()?.try_into().ok()?;
    VerifyingKey::from_bytes(&bytes).ok()
}

/// Bridge between WitnessLog's native types and the C2SP wire formats.
///
/// The native `SignedTreeHead` and a C2SP `Checkpoint` describe the same
/// thing with two differences worth stating plainly:
///
/// 1. **Origin.** C2SP identifies a log by an `origin` string, a
///    schema-less URL. WitnessLog identifies one by an Ed25519 identity
///    public key. The origin is therefore supplied by the caller rather
///    than derived — a log's operator chooses a stable name (e.g.
///    `agents.example.com/agent-42`) and publishes the mapping from that
///    name to the key, exactly as CT logs do.
///
/// 2. **Time.** A native STH carries `timestamp_ms`, self-asserted by the
///    signer. A C2SP checkpoint carries no timestamp at all; time comes
///    only from cosigners. Converting native → C2SP therefore *drops* a
///    field, and that is an improvement: THREAT_MODEL.md already
///    documents the self-asserted timestamp as carrying no evidentiary
///    weight, and `WitnessPolicy` already prefers witness-corroborated
///    time over it. Round-tripping C2SP → native → C2SP is lossless;
///    round-tripping native → C2SP → native loses only that field.
pub mod bridge {
    use super::*;
    use crate::sth::SignedTreeHead;

    /// Render a native checkpoint as a C2SP checkpoint under `origin`.
    pub fn checkpoint_from_sth(
        sth: &SignedTreeHead,
        origin: &str,
    ) -> Result<Checkpoint, C2spError> {
        let root_bytes = hex::decode(&sth.root_hash).map_err(|_| C2spError::MalformedRootHash)?;
        let root_hash: [u8; 32] = root_bytes
            .try_into()
            .map_err(|_| C2spError::MalformedRootHash)?;
        Ok(Checkpoint {
            origin: origin.to_string(),
            tree_size: sth.tree_size,
            root_hash,
            extensions: vec![],
        })
    }

    /// Sign a native checkpoint's contents as a C2SP signed note.
    ///
    /// Note this produces a signature over the C2SP note text, NOT over
    /// the native `witness-log-sth-v2` message — the two are different
    /// signed messages describing the same tree head. A log publishing
    /// both formats signs twice, which is expected and is why signed
    /// notes carry multiple signature lines.
    pub fn sign_as_c2sp(
        sth: &SignedTreeHead,
        origin: &str,
        signing_key: &SigningKey,
    ) -> Result<SignedNote, C2spError> {
        checkpoint_from_sth(sth, origin)?.sign(signing_key)
    }

    /// The vkey a third-party witness needs in order to verify this log's
    /// C2SP checkpoints. Publish this alongside the origin.
    pub fn log_vkey(origin: &str, identity_public_key: &VerifyingKey) -> VerifierKey {
        VerifierKey::for_ed25519(origin, identity_public_key)
    }
}

#[cfg(test)]
mod bridge_tests {
    use super::*;
    use crate::sth::SignedTreeHead;
    use rand::rngs::OsRng;

    #[test]
    fn native_checkpoint_converts_and_verifies_as_c2sp() {
        let key = SigningKey::generate(&mut OsRng);
        let root = [0x11u8; 32];
        let sth = SignedTreeHead::sign(&key, 9, &root, 1_700_000_000_000);

        let origin = "agents.example.com/agent-42";
        let note = bridge::sign_as_c2sp(&sth, origin, &key).unwrap();

        // A third party holding only the origin and the log's public key
        // can verify this — no WitnessLog-specific code required.
        let vkey = bridge::log_vkey(origin, &key.verifying_key());
        note.verify(&[vkey]).expect("C2SP checkpoint must verify");

        let cp = Checkpoint::from_note(&note).unwrap();
        assert_eq!(cp.tree_size, sth.tree_size);
        assert_eq!(hex::encode(cp.root_hash), sth.root_hash);
        assert_eq!(cp.origin, origin);
    }

    #[test]
    fn a_third_party_witness_can_cosign_a_converted_checkpoint() {
        // The whole point: an existing transparency-log witness, which
        // knows nothing about WitnessLog, cosigns using only C2SP.
        let log_key = SigningKey::generate(&mut OsRng);
        let witness_key = SigningKey::generate(&mut OsRng);
        let sth = SignedTreeHead::sign(&log_key, 5, &[0x22u8; 32], 1_700_000_000_000);
        let origin = "agents.example.com/agent-7";

        let mut note = bridge::sign_as_c2sp(&sth, origin, &log_key).unwrap();
        let body = note.text.clone();

        // Witness side: verify the log's signature, then cosign the body.
        let log_vkey = bridge::log_vkey(origin, &log_key.verifying_key());
        note.verify(std::slice::from_ref(&log_vkey))
            .expect("witness verifies the log first");
        let cosig = Cosignature::sign("witness.example/w1", &witness_key, 1_700_000_030, &body);
        note.signatures.push(cosig.to_note_signature());

        // Log side: the cosignature rides along and the log's own
        // verification still succeeds (unknown signatures are ignored).
        note.verify(&[log_vkey])
            .expect("log's own verification unaffected");

        // Verifier side: check the cosignature against the witness vkey.
        let witness_vkey =
            VerifierKey::for_cosignature("witness.example/w1", &witness_key.verifying_key());
        let recovered = Cosignature::from_note_signature(note.signatures.last().unwrap()).unwrap();
        recovered
            .verify(&witness_vkey, &body)
            .expect("cosignature must verify against the checkpoint body");
        assert_eq!(recovered.timestamp, 1_700_000_030);
    }
}
