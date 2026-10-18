//! Generates `corpus/16_ed25519_strict.json`: Ed25519 signatures at the
//! edges where implementations disagree (small-order and mixed-order
//! points, non-canonical encodings, non-canonical scalars), each with the
//! answer of the check every signature in a dossier goes through in the
//! reference verifier: `VerifyingKey::from_bytes` then
//! `VerifyingKey::verify_strict` (ed25519-dalek 2). SPEC.md §6 makes that
//! check normative; outside review III (H3/M3) found
//! the TypeScript verifier did not apply it and asked for differential
//! vectors that every verifier runs.
//!
//! Two parts. `signatures` are (public key, message, signature) triples
//! for the raw verification primitive, each also labelled with what a
//! non-strict RFC 8032 check would say, cofactorless (`[s]B - [k]A`
//! encodes to R's bytes) and cofactored (`[8]([s]B - [k]A - R)` is the
//! identity), so a reader can see why the case matters. `cases` embed
//! degenerate signatures in dossiers (a checkpoint, native and C2SP
//! receipts, a key binding, a revocation, an equivocation proof's notes)
//! and give the verdict, exit code and report fields, as in corpus 15.
//!
//!   cargo run -p witness-log-network --example generate_ed25519_corpus
//!
//! CI regenerates it and fails if the committed file differs. Every
//! expectation is computed by ed25519-dalek and checked against the value
//! the case was built to have, so a change of behaviour cannot slip in as
//! a regenerated expectation. Deterministic: fixed seeds, fixed nonces,
//! messages ground with a counter. Every key here is PUBLIC and for
//! conformance testing only.

use base64ct::{Base64, Encoding};
use curve25519_dalek::constants::EIGHT_TORSION;
use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::IsIdentity;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde_json::json;
use sha2::{Digest, Sha256, Sha512};
use witness_log_core::c2sp::{canonical_origin, key_id, Checkpoint, Cosignature, SIG_TYPE_ED25519};
use witness_log_core::identity::{KeyBindingStatement, KeyCustody, RevocationStatement};
use witness_log_core::leaf::{Leaf, LeafType};
use witness_log_core::merkle::{leaf_hash, MerkleTree};
use witness_log_core::sth::SignedTreeHead;
use witness_log_network::tlog_witness::EquivocationProof;
use witness_log_network::{
    Dossier, Verdict, VerifyContext, WitnessDirectory, WitnessEntry, WitnessReceipt, WitnessRuntime,
};

const IDENTITY_SEED: [u8; 32] = [0x16; 32];
const SESSION_SEED: [u8; 32] = [0x17; 32];
const OTHER_SEED: [u8; 32] = [0x18; 32];
const WITNESS_SEED: [u8; 32] = [0x26; 32];
const T0: u64 = 1_700_000_000_000;
const EM_DASH: char = '\u{2014}';

/// The group order L = 2^252 + 27742317777372353535851937790883648493,
/// little-endian.
const L_BYTES: [u8; 32] = [
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
];

/// p = 2^255 - 19, little-endian.
const P_BYTES: [u8; 32] = [
    0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
];

/// a + b as 256-bit little-endian integers; panics on overflow.
fn add_le(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut carry = 0u16;
    for i in 0..32 {
        let s = a[i] as u16 + b[i] as u16 + carry;
        out[i] = s as u8;
        carry = s >> 8;
    }
    assert_eq!(carry, 0, "overflow");
    out
}

fn small_le(n: u8) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[0] = n;
    out
}

fn with_sign_bit(mut b: [u8; 32]) -> [u8; 32] {
    b[31] |= 0x80;
    b
}

/// A scalar named by `label`, reduced mod L.
fn scalar(label: &str) -> Scalar {
    Scalar::from_bytes_mod_order_wide(&Sha512::digest(label.as_bytes()).into())
}

/// k = SHA-512(R || A || M) mod L, over the encodings as given.
fn challenge(r: &[u8], a: &[u8; 32], m: &[u8]) -> Scalar {
    let mut h = Sha512::new();
    h.update(r);
    h.update(a);
    h.update(m);
    Scalar::from_bytes_mod_order_wide(&h.finalize().into())
}

fn sig_bytes(r: &[u8; 32], s: &[u8; 32]) -> [u8; 64] {
    let mut out = [0u8; 64];
    out[..32].copy_from_slice(r);
    out[32..].copy_from_slice(s);
    out
}

/// The reference verifier's check, exactly as every dossier signature goes
/// through it (sth.rs, identity.rs, c2sp.rs, the network crate's receipts).
fn strict(a: &[u8; 32], m: &[u8], sig: &[u8; 64]) -> bool {
    VerifyingKey::from_bytes(a)
        .map(|k| k.verify_strict(m, &Signature::from_bytes(sig)).is_ok())
        .unwrap_or(false)
}

/// RFC 8032 without small-order checks, cofactorless: s < L, A decodes,
/// [s]B - [k]A encodes to exactly R's bytes.
fn cofactorless(a: &[u8; 32], m: &[u8], sig: &[u8; 64]) -> bool {
    let s: Option<Scalar> = Scalar::from_canonical_bytes(sig[32..].try_into().unwrap()).into();
    let (Some(s), Some(pa)) = (s, CompressedEdwardsY(*a).decompress()) else {
        return false;
    };
    let k = challenge(&sig[..32], a, m);
    EdwardsPoint::vartime_double_scalar_mul_basepoint(&k, &-pa, &s)
        .compress()
        .as_bytes()
        == &sig[..32]
}

/// RFC 8032 without small-order checks, cofactored: s < L, A and R decode,
/// [8]([s]B - [k]A - R) is the identity.
fn cofactored(a: &[u8; 32], m: &[u8], sig: &[u8; 64]) -> bool {
    let s: Option<Scalar> = Scalar::from_canonical_bytes(sig[32..].try_into().unwrap()).into();
    let r: [u8; 32] = sig[..32].try_into().unwrap();
    let (Some(s), Some(pa), Some(pr)) = (
        s,
        CompressedEdwardsY(*a).decompress(),
        CompressedEdwardsY(r).decompress(),
    ) else {
        return false;
    };
    let k = challenge(&r, a, m);
    (EdwardsPoint::vartime_double_scalar_mul_basepoint(&k, &-pa, &s) - pr)
        .mul_by_cofactor()
        .is_identity()
}

/// `base` followed by the first counter for which `ok(message)` holds.
fn grind(base: &str, ok: impl Fn(&[u8]) -> bool) -> Vec<u8> {
    for i in 0u32..10_000 {
        let m = format!("{base} #{i}").into_bytes();
        if ok(&m) {
            return m;
        }
    }
    panic!("no message found for {base}");
}

/// The 14 encodings of the 8 small-order points that decode: the 8
/// canonical ones, x = 0 with the sign bit set (identity, order 2), and
/// y >= p (y = p decodes as 0, y = p + 1 as 1), with and without the sign
/// bit. Every one is refused as A or R by verify_strict.
fn small_order_encodings() -> Vec<(String, [u8; 32])> {
    let order = [1, 8, 4, 8, 2, 8, 4, 8];
    let mut v: Vec<(String, [u8; 32])> = EIGHT_TORSION
        .iter()
        .enumerate()
        .map(|(i, t)| {
            let enc = t.compress().to_bytes();
            let what = if i == 0 {
                "the identity".to_string()
            } else {
                format!("order {} point {i}·T8", order[i])
            };
            (format!("{what}, canonical"), enc)
        })
        .collect();
    let identity = EIGHT_TORSION[0].compress().to_bytes();
    let order2 = EIGHT_TORSION[4].compress().to_bytes();
    let p0 = P_BYTES;
    let p1 = add_le(&P_BYTES, &small_le(1));
    v.extend([
        (
            "the identity, x = 0 with the sign bit set".to_string(),
            with_sign_bit(identity),
        ),
        (
            "order 2 point, x = 0 with the sign bit set".to_string(),
            with_sign_bit(order2),
        ),
        ("order 4 point, y = p (non-canonical y = 0)".to_string(), p0),
        (
            "order 4 point, y = p (non-canonical y = 0), sign bit set".to_string(),
            with_sign_bit(p0),
        ),
        (
            "the identity, y = p + 1 (non-canonical y = 1)".to_string(),
            p1,
        ),
        (
            "the identity, y = p + 1 (non-canonical y = 1), sign bit set".to_string(),
            with_sign_bit(p1),
        ),
    ]);
    for (name, enc) in &v[8..] {
        let p = CompressedEdwardsY(*enc).decompress().expect(name);
        assert_ne!(
            p.compress().to_bytes(),
            *enc,
            "{name} must be non-canonical"
        );
    }
    for (name, enc) in &v {
        let p = CompressedEdwardsY(*enc).decompress().expect(name);
        assert!(p.is_small_order(), "{name}");
    }
    v
}

/// Encodings y = p + c (c small) that decode to a point that is not of
/// small order, and canonical y = c that do not decode at all.
fn odd_encodings() -> (Vec<[u8; 32]>, Vec<[u8; 32]>) {
    let mut non_canonical = Vec::new();
    let mut undecodable = Vec::new();
    for c in 2u8..19 {
        let enc = add_le(&P_BYTES, &small_le(c));
        match CompressedEdwardsY(enc).decompress() {
            Some(p) if !p.is_small_order() => non_canonical.push(enc),
            _ => {}
        }
        if CompressedEdwardsY(small_le(c)).decompress().is_none() {
            undecodable.push(small_le(c));
        }
    }
    (non_canonical, undecodable)
}

struct SigCase {
    name: String,
    a: [u8; 32],
    m: Vec<u8>,
    sig: [u8; 64],
    /// What the case is built to show: (verify_strict, cofactorless, cofactored).
    intended: (bool, bool, bool),
}

/// `s = r + k·a` for a key `a·B + torsion` whose encoding is `a_enc`.
fn sign_with(a: &Scalar, a_enc: &[u8; 32], r: &Scalar, r_enc: &[u8; 32], m: &[u8]) -> [u8; 64] {
    let k = challenge(r_enc, a_enc, m);
    sig_bytes(r_enc, &(r + k * a).to_bytes())
}

fn signature_cases() -> Vec<SigCase> {
    let mut out = Vec::new();
    let mut push = |name: String, a: [u8; 32], m: Vec<u8>, sig: [u8; 64], intended| {
        out.push(SigCase {
            name,
            a,
            m,
            sig,
            intended,
        })
    };
    let key = SigningKey::from_bytes(&IDENTITY_SEED);
    let a = key.to_scalar();
    let a_enc = key.verifying_key().to_bytes();
    let other = SigningKey::from_bytes(&OTHER_SEED);
    let m1 = b"corpus 16: an honest message".to_vec();
    let honest = key.sign(&m1).to_bytes();
    let r_honest: [u8; 32] = honest[..32].try_into().unwrap();
    let s_honest: [u8; 32] = honest[32..].try_into().unwrap();

    // ---- honest signatures and plain failures
    push(
        "honest signature".into(),
        a_enc,
        m1.clone(),
        honest,
        (true, true, true),
    );
    push(
        "honest signature, empty message".into(),
        a_enc,
        vec![],
        key.sign(b"").to_bytes(),
        (true, true, true),
    );
    push(
        "honest signature, wrong message".into(),
        a_enc,
        b"corpus 16: another message".to_vec(),
        honest,
        (false, false, false),
    );
    push(
        "honest signature by another key".into(),
        a_enc,
        m1.clone(),
        other.sign(&m1).to_bytes(),
        (false, false, false),
    );
    push(
        "honest signature, R negated (sign bit flipped)".into(),
        a_enc,
        m1.clone(),
        sig_bytes(
            &{
                let mut r = r_honest;
                r[31] ^= 0x80;
                r
            },
            &s_honest,
        ),
        (false, false, false),
    );
    // ---- non-canonical s: s + L names the same scalar, and a verifier that
    // reduces s mod L would accept it.
    let s_plus_l = add_le(&s_honest, &L_BYTES);
    let s_plus_2l = add_le(&s_plus_l, &L_BYTES);
    push(
        "honest signature with s + L (non-canonical s)".into(),
        a_enc,
        m1.clone(),
        sig_bytes(&r_honest, &s_plus_l),
        (false, false, false),
    );
    push(
        "honest signature with s + 2L (non-canonical s)".into(),
        a_enc,
        m1.clone(),
        sig_bytes(&r_honest, &s_plus_2l),
        (false, false, false),
    );

    let small = small_order_encodings();
    let identity_enc = small[0].1;
    let zero = [0u8; 32];

    // ---- small-order public key A. R = r·B is an ordinary point and
    // s = r; the message is ground until k·A is the identity, so
    // [s]B - [k]A = R and a non-strict check accepts.
    for (i, (what, enc)) in small.iter().enumerate() {
        let r = scalar(&format!("corpus 16 small A {i}"));
        let r_enc = EdwardsPoint::mul_base(&r).compress().to_bytes();
        let t = CompressedEdwardsY(*enc).decompress().unwrap();
        let m = grind(&format!("corpus 16: small-order A {i}"), |m| {
            (challenge(&r_enc, enc, m) * t).is_identity()
        });
        push(
            format!("small-order A: {what}; R = r·B, s = r"),
            *enc,
            m,
            sig_bytes(&r_enc, &r.to_bytes()),
            (false, true, true),
        );
    }
    // The classic one: A = R = identity, s = 0 verifies every message
    // under a non-strict cofactorless check.
    push(
        "small-order A and R: both the identity, s = 0 (verifies any message non-strictly)".into(),
        identity_enc,
        b"corpus 16: any message at all".to_vec(),
        sig_bytes(&identity_enc, &zero),
        (false, true, true),
    );
    {
        let (what, enc) = &small[2]; // order 4, canonical
        let t = CompressedEdwardsY(*enc).decompress().unwrap();
        let r_point = EIGHT_TORSION[6];
        let r_enc = r_point.compress().to_bytes();
        let m = grind("corpus 16: small-order A and R", |m| {
            -(challenge(&r_enc, enc, m) * t) == r_point
        });
        push(
            format!("small-order A ({what}) and small-order R (order 4), s = 0"),
            *enc,
            m,
            sig_bytes(&r_enc, &zero),
            (false, true, true),
        );
    }
    {
        let (what, enc) = &small[9]; // order 2 with the sign bit
        let t = CompressedEdwardsY(*enc).decompress().unwrap();
        let m = grind("corpus 16: small-order A, R identity", |m| {
            (challenge(&identity_enc, enc, m) * t).is_identity()
        });
        push(
            format!("small-order A ({what}), R = the identity, s = 0"),
            *enc,
            m,
            sig_bytes(&identity_enc, &zero),
            (false, true, true),
        );
    }

    // ---- small-order R with an honest key: s = k·a, so [s]B - [k]A is
    // the identity. A cofactored check accepts every one; a cofactorless
    // one only the canonical identity encoding.
    for (i, (what, enc)) in small.iter().enumerate() {
        let m = format!("corpus 16: small-order R {i}").into_bytes();
        let k = challenge(enc, &a_enc, &m);
        push(
            format!("small-order R: {what}; honest A, s = k·a"),
            a_enc,
            m,
            sig_bytes(enc, &(k * a).to_bytes()),
            (false, i == 0, true),
        );
    }

    // ---- mixed-order public key A = a·B + T. verify_strict refuses only
    // small-order points, so a mixed-order key verifies when k·T is the
    // identity (the message is ground for it), and not otherwise.
    for (ti, order) in [(4usize, 2), (2, 4), (1, 8)] {
        let am = scalar(&format!("corpus 16 mixed A {ti}"));
        let pa = EdwardsPoint::mul_base(&am) + EIGHT_TORSION[ti];
        assert!(!pa.is_small_order() && !pa.is_torsion_free());
        let am_enc = pa.compress().to_bytes();
        let r = scalar(&format!("corpus 16 mixed A nonce {ti}"));
        let r_enc = EdwardsPoint::mul_base(&r).compress().to_bytes();
        let m = grind(&format!("corpus 16: mixed-order A {ti}"), |m| {
            (challenge(&r_enc, &am_enc, m) * EIGHT_TORSION[ti]).is_identity()
        });
        push(
            format!("mixed-order A (prime-order + order {order}), k·T = identity: verify_strict accepts"),
            am_enc,
            m.clone(),
            sign_with(&am, &am_enc, &r, &r_enc, &m),
            (true, true, true),
        );
        if order == 8 {
            let m = grind("corpus 16: mixed-order A, k·T not the identity", |m| {
                !(challenge(&r_enc, &am_enc, m) * EIGHT_TORSION[ti]).is_identity()
            });
            push(
                "mixed-order A (prime-order + order 8), k·T not the identity".into(),
                am_enc,
                m.clone(),
                sign_with(&am, &am_enc, &r, &r_enc, &m),
                (false, false, true),
            );
        }
    }
    // ---- mixed-order R.
    {
        let r = scalar("corpus 16 mixed R");
        let pr = EdwardsPoint::mul_base(&r) + EIGHT_TORSION[1];
        let r_enc = pr.compress().to_bytes();
        let m = b"corpus 16: mixed-order R".to_vec();
        push(
            "mixed-order R (r·B + order 8), honest A, s = r + k·a".into(),
            a_enc,
            m.clone(),
            sign_with(&a, &a_enc, &r, &r_enc, &m),
            (false, false, true),
        );
        // Both mixed, torsion cancelling: neither point is of small order,
        // so verify_strict accepts.
        let am = scalar("corpus 16 mixed A and R");
        let ta = EIGHT_TORSION[3];
        let am_enc = (EdwardsPoint::mul_base(&am) + ta).compress().to_bytes();
        let tr = EIGHT_TORSION[5];
        let r2 = EdwardsPoint::mul_base(&r) + tr;
        let r2_enc = r2.compress().to_bytes();
        let m = grind("corpus 16: mixed-order A and R", |m| {
            -(challenge(&r2_enc, &am_enc, m) * ta) == tr
        });
        push(
            "mixed-order A and mixed-order R whose torsion cancels: verify_strict accepts".into(),
            am_enc,
            m.clone(),
            sign_with(&am, &am_enc, &r, &r2_enc, &m),
            (true, true, true),
        );
    }

    // ---- R or A that does not decode, and A with y >= p that decodes to
    // a point of large order (accepted as a key by every decoder here; no
    // one can sign for it, so these only check that nothing breaks).
    let (non_canonical, undecodable) = odd_encodings();
    push(
        "R does not decode (y not on the curve), honest A and s".into(),
        a_enc,
        m1.clone(),
        sig_bytes(&undecodable[0], &s_honest),
        (false, false, false),
    );
    push(
        "A does not decode (y not on the curve)".into(),
        undecodable[0],
        m1.clone(),
        honest,
        (false, false, false),
    );
    push(
        "A with y >= p (non-canonical) decoding to a point of large order".into(),
        non_canonical[0],
        m1.clone(),
        honest,
        (false, false, false),
    );
    push(
        "A with y >= p (non-canonical), sign bit set, decoding to a point of large order".into(),
        with_sign_bit(non_canonical[0]),
        m1.clone(),
        honest,
        (false, false, false),
    );
    {
        // R = r·B, s = r under the non-canonical A: [s]B - [k]A is not R.
        let r = scalar("corpus 16 non-canonical A");
        let r_enc = EdwardsPoint::mul_base(&r).compress().to_bytes();
        push(
            "A with y >= p (non-canonical), R = r·B, s = r".into(),
            non_canonical[0],
            m1.clone(),
            sig_bytes(&r_enc, &r.to_bytes()),
            (false, false, false),
        );
    }
    out
}

// ------------------------------------------------------------- dossiers

fn leaf(index: u64, session: &str) -> Leaf {
    Leaf {
        index,
        leaf_type: LeafType::ActiveIntent.tag(),
        timestamp_ms: T0 + index * 1000,
        session_pubkey: session.to_string(),
        payload_hash: hex::encode([0x60 + index as u8; 32]),
        redacted_index: None,
        revoked_identity: None,
        handoff_direction: None,
        counterparty_pubkey: None,
        handoff_state_hash: None,
        authorization_event_kind: None,
        authorization_scope_hash: None,
        anchor_url: None,
        anchor_proof_json: None,
        anchor_proof_hash: None,
    }
}

fn root_of(leaves: &[Leaf]) -> [u8; 32] {
    let mut t = MerkleTree::new();
    for l in leaves {
        t.append(leaf_hash(&l.canonical_bytes()));
    }
    t.root()
}

fn lp(buf: &mut Vec<u8>, b: &[u8]) {
    buf.extend_from_slice(&(b.len() as u32).to_be_bytes());
    buf.extend_from_slice(b);
}

/// SPEC.md §6's checkpoint message.
fn sth_message(signer_hex: &str, tree_size: u64, root: &[u8; 32], ts: u64) -> Vec<u8> {
    let mut m = b"witness-log-sth-v2".to_vec();
    lp(&mut m, b"ed25519");
    lp(&mut m, signer_hex.as_bytes());
    m.extend_from_slice(&tree_size.to_be_bytes());
    m.extend_from_slice(root);
    m.extend_from_slice(&ts.to_be_bytes());
    m
}

/// SPEC.md §5's key binding message.
fn binding_message(identity: &[u8; 32], session: &[u8; 32], number: u64, ts: u64) -> Vec<u8> {
    let mut m = b"witness-log-key-bind-v1".to_vec();
    m.extend_from_slice(identity);
    m.extend_from_slice(session);
    m.extend_from_slice(&number.to_be_bytes());
    m.extend_from_slice(&ts.to_be_bytes());
    m.push(0);
    m
}

fn sth_with(signer_hex: &str, leaves: &[Leaf], ts: u64, sig: &[u8; 64]) -> SignedTreeHead {
    SignedTreeHead {
        tree_size: leaves.len() as u64,
        root_hash: hex::encode(root_of(leaves)),
        timestamp_ms: ts,
        sig_alg: "ed25519".into(),
        signer_pubkey: signer_hex.into(),
        signature: hex::encode(sig),
    }
}

fn dossier(identity_hex: &str, leaves: Vec<Leaf>, checkpoint: SignedTreeHead) -> Dossier {
    Dossier {
        identity_pubkey: identity_hex.into(),
        leaves,
        checkpoint,
        witness_receipts: vec![],
        witness_directory: WitnessDirectory::default(),
        key_bindings: vec![],
        revocations: vec![],
        fleet_anchor: None,
    }
}

fn entry(name: &str, org: &str, pubkey: &str) -> WitnessEntry {
    WitnessEntry {
        name: name.into(),
        operator_org: org.into(),
        url: format!("https://{name}.example"),
        pubkey: pubkey.into(),
        runtime: WitnessRuntime::Human,
        compute_provider: Some(format!("{name}-provider")),
        is_project_operated: false,
    }
}

/// `R = identity, s = k·a` over `m` for the key `a`: [s]B - [k]A is the
/// identity, so a cofactorless non-strict check accepts it for any message.
fn degenerate_r(a: &Scalar, a_enc: &[u8; 32], m: &[u8]) -> [u8; 64] {
    let identity = EIGHT_TORSION[0].compress().to_bytes();
    let k = challenge(&identity, a_enc, m);
    let sig = sig_bytes(&identity, &(k * a).to_bytes());
    assert!(!strict(a_enc, m, &sig) && cofactorless(a_enc, m, &sig));
    sig
}

/// A = R = identity, s = 0: verifies every message non-strictly.
fn trivial_forgery() -> ([u8; 32], [u8; 64]) {
    let identity = EIGHT_TORSION[0].compress().to_bytes();
    (identity, sig_bytes(&identity, &[0u8; 32]))
}

struct Case {
    name: &'static str,
    dossier: &'static str,
    directory: Option<&'static str>,
    min_witnesses: Option<usize>,
    evidence: Vec<&'static str>,
    intended_exit: u8,
}

fn case(name: &'static str, dossier: &'static str, intended_exit: u8) -> Case {
    Case {
        name,
        dossier,
        directory: None,
        min_witnesses: None,
        evidence: vec![],
        intended_exit,
    }
}

fn main() {
    // ---- the primitive vectors
    let mut signatures = Vec::new();
    for c in signature_cases() {
        let got = (
            strict(&c.a, &c.m, &c.sig),
            cofactorless(&c.a, &c.m, &c.sig),
            cofactored(&c.a, &c.m, &c.sig),
        );
        assert_eq!(
            got, c.intended,
            "{}: (strict, cofactorless, cofactored)",
            c.name
        );
        signatures.push(json!({
            "name": c.name,
            "public_key": hex::encode(c.a),
            "message": hex::encode(&c.m),
            "signature": hex::encode(c.sig),
            "valid": got.0,
            "cofactorless_non_strict": got.1,
            "cofactored_non_strict": got.2,
        }));
    }

    // ---- dossiers with degenerate signatures
    let identity = SigningKey::from_bytes(&IDENTITY_SEED);
    let a = identity.to_scalar();
    let a_enc = identity.verifying_key().to_bytes();
    let identity_hex = hex::encode(a_enc);
    let leaves: Vec<Leaf> = (0..2).map(|i| leaf(i, &identity_hex)).collect();
    let root = root_of(&leaves);
    let honest_sth = SignedTreeHead::sign(&identity, 2, &root, T0 + 10_000);
    {
        // sth_message is the message SignedTreeHead signs.
        let m = sth_message(&identity_hex, 2, &root, T0 + 10_000);
        assert_eq!(
            hex::encode(identity.sign(&m).to_bytes()),
            honest_sth.signature
        );
    }
    let honest = dossier(&identity_hex, leaves.clone(), honest_sth.clone());

    // A checkpoint "signed" by the identity point: R = identity, s = 0.
    let (id_point, forged) = trivial_forgery();
    let id_point_hex = hex::encode(id_point);
    let identity_point_checkpoint = dossier(
        &id_point_hex,
        vec![],
        sth_with(&id_point_hex, &[], T0 + 10_000, &forged),
    );

    // A checkpoint by an order-8 key: R = r·B, s = r, the timestamp ground
    // until k·A is the identity.
    let t8 = EIGHT_TORSION[1];
    let t8_enc = t8.compress().to_bytes();
    let t8_hex = hex::encode(t8_enc);
    let r = scalar("corpus 16 dossier small-order key");
    let r_enc = EdwardsPoint::mul_base(&r).compress().to_bytes();
    let empty_root = root_of(&[]);
    let ts = (0..10_000u64)
        .map(|i| T0 + 10_000 + i)
        .find(|ts| {
            let m = sth_message(&t8_hex, 0, &empty_root, *ts);
            (challenge(&r_enc, &t8_enc, &m) * t8).is_identity()
        })
        .unwrap();
    let small_key_checkpoint = dossier(
        &t8_hex,
        vec![],
        sth_with(&t8_hex, &[], ts, &sig_bytes(&r_enc, &r.to_bytes())),
    );

    // The identity's own key with R = identity, s = k·a.
    let small_r_checkpoint = dossier(
        &identity_hex,
        leaves.clone(),
        sth_with(
            &identity_hex,
            &leaves,
            T0 + 10_000,
            &degenerate_r(
                &a,
                &a_enc,
                &sth_message(&identity_hex, 2, &root, T0 + 10_000),
            ),
        ),
    );

    // A mixed-order key (a'·B + order 2) signing correctly: verify_strict
    // accepts it, so this one is valid everywhere.
    let am = scalar("corpus 16 dossier mixed-order key");
    let am_enc = (EdwardsPoint::mul_base(&am) + EIGHT_TORSION[4])
        .compress()
        .to_bytes();
    let am_hex = hex::encode(am_enc);
    let r = scalar("corpus 16 dossier mixed-order nonce");
    let r_enc = EdwardsPoint::mul_base(&r).compress().to_bytes();
    let ts = (0..10_000u64)
        .map(|i| T0 + 10_000 + i)
        .find(|ts| {
            let m = sth_message(&am_hex, 0, &empty_root, *ts);
            (challenge(&r_enc, &am_enc, &m) * EIGHT_TORSION[4]).is_identity()
        })
        .unwrap();
    let mixed_sig = sign_with(
        &am,
        &am_enc,
        &r,
        &r_enc,
        &sth_message(&am_hex, 0, &empty_root, ts),
    );
    let mixed_key_checkpoint = dossier(&am_hex, vec![], sth_with(&am_hex, &[], ts, &mixed_sig));

    // Receipts: one honest witness, one whose key is a small-order point
    // and whose receipt is the trivial forgery (native, then C2SP).
    let witness = SigningKey::from_bytes(&WITNESS_SEED);
    let witness_hex = hex::encode(witness.verifying_key().to_bytes());
    let good_receipt = WitnessReceipt::sign(&witness, &honest_sth, T0 + 11_000);
    let mut native = good_receipt.clone();
    native.witness_pubkey = id_point_hex.clone();
    native.signature = hex::encode(forged);
    let mut degenerate_native = honest.clone();
    degenerate_native.witness_receipts = vec![good_receipt.clone(), native];
    // The identity again, in another encoding (x = 0 with the sign bit).
    let id_neg = with_sign_bit(id_point);
    let id_neg_hex = hex::encode(id_neg);
    let c2sp_ts = T0 + 12_000;
    let c2sp = WitnessReceipt {
        witness_pubkey: id_neg_hex.clone(),
        tree_size: 2,
        root_hash: honest_sth.root_hash.clone(),
        witnessed_at_ms: c2sp_ts,
        signature: hex::encode(sig_bytes(&id_point, &[0u8; 32])),
        c2sp_origin: Some(canonical_origin(&identity.verifying_key())),
        witness_name: None,
    };
    {
        let body = Checkpoint {
            origin: canonical_origin(&identity.verifying_key()),
            tree_size: 2,
            root_hash: root,
            extensions: vec![],
        }
        .note_text()
        .unwrap();
        let m = Cosignature::message(c2sp_ts / 1000, &body);
        let sig: [u8; 64] = hex::decode(&c2sp.signature).unwrap().try_into().unwrap();
        assert!(!strict(&id_neg, m.as_bytes(), &sig) && cofactorless(&id_neg, m.as_bytes(), &sig));
    }
    let mut degenerate_c2sp = honest.clone();
    degenerate_c2sp.witness_receipts = vec![good_receipt, c2sp];
    let directories = json!({
        "native": WitnessDirectory { witnesses: vec![
            entry("corpus-16-witness-a", "corpus-16-operator-a", &witness_hex),
            entry("corpus-16-witness-b", "corpus-16-operator-b", &id_point_hex),
        ]},
        "c2sp": WitnessDirectory { witnesses: vec![
            entry("corpus-16-witness-a", "corpus-16-operator-a", &witness_hex),
            entry("corpus-16-witness-c", "corpus-16-operator-c", &id_neg_hex),
        ]},
    });

    // A key binding with R = identity, s = k·a, for the session key that
    // authored the leaves.
    let session = SigningKey::from_bytes(&SESSION_SEED);
    let session_enc = session.verifying_key().to_bytes();
    let session_hex = hex::encode(session_enc);
    let session_leaves: Vec<Leaf> = (0..2).map(|i| leaf(i, &session_hex)).collect();
    let session_root = root_of(&session_leaves);
    let mut binding = KeyBindingStatement {
        identity_pubkey: identity_hex.clone(),
        session_pubkey: session_hex.clone(),
        session_number: 1,
        timestamp_ms: T0 - 1000,
        custody: KeyCustody::SelfHeld,
        not_after_ms: None,
        signature: String::new(),
    };
    let bm = binding_message(&a_enc, &session_enc, 1, T0 - 1000);
    binding.signature = hex::encode(identity.sign(&bm).to_bytes());
    assert!(
        binding.verify().is_ok(),
        "binding_message is the signed message"
    );
    binding.signature = hex::encode(degenerate_r(&a, &a_enc, &bm));
    let mut degenerate_binding = dossier(
        &identity_hex,
        session_leaves,
        SignedTreeHead::sign(&identity, 2, &session_root, T0 + 10_000),
    );
    degenerate_binding.key_bindings = vec![binding];

    // An honest binding for a session "key" that is not a curve point: the
    // reference decodes the session key and refuses the binding, though the
    // session key signs nothing. And one for a small-order session key,
    // which decodes, so the binding stands.
    let session_binding = |session_enc: [u8; 32]| {
        let session_hex = hex::encode(session_enc);
        let leaves: Vec<Leaf> = (0..2).map(|i| leaf(i, &session_hex)).collect();
        let root = root_of(&leaves);
        let sig = identity.sign(&binding_message(&a_enc, &session_enc, 1, T0 - 1000));
        let mut d = dossier(
            &identity_hex,
            leaves,
            SignedTreeHead::sign(&identity, 2, &root, T0 + 10_000),
        );
        d.key_bindings = vec![KeyBindingStatement {
            identity_pubkey: identity_hex.clone(),
            session_pubkey: session_hex,
            session_number: 1,
            timestamp_ms: T0 - 1000,
            custody: KeyCustody::SelfHeld,
            not_after_ms: None,
            signature: hex::encode(sig.to_bytes()),
        }];
        d
    };
    let (_, undecodable) = odd_encodings();
    let undecodable_session = session_binding(undecodable[0]);
    let small_order_session = session_binding(EIGHT_TORSION[0].compress().to_bytes());

    // A revocation, long after the checkpoint, with R = identity, s = k·a.
    let as_of = T0 + 1_000_000;
    let rm = witness_log_core::identity::revocation_message(&a_enc, as_of, None, "corpus 16");
    let revocation = RevocationStatement {
        identity_pubkey: identity_hex.clone(),
        as_of_ms: as_of,
        as_of_index: None,
        reason: "corpus 16".into(),
        signature: hex::encode(degenerate_r(&a, &a_enc, &rm)),
    };
    let mut degenerate_revocation = dossier(
        &identity_hex,
        vec![],
        SignedTreeHead::sign(&identity, 0, &empty_root, T0 + 10_000),
    );
    degenerate_revocation.revocations = vec![revocation];

    // An equivocation proof whose two notes carry R = identity, s = k·a.
    let origin = canonical_origin(&identity.verifying_key());
    let id = key_id(&origin, SIG_TYPE_ED25519, &a_enc);
    let note = |root: &[u8; 32]| {
        let text = format!("{origin}\n2\n{}\n", Base64::encode_string(root));
        let mut payload = id.to_vec();
        payload.extend_from_slice(&degenerate_r(&a, &a_enc, text.as_bytes()));
        format!(
            "{text}\n{EM_DASH} {origin} {}\n",
            Base64::encode_string(&payload)
        )
    };
    let mut material = vec![SIG_TYPE_ED25519];
    material.extend_from_slice(&a_enc);
    let degenerate_proof = json!({
        "origin": origin,
        "log_vkey": format!("{origin}+{}+{}", hex::encode(id), Base64::encode_string(&material)),
        "earlier_note": note(&Sha256::digest(b"history A").into()),
        "conflicting_note": note(&Sha256::digest(b"history B").into()),
    });
    let evidence = json!({ "degenerate_notes": degenerate_proof });

    let dossiers = json!({
        "honest": honest,
        "identity_point_checkpoint": identity_point_checkpoint,
        "small_order_key_checkpoint": small_key_checkpoint,
        "small_order_r_checkpoint": small_r_checkpoint,
        "mixed_order_key_checkpoint": mixed_key_checkpoint,
        "degenerate_native_receipt": degenerate_native,
        "degenerate_c2sp_receipt": degenerate_c2sp,
        "degenerate_key_binding": degenerate_binding,
        "degenerate_revocation": degenerate_revocation,
        "undecodable_session_key": undecodable_session,
        "small_order_session_key": small_order_session,
    });
    let cases = vec![
        case("honest dossier", "honest", 20),
        case(
            "checkpoint by the identity point (A = R = identity, s = 0)",
            "identity_point_checkpoint",
            40,
        ),
        case(
            "checkpoint by an order-8 key (R = r·B, s = r)",
            "small_order_key_checkpoint",
            40,
        ),
        case(
            "checkpoint by an honest key with R = identity, s = k·a",
            "small_order_r_checkpoint",
            40,
        ),
        case(
            "checkpoint by a mixed-order key, signed correctly (valid)",
            "mixed_order_key_checkpoint",
            20,
        ),
        Case {
            directory: Some("native"),
            min_witnesses: Some(2),
            ..case(
                "native receipt by a small-order witness key does not count",
                "degenerate_native_receipt",
                10,
            )
        },
        Case {
            directory: Some("c2sp"),
            min_witnesses: Some(2),
            ..case(
                "C2SP cosignature by a small-order witness key does not count",
                "degenerate_c2sp_receipt",
                10,
            )
        },
        case(
            "key binding with R = identity, s = k·a",
            "degenerate_key_binding",
            40,
        ),
        case(
            "revocation with R = identity, s = k·a",
            "degenerate_revocation",
            40,
        ),
        case(
            "key binding for a session key that is not a curve point",
            "undecodable_session_key",
            40,
        ),
        case(
            "key binding for a small-order session key (it signs nothing: valid)",
            "small_order_session_key",
            20,
        ),
        Case {
            evidence: vec!["degenerate_notes"],
            ..case(
                "equivocation proof whose notes have R = identity, s = k·a is not evidence",
                "honest",
                20,
            )
        },
    ];

    let mut out_cases = Vec::new();
    for c in &cases {
        let d: Dossier = serde_json::from_value(dossiers[c.dossier].clone()).unwrap();
        let trusted: Option<WitnessDirectory> = c
            .directory
            .map(|n| serde_json::from_value(directories[n].clone()).unwrap());
        let proofs: Vec<EquivocationProof> = c
            .evidence
            .iter()
            .map(|k| EquivocationProof::from_evidence(&evidence[*k]).unwrap())
            .collect();
        let ctx = VerifyContext {
            expected_identity_pubkey: None,
            trusted_directory: trusted.as_ref(),
            min_receipts: c.min_witnesses,
            revocations: &[],
            known_heads: &[],
            evidence: &proofs,
            subject_org: None,
            accept_fleet_anchor: false,
        };
        let r = d.verify(0.66, &ctx);
        let exit_code = if r.split_view_unsafe {
            11
        } else {
            match r.verdict {
                Verdict::Witnessed => 0,
                Verdict::ConsistentUnwitnessed => 10,
                Verdict::Unanchored => 20,
                Verdict::Diverged => 30,
                Verdict::Invalid => 40,
            }
        };
        assert_eq!(
            exit_code, c.intended_exit,
            "{}: the reference no longer gives the intended exit ({:?})",
            c.name, r.failures
        );
        out_cases.push(json!({
            "name": c.name,
            "dossier": c.dossier,
            "directory": c.directory,
            "expected_identity": null,
            "threshold": 0.66,
            "min_witnesses": c.min_witnesses,
            "known_heads": [],
            "evidence": c.evidence,
            "allow_sub_majority": false,
            "subject_org": null,
            "expect": {
                "verdict": r.verdict,
                "exit_code": exit_code,
                "split_view_unsafe": r.split_view_unsafe,
                "internally_consistent": r.internally_consistent,
                "has_failures": !r.failures.is_empty(),
                "contradictions": r.contradictions.len(),
                "known_heads_unchecked": r.known_heads_unchecked.len(),
                "valid_receipts": r.quorum.as_ref().map(|q| q.valid_receipts),
                "independent_operators": r.quorum.as_ref().map(|q| q.distinct_independent_operators),
            },
        }));
    }

    let doc = json!({
        "description": "Strict Ed25519 (SPEC.md §6; outside review III, H3/M3). \
            `signatures`: run every entry through the Ed25519 check your verifier uses for \
            checkpoint, key binding, revocation, receipt and signed-note signatures, with the \
            hex public_key (32 bytes), message and signature (64 bytes); the result must equal \
            `valid`, which is what the reference's check returns: VerifyingKey::from_bytes \
            (A must decode; y >= p and x = 0 with the sign bit set are decoded, as in RFC 8032 \
            implementations generally) then ed25519-dalek 2's verify_strict: s < L, R must \
            decode, A and R must not be of small order (in any encoding), [s]B - [k]A with \
            k = SHA-512(R || A || M) over the encodings as given must encode to exactly R's \
            bytes. Mixed-order points are not refused. `cofactorless_non_strict` and \
            `cofactored_non_strict` say what RFC 8032 without the small-order checks would \
            answer, for the reader; they are not expectations. `cases`: run each as in \
            15_evidence_and_args.json, with the named dossier, the named trusted directory \
            from `directories` (none when null), threshold, min_witnesses and the named \
            evidence items; the verdict, exit code and report fields must equal expect. \
            Every key here is public and for testing only.",
        "signatures": signatures,
        "directories": directories,
        "dossiers": dossiers,
        "evidence": evidence,
        "cases": out_cases,
    });
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../corpus")
        .join("16_ed25519_strict.json");
    std::fs::write(&path, serde_json::to_string_pretty(&doc).unwrap() + "\n").unwrap();
    println!("wrote {}", path.display());
}
