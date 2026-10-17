//! A dossier whose receipts came from real `tlog-witness` cosignatures
//! must reach `Witnessed`. Before 0.3.1 it could not: cosignature-derived
//! receipts were re-verified with the native receipt message and silently
//! dropped, so no third-party witness could ever count.

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use witness_log_core::c2sp::{bridge, VerifierKey};
use witness_log_core::identity::IdentityKeypair;
use witness_log_core::log::WitnessLog;
use witness_log_network::tlog_witness::*;
use witness_log_network::*;

struct W {
    name: String,
    key: SigningKey,
    svc: WitnessService,
}

fn setup(n: usize) -> (WitnessLog, SigningKey, String, Vec<W>) {
    let identity = IdentityKeypair::generate();
    let key = SigningKey::from_bytes(&identity.to_bytes());
    let mut log = WitnessLog::resume(identity, 0);
    for i in 0..5u8 {
        log.append_intent(&[i]);
    }
    let origin = witness_log_core::c2sp::canonical_origin(&key.verifying_key());
    let ws = (0..n)
        .map(|i| {
            let mut svc = WitnessService::new();
            svc.add_log(&origin, bridge::log_vkey(&origin, &key.verifying_key()));
            W {
                name: format!("w{i}.example/witness"),
                key: SigningKey::generate(&mut OsRng),
                svc,
            }
        })
        .collect();
    (log, key, origin, ws)
}

fn cosign_all(
    log: &WitnessLog,
    key: &SigningKey,
    origin: &str,
    ws: &mut [W],
    now_s: u64,
) -> (Dossier, WitnessDirectory) {
    let cp = log.c2sp_checkpoint(origin);
    let native = log.checkpoint(key);
    let mut receipts = vec![];
    let mut dir = WitnessDirectory::default();
    for (i, w) in ws.iter_mut().enumerate() {
        let req = AddCheckpointRequest {
            old_size: w.svc.known_log(origin).map_or(0, |k| k.tree_size),
            consistency_proof: vec![],
            checkpoint_note: cp.sign(key).unwrap(),
        };
        let AddCheckpointOutcome::Cosigned { cosignature, .. } =
            w.svc.handle_add_checkpoint(&req, &w.name, &w.key, now_s)
        else {
            panic!("witness {i} refused")
        };
        let vk = VerifierKey::for_cosignature(&w.name, &w.key.verifying_key());
        receipts.push(
            cosignature_to_receipt(&cosignature, &vk, &cp, &native)
                .unwrap()
                .receipt,
        );
        dir.witnesses.push(WitnessEntry::independent(
            &w.name,
            format!("Org {i}"),
            "http://localhost",
            hex::encode(w.key.verifying_key().to_bytes()),
            Some(format!("cloud-{i}")),
        ));
    }
    let d = Dossier::from_log(log, native).with_receipts(receipts);
    (d, dir)
}

fn now_s() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

#[test]
fn cosigned_dossier_reaches_witnessed() {
    let (log, key, origin, mut ws) = setup(3);
    let (d, dir) = cosign_all(&log, &key, &origin, &mut ws, now_s());
    let ident = hex::encode(key.verifying_key().to_bytes());
    let ctx = VerifyContext {
        expected_identity_pubkey: Some(&ident),
        trusted_directory: Some(&dir),
        min_receipts: None,
        revocations: &[],
        known_heads: &[],
        evidence: &[],
        subject_org: None,
    };
    let r = d.verify(0.66, &ctx);
    assert_eq!(r.verdict, Verdict::Witnessed, "{r:#?}");

    // Survives a JSON round trip -- this is what actually gets shared.
    let d2: Dossier = serde_json::from_str(&serde_json::to_string(&d).unwrap()).unwrap();
    assert_eq!(d2.verify(0.66, &ctx).verdict, Verdict::Witnessed);
}

#[test]
fn tampered_cosigned_receipts_do_not_count() {
    let (log, key, origin, mut ws) = setup(3);
    let (d, dir) = cosign_all(&log, &key, &origin, &mut ws, now_s());
    let ident = hex::encode(key.verifying_key().to_bytes());
    let ctx = VerifyContext {
        expected_identity_pubkey: Some(&ident),
        trusted_directory: Some(&dir),
        min_receipts: None,
        revocations: &[],
        known_heads: &[],
        evidence: &[],
        subject_org: None,
    };
    // Each mutation must knock the verdict below Witnessed.
    type Mutation = Box<dyn Fn(&mut WitnessReceipt)>;
    let mutations: Vec<(&str, Mutation)> = vec![
        ("time", Box::new(|r| r.witnessed_at_ms += 1000)),
        ("sub-second time", Box::new(|r| r.witnessed_at_ms += 1)),
        (
            "origin",
            Box::new(|r| r.c2sp_origin = Some("evil.example/log".into())),
        ),
        (
            "sig",
            Box::new(|r| {
                let mut s = hex::decode(&r.signature).unwrap();
                s[0] ^= 1;
                r.signature = hex::encode(s);
            }),
        ),
        ("strip c2sp", Box::new(|r| r.c2sp_origin = None)),
    ];
    for (what, m) in mutations {
        let mut bad = d.clone();
        for r in &mut bad.witness_receipts {
            m(r);
        }
        let v = bad.verify(0.66, &ctx).verdict;
        assert_ne!(v, Verdict::Witnessed, "mutation `{what}` still Witnessed");
    }
}

#[test]
fn cosignature_for_a_non_canonical_origin_does_not_count() {
    // A log may use any origin with a witness, but only the origin derived
    // from its identity key counts toward a verdict -- otherwise one agent
    // could show different forks to witnesses under different names.
    let (log, key, _, mut ws) = setup(3);
    let origin = "agents.example.com/custom";
    for w in &mut ws {
        w.svc
            .add_log(origin, bridge::log_vkey(origin, &key.verifying_key()));
    }
    let (d, dir) = cosign_all(&log, &key, origin, &mut ws, now_s());
    let ident = hex::encode(key.verifying_key().to_bytes());
    let ctx = VerifyContext {
        expected_identity_pubkey: Some(&ident),
        trusted_directory: Some(&dir),
        min_receipts: None,
        revocations: &[],
        known_heads: &[],
        evidence: &[],
        subject_org: None,
    };
    assert_ne!(d.verify(0.66, &ctx).verdict, Verdict::Witnessed);
}
