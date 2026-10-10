//! Reference agent witness.
//!
//! This is what "an agent can be a witness" actually looks like as running
//! code, not just a claim: a loop that holds the last checkpoint it
//! trusted, receives a new one, demands a consistency proof, verifies it
//! *before* signing anything, and refuses outright if the proof doesn't
//! hold. Run with:
//!
//!   cargo run -p witness-log-network --example agent_witness
//!
//! A real deployment would poll an HTTP endpoint instead of calling a local
//! function, and publish receipts somewhere the log operator can't reach
//! (a public git repo, a separate service, another organization's
//! infrastructure) rather than printing them — see GOVERNANCE.md's witness
//! recruitment section for what "somewhere independent" needs to mean in
//! practice. The verification logic here — the part that actually matters
//! for trust — is real and complete.

use ed25519_dalek::SigningKey;
use std::time::{SystemTime, UNIX_EPOCH};
use witness_log_core::identity::IdentityKeypair;
use witness_log_core::log::WitnessLog;
use witness_log_core::merkle::verify_consistency;
use witness_log_core::sth::SignedTreeHead;
use witness_log_network::WitnessReceipt;

/// Everything an autonomous witness needs to remember between checks:
/// just the last checkpoint it trusted. Note this is deliberately tiny —
/// an agent witness does not need to store the target's leaves or full
/// tree, only the last root and size it vouched for.
struct AgentWitness {
    witness_key: SigningKey,
    last_trusted: Option<SignedTreeHead>,
    receipts_issued: u64,
    refusals: u64,
}

enum WitnessOutcome {
    Signed(WitnessReceipt),
    /// The proposed checkpoint failed the consistency check against the
    /// last one this witness trusted. This is the entire point of the
    /// exercise: a real refusal, not a formality.
    RefusedInconsistent {
        reason: String,
    },
}

impl AgentWitness {
    fn new(witness_key: SigningKey) -> Self {
        Self {
            witness_key,
            last_trusted: None,
            receipts_issued: 0,
            refusals: 0,
        }
    }

    /// Called every polling cycle with the target's current checkpoint and
    /// a consistency proof from the last checkpoint this witness trusted
    /// (or from tree_size 0, on the very first check).
    fn observe(
        &mut self,
        new_sth: &SignedTreeHead,
        consistency: &[witness_log_core::merkle::Hash],
    ) -> WitnessOutcome {
        if new_sth.verify().is_err() {
            self.refusals += 1;
            return WitnessOutcome::RefusedInconsistent {
                reason: "checkpoint signature itself is invalid".into(),
            };
        }

        let (old_size, old_root_hex) = match &self.last_trusted {
            Some(prev) => (prev.tree_size, prev.root_hash.clone()),
            None => (0u64, hex::encode([0u8; 32])), // sentinel; unused when old_size == 0
        };

        let old_root: [u8; 32] = if old_size == 0 {
            [0u8; 32]
        } else {
            hex::decode(old_root_hex).unwrap().try_into().unwrap()
        };
        let new_root: [u8; 32] = hex::decode(&new_sth.root_hash).unwrap().try_into().unwrap();

        let consistent = verify_consistency(
            old_size,
            &old_root,
            new_sth.tree_size,
            &new_root,
            consistency,
        );
        if !consistent {
            self.refusals += 1;
            return WitnessOutcome::RefusedInconsistent {
                reason: format!(
                    "checkpoint at tree_size {} is NOT a valid append-only extension of the last trusted checkpoint at tree_size {} — refusing to sign",
                    new_sth.tree_size, old_size
                ),
            };
        }

        let receipt = WitnessReceipt::sign(&self.witness_key, new_sth, now_ms());
        self.last_trusted = Some(new_sth.clone());
        self.receipts_issued += 1;
        WitnessOutcome::Signed(receipt)
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

fn main() {
    let identity = IdentityKeypair::generate();
    let identity_bytes = identity.to_bytes();
    let mut target_log = WitnessLog::resume(identity, 0);
    let target_signing_key = SigningKey::from_bytes(&identity_bytes);

    let witness_key = SigningKey::generate(&mut rand::rngs::OsRng);
    let mut witness = AgentWitness::new(witness_key);

    println!("=== Agent witness: honest polling loop ===\n");

    // Cycle 1: target appends a couple of leaves, checkpoints, witness
    // checks in for the first time (old_size == 0, trivially consistent).
    target_log.append_intent(b"cycle 1: intent");
    target_log.append_result(b"cycle 1: result");
    let sth1 = target_log.checkpoint(&target_signing_key);
    let proof1 = vec![]; // old_size == 0 always yields an empty consistency proof
    match witness.observe(&sth1, &proof1) {
        WitnessOutcome::Signed(r) => println!(
            "cycle 1: SIGNED receipt for tree_size={} root={}...",
            r.tree_size,
            &r.root_hash[..12]
        ),
        WitnessOutcome::RefusedInconsistent { reason } => {
            println!("cycle 1: unexpectedly refused: {reason}")
        }
    }

    // Cycle 2: target appends more, checkpoints again. This time the
    // witness demands a REAL consistency proof from tree_size 3 -> 5.
    target_log.append_intent(b"cycle 2: intent");
    target_log.append_result(b"cycle 2: result");
    let sth2 = target_log.checkpoint(&target_signing_key);
    // In a real deployment this proof comes from the target's own storage
    // (it has the full leaf history); here we rebuild an equivalent tree
    // locally purely to demonstrate what the target would serve.
    let proof2 = rebuild_and_prove(&target_log, sth1.tree_size, sth2.tree_size);
    match witness.observe(&sth2, &proof2) {
        WitnessOutcome::Signed(r) => println!(
            "cycle 2: SIGNED receipt for tree_size={} root={}...",
            r.tree_size,
            &r.root_hash[..12]
        ),
        WitnessOutcome::RefusedInconsistent { reason } => {
            println!("cycle 2: unexpectedly refused: {reason}")
        }
    }

    // Cycle 3: simulate a DISHONEST operator presenting a checkpoint for a
    // tree that does NOT actually extend the last trusted one — e.g. it
    // was quietly rewritten. The witness must refuse.
    println!("\n=== Simulating a dishonest checkpoint (rewritten history) ===\n");
    let fake_root = [0x42u8; 32];
    let fake_sth = SignedTreeHead::sign(
        &target_signing_key,
        sth2.tree_size + 2,
        &fake_root,
        now_ms(),
    );
    // An honest consistency proof for THIS fake root doesn't exist, so the
    // dishonest operator can only submit a proof for a DIFFERENT (honest)
    // continuation, or an empty/garbage one. Either way it won't verify
    // against fake_sth's root. We simulate the honest-but-mismatched case:
    let mismatched_proof = rebuild_and_prove(&target_log, sth2.tree_size, sth2.tree_size); // wrong shape on purpose
    match witness.observe(&fake_sth, &mismatched_proof) {
        WitnessOutcome::Signed(_) => {
            println!("cycle 3: INCORRECTLY signed a dishonest checkpoint — this would be a bug")
        }
        WitnessOutcome::RefusedInconsistent { reason } => {
            println!("cycle 3: correctly REFUSED — {reason}")
        }
    }

    println!(
        "\nSummary: {} receipts issued, {} refusals, last trusted tree_size = {}",
        witness.receipts_issued,
        witness.refusals,
        witness
            .last_trusted
            .as_ref()
            .map(|s| s.tree_size)
            .unwrap_or(0)
    );
}

/// Stand-in for "fetch a consistency proof from the target." A real
/// witness would call the target's API; here we have direct access to the
/// same process's log, which is only true because this is a demo.
fn rebuild_and_prove(
    log: &WitnessLog,
    first: u64,
    second: u64,
) -> Vec<witness_log_core::merkle::Hash> {
    use witness_log_core::merkle::{leaf_hash, MerkleTree};
    let mut tree = MerkleTree::new();
    for l in log.leaves() {
        tree.append(leaf_hash(&l.canonical_bytes()));
    }
    tree.consistency_proof(first, second).unwrap_or_default()
}
