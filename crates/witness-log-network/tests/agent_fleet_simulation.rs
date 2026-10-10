//! A 100-agent concurrent simulation.
//!
//! Single-agent tests cannot reach the code paths that matter most in
//! production: cross-agent handoff binding, a reciprocal witness mesh
//! where agents cosign each other, diversity scoring over a realistic
//! operator distribution, and adversaries operating inside an otherwise
//! honest fleet. This exercises all of it, on real OS threads, and
//! asserts invariants rather than merely checking nothing crashed.
//!
//! Design notes that make this find bugs rather than pass vacuously:
//!
//! - **Real threads.** Agents run concurrently, so `Send`/`Sync`
//!   problems and any accidental shared state surface here rather than
//!   in someone's async runtime.
//! - **Failures are collected, not fatal.** A panic on the first bad
//!   invariant would hide every later one. The run completes, then
//!   reports every violation at once.
//! - **Adversaries are realistic.** They don't submit malformed
//!   garbage — they produce cryptographically valid artifacts that are
//!   *lies*: a forged identity claim, a self-authored witness
//!   directory, a genuine equivocating fork. That is the threat this
//!   project exists for.

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use witness_log_core::identity::IdentityKeypair;
use witness_log_core::leaf::{verify_handoff_binding, Leaf};
use witness_log_core::log::WitnessLog;
use witness_log_core::sth::SignedTreeHead;
use witness_log_network::*;

const FLEET_SIZE: usize = 100;
const ACTIONS_PER_AGENT: usize = 20;
/// Operators are shared across agents, as in reality: many agents run
/// under few operators. This is what makes diversity scoring meaningful
/// rather than trivially 100%.
const OPERATOR_COUNT: usize = 12;
const COMPUTE_PROVIDERS: &[&str] = &["aws", "gcp", "azure", "fly.io", "on-prem", "hetzner"];

/// Collects every invariant violation across the whole run so one
/// failure doesn't mask the rest.
#[derive(Default)]
struct Findings {
    errors: Vec<String>,
}

impl Findings {
    fn check(&mut self, condition: bool, msg: impl Into<String>) {
        if !condition {
            self.errors.push(msg.into());
        }
    }
    fn report(&self, label: &str) {
        if self.errors.is_empty() {
            println!("  ✓ {label}: no violations");
            return;
        }
        println!("  ✗ {label}: {} violation(s)", self.errors.len());
        for (i, e) in self.errors.iter().enumerate().take(25) {
            println!("      {}. {e}", i + 1);
        }
        if self.errors.len() > 25 {
            println!("      ... and {} more", self.errors.len() - 25);
        }
    }
}

struct Agent {
    index: usize,
    identity_bytes: [u8; 32],
    identity_hex: String,
    operator_org: String,
    compute_provider: String,
    log: WitnessLog,
}

impl Agent {
    fn new(index: usize) -> Self {
        let identity = IdentityKeypair::generate();
        let identity_bytes = identity.to_bytes();
        let identity_hex = identity.public_hex();
        Self {
            index,
            identity_bytes,
            identity_hex,
            operator_org: format!("operator-{:02}", index % OPERATOR_COUNT),
            compute_provider: COMPUTE_PROVIDERS
                .get(index % COMPUTE_PROVIDERS.len())
                .copied()
                .unwrap_or("unknown")
                .to_string(),
            log: WitnessLog::resume(IdentityKeypair::from_bytes(&identity_bytes), 0),
        }
    }

    fn signing_key(&self) -> SigningKey {
        SigningKey::from_bytes(&self.identity_bytes)
    }

    /// Realistic agent activity: intents, results, a memory, and a
    /// redaction partway through.
    fn do_work(&mut self) {
        for i in 0..ACTIONS_PER_AGENT {
            match i % 4 {
                0 => {
                    self.log.append_intent(
                        format!(r#"{{"tool":"fetch","args":{{"n":{i}}}}}"#).as_bytes(),
                    );
                }
                1 => {
                    self.log
                        .append_result(format!(r#"{{"status":"ok","seq":{i}}}"#).as_bytes());
                }
                2 => {
                    let idx = self
                        .log
                        .append_memory(format!("contact-{}@example.com", self.index).as_bytes());
                    // Exercise redaction under concurrency on half the fleet.
                    if self.index % 2 == 0 {
                        self.log.forget(idx);
                    }
                }
                _ => {
                    self.log
                        .append_intent(format!(r#"{{"tool":"write","seq":{i}}}"#).as_bytes());
                }
            }
        }
    }
}

/// Phase 1: build the fleet concurrently and have every agent do work.
/// Returns agents plus the time taken, so a pathological slowdown shows
/// up as a number rather than a hang.
fn build_fleet() -> Vec<Agent> {
    let start = std::time::Instant::now();
    let handles: Vec<_> = (0..FLEET_SIZE)
        .map(|i| {
            std::thread::spawn(move || {
                let mut agent = Agent::new(i);
                agent.do_work();
                agent
            })
        })
        .collect();
    let mut agents: Vec<Agent> = handles.into_iter().filter_map(|h| h.join().ok()).collect();
    agents.sort_by_key(|a| a.index);
    println!(
        "  built {} agents x {} actions concurrently in {:?}",
        agents.len(),
        ACTIONS_PER_AGENT,
        start.elapsed()
    );
    agents
}

#[test]
fn fleet_of_100_agents_behaves_correctly_under_concurrency() {
    println!("\n╔══ 100-AGENT FLEET SIMULATION ══\n");

    // ---- Phase 1: concurrent fleet construction -------------------
    let mut agents = build_fleet();
    let mut f = Findings::default();
    f.check(
        agents.len() == FLEET_SIZE,
        format!("expected {FLEET_SIZE} agents, got {}", agents.len()),
    );
    for a in &agents {
        f.check(
            a.log.tree_size() > 0,
            format!("agent {} produced an empty log", a.index),
        );
        // Redacting agents append a tombstone, so they have MORE leaves.
        let expected_min = ACTIONS_PER_AGENT as u64;
        f.check(
            a.log.tree_size() >= expected_min,
            format!(
                "agent {} has {} leaves, expected at least {expected_min}",
                a.index,
                a.log.tree_size()
            ),
        );
    }
    f.report("Phase 1 — concurrent construction");

    // ---- Phase 2: cross-agent handoffs ----------------------------
    // Each agent hands off to the next, forming a ring. Both sides log
    // independently, then the binding is verified from outside.
    let mut f2 = Findings::default();
    let start = std::time::Instant::now();
    let mut handoff_pairs: Vec<(usize, usize, Leaf, Leaf)> = Vec::new();
    for i in 0..FLEET_SIZE {
        let j = (i + 1) % FLEET_SIZE;
        let payload = format!("handoff-state-{i}-to-{j}").into_bytes();
        let (sender_hex, receiver_hex) = (
            agents
                .get(i)
                .map(|a| a.identity_hex.clone())
                .unwrap_or_default(),
            agents
                .get(j)
                .map(|a| a.identity_hex.clone())
                .unwrap_or_default(),
        );
        let sender_idx = match agents.get_mut(i) {
            Some(a) => a.log.append_handoff_sent(&payload, &receiver_hex),
            None => continue,
        };
        let receiver_idx = match agents.get_mut(j) {
            Some(a) => a.log.append_handoff_received(&payload, &sender_hex),
            None => continue,
        };
        let sender_leaf = agents
            .get(i)
            .and_then(|a| a.log.leaves().get(sender_idx as usize))
            .cloned();
        let receiver_leaf = agents
            .get(j)
            .and_then(|a| a.log.leaves().get(receiver_idx as usize))
            .cloned();
        if let (Some(sl), Some(rl)) = (sender_leaf, receiver_leaf) {
            match verify_handoff_binding(&sender_hex, &sl, &receiver_hex, &rl) {
                Ok(()) => handoff_pairs.push((i, j, sl, rl)),
                Err(e) => f2
                    .errors
                    .push(format!("handoff {i}->{j} failed to bind: {e}")),
            }
        }
    }
    f2.check(
        handoff_pairs.len() == FLEET_SIZE,
        format!(
            "expected {FLEET_SIZE} bound handoffs, got {}",
            handoff_pairs.len()
        ),
    );

    // A handoff must NOT bind when attributed to the wrong counterparty.
    // If this passes, cross-agent attribution is forgeable.
    let mut false_bindings = 0usize;
    for (i, j, sl, rl) in handoff_pairs.iter().take(20) {
        let wrong = (j + 7) % FLEET_SIZE;
        if wrong == *i || wrong == *j {
            continue;
        }
        let wrong_hex = agents
            .get(wrong)
            .map(|a| a.identity_hex.clone())
            .unwrap_or_default();
        let sender_hex = agents
            .get(*i)
            .map(|a| a.identity_hex.clone())
            .unwrap_or_default();
        if verify_handoff_binding(&sender_hex, sl, &wrong_hex, rl).is_ok() {
            false_bindings += 1;
        }
    }
    f2.check(
        false_bindings == 0,
        format!("{false_bindings} handoffs bound to the WRONG counterparty"),
    );
    println!(
        "  {} handoffs bound in {:?}",
        handoff_pairs.len(),
        start.elapsed()
    );
    f2.report("Phase 2 — cross-agent handoff binding");

    // ---- Phase 3: checkpoints + reciprocal witness mesh -----------
    // Every agent checkpoints, then witnesses 5 peers. This is the
    // reciprocal-witnessing model: adoption creates witnesses.
    let mut f3 = Findings::default();
    let start = std::time::Instant::now();
    let checkpoints: Vec<SignedTreeHead> = agents
        .iter()
        .map(|a| a.log.checkpoint(&a.signing_key()))
        .collect();

    // Directory of the whole fleet, as a verifier would hold it.
    let mut directory = WitnessDirectory::default();
    for a in &agents {
        directory.witnesses.push(WitnessEntry {
            name: format!("agent-{:03}", a.index),
            operator_org: a.operator_org.clone(),
            url: format!("https://agent-{:03}.example", a.index),
            pubkey: a.identity_hex.clone(),
            runtime: WitnessRuntime::Agent,
            compute_provider: Some(a.compute_provider.clone()),
            is_project_operated: false,
        });
    }

    // Each checkpoint gets cosigned by 5 peers, in parallel.
    let receipts_by_agent: Arc<Mutex<HashMap<usize, Vec<WitnessReceipt>>>> =
        Arc::new(Mutex::new(HashMap::new()));
    let keys: Vec<(usize, [u8; 32])> = agents.iter().map(|a| (a.index, a.identity_bytes)).collect();
    let cps = Arc::new(checkpoints.clone());
    let keys = Arc::new(keys);
    let handles: Vec<_> = (0..FLEET_SIZE)
        .map(|target| {
            let cps = Arc::clone(&cps);
            let keys = Arc::clone(&keys);
            let out = Arc::clone(&receipts_by_agent);
            std::thread::spawn(move || {
                let Some(cp) = cps.get(target) else { return };
                let mut rs = Vec::new();
                for offset in 1..=5usize {
                    let w = (target + offset * 13) % FLEET_SIZE;
                    if w == target {
                        continue;
                    }
                    if let Some((_, kb)) = keys.get(w) {
                        let wk = SigningKey::from_bytes(kb);
                        rs.push(WitnessReceipt::sign(
                            &wk,
                            cp,
                            1_700_000_000_000 + target as u64,
                        ));
                    }
                }
                if let Ok(mut m) = out.lock() {
                    m.insert(target, rs);
                }
            })
        })
        .collect();
    for h in handles {
        let _ = h.join();
    }
    let receipts_map = receipts_by_agent
        .lock()
        .map(|m| m.clone())
        .unwrap_or_default();
    f3.check(
        receipts_map.len() == FLEET_SIZE,
        format!(
            "expected receipts for {FLEET_SIZE} agents, got {}",
            receipts_map.len()
        ),
    );
    println!(
        "  {} checkpoints cosigned by 5 peers each ({} receipts) in {:?}",
        FLEET_SIZE,
        receipts_map.values().map(|v| v.len()).sum::<usize>(),
        start.elapsed()
    );
    f3.report("Phase 3 — checkpoint + witness mesh");

    // ---- Phase 4: verify every honest dossier ---------------------
    let mut f4 = Findings::default();
    let start = std::time::Instant::now();
    let mut witnessed = 0usize;
    for (i, a) in agents.iter().enumerate() {
        let Some(cp) = checkpoints.get(i) else {
            continue;
        };
        let receipts = receipts_map.get(&i).cloned().unwrap_or_default();
        let dossier = Dossier {
            identity_pubkey: a.identity_hex.clone(),
            leaves: a.log.leaves().to_vec(),
            checkpoint: cp.clone(),
            witness_receipts: receipts,
            witness_directory: directory.clone(),
            key_bindings: a.log.all_bindings(),
            revocations: vec![],
        };

        // Unanchored: must never exceed Unanchored, however many
        // receipts the dossier carries.
        let bare = dossier.verify(0.03, &VerifyContext::default());
        f4.check(
            bare.verdict == Verdict::Unanchored,
            format!(
                "agent {i}: unanchored run gave {:?}, expected Unanchored",
                bare.verdict
            ),
        );

        // Anchored against a directory the verifier holds.
        let ctx = VerifyContext {
            expected_identity_pubkey: Some(&a.identity_hex),
            trusted_directory: Some(&directory),
        };
        let r = dossier.verify(0.03, &ctx);
        f4.check(
            r.is_internally_consistent(),
            format!("agent {i}: honest dossier failed internal consistency"),
        );
        f4.check(
            r.leaves_structurally_valid,
            format!("agent {i}: honest leaves failed structural validation"),
        );
        f4.check(
            r.bindings_valid,
            format!("agent {i}: honest key binding failed validation"),
        );
        f4.check(
            r.merkle_continuity_valid,
            format!("agent {i}: Merkle continuity failed"),
        );
        if r.verdict == Verdict::Witnessed {
            witnessed += 1;
        }
        if let Some(q) = &r.quorum {
            f4.check(
                q.valid_receipts <= q.total_directory_witnesses,
                format!(
                    "agent {i}: valid_receipts {} exceeds directory size",
                    q.valid_receipts
                ),
            );
            f4.check(
                (0.0..=1.0).contains(&q.quorum_fraction),
                format!(
                    "agent {i}: quorum_fraction {} outside [0,1]",
                    q.quorum_fraction
                ),
            );
            f4.check(
                (0.0..=1.0).contains(&q.diversity_fraction),
                format!(
                    "agent {i}: diversity_fraction {} outside [0,1]",
                    q.diversity_fraction
                ),
            );
            f4.check(
                q.project_operated_receipts == 0,
                format!(
                    "agent {i}: reported project-operated receipts in an all-independent fleet"
                ),
            );
        }
    }
    println!(
        "  verified {} dossiers in {:?} ({} reached WITNESSED)",
        FLEET_SIZE,
        start.elapsed(),
        witnessed
    );
    f4.check(
        witnessed > 0,
        "no agent reached WITNESSED — the witness mesh is not functioning".to_string(),
    );
    f4.report("Phase 4 — honest dossier verification");

    // ---- Phase 5: adversaries inside the fleet --------------------
    // These produce cryptographically VALID artifacts that lie.
    let mut f5 = Findings::default();

    // 5a. Impersonation: attacker's log, victim's identity on the label.
    {
        let attacker = IdentityKeypair::generate();
        let ab = attacker.to_bytes();
        let mut fake = WitnessLog::resume(IdentityKeypair::from_bytes(&ab), 0);
        fake.append_intent(br#"{"tool":"transfer","args":{"usd":10000000}}"#);
        let cp = fake.checkpoint(&SigningKey::from_bytes(&ab));
        let victim = agents
            .first()
            .map(|a| a.identity_hex.clone())
            .unwrap_or_default();
        let d = Dossier {
            identity_pubkey: victim,
            leaves: fake.leaves().to_vec(),
            checkpoint: cp,
            witness_receipts: vec![],
            witness_directory: directory.clone(),
            key_bindings: vec![],
            revocations: vec![],
        };
        let r = d.verify(0.03, &VerifyContext::default());
        f5.check(
            r.verdict == Verdict::Diverged,
            format!("impersonation produced {:?}, expected Diverged", r.verdict),
        );
        f5.check(
            !r.identity_bound,
            "impersonation was reported as identity-bound",
        );
    }

    // 5b. Self-witnessing: attacker ships its own directory and receipts.
    {
        let attacker = IdentityKeypair::generate();
        let ab = attacker.to_bytes();
        let mut fake = WitnessLog::resume(IdentityKeypair::from_bytes(&ab), 0);
        fake.append_intent(b"fabricated history");
        let cp = fake.checkpoint(&SigningKey::from_bytes(&ab));
        let mut fake_dir = WitnessDirectory::default();
        let mut fake_receipts = Vec::new();
        for n in 0..8 {
            let wk = SigningKey::generate(&mut OsRng);
            fake_dir.witnesses.push(WitnessEntry {
                name: format!("totally-real-auditor-{n}"),
                operator_org: format!("independent-org-{n}"),
                url: format!("https://auditor-{n}.example"),
                pubkey: hex::encode(wk.verifying_key().to_bytes()),
                runtime: WitnessRuntime::Human,
                compute_provider: Some(format!("provider-{n}")),
                is_project_operated: false,
            });
            fake_receipts.push(WitnessReceipt::sign(&wk, &cp, 1_700_000_000_000));
        }
        let d = Dossier {
            identity_pubkey: fake.identity_pubkey_hex(),
            leaves: fake.leaves().to_vec(),
            checkpoint: cp,
            witness_receipts: fake_receipts,
            witness_directory: fake_dir,
            key_bindings: fake.all_bindings(),
            revocations: vec![],
        };
        let r = d.verify(0.03, &VerifyContext::default());
        f5.check(
            r.verdict == Verdict::Unanchored,
            format!(
                "self-witnessed fabrication reached {:?}, must cap at Unanchored",
                r.verdict
            ),
        );
        f5.check(
            r.quorum.is_none(),
            "quorum was computed from the dossier's OWN directory",
        );
        f5.check(
            WitnessPolicy::production()
                .evaluate(&r, 1_700_000_000_000, 1_700_000_000_000)
                .is_err(),
            "self-witnessed fabrication passed the production policy",
        );
    }

    // 5c. Cross-fleet receipt replay: a valid receipt for agent A's
    // checkpoint must not count toward agent B's.
    {
        if let (Some(cp_a), Some(cp_b)) = (checkpoints.first(), checkpoints.get(1)) {
            let stolen = receipts_map.get(&0).cloned().unwrap_or_default();
            let mut replayed = 0usize;
            for r in &stolen {
                if r.verify(cp_b).is_ok() {
                    replayed += 1;
                }
            }
            f5.check(
                replayed == 0,
                format!(
                    "{replayed} of agent 0's receipts also validated against agent 1's checkpoint"
                ),
            );
            let _ = cp_a;
        }
    }

    // 5d. Equivocation: one identity, two validly-signed divergent histories.
    {
        let id = IdentityKeypair::generate();
        let ib = id.to_bytes();
        let key = SigningKey::from_bytes(&ib);
        let path = std::env::temp_dir().join(format!("fleet-equiv-{}.json", std::process::id()));
        let mut base = WitnessLog::resume(IdentityKeypair::from_bytes(&ib), 0);
        base.append_intent(b"shared prefix");
        let _ = base.save_snapshot(path.to_str().unwrap_or_default());
        let branch = |extra: &[u8]| -> Option<(Vec<Leaf>, SignedTreeHead)> {
            let mut l = WitnessLog::load_snapshot(path.to_str()?).ok()?;
            l.append_intent(extra);
            let cp = l.checkpoint(&key);
            Some((l.leaves().to_vec(), cp))
        };
        if let (Some((la, ca)), Some((lb, cb))) = (branch(b"paid $250"), branch(b"paid $9999999")) {
            f5.check(
                ca.root_hash != cb.root_hash,
                "two divergent histories produced the SAME root — equivocation undetectable",
            );
            f5.check(
                ca.verify().is_ok() && cb.verify().is_ok(),
                "equivocation fixture is invalid: both checkpoints must be validly signed",
            );
            // Both verify individually — that is exactly the problem,
            // and why comparing copies is the only detection path.
            let mk = |leaves: Vec<Leaf>, cp: SignedTreeHead| Dossier {
                identity_pubkey: id.public_hex(),
                leaves,
                checkpoint: cp,
                witness_receipts: vec![],
                witness_directory: WitnessDirectory::default(),
                key_bindings: vec![],
                revocations: vec![],
            };
            let ra = mk(la, ca).verify(0.03, &VerifyContext::default());
            let rb = mk(lb, cb).verify(0.03, &VerifyContext::default());
            f5.check(
                ra.is_internally_consistent() && rb.is_internally_consistent(),
                "equivocating branches should each be internally consistent in isolation",
            );
        }
        let _ = std::fs::remove_file(&path);
    }
    f5.report("Phase 5 — adversaries");

    // ---- Final report ---------------------------------------------
    let total: usize =
        f.errors.len() + f2.errors.len() + f3.errors.len() + f4.errors.len() + f5.errors.len();
    println!("\n╚══ TOTAL VIOLATIONS: {total} ══\n");
    assert_eq!(
        total, 0,
        "fleet simulation found {total} invariant violation(s); see output above"
    );
}

/// Prints the real quorum numbers at fleet scale. Kept as a permanent
/// diagnostic: it is how the directory-size scaling flaw was originally
/// diagnosed (5 independent operators scoring 5/12 = 0.42 and failing a
/// 0.5 fraction gate), and it makes the relationship between the
/// absolute and fractional measures inspectable rather than inferred.
#[test]
fn report_fleet_scale_quorum_numbers() {
    let mut agents: Vec<Agent> = (0..FLEET_SIZE).map(Agent::new).collect();
    for a in agents.iter_mut() {
        a.do_work();
    }
    let checkpoints: Vec<SignedTreeHead> = agents
        .iter()
        .map(|a| a.log.checkpoint(&a.signing_key()))
        .collect();
    let mut directory = WitnessDirectory::default();
    for a in &agents {
        directory.witnesses.push(WitnessEntry {
            name: format!("agent-{:03}", a.index),
            operator_org: a.operator_org.clone(),
            url: format!("https://agent-{:03}.example", a.index),
            pubkey: a.identity_hex.clone(),
            runtime: WitnessRuntime::Agent,
            compute_provider: Some(a.compute_provider.clone()),
            is_project_operated: false,
        });
    }
    let target = 0usize;
    let Some(cp) = checkpoints.get(target) else {
        return;
    };
    let mut receipts = Vec::new();
    for offset in 1..=5usize {
        let w = (target + offset * 13) % FLEET_SIZE;
        if let Some(a) = agents.get(w) {
            receipts.push(WitnessReceipt::sign(
                &a.signing_key(),
                cp,
                1_700_000_000_000,
            ));
        }
    }
    let q = evaluate_quorum(cp, &receipts, &directory, 0.03);
    println!("\n  FLEET-SCALE QUORUM NUMBERS (agent 0, 5 peer witnesses, 100-entry directory)");
    println!("    valid_receipts ................. {}", q.valid_receipts);
    println!(
        "    total_directory_witnesses ...... {}",
        q.total_directory_witnesses
    );
    println!(
        "    quorum_fraction ................ {:.4}",
        q.quorum_fraction
    );
    println!(
        "    meets_count_threshold .......... {}",
        q.meets_count_threshold
    );
    println!(
        "    distinct_operators_represented . {}",
        q.distinct_operators_represented
    );
    println!(
        "    distinct_operators_in_directory  {}",
        q.distinct_operators_in_directory
    );
    println!(
        "    diversity_fraction ............. {:.4}",
        q.diversity_fraction
    );
    println!(
        "    distinct_independent_operators . {}",
        q.distinct_independent_operators
    );
    println!(
        "    (Witnessed requires distinct_independent_operators >= {})\n",
        MIN_INDEPENDENT_OPERATORS_FOR_WITNESSED
    );
}

/// Regression for the scaling flaw the fleet simulation exposed.
///
/// The same 3 independent cosigners must produce the same verdict
/// whether the trusted directory knows about 4 operators or 4,000. The
/// old fraction-based gate failed this: diversity_fraction = 3/N falls
/// as N grows, so a larger and healthier witness network made WITNESSED
/// progressively unreachable. If this test regresses, witness-network
/// growth has started working against verification again.
#[test]
fn witnessed_verdict_does_not_degrade_as_the_directory_grows() {
    let subject = IdentityKeypair::generate();
    let sb = subject.to_bytes();
    let mut log = WitnessLog::resume(IdentityKeypair::from_bytes(&sb), 0);
    log.append_intent(b"an action worth witnessing");
    let cp = log.checkpoint(&SigningKey::from_bytes(&sb));

    // Three real cosigners, each under a distinct operator. Held fixed
    // across every directory size below.
    let cosigners: Vec<(SigningKey, String)> = (0..3)
        .map(|i| {
            (
                SigningKey::generate(&mut OsRng),
                format!("independent-org-{i}"),
            )
        })
        .collect();
    // Witness at the checkpoint's own time. A hardcoded past timestamp
    // would trip production()'s 10-minute staleness bar and mask the
    // property under test, which is about operator independence, not age.
    let receipts: Vec<WitnessReceipt> = cosigners
        .iter()
        .map(|(k, _)| WitnessReceipt::sign(k, &cp, cp.timestamp_ms))
        .collect();

    for directory_size in [4usize, 10, 50, 100, 500, 4000] {
        let mut directory = WitnessDirectory::default();
        for (k, org) in &cosigners {
            directory.witnesses.push(WitnessEntry {
                name: org.clone(),
                operator_org: org.clone(),
                url: format!("https://{org}.example"),
                pubkey: hex::encode(k.verifying_key().to_bytes()),
                runtime: WitnessRuntime::Human,
                compute_provider: Some(org.clone()),
                is_project_operated: false,
            });
        }
        // Pad with other known operators who did NOT cosign. These are
        // what used to sink the fraction.
        for n in 0..directory_size.saturating_sub(cosigners.len()) {
            let k = SigningKey::generate(&mut OsRng);
            directory.witnesses.push(WitnessEntry {
                name: format!("bystander-{n}"),
                operator_org: format!("bystander-org-{n}"),
                url: format!("https://bystander-{n}.example"),
                pubkey: hex::encode(k.verifying_key().to_bytes()),
                runtime: WitnessRuntime::Human,
                compute_provider: Some(format!("provider-{n}")),
                is_project_operated: false,
            });
        }

        let dossier = Dossier {
            identity_pubkey: subject.public_hex(),
            leaves: log.leaves().to_vec(),
            checkpoint: cp.clone(),
            witness_receipts: receipts.clone(),
            witness_directory: WitnessDirectory::default(),
            key_bindings: log.all_bindings(),
            revocations: vec![],
        };
        let subject_hex = subject.public_hex();
        let ctx = VerifyContext {
            expected_identity_pubkey: Some(&subject_hex),
            trusted_directory: Some(&directory),
        };
        // Threshold scaled to the directory: 3 of N by count. The point
        // is the OPERATOR-INDEPENDENCE gate, which must not care about N.
        let threshold = 3.0 / directory_size as f64;
        let report = dossier.verify(threshold, &ctx);
        let q = report.quorum.as_ref().expect("quorum must be computed");

        assert_eq!(
            q.distinct_independent_operators, 3,
            "directory size {directory_size}: expected 3 independent operators, got {}",
            q.distinct_independent_operators
        );
        assert_eq!(
            report.verdict,
            Verdict::Witnessed,
            "directory size {directory_size}: 3 independent cosigners must still reach \
             Witnessed (diversity_fraction here is {:.4} — proof that the fraction cannot \
             gate the verdict)",
            q.diversity_fraction
        );
        // And the production policy, which demands 3 independent
        // operators, must accept this at every scale.
        assert!(
            WitnessPolicy::production()
                .evaluate(&report, cp.timestamp_ms, cp.timestamp_ms)
                .is_ok(),
            "directory size {directory_size}: production policy rejected 3 independent cosigners"
        );
    }
}
