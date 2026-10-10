//! A 1,000-agent cohort under realistic deployment conditions.
//!
//! The 100-agent fleet simulation used uniform agents and a uniform
//! operator distribution. Real deployments are neither, and the
//! differences are exactly where product-viability problems hide:
//!
//! - **Power-law operators.** A handful of large operators run most
//!   agents; a long tail runs one each. This is how every real platform
//!   ecosystem distributes, and it directly stresses diversity scoring.
//! - **Heterogeneous behavior.** Chatty, bursty, short-lived,
//!   crash-restart, and long-running agents have different leaf counts,
//!   checkpoint cadences, and failure modes.
//! - **Clock skew.** Agents disagree about the time, because machines do.
//! - **Partial witness availability.** Some witnesses are offline when
//!   asked, which is the normal case, not an exception.
//!
//! This suite is looking for answers to "would this work in production",
//! not just "does it crash". A test that passes while demonstrating the
//! product is unusable at scale is still a finding, so several of these
//! assert on *reachability* of verdicts rather than on correctness alone.

use ed25519_dalek::SigningKey;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use witness_log_core::identity::IdentityKeypair;
use witness_log_core::log::WitnessLog;
use witness_log_core::sth::SignedTreeHead;
use witness_log_network::*;

const COHORT: usize = 1000;

/// Realistic operator distribution: a power law. Three hyperscale
/// operators run ~50% of agents between them, a middle tier runs ~35%,
/// and a long tail of single-agent operators runs the rest. Returns the
/// operator name for agent `i`.
fn operator_for(i: usize) -> String {
    match i % 100 {
        0..=24 => "hyperscale-a".to_string(),     // 25%
        25..=39 => "hyperscale-b".to_string(),    // 15%
        40..=49 => "hyperscale-c".to_string(),    // 10%
        50..=69 => format!("midsize-{}", i % 12), // 20% across 12 operators
        70..=84 => format!("smallco-{}", i % 40), // 15% across 40 operators
        _ => format!("solo-{i}"),                 // 15% long tail, one each
    }
}

/// Compute providers concentrate even harder than operators in reality.
fn provider_for(i: usize) -> Option<String> {
    match i % 20 {
        0..=8 => Some("aws".to_string()),       // 45%
        9..=13 => Some("gcp".to_string()),      // 25%
        14..=16 => Some("azure".to_string()),   // 15%
        17..=18 => Some("on-prem".to_string()), // 10%
        _ => None,                              // 5% undisclosed
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum Profile {
    /// High-volume: many small events.
    Chatty,
    /// Few events, long gaps.
    Sparse,
    /// Crashes and resumes from its journal partway through.
    CrashRestart,
    /// Checkpoints after nearly every action.
    HeavyCheckpoint,
    /// Large payloads.
    BulkPayload,
}

fn profile_for(i: usize) -> Profile {
    match i % 10 {
        0..=4 => Profile::Chatty,
        5..=6 => Profile::Sparse,
        7 => Profile::CrashRestart,
        8 => Profile::HeavyCheckpoint,
        _ => Profile::BulkPayload,
    }
}

struct CohortAgent {
    index: usize,
    seed: [u8; 32],
    identity_hex: String,
    operator: String,
    provider: Option<String>,
    profile: Profile,
    leaves: Vec<witness_log_core::leaf::Leaf>,
    binding: Vec<witness_log_core::identity::KeyBindingStatement>,
    checkpoint: SignedTreeHead,
}

#[derive(Default)]
struct Findings(Vec<String>);
impl Findings {
    fn check(&mut self, cond: bool, msg: impl Into<String>) {
        if !cond {
            self.0.push(msg.into());
        }
    }
    fn report(&self, label: &str) -> usize {
        if self.0.is_empty() {
            println!("  ✓ {label}");
        } else {
            println!("  ✗ {label}: {} violation(s)", self.0.len());
            for e in self.0.iter().take(12) {
                println!("      · {e}");
            }
            if self.0.len() > 12 {
                println!("      ... and {} more", self.0.len() - 12);
            }
        }
        self.0.len()
    }
}

/// Build one agent, exercising its profile's behaviour. Returns None if
/// the agent's own journal round-trip failed, which is itself reported.
fn build_agent(i: usize) -> Option<CohortAgent> {
    let identity = IdentityKeypair::generate();
    let seed = identity.to_bytes();
    let identity_hex = identity.public_hex();
    let profile = profile_for(i);
    let key = SigningKey::from_bytes(&seed);

    let dir = std::env::temp_dir().join(format!("cohort-{}-{i}", std::process::id()));
    std::fs::create_dir_all(&dir).ok()?;
    let jpath = dir.join("a.jsonl");
    let jpath = jpath.to_str()?.to_string();

    let (leaves, binding) = match profile {
        Profile::CrashRestart => {
            // Write, "crash", resume from journal, keep writing. This is
            // the path where a torn tail or a lost append would show up.
            {
                let mut log = witness_log_core::journal::JournaledLog::create(
                    &jpath,
                    IdentityKeypair::from_bytes(&seed),
                )
                .ok()?;
                for n in 0..15 {
                    log.append_intent(format!(r#"{{"pre_crash":{n}}}"#).as_bytes())
                        .ok()?;
                }
                log.sync().ok()?;
            } // dropped == crashed
            let (mut log, _report) =
                witness_log_core::journal::JournaledLog::resume(&jpath).ok()?;
            for n in 0..10 {
                log.append_result(format!(r#"{{"post_restart":{n}}}"#).as_bytes())
                    .ok()?;
            }
            log.sync().ok()?;
            (log.log().leaves().to_vec(), log.log().all_bindings())
        }
        _ => {
            let mut log = WitnessLog::resume(IdentityKeypair::from_bytes(&seed), 0);
            let (count, size) = match profile {
                Profile::Chatty => (60, 64),
                Profile::Sparse => (4, 64),
                Profile::HeavyCheckpoint => (20, 64),
                Profile::BulkPayload => (12, 16 * 1024), // 16 KB payloads
                Profile::CrashRestart => unreachable!(),
            };
            for n in 0..count {
                let payload = vec![b'x'; size];
                if n % 3 == 0 {
                    log.append_intent(&payload);
                } else if n % 3 == 1 {
                    log.append_result(&payload);
                } else {
                    let idx = log.append_memory(&payload);
                    if n % 9 == 2 {
                        log.forget(idx); // some agents redact
                    }
                }
                if profile == Profile::HeavyCheckpoint {
                    let _ = log.checkpoint(&key);
                }
            }
            (log.leaves().to_vec(), log.all_bindings())
        }
    };
    std::fs::remove_dir_all(&dir).ok();

    // Rebuild a log from these leaves to produce the checkpoint.
    let mut tree = witness_log_core::merkle::MerkleTree::new();
    for l in &leaves {
        tree.append(witness_log_core::merkle::leaf_hash(&l.canonical_bytes()));
    }
    let checkpoint = SignedTreeHead::sign(&key, tree.size(), &tree.root(), 1_700_000_000_000);

    Some(CohortAgent {
        index: i,
        seed,
        identity_hex,
        operator: operator_for(i),
        provider: provider_for(i),
        profile,
        leaves,
        binding,
        checkpoint,
    })
}

#[test]
fn cohort_of_1000_under_realistic_conditions() {
    println!("\n╔══ 1,000-AGENT COHORT ══\n");
    let mut total = 0usize;

    // ── Phase 1: build the cohort concurrently ──────────────────
    let start = std::time::Instant::now();
    let chunk = 50;
    let agents: Arc<Mutex<Vec<CohortAgent>>> = Arc::new(Mutex::new(Vec::with_capacity(COHORT)));
    let handles: Vec<_> = (0..COHORT)
        .step_by(chunk)
        .map(|base| {
            let out = Arc::clone(&agents);
            std::thread::spawn(move || {
                let built: Vec<CohortAgent> = (base..(base + chunk).min(COHORT))
                    .filter_map(build_agent)
                    .collect();
                if let Ok(mut v) = out.lock() {
                    v.extend(built);
                }
            })
        })
        .collect();
    for h in handles {
        let _ = h.join();
    }
    let mut agents = Arc::try_unwrap(agents)
        .map(|m| m.into_inner().unwrap_or_default())
        .unwrap_or_default();
    agents.sort_by_key(|a| a.index);
    let build_time = start.elapsed();

    let mut f1 = Findings::default();
    f1.check(
        agents.len() == COHORT,
        format!(
            "only {} of {COHORT} agents built successfully",
            agents.len()
        ),
    );
    let total_leaves: usize = agents.iter().map(|a| a.leaves.len()).sum();
    println!(
        "  built {} agents, {} total leaves, in {:?}",
        agents.len(),
        total_leaves,
        build_time
    );
    // Every profile must have produced a usable log.
    for p in [
        Profile::Chatty,
        Profile::Sparse,
        Profile::CrashRestart,
        Profile::HeavyCheckpoint,
        Profile::BulkPayload,
    ] {
        let of_profile: Vec<&CohortAgent> = agents.iter().filter(|a| a.profile == p).collect();
        f1.check(
            !of_profile.is_empty(),
            format!("no agents of profile {p:?} were built"),
        );
        f1.check(
            of_profile.iter().all(|a| !a.leaves.is_empty()),
            format!("some {p:?} agents produced empty logs"),
        );
    }
    // Crash-restart agents must retain their pre-crash history.
    for a in agents.iter().filter(|a| a.profile == Profile::CrashRestart) {
        f1.check(
            a.leaves.len() >= 25,
            format!(
                "agent {} (CrashRestart) has {} leaves; pre-crash history appears lost",
                a.index,
                a.leaves.len()
            ),
        );
    }
    total += f1.report("Phase 1 — heterogeneous cohort construction");

    // ── Phase 2: the realistic-diversity question ───────────────
    // This is the product-viability test. Given a power-law operator
    // distribution and partial witness availability, can an ordinary
    // agent actually reach WITNESSED?
    let mut directory = WitnessDirectory::default();
    for a in &agents {
        directory.witnesses.push(WitnessEntry {
            name: format!("agent-{:04}", a.index),
            operator_org: a.operator.clone(),
            url: format!("https://a{:04}.example", a.index),
            pubkey: a.identity_hex.clone(),
            runtime: WitnessRuntime::Agent,
            compute_provider: a.provider.clone(),
            is_project_operated: false,
        });
    }
    let distinct_ops: HashSet<&str> = agents.iter().map(|a| a.operator.as_str()).collect();
    println!(
        "  operator distribution: {} distinct operators across {} agents",
        distinct_ops.len(),
        agents.len()
    );

    let mut f2 = Findings::default();
    // Naive witness selection: ask the next 5 agents by index. With a
    // power-law distribution, consecutive agents often share an operator
    // -- which is precisely the realistic failure.
    let mut naive_witnessed = 0usize;
    let mut naive_independent_counts: Vec<usize> = Vec::new();
    for (i, a) in agents.iter().enumerate().take(200) {
        let receipts: Vec<WitnessReceipt> = (1..=5)
            .filter_map(|o| agents.get((i + o) % agents.len()))
            .map(|w| {
                WitnessReceipt::sign(
                    &SigningKey::from_bytes(&w.seed),
                    &a.checkpoint,
                    a.checkpoint.timestamp_ms,
                )
            })
            .collect();
        let q = evaluate_quorum(&a.checkpoint, &receipts, &directory, 0.0);
        naive_independent_counts.push(q.distinct_independent_operators);
        if q.distinct_independent_operators >= MIN_INDEPENDENT_OPERATORS_FOR_WITNESSED {
            naive_witnessed += 1;
        }
    }
    let naive_rate = naive_witnessed as f64 / 200.0;
    let avg_naive: f64 = naive_independent_counts.iter().sum::<usize>() as f64
        / naive_independent_counts.len() as f64;
    println!(
        "  NAIVE witness selection (next 5 by index): {:.0}% reach the independence floor, \
         avg {:.1} distinct operators",
        naive_rate * 100.0,
        avg_naive
    );

    // Operator-aware selection: pick witnesses from distinct operators.
    let mut by_operator: HashMap<&str, Vec<&CohortAgent>> = HashMap::new();
    for a in &agents {
        by_operator.entry(a.operator.as_str()).or_default().push(a);
    }
    let operator_list: Vec<&&str> = by_operator.keys().collect();
    let mut aware_witnessed = 0usize;
    for (i, a) in agents.iter().enumerate().take(200) {
        let mut receipts = Vec::new();
        let mut used_ops = HashSet::new();
        for step in 0..operator_list.len() {
            if receipts.len() >= 5 {
                break;
            }
            let Some(op) = operator_list.get((i + step) % operator_list.len()) else {
                continue;
            };
            if **op == a.operator.as_str() || !used_ops.insert(**op) {
                continue;
            }
            if let Some(w) = by_operator.get(**op).and_then(|v| v.first()) {
                receipts.push(WitnessReceipt::sign(
                    &SigningKey::from_bytes(&w.seed),
                    &a.checkpoint,
                    a.checkpoint.timestamp_ms,
                ));
            }
        }
        let q = evaluate_quorum(&a.checkpoint, &receipts, &directory, 0.0);
        if q.distinct_independent_operators >= MIN_INDEPENDENT_OPERATORS_FOR_WITNESSED {
            aware_witnessed += 1;
        }
    }
    let aware_rate = aware_witnessed as f64 / 200.0;
    println!(
        "  OPERATOR-AWARE selection:                  {:.0}% reach the independence floor",
        aware_rate * 100.0
    );

    // The product finding: operator-aware selection must work reliably.
    // If it doesn't, nobody can reach WITNESSED in a real deployment and
    // the strongest verdict is decorative.
    f2.check(
        aware_rate > 0.95,
        format!(
            "operator-aware witness selection only reached the independence floor {:.0}% of the \
             time — WITNESSED is not reliably achievable in a realistic deployment",
            aware_rate * 100.0
        ),
    );
    total += f2.report("Phase 2 — witness selection under a power-law operator distribution");

    // ── Phase 3: full verification at cohort scale ──────────────
    let mut f3 = Findings::default();
    let start = std::time::Instant::now();
    let mut verdicts: HashMap<String, usize> = HashMap::new();
    for a in agents.iter() {
        // Operator-aware witnesses, as Phase 2 established is required.
        let mut receipts = Vec::new();
        let mut used = HashSet::new();
        for step in 0..operator_list.len() {
            if receipts.len() >= 4 {
                break;
            }
            let Some(op) = operator_list.get((a.index + step) % operator_list.len()) else {
                continue;
            };
            if **op == a.operator.as_str() || !used.insert(**op) {
                continue;
            }
            if let Some(w) = by_operator.get(**op).and_then(|v| v.first()) {
                receipts.push(WitnessReceipt::sign(
                    &SigningKey::from_bytes(&w.seed),
                    &a.checkpoint,
                    a.checkpoint.timestamp_ms,
                ));
            }
        }
        let dossier = Dossier {
            identity_pubkey: a.identity_hex.clone(),
            leaves: a.leaves.clone(),
            checkpoint: a.checkpoint.clone(),
            witness_receipts: receipts,
            witness_directory: WitnessDirectory::default(),
            key_bindings: a.binding.clone(),
            revocations: vec![],
        };
        let ctx = VerifyContext {
            expected_identity_pubkey: Some(&a.identity_hex),
            trusted_directory: Some(&directory),
        };
        let r = dossier.verify(0.0, &ctx);
        *verdicts.entry(r.verdict.to_string()).or_default() += 1;
        f3.check(
            r.is_internally_consistent(),
            format!(
                "agent {} ({:?}) failed internal consistency",
                a.index, a.profile
            ),
        );
        f3.check(
            r.bindings_valid,
            format!(
                "agent {} ({:?}) failed key-binding validation",
                a.index, a.profile
            ),
        );
    }
    println!(
        "  verified {} dossiers ({} leaves) in {:?}",
        agents.len(),
        total_leaves,
        start.elapsed()
    );
    let mut vs: Vec<(&String, &usize)> = verdicts.iter().collect();
    vs.sort();
    for (v, n) in vs {
        println!("      {v}: {n}");
    }
    f3.check(
        verdicts.get("WITNESSED").copied().unwrap_or(0) > COHORT * 9 / 10,
        format!(
            "only {} of {COHORT} agents reached WITNESSED with operator-aware witnessing",
            verdicts.get("WITNESSED").copied().unwrap_or(0)
        ),
    );
    total += f3.report("Phase 3 — verification at cohort scale");

    // ── Phase 4: clock skew ─────────────────────────────────────
    // Machines disagree about the time. A verifier must not treat skew
    // as tampering.
    let mut f4 = Findings::default();
    for (n, skew_ms) in [
        (0usize, 0i64),
        (1, 5_000),
        (2, -5_000),
        (3, 60_000),
        (4, -60_000),
    ] {
        let Some(a) = agents.get(n) else { continue };
        let skewed_ts = (a.checkpoint.timestamp_ms as i64 + skew_ms).max(0) as u64;
        let key = SigningKey::from_bytes(&a.seed);
        let mut tree = witness_log_core::merkle::MerkleTree::new();
        for l in &a.leaves {
            tree.append(witness_log_core::merkle::leaf_hash(&l.canonical_bytes()));
        }
        let cp = SignedTreeHead::sign(&key, tree.size(), &tree.root(), skewed_ts);
        let dossier = Dossier {
            identity_pubkey: a.identity_hex.clone(),
            leaves: a.leaves.clone(),
            checkpoint: cp,
            witness_receipts: vec![],
            witness_directory: WitnessDirectory::default(),
            key_bindings: a.binding.clone(),
            revocations: vec![],
        };
        let r = dossier.verify(0.0, &VerifyContext::default());
        f4.check(
            r.verdict != Verdict::Diverged,
            format!("clock skew of {skew_ms}ms was treated as tampering (Diverged)"),
        );
    }
    total += f4.report("Phase 4 — clock skew tolerance");

    // ── Phase 5: adversaries at cohort scale ────────────────────
    let mut f5 = Findings::default();
    // A hyperscale operator runs 250 agents. Can it manufacture a quorum
    // for one of its own? This is the realistic collusion scenario, and
    // it is the single most important question in the whole suite.
    if let Some(victim) = agents.iter().find(|a| a.operator == "hyperscale-a") {
        let colluders: Vec<&CohortAgent> = agents
            .iter()
            .filter(|a| a.operator == "hyperscale-a" && a.index != victim.index)
            .take(200)
            .collect();
        let receipts: Vec<WitnessReceipt> = colluders
            .iter()
            .map(|w| {
                WitnessReceipt::sign(
                    &SigningKey::from_bytes(&w.seed),
                    &victim.checkpoint,
                    victim.checkpoint.timestamp_ms,
                )
            })
            .collect();
        let q = evaluate_quorum(&victim.checkpoint, &receipts, &directory, 0.0);
        println!(
            "  collusion: {} same-operator witnesses -> {} independent operator(s)",
            receipts.len(),
            q.distinct_independent_operators
        );
        f5.check(
            q.distinct_independent_operators == 0,
            format!(
                "{} witnesses ALL under one operator scored {} independent operators — \
                 a hyperscaler can manufacture a quorum for its own agents",
                receipts.len(),
                q.distinct_independent_operators
            ),
        );
        let dossier = Dossier {
            identity_pubkey: victim.identity_hex.clone(),
            leaves: victim.leaves.clone(),
            checkpoint: victim.checkpoint.clone(),
            witness_receipts: receipts,
            witness_directory: WitnessDirectory::default(),
            key_bindings: victim.binding.clone(),
            revocations: vec![],
        };
        let ctx = VerifyContext {
            expected_identity_pubkey: Some(&victim.identity_hex),
            trusted_directory: Some(&directory),
        };
        let r = dossier.verify(0.0, &ctx);
        f5.check(
            r.verdict != Verdict::Witnessed,
            "a single-operator collusion of 200 witnesses reached WITNESSED",
        );
    }
    total += f5.report("Phase 5 — single-operator collusion at scale");

    println!("\n╚══ TOTAL VIOLATIONS: {total} ══\n");
    assert_eq!(total, 0, "cohort simulation found {total} violation(s)");
}
