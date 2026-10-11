//! Two things the 100-agent fleet simulation doesn't cover.
//!
//! **Sybil resistance at scale.** The fleet simulation used honest
//! operator labels. The interesting case is an operator who runs many
//! witnesses and labels them to *look* independent. Since
//! `distinct_independent_operators` now gates `Verdict::Witnessed`,
//! inflating that count is the most direct attack on the whole trust
//! model — more direct than forging a signature, because it requires no
//! cryptography at all, just a text field.
//!
//! **Memory growth.** The crate documents roughly 200 bytes per leaf and
//! does not promise bounded memory. An undocumented-but-real superlinear
//! growth pattern would make that guidance wrong in a way nobody
//! discovers until a long-running agent falls over.

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use witness_log_core::identity::IdentityKeypair;
use witness_log_core::log::WitnessLog;
use witness_log_core::sth::SignedTreeHead;
use witness_log_network::*;

/// Build a directory of witnesses with caller-chosen operator labels,
/// plus valid receipts from every one of them. Every signature here is
/// genuine — the attack is entirely in the labels.
fn directory_with_labels(
    labels: &[(&str, Option<&str>, bool)], // (operator_org, compute_provider, is_project_operated)
    sth: &SignedTreeHead,
) -> (WitnessDirectory, Vec<WitnessReceipt>) {
    let mut directory = WitnessDirectory::default();
    let mut receipts = Vec::new();
    for (i, (org, provider, project)) in labels.iter().enumerate() {
        let k = SigningKey::generate(&mut OsRng);
        directory.witnesses.push(WitnessEntry {
            name: format!("witness-{i}"),
            operator_org: (*org).to_string(),
            url: format!("https://witness-{i}.example"),
            pubkey: hex::encode(k.verifying_key().to_bytes()),
            runtime: WitnessRuntime::Human,
            compute_provider: provider.map(|p| p.to_string()),
            is_project_operated: *project,
        });
        receipts.push(WitnessReceipt::sign(&k, sth, sth.timestamp_ms));
    }
    (directory, receipts)
}

fn subject_checkpoint() -> (IdentityKeypair, SignedTreeHead, WitnessLog) {
    let id = IdentityKeypair::generate();
    let b = id.to_bytes();
    let mut log = WitnessLog::resume(IdentityKeypair::from_bytes(&b), 0);
    log.append_intent(b"an action worth witnessing");
    let cp = log.checkpoint(&SigningKey::from_bytes(&b));
    (id, cp, log)
}

// ───────────────────────── Sybil resistance ─────────────────────────

/// One operator, many witnesses, labels differing ONLY by case.
///
/// This is the cheapest possible Sybil attack: no extra infrastructure,
/// no forged signatures, just the shift key. If these count as distinct
/// operators, `distinct_independent_operators` can be inflated at will
/// and `Verdict::Witnessed` means nothing.
#[test]
fn case_variants_of_one_operator_do_not_inflate_independence() {
    let (_, cp, _) = subject_checkpoint();
    let labels: Vec<(&str, Option<&str>, bool)> = vec![
        ("acme-corp", Some("aws"), false),
        ("Acme-Corp", Some("aws"), false),
        ("ACME-CORP", Some("aws"), false),
        ("AcMe-CoRp", Some("aws"), false),
        ("acme-CORP", Some("aws"), false),
    ];
    let (directory, receipts) = directory_with_labels(&labels, &cp);
    let q = evaluate_quorum(&cp, &receipts, &directory, 0.0);

    assert_eq!(
        q.valid_receipts, 5,
        "all five signatures are genuine and should count as receipts"
    );
    assert_eq!(
        q.distinct_independent_operators, 1,
        "five case-variants of ONE operator name must collapse to one operator bucket; \
         got {} — this is a Sybil vector: an operator inflates apparent independence \
         with the shift key and no extra infrastructure",
        q.distinct_independent_operators
    );
}

/// Same attack via leading/trailing whitespace.
#[test]
fn whitespace_variants_of_one_operator_do_not_inflate_independence() {
    let (_, cp, _) = subject_checkpoint();
    let labels: Vec<(&str, Option<&str>, bool)> = vec![
        ("northwind", Some("gcp"), false),
        (" northwind", Some("gcp"), false),
        ("northwind ", Some("gcp"), false),
        ("  northwind  ", Some("gcp"), false),
        ("\tnorthwind", Some("gcp"), false),
    ];
    let (directory, receipts) = directory_with_labels(&labels, &cp);
    let q = evaluate_quorum(&cp, &receipts, &directory, 0.0);
    assert_eq!(
        q.distinct_independent_operators, 1,
        "whitespace variants must collapse to one operator bucket, got {}",
        q.distinct_independent_operators
    );
}

/// Internal whitespace runs: "acme corp" vs "acme  corp".
#[test]
fn internal_whitespace_variants_collapse() {
    let (_, cp, _) = subject_checkpoint();
    let labels: Vec<(&str, Option<&str>, bool)> = vec![
        ("acme corp", None, false),
        ("acme  corp", None, false),
        ("acme\tcorp", None, false),
    ];
    let (directory, receipts) = directory_with_labels(&labels, &cp);
    let q = evaluate_quorum(&cp, &receipts, &directory, 0.0);
    assert_eq!(
        q.distinct_independent_operators, 1,
        "internal whitespace variants must collapse, got {}",
        q.distinct_independent_operators
    );
}

/// The same normalization must apply to the compute-provider axis, or
/// the identical attack works on the second diversity dimension.
#[test]
fn compute_provider_variants_do_not_inflate_provider_diversity() {
    let (_, cp, _) = subject_checkpoint();
    let labels: Vec<(&str, Option<&str>, bool)> = vec![
        ("org-a", Some("AWS"), false),
        ("org-b", Some("aws"), false),
        ("org-c", Some(" aws "), false),
        ("org-d", Some("Aws"), false),
    ];
    let (directory, receipts) = directory_with_labels(&labels, &cp);
    let q = evaluate_quorum(&cp, &receipts, &directory, 0.0);
    assert_eq!(
        q.distinct_independent_operators, 4,
        "these ARE four distinct operators"
    );
    assert_eq!(
        q.distinct_compute_providers_represented, 1,
        "four spellings of one cloud provider must collapse to one provider bucket, got {} — \
         otherwise a single-provider outage looks like provider diversity",
        q.distinct_compute_providers_represented
    );
}

/// A large Sybil fleet: 100 witnesses, all one operator, labels varied
/// by case and whitespace. This is the realistic shape of the attack —
/// cheap to mount, and it targets the exact number the verdict reads.
#[test]
fn hundred_witness_sybil_fleet_collapses_to_one_operator() {
    let (id, cp, log) = subject_checkpoint();
    let variants: Vec<String> = (0..100)
        .map(|i| match i % 5 {
            0 => "evil-corp".to_string(),
            1 => "Evil-Corp".to_string(),
            2 => "EVIL-CORP".to_string(),
            3 => format!(" evil-corp{}", " ".repeat(i % 3)),
            _ => "  Evil-Corp  ".to_string(),
        })
        .collect();
    let labels: Vec<(&str, Option<&str>, bool)> = variants
        .iter()
        .map(|v| (v.as_str(), Some("aws"), false))
        .collect();
    let (directory, receipts) = directory_with_labels(&labels, &cp);

    let q = evaluate_quorum(&cp, &receipts, &directory, 0.0);
    assert_eq!(q.valid_receipts, 100, "all 100 signatures are genuine");
    assert_eq!(
        q.distinct_independent_operators, 1,
        "100 witnesses run by ONE operator must score as one independent operator, got {}",
        q.distinct_independent_operators
    );

    // And the verdict must refuse to call this witnessed, because one
    // operator cannot corroborate itself no matter how many keys it holds.
    let dossier = Dossier {
        identity_pubkey: id.public_hex(),
        leaves: log.leaves().to_vec(),
        checkpoint: cp.clone(),
        witness_receipts: receipts,
        witness_directory: WitnessDirectory::default(),
        key_bindings: log.all_bindings(),
        revocations: vec![],
    };
    let subject_hex = id.public_hex();
    let ctx = VerifyContext {
        expected_identity_pubkey: Some(&subject_hex),
        trusted_directory: Some(&directory),
        min_receipts: None,
    };
    let report = dossier.verify(0.0, &ctx);
    assert_eq!(
        report.verdict,
        Verdict::ConsistentUnwitnessed,
        "100 Sybil witnesses under one operator must NOT reach Witnessed"
    );
    assert!(
        WitnessPolicy::production()
            .evaluate(&report, cp.timestamp_ms, cp.timestamp_ms)
            .is_err(),
        "production policy must reject a single-operator Sybil fleet"
    );
}

/// Genuinely distinct operators must still be counted. A normalization
/// aggressive enough to merge real operators would be worse than the bug
/// it fixes — it would silently suppress real independence.
#[test]
fn genuinely_distinct_operators_are_not_over_collapsed() {
    let (_, cp, _) = subject_checkpoint();
    let labels: Vec<(&str, Option<&str>, bool)> = vec![
        ("acme-corp", Some("aws"), false),
        ("acme-corporation", Some("gcp"), false), // similar, NOT the same
        ("acmecorp", Some("azure"), false),       // also not the same
        ("northwind", Some("on-prem"), false),
        ("example-university", Some("hetzner"), false),
    ];
    let (directory, receipts) = directory_with_labels(&labels, &cp);
    let q = evaluate_quorum(&cp, &receipts, &directory, 0.0);
    assert_eq!(
        q.distinct_independent_operators, 5,
        "five genuinely different operator names must count as five, got {} — \
         over-collapsing suppresses real independence",
        q.distinct_independent_operators
    );
    assert_eq!(q.distinct_compute_providers_represented, 5);
}

/// Project-operated witnesses must still collapse regardless of label
/// manipulation — the pre-existing guarantee, re-checked at scale and in
/// combination with case variants.
#[test]
fn project_operated_collapse_survives_label_manipulation() {
    let (_, cp, _) = subject_checkpoint();
    let mut labels: Vec<(&str, Option<&str>, bool)> = Vec::new();
    for _ in 0..30 {
        labels.push(("WitnessLog-Project", Some("fly.io"), true));
        labels.push(("witnesslog-project", Some("FLY.IO"), true));
        labels.push((" Definitely-Independent ", Some("aws"), true));
    }
    labels.push(("genuinely-external-university", Some("on-prem"), false));
    let (directory, receipts) = directory_with_labels(&labels, &cp);
    let q = evaluate_quorum(&cp, &receipts, &directory, 0.0);

    assert_eq!(
        q.distinct_independent_operators, 1,
        "90 project-operated witnesses under varied labels plus 1 genuine third party \
         must yield exactly 1 independent operator, got {}",
        q.distinct_independent_operators
    );
    assert_eq!(
        q.project_operated_receipts, 90,
        "all 90 project-operated receipts must be reported honestly"
    );
}

// ───────────────────────────── Soak ─────────────────────────────────

/// Resident memory of this process, in kilobytes, read from
/// /proc/self/status. Returns None where that isn't available, so the
/// test degrades to a timing check rather than failing on a platform
/// that simply doesn't expose it.
fn resident_kb() -> Option<u64> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("VmRSS:") {
            return rest.split_whitespace().next()?.parse().ok();
        }
    }
    None
}

/// Long-running soak: append many leaves, checkpointing throughout, and
/// check that memory and time grow LINEARLY rather than superlinearly.
///
/// This is the test that makes the crate's documented "~200 bytes per
/// leaf, no bounded-memory promise" guidance checkable rather than
/// aspirational. It also re-exercises the O(log n) checkpoint path at a
/// size where an accidental return to O(n) would be unmissable.
#[test]
fn soak_memory_and_time_grow_linearly() {
    const LEAVES: usize = 200_000;
    const SAMPLE_EVERY: usize = 25_000;

    let id = IdentityKeypair::generate();
    let b = id.to_bytes();
    let key = SigningKey::from_bytes(&b);
    let mut log = WitnessLog::resume(IdentityKeypair::from_bytes(&b), 0);

    let baseline_kb = resident_kb();
    let start = std::time::Instant::now();
    let mut samples: Vec<(usize, Option<u64>, std::time::Duration)> = Vec::new();

    for i in 0..LEAVES {
        log.append_intent(format!(r#"{{"seq":{i},"tool":"soak"}}"#).as_bytes());
        // Checkpoint periodically, as a real agent would. If root() ever
        // regresses to O(n) this becomes quadratic and the soak will
        // visibly stall.
        if i % 1000 == 0 {
            let _ = log.checkpoint(&key);
        }
        if (i + 1) % SAMPLE_EVERY == 0 {
            samples.push((i + 1, resident_kb(), start.elapsed()));
        }
    }

    println!("\n  SOAK: {LEAVES} leaves, checkpointing every 1000");
    println!("    leaves      elapsed        RSS        bytes/leaf");
    for (n, kb, el) in &samples {
        match (kb, baseline_kb) {
            (Some(k), Some(base)) => {
                let grown = k.saturating_sub(base);
                let per_leaf = (grown as f64 * 1024.0) / *n as f64;
                println!(
                    "    {n:>8}  {:>10.2?}  {grown:>7} KB   {per_leaf:>7.0} B",
                    el
                );
            }
            _ => println!("    {n:>8}  {:>10.2?}  (RSS unavailable)", el),
        }
    }

    // --- Time linearity -------------------------------------------
    // Compare the last quarter's throughput against the first quarter's.
    // Quadratic behaviour makes later work dramatically slower per leaf.
    if let (Some(first), Some(last)) = (samples.first(), samples.last()) {
        let first_per_leaf = first.2.as_secs_f64() / first.0 as f64;
        let last_per_leaf = last.2.as_secs_f64() / last.0 as f64;
        let ratio = last_per_leaf / first_per_leaf.max(f64::MIN_POSITIVE);
        println!("    per-leaf cost ratio (end/start): {ratio:.2}x");
        assert!(
            ratio < 3.0,
            "per-leaf cost grew {ratio:.2}x from start to end — that is superlinear. \
             A return to O(n) root() would look exactly like this."
        );
    }

    // --- Memory linearity and budget ------------------------------
    if let (Some(base), Some(last)) = (baseline_kb, samples.last().and_then(|s| s.1)) {
        let grown_bytes = last.saturating_sub(base) as f64 * 1024.0;
        let per_leaf = grown_bytes / LEAVES as f64;
        println!(
            "    final: {:.0} bytes/leaf over {LEAVES} leaves\n",
            per_leaf
        );

        // The crate documents "roughly 200+ bytes per leaf". Allow a wide
        // band: allocator slack and sampling noise are real, and a tight
        // bound here would be flaky rather than informative. What this
        // catches is an order-of-magnitude error in the documented
        // guidance, which is the thing that would actually mislead
        // someone sizing a deployment.
        assert!(
            per_leaf < 2_000.0,
            "{per_leaf:.0} bytes/leaf far exceeds the documented ~200 B/leaf budget; \
             the integration contract in lib.rs is misleading and needs correcting"
        );

        // Growth must be roughly proportional across samples, not
        // accelerating: the slope over the second half of the run must
        // not be much steeper than over the first half. RSS is
        // process-wide and the other tests in this binary run
        // concurrently, so a single early sample is noise; slopes over
        // halves are compared instead, and only once the first half has
        // grown past a noise floor.
        let points: Vec<(f64, f64)> = samples
            .iter()
            .filter_map(|(n, kb, _)| {
                kb.map(|k| (*n as f64, k.saturating_sub(base) as f64 * 1024.0))
            })
            .collect();
        if points.len() >= 4 {
            let mid = points.len() / 2;
            let (n0, m0) = points[0];
            let (n1, m1) = points[mid];
            let (n2, m2) = points[points.len() - 1];
            let first_half = (m1 - m0) / (n1 - n0);
            let second_half = (m2 - m1) / (n2 - n1);
            const NOISE_FLOOR_BYTES: f64 = 4.0 * 1024.0 * 1024.0;
            if m1 - m0 > NOISE_FLOOR_BYTES {
                let growth_ratio = second_half / first_half.max(f64::MIN_POSITIVE);
                assert!(
                    growth_ratio < 3.0,
                    "per-leaf memory slope grew {growth_ratio:.2}x from the first half to the \
                     second half of the soak ({first_half:.0} B/leaf -> {second_half:.0} B/leaf) \
                     — growth is superlinear"
                );
            }
        }
    }

    assert_eq!(log.tree_size(), LEAVES as u64);

    // The log must still be verifiable at this size — a soak that leaves
    // the structure broken proves nothing.
    let cp = log.checkpoint(&key);
    log.verify_continuity(&cp)
        .expect("a 200k-leaf log must still verify its own continuity");
}

/// Checkpoint cost must not depend on log size. This is the direct
/// assertion of the O(log n) property at a size where O(n) would be
/// obvious — a separate, sharper check than the soak's overall timing.
#[test]
fn checkpoint_cost_is_independent_of_log_size() {
    let id = IdentityKeypair::generate();
    let b = id.to_bytes();
    let key = SigningKey::from_bytes(&b);
    let mut log = WitnessLog::resume(IdentityKeypair::from_bytes(&b), 0);

    let mut timings = Vec::new();
    for target in [1_000usize, 10_000, 50_000, 100_000] {
        while (log.tree_size() as usize) < target {
            log.append_intent(b"x");
        }
        let start = std::time::Instant::now();
        for _ in 0..200 {
            let _ = log.checkpoint(&key);
        }
        let per_checkpoint = start.elapsed() / 200;
        println!("    {target:>7} leaves: {per_checkpoint:?} per checkpoint");
        timings.push((target, per_checkpoint.as_secs_f64()));
    }

    if let (Some((_, small)), Some((_, large))) = (timings.first(), timings.last()) {
        let ratio = large / small.max(f64::MIN_POSITIVE);
        println!("    100x more leaves cost {ratio:.2}x per checkpoint");
        // Checkpoint signing dominates and is constant; the Merkle root
        // is O(log n). A 100x size increase should cost well under 10x.
        // Under the old O(n) root it would be ~100x.
        assert!(
            ratio < 10.0,
            "checkpoint cost grew {ratio:.2}x for a 100x larger log — \
             that is the signature of an O(n) root computation returning"
        );
    }
}
