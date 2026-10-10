# Fuzz targets

Coverage-guided fuzzing of every surface that accepts attacker-controlled
bytes: dossier verification (the `witness-log verify` input path), checkpoint
parsing, and journal replay.

Requires nightly Rust (`cargo install cargo-fuzz`, then
`cargo +nightly fuzz run fuzz_dossier_verify`). Runs in CI on a schedule
(see .github/workflows/fuzz.yml), not per-commit.

**Honesty note:** these targets were authored and structurally validated
in an environment without nightly Rust; the first *executed* fuzzing runs
happen in CI. The stable-Rust hostile-input suite in
`crates/witness-log-network/tests/malformed_input_robustness.rs` covers the
same surfaces deterministically and runs on every commit.
