# Testing and evidence

Everything below runs in CI on every push (`.github/workflows/ci.yml`);
the large runs are committed under `examples/swarm/reports/`.

| layer | what | size |
|---|---|---|
| unit + integration (Rust) | Merkle (exhaustive consistency forks 1 ≤ m < n ≤ 64), signatures, journal crash cases, witness protocol, quorum/Sybil, 1,000-agent cohort simulation, 200k-leaf soak, three-perspective integrator suite, regression suites for every past review including the 0.3.5 fresh-eyes evaluation | 288 tests (1 ignored), debug + release, Linux/macOS/Windows, MSRV 1.75 |
| property tests (Rust) | `proptest`: inclusion and consistency on random trees up to 3,000 leaves; every single-bit mutation of leaf, roots and proof elements rejected; forks never extend the honest old head | 3 properties × 48 cases by default (`PROPTEST_CASES` to raise) |
| Python + MCP | bindings, schema validation of every dossier, stub/runtime surface check, fresh-eyes regressions, `Witnesser` against witnesses started from the CLI (one down, one answering 429), MCP end-to-end over stdio with the official client | 46 tests |
| framework adapters | LangChain, OpenAI Agents SDK and CrewAI tool-calling loops with fake models, dossier verified (`integrations` job, non-gating; skipped where the framework is not installed) | 3 tests |
| TypeScript client | `@witness-log/client` against the built CLI, the MCP server and two CLI witnesses (`npm.yml`) | 10 tests |
| overhead budget | append in memory and journaled, verify of 10k leaves, Python `@step`; fails on a >20% regression of the normalised median (`bench.yml`) | 5 metrics |
| conformance | corpus regenerated and diffed against the committed vectors | 11 vectors |
| supply chain | cargo-deny (advisories, licenses) on both workspaces; rustdoc with warnings denied; clippy with warnings denied | |
| fuzzing | cargo-fuzz targets for proofs, dossiers, journals, CLI rendering, witness requests | nightly, 30 min per target (`fuzz.yml`) |
| live network | 10 witnesses (8 Rust, 2 Python) through forks, crashes, hostile HTTP, 50 concurrent agents, Byzantine witnesses, offline audit | 10 scenarios |
| released-artifact swarm | downloads the GitHub release, 100 named scenarios, 12 witnesses, 25 agents | 100/100 on v0.3.2 and v0.3.3 |
| outside swarm | 1,000 (and 3,000) concurrent agents in 18 personas against 100 witnesses from four operators | 325,708 operations, 0 failures |

What the outside swarm found and fixed (0.3.3): a fraction-of-directory
threshold that did not scale to a registry, deterministic witness
selection that overloaded eight witnesses, clients that ignored
`Retry-After`. Reports before and after are both committed.

Reproduce any of it:

```sh
cargo test --workspace --release
PROPTEST_CASES=2000 cargo test -p witness-log-core --test merkle_properties --release
python examples/live-network/scenarios.py
python examples/swarm/run.py --release v0.3.3
python examples/swarm/outside.py --agents 1000 --directory <fleet>/directory.json

# Python, with the CLI built so the Witnesser tests run against real witnesses
cargo build --release -p witness-log-cli
(cd crates/witness-log-python && maturin develop --release)
python -m pytest -q crates/witness-log-python/tests integrations/mcp

# TypeScript client
(cd clients/typescript && npm ci && WITNESS_LOG_PYTHON=python npm test)

# Overhead budget
cargo bench -p witness-log-network --bench overhead
python benches/python_step.py --out target/bench-python.json
python benches/check_budget.py target/bench-rust.json target/bench-python.json
```

Run one fuzz target locally (nightly toolchain):

```sh
cargo install cargo-fuzz
cargo +nightly fuzz list
cargo +nightly fuzz run fuzz_merkle_proofs -- -max_total_time=300
cargo +nightly fuzz run fuzz_dossier_verify fuzz/artifacts/fuzz_dossier_verify/<crash-file>   # reproduce
```

Measured on the development machine (2-vCPU Intel Xeon @ 2.80GHz VM),
medians of 21 repetitions: in-memory append 4.4 µs, journaled append
without fsync 7.6–7.8 µs, verify of a 10,000-leaf dossier 23 ms, a
`@witness_log.step` call 19 µs in memory and 26 µs journaled. CI's
baseline (`benches/baseline.json`) records which runner produced it.
