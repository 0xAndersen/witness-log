# Testing and evidence

Everything below runs in CI on every push (`.github/workflows/ci.yml`);
the large runs are committed under `examples/swarm/reports/`.

| layer | what | size |
|---|---|---|
| unit + integration (Rust) | Merkle (exhaustive consistency forks 1 ≤ m < n ≤ 64), signatures, journal crash cases, witness protocol, quorum/Sybil, 1,000-agent cohort simulation, 200k-leaf soak, three-perspective integrator suite, regression suites for every past review | 268 tests, debug + release, Linux/macOS/Windows, MSRV 1.75 |
| Python + MCP | bindings, schema validation of every dossier, stub/runtime surface check, MCP end-to-end over stdio with the official client | 14 tests |
| conformance | corpus regenerated and diffed against the committed vectors | 11 vectors |
| supply chain | cargo-deny (advisories, licenses) on both workspaces; rustdoc with warnings denied; clippy with warnings denied | |
| fuzzing | cargo-fuzz targets for proofs, dossiers, journals, CLI rendering, witness requests | scheduled |
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
python examples/live-network/scenarios.py
python examples/swarm/run.py --release v0.3.3
python examples/swarm/outside.py --agents 1000 --directory <fleet>/directory.json
```
