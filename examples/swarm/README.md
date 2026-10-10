# Swarm: 100 scenarios against a released witness-log

`run.py` tests what a developer actually installs, the CLI binary and the
`witness_log` wheel, with twelve witnesses running live (8 Rust, 2 Python,
2 started by agents inside the swarm) and 25 concurrent agents logging,
submitting, verifying, tampering, crashing and racing against them. Every
scenario is one function with a one-line result; nothing is mocked.

```sh
cargo build --release -p witness-log-cli
(cd crates/witness-log-python && pip install maturin && maturin develop --release)
pip install jsonschema                           # for the schema scenario
python examples/swarm/run.py                     # local build, ~20 s
python examples/swarm/run.py --release v0.3.1    # a GitHub release: downloads CLI + wheel, verifies SHA256SUMS
python examples/swarm/run.py --only T038,T055    # a subset
```

Output: `<out>/REPORT.md` and `<out>/results.json`. Exit status is the
number of failures. CI runs the whole thing on every push and uploads the
report.

| category | count | what it covers |
|---|---|---|
| install | 6 | `--version`, `--help`, `demo`, package import, stubs, docstrings |
| cli-verify | 14 | exit codes 0/10/20/30/2, argument validation, `--json` fields, directory formats, `explain`, warnings |
| tamper | 14 | edited/deleted/reordered leaves, forged timestamps, receipt games, binding expiry, unknown leaf types, impersonation, `diff` |
| python | 16 | `open`/`step`, async, redaction across restarts, salt sidecar, locks and crashes, torn tails, corruption, proofs, validation, throughput |
| witness | 14 | submit/cosign, 409 resync, incremental proofs, same-size and growing forks, stale/replayed heads, origins, forged signatures, rollback guard, C2SP receipts |
| adversarial | 12 | garbage bodies, methods, size caps, chunked, junk proofs, slowloris, header floods, proof-line and body caps, connection bursts |
| crash | 8 | SIGKILL/SIGTERM witnesses, double serve, stale locks, swapped keys, missing state, Python witness state binding |
| swarm | 6 | 25 agents x 3 rounds, racing submitters, agents as witnesses, Byzantine witness, Sybil directory, 50 parallel verifies |
| c2sp | 5 | `show`/`--raw`/`--sign-with`, `verify`, corpus vector 10, key-id derivation |
| docs | 5 | README exit table, `conform`, JSON Schema, SPEC vs `explain`, `verify_demo.py` |

Scenarios tagged `fixed_in` are regressions for defects found in the named
release; those tagged `since` use an API first shipped then. Against
`v0.3.1` they fail and the report says so; against `0.3.2` all 100 pass.
A failure that carries neither tag is a new finding.

Results on 2026-10-10 (Linux x86_64, Python 3.13):

| target | passed | unexpected failures |
|---|---|---|
| GitHub release v0.3.1 (downloaded) | 67/100 | 0 (33 expected: 26 `fixed_in 0.3.2`, 7 `since 0.3.2`) |
| 0.3.2 local build | 100/100 | 0 |
| GitHub release v0.3.2 (downloaded) | 100/100 | 0 |

Reports: [`reports/v0.3.1-release.md`](reports/v0.3.1-release.md),
[`reports/0.3.2.md`](reports/0.3.2.md),
[`reports/v0.3.2-release.md`](reports/v0.3.2-release.md).

Every cryptographic, protocol, adversarial and concurrency scenario passed
on both. The 0.3.1 failures are the usability and recovery defects the
four-integrator review found, fixed in 0.3.2: redaction after a restart,
automatic stale-lock recovery, argument validation, `verify` prose, C2SP
tooling, state-to-key binding.
