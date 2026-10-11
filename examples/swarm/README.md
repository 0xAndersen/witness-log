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
| GitHub release v0.3.2 (downloaded) | 100/100 | 0 |

Reports: [`reports/v0.3.1-release.md`](reports/v0.3.1-release.md),
[`reports/v0.3.2-release.md`](reports/v0.3.2-release.md).

Every cryptographic, protocol, adversarial and concurrency scenario passed
on both. The 0.3.1 failures are the usability and recovery defects the
four-integrator review found, fixed in 0.3.2: redaction after a restart,
automatic stale-lock recovery, argument validation, `verify` prose, C2SP
tooling, state-to-key binding.

## outside.py: a thousand agents at once

`outside.py` is the load-and-behaviour test: N agents (default 1,000), each
its own identity and journal, each running one of 18 personas against a
live witness network, concurrently. Personas are what real users do: a
coder with decorated tool calls, a trader at 600 appends, a support bot
redacting PII across a restart, a two-stage pipeline with a handoff, an
MCP client, a CLI-only user, a supervisor whose child dies mid-session, an
auditor verifying strangers' dossiers and tampered copies, an adversary
trying to get a fork cosigned, an operator standing up its own witness
mid-swarm, a snapshot user, a five-session agent, 2 MiB payloads, a C2SP
user, a schema checker, a verifier that never logs, and an agent restoring
a journal from an old backup.

```sh
python deploy/witness/fleet.py init /tmp/fleet --count 100 --org "Example Org" \
    --name-base witness.example/w --url-base http://127.0.0.1 --base-port 20000
python deploy/witness/fleet.py serve /tmp/fleet --open-enrollment &
python examples/swarm/outside.py --agents 1000 --directory /tmp/fleet/directory.json
```

Every operation is timed; every error keeps its message; the report
clusters failures by signature so the common problems come first. What the
first 1,000-agent run against 100 witnesses (four operators x 25) found:

1. **The receipt threshold did not scale to a registry.** `--threshold 0.66`
   of a 100-witness directory demanded 66 cosignatures per checkpoint; agents
   with eight valid receipts from four operators stayed CONSISTENT-UNWITNESSED.
   Fixed: `--min-witnesses N` / `min_witnesses=` / `VerifyContext.min_receipts`,
   an absolute gate, reported as `count_gate`.
2. **Witness selection sent every agent to the same eight witnesses**, tripping
   their per-address enrollment limits (356 x 429) while 92 sat idle, and
   leaving the 429'd witnesses able to cosign a later fork they had never seen
   the honest head of. Fixed: selection is spread per subject identity across
   each operator's witnesses, and `select_witnesses` fills to `want` round-robin
   after one-per-operator.
3. **Clients gave up on 429.** The CLI honoured `Retry-After` only up to 15 s,
   the MCP server not at all. Fixed: both wait as told, up to 60 s.

After the fixes: 1,000 agents, 92,301 operations, 0 failures, 22,620
cosignings, every agent that asked for WITNESSED reached it
(`reports/outside-1000.md`; the run before the fixes is
`reports/outside-1000-before-fixes.md`). Witness `add-checkpoint` p50 was
108 ms with 128 agents in flight on a two-core host running all 100
witnesses and all agents. A 3,000-agent run on the same host
(`reports/outside-3000.md`): 325,708 operations, 137,462 cosignings, 0
failures, all 100 witnesses up at the end; the p99 of `add-checkpoint`
rose to 3.7 s because the two cores were saturated by agents and witnesses
together, not because anything queued inside the witness.
