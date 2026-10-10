# WitnessLog

**Witnessed, not trusted: a verifiable audit trail for autonomous agents.**

```
cargo install --git https://github.com/0xAndersen/witness-log witness-log-cli
witness-log demo
```

Also available as prebuilt binaries on the
[Releases](https://github.com/0xAndersen/witness-log/releases) page, as
`cargo install witness-log-cli` from crates.io, and for Python as
`pip install witness-log` (CPython 3.9+; Linux, macOS and Windows wheels).
Registry publication follows each tagged release; `--git` always works.

Zero arguments. Writes nothing to disk, makes no network calls. It builds
an agent log, redacts a leaf for GDPR, signs a checkpoint, gathers four
witnesses — then verifies the exact same bytes twice:

```
  A. With nothing supplied from outside the dossier:

       Verdict: UNANCHORED

     Every signature checked out. The Merkle root rebuilt correctly.
     But every input came from the file itself — including the list of
     witnesses it wants you to trust. This proves the file doesn't
     contradict itself. It proves nothing about who wrote it.

  B. With a witness directory YOU trust and the identity you expected,
     both obtained out-of-band (the directory lifts the ceiling; the
     identity pin says whose log it is -- a gate passes both):

       Verdict: WITNESSED

       4/4 witness signatures valid
       operator diversity          100%  (4 of 4 distinct operator buckets)
       compute-provider diversity  100%  (4 of 4 distinct providers)
```

Same bytes. Different question asked. **That gap is the whole idea** — a
log can be perfectly self-consistent and still tell you nothing, until you
anchor verification to something its author doesn't control.

Then watch a convincing forgery get caught:

```
cargo run -p witness-log-cli --bin witness-log -- demo --tamper
```

It builds the attack properly — attacker's own keypair, an invented
$10,000,000 transfer, the victim's real public key on the label, three
self-generated "independent auditors," and its own witness directory
shipped alongside. Every signature in the resulting file is valid. It
still fails:

```
    ✓ Checkpoint signature valid
    ✓ Leaf structure valid
    ✓ Merkle continuity verified
    ✗ Identity bound
        dossier claims:  caf16304…35001f81
        actually signed by: dcb4fa22…aaee61fe

    Verdict: DIVERGED
```

The forgery had flawless cryptography. It failed on a question
cryptography doesn't answer by itself: whose log is this?

## Three lines in an agent loop

```python
import witness_log
log = witness_log.open("agent.jsonl")        # create, or resume the same identity

@witness_log.step(log)                       # every call: a signed intent + result leaf
def call_tool(name: str, **args) -> dict: ...
```

That is the whole integration for any Python agent loop — LangChain,
LlamaIndex, OpenAI/Anthropic tool calling, or a hand-rolled one. Each call
appends an *intent* leaf before it runs and a *result* leaf after (errors
included), both signed, with payloads hashed under per-leaf salts so any
single entry can later be erased for GDPR (`log.forget(i)`) without
breaking a proof. `log.to_dossier_json()` is the record you hand to anyone;
`witness-log verify` checks it with no access to you.

Measured cost, this machine, Python 3.13: about **80 µs per decorated
call** on an in-memory log and **115 µs** journaled (two Ed25519-signed
leaves each; the disk write is batched, one `sync()` of 40,000 leaves
takes 28 ms). The Rust core is the same code the CLI and the witness
server run; nothing is re-implemented in Python.

For agents that speak MCP, [`integrations/mcp`](integrations/mcp) is the
same capability as seven tools: an agent provisions its own chain on
boot, records every step, proves any step, erases on request, and gets
its head cosigned by independent witnesses. Tested end to end with the
official MCP client.

Want to see a tampered record get caught? `python examples/verify_demo.py`
records three steps, edits entry #2 in storage the way a compromised
database would, and watches the verifier refuse it.

**For security and compliance teams:** this is the audit layer that
does not ask you to trust the operator. Every claim is a signature or a
hash you can recompute, the record verifies offline with nothing from
the agent's side, and `THREAT_MODEL.md` says exactly what is and is not
proven. "Witnessed" is only ever as strong as the witnesses *you* chose.

## Why this exists

Most "AI agent audit trail" tooling today assumes the operator is honest —
the log lives in your VPC, your SIEM, your Kubernetes namespace, and
"immutable" means "no delete button," not "a third party can prove nobody
rewrote it." WitnessLog is built for the case where that assumption doesn't
hold: agents transacting with other agents across organizational
boundaries, disputes where "whose log do we trust" is the actual question,
and regulatory evidence that needs to survive scrutiny from someone who
doesn't trust you by default.

It borrows its core design from Certificate Transparency (RFC 6962) rather
than blockchain consensus — an append-only Merkle log, signed checkpoints,
and independent third-party witnessing — because the problem (detecting
equivocation, verifying offline) doesn't require global consensus, a
token, or gas. See `spec/SPEC.md` for the full rationale.

**Read `THREAT_MODEL.md` before trusting this with anything real.** It
states exactly what's proven and what isn't — including the current
biggest gap (witness diversity is still thin; see `GOVERNANCE.md` for the
recruitment effort). This project would rather be honest about that than
oversell it.

## Commands

| Command | What it does |
|---|---|
| `witness-log demo [--tamper]` | The walkthrough above. No arguments, no files, no network. |
| `witness-log verify <dossier.json>` | Verify a dossier fully offline. Add `--identity` and `--directory` to anchor the run; `--explain` for what each check does and doesn't prove; `--json` for a machine-readable report. |
| `witness-log diff <a.json> <b.json>` | **The equivocation check.** Compare two copies of one log. A log that showed one history to you and a different one to someone else is exactly what witnessing exists to catch — this is how you catch it with two copies in hand. |
| `witness-log explain [verdict]` | What each verdict means, what it does NOT mean, and how to reach the next level. `--json` so an agent can ask programmatically. |
| `witness-log c2sp show <dossier.json> --origin <name>` | Render this log's checkpoint as a [C2SP](https://c2sp.org/tlog-checkpoint) checkpoint body — the artifact an existing Certificate-Transparency-ecosystem witness cosigns. |
| `witness-log c2sp verify <note.txt> --vkey <vkey>` | Verify a C2SP signed note and any witness cosignatures. Repeatable `--vkey`. |
| `witness-log witness init / serve / submit / info` | Run a [`tlog-witness`](https://c2sp.org/tlog-witness) witness, or get a journal cosigned by the witnesses in a directory (see *Run a witness, get witnessed*). |
| `witness-log conform <dir>` | Check another implementation's vectors against the reference corpus. |

**Exit codes are the verdict**, so gating needs no JSON parsing:

```sh
# proceeds only on WITNESSED (0); any weaker verdict is non-zero
witness-log verify d.json --identity "$ID" --directory "$DIR" || handle_failure
```

`0` WITNESSED · `10` CONSISTENT-UNWITNESSED · `20` UNANCHORED · `30` DIVERGED · `2` usage error

## Using it as a library

**Start here — one command, a complete working integration:**

```bash
cargo run -p witness-log-core --example quickstart
```

`crates/witness-log-core/examples/quickstart.rs` is the whole integration
in one runnable file: identity, logging intents and results, GDPR
redaction, surviving a restart, checkpointing, and exporting a dossier.
Nothing in it is pseudocode and nothing is elided. Copy the file, change
the payloads, ship it.


```toml
[dependencies]
witness-log-core = "0.3"
witness-log-network = "0.3"   # witnesses, quorum, dossiers, verification
# or, straight from the repository:
# witness-log-core = { git = "https://github.com/0xAndersen/witness-log", tag = "v0.3.2" }
```

```rust
use witness_log_core::identity::IdentityKeypair;
use witness_log_core::journal::JournaledLog;
use witness_log_network::{Dossier, VerifyContext};

// Persistent identity: generate once, keep identity.to_bytes() safe, and
// create the journal with it. Every later start is JournaledLog::resume.
let identity = IdentityKeypair::generate();
let mut log = JournaledLog::create("agent.jsonl", identity)?;

log.append_intent(br#"{"tool":"transfer_funds","args":{"amount_usd":250}}"#)?;
log.append_result(br#"{"status":"ok","tx_id":"tx_7ac31"}"#)?;
log.sync()?;

// Checkpoint signed by the identity key, and the dossier anyone can verify.
let sth = log.log().checkpoint_self();
let dossier = Dossier::from_log(log.log(), sth);
let report = dossier.verify(0.66, &VerifyContext::default());
assert!(report.internally_consistent);
```

Right-to-be-forgotten, without breaking tree continuity:

```rust
let leaf_index = log.append_memory(b"contact: alice@example.com")?;
log.forget(leaf_index)?; // salt erased from <journal>.salts; a 0x03 marker is appended.
                         // Every earlier leaf hash, and every proof over it, is unchanged.
```

The journal is two files: `agent.jsonl` (header with the identity key,
then one line per leaf) and `agent.jsonl.salts` (the redaction salts).
Both are created `0600`; back them up together and treat them as key
material. `witness_log_core::log::WitnessLog` is the in-memory core
underneath, for callers who bring their own persistence.

## Beyond the basics

Everything below is built, tested, and specified — see SPEC.md sections in parentheses.

- **Session expiry**: `resume_with_ttl(identity, session, ttl_ms)` issues a key binding that provably expires — a verifier can tell a stale session from a live one without an explicit revocation (§5).
- **Crash-safe persistence, two ways**: `save_snapshot`/`load_snapshot` (atomic whole-file rewrite — fine for logs up to the low thousands of leaves; the O(n)-per-save cost becomes the wall past that) and the append-only **journal** (`witness_log_core::journal::JournaledLog`) — one JSON line per leaf, written once, never rewritten, torn tail writes detected and physically healed on resume, the intended path to millions of leaves. Use the journal for long-lived logs.
- **Handoff attestations** (§3.1): when agent A passes context to agent B, each commits independently in its own log; `verify_handoff_binding` later proves both committed to the same bytes — no shared state, no coordination protocol.
- **Authorization events** (§3.2): logging-only record that a delegation/revocation/scope-change happened, with the same cross-log binding. If a grantee claims a wider scope than the granter logged, the binding fails. WitnessLog never mints or enforces authorization — see §1.1 on layering.
- **Machine-readable verification**: `witness-log verify --json`, and from Python, `witness_log.verify_dossier_json(dossier_json, threshold, identity, directory_json)` — the same single verification implementation the CLI uses, including quorum and both diversity axes. A regulator asking for "Q3 only" gets `WitnessLog::evidence_window(range, &key)`: the signed checkpoint, just those leaves, and an inclusion proof for each.
- **Running a witness in production**: [`deploy/witness/`](deploy/witness) has the Dockerfile, compose file, systemd unit and `OPERATORS.md` (backup rule, TLS, limits).
- **Conformance tooling**: `witness-log conform <your-corpus-dir>` field-diffs another implementation's vectors against `/corpus` — this is how a from-scratch reimplementation proves wire-format agreement (CONTRIBUTING.md).
- **Strict signature verification** (§6, normative): all Ed25519 verification is strict-mode, so conformant verifiers can never disagree about a dossier's validity on degenerate edge-case signatures.

## Catching equivocation

The attack a Merkle log alone does *not* stop is equivocation: presenting
history A to you and history B to someone else, each internally perfect,
each validly signed. Neither copy looks wrong on its own. The divergence
only exists in the comparison.

That comparison is what witnesses automate — and `witness-log diff` is
what it looks like when you do it by hand, during an incident or a
dispute, with two copies in front of you:

```
$ witness-log diff alice-copy.json bob-copy.json

  Both claim identity 92ddf224…7b13908b
  A checkpoint signature: valid   B checkpoint signature: valid

  A: 3 leaves, checkpoint at size 3, root 956a7924…31e8b78c
  B: 3 leaves, checkpoint at size 3, root 05339015…07e63ec1

  Leaves 0–1: identical
  Leaf 2: DIVERGENT

    A  type 0x01  ts 1787979414785  payload_hash 1db8b25b…c39c29a8
    B  type 0x01  ts 1787979414786  payload_hash a8a1ec2e…e277bea1

  ⚠ EQUIVOCATION DETECTED

  Neither copy is "the wrong one" — that is precisely the finding.
```

It also refuses to cry wolf. Two *different* logs that happen to record
the same events are not equivocation, and the tool says so rather than
raising an accusation — payload hashes are salted per log instance, so
independent logs always differ at leaf 0, and that specific case is
detected and explained rather than reported as a finding.

## Verifying a real dossier

`examples/sample-dossier.json` is a real generated fixture (see
`crates/witness-log-network/examples/generate_sample_dossier.rs`), not a
mock — an actual agent log with a redaction, four candidate witnesses (one
project-operated, one unresponsive), and a checkpoint, produced by running
the code in this repo.

```bash
# unanchored: proves internal consistency, nothing more
witness-log verify examples/sample-dossier.json

# anchored: the identity and the witness directory both come from you
witness-log verify examples/sample-dossier.json \
  --identity <hex-pubkey-you-expected> \
  --directory examples/trusted-directory.json
```

The unanchored run prints the exact anchored command to run next, with
the identity filled in — the CLI teaches its own trust model rather than
making you find it in a document. Add `--explain` to get a line under
every check stating what it does and, more importantly, what it doesn't
prove.

## Interoperating with existing transparency-log witnesses

The hardest problem here was never cryptographic. A witness network is
worthless until independent operators actually run witnesses, and nobody
wants to be first.

Certificate Transparency solved that over a decade. The operators, the
protocols, and the tooling already exist and are running now. So rather
than recruit a witness network from zero, WitnessLog speaks their
protocol — [`c2sp.org/signed-note`](https://c2sp.org/signed-note),
[`tlog-checkpoint`](https://c2sp.org/tlog-checkpoint), and
[`tlog-cosignature`](https://c2sp.org/tlog-cosignature) — so an existing
witness can cosign a WitnessLog checkpoint **without implementing
anything WitnessLog-specific**.

```bash
# render this log's checkpoint in C2SP form, to hand to a witness
witness-log c2sp show examples/sample-dossier.json --origin agents.example.com/agent-42

# verify what comes back, including the witness cosignature
witness-log c2sp verify cosigned-note.txt --vkey "$LOG_VKEY" --vkey "$WITNESS_VKEY"
```

Conformance is proven against the **specs' own published example
vectors** — the implementation parses the spec's signed note, verifies it
against the spec's verifier key, re-encodes it byte-for-byte, and
recomputes the spec's key ID independently. Round-trip tests pass just as
happily against a wrong-but-self-consistent implementation; those don't.
Corpus vector `10_c2sp_checkpoint.json` pins the encoding for anyone
building a second implementation.

One consequence worth knowing: a C2SP checkpoint carries **no timestamp**.
Time is asserted only by cosigners. A log structurally cannot claim its
own time, which is strictly stronger than the native format's
self-asserted field. See `spec/SPEC.md` §9.3.

## Run a witness, get witnessed

A witness is one command. It speaks
[`c2sp.org/tlog-witness`](https://c2sp.org/tlog-witness), so it serves
WitnessLog agents and any other C2SP log alike.

```bash
# operator: create a key and run it (state is fsynced before every cosignature)
witness-log witness init ./w1 --name w1.example.org/witness --org "Example Org" \
    --url http://w1.example.org:7380 --compute hetzner      # prints your directory entry
witness-log witness serve ./w1 --listen 0.0.0.0:7380 --open-enrollment
```

`--open-enrollment` accepts any agent whose origin is
`witness-log/<its identity key>`: the origin *names* the key, so there is
no key exchange and nothing to trust on first use. Forks are refused
(HTTP 422); when the log signed two roots for the same size, a
self-contained proof anyone can check goes to `evidence/`. `submit`
refuses to publish a journal that contradicts what witnesses already
cosigned, so an honest agent whose journal was rolled back cannot get
itself recorded as equivocating by accident. That memory lives in
`<journal>.witnesses.json`; a backup that restores the journal *and*
that file together restores the old memory too, so keep the two apart
(`--state <path>`) if your backups could ever roll the journal back.

```bash
# agent: get the journal cosigned by the witnesses in a directory, then verify
witness-log witness submit agent.jsonl --directory witnesses.json --out dossier.json
witness-log verify dossier.json --identity $AGENT_KEY --directory witnesses.json   # exit 0 = WITNESSED
```

`witnesses.json` is `{"witnesses": [ ... ]}` holding the entries `witness
init` prints (a bare JSON array of them is accepted too; `witness-log
witness info <url>` returns the entry under `directory_entry`). See
[`examples/trusted-directory.json`](examples/trusted-directory.json). The
resulting dossier verifies fully offline — the witnesses can be down.
WITNESSED needs cosignatures from at least two distinct `operator_org`
values in *your* directory; witnesses you run yourself all share one. From Python:
`log.add_checkpoint_body(old_size)` gives the POST body,
`log.dossier_from_responses([(witness_pubkey, body), ...])` builds the
dossier, and `witness_log.WitnessService.new(name, seed, state_path,
open_enrollment=True)` is a witness you can mount in any web framework
(create its state once with `WitnessService.create_state(path)`)
([60-line example](examples/live-network/py_witness.py)).

[`examples/live-network`](examples/live-network) runs ten live witnesses
(8 Rust, 2 Python) through ten scenarios — forks, crashes, hostile HTTP,
50 concurrent agents, Byzantine witnesses, offline audit — in about a
minute. [`examples/swarm`](examples/swarm) runs 100 named scenarios
against the *released* CLI and wheel (`--release v0.3.2` downloads them)
with twelve witnesses and 25 agents; both run in CI on every push and
their reports are committed under `examples/swarm/reports/`.

## Repository layout

```
witness-log/
├── crates/
│   ├── witness-log-core/      # leaf schema, Merkle tree, identity, redaction, STH
│   ├── witness-log-network/   # witness receipts, quorum + diversity evaluation, verdicts
│   ├── witness-log-cli/       # `witness-log` CLI: verify, diff, witness serve/submit
│   └── witness-log-python/    # PyO3 bindings — pip install witness-log, import witness_log
├── spec/SPEC.md          # normative wire format
├── corpus/               # frozen conformance test vectors (deterministic)
├── fuzz/                 # cargo-fuzz targets (Merkle proofs, dossiers, journals, CLI render, witness requests)
├── .github/workflows/    # CI (build/test/clippy/fmt/MSRV per-OS) and scheduled fuzzing
├── examples/             # sample dossier, verify_demo.py, live-network/ (10 witnesses), swarm/ (100 scenarios)
├── integrations/mcp/     # MCP server: the audit trail as tools for any MCP-capable agent
├── deploy/witness/       # run a witness in production: Dockerfile, compose, systemd, OPERATORS.md
├── THREAT_MODEL.md       # what this proves, what it doesn't
├── GOVERNANCE.md         # federation model, witness recruitment, transition plan
├── SECURITY.md           # vulnerability disclosure process
└── CONTRIBUTING.md       # conformance-gate workflow for spec/wire-format changes
```

## Conformance

`/corpus/*.json` (11 vectors) contains deterministic test vectors — leaf
encoding, Merkle roots, inclusion proofs, checkpoint signatures,
redaction continuity, consistency proofs, handoff attestations,
authorization events, external anchors, C2SP checkpoints, and the §8 payload hash — generated from a fixed seed
with no randomness, so any reimplementation can reproduce them exactly.
This is the actual interoperability gate: a wire-compatible
implementation is one that reproduces every value in `/corpus/`
byte-for-byte, not one that merely reads `SPEC.md` and looks similar.
See `CONTRIBUTING.md`.

## Status

Pre-1.0. The core log (`witness-log-core`) and witness protocol
(`witness-log-network`) are implemented and tested — see each crate's test
suite. Language bindings beyond Rust (Python via PyO3, then Node, then Go)
are in progress; see `crates/witness-log-python/README.md`.
The witness server and client are built and pressure-tested with live
processes (`examples/live-network`); real, independent witness operators
are still being recruited — see `GOVERNANCE.md`.

## License

AGPL-3.0 — see `LICENSE`. This is a deliberate choice for a trust-layer
project: derivatives, including ones offered as a network service, must
stay open. See `GOVERNANCE.md` for the broader reasoning on keeping this
infrastructure federated rather than single-vendor.

## Contributing

Spec changes go through a public RFC process (see `GOVERNANCE.md`). Code
changes should include or update conformance vectors where they touch
anything in §2–§9 of `spec/SPEC.md`.
