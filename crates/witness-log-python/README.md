# witness-log (Python)

Python bindings for `witness-log-core` and `witness-log-network`, built
with PyO3/maturin. Same wire format as the Rust crates and the same
guarantees: see the root `README.md` and `THREAT_MODEL.md` before using
this for anything real. Ships type stubs (`py.typed`).

## Install

```bash
pip install witness-log
```

abi3 wheels for Linux x86_64/aarch64 (glibc and musl), macOS x86_64/arm64
and Windows x86_64, Python ≥ 3.9; the same files with `SHA256SUMS` are on
the [GitHub release](https://github.com/0xAndersen/witness-log/releases).
To build from source: `pip install maturin && maturin build --release`
in this directory.

## Quickstart: an agent loop

```python
import witness_log

log = witness_log.open("agent.jsonl")        # create, or resume if it exists

@witness_log.step(log)                       # one line per tool
def transfer_funds(amount_usd: int) -> dict:
    return {"status": "ok", "tx_id": "tx_7ac31"}

transfer_funds(250)                          # two leaves: intent, then result
log.sync()                                   # fsync when you need durability

pii = log.append_memory(b"contact: alice@example.com")
log.forget(pii)        # right-to-be-forgotten: the salt is erased from agent.jsonl.salts
                       # and a marker leaf appended; every earlier proof is unchanged.

dossier = log.to_dossier_json()              # the bundle anyone can verify offline
report = witness_log.verify_dossier_json(dossier, 0.66, log.identity_pubkey_hex())
log.close()
```

`witness_log.open(path, identity_seed=None)` creates `path` with a new
identity (or `identity_seed`, 32 bytes you keep) and resumes it on every
later run. The journal is two files, `agent.jsonl` and `agent.jsonl.salts`,
both `0600`; the first line of the journal holds the identity **private**
key, so protect and back up both like key material. A process killed while
holding the journal leaves `agent.jsonl.lock`; on Linux `resume` clears it
when the recorded PID is gone, elsewhere call
`JournaledLog.force_unlock(path)` once you are sure nothing else has it open.

Any dossier produced here verifies with the Rust CLI unmodified:

```bash
witness-log verify dossier.json --identity <hex> --directory witnesses.json
```

That cross-language round trip is what the wire format (`spec/SPEC.md`)
and conformance corpus (`/corpus/`) exist to guarantee.

## Getting WITNESSED

A dossier with no independent cosignatures verifies as `unanchored` (or
`consistent_unwitnessed` with a directory). To reach `witnessed`, at least
two witnesses with distinct `operator_org` values in the verifier's
directory must cosign the head:

```python
w = witness_log.Witnesser(log, "trusted.json", "agent.jsonl")   # background thread
w.request()                         # never blocks, never raises
if w.flush(timeout=30):             # bounded wait for the current head
    report = witness_log.verify_dossier_json(w.dossier(), 0.66, log.identity_pubkey_hex(),
                                             open("trusted.json").read())
print(w.status())                   # witnessed_size, cosignatures, last_error (structured)
```

`Witnesser` follows `409` resyncs, honours `Retry-After`, backs off when
witnesses are down, keeps its state in `<journal>.witnesses.json` (the
CLI's file and format) and refuses to submit a journal that contradicts a
head witnesses already cosigned. `await w.aflush()` in asyncio code;
`witness_log.submit_round(...)` for one synchronous round. The protocol
primitives underneath are `add_checkpoint_body(old_size)` and
`dossier_from_responses(...)` (and their `_at(size, ...)` forms).

## Extras

| extra | gives you |
|---|---|
| `witness-log[mcp]` | the MCP server: `witness-log-mcp` (stdio), ten tools including `submit_to_witnesses` |
| `witness-log[langchain]` | `witness_log.integrations.langchain.WitnessLogCallbackHandler` |
| `witness-log[openai-agents]` | `witness_log.integrations.openai_agents.WitnessLogHooks` |
| `witness-log[crewai]` | `witness_log.integrations.crewai.witness_crewai` |

## Running a witness

`WitnessService.new(key_name, seed, state_path, open_enrollment=True)` is a
witness you can mount in any web framework: hand it the body of each
`POST /add-checkpoint` and send back what it returns. Create its state once
with `WitnessService.create_state(path)`; the state file is bound to the
witness key and persisted before any cosignature leaves the process.
[`examples/live-network/py_witness.py`](../../examples/live-network/py_witness.py)
is a complete 60-line server.

## API surface

Everything is typed in [`python/witness_log/_core.pyi`](python/witness_log/_core.pyi).

| | |
|---|---|
| `witness_log.open(path, identity_seed=None)` | `JournaledLog`: create or resume. |
| `witness_log.step(log, name=None, *, record_result=True, sync=False)` | Decorator: intent leaf before the call, result (or error) leaf after. Sync and async. |
| `witness_log.canonical_json(value)` | The byte form `step` hashes. |
| `JournaledLog.create(path, seed)` / `.create_ephemeral(path)` / `.resume(path)` | Explicit constructors; `resume` returns `(log, dropped_trailing_lines)`. |
| `.append_intent/.append_result/.append_memory(bytes)` | New leaf index. |
| `.append_handoff_sent/.append_handoff_received(state, counterparty_hex)` | SPEC §3.1 cross-log binding. |
| `.forget(i)` / `.can_forget(i)` | Redaction; works for leaves from earlier sessions. |
| `.checkpoint()` / `.to_dossier_json()` / `.leaves_json()` | JSON, SPEC §6 / §9 / §2. |
| `.inclusion_proof(i)` → `(tree_size, root_hex, path)` | Check offline with `verify_inclusion(...)`. |
| `.add_checkpoint_body(old_size)` / `.dossier_from_responses(...)` | Witness protocol client; `_at(size, ...)` forms pin an earlier head; `.root_hex_at(size)`. |
| `Witnesser(log, directory, path)` / `submit_round(log, directory, state_path)` | Background / one-shot witnessing (see above). |
| `.sync()` / `.close()` / context manager | Durability; releasing the lock. |
| `JournaledLog.force_unlock(path)` | After a crash, when `resume` cannot tell the holder is gone. |
| `WitnessLog` | The in-memory core (snapshots, no salt persistence). |
| `WitnessService` | A `tlog-witness` witness. |
| `verify_dossier_json(dossier, threshold, identity=None, directory_json=None)` | The CLI's verifier; report JSON with `verdict`, `identity_pinned`, `internally_consistent`, `quorum`. |
| `verify_inclusion(leaf_hash_hex, index, tree_size, path, root_hex)` | RFC 6962 inclusion check. |
| `select_diverse_witnesses(directory_json, subject_pubkey, want)` / `select_witnesses(...)` | Pick operator-diverse witnesses from a directory (object or bare list). |
| `witness_entry_independent(...)` / `witness_entry_project_operated(...)` | Build directory entries. |

Errors: `WitnessLogError` (base), `SignatureError`, `ContinuityError`,
`MalformedError`; I/O failures raise `OSError`; bad arguments raise
`ValueError`/`TypeError`. Payloads are `bytes`.

This crate is intentionally thin: it does not reimplement any
serialization logic; every JSON shape here is the Rust crates' own `serde`
output, so it stays in lockstep with `spec/SPEC.md` by construction.
