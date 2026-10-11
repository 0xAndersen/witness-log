# Quickstart: Python

Python ≥ 3.9. The wheel contains the Rust core; no compiler needed.

```sh
pip install witness-log
# until PyPI publication completes, download the wheel for your platform from
# https://github.com/0xAndersen/witness-log/releases/latest and pip install it
```

## Three lines in an agent loop

```python
import witness_log

log = witness_log.open("agent.jsonl")          # create, or resume if it exists

@witness_log.step(log)                         # one line per tool
def transfer_funds(amount_usd: int) -> dict:
    return {"status": "ok", "tx_id": "tx_7ac31"}

transfer_funds(250)                            # intent leaf before, result leaf after
log.sync()                                     # fsync when durability matters
```

Every call to a decorated function appends an *intent* leaf (tool name,
arguments, time) before it runs and a *result* leaf (outcome, return value,
or the exception, which is re-raised) after. Async functions work the same
way. Measured cost: tens of microseconds per decorated call, journaled.

Options: `@witness_log.step(log, name="search", record_result=False)` records
only the intent (for large or sensitive results); `sync=True` fsyncs every
call.

## Hand someone the proof

```python
dossier = log.to_dossier_json()                # one JSON file: leaves, checkpoint, bindings
report = witness_log.verify_dossier_json(dossier, 0.66, log.identity_pubkey_hex())
print(report)                                  # {"verdict": "unanchored", "internally_consistent": true, ...}
```

`unanchored` means "internally consistent, nobody independent has seen
it". To reach `witnessed`, submit to witnesses:

```python
import json, urllib.request
directory = json.load(open("directory.json"))  # witnesses YOU trust; registry/build_directory.py makes one
picks = json.loads(witness_log.select_witnesses(json.dumps(directory), log.identity_pubkey_hex(), 6))
responses = []
for w in picks:
    body = log.add_checkpoint_body(0)          # 409 → retry with add_checkpoint_body(int(response_body))
    req = urllib.request.Request(w["url"] + "/add-checkpoint", data=body.encode(), method="POST")
    with urllib.request.urlopen(req) as r:
        responses.append((w["pubkey"], r.read().decode()))
dossier, accepted = log.dossier_from_responses(responses)
report = json.loads(witness_log.verify_dossier_json(
    dossier, 0.66, log.identity_pubkey_hex(), json.dumps(directory), min_witnesses=3))
assert report["verdict"] == "witnessed"
```

Or let the CLI do it: `witness-log witness submit agent.jsonl --directory directory.json --out dossier.json`.

## Erase one entry (right to be forgotten)

```python
i = log.append_memory(b"contact: alice@example.com")
log.forget(i)        # salt erased from agent.jsonl.salts; a 0x03 marker is appended
log.can_forget(i)    # False now; every other proof is unchanged
```

Works for entries written in earlier runs too.

## Restarts, crashes, locks

- `witness_log.open(path)` resumes an existing journal with the same
  identity and a new session key; the dossier carries every binding.
- A process killed mid-write leaves a torn last line; `resume` drops it,
  truncates the file, and reports how many lines it dropped.
- A dead process leaves `agent.jsonl.lock`; on Linux `resume` recovers it
  when the PID is gone. Elsewhere: `JournaledLog.force_unlock(path)`.
- Two live processes on one journal: the second gets `OSError`. One
  writer per journal, by design.

## The files

| file | contents | treat as |
|---|---|---|
| `agent.jsonl` | header with the identity **private** key, then one line per leaf/binding | key material, 0600 |
| `agent.jsonl.salts` | per-leaf redaction salts | key material, 0600; back up with the journal |
| `agent.jsonl.lock` | PID of the holder | transient |
| `agent.jsonl.witnesses.json` | last size each witness cosigned (CLI submit) | cache |

Full API: `python/witness_log/_core.pyi` (typed stubs) and the
[Python README](https://github.com/0xAndersen/witness-log/blob/main/crates/witness-log-python/README.md).
