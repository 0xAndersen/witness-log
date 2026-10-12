# Quickstart: Python

This page gets you from `pip install` to a verified, erasable, witnessed
audit trail in about ten minutes, and explains *what is happening* at every
step so that when something surprises you later you already know why.

If you only want the code, every snippet on this page is complete and runs
as shown. If you want to understand the model first, read
[Concepts](Concepts) (ten terms, five minutes) and come back.

**What you will build:** an agent loop whose every tool call is recorded
before it runs and after it returns; a one-file proof you can hand to anyone;
an erasure that removes one entry's content without touching the proof of
anything else; and a `WITNESSED` verdict from independent operators.

---

## 0. Install

Python ≥ 3.9. The wheel contains the compiled Rust core, so there is no
compiler, no C toolchain, no native dependency to install.

```sh
pip install witness-log
python -c "import witness_log; print(witness_log.__version__)"
```

Wheels for Linux (x86_64, aarch64, musl), macOS (Intel, Apple Silicon)
and Windows, CPython 3.9+ (abi3). The same files, with `SHA256SUMS`, are on
the [Releases](https://github.com/0xAndersen/witness-log/releases/latest) page.

Why Rust underneath? The hashing, Merkle construction and Ed25519 code is
the part that must be *identical* across every language and every verifier,
forever; one implementation with a conformance corpus
([Spec and interop](Spec-and-Interop)) is how that is kept true. Python
only adds conveniences on top (`open`, `step`, `canonical_json`).

---

## 1. Open a journal

```python
import witness_log

log = witness_log.open("agent.jsonl")
print(log.identity_pubkey_hex())       # e.g. 'f7809c16…0506b3be'
```

**What just happened.** Three files may now exist next to your script:

| file | what it holds | why it matters |
|---|---|---|
| `agent.jsonl` | a header line with the agent's **identity private key**, then one JSON line per event (index, type, time, session key, payload *hash*) | this *is* the agent; whoever has it can sign as the agent |
| `agent.jsonl.salts` | one 32-byte random salt per event | deleting one salt is how one entry is erased (§4 below) |
| `agent.jsonl.lock` | the PID of the process that currently owns the journal | one writer at a time; a second `open` raises `OSError` |

Both data files are created `0600`. Treat them like a private key, because
they contain one. For anything beyond a laptop, keep the key out of the
journal: set `WITNESS_LOG_IDENTITY_SEED_ENV` to the *name* of an
environment variable holding a 32-byte hex seed (`export AGENT_KEY=$(python
-c 'import os; print(os.urandom(32).hex())'); export
WITNESS_LOG_IDENTITY_SEED_ENV=AGENT_KEY`) and `open()` seals the journal:
the header then holds only the public key, and the same variable must be
present on every resume. `open(path, seed, seal=True)` is the explicit
form.

**Identity vs. session.** `open` generated two keypairs. The **identity key**
is the agent's permanent name: it lives in the journal header and signs
checkpoints. The **session key** is fresh for *this process run*; each
event records which session wrote it. A signed *key binding* ("identity X
vouches for session Y, session number N") is written into the journal so a
verifier can prove the chain: this leaf → this session → this identity.

Why two tiers? So a restart is not a new agent. Run the script again and
`open` will **resume**: same identity, a new session, a new binding. The
history is continuous and provably so. Nothing about yesterday's events
depends on today's process still existing. Within one process, call
`witness_log.open(path, session="reuse")` to get the object you already
have open instead of a new session (a resume costs about a millisecond
and a binding line; a session key never leaves process memory, so reuse
is in-process only).

If you want the same identity on a different machine, pass
`identity_seed=log.identity_bytes()` from the original to `open` on the new
one. Otherwise never copy a journal to two live processes: the lock protects
one host, not two.

---

## 2. Record what the agent does

```python
@witness_log.step(log)
def transfer_funds(amount_usd: int) -> dict:
    return {"status": "ok", "tx_id": "tx_7ac31"}

transfer_funds(250)
log.sync()
print(log.tree_size(), log.root_hex())    # 2 <64 hex chars>
```

**What just happened.** The decorator appended **two leaves**:

1. an **intent** leaf *before* the function ran, committing to `{"args":[250],"kwargs":{},"t":<unix time>,"tool":"transfer_funds"}` (positional and keyword arguments are kept apart, exactly as the call was made);
2. a **result** leaf *after* it returned: the return value, or the exception (which is re-raised, so your error handling is unchanged).

Two leaves, not one, is the point. An audit trail that only records
outcomes cannot distinguish "the agent decided to do X and X failed" from
"the agent never decided to do X". Intent-before-action is what lets a
reviewer ask *what did it mean to do?* separately from *what happened?*
Async functions are decorated the same way.

**What a leaf is.** Neither the tree nor the journal stores your payload.
They store `payload_hash = SHA256(bucket_pad(payload) || salt || index)`,
where the salt is the random value in `agent.jsonl.salts` and `bucket_pad`
pads the payload to a 256-byte bucket so the hash does not leak the
payload's exact length. The payload bytes themselves stay wherever your
application already keeps them (your database, your trace store, the
function's return value). witness-log is a *commitment* layer: it proves
what was recorded and when, and with the salt you can later prove that a
stored payload is the one committed; it is not a second copy of your data.
This is also why the journal is small (a few hundred bytes per event) and
why nothing sensitive leaves the machine when you get witnessed.

**What `tree_size` and `root_hex` are.** Every leaf hash is a leaf of an
RFC 6962 Merkle tree. The **root** is one 32-byte value that commits to every
leaf *and their order*; change one byte anywhere, or swap two entries, and
the root changes. `tree_size` is how many leaves the tree has. The pair
`(tree_size, root)` is the entire state of the log in 40 bytes.

**What `sync()` does.** Appends are written to the journal immediately but
buffered by the OS. `sync()` calls `fsync` so the lines survive a power
loss. Call it when durability matters more than microseconds (after a
payment, before replying to a user); or pass `sync=True` to `step` to fsync
every call. Measured cost of a decorated call without sync: tens of
microseconds.

Options: `@witness_log.step(log, name="search", record_result=False)`
records only the intent (for very large or sensitive results);
`log.append_memory(b"...")` records a passive observation that is neither
intent nor result (something the agent read or was told).

---

## 3. Sign a checkpoint and hand someone the proof

```python
dossier = log.to_dossier_json()
report  = witness_log.verify_dossier_json(dossier, 0.66, log.identity_pubkey_hex())
print(report)
# {"verdict": "unanchored", "identity_pinned": true, "internally_consistent": true, ...}
```

**What a checkpoint is.** `(tree_size, root, timestamp)` signed by the
*identity* key. In Certificate Transparency this is called a Signed Tree
Head. It is a promise: "at this moment, my log had exactly these N leaves in
this order." Because the identity key signs it (not the session key), the
promise remains checkable after the process that made it is gone.

**What a dossier is.** One JSON document containing everything a stranger
needs to check that promise offline: the identity public key, every leaf
(index, type, timestamp, session key, payload hash; and the payload where
you include it), the checkpoint, the key bindings, any revocations, and
any witness receipts. Schema: `spec/dossier.schema.json`. There is no
server to query and no account to hold; the file is the proof.

**What the verifier did.** It rebuilt the Merkle tree from the leaves and
checked the root matches the checkpoint; checked the checkpoint signature
against the identity key; checked that every session key that wrote a leaf
has a valid binding to that identity; and checked the identity in the file
is the one *you said to expect* (`identity_pinned`). All of that passed, so
`internally_consistent` is true.

**Why the verdict is still only `unanchored`.** Every input came from the
file itself. The verifier has proved the dossier does not contradict
itself; it has not proved the dossier describes what actually happened,
because the agent could have rewritten its own history *and* re-signed a
new checkpoint. Nobody outside saw the old one. Anchoring the log in
someone else's memory is what witnesses are for, and that is the next step.
The four verdicts and what each one proves are in
[Verification and verdicts](Verification-and-Verdicts).

---

## 4. Erase one entry without breaking anything

```python
i = log.append_memory(b"contact: alice@example.com")
log.sync()
print(log.can_forget(i))   # True
log.forget(i)              # salt erased from agent.jsonl.salts; a Redaction leaf is appended
print(log.can_forget(i))   # False: it is gone
```

**Why this is hard elsewhere.** A hash chain or a blockchain commits to
content; delete the content and the chain no longer verifies, so most
systems either refuse erasure or break their own proofs. GDPR Article 17
does not care about your data structure.

**How witness-log does it.** Recall the leaf hash includes a random salt
stored *outside* the tree. `forget(i)`:

1. deletes leaf *i*'s salt from `agent.jsonl.salts` (the file is rewritten without it, not marked);
2. appends a **Redaction** leaf (type `0x03`) that names index *i*, so the fact that an erasure happened is itself on the record.

The original `payload_hash` for leaf *i* is unchanged, so every proof that
ever mentioned it still verifies, and every checkpoint any witness ever
cosigned is still a true statement about this tree. But without the salt,
the content behind that hash is computationally unrecoverable, even for a
payload as guessable as an email address (the salt is 32 random bytes;
there is nothing to brute-force against). The root changes because a leaf
was *added*, never because one was *changed*.

Works for entries written in earlier runs too, because the salts are on
disk, not in memory. Back up `agent.jsonl.salts` with the journal: lose it
and you have erased everything.

**The other direction: disclosing one entry.** The same salt lets you
prove to an auditor what one entry *was* without revealing anything else:

```python
log = witness_log.open("agent.jsonl", store_payloads=True)   # keep payloads in agent.jsonl.payloads
i = log.append_intent(witness_log.canonical_json({"tool": "pay", "amount_usd": 250}))
d = log.disclose(i)          # {"index", "leaf", "payload_hash", "salt", "payload"}
# the auditor, holding your dossier and nothing else:
assert witness_log.verify_disclosure(d["leaf"], d["payload"], d["salt"])
```

`verify_disclosure` recomputes `SHA256(bucket_pad(payload) || salt ||
index)` (SPEC §8; `witness_log.payload_hash` is that function) and
compares it with the leaf's `payload_hash`; the dossier verifier has
already shown the leaf is in the witnessed tree. Without
`store_payloads=True` you keep the payload yourself and `disclose` returns
the leaf and salt; with it, `agent.jsonl.payloads` holds every payload
(`0600`; it is exactly what the tree was built not to hold, so protect it
like the journal) and `forget(i)` zero-overwrites and drops its record.
Payloads from `step` are RFC 8785 canonical JSON (`canonical_json`), so a
verifier in any language can rebuild the bytes from the JSON value.

---

## 5. Get witnessed: the step that turns a claim into evidence

```python
import json

w = witness_log.Witnesser(log, "directory.json", "agent.jsonl")   # witnesses YOU trust; journal path for state
w.request()                       # call whenever you like: returns at once, never raises
...                               # the agent keeps working; submission runs in a background thread
if w.flush(timeout=30):           # bounded wait for the current head to be cosigned
    dossier = w.dossier()
    directory = open("directory.json").read()
    report = json.loads(witness_log.verify_dossier_json(
        dossier, 0.66, log.identity_pubkey_hex(), directory, min_witnesses=2))
    print(report["verdict"])      # 'witnessed' with two witnesses from two organisations
else:
    print(w.status().last_error)  # {"kind": "no_cosignatures", "message": ..., "outcomes": [...]}
w.close()
```

`Witnesser` follows the `409` resync, honours `Retry-After` on `429`/`503`,
backs off exponentially when witnesses are down, and keeps its state in
`agent.jsonl.witnesses.json`, the same file and format as the CLI, so
`witness-log witness submit agent.jsonl --directory directory.json --out
dossier.json` can take turns with it. In asyncio code use `await
w.aflush(timeout)`.

For a script that just wants the answer, one blocking round:

```python
out = log.submit("directory.json", want=8, min=2, timeout=10)   # or: await log.asubmit(...)
print(out["verdict"], out["cosignatures"], "/", out["contacted"])  # witnessed 2 / 2
json.dump(out["dossier"], open("dossier.json", "w"))
```

Same resync, `Retry-After` and refuse-to-equivocate rules (that last one
raises `RuntimeError`); per-witness failures are in `out["outcomes"]`.

Two rules it shares with the CLI: it pins the head it submits (the agent
may keep appending; the dossier it returns covers exactly the cosigned
prefix), and it refuses to submit a journal that does not extend a head
witnesses already cosigned for this identity (`status().last_error["kind"]
== "refused"`), because witnesses would keep both heads as proof that the
identity equivocated.

**Making `directory.json`.** `witness-log witness init` prints the
witness's directory entry as JSON on stdout. A directory is those entries
in a list: `jq -s '{witnesses: .}' w1.json w2.json > directory.json`, or a
bare JSON array of them.

**What a witness is.** A tiny HTTP service, ideally run by an organisation
that is not you, speaking the public `c2sp.org/tlog-witness` protocol (the
same one the Go module checksum database and Sigstore use). It holds one
key and one fact per log it has seen: *the last head I cosigned*. When you
send a new checkpoint it demands a **consistency proof** that the new tree
extends the old one without rewriting anything, then cosigns. If you ever
send a history that contradicts what it remembers, it refuses (`422`) and
keeps the two signed roots as publishable evidence of equivocation.

**Why `409` is normal.** The first time a witness sees your log you send
`add_checkpoint_body(0)` ("I have no prior head"). Later, the witness
remembers your size, and if you guessed wrong it answers `409` with the size
it expects. You resend with a proof from that size. `Witnesser`, the CLI
and the MCP server handle this loop for you.

**Why the directory is yours, not the dossier's.** The dossier carries a
copy of the witness list for display, but the verifier scores receipts
*only* against the directory the verifier supplies. Otherwise an attacker
would ship a dossier with three "independent auditors" of their own
invention. `registry/build_directory.py` builds a directory from the
public registry; you can edit it to exactly the operators you trust.

**Why `select_witnesses` and `min_witnesses=3`.** Independence is scored
by `operator_org`: two witnesses from one organisation are one voice.
`select_witnesses` picks one witness per operator first, then fills to
`want` round-robin, spread per agent so a thousand agents do not all hit
the same six machines (`Witnesser` uses it with `max_witnesses=8`).
`min_witnesses` is an absolute gate on receipt count, added because a
percentage threshold alone becomes meaningless as a directory grows; use
both, and set it to what your directory can deliver (with two local
witnesses, `min_witnesses=3` can never pass). `WITNESSED` requires at
least two distinct operators regardless of what you pass.

---

## 6. Restarts, crashes and locks: what to expect

- **Restart.** `witness_log.open(path)` resumes an existing journal: same identity, new session key, new binding. Nothing to configure.
- **Crash mid-write.** A process killed between bytes leaves a torn last line. `resume` detects it, truncates the file to the last complete line, and reports how many lines were dropped (`JournaledLog.resume(path)` returns `(log, dropped)`; `open` hides the count). You lose at most the event in flight, never the file.
- **Crash leaves a lock.** `agent.jsonl.lock` names a PID. On Linux, `resume` checks `/proc` and takes over a lock whose owner is dead. Elsewhere, or if you are sure: `JournaledLog.force_unlock(path)`.
- **Two live processes.** The second `open` raises `OSError`. This is deliberate: two writers would fork the history and your own witnesses would (correctly) record your identity as equivocating. One writer per journal; if you need many agents, give each its own journal and link them with handoff leaves ([Tutorial: multi-agent handoff](Tutorial-Multi-Agent-Handoff)).

---

## 7. Where to go next

- Put it in your framework in one line: [Framework guides](Framework-Guides) (LangChain, OpenAI Agents SDK, CrewAI, AutoGen, Google ADK, LlamaIndex, Claude).
- Expose it to any MCP-speaking agent: [MCP integration](MCP-Integration).
- Follow one leaf from `append` to `WITNESSED`, byte by byte: [How a leaf becomes a proof](How-a-Leaf-Becomes-a-Proof).
- Understand what each verdict does and does not prove before you gate a deployment on it: [Verification and verdicts](Verification-and-Verdicts).
- Full typed API: `python/witness_log/_core.pyi` and the [Python README](https://github.com/0xAndersen/witness-log/blob/main/crates/witness-log-python/README.md).
