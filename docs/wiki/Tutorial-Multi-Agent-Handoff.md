# Tutorial: multi-agent handoff

Two agents, two logs, one provable handoff. This tutorial shows how
witness-log records work that crosses an agent boundary (orchestrator →
worker, planner → executor, your agent → a partner's agent) without any
shared state, coordination protocol or requirement that both sides trust
each other, and how an auditor later proves that both committed to the
same content changing hands.

Time: 10 minutes. Python ≥3.9 with `witness-log`.

## Why this is its own problem

Most multi-agent systems log the handoff once, in the orchestrator. That is
one party's account. If the worker later claims it received different
instructions, or the orchestrator claims it never sent them, a single log
settles nothing. The rule in witness-log is **one writer per journal**: two
processes cannot share a log (the lock refuses, and if they could, the
history would fork). So each agent keeps its own log, and the handoff is
recorded *twice*, once per side, in a way that can be matched afterwards.

## The mechanism: HandoffAttestation leaves

Leaf type `0x05`. Agent A appends one with direction `Sent` and B's identity
as `counterparty_pubkey`; agent B appends one with direction `Received` and
A's identity. Both include `handoff_state_hash = SHA256(raw payload)`.

That hash is **deliberately unsalted**, unlike every other payload hash in
the system, because its whole purpose is to be compared across two
independently salted logs. The two leaves bind when:

```
a.direction == Sent  and  b.direction == Received
a.counterparty == B's identity  and  b.counterparty == A's identity
a.handoff_state_hash == b.handoff_state_hash
```

If all hold, both parties committed, in their own independently
witnessable logs, to the same bytes passing between the same two
identities. If the transport corrupted the bytes, the hashes differ and the
mismatch is visible instead of silently absorbed.

## Step 1: two agents, two journals

```python
# orchestrator.py and worker.py can be separate processes on separate machines;
# shown in one file for brevity.
import witness_log, json

orch   = witness_log.open("orchestrator.jsonl")
worker = witness_log.open("worker.jsonl")
ORCH_ID, WORKER_ID = orch.identity_pubkey_hex(), worker.identity_pubkey_hex()
```

The identities are exchanged out of band once (configuration, a registry,
a signed manifest). They are public keys; nothing secret moves.

## Step 2: the orchestrator decides and hands off

```python
task = witness_log.canonical_json({"task": "reconcile_ledger", "rows": 1200, "deadline": "2026-10-11T18:00Z"})

orch.append_intent(witness_log.canonical_json({"tool": "delegate", "to": WORKER_ID, "task": "reconcile_ledger"}))
i_sent = orch.append_handoff_sent(task, WORKER_ID)        # 0x05 Sent, counterparty = worker
orch.sync()
# ... transport `task` to the worker however you like: queue, HTTP, A2A, MCP ...
```

The intent leaf says *why* (the orchestrator chose to delegate); the
handoff leaf says *what* (the exact bytes) and *to whom*.

## Step 3: the worker receives and acknowledges

```python
received = task                                           # the bytes that actually arrived
i_recv = worker.append_handoff_received(received, ORCH_ID)   # 0x05 Received, counterparty = orchestrator
worker.append_intent(witness_log.canonical_json({"tool": "reconcile", "rows": 1200}))
worker.append_result(witness_log.canonical_json({"status": "ok", "mismatches": 3}))
worker.sync()
```

Note the worker hashes *what it received*, not what it was told it would
receive. That is the point: if the two hashes differ later, something
changed in transit.

## Step 4: optionally, hand the result back

```python
result = witness_log.canonical_json({"status": "ok", "mismatches": 3})
worker.append_handoff_sent(result, ORCH_ID)
orch.append_handoff_received(result, WORKER_ID)
orch.append_result(witness_log.canonical_json({"tool": "delegate", "outcome": "ok", "mismatches": 3}))
```

Now each log has a complete, self-contained account of its side, and the
two accounts cross-reference each other at two points.

## Step 5: get both witnessed

Each agent submits its own journal, exactly as a single agent would
([Getting witnessed](Getting-Witnessed)):

```sh
witness-log witness submit orchestrator.jsonl --directory trusted.json --out orch.json
witness-log witness submit worker.jsonl       --directory trusted.json --out worker.json
```

The witnesses do not know the two logs are related. They do not need to.

## Step 6: an auditor proves the handoff

Given both dossiers, the auditor verifies each (`WITNESSED`, pinned to the
expected identities), then matches the handoff leaves:

```python
import json
A, B = json.load(open("orch.json")), json.load(open("worker.json"))
sent = [l for l in A["leaves"] if l["leaf_type"] == 5 and l["handoff_direction"] == "Sent"]
recv = [l for l in B["leaves"] if l["leaf_type"] == 5 and l["handoff_direction"] == "Received"]

bound = [(a, b) for a in sent for b in recv
         if a["counterparty_pubkey"] == B["identity_pubkey"]
         and b["counterparty_pubkey"] == A["identity_pubkey"]
         and a["handoff_state_hash"] == b["handoff_state_hash"]]
print(f"{len(bound)} handoff(s) bound between the two logs")
```

Because both leaves sit inside independently witnessed Merkle trees, the
auditor can also show *when* each side committed (the checkpoint each leaf
is covered by) and that neither side has altered its account since. A
worker that later claims "I was told 12,000 rows" is contradicted by its own
witnessed `Received` leaf.

## What this proves, and what it does not

Proves: both named identities committed to the same content identifier,
in the stated roles, in histories that independent witnesses have cosigned.

Does not prove: real-time delivery (timestamps are self-asserted; witness
cosignatures give coarse corroborated time), or that the payload was not
tampered with *before either side logged it* in a way that fooled both
identically. Those are transport and attestation concerns, which witness-log
deliberately leaves to other layers ([Architecture](Architecture)).

`handoff_state_hash` is also independent of redaction: `forget()` on a
handoff leaf erases its salted `payload_hash` preimage but leaves the
unsalted state hash in place, so a binding can still be proven after the
content itself has been erased. If the content is sensitive, hand off a
reference (an object ID, a content address) rather than the data.

## Delegation of authority: AuthorizationEvent

The same two-sided pattern exists for *permissions*: leaf type `0x06`
`AuthorizationEvent` records that a delegation, scope change or revocation
happened between two identities, with an unsalted `authorization_scope_hash`
over the scope description. It is logging-only: witness-log is not an
authorization system and does not evaluate the scope; it records that the
change was committed by both sides so an auditor can later ask "under what
authority did the worker do this?" and get two matching answers.
(`append_authorization_event` in Rust; corpus vector `08_authorization_event.json`.)

## Patterns

- **Orchestrator with N workers.** One journal per worker, one per orchestrator; the orchestrator's log has N `Sent` leaves per round. Verification is per pair.
- **Cross-organisation.** Only the identity public keys are exchanged. Each side witnesses with its own directory; the auditor needs both dossiers and both parties' expected identities.
- **The other side does not run witness-log.** Record your side anyway. A one-sided `Sent` leaf is still a witnessed commitment to what you sent and to whom; it simply cannot be *bound* until the counterparty produces a matching leaf.

Next: [Keys and identity](Keys-and-Identity) · [Tutorial: audit a payments agent](Tutorial-Audit-a-Payments-Agent) · [Framework guides](Framework-Guides)
