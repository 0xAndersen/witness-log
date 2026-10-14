# Keys and identity

Every witness-log has one permanent key and many temporary ones. This page
explains the two tiers, what each signs, how a restart stays provably
continuous, what custody disclosure is, how revocation works, and how to
move an identity between machines without forking it.

## Two tiers

| | identity key | session key |
|---|---|---|
| lifetime | forever (the agent's name) | one process run |
| where it lives | the journal header (`agent.jsonl`), or `identity_seed` you supply | memory only |
| signs | checkpoints (STH), key bindings, revocations, write receipts | nothing directly: each leaf *records* which session wrote it |
| public half appears in | `identity_pubkey`, the canonical origin `witness-log/<hex>`, `--identity` | `session_pubkey` on every leaf, and in the key binding |

**Why not one key?** A single long-lived key signing every leaf would have to
be in memory, in every process, all the time; compromise it once and every
historical leaf is forgeable. A single short-lived key would make history
unverifiable the moment the process exited. Two tiers give the permanence
of the first with the exposure of the second: the identity key is used a
few times per run and can live in a KMS or HSM; the session key is
disposable.

**Why leaves are not individually signed.** A leaf records its
`session_pubkey` but carries no signature of its own. The checkpoint
signature over the whole tree is what is load-bearing; it covers every leaf
and every `session_pubkey` field. Signing each leaf would cost an Ed25519
signature per event for no additional guarantee: a leaf is either in the
signed tree or it is not.

## Key bindings: how a restart stays one agent

On every `create` or `resume`, the identity key signs a
**KeyBindingStatement** (§5):

```
"witness-log-key-bind-v1" || identity_pubkey || session_pubkey || session_number (8B BE)
                           || timestamp_ms (8B BE) || not_after_present (1B) [|| not_after_ms (8B BE)]
```

It says: *identity X authorises session Y as session number N, from this
time, optionally until that time*. It is written into the journal and
exported in the dossier. A verifier checks that every `session_pubkey` on a
leaf has a valid binding; otherwise `bindings_asserted` is false or the
verdict is INVALID (DIVERGED before 0.5.0), depending on whether bindings
were present at all.

So a journal resumed a hundred times has one identity, a hundred sessions,
a hundred bindings, and an unbroken chain: leaf → session → identity. The
`session_number` increments monotonically, which is how a verifier sees that
session 42 followed session 41 rather than being a parallel fork.

`resume_with_ttl` sets `not_after_ms`, after which the binding is provably
stale. Note the presence byte before the value: "no expiry" and "expiry at
time 0" can never be confused on the wire.

## Custody disclosure

Each binding carries an *unsigned* `custody` field describing how the
session key's private half is held:

`self_held` · `platform_held` · `hsm` · `kms` · `session_delegated` · `{"threshold":{"k":…,"n":…}}` · `undisclosed` (default)

It is self-asserted, so verifiers MUST show it next to the signature result
and MUST NOT let it change the verdict. The point is transparency about
*what a valid signature means*: under a `platform_held` key, a valid
signature proves the hosting platform authorised the leaves, not that the
agent alone did. `undisclosed` is the weakest tier and is never treated as
neutral; the CLI prints it.

## Revocation

A revocation is a statement signed by the identity key itself: "this key
is revoked as of `as_of_ms`". Publish it where your verifiers look; they
apply it with `witness-log verify --revocations revocation.json` (or
`revocations_json=` in Python, `revocations` in TypeScript and Go) even
when a dossier omits it. Leaves and checkpoints signed at or after
`as_of_ms` stop counting.

```sh
witness-log log revoke agent.jsonl --reason "key on a lost laptop" --out revocation.json
```

Both timestamps are written by whoever holds the key, and after a
compromise that may be the attacker, who can backdate. RFC-0005
(experimental since 0.4.3) adds a position: `--as-of-index N` (or
`--at-current-size`) also rejects every leaf at index N or later and
every checkpoint larger than N, whatever its timestamps. Pair it with a
witnessed checkpoint of size N; witnesses refuse a different root at
that size, so the history below the cut-off cannot be rewritten either.

```sh
witness-log submit agent.jsonl --directory trusted.json --out last-good.json   # witness the last good head
witness-log log revoke agent.jsonl --reason "compromised" --experimental --at-current-size --out revocation.json
```

A verifier older than 0.4.3 rejects an index revocation outright (its
signature does not verify under the v1 message), so the extension fails
closed rather than being silently ignored.

## The canonical origin

For C2SP interop the log's origin string is `witness-log/<64 lowercase hex
of the identity public key>`. The name *is* the key, so a witness can verify
a checkpoint's signature with no key exchange; this is what makes open
enrollment safe and trust-on-first-use unnecessary. If you also publish
C2SP checkpoints under a different origin (`example.com/agent-7`), publish
the mapping to the identity key as CT logs do; only the canonical origin
counts toward a witness-log verdict.

## Moving an identity

The identity seed is the first 32 bytes that matter. To run the same agent
on a new machine:

```python
seed = old_log.identity_bytes()                       # 32 bytes; protect like a private key
new_log = witness_log.open("agent.jsonl", identity_seed=seed)   # on the new machine, fresh journal
```

Then **stop the old one**. Two live journals under one identity will produce
two histories, and the first witness to see both will record the identity as
equivocating. That is permanent evidence, by design; the protocol cannot
tell a migration from an attack. The safe migration order is: stop old →
copy journal + salts (or export a checkpoint and start a new journal with
the seed) → start new → the first `submit` from the new machine gets a 409
and resends with a consistency proof, which is fine.

`witness submit` adds a local guard: it refuses to publish a head smaller
than or conflicting with what it remembers each witness cosigning, so a
journal restored from an old backup fails locally instead of equivocating.

## Sealed journals: keeping the seed off disk

By default the identity seed is stored in the journal header so that
`open(path)` alone resumes the same identity. That is convenient and, for a
file with mode 0600 on a machine you control, usually fine. It is not fine
when the journal is on a shared volume, shipped by a log collector, or
included in backups with wider access than the key should have.

A **sealed** journal stores only the identity *public* key:

```python
seed = kms.fetch("agent-7-identity")                       # 32 bytes, from wherever you keep secrets
log = witness_log.open("agent.jsonl", identity_seed=seed, seal=True)   # create and every resume
```

```rust
let mut log = JournaledLog::create_sealed("agent.jsonl", IdentityKeypair::from_bytes(&seed))?;
let (mut log, report) = JournaledLog::resume_with_identity("agent.jsonl", &seed)?;
```

A plain `resume` of a sealed journal fails with a message naming the fix;
a resume with the wrong seed fails because the header pins the public key.
Disclose custody as `kms`/`hsm` on the binding so verifiers see it.

## Where the private material is

| artefact | contains | permissions | back up |
|---|---|---|---|
| `agent.jsonl` header | identity seed (or only the public key, when sealed) | 0600 | yes, with the sidecar |
| `agent.jsonl.salts` | redaction salts | 0600 | yes, with the journal |
| process memory | session key | — | no; it is disposable |
| `witness.key` (operators) | witness seed | 0600 | yes, **with `logs/`** |

An identity key in a KMS: generate the seed there, pass it as
`identity_seed` at `create`, and disclose custody as `kms`. The journal
header will still hold the seed in the reference implementation; embedders
who need the seed never to touch disk implement the signing hook in Rust.

## Authorization kinds

An `AuthorizationEvent` leaf (0x06) records one side of a delegation between
two identities. Each side writes its own leaf, in its own log, with its own
view of the event; `witness-log bind` later matches the pairs. The `kind`
says which side this is and what happened:

| kind | written by | meaning |
|---|---|---|
| `granted_by_me` | the principal's agent | I granted `counterparty` the scope |
| `granted_to_me` | the receiving agent | `counterparty` granted me the scope |
| `revoked_by_me` | the principal's agent | I withdrew it |
| `revoked_to_me` | the receiving agent | it was withdrawn from me |
| `scope_changed_by_me` | the principal's agent | I replaced the scope (the leaf commits to the new one) |
| `scope_changed_to_me` | the receiving agent | my scope was replaced |

The pairs mirror: a `granted_by_me` in A's log binds to a `granted_to_me`
in B's log with the same scope bytes and each naming the other's identity.
A side that holds an event the other never recorded is how a unilateral
change shows up in `bind`. The scope is arbitrary bytes; the
[commerce profiles](Commerce-Profile) use the mandate's RFC 8785 hash.

## Agent-to-agent identity

`HandoffAttestation` (0x05) and `AuthorizationEvent` (0x06) leaves carry a
`counterparty_pubkey`: the *identity* key of the other agent. Each side logs
its own leaf, so two independently witnessed logs make a cross-referenced
claim neither could fake alone. See
[Tutorial: multi-agent handoff](Tutorial-Multi-Agent-Handoff).

Next: [How a leaf becomes a proof](How-a-Leaf-Becomes-a-Proof) · [Threat model](Threat-Model) · [Operations](Operations)
