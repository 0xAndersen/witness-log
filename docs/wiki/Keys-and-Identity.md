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
verdict is DIVERGED, depending on whether bindings were present at all.

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

A **RevocationStatement**, signed by the identity key:

```
"witness-log-revoke-v1" || identity_pubkey || as_of_ms (8B BE) || reason (UTF-8)
```

Leaves written by that identity's sessions after `as_of_ms` are untrusted.
`IdentityKeypair::revoke(as_of_ms, reason)` produces the statement; it is
carried in the dossier's `revocations` list (the `0x04` KeyRevocation leaf
type exists in the wire format for logs that record it in-tree). Revocation
is forward-only: it does not
retroactively invalidate the history witnesses already cosigned, which is
exactly what you want when a key leaks; the pre-leak record stands, and
anything after the line is suspect.

If the identity key is lost rather than leaked, there is no recovery: the
identity is the key. Start a new identity and, if useful, record a
`HandoffAttestation` from the old log's last state to the new one so an
auditor can follow the thread.

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

## Where the private material is

| artefact | contains | permissions | back up |
|---|---|---|---|
| `agent.jsonl` header | identity seed | 0600 | yes, with the sidecar |
| `agent.jsonl.salts` | redaction salts | 0600 | yes, with the journal |
| process memory | session key | — | no; it is disposable |
| `witness.key` (operators) | witness seed | 0600 | yes, **with `logs/`** |

An identity key in a KMS: generate the seed there, pass it as
`identity_seed` at `create`, and disclose custody as `kms`. The journal
header will still hold the seed in the reference implementation; embedders
who need the seed never to touch disk implement the signing hook in Rust.

## Agent-to-agent identity

`HandoffAttestation` (0x05) and `AuthorizationEvent` (0x06) leaves carry a
`counterparty_pubkey`: the *identity* key of the other agent. Each side logs
its own leaf, so two independently witnessed logs make a cross-referenced
claim neither could fake alone. See
[Tutorial: multi-agent handoff](Tutorial-Multi-Agent-Handoff).

Next: [How a leaf becomes a proof](How-a-Leaf-Becomes-a-Proof) · [Threat model](Threat-Model) · [Operations](Operations)
