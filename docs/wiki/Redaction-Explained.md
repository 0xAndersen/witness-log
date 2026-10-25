# Redaction explained

How witness-log erases one entry's content permanently while every proof
that ever mentioned it keeps verifying. This is the property most
tamper-evident systems cannot offer, and the one regulators ask about first.

## The problem

An audit trail must be immutable or it is not an audit trail. A privacy law
(GDPR Art. 17, CCPA, and the rest) says a person can require their data to be
erased. Hash chains, blockchains and most append-only logs commit directly
to content: delete the content and the chain no longer verifies, so
operators are forced to choose between the regulator and the auditor.
Common workarounds (store only hashes; store encrypted and "throw away the
key") have a flaw each: a bare hash of low-entropy data is a dictionary
lookup away from the data, and a shared encryption key erases everything or
nothing.

## The construction

Every leaf's hash includes a 32-byte random **salt** that is stored *outside*
the Merkle tree:

```
payload_hash = SHA256( bucket_pad(payload) || salt || leaf_index )
```

The tree commits to `payload_hash`. The payload itself is never stored by
witness-log; it lives wherever your application keeps it, and the salt
(kept in `agent.jsonl.salts`, one record per leaf, `0600`) is what lets you
prove later that a stored payload is the one committed.

To forget leaf *i*:

1. the salt record for *i* is **removed** from the sidecar (the file is rewritten without it; nothing is flagged or zeroed in place, the record ceases to exist);
2. a **Redaction leaf** (type `0x03`, `redacted_index = i`) is appended, so the erasure is itself on the permanent record;
3. you delete the payload from your own store, as you would have anyway. Without the salt, the hash left in the tree can no longer be matched to any content, even by someone who later obtains the deleted bytes from elsewhere.

Nothing about leaf *i*'s hash changed. So:

| proof | before `forget(i)` | after |
|---|---|---|
| inclusion proof for leaf *i* | valid | **still valid** (the hash is the same) |
| inclusion proof for any other leaf | valid | still valid |
| consistency proof between any two checkpoints | valid | still valid |
| every witness cosignature ever issued | a true statement | **still a true statement** |
| the content of leaf *i* | readable | **gone** |

The root changes, because a leaf was *added*, which is the normal thing a
log does; it never changes because a leaf was *altered*.

## Why the content is really gone

Without the salt, recovering the payload means finding `(payload, salt)` such
that the hash matches. The salt is 32 uniformly random bytes. Even for a
payload with one bit of entropy ("yes"/"no") there is no shortcut: the
attacker is brute-forcing 256 bits. Compare the unsalted design, where
`SHA256("alice@example.com")` is confirmed by one guess.

Bucket padding adds a second protection that survives erasure: `bucket_pad`
zero-pads the payload to a 256-byte bucket and prefixes its real length,
so the tree never reveals the exact length of what was erased, only its
bucket.

## What the record still shows

Erasure is honest, not invisible. After `forget(i)` anyone with the dossier
can see:

- that leaf *i* existed, its type (intent/result/memory), its timestamp and which session wrote it;
- that it was redacted, and when (the position of the Redaction leaf);
- nothing about what it said.

This is deliberate. A compliance officer needs to show that the erasure
happened and that it was *only* that entry; an auditor needs to know the
history has a hole in it and where. Hiding the hole would make redaction
indistinguishable from tampering. Leaf type, timestamp and tree position
are therefore metadata the scheme does not hide ([Threat model](Threat-Model)).

## Normative requirement

The spec (§8) leaves *where* salts live to the implementation but demands
one thing: a forgotten salt MUST be erased from every store the
implementation controls, not merely marked. In the reference implementation
the sidecar is rewritten without the record and fsynced. The `SaltStore`
trait exists so an embedder with a KMS or a database can implement the same
contract; `FileSaltStore` is the reference.

The in-memory `WitnessLog` (no journal) keeps salts in memory only; use
`JournaledLog` for anything that must survive a restart, or
`forget` after a restart will have nothing to erase (`can_forget` returns
false).

## Operational rules

- **Back up `agent.jsonl.salts` with `agent.jsonl`, atomically.** Lose the sidecar and you have erased every entry at once; the proofs still verify but nothing is readable.
- **Treat the sidecar as key material** (`0600`, same custody as the journal). It is the only thing that makes the payload hashes meaningful.
- **Erasure is irreversible.** `can_forget(i)` tells you whether the salt still exists; after `forget` it returns false and there is no undo.
- **Erasure works across runs.** Salts live on disk, so an entry written last month can be forgotten today.
- **Marker leaves have no salt.** Redaction (0x03) and KeyRevocation (0x04) carry no payload and commit the all-zero hash; `can_forget` is false for them by construction.

## Worked example

Corpus vector `05_redaction_continuity.json` is exactly this scenario: a
tree is built, a checkpoint signed, a salt forgotten, and the vector shows
that the previously committed leaf hash and every proof are unchanged. Run
`witness-log demo` to watch it with narration, or in Python:

<!-- doctest -->
```python
import json, witness_log
log = witness_log.open("demo.jsonl")
a = log.append_intent(b'{"tool":"lookup","args":{"customer":"alice@example.com"}}')
b = log.append_result(b'{"status":"ok"}')
before = log.to_dossier_json()                        # includes a proof of leaf a
log.forget(a)
after = log.to_dossier_json()

old, new = json.loads(before)["leaves"], json.loads(after)["leaves"]
assert new[a]["payload_hash"] == old[a]["payload_hash"]                # leaf a's hash is unchanged
assert not log.can_forget(a)                                           # its salt is gone from demo.jsonl.salts
assert new[-1]["leaf_type"] == 3 and new[-1]["redacted_index"] == a    # one more leaf: 0x03 naming a
for d in (before, after):                                              # and both dossiers verify
    assert json.loads(witness_log.verify_dossier_json(d, 0.66))["internally_consistent"]
```

## How this compares

| approach | erase one entry | proofs survive | content unrecoverable | erasure visible on record |
|---|---|---|---|---|
| plain hash chain / blockchain | no (breaks the chain) | — | — | — |
| store hashes only, no salt | yes | yes | **no** for guessable data | no |
| encrypt + destroy a shared key | all or nothing | yes | yes | no |
| encrypt per-entry keys | yes | yes | yes | no, unless you add a marker |
| **witness-log salted tombstones** | yes | yes | yes | yes (0x03 leaf) |

Next: [How a leaf becomes a proof](How-a-Leaf-Becomes-a-Proof) · [Compliance](Compliance) · [Threat model](Threat-Model)
