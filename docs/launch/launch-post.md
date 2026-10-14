# Witnessed, not trusted: an audit trail that survives its operator

*Draft long-form post. Not published. Every number links to the file in the
repository it comes from.*

An AI agent with a payments tool transfers $25,000 where the invoice said
$250. A week later there is a dispute, and the question is not "do you have
logs?" but "why should anyone believe them?" The logs are in a database the
operator controls. The operator is now a party to the dispute.

This is the case an audit trail exists for, and it is the case most audit
trails are not built for. witness-log is an attempt to build for it, using
machinery that has been running on the internet for a decade: Certificate
Transparency.

## Why logs and hash chains fail when the operator is the adversary

A log in a database is mutable by whoever holds the credentials. "Immutable"
there means there is no delete button, which is a policy, not a property.

A hash chain (each record includes the hash of the previous one) detects an
edit, but only for someone holding an earlier head. If the operator holds
every copy, it can rewrite from any point and recompute the chain.

Signing each record does not change this. Signatures prove *who* signed.
The operator holds the agent's key, so it can sign a new history just as
validly as the old one. Per-action receipts, signed and chained, are
excellent evidence against everyone except the party holding the key.

The problem is not cryptographic. It is that every copy of the evidence,
and every key that vouches for it, belongs to one party. The fix is to make
sure some fact about the history lives somewhere that party does not
control, and is checked before it is accepted.

## The construction, in plain terms

Four steps. The README has one graphic per step
([`docs/assets/stage-0-overview.png`](../assets/stage-0-overview.png) through
`stage-5-erase.png`).

```
  agent process                          other organisations           anyone, later, offline
 ┌──────────────────────────┐            ┌───────────────────┐         ┌──────────────────────┐
 │ tool call                │            │ witness A (org A) │         │ witness-log verify   │
 │  ├─ leaf: intent         │  checkpoint│  remembers (N, R) │ cosig.  │  dossier.json        │
 │  └─ leaf: result         │ ─────────► │  checks proof     │ ──────► │  --identity  <yours> │
 │ RFC 6962 tree, root R    │  + proof   │  N→N', persists,  │         │  --directory <yours> │
 │ identity key signs (N,R) │            │  then cosigns     │         │ exit 0/10/20/30/40   │
 └──────────────────────────┘            │ witness B (org B) │         └──────────────────────┘
                                         └───────────────────┘
```

**Record.** Each tool call produces two leaves: an intent before the tool
runs and a result after. A log of outcomes alone cannot tell "decided and
failed" from "never decided". The tree never holds content, only
`SHA256(bucket_pad(payload) || salt || index)` with a 32-byte random salt
kept outside the tree.

**Commit.** Leaves form an RFC 6962 Merkle tree. The agent's long-lived
identity key signs a checkpoint over (size, root). Leaves are not signed
individually; the signed checkpoint over the whole tree is what carries the
weight, and inclusion and consistency proofs connect any leaf, and any
older checkpoint, to it.

**Witness.** The agent sends its checkpoint, with a consistency proof from
the last head each witness saw, to witnesses run by other organisations,
over [`c2sp.org/tlog-witness`](https://c2sp.org/tlog-witness), the protocol
Certificate Transparency and Go checksum database witnesses already speak. A
witness rebuilds both roots from the proof (RFC 9162 §2.1.4.2), writes its
new memory to disk, and only then cosigns. Its whole state is the last head
it cosigned per log, about 200 bytes.

**Verify.** A dossier is one JSON file. The verifier supplies two things
the dossier cannot: the identity it expects, and the directory of witnesses
it trusts. Receipts count only if they come from that directory, and
WITNESSED requires at least two distinct operating organisations. A
fabricated dossier with flawless cryptography and invented "independent
auditors" tops out at UNANCHORED.

## The rewrite experiment

An independent evaluation of version 0.3.3 used three personas (an agent
developer, a transparency-log engineer and an agent-commerce lead), built
witness-log, attacked it, and ran other agent audit tools on the same
tasks. It found six defects, all fixed in 0.3.4 and listed in the
[changelog](../../CHANGELOG.md). It also ran one experiment that separated
the tools: the operator rewrote the agent's entire history and re-signed it
with the agent's own key.

It reported that Signet, agent-receipts and Microsoft's Agent Governance
Toolkit accepted the rewritten log as valid. That is not a bug in any of
them. Each project's documentation says, in its own words, that a key
holder or anyone who can rewrite the file can produce a valid history
unless an external anchor is configured; the
[comparison pages](../wiki/Comparison.md) quote them. witness-log's
witnesses refused the rewritten head with HTTP 422 and wrote a proof of
equivocation.

You can reproduce the witness-log side in one command:

```sh
pip install witness-log && cargo install witness-log-cli
python3 examples/rewrite-attack/run.py
```

It starts two witnesses for two organisations on localhost, has an agent
log an invoice read and a $25,000 transfer, gets size 4 cosigned, and
verifies it WITNESSED. Then the operator copies the journal, cuts it back to
two leaves, as restoring an old backup would, and appends a transfer of
$250. Same key, same size, every check passes on its own: exit 20,
UNANCHORED, internally consistent. Both witnesses answer the rewritten head
with:

```
422 consistency proof failed: witness holds size 4, submitted 4
```

and each writes a 980-byte evidence file holding both checkpoint notes,
each carrying only the log's own signature.
`witness-log witness verify-evidence` exits 0: "both notes are signed by
the log's key, name the same origin and size, and commit different roots."
The witness's honesty is not an input; anyone with the log's public key can
check it. `witness-log diff` on the two dossiers reports leaves 0–1
identical, leaf 2 divergent, EQUIVOCATION DETECTED. Pasting the honest
dossier's receipts into the rewritten one changes nothing, because they
sign the honest root. The full run takes 0.4 s on a two-core host
([README](../../examples/rewrite-attack/README.md)).

## Erasure without breaking proofs

Audit logs and privacy law usually collide: a hash chain breaks if you
delete an entry, and a public chain cannot delete anything. Because the
tree commits only to salted hashes, `log.forget(i)` deletes leaf *i*'s salt
and appends a redaction leaf naming the index. The leaf hash, every
inclusion and consistency proof, and every cosignature ever issued stay
valid; the content becomes a 32-byte brute-force problem even when it was
the single word "yes"; and the erasure itself is on the record. Leaf types,
timestamps and positions stay visible, and the unlinkability argument has
not had an external cryptographic review; [`THREAT_MODEL.md`](../../THREAT_MODEL.md)
says both.

## Five verdicts, as exit codes

```
witness-log verify dossier.json --identity "$AGENT_KEY" --directory trusted.json || exit 1
```

| exit | verdict | means |
|---|---|---|
| 0 | WITNESSED | proofs verify; ≥2 independent organisations in *your* directory cosigned |
| 10 | CONSISTENT-UNWITNESSED | cryptography sound; not enough of your witnesses saw it |
| 20 | UNANCHORED | self-consistent only; no directory given; a forger can reach this |
| 30 | DIVERGED | valid, but contradicts a head you kept (`--known-head`) or a witness's equivocation proof (`--evidence`) |
| 40 | INVALID | a check failed: altered, fabricated, or not the identity you pinned |

The exit code is the verdict, so a CI gate, a settlement service or another
agent can branch on it without parsing anything. A WITNESSED dossier whose
cosigners are not a majority of your directory exits 11, because a second
history could have been cosigned by the rest. No network, no account.

## Numbers you can reproduce

- **Per-call cost:** tens of microseconds; the evaluation measured 20–27 µs
  per decorated call, and the README states 20–115 µs across the machines
  it has been timed on.
- **3,000 concurrent agents, 18 personas, 100 witnesses:** 325,708
  operations, 0 failed, 137,462 cosignings, in 605 s on a two-core host
  ([report](../../examples/swarm/reports/outside-3000.md)). The adversary
  persona's fork attempts were refused; none was cosigned.
- **The run before the fixes** found three design defects: 356 rate-limit
  stalls and 3 honest logs mis-flagged, from a fraction-only quorum gate,
  every agent choosing the same eight witnesses, and clients ignoring
  `Retry-After` ([before](../../examples/swarm/reports/outside-1000-before-fixes.md),
  [after](../../examples/swarm/reports/outside-1000.md)).
- **100 release scenarios** against the published v0.3.3 artifacts: 100/100
  ([report](../../examples/swarm/reports/v0.3.3-release.md)).

Those 100 witnesses were run by the project on one host. The swarm tests
correctness under load, not independence.

## Limits, stated plainly

- **The registry of independent witness operators is empty.** Until outside
  organisations run witnesses, WITNESSED means "witnesses you chose", which
  may mean witnesses you run yourself. That is the single biggest limit.
- **Split views need a majority gate.** A log that sends history A to one
  half of a directory and history B to the other half never meets a witness
  that saw both. Requiring cosigners from more than half the directory
  rules it out; the default 0.66 does, 0.5 does not, and the CLI warns.
- **External anchors are recorded, not checked.** `ExternalAnchor` leaves
  are hash-bound to their proof, but the verifier does not fetch or verify
  them against Rekor or a timestamp authority.
- **Leaves are not individually signed.** A leaf is evidence only inside a
  signed tree.
- **It records, it does not judge.** A witness is a notary of history, not
  of facts. A hallucinated intent is faithfully preserved.

## Run a witness

```sh
witness-log witness init ./w1 --name w1.example.org/witness --org "Example Org" --url https://w1.example.org
witness-log witness serve ./w1 --listen 127.0.0.1:7380 --open-enrollment
```

Open enrollment is safe because a log's origin is its public key: there is
nothing to register and nothing to trust on first use. Back up the key and
its memory as one object; a key restored without its memory is the one
failure no code can catch. [`deploy/witness/AGENT_OPERATOR.md`](../../deploy/witness/AGENT_OPERATOR.md)
is a playbook a coding agent can execute on free always-on compute, and a
pull request to `registry/` lists you.

## The standards angle

Nothing here is new cryptography. The tree is RFC 6962, the consistency
check is RFC 9162, checkpoints and cosignatures are C2SP signed notes, and
the witness protocol is the one already deployed, so existing CT-ecosystem
witnesses could cosign an agent's log unchanged. The wire format is
specified ([`spec/SPEC.md`](../../spec/SPEC.md)) and pinned by 11
conformance vectors that `witness-log conform` checks byte for byte, so a
second implementation can prove agreement.

Relative to SCITT (RFC 9943), witness-log is the same shape of primitive with
the Issuer running its own log and witnesses providing the independence a
separate Transparency Service would. The [SCITT mapping](../wiki/SCITT-Mapping.md)
lays out where the two align, where they do not, and a proposal for
emitting SCITT receipts. Below mandates (AP2, x402, card-network
verifiable-intent schemes) it is the layer that records what was done under
the authorization; the [AP2 tutorial](../wiki/Tutorial-AP2-Mandates.md)
runs one end to end.

Apache-2.0: <https://github.com/0xAndersen/witness-log>. If you operate
infrastructure, the most useful thing you can do is run a witness.
