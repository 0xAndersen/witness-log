# Why witness-log

## The problem

An autonomous agent does things: calls tools, moves money, edits code,
sends email. Afterwards someone asks what it did. Today the answer is a log
line in a database owned by whoever ran the agent. That record can be
edited by the operator, by an attacker with database access, by a bug, or
by the agent itself; and nobody outside can tell. "The agent did X" is a
claim, not evidence.

Three audiences need better than that:

- **Developers** who need to debug and replay what an agent actually did.
- **Operators and their customers** who need to prove an agent did *not*
  do something (the refund was $250, not $25,000).
- **Auditors, regulators and counterparties** who will not take the
  operator's word for it.

## What witness-log does

1. **Every action is a leaf.** Intent before the call, result after, each
   hashed into an append-only Merkle tree (RFC 6962, the construction
   behind Certificate Transparency).
2. **The agent signs its own history.** A long-lived identity key signs
   checkpoints (tree size + root); ephemeral session keys are bound to it,
   so a restart is a provable continuation, not a new log.
3. **Independent witnesses cosign the head.** Witnesses speak the public
   `c2sp.org/tlog-witness` protocol, check a consistency proof before
   signing, and refuse (HTTP 422) any history that contradicts what they
   saw before. A log cannot show two histories without producing
   signed evidence of it.
4. **Anyone verifies offline.** A dossier (leaves + checkpoint + bindings
   + receipts) is one JSON file; `witness-log verify` returns one of four
   verdicts and an exit code, with no network and no trust in the
   operator.
5. **Right to be forgotten without breaking proofs.** Each payload is
   hashed with a per-leaf salt; erasing the salt makes that entry
   unrecoverable while every other proof stays valid.

## What it is not

- Not a database, a SIEM, or an observability product. It records
  commitments, not content; payloads stay wherever you keep them.
- Not an authorisation system. It records that a delegation happened; it
  does not mint or enforce permissions.
- Not proof that the logged content is *true*. An agent can honestly log
  a false statement. It is proof the record was not altered afterwards and
  that independent parties saw the same record.

## Why open, why Apache-2.0, why a spec

An audit trail only means something if anyone can check it with software
they did not get from the party being audited. The wire format is
specified (`spec/SPEC.md`) with a frozen conformance corpus, so a second
implementation in any language proves agreement byte for byte. The code is
Apache-2.0 (releases through 0.3.4 were AGPL-3.0); the format is free for
anyone to implement under any license.

## How it compares

| | witness-log | application logs / SIEM | blockchain anchoring | SaaS "AI observability" |
|---|---|---|---|---|
| tamper-evident after the fact | yes (Merkle + signatures) | no | yes | no |
| operator cannot rewrite history | yes, once witnessed | no | yes | no |
| verifiable offline by a third party | yes, one file | no | needs chain access | no |
| per-entry erasure (GDPR) without breaking integrity | yes | n/a | no | depends |
| cost per action | microseconds, local | low | gas / fees | per-seat |
| who runs the trust anchor | any independent witness | you | a chain | the vendor |
