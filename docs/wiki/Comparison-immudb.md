# witness-log and immudb

Part of [Comparison](Comparison). Checked against primary sources on
2026-10-12; links at the bottom.

## What immudb is

[immudb](https://github.com/codenotary/immudb) (Codenotary) is a database
"with built-in cryptographic proof and verification": key-value, document
and SQL models over a cryptographic commit log with a parallel Merkle tree.
It speaks gRPC and the PostgreSQL wire protocol, can be embedded as a Go
library, and records can be added in new versions but never changed or
deleted. Releases from 1.9DOM.2 on are under the Business Source License 1.1
with an additional use grant (production use allowed unless offered to third
parties as a competing hosted or embedded product), converting to Apache-2.0
four years after each version's publication.

## What it is good at

- **It is a database.** Queries, joins, indexes, ACID transactions,
  PostgreSQL clients and ORMs, millions of writes per second on the
  embedded store (per its README). witness-log stores no content and answers
  no queries.
- **Client-held state.** "It's the responsibility of the immudb client to
  track the server state": every verified read and write is checked
  against the state the client last trusted, so a client that keeps its
  state notices a server that rewrites history it already saw. That is the
  same idea as a witness, applied by every client.
- **An auditor.** `immuclient` in audit mode is an independent process that
  periodically checks the server against stored root hashes and can POST a
  notification when it detects tampering. The docs recommend running
  several in different zones.
- **Signed state.** With `--signingKey` the server signs its state, so a
  client can check it is talking to the server it expects.
- **Time-based retention** that removes old values from the value log while
  "leaving the proofs and schema configuration data intact".

## Where it differs, by property

| property | immudb | witness-log |
|---|---|---|
| unit | a database server (or embedded store) holding the content | a per-agent journal holding only salted commitments |
| who detects a server rewrite | each client that kept state, and auditors you run | witnesses run by other organisations, cosigning each head |
| what a detection produces | a failed verification at that client; an auditor result `tampered` and optional webhook (the docs note it cannot say at which transaction) | a `422` plus a self-contained equivocation proof anyone can verify with the log's key |
| what a third party can check later, offline | needs proofs from the server and a trusted state from somewhere | one dossier file + the verifier's own identity pin and witness directory |
| independence scoring | none; whoever runs clients and auditors | ≥2 distinct `operator_org` in the verifier's directory, project-run witnesses collapsed into one |
| erasure | database-level, time-based truncation of values; no per-entry erasure documented | per-entry `forget(i)`, any time, proofs intact, tombstone on the record |
| agent semantics | none (generic records) | intent/result leaves, handoff and authorization leaves |
| licence | BSL 1.1 (Apache-2.0 after four years per version) | Apache-2.0 |

The structural difference is where the trusted state lives. In immudb it
lives with each client and auditor, which is effective inside one
organisation that runs both the server and the checkers. Evidence for
someone outside (a regulator, a counterparty) needs a checker *they* trust
to have been watching, and a way to show what it saw; that is what
witness cosignatures in a dossier are.

## When to choose immudb instead

- You need a **queryable, tamper-evident database** for records your
  application reads back: ledgers, configuration history, sensor data.
- You control the clients and can run auditors, and the audience is inside
  the organisation.
- You need SQL or PostgreSQL-wire compatibility.

They compose: keep the content in immudb, and record each write's intent and
result (or just its transaction hash) as witness-log leaves so the record of
writes is witnessed by parties outside the organisation.

## If this is wrong

If anything here misstates immudb, open a PR against
`docs/wiki/Comparison-immudb.md` with a link to the source.

## Sources (checked 2026-10-12)

- immudb README and LICENSE: <https://github.com/codenotary/immudb> (model, performance figures, BSL 1.1 parameters)
- State management: <https://docs.immudb.io/1.9.6/management/state>
- Auditor (tampering detection): <https://docs.immudb.io/master/production/auditor.html>
- Data retention: <https://docs.immudb.io/master/production/retention>
