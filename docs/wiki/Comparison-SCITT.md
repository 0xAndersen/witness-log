# witness-log and SCITT (RFC 9943)

Part of [Comparison](Comparison). The concept-by-concept mapping and a
profile proposal are in [SCITT mapping](SCITT-Mapping). Checked against
primary sources on 2026-10-12; links at the bottom.

## What SCITT is

[RFC 9943](https://www.rfc-editor.org/rfc/rfc9943.html), "An Architecture
for Trustworthy and Transparent Digital Supply Chains" (Standards Track, June
2026), defines how an **Issuer** registers **Signed Statements** (COSE_Sign1
with CWT claims naming issuer and subject) with a **Transparency Service**,
which appends them to a Verifiable Data Structure and returns a **Receipt**
([RFC 9942](https://www.rfc-editor.org/rfc/rfc9942.html), COSE Receipts).
A Signed Statement plus its Receipt is a **Transparent Statement**, which a
**Relying Party** verifies offline; **Auditors** check the service's
consistency. It is an architecture standard, not a product.

## What it is good at

- **It is the standard.** An IETF Standards Track architecture with a
  standard envelope (COSE), standard receipts, and room for multiple
  verifiable data structures and receipt profiles. Anything that wants to
  be cited by procurement or regulators benefits from speaking it.
- **Separation of roles.** Issuers sign; the service only registers and
  endorses its log state; registration policy is explicit; Relying Parties
  never need online access to the service to check a Receipt.
- **Generality.** Any Statement about any artifact: SBOMs, build
  provenance, model cards, and, with an agent profile, agent actions.
- **Privacy guidance.** Statements may be hashes or encrypted; services can
  keep only cryptographic metadata (§8).

## Where it differs, by property

| property | SCITT (RFC 9943) | witness-log |
|---|---|---|
| who runs the log | a Transparency Service, one log for many Issuers | each agent's own process, one log per agent |
| who signs entries | each Signed Statement, by its Issuer | no per-leaf signature; the agent's identity signs checkpoints over the tree |
| non-equivocation | a security requirement on the service's VDS; Auditors with read access detect inconsistency (§4, §5.1.3, §9.7) | witnesses check a consistency proof before cosigning, refuse forks (422), and keep a proof; the verifier counts distinct organisations |
| witnesses | not part of the architecture | the core mechanism (`c2sp.org/tlog-witness`) |
| receipt | COSE Receipt from the service: "this statement is at this position in my log" | a witness cosignature: "this log's head extends what I saw before" (different statement; see the mapping page) |
| erasure | not specified; the log "cannot be modified, deleted, or reordered", but statements may be hashes | salted commitments; `forget(i)` keeps every proof |
| encoding | CBOR/COSE | binary canonical leaves, C2SP signed notes, JSON dossier |
| verdict | Receipt verification; policy is the Relying Party's | five verdicts, exit code is the verdict |

The shortest honest description: witness-log is a per-agent transparency log
whose independence comes from witnessing rather than from a separate
Transparency Service. It does not yet emit SCITT objects. The
[mapping page](SCITT-Mapping) lists what lines up, what does not, and a
concrete profile proposal.

## When to choose SCITT instead

- You need a **standards-track** artifact today, or interoperability with
  an existing SCITT Transparency Service.
- Many Issuers register into one service the ecosystem already trusts.
- Your statements are about artifacts (software, models, documents) rather
  than a per-agent sequence of actions.

## If this is wrong

If anything here misreads RFC 9943, open a PR against
`docs/wiki/Comparison-SCITT.md` with the section number.

## Sources (checked 2026-10-12)

- RFC 9943, SCITT Architecture (June 2026): <https://www.rfc-editor.org/rfc/rfc9943.html> (§3 terminology, §4, §5.1.3, §6, §8, §9.7)
- RFC 9942, COSE Receipts (June 2026): <https://www.rfc-editor.org/rfc/rfc9942.html>
- SCITT working group documents: <https://datatracker.ietf.org/wg/scitt/documents/>
