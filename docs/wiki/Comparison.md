# Comparison: where witness-log sits

How witness-log differs from the other ways people record what an agent
did, and when each is the right tool. The comparisons are by *property*,
because named products change; the properties do not.

## The properties that matter for an audit trail

1. **Tamper evidence**: can an edit after the fact be detected by someone who does not control the system?
2. **Independence**: does detection depend on anyone other than the operator? Who?
3. **Offline verifiability**: can a third party check the record years later with no account, no API and no uptime dependency?
4. **Erasure**: can one entry's content be removed for a privacy request without destroying the proofs around it?
5. **Intent capture**: is what the agent *decided* recorded separately from what *happened*?
6. **Cost and footprint**: what leaves the machine, what does it cost per event, what must stay up?
7. **Interoperability**: does it speak a format other tools already understand?

## Side by side

| | application logs / observability (traces, spans, APM) | database with audit table | hash chain / "immutable ledger" (single party) | public or consortium blockchain | **witness-log** |
|---|---|---|---|---|---|
| tamper evidence | none; whoever writes can rewrite | none against the DBA | yes, *if* someone saved an earlier head; otherwise the operator re-chains | yes | yes: Merkle root + signed checkpoint |
| independence | operator only | operator only | operator only, unless heads are published | validators / miners | ≥2 organisations *the verifier chooses* must have cosigned |
| offline verifiability | no | no | partially (need a trusted earlier head) | needs a node or an indexer | yes: one file, one static binary, exit code |
| erasure of one entry | yes (it is just data) | yes | **breaks the chain** | **impossible** (and content is public) | yes: delete the salt; proofs intact; tombstone recorded |
| intent before result | only if you instrument it | only if you instrument it | no | no | built in (decorator, MCP, frameworks) |
| what leaves the machine | everything, to the vendor | nothing / backups | nothing | **everything**, replicated to strangers, forever | 40-byte checkpoints to witnesses you pick |
| cost per event | vendor pricing | DB write | one hash | gas / fees, seconds of latency | one SHA-256 + a journal line; tens of µs |
| uptime dependency for verification | vendor | your DB | none | network | none |
| interop | OTLP etc. (observability, not evidence) | none | none | per chain | C2SP transparency formats; CT-ecosystem witnesses can cosign |
| what it is good at | debugging, metrics, dashboards | queries, joins | cheap integrity inside one org | public settlement, shared state between adversaries | evidence that survives the operator |

The rows are not a verdict on the other tools; they are different jobs.
You still want traces for debugging and a database for queries. witness-log
is the layer that turns "our logs say" into "here is proof", and it sits
beside them, not instead of them.

## Versus observability and tracing

Traces are for engineers to understand behaviour; they are owned, retained
and editable by the operator and the vendor. They answer "what happened?"
to people who already trust the system. witness-log answers "can you prove
it?" to people who do not. The natural integration is to keep tracing as
is and add two leaves per tool call ([Framework guides](Framework-Guides)),
then store the trace ID in the leaf payload so the proof points at the
detail.

## Versus a hash chain or single-party "immutable" log

A hash chain (each record hashes the previous) is tamper-*evident* only to
someone holding an earlier head. If the operator holds all copies, they can
rewrite from any point and re-chain; nobody can tell. Publishing heads fixes
that, and once you publish heads to independent parties who check
consistency before accepting the next one, you have reinvented witnesses.
witness-log is that design done with the standard protocol
(`c2sp.org/tlog-witness`), a Merkle tree (so inclusion proofs are
logarithmic rather than linear), and erasure that does not break the chain.

## Versus a blockchain

Blockchains solve a harder problem than an audit trail needs: agreeing on
shared state between mutually distrusting parties who all want to write.
An audit trail has one writer. Paying for consensus buys nothing here, and
the costs are real: content (or at least hashes) replicated to strangers
forever, which is incompatible with erasure; fees and latency per event;
and dependence on a network's continued existence to verify anything. A
witness-log checkpoint can be *anchored* to a chain or a timestamp authority
with an `ExternalAnchor` leaf when you want corroborated time from outside
the witness set; that is the sensible division of labour.

Independence in a blockchain comes from validators you did not choose.
Independence in witness-log comes from operators *the verifier* chose,
scored explicitly by organisation, with project-run witnesses collapsed
into one bucket so the project cannot vouch for itself.

## Versus a vendor's "AI audit log" feature

Platform-hosted audit logs are owned by the platform. They are useful and
you should keep them, but the platform can edit them, and a regulator or a
counterparty has to take the platform's word. witness-log's identity key
can live with the operator or in the operator's KMS, and custody is
disclosed on every binding (`self_held`, `kms`, `platform_held`, …) so a
verifier knows exactly whose signature they are looking at. The dossier
leaves the platform and verifies without it.

## Versus Certificate Transparency itself

witness-log *is* the CT construction (RFC 6962 tree, signed tree heads,
consistency proofs, independent witnesses) applied to agent actions instead
of certificates, with three additions CT did not need: two-tier keys for
restarting processes, salted payload hashes for erasure, and intent/result
leaf semantics. Where CT has one public log per operator with public
content, witness-log has one private log per agent with only commitments
public. The witness protocol is shared, deliberately, so the CT
ecosystem's witnesses are reusable ([Spec and interop](Spec-and-Interop)).

## Versus the agent-record and SCITT drafts

witness-log aims for wire compatibility with `draft-maintainer-1f916-agent-record`
where the primitive is the same and notes divergences inline in the spec.
Relative to IETF SCITT (supply-chain transparency) it occupies the same
*transparency* layer and leaves attestation, identity and authorization to
their own layers, which is the decomposition the proposed AUDIT working
group has converged on. The conformance corpus exists so that an
independent implementation can prove it computes the same bytes.

## When not to use witness-log

- You need queryable, mutable state shared between many writers: use a database (and log its changes with witness-log if they need to be provable).
- You need shared settlement between adversaries: that is a blockchain's job; anchor to it.
- You need the *content* to be publicly verifiable, not just its integrity: publish the payloads yourself; witness-log commits to them and lets you prove the match.
- You only need debugging: tracing alone is fine until someone outside asks for proof.

Next: [Architecture](Architecture) · [Threat model](Threat-Model) · [Why witness-log](Why-witness-log)
