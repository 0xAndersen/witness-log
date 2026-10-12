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

## Versus SCITT and the agent-record draft

SCITT ([RFC 9943](https://www.rfc-editor.org/rfc/rfc9943.html), Standards
Track, June 2026) occupies the same *transparency* layer. The structural
difference: SCITT separates the Issuer from a Transparency Service and asks
the service for non-equivocation, while witness-log makes each agent the
operator of its own log and gets non-equivocation from independent
witnesses. Both leave attestation, identity and authorization to their own
layers (RATS, WIMSE, OAuth), the decomposition used by
`draft-kuehlewind-audit-architecture`. [SCITT mapping](SCITT-Mapping) maps
every concept and proposes a path to SCITT-compatible receipts.

`draft-maintainer-1f916-agent-record` (individual draft, -01) shares
witness-log's model, including the four verdict names, but is **not
wire-compatible**: different checkpoint and countersignature encodings, no
C2SP, registries instead of per-agent logs, refusals counted as evidence.
The full divergence list is on the [SCITT mapping](SCITT-Mapping#divergence-list-draft-maintainer-1f916-agent-record)
page. The conformance corpus exists so that an independent implementation
can prove it computes the same bytes.

## Named projects, by the same properties

An independent three-persona evaluation of 0.3.3 built witness-log, attacked
it, and ran alternatives on the same tasks. The one test that separated
them: the operator rewrote the whole history with its own key. The
evaluation reported that Signet, agent-receipts and Microsoft's AGT accepted
the rewritten log as valid, and that witness-log's witnesses refused it
(422) and produced a proof of equivocation. In each case that is the
behaviour the other project's own documentation describes for its
configuration, not a bug in it; the per-project pages quote the relevant
text. [`examples/rewrite-attack/`](https://github.com/0xAndersen/witness-log/tree/main/examples/rewrite-attack)
reproduces the witness-log side in one command. The honest summary of the
rest is that the *primitives* are commodity and the *package* is not.

Each project has its own page, written to be fair to it: what it is good
at, where it differs by property, and when to choose it instead.

| project | what it is | tamper evidence against the operator | erasure | intent/result | third parties | licence |
|---|---|---|---|---|---|---|
| [**Tessera**](Comparison-Tessera) (transparency-dev; Rekor v2's storage layer) | a Go library for running C2SP tiled transparency logs | yes, as a public log with witnesses | not a feature; entries are public | no; generic entries | `c2sp.org/tlog-witness` cosigners, per a `tlog-policy` | Apache-2.0 |
| [**Microsoft Agent Governance Toolkit**](Comparison-Microsoft-AGT) | policy enforcement, identity, sandboxing and audit for agents | no: unkeyed hash chain + Merkle tree; no signatures; external anchoring specified but not shipped | not documented | policy decision records | none in the audit path | MIT |
| [**Signet**](Comparison-Signet) | Ed25519-signed receipt per tool call, local hash chain, delegation and policy proofs | no: the key holder can re-sign (its threat model says so) | hash-only or encrypted params; deleting a record breaks the chain | signed before the call; v3 adds a server-cosigned outcome | MCP server co-signs each action (v3) | Apache-2.0 / MIT |
| [**immudb**](Comparison-immudb) | a database with cryptographic proofs | yes, for clients and auditors that kept state | time-based truncation of values, database-wide | no | clients and auditors you run | BSL 1.1 (Apache-2.0 after four years) |
| [**Agent Receipts / obsigna**](Comparison-agent-receipts) | Ed25519 W3C-VC receipt per action, hash chain, signing daemon | conditional: checkpoints anchored to a sink the operator does not control (reference sinks today) | parameters stored only as an unsalted hash | action + outcome per receipt | anchor sinks (file, git, syslog) | Apache-2.0 (code), MIT (spec) |
| **AP2 / Mastercard Verifiable Intent / x402** | signed authorization or payment terms for an action | proves authorization, not the record of what was done | n/a | mandate, not execution | n/a | AP2: Apache-2.0 |
| [**SCITT (RFC 9943)**](Comparison-SCITT) | standards-track architecture: Issuers, Transparency Service, Receipts | required of the service; Auditors detect equivocation | not specified (hash-only statements allowed) | no agent profile in the RFC | Transparency Service; no witness role | IETF standard |
| **witness-log** | per-agent Merkle log + independent witnessing + erasure + offline verdicts | yes: a rewrite is refused (422) and recorded as evidence | yes, proofs intact | two leaves per action, plus handoff and authorization leaves | witnesses from ≥2 organisations the verifier chooses | Apache-2.0 |

Two things to take from the table. Of these, witness-log is the one combining
third-party witnessing of an agent's whole history with an agent schema and
proof-preserving erasure, and that combination is what catches the rewrite.
And none of it is exotic: a team already on Tessera could add the agent
schema and salted erasure, and Agent Receipts' roadmap includes
transparency-log anchoring, which is why this project publishes a
conformance corpus and speaks the existing witness protocol. The goal is the
standard shape of an agent audit trail, not a moat. Where a Tessera-based
deployment makes sense (a public, append-only log of non-personal data), use
it; witness-log's design is for the private, per-agent, erasable case.

A real limit, stated here too: the public registry of independent witness
operators is currently empty. Until outside organisations run witnesses,
WITNESSED means "witnesses you chose", which may mean witnesses you run
yourself ([Threat model](Threat-Model)).

## When not to use witness-log

- You need queryable, mutable state shared between many writers: use a database (and log its changes with witness-log if they need to be provable).
- You need shared settlement between adversaries: that is a blockchain's job; anchor to it.
- You need the *content* to be publicly verifiable, not just its integrity: publish the payloads yourself; witness-log commits to them and lets you prove the match.
- You only need debugging: tracing alone is fine until someone outside asks for proof.

Next: [Architecture](Architecture) · [Threat model](Threat-Model) · [Why witness-log](Why-witness-log)
