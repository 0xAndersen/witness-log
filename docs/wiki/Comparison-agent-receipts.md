# witness-log and Agent Receipts (obsigna)

Part of [Comparison](Comparison). Checked against primary sources on
2026-10-12; links at the bottom.

## What Agent Receipts is

[Agent Receipts](https://github.com/agent-receipts/ar) is an open protocol
(spec Draft v0.5.0, MIT) for "cryptographically signed, tamper-evident
records of AI agent actions", with **obsigna** as its reference toolset
(Apache-2.0): Go, TypeScript and Python SDKs, an out-of-process signing
daemon that owns the key and the receipt database, an MCP proxy with policy
hooks, and a PostToolUse hook for Claude Code. Each receipt is a W3C
Verifiable Credential signed with Ed25519, recording one action (classified
by a standard taxonomy with risk levels), its principal, issuer and outcome,
hash-chained to the previous receipt.

## What it is good at

- **A real protocol with conformance.** Three independent SDKs verify one
  another's receipts against shared positive and MUST-reject corpora, and
  the chain's tamper-evidence property is model-checked in Alloy (bounded,
  relative to the cryptographic assumptions, with the key-holder case named
  as out of scope).
- **Key custody by design.** The daemon architecture keeps the signing key
  out of the agent process, so a compromised agent cannot forge receipts.
  witness-log's default keeps the seed in the journal header (sealed
  journals move it to your KMS), and has no separate signing daemon.
- **Action taxonomy and outcomes.** Standardised action types with default
  risk levels, outcome status, reversibility and undo method in every
  receipt. witness-log's leaves are typed (intent, result, …) but the
  payload is yours.
- **Trusted time.** Receipts may carry an RFC 3161 timestamp token over the
  same canonical bytes that were signed. witness-log's leaf and checkpoint
  times are self-asserted; corroborated time comes only from witness
  cosignatures or an `ExternalAnchor`.
- **An honest threat model,** including the condition below.
- **External checkpoint anchoring, shipped.** The daemon emits signed
  `{chain_id, sequence, receipt_hash, timestamp}` checkpoints to
  operator-configured sinks (`file:`, `git:`, `syslog:`), and
  `obsigna verify --against-anchor` detects truncation and rewriting
  relative to the anchored head.

## Where it differs, by property

The project's threat model states the boundary precisely: the chain's
history survives key compromise "if and only if rotation events and periodic
checkpoints are anchored to a sink the daemon does not control", and
"Without an external anchor, daemon compromise is total — chain history can
be rewritten freely." The shipped sinks are dependency-free reference
adapters ("a plain file is only as append-only as the filesystem around
it"); production-grade sinks (S3 object-lock, transparency log, SIEM) are
listed as not yet shipped.

An independent evaluation of witness-log 0.3.3 that ran agent-receipts on
the same tasks reported that a whole-history rewrite under the operator's
key was accepted as valid (`CHANGELOG.md`, 0.3.4). That matches the threat
model's statement for a deployment without a qualifying external anchor; we
do not know which anchoring configuration, if any, the evaluation used.

| property | Agent Receipts | witness-log |
|---|---|---|
| per-action signature | yes (Ed25519 VC per receipt) | no; an identity-signed checkpoint over the whole tree |
| structure | hash chain; tail truncation needs an external `ExpectedLength` / `ExpectedFinalHash` | RFC 6962 Merkle tree; inclusion and consistency proofs |
| defence against the key holder | checkpoint anchoring to a sink the daemon does not control (reference sinks today) | cosignatures from witnesses run by ≥2 organisations the verifier chooses; a fork is refused with 422 and proven in a file |
| who the outside party is | an append-only store the operator configures | an independent operator that verifies a consistency proof before signing |
| privacy of parameters | `parameters_hash`: unsalted SHA-256 of JCS parameters; plaintext never stored | salted, bucket-padded `payload_hash`; a low-entropy payload cannot be dictionary-attacked |
| erasure | content is not stored; an unsalted hash of a guessable value remains guessable | `forget(i)` deletes the salt; content unrecoverable; proofs intact |
| time | optional RFC 3161 token per receipt | self-asserted; corroborated by witness cosignature time or `ExternalAnchor` |
| key isolation | signing daemon as its own OS user | in-process library; sealed journals keep the seed in a KMS |
| format | W3C VC, JSON, JCS | binary canonical leaves, C2SP checkpoints, JSON dossier |

The anchor and the witness solve the same problem from different ends. An
anchor sink records the head; a witness *checks* that each new head extends
the last one before signing it, remembers it durably, and turns a
contradiction into portable evidence. A transparency-log sink (on the
agent-receipts roadmap) would close most of the distance; one that spoke
`c2sp.org/tlog-witness` could use the same witnesses witness-log does.

## When to choose Agent Receipts instead

- You want **W3C Verifiable Credentials** per action, a standard action
  taxonomy, or RFC 3161 time on every record.
- You need the signing key **isolated from the agent** today.
- Your verifiers will check receipts one at a time rather than a whole
  history.

They compose: a signed receipt is a fine leaf payload, and a receipt
chain's checkpoint is a natural `ExternalAnchor` or `ActiveResult` in a
witnessed log.

## If this is wrong

If anything here misstates Agent Receipts or obsigna, open a PR against
`docs/wiki/Comparison-agent-receipts.md` with a link to the source.

## Sources (checked 2026-10-12)

- Repository README (protocol, obsigna tools, conformance, formal verification, licences): <https://github.com/agent-receipts/ar> (badges point to `agent-receipts/obsigna`)
- Threat model: <https://github.com/agent-receipts/obsigna/blob/main/docs/threat-model.md> ("What we explicitly claim", "Tail truncation", "Current implementation status")
- Protocol README and spec Draft v0.5.0: <https://github.com/agent-receipts/obsigna/blob/main/spec/README.md>, <https://github.com/agent-receipts/obsigna/blob/main/spec/v0.5.0/spec.md> (`parameters_hash`, `trusted_timestamp`, §7.3.1)
- PyPI `agent-receipts` 0.12.0 metadata (points to the repository above): <https://pypi.org/project/agent-receipts/>
