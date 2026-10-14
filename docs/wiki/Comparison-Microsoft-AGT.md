# witness-log and Microsoft Agent Governance Toolkit

Part of [Comparison](Comparison). Checked against primary sources on
2026-10-12; links at the bottom.

## What AGT is

The [Agent Governance Toolkit](https://github.com/microsoft/agent-governance-toolkit)
(AGT) is Microsoft's MIT-licensed toolkit for "policy enforcement, identity,
sandboxing, and SRE for autonomous AI agents", in public preview. Every tool
call, message and delegation is intercepted in application code before it
reaches the wire and evaluated by a policy engine (YAML, OPA or Cedar); the
decision is written to an audit log. It ships SDKs for Python, TypeScript,
.NET, Rust and Go, and first-party integrations for Copilot CLI, Claude Code,
Codex CLI and OpenCode, plus sandboxing (privilege rings), an MCP security
gateway, SRE tooling and compliance mappings.

## What it is good at

- **Prevention, not just evidence.** AGT's core job is to stop an action
  before it happens: a denied call raises `GovernanceDenied`. witness-log
  never blocks anything; it only records. If you need enforcement, AGT (or
  something like it) is the layer you want.
- **Breadth.** Policy, identity (SPIFFE/DID/mTLS), sandboxing, kill
  switches, SLOs, prompt-injection auditing and framework adapters in one
  install, across five languages.
- **Decision records.** Audit entries record what policy was active, what
  was requested and why it was allowed or denied, with compliance mappings
  (SOC 2, EU AI Act, GDPR article tags) built in.
- **A written audit spec.** `docs/specs/AUDIT-COMPLIANCE-1.0.md` states the
  entry schema, hash computation, Merkle construction and threat model
  precisely, including what is not yet covered.

## Where it differs, by property

AGT's audit integrity, per its own specification and changelog:

- Each entry carries `previous_hash`, and `entry_hash` is SHA-256 over a
  sorted-key JSON of nine fields (§4.4); a Merkle tree over entry hashes
  gives inclusion proofs (§9.3–§9.6).
- The spec defines no signature over entries or roots. The changelog is
  explicit about what this means: "The chain is unkeyed, so this raises the
  cost of editing a log rather than preventing it: someone who can rewrite
  the file can also rewrap it with a matching seam."
- Five optional fields (`arguments_hash`, `approver_did`, `policy_version`,
  `issued_at`, `completed_at`) are outside the hash in spec v1.0, and the
  spec says verifiers "MUST NOT rely on these fields for tamper detection".
- External anchoring is specified as optional (§14.4) but "The current AGT
  implementation (Public Preview) does NOT perform external anchoring", and
  the Commitment Engine that would have done it "has been removed from the
  implementation".

| property | AGT audit log | witness-log |
|---|---|---|
| tamper evidence | unkeyed hash chain + Merkle tree; detects edits by someone who does not recompute the chain | identity-signed checkpoints; edits break the signature or the root |
| against the operator rewriting history | not addressed in the shipped implementation (no signature, no anchoring) | witnesses refuse a contradicting head (422) and keep a proof |
| third parties | none in the audit path | witnesses from ≥2 organisations the verifier chooses |
| offline verdict | `verify_chain()` → valid / invalid | five verdicts; exit code is the verdict |
| Merkle construction | `SHA-256(left ‖ right)` (no leaf/node domain separation stated) | RFC 6962 with `0x00`/`0x01` domain separation |
| erasure | not documented in the audit spec | salted commitments; `forget(i)` keeps every proof |
| enforcement | yes, the core feature | none, by design |

An independent evaluation of witness-log 0.3.3 that ran AGT on the same
tasks reported that, when the operator rewrote the whole history, AGT
accepted the rewritten log as valid (see `CHANGELOG.md`, 0.3.4). That is the
behaviour AGT's own spec and changelog describe for an unkeyed chain without
anchoring; it is not a bug report against AGT.

## When to choose AGT instead

- You need to **block** actions by policy, sandbox agents, or run a kill
  switch. witness-log does none of this.
- Your audit question is internal ("what did our agents do, and which
  policy allowed it?") and the operator is trusted.
- You want one vendor-backed toolkit covering governance end to end.

They compose: AGT decides and enforces; witness-log records the intent, the
decision and the result as leaves and gets the head witnessed, so the
record of what AGT allowed survives the operator. AGT's decision record is a
natural `ActiveIntent` payload (its hash, not its content, enters the tree).

## If this is wrong

AGT moves quickly. If anything here is out of date (for example, signed
entries or external anchoring landing), open a PR against
`docs/wiki/Comparison-Microsoft-AGT.md` with a link to the source.

## Sources (checked 2026-10-12)

- AGT README: <https://github.com/microsoft/agent-governance-toolkit> (scope, packages, MIT, public preview)
- AGT Audit and Compliance Specification 1.0-DRAFT: <https://github.com/microsoft/agent-governance-toolkit/blob/main/docs/specs/AUDIT-COMPLIANCE-1.0.md> (§4.3.1, §4.4, §9, §14, §21.2.1)
- AGT CHANGELOG, Unreleased → Fixed, OpenCode audit-log rollover: <https://github.com/microsoft/agent-governance-toolkit/blob/main/CHANGELOG.md>
