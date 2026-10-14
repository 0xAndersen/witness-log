# witness-log and Signet

Part of [Comparison](Comparison). Checked against primary sources on
2026-10-12; links at the bottom.

## What Signet is

[Signet](https://github.com/Prismer-AI/signet) (Prismer AI, Apache-2.0 / MIT
dual licence) gives every agent an Ed25519 identity and signs every tool call
as a receipt: tool, parameters (or only their hash), target, signer,
timestamp and nonce, canonicalised with RFC 8785 (JCS). Receipts are appended
to a local SHA-256 hash-chained audit log. Later receipt versions add server
co-signing of the response (v3 "bilateral" receipts) and delegation chains
proving who authorised the agent (v4), plus signed policy attestations and
revocation records. It ships a Rust core, CLI, Python and TypeScript SDKs, an
MCP proxy, and plugins for Claude Code and Codex.

## What it is good at

- **Authorization evidence.** Delegation chains (permissions only narrow),
  authority-signed decisions bound to an `intent_hash`, revocation with
  explicit `revoked` / `unknown` status, and policy attestations carrying the
  policy hash and rule. witness-log deliberately has none of this; it logs
  *that* an authorization happened (an `AuthorizationEvent`) and leaves the
  authorization itself to systems like Signet.
- **The execution boundary.** An MCP server can verify a request before
  running it (signer, freshness, target binding, nonce replay protection)
  and reject it. witness-log records; it never gates a call.
- **A counterparty's signature per action.** v3 bilateral receipts have the
  MCP server co-sign the response and outcome. That is a second party
  attesting to each action as it happens.
- **Integration surface.** LangChain, LangGraph, CrewAI, AutoGen,
  LlamaIndex, Pydantic AI, Google ADK, smolagents, OpenAI Agents SDK, Vercel
  AI SDK, an MCP proxy needing no code changes, a local dashboard, and
  portable evidence bundles (`signet audit --bundle` / `--restore`).
- **Clear documentation of its own limits** (see below).

## Where it differs, by property

Signet's own threat model is direct about the boundary. Under "Tamper
detection" it lists "Modify and re-sign — Requires the private key", and
under limitations: "Audit log is local. An attacker with filesystem access
can delete the entire log"; "No remote attestation server (planned for
v2)"; truncating the tail is "Detectable if expected record count is known".

So a party holding the agent's key (in practice, the operator) can produce a
fresh, correctly signed, correctly chained history, and nothing in a Signet
bundle distinguishes it from the original. An independent evaluation of
witness-log 0.3.3 that ran Signet on the same tasks reported exactly this:
the rewritten log was accepted as valid (`CHANGELOG.md`, 0.3.4).

| property | Signet | witness-log |
|---|---|---|
| per-action signature | yes, every receipt (Ed25519, JCS) | no; leaves are unsigned records under an identity-signed checkpoint over the whole tree |
| ordering / deletion evidence | SHA-256 hash chain, local | RFC 6962 Merkle tree; inclusion and consistency proofs |
| key holder rewrites history | not detectable from the log (stated in its threat model) | witnesses refuse a contradicting head (422) and write a proof anyone can check |
| third parties | the MCP server, per action (bilateral receipts) | witnesses from ≥2 organisations the verifier chooses, per checkpoint |
| tail truncation | detectable if the expected count is known | detectable against any witnessed checkpoint |
| erasure | `--hash-only` stores only a parameter hash; `--encrypt-params` encrypts params in the log; deleting a record breaks the chain | salted commitments; `forget(i)` deletes the salt, every proof stays valid |
| authorization / policy | delegation chains, decisions, revocation, policy attestation | logged as `AuthorizationEvent` leaves; not evaluated |
| verdict | `verify` / `verify --chain` / `audit --verify` / `--restore` | five verdicts; exit code is the verdict |

The bilateral receipt is worth dwelling on, because it is the closest
Signet comes to witnessing: the server's signature proves the server saw
that call. It attests to individual calls, not to the history as a whole:
nothing in the scheme remembers a head, compares two copies of the log, or
refuses a fork. It also requires the server to run Signet.

## When to choose Signet instead

- You need **authorization evidence**: who allowed this agent, under which
  scope and policy, and whether that grant was revoked.
- You need the MCP server to **reject** unsigned, stale, replayed or
  mis-targeted calls.
- The operator is trusted, and the audience is internal or the operator's
  customers who accept the operator's key.

They compose. Signet's receipt for a call is a fine `ActiveIntent` or
`ActiveResult` payload, and a v4 receipt's authorization chain is a fine
`AuthorizationEvent` scope. witness-log then adds the property Signet's
threat model leaves open: a key holder cannot rewrite history that
independent witnesses have cosigned.

## If this is wrong

If anything here misstates Signet (it ships often), open a PR against
`docs/wiki/Comparison-Signet.md` with a link to the source.

## Sources (checked 2026-10-12)

- Signet README: <https://github.com/Prismer-AI/signet> (receipt format, receipt versions, CLI, integrations, licence)
- Signet security and threat model: <https://github.com/Prismer-AI/signet/blob/main/docs/SECURITY.md> ("Audit Log Integrity", "Limitations", "Threat Model")
- Signet audit log guide: <https://github.com/Prismer-AI/signet/blob/main/docs/guides/audit-log.md>
