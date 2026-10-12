# MCP integration: an audit trail for any MCP host, zero code

The `witness-log` Python package ships an MCP server (`witness-log-mcp`,
module `witness_log.mcp_server`) that exposes the whole system as eleven
tools over the Model Context Protocol. Any host that speaks MCP (Claude
Code, Claude Desktop, Cursor, Windsurf, Zed, VS Code Copilot agent mode,
OpenAI Agents SDK via MCP, custom hosts) can give its agent a witnessable
trail by adding one server entry. Python ≥ 3.10 (the MCP SDK's
requirement). Before 0.3.6 the server was a file in the repository
(`integrations/mcp/witness_mcp_server.py`); that path still works as a
launcher.

| tool | does |
|---|---|
| `initialize_witness_chain(session_id, metadata?)` | create, or resume on boot, a log bound to an Ed25519 identity (idempotent) |
| `append_audit_step(session_id, intent, tool_name, payload?, state_transition?)` | intent leaf (+ result leaf); returns a signed checkpoint and an inclusion proof |
| `record_result(session_id, intent_index, tool_name, outcome="ok", value?)` | result leaf for an intent recorded earlier: intent before acting, result after (0.3.6+) |
| `get_inclusion_proof(session_id, entry_index)` | proof a step is in the tree |
| `verify_chain_integrity(session_id, trusted_directory?, min_witnesses?)` | the full verifier; tamper alerts; includes the last cosignatures while the head is unchanged |
| `redact_audit_entry(session_id, entry_index)` | GDPR erasure of one payload |
| `export_dossier(session_id)` | the portable proof (with cosignatures when the head is the witnessed one; `witnessed_dossier` otherwise); also written to `<session>/dossier.json`, returned as `path`, `sha256`, `bytes` |
| `record_handoff(session_id, direction, counterparty_identity_pubkey, state)` | one side of an agent-to-agent handoff |
| `record_authorization(session_id, kind, counterparty_identity_pubkey, scope)` | one side of a delegation or scope change; `kind` is an enum of the six SPEC §3.2 kinds, `scope` a JSON object (committed as RFC 8785 canonical JSON) or a string (its UTF-8 bytes) |
| `submit_to_witnesses(session_id, directory?, max_witnesses=8, min_witnesses=2)` | get the head cosigned by diversity-selected witnesses |
| `audit_this_session(session_id)` | `{leaf_count, root, identity, witnessed, last_verdict, witnessed_size, journal}`: where the trail stands, with no side effects (0.3.7+) |

Already running an MCP server you want audited rather than giving the
model audit tools? [MCP proxy](MCP-Proxy): `witness-log-mcp-proxy --name
git --journal git.wlog -- mcp-server-git` records every `tools/call`
without any change to the server or the model's instructions.

Tool errors carry the reason (for example `session_id must be 1-128
characters ...` or `counterparty must be the other agent's identity public
key as 64 hex characters`), so the model can fix its call.

## Claude Code

`.mcp.json` in the project (or `~/.claude.json` for all projects):

```json
{"mcpServers": {"witness-log": {
  "command": "uvx",
  "args": ["--from", "witness-log[mcp]", "witness-log-mcp"],
  "env": {"WITNESS_LOG_HOME": "/var/lib/witness-log"}}}}
```

With `pip install "witness-log[mcp]"` already done, `"command":
"witness-log-mcp"` and no args is enough.

Then in `CLAUDE.md`:

```
At the start of every session call initialize_witness_chain with session_id "<project>-<date>".
Before any tool that changes files, money, or external state, call append_audit_step with the intent;
after it, call record_result with the returned intent_index. At the end of the session call submit_to_witnesses
and report the verdict.
```

A hook does it without relying on the model: `witness-log-hook install
claude-code` prints the `.claude/settings.json` `PreToolUse`/`PostToolUse`
entries that record every tool call through a daemon holding the journal
(see [Hooks](Hooks)).

## Claude Desktop

`claude_desktop_config.json` → same `mcpServers` block. The log lives under
`WITNESS_LOG_HOME` on your machine; `export_dossier` gives you the file to
share.

## Cursor / Windsurf / Zed / VS Code

Each has an MCP servers setting with the same shape (`command`, `args`,
`env`). Point `WITNESS_LOG_HOME` at a directory that persists.

## OpenAI Agents SDK (Python) as an MCP client

```python
from agents import Agent, Runner
from agents.mcp import MCPServerStdio

async with MCPServerStdio(params={"command": "witness-log-mcp", "args": []}) as wl:
    agent = Agent(name="ops", instructions="Record every action with append_audit_step.", mcp_servers=[wl])
    await Runner.run(agent, "Reconcile today's invoices")
```

## TypeScript

`@witness-log/client` (`clients/typescript`) starts the server over stdio
with the official MCP SDK and wraps it:

```ts
import { WitnessLogMCP } from "@witness-log/client";
const wl = await WitnessLogMCP.start({ sessionId: "agent-1" });
const out = await wl.step("transfer", async () => ({ ok: true }), { args: { amount: 5 } });
const report = await wl.verify();
await wl.close();
```

## Inspector

```sh
uv run --with "mcp[cli]>=2" --with "witness-log[mcp]" \
  mcp dev "$(python -c 'import witness_log.mcp_server as m; print(m.__file__)')"
```

## What the host sees

`append_audit_step` returns `{intent_index, result_index, checkpoint, inclusion_proof}`.
The checkpoint is signed by the log's identity key; the proof verifies
with `witness_log.verify_inclusion(...)` or any RFC 6962 verifier.
`verify_chain_integrity` returns `tamper_alerts: []` when the chain is intact.
After a successful `submit_to_witnesses`, `verify_chain_integrity` with the
same `trusted_directory` reports `witnessed` until the next append, and
`witnessed_size` / `witnessed_verdict` afterwards.

State: `$WITNESS_LOG_HOME/<session_id>/journal.jsonl` (+ `.salts`), one
identity per session id, resumed across host restarts, plus
`dossier.json` (the last `export_dossier`),
`journal.jsonl.witnesses.json` (the CLI's witness state file, so
`witness-log witness submit $WITNESS_LOG_HOME/<id>/journal.jsonl ...` can
take over) and `journal.jsonl.witnessed.json` (the latest witnessed
dossier). Session ids are restricted to `[A-Za-z0-9][A-Za-z0-9._-]{0,127}`
and never touch paths outside the home. Witness URLs must be http(s).

Identity: by default each session id gets its own identity, stored in its
journal header (`0600`). Set `WITNESS_LOG_IDENTITY_SEED_ENV` in the
server's `env` to the name of a variable holding a 32-byte hex seed and
every session is sealed to that one identity, with the seed never in a
journal file:

```json
{"mcpServers": {"witness-log": {
  "command": "witness-log-mcp",
  "env": {"WITNESS_LOG_HOME": "/var/lib/witness-log",
          "WITNESS_LOG_IDENTITY_SEED_ENV": "AGENT_KEY"}}}}
```

with `AGENT_KEY` set in the environment the host launches the server
from. Each journal is opened once per server process and kept open; a
tool call is an append and an fsync, not a resume.
