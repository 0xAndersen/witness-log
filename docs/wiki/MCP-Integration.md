# MCP integration: an audit trail for any MCP host, zero code

`integrations/mcp/witness_mcp_server.py` exposes the whole system as seven
tools over the Model Context Protocol. Any host that speaks MCP (Claude
Code, Claude Desktop, Cursor, Windsurf, Zed, VS Code Copilot agent mode,
OpenAI Agents SDK via MCP, custom hosts) can give its agent a signed,
witnessable trail by adding one server entry. Python ≥ 3.10 (the MCP SDK's
requirement).

| tool | does |
|---|---|
| `initialize_witness_chain(session_id, metadata?)` | create, or resume on boot, a log bound to an Ed25519 identity (idempotent) |
| `append_audit_step(session_id, intent, tool_name, payload?, state_transition?)` | intent leaf (+ result leaf); returns a signed checkpoint and an inclusion proof |
| `get_inclusion_proof(session_id, entry_index)` | proof a step is in the tree |
| `verify_chain_integrity(session_id, trusted_directory?, min_witnesses?)` | the full verifier; tamper alerts |
| `redact_audit_entry(session_id, entry_index)` | GDPR erasure of one payload |
| `export_dossier(session_id)` | the portable proof |
| `submit_to_witnesses(session_id, directory?, max_witnesses=8, min_witnesses=2)` | get the head cosigned by diversity-selected witnesses |

## Claude Code

`.mcp.json` in the project (or `~/.claude.json` for all projects):

```json
{"mcpServers": {"witness-log": {
  "command": "uv",
  "args": ["run", "--with", "mcp>=2", "--with", "witness-log",
           "/absolute/path/to/witness-log/integrations/mcp/witness_mcp_server.py"],
  "env": {"WITNESS_LOG_HOME": "/var/lib/witness-log"}}}}
```

Then in `CLAUDE.md`:

```
At the start of every session call initialize_witness_chain with session_id "<project>-<date>".
Before any tool that changes files, money, or external state, call append_audit_step with the intent;
after it, call append_audit_step with the result. At the end of the session call submit_to_witnesses
and report the verdict.
```

A hook does it without relying on the model: `.claude/settings.json`
`PreToolUse`/`PostToolUse` hooks can call `witness-log` or a small Python
script on every tool call (see [Framework guides](Framework-Guides) → Claude Code hook).

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

async with MCPServerStdio(params={"command": "uv", "args": ["run", "--with", "mcp>=2", "--with", "witness-log",
                                  "/path/witness_mcp_server.py"]}) as wl:
    agent = Agent(name="ops", instructions="Record every action with append_audit_step.", mcp_servers=[wl])
    await Runner.run(agent, "Reconcile today's invoices")
```

## Inspector

```sh
uv run --with "mcp[cli]>=2" --with witness-log mcp dev integrations/mcp/witness_mcp_server.py
```

## What the host sees

`append_audit_step` returns `{intent_index, result_index, checkpoint, inclusion_proof}`.
The checkpoint is signed by the session's identity key; the proof verifies
with `witness_log.verify_inclusion(...)` or any RFC 6962 verifier.
`verify_chain_integrity` returns `tamper_alerts: []` when the chain is intact.

State: `$WITNESS_LOG_HOME/<session_id>.jsonl` (+ `.salts`), one identity per
session id, resumed across host restarts. Session ids are restricted to
`[A-Za-z0-9][A-Za-z0-9._-]{0,127}` and never touch paths outside the home.
