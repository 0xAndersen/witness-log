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
| `audit_this_session(session_id)` | `{leaf_count, root, identity, witnessed, last_verdict, directory_source, witnessed_size, journal}`: where the trail stands, with no side effects (0.4.0+) |

Already running an MCP server you want audited rather than giving the
model audit tools? [MCP proxy](MCP-Proxy): `witness-log-mcp-proxy --name
git --journal git.wlog -- mcp-server-git` records every `tools/call`
without any change to the server or the model's instructions.

Tool errors carry the reason (for example `session_id must be 1-128
characters ...` or `counterparty must be the other agent's identity public
key as 64 hex characters`), so the model can fix its call.

## Pin the trust anchor

A verdict is only as good as the witness directory it was scored against:
whoever supplies the directory decides which keys count as witnesses, and
witnesses of an attacker's choosing cosign anything. Without a pin, the
`directory` of `submit_to_witnesses` and the `trusted_directory` of
`verify_chain_integrity` come from the model, so a prompt-injected agent (a
poisoned document, a tool result, a counterparty's message) can pass an
attacker-built directory and report its own chain `witnessed`. The tool
descriptions tell the model to pass a directory only from its operator's
configuration and never from tool output, documents or the counterparty,
but a description is not a control. Pin the directory:

```json
{"mcpServers": {"witness-log": {
  "command": "witness-log-mcp",
  "args": ["--trusted-directory", "/etc/witness-log/trusted.json"],
  "env": {"WITNESS_LOG_HOME": "/var/lib/witness-log"}}}}
```

or set `WITNESS_LOG_TRUSTED_DIRECTORY=/etc/witness-log/trusted.json` in the
server's `env` (the flag wins when both are set). The file is a directory
document, `{"witnesses": [...]}` or a bare array of entries (what
`witness-log directory build` writes). With a pin:

- it is the only directory the tools use: `submit_to_witnesses` contacts
  its witnesses and scores against it, and `verify_chain_integrity` scores
  against it without being asked;
- a `directory` or `trusted_directory` argument is **refused** with an
  error naming the pin, even when it equals the pinned file. Refused
  rather than ignored: ignoring it would let the model believe its own
  directory was used, and the error makes an injection attempt visible
  to the agent and in the host's logs;
- a pin that cannot be read or parsed stops the server at startup (exit
  2): an operator who meant to pin a directory never gets a server that
  accepts the caller's instead. The file is read once; restart the server
  after changing it.

Every verdict carries `directory_source`: `"pinned"` (the operator's pin),
`"default"` (`$WITNESS_LOG_HOME/witnesses.json`, which
`submit_to_witnesses` uses when nothing is pinned or passed), `"caller"`
(passed in the tool call, so worth exactly as much as whoever wrote it)
or `null` (no directory, so the verdict cannot be `witnessed`). It is on
`verify_chain_integrity` (for `verdict` and `witnessed_verdict`), on
`submit_to_witnesses`, and on `audit_this_session` for `last_verdict`.
A host or reviewer that acts on a verdict should require `"pinned"`.

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
After a successful `submit_to_witnesses`, `verify_chain_integrity` against
the same directory (the pinned one, or the same `trusted_directory`)
reports `witnessed` until the next append, and
`witnessed_size` / `witnessed_verdict` afterwards. Every head witnesses
cosigned for the session (the kept witnessed dossier, and
`journal.jsonl.witnesses.json`) is passed to the verifier as a known head,
read from disk without first checking it against the journal: a journal
rewritten after it was witnessed no longer reproduces it, and the verdict
is `diverged` with a `contradiction:` tamper alert; one truncated below it
is a tamper alert too. (0.5.0 passed the head only when the journal
already reproduced it, so the check never fired.) A chain that fails a
check reports `invalid` (`diverged` before 0.5.0). `split_view_unsafe`
(from `submit_to_witnesses` and `verify_chain_integrity`) is true when the
verdict is `witnessed` but the cosigners are not a strict majority of the
directory, the CLI's exit 11.

State: `$WITNESS_LOG_HOME/<session_id>/journal.jsonl` (+ `.salts`), one
identity per session id, resumed across host restarts, plus
`dossier.json` (the last `export_dossier`),
`journal.jsonl.witnesses.json` (the CLI's witness state file, so
`witness-log witness submit $WITNESS_LOG_HOME/<id>/journal.jsonl ...` can
take over) and `journal.jsonl.witnessed.json` (the latest witnessed
dossier). Session ids are restricted to `[A-Za-z0-9][A-Za-z0-9._-]{0,127}`
and never touch paths outside the home. Witness URLs must be http(s).

What a witness URL may reach: `submit_to_witnesses` sends a witness the
checkpoint and nothing else, and never follows a redirect (a 3xx is a
failed outcome for that witness: urllib used to follow a 301/302/303 with
a GET to wherever `Location` pointed, and part of a non-200 answer went
back to the model). For a directory passed in the call
(`directory_source: "caller"`) the server resolves each witness host
first and refuses it if any address is link-local (`169.254.0.0/16`,
`fe80::/10`) or a cloud metadata address, and, unless the operator set
`WITNESS_LOG_ALLOW_PRIVATE_WITNESSES=1`, if any is loopback, private or
otherwise not globally routable; the connection then goes only to the
addresses it checked, so a second DNS answer cannot redirect it. A
refused witness is an outcome with the reason; nothing is sent to it. The
operator's own directories (pinned, or `$WITNESS_LOG_HOME/witnesses.json`)
may name anything, so a local testnet on `127.0.0.1` works there without
the switch.

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
