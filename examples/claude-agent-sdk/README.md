# A Claude Agent SDK agent, on the record

A real agent built on the [Claude Agent SDK](https://pypi.org/project/claude-agent-sdk/)
answers one question with two tools. Every tool call it makes lands on a
witness-log journal as an intent leaf before the call and a result leaf
after it, through the SDK's own hooks. Then the dossier is exported,
verified offline, and one leaf is disclosed to show what it committed to.

```sh
pip install witness-log claude-agent-sdk     # or: pip install "witness-log[claude-agent-sdk]"
export ANTHROPIC_API_KEY=...
python3 examples/claude-agent-sdk/run.py     # --out DIR keeps the files there; --model picks the model
```

It makes one short agent run on your API key (the SDK starts the Claude
Code CLI bundled in its wheel; nothing else to install). The two tools are
an in-process SDK MCP server over a hard-coded ledger, built-in tools are
off (`tools=[]`) and filesystem settings are ignored (`setting_sources=[]`),
so the agent cannot touch anything outside the script. Without
`ANTHROPIC_API_KEY` it exits before doing anything.

## The wiring

```python
import witness_log
from claude_agent_sdk import query
from witness_log.integrations.claude_agent_sdk import WitnessLogClaudeHooks

log = witness_log.open("agent.jsonl")
audit = WitnessLogClaudeHooks(log)
options = audit.options(mcp_servers={"ledger": server}, allowed_tools=[...])   # ClaudeAgentOptions + the hooks
async for message in query(prompt="...", options=options):
    ...
```

`audit.options(...)` is `ClaudeAgentOptions(...)` with a `PreToolUse`, a
`PostToolUse` and a `PostToolUseFailure` hook added (an existing `hooks=`
is kept). `witness_hooks(log)` returns just the `hooks=` value.

## What it prints

1. The agent's answer.
2. The leaves: one intent per call (`PreToolUse`, the tool name and its
   input) and one result per call (`PostToolUse` or `PostToolUseFailure`)
   pointing back at its intent with `intent_index`. Payloads are the
   Claude Code hook's `hook.claude-code v1` profile, the same bytes
   `witness-log-hook` writes for the same event (results add
   `intent_index`), so this dossier reads like one recorded from Claude
   Code itself.
3. The dossier at `<out>/agent.dossier.json`, verified with
   `witness_log.verify_dossier_json` pinned to the agent's identity:
   **UNANCHORED**, internally consistent (no witness has cosigned it yet),
   and the equivalent `witness-log verify` command.
4. Leaf 0 disclosed: its payload and salt recompute the leaf's
   `payload_hash` in the dossier.

The script exits 0 only if at least one tool call was recorded, every
intent has its result, nothing failed to append, the dossier verifies and
the disclosure checks out.

Next: get it witnessed (`witness-log witness submit <out>/agent.jsonl
--directory trusted.json --out dossier.json`, see
[Getting witnessed](../../docs/wiki/Getting-Witnessed.md)), or read how
the adapter behaves in detail in the
[Framework guides](../../docs/wiki/Framework-Guides.md#claude-agent-sdk).
