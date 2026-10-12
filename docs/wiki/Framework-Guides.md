# Framework guides

Every framework below exposes a hook that fires before and after a tool
call. The pattern is always the same: *intent leaf before, result leaf
after, on one journal per agent identity*. `witness_log.step` does exactly
this for a plain function. For LangChain/LangGraph, the OpenAI Agents SDK
and CrewAI the package ships adapters as optional extras (0.3.6+); for the
others, copy the snippet.

| framework | install | adapter |
|---|---|---|
| LangChain / LangGraph | `pip install "witness-log[langchain]"` | `witness_log.integrations.langchain.WitnessLogCallbackHandler` |
| OpenAI Agents SDK | `pip install "witness-log[openai-agents]"` | `witness_log.integrations.openai_agents.WitnessLogHooks` |
| CrewAI | `pip install "witness-log[crewai]"` | `witness_log.integrations.crewai.witness_crewai` |
| MCP hosts | `pip install "witness-log[mcp]"` | `witness-log-mcp` ([MCP integration](MCP-Integration)) |

Each adapter is under 100 lines, pairs calls by the framework's own call
id (so parallel calls of one tool are recorded correctly), commits the same
payload shapes as `step` (`{"tool", "args", "t"}` then `{"tool",
"intent_index", "outcome", "value"}`), and never raises into the framework
unless you pass `raise_on_error=True`; append failures are kept in
`.errors`. `record_output=False` keeps return values out of the result leaf.
Each is tested in CI by running the framework's own tool-calling loop with
a fake model and verifying the dossier (`tests/test_integrations.py`).

To get witnessed while the agent runs, add a background
[`Witnesser`](Quickstart-Python) next to any of them:
`w = witness_log.Witnesser(log, "trusted.json", "agent.jsonl")`, then
`w.request()` whenever you like and `w.flush(timeout)` at the end.

## LangChain / LangGraph (Python)

```python
import witness_log
from witness_log.integrations.langchain import WitnessLogCallbackHandler

log = witness_log.open("agent.jsonl")
handler = WitnessLogCallbackHandler(log)

agent.invoke({"messages": [...]}, config={"callbacks": [handler]})   # create_agent / AgentExecutor
graph.invoke(state, config={"callbacks": [handler]})                 # LangGraph: same config
```

Without the extra, the handler is `on_tool_start` / `on_tool_end` /
`on_tool_error` keyed by `run_id`; the 0.3.5 version of this page recorded
every result under the name `"tool"`, which the adapter fixes.

## OpenAI Agents SDK (Python)

```python
import witness_log
from agents import Runner
from witness_log.integrations.openai_agents import WitnessLogHooks

log = witness_log.open("agent.jsonl")
await Runner.run(agent, "...", hooks=WitnessLogHooks(log))
```

The hooks key each call by `ToolContext.tool_call_id` and record
`ToolContext.tool_arguments`. The 0.3.5 snippet on this page keyed by tool
name and recorded no arguments; when the model called one tool twice in
parallel it raised `KeyError` inside the run. Alternatively decorate the
tool itself, arguments included:

```python
from agents import function_tool

@function_tool
@witness_log.step(log)
def get_balance(account: str) -> dict:
    return {"account": account, "balance": 42}
```

## CrewAI

```python
import witness_log
from witness_log.integrations.crewai import witness_crewai

log = witness_log.open("agent.jsonl")
with witness_crewai(log):                 # CrewAI's global before/after tool-call hooks
    crew.kickoff()
```

Or decorate individual tools (works with any CrewAI version):

```python
from crewai.tools import tool

@tool("search")
@witness_log.step(log, name="search")
def search(query: str) -> str:
    """Search the web."""
    return do_search(query)
```

crewai pins `mcp<2`, so install the `crewai` and `mcp` extras in separate
environments.

## A shared helper for the other frameworks

```python
# wl_audit.py
import witness_log
from witness_log.integrations import Recorder

log = witness_log.open("agent.jsonl")             # one identity per agent
rec = Recorder(log)                               # rec.intent(tool, args) -> index; rec.result(tool, index, value, outcome)
intent, result = rec.intent, rec.result
```

## AutoGen (AG2 / autogen-agentchat)

Register decorated functions as tools; every invocation is recorded.

```python
import witness_log, wl_audit

@witness_log.step(wl_audit.log)
def run_sql(query: str) -> str:
    return db.execute(query)

assistant.register_for_llm(name="run_sql", description="Run SQL")(run_sql)
user_proxy.register_for_execution(name="run_sql")(run_sql)
```

## Google ADK

`before_tool_callback` / `after_tool_callback` on the agent.

```python
import wl_audit
pending = {}

def before_tool(tool, args, tool_context):
    pending[tool_context.invocation_id] = wl_audit.intent(tool.name, args)
def after_tool(tool, args, tool_context, tool_response):
    wl_audit.result(tool.name, pending.pop(tool_context.invocation_id), tool_response)

agent = LlmAgent(name="ops", model="gemini-2.5-pro", tools=[...],
                 before_tool_callback=before_tool, after_tool_callback=after_tool)
```

## LlamaIndex

Wrap `FunctionTool` callables with `@witness_log.step`, or use the
instrumentation span handler for `FunctionTool.call` spans.

```python
from llama_index.core.tools import FunctionTool
import witness_log, wl_audit

@witness_log.step(wl_audit.log)
def fetch_doc(doc_id: str) -> str: ...
tools = [FunctionTool.from_defaults(fn=fetch_doc)]
```

## Anthropic / Claude API tool loop (hand-rolled)

```python
for block in response.content:
    if block.type == "tool_use":
        i = wl_audit.intent(block.name, block.input)
        out = TOOLS[block.name](**block.input)
        wl_audit.result(block.name, i, out)
```

## Claude Code hook (records every tool call the model makes)

`.claude/settings.json`:

```json
{"hooks": {
  "PreToolUse":  [{"matcher": "", "hooks": [{"type": "command", "command": "python3 /path/wl_hook.py pre"}]}],
  "PostToolUse": [{"matcher": "", "hooks": [{"type": "command", "command": "python3 /path/wl_hook.py post"}]}]}}
```

```python
# wl_hook.py: reads the hook JSON on stdin, appends a leaf, exits 0
import json, sys, witness_log
ev = json.load(sys.stdin)
log = witness_log.open(".claude/witness.jsonl")
payload = witness_log.canonical_json({k: ev.get(k) for k in ("tool_name", "tool_input", "tool_response", "session_id")})
(log.append_intent if sys.argv[1] == "pre" else log.append_result)(payload)
log.close()
```

One journal is opened per hook invocation here. The journal admits one
writer at a time, so if two hooks run at once (parallel tool calls) the
second `open` raises `OSError` and that event is not recorded; for parallel
tool use or high call rates, run the MCP server instead and let the agent
call `append_audit_step`.

## After the run: checkpoint, witness, verify

Whatever framework: `log.sync()`, then either a background
`witness_log.Witnesser(log, "trusted.json", "agent.jsonl")` with
`w.flush(timeout)` ([Quickstart: Python](Quickstart-Python) §5), or
`witness-log witness submit agent.jsonl --directory trusted.json --out dossier.json`,
then `witness-log verify dossier.json --identity <key> --directory trusted.json --min-witnesses N`
with `N` no larger than the number of witnesses that can cosign (two local
witnesses: `--min-witnesses 2`).
