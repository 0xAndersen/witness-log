# Framework guides

Every framework below exposes a hook that fires before and after a tool
call. The pattern is always the same: *intent leaf before, result leaf
after, on one journal per agent identity*. `witness_log.step` does exactly
this for a plain function; the snippets below wire it to each framework's
hook. All of them use only the public `witness_log` API documented in
[Quickstart: Python](Quickstart-Python). Adapter packages for these are
on the [Roadmap](Roadmap); until then, copy the snippet.

A shared helper used by every snippet:

```python
# wl_audit.py
import json, witness_log
log = witness_log.open("agent.jsonl")           # one identity per agent

def intent(tool: str, args) -> int:
    return log.append_intent(witness_log.canonical_json({"tool": tool, "args": args}))

def result(tool: str, intent_index: int, value, outcome: str = "ok") -> int:
    return log.append_result(witness_log.canonical_json(
        {"tool": tool, "intent_index": intent_index, "outcome": outcome, "value": value}))
```

## LangChain / LangGraph (Python)

A callback handler receives every tool start and end.

```python
from langchain_core.callbacks import BaseCallbackHandler
import wl_audit

class WitnessLogHandler(BaseCallbackHandler):
    def __init__(self):
        self._pending = {}
    def on_tool_start(self, serialized, input_str, *, run_id, **kw):
        self._pending[run_id] = wl_audit.intent(serialized.get("name", "tool"), input_str)
    def on_tool_end(self, output, *, run_id, **kw):
        i = self._pending.pop(run_id, None)
        if i is not None:
            wl_audit.result("tool", i, str(output))
    def on_tool_error(self, error, *, run_id, **kw):
        i = self._pending.pop(run_id, None)
        if i is not None:
            wl_audit.result("tool", i, repr(error), outcome="error")

# agent_executor.invoke({"input": ...}, config={"callbacks": [WitnessLogHandler()]})
# graph.invoke(state, config={"callbacks": [WitnessLogHandler()]})   # LangGraph: same config
```

## OpenAI Agents SDK (Python)

`RunHooks` fires on tool start/end; or decorate the tool functions.

```python
from agents import Agent, Runner, RunHooks, function_tool
import witness_log, wl_audit

class WitnessHooks(RunHooks):
    async def on_tool_start(self, context, agent, tool):
        context.context.setdefault("wl", {})[tool.name] = wl_audit.intent(tool.name, None)
    async def on_tool_end(self, context, agent, tool, result):
        wl_audit.result(tool.name, context.context["wl"].pop(tool.name), result)

# Simpler: decorate the tool itself, arguments included.
@function_tool
@witness_log.step(wl_audit.log)
def get_balance(account: str) -> dict:
    return {"account": account, "balance": 42}

await Runner.run(agent, "...", hooks=WitnessHooks(), context={})
```

## CrewAI

Tools are plain callables; decorate them.

```python
from crewai.tools import tool
import witness_log, wl_audit

@tool("search")
@witness_log.step(wl_audit.log, name="search")
def search(query: str) -> str:
    """Search the web."""
    return do_search(query)
```

`Crew(step_callback=...)` can additionally append a memory leaf per agent
step (`wl_audit.log.append_memory(witness_log.canonical_json(step))`).

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

One journal is opened per hook invocation here; for high tool-call rates,
run the MCP server instead and let the agent call `append_audit_step`.

## After the run: checkpoint, witness, verify

Whatever framework: `wl_audit.log.sync()`, then either
`witness-log witness submit agent.jsonl --directory trusted.json --out dossier.json`
or the Python submission loop in [Quickstart: Python](Quickstart-Python),
then `witness-log verify dossier.json --identity <key> --directory trusted.json --min-witnesses 3`.
