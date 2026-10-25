# Framework guides

Every framework below exposes a hook that fires before and after a tool
call. The pattern is always the same: *intent leaf before, result leaf
after, on one journal per agent identity*. `witness_log.step` does exactly
this for a plain function; the adapters in `witness_log.integrations` do it
through each framework's own hook, and record a handoff where the framework
has one.

| framework | install | adapter | handoff |
|---|---|---|---|
| OpenAI Agents SDK | `pip install "witness-log[openai-agents]"` | `witness_log.integrations.openai_agents.WitnessLogAudit` / `WitnessLogHooks` | `on_handoff` |
| Claude Agent SDK | `pip install "witness-log[claude-agent-sdk]"` | `witness_log.integrations.claude_agent_sdk.witness_hooks` / `WitnessLogClaudeHooks` | – |
| LangGraph | `pip install "witness-log[langgraph]"` | `witness_log.integrations.langgraph.WitnessLogGraphHandler` | `Command(goto=...)` |
| LangChain | `pip install "witness-log[langchain]"` | `witness_log.integrations.langchain.WitnessLogCallbackHandler` | – |
| Google ADK | `pip install "witness-log[google-adk]"` | `witness_log.integrations.google_adk.WitnessLogPlugin` | `transfer_to_agent` |
| pydantic-ai | `pip install "witness-log[pydantic-ai]"` | `witness_log.integrations.pydantic_ai.WitnessLogToolset` | – |
| AutoGen AgentChat | `pip install "witness-log[autogen]"` | `witness_log.integrations.autogen.WitnessLogAutoGen` | `HandoffMessage` |
| LlamaIndex | `pip install "witness-log[llamaindex]"` | `witness_log.integrations.llamaindex.WitnessLogLlamaIndex` / `WitnessLogSpanHandler` | `handoff` tool |
| CrewAI | `pip install "witness-log[crewai]"` | `witness_log.integrations.crewai.witness_crewai` | – |
| anything instrumented with OpenTelemetry (GenAI conventions or OpenInference) | `pip install "witness-log[otel]"` | `witness_log.integrations.otel.WitnessLogSpanProcessor` ([below](#opentelemetry)) | – |
| MCP hosts | `pip install "witness-log[mcp]"` | `witness-log-mcp` ([MCP integration](MCP-Integration)) | – |
| any stdio MCP server, as run | `pip install witness-log` | `witness-log-mcp-proxy` ([MCP proxy](MCP-Proxy)) | – |
| Claude Code hooks | `pip install witness-log` | `witness-log-hook` ([Hooks](Hooks)) | – |

`pip install "witness-log[all-frameworks]"` installs every extra except
`crewai` (its `mcp<2` pin conflicts with the `mcp` extra; give it its own
environment).

What is common to all of them:

- **Pairing by the framework's call id.** Two parallel calls of one tool
  are two intents and two results, each result's `intent_index` pointing
  at its own intent. Nothing is keyed by tool name.
- **Payload shapes match `step`**: the intent commits to `{"tool", "args",
  "t", "call_id", "agent", ...}`, the result to `{"tool", "intent_index",
  "outcome", "value", ...}` with `outcome` `"ok"` or `"error"`. A tool
  that raises is recorded as `"error"` whether the framework re-raises it,
  swallows it into a message for the model, or asks for a retry. The
  Claude Agent SDK adapter is the exception: it writes the Claude Code
  hook's payloads (`hook.claude-code v1`), so its records read like
  `witness-log-hook`'s; its results carry `intent_index` too.
- **Never raises into the framework** unless you pass
  `raise_on_error=True`; append failures are kept in `.errors`.
  `record_output=False` keeps return values out of the result leaf
  (errors are still recorded).
- **One log or one journal per agent.** Every adapter takes either a
  `JournaledLog` (the whole run in one journal) or an
  `AgentJournals` (one journal per agent name under a directory). With
  journals a handoff writes a `HandoffAttestation` `Sent` leaf in the
  source agent's journal and `Received` in the target's, over the same
  state bytes, so [`witness-log bind`](Tutorial-Multi-Agent-Handoff) (or
  `witness_log.profiles.ap2.bind_dossiers` in Python) proves the two
  journals agree on who handed what to whom. With one log the handoff is
  the handoff tool's own intent / result pair, annotated `handoff_to`.
- **Payloads are kept for disclosure.** The adapter's `Recorder` keeps the
  exact bytes it appended (`.recorder.payloads`, or
  `journals.recorder(name).payloads`), so a leaf can later be disclosed as
  leaf + payload + salt (`AgentJournals.disclose(i)`,
  `witness_log.profiles.ap2.dispute_export`) or erased
  (`AgentJournals.forget(i)`).
- **Tested against the real framework, nightly.** Each adapter has a test
  that imports the installed framework and runs its own tool-calling loop
  with a scripted model; the [`frameworks-live` workflow](Framework-Adapters-CI)
  installs the latest release of each framework from PyPI and fails if the
  test is skipped or breaks.

```python
# one journal per agent, sealed identities from your KMS; every adapter takes `journals` in place of a log
from agents import Runner
from witness_log.integrations import AgentJournals
from witness_log.integrations.openai_agents import WitnessLogHooks

journals = AgentJournals("audit/", seed_for=kms.seed_for, sealed=True)
await Runner.run(triage_agent, "bill me", hooks=WitnessLogHooks(journals))
journals.export_dossiers()                 # audit/<agent>.dossier.json, one per agent
journals.disclose(0, agent="triage")       # {"leaf", "payload", "salt", "verified": True}
journals.forget(0, agent="triage")         # right to be forgotten; the dossier still verifies
```

`journals.witness("trusted.json")` runs one witnessing round per journal
against your trusted directory and rewrites each dossier with the
cosignatures it collected.

To get witnessed *while* the agent runs, add a background
[`Witnesser`](Quickstart-Python) next to any single log:
`w = witness_log.Witnesser(log, "trusted.json", "agent.jsonl")`, then
`w.request()` whenever you like and `w.flush(timeout)` at the end.

## OpenAI Agents SDK

```python
import witness_log
from agents import Runner, add_trace_processor
from witness_log.integrations.openai_agents import WitnessLogAudit

audit = WitnessLogAudit("audit/", seed_for=kms.seed_for, sealed=True)   # one journal per agent.name
add_trace_processor(audit.processor())                                 # completes tools that raise through
result = await Runner.run(triage_agent, "bill me", hooks=audit.hooks)
audit.export_dossiers()                                                # audit/triage.dossier.json, audit/billing.dossier.json
```

For one journal shared by the run, `WitnessLogHooks(witness_log.open("agent.jsonl"))`
as `hooks=`. No `context=` is required.

What the adapter handles in this SDK specifically (tested against
`openai-agents` 0.23 with its `agents.testing.ScriptedModel`):

- Calls are keyed by `ToolContext.tool_call_id` and the arguments come
  from `ToolContext.tool_arguments` (the model's raw JSON, parsed). The
  0.3.5 wiki snippet keyed by tool name and raised `KeyError` when one
  tool was called twice in parallel.
- A tool that raises is replaced, before `on_tool_end` sees it, by the
  string *"An error occurred while running the tool. Please try again."*;
  the real exception goes only to the trace span as *"Error running tool
  (non-fatal)"*. The adapter reads the span error (or recognises the
  default text when tracing is off) and records `outcome: "error"`.
- A tool declared with `failure_error_function=None` raises through the
  run and never reaches `on_tool_end`; `audit.processor()` is a
  `TracingProcessor` that writes that result leaf when the function span
  ends. Nothing is exported anywhere by it.
- `on_handoff` writes `Sent` in the source agent's journal, `Received` in
  the target's, and an intent / result pair named `handoff` in the source.

Alternatively decorate the tool itself, arguments included:

```python
from agents import function_tool

@function_tool
@witness_log.step(log)
def get_balance(account: str) -> dict:
    return {"account": account, "balance": 42}
```

## Claude Agent SDK

```python
import witness_log
from claude_agent_sdk import ClaudeAgentOptions, query
from witness_log.integrations.claude_agent_sdk import WitnessLogClaudeHooks, witness_hooks

log = witness_log.open("agent.jsonl")
options = ClaudeAgentOptions(hooks=witness_hooks(log), allowed_tools=["Read", "Grep"])
async for message in query(prompt="summarise the open invoices", options=options):
    ...
```

`witness_hooks(log)` is the `hooks=` value: a `PreToolUse`, a
`PostToolUse` and a `PostToolUseFailure` `HookMatcher`, so every tool call
the agent makes (built-in tools, MCP tools, in-process `@tool` /
`create_sdk_mcp_server` tools alike) is an intent leaf and a result leaf.
To keep `.errors` and the kept payloads, or to merge into options that
already have hooks of their own:

```python
audit = WitnessLogClaudeHooks(log)
options = audit.options(ClaudeAgentOptions(model="...", hooks=my_hooks))   # a copy; your hooks are kept
```

The SDK hands a hook callback the same JSON object Claude Code pipes to a
command hook, so the payloads are the ones [`witness-log-hook`](Hooks)
writes, built by the same function (`witness_log.hook.normalize`), and a
dossier from the SDK reads like one from Claude Code:

```
PreToolUse          -> intent leaf:  {"profile": "hook.claude-code v1", "event": "PreToolUse",
                                      "session_id", "tool_name", "tool_input", "tool_use_id", "cwd"}
PostToolUse         -> result leaf:  the same plus "tool_response" and "intent_index"
PostToolUseFailure  -> result leaf:  every field but transcript_path ("error", "is_interrupt", ...)
                                     plus "intent_index"
```

The intent is byte for byte what the hook writes for that event;
`intent_index`, the leaf index of the call's intent, is the one key the
hook does not write (it is the link every adapter's result carries).
Calls are paired by `tool_use_id`, so parallel calls of one tool are
recorded separately, and the callbacks are safe across event loops and
threads. `record_output=False` leaves `tool_response` out.

Failure policy: a callback never raises into the SDK and never blocks the
tool. A failed append is kept in `.errors` and the callback answers `{}`
(no decision). `strict=True` is the SDK form of `witness-log-hook
--strict`: a `PreToolUse` whose intent leaf could not be written answers
`permissionDecision: "deny"` with the reason, so the tool does not run
unrecorded. There is no `raise_on_error`: Claude Code logs a hook callback
that fails and carries on, so raising would block nothing.

With an `AgentJournals` in place of the log, a call made inside a subagent
(the `Agent` / `Task` tool) goes to the journal named by its `agent_type`
and a main-thread call to `agent=` (default `"main"`); the payload itself
does not name the subagent, as with the hook. No handoff attestation is
written: the hook events do not say which `Agent` call started a
subagent. Only the configuration needs the SDK; the module imports
without it. Tested against `claude-agent-sdk` 0.2.168 and the 0.1.50
floor; see [`examples/claude-agent-sdk`](https://github.com/0xAndersen/witness-log/tree/main/examples/claude-agent-sdk)
for a run against the real agent.

## LangGraph

```python
import witness_log
from witness_log.integrations.langgraph import WitnessLogGraphHandler

handler = WitnessLogGraphHandler(witness_log.open("graph.jsonl"))
out = graph.invoke({"messages": [("user", "hi")]}, config={"callbacks": [handler]})
```

LangGraph runs tools through LangChain's callbacks, so this is the
LangChain handler keyed by `run_id` with two additions: the node a tool
runs in (`langgraph_node` in the callback metadata) is recorded as the
agent and, with `AgentJournals`, selects the journal; and a tool or node
that returns `Command(goto="other_node")` (the `create_handoff_tool` /
supervisor pattern) is a handoff from the current node to `goto`. Tool
errors are recorded as `"error"` whether `ToolNode(handle_tool_errors=True)`
turns them into a message or they propagate.

## LangChain

```python
import witness_log
from witness_log.integrations.langchain import WitnessLogCallbackHandler

handler = WitnessLogCallbackHandler(witness_log.open("agent.jsonl"))
agent.invoke({"messages": [("user", "balances?")]}, config={"callbacks": [handler]})   # create_agent / AgentExecutor
```

`on_tool_start` / `on_tool_end` / `on_tool_error` keyed by `run_id`. Use
the LangGraph handler above when the agent is a graph with several nodes.

## Google ADK

```python
import witness_log
from google.adk.apps import App
from google.adk.runners import InMemoryRunner
from witness_log.integrations.google_adk import WitnessLogPlugin

plugin = WitnessLogPlugin(witness_log.open("agent.jsonl"))
runner = InMemoryRunner(app=App(name="app", root_agent=root_agent, plugins=[plugin]))
```

A plugin applies to every agent under the runner (per-agent
`before_tool_callback` / `after_tool_callback` do not). Calls are keyed by
`ToolContext.function_call_id`, the agent is `ToolContext.agent_name`, a
tool that raises reaches `on_tool_error_callback` and is recorded as
`"error"` (the plugin returns `None` there, so ADK's own error handling is
unchanged). When a tool sets `tool_context.actions.transfer_to_agent`
(the built-in `transfer_to_agent`, which ADK adds for `sub_agents`), the
result leaf carries `handoff_to` and, with `AgentJournals`, the two
attestations are written. Tested against `google-adk` 2.11.

## pydantic-ai

```python
import witness_log
from pydantic_ai import Agent
from pydantic_ai.toolsets import FunctionToolset
from witness_log.integrations.pydantic_ai import WitnessLogToolset

tools = FunctionToolset([get_balance, send_invoice])
agent = Agent(model, name="billing", toolsets=[WitnessLogToolset(tools, witness_log.open("agent.jsonl"))])  # model: "openai:gpt-4o", ...
agent.run_sync("bill account a")
```

`WitnessLogToolset(wrapped, target)` is a `WrapperToolset`, so it takes
the wrapped toolset first as pydantic-ai's own wrappers do. Calls are
keyed by `RunContext.tool_call_id` and the recorded arguments are the
validated ones. `ModelRetry` is recorded as `"error"` with `retry: true`;
any other exception is recorded and re-raised unchanged. Tested against
`pydantic-ai-slim` 2.55.

## AutoGen AgentChat

```python
import witness_log
from witness_log.integrations.autogen import WitnessLogAutoGen

audit = WitnessLogAutoGen(witness_log.open("team.jsonl"))
result = await audit.run(team, task="bill me")          # in place of await team.run(task=...)
```

AgentChat has no per-tool hook; what agents do is the event stream, so the
adapter reads it. `ToolCallRequestEvent` is one intent per `FunctionCall`
(keyed by its `id`), `ToolCallExecutionEvent` one result per
`FunctionExecutionResult` (`outcome` from `is_error`), a `HandoffMessage` a
handoff from `source` to `target`. To keep your own loop:

```python
async for event in audit.record(team.run_stream(task="bill me")):
    ...                                                  # events pass through unchanged (Console works)
```

Tested against `autogen-agentchat` 0.7 with `autogen-ext`'s
`ReplayChatCompletionClient`.

## LlamaIndex

```python
import witness_log
from witness_log.integrations.llamaindex import WitnessLogLlamaIndex

audit = WitnessLogLlamaIndex(witness_log.open("agent.jsonl"))
result = await audit.run(workflow, user_msg="bill me")   # in place of await workflow.run(user_msg=...)
```

`AgentWorkflow` / `FunctionAgent` / `ReActAgent` emit a `ToolCall` and a
`ToolCallResult` (`tool_output.is_error`) per call with the model's
`tool_id`; the current agent comes from the surrounding `AgentInput` /
`AgentOutput` events. The built-in `handoff` tool (`can_handoff_to`) is
recorded as a handoff to `to_agent`. For tools called outside an agent
workflow, hook the instrumentation instead:

```python
from llama_index.core.instrumentation import get_dispatcher
from witness_log.integrations.llamaindex import WitnessLogSpanHandler

get_dispatcher().add_span_handler(WitnessLogSpanHandler(witness_log.open("tools.jsonl")))
```

That records the `FunctionTool.call` / `acall` spans: intent when the
span opens, result when it exits or is dropped with an exception. Use one
mechanism per log, not both. Tested against `llama-index-core` 0.14.

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

## OpenTelemetry

If your agent already emits traces, one span processor is enough, whatever
the framework: anything that follows the OpenTelemetry GenAI semantic
conventions (`gen_ai.*`: Google ADK, pydantic-ai and Logfire, Strands,
OpenLLMetry, the OpenTelemetry GenAI instrumentations) or OpenInference
(Arize Phoenix's instrumentors for LangChain, LlamaIndex, OpenAI Agents,
CrewAI and others).

```python
import witness_log
from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from witness_log.integrations.otel import WitnessLogSpanProcessor

provider = TracerProvider()
provider.add_span_processor(WitnessLogSpanProcessor(witness_log.open("agent.jsonl")))
trace.set_tracer_provider(provider)   # keep your exporter: the processor runs beside it
```

Each tool span (`execute_tool`, OpenInference `TOOL`) becomes an intent leaf
when it starts, before the tool runs, and a result leaf when it ends, with
the arguments and result the instrumentation records
(`gen_ai.tool.call.arguments` / `.result`, or `input.value` /
`output.value`). Each model or agent span (`chat`, `generate_content`,
`invoke_agent`, ..., OpenInference `LLM` / `AGENT`) becomes one memory leaf
with the model, provider, agent, conversation id, token usage and outcome.
Prompts and completions stay out unless `record_content=True`;
`record_inputs`, `record_outputs` and `record_calls` turn the rest off. Every
leaf carries the span's `trace_id` and `span_id`, so an entry in the log
points to the same span in your observability backend. A failing append
never breaks tracing: it lands in `processor.errors`.

## A shared helper for anything else

```python
# wl_audit.py
import witness_log
from witness_log.integrations import Recorder

log = witness_log.open("agent.jsonl")             # one identity per agent
rec = Recorder(log)                               # rec.intent(tool, args) -> index; rec.result(tool, index, value, outcome)
intent, result = rec.intent, rec.result
```

### Anthropic / Claude API tool loop (hand-rolled)

```python
for block in response.content:
    if block.type == "tool_use":
        i = wl_audit.intent(block.name, block.input, call_id=block.id)
        out = TOOLS[block.name](**block.input)
        wl_audit.result(block.name, i, out, call_id=block.id)
```

### Claude Code hook (records every tool call the model makes)

```sh
witness-log-hook install claude-code --journal ~/.witness-log/claude-code.jsonl
```

prints the `.claude/settings.json` entries (it writes nothing):

```json
{"hooks": {
  "PreToolUse":  [{"matcher": "", "hooks": [{"type": "command", "command": "witness-log-hook --autostart --journal ~/.witness-log/claude-code.jsonl"}]}],
  "PostToolUse": [{"matcher": "", "hooks": [{"type": "command", "command": "witness-log-hook --autostart --journal ~/.witness-log/claude-code.jsonl"}]}]}}
```

Each hook invocation sends the event to `witness-log-hookd`, a daemon
that holds the journal open behind a Unix socket (started on first use by
`--autostart`), so parallel tool calls do not fight over the journal's
single-writer lock and no session key is minted per call. `PreToolUse`
becomes an intent leaf, `PostToolUse` a result leaf. Details, the exact
payload shape, Cursor and Codex: [Hooks](Hooks).

## After the run: checkpoint, witness, verify

Whatever framework: `log.sync()` (or `journals.sync()`), then either a
background `witness_log.Witnesser(log, "trusted.json", "agent.jsonl")` with
`w.flush(timeout)` ([Quickstart: Python](Quickstart-Python) §5),
`journals.witness("trusted.json")` for a set of journals, or
`witness-log witness submit agent.jsonl --directory trusted.json --out dossier.json`,
then `witness-log verify dossier.json --identity <key> --directory trusted.json --min-witnesses N`
with `N` no larger than the number of witnesses that can cosign (two local
witnesses: `--min-witnesses 2`). Two agents' dossiers that handed work to
each other: `witness-log bind a.json b.json`.
