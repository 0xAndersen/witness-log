# Framework adapters: the nightly live run

The adapters in `witness_log.integrations` sit on other projects' hook
APIs, and those projects release often. An adapter can import cleanly,
pass a test against a stub, and still crash the first time the real SDK
calls it with a slightly different argument. An outside evaluation of the
0.3.5 release found exactly that in two comparable projects: adapters that
had never been run against the live framework. This page describes how
witness-log avoids being the third.

## Two layers of testing

**Pinned, in CI** (`.github/workflows/ci.yml`, job `integrations`). Runs on
every push and pull request with the versions pinned in
`pyproject.toml`'s extras. It cannot be broken by an upstream release, so
it stays a meaningful signal about *our* changes. Marked
`continue-on-error` so a framework's own flakiness does not block a
release of the core.

**Latest, nightly** (`.github/workflows/frameworks-live.yml`). Runs at
04:17 UTC every day, on `workflow_dispatch`, and on pull requests that
touch `witness_log/integrations/`, the live tests, `pyproject.toml` or the
workflow itself. One matrix job per adapter:

| job | installs (latest from PyPI) | runs |
|---|---|---|
| `openai-agents` | `openai-agents` | `tests/test_openai_agents_live.py`, `test_integrations.py::test_openai_agents_runner` |
| `langchain` | `langchain-core langchain` | `test_integrations.py::test_langchain_agent_loop` |
| `langgraph` | `langgraph langchain-core` | `tests/test_langgraph_live.py` |
| `google-adk` | `google-adk` | `tests/test_google_adk_live.py` |
| `pydantic-ai` | `pydantic-ai-slim` | `tests/test_pydantic_ai_live.py` |
| `autogen` | `autogen-agentchat autogen-core autogen-ext` | `tests/test_autogen_live.py` |
| `llamaindex` | `llama-index-core` | `tests/test_llamaindex_live.py` |
| `crewai` | `crewai` | `test_integrations.py::test_crewai_crew` |

Each job builds the wheel with `maturin build --release`, installs it,
installs the framework with `pip install --upgrade` (no version pin), runs
`pip check`, writes the resolved version to the job summary (so the run
says which release it tested), and runs that adapter's tests with `-rs`.
**A skipped test fails the job**: every live test starts with
`pytest.importorskip(<framework>)` so the ordinary suite stays runnable
without the frameworks, and in this workflow a skip can only mean the
framework did not import, which is the one thing the workflow exists to
notice. `fail-fast` is off, so one framework's bad week does not hide the
others' results.

## What a live test does

Every `tests/test_<adapter>_live.py`:

1. imports the real framework (not a stub of it);
2. builds a scripted model with the framework's own test double where it
   has one (`agents.testing.ScriptedModel`, pydantic-ai's `FunctionModel`,
   autogen-ext's `ReplayChatCompletionClient`, LlamaIndex's
   `MockFunctionCallingLLM`, LangChain's `GenericFakeChatModel`) or a
   minimal subclass of its model interface (Google ADK's `BaseLlm`,
   CrewAI's `BaseLLM`);
3. runs the framework's own agent loop with two parallel calls of one
   tool, one tool that raises, and, where the framework has one, a
   handoff;
4. asserts on the leaves: one intent and one result per call, each
   result's `intent_index` pointing at its own intent, the real
   arguments recorded, `outcome: "error"` for the failing tool, the
   handoff's `Sent` / `Received` attestations binding with
   `verify_handoff_binding`;
5. verifies the dossier with `verify_dossier_json` (and, for two
   journals, binds them with `witness_log.profiles.ap2.bind_dossiers`).

No network is used: the scripted models return canned tool calls, and the
tools are local functions.

## Reading a failure

A red nightly job names the framework and the version it installed (the
job summary and a `::notice` annotation). The usual causes, in order of
how often they happen to this kind of code:

- **The hook signature changed.** A keyword argument was renamed or a
  positional became keyword-only. The test's traceback points at the
  adapter method; fix the adapter, keep accepting the old shape where it
  costs nothing, and raise the floor in `pyproject.toml` only if the old
  shape cannot be supported.
- **The test double changed.** The framework's scripted model gained a
  required argument or changed what it yields. Fix the test; the adapter
  is fine.
- **An error path moved.** The framework now swallows an exception it
  used to raise (or the reverse), so the result leaf's `outcome` differs.
  Decide which behaviour the adapter should record and update both.
- **A dependency conflict.** `pip check` fails before the tests run; the
  framework's new release pins something the wheel or another extra
  conflicts with. Give it its own extra, as `crewai` already has.

When a fix lands, the pull request itself triggers this workflow (the
`paths` filter includes the adapters), so the fix is proven against the
same latest release before it merges.

## Running it locally

```sh
cd crates/witness-log-python
pip install maturin pytest && maturin develop --release
pip install --upgrade openai-agents          # or any of the packages in the table
pytest -q -rs tests/test_openai_agents_live.py
```

`crewai` wants its own virtual environment (it pins `mcp<2`; the `mcp`
extra needs `mcp>=2`).

Next: [Framework guides](Framework-Guides) · [Testing and evidence](Testing-and-Evidence)
