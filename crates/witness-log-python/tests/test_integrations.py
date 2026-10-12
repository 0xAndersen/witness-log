"""Each framework's own minimal tool-calling loop, driven by a fake model,
through the matching adapter; then the dossier is verified. Skipped when
the framework is not installed (the base CI stays light; the
`integrations` CI job installs them)."""

from __future__ import annotations

import asyncio
import json
import os

import pytest

import witness_log as wl


def _check(log, tools_called):
    d = log.to_dossier_json()
    rep = json.loads(wl.verify_dossier_json(d, 0.66, log.identity_pubkey_hex()))
    assert rep["verdict"] == "unanchored" and rep["internally_consistent"], rep
    leaves = json.loads(log.leaves_json())
    types = [l["leaf_type"] for l in leaves]
    # one intent (1) and one result (2) per call, nothing else; parallel
    # calls may interleave, but no result can precede every intent
    assert sorted(types) == [1] * tools_called + [2] * tools_called, types
    assert all(types[:i].count(1) >= types[:i].count(2) for i in range(len(types) + 1)), types


def test_langchain_agent_loop(tmp_path):
    pytest.importorskip("langchain_core")
    agents_mod = pytest.importorskip("langchain.agents")
    from langchain_core.language_models.fake_chat_models import GenericFakeChatModel
    from langchain_core.messages import AIMessage
    from langchain_core.tools import tool

    from witness_log.integrations.langchain import WitnessLogCallbackHandler

    @tool
    def get_balance(account: str) -> str:
        """Return an account balance."""
        return f"{account}: 42"

    @tool
    def fail(x: str) -> str:
        """Always fails."""
        raise ValueError("boom")

    class FakeToolModel(GenericFakeChatModel):
        def bind_tools(self, tools, **kw):
            return self

    model = FakeToolModel(
        messages=iter(
            [
                AIMessage(
                    content="",
                    tool_calls=[
                        {"name": "get_balance", "args": {"account": "a-1"}, "id": "c1"},
                        {"name": "get_balance", "args": {"account": "a-2"}, "id": "c2"},
                    ],
                ),
                AIMessage(content="done"),
            ]
        )
    )
    log = wl.open(str(tmp_path / "agent.jsonl"))
    h = WitnessLogCallbackHandler(log)
    out = agents_mod.create_agent(model, tools=[get_balance, fail]).invoke(
        {"messages": [{"role": "user", "content": "balances?"}]}, config={"callbacks": [h]}
    )
    assert out["messages"][-1].content == "done"
    assert h.errors == []
    _check(log, 2)
    # Results are paired to their own intents, with the tool's name.
    leaves = json.loads(log.leaves_json())
    assert len({l["index"] for l in leaves}) == 4

    # Errors are recorded as results of kind "error" and re-raised by LangChain.
    with pytest.raises(ValueError):
        fail.invoke({"x": "y"}, config={"callbacks": [h]})
    assert log.tree_size() == 6


def test_openai_agents_runner(tmp_path):
    pytest.importorskip("agents")
    from agents import Agent, Runner, function_tool
    from agents.items import ModelResponse
    from agents.models.interface import Model
    from agents.usage import Usage
    from openai.types.responses import ResponseFunctionToolCall, ResponseOutputMessage, ResponseOutputText

    from witness_log.integrations.openai_agents import WitnessLogHooks

    os.environ.setdefault("OPENAI_AGENTS_DISABLE_TRACING", "1")

    @function_tool
    def get_balance(account: str) -> dict:
        """Get a balance."""
        return {"account": account, "balance": 42}

    class FakeModel(Model):
        def __init__(self):
            self.turn = 0

        async def get_response(self, *a, **k):
            self.turn += 1
            if self.turn == 1:  # two parallel calls of the SAME tool
                out = [
                    ResponseFunctionToolCall(id=f"fc{i}", call_id=f"c{i}", type="function_call",
                                             name="get_balance", arguments=json.dumps({"account": f"a-{i}"}))
                    for i in (1, 2)
                ]
            else:
                out = [ResponseOutputMessage(id="m", type="message", role="assistant", status="completed",
                                             content=[ResponseOutputText(type="output_text", text="done", annotations=[])])]
            return ModelResponse(output=out, usage=Usage(), response_id=None)

        def stream_response(self, *a, **k):  # pragma: no cover
            raise NotImplementedError

    log = wl.open(str(tmp_path / "agent.jsonl"))
    hooks = WitnessLogHooks(log)
    agent = Agent(name="a", instructions="x", tools=[get_balance], model=FakeModel())
    r = asyncio.run(Runner.run(agent, "balances?", hooks=hooks))
    assert r.final_output == "done" and hooks.errors == []
    _check(log, 2)


def test_crewai_crew(tmp_path):
    pytest.importorskip("crewai")
    os.environ.setdefault("CREWAI_DISABLE_TELEMETRY", "true")
    os.environ.setdefault("OTEL_SDK_DISABLED", "true")
    from crewai import Agent, Crew, Task
    from crewai.llms.base_llm import BaseLLM
    from crewai.tools import tool

    from witness_log.integrations.crewai import witness_crewai

    @tool("search")
    def search(query: str) -> str:
        """Search the web."""
        return f"results for {query}"

    class StubLLM(BaseLLM):
        def __init__(self):
            super().__init__(model="stub")
            self.n = 0

        def call(self, messages, tools=None, callbacks=None, available_functions=None, **kw):
            self.n += 1
            if self.n == 1:
                return 'Thought: search\nAction: search\nAction Input: {"query": "witness logs"}'
            return "Thought: I now know the final answer\nFinal Answer: done"

        def supports_function_calling(self):
            return False

        def supports_stop_words(self):
            return False

        def get_context_window_size(self):
            return 8192

    log = wl.open(str(tmp_path / "agent.jsonl"))
    a = Agent(role="r", goal="g", backstory="b", tools=[search], llm=StubLLM(), verbose=False)
    t = Task(description="search", expected_output="anything", agent=a)
    with witness_crewai(log) as hooks:
        out = Crew(agents=[a], tasks=[t], verbose=False).kickoff()
    assert out.raw == "done" and hooks.errors == []
    _check(log, 1)
    leaves = json.loads(log.leaves_json())
    assert len(leaves) == 2
