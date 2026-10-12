"""Google ADK adapter against the installed google-adk: an LlmAgent tree
run by InMemoryRunner with a scripted BaseLlm, parallel tool calls, a
failing tool, and ``transfer_to_agent`` as a handoff."""

from __future__ import annotations

import asyncio
import json
from typing import AsyncGenerator, List

import pytest

import witness_log as wl

pytest.importorskip("google.adk")

from google.adk.agents import LlmAgent  # noqa: E402
from google.adk.apps import App  # noqa: E402
from google.adk.models.base_llm import BaseLlm  # noqa: E402
from google.adk.models.llm_request import LlmRequest  # noqa: E402
from google.adk.models.llm_response import LlmResponse  # noqa: E402
from google.adk.runners import InMemoryRunner  # noqa: E402
from google.genai import types  # noqa: E402

from witness_log.integrations import AgentJournals  # noqa: E402
from witness_log.integrations.google_adk import WitnessLogPlugin  # noqa: E402
from witness_log.profiles.ap2 import bind_dossiers  # noqa: E402


class ScriptedLlm(BaseLlm):
    """Each step is a list of ``(tool_name, args)`` function calls or a string."""

    steps: List[object] = []

    async def generate_content_async(self, llm_request: LlmRequest, stream: bool = False) -> AsyncGenerator[LlmResponse, None]:
        if not self.steps:
            raise AssertionError("ScriptedLlm ran out of steps")
        step = self.steps.pop(0)
        if isinstance(step, str):
            parts = [types.Part(text=step)]
        else:
            parts = [
                types.Part(function_call=types.FunctionCall(name=name, args=args, id=f"call-{k}-{name}"))
                for k, (name, args) in enumerate(step)
            ]
        yield LlmResponse(content=types.Content(role="model", parts=parts))


def get_balance(account: str) -> dict:
    """Return an account balance."""
    return {"account": account, "balance": 42}


def fail(x: str) -> str:
    """Always fails."""
    raise ValueError("boom " + x)


async def _run(runner: InMemoryRunner, text: str):
    session = await runner.session_service.create_session(app_name=runner.app_name, user_id="u")
    events = []
    async for ev in runner.run_async(user_id="u", session_id=session.id, new_message=types.Content(role="user", parts=[types.Part(text=text)])):
        events.append(ev)
    return events


def _payloads(rec):
    return {i: json.loads(p) for i, p in rec.payloads.items()}


def _verified(log):
    rep = json.loads(wl.verify_dossier_json(log.to_dossier_json(), 0.66, log.identity_pubkey_hex()))
    assert rep["internally_consistent"], rep


def test_parallel_tool_calls_in_one_log(tmp_path):
    llm = ScriptedLlm(model="scripted", steps=[[("get_balance", {"account": "a-1"}), ("get_balance", {"account": "a-2"})], "done"])
    agent = LlmAgent(name="ops", model=llm, instruction="x", tools=[get_balance])
    log = wl.open(str(tmp_path / "adk.jsonl"))
    plugin = WitnessLogPlugin(log)
    runner = InMemoryRunner(app=App(name="app", root_agent=agent, plugins=[plugin]))
    events = asyncio.run(_run(runner, "balances?"))
    assert events[-1].content.parts[0].text == "done" and plugin.errors == []
    p = _payloads(plugin.recorder)
    intents = {v["call_id"]: (i, v) for i, v in p.items() if "args" in v}
    results = {v["call_id"]: v for v in p.values() if "outcome" in v}
    assert set(intents) == set(results) and len(intents) == 2
    for cid, (i, v) in intents.items():
        assert v["tool"] == "get_balance" and v["agent"] == "ops" and v["args"]["account"].startswith("a-")
        assert results[cid]["intent_index"] == i and results[cid]["outcome"] == "ok"
        assert results[cid]["value"] == {"account": v["args"]["account"], "balance": 42}
    assert log.tree_size() == 4
    _verified(log)


def test_tool_error_is_recorded_and_still_raised(tmp_path):
    llm = ScriptedLlm(model="scripted", steps=[[("fail", {"x": "now"})], "never"])
    agent = LlmAgent(name="ops", model=llm, instruction="x", tools=[fail])
    log = wl.open(str(tmp_path / "adk.jsonl"))
    plugin = WitnessLogPlugin(log)
    runner = InMemoryRunner(app=App(name="app", root_agent=agent, plugins=[plugin]))
    with pytest.raises(ValueError):
        asyncio.run(_run(runner, "go"))
    p = _payloads(plugin.recorder)
    assert [v["tool"] for v in p.values()] == ["fail", "fail"]
    res = p[1]
    assert res["outcome"] == "error" and res["intent_index"] == 0 and "boom now" in res["value"]
    assert plugin.errors == []
    _verified(log)


def test_transfer_to_agent_is_a_handoff_between_journals(tmp_path):
    billing = LlmAgent(
        name="billing", model=ScriptedLlm(model="s", steps=[[("get_balance", {"account": "a-9"})], "paid"]),
        instruction="x", description="bills", tools=[get_balance],
    )
    triage = LlmAgent(
        name="triage", model=ScriptedLlm(model="s", steps=[[("transfer_to_agent", {"agent_name": "billing"})]]),
        instruction="x", description="routes", sub_agents=[billing],
    )
    j = AgentJournals(str(tmp_path / "audit"))
    plugin = WitnessLogPlugin(j)
    runner = InMemoryRunner(app=App(name="app", root_agent=triage, plugins=[plugin]))
    events = asyncio.run(_run(runner, "bill me"))
    assert any(e.content and e.content.parts and e.content.parts[0].text == "paid" for e in events)
    assert plugin.errors == []
    assert sorted(j.names()) == ["billing", "triage"]

    t = json.loads(j.log("triage").leaves_json())
    b = json.loads(j.log("billing").leaves_json())
    # triage: intent(transfer_to_agent), Sent, result(handoff_to=billing)
    assert [l["leaf_type"] for l in t] == [1, 5, 2]
    assert t[1]["handoff_direction"] == "Sent" and t[1]["counterparty_pubkey"] == j.identity("billing")
    tp = _payloads(j.recorder("triage"))
    assert tp[0]["tool"] == "transfer_to_agent" and tp[0]["args"] == {"agent_name": "billing"}
    assert tp[2]["handoff_to"] == "billing" and tp[2]["sent_leaf"] == 1 and tp[2]["received_leaf"] == 0
    # billing: Received, then its own tool pair
    assert [l["leaf_type"] for l in b] == [5, 1, 2]
    assert wl.verify_handoff_binding(j.identity("triage"), json.dumps(t[1]), j.identity("billing"), json.dumps(b[0])) is True
    bp = _payloads(j.recorder("billing"))
    assert bp[1]["tool"] == "get_balance" and bp[1]["agent"] == "billing" and bp[2]["outcome"] == "ok"

    docs = j.export_dossiers()
    for n in j.names():
        _verified(j.log(n))
    rep = bind_dossiers(docs["triage"], docs["billing"])
    assert rep["exit"] == 0 and rep["bound"][0]["kind"] == "handoff"
    j.close()
