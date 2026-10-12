"""AutoGen AgentChat adapter against the installed autogen-agentchat /
autogen-ext: an AssistantAgent with a ReplayChatCompletionClient making
parallel tool calls, a failing tool, and a handoff."""

from __future__ import annotations

import asyncio
import json

import pytest

import witness_log as wl

pytest.importorskip("autogen_agentchat")
pytest.importorskip("autogen_ext.models.replay")

from autogen_agentchat.agents import AssistantAgent  # noqa: E402
from autogen_agentchat.base import Handoff, TaskResult  # noqa: E402
from autogen_core import FunctionCall  # noqa: E402
from autogen_core.models import CreateResult, ModelInfo, RequestUsage  # noqa: E402
from autogen_ext.models.replay import ReplayChatCompletionClient  # noqa: E402

from witness_log.integrations import AgentJournals  # noqa: E402
from witness_log.integrations.autogen import WitnessLogAutoGen  # noqa: E402
from witness_log.profiles.ap2 import bind_dossiers  # noqa: E402

MODEL_INFO = ModelInfo(vision=False, function_calling=True, json_output=False, family="unknown", structured_output=False)
USAGE = RequestUsage(prompt_tokens=1, completion_tokens=1)


def get_balance(account: str) -> dict:
    """Return a balance."""
    return {"account": account, "balance": 42}


def fail(x: str) -> str:
    """Always fails."""
    raise ValueError("boom " + x)


def _calls(*items):
    return CreateResult(finish_reason="function_calls", content=[FunctionCall(id=i, name=n, arguments=json.dumps(a)) for i, n, a in items], usage=USAGE, cached=False)


def _agent(script, **kw):
    client = ReplayChatCompletionClient(script, model_info=MODEL_INFO)
    return AssistantAgent("triage", model_client=client, tools=[get_balance, fail], reflect_on_tool_use=False, max_tool_iterations=3, **kw)


def _payloads(rec):
    return {i: json.loads(p) for i, p in rec.payloads.items()}


def _verified(log):
    rep = json.loads(wl.verify_dossier_json(log.to_dossier_json(), 0.66, log.identity_pubkey_hex()))
    assert rep["internally_consistent"], rep


def test_parallel_tool_calls_and_error(tmp_path):
    agent = _agent([_calls(("c1", "get_balance", {"account": "a-1"}), ("c2", "get_balance", {"account": "a-2"}), ("c3", "fail", {"x": "now"})), "done"])
    log = wl.open(str(tmp_path / "ag.jsonl"))
    audit = WitnessLogAutoGen(log)
    result = asyncio.run(audit.run(agent, task="balances?"))
    assert isinstance(result, TaskResult) and audit.errors == []
    p = _payloads(audit.recorder)
    intents = {v["call_id"]: (i, v) for i, v in p.items() if "args" in v}
    results = {v["call_id"]: v for v in p.values() if "outcome" in v}
    assert set(intents) == set(results) == {"c1", "c2", "c3"}
    for cid in ("c1", "c2"):
        i, v = intents[cid]
        assert v["tool"] == "get_balance" and v["agent"] == "triage" and v["args"]["account"].startswith("a-")
        assert results[cid]["intent_index"] == i and results[cid]["outcome"] == "ok" and "42" in results[cid]["value"]
    assert results["c3"]["outcome"] == "error" and "boom now" in results["c3"]["value"]
    assert log.tree_size() == 6
    _verified(log)


def test_record_wraps_a_stream_unchanged(tmp_path):
    agent = _agent([_calls(("c1", "get_balance", {"account": "a-1"})), "done"])
    log = wl.open(str(tmp_path / "ag.jsonl"))
    audit = WitnessLogAutoGen(log)

    async def go():
        seen = []
        async for ev in audit.record(agent.run_stream(task="go")):
            seen.append(type(ev).__name__)
        return seen

    seen = asyncio.run(go())
    assert "ToolCallRequestEvent" in seen and "ToolCallExecutionEvent" in seen and seen[-1] == "TaskResult"
    assert log.tree_size() == 2


def test_handoff_between_journals(tmp_path):
    agent = _agent([_calls(("c1", "get_balance", {"account": "a-1"})), _calls(("h1", "transfer_to_billing", {}))], handoffs=[Handoff(target="billing")])
    j = AgentJournals(str(tmp_path / "audit"))
    audit = WitnessLogAutoGen(j)
    result = asyncio.run(audit.run(agent, task="bill me"))
    assert type(result.messages[-1]).__name__ == "HandoffMessage" and audit.errors == []
    assert sorted(j.names()) == ["billing", "triage"]
    t = json.loads(j.log("triage").leaves_json())
    b = json.loads(j.log("billing").leaves_json())
    # get_balance pair, transfer_to_billing tool pair, then handoff intent / Sent / result
    assert [l["leaf_type"] for l in t] == [1, 2, 1, 2, 1, 5, 2]
    assert [l["leaf_type"] for l in b] == [5] and b[0]["handoff_direction"] == "Received"
    assert wl.verify_handoff_binding(j.identity("triage"), json.dumps(t[5]), j.identity("billing"), json.dumps(b[0])) is True
    tp = _payloads(j.recorder("triage"))
    assert tp[4]["tool"] == "handoff" and tp[6]["handoff_to"] == "billing" and tp[6]["sent_leaf"] == 5 and tp[6]["received_leaf"] == 0
    docs = j.export_dossiers(write=False)
    assert bind_dossiers(docs["triage"], docs["billing"])["exit"] == 0
    for n in j.names():
        _verified(j.log(n))
    j.close()
