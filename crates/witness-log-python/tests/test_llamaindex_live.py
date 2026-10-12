"""LlamaIndex adapter against the installed llama-index-core: an
AgentWorkflow of FunctionAgents driven by MockFunctionCallingLLM, with
parallel tool calls, a failing tool and a ``handoff``; and the
instrumentation span handler on direct FunctionTool calls."""

from __future__ import annotations

import asyncio
import json

import pytest

import witness_log as wl

pytest.importorskip("llama_index.core")

from llama_index.core.agent.workflow import AgentWorkflow, FunctionAgent  # noqa: E402
from llama_index.core.base.llms.types import ToolCallBlock  # noqa: E402
from llama_index.core.instrumentation import get_dispatcher  # noqa: E402
from llama_index.core.llms import ChatMessage, MessageRole  # noqa: E402
from llama_index.core.llms.mock import MockFunctionCallingLLM  # noqa: E402
from llama_index.core.tools import FunctionTool  # noqa: E402

from witness_log.integrations import AgentJournals  # noqa: E402
from witness_log.integrations.llamaindex import WitnessLogLlamaIndex, WitnessLogSpanHandler  # noqa: E402
from witness_log.profiles.ap2 import bind_dossiers  # noqa: E402


def get_balance(account: str) -> dict:
    """Return a balance."""
    return {"account": account, "balance": 42}


def fail(x: str) -> str:
    """Always fails."""
    raise ValueError("boom " + x)


def _llm(script):
    steps = list(script)

    def gen(messages, **kw):
        step = steps.pop(0)
        if isinstance(step, str):
            return ChatMessage(role=MessageRole.ASSISTANT, content=step)
        return ChatMessage(role=MessageRole.ASSISTANT, blocks=[ToolCallBlock(tool_call_id=cid, tool_name=n, tool_kwargs=a) for cid, n, a in step])

    return MockFunctionCallingLLM(response_generator=gen)


def _payloads(rec):
    return {i: json.loads(p) for i, p in rec.payloads.items()}


def _verified(log):
    rep = json.loads(wl.verify_dossier_json(log.to_dossier_json(), 0.66, log.identity_pubkey_hex()))
    assert rep["internally_consistent"], rep


def _workflow(with_handoff: bool):
    triage_script = [[("c1", "get_balance", {"account": "a-1"}), ("c2", "get_balance", {"account": "a-2"}), ("c3", "fail", {"x": "now"})]]
    if with_handoff:
        triage_script.append([("h1", "handoff", {"to_agent": "billing", "reason": "money"})])
    else:
        triage_script.append("done")
    tools = [FunctionTool.from_defaults(fn=get_balance), FunctionTool.from_defaults(fn=fail)]
    triage = FunctionAgent(name="triage", description="routes", llm=_llm(triage_script), tools=tools, can_handoff_to=["billing"] if with_handoff else [])
    agents = [triage]
    if with_handoff:
        agents.append(FunctionAgent(name="billing", description="bills", llm=_llm(["billing done"]), tools=[]))
    return AgentWorkflow(agents=agents, root_agent="triage")


def test_workflow_tool_calls_and_error_in_one_log(tmp_path):
    log = wl.open(str(tmp_path / "li.jsonl"))
    audit = WitnessLogLlamaIndex(log)
    result = asyncio.run(audit.run(_workflow(with_handoff=False), user_msg="balances?"))
    assert str(result) == "done" and audit.errors == []
    p = _payloads(audit.recorder)
    intents = {v["call_id"]: (i, v) for i, v in p.items() if "args" in v}
    results = {v["call_id"]: v for v in p.values() if "outcome" in v}
    assert set(intents) == set(results) == {"c1", "c2", "c3"}
    for cid in ("c1", "c2"):
        i, v = intents[cid]
        assert v["tool"] == "get_balance" and v["agent"] == "triage"
        assert results[cid]["intent_index"] == i and results[cid]["outcome"] == "ok"
        assert results[cid]["value"] == {"account": v["args"]["account"], "balance": 42}
    assert results["c3"]["outcome"] == "error" and "boom now" in results["c3"]["value"]
    assert log.tree_size() == 6
    _verified(log)


def test_record_wraps_the_event_stream(tmp_path):
    log = wl.open(str(tmp_path / "li.jsonl"))
    audit = WitnessLogLlamaIndex(log)

    async def go():
        handler = _workflow(with_handoff=False).run(user_msg="go")
        names = [type(ev).__name__ async for ev in audit.record(handler.stream_events())]
        return names, await handler

    names, result = asyncio.run(go())
    assert "ToolCall" in names and "ToolCallResult" in names and str(result) == "done"
    assert log.tree_size() == 6


def test_handoff_between_journals(tmp_path):
    j = AgentJournals(str(tmp_path / "audit"))
    audit = WitnessLogLlamaIndex(j)
    result = asyncio.run(audit.run(_workflow(with_handoff=True), user_msg="bill me"))
    assert str(result) == "billing done" and audit.errors == []
    assert sorted(j.names()) == ["billing", "triage"]
    t = json.loads(j.log("triage").leaves_json())
    b = json.loads(j.log("billing").leaves_json())
    # three tool pairs, then handoff intent / Sent / result
    assert [l["leaf_type"] for l in t][-3:] == [1, 5, 2] and len(t) == 9
    assert [l["leaf_type"] for l in b] == [5] and b[0]["handoff_direction"] == "Received"
    sent = t[-2]
    assert wl.verify_handoff_binding(j.identity("triage"), json.dumps(sent), j.identity("billing"), json.dumps(b[0])) is True
    tp = _payloads(j.recorder("triage"))
    res = tp[t[-1]["index"]]
    assert res["tool"] == "handoff" and res["handoff_to"] == "billing" and res["sent_leaf"] == sent["index"] and res["received_leaf"] == 0
    assert tp[t[-3]["index"]]["args"] == {"to_agent": "billing", "reason": "money"}
    docs = j.export_dossiers(write=False)
    assert bind_dossiers(docs["triage"], docs["billing"])["exit"] == 0
    for n in j.names():
        _verified(j.log(n))
    j.close()


def test_span_handler_records_direct_tool_calls(tmp_path):
    log = wl.open(str(tmp_path / "spans.jsonl"))
    h = WitnessLogSpanHandler(log)
    get_dispatcher().add_span_handler(h)
    try:
        tool = FunctionTool.from_defaults(fn=get_balance)
        out = tool.call(account="a-7")
        assert out.raw_output == {"account": "a-7", "balance": 42}
        bad = FunctionTool.from_defaults(fn=fail)
        with pytest.raises(ValueError):  # the span is dropped with the exception
            asyncio.run(bad.acall(x="now"))
    finally:
        get_dispatcher().span_handlers.remove(h)
    p = _payloads(h.recorder)
    assert [v["tool"] for v in p.values()] == ["get_balance", "get_balance", "fail", "fail"]
    assert p[0]["args"] == {"account": "a-7"} and p[1]["outcome"] == "ok" and p[1]["value"] == {"account": "a-7", "balance": 42}
    assert p[3]["outcome"] == "error" and "boom now" in str(p[3]["value"])
    assert h.errors == []
    _verified(log)
