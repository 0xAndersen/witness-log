"""LangGraph adapter against the installed langgraph: a StateGraph with a
ToolNode, parallel tool calls, a failing tool, and ``Command(goto=...)``
handoffs from a tool and from a node."""

from __future__ import annotations

import json
from typing import Annotated

import pytest

import witness_log as wl

pytest.importorskip("langgraph")
pytest.importorskip("langchain_core")

from langchain_core.messages import AIMessage, HumanMessage, ToolMessage  # noqa: E402
from langchain_core.tools import InjectedToolCallId, tool  # noqa: E402
from langgraph.graph import END, START, MessagesState, StateGraph  # noqa: E402
from langgraph.prebuilt import ToolNode  # noqa: E402
from langgraph.types import Command  # noqa: E402

from witness_log.integrations import AgentJournals  # noqa: E402
from witness_log.integrations.langgraph import WitnessLogGraphHandler  # noqa: E402
from witness_log.profiles.ap2 import bind_dossiers  # noqa: E402


@tool
def get_balance(account: str) -> str:
    """Return an account balance."""
    return f"{account}: 42"


@tool
def fail(x: str) -> str:
    """Always fails."""
    raise ValueError("boom " + x)


@tool
def transfer_to_billing(tool_call_id: Annotated[str, InjectedToolCallId]) -> Command:
    """Hand the conversation to the billing agent."""
    return Command(goto="billing", update={"messages": [ToolMessage("transferred", tool_call_id=tool_call_id)]})


def _graph(handoff_from_node: bool = False):
    def triage(state):
        calls = [
            {"name": "get_balance", "args": {"account": "a-1"}, "id": "c1"},
            {"name": "get_balance", "args": {"account": "a-2"}, "id": "c2"},
            {"name": "fail", "args": {"x": "now"}, "id": "c3"},
        ]
        if not handoff_from_node:
            calls.append({"name": "transfer_to_billing", "args": {}, "id": "c4"})
        return {"messages": [AIMessage(content="", tool_calls=calls)]}

    def route(state):
        # Node-level handoff: the node itself returns a Command.
        return Command(goto="billing", update={"messages": [AIMessage(content="routing")]})

    def billing(state):
        return {"messages": [AIMessage(content="billing done")]}

    g = StateGraph(MessagesState)
    g.add_node("triage", triage)
    g.add_node("tools", ToolNode([get_balance, fail, transfer_to_billing], handle_tool_errors=True))
    g.add_node("billing", billing)
    g.add_edge(START, "triage")
    g.add_edge("triage", "tools")
    if handoff_from_node:
        g.add_node("route", route)
        g.add_edge("tools", "route")
    g.add_edge("billing", END)
    return g.compile()


def _payloads(rec):
    return {i: json.loads(p) for i, p in rec.payloads.items()}


def _verified(log):
    rep = json.loads(wl.verify_dossier_json(log.to_dossier_json(), 0.66, log.identity_pubkey_hex()))
    assert rep["internally_consistent"], rep


def test_single_log_tool_calls_errors_and_tool_handoff(tmp_path):
    log = wl.open(str(tmp_path / "graph.jsonl"))
    h = WitnessLogGraphHandler(log)
    out = _graph().invoke({"messages": [HumanMessage("hi")]}, config={"callbacks": [h]})
    assert out["messages"][-1].content == "billing done" and h.errors == []
    p = _payloads(h.recorder)
    intents = {v["run_id"]: (i, v) for i, v in p.items() if "args" in v}
    results = {v["run_id"]: v for i, v in p.items() if "outcome" in v}
    assert len(intents) == len(results) == 4 and set(intents) == set(results)
    by_tool = {}
    for rid, (i, v) in intents.items():
        r = results[rid]
        assert r["intent_index"] == i and r["tool"] == v["tool"] and v["node"] == "tools"
        by_tool.setdefault(v["tool"], []).append((v, r))
    accounts = sorted(v["args"]["account"] for v, _ in by_tool["get_balance"])
    assert accounts == ["a-1", "a-2"]
    assert all(r["outcome"] == "ok" and r["value"] == f"{v['args']['account']}: 42" for v, r in by_tool["get_balance"])
    (_, fr), = by_tool["fail"]
    assert fr["outcome"] == "error" and "boom now" in fr["value"]
    (_, hr), = by_tool["transfer_to_billing"]
    assert hr["outcome"] == "ok" and hr["handoff_to"] == "billing" and "handoff_leaves" not in hr
    assert hr["value"]["command"]["goto"] == ["billing"]
    assert log.tree_size() == 8
    _verified(log)


def test_journals_per_node_with_handoff_attestations(tmp_path):
    j = AgentJournals(str(tmp_path / "audit"))
    h = WitnessLogGraphHandler(j)
    out = _graph().invoke({"messages": [HumanMessage("hi")]}, config={"callbacks": [h]})
    assert out["messages"][-1].content == "billing done" and h.errors == []
    # Tools ran in node "tools"; the handoff goes tools -> billing.
    assert sorted(j.names()) == ["billing", "tools"]
    tools_leaves = json.loads(j.log("tools").leaves_json())
    billing_leaves = json.loads(j.log("billing").leaves_json())
    assert [l["leaf_type"] for l in billing_leaves] == [5] and billing_leaves[0]["handoff_direction"] == "Received"
    sent = [l for l in tools_leaves if l["leaf_type"] == 5]
    assert len(sent) == 1 and sent[0]["handoff_direction"] == "Sent"
    assert wl.verify_handoff_binding(j.identity("tools"), json.dumps(sent[0]), j.identity("billing"), json.dumps(billing_leaves[0])) is None
    hr = [v for v in _payloads(j.recorder("tools")).values() if v.get("tool") == "transfer_to_billing" and "outcome" in v][0]
    assert hr["handoff_leaves"] == [{"to": "billing", "sent_leaf": sent[0]["index"], "received_leaf": 0}]
    docs = j.export_dossiers()
    for n in j.names():
        _verified(j.log(n))
    assert bind_dossiers(docs["tools"], docs["billing"])["exit"] == 0
    j.close()


def test_node_level_command_is_a_handoff(tmp_path):
    j = AgentJournals(str(tmp_path / "audit"))
    h = WitnessLogGraphHandler(j)
    out = _graph(handoff_from_node=True).invoke({"messages": [HumanMessage("hi")]}, config={"callbacks": [h]})
    assert out["messages"][-1].content == "billing done" and h.errors == []
    assert sorted(j.names()) == ["billing", "route", "tools"]
    route = _payloads(j.recorder("route"))
    assert [v["tool"] for v in route.values()] == ["handoff", "handoff"]
    assert route[0]["args"] == {"from": "route", "to": "billing"}
    assert [l["leaf_type"] for l in json.loads(j.log("route").leaves_json())] == [1, 5, 2]
    assert [l["leaf_type"] for l in json.loads(j.log("billing").leaves_json())] == [5]
    docs = j.export_dossiers(write=False)
    assert bind_dossiers(docs["route"], docs["billing"])["exit"] == 0
    j.close()
