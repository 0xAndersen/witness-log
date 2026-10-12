"""pydantic-ai adapter against the installed pydantic-ai: an Agent driven
by its FunctionModel, parallel tool calls, ModelRetry and a tool that
raises, through a WitnessLogToolset-wrapped FunctionToolset."""

from __future__ import annotations

import json

import pytest

import witness_log as wl

pytest.importorskip("pydantic_ai")

from pydantic_ai import Agent, ModelRetry  # noqa: E402
from pydantic_ai.messages import ModelResponse, TextPart, ToolCallPart  # noqa: E402
from pydantic_ai.models.function import AgentInfo, FunctionModel  # noqa: E402
from pydantic_ai.toolsets import FunctionToolset  # noqa: E402

from witness_log.integrations import AgentJournals  # noqa: E402
from witness_log.integrations.pydantic_ai import WitnessLogToolset  # noqa: E402


def get_balance(account: str) -> dict:
    """Return an account balance."""
    return {"account": account, "balance": 42}


def flaky(x: str) -> str:
    """Asks the model to retry once, then succeeds."""
    if x == "first":
        raise ModelRetry("try again with x='second'")
    return "ok " + x


def explode(x: str) -> str:
    """Always fails."""
    raise RuntimeError("boom " + x)


def _model(script):
    steps = list(script)

    def fn(messages, info: AgentInfo) -> ModelResponse:
        step = steps.pop(0)
        if isinstance(step, str):
            return ModelResponse(parts=[TextPart(step)])
        return ModelResponse(parts=[ToolCallPart(name, args, tool_call_id=cid) for name, args, cid in step])

    return FunctionModel(fn)


def _payloads(rec):
    return {i: json.loads(p) for i, p in rec.payloads.items()}


def _verified(log):
    rep = json.loads(wl.verify_dossier_json(log.to_dossier_json(), 0.66, log.identity_pubkey_hex()))
    assert rep["internally_consistent"], rep


def test_parallel_calls_and_retry(tmp_path):
    log = wl.open(str(tmp_path / "pai.jsonl"))
    ts = WitnessLogToolset(FunctionToolset([get_balance, flaky]), log)
    model = _model(
        [
            [("get_balance", {"account": "a-1"}, "c1"), ("get_balance", {"account": "a-2"}, "c2"), ("flaky", {"x": "first"}, "c3")],
            [("flaky", {"x": "second"}, "c4")],
            "done",
        ]
    )
    agent = Agent(model, name="ops", toolsets=[ts])
    r = agent.run_sync("balances?")
    assert r.output == "done" and ts.errors == []
    p = _payloads(ts.recorder)
    intents = {v["call_id"]: (i, v) for i, v in p.items() if "args" in v}
    results = {v["call_id"]: v for v in p.values() if "outcome" in v}
    assert set(intents) == set(results) == {"c1", "c2", "c3", "c4"}
    for cid in ("c1", "c2"):
        i, v = intents[cid]
        assert v["tool"] == "get_balance" and v["agent"] == "ops"
        assert results[cid]["intent_index"] == i and results[cid]["value"] == {"account": v["args"]["account"], "balance": 42}
    assert results["c3"]["outcome"] == "error" and results["c3"]["retry"] is True and "try again" in results["c3"]["value"]
    assert results["c4"]["outcome"] == "ok" and results["c4"]["value"] == "ok second"
    assert log.tree_size() == 8
    _verified(log)


def test_tool_exception_is_recorded_and_re_raised(tmp_path):
    log = wl.open(str(tmp_path / "pai.jsonl"))
    ts = WitnessLogToolset(FunctionToolset([explode]), log)
    agent = Agent(_model([[("explode", {"x": "now"}, "e1")], "never"]), name="ops", toolsets=[ts])
    with pytest.raises(RuntimeError):
        agent.run_sync("go")
    p = _payloads(ts.recorder)
    assert [v["tool"] for v in p.values()] == ["explode", "explode"]
    assert p[1]["outcome"] == "error" and p[1]["intent_index"] == 0 and "boom now" in p[1]["value"]
    _verified(log)


def test_journals_select_by_agent_name_and_target_is_required(tmp_path):
    with pytest.raises(TypeError):
        WitnessLogToolset(FunctionToolset([get_balance]))
    j = AgentJournals(str(tmp_path / "audit"))
    ts = WitnessLogToolset(FunctionToolset([get_balance]), j)
    agent = Agent(_model([[("get_balance", {"account": "a-1"}, "c1")], "done"]), name="billing", toolsets=[ts])
    assert agent.run_sync("go").output == "done"
    assert j.names() == ["billing"] and j.log("billing").tree_size() == 2
    assert _payloads(j.recorder("billing"))[0]["agent"] == "billing"
    j.close()
