"""OpenAI Agents SDK adapter against the installed SDK, driven by its own
``agents.testing.ScriptedModel``. Skipped when the SDK is not installed;
the ``frameworks-live`` workflow installs the latest release and fails if
anything here is skipped."""

from __future__ import annotations

import asyncio
import json
import os

import pytest

import witness_log as wl

agents = pytest.importorskip("agents")
testing = pytest.importorskip("agents.testing")

from agents import Agent, Runner, function_tool, set_trace_processors, set_tracing_disabled  # noqa: E402
from agents.testing import ScriptedModel, assistant_message, function_call  # noqa: E402

from witness_log.integrations.openai_agents import WitnessLogAudit, WitnessLogHooks  # noqa: E402


@pytest.fixture(autouse=True)
def _no_trace_export():
    # Real spans (the adapter reads the function span's error) but nothing
    # leaves the process. Restored to disabled afterwards.
    set_trace_processors([])
    set_tracing_disabled(False)
    yield
    set_tracing_disabled(True)
    set_trace_processors([])


def _leaves(log):
    return json.loads(log.leaves_json())


def _verify(log):
    rep = json.loads(wl.verify_dossier_json(log.to_dossier_json(), 0.66, log.identity_pubkey_hex()))
    assert rep["internally_consistent"], rep
    return rep


def _payloads(rec):
    return {i: json.loads(p) for i, p in rec.payloads.items()}


@function_tool
def get_balance(account: str) -> dict:
    """Get a balance."""
    return {"account": account, "balance": 42}


@function_tool
def explode(x: str) -> str:
    """Always fails."""
    raise ValueError("boom " + x)


def test_parallel_calls_of_one_tool_are_paired_by_call_id(tmp_path):
    model = ScriptedModel(
        [
            [function_call("get_balance", {"account": "a-1"}, call_id="c1"),
             function_call("get_balance", {"account": "a-2"}, call_id="c2")],
            [assistant_message("done")],
        ]
    )
    log = wl.open(str(tmp_path / "agent.jsonl"))
    hooks = WitnessLogHooks(log)
    agent = Agent(name="a", instructions="x", tools=[get_balance], model=model)
    r = asyncio.run(Runner.run(agent, "balances?", hooks=hooks))  # no context= needed
    assert r.final_output == "done" and hooks.errors == []
    model.assert_complete()
    leaves = _leaves(log)
    assert [l["leaf_type"] for l in leaves] == [1, 1, 2, 2] or sorted(l["leaf_type"] for l in leaves) == [1, 1, 2, 2]
    p = _payloads(hooks.recorder)
    intents = {p[i]["call_id"]: (i, p[i]) for i in p if "args" in p[i]}
    results = {p[i]["call_id"]: p[i] for i in p if "outcome" in p[i]}
    assert set(intents) == set(results) == {"c1", "c2"}
    # Each result points at its own intent, and the real arguments are recorded.
    for cid, acct in (("c1", "a-1"), ("c2", "a-2")):
        idx, intent = intents[cid]
        assert intent["tool"] == "get_balance" and intent["args"] == {"account": acct} and intent["agent"] == "a"
        assert results[cid]["intent_index"] == idx and results[cid]["outcome"] == "ok"
        assert results[cid]["value"] == {"account": acct, "balance": 42}
    _verify(log)


def test_tool_error_is_recorded_as_error_not_ok(tmp_path):
    # The SDK replaces the exception with a fixed string before on_tool_end;
    # the span carries the real error. The result leaf must say "error".
    model = ScriptedModel([[function_call("explode", {"x": "now"}, call_id="e1")], [assistant_message("done")]])
    log = wl.open(str(tmp_path / "agent.jsonl"))
    hooks = WitnessLogHooks(log)
    agent = Agent(name="a", instructions="x", tools=[explode], model=model)
    r = asyncio.run(Runner.run(agent, "go", hooks=hooks))
    assert r.final_output == "done" and hooks.errors == []
    res = [v for v in _payloads(hooks.recorder).values() if "outcome" in v]
    assert len(res) == 1 and res[0]["outcome"] == "error", res
    assert res[0]["error"]["message"] == "Error running tool (non-fatal)"
    assert res[0]["error"]["data"]["tool_name"] == "explode"
    assert isinstance(res[0]["value"], str)  # the SDK's replacement text, kept as the value
    _verify(log)


def test_tool_error_detected_with_tracing_disabled(tmp_path):
    set_tracing_disabled(True)
    model = ScriptedModel([[function_call("explode", {"x": "now"}, call_id="e1")], [assistant_message("done")]])
    log = wl.open(str(tmp_path / "agent.jsonl"))
    hooks = WitnessLogHooks(log)
    agent = Agent(name="a", instructions="x", tools=[explode], model=model)
    asyncio.run(Runner.run(agent, "go", hooks=hooks))
    res = [v for v in _payloads(hooks.recorder).values() if "outcome" in v]
    assert res[0]["outcome"] == "error"


def test_tool_raising_through_is_completed_by_the_processor(tmp_path):
    @function_tool(failure_error_function=None)
    def raise_through(x: str) -> str:
        """Fails and lets the exception propagate."""
        raise RuntimeError("fatal " + x)

    model = ScriptedModel([[function_call("raise_through", {"x": "1"}, call_id="r1")], [assistant_message("never")]])
    log = wl.open(str(tmp_path / "agent.jsonl"))
    hooks = WitnessLogHooks(log)
    set_trace_processors([hooks.processor()])
    agent = Agent(name="a", instructions="x", tools=[raise_through], model=model)
    with pytest.raises(Exception) as ei:  # the SDK wraps it (UserError in 0.23); either way it propagates
        asyncio.run(Runner.run(agent, "go", hooks=hooks))
    assert "fatal 1" in str(ei.value) or isinstance(ei.value, RuntimeError)
    p = _payloads(hooks.recorder)
    assert [v["tool"] for v in p.values()] == ["raise_through", "raise_through"]
    res = [v for v in p.values() if "outcome" in v][0]
    assert res["outcome"] == "error" and res["intent_index"] == 0 and res["call_id"] == "r1"
    assert res["error"]["message"] in ("Error running tool", "Error running tool (non-fatal)") or "error" in res["error"]["message"].lower()
    assert hooks.errors == []
    _verify(log)


def test_audit_one_journal_per_agent_with_handoff(tmp_path):
    seeds = {}

    def seed_for(name: str) -> bytes:
        return seeds.setdefault(name, os.urandom(32))

    triage_model = ScriptedModel([[function_call("transfer_to_billing", {}, call_id="h1")]])
    billing_model = ScriptedModel([[function_call("get_balance", {"account": "a-9"}, call_id="b1")], [assistant_message("paid")]])
    billing = Agent(name="billing", instructions="x", tools=[get_balance], model=billing_model)
    triage = Agent(name="triage", instructions="x", handoffs=[billing], model=triage_model)

    audit = WitnessLogAudit(str(tmp_path / "audit"), seed_for=seed_for, sealed=True)
    set_trace_processors([audit.processor()])
    r = asyncio.run(Runner.run(triage, "bill me", hooks=audit.hooks))
    assert r.final_output == "paid" and audit.errors == []
    triage_model.assert_complete()
    billing_model.assert_complete()

    tl, bl = audit.log("triage"), audit.log("billing")
    assert sorted(audit.journals.names()) == ["billing", "triage"]
    t_leaves, b_leaves = _leaves(tl), _leaves(bl)
    # triage: handoff intent, Sent attestation, handoff result.
    assert [l["leaf_type"] for l in t_leaves] == [1, 5, 2]
    assert t_leaves[1]["handoff_direction"] == "Sent" and t_leaves[1]["counterparty_pubkey"] == bl.identity_pubkey_hex()
    # billing: Received attestation, then the tool pair.
    assert [l["leaf_type"] for l in b_leaves] == [5, 1, 2]
    assert b_leaves[0]["handoff_direction"] == "Received" and b_leaves[0]["counterparty_pubkey"] == tl.identity_pubkey_hex()
    assert wl.verify_handoff_binding(tl.identity_pubkey_hex(), json.dumps(t_leaves[1]), bl.identity_pubkey_hex(), json.dumps(b_leaves[0])) is True
    tp = _payloads(audit.journals.recorder("triage"))
    assert tp[0]["tool"] == "handoff" and tp[0]["args"] == {"from": "triage", "to": "billing"}
    assert tp[2]["handoff_to"] == "billing" and tp[2]["sent_leaf"] == 1 and tp[2]["received_leaf"] == 0
    bp = _payloads(audit.journals.recorder("billing"))
    assert bp[1]["tool"] == "get_balance" and bp[1]["agent"] == "billing" and bp[2]["outcome"] == "ok"

    # Dossiers: one per agent, each verifies pinned to its identity; the
    # Python bind reproduces `witness-log bind`.
    docs = audit.export_dossiers()
    assert set(docs) == {"billing", "triage"}
    for name, doc in docs.items():
        rep = json.loads(wl.verify_dossier_json(doc, 0.66, audit.log(name).identity_pubkey_hex()))
        assert rep["internally_consistent"]
        assert (tmp_path / "audit" / f"{name}.dossier.json").read_text() == doc
    from witness_log.profiles.ap2 import bind_dossiers

    rep = bind_dossiers(docs["triage"], docs["billing"])
    assert rep["exit"] == 0 and rep["bound"][0]["kind"] == "handoff"

    # Disclosure and forgetting on the billing journal.
    d = audit.disclose(1, "billing")
    assert d["complete"] and d["verified"] is True and json.loads(d["payload"])["args"] == {"account": "a-9"}
    with pytest.raises(ValueError):
        audit.disclose(1)  # two journals: agent= is required
    assert audit.forget(1, "billing") is True
    d2 = audit.disclose(1, "billing")
    assert not d2["complete"] and "payload" not in d2
    _verify(bl)

    # Sealed: no seed in the header, and resume needs the seed.
    header = json.loads((tmp_path / "audit" / "billing.jsonl").read_text().splitlines()[0])
    assert "identity_bytes_hex" not in header or not header.get("identity_bytes_hex")
    billing_id = bl.identity_pubkey_hex()
    audit.close()
    with pytest.raises(Exception):
        wl.open(str(tmp_path / "audit" / "billing.jsonl"))
    again = wl.open(str(tmp_path / "audit" / "billing.jsonl"), seeds["billing"], seal=True)
    assert again.identity_pubkey_hex() == billing_id and again.tree_size() == 4  # + the redaction leaf
    again.close()


def test_audit_without_seed_for_is_unsealed(tmp_path):
    with pytest.raises(ValueError):
        WitnessLogAudit(str(tmp_path / "x"), sealed=True)
    audit = WitnessLogAudit(str(tmp_path / "audit"))
    model = ScriptedModel([[function_call("get_balance", {"account": "a"}, call_id="c")], [assistant_message("ok")]])
    agent = Agent(name="solo agent", instructions="x", tools=[get_balance], model=model)
    asyncio.run(Runner.run(agent, "go", hooks=audit.hooks))
    assert audit.journals.names() == ["solo agent"]
    assert (tmp_path / "audit" / "solo_agent.jsonl").exists()
    assert audit.disclose(0)["verified"] is True  # one journal: agent= optional
    audit.close()
    resumed = wl.open(str(tmp_path / "audit" / "solo_agent.jsonl"))
    assert resumed.tree_size() == 2
