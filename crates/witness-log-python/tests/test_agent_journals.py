"""``witness_log.integrations.AgentJournals`` / ``Sink`` / ``Recorder``
without any framework: one journal per agent, handoffs on both sides,
kept payloads, disclosure, forgetting, resume."""

from __future__ import annotations

import json
import os
import threading

import pytest

import witness_log as wl
from witness_log.integrations import AgentJournals, Recorder, Sink, handoff_state
from witness_log.profiles.ap2 import bind_dossiers


def test_recorder_keeps_payloads_and_pairs_results(tmp_path):
    log = wl.open(str(tmp_path / "a.jsonl"))
    rec = Recorder(log)
    i = rec.intent("search", {"q": "x"}, call_id="c1")
    j = rec.result("search", i, {"hits": 3}, call_id="c1")
    assert (i, j) == (0, 1) and rec.errors == []
    assert json.loads(rec.payloads[0])["args"] == {"q": "x"} and json.loads(rec.payloads[1])["intent_index"] == 0
    rec2 = Recorder(log, keep_payloads=False, record_output=False)
    k = rec2.result("search", None, {"big": "output"})
    assert k == 2 and rec2.payloads == {} and "value" not in json.loads(wl.canonical_json({}))  # sanity
    log.close()
    # Append failures are kept, not raised, unless asked.
    rec3 = Recorder(log)
    assert rec3.intent("x", {}) is None and rec3.errors and "closed" in rec3.errors[0]
    with pytest.raises(OSError):
        Recorder(log, raise_on_error=True).intent("x", {})


def test_journals_handoff_binds_and_resumes(tmp_path):
    seeds = {}
    j = AgentJournals(str(tmp_path / "audit"), seed_for=lambda n: seeds.setdefault(n, os.urandom(32)))
    assert j.sealed is True
    j.recorder("a").intent("t", {})
    state = handoff_state("a", "b", seq=1)
    sent, recv = j.handoff("a", "b", state)
    assert (sent, recv) == (1, 0)
    j.recorder("b").intent("u", {})
    j.recorder("b").result("u", 1, "ok")
    assert sorted(j.names()) == ["a", "b"] and j.errors == []
    docs = j.export_dossiers()
    rep = bind_dossiers(docs["a"], docs["b"])
    assert rep["exit"] == 0 and rep["bound"][0] == {
        "kind": "handoff", "sender": j.identity("a"), "sender_leaf": 1, "receiver": j.identity("b"), "receiver_leaf": 0,
        "state_hash": json.loads(docs["a"])["leaves"][1]["handoff_state_hash"],
    }
    assert os.path.exists(tmp_path / "audit" / "a.dossier.json")
    ids = {n: j.identity(n) for n in j.names()}
    j.close()
    # Sealed journals resume with the same identities when the seeds are supplied.
    j2 = AgentJournals(str(tmp_path / "audit"), seed_for=lambda n: seeds[n])
    assert j2.identity("a") == ids["a"] and j2.log("b").tree_size() == 3
    j2.close()


def test_journals_unsealed_default_and_bad_arguments(tmp_path):
    with pytest.raises(ValueError):
        AgentJournals(str(tmp_path / "x"), sealed=True)
    j = AgentJournals(str(tmp_path / "audit"))
    assert j.sealed is False
    j.recorder("ops/agent 1").intent("t", {})
    assert j.path("ops/agent 1").endswith("ops_agent_1.jsonl") and os.path.exists(j.path("ops/agent 1"))
    with pytest.raises(IndexError):
        j.disclose(5)
    d = j.disclose(0)
    assert d["verified"] is True
    assert j.forget(0) and j.forget(0) is False
    assert not j.disclose(0)["complete"]
    j.close()


def test_journals_handoff_failure_is_kept_not_raised(tmp_path):
    j = AgentJournals(str(tmp_path / "audit"))
    j.log("a").close()
    assert j.handoff("a", "b", b"s") == (None, None)
    assert any("handoff a->b" in e for e in j.errors)
    j2 = AgentJournals(str(tmp_path / "audit2"), raise_on_error=True)
    j2.log("a").close()
    with pytest.raises(OSError):
        j2.handoff("a", "b", b"s")


def test_journals_are_thread_safe(tmp_path):
    j = AgentJournals(str(tmp_path / "audit"))

    def work(n):
        rec = j.recorder("a" if n % 2 else "b")
        for k in range(20):
            i = rec.intent("t", {"n": n, "k": k})
            rec.result("t", i, k)

    ts = [threading.Thread(target=work, args=(n,)) for n in range(8)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    assert j.errors == []
    assert j.log("a").tree_size() == 4 * 40 and j.log("b").tree_size() == 4 * 40
    for n in j.names():
        rep = json.loads(wl.verify_dossier_json(j.log(n).to_dossier_json(), 0.66, j.identity(n)))
        assert rep["internally_consistent"]
    j.close()


def test_sink_single_log_vs_journals(tmp_path):
    log = wl.open(str(tmp_path / "one.jsonl"))
    s = Sink(log)
    assert s.recorder("anything") is s.recorder("else")
    assert s.handoff("a", "b", b"x") == (None, None)  # no counterparty identity in one log
    s.recorder().intent("t", {})
    assert 0 in s.payloads and s.errors == []
    j = AgentJournals(str(tmp_path / "audit"))
    s2 = Sink(j)
    assert s2.recorder("a") is not s2.recorder("b")
    with pytest.raises(AttributeError):
        s2.payloads
    j.close()
