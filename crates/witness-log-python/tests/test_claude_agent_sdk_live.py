"""Claude Agent SDK adapter against the installed ``claude-agent-sdk``.

Two layers, neither needing a network, an API key or the Claude Code CLI:

* the hook callbacks driven directly with hook inputs built from the SDK's
  own TypedDicts (``PreToolUseHookInput``, ``PostToolUseHookInput``,
  ``PostToolUseFailureHookInput``);
* the SDK's own ``query()`` loop over a scripted stand-in for the CLI: a
  ``Transport`` that speaks the CLI's side of the control protocol
  (answers ``initialize``, sends ``hook_callback`` requests for parallel
  tool calls, reads the SDK's answers, ends with a ``result``), so the
  callbacks are registered and dispatched by the SDK's ``Query`` exactly as
  in a real run.

Tests that need the SDK are skipped when it is not installed; the
``frameworks-live`` workflow installs the latest release and fails on a
skip. ``test_imports_and_records_without_the_sdk`` runs either way."""

from __future__ import annotations

import asyncio
import importlib
import inspect
import json
import random
import sys
import threading

import pytest

import witness_log as wl
from witness_log import hook
from witness_log.integrations import AgentJournals
from witness_log.integrations.claude_agent_sdk import WitnessLogClaudeHooks, witness_hooks

try:
    import claude_agent_sdk as sdk
except ImportError:  # pragma: no cover - the base CI has no SDK
    sdk = None

needs_sdk = pytest.mark.skipif(sdk is None, reason="claude-agent-sdk is not installed")

CTX = {"signal": None}  # HookContext, as the SDK passes it
BASE = {
    "session_id": "4f1c-session",
    "transcript_path": "/home/u/.claude/projects/-work/4f1c-session.jsonl",
    "cwd": "/work",
    "permission_mode": "default",
}
PRE, POST, FAILURE = "PreToolUse", "PostToolUse", "PostToolUseFailure"


# --- hook inputs, from the SDK's TypedDicts --------------------------------------


def _typed(td, extra, **core):
    """``td(**core)``, failing if the SDK no longer declares a field of the
    shape the adapter relies on, then ``extra``: optional fields a newer
    CLI sends (``duration_ms``, ``prompt_id``, ``agent_type``, ...) that an
    older SDK's TypedDict may not list (it is not checked at run time)."""
    declared = set(td.__required_keys__) | set(td.__optional_keys__)
    unknown = set(core) - declared
    assert not unknown, f"{td.__name__} no longer declares {sorted(unknown)}"
    ev = td(**core)
    ev.update(extra)
    return ev


def pre(tid, name, args, **extra):
    return _typed(sdk.PreToolUseHookInput, extra, **BASE, hook_event_name=PRE, tool_name=name, tool_input=args, tool_use_id=tid)


def post(tid, name, args, response, **extra):
    return _typed(
        sdk.PostToolUseHookInput, {"duration_ms": 12, **extra}, **BASE, hook_event_name=POST, tool_name=name,
        tool_input=args, tool_response=response, tool_use_id=tid,
    )


def failure(tid, name, args, error, **extra):
    return _typed(
        sdk.PostToolUseFailureHookInput, {"is_interrupt": False, "duration_ms": 3, **extra}, **BASE,
        hook_event_name=FAILURE, tool_name=name, tool_input=args, tool_use_id=tid, error=error,
    )


def _mcp_text(text):
    return [{"type": "text", "text": text}]  # an SDK MCP tool's tool_response


async def _call(h, ev):
    fn = {PRE: h.pre_tool_use, POST: h.post_tool_use, FAILURE: h.post_tool_use_failure}[ev["hook_event_name"]]
    return await fn(ev, ev.get("tool_use_id"), CTX)


def _payloads(rec):
    return {i: json.loads(b) for i, b in rec.payloads.items()}


def _pairs(rec):
    p = _payloads(rec)
    intents = {v["tool_use_id"]: i for i, v in p.items() if v["event"] == PRE}
    results = {v["tool_use_id"]: v for v in p.values() if v["event"] != PRE}
    return p, intents, results


def _verified(log):
    rep = json.loads(wl.verify_dossier_json(log.to_dossier_json(), 0.66, log.identity_pubkey_hex()))
    assert rep["internally_consistent"], rep
    return rep


def _types(log):
    return [l["leaf_type"] for l in json.loads(log.leaves_json())]


class BrokenLog:
    """A log whose every append fails."""

    def append_intent(self, data):
        raise OSError("disk full")

    append_result = append_intent


# --- configuration ---------------------------------------------------------------


@needs_sdk
def test_hooks_config_is_what_claude_agent_options_takes(tmp_path):
    log = wl.open(str(tmp_path / "agent.jsonl"))
    h = WitnessLogClaudeHooks(log)
    cfg = h.hooks()
    assert set(cfg) == {PRE, POST, FAILURE}
    for event, fn in ((PRE, h.pre_tool_use), (POST, h.post_tool_use), (FAILURE, h.post_tool_use_failure)):
        (m,) = cfg[event]
        assert isinstance(m, sdk.HookMatcher) and m.matcher is None and m.hooks == [fn] and m.timeout is None
        assert inspect.iscoroutinefunction(fn)
    opts = sdk.ClaudeAgentOptions(hooks=cfg)
    assert opts.hooks is cfg
    only_bash = witness_hooks(log, matcher="Bash", timeout=5)
    assert all(ms[0].matcher == "Bash" and ms[0].timeout == 5 for ms in only_bash.values())


@needs_sdk
def test_options_merges_into_existing_hooks_without_touching_them(tmp_path):
    async def mine(input_data, tool_use_id, context):
        return {}

    h = WitnessLogClaudeHooks(wl.open(str(tmp_path / "agent.jsonl")))
    theirs = sdk.ClaudeAgentOptions(hooks={PRE: [sdk.HookMatcher(matcher="Bash", hooks=[mine])]}, max_turns=3)
    opts = h.options(theirs, model="claude-sonnet-5")
    assert [m.hooks for m in opts.hooks[PRE]] == [[mine], [h.pre_tool_use]]
    assert [m.hooks for m in opts.hooks[POST]] == [[h.post_tool_use]]
    assert opts.max_turns == 3 and opts.model == "claude-sonnet-5"
    assert len(theirs.hooks[PRE]) == 1 and POST not in theirs.hooks  # the original is not modified
    fresh = h.options(allowed_tools=["Read"])
    assert isinstance(fresh, sdk.ClaudeAgentOptions) and fresh.allowed_tools == ["Read"] and set(fresh.hooks) == {PRE, POST, FAILURE}


# --- payloads ----------------------------------------------------------------------


@needs_sdk
def test_one_call_is_an_intent_and_a_result_in_the_claude_code_hook_profile(tmp_path):
    log = wl.open(str(tmp_path / "agent.jsonl"))
    h = WitnessLogClaudeHooks(log)
    args = {"command": "ls -la", "description": "List files"}
    a = pre("toolu_01A", "Bash", args, prompt_id="p-1", effort={"level": "high"})
    b = post("toolu_01A", "Bash", args, {"stdout": "total 0\n", "stderr": "", "interrupted": False, "isImage": False}, prompt_id="p-1")
    assert asyncio.run(_call(h, a)) == {}
    assert asyncio.run(_call(h, b)) == {}
    assert h.errors == [] and _types(log) == [1, 2]

    # Byte for byte what witness-log-hook commits for the same Claude Code event...
    assert h.recorder.payloads[0] == wl.canonical_json(hook.normalize(a)[1])
    # ...and the result is that plus the link to its intent.
    assert h.recorder.payloads[1] == wl.canonical_json({**hook.normalize(b)[1], "intent_index": 0})
    p = _payloads(h.recorder)
    assert p[0] == {
        "profile": "hook.claude-code v1", "event": PRE, "session_id": BASE["session_id"], "tool_name": "Bash",
        "tool_input": args, "tool_use_id": "toolu_01A", "cwd": "/work",
    }
    assert p[1]["tool_response"]["stdout"] == "total 0\n" and p[1]["intent_index"] == 0
    assert all("transcript_path" not in v for v in p.values())

    leaves = json.loads(log.leaves_json())
    for i in (0, 1):  # each leaf discloses: payload + salt recompute its hash
        assert wl.verify_disclosure(leaves[i], h.recorder.payloads[i], log.salt_hex(i))
    _verified(log)


@needs_sdk
def test_failure_is_a_result_carrying_the_error(tmp_path):
    log = wl.open(str(tmp_path / "agent.jsonl"))
    h = WitnessLogClaudeHooks(log)
    args = {"file_path": "/work/missing.py"}
    f = failure("toolu_02", "Read", args, "File does not exist.")
    asyncio.run(_call(h, pre("toolu_02", "Read", args)))
    assert asyncio.run(_call(h, f)) == {}
    assert _types(log) == [1, 2] and h.errors == []
    # The profile's rule for any other event (what `witness-log-hook --kind result` writes), plus the link.
    assert h.recorder.payloads[1] == wl.canonical_json({**hook.normalize(f, "result")[1], "intent_index": 0})
    res = _payloads(h.recorder)[1]
    assert res["event"] == FAILURE and res["error"] == "File does not exist." and res["is_interrupt"] is False
    assert res["tool_use_id"] == "toolu_02" and "transcript_path" not in res
    _verified(log)


@needs_sdk
def test_record_output_false_keeps_tool_response_out_but_errors_in(tmp_path):
    log = wl.open(str(tmp_path / "agent.jsonl"))
    h = WitnessLogClaudeHooks(log, record_output=False)
    for ev in (
        pre("t1", "mcp__crm__lookup", {"email": "a@example.com"}),
        post("t1", "mcp__crm__lookup", {"email": "a@example.com"}, _mcp_text("Alice, VIP")),
        pre("t2", "mcp__crm__lookup", {"email": "b@example.com"}),
        failure("t2", "mcp__crm__lookup", {"email": "b@example.com"}, "not found"),
    ):
        asyncio.run(_call(h, ev))
    p = _payloads(h.recorder)
    assert "tool_response" not in p[1] and p[1]["intent_index"] == 0
    assert p[3]["error"] == "not found" and p[3]["intent_index"] == 2


@needs_sdk
def test_result_without_a_recorded_intent_is_still_recorded(tmp_path):
    log = wl.open(str(tmp_path / "agent.jsonl"))
    h = WitnessLogClaudeHooks(log)
    asyncio.run(_call(h, post("toolu_late", "Grep", {"pattern": "x"}, {"numFiles": 0})))
    assert _types(log) == [2] and _payloads(h.recorder)[0]["intent_index"] is None and h.errors == []


@needs_sdk
def test_tool_use_id_from_the_callback_argument_fills_a_missing_one(tmp_path):
    log = wl.open(str(tmp_path / "agent.jsonl"))
    h = WitnessLogClaudeHooks(log)
    a = {k: v for k, v in pre("toolu_x", "Glob", {"pattern": "*.py"}).items() if k != "tool_use_id"}
    b = {k: v for k, v in post("toolu_x", "Glob", {"pattern": "*.py"}, {"filenames": []}).items() if k != "tool_use_id"}
    asyncio.run(h.pre_tool_use(a, "toolu_x", CTX))
    asyncio.run(h.post_tool_use(b, "toolu_x", CTX))
    p = _payloads(h.recorder)
    assert p[0]["tool_use_id"] == p[1]["tool_use_id"] == "toolu_x" and p[1]["intent_index"] == 0


# --- concurrency ---------------------------------------------------------------------


@needs_sdk
def test_parallel_calls_of_one_tool_pair_by_tool_use_id(tmp_path):
    log = wl.open(str(tmp_path / "agent.jsonl"))
    h = WitnessLogClaudeHooks(log)
    n = 12
    ids = [f"toolu_{k:02d}" for k in range(n)]
    tool = "mcp__billing__get_balance"

    async def run():
        # Every PreToolUse in flight at once, then the results in a different order.
        assert await asyncio.gather(*(_call(h, pre(t, tool, {"account": t})) for t in ids)) == [{}] * n
        done = ids[:]
        random.Random(7).shuffle(done)
        evs = [failure(t, tool, {"account": t}, "timeout") if k % 4 == 0 else post(t, tool, {"account": t}, _mcp_text(f"{t}: 42"))
               for k, t in enumerate(done)]
        assert await asyncio.gather(*(_call(h, ev) for ev in evs)) == [{}] * n

    asyncio.run(run())
    assert h.errors == [] and log.tree_size() == 2 * n
    p, intents, results = _pairs(h.recorder)
    assert set(intents) == set(results) == set(ids)
    for t in ids:
        i = intents[t]
        assert p[i]["tool_input"] == {"account": t}
        assert results[t]["intent_index"] == i and results[t]["tool_input"] == {"account": t}
        assert results[t]["event"] == FAILURE or results[t]["tool_response"] == _mcp_text(f"{t}: 42")
    assert not h._pending  # nothing left waiting for a result
    _verified(log)


@needs_sdk
def test_several_event_loops_in_threads_share_one_hooks_object(tmp_path):
    log = wl.open(str(tmp_path / "agent.jsonl"))
    h = WitnessLogClaudeHooks(log)
    per = 25

    def worker(k):
        async def run():
            ids = [f"t{k}-{j}" for j in range(per)]
            await asyncio.gather(*(_call(h, pre(t, "Read", {"file_path": t})) for t in ids))
            await asyncio.gather(*(_call(h, post(t, "Read", {"file_path": t}, {"file": {"content": t}})) for t in ids))

        asyncio.run(run())

    threads = [threading.Thread(target=worker, args=(k,)) for k in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(30)
    assert h.errors == [] and log.tree_size() == 2 * 4 * per
    p, intents, results = _pairs(h.recorder)
    assert len(intents) == len(results) == 4 * per
    assert all(results[t]["intent_index"] == intents[t] for t in intents)
    _verified(log)


# --- failure policy ------------------------------------------------------------------


@needs_sdk
def test_a_logging_failure_never_raises_and_never_blocks():
    h = WitnessLogClaudeHooks(BrokenLog())
    assert asyncio.run(_call(h, pre("t1", "Bash", {"command": "rm -rf build"}))) == {}
    assert asyncio.run(_call(h, post("t1", "Bash", {"command": "rm -rf build"}, {"stdout": ""}))) == {}
    assert asyncio.run(_call(h, failure("t1", "Bash", {"command": "x"}, "boom"))) == {}
    assert len(h.errors) == 3 and all("disk full" in e for e in h.errors)
    # Input that is not a hook event at all: recorded if possible, never raised.
    assert asyncio.run(h.pre_tool_use(None, None, CTX)) == {}
    assert asyncio.run(h.post_tool_use("garbage", "t9", CTX)) == {}


@needs_sdk
def test_strict_denies_a_call_that_could_not_be_recorded():
    h = WitnessLogClaudeHooks(BrokenLog(), strict=True)
    out = asyncio.run(_call(h, pre("t1", "Bash", {"command": "deploy"})))
    spec = out["hookSpecificOutput"]
    assert spec["hookEventName"] == PRE and spec["permissionDecision"] == "deny"
    assert "disk full" in spec["permissionDecisionReason"]
    assert not h._pending  # a denied call will get no result
    # Results are never blocked (the tool already ran).
    assert asyncio.run(_call(h, post("t2", "Bash", {"command": "ls"}, {"stdout": ""}))) == {}


@needs_sdk
def test_strict_allows_when_the_intent_was_recorded(tmp_path):
    log = wl.open(str(tmp_path / "agent.jsonl"))
    h = WitnessLogClaudeHooks(log, strict=True)
    assert asyncio.run(_call(h, pre("t1", "Bash", {"command": "ls"}))) == {}
    assert _types(log) == [1]


# --- one journal per agent -------------------------------------------------------------


@needs_sdk
def test_agent_journals_select_by_subagent_type(tmp_path):
    j = AgentJournals(str(tmp_path / "audit"))
    h = WitnessLogClaudeHooks(j, agent="lead")
    sub = {"agent_id": "a-7f3", "agent_type": "code-reviewer"}

    async def run():
        await _call(h, pre("m1", "Agent", {"subagent_type": "code-reviewer", "prompt": "review"}))
        await _call(h, pre("s1", "Read", {"file_path": "/work/app.py"}, **sub))
        await _call(h, post("s1", "Read", {"file_path": "/work/app.py"}, {"file": {"content": "x"}}, **sub))
        await _call(h, post("m1", "Agent", {"subagent_type": "code-reviewer", "prompt": "review"}, _mcp_text("LGTM")))

    asyncio.run(run())
    assert h.errors == [] and sorted(j.names()) == ["code-reviewer", "lead"]
    for name, tool in (("lead", "Agent"), ("code-reviewer", "Read")):
        p = _payloads(j.recorder(name))
        assert [v["tool_name"] for v in p.values()] == [tool, tool] and p[1]["intent_index"] == 0
        assert all("agent_type" not in v for v in p.values())  # the profile does not carry it; the journal does
        _verified(j.log(name))
    docs = j.export_dossiers()
    assert set(docs) == {"lead", "code-reviewer"}
    j.close()


@needs_sdk
def test_agent_journals_record_output_false_is_honoured(tmp_path):
    j = AgentJournals(str(tmp_path / "audit"), record_output=False)
    h = WitnessLogClaudeHooks(j)
    asyncio.run(_call(h, pre("t1", "Read", {"file_path": "/etc/hosts"})))
    asyncio.run(_call(h, post("t1", "Read", {"file_path": "/etc/hosts"}, {"file": {"content": "secret"}})))
    p = _payloads(j.recorder("main"))
    assert "tool_response" not in p[1] and p[1]["intent_index"] == 0
    j.close()


# --- the SDK's own loop, over a scripted CLI ----------------------------------------------


def _scripted_cli(calls):
    """A ``Transport`` standing in for the Claude Code CLI. ``calls`` is one
    model turn of parallel tool calls: ``{"id", "name", "input"}`` plus
    ``"response"`` or ``"error"``."""

    class ScriptedCLI(sdk.Transport):
        def __init__(self):
            self.inbox = None
            self.callback_ids = {}
            self.answers = []  # (event, tool_use_id, the SDK's answer)
            self.refused = []  # control responses with subtype "error"
            self.ran = []
            self._waiting = {}
            self._n = 0
            self._tasks = []

        async def connect(self):
            self.inbox = asyncio.Queue()

        def is_ready(self):
            return self.inbox is not None

        async def write(self, data):
            for line in data.splitlines():
                if not line.strip():
                    continue
                msg = json.loads(line)
                if msg.get("type") == "control_request" and msg["request"].get("subtype") == "initialize":
                    for event, matchers in (msg["request"].get("hooks") or {}).items():
                        self.callback_ids[event] = [cid for m in matchers for cid in m["hookCallbackIds"]]
                    self.inbox.put_nowait({"type": "control_response", "response": {"subtype": "success", "request_id": msg["request_id"], "response": {}}})
                elif msg.get("type") == "user":
                    self._tasks.append(asyncio.ensure_future(self._turn()))
                elif msg.get("type") == "control_response":
                    fut = self._waiting.pop(msg["response"]["request_id"], None)
                    if fut is not None and not fut.done():
                        fut.set_result(msg["response"])

        async def read_messages(self):
            while True:
                msg = await self.inbox.get()
                if msg is None:
                    return
                yield msg

        async def end_input(self):  # stdin closed: the CLI exits, stdout ends
            self.inbox.put_nowait(None)

        async def close(self):
            for t in self._tasks:
                t.cancel()
            if self.inbox is not None:
                self.inbox.put_nowait(None)

        async def _fire(self, event, hook_input):
            answers = []
            for cid in self.callback_ids.get(event, []):
                self._n += 1
                rid = f"hook-{self._n}"
                fut = asyncio.get_running_loop().create_future()
                self._waiting[rid] = fut
                self.inbox.put_nowait({
                    "type": "control_request", "request_id": rid,
                    "request": {"subtype": "hook_callback", "callback_id": cid, "input": hook_input, "tool_use_id": hook_input["tool_use_id"]},
                })
                resp = await asyncio.wait_for(fut, 10)
                if resp.get("subtype") != "success":
                    self.refused.append(resp)
                    continue
                answers.append(resp.get("response"))
                self.answers.append((event, hook_input["tool_use_id"], resp.get("response")))
            return answers

        async def _turn(self):
            sid = BASE["session_id"]
            self.inbox.put_nowait({
                "type": "assistant", "parent_tool_use_id": None, "session_id": sid,
                "message": {"role": "assistant", "model": "scripted", "content": [
                    {"type": "tool_use", "id": c["id"], "name": c["name"], "input": c["input"]} for c in calls]},
            })
            decisions = await asyncio.gather(*(self._fire(PRE, pre(c["id"], c["name"], c["input"])) for c in calls))

            async def finish(c, answers):
                if any((a or {}).get("hookSpecificOutput", {}).get("permissionDecision") == "deny" for a in answers):
                    return  # blocked: the tool does not run, no Post event
                self.ran.append(c["id"])
                if "error" in c:
                    await self._fire(FAILURE, failure(c["id"], c["name"], c["input"], c["error"]))
                else:
                    await self._fire(POST, post(c["id"], c["name"], c["input"], c["response"]))

            await asyncio.gather(*(finish(c, a) for c, a in zip(calls, decisions)))
            self.inbox.put_nowait({
                "type": "assistant", "parent_tool_use_id": None, "session_id": sid,
                "message": {"role": "assistant", "model": "scripted", "content": [{"type": "text", "text": "done"}]},
            })
            self.inbox.put_nowait({
                "type": "result", "subtype": "success", "duration_ms": 5, "duration_api_ms": 0, "is_error": False,
                "num_turns": 2, "session_id": sid, "result": "done",
            })

    return ScriptedCLI()


def _run_query(options, cli):
    async def run():
        return [m async for m in sdk.query(prompt="what are the balances?", options=options, transport=cli)]

    return asyncio.run(asyncio.wait_for(run(), 30))


CALLS = [
    {"id": "toolu_A", "name": "mcp__billing__get_balance", "input": {"account": "a-1"}, "response": _mcp_text("a-1: 42")},
    {"id": "toolu_B", "name": "mcp__billing__get_balance", "input": {"account": "a-2"}, "response": _mcp_text("a-2: 7")},
    {"id": "toolu_C", "name": "Bash", "input": {"command": "cat ledger.csv"}, "error": "Exit code 1\ncat: ledger.csv: No such file"},
]


@needs_sdk
def test_query_loop_records_every_call(tmp_path):
    log = wl.open(str(tmp_path / "agent.jsonl"))
    audit = WitnessLogClaudeHooks(log)
    cli = _scripted_cli(CALLS)
    messages = _run_query(audit.options(), cli)
    assert isinstance(messages[-1], sdk.ResultMessage) and messages[-1].result == "done"
    assert cli.refused == [] and audit.errors == []
    # The SDK registered one callback per event and passed our answers through unchanged: no decision.
    assert set(cli.callback_ids) == {PRE, POST, FAILURE}
    assert len(cli.answers) == 6 and all(a == {} for _, _, a in cli.answers)
    assert sorted(cli.ran) == ["toolu_A", "toolu_B", "toolu_C"]

    assert sorted(_types(log)) == [1, 1, 1, 2, 2, 2]
    p, intents, results = _pairs(audit.recorder)
    assert set(intents) == set(results) == {"toolu_A", "toolu_B", "toolu_C"}
    for c in CALLS:
        i = intents[c["id"]]
        assert p[i]["profile"] == "hook.claude-code v1" and p[i]["tool_input"] == c["input"]
        r = results[c["id"]]
        assert r["intent_index"] == i
        if "error" in c:
            assert r["event"] == FAILURE and r["error"] == c["error"]
        else:
            assert r["event"] == POST and r["tool_response"] == c["response"]
    _verified(log)


@needs_sdk
def test_query_loop_strict_blocks_unrecorded_calls():
    audit = WitnessLogClaudeHooks(BrokenLog(), strict=True)
    cli = _scripted_cli(CALLS[:2])
    messages = _run_query(sdk.ClaudeAgentOptions(hooks=audit.hooks()), cli)
    assert isinstance(messages[-1], sdk.ResultMessage) and cli.refused == []
    assert cli.ran == []  # both calls denied before they ran
    denials = [a for e, _, a in cli.answers if e == PRE]
    assert len(denials) == 2 and all(a["hookSpecificOutput"]["permissionDecision"] == "deny" for a in denials)
    assert len(audit.errors) == 2


# --- without the SDK ---------------------------------------------------------------------


def test_imports_and_records_without_the_sdk(tmp_path, monkeypatch):
    monkeypatch.setitem(sys.modules, "claude_agent_sdk", None)  # `import claude_agent_sdk` now fails
    monkeypatch.delitem(sys.modules, "witness_log.integrations.claude_agent_sdk", raising=False)
    mod = importlib.import_module("witness_log.integrations.claude_agent_sdk")
    log = wl.open(str(tmp_path / "agent.jsonl"))
    h = mod.WitnessLogClaudeHooks(log)
    ev = {**BASE, "hook_event_name": PRE, "tool_name": "Bash", "tool_input": {"command": "ls"}, "tool_use_id": "t1"}
    assert asyncio.run(h.pre_tool_use(ev, "t1", CTX)) == {}
    assert asyncio.run(h.post_tool_use({**ev, "hook_event_name": POST, "tool_response": {"stdout": ""}}, "t1", CTX)) == {}
    assert _types(log) == [1, 2] and h.errors == []
    with pytest.raises(ImportError, match=r"pip install"):
        h.hooks()
    with pytest.raises(ImportError, match=r"claude-agent-sdk"):
        mod.witness_hooks(log)
