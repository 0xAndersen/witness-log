"""OpenAI Agents SDK: ``RunHooks`` plus a ``TracingProcessor`` that record
every function-tool call, and one journal per agent identity.

::

    from witness_log.integrations.openai_agents import WitnessLogAudit
    from agents import Runner, add_trace_processor

    audit = WitnessLogAudit("audit/", seed_for=kms.seed_for, sealed=True)
    add_trace_processor(audit.processor())            # optional: catches tools that raise through
    result = await Runner.run(triage, "...", hooks=audit.hooks)
    audit.export_dossiers()                           # audit/<agent>.dossier.json per agent

Or, for one journal shared by the whole run::

    hooks = WitnessLogHooks(witness_log.open("agent.jsonl"))
    await Runner.run(agent, "...", hooks=hooks)

What is recorded, and how the SDK's shape is handled:

* Calls are paired by ``ToolContext.tool_call_id``, never by tool name,
  so two parallel calls of one tool each get their own intent and result
  (keyed by name, the second call overwrote the first's pending index; a
  0.3.5 wiki snippet did exactly that and raised ``KeyError``).
* Arguments come from ``ToolContext.tool_arguments`` (the raw JSON the
  model produced), parsed when they parse. No ``context={}`` or any other
  run context is required from the caller.
* A tool that raises is, by default, turned into the string ``"An error
  occurred while running the tool. Please try again."`` before
  ``on_tool_end`` sees it, and the real exception goes only to the
  current trace span as ``"Error running tool (non-fatal)"``. The result
  leaf's ``outcome`` is read from that span error when tracing is on, and
  from the default message otherwise, so a failed tool is ``"error"``,
  not ``"ok"`` with an apologetic string as its value.
* A tool that raises *through* (``failure_error_function=None``) never
  reaches ``on_tool_end``. The :class:`TracingProcessor` from
  :meth:`WitnessLogHooks.processor` sees its function span end with an
  error and writes the result leaf then.
* A handoff writes a ``HandoffAttestation`` ``Sent`` leaf in the source
  agent's journal and ``Received`` in the target's (both over the same
  state bytes, so ``witness-log bind`` matches them), plus an intent /
  result pair named ``handoff`` in the source journal. With a single
  shared log only the pair is written.
"""

from __future__ import annotations

import json
import threading
from typing import Any, Callable, Dict, Optional, Tuple

from agents import RunHooks
from agents.tracing import TracingProcessor, get_current_span

from . import AgentJournals, Sink, handoff_state

try:  # the SDK's fixed replacement text for a failed tool
    from agents.tool import default_tool_error_function

    _DEFAULT_ERROR_TEXT: Optional[str] = default_tool_error_function(None, Exception())  # type: ignore[arg-type]
except Exception:  # noqa: BLE001 -- older/newer SDK without it: rely on the span
    _DEFAULT_ERROR_TEXT = None

__all__ = ["WitnessLogAudit", "WitnessLogHooks", "WitnessLogTraceProcessor"]


def _args(context: Any) -> Any:
    raw = getattr(context, "tool_arguments", None)
    if isinstance(raw, str):
        try:
            return json.loads(raw) if raw.strip() else {}
        except ValueError:
            return raw
    return raw


def _agent_name(agent: Any) -> str:
    return str(getattr(agent, "name", None) or "agent")


def _span_id(span: Any) -> Optional[str]:
    sid = getattr(span, "span_id", None)
    return str(sid) if sid else None


def _span_error(span: Any) -> Optional[Dict[str, Any]]:
    err = getattr(span, "error", None)
    if not err:
        return None
    if isinstance(err, dict):
        return {"message": err.get("message"), "data": err.get("data")}
    return {"message": getattr(err, "message", str(err)), "data": getattr(err, "data", None)}


class WitnessLogHooks(RunHooks):
    """Intent leaf in ``on_tool_start``, result leaf in ``on_tool_end``,
    handoff leaves in ``on_handoff``. ``target`` is a log (one journal for
    the run) or an :class:`~witness_log.integrations.AgentJournals` (one
    per agent, keyed by ``agent.name``)."""

    def __init__(self, target: Any, *, record_output: bool = True, raise_on_error: bool = False) -> None:
        super().__init__()
        self.sink = Sink(target, record_output=record_output, raise_on_error=raise_on_error)
        self._pending: Dict[Any, Tuple[str, str, Optional[int]]] = {}  # call key -> (agent, tool, intent index)
        self._by_span: Dict[str, Any] = {}  # function span id -> call key
        self._lock = threading.Lock()
        self._handoffs = 0

    @property
    def errors(self) -> list:
        return self.sink.errors

    @property
    def recorder(self) -> Any:
        """The single log's :class:`Recorder` (``.payloads`` for disclosure)."""
        return self.sink.recorder()

    def processor(self) -> "WitnessLogTraceProcessor":
        """A ``TracingProcessor`` for ``agents.add_trace_processor`` that
        completes the record of a tool that raised through."""
        return WitnessLogTraceProcessor(self)

    # -- RunHooks -----------------------------------------------------------

    @staticmethod
    def _key(context: Any, tool: Any) -> Any:
        return getattr(context, "tool_call_id", None) or (getattr(tool, "name", "tool"), id(context))

    async def on_tool_start(self, context: Any, agent: Any, tool: Any) -> None:
        name = str(getattr(context, "tool_name", None) or getattr(tool, "name", None) or "tool")
        who = _agent_name(agent)
        call_id = getattr(context, "tool_call_id", None)
        i = self.sink.recorder(who).intent(name, _args(context), call_id=call_id, agent=who)
        key = self._key(context, tool)
        with self._lock:
            self._pending[key] = (who, name, i)
            sid = _span_id(get_current_span())
            if sid:
                self._by_span[sid] = key

    async def on_tool_end(self, context: Any, agent: Any, tool: Any, result: Any) -> None:
        key = self._key(context, tool)
        with self._lock:
            who, name, i = self._pending.pop(key, (_agent_name(agent), str(getattr(tool, "name", "tool")), None))
            sid = _span_id(get_current_span())
            if sid:
                self._by_span.pop(sid, None)
        err = _span_error(get_current_span())
        outcome = "ok"
        extra: Dict[str, Any] = {"call_id": getattr(context, "tool_call_id", None)}
        if err is not None:
            outcome = "error"
            extra["error"] = err
        elif _DEFAULT_ERROR_TEXT is not None and isinstance(result, str) and result == _DEFAULT_ERROR_TEXT:
            outcome = "error"
            extra["error"] = {"message": "tool raised; the SDK replaced the exception with its default text", "data": None}
        self.sink.recorder(who).result(name, i, result, outcome=outcome, **extra)

    async def on_handoff(self, context: Any, from_agent: Any, to_agent: Any) -> None:
        src, dst = _agent_name(from_agent), _agent_name(to_agent)
        with self._lock:
            self._handoffs += 1
            n = self._handoffs
        state = handoff_state(src, dst, seq=n)
        rec = self.sink.recorder(src)
        i = rec.intent("handoff", {"from": src, "to": dst}, agent=src)
        sent, recv = self.sink.handoff(src, dst, state)
        rec.result("handoff", i, {"to": dst}, outcome="ok", handoff_to=dst, sent_leaf=sent, received_leaf=recv)

    # -- used by the processor ---------------------------------------------

    def _complete_from_span(self, span: Any) -> None:
        sid = _span_id(span)
        if not sid:
            return
        with self._lock:
            key = self._by_span.pop(sid, None)
            entry = self._pending.pop(key, None) if key is not None else None
        if entry is None:
            return  # on_tool_end already wrote the result
        who, name, i = entry
        err = _span_error(span) or {"message": "function span ended without on_tool_end", "data": None}
        self.sink.recorder(who).result(name, i, None, outcome="error", call_id=key if isinstance(key, str) else None, error=err)


class WitnessLogTraceProcessor(TracingProcessor):
    """Completes the record for a function span that ended while its call
    was still pending (the tool raised through to the caller, so
    ``on_tool_end`` never ran). Everything else is ignored; spans are not
    exported anywhere."""

    def __init__(self, hooks: WitnessLogHooks) -> None:
        self.hooks = hooks

    def on_trace_start(self, trace: Any) -> None:
        pass

    def on_trace_end(self, trace: Any) -> None:
        pass

    def on_span_start(self, span: Any) -> None:
        pass

    def on_span_end(self, span: Any) -> None:
        data = getattr(span, "span_data", None)
        if getattr(data, "type", None) == "function":
            self.hooks._complete_from_span(span)

    def shutdown(self) -> None:
        pass

    def force_flush(self) -> None:
        pass


class WitnessLogAudit:
    """One journal per agent identity under ``directory``, with the hooks,
    the processor and the after-the-run operations in one place.

    ``seed_for(agent_name) -> bytes`` supplies each agent's identity seed;
    ``sealed=True`` (the default when ``seed_for`` is given) keeps it out
    of the journal. Without ``seed_for`` each journal gets a fresh
    identity stored in its header."""

    def __init__(
        self,
        directory: str,
        *,
        seed_for: Optional[Callable[[str], bytes]] = None,
        sealed: Optional[bool] = None,
        record_output: bool = True,
        raise_on_error: bool = False,
    ) -> None:
        self.journals = AgentJournals(directory, seed_for=seed_for, sealed=sealed, record_output=record_output, raise_on_error=raise_on_error)
        self.hooks = WitnessLogHooks(self.journals, record_output=record_output, raise_on_error=raise_on_error)

    @property
    def errors(self) -> list:
        return self.journals.errors

    def processor(self) -> WitnessLogTraceProcessor:
        return self.hooks.processor()

    def log(self, agent: str) -> Any:
        return self.journals.log(agent)

    def witness(self, directory: Any, **kw: Any) -> Dict[str, Any]:
        return self.journals.witness(directory, **kw)

    def export_dossiers(self, write: bool = True) -> Dict[str, str]:
        return self.journals.export_dossiers(write=write)

    def disclose(self, index: int, agent: Optional[str] = None) -> Dict[str, Any]:
        return self.journals.disclose(index, agent)

    def forget(self, index: int, agent: Optional[str] = None) -> bool:
        return self.journals.forget(index, agent)

    def close(self) -> None:
        self.journals.close()

    def __enter__(self) -> "WitnessLogAudit":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()
