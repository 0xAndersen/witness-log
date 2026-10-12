"""LlamaIndex: record tool calls from an agent workflow's event stream, or
from the instrumentation spans of ``FunctionTool.call`` / ``acall``.

::

    from witness_log.integrations.llamaindex import WitnessLogLlamaIndex

    audit = WitnessLogLlamaIndex(witness_log.open("agent.jsonl"))
    result = await audit.run(workflow, user_msg="...")     # instead of await workflow.run(user_msg=...)

    # or keep your own loop over the stream:
    handler = workflow.run(user_msg="...")
    async for ev in audit.record(handler.stream_events()): ...
    result = await handler

``AgentWorkflow`` / ``FunctionAgent`` / ``ReActAgent`` surface every tool
call as a ``ToolCall`` event and its outcome as a ``ToolCallResult``
(``tool_output.is_error``), both carrying the model's ``tool_id``, so the
pairing is exact and parallel calls are separate. The current agent is
taken from the ``AgentInput`` / ``AgentOutput`` events around them; with
an :class:`~witness_log.integrations.AgentJournals` it selects the
journal. The built-in ``handoff`` tool (``can_handoff_to``) is recorded as
a handoff from the current agent to ``to_agent``: the tool's result leaf
carries ``handoff_to`` and, with journals, ``Sent`` / ``Received``
attestations are written on both sides.

For code that calls tools outside an agent workflow (a query engine
tool, a hand-rolled loop, the legacy agents), :class:`WitnessLogSpanHandler`
hooks LlamaIndex's instrumentation instead::

    from llama_index.core.instrumentation import get_dispatcher
    get_dispatcher().add_span_handler(WitnessLogSpanHandler(log))

It records the ``FunctionTool.call`` / ``acall`` spans: intent when the
span opens (tool name and bound arguments), result when it exits
(``ToolOutput.is_error``) or is dropped with an exception. Use one
mechanism or the other for a given log; both would record each call twice.
"""

from __future__ import annotations

import inspect
import threading
from typing import Any, AsyncIterator, Dict, Optional, Tuple

from llama_index.core.agent.workflow.workflow_events import AgentInput, AgentOutput, ToolCall, ToolCallResult
from llama_index_instrumentation.span_handlers.base import BaseSpanHandler
from pydantic import PrivateAttr

from . import Sink, handoff_state

__all__ = ["WitnessLogLlamaIndex", "WitnessLogSpanHandler"]

HANDOFF_TOOL = "handoff"


def _plain(v: Any) -> Any:
    if isinstance(v, dict):
        return {str(k): _plain(x) for k, x in v.items()}
    if isinstance(v, (list, tuple)):
        return [_plain(x) for x in v]
    if hasattr(v, "model_dump"):
        try:
            return v.model_dump(mode="json")
        except Exception:  # noqa: BLE001
            return repr(v)
    if isinstance(v, (str, int, float, bool)) or v is None:
        return v
    return repr(v)


def _bound(bound_args: inspect.BoundArguments) -> Any:
    """``FunctionTool.call(*args, **kwargs)``: flatten the bound ``kwargs``
    (and ``args``) into the recorded arguments, dropping ``self``/``ctx``."""
    out: Dict[str, Any] = {}
    for k, v in bound_args.arguments.items():
        if k in ("self", "ctx"):
            continue
        if k == "kwargs" and isinstance(v, dict):
            out.update({str(kk): _plain(vv) for kk, vv in v.items() if kk != "ctx"})
        elif k == "args" and isinstance(v, (list, tuple)):
            if v:
                out["args"] = [_plain(x) for x in v]
        else:
            out[k] = _plain(v)
    return out


def _output(tool_output: Any) -> Any:
    raw = getattr(tool_output, "raw_output", None)
    if raw is not None and isinstance(raw, (str, int, float, bool, dict, list)):
        return raw
    content = getattr(tool_output, "content", None)
    return content if content is not None else _plain(raw)


class WitnessLogLlamaIndex:
    """``handle(event)`` records one workflow event; ``record(stream)``
    wraps ``handler.stream_events()``; ``run(workflow, **kw)`` runs the
    workflow and returns its result."""

    def __init__(self, target: Any, *, record_output: bool = True, raise_on_error: bool = False) -> None:
        self.sink = Sink(target, record_output=record_output, raise_on_error=raise_on_error)
        self._pending: Dict[str, Tuple[Optional[str], str, Optional[int]]] = {}
        self._agent: Optional[str] = None
        self._lock = threading.Lock()
        self._seq = 0

    @property
    def errors(self) -> list:
        return self.sink.errors

    @property
    def recorder(self) -> Any:
        return self.sink.recorder()

    def handle(self, event: Any) -> None:
        if isinstance(event, (AgentInput, AgentOutput)):
            name = getattr(event, "current_agent_name", None)
            if name:
                with self._lock:
                    self._agent = str(name)
        elif isinstance(event, ToolCall):
            with self._lock:
                who = self._agent
            i = self.sink.recorder(who).intent(event.tool_name, _plain(dict(event.tool_kwargs)), call_id=event.tool_id, agent=who)
            with self._lock:
                self._pending[event.tool_id] = (who, event.tool_name, i)
        elif isinstance(event, ToolCallResult):
            with self._lock:
                entry = self._pending.pop(event.tool_id, None)
                who, name, i = entry if entry is not None else (self._agent, event.tool_name, None)
            out = event.tool_output
            outcome = "error" if getattr(out, "is_error", False) else "ok"
            extra: Dict[str, Any] = {"call_id": event.tool_id}
            if name == HANDOFF_TOOL and outcome == "ok" and event.tool_kwargs.get("to_agent"):
                dst = str(event.tool_kwargs["to_agent"])
                with self._lock:
                    self._seq += 1
                    n = self._seq
                sent, recv = self.sink.handoff(who, dst, handoff_state(who or "agent", dst, seq=n, call_id=event.tool_id))
                extra["handoff_to"] = dst
                if sent is not None or recv is not None:
                    extra["sent_leaf"], extra["received_leaf"] = sent, recv
            self.sink.recorder(who).result(name, i, _output(out), outcome=outcome, **extra)

    async def record(self, stream: AsyncIterator[Any]) -> AsyncIterator[Any]:
        """Yield every event of ``stream`` after recording it."""
        async for event in stream:
            self.handle(event)
            yield event

    async def run(self, workflow: Any, **kwargs: Any) -> Any:
        """``await workflow.run(**kwargs)`` with recording."""
        handler = workflow.run(**kwargs)
        async for _ in self.record(handler.stream_events()):
            pass
        return await handler


class WitnessLogSpanHandler(BaseSpanHandler[Dict[str, Any]]):
    """Instrumentation span handler for ``FunctionTool.call`` / ``acall``
    (and any ``BaseTool`` whose call is a span). Register it with
    ``get_dispatcher().add_span_handler(...)``."""

    _sink: Any = PrivateAttr()
    _pending: Dict[str, Tuple[str, Optional[int]]] = PrivateAttr(default_factory=dict)
    _plock: Any = PrivateAttr(default_factory=threading.Lock)

    def __init__(self, target: Any, *, record_output: bool = True, raise_on_error: bool = False) -> None:
        super().__init__()
        self._sink = Sink(target, record_output=record_output, raise_on_error=raise_on_error)

    @classmethod
    def class_name(cls) -> str:
        return "WitnessLogSpanHandler"

    @property
    def errors(self) -> list:
        return self._sink.errors

    @property
    def recorder(self) -> Any:
        return self._sink.recorder()

    @staticmethod
    def _is_tool_call(id_: str, instance: Any) -> bool:
        head = id_.split("-", 1)[0]
        return head.endswith(".call") or head.endswith(".acall") or head.endswith("Tool.__call__")

    def new_span(self, id_: str, bound_args: inspect.BoundArguments, instance: Any = None, parent_span_id: Optional[str] = None, tags: Any = None, **kwargs: Any) -> Optional[Dict[str, Any]]:
        if not self._is_tool_call(id_, instance):
            return None
        meta = getattr(instance, "metadata", None)
        name = str(getattr(meta, "name", None) or type(instance).__name__)
        i = self._sink.recorder().intent(name, _bound(bound_args), span_id=id_)
        with self._plock:
            self._pending[id_] = (name, i)
        return {"id": id_, "tool": name}

    def prepare_to_exit_span(self, id_: str, bound_args: inspect.BoundArguments, instance: Any = None, result: Any = None, **kwargs: Any) -> Optional[Dict[str, Any]]:
        with self._plock:
            entry = self._pending.pop(id_, None)
        if entry is None:
            return None
        name, i = entry
        outcome = "error" if getattr(result, "is_error", False) else "ok"
        extra: Dict[str, Any] = {"span_id": id_}
        to_agent = _bound(bound_args).get("to_agent")
        if name == HANDOFF_TOOL and outcome == "ok" and to_agent:
            extra["handoff_to"] = str(to_agent)
        self._sink.recorder().result(name, i, _output(result), outcome=outcome, **extra)
        return {"id": id_, "tool": name}

    def prepare_to_drop_span(self, id_: str, bound_args: inspect.BoundArguments, instance: Any = None, err: Optional[BaseException] = None, **kwargs: Any) -> Optional[Dict[str, Any]]:
        with self._plock:
            entry = self._pending.pop(id_, None)
        if entry is None:
            return None
        name, i = entry
        self._sink.recorder().result(name, i, f"{type(err).__name__}: {err}", outcome="error", span_id=id_)
        return {"id": id_, "tool": name}
