"""AutoGen AgentChat: record tool calls and handoffs from the event stream.

::

    from witness_log.integrations.autogen import WitnessLogAutoGen

    audit = WitnessLogAutoGen(witness_log.open("team.jsonl"))
    result = await audit.run(team, task="...")           # instead of team.run(task=...)

    # or keep your own loop over the stream:
    async for event in audit.record(team.run_stream(task="...")):
        console_print(event)

AgentChat exposes what its agents do as a stream of messages and
events; there is no per-tool hook, so this adapter reads the stream.
``ToolCallRequestEvent`` becomes one intent leaf per ``FunctionCall``
(keyed by its ``id``), ``ToolCallExecutionEvent`` one result leaf per
``FunctionExecutionResult`` (``outcome`` from ``is_error``), and a
``HandoffMessage`` a handoff from its ``source`` to its ``target``. The
agent is the event's ``source``; with an
:class:`~witness_log.integrations.AgentJournals` that selects the journal
and a handoff writes ``Sent`` in the source's journal and ``Received`` in
the target's. Events are yielded unchanged, so ``Console`` and other
consumers work as before.
"""

from __future__ import annotations

import json
import threading
from typing import Any, AsyncIterator, Dict, Optional, Tuple

from autogen_agentchat.messages import HandoffMessage, ToolCallExecutionEvent, ToolCallRequestEvent

from . import Sink, handoff_state

__all__ = ["WitnessLogAutoGen"]


def _args(raw: Any) -> Any:
    if isinstance(raw, str):
        try:
            return json.loads(raw) if raw.strip() else {}
        except ValueError:
            return raw
    return raw


class WitnessLogAutoGen:
    """``handle(event)`` records one event; ``record(stream)`` wraps an
    ``agent.run_stream(...)`` / ``team.run_stream(...)``; ``run(...)``
    consumes one and returns its ``TaskResult``."""

    def __init__(self, target: Any, *, record_output: bool = True, raise_on_error: bool = False) -> None:
        self.sink = Sink(target, record_output=record_output, raise_on_error=raise_on_error)
        self._pending: Dict[str, Tuple[Optional[str], str, Optional[int]]] = {}
        self._lock = threading.Lock()
        self._seq = 0

    @property
    def errors(self) -> list:
        return self.sink.errors

    @property
    def recorder(self) -> Any:
        return self.sink.recorder()

    def handle(self, event: Any) -> None:
        """Record ``event`` if it is a tool request, a tool result or a handoff."""
        if isinstance(event, ToolCallRequestEvent):
            who = getattr(event, "source", None)
            rec = self.sink.recorder(who)
            for call in event.content:
                i = rec.intent(call.name, _args(call.arguments), call_id=call.id, agent=who)
                with self._lock:
                    self._pending[call.id] = (who, call.name, i)
        elif isinstance(event, ToolCallExecutionEvent):
            who = getattr(event, "source", None)
            for res in event.content:
                with self._lock:
                    entry = self._pending.pop(res.call_id, None)
                p_who, name, i = entry if entry is not None else (who, res.name or "tool", None)
                outcome = "error" if res.is_error else "ok"
                self.sink.recorder(p_who or who).result(name, i, res.content, outcome=outcome, call_id=res.call_id)
        elif isinstance(event, HandoffMessage):
            src, dst = str(event.source), str(event.target)
            with self._lock:
                self._seq += 1
                n = self._seq
            rec = self.sink.recorder(src)
            i = rec.intent("handoff", {"from": src, "to": dst}, agent=src)
            sent, recv = self.sink.handoff(src, dst, handoff_state(src, dst, seq=n))
            rec.result("handoff", i, event.content, outcome="ok", handoff_to=dst, sent_leaf=sent, received_leaf=recv)

    async def record(self, stream: AsyncIterator[Any]) -> AsyncIterator[Any]:
        """Yield every item of ``stream`` after recording it."""
        async for event in stream:
            self.handle(event)
            yield event

    async def run(self, runner: Any, **kwargs: Any) -> Any:
        """``await runner.run(**kwargs)`` with recording: iterates
        ``runner.run_stream(**kwargs)`` and returns the final ``TaskResult``."""
        last = None
        async for event in self.record(runner.run_stream(**kwargs)):
            last = event
        return last
