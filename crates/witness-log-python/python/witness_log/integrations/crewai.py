"""CrewAI: record every tool call through CrewAI's tool-call hooks.

::

    from witness_log.integrations.crewai import witness_crewai
    with witness_crewai(witness_log.open("agent.jsonl")):
        crew.kickoff()

The hooks are CrewAI's global ``before_tool_call`` / ``after_tool_call``
hooks, so every agent in the process is recorded while the context is
open (call ``.close()`` instead of using ``with`` to keep it longer). A
before hook that returns ``False`` would block the tool; this one never
does. Calls are paired per thread and tool name, first in first out.
"""

from __future__ import annotations

import threading
from collections import defaultdict, deque
from typing import Any, Deque, Dict, Optional, Tuple

from crewai.hooks import (
    register_after_tool_call_hook,
    register_before_tool_call_hook,
    unregister_after_tool_call_hook,
    unregister_before_tool_call_hook,
)

from . import Recorder

__all__ = ["witness_crewai", "WitnessCrewAIHooks"]


class WitnessCrewAIHooks:
    def __init__(self, log: Any, *, record_output: bool = True, raise_on_error: bool = False) -> None:
        self.recorder = Recorder(log, record_output=record_output, raise_on_error=raise_on_error)
        self._pending: Dict[Tuple[int, str], Deque[Optional[int]]] = defaultdict(deque)
        self._lock = threading.Lock()
        register_before_tool_call_hook(self._before)
        register_after_tool_call_hook(self._after)

    @property
    def errors(self) -> list:
        return self.recorder.errors

    def _before(self, ctx: Any) -> None:
        name = getattr(ctx, "tool_name", "tool")
        i = self.recorder.intent(name, dict(getattr(ctx, "tool_input", None) or {}))
        with self._lock:
            self._pending[(threading.get_ident(), name)].append(i)
        return None  # never block the tool

    def _after(self, ctx: Any) -> None:
        name = getattr(ctx, "tool_name", "tool")
        with self._lock:
            q = self._pending.get((threading.get_ident(), name))
            i = q.popleft() if q else None
        raw = getattr(ctx, "raw_tool_result", None)
        self.recorder.result(name, i, raw if raw is not None else getattr(ctx, "tool_result", None))
        return None  # keep the tool's result unchanged

    def close(self) -> None:
        unregister_before_tool_call_hook(self._before)
        unregister_after_tool_call_hook(self._after)

    def __enter__(self) -> "WitnessCrewAIHooks":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()


def witness_crewai(log: Any, **kwargs: Any) -> WitnessCrewAIHooks:
    """Register the hooks; use as a context manager or call ``.close()``."""
    return WitnessCrewAIHooks(log, **kwargs)
