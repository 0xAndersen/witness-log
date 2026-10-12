"""OpenAI Agents SDK: ``RunHooks`` that record every function-tool call.

::

    from witness_log.integrations.openai_agents import WitnessLogHooks
    hooks = WitnessLogHooks(witness_log.open("agent.jsonl"))
    await Runner.run(agent, "...", hooks=hooks)

Calls are paired by the SDK's ``tool_call_id`` and the arguments come
from ``ToolContext.tool_arguments``, so two parallel calls of the same
tool are recorded separately (the 0.3.5 wiki snippet keyed by tool name
and raised ``KeyError`` on exactly that).
"""

from __future__ import annotations

import json
from typing import Any, Dict

from agents import RunHooks

from . import Recorder

__all__ = ["WitnessLogHooks"]


def _call_key(context: Any, tool: Any) -> Any:
    return getattr(context, "tool_call_id", None) or (getattr(tool, "name", "tool"), id(context))


def _args(context: Any) -> Any:
    raw = getattr(context, "tool_arguments", None)
    if isinstance(raw, str):
        try:
            return json.loads(raw)
        except ValueError:
            return raw
    return raw


class WitnessLogHooks(RunHooks):
    """Intent leaf in ``on_tool_start``, result leaf in ``on_tool_end``.
    A tool that raises reaches ``on_tool_end`` with the SDK's error
    string as its result (the SDK's default failure handling), so it is
    recorded as a result too."""

    def __init__(self, log: Any, *, record_output: bool = True, raise_on_error: bool = False) -> None:
        self.recorder = Recorder(log, record_output=record_output, raise_on_error=raise_on_error)
        self._pending: Dict[Any, int] = {}

    @property
    def errors(self) -> list:
        return self.recorder.errors

    async def on_tool_start(self, context: Any, agent: Any, tool: Any) -> None:
        name = getattr(tool, "name", "tool")
        i = self.recorder.intent(name, _args(context), call_id=getattr(context, "tool_call_id", None))
        self._pending[_call_key(context, tool)] = i

    async def on_tool_end(self, context: Any, agent: Any, tool: Any, result: Any) -> None:
        name = getattr(tool, "name", "tool")
        i = self._pending.pop(_call_key(context, tool), None)
        self.recorder.result(name, i, result)
