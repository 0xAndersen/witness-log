"""Google ADK: a ``BasePlugin`` that records every tool call and treats
``transfer_to_agent`` as a handoff.

::

    from google.adk.apps import App
    from google.adk.runners import InMemoryRunner
    from witness_log.integrations.google_adk import WitnessLogPlugin

    plugin = WitnessLogPlugin(witness_log.open("agent.jsonl"))
    runner = InMemoryRunner(app=App(name="app", root_agent=root_agent, plugins=[plugin]))

    # or one journal per agent, with handoff leaves on transfer_to_agent:
    from witness_log.integrations import AgentJournals
    plugin = WitnessLogPlugin(AgentJournals("audit/", seed_for=kms.seed_for))

A plugin applies to every agent under the runner, unlike per-agent
``before_tool_callback`` / ``after_tool_callback``. Calls are paired by
``ToolContext.function_call_id``, so parallel calls of one tool are
recorded separately; the agent is ``ToolContext.agent_name``. A tool that
raises reaches ``on_tool_error_callback`` and is recorded as
``outcome: "error"``; the plugin returns ``None`` there, so ADK's own
error handling is unchanged (the error propagates unless another plugin
answers it). When a tool sets ``tool_context.actions.transfer_to_agent``
(the built-in ``transfer_to_agent`` tool, or your own), the result leaf
carries ``handoff_to`` and, with journals, a ``Sent`` attestation is
written in the current agent's journal and ``Received`` in the target's.
"""

from __future__ import annotations

import threading
from typing import Any, Dict, Optional, Tuple

from google.adk.plugins.base_plugin import BasePlugin

from . import Sink, handoff_state

__all__ = ["WitnessLogPlugin"]


def _call_id(tool_context: Any, tool: Any) -> Any:
    return getattr(tool_context, "function_call_id", None) or (getattr(tool, "name", "tool"), id(tool_context))


def _agent(tool_context: Any) -> Optional[str]:
    try:
        n = tool_context.agent_name
    except Exception:  # noqa: BLE001
        n = None
    return str(n) if n else None


def _plain(v: Any) -> Any:
    if isinstance(v, dict):
        return {str(k): _plain(x) for k, x in v.items()}
    if isinstance(v, (list, tuple)):
        return [_plain(x) for x in v]
    if hasattr(v, "model_dump"):
        try:
            return v.model_dump(exclude_none=True, mode="json")
        except Exception:  # noqa: BLE001
            return repr(v)
    return v


class WitnessLogPlugin(BasePlugin):
    """Intent leaf in ``before_tool_callback``, result leaf in
    ``after_tool_callback`` / ``on_tool_error_callback``. ``target`` is a
    log or an ``AgentJournals``."""

    def __init__(self, target: Any, *, name: str = "witness_log", record_output: bool = True, raise_on_error: bool = False) -> None:
        super().__init__(name=name)
        self.sink = Sink(target, record_output=record_output, raise_on_error=raise_on_error)
        self._pending: Dict[Any, Tuple[Optional[str], str, Optional[int]]] = {}
        self._lock = threading.Lock()
        self._seq = 0

    @property
    def errors(self) -> list:
        return self.sink.errors

    @property
    def recorder(self) -> Any:
        return self.sink.recorder()

    async def before_tool_callback(self, *, tool: Any, tool_args: Dict[str, Any], tool_context: Any) -> Optional[Dict[str, Any]]:
        name = str(getattr(tool, "name", None) or "tool")
        who = _agent(tool_context)
        call_id = getattr(tool_context, "function_call_id", None)
        i = self.sink.recorder(who).intent(name, _plain(dict(tool_args or {})), call_id=call_id, agent=who)
        with self._lock:
            self._pending[_call_id(tool_context, tool)] = (who, name, i)
        return None  # never answer the call for the tool

    async def after_tool_callback(self, *, tool: Any, tool_args: Dict[str, Any], tool_context: Any, result: Any) -> Optional[Dict[str, Any]]:
        with self._lock:
            entry = self._pending.pop(_call_id(tool_context, tool), None)
        if entry is None:
            return None  # already recorded by on_tool_error_callback
        who, name, i = entry
        extra: Dict[str, Any] = {"call_id": getattr(tool_context, "function_call_id", None)}
        target = None
        try:
            target = tool_context.actions.transfer_to_agent
        except Exception:  # noqa: BLE001
            target = None
        if target:
            target = str(target)
            with self._lock:
                self._seq += 1
                n = self._seq
            state = handoff_state(who or "agent", target, seq=n, tool=name, call_id=extra["call_id"])
            sent, recv = self.sink.handoff(who, target, state)
            extra["handoff_to"] = target
            if sent is not None or recv is not None:
                extra["sent_leaf"], extra["received_leaf"] = sent, recv
        self.sink.recorder(who).result(name, i, _plain(result), **extra)
        return None  # keep the tool's result unchanged

    async def on_tool_error_callback(self, *, tool: Any, tool_args: Dict[str, Any], tool_context: Any, error: Exception) -> Optional[Dict[str, Any]]:
        with self._lock:
            entry = self._pending.pop(_call_id(tool_context, tool), None)
        if entry is None:
            who, name, i = _agent(tool_context), str(getattr(tool, "name", "tool")), None
        else:
            who, name, i = entry
        self.sink.recorder(who).result(
            name, i, f"{type(error).__name__}: {error}", outcome="error", call_id=getattr(tool_context, "function_call_id", None)
        )
        return None  # leave ADK's error handling as it is
